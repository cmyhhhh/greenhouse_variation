from telnetlib import IP
from . import *
from .LLMServer import NvramServer

import os, shutil, stat, getpass, glob
import subprocess
from subprocess import Popen, PIPE
import pathlib
import ipaddress
import re
import time
import string
import angr
import ifaddr

def remove_markdown_comments(code):
    """
    移除Markdown注释
    """
    pattern = re.compile(r"^```.*$", re.MULTILINE)
    cleaned_content = re.sub(pattern, "", code)
    pattern = re.compile(r"^\s*$(?:\r?\n)?", re.MULTILINE)
    cleaned_content = re.sub(pattern, "", cleaned_content)
    if cleaned_content and cleaned_content[-1] == '\n':
        cleaned_content = cleaned_content[:-1]
    return cleaned_content


def llm_evaluate_init_candidates(candidates, fs_path):
    """Evaluate init candidates using LLM and return the optimal candidate"""
    try:
        from openai import OpenAI
        import time
        
        # Build candidate information
        candidates_info = []
        for i, candidate in enumerate(candidates, 1):
            # Resolve symlink to get real file path
            real_path = candidate
            # Use LLMServer-style symlink resolution with circular link protection
            max_resolve_attempts = 10  # Prevent circular symlinks
            attempt = 0
            
            while os.path.islink(real_path) and attempt < max_resolve_attempts:
                attempt += 1
                try:
                    link_target = os.readlink(real_path)
                    # Always treat link target as relative to firmware filesystem root
                    link_target_in_fs = link_target.lstrip('/')
                    real_path = os.path.join(fs_path, link_target_in_fs)
                    # Normalize path to avoid ../ in path
                    real_path = os.path.normpath(real_path)
                except Exception:
                    break
            
            if attempt >= max_resolve_attempts:
                print(f"[LLM Init Evaluation] Too many symlink resolution attempts, possible circular symlink: {candidate}")
            
            found_files = []
            
            # Check if resolved path exists
            if os.path.exists(real_path) and not os.path.isdir(real_path):
                found_files = [real_path]
            else:
                print(f"[LLM Init Evaluation] File not found: {real_path}")
                # Search for matching files in fs_path
                import mimetypes
                
                # Get target filename
                target_filename = os.path.basename(candidate)
                
                # Recursively search all files in fs_path
                for root, dirs, files in os.walk(fs_path):
                    for file in files:
                        if file == target_filename:
                            full_path = os.path.join(root, file)
                            # Handle symlinks for found files
                            temp_resolved = full_path
                            temp_attempt = 0
                            while os.path.islink(temp_resolved) and temp_attempt < max_resolve_attempts:
                                temp_attempt += 1
                                try:
                                    temp_link_target = os.readlink(temp_resolved)
                                    temp_link_target_in_fs = temp_link_target.lstrip('/')
                                    temp_resolved = os.path.join(fs_path, temp_link_target_in_fs)
                                    temp_resolved = os.path.normpath(temp_resolved)
                                except Exception:
                                    break
                            if temp_attempt < max_resolve_attempts:
                                found_files.append(temp_resolved)
                
                if found_files:
                    # If only one file found, use it directly
                    if len(found_files) == 1:
                        real_path = found_files[0]
                        print(f"[LLM Init Evaluation] Found single file: {real_path}")
                    else:
                        # Filter text and ELF files
                        text_files = []
                        elf_files = []
                        
                        for file_path in found_files:
                            # Check if it's an ELF file
                            try:
                                result = subprocess.run(["file", file_path], capture_output=True, text=True)
                                file_info = result.stdout.lower()
                                if "elf" in file_info:
                                    elf_files.append(file_path)
                                else:
                                    # Check if it's a text file
                                    # Guess file type using mimetypes
                                    mime_type, _ = mimetypes.guess_type(file_path)
                                    if mime_type and mime_type.startswith('text/'):
                                        text_files.append(file_path)
                                    else:
                                        # Try to read file content to determine if it's text
                                        try:
                                            with open(file_path, 'r') as f:
                                                f.read(1024)  # Only read first 1024 bytes
                                            text_files.append(file_path)
                                        except UnicodeDecodeError:
                                            continue
                            except Exception:
                                continue
                        if elf_files:
                            real_path = elf_files[0]
                            print(f"[LLM Init Evaluation] Found ELF file: {real_path}")
                        elif text_files:
                            real_path = text_files[0]
                            print(f"[LLM Init Evaluation] Found text file: {real_path}")
                        else:
                            # No suitable files found, select first found file
                            real_path = found_files[0]
                            print(f"[LLM Init Evaluation] Found file: {real_path}")
                else:
                    print(f"[LLM Init Evaluation] No matching files found in {fs_path}")
            
            # Get relative path for prompt (without fs_path)
            relative_path = real_path.replace(fs_path, "").lstrip('/')
            if not relative_path:
                continue
            
            info = {
                "index": i,
                "path": candidate,
                "relative_path": relative_path,
                "content": "",
                "is_elf": False
            }
            
            # Get file content or relevant information
            if found_files and os.path.exists(real_path) and not os.path.isdir(real_path):
                try:
                    # Check if it's a text file
                    result = subprocess.run(["file", real_path], capture_output=True, text=True)
                    file_info = result.stdout.lower()
                    
                    if "text" in file_info or "script" in file_info:
                        # For text files, read content
                        with open(real_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            # Limit content length to avoid long prompt
                            if len(content) > 5000:
                                info["content"] = content[:5000] + "\n[Content too long, truncated]"
                            else:
                                info["content"] = content
                    elif "elf" in file_info:
                        # For ELF files, extract key information
                        info["is_elf"] = True
                        elf_info = []
                        
                        # Use strings to extract key strings, limit output
                        try:
                            strings_result = subprocess.run(
                                ["strings", "-n", "6", real_path], 
                                capture_output=True, text=True, timeout=5
                            )
                            # Filter and extract key strings
                            strings_output = strings_result.stdout.strip().split('\n')
                            # Filter strings related to init
                            init_related_strings = [s for s in strings_output if any(keyword in s.lower() for keyword in ['init', 'start', 'boot', 'service', 'rc', 'system', 'process', 'rcS', 'profile'])]
                            # Get non-empty strings
                            non_empty_strings = [s for s in strings_output if s.strip()]
                            # Prioritize related strings, supplement with others if less than 100
                            selected_strings = init_related_strings.copy()
                            if len(selected_strings) < 100:
                                # Add other non-related strings, avoid duplicates
                                for s in non_empty_strings:
                                    if s not in selected_strings and len(selected_strings) < 100:
                                        selected_strings.append(s)
                            # Take maximum 100 strings
                            selected_strings = selected_strings[:100]
                            if selected_strings:
                                elf_info.append("Key strings:\n" + "\n".join(selected_strings))
                        except Exception:
                            pass
                        
                        # Use readelf to extract function names, limit output
                        try:
                            readelf_result = subprocess.run(
                                ["readelf", "-s", real_path], 
                                capture_output=True, text=True, timeout=5
                            )
                            # Extract function names (only关注FUNC type symbols)
                            readelf_output = readelf_result.stdout.strip().split('\n')
                            function_names = []
                            for line in readelf_output:
                                if len(function_names) >= 100:
                                    break
                                # Parse readelf output, extract function names
                                parts = line.split()
                                if len(parts) >= 8 and parts[3] == 'FUNC':
                                    func_name = parts[7]
                                    if func_name not in function_names:
                                        function_names.append(func_name)
                            if function_names:
                                elf_info.append("Function names:\n" + "\n".join(function_names[:100]))
                        except Exception:
                            pass
                        
                        if elf_info:
                            info["content"] = "[ELF file information]\n" + "\n".join(elf_info)
                        else:
                            info["content"] = "[ELF file, unable to extract key information]"
                    else:
                        info["content"] = "[Other file type, unable to analyze]"
                except Exception:
                    info["content"] = "[Unable to read file content]"
            
            candidates_info.append(info)
        
        # Build prompt
        prompt = [
            {
                "role": "system",
                "content": "You are a firmware analysis expert specializing in evaluating initialization programs for embedded devices. Based on the provided information, please select the optimal init program candidate. Focus on the file's functional completeness and ability to boot the system."
            },
            {
                "role": "user",
                "content": "Please analyze the following init program candidates, select the optimal one:\n\n"
            }
        ]
        
        # Add candidate information
        for info in candidates_info:
            candidate_content = f"Candidate {info['index']}:\n"
            candidate_content += f"- Path: /{info['relative_path']}\n"
            if info['content']:
                candidate_content += f"- Analysis information:\n{info['content']}\n"
            prompt[1]["content"] += candidate_content + "\n"
        
        # Add evaluation criteria
        prompt[1]["content"] += "Please evaluate based on the following criteria:\n"
        prompt[1]["content"] += "1. Functionality: Can it fully start system services and initialization processes?\n"
        prompt[1]["content"] += "2. Completeness: Does it include necessary startup steps (such as mounting filesystems, starting network, etc.)?\n"
        prompt[1]["content"] += "3. Reasonableness: Does it conform to the boot process of embedded devices?\n"
        prompt[1]["content"] += "\nPlease select the optimal init program. DO NOT provide any explanation or reasoning. Simply output the path of the optimal candidate on a single line.\n"
        prompt[1]["content"] += "\nExample output:\n"
        prompt[1]["content"] += "/sbin/init"
        
        # Initialize OpenAI client
        client = OpenAI(
            api_key="sk-o20HTjWDHvtm25HPmjfWgkrOdRDH79bXLRA3UGZDFPXTTYL5",
            base_url="https://api.vectorengine.ai/v1",
        )
        
        # 调用LLM
        response = client.chat.completions.create(
            model="deepseek-v3.2",
            messages=prompt,
            temperature=1,
            top_p=0.5,
        )
        
        # 处理响应
        response_content = response.choices[0].message.content
        # 移除Markdown注释
        response_content = remove_markdown_comments(response_content)
        print("[LLM Init Evaluation] " + "=" * 20 + "LLM Response" + "=" * 20)
        print(f"[LLM Init Evaluation] {response_content}")
        
        # 提取最优候选路径
        lines = response_content.strip().split('\n')
        best_candidate = None
        
        # 尝试从最后几行中提取路径
        for line in reversed(lines):
            line = line.strip()
            # 检查是否是有效的文件路径
            if line:
                # 尝试在路径前加上 fs_path 检查
                full_path = os.path.join(fs_path, line.lstrip('/'))
                if os.path.exists(full_path):
                    best_candidate = full_path
                    break
        
        # 检查返回的路径是否以 fs_path 开头，如果不是，加上 fs_path
        if best_candidate and not best_candidate.startswith(fs_path):
            best_candidate = os.path.join(fs_path, best_candidate.lstrip('/'))
        
        return best_candidate
    except Exception as e:
        print(f"[LLM Init Evaluation] Error: {e}")
        return None


WEBROOTS = ["www", "www.eng" "web", "webs"]
WEB_EXTS = ["html", "htm", "xhtm", "jhtm", "cgi", "xml", "js", "wss", "php", "php4", "php3", "phtml", \
            "rss", "svg", "dll", "asp", "aspx", "axd", "asx", "asmx", "ashx", "cfm", "swf"]
BACKUP_TAGS = ["bak", "bak2", "bkup"]
POTENTIAL_HTTPSERV = ["httpd", "uhttpd", "lighttpd", "jjhttpd", "shttpd", "thttpd","minihttpd", "mini_httpd", \
                    "mini_httpds", "dhttpd", "alphapd", "goahead", "boa", "appweb", "shgw_httpd", \
                    "tenda_httpd", "funjsq_httpd", "webs", "hunt_server", "hydra"]
POTENTIAL_UPNPSERV = ["miniupnpd", "miniupnpc", "mini_upnpd", "miniupnpd_ap", "miniupnpd_wsc", \
                      "upnp", "upnpc", "upnpd", "upnpc-static", "upnprenderer", \
                      "bcmupnp", "wscupnpd", "upnp_app", "upnp_igd", "upnp_tv_devices"]
POTENTIAL_DNSSERV = ["ddnsd", "dnsmasq"]
POTENTIAL_DHCPSERV = ["udhcpd", "dnsmasq"]
BACKGROUND_SCRIPTS = {"xmldb" : "-n gh_xml_root_node -t", "userconfig" : ""}
GH_BUSYBOX = "busybox"
GH_IP = "ip"
GREENHOUSE = "greenhouse"
NVRAM_FOLDER = "libnvram_faker"
NVRAM_FAKER_LIB = "libnvram-faker.so"
NVRAM_INIT = "nvram.ini"
NVRAM_KEY_VALUE_FOLDER = "gh_nvram"
NVRAM_IP_KEYS = ["ip_addr", "ipaddr"]
RAND = "8467206204610564372101238468369273619216273019100147216372162374"*100 # "random number" string for 'entropy'
MUSL_LD_DEFAULT = "/lib:/usr/local/lib:/usr/lib"
ARCH_MAP = {"arm": "qemu-arm-static",
                        # "armeb32": "qemu-armeb-static",
                        # "arm64": "qemu-aarch64-static",
                        # "armeb64": "qemu-aarch64_be-static",
                         "x86": "qemu-i386-static",
                        # "x86_64": "qemu-x86_64-static",
                         "mips": "qemu-mips-static",
                         "mipsel": "qemu-mipsel-static",
                        # "mips64": "qemu-mips64-static",
                        # "mips64el": "qemu-mips64el-static",
                        }
RESERVED_IPS = ["0.0.0.0", "127.0.0.1", "1.1.1.1", "1.0.0.1"]
PORTS_BLACKLIST = ['0', '22']
MAC_NVRAM_KEYS = ["lan_hwaddr"]
POTENTIAL_INIT = ["/sbin/preinit", "/bin/init","/sbin/init", "/etc/init", "/sbin/rc", 
                  "/etc/init.d/rcS", "/usr/etc/rcS", "/etc/system/sysinit", "/sbin/rc", "/etc/init.d/rc"
                  "/sbin/rcd", "/sbin/procd", "/sbin/rc_app/rc_apps"]
POTENTIAL_INIT_BASENAME = ["preinitmt", "preinit","rcs", "rc", "profile", "sysinit", "rc_apps", "rcd", "procd"]

class Fixer():
    def __init__(self, qemu_src_path, gh_path, scripts_path, brand, baseline_mode, no_services=False):

        self.qemu_src_path = qemu_src_path
        self.qemu_src_path_ori = qemu_src_path + "_ori"  # 在路径后面加上 _ori 后缀
        self.qemu_run_path = ""
        self.scripts_path = scripts_path
        self.gh_path = gh_path
        self.nvram_faker_path = os.path.join(self.gh_path, NVRAM_FOLDER)
        self.nvram_init_path = ""
        self.nvram_key_value_path = ""
        self.nvram_map = dict()
        self.nvram_brand_map = dict()
        self.qemu_arch = None
        self.arch = None
        self.brand = brand
        self.clib = "glibc" # default
        self.baseline_mode = baseline_mode
        self.no_services = no_services
        self.nvram_server = None
        self.found_funcs = []
        self.binary_path = None
        self.fs_path = None
        
        self.total_input_tokens = 0
        self.total_output_tokens = 0

    def set_found_funcs(self, found_funcs):
        """
        设置在二进制文件中找到的 nvram 函数名

        Args:
            found_funcs: 在二进制文件中找到的 nvram 函数名列表
        """
        self.found_funcs = found_funcs
        # 初始化 nvram_server
        if found_funcs and self.binary_path and self.fs_path and not self.nvram_server and not self.no_services:
            try:
                print("    - initializing NvramServer for value prediction")
                self.nvram_server = NvramServer(
                    binary_path=self.binary_path,
                    fs_path=self.fs_path
                )
                # 设置找到的 nvram 函数名
                print(f"    - setting found nvram functions: {', '.join(found_funcs)}")
                self.nvram_server.set_found_funcs(found_funcs)
            except Exception as e:
                print(f"    ! failed to initialize NvramServer: {e}")
        elif self.no_services:
            print("    - NvramServer is disabled due to --no_services flag")

    def initial_setup(self, fs_path, binary_path):

        # Store paths as instance variables
        self.fs_path = fs_path
        self.binary_path = binary_path

        # get architecture involved
        full_path = os.path.join(fs_path, binary_path)
        full_path = str(pathlib.Path(full_path).resolve()) # handle symlinks
        print("Checking binary at ", full_path)
        sp = subprocess.run(["file", full_path], stdout=PIPE, stderr=PIPE)
        stdout = sp.stdout
        print("    - ", stdout)
        self.arch = Fixer.get_arch_from_file_command(stdout)
        self.clibc = Fixer.get_clib_from_file_command(stdout)
        if self.arch is None:
            print("    - ERROR: unsupported arch", stdout)
            return False
        self.qemu_arch = ARCH_MAP[self.arch]

        # copy relevant qemu static
        self.qemu_run_path = self.copy_qemu_user_static(self.arch, fs_path)

        #chmod +rw entire directory so its editable
        sp = subprocess.run(["chmod", "-R", "a+rw", fs_path])

        # copy statically compiled helper binaries
        greenhousePath = os.path.join(fs_path, GREENHOUSE)
        iproutePath = os.path.join(self.gh_path, GH_IP)
        busyboxPath = os.path.join(self.gh_path, GH_BUSYBOX)
        iprouteDest =os.path.join(fs_path, GREENHOUSE, GH_IP)
        busyboxDest =os.path.join(fs_path, GREENHOUSE, GH_BUSYBOX)
        Files.mkdir(greenhousePath)
        Files.copy_file(iproutePath, iprouteDest)
        Files.copy_file(busyboxPath, busyboxDest)
        Files.touch_file(os.path.join(fs_path, "GREENHOUSE_WEB_CANARY"), root=fs_path) # create index page 'canary'

        # Check if gh_nvram folder exists and copy to fs_path
        gh_nvram_source = os.path.join(self.gh_path, "gh_nvram")
        if os.path.exists(gh_nvram_source) and os.path.isdir(gh_nvram_source):
            gh_nvram_dest = os.path.join(fs_path, NVRAM_KEY_VALUE_FOLDER)
            print(f"    - Found gh_nvram folder, copying from {gh_nvram_source} to {gh_nvram_dest}")
            # If destination exists, remove it first to avoid errors
            if os.path.exists(gh_nvram_dest):
                import shutil
                shutil.rmtree(gh_nvram_dest)
            Files.copy_directory(gh_nvram_source, gh_nvram_dest)

        # Check if filtered_init_scripts folder exists and handle filtered_init_scripts.txt
        init_scripts_path = os.path.join(self.gh_path, "init_files")
        if os.path.exists(init_scripts_path) and os.path.isdir(init_scripts_path):
            filtered_scripts_file = os.path.join(init_scripts_path, "filtered_init_scripts.txt")
            if os.path.exists(filtered_scripts_file):
                print(f"    - Found init_files folder with filtered_init_scripts.txt")
                with open(filtered_scripts_file, 'r') as f:
                    scripts = [line.strip() for line in f if line.strip()]
                for script_path in scripts:
                    # 去掉开头的 /，防止 join 时产生绝对路径
                    if script_path.startswith('/'):
                        script_path = script_path[1:]
                    # Source path in self.gh_path/init_scripts
                    source = os.path.join(init_scripts_path, script_path)
                    # Destination path in fs_path
                    dest = os.path.join(fs_path, script_path)
                    # Check if source exists
                    if os.path.exists(source):
                        # Create destination directory if it doesn't exist
                        dest_dir = os.path.dirname(dest)
                        if not os.path.exists(dest_dir):
                            print(f"    - Creating directory {dest_dir}")
                            Files.mkdir(dest_dir, root=fs_path, silent=True)
                        # Copy source to destination
                        print(f"    - Copying {source} to {dest}")
                    else:
                        print(f"    - Source {source} does not exist, skipping")
            
            # Copy banned_cmds.txt if it exists
            banned_cmds_file = os.path.join(init_scripts_path, "banned_cmds.txt")
            if os.path.exists(banned_cmds_file):
                dst_file = os.path.join(fs_path, "banned_cmds.txt")
                print(f"    - Copying banned_cmds.txt to {dst_file}")
                Files.copy_file(banned_cmds_file, dst_file)
            
            # Copy gh_nvram directory if it exists
            gh_nvram_dir = os.path.join(init_scripts_path, "gh_nvram")
            if os.path.exists(gh_nvram_dir) and os.path.isdir(gh_nvram_dir):
                dst_dir = os.path.join(fs_path, "gh_nvram")
                print(f"    - Copying gh_nvram directory to {dst_dir}")
                # If destination exists, remove it first
                if os.path.exists(dst_dir):
                    shutil.rmtree(dst_dir)
                Files.copy_directory(gh_nvram_dir, dst_dir)

        #chmod +x
        sp = subprocess.run(["chmod", "+x", self.qemu_run_path])
        sp = subprocess.run(["chmod", "+x", full_path])

        # initial environment setup
        self.setup_devfiles(fs_path)
        self.remove_reboots(fs_path)
        if not self.baseline_mode:
            self.setup_custom_libraries(fs_path)
        self.propgate_contents(fs_path)

        return True

    def setup_devfiles(self, fs_path):
        # setup dev files
        print("    - setup /dev and /ghdev files")
        Files.rm_target(os.path.join(fs_path, "dev", "null"))
        Files.rm_target(os.path.join(fs_path, "dev", "urandom"))
        Files.rm_target(os.path.join(fs_path, "dev", "random"))
        Files.touch_file(os.path.join(fs_path, "dev", "null"), root=fs_path, silent=True) # empty file
        Files.write_file(os.path.join(fs_path, "dev", "urandom"), RAND, root=fs_path, silent=True) # 'random' bytes for entropy
        Files.write_file(os.path.join(fs_path, "dev", "random"), RAND, root=fs_path, silent=True) # 'random' bytes for entropy
        Files.copy_directory(os.path.join(fs_path, "dev"), os.path.join(fs_path, "ghdev"))
        Files.copy_directory(os.path.join(fs_path, "proc"), os.path.join(fs_path, "ghproc"))
        Files.mkdir(os.path.join(fs_path, "ghtmp"))

        setup_dev_path = os.path.join(self.gh_path, "setup_dev.sh")
        setup_dev_dest = os.path.join(fs_path, "setup_dev.sh")
        Files.copy_file(setup_dev_path, setup_dev_dest)

    def remove_reboots(self, fs_path):
        # setup dev files
        print("    - removing reboot and shutdown scripts")
        reboot_files = self.find_files("reboot", fs_path, resolve_symlinks=False)
        shutdown_files = self.find_files("shutdown", fs_path, resolve_symlinks=False)
        dummy_script_path = os.path.join(self.gh_path, "dummy.sh")

        for rf in reboot_files:
            Files.rm_target(rf)
            Files.copy_file(dummy_script_path, rf)

        for sf in shutdown_files:
            Files.rm_target(sf)
            Files.copy_file(dummy_script_path, sf)


    def propgate_contents(self, fs_path):
        #NOTE: currently mostly found in tendas
        webroot_path = os.path.join(fs_path, "webroot_ro")
        if os.path.exists(webroot_path):
            dest = os.path.join(fs_path, "var")
            if not os.path.exists(dest):
                Files.mkdir(dest, root=fs_path)
            dest = os.path.join(dest, "webroot")
            if os.path.exists(dest):
                shutil.rmtree(dest)
            shutil.copytree(webroot_path, dest, symlinks=True)
            print("Created", dest)

    def find_library(self, libname, fs_path, resolve_symlinks=True, skip=[], file_cache=None):
        # 优先使用缓存
        if file_cache is not None:
            print("    - [Cache] Searching for library %s in file cache" % libname)
            for filename, paths in file_cache.items():
                # 对于库文件，允许版本化匹配
                if filename == libname or (libname.endswith('.so') and filename.startswith(libname)):
                    print("    - [Cache] Found library %s in file cache" % filename)
                    for lib_path in paths:
                        if lib_path not in skip and os.path.exists(lib_path):
                            print("    - [Cache] Using cached library: %s" % lib_path)
                            return lib_path
        
        # 缓存未命中时，使用原始方法
        print("    - [Cache] Cache miss for library %s, using original method" % libname)
        for root, dirs, files in os.walk(fs_path):
            for f in files:
                # 对于库文件，允许版本化匹配
                if f == libname or (libname.endswith('.so') and f.startswith(libname)):
                    lib_path = os.path.join(root, f)
                    if os.path.islink(lib_path):
                        if resolve_symlinks:
                            lib_path = str(pathlib.Path(lib_path).resolve()) # handle symlinks
                        if not lib_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                            while lib_path.startswith("/") or lib_path.endswith("/"):
                                lib_path = lib_path.strip("/")
                            lib_path = os.path.join(fs_path, lib_path)
                    if lib_path in skip:
                        continue
                    if not os.path.exists(lib_path):
                        continue
                    return lib_path
        return ""

    def find_file(self, filename, fs_path, include_backups=False, resolve_symlinks=True, skip=[]):
        for root, dirs, files in os.walk(fs_path):
            for f in files:
                if f == filename:
                    file_path = os.path.join(root, f)
                    if os.path.islink(file_path):
                        if resolve_symlinks:
                            file_path = str(pathlib.Path(file_path).resolve()) # handle symlinks
                        if not file_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                            while file_path.startswith("/") or file_path.endswith("/"):
                                file_path = file_path.strip("/")
                            file_path = os.path.join(fs_path, file_path)
                    if file_path in skip:
                        continue
                    if not os.path.exists(file_path):
                        continue
                    return file_path
                if include_backups:
                    for tag in BACKUP_TAGS:
                        if f.lower().endswith(filename.lower()+"."+tag):
                            file_path = os.path.join(root, f)
                            if os.path.islink(file_path):
                                if resolve_symlinks:
                                    file_path = str(pathlib.Path(file_path).resolve()) # handle symlinks
                                if not file_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                                    while file_path.startswith("/") or file_path.endswith("/"):
                                        file_path = file_path.strip("/")
                                    file_path = os.path.join(fs_path, file_path)
                            if file_path in skip:
                                continue
                            if not os.path.exists(file_path):
                                continue
                            return file_path
        return ""

    def find_webroot(self, fs_path):
        for root, dirs, files in os.walk(fs_path):
            for d in dirs:
                if d in WEBROOTS:
                    path = os.path.join(root, d)
                    relative_path = os.path.join("/", os.path.relpath(path, fs_path))
                    return relative_path
        return ""
    
    def find_files_with_extension(self, basename, extensions, fs_path, resolve_symlinks=True, skip=[]):
        found = []
        targets = [basename+"."+ext for ext in extensions]
        for root, dirs, files in os.walk(fs_path):
            for f in files:
                for t in targets:
                    if f == t:
                        file_path = os.path.join(root, f)
                        if os.path.dirname(file_path) == fs_path:
                            continue # skip files in 'root' dir
                        if os.path.islink(file_path):
                            if resolve_symlinks:
                                file_path = str(pathlib.Path(file_path).resolve()) # handle symlinks
                            if not file_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                                while file_path.startswith("/") or file_path.endswith("/"):
                                    file_path = file_path.strip("/")
                                file_path = os.path.join(fs_path, file_path)
                        if file_path in skip or file_path in found:
                            continue
                        if not os.path.exists(file_path):
                            continue
                        found.append(file_path)
        return found


    def find_files(self, filename, fs_path, include_backups=False, resolve_symlinks=True, skip=[]):
        found = []
        for root, dirs, files in os.walk(fs_path):
            for f in files:
                if f == filename:
                    file_path = os.path.join(root, f)
                    if os.path.dirname(file_path) == fs_path:
                        continue # skip files in 'root' dir
                    if os.path.islink(file_path):
                        if resolve_symlinks:
                            file_path = str(pathlib.Path(file_path).resolve()) # handle symlinks
                        if not file_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                            while file_path.startswith("/") or file_path.endswith("/"):
                                file_path = file_path.strip("/")
                            file_path = os.path.join(fs_path, file_path)
                    if file_path in skip or file_path in found:
                        continue
                    if not os.path.exists(file_path):
                        continue
                    found.append(file_path)
                if include_backups:
                    for tag in BACKUP_TAGS:
                        if f.lower().endswith(filename.lower()+"."+tag):
                            file_path = os.path.join(root, f)
                            if os.path.dirname(file_path) == fs_path:
                                continue # skip files in 'root' dir
                            if os.path.islink(file_path):
                                if resolve_symlinks:
                                    file_path = str(pathlib.Path(file_path).resolve()) # handle symlinks
                                if not file_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                                    while file_path.startswith("/") or file_path.endswith("/"):
                                        file_path = file_path.strip("/")
                                    file_path = os.path.join(fs_path, file_path)
                            if file_path in skip or file_path in found:
                                continue
                            if not os.path.exists(file_path):
                                continue
                            found.append(file_path)
        return found


    def find_files_ending_with(self, filename, fs_path, include_backups=False, resolve_symlinks=True, skip=[]):
        found = []
        for root, dirs, files in os.walk(fs_path):
            for f in files:
                if f.endswith(filename):
                    file_path = os.path.join(root, f)
                    if os.path.dirname(file_path) == fs_path:
                        continue # skip files in 'root' dir
                    if os.path.islink(file_path):
                        if resolve_symlinks:
                            file_path = str(pathlib.Path(file_path).resolve()) # handle symlinks
                        if not file_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                            while file_path.startswith("/") or file_path.endswith("/"):
                                file_path = file_path.strip("/")
                            file_path = os.path.join(fs_path, file_path)
                    if file_path in skip or file_path in found:
                        continue
                    if not os.path.exists(file_path):
                        continue
                    found.append(file_path)
                if include_backups:
                    for tag in BACKUP_TAGS:
                        if f.lower().endswith(filename.lower()+"."+tag):
                            file_path = os.path.join(root, f)
                            if os.path.dirname(file_path) == fs_path:
                                continue # skip files in 'root' dir
                            if os.path.islink(file_path):
                                if resolve_symlinks:
                                    file_path = str(pathlib.Path(file_path).resolve()) # handle symlinks
                                if not file_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                                    while file_path.startswith("/") or file_path.endswith("/"):
                                        file_path = file_path.strip("/")
                                    file_path = os.path.join(fs_path, file_path)
                            if file_path in skip or file_path in found:
                                continue
                            if not os.path.exists(file_path):
                                continue
                            found.append(file_path)
        return found

    def get_clib_from_file_command(outline):
        if b"uClibc" in outline:
            return "uclibc"
        elif b"GNU/Linux" in outline:
            return "glibc"
        elif b"musl" in outline:
            return "musl"
        return "glibc" #default


    def get_arch_from_file_command(outline):
        if b"64-bit" in outline:
            if b" ARM" in outline and b" LSB" in outline:
                return "arm64"
            elif b" x86-64" in outline:
                return "x86_64"
            elif b" MIPS" in outline and b" MSB" in outline:
                return "mips64"
            elif b" MIPS" in outline and b" LSB" in outline:
                return "mips64el"
        else:
            if b" ARM" in outline and b" MSB" in outline:
                return "armeb"
            elif b" ARM" in outline and b" LSB" in outline:
                return "arm"
            elif b" x86-64" in outline:
                return "x86_64"
            elif b" 80386" in outline:
                return "x86"
            elif b" MIPS" in outline and b" MSB" in outline:
                return "mips"
            elif b" MIPS" in outline and b" LSB" in outline:
                return "mipsel"
        return None

    def copy_qemu_user_static(self, arch, fs_path):
        qemu_binary = ARCH_MAP[arch]
        path = os.path.join(self.qemu_src_path, qemu_binary)
        target_path = os.path.join(fs_path, qemu_binary)

        print("    - Copying %s to %s" % (path, target_path))
        Files.copy_file(path, target_path)

        qemu_binary_oir = qemu_binary + "_ori"
        path_ori = os.path.join(self.qemu_src_path_ori, qemu_binary)
        target_path_ori = os.path.join(fs_path, qemu_binary_oir)

        print("    - Copying %s to %s" % (path_ori, target_path_ori))
        Files.copy_file(path_ori, target_path_ori)

        return target_path

    def setup_custom_libraries(self, fs_path):
        # make nvram ini
        self.nvram_init_path = os.path.join(fs_path, NVRAM_INIT)
        self.nvram_key_value_path = os.path.join(fs_path, NVRAM_KEY_VALUE_FOLDER)
        nvram_ref_path = os.path.join(self.nvram_faker_path, "conf", NVRAM_INIT)
        nvram_brand_path = os.path.join(self.nvram_faker_path, "conf", self.brand, NVRAM_INIT)
        Files.touch_file(self.nvram_init_path, root=fs_path)
        if not os.path.exists(self.nvram_key_value_path):
            Files.mkdir(self.nvram_key_value_path, root=fs_path)
            subprocess.run(["chmod", "-R", "a+rw", self.nvram_key_value_path])

        # copy in libnvram.so
        lib_path = os.path.join(fs_path, "lib")
        target_nvram_faker_path = os.path.join(self.nvram_faker_path, "lib", self.arch, self.clibc, "libnvram-faker.so")
        print("Using ", target_nvram_faker_path)
        shutil.copy(target_nvram_faker_path, lib_path)

        # backup and replace the original libnvram in case hook does not work
        real_libnvram_path = os.path.join(lib_path, "libnvram.so")
        if os.path.exists(real_libnvram_path):
            os.rename(real_libnvram_path, real_libnvram_path+".bak")
        shutil.copy(target_nvram_faker_path, real_libnvram_path)

        # read in reference nvram values
        if nvram_ref_path != "" and os.path.exists(nvram_ref_path):
            with open(nvram_ref_path, "r") as nvramIniFile:
                for line in nvramIniFile:
                    line = line.strip()
                    if len(line) > 0:
                        array = line.split("=")
                        key = array[0].strip()
                        value = array[1].strip()
                        self.nvram_map[key] = value
        nvramIniFile.close()

        if nvram_brand_path != "" and os.path.exists(nvram_brand_path):
            with open(nvram_brand_path, "r") as nvramIniFile:
                for line in nvramIniFile:
                    line = line.strip()
                    if len(line) > 0:
                        array = line.split("=")
                        key = array[0].strip()
                        value = array[1].strip()
                        self.nvram_brand_map[key] = value
        nvramIniFile.close()

    def update_nvram_map(self, new_values):
        if not new_values:
            print("    - invalid new_values for nvram_map: ", new_values)
            return

        print("    - updating nvram_map")
        for key, value in new_values.items():
            self.nvram_brand_map[key] = value

    def write_nvram(self, keys, changelog=[], fs_path=None, binary_path=None):
        # Use instance variables as defaults if parameters not provided
        if fs_path is None:
            fs_path = self.fs_path
        if binary_path is None:
            binary_path = self.binary_path
        for key in keys:
            key = key.strip().strip("/")
            if len(key) <= 0:
                print("    ! skipping empty key")
                continue
            if "/" in key:
                key = key.replace("/", "_")
            key_path = os.path.join(self.nvram_key_value_path , key)
            value = ""
            if key in self.nvram_brand_map.keys():
                value = self.nvram_brand_map[key]
                changelog.append("[ROADBLOCK] requires NVRAM KEY: %s"  % key)
                changelog.append("[ROADBLOCK] requires NVRAM VALUE: %s" %  value)
            elif key in self.nvram_map.keys():
                value = self.nvram_map[key]
                changelog.append("[ROADBLOCK] requires NVRAM KEY: %s"  % key)
                changelog.append("[ROADBLOCK] requires NVRAM VALUE: %s" %  value)
            else:
                # 使用 NvramServer 推测值
                if self.nvram_server and not self.no_services:
                    try:
                        print(f"    - predicting value for nvram key: {key}")
                        response = self.nvram_server.get_nvram_value(key)
                        if response:
                            # 解析 LLM 响应
                            parts = response.strip().split(" ")
                            if len(parts) == 2:
                                value_type, value = parts
                                # 只需要值部分
                                if "apmib_get" or "apmib_getDef" in self.found_funcs:
                                    type_map = {
                                        "bool": "0",
                                        "char": "1",
                                        "short": "2",
                                        "int": "3",
                                        "long long": "4"
                                    }
                                    if value_type in type_map:
                                        value = type_map[value_type] + value
                                    else:
                                        value = "1" + value
                                print(f"    - predicted value_type {value_type}, value: {value}")
                                changelog.append("[ROADBLOCK] requires NVRAM KEY: %s"  % key)
                                changelog.append("[ROADBLOCK] requires NVRAM VALUE: %s" %  value)
                    except Exception as e:
                        print(f"    ! failed to predict nvram value: {e}")
                elif self.no_services:
                    print("    - NvramServer is disabled due to --no_services flag, using empty value")
            
            print("    - adding nvram key: %s=%s" % (key, value))
            if os.path.isdir(key_path):
                print("    ! skipping invalid key", key)
                continue
            with open(key_path, "w") as keyFile:
                keyFile.write(value)
            keyFile.close()
        subprocess.run(["chmod", "-R", "a+rw", self.nvram_key_value_path])

        keylog = []
        with open(self.nvram_init_path, "r") as nvramFile:
            for line in nvramFile:
                line = line.strip()
                if line not in keylog:
                    keylog.append(line)
            for key in keys:
                if key not in keylog:
                    keylog.append(key)
        nvramFile.close()


        with open(self.nvram_init_path, "w") as nvramFile:
            for key in keylog:
                nvramFile.write(key+"\n")
        nvramFile.close()
        
        # 统计 NvramServer 的 token 消耗
        if self.nvram_server and not self.no_services:
            self.total_input_tokens += self.nvram_server.get_total_input_tokens()
            self.total_output_tokens += self.nvram_server.get_total_output_tokens()
            print(f"NvramServer Token Usage - Input: {self.nvram_server.get_total_input_tokens()}, Output: {self.nvram_server.get_total_output_tokens()}")

    def get_token_stats(self):
        """
        获取token统计信息
        """
        return {
            'input_tokens': self.total_input_tokens,
            'output_tokens': self.total_output_tokens,
            'total_tokens': self.total_input_tokens + self.total_output_tokens
        }

    def check_ip(self, ip):
        if len(ip) > 0:
            try:
                ipaddress.ip_address(ip)
                return True
            except ValueError:
                pass
        return False

    def get_ips_from_nvram(self):
        nvramIPfiles = []
        nvram_ips = []
        with open(self.nvram_init_path, "r") as nvramFile:
            for line in nvramFile:
                for iptag in NVRAM_IP_KEYS:
                    if iptag in line:
                        nvramIPfiles.append(line.strip())
        nvramFile.close()

        for key in nvramIPfiles:
            path = os.path.join(self.nvram_key_value_path, key)
            nvramVal = ""
            with open(path, "r") as nvramFile:
                nvramVal = nvramFile.read().strip()
            if len(nvramVal) > 0 and nvramVal not in nvram_ips and self.check_ip(nvramVal):
                nvram_ips.append(nvramVal)

        return nvram_ips



class Planter():

    def __init__(self, gh_path, scripts_path, qemu_src_path, brand, no_services=False):
        self.gh_path = gh_path
        self.gh_templates_path = os.path.join(self.gh_path, "templates")
        self.scripts_path = scripts_path
        self.qemu_src_path = qemu_src_path
        self.fixer = None
        self.brand = brand
        self.no_services = no_services
        self.indicators = ["/bin/sh", "/bin/busybox"]
        self.llm_init = ""
        self.file_cache = None  # 文件系统缓存

    def build_file_cache(self, fs_path):
        """
        预扫描文件系统，构建文件缓存
        """
        print("[GreenHouse] Building file system cache...")
        start_time = time.monotonic()
        
        file_cache = {}
        for root, dirs, files in os.walk(fs_path):
            for f in files:
                file_path = os.path.join(root, f)
                # 处理符号链接
                if os.path.islink(file_path):
                    try:
                        resolved_path = str(pathlib.Path(file_path).resolve())
                        # 确保路径在文件系统内
                        if not resolved_path.startswith(fs_path):
                            while resolved_path.startswith("/") or resolved_path.endswith("/"):
                                resolved_path = resolved_path.strip("/")
                            resolved_path = os.path.join(fs_path, resolved_path)
                        file_path = resolved_path
                    except:
                        pass
                
                # 按文件名缓存，如果存在则跳过
                filename = os.path.basename(f)
                if filename not in file_cache:
                    file_cache[filename] = [file_path]
                else:
                    file_path_ori = file_cache[filename]
                    file_name_ori = os.path.basename(file_path_ori[0])
                    if file_name_ori != filename or "GHTMPSTORE" in file_path_ori[0]:
                        file_cache[filename] = [file_path]
        
        self.file_cache = file_cache
        end_time = time.monotonic()
        print(f"[GreenHouse] File system cache built in {end_time - start_time:.2f} seconds")
        print(f"[GreenHouse] Cached {len(file_cache)} unique filenames")

    def identify_target_folder(self, extracted_path):
        found_fs = ""
        for root, dirs, subdirs in os.walk(extracted_path):
            dirs_sorted = sorted(dirs)
            for d in dirs_sorted:
            # if re.findall("^.*-root[-_0-9]*$", d):
                target_path = os.path.join(root, d)
                for target_root, target_dirs, target_files in os.walk(target_path):
                    for td in sorted(target_dirs):
                        if "bin" in td:
                            binfolder_path = os.path.join(target_root, td)
                            binfolder_path = os.path.realpath(binfolder_path)
                            if not binfolder_path.startswith(extracted_path):
                                continue
                            bin_files = os.listdir(binfolder_path)
                            for f in sorted(bin_files):
                                bin_path = os.path.join(target_root, td, f)
                                for indicator in self.indicators:
                                    if bin_path.endswith(indicator):
                                        full_path = str(pathlib.Path(bin_path).resolve()) # handle symlinks
                                        print("Checking arch of binary at ", full_path)
                                        if not os.path.exists(full_path):
                                            print("    - does not exist, skipping...")
                                            continue
                                        sp = subprocess.run(["file", full_path], stdout=PIPE, stderr=PIPE)
                                        stdout = sp.stdout
                                        print("    - ", stdout)
                                        arch = Fixer.get_arch_from_file_command(stdout)
                                        if arch in ARCH_MAP.keys():
                                            found_fs = target_root
                                            return found_fs
        return ""

    def unpack_image(self, img_path, fs_path_override, workspace=""):

        img_path = os.path.realpath(img_path)
        print("    - Unpacking image", img_path)
        image_name = os.path.basename(img_path)
        dir_name = os.path.dirname(img_path)
        if workspace:
            dir_base = os.path.basename(dir_name)
            dir_name = os.path.join(workspace, dir_base)
        extracted_name = "_"+image_name+".extracted"
        extracted_path = os.path.join(dir_name, extracted_name)

        if os.path.exists(extracted_path):
            print("Extracted directory %s already exists, skipping extraction" % extracted_path)
        else:
            curruser = getpass.getuser()
            binwalk_command = ["binwalk"]
            if curruser == "root":
                binwalk_command.extend(["--run-as=root"])
            binwalk_command.extend(["--preserve-symlinks", "-eMq", img_path, "-C", dir_name])
            subprocess.run(binwalk_command)
            time.sleep(1)

        fs_path = ""
        if fs_path_override != "":
            if os.path.exists(fs_path_override):
                print("    - Using known rootfs path", fs_path_override)
                fs_path = fs_path_override.rstrip("/")
                return fs_path
            else:
                print("known rootfs path %s does not exist, defaulting to search..." % fs_path_override)

        if os.path.exists(extracted_path):
            # make entire folder RWXtable
            print("Calling chmod  on", extracted_path)
            sp = subprocess.run(["chmod", "-R", "a+rwx", extracted_path])
            stdout = sp.stdout
            print("    - ", stdout)
            found_fs = self.identify_target_folder(extracted_path)
            if found_fs:
                # Process each directory level to handle multiple levels with special characters
                current_path = ""
                components = found_fs.split(os.sep)
                
                for i, component in enumerate(components):
                    # Handle absolute paths (first component is empty for paths starting with /)
                    if i == 0 and not component:
                        current_path = os.sep
                        continue
                    
                    # Skip other empty components
                    if not component:
                        continue
                    
                    # Process the component - replace spaces and special characters with underscores
                    new_component = re.sub(r'[\(\)\-\s]', '_', component)
                    
                    # Build the next path segment
                    if current_path:
                        next_path = os.path.join(current_path, new_component)
                        old_next_path = os.path.join(current_path, component)
                    else:
                        # First non-empty component (relative path)
                        next_path = new_component
                        old_next_path = component
                    
                    # Rename if needed
                    if new_component != component and os.path.exists(old_next_path):
                        print(f"Renaming directory from '{old_next_path}' to '{next_path}'")
                        os.rename(old_next_path, next_path)
                    
                    # Update current path
                    current_path = next_path
                
                fs_path = current_path
                print("Found root dir at %s" % fs_path)
                return fs_path

        else:
            print("ERROR %s does not exist!" % extracted_path)

        print("Unable to find a proper root directory for ", extracted_path)
        return ""

    def get_bg_scripts(self, fs_path, blacklist=[]):
        bg_scripts = dict()
        for binaryname, args in BACKGROUND_SCRIPTS.items():
            results = pathlib.Path(fs_path).rglob(binaryname)
            for ppath in results: # return first valid result
                if not ppath.is_symlink() and fs_path in str(ppath):
                    relative_path = "/"+str(ppath.relative_to(fs_path)).strip("/")
                    bg_scripts[relative_path] = args
                    break
        return bg_scripts

    def get_potential_binaries(self, rehost_type):
        if rehost_type == "HTTP":
            return POTENTIAL_HTTPSERV
        elif rehost_type == "UPNP":
            return POTENTIAL_UPNPSERV
        elif rehost_type == "DNS":
            return POTENTIAL_DNSSERV
        elif rehost_type == "DHCP":
            return POTENTIAL_DHCPSERV
        return "UNKNOWN"
    
    def is_network_facing_binary(self, binary):
        proj = angr.Project(binary)
        for sym in proj.loader.symbols:
            if "bind" in sym.name or "listen" in sym.name:
                return True
        return False    

    def extract_kernel_from_firmware(self, firmware_path, output_dir, firmae_path=None):
        """
        从固件中提取内核
        
        Args:
            firmware_path: 固件文件路径
            output_dir: 输出目录
            firmae_path: FirmAE的安装路径
            
        Returns:
            提取的内核文件路径
        """        
        kernel_path = None
        # 检查FirmAE的extractor.py是否存在
        firmae_extractor = os.path.join(firmae_path, "sources", "extractor", "extractor.py")
            
        if os.path.exists(firmae_extractor):
            print(f"    - Using FirmAE extractor to extract kernel")
            # 使用FirmAE的extractor.py提取内核，添加-sql参数
            extractor_command = [
                "python3", firmae_extractor,
                "-np",  # 禁用并行处理
                "-nf",  # 只提取内核，不提取文件系统
                firmware_path,
                output_dir
            ]
            
            # 执行提取命令
            subprocess.run(extractor_command, capture_output=True, text=True)
            
            # 查找提取的内核文件
            for file in os.listdir(output_dir):
                if file.endswith(".kernel"):
                    kernel_path = os.path.join(output_dir, file)
                    print(f"    - Extracted kernel using FirmAE extractor: {kernel_path}")
                    return kernel_path
            
        return kernel_path

    def extract_init_from_kernel(self, kernel_path):
        """
        从提取的内核中提取init信息
        
        Args:
            kernel_path: 内核文件路径
            
        Returns:
            从内核中提取的init路径列表
        """
        init_paths = []
        
        if not os.path.exists(kernel_path):
            print(f"    - Kernel file not found: {kernel_path}")
            return init_paths
        
        try:
            # 使用strings命令从内核中提取字符串
            result = subprocess.run(
                ["strings", kernel_path],
                capture_output=True,
                text=True
            )
            
            # 搜索包含"init=/"的字符串
            for line in result.stdout.split('\n'):
                line = line.strip()
                if "init=/" in line:
                    # 提取init路径
                    init_match = re.search(r'init=(/[^\s]+)', line)
                    if init_match:
                        init_path = init_match.group(1)
                        # 移除可能的引号
                        init_path = init_path.strip('"\'')
                        init_paths.append(init_path)
                        print(f"    - Found init path in kernel: {init_path}")
        except Exception as e:
            print(f"    - Error extracting init from kernel: {e}")
        
        # 去重
        return list(set(init_paths))

    def get_init(self, fs_path, kernel_path=None):
        # 搜集所有可能的init程序
        all_init_candidates = []
        
        # 从内核中提取init信息
        if kernel_path:
            kernel_init_paths = self.extract_init_from_kernel(kernel_path)
            for init_path in kernel_init_paths:
                # 转换为文件系统路径
                full_path = os.path.join(fs_path, init_path.lstrip('/'))
                print(f"    - Kernel init path: {init_path} -> Full path: {full_path}")
                # 检查路径是否存在且不是目录
                if os.path.exists(full_path) and not os.path.isdir(full_path):
                    all_init_candidates.append(full_path)
                else:
                    print(f"    - Kernel init path does not exist: {full_path}")
        
        # 先按POTENTIAL_INIT中的路径搜索具体文件
        for init_path in POTENTIAL_INIT:
            full_path = os.path.join(fs_path, init_path.lstrip('/'))
            if os.path.exists(full_path) and not os.path.isdir(full_path):
                all_init_candidates.append(full_path)
                
        # 若没搜索到则在fs_path搜索POTENTIAL_INIT_BASENAME的文件名
        if not all_init_candidates:  # 如果前面没有搜索到任何 init 候选
            for root, dirs, files in os.walk(fs_path, topdown=False):
                for name in files:
                    if name.lower() in [item.lower() for item in POTENTIAL_INIT_BASENAME]:
                        full_path = os.path.join(root, name)
                        all_init_candidates.append(full_path)
        
        # 去重但保持原始顺序
        seen = set()
        unique_init_candidates = []
        for candidate in all_init_candidates:
            if candidate not in seen:
                seen.add(candidate)
                unique_init_candidates.append(candidate)
        
        # 打印所有可能的init程序
        if unique_init_candidates:
            print("    - Found all potential init candidates:")
            for candidate in unique_init_candidates:
                print(f"        * {candidate}")
            # # 尝试使用LLM评估
            # llm_best = llm_evaluate_init_candidates(unique_init_candidates, fs_path)
            # if llm_best:
            #     self.llm_init = llm_best
            #     print(f"    - Found best init (LLM): {llm_best}")
            #     return llm_best
            # 选择第一个
            print(f"    - Selecting first candidate: {unique_init_candidates[0]}")
            return unique_init_candidates[0]
        else:
            print("    - No init candidates found")
            return ""
    
    def get_target_binary_and_init(self, fs_path, rehost_type, kernel_path=None):
        potential_binaries = self.get_potential_binaries(rehost_type)
        pot_targets = dict()
        bin_path_final = ""
        
        # 收集潜在的二进制文件
        for root, dirs, files in os.walk(fs_path, topdown=False):
            for name in files:
                if name.lower() in potential_binaries:
                    if name.lower() not in pot_targets.keys():
                        pot_targets[name.lower()] = []
                    pot_targets[name.lower()].append(os.path.join(root, name))

        print("Potential Binaries: " + str(pot_targets))
        # return "best" match in order listed in potential_binaries
        for binary in potential_binaries:
            if binary in pot_targets.keys():
                for bin_path in pot_targets[binary]:
                    sp = subprocess.run(
                        ["file", bin_path], stdout=PIPE, stderr=PIPE)
                    stdout = sp.stdout
                    details = stdout.split(b":")[1].strip()
                    if details.startswith(b"ELF "):
                        print("    - Found binary: %s" % bin_path)
                        bin_path_final = bin_path
                        break
                else:
                    continue
                break
            
        # 调用get_init函数获取init程序
        init_path_final = self.get_init(fs_path, kernel_path)

        return [bin_path_final, init_path_final]
    
    def get_target_binary(self, fs_path, rehost_type):
        potential_binaries = self.get_potential_binaries(rehost_type)
        pot_targets = dict()
        for root, dirs, files in os.walk(fs_path, topdown=False):
            for name in files:
                if name.lower() in potential_binaries:
                    if name.lower() not in pot_targets.keys():
                        pot_targets[name.lower()] = []
                    pot_targets[name.lower()].append(os.path.join(root, name))

        print("Potential Binaries: ", pot_targets)
        # return "best" match in order listed in potential_binaries
        for binary in potential_binaries:
            if binary in pot_targets.keys():
                for bin_path in pot_targets[binary]:
                    sp = subprocess.run(["file", bin_path], stdout=PIPE, stderr=PIPE)
                    stdout = sp.stdout
                    details = stdout.split(b":")[1].strip()
                    if details.startswith(b"ELF "):
                        print("    - Found binary: %s" % bin_path)
                        return bin_path
        return ""

    def get_mac_from_nvrams(self, fs_path):
        # heuristic for targets the require a specific mac address
        nvram_key_value_path = os.path.join(fs_path, NVRAM_KEY_VALUE_FOLDER)
        if os.path.exists(nvram_key_value_path):
            nvram_keys = os.listdir(nvram_key_value_path)
            for key in nvram_keys:
                key = key.strip()
                if key in MAC_NVRAM_KEYS:
                    keypath = os.path.join(nvram_key_value_path, key)
                    value = ""
                    if os.path.exists(keypath):
                        with open(keypath, "r") as vFile:
                            value = vFile.read().strip()
                            match = re.match(r"[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}", value)
                            if match is not None:
                                value = match.group(0)
                        vFile.close()
                    else:
                        print("    - unable to open keypath", keypath)
                    if len(value) > 0:
                        return value
        return ""

    def setup_env(self, qemu_src_path, fs_path, bin_path, baseline_mode):
        self.fixer = Fixer(qemu_src_path, self.gh_path, self.scripts_path, self.brand, baseline_mode, self.no_services)
        r = self.fixer.initial_setup(fs_path, bin_path)
        return r 

    def check_cwd(self, fs_path, targets, old_cwd, cwd_rh_replaced, already_success):
        if cwd_rh_replaced or already_success:
            print("    - already got correct directory, skipping...")
            return False, old_cwd
        relative_targets = []
        for target in targets:
            if not target.startswith("/") and target not in relative_targets:
                relative_targets.append(target)

        cwds = dict()
        for target in relative_targets:
            # skip none html and cgi files, we can pretty much copy everything else
            ext = target.split(".")[-1]
            if ext not in WEB_EXTS:
                continue
            # check if file might exists somewhere else
            path = os.path.join(fs_path, target)
            sourcefiles = self.fixer.find_files(os.path.basename(target), fs_path, include_backups=True, skip=[path])
            for sourcefile in sourcefiles:
                print("target", target, "source", sourcefile)
                if len(sourcefile) > 0:
                    cwd_path = os.path.dirname(sourcefile)
                    relative_path = os.path.relpath(cwd_path, fs_path)
                    if relative_path not in cwds and relative_path != ".":
                        cwds[relative_path] = 0
                    if relative_path != ".":
                        print("    - adding relative path", target)
                        cwds[relative_path] += 1

        if len(cwds) <= 0:
            print("No relative cwd targets found")
            return False, old_cwd

        # else len(cwds) > 1:
        print("More than one possible CWD: ", cwds)
        majority_cwds = []
        highest = 0
        for k, v in cwds.items():
            if v > highest:
                majority_cwds.clear()
                highest = v
            if v >= highest:
                majority_cwds.append(k)
        cwds_sorted = sorted(majority_cwds, key=lambda x: ("www" not in x and "web" not in x and "htm" in x, x.count('/'), len(x), x))
        cwd_path = cwds_sorted[0]
        print("CWD target found", cwd_path)
        return True, cwd_path

    def add_interfaces(self, interfaces, urls):
        # we rebuild the interface <-> ip address mapping each time
        # just to be safe
        new_urls = []
        noninterface_urls = []
        iface_cmds = []
        for url in urls:
            fields = url.split(".")
            if fields[0] == "172":
                id = int(fields[1])
                if id >= 100 and id < 200:
                    # is a special interface, skip
                    continue
            noninterface_urls.append(url)

        i = 1
        for iface in interfaces:
            url = ""
            url = "172.%s.0.1" % (100+i)
            if i > 100:
                print("ERROR - too many interfaces. skipping extra interface")
                continue
            # index of iface matches index in urls
            new_urls.append(url)
            iface_cmds.append("/greenhouse/ip link set eth%d down" % i)
            iface_cmds.append("/greenhouse/ip link set eth%d name %s" % (i, iface))
            iface_cmds.append("/greenhouse/ip link set %s up" % iface)            
            i += 1
        new_urls.extend(noninterface_urls)
        
        return new_urls, iface_cmds

    def get_subnet(self, ipaddr, netmask="255.255.255.0"):
        subnet_string = "%s/%s" % (ipaddr, netmask)
        subnet = ""
        try:
            subnet = str(ipaddress.ip_interface(subnet_string).network)
        except:
            pass
        return subnet

    def parse_ips(self, ip_targets_path, ip_addrs, old_ips=[]):
        # script = "#!/bin/sh\n\n"
        # count = 0
        new_ips = []
        in_use_subnets = []

        # check in use ips
        adapters = ifaddr.get_adapters()
        for adapter in adapters:
            for ip in adapter.ips:
                in_use_subnet = self.get_subnet(ip.ip)
                if len(in_use_subnet) > 0:
                    in_use_subnets.append(in_use_subnet)

        for ip in ip_addrs:
            subnet = self.get_subnet(ip)
            if ip not in RESERVED_IPS and \
               ip not in old_ips and \
               not ip.startswith("255.") and \
               not ip.endswith(".255") and \
               not ip.endswith(".0") and \
               subnet not in in_use_subnets:
                print("    - adding ip device %s" % ip)
                new_ips.append(ip)

        # update ip targets
        with open(ip_targets_path, "w+") as ipFile:
            for ip in old_ips:
                ipFile.write(ip+"\n")
            for ip in new_ips:
                ipFile.write(ip+"\n")
        ipFile.close()

        return new_ips

    def parse_ports(self, ports_path, ports, old_ports=[]):
        # script = "#!/bin/sh\n\n"
        # count = 0
        new_ports = []
        for p in ports:
            if p not in old_ports and p not in PORTS_BLACKLIST:
                print("    - adding port target %s" % p)
                new_ports.append(p)

        # update ip targets
        with open(ports_path, "w+") as portFile:
            for p in old_ports:
                if p not in PORTS_BLACKLIST:
                    portFile.write(p+"\n")
            for p in new_ports:
                if p not in PORTS_BLACKLIST:
                    portFile.write(p+"\n")
        portFile.close()

        return new_ports


    def get_ips_from_nvram(self):
        return self.fixer.get_ips_from_nvram()

    def find_sourcefile(self, target, fs_path, path):
        target_name = os.path.basename(target)
        
        # 优先使用缓存
        if self.file_cache is not None:
            print("    - [Cache] Searching for %s in file cache" % target_name)
            if target_name in self.file_cache:
                print("    - [Cache] Found %s in file cache" % target_name)
                for file_path in self.file_cache[target_name]:
                    if file_path != path and os.path.exists(file_path):
                        print("    - [Cache] Using cached file: %s" % file_path)
                        return file_path
            
            # 处理备份文件
            for tag in BACKUP_TAGS:
                backup_name = target_name + "." + tag
                if backup_name in self.file_cache:
                    print("    - [Cache] Found backup %s in file cache" % backup_name)
                    for file_path in self.file_cache[backup_name]:
                        if file_path != path and os.path.exists(file_path):
                            print("    - [Cache] Using cached backup file: %s" % file_path)
                            return file_path
            
            # 处理htm和html等效的情况
            if (target.endswith(".html") or target.endswith(".htm")):
                targetbasename = target_name.rsplit(".")[0]
                for ext in [".htm", ".html"]:
                    alt_name = targetbasename + ext
                    if alt_name in self.file_cache:
                        print("    - [Cache] Found alternative %s in file cache" % alt_name)
                        for file_path in self.file_cache[alt_name]:
                            if file_path != path and os.path.exists(file_path):
                                print("    - [Cache] Using cached alternative file: %s" % file_path)
                                return file_path
                    # 处理备份文件
                    for tag in BACKUP_TAGS:
                        backup_name = alt_name + "." + tag
                        if backup_name in self.file_cache:
                            print("    - [Cache] Found backup %s in file cache" % backup_name)
                            for file_path in self.file_cache[backup_name]:
                                if file_path != path and os.path.exists(file_path):
                                    print("    - [Cache] Using cached backup file: %s" % file_path)
                                    return file_path
            
            # 处理conf, config和cnf等效的情况
            if (target.endswith(".conf") or target.endswith(".cnf") or target.endswith(".config")):
                targetbasename = target_name.rsplit(".")[0]
                for ext in [".config", ".conf", ".cnf"]:
                    alt_name = targetbasename + ext
                    if alt_name in self.file_cache:
                        print("    - [Cache] Found alternative %s in file cache" % alt_name)
                        for file_path in self.file_cache[alt_name]:
                            if file_path != path and os.path.exists(file_path):
                                print("    - [Cache] Using cached alternative file: %s" % file_path)
                                return file_path
                    # 处理备份文件
                    for tag in BACKUP_TAGS:
                        backup_name = alt_name + "." + tag
                        if backup_name in self.file_cache:
                            print("    - [Cache] Found backup %s in file cache" % backup_name)
                            for file_path in self.file_cache[backup_name]:
                                if file_path != path and os.path.exists(file_path):
                                    print("    - [Cache] Using cached backup file: %s" % file_path)
                                    return file_path
        
        # 缓存未命中时，使用原始方法
        print("    - [Cache] Cache miss for %s, using original method" % target_name)
        sourcefile = self.fixer.find_file(target_name, fs_path, include_backups=True, skip=[path])

        # handle edge case where htm and html are equivalent
        if len(sourcefile) <= 0 and (target.endswith(".html") or target.endswith(".htm")):
            targetbasename = os.path.basename(target.rsplit(".")[0])
            sourcefiles = self.fixer.find_files_with_extension(targetbasename, [".htm", ".html"], fs_path, skip=[path])
            for sf in sourcefiles:
                if sf.endswith(targetbasename):
                    sourcefile = sf
                    break
                else:
                    sourcefile = sf
        
        # handle edge case where conf, config and cnf are equivalent
        if len(sourcefile) <= 0 and (target.endswith(".conf") or target.endswith(".cnf") or target.endswith(".config")):
            targetbasename = os.path.basename(target.rsplit(".")[0])
            sourcefiles = self.fixer.find_files_with_extension(targetbasename, [".config", ".conf", "cnf"], fs_path, skip=[path])
            for sf in sourcefiles:
                if sf.endswith(targetbasename):
                    sourcefile = sf
                    break
                else:
                    sourcefile = sf
        return sourcefile

    def transplant(self, fs_path, targets, folders, configs, failed, already_success, no_skip, hackdevproc, changelog):
        print("    - processing nvram configs")
        self.fixer.write_nvram(configs, changelog)

        if already_success:
            print("    - already successful, focusing on get working nvrams up")
            return

        # 构建文件系统缓存，避免重复遍历
        if self.file_cache is None:
            self.build_file_cache(fs_path)

        for folder in folders:
            if folder in failed:
                failed.remove(folder)
            
            while folder.startswith("/") or folder.endswith("/"):
                folder = folder.strip("/")
            path = os.path.join(fs_path, folder)
            print("[] Making folder ", path)
            if os.path.exists(path) and os.path.isdir(path):
                print("    - folder exists, skip!")
                continue
            Files.mkdir(path, root=fs_path, silent=True)
            rb = "[ROADBLOCK] requires missing directory"
            if rb not in changelog:
                changelog.append(rb)
            changelog.append("[GreenHouse] MKDIR: %s"  % path)

        skipped = []
        for target in targets:

            target = "".join(filter(lambda x: x in string.printable, target))
            print("[GreenHouse] target: ", target)
            if target in failed:
                failed.remove(target)

            if not target.startswith("/"):
                print("    - target is a relative CWD, skip!")
                continue

            if hackdevproc and target.startswith("/proc/"):
                oldtarget = target
                target = target[6:]
                target = os.path.join("/ghproc", target)
                print("    - switching %s to %s" % (oldtarget, target))

            if hackdevproc and target.startswith("/dev/"):
                oldtarget = target
                target = target[5:]
                target = os.path.join("/ghdev", target)
                print("    - switching %s to %s" % (oldtarget, target))

            while target.startswith("/") or target.endswith("/"):
                target = target.strip("/")
            path = os.path.join(fs_path, target)
            path = str(pathlib.Path(path).resolve()) # handle symlinks

            if os.path.isdir(path):
                print("    ! target %s is directory, skipping" % path)
                continue # skip transplanting full directories

            # handle edge case where symlink resolves to host machine path
            if fs_path not in path:
                path = os.path.join(fs_path, path.strip("/"))
            dirname = os.path.dirname(path)

            # create target folder env
            if not os.path.exists(dirname):
                Files.mkdir(dirname, root=fs_path, silent=True)
                rb = "[ROADBLOCK] requires missing directory"
                if rb not in changelog:
                    changelog.append(rb)
                changelog.append("[GreenHouse] MKDIR: %s"  % dirname)

            # pid files should be created by the process, however we want to
            # create the root directories they are in
            if target.endswith(".pid") and target not in no_skip:
                print("    - target is a PID file, skip!")
                if target not in skipped:
                    skipped.append(target)
                continue

            if target.startswith("tmp/") and target not in no_skip:
                print("    - target is a /tmp/ file, skip!")
                if target not in skipped:
                    skipped.append(target)
                continue

            # check if file might exists somewhere else we can copy
            sourcefile = self.find_sourcefile(target, fs_path, path)
            # target_name = os.path.basename(path)
            # sourcefile = self.find_sourcefile(target_name, fs_path, path)
            if len(sourcefile) <= 0:
                # try looking in templates
                sourcefile = self.find_sourcefile(target, self.gh_templates_path, path)
                # sourcefile = self.find_sourcefile(target_name, self.gh_templates_path, path)

            # transplant file
            if len(sourcefile) > 0:
                print("    - Found backup, copying from %s to %s" % (sourcefile, path))
                Files.touch_file(path, root=fs_path, silent=True) # create folders to path
                Files.rm_file(path, silent=True) # rm basefile so it can be copied over
                if os.path.isdir(sourcefile):
                    print("    ! backup is a directory, skipping.")
                    continue
                Files.copy_file(sourcefile, path, silent=True)
            elif os.path.basename(path).startswith("ld-musl") and os.path.basename(path).endswith(".path"):
                # handle ld-musl .path file special case
                # Files.write_file(path, MUSL_LD_DEFAULT) # 'random' bytes for entropy
                print("    ! ld-musl-arch.path file, skipping.")
                # currently we skip handling this
                continue
            else:
                print("    - Creating file ", path)
                Files.touch_file(path, root=fs_path, silent=True)
                rb = "[ROADBLOCK] requires missing file"
                if rb not in changelog:
                    changelog.append(rb)
                changelog.append("[GreenHouse] MKFILE: %s"  % path)

        # handle special cases
        cache = set()
        for f in failed:
            # dont repeat work
            if f in cache:
                continue
            cache.add(f)

            # process
            while f.startswith("/") or f.endswith("/"):
                f = f.strip("/")
            target_path = os.path.join(fs_path, f)
            target_path = str(pathlib.Path(target_path).resolve()) # handle symlinks
            # try:
            #     target_path = str(pathlib.Path(target_path).resolve()) # handle symlinks
            # except FileNotFoundError:
            #     # 符号链接存在但目标不存在，保持原始路径
            #     pass
            if fs_path not in target_path:
                while target_path.startswith("/") or target_path.endswith("/"):
                    target_path = target_path.strip("/")
                target_path = os.path.join(fs_path, target_path)
            libpath = self.fixer.find_library(os.path.basename(f), fs_path, skip=[target_path], file_cache=self.file_cache)
            print("    - [Greenhouse] Processing failed lib %s" % f)
            if len(libpath) > 0 and os.path.exists(libpath):
                print("    - Found misplaced library %s, moving to %s" % (libpath, target_path))
                print("    - copying from", libpath)
                dirPath = os.path.dirname(target_path)
                if not os.path.exists(dirPath) or not os.path.isdir(dirPath):
                    Files.mkdir(dirPath, root=fs_path, silent=True)
                if os.path.exists(target_path) or os.path.islink(target_path):
                    Files.rm_file(target_path, silent=True)
                if os.path.exists(libpath):
                    Files.copy_file(libpath, target_path, silent=True)
                    if len(targets) <= 0:
                        targets.add(".") # dummy trigger so we loop at least one more time
                    rb = "[ROADBLOCK] requires missing library"
                    if rb not in changelog:
                        changelog.append(rb)
                    changelog.append("[GreenHouse] FIXLIB: %s"  % target_path)
                else:
                    print("    - %s missing. Skipping..." % libpath)

                continue
            elif "libc.so" in f:
                libpath = self.fixer.find_library("libc.so.", fs_path)
                target_path = os.path.join(fs_path, f)
                if libpath:
                    print("Fixing special case for missing libc.so.6 with a hack...")
                    print("    - copying from", libpath)
                    dirPath = os.path.dirname(target_path)
                    if not os.path.exists(dirPath):
                        Files.mkdir(dirPath, root=fs_path, silent=True)
                    Files.copy_file(libpath, target_path, silent=True)
                    targets.add(".") # dummy trigger so we loop at least one more time
                    rb = "[ROADBLOCK] requires missing library"
                    if rb not in changelog:
                        changelog.append(rb)
                    changelog.append("[GreenHouse] FIXLIB: %s"  % target_path)

        return skipped

    def setup_cl_args(self, brand, fs_path, full_binary_path, changelog, extra_args=[], rehost_type="HTTP"):
        if not os.path.exists(full_binary_path):
            print("    - error, no binary found at [%s]" % full_binary_path)
            return []

        cl_args = []
        has_httpd_conf_args = False
        has_cert_args = False
        DEFAULT_IP = "0.0.0.0"
        if rehost_type == "HTTP":
            DEFAULT_PORT = 80
        elif rehost_type == "UPNP":
            DEFAULT_PORT = 1900
        elif rehost_type == "DNS":
            DEFAULT_PORT = 53
        else:
            print("   - unknown rehost type %s, defaulting to port 80" % rehost_type)
            DEFAULT_PORT = 80

        print("Setting up cmd line args...")

        with open(full_binary_path, "rb") as bFile:
            data = bFile.read()
            has_httpd_conf_args = re.findall(b"(?=[ -~\s]*-[fc])(?=[ -~\s]*[Cc]onfiguration)[ -~\s]*", data)
            if not has_httpd_conf_args:
                has_httpd_conf_args = re.findall(b"(?=[ -~\s]*-[fc])(?=[ -~\s]*[Cc]onfig\-file)[ -~\s]*", data)
            has_webroot_args = re.findall(b"(?=[ -~\s]*-h)(?=[ -~\s]*document root)[ -~\s]*", data)
            has_cert_args = re.findall(b"-E cert", data)
            has_port_args = re.findall(b"-p [ -,.-~\s]*port", data)
            has_ext_if_args = re.findall(b"-i ext_ifname", data)
        bFile.close()

        if has_port_args:
            cl_args.append("-p %d" % (DEFAULT_PORT))

        if has_ext_if_args:
            cl_args.append("-d -i %s" % (DEFAULT_IP))

        if has_httpd_conf_args:
            flag = ""
            for results in has_httpd_conf_args:
                for line in results.splitlines():
                    if b"configuration" in line or b"Configuration" in line or b"onfig-file" in line:
                        if b"-c" in line:
                            flag = "-c"
                            break
                        elif b"-f" in line:
                            flag = "-f"
                            break
                        else:
                            flag = ""
                if flag != "":
                    break
            if len(flag) > 0:
                sourcefiles = self.fixer.find_files_ending_with(".conf", fs_path, include_backups=True, skip=[])
                sourcefile = ""
                binary_basename = os.path.basename(full_binary_path)
                for sf in sourcefiles:
                    if binary_basename in sf:
                        sourcefile = sf
                        break

                if sourcefile and fs_path in sourcefile:
                    sourcefile_basename = os.path.basename(sourcefile)
                    dest =  os.path.join(fs_path, sourcefile_basename)

                    if os.path.exists(dest):
                        print("Conf file exists at destination, skipping copy...")
                    else:
                        print("    - Copying %s to %s" % (sourcefile, dest))
                        Files.copy_file(sourcefile, dest)

                    relative_path = os.path.relpath(dest, fs_path)
                    add_arg = True
                    for arg in extra_args.split():
                        if relative_path in arg:
                            add_arg = False

                    if not relative_path.startswith("/"):
                        relative_path = "/"+relative_path

                    if add_arg:
                        cl_args.append("%s %s" % (flag, relative_path))
                    else:
                        print("    - %s already in extra_args, continuing" % relative_path)
                else:
                    print("    - no source found for config arg. Skip adding it as an extra arg")

        if has_webroot_args:
            webroot = self.fixer.find_webroot(fs_path)
            if len(webroot) > 0:
                webroot = webroot.strip("/")
                print("    - found relative webroot", webroot)
                webroot_name = os.path.basename(webroot)
                webroot_link_path = os.path.join(fs_path, webroot_name)
                print("    - linking %s to %s" % (webroot_link_path, webroot))
                Files.mk_link(webroot_link_path, webroot, relative_dir=fs_path)
                cl_args.append("-h %s" % (webroot_name))
                rb = "[ROADBLOCK] requires webroot argument"
                if rb not in changelog:
                    changelog.append(rb)
                changelog.append("[GreenHouse] MISSING WEBROOT: %s"  % webroot)

        if has_cert_args and brand == "netgear":
            cafile = self.fixer.find_file("ca.pem", fs_path, include_backups=True, skip=[])
            httpsdfile = self.fixer.find_file("httpsd.pem", fs_path, include_backups=True, skip=[])

            cabaseName = ""
            if cafile and fs_path in cafile:
                sourcefile = cafile
                cabaseName = os.path.basename(cafile)
            else:
                sourcefile = os.path.join(self.gh_path, "openssl", "ca.pem")
                cabaseName = os.path.basename("ca.pem")
                rb = "[ROADBLOCK] requires missing cert"
                if rb not in changelog:
                    changelog.append(rb)
                changelog.append("[GreenHouse] MISSING CERT: %s"  % cabaseName)
            dest = os.path.join(fs_path, cabaseName)

            if os.path.exists(dest):
                print("    - %s file exists at destination, skipping copy..." % cabaseName)
            else:
                print("    - Copying %s to %s" % (sourcefile, dest))
                Files.copy_file(sourcefile, dest)

            httpsdbaseName = ""
            if httpsdfile and fs_path in httpsdfile:
                sourcefile = httpsdfile
                httpsdbaseName = os.path.basename(httpsdfile)
            else:
                sourcefile = os.path.join(self.gh_path, "openssl", "httpsd.pem")
                httpsdbaseName = os.path.basename("httpsd.pem")
                rb = "[ROADBLOCK] requires missing cert"
                if rb not in changelog:
                    changelog.append(rb)
                changelog.append("[GreenHouse] MISSING CERT: %s"  % httpsdbaseName)
            dest = os.path.join(fs_path, httpsdbaseName)

            if os.path.exists(dest):
                print("    - %s file exists at destination, skipping copy..." % httpsdbaseName)
            else:
                print("    - Copying %s to %s" % (sourcefile, dest))
                Files.copy_file(sourcefile, dest)

            cl_args.append("-S -E %s %s" % (cabaseName, httpsdbaseName))

        print("    - cl_args:", cl_args)
        print("done!")
        return cl_args

    def get_qemu_run_path(self):
        if self.fixer == None:
            return ""
        return self.fixer.qemu_run_path

    def get_qemu_arch(self):
        if self.fixer == None:
            return ""
        return self.fixer.qemu_arch

    def clean_fs(self, target_fs):
        # cleanup special files that might have been created:
        target_fs = os.path.realpath(target_fs)
        print("    - cleaning", target_fs)
        for root, dirs, files in os.walk(target_fs, topdown=False):
            for f in files:
                fpath = os.path.join(root, f)
                fpath = os.path.realpath(fpath)
                if os.path.exists(fpath) and fpath.startswith(target_fs):
                    st_mode = os.stat(fpath).st_mode
                    if stat.S_ISBLK(st_mode) or stat.S_ISCHR(st_mode) or stat.S_ISSOCK(st_mode) or stat.S_ISFIFO(st_mode):
                        print("    - replacing special file", fpath)
                        os.unlink(fpath)
                        if not (stat.S_ISSOCK(st_mode) or stat.S_ISBLK(st_mode) or stat.S_ISCHR(st_mode)):
                            # do not recreate sock files
                            # blk and chr device creation handled by script now
                            os.mknod(fpath)
                if f.endswith(".conf"):
                    # remove Interface tags from configuration files
                    if os.path.exists(fpath):
                        lines = []
                        with open(fpath, "r", encoding="utf-8", errors="surrogateescape") as confFile:
                            for line in confFile:
                                if "Interface " in line or "Interface:" in line:
                                    print("    - removing line", line, "from confFile", fpath)
                                    continue
                                lines.append(line)
                        confFile.close()

                        with open(fpath, "w", encoding="utf-8", errors="surrogateescape") as confFile:
                            for line in lines:
                                confFile.write(line)
                        confFile.close()
        
        # 需要检查的符号链接基本名称列表
        important_dirs = {"etc", "usr", "var", "dev", "home", "mnt", "www", "etc_ro", "tmp", "run", "sys", "proc", "media", "root"}
        # 只检查第一层文件夹
        for item in os.listdir(target_fs):
            item_path = os.path.join(target_fs, item)
            if os.path.islink(item_path):
                basename = os.path.basename(item_path)
                if basename in important_dirs:
                    link_target = os.readlink(item_path)
                    link_target = os.path.join(target_fs, link_target.lstrip('/'))
                    print(f"Symlink {item_path} points to {link_target}")
                    # 若符号连接的目标路径不存在，则创建
                    if not os.path.exists(link_target):
                        print(f"Creating symlink target: {link_target}")
                        try:
                            os.makedirs(link_target, exist_ok=True)
                            print(f"Successfully created: {link_target}")
                        except Exception as e:
                            print(f"Error creating {link_target}: {e}")
                    else:
                        print(f"Symlink target already exists: {link_target}")
