import io
import os
import socket
import json
import tarfile
import zipfile
import argparse
import subprocess
import time
import re
import docker
import threading
from collections import defaultdict
from openai import OpenAI, APIError, APIConnectionError, RateLimitError, AuthenticationError, BadRequestError
import sys
import glob

# LLM请求锁文件前缀
LLM_LOCK_PREFIX = "/tmp/llm_request_"

class ReverseClient:
    """
    逆向分析客户端类

    负责连接服务器，发送二进制文件，接收分析结果
    """

    def __init__(self, host='localhost', port=8888):
        """
        初始化客户端

        Args:
            host (str): 服务器地址，默认 'localhost'
            port (int): 服务器端口，默认 8888
        """
        self.host = host
        self.port = port

    def send_binary_for_analysis(self, binary_path, reverse_dir):
        """
        发送二进制文件进行逆向分析

        Args:
            binary_path (str): 二进制文件路径

        Raises:
            Exception: 连接或传输错误
        """
        filename = os.path.basename(binary_path)
        filesize = os.path.getsize(binary_path)

        try:
            # 连接服务器
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.host, self.port))
                print(f"[ReverseClient] Connected to server {self.host}:{self.port}")

                # 发送文件信息
                file_info = {
                    "filename": filename,
                    "filesize": filesize
                }
                file_info_data = json.dumps(file_info).encode('utf-8')
                s.send(len(file_info_data).to_bytes(8, 'big'))
                s.send(file_info_data)

                # 发送文件内容
                print(f"[ReverseClient] Sending file: {filename} ({filesize} bytes)")
                with open(binary_path, 'rb') as f:
                    while True:
                        chunk = f.read(4096)
                        if not chunk:
                            break
                        s.send(chunk)
                print("[ReverseClient] File sending completed")

                # 接收响应
                response_data = self.receive_reverse_metadata(s)
                response = json.loads(response_data.decode('utf-8'))

                if "error" in response:
                    raise Exception(f"服务器错误: {response['error']}")

                result_filesize = response['filesize']
                result_filename = response['filename']

                print(f"[ReverseClient] Receiving result file: {result_filename} ({result_filesize} bytes)")

                # 确保文件夹存在
                if not os.path.exists(reverse_dir):
                    os.makedirs(reverse_dir)
                # 将压缩文件保存到该文件夹下
                output_path = os.path.join(reverse_dir, result_filename)

                self.receive_reverse_compressed_file(
                    s, output_path, result_filesize)
                print(f"[ReverseClient] Result saved to: {output_path}")

                # 自动解压结果文件
                extract_dir = self.extract_zip(output_path)
                print(f"[ReverseClient] Extraction result saved to: {extract_dir}")
                
                # Remove annotations from decompiled files
                self.remove_annotations(extract_dir)

                return extract_dir

        except Exception as e:
            print(f"[ReverseClient] Client error: {e}")
            raise

    def receive_reverse_metadata(self, socket_obj):
        """
        接收数据

        Args:
            socket_obj: socket对象

        Returns:
            bytes: 接收到的数据
        """
        length_bytes = socket_obj.recv(8)
        if not length_bytes:
            return None
        length = int.from_bytes(length_bytes, 'big')
        data = b''
        while len(data) < length:
            chunk = socket_obj.recv(min(4096, length - len(data)))
            if not chunk:
                return None
            data += chunk
        return data

    def receive_reverse_compressed_file(self, socket_obj, file_path, filesize):
        """
        接收文件

        Args:
            socket_obj: socket对象
            file_path: 保存文件的路径
            filesize: 文件大小
        """
        with open(file_path, 'wb') as f:
            received = 0
            while received < filesize:
                chunk = socket_obj.recv(min(4096, filesize - received))
                if not chunk:
                    break
                f.write(chunk)
                received += len(chunk)

    def extract_zip(self, zip_path, extract_dir=None):
        """
        解压结果文件

        Args:
            zip_path (str): ZIP文件路径
            extract_dir (str): 解压目录，可选，默认与ZIP文件相同目录

        Returns:
            str: 解压目录路径
        """
        if extract_dir is None:
            extract_dir = os.path.dirname(zip_path)

        print(f"[ReverseClient] Extracting result to: {extract_dir}")
        with zipfile.ZipFile(zip_path, 'r') as zipf:
            zipf.extractall(extract_dir)

        print("[ReverseClient] Extraction completed")

        # 删除压缩文件
        try:
            os.remove(zip_path)
            print(f"[ReverseClient] Compressed file deleted: {zip_path}")
        except OSError as e:
            print(f"[ReverseClient] Failed to delete compressed file: {e}")

        return extract_dir

    def remove_annotations(self, reverse_dir):
        """
        从逆向文件中移除所有注释行
        
        Args:
            reverse_dir (str): 逆向目录路径
        """
        # 遍历逆向目录下的所有.c文件
        for root, _, files in os.walk(reverse_dir):
            for file in files:
                if not file.endswith(".c"):
                    continue
                file_path = os.path.join(root, file)

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # 删除文件开头的 Hex-Rays 注释块
                    prefix = "/* This file was generated by the Hex-Rays decompiler"
                    if content.startswith(prefix):
                        end_pos = content.find("*/", len(prefix))
                        if end_pos != -1:
                            # 删除整个注释块及其后的换行符
                            content = content[end_pos + 2:].lstrip('\n')
                    # 按行分割以便后续处理
                    lines = content.splitlines(True)

                    # 过滤掉所有注释行（包括行尾 // 注释）
                    filtered_lines = []
                    for line in lines:
                        # 去掉行尾换行符，方便处理
                        stripped = line.rstrip('\n')
                        # 如果整行以 // 开头，直接跳过
                        if stripped.lstrip().startswith('//'):
                            continue
                        # 去掉行尾 // 及其后的内容
                        if '//' in stripped:
                            stripped = stripped[:stripped.index('//')]
                        # 如果整行只剩空白则跳过
                        if not stripped.strip():
                            continue
                        # 重新加回换行符
                        filtered_lines.append(stripped + '\n')

                    # 写回文件
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.writelines(filtered_lines)
                except Exception as e:
                    print(f"[ReverseClient] Error processing file {file_path}: {e}")

    def local_reverse_analysis(self, binary_path, reverse_dir):
        """
        在本地进行二进制文件逆向分析

        Args:
            binary_path (str): 二进制文件路径

        Returns:
            str: 结果文件夹路径

        Raises:
            FileNotFoundError: 文件不存在
            Exception: 逆向分析错误
        """
        import time
        import shutil
        import concurrent.futures

        filename = os.path.basename(binary_path)
        total_start_time = time.time()

        try:
            # 检查是否存在同名.i64文件，若存在则复用，否则生成
            i64_file = os.path.join(reverse_dir, f"{filename}.i64")

            # 获取IDA Pro脚本路径
            ida_script_path = "/ida/ida_pro_Hex_Ray_get_functions_name.py"

            if os.path.exists(i64_file):
                ida_cmd = f"/ida/idat64 -A -L{reverse_dir}/decompileC.log -S{ida_script_path} {i64_file} 2>/dev/null"
                result = subprocess.run(ida_cmd, shell=True, capture_output=True, text=True)
                print(f"[ReverseClient] IDA cmd executed: {ida_cmd}")
                print(f"[ReverseClient] IDA stdout: {result.stdout}")
                print(f"[ReverseClient] IDA stderr: {result.stderr}")
            else:
                ida_cmd = f"/ida/idat64 -A -L{reverse_dir}/decompileC.log -S{ida_script_path} -o{i64_file} {binary_path} 2>/dev/null"
                result = subprocess.run(ida_cmd, shell=True, capture_output=True, text=True)
                print(f"[ReverseClient] IDA cmd executed: {ida_cmd}")
                print(f"[ReverseClient] IDA stdout: {result.stdout}")
                print(f"[ReverseClient] IDA stderr: {result.stderr}")

            decompile_functions_name_path = os.path.join(
                reverse_dir, "functions_name.txt")
            if not os.path.exists(decompile_functions_name_path):
                raise Exception(f"{filename} 反编译失败，未生成函数列表{decompile_functions_name_path}")

            with open(decompile_functions_name_path, 'r', encoding='utf-8') as f:
                decompile_functions = f.read().splitlines()

            # 将函数列表分成 num_groups 组
            num_groups = 10
            filtered_functions = [
                func_name for func_name in decompile_functions if not func_name.startswith('.')]
            group_size = len(filtered_functions) // num_groups
            remainder = len(filtered_functions) % num_groups

            # 生成反编译脚本
            scripts = []
            for i in range(num_groups):
                start_idx = i * group_size + min(i, remainder)
                end_idx = (i + 1) * group_size + min(i + 1, remainder)
                group_funcs = filtered_functions[start_idx:end_idx]

                if not group_funcs:
                    continue

                # 为每组创建ida db独立副本，若多组同时反编译会导致ida db冲突
                group_i64 = os.path.join(
                    reverse_dir, f"{filename}_group_{i}.i64")
                if not os.path.exists(group_i64):
                    shutil.copy2(i64_file, group_i64)

                script_lines = ["#!/bin/sh"]
                for func_name in group_funcs:
                    cmd = f"/ida/idat64 -A -L{reverse_dir}/decompileC_{i}.log -Ohexrays:{reverse_dir}/{func_name}.c:{func_name} {group_i64} 2>/dev/null"
                    script_lines.append(cmd)

                script_content = "\n".join(script_lines)
                script_path = os.path.join(
                    reverse_dir, f"decompile_group_{i}.sh")
                scripts.append(script_path)

                with open(script_path, "w") as f:
                    f.write(script_content)
                os.chmod(script_path, 0o755)

            # 执行所有脚本
            print(f"[ReverseClient]    - Starting parallel execution of {len(scripts)} scripts...")
            results = []

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_to_script = {}
                for script in scripts:
                    future = executor.submit(
                        subprocess.run, ["/bin/sh", script], capture_output=True, text=True)
                    future_to_script[future] = script

                for future in concurrent.futures.as_completed(future_to_script):
                    script = future_to_script[future]
                    try:
                        result = future.result()
                        results.append(result)
                        if result.returncode == 0:
                            print(
                                f"[ReverseClient]    - 脚本执行完成: {os.path.basename(script)} (返回码: {result.returncode})")
                        else:
                            print(
                                f"[ReverseClient]    - 脚本执行完成: {os.path.basename(script)} (返回码: {result.returncode}) - 部分函数反编译失败!")
                    except Exception as e:
                        print(f"[ReverseClient]    - Script execution error: {os.path.basename(script)} - {e}")

            # 总时间结束
            total_end_time = time.time()
            total_duration = total_end_time - total_start_time
            print(f"[ReverseClient] Reverse analysis completed: {filename}")
            print(f"[ReverseClient] Total time consumed: {total_duration:.2f} seconds")
            print(f"[ReverseClient] Local reverse analysis results saved to: {reverse_dir}")
            
            # Remove annotations from decompiled files
            self.remove_annotations(reverse_dir)

        except Exception as e:
            print(f"[ReverseClient] Local reverse analysis error: {e}")
            raise

class NvramServer:
    """
    NVRAM LLM推理模块类

    负责监控指定容器内的/fs/msg_nvram.txt文件，
    从文件中获取<FUNTION_NAME>和<KEY>信息，
    从逆向文件中搜寻对应<FUNTION_NAME>到key_to_func_name.json文件中
    """

    def __init__(self, binary_path, fs_path,
                 reverse_host="10.201.169.58", reverse_port=9998, api_key="sk-o20HTjWDHvtm25HPmjfWgkrOdRDH79bXLRA3UGZDFPXTTYL5", model="qwen3-max"):
        self.reverse_dir = f"/tmp/{os.path.basename(binary_path)}_decompile"
        self.binary_path = binary_path
        self.fs_path = fs_path
        self.reverse_host = reverse_host
        self.reverse_port = reverse_port
        self.total_input_token = 0
        self.total_output_token = 0
        self.model = model
        self.nvram_dir = os.path.join(fs_path, "gh_nvram")
        self.consume_time = 0.0

        self._parsed_functions = set()
        self.key_to_func_name = {}
        self.apmib_set_var_type = {}
        # 如果本地已存在已解析函数列表文件，则加载
        parsed_funcs_file = os.path.join(
            self.reverse_dir, "parsed_functions.json")
        if os.path.exists(parsed_funcs_file):
            try:
                with open(parsed_funcs_file, "r") as f:
                    self._parsed_functions = set(json.load(f))
                print(f"[NvramServer] Loaded parsed function list from local file: {parsed_funcs_file}")
            except Exception as e:
                print(f"[NvramServer] Failed to load parsed function list: {e}")

        # 如果本地已存在 key_to_func_name 映射文件，则加载
        key_to_func_file = os.path.join(
            self.reverse_dir, "key_to_func_name.json")
        if os.path.exists(key_to_func_file):
            try:
                with open(key_to_func_file, "r") as f:
                    self.key_to_func_name = json.load(f)
                print(f"[NvramServer] Loaded key_to_func_name mapping from local file: {key_to_func_file}")
            except Exception as e:
                print(f"[NvramServer] Failed to load key_to_func_name mapping: {e}")

        # 如果本地已存在 apmib_set_var_type 映射文件，则加载
        apmib_set_var_type_file = os.path.join(
            self.reverse_dir, "apmib_set_results.json")
        if os.path.exists(apmib_set_var_type_file):
            try:
                with open(apmib_set_var_type_file, "r") as f:
                    self.apmib_set_var_type = json.load(f)
                print(
                    f"[NvramServer] 已从本地文件加载 apmib_set_var_type 映射: {apmib_set_var_type_file}")
            except Exception as e:
                print(f"[NvramServer] Failed to load apmib_set_var_type mapping: {e}")

        self.nvram_funcs_key_pos = {
            # Get functions
            "_nvram_get": 0,
            "nvram_get": 0,
            "nvram_get_internal": 0,
            "nvram_get_buf": 0,
            "nvram_get_int": 0,
            "nvram_default_get": 0,
            "nvram_nget": 0,
            "nvram_get_state": 0,
            "nvram_list_exist": 0,
            "nvram_get_nvramspace": 0,
            "artblock_get": 0,
            "artblock_fast_get": 0,
            "artblock_safe_get": 0,
            "acos_nvram_get": 0,
            "acos_nvram_read": 0,
            "acosNvramConfig_exist": 0,
            "acosNvramConfig_get": 0,
            "acosNvramConfig_read": 0,
            "acosNvramConfig_readAsInt": 0,
            "nvram_get_adv": 1,
            "nvram_bufget": 1,
            "apmib_get": 0,
            "apmib_getDef": 0,
            "WAN_ith_CONFIG_GET": 1,
            "envram_get": 1,
            "envram_get_func": 1,
            "envram_getf": 0,
            "nvram_getf": 0,
            "nvram_safe_get": 0,
            
            # Set functions
            "nvram_set": 0,
            "nvram_set_int": 0,
            "nvram_set_state": 0,
            "nvram_nset": 1,
            "nvram_nset_int": 1,
            "nvram_nmatch": 1,
            "nvram_list_add": 0,
            "nvram_list_del": 0,
            "nvram_unset": 0,
            "artblock_set": 0,
            "acos_nvram_set": 0,
            "acosNvramConfig_set": 0,
            "acosNvramConfig_write": 0,
            "nvram_set_adv": 2,
            "nvram_bufset": 2,
            "apmib_set": 0,
            "WAN_ith_CONFIG_SET_AS_STR": 1,
            "WAN_ith_CONFIG_SET_AS_INT": 1,
            "envram_set": 1,
            "envram_set_func": 1,
            "envram_setf": 1,
            "nvram_setf": 1,
            
            # Match functions
            "nvram_match": 0,
            "nvram_invmatch": 0,
            "acosNvramConfig_match": 0,
            "acosNvramConfig_invmatch": 0,
            "envram_match": 0,
            
            # Other functions with key
            "foreach_nvram_from": 0,
            "acos_nvram_unset": 0,
            "acosNvramConfig_unset": 0,
            "envram_unset": 1
        }

        self.nvram_value_type = {
            "bool": "0",
            "char": "1",
            "short": "2",
            "int": "3",
            "long long": "4"
        }
        
        # LLM请求计数
        self.llm_request_count = 0
        # 使用threading.Lock保证线程安全
        self.llm_request_lock = threading.Lock()
        # 找到的nvram函数名
        self.found_funcs = []

        # 初始化OpenAI客户端
        self.client = OpenAI(
            api_key=api_key,
            base_url="https://api.vectorengine.ai/v1",
        )
        self.try_max_num = 3  # Maximum retry attempts
        self.is_error = False
        self.stop_flag = False

    def set_found_funcs(self, found_funcs):
        """
        设置在二进制文件中找到的 nvram 函数名

        Args:
            found_funcs: 在二进制文件中找到的 nvram 函数名列表
        """
        self.found_funcs = found_funcs
        
    def get_time(self):
        time = self.consume_time
        self.consume_time = 0.0
        return time

    def remove_markdown_comments(self, code):
        """
        删除所有以 ``` 开头的行

        Args:
            code (str): 代码字符串

        Returns:
            str: 清理后的代码
        """
        pattern = re.compile(r"^```.*$", re.MULTILINE)
        cleaned_content = re.sub(pattern, "", code)
        pattern = re.compile(r"^\s*$(?:\r?\n)?", re.MULTILINE)
        cleaned_content = re.sub(pattern, "", cleaned_content)
        if cleaned_content and cleaned_content[-1] == '\n':
            cleaned_content = cleaned_content[:-1]
        return cleaned_content

    def get_related_code(self, key):
        """
        获取与指定key相关的代码

        Args:
            key (str): NVRAM key

        Returns:
            str: 相关代码提示
        """
        # TODO: 优化prompt，需要在回答中加上简洁解释，并让其检查给出的回答
        system_content = f'''
You are a firmware analysis expert familiar with the working principles of router firmware. In a virtualization scenario, the lack of NVRAM hardware causes programs to fail to obtain NVRAM key-value pair data. Please, based on the provided router firmware code snippet and the following information, provide an appropriate NVRAM value for the key={key}. NVRAM function name possible candidates are {self._parsed_functions}.

Output format:
Generate a command following this structure (no comments or extra information):
<value_type> <value>

Parameter definitions:
<value_type>: Type of the NVRAM value (only int, string, short, long long, bool=1/0)
<value>: The NVRAM value

Examples:
int __fastcall formLogin(_DWORD* a1) {{
...
v23 = websGetVar(a1, (int)"login_n", (int)&dword_47EFB4);
v22 = (char*)websGetVar(a1, (int)"login_pass", (int)&dword_47EFB4);
apmib_get(378, v11);
apmib_get(379, v12);
...
if (strcmp(v11, v23) ||
    ((memset(v17, 0, sizeof(v17)), base64decode((int)v17, v22, 128),
    strcmp(v12, v17)) ||
    (v7 = strlen(v12), v7 != strlen(v17))) &&
        (v12[0] || v22)) {{
    loginFailFlag = 1;
    goto LABEL_14;
}}
...
}}
The NVRAM value with key 378 is the user name. So give the command: string admin
        '''

        user_content = f'''
Requirements:
1. Ensure the web server runs successfully; disable/ignore unrelated services/features/configs.
2. Dynamically adjust NVRAM values per code logic, prioritize runtime stability over relevant router information.
3. Set long timeout thresholds to avoid premature termination.
4. Disable/bypass security restrictions to ensure program execution.
5. Web-display-only strings use "nvram_llm". 
6. Prefer source code default values over external suggestions.

Relevant router information (for reference):
Network configuration: LAN_IP=172.21.0.3; WAN_IP=172.21.0.2; subnet mask=255.255.255.0; MAC=01:23:45:67:89:ab; ifname=eth0; gateway=172.20.0.1; routing mode; disable ipv6/port_forward
Authentication: account=admin; password=admin; disable other authentication methods (e.g., verification codes) 
System settings: Login duration=20m; Region=China; language=English; routing mode; insecure mode;
Security settings: secret_key=123456; disable WPS/QoS/parent_control
Hardware configuration: Use placeholder or dummy values where hardware-specific data is missing—ensure they don't break execution.
Disabled services: DHCP/firewall/PPTP/logs/DDNS/UPnP/email/SNMP/telnet/DNS/NTP/Upgrade, etc
Debug mode is disabled; skip checks that might block firmware continuation
        '''

        visited_files = set()
        total_lines_used = 0
        # 检查key是否在key_to_func_name字典中
        if key in self.key_to_func_name:
            key_datas = sorted(self.key_to_func_name[key], key=lambda x: x["total_lines"])
            for key_data in key_datas:
                if total_lines_used >= 1000:
                    break
                function_name_file = key_data["file"]
                if function_name_file in visited_files:
                    continue
                visited_files.add(function_name_file)
                line_num = key_data["line_num"]
                total_lines = key_data["total_lines"]
                function_pseudocode_path = os.path.join(
                    self.reverse_dir, function_name_file)
                if os.path.exists(function_pseudocode_path):
                    with open(function_pseudocode_path, "r") as f:
                        lines = f.readlines()
                        header_lines = []
                        # 函数行数小于100行，直接截取全部代码
                        if total_lines < 100:
                            key_snippet_lines = lines
                        else:
                            # 找到函数定义的行号，在逆向代码中是函数名第二次出现的行号
                            base_func_name = function_name_file.replace('.c', '')
                            func_line = -1
                            appear_cnt = 0
                            for idx in range(len(lines)):
                                if base_func_name in lines[idx]:
                                    appear_cnt += 1
                                    if appear_cnt == 2:
                                        func_line = idx
                                        break
                            # 如果找到函数定义行，则把该行及之前的变量数据信息也加入提示
                            if func_line > 0:
                                header_lines = lines[:func_line]
                            start_line = max(1, line_num - 50)
                            end_line = min(total_lines, line_num + 49)
                            key_snippet_lines = lines[start_line - 1:end_line]
                        
                        # 合并header与关键代码段，精确防止重叠
                        combined_lines = []
                        if header_lines and key_snippet_lines:
                            # 获取key_snippet_lines的起始行索引
                            key_start_idx = start_line - 1 if total_lines >= 100 else 0
                            header_end_idx = len(header_lines)
                            
                            # 检查是否有重叠
                            if key_start_idx < header_end_idx:
                                # 有重叠，保留header中不重叠的部分 + key_snippet_lines
                                # header_lines[:key_start_idx] 是不重叠的部分
                                combined_lines = header_lines[:key_start_idx] + key_snippet_lines
                            else:
                                # 无重叠，直接合并
                                combined_lines = header_lines + key_snippet_lines
                        else:
                            combined_lines = header_lines + key_snippet_lines
                        
                        combined_content = ''.join(combined_lines)
                        # 累加已使用行数
                        total_lines_used += len(combined_lines)
                        user_content = user_content + f"\ncode snippet:\n" + \
                            combined_content + "\n"

            prompt = [
                {"role": "system", "content": system_content},
                {"role": "user", "content": user_content},
            ]
            return prompt
        else:
            # 如果key不在key_to_func_name字典中，返回None
            return None

    def check_response(self, response_content):
        """
        检查LLM回复是否符合要求

        Args:
            response_content (str): LLM回复内容

        Returns:
            bool: 是否符合要求
        """
        # 优先用空格分割，若无法得到两部分，则改用=分割
        parts = response_content.strip().split(" ")
        if len(parts) != 2:
            parts = response_content.strip().split("=")
            if len(parts) != 2:
                return False
        value_type = parts[0]
        value = parts[1]
        if value_type == "int" and value.isdigit():
            return True
        elif value_type == "string":
            return True
        elif value_type == "short" and value.isdigit():
            return True
        elif value_type == "long long" and value.isdigit():
            return True
        elif value_type == "bool" and value in ["true", "false"]:
            return True
        else:
            return False

    def get_nvram_value(self, key):
        """
        使用LLM推理获取NVRAM值

        Args:
            key (str): NVRAM key
        """
        # 检查二进制文件是否存在
        if not os.path.exists(self.binary_path):
            print(f"[NvramServer] Error: File does not exist: {self.binary_path}")
            default_response = "string "
            return default_response

        # 检查并执行逆向分析
        if not self.check_if_reversed():
            print("[NvramServer] Binary file not reversed, starting reverse analysis...")
            self.reverse_binary()

        # 生成key_to_func_name.json文件
        # 使用在二进制文件中找到的nvram函数，生成key_to_func_name映射
        if self.found_funcs:
            print(f"[NvramServer] Using found nvram functions: {', '.join(self.found_funcs)}")
            for func_name in self.found_funcs:                
                if func_name not in self._parsed_functions:
                    print(f"[NvramServer] Processing function: {func_name}")
                    self.generate_key_to_func_json(func_name)
                    self._parsed_functions.add(func_name)
                    parsed_funcs_file = os.path.join(
                        self.reverse_dir, "parsed_functions.json")
                    try:
                        with open(parsed_funcs_file, "w") as f:
                            json.dump(list(self._parsed_functions), f, indent=2)
                        print(f"[NvramServer] Updated parsed function list file: {parsed_funcs_file}")
                    except Exception as e:
                        print(f"[NvramServer] Failed to save parsed function list: {e}")
        else:
            # 如果没有找到nvram函数，使用默认的nvram函数列表
            print("[NvramServer] No found nvram functions, using default list")
            for func_name in self.nvram_funcs_key_pos:                
                if func_name not in self._parsed_functions:
                    print(f"[NvramServer] Processing function: {func_name}")
                    self.generate_key_to_func_json(func_name)
                    self._parsed_functions.add(func_name)
                    parsed_funcs_file = os.path.join(
                        self.reverse_dir, "parsed_functions.json")
                    try:
                        with open(parsed_funcs_file, "w") as f:
                            json.dump(list(self._parsed_functions), f, indent=2)
                        print(f"[NvramServer] Updated parsed function list file: {parsed_funcs_file}")
                    except Exception as e:
                        print(f"[NvramServer] Failed to save parsed function list: {e}")

        # 检查key是否在key_to_func_name中
        if key not in self.key_to_func_name:
            print(f"[NvramServer] Key {key} not found in key_to_func_name, using default value")
            default_response = "string "
            return default_response

        # 使用LLM推理获取NVRAM值
        prompt = []
        num_try = 0
        previous_response = ""

        while num_try < self.try_max_num:
            num_try += 1

            if num_try == 1:
                prompt = self.get_related_code(key)
                # 如果prompt为None，说明key不存在，直接返回默认值
                if prompt is None:
                    print(f"[NvramServer] Key {key} not found, returning default response")
                    default_response = "string "
                    return default_response
            else:
                # 在后续尝试中，向系统提示添加之前的失败原因和上次回复
                if previous_response:
                    updated_system = prompt[1]["content"] + f"\nPrevious attempt failed with: Invalid output format\nLast response: {previous_response}\n"
                    prompt[1]["content"] = updated_system

            start_time = time.time()
            
            # 增加LLM请求计数
            with self.llm_request_lock:
                self.llm_request_count += 1
                # 创建锁文件，使用时间戳防止重复
                timestamp = int(time.time() * 1000)  # 毫秒级时间戳
                lock_file = f"{LLM_LOCK_PREFIX}{timestamp}"
                # print(f"[NvramServer] Creating lock file: {lock_file}")
                open(lock_file, 'w').close()
            
            try:
                # 使用OpenAI客户端调用LLM
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=prompt,
                    temperature=1,
                    top_p=0.5,
                )
                
                end_time = time.time()
                llm_time = end_time - start_time

                # 打印输入token数
                print(f"[NvramServer] Input tokens for attempt {num_try}: {response.usage.prompt_tokens}")
                # 打印输出token数
                print(f"[NvramServer] Output tokens for attempt {num_try}: {response.usage.completion_tokens}")
                # 打印耗时
                print(f"[NvramServer] LLM API call time for attempt {num_try}: {llm_time:.2f} seconds")
                self.total_input_token += response.usage.prompt_tokens
                self.total_output_token += response.usage.completion_tokens

                # 获取回复内容
                response_content = response.choices[0].message.content

                # 仅检查最后一行
                last_line = response_content.strip().split('\n')[-1]
                if not self.check_response(last_line):
                    # 保存上次回复用于下次尝试
                    previous_response = last_line
                    continue

                return last_line
            except AuthenticationError as e:
                print(f"[NvramServer] Authentication error: {e}")
                print(f"[NvramServer] Please check your API key.")
                break  # 认证错误，直接跳出循环，不重试
            except BadRequestError as e:
                print(f"[NvramServer] Bad request error: {e}")
                print(f"[NvramServer] Please check your request parameters.")
                break  # 请求参数错误，直接跳出循环，不重试
            except RateLimitError as e:
                print(f"[NvramServer] Rate limit error: {e}")
                print(f"[NvramServer] Too many requests, waiting before retry...")
                # 保存错误信息用于下次尝试
                previous_response = f"Error: {str(e)}"
                time.sleep(2)  # 速率限制，等待2秒后重试
                continue
            except APIConnectionError as e:
                print(f"[NvramServer] Connection error: {e}")
                print(f"[NvramServer] Network issue, retrying...")
                # 保存错误信息用于下次尝试
                previous_response = f"Error: {str(e)}"
                time.sleep(1)  # 连接错误，等待1秒后重试
                continue
            except APIError as e:
                print(f"[NvramServer] API error: {e}")
                print(f"[NvramServer] Server error, retrying...")
                # 保存错误信息用于下次尝试
                previous_response = f"Error: {str(e)}"
                time.sleep(1)  # API错误，等待1秒后重试
                continue
            except Exception as e:
                print(f"[NvramServer] Unexpected error: {e}")
                print(f"[NvramServer] Unknown error, retrying...")
                # 保存错误信息用于下次尝试
                previous_response = f"Error: {str(e)}"
                time.sleep(1)  # 未知错误，等待1秒后重试
                continue
            finally:
                # 减少LLM请求计数
                with self.llm_request_lock:
                    self.llm_request_count -= 1
                    # 删除锁文件
                    os.remove(lock_file)
        
        # 如果所有尝试都失败，返回一个默认值而不是None
        default_response = "string "
        print(f"[NvramServer] All inference attempts failed. Using default response: {default_response}")
        return default_response

    def check_if_reversed(self):
        """
        检查目标二进制文件是否已被逆向

        Returns:
            bool: 是否已被逆向
        """
        # 检查逆向目录是否存在，且包含functions_name.txt文件
        functions_name_path = os.path.join(
            self.reverse_dir, "functions_name.txt")
        if not (os.path.exists(self.reverse_dir) and os.path.exists(functions_name_path)):
            return False

        # 还要检查是否存在.c文件
        for _, _, files in os.walk(self.reverse_dir):
            for file in files:
                if file.endswith(".c"):
                    return True
        return False

    def reverse_binary(self):
        """
        对目标二进制文件进行逆向分析

        Returns:
            str: 逆向结果目录路径
        """
        # 创建逆向客户端实例
        client = ReverseClient()

        if not os.path.exists(self.reverse_dir):
            os.makedirs(self.reverse_dir, exist_ok=True)

        # 检查是否有本地IDA Pro
        ida_path = '/ida/idat64'
        if os.path.exists(ida_path):
            print(f"[NvramServer] Local IDA detected: {ida_path}")
            print(f"[NvramServer] Starting local reverse analysis of file: {self.binary_path}")
            client.local_reverse_analysis(self.binary_path, self.reverse_dir)
        else:
            print(f"[NvramServer] Local IDA Pro not detected: {ida_path}")
            print(f"[NvramServer] Starting to send file to server for reverse analysis: {self.binary_path}")
            client.send_binary_for_analysis(self.binary_path, self.reverse_dir)

    def search_function_in_files(self, func_name):
        """
        在逆向文件中搜索指定函数名

        Args:
            func_name (str): 要搜索的函数名

        Returns:
            dict: key到函数名的映射
        """
        results = {}
        # 获取当前函数的key位置，默认为0
        key_pos = self.nvram_funcs_key_pos.get(func_name, 0)

        # 生成正则表达式，匹配函数调用并提取key参数
        pattern = rf'{func_name}\s*\(\s*(.*?)\s*\)'

        # 只遍历逆向目录下的所有.c文件
        for root, _, files in os.walk(self.reverse_dir):
            for file in files:
                if not file.endswith(".c"):
                    continue
                file_path = os.path.join(root, file)

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()

                    # 遍历每一行，查找匹配
                    for line_num, line in enumerate(lines, 1):
                        if line.strip().startswith('//'):
                            continue
                        matches = re.finditer(pattern, line)
                        for match in matches:
                            params = match.group(1)
                            # 按英文逗号划分参数
                            param_list = [p.strip()
                                          for p in params.split(',') if p.strip()]
                            if param_list and len(param_list) > key_pos:
                                key = param_list[key_pos]

                                # 处理key，移除引号及前后空格
                                if key.startswith('"') and key.endswith('"'):
                                    clean_key = key[1:-1]
                                elif key.startswith("'") and key.endswith("'"):
                                    clean_key = key[1:-1]
                                else:
                                    clean_key = key

                                # 用dict存储，clean_key作为key，file和line_num作为里面的一条信息
                                if clean_key not in results:
                                    results[clean_key] = []

                                results[clean_key].append({
                                    'file': file,
                                    'line_num': line_num,
                                    'total_lines': len(lines)
                                })
                except Exception as e:
                    print(f"[NvramServer] Error processing file {file_path}: {e}")

        return results

    def get_variable_type(self, file_path, variable_name):
        """
        检索 C 文件中指定变量的类型

        Args:
            file_path (str): C 文件路径
            variable_name (str): 要检索类型的变量名

        Returns:
            str: 变量类型，如果未找到则返回 None
        """
        try:
            with open(file_path, 'r') as f:
                content = f.read()

            # 匹配全局变量定义，如：int dword_47EFB4 = 0; 或 char buffer[100];
            # 支持数组
            global_pattern = rf'^(\w+(?:\s*\*)?)\s+\b{re.escape(variable_name)}\b\s*(?:\[.*?\])?\s*[;=]'
            global_match = re.search(global_pattern, content, re.MULTILINE)
            if global_match:
                return global_match.group(1)

            # 匹配函数内部变量定义，如：int Var; 或 _BYTE *v3; 或 char clean_buf[100]; （支持缩进、指针和数组）
            # 支持缩进、指针、自定义类型和数组
            local_pattern = rf'^\s*([\w_]+)\s*(?:\*\s*)?\b{re.escape(variable_name)}\b\s*(?:\[.*?\])?\s*;'
            local_match = re.search(local_pattern, content, re.MULTILINE)
            if local_match:
                return local_match.group(1)

            # 仅匹配与文件名同名的函数参数，如：int __fastcall formSetEmail(int a1)
            base_name = os.path.basename(file_path).replace('.c', '')
            param_pattern = rf'{base_name}\s*\(\s*(.*?)\s*\)'
            param_match = re.search(param_pattern, content, re.MULTILINE)
            if param_match:
                # 提取括号内的参数列表
                params_part = param_match.group(1)
                # 分割参数并查找目标变量
                for param in params_part.split(','):
                    param = param.strip()
                    if variable_name in param:
                        # 提取参数类型
                        param_type = param.replace(variable_name, '').strip()
                        # 移除可能的指针符号
                        if '*' in param_type:
                            param_type = param_type.split('*')[0].strip()
                        return param_type

            return None
        except Exception as e:
            print(f"[NvramServer] Error: {e}")
            return None

    def handle_apmib_set(self):
        """
        处理apmib_set请求，搜索对应key的函数

        Args:
            key (str): 要搜索的key

        Returns:
            dict: 搜索结果
        """
        func_name = "apmib_set"
        key_pos = 0
        buf_pos = 1

        # 生成正则表达式，匹配函数调用并提取key参数
        pattern = rf'{func_name}\s*\(\s*(.*?)\s*\)'

        # 只遍历逆向目录下的所有.c文件
        for root, _, files in os.walk(self.reverse_dir):
            for file in files:
                if not file.endswith(".c"):
                    continue
                file_path = os.path.join(root, file)

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()

                    # 遍历每一行，查找匹配
                    for _, line in enumerate(lines, 1):
                        matches = re.finditer(pattern, line)
                        for match in matches:
                            params = match.group(1)
                            # 按英文逗号划分参数
                            param_list = [p.strip()
                                          for p in params.split(',') if p.strip()]
                            if param_list and len(param_list) > key_pos:
                                key = param_list[key_pos]
                                if key.startswith('"') and key.endswith('"'):
                                    clean_key = key[1:-1]
                                elif key.startswith("'") and key.endswith("'"):
                                    clean_key = key[1:-1]
                                else:
                                    clean_key = key

                                buf = param_list[buf_pos]
                                if buf.startswith('"') and buf.endswith('"'):
                                    clean_buf = buf[1:-1]
                                elif buf.startswith("'") and buf.endswith("'"):
                                    clean_buf = buf[1:-1]
                                else:
                                    clean_buf = buf

                                # 利用 get_variable_type 获取 clean_buf 对应的变量类型
                                buf_type = self.get_variable_type(
                                    file_path, clean_buf)

                                if buf_type:
                                    # 将逆向代码中的变量类型转换为 string、int、bool 类型
                                    type_mapping = {
                                        # 常见的 C 类型映射
                                        'char': 'char',
                                        'char*': 'char',
                                        'const char*': 'char',
                                        'char *': 'char',
                                        'unsigned char': 'char',
                                        'signed char': 'char',

                                        'int': 'int',
                                        'unsigned int': 'int',
                                        'signed int': 'int',
                                        'long': 'int',
                                        'unsigned long': 'int',
                                        'long long': 'long long',
                                        'unsigned long long': 'long long',
                                        'short': 'short',
                                        'unsigned short': 'short',
                                        'signed short': 'short',

                                        'bool': 'bool',
                                        '_Bool': 'bool',
                                        'int8_t': 'char',
                                        'uint8_t': 'char',
                                        'int16_t': 'short',
                                        'uint16_t': 'short',
                                        'int32_t': 'int',
                                        'uint32_t': 'int',
                                        'int64_t': 'long long',
                                        'uint64_t': 'long long',

                                        # 逆向分析中可能出现的类型
                                        '_BYTE': 'char',
                                        '_WORD': 'short',
                                        '_DWORD': 'int',
                                        '_QWORD': 'long long',
                                        'dword': 'int',
                                        'word': 'short',
                                        'byte': 'char',
                                        'size_t': 'int',
                                        'ptrdiff_t': 'int',
                                        'ssize_t': 'int',
                                    }

                                    # 转换类型 - 遍历 type_mapping 查找匹配的类型
                                    converted_type = 'char'  # 默认类型
                                    
                                    # 先检查布尔类型的特殊情况
                                    if buf_type and ('bool' in buf_type.lower() or '_BOOL' in buf_type):
                                        converted_type = 'bool'
                                    # 检查指针类型
                                    elif buf_type and ('*' in buf_type or 'ptr' in buf_type.lower()):
                                        converted_type = 'char'
                                    # 遍历 type_mapping 查找匹配的类型
                                    else:
                                        for c_type, mapped_type in type_mapping.items():
                                            if c_type in buf_type:
                                                converted_type = mapped_type
                                                break

                                    self.apmib_set_var_type[clean_key] = {
                                        "key": clean_key,
                                        "buf": clean_buf,
                                        "buf_type": converted_type
                                    }

                except Exception as e:
                    print(f"[NvramServer] Error processing file {file_path}: {e}")
        # 将 results 保存为本地 JSON 文件
        results_file = os.path.join(
            self.reverse_dir, f"apmib_set_results.json")
        try:
            with open(results_file, "w", encoding="utf-8") as f:
                json.dump(self.apmib_set_var_type, f,
                          ensure_ascii=False, indent=2)
            print(f"[NvramServer] apmib_set search results saved to: {results_file}")
        except Exception as e:
            print(f"[NvramServer] Failed to save apmib_set search results: {e}")

    def generate_key_to_func_json(self, func_name):
        """
        生成key到函数名的JSON文件

        Args:
            func_name (str): 函数名

        Returns:
            str: JSON文件路径
        """
        # TODO: 加上各种nvram函数的key_pos，包括set等
        # 搜索函数
        results = self.search_function_in_files(func_name)
        # 将新搜索到的结果合并到 self.key_to_func_name 中
        for key, locations in results.items():
            if key not in self.key_to_func_name:
                self.key_to_func_name[key] = []
            self.key_to_func_name[key].extend(locations)
        # 生成JSON文件
        json_file_path = os.path.join(
            self.reverse_dir, "key_to_func_name.json")
        with open(json_file_path, "w") as f:
            json.dump(self.key_to_func_name, f, indent=2)

        print(f"[NvramServer] Generated key_to_func_name.json file, path: {json_file_path}")
        return json_file_path

    def parse_communication_file(self):
        """
        解析通信文件，获取FUNTION_NAME和KEY

        Returns:
            tuple: (function_name, key) 或 (None, None) 如果解析失败
        """
        try:
            # 从容器中读取通信文件内容
            exit_code, output = self.container.exec_run(
                f"cat {self.communication_file}")
            if exit_code != 0:
                print(
                    f"[NvramServer] 读取容器内通信文件失败: {output.decode('utf-8', errors='ignore')}")
                return None, None
            content = output.decode('utf-8', errors='ignore').strip()

            # 解析格式: --nvram_function_name <FUNTION_NAME> --key <KEY>
            pattern = r"--nvram_function_name\s+(\w+)\s+--key\s+(\w+)"
            match = re.match(pattern, content)

            if match:
                function_name = match.group(1)
                key = match.group(2)
                return function_name, key
            else:
                print(f"[NvramServer] Invalid communication file format: {content}")
                return None, None
        except Exception as e:
            print(f"[NvramServer] Error parsing communication file: {e}")
            return None, None

    def cleanup_files(self):
        """
        清理通信文件和锁文件（在容器内操作）
        """
        try:
            # 删除容器内的通信文件
            exit_code, output = self.container.exec_run(
                f"rm -f {self.communication_file}")
            if exit_code != 0:
                print(
                        f"[NvramServer] 删除容器内通信文件失败: {output.decode('utf-8', errors='ignore')}")

            # 删除容器内的锁文件
            exit_code, output = self.container.exec_run(
                f"rm -f {self.lock_file}")
            if exit_code != 0:
                print(f"[NvramServer] 删除容器内锁文件失败: {output.decode('utf-8', errors='ignore')}") 
        except Exception as e:
            print(f"[NvramServer] Error cleaning container files: {e}")


    def get_total_input_tokens(self):
        """
        获取总输入token数
        """
        return self.total_input_token

    def get_total_output_tokens(self):
        """
        获取总输出token数
        """
        return self.total_output_token

class StartupCommandServer:
    """
    启动命令推理模块类
    
    负责推理固件应用的启动命令
    """
    
    def __init__(self, fs_path, bin_path, qemu_arch, container_name, api_key="sk-o20HTjWDHvtm25HPmjfWgkrOdRDH79bXLRA3UGZDFPXTTYL5", model="qwen3-max"):
        self.fs_path = fs_path
        self.bin_path = bin_path
        self.qemu_arch = qemu_arch
        self.container_name = container_name
        self.model = model
        self.total_input_token = 0
        self.total_output_token = 0
        
        # 初始化OpenAI客户端
        self.client = OpenAI(
            api_key=api_key,
            base_url="https://api.vectorengine.ai/v1",
        )
    
    def copy_logs_from_container(self):
        """
        将容器中的日志文件复制到宿主机的self.fs_path目录
        """
        try:
            client = docker.from_env()
            container = client.containers.get(self.container_name)
            
            # 列出容器中所有的trace.log文件
            ls_cmd = "ls /fs/*_trace.log*"
            exec_result = container.exec_run(["/bin/sh", "-c", ls_cmd])
            
            if exec_result.exit_code == 0:
                output = exec_result.output.decode().strip()
                if output:
                    container_logs = output.split()
                    print(f"[StartupCommandServer] Found {len(container_logs)} trace.log files in container")
                    
                    for log_path in container_logs:
                        # 获取文件名
                        log_name = os.path.basename(log_path)
                        # 容器内的完整路径
                        container_full_path = f"/fs/{log_name}"
                        # 宿主机上的目标路径
                        host_path = os.path.join(self.fs_path, log_name)
                        
                        print(f"[StartupCommandServer] Copying {container_full_path} to {host_path}")
                        
                        # 使用get_archive获取文件内容
                        archive_stream, _ = container.get_archive(container_full_path)
                        
                        # 提取文件到宿主机
                        with open(host_path, 'wb') as f:
                            for chunk in archive_stream:
                                f.write(chunk)
                        
                        print(f"[StartupCommandServer] Successfully copied {log_name}")
        except Exception as e:
            print(f"[StartupCommandServer] Error copying logs from container: {e}")
    
    def get_potential_start_target_files(self):
        # 使用strings对固件文件系统的elf文件进行筛选
        potential_start_target_files = []
        target_app_name = os.path.basename(self.bin_path)
        
        # 首先将日志从容器复制到宿主机
        self.copy_logs_from_container()
        
        # 然后从self.fs_path获取日志
        existing_logs = sorted(glob.glob(os.path.join(self.fs_path, "*_trace.log*")))
        print(f"[StartupCommandServer] Found {len(existing_logs)} existing log files, prioritizing applications corresponding to these logs for filtering")
        
        candidates = set()
        # 提取日志文件对应的应用名
        for log_path in existing_logs:
            # 提取日志文件前的应用名（去掉 _trace.log 及之后的部分）
            log_name = os.path.basename(log_path)
            candidate_app = log_name.split('_trace.log')[0]
            if candidate_app.endswith('_sh'):
                candidate_app = candidate_app[:-3] + '.' + candidate_app[-2:]
            
            # 去重：跳过已处理过的 candidate_app
            if candidate_app in candidates:
                continue
            candidates.add(candidate_app)
            
            # 使用 glob 查找文件
            pattern = os.path.join(self.fs_path, "**", candidate_app)
            matches = glob.glob(pattern, recursive=True)
            if matches:
                app_path = matches[0]
                # 检查路径是否包含 target_app_name，如果包含则跳过
                if target_app_name in app_path:
                    print(f"[StartupCommandServer]      ⚠ Skipping {app_path} as it contains target_app_name in path")
                    continue
            else:
                print(f"[StartupCommandServer]      ⚠ Could not find {candidate_app}")
                continue
            
            # 检查字符串
            strings_cmd = f"strings {app_path} | grep -w -i {target_app_name}"
            out = subprocess.run(strings_cmd, shell=True, capture_output=True, text=True)
            # print(f"strings {app_path} | grep -w -i {target_app_name} output: {out.stdout}")
            if out.stdout:
                print(f"[StartupCommandServer]      ✓ Found string containing {target_app_name} in {app_path}")
                potential_start_target_files.append(app_path)
            
        # 如果没有匹配到任何log对应的应用，进行全盘搜索
        if not potential_start_target_files:
            print(f"[StartupCommandServer]   - No log file corresponding to {target_app_name}, starting full search for ELF files containing {target_app_name}...")
            # 跳过 gh_nvram、ghdev、ghproc、lib、proc、sys、greenhouse、www、dev、libexec 目录
            skip_dirs = {'gh_nvram', 'ghdev', 'ghproc', 'lib', 'proc', 'sys', 'greenhouse', 'www', 'dev', 'libexec', 'ghetc'}
            # 首先收集所有需要检查的文件
            for root, dirs, filenames in os.walk(self.fs_path):
                dirs[:] = [d for d in dirs if d not in skip_dirs]
                # 跳过最外层文件夹下面的直接文件，只处理子文件夹中的文件
                if root == self.fs_path:
                    continue
                for filename in filenames:
                    file_path = os.path.join(root, filename)
                    is_string = False
                    if filename.endswith('.sh'):
                        is_string = True
                    elif filename.endswith('.so'):
                        is_string = False
                    else:
                        try:
                            with open(file_path, 'rb') as elf_file:
                                magic = elf_file.read(4)
                                if magic == b'\x7fELF':
                                    is_string = True
                        except (IOError, OSError):
                            continue
                    
                    if is_string:
                        # 检查路径是否包含 target_app_name，如果包含则跳过
                        if target_app_name in file_path:
                            # print(f"   ⚠ Skipping {file_path} as it contains target_app_name in path")
                            continue
                        # 检查字符串是否包含target_app_name
                        strings_cmd = 'strings %s | grep -w -i %s' % (file_path, target_app_name)
                        out = subprocess.run(strings_cmd, shell=True, capture_output=True, text=True)
                        if out.stdout:
                            # print(f"   - Strings output: {out.stdout.strip()}")
                            print(f"[StartupCommandServer]   ✓ Found string containing {target_app_name} in {file_path}")
                            potential_start_target_files.append(file_path)
                                
        return potential_start_target_files
    
    def reverse_potential_start_target_files(self, potential_start_target_files):
        # Create ReverseClient instance
        reverse_client = ReverseClient()
        
        for f in potential_start_target_files:
            if f.endswith('.sh'):
                continue
            # For ELF files, use ReverseClient for decompilation
            else:                
                f_basename = os.path.basename(f)
                # Create decompile directory
                decompile_dir = f"/tmp/{f_basename}_decompile"
                os.makedirs(decompile_dir, exist_ok=True)
                
                # Check if already decompiled (has .c files)
                if any(f.endswith(".c") for f in os.listdir(decompile_dir)):
                    print(f"[StartupCommandServer]   - {f} has been decompiled, skip")
                    continue
                
                # 检查是否有本地IDA Pro
                ida_path = '/ida/idat64'
                if os.path.exists(ida_path):
                    reverse_client.local_reverse_analysis(f, decompile_dir)
                else:
                    reverse_client.send_binary_for_analysis(f, decompile_dir)
                    
    def get_target_app_help_info(self, target_app_name):
        help_info = ""
        # 使用Docker容器运行qemu命令获取帮助信息
        import docker
        
        # 定义常量
        DOCKER_FS = "fs"
        
        # 创建Docker客户端
        client = docker.from_env()
        
        try:
            # 获取已存在的容器
            tempCont = client.containers.get(self.container_name)
            
            # 计算容器内的路径
            relative_bin_path = self.bin_path.replace(self.fs_path, "")
            qemu_command = ["chroot", DOCKER_FS, "/"+self.qemu_arch, relative_bin_path, "--help"]
            help_cmd = " ".join(qemu_command)
            # print(f"target app help cmd: {help_cmd}")
            result = tempCont.exec_run(
                help_cmd,
                stream=False,
                detach=False,
                tty=True
            )
                
            help_info = result.output.decode('utf-8', errors='ignore').strip()
            # print(f"target app help output: {help_info}")
            return help_info
        except docker.errors.NotFound:
            print(f"[StartupCommandServer] Container '{self.container_name}' does not exist, please check the container name is correct")
        except docker.errors.APIError as e:
            print(f"[StartupCommandServer] Docker API call failed: {e}")
        except Exception as e:
            print(f"[StartupCommandServer] Unknown error occurred when getting container instance: {e}")
                
        return help_info
                    
    def extract_code_snippet(self, file_path, target_app_name):
        """
        从指定文件中提取包含target_app_name的代码片段
        
        Args:
            file_path: 文件路径
            target_app_name: 目标应用名称
            
        Returns:
            tuple: (combined_content, lines_used)，其中：
                - combined_content: 提取的代码片段内容
                - lines_used: 使用的行数
        """
        combined_content = ""
        lines_used = 0
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as cf:
                content = cf.read()
                if target_app_name not in content:
                    return combined_content, lines_used
                
            lines = content.splitlines(keepends=True)
            total_lines = len(lines)
            
            # 1. 首先找到target_app_name所在的行号line_num
            line_num = -1
            for idx, line in enumerate(lines):
                if target_app_name in line:
                    line_num = idx + 1
                    break
            
            if line_num == -1:
                return combined_content, lines_used
            
            # 2. 初始化变量
            header_lines = []
            key_snippet_lines = []
            
            # 3. 处理代码截取
            # 函数行数小于100行，直接截取全部代码
            if total_lines < 100:
                key_snippet_lines = lines
            else:
                # 找到函数定义的行号，在逆向代码中是函数名第二次出现的行号
                file_name = os.path.basename(file_path)
                base_func_name = file_name.replace('.c', '')
                func_line = -1
                appear_cnt = 0
                for idx in range(len(lines)):
                    if base_func_name in lines[idx]:
                        appear_cnt += 1
                        if appear_cnt == 2:
                            func_line = idx
                            break
                # 如果找到函数定义行，则把该行及之前的变量数据信息也加入提示
                if func_line > 0:
                    header_lines = lines[:func_line]
                
                # 使用target_app_name所在的行号line_num进行截取
                start_line = max(1, line_num - 50)
                end_line = min(total_lines, line_num + 49)
                key_snippet_lines = lines[start_line - 1:end_line]
            
            # 4. 合并header与关键代码段，精确防止重叠
            combined_lines = []
            if header_lines and key_snippet_lines:
                # 获取key_snippet_lines的起始行索引
                key_start_idx = start_line - 1 if total_lines >= 100 else 0
                header_end_idx = len(header_lines)
                
                # 检查是否有重叠
                if key_start_idx < header_end_idx:
                    # 有重叠，保留header中不重叠的部分 + key_snippet_lines
                    combined_lines = header_lines[:key_start_idx] + key_snippet_lines
                else:
                    # 无重叠，直接合并
                    combined_lines = header_lines + key_snippet_lines
            else:
                combined_lines = header_lines + key_snippet_lines
            
            combined_content = ''.join(combined_lines)
            lines_used = len(combined_lines)
            
        except Exception as e:
            print(f"[StartupCommandServer] Error extracting code snippet from {file_path}: {e}")
        
        return combined_content, lines_used
    
    def get_infer_startup_prompt(self, target_app_name, potential_start_target_files, ps_target_app_startup):
        # 获取目标应用的--help信息
        help_info = self.get_target_app_help_info(target_app_name)
        
        system_content = f'''
You are a firmware analysis expert familiar with the working principles of router firmware. 
Your task is to infer the minimal and most likely startup command for a target application ({target_app_name}).

Guidelines:
1. Prefer the simplest (minimal) command that satisfies the observed logic.
2. Do not include comments, explanations, or additional text in the output.
3. If multiple branches exist in the code, choose the branch that represents the default.
4. Substitute placeholders (e.g., %d, %s) with concrete values inferred from the code.
5. Give the absolute path of the file.

Output format:
<target_app_name> <parameters>

Examples:
code snippet:
if ( *((_BYTE *)a3 + 66) == 1 )
    _system(
    "ncc_httpd.c",
    204,
    "httpdStart",
    "%s -M 0 -C %s/mini_httpd_%d.conf -S -E /etc_ro/mini_httpd.pem",
    "mini_httpd",
    "/var/tmp",
    *((_DWORD *)a3 + 17));
else
    _system(
    "ncc_httpd.c",
    206,
    "httpdStart",
    "%s -M 0 -C %s/mini_httpd_%d.conf",
    "mini_httpd",
    "/var/tmp",
    *((_DWORD *)a3 + 17));

target app --help output:
usage:  /sbin/mini_httpd [-C configfile] [-D] [-S] [-E certfile] [-Y cipher] [-p port] [-d dir] [-dd data_dir] [-c cgipat] [-u user] [-h hostname] [-r] [-v] [-l logfile] [-i pidfile] [-T charset] [-P P3P] [-M maxage]

Inferred command: mini_httpd -M 0 -C /var/tmp/mini_httpd_0.conf
        '''
        user_content = ""
        max_lines = 2000
        lines_used_total = 0  # 累计已用行数
        for f in potential_start_target_files:
            if f.endswith('.sh'):
                f_basename = os.path.basename(f)
                with open(f, 'r', encoding='utf-8', errors='ignore') as sf:
                    lines = sf.readlines()
                # 只保留含 target_app_name 的上下各 10 行
                filtered = []
                for idx, line in enumerate(lines):
                    if target_app_name in line:
                        start = max(1, idx - 10)
                        end = min(len(lines), idx + 10)
                        filtered.extend(lines[start:end])
                snippet = ''.join(filtered)
                snippet_lines = len(filtered)
                user_content += f"Shell script {f_basename}:\n{snippet}\n"
                lines_used_total += snippet_lines
                if lines_used_total >= max_lines:
                    break
            else:
                f_basename = os.path.basename(f)
                decompile_dir = f"/tmp/{f_basename}_decompile"
                if not os.path.exists(decompile_dir):
                    continue

                for root, _, files in os.walk(decompile_dir):
                    for file in files:
                        if lines_used_total >= max_lines:
                            break
                        if not file.endswith(".c"):
                            continue

                        file_path = os.path.join(root, file)
                        snippet_content, snippet_lines = self.extract_code_snippet(file_path, target_app_name)
                        if snippet_content:
                            user_content += f"\ncode snippet:\n{snippet_content}\n"
                            lines_used_total += snippet_lines
                    if lines_used_total >= max_lines:
                        break
                if lines_used_total >= max_lines:
                        break
        
        # 将help信息追加到user_content
        if help_info:
            user_content += f"\ntarget app {target_app_name} --help output:\n{help_info}\n"

        # 将ps_target_app_startup信息追加到user_content
        if ps_target_app_startup:
            ps_info = "\n".join(ps.decode() for ps in ps_target_app_startup)
            user_content += f"\ntarget app process information from ps:\n{ps_info}\n"

        # 构造LLM请求
        prompt = [
            {"role": "system", "content": system_content},
            {"role": "user", "content": user_content}
        ]
        return prompt
    
    def check_command_files_exist(self, command):
        """
        检查命令中使用的文件是否存在，并替换为实际路径
        
        Args:
            command: LLM推测的启动命令
            
        Returns:
            tuple: (bool, list, dict, str) - 
                第一个元素表示所有文件是否存在，
                第二个元素是不存在的文件列表，
                第三个元素是找到的文件映射关系（原始路径 -> 实际路径），
                第四个元素是替换后的命令
        """
        import re
        import docker
        
        # 正则表达式模式，用于匹配命令中的文件路径
        # 匹配常见的文件路径模式，包括：
        # 1. 绝对路径：/etc/httpd.conf, /usr/bin/app
        # 2. 相对路径：config.txt, ./config.txt, ../config.txt, test_data/config.txt
        # 3. 带波浪号的路径：~/Documents/file.txt
        file_pattern = r'(\w+/[\w\-./]+)|(\./[\w\-./]+)|(\.\./[\w\-./]+)|(/[\w\-./]+)|(~?/[\w\-./]+)'
        
        # 提取所有可能的文件路径
        potential_files = re.findall(file_pattern, command)
        
        # 去除空字符串并去重
        potential_files = list(set([''.join(match) for match in potential_files if ''.join(match)]))
        
        missing_files = []
        file_mapping = {}
        updated_command = command
        
        # 创建Docker客户端
        client = docker.from_env()
        
        try:
            # 获取已存在的容器
            container = client.containers.get(self.container_name)
            
            for file_path in potential_files:
                actual_path = None
                
                # 在容器中检查是否为文件（不是文件夹）
                check_cmd = f"if [ -f {file_path} ]; then echo 'FILE_EXISTS'; elif [ -d {file_path} ]; then echo 'DIRECTORY_EXISTS'; else echo 'NOT_EXIST'; fi"
                result = container.exec_run(
                    ["/bin/sh", "-c", check_cmd],
                    stream=False,
                    detach=False,
                    tty=True
                )
                
                output = result.output.decode('utf-8', errors='ignore').strip()
                
                # 如果是文件，使用该路径
                if output == 'FILE_EXISTS':
                    actual_path = file_path
                elif output != 'DIRECTORY_EXISTS':  # 不是文件夹，尝试搜索
                    # 如果不存在，尝试在容器的根目录下搜索同名文件
                    filename = file_path.split('/')[-1]
                    search_cmd = f"find /fs/ -name '{filename}' -type f 2>/dev/null | head -1"
                    search_result = container.exec_run(
                        ["/bin/sh", "-c", search_cmd],
                        stream=False,
                        detach=False,
                        tty=True
                    )
                    
                    search_output = search_result.output.decode('utf-8', errors='ignore').strip()
                    
                    if search_output:
                        actual_path = search_output
                
                if actual_path:
                    # 记录文件映射关系
                    file_mapping[file_path] = actual_path
                    # 替换命令中的文件路径
                    updated_command = updated_command.replace(file_path, actual_path)
                else:
                    # 如果仍然没有找到，则添加到缺失文件列表
                    missing_files.append(file_path)
                    
        except docker.errors.NotFound:
            print(f"[StartupCommandServer] Container '{self.container_name}' does not exist, please check the container name is correct")
            missing_files = potential_files
        except docker.errors.APIError as e:
            print(f"[StartupCommandServer] Docker API call failed: {e}")
            missing_files = potential_files
        except Exception as e:
            print(f"[StartupCommandServer] Unknown error occurred when checking file existence: {e}")
            missing_files = potential_files
        
        return missing_files, file_mapping, updated_command
    
    def llm_infer_start_target_app(self, potential_start_target_files, ps_target_app_startup):
        target_app_name = os.path.basename(self.bin_path)
        
        # 获取prompt
        prompt = self.get_infer_startup_prompt(target_app_name, potential_start_target_files, ps_target_app_startup)
        
        max_retries = 5
        retry_count = 0
        inferred_cmd = ""
        # 存储最后一次尝试的信息
        last_missing_files = []
        last_inferred_cmd = ""
        
        while retry_count < max_retries:
            try:
                start_time = time.time()
                
                # 使用OpenAI客户端调用LLM
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=prompt,
                    temperature=1,
                    top_p=0.5,
                )
                
                end_time = time.time()
                llm_time = end_time - start_time
                
                # 记录token使用情况
                self.total_input_token += response.usage.prompt_tokens
                self.total_output_token += response.usage.completion_tokens
                print(f"[StartupCommandServer] Input tokens for attempt {retry_count}: {response.usage.prompt_tokens}")
                print(f"[StartupCommandServer] Output tokens for attempt {retry_count}: {response.usage.completion_tokens}")
                print(f"[StartupCommandServer] LLM API call time for attempt {retry_count}: {llm_time:.2f} seconds")
                
                # 获取回复内容
                response_content = response.choices[0].message.content
                print(f"[StartupCommandServer] " + "=" * 20 + "Complete Response" + "=" * 20)
                print(f"[StartupCommandServer] {response_content}")
                
                inferred_cmd = response_content.strip().split('\n')[-1]
                first_word = inferred_cmd.split()[0] if inferred_cmd.split() else ""
                # 提取first_word的基本名称，以便与target_app_name正确比较
                first_word_basename = os.path.basename(first_word)
                if first_word_basename == target_app_name:
                    # 检查命令中使用的文件是否存在，并替换为实际路径
                    missing_files, file_mapping, updated_cmd = self.check_command_files_exist(inferred_cmd)
                    inferred_cmd = updated_cmd
                    if not missing_files:
                        print(f"[StartupCommandServer] Original inferred command: {inferred_cmd}")
                        print(f"[StartupCommandServer] File mapping: {file_mapping}")
                        return inferred_cmd
                    else:
                        print(f"[StartupCommandServer] Command uses missing files: {missing_files}")
                        print(f"[StartupCommandServer] Retrying to get a valid command...")
                        missing_files_str = ", ".join(missing_files)
                        prompt[1]["content"] += f"\nLast attempt:{inferred_cmd}. There are no files with the same name in file system: {missing_files_str}. Please don't use these files.\n"
                        # 保存最后一次尝试的信息
                        last_missing_files = missing_files
                        last_inferred_cmd = inferred_cmd
                else:
                    prompt[1]["content"] += f"\nLast attempt:{inferred_cmd}. The first word is not the target app name.\n"
                    # 重置最后一次尝试的信息
                    last_missing_files = []
                    last_inferred_cmd = ""
                
                retry_count += 1
                inferred_cmd = ""
            except AuthenticationError as e:
                print(f"[StartupCommandServer] Authentication error: {e}")
                print(f"[StartupCommandServer] Please check your API key.")
                return inferred_cmd  # 认证错误，直接返回，不重试
            except BadRequestError as e:
                print(f"[StartupCommandServer] Bad request error: {e}")
                print(f"[StartupCommandServer] Please check your request parameters.")
                return inferred_cmd  # 请求参数错误，直接返回，不重试
            except RateLimitError as e:
                print(f"[StartupCommandServer] Rate limit error: {e}")
                print(f"[StartupCommandServer] Too many requests, waiting before retry...")
                retry_count += 1
                time.sleep(2)  # 速率限制，等待2秒后重试
            except APIConnectionError as e:
                print(f"[StartupCommandServer] Connection error: {e}")
                print(f"[StartupCommandServer] Network issue, retrying...")
                retry_count += 1
                time.sleep(1)  # 连接错误，等待1秒后重试
            except APIError as e:
                print(f"[StartupCommandServer] API error: {e}")
                print(f"[StartupCommandServer] Server error, retrying...")
                retry_count += 1
                time.sleep(1)  # API错误，等待1秒后重试
            except Exception as e:
                print(f"[StartupCommandServer] Unexpected error: {e}")
                print(f"[StartupCommandServer] Unknown error, retrying...")
                retry_count += 1
                time.sleep(1)  # 未知错误，等待1秒后重试
            
        # 所有重试都失败，尝试处理最后一次的结果
        if last_inferred_cmd and last_missing_files:
            print(f"[StartupCommandServer] All retries failed. Processing last attempt by removing missing files and their parameters.")
            
            # 解析命令，删除包含missing_files的参数及其前后可能的参数
            cmd_parts = last_inferred_cmd.split()
            processed_cmd_parts = []
            i = 0
            
            while i < len(cmd_parts):
                # 检查当前部分是否是missing_file
                is_missing = False
                for missing_file in last_missing_files:
                    if missing_file in cmd_parts[i]:
                        is_missing = True
                        break
                
                if is_missing:
                    # 删除当前参数（文件名）
                    print(f"[StartupCommandServer] Removing missing file parameter: {cmd_parts[i]}")
                    i += 1
                    # 如果前面有参数标志（如 -f, --file），也删除
                    if i > 1 and (cmd_parts[i-2].startswith('-') or cmd_parts[i-2].startswith('--')):
                        print(f"[StartupCommandServer] Also removing associated flag: {cmd_parts[i-2]}")
                        processed_cmd_parts.pop()
                else:
                    processed_cmd_parts.append(cmd_parts[i])
                    i += 1
            
            # 重新组合命令
            if processed_cmd_parts:
                inferred_cmd = " ".join(processed_cmd_parts)
                print(f"[StartupCommandServer] Final processed command after removing missing files: {inferred_cmd}")
            
        return inferred_cmd
    
    def get_target_app_startup(self, ps_target_app_startup):
        """
        获取目标应用的启动命令
        
        Args:
            ps_target_app_startup: 进程快照中的目标应用启动信息
            
        Returns:
            str: 推理出的目标应用启动命令
        """
        potential_start_target_files = self.get_potential_start_target_files()
        self.reverse_potential_start_target_files(potential_start_target_files)
        return self.llm_infer_start_target_app(potential_start_target_files, ps_target_app_startup)

class ContainerPsMonitor:
    """
    监控容器内ps进程信息的类，用于统计shell进程树的叶子节点数量
    """
    
    def __init__(self, container_name, bin_path=None, max_cmd_count=80, container_fs_path="/fs", fs_path=None):
        """
        初始化容器ps监控器
        
        Args:
            container_name: Docker容器名称
            bin_path: 目标应用的二进制路径，用于检查目标应用日志
            max_cmd_count: 命令最大允许执行次数，超过则被禁止，默认80
            container_fs_path: 容器文件系统路径
            fs_path: 固件文件系统路径，用于保存文件
        """
        self.container_name = container_name
        self.bin_path = bin_path
        self.DOCKER_FS = container_fs_path
        self.fs_path = fs_path
        self.shell_commands = {'sh', "/bin/sh", "/usr/bin/sh", "/usr/sbin/sh", "/bin/bash", "/usr/bin/bash", "bash"}
        self.cmd_leaf_counts = defaultdict(int)
        self.cmd_kill_counts = defaultdict(int)  # 记录每个命令被kill的次数
        self.stop_flag = False
        self.max_cmd_count = max_cmd_count
        self.banned_cmds_file = os.path.join(self.fs_path, "banned_cmds.txt")
        self.banned_cmds = self.load_banned_cmds()
        # 保存banned_cmds对应的脚本文件路径
        self.banned_cmd_scripts = {}
        # shell脚本扩展名
        self.shell_extensions = {'.sh', '.bash', '.ksh', '.zsh', '.csh'}
        
        # 获取docker容器实例
        try:
            self.container = docker.from_env().containers.get(container_name)
            print(f"[ContainerPsMonitor] Successfully obtained container instance: {container_name}")
        except docker.errors.NotFound:
            raise RuntimeError(f"容器 '{container_name}' 不存在，请检查容器名称是否正确")
        except docker.errors.APIError as e:
            raise RuntimeError(f"Docker API 调用失败: {e}")
        except Exception as e:
            raise RuntimeError(f"获取容器实例时发生未知错误: {e}")
    
    def load_banned_cmds(self):
        """
        从本地文件加载被禁止的命令
        
        Returns:
            set: 被禁止的命令集合
        """
        banned_cmds = set()
        try:
            with open(self.banned_cmds_file, 'r') as f:
                for line in f:
                    cmd = line.strip()
                    if cmd:
                        banned_cmds.add(cmd)
            print(f"[ContainerPsMonitor] Loaded {len(banned_cmds)} banned commands from {self.banned_cmds_file}")
        except FileNotFoundError:
            print(f"[ContainerPsMonitor] No banned commands file found at {self.banned_cmds_file}")
        except Exception as e:
            print(f"[ContainerPsMonitor] Error loading banned commands: {e}")
        return banned_cmds
    
    def save_banned_cmd(self, cmd):
        """
        将命令保存到本地文件
        
        Args:
            cmd: 要保存的命令
        """
        try:
            with open(self.banned_cmds_file, 'a') as f:
                f.write(cmd + '\n')
            print(f"[ContainerPsMonitor] Saved banned command to {self.banned_cmds_file}: {cmd}")
        except Exception as e:
            print(f"[ContainerPsMonitor] Error saving banned command: {e}")
    
    def kill_process(self, pid):
        """
        在容器内kill指定PID的进程
        
        Args:
            pid: 要kill的进程ID
        """
        try:
            exit_code, output = self.container.exec_run(f"kill -9 {pid}")
            # if exit_code == 0:
            #     print(f"[ContainerPsMonitor] Successfully killed process {pid}")
            # else:
            #     print(f"[ContainerPsMonitor] Failed to kill process {pid}: {output.decode('utf-8', errors='ignore')}")
        except Exception as e:
            print(f"[ContainerPsMonitor] Error killing process {pid}: {e}")
        
    def is_shell_process(self, cmd):
        """
        判断进程是否为shell进程的辅助函数
        
        Args:
            cmd: 进程命令
        
        Returns:
            bool: 是否为shell进程
        """
        parts = cmd.split()
        if not parts:
            return False
        
        for part in parts:
            if part in self.shell_commands:
                return True
        
        return False
    
    def parse_ps_output(self, ps_output):
        """
        解析ps命令输出，获取shell进程树的叶子节点
        
        Args:
            ps_output: ps命令的输出结果
        
        Returns:
            list: shell进程树的叶子节点列表，每个节点包含pid和cmd
        """
        processes = {}
        ppid_map = defaultdict(list)
        
        # 解析所有进程信息
        for line in ps_output.splitlines():
            line = line.strip()
            if not line or line.startswith("UID"):
                continue
            
            # 分割为字段：UID, PID, PPID, C, STIME, TTY, TIME, CMD
            parts = line.split(None, 7)
            if len(parts) < 8:
                continue
            
            _, pid_str, ppid_str, _, _, _, _, cmd = parts
            pid = int(pid_str)
            ppid = int(ppid_str)
            
            processes[pid] = {'pid': pid, 'ppid': ppid, 'cmd': cmd}
            ppid_map[ppid].append(pid)
        
        # 查找根进程（qemu_run.sh），找到第一个就停止
        root_pid = None
        for pid, info in processes.items():
            if "qemu_run.sh" in info['cmd']:
                root_pid = pid
                break  # 找到第一个就停止搜索
        
        # 从根进程开始，查找shell进程树的叶子节点
        leaf_processes = []
        
        def dfs(pid):
            """深度优先搜索查找shell进程树的叶子节点"""
            children = ppid_map.get(pid, [])
            has_shell_child = False
            is_shell = self.is_shell_process(processes[pid]['cmd'])
            
            # 检查所有子进程
            for child_pid in children:
                if child_pid in processes:
                    child_is_shell = dfs(child_pid)
                    if child_is_shell:
                        has_shell_child = True
            
            # 如果当前进程是shell进程且没有shell子进程，就是叶子节点
            if is_shell and not has_shell_child:
                leaf_processes.append(processes[pid])
                
            return is_shell
        
        if root_pid is not None:
            dfs(root_pid)
        
        return leaf_processes
    
    def _get_ignore_pid_from_lock_file(self):
        """
        从容器内的msg_init.lock文件中读取忽略的PID
        
        Returns:
            int or None: 从锁文件中读取的PID，如果文件不存在或内容无效则返回None
        """
        ignore_pid = None
        lock_file_path = f"/{self.DOCKER_FS}/msg_init.lock"
        
        # 先检查锁文件是否存在
        check_cmd = f"test -f {lock_file_path}"
        exit_code, _ = self.container.exec_run(check_cmd)
        if exit_code == 0:
            # 文件存在，读取内容
            cat_cmd = f"cat {lock_file_path}"
            exit_code, output = self.container.exec_run(cat_cmd)
            print(f"[ContainerPsMonitor] msg_init.lock content: {output.decode('utf-8', errors='ignore')}")
            if exit_code == 0:
                lock_content = output.decode('utf-8').strip()
                if lock_content.isdigit():
                    ignore_pid = int(lock_content)
                    print(f"[ContainerPsMonitor] Found ignore pid {ignore_pid} in msg_init.lock")
                else:
                    print(f"[ContainerPsMonitor] msg_init.lock content is not a valid pid: {lock_content}")
        return ignore_pid
    
    def _delete_script_for_banned_command(self, cmd):
        """
        删除被禁止命令对应的脚本文件
        
        Args:
            cmd: 被禁止的命令字符串
        """
        try:
            # 检查是否已经保存了该cmd对应的脚本路径
            script_path = None
            if cmd in self.banned_cmd_scripts:
                script_path = self.banned_cmd_scripts[cmd]
            else:
                # 解析命令
                cmd_parts = cmd.split()
                
                # 处理qemu开头的命令，从/trace.log字段后面开始正序检查
                try:
                    # 找到/trace.log的位置
                    trace_log_index = cmd_parts.index('/trace.log')
                    # 从/trace.log后面开始正序检查
                    for i in range(trace_log_index + 1, len(cmd_parts)):
                        part = cmd_parts[i]
                        # 跳过可能的选项参数
                        if part.startswith('-'):
                            continue
                        # 跳过/bin/sh等shell解释器
                        if part in self.shell_commands:
                            continue
                        
                        # 检查是否为脚本文件（根据扩展名）
                        if any(part.endswith(ext) for ext in self.shell_extensions):
                            script_path = part
                            break
                        # 如果没有找到带扩展名的脚本，检查是否为文件
                        else:
                            check_cmd = f"test -f {part}"
                            exit_code, output = self.container.exec_run(check_cmd)
                            # print(f"[ContainerPsMonitor] check_cmd: {check_cmd}, exit_code: {exit_code}, output: {output.decode('utf-8', errors='ignore')}")
                            if exit_code == 0:
                                script_path = part
                                break
                except ValueError:
                    # 如果没有找到/trace.log，使用默认逻辑
                    print(f"[ContainerPsMonitor] No /trace.log found in command '{cmd}', using default logic")

            
            # 如果找到脚本路径，删除它
            if script_path:
                self.banned_cmd_scripts[cmd] = script_path
                
                # 先检查脚本是否存在，存在再删除
                check_cmd = f"test -f /{self.DOCKER_FS}/{script_path}"
                exit_code, output = self.container.exec_run(check_cmd)
                # print(f"[ContainerPsMonitor] check_cmd: {check_cmd}, exit_code: {exit_code}, output: {output.decode('utf-8', errors='ignore')}")
                if exit_code == 0:
                    # 在容器内删除脚本文件
                    exit_code, output = self.container.exec_run(f"rm -f /{self.DOCKER_FS}/{script_path}")
                    # print(f"[ContainerPsMonitor] rm_cmd: {f'rm -f /{self.DOCKER_FS}/{script_path}'}, exit_code: {exit_code}, output: {output.decode('utf-8', errors='ignore')}")
                    # if exit_code == 0:
                    #     print(f"[ContainerPsMonitor] Successfully deleted script '{script_path}'")
                    # else:
                    #     print(f"[ContainerPsMonitor] Failed to delete script '{script_path}': {output.decode('utf-8', errors='ignore')}")
                else:
                    print(f"[ContainerPsMonitor] Script '{script_path}' not found, skipping deletion")
        except Exception as e:
            print(f"[ContainerPsMonitor] Error deleting script for command '{cmd}': {e}")
    
    def update_process_info(self):
        """
        更新容器内进程信息，统计shell进程树的叶子节点数量
        """
        try:
            # 先检查容器是否在运行
            if self.container.status != 'running':
                return
            
            # 检查是否有目标应用日志，如果有则停止监控
            if self.bin_path:
                app_name = os.path.basename(self.bin_path)
                base_logname = f"{app_name}_trace.log"
                
                # 在容器内查找目标应用日志文件
                list_cmd = f"ls /{self.DOCKER_FS}/{base_logname}*"
                exit_code, output = self.container.exec_run(list_cmd)
                if exit_code == 0:
                    out = output.decode('utf-8').strip()
                    if out and "No such file" not in out:
                        print(f"[ContainerPsMonitor] Found target app log files, stopping ps check")
                        self.stop()
                        return
            
            # 检查LLM请求锁文件是否存在，如果存在则暂停统计，因为LLM在推理，shell脚本并不在运行
            lock_files = glob.glob(f"{LLM_LOCK_PREFIX}*")
            if lock_files:
                # print(f"[ContainerPsMonitor] Found {len(lock_files)} LLM lock files, pausing statistics collection (LLM reasoning)")
                return
            
            # ignore_pid = self._get_ignore_pid_from_lock_file()
            
            # 在容器内执行ps命令
            exit_code, output = self.container.exec_run("ps -efww")
            if exit_code == 0:
                ps_output = output.decode('utf-8')
                leaf_processes = self.parse_ps_output(ps_output)
                # print(f"[ContainerPsMonitor] leaf_processes count: {len(leaf_processes)}")
                # print(f"[ContainerPsMonitor] leaf_processes: {leaf_processes}")
                
                # 处理每个叶子进程
                for process in leaf_processes:
                    pid = process['pid']
                    ppid = process['ppid']
                    cmd = process['cmd']
                    
                    # 检查命令是否在被禁止列表中，如果是直接kill
                    if cmd in self.banned_cmds:
                        print(f"[ContainerPsMonitor] Found banned command '{cmd}', killing process {pid}")
                        self._delete_script_for_banned_command(cmd)
                        self.kill_process(pid)
                        # 增加命令被kill的次数
                        self.cmd_kill_counts[cmd] += 1
                        kill_count = self.cmd_kill_counts[cmd]
                        # print(f"[ContainerPsMonitor] Command '{cmd}' has been killed {kill_count} times")
                        
                        # 如果命令被kill了2次，就kill其父进程
                        if kill_count >= 2:
                            print(f"[ContainerPsMonitor] Command '{cmd}' has been killed 2 times, killing its parent process {ppid}")
                            self.kill_process(ppid)
                        continue
                    
                    # # 如果pid和ignore_pid相同则跳过（类型均为int，可直接比较）
                    # if ignore_pid is not None and int(pid) == ignore_pid:
                    #     continue
                                        
                    # 统计命令出现次数
                    self.cmd_leaf_counts[cmd] += 1
                    count = self.cmd_leaf_counts[cmd]
                    # print(f"[ContainerPsMonitor] Command '{cmd}' count: {count}")
                    
                    # 如果命令次数超过max_cmd_count次，将其加入禁止列表并kill进程
                    if count > self.max_cmd_count:
                        print(f"[ContainerPsMonitor] Command '{cmd}' exceeded {self.max_cmd_count} counts, banning and killing process {pid}")
                        # 添加到被禁止列表
                        self.banned_cmds.add(cmd)
                        # 保存到本地文件
                        self.save_banned_cmd(cmd)
                        # kill进程
                        self.kill_process(pid)
                        # 增加命令被kill的次数
                        self.cmd_kill_counts[cmd] += 1
                        kill_count = self.cmd_kill_counts[cmd]
                        # print(f"[ContainerPsMonitor] Command '{cmd}' has been killed {kill_count} times")
                        
                # 对于所有的父shell进程，将其计数-1，避免其中的子shell进程由于父进程被杀掉而直接不启动
                for cmd in self.cmd_leaf_counts.keys():
                    if cmd not in [p['cmd'] for p in leaf_processes] and self.cmd_leaf_counts[cmd] > 0:
                        self.cmd_leaf_counts[cmd] = self.cmd_leaf_counts[cmd] - 1 
                        print(f"[ContainerPsMonitor] Command '{cmd}' count -1")
            
        except Exception as e:
            print(f"[ContainerPsMonitor] Error updating process info: {e}")
            
    def get_cmd_leaf_counts(self):
        """
        获取每个cmd作为叶子节点出现的次数
        
        Returns:
            defaultdict: 键为cmd字符串，值为出现次数的字典
        """
        return self.cmd_leaf_counts
    
    def stop(self):
        """
        停止容器进程监控
        """
        self.stop_flag = True
        print("[ContainerPsMonitor] Container process monitoring stop flag set")
    
    def get_banned_cmds(self):
        """
        获取被禁止的命令列表
        
        Returns:
            set: 被禁止的命令集合
        """
        return self.banned_cmds
    
    def run(self, interval=1):
        """
        运行容器进程监控
        
        Args:
            interval: 检查进程的时间间隔，单位秒，默认2秒
        """
        print(f"[ContainerPsMonitor] Container process monitoring started")
        print(f"[ContainerPsMonitor] Check interval: {interval} seconds")
        
        try:
            while not self.stop_flag:
                self.update_process_info()
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[ContainerPsMonitor] Container process monitoring stopped")
        except Exception as e:
            print(f"[ContainerPsMonitor] Error running container process monitoring: {e}")
        finally:
            print("[ContainerPsMonitor] Container process monitoring exited")

class InitServer:
    """
    Init脚本处理服务器类

    负责监控指定容器内的通信文件，
    从文件中获取init脚本路径，
    处理init脚本，包括过滤、解析和管理白名单黑名单
    """

    # 不可被更改的黑白名单
    # 这些命令始终保持在相应的列表中，不受动态更新影响
    # 白名单包含基础命令、网络相关命令和配置相关命令
    # 黑名单包含危险命令、系统修改命令、执行权限命令、网络危险命令、硬件相关命令和挂载命令
    IMMUTABLE_WHITELIST = {        
        "exec", "eval", "source", "unlink",
        "bash", "sh", "dash", "zsh", "csh",
        "ls", "cat", "echo", "cp", "mv", "rm", "mkdir", "rmdir",
        "cd", "pwd", "grep", "sed", "awk", "head", "tail", "test"
        "ps", "top", "kill", "chmod", "chown", "chgrp", "expr"
        "touch", "ln", "find", "xargs", "cut", "sort", "uniq",
        "wc", "diff", "patch", "tar", "gzip", "gunzip", "zip", "unzip",
        "date", "time", "sleep", "true", "false", "exit", "[", "[[",
        "ifconfig", "ip", "route", "ping", "traceroute", "netstat", "arp", "iptables",
        "telnet", "ssh", "scp", "iwconfig", "iw", "wget", "curl", "nslookup", "dig", "ss", "tc",
        "ifup", "ifdown", "vconfig", "bridge", "iproute", "netcat", "nc", "tftp", "ftp",
        "df", "du", "free", "uptime", "uname", "hostname",
        "nice", "renice", "sysctl", "passwd", "chpasswd", "sysinfo",
        "fsck", "mkfs", "mke2fs", "mountpoint", "dd", "cpio", "mksquashfs", "unsquashfs", "mkfs.ext3", "mkfs.ext4",
        "killall", "pgrep", "pkill", "pidof", "nohup", "bg", "fg", "jobs",
        "vi", "vim", "nano", "ed", "emacs", "less", "more",
        "opkg", "ipkg", "pkg_add", "pkg_info",
        "uci", "nmcli", "networkctl", "brctl",
        "htop", "mpstat", "vmstat", "iostat", "sar", "lsof", "tcpdump",
        "openssl", "md5sum", "sha1sum", "sha256sum", "sha512sum",
        "ntpdate", "chronyd", "ntpd", "rdate", "busybox",
        "xz", "bzip2", "lbzip2", "lzma", "lzip", "zstd",
        "clear", "history", "which", "whereis", "whoami", "id", "su", "sudo", "reset", "tty",
        "od", "hexdump", "xxd", "stat", "file", "lshw", "lscpu", "sync", "mdadm", "ntfs-3g",
        "httpd", "uhttpd", "lighttpd", "jjhttpd", "shttpd", "thttpd", "minihttpd", "mini_httpd",
        "mini_httpds", "dhttpd", "alphapd", "goahead", "boa", "appweb", "shgw_httpd",
        "tenda_httpd", "funjsq_httpd", "webs", "hunt_server", "hydra",
        "miniupnpd", "miniupnpc", "mini_upnpd", "miniupnpd_ap", "miniupnpd_wsc",
        "upnp", "upnpc", "upnpd", "upnpc-static", "upnprenderer",
        "bcmupnp", "wscupnpd", "upnp_app", "upnp_igd", "upnp_tv_devices",
        "ddnsd", "dnsmasq", "udhcpd", "dnsmasq"
    }
    
    # 黑名单包含危险命令，这些命令始终被禁止执行
    IMMUTABLE_BLACKLIST = {
        "insmod", "modprobe", "rmmod", "shutdown"
        "mount", "umount", "poweroff", "reboot"
    }

    def __init__(self, container_fs_path, container_name, fs_path,
                 api_key="sk-o20HTjWDHvtm25HPmjfWgkrOdRDH79bXLRA3UGZDFPXTTYL5", model="deepseek-v3.2",
                 target_application="HTTP Server", host_accesscontrold="10.201.169.58", port_accesscontrold=9999):
        self.container_fs_path = container_fs_path
        self.container_name = container_name
        self.fs_path = fs_path
        self.api_key = api_key
        self.model = model
        self.target_application = target_application
        self.host = host_accesscontrold
        self.port = port_accesscontrold
        self.try_max_num = 3
        
        # 设置环境变量
        # os.environ['https_proxy'] = f'http://{proxy_ip}:{proxy_port}'
        # os.environ['http_proxy'] = f'http://{proxy_ip}:{proxy_port}'
        # os.environ['all_proxy'] = f'socks5://{proxy_ip}:{proxy_port}'
        
        # LLM相关属性
        self.total_input_token = 0
        self.total_output_token = 0
        
        # 通信文件路径
        self.communication_file = os.path.join(container_fs_path, "msg_init.txt")
        self.result_file = os.path.join(container_fs_path, "result_init.txt")
        self.lock_file = os.path.join(container_fs_path, "msg_init.lock")
        
        # 其他属性
        self.init_script_path = ""
        self.is_error = False
        self.stop_flag = False
        self.script_process_time = 0
        self.check_blacklist_time = 0
        
        # LLM请求计数
        self.llm_request_count = 0
        # 使用threading.Lock保证线程安全
        self.llm_request_lock = threading.Lock()
        
        # 白名单和黑名单
        self.whitelist: set[str] = set()
        self.blacklist: set[str] = set()
        self.cmds: list[str] = []
        self.original_cmds: list[str] = []
        self.whitelist_loaded: bool = False
        self.blacklist_loaded: bool = False
        
        # 已过滤脚本列表
        self.filtered_scripts_file = os.path.join(self.fs_path, "filtered_init_scripts.txt")
        self.filtered_scripts: set[str] = set()
        self.load_filtered_scripts()
        
        # 获取docker容器实例
        try:
            self.container = docker.from_env().containers.get(container_name)
        except docker.errors.NotFound:
            raise RuntimeError(f"容器 '{container_name}' 不存在，请检查容器名称是否正确")
        except docker.errors.APIError as e:
            raise RuntimeError(f"Docker API 调用失败: {e}")
        except Exception as e:
            raise RuntimeError(f"获取容器实例时发生未知错误: {e}")
        
        # 初始化OpenAI客户端
        self.client = OpenAI(
            api_key=api_key,
            base_url="https://api.vectorengine.ai/v1",
        )
        
        # 构建提示词
        self.system_content = f'''
You are a firmware analysis expert specializing in router firmware internals and their behavior in virtualized environments.
The firmware runs on a generic hardware platform (e.g., server) in a Docker container, without support for specific hardware like network cards, storage, or NVRAM, preventing some components from functioning properly.
Your task is to analyze and sanitize a router init script to make it suitable for virtualization, while preserving functionality related to the target application {self.target_application}.

Objective
Remove script sections unrelated to the target application, retaining only the necessary operations to ensure the proper functioning of the target application.

Editing Rules
1. Commands that must always be retained: cp, echo, mkdir.
2. Output the full modified script, with no comments (all # ... lines removed).
3. Use a conservative strategy: If you are unsure whether a command affects {self.target_application}, keep it.

Classification Criteria
Retain relevant operations:
1. Network interface setup, such as ifconfig, brctl, vconfig, ip, bridge/routing/VLAN/WAN/LAN/WiFi configuration, etc.
2. Database/configuration services, such as xmldb, rgdb, or configuration storage access.
3. Any command, script, or service that may directly or indirectly interact with {self.target_application}.
Remove irrelevant operations:
1. Hardware-related: Focus on the software layer, as hardware is unavailable. Exclude kernel module loading (insmod, modprobe), device mounts (mount /dev/...), drivers (USB, storage, NVRAM, etc.), and device checks (e.g., network card existence), devive config.
2. System services: Remove file systems, reset daemons, and init daemons unrelated to networking or database access.
3. Security & access control: Remove ACLs, WPS, encryption, guest zones, certificates, etc., as they may block access to the target application.
4. Background services: Remove logging, printing, DNS, DHCP, and country/language/timezone setup. 
5. Identify and sanitize script logic that may cause infinite loops(while, for) or blocking behavior because of missing hardware or file system files.

Example:
Input:
#!/bin/sh
insmod /lib/modules/nas_gpio_access.ko
mount /dev/sda1 /mnt
/etc/templates/logs.sh
ifconfig ath0 hw ether "00:13:10:d1:00:02"
rgdb -i -s /runtime/wan/inf:1/mac "00:13:10:d1:00:01"
brctl addbr br0
while [ -n " $ V_NAME" ]
do
    VIRTUAL_WLAN_INTERFACE=" $ VIRTUAL_WLAN_INTERFACE  $ VIRTUAL_WLAN_PREFIX $ VIRTUAL_NUM"
    VIRTUAL_NUM='expr  $ VIRTUAL_NUM + 1'
    V_LINE='echo  $ V_DATA | grep  $ VIRTUAL_WLAN_PREFIX $ VIRTUAL_NUM'
    V_NAME='echo  $ V_LINE | cut -b -9'
done

Output:
#!/bin/sh
# Stripped hardware ops, loops, and irrelevant services.
ifconfig ath0 hw ether "00:13:10:d1:00:02"
rgdb -i -s /runtime/wan/inf:1/mac "00:13:10:d1:00:01"
brctl addbr br0
'''

    def get_filtered_scripts(self):
        """
        获取已过滤的脚本集合
        """
        return self.filtered_scripts
    
    def rename_file(self, file_path, suffix="_bak"):
        """
        重命名文件
        """
        base_name, extension = os.path.splitext(file_path)
        new_file_path = base_name + suffix + extension
        os.rename(file_path, new_file_path)
        print(f"[InitServer] Rename file: {file_path} -> {new_file_path}")
    
    def load_filtered_scripts(self):
        """
        加载已过滤的脚本路径列表
        """
        try:
            if os.path.exists(self.filtered_scripts_file):
                with open(self.filtered_scripts_file, 'r') as f:
                    for line in f:
                        script_path = line.strip()
                        if script_path:
                            # 保存完整脚本路径
                            self.filtered_scripts.add(script_path)
                print(f"[InitServer] Loaded {len(self.filtered_scripts)} filtered scripts from {self.filtered_scripts_file}")
        except Exception as e:
            print(f"[InitServer] [!] Error loading filtered scripts: {e}")
    
    def add_filtered_script(self, script_path):
        """
        添加已过滤的脚本路径到列表和文件，确保不重复
        """
        
        if script_path not in self.filtered_scripts:
            self.filtered_scripts.add(script_path)
            try:
                with open(self.filtered_scripts_file, 'a') as f:
                    f.write(f"{script_path}\n")
                # print(f"[InitServer] Added {script_path} to filtered scripts list")
            except Exception as e:
                print(f"[InitServer] [!] Error adding {script_path} to filtered scripts file: {e}")

    def remove_markdown_comments(self, code):
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

    def send_request_via_tcp(self, host: str, port: int, obj, timeout=10.0):
        """
        通过TCP socket发送请求
        """
        with socket.create_connection((host, port), timeout=timeout) as s:
            data = json.dumps(obj, ensure_ascii=False) + "\n"
            s.sendall(data.encode("utf-8"))
            resp = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if b"\n" in resp:
                    line, _ = resp.split(b"\n", 1)
                    return json.loads(line.decode("utf-8"))
        raise RuntimeError("no response")

    def _call_accesscontrol_client(self, command: str, entry: str = None) -> dict:
        """
        调用accesscontrol客户端
        """
        obj = {"action": command}
        if entry is not None:
            obj["entry"] = entry
        
        try:
            resp = self.send_request_via_tcp(self.host, self.port, obj, timeout=10.0)
            # print(f"[InitServer] AccessControl command '{command}' succeeded")
            return resp
        except Exception as e:
            print(f"[InitServer] [!] TCP IPC failed: {e}")
            return {"status": "error", "message": f"TCP IPC failed: {e}"}

    def load_whitelist_blacklist(self, list_type="both", force_reload=False):
        """
        加载白名单和黑名单
        """
        if list_type not in ["both", "whitelist", "blacklist"]:
            print(f"[InitServer] [!] Invalid list_type: {list_type}, using 'both'")
            list_type = "both"
        
        # 检查是否需要加载白名单
        need_whitelist = list_type in ["both", "whitelist"]
        need_blacklist = list_type in ["both", "blacklist"]
        
        # 如果已经加载且不强制重新加载，则跳过
        if not force_reload:
            if need_whitelist and self.whitelist_loaded:
                # print(f"[InitServer] Whitelist already loaded, skipping ({len(self.whitelist)} entries)")
                need_whitelist = False
            if need_blacklist and self.blacklist_loaded:
                # print(f"[InitServer] Blacklist already loaded, skipping ({len(self.blacklist)} entries)")
                need_blacklist = False
        
        # 如果都不需要加载，直接返回
        if not need_whitelist and not need_blacklist:
            return True
        
        if need_whitelist:
            print("[InitServer] Loading whitelist from accesscontrold")
            whitelist_response = self._call_accesscontrol_client("whitelist_list")
            if whitelist_response.get("status") == "ok":
                self.whitelist = set(whitelist_response.get("data", []))
                self.whitelist_loaded = True
                print(f"[InitServer] Whitelist loaded: {len(self.whitelist)} entries")
            else:
                print(f"[InitServer] [!] Failed to load whitelist: {whitelist_response.get('message', 'Unknown error')}")
                # self.whitelist = set()
                # self.whitelist_loaded = False
                return False
        
        if need_blacklist:
            print("[InitServer] Loading blacklist from accesscontrold")
            blacklist_response = self._call_accesscontrol_client("blacklist_list")
            if blacklist_response.get("status") == "ok":
                self.blacklist = set(blacklist_response.get("data", []))
                self.blacklist_loaded = True
                print(f"[InitServer] Blacklist loaded: {len(self.blacklist)} entries")
            else:
                print(f"[InitServer] [!] Failed to load blacklist: {blacklist_response.get('message', 'Unknown error')}")
                # self.blacklist = set()
                # self.blacklist_loaded = False
                return False
        
        return True

    def load_ast(self, path) -> any:
        """
        加载AST JSON文件
        """
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            print(f"[InitServer] [✖] JSON parsing failed for {path}: {e}")
            return None
        except Exception as e:
            print(f"[InitServer] [✖] Failed to load AST file {path}: {e}")
            return None

    def extract_literal(self, word_node) -> str:
        """
        递归提取 Word/Parts/Lit 的值
        """
        if not isinstance(word_node, dict):
            return ""
        t = word_node.get("Type")
        if t == "Lit":
            return word_node.get("Value", "")
        # Word 节点可能有 Parts 列表
        for key in ["Parts", "Words"]:
            if key in word_node:
                for p in word_node[key]:
                    val = self.extract_literal(p)
                    if val:
                        return val
        return ""

    def extract_commands(self, node, cmds):
        """
        从AST中提取命令
        """
        if not isinstance(node, dict):
            return

        node_type = node.get("Type")

        # CallExpr 节点处理
        if node_type == "CallExpr":
            args = node.get("Args", [])
            if args:
                first = args[0]
                cmd_name = self.extract_literal(first)
                if cmd_name and cmd_name not in cmds:
                    cmds.append(cmd_name)

        # 递归遍历其它字段
        for key, value in node.items():
            if isinstance(value, dict):
                self.extract_commands(value, cmds)
            elif isinstance(value, list):
                for item in value:
                    self.extract_commands(item, cmds)

    def parse_init_script(self, save_original=False):
        """
        解析init脚本为AST，并提取命令
        
        Returns:
            bool: 解析成功返回True，失败返回False
        """
        # 使用已经转换好的self.init_script_path
        real_init_script_path = os.path.join(self.fs_path, self.init_script_path.lstrip("/"))
            
        base_name, _ = os.path.splitext(os.path.basename(real_init_script_path))
        parser_ast_path = f"/tmp/{base_name}_ast.json"
        
        # 如果 AST 文件已存在则跳过 shfmt
        if not os.path.exists(parser_ast_path):
            # 使用真实文件路径执行 shfmt 命令
            shell_to_ast_cmd = f"shfmt --to-json < {real_init_script_path} > {parser_ast_path}"
            # print(f"[InitServer] Running: {shell_to_ast_cmd}")
            
            try:
                result = subprocess.run(shell_to_ast_cmd, shell=True, check=True, text=True, capture_output=True)
                # Check if the generated file is empty
                if os.path.exists(parser_ast_path):
                    if os.path.getsize(parser_ast_path) == 0:
                        print(f"[InitServer] [✖] shfmt generated empty JSON file: {parser_ast_path}")
                        return False
                else:
                    print(f"[InitServer] [!] File not found: {parser_ast_path}")
                    return False
            except subprocess.CalledProcessError as e:
                print(f"[InitServer] [✖] Generate AST JSON failed with error code {e.returncode}")
                print(f"[InitServer] [✖] Error output: {e.stderr}")
                print(f"[InitServer] [✖] Command: {shell_to_ast_cmd}")
                return False
            except Exception as e:
                print(f"[InitServer] [✖] Unexpected error generating AST: {e}")
                print(f"[InitServer] [✖] Command: {shell_to_ast_cmd}")
                return False
        
        ast_data = self.load_ast(parser_ast_path)
        
        if ast_data is None:
            print(f"[InitServer] [✖] Failed to load or parse AST data from {parser_ast_path}")
            return False
        
        # 如果保存原始命令集(方便对比过滤前后命令差别)，则先保存到original_cmds，否则保存到cmds
        if save_original:
            self.extract_commands(ast_data, self.original_cmds)
            # print(f"Original commands: {', '.join(self.original_cmds)}")
        else:
            self.extract_commands(ast_data, self.cmds)
            # print(f"Current commands: {', '.join(self.cmds)}")
        
        return True

    def get_time(self) -> float:
        """
        获取指定时间类型的时间值
        """
        time = self.script_process_time
        self.script_process_time = 0.0
        time = time + self.check_blacklist_time
        self.check_blacklist_time = 0.0
        return time
    
    def compare_commands_with_lists(self) -> dict:
        """
        比较命令与白名单和黑名单
        """
        result = {
            "in_blacklist": [],
            "in_whitelist": [],
            "not_in_lists": []
        }

        for cmd in self.original_cmds:
            cmd_name = cmd.split()[0] if cmd.strip() else ""
            if not cmd_name:
                continue

            # 首先检查不可被更改的黑名单
            if cmd_name in self.IMMUTABLE_BLACKLIST:
                result["in_blacklist"].append(cmd)
            # 然后检查不可被更改的白名单
            elif cmd_name in self.IMMUTABLE_WHITELIST:
                result["in_whitelist"].append(cmd)
            # 然后检查常规黑名单
            elif cmd_name in self.blacklist:
                result["in_blacklist"].append(cmd)
            # 最后检查常规白名单
            elif cmd_name in self.whitelist:
                result["in_whitelist"].append(cmd)
            else:
                result["not_in_lists"].append(cmd)

        # print(f"[InitServer] in_blacklist: {result['in_blacklist']}")
        # print(f"[InitServer] in_whitelist: {result['in_whitelist']}")
        # print(f"[InitServer] not_in_lists: {result['not_in_lists']}")

        return result

    def compare_original_and_new_commands(self):
        """
        比较原始命令和新命令
        """
        if not self.original_cmds:
            print("[InitServer] [!] No original commands to compare")
            return set(), set()
        
        # 找出被移除的命令
        removed_commands = set(self.original_cmds) - set(self.cmds)
        # 找出保留的命令
        retained_commands = set(self.original_cmds) & set(self.cmds)
        
        # 过滤掉不可变命令
        filtered_removed_commands = set()
        for cmd in removed_commands:
            cmd_name = cmd.split()[0] if cmd.strip() else ""
            if cmd_name and cmd_name not in self.IMMUTABLE_WHITELIST and cmd_name not in self.IMMUTABLE_BLACKLIST:
                filtered_removed_commands.add(cmd)
        
        filtered_retained_commands = set()
        for cmd in retained_commands:
            cmd_name = cmd.split()[0] if cmd.strip() else ""
            if cmd_name and cmd_name not in self.IMMUTABLE_WHITELIST and cmd_name not in self.IMMUTABLE_BLACKLIST:
                filtered_retained_commands.add(cmd)
        
        # print("[InitServer] === Command Set Comparison Results ===")
        # print(f"[InitServer] Original command count: {len(self.original_cmds)}")
        # print(f"[InitServer] New script command count: {len(self.cmds)}")
        # print(f"[InitServer] Retained command count: {len(filtered_retained_commands)}")
        # print(f"[InitServer] Removed command count: {len(filtered_removed_commands)}")
        
        # if filtered_removed_commands:
        #     print(f"[InitServer] Removed commands: {', '.join(filtered_removed_commands)}")
        # if filtered_retained_commands:
        #     print(f"[InitServer] Retained commands: {', '.join(filtered_retained_commands)}")
        
        # print("[InitServer] === Command Set Comparison Completed ===")
        
        return filtered_removed_commands, filtered_retained_commands

    def update_whitelist_and_blacklist(self, removed_commands, retained_commands):
        """
        更新白名单和黑名单
        """
        # print("Updating whitelist and blacklist in accesscontrol_server")
        
        # 如果被移除的命令在当前白名单中，则从白名单中移除，并加入到黑名单
        for cmd in removed_commands:
            cmd_name = cmd.split()[0] if cmd.strip() else ""
            if not cmd_name:
                continue
                
            # 跳过不可被更改的命令
            if cmd_name in self.IMMUTABLE_WHITELIST or cmd_name in self.IMMUTABLE_BLACKLIST:
                # print(f"[InitServer] Skipping immutable command: {cmd}")
                continue
            
            # 跳过以.sh结尾的文件
            if cmd_name.endswith('.sh'):
                # print(f"[InitServer] Skipping .sh file: {cmd}")
                continue
                
            if cmd in self.whitelist:
                response = self._call_accesscontrol_client("whitelist_remove", cmd)
                if response.get("status") == "ok":
                    # print(f"[InitServer] Removed from whitelist: {cmd}")
                    self.whitelist.discard(cmd)
                else:
                    print(f"[InitServer] [!] Failed to remove {cmd} from whitelist: {response.get('message', 'Unknown error')}")
                    return False
                
            if cmd not in self.blacklist:
                response = self._call_accesscontrol_client("blacklist_add", cmd)
                if response.get("status") == "ok":
                    # print(f"[InitServer] Added to blacklist: {cmd}")
                    self.blacklist.add(cmd)
                else:
                    print(f"[InitServer] [!] Failed to add {cmd} to blacklist: {response.get('message', 'Unknown error')}")
                    return False
        
        # 如果被保留的命令在当前黑名单中，则从黑名单中移除，并加入到白名单
        for cmd in retained_commands:
            cmd_name = cmd.split()[0] if cmd.strip() else ""
            if not cmd_name:
                continue
                
            # 跳过不可被更改的命令
            if cmd_name in self.IMMUTABLE_WHITELIST or cmd_name in self.IMMUTABLE_BLACKLIST:
                # print(f"[InitServer] Skipping immutable command: {cmd}")
                continue
            
            # 跳过以.sh结尾的文件
            if cmd_name.endswith('.sh'):
                # print(f"[InitServer] Skipping .sh file: {cmd}")
                continue
                
            if cmd in self.blacklist:
                response = self._call_accesscontrol_client("blacklist_remove", cmd)
                if response.get("status") == "ok":
                    print(f"[InitServer] Removed from blacklist: {cmd}")
                    self.blacklist.discard(cmd)
                else:
                    print(f"[InitServer] [!] Failed to remove {cmd} from blacklist: {response.get('message', 'Unknown error')}")
                    return False
                
            if cmd not in self.whitelist:
                response = self._call_accesscontrol_client("whitelist_add", cmd)
                if response.get("status") == "ok":
                    # print(f"[InitServer] Added to whitelist: {cmd}")
                    self.whitelist.add(cmd)
                else:
                    print(f"[InitServer] [!] Failed to add {cmd} to whitelist: {response.get('message', 'Unknown error')}")
                    return False       
        
        # print(f"[InitServer] Whitelist updated: {len(self.whitelist)} entries")
        # print(f"[InitServer] Blacklist updated: {len(self.blacklist)} entries")
        return True

    def filter_init_script(self):
        """
        过滤init脚本
        """
        real_init_script_path = os.path.join(self.fs_path, self.init_script_path.lstrip("/"))
        with open(real_init_script_path, 'r') as f:
            init_script = f.read()
        
        prompt = [
            {"role": "system", "content": self.system_content},
            {"role": "user", "content": init_script}
        ]
        
        response_content = ""
        num_try = 0
        
        while num_try <= self.try_max_num:
            num_try += 1
            
            # print(f"[InitServer] Calling Qwen API for the {num_try}th time")
            
            start_time = time.time()
            
            # 增加LLM请求计数
            with self.llm_request_lock:
                self.llm_request_count += 1
                # 创建锁文件，使用时间戳防止重复
                timestamp = int(time.time() * 1000)  # 毫秒级时间戳
                lock_file = f"{LLM_LOCK_PREFIX}{timestamp}"
                # print(f"[InitServer] Creating lock file: {lock_file}")
                open(lock_file, 'w').close()
            
            try:
                # 使用OpenAI客户端调用LLM
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=prompt,
                    temperature=1,
                    top_p=0.5,
                )
                
                end_time = time.time()
                llm_time = end_time - start_time
                
                # 记录token使用情况
                self.total_input_token += response.usage.prompt_tokens
                self.total_output_token += response.usage.completion_tokens
                print(f"[InitServer] Input tokens for attempt {num_try}: {response.usage.prompt_tokens}")
                print(f"[InitServer] Output tokens for attempt {num_try}: {response.usage.completion_tokens}")
                print(f"[InitServer] LLM API call time for attempt {num_try}: {llm_time:.2f} seconds")
                
                # 获取回复内容
                response_content = response.choices[0].message.content
                # print("=" * 20 + "Complete Response" + "=" * 20)
                # print(response_content)
                break
            except AuthenticationError as e:
                print(f"[InitServer] Authentication error: {e}")
                print(f"[InitServer] Please check your API key.")
                response_content = ""  # 清空回复内容，触发后续的失败处理
                break  # 认证错误，直接跳出循环，不重试
            except BadRequestError as e:
                print(f"[InitServer] Bad request error: {e}")
                print(f"[InitServer] Please check your request parameters.")
                response_content = ""  # 清空回复内容，触发后续的失败处理
                break  # 请求参数错误，直接跳出循环，不重试
            except RateLimitError as e:
                print(f"[InitServer] Rate limit error: {e}")
                print(f"[InitServer] Too many requests, waiting before retry...")
                response_content = ""  # 清空回复内容，以便进行下一次尝试
                time.sleep(2)  # 速率限制，等待2秒后重试
            except APIConnectionError as e:
                print(f"[InitServer] Connection error: {e}")
                print(f"[InitServer] Network issue, retrying...")
                response_content = ""  # 清空回复内容，以便进行下一次尝试
                time.sleep(1)  # 连接错误，等待1秒后重试
            except APIError as e:
                print(f"[InitServer] API error: {e}")
                print(f"[InitServer] Server error, retrying...")
                response_content = ""  # 清空回复内容，以便进行下一次尝试
                time.sleep(1)  # API错误，等待1秒后重试
            except Exception as e:
                print(f"[InitServer] Unexpected error: {e}")
                print(f"[InitServer] Unknown error, retrying...")
                response_content = ""  # 清空回复内容，以便进行下一次尝试
                time.sleep(1)  # 未知错误，等待1秒后重试
            finally:
                # 减少LLM请求计数
                with self.llm_request_lock:
                    self.llm_request_count -= 1
                    # 删除锁文件
                    os.remove(lock_file)
        
        if not response_content:
            print("[InitServer] [!] All attempts failed, unable to get LLM response")
            return
        
        # 移除Markdown注释
        response_content = self.remove_markdown_comments(response_content)
        
        # # 备份原文件并写入新内容
        # self.rename_file(real_init_script_path)
        # 删除原文件并写入新内容
        if os.path.exists(real_init_script_path):
            os.remove(real_init_script_path)
            # print(f"[InitServer] Deleted original init script: {real_init_script_path}")
        
        # print(f"[InitServer] Writing new init script to {real_init_script_path}")
        with open(real_init_script_path, 'w') as f:
            f.write(response_content)
        
        # 复制过滤后的脚本到容器中
        try:
            tar_stream = io.BytesIO()
            with tarfile.open(fileobj=tar_stream, mode='w') as tar:
                tar.add(real_init_script_path, arcname=os.path.basename(self.init_script_path))
            tar_stream.seek(0)
            docker_path = os.path.join(self.container_fs_path, os.path.dirname(self.init_script_path))
            # 复制到容器中的对应路径
            self.container.put_archive(path=docker_path, data=tar_stream.read())
            # print(f"[InitServer] Successfully copied filtered init script to container")
        except Exception as e:
            print(f"[InitServer] Failed to copy filtered init script to container: {e}")
            
        # 解析新脚本
        # print("[InitServer] Parsing LLM-generated init script")
        self.parse_init_script()
        
        # 比较原始脚本和新脚本
        removed_commands, retained_commands = self.compare_original_and_new_commands()
        
        # 更新白名单和黑名单
        self.update_whitelist_and_blacklist(removed_commands, retained_commands)

    def resolve_init_script_path(self):
        """
        解析并转换init脚本路径
        
        Returns:
            str: 成功返回True，失败返回错误信息
        """
        # 在self.fs_path中查找init脚本
        real_init_script_path = os.path.join(self.fs_path, self.init_script_path.lstrip("/"))
        found_files = []
        
        # 先处理软连接，获取真实文件路径
        resolved_path = real_init_script_path
        max_resolve_attempts = 10  # 防止循环软连接
        attempt = 0
        
        while os.path.islink(resolved_path) and attempt < max_resolve_attempts:
            attempt += 1
            link_target = os.readlink(resolved_path)
            link_target_in_fs = link_target.lstrip("/")
            resolved_path = os.path.join(self.fs_path, link_target_in_fs)
            
            # 标准化路径，避免路径中出现../
            resolved_path = os.path.normpath(resolved_path)
            # print(f"[InitServer] [✓] Resolved {real_init_script_path} symlink to: {resolved_path} (attempt {attempt})")
        
        if attempt >= max_resolve_attempts:
            print(f"[InitServer] [✖] Too many symlink resolution attempts, possible circular symlink: {real_init_script_path}")
            return "parse_init_script_error"
        
        # 检查文件是否存在
        if os.path.exists(resolved_path):
            found_files = [resolved_path]
        else:
            print(f"[InitServer] [!] File not found: Init script <{resolved_path}>")
            # 在self.fs_path中搜索匹配的文件
            import mimetypes
            
            # 获取要查找的文件名
            target_filename = os.path.basename(self.init_script_path)
            
            # 在self.fs_path中递归搜索所有文件
            for root, dirs, files in os.walk(self.fs_path):
                for file in files:
                    if file == target_filename:
                        full_path = os.path.join(root, file)
                        # 处理找到的文件路径的软连接
                        temp_resolved = full_path
                        temp_attempt = 0
                        while os.path.islink(temp_resolved) and temp_attempt < max_resolve_attempts:
                            temp_attempt += 1
                            temp_link_target = os.readlink(temp_resolved)
                            temp_link_target_in_fs = temp_link_target.lstrip("/")
                            temp_resolved = os.path.join(self.fs_path, temp_link_target_in_fs)
                            temp_resolved = os.path.normpath(temp_resolved)
                            print(f"[InitServer] [✓] Resolved symlink to: {temp_resolved} (attempt {temp_attempt})")
                        if temp_attempt < max_resolve_attempts:
                            found_files.append(temp_resolved)
            
            if found_files:
                # 如果只找到一个文件则直接使用，不用检查
                if len(found_files) == 1:
                    resolved_path = found_files[0]
                    print(f"[InitServer] [✓] Found single file: {resolved_path}")
                else:
                    # 筛选文本文件
                    text_files = []
                    for file_path in found_files:
                        # 使用mimetypes猜测文件类型
                        mime_type, _ = mimetypes.guess_type(file_path)
                        if mime_type and mime_type.startswith('text/'):
                            text_files.append(file_path)
                        else:
                            # 尝试读取文件内容，判断是否为文本文件
                            try:
                                with open(file_path, 'r') as f:
                                    f.read(1024)  # 只读取前1024字节
                                text_files.append(file_path)
                            except UnicodeDecodeError:
                                continue
                    
                    if text_files:
                        # 选择第一个文本文件
                        resolved_path = text_files[0]
                        print(f"[InitServer] [✓] Found text file: {resolved_path}")
                    else:
                        # 没有找到文本文件，选择第一个找到的文件
                        resolved_path = found_files[0]
                        print(f"[InitServer] [✓] Found non-text file: {resolved_path}")
            else:
                print(f"[InitServer] [✖] No matching files found in {self.fs_path}")
                return "parse_init_script_error"
        
        # 更新为解析后的真实路径
        real_init_script_path = resolved_path
        self.init_script_path = os.path.relpath(real_init_script_path, self.fs_path)
        return True
    
    def script_process(self):
        """
        处理init脚本
        """
        # 跳过运行时产生的临时文件夹下的脚本过滤
        runtime_dirs = ['tmp/', 'var/', 'run/', 'mnt/', 'media/', 'dev/', 'sys/', 'proc/']
        runtime_paths = ['/tmp/', '/var/', '/run/', '/mnt/', '/media/', '/dev/', '/sys/', '/proc/']
        
        script_path = self.init_script_path
        skip_filter = False
        for dir_prefix in runtime_dirs:
            if script_path.startswith(dir_prefix):
                skip_filter = True
                break
        
        if not skip_filter:
            for path in runtime_paths:
                if path in script_path:
                    skip_filter = True
                    break
        
        if skip_filter:
            print(f"[InitServer] Script {script_path} is in runtime directory, skipping LLM filtering")
            return "success"
        
        # 解析并转换init脚本路径
        result = self.resolve_init_script_path()
        if result != True:
            return "not_found_init_script"
        
        # 检查脚本是否已经被LLM过滤过
        script_path = self.init_script_path
        
        if script_path in self.filtered_scripts:
            print(f"[InitServer] Script {script_path} has been filtered by LLM before, skipping LLM filtering")
            return "success"
        
        # 解析原始脚本并保存原始shell指令集合
        parse_success = self.parse_init_script(save_original=True)
        
        # 如果解析成功，加载白名单和黑名单并比较命令
        if parse_success:
            # 加载白名单和黑名单
            if not self.load_whitelist_blacklist("both"):
                return "accesscontrold_error"
            
            # 与白名单和黑名单比较当前shell脚本中命令
            result = self.compare_commands_with_lists()

            # 如果存在不在白名单和黑名单中的命令，使用LLM过滤
            if result["not_in_lists"]:
                # print(f"[InitServer] Commands not in whitelist or blacklist found, using LLM to filter init script")
                self.filter_init_script()
                # 添加到已过滤脚本列表
                self.add_filtered_script(self.init_script_path)
                return "success"
            
            # 如果都是已知命令，且存在黑名单中的命令，则将黑名单写入本地文件，供qemu内部判断是否需要跳过对应命令
            elif result["in_blacklist"]:
                print(f"[InitServer] Some commands in blacklist, running init script")
                return "some_in_blacklist"
            
            # 如果全是白名单中的命令，直接运行
            else:
                # print(f"[InitServer] All commands in whitelist, running init script")
                return "success"
        
        # 如果解析失败，直接使用LLM进行过滤
        else:
            # print(f"[InitServer] Script parsing failed, using LLM to filter init script directly")
            self.filter_init_script()
            # 添加到已过滤脚本列表
            self.add_filtered_script(self.init_script_path)
            return "success"

    def check_command_blacklist(self, entry: str) -> str:
        """
        检查命令是否在黑名单中
        """
        # 首先检查不可被更改的黑名单
        if entry in self.IMMUTABLE_BLACKLIST:
            # print(f"[InitServer] {entry} is in immutable blacklist")
            return "in_blacklist"
        
        # 然后检查常规黑名单
        if not self.load_whitelist_blacklist("blacklist"):
            return "accesscontrold_error"
        
        if entry in self.blacklist:
            # print(f"[InitServer] {entry} is in blacklist")
            return "in_blacklist"
        else:
            # print(f"[InitServer] {entry} is not in blacklist")
            return "not_in_blacklist"

    def parse_communication_file(self):
        """
        解析通信文件
        """
        try:
            # 从容器中读取通信文件内容
            exit_code, output = self.container.exec_run(f"cat {self.communication_file}")
            if exit_code != 0:
                print(f"[InitServer] Failed to read communication file in container: {output.decode('utf-8', errors='ignore')}")
                return None, None
            content = output.decode('utf-8', errors='ignore').strip()
            
            # print(f"[InitServer] Received message: {content}")
            
            # 解析消息格式：s;消息内容
            parts = content.split(';', 1)
            if len(parts) == 2:
                service_id = parts[0]
                actual_message = parts[1]
                return service_id, actual_message
            else:
                print(f"[InitServer] [!] Invalid message format: {content}")
                return None, None
        except Exception as e:
            print(f"[InitServer] [!] Parse communication file error: {e}")
            return None, None

    def process_communication_file(self):
        """
        处理通信文件
        """
        start_time = time.time()
        try:
            # 检查容器是否运行
            if self.container.status != 'running':
                return
                
            # 检查锁文件是否存在
            exit_code, _ = self.container.exec_run(f"test -f {self.lock_file}")
            # print(f"[InitServer] lock_file exit_code {exit_code}")
            if exit_code == 0:
                return
            
            # 检查通信文件是否存在
            exit_code, _ = self.container.exec_run(f"test -f {self.communication_file}")
            # print(f"[InitServer] communication_file exit_code {exit_code}")
            if exit_code != 0:
                return
        except Exception as e:
            print(f"[InitServer] [!] Check container files error: {e}")
            return
        
        # 创建锁文件
        try:
            self.container.exec_run(f"touch {self.lock_file}")
        except Exception as e:
            print(f"[InitServer] [!] Create lock file failed: {e}")
            return
        
        # 解析通信文件
        service_id, actual_message = self.parse_communication_file()
        if not service_id or not actual_message:
            self.cleanup_files()
            return
        
        # 处理不同类型的请求
        reply = "unknown_service"
        if service_id == "e":
            # print("================================")
            # print(f"[InitServer] Checking blacklist for: {actual_message}")
            reply = self.check_command_blacklist(actual_message)
            end_time = time.time()
            self.check_blacklist_time += end_time - start_time
            # print(f"[InitServer] Check blacklist time: {end_time - start_time}")
        elif service_id == "s":
            # print("================================")
            self.init_script_path = actual_message
            print(f"[InitServer] Processing init script: {self.init_script_path}")
            reply = self.script_process()
            end_time = time.time()
            self.script_process_time += end_time - start_time
            # print(f"[InitServer] Script process time: {end_time - start_time}")
        else:
            print(f"[InitServer] [!] Unknown service: {service_id}")
        
        # 写入结果文件
        try:
            # 使用sh -c来正确处理重定向
            exit_code, output = self.container.exec_run(f'sh -c "echo \\"{reply}\\" > {self.result_file}"')
            # print(f"[InitServer] bash -c \"echo \\\"{reply}\\\" > {self.result_file}\"")
            if exit_code != 0:
            #     # 再次确认文件是否成功写入
            #     chk_exit, chk_out = self.container.exec_run(f"test -f {self.result_file}")
            #     if chk_exit == 0:
            #         print(f"[InitServer] Response sent: {reply}")
            #     else:
            #         print(f"[InitServer] [!] Result file not found after write: {self.result_file}")
            # else:
                print(f"[InitServer] [!] Write result file failed: {output.decode('utf-8', errors='ignore')}")
        except Exception as e:
            print(f"[InitServer] [!] Write result file error: {e}")
        
        # 清理文件
        self.cleanup_files()

    def cleanup_files(self):
        """
        清理文件
        """
        try:
            # 删除通信文件
            exit_code, output = self.container.exec_run(f"rm -f {self.communication_file}")
            if exit_code != 0:
                print(f"[InitServer] [!] Delete communication file failed: {output.decode('utf-8', errors='ignore')}")
            
            # 删除锁文件
            exit_code, output = self.container.exec_run(f"rm -f {self.lock_file}")
            if exit_code != 0:
                print(f"[InitServer] [!] Delete lock file failed: {output.decode('utf-8', errors='ignore')}")
        except Exception as e:
            print(f"[InitServer] [!] Cleanup files error: {e}")

    def stop(self):
        """
        停止服务器
        """
        self.stop_flag = True
        print("[InitServer] Init Script Server stop flag set")
        
        # 等待所有LLM请求结束
        import time
        print("[InitServer] Waiting for all LLM requests to complete...")
        while True:
            with self.llm_request_lock:
                current_count = self.llm_request_count
            if current_count == 0:
                break
            print(f"[InitServer] Still {current_count} LLM requests in progress, waiting...")
            time.sleep(5)
        print("[InitServer] All LLM requests completed")

    def check_accesscontrol_service(self):
        """
        检查accesscontrol服务是否开启
        """
        print(f"[InitServer] Checking accesscontrol service at {self.host}:{self.port}")
        try:
            # 尝试连接到accesscontrol服务
            with socket.create_connection((self.host, self.port), timeout=5.0):
                print("[InitServer] accesscontrol service is running")
                return True
        except Exception as e:
            print(f"[InitServer] [!] Failed to connect to accesscontrol service: {e}")
            return False

    def run(self, interval=1):
        """
        运行服务器
        """
        # 检查accesscontrol服务是否开启
        if not self.check_accesscontrol_service():
            print("[InitServer] [!] accesscontrol service is not running, exiting")
            return
        
        print(f"[InitServer] Init Script Server started")
        
        try:
            while not self.stop_flag:
                self.process_communication_file()
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[InitServer] Init Script Server stopped")
        except Exception as e:
            print(f"[InitServer] [!] Server error: {e}")
        finally:
            print("[InitServer] Init Script Server exited")

    def get_total_input_tokens(self):
        """
        获取总输入token数
        """
        return self.total_input_token

    def get_total_output_tokens(self):
        """
        获取总输出token数
        """
        return self.total_output_token
