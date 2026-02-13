import subprocess
import docker
from docker.errors import *
import os, shutil, stat
import time, tarfile
import traceback
import ipaddress
import json
import pathlib
import threading

from . import *
from .LLMServer import InitServer, ContainerPsMonitor, StartupCommandServer

DOCKER_FS = "fs"
TMP_DIR = "/tmp/greencontainers"
TMP_DEV = "gh_dev_tmp"
TMP_PROC = "gh_proc_tmp"
BG_SCRIPT = "run_background.sh"
SETUP_SCRIPT = "run_setup.sh"
INSTALL_CMD = "apt-get update && apt-get -y install vim curl"
SCRATCH_COMMANDS = "FROM ubuntu:20.04\nCOPY fs /%s\n" % DOCKER_FS
DEBUG_COMMANDS = "FROM ubuntu:20.04\nRUN %s\nCOPY fs /%s\nCMD [\"./%s/run_debug.sh\"]\n" % (INSTALL_CMD, DOCKER_FS, DOCKER_FS)
TRACE_LOG = "trace.log"
EXIT_CODE_TAG = "Greenhouse_EXIT_CODE::"
DONE_TAG = "GH_DONE"
HARD_TIMEOUT = 20 # mins
MISSING_NVRAM_FILE = "MISSING_NVRAMS"
BG_LOG = "GREENHOUSE_BGLOG"
GREENHOUSE_LOG = "GREENHOUSE_STDLOG"

class QemuRunner:
    ERROR_CODES = [139, # segfault
                   255, # can also mean exiting with -1
                    20, # 'network' error (peripheral device)
                   -11,
                   127, # assertion failed (invalid command)
                   132, # illegal instruction
                   134, # abort
                   -6,
                   135, # bus error
                   136, # arithmetic error
                   -8]
    TIMEOUT_CODE = 124 # linux timeout return value
    VERBOSE_LOG_TIMEOUT_MULTIPLIER = 5

    def __init__(self, fs_path, bin_path, init_path, qemu_arch, hash="", checker=None, 
                changelog=[], docker_ip="172.20.0.2", baseline_mode=False, hackbind=True, hackdevproc=True, hacksysinfo=True, api_key="", model=""):
        self.fs_path = fs_path
        self.bin_path = bin_path
        self.init_path = init_path
        self.qemu_arch = qemu_arch
        self.checker = checker
        self.hash = hash
        self.changelog = changelog
        self.docker_ip = docker_ip
        self.last_bincwd = "/"
        self.relative_bin_path = ""
        self.extra_args = ""
        self.nd_args = ""
        self.bg_cmds = []
        self.bg_sleep = 0
        self.qemu_command = ""
        self.emulation_output = ""
        self.client = None
        self.ipv6enable = False
        self.baseline_mode = baseline_mode
        self.hackbind = hackbind
        self.hackdevproc = hackdevproc 
        self.hacksysinfo = hacksysinfo 
        self.api_key = api_key
        self.model = model
        
        self.total_input_tokens = 0
        self.total_output_tokens = 0

    def get_token_stats(self):
        """
        获取token统计信息
        """
        return {
            'input_tokens': self.total_input_tokens,
            'output_tokens': self.total_output_tokens,
            'total_tokens': self.total_input_tokens + self.total_output_tokens
        } 

    def cleanup_dockerfs(self):
        print("Cleaning up ", self.fs_path)
        ARTIFACTS = ["GREENHOUSE_WEB_CANARY", "GHTMPSTORE", \
                     "npipes.log", "patch.log", "ps.log", "cwd.log" \
                     "qemu.final.serial.log", "target_ports", "target_urls"]
        # remove greenhouse artifacts
        for root, dirs, files in os.walk(self.fs_path, topdown=False):
            for f in files:
                if f in ARTIFACTS or f.startswith("trace.log"):
                    path = os.path.join(root, f)
                    Files.rm_target(path, silent=True)
            for d in dirs:
                if d in ARTIFACTS:
                    path = os.path.join(root, d)
                    Files.rm_target(path, silent=True)
        print("...done!")


    def export_current_dockerfs(self, dest_dir, result, name="", brand="", hash="", checker=None, external_qemu="", urls=[], time_to_up=-1):
        self.cleanup_dockerfs()

        if os.path.exists(dest_dir):
            Files.rm_folder(dest_dir, silent=True)
        minimal_folder = "minimal"
        debug_folder = "debug"
        src = self.fs_path
        mindest = os.path.join(dest_dir, minimal_folder)
        mindestfs = os.path.join(mindest, "fs")
        debugdest = os.path.join(dest_dir, debug_folder)
        debugdestfs = os.path.join(debugdest, "fs")
        
        if not os.path.exists(mindest):
            Files.mkdir(mindest, silent=True)
        Files.copy_directory(src, mindestfs)

        if not os.path.exists(debugdest):
            Files.mkdir(debugdest, silent=True)
        Files.copy_directory(src, debugdestfs)

        # copy tmp folder for min container
        tmp_path = str(pathlib.Path(os.path.join(mindestfs, "tmp")).resolve()) # handle symlinks
        if not tmp_path.startswith(mindestfs):
            tmp_path = os.path.join(mindestfs, tmp_path.strip("/"))
        if not os.path.exists(tmp_path):
            Files.mkdir(tmp_path, silent=True)
        Files.copy_directory(tmp_path, os.path.join(mindestfs, "ghtmp"))
        # copy etc folder for min container
        etc_path = str(pathlib.Path(os.path.join(mindestfs, "etc")).resolve()) # handle symlinks
        if not etc_path.startswith(mindestfs):
            etc_path = os.path.join(mindestfs, etc_path.strip("/"))
        if not os.path.exists(etc_path):
            Files.mkdir(etc_path, silent=True)
        Files.copy_directory(etc_path, os.path.join(mindestfs, "ghetc"))

        # replace qemu if exists in min cont
        if external_qemu != "":
            new_qemu_path = os.path.join(external_qemu, self.qemu_arch)
            old_qemu_path = os.path.join(mindestfs, self.qemu_arch)
            sbin_path = os.path.join(mindestfs, "usr", "bin")
            qemu_sbin_path = os.path.join(sbin_path, self.qemu_arch)
            print("    - replacing %s with %s" % (old_qemu_path, new_qemu_path))
            Files.copy_file(new_qemu_path, old_qemu_path, silent=True)
            print("    - replacing %s with %s" % (qemu_sbin_path, new_qemu_path))
            if not os.path.exists(sbin_path) or not os.path.isdir(sbin_path):
                Files.mkdir(sbin_path, silent=True)
            Files.copy_file(new_qemu_path, qemu_sbin_path, silent=True)

        ipaddr = ""
        port = ""
        ports = ["80", "1900"] # also expose UDP ports
        user = ""
        password = ""
        loginurl = ""
        logintype = ""
        configs = dict()
        qemu_args = dict()

        ipaddr, port, loginurl, logintype, user, password, headers, payload = ("", "", "", "", "", "", "", "")
        # make json dump
        if checker is not None:
            ipaddr, port, loginurl, logintype, user, password, headers, payload = checker.get_working_ip_set()
            port = port.strip()
            if len(port) > 0 and port not in ports:
                ports.append(port)

        # path to background script
        bg_scripts = []
        bg_path = self.get_minimal_command("/bin/sh /%s" % BG_SCRIPT).strip()
        setup_bind_path = "/%s" % SETUP_SCRIPT
        bg_scripts.append((bg_path, self.bg_sleep))
        bg_scripts.append((setup_bind_path, 1))

        # add extra qemu arguments
        otherargs = "/"+self.qemu_arch
        if self.hackbind:
            qemu_args["hackbind"] = ""
            otherargs += " -hackbind"
        if self.hackdevproc:
            qemu_args["hackproc"] = ""
            otherargs += " -hackproc"
        if self.hacksysinfo:
            qemu_args["hacksysinfo"] = ""
            otherargs += " -hacksysinfo"
        qemu_args["execve"] = otherargs

        configs["image"] = name
        configs["hash"] = hash
        configs["brand"] = brand
        configs["result"] = result
        configs["seconds_to_up"] = time_to_up
        configs["targetpath"] = self.relative_bin_path
        configs["targetip"] = ipaddr
        configs["targetport"] = port
        configs["ipv6enable"] = self.ipv6enable
        configs["env"] = {"LD_PRELOAD" : "libnvram-faker.so"}
        configs["workdir"] = self.last_bincwd
        configs["background"] = bg_scripts
        configs["loginuser"] = user
        configs["loginpassword"] = password
        configs["loginurl"] = loginurl
        configs["logintype"] = logintype
        configs["loginheaders"] = headers
        configs["loginpayload"] = payload
        configs["qemuargs"] = qemu_args
        jsonFileDest = os.path.join(dest_dir, "config.json")
        with open(jsonFileDest, "w") as jsonFile:        
            json.dump(configs, jsonFile, indent = 6)        
        jsonFile.close()

        # create dockerfile
        dockerfileDest = os.path.join(mindest, "Dockerfile")
        # construct minimal dockerfile for exporting
        with open(dockerfileDest, "w") as dockerFile:
            dockerFile.write("FROM scratch\n")
            dockerFile.write("ADD fs /\n\n")
            dockerFile.write("ENV LD_PRELOAD=libnvram-faker.so\n\n")
            # dockerFile.write("WORKDIR %s\n\n" % self.last_bincwd)
            for port in ports:
                dockerFile.write("EXPOSE %s/tcp\n" % port)
                dockerFile.write("EXPOSE %s/udp\n" % port)
            dockerFile.write("\n")
            dockerFile.write("ENTRYPOINT [\"/greenhouse/busybox\", \"sh\", \"/run_clean.sh\"]\n\n")
            dockerFile.write("CMD [\"%s\", \"--\", \"%s\"" % (self.qemu_arch, self.relative_bin_path))
            if len(self.nd_args) > 0:
                dockerFile.write(", \"%s\"" % self.nd_args)
            for arg in self.extra_args.split():
                dockerFile.write(", \"%s\"" % arg)
            dockerFile.write("]")
        dockerFile.close()

        # create debug dockerfile
        dockerfileDest = os.path.join(debugdest, "Dockerfile")
        # construct debug dockerfile for exporting
        with open(dockerfileDest, "w") as dockerFile:
            dockerFile.write(DEBUG_COMMANDS)
        dockerFile.close()

        # create debug script
        debugRun = os.path.join(debugdest, DOCKER_FS, "run_debug.sh")
        with open(debugRun, "w") as df:
            df.write("#!/bin/sh\n")
            df.write("\n")
            df.write("chroot /%s /%s\n" % (DOCKER_FS, SETUP_SCRIPT))   
            df.write("\n")   
            command = self.get_script_command("/bin/sh /%s > /%s/%s 2>&1\n" % (BG_SCRIPT, DOCKER_FS, BG_LOG))
            df.write(command)
            df.write("\n")
            command = self.get_script_command("/bin/sh /qemu_run.sh\n")
            df.write(command)
            df.write("\n")
            df.write("while true; do sleep 10000; done")
        df.close()
        org_mode = os.stat(debugRun)
        os.chmod(debugRun, org_mode.st_mode | stat.S_IXUSR)

        # modify run_setup script for standalone fuzzing
        setupRun = os.path.join(mindest, DOCKER_FS, "run_setup.sh")
        count = 0
        with open(setupRun, "w") as pf:
            pf.write("#!/bin/sh\n")
            pf.write("\n")
            # pf.write("/greenhouse/busybox cp -r /ghdev/* /dev\n")
            # pf.write("/greenhouse/busybox cp -r /ghproc/* /proc\n")
            pf.write("/greenhouse/busybox sh /setup_dev.sh /greenhouse/busybox /ghdev\n")
            pf.write("/greenhouse/busybox cp -r /ghtmp/* /tmp\n")  
            pf.write("/greenhouse/busybox cp -r /ghetc/* /etc\n")  
            pf.write("\n")
            for url in urls:
                if url != self.docker_ip:
                    devName = "dummy%d" % count
                    pf.write("/greenhouse/ip link add %s type dummy\n" % devName)
                    pf.write("/greenhouse/ip addr add %s/24 dev %s\n" % (url, devName))
                    pf.write("/greenhouse/ip link set %s up\n" % devName)
                    count += 1
        pf.close()

        # copy the docker-compose
        composeSrc = os.path.join(TMP_DIR, "fs", "docker-compose.yml")
        composeMinDest = os.path.join(mindest, "docker-compose.yml")
        composeDebugDest = os.path.join(debugdest, "docker-compose.yml")
        if os.path.exists(composeSrc):
            Files.copy_file(composeSrc, composeMinDest, silent=True)
            Files.copy_file(composeSrc, composeDebugDest, silent=True)

    def get_gateway(self, subnet, reserved_urls):
        baseurl = subnet.rsplit(".", maxsplit=1)[0]
        gateway = ""
        for count in range(1, 255):
            is_reserved = False
            gateway = "%s.%d" % (baseurl, count)
            for reserved in reserved_urls:
                if gateway in reserved:
                    is_reserved = True
                    break
            if is_reserved:
                continue
            break
        return gateway


    def setup_bridges(self, urls):
        count = 0
        bridges = dict()
        bridge_map = []
        existing_networks = []
        docker_networks = self.client.networks.list()

        for dnet in docker_networks:
            configs = dnet.attrs['IPAM']['Config']
            for conf in configs:
                subnet = conf['Subnet']
                subnet_addr = subnet.split("/")[0]
                if subnet_addr not in existing_networks:
                    existing_networks.append(subnet_addr)
        for url in urls:
            subnet_string = "%s/255.255.255.0" % url
            try:
                subnet = str(ipaddress.ip_interface(subnet_string).network)
                subnet_addr = subnet.split("/")[0]
                if subnet_addr in existing_networks:
                    print("    - skipping existing subnet", subnet_addr)
                    continue
                gateway = self.get_gateway(subnet, urls)
                ipam_pool = docker.types.IPAMPool(subnet=subnet, gateway=gateway)
                ipam_config = docker.types.IPAMConfig(pool_configs=[ipam_pool])
                bridge_name = "%sghbridge%d" % (self.hash, count)
                print("    - creating docker bridge %s on subnet %s for url %s via gateway %s" % (bridge_name, subnet, url, gateway))

                b = self.client.networks.create(bridge_name, driver="bridge", ipam=ipam_config)
                bridges[b] = url
                existing_networks.append(subnet_addr)
                bridge_map.append((url, subnet, gateway))
                count += 1
            except Exception as e:
                print(e)
                continue
        return bridges, bridge_map

    def make_docker_compose(self, fs_path, bridge_map, ports=[], mac=""):
        docker_compose_path = os.path.join(fs_path, "docker-compose.yml")
        print("Writing docker-compose file to ", docker_compose_path)
        with open(docker_compose_path, "w+") as dcFile:
            dcFile.write("version: \"2.2\"\n\n")
            dcFile.write("services:\n")
            dcFile.write("  gh_rehosted:\n")
            dcFile.write("    build: .\n")
            dcFile.write("    privileged: true\n")
            if len(mac) > 0:
                dcFile.write("    mac_address: \"%s\"\n" % mac)
            if len(bridge_map) > 0:
                dcFile.write("    networks:\n")
                count = 0
                for targeturl, subnet, gateway in bridge_map:
                    dcFile.write("      %sghbridge%d:\n" % (self.hash, count))
                    dcFile.write("        ipv4_address: %s\n" % targeturl)
                    count += 1
            
            # ports
            dcFile.write("    ports:\n")
            for port in ports:
                dcFile.write("      - %s:%s/tcp\n" % (port, port))
                dcFile.write("      - %s:%s/udp\n" % (port, port))

            if len(bridge_map) > 0:
                dcFile.write("\n")
                dcFile.write("networks:\n")
                count = 0
                for targeturl, subnet, gateway in bridge_map:
                    dcFile.write("   %sghbridge%d:\n" % (self.hash, count))
                    dcFile.write("     driver: bridge\n")
                    dcFile.write("     ipam:\n")
                    dcFile.write("       config:\n")
                    dcFile.write("       - subnet: %s\n" % subnet)
                    dcFile.write("         gateway: %s\n" % gateway)
                    count += 1
        dcFile.close()

    def get_minimal_command(self, base_cmd):
        command = "/%s" % (self.qemu_arch)
        if self.hackbind:
            command += " -hackbind"        
        if self.hackdevproc:
            command += " -hackproc"
        if self.hacksysinfo:
            command += " -hacksysinfo"
        command += " -execve \"/%s" % (self.qemu_arch)
        if self.hackbind:
            command += " -hackbind"  
        if self.hackdevproc:
            command += " -hackproc"
        if self.hacksysinfo:
            command += " -hacksysinfo"
        command += " \""
        if not self.baseline_mode:
            command += " -E LD_PRELOAD=\"libnvram-faker.so\"" 
        command += " %s\n" % (base_cmd)
        return command

    def get_script_command(self, base_cmd):
        command =  "chroot %s /%s" % (DOCKER_FS, self.qemu_arch)
        if self.hackbind:
            command += " -hackbind"  
        if self.hackdevproc:
            command += " -hackproc"
        if self.hacksysinfo:
            command += " -hacksysinfo"
        command += " -execve \"/%s" % (self.qemu_arch)
        if self.hackbind:
            command += " -hackbind"  
        if self.hackdevproc:
            command += " -hackproc"
        if self.hacksysinfo:
            command += " -hacksysinfo"
        command += " \""
        if not self.baseline_mode:
            command += " -E LD_PRELOAD=\"libnvram-faker.so\"" 
        command += " %s\n" % (base_cmd)
        return command


    def run(self, delay=200, timeout=HARD_TIMEOUT, extra_args="", nd_args="", bin_cwd="/",
            potential_urls=[], ports_file="", bg_cmds=[], bg_sleep=0, interface_cmds=[], 
            mac="",
            has_ipv6=False, greenhouse_mode=True, target_app_startup=None, need_infer_startup=False):

        if not os.path.exists(TMP_DIR):
            Files.mkdir(TMP_DIR)

        dockerfilePath = os.path.join(TMP_DIR, "Dockerfile")
        if os.path.exists(dockerfilePath):
            Files.rm_file(dockerfilePath)

        # get ports to probe
        ports = []
        with open(ports_file, "r+") as pFile:
            for p in pFile:
                p = p.strip()
                ports.append(p)
        pFile.close()

        # set up command to be run
        # qemu_command.extend(['-execve', "./"+self.qemu_static])

        logfilename = "/"+TRACE_LOG
        logpath = os.path.join("/",  DOCKER_FS, TRACE_LOG+"1")
        self.relative_bin_path =  self.bin_path.replace(self.fs_path, "")
        self.relative_init_path = self.init_path.replace(self.fs_path, "")
        self.extra_args = extra_args
        self.nd_args = nd_args
        self.bg_cmds = bg_cmds
        self.bg_sleep = bg_sleep
        self.interface_cmds = interface_cmds
        self.ipv6enable = has_ipv6
        self.last_bincwd = bin_cwd

        delay += bg_sleep

        qemu_command = ["chroot", DOCKER_FS, "/"+self.qemu_arch]
        qemu_command.extend(["-pconly"])
        if self.hackbind and not self.baseline_mode:
            qemu_command.extend(["-hackbind"])
        if self.hackdevproc and not self.baseline_mode:
            qemu_command.extend(["-hackproc"])
        if self.hacksysinfo and not self.baseline_mode:
            qemu_command.extend(["-hacksysinfo"])
        qemu_command.extend(["-D", "qemu_run_sh_"+TRACE_LOG+"1"])
        # TODO: greenhouse_mode待处理
        # if greenhouse_mode:
        qemu_command.extend(["-strace"])
        # else:
        #     qemu_command.extend(["-d", "exec,nochain,page"])
        
        # -execve部分参数
        qemu_command.extend(["-execve", "\"/"+self.qemu_arch+" -pconly"])
        if self.hackbind and not self.baseline_mode:
            qemu_command.extend(["-hackbind"])
        if self.hackdevproc and not self.baseline_mode:
            qemu_command.extend(["-hackproc"])
        if self.hacksysinfo and not self.baseline_mode:
            qemu_command.extend(["-hacksysinfo"])
        # TODO: greenhouse_mode待处理
        # if greenhouse_mode:
        qemu_command.extend(["-strace"])
        # else:
        #     qemu_command.extend(["-d", "exec,nochain,page"])
        qemu_command.extend(["-D "+logfilename+"\""])
        if not self.baseline_mode:
            qemu_command.extend(["-E", "PATH=\"/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/sbin:/usr/local/bin\"", "-E", "LD_PRELOAD=\"libnvram-faker.so\""])
        qemu_command.extend(["/bin/sh", "qemu_run.sh", ">", "/"+DOCKER_FS+"/"+GREENHOUSE_LOG, "2>&1"])
        # qemu_command.extend(extra_args.split())
        # qemu_command.extend([">", ERROR_LOG])
        # qemu_command.extend(["&"])
        docker_command = " ".join(qemu_command)

        clean_command = ["/"+self.qemu_arch]
        if self.hackbind and not self.baseline_mode:
            clean_command.extend(["-hackbind"])
        if self.hackdevproc and not self.baseline_mode:
            clean_command.extend(["-hackproc"])
        if self.hacksysinfo and not self.baseline_mode:
            clean_command.extend(["-hacksysinfo"])

        clean_command.extend(["-execve", "\"/"+self.qemu_arch])
        if self.hackdevproc and not self.baseline_mode:
            clean_command.extend(["-hackbind -hackproc"])
        if self.hacksysinfo and not self.baseline_mode:
            clean_command.extend(["-hacksysinfo"])
        clean_command.extend(["\""])
        if not self.baseline_mode:
            clean_command.extend(["-E", "PATH=\"/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/sbin:/usr/local/bin\"", "-E", "LD_PRELOAD=\"libnvram-faker.so\""])
        clean_command.extend(["/bin/sh", "qemu_run.sh"])
        docker_clean_command = " ".join(clean_command)

        cwd_command = "%s %s %s\n" % (self.relative_bin_path, nd_args, extra_args)
        command_script_path = os.path.join("", self.fs_path, "qemu_run.sh")
        wrapper_script_path = os.path.join(self.fs_path, "run.sh")
        clean_script_path = os.path.join(self.fs_path, "run_clean.sh")
        setup_script_path = os.path.join(self.fs_path, SETUP_SCRIPT)        
        bg_script_path = os.path.join(self.fs_path, BG_SCRIPT)        

        print("Building run_background.sh...")
        with open(bg_script_path, "w") as ws:   
            ws.write("#!/bin/sh\n")
            ws.write("\n")   
            ws.write("\n")   
            for base_cmd in self.bg_cmds:
                ws.write(base_cmd)
                ws.write("\n")
        
        print("Building setup script...")
        with open(setup_script_path, "w") as ws:   
            ws.write("#!/bin/sh\n")
            ws.write("\n")
            ws.write("/greenhouse/busybox sh /setup_dev.sh /greenhouse/busybox /ghdev\n")
            ws.write("\n")  
            for command in self.interface_cmds:
                ws.write(command)
                ws.write("\n")
            ws.write("\n")

        print("Building run.sh wrapper...")
        with open(wrapper_script_path, "w") as ws:
            ws.write("#!/bin/sh\n")
            ws.write("\n")
            ws.write("chroot /%s /%s\n" % (DOCKER_FS, SETUP_SCRIPT))   
            ws.write("\n")   
            command = self.get_script_command("/bin/sh /%s > /%s/%s 2>&1\n" % (BG_SCRIPT, DOCKER_FS, BG_LOG))
            ws.write(command)
            ws.write("\n")
            ws.write(docker_command)
            ws.write("\n")
            ws.write("echo \"%s\"$? >> /%s/%s" % (EXIT_CODE_TAG, DOCKER_FS, GREENHOUSE_LOG))
            ws.write("\n")
            ws.write("echo \"%s\" > %s" % (EXIT_CODE_TAG, DONE_TAG))
            ws.write("\n")
            ws.write("while true; do sleep 10000; done")
            ws.write("\n")
        ws.close()

        print("Building run_clean.sh wrapper...")
        with open(clean_script_path, "w") as ws:
            ws.write("#!/bin/sh\n")
            ws.write("\n")
            ws.write("/%s\n" % SETUP_SCRIPT)   
            ws.write("\n")  
            command = self.get_minimal_command("/bin/sh /%s > /%s 2>&1\n" % (BG_SCRIPT, BG_LOG))
            ws.write(command)
            ws.write("\n")
            ws.write(docker_clean_command)
            ws.write("\n")
            ws.write("while true; do /greenhouse/busybox sleep 100000; done")
        ws.close()
        print("done!")

        init_command = "%s %s\n" % ("sh", self.relative_init_path)
        
        with open(command_script_path, "w") as cs:
            cs.write("\n")
            cs.write("cd %s\n" % bin_cwd)
            cs.write("\n")
            cs.write(init_command)
            print("    - running init command")
            cs.write("\n")
        cs.close()

        org_mode = os.stat(command_script_path)
        os.chmod(command_script_path, org_mode.st_mode | stat.S_IXUSR)
        org_mode = os.stat(wrapper_script_path)
        os.chmod(wrapper_script_path, org_mode.st_mode | stat.S_IXUSR)
        org_mode = os.stat(clean_script_path)
        os.chmod(clean_script_path, org_mode.st_mode | stat.S_IXUSR)
        org_mode = os.stat(bg_script_path)
        os.chmod(bg_script_path, org_mode.st_mode | stat.S_IXUSR)
        org_mode = os.stat(setup_script_path)
        os.chmod(setup_script_path, org_mode.st_mode | stat.S_IXUSR)


        # cleanup old logs
        print("    - cleaning up old traces")
        for f in os.listdir(self.fs_path):
            fpath = os.path.join(self.fs_path, f)
            if os.path.isfile(fpath) and TRACE_LOG in f:
                print(f"    - removing old log {fpath}")
                Files.rm_file(fpath, silent=True)


        # check for named pipes
        npipes = []
        for root, dirs, files in os.walk(self.fs_path):
            for f in files:
                path = os.path.join(root, f)
                if os.path.exists(path) and stat.S_ISFIFO(os.stat(path).st_mode):
                    npipes.append(path)
                    print("    - Removing pipe", path)
                    Files.rm_file(path, silent=True)

        npipeLog = os.path.join(self.fs_path, "npipes.log")
        if os.path.exists(npipeLog):
            with open(npipeLog, 'r') as npFile:
                for pipe in npFile:
                    pipe = pipe.strip()
                    if pipe not in npipes:
                        npipes.append(pipe)
            npFile.close()

        with open(npipeLog, 'w') as npFile:
            for pipe in npipes:
                npFile.write(pipe+"\n")
        npFile.close()

        # copy fs to tmp directory:
        dest = os.path.join(TMP_DIR, "fs")
        Files.copy_directory(self.fs_path, dest)

        with open(dockerfilePath, "w") as dockerFile:
            dockerFile.write(SCRATCH_COMMANDS)
            dockerFile.write("\nCMD [\"/bin/sh\"]\n")
        dockerFile.close()

        print("Building docker image...")
        build_success = False
        self.client = docker.from_env()
        while not build_success:
            try:
                img, jsonlog = self.client.images.build(path=TMP_DIR, rm=True)
            except BuildError as e:
                print(e)
                print("    - rate limited, backing off and retrying in 60s")
                time.sleep(60)
                continue
            build_success = True


        # setup bridge devices
        self.client.networks.prune() # cleanup
        network_bridges, bridge_map = self.setup_bridges(potential_urls)
        self.make_docker_compose(dest, bridge_map, ports, mac)

        print("Creating new temp container...")
        tempCont = self.client.containers.create(img, detach=False, tty=True, mem_limit="64G",
                                                      ipc_mode="shareable", privileged=True)

        # disconnect from default bridge network
        docker0_bridge = self.client.networks.get("bridge")
        docker0_bridge.disconnect(tempCont)

        # add own networks
        for network, container_url in network_bridges.items():
            try:
                network.connect(tempCont, ipv4_address=container_url)
            except Exception as e:
                print(e)

        # strace_path = os.path.join(self.fs_path, TRACE_LOG)
        # if os.path.exists(strace_path):
        #     Files.rm_file(strace_path)
        # print("...created! Beginning Emulation.")

        docker_stream = None
        bg_stream = None
        r = None
        status_code = -1
        exitcode = None
        self.emulation_output = ""
        network_flags = ""
        timedout = False
        starttime = time.time()
        time_to_up = -1
        total_llm_time = 0.0
        banned_cmds = set()
        inferred_startup_cmd = target_app_startup
        ps_target_app_startup = []

        # run container
        try:
            print("Running command: ", docker_command)
            print("                > ", init_command)
            print("                > CWD: ", bin_cwd)
            print(">"*60)

            tempCont.start()
            
            import threading
            self.init_server = InitServer(container_fs_path="/"+DOCKER_FS, container_name=tempCont.name, fs_path=self.fs_path, model="qwen3-max")
            self.init_thread = threading.Thread(target=self.init_server.run, args=(0.1,), daemon=True)
            self.init_thread.start()
            
            self.container_monitor = ContainerPsMonitor(container_name=tempCont.name, bin_path=self.bin_path, container_fs_path="/"+DOCKER_FS, fs_path=self.fs_path)
            self.container_monitor_thread = threading.Thread(target=self.container_monitor.run, args=(1,), daemon=True)
            self.container_monitor_thread.start()
            
            print("-"*50)
            cmd = "ls %s" % DOCKER_FS
            out = tempCont.exec_run(cmd)[1]
            runstart = time.time()
            print("Directory structure: ", out)
            print("-"*50)

            cmd = "ls %s/dev" % DOCKER_FS
            out = tempCont.exec_run(cmd)[1]
            print("/dev structure: ", out)
            print("-"*50)

            exec_command = "/bin/sh ./%s/run.sh" % (DOCKER_FS)
            tempCont.exec_run(exec_command, stream=False, detach=True, tty=True)
            print("    - delay for %ds" % delay)
            time.sleep(delay)

            # 定义推理并启动目标应用的函数
            def infer_and_start_target_app():
                nonlocal inferred_startup_cmd
                
                # 如果已经有了目标应用启动命令（通过参数提供），不需要再推理
                if inferred_startup_cmd:
                    print(f"Target app startup command already exists: {inferred_startup_cmd}")
                else:
                    print("Starting to infer target app startup command...")
                # 使用StartupCommandServer进行推理
                startup_server = StartupCommandServer(self.fs_path, self.bin_path, self.qemu_arch, tempCont.name, self.api_key, self.model)
                inferred_startup_cmd = startup_server.get_target_app_startup(ps_target_app_startup)
                
                # 统计 StartupCommandServer 的 token 消耗
                self.total_input_tokens += startup_server.get_total_input_tokens()
                self.total_output_tokens += startup_server.get_total_output_tokens()
                print(f"StartupCommandServer Token Usage - Input: {startup_server.get_total_input_tokens()}, Output: {startup_server.get_total_output_tokens()}")
                    
                if not inferred_startup_cmd:
                    print("Inference did not get a valid target app startup command, skipping...")
                    return
            
                    print(f"Inferred target app startup command: {inferred_startup_cmd}")
                # Reference command_script_path method, build script and execute
                print("Executing command in container...")
                
                # 创建qemu_run_target.sh脚本文件
                target_script_path = os.path.join(self.fs_path, "qemu_run_target.sh")
                print(f"    - creating target script: {target_script_path}")
                
                with open(target_script_path, "w") as ts:
                    ts.write("\n")
                    ts.write("cd %s\n" % self.last_bincwd)
                    ts.write(inferred_startup_cmd)
                    ts.write("\n")
                    print(f"    - writing inferred startup command to script")
                
                # 设置脚本执行权限
                os.chmod(target_script_path, 0o755)
                
                # 在容器中执行目标应用启动脚本
                target_exec_command = "/bin/sh ./%s/qemu_run_target.sh" % (DOCKER_FS)
                print(f"    - executing target command: {target_exec_command}")
                tempCont.exec_run(target_exec_command, stream=False, detach=True, tty=True)
                print("    - target app startup command executed")

            # print("-"*50)
            # cmd = "ps -a"
            # print("Check: ps -a")
            # out = tempCont.exec_run(cmd)[1]
            # print("Processes: ", out)
            # print("-"*50)

            # check for changes in tracelog to determine if we are stuck in a loop
            lineCount = 0
            prevCount = -1
            loopCount = 0
            stableCount = 0
            noTargetCount = 0
            devnulllines = ""

            INTERVAL_SIZE = 10 #seconds
            # MAX_LOOPS = HARD_TIMEOUT / INTERVAL_SIZE
            LOOP_THRESHOLD = 10
            STABLE_THRESHOLD = 3
            NO_TARGET_THRESHOLD = 20 # 无目标应用日志最大检测次数
            # MAX_TAIL = 10000000
            TAIL_SIZE = 10000000
            MAX_TRACES = 200
            print("Checking for program end")

            backtrace = []
            traceList = []
            parttrace = []
            running_tally = dict() # running tally tracks "interrupted" loops
            while True:
                current_llm_time = self.init_server.get_time()
                print(f"Current LLM_time: {current_llm_time}, Total LLM_time: {total_llm_time}")
                total_llm_time += current_llm_time
                time.sleep(INTERVAL_SIZE + current_llm_time)
                
                import glob
                llm_lock_files = glob.glob("/tmp/llm_request_*")
                if llm_lock_files:
                    print(f"Found {len(llm_lock_files)} LLM request lock file(s), waiting for LLM to complete...")
                    noTargetCount = 0
                    continue

                # 查找所有以目标应用名开头的日志文件
                lineCount = 0
                app_name = os.path.basename(self.bin_path)
                base_logname = f"{app_name}_trace.log"
                
                list_cmd = f"ls /{DOCKER_FS}/{base_logname}*"
                out = tempCont.exec_run(["/bin/sh", "-c", list_cmd])[1].decode().strip()
                
                if out and "No such file" not in out:
                    # 获取所有匹配的日志文件列表
                    target_log_files = sorted(out.split())
                else:
                    target_log_files = []
                    noTargetCount += 1
                    if noTargetCount > NO_TARGET_THRESHOLD:
                        if need_infer_startup:
                            # 在检测到要退出时，推理并启动目标应用
                            infer_and_start_target_app()
                            need_infer_startup = False
                            continue
                        time_to_up = (time.time() - runstart) - total_llm_time
                        print(f"No target log files found for {NO_TARGET_THRESHOLD} consecutive checks! Stopping...")
                        break
                    continue
                
                # perform checker operations
                probe_success = self.checker.probe(potential_urls, ports) #url, cont

                if probe_success:
                    print("Response received! Stopping...")
                    time_to_up = (time.time() - runstart) - total_llm_time
                    break
                
                target_log_count = 0
                for tracelogpath in target_log_files:
                    # 统计每个日志文件的行数
                    traceCommand = f"wc -l {tracelogpath}"
                    print(f"   - checking {tracelogpath}")
                    out = tempCont.exec_run(traceCommand)[1]
                    try:
                        wc_out = str(out)[2:].split()[0]
                        lineCount += int(wc_out)
                    except Exception as e:
                        print(f"ERROR - Unable to convert wc for {wc_out}")
                        print(str(e))
                    
                    target_log_count += 1
                    if target_log_count > MAX_TRACES:
                        break

                print("   # ", lineCount, prevCount)
                if lineCount == prevCount:
                    if stableCount > STABLE_THRESHOLD:
                        print("Run complete! Stopping...")
                        time_to_up = (time.time() - runstart) - total_llm_time
                        break
                    else:
                        stableCount += 1
                        continue
                else:
                    stableCount = 0

                prevCount = lineCount

                def filter_exec(line):
                    if line.startswith(b"Trace "):
                        return False
                    if line.startswith(b"---"):
                        return False
                    if line.startswith(b"start"):
                        return False
                    if line.startswith(b" "):
                        return False
                    if b"-" in line.split(b" ", 1)[0]:
                        return False
                    if b"rt_sigaction" in line:
                        return False
                    if b"close(" in line: # these are bad for looping
                        return False
                    if b" " not in line:
                        return False
                    return True

                def filter_trace(line):
                    if b"[00000000/00" in line:
                        return True
                    return False

                # TODO:检测目标应用的执行轨迹中是否出现无限循环，但判断逻辑是将前半段==后半段，有改进空间
                print(f"Running to get log content, using tail if needed...")
                # 使用第一个字典序的日志文件作为判断日志
                if target_log_files:
                    logpath = target_log_files[0]
                    wc_cmd = f"wc -l {logpath}"
                    wc_output = tempCont.exec_run(wc_cmd)[1].strip()
                    # Parse the output - the first number is the line count
                    total_lines = int(wc_output.split()[0] or 0) if wc_output else 0
                    if total_lines <= TAIL_SIZE:
                        traceCommand = f"cat {logpath}"
                    else:
                        traceCommand = f"tail -n {TAIL_SIZE} {logpath}"
                    out = tempCont.exec_run(traceCommand)[1]
                    traceList = out.splitlines()
                else:
                    traceList = []
                    
                # TODO: greenhouse_mode模式待处理，Trace 是二进制指令执行日志
                # startIndex = 0
                # if not greenhouse_mode:
                #     for line in traceList:
                #         if line.startswith(b"Trace "):
                #             break
                #         startIndex += 1
                #     traceList = traceList[startIndex:]

                print("Filtering...")
                # 先过滤最后发生的系统调用
                traceList = traceList[::-1]
                filtered_exec = list(filter(filter_exec, traceList))
                if filtered_exec:
                    traceList = filtered_exec
                    traceList = [line.split(b" ", 1)[1].split(b"(", 1)[0] for line in traceList]
                # else:
                #     # use addresses instead
                #     traceList = list(filter(filter_trace, traceList))
                #     traceList = [line.split(b"/", 1)[1] for line in traceList]

                count = 0
                looping = False
                # trace_started = False
                print("-"*100)
                # if len(traceList) > 100:
                #     print(traceList[:100])
                # else:
                #     print(traceList)
                
                # 检测是否存在循环
                for line in traceList:
                    backtrace.append(line)
                    partlen = len(backtrace) // 2
                    parttrace = backtrace[:partlen]
                    count += 1
                    buffertrace = parttrace + parttrace
                    repeats = 0
                    if buffertrace == backtrace:
                        traceString = (b"".join(traceList))
                        bufString = (b"".join(buffertrace))
                        partString = (b"".join(parttrace))
                        
                        while True:
                            if traceString.startswith(bufString):
                                repeats += 1
                                bufString += partString
                                # print(bufString)
                                # print("-"*100)
                                print("Repeats", repeats)
                                if repeats > LOOP_THRESHOLD:
                                    looping = True
                                    break
                            else:
                                break

                            if repeats > 0:
                                if partString not in running_tally:
                                    running_tally[partString] = 0
                                running_tally[partString] += repeats
                                print("running tally for ", partString)
                                print("repeats: ", running_tally[partString])
                                if running_tally[partString] > LOOP_THRESHOLD:
                                    looping = True
                                    break
                        break
                if len(backtrace) > 100:
                    print(backtrace[:100])

                if looping:
                    print("Looping detected! Excessive repetition in execution trace. Stopping...")
                    print(parttrace)
                    timedout = True
                    time_to_up = (time.time() - runstart) - total_llm_time
                    break
                time_passed = (time.time() - starttime) / 60 # mins
                if (time_passed) > timeout: # mins
                    print("HARD_TIMEOUT exceeded, force stop!")
                    timedout = True
                    time_to_up = (time.time() - runstart) - total_llm_time
                    break

                traceList.clear()
                backtrace.clear()
                parttrace.clear()
                loopCount += 1
                print("loops:", loopCount)
                print("time passed: ", time_passed, "mins")


            print("LOOP COMPLETE")
            devnulllines = []
            cmd = "cat /%s/dev/null" % DOCKER_FS
            out = tempCont.exec_run(cmd)[1]
            # print(out)
            if len(out) > 0:
                out = out.decode("utf-8", errors='ignore')
                devnulllines = out.splitlines()

            cmd = "cat /%s/ghdev/null" % DOCKER_FS
            out = tempCont.exec_run(cmd)[1]
            print(out)
            if len(out) > 0:
                out = out.decode("utf-8", errors='ignore')
                devnulllines += "\n"
                devnulllines += out.splitlines()

            # get nvram log file
            nvramDockerPath = os.path.join(DOCKER_FS, MISSING_NVRAM_FILE)
            nvramLogPath = os.path.join(self.fs_path, MISSING_NVRAM_FILE)
            cmd = "cat %s" % nvramDockerPath
            out = tempCont.exec_run(cmd)[1]
            cache = set()
            if b"No such file" not in out:
                print("    - retrieving missing nvram logs", nvramDockerPath)
                with open(nvramLogPath, "wb") as nvramFile:
                    for line in out.splitlines():
                        line = line.strip()
                        if line not in cache:
                            nvramFile.write(line+b"\n")
                            cache.add(line)
                nvramFile.close()

            # get std stream
            cmd = "cat /%s/%s" % (DOCKER_FS, GREENHOUSE_LOG)
            docker_stream = tempCont.exec_run(cmd)[1]      

            cmd = "cat /%s/%s" % (DOCKER_FS, BG_LOG)
            bg_stream = tempCont.exec_run(cmd)[1]      

            # get strace results
            # 按照数值顺序排序 trace 文件
            cmd = "ls /%s/" % DOCKER_FS
            ls_out = tempCont.exec_run(cmd)[1]
            
            if ls_out and b"No such file" not in ls_out:
                docker_fs_files = ls_out.splitlines()
                # 筛选出包含 trace.log 的文件
                trace_files = []
                for file in docker_fs_files:
                    if b"trace.log" in file:
                        trace_files.append(file)
                
                # 按照数值顺序排序 trace 文件
                def sort_key(file):
                    file_str = file.decode('utf-8')
                    # 提取前缀和数字部分
                    if "_trace.log" in file_str:
                        prefix_part = file_str.split("_trace.log")[0]
                        # 提取数字部分，如果有的话
                        number_part = file_str.split("_trace.log")[1] or "0"
                        # 尝试将数字部分转换为整数
                        try:
                            number = int(number_part)
                        except ValueError:
                            number = 0
                        return (prefix_part, number)
                    return (file_str, 0)
                
                # 按数值顺序排序
                sorted_trace_files = sorted(trace_files, key=sort_key)
                
                # 记录相同前缀的出现次数
                prefix_count = {}
                # 处理所有 trace 文件
                for file in sorted_trace_files:
                    file_str = file.decode('utf-8')
                    # 提取 _trace.log 前的部分作为前缀
                    prefix = file_str.split("_trace.log")[0]
                    prefix_count[prefix] = prefix_count.get(prefix, 0) + 1
                    # 如果同一前缀已出现 MAX_TRACES 次，则跳过
                    if prefix_count[prefix] > MAX_TRACES:
                        continue
                    print(f"    - retrieving trace {file}")
                    docker_path = os.path.join(DOCKER_FS, file_str)
                    path = f"{self.fs_path}/{file_str}.tar"
                    with open(path, "wb") as straceFile:
                        archive = tempCont.get_archive(docker_path)
                        for line in archive[0]:
                            straceFile.write(line)

            cmd = "ls /%s" % DOCKER_FS
            traceFiles = tempCont.exec_run(cmd)[1].splitlines()
            print("Cleaning up...")
            # make sure to kill everything
            pids = []
            out = tempCont.exec_run("ps -efww")[1]
            app_name = os.path.basename(self.bin_path)
            for process in out.splitlines():
                print(f"    - {process}")
                if b"ps -efww" in process:
                    continue
                # 过滤出目标应用的启动进程
                if app_name.encode() in process:
                    ps_target_app_startup.append(process)
                fields = process.split()
                pid = fields[1]
                if pid.isdigit():
                    pid = int(pid)
                    if pid > 1:
                        pids.append(pid)

            for pid in pids:
                print("    - killing %d" % pid)
                tempCont.exec_run("kill -15 %d &" % pid, detach=True)

            # try graceful termination first the -9 forcekill
            time.sleep(5)
            print("Trying Forcekill")
            for pid in pids:
                print("    - force killing %d" % pid)
                tempCont.exec_run("kill -9 %d &" % pid, detach=True)

            # remove old trace file
            for line in traceFiles:
                if b"trace.log" in line:
                    tempCont.exec_run("rm /%s &" % line, detach=True)
            time.sleep(2)

        except Exception as e:
            print("!! UNCAUGHT EXCEPTION !!")
            print(e)
            print(traceback.format_exc())
        finally:
            print("Stopping Container...")
            
            if hasattr(self, 'init_server') and self.init_server:
                print("Stopping Init Server...")
                self.init_server.stop()
                self.total_input_tokens += self.init_server.get_total_input_tokens()
                self.total_output_tokens += self.init_server.get_total_output_tokens()
                # 获取已过滤的脚本集合
                filtered_scripts = self.init_server.get_filtered_scripts()
                print(f"Init Server Token Usage - Input: {self.init_server.get_total_input_tokens()}, Output: {self.init_server.get_total_output_tokens()}")
            if hasattr(self, 'init_thread') and self.init_thread:
                print("Joining Init Thread...")
                self.init_thread.join(timeout=5)
            
            if hasattr(self, 'container_monitor') and self.container_monitor:
                print("Stopping ContainerPsMonitor...")
                self.container_monitor.stop()
                # 获取被禁止的命令列表
                banned_cmds = self.container_monitor.get_banned_cmds()
            if hasattr(self, 'container_monitor_thread') and self.container_monitor_thread:
                print("Joining ContainerPsMonitor Thread...")
                self.container_monitor_thread.join(timeout=5)

            tempCont.stop()

        print("Emulation Terminated")
        totaltime = time.time() - starttime
        print("    - emulation time = ", (totaltime / 60), "mins")
        print(f"    - Total Token Usage - Input: {self.total_input_tokens}, Output: {self.total_output_tokens}")
        print(f"    - Total Tokens: {self.total_input_tokens + self.total_output_tokens}")

        if bg_stream:
            print("----- bg output -----")
            self.changelog.append("[QemuRunner] ----- bg output -----")
            bgoutput = bg_stream.decode("utf-8", errors='ignore')
            bglines = bgoutput.splitlines()
            for bg_string in bglines:
                print(bg_string)
                self.emulation_output += bg_string+"\n"

        if docker_stream:
            print("----- emulation output -----")
            self.changelog.append("[QemuRunner] ----- emulation output -----")
            exitcode_end = ""
            dsoutput = docker_stream.decode("utf-8", errors='ignore')
            dslines = dsoutput.splitlines()
            for ds_string in dslines:
                print(ds_string)
                if EXIT_CODE_TAG in ds_string and "-arg" not in ds_string:
                    exitcode_end = ds_string
                    ds_string = ds_string.strip()
                    try:
                        exitcode_string = ds_string.split(EXIT_CODE_TAG)[1].split()[0]
                        exitcode = int(exitcode_string)
                    except Exception as e:
                        print("-"*100)
                        print("Error converting", ds_string)
                        print(e)
                        print("-"*100)
                    ds_string = ""
                self.emulation_output += ds_string+"\n"
            for line in devnulllines:
                print(line)
                self.emulation_output += line+"\n"
            self.emulation_output += exitcode_end
            print("-----------------------------")
            log = self.emulation_output
            if len(log) > 500:
                self.emulation_output[-500:]
            self.changelog.append(self.emulation_output[-500:])
            self.changelog.append("[QemuRunner] ----- emulation end -----")
        else:
            print("-----------------------------")
            print("[QemuRunner] - No data returned!")
            print("-----------------------------")
        self.changelog.append("[QemuRunner] Network Flags")
        for line in network_flags:
            self.changelog.append("[QemuRunner] %s" % network_flags)

        # cleanup
        for network in network_bridges.keys():
            try:
                network.disconnect(tempCont)
                network.remove()
            except Exception as e:
                print(e)


        time.sleep(10)
        tempCont.remove(force=True)
        time.sleep(5)
        print("    - tempCont removed")
        self.client.images.remove(img.id, force=True)
        print("    - client removed")


        # generate qemu_command for docker

        self.client.close()
        print("    - client closed")

        print("<"*60)
        print("DONE!")
        
        return self.emulation_output, exitcode, timedout, time_to_up, banned_cmds, inferred_startup_cmd, filtered_scripts
    