from . import *

import re, os
import json

import tarfile
import subprocess
import ipaddress

NVRAM_LOG_PATH = "MISSING_NVRAMS"

#stores information about a single trace run of a binary
#contains run information and path information
class Trace:
    def __init__(self, trace_path):
        self.trace_path = trace_path
        self.base_addr = 0
        self.start_code = 0
        self.end_code = 0
        self.parent_pid = -1
        self.load_trace(trace_path)

    def load_trace(self, trace_path):
        with open(self.trace_path, "r") as jfile:
            trace = json.loads(jfile.read())
        jfile.close()

        self.base_addr = trace["base_addr"]
        self.start_code = trace["base_addr"]
        self.end_code = trace["end_addr"]
        self.traces = trace["traces"]
        self.parent_pid = str(trace["parent_pid"])

    def read_trace(self, path):
        addr_trace = []
        with open(path, "r") as traceFile:
            for line in traceFile:
                line = line.strip()
                addr = int(line)
                addr_trace.append(addr)
        traceFile.close()
        return addr_trace

    def is_code(self, addr):
        return addr >= self.start_code and addr <= self.end_code

    def has_addr_sequence(self, addr_sequence, pid, use_baddr=False):
        target_sequence = addr_sequence
        tracePath = self.traces[pid]
        with open(tracePath, "r") as traceFile:
            for line in traceFile:
                addr = int(line.strip())
                for target_addr in addr_sequence:
                    if target_addr == addr:
                        if len(addr_sequence) <= 1:
                            return True
                        target_sequence = addr_sequence[1:]
                addr_sequence = target_sequence
        traceFile.close()

        return False

    def get_last_n_code_addrs(self, n, pid, use_baddr=False):
        last_addrs = []
        count = 0
        tracePath = self.traces[pid]
        reversedTracePath = tracePath+".reversed"
        with open(reversedTracePath, "w+") as reversedFile:
            subprocess.call(["tac", tracePath],  stdout=reversedFile)
        reversedFile.close()

        with open(reversedTracePath, "r") as reversedFile:
            for line in reversedFile:
                addr = int(line.strip())
                if self.is_code(addr):
                    last_addrs.append(addr)
                    count += 1
                    if count >= n:
                        break
        reversedFile.close()

        if(use_baddr):
            last_addrs = [addr - self.base_addr for addr in last_addrs]

        last_addrs = last_addrs[::-1] #reverse
        return last_addrs

    def get_last_code_addr(self, pid, use_baddr=False):
        last_addr = -1
        tracePath = self.traces[pid]
        reversedTracePath = tracePath+".reversed"
        with open(reversedTracePath, "w+") as reversedFile:
            subprocess.call(["tac", tracePath],  stdout=reversedFile)
        reversedFile.close()

        with open(reversedTracePath, "r") as reversedFile:
            for line in reversedFile:
                addr = int(line.strip())
                if self.is_code(addr):
                    last_addr = addr
                    break
        reversedFile.close()

        if(use_baddr):
            last_addr = last_addr - self.base_addr
        return last_addr

    def get_caller(self, pid, bintrunk, func_addr, use_baddr=False):
        last_addr = -1
        func_latch = False

        tracePath = self.traces[pid]
        reversedTracePath = tracePath+".reversed"
        with open(reversedTracePath, "w+") as reversedFile:
            subprocess.call(["tac", tracePath],  stdout=reversedFile)
        reversedFile.close()

        with open(reversedTracePath, "r") as reversedFile:
            for line in reversedFile:
                addr = int(line.strip())
                if self.is_code(addr):
                    if addr == func_addr:
                        func_latch = True
                    elif func_latch:
                        last_addr = addr
                        break
        reversedFile.close()

        if(use_baddr):
            last_addr = last_addr - self.base_addr

        return last_addr

# sorts into "dir", "nvram" and "libs"
class TraceParser():
    def __init__(self, fs_path):
        self.fs_path = fs_path
        # "open(\"(?P<file>)\",.*) = (?P<retval>) .*"
        self.open_re =  re.compile(b"(.*)open(at){0,1}\((.*)\"(?P<file>.*)\"(.*) = (?P<retval>.*)")
        self.access_re =  re.compile(b"(.*)access(at){0,1}[0-9]*\(\"(?P<file>.*)\"(.*) = (?P<retval>.*)")
        self.stat_re =  re.compile(b"(.*)stat[0-9]*\(\"(?P<file>.*)\"(.*) = (?P<retval>.*)")
        self.chdir_re =  re.compile(b"(.*)chdir\(\"(?P<file>.*)\"(.*) = (?P<retval>.*)")
        self.error_re =  re.compile(r"(?P<nvram>.*)=Unknown")

        self.trace_re = re.compile(br'Trace (.*) PID (?P<pid>.*):(.*) \[(?P<something1>.*)\/(?P<addr>.*)\/(?P<flags>.*)\/(?P<cflags>.*)\].*')
        self.start_code_re = re.compile(br'.*_code (.*) 0x(?P<addr>.*)')

    def parse(self, emulation_dump, strace_path, curr_directory="/", forkmap=dict(), MAX_SET=100):
        opened = set()
        folders = set()
        failed = set()
        is_daemonized = False
        segfaulted = False
        forked = False
        pid = -1
        
        targets = set()
        nvrams =  set()
        ip_addrs =  set()
        ipv6_addrs = set()
        target_ports =  set()
        interfaces =  set()
        # target = ports = []
        for line in emulation_dump.split("\n"):
            if line.startswith("[qemu]"):
                continue
            if "=Unknown" in line:
                if "22;31m" in line:
                    line = line.split("22;31m")[1]
                groups = self.error_re.match(line)
                if groups != None:
                    config = groups.group('nvram')
                    config = config.strip()
                    if config not in nvrams:
                        nvrams.add(config)
                else:
                    print("Error processing line ", line)
            if "[GreenHouseQEMU]" in line:
                if "IP:" in line:
                    fields = line.split(":")
                    ip = fields[1].strip()
                    if ip not in ip_addrs and self.check_ip(ip):
                        ip_addrs.add(ip)
                if "IPV6:" in line:
                    fields = line.split(":")
                    ip = fields[1].strip()
                    if ip not in ipv6_addrs:
                        ipv6_addrs.add(ip)
                if "PORT:" in line:
                    fields = line.split(":")
                    port = fields[1].strip()
                    if port not in target_ports:
                        target_ports.add(port)
                if "BIND_DEVICE:" in line:
                    fields = line.split(":")
                    device = fields[1].strip()
                    if device not in interfaces:
                        interfaces.add(device)
                if "SIGSEGV" in line:
                    segfaulted = True
            # 处理文件找不到的情况，如 "/usr/etc/rcS: line 6: /usr/sbin/rc_app/rc_init: not found"
            if ": not found" in line:
                # 提取文件路径
                parts = line.split(":")
                if len(parts) >= 3:
                    # 格式: "file: line X: path: not found"
                    file_path = parts[2].strip()
                    if file_path and file_path not in targets:
                        targets.add(file_path)
                        # print(f"    - File not found: {file_path}")

        print("TraceParser parsing", strace_path)
        if (".tar" not in strace_path):
            print("    - ERROR trace dump should be a tar archive!")
            return targets, folders, nvrams, ip_addrs, ipv6_addrs, target_ports, interfaces, failed, segfaulted, is_daemonized
        # time.sleep(1)        
        # 直接读取文件内容获取行数
        total_lines = 0
        with tarfile.open(strace_path) as tFile:
            # 获取第一个成员的文件流（这是一个类文件对象）
            members = tFile.getmembers()
            # 确保文件存在，防止索引越界
            if members:
                sFile = tFile.extractfile(members[0])
                
                if sFile:
                    # 直接读取并计算行数，避免使用subprocess.run
                    line_count = 0
                    for line in sFile:
                        line_count += 1
                    total_lines = line_count
                    print(f"    - Log file has {total_lines} lines")
        
        # 检查前3000行是否有qemu的二进制指令
        is_qemu_binary = False
        # 第二次遍历：处理文件
        with tarfile.open(strace_path) as tFile:
            members = tFile.getmembers()
            sFile = tFile.extractfile(members[0])
            
            line_count = 0
            skip_mode = False
            skip_until = 0
            
            if total_lines > 6000:
                skip_until = total_lines - 3000
            
            for line in sFile:
                line_count += 1
                
                # 若没有qemu的二进制指令，跳过中间日志，直接处理最后3000行
                if line_count > 3000 and not is_qemu_binary and line_count < skip_until:
                    continue
                
                # Skip lines to speed up processing
                if line.startswith(b"Trace "):
                    is_qemu_binary = True
                    continue
                if line.startswith(b"---"):
                    continue
                if line.startswith(b"start"):
                    is_qemu_binary = True
                    continue
                if line.startswith(b" "):
                    continue
                if line.startswith(b"0x"):
                    is_qemu_binary = True
                    continue
                if line.startswith(b"IN"):
                    is_qemu_binary = True
                    continue
                
                if pid == -1:
                    pid = line.split()[0].strip().decode("utf-8", errors="ignore")
                    if pid in forkmap.keys():
                        curr_directory = forkmap[pid]
                if b"/gh_nvram" in line: # skip reads from gh_folder
                    continue
                if len(failed) < MAX_SET:
                    # edge case - fstat uses fd not path, so must be skipped. accept all other variants
                    addfile = False
                    try:
                        if b"open(" in line or b"openat(" in line:
                            groups = self.open_re.match(line)
                            addfile = True
                        elif b"stat" in line and b"fstat(" not in line:
                            groups = self.stat_re.match(line)
                            addfile = True
                        elif b"access(" in line:
                            groups = self.access_re.match(line)
                            addfile = True
                        elif b"chdir(" in line:
                            groups = self.chdir_re.match(line)
                            if groups:
                                filename = groups.group('file').decode("utf-8")
                                retval = groups.group('retval')
                                retval = int(retval.split()[0].decode("utf-8"))
                                # print(filename, retval)
                                if retval < 0:
                                    folders.add(filename)
                                else:
                                    if filename in folders:
                                        folders.remove(filename)
                                    opened.add(filename)
                                    print("    - chdir %s --> %s" % (curr_directory, filename))
                                    if filename.startswith("/"):
                                        curr_directory = filename
                                    else:
                                        curr_directory = os.path.join(curr_directory, filename)
                        elif b"fork(" in line:
                            forked = True
                            forkedpid = line.split(b"=")[1].strip()
                            if forkedpid != 0:
                                forkmap[forkedpid] = curr_directory
                        elif b"exit(" in line:
                            if forked:
                                is_daemonized = True
                            # else:
                            #     print("    - !! ERROR !! Regex chdir_re does not match", line)
                        
                        # add file
                        if addfile and groups and len(groups.group('file')) > 0 and len(groups.group('retval')) > 0:
                                filename = groups.group('file').decode("utf-8")
                                retval = groups.group('retval')
                                if b"0x" in retval:
                                    retval = int(retval.split()[0].decode("utf-8"), 16)
                                else:
                                    retval = int(retval.split()[0].decode("utf-8"))
                                # print(filename, retval)
                                basefilename = os.path.basename(filename)
                                if len(filename) <= 0 or filename.strip() == "/" or \
                                   len(basefilename) <= 0 or basefilename.startswith("."): #skip likely malformed filenames
                                    continue
                                if not filename.startswith("/") and curr_directory.strip() != "/":
                                    filename = os.path.join(curr_directory, filename)
                                
                                # 跳过带有数字名称的 proc 文件（如 proc/12421）
                                is_proc_numeric = False
                                if "proc/" in filename:
                                    proc_parts = filename.split("proc/")
                                    if len(proc_parts) > 1:
                                        proc_path = proc_parts[1]
                                        first_part = proc_path.split("/")[0]
                                        if first_part.isdigit():
                                            is_proc_numeric = True
                                
                                if is_proc_numeric:
                                    continue
                                
                                if retval < 0:
                                    if b"O_DIRECTORY" in line:
                                        folders.add(filename)
                                        # if not filename.startswith("/"):
                                        #     folders.add(os.path.join(curr_directory, filename))
                                    else:
                                        failed.add(filename)
                                        # if not filename.startswith("/"):
                                        #     failed.add(os.path.join(curr_directory, filename))
                                else:
                                    if filename in failed:
                                        failed.remove(filename)
                                        # if not filename.startswith("/"):
                                        #     failed.remove(os.path.join(curr_directory, filename))
                                    opened.add(filename)
                                    # if not filename.startswith("/"):
                                    #     opened.add(os.path.join(curr_directory, filename))
                    except ValueError as e:
                        print("!"*100)
                        print(e)
                        print(line)
                        print("!"*100)
                        continue
                    except IndexError as e:
                        print("!"*100)
                        print(e)
                        print(line)
                        print("!"*100)
                        continue
            
            
            # # 第一遍：计算总行数并检查前1000行是否含有qemu二进制指令转储
            # total_lines = 0
            # has_binary_dump = False
            # check_count = 0
            
            # # 先逐行读取计算总行数并检查前1000行
            # for line in sFile:
            #     total_lines += 1
            #     if check_count < 1000:
            #         line_str = line.decode('utf-8', errors='ignore')
            #         if line_str.strip().startswith('Trace'):
            #             has_binary_dump = True
            #         check_count += 1
            
            # print(f"    - Log file has {total_lines} lines")
            
            # # 第二遍：根据需要处理文件
            # sFile.seek(0)  # 重置文件指针到开头
            
            # # 确定要处理的行范围
            # if total_lines > 6000 and has_binary_dump:
            #     print("    - Log file exceeds 6000 lines and contains binary dump, processing first 3000 and last 3000 lines")
                
            #     # 处理前3000行
            #     current_line = 0
            #     for line in sFile:
            #         current_line += 1
            #         if current_line > 3000:
            #             break
                    
            #         if pid == -1:
            #             pid = line.split()[0].strip().decode("utf-8", errors="ignore")
            #             if pid in forkmap.keys():
            #                 curr_directory = forkmap[pid]
            #         if b"/gh_nvram" in line: # skip reads from gh_folder
            #             continue
            #         if len(failed) < MAX_SET:
            #             # edge case - fstat uses fd not path, so must be skipped. accept all other variants
            #             addfile = False
            #             try:
            #                 if b"open(" in line or b"openat(" in line:
            #                     groups = self.open_re.match(line)
            #                     addfile = True
            #                 elif b"stat" in line and b"fstat(" not in line:
            #                     groups = self.stat_re.match(line)
            #                     addfile = True
            #                 elif b"access(" in line:
            #                     groups = self.access_re.match(line)
            #                     addfile = True
            #                 elif b"chdir(" in line:
            #                     groups = self.chdir_re.match(line)
            #                     if groups:
            #                         filename = groups.group('file').decode("utf-8")
            #                         retval = groups.group('retval')
            #                         retval = int(retval.split()[0].decode("utf-8"))
            #                         # print(filename, retval)
            #                         if retval < 0:
            #                             folders.add(filename)
            #                         else:
            #                             if filename in folders:
            #                                 folders.remove(filename)
            #                             opened.add(filename)
            #                             print("    - chdir %s --> %s" % (curr_directory, filename))
            #                             if filename.startswith("/"):
            #                                 curr_directory = filename
            #                             else:
            #                                 curr_directory = os.path.join(curr_directory, filename)
            #                 elif b"fork(" in line:
            #                     forked = True
            #                     forkedpid = line.split(b"=")[1].strip()
            #                     if forkedpid != 0:
            #                         forkmap[forkedpid] = curr_directory
            #                 elif b"exit(" in line:
            #                     if forked:
            #                         is_daemonized = True
            #                     # else:
            #                     #     print("    - !! ERROR !! Regex chdir_re does not match", line)
                            
            #                 # add file
            #                 if addfile and groups and len(groups.group('file')) > 0 and len(groups.group('retval')) > 0:
            #                         filename = groups.group('file').decode("utf-8")
            #                         retval = groups.group('retval')
            #                         if b"0x" in retval:
            #                             retval = int(retval.split()[0].decode("utf-8"), 16)
            #                         else:
            #                             retval = int(retval.split()[0].decode("utf-8"))
            #                         # print(filename, retval)
            #                         basefilename = os.path.basename(filename)
            #                         if len(filename) <= 0 or filename.strip() == "/" or \
            #                            len(basefilename) <= 0 or basefilename.startswith("."): #skip likely malformed filenames
            #                             continue
            #                         if not filename.startswith("/") and curr_directory.strip() != "/":
            #                             filename = os.path.join(curr_directory, filename)
                                    
            #                         # 跳过带有数字名称的 proc 文件（如 proc/12421）
            #                         is_proc_numeric = False
            #                         if "proc/" in filename:
            #                             proc_parts = filename.split("/proc/")
            #                             if len(proc_parts) > 1:
            #                                 proc_path = proc_parts[1]
            #                                 first_part = proc_path.split("/")[0]
            #                                 if first_part.isdigit():
            #                                     is_proc_numeric = True
                                    
            #                         if retval < 0:
            #                             if b"O_DIRECTORY" in line:
            #                                 folders.add(filename)
            #                                 # if not filename.startswith("/"):
            #                                 #     folders.add(os.path.join(curr_directory, filename))
            #                             elif not is_proc_numeric:
            #                                 failed.add(filename)
            #                                 # if not filename.startswith("/"):
            #                                 #     failed.add(os.path.join(curr_directory, filename))
            #                         else:
            #                             if filename in failed:
            #                                 failed.remove(filename)
            #                                 # if not filename.startswith("/"):
            #                                 #     failed.remove(os.path.join(curr_directory, filename))
            #                             opened.add(filename)
            #                             # if not filename.startswith("/"):
            #                             #     opened.add(os.path.join(curr_directory, filename))
            #             except ValueError as e:
            #                 print("!"*100)
            #                 print(e)
            #                 print(line)
            #                 print("!"*100)
            #                 continue
            #             except IndexError as e:
            #                 print("!"*100)
            #                 print(e)
            #                 print(line)
            #                 print("!"*100)
            #                 continue
                
            #     # 处理后3000行
            #     # 先跳过中间的行
            #     skip_lines = total_lines - 6000
            #     current_line = 0
            #     for line in sFile:
            #         current_line += 1
            #         if current_line > skip_lines:
            #             break
                
            #     # 处理最后3000行
            #     current_line = 0
            #     for line in sFile:
            #         current_line += 1
            #         if current_line > 3000:
            #             break
                    
            #         if pid == -1:
            #             pid = line.split()[0].strip().decode("utf-8", errors="ignore")
            #             if pid in forkmap.keys():
            #                 curr_directory = forkmap[pid]
            #         if b"/gh_nvram" in line: # skip reads from gh_folder
            #             continue
            #         if len(failed) < MAX_SET:
            #             # edge case - fstat uses fd not path, so must be skipped. accept all other variants
            #             addfile = False
            #             try:
            #                 if b"open(" in line or b"openat(" in line:
            #                     groups = self.open_re.match(line)
            #                     addfile = True
            #                 elif b"stat" in line and b"fstat(" not in line:
            #                     groups = self.stat_re.match(line)
            #                     addfile = True
            #                 elif b"access(" in line:
            #                     groups = self.access_re.match(line)
            #                     addfile = True
            #                 elif b"chdir(" in line:
            #                     groups = self.chdir_re.match(line)
            #                     if groups:
            #                         filename = groups.group('file').decode("utf-8")
            #                         retval = groups.group('retval')
            #                         retval = int(retval.split()[0].decode("utf-8"))
            #                         # print(filename, retval)
            #                         if retval < 0:
            #                             folders.add(filename)
            #                         else:
            #                             if filename in folders:
            #                                 folders.remove(filename)
            #                             opened.add(filename)
            #                             print("    - chdir %s --> %s" % (curr_directory, filename))
            #                             if filename.startswith("/"):
            #                                 curr_directory = filename
            #                             else:
            #                                 curr_directory = os.path.join(curr_directory, filename)
            #                 elif b"fork(" in line:
            #                     forked = True
            #                     forkedpid = line.split(b"=")[1].strip()
            #                     if forkedpid != 0:
            #                         forkmap[forkedpid] = curr_directory
            #                 elif b"exit(" in line:
            #                     if forked:
            #                         is_daemonized = True
            #                     # else:
            #                     #     print("    - !! ERROR !! Regex chdir_re does not match", line)
                            
            #                 # add file
            #                 if addfile and groups and len(groups.group('file')) > 0 and len(groups.group('retval')) > 0:
            #                         filename = groups.group('file').decode("utf-8")
            #                         retval = groups.group('retval')
            #                         if b"0x" in retval:
            #                             retval = int(retval.split()[0].decode("utf-8"), 16)
            #                         else:
            #                             retval = int(retval.split()[0].decode("utf-8"))
            #                         # print(filename, retval)
            #                         basefilename = os.path.basename(filename)
            #                         if len(filename) <= 0 or filename.strip() == "/" or \
            #                            len(basefilename) <= 0 or basefilename.startswith("."): #skip likely malformed filenames
            #                             continue
            #                         if not filename.startswith("/") and curr_directory.strip() != "/":
            #                             filename = os.path.join(curr_directory, filename)
                                    
            #                         # 跳过带有数字名称的 proc 文件（如 proc/12421）
            #                         is_proc_numeric = False
            #                         if "proc/" in filename:
            #                             proc_parts = filename.split("/proc/")
            #                             if len(proc_parts) > 1:
            #                                 proc_path = proc_parts[1]
            #                                 first_part = proc_path.split("/")[0]
            #                                 if first_part.isdigit():
            #                                     is_proc_numeric = True
                                    
            #                         if retval < 0:
            #                             if b"O_DIRECTORY" in line:
            #                                 folders.add(filename)
            #                                 # if not filename.startswith("/"):
            #                                 #     folders.add(os.path.join(curr_directory, filename))
            #                             elif not is_proc_numeric:
            #                                 failed.add(filename)
            #                                 # if not filename.startswith("/"):
            #                                 #     failed.add(os.path.join(curr_directory, filename))
            #                         else:
            #                             if filename in failed:
            #                                 failed.remove(filename)
            #                                 # if not filename.startswith("/"):
            #                                 #     failed.remove(os.path.join(curr_directory, filename))
            #                             opened.add(filename)
            #                             # if not filename.startswith("/"):
            #                             #     opened.add(os.path.join(curr_directory, filename))
            #             except ValueError as e:
            #                 print("!"*100)
            #                 print(e)
            #                 print(line)
            #                 print("!"*100)
            #                 continue
            #             except IndexError as e:
            #                 print("!"*100)
            #                 print(e)
            #                 print(line)
            #                 print("!"*100)
            #                 continue
            # else:
            #     # 处理所有行
            #     for line in sFile:
            #         if pid == -1:
            #             pid = line.split()[0].strip().decode("utf-8", errors="ignore")
            #             if pid in forkmap.keys():
            #                 curr_directory = forkmap[pid]
            #         if b"/gh_nvram" in line: # skip reads from gh_folder
            #             continue
            #         if len(failed) < MAX_SET:
            #             # edge case - fstat uses fd not path, so must be skipped. accept all other variants
            #             addfile = False
            #             try:
            #                 if b"open(" in line or b"openat(" in line:
            #                     groups = self.open_re.match(line)
            #                     addfile = True
            #                 elif b"stat" in line and b"fstat(" not in line:
            #                     groups = self.stat_re.match(line)
            #                     addfile = True
            #                 elif b"access(" in line:
            #                     groups = self.access_re.match(line)
            #                     addfile = True
            #                 elif b"chdir(" in line:
            #                     groups = self.chdir_re.match(line)
            #                     if groups:
            #                         filename = groups.group('file').decode("utf-8")
            #                         retval = groups.group('retval')
            #                         retval = int(retval.split()[0].decode("utf-8"))
            #                         # print(filename, retval)
            #                         if retval < 0:
            #                             folders.add(filename)
            #                         else:
            #                             if filename in folders:
            #                                 folders.remove(filename)
            #                             opened.add(filename)
            #                             print("    - chdir %s --> %s" % (curr_directory, filename))
            #                             if filename.startswith("/"):
            #                                 curr_directory = filename
            #                             else:
            #                                 curr_directory = os.path.join(curr_directory, filename)
            #                 elif b"fork(" in line:
            #                     forked = True
            #                     forkedpid = line.split(b"=")[1].strip()
            #                     if forkedpid != 0:
            #                         forkmap[forkedpid] = curr_directory
            #                 elif b"exit(" in line:
            #                     if forked:
            #                         is_daemonized = True
            #                     # else:
            #                     #     print("    - !! ERROR !! Regex chdir_re does not match", line)
                            
            #                 # add file
            #                 if addfile and groups and len(groups.group('file')) > 0 and len(groups.group('retval')) > 0:
            #                         filename = groups.group('file').decode("utf-8")
            #                         retval = groups.group('retval')
            #                         if b"0x" in retval:
            #                             retval = int(retval.split()[0].decode("utf-8"), 16)
            #                         else:
            #                             retval = int(retval.split()[0].decode("utf-8"))
            #                         # print(filename, retval)
            #                         basefilename = os.path.basename(filename)
            #                         if len(filename) <= 0 or filename.strip() == "/" or \
            #                            len(basefilename) <= 0 or basefilename.startswith("."): #skip likely malformed filenames
            #                             continue
            #                         if not filename.startswith("/") and curr_directory.strip() != "/":
            #                             filename = os.path.join(curr_directory, filename)
                                    
            #                         # 跳过带有数字名称的 proc 文件（如 proc/12421）
            #                         is_proc_numeric = False
            #                         if "proc/" in filename:
            #                             proc_parts = filename.split("/proc/")
            #                             if len(proc_parts) > 1:
            #                                 proc_path = proc_parts[1]
            #                                 first_part = proc_path.split("/")[0]
            #                                 if first_part.isdigit():
            #                                     is_proc_numeric = True
                                    
            #                         if retval < 0:
            #                             if b"O_DIRECTORY" in line:
            #                                 folders.add(filename)
            #                                 # if not filename.startswith("/"):
            #                                 #     folders.add(os.path.join(curr_directory, filename))
            #                             elif not is_proc_numeric:
            #                                 failed.add(filename)
            #                                 # if not filename.startswith("/"):
            #                                 #     failed.add(os.path.join(curr_directory, filename))
            #                         else:
            #                             if filename in failed:
            #                                 failed.remove(filename)
            #                                 # if not filename.startswith("/"):
            #                                 #     failed.remove(os.path.join(curr_directory, filename))
            #                             opened.add(filename)
            #                             # if not filename.startswith("/"):
            #                             #     opened.add(os.path.join(curr_directory, filename))
            #             except ValueError as e:
            #                 print("!"*100)
            #                 print(e)
            #                 print(line)
            #                 print("!"*100)
            #                 continue
            #             except IndexError as e:
            #                 print("!"*100)
            #                 print(e)
            #                 print(line)
            #                 print("!"*100)
            #                 continue


        tFile.close()

        print("    - [pid:%s] parse completed!" % pid)
        
        # check for nvrams inside log file
        nvramLogPath = os.path.join(self.fs_path, NVRAM_LOG_PATH)
        if os.path.exists(nvramLogPath):
            print("Parsing ", nvramLogPath)
            with open(nvramLogPath, "rb") as nvramMissingFile:
                for line in nvramMissingFile:
                    line = line.decode('utf-8', errors='ignore')
                    key = line.strip()
                    if key not in nvrams:
                        print("    - queuing missing nvram config target: ", key)
                        nvrams.add(key)
            nvramMissingFile.close()
            Files.rm_file(nvramLogPath)
            print("done")

        for filename in failed:
            if ".so" not in filename and \
               "/dev/mtdblock" not in filename: # blacklist mtdblock devices
                # if filename not in targets:
                targets.add(filename)

        for foldername in folders:
            failed.add(foldername)

        if failed:
            print("failed", failed)
        if folders:
            print("folders", folders)
        if targets:
            print("targets", targets)
        if interfaces:
            print("interfaces", interfaces)
        if ip_addrs:
            print("ip addrs", ip_addrs)
        if ipv6_addrs:
            print("ip addrs", ipv6_addrs)
        if nvrams:
            print("nvrams", nvrams)
        return targets, folders, nvrams, ip_addrs, ipv6_addrs, target_ports, interfaces, failed, segfaulted, is_daemonized

    def check_ip(self, ip):
        if len(ip) > 0:
            try:
                ipaddress.ip_address(ip)
                return True
            except ValueError:
                pass
        return False
    
    def convert(self, trace_path, output_path):
        tracedump = dict()
        traces = dict()
        straces = dict()
        trace_files = dict()
        fds = list()
        base_addr = -1
        end_addr = -1
        parent_pid = -1

        print("converting", trace_path)

        if not os.path.exists(trace_path):
            print("ERROR %s does not exist" % trace_path)
            return False

        with open(trace_path, "rb") as tf:
            for line in tf: #skip to last line

                if base_addr < 0 or end_addr < 0:
                    if(b"start_code" in line):
                        base_addr_field = self.start_code_re.match(line).group('addr')
                        base_addr = -1
                        try:
                            base_addr = int(base_addr_field, 16)
                        except ValueError:
                            print("error, tried to convert addr %s" % base_addr_field)
                            base_addr = -1

                    elif(b"end_code" in line):
                        end_addr_field = self.start_code_re.match(line).group('addr')
                        end_addr = -1
                        try:
                            end_addr = int(end_addr_field, 16)
                        except ValueError:
                            print("error, tried to convert addr %s" % end_addr_field)
                            end_addr = -1
                else:
                    # NOTE: this entire part can probably be replaced by a bunch of grep/sed bash scripts
                    if(b"Trace" in  line):
                        try:
                            pidfield = self.trace_re.match(line).group('pid')
                            addrfield = self.trace_re.match(line).group('addr')
                            pid = -1
                            addr = -1
                            addr = int(addrfield, 16)
                        except ValueError:
                            print("error, tried to convert addr %s" % addrfield)
                            addr = -1
                        except Exception as e:
                            print(e)
                            print(line)
                            continue

                        try:
                            pid = int(pidfield)
                        except ValueError:
                            print("error, tried to convert pid %s" % pidfield)
                            pid = -1

                        if addr > 0 and pid >= 0:
                            if pid not in traces.keys():
                                pidname = "%d.trace" % pid
                                tracePath = os.path.join(self.fs_path, pidname)
                                fd = open(tracePath, "a+")
                                fds.append(fd)
                                trace_files[pid] = fd
                                traces[pid] = tracePath
                                if parent_pid == -1: #first pid encountered
                                    parent_pid = pid
                            fd = trace_files[pid]
                            addrline = "%d\n" % addr
                            fd.write(addrline)
                        else:
                            print("!! ERROR !! Invalid address found in trace")
                            # raise(Exception("Invalid address found in trace"))

                    elif(b"STRACE" in line):
                        if pid not in straces.keys():
                            straces[pid] = list()
                        straces[pid].append(line)

        tf.close()

        for fd in fds:
            fd.close()

        tracedump["base_addr"] = base_addr
        tracedump["end_addr"] = end_addr
        tracedump["parent_pid"] = parent_pid
        tracedump["traces"] = traces
        tracedump["straces"] = straces
        for pid in traces.keys():
            print(pid, ": contains ", len(traces[pid]), "lines")


        with open(output_path, "w") as jfile:
            json.dump(tracedump, jfile)

        jfile.close()

        return True