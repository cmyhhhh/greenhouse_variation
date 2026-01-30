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
                subprocess.run(ida_cmd, shell=True)
            else:
                ida_cmd = f"/ida/idat64 -A -L{reverse_dir}/decompileC.log -S{ida_script_path} -o{i64_file} {binary_path} 2>/dev/null"
                subprocess.run(ida_cmd, shell=True)

            decompile_functions_name_path = os.path.join(
                reverse_dir, "functions_name.txt")
            if not os.path.exists(decompile_functions_name_path):
                raise Exception(f"{filename} 反编译失败，未生成函数列表")

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

    def __init__(self, container_fs_path, binary_path, container_name, fs_path,
                 reverse_host="10.201.169.58", reverse_port=9998, api_key="sk-o20HTjWDHvtm25HPmjfWgkrOdRDH79bXLRA3UGZDFPXTTYL5", model="qwen-plus"):
        self.container_fs_path = container_fs_path
        self.reverse_dir = f"/tmp/{os.path.basename(binary_path)}_decompile"
        self.binary_path = binary_path
        self.communication_file = os.path.join(
            container_fs_path, "msg_nvram.txt")
        self.lock_file = os.path.join(container_fs_path, "msg_nvram.lock")
        self.container_name = container_name
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

        # TODO: 加上各种nvram函数的key_pos，包括set等
        self.nvram_funcs_key_pos = {
            "_nvram_get": 0,
            "nvram_nget": 0,
            "nvram_get_state": 0,
            "artblock_get": 0,
            "artblock_fast_get": 0,
            "artblock_safe_get": 0,
            "acos_nvram_get": 0,
            "acosNvramConfig_exist": 0,
            "acosNvramConfig_get": 0,
            "nvram_get_adv": 1,
            "nvram_bufget": 1,
            "apmib_get": 0,
            "apmib_getDef": 0,
            "apmib_set": 0,
            "WAN_ith_CONFIG_GET": 1,
            "envram_get": 1,
            "envram_get_func": 1,
            "envram_getf": 0,
            "nvram_getf": 0
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
        self.try_max_num = 3  # Maximum retry attempts
        self.is_error = False
        self.stop_flag = False
        
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
<value_type>: Type of the NVRAM value (only int, string, short, long long, bool=true/false)
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

    def add_nvram(self, key, response_content, function_name):
        """
        添加NVRAM值

        Args:
            key (str): NVRAM key
            response_content (str): LLM回复内容
            function_name (str): 调用该函数的nvram函数名
        """
        nvram_file_path = os.path.join(self.nvram_dir, key)

        if not os.path.exists(nvram_file_path):
            # 文件不存在，创建文件夹和文件
            os.makedirs(os.path.dirname(nvram_file_path), exist_ok=True)
            with open(nvram_file_path, 'w') as file:
                file.write('')

        with open(nvram_file_path, 'wb') as file:
            parts = response_content.strip().split(" ")
            if len(parts) == 2:
                value_type, value = parts
            else:
                parts = response_content.strip().split("=")
                if len(parts) == 2:
                    value_type, value = parts
                else:
                    value_type = "string"
                    value = ""

            # 对于apmib_getDef和apmib_get函数，在内容前面写入值类型
            if function_name in ["apmib_getDef", "apmib_get"]:
                # 获取对应的数字类型
                type_num = self.nvram_value_type.get(
                    value_type, "1")  # 默认char类型
                if value_type == "bool":
                    type_num = self.nvram_value_type["bool"]
                elif value_type == "string":
                    type_num = self.nvram_value_type["char"]
                elif value_type == "int":
                    type_num = self.nvram_value_type["int"]
                elif value_type == "short":
                    type_num = self.nvram_value_type["short"]
                elif value_type == "long long":
                    type_num = self.nvram_value_type["long long"]

                # 写入值类型
                file.write(type_num.encode('utf-8'))

            file.write(value.encode('utf-8'))

        try:
            tar_stream = io.BytesIO()
            with tarfile.open(fileobj=tar_stream, mode='w') as tar:
                tar.add(nvram_file_path, arcname=key)
            tar_stream.seek(0)
            self.container.put_archive(path=os.path.join(
                self.container_fs_path, "gh_nvram"), data=tar_stream.read())
        except Exception as e:
            print(f"[NvramServer] Failed to copy gh_nvram to container: {e}")

    def get_nvram_value(self, key):
        """
        使用LLM推理获取NVRAM值

        Args:
            key (str): NVRAM key
        """
        prompt = []
        num_try = 0
        previous_response = ""

        while num_try < self.try_max_num:
            num_try += 1

            if num_try == 1:
                prompt = self.get_related_code(key)
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

                                    # 转换类型 - ensure buf_type is not None before stripping
                                    stripped_buf_type = buf_type.strip() if buf_type else ''
                                    converted_type = type_mapping.get(
                                        stripped_buf_type, 'char')
                                    # 检查指针类型
                                    if buf_type and ('*' in buf_type or 'ptr' in buf_type.lower()):
                                        converted_type = 'char'
                                    # 检查布尔类型的特殊情况
                                    if buf_type and ('bool' in buf_type.lower() or '_BOOL' in buf_type):
                                        converted_type = 'bool'

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

    def process_communication_file(self):
        """
        处理通信文件
        """
        start_time = time.time()
        try:
            # 先检查容器是否在运行
            if self.container.status != 'running':
                return
                
            # 再检查锁文件是否存在，若存在则跳过本次处理
            exit_code, _ = self.container.exec_run(f"test -f {self.lock_file}")
            if exit_code == 0:
                return
            
            # 再检查通信文件是否存在
            exit_code, _ = self.container.exec_run(
                f"test -f {self.communication_file}")
            if exit_code != 0:
                return
        except Exception as e:
            print(f"[NvramServer] Error checking container files: {e}")
            return

        # 创建锁文件，确保互斥访问
        try:
            self.container.exec_run(f"touch {self.lock_file}")
        except Exception as e:
            print(f"[NvramServer] Failed to create lock file: {e}")
            return

        # print(f"发现通信文件: {self.communication_file}")

        # 解析文件
        function_name, key = self.parse_communication_file()
        if not function_name or not key:
            # 删除无效文件
            self.cleanup_files()
            return

        print(f"[NvramServer] Obtained information: function_name={function_name}, key={key}")

        if function_name == "apmib_set":
            if not self.apmib_set_var_type:
                self.handle_apmib_set()

            if key in self.apmib_set_var_type:
                var_type = self.apmib_set_var_type[key]
            else:
                var_type = "char"

            var_type = self.nvram_value_type[var_type]

            # 将 var_type 写入容器内的回复文件
            reply_file = f"{self.container_fs_path}/msg_nvram_reply.txt"
            try:
                exit_code, output = self.container.exec_run(
                    f"sh -c 'echo \"{var_type}\" > {reply_file}'")
                if exit_code == 0:
                    print(f"[NvramServer] var_type written to reply file in container: {reply_file}")
                else:
                    print(
                        f"[NvramServer] 写入容器内回复文件失败: {output.decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"[NvramServer] Error writing to reply file in container: {e}")
            self.cleanup_files()
            return

        if function_name not in self._parsed_functions:
            self.generate_key_to_func_json(function_name)
            self._parsed_functions.add(function_name)
            parsed_funcs_file = os.path.join(
                self.reverse_dir, "parsed_functions.json")
            try:
                with open(parsed_funcs_file, "w") as f:
                    json.dump(list(self._parsed_functions), f, indent=2)
                print(f"[NvramServer] Updated parsed function list file: {parsed_funcs_file}")
            except Exception as e:
                print(f"[NvramServer] Failed to save parsed function list: {e}")

        response = self.get_nvram_value(key)
        self.add_nvram(key, response, function_name)

        # 处理完成后清理文件
        self.cleanup_files()
        
        end_time = time.time()
        self.consume_time += end_time - start_time

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
    
    def stop(self):
        """
        停止NVRAM LLM推理模块
        """
        self.stop_flag = True
        print("[NvramServer] NVRAM LLM inference module stop flag set")
        
        # 等待所有LLM请求结束
        import time
        print("[NvramServer] Waiting for all LLM requests to complete...")
        while True:
            with self.llm_request_lock:
                current_count = self.llm_request_count
            if current_count == 0:
                break
            print(f"[NvramServer] Still {current_count} LLM requests in progress, waiting...")
            time.sleep(5)
        print("[NvramServer] All LLM requests completed")


    def run(self, interval=0.5):
        """
        运行NVRAM LLM推理模块

        Args:
            interval: 检查文件的时间间隔，单位秒，默认0.1秒
        """
        print(f"[NvramServer] NVRAM LLM inference module started")
        print(f"[NvramServer] Monitoring path in container: {self.communication_file}")
        print(f"[NvramServer] Reverse analysis file directory: {self.reverse_dir}")
        print(f"[NvramServer] Check interval: {interval} seconds")

        if not os.path.exists(self.binary_path):
            print(f"[NvramServer] Error: File does not exist: {self.binary_path}")
            exit(1)

        start_time = time.time()
        # 启动时检查并逆向二进制文件
        if not self.check_if_reversed() and self.binary_path:
            print("[NvramServer] Binary file not reversed, starting reverse analysis...")
            self.reverse_binary()
        end_time = time.time()
        self.consume_time += end_time - start_time

        try:
            while not self.stop_flag:
                self.process_communication_file()
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[NvramServer] NVRAM LLM inference module stopped")
        except Exception as e:
            print(f"[NvramServer] Server runtime error: {e}")
            self.cleanup_files()
        finally:
            print("[NvramServer] NVRAM LLM inference module exited")

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