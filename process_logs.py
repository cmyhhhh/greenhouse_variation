import os
import sys
import traceback

def parse_log_file(log_path):
    """
    解析单个日志文件，提取关键信息
    
    Args:
        log_path: 日志文件路径
        
    Returns:
        dict: 包含提取信息的字典
    """
    result = {
        'log_path': log_path,
        'brand': '',
        'path': '',
        'name': '',
        'sha256sum': '',
        'extracted': '',
        'canrun': 'FALSE',
        'curlpassed': 'FALSE',
        'webpassed': 'FALSE'
    }
    
    if not os.path.exists(log_path):
        print(f"{log_path} 不存在")
        return result
    
    # # 检查后100行是否存在 "REHOST STATUS"
    # # 如果后100没有REHOST STATUS则直接退出
    # try:
    #     with open(log_path, "rb") as bFile:
    #         lines = bFile.readlines()
    #         total_lines = len(lines)
    #         start_line = max(0, total_lines - 100)
    #         found = False
    #         for idx in range(start_line, total_lines):
    #             line = lines[idx]
    #             try:
    #                 line_str = line.decode('utf-8', errors='ignore')
    #                 if "REHOST STATUS" in line_str:
    #                     found = True
    #                     break
    #             except:
    #                 continue
    #         if not found:
    #             return result
    # except:
    #     return result
    
    # 一次性读取所有行并处理
    try:
        with open(log_path, "rb") as bFile:
            lines = bFile.readlines()
            
            # 逐行提取所有字段
            for line_count, line in enumerate(lines, 1):
                try:
                    line_str = line.decode('utf-8', errors='ignore')
                    
                    # 提取品牌、路径、名称
                    if line_str.startswith("copying "):
                        result['path'] = line_str.split()[1]
                        result['name'] = result['path'].split("/")[-1]
                        result['name'] = result['name'].replace("(", "_").replace(")", "_").replace("-", "_")
                        dirpath = os.path.dirname(result['path'])
                        result['brand'] = dirpath.split("/")[-1].split("_")[0].strip()
                    
                    # 提取哈希值
                    if "TARGET HASH" in line_str:
                        result['sha256sum'] = line_str.split(":")[1].strip()
                    
                    # 提取 nvram 信息
                    # if "Found nvram functions" in line_str:
                    #     result['nvram'] = 'TRUE'
                        
                    # if "No nvram functions" in line_str:
                    #     result['nvram'] = 'FALSE'
                        
                    if "Error, unable to find binary path for" in line_str or "Error, unable to unpack image" in line_str:
                        result['extracted'] = 'FALSE'
                        break
                    
                    # 提取 extracted 状态
                    if "PATCH LOOP [0]" in line_str:
                        result['extracted'] = 'TRUE'
                        
                    # 提取 canrun 状态
                    if "target log file found" in line_str or result['curlpassed'] == 'TRUE':
                        result['canrun'] = 'TRUE'
                    
                    # 提取 curlpassed 状态
                    if line_str.startswith("[+] curlpassed") or "[connected]: True" in line_str:
                    # if "[connected]: True" in line_str:
                        result['curlpassed'] = 'TRUE'
                    
                    # 提取 webpassed 状态
                    if line_str.startswith("[+] webpassed") or "[wellformed]: True" in line_str:
                    # if "[wellformed]: True" in line_str:
                        result['webpassed'] = 'TRUE'
                        
                except Exception as e:
                    print(f"处理日志文件 {log_path} 时出错:")
                    print(f"错误: {e}")
                    print(f"行号: {line_count}")
                    print(traceback.format_exc())
                    # 继续处理下一行
                    continue
    except Exception as e:
        print(f"读取日志文件 {log_path} 时出错: {e}")
    
    return result

def save_results(results, output_file):
    """
    将结果保存到CSV文件
    
    Args:
        results: 包含解析结果的列表
        output_file: 输出文件路径
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            # 写入表头
            f.write("HASH,Brand,NAME,Extracted,Run,Connect,Web\n")
            # 写入数据
            for result in results:
                f.write(f"{result['sha256sum']},{result['brand']},{result['name']},{result['extracted']},{result['canrun']},{result['curlpassed']},{result['webpassed']}\n")
        print(f"结果已保存到 {output_file}")
    except Exception as e:
        print(f"保存结果时出错: {e}")


def main(log_folder, output_file=None):
    """
    主函数，处理指定目录下的所有日志文件
    
    Args:
        log_folder: 日志文件夹路径
        output_file: 输出文件路径，默认为 None
    """
    # 存储所有结果
    results = []
    
    # 获取日志文件夹中的所有文件
    try:
        log_files = os.listdir(log_folder)
    except Exception as e:
        print(f"无法读取日志文件夹 {log_folder}: {e}")
        return
    
    # 处理每个日志文件
    for log_file_name in log_files:
        log_path = os.path.join(log_folder, log_file_name)
        
        # 解析日志文件
        result = parse_log_file(log_path)
        
        if not result['brand'] or not result['sha256sum'] or not result['name']:
            continue
        
        # 如果结果中有数据或为错误情况，则添加到结果列表
        if result['brand'] and result['sha256sum'] and result['name'] and result['extracted'] and result['canrun'] and result['curlpassed'] and result['webpassed']:
            results.append(result)
            print(f"{result['log_path']},{result['sha256sum']},{result['brand']},{result['name']},{result['extracted']},{result['canrun']},{result['curlpassed']},{result['webpassed']}")
    
    # 如果指定了输出文件，则保存结果
    if output_file:
        save_results(results, output_file)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: process_logs.py <path-to-log-folder> [output-file]")
        sys.exit(1)
    
    log_folder = sys.argv[1]
    
    # 确定输出文件路径
    if len(sys.argv) >= 3:
        output_file = sys.argv[2]
    else:
        # 默认保存到当前执行目录，文件名格式为：process_logs_YYYYMMDD_HHMMSS.csv
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(os.getcwd(), f"process_logs_{timestamp}.csv")
    
    if not os.path.exists(log_folder):
        print(f"{log_folder} 不存在")
        sys.exit(1)
    
    if not os.path.isdir(log_folder):
        print(f"{log_folder} 不是一个目录")
        sys.exit(1)
    
    main(log_folder, output_file)
