#!/usr/bin/env python3
"""
日志提取工具

该脚本用于从/share/k8/logs目录下的日志文件中提取固件信息，包括Hash、Brand、固件名、Extracted、Run、Connect、Web等字段，并将结果保存为CSV文件。
"""

import os
import re
import csv
import argparse
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def extract_firmware_info(log_content):
    """
    从日志内容中提取固件信息
    
    Args:
        log_content (str): 日志文件内容
        
    Returns:
        dict: 提取的固件信息
    """
    # 提取Hash值
    hash_match = re.search(r'TARGET HASH:\s+([0-9a-fA-F]{64})', log_content)
    hash_value = hash_match.group(1) if hash_match else ""
    
    # 提取Brand
    brand_match = re.search(r'target firmware brand:\s+(\w+)', log_content)
    brand = brand_match.group(1) if brand_match else ""
    
    # 提取固件名
    firmware_match = re.search(r'/shared/samplesusenix/\w+/([^/]+\.zip)', log_content)
    firmware = firmware_match.group(1) if firmware_match else ""
    
    # 检查Extracted
    extracted = "TRUE" if "extract done!!!" in log_content else "FALSE"
    
    # 检查Run
    run = "TRUE" if "infer network start!!!" in log_content else "FALSE"
    
    # 提取Connect和Web
    connect = False
    web = False
    http_checker_match = re.search(r'Greenhouse-style HTTP checker result:\s+[^\s]+\s+(\w+)\s+(\w+)', log_content)
    if http_checker_match:
        connect = http_checker_match.group(1)
        web = http_checker_match.group(2)
    
    return {
        "HASH": hash_value,
        "Brand": brand,
        "NAME": firmware,
        "Extracted": extracted,
        "Run": run,
        "Connect": connect,
        "Web": web
    }


def process_log_file(log_path):
    """
    处理单个日志文件
    
    Args:
        log_path (str): 日志文件路径
        
    Returns:
        dict or None: 提取的固件信息，如果没有找到Hash值则返回None
    """
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            info = extract_firmware_info(content)
            if info["HASH"]:
                logger.info(f"成功处理文件: {os.path.basename(log_path)}")
                return info
            else:
                logger.warning(f"未找到Hash值，跳过文件: {os.path.basename(log_path)}")
                return None
    except Exception as e:
        logger.error(f"处理文件 {os.path.basename(log_path)} 时出错: {str(e)}")
        return None


def main(log_dir, output_csv):
    """
    主函数
    
    Args:
        log_dir (str): 日志目录路径
        output_csv (str): 输出CSV文件路径
    """
    # 存储提取的信息
    results = []
    
    # 遍历日志目录中的所有文件
    logger.info(f"开始处理日志目录: {log_dir}")
    for filename in os.listdir(log_dir):
        # 处理所有文件，不限制文件名格式
        log_path = os.path.join(log_dir, filename)
        info = process_log_file(log_path)
        if info:
            results.append(info)
    
    # 写入CSV文件
    logger.info(f"共提取 {len(results)} 条记录")
    logger.info(f"正在写入CSV文件: {output_csv}")
    
    with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ["HASH", "Brand", "NAME", "Extracted", "Run", "Connect", "Web"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result)
    
    logger.info(f"提取完成，结果已保存到 {output_csv}")


if __name__ == "__main__":
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='提取日志中的固件信息')
    # parser.add_argument('--log-dir', default='/share/k8/logs_server1', help='日志目录路径')
    # parser.add_argument('--output', default='/share/k8/extracted_server1_info.csv', help='输出CSV文件路径')
    parser.add_argument('--log-dir', default='/share/FirmAgent_logs', help='日志目录路径')
    parser.add_argument('--output', default='/share/FirmAE_info.csv', help='输出CSV文件路径')
    args = parser.parse_args()
    
    # 运行主函数
    main(args.log_dir, args.output)
