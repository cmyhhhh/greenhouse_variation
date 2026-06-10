#!/bin/bash

# 输出文件路径
TIMEOUT_FILE="/share/k8/target_timeout.list"
OOM_FILE="/share/k8/target_oom.list"
FINE_FILE="/share/k8/target_fine.list"

# 确保输出文件存在并清空
mkdir -p "$(dirname "$TIMEOUT_FILE")"
> "$TIMEOUT_FILE"
> "$OOM_FILE"
> "$FINE_FILE"

# 确保 FirmAgent_logs 目录存在
FIRMAGENT_LOGS_DIR="/share/FirmAgent_logs"
mkdir -p "$FIRMAGENT_LOGS_DIR"

# 处理 /share/k8/logs 目录下的所有文件
for log_file in "/share/k8/logs"/*; do
  if [ -f "$log_file" ]; then
    # 提取 hash 值
    hash_value=$(grep -a -oP 'TARGET HASH:\s+\K\S+' "$log_file" | head -1)
    
    # 读取日志的第三行
    third_line=$(sed -n '3p' "$log_file")
    
    # 检查文件中是否存在 REHOST TIMEDOUT
    if grep -q "REHOST TIMEDOUT" "$log_file"; then
      # 提取 brand (从 "target firmware brand: " 行)
      brand=$(grep -oP 'target firmware brand: \K\w+' "$log_file")
      
      # 从第三行提取 path 和 name
      full_path=$(echo "$third_line" | awk '{print $1}')
      name=$(echo "$third_line" | awk '{print $3}')
      
      # 移除 /shared/ 前缀
      path=$(echo "$full_path" | sed 's|^/shared/||')
      
      # 提取 REHOST TIMEDOUT 所在行号
      line_number=$(grep -n "REHOST TIMEDOUT" "$log_file" | cut -d: -f1)
      
      # 按照指定格式写入输出文件 (brand name path)
      echo "$brand $name $path" >> "$TIMEOUT_FILE"
      
      # 输出处理信息
      echo "Processed $log_file: found REHOST TIMEDOUT at line $line_number"
      echo "  Brand: $brand"
      echo "  Name: $name"
      echo "  Path: $path"
    elif grep -q "GHREHOST COMPLETE:  *137" "$log_file"; then
      # 检查文件中是否存在 OOM (GHREHOST COMPLETE:  137)
      # 提取 brand (从 "target firmware brand: " 行)
      brand=$(grep -oP 'target firmware brand: \K\w+' "$log_file")
      
      # 从第三行提取 path 和 name
      full_path=$(echo "$third_line" | awk '{print $1}')
      name=$(echo "$third_line" | awk '{print $3}')
      
      # 移除 /shared/ 前缀
      path=$(echo "$full_path" | sed 's|^/shared/||')
      
      # 提取 GHREHOST COMPLETE:  137 所在行号
      line_number=$(grep -n "GHREHOST COMPLETE:  *137" "$log_file" | cut -d: -f1)
      
      # 按照指定格式写入输出文件 (brand name path)
      echo "$brand $name $path" >> "$OOM_FILE"
      
      # 输出处理信息
      echo "Processed $log_file: found OOM at line $line_number"
      echo "  Brand: $brand"
      echo "  Name: $name"
      echo "  Path: $path"
    else
      # 没有问题的日志文件
      # 提取 brand (从 "target firmware brand: " 行)
      brand=$(grep -oP 'target firmware brand: \K\w+' "$log_file")
      
      # 从第三行提取 path 和 name
      full_path=$(echo "$third_line" | awk '{print $1}')
      name=$(echo "$third_line" | awk '{print $3}')
      
      # 移除 /shared/ 前缀
      path=$(echo "$full_path" | sed 's|^/shared/||')
      
      # 按照指定格式写入输出文件 (brand name path)
      echo "$brand $name $path" >> "$FINE_FILE"
      
      # 输出处理信息
      echo "Processed $log_file: no issues found"
      echo "  Brand: $brand"
      echo "  Name: $name"
      echo "  Path: $path"
      
      # 只复制 fine 的日志文件到 FirmAgent_logs 目录，并以 hash 值命名
      if [ -n "$hash_value" ]; then
        cp "$log_file" "$FIRMAGENT_LOGS_DIR/$hash_value"
        echo "Copied $log_file to $FIRMAGENT_LOGS_DIR/$hash_value"
      else
        echo "Warning: No TARGET HASH found in $log_file, skipping copy"
      fi
    fi
  fi
done

echo "Processing complete."
echo "Timeout results saved to $TIMEOUT_FILE"
echo "OOM results saved to $OOM_FILE"
echo "Fine results saved to $FINE_FILE"
echo "Logs copied to $FIRMAGENT_LOGS_DIR with hash names"
