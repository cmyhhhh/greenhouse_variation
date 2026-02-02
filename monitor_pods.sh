#!/bin/bash

# 监控脚本：持续监控当前 pods 的资源消耗

# 输出文件
OUTPUT_FILE="pod_resource_monitoring.log"

# 清除旧的输出文件
> $OUTPUT_FILE

echo "开始监控 Pod 资源消耗..."
echo "监控结果将保存到 $OUTPUT_FILE"
echo "按 Ctrl+C 停止监控"

echo "\n===== Pod 资源监控开始 =====" >> $OUTPUT_FILE
echo "监控开始时间: $(date)" >> $OUTPUT_FILE

try_count=0
max_tries=3

# 主监控循环
while true; do
  echo "\n----- $(date) -----" >> $OUTPUT_FILE
  
  # 尝试获取 Pod 列表
  pod_list=$(minikube kubectl -- get pods | grep greenhouse-batch | grep Running | awk '{print $1}')
  
  if [ -z "$pod_list" ]; then
    echo "未找到运行中的 greenhouse-batch Pods" >> $OUTPUT_FILE
    try_count=$((try_count + 1))
    
    if [ $try_count -ge $max_tries ]; then
      echo "连续 $max_tries 次未找到运行中的 Pods，检查是否有其他 Pods 运行..." >> $OUTPUT_FILE
      minikube kubectl -- get pods >> $OUTPUT_FILE
      try_count=0
    fi
  else
    try_count=0
    echo "找到以下运行中的 Pods: $pod_list" >> $OUTPUT_FILE
    
    # 定义要监控的节点
    nodes=("minikube" "minikube-m02")
    
    # 遍历每个节点执行监控
    for node in "${nodes[@]}"; do
      # 使用 docker stats 监控资源使用
      echo "\n=== 节点 $node - Docker 容器资源使用情况 ===" >> $OUTPUT_FILE
      minikube ssh --node $node -- 'docker stats --no-stream | grep greenhouse' >> $OUTPUT_FILE
      
      # 使用 top 命令查看系统整体资源使用
      echo "\n=== 节点 $node - 系统整体资源使用情况 ===" >> $OUTPUT_FILE
      minikube ssh --node $node -- 'top -b -n 1 | head -10' >> $OUTPUT_FILE
      
      # 使用 df 查看存储使用
      echo "\n=== 节点 $node - 存储使用情况 ===" >> $OUTPUT_FILE
      minikube ssh --node $node -- 'df -h | grep -E "shared|vda1"' >> $OUTPUT_FILE
    done
  fi
  
  # 等待 30 秒后再次监控
  sleep 60
done