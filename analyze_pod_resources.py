import re
import sys
from collections import defaultdict

# 读取日志文件
with open('/greenhouse_variation/pod_resource_monitoring.log', 'r', encoding='utf-8') as f:
    content = f.read()

# 定义正则表达式来匹配容器资源使用情况
container_pattern = re.compile(r'\w+\s+k8s_gh-single-worker_(greenhouse-batch-\d+-\w+)_default_[\w-]+_\d+\s+([\d.]+%)\s+([\d.]+\w+)\s+/\s+([\d.]+\w+)\s+([\d.]+%)')

# 存储每个POD的资源使用数据
pod_resources = defaultdict(list)

# 解析日志内容
matches = container_pattern.findall(content)
for match in matches:
    pod_name = match[0]
    cpu_usage = match[1]
    memory_usage = match[2]
    memory_total = match[3]
    memory_percent = match[4]
    
    # 转换数据格式
    cpu_value = float(cpu_usage.rstrip('%'))
    
    # 转换内存使用量为MB
    memory_value = memory_usage
    if memory_value.endswith('MiB'):
        memory_mb = float(memory_value.rstrip('MiB'))
    elif memory_value.endswith('GiB'):
        memory_mb = float(memory_value.rstrip('GiB')) * 1024
    elif memory_value.endswith('KiB'):
        memory_mb = float(memory_value.rstrip('KiB')) / 1024
    else:
        memory_mb = float(memory_value)
    
    pod_resources[pod_name].append({
        'cpu': cpu_value,
        'memory_mb': memory_mb
    })

# 计算每个POD的平均资源使用量
print("=== POD资源使用情况分析 ===")
print("POD名称\t\t平均CPU使用率(%)\t平均内存使用量(MB)")
print("-" * 70)

all_cpu_values = []
all_memory_values = []

for pod_name, resources in pod_resources.items():
    if resources:
        avg_cpu = sum(r['cpu'] for r in resources) / len(resources)
        avg_memory = sum(r['memory_mb'] for r in resources) / len(resources)
        
        all_cpu_values.append(avg_cpu)
        all_memory_values.append(avg_memory)
        
        print(f"{pod_name}\t{avg_cpu:.2f}\t\t{avg_memory:.2f}")

# 计算整体平均值
if all_cpu_values and all_memory_values:
    overall_avg_cpu = sum(all_cpu_values) / len(all_cpu_values)
    overall_avg_memory = sum(all_memory_values) / len(all_memory_values)
    
    print("-" * 70)
    print(f"整体平均\t\t{overall_avg_cpu:.2f}\t\t{overall_avg_memory:.2f}")
    print("-" * 70)
    print(f"分析的POD数量: {len(pod_resources)}")
