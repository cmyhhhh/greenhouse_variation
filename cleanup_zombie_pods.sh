#!/usr/bin/env bash

# =========================
# Config
# =========================
NAMESPACE="default"
JOB_NAME="greenhouse-batch-2"
INTERVAL=30   # 秒

# =========================
# Helper
# =========================
log() {
  echo "[`date '+%Y-%m-%d %H:%M:%S'`] $1"
}

# =========================
# 判断是否是僵尸 Pod
# =========================
is_zombie() {
  local pod="$1"

  # minikube kubectl -- get pod greenhouse-batch-2-40-b6cjn -n default --no-headers 2>/dev/null | awk '{print $3}'
  status=$(minikube kubectl -- get pod "$pod" -n "$NAMESPACE" --no-headers 2>/dev/null | awk '{print $3}')
  ready=$(minikube kubectl -- get pod "$pod" -n "$NAMESPACE" --no-headers 2>/dev/null | awk '{print $2}')

  # 1. ContainerStatusUnknown
  if [[ "$status" == "ContainerStatusUnknown" ]]; then
    return 0
  fi

  # 2. Error
  if [[ "$status" == "Error" ]]; then
    return 0
  fi

  # 3. OOMKilled
  if [[ "$status" == "OOMKilled" ]]; then
    return 0
  fi

#   # 4. Terminating 卡住（通过 deletionTimestamp 判断）
#   deleting=$(minikube kubectl -- get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.metadata.deletionTimestamp}' 2>/dev/null)
#   if [[ -n "$deleting" ]]; then
#     return 0
#   fi

#   # 4. Running 但不 Ready（卡死）
#   if [[ "$status" == "Running" && "$ready" != "1/1" ]]; then
#     return 0
#   fi

  return 1
}

# =========================
# 主循环
# =========================
log "Start zombie pod cleaner for job=$JOB_NAME"

while true; do
  # 获取属于该 Job 的 Pod
  pods=$(minikube kubectl -- get pods -n "$NAMESPACE" \
    -l job-name="$JOB_NAME" \
    --no-headers | awk '{print $1}')
 # minikube kubectl -- get pods -n default -l job-name=greenhouse-batch-2 --no-headers | awk '{print $1}'

  zombie_count=0

  for pod in $pods; do
    if is_zombie "$pod"; then
      log "Zombie detected: $pod"

      # minikube kubectl -- delete pod greenhouse-batch-2-42-fzv99 -n default --force --grace-period=0

      minikube kubectl -- patch pod "$pod" \
        -p '{"metadata":{"finalizers":[]}}' \
        --type=merge \
        >/dev/null 2>&1
        
      minikube kubectl -- delete pod "$pod" \
        -n "$NAMESPACE" \
        --force --grace-period=0 \
        >/dev/null 2>&1

      log "Deleted: $pod"
      ((zombie_count++))
    fi
  done

  if [[ $zombie_count -gt 0 ]]; then
    log "Cleaned $zombie_count zombie pods"
  fi

  sleep $INTERVAL
done