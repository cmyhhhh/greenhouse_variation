#!/bin/bash

target_date="2026-03-31"

while true; do
    current_date=$(date +%Y-%m-%d)
    if [[ "$current_date" < "$target_date" ]]; then
        sudo date -s "2026-03-31 13:30:00"
    fi
    sleep 2
done

# minikube cp /greenhouse_variation/k8/check_date.sh /
# minikube cp /greenhouse_variation/k8/check_date.sh minikube-m02:/
# sudo chmod 777 /check_date.sh
# nohup sh /check_date.sh &
# ps -ef | grep check_date.sh
