#!/bin/bash
REMOTE_HOST="192.168.0.5"
REMOTE_PATH="/home/cmy/share/k8"
LOCAL_PATH="/shared"
SSH_USER="cmy"
SSH_PWD="oPXGBnnF9n5Khi0h"


umount $LOCAL_PATH 2>/dev/null
mkdir -p $LOCAL_PATH

nohup sshpass -p $SSH_PWD sshfs ${SSH_USER}@${REMOTE_HOST}:${REMOTE_PATH} ${LOCAL_PATH} \
  -o allow_other \
  -o StrictHostKeyChecking=no &

# sshpass -p "oPXGBnnF9n5Khi0h" sshfs cmy@192.168.0.5:/data/cmy/share/k8 /shared -o allow_other -o StrictHostKeyChecking=no

sleep 5

if mount | grep "$LOCAL_PATH"; then
  echo "success"
else
  echo "fail"
  exit 1
fi