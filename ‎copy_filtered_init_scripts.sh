#!/bin/bash

# 源目录
SOURCE_DIR=$1

# 目标目录
TARGET_INIT_DIR="/gh/greenhouse_files/init_files"

# 检查源目录是否存在
if [ ! -d "$SOURCE_DIR" ]; then
    echo "错误: 源目录 $SOURCE_DIR 不存在"
    exit 1
fi

# 如果目标目录不存在，则创建它
if [ ! -d "$TARGET_INIT_DIR" ]; then
    mkdir -p "$TARGET_INIT_DIR"
fi

echo "开始处理文件复制..."

# 检查filtered_init_scripts文件夹
INIT_LLM_SCRIPT_PATH="$SOURCE_DIR/filtered_init_scripts.txt"
# 如果filtered_init_scripts.txt存在，则复制到目标目录
if [ -f "$INIT_LLM_SCRIPT_PATH" ]; then
    cp "$INIT_LLM_SCRIPT_PATH" "$TARGET_INIT_DIR/"
    # 读取filtered_init_scripts.txt中的每一行（相对路径），拼接源目录后复制到目标init目录
    while IFS= read -r line; do
        # 跳过空行
        [ -z "$line" ] && continue

        src_file="$SOURCE_DIR/$line"
        dst_file="$TARGET_INIT_DIR/$line"
        # 确保目标子目录存在
        mkdir -p "$(dirname "$dst_file")"
        if [ -f "$src_file" ]; then
            cp "$src_file" "$dst_file"
            echo "已复制 $src_file 到 $dst_file"
        else
            echo "警告: 源文件 $src_file 不存在，跳过复制"
        fi
    done < "$INIT_LLM_SCRIPT_PATH"
else
    echo "警告: $INIT_LLM_SCRIPT_PATH 不存在，跳过复制"
fi

# 复制 banned_cmds.txt（如果存在）
BANNED_CMDS_PATH="$SOURCE_DIR/banned_cmds.txt"
if [ -f "$BANNED_CMDS_PATH" ]; then
    cp "$BANNED_CMDS_PATH" "$TARGET_INIT_DIR/"
    echo "已复制 $BANNED_CMDS_PATH 到 $TARGET_INIT_DIR/"
fi

# 复制 gh_nvram 目录下的所有文件到目标目录
GH_NVRAM_DIR="$SOURCE_DIR/gh_nvram"
if [ -d "$GH_NVRAM_DIR" ]; then
    # 检查目录下是否有文件（包括隐藏文件）
    if [ -n "$(ls -A "$GH_NVRAM_DIR" 2>/dev/null)" ]; then
        mkdir -p "$TARGET_INIT_DIR/gh_nvram"
        cp -r "$GH_NVRAM_DIR"/* "$TARGET_INIT_DIR/gh_nvram" 2>/dev/null
        echo "已复制 $GH_NVRAM_DIR 下的文件到 $TARGET_INIT_DIR/gh_nvram"
    fi
fi
