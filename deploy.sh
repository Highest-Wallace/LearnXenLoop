#!/bin/bash

# 1. 检查是否提供了文件名参数
if [ -z "$1" ]; then
    echo "❌ 错误: 请指定要传输的文件名。"
    echo "用法: $0 <文件名>"
    exit 1
fi

FILE="$1"

# 2. 检查本地文件是否存在
if [ ! -f "$FILE" ]; then
    echo "❌ 错误: 文件 '$FILE' 不存在。"
    exit 1
fi

# 3. 定义目标服务器列表
SERVERS=(
    "csp@10.75.85.53"
    "csp@10.75.85.35"
)

# 目标路径
REMOTE_PATH="~/"

echo "========================================"
echo "开始将 '$FILE' 传输到目标服务器..."
echo "========================================"

# 4. 循环遍历服务器并执行 scp
for SERVER in "${SERVERS[@]}"; do
    echo -n "正在传输到 $SERVER ... "
    
    # 执行 scp 命令，抑制非错误输出 (-q)
    scp -q "$FILE" "$SERVER:$REMOTE_PATH"
    
    # 检查 scp 的退出状态码
    if [ $? -eq 0 ]; then
        echo "✅ [成功]"
    else
        echo "❌ [失败]"
    fi
done

echo "========================================"
echo "完成。"