#!/bin/bash

# --- 配置 ---
TIME="30" # 每个测试运行的持续时间（秒）
IP_DOMU="127.0.0.1" # 运行 netserver 的远程 domU 的 IP 地址
# 要测试的消息大小列表（单位：字节）
MESSAGE_SIZES=(64 128 256 512 1024 2048 4096 8192 16384 32768 65500)

# --- 脚本前言 ---
echo "正在 $HOSTNAME 上开始性能测试"
echo "远程 domU IP: $IP_DOMU"
echo "每次运行的测试时长: ${TIME}s"
echo

echo "正在 ping 远程 domU 以建立连接..."
ping -4 -c 3 $IP_DOMU
echo

# --- 主测试循环 ---
echo "=== 开始运行随消息大小变化的性能测试 ==="
echo

# 循环遍历每种消息大小
for SIZE in "${MESSAGE_SIZES[@]}"
do
    echo "-----------------------------------------------------"
    echo "--- 正在测试，消息大小: ${SIZE} 字节 ---"
    echo "-----------------------------------------------------"
    echo

    for R in {1..5}
    do 
        # --- TCP 测试 ---
        echo "==> TCP 测试 (大小: ${SIZE}B)"
        # TCP 吞吐量测试 (TCP_STREAM)
        echo "TCP 吞吐量 (TCP_STREAM)"
        netperf -4 -H $IP_DOMU -l $TIME -t TCP_STREAM -- -m $SIZE -o throughput
        echo

        # TCP 事务处理速率测试 (TCP_RR)
        echo "TCP 事务处理速率 (TCP_RR)"
        netperf -4 -H $IP_DOMU -l $TIME -t TCP_RR -- -r ${SIZE},${SIZE} -o transaction_rate,mean_latency
        echo

        # --- UDP 测试 ---
        echo "==> UDP 测试 (大小: ${SIZE}B)"
        # UDP 吞吐量测试 (UDP_STREAM)
        echo "UDP 吞吐量 (UDP_STREAM)"
        netperf -4 -H $IP_DOMU -l $TIME -t UDP_STREAM -- -m $SIZE -o throughput
        echo

        # UDP 事务处理速率测试 (UDP_RR)
        echo "UDP 事务处理速率 (UDP_RR)"
        netperf -4 -H $IP_DOMU -l $TIME -t UDP_RR -- -r ${SIZE},${SIZE} -o transaction_rate,mean_latency
        echo
    done
done

echo "====================================================="
echo "所有测试已完成。"