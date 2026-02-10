#!/bin/bash

# --- 配置区域 ---
MODE="BENCHMARK"        # 修改这里切换模式: "DEBUG" 或 "BENCHMARK"
IP_DOMU="10.177.21.218" 

if [ "$MODE" == "DEBUG" ]; then
    TIME="5"
    REPEATS=1
    MESSAGE_SIZES=(64 1024 65500) 
else
    TIME="20"
    REPEATS=3
    MESSAGE_SIZES=(64 128 256 512 1024 2048 4096 8192 16384 32768 65500)
fi

# --- 脚本前言 ---
echo "====================================================="
echo "测试主机: $HOSTNAME -> 目标: $IP_DOMU"
echo "模式: $MODE | 时长: ${TIME}s | 轮次: $REPEATS"
echo "====================================================="

# 检查网络连接
ping -4 -c 2 -W 1 $IP_DOMU > /dev/null
if [ $? -ne 0 ]; then
    echo "❌ 错误: 无法 ping 通 $IP_DOMU。"
    exit 1
fi

print_header() {
    printf "%-10s | %-12s | %-8s | %-15s | %-15s\n" "Size(B)" "Type" "Run" "Throughput/Rate" "Latency(us)"
    echo "------------------------------------------------------------------------"
}

print_header

# --- 主循环 ---
for SIZE in "${MESSAGE_SIZES[@]}"
do
    for (( i=1; i<=REPEATS; i++ ))
    do 
        # ===========================================================
        # 1. TCP_STREAM 
        # 策略: 保持 -o THROUGHPUT，这在之前的测试中已被验证是可靠的
        # ===========================================================
        RES_TCP_TP=$(netperf -4 -H $IP_DOMU -l $TIME -t TCP_STREAM -P 0 -- -m $SIZE -o THROUGHPUT | head -n 1 | tr -d '\r')
        printf "%-10s | %-12s | %-8s | %-15s | %-15s\n" "$SIZE" "TCP_STREAM" "#$i" "${RES_TCP_TP} Mbps" "-"

        # ===========================================================
        # 2. TCP_RR (根据分析结果校正)
        # 策略: 抓取第1行 (head -n 1)，抓取第6列 ($6)
        # ===========================================================
        TCP_RR_RAW=$(netperf -4 -H $IP_DOMU -l $TIME -t TCP_RR -P 0 -- -r ${SIZE},${SIZE} | head -n 1 | tr -d '\r')
        TCP_TPS=$(echo $TCP_RR_RAW | awk '{print $6}') 
        
        # 计算延迟: 1,000,000 / TPS
        # 使用 bc 进行高精度计算
        if [[ ! -z "$TCP_TPS" ]] && (( $(echo "$TCP_TPS > 0" | bc -l) )); then
            TCP_LAT=$(echo "scale=2; 1000000 / $TCP_TPS" | bc)
        else
            TCP_LAT="-"
        fi
        printf "%-10s | %-12s | %-8s | %-15s | %-15s\n" "$SIZE" "TCP_RR" "#$i" "${TCP_TPS} TPS" "${TCP_LAT}"

        # ===========================================================
        # 3. UDP_STREAM
        # ===========================================================
        RES_UDP_TP=$(netperf -4 -H $IP_DOMU -l $TIME -t UDP_STREAM -P 0 -- -m $SIZE -o THROUGHPUT | head -n 1 | tr -d '\r')
        printf "%-10s | %-12s | %-8s | %-15s | %-15s\n" "$SIZE" "UDP_STREAM" "#$i" "${RES_UDP_TP} Mbps" "-"

        # ===========================================================
        # 4. UDP_RR (根据分析结果校正)
        # 策略: 抓取第1行 (head -n 1)，抓取第6列 ($6)
        # ===========================================================
        UDP_RR_RAW=$(netperf -4 -H $IP_DOMU -l $TIME -t UDP_RR -P 0 -- -r ${SIZE},${SIZE} | head -n 1 | tr -d '\r')
        UDP_TPS=$(echo $UDP_RR_RAW | awk '{print $6}')
        
        if [[ ! -z "$UDP_TPS" ]] && (( $(echo "$UDP_TPS > 0" | bc -l) )); then
            UDP_LAT=$(echo "scale=2; 1000000 / $UDP_TPS" | bc)
        else
            UDP_LAT="-"
        fi
        printf "%-10s | %-12s | %-8s | %-15s | %-15s\n" "$SIZE" "UDP_RR" "#$i" "${UDP_TPS} TPS" "${UDP_LAT}"
    done
    
    if [ "$REPEATS" -gt 1 ]; then echo "------------------------------------------------------------------------"; fi
done

echo
echo "所有测试已完成。"