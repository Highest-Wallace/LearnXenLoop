#!/bin/bash

# --- 配置区域 ---
MODE="DEBUG"        # "DEBUG" 或 "BENCHMARK"
IP_DOMU="10.75.85.53" 
PORT="6379"
# PASSWORD="your_password" 

# 临时文件
TMP_LOG="/tmp/redis_bench_raw.log"

# --- 检查 ---
if ! command -v redis-benchmark &> /dev/null; then
    echo "❌ 错误: 未找到 redis-benchmark。"
    exit 1
fi

# --- 模式定义 ---
if [ "$MODE" == "DEBUG" ]; then
    REQUESTS=10000
    CONCURRENCY_LEVELS=(1 50) 
    PAYLOAD_SIZES=(32) 
else
    REQUESTS=100000
    CONCURRENCY_LEVELS=(1 10 50 100)
    PAYLOAD_SIZES=(3 1024 4096)
fi

echo "====================================================="
echo "Redis 测试 (v8.x适配版): $HOSTNAME -> $IP_DOMU:$PORT"
echo "Redis版本: $(redis-benchmark --version | awk '{print $2}')"
echo "====================================================="

# 连接检查
timeout 1 bash -c "cat < /dev/null > /dev/tcp/$IP_DOMU/$PORT" 2> /dev/null
if [ $? -ne 0 ]; then
    echo "❌ 错误: 无法连接 $IP_DOMU:$PORT。"
    exit 1
fi

AUTH_PARAM=""
if [ ! -z "$PASSWORD" ]; then AUTH_PARAM="-a $PASSWORD"; fi

print_header() {
    # 调整列宽以适应高精度显示
    printf "%-10s | %-12s | %-8s | %-15s | %-15s | %-15s\n" "Config" "Type" "Concur" "QPS" "P99 Lat(ms)" "Avg Lat(ms)"
    echo "----------------------------------------------------------------------------------------"
}

print_header

# --- 主循环 ---
for SIZE in "${PAYLOAD_SIZES[@]}"
do
    for CONCUR in "${CONCURRENCY_LEVELS[@]}"
    do 
        CONFIG_STR="D:${SIZE}B"
        
        run_bench() {
            TYPE=$1
            # 运行测试
            # 8.0+ 的输出默认包含 Summary 块
            redis-benchmark -h $IP_DOMU -p $PORT $AUTH_PARAM -t $TYPE -c $CONCUR -d $SIZE -n $REQUESTS > "$TMP_LOG" 2>&1
            
            # --- 解析逻辑 (针对 Redis 8.0.5 Summary 块) ---
            
            # 1. 解析吞吐量 (throughput summary: 7751.94 requests per second)
            # 取第三列
            QPS=$(grep "throughput summary" "$TMP_LOG" | awk '{print $3}')
            
            # 2. 解析延迟 (latency summary)
            # 结构如下：
            # latency summary (msec):
            #       avg       min       p50       p95       p99       max
            #     0.104     0.088     0.103     0.111     0.119     2.359
            
            # 使用 awk 找到 "latency summary"，然后读取下下行 (header下一行是数据)
            # 注意：实际输出中，header 和数据紧挨着，还是隔了一行？
            # 根据你提供的输出：header下一行就是数据。
            # "latency summary (msec):" 是特征行
            # 下一行包含: avg min p50 p95 p99 max
            # 所以我们要取第 5 列 (p99) 和 第 1 列 (avg)
            
            LATENCY_DATA=$(awk '/latency summary \(msec\):/{getline; getline; print $1, $5}' "$TMP_LOG")
            AVG_LAT=$(echo $LATENCY_DATA | awk '{print $1}')
            P99_LAT=$(echo $LATENCY_DATA | awk '{print $2}')
            
            # 兜底：如果解析失败（比如版本不匹配），回退到旧逻辑或显示 -
            if [ -z "$P99_LAT" ]; then 
                 # 尝试只读下一行（针对某些格式变体）
                 LATENCY_DATA=$(awk '/latency summary \(msec\):/{getline; print $1, $5}' "$TMP_LOG")
                 AVG_LAT=$(echo $LATENCY_DATA | awk '{print $1}')
                 P99_LAT=$(echo $LATENCY_DATA | awk '{print $2}')
            fi
            
            if [ -z "$QPS" ]; then QPS="-"; fi
            if [ -z "$P99_LAT" ]; then P99_LAT="-"; fi

            printf "%-10s | %-12s | %-8s | %-15s | %-15s | %-15s\n" "$CONFIG_STR" "${TYPE^^}" "$CONCUR" "${QPS}" "${P99_LAT}" "${AVG_LAT}"
        }

        run_bench "set"
        run_bench "get"

    done
    echo "----------------------------------------------------------------------------------------"
done

rm -f "$TMP_LOG"
echo
echo "测试完成。"