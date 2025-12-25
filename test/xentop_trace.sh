IP_DOM1="10.75.85.53"
IP_DOM2="10.75.85.35"

# 1. 启动 xentrace，后台运行或设定时间
echo "Starting trace..."
sudo xentrace -D -e all -T 60 trace.bin &  # 让它在后台运行60秒
TRACE_PID=$!

# 2. 稍微等一下，确保 trace 已经开始
sleep 2

# 3. 触发远程 DomU 的测试
ssh csp@$IP_DOM2 "netperf -H $IP_DOM1 -l 50" # 测试运行50秒
# netperf -H 10.75.85.53 -l 50

# 4. 等待 xentrace 自己结束
wait $TRACE_PID
echo "Trace finished."

# 5. 分析
sudo xenalyze --summary trace.bin > result_summary.txt