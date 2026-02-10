#!/bin/bash

# ================= 配置区 =================
IP_DOM1="10.177.21.218"  # 接收端 IP
IP_DOM2="10.177.21.36"   # 发送端 IP
LOG_FILE="xentop_log_custom.txt" # xentop 输出的文件名
DURATION=20              # Netperf 测试时长
# =========================================

# 1. 清理旧日志
rm -f "$LOG_FILE"

echo "==========================================="
echo "开始纯 xentop 监控测试..."
echo "结果将保存至: $LOG_FILE"
echo "==========================================="

# 2. 启动 xentop 监控
# -b: 批处理模式 (必须，否则 Python 脚本无法解析)
# -d 1: 采样间隔 1秒
# -i 30: 运行次数。设置为 30 次足以覆盖 5s 等待 + 20s 测试 + 缓冲时间
echo "[1/3] 启动 xentop 后台监控..."
sudo xentop -b -d 1 -i 30 > "$LOG_FILE" &
XENTOP_PID=$!

# 3. 等待基准线 (Baseline)
# 先空跑 5 秒，让图表左侧有一段平稳的“低负载”直线，便于对比
echo "[2/3] 等待 5秒采集基准数据..."
sleep 5

# 4. 触发远程 DomU 的负载 (Netperf)
echo "[3/3] 开始 Netperf 压力测试 (Dom2 -> Dom1, ${DURATION}秒)..."
# 注意：SSH 命令会阻塞直到 netperf 跑完
ssh csp@$IP_DOM2 "netperf -H $IP_DOM1 -l $DURATION"

echo ">>> Netperf 测试结束 <<<"

# 5. 等待 xentop 自动结束
# 因为我们指定了 -i 30，xentop 会在采集完 30 次后自动退出
echo "等待 xentop 数据写入完成..."
wait $XENTOP_PID

echo "==========================================="
echo "测试完成！"
echo "请使用以下命令绘图："
echo "python3 plot_xentop.py" 
echo "注意：请先修改 plot_xentop.py 中的文件名: parse_xentop_log('$LOG_FILE')"
echo "==========================================="