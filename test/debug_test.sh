#!/bin/bash

# 简化的测试脚本，用于调试XenLoop连接问题

echo "=== XenLoop Connection Debug Test ==="
echo "Host: $(hostname)"
echo "Time: $(date)"
echo ""

# 检查模块是否已加载
if lsmod | grep -q xenloop; then
    echo "✓ XenLoop module is loaded"
else
    echo "✗ XenLoop module is NOT loaded"
    echo "Please load with: sudo insmod xenloop.ko nic=eth0"
    exit 1
fi

# 显示当前连接状态
echo ""
echo "=== Current Network Interfaces ==="
ip addr show | grep -E "^[0-9]+:|inet "
echo ""
echo "=== XenLoop Kernel Messages (last 20 lines) ==="
dmesg | grep -E "(xenloop|xf_|bf_)" | tail -20

echo ""
echo "=== Testing Connectivity ==="

# 设置测试目标
if [ "$(hostname)" = "dom1" ]; then
    TARGET_IP="10.12.134.101"  # dom2
    echo "Testing connection from dom1 to dom2 ($TARGET_IP)"
elif [ "$(hostname)" = "dom2" ]; then
    TARGET_IP="10.12.134.100"  # dom1 (假设是这个IP)
    echo "Testing connection from dom2 to dom1 ($TARGET_IP)"
else
    TARGET_IP="10.12.134.100"
    echo "Unknown host, testing to $TARGET_IP"
fi

echo ""
echo "Sending 3 ping packets to trigger ARP and connection setup..."
ping -c 3 -W 2 $TARGET_IP

echo ""
echo "=== Post-Ping Kernel Messages ==="
dmesg | grep -E "(xenloop|xf_|bf_|ERROR|DEBUG)" | tail -10

echo ""
echo "=== Test Complete ==="
