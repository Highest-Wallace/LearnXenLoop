/*
 *  XenLoop -- A High Performance Inter-VM Network Loopback
 *
 *  Installation and Usage instructions
 *
 *  Authors:
 *  	Jian Wang - Binghamton University (jianwang@cs.binghamton.edu)
 *  	Kartik Gopalan - Binghamton University (kartik@cs.binghamton.edu)
 *
 *  Copyright (C) 2007-2009 Kartik Gopalan, Jian Wang
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <linux/genhd.h>
#include <linux/if_ether.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/ip.h>

#include <asm/xen/hypercall.h>
#include <xen/events.h>
#include <xen/grant_table.h>

#include "bififo.h"
#include "debug.h"
#include "maptable.h"
#include "xenfifo.h"

// 外部变量声明
extern HashTable mac_domid_map; // MAC地址到域ID的哈希映射表
extern wait_queue_head_t swq;   // 等待队列，用于在特定条件下唤醒进程
extern struct net_device *NIC;  // 网络接口控制器设备
extern Entry *lookup_bfh(HashTable *, void *); // 在哈希表中查找条目的函数
extern int tx_mode;
extern int rx_mode;
extern int batch_pkt_threshold;
extern int batch_time_threshold;

void bf_wakeup_tasklet_func(struct tasklet_struct *t);
DECLARE_TASKLET(bf_wakeup_tasklet, bf_wakeup_tasklet_func);

void bf_wakeup_tasklet_func(struct tasklet_struct *t) {
	wake_up_interruptible(&swq);
}

/**
 * @brief 向指定的事件通道端口发送一个通知。
 * @param port 目标事件通道端口。
 */
void bf_notify(uint32_t port) {
	struct evtchn_send op;
	int ret;

	TRACE_ENTRY;

	memset(&op, 0, sizeof(op));
	op.port = port;

	// 通过 hypercall 发送事件通道操作
	ret = HYPERVISOR_event_channel_op(EVTCHNOP_send, &op);
	if (ret != 0) {
		EPRINTK("Unable to signal on event channel\n");
		goto out;
	}

	TRACE_EXIT;
	return;

out:
	TRACE_ERROR;
}

/**
 * @brief 从 FIFO 复制一个可能跨越多个数据块的大数据包到 sk_buff 中。
 * @param mdata 指向包含数据包信息的元数据。
 * @param skb 指向目标 sk_buff 的指针。
 * @param xfh 指向源 FIFO 句柄的指针。
 */
static inline void copy_large_pkt(bf_data_t *mdata, struct sk_buff *skb,
                                  xf_handle_t *xfh) {
	char *pback, *pfront, *pfifo;
	int num_entries, len, len1, len2, pkt_len;

	TRACE_ENTRY;

	// 为 skb 预留以太网头和一些额外空间，然后放入数据
	skb_reserve(skb, 2 + ETH_HLEN);
	skb_put(skb, mdata->pkt_info);

	pkt_len = mdata->pkt_info;
	// 计算数据包占用的 FIFO 条目数
	num_entries = pkt_len / sizeof(bf_data_t);
	if (pkt_len % sizeof(bf_data_t))
		num_entries++;

	pfifo = (char *)xfh->fifo;
	// 获取数据包的起始和结束位置指针
	pfront = (char *)xf_entry(xfh, bf_data_t, 1);
	pback = (char *)xf_entry(xfh, bf_data_t, num_entries);

	BUG_ON(!pfifo);
	BUG_ON(!pfront);
	BUG_ON(!pback);

	// 检查数据是否环绕
	if (pback >= pfront) {
		// 数据是连续的，直接复制
		memcpy(skb->data, pfront, pkt_len);
	} else {
		// 数据是环绕的，需要分两次复制
		len1 = (pfifo + xfh->descriptor->max_data_entries * sizeof(bf_data_t)) -
		       pfront;
		len = (len1 >= pkt_len) ? pkt_len : len1;
		memcpy(skb->data, pfront, len);

		len2 = pkt_len - len;
		if (len2 > 0) {
			memcpy(skb->data + len, pfifo, len2);
		}
	}

	// 设置 skb 的网络层相关信息
	skb->mac_header = (__u16)(skb->data - skb->head) + ETH_HLEN;
	skb->ip_summed = CHECKSUM_UNNECESSARY; // 内部通信，无需校验和
	skb->pkt_type = PACKET_HOST;
	skb->protocol = htons(ETH_P_IP);
	skb->dev = NIC;
	skb_shinfo(skb)->nr_frags = 0;
	skb_shinfo(skb)->frag_list = NULL;
	skb_shinfo(skb)->frags[0].bv_page = NULL;

	TRACE_EXIT;
}

/**
 * @brief 从 FIFO 中复制一个完整的数据包到新分配的 sk_buff 中。
 * @param xfh 指向 FIFO 句柄的指针。
 * @return 成功则返回包含数据包的 sk_buff，失败则返回 NULL。
 */
static inline struct sk_buff *copy_packet(xf_handle_t *xfh) {
	struct sk_buff *skb = NULL;
	bf_data_t *data;
	int n, ret;

	TRACE_ENTRY;

	/*
	 * 读内存屏障：确保在读取任何数据之前，我们已经看到了生产者
	 * 对 back 指针的最新更新。这是无锁实现的关键。
	 */
	rmb();

	// 检查队列是否真的有数据
	if (xf_empty(xfh)) {
		goto out;
	}

	// 获取 FIFO 头部的元数据
	data = xf_front(xfh, bf_data_t);
	BUG_ON(!data);

	// 分配 skb
	skb = alloc_skb(data->pkt_info + 2 + ETH_HLEN, GFP_ATOMIC);
	if (!skb) {
		DB("Cannot allocate skb for size %d\n", data->pkt_info + 2 + ETH_HLEN);
		goto out;
	}

	// 复制数据包内容
	copy_large_pkt(data, skb, xfh);

	// 计算数据包占用的 FIFO 条目数并弹出
	n = data->pkt_info / sizeof(bf_data_t) + 1;
	if (data->pkt_info % sizeof(bf_data_t))
		n++;

	ret = xf_popn(xfh, n);
	BUG_ON(ret < 0);

out:
	TRACE_EXIT;
	return skb;
}

/**
 * @brief 从给定的双向 FIFO 句柄的输入队列中接收所有数据包。
 * @param bfh 指向双向 FIFO 句柄的指针。
 */
void recv_packets(bf_handle_t *bfh) {
	static DEFINE_SPINLOCK(recv_lock);
	struct sk_buff *skb;
	unsigned long flags;

	TRACE_ENTRY;

	spin_lock_irqsave(&recv_lock, flags);

	// 循环直到输入 FIFO 为空
	while (!xf_empty(bfh->in)) {

		skb = copy_packet(bfh->in);
		if (!skb)
			break;

		spin_unlock_irqrestore(&recv_lock, flags);

		// DPRINTK("packet received through xenlcnh\n");
		// 将接收到的包交给网络协议栈处理
		netif_rx(skb);

		// TODO: 如果能直接调用 ip_local_deliver 或 ip_rcv 会更好，
		//       但可惜这些符号没有导出到内核模块中。
		// ip_local_deliver(skb);

		spin_lock_irqsave(&recv_lock, flags);
	}

	spin_unlock_irqrestore(&recv_lock, flags);

	TRACE_EXIT;
}

/**
 * @brief 批处理定时器回调函数
 */
static void bf_batch_timer_callback(struct timer_list *t) {
	bf_handle_t *bfh = container_of(t, bf_handle_t, batch_timer);
	unsigned long flags;
	int pending;

	spin_lock_irqsave(&bfh->tx_lock, flags);

	pending = atomic_read(&bfh->tx_stats.pending_pkts);

	// 如果有待发送的数据包，立即通知
	if (pending > 0) {
		spin_unlock_irqrestore(&bfh->tx_lock, flags);

		bf_notify(bfh->port);

		spin_lock_irqsave(&bfh->tx_lock, flags);
		atomic_set(&bfh->tx_stats.pending_pkts, 0);
		bfh->tx_stats.last_notify_time = jiffies;
		atomic_inc(&bfh->tx_stats.batch_notify_count);
	}

	spin_unlock_irqrestore(&bfh->tx_lock, flags);
}

/**
 * @brief 智能批处理通知函数
 * @param bfh FIFO句柄
 * @param pkt_size 当前数据包大小
 * @return 是否发送了通知
 */
int bf_notify_smart(bf_handle_t *bfh, unsigned int pkt_size) {
	unsigned long flags;
	int pending;
	unsigned long time_elapsed;
	int should_notify = 0;

	if (!bfh) {
		return 0;
	}

	// 安全检查：如果模块正在卸载，不要使用定时器
	extern u8 freezed;
	if (freezed) {
		// 直接发送通知，不使用批处理
		bf_notify(bfh->port);
		return 1;
	}

	spin_lock_irqsave(&bfh->tx_lock, flags);

	// 更新统计
	pending = atomic_inc_return(&bfh->tx_stats.pending_pkts);
	bfh->tx_stats.tx_packets++;
	bfh->tx_stats.tx_bytes += pkt_size;

	time_elapsed = jiffies - bfh->tx_stats.last_notify_time;

	switch (bfh->tx_notify_mode) {
	case BF_NOTIFY_MODE_IMMEDIATE:
		// 立即通知模式（原有行为）
		should_notify = 1;
		break;

	case BF_NOTIFY_MODE_BATCH_COUNT:
		// 基于数量的批处理
		if (pending >= bfh->batch_pkt_threshold) {
			should_notify = 1;
		}
		break;

	case BF_NOTIFY_MODE_BATCH_TIME:
		// 基于时间的批处理
		if (time_elapsed >= usecs_to_jiffies(bfh->batch_time_threshold)) {
			should_notify = 1;
		} else if (pending == 1) {
			// 第一个包，启动定时器（如果还没运行）
			if (!timer_pending(&bfh->batch_timer)) {
				mod_timer(&bfh->batch_timer,
				          jiffies +
				              usecs_to_jiffies(bfh->batch_time_threshold));
			}
		}
		break;

	case BF_NOTIFY_MODE_ADAPTIVE:
		// 自适应模式：结合数量和时间
		// 1. 大包 (>= 1024) 立即发送，提高吞吐量
		// 2. 极小包 (< 128, 如 TCP ACKs) 立即发送，降低延迟
		if (pkt_size >= 1024 || pkt_size < 128) {
			should_notify = 1;
		} else if (pending >= bfh->batch_pkt_threshold) {
			should_notify = 1;
		} else if (time_elapsed >=
		           usecs_to_jiffies(bfh->batch_time_threshold)) {
			should_notify = 1;
		} else if (pending == 1) {
			if (!timer_pending(&bfh->batch_timer)) {
				mod_timer(&bfh->batch_timer,
				          jiffies +
				              usecs_to_jiffies(bfh->batch_time_threshold));
			}
		}
	}

	if (should_notify) {
		// 先解锁，再发送通知（避免在持锁状态下hypercall）
		spin_unlock_irqrestore(&bfh->tx_lock, flags);

		bf_notify(bfh->port);

		spin_lock_irqsave(&bfh->tx_lock, flags);
		atomic_set(&bfh->tx_stats.pending_pkts, 0);
		bfh->tx_stats.last_notify_time = jiffies;

		if (bfh->tx_notify_mode == BF_NOTIFY_MODE_IMMEDIATE) {
			atomic_inc(&bfh->tx_stats.immediate_notify_count);
		} else {
			atomic_inc(&bfh->tx_stats.batch_notify_count);
		}

		// 取消定时器
		if (timer_pending(&bfh->batch_timer)) {
			del_timer(&bfh->batch_timer);
		}
	}

	spin_unlock_irqrestore(&bfh->tx_lock, flags);

	atomic_inc(&bfh->tx_stats.notify_count);
	return should_notify;
}

/**
 * @brief 接收端轮询处理函数（类似NAPI的poll）
 * @param bfh FIFO句柄
 * @param quota 本次最多处理的包数
 * @return 实际处理的包数
 */
int bf_poll_rx(bf_handle_t *bfh, int quota) {
	struct sk_buff *skb;
	int work_done = 0;

	// 设置一个较大的硬限制，防止死循环，但要远大于默认 quota 以清空积压
	int hard_limit = 512;

	TRACE_ENTRY;

	// 处理FIFO中的数据包，但不超过quota
	while (work_done < hard_limit && !xf_empty(bfh->in)) {
		skb = copy_packet(bfh->in);
		if (!skb) {
			break;
		}

		// 更新统计
		atomic_inc(&bfh->rx_poll.rx_packets);
		atomic_add(skb->len, &bfh->rx_poll.rx_bytes);
		bfh->rx_poll.last_rx_time = jiffies;

		netif_rx(skb);
		work_done++;
	}

	// 修复：无论是否处理完所有包，都必须清除轮询标志，
	// 否则如果 FIFO 未空但达到 quota，标志位将卡在 1，导致后续中断被忽略。
	atomic_set(&bfh->rx_poll.polling, 0);

	// // 如果处理完所有包，清除轮询标志
	// if (xf_empty(bfh->in)) {
	// 	atomic_set(&bfh->rx_poll.polling, 0);
	// }

	TRACE_EXIT;
	return work_done;
}

/**
 * @brief 事件通道中断回调函数 (IRQ handler)。
 *        当远程域通过事件通道发送通知时，此函数被调用。
 * @param rq IRQ 号。
 * @param dev_id 传递给中断处理程序的设备 ID (这里是 bf_handle_t *)。
 * @return IRQ_HANDLED 表示中断已处理。
 */
irqreturn_t bf_callback(int rq, void *dev_id) {
	bf_handle_t *bfh = (bf_handle_t *)dev_id;

	TRACE_ENTRY;

	BUG_ON(!check_descriptor(bfh));

	// 检查 FIFO 是否被挂起 (例如，在虚拟机迁移期间)
	if (BF_SUSPEND_IN(bfh) || BF_SUSPEND_OUT(bfh)) {
		Entry *e = lookup_bfh(&mac_domid_map, bfh);
		BUG_ON(!e);

		// 设置状态为挂起并唤醒等待队列
		e->status = XENLCNH_STATUS_SUSPEND;

		// wake_up_interruptible(&swq);
		// 使用 tasklet 在安全上下文中唤醒线程
		tasklet_schedule(&bf_wakeup_tasklet);

		TRACE_EXIT;
		return IRQ_HANDLED;
	}

	if (bfh->rx_mode == BF_RX_MODE_POLLING) {
		// 轮询模式：设置标志并处理有限数量的包
		if (atomic_cmpxchg(&bfh->rx_poll.polling, 0, 1) == 0) {
			// 成功设置轮询标志，开始处理
			bf_poll_rx(bfh, BF_POLLING_QUOTA);
		}
		// 如果已经在轮询中，忽略这次中断
	} else {
		// 中断模式：直接处理所有包（原有行为）
		recv_packets(bfh);
	}

	TRACE_EXIT;
	return IRQ_HANDLED;
}

/**
 * @brief 释放事件通道资源。
 * @param port 事件通道端口。
 * @param irq 绑定的 IRQ。
 * @param dev_id 设备 ID。
 */
void free_evtch(uint32_t port, int irq, void *dev_id) {
	struct evtchn_close op;
	int ret;

	TRACE_ENTRY;

	if (irq) {
		unbind_from_irqhandler(irq, dev_id);
		DPRINTK("free port: %d\n", port);
	}

	if (port) {
		memset(&op, 0, sizeof(op));
		DPRINTK("free port: %u\n", port);
		op.port = port;
		ret = HYPERVISOR_event_channel_op(EVTCHNOP_close, &op);
		if (ret) {
			if (ret == -EINVAL) {
				DPRINTK("Event channel %d was already closed\n", port);
			} else {
				EPRINTK("Unable to cleanly close event channel, err: %d\n",
				        ret);
			}
		} else {
			DPRINTK("Successfully closed event channel %d\n", port);
		}
	}

	TRACE_EXIT;
}

/**
 * @brief 为监听端创建一个未绑定的事件通道。
 * @param rdomid 远程域 ID。
 * @param port [输出] 创建的本地事件通道端口。
 * @param irq [输出] 绑定到该端口的 IRQ。
 * @param arg 传递给 IRQ 处理程序的回调参数。
 * @return 成功返回 0，失败返回 -1。
 */
int create_evtch(domid_t rdomid, uint32_t *port, int *irq, void *arg) {
	struct evtchn_alloc_unbound op;
	int ret;

	TRACE_ENTRY;

	if (!irq || !port)
		BUG();

	// 分配一个未绑定的事件通道，用于监听来自 rdomid 的连接
	memset(&op, 0, sizeof(op));
	op.dom = DOMID_SELF;
	op.remote_dom = rdomid;

	ret = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound, &op);
	if (ret != 0) {
		EPRINTK("Unable to allocate event channel\n");
		goto out;
	}
	*port = op.port;

	// 将分配的端口绑定到一个 IRQ 处理程序
	ret = bind_evtchn_to_irqhandler(op.port, bf_callback, SA_RESTART,
	                                "bf_listener", arg);
	if (ret <= 0) {
		EPRINTK("Failed to bind irq to port %d\n", op.port);
		goto out1;
	}

	*irq = ret;
	DB("unbound port = %u irq = %d\n", *port, *irq);

	TRACE_EXIT;
	return 0;

out1:
	free_evtch(*port, *irq, arg);
out:
	TRACE_ERROR;
	return -1;
}

/**
 * @brief 销毁一个监听端的双向 FIFO 句柄及其所有资源。
 * @param bfl 指向要销毁的 bf_handle_t 的指针。
 */
void bf_destroy(bf_handle_t *bfl) {
	TRACE_ENTRY;

	if (!bfl) {
		EPRINTK("bfl = NULL\n");
		goto err;
	}

	// 1. 首先停止定时器（关键：必须在最开始）
	// 使用 del_timer_sync 确保定时器回调完全停止
	if (bfl->tx_notify_mode == BF_NOTIFY_MODE_BATCH_TIME ||
	    bfl->tx_notify_mode == BF_NOTIFY_MODE_ADAPTIVE) {
		// 先尝试删除定时器
		if (timer_pending(&bfl->batch_timer)) {
			DPRINTK("Stopping pending batch timer\n");
			del_timer_sync(&bfl->batch_timer);
		}
	}

	// 2. 强制发送所有待处理的通知
	if (atomic_read(&bfl->tx_stats.pending_pkts) > 0) {
		DPRINTK("Flushing %d pending packets\n",
		        atomic_read(&bfl->tx_stats.pending_pkts));
		bf_notify(bfl->port);
		atomic_set(&bfl->tx_stats.pending_pkts, 0);
	}

	// 3. 等待一小段时间，确保远端处理完成
	msleep(10);

	// 4. 释放事件通道
	free_evtch(bfl->port, bfl->irq, (void *)bfl);

	// 5. 销毁输入和输出 FIFO
	if (bfl->in) {
		xf_destroy(bfl->in);
		bfl->in = NULL; // 防止重复释放
	}

	if (bfl->out) {
		xf_destroy(bfl->out);
		bfl->out = NULL; // 防止重复释放
	}

	// 6. 最后释放句柄本身
	kfree(bfl);

	TRACE_EXIT;
	return;
err:
	TRACE_ERROR;
}

/**
 * @brief (监听端) 创建一个双向 FIFO。
 *        这包括创建两个单向 FIFO (in 和 out) 和一个事件通道。
 * @param rdomid 准备接受连接的远程域 ID。
 * @param entry_order FIFO 的容量 (2 的幂)。
 * @return 成功则返回 bf_handle_t 指针，失败则返回 NULL。
 */
bf_handle_t *bf_create(domid_t rdomid, int entry_order) {
	bf_handle_t *bfl = NULL;
	int ret;
	TRACE_ENTRY;

	// 分配 bf_handle_t 结构体内存
	bfl = (bf_handle_t *)kmalloc(sizeof(bf_handle_t), GFP_KERNEL);
	if (!bfl) {
		EPRINTK("Can't allocate bfl\n");
		goto err;
	}

	memset(bfl, 0, sizeof(bf_handle_t));

	// 初始化批处理相关字段 - 默认使用立即模式，避免初期问题
	bfl->tx_notify_mode = tx_mode;
	bfl->rx_mode = rx_mode;
	bfl->batch_pkt_threshold = batch_pkt_threshold;
	bfl->batch_time_threshold = batch_time_threshold;

	// 参数验证
	if (bfl->tx_notify_mode < BF_NOTIFY_MODE_IMMEDIATE ||
	    bfl->tx_notify_mode > BF_NOTIFY_MODE_ADAPTIVE) {
		EPRINTK("Invalid tx_mode %d, using immediate mode\n", tx_mode);
		bfl->tx_notify_mode = BF_NOTIFY_MODE_IMMEDIATE;
	}

	if (bfl->rx_mode < BF_RX_MODE_INTERRUPT ||
	    bfl->rx_mode > BF_RX_MODE_POLLING) {
		EPRINTK("Invalid rx_mode %d, using interrupt mode\n", rx_mode);
		bfl->rx_mode = BF_RX_MODE_INTERRUPT;
	}

	// 输出当前配置（便于调试）
	DPRINTK("Creating FIFO with tx_mode=%d, rx_mode=%d, pkt_thresh=%d, "
	        "time_thresh=%d\n",
	        bfl->tx_notify_mode, bfl->rx_mode, bfl->batch_pkt_threshold,
	        bfl->batch_time_threshold);

	spin_lock_init(&bfl->tx_lock);
	spin_lock_init(&bfl->rx_lock);

	// 初始化统计
	atomic_set(&bfl->tx_stats.pending_pkts, 0);
	atomic_set(&bfl->tx_stats.notify_count, 0);
	atomic_set(&bfl->tx_stats.batch_notify_count, 0);
	atomic_set(&bfl->tx_stats.immediate_notify_count, 0);
	bfl->tx_stats.last_notify_time = jiffies;

	atomic_set(&bfl->rx_poll.polling, 0);
	atomic_set(&bfl->rx_poll.rx_packets, 0);
	atomic_set(&bfl->rx_poll.rx_bytes, 0);
	bfl->rx_poll.irq_enabled = 1;

	// 只有在需要批处理时才初始化定时器
	if (bfl->tx_notify_mode == BF_NOTIFY_MODE_BATCH_TIME ||
	    bfl->tx_notify_mode == BF_NOTIFY_MODE_ADAPTIVE) {
		timer_setup(&bfl->batch_timer, bf_batch_timer_callback, 0);
	}

	bfl->remote_domid = rdomid;
	// 创建输出和输入 FIFO
	bfl->out = xf_create(rdomid, sizeof(bf_data_t), entry_order);
	bfl->in = xf_create(rdomid, sizeof(bf_data_t), entry_order);
	if (!bfl->out || !bfl->in) {
		EPRINTK("Can't allocate bfl->in %p or bfl->out %p\n", bfl->in,
		        bfl->out);
		goto err;
	}

	// 创建事件通道用于接收通知
	ret = create_evtch(rdomid, &bfl->port, &bfl->irq, (void *)bfl);
	if (ret < 0) {
		EPRINTK("Can't allocate event channel\n");
		goto err;
	}

	TRACE_EXIT;
	return bfl;

err:
	// 错误处理：销毁已创建的资源
	bf_destroy(bfl);
	TRACE_ERROR;
	return NULL;
}

/**
 * @brief 为连接端绑定一个域间事件通道。
 * @param rdomid 远程域 ID。
 * @param rport 远程域的事件通道端口。
 * @param local_port [输出] 绑定的本地端口。
 * @param local_irq [输出] 绑定到本地端口的 IRQ。
 * @param arg 传递给 IRQ 处理程序的回调参数。
 * @return 成功返回 0，失败返回 -1。
 */
int bind_evtch(domid_t rdomid, uint32_t rport, uint32_t *local_port,
               int *local_irq, void *arg) {

	struct evtchn_bind_interdomain op;
	int ret;
	TRACE_ENTRY;

	if (!local_irq || !local_port)
		BUG();

	// 绑定到远程域的指定端口
	memset(&op, 0, sizeof(op));
	op.remote_dom = rdomid;
	op.remote_port = rport;

	ret = HYPERVISOR_event_channel_op(EVTCHNOP_bind_interdomain, &op);
	if (ret != 0) {
		EPRINTK("Unable to bind event channel\n");
		goto out;
	}
	*local_port = op.local_port;

	// 将本地端口绑定到 IRQ 处理程序
	ret = bind_evtchn_to_irqhandler(op.local_port, bf_callback, SA_RESTART,
	                                "bf_connector", arg);
	if (ret <= 0) {
		EPRINTK("Failed to bind irq to port %d\n", op.local_port);
		goto out1;
	}
	*local_irq = ret;

	TRACE_EXIT;
	return 0;

out1:
	free_evtch(*local_port, *local_irq, arg);
out:
	TRACE_ERROR;
	return -1;
}

/**
 * @brief 断开连接端的双向 FIFO 连接并释放资源。
 * @param bfc 指向要断开的 bf_handle_t 的指针。
 */
void bf_disconnect(bf_handle_t *bfc) {
	TRACE_ENTRY;

	if (!bfc) {
		EPRINTK("bfc = NULL\n");
		goto err;
	}

	// 1. 停止定时器
	if (bfc->tx_notify_mode == BF_NOTIFY_MODE_BATCH_TIME ||
	    bfc->tx_notify_mode == BF_NOTIFY_MODE_ADAPTIVE) {
		if (timer_pending(&bfc->batch_timer)) {
			DPRINTK("Stopping pending batch timer (connect side)\n");
			del_timer_sync(&bfc->batch_timer);
		}
	}

	// 2. 发送待处理的通知
	if (atomic_read(&bfc->tx_stats.pending_pkts) > 0) {
		DPRINTK("Flushing %d pending packets (connect side)\n",
		        atomic_read(&bfc->tx_stats.pending_pkts));
		bf_notify(bfc->port);
		atomic_set(&bfc->tx_stats.pending_pkts, 0);
	}

	// 3. 等待
	msleep(10);

	// 4. 释放事件通道
	free_evtch(bfc->port, bfc->irq, (void *)bfc);

	// 5. 断开输入和输出 FIFO
	if (bfc->in) {
		xf_disconnect(bfc->in);
		bfc->in = NULL;
	}

	if (bfc->out) {
		xf_disconnect(bfc->out);
		bfc->out = NULL;
	}

	// 6. 释放句柄
	kfree(bfc);

	TRACE_EXIT;
	return;
err:
	TRACE_ERROR;
}

/**
 * @brief (连接端) 连接到一个远程的监听端。
 * @param rdomid 远程监听域的 ID。
 * @param rgref_in 传入远程域的输出 FIFO (即本地域的输入 FIFO) 的 grant
 * reference。
 * @param rgref_out 传入远程域的输入 FIFO (即本地域的输出 FIFO) 的 grant
 * reference。
 * @param rport 远程域的事件通道端口。
 * @return 成功则返回 bf_handle_t 指针，失败则返回 NULL。
 */
bf_handle_t *bf_connect(domid_t rdomid, int rgref_in, int rgref_out,
                        uint32_t rport) {
	bf_handle_t *bfc = NULL;
	int ret;
	TRACE_ENTRY;

	// 分配 bf_handle_t 结构体内存
	bfc = (bf_handle_t *)kmalloc(sizeof(bf_handle_t), GFP_KERNEL);
	if (!bfc) {
		EPRINTK("Can't allocate bfc\n");
		goto err;
	}

	memset(bfc, 0, sizeof(bf_handle_t));

	// 初始化批处理相关字段 - 连接端也需要初始化
	bfc->tx_notify_mode = tx_mode;
	bfc->rx_mode = rx_mode;
	bfc->batch_pkt_threshold = batch_pkt_threshold;
	bfc->batch_time_threshold = batch_time_threshold;

	// 参数验证
	if (bfc->tx_notify_mode < BF_NOTIFY_MODE_IMMEDIATE ||
	    bfc->tx_notify_mode > BF_NOTIFY_MODE_ADAPTIVE) {
		EPRINTK("Invalid tx_mode %d, using immediate mode\n", tx_mode);
		bfc->tx_notify_mode = BF_NOTIFY_MODE_IMMEDIATE;
	}

	if (bfc->rx_mode < BF_RX_MODE_INTERRUPT ||
	    bfc->rx_mode > BF_RX_MODE_POLLING) {
		EPRINTK("Invalid rx_mode %d, using interrupt mode\n", rx_mode);
		bfc->rx_mode = BF_RX_MODE_INTERRUPT;
	}

	DPRINTK("Connecting FIFO with tx_mode=%d, rx_mode=%d\n",
	        bfc->tx_notify_mode, bfc->rx_mode);

	spin_lock_init(&bfc->tx_lock);
	spin_lock_init(&bfc->rx_lock);

	atomic_set(&bfc->tx_stats.pending_pkts, 0);
	atomic_set(&bfc->tx_stats.notify_count, 0);
	atomic_set(&bfc->tx_stats.batch_notify_count, 0);
	atomic_set(&bfc->tx_stats.immediate_notify_count, 0);
	bfc->tx_stats.last_notify_time = jiffies;

	atomic_set(&bfc->rx_poll.polling, 0);
	atomic_set(&bfc->rx_poll.rx_packets, 0);
	atomic_set(&bfc->rx_poll.rx_bytes, 0);
	bfc->rx_poll.irq_enabled = 1;

	// 只有在需要批处理时才初始化定时器
	if (bfc->tx_notify_mode == BF_NOTIFY_MODE_BATCH_TIME ||
	    bfc->tx_notify_mode == BF_NOTIFY_MODE_ADAPTIVE) {
		timer_setup(&bfc->batch_timer, bf_batch_timer_callback, 0);
	}

	bfc->remote_domid = rdomid;
	// 连接到远程的 FIFO
	// 注意：远程的 'in' 是我们的 'out'，远程的 'out' 是我们的 'in'
	DPRINTK("DEBUG: Attempting to connect output FIFO (rgref_out=%d)\n",
	        rgref_out);
	bfc->out = xf_connect(rdomid, rgref_out);
	if (!bfc->out) {
		EPRINTK("Failed to connect output FIFO with gref %d\n", rgref_out);
		goto err;
	}

	DPRINTK("DEBUG: Attempting to connect input FIFO (rgref_in=%d)\n",
	        rgref_in);
	bfc->in = xf_connect(rdomid, rgref_in);
	if (!bfc->in) {
		EPRINTK("Failed to connect input FIFO with gref %d\n", rgref_in);
		goto err;
	}

	if (!bfc->out || !bfc->in) {
		EPRINTK("Can't allocate bfc->in %p or bfc->out %p\n", bfc->in,
		        bfc->out);
		goto err;
	}

	// 绑定到远程的事件通道
	DPRINTK("DEBUG: Attempting to bind event channel (rport=%u)\n", rport);
	ret = bind_evtch(rdomid, rport, &bfc->port, &bfc->irq, (void *)bfc);
	if (ret < 0) {
		EPRINTK("Can't bind to event channel (port %u)\n", rport);
		goto err;
	}

	DPRINTK("DEBUG: bf_connect successful, local_port=%u, local_irq=%d\n",
	        bfc->port, bfc->irq);
	TRACE_EXIT;
	return bfc;
err:
	// 错误处理：断开已建立的连接
	EPRINTK("ERROR: Exiting bf_connect\n");
	bf_disconnect(bfc);
	TRACE_ERROR;
	return NULL;
}
