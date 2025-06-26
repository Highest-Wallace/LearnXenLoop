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


#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/genhd.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <net/ip.h>

#include <asm/xen/hypercall.h>
#include <xen/grant_table.h>
#include <xen/events.h>

#include "debug.h"
#include "xenfifo.h"
#include "bififo.h"
#include "maptable.h"

// 外部变量声明
extern HashTable mac_domid_map;	// MAC地址到域ID的哈希映射表
extern wait_queue_head_t swq;	// 等待队列，用于在特定条件下唤醒进程
extern struct net_device *NIC;	// 网络接口控制器设备
extern Entry* lookup_bfh(HashTable *, void *); // 在哈希表中查找条目的函数

/**
 * @brief 向指定的事件通道端口发送一个通知。
 * @param port 目标事件通道端口。
 */
void bf_notify(uint32_t port)
{
	struct evtchn_send op;
	int ret;

	TRACE_ENTRY;

	memset(&op, 0, sizeof(op));
	op.port = port;

	// 通过 hypercall 发送事件通道操作
	ret = HYPERVISOR_event_channel_op(EVTCHNOP_send, &op);
	if ( ret != 0 ) {
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
static inline void copy_large_pkt(bf_data_t * mdata, struct sk_buff *skb, xf_handle_t *xfh)
{
	char *pback, *pfront, *pfifo;
	int num_entries, len, len1, len2, pkt_len;

	TRACE_ENTRY;

    // 为 skb 预留以太网头和一些额外空间，然后放入数据
    skb_reserve(skb, 2 + ETH_HLEN);
    skb_put(skb, mdata->pkt_info);

	pkt_len = mdata->pkt_info;
	// 计算数据包占用的 FIFO 条目数
	num_entries = pkt_len/sizeof(bf_data_t);
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
	if( pback >= pfront ) {
		// 数据是连续的，直接复制
		memcpy(skb->data, pfront, pkt_len);
	} else {
		// 数据是环绕的，需要分两次复制
		len1 = (pfifo + xfh->descriptor->max_data_entries*sizeof(bf_data_t)) - pfront;
		len = (len1 >= pkt_len) ? pkt_len : len1;
		memcpy(skb->data,  pfront, len);

		len2 = pkt_len - len;
		if (len2 > 0) {
			memcpy(skb->data + len, pfifo, len2);
		}
	}

    // 设置 skb 的网络层相关信息
    skb->mac_header = (__u16)(skb->data - skb->head) + ETH_HLEN;
    skb->ip_summed = CHECKSUM_UNNECESSARY; // XenLoop 内部通信，无需校验和
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
static inline struct sk_buff * copy_packet(xf_handle_t * xfh)
{
	struct sk_buff *skb = NULL;
	bf_data_t * data;
	int n, ret;

	TRACE_ENTRY;

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
	n = data->pkt_info/sizeof(bf_data_t) + 1;
	if (data->pkt_info % sizeof(bf_data_t))
		n++;

	ret = xf_popn(xfh, n);
	BUG_ON( ret < 0 );

out:
	TRACE_EXIT;
	return skb;
}

/**
 * @brief 从给定的双向 FIFO 句柄的输入队列中接收所有数据包。
 * @param bfh 指向双向 FIFO 句柄的指针。
 */
void recv_packets(bf_handle_t *bfh)
{
	static DEFINE_SPINLOCK(recv_lock);
	struct sk_buff *skb;
	unsigned long flags;

	TRACE_ENTRY;

	spin_lock_irqsave(&recv_lock, flags);

	// 循环直到输入 FIFO 为空
	while( !xf_empty(bfh->in) ) {

		skb = copy_packet(bfh->in);
		if (!skb)
			break;

		spin_unlock_irqrestore(&recv_lock, flags);

		// DPRINTK("packet received through xenloop\n");
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
 * @brief 事件通道中断回调函数 (IRQ handler)。
 *        当远程域通过事件通道发送通知时，此函数被调用。
 * @param rq IRQ 号。
 * @param dev_id 传递给中断处理程序的设备 ID (这里是 bf_handle_t *)。
 * @return IRQ_HANDLED 表示中断已处理。
 */
irqreturn_t bf_callback(int rq, void *dev_id)
{
	bf_handle_t *bfh = (bf_handle_t *)dev_id;

	TRACE_ENTRY;

	BUG_ON(!check_descriptor(bfh));

	// 检查 FIFO 是否被挂起 (例如，在虚拟机迁移期间)
	if (BF_SUSPEND_IN(bfh) || BF_SUSPEND_OUT(bfh)) {
		Entry *e = lookup_bfh(&mac_domid_map, bfh);
		BUG_ON(!e);

		// 设置状态为挂起并唤醒等待队列
		e->status = XENLOOP_STATUS_SUSPEND;

		wake_up_interruptible(&swq);
		TRACE_EXIT;
		return IRQ_HANDLED;
	}

	// 接收数据包
	recv_packets(bfh);

	TRACE_EXIT;
	return IRQ_HANDLED;
}

/**
 * @brief 释放事件通道资源。
 * @param port 事件通道端口。
 * @param irq 绑定的 IRQ。
 * @param dev_id 设备 ID。
 */
void free_evtch(uint32_t port, int irq, void *dev_id)
{
	struct evtchn_close op;
	int ret;

	TRACE_ENTRY;

	if(irq)
		unbind_from_irqhandler(irq, dev_id);

	if(port) {
		memset(&op, 0, sizeof(op));
		DPRINTK("free port: %u\n", port);
		op.port = port;
		ret = HYPERVISOR_event_channel_op(EVTCHNOP_close, &op);
		if ( ret != 0 )
			EPRINTK("Unable to cleanly close event channel, err: %d\n", ret);
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
int create_evtch(domid_t rdomid, uint32_t *port, int *irq, void *arg)
{
	struct evtchn_alloc_unbound op;
	int ret;

	TRACE_ENTRY;

	if(!irq || !port )
		BUG();

	// 分配一个未绑定的事件通道，用于监听来自 rdomid 的连接
	memset(&op, 0, sizeof(op));
	op.dom = DOMID_SELF;
	op.remote_dom = rdomid;

	ret = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound, &op);
	if ( ret != 0 ) {
		EPRINTK("Unable to allocate event channel\n");
		goto out;
	}
	*port = op.port;

	// 将分配的端口绑定到一个 IRQ 处理程序
	ret = bind_evtchn_to_irqhandler(op.port, bf_callback, SA_RESTART, "bf_listener", arg);
	if ( ret  <= 0 ) {
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
void bf_destroy(bf_handle_t *bfl)
{
	TRACE_ENTRY;

	if(!bfl) {
		EPRINTK("bfl = NULL\n");
		goto err;
	}

	// 销毁输入和输出 FIFO
	if(bfl->in)
		xf_destroy(bfl->in);

	if(bfl->out)
		xf_destroy(bfl->out);

	// 释放事件通道
	free_evtch(bfl->port, bfl->irq, (void *)bfl);

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
bf_handle_t *bf_create(domid_t rdomid, int entry_order)
{
	bf_handle_t *bfl = NULL;
	int ret;
	TRACE_ENTRY;

	// 分配 bf_handle_t 结构体内存
	bfl = (bf_handle_t *) kmalloc(sizeof(bf_handle_t), GFP_KERNEL);
	if(!bfl) {
		EPRINTK("Can't allocate bfl\n");
		goto err;
	}

	memset(bfl, 0, sizeof(bf_handle_t));
	bfl->remote_domid = rdomid;
	// 创建输出和输入 FIFO
	bfl->out = xf_create(rdomid, sizeof(bf_data_t), entry_order);
	bfl->in = xf_create(rdomid, sizeof(bf_data_t), entry_order);
	if(!bfl->out || !bfl->in) {
		EPRINTK("Can't allocate bfl->in %p or bfl->out %p\n", bfl->in, bfl->out);
		goto err;
	}

	// 创建事件通道用于接收通知
	ret = create_evtch(rdomid, &bfl->port, &bfl->irq, (void *)bfl);
	if(ret < 0) {
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
int bind_evtch(domid_t rdomid, uint32_t rport, uint32_t *local_port, int *local_irq, void *arg)
{

	struct evtchn_bind_interdomain op;
	int ret;
	TRACE_ENTRY;

	if(!local_irq || !local_port )
		BUG();

	// 绑定到远程域的指定端口
	memset(&op, 0, sizeof(op));
	op.remote_dom = rdomid;
	op.remote_port = rport;

	ret = HYPERVISOR_event_channel_op(EVTCHNOP_bind_interdomain, &op);
	if ( ret != 0 ) {
		EPRINTK("Unable to bind event channel\n");
		goto out;
	}
	*local_port = op.local_port;

	// 将本地端口绑定到 IRQ 处理程序
	ret = bind_evtchn_to_irqhandler(op.local_port, bf_callback, SA_RESTART, "bf_connector", arg);
	if ( ret  <= 0 ) {
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
void bf_disconnect(bf_handle_t *bfc)
{
	TRACE_ENTRY;

	if(!bfc) {
		EPRINTK("bfc = NULL\n");
		goto err;
	}

	// 断开输入和输出 FIFO
	if(bfc->in)
		xf_disconnect(bfc->in);

	if(bfc->out)
		xf_disconnect(bfc->out);

	// 释放事件通道
	free_evtch(bfc->port, bfc->irq, (void *)bfc);

	kfree(bfc);

	TRACE_EXIT;
	return;
err:
	TRACE_ERROR;

}

/**
 * @brief (连接端) 连接到一个远程的监听端。
 * @param rdomid 远程监听域的 ID。
 * @param rgref_in 传入远程域的输出 FIFO (即本地域的输入 FIFO) 的 grant reference。
 * @param rgref_out 传入远程域的输入 FIFO (即本地域的输出 FIFO) 的 grant reference。
 * @param rport 远程域的事件通道端口。
 * @return 成功则返回 bf_handle_t 指针，失败则返回 NULL。
 */
bf_handle_t *bf_connect(domid_t rdomid, int rgref_in, int rgref_out, uint32_t rport)
{
	bf_handle_t *bfc = NULL;
	int ret;
	TRACE_ENTRY;

	// 分配 bf_handle_t 结构体内存
	bfc = (bf_handle_t *) kmalloc(sizeof(bf_handle_t), GFP_KERNEL);
	if(!bfc) {
		EPRINTK("Can't allocate bfc\n");
		goto err;
	}

	memset(bfc, 0, sizeof(bf_handle_t));
	bfc->remote_domid = rdomid;
	// 连接到远程的 FIFO
	// 注意：远程的 'in' 是我们的 'out'，远程的 'out' 是我们的 'in'
	bfc->out = xf_connect(rdomid, rgref_out);
	bfc->in = xf_connect(rdomid, rgref_in);
	if(!bfc->out || !bfc->in) {
		EPRINTK("Can't allocate bfc->in %p or bfc->out %p\n", bfc->in, bfc->out);
		goto err;
	}

	// 绑定到远程的事件通道
	ret = bind_evtch(rdomid, rport, &bfc->port, &bfc->irq, (void *)bfc);
	if(ret < 0) {
		EPRINTK("Can't bind to event channel\n");
		goto err;
	}

	TRACE_EXIT;
	return bfc;
err:
	// 错误处理：断开已建立的连接
	bf_disconnect(bfc);
	TRACE_ERROR;
	return NULL;
}
