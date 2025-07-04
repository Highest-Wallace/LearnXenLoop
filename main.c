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

#include <asm/xen/hypercall.h>
#include <xen/grant_table.h>
#include <xen/events.h>
#include <xen/xenbus.h>

#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/protocol.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <net/neighbour.h>
#include <net/dst.h>
#include <linux/if_ether.h>
#include <net/inet_common.h>
#include <linux/inetdevice.h>
#include <linux/mm.h>
#include <linux/time.h>
#include <linux/genhd.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include "main.h"
#include "debug.h"
#include "bififo.h"
#include "maptable.h"

#include <linux/if_arp.h>
#include <uapi/linux/netfilter_arp.h>


// 从 maptable.c 导入的哈希表操作函数
extern int 	init_hash_table(HashTable *, char *);
extern void 	clean_table(HashTable *);
extern void 	insert_table(HashTable *, void *, u8);
extern void*	lookup_table(HashTable *, void *);
extern void     update_table(HashTable *,u8 *, int);
extern void	mark_suspend(HashTable *);
extern int	has_suspend_entry(HashTable *);
extern void	clean_suspended_entries(HashTable * ht);
extern void 	notify_all_bfs(HashTable * ht);
extern void	check_timeout(HashTable * ht);

// 全局变量声明
static domid_t my_domid; // 本地域（Domain）的ID
static u8 my_macs[MAX_MAC_NUM][ETH_ALEN]; // 存储本地所有网络接口的MAC地址
static u8 num_of_macs = 0; // 本地MAC地址的数量
static u8 freezed = 0; // 标志位，用于在迁移期间冻结模块活动
struct net_device *NIC = NULL; // 用于发送会话管理消息的网络接口设备
static int if_drops = 0; // 记录网络接口丢弃的数据包数量
static skb_queue_t out_queue; // 用于暂存待通过XenLoop发送的数据包队列
static skb_queue_t pending_free; // 待释放的skb队列 (当前代码中未使用)

// 静态函数声明
static int xenloop_connect(message_t *msg, Entry *e);
static int xenloop_listen(Entry *e);
static struct task_struct *suspend_thread = NULL; // 用于处理挂起连接的内核线程
DECLARE_WAIT_QUEUE_HEAD(swq); // suspend_thread的等待队列
static struct task_struct *pending_thread = NULL; // 用于处理待发送数据包的内核线程
DECLARE_WAIT_QUEUE_HEAD(pending_wq); // pending_thread的等待队列

// 针对IP哈希表的额外映射表函数
extern void insert_table_ip(HashTable* ht, u32 ip, Entry* old_entry);
extern void * lookup_table_ip(HashTable * ht, u32 ip);
extern void remove_entry_mac(HashTable* ht, void* mac);
extern int init_hash_table_ip(HashTable* ht);

// 哈希表实例，用于存储MAC/IP地址到Domain ID的映射
HashTable mac_domid_map; // MAC地址 -> Domain ID 映射表
HashTable ip_domid_map;  // IP地址 -> Domain ID 映射表

// 模块参数，用于指定XenLoop使用的物理网卡名称
static char* nic = NULL;
module_param(nic,charp,0660);

/**
 * @brief 将XenLoop的状态写入XenStore。
 *
 * @param status 要写入的状态值 (1: 运行中, 0: 已停止/挂起)。
 * @return 成功返回0，失败返回错误码。
 */
static int  write_xenstore(int status)
{
	int err = 1;

	err = xenbus_printf(XBT_NIL, "xenloop", "xenloop","%d", status);
    if (err) {
		EPRINTK( "writing xenstore xenloop status failed, err = %d \n", err);
	}
	return err;
}

/**
 * @brief 从XenStore读取并返回当前Domain的ID。
 *
 * @return 返回当前Domain的ID，失败则返回错误码。
 */
static domid_t get_my_domid(void)
{
	char *domidstr;
	domid_t domid;

	domidstr = xenbus_read(XBT_NIL, "domid", "", NULL);
	if ( IS_ERR(domidstr) ) {
		EPRINTK("xenbus_read error\n");
		return PTR_ERR(domidstr);
	}

	domid = (domid_t) simple_strtoul(domidstr, NULL, 10);

	kfree(domidstr);

	return domid;
}


/**
 * @brief 将字符串格式的MAC地址解析并存储到my_macs数组中。
 *
 * @param mac 指向MAC地址字符串的指针。
 * @return 总是返回0。
 */
int store_mac(char* mac)
{
	char *pEnd = mac;
	int i;

	for (i=0; i < (ETH_ALEN-1); i++) {
		my_macs[(int)num_of_macs][i] = simple_strtol(pEnd, &pEnd, 16);
		pEnd++;
	}

	my_macs[(int)num_of_macs][ETH_ALEN-1] = simple_strtol(pEnd, NULL, 16);

	num_of_macs++;

	return 0;
}



/**
 * @brief 探测并存储本地所有的虚拟网络接口（VIF）的MAC地址。
 *
 * @return 成功返回0，失败返回错误码。
 */
static int probe_vifs(void)
{
        int err = 0;
        char **dir;
		char * path, *macstr;
        unsigned int i, dir_n;

        dir = xenbus_directory(XBT_NIL, "device/vif", "", &dir_n);
        if (IS_ERR(dir))
                return PTR_ERR(dir);

        for (i = 0; i < dir_n; i++) {

		path = kasprintf(GFP_KERNEL, "device/vif/%s", dir[i]);

		if (!path) {
			EPRINTK("kasprintf failed dir[%d]=%s \n", i, dir[i]);
			err = -ENOMEM;
			goto out;
		}

		macstr = xenbus_read(XBT_NIL, path, "mac", NULL);
		if ( IS_ERR(macstr) ) {
			EPRINTK("xenbus_read error path=%s \n", path);
			err = PTR_ERR(macstr);
			kfree(path);
			goto out;
		}

		store_mac(macstr);
		DB("device/vif/%s/mac path=%s ==> %s\n", dir[i], path, macstr);


		kfree(macstr);
		kfree(path);
	}

out:
	kfree(dir);
	return err;
}

/**
 * @brief 根据收到的会话发现消息更新MAC-DomID映射表。
 *
 * 当收到一个XENLOOP_MSG_TYPE_SESSION_DISCOVER类型的消息时，
 * 此函数会检查消息中包含的MAC地址列表。如果某个MAC地址不在本地
 * 的映射表中，则将其和对应的Domain ID添加到表中。
 *
 * @param msg 指向收到的消息结构体的指针。
 */
void session_update(message_t* msg)
{
	int i, found = 0;
	u8 mac_count = msg->mac_count;
	Entry * e;

	for(i=0; i<mac_count; i++) {
		// 检查消息中的MAC地址是否是本地MAC地址之一
		if (memcmp(msg->mac[i], my_macs[0], ETH_ALEN) == 0) {
			found = 1;
			break;
		}
	}
	// 如果消息与本域无关，则直接返回
	if (!found) return;

	for(i=0; i<mac_count; i++) {
		// 跳过自己的MAC地址
		if (memcmp(msg->mac[i], my_macs[0], ETH_ALEN) == 0)
			continue;

		// 如果某个MAC地址不在映射表中，则添加新条目
		if (!(e = lookup_table(&mac_domid_map, msg->mac[i]))) {

			insert_table(&mac_domid_map, msg->mac[i], msg->guest_domids[i]);

			DPRINTK("Added one new guest mac = " MAC_FMT  " Domid=%d.\n", \
			   MAC_NTOA(msg->mac[i]), msg->guest_domids[i]);

		} else // 如果已存在，则更新时间戳
			e->timestamp = jiffies;
	}

	// 更新哈希表，移除过时的条目
	update_table(&mac_domid_map, (u8*)msg->mac, msg->mac_count);
}

/**
 * @brief 在处理连接创建消息前进行预检查。
 *
 * @param msg 指向会话消息的指针。
 * @return 如果找到对应的条目，则返回该条目指针；否则返回NULL。
 */
Entry *pre_check_msg(message_t *msg)
{
	Entry *e = NULL;
	if(msg->mac_count > 1){
		EPRINTK("warning more than one mac\n");
	}

	if (!(e = lookup_table(&mac_domid_map, msg->mac[0]))) {
		EPRINTK("lookup table failed\n");
	}

	return e;
}

/**
 * @brief 接收并处理来自Dom0的会话管理消息。
 *
 * @param skb 包含消息的网络数据包。
 * @param dev 接收设备。
 * @param pt 数据包类型。
 * @param d 原始设备。
 * @return 总是返回 NET_RX_SUCCESS。
 */
int session_recv(struct sk_buff * skb, net_device * dev, packet_type * pt, net_device * d)
{
	int ret = NET_RX_SUCCESS;
	message_t * msg = NULL;
	Entry *e;

	TRACE_ENTRY;

	BUG_ON(!skb);

	msg = (message_t *)skb->data;
	BUG_ON(!msg);

	skb_linearize(skb);

	switch(msg->type) {
		case XENLOOP_MSG_TYPE_SESSION_DISCOVER:
			// 如果模块未被冻结，则更新会话信息
			if (!freezed)
				session_update(msg);
			break;
		case XENLOOP_MSG_TYPE_CREATE_CHN:
			// 处理创建通道的请求
			e = pre_check_msg(msg);
			if(!e)	goto out;

			ret = xenloop_connect(msg, e);
			break;
		case XENLOOP_MSG_TYPE_CREATE_ACK:
			// 处理创建通道的确认消息
			e = pre_check_msg(msg);
			if(!e)	goto out;

			// 更新状态为已连接，并删除ACK超时定时器
			e->status = XENLOOP_STATUS_CONNECTED;
			if(e->del_timer) {
				del_timer(&e->ack_timer);
			}
			DPRINTK("LISTENER status changed to XENLOOP_STATUS_CONNECTED!!!\n");
			break;
		default:
			EPRINTK("session_recv(): unknown msg type %d\n", msg->type);
	}

out:
	kfree_skb(skb);
	TRACE_EXIT;
	return ret;
}


// 定义一个packet_type结构，用于接收特定以太网类型（ETH_P_TIDC）的数据包
static packet_type xenloop_ptype = {
	.type		= __constant_htons(ETH_P_TIDC), // 协议类型
	.func 		= session_recv, // 处理函数
	.dev 		= NULL, // 监听所有设备
	.af_packet_priv = NULL,
};


/**
 * @brief 通过指定的网络接口发送一个skb。
 *
 * @param skb 要发送的数据包。
 * @param dest 目标MAC地址。
 */
inline void net_send(struct sk_buff * skb, u8 * dest)
{
	ethhdr * eth;
	int ret;

	skb->network_header = 0;

	// 设置以太网头部
	skb->len = headers;
	skb->data_len = 0;
	skb_shinfo(skb)->nr_frags 	= 0;
	skb_shinfo(skb)->frag_list 	= NULL;
	skb->tail = headers;

	skb->dev 	= NIC;
	skb->protocol 	= htons(ETH_P_TIDC);
	eth 		= (ethhdr *) skb->data;
	eth->h_proto 	= htons(ETH_P_TIDC);
	memcpy(eth->h_dest, dest, ETH_ALEN);

	memcpy(eth->h_source, NIC->dev_addr, ETH_ALEN);

	if((skb_shinfo(skb) == NULL)) {
		WARN_ON(1);
		TRACE_ERROR;
	}

	SKB_LINEAR_ASSERT(skb);


	// 发送数据包
	if((ret = dev_queue_xmit(skb))) {
		DB("Non-zero return code: %d %s", ret,
		   skb_shinfo(skb) ? "good" : "bad");

		if_drops++;
		TRACE_ERROR;
	}


}


/**
 * @brief 发送一个创建通道的消息。
 *
 * @param gref_in 输入FIFO的grant reference。
 * @param gref_out 输出FIFO的grant reference。
 * @param remote_port 远端的事件通道端口。
 * @param dest_mac 目标MAC地址。
 */
void send_create_chn_msg(int gref_in, int gref_out, int remote_port, u8 *dest_mac)
{
	message_t *m;
	struct sk_buff *skb;

	TRACE_ENTRY;

	skb = alloc_skb(headers, GFP_ATOMIC);
	BUG_ON(!skb);

	m = (message_t *) (skb->data + LINK_HDR);

	// 填充消息内容
	memset(m, 0, MSGSIZE);
	m->type = XENLOOP_MSG_TYPE_CREATE_CHN;
	m->domid= my_domid;
	m->mac_count = num_of_macs;
	memcpy(m->mac, my_macs, num_of_macs*ETH_ALEN);
	m->gref_in = gref_in;
	m->gref_out = gref_out;
	m->remote_port = remote_port;

	net_send(skb, dest_mac);

	TRACE_EXIT;
}

/**
 * @brief 发送一个创建通道的确认消息。
 *
 * @param dest_mac 目标MAC地址。
 */
void send_create_ack_msg(u8 *dest_mac)
{
	message_t *m;
	struct sk_buff *skb;

	TRACE_ENTRY;

	BUG_ON(!(skb = alloc_skb(headers, GFP_ATOMIC)));

	m = (message_t *) (skb->data + LINK_HDR);

	// 填充消息内容
	memset(m, 0, MSGSIZE);
	m->type = XENLOOP_MSG_TYPE_CREATE_ACK;
	m->domid= my_domid;
	m->mac_count = num_of_macs;
	memcpy(m->mac, my_macs, num_of_macs*ETH_ALEN);

	net_send(skb, dest_mac);

	TRACE_EXIT;
}

/**
 * @brief 创建通道确认消息的超时处理函数。
 *
 * @param tm 指向定时器列表的指针。
 */
static void ack_timeout(struct timer_list* tm)
{
	// the first member of the struct is the address of the struct Entry
	// 从定时器结构获取Entry结构
	Entry* e = container_of(tm, struct Entry, ack_timer);
	bf_handle_t *bfl;

	TRACE_ENTRY;

	BUG_ON(!e);
	BUG_ON(!e->listen_flag);


	// 如果已经连接，则直接返回
	if( e->status == XENLOOP_STATUS_CONNECTED )
		return;

	BUG_ON(e->status != XENLOOP_STATUS_LISTEN);

 	bfl = e->bfh;
	BUG_ON(!bfl);

	// 如果重试次数未超过上限，则重发创建通道消息并重置定时器
	if(e->retry_count < MAX_RETRY_COUNT ) {

		send_create_chn_msg(BF_GREF_IN(bfl),		\
					BF_GREF_OUT(bfl),	\
					BF_EVT_PORT(bfl),	\
					e->mac);
		e->retry_count++;
		mod_timer(&e->ack_timer, jiffies + XENLOOP_ACK_TIMEOUT*HZ);
	} else { // 如果超过重试次数，则将通道标记为挂起状态，并唤醒挂起处理线程
		if (check_descriptor(e->bfh)) {
			BF_SUSPEND_IN(e->bfh) = 1;
			BF_SUSPEND_OUT(e->bfh) = 1;
		}
		e->status = XENLOOP_STATUS_SUSPEND;
		wake_up_interruptible(&swq);
	}

	TRACE_EXIT;
}



/**
 * @brief 监听并等待远端VM的连接请求（作为连接的发起方）。
 *
 * @param e 指向对应连接的Entry。
 * @return 成功返回0，失败返回-1。
 */
static int xenloop_listen(Entry *e)
{
	static DEFINE_SPINLOCK(listen_lock);
	unsigned long flag;
	domid_t remote_domid = e->domid;
	bf_handle_t *bfl = NULL;
	int i;
	bf_data_t *pbf;

	TRACE_ENTRY;

	// 使用自旋锁确保线程安全
	spin_lock_irqsave(&listen_lock, flag);

	// 如果状态不是初始状态，说明已经有其他线程在处理，直接返回
	if( e->status != XENLOOP_STATUS_INIT) {
		spin_unlock_irqrestore(&listen_lock, flag);
		TRACE_EXIT;
		return 0;
	}

	// 设置状态为监听中
	e->status = XENLOOP_STATUS_LISTEN;

	spin_unlock_irqrestore(&listen_lock, flag);



	// 创建双向FIFO
	bfl = bf_create(remote_domid, XENLOOP_ENTRY_ORDER);
	if(!bfl) {
		e->status = XENLOOP_STATUS_INIT;

		EPRINTK("bf_create failed\n");
		TRACE_ERROR;
		return -1;
	}

	// 初始化FIFO中的数据项状态
	for(i=0; i<=xf_size(bfl->in); i++) {
		pbf = xf_entry(bfl->in, bf_data_t, i);
		pbf->status = BF_FREE;
	}
	for(i=0; i<=xf_size(bfl->out); i++) {
		pbf = xf_entry(bfl->out, bf_data_t, i);
		pbf->status = BF_FREE;
	}

	e->listen_flag = 1; // 标记为监听方
	e->bfh = bfl;


	// 发送创建通道的消息给对端
	send_create_chn_msg(BF_GREF_IN(bfl),
				BF_GREF_OUT(bfl),
				BF_EVT_PORT(bfl),
				e->mac);


	// 启动ACK超时定时器
	timer_setup(&e->ack_timer, ack_timeout, 0);
	e->del_timer = 1;
	e->ack_timer.expires	= jiffies + XENLOOP_ACK_TIMEOUT*HZ;
	add_timer(&e->ack_timer);

	TRACE_EXIT;
	return 0;
}

/**
 * @brief 连接到远端VM（作为连接的接收方）。
 *
 * @param msg 包含连接信息的会话消息。
 * @param e 指向对应连接的Entry。
 * @return 成功返回0，失败返回-1。
 */
static int xenloop_connect(message_t *msg, Entry *e)
{
	domid_t remote_domid = e->domid;
	bf_handle_t *bfc = NULL;

	TRACE_ENTRY;

	BUG_ON(!msg);

	// 如果已经连接，则只需回复ACK
	if(e->status == XENLOOP_STATUS_CONNECTED) {
		send_create_ack_msg(e->mac);
		TRACE_EXIT;
		return 0;
	}


	// 检查传入的grant reference和端口号是否有效
	if(msg->gref_in <= 0 || msg->gref_out <= 0 || msg->remote_port <= 0) {
		EPRINTK("Invalid parameters: gref_in %d gref_out %d remote_port %d\n", 
			msg->gref_in, msg->gref_out, msg->remote_port);
		goto err;
	}

	DPRINTK("DEBUG: Attempting to connect with gref_in=%d, gref_out=%d, remote_port=%d, remote_domid=%d\n",
		msg->gref_in, msg->gref_out, msg->remote_port, remote_domid);

	// 连接到远端提供的FIFO
	bfc = bf_connect(remote_domid, msg->gref_out, msg->gref_in, msg->remote_port);
	if(!bfc) {
		EPRINTK("bf_connect failed for domid %d\n", remote_domid);
		goto err;
	}

	e->listen_flag = 0; // 标记为连接方
	e->bfh = bfc;

	e->status = XENLOOP_STATUS_CONNECTED;
	DPRINTK("CONNECTOR status changed to XENLOOP_STATUS_CONNECTED!!!\n");


	// 发送ACK确认连接成功
	send_create_ack_msg(e->mac);

	TRACE_EXIT;
	return 0;
err:
	TRACE_ERROR;
	return -1;
}



/**
 * @brief 通过XenLoop的FIFO发送一个大数据包（可能跨越多个FIFO条目）。
 *
 * @param skb 要发送的数据包。
 * @param xfh 要使用的单向FIFO句柄。
 * @return 成功返回0，失败返回-1。
 */
static int xmit_large_pkt(struct sk_buff *skb, xf_handle_t *xfh)
{
	bf_data_t *mdata;
	char *pback, *pfront, *pfifo;
	int num_entries, ret, len=0, len1=0, len2=0;

	TRACE_ENTRY;
	BUG_ON(!skb);
	BUG_ON(!xfh);

	// 添加调试信息：检查 xfh 的内容
	if (!xfh->descriptor) {
		EPRINTK("ERROR: xfh->descriptor is NULL!\n");
		return -1;
	}

	if (!xfh->fifo) {
		EPRINTK("ERROR: xfh->fifo is NULL!\n");
		return -1;
	}

	// DPRINTK("DEBUG: xmit_large_pkt - skb->len=%u, fifo=%p, descriptor=%p, num_pages=%u, max_entries=%u\n",
	// 	skb->len, xfh->fifo, xfh->descriptor, 
	// 	xfh->descriptor->num_pages, xfh->descriptor->max_data_entries);

	// 检查FIFO是否有足够空间
	if( skb->len + sizeof(bf_data_t) > xf_free(xfh)*sizeof(bf_data_t) ) {
		TRACE_EXIT;
		return -1;
	}

	// 在FIFO中预留一个条目用于存储元数据
	mdata  = xf_entry(xfh, bf_data_t, xf_size(xfh));
	if (!mdata) {
		EPRINTK("ERROR: xf_entry returned NULL pointer!\n");
		return -1;
	}

	mdata->status = BF_WAITING; // 标记为等待处理
	mdata->type = BF_PACKET;    // 类型为数据包
	mdata->pkt_info = skb->len; // 存储数据包长度

	// 计算数据包需要占用的FIFO条目数
	num_entries = skb->len/sizeof(bf_data_t);
	if (skb->len % sizeof(bf_data_t))
		num_entries++;

	// 获取FIFO的内存地址信息，用于处理环形缓冲区的回绕
	pfifo = (char *)xfh->fifo;
	pfront = (char *)xf_entry(xfh, bf_data_t, 0);
	pback = (char *) xf_entry(xfh, bf_data_t, xf_size(xfh) + 1);

	BUG_ON(!pfifo);
	BUG_ON(!pfront);
	BUG_ON(!pback);

	// 拷贝数据包内容到FIFO
	if( pback >= pfront ) { // 不需要回绕
		len1 = (pfifo + xfh->descriptor->max_data_entries*sizeof(bf_data_t)) - pback;
		len = (len1 >= skb->len) ? skb->len : len1;
		if(skb_copy_bits(skb, 0, pback, len))
			BUG();

		len2 = skb->len - len;
		if( len2  > 0 ) {
			if(skb_copy_bits(skb, len, pfifo, len2))
				BUG();
		}
	} else { // 直接拷贝
		if(skb_copy_bits(skb, 0, pback, skb->len))
			BUG();
	}

	// 更新FIFO的生产者指针
	ret = xf_pushn(xfh, num_entries + 1);
	BUG_ON( ret < 0 );

	TRACE_EXIT;

	return 0;
}

/**
 * @brief 将一个skb入队。
 *
 * @param Q 目标队列。
 * @param skb 要入队的数据包。
 */
void enqueue(skb_queue_t *Q, struct sk_buff *skb)
{
	if (Q->count++ == 0) {
		Q->head = skb;
		Q->tail = skb;
	} else {
		Q->tail->next = skb;
		Q->tail = skb;
	}
}

/**
 * @brief 从队列头部移除一个skb。
 *
 * @param Q 目标队列。
 */
void dequeue(skb_queue_t *Q)
{
	if (Q->head != Q->tail)
		Q->head = Q->head->next;
	if (--Q->count == 0) {
		Q->head = NULL;
		Q->tail = NULL;
	}
}

/**
 * @brief 清空一个skb队列并释放所有数据包。
 *
 * @param Q 要清空的队列。
 */
void clean_pending(skb_queue_t *Q) {
	struct sk_buff *skb;
	while (Q->count > 0) {
		skb = Q->head;
		dequeue(Q);
		kfree_skb(skb);
	}
}

// TODO just pass Entry e to this function?
// sometimes this get's passed NULL to just empty the queue out
// queue will fill up if xmit_large_pkt returns some error
// TODO: 仅向此函数传递Entry e？
// 有时会传递NULL以清空队列
// 如果xmit_large_pkt返回错误，队列将会填满
/**
 * @brief 从out_queue中取出数据包并通过XenLoop发送。
 *
 * @param skb 要发送的新数据包（可以为NULL，表示只处理队列中已有的包）。
 * @return 成功返回0，失败返回-1。
 */
inline int xmit_packets(struct sk_buff *skb)
{
	static DEFINE_SPINLOCK(xmit_lock);
	int ret = 0;
	unsigned long flags;

	TRACE_ENTRY;

	BUG_ON( in_irq() );

	// 使用自旋锁保护队列访问
	spin_lock_irqsave( &xmit_lock, flags );

	if(skb) {
		// 检查数据包大小是否超过FIFO容量
		if ( skb->len + sizeof(bf_data_t) < (1 << XENLOOP_ENTRY_ORDER)*sizeof(bf_data_t) )
			enqueue(&out_queue, skb);
		else {
			DB("Packet size greater than total fifo size\n");
			ret = -1;
		}
	}

	// 循环处理队列中的所有数据包
	while (out_queue.count > 0) {
		int rc;
		Entry *e;

		skb = out_queue.head;
		BUG_ON(!skb);

		// TODO store skb and entry together? so we don't have to do this lookup
		// this lookup is fairly negligle though
		// TODO: 将skb和entry一起存储？这样就不必进行查找
		// 不过这个查找的开销可以忽略不计
		// 根据目的IP地址查找对应的连接条目
		e = lookup_table_ip(&ip_domid_map, ip_hdr(skb)->daddr);
		if (!e) {
			EPRINTK("ERROR: lookup_table_ip failed for IP %pI4\n", &ip_hdr(skb)->daddr);
			dequeue(&out_queue);
			kfree_skb(skb);
			continue;
		}

		if (!e->bfh) {
			EPRINTK("ERROR: Entry has NULL bfh for IP %pI4\n", &ip_hdr(skb)->daddr);
			dequeue(&out_queue);
			kfree_skb(skb);
			continue;
		}

		if (!e->bfh->out) {
			EPRINTK("ERROR: bfh has NULL out FIFO for IP %pI4\n", &ip_hdr(skb)->daddr);
			dequeue(&out_queue);
			kfree_skb(skb);
			continue;
		}

		// 发送数据包
		rc = xmit_large_pkt(skb, e->bfh->out);

		if (rc < 0) {
			// EPRINTK("xmit_large_pkt failed: %d\n", rc);
			// TODO this seems dangerous, I think calling bf_notify here could lock the CPU (since we're in irqsave)
			// we're disabling interrupts and then calling a hypercall in bf_notify, we'll probably lose the return and get stuck :(
			// why do we even need a notify here in the first place? the xmit_pending thread will just call this function again
			// we haven't transmitted any data, so why tell the other guest we did? seems silly, but maybe I'm wrong

			// NOTE: the original XenLoop calls bf_notify here
			// to me, this seems dangerous since it uses a hypercall to send a signal on the event channel, but we've disabled interrupts
			// I'm not sure this is 100% dangerous, but it seems like it could lock up the CPU since we'll never get a response to the hypercall with interrupts masked
			// bf_notify(e->bfh->port);
			// TODO: 这看起来很危险，我认为在这里调用bf_notify可能会锁定CPU（因为我们在irqsave中）
			// 我们禁用了中断，然后在bf_notify中调用了一个hypercall，我们可能永远不会得到返回并卡住 :(
			// 首先，为什么我们在这里需要一个通知？xmit_pending线程会再次调用这个函数
			// 我们没有传输任何数据，为什么要告诉另一个客户机我们传输了？看起来很傻，但也许我错了

			// 注意：原始的XenLoop在这里调用bf_notify
			// 对我来说，这似乎很危险，因为它使用hypercall在事件通道上发送信号，但我们已经禁用了中断
			// 我不确定这是否100%危险，但看起来它可能会锁住CPU，因为我们永远不会收到对hypercall的响应，当中断被屏蔽时
			// bf_notify(e->bfh->port);
			// 唤醒pending_thread，以便稍后重试
			wake_up_interruptible(&pending_wq);
			break;
		}

		// 发送成功，出队并释放skb
		dequeue(&out_queue);

		kfree_skb(skb);
	}

	spin_unlock_irqrestore( &xmit_lock, flags );

	// TODO why don't we onlt call notify on the bififos we updated? we'd have to track that
	// we can't call notify while IRQs are masked for the same reason as above, it could lock the CPU
	// calling bf_notify in the above loop seemed to confirm this theory as the CPU locked up
	// TODO: 为什么我们不只对更新过的bififo调用notify？我们需要跟踪这一点
	// 我们不能在IRQ被屏蔽时调用notify，原因同上，它可能会锁住CPU
	// 在上面的循环中调用bf_notify似乎证实了这个理论，因为CPU锁死了
	// 通知所有可能接收了数据的对端VM
	notify_all_bfs(&ip_domid_map);

	TRACE_EXIT;
	return ret;
}


// hook outgoing packets
/**
 * @brief Netfilter钩子函数，用于截获向外发送的IP包。
 *
 * @param priv 私有数据。
 * @param skb 数据包。
 * @param state 钩子状态。
 * @return NF_ACCEPT (正常处理), NF_STOLEN (数据包已被处理)。
 */
static unsigned int iphook_out(
	void* priv,
	struct sk_buff *skb,
	const struct nf_hook_state* state) {
	Entry * e;
	int ret = NF_ACCEPT;

	// DPRINTK("Hooked out IP: %\n", htonl(ip_hdr(skb)->daddr));
	// 检查目的IP是否在我们的映射表中
	if(!(e = lookup_table_ip(&ip_domid_map, ip_hdr(skb)->daddr))) {
		// DPRINTK("Not in table, using normal routing\n");
		return NF_ACCEPT; // 不在，则正常通过网络栈
	}

	TRACE_ENTRY;

	// 检查连接是否被挂起
	if (check_descriptor(e->bfh) && (BF_SUSPEND_IN(e->bfh) || BF_SUSPEND_OUT(e->bfh))) {
		e->status = XENLOOP_STATUS_SUSPEND;
		wake_up_interruptible(&swq);
		return NF_ACCEPT;
	}

	switch (e->status) {
		case  XENLOOP_STATUS_INIT:
			// 如果是初始状态，且本地域ID较小，则发起连接
			if( my_domid < e->domid)  {
				xenloop_listen(e);
			}

			TRACE_EXIT;
			return NF_ACCEPT; // 初始连接时，让第一个包正常发出

		case XENLOOP_STATUS_CONNECTED:
			// 如果已连接，则通过XenLoop发送
			if( xmit_packets(skb) < 0  ) {
				EPRINTK("Couldn't send packet via bififo. Using network instead\n");
				ret = NF_ACCEPT; // 发送失败，则退回正常网络路径
				goto out;
			}
			// DPRINTK("packet transmitted through Xenloop\n");
			ret = NF_STOLEN; // 发送成功，数据包被"窃取"，不再经过网络栈
			break;

		case XENLOOP_STATUS_LISTEN:
		default:
			TRACE_EXIT;
			return ret;
	}
out:
	TRACE_EXIT;
	return ret;
}



/**
 * @brief Netfilter钩子函数，用于截获进入的IP包。
 *
 * @param priv 私有数据。
 * @param skb 数据包。
 * @param state 钩子状态。
 * @return 总是返回 NF_ACCEPT。
 */
static unsigned int iphook_in(
	void* priv,
	struct sk_buff* skb,
	const struct nf_hook_state* state)
{

	Entry * e;
	int ret = NF_ACCEPT;

	// 检查目的IP是否在映射表中
	if(!(e = lookup_table_ip(&ip_domid_map, ip_hdr(skb)->daddr))) {
		return ret;
	}

	// 如果是初始状态且本地域ID较小，发起连接
	// 这是为了处理对端先发起通信的情况
	if ((e->status == XENLOOP_STATUS_INIT) && (my_domid < e->domid))
		xenloop_listen(e);

	TRACE_EXIT;

        return NF_ACCEPT;
}

// hook incoming ARP packets
// if it's resolving a MAC address the dom0 has told us about, add it's IP to the table we check
/**
 * @brief Netfilter钩子函数，用于截获进入的ARP包。
 *
 * @param priv 私有数据。
 * @param skb 数据包。
 * @param state 钩子状态。
 * @return 总是返回 NF_ACCEPT。
 */
static unsigned int arphook_in(void* priv, struct sk_buff* skb,
	 						   const struct nf_hook_state* state) {
	int ret = NF_ACCEPT;
	struct arphdr* hdr;
	Entry* e;
	u32 ip;
	u8* mac;

	hdr = arp_hdr(skb);

	// 只处理IP协议的ARP请求/应答
	if(hdr->ar_pro != htons(ETH_P_IP)) {
		return ret;
	}

	// 从ARP包中提取源MAC地址
	mac = (u8*)(&(hdr->ar_op)) + 2;

	// 检查该MAC地址是否在我们已知的虚拟机列表中
	if(!(e = lookup_table(&mac_domid_map, (void*)(&(hdr->ar_op)) + 2))) {
		return ret;
	}

	// 提取源IP地址
	memcpy((void*)&ip, (void*)(&(hdr->ar_op)) + 2 + ETH_ALEN, 4);

	// 如果该IP不在IP->DomID映射表中，则添加它
	if(NULL == lookup_table_ip(&ip_domid_map, ip)) {
		insert_table_ip(&ip_domid_map, ip, e);
		DPRINTK("Added IP: %u to table\n", ip);
	}

	// NOTE: we now the same entry in our MAC and IP table,
	// the IP table stores a pointer to the Entry allocated by the mac table
	// 注意：现在MAC表和IP表中的同一个条目
	// IP表存储一个指向由MAC表分配的Entry的指针

	return ret;
}



// 定义Netfilter钩子结构
struct nf_hook_ops iphook_in_ops = {
	.hook = iphook_in,
	.pf = PF_INET, // NOTE: this should be NFPROTO_IPV4, which is the same as PF_INET (and the same as AF_INET) however this is hardcoded for both
	// 注意：这里应该是NFPROTO_IPV4，它与PF_INET（以及AF_INET）相同，但这里对两者都进行了硬编码
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = 10,
};

struct nf_hook_ops iphook_out_ops = {
	.hook = iphook_out,
	.pf = PF_INET, // NOTE: should be NFPROTO_IPV4, same reason as with 'iphook_in_ops' above
	// 注意：应该是NFPROTO_IPV4，原因同上'iphook_in_ops'
	.hooknum = NF_INET_LOCAL_OUT, // NOTE: this used to be NF_INET_POST_ROUTING, but since we do IP lookup instead of MAC lookup we can hook further up in the stack
	// 注意：这以前是NF_INET_POST_ROUTING，但由于我们进行IP查找而不是MAC查找，我们可以在协议栈中更早地挂钩
	.priority = 10,
};

struct nf_hook_ops hook_arp_ops = {
	.hook = arphook_in,
	.pf = NFPROTO_ARP,
	.hooknum = NF_ARP_IN,
	.priority = 10,
};

/**
 * @brief 初始化网络相关的部分。
 *
 * @return 成功返回0，失败返回错误码。
 */
int net_init(void)
{
	int ret = 0;

	TRACE_ENTRY;

	// 根据模块参数获取网络设备
	NIC = dev_get_by_name(&init_net, nic);

	if(!NIC) {
		EPRINTK("Could not find network card %s\n", nic);
		ret = -ENODEV;
		goto out;
	}

	DB("Using interface %s, MTU: %d bytes\n", NIC->name, NIC->mtu);

	// 注册Netfilter钩子
	ret = nf_register_net_hook(&init_net, &iphook_out_ops);
	if (ret < 0) {
		EPRINTK("can't register OUT hook.\n");
		goto out;
	}
	ret = nf_register_net_hook(&init_net, &iphook_in_ops);
	if (ret < 0) {
		EPRINTK("can't register OUT hook.\n");
		goto out;
	}
	ret = nf_register_net_hook(&init_net, &hook_arp_ops);
	if (ret < 0) {
		EPRINTK("can't register ARP hook.\n");
		goto out;
	}

	// 注册用于接收会话管理消息的packet_type
	dev_add_pack(&xenloop_ptype);

out:
	TRACE_EXIT;
	return ret;
}

/**
 * @brief 清理网络相关的资源。
 */
void net_exit(void)
{
	TRACE_ENTRY;

	dev_remove_pack(&xenloop_ptype);

	// 注销Netfilter钩子
	nf_unregister_net_hook(&init_net, &iphook_in_ops);
	nf_unregister_net_hook(&init_net, &iphook_out_ops);
	nf_unregister_net_hook(&init_net, &hook_arp_ops);

	if(NIC) dev_put(NIC);

	TRACE_EXIT;
}

/**
 * @brief 在虚拟机迁移前执行的操作。
 */
void pre_migration(void)
{
	TRACE_ENTRY;

	write_xenstore(0); // 通知Dom0本VM将要挂起
	freezed = 1; // 冻结模块活动
	mark_suspend(&mac_domid_map); // 将所有连接标记为挂起

	wake_up_interruptible(&swq); // 唤醒挂起处理线程
	TRACE_EXIT;
	return;
}

/**
 * @brief 在虚拟机迁移后执行的操作。
 */
void post_migration(void)
{
	TRACE_ENTRY;

	freezed = 0; // 解冻模块
	write_xenstore(1); // 通知Dom0本VM已恢复

	TRACE_EXIT;
	return;
}


#define LONG_PENDING_TIMEOUT 1 // seconds
#define SHORT_PENDING_TIMEOUT 1 // jiffies
/**
 * @brief 内核线程函数，用于处理待发送的数据包队列。
 *
 * @param useless 未使用。
 * @return 总是返回0。
 */
static int xmit_pending(void *useless)
{
	unsigned long timeout;
	TRACE_ENTRY;

	while(!kthread_should_stop()) {
		// 根据队列是否为空设置不同的等待超时
		timeout = out_queue.count ? SHORT_PENDING_TIMEOUT : LONG_PENDING_TIMEOUT*HZ;
		// 等待被唤醒或超时
		wait_event_interruptible_timeout(pending_wq, (out_queue.count > 0), timeout);
		// 处理队列中的数据包
		xmit_packets(NULL);
	}
	TRACE_EXIT;
	return 0;
}

#define SUSPEND_TIMEOUT 5
/**
 * @brief 内核线程函数，用于检查和清理挂起的或超时的连接。
 *
 * @param useless 未使用。
 * @return 总是返回0。
 */
static int check_suspend(void *useless) {
	int ret;
	TRACE_ENTRY;

	while(!kthread_should_stop()) {
		// 等待有挂起条目或超时
		ret = wait_event_interruptible_timeout(swq, has_suspend_entry(&mac_domid_map), SUSPEND_TIMEOUT*HZ);
		if (ret > 0) {
			// 如果被唤醒，说明有挂起的条目需要清理
			clean_suspended_entries(&mac_domid_map);
		} else if (ret == 0) {
			// 如果是超时，则检查所有连接是否超时
			check_timeout(&mac_domid_map);
		}
	}
	TRACE_EXIT;
	return 0;
}


/**
 * @brief Xenbus watch回调函数，用于处理挂起/恢复事件。
 *
 * @param watch xenbus_watch结构体。
 * @param path 事件路径。
 * @param token 事件令牌。
 */
static void suspend_resume_handler(struct xenbus_watch *watch,
                             const char *path, const char* token)
{
        char **dir;
        unsigned int i, dir_n;

#define SR_UNDEFINED 0
#define SR_SUSPENDED 1
#define SR_RESUMED 2
	static int cur_state = SR_UNDEFINED;
	int prev_state = cur_state;


	// 首次调用时，初始化状态为RESUMED
	if( prev_state == SR_UNDEFINED ) {
		cur_state = SR_RESUMED;
		return;
	}

        // 检查control目录下的shutdown文件是否存在，以判断是否进入挂起状态
        dir = xenbus_directory(XBT_NIL, "control", "", &dir_n);
        if (IS_ERR(dir)) {
		EPRINTK("ERROR\n");
		return;
	}


	cur_state = SR_RESUMED;
        for (i = 0; i < dir_n; i++) {

		if (strcmp(dir[i], "shutdown") != 0)
			continue;

		cur_state = SR_SUSPENDED;
		break;
	}

	// 如果状态没有变化，则不作处理
	if( prev_state == cur_state)
		goto out;

	// 根据状态变化调用相应的处理函数
	switch(cur_state)  {

	case SR_SUSPENDED:
		pre_migration();
		break;

	case SR_RESUMED:
		post_migration();
		break;

	}

out:
	kfree(dir);
}


// 定义一个xenbus_watch来监控control/shutdown路径
static struct xenbus_watch suspend_resume_watch = {
        .node = "control/shutdown",
        .callback = suspend_resume_handler
};

/**
 * @brief 模块退出函数。
 */
static void xenloop_exit(void)
{

	TRACE_ENTRY;

	write_xenstore(0); // 通知Dom0模块将要卸载
	freezed = 1;

	// 停止内核线程
	if(pending_thread)
		kthread_stop(pending_thread);

	// mark everything as suspended
	// 将所有连接标记为挂起
	mark_suspend(&mac_domid_map);

	if(suspend_thread)
		kthread_stop(suspend_thread);

	// 注销xenbus watch
	unregister_xenbus_watch(&suspend_resume_watch);

	// 清理网络资源
	net_exit();

	// NOTE: we don't clean the IP table since all of it's memory references Entries in the mac table
	// 注意：我们不清理IP表，因为它所有的内存都引用了MAC表中的条目
	// 清理哈希表
	clean_table(&mac_domid_map);

	DPRINTK("Exiting xenloop module.\n");
	TRACE_EXIT;
}


/**
 * @brief 模块初始化函数。
 *
 * @return 成功返回0，失败返回错误码。
 */
static int __init xenloop_init(void)
{
	int rc = 0;

	// 检查是否传入了必要的nic参数
	if(nic == NULL) {
		EPRINTK("no NIC device name passed in as module parameter, exiting\n");
		rc = -EINVAL;
		goto out;
	}

	TRACE_ENTRY;

	// 初始化队列
	out_queue.head = NULL;
	out_queue.tail = NULL;
	out_queue.count = 0;

	pending_free.head = NULL;
	pending_free.tail = NULL;
	pending_free.count = 0;


	// 初始化哈希表
	if(init_hash_table(&mac_domid_map, "MAC_DOMID_MAP_Table") != 0) {
		rc = -ENOMEM;
		goto out;
	}

	// NOTE: this should never fail, since we allocate no memory
	// leave the error check here in case we have a failure case in the future
	// 注意：这应该永远不会失败，因为我们没有分配内存
	// 保留错误检查以防将来出现失败情况
	if(init_hash_table_ip(&ip_domid_map) != 0) {
		rc = -ENOMEM;
		goto out;
	}

	// 获取本地域ID和MAC地址
	my_domid = get_my_domid();
	probe_vifs();

	// 初始化网络
	if ((rc = net_init()) < 0) {
		EPRINTK("session_init(): net_init failed\n");
		clean_table(&mac_domid_map);
		// NOTE: we don't clean the IP table since all of it's memory references Entries in the mac table
		// 注意：我们不清理IP表，因为它所有的内存都引用了MAC表中的条目
		goto out;
	}

	// 向XenStore写入状态
	if((rc = write_xenstore(1))) {
		EPRINTK("Failed to write to xenstore, permissions error?\n");
		net_exit();
		clean_table(&mac_domid_map);
		// NOTE: we don't clean the IP table since all of it's memory references Entries in the mac table
		// 注意：我们不清理IP表，因为它所有的内存都引用了MAC表中的条目
		goto out;
	}

	// 注册xenbus watch
	rc = register_xenbus_watch(&suspend_resume_watch);
        if (rc) {
                EPRINTK("Failed to set shutdown watcher\n");
        }

	// 创建并运行内核线程
	pending_thread = kthread_run(xmit_pending, NULL, "pending");
	if(!pending_thread) {
		xenloop_exit();
		rc = -1;
		goto out;
	}

	suspend_thread = kthread_run(check_suspend, NULL, "suspend");
	if(!suspend_thread) {
		xenloop_exit();
		rc = -1;
		goto out;
	}

	DPRINTK("XENLOOP successfully initialized!\n");

out:
	TRACE_EXIT;
	return rc;
}

module_init(xenloop_init);
module_exit(xenloop_exit);

MODULE_LICENSE("GPL");
