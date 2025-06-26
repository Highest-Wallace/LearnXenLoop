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


#ifndef BIFIFO_H
#define BIFIFO_H

#include "xenfifo.h"

// 定义 bf_data_t 的类型
#define BF_PACKET 0	// 数据包
#define BF_RESPONSE 1	// 响应

// 定义 bf_data_t 的状态
#define BF_WAITING 0	// 等待处理
#define BF_PROCESSING 1	// 正在处理
#define BF_FREE 2	// 空闲

/*
 * @brief FIFO 中传输的数据单元结构体
 * @note 请不要使用指针，因为数据是直接复制到 FIFO 中供另一个域读取的。
 * 	尽量保持 sizeof(bf_data_t) 是 2 的幂，因为它需要适应 2^page_order 的页面大小。
 */
struct bf_data {
	uint8_t type;		// 数据类型 (BF_PACKET 或 BF_RESPONSE)
	uint16_t status;	// 状态 (BF_WAITING, BF_PROCESSING, BF_FREE)
	uint32_t pkt_info;	// 包信息，通常是包的长度
};
typedef struct bf_data bf_data_t;

/*
 * @brief 双向 FIFO 句柄结构体
 * 	包含一个输入 FIFO 和一个输出 FIFO，以及事件通道信息
 */
struct bf_handle {
	domid_t remote_domid;	// 远程域 ID
	xf_handle_t *out;	// 输出 FIFO (从本域到远程域)
	xf_handle_t *in;	// 输入 FIFO (从远程域到本域)
	uint32_t port;		// 本地域的事件通道端口
	int irq;			// 绑定到事件通道的 IRQ
};
typedef struct bf_handle bf_handle_t;

// 宏定义，用于方便地访问 bf_handle_t 的成员
#define BF_GREF_IN(handle) (handle->in->descriptor->dgref)	// 获取输入 FIFO 的 grant reference
#define BF_GREF_OUT(handle) (handle->out->descriptor->dgref)	// 获取输出 FIFO 的 grant reference
#define BF_SUSPEND_IN(handle) (handle->in->descriptor->suspended_flag) // 检查输入 FIFO 是否挂起
#define BF_SUSPEND_OUT(handle) (handle->out->descriptor->suspended_flag)// 检查输出 FIFO 是否挂起
#define BF_EVT_PORT(handle) (handle->port)			// 获取事件通道端口
#define BF_EVT_IRQ(handle) (handle->irq)			// 获取事件通道 IRQ

// 监听端函数：创建一个双向 FIFO
extern bf_handle_t *bf_create(domid_t, int);
// 连接端函数：连接到一个已存在的双向 FIFO
extern bf_handle_t *bf_connect(domid_t, int, int, uint32_t);
// 监听端函数：销毁一个双向 FIFO
extern void bf_destroy(bf_handle_t *);
// 连接端函数：断开一个双向 FIFO 连接
extern void bf_disconnect(bf_handle_t *);
// 发送事件通知到指定的端口
extern void bf_notify(uint32_t port);
// 事件通道中断回调函数
extern irqreturn_t bf_callback(int rq, void *dev_id);
// 虚拟机迁移时保存状态
extern void migrate_save(void *);
// 虚拟机迁移时发送状态
extern void migrate_send(void);

// XenLoop 连接状态定义
#define XENLOOP_STATUS_INIT 	1	// 初始状态
#define XENLOOP_STATUS_LISTEN 	2	// 监听状态
#define XENLOOP_STATUS_CONNECTED 4	// 已连接状态
#define XENLOOP_STATUS_SUSPEND   8	// 挂起状态

/*
 * @brief 连接条目结构体
 * 	用于在哈希表中存储每个连接的信息
 */
typedef struct Entry {
	struct list_head mapping;	// 用于哈希表链表
	struct list_head ip_mapping;	// 用于 IP 映射链表
	u8		mac[ETH_ALEN];	// 远程域的 MAC 地址
	u32		ip;		// 远程域的 IP 地址
	u8		status;		// 连接状态 (XENLOOP_STATUS_*)
	u8		listen_flag;	// 是否为监听端
	u8		retry_count;	// 重试计数
	domid_t		domid;		// 远程域 ID
	ulong		timestamp;	// 时间戳
	u8 del_timer;		// 是否删除定时器
	struct timer_list ack_timer;	// ACK 定时器
	bf_handle_t 	*bfh;		// 指向双向 FIFO 句柄的指针
} Entry;


#endif // BIFIFO_H
