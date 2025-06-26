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



#ifndef _XENFIFO_H_
#define _XENFIFO_H_

#include <xen/xenbus.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>

#include <asm/xen/hypercall.h>
//#include <xen/driver_util.h>
//#include <xen/gnttab.h>
#include <xen/grant_table.h>
//#include <xen/evtchn.h>
#include <xen/events.h>

#include "debug.h"

#define MAX_FIFO_PAGES 64
#define MAX_FIFO_PAGE_ORDER 6

/*
 * 共享 FIFO 描述符页
 * sizeof(xf_descriptor_t) 应该不大于 PAGE_SIZE
 */
struct xf_descriptor {
	u8 suspended_flag;	// 挂起标志，用于暂停 FIFO 操作
	unsigned int num_pages;	// FIFO 缓冲区使用的页数
	int grefs[MAX_FIFO_PAGES]; /* FIFO 页的授权引用(grant references) -- 目前预计页数不多 */
	int dgref;		// 描述符页的授权引用
	uint16_t max_data_entries; /* 最大数据条目数，最大 64K，应为 2 的幂 */
	uint32_t front, back; /* 这两个索引的范围必须是 2 的幂，并且大于 max_data_entries */
	uint32_t index_mask;	// 用于环形缓冲区索引计算的掩码
};
typedef struct xf_descriptor xf_descriptor_t;

/*
 * xf_handle_t 结构体
 * 这是 FIFO 端点的句柄，每个域（domain）都有自己的句柄，不是共享的。
 */
struct xf_handle {

	domid_t remote_id;		// 远程域的 ID
	xf_descriptor_t *descriptor;	// 指向共享描述符的指针（可能是映射过来的）
	void *fifo;			// 指向 FIFO 缓冲区的指针（可能是映射过来的）
	int listen_flag;		// 标志位，1 表示监听端（创建者），0 表示连接端


	// grant_handle_t 用于跟踪映射的授权引用
	grant_handle_t dhandle;		// 描述符页的 grant handle
	grant_handle_t fhandles[MAX_FIFO_PAGES]; // FIFO 数据页的 grant handle 数组

};
typedef struct xf_handle xf_handle_t;

/******************* 监听端函数 *********************************/
// 创建一个 FIFO (由监听端调用)
extern xf_handle_t *xf_create(domid_t remote_domid, unsigned int entry_size, unsigned int entry_order);
// 销毁一个 FIFO (由监听端调用)
extern int xf_destroy(xf_handle_t *xfl);
/******************* 连接端函数 *********************************/
// 连接到一个现有的 FIFO (由连接端调用)
extern xf_handle_t *xf_connect(domid_t remote_domid, int remote_gref);
// 从 FIFO 断开 (由连接端调用)
extern int xf_disconnect(xf_handle_t *xfc);

/************** 监听端和连接端共用的函数 ******************
 * 尽管最好是一端只进行 push/back 操作，另一端只进行 pop/front 操作
 ****************************************************************************/

/*
 * @brief 获取 FIFO 中当前存储的数据条目数量
 * @param h FIFO 句柄
 * @return FIFO 中的数据量
 */
static inline uint32_t xf_size(xf_handle_t *h)
{
	return h->descriptor->back - h->descriptor->front;
}


/*
 * @brief 获取 FIFO 的剩余可用空间（可以容纳的数据条目数量）
 * @param h FIFO 句柄
 * @return FIFO 的可用空间
 */
static inline uint32_t xf_free(xf_handle_t *h)
{
	return  h->descriptor->max_data_entries - xf_size(h);
}

/*
 * @brief 检查 FIFO 是否已满
 * @param h FIFO 句柄
 * @return 如果已满返回 1，否则返回 0
 */
static inline int xf_full(xf_handle_t *h)
{
	return ( xf_size(h) == h->descriptor->max_data_entries );
}

/*
 * @brief 检查 FIFO 是否为空
 * @param h FIFO 句柄
 * @return 如果为空返回 1，否则返回 0
 */
static inline int xf_empty(xf_handle_t *h)
{
	return ( xf_size(h) == 0 );
}

/*
 * @brief 将一个数据条目推入 FIFO 的尾部
 * @param handle FIFO 句柄
 * @return 成功返回 0，失败（FIFO 已满）返回 -1
 */
static inline uint32_t xf_push(xf_handle_t *handle)
{
	xf_descriptor_t *des = handle->descriptor;

	if( xf_full(handle) ) {
		return -1;
	}

	// 增加尾指针，表示一个条目已推入
	des->back++;

	return 0;
}

/*
 * @brief 将 n 个数据条目推入 FIFO 的尾部
 * @param handle FIFO 句柄
 * @param n 要推入的条目数量
 * @return 成功返回 0，失败（空间不足）返回 -1
 */
static inline uint32_t xf_pushn(xf_handle_t *handle, uint32_t n)
{
	xf_descriptor_t *des = handle->descriptor;

	if( xf_free(handle) < n ) {
		return -1;
	}

	// 增加尾指针
	des->back += n;

	return 0;
}

/*
 * @brief 从 FIFO 头部弹出一个数据条目
 * @param handle FIFO 句柄
 * @return 成功返回 0，失败（FIFO 为空）返回 -1
 */
static inline uint32_t xf_pop(xf_handle_t *handle)
{
	xf_descriptor_t *des = handle->descriptor;

	if( xf_empty(handle) ) {
		return -1;
	}

	// 增加头指针，表示一个条目已弹出
	des->front++;

	return 0;
}

/*
 * @brief 从 FIFO 头部弹出 n 个数据条目
 * @param handle FIFO 句柄
 * @param n 要弹出的条目数量
 * @return 成功返回 0，失败（数据不足）返回 -1
 */
static inline uint32_t xf_popn(xf_handle_t *handle, uint32_t n)
{
	xf_descriptor_t *des = handle->descriptor;

	if( xf_size(handle) < n ) {
		return -1;
	}

	// 增加头指针
	des->front += n;

	return 0;
}

/*
 * @brief 返回指向 FIFO 尾部空闲数据位置的引用
 * @note xf_back 不会从 FIFO 中移除数据，需要调用 xf_push 来完成入队操作
 * @param handle FIFO 句柄
 * @param type 数据类型
 * @return 如果 FIFO 已满则返回 NULL，否则返回指向尾部条目的指针
 */
#define xf_back(handle, type) (  					\
{ 									\
type * _xf_ret;								\
do									\
{									\
	xf_descriptor_t *_xf_des = handle->descriptor;			\
	type *_xf_fifo = (type *)handle->fifo;				\
									\
	if( xf_full(handle) ) {						\
		_xf_ret = NULL;						\
		break;							\
	}								\
									\
	/* 使用掩码计算环形缓冲区的实际索引 */					\
	_xf_ret = &_xf_fifo[_xf_des->back & _xf_des->index_mask];	\
 									\
} while (0);								\
_xf_ret;								\
}									\
)

/*
 * @brief 返回指向 FIFO 头部数据条目的引用
 * @note xf_front 不会从 FIFO 中移除数据，需要调用 xf_pop 来完成出队操作
 * @param handle FIFO 句柄
 * @param type 数据类型
 * @return 如果 FIFO 为空则返回 NULL，否则返回指向头部条目的指针
 */
#define xf_front(handle, type) (  				\
{ 									\
type * _xf_ret;								\
do									\
{									\
	xf_descriptor_t *_xf_des = handle->descriptor;			\
	type *_xf_fifo = (type *)handle->fifo;				\
									\
	if( xf_empty(handle) ) {					\
		_xf_ret = NULL;						\
		break;							\
	}								\
									\
	/* 使用掩码计算环形缓冲区的实际索引 */					\
	_xf_ret = &_xf_fifo[_xf_des->front & _xf_des->index_mask];	\
 									\
} while (0);								\
_xf_ret;								\
}									\
)

/*
 * @brief 返回指向 FIFO 中指定索引位置的条目的指针
 * @note 不检查索引是否在 front 和 back 指针之间
 * @param handle FIFO 句柄
 * @param type 数据类型
 * @param index 从 front 开始的偏移量
 * @return 指向指定条目的指针
 */
#define xf_entry(handle, type, index) (					\
{ 									\
type * _xf_ret;								\
do									\
{									\
	xf_descriptor_t *_xf_des = handle->descriptor;			\
	type *_xf_fifo = (type *)handle->fifo;				\
									\
	/* 计算从 front 开始第 index 个条目的实际位置 */			\
	_xf_ret = &_xf_fifo[ (_xf_des->front + index) & _xf_des->index_mask]; \
 									\
} while (0);								\
_xf_ret;								\
}									\
)

#endif // _XENFIFO_H_
