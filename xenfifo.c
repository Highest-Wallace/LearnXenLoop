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


#include "debug.h"
#include "xenfifo.h"
#include <linux/vmalloc.h>

/*
 * @brief 创建一个 FIFO 的监听端，远程域可以连接到该监听端。
 * 	由 FIFO 的监听端调用。
 *
 * @param remote_domid - 允许连接的远程域的 ID。
 * @param entry_size - FIFO 中每个条目的大小。
 * @param entry_order - FIFO 的最大容量，以 2 的幂表示。当前最大为 256。最大大小 = 2^16。
 *
 * @return 指向共享 FIFO 结构的指针，失败则返回 NULL。
 */
xf_handle_t *xf_create(domid_t remote_domid, unsigned int entry_size, unsigned int entry_order)
{
	// 计算 FIFO 缓冲区所需的内存页阶数
	unsigned long page_order = get_order(entry_size*(1<<entry_order));
	xf_handle_t * xfl = NULL;
	int i;

	TRACE_ENTRY;

	if (entry_order > 16) {
		EPRINTK("More than 64K entries requested\n");
		goto err;
	}

	// 确保描述符结构的大小不超过一个页
	if( sizeof(xf_descriptor_t) > PAGE_SIZE)
		BUG();


	// 检查请求的页数是否超过最大限制
	if( page_order > MAX_FIFO_PAGE_ORDER) {
		EPRINTK("%d > 2^MAX_PAGE_ORDER pages requested for FIFO\n", 1<<page_order);
		goto err;
	}

	// 为 FIFO 句柄分配内存
	xfl = kmalloc(sizeof(xf_handle_t), GFP_ATOMIC);
	if(!xfl) {
		EPRINTK("Out of memory\n");
		goto err;
	}
	memset(xfl, 0, sizeof(xf_handle_t));


	// 为 FIFO 描述符分配一页内存
	xfl->descriptor = (xf_descriptor_t*) kmalloc(PAGE_SIZE, GFP_ATOMIC);
	if(!xfl->descriptor) {
		EPRINTK("Cannot allocate descriptor memory page for FIFO\n");
		goto err;
	}
	// 设置 FIFO 缓冲区占用的页数
	xfl->descriptor->num_pages = (1<<page_order);

	// 为 FIFO 缓冲区分配内存
	xfl->fifo = (void*) kmalloc(xfl->descriptor->num_pages * PAGE_SIZE, GFP_ATOMIC);
	if(!xfl->fifo) {
		EPRINTK("Cannot allocate buffer memory pages for FIFO\n");
		goto err;
	} else {
		DPRINTK("Allocated %u memory pages for FIFO\n", (1<<page_order));
	}


	// 初始化句柄和描述符
	xfl->listen_flag = 1; // 标记为监听端
	xfl->remote_id = remote_domid;
	xfl->descriptor->suspended_flag = 0;
	xfl->descriptor->max_data_entries = (1<<entry_order);
	xfl->descriptor->index_mask = ~(0xffffffff<<entry_order);
	xfl->descriptor->front = xfl->descriptor->back = 0;

	// 授予远程域对描述符页的访问权限
	xfl->descriptor->dgref = gnttab_grant_foreign_access(remote_domid, virt_to_mfn(xfl->descriptor), 0);
	if ( xfl->descriptor->dgref < 0) {
		EPRINTK("Cannot share descriptor gref page %p\n", xfl->descriptor);
		goto err;
	}

	// 授予远程域对每个 FIFO 缓冲区页的访问权限
	for( i=0; i < xfl->descriptor->num_pages; i++) {

		xfl->descriptor->grefs[i] =
				gnttab_grant_foreign_access(remote_domid,
						virt_to_mfn(((uint8_t *)xfl->fifo) + i*PAGE_SIZE), 0);

		if ( xfl->descriptor->grefs[i] < 0) {
			EPRINTK("Cannot share FIFO %p page %d\n", xfl->fifo, i);
			// 如果授权失败，撤销已经授予的权限
			while(--i) gnttab_end_foreign_access_ref(xfl->descriptor->grefs[i], 0);
			gnttab_end_foreign_access_ref(xfl->descriptor->dgref, 0);
			goto err;
		}
	}

	TRACE_EXIT;
	return xfl;

err:
	// 错误处理：释放所有已分配的资源
	if( xfl) {
		if(xfl->fifo) {
			kfree(xfl->fifo);
		}

		if(xfl->descriptor) {
			kfree(xfl->descriptor);
		}

		kfree(xfl);
	}

	TRACE_ERROR;
	return NULL;
}

/*
 * @brief 销毁 FIFO
 * 	只能由创建者（监听端）调用
 *
 * @param xfl 要销毁的 FIFO 的句柄
 * @return 成功返回 0，失败返回 -1
 */
int xf_destroy(xf_handle_t *xfl)
{
	int i;
	unsigned int num_pages;
	// 临时存储 grefs，因为 xfl->descriptor 即将被释放
	int grefs[MAX_FIFO_PAGES];
	int dgref;

	TRACE_ENTRY;

	if(!xfl || !xfl->descriptor || !xfl->fifo) {
		EPRINTK("xfl OR descriptor OR fifo is NULL\n");
		goto err;
	}

	num_pages = xfl->descriptor->num_pages;

	// 复制 grefs，以便在释放描述符后仍能使用它们
	for(i=0; i < num_pages; i++) {
		grefs[i] = xfl->descriptor->grefs[i];
	}
	dgref = xfl->descriptor->dgref;

	// 释放内存
	kfree(xfl->fifo);
	kfree(xfl->descriptor);
	kfree(xfl);

	// 结束对 FIFO 缓冲区页的外部访问授权
	for(i=0; i < num_pages; i++) {
		gnttab_end_foreign_access_ref(grefs[i], 0);
	}
	// 结束对描述符页的外部访问授权
	gnttab_end_foreign_access_ref(dgref, 0);

	TRACE_EXIT;
	return 0;

err:
	TRACE_ERROR;
	return -1;
}


/*
 * @brief 连接到另一个域上的 FIFO 监听端
 * @param remote_domid 监听端所在的远程域 ID
 * @param remote_gref 远程域共享的描述符页的 grant reference
 * @return 连接成功则返回 FIFO 句柄，否则返回 NULL
 */

xf_handle_t *xf_connect(domid_t remote_domid, int remote_gref)
{
	xf_handle_t *xfc = NULL;
	struct gnttab_map_grant_ref map_op;
	int ret;
	int i;
	TRACE_ENTRY;

	// 为连接端的 FIFO 句柄分配内存
	xfc = kmalloc(sizeof(xf_handle_t), GFP_ATOMIC);
	if(!xfc) {
		EPRINTK("Out of memory\n");
		goto err;
	}
	memset(xfc, 0, sizeof(xf_handle_t));

	// 为本地描述符指针分配一页内存
	xfc->descriptor = (xf_descriptor_t*) kmalloc(PAGE_SIZE, GFP_ATOMIC);

	if(!xfc->descriptor) {
		EPRINTK("Cannot allocate memory page for descriptor\n");
		goto err;
	}

	// 将我们本地的描述符页映射到对方客户虚拟机与我们共享的描述符页
	gnttab_set_map_op(&map_op, (unsigned long)xfc->descriptor,
				GNTMAP_host_map, remote_gref, remote_domid);
	ret = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &map_op, 1);
	if( ret || (map_op.status != GNTST_okay) ) {
		EPRINTK("HYPERVISOR_grant_table_op failed ret = %d status = %d\n", ret, map_op.status);
		goto err;
	}

	// 初始化句柄
	xfc->listen_flag = 0; // 标记为连接端
	xfc->remote_id = remote_domid;
	xfc->dhandle = map_op.handle; // 保存描述符页的映射句柄

	// 根据描述符中记录的页数，为本地 FIFO 缓冲区分配内存
	xfc->fifo = (void*) kmalloc(xfc->descriptor->num_pages * PAGE_SIZE, GFP_ATOMIC);

	if(!xfc->fifo) {
		EPRINTK("Cannot allocate %u memory pages for FIFO\n", xfc->descriptor->num_pages);
		goto err;
	} else {
		DPRINTK("Allocated %u memory pages for FIFO\n", xfc->descriptor->num_pages);
	}

	// 将客户虚拟机的 FIFO 页映射到我们自己的页上
	for(i=0; i < xfc->descriptor->num_pages; i++) {
		gnttab_set_map_op(&map_op,
				(unsigned long)(xfc->fifo + i*PAGE_SIZE),
				GNTMAP_host_map, xfc->descriptor->grefs[i], remote_domid);

		ret = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &map_op, 1);

		if( ret || (map_op.status != GNTST_okay) ) {
			// 如果映射失败，需要取消所有已建立的映射
			struct gnttab_unmap_grant_ref unmap_op;

			EPRINTK("HYPERVISOR_grant_table_op failed ret = %d status = %d\n", ret, map_op.status);
			while(--i >= 0) {
				gnttab_set_unmap_op(&unmap_op,
					(unsigned long)xfc->fifo + i*PAGE_SIZE,
					GNTMAP_host_map, xfc->fhandles[i]);
				ret = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &unmap_op, 1);
				if( ret )
					EPRINTK("HYPERVISOR_grant_table_op unmap failed ret = %d \n", ret);
			}

			gnttab_set_unmap_op(&unmap_op,
				(unsigned long)xfc->descriptor,
				GNTMAP_host_map, xfc->dhandle);
			ret = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &unmap_op, 1);
			if( ret )
				EPRINTK("HYPERVISOR_grant_table_op unmap failed ret = %d \n", ret);

			goto err;
		}

		// 保存 FIFO 缓冲区页的映射句柄
		xfc->fhandles[i] = map_op.handle;
	}

	TRACE_EXIT;
	return xfc;

err:
	// 错误处理：释放所有已分配的资源
	if(xfc) {
		if(xfc->fifo) {
			kfree(xfc->fifo);
		}

		if(xfc->descriptor) {
			kfree(xfc->descriptor);
		}

		kfree(xfc);
	}
	TRACE_ERROR;
	return NULL;
}

/*
 * @brief 断开与 FIFO 的连接
 * @param xfc 要断开的 FIFO 的句柄
 * @return 成功返回 0，失败返回 -1
 */
int xf_disconnect(xf_handle_t *xfc)
{
	struct gnttab_unmap_grant_ref unmap_op;
	int i, ret;
	TRACE_ENTRY;

	if(!xfc || !xfc->descriptor || !xfc->fifo) {
		EPRINTK("Something is NULL\n");
		goto err;
	}

	DPRINTK("descriptor: %p\n", xfc->descriptor);

	// 取消对 FIFO 缓冲区页的映射
	for(i=0; i < xfc->descriptor->num_pages; i++) {
		gnttab_set_unmap_op(&unmap_op, (unsigned long)(xfc->fifo + i*PAGE_SIZE),
			GNTMAP_host_map, xfc->fhandles[i]);
		ret = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &unmap_op, 1);
		if( ret )
			EPRINTK("HYPERVISOR_grant_table_op unmap failed for fifo page %d ret = %d \n", i, ret);
	}

	// 取消对描述符页的映射
	gnttab_set_unmap_op(&unmap_op, (unsigned long)xfc->descriptor,
			GNTMAP_host_map, xfc->dhandle);
	ret = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &unmap_op, 1);
	if( ret )
		EPRINTK("HYPERVISOR_grant_table_op unmap failed ret = %d \n", ret);

	// 根据 KEDR (内存泄漏检查工具) 的说法，这些页面没有被释放
	kfree((void*)(xfc->descriptor)); // BUG 在这里，这似乎会导致页错误，或者稍后在 check_suspended_entries 中出现页错误
	kfree((void*)xfc);
	kfree(xfc->fifo);
	// c2109347fac5445c03297c6354719dd220f782dc 这个提交似乎在这个问题上要少一些？
	// 现在它在卸载时会产生页错误

	TRACE_EXIT;
	return 0;

err:
	TRACE_ERROR;
	return -1;
}
