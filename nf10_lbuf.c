/*******************************************************************************
*
*  NetFPGA-10G http://www.netfpga.org
*
*  File:
*        nf10_lbuf.c
*
*  Project:
*
*
*  Author:
*        Hwanju Kim
*
*  Description:
*	 This is the large-buffer (lbuf) DMA-dependent module, an implementation
*	 of hw_ops (lbuf_hw_ops) of nf10_adapter. For RX, the implementation is 
*	 by default use a 2MB hugepage taking advantage of architectual support.
*	 A huge buffer is not pre-sliced and provided to NetFPGA per huge page
*	 basis. DMA packs the packets in the buffer and an interrupt is 
*	 generated once the buffer is filled up. For TX, although lbuf can also
*	 be used, currently transmission is conducted for each packet. Later on,
*	 it can be optimized. Regarding TX, there is some restriction enforced by
*	 DMA for now such as dword-aligned and headroom for metadata, which
*	 contains nf10 port and packet length. This restriction leads to adding
*	 some software overheads of copy-and-expand skb. It could be relieved by
*	 using lbuf at TX side as well.
*
*	 This code is initially developed for the Network-as-a-Service (NaaS) project.
*	 (under development in https://github.com/NetFPGA-NewNIC/linux-driver)
*
*  Copyright notice:
*        Copyright (C) 2014 University of Cambridge
*
*  Licence:
*        This file is part of the NetFPGA 10G development base package.
*
*        This file is free code: you can redistribute it and/or modify it under
*        the terms of the GNU Lesser General Public License version 2.1 as
*        published by the Free Software Foundation.
*
*        This package is distributed in the hope that it will be useful, but
*        WITHOUT ANY WARRANTY; without even the implied warranty of
*        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
*        Lesser General Public License for more details.
*
*        You should have received a copy of the GNU Lesser General Public
*        License along with the NetFPGA source package.  If not, see
*        http://www.gnu.org/licenses/.
*
*/

#include <linux/etherdevice.h>
#include "nf10.h"
#include "nf10_lbuf.h"
#include "nf10_lbuf_api.h"
#include "nf10_user.h"

static struct kmem_cache *desc_cache;

static struct lbuf_info {
	struct nf10_adapter *adapter;
	struct desc *rx_desc[NR_SLOT];
	struct lbuf_user *u;

	/* tx completion buffer */
	void *tx_completion_kern_addr;
	dma_addr_t tx_completion_dma_addr;
} lbuf_info;

/* 
 * helper macros for prod/cons pointers and descriptors
 */
#define rx_idx()		(lbuf_info.u->rx_idx)
#define tx_idx()		(lbuf_info.u->tx_idx)
#define inc_rx_idx()		inc_idx(rx_idx())
#define inc_tx_idx()		inc_idx(tx_idx())

#define get_rx_desc(idx)	(lbuf_info.rx_desc[idx])
#define set_rx_desc(idx, d)	do { lbuf_info.rx_desc[idx] = d; } while(0)
#define cur_rx_desc()		get_rx_desc(rx_idx())

#define get_tx_completion(idx)	(((u32 *)lbuf_info.tx_completion_kern_addr)[idx])
#define get_tx_avail(idx)	(get_tx_completion(idx) == TX_AVAIL)
#define set_tx_avail(idx)	do { get_tx_completion(idx) = TX_AVAIL; } while(0)
#define set_tx_used(idx)	do { get_tx_completion(idx) = TX_USED; } while(0)

/* following get/set accessors are for pointer management inside a lbuf */
#define get_rx_cons()		(lbuf_info.u->rx_cons)
#define set_rx_cons(v)		do { lbuf_info.u->rx_cons = v; } while(0)

#define get_tx_prod()		(lbuf_info.u->tx_prod)
#define set_tx_prod(v)		do { lbuf_info.u->tx_prod = v; } while(0)
#define get_tx_prod_pvt()	(lbuf_info.u->tx_prod_pvt)
#define set_tx_prod_pvt(v)	do { lbuf_info.u->tx_prod_pvt = v; } while(0)
#define get_tx_cons()		(lbuf_info.u->tx_cons)
#define set_tx_cons(v)		do { lbuf_info.u->tx_cons = v; } while(0)
#define tx_clean_completed()	(get_tx_prod() == get_tx_cons())

#define get_tx_writeback()	(lbuf_info.u->tx_writeback)
#define get_rx_writeback()	(lbuf_info.u->rx_writeback)
#define set_tx_writeback(v)	do { lbuf_info.u->tx_writeback = (unsigned long)v; } while(0)
#define set_rx_writeback(v)	do { lbuf_info.u->rx_writeback = (unsigned long)v; } while(0)

#define lbuf_cb(skb)		(*(u64 *)&((skb)->cb[32]))
#define get_tx_last_gc_addr()	ACCESS_ONCE(*(u64 *)(lbuf_info.tx_completion_kern_addr + TX_LAST_GC_ADDR_OFFSET))

spinlock_t tx_lock;

/* tx buffer */
struct desc *active_tx_lbuf;
struct desc *main_tx_lbuf;

#if 0
/* tx buffers reserved for user space */
struct desc *tx_user_lbufs[NR_TX_USER_LBUF];
/* to distinguish user and kernel tx buffers, reuse skb by making
 * skb and kern_addr equal */
#define is_user_lbuf(desc)	(desc->kern_addr == desc->skb)
static inline void make_user_lbuf(struct desc *desc)
{
	desc->skb = desc->kern_addr;
	LBUF_SET_TX_AVAIL(desc->kern_addr);
}
#endif

/* default tx buffer size for kernel space */
#define DEFAULT_TX_LBUF_SIZE	(128*1024)

/* profiling memcpy performance */
#ifdef CONFIG_PROFILE
/* WARN: note that it does not do bound check for performance */
#define DEFINE_TIMESTAMP(n)	u64	_t1, _t2, _total[n] = {0}
#define START_TIMESTAMP(i)	rdtscll(_t1)
#define STOP_TIMESTAMP(i)	\
	do {	\
		rdtscll(_t2);	\
		_total[i] += (_t2 - _t1);	\
	} while(0)
#define ELAPSED_CYCLES(i)	(_total[i])
#else
#define DEFINE_TIMESTAMP(n)
#define START_TIMESTAMP(i)
#define STOP_TIMESTAMP(i)
#define ELAPSED_CYCLES(i)	(0ULL)
#endif

/*
 * Memory allocation/free functions:
 */
static inline void *__alloc_lbuf(struct nf10_adapter *adapter,
			       struct desc *desc, u32 size)
{
	desc->kern_addr = pci_alloc_consistent(adapter->pdev, size,
					       &desc->dma_addr);
	desc->size = size;
	skb_queue_head_init(&desc->skbq);

	return desc->kern_addr;
}

static inline void __free_lbuf(struct nf10_adapter *adapter, struct desc *desc)
{
	pci_free_consistent(adapter->pdev, desc->size,
			    desc->kern_addr, desc->dma_addr);
}

static struct desc *alloc_desc(void)
{
	return kmem_cache_alloc(desc_cache, GFP_ATOMIC);
}

static void __free_desc(struct desc *desc)
{
	kmem_cache_free(desc_cache, desc);
}

static struct desc *alloc_lbuf(struct nf10_adapter *adapter, unsigned long size)
{
	struct desc *desc = alloc_desc();

	if (unlikely(!desc))
		return NULL;

	if (unlikely(!__alloc_lbuf(adapter, desc, size))) {
		__free_desc(desc);
		return NULL;
	}
	netif_dbg(adapter, drv, default_netdev(adapter),
		  "%s: addr=(kern=%p:dma=%p)\n", __func__,
		  desc->kern_addr, (void *)desc->dma_addr);
	return desc;
}

static void free_lbuf(struct nf10_adapter *adapter, struct desc *desc)
{
	if (unlikely(desc == NULL))
		return;

	netif_dbg(adapter, drv, default_netdev(adapter), 
		"%s: addr=(kern=%p:dma=%p)\n", __func__,
		desc->kern_addr, (void *)desc->dma_addr);

	__free_lbuf(adapter, desc);
	__free_desc(desc);
}

void lbuf_queue_tail(struct lbuf_head *head, struct desc *desc)
{
	spin_lock(&head->lock);
	__lbuf_queue_tail(head, desc);
	spin_unlock(&head->lock);
}

void lbuf_queue_head(struct lbuf_head *head, struct desc *desc)
{
	/* no need of lockless currently */
	spin_lock(&head->lock);
	__lbuf_queue_head(head, desc);
	spin_unlock(&head->lock);
}

struct desc *lbuf_dequeue(struct lbuf_head *head)
{
	struct desc *desc;

	spin_lock(&head->lock);
	desc = __lbuf_dequeue(head);
	spin_unlock(&head->lock);

	return desc;
}

static void enable_irq(struct nf10_adapter *adapter)
{
	if (get_tx_writeback())
		nf10_writeq(adapter, TX_WRITEBACK_REG, get_tx_writeback());
	if (get_rx_writeback())
		nf10_writeq(adapter, RX_WRITEBACK_REG, get_rx_writeback());
	wmb();
	nf10_writel(adapter, IRQ_ENABLE_REG, IRQ_CTRL_VAL);
	netif_dbg(adapter, intr, default_netdev(adapter),
		  "enable_irq (wb=[tx:%p,rx:%p])\n",
		  (void *)get_tx_writeback(), (void *)get_rx_writeback());
}

static void disable_irq(struct nf10_adapter *adapter)
{
	nf10_writel(adapter, IRQ_DISABLE_REG, IRQ_CTRL_VAL);
	netif_dbg(adapter, intr, default_netdev(adapter), "disable_irq\n");
}

void (*irq_ctrl_handlers[NR_IRQ_CTRL])(struct nf10_adapter *adapter) = {
	[IRQ_CTRL_ENABLE]	= enable_irq,
	[IRQ_CTRL_DISABLE]	= disable_irq,
};

static int init_tx_lbufs(struct nf10_adapter *adapter)
{
	int i;

	BUG_ON(main_tx_lbuf);
	if (!(main_tx_lbuf = alloc_lbuf(adapter, LBUF_TX_SIZE)))
		return -ENOMEM;
	active_tx_lbuf = main_tx_lbuf;

	/* tx completion DMA-coherent buffer */
	lbuf_info.tx_completion_kern_addr =
		pci_alloc_consistent(adapter->pdev, TX_COMPLETION_SIZE,
				     &lbuf_info.tx_completion_dma_addr);

	if (lbuf_info.tx_completion_kern_addr == NULL) {
		free_lbuf(adapter, main_tx_lbuf);
		return -ENOMEM;
	}

	for (i = 0; i < NR_SLOT; i++)
		set_tx_avail(i);

	nf10_writeq(adapter, TX_COMPLETION_ADDR,
		    lbuf_info.tx_completion_dma_addr);
	return 0;
}

static void free_tx_lbufs(struct nf10_adapter *adapter)
{
	free_lbuf(adapter, main_tx_lbuf);
	active_tx_lbuf = main_tx_lbuf = NULL;
	pci_free_consistent(adapter->pdev, TX_COMPLETION_SIZE,
			    lbuf_info.tx_completion_kern_addr,
			    lbuf_info.tx_completion_dma_addr);
}

static void nf10_lbuf_prepare_rx(struct nf10_adapter *adapter, unsigned long idx)
{
	void *kern_addr;
	dma_addr_t dma_addr;
	struct desc *desc;

	/* sanity check due to malicious user-driven preparation */
	if (unlikely(idx >= NR_SLOT)) {
		pr_err("%s: invalid desc index(=%lu)\n", __func__, idx);
		return;
	}
	desc = get_rx_desc(idx);
	if (unlikely(desc->kern_addr == NULL)) {
		pr_err("%s: desc->kern_addr is NULL\n", __func__);
		return;
	}

	kern_addr = desc->kern_addr;
	dma_addr = desc->dma_addr;

	nf10_writeq(adapter, rx_addr_off(idx), dma_addr);
	nf10_writel(adapter, rx_stat_off(idx), RX_READY);

	netif_dbg(adapter, rx_status, default_netdev(adapter),
		  "RX lbuf[%lu] is prepared to nf10\n", idx);
}

static void nf10_lbuf_prepare_rx_all(struct nf10_adapter *adapter)
{
	unsigned long i;

	netif_dbg(adapter, drv, default_netdev(adapter),
		  "init to prepare all rx descriptors\n");
	for (i = 0; i < NR_SLOT; i++)
		nf10_lbuf_prepare_rx(adapter, i);

	set_rx_cons(NR_RESERVED_DWORDS);
}

static void free_rx_lbufs(struct nf10_adapter *adapter)
{
	int i;

	for (i = 0; i < NR_SLOT; i++) {
		struct desc *desc = get_rx_desc(i);
		if (desc) {
			netif_info(adapter, drv, default_netdev(adapter),
				   "RX lbuf[%d] is freed from kern_addr=%p",
				   i, desc->kern_addr);
			free_lbuf(adapter, desc);
			set_rx_desc(i, NULL);
		}
	}
}

static int init_rx_lbufs(struct nf10_adapter *adapter)
{
	int i;

	for (i = 0; i < NR_SLOT; i++) {
		/* RX desc is normally allocated once and used permanently
		 * unlike RX lbuf */
		struct desc *desc;

		BUG_ON(get_rx_desc(i));	/* ensure unused desc is NULL */
		desc = alloc_lbuf(adapter, LBUF_RX_SIZE);
		if (unlikely(!desc))
			goto alloc_fail;
		set_rx_desc(i, desc);

		netif_info(adapter, probe, default_netdev(adapter),
			   "RX lbuf[%d] allocated at kern_addr=%p/dma_addr=%p"
			   " (size=%u bytes)\n", i,
			   desc->kern_addr, (void *)desc->dma_addr, desc->size);
	}
	nf10_lbuf_prepare_rx_all(adapter);

	nf10_writel(adapter, IRQ_PERIOD_REG, 200000);	/* XXX: irq inter-arrival is 200us */
	return 0;

alloc_fail:
	free_rx_lbufs(adapter);
	return -ENOMEM;
}

static u64 nf10_lbuf_user_init(struct nf10_adapter *adapter)
{
	netif_dbg(adapter, drv, default_netdev(adapter),
		  "user request to initialize rx\n");

	adapter->nr_user_mmap = 0;

	return 0;
}

#if 0	/* extra_tx_buf */
static unsigned long get_tx_user_lbuf(int idx, unsigned long size)
{
	struct desc *desc;

	if (unlikely(idx >= NR_TX_USER_LBUF)) {
		pr_err("%s: idx(=%d) >= %d\n", __func__, idx, NR_TX_USER_LBUF);
		return 0;
	}

	desc = tx_user_lbufs[idx];
	/* reuse tx buffer if existing lbuf >= requested size */
	if (!desc || desc->size < size) {
		put_tx_lbuf(desc);
		if ((desc = get_tx_lbuf(size)) == NULL) {
			pr_err("%s: failed to allocate tx_user_lbufs[%d]\n",
			       __func__, idx);
			return 0;
		}
		tx_user_lbufs[idx] = desc;
	}
	make_user_lbuf(desc);
	smp_wmb();

	return virt_to_phys(desc->kern_addr) >> PAGE_SHIFT;
	return 0;
}

static void put_tx_user_lbuf(int idx)
{
	if (idx >= NR_TX_USER_LBUF || !tx_user_lbufs[idx])
		return;
	put_tx_lbuf(tx_user_lbufs[idx]);
	tx_user_lbufs[idx] = NULL;
}

static void free_tx_user_buffers(void)
{
	int i;
	for (i = 0; i < NR_TX_USER_LBUF; i++)
		put_tx_user_lbuf(i);
}
#endif

static unsigned long nf10_lbuf_get_pfn(struct nf10_adapter *adapter,
				       unsigned long size)
{
	unsigned int idx = adapter->nr_user_mmap;
	unsigned long pfn = 0;	/* 0 means error */

	if (idx == 0) {		/* metadata page */
		pfn = virt_to_phys(lbuf_info.u) >> PAGE_SHIFT;
		netif_dbg(adapter, drv, default_netdev(adapter),
			  "%s: [%u] DMA metadata page (pfn=%lx)\n",
			  __func__, idx, pfn);
	}
	else {			/* data pages */
		idx--;	/* adjust index to data */
		if (idx < NR_SLOT && size == LBUF_RX_SIZE)	/* rx */
			pfn = get_rx_desc(idx)->dma_addr >> PAGE_SHIFT;
		else if (idx == NR_SLOT && size == LBUF_TX_SIZE)
			pfn = main_tx_lbuf->dma_addr >> PAGE_SHIFT;
		/* TODO: extra_tx_buf */
			
		netif_dbg(adapter, drv, default_netdev(adapter),
			  "%s: [%u] data page (pfn=%lx size=%lu)\n",
			  __func__, adapter->nr_user_mmap, pfn, size);
	}
	return pfn;
}

static int lbuf_xmit(struct nf10_adapter *adapter, struct desc *desc);
static int nf10_lbuf_user_xmit(struct nf10_adapter *adapter, unsigned long arg)
{
	struct desc *desc;
	
	netif_dbg(adapter, drv, default_netdev(adapter),
		  "user_xmit: arg=%lx\n", arg);

	/* TODO: extra_tx_buf, now only supports main_tx_lbuf 
	 * - ref bound check */
	desc = main_tx_lbuf;
	lbuf_xmit(adapter, desc);

	return 0;
#if 0
	if (unlikely(ref >= NR_TX_USER_LBUF)) {
		pr_err("%s: Error invalid ref %u >= %d\n",
		       __func__, ref, NR_TX_USER_LBUF);
		return -EINVAL;
	}
	desc = tx_user_lbufs[ref];
	if (unlikely(desc == NULL)) {
		pr_err("%s: Error tx_user_lbufs[%d] is NULL\n", __func__, ref);
		return -EINVAL;
	}
	desc->offset = len;
	lbuf_queue_work(desc);
#endif
}

static struct nf10_user_ops lbuf_user_ops = {
	.init			= nf10_lbuf_user_init,
	.get_pfn		= nf10_lbuf_get_pfn,
	.prepare_rx_buffer	= nf10_lbuf_prepare_rx,
	.start_xmit		= nf10_lbuf_user_xmit,
};

/* nf10_hw_ops functions */
static int nf10_lbuf_init(struct nf10_adapter *adapter)
{
	/* create desc pool */
	desc_cache = kmem_cache_create("lbuf_desc",
				       sizeof(struct desc),
				       __alignof__(struct desc),
				       0, NULL);
	if (desc_cache == NULL) {
		pr_err("failed to alloc desc_cache\n");
		return -ENOMEM;
	}
	/* init tx-related list/spinlock */
	spin_lock_init(&tx_lock);

	/* init lbuf user-visiable single-page space in lbuf_hw */
	if ((lbuf_info.u =
	     (struct lbuf_user *)get_zeroed_page(GFP_KERNEL)) == NULL) {
		netif_err(adapter, rx_err, default_netdev(adapter),
			  "failed to alloc lbuf user page\n");
		kmem_cache_destroy(desc_cache);
		return -ENOMEM;
	}
	lbuf_info.adapter = adapter;
	adapter->user_ops = &lbuf_user_ops;
	return 0;
}

static void nf10_lbuf_free(struct nf10_adapter *adapter)
{
	kmem_cache_destroy(desc_cache);
}

static int nf10_lbuf_init_buffers(struct nf10_adapter *adapter)
{
	int err = 0;

	if ((err = init_tx_lbufs(adapter)))
		return err;

	if ((err = init_rx_lbufs(adapter)))
		free_tx_lbufs(adapter);

	return err;
}

static void nf10_lbuf_free_buffers(struct nf10_adapter *adapter)
{
	free_tx_lbufs(adapter);
	free_rx_lbufs(adapter);
#if 0	/* extra_tx_buf */
	free_tx_user_buffers();
#endif
}

static int nf10_lbuf_napi_budget(void)
{
	return 64;
}

static void move_to_next_lbuf(struct nf10_adapter *adapter)
{
	netif_dbg(adapter, rx_status, default_netdev(adapter),
		  "%s: rx_idx=%u\n", __func__, rx_idx());

	LBUF_INIT_HEADER(cur_rx_desc()->kern_addr);
	wmb();
	nf10_lbuf_prepare_rx(adapter, (unsigned long)rx_idx());
	inc_rx_idx();
	set_rx_cons(NR_RESERVED_DWORDS);
}

static void deliver_packet(struct net_device *netdev, void *pkt_addr,
		unsigned int pkt_len, struct sk_buff **pskb, int *work_done)
{
	struct nf10_adapter *adapter = netdev_adapter(netdev);
	struct sk_buff *skb = *pskb;

	/* interface is down, skip it */
	if (unlikely(netdev_port_up(netdev) == 0))
		return;

	//pr_debug("dps: %p l=%u wd=%d\n", pkt_addr, pkt_len, *work_done);

	skb_copy_to_linear_data(skb, pkt_addr, pkt_len);
	memset(pkt_addr - 8, 0, ALIGN(pkt_len, 8) + 8);
	skb_put(skb, pkt_len);
	skb->protocol = eth_type_trans(skb, netdev);
	skb->ip_summed = CHECKSUM_NONE;

	napi_gro_receive(&adapter->napi, skb);

	netdev->stats.rx_packets++;
	(*work_done)++;
	(*pskb) = NULL;

	//pr_debug("dpe\n");
}

static void nf10_lbuf_process_rx_irq(struct nf10_adapter *adapter, 
				     int *work_done, int budget)
{
	void *buf_addr;
	unsigned int dword_idx, next_dword_idx;
	struct sk_buff *skb;
	int port_num;
	void *pkt_addr;
	unsigned int pkt_len, next_pkt_len;
	struct net_device *netdev;
	unsigned long poll_cnt;
	union lbuf_header lh;

	if (nf10_user_rx_callback(adapter)) {
		*work_done = budget;
		return;
	}

	do {
		poll_cnt = 0;
		skb = NULL;
		buf_addr = cur_rx_desc()->kern_addr;
		dword_idx = get_rx_cons();
wait_to_start_recv:
		port_num = LBUF_PKT_PORT_NUM(buf_addr, dword_idx);
		pkt_len = LBUF_PKT_LEN(buf_addr, dword_idx);
#if 0
		if (poll_cnt == 0)
			pr_debug("pc=%lu: i=%u l=%u\n", poll_cnt, dword_idx, pkt_len);
#endif
		if (pkt_len == 0) {
			/* if this lbuf is closed, move to next lbuf */
			LBUF_GET_HEADER(buf_addr, lh);
			if (LBUF_CLOSED(dword_idx, lh)) {
				//pr_err("1-drop: h=0x%016llx 0x%04x %u\n", lh.qword, lh.nr_drops, lh.nr_drops);
				move_to_next_lbuf(adapter);
				continue;
			}
			/* Now, current packet doesn't start being received.
			   if polling enough or from 2nd loop of polling, exit loop */
			if (*work_done > 0 || poll_cnt++ > LBUF_POLL_THRESH) {
				netif_dbg(adapter, rx_status, default_netdev(adapter),
					  "out of poll: wd=%d drop=%u",
					  *work_done, lh.nr_drops);
				break;
			}
			goto wait_to_start_recv;	/* continue polling */
		}
		/* bug if packet len is invalid */
		if (unlikely(!LBUF_IS_PKT_VALID(port_num, pkt_len))) {
			netdev = LBUF_IS_PORT_VALID(port_num) ?
				adapter->netdev[port_num] :
				default_netdev(adapter);
			netif_err(adapter, rx_err, netdev,
				  "Error: invalid packet "
				  "(port_num=%d, len=%u at rx_idx=%d lbuf[%u])",
				  port_num, pkt_len, rx_idx(), dword_idx);
			printk("-prev packet --------------------------------\n");
			print_hex_dump(KERN_WARNING, "", DUMP_PREFIX_NONE, 16, 1,
				       (u32 *)buf_addr + (dword_idx - 18), 72, true);
			printk("-this packet --------------------------------\n");
			print_hex_dump(KERN_WARNING, "", DUMP_PREFIX_NONE, 16, 1,
				       (u32 *)buf_addr + dword_idx, 72, true);
			break;
		}
		/* Now, pkt_len > 0,
		 * meaning the current packet starts being received */
		netdev = adapter->netdev[port_num];
		if (unlikely(!skb)) { /* skb becomes NULL if delieved */
			skb = netdev_alloc_skb_ip_align(netdev, pkt_len);
			if (unlikely(!skb)) {
				netif_err(adapter, rx_err, netdev,
					"failed to alloc skb (l=%u)", pkt_len);
				break;
			}
		}
		pkt_addr = LBUF_PKT_ADDR(buf_addr, dword_idx);
		next_dword_idx = LBUF_NEXT_DWORD_IDX(dword_idx, pkt_len);
wait_to_end_recv:
		next_pkt_len = LBUF_PKT_LEN(buf_addr, next_dword_idx);
		//pr_debug("ptc: nl=%u ni=%u pc=%lu\n", next_pkt_len, next_dword_idx, poll_cnt);
		if (next_pkt_len > 0) {
			/* if entire packet has been received, consume it */
			deliver_packet(netdev, pkt_addr, pkt_len,
				       &skb, work_done);
			set_rx_cons(next_dword_idx);
		}
		else {	/* next_pkt_len == 0 */
			LBUF_GET_HEADER(buf_addr, lh);
			/* still waiting for the packet to be received,
			 * continue polling on next_pkt_len */
			if ((lh.nr_qwords << 1) < next_dword_idx - NR_RESERVED_DWORDS)
				goto wait_to_end_recv;

			/* if nr_dwords >= next_dword_idx,
			 * the entire packet is received, consume it */
			deliver_packet(netdev, pkt_addr, pkt_len,
				       &skb, work_done);

			/* check if the lbuf is closed */
			if (LBUF_CLOSED(next_dword_idx, lh)) {
				move_to_next_lbuf(adapter);
				continue;
			}
			/* timeout has occured, but don't know which packet is
			 * associated with the timeout, so check next_pkt_len
			 * again to see if it's zero. If so, hw has jumped to
			 * next 128B-aligned offset */
			next_pkt_len = LBUF_PKT_LEN(buf_addr, next_dword_idx);
			if (next_pkt_len == 0)
				next_dword_idx = LBUF_128B_ALIGN(next_dword_idx);
			set_rx_cons(next_dword_idx);
		}
		/* check if next_dword_idx exceeds lbuf */
		if (get_rx_cons() >= (cur_rx_desc()->size >> 2))
			move_to_next_lbuf(adapter);
	} while(*work_done < budget);

	netif_dbg(adapter, rx_status, default_netdev(adapter),
		  "loop exit: i=%u wd=%d rxaddr=%p\n",
		  dword_idx, *work_done, &DWORD_GET(cur_rx_desc()->dma_addr, dword_idx));
	set_rx_writeback(&DWORD_GET(cur_rx_desc()->dma_addr, dword_idx));
}

static int lbuf_xmit(struct nf10_adapter *adapter, struct desc *desc)
{
	u32 idx;
	u32 nr_qwords;
	u32 prod, next_prod;
 	u32 prod_pvt;
	dma_addr_t dma_addr;

	/* TODO: 
	 * sanity check for alignment,
	 * optimization with test avail? */
	spin_lock_bh(&tx_lock);
	idx = tx_idx();
	prod = get_tx_prod();
	prod_pvt = get_tx_prod_pvt();
	if (!get_tx_avail(idx) || prod == prod_pvt) {
		spin_unlock(&tx_lock);
		return -EBUSY;
 	}
	next_prod = ALIGN(prod_pvt, 4096);
	if (unlikely(next_prod == desc->size))
		next_prod = 0;
	set_tx_prod(next_prod);
	set_tx_prod_pvt(next_prod);

	set_tx_used(idx);
	inc_tx_idx();
	spin_unlock_bh(&tx_lock);

	dma_addr = desc->dma_addr + prod;
 	nr_qwords = (prod_pvt - prod) >> 3;

	wmb();
	nf10_writeq(adapter, tx_addr_off(idx), dma_addr);
	nf10_writel(adapter, tx_stat_off(idx), nr_qwords);

	netif_info(adapter, tx_queued, default_netdev(adapter),
		   "\trqtx[%u]: c%d l=%u prod=[%u:%u] dma_addr=%p/skbqlen=%u qw=%u\n",
		   idx, smp_processor_id(), prod_pvt - prod, prod, prod_pvt,
		   (void *)dma_addr, skb_queue_len(&desc->skbq), nr_qwords);

#if 0
	print_hex_dump(KERN_WARNING, "", DUMP_PREFIX_NONE,
		       16, 1, desc->kern_addr + prod, 128, true);
#endif

	return 0;
}

static unsigned long __copy_skb_to_lbuf(struct desc *desc, void *buf_addr,
					int port_num, struct sk_buff *skb)
{
	buf_addr = LBUF_CUR_TX_ADDR(buf_addr, port_num, skb->len);
	skb_copy_from_linear_data(skb, buf_addr, skb->len);
	buf_addr = LBUF_NEXT_TX_ADDR(buf_addr, skb->len);
	lbuf_cb(skb) = (u64)buf_addr;	/* for gc on irq */
	skb_queue_tail(&desc->skbq, skb);

	return buf_addr - desc->kern_addr;	/* updated prod_pvt */
}

static int copy_skb_to_lbuf(struct net_device *netdev, struct sk_buff *skb)
{
	/* skb is handled by main_tx_lbuf */
	struct desc *desc = main_tx_lbuf;	
	unsigned int pkt_len = skb->len;
	u32 prod;
	u32 prod_pvt;
	u32 cons;
	u32 avail_size;

	spin_lock(&tx_lock);
	prod = get_tx_prod();
	prod_pvt = get_tx_prod_pvt();
	pr_debug("%s: prod=%u prod_pvt=%u\n", __func__, prod, prod_pvt);
	/* check if need to wrap around by examining tail room */
	if (!LBUF_HAS_TX_ROOM(desc->size, prod_pvt, pkt_len)) {
		/* if unsent packets exist, return with busy, since
		 * discontrigous packets are not allowed to be sent as a lbuf */
		if (prod != prod_pvt) {
			spin_unlock(&tx_lock);
			return -EBUSY;
		}
		/* now ensure all pending packets have been sent, wrap around */
		prod = prod_pvt = 0;
		set_tx_prod(prod);
		set_tx_prod_pvt(prod_pvt);
		pr_debug("%s: wrap around to 0\n", __func__);
	}
	/* check to safely produce packet by examining cons */
	cons = get_tx_cons();
	avail_size = (cons > prod_pvt ? 0 : desc->size) + cons - prod_pvt - 1;
	pr_debug("%s: prod_pvt=%u cons=%u avail=%u req_size=%u pkt_len=%u\n", __func__,
		 prod_pvt, cons, avail_size, ALIGN(pkt_len, 8) + LBUF_TX_METADATA_SIZE, pkt_len);
	if (ALIGN(pkt_len, 8) + LBUF_TX_METADATA_SIZE > avail_size) {
		spin_unlock(&tx_lock);
		return -EBUSY;
	}

	/* now we have enough room to copy the packet */
	prod_pvt = __copy_skb_to_lbuf(desc, desc->kern_addr + prod_pvt,
				      netdev_port_num(netdev), skb);
	set_tx_prod_pvt(prod_pvt);
	spin_unlock(&tx_lock);

	netdev->stats.tx_packets++;
	pr_debug("%s: updated prod_pvt=%u tx_packets=%lu\n", __func__,
		 prod_pvt, netdev->stats.tx_packets);

	return 0;
}

static netdev_tx_t nf10_lbuf_start_xmit(struct sk_buff *skb,
					struct net_device *netdev)
{
	struct nf10_adapter *adapter = netdev_adapter(netdev);

	if (copy_skb_to_lbuf(netdev, skb)) {
		/* no space available in lbuf */
		netif_stop_queue(netdev);
		return NETDEV_TX_BUSY;
	}
	/* now we have copied skb to lbuf */
	lbuf_xmit(adapter, main_tx_lbuf);

	return NETDEV_TX_OK;
}

static int nf10_lbuf_clean_tx_irq(struct nf10_adapter *adapter)
{
	dma_addr_t gc_addr;
	u32 cons;
	struct desc *desc = active_tx_lbuf;
	struct sk_buff *skb;
	int i;
again:
	rmb();
	gc_addr = get_tx_last_gc_addr();
	pr_debug("%s: gc_addr=%p tx_wb=%p prod=%u cons=%u\n", __func__,
		 (void *)gc_addr, (void *)get_tx_writeback(), get_tx_prod(), get_tx_cons());

	if (gc_addr == get_tx_writeback())
		goto out;
	cons = ALIGN(gc_addr - desc->dma_addr, 4096);
	if (cons == desc->size)
		cons = 0;
	set_tx_cons(cons);
	smp_wmb();
	if (get_tx_prod_pvt() - get_tx_prod() > 0) {
		pr_debug("lbuf_xmit in irq\n");
		lbuf_xmit(adapter, desc);
	}
	while((skb = skb_dequeue(&desc->skbq))) {
		pr_debug("\t--gcskb=%p\n", (void *)lbuf_cb(skb));
		dev_kfree_skb_any(skb);
		if (lbuf_cb(skb) == (u64)gc_addr)
			break;
	}
	for (i = 0; i < CONFIG_NR_PORTS; i++)
		if (netif_queue_stopped(adapter->netdev[i]))
			netif_wake_queue(adapter->netdev[i]);

	set_tx_writeback(gc_addr);
	pr_debug("%s: -> cons=%u\n", __func__, cons);
	if (!tx_clean_completed())
		goto again;
out:
	return tx_clean_completed();
}

static unsigned long nf10_lbuf_ctrl_irq(struct nf10_adapter *adapter,
					unsigned long cmd)
{
	if (unlikely(cmd >= NR_IRQ_CTRL))
		return -EINVAL;
	irq_ctrl_handlers[cmd](adapter);
	return 0;
}

static struct nf10_hw_ops lbuf_hw_ops = {
	.init			= nf10_lbuf_init,
	.free			= nf10_lbuf_free,
	.init_buffers		= nf10_lbuf_init_buffers,
	.free_buffers		= nf10_lbuf_free_buffers,
	.get_napi_budget	= nf10_lbuf_napi_budget,
	.process_rx_irq		= nf10_lbuf_process_rx_irq,
	.start_xmit		= nf10_lbuf_start_xmit,
	.clean_tx_irq		= nf10_lbuf_clean_tx_irq,
	.ctrl_irq		= nf10_lbuf_ctrl_irq
};

void nf10_lbuf_set_hw_ops(struct nf10_adapter *adapter)
{
	adapter->hw_ops = &lbuf_hw_ops;
}
