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
*	 TODO:
*		- RX latency optimization: per-packet interrupt/polling once DMA
*		is revised.
*		- TX batching when available TX descriptor doesn't exist
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
#include <asm/cacheflush.h>

static struct kmem_cache *desc_cache;

struct large_buffer {
	struct desc descs[2][NR_LBUF];	/* 0=TX and 1=RX */
	unsigned int prod[2], cons[2];

	/* tx completion buffer */
	void *tx_completion_kern_addr;
	dma_addr_t tx_completion_dma_addr;
};

static struct lbuf_hw {
	struct nf10_adapter *adapter;
	struct large_buffer lbuf;
} lbuf_hw;
#define get_lbuf()	(&lbuf_hw.lbuf)

/* 
 * helper macros for prod/cons pointers and descriptors
 */
#define prod(rx)	(get_lbuf()->prod[rx])
#define cons(rx)	(get_lbuf()->cons[rx])
#define tx_prod()	prod(TX)
#define rx_prod()	prod(RX)
#define tx_cons()	cons(TX)
#define rx_cons()	cons(RX)

#define inc_prod(rx)	inc_pointer(prod(rx))
#define inc_cons(rx)	inc_pointer(cons(rx))
#define inc_tx_prod()	inc_prod(TX)
#define inc_rx_prod()	inc_prod(RX)
#define inc_tx_cons()	inc_cons(TX)
#define inc_rx_cons()	inc_cons(RX)

#define get_desc(rx, pointer)	(&(get_lbuf()->descs[rx][pointer]))
#define prod_desc(rx)		get_desc(rx, prod(rx))
#define cons_desc(rx)		get_desc(rx, cons(rx))
#define tx_prod_desc()		prod_desc(TX)
#define rx_prod_desc()		prod_desc(RX)
#define tx_cons_desc()		cons_desc(TX)
#define rx_cons_desc()		cons_desc(RX)

#define tx_completion_kern_addr()	(get_lbuf()->tx_completion_kern_addr)
#define tx_completion_dma_addr()	(get_lbuf()->tx_completion_dma_addr)

spinlock_t tx_lock;

/* garbage collection of tx buffer */
struct lbuf_head pending_gc_head;
#define get_tx_last_gc_addr()	(tx_completion_kern_addr() + TX_LAST_GC_ADDR_OFFSET)

static unsigned long debug_count;	/* for debug */

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

static inline void *alloc_lbuf(struct nf10_adapter *adapter, struct desc *desc)
{
#ifndef CONFIG_LBUF_COHERENT
	struct page *page;

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	page = alloc_pages(GFP_TRANSHUGE | GFP_ATOMIC, LBUF_ORDER);
#else
	page = alloc_pages(GFP_ATOMIC, LBUF_ORDER);
#endif
	if (page) {
		desc->kern_addr = page_address(page);
		/* lbuf is prepared only if lbuf is invalidated */
		LBUF_INVALIDATE(desc->kern_addr);
	}
	else
		desc->kern_addr = NULL;
#else
	/* NOTE that pci_alloc_consistent returns allocated pages that have
	 * been zeroed, so taking longer time than normal allocation */
	desc->kern_addr = pci_alloc_consistent(adapter->pdev, LBUF_SIZE,
					       &desc->dma_addr);
#endif
	desc->size = LBUF_SIZE;
	desc->offset = 0;
	desc->skb = NULL;

	return desc->kern_addr;
}

static inline void free_lbuf(struct nf10_adapter *adapter, struct desc *desc)
{
#ifndef CONFIG_LBUF_COHERENT
	__free_pages(virt_to_page(desc->kern_addr), LBUF_ORDER);
#else
	pci_free_consistent(adapter->pdev, LBUF_SIZE,
			    desc->kern_addr, desc->dma_addr);
#endif
	/* TODO: if skb is not NULL, release it safely */
}

static void unmap_and_free_lbuf(struct nf10_adapter *adapter,
				struct desc *desc, int rx)
{
	if (unlikely(desc->kern_addr == NULL))
		return;
#ifndef CONFIG_LBUF_COHERENT	/* explicitly unmap to/from normal pages */
	pci_unmap_single(adapter->pdev, desc->dma_addr, LBUF_SIZE,
			 rx ? PCI_DMA_FROMDEVICE : PCI_DMA_TODEVICE);
#endif
	free_lbuf(adapter, desc);
	netif_dbg(adapter, drv, default_netdev(adapter),
		  "%s: addr=(kern=%p:dma=%p)\n", __func__,
		  desc->kern_addr, (void *)desc->dma_addr);
}

static int alloc_and_map_lbuf(struct nf10_adapter *adapter,
			      struct desc *desc, int rx)
{
	if (alloc_lbuf(adapter, desc) == NULL)
		return -ENOMEM;

#ifndef CONFIG_LBUF_COHERENT	/* explicitly map to/from normal pages */
	desc->dma_addr = pci_map_single(adapter->pdev, desc->kern_addr,
			LBUF_SIZE, rx ? PCI_DMA_FROMDEVICE : PCI_DMA_TODEVICE);
	if (pci_dma_mapping_error(adapter->pdev, desc->dma_addr)) {
		netif_err(adapter, probe, default_netdev(adapter),
			  "failed to map to dma addr (kern_addr=%p)\n",
			  desc->kern_addr);
		free_lbuf(adapter, desc);
		return -EIO;
	}
#endif
	netif_dbg(adapter, drv, default_netdev(adapter), 
		"%s: addr=(kern=%p:dma=%p)\n", __func__,
		desc->kern_addr, (void *)desc->dma_addr);
	return 0;
}

/* functions for desc */
static struct desc *alloc_desc(void)
{
	return kmem_cache_alloc(desc_cache, GFP_ATOMIC);
}

static void free_desc(struct desc *desc)
{
	kmem_cache_free(desc_cache, desc);
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

static bool desc_full(int rx)
{
	/* use non-null kern_addr as an indicator that distinguishes
	 * full from empty, so make sure kern_addr sets to NULL when consumed */
	return prod(rx) == cons(rx) &&
	       cons_desc(rx)->kern_addr != NULL;
}
#define tx_desc_full()	desc_full(TX)
#define rx_desc_full()	desc_full(RX)

static bool desc_empty(int rx)
{
	return prod(rx) == cons(rx) &&
	       cons_desc(rx)->kern_addr == NULL;
}
#define tx_desc_empty()	desc_empty(TX)
#define rx_desc_empty()	desc_empty(RX)

static int add_to_pending_gc_list(struct desc *desc)
{
	struct desc *pdesc;

	if ((pdesc = alloc_desc()) == NULL) {
		pr_err("Error: failed to alloc pdesc causing memory leak\n");
		return -ENOMEM;
	}

	*pdesc = *desc;	/* copy */

	/* irq must be disabled since tx irq handling can call this function */
	__lbuf_queue_tail(&pending_gc_head, pdesc);

	return 0;
}

static void lbuf_gc(struct nf10_adapter *adapter,
		    struct desc *desc)
{
	BUG_ON(!desc);

	/* FIXME: skb-to-desc - currently, assume one skb per desc */
	if (desc->skb->data != desc->kern_addr)
		pr_err("Error: skb->data=%p != kern_addr=%p\n", desc->skb->data, desc->kern_addr);

	BUG_ON(!desc->kern_addr);

	netif_dbg(adapter, drv, default_netdev(adapter),
		  "gctx: addr=%p skb=%p\n", (void *)desc->dma_addr, desc->skb);

	/* FIXME: skb-to-desc - skb->len will be changed */
	pci_unmap_single(adapter->pdev, desc->dma_addr, desc->skb->len,
			 PCI_DMA_TODEVICE);

	dev_kfree_skb_any(desc->skb);

	free_desc(desc);
}

/* should be called with tx_lock held */
static bool clean_tx_pending_gc(struct nf10_adapter *adapter, u64 last_gc_addr)
{
	struct desc *desc, *_desc;
	bool empty;
	
	lbuf_for_each_entry_safe(desc, _desc, &pending_gc_head) {
		__lbuf_del(desc);
		lbuf_gc(adapter, desc);
		if (desc->dma_addr == last_gc_addr) {
			netif_dbg(adapter, drv, default_netdev(adapter),
				  "[txdebug] meet gc addr and exit\n");
			break;
		}
	}
	empty = lbuf_queue_empty(&pending_gc_head);

	return empty;
}

static void check_tx_completion(void)
{
	u32 *completion = tx_completion_kern_addr();

	while (tx_desc_empty() == false &&
	       completion[tx_cons()] == TX_COMPLETION_OKAY) {
		struct desc *desc = tx_cons_desc();

		add_to_pending_gc_list(desc);

		/* clean */
		clean_desc(desc);
		completion[tx_cons()] = 0;
		mb();

		/* update cons */
		inc_tx_cons();
	}
}

static void enable_intr(struct nf10_adapter *adapter)
{
	/* FIXME: replace 0xcacabeef */
	nf10_writel(adapter, TX_INTR_CTRL_ADDR, 0xcacabeef);
}

static int init_tx_completion_buffer(struct nf10_adapter *adapter)
{
	tx_completion_kern_addr() =
		pci_alloc_consistent(adapter->pdev, TX_COMPLETION_SIZE,
				     &tx_completion_dma_addr());

	if (tx_completion_kern_addr() == NULL)
		return -ENOMEM;

	nf10_writeq(adapter, TX_COMPLETION_ADDR, tx_completion_dma_addr());

	return 0;
}

static void free_tx_completion_buffer(struct nf10_adapter *adapter)
{
	pci_free_consistent(adapter->pdev, TX_COMPLETION_SIZE,
			    tx_completion_kern_addr(),
			    tx_completion_dma_addr());
}

/*
 * this function takes idx as a parameter, which locates a descriptor to be
 * prepared. duplicate preparation is allowed, but it checks if idx equals to
 * rx_prod. if so rx_prod is advanced, otherwise it's kept unchanged 
 */
static void nf10_lbuf_prepare_rx(struct nf10_adapter *adapter, unsigned long idx)
{
	void *kern_addr;
	dma_addr_t dma_addr;
	struct desc *desc;

	/* sanity check due to malicious user-driven preparation */
	if (unlikely(idx >= NR_LBUF)) {
		pr_err("%s: invalid descriptor index provided\n", __func__);
		return;
	}

	desc = get_desc(RX, idx);

	/* when changed from kernel to user packet processing mode:
	 * this rarely happens */
	if (unlikely(desc->kern_addr == NULL))
		alloc_and_map_lbuf(adapter, desc, RX);

	kern_addr = desc->kern_addr;
	dma_addr = desc->dma_addr;

	/* before sending a new lbuf to NIC, invalidate header space
	 * by zeroing it so that it can poll the header to identify
	 * readiness of any recieved packets in the lbuf */
	LBUF_INVALIDATE(kern_addr);

#ifndef CONFIG_LBUF_COHERENT
	/* this function can be called from user thread via ioctl,
	 * so this mapping should be done safely in that case */
	pci_dma_sync_single_for_device(adapter->pdev, dma_addr,
				       LBUF_SIZE, PCI_DMA_FROMDEVICE);
#endif
	nf10_writeq(adapter, rx_addr_off(idx), dma_addr);
	nf10_writel(adapter, rx_stat_off(idx), RX_READY);

	netif_dbg(adapter, rx_status, default_netdev(adapter),
		  "RX lbuf[%lu] is prepared to nf10\n", idx);
	if (likely((unsigned int)idx == rx_prod()))
		inc_rx_prod();
	else	/* may be duplicate preparation by user */
		netif_warn(adapter, rx_status, default_netdev(adapter),
			   "prepared idx(=%lu) mismatches rx_prod=%u\n",
			   idx, rx_prod());
}

static void nf10_lbuf_prepare_rx_all(struct nf10_adapter *adapter)
{
	unsigned long i;

	netif_dbg(adapter, drv, default_netdev(adapter),
		  "init to prepare all rx descriptors\n");
	for (i = 0; i < NR_LBUF; i++)
		nf10_lbuf_prepare_rx(adapter, i);
}

static int __nf10_lbuf_init_buffers(struct nf10_adapter *adapter, int rx)
{
	int i;
	int err = 0;

	for (i = 0; i < NR_LBUF; i++) {
		struct desc *desc = get_desc(rx, i);
		if ((err = alloc_and_map_lbuf(adapter, desc, rx)))
			break;
		netif_info(adapter, probe, default_netdev(adapter),
			   "%s lbuf[%d] allocated at kern_addr=%p/dma_addr=%p"
			   " (size=%lu bytes)\n", rx ? "RX" : "TX", i,
			   desc->kern_addr, (void *)desc->dma_addr, LBUF_SIZE);
	}
	if (unlikely(err))	/* failed to allocate all lbufs */
		for (i--; i >= 0; i--)
			unmap_and_free_lbuf(adapter, get_desc(rx, i), rx);
	else if (rx) 
		nf10_lbuf_prepare_rx_all(adapter);

	return err;
}

static void __nf10_lbuf_free_buffers(struct nf10_adapter *adapter, int rx)
{
	int i;

	for (i = 0; i < NR_LBUF; i++) {
		unmap_and_free_lbuf(adapter, get_desc(rx, i), rx);
		netif_info(adapter, drv, default_netdev(adapter),
			   "%s lbuf[%d] is freed from kern_addr=%p",
			   rx ? "RX" : "TX", i, get_desc(rx, i)->kern_addr);
	}
}

static int deliver_packets(struct nf10_adapter *adapter, void *buf_addr,
			   unsigned int dword_idx, unsigned int nr_dwords)
{
	int port_num;
	u32 pkt_len;
	struct net_device *netdev;
	struct sk_buff *skb;
	unsigned int rx_packets = 0;
	DEFINE_TIMESTAMP(3);

	do {
		port_num = LBUF_PKT_PORT_NUM(buf_addr, dword_idx);
		pkt_len = LBUF_PKT_LEN(buf_addr, dword_idx);

		if (unlikely(LBUF_IS_PKT_VALID(port_num, pkt_len) == false)) {	
			/* for error reporting */
			netdev = LBUF_IS_PORT_VALID(port_num) ?
				adapter->netdev[port_num] :
				default_netdev(adapter);
			netif_err(adapter, rx_err, netdev,
				  "Error: invalid packet "
				  "(port_num=%d, len=%u at rx_cons=%d lbuf[%u])",
				  rx_cons(), dword_idx, port_num, pkt_len);
			goto next_pkt;
		}
		netdev = adapter->netdev[port_num];

		/* interface is down, skip it */
		if (netdev_port_up(netdev) == 0)
			goto next_pkt;

		START_TIMESTAMP(0);
		if ((skb = netdev_alloc_skb(netdev, pkt_len)) == NULL) {
			netif_err(adapter, rx_err, netdev,
				  "rx_cons=%d failed to alloc skb", rx_cons());
			goto next_pkt;
		}
		STOP_TIMESTAMP(0);

		START_TIMESTAMP(1);
		skb_copy_to_linear_data(skb, LBUF_PKT_ADDR(buf_addr, dword_idx), 
					pkt_len);	/* memcpy */
		STOP_TIMESTAMP(1);

		skb_put(skb, pkt_len);
		skb->protocol = eth_type_trans(skb, netdev);
		skb->ip_summed = CHECKSUM_NONE;

		START_TIMESTAMP(2);
		napi_gro_receive(&adapter->napi, skb);
		STOP_TIMESTAMP(2);

		rx_packets++;
next_pkt:
		dword_idx = LBUF_NEXT_DWORD_IDX(dword_idx, pkt_len);
	} while(dword_idx < nr_dwords);

	netdev->stats.rx_packets += rx_packets;

	netif_dbg(adapter, rx_status, netdev,
		  "RX lbuf delivered to host nr_dwords=%u rx_packets=%u/%lu" 
		  " alloc=%llu memcpy=%llu skbpass=%llu\n",
		  nr_dwords, rx_packets, netdev->stats.rx_packets,
		  ELAPSED_CYCLES(0), ELAPSED_CYCLES(1), ELAPSED_CYCLES(2));

	return 0;
}

static void deliver_lbuf(struct nf10_adapter *adapter, struct desc *desc)
{
	void *buf_addr = desc->kern_addr;
	unsigned int nr_dwords = LBUF_NR_DWORDS(buf_addr);
	unsigned int dword_idx = LBUF_FIRST_DWORD_IDX();

	if (LBUF_IS_VALID(nr_dwords) == false) {
		netif_err(adapter, rx_err, default_netdev(adapter),
			  "rx_cons=%d's header contains invalid # of dwords=%u",
			  rx_cons(), nr_dwords);
		return;
	}
	deliver_packets(adapter, buf_addr, dword_idx, nr_dwords);
	unmap_and_free_lbuf(adapter, desc, RX);
}

static u64 nf10_lbuf_user_init(struct nf10_adapter *adapter)
{
	netif_dbg(adapter, drv, default_netdev(adapter),
		  "user request to initialize rx\n");

	adapter->nr_user_mmap = 0;

	nf10_lbuf_prepare_rx_all(adapter);

	/* rx_cons() is just returned for short-term compatibility
	 * so will be removed or possibly infomration given to user at init */
	return rx_cons();
}

static unsigned long nf10_lbuf_get_pfn(struct nf10_adapter *adapter,
				       unsigned long arg)
{
	/* FIXME: currently, test first for rx, fetch pfn from rx first */
	int rx	= ((int)(arg / NR_LBUF) & 0x1) ^ 0x1;
	int idx	= (int)(arg % NR_LBUF);

	netif_dbg(adapter, drv, default_netdev(adapter),
		  "%s: rx=%d, idx=%d, arg=%lu\n", __func__, rx, idx, arg);
	return get_desc(rx, idx)->dma_addr >> PAGE_SHIFT;
}

static struct nf10_user_ops lbuf_user_ops = {
	.init			= nf10_lbuf_user_init,
	.get_pfn		= nf10_lbuf_get_pfn,
	.prepare_rx_buffer	= nf10_lbuf_prepare_rx,
};

/* nf10_hw_ops functions */
static int nf10_lbuf_init(struct nf10_adapter *adapter)
{
	desc_cache = kmem_cache_create("lbuf_desc",
				       sizeof(struct desc),
				       __alignof__(struct desc),
				       0, NULL);
	if (desc_cache == NULL) {
		pr_err("failed to alloc desc_cache\n");
		return -ENOMEM;
	}

	spin_lock_init(&tx_lock);
	lbuf_head_init(&pending_gc_head);

	lbuf_hw.adapter = adapter;
	adapter->user_ops = &lbuf_user_ops;

	return 0;
}

static void nf10_lbuf_free(struct nf10_adapter *adapter)
{
	unsigned long flags;

	spin_lock_irqsave(&tx_lock, flags);
	/* 0: purge all pending descs: not empty -> bug */
	BUG_ON(!clean_tx_pending_gc(adapter, 0));
	spin_unlock_irqrestore(&tx_lock, flags);

	kmem_cache_destroy(desc_cache);
}

static int nf10_lbuf_init_buffers(struct nf10_adapter *adapter)
{
	int err = 0;

	tx_prod() = tx_cons() = rx_prod() = rx_cons() = 0;

	if ((err = init_tx_completion_buffer(adapter)))
		return err;

	if ((err = __nf10_lbuf_init_buffers(adapter, RX)))
		free_tx_completion_buffer(adapter);

	return err;
}

static void nf10_lbuf_free_buffers(struct nf10_adapter *adapter)
{
	free_tx_completion_buffer(adapter);
	__nf10_lbuf_free_buffers(adapter, RX);
}

static int nf10_lbuf_napi_budget(void)
{
	/* XXX: napi budget as # of large buffers, instead of # of packets.
	 * set 1 as a minimum budget. It will be changed to packet-based budget
	 * when per-packet delivery is implemented in DMA */ 
	return 1;
}

static int consume_rx_desc(struct nf10_adapter *adapter, struct desc *desc)
{
	if (rx_desc_empty())
		return -1;

	if (LBUF_IS_VALID(LBUF_NR_DWORDS(rx_cons_desc()->kern_addr)) == false) {
		netif_dbg(adapter, rx_status, default_netdev(adapter),
			  "nothing to consume for rx: cons=%u nr_dwords=%u\n",
			  rx_cons(), LBUF_NR_DWORDS(rx_cons_desc()->kern_addr));
		return -1;
	}

	/* copy metadata to allow for further producing rx buffer */
	*desc = *rx_cons_desc();

#ifndef CONFIG_USER_ONLY	/* if user-only, no clean desc */
	/* XXX: for user to permanently reuse current buffers,
	 * desc is cleaned only if kernel will process it */
	if (adapter->nr_user_mmap == 0)
		clean_desc(rx_cons_desc());
#endif
	adapter->user_private = rx_cons();
	inc_rx_cons();

	return 0;
}

static void nf10_lbuf_process_rx_irq(struct nf10_adapter *adapter, 
				     int *work_done, int budget)
{
	struct desc desc;

	do {
		if (consume_rx_desc(adapter, &desc))
			return;		/* nothing to process */
#ifndef CONFIG_LBUF_COHERENT
		pci_dma_sync_single_for_cpu(adapter->pdev, desc.dma_addr,
				LBUF_SIZE, PCI_DMA_FROMDEVICE);
#endif
		/* if a user process can handle it, pass it up and return.
		 * In this case, rx buffer is not newly allocated and sent,
		 * instead a user app permanently maps and reuse initial buffers */
		if (nf10_user_rx_callback(adapter)) {
			(*work_done)++;
			return;
		}
#ifdef CONFIG_USER_ONLY
		netif_dbg(adapter, drv, default_netdev(adapter),
			  "No user task awaiting in user-only mode\n");
		nf10_lbuf_prepare_rx(adapter, adapter->user_private);
		return;
#endif

		/* for now with strong assumption where processing one lbuf at a time
		 * refill a single rx buffer */
		if (likely(!rx_desc_full())) {
			alloc_and_map_lbuf(adapter, rx_prod_desc(), RX);
			nf10_lbuf_prepare_rx(adapter, (unsigned long)rx_prod());
		}

		deliver_lbuf(adapter, &desc);
		(*work_done)++;
	} while (*work_done < budget);
}

static int lbuf_xmit(struct net_device *netdev, void *buf_addr,
		     unsigned int len, struct sk_buff *skb)
{
	struct nf10_adapter *adapter = netdev_adapter(netdev);
	u32 nr_qwords;
	struct desc *desc = tx_prod_desc();

	if (unlikely(((unsigned long)buf_addr & 0x3)))
		pr_warn("WARN: buf_addr(%p) is not dword-aligned!\n", buf_addr);

	nr_qwords = ALIGN(len, 8) >> 3;

	desc->dma_addr = pci_map_single(adapter->pdev, buf_addr, len,
					PCI_DMA_TODEVICE);
	if (pci_dma_mapping_error(adapter->pdev, desc->dma_addr)) {
		netif_err(adapter, probe, netdev,
			  "failed to map to dma addr (kern_addr=%p)\n",
			  desc->kern_addr);
		return -EIO;
	}
	desc->kern_addr = buf_addr;
	desc->skb = skb;

	netif_dbg(adapter, drv, default_netdev(adapter),
		 "\trqtx[%u]: desc=%p len=%u, dma_addr/kern_addr/skb=%p/%p/%p,"
		 "nr_qwords=%u, addr=0x%x, stat=0x%x\n",
		 tx_prod(), desc, len, (void *)desc->dma_addr, desc->kern_addr, desc->skb,
		 nr_qwords, tx_addr_off(tx_prod()), tx_stat_off(tx_prod()));

	wmb();
	nf10_writeq(adapter, tx_addr_off(tx_prod()), desc->dma_addr);
	nf10_writel(adapter, tx_stat_off(tx_prod()), nr_qwords);

	inc_tx_prod();

	/* FIXME: currently a single packet in a lbuf */
	netdev->stats.tx_packets++;

	return 0;
}

static netdev_tx_t nf10_lbuf_start_xmit(struct sk_buff *skb,
					struct net_device *netdev)
{
	struct nf10_adapter *adapter = netdev_adapter(netdev);
	unsigned long flags;
	unsigned int headroom, headroom_to_expand;
	int ret;

	spin_lock_irqsave(&tx_lock, flags);

	check_tx_completion();

	if (tx_desc_full()) {
		if (++debug_count >> 20) {	/* XXX: debugging */
			u32 *completion = tx_completion_kern_addr();
			/* normally it's not warning, but at the stage of TX DMA debugging,
			 * it could be a bug, so until any error is completely gone,
			 * remain the this if body with the following message */
			pr_warn("FULL [c=%u:p=%u] - desc=%p empty=%d completion=[%x:%x] dma_addr/kern_addr/skb=%p/%p/%p\n",
				tx_cons(), tx_prod(), tx_cons_desc(), tx_desc_empty(), completion[0], completion[1],
				(void *)tx_cons_desc()->dma_addr, tx_cons_desc()->kern_addr, tx_cons_desc()->skb);

			print_hex_dump(KERN_WARNING, "", DUMP_PREFIX_NONE,
					16, 1, tx_cons_desc()->kern_addr, 128, true);
			debug_count = 0;
		}
#if 0	/* TODO */
		netif_stop_queue(dev);
#endif
		spin_unlock_irqrestore(&tx_lock, flags);
		return NETDEV_TX_BUSY;
	}
	debug_count = 0;

	/* TODO: if skb is shared, must allocate separate buf
	 * so, w/o it, pktgen is not working */
	if (!skb_shared(skb) &&
	    ((headroom = skb_headroom(skb)) < 8 ||
	     !IS_ALIGNED((unsigned long)skb->data, 4))) {
		headroom_to_expand = headroom < 8 ? 8 - headroom :
			ALIGN((unsigned long)skb->data, 4) - (unsigned long)skb->data;

		pskb_expand_head(skb, headroom_to_expand, 0, GFP_ATOMIC);
		netif_dbg(adapter, drv, default_netdev(adapter),
			 "NOTE: skb is expanded(headroom=%u->%u head=%p data=%p len=%u)",
			 headroom, skb_headroom(skb), skb->head, skb->data, skb->len);
	}
	skb_push(skb, 8);
	((u32 *)skb->data)[0] = LBUF_ENCODE_PORT_NUM(netdev_port_num(netdev));
	((u32 *)skb->data)[1] = skb->len - 8;

	ret = lbuf_xmit(netdev, skb->data, skb->len, skb);

	spin_unlock_irqrestore(&tx_lock, flags);

	return ret == 0 ? NETDEV_TX_OK : NETDEV_TX_BUSY;
}

static int nf10_lbuf_clean_tx_irq(struct nf10_adapter *adapter)
{
	u64 *tx_last_gc_addr_ptr = get_tx_last_gc_addr();
	dma_addr_t tx_last_gc_addr;
	int complete;
	unsigned long flags;

	/* no gc buffer updated */
	if (*tx_last_gc_addr_ptr == 0)
		return 1;	/* clean complete */

	netif_dbg(adapter, drv, default_netdev(adapter),
		"tx-irq: gc_addr=%p\n", (void *)(*tx_last_gc_addr_ptr));

	/* TODO: optimization possible in case where one-by-one tx/completion,
	 * we can avoid add and delete to-be-cleaned desc to/from gc list */
again:
	spin_lock_irqsave(&tx_lock, flags);

	check_tx_completion();
	tx_last_gc_addr = *tx_last_gc_addr_ptr;
	complete = clean_tx_pending_gc(adapter, tx_last_gc_addr);

	spin_unlock_irqrestore(&tx_lock, flags);

	if (tx_last_gc_addr != *tx_last_gc_addr_ptr) {
		netif_dbg(adapter, drv, default_netdev(adapter),
			  "tx-irq: \ttry to clean again at 1st pass\n");
		goto again;
	}

	if (cmpxchg64(tx_last_gc_addr_ptr, tx_last_gc_addr, 0) != tx_last_gc_addr) {
		netif_dbg(adapter, drv, default_netdev(adapter),
			  "tx-irq: \ttry to clean again at 2nd pass\n");
		goto again;
	}

	netif_dbg(adapter, drv, default_netdev(adapter),
		  "tx-irq: clean complete=%d\n", complete);

	return complete;
}

static unsigned long nf10_lbuf_ctrl_irq(struct nf10_adapter *adapter,
					unsigned long cmd)
{
	if (cmd == IRQ_CTRL_ENABLE) {
		netif_dbg(adapter, drv, default_netdev(adapter), "irq enabled\n");
		enable_intr(adapter);
	}
	/* TODO: disable interrupt */
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
