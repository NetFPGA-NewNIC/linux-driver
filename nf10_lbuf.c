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

static struct kmem_cache *desc_cache;

#define TX_LBUF_SIZE	(128*1024)
static struct kmem_cache *tx_lbuf_cache;

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
#define get_lbuf_hw()	(&lbuf_hw.lbuf)

/* 
 * helper macros for prod/cons pointers and descriptors
 */
#define prod(rx)	(get_lbuf_hw()->prod[rx])
#define cons(rx)	(get_lbuf_hw()->cons[rx])
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

#define get_desc(rx, pointer)	(&(get_lbuf_hw()->descs[rx][pointer]))
#define prod_desc(rx)		get_desc(rx, prod(rx))
#define cons_desc(rx)		get_desc(rx, cons(rx))
#define tx_prod_desc()		prod_desc(TX)
#define rx_prod_desc()		prod_desc(RX)
#define tx_cons_desc()		cons_desc(TX)
#define rx_cons_desc()		cons_desc(RX)

#define tx_completion_kern_addr()	(get_lbuf_hw()->tx_completion_kern_addr)
#define tx_completion_dma_addr()	(get_lbuf_hw()->tx_completion_dma_addr)

spinlock_t tx_lock;

struct lbuf_head tx_queue_head;
struct workqueue_struct *tx_wq;
struct work_struct tx_work;

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

	/* TODO:
	 * LBUF_ORDER is the same as 2MB hugepage, but if using GFP_TRANSHUGE,
	 * it turns on __GFP_WAIT, which allows sleeping. However, alloc_lbuf
	 * is usually called in atomic state, which means in_atomic() is true.
	 * Currently, GFP_ATOMIC is just used, but in the future it will be
	 * optimized using huge page. NOTE: conditional code will be needed for
	 * old kernel version using CONFIG_TRANSPARENT_HUGEPAGE */
	page = alloc_pages(GFP_ATOMIC, LBUF_ORDER);
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

static inline void *alloc_tx_lbuf(struct desc *desc)
{
	desc->kern_addr = kmem_cache_alloc(tx_lbuf_cache, GFP_ATOMIC);
	desc->size = TX_LBUF_SIZE;
	desc->offset = 0;
	desc->skb = NULL;

	return desc->kern_addr;
}

static inline void free_tx_lbuf(struct desc *desc)
{
	kmem_cache_free(tx_lbuf_cache, desc->kern_addr);
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

static void clean_desc(struct desc *desc)
{
	desc->kern_addr = NULL;
	desc->skb = NULL;
}

static void copy_desc(struct desc *to, struct desc *from)
{
	*to = *from;
}

static void add_skb_to_lbuf(struct desc *desc, struct sk_buff *skb)
{
	if (desc->skb == NULL)
		desc->skb = skb->prev = skb->next = skb;
	else {
		struct sk_buff *last = desc->skb->prev;
		last->next = skb;
		desc->skb->prev = skb;
		skb->prev = last;
		skb->next = desc->skb;
	}
}

static struct sk_buff *del_skb_from_lbuf(struct desc *desc)
{
	struct sk_buff *skb = desc->skb;

	if (skb == NULL)
		return NULL;

	if (desc->skb->next == desc->skb)
		desc->skb = NULL;
	else {
		struct sk_buff *prev = desc->skb->prev;
		struct sk_buff *next = desc->skb->next;
		prev->next = desc->skb->next;
		next->prev = desc->skb->prev;
		desc->skb = next;
	}
	skb->prev = skb->next = NULL;

	return skb;
}

static struct desc *get_lbuf(struct nf10_adapter *adapter)
{
	struct desc *desc = alloc_desc();
	if (unlikely(desc == NULL))
		return NULL;
	if (unlikely(alloc_tx_lbuf(desc) == NULL)) {
		free_desc(desc);
		return NULL;
	}
	return desc;
}

static void put_lbuf(struct nf10_adapter *adapter, struct desc *desc)
{
	free_tx_lbuf(desc);
	free_desc(desc);
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

static void lbuf_queue_work(struct desc *desc)
{
	lbuf_queue_tail(&tx_queue_head, desc);
	queue_work(tx_wq, &tx_work);
}

static int add_packet_to_lbuf(struct desc *desc, int port_num,
		void *pkt_addr, unsigned int pkt_len, struct sk_buff *skb)
{
	struct nf10_adapter *adapter = lbuf_hw.adapter;
	void *buf_addr;

	buf_addr = desc->kern_addr + desc->offset;
	if (unlikely(!IS_ALIGNED((unsigned long)buf_addr, 8 /* qword */))) {
		pr_err("Error: tx lbuf+offset is not qword-aligned\n");
		return -EINVAL;
	}

	buf_addr = LBUF_SET_TX_METADATA(buf_addr, port_num, pkt_len);
	memcpy(buf_addr, pkt_addr, pkt_len);
	desc->offset += (LBUF_TX_METADATA_SIZE + pkt_len);
	desc->offset = ALIGN(desc->offset, 8 /* qword */);
	if (skb)
		add_skb_to_lbuf(desc, skb);

#if 0
	netif_dbg(adapter, tx_queued, default_netdev(adapter),
		"qpkt: cpu%d pid=%d comm=%s port_num=%d pkt_addr=%p pkt_len=%u desc->(kern_addr=%p offset=%u) skb=%p\n",
		smp_processor_id(), current->pid, current->comm, port_num, pkt_addr, pkt_len, desc->kern_addr, desc->offset, skb);
#endif
	return 0;
}

static int queue_tx_packet(struct nf10_adapter *adapter, int port_num,
			   struct sk_buff *skb)
{
	struct lbuf_head *head = &tx_queue_head;
	void *pkt_addr = skb->data;
	unsigned int pkt_len = skb->len;
	struct desc *desc;
	int ret = 0;

	/* find the queued last lbuf that has enough room queue the packet:
	 * it holds tx_queue_head's lock to find lbuf and copy packet to it */
	spin_lock(&head->lock);
	if (!lbuf_queue_empty(head)) {
		desc = list_last_entry(&head->head, struct desc, list);
		if (LBUF_HAS_TX_ROOM(desc->size, desc->offset, pkt_len)) {
			ret = add_packet_to_lbuf(desc, port_num,
					pkt_addr, pkt_len, skb);
			spin_unlock(&head->lock);
			goto out;
		}
	}
	spin_unlock(&head->lock);

	/* now need to allocate a new lbuf to push the packet */
	if ((desc = get_lbuf(adapter)) == NULL)
		return -ENOMEM;
	ret = add_packet_to_lbuf(desc, port_num, pkt_addr, pkt_len, skb);
	if (likely(ret == 0))
		lbuf_queue_tail(head, desc);
	else
		put_lbuf(adapter, desc);
out:
	/* if the packet is queued, schedule lbuf_tx_worker */
	if (likely(ret == 0))
		queue_work(tx_wq, &tx_work);

	return ret;
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
	copy_desc(pdesc, desc);
	lbuf_queue_tail(&pending_gc_head, pdesc);
	/* for lockless emptiness check in nf10_lbuf_clean_tx_irq */
	smp_wmb();

	return 0;
}

static void lbuf_gc(struct nf10_adapter *adapter, struct desc *desc)
{
	struct sk_buff *skb;
	bool decoupled_buf;

	BUG_ON(!desc);
	BUG_ON(!desc->kern_addr);

	/* i) !desc->skb -> no dependent skbs with lbuf alone,
	 * ii) desc->skb->data != desc->kern_addr -> skb(s) are copied to lbuf,
	 * otherwise, desc->skb->data is directly on tx descriptor w/o lbuf */
	decoupled_buf = !desc->skb || desc->skb->data != desc->kern_addr;
	netif_dbg(adapter, drv, default_netdev(adapter),
		  "gctx: addr=%p skb=%p decoupled_buf=%d\n", (void *)desc->dma_addr, desc->skb, decoupled_buf);

	pci_unmap_single(adapter->pdev, desc->dma_addr, desc->offset,
			 PCI_DMA_TODEVICE);

	while ((skb = del_skb_from_lbuf(desc))) {
#if 0
		netif_dbg(adapter, drv, default_netdev(adapter),
			  "\t--gcskb=%p\n", skb);
#endif
		dev_kfree_skb_any(skb);
	}

	if (decoupled_buf)
		free_tx_lbuf(desc);

	free_desc(desc);
}

static bool clean_tx_pending_gc(struct nf10_adapter *adapter, u64 last_gc_addr)
{
	struct desc *desc;
	
	while((desc = lbuf_dequeue(&pending_gc_head))) {
		/* for lockless emptiness check in nf10_lbuf_clean_tx_irq */
		smp_wmb();
		lbuf_gc(adapter, desc);
		if (desc->dma_addr == last_gc_addr) {
			netif_dbg(adapter, drv, default_netdev(adapter),
				  "[txdebug] meet gc addr and exit\n");
			break;
		}
	}
	smp_read_barrier_depends();
	return lbuf_queue_empty(&pending_gc_head);	/* completed */
}

/* should be called with tx_lock held */
static void check_tx_completion(void)
{
	u32 *completion = tx_completion_kern_addr();
	int cleaned = 0;

	while (tx_desc_empty() == false &&
	       completion[tx_cons()] == TX_COMPLETION_OKAY) {
		struct desc *desc = tx_cons_desc();

		add_to_pending_gc_list(desc);

		/* clean */
		clean_desc(desc);
		completion[tx_cons()] = 0;
		mb();
		cleaned = 1;

		/* update cons */
		inc_tx_cons();
	}
	if (cleaned)
		queue_work(tx_wq, &tx_work);
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
		if ((skb = netdev_alloc_skb_ip_align(netdev, pkt_len)) == NULL) {
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
		  "RX lbuf to host nr_dwords=%u rx_packets=%u/%lu on cpu%d " 
		  "(alloc=%llu memcpy=%llu skbpass=%llu)\n",
		  nr_dwords, rx_packets, netdev->stats.rx_packets, smp_processor_id(),
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

static unsigned long nf10_lbuf_gen(struct nf10_adapter *adapter,
		unsigned int pkt_len, unsigned long pkt_count, int batch)
{
	/* FIXME: currently assume batch == 1, ignoring it */
	struct desc *desc = NULL;
	unsigned long xmit_count;
	void *pkt_addr;

	/* zeroed packet: manipulate its content for a specific packet */
	if ((pkt_addr = kzalloc(pkt_len, GFP_KERNEL)) == NULL)
		return 0;

	pr_debug("%s started: pkt_len=%u pkt_count=%lu batch=%d\n",
		 __func__, pkt_len, pkt_count, batch);
	for (xmit_count = 0; xmit_count < pkt_count; xmit_count++) {
		if (desc == NULL ||
		    !LBUF_HAS_TX_ROOM(desc->size, desc->offset, pkt_len)) {
			if (desc)	/* send previous filled lbuf */
				lbuf_queue_work(desc);
			if ((desc = get_lbuf(adapter)) == NULL)
				goto out;
		}
		if (add_packet_to_lbuf(desc, 0, pkt_addr, pkt_len, NULL) < 0) {
			put_lbuf(adapter, desc);
			goto out;
		}
	}
	if (desc)
		lbuf_queue_work(desc);
out:
	kfree(pkt_addr);
	return xmit_count;
}

static struct nf10_user_ops lbuf_user_ops = {
	.init			= nf10_lbuf_user_init,
	.get_pfn		= nf10_lbuf_get_pfn,
	.prepare_rx_buffer	= nf10_lbuf_prepare_rx,
	.pkt_gen		= nf10_lbuf_gen,
};

/* nf10_hw_ops functions */
static void lbuf_tx_worker(struct work_struct *work);
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

	tx_lbuf_cache = kmem_cache_create("tx_lbuf",
				       TX_LBUF_SIZE,
				       __alignof__(TX_LBUF_SIZE),
				       0, NULL);
	if (tx_lbuf_cache == NULL) {
		pr_err("failed to alloc tx_lbuf_cache\n");
		return -ENOMEM;
	}

	spin_lock_init(&tx_lock);
	lbuf_head_init(&tx_queue_head);
	lbuf_head_init(&pending_gc_head);

	INIT_WORK(&tx_work, lbuf_tx_worker);
	tx_wq = alloc_workqueue("lbuf_tx", WQ_MEM_RECLAIM, 0);
	if (tx_wq == NULL) {
		netif_err(adapter, rx_err, default_netdev(adapter),
			  "failed to alloc lbuf tx workqueue\n");
		return -ENOMEM;
	}

	lbuf_hw.adapter = adapter;
	adapter->user_ops = &lbuf_user_ops;

	return 0;
}

static void nf10_lbuf_free(struct nf10_adapter *adapter)
{
	/* 0: purge all pending descs: not empty -> bug */
	local_bh_disable();
	BUG_ON(!clean_tx_pending_gc(adapter, 0));
	local_bh_enable();
	destroy_workqueue(tx_wq);
	kmem_cache_destroy(desc_cache);
	kmem_cache_destroy(tx_lbuf_cache);
}

static int nf10_lbuf_init_buffers(struct nf10_adapter *adapter)
{
	int i;
	int err = 0;

	/* initialize descriptors and pointers. RX descriptors are initialized
	 * by the following __nf10_lbuf_free_buffers */
	for (i = 0; i < NR_LBUF; i++)
		clean_desc(get_desc(TX, i));

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
	copy_desc(desc, rx_cons_desc());

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
		if (likely(!rx_desc_full() &&
		    alloc_and_map_lbuf(adapter, rx_prod_desc(), RX) == 0))
			nf10_lbuf_prepare_rx(adapter, (unsigned long)rx_prod());

		deliver_lbuf(adapter, &desc);
		(*work_done)++;
	} while (*work_done < budget);
}

static int lbuf_xmit(struct nf10_adapter *adapter, void *buf_addr,
		     unsigned int len, struct sk_buff *skb)
{
	u32 nr_qwords;
	struct desc *desc = tx_prod_desc();

	if (unlikely(!IS_ALIGNED((unsigned long)buf_addr, 4)))
		pr_warn("WARN: buf_addr(%p) is not dword-aligned!\n", buf_addr);

	nr_qwords = ALIGN(len, 8) >> 3;

	desc->dma_addr = pci_map_single(adapter->pdev, buf_addr, len,
					PCI_DMA_TODEVICE);
	if (pci_dma_mapping_error(adapter->pdev, desc->dma_addr)) {
		netif_err(adapter, probe, default_netdev(adapter),
			  "failed to map to dma addr (kern_addr=%p)\n",
			  desc->kern_addr);
		return -EIO;
	}
	desc->kern_addr = buf_addr;
	desc->offset = len;
	desc->skb = skb;

	netif_dbg(adapter, tx_queued, default_netdev(adapter),
		 "\trqtx[%u]: cpu%d desc=%p len=%u, dma_addr/kern_addr/skb=%p/%p/%p,"
		 "nr_qwords=%u, addr=0x%x, stat=0x%x\n",
		 tx_prod(), smp_processor_id(), desc, len, (void *)desc->dma_addr, desc->kern_addr, desc->skb,
		 nr_qwords, tx_addr_off(tx_prod()), tx_stat_off(tx_prod()));

	wmb();
	nf10_writeq(adapter, tx_addr_off(tx_prod()), desc->dma_addr);
	nf10_writel(adapter, tx_stat_off(tx_prod()), nr_qwords);

	inc_tx_prod();

	return 0;
}

static void debug_tx_desc_full(void)
{
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
}

static netdev_tx_t nf10_lbuf_start_xmit(struct sk_buff *skb,
					struct net_device *netdev)
{
	struct nf10_adapter *adapter = netdev_adapter(netdev);
	unsigned int headroom, headroom_to_expand;
	int ret;

	/* TEST */
	queue_tx_packet(adapter, netdev_port_num(netdev), skb);
	netdev->stats.tx_packets++;
	return NETDEV_TX_OK;
	/********/

	spin_lock_bh(&tx_lock);

	check_tx_completion();

	if (tx_desc_full()) {
		debug_tx_desc_full();
#if 0	/* TODO */
		netif_stop_queue(dev);
#endif
		spin_unlock_bh(&tx_lock);
		return NETDEV_TX_BUSY;
	}
	debug_count = 0;

	/* TODO: if skb is shared, must allocate separate buf
	 * so, w/o it, pktgen is not working */
	if (!skb_shared(skb) &&
	    ((headroom = skb_headroom(skb)) < LBUF_TX_METADATA_SIZE ||
	     !IS_ALIGNED((unsigned long)skb->data, 4 /* dword */))) {
		headroom_to_expand = headroom < LBUF_TX_METADATA_SIZE ?
			LBUF_TX_METADATA_SIZE - headroom :
			ALIGN((unsigned long)skb->data, 4) - (unsigned long)skb->data;

		pskb_expand_head(skb, headroom_to_expand, 0, GFP_ATOMIC);
		netif_dbg(adapter, drv, default_netdev(adapter),
			 "NOTE: skb is expanded(headroom=%u->%u head=%p data=%p len=%u)",
			 headroom, skb_headroom(skb), skb->head, skb->data, skb->len);
	}
	skb_push(skb, LBUF_TX_METADATA_SIZE);
	LBUF_SET_TX_METADATA(skb->data, netdev_port_num(netdev),
			     skb->len - LBUF_TX_METADATA_SIZE);

	skb->prev = skb->next = skb;
	ret = lbuf_xmit(adapter, skb->data, skb->len, skb);

	spin_unlock_bh(&tx_lock);

	if (likely(ret == 0))
		netdev->stats.tx_packets++;

	return ret == 0 ? NETDEV_TX_OK : NETDEV_TX_BUSY;
}

static void lbuf_tx_worker(struct work_struct *work)
{
	struct nf10_adapter *adapter = lbuf_hw.adapter;
	struct desc *desc;
	bool cont = true;

	netif_dbg(adapter, drv, default_netdev(adapter),
		  "%s scheduled on cpu%d\n", __func__, smp_processor_id());
	while(cont) {
		spin_lock_bh(&tx_lock);
		desc = lbuf_dequeue(&tx_queue_head);
		check_tx_completion();
		if (!desc)
			cont = false;
		else if (tx_desc_full()) {
			lbuf_queue_head(&tx_queue_head, desc);
			cont = false;
		}
		else
			lbuf_xmit(adapter, desc->kern_addr, desc->offset, desc->skb);
		spin_unlock_bh(&tx_lock);

		if (cont)
			free_desc(desc);
	}
#if 0
	while ((desc = lbuf_dequeue(&tx_queue_head))) {
		spin_lock_bh(&tx_lock);
		check_tx_completion();
		if (tx_desc_full()) {
			spin_unlock_bh(&tx_lock);
			lbuf_queue_head(&tx_queue_head, desc);
			break;
		}
		if (unlikely(desc->offset == 0)) {
			spin_unlock_bh(&tx_lock);
			free_desc(desc);
			continue;
		}
		lbuf_xmit(adapter, desc->kern_addr, desc->offset, desc->skb);
		spin_unlock_bh(&tx_lock);
		free_desc(desc);
	}
#endif
}

static int nf10_lbuf_clean_tx_irq(struct nf10_adapter *adapter)
{
	volatile u64 *tx_last_gc_addr_ptr = get_tx_last_gc_addr();
	dma_addr_t tx_last_gc_addr;
	int complete;

	/* no gc buffer updated:
	 * return false unless pending_gc_head is empty to keep polling */
	rmb();
	if (*tx_last_gc_addr_ptr == 0) {
		smp_read_barrier_depends();
		return lbuf_queue_empty(&pending_gc_head);
	}

	netif_dbg(adapter, drv, default_netdev(adapter),
		"tx-irq: cpu%d gc_addr=%p\n", smp_processor_id(), (void *)(*tx_last_gc_addr_ptr));

	/* TODO: optimization possible in case where one-by-one tx/completion,
	 * we can avoid add and delete to-be-cleaned desc to/from gc list */
again:
	spin_lock_bh(&tx_lock);
	check_tx_completion();
	spin_unlock_bh(&tx_lock);

	rmb();
	tx_last_gc_addr = *tx_last_gc_addr_ptr;
	complete = clean_tx_pending_gc(adapter, tx_last_gc_addr);

	rmb();
	if (tx_last_gc_addr != *tx_last_gc_addr_ptr) {
		netif_dbg(adapter, drv, default_netdev(adapter),
			  "tx-irq: \ttry to clean again at 1st pass\n");
		goto again;
	}

	rmb();
	if (cmpxchg64(tx_last_gc_addr_ptr, tx_last_gc_addr, 0) != tx_last_gc_addr) {
		netif_dbg(adapter, drv, default_netdev(adapter),
			  "tx-irq: \ttry to clean again at 2nd pass\n");
		goto again;
	}

	netif_dbg(adapter, drv, default_netdev(adapter),
		  "tx-irq: cpu%d clean complete=%d\n", smp_processor_id(), complete);

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
