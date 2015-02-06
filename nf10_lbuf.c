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
*	 of hw_ops (lbuf_hw_ops) of nf10_adapter. Lbuf DMA is basically to use
*	 large buffer as a transport. For RX, lbuf size is determined by DMA hw
*	 but not impossible to be flexible (DMA can be changed variable size).
*	 For TX, there is no dependency on DMA, now a single large TX buffer is
*	 allocated and permanently used for tx.
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

struct lbuf_stats {
	u64 tx_lbufs;
	u64 tx_bytes;
	u32 tx_stops;
	u64 rx_mac_timeout;
};

/**
 * desc - lbuf descriptor
 **/
struct desc {
	void			*kern_addr;
	dma_addr_t		dma_addr;
	u32			size;
	unsigned int		tx_prod;
	unsigned int		tx_prod_pvt;
	unsigned int		tx_cons;
	spinlock_t		lock;
};

/**
 * lbuf_info - core data structure for lbuf DMA
 **/
static struct lbuf_info {
	/* associated adapter set by nf10_lbuf_init */
	struct nf10_adapter *adapter;
	/* NR_SLOT rx lbufs' descriptors */
	struct desc *rx_desc[NR_SLOT];
	/* kernel tx lbuf descriptor: currently using one tx lbuf for kernel */
	struct desc *tx_kern_desc;
	/* user tx lbufs' descriptors: its number can be configured by user */
	struct desc *tx_user_desc[MAX_TX_USER_LBUF];
	/* shared single-page metadata structure between kernel and user */
	struct lbuf_user *u;
	/* kernel gc address updated in nf10_clean_tx_irq on IRQ:
	 * last address of tx lbuf that is drained to DMA for flow control */
	unsigned long long last_gc_addr;
	/* tx completion buffer: slot availablility and hw gc address */
	void *tx_completion_kern_addr;		/* for sw use */
	dma_addr_t tx_completion_dma_addr;	/* for hw use */
	/* lbuf stats */
	struct lbuf_stats stats;
	struct device_attribute stat_attr;
} lbuf_info;

#define LBUF_TX_ORDER	10	/* default 4MB */
#define LBUF_TX_SIZE	(1UL << (PAGE_SHIFT + LBUF_TX_ORDER))
#define DEFAULT_INTR_PERIOD_USECS	30
#define TX_CLEAN_BUDGET			64

/** 
 * Accessor/updator macros for primary pointers/stats in lbuf_info:
 * use the following macros not accessing/manipulating values directly
 * for debugging
 * - idx: slot index
 * - rx_cons: rx cons pointer in rx lbuf[idx]
 * - tx_prod/prod_pvt/cons: tx pointers in kernel tx lbuf
 **/
#define rx_idx()		(lbuf_info.u->rx_idx)
#define tx_idx()		(lbuf_info.u->tx_idx)
#define inc_rx_idx()		inc_idx(rx_idx())
#define inc_tx_idx()		inc_idx(tx_idx())

#define get_rx_desc(idx)	(lbuf_info.rx_desc[idx])
#define set_rx_desc(idx, d)	do { lbuf_info.rx_desc[idx] = d; } while(0)
#define cur_rx_desc()		get_rx_desc(rx_idx())

#define get_tx_completion(idx)	LBUF_TX_COMPLETION(lbuf_info.tx_completion_kern_addr, idx)
#define get_tx_avail(idx)	(get_tx_completion(idx) == TX_AVAIL)
#define set_tx_avail(idx)	do { get_tx_completion(idx) = TX_AVAIL; } while(0)
#define set_tx_used(idx)	do { get_tx_completion(idx) = TX_USED; } while(0)

#define get_rx_cons()		(lbuf_info.u->rx_cons)
#define set_rx_cons(v)		do { lbuf_info.u->rx_cons = v; } while(0)

#define tx_kern_desc()		(lbuf_info.tx_kern_desc)
#define tx_user_desc(ref)	(lbuf_info.tx_user_desc[ref])
#define get_tx_prod(d)		(d->tx_prod)
#define set_tx_prod(d, v)	do { d->tx_prod = v; } while(0)
#define get_tx_prod_pvt(d)	(d->tx_prod_pvt)
#define set_tx_prod_pvt(d, v)	do { d->tx_prod_pvt = v; } while(0)
#define get_tx_cons(d)		(d->tx_cons)
#define set_tx_cons(d, v)	do { d->tx_cons = v; } while(0)
#define init_tx_pointers(d)	do { set_tx_prod(desc, 0); set_tx_prod_pvt(desc, 0); set_tx_cons(desc, 0); } while(0)
#define tx_clean_completed(d)	(get_tx_prod(d) == get_tx_cons(d))
#define tx_pending(d)		(get_tx_prod_pvt(d) - get_tx_prod(d) > 0)
#define set_tx_dma_addr(i, v)	do { lbuf_info.u->tx_dma_addr[i] = v; } while(0)
#define set_rx_dma_addr(i, v)	do { lbuf_info.u->rx_dma_addr[i] = v; } while(0)

#define get_sw_gc_addr()	(lbuf_info.last_gc_addr)
#define set_sw_gc_addr(v)	do { lbuf_info.last_gc_addr = (unsigned long)v; } while(0)
#define get_sw_user_gc_addr()	(lbuf_info.u->last_gc_addr)

#define get_hw_gc_addr()	LBUF_GC_ADDR(lbuf_info.tx_completion_kern_addr)

#define addr_in_lbuf(d, addr)	(addr > d->dma_addr && addr <= d->dma_addr + d->size)

/**
 * Simple profiling macros with rdtsc:
 * if you want to use it, adjust NR_TIMESTAMPS depending on the number of
 * events to be profiled and enclose the code where you want to measure time
 * with START_TIMESTAMP(i) and STOP_TIMESTAMP(i). Each can be reported using
 * ELAPSED_CYCLES(i), which is currently included in show_lbuf_stat().
 **/
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
#define NR_TIMESTAMPS	4
DEFINE_TIMESTAMP(NR_TIMESTAMPS);

static inline void *__alloc_lbuf(struct nf10_adapter *adapter,
			       struct desc *desc, u32 size)
{
	desc->kern_addr = pci_alloc_consistent(adapter->pdev, size,
					       &desc->dma_addr);
	desc->size = size;
	init_tx_pointers(desc);
	spin_lock_init(&desc->lock);

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

/**
 * alloc_lbuf - allocate DMA-coherent lbuf with size
 * @adapter: associated adapter structure
 * @size: requested size
 *
 * This is the top-level function for allocating a lbuf with size.
 *
 * Returns desc if allocation is succeeded, NULL otherwise.
 **/
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

/**
 * free_lbuf - free desc's lbuf
 * @adapter: associated adapter structure
 * @desc: lbuf descriptor to be freed
 *
 * This is the top-level function for freeing a lbuf.
 **/
static void free_lbuf(struct nf10_adapter *adapter, struct desc *desc)
{
	/* this function is safe with NULL desc */
	if (unlikely(desc == NULL))
		return;

	netif_dbg(adapter, drv, default_netdev(adapter), 
		"%s: addr=(kern=%p:dma=%p)\n", __func__,
		desc->kern_addr, (void *)desc->dma_addr);

	__free_lbuf(adapter, desc);
	__free_desc(desc);
}

/**
 * __enable_irq - do synchronization with hw and enable IRQ
 * @adapter: associated adapter structure
 *
 * This function firstly synchronizes current status of rx and tx with DMA, and
 * then enables IRQ. For rx, it lets DMA know the current rx_cons address, and
 * for tx, it writes the gc address last seen by kernel. Such synchronization
 * is needed to tickle DMA to generate IRQ if sw has not seen up-to-date
 * information (i.e., new rx packets and newly drained tx packets)
 *
 * It is also invoked from user process via poll/select(). When user process
 * goes to sleep due to no pending evnet, it enables IRQ to wake up when IRQ is
 * delivered. In this case, UF_GC_ADDR_SYNC is set to synchronize user gc
 * address.
 **/
static void __enable_irq(struct nf10_adapter *adapter)
{
	u64 last_rx_dma_addr =
		(u64)&DWORD_GET(cur_rx_desc()->dma_addr, get_rx_cons());
	
	/* if requested, user gc address is synchronized */
	if (unlikely(adapter->user_flags & UF_GC_ADDR_SYNC)) {
		set_sw_gc_addr(get_sw_user_gc_addr());
		adapter->user_flags &= ~UF_GC_ADDR_SYNC;
	}
	/* tx: sync gc address if non-zero */
	if (get_sw_gc_addr())
		nf10_writeq(adapter, TX_SYNC_REG, get_sw_gc_addr());
	/* rx: sync rx_cons address */
	nf10_writeq(adapter, RX_SYNC_REG, last_rx_dma_addr);
	wmb();
	nf10_writel(adapter, IRQ_ENABLE_REG, IRQ_CTRL_VAL);
	netif_dbg(adapter, intr, default_netdev(adapter),
		  "enable_irq (wb=[tx:%p,rx:%p])\n",
		  (void *)get_sw_gc_addr(), (void *)last_rx_dma_addr);
}

static void __disable_irq(struct nf10_adapter *adapter)
{
	nf10_writel(adapter, IRQ_DISABLE_REG, IRQ_CTRL_VAL);
	netif_dbg(adapter, intr, default_netdev(adapter), "disable_irq\n");
}

/**
 * this structure is extensible when adding any other IRQ control feature.
 * if you extend a new control, define IRQ_CTRL_* in nf10.h and add its function
 * to the following structure
 **/
void (*irq_ctrl_handlers[NR_IRQ_CTRL])(struct nf10_adapter *adapter) = {
	[IRQ_CTRL_ENABLE]	= __enable_irq,
	[IRQ_CTRL_DISABLE]	= __disable_irq,
};

static int init_tx_lbufs(struct nf10_adapter *adapter)
{
	int i;

	/* allocate kernel tx lbuf: currently a single tx lbuf is used
	 * for kernel-level tx (but it can be extended) */
	BUG_ON(tx_kern_desc());
	if (!(tx_kern_desc() = alloc_lbuf(adapter, LBUF_TX_SIZE)))
		return -ENOMEM;
	netif_info(adapter, probe, default_netdev(adapter),
		   "TX kern lbuf allocated at kern_addr=%p/dma_addr=%p"
		   " (size=%u bytes)\n", tx_kern_desc()->kern_addr,
		   (void *)tx_kern_desc()->dma_addr, tx_kern_desc()->size);

	/* tx completion DMA-coherent buffer: it's for the availablity of
	 * each slot and gc address */
	lbuf_info.tx_completion_kern_addr =
		pci_alloc_consistent(adapter->pdev, TX_COMPLETION_SIZE,
				     &lbuf_info.tx_completion_dma_addr);

	if (lbuf_info.tx_completion_kern_addr == NULL) {
		free_lbuf(adapter, tx_kern_desc());
		return -ENOMEM;
	}

	/* make all slots available. this is the only place where software
	 * sets each slot available at initialization.
	 * Afterwards slot is made available by DMA, when the slot's PCIe read
	 * requests are all sent. */
	for (i = 0; i < NR_SLOT; i++)
		set_tx_avail(i);

	/* let DMA know where the tx completion area is allocated */
	nf10_writeq(adapter, TX_COMPLETION_ADDR,
		    lbuf_info.tx_completion_dma_addr);
	return 0;
}

/**
 * get_tx_user_lbuf - get a tx user lbuf based on ref and size
 * @adapter: associated adapter structure
 * @ref: reference (index) to tx user lbuf array
 * @size: requested size via mmap
 *
 * This function checks if user tx lbuf with the requested size is avaialble.
 * If so, return its PFN, otherwise, allocate a new tx lbuf.
 *
 * Returns PFN of a tx lbuf of ref and size, but 0 if failed.
 **/
static unsigned long get_tx_user_lbuf(struct nf10_adapter *adapter,
				      int ref, unsigned long size)
{
	struct desc *desc;

	if (unlikely(ref >= MAX_TX_USER_LBUF)) {
		pr_err("%s: ref(=%d) >= %d\n", __func__, ref, MAX_TX_USER_LBUF);
		return 0;
	}

	desc = tx_user_desc(ref);
	/* reuse tx buffer if existing lbuf >= requested size */
	if (!desc || desc->size < size) {
		free_lbuf(adapter, desc);
		if ((desc = alloc_lbuf(adapter, size)) == NULL) {
			pr_err("%s: failed to allocate tx_user_desc[%d]\n",
			       __func__, ref);
			return 0;
		}
		tx_user_desc(ref) = desc;
	}
	set_tx_dma_addr(ref, desc->dma_addr);
	return virt_to_phys(desc->kern_addr) >> PAGE_SHIFT;
}

static void put_tx_user_lbuf(struct nf10_adapter *adapter, int ref)
{
	if (ref >= MAX_TX_USER_LBUF || !tx_user_desc(ref))
		return;
	free_lbuf(adapter, tx_user_desc(ref));
	tx_user_desc(ref) = NULL;
}

static void free_tx_lbufs(struct nf10_adapter *adapter)
{
	int i;

	free_lbuf(adapter, tx_kern_desc());
	tx_kern_desc() = NULL;
	pci_free_consistent(adapter->pdev, TX_COMPLETION_SIZE,
			    lbuf_info.tx_completion_kern_addr,
			    lbuf_info.tx_completion_dma_addr);

	for (i = 0; i < MAX_TX_USER_LBUF; i++)
		put_tx_user_lbuf(adapter, i);
}

/**
 * nf10_lbuf_prepare_rx - [user_ops] prepare a rx lbuf to DMA (low-level)
 * @adapter: associated adapter structure
 * @idx: rx lbuf slot index
 *
 * This function prepares a rx lbuf to DMA by writing address and readiness of
 * the lbuf to the registers of the slot indicated by idx.
 **/
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
	dma_addr  = desc->dma_addr;

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

	/* initialize rx_cons to LBUF_RX_RESERVED_DWORDS, a start point for data */
	set_rx_cons(LBUF_RX_RESERVED_DWORDS);
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

/**
 * init_rx_lbufs - allocate and prepare rx lbufs
 * @adapter: associated adapter structure
 *
 * This function allocates NR_SLOT rx lbufs and prepare them to DMA.
 **/
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
		set_rx_dma_addr(i, desc->dma_addr);

		netif_info(adapter, probe, default_netdev(adapter),
			   "RX lbuf[%d] allocated at kern_addr=%p/dma_addr=%p"
			   " (size=%u bytes)\n", i,
			   desc->kern_addr, (void *)desc->dma_addr, desc->size);
	}
	nf10_lbuf_prepare_rx_all(adapter);

	return 0;

alloc_fail:
	free_rx_lbufs(adapter);
	return -ENOMEM;
}

static ssize_t show_lbuf_stat(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	int i;
	struct lbuf_info *info = container_of(attr, struct lbuf_info,
					      stat_attr);
	struct lbuf_stats *stats = &info->stats;
	unsigned long rx_bytes = 0;

	sprintf(buf, "tx_lbufs=%llu\ntx_bytes=%llu\ntx_avg_bytes=%llu\n",
		stats->tx_lbufs, stats->tx_bytes,
		stats->tx_lbufs ? stats->tx_bytes / stats->tx_lbufs : 0);
	sprintf(buf + strlen(buf), "tx_stops=%u\n", stats->tx_stops);
	sprintf(buf + strlen(buf), "rx_mac_timeout=%llu\n",
		stats->rx_mac_timeout);
	for (i = 0; i < CONFIG_NR_PORTS; i++)
		rx_bytes += info->adapter->netdev[i]->stats.rx_bytes;
	if (rx_bytes > 0) {
		sprintf(buf + strlen(buf), "rx_cycles_per_KB rx_alloc=%llu"
			" copy=%llu zero=%llu stack=%llu\n",
			(ELAPSED_CYCLES(0) << 10) / rx_bytes,
			(ELAPSED_CYCLES(1) << 10) / rx_bytes,
			(ELAPSED_CYCLES(2) << 10) / rx_bytes,
			(ELAPSED_CYCLES(3) << 10) / rx_bytes);
	}

	return strlen(buf);
}

static ssize_t init_lbuf_stat(struct device *dev,
			     struct device_attribute *attr,
			     const char *buf, size_t count)
{
	struct lbuf_info *info = container_of(attr, struct lbuf_info,
					      stat_attr);
	memset(&info->stats, 0, sizeof(info->stats));
	return count;
}

/**
 * nf10_lbuf_get_pfn - [user_ops] return PFN of kernel page by mmap index
 * @adapter: associated adapter structure
 * @size: lbuf size requested by user process via mmap
 *
 * This function is called by mmap from user process to map metadata and lbuf
 * pages allocated in kernel. size is used for sanity check.
 * Corresponding page is decided by adapter->nr_user_mmap, which is incremented
 * if mmap is sucessfully done. The current mapping is
 * nr_user_mmap == 0: general metadata page
 *              == 1: metadata for tx completion (slot availability, gc address)
 *              == 2-(2+NR_SLOT-1): rx lbufs
 *              == (2+NR_SLOT)- : tx lbufs (variable and guided by user process)
 **/
static unsigned long nf10_lbuf_get_pfn(struct nf10_adapter *adapter,
				       unsigned long size)
{
	unsigned int idx = adapter->nr_user_mmap;
	unsigned long pfn = 0;	/* 0 means error */

	if (idx == 0) {		/* general metadata page */
		pfn = virt_to_phys(lbuf_info.u) >> PAGE_SHIFT;
		netif_info(adapter, drv, default_netdev(adapter),
			   "%s: [%u] DMA metadata page (pfn=%lx)\n",
			   __func__, idx, pfn);
	}
	else if (idx == 1) {	/* metadata for tx completion page */
		void *addr = lbuf_info.tx_completion_kern_addr;
		pfn = virt_to_phys(addr) >> PAGE_SHIFT;
		netif_info(adapter, drv, default_netdev(adapter),
			   "%s: [%u] DMA tx completion area (pfn=%lx)\n",
			   __func__, idx, pfn);
	}
	else {			/* rx/tx data pages */
		idx -= 2;	/* adjust index to data */
		if (idx < NR_SLOT && size == LBUF_RX_SIZE)	/* rx */
			pfn = get_rx_desc(idx)->dma_addr >> PAGE_SHIFT;
		else if (idx >= NR_SLOT && size >= MIN_TX_USER_LBUF_SIZE &&
					   size <= MAX_TX_USER_LBUF_SIZE)
			pfn = get_tx_user_lbuf(adapter, idx - NR_SLOT, size);
			
		netif_info(adapter, drv, default_netdev(adapter),
			   "%s: [%u] data page (pfn=%lx size=%lu)\n",
			   __func__, adapter->nr_user_mmap, pfn, size);
	}
	return pfn;
}

/**
 * nf10_lbuf_user_xmit - [user_ops] transmit user tx lbuf
 * @adapter: associated adapter structure
 * @arg: metadata including reference id and legnth of user tx lbuf
 *
 * This function is called by user process via ioctl (in nf10_user.c)
 **/
static u32 lbuf_xmit(struct nf10_adapter *adapter, struct desc *desc);
static int nf10_lbuf_user_xmit(struct nf10_adapter *adapter, unsigned long arg)
{
	struct desc *desc;
	u32 ref = XMIT_REF(arg);
	u32 len = XMIT_LEN(arg);
	
	netif_dbg(adapter, drv, default_netdev(adapter),
		  "user_xmit: ref=%u len=%u arg=%lx\n", ref, len, arg);

	if (unlikely(ref >= MAX_TX_USER_LBUF)) {
		pr_err("%s: Error invalid ref %u >= %d\n",
		       __func__, ref, MAX_TX_USER_LBUF);
		return -EINVAL;
	}
	desc = tx_user_desc(ref);
	if (unlikely(desc == NULL)) {
		pr_err("%s: Error tx_user_lbufs[%d] is NULL\n", __func__, ref);
		return -EINVAL;
	}
	/* no need to acquire desc->lock, since this lbuf is ensured not to
	 * have been transmitted to hardware. user tx lbuf is used one-shot,
	 * so prod (=0) to prod_pvt (=len) represents pending data before
	 * lbuf_xmit, while cons is 0, since it's not consumed */
	set_tx_prod(desc, 0);
	set_tx_prod_pvt(desc, len);
	set_tx_cons(desc, 0);

	lbuf_xmit(adapter, desc);

	return 0;
}

static struct nf10_user_ops lbuf_user_ops = {
	.get_pfn		= nf10_lbuf_get_pfn,
	.prepare_rx_buffer	= nf10_lbuf_prepare_rx,
	.start_xmit		= nf10_lbuf_user_xmit,
};

/**
 * nf10_lbuf_set_irq_period - [hw_ops] set IRQ period to DMA
 * @adapter: associated adapter structure
 *
 * The period to be set should be updated first in adapter->irq_period_usecs 
 **/
static int nf10_lbuf_set_irq_period(struct nf10_adapter *adapter)
{
	nf10_writel(adapter, IRQ_PERIOD_REG,
		    adapter->irq_period_usecs * 1000 /* ns */);
	netif_info(adapter, probe, default_netdev(adapter),
		   "%u us is set as irq period\n", adapter->irq_period_usecs);
	return 0;
}

/**
 * nf10_lbuf_init - [hw_ops] init lbuf DMA
 * @adapter: associated adapter structure
 **/
static int nf10_lbuf_init(struct nf10_adapter *adapter)
{
	int err;

	/* create desc pool */
	desc_cache = kmem_cache_create("lbuf_desc",
				       sizeof(struct desc),
				       __alignof__(struct desc),
				       0, NULL);
	if (desc_cache == NULL) {
		pr_err("failed to alloc desc_cache\n");
		return -ENOMEM;
	}
	/* init lbuf user-visiable single-page space for metadata */
	if ((lbuf_info.u =
	     (struct lbuf_user *)get_zeroed_page(GFP_KERNEL)) == NULL) {
		netif_err(adapter, rx_err, default_netdev(adapter),
			  "failed to alloc lbuf user page\n");
		kmem_cache_destroy(desc_cache);
		return -ENOMEM;
	}
	lbuf_info.adapter = adapter;
	adapter->user_ops = &lbuf_user_ops;

	adapter->irq_period_usecs = DEFAULT_INTR_PERIOD_USECS;
	nf10_lbuf_set_irq_period(adapter);

	/* create a device file to show lbuf stats */
	lbuf_info.stat_attr.attr.name = "lbuf_stat";
	lbuf_info.stat_attr.attr.mode = S_IRUGO | S_IWUSR;
	lbuf_info.stat_attr.show = show_lbuf_stat;
	lbuf_info.stat_attr.store = init_lbuf_stat;

	sysfs_attr_init(&lbuf_info.stat_attr.attr);

	err = device_create_file(&adapter->pdev->dev, &lbuf_info.stat_attr);
	if (err)
		pr_warn("failed to create file for lbuf_stat\n");

	return 0;
}

/**
 * nf10_lbuf_free - [hw_ops] free lbuf DMA
 * @adapter: associated adapter structure
 **/
static void nf10_lbuf_free(struct nf10_adapter *adapter)
{
	kmem_cache_destroy(desc_cache);
	device_remove_file(&adapter->pdev->dev, &lbuf_info.stat_attr);
}

/**
 * nf10_lbuf_init_buffers - [hw_ops] init tx and rx lbufs
 * @adapter: associated adapter structure
 **/
static int nf10_lbuf_init_buffers(struct nf10_adapter *adapter)
{
	int err = 0;

	if ((err = init_tx_lbufs(adapter)))
		return err;

	if ((err = init_rx_lbufs(adapter)))
		free_tx_lbufs(adapter);

	return err;
}

/**
 * nf10_lbuf_free_buffers - [hw_ops] free tx and rx lbufs
 * @adapter: associated adapter structure
 **/
static void nf10_lbuf_free_buffers(struct nf10_adapter *adapter)
{
	free_tx_lbufs(adapter);
	free_rx_lbufs(adapter);
}

/**
 * move_to_next_lbuf - re-prepare current lbuf and switch to next lbuf
 * @adapter: associated adapter structure
 *
 * This function prepares the current closed lbuf and increment rx lbuf slot
 * index. In deliver_packet, all the consumed area had been zeroed, so just
 * need to initialize lbuf header before preparation. rx_cons is initialized
 * to LBUF_RX_RESERVED_DWORDS, the start point for packet data.
 **/
static void move_to_next_lbuf(struct nf10_adapter *adapter)
{
	netif_dbg(adapter, rx_status, default_netdev(adapter),
		  "%s: rx_idx=%u\n", __func__, rx_idx());

	LBUF_RX_INIT_HEADER(cur_rx_desc()->kern_addr);
	wmb();
	nf10_lbuf_prepare_rx(adapter, (unsigned long)rx_idx());
	inc_rx_idx();
	set_rx_cons(LBUF_RX_RESERVED_DWORDS);
}

/**
 * deliver_packet - deliver a packet from lbuf to kernel protocol layer
 * @netdev: net device passed from a packet
 * @pkt_addr: address of the packet to be delivered from lbuf
 * @pkt_len: length of the packet
 * @pskb: allocated skb to convey the packet (*pskb becomes NULL after delivery)
 * @work_done: # of delivered packets for NAPI (incremented after delivery)
 *
 * Since rx lbuf is permanently used, it should be zeroed before preparing to
 * DMA. Currently, zeroing is done right after a pakcet is copied to skb data.
 * An alternative is that zeroing before preparation.
 **/
static void deliver_packet(struct net_device *netdev, void *pkt_addr,
		unsigned int pkt_len, struct sk_buff **pskb, int *work_done)
{
	struct nf10_adapter *adapter = netdev_adapter(netdev);
	struct sk_buff *skb = *pskb;

	/* interface is down, skip it */
	if (unlikely(netdev_port_up(netdev) == 0))
		return;

	START_TIMESTAMP(1);
	skb_copy_to_linear_data(skb, pkt_addr, pkt_len);
	STOP_TIMESTAMP(1);

	START_TIMESTAMP(2);
	memset(pkt_addr - LBUF_TX_METADATA_SIZE, 0,
	       ALIGN(pkt_len, 8) + LBUF_TX_METADATA_SIZE);
	STOP_TIMESTAMP(2);

	START_TIMESTAMP(3);
	skb_put(skb, pkt_len);
	skb->protocol = eth_type_trans(skb, netdev);
	skb->ip_summed = CHECKSUM_NONE;
	napi_gro_receive(&adapter->napi, skb);
	STOP_TIMESTAMP(3);

	netdev->stats.rx_packets++;
	netdev->stats.rx_bytes += pkt_len;
	(*work_done)++;
	(*pskb) = NULL;
}

/**
 * nf10_lbuf_process_rx_irq - [hw_ops] process received packets from rx lbuf
 * @adapter: associated adapter structure
 * @work_done: # of packets handled in the function and returned to NAPI loop
 * @budget: NAPI budget of packets that are allowed to consumed in a call
 *
 * This function scans the current rx lbuf, extracts each packet received, and
 * passes it to upper layer using skb. In lbuf DMA, packets received from MAC
 * core are written to a rx lbuf in a compact way, hence currently variable sized
 * area for each packet. To deal with such variable size, the lbuf should be
 * prepared as a zeroed lbuf making software to decide each packet is completely
 * received, so that it can be safely passed to upper layer.
 * See README for the details.
 **/
static void nf10_lbuf_process_rx_irq(struct nf10_adapter *adapter, 
				     int *work_done, int budget)
{
	void *buf_addr;
	unsigned int dword_idx, next_dword_idx;
	struct sk_buff *skb;
	int port_num;
	void *pkt_addr;
	unsigned int pkt_len, next_pkt_len;
	struct net_device *netdev = NULL;
	union lbuf_header lh;

	do {
		skb = NULL;
		buf_addr = cur_rx_desc()->kern_addr;
		/* rx cons pointer is maintained in dword unit */
		dword_idx = get_rx_cons();
		pkt_len = LBUF_RX_PKT_LEN(buf_addr, dword_idx);
		port_num = LBUF_PKT_PORT_NUM(buf_addr, dword_idx);

		/* if the current packet length is zero, two cases are possible:
		 * 1) no more packet has arrived
		 * 2) this lbuf has no space to receive (so-called lbuf closed)
		 */
		if (pkt_len == 0) {
			/* if this lbuf is closed, move to next lbuf */
			LBUF_RX_GET_HEADER(buf_addr, lh);
			if (LBUF_RX_CLOSED(dword_idx, lh)) {
				move_to_next_lbuf(adapter);
				continue;
			}
			/* Now make sure no packet has arrived, exit the loop */
			break;
		}
		/* BUG if the fetched port number or packet length is invalid.
		 * if so, sync between sw and hw is likely to be lost */
		if (unlikely(!LBUF_IS_PKT_VALID(port_num, pkt_len))) {
			netdev = LBUF_IS_PORT_VALID(port_num) ?
				adapter->netdev[port_num] :
				default_netdev(adapter);
			netif_err(adapter, rx_err, netdev,
				  "Error: invalid packet "
				  "(port_num=%d, len=%u at rx_idx=%d lbuf[%u])",
				  port_num, pkt_len, rx_idx(), dword_idx);
			/* For DMA hardware debugging, some contents of previous
			 * and next packets are dumped */
			print_hex_dump(KERN_WARNING, "", DUMP_PREFIX_NONE, 16,1,
				(u32 *)buf_addr + (dword_idx - 32), 128, true);
			printk("-this packet ------------------------------\n");
			print_hex_dump(KERN_WARNING, "", DUMP_PREFIX_NONE, 16,1,
				(u32 *)buf_addr + dword_idx, 128, true);
			/* XXX: user_flags is not meant for it, but in this
			 * exceptional case (RX hang), we disable IRQ for good
			 * not to indefinitely generate IRQ and this report.
			 * Anyway, this is unrecoverable situation */
			adapter->user_flags |= UF_IRQ_DISABLED;
			break;
		}
		/* Now, pkt_len > 0,
		 * meaning the current packet starts being received.
		 * First, check if user process is running for rx */
		if (nf10_user_callback(adapter, 1)) {
			/* if user process takes it, work_done 0 lets
			 * NAPI loop stop */
			*work_done = 0;
			return;
		}
		netdev = adapter->netdev[port_num];
		if (unlikely(!skb)) { /* skb becomes NULL if delieved */
			START_TIMESTAMP(0);
			skb = netdev_alloc_skb_ip_align(netdev, pkt_len);
			STOP_TIMESTAMP(0);
			if (unlikely(!skb)) {
				netif_err(adapter, rx_err, netdev,
					"failed to alloc skb (l=%u)", pkt_len);
				break;
			}
		}
		pkt_addr = LBUF_RX_PKT_ADDR(buf_addr, dword_idx);
		next_dword_idx = LBUF_RX_NEXT_DWORD_IDX(dword_idx, pkt_len);
wait_to_end_recv:
		/* lbuf rx engine uses the value of the length of next packet
		 * to determine if the current packet is completely received */
		next_pkt_len = LBUF_RX_PKT_LEN(buf_addr, next_dword_idx);
		if (next_pkt_len > 0) {
			/* if next packet length is non-zero, the current packet
			 * is received entirely, so deliver this to kernel */
			deliver_packet(netdev, pkt_addr, pkt_len,
				       &skb, work_done);
			set_rx_cons(next_dword_idx);
		}
		else {	/* next_pkt_len == 0 */
			/* if next pakcet length is zero, three cases:
			 * 1) the current packet reception is in progress
			 * 2) this lbuf is closed due to insufficient space
			 * 3) MAC timeout occurs, so DMA jumped to 128B-aligned
			 */
			LBUF_RX_GET_HEADER(buf_addr, lh);
			/* lazy update: rx_dropped is eventually accurate */
			netdev->stats.rx_dropped = lh.nr_drops;

			/* using nr_qwords in lbuf header to know if 1) is true
			 * if nr_qwords < next qword index, 1) is met,
			 * so keep waiting for the current packet */
			if ((lh.nr_qwords << 1) <
			    next_dword_idx - LBUF_RX_RESERVED_DWORDS)
				goto wait_to_end_recv;

			/* if nr_qwords >= next qword index
			 * the entire packet is received, consume it */
			deliver_packet(netdev, pkt_addr, pkt_len,
				       &skb, work_done);

			/* check if the lbuf is closed -> 2) is true */
			if (LBUF_RX_CLOSED(next_dword_idx, lh)) {
				move_to_next_lbuf(adapter);
				continue;
			}
			/* now would make sure that only 3) is left, but next
			 * packet length may become non-zero, which means
			 * a following packet triggers MAC time out. So, before
			 * asserting MAC timeout occurance, check again */
			next_pkt_len = LBUF_RX_PKT_LEN(buf_addr, next_dword_idx);
			if (next_pkt_len == 0) {
				/* MAC timeout, DMA has jumped to 128-aligned
				 * address for the next packet */
				next_dword_idx = LBUF_RX_128B_ALIGN(next_dword_idx);
				lbuf_info.stats.rx_mac_timeout++;
			}
			set_rx_cons(next_dword_idx);
		}
		/* check if next_dword_idx exceeds lbuf */
		if (get_rx_cons() >= (cur_rx_desc()->size >> 2))
			move_to_next_lbuf(adapter);
	} while(*work_done < budget);

	netif_dbg(adapter, rx_status, default_netdev(adapter),
		  "loop exit: i=%u n=%d rx=%lu\n", dword_idx, *work_done,
		  likely(netdev) ? netdev->stats.rx_packets : 0);
}

/**
 * lbuf_xmit - send pending data in lbuf to hardware
 * @adapter: associated adapter structure
 * @desc: lbuf descriptor to be transmitted
 *
 * This function flushes pending data (from prod to prod_pvt) from lbuf
 * to hardware by writing address and length to tx doorbell register.
 * Since there are multiple doorbell slots, slot index is claimed first
 * and write to the doorbell registers on the claimed slot.
 * Before touching the doorbell registers, a few pointer manipulation
 * with desc->lock being held is needed. 
 * 1) Once any pending data is sent, next prod must be aligned with 4KB.
 * 2) If the next prod reaches the end of lbuf, it must be wrapped around to 0.
 * 3) Since pending data to prod_pvt is sent, prod becomes the same as prod_pvt.
 *
 * Returns sent bytes
 **/
static u32 lbuf_xmit(struct nf10_adapter *adapter, struct desc *desc)
{
	u32 idx;
	u32 nr_qwords;
	u32 prod, next_prod;
 	u32 prod_pvt;
	u32 bytes_to_send;
	dma_addr_t dma_addr;

	spin_lock_bh(&desc->lock);
	/* get the current slot index, prod, prod_pvt */
	idx = tx_idx();
	prod = get_tx_prod(desc);
	prod_pvt = get_tx_prod_pvt(desc);

	/* if the current slot is unavailable or no pending data exists
	 * return zero byte */
	if (!get_tx_avail(idx) || prod == prod_pvt) {
		spin_unlock_bh(&desc->lock);
		return 0;
 	}
	/* before making prod and prod_pvt the same, let prod_pvt be aligned
	 * with 4KB, which is required by hardware */
	next_prod = ALIGN(prod_pvt, 4096);
	/* wrap around if reaching the end of lbuf */
	if (unlikely(next_prod == desc->size))
		next_prod = 0;
	/* synchronize prod and prod_pvt with the same next pointer */
	set_tx_prod(desc, next_prod);
	set_tx_prod_pvt(desc, next_prod);

	/* claim the current slot */
	set_tx_used(idx);
	inc_tx_idx();

	/* update stats */
	lbuf_info.stats.tx_lbufs++;
	bytes_to_send = prod_pvt - prod;
	lbuf_info.stats.tx_bytes += bytes_to_send;
	spin_unlock_bh(&desc->lock);

	dma_addr = desc->dma_addr + prod;
 	nr_qwords = bytes_to_send >> 3;

	if (unlikely(!IS_ALIGNED(dma_addr, 4096))) {
		pr_err("Error: cannot send 4K-unaligned buffer:%p\n",
		       (void *)dma_addr);
		return -EINVAL;
	}
	/* write hardware address and length in qwords to the doorbell
	 * registers of the claimed slot */
	wmb();
	nf10_writeq(adapter, tx_addr_off(idx), dma_addr);
	nf10_writel(adapter, tx_stat_off(idx), nr_qwords);

	netif_dbg(adapter, tx_queued, default_netdev(adapter),
		  "\trqtx[%u]: c%d l=%u prod=[%u:%u] dma_addr=%p qw=%u\n",
		  idx, smp_processor_id(), bytes_to_send, prod, prod_pvt,
		  (void *)dma_addr, nr_qwords);

	return bytes_to_send;
}

static unsigned long __copy_skb_to_lbuf(struct desc *desc, void *buf_addr,
					int port_num, struct sk_buff *skb)
{
	int i;
	void *p;

	/* to take advantage of GSO, we faked SG and now emulate SG by copying
	 * from scattered buffers to lbuf */
	buf_addr = LBUF_TX_CUR_ADDR(buf_addr, port_num, skb->len);
	skb_copy_from_linear_data(skb, buf_addr, skb_headlen(skb));
	p = buf_addr + skb_headlen(skb);
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0)
		memcpy(p, skb_frag_address(frag), skb_frag_size(frag));
#else
		memcpy(p, page_address(frag->page) + frag->page_offset, frag->size);
#endif
		p += frag->size;
	}
	buf_addr = LBUF_TX_NEXT_ADDR(buf_addr, skb->len);
	return buf_addr - desc->kern_addr;	/* updated prod_pvt */
}

/**
 * copy_skb_to_lbuf - copy skb's data with its length to tx lbuf
 * @netdev: transmitting netdev
 * @skb: skb to be transmitted
 * @desc: destination tx lbuf (usually kernel tx lbuf)
 *
 * This function is in charge copying skb'data to tx lbuf, along with
 * available space check and update of prod_pvt. Note that data from prod
 * to prod_pvt represents pending (copied-but-not-sent) packets.
 * Currently, pointer manipulation and copying itself are
 * protected by desc->lock to handle race with lbuf_xmit in irq handler.
 * TODO: it could be optimized by reducing the critical section.
 *
 * Returns whether copying is succeeded or not to guide nf10_lbuf_start_xmit
 * to decide to call lbuf_xmit to flush the pending packets
 **/
static int copy_skb_to_lbuf(struct net_device *netdev,
			    struct sk_buff *skb, struct desc *desc)
{
	unsigned int pkt_len = skb->len;
	u32 prod;
	u32 prod_pvt;
	u32 cons;
	u32 avail_size;

	if (unlikely(pkt_len == 0))
		return 0;

	spin_lock_bh(&desc->lock);
	prod = get_tx_prod(desc);
	prod_pvt = get_tx_prod_pvt(desc);

	/* check if space is available, if not, returned with EBUSY,
	 * irq handler calls lbuf_xmit, which takes care of wrap-around, and
	 * wakes up netdev's tx queue to retry this copy */
	if (!LBUF_TX_HAS_ROOM(desc->size, prod_pvt, pkt_len))
		goto no_buf_space;

	/* check to safely produce packet by examining cons */
	cons = get_tx_cons(desc);
	avail_size = (cons > prod_pvt ? 0 : desc->size) + cons - prod_pvt;
	/* 4KB margin is needed to prevent prod from overtaking cons */
	if (ALIGN(pkt_len, 8) + LBUF_TX_METADATA_SIZE + 4096 > avail_size)
		goto no_buf_space;

	/* now we have enough room to copy the packet */
	prod_pvt = __copy_skb_to_lbuf(desc, desc->kern_addr + prod_pvt,
				      netdev_port_num(netdev), skb);
	set_tx_prod_pvt(desc, prod_pvt);

	if (unlikely(prod_pvt > cons && prod < cons))	/* must not happen */
		pr_err("Error: overwritten (p=%u p'=%u c=%u a=%u)\n",
		       prod_pvt, prod, cons, avail_size);
	netdev->stats.tx_packets++;
	netdev->stats.tx_bytes += pkt_len;
	spin_unlock_bh(&desc->lock);

	return 0;

no_buf_space:
	spin_unlock_bh(&desc->lock);
	return -EBUSY;
}

/**
 * nf10_lbuf_start_xmit - [hw_ops] entry point of tx from kernel protocol layer
 * @skb: skb passed from kernel
 * @netdev: relevant device associated with a nf10 port
 *
 * This function copies skb's data to the preallocated kernel buffer for tx.
 * If the buffer doesn't have enough space, it stops the queue and return BUSY.
 **/
static netdev_tx_t nf10_lbuf_start_xmit(struct sk_buff *skb,
					struct net_device *netdev)
{
	struct nf10_adapter *adapter = netdev_adapter(netdev);
	struct desc *desc = tx_kern_desc();

	if (copy_skb_to_lbuf(netdev, skb, desc)) {
		/* no space available in lbuf */
		lbuf_info.stats.tx_stops++;
		netif_stop_queue(netdev);
		return NETDEV_TX_BUSY;
	}
	/* now we have copied skb to lbuf */
	lbuf_xmit(adapter, desc);
	dev_kfree_skb_any(skb);

	return NETDEV_TX_OK;
}

/**
 * nf10_lbuf_clean_tx_irq - [hw_ops] clean tx buffers drained to hardware
 * @adapter: associated adapter structure
 *
 * This function is called by NAPI loop to make kernel tx buffer space
 * that is drained from host memory to hardware available to be reused
 * for the transmission of new packets.
 *
 * Returns whether pending tx buffer is entire cleaned or not to guide
 * NAPI loop whether to continue
 **/
static int nf10_lbuf_clean_tx_irq(struct nf10_adapter *adapter)
{
	dma_addr_t hw_gc_addr, sw_gc_addr;
	u32 cons;
	struct desc *desc = tx_kern_desc();
	int i;
	u32 nr_cleaned = 0;

again:
	rmb();
	hw_gc_addr = get_hw_gc_addr();
	sw_gc_addr = get_sw_gc_addr();
	/* if no hw gc address updated since the last update of sw gc addr,
	 * no need to proceed gc, but also comply with tx clean budget
	 * to give rx cleaner a chance to receive packets */
	if (hw_gc_addr == sw_gc_addr || nr_cleaned > TX_CLEAN_BUDGET)
		goto out;

	nr_cleaned++;

	/* the only place where sw gc addr is synced with hw one,
	 * this updated one will be synced with hw when enable_irq */
	set_sw_gc_addr(hw_gc_addr);

	if (!addr_in_lbuf(tx_kern_desc(), hw_gc_addr)) {
		/* gc addr doesn't belong to kernel tx buffer, it's for
		 * user buffer, so wake up user process if any.
		 * if user process has been initialized, this function returns
		 * true, and return with 1 indicating tx clean is complete */
		if (nf10_user_callback(adapter, 0))
			return 1;

		/* user is not on, it may be the one for previous tx by user,
		 * which is now terminated */
		pr_warn("Warn: non-kernel hw_gc_addr (%p) seen in irq\n",
			(void *)hw_gc_addr);
		goto out;
	}

	/* cons is always maintained as
	 * 1) relative offset based on desc->dma_addr
	 * 2) 4KB-aligned */
	cons = ALIGN(hw_gc_addr - desc->dma_addr, 4096);
	if (cons == desc->size)
		cons = 0;
	set_tx_cons(desc, cons);
	smp_wmb();

	/* we've just collected newly available tx space,
	 * let's try tx for pending packets */
	lbuf_xmit(adapter, desc);

	/* wake stopped queue, to resume pending skbs to be copied */
	for (i = 0; i < CONFIG_NR_PORTS; i++)
		if (netif_queue_stopped(adapter->netdev[i]))
			netif_wake_queue(adapter->netdev[i]);

	netif_dbg(adapter, tx_done, default_netdev(adapter),
		  "gctx: gc_addr=(hw:%p,last-sw:%p) cons=%u\n",
		  (void *)hw_gc_addr, (void *)sw_gc_addr, get_tx_cons(desc));

	/* if still not cleaned for tx, try again to see if more gc needed */
	if (!tx_clean_completed(desc))
		goto again;
out:
	return tx_clean_completed(desc);
}

/**
 * nf10_lbuf_ctrl_irq - [hw_ops] control IRQ with command
 * @adapter: associated adapter structure
 * @cmd: control command
 *
 * The commands are defined in nf10.h.
 **/
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
	.process_rx_irq		= nf10_lbuf_process_rx_irq,
	.start_xmit		= nf10_lbuf_start_xmit,
	.clean_tx_irq		= nf10_lbuf_clean_tx_irq,
	.ctrl_irq		= nf10_lbuf_ctrl_irq,
	.set_irq_period		= nf10_lbuf_set_irq_period,
};

void nf10_lbuf_set_hw_ops(struct nf10_adapter *adapter)
{
	adapter->hw_ops = &lbuf_hw_ops;
}
