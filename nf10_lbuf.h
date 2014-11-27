/*******************************************************************************
*
*  NetFPGA-10G http://www.netfpga.org
*
*  File:
*        nf10_lbuf.h
*
*  Project:
*
*
*  Author:
*        Hwanju Kim
*
*  Description:
*	 This header file is for lbuf DMA implmentation.
*
*	 This code is initially developed for the Network-as-a-Service (NaaS) project.
*	 (under development in https://github.com/NetFPGA-NewNIC/linux-driver)
*        
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

#ifndef _NF10_LBUF_H
#define _NF10_LBUF_H

#include <linux/types.h>
#include <linux/pci.h>
#include <linux/list.h>
#include "nf10.h"

/* offset to bar2 address of the card */
#define RX_LBUF_ADDR_BASE	0x40
#define RX_LBUF_STAT_BASE	0x60
#define RX_READY		0x1
#define TX_LBUF_ADDR_BASE	0x80
#define TX_LBUF_STAT_BASE	0xA0
#define TX_COMPLETION_ADDR	0xB0
#define TX_COMPLETION_SIZE	((NR_SLOT << 2) + 8)	/* DWORD for each desc + QWORD (last gc addr) */
#define TX_LAST_GC_ADDR_OFFSET	(NR_SLOT << 2)		/* last gc addr following completion buffers for all descs */
#define TX_AVAIL		0xcacabeef
#define TX_USED			0		/* not HW-dependent could be any value but TX_AVAIL */
#define IRQ_ENABLE_REG		0x20
#define IRQ_DISABLE_REG		0x24
#define IRQ_PERIOD_REG		0x28
#define IRQ_CTRL_VAL		0xcacabeef
#define TX_WRITEBACK_REG	0xB8
#define RX_WRITEBACK_REG	0x78

#define rx_addr_off(i)	(RX_LBUF_ADDR_BASE + (i << 3))
#define rx_stat_off(i)	(RX_LBUF_STAT_BASE + (i << 2))
#define tx_addr_off(i)	(TX_LBUF_ADDR_BASE + (i << 3))
#define tx_stat_off(i)	(TX_LBUF_STAT_BASE + (i << 2))

struct nf10_adapter;
extern void nf10_lbuf_set_hw_ops(struct nf10_adapter *adapter);

struct desc {
	void			*kern_addr;
	dma_addr_t		dma_addr;
	u32			size;
	struct sk_buff_head	skbq;
	struct list_head	list;
};

struct lbuf_head {
	struct list_head head;
	spinlock_t lock;
};

#define lbuf_for_each_entry_safe(pos, n, lhead)	\
	list_for_each_entry_safe(pos, n, &(lhead)->head, list)

static inline void lbuf_head_init(struct lbuf_head *head)
{
	INIT_LIST_HEAD(&head->head);
	spin_lock_init(&head->lock);
}

static inline int lbuf_queue_empty(struct lbuf_head *head)
{
	smp_read_barrier_depends();
	return list_empty(&head->head);
}

static inline void __lbuf_queue_tail(struct lbuf_head *head, struct desc *desc)
{
	list_add_tail(&desc->list, &head->head);
}

static inline void __lbuf_queue_head(struct lbuf_head *head, struct desc *desc)
{
	list_add(&desc->list, &head->head);
}

static inline struct desc *__lbuf_dequeue(struct lbuf_head *head)
{
	struct desc *desc = NULL;

	if (!list_empty(&head->head)) {
		desc = list_first_entry(&head->head, struct desc, list);
		list_del(&desc->list);
	}
	return desc;
}

static inline void __lbuf_del(struct desc *desc)
{
	list_del(&desc->list);
}

extern void lbuf_queue_tail(struct lbuf_head *head, struct desc *desc);
extern void lbuf_queue_head(struct lbuf_head *head, struct desc *desc);
extern struct desc *lbuf_dequeue(struct lbuf_head *head);

#endif
