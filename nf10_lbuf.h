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
	unsigned int		tx_prod;
	unsigned int		tx_prod_pvt;
	unsigned int		tx_cons;
};
#endif
