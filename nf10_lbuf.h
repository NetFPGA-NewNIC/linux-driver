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

struct nf10_adapter;
extern void nf10_lbuf_set_hw_ops(struct nf10_adapter *adapter);

struct desc {
	void			*kern_addr;
	dma_addr_t		dma_addr;
	u32			size;
	unsigned int		tx_prod;
	unsigned int		tx_prod_pvt;
	unsigned int		tx_cons;
	spinlock_t		lock;
};
/* 
 * kernel buffers: kernel uses pre-allocated dma-coherent tx and rx buffers.
 * The size of tx buffer could be configured at compile time, but
 * the size of rx buffer is currently fixed to 2MB by DMA hardware.
 * The information of rx buffers are defined in nf10_lbuf_api.h, since
 * the kernel buffers are directly used by user-level library via mmap().
 */
#define LBUF_TX_ORDER	10	/* default 4MB */
#define LBUF_TX_SIZE	(1UL << (PAGE_SHIFT + LBUF_TX_ORDER))
#endif
