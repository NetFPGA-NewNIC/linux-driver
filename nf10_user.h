/*******************************************************************************
*
*  NetFPGA-10G http://www.netfpga.org
*
*  File:
*        nf10_user.h
*
*  Project:
*
*
*  Author:
*        Hwanju Kim
*
*  Description:
*	 This header file is for kernel-user interface.
*	 It can be included in both the kernel and user who wants to directly
*	 access DMA. It works with legacy rdaxi/wraxi in the original NetFPGA
*	 by assigning the same command codes to NF10_IOCTL_CMD_{WRITE|READ}_REG.
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

#ifndef _NF10_USER_H
#define _NF10_USER_H

#define NF10_DRV_NAME			"nf10"
#define NF10_IOCTL_CMD_READ_STAT	(SIOCDEVPRIVATE+0)
#define NF10_IOCTL_CMD_WRITE_REG	(SIOCDEVPRIVATE+1)
#define NF10_IOCTL_CMD_READ_REG		(SIOCDEVPRIVATE+2)
#ifdef CONFIG_OSNT
/* for compat w/ OSNT python apps */
#define NF10_IOCTL_CMD_WRITE_REG_PY	(SIOCDEVPRIVATE+9)
#endif

/*
 * Packet processing
 */
#define NF10_IOCTL_CMD_INIT		(SIOCDEVPRIVATE+3)
#define NF10_IOCTL_CMD_EXIT		(SIOCDEVPRIVATE+4)
/* Rx */
#define NF10_IOCTL_CMD_PREPARE_RX	(SIOCDEVPRIVATE+5)
/* Tx */
#define NF10_IOCTL_CMD_XMIT		(SIOCDEVPRIVATE+20)

#define XMIT_SHIFT			28
#define XMIT_MASK			((1 << XMIT_SHIFT) - 1)
#define NF10_IOCTL_ARG_XMIT(ref, len)	((ref << XMIT_SHIFT) | (len & XMIT_MASK))

/* user_flags (for user and kernel) */
#define UF_RX_ON	0x01
#define UF_TX_ON	0x02
#define UF_ON_MASK	(UF_RX_ON | UF_TX_ON)

#ifdef __KERNEL__
#include "nf10.h"
#define XMIT_LEN(arg)			(arg & XMIT_MASK)
#define XMIT_REF(arg)			(arg >> XMIT_SHIFT)

/* user_flags (for kernel only) */
#define UF_RX_PENDING	0x04
#define UF_TX_PENDING	0x08
#define UF_IRQ_DISABLED	0x10
#define UF_GC_ADDR_SYNC	0x20

extern int nf10_init_fops(struct nf10_adapter *adapter);
extern int nf10_remove_fops(struct nf10_adapter *adapter);
extern bool nf10_user_callback(struct nf10_adapter *adapter, int rx);
#endif
#endif
