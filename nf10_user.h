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
#define NF10_IOCTL_CMD_INIT		(SIOCDEVPRIVATE+3)
#define NF10_IOCTL_CMD_PREPARE_RX	(SIOCDEVPRIVATE+4)
#define NF10_IOCTL_CMD_WAIT_INTR	(SIOCDEVPRIVATE+5)
#ifdef CONFIG_OSNT
/* for compat w/ OSNT python apps */
#define NF10_IOCTL_CMD_WRITE_REG_PY	(SIOCDEVPRIVATE+9)
#endif

#ifdef __KERNEL__
#include "nf10.h"
extern int nf10_init_fops(struct nf10_adapter *adapter);
extern int nf10_remove_fops(struct nf10_adapter *adapter);
extern bool nf10_user_rx_callback(struct nf10_adapter *adapter);
#endif

#endif
