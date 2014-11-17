/*******************************************************************************
*
*  NetFPGA-10G http://www.netfpga.org
*
*  File:
*        nf10.h
*
*  Project:
*
*
*  Author:
*        Hwanju Kim
*
*  Description:
*	 This header file is the main header independent of DMA implmentation.
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

#ifndef _NF10_H
#define _NF10_H

#include <linux/netdevice.h>
#include <linux/types.h>
#include <linux/ethtool.h>
#include <linux/pci.h>
#include <linux/cdev.h>
#include "nf10_lbuf.h"

#define NF10_VENDOR_ID	0x10ee
#define NF10_DEVICE_ID	0x4245

struct nf10_adapter {
	struct napi_struct napi;
	struct net_device *netdev[CONFIG_NR_PORTS];
	struct pci_dev *pdev;

	u8 __iomem *bar0;
	u8 __iomem *bar2;

	struct nf10_hw_ops *hw_ops;

	u16 msg_enable;
#ifdef CONFIG_PHY_INIT
	atomic_t mdio_access_rdy;
#endif
	/* direct user access (kernel bypass) */
	struct nf10_user_ops *user_ops;
	unsigned long user_private;
	struct cdev cdev;
	unsigned int nr_user_mmap;
	wait_queue_head_t wq_user_intr;
	/* AXI register interface */
	dma_addr_t axi_completion_dma_addr;
	void *axi_completion_kern_addr;
};
#define default_netdev(adapter)		(adapter->netdev[0])

struct nf10_netdev_priv {
	struct nf10_adapter *adapter;
	int port_num;
	int port_up;
};
#define get_netdev_priv(netdev)	((struct nf10_netdev_priv *)netdev_priv(netdev))
#define netdev_adapter(netdev)	(get_netdev_priv(netdev)->adapter)
#define netdev_port_num(netdev)	(get_netdev_priv(netdev)->port_num)
#define netdev_port_up(netdev)	(get_netdev_priv(netdev)->port_up)

/* interrupt control commands used for nf10_hw_ops->ctrl_irq */
enum {
	IRQ_CTRL_ENABLE = 0,
	IRQ_CTRL_DISABLE,
	NR_IRQ_CTRL,
};

struct nf10_hw_ops {
	int		(*init)(struct nf10_adapter *adapter);
	void		(*free)(struct nf10_adapter *adapter);
	int		(*init_buffers)(struct nf10_adapter *adapter);
	void		(*free_buffers)(struct nf10_adapter *adapter);
	int		(*get_napi_budget)(void);
	void		(*process_rx_irq)(struct nf10_adapter *adapter, 
					  int *work_done, int budget);
	netdev_tx_t     (*start_xmit)(struct sk_buff *skb, 
				      struct net_device *dev);
	int		(*clean_tx_irq)(struct nf10_adapter *adapter);
	unsigned long	(*ctrl_irq)(struct nf10_adapter *adapter, unsigned long cmd);
};

struct nf10_user_ops {
	u64		(*init)(struct nf10_adapter *adapter);
	unsigned long	(*get_pfn)(struct nf10_adapter *adapter, unsigned long arg);
	void		(*prepare_rx_buffer)(struct nf10_adapter *adapter,
					     unsigned long size);
	int		(*start_xmit)(struct nf10_adapter *adapter, unsigned long arg);
	unsigned long	(*pkt_gen)(struct nf10_adapter *adapter, unsigned int pkt_len,
				   unsigned long pkt_count, int batch);
};

static inline void nf10_writel(struct nf10_adapter *adapter, int off, u32 val)
{
	writel(val, adapter->bar2 + off);
}

static inline void nf10_writeq(struct nf10_adapter *adapter, int off, u64 val)
{
	writeq(val, adapter->bar2 + off);
}

extern void nf10_set_ethtool_ops(struct net_device *netdev);

#endif
