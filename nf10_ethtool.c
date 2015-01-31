/*******************************************************************************
*
*  NetFPGA-10G http://www.netfpga.org
*
*  File:
*        nf10_ethtool.c
*
*  Project:
*
*
*  Author:
*        Hwanju Kim
*
*  Description:
*	 This module provides the implementation of ethtool.
*	 It began providing only get/set_msglevel for debugging purpose, and
*	 a coalescing feature with rx-usecs.
*	 It will be extended as needed for additional ethtool features.
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

#include "nf10.h"

static u32 nf10_get_msglevel(struct net_device *netdev)
{
	struct nf10_adapter *adapter = netdev_adapter(netdev);
	return adapter->msg_enable;
}

static void nf10_set_msglevel(struct net_device *netdev, u32 data)
{
	struct nf10_adapter *adapter = netdev_adapter(netdev);
	adapter->msg_enable = data;
}

static int nf10_get_coalesce(struct net_device *netdev,
			     struct ethtool_coalesce *ec)
{
	struct nf10_adapter *adapter = netdev_adapter(netdev);
	ec->rx_coalesce_usecs = adapter->irq_period_usecs;

	return 0;
}

static int nf10_set_coalesce(struct net_device *netdev,
			     struct ethtool_coalesce *ec)
{
	struct nf10_adapter *adapter = netdev_adapter(netdev);
	if (!adapter->hw_ops || !adapter->hw_ops->set_irq_period)
		return -EOPNOTSUPP;
	adapter->irq_period_usecs = ec->rx_coalesce_usecs;

	return adapter->hw_ops->set_irq_period(adapter);
}

static const struct ethtool_ops nf10_ethtool_ops = {
	.get_msglevel           = nf10_get_msglevel,
	.set_msglevel           = nf10_set_msglevel,
	.get_coalesce		= nf10_get_coalesce,
	.set_coalesce		= nf10_set_coalesce,
};

void nf10_set_ethtool_ops(struct net_device *netdev)
{
	SET_ETHTOOL_OPS(netdev, &nf10_ethtool_ops);
}
