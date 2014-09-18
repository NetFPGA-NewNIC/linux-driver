/*******************************************************************************
*
*  NetFPGA-10G http://www.netfpga.org
*
*  File:
*        nf10_user.c
*
*  Project:
*
*
*  Author:
*        Hwanju Kim
*
*  Description:
*	 This module provides user-level access interface for AXI registers and
*	 direct access for data path. Note that the current direct access
*	 by user-level app is done by making buffers permanently to be
*	 mapped by the app. So, it is a responsibility of the app to copy
*	 a received buffer to its own user buffer if packet processing takes
*	 time lagging behind the packet arrival rate. The kernel-user interface
*	 is minimalistic for now.
*
*        TODO:
*		- additional interface for TX
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

#include "nf10.h"
#include "nf10_user.h"
#include <linux/sched.h>

/* AXI host completion buffer size: 1st 8B for read and 2nd 8B for write */
#define AXI_COMPLETION_SIZE		16
#define AXI_COMPLETION_READ_ADDR	112
#define AXI_COMPLETION_WRITE_ADDR	176
#define AXI_READ_ADDR			64
#define AXI_WRITE_ADDR			128
#define axi_read_completion(adapter)	(u64 *)(adapter->axi_completion_kern_addr)
#define axi_write_completion(adapter)	(u64 *)(adapter->axi_completion_kern_addr + 0x8)
/* return codes via upper 32bit of completion buffer */
#define AXI_COMPLETION_WAIT		0x0
#define AXI_COMPLETION_OKAY		0x1
#define AXI_COMPLETION_NACK		0x2
#define axi_completion_stat(completion)	(u32)(completion >> 32)
#define axi_completion_data(completion)	(completion & ((1ULL << 32) - 1))

static dev_t devno;
static struct class *dev_class;
static struct mutex axi_mutex;

static int nf10_open(struct inode *n, struct file *f)
{
	struct nf10_adapter *adapter = (struct nf10_adapter *)container_of(
					n->i_cdev, struct nf10_adapter, cdev);
	if (adapter->user_ops == NULL) {
		netif_err(adapter, drv, default_netdev(adapter),
				"no user_ops is set\n");
		return -EINVAL;
	}
	f->private_data = adapter;
	return 0;
}

static int nf10_mmap(struct file *f, struct vm_area_struct *vma)
{
	struct nf10_adapter *adapter = f->private_data;
	unsigned long pfn;
	unsigned long size;
	int err = 0;
	
	if ((vma->vm_start & ~PAGE_MASK) || (vma->vm_end & ~PAGE_MASK)) {
		netif_err(adapter, drv, default_netdev(adapter),
			  "not aligned vaddrs (vm_start=%lx vm_end=%lx)", 
			  vma->vm_start, vma->vm_end);
		return -EINVAL;
	}

	size = vma->vm_end - vma->vm_start;
	/* TODO: some arg/bound checking: 
	 * size must be the same as kernel buffer */

	pfn = adapter->user_ops->get_pfn(adapter, adapter->nr_user_mmap);

	err = remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot);

	netif_dbg(adapter, drv, default_netdev(adapter),
		  "mmapped [%d] err=%d va=%p pfn=%lx size=%lu\n",
		  adapter->nr_user_mmap, err, (void *)vma->vm_start, pfn, size);

	if (!err)
		adapter->nr_user_mmap++;

	return err;
}

static int write_axi(struct nf10_adapter *adapter, u64 addr_val)
{
	volatile u64 *completion = axi_write_completion(adapter);
	u32 ret;

	/* init -> write addr & val -> poll stat -> return stat */
	*completion = 0;
	writeq(addr_val, adapter->bar0 + AXI_WRITE_ADDR);
	while ((ret = axi_completion_stat(*completion)) == AXI_COMPLETION_WAIT);
	netif_dbg(adapter, drv, default_netdev(adapter),
		  "%s: addr=%llx val=%llx ret=%d\n",
		  __func__, addr_val >> 32, addr_val & 0xffffffff, ret);

	return ret;
}

static int read_axi(struct nf10_adapter *adapter, u64 addr, u64 *val)
{
	volatile u64 *completion = axi_read_completion(adapter);
	u32 ret;

	/* init -> write addr -> poll stat -> return val & stat */
	*completion = 0;
	writeq(addr, adapter->bar0 + AXI_READ_ADDR);
	while ((ret = axi_completion_stat(*completion)) == AXI_COMPLETION_WAIT);
	*val = axi_completion_data(*completion);
	netif_dbg(adapter, drv, default_netdev(adapter),
		  "%s: addr=%llx val=%llx ret=%d\n",
		  __func__, addr, *val, ret);

	return ret;
}

static int check_axi(int ret)
{
	BUG_ON(ret == AXI_COMPLETION_WAIT);
	/* let user know returning EFAULT if nacked */
	if (ret == AXI_COMPLETION_NACK) {
		pr_err("Error: AXI write request gets NACK\n");
		return -EFAULT;
	}
	return 0;
}

static long nf10_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct nf10_adapter *adapter = (struct nf10_adapter *)f->private_data;

	switch(cmd) {
	case NF10_IOCTL_CMD_READ_STAT:
		/* nothing to do: this placeholder is for compatability
		 * it was used for debugging purpose of the previous dma */
		break;
	case NF10_IOCTL_CMD_WRITE_REG:
#ifdef CONFIG_OSNT
	case NF10_IOCTL_CMD_WRITE_REG_PY:   /* compat w/ OSNT python apps */
#endif
	{
		u32 ret;
		u64 addr_val = (u64)arg;
#ifdef CONFIG_OSNT
		if (cmd == NF10_IOCTL_CMD_WRITE_REG_PY)
			addr_val = *((u64 *)arg);
#endif
		mutex_lock(&axi_mutex);
		ret = check_axi(write_axi(adapter, addr_val));
		mutex_unlock(&axi_mutex);
		if (ret)
			return ret;	/* error */
		break;
	}
	case NF10_IOCTL_CMD_READ_REG:
	{
		u64 addr, val;
		u32 ret;
		if (copy_from_user(&addr, (u64 *)arg, 8)) {
			pr_err("Error: failed to copy AXI read addr\n");
			return -EFAULT;
		}
		mutex_lock(&axi_mutex);
		ret = check_axi(read_axi(adapter, addr, &val));
		mutex_unlock(&axi_mutex);
		if (ret)
			return ret;	/* error */
		val |= (addr << 32);	/* for compatability with older rdaxi */
		if (copy_to_user((u64 *)arg, &val, 8)) {
			pr_err("Error: failed to copy AXI read val\n");
			return -EFAULT;
		}
		break;
	}
	case NF10_IOCTL_CMD_INIT:
	{
		u64 ret;
		ret = adapter->user_ops->init(adapter);
		if (copy_to_user((void __user *)arg, &ret, sizeof(u64)))
			return -EFAULT;
		break;
	}
	case NF10_IOCTL_CMD_PREPARE_RX:
		adapter->user_ops->prepare_rx_buffer(adapter, arg);
		break;
	case NF10_IOCTL_CMD_WAIT_INTR:
	{
		u64 ret;

		DEFINE_WAIT(wait);
		prepare_to_wait(&adapter->wq_user_intr, &wait,
				TASK_INTERRUPTIBLE);
		io_schedule();
		finish_wait(&adapter->wq_user_intr, &wait);
		ret = adapter->user_private;
		if (copy_to_user((void __user *)arg, &ret, sizeof(u64)))
			return -EFAULT;
		if (signal_pending(current))
			pr_debug("signal wakes up a user process\n");
		break;
	}
	default:
		return -EINVAL;
	}
	return 0;
}

static int nf10_release(struct inode *n, struct file *f)
{
	f->private_data = NULL;
	return 0;
}

static struct file_operations nf10_fops = {
	.owner = THIS_MODULE,
	.open = nf10_open,
	.mmap = nf10_mmap,
	.unlocked_ioctl = nf10_ioctl,
	.release = nf10_release
};

int nf10_init_fops(struct nf10_adapter *adapter)
{
	int err;

	if ((err = alloc_chrdev_region(&devno, 0, 1, NF10_DRV_NAME))) {
		netif_err(adapter, probe, default_netdev(adapter),
				"failed to alloc chrdev\n");
		return err;
	}
	cdev_init(&adapter->cdev, &nf10_fops);
	adapter->cdev.owner = THIS_MODULE;
	adapter->cdev.ops = &nf10_fops;
	if ((err = cdev_add(&adapter->cdev, devno, 1))) {
		netif_err(adapter, probe, default_netdev(adapter),
			  "failed to add cdev\n");
		return err;
	}

	dev_class = class_create(THIS_MODULE, NF10_DRV_NAME);
	device_create(dev_class, NULL, devno, NULL, NF10_DRV_NAME);

	/* alloc completion buffer for AXI register interface */
	adapter->axi_completion_kern_addr = pci_alloc_consistent(adapter->pdev,
			AXI_COMPLETION_SIZE, &adapter->axi_completion_dma_addr);
	if (adapter->axi_completion_kern_addr == NULL) {
		pr_err("Error: failed to alloc axi completion buffer."
		       "       note that axi interface won't work.");
		return -ENOMEM;
	}
	writeq(adapter->axi_completion_dma_addr,
	       adapter->bar0 + AXI_COMPLETION_READ_ADDR);
	writeq(adapter->axi_completion_dma_addr + 0x8,
	       adapter->bar0 + AXI_COMPLETION_WRITE_ADDR);

	pr_debug("%s: alloc axi completion buffer(kern_addr=(R=%p,W=%p), dma_addr=(R=%p,W=%p))\n",
		__func__, adapter->axi_completion_kern_addr, adapter->axi_completion_kern_addr + 0x8,
		(void *)adapter->axi_completion_dma_addr, (void *)(adapter->axi_completion_dma_addr + 0x8));

	mutex_init(&axi_mutex);

	return 0;
}

int nf10_remove_fops(struct nf10_adapter *adapter)
{
	device_destroy(dev_class, devno);
	class_unregister(dev_class);
	class_destroy(dev_class);
	cdev_del(&adapter->cdev);
	unregister_chrdev_region(devno, 1);

	if (adapter->axi_completion_kern_addr != NULL)
		pci_free_consistent(adapter->pdev, AXI_COMPLETION_SIZE,
				adapter->axi_completion_kern_addr,
				adapter->axi_completion_dma_addr);

	mutex_destroy(&axi_mutex);
	return 0;
}

bool nf10_user_rx_callback(struct nf10_adapter *adapter)
{
	/* if direct user access mode is enabled, just wake up
	 * a waiting user thread */
	if (adapter->nr_user_mmap > 0) { 
		if (likely(waitqueue_active(&adapter->wq_user_intr))) {
			wmb();	/* adapter->user_private */
			wake_up(&adapter->wq_user_intr);
		}
		else
			pr_debug("WARN: mmap > 0 (=%u) but no waiting task!\n",
				adapter->nr_user_mmap);
		return true;
	}
	return false;
}
