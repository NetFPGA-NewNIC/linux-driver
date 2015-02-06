/*******************************************************************************
*
*  NetFPGA-10G http://www.netfpga.org
*
*  File:
*        lbufnet.c
*
*  Project:
*
*
*  Author:
*        Hwanju Kim
*
*  Description:
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <sys/time.h>
#include <poll.h>
#include <dirent.h>
#include <sys/stat.h>

#include <lbufnet.h>
#include "nf10_lbuf_api.h"
#include "nf10_user.h"

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

#define DEV_FNAME	"/dev/" NF10_DRV_NAME
#ifdef DEBUG
#define dprintf(format, arg...)	\
	do { printf(NF10_DRV_NAME ": " format, ##arg); } while (0)
#else
#define dprintf(format, arg...)
#endif

#define eprintf(format, arg...)	\
	do { fprintf(stderr, NF10_DRV_NAME ": " format, ##arg); } while (0)

static unsigned long flags;
static int fd;
static struct lbuf_user *ld;	/* lbuf descriptor */
void *tx_completion;
static void *rx_lbuf[NR_SLOT];
static void *tx_lbuf[MAX_TX_USER_LBUF];
static int initialized;
static unsigned int prev_nr_drops;
static union lbuf_header lh;
static unsigned int tx_lbuf_size;
static unsigned int tx_lbuf_count;
static unsigned int tx_prod;
static unsigned int tx_cons;
static uint32_t tx_offset;

#define inc_tx_pointer(pointer)	\
	do { pointer = pointer == tx_lbuf_count - 1 ? 0 : pointer + 1; } while(0)
/* # of used bufs == tx_lbuf_count - 1 means it's full */
#define tx_full()	(((tx_prod >= tx_cons ? 0 : tx_lbuf_count) + tx_prod - tx_cons) == (tx_lbuf_count - 1))
#define tx_empty()	(tx_prod == tx_cons)

static lbufnet_input_cb input_cb;
static lbufnet_exit_cb exit_cb;
struct lbufnet_stat lbufnet_stat;
static void (*xmit_packet)(void);
static void (*prepare_rx_lbuf)(void);

/* direct pci access */
static int pcifd;
static void *pci_base_addr;

static inline uint64_t rdtsc(void)
{       
	unsigned int low, high; 

	asm volatile("rdtsc" : "=a" (low), "=d" (high));

	return low | ((uint64_t)high) << 32;
}

static inline void xmit_packet_ioctl(void)
{
	ioctl(fd, NF10_IOCTL_CMD_XMIT, NF10_IOCTL_ARG_XMIT(tx_prod, tx_offset));
}

static inline void xmit_packet_pci(void)
{
	uint32_t idx = ld->tx_idx;
	LBUF_TX_COMPLETION(tx_completion, idx) = TX_USED;
	inc_idx(ld->tx_idx);
	/* XXX: need __sync_synchronize() here? */
	*((uint64_t *)(pci_base_addr + tx_addr_off(idx))) = ld->tx_dma_addr[tx_prod];
	*((uint32_t *)(pci_base_addr + tx_stat_off(idx))) = tx_offset >> 3;
}

static inline void prepare_rx_lbuf_ioctl(void)
{
	ioctl(fd, NF10_IOCTL_CMD_PREPARE_RX, ld->rx_idx);
}

static inline void prepare_rx_lbuf_pci(void)
{
	uint32_t idx = ld->rx_idx;
	/* XXX: need __sync_synchronize() here? */
	*((uint64_t *)(pci_base_addr + rx_addr_off(idx))) = ld->rx_dma_addr[idx];
	*((uint32_t *)(pci_base_addr + rx_stat_off(idx))) = 0xcacabeef;
}

static char *get_pci_filename(void)
{
	DIR *dp;
	struct dirent *ep;
	struct stat st;
	char path[128];
	char *base_dir = "/sys/bus/pci/drivers/" NF10_DRV_NAME;
	dp = opendir(base_dir);
	if (!dp) {
		perror("opendir");
		return NULL;
	}
	while ((ep = readdir(dp))) {
		snprintf(path, 128, "%s/%s/resource2", base_dir, ep->d_name);
		if (stat(path, &st) == 0)
			return strdup(path);
	}
	return NULL;
}

static inline int addr_in_lbuf(unsigned int idx, uint64_t gc_addr)
{
	return gc_addr > ld->tx_dma_addr[idx] &&
		gc_addr <= ld->tx_dma_addr[idx] + tx_lbuf_size;
}

static void clean_tx(void)
{
	int last = 0;
	uint64_t gc_addr = LBUF_GC_ADDR(tx_completion);
	if (gc_addr == ld->last_gc_addr)
		return;
	do {
		last = addr_in_lbuf(tx_cons, gc_addr);
		dprintf("%s: tx_cons=%d tx_prod=%d by gc_addr %p (last=%d)\n",
		      __func__, tx_cons, tx_prod, (void *)gc_addr, last);
		inc_tx_pointer(tx_cons);
	} while (!last && tx_cons != tx_prod);
	ld->last_gc_addr = gc_addr;
}

int lbufnet_exit(void)
{
	unsigned int i;

	/* waiting for draining all transmitted packets */
	dprintf("tx purging start: empty=%d last_gc=%llx\n", tx_empty(), ld->last_gc_addr);
	while(!tx_empty())
		clean_tx();
	dprintf("tx purging done\n");

	if (exit_cb) {
		lbufnet_stat.nr_drops = lh.nr_drops - prev_nr_drops;
		exit_cb(&lbufnet_stat);
	}

	if (pci_base_addr)
		munmap(pci_base_addr, PAGE_SIZE);
	if (tx_lbuf_size)
		for (i = 0; i < tx_lbuf_count; i++)
			if (tx_lbuf[i])
				munmap(tx_lbuf[i], tx_lbuf_size);
	for (i = 0; i < NR_SLOT; i++)
		if (rx_lbuf[i])
			munmap(rx_lbuf[i], LBUF_RX_SIZE);
	if (tx_completion)
		munmap(tx_completion, PAGE_SIZE);
	if (ld)
		munmap(ld, PAGE_SIZE);

	if (ioctl(fd, NF10_IOCTL_CMD_EXIT)) {
		perror("ioctl init");
		return -1;
	}
	close(fd);

	initialized = 0;
	return 0;
}

static void lbufnet_finish(int sig)
{
	(void)sig;
	dprintf("signal is caught by lbufnet handler\n");
	lbufnet_exit();
	exit(0);
}

int lbufnet_init(struct lbufnet_conf *conf)
{
	unsigned int i;

	/* sanity checks before initialization */
	if (conf->flags == 0) {	/* any flag of tx or rx should be on */
		eprintf("Error: invalid flags=%lx\n", flags);
		return -1;
	}
	flags = conf->flags & UF_ON_MASK;
	if (flags & TX_ON) {
		if (conf->tx_lbuf_count < MIN_TX_USER_LBUF || conf->tx_lbuf_count > MAX_TX_USER_LBUF) {
			eprintf("Error: invalid tx_lbuf_count (must be between %d and %d)\n", MIN_TX_USER_LBUF, MAX_TX_USER_LBUF);
			return -1;
		}
		if (conf->tx_lbuf_size < MIN_TX_USER_LBUF_SIZE || conf->tx_lbuf_size > MAX_TX_USER_LBUF_SIZE) {
			eprintf("Error: invalid tx_lbuf_size (must be between %d and %d)\n", MIN_TX_USER_LBUF_SIZE, MAX_TX_USER_LBUF_SIZE);
			return -1;
		}
	}
	tx_lbuf_count = conf->tx_lbuf_count;
	tx_lbuf_size = conf->tx_lbuf_size;

	/* initialization */
	if ((fd = open(DEV_FNAME, O_RDWR, 0755)) < 0) {
		perror("open");
		return -1;
	}
	if (ioctl(fd, NF10_IOCTL_CMD_INIT, flags)) {
		close(fd);
		perror("ioctl init");
		return -1;
	}
	dprintf("initialized for direct user access for%s%s\n",
		flags & UF_TX_ON ? " TX" : "", flags & UF_RX_ON ? " RX" : "");

	/* 1st mmap is for main metadata */
	ld = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ld == MAP_FAILED) {
		perror("mmap");
		goto err_init;
	}
	dprintf("DMA metadata is mmaped to vaddr=%p\n", ld);
	dprintf("\ttx_idx=%u rx_idx=%u\n", ld->tx_idx, ld->rx_idx);
	dprintf("\trx_cons=%u\n", ld->rx_cons);
	dprintf("\ttx_dma_addr\n");
	for (i = 0; i < tx_lbuf_count; i++)
		dprintf("\t\t[%d]=%p\n", i, (void *)ld->tx_dma_addr[i]);
	dprintf("\trx_dma_addr\n");
	for (i = 0; i < NR_SLOT; i++)
		dprintf("\t\t[%d]=%p\n", i, (void *)ld->rx_dma_addr[i]);
	dprintf("\tlast_gc_addr=0x%llx\n", ld->last_gc_addr);

	/* 2nd mmap is for metadata of tx completion */
	tx_completion = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (tx_completion == MAP_FAILED) {
		perror("mmap");
		goto err_init;
	}
	dprintf("DMA tx completion area is mmaped to vaddr=%p\n", tx_completion);
	for (i = 0; i < NR_SLOT; i++)
		dprintf("\tcompletion[%d]=%x\n", i, LBUF_TX_COMPLETION(tx_completion, i));
	dprintf("\tgc_addr=%p\n", (void *)LBUF_GC_ADDR(tx_completion));
	ld->last_gc_addr = (uint64_t)LBUF_GC_ADDR(tx_completion);
	for (i = 0; i < tx_lbuf_count; i++) {
		if (addr_in_lbuf(i, ld->last_gc_addr)) {
			tx_prod = tx_cons = (i == tx_lbuf_count - 1) ? 0 : i + 1; 
			break;
		}
	}
	dprintf("\ttx_prod=%u tx_cons=%u\n", tx_prod, tx_cons);

	/* 3rd mmap is for RX buffers reserved and used by kernel */
	for (i = 0; i < NR_SLOT; i++) {
		rx_lbuf[i] = mmap(NULL, LBUF_RX_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (rx_lbuf[i] == MAP_FAILED) {
			perror("mmap");
			goto err_init;
		}
		dprintf("RX lbuf[%d] is mmaped to vaddr=%p w/ size=%lu\n",
		      i, rx_lbuf[i], LBUF_RX_SIZE);
	}
	LBUF_RX_GET_HEADER(rx_lbuf[ld->rx_idx], lh);
	prev_nr_drops = lh.nr_drops;

	/* 4th mmap is for TX buffers exclusively used by user (but allocated by kernel) */
	if (tx_lbuf_size) {
		for (i = 0; i < tx_lbuf_count; i++) {
			tx_lbuf[i] = mmap(NULL, tx_lbuf_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
			if (tx_lbuf[i] == MAP_FAILED) {
				perror("mmap");
				goto err_init;
			}
			dprintf("TX lbuf[%d] is mmaped to vaddr=%p w/ size=%u (dma_addr=%p)\n",
					i, tx_lbuf[i], tx_lbuf_size, (void *)ld->tx_dma_addr[i]);
		}
	}
	/* set xmit_packet handler based on pci_direct_access config */
	if (conf->pci_direct_access) {
		char *fn = get_pci_filename();
		if (!fn) {
			eprintf("failed to get pci file name from sysfs\n");
			goto err_init;
		}
		if ((pcifd = open(fn, O_RDWR, 0755)) < 0) {
			free(fn);
			perror("open");
			goto err_init;
		}
		free(fn);
		pci_base_addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, pcifd, 0);
		if (pci_base_addr == MAP_FAILED) {
			perror("mmap");
			goto err_init;
		}
		xmit_packet = xmit_packet_pci;
		prepare_rx_lbuf = prepare_rx_lbuf_pci;
		dprintf("pci bar2 is mapped to vaddr=%p w/ size=%u\n", pci_base_addr, PAGE_SIZE);
	}
	else {
		xmit_packet = xmit_packet_ioctl;
		prepare_rx_lbuf = prepare_rx_lbuf_ioctl;
	}

	initialized = 1;

	signal(SIGINT, lbufnet_finish);	/* XXX: needed? or adding more signals */

	return 0;

err_init:
	lbufnet_exit();
	return -1;
}

int lbufnet_register_input_callback(lbufnet_input_cb cb)
{
	input_cb = cb;
	return 0;
}

int lbufnet_register_exit_callback(lbufnet_exit_cb cb)
{
	exit_cb = cb;
	return 0;
}

static inline void move_to_next_lbuf(void *buf_addr)
{
	LBUF_RX_INIT_HEADER(buf_addr);
	prepare_rx_lbuf();
	inc_idx(ld->rx_idx);
	ld->rx_cons = LBUF_RX_RESERVED_DWORDS;
}

static inline void deliver_packet(struct lbufnet_rx_packet *pkt, uint64_t *rx_packets)
{
	*rx_packets += input_cb(pkt);
	memset(pkt->data - LBUF_TX_METADATA_SIZE, 0, ALIGN(pkt->len, 8) + LBUF_TX_METADATA_SIZE);
}

int lbufnet_input(unsigned long nr_packets, int sync_flags)
{
	void *buf_addr;
	unsigned int dword_idx, next_dword_idx;
	uint32_t next_pkt_len;
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	int n;
	unsigned long rx_packets = 0;
	struct lbufnet_rx_packet pkt;

	/* rx sanity check */
	if (unlikely(!initialized)) {
		eprintf("Error: lbuf is not initialized\n");
		return -1;
	}
	if (unlikely(!input_cb)) {
		eprintf("Error: input callback is not initialized\n");
		return -1;
	}
	if (unlikely(!(flags & RX_ON))) {
		eprintf("Error: RX is not turned on\n");
		return -1;
	}
	if (unlikely(sync_flags != SF_BLOCK && sync_flags != SF_NON_BLOCK && sync_flags != SF_BUSY_BLOCK)) {
		eprintf("Error: undefined sync flags\n");
		return -1;
	}
wait_rx:
	if (sync_flags == SF_BLOCK) {
		do {
			n = poll(&pfd, 1, -1);
			dprintf("Waiting for RX packets (n=%d, revents=%x)\n", n, pfd.revents);
		} while (n <= 0 || pfd.revents & POLLERR || !(pfd.revents & POLLIN));
	}
	dprintf("Start receiving packets (rx_packets=%lu)\n", rx_packets);
	do {
		dword_idx = ld->rx_cons;
		buf_addr = rx_lbuf[ld->rx_idx];
		pkt.len = LBUF_RX_PKT_LEN(buf_addr, dword_idx);
		pkt.port_num = LBUF_PKT_PORT_NUM(buf_addr, dword_idx);

		if (unlikely(pkt.len == 0)) {
			/* if this lbuf is closed, move to next lbuf */
			LBUF_RX_GET_HEADER(buf_addr, lh);
			if (LBUF_RX_CLOSED(dword_idx, lh)) {
				move_to_next_lbuf(buf_addr);
				continue;
			}
			if (sync_flags == SF_NON_BLOCK)
				return 0;
			goto wait_rx;
		}
		if (unlikely(!LBUF_IS_PKT_VALID(pkt.port_num, pkt.len))) {
			eprintf("Error: rx_idx=%d lbuf contains invalid pkt len=%u\n",
				ld->rx_idx, pkt.len);
			break;
		}
		next_dword_idx = LBUF_RX_NEXT_DWORD_IDX(dword_idx, pkt.len);
		pkt.data = LBUF_RX_PKT_ADDR(buf_addr, dword_idx);
wait_to_end_recv:
		next_pkt_len = LBUF_RX_PKT_LEN(buf_addr, next_dword_idx);
		if (next_pkt_len > 0) {
			/* timestamp is written after packet length, so this is the safe point
			 * to fetch valid timestamp when ensuring the current packet is received. */
			pkt.timestamp = LBUF_RX_TIMESTAMP(buf_addr, dword_idx);
			deliver_packet(&pkt, &rx_packets);
			ld->rx_cons = next_dword_idx;
		}
		else {
			LBUF_RX_GET_HEADER(buf_addr, lh);
			if ((lh.nr_qwords << 1) < next_dword_idx - LBUF_RX_RESERVED_DWORDS) {
				lbufnet_stat.nr_polls++;
				goto wait_to_end_recv;
			}
			pkt.timestamp = LBUF_RX_TIMESTAMP(buf_addr, dword_idx);
			deliver_packet(&pkt, &rx_packets);
			if (unlikely(LBUF_RX_CLOSED(next_dword_idx, lh))) {
				move_to_next_lbuf(buf_addr);
				continue;
			}
			next_pkt_len = LBUF_RX_PKT_LEN(buf_addr, next_dword_idx);
			if (next_pkt_len == 0)
				next_dword_idx = LBUF_RX_128B_ALIGN(next_dword_idx);
			ld->rx_cons = next_dword_idx;
		}
		if (unlikely(ld->rx_cons >= (LBUF_RX_SIZE >> 2)))
			move_to_next_lbuf(buf_addr);
	} while (nr_packets == LBUFNET_INPUT_FOREVER || rx_packets < nr_packets);

	return rx_packets;
}

static inline int tx_sanity_check(void)
{
	if (unlikely(!initialized)) {
		eprintf("Error: lbuf is not initialized\n");
		return 0;
	}
	if (unlikely(!(flags & TX_ON))) {
		eprintf("Error: TX is not turned on\n");
		return 0;
	}
	if (unlikely(tx_lbuf_size == 0)) {
		eprintf("Error: tx lbuf is not initialized\n");
		return 0;
	}
	return 1;
}

int lbufnet_flush(int sync_flags)
{
	int out_bytes;
	struct pollfd pfd = { .fd = fd, .events = POLLOUT };
	int n;

	if (!tx_sanity_check())
		return -1;

	/* no data to be flushed */
	if (unlikely(tx_offset == 0))
		return 0;

	while (LBUF_TX_COMPLETION(tx_completion, ld->tx_idx) != TX_AVAIL) {
		if (sync_flags == SF_NON_BLOCK)
			return 0;
		if (sync_flags == SF_BUSY_BLOCK) {
			clean_tx();
			continue;
		}
		if (unlikely(sync_flags != SF_BLOCK))
			return -1;
		do {
			n = poll(&pfd, 1, -1);
		} while (n <= 0 || pfd.revents & POLLERR);
		clean_tx();
	}

	xmit_packet();

	dprintf("%s: tx_prod=%d tx_cons=%d tx_offset=%u\n", __func__, tx_prod, tx_cons, tx_offset);
	inc_tx_pointer(tx_prod);
	out_bytes = tx_offset;
	tx_offset = 0;

	return out_bytes;
}

int lbufnet_write(struct lbufnet_tx_packet *pkt)
{
	void *data = pkt->data;
	unsigned int len = pkt->len;
	int port_num = pkt->port_num;
	int sync_flags = pkt->sync_flags;
	void *buf_addr;
	struct pollfd pfd = { .fd = fd, .events = POLLOUT };
	int n;

	if (!tx_sanity_check())
		return -1;
avail_check:
	clean_tx();
	while (tx_full()) {
		dprintf("%s: tx_full=%d prod=%u cons=%u\n", __func__, tx_full(), tx_prod, tx_cons);
		clean_tx();
		if (tx_full()) {
			if (sync_flags == SF_NON_BLOCK)
				return 0;
			if (sync_flags == SF_BUSY_BLOCK)
				continue;
			if (sync_flags != SF_BLOCK)
				return -1;
			do {
				n = poll(&pfd, 1, -1);
			} while (n <= 0 || pfd.revents & POLLERR);
		}
	}
	if (unlikely(!LBUF_TX_HAS_ROOM(tx_lbuf_size, tx_offset, len))) {
		lbufnet_flush(sync_flags);
		goto avail_check;
	}
	/* now tx lbuf avaialable */
	buf_addr = tx_lbuf[tx_prod] + tx_offset;
	buf_addr = LBUF_TX_CUR_ADDR(buf_addr, port_num, len);
	memcpy(buf_addr, data, len);
	tx_offset = LBUF_TX_NEXT_ADDR(buf_addr, len) - tx_lbuf[tx_prod];

	return tx_offset;
}

int lbufnet_output(struct lbufnet_tx_packet *pkt)
{
	int ret;
	if ((ret = lbufnet_write(pkt)) > 0)
		return lbufnet_flush(pkt->sync_flags);
	return ret;
}
