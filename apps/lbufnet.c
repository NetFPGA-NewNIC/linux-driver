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

#include "nf10_lbuf_api.h"
#include "nf10_user.h"
#include "lbufnet.h"

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

#define DEV_FNAME	"/dev/" NF10_DRV_NAME
#ifdef DEBUG
#define dprintf(format, arg...)	\
	do { printf(NF10_DRV_NAME ": " format, ##arg); } while(0)
#else
#define dprintf
#endif

#define eprintf(format, arg...)	\
	do { fprintf(stderr, NF10_DRV_NAME ": " format, ##arg); } while(0)

static int fd;
static struct lbuf_user *ld;	/* lbuf descriptor */
void *tx_completion;
static void *rx_lbuf[NR_SLOT];
static void *tx_lbuf[NR_TX_USER_LBUF];
static int initialized;
static unsigned int prev_nr_drops;
static union lbuf_header lh;
static unsigned int tx_lbuf_size;
static int ref_prod;
static int ref_cons;
static uint32_t tx_offset;
static uint8_t tx_avail[NR_TX_USER_LBUF];
static lbufnet_input_cb input_cb;
static lbufnet_exit_cb exit_cb;
struct lbufnet_stat stat;
/* direct pci access */
static int pcifd;
static void *pci_base_addr;
static void (*xmit_packet)(void);

static inline uint64_t rdtsc(void)
{       
	unsigned int low, high; 

	asm volatile("rdtsc" : "=a" (low), "=d" (high));

	return low | ((uint64_t)high) << 32;
}

static inline void xmit_packet_ioctl(void)
{
	ioctl(fd, NF10_IOCTL_CMD_XMIT, NF10_IOCTL_ARG_XMIT(ref_prod, tx_offset));
}

static inline void xmit_packet_pci(void)
{
	uint32_t idx = ld->tx_idx;
	LBUF_TX_COMPLETION(tx_completion, idx) = TX_USED;
	inc_idx(ld->tx_idx);
	/* XXX: need __sync_synchronize() here? */
	*((uint64_t *)(pci_base_addr + 0x80 + (idx << 3))) = ld->tx_dma_addr[ref_prod];
	*((uint32_t *)(pci_base_addr + 0xA0 + (idx << 2))) = tx_offset >> 3;
}

int lbufnet_exit(void);
static void lbufnet_finish(int sig)
{
	if (exit_cb) {
		stat.nr_drops = lh.nr_drops - prev_nr_drops;
		exit_cb(&stat);
	}
	lbufnet_exit();
	exit(0);
}

int lbufnet_init(struct lbufnet_conf *conf)
{
	int i;

	if ((fd = open(DEV_FNAME, O_RDWR, 0755)) < 0) {
		perror("open");
		return -1;
	}
	if (ioctl(fd, NF10_IOCTL_CMD_INIT)) {
		perror("ioctl init");
		return -1;
	}
	dprintf("initialized for direct user access\n");

	ld = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ld == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	dprintf("DMA metadata is mmaped to vaddr=%p\n", ld);
	dprintf("\ttx_idx=%u rx_idx=%u\n", ld->tx_idx, ld->rx_idx);
	dprintf("\trx_cons=%u\n", ld->rx_cons);
	dprintf("\ttx_dma_addr\n");
	for (i = 0; i < NR_TX_USER_LBUF; i++)
		dprintf("\t\t[%d]=%p\n", i, (void *)ld->tx_dma_addr[i]);
	dprintf("\tlast_gc_addr=0x%llx\n", ld->last_gc_addr);

	tx_completion = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (tx_completion == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	dprintf("DMA tx completion area is mmaped to vaddr=%p\n", tx_completion);
	for (i = 0; i < NR_SLOT; i++)
		dprintf("\tcompletion[%d]=%x\n", i, LBUF_TX_COMPLETION(tx_completion, i));
	dprintf("\tgc_addr=%p\n", (void *)LBUF_GC_ADDR(tx_completion));

	for (i = 0; i < NR_SLOT; i++) {
		rx_lbuf[i] = mmap(NULL, LBUF_RX_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (rx_lbuf[i] == MAP_FAILED) {
			perror("mmap");
			return -1;
		}
		dprintf("RX lbuf[%d] is mmaped to vaddr=%p w/ size=%lu\n",
		      i, rx_lbuf[i], LBUF_RX_SIZE);
	}
	LBUF_GET_HEADER(rx_lbuf[ld->rx_idx], lh);
	prev_nr_drops = lh.nr_drops;

	if (conf->tx_lbuf_size) {
		for (i = 0; i < NR_TX_USER_LBUF; i++) {
			tx_lbuf[i] = mmap(NULL, conf->tx_lbuf_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
			if (tx_lbuf[i] == MAP_FAILED) {
				perror("mmap");
				return -1;
			}
			tx_avail[i] = 1;
			dprintf("TX lbuf[%d] is mmaped to vaddr=%p w/ size=%u (dma_addr=%p)\n",
					i, tx_lbuf[i], conf->tx_lbuf_size, (void *)ld->tx_dma_addr[i]);
		}
	}
	tx_lbuf_size = conf->tx_lbuf_size;

	if (conf->pci_direct_access) {
		if ((pcifd = open("/sys/bus/pci/drivers/nf10/0000:01:00.0/resource2", O_RDWR, 0755)) < 0) {
			perror("open");
			return -1;
		}
		pci_base_addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, pcifd, 0);
		if (pci_base_addr == MAP_FAILED) {
			perror("mmap");
			return -1;
		}
		xmit_packet = xmit_packet_pci;
		dprintf("pci bar2 is mapped to vaddr=%p w/ size=%u\n", pci_base_addr, PAGE_SIZE);
	}
	else
		xmit_packet = xmit_packet_ioctl;

	initialized = 1;

	signal(SIGINT, lbufnet_finish);	/* XXX: needed? or adding more signals */
}

int lbufnet_exit(void)
{
	if (!initialized)
		return -1;

	if (ioctl(fd, NF10_IOCTL_CMD_EXIT)) {
		perror("ioctl init");
		return -1;
	}
	return 0;
}

int lbufnet_register_input_callback(lbufnet_input_cb cb)
{
	input_cb = cb;
}

int lbufnet_register_exit_callback(lbufnet_exit_cb cb)
{
	exit_cb = cb;
}

static inline void move_to_next_lbuf(void *buf_addr)
{
	LBUF_INIT_HEADER(buf_addr);
	ioctl(fd, NF10_IOCTL_CMD_PREPARE_RX, ld->rx_idx);
	inc_idx(ld->rx_idx);
	ld->rx_cons = NR_RESERVED_DWORDS;
}

static inline void deliver_packet(void *pkt_addr, uint32_t pkt_len, uint64_t *rx_packets)
{
	*rx_packets += input_cb(pkt_addr, pkt_len);
	memset(pkt_addr - LBUF_TX_METADATA_SIZE, 0, ALIGN(pkt_len, 8) + LBUF_TX_METADATA_SIZE);
}

static void clean_tx(void)
{
	int last = 0;
	uint64_t gc_addr = LBUF_GC_ADDR(tx_completion);
	if (gc_addr == ld->last_gc_addr)
		return;
	do {
		last = gc_addr > ld->tx_dma_addr[ref_cons] &&
		       gc_addr <= ld->tx_dma_addr[ref_cons] + tx_lbuf_size;
		tx_avail[ref_cons] = 1;
		dprintf("%s: ref_cons=%d ref_prod=%d by gc_addr %p (last=%d)\n",
		      __func__, ref_cons, ref_prod, (void *)gc_addr, last);
		inc_txbuf_ref(ref_cons);
	} while(!last && ref_cons != ref_prod);
	ld->last_gc_addr = gc_addr;
}

/* TODO: multi-port support */
int lbufnet_input(unsigned long nr_packets, int sync_flags)
{
	void *buf_addr;
	unsigned int dword_idx, next_dword_idx;
	int port_num;
	uint32_t pkt_len, next_pkt_len;
	void *pkt_addr;
	struct pollfd pfd = { .fd = fd, .events = POLLIN | POLLOUT };
	int n;
	unsigned long rx_packets = 0;

	if (unlikely(!initialized)) {
		eprintf("Error: lbuf is not initialized\n");
		return -1;
	}
	if (unlikely(!input_cb)) {
		eprintf("Error: input callback is not initialized\n");
		return -1;
	}
	if (unlikely(sync_flags != SF_BLOCK && sync_flags != SF_NON_BLOCK && sync_flags != SF_BUSY_BLOCK)) {
		eprintf("Error: undefined sync flags\n");
		return -1;
	}
wait_rx:
	if (sync_flags == SF_BLOCK) {
		do {
			n = poll(&pfd, 1, 1000);
			dprintf("Waiting for RX packets (n=%d, revents=%x)\n", n, pfd.revents);
			if (pfd.revents & POLLOUT)
				clean_tx();
		} while (n <= 0 || pfd.revents & POLLERR || !(pfd.revents & POLLIN));
	}
	dprintf("Start receiving packets...\n");
	do {
		dword_idx = ld->rx_cons;
		buf_addr = rx_lbuf[ld->rx_idx];
		port_num = LBUF_PKT_PORT_NUM(buf_addr, dword_idx);
		pkt_len = LBUF_PKT_LEN(buf_addr, dword_idx);

		if (unlikely(pkt_len == 0)) {
			/* if this lbuf is closed, move to next lbuf */
			LBUF_GET_HEADER(buf_addr, lh);
			if (LBUF_CLOSED(dword_idx, lh)) {
				move_to_next_lbuf(buf_addr);
				continue;
			}
			if (sync_flags == SF_NON_BLOCK)
				return 0;
			goto wait_rx;
		}
		if (unlikely(!LBUF_IS_PKT_VALID(port_num, pkt_len))) {
			fprintf(stderr, "Error: rx_idx=%d lbuf contains invalid pkt len=%u\n",
				ld->rx_idx, pkt_len);
			break;
		}
		next_dword_idx = LBUF_NEXT_DWORD_IDX(dword_idx, pkt_len);
		pkt_addr = LBUF_PKT_ADDR(buf_addr, dword_idx);
wait_to_end_recv:
		next_pkt_len = LBUF_PKT_LEN(buf_addr, next_dword_idx);
		if (next_pkt_len > 0) {
			deliver_packet(pkt_addr, pkt_len, &rx_packets);
			ld->rx_cons = next_dword_idx;
		}
		else {
			LBUF_GET_HEADER(buf_addr, lh);
			if ((lh.nr_qwords << 1) < next_dword_idx - NR_RESERVED_DWORDS) {
				stat.nr_polls++;
				goto wait_to_end_recv;
			}
			deliver_packet(pkt_addr, pkt_len, &rx_packets);
			if (unlikely(LBUF_CLOSED(next_dword_idx, lh))) {
				move_to_next_lbuf(buf_addr);
				continue;
			}
			next_pkt_len = LBUF_PKT_LEN(buf_addr, next_dword_idx);
			if (next_pkt_len == 0)
				next_dword_idx = LBUF_128B_ALIGN(next_dword_idx);
			ld->rx_cons = next_dword_idx;
		}
		if (unlikely(ld->rx_cons >= (LBUF_RX_SIZE >> 2)))
			move_to_next_lbuf(buf_addr);
	} while(nr_packets == LBUFNET_INPUT_FOREVER || rx_packets < nr_packets);

	return rx_packets;
}

int lbufnet_flush(int sync_flags)
{
	int out_bytes;
	struct pollfd pfd = { .fd = fd, .events = POLLOUT };
	int n;

	if (unlikely(!initialized)) {
		eprintf("Error: lbuf is not initialized\n");
		return -1;
	}
	if (unlikely(tx_lbuf_size == 0)) {
		eprintf("Error: tx lbuf is not initialized\n");
		return -1;
	}
	if (unlikely(tx_offset == 0))
		return -1;

	while(LBUF_TX_COMPLETION(tx_completion, ld->tx_idx) != TX_AVAIL) {
		if (sync_flags == SF_NON_BLOCK)
			return 0;
		if (sync_flags == SF_BUSY_BLOCK) {
			clean_tx();
			continue;
		}
		if (unlikely(sync_flags != SF_BLOCK))
			return -1;
		do {
			n = poll(&pfd, 1, 1000);
		} while (n <= 0 || pfd.revents & POLLERR);
		clean_tx();
	}
	tx_avail[ref_prod] = 0;

	xmit_packet();

	dprintf("%s: ref_prod=%d ref_cons=%d tx_offset=%u\n", __func__, ref_prod, ref_cons, tx_offset);
	inc_txbuf_ref(ref_prod);
	out_bytes = tx_offset;
	tx_offset = 0;

	return out_bytes;
}

int lbufnet_write(void *data, unsigned int len, int sync_flags)
{
	void *buf_addr;
	struct pollfd pfd = { .fd = fd, .events = POLLOUT };
	int n;

	if (unlikely(!initialized)) {
		eprintf("Error: lbuf is not initialized\n");
		return -1;
	}
	if (unlikely(tx_lbuf_size == 0)) {
		eprintf("Error: tx lbuf is not initialized\n");
		return -1;
	}
avail_check:
	clean_tx();
	while(!tx_avail[ref_prod]) {
		if (!tx_avail[ref_prod]) {
			if (sync_flags == SF_NON_BLOCK)
				return 0;
			if (sync_flags == SF_BUSY_BLOCK)
				continue;
			if (sync_flags != SF_BLOCK)
				return -1;
			do {
				n = poll(&pfd, 1, 1000);
			} while (n <= 0 || pfd.revents & POLLERR);
		}
		clean_tx();
	}
	if (unlikely(!LBUF_HAS_TX_ROOM(tx_lbuf_size, tx_offset, len))) {
		lbufnet_flush(sync_flags);
		goto avail_check;
	}
	/* now tx lbuf avaialable */
	buf_addr = tx_lbuf[ref_prod] + tx_offset;
	buf_addr = LBUF_CUR_TX_ADDR(buf_addr, 0, len);
	memcpy(buf_addr, data, len);
	tx_offset = LBUF_NEXT_TX_ADDR(buf_addr, len) - tx_lbuf[ref_prod];

	return tx_offset;
}

int lbufnet_output(void *data, unsigned len, int sync_flags)
{
	int ret;
	if ((ret = lbufnet_write(data, len, sync_flags)) > 0)
		return lbufnet_flush(sync_flags);
	return ret;
}
