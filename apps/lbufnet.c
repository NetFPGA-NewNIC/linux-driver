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

#define DEV_FNAME	"/dev/" NF10_DRV_NAME
#define debug(format, arg...)	\
	do { printf(NF10_DRV_NAME ": " format, ##arg); } while(0)

static int fd;
static struct lbuf_user *ld;	/* lbuf descriptor */
void *tx_completion;
static void *rx_lbuf[NR_SLOT];
static void *tx_lbuf[NR_TX_USER_LBUF];
static int initialized;
static int prev_nr_drops;
static union lbuf_header lh;
static unsigned int tx_lbuf_size;
static int ref_prod;
static int ref_cons;
static uint32_t tx_offset;
static uint8_t tx_avail[NR_TX_USER_LBUF];

unsigned long total_rx_packets, total_rx_bytes;

int lbufnet_exit(void);
static void lbufnet_finish(int sig)
{
	printf("\nReceived packets = %lu (total=%luB avg=%luB)\n",
		total_rx_packets, total_rx_bytes, total_rx_packets ? total_rx_bytes / total_rx_packets : 0);
	printf("Dropped packets=%u\n", lh.nr_drops - prev_nr_drops);

	lbufnet_exit();

	exit(0);
}

int lbufnet_init(unsigned int _tx_lbuf_size)
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
	debug("initialized for direct user access\n");

	ld = mmap(NULL, 1 << PAGE_SHIFT, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ld == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	debug("DMA metadata is mmaped to vaddr=%p\n", ld);
	debug("\ttx_idx=%u rx_idx=%u\n", ld->tx_idx, ld->rx_idx);
	debug("\trx_cons=%u\n", ld->rx_cons);
	debug("\ttx_dma_addr\n");
	for (i = 0; i < NR_TX_USER_LBUF; i++)
		debug("\t\t[%d]=%p\n", i, (void *)ld->tx_dma_addr[i]);
	debug("\ttx_writeback=0x%llx rx_writeback=0x%llx\n", ld->tx_writeback, ld->rx_writeback);

	tx_completion = mmap(NULL, 1 << PAGE_SHIFT, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (tx_completion == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	debug("DMA tx completion area is mmaped to vaddr=%p\n", tx_completion);
	for (i = 0; i < NR_SLOT; i++)
		debug("\tcompletion[%d]=%x\n", i, LBUF_TX_COMPLETION(tx_completion, i));
	debug("\tgc_addr=%p\n", (void *)LBUF_GC_ADDR(tx_completion));

	for (i = 0; i < NR_SLOT; i++) {
		rx_lbuf[i] = mmap(NULL, LBUF_RX_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (rx_lbuf[i] == MAP_FAILED) {
			perror("mmap");
			return -1;
		}
		debug("RX lbuf[%d] is mmaped to vaddr=%p w/ size=%lu\n",
		      i, rx_lbuf[i], LBUF_RX_SIZE);
	}
	LBUF_GET_HEADER(rx_lbuf[ld->rx_idx], lh);
	prev_nr_drops = lh.nr_drops;

	for (i = 0; i < NR_TX_USER_LBUF; i++) {
		tx_lbuf[i] = mmap(NULL, _tx_lbuf_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (tx_lbuf[i] == MAP_FAILED) {
			perror("mmap");
			return -1;
		}
		tx_avail[i] = 1;
		debug("TX lbuf[%d] is mmaped to vaddr=%p w/ size=%u (dma_addr=%p)\n",
		      i, tx_lbuf[i], _tx_lbuf_size, (void *)ld->tx_dma_addr[i]);
	}

	tx_lbuf_size = _tx_lbuf_size;
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

#define move_to_next_lbuf()	\
do {	\
	LBUF_INIT_HEADER(buf_addr);	\
	ioctl(fd, NF10_IOCTL_CMD_PREPARE_RX, ld->rx_idx);	\
	inc_idx(ld->rx_idx);	\
	ld->rx_cons = NR_RESERVED_DWORDS;	\
} while(0)

#define lbuf_input()	\
do {	\
	memset(pkt_addr - 8, 0, ALIGN(pkt_len, 8) + 8);	\
	total_rx_bytes += pkt_len;	\
	total_rx_packets++;	\
} while(0)

/* TODO: multi-port support */
void lbufnet_input(void)
{
	void *buf_addr;
	unsigned int dword_idx, next_dword_idx;
	int port_num;
	uint32_t pkt_len, next_pkt_len;
	void *pkt_addr;
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	int n;
	unsigned long poll_cnt;

	if (!initialized) {
		debug("Error: lbuf is not initialized\n");
		return;
	}
wait_rx:
	do {
		n = poll(&pfd, 1, 1000);
		debug("Waiting for RX packets (n=%d, revents=%x)\n", n, pfd.revents);
	} while(n <= 0 || pfd.revents & POLLERR);

	debug("Start receiving packets...\n");
	do {
		poll_cnt = 0;
		dword_idx = ld->rx_cons;
		buf_addr = rx_lbuf[ld->rx_idx];
wait_to_start_recv:
		port_num = LBUF_PKT_PORT_NUM(buf_addr, dword_idx);
		pkt_len = LBUF_PKT_LEN(buf_addr, dword_idx);

		if (pkt_len == 0) {
			/* if this lbuf is closed, move to next lbuf */
			LBUF_GET_HEADER(buf_addr, lh);
			if (LBUF_CLOSED(dword_idx, lh)) {
				move_to_next_lbuf();
				continue;
			}
			goto wait_rx;
		}
		if (!LBUF_IS_PKT_VALID(port_num, pkt_len)) {
			fprintf(stderr, "Error: rx_idx=%d lbuf contains invalid pkt len=%u\n",
				ld->rx_idx, pkt_len);
			break;
		}
		next_dword_idx = LBUF_NEXT_DWORD_IDX(dword_idx, pkt_len);
		pkt_addr = LBUF_PKT_ADDR(buf_addr, dword_idx);
wait_to_end_recv:
		next_pkt_len = LBUF_PKT_LEN(buf_addr, next_dword_idx);
		if (next_pkt_len > 0) {
			lbuf_input();
			ld->rx_cons = next_dword_idx;
		}
		else {
			LBUF_GET_HEADER(buf_addr, lh);
			if ((lh.nr_qwords << 1) < next_dword_idx - NR_RESERVED_DWORDS)
				goto wait_to_end_recv;
			lbuf_input();
			if (LBUF_CLOSED(next_dword_idx, lh)) {
				move_to_next_lbuf();
				continue;
			}
			next_pkt_len = LBUF_PKT_LEN(buf_addr, next_dword_idx);
			if (next_pkt_len == 0)
				next_dword_idx = LBUF_128B_ALIGN(next_dword_idx);
			ld->rx_cons = next_dword_idx;
		}
		if (ld->rx_cons >= (LBUF_RX_SIZE >> 2))
			move_to_next_lbuf();
	} while(1);
}

int lbufnet_output(int sync_flags)
{
	int out_bytes;
	struct pollfd pfd = { .fd = fd, .events = POLLOUT };
	int n;

	if (!initialized) {
		debug("Error: lbuf is not initialized\n");
		return -1;
	}
	if (tx_offset == 0)
		return -1;
	while(LBUF_TX_COMPLETION(tx_completion, ld->tx_idx) != TX_AVAIL) {
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
	tx_avail[ref_prod] = 0;
	ioctl(fd, NF10_IOCTL_CMD_XMIT, NF10_IOCTL_ARG_XMIT(ref_prod, tx_offset));
	inc_txbuf_ref(ref_prod);
	out_bytes = tx_offset;
	tx_offset = 0;

	return out_bytes;
}

static void clean_tx(void)
{
	int last = 0;
	uint64_t gc_addr = LBUF_GC_ADDR(tx_completion);
	debug("%s: gc addr=%p tx_writeback=%p\n",
	      __func__, (void *)gc_addr, (void *)ld->tx_writeback);
	if (gc_addr == ld->tx_writeback)
		return;
	do {
		last = gc_addr > ld->tx_dma_addr[ref_cons] &&
		       gc_addr <= ld->tx_dma_addr[ref_cons] + tx_lbuf_size;
		tx_avail[ref_cons] = 1;
		debug("%s: clean ref_cons=%d ref_prod=%d by gc_addr %p (last=%d)\n",
		      __func__, ref_cons, ref_prod, (void *)gc_addr, last);
		inc_txbuf_ref(ref_cons);
	} while(!last && ref_cons != ref_prod);
	ld->tx_writeback = gc_addr;
}

unsigned int lbufnet_write(void *data, unsigned int len, int sync_flags)
{
	void *buf_addr;
	struct pollfd pfd = { .fd = fd, .events = POLLOUT };
	int n;

	if (!initialized) {
		debug("Error: lbuf is not initialized\n");
		return -1;
	}
avail_check:
	while(!tx_avail[ref_prod]) {
		clean_tx();
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
	}
	if (!LBUF_HAS_TX_ROOM(tx_lbuf_size, tx_offset, len)) {
		lbufnet_output(sync_flags);
		goto avail_check;
	}
	//debug("ref=%d off=%u len=%u\n", ref_prod, tx_offset, len);
	/* now tx lbuf avaialable */
	buf_addr = tx_lbuf[ref_prod] + tx_offset;
	buf_addr = LBUF_CUR_TX_ADDR(buf_addr, 0, len);
	memcpy(buf_addr, data, len);
	tx_offset = LBUF_NEXT_TX_ADDR(buf_addr, len) - tx_lbuf[ref_prod];

	return tx_offset;
}

#if 0
int main(int argc, char *argv[])
{
	lbufnet_init(2 << 20);
	lbufnet_input();

	return 0;
}
#endif
