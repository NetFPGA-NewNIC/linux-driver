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

#include "nf10_lbuf_api.h"
#include "nf10_user.h"

#define DEV_FNAME	"/dev/" NF10_DRV_NAME
#define debug(format, arg...)	\
	do { printf(NF10_DRV_NAME ":" format, ##arg); } while(0)

static int fd;
static struct lbuf_user *ld;	/* lbuf descriptor */
static void *rx_lbuf[NR_SLOT];
static void *tx_lbuf;
static int initialized;
static int prev_nr_drops;
static union lbuf_header lh;

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

int lbufnet_init(void)
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
	debug("\ttx_prod=%u tx_prod_pvt=%u tx_cons=%u\n", ld->tx_prod, ld->tx_prod_pvt, ld->tx_cons);
	debug("\ttx_writeback=0x%llx rx_writeback=0x%llx\n", ld->tx_writeback, ld->rx_writeback);

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
	debug("RX qword=%llx, nr_drops=%u\n", lh.qword, lh.nr_drops);

	tx_lbuf = mmap(NULL, LBUF_TX_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (tx_lbuf == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	debug("TX lbuf is mmaped to vaddr=%p w/ size=%lu\n",tx_lbuf, LBUF_TX_SIZE);

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

void lbufnet_input(void)
{
	void *buf_addr;
	unsigned int dword_idx, next_dword_idx;
	int port_num;
	uint32_t pkt_len, next_pkt_len;
	void *pkt_addr;

	if (!initialized) {
		debug("Error: lbuf is not initialized\n");
		return;
	}

	do {
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
#if 0
			if (poll_cnt++ > LBUF_POLL_THRESH)
				goto wait_intr;
#endif
			goto wait_to_start_recv;
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

int main(int argc, char *argv[])
{
	lbufnet_init();
	lbufnet_input();

	return 0;
}
