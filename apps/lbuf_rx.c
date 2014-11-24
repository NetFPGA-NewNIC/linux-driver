/*******************************************************************************
*
*  NetFPGA-10G http://www.netfpga.org
*
*  File:
*        lbuf_rx.c
*
*  Project:
*
*
*  Author:
*        Hwanju Kim
*
*  Description:
*	 This is a user-level program that is able to directly receive packets
*	 from lbuf DMA on NetFPGA. This program is the simplest one without any
*	 packet processing while fetching received packets from a large buffer.
*	 The format agreement is defined in nf10_lbuf_api.h, which is included
*	 in this source file. To run this, first go to the driver directory,
*	 # insmod nf10.ko
*	 and here at the directory of lbuf_rx, run
*	 # ./lbuf_rx
*	 Notice that this simple user-level rx app is meant for DMA performance
*	 testing in terms of NetFPGA-to-host speed. No support for multiple
*	 processes on a single NIC and concurrent access by kernel and user.
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

int fd;
unsigned long total_rx_packets, total_rx_bytes;
struct timeval start_tv, end_tv;

void finish(int sig)
{
	uint64_t dummy;
	struct timeval elapsed_tv;
	double elapsed_sec;

	timersub(&end_tv, &start_tv, &elapsed_tv);
	elapsed_sec = elapsed_tv.tv_sec + ((double)elapsed_tv.tv_usec / 1000000);

	printf("\nReceived packets = %lu (total=%luB avg=%luB)\n",
		total_rx_packets, total_rx_bytes, total_rx_packets ? total_rx_bytes / total_rx_packets : 0);
	printf("Elapsed time = %.6lf sec\n", elapsed_sec);
	if (elapsed_sec > 0)
		printf("Throughput = %.2lf pps (%.2lf Mb/sec)\n",
			total_rx_packets / elapsed_sec, (total_rx_bytes * 8 / 1000000) / elapsed_sec);

	ioctl(fd, NF10_IOCTL_CMD_INIT, &dummy);
	exit(0);
}

#define move_to_next_lbuf()	\
do {	\
	LBUF_INIT_HEADER(buf_addr);	\
	ioctl(fd, NF10_IOCTL_CMD_PREPARE_RX, rx_cons);	\
	inc_pointer(rx_cons);	\
	dword_idx = NR_RESERVED_DWORDS;	\
} while(0)

#define lbuf_input()	\
do {	\
	memset(pkt_addr - 8, 0, ALIGN(pkt_len, 8) + 8);	\
	total_rx_bytes += pkt_len;	\
	total_rx_packets++;	\
} while(0)


int main(int argc, char *argv[])
{
	uint64_t ret;
	int32_t rx_cons = -1;
	int i;
	struct large_buffer_user *lbuf_desc;
	void *buf[NR_LBUF];
	uint32_t *buf_addr;
	int dword_idx = NR_RESERVED_DWORDS, next_dword_idx;
	union lbuf_header lh;
	int port_num;
	uint32_t pkt_len, next_pkt_len;
	void *pkt_addr;
	////unsigned long poll_cnt;

	if ((fd = open(DEV_FNAME, O_RDWR, 0755)) < 0) {
		perror("open");
		return -1;
	}

	if (ioctl(fd, NF10_IOCTL_CMD_INIT, &ret)) {
		perror("ioctl init");
		return -1;
	}

	debug("initialized for direct user access\n");

	lbuf_desc = mmap(NULL, 1 << PAGE_SHIFT, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (lbuf_desc == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	debug("DMA metadata is mmaped to vaddr=%p\n", lbuf_desc);
	debug("\trx_prod=%u rx_cons=%u tx_prod=%u tx_cons=%u\n",
	      lbuf_desc->prod[RX], lbuf_desc->cons[RX], lbuf_desc->prod[TX], lbuf_desc->cons[TX]);
	debug("\trx_dword_idx=%u\n", lbuf_desc->rx_dword_idx);
	debug("\trx_writeback=%lx tx_writeback=%lx\n", lbuf_desc->writeback[RX], lbuf_desc->writeback[TX]);

	for (i = 0; i < NR_LBUF; i++) {
		/* PROT_READ for rx only */
		buf[i] = mmap(NULL, LBUF_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (buf[i] == MAP_FAILED) {
			perror("mmap");
			return -1;
		}
		debug("lbuf[%d] is mmaped to vaddr=%p w/ size=%lu\n",
		      i, buf[i], LBUF_SIZE);
	}

	signal(SIGINT, finish);
	printf("Press Ctrl+C to finish and see # of rx packets\n");

#if 0
wait_intr:
	/* wait interrupt: blocked */
	ioctl(fd, NF10_IOCTL_CMD_WAIT_INTR, &ret);
	if (rx_cons == -1)
		rx_cons = (int32_t)ret;
#else
	rx_cons = 0;
#endif
	do {
		buf_addr = buf[rx_cons];
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
			fprintf(stderr, "Error: rx_cons=%d lbuf contains invalid pkt len=%u\n",
				rx_cons, pkt_len);
			break;
		}
		next_dword_idx = LBUF_NEXT_DWORD_IDX(dword_idx, pkt_len);
		pkt_addr = LBUF_PKT_ADDR(buf_addr, dword_idx);
wait_to_end_recv:
		next_pkt_len = LBUF_PKT_LEN(buf_addr, next_dword_idx);
		if (next_pkt_len > 0) {
			lbuf_input();
			dword_idx = next_dword_idx;
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
			dword_idx = next_dword_idx;
		}
		if (dword_idx >= (LBUF_SIZE >> 2))
			move_to_next_lbuf();
	} while(1);
	return 0;
}
