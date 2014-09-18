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

int main(int argc, char *argv[])
{
	uint64_t ret;
	uint32_t rx_cons;
	int i;
	void *buf[NR_LBUF];
	uint32_t *buf_addr;
	uint32_t nr_dwords;
	int dword_idx, max_dword_idx;
	int port_num;
	uint32_t pkt_len;
	uint8_t bytes_remainder;
	uint32_t rx_packets;

	if ((fd = open(DEV_FNAME, O_RDWR, 0755)) < 0) {
		perror("open");
		return -1;
	}

	if (ioctl(fd, NF10_IOCTL_CMD_INIT, &ret)) {
		perror("ioctl init");
		return -1;
	}

	debug("initialized for direct user access\n");

	for (i = 0; i < NR_LBUF; i++) {
		/* PROT_READ for rx only */
		buf[i] = mmap(NULL, LBUF_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
		if (buf[i] == MAP_FAILED) {
			perror("mmap");
			return -1;
		}
		debug("lbuf[%d] is mmaped to vaddr=%p w/ size=%lu\n",
		      i, buf[i], LBUF_SIZE);
	}

	signal(SIGINT, finish);
	printf("Press Ctrl+C to finish and see # of rx packets\n");
	do {

		/* wait interrupt: blocked */
		ioctl(fd, NF10_IOCTL_CMD_WAIT_INTR, &ret);
		rx_cons = (uint32_t)ret;
lbuf_poll_loop:
		rx_packets = 0;

		buf_addr = buf[rx_cons];
		nr_dwords = LBUF_NR_DWORDS(buf_addr);
		dword_idx = LBUF_FIRST_DWORD_IDX();

		/* if lbuf is invalid, usually normal case at the end of the
		 * lbuf loop, BUT note that it could be caused by a DMA bug */
		if (!LBUF_IS_VALID(nr_dwords))
			continue;

		/* packet processing loop */
		do {
			port_num = LBUF_PKT_PORT_NUM(buf_addr, dword_idx);
			pkt_len = LBUF_PKT_LEN(buf_addr, dword_idx);
			/* if you want to get timestamp of a packet,
			 * use LBUF_TIMESTAMP(buf_addr, dword_idx) */

			if (LBUF_IS_PKT_VALID(port_num, pkt_len)) {
				if (total_rx_packets == 0 && rx_packets == 0)
					gettimeofday(&start_tv, NULL);
				rx_packets++;
				total_rx_bytes += pkt_len;
			}
			else
				fprintf(stderr, "Error: rx_cons=%d lbuf contains invalid pkt len=%u\n",
					rx_cons, pkt_len);
			dword_idx = LBUF_NEXT_DWORD_IDX(dword_idx, pkt_len);
		} while(dword_idx < nr_dwords);

		gettimeofday(&end_tv, NULL);

		/* send this lbuf back to the board, and proceed the pointer */
		ioctl(fd, NF10_IOCTL_CMD_PREPARE_RX, rx_cons);

		total_rx_packets += rx_packets;
#if 0
		debug("C [rx_cons=%d] nr_dwords=%u rx_packets=%u/%lu\n",
				rx_cons, nr_dwords, rx_packets, total_rx_packets);
#endif

		inc_pointer(rx_cons);
		goto lbuf_poll_loop;
	} while(1);

	return 0;
}
