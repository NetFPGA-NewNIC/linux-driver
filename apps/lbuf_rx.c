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
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include "lbufnet.h"

unsigned long total_rx_packets, total_rx_bytes;
struct timeval start_tv, end_tv;

void show_stat(struct lbufnet_stat *s)
{
	struct timeval elapsed_tv;
	double elapsed_sec;

	timersub(&end_tv, &start_tv, &elapsed_tv);
	elapsed_sec = elapsed_tv.tv_sec + ((double)elapsed_tv.tv_usec / 1000000);

	printf("\nReceived packets = %lu (total=%luB avg=%luB drops=%u polls=%lu)\n",
		total_rx_packets, total_rx_bytes,
		total_rx_packets ? total_rx_bytes / total_rx_packets : 0,
		s->nr_drops, s->nr_polls);
	printf("Elapsed time = %.6lf sec\n", elapsed_sec);
	if (elapsed_sec > 0)
		printf("Throughput = %.2lf pps (%.6lf Gbps raw=%.6lf Gbps)\n",
			total_rx_packets / elapsed_sec,
			(total_rx_bytes * 8 * 1e-9) / elapsed_sec,
			/* add 24B = 20B framing(12B IFG + 8B Preemble) + 4B CRC */
			((total_rx_bytes + (24 * total_rx_packets)) * 8) * 1e-9 / elapsed_sec);
}

int input_handler(void *data, unsigned int len)
{
	if (total_rx_packets == 0)
		gettimeofday(&start_tv, NULL);
	else
		gettimeofday(&end_tv, NULL);
	total_rx_packets++;
	total_rx_bytes += len;
	return 1;
}

int main(int argc, char *argv[])
{
	int sync_flag = SF_BLOCK;
	int opt;
	struct lbufnet_conf conf = {
		.tx_lbuf_size = 0,	/* don't use tx by this app */
		.pci_direct_access = 0,	/* use ioctl by default */
	};

	while ((opt = getopt(argc, argv, "f:p")) != -1) {
		switch(opt) {
		case 'f':
			sync_flag = atoi(optarg);
			break;
		case 'p':
			conf.pci_direct_access = 1;
			break;
		}
	}
	if (lbufnet_init(&conf)) {
		fprintf(stderr, "Error: failed to initialize lbufnet\n");
		return -1;
	}
	lbufnet_register_input_callback(input_handler);
	lbufnet_register_exit_callback(show_stat);
	lbufnet_input(LBUFNET_INPUT_FOREVER, sync_flag);

	return 0;
}
