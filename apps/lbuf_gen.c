/*******************************************************************************
*
*  NetFPGA-10G http://www.netfpga.org
*
*  File:
*        lbuf_gen.c
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
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

#include "lbufnet.h"

struct timeval start_tv, end_tv;
uint32_t sent;
uint32_t len = 1 << 10;
uint64_t count = 1000000;
uint32_t sync_flags = SF_BLOCK;

static void show_usage(char *cmd)
{
	fprintf(stderr,
		"Usage: %s args\n"
		"\t-h: show this usage\n"
		"\t-n <# of packets>\n"
		"\t-l <packet length in byte>\n"
		"\t-f <sync flag: 0=non-block, 1=block, 2=busy-wait>\n"
		"\t-p: if specified, pci direct access w/o ioctl\n",
		cmd);
}

void show_stat(struct lbufnet_stat *s)
{
	struct timeval elapsed_tv;
	double elapsed_sec;

	(void)s;
	gettimeofday(&end_tv, NULL);
	timersub(&end_tv, &start_tv, &elapsed_tv);
	elapsed_sec = elapsed_tv.tv_sec + ((double)elapsed_tv.tv_usec / 1000000);
	printf("Elapsed time = %.6lf sec\n", elapsed_sec);
	if (elapsed_sec > 0)
		printf("Throughput = %.6lf Gbps\n", (len * 8 * 1e-9 * sent) / elapsed_sec);
}

int main(int argc, char *argv[])
{
	int opt;
	struct lbufnet_tx_packet pkt;
	DEFINE_LBUFNET_CONF(conf);

	while ((opt = getopt(argc, argv, "hn:l:f:p")) != -1) {
		switch(opt) {
		case 'h':
			show_usage(argv[0]);
			return -1;
		case 'n':
			count = atol(optarg);
			break;
		case 'l':
			len = atoi(optarg);
			break;
		case 'f':
			sync_flags = atoi(optarg);
			break;
		case 'p':
			conf.pci_direct_access = 1;
			break;
		}
	}
	if ((pkt.data = malloc(len)) == NULL) {
		fprintf(stderr, "Error: failed to allocate packet data\n");
		return -1;
	}
	memset(pkt.data, 0, len);
	pkt.len = len;
	pkt.sync_flags = sync_flags;

	conf.flags = TX_ON;	/* tx only */
	/* XXX: plus lbuf dma header size and 4KB-aligned:
	 * will hide this dirty stuff inside liblbufnet */
	conf.tx_lbuf_size = (len + 8 + 4095) & ~4095;	/* 4KB-aligned */
	printf("len=%u count=%lu tx_lbuf_size=%u\n", len, count, conf.tx_lbuf_size);
	if (lbufnet_init(&conf)) {
		fprintf(stderr, "Error: failed to initialize lbufnet\n");
		return -1;
	}
	printf("Data transmission: count=%lu length=%uB\n", count, len);
	printf("\tlbufnet: sync_flags=%d(%s) pci_access=%s\n",
		sync_flags, lbufnet_sync_flag_names[sync_flags],
		conf.pci_direct_access ? "direct" : "ioctl");

	lbufnet_register_exit_callback(show_stat);

	gettimeofday(&start_tv, NULL);
	for (sent = 0; sent < count; sent++)
		lbufnet_output(&pkt);
	lbufnet_exit();

	return 0;
}
