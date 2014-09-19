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
*	 This user-level application is to generate packets on lbuf DMA.
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
#include <sys/ioctl.h>
#include <fcntl.h>

#include "nf10_user.h"

#define DEV_FNAME	"/dev/" NF10_DRV_NAME

int main(int argc, char *argv[])
{
	int fd;
	unsigned long req_count;
	struct pkt_gen_info pgi;

	if (argc != 4) {
		fprintf(stderr, "Usage: %s <pkt len (in bytes)> <pkt count> <batch(=0 or 1)>\n", argv[0]);
		return -1;
	}
	pgi.pkt_len = (unsigned int)atoi(argv[1]);
	pgi.pkt_count = req_count = (unsigned long)atol(argv[2]);
	pgi.batch = atoi(argv[3]);

	if ((fd = open(DEV_FNAME, O_RDWR, 0755)) < 0) {
		perror("open");
		return -1;
	}
	ioctl(fd, NF10_IOCTL_CMD_PKT_GEN, &pgi);

	printf("# of generated packets = %lu/%lu\n", pgi.pkt_count, req_count);

	return 0;
}
