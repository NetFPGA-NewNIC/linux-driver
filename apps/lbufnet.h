/*******************************************************************************
*
*  NetFPGA-10G http://www.netfpga.org
*
*  File:
*        lbufnet.h
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

struct lbufnet_stat {
	unsigned int nr_drops;
	unsigned long nr_polls;
};

enum {
	SF_NON_BLOCK = 0,
	SF_BLOCK,
	SF_BUSY_BLOCK,
};

typedef void (*lbufnet_input_cb)(void *data, unsigned int len);
typedef void (*lbufnet_exit_cb)(struct lbufnet_stat *stat);

int lbufnet_init(unsigned int _tx_lbuf_size);
int lbufnet_exit(void);
int lbufnet_register_input_callback(lbufnet_input_cb cb);
int lbufnet_register_exit_callback(lbufnet_exit_cb cb);
int lbufnet_input(unsigned long nr_packets, int sync_flags);
int lbufnet_flush(int sync_flags);
int lbufnet_write(void *data, unsigned int len, int sync_flags);
int lbufnet_output(void *data, unsigned len, int sync_flags);
