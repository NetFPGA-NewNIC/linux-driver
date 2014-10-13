/*******************************************************************************
*
*  NetFPGA-10G http://www.netfpga.org
*
*  File:
*        nf10_lbuf_api.h
*
*  Project:
*
*
*  Author:
*        Hwanju Kim
*
*  Description:
*	 This header file provides lbuf API for any packet processing software
*	 to retrieve packets from a lbuf. The lbuf DMA fills packets in lbuf
*	 in its own way with a certain format, so software should know this
*	 format to fetch them. This header file can be included not only in
*	 the kernel driver, but also in user-level apps. Whenever DMA hardware
*	 changes its way of filling packets, this file should be modified.
*
*        TODO: 
*		- API for TX
*
*	 This code is initially developed for the Network-as-a-Service (NaaS) project.
*	 (under development in https://github.com/NetFPGA-NewNIC/linux-driver)
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

/* lbuf version 1.0 */
/* NR_LBUF is dependent on lbuf DMA engine */
#define NR_LBUF		2
#define inc_pointer(pointer)	\
	do { pointer = pointer == NR_LBUF - 1 ? 0 : pointer + 1; } while(0)

#ifndef PAGE_SHIFT
#define PAGE_SHIFT	12
#endif
#define LBUF_ORDER	9
#define LBUF_SIZE	(1UL << (PAGE_SHIFT + LBUF_ORDER))
#define LBUF_NR_PORTS	4	/* only used for sanity check: should be the same as # of physical ports */

#define NR_RESERVED_DWORDS		32
/* 1st dword is # of qwords, so # of dwords includes it plus reserved area */
#define LBUF_NR_DWORDS(buf_addr)	((((unsigned int *)buf_addr)[0] << 1) + NR_RESERVED_DWORDS)
#define LBUF_FIRST_DWORD_IDX()		NR_RESERVED_DWORDS
#define LBUF_INVALIDATE(buf_addr)	do { ((unsigned int *)buf_addr)[0] = 0; } while(0)

/* in each packet, 1st dword	  = packet metadata (upper 16bit = port num encoded)
 *		   2nd dword	  = packet length in bytes
 *		   3rd-4th dword  = packet length in bytes
 *		   5th dword~	  = packet payload
 *		   pad = keeping qword-aligned
 */
#define LBUF_PKT_METADATA(buf_addr, dword_idx)	((unsigned int *)buf_addr)[dword_idx]
#define LBUF_PKT_LEN(buf_addr, dword_idx)	((unsigned int *)buf_addr)[dword_idx+1]
#ifdef CONFIG_NO_TIMESTAMP
#define LBUF_TIMESTAMP(buf_addr, dword_idx)	0ULL
#define LBUF_PKT_START_OFFSET	2
#else
#define LBUF_TIMESTAMP(buf_addr, dword_idx)	*(unsigned long long *)((unsigned int *)buf_addr + dword_idx + 2)
#define LBUF_PKT_START_OFFSET	4
#endif
#define LBUF_PKT_ADDR(buf_addr, dword_idx)	(void *)&((unsigned int *)buf_addr)[dword_idx+LBUF_PKT_START_OFFSET]
#define LBUF_NEXT_DWORD_IDX(dword_idx, pkt_len)     (dword_idx + LBUF_PKT_START_OFFSET + (((pkt_len + 7) & ~7) >> 2))

/* check functions */
#define LBUF_IS_VALID(nr_dwords)		(nr_dwords > NR_RESERVED_DWORDS && nr_dwords <= (LBUF_SIZE >> 2))
#define LBUF_IS_PORT_VALID(port_num)		(port_num >=0 && port_num < LBUF_NR_PORTS)
#define LBUF_IS_PKT_VALID(port_num, pkt_len)	(LBUF_IS_PORT_VALID(port_num) && pkt_len >= 60 && pkt_len <= 1518)

#if defined(CONFIG_NR_PORTS) && (CONFIG_NR_PORTS == 1)
#define LBUF_PKT_PORT_NUM(buf_addr, dword_idx)	(0)
#else
/* port encode/decode */
static inline int LBUF_PKT_PORT_NUM(void *buf_addr, unsigned int dword_idx)
{
	/* decode */
	int port_enc = (LBUF_PKT_METADATA(buf_addr, dword_idx) >> 16) & 0xff;
	switch (port_enc) {
		case 0x02:	return 0;
		case 0x08:	return 1;
		case 0x20:	return 2;
		case 0x80:	return 3;
		default:	return -1;
	}
	return -1;
}
#endif

static inline unsigned int LBUF_ENCODE_PORT_NUM(int port_num)
{
	/* encode */
	static unsigned int port_map[] = {0x02, 0x08, 0x20, 0x80};
	if (!LBUF_IS_PORT_VALID(port_num))
		return 0;
	return port_map[port_num];
}
