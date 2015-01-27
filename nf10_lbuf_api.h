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
/* NR_SLOT is dependent on lbuf DMA engine */
#define NR_SLOT		2
#define inc_idx(idx)	\
	do { idx = idx == NR_SLOT - 1 ? 0 : idx + 1; } while(0)

#define MIN_TX_USER_LBUF	4
#define MAX_TX_USER_LBUF	32
#define MIN_TX_USER_LBUF_SIZE	(4 << 10)	/* 4KB */
#define MAX_TX_USER_LBUF_SIZE	(2 << 20)	/* 2MB */

#ifndef PAGE_SHIFT
#define PAGE_SHIFT	12
#define PAGE_SIZE	(1 << PAGE_SHIFT)
#endif
#define LBUF_RX_ORDER	9	/* default 2MB */
#define LBUF_RX_SIZE	(1UL << (PAGE_SHIFT + LBUF_RX_ORDER))

#define LBUF_NR_PORTS	4	/* only used for sanity check: should be the same as # of physical ports */

#ifndef ACCESS_ONCE
#define ACCESS_ONCE(x)	(*(volatile typeof(x) *)&(x))
#endif
#define DWORD_GET(p, i)		(((unsigned int *)p)[i])
#define DWORD_GET_ONCE(p, i)	ACCESS_ONCE(((unsigned int *)p)[i])
#define QWORD_GET_ONCE(p, i)	ACCESS_ONCE(((unsigned long long *)p)[i])

#ifndef ALIGN
#define ALIGN(x, a)	(((x) + (typeof(x))(a-1)) & ~(typeof(x))(a-1))
#endif

/*
 * lbuf dma metadata
 */
struct lbuf_user {
	unsigned int tx_idx, rx_idx;

	/* rx dword offset to clean (consume) in current lbuf */
	unsigned int rx_cons;

	unsigned long long tx_dma_addr[MAX_TX_USER_LBUF];
	unsigned long long rx_dma_addr[NR_SLOT];
	unsigned long long last_gc_addr;
};

#define NR_RESERVED_DWORDS		32
/* 1st dword is # of qwords, so # of dwords includes it plus reserved area */
#define LBUF_NR_DWORDS(buf_addr)	((DWORD_GET_ONCE(buf_addr, 0) << 1) + NR_RESERVED_DWORDS)
#define LBUF_FIRST_DWORD_IDX()		NR_RESERVED_DWORDS
#define LBUF_INVALIDATE(buf_addr)	do { QWORD_GET_ONCE(buf_addr, 0) = 0; } while(0)

/* Rx
 * in each packet, 1st dword	  = packet metadata (upper 16bit = port num encoded)
 *		   2nd dword	  = packet length in bytes
 *		   3rd-4th dword  = packet length in bytes
 *		   5th dword~	  = packet payload
 *		   pad = keeping qword-aligned
 */
#define LBUF_PKT_METADATA(buf_addr, dword_idx)	DWORD_GET_ONCE(buf_addr, dword_idx)
#define LBUF_PKT_LEN(buf_addr, dword_idx)	DWORD_GET_ONCE(buf_addr, dword_idx + 1)
#ifdef CONFIG_NO_TIMESTAMP
#define LBUF_TIMESTAMP(buf_addr, dword_idx)	0ULL
#define LBUF_PKT_START_OFFSET	2
#else
#define LBUF_TIMESTAMP(buf_addr, dword_idx)	*(volatile unsigned long long *)((unsigned int *)buf_addr + dword_idx + 2)
#define LBUF_PKT_START_OFFSET	4
#endif
#define LBUF_PKT_ADDR(buf_addr, dword_idx)	(void *)&((unsigned int *)buf_addr)[dword_idx+LBUF_PKT_START_OFFSET]
#define LBUF_NEXT_DWORD_IDX(dword_idx, pkt_len)     (dword_idx + LBUF_PKT_START_OFFSET + (ALIGN(pkt_len, 8) >> 2))

/* Tx */
#define LBUF_TX_METADATA_SIZE	8
#define LBUF_CUR_TX_ADDR(buf_addr, port_num, pkt_len)		\
({								\
	((unsigned int *)buf_addr)[0] = LBUF_ENCODE_PORT_NUM(port_num);	\
	((unsigned int *)buf_addr)[1] = pkt_len;				\
	(void *)buf_addr + LBUF_TX_METADATA_SIZE;		\
})
#define LBUF_NEXT_TX_ADDR(buf_addr, pkt_len)	(void *)ALIGN(((unsigned long)buf_addr + pkt_len), 8)
#define LBUF_HAS_TX_ROOM(buf_size, buf_offset, pkt_size)	\
	(ALIGN(buf_offset + LBUF_TX_METADATA_SIZE + pkt_size, 8) <= buf_size)
/* for user to poll if tx buffer is available, check if the first packet's pkt_len == 0.
 * gc handler sets pkt_len to zero if tx lbuf is allocated for user rather than releasing it */
#define LBUF_IS_TX_AVAIL(buf_addr)	(DWORD_GET_ONCE(buf_addr, 1) == 0)
#define LBUF_SET_TX_AVAIL(buf_addr)	do { DWORD_GET_ONCE(buf_addr, 1) = 0; } while(0)

/* check functions */
#define LBUF_IS_VALID(nr_dwords)		(nr_dwords > NR_RESERVED_DWORDS && nr_dwords <= (LBUF_SIZE >> 2))
#define LBUF_IS_PORT_VALID(port_num)		(port_num < LBUF_NR_PORTS)
#define LBUF_IS_PKT_VALID(port_num, pkt_len)	(LBUF_IS_PORT_VALID(port_num) && pkt_len >= 60 && pkt_len <= 1514)

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
		return 0x02;	/* if invalid, port 0 by default */
	return port_map[port_num];
}

union lbuf_header {
	struct {
		unsigned nr_qwords:32;
		unsigned is_closed:1;
		unsigned unused2:7;
		unsigned nr_drops:16;
		unsigned unused1:8;
	};
	unsigned long long qword;
};

#define LBUF_INIT_HEADER(buf_addr)	do { QWORD_GET_ONCE(buf_addr, 0) = 0; } while(0)
#define LBUF_GET_HEADER(buf_addr, lh)	do { lh.qword = QWORD_GET_ONCE(buf_addr, 0); } while(0)
#define LBUF_CLOSED(dword_idx, lh)	\
	(lh.is_closed && (lh.nr_qwords << 1) == dword_idx - NR_RESERVED_DWORDS)
#define LBUF_128B_ALIGN(dword_idx)	ALIGN(dword_idx, 32)

/* offset to bar2 address of the card */
#define RX_LBUF_ADDR_BASE	0x40
#define RX_LBUF_STAT_BASE	0x60
#define RX_READY		0x1
#define TX_LBUF_ADDR_BASE	0x80
#define TX_LBUF_STAT_BASE	0xA0
#define TX_COMPLETION_ADDR	0xB0
#define TX_COMPLETION_SIZE	((NR_SLOT << 2) + 8)	/* DWORD for each desc + QWORD (last gc addr) */
#define IRQ_ENABLE_REG		0x20
#define IRQ_DISABLE_REG		0x24
#define IRQ_PERIOD_REG		0x28
#define IRQ_CTRL_VAL		0xcacabeef
#define TX_SYNC_REG		0xB8
#define RX_SYNC_REG		0x78

#define rx_addr_off(i)	(RX_LBUF_ADDR_BASE + (i << 3))
#define rx_stat_off(i)	(RX_LBUF_STAT_BASE + (i << 2))
#define tx_addr_off(i)	(TX_LBUF_ADDR_BASE + (i << 3))
#define tx_stat_off(i)	(TX_LBUF_STAT_BASE + (i << 2))

#define TX_AVAIL		0xcacabeef
#define TX_USED			0		/* not HW-dependent could be any value but TX_AVAIL */
#define TX_LAST_GC_ADDR_OFFSET	(NR_SLOT << 2)		/* last gc addr following completion buffers for all descs */
#define LBUF_TX_COMPLETION(tx_compl_addr, idx)	DWORD_GET_ONCE(tx_compl_addr, idx)
#define LBUF_GC_ADDR(tx_compl_addr)		ACCESS_ONCE(*(unsigned long long *)(tx_compl_addr + TX_LAST_GC_ADDR_OFFSET))
