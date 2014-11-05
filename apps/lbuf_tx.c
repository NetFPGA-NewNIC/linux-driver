/*******************************************************************************
*
*  NetFPGA-10G http://www.netfpga.org
*
*  File:
*        lbuf_tx.c
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
#include <sys/time.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "nf10_lbuf_api.h"
#include "nf10_user.h"

#define DEV_FNAME	"/dev/" NF10_DRV_NAME
#define debug(format, arg...)	\
	do { printf(NF10_DRV_NAME ":" format, ##arg); } while(0)

int fd;
unsigned long total_tx_packets, total_tx_bytes;
struct timeval start_tv, end_tv;

#define POLL_THRESHOLD		10000000000ULL
#define UDPDEFPORT		5001
#define MAX_PAYLOAD_SIZE	2048
struct packet {
	struct ether_header ethhdr;
	struct ip iphdr;
	struct udphdr udphdr;
	uint8_t payload[MAX_PAYLOAD_SIZE];
} __attribute__((__packed__));

struct packet_info {
	char *src_ip;
	char *dst_ip;
	char *src_mac;
	char *dst_mac;
	uint32_t len;
	uint32_t buflen;
	uint32_t batchlen;
	uint64_t count;
	struct packet pkt_data;
};

/* wrapsum & checksum are taken from pkt-gen.c in netmap */
static uint16_t wrapsum(uint32_t sum)
{
	sum = ~sum & 0xFFFF;
	return (htons(sum));
}

static uint16_t checksum(const void *data, uint16_t len, uint32_t sum)
{
        const uint8_t *addr = data;
	uint32_t i;

        for (i = 0; i < (len & ~1U); i += 2) {
                sum += (uint16_t)ntohs(*((uint16_t *)(addr + i)));
                if (sum > 0xFFFF)
                        sum -= 0xFFFF;
        }
	if (i < len) {
		sum += addr[i] << 8;
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}
	return sum;
}

void init_packet(struct packet_info *pinfo)
{
	struct ether_header *eh;
	struct ip *ip;
	struct udphdr *udp;
	struct in_addr ip_src, ip_dst;
	uint16_t ip_len, udp_len;

	memset(&pinfo->pkt_data, 0, sizeof(struct packet));

	inet_aton(pinfo->src_ip, &ip_src);
	inet_aton(pinfo->dst_ip, &ip_dst);

	ip = &pinfo->pkt_data.iphdr;
	ip_len = pinfo->len - sizeof(struct ether_header);
	ip->ip_v	= IPVERSION;
	ip->ip_hl	= 5;
	ip->ip_tos	= IPTOS_LOWDELAY;
	ip->ip_len	= htons(ip_len);
	ip->ip_id	= 0;
	ip->ip_off	= htons(IP_DF);
	ip->ip_ttl	= IPDEFTTL;
	ip->ip_p	= IPPROTO_UDP;
	ip->ip_src	= ip_src;
	ip->ip_dst	= ip_dst;
	ip->ip_sum	= wrapsum(checksum(ip, sizeof(*ip), 0));

	udp = &pinfo->pkt_data.udphdr;
	udp_len = ip_len - sizeof(struct ip);
	udp->source	= htons(UDPDEFPORT);
	udp->dest	= htons(UDPDEFPORT);
	udp->len	= htons(udp_len); 
	udp->check	= wrapsum(checksum(udp, sizeof(*udp),
				  checksum(pinfo->pkt_data.payload, udp_len - sizeof(*udp),
				  checksum(&ip->ip_src, 2 * sizeof(ip->ip_src),
				  IPPROTO_UDP + (uint32_t)ntohs(udp->len))))
			  );

	eh = &pinfo->pkt_data.ethhdr;
	memcpy(eh->ether_shost, ether_aton(pinfo->src_mac), ETH_ALEN);
	memcpy(eh->ether_dhost, ether_aton(pinfo->dst_mac), ETH_ALEN);
	eh->ether_type	= htons(ETHERTYPE_IP);
}

int main(int argc, char *argv[])
{
	uint64_t ret;
	int i;
	void *rx_buf[NR_LBUF];
	void *tx_buf[NR_TX_USER_LBUF];
	void *buf_addr;
	uint32_t ref;
	uint32_t pkt_len;
	uint64_t total_poll_wait_cnt = 0, poll_wait_cnt = 0;
	int opt;
	struct packet_info pinfo = {
		"11.0.0.1",
		"12.0.0.1",
		"00:00:00:00:00:00",
		"ff:ff:ff:ff:ff:ff",
		60,		/* packet len */
		2 << 20,	/* buflen: 2MB */
		2 << 20,	/* batchlen: 2MB */
		1,		/* count */
	};

	while ((opt = getopt(argc, argv, "s:d:S:D:n:l:b:B:")) != -1) {
		switch(opt) {
		case 's':
			pinfo.src_ip = optarg;
			break;
		case 'd':
			pinfo.dst_ip = optarg;
			break;
		case 'S':
			pinfo.src_mac = optarg;
			break;
		case 'D':
			pinfo.dst_mac = optarg;
			break;
		case 'n':
			pinfo.count = atol(optarg);
			break;
		case 'l':
			pinfo.len = atoi(optarg);
			break;
		case 'b':
			pinfo.buflen = atoi(optarg) << 10;	/* in KB */
			if (pinfo.buflen < (4<<10) || pinfo.buflen > (1<<30)) {
				fprintf(stderr, "Error: buflen must be >= 4K and <= 1G\n");
				return -1;
			}
			break;
		case 'B':
			pinfo.batchlen = atoi(optarg) << 10;	/* in KB */
			break;
		}
	}
	if (pinfo.batchlen > pinfo.buflen)
		pinfo.batchlen = pinfo.buflen;

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
		rx_buf[i] = mmap(NULL, LBUF_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
		if (rx_buf[i] == MAP_FAILED) {
			perror("mmap");
			return -1;
		}
		debug("RX lbuf[%d] is mmaped to vaddr=%p w/ size=%lu\n",
		      i, rx_buf[i], LBUF_SIZE);
	}

	for (i = 0; i < NR_TX_USER_LBUF; i++) {
		/* it should be writable and MAP_SHARED, otherwise write leads to CoW and 
		 * kernel cannot see the update in the right place */
		tx_buf[i] = mmap(NULL, pinfo.buflen, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (tx_buf[i] == MAP_FAILED) {
			perror("mmap");
			return -1;
		}
		debug("TX lbuf[%d] is mmaped to vaddr=%p w/ size=%u\n",
		      i, tx_buf[i], pinfo.buflen);
	}

	init_packet(&pinfo);

	pkt_len = pinfo.len;
	i = ref = 0;
	while (i < pinfo.count) {
		uint32_t offset;
		buf_addr = tx_buf[ref];

		/* polling for lbuf to be available */
		while(!LBUF_IS_TX_AVAIL(buf_addr)) {
			total_poll_wait_cnt++;
			if (++poll_wait_cnt >= POLL_THRESHOLD)
				goto err;
		}
		poll_wait_cnt = 0;
cont_fill:
		offset = buf_addr - tx_buf[ref];
		if (LBUF_HAS_TX_ROOM(pinfo.buflen, offset, pkt_len)) {
			buf_addr = LBUF_CUR_TX_ADDR(buf_addr, 0, pkt_len);
			memcpy(buf_addr, &pinfo.pkt_data, pkt_len);
			buf_addr = LBUF_NEXT_TX_ADDR(buf_addr, pkt_len);
			if (++i < pinfo.count && (offset + (2 * pkt_len)) <= pinfo.batchlen)
				goto cont_fill;
			else
				offset = buf_addr - tx_buf[ref];
		}
		ioctl(fd, NF10_IOCTL_CMD_XMIT, NF10_IOCTL_ARG_XMIT(ref, offset));
		inc_txbuf_ref(ref);
	}
err:
	debug("%d packets sent (ref=%d total_poll_wait_cnt=%lu (status=%s))\n",
	      i, ref, total_poll_wait_cnt, poll_wait_cnt == POLL_THRESHOLD ? "Error" : "Done");

	return 0;
}
