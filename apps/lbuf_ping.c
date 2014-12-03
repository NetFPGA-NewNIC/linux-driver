/*******************************************************************************
*
*  NetFPGA-10G http://www.netfpga.org
*
*  File:
*        lbuf_ping.c
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
#include <sys/ioctl.h>
#include <stdint.h>
#include <sys/time.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include "lbufnet.h"

#define MODE_PING	0
#define MODE_PONG	1

#define MAX_PAYLOAD_SIZE	2048
struct packet {
	struct ether_header ethhdr;
	struct ip iphdr;
	struct icmphdr icmphdr;
	char payload[MAX_PAYLOAD_SIZE];
} __attribute__((__packed__));

struct ping_info {
	char *src_ip;
	char *dst_ip;
	char *src_mac;
	char *dst_mac;
	int mode;
	uint64_t count;
	uint32_t interval_us;
	uint8_t len;
	uint8_t datalen;
	uint32_t sync_flag;
	struct packet pkt_data;
} pinfo = {
	.mode = MODE_PING,	/* ping */
	.count = 0,		/* forever */
	.interval_us = 1000000,	/* 1 sec */
	.datalen = 56,		/* same default as ping */
	.sync_flag = SF_BLOCK,
};

struct timeval start_tv, end_tv;

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

uint16_t sequence;
uint32_t base_sum;
void init_packet(struct ping_info *pinfo)
{
	struct ether_header *eh;
	struct ip *ip;
	struct icmphdr *icmp;
	struct in_addr ip_src, ip_dst;
	uint16_t ip_len;

	memset(&pinfo->pkt_data, 0, sizeof(struct packet));
	pinfo->len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + pinfo->datalen;

	inet_aton(pinfo->src_ip, &ip_src);
	inet_aton(pinfo->dst_ip, &ip_dst);

	ip = &pinfo->pkt_data.iphdr;
	ip_len = pinfo->len - sizeof(struct ether_header);
	ip->ip_v	= IPVERSION;
	ip->ip_hl	= 5;
	ip->ip_tos	= IPTOS_CLASS_DEFAULT;
	ip->ip_len	= htons(ip_len);
	ip->ip_id	= 0;
	ip->ip_off	= 0;
	ip->ip_ttl	= IPDEFTTL;
	ip->ip_p	= IPPROTO_ICMP;
	ip->ip_src	= ip_src;
	ip->ip_dst	= ip_dst;
	ip->ip_sum	= wrapsum(checksum(ip, sizeof(*ip), 0));

	icmp = &pinfo->pkt_data.icmphdr;
	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->un.echo.id = htons(0x121d);	/* XXX */
	base_sum = checksum(icmp, ip_len - sizeof(struct iphdr), 0);

	eh = &pinfo->pkt_data.ethhdr;
	memcpy(eh->ether_shost, ether_aton(pinfo->src_mac), ETH_ALEN);
	memcpy(eh->ether_dhost, ether_aton(pinfo->dst_mac), ETH_ALEN);
	eh->ether_type	= htons(ETHERTYPE_IP);
}

void input_handler(void *data, unsigned int len)
{
	struct packet *pkt = data;

	if (pkt->iphdr.ip_p != IPPROTO_ICMP)
		return;

	if (pinfo.mode == MODE_PING) {
		double elapsed_ms;
		struct timeval elapsed_tv;

		if (pkt->icmphdr.type != ICMP_ECHOREPLY)
			return;
		gettimeofday(&end_tv, NULL);
		timersub(&end_tv, &start_tv, &elapsed_tv);
		elapsed_ms = elapsed_tv.tv_sec * 1000 + ((double)elapsed_tv.tv_usec / 1000);
		printf("%lu bytes from %s: icmp_req=%u ttl=%u time=%.3lf ms\n",
			len - sizeof(struct ether_header) - sizeof(struct iphdr),
			inet_ntoa(pkt->iphdr.ip_src),
			ntohs(pkt->icmphdr.un.echo.sequence) + 1,
			pkt->iphdr.ip_ttl,
			elapsed_ms);
	}
	else if (pinfo.mode == MODE_PONG) {
		struct in_addr ip_tmp;
		uint8_t mac_tmp[ETH_ALEN];
		uint16_t icmplen;

		if (pkt->icmphdr.type != ICMP_ECHO)
			return;
		icmplen = len - sizeof(struct ether_header) - sizeof(struct ip);
		/* check if checksum is correct */
		if (wrapsum(checksum(&pkt->icmphdr, icmplen, 0)) != 0)
			return;

		pkt->icmphdr.type = ICMP_ECHOREPLY;
		pkt->icmphdr.checksum = 0;
		/* swap ip and mac */
		ip_tmp = pkt->iphdr.ip_src;
		pkt->iphdr.ip_src = pkt->iphdr.ip_dst;
		pkt->iphdr.ip_dst = ip_tmp;
		memcpy(mac_tmp, pkt->ethhdr.ether_shost, ETH_ALEN);
		memcpy(pkt->ethhdr.ether_shost, pkt->ethhdr.ether_dhost, ETH_ALEN);
		memcpy(pkt->ethhdr.ether_dhost, mac_tmp, ETH_ALEN);
		pkt->icmphdr.checksum = wrapsum(checksum(&pkt->icmphdr, icmplen, 0));

		lbufnet_output(data, len, pinfo.sync_flag);
	}
}

int main(int argc, char *argv[])
{
	uint64_t ret;
	int i;
	unsigned int batched_size;
	int opt;

	while ((opt = getopt(argc, argv, "s:d:S:D:n:f:m:i:l:")) != -1) {
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
		case 'm':
			pinfo.mode = atoi(optarg);
			break;
		case 'i':
			pinfo.interval_us = (uint32_t)(atof(optarg) * 1000000);
			break;
		case 'l':
			pinfo.datalen = atoi(optarg);
			break;
		case 'f':
			pinfo.sync_flag = atoi(optarg);
			break;
		}
	}
	lbufnet_init(4096);	/* 4KB tx buffer */
	lbufnet_register_input_callback(input_handler);
	if (pinfo.mode == MODE_PING) {
		if (!pinfo.src_ip || !pinfo.src_mac || !pinfo.dst_ip || !pinfo.dst_mac) {
			fprintf(stderr, "ping mode requires src and dst ip/mac addresses\n");
			return -1;
		}
		printf("PING %s (%s) from %s nf0: %u(%ld) bytes of data.\n",
			pinfo.dst_ip, pinfo.dst_ip, pinfo.src_ip, pinfo.datalen,
			pinfo.datalen + sizeof(struct icmphdr) + sizeof(struct iphdr));

		init_packet(&pinfo);
		do {
			pinfo.pkt_data.icmphdr.un.echo.sequence = htons(sequence);
			pinfo.pkt_data.icmphdr.checksum = wrapsum(base_sum + sequence);
			gettimeofday(&start_tv, NULL);
			lbufnet_output(&pinfo.pkt_data, pinfo.len, pinfo.sync_flag);
			lbufnet_input(1, pinfo.sync_flag);
			usleep(pinfo.interval_us);
			sequence++;
		} while(pinfo.count == 0 || sequence <= pinfo.count);
	}
	else if (pinfo.mode == MODE_PONG)
		lbufnet_input(0, pinfo.sync_flag);

	return 0;
}
