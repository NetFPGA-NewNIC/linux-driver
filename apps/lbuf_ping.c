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
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <stdlib.h>	/* atof */

#include "lbufnet.h"

#define MODE_PING	0
#define MODE_PONG	1

#define MAX_PAYLOAD_SIZE	1472
struct icmp_packet {
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
	uint16_t len;
	uint16_t datalen;
	uint8_t checksum;
	uint32_t sync_flags;
	struct icmp_packet pkt_data;
} pinfo = {
	.mode = MODE_PING,	/* ping */
	.count = 0,		/* forever */
	.interval_us = 1000000,	/* 1 sec */
	.datalen = 56,		/* same default as ping */
	.sync_flags = SF_BLOCK,
	.checksum = 1,
};

struct timespec start_ts, end_ts;

static void show_usage(char *cmd)
{
	fprintf(stderr,
		"Usage: %s args\n"
		"\t-h: show this usage\n"
		"\t-m <mode: 0=ping 1=pong>\n"
		"\t-s <source IP address>\n"
		"\t-d <destination IP address>\n"
		"\t-S <source MAC address>\n"
		"\t-D <destination MAC address>\n"
		"\t-n <# of packets>\n"
		"\t-l <packet length in byte>\n"
		"\t-i <ping interval in second>\n"
		"\t-c <ICMP checksum: 0=disabled 1=enabled>\n"
		"\t-f <sync flag: 0=non-block, 1=block, 2=busy-wait>\n"
		"\t-p: if specified, pci direct access w/o ioctl\n",
		cmd);
}

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

uint32_t base_sum;
uint16_t echo_id = 0x3412;	/* XXX */
void init_packet(struct ping_info *pinfo)
{
	struct ether_header *eh;
	struct ip *ip;
	struct icmphdr *icmp;
	struct in_addr ip_src, ip_dst;
	uint16_t ip_len;

	memset(&pinfo->pkt_data, 0, sizeof(struct icmp_packet));
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
	icmp->un.echo.id = echo_id;
	base_sum = checksum(icmp, ip_len - sizeof(struct iphdr), 0);

	eh = &pinfo->pkt_data.ethhdr;
	memcpy(eh->ether_shost, ether_aton(pinfo->src_mac), ETH_ALEN);
	memcpy(eh->ether_dhost, ether_aton(pinfo->dst_mac), ETH_ALEN);
	eh->ether_type	= htons(ETHERTYPE_IP);
}

static int input_handler(struct lbufnet_rx_packet *rx_pkt)
{
	struct icmp_packet *icmp_pkt = rx_pkt->data;
	struct timespec ts;
	uint16_t icmplen;

	if (icmp_pkt->iphdr.ip_p != IPPROTO_ICMP)
		return 0;

	if (pinfo.mode == MODE_PING &&
	    (icmp_pkt->icmphdr.type != ICMP_ECHOREPLY ||
	     icmp_pkt->icmphdr.un.echo.id != echo_id))
		return 0;

	if (pinfo.mode == MODE_PONG &&
	    icmp_pkt->icmphdr.type != ICMP_ECHO)
		return 0;

	icmplen = rx_pkt->len - sizeof(struct ether_header) - sizeof(struct ip);
	/* check if checksum is correct */
	if (pinfo.checksum && wrapsum(checksum(&icmp_pkt->icmphdr, icmplen, 0)) != 0) {
		fprintf(stderr, "ping request received, but ICMP checksum is incorrect!\n");
		return 1;
	}

	if (pinfo.mode == MODE_PING) {
		double elapsed_ms;

		clock_gettime(CLOCK_MONOTONIC, &end_ts);
		ts.tv_sec = end_ts.tv_sec - start_ts.tv_sec;
		ts.tv_nsec = end_ts.tv_nsec - start_ts.tv_nsec;
		if (ts.tv_nsec < 0 ) {
			--ts.tv_sec;
			ts.tv_nsec += 1000000000;
		}
		elapsed_ms = ts.tv_sec * 1000 + ((double)ts.tv_nsec / 1000000);
		printf("%lu bytes from %s: icmp_req=%u ttl=%u time=%.6lf ms\n",
			rx_pkt->len - sizeof(struct ether_header) - sizeof(struct iphdr),
			inet_ntoa(icmp_pkt->iphdr.ip_src),
			ntohs(icmp_pkt->icmphdr.un.echo.sequence),
			icmp_pkt->iphdr.ip_ttl,
			elapsed_ms);
	}
	else if (pinfo.mode == MODE_PONG) {
		struct in_addr ip_tmp;
		uint8_t mac_tmp[ETH_ALEN];
		struct lbufnet_tx_packet tx_pkt = {
			.data = rx_pkt->data,
			.len  = rx_pkt->len,
			.port_num = rx_pkt->port_num,
			.sync_flags = pinfo.sync_flags,
		};

		icmp_pkt->icmphdr.type = ICMP_ECHOREPLY;
		icmp_pkt->icmphdr.checksum = 0;
		/* swap ip and mac */
		ip_tmp = icmp_pkt->iphdr.ip_src;
		icmp_pkt->iphdr.ip_src = icmp_pkt->iphdr.ip_dst;
		icmp_pkt->iphdr.ip_dst = ip_tmp;
		memcpy(mac_tmp, icmp_pkt->ethhdr.ether_shost, ETH_ALEN);
		memcpy(icmp_pkt->ethhdr.ether_shost, icmp_pkt->ethhdr.ether_dhost, ETH_ALEN);
		memcpy(icmp_pkt->ethhdr.ether_dhost, mac_tmp, ETH_ALEN);
		if (pinfo.checksum)
			icmp_pkt->icmphdr.checksum = wrapsum(checksum(&icmp_pkt->icmphdr, icmplen, 0));

		lbufnet_output(&tx_pkt);
		clock_gettime(CLOCK_MONOTONIC, &ts);
		printf("[%lu.%09lu sec] pong for ping request %lu bytes from %s: icmp_req=%u\n",
			ts.tv_sec, ts.tv_nsec,
			rx_pkt->len - sizeof(struct ether_header) - sizeof(struct iphdr),
			inet_ntoa(icmp_pkt->iphdr.ip_src),
			ntohs(icmp_pkt->icmphdr.un.echo.sequence));
	}
	return 1;
}

int main(int argc, char *argv[])
{
	int opt;
	DEFINE_LBUFNET_CONF(conf);

	while ((opt = getopt(argc, argv, "hm:s:d:S:D:n:l:i:c:f:p")) != -1) {
		switch(opt) {
		case 'h':
			show_usage(argv[0]);
			return -1;
		case 'm':
			pinfo.mode = atoi(optarg);
			break;
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
			pinfo.datalen = atoi(optarg);
			if (pinfo.datalen > MAX_PAYLOAD_SIZE) {
				fprintf(stderr, "datalen cannot exceed %d\n", MAX_PAYLOAD_SIZE);
				return -1;
			}
			break;
		case 'i':
			pinfo.interval_us = (uint32_t)(atof(optarg) * 1000000);
			break;
		case 'c':
			pinfo.checksum = atoi(optarg);
			break;
		case 'f':
			pinfo.sync_flags = atoi(optarg);
			break;
		case 'p':
			conf.pci_direct_access = 1;
			break;
		}
	}
	conf.tx_lbuf_size = 4096;	/* minimum size */
	if (lbufnet_init(&conf)) {
		fprintf(stderr, "Error: failed to initialize lbufnet\n");
		return -1;
	}

	printf("lbuf_ping: mode=%s w/ checksum %s\n",
		pinfo.mode == MODE_PING ? "PING" : "PONG",
		pinfo.checksum ? "enabled" : "disabled");
	if (pinfo.mode == MODE_PING)
		printf("\tsrc=%s(%s) -> dst=%s(%s)\n",
			pinfo.src_ip, pinfo.src_mac, pinfo.dst_ip, pinfo.dst_mac);
	printf("\tlbufnet: sync_flags=%d(%s) pci_access=%s\n",
		pinfo.sync_flags, lbufnet_sync_flag_names[pinfo.sync_flags],
		conf.pci_direct_access ? "direct" : "ioctl");

	lbufnet_register_input_callback(input_handler);
	if (pinfo.mode == MODE_PING) {
		uint16_t sequence;
		struct lbufnet_tx_packet tx_pkt;

		if (!pinfo.src_ip || !pinfo.src_mac || !pinfo.dst_ip || !pinfo.dst_mac) {
			show_usage(argv[0]);
			lbufnet_exit();
			fprintf(stderr, "ping mode requires src and dst ip/mac addresses\n");
			return -1;
		}
		printf("PING %s (%s) from %s nf0: %u(%ld) bytes of data.\n",
			pinfo.dst_ip, pinfo.dst_ip, pinfo.src_ip, pinfo.datalen,
			pinfo.datalen + sizeof(struct icmphdr) + sizeof(struct iphdr));

		init_packet(&pinfo);
		tx_pkt.data = &pinfo.pkt_data;
		tx_pkt.len = pinfo.len;
		tx_pkt.port_num = 0;	/* use port 0 by default */
		tx_pkt.sync_flags = pinfo.sync_flags;
		sequence = 1;
		do {
			pinfo.pkt_data.icmphdr.un.echo.sequence = htons(sequence);
			if (pinfo.checksum)
				pinfo.pkt_data.icmphdr.checksum = wrapsum(base_sum + sequence);
			clock_gettime(CLOCK_MONOTONIC, &start_ts);
			lbufnet_output(&tx_pkt);		/* send ping */
			lbufnet_input(1, pinfo.sync_flags);	/* wait pong */
			usleep(pinfo.interval_us);
			sequence++;
		} while(pinfo.count == 0 || sequence <= pinfo.count);
	}
	else if (pinfo.mode == MODE_PONG) {
		printf("PONG waits PING...\n");
		lbufnet_input(LBUFNET_INPUT_FOREVER, pinfo.sync_flags);
	}

	return 0;
}
