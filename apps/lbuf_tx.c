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
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "lbufnet.h"

#define UDPDEFPORT		50001
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
	uint32_t sync_flags;
	struct packet pkt_data;
};

struct packet_info pinfo = {
	.src_ip = "11.0.0.1",
	.dst_ip = "12.0.0.1",
	.src_mac = "00:00:00:00:00:00",
	.dst_mac = "ff:ff:ff:ff:ff:ff",
	.len = 60,
	.buflen = 128 << 10,	/* 128KB */
	.batchlen = 128 << 10,	/* 128KB */
	.count = 1,
	.sync_flags = SF_BLOCK,
};

static void show_usage(char *cmd)
{
	fprintf(stderr,
		"Usage: %s args\n"
		"\t-h: show this usage\n"
		"\t-s <source IP address>\n"
		"\t-d <destination IP address>\n"
		"\t-S <source MAC address>\n"
		"\t-D <destination MAC address>\n"
		"\t-n <# of packets>\n"
		"\t-l <packet length in byte>\n"
		"\t-r <tx buffer ring count (= tx lbuf count)>\n"
		"\t-b <tx lbuf size in byte>\n"
		"\t-B <tx batch size in byte>\n"
		"\t-f <sync flag: 0=non-block, 1=block, 2=busy-wait>\n"
		"\t-p: if specified, pci direct access w/o ioctl\n"
		"\t-P <# of ports: if > 1, tx on multiple ports in a round-robin manner>\n",
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

struct timeval start_tv, end_tv;
uint64_t tx_packets;
void show_stat(struct lbufnet_stat *s)
{
	struct timeval elapsed_tv;
	double elapsed_sec;
	double tx_gbits = tx_packets * pinfo.len * 8 * 1e-9;

	(void)s;
	gettimeofday(&end_tv, NULL);
	timersub(&end_tv, &start_tv, &elapsed_tv);
	elapsed_sec = elapsed_tv.tv_sec + ((double)elapsed_tv.tv_usec / 1000000);
	printf("Elapsed time = %.6lf sec\n", elapsed_sec);
	if (elapsed_sec > 0)
		printf("Throughput = %.2lf pps (%.6lf Gbps raw=%.6lf Gbps)\n",
			tx_packets / elapsed_sec,
			tx_gbits / elapsed_sec,
			/* add 24B = 20B framing(12B IFG + 8B Preemble) + 4B CRC */
			(tx_gbits + (24 * 8 * tx_packets * 1e-9)) / elapsed_sec);
}

int main(int argc, char *argv[])
{
	unsigned int batched_size;
	int opt;
	unsigned int nr_ports = 1;
	unsigned int port_num = 0;
	struct lbufnet_tx_packet pkt;
	DEFINE_LBUFNET_CONF(conf);

	while ((opt = getopt(argc, argv, "hs:d:S:D:n:l:b:B:r:P:f:p")) != -1) {
		switch(opt) {
		case 'h':
			show_usage(argv[0]);
			return -1;
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
		case 'r':
			conf.tx_lbuf_count = atoi(optarg);
			break;
		case 'b':
			pinfo.buflen = atoi(optarg);
			break;
		case 'B':
			pinfo.batchlen = atoi(optarg);
			break;
		case 'P':
			nr_ports = atoi(optarg);
			break;
		case 'f':
			pinfo.sync_flags = atoi(optarg);
			break;
		case 'p':
			conf.pci_direct_access = 1;
			break;
		}
	}
	if (pinfo.batchlen > pinfo.buflen)
		pinfo.batchlen = pinfo.buflen;

	conf.flags = TX_ON;	/* tx only */
	conf.tx_lbuf_size = pinfo.buflen;
	if (lbufnet_init(&conf)) {
		fprintf(stderr, "Error: failed to initialize lbufnet\n");
		return -1;
	}
	lbufnet_register_exit_callback(show_stat);

	printf("Packet transmission from src=%s:%u(%s) to dst=%s:%u(%s)\n",
		pinfo.src_ip, UDPDEFPORT, pinfo.src_mac,
		pinfo.dst_ip, UDPDEFPORT, pinfo.dst_mac);
	printf("\tcount=%lu length=%uB tx_lbuf_count=%u tx_lbuf_size=%uB batch_size=%uB\n",
		pinfo.count, pinfo.len, conf.tx_lbuf_count, conf.tx_lbuf_size, pinfo.batchlen);
	printf("\tlbufnet: sync_flags=%d(%s) pci_access=%s\n",
		pinfo.sync_flags, lbufnet_sync_flag_names[pinfo.sync_flags],
		conf.pci_direct_access ? "direct" : "ioctl");

	init_packet(&pinfo);

	pkt.data = &pinfo.pkt_data;
	pkt.len = pinfo.len;
	pkt.sync_flags = pinfo.sync_flags;
	gettimeofday(&start_tv, NULL);
	for (tx_packets = 0; tx_packets < pinfo.count; tx_packets++) {
		pkt.port_num = (port_num++) % nr_ports; 
		batched_size = lbufnet_write(&pkt);
		if (batched_size >= pinfo.batchlen)
			lbufnet_flush(pkt.sync_flags);
	}
	lbufnet_flush(pkt.sync_flags);
	lbufnet_exit();

	return 0;
}
