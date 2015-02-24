#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <rte_random.h>
#include "dpdk.h"

#define UDP_SRC_PORT 1024
#define UDP_DST_PORT 1024

#define IP_SRC_ADDR ((192U << 24) | (168 << 16) | (0 << 8) | 1)

#define IP_DEFTTL  64   /* from RFC 1340. */
#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)

#define MAX_ROUTE (1 << 25)

unsigned num_routes = 8000000;
uint32_t dst_addr_array[MAX_ROUTE];

#define ENABLE_FLOW_CONTROL

unsigned num_enabled_ports;
unsigned flow_control = 100;

static void
make_udp_pkt(portid_t port_id, struct rte_mbuf *pkt, unsigned ctx)
{
	uint16_t pkt_len = 60;
	
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *)((char *)eth_hdr + sizeof(struct ether_hdr));
	struct udp_hdr *udp_hdr = (struct udp_hdr *)((char *)ip_hdr + sizeof(struct ipv4_hdr));
	char *payload = (char *)((char *)udp_hdr + sizeof(struct udp_hdr));

	memset(payload, 0, pkt_len - sizeof(struct ether_hdr) - sizeof(struct ipv4_hdr) - sizeof(struct udp_hdr));

	eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	memcpy(&eth_hdr->s_addr, &port_data[port_id].ethaddr, sizeof(struct ether_addr));

	ip_hdr->src_addr = IP_SRC_ADDR;
	ip_hdr->dst_addr = dst_addr_array[ctx];
	ip_hdr->version_ihl = IP_VHL_DEF;
	ip_hdr->type_of_service = 0;
	ip_hdr->fragment_offset = 0;
	ip_hdr->time_to_live = IP_DEFTTL;
	ip_hdr->next_proto_id = IPPROTO_UDP;
	ip_hdr->packet_id = 0;
	ip_hdr->total_length = rte_cpu_to_be_16(pkt_len - sizeof(struct ether_hdr));

	udp_hdr->src_port = UDP_SRC_PORT;
	udp_hdr->dst_port = UDP_DST_PORT;
	udp_hdr->dgram_len = rte_cpu_to_be_16(pkt_len - sizeof(struct ether_hdr) - sizeof(struct ipv4_hdr));
	udp_hdr->dgram_cksum = 0;
	
	uint16_t *ptr16 = (uint16_t *)ip_hdr;
	uint32_t ip_cksum;
	ip_cksum = 0;
	ip_cksum += ptr16[0]; ip_cksum += ptr16[1];
	ip_cksum += ptr16[2]; ip_cksum += ptr16[3];
	ip_cksum += ptr16[4];
	ip_cksum += ptr16[6]; ip_cksum += ptr16[7];
	ip_cksum += ptr16[8]; ip_cksum += ptr16[9];

	/*
	 * reduce 32 bit checksum to 16 bits and complement it
	 */
	ip_cksum = ((ip_cksum & 0xFFFF0000) >> 16) + (ip_cksum & 0x0000FFFF);
	if (ip_cksum > 65535)
		ip_cksum -= 65535;
	ip_cksum = (~ip_cksum) & 0x00005555;
	if (ip_cksum == 0)
		ip_cksum = 0xFFFF;
	ip_hdr->hdr_checksum = (uint16_t)ip_cksum;

	pkt->pkt.data_len = pkt_len;
	pkt->pkt.next = NULL; /* last segment of packet */
	pkt->pkt.nb_segs = 1;
	pkt->pkt.pkt_len = pkt_len;
	pkt->ol_flags = 0;
}

lcoreid_t master_lcore_id;

static int
pktgen_loop(void *arg)
{
	lcoreid_t lcore_id = rte_lcore_id();
	unsigned socket_id = rte_lcore_to_socket_id(lcore_id);
	portid_t port_id;
	struct rte_mbuf *pkt;
	uint64_t cur_tsc, start_tsc, next_tsc;
	uint64_t tsc_hz = rte_get_tsc_hz();
	unsigned ctx[MAX_PORT];
#ifdef ENABLE_FLOW_CONTROL
	unsigned cap = num_enabled_ports * flow_control;
#endif

	start_tsc = rte_rdtsc();
	next_tsc = start_tsc + tsc_hz;

	for (port_id = 0; port_id < num_ports; ++port_id)
		ctx[port_id] = 0;

	while (1) {
		cur_tsc = rte_rdtsc();

		if (cur_tsc >= next_tsc) {
			if (lcore_id == master_lcore_id) {
				double thruput = 0.0;

				for (port_id = 0; port_id < num_ports; ++port_id) {
					if (!((enabled_port_mask >> port_id) & 1))
						continue;

					struct rte_eth_stats stats;
					rte_eth_stats_get(port_id, &stats);
					thruput += stats.opackets - port_data[port_id].stats.opackets;
					port_data[port_id].stats = stats;
				}

				printf(
					"%04llu thruput=%.2lf\n",
					(cur_tsc - start_tsc) / tsc_hz,
					((double)thruput) / 1000000.0);
			}

			next_tsc += tsc_hz;

#ifdef ENABLE_FLOW_CONTROL
			cap = num_enabled_ports * flow_control;
#endif
		}

		for (port_id = 0; port_id < num_ports; ++port_id) {
			if (!((enabled_port_mask >> port_id) & 1))
				continue;
			
#ifdef ENABLE_FLOW_CONTROL
			if (cap > 0)
				--cap;
			else
				break;
#endif
			pkt = alloc_pkt(lcore_data[lcore_id]->mbp);
			make_udp_pkt(port_id, pkt, ctx[port_id]);
			ctx[port_id] = (ctx[port_id] + 1) % num_routes;
			send_pkt(port_id, pkt);
		}		
	}
}

int
main(int argc, char **argv)
{
	portid_t portid;
	unsigned i, leading = 1;
	
	dpdk_initialize(argc, argv);

	rte_srand(0xdeadbeef);
	for (i = 0; i < num_routes; ++i) {
		/* uint32_t ip = (uint32_t)(rte_rand() & 0xffffffff); */
		uint32_t ip = i;
		dst_addr_array[i] = ip;
	}

	master_lcore_id = rte_get_master_lcore();
	printf("master_lcore_id=%d\n", master_lcore_id);

	printf("tx_burst_size=%d\n", tx_burst_size);
	printf("enabled_ports=");
	for (portid = 0; portid < num_ports; ++portid)
		if ((enabled_port_mask >> portid) & 1) {
			if (!leading)
				putchar(',');
			leading = 0;
			printf("%u", portid);
		}
	printf("\n");
	num_enabled_ports = __builtin_popcountll(enabled_port_mask);

	rte_eal_mp_remote_launch(pktgen_loop, NULL, CALL_MASTER);
	rte_eal_mp_wait_lcore();

	return 0;
}
