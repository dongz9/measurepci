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
#include "dpdk.h"

lcoreid_t master_lcore_id;

uint64_t port_ipackets[MAX_PORT], prev_port_ipackets[MAX_PORT];
uint64_t port_opackets[MAX_PORT], prev_port_opackets[MAX_PORT];

static int
echo_loop(void *arg)
{
	lcoreid_t lcore_id = rte_lcore_id();
	unsigned socket_id = rte_lcore_to_socket_id(lcore_id);
	portid_t port_id;
	queueid_t queue_id;
	struct rte_mbuf *pkts[DEFAULT_PKT_BURST];
	uint16_t num_pkts;
	uint64_t prev_tsc, cur_tsc, start_tsc;
	uint64_t tsc_hz = rte_get_tsc_hz();

	prev_tsc = start_tsc = rte_rdtsc();

	while (1) {
		cur_tsc = rte_rdtsc();

		if (cur_tsc - prev_tsc > tsc_hz) {
			if (lcore_id == master_lcore_id) {
				double ipackets = 0.0, opackets = 0.0;

				for (port_id = 0; port_id < num_ports; ++port_id) {
					if (!((enabled_port_mask >> port_id) & 1))
						continue;

					struct rte_eth_stats stats;
					/* rte_eth_stats_get(port_id, &stats); */
					ipackets += port_ipackets[port_id] - prev_port_ipackets[port_id];
					opackets += port_opackets[port_id] - prev_port_opackets[port_id];
					prev_port_ipackets[port_id] = port_ipackets[port_id];
					prev_port_opackets[port_id] = port_opackets[port_id];
				}

				printf(
					"%04llu ipackets=%.2lf, opackets=%.2lf\n",
					(cur_tsc - start_tsc) / tsc_hz,
					(double)ipackets / 1000000.0,
					(double)opackets / 1000000.0);
			}

			prev_tsc = cur_tsc;
		}

		unsigned i, queue;

		for (queue = 0; queue < lcore_data[lcore_id]->num_rx_queues; ++queue) {
			port_id = lcore_data[lcore_id]->rx_queue_list[queue].port_id;
			queue_id = lcore_data[lcore_id]->rx_queue_list[queue].queue_id;
			if (!((enabled_port_mask >> port_id) & 1))
				continue;

			num_pkts = recv_pkts(port_id, queue_id, pkts, DEFAULT_PKT_BURST);
			port_ipackets[port_id] += num_pkts;
			
			for (i = 0; i < num_pkts; ++i)
				send_pkt(port_id, pkts[i]);
			port_opackets[port_id] += num_pkts;
		}
	}
}

int
main(int argc, char **argv)
{
	dpdk_initialize(argc, argv);

	master_lcore_id = rte_get_master_lcore();
	rte_eal_mp_remote_launch(echo_loop, NULL, CALL_MASTER);
	rte_eal_mp_wait_lcore();

	return 0;
}
