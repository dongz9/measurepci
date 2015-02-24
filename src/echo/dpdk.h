#ifndef __DPDK_LIB_H__
#define __DPDK_LIB_H__

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>

#define MAX_LCORE (RTE_MAX_LCORE)

#define MAX_SOCKET (4)

#define MAX_PORT (RTE_MAX_ETHPORTS)

typedef uint8_t  lcoreid_t;
typedef uint8_t  portid_t;
typedef uint16_t queueid_t;

#define DEFAULT_PKT_BURST (32)

struct port_data {
	struct ether_addr ethaddr;
	struct rte_eth_stats stats;
} __rte_cache_aligned;
typedef struct port_data port_data_t;

/*
 * Configuration of Ethernet ports
 */
extern portid_t num_ports;
extern port_data_t *port_data;
extern uint64_t enabled_port_mask;

struct lcore_rx_queue {
	uint8_t port_id;
	uint8_t queue_id;
} __rte_cache_aligned;
typedef struct lcore_rx_queue lcore_rx_queue_t;

struct mbuf_table {
	struct rte_mbuf *pkts[DEFAULT_PKT_BURST];
	uint16_t num_pkts;
} __rte_cache_aligned;
typedef struct mbuf_table mbuf_table_t;

struct lcore_data {
	struct rte_mempool *mbp;
	uint16_t num_rx_queues;
	lcore_rx_queue_t rx_queue_list[MAX_PORT];
	uint16_t tx_queue_id[MAX_PORT];
	mbuf_table_t tx_mbufs[MAX_PORT];
} __rte_cache_aligned;
typedef struct lcore_data lcore_data_t;

extern lcoreid_t num_lcores;
extern lcore_data_t **lcore_data;

extern uint16_t tx_burst_size;

static inline lcore_data_t *
current_lcore_data(void)
{
	return lcore_data[rte_lcore_id()];
}

static inline void
mbuf_poolname_build(unsigned int sock_id, char* mp_name, int name_size)
{
	snprintf(mp_name, name_size, "mbuf_pool_socket_%u", sock_id);
}

static inline struct rte_mempool *
mbuf_pool_find(unsigned int socket_id)
{
	char pool_name[RTE_MEMPOOL_NAMESIZE];

	mbuf_poolname_build(socket_id, pool_name, sizeof(pool_name));
	return (rte_mempool_lookup((const char *)pool_name));
}

static inline struct rte_mbuf *
alloc_pkt(struct rte_mempool *mp)
{
	struct rte_mbuf *m;

	m = __rte_mbuf_raw_alloc(mp);
	return (m);
}

static inline void
free_pkt(struct rte_mbuf *pkt)
{
	rte_pktmbuf_free(pkt);
}

void
dpdk_initialize();

void
send_pkt(portid_t port_id, struct rte_mbuf *pkt);

static inline uint16_t
recv_pkts(portid_t port_id, queueid_t queue_id, struct rte_mbuf **pkts, uint16_t num_pkts)
{
	uint16_t n = rte_eth_rx_burst(
		port_id,
		queue_id,
		pkts,
		num_pkts);
	return n;
}

#endif /* __DPDK_LIB_H__ */
