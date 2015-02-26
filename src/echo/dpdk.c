#include "dpdk.h"
#include <unistd.h>
#include <getopt.h>

#define MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define MEMPOOL_CACHE_SIZE (256)

#define DEFAULT_RX_DESC (128)
#define DEFAULT_TX_DESC (512)

/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
#define RX_PTHRESH 8 /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 8 /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 4 /**< Default values of RX write-back threshold reg. */

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#define TX_PTHRESH 36 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH 0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH 0  /**< Default values of TX write-back threshold reg. */

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.max_rx_pkt_len = ETHER_MAX_LEN,
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 1, /**< IP checksum offload enabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_IP,
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

static const struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = RX_PTHRESH,
		.hthresh = RX_HTHRESH,
		.wthresh = RX_WTHRESH,
	},
	.rx_free_thresh = 32,
};

static struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = TX_PTHRESH,
		.hthresh = TX_HTHRESH,
		.wthresh = TX_WTHRESH,
	},
	.tx_free_thresh = 0, /* Use PMD default values */
	.tx_rs_thresh = 0, /* Use PMD default values */
	.txq_flags = (ETH_TXQ_FLAGS_NOMULTSEGS |
			ETH_TXQ_FLAGS_NOVLANOFFL |
			ETH_TXQ_FLAGS_NOXSUMSCTP |
			ETH_TXQ_FLAGS_NOXSUMUDP |
			ETH_TXQ_FLAGS_NOXSUMTCP)

};

portid_t num_ports;
port_data_t *port_data;
portid_t num_enabled_ports;
uint64_t enabled_port_mask;

lcoreid_t num_lcores;
lcore_data_t **lcore_data;

uint16_t tx_burst_size = 1;

static int promiscuous_on = 1;

static void
mbuf_pool_create(unsigned num_mbuf, unsigned socket_id)
{
	char pool_name[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *rte_mp;

	mbuf_poolname_build(socket_id, pool_name, sizeof(pool_name));

	rte_mp = rte_mempool_create(
		pool_name, num_mbuf, MBUF_SIZE,	MEMPOOL_CACHE_SIZE,
		sizeof(struct rte_pktmbuf_pool_private),
		rte_pktmbuf_pool_init, NULL,
		rte_pktmbuf_init, NULL,
		socket_id, 0);

	if (rte_mp == NULL)
		rte_exit(EXIT_FAILURE, "Creation of mbuf pool for socket %u failed\n", socket_id);
}

static void
init_config()
{
	lcoreid_t lcore_id;
	unsigned socket_id;
	unsigned num_mbuf_per_pool;

	lcore_data = rte_zmalloc(
		"dpdk_lib: lcore_data",
		sizeof(struct lcore_data *) * MAX_LCORE,
		CACHE_LINE_SIZE);
	if (lcore_data == NULL) {
		rte_exit(EXIT_FAILURE, "rte_zmalloc(%d (struct lcore_data *)) failed\n", num_lcores);
	}
	num_mbuf_per_pool = RTE_MAX(
		num_ports * num_lcores * DEFAULT_RX_DESC +
		num_ports * num_lcores * DEFAULT_PKT_BURST +
		num_ports * num_lcores * DEFAULT_TX_DESC +
		num_lcores * MEMPOOL_CACHE_SIZE,
		8192
		);
	for (lcore_id = 0; lcore_id < MAX_LCORE; lcore_id++) {
		if (!rte_lcore_is_enabled(lcore_id))
			continue;
		lcore_data[lcore_id] = rte_zmalloc(
			"dpdk_lib: struct lcore_data",
			sizeof(struct lcore_data),
			CACHE_LINE_SIZE);
		if (lcore_data[lcore_id] == NULL) {
			rte_exit(EXIT_FAILURE, "rte_zmalloc(struct lcore_data) failed\n");
		}
		socket_id = rte_lcore_to_socket_id(lcore_id);
		if (!mbuf_pool_find(socket_id))
			mbuf_pool_create(num_mbuf_per_pool, socket_id);
		lcore_data[lcore_id]->mbp = mbuf_pool_find(socket_id);
	}
}

static void
print_ethaddr(const char *name, const struct ether_addr *eth_addr)
{
   printf("%s%02X:%02X:%02X:%02X:%02X:%02X", name,
          eth_addr->addr_bytes[0],
          eth_addr->addr_bytes[1],
          eth_addr->addr_bytes[2],
          eth_addr->addr_bytes[3],
          eth_addr->addr_bytes[4],
          eth_addr->addr_bytes[5]);
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(portid_t num_ports)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("Checking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < num_ports; portid++) {
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
						(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == 0) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

static void
start_port()
{
	int ret;
	portid_t port_id;
	queueid_t rx_queue_id, tx_queue_id;
	lcoreid_t lcore_id;
	unsigned socket_id;

	for (port_id = 0; port_id < num_ports; ++port_id) {
		if (!((enabled_port_mask >> port_id) & 1))
			continue;
		
		ret = rte_eth_dev_configure(
			port_id,
			num_lcores,
			num_lcores,
			&port_conf);
		if (ret < 0)
			rte_exit(
				EXIT_FAILURE, "Cannot configure device: err=%d, port=%d\n",
				ret, port_id);

		rx_queue_id = tx_queue_id = 0;
		for (lcore_id = 0; lcore_id < MAX_LCORE; ++lcore_id) {
			if (rte_lcore_is_enabled(lcore_id) == 0)
				continue;
			socket_id = rte_lcore_to_socket_id(lcore_id);

			ret = rte_eth_rx_queue_setup(
				port_id,
				rx_queue_id,
				DEFAULT_RX_DESC,
				socket_id,
				&rx_conf,
				lcore_data[lcore_id]->mbp);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d, port=%d\n", ret, port_id);
			lcore_data[lcore_id]->rx_queue_list[lcore_data[lcore_id]->num_rx_queues].port_id = port_id;
			lcore_data[lcore_id]->rx_queue_list[lcore_data[lcore_id]->num_rx_queues].queue_id = rx_queue_id;
			++lcore_data[lcore_id]->num_rx_queues;
			rx_queue_id++;
			
			/* ret = rte_eth_rx_queue_setup( */
			/* 	port_id, */
			/* 	rx_queue_id, */
			/* 	DEFAULT_RX_DESC, */
			/* 	socket_id, */
			/* 	&rx_conf, */
			/* 	lcore_data[lcore_id]->mbp); */
			/* if (ret < 0) */
			/* 	rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d, port=%d\n", ret, port_id); */
			/* lcore_data[lcore_id]->rx_queue_list[lcore_data[lcore_id]->num_rx_queues].port_id = port_id; */
			/* lcore_data[lcore_id]->rx_queue_list[lcore_data[lcore_id]->num_rx_queues].queue_id = rx_queue_id; */
			/* ++lcore_data[lcore_id]->num_rx_queues; */
			/* rx_queue_id++; */

			ret = rte_eth_tx_queue_setup(
				port_id,
				tx_queue_id,
				DEFAULT_TX_DESC,
				socket_id,
				&tx_conf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, port=%d\n", ret, port_id);
			lcore_data[lcore_id]->tx_queue_id[port_id] = tx_queue_id;
			tx_queue_id++;
		}

		/* Start device */
		ret = rte_eth_dev_start(port_id);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n", ret, port_id);

		if (promiscuous_on)
			rte_eth_promiscuous_enable(port_id);

		rte_eth_stats_get(port_id, &port_data[port_id].stats);
	}

	check_all_ports_link_status(num_ports);
}

static uint64_t
parse_portmask(const char *s)
{
	char *end = NULL;
	unsigned long long pm;

	/* parse hexadecimal string */
	pm = strtoull(s, &end, 16);
	if ((s[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return (uint64_t)pm;
}

static int
parse_tx_burst_size(const char *s)
{
	char *end = NULL;
	unsigned long tx_burst_size;
	/* parse hexadecimal string */
	tx_burst_size = strtoul(s, &end, 10);
	if ((s[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (tx_burst_size == 0)
		return -1;

	return tx_burst_size;
}

#define CMD_LINE_OPT_TX_BURST_SIZE "tx-burst-size"

static void
parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	static struct option lgopts[] = {
		{CMD_LINE_OPT_TX_BURST_SIZE, 1, 0, 0},
		{NULL, 0, 0, 0}
	};

	argvopt = argv;
	
	while ((opt = getopt_long(argc, argvopt, "p:", lgopts, &option_index)) != EOF) {
		switch (opt) {
		case 'p':
			enabled_port_mask = parse_portmask(optarg);
			break;

		case 0:
			if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_TX_BURST_SIZE,
						 sizeof(CMD_LINE_OPT_TX_BURST_SIZE))) {
				/* printf("%s\n", optarg); */
				ret = parse_tx_burst_size(optarg);
				if ((ret > 0) && (ret <= DEFAULT_PKT_BURST)){
					tx_burst_size = ret;
				} else {
					printf("invalid TX burst size\n");
				}
			}
			break;
		}
	}
}

void
dpdk_initialize(int argc, char **argv)
{
	portid_t port_id;
	int ret;

	rte_set_log_level(RTE_LOG_NOTICE);

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

	num_ports = rte_eth_dev_count();
	port_data = rte_zmalloc(
		"dpdk_lib: port_data",
		sizeof(struct port_data) * num_ports,
		CACHE_LINE_SIZE);
	printf("Detected %u ports\n", num_ports);
	for (port_id = 0; port_id < num_ports; ++port_id) {
		rte_eth_macaddr_get(port_id, &port_data[port_id].ethaddr);
		printf("Port %d", port_id);
		print_ethaddr(" address", &port_data[port_id].ethaddr);
		printf("\n");
	}
	enabled_port_mask = ~0;
	
	num_lcores = rte_lcore_count();
	printf("Detected %u lcores\n", num_lcores);

	argc -= ret;
	argv += ret;
	parse_args(argc, argv);
	num_enabled_ports = __builtin_popcountll(enabled_port_mask);

	init_config();
	start_port();
}

void
send_pkt(portid_t port_id, struct rte_mbuf *pkt)
{
	lcore_data_t *ld = current_lcore_data();

	queueid_t queue_id = ld->tx_queue_id[port_id];
	mbuf_table_t *mbuf_table = &(ld->tx_mbufs[port_id]);
	uint16_t num_pkts = mbuf_table->num_pkts;

	mbuf_table->pkts[num_pkts++] = pkt;
	if (num_pkts >= tx_burst_size) {
		uint16_t n = rte_eth_tx_burst(
			port_id,
			queue_id,
			mbuf_table->pkts,
			num_pkts);
		if (unlikely(n < num_pkts)) {
			do {
				rte_pktmbuf_free(mbuf_table->pkts[n++]);
			} while (n < num_pkts);
		}
		num_pkts = 0;
	}
	mbuf_table->num_pkts = num_pkts;
}
	
