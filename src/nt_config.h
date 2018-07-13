/*
 * config.h
 *
 *  Created on: May 9, 2018
 *      Author: cicerali
 */

#ifndef NT_CONFIG_H_
#define NT_CONFIG_H_

#define _XOPEN_SOURCE
#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include <sys/param.h>
#include <stdint.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>

#include "nt_common.h"

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_ip_frag.h>
#include <rte_lpm.h>

#define DEBUG 0
#define RX_RING_SIZE 512
#define TX_RING_SIZE 512
#define MBUF_CACHE_SIZE 128 // MAX 512
#define NUM_MBUFS ((1 <<  14) - 1) // 16383
#define BURST_SIZE 32 // burst size for rx an tx
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MAX_FLOW_NUM 0x1000 // for ip fragmentation
#define IP_FRAG_TBL_BUCKET_ENTRIES 16 /*should be power of 2 */
#define MAX_FLOW_TTL (3600 * MS_PER_S)
#define IPV4_MTU_DEFAULT ETHER_MTU
#define MAX_PACKET_FRAG RTE_LIBRTE_IP_FRAG_MAX_FRAG
#define MAX_LPM_RULES 1024
#define NT_ARP_TABLE_MAX_ENTRIES 1024
#define ARP_TABLE_EXPIRE_TIME 300

#define MAX_SOCKET_COUNT 1024

extern int number_of_lcores;
extern int number_of_ports;
extern uint16_t nb_rx_queues;
extern uint16_t nb_tx_queues;
extern uint32_t port_ipv4_addr;
extern struct ether_addr port_mac_addr;
extern struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

extern struct rte_mempool *socket_direct_pool; // single socket configuration
extern struct rte_mempool *socket_indirect_pool;

struct nt_socket_map
{
	pthread_mutex_t count_mutex;
	pthread_cond_t count_cv;
	struct sockaddr_in addr; //socket address
	struct rte_ring *send_ring; // socket send ring
	struct rte_ring *recv_ring; // socket rscv ring
	struct rte_mempool *mem_pool; // memory pool for mbuf allocation
};

struct nt_socket_table
{
	struct rte_hash *socket_hash_table;
	struct nt_socket_map *socket_entries; //arp entries
};

struct nt_port_statistics
{
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
}__rte_cache_aligned;

extern struct nt_port_statistics port_statistics[RTE_MAX_ETHPORTS];

struct lcore_rx_conf
{
	uint16_t port_id; // packet incoming port
	uint16_t queue_id; // packet incoming queue
	struct rte_ip_frag_tbl *frag_tbl; // ip fragmentation table
	struct rte_ip_frag_death_row death_row; // reassembly waste packets

};

struct lcore_tx_conf
{
	uint16_t queue_id; // tx queue id // how we know tx port?
	struct rte_mbuf *frag_buf[MAX_PACKET_FRAG];
	struct rte_mempool *direct_pool; // for ip fragmentation
	struct rte_mempool *indirect_pool; // for ip fragmentation
};

struct lcore_conf
{
	struct lcore_rx_conf rx; // rx conf
	struct lcore_tx_conf tx; //tx conf
};

extern struct lcore_conf lcore_conf[RTE_MAX_LCORE];

extern struct nt_arp_table arp_table;
extern struct nt_lpm_table lpm_table;
extern struct nt_socket_table socket_table;

struct pkt_queue
{
	struct rte_mbuf *pkt; // packet itself
	TAILQ_ENTRY(pkt_queue)
	queue; // for tail queue pointers
};

struct arp_table_entry
{
	struct ether_addr eth_addr; // ethernet adress
	uint32_t ip_addr;	// ip address
	uint32_t expire; // timeout(TTL)
	int state; // entry state
#define ARP_FREE 0
#define ARP_WAITING 1
#define ARP_RESOLVED 2
	TAILQ_HEAD(tailq_head, pkt_queue)
	qhead;
};

struct nt_arp_table
{
	struct rte_hash *arp_hash_table; // hash table for arp entries
	struct arp_table_entry *arp_entries; //arp entries
};

struct route_table_entry
{
	uint32_t ip; // destination
	uint8_t depth; // mask bits
	uint32_t gw; // gateway
	uint8_t flags; // isup isgw
#define GATEWAY_ENTRY 0x01
#define ROUTE_UP 0x02
	uint8_t if_out; // output interface
};

struct lpm_table_entry
{
	struct route_table_entry route; //route entry
	int32_t index; //entry index
};

struct nt_lpm_table
{
	struct rte_lpm *route_lookup_table; // lpm table for route entries
	struct rte_hash *route_hash_table; // hash table for route entries
	struct lpm_table_entry *route_entries; // route entries
};

/**
 * Create a named thread and set it's affinity
 */
int nt_create_thread(int cpu_core, void *(*start_routine)(void *), char *name,
		void *args);

/**
 * Create arp table for arp lookup
 */

int nt_create_arp_table(int socketid);

/**
 * Create route table for route lookup
 */
int nt_create_route_table(int socketid);

/**
 * Create socket table for socket lookup
 * This table will checks incoming ip packets
 * if they assign to an application
 */
int nt_create_socket_table(int socketid);

/**
 * Checks key(socket address) if in socket table
 */
int nt_socket_table_lookup(struct sockaddr_in *key,
		struct nt_socket_map **entry);

/**
 * Used for communication with client apps
 */
void* nt_internal_loop(void *param);

/**
 * Add some default routes for test purpose
 */
void add_some_routes();

/**
 * Signal handler function
 */
void nt_signal_handler(int signum);

/**
 * Prints port configuration
 */
void nt_print_port_config(uint16_t port_id);

/**
 * Initialize nt_stack(memory, ports, tables..)
 * arguments will pass to dpdk directly
 */
int nt_init(int argc, char *argv[]);

/**
 * Initialize ethernet port
 */
int nt_port_init(uint16_t port_id, uint16_t lcore_id,
		struct rte_mempool *mbuf_pool, struct rte_mempool *indirect_mbuf_pool);

#endif /* NT_CONFIG_H_ */
