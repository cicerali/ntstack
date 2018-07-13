/*
 * nt_packet.h
 *
 *  Created on: May 10, 2018
 *      Author: cicerali
 */

#ifndef NT_PACKET_H_
#define NT_PACKET_H_

#include <nt_config.h>

#include <stdbool.h>
#include <arpa/inet.h>
#include <assert.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_ip.h>

/**
 * Main loop for packet processing
 * packet input output point
 */
void nt_io_loop(struct lcore_conf *qconf);

/**
 * Packet input point
 */
int nt_packet_input(struct rte_mbuf **bufs, uint16_t nb_rx, uint64_t cur_tsc);

/**
 * Sends packets to out
 */
int nt_packet_output(uint16_t port_id, uint16_t queue_id,
		struct rte_mbuf *packet, struct ether_hdr *ether_hdr);

/**
 * Prints ethernet header
 */
void nt_print_ether_hdr(struct ether_hdr *eth_hdr);

/**
 * Prints ethernet address
 */
void nt_print_ether_addr(const char *tagname, struct ether_addr *ether_addr);

/**
 * Running on every packet processing  core
 * DPDK worker core function
 */
int lcore_function(void *arg);

/**
 * Checks apps sockets for outgoing packets
 * Receive packets from apps and sent them out
 */
int nt_socket_loop();

/**
 * Swaps ethernet addresses
 */
void ether_addr_swap(struct ether_addr *ea_1, struct ether_addr *ea_2);

#endif /* NT_PACKET_H_ */
