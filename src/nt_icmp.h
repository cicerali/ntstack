/*
 * nt_icmp.h
 *
 *  Created on: May 11, 2018
 *      Author: cicerali
 */

#ifndef NT_ICMP_H_
#define NT_ICMP_H_

#include <nt_packet.h>
#include <nt_ipv4.h>

#include <rte_icmp.h>

/**
 * Icmp packet input point
 */
int nt_icmp_input(struct rte_mbuf *icmp_packet, struct icmp_hdr *icmp_hdr);

/**
 * Send out icmp packet
 */
int nt_icmp_output(struct rte_mbuf *icmp_packet, struct icmp_hdr *icmp_hdr,
		uint16_t icmp_len);

/**
 * Prints icmp header
 */
void nt_print_icmp_hdr(struct icmp_hdr *icmp_hdr);

/**
 * Calculate icmp checksum
 * before call this function icmp header checksum field must be 0
 */
uint16_t nt_icmp_checksum_multi_seq(struct rte_mbuf *icmp_packet, void *icmp,
		int len);

/**
 * Process icmp echo request and send back icmp reply
 */
int nt_process_icmp_echo_request(struct rte_mbuf *icmp_packet,
		struct icmp_hdr *icmp_hdr);

#endif /* NT_ICMP_H_ */
