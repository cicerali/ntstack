/*
 * nt_ipv4.h
 *
 *  Created on: May 10, 2018
 *      Author: cicerali
 */

#ifndef NT_IPV4_H_
#define NT_IPV4_H_

#include <nt_packet.h>
#include <nt_icmp.h>
#include <nt_udp.h>
#include <nt_arp.h>

/**
 * A macro that points to an offset into the data in the ipv4 packet.
 *
 * The returned pointer is cast to type t
 *
 * @param p
 *   The ipv4 header.
 * @param t
 *   The type to cast the result into.
 */
#define nt_ipv4_data_offset(p, t)	\
	((t)((char *)(p) + (((p)->version_ihl & 0x0F) << 2)))

/**
 * 	Reassemble function for ipv4 packets
 * 	Returns reassembled packet or NULL pointer
 * 	if no packet comes out
 */
struct rte_mbuf * nt_ipv4_reassemble(struct rte_mbuf *in,
		struct ipv4_hdr *ipv4_hdr, uint64_t cur_tsc);

/**
 * ipv4 packet input point
 *
 */
int nt_ipv4_input(struct rte_mbuf *ip_packet, struct ipv4_hdr *ipv4_hdr);

/**
 * Finds next hop for ipv4 packets(routing)
 * If not found returns -(errnum)
 */
int nt_find_next_ipv4_hop(uint32_t dest, uint32_t *next_hop);

/**
 * ipv4 packet output point
 * If not success returns -(errnum)
 */
int nt_ipv4_output(struct rte_mbuf *ip_packet, struct ipv4_hdr *ipv4_hdr,
		uint32_t *s_addr, uint32_t *d_addr);

/**
 * Prints ipv4 header
 */
void nt_print_ipv4_hdr(struct ipv4_hdr *ipv4_hdr);

/**
 * Prints ipv4 address
 */
void nt_print_ipv4_addr(const char *tagname, uint32_t *addr);

/**
 * Swaps ipv4 addresses
 */
void ipv4_addr_swap(uint32_t *ipv4a_1, uint32_t *ipv4a_2);

#endif /* NT_IPV4_H_ */
