/*
 * arp.h
 *
 *  Created on: May 11, 2018
 *      Author: cicerali
 */

#ifndef ARP_H_
#define ARP_H_

#include <nt_packet.h>
#include <nt_ipv4.h>
#include <rte_arp.h>

/**
 * Arp packet input point
 *
 */
int nt_arp_input(struct rte_mbuf *arp_packet, struct arp_hdr *arp_hdr);

/**
 * Prints arp header
 */
void nt_print_arp_hdr(struct arp_hdr *arp_hdr);

/**
 * Process arp request message
 * and send back arp replay
 * Also save arp entry for sender side
 */
int nt_process_arp_request(struct rte_mbuf *arp_packet, struct arp_hdr *arp_hdr);

/**
 * Process arp reply message
 * and also save arp entry
 */
int nt_process_arp_reply(struct rte_mbuf *arp_packet, struct arp_hdr *arp_hdr);

/**
 * Send out arp packet
 * packet should contain output port id
 */
int nt_arp_output(struct rte_mbuf *arp_packet, struct arp_hdr *arp_hdr,
		struct ether_addr *d_addr);

/**
 * Process arp queue which contains
 * ip packets for waiting arp resolution
 * After arp resolution arp queue will processed
 */
int nt_process_arp_queue(struct arp_table_entry *entry);

/**
 * Makes an arp request for target ip address
 */
int nt_make_arp_request(uint16_t port, uint32_t target_ip);

/**
 * Finds arp table entry for requested ipv4 address
 */
int nt_arp_table_lookup(uint32_t lookup_ip, struct arp_table_entry **entry);

/**
 * Adds new arp entry to arp table
 */
int nt_arp_table_add(uint32_t lookup_ip, struct arp_table_entry **entry);

#endif /* ARP_H_ */
