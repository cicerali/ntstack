/*
 * nt_udp.h
 *
 *  Created on: Jun 19, 2018
 *      Author: cicerali
 */

#ifndef NT_UDP_H_
#define NT_UDP_H_

#include <nt_packet.h>
#include <rte_udp.h>

/**
 * Udp packet input point
 */
int nt_udp_input(struct rte_mbuf *udp_packet, struct udp_hdr *udp_hdr);

#endif /* NT_UDP_H_ */
