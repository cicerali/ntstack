/*
 * nt_ipv4.c
 *
 *  Created on: May 10, 2018
 *      Author: cicerali
 */
#include <nt_ipv4.h>

int nt_ipv4_input(struct rte_mbuf *ip_packet, struct ipv4_hdr *ipv4_hdr)
{
#if DEBUG
	nt_print_ipv4_hdr(ipv4_hdr);
#endif
	if (rte_be_to_cpu_32(ipv4_hdr->dst_addr) != port_ipv4_addr)
	{
		// not to us
		return -ENXIO;
	}

	if (ipv4_hdr->next_proto_id == IPPROTO_ICMP)
	{
		struct icmp_hdr *icmp_hdr = nt_ipv4_data_offset(ipv4_hdr,
				struct icmp_hdr *);
		nt_icmp_input(ip_packet, icmp_hdr);
	}
	else if (ipv4_hdr->next_proto_id == IPPROTO_UDP)
	{
		struct udp_hdr *udp_hdr = nt_ipv4_data_offset(ipv4_hdr,
				struct udp_hdr *);
		nt_udp_input(ip_packet, udp_hdr);
	}
	else if (ipv4_hdr->next_proto_id == IPPROTO_TCP)
	{
		rte_pktmbuf_free(ip_packet);
	}
	else
	{
		rte_pktmbuf_free(ip_packet);
	}
	return 0;
}

struct rte_mbuf * nt_ipv4_reassemble(struct rte_mbuf *in,
		struct ipv4_hdr *ipv4_hdr, uint64_t cur_tsc)
{
	struct rte_ip_frag_tbl *tbl;
	struct rte_ip_frag_death_row *dr;

	uint32_t lcore_id = rte_lcore_id();
	struct lcore_conf *qconf = &lcore_conf[lcore_id];
	if (rte_ipv4_frag_pkt_is_fragmented(ipv4_hdr))
	{
		// segmented packet in
		struct rte_mbuf *out;
		tbl = qconf->rx.frag_tbl;
		dr = &qconf->rx.death_row;
		in->l2_len = sizeof(struct ether_hdr);
		in->l3_len = (ipv4_hdr->version_ihl & 0x0F) << 2;
		out = rte_ipv4_frag_reassemble_packet(tbl, dr, in, cur_tsc, ipv4_hdr);
		if (out == NULL)
		{
			// no packet to send out
		}
		else if (out == in)
		{
			RTE_LOG(NOTICE, USER1,
					__AT__"rte_ipv4_frag_reassemble_packet -> error\n");
		}
		rte_ip_frag_free_death_row(dr, 3);
		return out;
	}
	else
	{
		return in;
	}
}

int nt_ipv4_output(struct rte_mbuf *ip_packet, struct ipv4_hdr *ipv4_hdr,
		uint32_t *s_addr, uint32_t *d_addr)
{
	if (likely(ip_packet != NULL))
	{
		ipv4_hdr->packet_id = 0;
		ipv4_hdr->time_to_live = UINT8_MAX;
		ipv4_hdr->hdr_checksum = 0;
		if (s_addr != NULL && d_addr != NULL)
		{
			ipv4_hdr->dst_addr = *d_addr;
			ipv4_hdr->src_addr = *s_addr;
		}
		ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);

		//first check route table and find route ip
		uint32_t next_hop_ip;
		uint32_t dest_ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
		int port = nt_find_next_ipv4_hop(dest_ip, &next_hop_ip);
		if (unlikely(port < 0))
		{
			return port;
		}
		ip_packet->port = port; // set packet output port
		struct arp_table_entry *arp_entry = NULL;
		int ret = nt_arp_table_lookup(next_hop_ip, &arp_entry);
		if (ret < 0)
		{

			ret = nt_arp_table_add(next_hop_ip, &arp_entry);
			nt_make_arp_request(port, next_hop_ip);
		}

		if (ret >= 0 && arp_entry->state == ARP_RESOLVED)
		{
			struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(ip_packet,
					struct ether_hdr *);
			ether_addr_copy(&port_mac_addr, &eth_hdr->s_addr);
			ether_addr_copy(&arp_entry->eth_addr, &eth_hdr->d_addr);
			return nt_packet_output(port, 0, ip_packet, eth_hdr);
		}
		else if (ret >= 0 && arp_entry->state == ARP_WAITING)
		{
			struct pkt_queue *tq = (struct pkt_queue *) rte_malloc(NULL,
					sizeof(struct pkt_queue), 0);
			tq->pkt = ip_packet;
			if (TAILQ_EMPTY(&arp_entry->qhead))
			{
				TAILQ_INSERT_HEAD(&arp_entry->qhead, tq, queue);
			}
			else
			{
				TAILQ_INSERT_TAIL(&arp_entry->qhead, tq, queue);
			}
		}
		else
		{
			return ret;
		}
	}
	return -EINVAL;
}

int nt_find_next_ipv4_hop(uint32_t dest, uint32_t *next_hop)
{
	uint32_t route_index;
	int port = -1;
	int ret = rte_lpm_lookup(lpm_table.route_lookup_table, dest, &route_index);

	if (ret == 0)
	{
		struct route_table_entry *r_entry =
				&lpm_table.route_entries[route_index].route;
		if (r_entry->gw == 0)
		{
			*next_hop = dest;
		}
		else
		{
			*next_hop = r_entry->gw;
		}
		port = r_entry->if_out;
	}
	return (ret == 0) ? port : ret;
}

void ipv4_addr_swap(uint32_t *ipv4a_1, uint32_t *ipv4a_2)
{
	uint32_t temp = *ipv4a_1;
	*ipv4a_1 = *ipv4a_2;
	*ipv4a_2 = temp;
}

void nt_print_ipv4_hdr(struct ipv4_hdr *ipv4_hdr)
{
	RTE_LOG(NOTICE, USER1, "%-30s:\t%d\n", "ipv4_hdr->version",
			ipv4_hdr->version_ihl >> 4);
	RTE_LOG(NOTICE, USER1, "%-30s:\t%d\n", "ipv4_hdr->header_length",
			(ipv4_hdr->version_ihl & 0x0F) << 2);
	RTE_LOG(NOTICE, USER1, "%-30s:\t%#02x\n", "ipv4_hdr->type_of_service",
			ipv4_hdr->type_of_service);
	RTE_LOG(NOTICE, USER1, "%-30s:\t%d\n", "ipv4_hdr->total_length",
			rte_be_to_cpu_16(ipv4_hdr->total_length));
	RTE_LOG(NOTICE, USER1, "%-30s:\t%#04x\n", "ipv4_hdr->packet_id",
			rte_be_to_cpu_16(ipv4_hdr->packet_id));
	RTE_LOG(NOTICE, USER1, "%-30s:\t%#04x\n", "ipv4_hdr->fragment_offset",
			ipv4_hdr->fragment_offset);
	RTE_LOG(NOTICE, USER1, "%-30s:\t%d\n", "ipv4_hdr->time_to_live",
			ipv4_hdr->time_to_live);
	RTE_LOG(NOTICE, USER1, "%-30s:\t%d\n", "ipv4_hdr->next_proto_id",
			ipv4_hdr->next_proto_id);
	RTE_LOG(NOTICE, USER1, "%-30s:\t%#04x\n", "ipv4_hdr->hdr_checksum",
			rte_be_to_cpu_16(ipv4_hdr->hdr_checksum));
	nt_print_ipv4_addr("ipv4_hdr->src_addr", &ipv4_hdr->src_addr);
	nt_print_ipv4_addr("ipv4_hdr->dst_addr", &ipv4_hdr->dst_addr);
	RTE_LOG(NOTICE, USER1, "%-30s:\t%s\n", "ipv4_hdr->options",
			(ipv4_hdr->version_ihl & 0x0F) > 5 ? "yes" : "no");
}

void nt_print_ipv4_addr(const char *tagname, uint32_t *addr)
{
	RTE_LOG(NOTICE, USER1, "%-30s:\t%d.%d.%d.%d\n", tagname,
			((uint8_t * )addr)[0], ((uint8_t * )addr)[1], ((uint8_t * )addr)[2],
			((uint8_t * )addr)[3]);
}
