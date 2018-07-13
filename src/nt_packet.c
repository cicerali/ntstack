/*
 * nt_packet.c
 *
 *  Created on: May 10, 2018
 *      Author: cicerali
 */

#include <nt_packet.h>
#include <nt_ipv4.h>
#include <nt_arp.h>

void nt_io_loop(struct lcore_conf *qconf)
{
	uint64_t prev_tsc, diff_tsc, cur_tsc;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S
			* BURST_TX_DRAIN_US;
	prev_tsc = 0;
	while (true)
	{
		cur_tsc = rte_rdtsc();
		/* TX burst queue drain */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc))
		{
			rte_eth_tx_buffer_flush(qconf->rx.port_id, qconf->tx.queue_id,
					tx_buffer[qconf->rx.port_id]);
			prev_tsc = cur_tsc;
		}

		struct rte_mbuf *bufs[BURST_SIZE];
		uint16_t nb_rx = rte_eth_rx_burst(qconf->rx.port_id, qconf->rx.queue_id,
				bufs, BURST_SIZE);

		nt_packet_input(bufs, nb_rx, cur_tsc);

		// check packets from app to network
		// use ring for it
		// maybe one ring for per core
		// or ring per socket(created by an app)
		nt_socket_loop();

	}

}

int nt_socket_loop()
{
	// check open sockets and receive data form their queue
	// and process them
	struct sockaddr_in *sock;
	struct nt_socket_map *s_map;
	uint32_t next = 0;
	int rc;
	while (true)
	{
		rc = rte_hash_iterate(socket_table.socket_hash_table,
				(const void **) &sock, (void**) &s_map, &next);
		if (rc < 0)
		{
			break;
		}
		//RTE_LOG(NOTICE, USER1, "nt_socket_map: %d %d\n", socket_table.socket_entries[rc].addr.sin_addr.s_addr, socket_table.socket_entries[rc].addr.sin_port);
		if (socket_table.socket_entries[rc].recv_ring != NULL)
		{
			struct rte_mbuf *mbuf[32];
			struct ipv4_hdr *ipv4_hdr;
			struct udp_hdr *udp_hdr;
			rc = rte_ring_dequeue_burst(
					socket_table.socket_entries[rc].recv_ring, (void**) &mbuf,
					32, NULL);
			for (int i = 0; i < rc; i++)
			{
				ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf[i], struct ipv4_hdr *,
						sizeof(struct ether_hdr));
				ipv4_hdr->hdr_checksum = 0;
				if (ipv4_hdr->next_proto_id == IPPROTO_UDP)
				{
					udp_hdr = nt_ipv4_data_offset(ipv4_hdr, struct udp_hdr *);
					udp_hdr->dgram_cksum = 0;
					udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_hdr,
							udp_hdr);
				}
				nt_ipv4_output(mbuf[i], ipv4_hdr, NULL, NULL);
			}
			return 0;
		}
	}

	return 0;
}

int nt_packet_input(struct rte_mbuf **bufs, uint16_t nb_rx, uint64_t cur_tsc)
{
	for (int i = 0; i < nb_rx; i++)
	{
#if 0
		rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));
		rte_hexdump(stdout, "PACKET",
				rte_pktmbuf_mtod(bufs[i], char *, 0), bufs[i]->data_len);
#endif
		struct ether_hdr *eth_hdr = rte_pktmbuf_mtod_offset(bufs[i],
				struct ether_hdr *, 0);
#if DEBUG
		nt_print_ether_hdr(eth_hdr);
#endif

		uint16_t e_type = rte_be_to_cpu_16(eth_hdr->ether_type);
		if (e_type == ETHER_TYPE_IPv4)
		{
			struct ipv4_hdr *v4_hdr = rte_pktmbuf_mtod_offset(bufs[i],
					struct ipv4_hdr *, sizeof(struct ether_hdr));
			struct rte_mbuf *out = nt_ipv4_reassemble(bufs[i], v4_hdr, cur_tsc);
			if (out == NULL)
			{
				// no packet out, do nothing
				continue;
			}
			else if (out != bufs[i])
			{
				// ip packet reassembled, set new header
				v4_hdr = rte_pktmbuf_mtod_offset(out, struct ipv4_hdr *,
						sizeof(struct ether_hdr));
			}
			nt_ipv4_input(out, v4_hdr);
		}
		else if (e_type == ETHER_TYPE_IPv6)
		{
			RTE_LOG(NOTICE, USER1, __AT__"Ip version 6 not implemented!!!\n");
			rte_pktmbuf_free(bufs[i]);
		}
		else if (e_type == ETHER_TYPE_ARP)
		{
			struct arp_hdr *arp_hdr = rte_pktmbuf_mtod_offset(bufs[i],
					struct arp_hdr *, sizeof(struct ether_hdr));
			nt_arp_input(bufs[i], arp_hdr);
		}
		else
		{
			RTE_LOG(NOTICE, USER1, __AT__"Not implemented, %s : %#04x\n",
					(e_type > 1500) ? "e_type" : "e_size", e_type);
			rte_pktmbuf_free(bufs[i]);
		}
	}
	return nb_rx;
}

int nt_packet_output(uint16_t port_id, uint16_t queue_id,
		struct rte_mbuf *packet, struct ether_hdr *ether_hdr)
{
	uint32_t lcore_id = rte_lcore_id();
	struct lcore_conf *qconf = &lcore_conf[lcore_id];
	int32_t ret_len;

	ether_addr_copy(&port_mac_addr, &ether_hdr->s_addr);
	uint16_t e_type = rte_be_to_cpu_16(ether_hdr->ether_type);
	if (e_type == ETHER_TYPE_IPv4)
	{
		if (likely(
				IPV4_MTU_DEFAULT >= packet->pkt_len - sizeof(struct ether_hdr)))
		{
			rte_eth_tx_buffer(port_id, 0, tx_buffer[port_id], packet);
		}
		else
		{
			struct ether_hdr ether_hdr_orig = *ether_hdr;
			rte_pktmbuf_adj(packet, sizeof(struct ether_hdr));
			/* because of fragment functions assume that input mbuf data
			 points to the start of the IP header of the packet */
			ret_len = rte_ipv4_fragment_packet(packet, &qconf->tx.frag_buf[0],
			MAX_PACKET_FRAG, IPV4_MTU_DEFAULT, qconf->tx.direct_pool,
					qconf->tx.indirect_pool);
			rte_pktmbuf_free(packet);
			if ((unlikely(ret_len < 0)))
			{
				return ret_len;
			}
			struct ether_hdr *eth_hdr = NULL;
			for (int i = 0; i < ret_len; i++)
			{
				packet = qconf->tx.frag_buf[i];
				eth_hdr = (struct ether_hdr *) rte_pktmbuf_prepend(packet,
						sizeof(struct ether_hdr));
				if (eth_hdr == NULL)
				{
					rte_panic("No headroom in mbuf\n");
				}
				packet->l2_len = sizeof(struct ether_hdr);
				*eth_hdr = ether_hdr_orig;
				((struct ipv4_hdr *) (eth_hdr + 1))->hdr_checksum = 0;

				((struct ipv4_hdr *) (eth_hdr + 1))->hdr_checksum =
						rte_ipv4_cksum((struct ipv4_hdr *) (eth_hdr + 1));
				rte_eth_tx_buffer(port_id, 0, tx_buffer[port_id], packet);
			}
		}

	}
	else
	{
		rte_eth_tx_buffer(port_id, 0, tx_buffer[port_id], packet);
	}
	return 0;
}

void nt_print_ether_hdr(struct ether_hdr *eth_hdr)
{
	nt_print_ether_addr("ether_hdr->d_addr", &eth_hdr->d_addr);
	nt_print_ether_addr("ether_hdr->s_addr", &eth_hdr->s_addr);
	uint16_t type_or_size = rte_be_to_cpu_16(eth_hdr->ether_type);
	RTE_LOG(NOTICE, USER1, "%-30s:\t%#04x\n",
			(type_or_size > 1500) ?
					"ether_hdr->ether_type" : "ether_hdr->ether_size",
			type_or_size);
}

void nt_print_ether_addr(const char *tagname, struct ether_addr *ether_addr)
{
	char buf[ETHER_ADDR_FMT_SIZE];
	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, ether_addr);
	RTE_LOG(NOTICE, USER1, "%-30s:\t%s\n", tagname, buf);
}

void ether_addr_swap(struct ether_addr *ea_1, struct ether_addr *ea_2)
{
	struct ether_addr temp = *ea_1;
	*ea_1 = *ea_2;
	*ea_2 = temp;
}

int lcore_function(void *arg)
{
	unsigned lcore_id = rte_lcore_id();
	RTE_LOG(NOTICE, USER1, "rte_lcore_id: %d\n", lcore_id);
	struct lcore_conf *qconf = &lcore_conf[lcore_id];
	nt_io_loop(qconf);
	return 0;
}
