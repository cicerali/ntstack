/*
 * nt_arp.c
 *
 *  Created on: May 11, 2018
 *      Author: cicerali
 */

#include <nt_arp.h>

int nt_arp_input(struct rte_mbuf *arp_packet, struct arp_hdr *arp_hdr)
{

#if DEBUG
	nt_print_arp_hdr(arp_hdr);
#endif

	switch (rte_be_to_cpu_16(arp_hdr->arp_op))
	{
	case ARP_OP_REQUEST:
	{
		nt_process_arp_request(arp_packet, arp_hdr);
		break;
	}
	case ARP_OP_REPLY:
	{
		nt_process_arp_reply(arp_packet, arp_hdr);
		break;
	}
	default:
	{
		rte_pktmbuf_free(arp_packet);
		break;
	}
	}
	return 0;
}

int nt_process_arp_queue(struct arp_table_entry *entry)
{
	struct pkt_queue *tq = NULL;
	int ret = 0;
	if (TAILQ_EMPTY(&entry->qhead))
	{
		return 0;
	}

	TAILQ_FOREACH(tq, &entry->qhead, queue)
	{
		struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(tq->pkt,
				struct ether_hdr *);
		ether_addr_copy(&port_mac_addr, &eth_hdr->s_addr);
		ether_addr_copy(&entry->eth_addr, &eth_hdr->d_addr);
		(nt_packet_output(tq->pkt->port, 0, tq->pkt, eth_hdr) > 0) ?
				ret++ : ret;
	}
	while ((tq = TAILQ_FIRST(&entry->qhead)))
	{
		TAILQ_REMOVE(&entry->qhead, tq, queue);
		rte_free(tq);
	}
	return ret;
}

int nt_make_arp_request(uint16_t port, uint32_t target_ip)
{
	struct rte_mbuf *arp_packet = rte_pktmbuf_alloc(socket_direct_pool);
	if (arp_packet == NULL)
	{
		RTE_LOG(ERR, USER1, __AT__"Mbuf allocation failed!");
		return -ENOMEM;
	}

	arp_packet->data_len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
	arp_packet->pkt_len = arp_packet->data_len;
	arp_packet->port = port;
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(arp_packet,
			struct ether_hdr *);
	ether_addr_copy(&port_mac_addr, &eth_hdr->s_addr);
	eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_ARP);

	struct arp_hdr *arp_hdr;
	arp_hdr = (struct arp_hdr *) ((char *) eth_hdr + sizeof(struct ether_hdr));
	arp_hdr->arp_hrd = rte_cpu_to_be_16(ARP_HRD_ETHER);
	arp_hdr->arp_pro = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	arp_hdr->arp_hln = ETHER_ADDR_LEN;
	arp_hdr->arp_pln = sizeof(uint32_t);
	arp_hdr->arp_op = rte_cpu_to_be_16(ARP_OP_REQUEST);

	ether_addr_copy(&port_mac_addr, &arp_hdr->arp_data.arp_sha);
	arp_hdr->arp_data.arp_sip = rte_cpu_to_be_32(port_ipv4_addr);
	memset(&arp_hdr->arp_data.arp_tha, 0, ETHER_ADDR_LEN);
	arp_hdr->arp_data.arp_tip = rte_cpu_to_be_32(target_ip);

	return nt_arp_output(arp_packet, arp_hdr, NULL);
}

int nt_process_arp_reply(struct rte_mbuf *arp_packet, struct arp_hdr *arp_hdr)
{
	uint32_t source_ip = rte_be_to_cpu_32(arp_hdr->arp_data.arp_sip);

	struct arp_table_entry *entry = NULL;
	int ret = nt_arp_table_lookup(source_ip, &entry);
	if (ret >= 0)
	{
		// maybe set TTL(expire)
		entry->expire = 0;
		entry->ip_addr = source_ip;
		entry->state = ARP_RESOLVED;
		ether_addr_copy(&arp_hdr->arp_data.arp_sha, &entry->eth_addr);
		ret = nt_process_arp_queue(entry);

	}
	else
	{
		RTE_LOG(ERR, USER1,
				__AT__"Replay(arp) message not matched arp table!\n");
		return ret;
	}
	return (ret < 0) ? ret : 0;
}

int nt_process_arp_request(struct rte_mbuf *arp_packet, struct arp_hdr *arp_hdr)
{
	uint32_t lookup_ip = rte_be_to_cpu_32(arp_hdr->arp_data.arp_sip);

	struct arp_table_entry *entry = NULL;
	int ret = nt_arp_table_lookup(lookup_ip, &entry);
	if (ret >= 0)
	{
		// already in cache, maybe set TTL
		entry->expire = 0;
		entry->ip_addr = lookup_ip;
		entry->state = ARP_RESOLVED;
		ether_addr_copy(&arp_hdr->arp_data.arp_sha, &entry->eth_addr);
		nt_process_arp_queue(entry);
	}
	else if (-ret == ENOENT)
	{
		// not in cache, add it to arp cache
		ret = nt_arp_table_add(lookup_ip, &entry);
		if (ret >= 0)
		{
			entry->expire = 0;
			entry->ip_addr = lookup_ip;
			entry->state = ARP_RESOLVED;
			ether_addr_copy(&arp_hdr->arp_data.arp_sha, &entry->eth_addr);
			nt_process_arp_queue(entry);
		}
		else
		{
			RTE_LOG(ERR, USER1, __AT__"Arp entry saving failed, errno: %d\n",
					-ret);
		}
	}
	else
	{
		RTE_LOG(ERR, USER1, __AT__"Arp entry lookup failed, errno: %d\n", -ret);
	}

	arp_hdr->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
	ipv4_addr_swap(&arp_hdr->arp_data.arp_sip, &arp_hdr->arp_data.arp_tip);
	arp_hdr->arp_data.arp_sip = rte_cpu_to_be_32(port_ipv4_addr);
	ether_addr_swap(&arp_hdr->arp_data.arp_sha, &arp_hdr->arp_data.arp_tha);
	ether_addr_copy(&port_mac_addr, &arp_hdr->arp_data.arp_sha);
	return nt_arp_output(arp_packet, arp_hdr, &arp_hdr->arp_data.arp_tha);
}

int nt_arp_output(struct rte_mbuf *arp_packet, struct arp_hdr *arp_hdr,
		struct ether_addr *d_addr)
{
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod_offset(arp_packet,
			struct ether_hdr *, 0);
	if (d_addr != NULL)
	{
		ether_addr_copy(d_addr, &eth_hdr->d_addr);
	}
	else
	{
		memset(&eth_hdr->d_addr, 0xFF, ETHER_ADDR_LEN); // broadcast
	}
	return nt_packet_output(arp_packet->port, 0, arp_packet, eth_hdr);
}

int nt_arp_table_add(uint32_t lookup_ip, struct arp_table_entry **entry)
{
	int ret = rte_hash_add_key(arp_table.arp_hash_table, &lookup_ip);

	if (ret < 0)
	{
		*entry = NULL;
	}
	else
	{
		arp_table.arp_entries[ret].state = ARP_WAITING;
		arp_table.arp_entries[ret].ip_addr = lookup_ip;
		*entry = &arp_table.arp_entries[ret];
	}

	return ret;
}

int nt_arp_table_lookup(uint32_t lookup_ip, struct arp_table_entry **entry)
{
	int ret = rte_hash_lookup(arp_table.arp_hash_table, &lookup_ip);

	if (ret < 0)
	{
		*entry = NULL;
	}
	else
	{
		*entry = &arp_table.arp_entries[ret];
	}
	return ret;
}

void nt_print_arp_hdr(struct arp_hdr *arp_hdr)
{
	RTE_LOG(NOTICE, USER1, "%-30s:\t%d\n", "arp_hdr->hrd_type",
			rte_be_to_cpu_16(arp_hdr->arp_hrd));
	RTE_LOG(NOTICE, USER1, "%-30s:\t%#04x\n", "arp_hdr->prot_type",
			rte_be_to_cpu_16(arp_hdr->arp_pro));
	RTE_LOG(NOTICE, USER1, "%-30s:\t%d\n", "arp_hdr->hrd_size",
			arp_hdr->arp_hln);
	RTE_LOG(NOTICE, USER1, "%-30s:\t%d\n", "arp_hdr->prot_size",
			arp_hdr->arp_pln);
	RTE_LOG(NOTICE, USER1, "%-30s:\t%d\n", "arp_hdr->op_code",
			rte_be_to_cpu_16(arp_hdr->arp_op));
	nt_print_ether_addr("arp_hdr->arp_data.arp_sha",
			&arp_hdr->arp_data.arp_sha);
	nt_print_ipv4_addr("arp_hdr->arp_data.arp_sip", &arp_hdr->arp_data.arp_sip);
	nt_print_ether_addr("arp_hdr->arp_data.arp_tha",
			&arp_hdr->arp_data.arp_tha);
	nt_print_ipv4_addr("arp_hdr->arp_data.arp_tip", &arp_hdr->arp_data.arp_tip);
}
