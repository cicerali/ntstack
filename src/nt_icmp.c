/*
 * nt_icmp.c
 *
 *  Created on: May 11, 2018
 *      Author: cicerali
 */

#include <nt_icmp.h>

int nt_icmp_input(struct rte_mbuf *icmp_packet, struct icmp_hdr *icmp_hdr)
{

	int ret = 0;
#if DEBUG
	nt_print_icmp_hdr(icmp_hdr);
#endif

	switch (icmp_hdr->icmp_type)
	{
	case IP_ICMP_ECHO_REQUEST:
	{
		// maybe need checksum control
		ret = nt_process_icmp_echo_request(icmp_packet, icmp_hdr);
		break;
	}
	case IP_ICMP_ECHO_REPLY:
	{
		// maybe need to do something
		break;
	}
	default:
	{
		// maybe need to do something
		break;
	}
	}

	return ret;
}

int nt_icmp_output(struct rte_mbuf *icmp_packet, struct icmp_hdr *icmp_hdr,
		uint16_t icmp_len)
{
	if (likely(icmp_packet != NULL))
	{
		// no need to mbuf allocation, probably it is an echo reply, so we may use received mbuf
		struct ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(icmp_packet,
				struct ipv4_hdr *, sizeof(struct ether_hdr));
		if (icmp_len <= 0)
		{
			icmp_len = rte_be_to_cpu_16(ipv4_hdr->total_length)
					- ((ipv4_hdr->version_ihl & 0x0F) << 2);
		}
		icmp_hdr->icmp_type = IP_ICMP_ECHO_REPLY;
		icmp_hdr->icmp_cksum = 0;
		icmp_hdr->icmp_cksum = nt_icmp_checksum_multi_seq(icmp_packet, icmp_hdr,
				icmp_len);
		//just replace src and dest address
		uint32_t dst_addr = ipv4_hdr->src_addr;
		uint32_t src_addr = ipv4_hdr->dst_addr;
		return nt_ipv4_output(icmp_packet, ipv4_hdr, &src_addr, &dst_addr);
	}
	return -EINVAL;
}

int nt_process_icmp_echo_request(struct rte_mbuf *icmp_packet,
		struct icmp_hdr *icmp_hdr)
{
	icmp_hdr->icmp_type = IP_ICMP_ECHO_REPLY;
	return nt_icmp_output(icmp_packet, icmp_hdr, 0);
}

uint16_t nt_icmp_checksum_multi_seq(struct rte_mbuf *icmp_packet, void *icmp,
		int len)
{
	struct rte_mbuf *temp = icmp_packet;
	int total_skip = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr);
	int icmp_segment_len;
	if (temp != NULL)
	{
		icmp_segment_len = temp->data_len - total_skip;
	}

	assert(len >= 0);

	uint16_t *icmph = (uint16_t *) icmp;

	uint16_t ret = 0;
	uint32_t sum = 0;
	uint8_t odd_byte;

	while (len > 1)
	{
		sum += *icmph++;
		len -= 2;
		icmp_segment_len -= 2;

		if (icmp_segment_len == 0 && temp != NULL && temp->next != NULL)
		{
			temp = temp->next;
			icmph = rte_pktmbuf_mtod_offset(temp, uint16_t *, 0);
			icmp_segment_len = temp->data_len;
		}
	}
	if (len == 1)
	{
		odd_byte = *(uint8_t*) icmph;
		sum += odd_byte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	ret = (sum == 0xffff) ? sum : ~sum;
	return ret;
}

void nt_print_icmp_hdr(struct icmp_hdr *icmp_hdr)
{
	RTE_LOG(NOTICE, USER1, "%-30s:\t%d\n", "icmp_hdr->icmp_type",
			icmp_hdr->icmp_type);
	RTE_LOG(NOTICE, USER1, "%-30s:\t%d\n", "icmp_hdr->icmp_code",
			icmp_hdr->icmp_code);
	RTE_LOG(NOTICE, USER1, "%-30s:\t%#04x\n", "icmp_hdr->icmp_cksum",
			rte_be_to_cpu_16(icmp_hdr->icmp_cksum));
	if ((icmp_hdr->icmp_type == IP_ICMP_ECHO_REPLY)
			|| (icmp_hdr->icmp_type == IP_ICMP_ECHO_REQUEST))
	{
		RTE_LOG(NOTICE, USER1, "%-30s:\t%d\n", "icmp_hdr->icmp_ident",
				rte_be_to_cpu_16(icmp_hdr->icmp_ident));
		RTE_LOG(NOTICE, USER1, "%-30s:\t%d\n", "icmp_hdr->icmp_seq_nb",
				rte_be_to_cpu_16(icmp_hdr->icmp_seq_nb));
	}
}
