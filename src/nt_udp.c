/*
 * nt_udp.c
 *
 *  Created on: Jun 19, 2018
 *      Author: cicerali
 */

#include <nt_udp.h>

int nt_udp_input(struct rte_mbuf *udp_packet, struct udp_hdr *udp_hdr)
{
	// search an udp socket
	// and send to data to this socket
	// use ring for this purpose
	struct ipv4_hdr *v4_hdr = rte_pktmbuf_mtod_offset(udp_packet,
			struct ipv4_hdr *, sizeof(struct ether_hdr));
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = v4_hdr->dst_addr;
	addr.sin_port = udp_hdr->dst_port;

	struct nt_socket_map *socket;
	int ret = nt_socket_table_lookup(&addr, &socket);
	if (ret >= 0)
	{
		//RTE_LOG(NOTICE, USER1, __AT__"nt_socket_table_lookup success, ret: %d\n", ret);
		if (rte_ring_enqueue(socket_table.socket_entries[ret].send_ring,
				(void*) udp_packet) == 0)
		{
			//RTE_LOG(NOTICE, USER1, __AT__"ring enque SUCEECSS\n");
			int count = rte_ring_count(
					socket_table.socket_entries[ret].send_ring);
			if (count == 1)
			{
				//send signal
				//RTE_LOG(NOTICE, USER1, __AT__"Ringe yeni mesaj geldi: %d\n", count);
				pthread_mutex_lock(
						&socket_table.socket_entries[ret].count_mutex);
				pthread_cond_signal(&socket_table.socket_entries[ret].count_cv);
				pthread_mutex_unlock(
						&socket_table.socket_entries[ret].count_mutex);

			}
		}
		else
		{
			rte_pktmbuf_free(udp_packet);
		}
	}
	else
	{
		// TODO return port unreachable message
		rte_pktmbuf_free(udp_packet);
	}
	return 0;
}

