/*
 * nt_socket.c
 *
 *  Created on: Jun 19, 2018
 *      Author: cicerali
 */

#include "nt_socket.h"

/*
 * ring name should be like NT_'SOCKET_ID'_REVC and NT_'SOCKET_ID'_SEND
 * mempool name should be like MBUF_POOL_DIRECT
 *
 */

struct rte_mempool *message_pool;

//do first
int nt_client_init()
{
	int rc = -1;
	nt_main();
	rc = nt_create_client_socket();

	return rc;
}

struct nt_socket* nt_socket(int family, int type, int protocol)
{
	struct nt_socket* sock = NULL;
	if (family != AF_INET)
	{
		printf( __AT__"Only INET sockets supported\n");
		goto out;
	}

	if (type == SOCK_DGRAM && protocol == IPPROTO_UDP)
	{
		printf( __AT__"Creating UDP socket\n");
	}
	else if (type == SOCK_STREAM && protocol == IPPROTO_TCP)
	{
		printf( __AT__"Creating TCP socket\n");
	}
	else
	{
		printf( __AT__"Unsupported socket type or protocol\n");
		goto out;
	}

	//create unique socket id
	sock = (struct nt_socket*) rte_zmalloc("SOCKET", sizeof(struct nt_socket),
			0);
	sock->family = family;
	sock->protocol = protocol;
	sock->type = type;
	if (protocol == IPPROTO_UDP)
	{
		sock->funcs.bind = nt_bind;
		sock->funcs.sendto = nt_udp_sendto;
		sock->funcs.recvfrom = nt_udp_recvfrom;
	}

	out:

	return sock;
}

int nt_client_socket;
struct sockaddr_un remote;

int nt_create_client_socket()
{
	nt_client_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (nt_client_socket == -1)
	{
		printf( __AT__"SOCKET ERROR = %d\n", errno);
		return -1;
	}
	struct sockaddr_un client_sockaddr;
	memset(&client_sockaddr, 0, sizeof(struct sockaddr_un));
	client_sockaddr.sun_family = AF_UNIX;
	int len = sizeof(client_sockaddr);
	sprintf(client_sockaddr.sun_path, "client.%d.sock", getpid());
	printf( __AT__"client sock addr = %s\n", client_sockaddr.sun_path);
	int rc = bind(nt_client_socket, (struct sockaddr *) &client_sockaddr, len);
	if (rc == -1)
	{
		close(nt_client_socket);
		printf( __AT__"BIND ERROR = %d\n", errno);
		return -1;
	}
	remote.sun_family = AF_UNIX;
	strcpy(remote.sun_path, SERVER_PATH);
	return nt_client_socket;
}

int nt_send_dpdk_proc(void * buf, int len)
{

	int rc = sendto(nt_client_socket, buf, len, 0, (struct sockaddr *) &remote,
			sizeof(remote));
	if (rc == -1)
	{
		printf( __AT__"SENDTO ERROR = %d\n", errno);
		return -1;
	}
	return rc;
}

int nt_recv_dpdk_proc(void * buf, int len)
{

	int rc = recv(nt_client_socket, buf, len, 0);
	if (rc == -1)
	{
		printf( __AT__"RECV ERROR = %d", errno);
	}
	return rc;
}

int nt_bind(struct nt_socket* socket, struct sockaddr* my_addr, int addrlen)
{
	int err = -1;
	if (socket->addr.sin_port)
	{
		printf( __AT__"Socket already binded!\n");
		goto out;
	}
	socket->addr = *(struct sockaddr_in *) my_addr;

	// send a message to main process
	// main process will create socket rings and send back an ack
	// after that we can use this rings for communication
	struct nt_sock_msg msg;
	memset(&msg, 0, sizeof(struct nt_sock_msg));
	msg.type = BIND_SOCKET;
	msg.bnd_socket.bind_addr = *(struct sockaddr_in*) my_addr;

	rte_hexdump(stdout, "SOCKET0", (char *) &msg.bnd_socket.bind_addr,
			sizeof(struct sockaddr_in));
	int rc = nt_send_dpdk_proc(&msg, sizeof(msg));
	err = (rc >= 0) ? 0 : -1;
	if (err == 0)
	{
		rc = nt_recv_dpdk_proc(&msg, sizeof(msg));
		if (rc < 0)
		{
			err = -1;
			goto out;
		}
		else
		{
			if (msg.type == BIND_SOCKET_ACK
					&& msg.bnd_socket_ack.ret_code == SUCCESS)
			{
				printf( __AT__"Bind success socket id %d\n",
						msg.bnd_socket_ack.id);
				socket->recv_ring = msg.bnd_socket_ack.recv_ring;
				socket->send_ring = msg.bnd_socket_ack.send_ring;
				err = 0;
				socket->count_cv = msg.bnd_socket_ack.count_cv;
				socket->count_mutex = msg.bnd_socket_ack.count_mutex;
				socket->mem_pool = msg.bnd_socket_ack.mem_pool;
			}
			else
			{
				err = -1;
				printf( __AT__"nt_stack returns ERROR!!!\n");
				goto out;
			}
		}
	}

	out: return err;
}

int nt_close(struct nt_socket* socket)
{
	int err = -1;
	if (socket != NULL)
	{
		struct nt_sock_msg msg;
		memset(&msg, 0, sizeof(struct nt_sock_msg_old));
		msg.type = CLOSE_SOCKET;
		msg.cls_socket.id = socket->id;
		int rc = nt_send_dpdk_proc(&msg, sizeof(msg));
		err = (rc >= 0) ? 0 : -1;
		if (err == 0)
		{
			rc = nt_recv_dpdk_proc(&msg, sizeof(msg));
			if (rc < 0)
			{
				err = -1;
				goto out;
			}
			if (msg.type == CLOSE_SOCKET_ACK
					&& msg.cls_socket_ack.ret_code == SUCCESS)
			{
				err = 0;
				socket->mem_pool = NULL;
				socket->recv_ring = NULL;
				socket->send_ring = NULL;
				printf( __AT__"nt_stack returns SUCCESS!!!\n");
			}
			else
			{
				err = -1;
				printf( __AT__"nt_stack returns ERROR!!!\n");
				goto out;
			}

		}

	}
	out: return err;
}

int nt_sendto(struct nt_socket* socket, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen)
{
	int err = -1;
	if (socket->protocol == IPPROTO_UDP)
	{
		err = socket->funcs.sendto(socket, buf, len, flags, dest_addr, addrlen);
	}
	else
	{
		printf( __AT__"Protocol not supported yet!\n");
		goto out;
	}

	out:

	return err;
}

int nt_recvfrom(struct nt_socket* socket, void *buf, size_t len, int flags,
		struct sockaddr *src_addr, socklen_t *addrlen)
{
	int err = -1;
	if (socket->protocol == IPPROTO_UDP)
	{
		err = socket->funcs.recvfrom(socket, buf, len, flags, src_addr,
				addrlen);
	}
	else
	{
		printf( __AT__"Protocol not supported yet!\n");
		goto out;
	}

	out:

	return err;
}

int nt_udp_sendto(struct nt_socket* socket, const void *buf, size_t len,
		int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
	// alloc an mbuf from mempool
	// chekcsum calc and other cacls should be in dpdk main proc
	//TODO segmented packet
	struct rte_mbuf *packet = rte_pktmbuf_alloc(socket->mem_pool);
	if (packet == NULL)
	{
		printf( __AT__"Mbuf allocation failed!\n");
		return -1;
	}
	packet->data_len = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr)
			+ sizeof(struct udp_hdr) + len;
	packet->pkt_len = packet->data_len;
	struct udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(packet, struct udp_hdr *,
			sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
	udp_hdr->dgram_cksum = 0;
	udp_hdr->dgram_len = rte_cpu_to_be_16(len + sizeof(struct udp_hdr));
	udp_hdr->src_port = socket->addr.sin_port;
	udp_hdr->dst_port = ((struct sockaddr_in *) dest_addr)->sin_port;

	struct ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(packet,
			struct ipv4_hdr *, sizeof(struct ether_hdr));
	ipv4_hdr->dst_addr = ((struct sockaddr_in *) dest_addr)->sin_addr.s_addr;
	ipv4_hdr->src_addr = socket->addr.sin_addr.s_addr;
	ipv4_hdr->version_ihl = 0x45;
	ipv4_hdr->time_to_live = UINT8_MAX;
	ipv4_hdr->next_proto_id = IPPROTO_UDP;
	ipv4_hdr->total_length = rte_cpu_to_be_16(
			sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr) + len);
	struct ether_hdr *ether_hdr = rte_pktmbuf_mtod(packet, struct ether_hdr *);
	ether_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	rte_memcpy(udp_hdr + 1, buf, len);

	unsigned int space;
	int rc = rte_ring_enqueue_burst(socket->send_ring, (void**) &packet, 1,
			&space);
	if (rc == 0)
	{
		rte_pktmbuf_free(packet);
		printf( __AT__"Freeing packet!\n");
	}
	if (space < 50)
	{
		rte_delay_ms(1);
	}
	return (rc > 0) ? len : -105;
}

int nt_udp_recvfrom(struct nt_socket* socket, void *buf, size_t len, int flags,
		struct sockaddr *src_addr, socklen_t *addrlen)
{

	// wait an input from ring after return
	struct rte_mbuf *buffer;
	if (rte_ring_count(socket->recv_ring) < 1)
	{
		pthread_mutex_lock(socket->count_mutex);
		pthread_cond_wait(socket->count_cv, socket->count_mutex);
		pthread_mutex_unlock(socket->count_mutex);
	}

	if (rte_ring_dequeue(socket->recv_ring, (void**) &buffer) != 0)
	{
		//return error
		return -1;
	}
	struct sockaddr_in *addr = (struct sockaddr_in *) src_addr;
	struct ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(buffer,
			struct ipv4_hdr *, sizeof(struct ether_hdr));
	addr->sin_addr.s_addr = ipv4_hdr->src_addr;
	struct udp_hdr *udp_hdr = (struct udp_hdr *) (ipv4_hdr + 1);
	addr->sin_port = udp_hdr->src_port;
	int data_len = rte_be_to_cpu_16(ipv4_hdr->total_length)
			- sizeof(struct ipv4_hdr) - sizeof(struct udp_hdr);
	void *data_ref = udp_hdr + 1;
	if (len < data_len)
	{
		return -1; //maybe set errno
	}
	rte_memcpy(buf, data_ref, data_len);
	rte_pktmbuf_free(buffer);
	return data_len;
}

