/*
 * nt_common.h
 *
 *  Created on: Jun 27, 2018
 *      Author: cicerali
 */

#ifndef NT_COMMON_H_
#define NT_COMMON_H_

#include <netinet/in.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_hexdump.h>
#include <rte_cycles.h>

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define __AT__ __FILE__ ":" TOSTRING(__LINE__) "   "

#define SERVER_PATH "nt_dpdk.sock"
#define MBUF_POOL_DIRECT "MBUF_POOL_DIRECT"
#define MBUF_POOL_INDIRECT "MBUF_POOL_INDIRECT"

int nt_main();

struct nt_sock_msg_old
{
	uint8_t type;
	uint8_t r_code;
	uint32_t id;
	struct sockaddr_in addr;
};

enum SOCK_MSG_RET_CODE
{
	SUCCESS = 0, FAILED
};

enum SOCK_MSG_TYPE
{
	CREATE_SOCKET = 0,
	BIND_SOCKET,
	CLOSE_SOCKET,
	CREATE_SOCKET_ACK,
	BIND_SOCKET_ACK,
	CLOSE_SOCKET_ACK
};

struct nt_sock_msg
{
	uint8_t type;
	union
	{
		struct create_socket
		{
			int family;
			int type;
			int protocol;
		} crt_socket;
		struct bind_socket
		{
			struct sockaddr_in bind_addr;
		} bnd_socket;
		struct create_socket_ack
		{
			int ret_code;
			int id;
		} crt_socket_ack;
		struct bind_socket_ack
		{
			int ret_code;
			int id;
			pthread_mutex_t *count_mutex;
			pthread_cond_t *count_cv;
			struct rte_ring *send_ring;
			struct rte_ring *recv_ring;
			struct rte_mempool *mem_pool;
		} bnd_socket_ack;
		struct close_scoket
		{
			int id;
		} cls_socket;
		struct close_scoket_ack
		{
			int id;
			int ret_code;
		} cls_socket_ack;
	};
};

#endif /* NT_COMMON_H_ */
