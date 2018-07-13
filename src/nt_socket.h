/*
 * nt_socket.h
 *
 *  Created on: Jun 19, 2018
 *      Author: cicerali
 */

#ifndef NT_SOCKET_H_
#define NT_SOCKET_H_

#define _XOPEN_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <rte_udp.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include "nt_common.h"


struct nt_socket;

struct nt_socket_funcs
{
	//int (*socket)();
	int (*bind)(struct nt_socket* socket, struct sockaddr *my_addr, int addrlen);
	//int (*listen)(int sockfd, int backlog);
	//int (*connect)(int sockfd, struct sockaddr *serv_addr, int addrlen);
	//int (*accept)(int sockfd, struct sockaddr *cliaddr, socklen_t *addrlen);
	//int (*send)(int sockfd, const void *msg, int len, int flags);
	//int (*recv)(int sockfd, void *buf, int len, unsigned int flags);
	int (*sendto)(struct nt_socket* socket, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
	int (*recvfrom)(struct nt_socket* socket, void *buf, size_t len, int flags,
	        struct sockaddr *src_addr, socklen_t *addrlen);
	//int (*close)(int sockfd);
	//int (*select)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *errorfds,
	//		struct timeval *timeout);
	//int (*write)(int fildes, const void *buf, int nbyte);
	//int (*read)(int fildes, const void *buf, int nbyte);
};

struct nt_socket
{
	int id;
	unsigned int state;
	unsigned int family;
	unsigned int type;
	unsigned int protocol;
	struct sockaddr_in addr;
	struct nt_socket_funcs funcs;
	struct rte_ring *send_ring;
	struct rte_ring *recv_ring;
	struct rte_mempool *mem_pool;
	pthread_mutex_t *count_mutex;
	pthread_cond_t *count_cv;
};

int nt_client_init();

struct nt_socket* nt_socket(int family, int type, int protocol);
int nt_bind(struct nt_socket* socket, struct sockaddr* my_addr, int addrlen);
int nt_sendto(struct nt_socket* socket, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
int nt_udp_sendto(struct nt_socket* socket, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);

int nt_udp_recvfrom(struct nt_socket* socket, void *buf, size_t len, int flags,
        struct sockaddr *src_addr, socklen_t *addrlen);
int nt_recvfrom(struct nt_socket* socket, void *buf, size_t len, int flags,
		struct sockaddr *src_addr, socklen_t *addrlen);

int nt_close(struct nt_socket* socket);


int nt_create_client_socket();
int nt_send_dpdk_proc(void * buf, int len);

#endif /* NT_SOCKET_H_ */
