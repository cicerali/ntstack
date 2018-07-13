/*
 * config.c
 *
 *  Created on: May 9, 2018
 *      Author: cicerali
 */
#include <nt_config.h>

int number_of_lcores;
int number_of_ports;
uint32_t port_ipv4_addr = 0x0a0a0a0f;
struct ether_addr port_mac_addr;

struct nt_arp_table arp_table;
struct nt_lpm_table lpm_table;
struct nt_socket_table socket_table;

struct lcore_conf lcore_conf[RTE_MAX_LCORE];
uint16_t nb_rx_queues = 1;
uint16_t nb_tx_queues = 1;

struct rte_mempool *socket_direct_pool;
struct rte_mempool *socket_indirect_pool;

struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];
struct nt_port_statistics port_statistics[RTE_MAX_ETHPORTS];

static struct rte_eth_conf port_conf =
{ .rxmode =
{ .split_hdr_size = 0, .ignore_offload_bitfield = 1, .offloads =
DEV_RX_OFFLOAD_CRC_STRIP, }, .txmode =
{ .mq_mode = ETH_MQ_TX_NONE, .offloads = (DEV_TX_OFFLOAD_IPV4_CKSUM
		| DEV_TX_OFFLOAD_MULTI_SEGS), }, };

void nt_signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM || signum == SIGSEGV)
	{
		rte_dump_stack();
		rte_exit(EXIT_FAILURE,
		__AT__"Signal %d received, preparing to exit...\n", signum);
	}
}

void nt_print_port_config(uint16_t port_id)
{
	struct rte_eth_dev_info _dev_info;
	struct rte_eth_dev_info *dev_info = &_dev_info;
	rte_eth_dev_info_get(port_id, dev_info);
	RTE_LOG(NOTICE, USER1, "dev_info->if_index: %s\n", dev_info->driver_name);
	RTE_LOG(NOTICE, USER1, "dev_info->if_index: %15d\n", dev_info->if_index);
	RTE_LOG(NOTICE, USER1, "dev_info->max_rx_pktlen:  %10d\n",
			dev_info->max_rx_pktlen);
	RTE_LOG(NOTICE, USER1, "dev_info->max_rx_queues:  %10d\n",
			dev_info->max_rx_queues);
	RTE_LOG(NOTICE, USER1, "dev_info->max_tx_queues:  %10d\n",
			dev_info->max_tx_queues);
	RTE_LOG(NOTICE, USER1, "dev_info->min_rx_bufsize: %10d\n",
			dev_info->min_rx_bufsize);
	RTE_LOG(NOTICE, USER1, "dev_info->nb_rx_queues:   %10d\n",
			dev_info->nb_rx_queues);
	RTE_LOG(NOTICE, USER1, "dev_info->nb_tx_queues:   %10d\n",
			dev_info->nb_tx_queues);
	RTE_LOG(NOTICE, USER1, "dev_info->speed_capa:     %10d\n",
			dev_info->speed_capa);
	RTE_LOG(NOTICE, USER1, "dev_info->txq_flags:      %#10lx\n",
			dev_info->tx_offload_capa);
	return;
}

int nt_init(int argc, char *argv[])
{
	int cnt_args_parsed;
	rte_log_set_global_level(RTE_LOG_DEBUG);
	/* Init runtime environment */
	cnt_args_parsed = rte_eal_init(argc, argv);
	if (cnt_args_parsed < 0)
	{
		rte_exit(EXIT_FAILURE, __AT__"rte_eal_init(): Failed!\n");
	}

	signal(SIGINT, nt_signal_handler);
	signal(SIGTERM, nt_signal_handler);
	signal(SIGSEGV, nt_signal_handler);

	number_of_ports = rte_eth_dev_count();
	number_of_lcores = rte_lcore_count();
	rte_eth_macaddr_get(0, &port_mac_addr); // set it port based

	RTE_LOG(NOTICE, USER1, __AT__"Number of NIC port(s): %i\n",
			number_of_ports);
	RTE_LOG(NOTICE, USER1, __AT__"Number of logical core(s): %i\n",
			number_of_lcores);
	char buf[ETHER_ADDR_FMT_SIZE];
	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, &port_mac_addr);
	RTE_LOG(NOTICE, USER1, __AT__"Main port mac address: %s\n", buf);
	if (number_of_ports == 0)
	{
		rte_exit(EXIT_FAILURE, __AT__"No available NIC ports!\n");
	}
	else if (number_of_lcores == 0)
	{
		rte_exit(EXIT_FAILURE, __AT__"No available logical core!\n");
	}
	else if (number_of_lcores <= number_of_ports)
	{
		rte_exit(EXIT_FAILURE,
				__AT__"Number of logical core must be greater than number of NIC ports!\n");
	}

	int socket_id = rte_socket_id();
	RTE_LOG(NOTICE, USER1, __AT__"Socket id = %d\n", socket_id);

	RTE_LOG(NOTICE, USER1, __AT__"rte_pktmbuf_pool_create for direct pool\n");
	socket_direct_pool = rte_pktmbuf_pool_create(MBUF_POOL_DIRECT,
	NUM_MBUFS, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
	if (socket_direct_pool == NULL)
	{
		rte_exit(EXIT_FAILURE,
		__AT__"direct mbuf_pool create failed, rte_errno = %d\n",
		rte_errno);
	}

	RTE_LOG(NOTICE, USER1, __AT__"rte_pktmbuf_pool_create for indirect pool\n");
	socket_indirect_pool = rte_pktmbuf_pool_create(MBUF_POOL_INDIRECT,
	NUM_MBUFS, 32, 0, 0, socket_id);
	if (socket_indirect_pool == NULL)
	{
		rte_exit(EXIT_FAILURE,
		__AT__"indirect mbuf_pool create failed, rte_errno = %d\n",
		rte_errno);
	}

	for (uint16_t i = 0, j = rte_get_next_lcore(rte_get_master_lcore(), true,
	true); i < number_of_ports; i++)
	{
		nt_print_port_config(i);
		if (nt_port_init(i, j, socket_direct_pool, socket_indirect_pool) != 0)
		{
			rte_exit(EXIT_FAILURE,
			__AT__"nt_port_init failed, rte_errno = %d\n",
			rte_errno);
		}

	}

	if (nt_create_arp_table(socket_id) != 0)
	{
		rte_exit(EXIT_FAILURE,
		__AT__"nt_create_arp_table failed, rte_errno = %d\n",
		rte_errno);
	}

	if (nt_create_route_table(socket_id) != 0)
	{
		rte_exit(EXIT_FAILURE,
		__AT__"nt_create_route_table failed, rte_errno = %d\n",
		rte_errno);
	}

	if (nt_create_socket_table(socket_id) != 0)
	{
		rte_exit(EXIT_FAILURE,
		__AT__"nt_create_socket_table failed, rte_errno = %d\n",
		rte_errno);
	}

	add_some_routes();
	return 0;
}

void add_some_routes()
{
	struct lpm_table_entry entry;
	entry.route.ip = IPv4(10, 10, 10, 0);
	entry.route.depth = 24;
	entry.route.gw = IPv4(0, 0, 0, 0);
	entry.route.flags = ROUTE_UP;
	entry.route.if_out = 0;
	entry.index = rte_hash_add_key(lpm_table.route_hash_table, &entry.route.ip);
	if (entry.index < 0)
	{
		return;
	}
	lpm_table.route_entries[entry.index] = entry;
	int ret = rte_lpm_add(lpm_table.route_lookup_table, entry.route.ip,
			entry.route.depth, entry.index);
	RTE_LOG(NOTICE, USER1, __AT__"add_some_routes, entry index: %d\n", ret);
}

int nt_port_init(uint16_t port_id, uint16_t lcore_id,
		struct rte_mempool *mbuf_pool, struct rte_mempool *indirect_mbuf_pool)
{

	struct rte_eth_conf local_port_conf;
	local_port_conf = port_conf;
	local_port_conf.rxmode.max_rx_pkt_len = ETHER_MAX_LEN;
	RTE_LOG(NOTICE, USER1, __AT__"rte_eth_dev_configure\n");
	int ret = rte_eth_dev_configure(port_id, nb_rx_queues, nb_tx_queues,
			&local_port_conf);
	if (ret != 0)
	{
		RTE_LOG(NOTICE, USER1, __AT__"rte_eth_dev_configure -> error %d\n",
				ret);
		return ret;
	}

	RTE_LOG(NOTICE, USER1, __AT__"rte_eth_rx_queue_setup\n");
	ret = rte_eth_rx_queue_setup(port_id, 0, RX_RING_SIZE,
			rte_eth_dev_socket_id(port_id),
			NULL, mbuf_pool);
	if (ret != 0)
	{
		RTE_LOG(NOTICE, USER1, __AT__"rte_eth_rx_queue_setup -> error %d\n",
				ret);
		return ret;
	}

	RTE_LOG(NOTICE, USER1, __AT__"rte_eth_tx_queue_setup\n");
	ret = rte_eth_tx_queue_setup(port_id, 0, TX_RING_SIZE,
			rte_eth_dev_socket_id(port_id),
			NULL);
	if (ret != 0)
	{
		RTE_LOG(NOTICE, USER1, __AT__"rte_eth_tx_queue_setup -> error %d\n",
				ret);
		return ret;
	}

	RTE_LOG(NOTICE, USER1, __AT__"rte_eth_promiscuous_enable\n");
	rte_eth_promiscuous_enable(port_id);

	//Initialize TX buffers
	tx_buffer[port_id] = rte_zmalloc_socket("tx_buffer",
			RTE_ETH_TX_BUFFER_SIZE(BURST_SIZE), 0,
			rte_eth_dev_socket_id(port_id));
	if (tx_buffer[port_id] == NULL)
	{
		RTE_LOG(NOTICE, USER1,
				__AT__"Cannot allocate buffer for tx on port %u\n", port_id);
	}
	rte_eth_tx_buffer_init(tx_buffer[port_id], BURST_SIZE);
	ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[port_id],
			rte_eth_tx_buffer_count_callback,
			&port_statistics[port_id].dropped);
	if (ret < 0)
	{
		RTE_LOG(NOTICE, USER1,
				__AT__"Cannot set error callback for tx buffer on port %u\n",
				port_id);
	}

	RTE_LOG(NOTICE, USER1, __AT__"rte_eth_dev_start\n");
	ret = rte_eth_dev_start(port_id);
	if (ret != 0)
	{
		RTE_LOG(NOTICE, USER1, __AT__"rte_eth_dev_start -> error %d\n", ret);
		return ret;
	}
	lcore_conf[lcore_id].rx.port_id = port_id;
	lcore_conf[lcore_id].rx.queue_id = 0;
	lcore_conf[lcore_id].tx.direct_pool = mbuf_pool;
	lcore_conf[lcore_id].tx.indirect_pool = indirect_mbuf_pool;
	lcore_conf[lcore_id].tx.queue_id = 0;

	uint64_t frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S
			* MAX_FLOW_TTL;
	int socket = rte_lcore_to_socket_id(lcore_id);
	lcore_conf[lcore_id].rx.frag_tbl = rte_ip_frag_table_create(
	MAX_FLOW_NUM, IP_FRAG_TBL_BUCKET_ENTRIES, MAX_FLOW_NUM, frag_cycles,
			socket);
	if (lcore_conf[lcore_id].rx.frag_tbl == NULL)
	{
		RTE_LOG(NOTICE, USER1, __AT__"rte_ip_frag_table_create -> error %d\n",
				ret);
		return ret;
	}

	return 0;
}

int nt_create_arp_table(int socketid)
{
	struct rte_hash_parameters arp_table_params;
	arp_table_params.name = "arp_table";
	arp_table_params.entries = NT_ARP_TABLE_MAX_ENTRIES;
	arp_table_params.extra_flag = 0;
	arp_table_params.socket_id = socketid;
	arp_table_params.reserved = 0;
	arp_table_params.key_len = 4;
	arp_table_params.hash_func_init_val = 0;
	arp_table_params.hash_func = rte_jhash;

	arp_table.arp_entries = (struct arp_table_entry*) rte_zmalloc(NULL,
			sizeof(struct arp_table_entry) * NT_ARP_TABLE_MAX_ENTRIES, 0);
	if (arp_table.arp_entries == NULL)
	{
		return -1;
	}

	for (int i = 0; i < NT_ARP_TABLE_MAX_ENTRIES; i++)
	{
		TAILQ_INIT(&arp_table.arp_entries[i].qhead);
	}

	arp_table.arp_hash_table = rte_hash_create(&arp_table_params);

	return (arp_table.arp_hash_table == NULL) ? -1 : 0;
}

int nt_create_route_table(int socketid)
{
	struct rte_lpm_config lpm_ipv4_config;
	lpm_ipv4_config.max_rules = MAX_LPM_RULES;
	lpm_ipv4_config.number_tbl8s = 256;
	lpm_ipv4_config.flags = 0;

	lpm_table.route_lookup_table = rte_lpm_create("lpm_table", socketid,
			&lpm_ipv4_config);
	if (lpm_table.route_lookup_table == NULL)
	{
		return -1;
	}

	lpm_table.route_entries = (struct lpm_table_entry*) rte_zmalloc(NULL,
			sizeof(struct lpm_table_entry) * MAX_LPM_RULES, 0);

	if (lpm_table.route_entries == NULL)
	{
		return -1;
	}

	struct rte_hash_parameters lpm_table_params;
	lpm_table_params.name = "lpm_table";
	lpm_table_params.entries = MAX_LPM_RULES;
	lpm_table_params.extra_flag = 0;
	lpm_table_params.socket_id = socketid;
	lpm_table_params.reserved = 0;
	lpm_table_params.key_len = 4;
	lpm_table_params.hash_func_init_val = 0;
	lpm_table_params.hash_func = rte_jhash;
	lpm_table.route_hash_table = rte_hash_create(&lpm_table_params);
	return (lpm_table.route_hash_table == NULL) ? -1 : 0;

}

int nt_create_socket_table(int socketid)
{
	socket_table.socket_entries = (struct nt_socket_map *) rte_zmalloc(NULL,
			sizeof(struct nt_socket_map) * MAX_SOCKET_COUNT, 0);

	if (socket_table.socket_entries == NULL)
	{
		return -1;
	}

	struct rte_hash_parameters socket_table_params;
	socket_table_params.name = "socket_table";
	socket_table_params.entries = MAX_SOCKET_COUNT;
	socket_table_params.extra_flag = 0;
	socket_table_params.socket_id = socketid;
	socket_table_params.reserved = 0;
	socket_table_params.key_len = sizeof(struct sockaddr_in);
	socket_table_params.hash_func_init_val = 0;
	socket_table_params.hash_func = rte_jhash;
	socket_table.socket_hash_table = rte_hash_create(&socket_table_params);

	return (socket_table.socket_hash_table == NULL) ? -1 : 0;
}

int nt_socket_table_lookup(struct sockaddr_in *addr,
		struct nt_socket_map **entry)
{
	int ret = rte_hash_lookup(socket_table.socket_hash_table, addr);

	if (ret < 0)
	{
		*entry = NULL;
	}
	else
	{
		*entry = &socket_table.socket_entries[ret];
	}
	return ret;
}

int nt_socket_table_add(struct sockaddr_in *key, struct sockaddr_in *entry)
{
	int ret = rte_hash_add_key(socket_table.socket_hash_table, key);
	if (ret < 0)
	{
		//TODO errors
	}
	else
	{
		RTE_LOG(ERR, USER1, __AT__"nt_socket_table_add  %d %d %d\n", ret,
				key->sin_addr.s_addr, key->sin_port);
		socket_table.socket_entries[ret].addr = *entry;

		// create socket recv and send rings
		// TODO ring size should be modifiable
		char ringname[100];
		sprintf(ringname, "NT_%d_RECV", ret);
		socket_table.socket_entries[ret].send_ring = rte_ring_create(ringname,
				2048, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (socket_table.socket_entries[ret].send_ring == NULL)
		{
			RTE_LOG(ERR, USER1, __AT__"rte_ring_create failed for %s\n",
					ringname);
			return -1;
		}
		RTE_LOG(NOTICE, USER1, __AT__"rte_ring_create success for %s\n",
				ringname);
		sprintf(ringname, "NT_%d_SEND", ret);
		socket_table.socket_entries[ret].recv_ring = rte_ring_create(ringname,
				2048, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (socket_table.socket_entries[ret].recv_ring == NULL)
		{
			RTE_LOG(ERR, USER1, __AT__"rte_ring_create failed for %s\n",
					ringname);
			return -1;
		}
		RTE_LOG(NOTICE, USER1, __AT__"rte_ring_create success for %s\n",
				ringname);

		pthread_mutex_init(&socket_table.socket_entries[ret].count_mutex, NULL);
		pthread_cond_init(&socket_table.socket_entries[ret].count_cv, NULL);
		socket_table.socket_entries[ret].mem_pool = socket_direct_pool;

	}

	return ret;
}

int nt_socket_table_del(struct sockaddr_in *key)
{
	int ret = rte_hash_del_key(socket_table.socket_hash_table, key);
	if (ret < 0)
	{
		RTE_LOG(NOTICE, USER1, __AT__"rte_hash_del_key error -> errnum %d\n",
				ret);
		return ret;
	}
	else
	{
		rte_ring_free(socket_table.socket_entries[ret].recv_ring);
		rte_ring_free(socket_table.socket_entries[ret].send_ring);
		pthread_cond_destroy(&socket_table.socket_entries[ret].count_cv);
		pthread_mutex_destroy(&socket_table.socket_entries[ret].count_mutex);
		RTE_LOG(NOTICE, USER1, __AT__"Socket config deleted\n");
	}
	return 0;
}

void* nt_internal_loop(void *param)
{
	RTE_LOG(NOTICE, USER1, __AT__"nt_internal_loop\n");
	int server_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (server_sock == -1)
	{
		rte_exit(EXIT_FAILURE, __AT__"SOCKET ERROR = %d", errno);
	}
	struct sockaddr_un server_sockaddr;
	char buf[256];
	memset(&server_sockaddr, 0, sizeof(struct sockaddr_un));
	server_sockaddr.sun_family = AF_UNIX;
	strcpy(server_sockaddr.sun_path, SERVER_PATH);
	int len = sizeof(server_sockaddr);
	unlink(SERVER_PATH);
	int rc = bind(server_sock, (struct sockaddr *) &server_sockaddr, len);
	if (rc == -1)
	{
		close(server_sock);
		rte_exit(EXIT_FAILURE, __AT__"BIND ERROR = %d", errno);
	}
	struct sockaddr_un peer_sock;
	int peer_sock_len = sizeof(struct sockaddr_un);
	;
	RTE_LOG(NOTICE, USER1, __AT__"waiting to recv...\n");

	while (true)
	{
		rc = recvfrom(server_sock, buf, 256, 0, (struct sockaddr *) &peer_sock,
				(socklen_t *) &peer_sock_len);
		RTE_LOG(NOTICE, USER1,
				__AT__"Message received from client address %d , %s\n",
				peer_sock.sun_family, peer_sock.sun_path);
		if (rc == -1)
		{
			RTE_LOG(ERR, USER1, __AT__"RECV ERROR = %d", errno);
		}
		else
		{
			struct nt_sock_msg *msg = (struct nt_sock_msg *) buf;
			RTE_LOG(NOTICE, USER1, __AT__"message type = %u\n", msg->type);

			if (msg->type == BIND_SOCKET)
			{
				struct nt_socket_map *socket;
				int ret = nt_socket_table_lookup(&msg->bnd_socket.bind_addr,
						&socket);
				if (ret >= 0)
				{
					//return error
					msg->type = BIND_SOCKET_ACK;
					msg->bnd_socket_ack.ret_code = FAILED;
					rc = sendto(server_sock, buf, 256, 0,
							(struct sockaddr *) &peer_sock,
							sizeof(struct sockaddr_un));
					RTE_LOG(NOTICE, USER1,
							__AT__"Socket already binded to index %d\n", ret);

				}
				else
				{
					rte_hexdump(stdout, "SOCKET BIND ADDRESS",
							(char *) &msg->bnd_socket.bind_addr,
							sizeof(struct sockaddr_in));
					ret = nt_socket_table_add(&msg->bnd_socket.bind_addr,
							&msg->bnd_socket.bind_addr);

					memset(buf, 256, 0); // reset buffer
					msg->type = BIND_SOCKET_ACK;
					msg->bnd_socket_ack.id = ret;

					if (ret >= 0)
					{
						msg->bnd_socket_ack.ret_code = SUCCESS;
						msg->bnd_socket_ack.count_cv =
								&socket_table.socket_entries[ret].count_cv;
						msg->bnd_socket_ack.count_mutex =
								&socket_table.socket_entries[ret].count_mutex;
						msg->bnd_socket_ack.recv_ring =
								socket_table.socket_entries[ret].send_ring;
						msg->bnd_socket_ack.send_ring =
								socket_table.socket_entries[ret].recv_ring;
						msg->bnd_socket_ack.mem_pool =
								socket_table.socket_entries[ret].mem_pool;
					}
					else
					{
						msg->bnd_socket_ack.ret_code = FAILED;
					}

					rc = sendto(server_sock, buf, 256, 0,
							(struct sockaddr *) &peer_sock,
							sizeof(struct sockaddr_un));
					RTE_LOG(NOTICE, USER1,
							__AT__"Message sended to client SUCCESS %d rc %d\n",
							ret, rc);
				}
			}
			else if (msg->type == CLOSE_SOCKET)
			{
				struct nt_socket_map *socket;
				if (msg->cls_socket.id < MAX_SOCKET_COUNT)
				{
					struct sockaddr_in *key =
							&socket_table.socket_entries[msg->cls_socket.id].addr;
					int ret = nt_socket_table_lookup(key, &socket);
					if (ret >= 0)
					{
						ret = nt_socket_table_del(key);

						memset(buf, 256, 0); //reset buffer
						msg->type = CLOSE_SOCKET_ACK;
						msg->cls_socket_ack.ret_code =
								(ret == 0) ? SUCCESS : FAILED;
						rc = sendto(server_sock, buf, 256, 0,
								(struct sockaddr *) &peer_sock,
								sizeof(struct sockaddr_un));
						RTE_LOG(NOTICE, USER1,
								__AT__"Message sended to client SUCCESS %d rc %d\n",
								ret, rc);
					}
					else
					{

						RTE_LOG(ERR, USER1, __AT__"Socket not found!!! %d\n",
								ret);
					}
				}
				else
				{
					RTE_LOG(ERR, USER1, __AT__"Socket not found!!!\n");
				}
			}

		}
	}
	RTE_LOG(NOTICE, USER1,
			__AT__"Waiting all slave core for finish their jobs , lcoreid = %d\n",
			rte_get_master_lcore());
	rte_eal_mp_wait_lcore();
}

int nt_create_thread(int cpu_core, void *(*start_routine)(void *), char *name,
		void *args)
{
	pthread_attr_t attr;
	int rc = -1;
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(cpu_core, &mask);
	rc = pthread_attr_init(&attr);
	if (rc != 0)
	{
		goto out;
	}
	rc = pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &mask);
	if (rc != 0)
	{
		goto out;
	}

	pthread_t tid;
	rc = pthread_create(&tid, &attr, start_routine, args);
	char t_name[100];
	sprintf(t_name, "%12s_%d", name, cpu_core);
	int ret = pthread_setname_np(tid, t_name);
	if (ret != 0)
	{
		RTE_LOG(ERR, USER1, __AT__"pthread_setname_np failed, errnum: %d\n",
				ret);
	}

	out: return rc;
}
