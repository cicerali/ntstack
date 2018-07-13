/*
 * main.c
 *
 *  Created on: Apr 10, 2018
 *      Author: cicerali
 */
#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdbool.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_log.h>

#include <nt_config.h>
#include <nt_packet.h>

void nt_run(void)
{

	for (int i = 0, j = rte_get_next_lcore(rte_get_master_lcore(), true, true);
			i < number_of_ports; i++)
	{
		rte_eal_remote_launch(lcore_function, NULL, j);
		j = rte_get_next_lcore(j, true, true);
	}

	nt_create_thread(rte_get_master_lcore(), nt_internal_loop, "internal_loop",
			NULL);
	return;
}

int nt_main()
{
	RTE_LOG(NOTICE, USER1, __AT__"Hello DPDK core!\n");

	int nt_argc = 3;
	char *nt_argv[] =
	{ "nt_stack", "-l 1-2", "--proc-type=primary" };
	nt_init(nt_argc, nt_argv);
	nt_run();

	RTE_LOG(NOTICE, USER1,
			__AT__"DPDK initialization done, wait 3 seconds for worker thread stabilization\n");
	rte_delay_ms(3000);
	return 0;
}
