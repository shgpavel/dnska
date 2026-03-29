/* SPDX-License-Identifier: MIT */

#ifndef DNSKA_SERVER_H
#define DNSKA_SERVER_H

#include <semaphore.h>
#include <signal.h>
#include <stdint.h>

struct server_config {
	int                   listen_port;
	char                  upstream_addr[256];
	uint16_t              upstream_port;
	int                   sock_fd;
	int                   sock_fd6;
	volatile sig_atomic_t running;
	sem_t                 query_sem;
};

int
server_init(struct server_config *cfg);
int
server_run(struct server_config *cfg);
void
server_stop(struct server_config *cfg);

#endif /* DNSKA_SERVER_H */
