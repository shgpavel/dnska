/* SPDX-License-Identifier: MIT */

#ifndef DNSKA_SERVER_H
#define DNSKA_SERVER_H

#include <stdbool.h>
#include <netinet/in.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "cache.h"
#include "config.h"
#include "dns.h"

enum { MAX_CONCURRENT_QUERIES = 64 };
enum {
	MAX_CONCURRENT_QUERIES_PER_SOURCE = 4,
	SOURCE_LIMIT_SLOTS                = 256,
};

struct server;

struct source_limit_entry {
	struct in6_addr addr6;
	unsigned int    inflight;
	bool            in_use;
};

struct query_task {
	struct server          *srv;
	int                     slot;
	int                     source_slot;
	int                     sock_fd;
	uint8_t                 query[DNS_MAX_MSG_SIZE];
	size_t                  query_len;
	struct sockaddr_storage client_addr;
	socklen_t               addr_len;
};

struct server {
	struct dns_config     config;
	int                   sock_fd;
	int                   sock_fd6;
	volatile sig_atomic_t running;
	sem_t                 query_sem;
	pthread_mutex_t       task_lock;
	struct query_task     query_tasks[MAX_CONCURRENT_QUERIES];
	int                   free_task_slots[MAX_CONCURRENT_QUERIES];
	int                   free_task_top;
	uint32_t              source_hash_seed;
	struct source_limit_entry source_limits[SOURCE_LIMIT_SLOTS];
	struct cache          cache;
};

int
server_init(struct server *srv, const struct dns_config *cfg);
int
server_run(struct server *srv);
void
server_stop(struct server *srv);

#endif /* DNSKA_SERVER_H */
