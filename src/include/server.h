/* SPDX-License-Identifier: MIT */

#ifndef DNSKA_SERVER_H
#define DNSKA_SERVER_H

#include <stdbool.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include <openssl/ssl.h>

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
	int                     sock_fd;   /* UDP: server bound socket, or -1 */
	int                     conn_fd;   /* TCP/DoT: accepted conn, or -1 */
	SSL_CTX                *tls_ctx;   /* non-NULL if incoming DoT conn */
	SSL                    *tls;       /* allocated in handle_query() */
	uint8_t                 query[DNS_MAX_MSG_SIZE];
	size_t                  query_len; /* 0 for TCP/DoT tasks pending read */
	struct sockaddr_storage client_addr;
	socklen_t               addr_len;
};

struct server {
	struct dns_config         config;
	int                       sock_fd;
	int                       sock_fd6;
	int                       tcp_fd;
	int                       tcp_fd6;
	int                       dot_fd;  /* DoT IPv4 listen socket, or -1 */
	int                       dot_fd6; /* DoT IPv6 listen socket, or -1 */
	SSL_CTX                  *tls_ctx; /* server TLS context for DoT */
	volatile sig_atomic_t     running;
	pthread_t                 pool[MAX_CONCURRENT_QUERIES];
	pthread_mutex_t           task_lock;
	pthread_cond_t            work_cond;
	struct query_task         query_tasks[MAX_CONCURRENT_QUERIES];
	int                       free_task_slots[MAX_CONCURRENT_QUERIES];
	int                       free_task_top;
	/* pending work queue: ring buffer of task slot indices */
	int                       pending[MAX_CONCURRENT_QUERIES];
	int                       pending_head;
	int                       pending_count;
	bool                      shutdown;
	uint32_t                  source_hash_seed;
	struct source_limit_entry source_limits[SOURCE_LIMIT_SLOTS];
	struct cache              cache;
};

int
server_init(struct server *srv, const struct dns_config *cfg);
int
server_run(struct server *srv);
void
server_stop(struct server *srv);

#endif /* DNSKA_SERVER_H */
