/* SPDX-License-Identifier: MIT */

#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "cache.h"
#include "dns.h"
#include "random.h"
#include "resolver.h"
#include "server.h"
#include "wire.h"

static void
addr_str(const struct sockaddr_storage *addr, char *buf, size_t len,
         uint16_t *port)
{
	if (addr->ss_family == AF_INET) {
		const struct sockaddr_in *a4 = (const struct sockaddr_in *)addr;
		inet_ntop(AF_INET, &a4->sin_addr, buf, len);
		*port = ntohs(a4->sin_port);
	} else if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)addr;
		inet_ntop(AF_INET6, &a6->sin6_addr, buf, len);
		*port = ntohs(a6->sin6_port);
	} else {
		snprintf(buf, len, "unknown");
		*port = 0;
	}
}

static size_t
question_wire_len_or_zero(const uint8_t *query, size_t query_len)
{
	if (query_len < DNS_HEADER_SIZE || wire_read_u16(query + 4) < 1)
		return 0;

	int n = wire_skip_name(query, query_len, DNS_HEADER_SIZE);
	if (n < 0)
		return 0;

	size_t qd_wire_len = (size_t)n + 4;
	if (DNS_HEADER_SIZE + qd_wire_len > query_len)
		return 0;
	return qd_wire_len;
}

static size_t
make_error_response(const uint8_t *query, size_t query_len, size_t qd_wire_len,
                    uint8_t rcode, uint8_t *resp, size_t resp_size)
{
	size_t resp_len = DNS_HEADER_SIZE + qd_wire_len;
	if (query_len < DNS_HEADER_SIZE || resp_len > resp_size)
		return 0;

	resp[0]    = query[0];
	resp[1]    = query[1];

	uint8_t rd = query[2] & 0x01;
	resp[2]    = 0x80 | rd;
	resp[3]    = 0x80 | (rcode & DNS_FLAGS_RCODE_MASK); /* RA=1 */

	resp[4]    = 0;
	resp[5]    = qd_wire_len > 0 ? 1 : 0;
	resp[6]    = 0;
	resp[7]    = 0;
	resp[8]    = 0;
	resp[9]    = 0;
	resp[10]   = 0;
	resp[11]   = 0;

	if (qd_wire_len > 0)
		memcpy(resp + DNS_HEADER_SIZE, query + DNS_HEADER_SIZE,
		       qd_wire_len);

	return resp_len;
}

static void
write_u16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static bool
source_addr_to_v6(const struct sockaddr_storage *addr, struct in6_addr *out)
{
	memset(out, 0, sizeof(*out));

	if (addr->ss_family == AF_INET) {
		const struct sockaddr_in *a4 = (const struct sockaddr_in *)addr;

		out->s6_addr[10] = 0xFF;
		out->s6_addr[11] = 0xFF;
		memcpy(&out->s6_addr[12], &a4->sin_addr, sizeof(a4->sin_addr));
		return true;
	}

	if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)addr;

		*out = a6->sin6_addr;
		return true;
	}

	return false;
}

static uint32_t
source_hash(const struct sockaddr_storage *addr, uint32_t seed)
{
	struct in6_addr addr6;
	uint32_t        h = 2166136261u ^ seed;

	if (!source_addr_to_v6(addr, &addr6))
		return 0;

	for (size_t i = 0; i < sizeof(addr6.s6_addr); i++) {
		h ^= addr6.s6_addr[i];
		h *= 16777619u;
	}

	return h;
}

static int
skip_rr(const uint8_t *buf, size_t buf_len, size_t offset, size_t *next_offset)
{
	int n = wire_skip_name(buf, buf_len, offset);
	if (n < 0)
		return -1;

	size_t pos = offset + (size_t)n;
	if (pos + 10 > buf_len)
		return -1;

	size_t next = pos + 10 + wire_read_u16(buf + pos + 8);
	if (next > buf_len)
		return -1;

	*next_offset = next;
	return 0;
}

static size_t
client_udp_payload_limit(const struct dns_query_cache_key *key)
{
	if (key != NULL && key->has_opt && key->opt_udp_size != 0)
		return key->opt_udp_size;

	return 512;
}

static size_t
truncate_response_for_client(uint8_t *response, size_t response_len, size_t payload_limit)
{
	size_t   limit = payload_limit;
	size_t   pos   = DNS_HEADER_SIZE;
	uint16_t qdcount;
	uint16_t section_counts[3];
	bool     truncated = false;

	if (response_len <= limit)
		return response_len;
	if (response_len < DNS_HEADER_SIZE)
		return 0;
	if (limit > DNS_MAX_MSG_SIZE)
		limit = DNS_MAX_MSG_SIZE;
	if (limit < DNS_HEADER_SIZE)
		return 0;

	qdcount           = wire_read_u16(response + 4);
	section_counts[0] = wire_read_u16(response + 6);
	section_counts[1] = wire_read_u16(response + 8);
	section_counts[2] = wire_read_u16(response + 10);

	for (uint16_t i = 0; i < qdcount; i++) {
		int n = wire_skip_name(response, response_len, pos);
		if (n < 0 || pos + (size_t)n + 4 > response_len)
			goto header_only;
		pos += (size_t)n + 4;
	}

	if (pos > limit)
		goto header_only;

	size_t truncated_len = pos;
	for (int section = 0; section < 3; section++) {
		uint16_t included = 0;

		for (uint16_t i = 0; i < section_counts[section]; i++) {
			size_t next_offset;
			if (skip_rr(response, response_len, truncated_len, &next_offset) < 0) {
				section_counts[section] = included;
				truncated = true;
				goto finish;
			}
			if (next_offset > limit) {
				section_counts[section] = included;
				truncated = true;
				goto finish;
			}
			truncated_len = next_offset;
			included++;
		}

		section_counts[section] = included;
	}

finish:
	if (!truncated)
		return response_len;

	write_u16(response + 4, qdcount);
	write_u16(response + 6, section_counts[0]);
	write_u16(response + 8, section_counts[1]);
	write_u16(response + 10, section_counts[2]);
	write_u16(response + 2, wire_read_u16(response + 2) | DNS_FLAG_TC);
	return truncated_len;

header_only:
	write_u16(response + 4, 0);
	write_u16(response + 6, 0);
	write_u16(response + 8, 0);
	write_u16(response + 10, 0);
	write_u16(response + 2, wire_read_u16(response + 2) | DNS_FLAG_TC);
	return DNS_HEADER_SIZE;
}

static bool
source_addr_matches(const struct source_limit_entry *entry,
                    const struct sockaddr_storage *addr)
{
	struct in6_addr candidate;

	if (!entry->in_use)
		return false;
	if (!source_addr_to_v6(addr, &candidate))
		return false;

	return memcmp(&entry->addr6, &candidate, sizeof(candidate)) == 0;
}

static void
store_source_addr(struct source_limit_entry *entry,
                  const struct sockaddr_storage *addr)
{
	entry->in_use = source_addr_to_v6(addr, &entry->addr6);
}

static int
acquire_source_slot_locked(struct server *srv,
                           const struct sockaddr_storage *addr)
{
	uint32_t hash      = source_hash(addr, srv->source_hash_seed);
	int      free_slot = -1;

	for (int i = 0; i < SOURCE_LIMIT_SLOTS; i++) {
		int idx = (int)((hash + (uint32_t)i) % SOURCE_LIMIT_SLOTS);
		struct source_limit_entry *entry = &srv->source_limits[idx];

		if (source_addr_matches(entry, addr)) {
			if (entry->inflight >= MAX_CONCURRENT_QUERIES_PER_SOURCE)
				return -1;
			entry->inflight++;
			return idx;
		}

		if (!entry->in_use && free_slot == -1)
			free_slot = idx;
	}

	if (free_slot == -1)
		return -1;

	store_source_addr(&srv->source_limits[free_slot], addr);
	srv->source_limits[free_slot].inflight = 1;
	return free_slot;
}

static void
release_source_slot_locked(struct server *srv, int source_slot)
{
	if (source_slot < 0 || source_slot >= SOURCE_LIMIT_SLOTS)
		return;

	struct source_limit_entry *entry = &srv->source_limits[source_slot];

	assert(entry->in_use);
	assert(entry->inflight > 0);
	entry->inflight--;
	if (entry->inflight == 0) {
		entry->in_use = false;
		memset(&entry->addr6, 0, sizeof(entry->addr6));
	}
}

static void
release_task_slot(struct query_task *task)
{
	pthread_mutex_lock(&task->srv->task_lock);
	release_source_slot_locked(task->srv, task->source_slot);
	assert(task->srv->free_task_top < MAX_CONCURRENT_QUERIES);
	task->srv->free_task_slots[task->srv->free_task_top++] = task->slot;
	pthread_mutex_unlock(&task->srv->task_lock);
	task->source_slot = -1;
	sem_post(&task->srv->query_sem);
}

static void *
handle_query(void *arg)
{
	struct query_task *task = arg;
	struct dns_message msg;
	char               addr_buf[INET6_ADDRSTRLEN];
	char               qtype_buf[32];
	char               rcode_buf[32];
	uint16_t           port;

	addr_str(&task->client_addr, addr_buf, sizeof(addr_buf), &port);

	if (dns_parse_message(&msg, task->query, task->query_len) < 0) {
		uint8_t response[DNS_MAX_MSG_SIZE];
		size_t  response_len = make_error_response(task->query, task->query_len,
		                                           question_wire_len_or_zero(task->query, task->query_len),
		                                           DNS_RCODE_FORMERR,
		                                           response, sizeof(response));

		fprintf(stderr, "server: failed to parse query from %s:%d\n",
		        addr_buf, port);
		if (response_len > 0) {
			ssize_t sent = sendto(task->sock_fd, response, response_len, 0,
			                      (struct sockaddr *)&task->client_addr,
			                      task->addr_len);
			if (sent < 0)
				fprintf(stderr, "server: sendto: %s\n", strerror(errno));
		}
		release_task_slot(task);
		return NULL;
	}

	fprintf(stderr, "query: %s %s from %s:%d\n",
	        msg.question.name,
	        dns_type_str(msg.question.qtype, qtype_buf, sizeof(qtype_buf)),
	        addr_buf, port);

	uint8_t  response[DNS_MAX_MSG_SIZE];
	size_t   response_len = 0;
	uint16_t query_id     = msg.header.id;

	int      hit          = 0;

	if (msg.cacheable)
		hit = cache_lookup(&task->srv->cache,
		                   msg.question.name,
		                   msg.question.qtype,
		                   msg.question.qclass,
		                   &msg.cache_key,
		                   query_id,
		                   task->query + DNS_HEADER_SIZE,
		                   msg.question_wire_len,
		                   response, sizeof(response), &response_len);
	if (hit == -2)
		fprintf(stderr, "cache: expired %s %s\n",
		        msg.question.name,
		        dns_type_str(msg.question.qtype, qtype_buf, sizeof(qtype_buf)));
	if (hit == -1)
		fprintf(stderr, "cache: failed to build cached response for %s %s\n",
		        msg.question.name,
		        dns_type_str(msg.question.qtype, qtype_buf, sizeof(qtype_buf)));
	if (hit == 1) {
		fprintf(stderr, "cache: hit %s %s (%zu bytes)\n",
		        msg.question.name,
		        dns_type_str(msg.question.qtype, qtype_buf, sizeof(qtype_buf)),
		        response_len);
	} else {
		int rc = resolver_forward(task->srv->config.upstream_addr,
		                          task->srv->config.upstream_port,
		                          task->query, task->query_len,
		                          response, sizeof(response),
		                          &response_len);

		if (rc < 0) {
			fprintf(stderr, "server: upstream failed for %s, "
			                "sending SERVFAIL\n",
			        msg.question.name);

			response_len = make_error_response(task->query, task->query_len,
			                                   msg.question_wire_len,
			                                   DNS_RCODE_SERVFAIL,
			                                   response, sizeof(response));
			if (response_len == 0) {
				release_task_slot(task);
				return NULL;
			}
		} else {
			uint16_t rcode = response_len >= 4 ? (response[3] & DNS_FLAGS_RCODE_MASK) : 0;
			fprintf(stderr, "reply: %s %s -> %s (%zu bytes)\n",
			        msg.question.name,
			        dns_type_str(msg.question.qtype, qtype_buf, sizeof(qtype_buf)),
			        dns_rcode_str(rcode, rcode_buf, sizeof(rcode_buf)),
			        response_len);

			uint16_t flags = wire_read_u16(response + 2);
			uint32_t cache_ttl = (rcode == DNS_RCODE_SERVFAIL) ? CACHE_SERVFAIL_TTL : 0;
			if (msg.cacheable
			    && (flags & DNS_FLAG_TC) == 0
			    && (rcode == DNS_RCODE_OK || rcode == DNS_RCODE_NXDOMAIN || rcode == DNS_RCODE_SERVFAIL)) {
				if (!dns_response_matches_query(&msg, response, response_len)) {
					fprintf(stderr,
					        "cache: reject upstream reply for %s %s "
					        "(question mismatch or malformed response)\n",
					        msg.question.name,
					        dns_type_str(msg.question.qtype, qtype_buf, sizeof(qtype_buf)));
				} else {
					cache_insert(&task->srv->cache,
					             msg.question.name,
					             msg.question.qtype,
					             msg.question.qclass,
					             &msg.cache_key,
					             response, response_len, cache_ttl);
				}
			} else if ((flags & DNS_FLAG_TC) != 0) {
				fprintf(stderr,
				        "cache: skip truncated response for %s %s\n",
				        msg.question.name,
				        dns_type_str(msg.question.qtype, qtype_buf, sizeof(qtype_buf)));
			}
		}
	}

	size_t client_limit = client_udp_payload_limit(&msg.cache_key);
	if (response_len > client_limit) {
		size_t truncated_len = truncate_response_for_client(response, response_len,
		                                                    client_limit);
		if (truncated_len == 0) {
			release_task_slot(task);
			return NULL;
		}
		response_len = truncated_len;
	}

	ssize_t sent = sendto(task->sock_fd, response, response_len, 0,
	                      (struct sockaddr *)&task->client_addr, task->addr_len);
	if (sent < 0) {
		fprintf(stderr, "server: sendto: %s\n", strerror(errno));
	}

	release_task_slot(task);
	return NULL;
}

static int
bind_udp(int family, int port)
{
	int fd = socket(family, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	int optval = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
	               &optval, sizeof(optval))
	    < 0) {
		fprintf(stderr, "server: setsockopt SO_REUSEADDR: %s\n",
		        strerror(errno));
		close(fd);
		return -1;
	}

	if (family == AF_INET6) {
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
		               &optval, sizeof(optval))
		    < 0) {
			fprintf(stderr, "server: setsockopt IPV6_V6ONLY: %s\n",
			        strerror(errno));
			close(fd);
			return -1;
		}
	}

	struct sockaddr_storage addr;
	socklen_t               addr_len;
	memset(&addr, 0, sizeof(addr));

	if (family == AF_INET) {
		struct sockaddr_in *a4 = (struct sockaddr_in *)&addr;
		a4->sin_family         = AF_INET;
		a4->sin_port           = htons(port);
		a4->sin_addr.s_addr    = INADDR_ANY;
		addr_len               = sizeof(*a4);
	} else {
		struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&addr;
		a6->sin6_family         = AF_INET6;
		a6->sin6_port           = htons(port);
		a6->sin6_addr           = in6addr_any;
		addr_len                = sizeof(*a6);
	}

	if (bind(fd, (struct sockaddr *)&addr, addr_len) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

int
server_init(struct server *srv, const struct dns_config *cfg)
{
	memset(srv, 0, sizeof(*srv));
	srv->sock_fd  = -1;
	srv->sock_fd6 = -1;
	srv->config   = *cfg;

	if (random_bytes(&srv->source_hash_seed, sizeof(srv->source_hash_seed)) < 0) {
		fprintf(stderr, "server: failed to generate source hash seed\n");
		return -1;
	}

	if (cache_init(&srv->cache) < 0) {
		fprintf(stderr, "server: cache_init failed\n");
		return -1;
	}

	if (sem_init(&srv->query_sem, 0, MAX_CONCURRENT_QUERIES) < 0) {
		fprintf(stderr, "server: sem_init: %s\n", strerror(errno));
		cache_destroy(&srv->cache);
		return -1;
	}

	if (pthread_mutex_init(&srv->task_lock, NULL) != 0) {
		fprintf(stderr, "server: pthread_mutex_init failed\n");
		sem_destroy(&srv->query_sem);
		cache_destroy(&srv->cache);
		return -1;
	}

	srv->free_task_top = MAX_CONCURRENT_QUERIES;
	for (int i = 0; i < MAX_CONCURRENT_QUERIES; i++) {
		srv->free_task_slots[i] = MAX_CONCURRENT_QUERIES - 1 - i;
		srv->query_tasks[i].source_slot = -1;
	}

	srv->sock_fd = bind_udp(AF_INET, srv->config.listen_port);
	if (srv->sock_fd < 0) {
		fprintf(stderr, "server: bind IPv4 port %d: %s\n",
		        srv->config.listen_port, strerror(errno));
		pthread_mutex_destroy(&srv->task_lock);
		sem_destroy(&srv->query_sem);
		cache_destroy(&srv->cache);
		return -1;
	}

	srv->sock_fd6 = bind_udp(AF_INET6, srv->config.listen_port);
	if (srv->sock_fd6 < 0) {
		fprintf(stderr, "server: warning: IPv6 bind port %d failed: "
		                "%s\n",
		        srv->config.listen_port, strerror(errno));
		srv->sock_fd6 = -1;
	}

	srv->running = 1;
	fprintf(stderr, "server: listening on 0.0.0.0:%d, upstream %s:%d\n",
	        srv->config.listen_port, srv->config.upstream_addr,
	        srv->config.upstream_port);
	fprintf(stderr, "server: warning: no client ACL and only basic per-source limits; "
	                "not safe for public exposure\n");

	return 0;
}

static void
receive_and_dispatch(struct server *srv, int sock_fd)
{
	struct sockaddr_storage client_addr;
	socklen_t               addr_len = sizeof(client_addr);
	uint8_t                 query[DNS_MAX_MSG_SIZE];
	ssize_t                 n;

	n = recvfrom(sock_fd, query, sizeof(query), 0,
	             (struct sockaddr *)&client_addr, &addr_len);
	if (n < 0) {
		fprintf(stderr, "server: recvfrom: %s\n", strerror(errno));
		return;
	}

	if (n < DNS_HEADER_SIZE) {
		fprintf(stderr, "server: runt packet (%zd bytes)\n", n);
		return;
	}

	if (sem_trywait(&srv->query_sem) != 0) {
		fprintf(stderr, "server: at capacity, dropping query\n");
		return;
	}

	pthread_mutex_lock(&srv->task_lock);
	int source_slot = acquire_source_slot_locked(srv, &client_addr);
	if (source_slot < 0) {
		pthread_mutex_unlock(&srv->task_lock);
		sem_post(&srv->query_sem);
		fprintf(stderr, "server: source concurrency limit exceeded\n");
		return;
	}

	/*
	 * Once query_sem is acquired and a source slot is reserved, a task slot
	 * must be available. The semaphore, source limiter, and task pool stay
	 * aligned unless there is a logic bug elsewhere.
	 */
	assert(srv->free_task_top > 0);
	if (srv->free_task_top == 0) {
		release_source_slot_locked(srv, source_slot);
		pthread_mutex_unlock(&srv->task_lock);
		fprintf(stderr, "server: task pool exhausted\n");
		sem_post(&srv->query_sem);
		return;
	}

	int slot = srv->free_task_slots[--srv->free_task_top];
	pthread_mutex_unlock(&srv->task_lock);

	struct query_task *task = &srv->query_tasks[slot];
	task->srv               = srv;
	task->slot              = slot;
	task->source_slot       = source_slot;
	task->sock_fd           = sock_fd;
	task->query_len         = (size_t)n;
	task->addr_len          = addr_len;
	memcpy(task->query, query, (size_t)n);
	memcpy(&task->client_addr, &client_addr, sizeof(client_addr));

	pthread_t      tid;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	if (pthread_create(&tid, &attr, handle_query, task) != 0) {
		fprintf(stderr, "server: pthread_create: %s\n", strerror(errno));
		release_task_slot(task);
	}

	pthread_attr_destroy(&attr);
}

int
server_run(struct server *srv)
{
	while (srv->running) {
		struct pollfd pfds[2];
		nfds_t        nfds = 1;

		memset(pfds, 0, sizeof(pfds));
		pfds[0].fd     = srv->sock_fd;
		pfds[0].events = POLLIN;

		if (srv->sock_fd6 >= 0) {
			pfds[1].fd     = srv->sock_fd6;
			pfds[1].events = POLLIN;
			nfds           = 2;
		}

		int ret = poll(pfds, nfds, 1000);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "server: poll: %s\n", strerror(errno));
			return -1;
		}

		if (ret == 0)
			continue;

		if ((pfds[0].revents & POLLIN) != 0)
			receive_and_dispatch(srv, srv->sock_fd);

		if (nfds > 1 && (pfds[1].revents & POLLIN) != 0)
			receive_and_dispatch(srv, srv->sock_fd6);
	}

	return 0;
}

static bool
realtime_deadline_after_ms(struct timespec *deadline, long timeout_ms)
{
	if (clock_gettime(CLOCK_REALTIME, deadline) < 0)
		return false;

	deadline->tv_sec  += timeout_ms / 1000;
	deadline->tv_nsec += (timeout_ms % 1000) * 1000000L;
	if (deadline->tv_nsec >= 1000000000L) {
		deadline->tv_sec++;
		deadline->tv_nsec -= 1000000000L;
	}

	return true;
}

static bool
drain_query_threads(struct server *srv)
{
	struct timespec deadline;

	if (!realtime_deadline_after_ms(&deadline, 10000))
		return false;

	for (int i = 0; i < MAX_CONCURRENT_QUERIES;) {
		if (sem_timedwait(&srv->query_sem, &deadline) == 0) {
			i++;
			continue;
		}
		if (errno == EINTR)
			continue;
		return false;
	}

	return true;
}

void
server_stop(struct server *srv)
{
	srv->running = 0;

	bool drained = drain_query_threads(srv);
	if (!drained) {
		fprintf(stderr, "server: warning: query threads did not drain "
		                "within 10 seconds; process must exit immediately "
		                "after shutdown\n");
	}

	if (srv->sock_fd >= 0) {
		close(srv->sock_fd);
		srv->sock_fd = -1;
	}
	if (srv->sock_fd6 >= 0) {
		close(srv->sock_fd6);
		srv->sock_fd6 = -1;
	}
	if (drained) {
		pthread_mutex_destroy(&srv->task_lock);
		sem_destroy(&srv->query_sem);
		cache_destroy(&srv->cache);
	}
}
