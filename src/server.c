/* SPDX-License-Identifier: MIT */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "dns.h"
#include "resolver.h"
#include "server.h"

enum { MAX_CONCURRENT_QUERIES = 64 };

struct query_task {
	struct server_config   *cfg;
	int                     sock_fd;
	uint8_t                 query[DNS_MAX_MSG_SIZE];
	size_t                  query_len;
	struct sockaddr_storage client_addr;
	socklen_t               addr_len;
};

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
make_servfail(const uint8_t *query, size_t query_len, size_t qd_wire_len,
              uint8_t *resp, size_t resp_size)
{
	size_t resp_len = DNS_HEADER_SIZE + qd_wire_len;
	if (query_len < DNS_HEADER_SIZE || resp_len > resp_size)
		return 0;

	resp[0]    = query[0];
	resp[1]    = query[1];

	uint8_t rd = query[2] & 0x01;
	resp[2]    = 0x80 | rd;
	resp[3]    = 0x80 | DNS_RCODE_SERVFAIL; /* RA=1, RCODE=SERVFAIL */

	resp[4]    = query[4];
	resp[5]    = query[5];
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

static void *
handle_query(void *arg)
{
	struct query_task *task = arg;
	struct dns_message msg;
	char               addr_buf[INET6_ADDRSTRLEN];
	uint16_t           port;

	addr_str(&task->client_addr, addr_buf, sizeof(addr_buf), &port);

	if (dns_parse_message(&msg, task->query, task->query_len) < 0) {
		fprintf(stderr, "server: failed to parse query from %s:%d\n",
		        addr_buf, port);
		sem_post(&task->cfg->query_sem);
		free(task);
		return NULL;
	}

	fprintf(stderr, "query: %s %s from %s:%d\n",
	        msg.question.name,
	        dns_type_str(msg.question.qtype),
	        addr_buf, port);

	uint8_t response[DNS_MAX_MSG_SIZE];
	size_t  response_len = 0;

	int     rc           = resolver_forward(task->cfg->upstream_addr,
	                                        task->cfg->upstream_port,
	                                        task->query, task->query_len,
	                                        response, sizeof(response),
	                                        &response_len);

	if (rc < 0) {
		fprintf(stderr, "server: upstream failed for %s, "
		                "sending SERVFAIL\n",
		        msg.question.name);

		response_len = make_servfail(task->query, task->query_len,
		                             msg.question_wire_len,
		                             response, sizeof(response));
		if (response_len == 0) {
			sem_post(&task->cfg->query_sem);
			free(task);
			return NULL;
		}
	} else {
		uint16_t rcode = response_len >= 4 ? (response[3] & DNS_FLAGS_RCODE_MASK) : 0;
		fprintf(stderr, "reply: %s %s -> %s (%zu bytes)\n",
		        msg.question.name,
		        dns_type_str(msg.question.qtype),
		        dns_rcode_str(rcode),
		        response_len);
	}

	ssize_t sent = sendto(task->sock_fd, response, response_len, 0,
	                      (struct sockaddr *)&task->client_addr, task->addr_len);
	if (sent < 0) {
		fprintf(stderr, "server: sendto: %s\n", strerror(errno));
	}

	sem_post(&task->cfg->query_sem);
	free(task);
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
server_init(struct server_config *cfg)
{
	if (sem_init(&cfg->query_sem, 0, MAX_CONCURRENT_QUERIES) < 0) {
		fprintf(stderr, "server: sem_init: %s\n", strerror(errno));
		return -1;
	}

	cfg->sock_fd = bind_udp(AF_INET, cfg->listen_port);
	if (cfg->sock_fd < 0) {
		fprintf(stderr, "server: bind IPv4 port %d: %s\n",
		        cfg->listen_port, strerror(errno));
		return -1;
	}

	cfg->sock_fd6 = bind_udp(AF_INET6, cfg->listen_port);
	if (cfg->sock_fd6 < 0) {
		fprintf(stderr, "server: warning: IPv6 bind port %d failed: "
		                "%s\n",
		        cfg->listen_port, strerror(errno));
		cfg->sock_fd6 = -1;
	}

	cfg->running = 1;
	fprintf(stderr, "server: listening on 0.0.0.0:%d, upstream %s:%d\n",
	        cfg->listen_port, cfg->upstream_addr, cfg->upstream_port);

	return 0;
}

static void
receive_and_dispatch(struct server_config *cfg, int sock_fd)
{
	struct query_task *task = malloc(sizeof(struct query_task));
	if (!task) {
		fprintf(stderr, "server: malloc: %s\n", strerror(errno));
		return;
	}

	task->cfg      = cfg;
	task->sock_fd  = sock_fd;
	task->addr_len = sizeof(task->client_addr);

	ssize_t n      = recvfrom(sock_fd, task->query, sizeof(task->query), 0,
	                          (struct sockaddr *)&task->client_addr, &task->addr_len);
	if (n < 0) {
		fprintf(stderr, "server: recvfrom: %s\n", strerror(errno));
		free(task);
		return;
	}

	if (n < DNS_HEADER_SIZE) {
		fprintf(stderr, "server: runt packet (%zd bytes)\n", n);
		free(task);
		return;
	}

	task->query_len = (size_t)n;

	if (sem_trywait(&cfg->query_sem) != 0) {
		fprintf(stderr, "server: at capacity, dropping query\n");
		free(task);
		return;
	}

	pthread_t      tid;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	if (pthread_create(&tid, &attr, handle_query, task) != 0) {
		fprintf(stderr, "server: pthread_create: %s\n", strerror(errno));
		sem_post(&cfg->query_sem);
		free(task);
	}

	pthread_attr_destroy(&attr);
}

int
server_run(struct server_config *cfg)
{
	fd_set         rfds;
	struct timeval tv;

	while (cfg->running) {
		FD_ZERO(&rfds);
		FD_SET(cfg->sock_fd, &rfds);
		int maxfd = cfg->sock_fd;

		if (cfg->sock_fd6 >= 0) {
			FD_SET(cfg->sock_fd6, &rfds);
			if (cfg->sock_fd6 > maxfd)
				maxfd = cfg->sock_fd6;
		}

		tv.tv_sec  = 1;
		tv.tv_usec = 0;

		int ret    = select(maxfd + 1, &rfds, NULL, NULL, &tv);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "server: select: %s\n", strerror(errno));
			return -1;
		}

		if (ret == 0)
			continue;

		if (FD_ISSET(cfg->sock_fd, &rfds))
			receive_and_dispatch(cfg, cfg->sock_fd);

		if (cfg->sock_fd6 >= 0 && FD_ISSET(cfg->sock_fd6, &rfds))
			receive_and_dispatch(cfg, cfg->sock_fd6);
	}

	return 0;
}

void
server_stop(struct server_config *cfg)
{
	cfg->running = 0;

	for (int i = 0; i < MAX_CONCURRENT_QUERIES; i++)
		sem_wait(&cfg->query_sem);

	if (cfg->sock_fd >= 0) {
		close(cfg->sock_fd);
		cfg->sock_fd = -1;
	}
	if (cfg->sock_fd6 >= 0) {
		close(cfg->sock_fd6);
		cfg->sock_fd6 = -1;
	}
	sem_destroy(&cfg->query_sem);
}
