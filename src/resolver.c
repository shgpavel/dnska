/* SPDX-License-Identifier: MIT */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "dns.h"
#include "random.h"
#include "resolver.h"
#include "wire.h"

enum {
	RESOLVER_MIN_SOURCE_PORT    = 1024,
	RESOLVER_BIND_RETRIES       = 64,
	RESOLVER_TIMEOUT_SEC       = 3,
	RESOLVER_ID_MISMATCH_LIMIT = 3,
};

static int
bind_random_source_port(int fd, int family)
{
	for (int attempt = 0; attempt < RESOLVER_BIND_RETRIES; attempt++) {
		uint16_t port;

		if (random_bytes(&port, sizeof(port)) < 0)
			return -1;

		port = (uint16_t)(RESOLVER_MIN_SOURCE_PORT
		                  + (port % (UINT16_MAX - RESOLVER_MIN_SOURCE_PORT + 1)));

		if (family == AF_INET) {
			struct sockaddr_in addr4;

			memset(&addr4, 0, sizeof(addr4));
			addr4.sin_family      = AF_INET;
			addr4.sin_port        = htons(port);
			addr4.sin_addr.s_addr = htonl(INADDR_ANY);

			if (bind(fd, (struct sockaddr *)&addr4, sizeof(addr4)) == 0)
				return 0;
		} else {
			struct sockaddr_in6 addr6;

			memset(&addr6, 0, sizeof(addr6));
			addr6.sin6_family = AF_INET6;
			addr6.sin6_port   = htons(port);
			addr6.sin6_addr   = in6addr_any;

			if (bind(fd, (struct sockaddr *)&addr6, sizeof(addr6)) == 0)
				return 0;
		}

		if (errno != EADDRINUSE && errno != EACCES)
			return -1;
	}

	return -1;
}

int
resolver_forward(const char *upstream_addr, uint16_t upstream_port,
                 const uint8_t *query, size_t query_len,
                 uint8_t *response, size_t response_size,
                 size_t *response_len)
{
	struct sockaddr_storage ss;
	socklen_t               ss_len;
	int                     family;
	uint8_t                 forwarded_query[DNS_MAX_MSG_SIZE];
	uint16_t                upstream_id;

	memset(&ss, 0, sizeof(ss));

	if (query_len < DNS_HEADER_SIZE || query_len > sizeof(forwarded_query)) {
		fprintf(stderr, "resolver: invalid query size: %zu\n", query_len);
		return -1;
	}
	if (random_bytes(&upstream_id, sizeof(upstream_id)) < 0) {
		fprintf(stderr, "resolver: failed to generate query id\n");
		return -1;
	}

	memcpy(forwarded_query, query, query_len);
	forwarded_query[0]      = (uint8_t)(upstream_id >> 8);
	forwarded_query[1]      = (uint8_t)upstream_id;
	uint16_t forwarded_flags = wire_read_u16(query + 2)
	                           & (DNS_FLAGS_OPCODE_MASK | DNS_FLAG_RD);
	forwarded_query[2]      = (uint8_t)(forwarded_flags >> 8);
	forwarded_query[3]      = (uint8_t)forwarded_flags;

	struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&ss;
	struct sockaddr_in  *a4 = (struct sockaddr_in *)&ss;

	if (inet_pton(AF_INET6, upstream_addr, &a6->sin6_addr) == 1) {
		family          = AF_INET6;
		a6->sin6_family = AF_INET6;
		a6->sin6_port   = htons(upstream_port);
		ss_len          = sizeof(*a6);
	} else if (inet_pton(AF_INET, upstream_addr, &a4->sin_addr) == 1) {
		family         = AF_INET;
		a4->sin_family = AF_INET;
		a4->sin_port   = htons(upstream_port);
		ss_len         = sizeof(*a4);
	} else {
		fprintf(stderr, "resolver: invalid upstream address: %s\n",
		        upstream_addr);
		return -1;
	}

	int fd = socket(family, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "resolver: socket: %s\n", strerror(errno));
		return -1;
	}

	if (bind_random_source_port(fd, family) < 0) {
		fprintf(stderr, "resolver: bind random source port: %s\n",
		        strerror(errno));
		close(fd);
		return -1;
	}

	if (connect(fd, (struct sockaddr *)&ss, ss_len) < 0) {
		fprintf(stderr, "resolver: connect: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	struct timeval tv = { .tv_sec = RESOLVER_TIMEOUT_SEC, .tv_usec = 0 };
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		fprintf(stderr, "resolver: setsockopt: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	ssize_t sent = send(fd, forwarded_query, query_len, 0);
	if (sent < 0) {
		fprintf(stderr, "resolver: send: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	if (sent != (ssize_t)query_len) {
		fprintf(stderr, "resolver: short send: %zd of %zu bytes\n",
		        sent, query_len);
		close(fd);
		return -1;
	}

	ssize_t recvd      = -1;
	int     mismatches = 0;

	for (;;) {
		recvd = recv(fd, response, response_size, 0);
		if (recvd < 0) {
			fprintf(stderr, "resolver: recv: %s\n", strerror(errno));
			close(fd);
			return -1;
		}
		if ((size_t)recvd < DNS_HEADER_SIZE) {
			fprintf(stderr, "resolver: short response: %zd bytes\n", recvd);
			close(fd);
			return -1;
		}
		if ((((uint16_t)response[0] << 8) | response[1]) == upstream_id)
			break;

		mismatches++;
		if (mismatches >= RESOLVER_ID_MISMATCH_LIMIT) {
			fprintf(stderr,
			        "resolver: too many response id mismatches (%d)\n",
			        mismatches);
			close(fd);
			return -1;
		}
	}

	response[0] = query[0];
	response[1] = query[1];

	close(fd);
	*response_len = (size_t)recvd;
	return 0;
}
