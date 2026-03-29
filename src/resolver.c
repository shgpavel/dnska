/* SPDX-License-Identifier: MIT */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "resolver.h"

static const int resolver_timeout_sec = 5;

int
resolver_forward(const char *upstream_addr, uint16_t upstream_port,
                 const uint8_t *query, size_t query_len,
                 uint8_t *response, size_t response_size,
                 size_t *response_len)
{
	struct sockaddr_storage ss;
	socklen_t               ss_len;
	int                     family;

	memset(&ss, 0, sizeof(ss));

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

	if (connect(fd, (struct sockaddr *)&ss, ss_len) < 0) {
		fprintf(stderr, "resolver: connect: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	struct timeval tv = { .tv_sec = resolver_timeout_sec, .tv_usec = 0 };
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		fprintf(stderr, "resolver: setsockopt: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	ssize_t sent = send(fd, query, query_len, 0);
	if (sent < 0) {
		fprintf(stderr, "resolver: send: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	ssize_t recvd = recv(fd, response, response_size, 0);
	if (recvd < 0) {
		fprintf(stderr, "resolver: recv: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	close(fd);
	*response_len = (size_t)recvd;
	return 0;
}
