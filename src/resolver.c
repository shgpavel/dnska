/* SPDX-License-Identifier: MIT */

#include <arpa/inet.h>
#include <ctype.h>
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
	RESOLVER_MIN_SOURCE_PORT   = 1024,
	RESOLVER_BIND_RETRIES      = 64,
	RESOLVER_TIMEOUT_SEC       = 3,
	RESOLVER_ID_MISMATCH_LIMIT = 3,
};

static int
writen(int fd, const uint8_t *buf, size_t len)
{
	size_t sent = 0;

	while (sent < len) {
		ssize_t n = write(fd, buf + sent, len - sent);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		sent += (size_t)n;
	}
	return 0;
}

static int
readn(int fd, uint8_t *buf, size_t len)
{
	size_t recvd = 0;

	while (recvd < len) {
		ssize_t n = read(fd, buf + recvd, len - recvd);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1; /* EOF */
		recvd += (size_t)n;
	}
	return 0;
}

/*
 * Randomize ASCII letter case in each QNAME label (RFC 5452 / 0x20
 * anti-spoofing).  Operates in-place starting at buf[offset].
 */
static void
randomize_qname_case(uint8_t *buf, size_t buf_len, size_t offset)
{
	size_t pos = offset;

	while (pos < buf_len) {
		uint8_t label_len = buf[pos];

		if (label_len == 0)
			break;
		if ((label_len & 0xC0) == 0xC0)
			break; /* compression pointer, not expected in a query */
		if (label_len > DNS_MAX_LABEL_LEN)
			break;

		pos++;
		for (uint8_t i = 0; i < label_len; i++) {
			if (pos + i >= buf_len)
				return;
			uint8_t c = buf[pos + i];
			if (isalpha((unsigned char)c)) {
				uint8_t rnd = 0;
				if (random_bytes(&rnd, 1) == 0)
					buf[pos + i] = (rnd & 1) ? (uint8_t)toupper((unsigned char)c) : (uint8_t)tolower((unsigned char)c);
			}
		}
		pos += label_len;
	}
}

/*
 * Compare QNAME labels in the response question section against the
 * QNAME in the sent query, case-sensitively.  Returns true if they
 * match or if the response uses compression (which we cannot check).
 */
static bool
qname_case_matches(const uint8_t *resp, size_t resp_len,
                   const uint8_t *query, size_t query_len)
{
	size_t rpos = DNS_HEADER_SIZE;
	size_t qpos = DNS_HEADER_SIZE;

	while (rpos < resp_len && qpos < query_len) {
		if ((resp[rpos] & 0xC0) == 0xC0)
			return true; /* compression - skip 0x20 check */
		if (resp[rpos] != query[qpos])
			return false;
		uint8_t label_len = resp[rpos];
		if (label_len == 0)
			return true;
		rpos++;
		qpos++;
		if (rpos + label_len > resp_len || qpos + label_len > query_len)
			return false;
		if (memcmp(resp + rpos, query + qpos, label_len) != 0)
			return false;
		rpos += label_len;
		qpos += label_len;
	}
	return false;
}

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

			if (bind(fd, (struct sockaddr *)&addr4,
			         sizeof(addr4))
			    == 0)
				return 0;
		} else {
			struct sockaddr_in6 addr6;

			memset(&addr6, 0, sizeof(addr6));
			addr6.sin6_family = AF_INET6;
			addr6.sin6_port   = htons(port);
			addr6.sin6_addr   = in6addr_any;

			if (bind(fd, (struct sockaddr *)&addr6,
			         sizeof(addr6))
			    == 0)
				return 0;
		}

		if (errno != EADDRINUSE && errno != EACCES)
			return -1;
	}

	return -1;
}

/*
 * Forward query to upstream over TCP and return the response.
 * query[] already has the upstream ID substituted and may have 0x20
 * randomized QNAME.  orig_query[] is used to restore the client ID.
 */
static int
forward_tcp(const struct sockaddr *upstream, socklen_t upstream_len,
            int            family,
            const uint8_t *query, size_t query_len,
            uint16_t upstream_id, const uint8_t *orig_query,
            uint8_t *response, size_t response_size,
            size_t *response_len)
{
	uint8_t len_buf[2];

	int     fd = socket(family, SOCK_STREAM, 0);
	if (fd < 0) {
		fprintf(stderr, "resolver: TCP socket: %s\n", strerror(errno));
		return -1;
	}

	struct timeval tv = { .tv_sec = RESOLVER_TIMEOUT_SEC, .tv_usec = 0 };
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0
	    || setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
		fprintf(stderr, "resolver: TCP setsockopt: %s\n",
		        strerror(errno));
		close(fd);
		return -1;
	}

	if (connect(fd, upstream, upstream_len) < 0) {
		fprintf(stderr, "resolver: TCP connect: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	if (query_len > UINT16_MAX) {
		close(fd);
		return -1;
	}
	len_buf[0] = (uint8_t)(query_len >> 8);
	len_buf[1] = (uint8_t)query_len;

	if (writen(fd, len_buf, 2) < 0
	    || writen(fd, query, query_len) < 0) {
		fprintf(stderr, "resolver: TCP send: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	if (readn(fd, len_buf, 2) < 0) {
		fprintf(stderr, "resolver: TCP recv length: %s\n",
		        strerror(errno));
		close(fd);
		return -1;
	}

	size_t resp_size = (size_t)(((uint16_t)len_buf[0] << 8) | len_buf[1]);
	if (resp_size < DNS_HEADER_SIZE || resp_size > response_size) {
		fprintf(stderr, "resolver: TCP bad response length: %zu\n",
		        resp_size);
		close(fd);
		return -1;
	}

	if (readn(fd, response, resp_size) < 0) {
		fprintf(stderr, "resolver: TCP recv body: %s\n",
		        strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);

	uint16_t got_id = (uint16_t)(((uint16_t)response[0] << 8) | response[1]);
	if (got_id != upstream_id) {
		fprintf(stderr, "resolver: TCP response ID mismatch\n");
		return -1;
	}

	response[0]   = orig_query[0];
	response[1]   = orig_query[1];

	*response_len = resp_size;
	return 0;
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
		fprintf(stderr, "resolver: invalid query size: %zu\n",
		        query_len);
		return -1;
	}
	if (random_bytes(&upstream_id, sizeof(upstream_id)) < 0) {
		fprintf(stderr, "resolver: failed to generate query id\n");
		return -1;
	}

	memcpy(forwarded_query, query, query_len);
	forwarded_query[0]       = (uint8_t)(upstream_id >> 8);
	forwarded_query[1]       = (uint8_t)upstream_id;
	uint16_t forwarded_flags = wire_read_u16(query + 2)
	                           & (DNS_FLAGS_OPCODE_MASK | DNS_FLAG_RD);
	forwarded_query[2]       = (uint8_t)(forwarded_flags >> 8);
	forwarded_query[3]       = (uint8_t)forwarded_flags;

	/* 0x20 QNAME case randomization (RFC 5452 §3.2) */
	if (wire_read_u16(forwarded_query + 4) >= 1)
		randomize_qname_case(forwarded_query, query_len,
		                     DNS_HEADER_SIZE);

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
			fprintf(stderr, "resolver: short response: %zd bytes\n",
			        recvd);
			close(fd);
			return -1;
		}

		uint16_t got_id = (uint16_t)(((uint16_t)response[0] << 8) | response[1]);
		if (got_id != upstream_id) {
			mismatches++;
			if (mismatches >= RESOLVER_ID_MISMATCH_LIMIT) {
				fprintf(stderr,
				        "resolver: too many response id "
				        "mismatches (%d)\n",
				        mismatches);
				close(fd);
				return -1;
			}
			continue;
		}

		/* 0x20 case check: response must echo the randomized QNAME */
		if (!qname_case_matches(response, (size_t)recvd,
		                        forwarded_query, query_len)) {
			mismatches++;
			if (mismatches >= RESOLVER_ID_MISMATCH_LIMIT) {
				fprintf(stderr,
				        "resolver: too many 0x20 QNAME "
				        "mismatches (%d)\n",
				        mismatches);
				close(fd);
				return -1;
			}
			continue;
		}

		break;
	}

	close(fd);

	/* RFC 7766 §6.2.1: retry over TCP when upstream signals truncation */
	if ((wire_read_u16(response + 2) & DNS_FLAG_TC) != 0) {
		fprintf(stderr, "resolver: upstream truncated, retrying TCP\n");
		return forward_tcp((const struct sockaddr *)&ss, ss_len, family,
		                   forwarded_query, query_len,
		                   upstream_id, query,
		                   response, response_size, response_len);
	}

	response[0]   = query[0];
	response[1]   = query[1];

	*response_len = (size_t)recvd;
	return 0;
}
