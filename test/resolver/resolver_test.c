/* SPDX-License-Identifier: MIT */

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "dns.h"
#include "resolver.h"
#include "test.h"
#include "wire.h"

struct upstream_fixture {
	int      fd;
	uint16_t observed_flags;
	uint16_t observed_id;
	uint16_t client_port;
};

static void
write_u16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static size_t
append_name(uint8_t *buf, size_t pos, const char *name)
{
	const char *label = name;

	while (*label != '\0') {
		const char *dot = strchr(label, '.');
		size_t      len = dot ? (size_t)(dot - label) : strlen(label);

		TEST_CHECK(len <= DNS_MAX_LABEL_LEN);
		buf[pos++] = (uint8_t)len;
		memcpy(buf + pos, label, len);
		pos += len;

		if (dot == NULL)
			break;
		label = dot + 1;
	}

	buf[pos++] = 0;
	return pos;
}

static size_t
make_query(uint8_t *buf, uint16_t id, uint16_t flags, const char *qname)
{
	memset(buf, 0, DNS_HEADER_SIZE);
	write_u16(buf, id);
	write_u16(buf + 2, flags);
	write_u16(buf + 4, 1);

	size_t pos = DNS_HEADER_SIZE;
	pos        = append_name(buf, pos, qname);
	write_u16(buf + pos, DNS_TYPE_A);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	return pos + 4;
}

static void *
serve_upstream(void *arg)
{
	struct upstream_fixture *fixture = arg;
	struct sockaddr_in       client_addr;
	socklen_t                client_len = sizeof(client_addr);
	uint8_t                  query[DNS_MAX_MSG_SIZE];
	uint8_t                  response[DNS_MAX_MSG_SIZE];
	ssize_t                  recvd;

	recvd = recvfrom(fixture->fd, query, sizeof(query), 0,
	                 (struct sockaddr *)&client_addr, &client_len);
	TEST_CHECK(recvd >= (ssize_t)DNS_HEADER_SIZE);

	fixture->client_port    = ntohs(client_addr.sin_port);
	fixture->observed_id    = wire_read_u16(query);
	fixture->observed_flags = wire_read_u16(query + 2);

	memcpy(response, query, (size_t)recvd);
	write_u16(response + 2,
	          DNS_FLAG_QR | DNS_FLAG_RA | (fixture->observed_flags & DNS_FLAG_RD));

	write_u16(response, (uint16_t)(fixture->observed_id ^ 0xFFFFu));
	TEST_CHECK(sendto(fixture->fd, response, (size_t)recvd, 0,
	                  (struct sockaddr *)&client_addr, client_len)
	           == recvd);

	write_u16(response, fixture->observed_id);
	TEST_CHECK(sendto(fixture->fd, response, (size_t)recvd, 0,
	                  (struct sockaddr *)&client_addr, client_len)
	           == recvd);

	return NULL;
}

int
main(void)
{
	struct sockaddr_in     upstream_addr;
	socklen_t              upstream_len = sizeof(upstream_addr);
	struct upstream_fixture fixture;
	pthread_t              thread;
	uint8_t                query[DNS_MAX_MSG_SIZE];
	uint8_t                response[DNS_MAX_MSG_SIZE];
	size_t                 query_len;
	size_t                 response_len = 0;
	int                    rc;

	memset(&fixture, 0, sizeof(fixture));
	fixture.fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fixture.fd < 0 && (errno == EPERM || errno == EACCES))
		TEST_SKIP("resolver tests skipped: UDP sockets unavailable");
	TEST_CHECK(fixture.fd >= 0);

	memset(&upstream_addr, 0, sizeof(upstream_addr));
	upstream_addr.sin_family      = AF_INET;
	upstream_addr.sin_port        = 0;
	upstream_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	TEST_CHECK(bind(fixture.fd, (struct sockaddr *)&upstream_addr,
	                sizeof(upstream_addr))
	           == 0);
	TEST_CHECK(getsockname(fixture.fd, (struct sockaddr *)&upstream_addr,
	                       &upstream_len)
	           == 0);
	TEST_CHECK(pthread_create(&thread, NULL, serve_upstream, &fixture) == 0);

	query_len = make_query(query, 0x1234,
	                       DNS_FLAG_RD | DNS_FLAG_AD | DNS_FLAG_CD,
	                       "example.com");
	rc = resolver_forward("127.0.0.1", ntohs(upstream_addr.sin_port),
	                      query, query_len,
	                      response, sizeof(response), &response_len);

	TEST_CHECK(pthread_join(thread, NULL) == 0);
	close(fixture.fd);

	TEST_EXPECT_INT_EQ(rc, 0);
	TEST_EXPECT_SIZE_EQ(response_len, query_len);
	TEST_EXPECT_INT_EQ(wire_read_u16(response), 0x1234);
	TEST_EXPECT_INT_EQ(fixture.observed_flags, DNS_FLAG_RD);
	TEST_CHECK(fixture.client_port >= 1024);

	uint16_t response_flags = wire_read_u16(response + 2);
	TEST_CHECK((response_flags & DNS_FLAG_QR) != 0);
	TEST_CHECK((response_flags & DNS_FLAG_RA) != 0);
	TEST_CHECK((response_flags & DNS_FLAG_RD) != 0);
	TEST_CHECK((response_flags & DNS_FLAG_AD) == 0);
	TEST_CHECK((response_flags & DNS_FLAG_CD) == 0);

	puts("resolver tests passed");
	return 0;
}
