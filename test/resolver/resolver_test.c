/* SPDX-License-Identifier: MIT */

#include <arpa/inet.h>
#include <ctype.h>
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

/*
 * Mock upstream: sends one wrong-ID response then one correct response.
 * Records the incoming query's flags and ID for later inspection.
 */
struct upstream_fixture {
	int      fd;
	uint16_t observed_flags;
	uint16_t observed_id;
	uint16_t client_port;
	/* QNAME bytes as received from the resolver (label-wire form) */
	uint8_t  observed_qname[DNS_MAX_NAME_LEN + 2];
	size_t   observed_qname_len;
};

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

	/* Copy QNAME bytes from question section */
	size_t qpos             = DNS_HEADER_SIZE;
	size_t qlen             = 0;
	while (qpos < (size_t)recvd && qlen < sizeof(fixture->observed_qname)) {
		uint8_t label_len               = query[qpos];
		fixture->observed_qname[qlen++] = label_len;
		if (label_len == 0)
			break;
		if ((label_len & 0xC0) == 0xC0) {
			fixture->observed_qname[qlen++] = query[qpos + 1];
			break;
		}
		qpos++;
		if (qpos + label_len > (size_t)recvd)
			break;
		memcpy(fixture->observed_qname + qlen, query + qpos, label_len);
		qlen += label_len;
		qpos += label_len;
	}
	fixture->observed_qname_len = qlen;

	memcpy(response, query, (size_t)recvd);
	write_u16(response + 2,
	          DNS_FLAG_QR | DNS_FLAG_RA | (fixture->observed_flags & DNS_FLAG_RD));

	/* First send: wrong ID → resolver should ignore and wait */
	write_u16(response, (uint16_t)(fixture->observed_id ^ 0xFFFFu));
	TEST_CHECK(sendto(fixture->fd, response, (size_t)recvd, 0,
	                  (struct sockaddr *)&client_addr, client_len)
	           == recvd);

	/* Second send: correct ID → resolver accepts */
	write_u16(response, fixture->observed_id);
	TEST_CHECK(sendto(fixture->fd, response, (size_t)recvd, 0,
	                  (struct sockaddr *)&client_addr, client_len)
	           == recvd);

	return NULL;
}

/* --- basic UDP forwarding behavior --- */

static void
test_id_randomized_flags_stripped(void)
{
	struct sockaddr_in      upstream_addr;
	socklen_t               upstream_len = sizeof(upstream_addr);
	struct upstream_fixture fixture;
	pthread_t               thread;
	uint8_t                 query[DNS_MAX_MSG_SIZE];
	uint8_t                 response[DNS_MAX_MSG_SIZE];
	size_t                  query_len;
	size_t                  response_len = 0;
	int                     rc;

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

	char addrs[1][INET6_ADDRSTRLEN];
	snprintf(addrs[0], INET6_ADDRSTRLEN, "127.0.0.1");
	rc = resolver_forward(addrs, 1, ntohs(upstream_addr.sin_port),
	                      false, false, NULL, NULL, query, query_len,
	                      response, sizeof(response), &response_len);

	TEST_CHECK(pthread_join(thread, NULL) == 0);
	close(fixture.fd);

	TEST_EXPECT_INT_EQ(rc, 0);

	/* Response ID must be restored to the original client ID */
	TEST_EXPECT_INT_EQ(wire_read_u16(response), 0x1234);

	/* Upstream must have seen a different (randomized) ID */
	TEST_CHECK(fixture.observed_id != 0x1234);

	/* Upstream must see RD and DNSSEC pass-through bits (AD, CD) */
	TEST_EXPECT_INT_EQ(fixture.observed_flags,
	                   DNS_FLAG_RD | DNS_FLAG_AD | DNS_FLAG_CD);

	/* Source port must be random and ≥ 1024 */
	TEST_CHECK(fixture.client_port >= 1024);

	/* Response must have QR and RA set */
	uint16_t response_flags = wire_read_u16(response + 2);
	TEST_CHECK((response_flags & DNS_FLAG_QR) != 0);
	TEST_CHECK((response_flags & DNS_FLAG_RA) != 0);
	TEST_CHECK((response_flags & DNS_FLAG_AD) == 0);
	TEST_CHECK((response_flags & DNS_FLAG_CD) == 0);
}

/* --- 0x20 QNAME case randomization (RFC 5452) --- */

/*
 * Mock that expects exactly one UDP query and echoes it back verbatim
 * (including whatever QNAME case it received).
 */
struct echo_fixture {
	int     fd;
	uint8_t received_query[DNS_MAX_MSG_SIZE];
	ssize_t received_len;
};

static void *
serve_echo(void *arg)
{
	struct echo_fixture *fixture = arg;
	struct sockaddr_in   client_addr;
	socklen_t            client_len = sizeof(client_addr);
	uint8_t              response[DNS_MAX_MSG_SIZE];

	fixture->received_len = recvfrom(
	        fixture->fd, fixture->received_query, sizeof(fixture->received_query),
	        0, (struct sockaddr *)&client_addr, &client_len);

	TEST_CHECK(fixture->received_len >= (ssize_t)DNS_HEADER_SIZE);

	memcpy(response, fixture->received_query,
	       (size_t)fixture->received_len);
	write_u16(response + 2, DNS_FLAG_QR | DNS_FLAG_RA | (wire_read_u16(response + 2) & DNS_FLAG_RD));
	/* Keep the same ID the resolver sent */
	sendto(fixture->fd, response, (size_t)fixture->received_len, 0,
	       (struct sockaddr *)&client_addr, client_len);

	return NULL;
}

static void
test_0x20_randomization_uppercase_present(void)
{
	struct sockaddr_in  upstream_addr;
	socklen_t           upstream_len = sizeof(upstream_addr);
	struct echo_fixture fixture;
	pthread_t           thread;
	uint8_t             query[DNS_MAX_MSG_SIZE];
	uint8_t             response[DNS_MAX_MSG_SIZE];
	size_t              query_len;
	size_t              response_len = 0;

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
	TEST_CHECK(pthread_create(&thread, NULL, serve_echo, &fixture) == 0);

	/* "example.com" has 10 alphabetic bytes: P(all lower) = 1/1024 */
	query_len = make_query(query, 0xABCD, DNS_FLAG_RD, "example.com");

	char addrs[1][INET6_ADDRSTRLEN];
	snprintf(addrs[0], INET6_ADDRSTRLEN, "127.0.0.1");
	resolver_forward(addrs, 1, ntohs(upstream_addr.sin_port), false, false,
	                 NULL, NULL, query, query_len, response,
	                 sizeof(response), &response_len);

	TEST_CHECK(pthread_join(thread, NULL) == 0);
	close(fixture.fd);

	TEST_CHECK(fixture.received_len >= (ssize_t)DNS_HEADER_SIZE);

	/*
	 * Walk the QNAME bytes the upstream received.  Verify each byte is
	 * either exactly the original letter or its opposite case.  At least
	 * one byte must differ from the original all-lowercase query QNAME.
	 */
	const uint8_t *orig_qname     = query + DNS_HEADER_SIZE;
	const uint8_t *received_qname = fixture.received_query + DNS_HEADER_SIZE;
	size_t         buf_len        = (size_t)fixture.received_len;
	size_t         qpos           = DNS_HEADER_SIZE;
	bool           any_uppercase  = false;

	while (qpos < buf_len) {
		uint8_t rlen = fixture.received_query[qpos];
		uint8_t olen = orig_qname[qpos - DNS_HEADER_SIZE];

		if (rlen == 0 || (rlen & 0xC0) == 0xC0)
			break;
		TEST_CHECK(rlen == olen);

		for (uint8_t i = 0; i < rlen; i++) {
			uint8_t rc = received_qname[qpos - DNS_HEADER_SIZE + 1 + i];
			uint8_t oc = orig_qname[qpos - DNS_HEADER_SIZE + 1 + i];
			/* Non-alpha bytes must be unchanged */
			if (!isalpha((unsigned char)oc)) {
				TEST_CHECK(rc == oc);
			} else {
				/* Must be same letter, either case */
				TEST_CHECK(tolower((unsigned char)rc)
				           == tolower((unsigned char)oc));
				if (isupper((unsigned char)rc))
					any_uppercase = true;
			}
		}
		qpos += 1 + rlen;
	}

	/*
	 * With 10 alpha bytes, P(no uppercase) = 1/1024 ≈ 0.1%.
	 * Fail the test if all stayed lowercase — indicates broken
	 * randomization.  (Extremely rare false failures are acceptable.)
	 */
	TEST_CHECK(any_uppercase);
}

/* --- TCP fallback on TC=1 (RFC 7766 §6.2.1) --- */

struct tc_upstream_fixture {
	int      udp_fd;
	int      tcp_listen_fd;
	uint16_t port;
	/* Full A-record response to send over TCP */
	uint8_t  full_response[DNS_MAX_MSG_SIZE];
	size_t   full_response_len;
	/* Captured upstream ID from the UDP query */
	uint16_t upstream_id;
};

/*
 * Upstream thread: responds to one UDP query with TC=1, then serves
 * one TCP query with the full response on the same port.
 */
static void *
serve_tc_then_tcp(void *arg)
{
	struct tc_upstream_fixture *fx = arg;
	struct sockaddr_in          client_addr;
	socklen_t                   client_len = sizeof(client_addr);
	uint8_t                     query[DNS_MAX_MSG_SIZE];
	uint8_t                     tc_response[DNS_HEADER_SIZE];
	ssize_t                     recvd;

	/* --- UDP: receive query, reply with TC=1 --- */
	recvd = recvfrom(fx->udp_fd, query, sizeof(query), 0,
	                 (struct sockaddr *)&client_addr, &client_len);
	TEST_CHECK(recvd >= (ssize_t)DNS_HEADER_SIZE);

	fx->upstream_id = wire_read_u16(query);

	memset(tc_response, 0, sizeof(tc_response));
	write_u16(tc_response, fx->upstream_id);
	write_u16(tc_response + 2,
	          DNS_FLAG_QR | DNS_FLAG_RA | DNS_FLAG_TC | DNS_FLAG_RD);
	write_u16(tc_response + 4, 1); /* QDCOUNT=1 */

	/* Echo the question section */
	uint8_t tc_full[DNS_MAX_MSG_SIZE];
	memcpy(tc_full, tc_response, DNS_HEADER_SIZE);
	size_t qd_len = (size_t)recvd - DNS_HEADER_SIZE;
	memcpy(tc_full + DNS_HEADER_SIZE, query + DNS_HEADER_SIZE, qd_len);

	sendto(fx->udp_fd, tc_full, DNS_HEADER_SIZE + qd_len, 0,
	       (struct sockaddr *)&client_addr, client_len);

	/* --- TCP: accept, read query, send full response --- */
	struct sockaddr_in tcp_client;
	socklen_t          tcp_len = sizeof(tcp_client);
	int                conn    = accept(fx->tcp_listen_fd,
	                                    (struct sockaddr *)&tcp_client,
	                                    &tcp_len);
	TEST_CHECK(conn >= 0);

	uint8_t len_buf[2];
	TEST_CHECK(recv(conn, len_buf, 2, MSG_WAITALL) == 2);
	uint16_t msg_size = (uint16_t)(((uint16_t)len_buf[0] << 8) | len_buf[1]);
	TEST_CHECK(recv(conn, query, msg_size, MSG_WAITALL) == msg_size);

	/* The TCP query should use the same upstream ID */
	uint16_t tcp_id = wire_read_u16(query);

	/* Patch the full response to use the TCP query's ID */
	memcpy(fx->full_response, fx->full_response, fx->full_response_len);
	write_u16(fx->full_response, tcp_id);

	/* Send with 2-byte length prefix */
	len_buf[0] = (uint8_t)(fx->full_response_len >> 8);
	len_buf[1] = (uint8_t)(fx->full_response_len);
	send(conn, len_buf, 2, 0);
	send(conn, fx->full_response, fx->full_response_len, 0);

	close(conn);
	return NULL;
}

static void
test_tcp_fallback_on_truncation(void)
{
	struct tc_upstream_fixture fx;
	struct sockaddr_in         addr;
	socklen_t                  addr_len = sizeof(addr);
	pthread_t                  thread;
	uint8_t                    query[DNS_MAX_MSG_SIZE];
	uint8_t                    response[DNS_MAX_MSG_SIZE];
	size_t                     query_len;
	size_t                     response_len = 0;
	int                        rc;

	memset(&fx, 0, sizeof(fx));

	/* Bind UDP socket */
	fx.udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fx.udp_fd < 0 && (errno == EPERM || errno == EACCES))
		TEST_SKIP("resolver tests skipped: UDP sockets unavailable");
	TEST_CHECK(fx.udp_fd >= 0);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_port        = 0;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	TEST_CHECK(bind(fx.udp_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
	TEST_CHECK(getsockname(fx.udp_fd, (struct sockaddr *)&addr,
	                       &addr_len)
	           == 0);
	fx.port          = ntohs(addr.sin_port);

	/* Bind TCP socket on the same port */
	fx.tcp_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	TEST_CHECK(fx.tcp_listen_fd >= 0);
	int optval = 1;
	setsockopt(fx.tcp_listen_fd, SOL_SOCKET, SO_REUSEADDR,
	           &optval, sizeof(optval));
	addr.sin_family      = AF_INET;
	addr.sin_port        = htons(fx.port);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	TEST_CHECK(bind(fx.tcp_listen_fd, (struct sockaddr *)&addr,
	                sizeof(addr))
	           == 0);
	TEST_CHECK(listen(fx.tcp_listen_fd, 1) == 0);

	/* Build the full A-record response that the TCP upstream will send */
	size_t fpos = DNS_HEADER_SIZE;
	memset(fx.full_response, 0, DNS_HEADER_SIZE);
	write_u16(fx.full_response + 2,
	          DNS_FLAG_QR | DNS_FLAG_RA | DNS_FLAG_RD);
	write_u16(fx.full_response + 4, 1);
	write_u16(fx.full_response + 6, 1);

	fpos = append_name(fx.full_response, fpos, "example.com");
	write_u16(fx.full_response + fpos, DNS_TYPE_A);
	write_u16(fx.full_response + fpos + 2, DNS_CLASS_IN);
	fpos                     += 4;

	fx.full_response[fpos++]  = 0xC0;
	fx.full_response[fpos++]  = DNS_HEADER_SIZE;
	write_u16(fx.full_response + fpos, DNS_TYPE_A);
	write_u16(fx.full_response + fpos + 2, DNS_CLASS_IN);
	write_u16(fx.full_response + fpos + 4, 0);
	write_u16(fx.full_response + fpos + 6, 300); /* TTL */
	write_u16(fx.full_response + fpos + 8, 4);
	fpos                     += 10;
	fx.full_response[fpos++]  = 93;
	fx.full_response[fpos++]  = 184;
	fx.full_response[fpos++]  = 216;
	fx.full_response[fpos++]  = 34;
	fx.full_response_len      = fpos;

	TEST_CHECK(pthread_create(&thread, NULL, serve_tc_then_tcp, &fx) == 0);

	query_len = make_query(query, 0x1234, DNS_FLAG_RD, "example.com");

	char addrs[1][INET6_ADDRSTRLEN];
	snprintf(addrs[0], INET6_ADDRSTRLEN, "127.0.0.1");
	rc = resolver_forward(addrs, 1, fx.port, false, false, NULL, NULL,
	                      query, query_len, response, sizeof(response),
	                      &response_len);

	TEST_CHECK(pthread_join(thread, NULL) == 0);
	close(fx.udp_fd);
	close(fx.tcp_listen_fd);

	/* TCP fallback must succeed */
	TEST_EXPECT_INT_EQ(rc, 0);

	/* Client ID must be restored */
	TEST_EXPECT_INT_EQ(wire_read_u16(response), 0x1234);

	/* Response must NOT have TC bit (we got the full answer via TCP) */
	TEST_CHECK((wire_read_u16(response + 2) & DNS_FLAG_TC) == 0);

	/* Must have one answer RR */
	TEST_EXPECT_INT_EQ(wire_read_u16(response + 6), 1);

	/* response_len must be the full TCP response length */
	TEST_EXPECT_SIZE_EQ(response_len, fx.full_response_len);
}

/* --- multi-address upstream failover --- */

static void
test_multi_addr_failover_skips_dead_first(void)
{
	struct sockaddr_in      upstream_addr;
	socklen_t               upstream_len = sizeof(upstream_addr);
	struct upstream_fixture fixture;
	pthread_t               thread;
	uint8_t                 query[DNS_MAX_MSG_SIZE];
	uint8_t                 response[DNS_MAX_MSG_SIZE];
	size_t                  query_len;
	size_t                  response_len = 0;
	int                     rc;

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
	TEST_CHECK(pthread_create(&thread, NULL, serve_upstream, &fixture)
	           == 0);

	query_len = make_query(query, 0x1234, DNS_FLAG_RD, "example.com");

	/* First addr is unrouted ENETUNREACH-style; second is the live mock. */
	char addrs[2][INET6_ADDRSTRLEN];
	snprintf(addrs[0], INET6_ADDRSTRLEN, "192.0.2.1"); /* TEST-NET-1 */
	snprintf(addrs[1], INET6_ADDRSTRLEN, "127.0.0.1");

	rc = resolver_forward(addrs, 2, ntohs(upstream_addr.sin_port), false,
	                      false, NULL, NULL, query, query_len, response,
	                      sizeof(response), &response_len);

	TEST_CHECK(pthread_join(thread, NULL) == 0);
	close(fixture.fd);

	/* Failover must succeed and the live mock must have observed traffic */
	TEST_EXPECT_INT_EQ(rc, 0);
	TEST_CHECK(fixture.observed_id != 0);
	TEST_EXPECT_INT_EQ(wire_read_u16(response), 0x1234);
}

int
main(void)
{
	test_id_randomized_flags_stripped();
	test_0x20_randomization_uppercase_present();
	test_tcp_fallback_on_truncation();
	test_multi_addr_failover_skips_dead_first();

	puts("resolver tests passed");
	return 0;
}
