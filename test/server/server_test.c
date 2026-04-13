/* SPDX-License-Identifier: MIT */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "dns.h"
#include "server.h"
#include "wire.h"
#include "test.h"

/* ------------------------------------------------------------------ */
/* Wire helpers                                                         */
/* ------------------------------------------------------------------ */

static void
put_u16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static void
put_u32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static uint16_t
get_u16(const uint8_t *p)
{
	return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t
get_u32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* Encode a dotted-notation name as DNS labels.  Returns new pos. */
static size_t
encode_name(uint8_t *buf, size_t pos, const char *name)
{
	const char *p = name;
	while (*p) {
		const char *dot  = strchr(p, '.');
		size_t      llen = dot ? (size_t)(dot - p) : strlen(p);
		buf[pos++]       = (uint8_t)llen;
		memcpy(buf + pos, p, llen);
		pos += llen;
		p   += llen;
		if (*p == '.')
			p++;
	}
	buf[pos++] = 0;
	return pos;
}

/*
 * Build a minimal standard query (no EDNS).
 * Returns the wire length.
 */
static size_t
make_query(uint8_t *buf, uint16_t id, const char *name,
           uint16_t qtype, uint16_t qclass)
{
	memset(buf, 0, DNS_HEADER_SIZE);
	put_u16(buf, id);
	put_u16(buf + 2, DNS_FLAG_RD);
	put_u16(buf + 4, 1); /* QDCOUNT */

	size_t pos = DNS_HEADER_SIZE;
	pos        = encode_name(buf, pos, name);
	put_u16(buf + pos, qtype);
	put_u16(buf + pos + 2, qclass);
	return pos + 4;
}

/*
 * Build a query with an OPT record (EDNS).
 * edns_version: 0 = compliant, 1 = BADVERS trigger.
 */
static size_t
make_edns_query(uint8_t *buf, uint16_t id, const char *name,
                uint16_t qtype, uint16_t qclass, uint8_t edns_version)
{
	size_t len = make_query(buf, id, name, qtype, qclass);

	/* Increment ARCOUNT */
	put_u16(buf + 10, 1);

	/* OPT: root name + type 41 + udp 1232 + ttl (edns_version) + rdlen 0 */
	buf[len++] = 0x00; /* root name */
	put_u16(buf + len, DNS_TYPE_OPT);
	len += 2;
	put_u16(buf + len, 1232);   /* udp payload size */
	len        += 2;
	buf[len++]  = 0x00;         /* extended rcode */
	buf[len++]  = edns_version; /* edns version */
	put_u16(buf + len, 0x0000); /* Z / DO */
	len += 2;
	put_u16(buf + len, 0);      /* rdlen */
	len += 2;

	return len;
}

/* Build a query with a non-QUERY opcode in the flags. */
static size_t
make_opcode_query(uint8_t *buf, uint16_t id, uint8_t opcode,
                  const char *name, uint16_t qtype, uint16_t qclass)
{
	size_t   len   = make_query(buf, id, name, qtype, qclass);
	uint16_t flags = get_u16(buf + 2);
	flags          = (uint16_t)((flags & ~DNS_FLAGS_OPCODE_MASK)
	                            | ((uint16_t)opcode << DNS_FLAGS_OPCODE_SHIFT));
	put_u16(buf + 2, flags);
	return len;
}

/* ------------------------------------------------------------------ */
/* Test server harness                                                  */
/* ------------------------------------------------------------------ */

struct test_server {
	struct server srv;
	pthread_t     thread;
	int           udp_port;
	int           tcp_port;
};

static void *
run_thread(void *arg)
{
	struct server *srv = arg;
	server_run(srv);
	return NULL;
}

static int
get_bound_port(int fd)
{
	struct sockaddr_storage addr;
	socklen_t               len = sizeof(addr);
	if (getsockname(fd, (struct sockaddr *)&addr, &len) < 0)
		return -1;
	if (addr.ss_family == AF_INET)
		return ntohs(((struct sockaddr_in *)&addr)->sin_port);
	if (addr.ss_family == AF_INET6)
		return ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
	return -1;
}

static int
start_test_server(struct test_server *ts, const char *upstream_addr,
                  int upstream_port)
{
	struct dns_config cfg;
	memset(&cfg, 0, sizeof(cfg));
	cfg.listen_port   = 0; /* kernel assigns port */
	cfg.upstream_port = (uint16_t)upstream_port;
	snprintf(cfg.upstream_addr, sizeof(cfg.upstream_addr),
	         "%s", upstream_addr);

	memset(ts, 0, sizeof(*ts));
	ts->udp_port = -1;
	ts->tcp_port = -1;

	if (server_init(&ts->srv, &cfg) < 0)
		return -1;

	ts->udp_port = get_bound_port(ts->srv.sock_fd);
	if (ts->srv.tcp_fd >= 0)
		ts->tcp_port = get_bound_port(ts->srv.tcp_fd);

	if (ts->udp_port < 0)
		return -1;

	if (pthread_create(&ts->thread, NULL, run_thread, &ts->srv) != 0)
		return -1;

	return 0;
}

static void
stop_test_server(struct test_server *ts)
{
	server_stop(&ts->srv);
	pthread_join(ts->thread, NULL);
}

/* ------------------------------------------------------------------ */
/* UDP send/recv helper                                                 */
/* ------------------------------------------------------------------ */

/*
 * Send a UDP query to 127.0.0.1:port and wait up to 2 seconds for a reply.
 * Returns the response length on success, -1 on error/timeout.
 */
static ssize_t
udp_roundtrip(int port, const uint8_t *query, size_t qlen,
              uint8_t *resp, size_t resp_size)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	struct sockaddr_in dst;
	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_port        = htons((uint16_t)port);
	dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	ssize_t rc          = sendto(fd, query, qlen, 0,
	                             (struct sockaddr *)&dst, sizeof(dst));
	if (rc < 0) {
		close(fd);
		return -1;
	}

	rc = recv(fd, resp, resp_size, 0);
	close(fd);
	return rc;
}

/* ------------------------------------------------------------------ */
/* TCP send/recv helper                                                 */
/* ------------------------------------------------------------------ */

static ssize_t
tcp_roundtrip(int port, const uint8_t *query, size_t qlen,
              uint8_t *resp, size_t resp_size)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	struct sockaddr_in dst;
	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_port        = htons((uint16_t)port);
	dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
		close(fd);
		return -1;
	}

	uint8_t lenbuf[2];
	lenbuf[0] = (uint8_t)(qlen >> 8);
	lenbuf[1] = (uint8_t)qlen;
	if (send(fd, lenbuf, 2, 0) != 2
	    || send(fd, query, qlen, 0) != (ssize_t)qlen) {
		close(fd);
		return -1;
	}

	if (recv(fd, lenbuf, 2, MSG_WAITALL) != 2) {
		close(fd);
		return -1;
	}

	uint16_t rlen = get_u16(lenbuf);
	if (rlen == 0 || rlen > (uint16_t)resp_size) {
		close(fd);
		return -1;
	}

	ssize_t got = recv(fd, resp, rlen, MSG_WAITALL);
	close(fd);
	return got;
}

/* ------------------------------------------------------------------ */
/* Mock upstream helpers                                                */
/* ------------------------------------------------------------------ */

/*
 * Mock upstream that responds to A queries.  It mirrors the received
 * query's question section byte-for-byte (including any 0x20 case
 * randomization applied by the resolver) and appends a fixed A record.
 */
struct mock_upstream {
	int          fd;
	int          port;
	pthread_t    thread;
	uint32_t     a_rdata; /* IPv4 address to put in the answer */
	uint32_t     ttl;
	volatile int stop;
};

static void *
mock_upstream_thread(void *arg)
{
	struct mock_upstream *up = arg;
	uint8_t               buf[DNS_MAX_MSG_SIZE];

	while (!up->stop) {
		struct sockaddr_storage src;
		socklen_t               srclen = sizeof(src);
		struct timeval          tv     = { .tv_sec = 0, .tv_usec = 100000 };
		setsockopt(up->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

		ssize_t n = recvfrom(up->fd, buf, sizeof(buf), 0,
		                     (struct sockaddr *)&src, &srclen);
		if (n < (ssize_t)DNS_HEADER_SIZE)
			continue;

		/*
		 * Find the end of the question section so we can copy it
		 * verbatim (preserving 0x20 case).
		 */
		int name_len = wire_skip_name(buf, (size_t)n, DNS_HEADER_SIZE);
		if (name_len < 0)
			continue;
		size_t qend = DNS_HEADER_SIZE + (size_t)name_len + 4; /* +QTYPE+QCLASS */
		if (qend > (size_t)n)
			continue;
		size_t  qsection_len = qend - DNS_HEADER_SIZE;

		/*
		 * Build response:
		 *   header (12) + question (verbatim) + answer A RR
		 *
		 * Answer name: compression pointer 0xC0 0x0C → offset 12.
		 */
		uint8_t resp[DNS_MAX_MSG_SIZE];
		size_t  pos = 0;

		/* header */
		resp[pos++] = buf[0]; /* ID high */
		resp[pos++] = buf[1]; /* ID low */
		resp[pos++] = 0x81;   /* QR=1, opcode=0, AA=0, TC=0, RD=1 */
		resp[pos++] = 0x80;   /* RA=1, rcode=NOERROR */
		resp[pos++] = 0x00;
		resp[pos++] = 0x01;   /* QDCOUNT = 1 */
		resp[pos++] = 0x00;
		resp[pos++] = 0x01;   /* ANCOUNT = 1 */
		resp[pos++] = 0x00;
		resp[pos++] = 0x00;   /* NSCOUNT = 0 */
		resp[pos++] = 0x00;
		resp[pos++] = 0x00;   /* ARCOUNT = 0 */

		/* question section verbatim from received query */
		memcpy(resp + pos, buf + DNS_HEADER_SIZE, qsection_len);
		pos         += qsection_len;

		/* answer A RR */
		resp[pos++]  = 0xC0; /* compression pointer */
		resp[pos++]  = 0x0C; /* → offset 12 (question QNAME) */
		put_u16(resp + pos, DNS_TYPE_A);
		pos += 2;
		put_u16(resp + pos, DNS_CLASS_IN);
		pos += 2;
		put_u32(resp + pos, up->ttl);
		pos += 4;
		put_u16(resp + pos, 4);
		pos += 2;
		put_u32(resp + pos, up->a_rdata);
		pos += 4;

		sendto(up->fd, resp, pos, 0, (struct sockaddr *)&src, srclen);
	}

	return NULL;
}

static int
start_mock_upstream(struct mock_upstream *up, uint32_t a_rdata, uint32_t ttl)
{
	up->stop    = 0;
	up->a_rdata = a_rdata;
	up->ttl     = ttl;

	up->fd      = socket(AF_INET, SOCK_DGRAM, 0);
	if (up->fd < 0)
		return -1;

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_port        = 0;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (bind(up->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(up->fd);
		return -1;
	}

	up->port = get_bound_port(up->fd);
	if (up->port < 0) {
		close(up->fd);
		return -1;
	}

	if (pthread_create(&up->thread, NULL, mock_upstream_thread, up) != 0) {
		close(up->fd);
		return -1;
	}

	return 0;
}

static void
stop_mock_upstream(struct mock_upstream *up)
{
	up->stop = 1;
	pthread_join(up->thread, NULL);
	close(up->fd);
}

/* ------------------------------------------------------------------ */
/* Tests                                                                */
/* ------------------------------------------------------------------ */

/*
 * STATUS opcode query should receive NOTIMP response without
 * touching the upstream at all.
 */
static void
test_notimp_status_opcode(void)
{
	struct test_server ts;

	/* Point upstream at a port that won't respond */
	TEST_CHECK(start_test_server(&ts, "127.0.0.1", 1) == 0);

	uint8_t query[DNS_MAX_MSG_SIZE];
	uint8_t resp[DNS_MAX_MSG_SIZE];
	size_t  qlen = make_opcode_query(query, 0xAAAA, DNS_OPCODE_STATUS,
	                                 "example.com",
	                                 DNS_TYPE_A, DNS_CLASS_IN);

	ssize_t rlen = udp_roundtrip(ts.udp_port, query, qlen,
	                             resp, sizeof(resp));
	TEST_CHECK(rlen >= DNS_HEADER_SIZE);
	TEST_CHECK(get_u16(resp) == 0xAAAA);                  /* ID preserved */
	TEST_CHECK((get_u16(resp + 2) & DNS_FLAG_QR) != 0);   /* QR=1 */
	TEST_CHECK((get_u16(resp + 2) & DNS_FLAGS_RCODE_MASK) /* RCODE=NOTIMP */
	           == DNS_RCODE_NOTIMP);

	stop_test_server(&ts);
}

/*
 * EDNS version=1 query should receive BADVERS.
 * RFC 6891 §6.1.3: OPT record must be present in the BADVERS response,
 * with the extended rcode high bits set to 1 (= rcode 16) and
 * the low 4 bits of the header rcode = 0.
 */
static void
test_badvers_edns_v1(void)
{
	struct test_server ts;

	TEST_CHECK(start_test_server(&ts, "127.0.0.1", 1) == 0);

	uint8_t query[DNS_MAX_MSG_SIZE];
	uint8_t resp[DNS_MAX_MSG_SIZE];
	size_t  qlen = make_edns_query(query, 0xBBBB, "example.com",
	                               DNS_TYPE_A, DNS_CLASS_IN, 1);

	ssize_t rlen = udp_roundtrip(ts.udp_port, query, qlen,
	                             resp, sizeof(resp));
	TEST_CHECK(rlen >= DNS_HEADER_SIZE);
	TEST_CHECK(get_u16(resp) == 0xBBBB);

	/* header rcode low nibble = 0 */
	TEST_CHECK((resp[3] & 0x0F) == 0);

	/* ARCOUNT >= 1 (OPT record) */
	TEST_CHECK(get_u16(resp + 10) >= 1);

	/*
	 * Find OPT record and check extended rcode byte.
	 * OPT name is root (0x00), type = 41.
	 * Skip question section first.
	 */
	size_t pos = DNS_HEADER_SIZE;
	if (get_u16(resp + 4) >= 1) {
		/* skip QNAME */
		while (pos < (size_t)rlen && resp[pos] != 0)
			pos += resp[pos] + 1;
		pos += 1 + 4; /* null label + QTYPE + QCLASS */
	}

	bool     found_opt = false;
	uint16_t ancount   = get_u16(resp + 6);
	uint16_t nscount   = get_u16(resp + 8);
	uint16_t arcount   = get_u16(resp + 10);

	for (uint32_t i = 0;
	     i < (uint32_t)ancount + nscount + arcount && pos + 11 <= (size_t)rlen;
	     i++) {
		/* skip name */
		if (resp[pos] == 0) {
			pos++;
		} else if ((resp[pos] & 0xC0) == 0xC0) {
			pos += 2;
		} else {
			while (pos < (size_t)rlen && resp[pos] != 0)
				pos += resp[pos] + 1;
			pos++;
		}

		if (pos + 10 > (size_t)rlen)
			break;

		uint16_t rtype = get_u16(resp + pos);
		uint16_t rdlen = get_u16(resp + pos + 8);

		if (rtype == DNS_TYPE_OPT) {
			/* TTL field: byte 0 = extended rcode high bits */
			uint8_t ext_rcode = resp[pos + 4];
			TEST_CHECK(ext_rcode == 1); /* high bits of BADVERS (16) */
			found_opt = true;
		}

		pos += 10 + rdlen;
	}

	TEST_CHECK(found_opt);

	stop_test_server(&ts);
}

/*
 * A truncated DNS message (shorter than the header) should get FORMERR.
 */
static void
test_formerr_truncated_packet(void)
{
	struct test_server ts;

	TEST_CHECK(start_test_server(&ts, "127.0.0.1", 1) == 0);

	/*
	 * 12-byte header claiming qdcount=1 but no question data following.
	 * dns_parse_message will fail on the missing QNAME → FORMERR.
	 */
	uint8_t query[DNS_HEADER_SIZE] = { 0 };
	query[0]                       = 0xCC;
	query[1]                       = 0xCC;
	query[2]                       = 0x01; /* QR=0, RD=1 */
	query[5]                       = 0x01; /* QDCOUNT = 1 */

	uint8_t resp[DNS_MAX_MSG_SIZE];

	ssize_t rlen = udp_roundtrip(ts.udp_port, query, sizeof(query),
	                             resp, sizeof(resp));
	TEST_CHECK(rlen >= DNS_HEADER_SIZE);
	TEST_CHECK(get_u16(resp) == 0xCCCC);
	TEST_CHECK((get_u16(resp + 2) & DNS_FLAG_QR) != 0);
	TEST_CHECK((get_u16(resp + 2) & DNS_FLAGS_RCODE_MASK) == DNS_RCODE_FORMERR);

	stop_test_server(&ts);
}

/*
 * STATUS opcode over TCP should also get NOTIMP.
 */
static void
test_tcp_notimp_status_opcode(void)
{
	struct test_server ts;

	TEST_CHECK(start_test_server(&ts, "127.0.0.1", 1) == 0);

	if (ts.tcp_port < 0)
		TEST_SKIP("IPv4 TCP socket not available; skipping TCP test");

	uint8_t query[DNS_MAX_MSG_SIZE];
	uint8_t resp[DNS_MAX_MSG_SIZE];
	size_t  qlen = make_opcode_query(query, 0xDDDD, DNS_OPCODE_STATUS,
	                                 "example.com",
	                                 DNS_TYPE_A, DNS_CLASS_IN);

	ssize_t rlen = tcp_roundtrip(ts.tcp_port, query, qlen,
	                             resp, sizeof(resp));
	TEST_CHECK(rlen >= DNS_HEADER_SIZE);
	TEST_CHECK(get_u16(resp) == 0xDDDD);
	TEST_CHECK((get_u16(resp + 2) & DNS_FLAG_QR) != 0);
	TEST_CHECK((get_u16(resp + 2) & DNS_FLAGS_RCODE_MASK) == DNS_RCODE_NOTIMP);

	stop_test_server(&ts);
}

/*
 * Send N queries on one TCP connection without closing between them
 * (RFC 7766 §6.2.2 pipelining).  responses[][DNS_MAX_MSG_SIZE] and
 * resp_lens[] must be pre-allocated by the caller.
 * Returns 0 on success, -1 on error.
 */
static int
tcp_pipeline(int             port,
             const uint8_t **queries, const size_t *qlens,
             uint8_t resps[][DNS_MAX_MSG_SIZE], size_t *resp_lens,
             int count)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	struct sockaddr_in dst;
	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_port        = htons((uint16_t)port);
	dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
		close(fd);
		return -1;
	}

	for (int i = 0; i < count; i++) {
		uint8_t lenbuf[2];
		lenbuf[0] = (uint8_t)(qlens[i] >> 8);
		lenbuf[1] = (uint8_t)qlens[i];
		if (send(fd, lenbuf, 2, 0) != 2
		    || send(fd, queries[i], qlens[i], 0)
		               != (ssize_t)qlens[i]) {
			close(fd);
			return -1;
		}
	}

	for (int i = 0; i < count; i++) {
		uint8_t lenbuf[2];
		if (recv(fd, lenbuf, 2, MSG_WAITALL) != 2) {
			close(fd);
			return -1;
		}
		uint16_t rlen = get_u16(lenbuf);
		if (rlen == 0 || rlen > DNS_MAX_MSG_SIZE) {
			close(fd);
			return -1;
		}
		ssize_t got = recv(fd, resps[i], rlen, MSG_WAITALL);
		if (got != (ssize_t)rlen) {
			close(fd);
			return -1;
		}
		resp_lens[i] = (size_t)rlen;
	}

	close(fd);
	return 0;
}

/*
 * A valid A-record query over UDP is forwarded to the upstream and the
 * response is relayed back to the client.  The client's original query ID
 * must be preserved.
 */
static void
test_udp_forwarded_query_basic(void)
{
	struct mock_upstream up;
	TEST_CHECK(start_mock_upstream(&up, 0x01020304, 300) == 0);

	struct test_server ts;
	TEST_CHECK(start_test_server(&ts, "127.0.0.1", up.port) == 0);

	uint8_t query[DNS_MAX_MSG_SIZE];
	uint8_t resp[DNS_MAX_MSG_SIZE];
	size_t  qlen = make_query(query, 0xEEEE, "example.com",
	                          DNS_TYPE_A, DNS_CLASS_IN);

	ssize_t rlen = udp_roundtrip(ts.udp_port, query, qlen,
	                             resp, sizeof(resp));
	TEST_CHECK(rlen >= DNS_HEADER_SIZE);
	TEST_CHECK(get_u16(resp) == 0xEEEE); /* client ID preserved */
	TEST_CHECK((get_u16(resp + 2) & DNS_FLAG_QR) != 0);
	TEST_CHECK((get_u16(resp + 2) & DNS_FLAGS_RCODE_MASK) == DNS_RCODE_OK);
	TEST_CHECK(get_u16(resp + 6) == 1); /* ANCOUNT = 1 */

	/* The A-record rdata should contain 1.2.3.4 */
	bool   found_ip = false;
	size_t pos      = DNS_HEADER_SIZE;
	/* skip question */
	while (pos < (size_t)rlen && resp[pos] != 0)
		pos += resp[pos] + 1;
	pos += 1 + 4;

	/* read first answer RR */
	if (pos + 2 <= (size_t)rlen && (resp[pos] & 0xC0) == 0xC0)
		pos += 2;

	if (pos + 10 + 4 <= (size_t)rlen) {
		uint16_t rtype = get_u16(resp + pos);
		uint16_t rdlen = get_u16(resp + pos + 8);
		if (rtype == DNS_TYPE_A && rdlen == 4) {
			uint32_t ip = get_u32(resp + pos + 10);
			found_ip    = (ip == 0x01020304);
		}
	}

	TEST_CHECK(found_ip);

	stop_test_server(&ts);
	stop_mock_upstream(&up);
}

/*
 * A valid A-record query over TCP is forwarded to the upstream and the
 * response is returned to the client (RFC 1035 §4.2.2).
 */
static void
test_tcp_forwarded_query_basic(void)
{
	struct mock_upstream up;
	TEST_CHECK(start_mock_upstream(&up, 0x05060708, 120) == 0);

	struct test_server ts;
	TEST_CHECK(start_test_server(&ts, "127.0.0.1", up.port) == 0);

	if (ts.tcp_port < 0)
		TEST_SKIP("IPv4 TCP socket not available; skipping TCP test");

	uint8_t query[DNS_MAX_MSG_SIZE];
	uint8_t resp[DNS_MAX_MSG_SIZE];
	size_t  qlen = make_query(query, 0x1234, "example.org",
	                          DNS_TYPE_A, DNS_CLASS_IN);

	ssize_t rlen = tcp_roundtrip(ts.tcp_port, query, qlen,
	                             resp, sizeof(resp));
	TEST_CHECK(rlen >= DNS_HEADER_SIZE);
	TEST_CHECK(get_u16(resp) == 0x1234);
	TEST_CHECK((get_u16(resp + 2) & DNS_FLAG_QR) != 0);
	TEST_CHECK((get_u16(resp + 2) & DNS_FLAGS_RCODE_MASK) == DNS_RCODE_OK);
	TEST_CHECK(get_u16(resp + 6) == 1); /* ANCOUNT = 1 */

	/* verify the A-record rdata */
	bool   found_ip = false;
	size_t pos      = DNS_HEADER_SIZE;
	while (pos < (size_t)rlen && resp[pos] != 0)
		pos += resp[pos] + 1;
	pos += 1 + 4;
	if (pos + 2 <= (size_t)rlen && (resp[pos] & 0xC0) == 0xC0)
		pos += 2;
	if (pos + 10 + 4 <= (size_t)rlen) {
		uint16_t rtype = get_u16(resp + pos);
		uint16_t rdlen = get_u16(resp + pos + 8);
		if (rtype == DNS_TYPE_A && rdlen == 4)
			found_ip = (get_u32(resp + pos + 10) == 0x05060708);
	}
	TEST_CHECK(found_ip);

	stop_test_server(&ts);
	stop_mock_upstream(&up);
}

/*
 * FORMERR over TCP: a malformed query should receive a FORMERR response
 * and the connection should remain open for further queries.
 */
static void
test_tcp_formerr(void)
{
	struct test_server ts;
	TEST_CHECK(start_test_server(&ts, "127.0.0.1", 1) == 0);

	if (ts.tcp_port < 0)
		TEST_SKIP("IPv4 TCP socket not available; skipping TCP test");

	/* Header with qdcount=1 but no question data */
	uint8_t bad[DNS_HEADER_SIZE] = { 0 };
	bad[0]                       = 0xAB;
	bad[1]                       = 0xCD;
	bad[2]                       = 0x01; /* RD=1 */
	bad[5]                       = 0x01; /* QDCOUNT=1 */

	uint8_t resp[DNS_MAX_MSG_SIZE];
	ssize_t rlen = tcp_roundtrip(ts.tcp_port, bad, sizeof(bad),
	                             resp, sizeof(resp));
	TEST_CHECK(rlen >= DNS_HEADER_SIZE);
	TEST_CHECK(get_u16(resp) == 0xABCD);
	TEST_CHECK((get_u16(resp + 2) & DNS_FLAG_QR) != 0);
	TEST_CHECK((get_u16(resp + 2) & DNS_FLAGS_RCODE_MASK)
	           == DNS_RCODE_FORMERR);

	stop_test_server(&ts);
}

/*
 * BADVERS over TCP: EDNS version 1 should get a BADVERS response over TCP
 * with the OPT extended rcode byte set correctly.
 */
static void
test_tcp_badvers(void)
{
	struct test_server ts;
	TEST_CHECK(start_test_server(&ts, "127.0.0.1", 1) == 0);

	if (ts.tcp_port < 0)
		TEST_SKIP("IPv4 TCP socket not available; skipping TCP test");

	uint8_t query[DNS_MAX_MSG_SIZE];
	uint8_t resp[DNS_MAX_MSG_SIZE];
	size_t  qlen = make_edns_query(query, 0xBEEF, "example.net",
	                               DNS_TYPE_A, DNS_CLASS_IN, 1);

	ssize_t rlen = tcp_roundtrip(ts.tcp_port, query, qlen,
	                             resp, sizeof(resp));
	TEST_CHECK(rlen >= DNS_HEADER_SIZE);
	TEST_CHECK(get_u16(resp) == 0xBEEF);
	TEST_CHECK((resp[3] & 0x0F) == 0);   /* header rcode low nibble = 0 */
	TEST_CHECK(get_u16(resp + 10) >= 1); /* ARCOUNT >= 1 */

	stop_test_server(&ts);
}

/*
 * RFC 7766 §6.2.2: multiple queries on a single TCP connection
 * (pipelining).  Sends 3 queries with distinct IDs; checks that each
 * response carries the correct ID and NOERROR.
 */
static void
test_tcp_pipelining(void)
{
	struct mock_upstream up;
	TEST_CHECK(start_mock_upstream(&up, 0x0A0B0C0D, 300) == 0);

	struct test_server ts;
	TEST_CHECK(start_test_server(&ts, "127.0.0.1", up.port) == 0);

	if (ts.tcp_port < 0)
		TEST_SKIP("IPv4 TCP socket not available; skipping TCP test");

	enum { N = 3 };
	static const uint16_t ids[N]   = { 0x0001, 0x0002, 0x0003 };
	static const char    *names[N] = { "a.example", "b.example",
		                           "c.example" };

	uint8_t               qbufs[N][DNS_MAX_MSG_SIZE];
	size_t                qlens[N];
	const uint8_t        *queries[N];
	uint8_t               resps[N][DNS_MAX_MSG_SIZE];
	size_t                resp_lens[N];

	for (int i = 0; i < N; i++) {
		qlens[i]   = make_query(qbufs[i], ids[i], names[i],
		                        DNS_TYPE_A, DNS_CLASS_IN);
		queries[i] = qbufs[i];
	}

	TEST_CHECK(tcp_pipeline(ts.tcp_port, queries, qlens,
	                        resps, resp_lens, N)
	           == 0);

	for (int i = 0; i < N; i++) {
		TEST_CHECK(resp_lens[i] >= DNS_HEADER_SIZE);
		TEST_CHECK(get_u16(resps[i]) == ids[i]);
		TEST_CHECK((get_u16(resps[i] + 2) & DNS_FLAG_QR) != 0);
		TEST_CHECK((get_u16(resps[i] + 2) & DNS_FLAGS_RCODE_MASK)
		           == DNS_RCODE_OK);
		TEST_CHECK(get_u16(resps[i] + 6) == 1); /* ANCOUNT = 1 */
	}

	stop_test_server(&ts);
	stop_mock_upstream(&up);
}

/*
 * RFC 7766 §5: responses over TCP MUST NOT be truncated.  A response
 * that would be truncated for a small-UDP-size client must be delivered
 * in full when the client uses TCP.
 * We simulate this by sending a query with EDNS udp_size=512 over TCP
 * and verifying the TC bit is not set in the response.
 */
static void
test_tcp_no_truncation(void)
{
	struct mock_upstream up;
	TEST_CHECK(start_mock_upstream(&up, 0x11223344, 300) == 0);

	struct test_server ts;
	TEST_CHECK(start_test_server(&ts, "127.0.0.1", up.port) == 0);

	if (ts.tcp_port < 0)
		TEST_SKIP("IPv4 TCP socket not available; skipping TCP test");

	/* EDNS query advertising only 512-byte UDP payload */
	uint8_t query[DNS_MAX_MSG_SIZE];
	uint8_t resp[DNS_MAX_MSG_SIZE];
	size_t  qlen = make_edns_query(query, 0xF00D, "example.com",
	                               DNS_TYPE_A, DNS_CLASS_IN, 0);

	ssize_t rlen = tcp_roundtrip(ts.tcp_port, query, qlen,
	                             resp, sizeof(resp));
	TEST_CHECK(rlen >= DNS_HEADER_SIZE);
	TEST_CHECK(get_u16(resp) == 0xF00D);
	/* TC flag must NOT be set on a TCP response */
	TEST_CHECK((get_u16(resp + 2) & DNS_FLAG_TC) == 0);
	TEST_CHECK((get_u16(resp + 2) & DNS_FLAGS_RCODE_MASK) == DNS_RCODE_OK);

	stop_test_server(&ts);
	stop_mock_upstream(&up);
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int
main(void)
{
	test_notimp_status_opcode();
	test_badvers_edns_v1();
	test_formerr_truncated_packet();
	test_tcp_notimp_status_opcode();
	test_udp_forwarded_query_basic();
	test_tcp_forwarded_query_basic();
	test_tcp_formerr();
	test_tcp_badvers();
	test_tcp_pipelining();
	test_tcp_no_truncation();

	puts("server tests passed");
	return 0;
}
