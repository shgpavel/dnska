/* SPDX-License-Identifier: MIT */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "dns.h"
#include "resolver.h"
#include "test.h"
#include "wire.h"

enum {
	TEST_DNS_TYPE_SVCB       = 64,
	TEST_EDNS_OPTION_PADDING = 12,
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

static int
make_selfsigned_cert(SSL_CTX *ctx)
{
	EVP_PKEY *pkey = EVP_EC_gen("P-256");
	if (pkey == NULL)
		return -1;

	X509 *cert = X509_new();
	if (cert == NULL) {
		EVP_PKEY_free(pkey);
		return -1;
	}

	X509_NAME *name;
	int        ok = X509_set_version(cert, 2) == 1
	                && ASN1_INTEGER_set(X509_get_serialNumber(cert), 1)
	                           == 1
	                && X509_gmtime_adj(X509_getm_notBefore(cert), 0)
	                           != NULL
	                && X509_gmtime_adj(X509_getm_notAfter(cert),
	                                   (long)30 * 24 * 60 * 60)
	                           != NULL
	                && X509_set_pubkey(cert, pkey) == 1;
	if (!ok) {
		X509_free(cert);
		EVP_PKEY_free(pkey);
		return -1;
	}

	name = X509_get_subject_name(cert);
	ok   = X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
	                                  (const unsigned char *)"dnska",
	                                  -1, -1, 0)
	               == 1
	       && X509_set_issuer_name(cert, name) == 1
	       && X509_sign(cert, pkey, EVP_sha256()) > 0
	       && SSL_CTX_use_certificate(ctx, cert) == 1
	       && SSL_CTX_use_PrivateKey(ctx, pkey) == 1;

	X509_free(cert);
	EVP_PKEY_free(pkey);
	return ok ? 0 : -1;
}

static int
ssl_read_exact(SSL *ssl, uint8_t *buf, size_t len)
{
	size_t pos = 0;

	while (pos < len) {
		int n = SSL_read(ssl, buf + pos, (int)(len - pos));
		if (n <= 0)
			return -1;
		pos += (size_t)n;
	}

	return 0;
}

static int
ssl_write_exact(SSL *ssl, const uint8_t *buf, size_t len)
{
	size_t pos = 0;

	while (pos < len) {
		int n = SSL_write(ssl, buf + pos, (int)(len - pos));
		if (n <= 0)
			return -1;
		pos += (size_t)n;
	}

	return 0;
}

static bool
find_edns_option(const uint8_t *query, size_t query_len, uint16_t option_code,
                 uint16_t *option_len)
{
	size_t opt_off;
	size_t opt_total;
	int    rc = dns_find_opt(query, query_len, &opt_off, &opt_total);

	if (rc != 0)
		return false;

	int n = wire_skip_name(query, query_len, opt_off);
	if (n < 0)
		return false;

	size_t fixed_off = opt_off + (size_t)n;
	if (fixed_off + 10 > query_len)
		return false;

	size_t   rdata_off = fixed_off + 10;
	uint16_t rdlen     = wire_read_u16(query + fixed_off + 8);
	size_t   pos       = rdata_off;
	size_t   end       = rdata_off + rdlen;

	if (end > query_len)
		return false;

	while (pos < end) {
		if (end - pos < 4)
			return false;
		uint16_t code = wire_read_u16(query + pos);
		uint16_t len  = wire_read_u16(query + pos + 2);
		if (pos + 4 + len > end)
			return false;
		if (code == option_code) {
			*option_len = len;
			return true;
		}
		pos += 4 + len;
	}

	return false;
}

static bool
find_padding_option(const uint8_t *query, size_t query_len,
                    uint16_t *padding_len)
{
	return find_edns_option(query, query_len,
	                        TEST_EDNS_OPTION_PADDING, padding_len);
}

static size_t
append_test_opt(uint8_t *query, size_t query_len)
{
	size_t pos   = query_len;

	query[pos++] = 0; /* root owner */
	write_u16(query + pos, DNS_TYPE_OPT);
	write_u16(query + pos + 2, 1232);
	write_u16(query + pos + 4, 0);
	write_u16(query + pos + 6, 0);
	size_t rdlen_off  = pos + 8;
	pos              += 10;

	/* Preserve a non-padding option across padding replacement. */
	write_u16(query + pos, DNS_EDNS_OPTION_NSID);
	write_u16(query + pos + 2, 2);
	query[pos + 4]  = 0xAB;
	query[pos + 5]  = 0xCD;
	pos            += 6;

	/* Existing client padding should be replaced, not duplicated. */
	write_u16(query + pos, TEST_EDNS_OPTION_PADDING);
	write_u16(query + pos + 2, 5);
	memset(query + pos + 4, 0, 5);
	pos += 9;

	write_u16(query + rdlen_off, 15);
	write_u16(query + 10, 1);
	return pos;
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
	rc = resolver_forward_transport(addrs, 1, ntohs(upstream_addr.sin_port),
	                                DNS_UPSTREAM_TRANSPORT_PLAIN, NULL,
	                                NULL, 0, query, query_len,
	                                response, sizeof(response),
	                                &response_len);

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
	resolver_forward_transport(addrs, 1, ntohs(upstream_addr.sin_port),
	                           DNS_UPSTREAM_TRANSPORT_PLAIN, NULL, NULL,
	                           0, query, query_len, response,
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

/* --- EDNS padding for encrypted upstreams --- */

struct dot_padding_fixture {
	int      fd;
	SSL_CTX *ctx;
	uint16_t port;
	uint8_t  received_query[DNS_MAX_MSG_SIZE];
	size_t   received_len;
};

static void *
serve_dot_padding(void *arg)
{
	struct dot_padding_fixture *fixture = arg;
	struct sockaddr_in          client_addr;
	socklen_t                   client_len = sizeof(client_addr);
	int                         conn;
	SSL                        *ssl;
	uint8_t                     len_buf[2];
	uint8_t                     response[DNS_MAX_MSG_SIZE];

	conn = accept(fixture->fd, (struct sockaddr *)&client_addr,
	              &client_len);
	TEST_CHECK(conn >= 0);

	ssl = SSL_new(fixture->ctx);
	TEST_CHECK(ssl != NULL);
	TEST_CHECK(SSL_set_fd(ssl, conn) == 1);
	TEST_CHECK(SSL_accept(ssl) > 0);

	TEST_CHECK(ssl_read_exact(ssl, len_buf, 2) == 0);
	fixture->received_len = (size_t)(((uint16_t)len_buf[0] << 8) | len_buf[1]);
	TEST_CHECK(fixture->received_len <= sizeof(fixture->received_query));
	TEST_CHECK(ssl_read_exact(ssl, fixture->received_query,
	                          fixture->received_len)
	           == 0);

	memcpy(response, fixture->received_query, fixture->received_len);
	write_u16(response + 2,
	          DNS_FLAG_QR | DNS_FLAG_RA | (wire_read_u16(response + 2) & DNS_FLAG_RD));
	len_buf[0] = (uint8_t)(fixture->received_len >> 8);
	len_buf[1] = (uint8_t)fixture->received_len;
	TEST_CHECK(ssl_write_exact(ssl, len_buf, 2) == 0);
	TEST_CHECK(ssl_write_exact(ssl, response, fixture->received_len)
	           == 0);

	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(conn);
	return NULL;
}

static int
run_dot_padding_forward(struct dot_padding_fixture *fixture,
                        const uint8_t *query, size_t query_len,
                        uint16_t padding_block,
                        uint8_t *response, size_t response_size,
                        size_t *response_len)
{
	struct sockaddr_in addr;
	socklen_t          addr_len = sizeof(addr);
	pthread_t          thread;
	int                rc;

	memset(fixture, 0, sizeof(*fixture));
	fixture->fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fixture->fd < 0 && (errno == EPERM || errno == EACCES))
		TEST_SKIP("resolver tests skipped: TCP sockets unavailable");
	TEST_CHECK(fixture->fd >= 0);

	int optval = 1;
	setsockopt(fixture->fd, SOL_SOCKET, SO_REUSEADDR,
	           &optval, sizeof(optval));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_port        = 0;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	TEST_CHECK(bind(fixture->fd, (struct sockaddr *)&addr, sizeof(addr))
	           == 0);
	TEST_CHECK(getsockname(fixture->fd, (struct sockaddr *)&addr,
	                       &addr_len)
	           == 0);
	TEST_CHECK(listen(fixture->fd, 1) == 0);
	fixture->port = ntohs(addr.sin_port);

	fixture->ctx  = SSL_CTX_new(TLS_server_method());
	TEST_CHECK(fixture->ctx != NULL);
	SSL_CTX_set_min_proto_version(fixture->ctx, TLS1_2_VERSION);
	TEST_CHECK(make_selfsigned_cert(fixture->ctx) == 0);

	TEST_CHECK(pthread_create(&thread, NULL, serve_dot_padding,
	                          fixture)
	           == 0);

	resolver_set_tls_config(NULL, NULL, true);

	char addrs[1][INET6_ADDRSTRLEN];
	snprintf(addrs[0], INET6_ADDRSTRLEN, "127.0.0.1");
	rc = resolver_forward_transport(addrs, 1, fixture->port,
	                                DNS_UPSTREAM_TRANSPORT_DOT, NULL,
	                                "localhost", padding_block,
	                                query, query_len,
	                                response, response_size,
	                                response_len);

	TEST_CHECK(pthread_join(thread, NULL) == 0);
	close(fixture->fd);
	SSL_CTX_free(fixture->ctx);
	return rc;
}

static void
test_dot_edns_padding_block_128(void)
{
	struct dot_padding_fixture fixture;
	uint8_t                    query[DNS_MAX_MSG_SIZE];
	uint8_t                    response[DNS_MAX_MSG_SIZE];
	size_t                     query_len;
	size_t                     response_len = 0;
	uint16_t                   padding_len  = 0;

	query_len                               = make_query(query, 0xCAFE, DNS_FLAG_RD, "example.com");
	int rc                                  = run_dot_padding_forward(&fixture, query, query_len, 128,
	                                                                  response, sizeof(response),
	                                                                  &response_len);

	TEST_EXPECT_INT_EQ(rc, 0);
	TEST_CHECK(fixture.received_len > query_len);
	TEST_EXPECT_SIZE_EQ(fixture.received_len % 128, 0);
	TEST_CHECK(find_padding_option(fixture.received_query,
	                               fixture.received_len,
	                               &padding_len));
	TEST_EXPECT_INT_EQ(padding_len, 84);
	TEST_EXPECT_INT_EQ(wire_read_u16(response), 0xCAFE);
}

static void
test_dot_edns_padding_updates_existing_opt(void)
{
	struct dot_padding_fixture fixture;
	uint8_t                    query[DNS_MAX_MSG_SIZE];
	uint8_t                    response[DNS_MAX_MSG_SIZE];
	size_t                     query_len;
	size_t                     response_len = 0;
	uint16_t                   nsid_len     = 0;
	uint16_t                   padding_len  = 0;

	query_len                               = make_query(query, 0xBEEF, DNS_FLAG_RD, "example.com");
	query_len                               = append_test_opt(query, query_len);

	int rc                                  = run_dot_padding_forward(&fixture, query, query_len, 128,
	                                                                  response, sizeof(response),
	                                                                  &response_len);

	TEST_EXPECT_INT_EQ(rc, 0);
	TEST_EXPECT_SIZE_EQ(fixture.received_len % 128, 0);
	TEST_CHECK(find_edns_option(fixture.received_query,
	                            fixture.received_len,
	                            DNS_EDNS_OPTION_NSID,
	                            &nsid_len));
	TEST_EXPECT_INT_EQ(nsid_len, 2);
	TEST_CHECK(find_padding_option(fixture.received_query,
	                               fixture.received_len,
	                               &padding_len));
	TEST_EXPECT_INT_EQ(padding_len, 78);
	TEST_EXPECT_INT_EQ(wire_read_u16(response), 0xBEEF);
}

struct dot_reuse_fixture {
	int      fd;
	SSL_CTX *ctx;
	uint16_t port;
	int      accepted_connections;
	uint8_t  received_query[2][DNS_MAX_MSG_SIZE];
	size_t   received_len[2];
};

static void *
serve_dot_reuse(void *arg)
{
	struct dot_reuse_fixture *fixture = arg;
	struct sockaddr_in        client_addr;
	socklen_t                 client_len = sizeof(client_addr);
	int                       conn;
	SSL                      *ssl;
	uint8_t                   len_buf[2];
	uint8_t                   response[DNS_MAX_MSG_SIZE];

	conn = accept(fixture->fd, (struct sockaddr *)&client_addr,
	              &client_len);
	TEST_CHECK(conn >= 0);
	fixture->accepted_connections++;

	ssl = SSL_new(fixture->ctx);
	TEST_CHECK(ssl != NULL);
	TEST_CHECK(SSL_set_fd(ssl, conn) == 1);
	TEST_CHECK(SSL_accept(ssl) > 0);

	for (size_t i = 0; i < 2; i++) {
		TEST_CHECK(ssl_read_exact(ssl, len_buf, 2) == 0);
		fixture->received_len[i] = (size_t)(((uint16_t)len_buf[0] << 8) | len_buf[1]);
		TEST_CHECK(fixture->received_len[i]
		           <= sizeof(fixture->received_query[i]));
		TEST_CHECK(ssl_read_exact(ssl, fixture->received_query[i],
		                          fixture->received_len[i])
		           == 0);

		memcpy(response, fixture->received_query[i],
		       fixture->received_len[i]);
		write_u16(response + 2,
		          DNS_FLAG_QR | DNS_FLAG_RA | (wire_read_u16(response + 2) & DNS_FLAG_RD));
		len_buf[0] = (uint8_t)(fixture->received_len[i] >> 8);
		len_buf[1] = (uint8_t)fixture->received_len[i];
		TEST_CHECK(ssl_write_exact(ssl, len_buf, 2) == 0);
		TEST_CHECK(ssl_write_exact(ssl, response,
		                           fixture->received_len[i])
		           == 0);
	}

	SSL_free(ssl);
	close(conn);
	return NULL;
}

static void
test_dot_tls_connection_reused_and_padding_is_per_query(void)
{
	struct dot_reuse_fixture fixture;
	struct sockaddr_in       addr;
	socklen_t                addr_len = sizeof(addr);
	pthread_t                thread;
	uint8_t                  query1[DNS_MAX_MSG_SIZE];
	uint8_t                  query2[DNS_MAX_MSG_SIZE];
	uint8_t                  response[DNS_MAX_MSG_SIZE];
	size_t                   query1_len;
	size_t                   query2_len;
	size_t                   response_len = 0;
	uint16_t                 padding_len1 = 0;
	uint16_t                 padding_len2 = 0;

	memset(&fixture, 0, sizeof(fixture));
	fixture.fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fixture.fd < 0 && (errno == EPERM || errno == EACCES))
		TEST_SKIP("resolver tests skipped: TCP sockets unavailable");
	TEST_CHECK(fixture.fd >= 0);

	int optval = 1;
	setsockopt(fixture.fd, SOL_SOCKET, SO_REUSEADDR,
	           &optval, sizeof(optval));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_port        = 0;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	TEST_CHECK(bind(fixture.fd, (struct sockaddr *)&addr, sizeof(addr))
	           == 0);
	TEST_CHECK(getsockname(fixture.fd, (struct sockaddr *)&addr,
	                       &addr_len)
	           == 0);
	TEST_CHECK(listen(fixture.fd, 1) == 0);
	fixture.port = ntohs(addr.sin_port);

	fixture.ctx  = SSL_CTX_new(TLS_server_method());
	TEST_CHECK(fixture.ctx != NULL);
	SSL_CTX_set_min_proto_version(fixture.ctx, TLS1_2_VERSION);
	TEST_CHECK(make_selfsigned_cert(fixture.ctx) == 0);

	TEST_CHECK(pthread_create(&thread, NULL, serve_dot_reuse,
	                          &fixture)
	           == 0);

	resolver_set_tls_config(NULL, NULL, true);

	query1_len = make_query(query1, 0x1111, DNS_FLAG_RD, "example.com");
	query2_len = make_query(query2, 0x2222, DNS_FLAG_RD, "example.com");
	query2_len = append_test_opt(query2, query2_len);

	char addrs[1][INET6_ADDRSTRLEN];
	snprintf(addrs[0], INET6_ADDRSTRLEN, "127.0.0.1");
	int rc1 = resolver_forward_transport(
	        addrs, 1, fixture.port, DNS_UPSTREAM_TRANSPORT_DOT, NULL,
	        "localhost", 128, query1, query1_len, response,
	        sizeof(response), &response_len);
	int rc2 = resolver_forward_transport(
	        addrs, 1, fixture.port, DNS_UPSTREAM_TRANSPORT_DOT, NULL,
	        "localhost", 128, query2, query2_len, response,
	        sizeof(response), &response_len);

	TEST_CHECK(pthread_join(thread, NULL) == 0);
	close(fixture.fd);
	SSL_CTX_free(fixture.ctx);

	TEST_EXPECT_INT_EQ(rc1, 0);
	TEST_EXPECT_INT_EQ(rc2, 0);
	TEST_EXPECT_INT_EQ(fixture.accepted_connections, 1);
	TEST_CHECK(fixture.received_len[0] > query1_len);
	TEST_CHECK(fixture.received_len[1] > query2_len);
	TEST_EXPECT_SIZE_EQ(fixture.received_len[0] % 128, 0);
	TEST_EXPECT_SIZE_EQ(fixture.received_len[1] % 128, 0);
	TEST_CHECK(find_padding_option(fixture.received_query[0],
	                               fixture.received_len[0],
	                               &padding_len1));
	TEST_CHECK(find_padding_option(fixture.received_query[1],
	                               fixture.received_len[1],
	                               &padding_len2));
	TEST_EXPECT_INT_EQ(padding_len1, 84);
	TEST_EXPECT_INT_EQ(padding_len2, 78);
}

static void
test_plain_udp_does_not_add_edns_padding(void)
{
	struct sockaddr_in  upstream_addr;
	socklen_t           upstream_len = sizeof(upstream_addr);
	struct echo_fixture fixture;
	pthread_t           thread;
	uint8_t             query[DNS_MAX_MSG_SIZE];
	uint8_t             response[DNS_MAX_MSG_SIZE];
	size_t              query_len;
	size_t              response_len = 0;
	uint16_t            padding_len  = 0;
	int                 rc;

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

	query_len = make_query(query, 0xC001, DNS_FLAG_RD,
	                       "plain-padding.example");

	char addrs[1][INET6_ADDRSTRLEN];
	snprintf(addrs[0], INET6_ADDRSTRLEN, "127.0.0.1");
	rc = resolver_forward_transport(addrs, 1, ntohs(upstream_addr.sin_port),
	                                DNS_UPSTREAM_TRANSPORT_PLAIN, NULL,
	                                NULL, 128, query, query_len,
	                                response, sizeof(response),
	                                &response_len);

	TEST_CHECK(pthread_join(thread, NULL) == 0);
	close(fixture.fd);

	TEST_EXPECT_INT_EQ(rc, 0);
	TEST_CHECK(fixture.received_len >= (ssize_t)DNS_HEADER_SIZE);
	TEST_CHECK(!find_padding_option(fixture.received_query,
	                                (size_t)fixture.received_len,
	                                &padding_len));
}

struct doh_fixture {
	int         fd;
	SSL_CTX    *ctx;
	uint16_t    port;
	bool        saw_custom_path;
	bool        saw_host;
	uint8_t     received_query[DNS_MAX_MSG_SIZE];
	size_t      received_len;
	const char *response_content_type;
	const char *response_content_length;
	bool        send_body;
};

static int
ssl_read_http_headers(SSL *ssl, char *headers, size_t headers_size)
{
	size_t pos = 0;

	while (pos + 1 < headers_size) {
		int n = SSL_read(ssl, headers + pos, 1);
		if (n <= 0)
			return -1;
		pos += (size_t)n;
		if (pos >= 4 && memcmp(headers + pos - 4, "\r\n\r\n", 4) == 0) {
			headers[pos] = '\0';
			return 0;
		}
	}

	return -1;
}

static size_t
http_content_length(const char *headers)
{
	const char *line = strstr(headers, "\r\nContent-Length: ");

	if (line == NULL)
		return 0;
	line += strlen("\r\nContent-Length: ");

	return (size_t)strtoul(line, NULL, 10);
}

static void *
serve_doh_once(void *arg)
{
	struct doh_fixture *fixture = arg;
	struct sockaddr_in  client_addr;
	socklen_t           client_len = sizeof(client_addr);
	int                 conn;
	SSL                *ssl;
	char                headers[2048];
	char                response_headers[256];
	uint8_t             response[DNS_MAX_MSG_SIZE];

	conn = accept(fixture->fd, (struct sockaddr *)&client_addr,
	              &client_len);
	TEST_CHECK(conn >= 0);

	ssl = SSL_new(fixture->ctx);
	TEST_CHECK(ssl != NULL);
	TEST_CHECK(SSL_set_fd(ssl, conn) == 1);
	TEST_CHECK(SSL_accept(ssl) > 0);

	TEST_CHECK(ssl_read_http_headers(ssl, headers, sizeof(headers)) == 0);
	fixture->saw_custom_path = strncmp(headers, "POST /custom-dns HTTP/1.1\r\n", 27) == 0;
	fixture->saw_host        = strstr(headers, "\r\nHost: localhost\r\n") != NULL;

	fixture->received_len    = http_content_length(headers);
	TEST_CHECK(fixture->received_len >= DNS_HEADER_SIZE);
	TEST_CHECK(fixture->received_len <= sizeof(fixture->received_query));
	TEST_CHECK(ssl_read_exact(ssl, fixture->received_query,
	                          fixture->received_len)
	           == 0);

	memcpy(response, fixture->received_query, fixture->received_len);
	write_u16(response + 2,
	          DNS_FLAG_QR | DNS_FLAG_RA | (wire_read_u16(response + 2) & DNS_FLAG_RD));

	const char *content_type = fixture->response_content_type != NULL ?
	                                   fixture->response_content_type :
	                                   "application/dns-message";
	char        content_length[64];
	if (fixture->response_content_length != NULL) {
		snprintf(content_length, sizeof(content_length), "%s",
		         fixture->response_content_length);
	} else {
		snprintf(content_length, sizeof(content_length), "%zu",
		         fixture->received_len);
	}

	int hn = snprintf(response_headers, sizeof(response_headers),
	                  "HTTP/1.1 200 OK\r\n"
	                  "Content-Type: %s\r\n"
	                  "Content-Length: %s\r\n"
	                  "Connection: close\r\n\r\n",
	                  content_type, content_length);
	TEST_CHECK(hn > 0 && (size_t)hn < sizeof(response_headers));
	TEST_CHECK(ssl_write_exact(ssl, (const uint8_t *)response_headers,
	                           (size_t)hn)
	           == 0);
	if (fixture->send_body)
		TEST_CHECK(ssl_write_exact(ssl, response, fixture->received_len) == 0);

	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(conn);
	return NULL;
}

static void
test_doh_transport_uses_https_path_and_padding(void)
{
	struct doh_fixture fixture;
	struct sockaddr_in addr;
	socklen_t          addr_len = sizeof(addr);
	pthread_t          thread;
	uint8_t            query[DNS_MAX_MSG_SIZE];
	uint8_t            response[DNS_MAX_MSG_SIZE];
	size_t             query_len;
	size_t             response_len = 0;
	uint16_t           padding_len  = 0;

	memset(&fixture, 0, sizeof(fixture));
	fixture.send_body = true;
	fixture.fd        = socket(AF_INET, SOCK_STREAM, 0);
	if (fixture.fd < 0 && (errno == EPERM || errno == EACCES))
		TEST_SKIP("resolver tests skipped: TCP sockets unavailable");
	TEST_CHECK(fixture.fd >= 0);

	int optval = 1;
	setsockopt(fixture.fd, SOL_SOCKET, SO_REUSEADDR,
	           &optval, sizeof(optval));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_port        = 0;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	TEST_CHECK(bind(fixture.fd, (struct sockaddr *)&addr, sizeof(addr))
	           == 0);
	TEST_CHECK(getsockname(fixture.fd, (struct sockaddr *)&addr,
	                       &addr_len)
	           == 0);
	TEST_CHECK(listen(fixture.fd, 1) == 0);
	fixture.port = ntohs(addr.sin_port);

	fixture.ctx  = SSL_CTX_new(TLS_server_method());
	TEST_CHECK(fixture.ctx != NULL);
	SSL_CTX_set_min_proto_version(fixture.ctx, TLS1_2_VERSION);
	TEST_CHECK(make_selfsigned_cert(fixture.ctx) == 0);

	TEST_CHECK(pthread_create(&thread, NULL, serve_doh_once,
	                          &fixture)
	           == 0);

	resolver_set_tls_config(NULL, NULL, true);

	query_len = make_query(query, 0xD0A0, DNS_FLAG_RD, "example.com");

	char addrs[1][INET6_ADDRSTRLEN];
	snprintf(addrs[0], INET6_ADDRSTRLEN, "127.0.0.1");
	int rc = resolver_forward_transport(
	        addrs, 1, fixture.port, DNS_UPSTREAM_TRANSPORT_DOH,
	        "/custom-dns", "localhost", 128, query, query_len,
	        response, sizeof(response), &response_len);

	TEST_CHECK(pthread_join(thread, NULL) == 0);
	close(fixture.fd);
	SSL_CTX_free(fixture.ctx);

	TEST_EXPECT_INT_EQ(rc, 0);
	TEST_CHECK(fixture.saw_custom_path);
	TEST_CHECK(fixture.saw_host);
	TEST_CHECK(fixture.received_len > query_len);
	TEST_EXPECT_SIZE_EQ(fixture.received_len % 128, 0);
	TEST_CHECK(find_padding_option(fixture.received_query,
	                               fixture.received_len,
	                               &padding_len));
	TEST_EXPECT_INT_EQ(wire_read_u16(response), 0xD0A0);
}

static void
run_doh_bad_header_rejected(const char *content_type,
                            const char *content_length)
{
	struct doh_fixture fixture;
	struct sockaddr_in addr;
	socklen_t          addr_len = sizeof(addr);
	pthread_t          thread;
	uint8_t            query[DNS_MAX_MSG_SIZE];
	uint8_t            response[DNS_MAX_MSG_SIZE];
	size_t             query_len;
	size_t             response_len = 0;

	memset(&fixture, 0, sizeof(fixture));
	fixture.response_content_type   = content_type;
	fixture.response_content_length = content_length;
	fixture.send_body               = false;
	fixture.fd                      = socket(AF_INET, SOCK_STREAM, 0);
	if (fixture.fd < 0 && (errno == EPERM || errno == EACCES))
		TEST_SKIP("resolver tests skipped: TCP sockets unavailable");
	TEST_CHECK(fixture.fd >= 0);

	int optval = 1;
	setsockopt(fixture.fd, SOL_SOCKET, SO_REUSEADDR,
	           &optval, sizeof(optval));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_port        = 0;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	TEST_CHECK(bind(fixture.fd, (struct sockaddr *)&addr, sizeof(addr))
	           == 0);
	TEST_CHECK(getsockname(fixture.fd, (struct sockaddr *)&addr,
	                       &addr_len)
	           == 0);
	TEST_CHECK(listen(fixture.fd, 1) == 0);
	fixture.port = ntohs(addr.sin_port);

	fixture.ctx  = SSL_CTX_new(TLS_server_method());
	TEST_CHECK(fixture.ctx != NULL);
	SSL_CTX_set_min_proto_version(fixture.ctx, TLS1_2_VERSION);
	TEST_CHECK(make_selfsigned_cert(fixture.ctx) == 0);

	TEST_CHECK(pthread_create(&thread, NULL, serve_doh_once,
	                          &fixture)
	           == 0);

	resolver_set_tls_config(NULL, NULL, true);

	query_len = make_query(query, 0xD0B0, DNS_FLAG_RD, "bad-doh.example");

	char addrs[1][INET6_ADDRSTRLEN];
	snprintf(addrs[0], INET6_ADDRSTRLEN, "127.0.0.1");
	int rc = resolver_forward_transport(
	        addrs, 1, fixture.port, DNS_UPSTREAM_TRANSPORT_DOH,
	        "/dns-query", "localhost", 0, query, query_len,
	        response, sizeof(response), &response_len);

	TEST_CHECK(pthread_join(thread, NULL) == 0);
	close(fixture.fd);
	SSL_CTX_free(fixture.ctx);

	TEST_EXPECT_INT_EQ(rc, -1);
	TEST_EXPECT_SIZE_EQ(response_len, 0);
}

static void
test_doh_transport_rejects_malformed_response_headers(void)
{
	run_doh_bad_header_rejected("application/dns-messageXYZ", NULL);
	run_doh_bad_header_rejected(NULL, "12junk");
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
	rc = resolver_forward_transport(addrs, 1, fx.port,
	                                DNS_UPSTREAM_TRANSPORT_PLAIN, NULL,
	                                NULL, 0, query, query_len, response,
	                                sizeof(response), &response_len);

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

	rc = resolver_forward_transport(addrs, 2, ntohs(upstream_addr.sin_port),
	                                DNS_UPSTREAM_TRANSPORT_PLAIN, NULL,
	                                NULL, 0, query, query_len, response,
	                                sizeof(response), &response_len);

	TEST_CHECK(pthread_join(thread, NULL) == 0);
	close(fixture.fd);

	/* Failover must succeed and the live mock must have observed traffic */
	TEST_EXPECT_INT_EQ(rc, 0);
	TEST_CHECK(fixture.observed_id != 0);
	TEST_EXPECT_INT_EQ(wire_read_u16(response), 0x1234);
}

/* --- resolver SVCB discovery --- */

struct svcb_fixture {
	int  fd;
	char observed_qname[DNS_MAX_NAME_LEN + 1];
};

static size_t
append_param(uint8_t *buf, size_t pos, uint16_t key,
             const uint8_t *value, uint16_t value_len)
{
	write_u16(buf + pos, key);
	write_u16(buf + pos + 2, value_len);
	pos += 4;
	memcpy(buf + pos, value, value_len);
	return pos + value_len;
}

static size_t
append_svcb_answer(uint8_t *response, size_t pos, uint16_t priority,
                   const char *target, const uint8_t *params,
                   size_t params_len)
{
	response[pos++] = 0xC0;
	response[pos++] = DNS_HEADER_SIZE;
	write_u16(response + pos, TEST_DNS_TYPE_SVCB);
	write_u16(response + pos + 2, DNS_CLASS_IN);
	write_u16(response + pos + 4, 0);
	write_u16(response + pos + 6, 60);
	size_t rdlen_off    = pos + 8;
	pos                += 10;
	size_t rdata_start  = pos;

	write_u16(response + pos, priority);
	pos += 2;
	pos  = append_name(response, pos, target);
	if (params_len > 0) {
		memcpy(response + pos, params, params_len);
		pos += params_len;
	}

	write_u16(response + rdlen_off, (uint16_t)(pos - rdata_start));
	return pos;
}

static void *
serve_svcb_discovery(void *arg)
{
	struct svcb_fixture *fixture = arg;
	struct sockaddr_in   client_addr;
	socklen_t            client_len = sizeof(client_addr);
	uint8_t              query[DNS_MAX_MSG_SIZE];
	uint8_t              response[DNS_MAX_MSG_SIZE];
	ssize_t              recvd;

	recvd = recvfrom(fixture->fd, query, sizeof(query), 0,
	                 (struct sockaddr *)&client_addr, &client_len);
	TEST_CHECK(recvd >= (ssize_t)DNS_HEADER_SIZE);
	TEST_CHECK(dns_parse_name(query, (size_t)recvd, DNS_HEADER_SIZE,
	                          fixture->observed_qname,
	                          sizeof(fixture->observed_qname),
	                          NULL)
	           == 0);

	int qname_len = wire_skip_name(query, (size_t)recvd,
	                               DNS_HEADER_SIZE);
	TEST_CHECK(qname_len > 0);
	size_t qd_len = (size_t)qname_len + 4;

	memset(response, 0, sizeof(response));
	write_u16(response, wire_read_u16(query));
	write_u16(response + 2, DNS_FLAG_QR | DNS_FLAG_RA | DNS_FLAG_RD);
	write_u16(response + 4, 1);
	write_u16(response + 6, 1);
	memcpy(response + DNS_HEADER_SIZE, query + DNS_HEADER_SIZE, qd_len);

	size_t pos      = DNS_HEADER_SIZE + qd_len;
	response[pos++] = 0xC0;
	response[pos++] = DNS_HEADER_SIZE;
	write_u16(response + pos, TEST_DNS_TYPE_SVCB);
	write_u16(response + pos + 2, DNS_CLASS_IN);
	write_u16(response + pos + 4, 0);
	write_u16(response + pos + 6, 60);
	size_t rdlen_off    = pos + 8;
	pos                += 10;
	size_t rdata_start  = pos;

	write_u16(response + pos, 1);
	pos                  += 2;
	pos                   = append_name(response, pos, "resolver.example");

	const uint8_t alpn[]  = {
		2,
		'h',
		'2',
		3,
		'd',
		'o',
		't',
	};
	pos                     = append_param(response, pos, 1, alpn, sizeof(alpn));

	const uint8_t port[]    = { 0x22, 0x95 }; /* 8853 */
	pos                     = append_param(response, pos, 3, port, sizeof(port));

	const uint8_t dohpath[] = "/dns-query{?dns}";
	pos                     = append_param(response, pos, 7, dohpath,
	                                       (uint16_t)(sizeof(dohpath) - 1));

	write_u16(response + rdlen_off, (uint16_t)(pos - rdata_start));

	TEST_CHECK(sendto(fixture->fd, response, pos, 0,
	                  (struct sockaddr *)&client_addr, client_len)
	           == (ssize_t)pos);
	return NULL;
}

static void *
serve_svcb_discovery_with_unusable_records(void *arg)
{
	struct svcb_fixture *fixture = arg;
	struct sockaddr_in   client_addr;
	socklen_t            client_len = sizeof(client_addr);
	uint8_t              query[DNS_MAX_MSG_SIZE];
	uint8_t              response[DNS_MAX_MSG_SIZE];
	ssize_t              recvd;

	recvd = recvfrom(fixture->fd, query, sizeof(query), 0,
	                 (struct sockaddr *)&client_addr, &client_len);
	TEST_CHECK(recvd >= (ssize_t)DNS_HEADER_SIZE);
	TEST_CHECK(dns_parse_name(query, (size_t)recvd, DNS_HEADER_SIZE,
	                          fixture->observed_qname,
	                          sizeof(fixture->observed_qname),
	                          NULL)
	           == 0);

	int qname_len = wire_skip_name(query, (size_t)recvd,
	                               DNS_HEADER_SIZE);
	TEST_CHECK(qname_len > 0);
	size_t qd_len = (size_t)qname_len + 4;

	memset(response, 0, sizeof(response));
	write_u16(response, wire_read_u16(query));
	write_u16(response + 2, DNS_FLAG_QR | DNS_FLAG_RA | DNS_FLAG_RD);
	write_u16(response + 4, 1);
	write_u16(response + 6, 3);
	memcpy(response + DNS_HEADER_SIZE, query + DNS_HEADER_SIZE, qd_len);

	size_t pos = DNS_HEADER_SIZE + qd_len;

	pos        = append_svcb_answer(response, pos, 0, "alias.example",
	                                NULL, 0);

	uint8_t bad_params[32];
	size_t  bad_len = 0;
	uint8_t unsupported_mandatory[2];
	write_u16(unsupported_mandatory, 65400);
	bad_len = append_param(bad_params, bad_len, 0,
	                       unsupported_mandatory,
	                       (uint16_t)sizeof(unsupported_mandatory));
	pos     = append_svcb_answer(response, pos, 1, "bad.example",
	                             bad_params, bad_len);

	uint8_t valid_params[32];
	size_t  valid_len = 0;
	uint8_t alpn[]    = { 3, 'd', 'o', 't' };
	valid_len         = append_param(valid_params, valid_len, 1,
	                                 alpn, (uint16_t)sizeof(alpn));
	uint8_t port[]    = { 0x22, 0x95 }; /* 8853 */
	valid_len         = append_param(valid_params, valid_len, 3,
	                                 port, (uint16_t)sizeof(port));
	pos               = append_svcb_answer(response, pos, 2,
	                                       "valid.example",
	                                       valid_params, valid_len);

	TEST_CHECK(sendto(fixture->fd, response, pos, 0,
	                  (struct sockaddr *)&client_addr, client_len)
	           == (ssize_t)pos);
	return NULL;
}

static void
test_resolver_svcb_discovery_parses_metadata(void)
{
	struct svcb_fixture              fixture;
	struct sockaddr_in               upstream_addr;
	socklen_t                        upstream_len = sizeof(upstream_addr);
	pthread_t                        thread;
	struct resolver_discovery_result result;

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
	TEST_CHECK(pthread_create(&thread, NULL, serve_svcb_discovery,
	                          &fixture)
	           == 0);

	char addrs[1][INET6_ADDRSTRLEN];
	snprintf(addrs[0], INET6_ADDRSTRLEN, "127.0.0.1");
	int rc = resolver_discover_svcb_transport(
	        addrs, 1, ntohs(upstream_addr.sin_port),
	        DNS_UPSTREAM_TRANSPORT_PLAIN, NULL, NULL, 0,
	        "resolver.example", &result);

	TEST_CHECK(pthread_join(thread, NULL) == 0);
	close(fixture.fd);

	TEST_EXPECT_INT_EQ(rc, 0);
	TEST_EXPECT_STR_EQ(fixture.observed_qname, "_dns.resolver.example");
	TEST_CHECK(result.found);
	TEST_CHECK(result.supports_doh);
	TEST_CHECK(result.supports_dot);
	TEST_CHECK(!result.supports_doq);
	TEST_EXPECT_INT_EQ(result.port, 8853);
	TEST_EXPECT_STR_EQ(result.doh_path, "/dns-query");
	TEST_EXPECT_STR_EQ(result.target_name, "resolver.example");
}

static void
test_resolver_svcb_discovery_ignores_unusable_records(void)
{
	struct svcb_fixture              fixture;
	struct sockaddr_in               upstream_addr;
	socklen_t                        upstream_len = sizeof(upstream_addr);
	pthread_t                        thread;
	struct resolver_discovery_result result;

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
	TEST_CHECK(pthread_create(&thread, NULL,
	                          serve_svcb_discovery_with_unusable_records,
	                          &fixture)
	           == 0);

	char addrs[1][INET6_ADDRSTRLEN];
	snprintf(addrs[0], INET6_ADDRSTRLEN, "127.0.0.1");
	int rc = resolver_discover_svcb_transport(
	        addrs, 1, ntohs(upstream_addr.sin_port),
	        DNS_UPSTREAM_TRANSPORT_PLAIN, NULL, NULL, 0,
	        "resolver.example", &result);

	TEST_CHECK(pthread_join(thread, NULL) == 0);
	close(fixture.fd);

	TEST_EXPECT_INT_EQ(rc, 0);
	TEST_EXPECT_STR_EQ(fixture.observed_qname, "_dns.resolver.example");
	TEST_CHECK(result.found);
	TEST_CHECK(result.supports_dot);
	TEST_CHECK(!result.supports_doh);
	TEST_CHECK(!result.supports_doq);
	TEST_CHECK(!result.supports_odoh);
	TEST_EXPECT_INT_EQ(result.priority, 2);
	TEST_EXPECT_INT_EQ(result.port, 8853);
	TEST_EXPECT_STR_EQ(result.target_name, "valid.example");
}

int
main(void)
{
	test_id_randomized_flags_stripped();
	test_0x20_randomization_uppercase_present();
	test_dot_edns_padding_block_128();
	test_dot_edns_padding_updates_existing_opt();
	test_dot_tls_connection_reused_and_padding_is_per_query();
	test_plain_udp_does_not_add_edns_padding();
	test_doh_transport_uses_https_path_and_padding();
	test_doh_transport_rejects_malformed_response_headers();
	test_tcp_fallback_on_truncation();
	test_multi_addr_failover_skips_dead_first();
	test_resolver_svcb_discovery_parses_metadata();
	test_resolver_svcb_discovery_ignores_unusable_records();

	puts("resolver tests passed");
	return 0;
}
