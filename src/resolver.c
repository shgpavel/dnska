/* SPDX-License-Identifier: MIT */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "dns.h"
#include "random.h"
#include "resolver.h"
#include "wire.h"

enum {
	RESOLVER_MIN_SOURCE_PORT      = 1024,
	RESOLVER_BIND_RETRIES         = 64,
	RESOLVER_TIMEOUT_SEC          = 3,
	RESOLVER_ID_MISMATCH_LIMIT    = 3,
	RESOLVER_DNS_TYPE_SVCB        = 64,
	RESOLVER_EDNS_OPTION_PADDING  = 12,
	RESOLVER_SVCB_PARAM_MANDATORY = 0,
	RESOLVER_SVCB_PARAM_ALPN      = 1,
	RESOLVER_SVCB_PARAM_PORT      = 3,
	RESOLVER_SVCB_PARAM_DOH_PATH  = 7,
};

static SSL_CTX       *client_tls_ctx;
static pthread_once_t client_tls_once = PTHREAD_ONCE_INIT;

/* Configured via resolver_set_tls_config(); read-only after init. */
static char           tls_ca_file[256];
static char           tls_auth_name[256];
static bool           tls_insecure;

void
resolver_set_tls_config(const char *ca_file, const char *auth_name,
                        bool insecure)
{
	tls_ca_file[0]   = '\0';
	tls_auth_name[0] = '\0';
	if (ca_file != NULL)
		snprintf(tls_ca_file, sizeof(tls_ca_file), "%s", ca_file);
	if (auth_name != NULL)
		snprintf(tls_auth_name, sizeof(tls_auth_name), "%s", auth_name);
	tls_insecure = insecure;
}

static void
init_client_tls_ctx(void)
{
	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	if (ctx == NULL)
		return;
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

	if (tls_insecure) {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	} else {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
		if (tls_ca_file[0] != '\0') {
			if (SSL_CTX_load_verify_locations(ctx, tls_ca_file, NULL)
			    != 1) {
				fprintf(stderr,
				        "resolver: failed to load CA file %s\n",
				        tls_ca_file);
				SSL_CTX_free(ctx);
				return;
			}
		} else if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
			fprintf(stderr,
			        "resolver: failed to load default CA paths\n");
			SSL_CTX_free(ctx);
			return;
		}
	}
	client_tls_ctx = ctx;
}

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

static int
ssl_readn(SSL *ssl, uint8_t *buf, size_t len)
{
	size_t recvd = 0;

	while (recvd < len) {
		int n = SSL_read(ssl, buf + recvd, (int)(len - recvd));
		if (n <= 0)
			return -1;
		recvd += (size_t)n;
	}
	return 0;
}

static int
ssl_writen(SSL *ssl, const uint8_t *buf, size_t len)
{
	size_t sent = 0;

	while (sent < len) {
		int n = SSL_write(ssl, buf + sent, (int)(len - sent));
		if (n <= 0)
			return -1;
		sent += (size_t)n;
	}
	return 0;
}

static void
tls_close(SSL *ssl, int fd)
{
	if (ssl != NULL) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	if (fd >= 0)
		close(fd);
}

/*
 * Open a verified TLS connection to upstream.  hostname is used as the
 * SNI/verify name when --tls-auth-name is unset.  On success returns 0
 * with *out_fd and *out_ssl populated; caller frees via tls_close().
 */
static int
tls_connect(const struct sockaddr *upstream, socklen_t upstream_len,
            int family, const char *hostname,
            int *out_fd, SSL **out_ssl)
{
	*out_fd  = -1;
	*out_ssl = NULL;

	pthread_once(&client_tls_once, init_client_tls_ctx);
	if (client_tls_ctx == NULL) {
		fprintf(stderr, "resolver: TLS context unavailable\n");
		return -1;
	}

	int fd = socket(family, SOCK_STREAM, 0);
	if (fd < 0) {
		fprintf(stderr, "resolver: TLS socket: %s\n", strerror(errno));
		return -1;
	}

	struct timeval tv = { .tv_sec = RESOLVER_TIMEOUT_SEC, .tv_usec = 0 };
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0
	    || setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
		fprintf(stderr, "resolver: TLS setsockopt: %s\n",
		        strerror(errno));
		close(fd);
		return -1;
	}

	if (connect(fd, upstream, upstream_len) < 0) {
		fprintf(stderr, "resolver: TLS connect: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	SSL *ssl = SSL_new(client_tls_ctx);
	if (ssl == NULL || SSL_set_fd(ssl, fd) != 1) {
		fprintf(stderr, "resolver: TLS SSL_new/set_fd failed\n");
		if (ssl != NULL)
			SSL_free(ssl);
		close(fd);
		return -1;
	}

	const char *verify_name = tls_auth_name[0] != '\0' ? tls_auth_name : (hostname != NULL && hostname[0] != '\0') ? hostname :
	                                                                                                                 NULL;

	if (verify_name != NULL)
		SSL_set_tlsext_host_name(ssl, verify_name);

	if (!tls_insecure) {
		if (verify_name == NULL) {
			fprintf(stderr,
			        "resolver: TLS verification requires a hostname "
			        "or --tls-auth-name (use --insecure to skip)\n");
			tls_close(ssl, fd);
			return -1;
		}
		SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
		if (SSL_set1_host(ssl, verify_name) != 1) {
			fprintf(stderr,
			        "resolver: SSL_set1_host failed for %s\n",
			        verify_name);
			tls_close(ssl, fd);
			return -1;
		}
	}

	if (SSL_connect(ssl) <= 0) {
		long verify_rc = SSL_get_verify_result(ssl);
		fprintf(stderr,
		        "resolver: TLS handshake failed: %s (verify=%ld %s)\n",
		        ERR_reason_error_string(ERR_get_error()),
		        verify_rc, X509_verify_cert_error_string(verify_rc));
		tls_close(ssl, fd);
		return -1;
	}

	*out_fd  = fd;
	*out_ssl = ssl;
	return 0;
}

/*
 * Forward query to upstream over DNS-over-TLS (RFC 7858).
 * Uses TCP with a TLS layer; same length-prefix framing as DNS-over-TCP.
 */
static int
forward_tls(const struct sockaddr *upstream, socklen_t upstream_len,
            int family, const char *hostname,
            const uint8_t *query, size_t query_len,
            uint16_t upstream_id, const uint8_t *orig_query,
            uint8_t *response, size_t response_size,
            size_t *response_len)
{
	uint8_t len_buf[2];
	SSL    *ssl = NULL;
	int     fd  = -1;

	if (tls_connect(upstream, upstream_len, family, hostname, &fd, &ssl) < 0)
		return -1;

	if (query_len > UINT16_MAX) {
		tls_close(ssl, fd);
		return -1;
	}
	len_buf[0] = (uint8_t)(query_len >> 8);
	len_buf[1] = (uint8_t)query_len;

	if (ssl_writen(ssl, len_buf, 2) < 0
	    || ssl_writen(ssl, query, query_len) < 0) {
		fprintf(stderr, "resolver: TLS send: %s\n", strerror(errno));
		tls_close(ssl, fd);
		return -1;
	}

	if (ssl_readn(ssl, len_buf, 2) < 0) {
		fprintf(stderr, "resolver: TLS recv length: %s\n",
		        strerror(errno));
		tls_close(ssl, fd);
		return -1;
	}

	size_t resp_size = (size_t)(((uint16_t)len_buf[0] << 8) | len_buf[1]);
	if (resp_size < DNS_HEADER_SIZE || resp_size > response_size) {
		fprintf(stderr, "resolver: TLS bad response length: %zu\n",
		        resp_size);
		tls_close(ssl, fd);
		return -1;
	}

	if (ssl_readn(ssl, response, resp_size) < 0) {
		fprintf(stderr, "resolver: TLS recv body: %s\n",
		        strerror(errno));
		tls_close(ssl, fd);
		return -1;
	}

	tls_close(ssl, fd);

	uint16_t got_id = (uint16_t)(((uint16_t)response[0] << 8) | response[1]);
	if (got_id != upstream_id) {
		fprintf(stderr, "resolver: TLS response ID mismatch\n");
		return -1;
	}

	response[0]   = orig_query[0];
	response[1]   = orig_query[1];

	*response_len = resp_size;
	return 0;
}

/*
 * Read until "\r\n\r\n" or buffer full.  Returns 0 on success and the
 * total header byte count (including the terminating CRLFCRLF) in
 * *header_len.  Buffer is NUL-terminated on success.
 */
static int
read_http_headers(SSL *ssl, char *buf, size_t buf_size, size_t *header_len)
{
	size_t pos = 0;

	while (pos + 1 < buf_size) {
		int n = SSL_read(ssl, buf + pos, 1);
		if (n <= 0)
			return -1;
		pos++;
		if (pos >= 4 && buf[pos - 4] == '\r' && buf[pos - 3] == '\n' && buf[pos - 2] == '\r' && buf[pos - 1] == '\n') {
			buf[pos]    = '\0';
			*header_len = pos;
			return 0;
		}
	}
	return -1;
}

static int
http_parse_status(const char *headers, int *status_code)
{
	if (strncmp(headers, "HTTP/1.", 7) != 0)
		return -1;
	const char *space = strchr(headers, ' ');
	if (space == NULL)
		return -1;
	*status_code = atoi(space + 1);
	return 0;
}

static const char *
http_find_header(const char *headers, const char *name)
{
	size_t      name_len = strlen(name);
	const char *p        = strchr(headers, '\n');

	if (p == NULL)
		return NULL;
	p++; /* skip past status line */

	while (*p != '\0') {
		if (*p == '\r' && p[1] == '\n')
			return NULL;
		if (strncasecmp(p, name, name_len) == 0 && p[name_len] == ':') {
			const char *v = p + name_len + 1;
			while (*v == ' ' || *v == '\t')
				v++;
			return v;
		}
		const char *eol = strstr(p, "\r\n");
		if (eol == NULL)
			return NULL;
		p = eol + 2;
	}
	return NULL;
}

/*
 * Forward query to upstream over DNS-over-HTTPS (RFC 8484).  Uses POST
 * with application/dns-message.  hostname is required (Host header +
 * SNI/verify) unless --tls-auth-name is configured.
 */
static int
forward_doh(const struct sockaddr *upstream, socklen_t upstream_len,
            int family, const char *hostname, const char *doh_path,
            const uint8_t *query, size_t query_len,
            uint16_t upstream_id, const uint8_t *orig_query,
            uint8_t *response, size_t response_size,
            size_t *response_len)
{
	SSL        *ssl  = NULL;
	int         fd   = -1;
	const char *path = (doh_path != NULL && doh_path[0] != '\0') ? doh_path : "/dns-query";
	const char *host = (hostname != NULL && hostname[0] != '\0') ? hostname : (tls_auth_name[0] != '\0' ? tls_auth_name : NULL);

	if (host == NULL) {
		fprintf(stderr,
		        "resolver: DoH requires a hostname or "
		        "--tls-auth-name\n");
		return -1;
	}

	if (tls_connect(upstream, upstream_len, family, host, &fd, &ssl) < 0)
		return -1;

	char header_buf[1024];
	int  hn = snprintf(header_buf, sizeof(header_buf),
	                   "POST %s HTTP/1.1\r\n"
	                   "Host: %s\r\n"
	                   "User-Agent: dnska/0.1\r\n"
	                   "Accept: application/dns-message\r\n"
	                   "Content-Type: application/dns-message\r\n"
	                   "Content-Length: %zu\r\n"
	                   "Connection: close\r\n\r\n",
	                   path, host, query_len);
	if (hn < 0 || (size_t)hn >= sizeof(header_buf)) {
		fprintf(stderr, "resolver: DoH header too large\n");
		tls_close(ssl, fd);
		return -1;
	}

	if (ssl_writen(ssl, (const uint8_t *)header_buf, (size_t)hn) < 0
	    || ssl_writen(ssl, query, query_len) < 0) {
		fprintf(stderr, "resolver: DoH send failed\n");
		tls_close(ssl, fd);
		return -1;
	}

	char   resp_headers[4096];
	size_t header_len = 0;
	if (read_http_headers(ssl, resp_headers, sizeof(resp_headers),
	                      &header_len)
	    < 0) {
		fprintf(stderr, "resolver: DoH read headers failed\n");
		tls_close(ssl, fd);
		return -1;
	}

	int status = 0;
	if (http_parse_status(resp_headers, &status) < 0 || status != 200) {
		fprintf(stderr, "resolver: DoH HTTP status %d\n", status);
		tls_close(ssl, fd);
		return -1;
	}

	const char *ctype = http_find_header(resp_headers, "Content-Type");
	if (ctype == NULL
	    || strncasecmp(ctype, "application/dns-message", 23) != 0) {
		fprintf(stderr,
		        "resolver: DoH bad Content-Type (need application/"
		        "dns-message)\n");
		tls_close(ssl, fd);
		return -1;
	}

	const char *clen = http_find_header(resp_headers, "Content-Length");
	if (clen == NULL) {
		fprintf(stderr, "resolver: DoH missing Content-Length\n");
		tls_close(ssl, fd);
		return -1;
	}
	size_t content_length = (size_t)strtoul(clen, NULL, 10);
	if (content_length < DNS_HEADER_SIZE
	    || content_length > response_size) {
		fprintf(stderr, "resolver: DoH bad body length: %zu\n",
		        content_length);
		tls_close(ssl, fd);
		return -1;
	}

	if (ssl_readn(ssl, response, content_length) < 0) {
		fprintf(stderr, "resolver: DoH read body failed\n");
		tls_close(ssl, fd);
		return -1;
	}

	tls_close(ssl, fd);

	uint16_t got_id = (uint16_t)(((uint16_t)response[0] << 8) | response[1]);
	if (got_id != upstream_id) {
		fprintf(stderr, "resolver: DoH response ID mismatch\n");
		return -1;
	}

	response[0]   = orig_query[0];
	response[1]   = orig_query[1];

	*response_len = content_length;
	return 0;
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

static size_t
remove_edns_padding(uint8_t *buf, size_t len, size_t opt_off)
{
	int n = wire_skip_name(buf, len, opt_off);
	if (n < 0)
		return 0;

	size_t fixed_off = opt_off + (size_t)n;
	if (fixed_off + 10 > len)
		return 0;

	size_t   rdlen_off = fixed_off + 8;
	size_t   rdata_off = fixed_off + 10;
	uint16_t rdlen     = wire_read_u16(buf + rdlen_off);
	size_t   rdata_end = rdata_off + rdlen;
	size_t   read_pos  = rdata_off;
	size_t   write_pos = rdata_off;

	if (rdata_end > len)
		return 0;

	while (read_pos < rdata_end) {
		if (rdata_end - read_pos < 4)
			return 0;

		uint16_t opt_code = wire_read_u16(buf + read_pos);
		uint16_t opt_len  = wire_read_u16(buf + read_pos + 2);
		size_t   opt_size = (size_t)opt_len + 4;

		if (rdata_end - read_pos < opt_size)
			return 0;

		if (opt_code != RESOLVER_EDNS_OPTION_PADDING) {
			if (write_pos != read_pos)
				memmove(buf + write_pos, buf + read_pos,
				        opt_size);
			write_pos += opt_size;
		}

		read_pos += opt_size;
	}

	size_t kept_len = write_pos - rdata_off;
	size_t removed  = (size_t)rdlen - kept_len;
	if (removed == 0)
		return len;

	memmove(buf + write_pos, buf + rdata_end, len - rdata_end);
	wire_write_u16(buf + rdlen_off, (uint16_t)kept_len);
	return len - removed;
}

static size_t
add_edns_padding(uint8_t *buf, size_t len, size_t max_size,
                 uint16_t block_size)
{
	if (block_size == 0)
		return len;

	size_t opt_off   = 0;
	size_t opt_total = 0;
	int    rc        = dns_find_opt(buf, len, &opt_off, &opt_total);

	if (rc != 0)
		return 0;

	len = remove_edns_padding(buf, len, opt_off);
	if (len == 0)
		return 0;

	rc = dns_find_opt(buf, len, &opt_off, &opt_total);
	if (rc != 0)
		return 0;

	size_t rem = len % block_size;
	if (rem == 0)
		return len;

	size_t option_size = (size_t)block_size - rem;
	if (option_size < 4)
		option_size += block_size;
	if (option_size > UINT16_MAX || len + option_size > max_size)
		return 0;

	int n = wire_skip_name(buf, len, opt_off);
	if (n < 0)
		return 0;

	size_t fixed_off = opt_off + (size_t)n;
	if (fixed_off + 10 > len)
		return 0;

	size_t   rdlen_off = fixed_off + 8;
	size_t   rdata_off = fixed_off + 10;
	uint16_t rdlen     = wire_read_u16(buf + rdlen_off);
	size_t   insert    = rdata_off + rdlen;

	if (insert > len || (size_t)rdlen + option_size > UINT16_MAX)
		return 0;

	memmove(buf + insert + option_size, buf + insert, len - insert);
	wire_write_u16(buf + insert, RESOLVER_EDNS_OPTION_PADDING);
	wire_write_u16(buf + insert + 2, (uint16_t)(option_size - 4));
	memset(buf + insert + 4, 0, option_size - 4);
	wire_write_u16(buf + rdlen_off, (uint16_t)(rdlen + option_size));

	return len + option_size;
}

static int
build_discovery_qname(const char *resolver_name, char *out, size_t out_size)
{
	size_t name_len;
	int    n;

	if (resolver_name == NULL || resolver_name[0] == '\0')
		return -1;

	name_len = strlen(resolver_name);
	while (name_len > 0 && resolver_name[name_len - 1] == '.')
		name_len--;
	if (name_len == 0)
		return -1;
	if (name_len > DNS_MAX_NAME_LEN)
		return -1;

	if (name_len >= 5
	    && strncasecmp(resolver_name, "_dns.", 5) == 0) {
		n = snprintf(out, out_size, "%.*s", (int)name_len,
		             resolver_name);
	} else {
		n = snprintf(out, out_size, "_dns.%.*s", (int)name_len,
		             resolver_name);
	}
	if (n < 0 || (size_t)n >= out_size)
		return -1;

	return 0;
}

static size_t
append_wire_name(uint8_t *buf, size_t pos, size_t buf_size,
                 const char *name)
{
	const char *label = name;

	if (name[0] == '.' && name[1] == '\0') {
		if (pos + 1 > buf_size)
			return 0;
		buf[pos++] = 0;
		return pos;
	}

	while (*label != '\0') {
		const char *dot = strchr(label, '.');
		size_t      len = dot != NULL ? (size_t)(dot - label) :
		                                strlen(label);

		if (len == 0 || len > DNS_MAX_LABEL_LEN)
			return 0;
		if (pos + 1 + len > buf_size)
			return 0;

		buf[pos++] = (uint8_t)len;
		memcpy(buf + pos, label, len);
		pos += len;

		if (dot == NULL)
			break;
		label = dot + 1;
	}

	if (pos + 1 > buf_size)
		return 0;
	buf[pos++] = 0;
	return pos;
}

static size_t
build_svcb_query(uint8_t *buf, size_t buf_size, uint16_t id,
                 const char *qname)
{
	if (buf_size < DNS_HEADER_SIZE)
		return 0;

	memset(buf, 0, DNS_HEADER_SIZE);
	wire_write_u16(buf, id);
	wire_write_u16(buf + 2, DNS_FLAG_RD);
	wire_write_u16(buf + 4, 1);

	size_t pos = append_wire_name(buf, DNS_HEADER_SIZE, buf_size,
	                              qname);
	if (pos == 0 || pos + 4 > buf_size)
		return 0;

	wire_write_u16(buf + pos, RESOLVER_DNS_TYPE_SVCB);
	wire_write_u16(buf + pos + 2, DNS_CLASS_IN);
	return pos + 4;
}

static bool
svcb_mandatory_key_supported(uint16_t key)
{
	switch (key) {
	case RESOLVER_SVCB_PARAM_MANDATORY:
	case RESOLVER_SVCB_PARAM_ALPN:
	case 2: /* no-default-alpn */
	case RESOLVER_SVCB_PARAM_PORT:
	case 4: /* ipv4hint */
	case 6: /* ipv6hint */
	case RESOLVER_SVCB_PARAM_DOH_PATH:
		return true;
	default:
		return false;
	}
}

static bool
parse_svcb_mandatory(const uint8_t *value, size_t len)
{
	if ((len % 2) != 0)
		return false;

	for (size_t pos = 0; pos < len; pos += 2) {
		if (!svcb_mandatory_key_supported(wire_read_u16(value + pos)))
			return false;
	}

	return true;
}

static bool
alpn_equals(const uint8_t *value, size_t len, const char *alpn)
{
	size_t alpn_len = strlen(alpn);

	return len == alpn_len && memcmp(value, alpn, len) == 0;
}

static bool
parse_svcb_alpn(struct resolver_discovery_result *candidate,
                const uint8_t *value, size_t len)
{
	size_t pos = 0;

	if (len == 0)
		return false;

	while (pos < len) {
		uint8_t alpn_len = value[pos++];

		if (alpn_len == 0 || pos + alpn_len > len)
			return false;

		if (alpn_equals(value + pos, alpn_len, "dot"))
			candidate->supports_dot = true;
		else if (alpn_equals(value + pos, alpn_len, "h2")
		         || alpn_equals(value + pos, alpn_len, "h3")
		         || alpn_equals(value + pos, alpn_len, "http/1.1"))
			candidate->supports_doh = true;
		else if (alpn_equals(value + pos, alpn_len, "doq"))
			candidate->supports_doq = true;
		else if (alpn_equals(value + pos, alpn_len, "odoh"))
			candidate->supports_odoh = true;

		pos += alpn_len;
	}

	return true;
}

static bool
copy_doh_path(char *out, size_t out_size, const uint8_t *value, size_t len)
{
	size_t copy_len = 0;

	if (len == 0 || value[0] != '/')
		return false;

	while (copy_len < len && value[copy_len] != '{') {
		if (value[copy_len] == '\0'
		    || value[copy_len] == ' '
		    || value[copy_len] == '\t'
		    || value[copy_len] == '\r'
		    || value[copy_len] == '\n')
			return false;
		copy_len++;
	}

	if (copy_len == 0 || copy_len >= out_size)
		return false;

	memcpy(out, value, copy_len);
	out[copy_len] = '\0';
	return true;
}

static bool
parse_svcb_rdata(const uint8_t *msg, size_t msg_len,
                 size_t rdata_off, uint16_t rdlen,
                 struct resolver_discovery_result *candidate)
{
	size_t rdata_end;
	size_t target_len = 0;
	size_t pos;
	bool   have_alpn = false;

	if (rdlen < 3)
		return false;
	if (rdata_off + rdlen > msg_len)
		return false;

	memset(candidate, 0, sizeof(*candidate));
	candidate->priority = wire_read_u16(msg + rdata_off);
	if (candidate->priority == 0)
		return false; /* AliasMode needs another query; leave fallback. */

	pos       = rdata_off + 2;
	rdata_end = rdata_off + rdlen;
	if (dns_parse_name(msg, msg_len, pos, candidate->target_name,
	                   sizeof(candidate->target_name), &target_len)
	    < 0)
		return false;
	pos += target_len;
	if (pos > rdata_end)
		return false;

	while (pos < rdata_end) {
		if (rdata_end - pos < 4)
			return false;

		uint16_t key       = wire_read_u16(msg + pos);
		uint16_t value_len = wire_read_u16(msg + pos + 2);
		size_t   value_off = pos + 4;

		if (value_off + value_len > rdata_end)
			return false;

		switch (key) {
		case RESOLVER_SVCB_PARAM_MANDATORY:
			if (!parse_svcb_mandatory(msg + value_off, value_len))
				return false;
			break;
		case RESOLVER_SVCB_PARAM_ALPN:
			have_alpn = true;
			if (!parse_svcb_alpn(candidate, msg + value_off,
			                     value_len))
				return false;
			break;
		case RESOLVER_SVCB_PARAM_PORT:
			if (value_len != 2)
				return false;
			candidate->port = wire_read_u16(msg + value_off);
			break;
		case RESOLVER_SVCB_PARAM_DOH_PATH:
			if (!copy_doh_path(candidate->doh_path,
			                   sizeof(candidate->doh_path),
			                   msg + value_off, value_len))
				candidate->doh_path[0] = '\0';
			break;
		default:
			break;
		}

		pos = value_off + value_len;
	}

	if (!have_alpn)
		return false;
	if (candidate->supports_doh && candidate->doh_path[0] == '\0')
		candidate->supports_doh = false;

	candidate->found = candidate->supports_dot || candidate->supports_doh || candidate->supports_doq || candidate->supports_odoh;
	return candidate->found;
}

static int
parse_svcb_response(const uint8_t *response, size_t response_len,
                    struct resolver_discovery_result *result)
{
	struct resolver_discovery_result best;
	uint16_t                         qdcount;
	uint16_t                         ancount;
	size_t                           pos = DNS_HEADER_SIZE;

	if (response_len < DNS_HEADER_SIZE)
		return -1;

	memset(&best, 0, sizeof(best));
	qdcount = wire_read_u16(response + 4);
	ancount = wire_read_u16(response + 6);

	for (uint16_t i = 0; i < qdcount; i++) {
		int n = wire_skip_name(response, response_len, pos);
		if (n < 0)
			return -1;
		pos += (size_t)n + 4;
		if (pos > response_len)
			return -1;
	}

	for (uint16_t i = 0; i < ancount; i++) {
		int n = wire_skip_name(response, response_len, pos);
		if (n < 0)
			return -1;
		pos += (size_t)n;
		if (pos + 10 > response_len)
			return -1;

		uint16_t type      = wire_read_u16(response + pos);
		uint16_t rrclass   = wire_read_u16(response + pos + 2);
		uint16_t rdlen     = wire_read_u16(response + pos + 8);
		size_t   rdata_off = pos + 10;
		size_t   next      = rdata_off + rdlen;

		if (next > response_len)
			return -1;

		if (type == RESOLVER_DNS_TYPE_SVCB
		    && rrclass == DNS_CLASS_IN) {
			struct resolver_discovery_result candidate;

			if (parse_svcb_rdata(response, response_len,
			                     rdata_off, rdlen,
			                     &candidate)
			    && (!best.found
			        || candidate.priority < best.priority))
				best = candidate;
		}

		pos = next;
	}

	*result = best;
	return 0;
}

static int
forward_one_address(const char *upstream_addr, uint16_t upstream_port,
                    bool upstream_tls, bool upstream_doh,
                    const char    *doh_path,
                    const char    *upstream_hostname,
                    uint16_t       edns_padding_block,
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
	                           & (DNS_FLAGS_OPCODE_MASK | DNS_FLAG_RD | DNS_FLAG_AD | DNS_FLAG_CD);
	forwarded_query[2]       = (uint8_t)(forwarded_flags >> 8);
	forwarded_query[3]       = (uint8_t)forwarded_flags;

	/* 0x20 QNAME case randomization (RFC 5452 §3.2) */
	if (wire_read_u16(forwarded_query + 4) >= 1)
		randomize_qname_case(forwarded_query, query_len,
		                     DNS_HEADER_SIZE);

	/*
	 * Detect whether the client asked with EDNS.  Always force DO=1
	 * on the upstream copy so we can pass DNSSEC records through; if
	 * the client was non-EDNS, strip the OPT from the upstream reply
	 * before returning (RFC 6891 §6.1.1).
	 */
	size_t client_opt_off   = 0;
	size_t client_opt_total = 0;
	int    client_opt_rc    = dns_find_opt(query, query_len,
	                                       &client_opt_off, &client_opt_total);
	bool   client_had_opt   = (client_opt_rc == 0);

	size_t forwarded_len    = dns_set_outbound_edns(
	        forwarded_query, query_len, sizeof(forwarded_query));
	if (forwarded_len == 0) {
		fprintf(stderr, "resolver: failed to set outbound EDNS\n");
		return -1;
	}
	query_len = forwarded_len;

	if ((upstream_tls || upstream_doh) && edns_padding_block != 0) {
		size_t padded_len = add_edns_padding(
		        forwarded_query, query_len, sizeof(forwarded_query),
		        edns_padding_block);
		if (padded_len == 0) {
			fprintf(stderr,
			        "resolver: failed to add EDNS padding\n");
			return -1;
		}
		query_len = padded_len;
	}

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

	/* DoH: HTTP POST over TLS */
	if (upstream_doh) {
		int rc = forward_doh((const struct sockaddr *)&ss, ss_len, family,
		                     upstream_hostname, doh_path,
		                     forwarded_query, query_len,
		                     upstream_id, query,
		                     response, response_size, response_len);
		if (rc == 0 && !client_had_opt)
			*response_len = dns_strip_response_opt(response,
			                                       *response_len);
		return rc;
	}

	/* DoT: bypass UDP entirely and go directly to TLS */
	if (upstream_tls) {
		int rc = forward_tls((const struct sockaddr *)&ss, ss_len, family,
		                     upstream_hostname,
		                     forwarded_query, query_len,
		                     upstream_id, query,
		                     response, response_size, response_len);
		if (rc == 0 && !client_had_opt)
			*response_len = dns_strip_response_opt(response,
			                                       *response_len);
		return rc;
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
		int rc = forward_tcp((const struct sockaddr *)&ss, ss_len, family,
		                     forwarded_query, query_len,
		                     upstream_id, query,
		                     response, response_size, response_len);
		if (rc == 0 && !client_had_opt)
			*response_len = dns_strip_response_opt(response,
			                                       *response_len);
		return rc;
	}

	response[0]   = query[0];
	response[1]   = query[1];

	*response_len = (size_t)recvd;

	if (!client_had_opt)
		*response_len = dns_strip_response_opt(response, *response_len);

	return 0;
}

int
resolver_forward(const char upstream_addrs[][INET6_ADDRSTRLEN],
                 size_t     upstream_addr_count,
                 uint16_t upstream_port, bool upstream_tls,
                 bool upstream_doh, const char *doh_path,
                 const char    *upstream_hostname,
                 uint16_t       edns_padding_block,
                 const uint8_t *query, size_t query_len,
                 uint8_t *response, size_t response_size,
                 size_t *response_len)
{
	if (upstream_addr_count == 0) {
		fprintf(stderr, "resolver: no upstream addresses\n");
		return -1;
	}

	for (size_t i = 0; i < upstream_addr_count; i++) {
		int rc = forward_one_address(upstream_addrs[i], upstream_port,
		                             upstream_tls, upstream_doh,
		                             doh_path, upstream_hostname,
		                             edns_padding_block,
		                             query, query_len,
		                             response, response_size,
		                             response_len);
		if (rc == 0)
			return 0;
		if (i + 1 < upstream_addr_count)
			fprintf(stderr,
			        "resolver: upstream %s failed, trying %s\n",
			        upstream_addrs[i], upstream_addrs[i + 1]);
	}

	return -1;
}

int
resolver_discover_svcb(const char upstream_addrs[][INET6_ADDRSTRLEN],
                       size_t     upstream_addr_count,
                       uint16_t upstream_port, bool upstream_tls,
                       bool upstream_doh, const char *doh_path,
                       const char                       *upstream_hostname,
                       uint16_t                          edns_padding_block,
                       const char                       *resolver_name,
                       struct resolver_discovery_result *result)
{
	char     qname[DNS_MAX_NAME_LEN + 1];
	uint8_t  query[DNS_MAX_MSG_SIZE];
	uint8_t  response[DNS_MAX_MSG_SIZE];
	uint16_t id = 0;
	size_t   query_len;
	size_t   response_len = 0;

	if (result == NULL)
		return -1;
	memset(result, 0, sizeof(*result));

	if (build_discovery_qname(resolver_name, qname, sizeof(qname)) < 0)
		return -1;
	if (random_bytes(&id, sizeof(id)) < 0)
		return -1;

	query_len = build_svcb_query(query, sizeof(query), id, qname);
	if (query_len == 0)
		return -1;

	if (resolver_forward(upstream_addrs, upstream_addr_count,
	                     upstream_port, upstream_tls, upstream_doh,
	                     doh_path, upstream_hostname,
	                     edns_padding_block,
	                     query, query_len,
	                     response, sizeof(response),
	                     &response_len)
	    < 0)
		return -1;

	if (response_len < DNS_HEADER_SIZE)
		return -1;
	if ((response[3] & DNS_FLAGS_RCODE_MASK) != DNS_RCODE_OK)
		return 0;

	return parse_svcb_response(response, response_len, result);
}
