/* SPDX-License-Identifier: MIT */

#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "cache.h"
#include "dns.h"
#include "log.h"
#include "random.h"
#include "resolver.h"
#include "server.h"
#include "wire.h"

/* RFC 7766 §6.4: servers SHOULD implement an idle timeout >= 10 seconds */
enum { TCP_IDLE_TIMEOUT_SEC = 10 };

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

/*
 * Build a BADVERS response (RFC 6891 §6.1.3).  BADVERS is extended
 * rcode 16: low 4 bits in the DNS header are 0, high 8 bits (= 1) go
 * in the OPT record's TTL field.  An OPT record MUST be included.
 */
static size_t
make_badvers_response(const uint8_t *query, size_t query_len,
                      size_t   qd_wire_len,
                      uint8_t *resp, size_t resp_size)
{
	/* OPT wire: 1 (root) + 2 (type) + 2 (udp) + 4 (ttl) + 2 (rdlen) */
	enum { OPT_WIRE_LEN = 11 };

	size_t resp_len = DNS_HEADER_SIZE + qd_wire_len + OPT_WIRE_LEN;
	if (query_len < DNS_HEADER_SIZE || resp_len > resp_size)
		return 0;

	resp[0]    = query[0];
	resp[1]    = query[1];

	uint8_t rd = query[2] & 0x01;
	resp[2]    = 0x80 | rd; /* QR=1, opcode=0 */
	resp[3]    = 0x80;      /* RA=1, rcode=0 (low nibble of 16 = 0) */

	resp[4]    = 0;
	resp[5]    = qd_wire_len > 0 ? 1 : 0;
	resp[6]    = 0;
	resp[7]    = 0;
	resp[8]    = 0;
	resp[9]    = 0;
	resp[10]   = 0;
	resp[11]   = 1; /* ARCOUNT = 1 (OPT) */

	if (qd_wire_len > 0)
		memcpy(resp + DNS_HEADER_SIZE, query + DNS_HEADER_SIZE,
		       qd_wire_len);

	size_t p  = DNS_HEADER_SIZE + qd_wire_len;
	resp[p++] = 0x00; /* root name */
	resp[p++] = 0x00; /* TYPE OPT high */
	resp[p++] = 0x29; /* TYPE OPT low (41) */
	resp[p++] = 0x04; /* UDP payload size high (1232) */
	resp[p++] = 0xD0; /* UDP payload size low */
	resp[p++] = 0x01; /* extended RCODE high byte = 1 (BADVERS=16) */
	resp[p++] = 0x00; /* EDNS version = 0 */
	resp[p++] = 0x00; /* flags high (DO=0) */
	resp[p++] = 0x00; /* flags low */
	resp[p++] = 0x00; /* RDLEN high */
	resp[p++] = 0x00; /* RDLEN low */

	return p;
}

static bool
source_addr_to_v6(const struct sockaddr_storage *addr, struct in6_addr *out)
{
	memset(out, 0, sizeof(*out));

	if (addr->ss_family == AF_INET) {
		const struct sockaddr_in *a4 = (const struct sockaddr_in *)addr;

		out->s6_addr[10]             = 0xFF;
		out->s6_addr[11]             = 0xFF;
		memcpy(&out->s6_addr[12], &a4->sin_addr, sizeof(a4->sin_addr));
		return true;
	}

	if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)addr;

		*out                          = a6->sin6_addr;
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
truncate_response_for_client(uint8_t *response, size_t response_len,
                             size_t payload_limit)
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
			if (skip_rr(response, response_len, truncated_len,
			            &next_offset)
			    < 0) {
				section_counts[section] = included;
				truncated               = true;
				goto finish;
			}
			if (next_offset > limit) {
				section_counts[section] = included;
				truncated               = true;
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

	wire_write_u16(response + 4, qdcount);
	wire_write_u16(response + 6, section_counts[0]);
	wire_write_u16(response + 8, section_counts[1]);
	wire_write_u16(response + 10, section_counts[2]);
	wire_write_u16(response + 2, wire_read_u16(response + 2) | DNS_FLAG_TC);
	return truncated_len;

header_only:
	wire_write_u16(response + 4, 0);
	wire_write_u16(response + 6, 0);
	wire_write_u16(response + 8, 0);
	wire_write_u16(response + 10, 0);
	wire_write_u16(response + 2, wire_read_u16(response + 2) | DNS_FLAG_TC);
	return DNS_HEADER_SIZE;
}

static bool
source_addr_matches(const struct source_limit_entry *entry,
                    const struct sockaddr_storage   *addr)
{
	struct in6_addr candidate;

	if (!entry->in_use)
		return false;
	if (!source_addr_to_v6(addr, &candidate))
		return false;

	return memcmp(&entry->addr6, &candidate, sizeof(candidate)) == 0;
}

static void
store_source_addr(struct source_limit_entry     *entry,
                  const struct sockaddr_storage *addr)
{
	entry->in_use = source_addr_to_v6(addr, &entry->addr6);
}

static int
acquire_source_slot_locked(struct server                 *srv,
                           const struct sockaddr_storage *addr)
{
	uint32_t hash      = source_hash(addr, srv->source_hash_seed);
	int      free_slot = -1;

	for (int i = 0; i < SOURCE_LIMIT_SLOTS; i++) {
		int                        idx   = (int)((hash + (uint32_t)i) % SOURCE_LIMIT_SLOTS);
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
	if (task->tls != NULL) {
		SSL_shutdown(task->tls);
		SSL_free(task->tls);
		task->tls = NULL;
	}
	if (task->conn_fd >= 0) {
		close(task->conn_fd);
		task->conn_fd = -1;
	}
	pthread_mutex_lock(&task->srv->task_lock);
	release_source_slot_locked(task->srv, task->source_slot);
	assert(task->srv->free_task_top < MAX_CONCURRENT_QUERIES);
	task->srv->free_task_slots[task->srv->free_task_top++] = task->slot;
	pthread_mutex_unlock(&task->srv->task_lock);
	task->source_slot = -1;
}

static int
send_tcp_response(int fd, const uint8_t *response, size_t response_len)
{
	uint8_t prefix[2];
	size_t  sent = 0;

	prefix[0]    = (uint8_t)(response_len >> 8);
	prefix[1]    = (uint8_t)response_len;

	while (sent < 2) {
		ssize_t n = write(fd, prefix + sent, 2 - sent);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		sent += (size_t)n;
	}
	sent = 0;
	while (sent < response_len) {
		ssize_t n = write(fd, response + sent, response_len - sent);
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
tls_readn(SSL *ssl, uint8_t *buf, size_t len)
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
send_tls_response(SSL *ssl, const uint8_t *response, size_t response_len)
{
	uint8_t prefix[2];
	size_t  sent = 0;

	prefix[0]    = (uint8_t)(response_len >> 8);
	prefix[1]    = (uint8_t)response_len;

	while (sent < 2) {
		int n = SSL_write(ssl, prefix + sent, (int)(2 - sent));
		if (n <= 0)
			return -1;
		sent += (size_t)n;
	}
	sent = 0;
	while (sent < response_len) {
		int n = SSL_write(ssl, response + sent,
		                  (int)(response_len - sent));
		if (n <= 0)
			return -1;
		sent += (size_t)n;
	}
	return 0;
}

/*
 * Unified response sender: TLS for DoT connections, TCP otherwise.
 * For UDP connections (conn_fd < 0) always returns 0.
 */
static int
send_response(struct query_task *task, const uint8_t *response,
              size_t response_len)
{
	if (task->conn_fd >= 0) {
		if (task->tls != NULL)
			return send_tls_response(task->tls, response,
			                         response_len);
		return send_tcp_response(task->conn_fd, response, response_len);
	}
	sendto(task->sock_fd, response, response_len, 0,
	       (struct sockaddr *)&task->client_addr, task->addr_len);
	return 0;
}

/*
 * Process the DNS query already in task->query[0..task->query_len-1].
 * Sends the response via conn_fd (TCP) or sock_fd (UDP).
 * Returns  0 on success or after sending an error response.
 * Returns -1 on a fatal TCP I/O error (caller should close the connection).
 * Does NOT call release_task_slot.
 */
static int
process_dns_query(struct query_task *task)
{
	struct dns_message msg;
	char               addr_buf[INET6_ADDRSTRLEN];
	char               qtype_buf[32];
	char               rcode_buf[32];
	uint16_t           port;

	addr_str(&task->client_addr, addr_buf, sizeof(addr_buf), &port);

	if (dns_parse_message(&msg, task->query, task->query_len) < 0) {
		uint8_t response[DNS_MAX_MSG_SIZE];
		size_t  qd_wire_len  = question_wire_len_or_zero(task->query,
		                                                 task->query_len);
		size_t  response_len = make_error_response(task->query,
		                                           task->query_len,
		                                           qd_wire_len,
		                                           DNS_RCODE_FORMERR,
		                                           response,
		                                           sizeof(response));

		log_msg(LOG_WARN, "server: failed to parse query from %s:%d\n",
		        addr_buf, port);
		if (response_len > 0)
			return send_response(task, response, response_len);
		return 0;
	}

	/* RFC 1035: return NOTIMP for opcodes we do not handle */
	uint8_t opcode = (uint8_t)((msg.header.flags & DNS_FLAGS_OPCODE_MASK)
	                           >> DNS_FLAGS_OPCODE_SHIFT);
	if (opcode != DNS_OPCODE_QUERY) {
		uint8_t response[DNS_MAX_MSG_SIZE];
		size_t  response_len = make_error_response(task->query,
		                                           task->query_len,
		                                           msg.question_wire_len,
		                                           DNS_RCODE_NOTIMP,
		                                           response,
		                                           sizeof(response));

		log_msg(LOG_WARN, "server: opcode %u from %s:%d -> NOTIMP\n",
		        opcode, addr_buf, port);
		if (response_len > 0)
			return send_response(task, response, response_len);
		return 0;
	}

	/* RFC 6891 §6.1.3: reject EDNS version > 0 with BADVERS */
	if (msg.has_edns && msg.edns_version > 0) {
		uint8_t response[DNS_MAX_MSG_SIZE];
		size_t  response_len = make_badvers_response(task->query,
		                                             task->query_len,
		                                             msg.question_wire_len,
		                                             response,
		                                             sizeof(response));

		log_msg(LOG_WARN,
		        "server: EDNS version %u from %s:%d -> BADVERS\n",
		        msg.edns_version, addr_buf, port);
		if (response_len > 0)
			return send_response(task, response, response_len);
		return 0;
	}

	log_msg(LOG_INFO, "query: %s %s from %s:%d\n",
	        msg.question.name,
	        dns_type_str(msg.question.qtype, qtype_buf, sizeof(qtype_buf)),
	        addr_buf, port);

	uint8_t  response[DNS_MAX_MSG_SIZE];
	size_t   response_len = 0;
	uint16_t query_id     = msg.header.id;
	int      hit          = 0;

	if (dns_query_is_cacheable(&msg))
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
		log_msg(LOG_DEBUG, "cache: expired %s %s\n",
		        msg.question.name,
		        dns_type_str(msg.question.qtype, qtype_buf,
		                     sizeof(qtype_buf)));
	if (hit == -1)
		log_msg(LOG_WARN,
		        "cache: failed to build cached response for %s %s\n",
		        msg.question.name,
		        dns_type_str(msg.question.qtype, qtype_buf,
		                     sizeof(qtype_buf)));
	if (hit == 1) {
		log_msg(LOG_DEBUG, "cache: hit %s %s (%zu bytes)\n",
		        msg.question.name,
		        dns_type_str(msg.question.qtype, qtype_buf,
		                     sizeof(qtype_buf)),
		        response_len);
	} else {
		int rc = resolver_forward(task->srv->config.upstream_addr,
		                          task->srv->config.upstream_port,
		                          task->srv->config.upstream_tls,
		                          task->query, task->query_len,
		                          response, sizeof(response),
		                          &response_len);

		if (rc < 0) {
			log_msg(LOG_WARN,
			        "server: upstream failed for %s, "
			        "sending SERVFAIL\n",
			        msg.question.name);

			response_len = make_error_response(
			        task->query, task->query_len,
			        msg.question_wire_len,
			        DNS_RCODE_SERVFAIL,
			        response, sizeof(response));
			if (response_len == 0)
				return 0;
		} else {
			uint16_t rcode = response_len >= 4 ? (response[3] & DNS_FLAGS_RCODE_MASK) : 0;
			log_msg(LOG_INFO, "reply: %s %s -> %s (%zu bytes)\n",
			        msg.question.name,
			        dns_type_str(msg.question.qtype, qtype_buf,
			                     sizeof(qtype_buf)),
			        dns_rcode_str(rcode, rcode_buf, sizeof(rcode_buf)),
			        response_len);

			uint16_t flags     = wire_read_u16(response + 2);
			uint32_t cache_ttl = (rcode == DNS_RCODE_SERVFAIL) ? CACHE_SERVFAIL_TTL : 0;

			if (dns_query_is_cacheable(&msg)
			    && (flags & DNS_FLAG_TC) == 0
			    && (rcode == DNS_RCODE_OK
			        || rcode == DNS_RCODE_NXDOMAIN
			        || rcode == DNS_RCODE_SERVFAIL)) {
				if (!dns_response_matches_query(&msg, response,
				                                response_len)) {
					log_msg(LOG_WARN,
					        "cache: reject upstream reply "
					        "for %s %s (question mismatch "
					        "or malformed response)\n",
					        msg.question.name,
					        dns_type_str(msg.question.qtype,
					                     qtype_buf,
					                     sizeof(qtype_buf)));
				} else {
					cache_insert(&task->srv->cache,
					             msg.question.name,
					             msg.question.qtype,
					             msg.question.qclass,
					             &msg.cache_key,
					             response, response_len,
					             cache_ttl);
				}
			} else if ((flags & DNS_FLAG_TC) != 0) {
				log_msg(LOG_DEBUG,
				        "cache: skip truncated response for "
				        "%s %s\n",
				        msg.question.name,
				        dns_type_str(msg.question.qtype,
				                     qtype_buf, sizeof(qtype_buf)));
			}
		}
	}

	/* For TCP clients, the full response is always usable (RFC 7766
	 * §5); for UDP, respect the client's advertised payload limit. */
	if (task->conn_fd < 0) {
		size_t client_limit = client_udp_payload_limit(&msg.cache_key);
		if (response_len > client_limit) {
			size_t truncated_len = truncate_response_for_client(
			        response, response_len, client_limit);
			if (truncated_len == 0)
				return 0;
			response_len = truncated_len;
		}
	}

	if (send_response(task, response, response_len) < 0) {
		log_msg(LOG_ERROR, "server: write response: %s\n",
		        strerror(errno));
		return -1;
	}

	return 0;
}

/*
 * Entry point for a query worker.  For UDP, process the single query
 * already in task->query.  For TCP and DoT (RFC 7766 §6.2.2 / RFC 7858),
 * read length-prefixed messages in a loop until the client closes the
 * connection or the idle timeout expires (RFC 7766 §6.4).  DoT performs
 * the TLS handshake before entering the read loop.
 */
static void
handle_query(struct query_task *task)
{
	if (task->conn_fd >= 0) {
		/* DoT: perform TLS handshake before reading queries */
		if (task->tls_ctx != NULL) {
			SSL *ssl = SSL_new(task->tls_ctx);
			if (ssl == NULL || SSL_set_fd(ssl, task->conn_fd) != 1) {
				log_msg(LOG_ERROR,
				        "server: DoT SSL_new/set_fd failed\n");
				if (ssl != NULL)
					SSL_free(ssl);
				release_task_slot(task);
				return;
			}
			if (SSL_accept(ssl) <= 0) {
				log_msg(LOG_WARN,
				        "server: DoT TLS handshake failed: %s\n",
				        ERR_reason_error_string(ERR_get_error()));
				SSL_free(ssl);
				release_task_slot(task);
				return;
			}
			task->tls = ssl;
		}

		struct timeval tv = { .tv_sec  = TCP_IDLE_TIMEOUT_SEC,
			              .tv_usec = 0 };
		if (setsockopt(task->conn_fd, SOL_SOCKET, SO_RCVTIMEO,
		               &tv, sizeof(tv))
		            < 0
		    || setsockopt(task->conn_fd, SOL_SOCKET, SO_SNDTIMEO,
		                  &tv, sizeof(tv))
		               < 0) {
			release_task_slot(task);
			return;
		}

		for (;;) {
			uint8_t  len_buf[2];
			uint16_t msg_size;

			if (task->tls != NULL) {
				if (tls_readn(task->tls, len_buf, 2) < 0)
					break;
			} else {
				ssize_t n = recv(task->conn_fd, len_buf, 2,
				                 MSG_WAITALL);
				if (n != 2)
					break;
			}

			msg_size = (uint16_t)(((uint16_t)len_buf[0] << 8)
			                      | len_buf[1]);
			if (msg_size < DNS_HEADER_SIZE
			    || msg_size > DNS_MAX_MSG_SIZE)
				break;

			if (task->tls != NULL) {
				if (tls_readn(task->tls, task->query,
				              msg_size)
				    < 0)
					break;
			} else {
				ssize_t n = recv(task->conn_fd, task->query,
				                 msg_size, MSG_WAITALL);
				if (n != (ssize_t)msg_size)
					break;
			}
			task->query_len = (size_t)msg_size;

			if (process_dns_query(task) < 0)
				break;
		}

		release_task_slot(task);
		return;
	}

	process_dns_query(task);
	release_task_slot(task);
}

static void *
worker_thread(void *arg)
{
	struct server *srv = arg;

	pthread_mutex_lock(&srv->task_lock);
	for (;;) {
		while (srv->pending_count == 0 && !srv->shutdown)
			pthread_cond_wait(&srv->work_cond, &srv->task_lock);
		if (srv->shutdown && srv->pending_count == 0) {
			pthread_mutex_unlock(&srv->task_lock);
			return NULL;
		}
		int slot          = srv->pending[srv->pending_head];
		srv->pending_head = (srv->pending_head + 1)
		                    % MAX_CONCURRENT_QUERIES;
		srv->pending_count--;
		pthread_mutex_unlock(&srv->task_lock);

		handle_query(&srv->query_tasks[slot]);

		pthread_mutex_lock(&srv->task_lock);
	}
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

static int
bind_tcp(int family, int port)
{
	int fd = socket(family, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	int optval = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
	               &optval, sizeof(optval))
	    < 0) {
		close(fd);
		return -1;
	}

	if (family == AF_INET6) {
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
		               &optval, sizeof(optval))
		    < 0) {
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

	if (listen(fd, 32) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * Common dispatch path for UDP and TCP queries.  Takes the mutex,
 * acquires a task slot, enqueues the task, and signals a worker.
 * query/query_len are for UDP (already received); conn_fd >= 0 and
 * query_len == 0 signals TCP (worker reads the query from conn_fd).
 * On any error conn_fd is closed before returning.
 */
static void
dispatch_task(struct server *srv, const uint8_t *query, size_t query_len,
              const struct sockaddr_storage *client_addr, socklen_t addr_len,
              int sock_fd, int conn_fd, SSL_CTX *tls_ctx)
{
	pthread_mutex_lock(&srv->task_lock);

	if (srv->free_task_top == 0) {
		pthread_mutex_unlock(&srv->task_lock);
		if (conn_fd >= 0)
			close(conn_fd);
		log_msg(LOG_WARN, "server: at capacity, dropping query\n");
		return;
	}

	int source_slot = acquire_source_slot_locked(srv, client_addr);
	if (source_slot < 0) {
		pthread_mutex_unlock(&srv->task_lock);
		if (conn_fd >= 0)
			close(conn_fd);
		log_msg(LOG_WARN,
		        "server: source concurrency limit exceeded\n");
		return;
	}

	assert(srv->free_task_top > 0);
	int                slot = srv->free_task_slots[--srv->free_task_top];

	struct query_task *task = &srv->query_tasks[slot];
	task->srv               = srv;
	task->slot              = slot;
	task->source_slot       = source_slot;
	task->sock_fd           = sock_fd;
	task->conn_fd           = conn_fd;
	task->tls_ctx           = tls_ctx;
	task->tls               = NULL;
	task->query_len         = query_len;
	task->addr_len          = addr_len;
	if (query && query_len > 0)
		memcpy(task->query, query, query_len);
	memcpy(&task->client_addr, client_addr, sizeof(*client_addr));

	int tail           = (srv->pending_head + srv->pending_count)
	                     % MAX_CONCURRENT_QUERIES;
	srv->pending[tail] = slot;
	srv->pending_count++;
	pthread_cond_signal(&srv->work_cond);
	pthread_mutex_unlock(&srv->task_lock);
}

static void
accept_and_dispatch_tcp(struct server *srv, int listen_fd)
{
	struct sockaddr_storage client_addr;
	socklen_t               addr_len = sizeof(client_addr);
	int                     conn_fd;

	conn_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &addr_len);
	if (conn_fd < 0) {
		if (errno != EINTR && errno != ECONNABORTED)
			log_msg(LOG_ERROR, "server: TCP accept: %s\n",
			        strerror(errno));
		return;
	}

	/* query_len=0 signals the worker to read the query from conn_fd */
	dispatch_task(srv, NULL, 0, &client_addr, addr_len, -1, conn_fd, NULL);
}

static void
accept_and_dispatch_dot(struct server *srv, int listen_fd)
{
	struct sockaddr_storage client_addr;
	socklen_t               addr_len = sizeof(client_addr);
	int                     conn_fd;

	conn_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &addr_len);
	if (conn_fd < 0) {
		if (errno != EINTR && errno != ECONNABORTED)
			log_msg(LOG_ERROR, "server: DoT accept: %s\n",
			        strerror(errno));
		return;
	}

	dispatch_task(srv, NULL, 0, &client_addr, addr_len, -1, conn_fd,
	              srv->tls_ctx);
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
		log_msg(LOG_ERROR, "server: recvfrom: %s\n", strerror(errno));
		return;
	}

	if (n < DNS_HEADER_SIZE) {
		log_msg(LOG_WARN, "server: runt packet (%zd bytes)\n", n);
		return;
	}

	dispatch_task(srv, query, (size_t)n, &client_addr, addr_len,
	              sock_fd, -1, NULL);
}

int
server_init(struct server *srv, const struct dns_config *cfg)
{
	memset(srv, 0, sizeof(*srv));
	srv->sock_fd      = -1;
	srv->sock_fd6     = -1;
	srv->tcp_fd       = -1;
	srv->tcp_fd6      = -1;
	srv->dot_fd       = -1;
	srv->dot_fd6      = -1;
	srv->tls_ctx      = NULL;
	srv->pending_head = 0;
	srv->config       = *cfg;

	if (random_bytes(&srv->source_hash_seed,
	                 sizeof(srv->source_hash_seed))
	    < 0) {
		log_msg(LOG_ERROR,
		        "server: failed to generate source hash seed\n");
		return -1;
	}

	if (cache_init(&srv->cache) < 0) {
		log_msg(LOG_ERROR, "server: cache_init failed\n");
		return -1;
	}

	if (pthread_mutex_init(&srv->task_lock, NULL) != 0) {
		log_msg(LOG_ERROR, "server: pthread_mutex_init failed\n");
		cache_destroy(&srv->cache);
		return -1;
	}

	if (pthread_cond_init(&srv->work_cond, NULL) != 0) {
		log_msg(LOG_ERROR, "server: pthread_cond_init failed\n");
		pthread_mutex_destroy(&srv->task_lock);
		cache_destroy(&srv->cache);
		return -1;
	}

	srv->free_task_top = MAX_CONCURRENT_QUERIES;
	for (int i = 0; i < MAX_CONCURRENT_QUERIES; i++) {
		srv->free_task_slots[i]         = MAX_CONCURRENT_QUERIES - 1 - i;
		srv->query_tasks[i].source_slot = -1;
		srv->query_tasks[i].conn_fd     = -1;
		srv->query_tasks[i].tls_ctx     = NULL;
		srv->query_tasks[i].tls         = NULL;
	}

	srv->sock_fd = bind_udp(AF_INET, srv->config.listen_port);
	if (srv->sock_fd < 0) {
		log_msg(LOG_ERROR, "server: bind IPv4 UDP port %d: %s\n",
		        srv->config.listen_port, strerror(errno));
		pthread_cond_destroy(&srv->work_cond);
		pthread_mutex_destroy(&srv->task_lock);
		cache_destroy(&srv->cache);
		return -1;
	}

	srv->sock_fd6 = bind_udp(AF_INET6, srv->config.listen_port);
	if (srv->sock_fd6 < 0) {
		log_msg(LOG_WARN, "server: warning: IPv6 UDP bind port %d "
		                  "failed: %s\n",
		        srv->config.listen_port, strerror(errno));
	}

	srv->tcp_fd = bind_tcp(AF_INET, srv->config.listen_port);
	if (srv->tcp_fd < 0) {
		log_msg(LOG_WARN, "server: warning: IPv4 TCP bind port %d "
		                  "failed: %s\n",
		        srv->config.listen_port, strerror(errno));
	}

	srv->tcp_fd6 = bind_tcp(AF_INET6, srv->config.listen_port);
	if (srv->tcp_fd6 < 0) {
		log_msg(LOG_WARN, "server: warning: IPv6 TCP bind port %d "
		                  "failed: %s\n",
		        srv->config.listen_port, strerror(errno));
	}

	/* DoT listener (RFC 7858): requires cert and key paths */
	if (cfg->dot_port > 0
	    && cfg->tls_cert[0] != '\0'
	    && cfg->tls_key[0] != '\0') {
		SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
		if (ctx == NULL) {
			log_msg(LOG_ERROR,
			        "server: DoT SSL_CTX_new failed\n");
		} else {
			SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
			if (SSL_CTX_use_certificate_file(ctx, cfg->tls_cert,
			                                 SSL_FILETYPE_PEM)
			            != 1
			    || SSL_CTX_use_PrivateKey_file(ctx, cfg->tls_key,
			                                   SSL_FILETYPE_PEM)
			               != 1) {
				log_msg(LOG_ERROR,
				        "server: DoT failed to load cert/key: "
				        "cert=%s key=%s\n",
				        cfg->tls_cert, cfg->tls_key);
				SSL_CTX_free(ctx);
			} else {
				srv->tls_ctx = ctx;
				srv->dot_fd  = bind_tcp(AF_INET,
				                        cfg->dot_port);
				if (srv->dot_fd < 0)
					log_msg(LOG_WARN,
					        "server: warning: IPv4 DoT bind "
					        "port %d failed: %s\n",
					        cfg->dot_port, strerror(errno));
				srv->dot_fd6 = bind_tcp(AF_INET6,
				                        cfg->dot_port);
				if (srv->dot_fd6 < 0)
					log_msg(LOG_WARN,
					        "server: warning: IPv6 DoT bind "
					        "port %d failed: %s\n",
					        cfg->dot_port, strerror(errno));
			}
		}
	}

	/* Spawn the worker thread pool */
	for (int i = 0; i < MAX_CONCURRENT_QUERIES; i++) {
		if (pthread_create(&srv->pool[i], NULL, worker_thread,
		                   srv)
		    != 0) {
			log_msg(LOG_ERROR,
			        "server: failed to create worker thread %d: "
			        "%s\n",
			        i, strerror(errno));
			/* Signal already-running threads to exit */
			pthread_mutex_lock(&srv->task_lock);
			srv->shutdown = true;
			pthread_cond_broadcast(&srv->work_cond);
			pthread_mutex_unlock(&srv->task_lock);
			for (int j = 0; j < i; j++)
				pthread_join(srv->pool[j], NULL);
			if (srv->sock_fd >= 0)
				close(srv->sock_fd);
			if (srv->sock_fd6 >= 0)
				close(srv->sock_fd6);
			if (srv->tcp_fd >= 0)
				close(srv->tcp_fd);
			if (srv->tcp_fd6 >= 0)
				close(srv->tcp_fd6);
			if (srv->dot_fd >= 0)
				close(srv->dot_fd);
			if (srv->dot_fd6 >= 0)
				close(srv->dot_fd6);
			if (srv->tls_ctx != NULL)
				SSL_CTX_free(srv->tls_ctx);
			pthread_cond_destroy(&srv->work_cond);
			pthread_mutex_destroy(&srv->task_lock);
			cache_destroy(&srv->cache);
			return -1;
		}
	}

	srv->running = 1;
	log_msg(LOG_INFO, "server: listening on 0.0.0.0:%d (UDP+TCP), "
	                  "upstream %s:%d%s\n",
	        srv->config.listen_port, srv->config.upstream_addr,
	        srv->config.upstream_port,
	        srv->config.upstream_tls ? " (DoT)" : "");
	if (srv->tls_ctx != NULL)
		log_msg(LOG_INFO,
		        "server: DoT listener on port %d\n",
		        srv->config.dot_port);
	log_msg(LOG_WARN, "server: warning: no client ACL and only basic "
	                  "per-source limits; not safe for public exposure\n");

	return 0;
}

int
server_run(struct server *srv)
{
	while (srv->running) {
		struct pollfd pfds[6];
		nfds_t        nfds = 0;

		memset(pfds, 0, sizeof(pfds));

		pfds[nfds].fd     = srv->sock_fd;
		pfds[nfds].events = POLLIN;
		nfds++;

		if (srv->sock_fd6 >= 0) {
			pfds[nfds].fd     = srv->sock_fd6;
			pfds[nfds].events = POLLIN;
			nfds++;
		}
		if (srv->tcp_fd >= 0) {
			pfds[nfds].fd     = srv->tcp_fd;
			pfds[nfds].events = POLLIN;
			nfds++;
		}
		if (srv->tcp_fd6 >= 0) {
			pfds[nfds].fd     = srv->tcp_fd6;
			pfds[nfds].events = POLLIN;
			nfds++;
		}
		if (srv->dot_fd >= 0) {
			pfds[nfds].fd     = srv->dot_fd;
			pfds[nfds].events = POLLIN;
			nfds++;
		}
		if (srv->dot_fd6 >= 0) {
			pfds[nfds].fd     = srv->dot_fd6;
			pfds[nfds].events = POLLIN;
			nfds++;
		}

		int ret = poll(pfds, nfds, 1000);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			log_msg(LOG_ERROR, "server: poll: %s\n", strerror(errno));
			return -1;
		}

		if (ret == 0)
			continue;

		for (nfds_t i = 0; i < nfds; i++) {
			if ((pfds[i].revents & POLLIN) == 0)
				continue;
			if (pfds[i].fd == srv->dot_fd
			    || pfds[i].fd == srv->dot_fd6) {
				accept_and_dispatch_dot(srv, pfds[i].fd);
			} else if (pfds[i].fd == srv->tcp_fd
			           || pfds[i].fd == srv->tcp_fd6) {
				accept_and_dispatch_tcp(srv, pfds[i].fd);
			} else {
				receive_and_dispatch(srv, pfds[i].fd);
			}
		}
	}

	return 0;
}

void
server_stop(struct server *srv)
{
	srv->running = 0;

	/* Signal all idle workers to exit, then join them all */
	pthread_mutex_lock(&srv->task_lock);
	srv->shutdown = true;
	pthread_cond_broadcast(&srv->work_cond);
	pthread_mutex_unlock(&srv->task_lock);

	for (int i = 0; i < MAX_CONCURRENT_QUERIES; i++)
		pthread_join(srv->pool[i], NULL);

	if (srv->sock_fd >= 0) {
		close(srv->sock_fd);
		srv->sock_fd = -1;
	}
	if (srv->sock_fd6 >= 0) {
		close(srv->sock_fd6);
		srv->sock_fd6 = -1;
	}
	if (srv->tcp_fd >= 0) {
		close(srv->tcp_fd);
		srv->tcp_fd = -1;
	}
	if (srv->tcp_fd6 >= 0) {
		close(srv->tcp_fd6);
		srv->tcp_fd6 = -1;
	}
	if (srv->dot_fd >= 0) {
		close(srv->dot_fd);
		srv->dot_fd = -1;
	}
	if (srv->dot_fd6 >= 0) {
		close(srv->dot_fd6);
		srv->dot_fd6 = -1;
	}
	if (srv->tls_ctx != NULL) {
		SSL_CTX_free(srv->tls_ctx);
		srv->tls_ctx = NULL;
	}

	pthread_cond_destroy(&srv->work_cond);
	pthread_mutex_destroy(&srv->task_lock);
	cache_destroy(&srv->cache);
}
