/* SPDX-License-Identifier: MIT */

#ifndef DNSKA_RESOLVER_H
#define DNSKA_RESOLVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <netinet/in.h>

/*
 * Configure upstream TLS verification.  Must be called once before any
 * forwarding occurs.  ca_file is optional (empty string -> use system
 * default trust paths), auth_name overrides SNI/hostname check (empty
 * string -> use upstream_hostname), insecure disables verification
 * entirely (use only for testing).
 */
void
resolver_set_tls_config(const char *ca_file, const char *auth_name,
                        bool insecure);

/*
 * Try each address in upstream_addrs in order until one succeeds.
 * upstream_addrs is an array of NUL-terminated IP literals.  Returns 0
 * on first successful forward, -1 if every address failed.
 *
 * upstream_doh selects DoH (RFC 8484); doh_path is the URL path
 * (defaults to /dns-query when NULL or empty).  When upstream_doh is
 * true, upstream_tls is implied.  Otherwise upstream_tls selects DoT
 * (RFC 7858); plain UDP/TCP is used when both are false.
 */
int
resolver_forward(const char upstream_addrs[][INET6_ADDRSTRLEN],
                 size_t     upstream_addr_count,
                 uint16_t upstream_port, bool upstream_tls,
                 bool upstream_doh, const char *doh_path,
                 const char    *upstream_hostname,
                 const uint8_t *query, size_t query_len,
                 uint8_t *response, size_t response_size,
                 size_t *response_len);

#endif /* DNSKA_RESOLVER_H */
