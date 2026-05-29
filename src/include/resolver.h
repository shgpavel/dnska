/* SPDX-License-Identifier: MIT */

#ifndef DNSKA_RESOLVER_H
#define DNSKA_RESOLVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <netinet/in.h>

#include "config.h"

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

struct resolver_discovery_result {
	bool     found;
	bool     supports_dot;
	bool     supports_doh;
	bool     supports_doq;
	bool     supports_odoh;
	uint16_t priority;
	uint16_t port;
	char     target_name[256];
	char     doh_path[128];
};

/*
 * Try each address in upstream_addrs in order until one succeeds.
 * upstream_addrs is an array of NUL-terminated IP literals.  Returns 0
 * on first successful forward, -1 if every address failed.
 *
 * upstream_transport selects plain DNS (UDP with TCP fallback), DoT
 * (RFC 7858), or DoH (RFC 8484).  doh_path is the URL path for DoH
 * (defaults to /dns-query when NULL or empty).
 *
 * edns_padding_block enables EDNS(0) padding for encrypted upstream
 * transports (DoT/DoH) when non-zero.  Plain DNS forwarding is never
 * padded by this option.
 */
int
resolver_forward_transport(const char                  upstream_addrs[][INET6_ADDRSTRLEN],
                           size_t                      upstream_addr_count,
                           uint16_t                    upstream_port,
                           enum dns_upstream_transport upstream_transport,
                           const char                 *doh_path,
                           const char                 *upstream_hostname,
                           uint16_t                    edns_padding_block,
                           const uint8_t *query, size_t query_len,
                           uint8_t *response, size_t response_size,
                           size_t *response_len);

/*
 * Compatibility wrapper for legacy callers that still pass upstream_tls and
 * upstream_doh booleans.  upstream_doh takes precedence, matching historical
 * behavior.
 */
int
resolver_forward(const char upstream_addrs[][INET6_ADDRSTRLEN],
                 size_t     upstream_addr_count,
                 uint16_t upstream_port, bool upstream_tls,
                 bool upstream_doh, const char *doh_path,
                 const char    *upstream_hostname,
                 uint16_t       edns_padding_block,
                 const uint8_t *query, size_t query_len,
                 uint8_t *response, size_t response_size,
                 size_t *response_len);

/*
 * Query _dns.<resolver_name> SVCB metadata using the already configured
 * bootstrap upstream.  The result is advisory: callers should keep their
 * previous transport as fallback if no supported metadata is found.
 */
int
resolver_discover_svcb_transport(
        const char upstream_addrs[][INET6_ADDRSTRLEN],
        size_t upstream_addr_count, uint16_t upstream_port,
        enum dns_upstream_transport upstream_transport,
        const char *doh_path, const char *upstream_hostname,
        uint16_t edns_padding_block, const char *resolver_name,
        struct resolver_discovery_result *result);

int
resolver_discover_svcb(const char upstream_addrs[][INET6_ADDRSTRLEN],
                       size_t     upstream_addr_count,
                       uint16_t upstream_port, bool upstream_tls,
                       bool upstream_doh, const char *doh_path,
                       const char                       *upstream_hostname,
                       uint16_t                          edns_padding_block,
                       const char                       *resolver_name,
                       struct resolver_discovery_result *result);

#endif /* DNSKA_RESOLVER_H */
