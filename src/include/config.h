/* SPDX-License-Identifier: MIT */

#ifndef DNSKA_CONFIG_H
#define DNSKA_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <netinet/in.h>

enum {
	DNS_UPSTREAM_MAX_ADDRS         = 4,
	DNS_EDNS_PADDING_DEFAULT_BLOCK = 128,
	DNS_EDNS_PADDING_MAX_BLOCK     = 512,
};

enum dns_listen_mode {
	DNS_LISTEN_AUTO = 0,
	DNS_LISTEN_PLAIN,
	DNS_LISTEN_DOT,
};

struct dns_config {
	int                  listen_port;
	enum dns_listen_mode listen_mode;
	bool                 listen_port_explicit;
	bool                 listen_doh;
	int                  doh_listen_port;
	bool                 doh_listen_port_explicit;
	char                 upstream_addr[256]; /* primary upstream IP for logs */
	char                 upstream_addrs[DNS_UPSTREAM_MAX_ADDRS][INET6_ADDRSTRLEN];
	size_t               upstream_addr_count;
	char                 upstream_hostname[256]; /* original hostname, empty if IP */
	uint16_t             upstream_port;
	bool                 upstream_port_explicit;
	bool                 upstream_tls;       /* forward to upstream over DoT */
	bool                 upstream_doh;       /* forward upstream over DoH (RFC 8484) */
	char                 doh_path[128];      /* DoH URL path (default /dns-query) */
	bool                 edns_padding;       /* pad encrypted upstream queries */
	uint16_t             edns_padding_block; /* RFC 8467-style block size */
	bool                 resolver_discovery; /* opt-in SVCB/DDR metadata query */
	char                 resolver_discovery_name[256];
	char                 tls_cert[256];      /* PEM cert for DoT listener */
	char                 tls_key[256];       /* PEM key for DoT listener */
	char                 tls_ca_file[256];   /* PEM CA bundle for upstream verify */
	char                 tls_auth_name[256]; /* SNI/verify override for IP upstream */
	bool                 tls_insecure;       /* skip upstream cert verification */
};

int
config_load(const char *path, struct dns_config *cfg);
int
config_parse_port_u16(const char *value, uint16_t *out);
int
config_parse_edns_padding_block(const char *value, uint16_t *out);
int
config_parse_listen_mode(const char *value, enum dns_listen_mode *out);
enum dns_listen_mode
config_effective_listen_mode(const struct dns_config *cfg);
void
config_apply_transport_defaults(struct dns_config *cfg, bool upstream_is_hostname);

#endif /* DNSKA_CONFIG_H */
