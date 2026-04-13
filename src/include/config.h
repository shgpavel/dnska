/* SPDX-License-Identifier: MIT */

#ifndef DNSKA_CONFIG_H
#define DNSKA_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

struct dns_config {
	int      listen_port;
	int      dot_port; /* DoT listen port; 0 = disabled */
	char     upstream_addr[256];
	uint16_t upstream_port;
	bool     upstream_tls;  /* forward to upstream over DoT */
	char     tls_cert[256]; /* PEM cert for DoT listener */
	char     tls_key[256];  /* PEM key for DoT listener */
};

int
config_load(const char *path, struct dns_config *cfg);
int
config_parse_port_u16(const char *value, uint16_t *out);

#endif /* DNSKA_CONFIG_H */
