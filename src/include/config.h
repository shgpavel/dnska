/* SPDX-License-Identifier: MIT */

#ifndef DNSKA_CONFIG_H
#define DNSKA_CONFIG_H

#include <stdint.h>

struct dns_config {
	int      listen_port;
	char     upstream_addr[256];
	uint16_t upstream_port;
};

int
config_load(const char *path, struct dns_config *cfg);
int
config_parse_port_u16(const char *value, uint16_t *out);

#endif /* DNSKA_CONFIG_H */
