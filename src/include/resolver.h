/* SPDX-License-Identifier: MIT */

#ifndef DNSKA_RESOLVER_H
#define DNSKA_RESOLVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

int
resolver_forward(const char *upstream_addr, uint16_t upstream_port,
                 bool           upstream_tls,
                 const uint8_t *query, size_t query_len,
                 uint8_t *response, size_t response_size,
                 size_t *response_len);

#endif /* DNSKA_RESOLVER_H */
