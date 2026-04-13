/* SPDX-License-Identifier: MIT */

#ifndef DNSKA_WIRE_H
#define DNSKA_WIRE_H

#include <stddef.h>
#include <stdint.h>

enum {
	WIRE_NAME_MAX_HOPS = 10,
};

static inline uint16_t
wire_read_u16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

static inline uint32_t
wire_read_u32(const uint8_t *p)
{
	return ((uint32_t)wire_read_u16(p) << 16) | wire_read_u16(p + 2);
}

static inline void
wire_write_u16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static inline void
wire_write_u32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

int
wire_skip_name(const uint8_t *buf, size_t buf_len, size_t offset);

#endif /* DNSKA_WIRE_H */
