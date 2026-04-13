/* SPDX-License-Identifier: MIT */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "cache.h"

static void
write_u16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static void
write_u32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static size_t
make_query(uint8_t *buf, uint16_t id, const char *name)
{
	const char *label;
	size_t      pos;

	memset(buf, 0, DNS_HEADER_SIZE);
	write_u16(buf, id);
	write_u16(buf + 2, DNS_FLAG_RD);
	write_u16(buf + 4, 1);

	pos   = DNS_HEADER_SIZE;
	label = name;
	while (*label != '\0') {
		const char *dot = strchr(label, '.');
		size_t      len = dot ? (size_t)(dot - label) : strlen(label);
		buf[pos++]      = (uint8_t)len;
		memcpy(buf + pos, label, len);
		pos += len;
		if (dot == NULL)
			break;
		label = dot + 1;
	}
	buf[pos++] = 0;
	write_u16(buf + pos, DNS_TYPE_A);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	return pos + 4;
}

static size_t
make_a_response(uint8_t *buf, uint16_t id, const char *name, uint32_t ttl)
{
	const char *label;
	size_t      pos;

	memset(buf, 0, DNS_HEADER_SIZE);
	write_u16(buf, id);
	write_u16(buf + 2, DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA);
	write_u16(buf + 4, 1);
	write_u16(buf + 6, 1);

	pos   = DNS_HEADER_SIZE;
	label = name;
	while (*label != '\0') {
		const char *dot = strchr(label, '.');
		size_t      len = dot ? (size_t)(dot - label) : strlen(label);
		buf[pos++]      = (uint8_t)len;
		memcpy(buf + pos, label, len);
		pos += len;
		if (dot == NULL)
			break;
		label = dot + 1;
	}
	buf[pos++] = 0;
	write_u16(buf + pos, DNS_TYPE_A);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	pos        += 4;

	buf[pos++]  = 0xC0;
	buf[pos++]  = DNS_HEADER_SIZE;
	write_u16(buf + pos, DNS_TYPE_A);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	write_u32(buf + pos + 4, ttl);
	write_u16(buf + pos + 8, 4);
	pos        += 10;
	buf[pos++]  = 192;
	buf[pos++]  = 0;
	buf[pos++]  = 2;
	buf[pos++]  = 1;
	return pos;
}

static void
bench_cache_insert(void)
{
	struct cache               cache;
	struct dns_query_cache_key key = { 0 };
	uint8_t                    response[DNS_MAX_MSG_SIZE];
	size_t                     response_len;
	struct timespec            t0, t1;
	long                       n = 1000000;
	long                       i;
	double                     elapsed;

	cache_init(&cache);
	response_len = make_a_response(response, 0x1111, "example.com", 3600);

	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (i = 0; i < n; i++)
		cache_insert(&cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN,
		             &key, response, response_len, 0);
	clock_gettime(CLOCK_MONOTONIC, &t1);

	elapsed = (double)(t1.tv_sec - t0.tv_sec)
	          + (double)(t1.tv_nsec - t0.tv_nsec) * 1e-9;
	printf("cache_insert       %ldM ops  %.3f s  %.1f ns/op\n",
	       n / 1000000, elapsed, elapsed * 1e9 / (double)n);

	cache_destroy(&cache);
}

static void
bench_cache_lookup_hit(void)
{
	struct cache               cache;
	struct dns_query_cache_key key = { 0 };
	uint8_t                    response[DNS_MAX_MSG_SIZE];
	uint8_t                    query[DNS_MAX_MSG_SIZE];
	uint8_t                    out[DNS_MAX_MSG_SIZE];
	size_t                     response_len;
	size_t                     query_len;
	size_t                     out_len;
	struct timespec            t0, t1;
	long                       n = 1000000;
	long                       i;
	double                     elapsed;

	cache_init(&cache);
	response_len = make_a_response(response, 0x1111, "example.com", 3600);
	query_len    = make_query(query, 0x2222, "example.com");
	cache_insert(&cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN,
	             &key, response, response_len, 0);

	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (i = 0; i < n; i++) {
		out_len = 0;
		cache_lookup(&cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN,
		             &key, 0x3333,
		             query + DNS_HEADER_SIZE,
		             query_len - DNS_HEADER_SIZE,
		             out, sizeof(out), &out_len);
	}
	clock_gettime(CLOCK_MONOTONIC, &t1);

	elapsed = (double)(t1.tv_sec - t0.tv_sec)
	          + (double)(t1.tv_nsec - t0.tv_nsec) * 1e-9;
	printf("cache_lookup (hit) %ldM ops  %.3f s  %.1f ns/op\n",
	       n / 1000000, elapsed, elapsed * 1e9 / (double)n);

	cache_destroy(&cache);
}

int
main(void)
{
	bench_cache_insert();
	bench_cache_lookup_hit();
	return 0;
}
