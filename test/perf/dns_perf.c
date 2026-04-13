/* SPDX-License-Identifier: MIT */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "dns.h"

static void
write_u16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static size_t
make_query(uint8_t *buf, uint16_t id, const char *name, uint16_t qtype)
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
	write_u16(buf + pos, qtype);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	return pos + 4;
}

static void
bench_dns_parse_message(void)
{
	uint8_t            buf[DNS_MAX_MSG_SIZE];
	struct dns_message msg;
	size_t             len;
	struct timespec    t0, t1;
	long               n = 1000000;
	long               i;
	double             elapsed;

	len = make_query(buf, 0x1234, "example.com", DNS_TYPE_A);

	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (i = 0; i < n; i++)
		dns_parse_message(&msg, buf, len);
	clock_gettime(CLOCK_MONOTONIC, &t1);

	elapsed = (double)(t1.tv_sec - t0.tv_sec)
	          + (double)(t1.tv_nsec - t0.tv_nsec) * 1e-9;
	printf("dns_parse_message  %ldM ops  %.3f s  %.1f ns/op\n",
	       n / 1000000, elapsed, elapsed * 1e9 / (double)n);
}

int
main(void)
{
	bench_dns_parse_message();
	return 0;
}
