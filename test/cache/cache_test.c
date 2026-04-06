/* SPDX-License-Identifier: MIT */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "cache.h"
#include "test.h"
#include "wire.h"

#undef assert
#define assert(expr) TEST_CHECK(expr)

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
append_name(uint8_t *buf, size_t pos, const char *name)
{
	const char *label = name;

	while (*label != '\0') {
		const char *dot = strchr(label, '.');
		size_t      len = dot ? (size_t)(dot - label) : strlen(label);

		assert(len <= DNS_MAX_LABEL_LEN);
		buf[pos++] = (uint8_t)len;
		memcpy(buf + pos, label, len);
		pos += len;

		if (dot == NULL)
			break;
		label = dot + 1;
	}

	buf[pos++] = 0;
	return pos;
}

static size_t
make_query(uint8_t *buf, uint16_t id, const char *qname,
           uint16_t qtype, uint16_t qclass)
{
	memset(buf, 0, DNS_HEADER_SIZE);
	write_u16(buf, id);
	write_u16(buf + 2, DNS_FLAG_RD);
	write_u16(buf + 4, 1);

	size_t pos = DNS_HEADER_SIZE;
	pos        = append_name(buf, pos, qname);
	write_u16(buf + pos, qtype);
	write_u16(buf + pos + 2, qclass);
	return pos + 4;
}

static size_t
make_a_response(uint8_t *buf, uint16_t id, uint16_t rcode, const char *qname,
                uint32_t ttl)
{
	memset(buf, 0, DNS_HEADER_SIZE);
	write_u16(buf, id);
	write_u16(buf + 2, DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA | rcode);
	write_u16(buf + 4, 1);
	write_u16(buf + 6, 1);

	size_t pos = DNS_HEADER_SIZE;
	pos        = append_name(buf, pos, qname);
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

static size_t
make_nxdomain_response(uint8_t *buf, uint16_t id, const char *qname,
                       uint32_t soa_ttl, uint32_t minimum_ttl)
{
	memset(buf, 0, DNS_HEADER_SIZE);
	write_u16(buf, id);
	write_u16(buf + 2,
	          DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA | DNS_RCODE_NXDOMAIN);
	write_u16(buf + 4, 1);
	write_u16(buf + 8, 1);

	size_t pos = DNS_HEADER_SIZE;
	pos        = append_name(buf, pos, qname);
	write_u16(buf + pos, DNS_TYPE_A);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	pos        += 4;

	buf[pos++]  = 0xC0;
	buf[pos++]  = DNS_HEADER_SIZE;
	write_u16(buf + pos, DNS_TYPE_SOA);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	write_u32(buf + pos + 4, soa_ttl);
	write_u16(buf + pos + 8, 22);
	pos        += 10;

	buf[pos++]  = 0;
	buf[pos++]  = 0;
	write_u32(buf + pos, 1);
	write_u32(buf + pos + 4, 2);
	write_u32(buf + pos + 8, 3);
	write_u32(buf + pos + 12, 4);
	write_u32(buf + pos + 16, minimum_ttl);
	return pos + 20;
}

static size_t
make_nxdomain_without_soa_response(uint8_t *buf, uint16_t id, const char *qname)
{
	memset(buf, 0, DNS_HEADER_SIZE);
	write_u16(buf, id);
	write_u16(buf + 2,
	          DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA | DNS_RCODE_NXDOMAIN);
	write_u16(buf + 4, 1);

	size_t pos = DNS_HEADER_SIZE;
	pos        = append_name(buf, pos, qname);
	write_u16(buf + pos, DNS_TYPE_A);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	return pos + 4;
}

static uint32_t
first_rr_ttl(const uint8_t *buf, size_t len)
{
	size_t pos = DNS_HEADER_SIZE;
	int    n   = wire_skip_name(buf, len, pos);

	assert(n >= 0);
	pos += (size_t)n + 4;
	assert(pos + 10 <= len);
	n = wire_skip_name(buf, len, pos);
	assert(n >= 0);
	pos += (size_t)n;
	assert(pos + 8 <= len);
	return wire_read_u32(buf + pos + 4);
}

static void
test_negative_ttl_cap(void)
{
	struct cache               cache;
	struct dns_query_cache_key key = { 0 };
	uint8_t                    response[DNS_MAX_MSG_SIZE];
	uint8_t                    query[DNS_MAX_MSG_SIZE];
	uint8_t                    out[DNS_MAX_MSG_SIZE];
	size_t                     response_len;
	size_t                     query_len;
	size_t                     out_len = 0;

	assert(cache_init(&cache) == 0);

	response_len = make_nxdomain_response(response, 0x1111, "example.com", 3600, 60);
	query_len    = make_query(query, 0x2222, "example.com", DNS_TYPE_A, DNS_CLASS_IN);

	cache_insert(&cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN,
	             &key, response, response_len, 0);
	assert(cache_lookup(&cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN,
	                    &key, 0x3333,
	                    query + DNS_HEADER_SIZE, query_len - DNS_HEADER_SIZE,
	                    out, sizeof(out), &out_len)
	       == 1);
	assert(wire_read_u16(out) == 0x3333);
	assert(first_rr_ttl(out, out_len) == 60);

	cache_destroy(&cache);
}

static void
test_servfail_ttl_override_cap(void)
{
	struct cache               cache;
	struct dns_query_cache_key key = { 0 };
	uint8_t                    response[DNS_MAX_MSG_SIZE];
	uint8_t                    query[DNS_MAX_MSG_SIZE];
	uint8_t                    out[DNS_MAX_MSG_SIZE];
	size_t                     response_len;
	size_t                     query_len;
	size_t                     out_len = 0;

	assert(cache_init(&cache) == 0);

	response_len = make_a_response(response, 0x4444, DNS_RCODE_SERVFAIL,
	                               "example.com", 300);
	query_len    = make_query(query, 0x5555, "example.com", DNS_TYPE_A, DNS_CLASS_IN);

	cache_insert(&cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN,
	             &key, response, response_len, 5);
	assert(cache_lookup(&cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN,
	                    &key, 0x6666,
	                    query + DNS_HEADER_SIZE, query_len - DNS_HEADER_SIZE,
	                    out, sizeof(out), &out_len)
	       == 1);
	assert(wire_read_u16(out) == 0x6666);
	assert(first_rr_ttl(out, out_len) == 5);

	cache_destroy(&cache);
}

static void
test_cached_response_uses_current_question_bytes(void)
{
	struct cache               cache;
	struct dns_query_cache_key key = { 0 };
	uint8_t                    response[DNS_MAX_MSG_SIZE];
	uint8_t                    lower_query[DNS_MAX_MSG_SIZE];
	uint8_t                    out[DNS_MAX_MSG_SIZE];
	size_t                     response_len;
	size_t                     query_len;
	size_t                     out_len = 0;

	assert(cache_init(&cache) == 0);

	response_len = make_a_response(response, 0x7777, DNS_RCODE_OK,
	                               "ExAmPlE.com", 300);
	query_len    = make_query(lower_query, 0x8888, "example.com",
	                          DNS_TYPE_A, DNS_CLASS_IN);

	cache_insert(&cache, "ExAmPlE.com", DNS_TYPE_A, DNS_CLASS_IN,
	             &key, response, response_len, 0);
	assert(cache_lookup(&cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN,
	                    &key, 0x9999,
	                    lower_query + DNS_HEADER_SIZE,
	                    query_len - DNS_HEADER_SIZE,
	                    out, sizeof(out), &out_len)
	       == 1);
	assert(wire_read_u16(out) == 0x9999);
	assert(memcmp(out + DNS_HEADER_SIZE, lower_query + DNS_HEADER_SIZE,
	              query_len - DNS_HEADER_SIZE)
	       == 0);

	cache_destroy(&cache);
}

static void
test_nxdomain_without_soa_uses_floor_ttl(void)
{
	struct cache               cache;
	struct dns_query_cache_key key = { 0 };
	uint8_t                    response[DNS_MAX_MSG_SIZE];
	uint8_t                    query[DNS_MAX_MSG_SIZE];
	uint8_t                    out[DNS_MAX_MSG_SIZE];
	size_t                     response_len;
	size_t                     query_len;
	size_t                     out_len = 0;

	assert(cache_init(&cache) == 0);

	response_len = make_nxdomain_without_soa_response(response, 0xAAAA,
	                                                  "missing.example");
	query_len    = make_query(query, 0xBBBB, "missing.example",
	                          DNS_TYPE_A, DNS_CLASS_IN);

	cache_insert(&cache, "missing.example", DNS_TYPE_A, DNS_CLASS_IN,
	             &key, response, response_len, 0);
	assert(cache_lookup(&cache, "missing.example", DNS_TYPE_A, DNS_CLASS_IN,
	                    &key, 0xCCCC,
	                    query + DNS_HEADER_SIZE, query_len - DNS_HEADER_SIZE,
	                    out, sizeof(out), &out_len)
	       == 1);
	assert(wire_read_u16(out) == 0xCCCC);

	cache_destroy(&cache);
}

static void
test_lookup_promotes_entry_to_lru_head(void)
{
	struct cache               cache;
	struct dns_query_cache_key key = { 0 };
	uint8_t                    response_a[DNS_MAX_MSG_SIZE];
	uint8_t                    response_b[DNS_MAX_MSG_SIZE];
	uint8_t                    query[DNS_MAX_MSG_SIZE];
	uint8_t                    out[DNS_MAX_MSG_SIZE];
	char                       head_name[DNS_MAX_NAME_LEN + 1];
	char                       tail_name[DNS_MAX_NAME_LEN + 1];
	size_t                     response_a_len;
	size_t                     response_b_len;
	size_t                     query_len;
	size_t                     out_len = 0;

	assert(cache_init(&cache) == 0);

	response_a_len = make_a_response(response_a, 0x1111, DNS_RCODE_OK,
	                                 "alpha.example", 300);
	response_b_len = make_a_response(response_b, 0x2222, DNS_RCODE_OK,
	                                 "beta.example", 300);
	query_len      = make_query(query, 0x3333, "alpha.example",
	                            DNS_TYPE_A, DNS_CLASS_IN);

	cache_insert(&cache, "alpha.example", DNS_TYPE_A, DNS_CLASS_IN,
	             &key, response_a, response_a_len, 0);
	cache_insert(&cache, "beta.example", DNS_TYPE_A, DNS_CLASS_IN,
	             &key, response_b, response_b_len, 0);

	assert(cache_lru_head_name(&cache, head_name, sizeof(head_name)));
	assert(cache_lru_tail_name(&cache, tail_name, sizeof(tail_name)));
	TEST_EXPECT_STR_EQ(head_name, "beta.example");
	TEST_EXPECT_STR_EQ(tail_name, "alpha.example");

	assert(cache_lookup(&cache, "alpha.example", DNS_TYPE_A, DNS_CLASS_IN,
	                    &key, 0x4444,
	                    query + DNS_HEADER_SIZE, query_len - DNS_HEADER_SIZE,
	                    out, sizeof(out), &out_len)
	       == 1);
	assert(cache_lru_head_name(&cache, head_name, sizeof(head_name)));
	assert(cache_lru_tail_name(&cache, tail_name, sizeof(tail_name)));
	TEST_EXPECT_STR_EQ(head_name, "alpha.example");
	TEST_EXPECT_STR_EQ(tail_name, "beta.example");

	cache_destroy(&cache);
}

int
main(void)
{
	test_negative_ttl_cap();
	test_servfail_ttl_override_cap();
	test_cached_response_uses_current_question_bytes();
	test_nxdomain_without_soa_uses_floor_ttl();
	test_lookup_promotes_entry_to_lru_head();
	puts("cache tests passed");
	return 0;
}
