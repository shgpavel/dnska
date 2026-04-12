/* SPDX-License-Identifier: MIT */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dns.h"
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
append_fill_label(uint8_t *buf, size_t pos, uint8_t len, char ch)
{
	buf[pos++] = len;
	memset(buf + pos, ch, len);
	return pos + len;
}

static size_t
append_name(uint8_t *buf, size_t pos, const char *name)
{
	const char *label = name;

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
	return pos;
}

static size_t
make_header(uint8_t *buf, uint16_t qdcount, uint16_t ancount,
            uint16_t nscount, uint16_t arcount)
{
	memset(buf, 0, DNS_HEADER_SIZE);
	write_u16(buf + 4, qdcount);
	write_u16(buf + 6, ancount);
	write_u16(buf + 8, nscount);
	write_u16(buf + 10, arcount);
	return DNS_HEADER_SIZE;
}

static size_t
append_opt_record(uint8_t *buf, size_t pos, uint16_t udp_size,
                  uint32_t ttl, const uint8_t *rdata, uint16_t rdlen)
{
	buf[pos++] = 0;
	write_u16(buf + pos, DNS_TYPE_OPT);
	write_u16(buf + pos + 2, udp_size);
	write_u32(buf + pos + 4, ttl);
	write_u16(buf + pos + 8, rdlen);
	pos += 10;

	if (rdlen > 0) {
		memcpy(buf + pos, rdata, rdlen);
		pos += rdlen;
	}

	return pos;
}

/* --- name parsing --- */

static void
test_parse_name_max_length(void)
{
	uint8_t buf[256];
	char    out[DNS_MAX_NAME_LEN + 1];
	size_t  consumed = 0;
	size_t  pos      = 0;

	pos        = append_fill_label(buf, pos, 63, 'a');
	pos        = append_fill_label(buf, pos, 63, 'b');
	pos        = append_fill_label(buf, pos, 63, 'c');
	pos        = append_fill_label(buf, pos, 61, 'd');
	buf[pos++] = 0;

	assert(pos == 255);
	assert(dns_parse_name(buf, pos, 0, out, sizeof(out), &consumed) == 0);
	assert(consumed == pos);
	assert(strlen(out) == 253);
	assert(out[63] == '.');
	assert(out[127] == '.');
	assert(out[191] == '.');
}

static void
test_parse_root_name(void)
{
	uint8_t buf[] = { 0 };
	char    out[DNS_MAX_NAME_LEN + 1];
	size_t  consumed = 0;

	assert(dns_parse_name(buf, sizeof(buf), 0, out, sizeof(out), &consumed)
	       == 0);
	assert(consumed == 1);
	assert(strcmp(out, "") == 0);
}

static void
test_parse_name_pointer_failures(void)
{
	uint8_t loop_buf[] = { 0xC0, 0x00 };
	uint8_t eob_buf[]  = { 0xC0, 0x02 };
	uint8_t hop_buf[23];
	char    out[DNS_MAX_NAME_LEN + 1];

	memset(hop_buf, 0, sizeof(hop_buf));
	for (size_t pos = 0; pos + 2 <= sizeof(hop_buf) - 1; pos += 2) {
		hop_buf[pos]     = 0xC0;
		hop_buf[pos + 1] = (uint8_t)(pos + 2);
	}
	hop_buf[22] = 0;

	assert(dns_parse_name(loop_buf, sizeof(loop_buf), 0, out, sizeof(out),
	                      NULL)
	       < 0);
	assert(dns_parse_name(eob_buf, sizeof(eob_buf), 0, out, sizeof(out),
	                      NULL)
	       < 0);
	assert(dns_parse_name(hop_buf, sizeof(hop_buf), 0, out, sizeof(out),
	                      NULL)
	       < 0);
}

static void
test_parse_name_valid_pointer(void)
{
	/* "foo\0" at offset 0; pointer to offset 0 at offset 5 */
	uint8_t buf[8];
	char    out[DNS_MAX_NAME_LEN + 1];
	size_t  consumed = 0;

	buf[0] = 3;
	buf[1] = 'f';
	buf[2] = 'o';
	buf[3] = 'o';
	buf[4] = 0;
	buf[5] = 0xC0;
	buf[6] = 0x00;

	assert(dns_parse_name(buf, 7, 5, out, sizeof(out), &consumed) == 0);
	assert(consumed == 2);
	assert(strcmp(out, "foo") == 0);
}

static void
test_wire_skip_name_rejects_truncated_label_data(void)
{
	uint8_t truncated_label[] = { 3, 'w', 'w' };

	assert(wire_skip_name(truncated_label, sizeof(truncated_label), 0) < 0);
}

/* --- message parsing: structure --- */

static void
test_parse_message_zero_qdcount(void)
{
	/* qdcount=0 → parse must fail */
	uint8_t            buf[DNS_HEADER_SIZE] = { 0 };
	struct dns_message msg;

	assert(dns_parse_message(&msg, buf, sizeof(buf)) < 0);
}

static void
test_multi_question_query(void)
{
	uint8_t            buf[DNS_MAX_MSG_SIZE];
	struct dns_message msg;
	size_t             pos = make_header(buf, 2, 0, 0, 0);

	pos = append_name(buf, pos, "example.com");
	write_u16(buf + pos, DNS_TYPE_A);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	pos += 4;

	pos = append_name(buf, pos, "example.net");
	write_u16(buf + pos, DNS_TYPE_AAAA);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	pos += 4;

	assert(dns_parse_message(&msg, buf, pos) == 0);
	assert(msg.header.qdcount == 2);
	assert(strcmp(msg.question.name, "example.com") == 0);
	assert(msg.question.qtype == DNS_TYPE_A);
	assert(!msg.cacheable);
}

static void
test_parse_message_normalizes_name_to_lowercase(void)
{
	uint8_t            buf[DNS_MAX_MSG_SIZE];
	struct dns_message msg;
	size_t             pos = make_header(buf, 1, 0, 0, 0);

	write_u16(buf, 0x1234);
	write_u16(buf + 2, DNS_FLAG_RD);
	pos = append_name(buf, pos, "ExAmPlE.CoM");
	write_u16(buf + pos, DNS_TYPE_A);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	pos += 4;

	assert(dns_parse_message(&msg, buf, pos) == 0);
	assert(strcmp(msg.question.name, "example.com") == 0);
}

static void
test_truncated_messages(void)
{
	uint8_t            buf[DNS_MAX_MSG_SIZE];
	struct dns_message msg;
	size_t             pos = make_header(buf, 1, 0, 0, 1);

	pos = append_name(buf, pos, "example.com");
	assert(dns_parse_message(&msg, buf, pos) < 0);

	pos = make_header(buf, 1, 0, 0, 1);
	pos = append_name(buf, pos, "example.com");
	write_u16(buf + pos, DNS_TYPE_A);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	pos += 4;
	assert(dns_parse_message(&msg, buf, pos) < 0);
}

static void
test_trailing_garbage_rejected(void)
{
	uint8_t            buf[DNS_MAX_MSG_SIZE];
	struct dns_message msg;
	size_t             pos = make_header(buf, 1, 0, 0, 0);

	pos        = append_name(buf, pos, "example.com");
	write_u16(buf + pos, DNS_TYPE_A);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	pos        += 4;
	buf[pos++]  = 0xFF; /* trailing garbage byte */

	assert(dns_parse_message(&msg, buf, pos) < 0);
}

/* --- message parsing: cacheability --- */

static void
test_non_query_opcode_not_cacheable(void)
{
	uint8_t            buf[DNS_MAX_MSG_SIZE];
	struct dns_message msg;
	size_t             pos = make_header(buf, 1, 0, 0, 0);

	write_u16(buf, 0x1234);
	/* STATUS opcode = 2, bits 14:11 */
	write_u16(buf + 2, (uint16_t)(DNS_OPCODE_STATUS << DNS_FLAGS_OPCODE_SHIFT));
	pos = append_name(buf, pos, "example.com");
	write_u16(buf + pos, DNS_TYPE_A);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	pos += 4;

	assert(dns_parse_message(&msg, buf, pos) == 0);
	assert(!msg.cacheable);
}

static void
test_query_with_answer_section_not_cacheable(void)
{
	uint8_t            buf[DNS_MAX_MSG_SIZE];
	struct dns_message msg;
	size_t             pos = make_header(buf, 1, 1, 0, 0);

	write_u16(buf, 0x1234);
	write_u16(buf + 2, DNS_FLAG_RD);
	pos        = append_name(buf, pos, "example.com");
	write_u16(buf + pos, DNS_TYPE_A);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	pos        += 4;

	/* Answer section RR (compressed name) */
	buf[pos++]  = 0xC0;
	buf[pos++]  = DNS_HEADER_SIZE;
	write_u16(buf + pos, DNS_TYPE_A);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	write_u32(buf + pos + 4, 300);
	write_u16(buf + pos + 8, 4);
	pos        += 10;
	buf[pos++]  = 1;
	buf[pos++]  = 2;
	buf[pos++]  = 3;
	buf[pos++]  = 4;

	assert(dns_parse_message(&msg, buf, pos) == 0);
	assert(!msg.cacheable);
}

static void
test_multiple_opt_records_not_cacheable(void)
{
	uint8_t            buf[DNS_MAX_MSG_SIZE];
	struct dns_message msg;
	size_t             pos = make_header(buf, 1, 0, 0, 2);

	write_u16(buf, 0x1234);
	write_u16(buf + 2, DNS_FLAG_RD);
	pos = append_name(buf, pos, "example.com");
	write_u16(buf + pos, DNS_TYPE_A);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	pos += 4;
	pos = append_opt_record(buf, pos, 1232, 0, NULL, 0);
	pos = append_opt_record(buf, pos, 1232, 0, NULL, 0);

	assert(dns_parse_message(&msg, buf, pos) == 0);
	assert(!msg.cacheable);
}

static void
test_opt_in_wrong_section(void)
{
	uint8_t            buf[DNS_MAX_MSG_SIZE];
	struct dns_message msg;
	size_t             pos = make_header(buf, 1, 1, 0, 0);

	pos        = append_name(buf, pos, "example.com");
	write_u16(buf + pos, DNS_TYPE_A);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	pos        += 4;

	buf[pos++]  = 0xC0;
	buf[pos++]  = DNS_HEADER_SIZE;
	write_u16(buf + pos, DNS_TYPE_OPT);
	write_u16(buf + pos + 2, 1232);
	memset(buf + pos + 4, 0, 6);
	pos += 10;

	assert(dns_parse_message(&msg, buf, pos) == 0);
	assert(!msg.cacheable);
}

/* --- message parsing: EDNS --- */

static void
test_edns_version_zero_sets_has_edns(void)
{
	/* OPT with TTL=0 → has_edns=true, edns_version=0 */
	uint8_t            buf[DNS_MAX_MSG_SIZE];
	struct dns_message msg;
	size_t             pos = make_header(buf, 1, 0, 0, 1);

	write_u16(buf, 0x1234);
	write_u16(buf + 2, DNS_FLAG_RD);
	pos = append_name(buf, pos, "example.com");
	write_u16(buf + pos, DNS_TYPE_A);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	pos += 4;
	pos = append_opt_record(buf, pos, 1232, 0x00000000UL, NULL, 0);

	assert(dns_parse_message(&msg, buf, pos) == 0);
	assert(msg.has_edns);
	assert(msg.edns_version == 0);
	assert(msg.cacheable);
}

static void
test_edns_version_nonzero_extracted(void)
{
	/* OPT TTL = 0x00030000 → bits 23-16 = 3 → edns_version=3 */
	uint8_t            buf[DNS_MAX_MSG_SIZE];
	struct dns_message msg;
	size_t             pos = make_header(buf, 1, 0, 0, 1);

	write_u16(buf, 0x1234);
	write_u16(buf + 2, DNS_FLAG_RD);
	pos = append_name(buf, pos, "example.com");
	write_u16(buf + pos, DNS_TYPE_A);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	pos += 4;
	pos = append_opt_record(buf, pos, 1232, 0x00030000UL, NULL, 0);

	assert(dns_parse_message(&msg, buf, pos) == 0);
	assert(msg.has_edns);
	assert(msg.edns_version == 3);
}

static void
test_edns_version_extracted_even_when_not_cacheable(void)
{
	/* Multi-question query (not cacheable) with EDNS v1 → has_edns still set */
	uint8_t            buf[DNS_MAX_MSG_SIZE];
	struct dns_message msg;
	size_t             pos = make_header(buf, 2, 0, 0, 1);

	write_u16(buf, 0x1234);
	write_u16(buf + 2, DNS_FLAG_RD);

	pos = append_name(buf, pos, "example.com");
	write_u16(buf + pos, DNS_TYPE_A);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	pos += 4;

	pos = append_name(buf, pos, "example.net");
	write_u16(buf + pos, DNS_TYPE_AAAA);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	pos += 4;

	/* EDNS version = 1 in TTL bits 23-16 */
	pos = append_opt_record(buf, pos, 1232, 0x00010000UL, NULL, 0);

	assert(dns_parse_message(&msg, buf, pos) == 0);
	assert(!msg.cacheable);
	assert(msg.has_edns);
	assert(msg.edns_version == 1);
}

static void
test_no_opt_has_edns_false(void)
{
	/* No OPT record → has_edns=false, edns_version=0 */
	uint8_t            buf[DNS_MAX_MSG_SIZE];
	struct dns_message msg;
	size_t             pos = make_header(buf, 1, 0, 0, 0);

	pos = append_name(buf, pos, "example.com");
	write_u16(buf + pos, DNS_TYPE_A);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	pos += 4;

	assert(dns_parse_message(&msg, buf, pos) == 0);
	assert(!msg.has_edns);
	assert(msg.edns_version == 0);
}

/* --- EDNS cache-key normalization --- */

static void
test_opt_cookie_ignored_in_cache_key(void)
{
	uint8_t            buf_a[DNS_MAX_MSG_SIZE];
	uint8_t            buf_b[DNS_MAX_MSG_SIZE];
	struct dns_message msg_a;
	struct dns_message msg_b;
	uint8_t            cookie_a[] = {
		0x00, DNS_EDNS_OPTION_COOKIE,
		0x00, 0x08,
		0x01, 0x23, 0x45, 0x67,
		0x89, 0xAB, 0xCD, 0xEF,
	};
	uint8_t            cookie_b[] = {
		0x00, DNS_EDNS_OPTION_COOKIE,
		0x00, 0x08,
		0x10, 0x32, 0x54, 0x76,
		0x98, 0xBA, 0xDC, 0xFE,
	};
	size_t             pos_a;
	size_t             pos_b;

	pos_a = make_header(buf_a, 1, 0, 0, 1);
	write_u16(buf_a, 0x1234);
	write_u16(buf_a + 2, DNS_FLAG_RD | DNS_FLAG_AD);
	pos_a = append_name(buf_a, pos_a, "example.com");
	write_u16(buf_a + pos_a, DNS_TYPE_A);
	write_u16(buf_a + pos_a + 2, DNS_CLASS_IN);
	pos_a += 4;
	pos_a = append_opt_record(buf_a, pos_a, 1232, 0, cookie_a,
	                          sizeof(cookie_a));

	pos_b = make_header(buf_b, 1, 0, 0, 1);
	write_u16(buf_b, 0x5678);
	write_u16(buf_b + 2, DNS_FLAG_RD | DNS_FLAG_AD);
	pos_b = append_name(buf_b, pos_b, "example.com");
	write_u16(buf_b + pos_b, DNS_TYPE_A);
	write_u16(buf_b + pos_b + 2, DNS_CLASS_IN);
	pos_b += 4;
	pos_b = append_opt_record(buf_b, pos_b, 1232, 0, cookie_b,
	                          sizeof(cookie_b));

	assert(dns_parse_message(&msg_a, buf_a, pos_a) == 0);
	assert(dns_parse_message(&msg_b, buf_b, pos_b) == 0);
	assert(msg_a.cacheable);
	assert(msg_b.cacheable);
	assert(msg_a.cache_key.has_opt);
	assert(msg_b.cache_key.has_opt);
	assert(msg_a.cache_key.opt_rdlen == 0);
	assert(msg_b.cache_key.opt_rdlen == 0);
	assert(msg_a.cache_key.opt_rdata_hash == 0);
	assert(msg_b.cache_key.opt_rdata_hash == 0);
	assert(msg_a.cache_key.opt_udp_size == msg_b.cache_key.opt_udp_size);
	assert(msg_a.cache_key.opt_ttl == msg_b.cache_key.opt_ttl);
}

static void
test_opt_non_cookie_data_affects_cache_key(void)
{
	uint8_t            buf_a[DNS_MAX_MSG_SIZE];
	uint8_t            buf_b[DNS_MAX_MSG_SIZE];
	struct dns_message msg_a;
	struct dns_message msg_b;
	uint8_t            opt_a[] = {
		0x00, DNS_EDNS_OPTION_NSID,
		0x00, 0x03,
		'a', 'b', 'c',
	};
	uint8_t            opt_b[] = {
		0x00, DNS_EDNS_OPTION_NSID,
		0x00, 0x03,
		'a', 'b', 'd',
	};
	size_t             pos_a;
	size_t             pos_b;

	pos_a = make_header(buf_a, 1, 0, 0, 1);
	write_u16(buf_a, 0x1000);
	write_u16(buf_a + 2, DNS_FLAG_RD);
	pos_a = append_name(buf_a, pos_a, "example.com");
	write_u16(buf_a + pos_a, DNS_TYPE_A);
	write_u16(buf_a + pos_a + 2, DNS_CLASS_IN);
	pos_a += 4;
	pos_a = append_opt_record(buf_a, pos_a, 1232, 0, opt_a, sizeof(opt_a));

	pos_b = make_header(buf_b, 1, 0, 0, 1);
	write_u16(buf_b, 0x1001);
	write_u16(buf_b + 2, DNS_FLAG_RD);
	pos_b = append_name(buf_b, pos_b, "example.com");
	write_u16(buf_b + pos_b, DNS_TYPE_A);
	write_u16(buf_b + pos_b + 2, DNS_CLASS_IN);
	pos_b += 4;
	pos_b = append_opt_record(buf_b, pos_b, 1232, 0, opt_b, sizeof(opt_b));

	assert(dns_parse_message(&msg_a, buf_a, pos_a) == 0);
	assert(dns_parse_message(&msg_b, buf_b, pos_b) == 0);
	assert(msg_a.cacheable);
	assert(msg_b.cacheable);
	assert(msg_a.cache_key.opt_rdlen == sizeof(opt_a));
	assert(msg_b.cache_key.opt_rdlen == sizeof(opt_b));
	assert(msg_a.cache_key.opt_rdata_hash != 0);
	assert(msg_b.cache_key.opt_rdata_hash != 0);
	assert(msg_a.cache_key.opt_rdata_hash != msg_b.cache_key.opt_rdata_hash);
}

/* --- response matching --- */

static void
test_response_match_uses_question_section_only(void)
{
	uint8_t            query_buf[DNS_MAX_MSG_SIZE];
	uint8_t            response_buf[DNS_MAX_MSG_SIZE];
	struct dns_message query;
	size_t             pos;

	pos = make_header(query_buf, 1, 0, 0, 0);
	write_u16(query_buf, 0x1234);
	write_u16(query_buf + 2, DNS_FLAG_RD);
	pos = append_name(query_buf, pos, "example.com");
	write_u16(query_buf + pos, DNS_TYPE_A);
	write_u16(query_buf + pos + 2, DNS_CLASS_IN);
	pos += 4;
	assert(dns_parse_message(&query, query_buf, pos) == 0);

	pos = make_header(response_buf, 1, 1, 0, 0);
	write_u16(response_buf, 0x1234);
	write_u16(response_buf + 2,
	          DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA);
	pos = append_name(response_buf, pos, "example.com");
	write_u16(response_buf + pos, DNS_TYPE_A);
	write_u16(response_buf + pos + 2, DNS_CLASS_IN);
	pos                  += 4;

	response_buf[pos++]   = 0xC0;
	response_buf[pos++]   = DNS_HEADER_SIZE;
	write_u16(response_buf + pos, DNS_TYPE_A);
	write_u16(response_buf + pos + 2, DNS_CLASS_IN);
	write_u32(response_buf + pos + 4, 300);
	write_u16(response_buf + pos + 8, 4);
	pos                  += 10;
	response_buf[pos++]   = 192;
	response_buf[pos++]   = 0;
	response_buf[pos++]   = 2;
	response_buf[pos++]   = 1;

	assert(dns_response_matches_query(&query, response_buf, pos));

	write_u16(response_buf, 0x9999);
	assert(!dns_response_matches_query(&query, response_buf, pos));
}

static void
test_response_matches_case_insensitive_qname(void)
{
	/* Response echoes QNAME in different case → must still match */
	uint8_t            query_buf[DNS_MAX_MSG_SIZE];
	uint8_t            resp_buf[DNS_MAX_MSG_SIZE];
	struct dns_message query;
	size_t             pos;

	pos = make_header(query_buf, 1, 0, 0, 0);
	write_u16(query_buf, 0x5678);
	write_u16(query_buf + 2, DNS_FLAG_RD);
	pos = append_name(query_buf, pos, "example.com");
	write_u16(query_buf + pos, DNS_TYPE_A);
	write_u16(query_buf + pos + 2, DNS_CLASS_IN);
	pos += 4;
	assert(dns_parse_message(&query, query_buf, pos) == 0);

	pos = make_header(resp_buf, 1, 0, 0, 0);
	write_u16(resp_buf, 0x5678);
	write_u16(resp_buf + 2, DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA);
	pos = append_name(resp_buf, pos, "ExAmPlE.CoM");
	write_u16(resp_buf + pos, DNS_TYPE_A);
	write_u16(resp_buf + pos + 2, DNS_CLASS_IN);
	pos += 4;

	assert(dns_response_matches_query(&query, resp_buf, pos));
}

static void
test_response_matches_wrong_qtype(void)
{
	uint8_t            query_buf[DNS_MAX_MSG_SIZE];
	uint8_t            resp_buf[DNS_MAX_MSG_SIZE];
	struct dns_message query;
	size_t             pos;

	pos = make_header(query_buf, 1, 0, 0, 0);
	write_u16(query_buf, 0x1234);
	write_u16(query_buf + 2, DNS_FLAG_RD);
	pos = append_name(query_buf, pos, "example.com");
	write_u16(query_buf + pos, DNS_TYPE_A);
	write_u16(query_buf + pos + 2, DNS_CLASS_IN);
	pos += 4;
	assert(dns_parse_message(&query, query_buf, pos) == 0);

	pos = make_header(resp_buf, 1, 0, 0, 0);
	write_u16(resp_buf, 0x1234);
	write_u16(resp_buf + 2, DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA);
	pos = append_name(resp_buf, pos, "example.com");
	write_u16(resp_buf + pos, DNS_TYPE_AAAA); /* wrong type */
	write_u16(resp_buf + pos + 2, DNS_CLASS_IN);
	pos += 4;

	assert(!dns_response_matches_query(&query, resp_buf, pos));
}

static void
test_response_matches_not_a_response(void)
{
	/* QR=0 in the "response" → must not match */
	uint8_t            query_buf[DNS_MAX_MSG_SIZE];
	uint8_t            resp_buf[DNS_MAX_MSG_SIZE];
	struct dns_message query;
	size_t             pos;

	pos = make_header(query_buf, 1, 0, 0, 0);
	write_u16(query_buf, 0xAAAA);
	write_u16(query_buf + 2, DNS_FLAG_RD);
	pos = append_name(query_buf, pos, "example.com");
	write_u16(query_buf + pos, DNS_TYPE_A);
	write_u16(query_buf + pos + 2, DNS_CLASS_IN);
	pos += 4;
	assert(dns_parse_message(&query, query_buf, pos) == 0);

	/* Clone query as "response" but leave QR=0 */
	memcpy(resp_buf, query_buf, pos);

	assert(!dns_response_matches_query(&query, resp_buf, pos));
}

/* --- string fallbacks --- */

static void
test_string_fallbacks(void)
{
	char type_buf[32];
	char rcode_buf[32];

	assert(strcmp(dns_type_str(DNS_TYPE_SOA, type_buf, sizeof(type_buf)),
	              "SOA")
	       == 0);
	assert(strcmp(dns_type_str(65000, type_buf, sizeof(type_buf)),
	              "TYPE65000")
	       == 0);
	assert(strcmp(dns_rcode_str(23, rcode_buf, sizeof(rcode_buf)),
	              "RCODE23")
	       == 0);
}

int
main(void)
{
	test_parse_name_max_length();
	test_parse_root_name();
	test_parse_name_pointer_failures();
	test_parse_name_valid_pointer();
	test_wire_skip_name_rejects_truncated_label_data();

	test_parse_message_zero_qdcount();
	test_multi_question_query();
	test_parse_message_normalizes_name_to_lowercase();
	test_truncated_messages();
	test_trailing_garbage_rejected();

	test_non_query_opcode_not_cacheable();
	test_query_with_answer_section_not_cacheable();
	test_multiple_opt_records_not_cacheable();
	test_opt_in_wrong_section();

	test_edns_version_zero_sets_has_edns();
	test_edns_version_nonzero_extracted();
	test_edns_version_extracted_even_when_not_cacheable();
	test_no_opt_has_edns_false();

	test_opt_cookie_ignored_in_cache_key();
	test_opt_non_cookie_data_affects_cache_key();

	test_response_match_uses_question_section_only();
	test_response_matches_case_insensitive_qname();
	test_response_matches_wrong_qtype();
	test_response_matches_not_a_response();

	test_string_fallbacks();

	puts("dns tests passed");
	return 0;
}
