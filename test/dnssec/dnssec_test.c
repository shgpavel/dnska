/* SPDX-License-Identifier: MIT */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dns.h"
#include "dnssec.h"
#include "test.h"

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
append_rr(uint8_t *buf, size_t pos, const char *owner, uint16_t type,
          const uint8_t *rdata, uint16_t rdlen)
{
	pos = append_name(buf, pos, owner);
	write_u16(buf + pos, type);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	write_u32(buf + pos + 4, 300);
	write_u16(buf + pos + 8, rdlen);
	pos += 10;
	memcpy(buf + pos, rdata, rdlen);
	return pos + rdlen;
}

static size_t
append_question(uint8_t *buf, size_t pos, const char *name, uint16_t qtype)
{
	pos = append_name(buf, pos, name);
	write_u16(buf + pos, qtype);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	return pos + 4;
}

static size_t
make_response(uint8_t *buf, uint16_t ancount)
{
	memset(buf, 0, DNS_HEADER_SIZE);
	write_u16(buf + 2, DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA);
	write_u16(buf + 4, 1);
	write_u16(buf + 6, ancount);
	return DNS_HEADER_SIZE;
}

static size_t
make_rrsig_rdata(uint8_t *buf)
{
	size_t pos = 0;

	write_u16(buf + pos, DNS_TYPE_A);
	buf[pos + 2] = DNSSEC_ALGORITHM_ECDSAP256SHA256;
	buf[pos + 3] = 2;
	write_u32(buf + pos + 4, 3600);
	write_u32(buf + pos + 8, 1700001000);
	write_u32(buf + pos + 12, 1700000000);
	write_u16(buf + pos + 16, 0x051F);
	pos        += 18;

	pos         = append_name(buf, pos, "example.com");
	buf[pos++]  = 0xDE;
	buf[pos++]  = 0xAD;
	buf[pos++]  = 0xBE;
	buf[pos++]  = 0xEF;
	return pos;
}

static void
test_parse_ds_and_dnskey(void)
{
	uint8_t              ds_rdata[36];
	uint8_t              dnskey_rdata[36] = { 0x01, 0x01, 0x03,
		                                  DNSSEC_ALGORITHM_ECDSAP256SHA256 };
	struct dnssec_ds     ds;
	struct dnssec_dnskey dnskey;

	for (size_t i = 4; i < sizeof(dnskey_rdata); i++)
		dnskey_rdata[i] = (uint8_t)(i - 3);

	write_u16(ds_rdata, 0x051F);
	ds_rdata[2] = DNSSEC_ALGORITHM_ECDSAP256SHA256;
	ds_rdata[3] = DNSSEC_DS_DIGEST_SHA256;
	memset(ds_rdata + 4, 0xA5, 32);

	assert(dnssec_parse_ds(ds_rdata, sizeof(ds_rdata), &ds) == DNSSEC_OK);
	assert(ds.key_tag == 0x051F);
	assert(ds.algorithm == DNSSEC_ALGORITHM_ECDSAP256SHA256);
	assert(ds.digest_type == DNSSEC_DS_DIGEST_SHA256);
	assert(ds.digest_len == 32);
	assert(ds.digest[0] == 0xA5);

	assert(dnssec_parse_dnskey(dnskey_rdata, sizeof(dnskey_rdata),
	                           &dnskey)
	       == DNSSEC_OK);
	assert(dnskey.flags == 0x0101);
	assert(dnskey.protocol == 3);
	assert(dnskey.algorithm == DNSSEC_ALGORITHM_ECDSAP256SHA256);
	assert(dnskey.public_key_len == 32);
	assert(dnssec_dnskey_key_tag(dnskey_rdata, sizeof(dnskey_rdata))
	       == 0x051F);
}

static void
test_ds_matches_dnskey_sha256(void)
{
	uint8_t dnskey_rdata[36] = { 0x01, 0x01, 0x03,
		                     DNSSEC_ALGORITHM_ECDSAP256SHA256 };
	uint8_t digest[DNSSEC_MAX_DS_DIGEST_LEN];
	uint8_t ds_rdata[4 + DNSSEC_MAX_DS_DIGEST_LEN];
	size_t  digest_len = 0;
	bool    matches    = false;

	for (size_t i = 4; i < sizeof(dnskey_rdata); i++)
		dnskey_rdata[i] = (uint8_t)(i - 3);

	assert(dnssec_dnskey_ds_digest("Example.COM.", dnskey_rdata,
	                               sizeof(dnskey_rdata),
	                               DNSSEC_DS_DIGEST_SHA256,
	                               digest, sizeof(digest),
	                               &digest_len)
	       == DNSSEC_OK);
	assert(digest_len == 32);

	write_u16(ds_rdata, dnssec_dnskey_key_tag(dnskey_rdata,
	                                          sizeof(dnskey_rdata)));
	ds_rdata[2] = DNSSEC_ALGORITHM_ECDSAP256SHA256;
	ds_rdata[3] = DNSSEC_DS_DIGEST_SHA256;
	memcpy(ds_rdata + 4, digest, digest_len);

	struct dnssec_ds     ds;
	struct dnssec_dnskey dnskey;
	assert(dnssec_parse_ds(ds_rdata, 4 + digest_len, &ds) == DNSSEC_OK);
	assert(dnssec_parse_dnskey(dnskey_rdata, sizeof(dnskey_rdata),
	                           &dnskey)
	       == DNSSEC_OK);
	assert(dnssec_ds_matches_dnskey("example.com", &ds, &dnskey,
	                                dnskey_rdata,
	                                sizeof(dnskey_rdata),
	                                &matches)
	       == DNSSEC_OK);
	assert(matches);

	ds_rdata[9] ^= 0x80;
	assert(dnssec_parse_ds(ds_rdata, 4 + digest_len, &ds) == DNSSEC_OK);
	assert(dnssec_ds_matches_dnskey("example.com", &ds, &dnskey,
	                                dnskey_rdata,
	                                sizeof(dnskey_rdata),
	                                &matches)
	       == DNSSEC_OK);
	assert(!matches);

	ds_rdata[9] ^= 0x80;
	ds_rdata[3]  = DNSSEC_DS_DIGEST_SHA384;
	assert(dnssec_parse_ds(ds_rdata, 4 + digest_len, &ds) == DNSSEC_OK);
	assert(dnssec_ds_matches_dnskey("example.com", &ds, &dnskey,
	                                dnskey_rdata,
	                                sizeof(dnskey_rdata),
	                                &matches)
	       == DNSSEC_ERR_UNSUPPORTED);
}

static void
test_parse_rrsig_nsec_nsec3(void)
{
	uint8_t             rrsig_rdata[128];
	uint8_t             nsec_rdata[128];
	uint8_t             nsec3_rdata[32];
	struct dnssec_rrsig rrsig;
	struct dnssec_nsec  nsec;
	struct dnssec_nsec3 nsec3;
	size_t              rrsig_len = make_rrsig_rdata(rrsig_rdata);
	size_t              pos       = 0;

	assert(dnssec_parse_rrsig(rrsig_rdata, rrsig_len, &rrsig)
	       == DNSSEC_OK);
	assert(rrsig.type_covered == DNS_TYPE_A);
	assert(rrsig.algorithm == DNSSEC_ALGORITHM_ECDSAP256SHA256);
	assert(rrsig.original_ttl == 3600);
	TEST_EXPECT_STR_EQ(rrsig.signer_name, "example.com");
	assert(rrsig.signature_len == 4);
	assert(rrsig.signature[0] == 0xDE);

	pos                           = append_name(nsec_rdata, 0, "next.example.com");
	static const uint8_t bitmap[] = {
		0,
		7,
		0x40,
		0x00,
		0x00,
		0x00,
		0x00,
		0x02,
		0x80,
	};
	memcpy(nsec_rdata + pos, bitmap, sizeof(bitmap));
	pos += sizeof(bitmap);
	assert(dnssec_parse_nsec(nsec_rdata, pos, &nsec) == DNSSEC_OK);
	TEST_EXPECT_STR_EQ(nsec.next_domain_name, "next.example.com");
	assert(dnssec_type_bitmap_has_type(nsec.type_bit_maps,
	                                   nsec.type_bit_maps_len,
	                                   DNS_TYPE_A));
	assert(dnssec_type_bitmap_has_type(nsec.type_bit_maps,
	                                   nsec.type_bit_maps_len,
	                                   DNS_TYPE_RRSIG));
	assert(!dnssec_type_bitmap_has_type(nsec.type_bit_maps,
	                                    nsec.type_bit_maps_len,
	                                    DNS_TYPE_AAAA));

	pos                = 0;
	nsec3_rdata[pos++] = 1; /* SHA-1 */
	nsec3_rdata[pos++] = 0;
	write_u16(nsec3_rdata + pos, 10);
	pos                += 2;
	nsec3_rdata[pos++]  = 2;
	nsec3_rdata[pos++]  = 0xAB;
	nsec3_rdata[pos++]  = 0xCD;
	nsec3_rdata[pos++]  = 4;
	nsec3_rdata[pos++]  = 0x11;
	nsec3_rdata[pos++]  = 0x22;
	nsec3_rdata[pos++]  = 0x33;
	nsec3_rdata[pos++]  = 0x44;
	nsec3_rdata[pos++]  = 0;
	nsec3_rdata[pos++]  = 1;
	nsec3_rdata[pos++]  = 0x40;

	assert(dnssec_parse_nsec3(nsec3_rdata, pos, &nsec3) == DNSSEC_OK);
	assert(nsec3.hash_algorithm == 1);
	assert(nsec3.iterations == 10);
	assert(nsec3.salt_len == 2);
	assert(nsec3.next_hashed_owner_len == 4);
	assert(dnssec_type_bitmap_has_type(nsec3.type_bit_maps,
	                                   nsec3.type_bit_maps_len,
	                                   DNS_TYPE_A));
}

static void
test_analyze_message_states(void)
{
	uint8_t                         dns_msg[DNS_MAX_MSG_SIZE];
	uint8_t                         a_rdata[4] = { 192, 0, 2, 1 };
	uint8_t                         rrsig_rdata[128];
	uint8_t                         dnskey_rdata[4] = { 0x01, 0x01, 0x03,
		                                            DNSSEC_ALGORITHM_ECDSAP256SHA256 };
	struct dnssec_validation_result result;
	size_t                          pos;

	pos = make_response(dns_msg, 1);
	pos = append_question(dns_msg, pos, "example.com", DNS_TYPE_A);
	pos = append_rr(dns_msg, pos, "example.com", DNS_TYPE_A,
	                a_rdata, sizeof(a_rdata));
	assert(dnssec_analyze_message(dns_msg, pos, &result) == DNSSEC_OK);
	assert(result.state == DNSSEC_VALIDATION_UNCHECKED);
	assert(result.dnssec_records == 0);

	size_t rrsig_len = make_rrsig_rdata(rrsig_rdata);
	pos              = make_response(dns_msg, 1);
	pos              = append_question(dns_msg, pos, "example.com", DNS_TYPE_A);
	pos              = append_rr(dns_msg, pos, "example.com", DNS_TYPE_RRSIG,
	                             rrsig_rdata, (uint16_t)rrsig_len);
	assert(dnssec_analyze_message(dns_msg, pos, &result) == DNSSEC_OK);
	assert(result.state == DNSSEC_VALIDATION_INDETERMINATE);
	assert(result.dnssec_records == 1);
	assert(result.malformed_dnssec_records == 0);

	pos = make_response(dns_msg, 1);
	pos = append_question(dns_msg, pos, "example.com", DNS_TYPE_DNSKEY);
	pos = append_rr(dns_msg, pos, "example.com", DNS_TYPE_DNSKEY,
	                dnskey_rdata, sizeof(dnskey_rdata));
	assert(dnssec_analyze_message(dns_msg, pos, &result) == DNSSEC_OK);
	assert(result.state == DNSSEC_VALIDATION_BOGUS);
	assert(result.dnssec_records == 1);
	assert(result.malformed_dnssec_records == 1);
}

int
main(void)
{
	test_parse_ds_and_dnskey();
	test_ds_matches_dnskey_sha256();
	test_parse_rrsig_nsec_nsec3();
	test_analyze_message_states();

	puts("dnssec_test: ok");
	return 0;
}
