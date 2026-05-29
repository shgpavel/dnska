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
append_compressed_rr(uint8_t *buf, size_t pos, uint16_t owner_ptr,
                     uint16_t type, const uint8_t *rdata, uint16_t rdlen)
{
	buf[pos++] = (uint8_t)(0xC0 | (owner_ptr >> 8));
	buf[pos++] = (uint8_t)owner_ptr;
	write_u16(buf + pos, type);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	write_u32(buf + pos + 4, 600);
	write_u16(buf + pos + 8, rdlen);
	pos += 10;
	memcpy(buf + pos, rdata, rdlen);
	return pos + rdlen;
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
test_canonical_name_and_rr_helpers(void)
{
	uint8_t name[DNS_MAX_NAME_LEN + 1];
	uint8_t expected[] = {
		7,
		'e',
		'x',
		'a',
		'm',
		'p',
		'l',
		'e',
		3,
		'c',
		'o',
		'm',
		0,
	};
	uint8_t                    buf[128];
	uint8_t                    rdata[4] = { 192, 0, 2, 55 };
	size_t                     name_len = 0;
	size_t                     consumed = 0;
	size_t                     rr_len   = 0;
	size_t                     pos      = 0;
	struct dnssec_canonical_rr rr_a;
	struct dnssec_canonical_rr rr_b;

	assert(dnssec_canonical_name_from_text("Example.COM.", name,
	                                       sizeof(name), &name_len)
	       == DNSSEC_OK);
	assert(name_len == sizeof(expected));
	assert(memcmp(name, expected, sizeof(expected)) == 0);

	assert(dnssec_canonical_name_from_text(".", name, sizeof(name),
	                                       &name_len)
	       == DNSSEC_OK);
	assert(name_len == 1);
	assert(name[0] == 0);

	pos = append_name(buf, 0, "Example.COM");
	pos = append_compressed_rr(buf, pos, 0, DNS_TYPE_A, rdata,
	                           sizeof(rdata));

	assert(dnssec_canonical_name_from_wire(buf, pos, 13, name,
	                                       sizeof(name), &name_len,
	                                       &consumed)
	       == DNSSEC_OK);
	assert(consumed == 2);
	assert(name_len == sizeof(expected));
	assert(memcmp(name, expected, sizeof(expected)) == 0);

	assert(dnssec_parse_canonical_rr(buf, pos, 13, &rr_a, &rr_len)
	       == DNSSEC_OK);
	assert(rr_len == 16);
	assert(rr_a.type == DNS_TYPE_A);
	assert(rr_a.rrclass == DNS_CLASS_IN);
	assert(rr_a.ttl == 600);
	assert(rr_a.rdata_len == sizeof(rdata));
	assert(memcmp(rr_a.rdata, rdata, sizeof(rdata)) == 0);

	pos = append_name(buf, 0, "example.com");
	pos = append_rr(buf, pos, "EXAMPLE.COM", DNS_TYPE_A, rdata,
	                sizeof(rdata));
	assert(dnssec_parse_canonical_rr(buf, pos, 13, &rr_b, NULL)
	       == DNSSEC_OK);
	assert(dnssec_canonical_rr_same_rrset(&rr_a, &rr_b));

	rr_b.type = DNS_TYPE_AAAA;
	assert(!dnssec_canonical_rr_same_rrset(&rr_a, &rr_b));
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
	ds_rdata[3]  = DNSSEC_DS_DIGEST_SHA1;
	assert(dnssec_parse_ds(ds_rdata, 4 + digest_len, &ds) == DNSSEC_OK);
	assert(dnssec_ds_matches_dnskey("example.com", &ds, &dnskey,
	                                dnskey_rdata,
	                                sizeof(dnskey_rdata),
	                                &matches)
	       == DNSSEC_ERR_UNSUPPORTED);
}

static void
test_ds_matches_dnskey_sha384(void)
{
	uint8_t dnskey_rdata[36] = { 0x01, 0x01, 0x03,
		                     DNSSEC_ALGORITHM_ECDSAP256SHA256 };
	uint8_t digest[DNSSEC_MAX_DS_DIGEST_LEN];
	uint8_t ds_rdata[4 + DNSSEC_MAX_DS_DIGEST_LEN];
	size_t  digest_len = 0;
	bool    matches    = false;

	for (size_t i = 4; i < sizeof(dnskey_rdata); i++)
		dnskey_rdata[i] = (uint8_t)(0xF0 - i);

	assert(dnssec_dnskey_ds_digest("Example.COM.", dnskey_rdata,
	                               sizeof(dnskey_rdata),
	                               DNSSEC_DS_DIGEST_SHA384,
	                               digest, sizeof(digest),
	                               &digest_len)
	       == DNSSEC_OK);
	assert(digest_len == 48);

	write_u16(ds_rdata, dnssec_dnskey_key_tag(dnskey_rdata,
	                                          sizeof(dnskey_rdata)));
	ds_rdata[2] = DNSSEC_ALGORITHM_ECDSAP256SHA256;
	ds_rdata[3] = DNSSEC_DS_DIGEST_SHA384;
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
test_type_bitmap_multi_window(void)
{
	static const uint8_t bitmap[] = {
		0,
		1,
		0x40, /* TYPE1 / A */
		1,
		1,
		0x40, /* TYPE257 / CAA */
		2,
		1,
		0x80, /* TYPE512 */
	};
	static const uint8_t duplicate_window[] = {
		0,
		1,
		0x40,
		0,
		1,
		0x80,
	};
	static const uint8_t zero_length_window[] = {
		0,
		0,
	};

	assert(dnssec_type_bitmap_is_well_formed(bitmap, sizeof(bitmap)));
	assert(dnssec_type_bitmap_has_type(bitmap, sizeof(bitmap), DNS_TYPE_A));
	assert(dnssec_type_bitmap_has_type(bitmap, sizeof(bitmap), DNS_TYPE_CAA));
	assert(dnssec_type_bitmap_has_type(bitmap, sizeof(bitmap), 512));
	assert(!dnssec_type_bitmap_has_type(bitmap, sizeof(bitmap), DNS_TYPE_AAAA));
	assert(!dnssec_type_bitmap_has_type(bitmap, sizeof(bitmap), 258));
	assert(!dnssec_type_bitmap_is_well_formed(duplicate_window,
	                                          sizeof(duplicate_window)));
	assert(!dnssec_type_bitmap_is_well_formed(zero_length_window,
	                                          sizeof(zero_length_window)));
}

static void
test_parse_tlsa_and_dane_precheck(void)
{
	uint8_t                      tlsa_rdata[3 + 64];
	struct dnssec_tlsa           tlsa;
	enum dnssec_validation_state dane_state;

	memset(tlsa_rdata, 0x5A, sizeof(tlsa_rdata));
	tlsa_rdata[0] = DNSSEC_TLSA_USAGE_DANE_EE;
	tlsa_rdata[1] = DNSSEC_TLSA_SELECTOR_SPKI;
	tlsa_rdata[2] = DNSSEC_TLSA_MATCHING_SHA256;

	assert(dnssec_parse_tlsa(tlsa_rdata, 3 + 32, &tlsa) == DNSSEC_OK);
	assert(tlsa.certificate_usage == DNSSEC_TLSA_USAGE_DANE_EE);
	assert(tlsa.selector == DNSSEC_TLSA_SELECTOR_SPKI);
	assert(tlsa.matching_type == DNSSEC_TLSA_MATCHING_SHA256);
	assert(tlsa.association_data_len == 32);
	assert(tlsa.association_data[0] == 0x5A);

	assert(dnssec_parse_tlsa(tlsa_rdata, 3 + 31, &tlsa)
	       == DNSSEC_ERR_MALFORMED);
	tlsa_rdata[2] = DNSSEC_TLSA_MATCHING_SHA512;
	assert(dnssec_parse_tlsa(tlsa_rdata, sizeof(tlsa_rdata), &tlsa)
	       == DNSSEC_OK);
	assert(tlsa.association_data_len == 64);
	tlsa_rdata[0] = 4;
	assert(dnssec_parse_tlsa(tlsa_rdata, sizeof(tlsa_rdata), &tlsa)
	       == DNSSEC_ERR_UNSUPPORTED);

	assert(dnssec_dane_tlsa_precheck(DNSSEC_VALIDATION_SECURE, true,
	                                 &dane_state)
	       == DNSSEC_OK);
	assert(dane_state == DNSSEC_VALIDATION_SECURE);
	assert(dnssec_dane_tlsa_precheck(DNSSEC_VALIDATION_INSECURE, true,
	                                 &dane_state)
	       == DNSSEC_OK);
	assert(dane_state == DNSSEC_VALIDATION_INSECURE);
	assert(dnssec_dane_tlsa_precheck(DNSSEC_VALIDATION_UNCHECKED, true,
	                                 &dane_state)
	       == DNSSEC_OK);
	assert(dane_state == DNSSEC_VALIDATION_INSECURE);
	assert(dnssec_dane_tlsa_precheck(DNSSEC_VALIDATION_INDETERMINATE, true,
	                                 &dane_state)
	       == DNSSEC_OK);
	assert(dane_state == DNSSEC_VALIDATION_INDETERMINATE);
	assert(dnssec_dane_tlsa_precheck(DNSSEC_VALIDATION_BOGUS, true,
	                                 &dane_state)
	       == DNSSEC_OK);
	assert(dane_state == DNSSEC_VALIDATION_BOGUS);
	assert(dnssec_dane_tlsa_precheck(DNSSEC_VALIDATION_SECURE, false,
	                                 &dane_state)
	       == DNSSEC_OK);
	assert(dane_state == DNSSEC_VALIDATION_INDETERMINATE);
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
	test_canonical_name_and_rr_helpers();
	test_parse_ds_and_dnskey();
	test_ds_matches_dnskey_sha256();
	test_ds_matches_dnskey_sha384();
	test_parse_rrsig_nsec_nsec3();
	test_type_bitmap_multi_window();
	test_parse_tlsa_and_dane_precheck();
	test_analyze_message_states();

	puts("dnssec_test: ok");
	return 0;
}
