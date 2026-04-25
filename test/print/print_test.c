/* SPDX-License-Identifier: MIT */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dns.h"
#include "print.h"
#include "test.h"

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
make_response_header(uint8_t *buf, uint16_t id, uint16_t flags, uint16_t qd,
                     uint16_t an, uint16_t ns, uint16_t ar)
{
	memset(buf, 0, DNS_HEADER_SIZE);
	write_u16(buf, id);
	write_u16(buf + 2, flags);
	write_u16(buf + 4, qd);
	write_u16(buf + 6, an);
	write_u16(buf + 8, ns);
	write_u16(buf + 10, ar);
	return DNS_HEADER_SIZE;
}

static size_t
append_question(uint8_t *buf, size_t pos, const char *qname, uint16_t qtype)
{
	pos = append_name(buf, pos, qname);
	write_u16(buf + pos, qtype);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	return pos + 4;
}

static size_t
append_rr_header(uint8_t *buf, size_t pos, const char *name, uint16_t type,
                 uint32_t ttl, uint16_t rdlen)
{
	pos = append_name(buf, pos, name);
	write_u16(buf + pos, type);
	write_u16(buf + pos + 2, DNS_CLASS_IN);
	write_u32(buf + pos + 4, ttl);
	write_u16(buf + pos + 8, rdlen);
	return pos + 10;
}

static int
contains(const char *haystack, const char *needle)
{
	return strstr(haystack, needle) != NULL;
}

static size_t
print_to_buffer(const uint8_t *msg, size_t len, char *out, size_t out_size)
{
	FILE *f = fmemopen(out, out_size, "w");
	TEST_CHECK(f != NULL);
	int rc = dns_print_response(f, msg, len);
	TEST_EXPECT_INT_EQ(rc, 0);
	fflush(f);
	long pos = ftell(f);
	fclose(f);
	TEST_CHECK(pos > 0 && (size_t)pos < out_size);
	out[pos] = '\0';
	return (size_t)pos;
}

/* --- dns_type_from_str --- */

static void
test_type_from_str_known(void)
{
	uint16_t v = 0;

	TEST_EXPECT_INT_EQ(dns_type_from_str("A", &v), 0);
	TEST_EXPECT_INT_EQ(v, DNS_TYPE_A);
	TEST_EXPECT_INT_EQ(dns_type_from_str("aaaa", &v), 0);
	TEST_EXPECT_INT_EQ(v, DNS_TYPE_AAAA);
	TEST_EXPECT_INT_EQ(dns_type_from_str("MX", &v), 0);
	TEST_EXPECT_INT_EQ(v, DNS_TYPE_MX);
	TEST_EXPECT_INT_EQ(dns_type_from_str("DNSKEY", &v), 0);
	TEST_EXPECT_INT_EQ(v, DNS_TYPE_DNSKEY);
}

static void
test_type_from_str_typennn(void)
{
	uint16_t v = 0;

	TEST_EXPECT_INT_EQ(dns_type_from_str("TYPE99", &v), 0);
	TEST_EXPECT_INT_EQ(v, 99);
	TEST_EXPECT_INT_EQ(dns_type_from_str("type65000", &v), 0);
	TEST_EXPECT_INT_EQ(v, 65000);
}

static void
test_type_from_str_invalid(void)
{
	uint16_t v = 0;

	TEST_CHECK(dns_type_from_str("FOOBAR", &v) < 0);
	TEST_CHECK(dns_type_from_str("", &v) < 0);
	TEST_CHECK(dns_type_from_str(NULL, &v) < 0);
	TEST_CHECK(dns_type_from_str("TYPE99x", &v) < 0);
	TEST_CHECK(dns_type_from_str("TYPE99999", &v) < 0); /* > 0xFFFF */
}

/* --- dns_print_response --- */

static void
test_print_a_record(void)
{
	uint8_t buf[DNS_MAX_MSG_SIZE];
	char    out[4096];
	size_t  pos = make_response_header(buf, 0x1234,
	                                   DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA,
	                                   1, 1, 0, 0);

	pos         = append_question(buf, pos, "example.com", DNS_TYPE_A);
	pos         = append_rr_header(buf, pos, "example.com", DNS_TYPE_A, 300, 4);
	buf[pos++]  = 93;
	buf[pos++]  = 184;
	buf[pos++]  = 216;
	buf[pos++]  = 34;

	print_to_buffer(buf, pos, out, sizeof(out));

	TEST_CHECK(contains(out, "->>HEADER<<-"));
	TEST_CHECK(contains(out, "status: NOERROR"));
	TEST_CHECK(contains(out, "id: 4660")); /* 0x1234 */
	TEST_CHECK(contains(out, "qr"));
	TEST_CHECK(contains(out, "rd"));
	TEST_CHECK(contains(out, "ra"));
	TEST_CHECK(contains(out, "QUESTION SECTION"));
	TEST_CHECK(contains(out, ";example.com."));
	TEST_CHECK(contains(out, "ANSWER SECTION"));
	TEST_CHECK(contains(out, "example.com."));
	TEST_CHECK(contains(out, "300"));
	TEST_CHECK(contains(out, "93.184.216.34"));
}

static void
test_print_aaaa_record(void)
{
	uint8_t buf[DNS_MAX_MSG_SIZE];
	char    out[4096];
	size_t  pos      = make_response_header(buf, 1,
	                                        DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA,
	                                        1, 1, 0, 0);

	pos              = append_question(buf, pos, "v6.example", DNS_TYPE_AAAA);
	pos              = append_rr_header(buf, pos, "v6.example", DNS_TYPE_AAAA, 60, 16);
	uint8_t addr[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
	memcpy(buf + pos, addr, 16);
	pos += 16;

	print_to_buffer(buf, pos, out, sizeof(out));
	TEST_CHECK(contains(out, "AAAA"));
	TEST_CHECK(contains(out, "2001:db8::1"));
}

static void
test_print_mx_record(void)
{
	uint8_t buf[DNS_MAX_MSG_SIZE];
	char    out[4096];
	size_t  pos = make_response_header(buf, 2,
	                                   DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA,
	                                   1, 1, 0, 0);

	pos         = append_question(buf, pos, "example.com", DNS_TYPE_MX);
	/* Build rdata first to know length. */
	uint8_t rdata[64];
	size_t  rdlen  = 0;
	rdata[rdlen++] = 0;
	rdata[rdlen++] = 10; /* preference 10 */
	rdlen          = append_name(rdata, rdlen, "mail.example.com");

	pos            = append_rr_header(buf, pos, "example.com", DNS_TYPE_MX, 300,
	                                  (uint16_t)rdlen);
	memcpy(buf + pos, rdata, rdlen);
	pos += rdlen;

	print_to_buffer(buf, pos, out, sizeof(out));
	TEST_CHECK(contains(out, "MX"));
	TEST_CHECK(contains(out, "10 mail.example.com"));
}

static void
test_print_txt_record(void)
{
	uint8_t buf[DNS_MAX_MSG_SIZE];
	char    out[4096];
	size_t  pos       = make_response_header(buf, 3,
	                                         DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA,
	                                         1, 1, 0, 0);

	pos               = append_question(buf, pos, "txt.example", DNS_TYPE_TXT);
	const char *str   = "v=spf1 -all";
	uint8_t     slen  = (uint8_t)strlen(str);
	uint16_t    rdlen = (uint16_t)(1 + slen);
	pos               = append_rr_header(buf, pos, "txt.example", DNS_TYPE_TXT, 60, rdlen);
	buf[pos++]        = slen;
	memcpy(buf + pos, str, slen);
	pos += slen;

	print_to_buffer(buf, pos, out, sizeof(out));
	TEST_CHECK(contains(out, "TXT"));
	TEST_CHECK(contains(out, "\"v=spf1 -all\""));
}

static void
test_print_soa_record(void)
{
	uint8_t buf[DNS_MAX_MSG_SIZE];
	char    out[4096];
	size_t  pos = make_response_header(buf, 4,
	                                   DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA,
	                                   1, 0, 1, 0);

	pos         = append_question(buf, pos, "example.com", DNS_TYPE_SOA);

	uint8_t rdata[256];
	size_t  rdlen = 0;
	rdlen         = append_name(rdata, rdlen, "ns.example.com");
	rdlen         = append_name(rdata, rdlen, "hostmaster.example.com");
	write_u32(rdata + rdlen, 2026010101);
	write_u32(rdata + rdlen + 4, 7200);
	write_u32(rdata + rdlen + 8, 3600);
	write_u32(rdata + rdlen + 12, 1209600);
	write_u32(rdata + rdlen + 16, 3600);
	rdlen += 20;

	pos    = append_rr_header(buf, pos, "example.com", DNS_TYPE_SOA, 600,
	                          (uint16_t)rdlen);
	memcpy(buf + pos, rdata, rdlen);
	pos += rdlen;

	print_to_buffer(buf, pos, out, sizeof(out));
	TEST_CHECK(contains(out, "AUTHORITY SECTION"));
	TEST_CHECK(contains(out, "SOA"));
	TEST_CHECK(contains(out, "ns.example.com"));
	TEST_CHECK(contains(out, "hostmaster.example.com"));
	TEST_CHECK(contains(out, "2026010101"));
	TEST_CHECK(contains(out, "7200"));
}

static void
test_print_nxdomain_status(void)
{
	uint8_t buf[DNS_MAX_MSG_SIZE];
	char    out[4096];
	size_t  pos = make_response_header(buf, 5,
	                                   DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA | DNS_RCODE_NXDOMAIN,
	                                   1, 0, 0, 0);

	pos         = append_question(buf, pos, "no.such.host", DNS_TYPE_A);

	print_to_buffer(buf, pos, out, sizeof(out));
	TEST_CHECK(contains(out, "status: NXDOMAIN"));
	TEST_CHECK(contains(out, ";no.such.host."));
}

static void
test_print_unknown_type_hex(void)
{
	uint8_t buf[DNS_MAX_MSG_SIZE];
	char    out[4096];
	size_t  pos     = make_response_header(buf, 6,
	                                       DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA,
	                                       1, 1, 0, 0);

	pos             = append_question(buf, pos, "x.example", 99);

	uint8_t rdata[] = { 0xDE, 0xAD, 0xBE, 0xEF };
	pos             = append_rr_header(buf, pos, "x.example", 99, 60, sizeof(rdata));
	memcpy(buf + pos, rdata, sizeof(rdata));
	pos += sizeof(rdata);

	print_to_buffer(buf, pos, out, sizeof(out));
	TEST_CHECK(contains(out, "TYPE99"));
	TEST_CHECK(contains(out, "deadbeef"));
}

static void
test_print_rejects_short_buffer(void)
{
	uint8_t buf[DNS_HEADER_SIZE - 1] = { 0 };

	FILE   *f                        = fmemopen((char[1024]){ 0 }, 1024, "w");
	TEST_CHECK(f != NULL);
	TEST_CHECK(dns_print_response(f, buf, sizeof(buf)) < 0);
	fclose(f);
}

int
main(void)
{
	test_type_from_str_known();
	test_type_from_str_typennn();
	test_type_from_str_invalid();

	test_print_a_record();
	test_print_aaaa_record();
	test_print_mx_record();
	test_print_txt_record();
	test_print_soa_record();
	test_print_nxdomain_status();
	test_print_unknown_type_hex();
	test_print_rejects_short_buffer();

	puts("print tests passed");
	return 0;
}
