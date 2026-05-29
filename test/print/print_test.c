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
append_rr_header_class(uint8_t *buf, size_t pos, const char *name,
                       uint16_t type, uint16_t rrclass, uint32_t ttl,
                       uint16_t rdlen)
{
	pos = append_name(buf, pos, name);
	write_u16(buf + pos, type);
	write_u16(buf + pos + 2, rrclass);
	write_u32(buf + pos + 4, ttl);
	write_u16(buf + pos + 8, rdlen);
	return pos + 10;
}

static size_t
append_rr_header(uint8_t *buf, size_t pos, const char *name, uint16_t type,
                 uint32_t ttl, uint16_t rdlen)
{
	return append_rr_header_class(buf, pos, name, type, DNS_CLASS_IN, ttl,
	                              rdlen);
}

static size_t
append_svcparam(uint8_t *buf, size_t pos, uint16_t key,
                const uint8_t *value, uint16_t len)
{
	write_u16(buf + pos, key);
	write_u16(buf + pos + 2, len);
	pos += 4;
	memcpy(buf + pos, value, len);
	return pos + len;
}

static size_t
append_edns_option(uint8_t *buf, size_t pos, uint16_t code,
                   const uint8_t *value, uint16_t len)
{
	write_u16(buf + pos, code);
	write_u16(buf + pos + 2, len);
	pos += 4;
	memcpy(buf + pos, value, len);
	return pos + len;
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
	TEST_EXPECT_INT_EQ(dns_type_from_str("SSHFP", &v), 0);
	TEST_EXPECT_INT_EQ(v, DNS_TYPE_SSHFP);
	TEST_EXPECT_INT_EQ(dns_type_from_str("NSEC3", &v), 0);
	TEST_EXPECT_INT_EQ(v, DNS_TYPE_NSEC3);
	TEST_EXPECT_INT_EQ(dns_type_from_str("NSEC3PARAM", &v), 0);
	TEST_EXPECT_INT_EQ(v, DNS_TYPE_NSEC3PARAM);
	TEST_EXPECT_INT_EQ(dns_type_from_str("TLSA", &v), 0);
	TEST_EXPECT_INT_EQ(v, DNS_TYPE_TLSA);
	TEST_EXPECT_INT_EQ(dns_type_from_str("CDS", &v), 0);
	TEST_EXPECT_INT_EQ(v, DNS_TYPE_CDS);
	TEST_EXPECT_INT_EQ(dns_type_from_str("CDNSKEY", &v), 0);
	TEST_EXPECT_INT_EQ(v, DNS_TYPE_CDNSKEY);
	TEST_EXPECT_INT_EQ(dns_type_from_str("ZONEMD", &v), 0);
	TEST_EXPECT_INT_EQ(v, DNS_TYPE_ZONEMD);
	TEST_EXPECT_INT_EQ(dns_type_from_str("SVCB", &v), 0);
	TEST_EXPECT_INT_EQ(v, DNS_TYPE_SVCB);
	TEST_EXPECT_INT_EQ(dns_type_from_str("https", &v), 0);
	TEST_EXPECT_INT_EQ(v, DNS_TYPE_HTTPS);
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
test_print_https_record_with_svcparams(void)
{
	uint8_t buf[DNS_MAX_MSG_SIZE];
	char    out[4096];
	size_t  pos = make_response_header(buf, 7,
	                                   DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA,
	                                   1, 1, 0, 0);

	pos         = append_question(buf, pos, "example.com", DNS_TYPE_HTTPS);

	uint8_t rdata[512];
	size_t  rdlen = 0;
	write_u16(rdata + rdlen, 1);
	rdlen += 2;
	rdlen  = append_name(rdata, rdlen, "svc.example.com");

	uint8_t mandatory[4];
	write_u16(mandatory, 1);     /* alpn */
	write_u16(mandatory + 2, 3); /* port */
	rdlen          = append_svcparam(rdata, rdlen, 0, mandatory,
	                                 (uint16_t)sizeof(mandatory));

	uint8_t alpn[] = { 2, 'h', '2', 2, 'h', '3' };
	rdlen          = append_svcparam(rdata, rdlen, 1, alpn,
	                                 (uint16_t)sizeof(alpn));

	uint8_t port[2];
	write_u16(port, 8443);
	rdlen                = append_svcparam(rdata, rdlen, 3, port,
	                                       (uint16_t)sizeof(port));

	uint8_t ipv4hint[]   = { 192, 0, 2, 1, 198, 51, 100, 2 };
	rdlen                = append_svcparam(rdata, rdlen, 4, ipv4hint,
	                                       (uint16_t)sizeof(ipv4hint));

	uint8_t ech[]        = { 0x00, 0x11, 0x22 };
	rdlen                = append_svcparam(rdata, rdlen, 5, ech,
	                                       (uint16_t)sizeof(ech));

	uint8_t ipv6hint[16] = {
		0x20,
		0x01,
		0x0d,
		0xb8,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		1,
	};
	rdlen               = append_svcparam(rdata, rdlen, 6, ipv6hint,
	                                      (uint16_t)sizeof(ipv6hint));

	const char *dohpath = "/dns-query{?dns}";
	rdlen               = append_svcparam(rdata, rdlen, 7, (const uint8_t *)dohpath,
	                                      (uint16_t)strlen(dohpath));

	uint8_t unknown[]   = { 0xaa, 0xbb };
	rdlen               = append_svcparam(rdata, rdlen, 65400, unknown,
	                                      (uint16_t)sizeof(unknown));

	pos                 = append_rr_header(buf, pos, "example.com", DNS_TYPE_HTTPS, 300,
	                                       (uint16_t)rdlen);
	memcpy(buf + pos, rdata, rdlen);
	pos += rdlen;

	print_to_buffer(buf, pos, out, sizeof(out));
	TEST_CHECK(contains(out, "HTTPS"));
	TEST_CHECK(contains(out, "1 svc.example.com"));
	TEST_CHECK(contains(out, "mandatory=alpn,port"));
	TEST_CHECK(contains(out, "alpn=h2,h3"));
	TEST_CHECK(contains(out, "port=8443"));
	TEST_CHECK(contains(out, "ipv4hint=192.0.2.1,198.51.100.2"));
	TEST_CHECK(contains(out, "ech=001122"));
	TEST_CHECK(contains(out, "ipv6hint=2001:db8::1"));
	TEST_CHECK(contains(out, "dohpath=\"/dns-query{?dns}\""));
	TEST_CHECK(contains(out, "key65400=aabb"));
}

static void
test_print_svcb_no_default_alpn_and_bad_params(void)
{
	uint8_t buf[DNS_MAX_MSG_SIZE];
	char    out[4096];
	size_t  pos = make_response_header(buf, 10,
	                                   DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA,
	                                   1, 1, 0, 0);

	pos         = append_question(buf, pos, "svc.example.com", DNS_TYPE_SVCB);

	uint8_t rdata[256];
	size_t  rdlen = 0;
	write_u16(rdata + rdlen, 1);
	rdlen                   += 2;
	rdlen                    = append_name(rdata, rdlen, "svc.example.com");

	uint8_t empty            = 0;
	rdlen                    = append_svcparam(rdata, rdlen, 2, &empty, 0);

	uint8_t bad_alpn[]       = { 3, 'h' };
	rdlen                    = append_svcparam(rdata, rdlen, 1, bad_alpn,
	                                           (uint16_t)sizeof(bad_alpn));

	uint8_t bad_port[]       = { 0x23 };
	rdlen                    = append_svcparam(rdata, rdlen, 3, bad_port,
	                                           (uint16_t)sizeof(bad_port));

	uint8_t bad_mandatory[]  = { 0x00 };
	rdlen                    = append_svcparam(rdata, rdlen, 0, bad_mandatory,
	                                           (uint16_t)sizeof(bad_mandatory));

	pos                      = append_rr_header(buf, pos, "svc.example.com", DNS_TYPE_SVCB,
	                                            300, (uint16_t)rdlen);
	memcpy(buf + pos, rdata, rdlen);
	pos += rdlen;

	print_to_buffer(buf, pos, out, sizeof(out));
	TEST_CHECK(contains(out, "SVCB"));
	TEST_CHECK(contains(out, "1 svc.example.com"));
	TEST_CHECK(contains(out, "no-default-alpn"));
	TEST_CHECK(contains(out, "alpn=<bad>"));
	TEST_CHECK(contains(out, "port=<bad len 1>"));
	TEST_CHECK(contains(out, "mandatory=<bad>"));
}

static void
test_print_https_truncated_svcparam_header(void)
{
	uint8_t buf[DNS_MAX_MSG_SIZE];
	char    out[4096];
	size_t  pos = make_response_header(buf, 11,
	                                   DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA,
	                                   1, 1, 0, 0);

	pos         = append_question(buf, pos, "bad.example.com", DNS_TYPE_HTTPS);

	uint8_t rdata[256];
	size_t  rdlen = 0;
	write_u16(rdata + rdlen, 1);
	rdlen += 2;
	rdlen  = append_name(rdata, rdlen, "svc.example.com");
	write_u16(rdata + rdlen, 3);
	rdlen += 2;

	pos    = append_rr_header(buf, pos, "bad.example.com", DNS_TYPE_HTTPS,
	                          300, (uint16_t)rdlen);
	memcpy(buf + pos, rdata, rdlen);
	pos += rdlen;

	print_to_buffer(buf, pos, out, sizeof(out));
	TEST_CHECK(contains(out, "HTTPS"));
	TEST_CHECK(contains(out, "<bad HTTPS param>"));
}

static void
test_print_tlsa_and_zonemd_records(void)
{
	uint8_t buf[DNS_MAX_MSG_SIZE];
	char    out[4096];
	size_t  pos    = make_response_header(buf, 8,
	                                      DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA,
	                                      1, 2, 0, 0);

	pos            = append_question(buf, pos, "_443._tcp.example.com",
	                                 DNS_TYPE_TLSA);

	uint8_t tlsa[] = { 3, 1, 1, 0xde, 0xad, 0xbe, 0xef };
	pos            = append_rr_header(buf, pos, "_443._tcp.example.com", DNS_TYPE_TLSA,
	                                  300, (uint16_t)sizeof(tlsa));
	memcpy(buf + pos, tlsa, sizeof(tlsa));
	pos += sizeof(tlsa);

	uint8_t zonemd[10];
	write_u32(zonemd, 2026010101);
	zonemd[4] = 1; /* simple */
	zonemd[5] = 1; /* sha384 */
	zonemd[6] = 1;
	zonemd[7] = 2;
	zonemd[8] = 3;
	zonemd[9] = 4;
	pos       = append_rr_header(buf, pos, "example.com", DNS_TYPE_ZONEMD, 3600,
	                             (uint16_t)sizeof(zonemd));
	memcpy(buf + pos, zonemd, sizeof(zonemd));
	pos += sizeof(zonemd);

	print_to_buffer(buf, pos, out, sizeof(out));
	TEST_CHECK(contains(out, "TLSA"));
	TEST_CHECK(contains(out, "usage=3 selector=1 matching=1 data=deadbeef"));
	TEST_CHECK(contains(out, "ZONEMD"));
	TEST_CHECK(contains(out, "serial=2026010101"));
	TEST_CHECK(contains(out, "scheme=1(simple)"));
	TEST_CHECK(contains(out, "hash=1(sha384)"));
	TEST_CHECK(contains(out, "digest=01020304"));
}

static void
test_print_opt_edns_options(void)
{
	uint8_t buf[DNS_MAX_MSG_SIZE];
	char    out[4096];
	size_t  pos = make_response_header(buf, 9,
	                                   DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA,
	                                   1, 0, 0, 1);

	pos         = append_question(buf, pos, "example.com", DNS_TYPE_A);

	uint8_t opt_rdata[128];
	size_t  opt_len    = 0;

	uint8_t ecs[]      = { 0x00, 0x01, 24, 0, 203, 0, 113 };
	opt_len            = append_edns_option(opt_rdata, opt_len, DNS_EDNS_OPTION_ECS,
	                                        ecs, (uint16_t)sizeof(ecs));

	uint8_t padding[4] = { 0 };
	opt_len            = append_edns_option(opt_rdata, opt_len,
	                                        DNS_EDNS_OPTION_PADDING, padding,
	                                        (uint16_t)sizeof(padding));

	uint8_t ede[8];
	write_u16(ede, 15);
	memcpy(ede + 2, "policy", 6);
	opt_len = append_edns_option(opt_rdata, opt_len, DNS_EDNS_OPTION_EDE,
	                             ede, (uint16_t)sizeof(ede));

	pos     = append_rr_header_class(buf, pos, "", DNS_TYPE_OPT, 1232,
	                                 0x00008000U, (uint16_t)opt_len);
	memcpy(buf + pos, opt_rdata, opt_len);
	pos += opt_len;

	print_to_buffer(buf, pos, out, sizeof(out));
	TEST_CHECK(contains(out, ";; OPT udp_size=1232"));
	TEST_CHECK(contains(out, "version=0"));
	TEST_CHECK(contains(out, "flags=0x8000"));
	TEST_CHECK(contains(out, "EDNS option ECS family=1 source=24 scope=0 address=203.0.113.0"));
	TEST_CHECK(contains(out, "EDNS option Padding len=4"));
	TEST_CHECK(contains(out, "EDNS option EDE code=15 (Blocked) text=\"policy\""));
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
	test_print_https_record_with_svcparams();
	test_print_svcb_no_default_alpn_and_bad_params();
	test_print_https_truncated_svcparam_header();
	test_print_tlsa_and_zonemd_records();
	test_print_opt_edns_options();
	test_print_nxdomain_status();
	test_print_unknown_type_hex();
	test_print_rejects_short_buffer();

	puts("print tests passed");
	return 0;
}
