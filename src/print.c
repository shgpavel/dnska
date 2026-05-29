/* SPDX-License-Identifier: MIT */

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "dns.h"
#include "print.h"
#include "wire.h"

struct type_entry {
	const char *name;
	uint16_t    value;
};

static const struct type_entry type_table[] = {
	{ "A",          DNS_TYPE_A          },
	{ "NS",         DNS_TYPE_NS         },
	{ "CNAME",      DNS_TYPE_CNAME      },
	{ "SOA",        DNS_TYPE_SOA        },
	{ "PTR",        DNS_TYPE_PTR        },
	{ "MX",         DNS_TYPE_MX         },
	{ "TXT",        DNS_TYPE_TXT        },
	{ "AAAA",       DNS_TYPE_AAAA       },
	{ "SRV",        DNS_TYPE_SRV        },
	{ "OPT",        DNS_TYPE_OPT        },
	{ "DS",         DNS_TYPE_DS         },
	{ "SSHFP",      DNS_TYPE_SSHFP      },
	{ "RRSIG",      DNS_TYPE_RRSIG      },
	{ "NSEC",       DNS_TYPE_NSEC       },
	{ "DNSKEY",     DNS_TYPE_DNSKEY     },
	{ "NSEC3",      DNS_TYPE_NSEC3      },
	{ "NSEC3PARAM", DNS_TYPE_NSEC3PARAM },
	{ "TLSA",       DNS_TYPE_TLSA       },
	{ "CDS",        DNS_TYPE_CDS        },
	{ "CDNSKEY",    DNS_TYPE_CDNSKEY    },
	{ "ZONEMD",     DNS_TYPE_ZONEMD     },
	{ "SVCB",       DNS_TYPE_SVCB       },
	{ "HTTPS",      DNS_TYPE_HTTPS      },
	{ "CAA",        DNS_TYPE_CAA        },
};

int
dns_type_from_str(const char *s, uint16_t *out)
{
	if (s == NULL || *s == '\0')
		return -1;

	for (size_t i = 0; i < sizeof(type_table) / sizeof(type_table[0]); i++) {
		if (strcasecmp(s, type_table[i].name) == 0) {
			*out = type_table[i].value;
			return 0;
		}
	}

	if (strncasecmp(s, "TYPE", 4) == 0) {
		char         *end;
		unsigned long v = strtoul(s + 4, &end, 10);
		if (*end == '\0' && v <= 0xFFFF) {
			*out = (uint16_t)v;
			return 0;
		}
	}

	return -1;
}

static int
read_name(const uint8_t *buf, size_t len, size_t off, char *out, size_t out_size,
          size_t *consumed)
{
	return dns_parse_name(buf, len, off, out, out_size, consumed);
}

static void
print_a(FILE *out, const uint8_t *rdata, size_t rdlen)
{
	char ip[INET_ADDRSTRLEN];

	if (rdlen != 4) {
		fprintf(out, "<bad A rdlen %zu>", rdlen);
		return;
	}
	inet_ntop(AF_INET, rdata, ip, sizeof(ip));
	fputs(ip, out);
}

static void
print_aaaa(FILE *out, const uint8_t *rdata, size_t rdlen)
{
	char ip[INET6_ADDRSTRLEN];

	if (rdlen != 16) {
		fprintf(out, "<bad AAAA rdlen %zu>", rdlen);
		return;
	}
	inet_ntop(AF_INET6, rdata, ip, sizeof(ip));
	fputs(ip, out);
}

static void
print_name_rr(FILE *out, const uint8_t *msg, size_t msg_len, size_t rdoff)
{
	char   name[DNS_MAX_NAME_LEN + 1];
	size_t consumed = 0;

	if (read_name(msg, msg_len, rdoff, name, sizeof(name), &consumed) < 0) {
		fputs("<bad name>", out);
		return;
	}
	fputs(name[0] ? name : ".", out);
}

static void
print_mx(FILE *out, const uint8_t *msg, size_t msg_len,
         const uint8_t *rdata, size_t rdlen, size_t rdoff)
{
	if (rdlen < 2) {
		fprintf(out, "<bad MX>");
		return;
	}
	uint16_t pref = wire_read_u16(rdata);
	fprintf(out, "%u ", pref);
	print_name_rr(out, msg, msg_len, rdoff + 2);
}

static void
print_soa(FILE *out, const uint8_t *msg, size_t msg_len, size_t rdoff,
          size_t rdlen)
{
	char   ns[DNS_MAX_NAME_LEN + 1];
	char   mb[DNS_MAX_NAME_LEN + 1];
	size_t c1 = 0, c2 = 0;

	if (read_name(msg, msg_len, rdoff, ns, sizeof(ns), &c1) < 0) {
		fputs("<bad SOA mname>", out);
		return;
	}
	if (read_name(msg, msg_len, rdoff + c1, mb, sizeof(mb), &c2) < 0) {
		fputs("<bad SOA rname>", out);
		return;
	}
	size_t fields_off = rdoff + c1 + c2;
	if (fields_off + 20 > rdoff + rdlen) {
		fputs("<bad SOA fields>", out);
		return;
	}
	uint32_t serial  = wire_read_u32(msg + fields_off);
	uint32_t refresh = wire_read_u32(msg + fields_off + 4);
	uint32_t retry   = wire_read_u32(msg + fields_off + 8);
	uint32_t expire  = wire_read_u32(msg + fields_off + 12);
	uint32_t minimum = wire_read_u32(msg + fields_off + 16);

	fprintf(out, "%s %s %u %u %u %u %u",
	        ns[0] ? ns : ".", mb[0] ? mb : ".",
	        serial, refresh, retry, expire, minimum);
}

static void
print_txt(FILE *out, const uint8_t *rdata, size_t rdlen)
{
	size_t pos   = 0;
	int    first = 1;

	while (pos < rdlen) {
		uint8_t slen = rdata[pos++];
		if (pos + slen > rdlen) {
			fputs("<bad TXT>", out);
			return;
		}
		if (!first)
			fputc(' ', out);
		first = 0;
		fputc('"', out);
		for (uint8_t i = 0; i < slen; i++) {
			uint8_t c = rdata[pos + i];
			if (c == '"' || c == '\\')
				fputc('\\', out);
			if (c < 0x20 || c >= 0x7F)
				fprintf(out, "\\%03u", c);
			else
				fputc(c, out);
		}
		fputc('"', out);
		pos += slen;
	}
}

static void
print_srv(FILE *out, const uint8_t *msg, size_t msg_len,
          const uint8_t *rdata, size_t rdlen, size_t rdoff)
{
	if (rdlen < 6) {
		fputs("<bad SRV>", out);
		return;
	}
	uint16_t prio   = wire_read_u16(rdata);
	uint16_t weight = wire_read_u16(rdata + 2);
	uint16_t port   = wire_read_u16(rdata + 4);
	fprintf(out, "%u %u %u ", prio, weight, port);
	print_name_rr(out, msg, msg_len, rdoff + 6);
}

static void
print_caa(FILE *out, const uint8_t *rdata, size_t rdlen)
{
	if (rdlen < 2) {
		fputs("<bad CAA>", out);
		return;
	}
	uint8_t flags   = rdata[0];
	uint8_t tag_len = rdata[1];
	if ((size_t)tag_len + 2 > rdlen) {
		fputs("<bad CAA tag>", out);
		return;
	}
	fprintf(out, "%u ", flags);
	for (uint8_t i = 0; i < tag_len; i++)
		fputc((char)rdata[2 + i], out);
	fputc(' ', out);
	fputc('"', out);
	for (size_t i = (size_t)tag_len + 2; i < rdlen; i++)
		fputc((char)rdata[i], out);
	fputc('"', out);
}

static void
print_hex(FILE *out, const uint8_t *rdata, size_t rdlen)
{
	for (size_t i = 0; i < rdlen; i++) {
		if (i > 0 && (i % 32) == 0)
			fputc(' ', out);
		fprintf(out, "%02x", rdata[i]);
	}
}

static void
print_escaped_unquoted(FILE *out, const uint8_t *data, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		uint8_t c = data[i];
		if (c == ',' || c == '"' || c == '\\') {
			fputc('\\', out);
			fputc((char)c, out);
		} else if (c < 0x20 || c >= 0x7F) {
			fprintf(out, "\\%03u", c);
		} else {
			fputc((char)c, out);
		}
	}
}

static void
print_quoted_bytes(FILE *out, const uint8_t *data, size_t len)
{
	fputc('"', out);
	for (size_t i = 0; i < len; i++) {
		uint8_t c = data[i];
		if (c == '"' || c == '\\')
			fputc('\\', out);
		if (c < 0x20 || c >= 0x7F)
			fprintf(out, "\\%03u", c);
		else
			fputc((char)c, out);
	}
	fputc('"', out);
}

static const char *
svcparam_key_str(uint16_t key, char *buf, size_t buf_len)
{
	switch (key) {
	case 0:
		return "mandatory";
	case 1:
		return "alpn";
	case 2:
		return "no-default-alpn";
	case 3:
		return "port";
	case 4:
		return "ipv4hint";
	case 5:
		return "ech";
	case 6:
		return "ipv6hint";
	case 7:
		return "dohpath";
	default:
		if (buf != NULL && buf_len > 0)
			snprintf(buf, buf_len, "key%u", key);
		return buf != NULL && buf_len > 0 ? buf : "key?";
	}
}

static void
print_svcparam_mandatory(FILE *out, const uint8_t *data, size_t len)
{
	if (len == 0 || (len % 2) != 0) {
		fputs("mandatory=<bad>", out);
		return;
	}

	fputs("mandatory=", out);
	for (size_t pos = 0; pos < len; pos += 2) {
		char key_buf[32];
		if (pos > 0)
			fputc(',', out);
		fputs(svcparam_key_str(wire_read_u16(data + pos),
		                       key_buf, sizeof(key_buf)),
		      out);
	}
}

static int
print_svcparam_alpn(FILE *out, const uint8_t *data, size_t len)
{
	size_t pos   = 0;
	int    first = 1;

	while (pos < len) {
		uint8_t alpn_len = data[pos++];
		if (pos + alpn_len > len)
			return -1;
		if (!first)
			fputc(',', out);
		first = 0;
		print_escaped_unquoted(out, data + pos, alpn_len);
		pos += alpn_len;
	}

	return first ? -1 : 0;
}

static void
print_svcparam_ipv4hint(FILE *out, const uint8_t *data, size_t len)
{
	if (len == 0 || (len % 4) != 0) {
		fputs("ipv4hint=<bad>", out);
		return;
	}

	fputs("ipv4hint=", out);
	for (size_t pos = 0; pos < len; pos += 4) {
		char ip[INET_ADDRSTRLEN];
		if (pos > 0)
			fputc(',', out);
		if (inet_ntop(AF_INET, data + pos, ip, sizeof(ip)) == NULL)
			fputs("<bad>", out);
		else
			fputs(ip, out);
	}
}

static void
print_svcparam_ipv6hint(FILE *out, const uint8_t *data, size_t len)
{
	if (len == 0 || (len % 16) != 0) {
		fputs("ipv6hint=<bad>", out);
		return;
	}

	fputs("ipv6hint=", out);
	for (size_t pos = 0; pos < len; pos += 16) {
		char ip[INET6_ADDRSTRLEN];
		if (pos > 0)
			fputc(',', out);
		if (inet_ntop(AF_INET6, data + pos, ip, sizeof(ip)) == NULL)
			fputs("<bad>", out);
		else
			fputs(ip, out);
	}
}

static void
print_svcparam(FILE *out, uint16_t key, const uint8_t *data, size_t len)
{
	char key_buf[32];

	switch (key) {
	case 0:
		print_svcparam_mandatory(out, data, len);
		break;
	case 1:
		fputs("alpn=", out);
		if (print_svcparam_alpn(out, data, len) < 0)
			fputs("<bad>", out);
		break;
	case 2:
		if (len == 0)
			fputs("no-default-alpn", out);
		else
			fprintf(out, "no-default-alpn=<bad len %zu>", len);
		break;
	case 3:
		if (len != 2) {
			fprintf(out, "port=<bad len %zu>", len);
		} else {
			fprintf(out, "port=%u", wire_read_u16(data));
		}
		break;
	case 4:
		print_svcparam_ipv4hint(out, data, len);
		break;
	case 5:
		fputs("ech=", out);
		print_hex(out, data, len);
		break;
	case 6:
		print_svcparam_ipv6hint(out, data, len);
		break;
	case 7:
		fputs("dohpath=", out);
		print_quoted_bytes(out, data, len);
		break;
	default:
		fputs(svcparam_key_str(key, key_buf, sizeof(key_buf)), out);
		if (len > 0) {
			fputc('=', out);
			print_hex(out, data, len);
		}
		break;
	}
}

static void
print_svcb(FILE *out, const char *rr_name, const uint8_t *msg,
           size_t msg_len, size_t rdoff, size_t rdlen)
{
	if (rdlen < 2) {
		fprintf(out, "<bad %s>", rr_name);
		return;
	}

	size_t   end          = rdoff + rdlen;
	uint16_t svc_priority = wire_read_u16(msg + rdoff);
	char     target[DNS_MAX_NAME_LEN + 1];
	size_t   target_consumed = 0;

	if (read_name(msg, msg_len, rdoff + 2, target, sizeof(target),
	              &target_consumed)
	            < 0
	    || rdoff + 2 + target_consumed > end) {
		fprintf(out, "<bad %s target>", rr_name);
		return;
	}

	fprintf(out, "%u %s", svc_priority, target[0] ? target : ".");

	size_t pos = rdoff + 2 + target_consumed;
	while (pos < end) {
		if (end - pos < 4) {
			fprintf(out, " <bad %s param>", rr_name);
			return;
		}
		uint16_t key  = wire_read_u16(msg + pos);
		uint16_t len  = wire_read_u16(msg + pos + 2);
		pos          += 4;
		if (end - pos < len) {
			fprintf(out, " <bad %s param>", rr_name);
			return;
		}
		fputc(' ', out);
		print_svcparam(out, key, msg + pos, len);
		pos += len;
	}
}

static void
print_tlsa(FILE *out, const uint8_t *rdata, size_t rdlen)
{
	if (rdlen < 3) {
		fputs("<bad TLSA>", out);
		return;
	}

	fprintf(out, "usage=%u selector=%u matching=%u data=",
	        rdata[0], rdata[1], rdata[2]);
	print_hex(out, rdata + 3, rdlen - 3);
}

static const char *
zonemd_scheme_name(uint8_t scheme)
{
	switch (scheme) {
	case 1:
		return "simple";
	default:
		return NULL;
	}
}

static const char *
zonemd_hash_name(uint8_t hash)
{
	switch (hash) {
	case 1:
		return "sha384";
	case 2:
		return "sha512";
	default:
		return NULL;
	}
}

static void
print_zonemd(FILE *out, const uint8_t *rdata, size_t rdlen)
{
	if (rdlen < 6) {
		fputs("<bad ZONEMD>", out);
		return;
	}

	uint32_t    serial = wire_read_u32(rdata);
	uint8_t     scheme = rdata[4];
	uint8_t     hash   = rdata[5];
	const char *sname  = zonemd_scheme_name(scheme);
	const char *hname  = zonemd_hash_name(hash);

	fprintf(out, "serial=%u scheme=%u", serial, scheme);
	if (sname != NULL)
		fprintf(out, "(%s)", sname);
	fprintf(out, " hash=%u", hash);
	if (hname != NULL)
		fprintf(out, "(%s)", hname);
	fputs(" digest=", out);
	print_hex(out, rdata + 6, rdlen - 6);
}

static void
print_rdata(FILE *out, uint16_t type, const uint8_t *msg, size_t msg_len,
            size_t rdoff, size_t rdlen)
{
	const uint8_t *rdata = msg + rdoff;

	switch (type) {
	case DNS_TYPE_A:
		print_a(out, rdata, rdlen);
		break;
	case DNS_TYPE_AAAA:
		print_aaaa(out, rdata, rdlen);
		break;
	case DNS_TYPE_NS:
	case DNS_TYPE_CNAME:
	case DNS_TYPE_PTR:
		print_name_rr(out, msg, msg_len, rdoff);
		break;
	case DNS_TYPE_MX:
		print_mx(out, msg, msg_len, rdata, rdlen, rdoff);
		break;
	case DNS_TYPE_TXT:
		print_txt(out, rdata, rdlen);
		break;
	case DNS_TYPE_SOA:
		print_soa(out, msg, msg_len, rdoff, rdlen);
		break;
	case DNS_TYPE_SRV:
		print_srv(out, msg, msg_len, rdata, rdlen, rdoff);
		break;
	case DNS_TYPE_SVCB:
		print_svcb(out, "SVCB", msg, msg_len, rdoff, rdlen);
		break;
	case DNS_TYPE_HTTPS:
		print_svcb(out, "HTTPS", msg, msg_len, rdoff, rdlen);
		break;
	case DNS_TYPE_TLSA:
		print_tlsa(out, rdata, rdlen);
		break;
	case DNS_TYPE_ZONEMD:
		print_zonemd(out, rdata, rdlen);
		break;
	case DNS_TYPE_CAA:
		print_caa(out, rdata, rdlen);
		break;
	default:
		print_hex(out, rdata, rdlen);
		break;
	}
}

static int
print_question(FILE *out, const uint8_t *msg, size_t msg_len,
               size_t off, size_t *next_off)
{
	char   name[DNS_MAX_NAME_LEN + 1];
	char   tbuf[32];
	size_t consumed = 0;

	if (read_name(msg, msg_len, off, name, sizeof(name), &consumed) < 0)
		return -1;
	if (off + consumed + 4 > msg_len)
		return -1;

	uint16_t qtype  = wire_read_u16(msg + off + consumed);
	uint16_t qclass = wire_read_u16(msg + off + consumed + 2);

	fprintf(out, ";%s.\t\t%s\t%s\n",
	        name[0] ? name : "",
	        qclass == DNS_CLASS_IN ? "IN" : "?",
	        dns_type_str(qtype, tbuf, sizeof(tbuf)));

	*next_off = off + consumed + 4;
	return 0;
}

static const char *
ede_info_code_name(uint16_t code)
{
	switch (code) {
	case 0:
		return "Other";
	case 1:
		return "Unsupported DNSKEY Algorithm";
	case 2:
		return "Unsupported DS Digest Type";
	case 3:
		return "Stale Answer";
	case 4:
		return "Forged Answer";
	case 5:
		return "DNSSEC Indeterminate";
	case 6:
		return "DNSSEC Bogus";
	case 7:
		return "Signature Expired";
	case 8:
		return "Signature Not Yet Valid";
	case 9:
		return "DNSKEY Missing";
	case 10:
		return "RRSIGs Missing";
	case 11:
		return "No Zone Key Bit Set";
	case 12:
		return "NSEC Missing";
	case 13:
		return "Cached Error";
	case 14:
		return "Not Ready";
	case 15:
		return "Blocked";
	case 16:
		return "Censored";
	case 17:
		return "Filtered";
	case 18:
		return "Prohibited";
	case 19:
		return "Stale NXDOMAIN Answer";
	case 20:
		return "Not Authoritative";
	case 21:
		return "Not Supported";
	case 22:
		return "No Reachable Authority";
	case 23:
		return "Network Error";
	case 24:
		return "Invalid Data";
	default:
		return NULL;
	}
}

static void
print_edns_ecs(FILE *out, const uint8_t *data, size_t len)
{
	if (len < 4) {
		fputs("ECS <bad>", out);
		return;
	}

	uint16_t family = wire_read_u16(data);
	uint8_t  source = data[2];
	uint8_t  scope  = data[3];

	if (family != 1 && family != 2) {
		fprintf(out, "ECS family=%u source=%u scope=%u address=",
		        family, source, scope);
		print_hex(out, data + 4, len - 4);
		return;
	}

	uint8_t max_bits = family == 1 ? 32 : 128;
	size_t  addr_len = ((size_t)source + 7) / 8;
	if (source > max_bits || scope > max_bits || len != 4 + addr_len) {
		fprintf(out, "ECS family=%u source=%u scope=%u <bad>",
		        family, source, scope);
		return;
	}

	uint8_t addr[16] = { 0 };
	memcpy(addr, data + 4, addr_len);

	char ip[INET6_ADDRSTRLEN];
	int  af = family == 1 ? AF_INET : AF_INET6;
	if (inet_ntop(af, addr, ip, sizeof(ip)) == NULL) {
		fprintf(out, "ECS family=%u source=%u scope=%u <bad>",
		        family, source, scope);
		return;
	}

	fprintf(out, "ECS family=%u source=%u scope=%u address=%s",
	        family, source, scope, ip);
}

static void
print_edns_ede(FILE *out, const uint8_t *data, size_t len)
{
	if (len < 2) {
		fputs("EDE <bad>", out);
		return;
	}

	uint16_t    info_code = wire_read_u16(data);
	const char *name      = ede_info_code_name(info_code);

	fprintf(out, "EDE code=%u", info_code);
	if (name != NULL)
		fprintf(out, " (%s)", name);
	if (len > 2) {
		fputs(" text=", out);
		print_quoted_bytes(out, data + 2, len - 2);
	}
}

static void
print_edns_option(FILE *out, uint16_t code, const uint8_t *data, size_t len)
{
	switch (code) {
	case DNS_EDNS_OPTION_NSID:
		fputs("NSID", out);
		if (len > 0) {
			fputs(" data=", out);
			print_hex(out, data, len);
		}
		break;
	case DNS_EDNS_OPTION_ECS:
		print_edns_ecs(out, data, len);
		break;
	case DNS_EDNS_OPTION_COOKIE:
		fputs("COOKIE", out);
		if (len > 0) {
			fputs(" data=", out);
			print_hex(out, data, len);
		}
		break;
	case DNS_EDNS_OPTION_PADDING:
		fprintf(out, "Padding len=%zu", len);
		break;
	case DNS_EDNS_OPTION_EDE:
		print_edns_ede(out, data, len);
		break;
	default:
		fprintf(out, "OPTION%u len=%zu", code, len);
		if (len > 0) {
			fputs(" data=", out);
			print_hex(out, data, len);
		}
		break;
	}
}

static void
print_opt(FILE *out, uint16_t udp_size, uint32_t ttl,
          const uint8_t *rdata, size_t rdlen)
{
	uint8_t  ext_rcode = (uint8_t)(ttl >> 24);
	uint8_t  version   = (uint8_t)((ttl >> 16) & 0xFF);
	uint16_t flags     = (uint16_t)(ttl & 0xFFFF);

	fprintf(out, ";; OPT udp_size=%u ext_rcode=%u version=%u flags=0x%04x\n",
	        udp_size, ext_rcode, version, flags);

	size_t pos = 0;
	while (pos < rdlen) {
		if (rdlen - pos < 4) {
			fputs(";; EDNS option <bad>\n", out);
			return;
		}

		uint16_t code     = wire_read_u16(rdata + pos);
		uint16_t opt_len  = wire_read_u16(rdata + pos + 2);
		pos              += 4;
		if (rdlen - pos < opt_len) {
			fputs(";; EDNS option <bad>\n", out);
			return;
		}

		fputs(";; EDNS option ", out);
		print_edns_option(out, code, rdata + pos, opt_len);
		fputc('\n', out);
		pos += opt_len;
	}
}

static int
print_rr(FILE *out, const uint8_t *msg, size_t msg_len, size_t off,
         size_t *next_off)
{
	char   name[DNS_MAX_NAME_LEN + 1];
	char   tbuf[32];
	size_t consumed = 0;

	if (read_name(msg, msg_len, off, name, sizeof(name), &consumed) < 0)
		return -1;

	size_t fixed = off + consumed;
	if (fixed + 10 > msg_len)
		return -1;

	uint16_t type    = wire_read_u16(msg + fixed);
	uint16_t rrclass = wire_read_u16(msg + fixed + 2);
	uint32_t ttl     = wire_read_u32(msg + fixed + 4);
	uint16_t rdlen   = wire_read_u16(msg + fixed + 8);
	size_t   rdoff   = fixed + 10;
	if (rdoff + rdlen > msg_len)
		return -1;

	if (type == DNS_TYPE_OPT) {
		print_opt(out, rrclass, ttl, msg + rdoff, rdlen);
	} else {
		fprintf(out, "%s.\t%u\t%s\t%s\t",
		        name[0] ? name : "",
		        ttl,
		        rrclass == DNS_CLASS_IN ? "IN" : "?",
		        dns_type_str(type, tbuf, sizeof(tbuf)));
		print_rdata(out, type, msg, msg_len, rdoff, rdlen);
		fputc('\n', out);
	}

	*next_off = rdoff + rdlen;
	return 0;
}

int
dns_print_response(FILE *out, const uint8_t *msg, size_t len)
{
	if (len < DNS_HEADER_SIZE)
		return -1;

	uint16_t id     = wire_read_u16(msg);
	uint16_t flags  = wire_read_u16(msg + 2);
	uint16_t qd     = wire_read_u16(msg + 4);
	uint16_t an     = wire_read_u16(msg + 6);
	uint16_t ns     = wire_read_u16(msg + 8);
	uint16_t ar     = wire_read_u16(msg + 10);
	uint8_t  rcode  = (uint8_t)(flags & DNS_FLAGS_RCODE_MASK);
	uint8_t  opcode = (uint8_t)((flags & DNS_FLAGS_OPCODE_MASK)
	                            >> DNS_FLAGS_OPCODE_SHIFT);

	char     rcbuf[32];
	fprintf(out, ";; ->>HEADER<<- opcode: %u, status: %s, id: %u\n",
	        opcode, dns_rcode_str(rcode, rcbuf, sizeof(rcbuf)), id);
	fprintf(out, ";; flags:%s%s%s%s%s%s%s; ",
	        (flags & DNS_FLAG_QR) ? " qr" : "",
	        (flags & DNS_FLAG_AA) ? " aa" : "",
	        (flags & DNS_FLAG_TC) ? " tc" : "",
	        (flags & DNS_FLAG_RD) ? " rd" : "",
	        (flags & DNS_FLAG_RA) ? " ra" : "",
	        (flags & DNS_FLAG_AD) ? " ad" : "",
	        (flags & DNS_FLAG_CD) ? " cd" : "");
	fprintf(out, "QUERY: %u, ANSWER: %u, AUTHORITY: %u, ADDITIONAL: %u\n",
	        qd, an, ns, ar);

	size_t off = DNS_HEADER_SIZE;
	if (qd > 0) {
		fputs("\n;; QUESTION SECTION:\n", out);
		for (uint16_t i = 0; i < qd; i++) {
			if (print_question(out, msg, len, off, &off) < 0)
				return -1;
		}
	}

	const char *labels[3] = { "ANSWER", "AUTHORITY", "ADDITIONAL" };
	uint16_t    counts[3] = { an, ns, ar };
	for (int sec = 0; sec < 3; sec++) {
		if (counts[sec] == 0)
			continue;
		fprintf(out, "\n;; %s SECTION:\n", labels[sec]);
		for (uint16_t i = 0; i < counts[sec]; i++) {
			if (print_rr(out, msg, len, off, &off) < 0)
				return -1;
		}
	}

	return 0;
}
