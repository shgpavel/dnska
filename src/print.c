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
	{ "A",      DNS_TYPE_A      },
	{ "NS",     DNS_TYPE_NS     },
	{ "CNAME",  DNS_TYPE_CNAME  },
	{ "SOA",    DNS_TYPE_SOA    },
	{ "PTR",    DNS_TYPE_PTR    },
	{ "MX",     DNS_TYPE_MX     },
	{ "TXT",    DNS_TYPE_TXT    },
	{ "AAAA",   DNS_TYPE_AAAA   },
	{ "SRV",    DNS_TYPE_SRV    },
	{ "OPT",    DNS_TYPE_OPT    },
	{ "DS",     DNS_TYPE_DS     },
	{ "RRSIG",  DNS_TYPE_RRSIG  },
	{ "NSEC",   DNS_TYPE_NSEC   },
	{ "DNSKEY", DNS_TYPE_DNSKEY },
	{ "CAA",    DNS_TYPE_CAA    },
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
		fprintf(out, ";; OPT udp_size=%u flags=0x%04x\n",
		        rrclass, (unsigned)(ttl & 0xFFFF));
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
