/* SPDX-License-Identifier: MIT */

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "dns.h"
#include "wire.h"

struct dns_rr_view {
	uint16_t type;
	uint16_t rrclass;
	uint16_t rdlen;
	uint32_t ttl;
	size_t   rdata_offset;
	size_t   next_offset;
};

static uint64_t
hash_bytes_seeded(uint64_t h, const uint8_t *buf, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		h ^= buf[i];
		h *= 1099511628211ULL;
	}

	return h;
}

static int
parse_rr_view(struct dns_rr_view *rr, const uint8_t *buf, size_t len, size_t offset)
{
	int n = wire_skip_name(buf, len, offset);
	if (n < 0)
		return -1;

	size_t pos = offset + (size_t)n;
	if (pos + 10 > len)
		return -1;

	rr->type         = wire_read_u16(buf + pos);
	rr->rrclass      = wire_read_u16(buf + pos + 2);
	rr->ttl          = wire_read_u32(buf + pos + 4);
	rr->rdlen        = wire_read_u16(buf + pos + 8);
	rr->rdata_offset = pos + 10;
	rr->next_offset  = rr->rdata_offset + rr->rdlen;

	if (rr->next_offset > len)
		return -1;

	return 0;
}

static bool
normalize_opt_for_cache(const uint8_t *rdata, uint16_t rdlen,
                        uint16_t *normalized_rdlen, uint64_t *normalized_hash)
{
	size_t   pos      = 0;
	uint16_t kept_len = 0;
	uint64_t h        = 1469598103934665603ULL;

	while (pos < rdlen) {
		if (rdlen - pos < 4)
			return false;

		uint16_t opt_code = wire_read_u16(rdata + pos);
		uint16_t opt_len  = wire_read_u16(rdata + pos + 2);
		size_t   opt_size = (size_t)opt_len + 4;

		if ((size_t)rdlen - pos < opt_size)
			return false;

		if (opt_code != DNS_EDNS_OPTION_COOKIE) {
			h        = hash_bytes_seeded(h, rdata + pos, opt_size);
			kept_len = (uint16_t)(kept_len + opt_size);
		}

		pos += opt_size;
	}

	*normalized_rdlen = kept_len;
	*normalized_hash  = kept_len == 0 ? 0 : h;
	return true;
}

int
dns_parse_name(const uint8_t *buf, size_t buf_len, size_t offset,
               char *out, size_t out_size, size_t *bytes_consumed)
{
	size_t out_pos    = 0;
	size_t pos        = offset;
	size_t consumed   = 0;
	bool   jumped     = false;
	bool   terminated = false;
	int    jumps      = 0;

	while (pos < buf_len) {
		uint8_t len = buf[pos];

		if (len == 0) {
			if (!jumped)
				consumed = pos - offset + 1;
			terminated = true;
			break;
		}

		if ((len & 0xC0) == 0xC0) {
			if (pos + 1 >= buf_len || ++jumps > WIRE_NAME_MAX_HOPS)
				return -1;
			if (!jumped)
				consumed = pos - offset + 2;
			uint16_t ptr = ((len & 0x3F) << 8) | buf[pos + 1];
			if (ptr >= buf_len)
				return -1;
			pos    = ptr;
			jumped = true;
			continue;
		}

		if (len > DNS_MAX_LABEL_LEN)
			return -1;

		pos++;
		if (pos + len > buf_len)
			return -1;

		if (out_pos > 0) {
			if (out_pos + 1 >= out_size)
				return -1;
			out[out_pos++] = '.';
		}

		if (out_pos + len >= out_size)
			return -1;

		for (uint8_t i = 0; i < len; i++)
			out[out_pos++] = (char)tolower((unsigned char)buf[pos + i]);
		pos += len;
	}

	if (!terminated)
		return -1;

	out[out_pos] = '\0';
	if (bytes_consumed)
		*bytes_consumed = consumed;
	return 0;
}

int
dns_parse_message(struct dns_message *msg, const uint8_t *buf, size_t len)
{
	if (len < DNS_HEADER_SIZE || len > DNS_MAX_MSG_SIZE)
		return -1;

	memset(msg, 0, sizeof(*msg));

	msg->header.id      = wire_read_u16(buf);
	msg->header.flags   = wire_read_u16(buf + 2);
	msg->header.qdcount = wire_read_u16(buf + 4);
	msg->header.ancount = wire_read_u16(buf + 6);
	msg->header.nscount = wire_read_u16(buf + 8);
	msg->header.arcount = wire_read_u16(buf + 10);

	if (msg->header.qdcount < 1)
		return -1;

	size_t offset        = DNS_HEADER_SIZE;
	size_t name_consumed = 0;

	if (dns_parse_name(buf, len, offset, msg->question.name,
	                   sizeof(msg->question.name), &name_consumed)
	    < 0)
		return -1;

	offset += name_consumed;
	if (offset + 4 > len)
		return -1;

	msg->question.qtype     = wire_read_u16(buf + offset);
	msg->question.qclass    = wire_read_u16(buf + offset + 2);

	msg->question_wire_len  = name_consumed + 4;
	msg->cache_key.flags    = msg->header.flags & DNS_CACHE_FLAGS_MASK;

	offset                 += 4;

	for (uint16_t i = 1; i < msg->header.qdcount; i++) {
		int n = wire_skip_name(buf, len, offset);
		if (n < 0)
			return -1;
		offset += (size_t)n + 4;
		if (offset > len)
			return -1;
	}

	for (uint32_t i = 0; i < (uint32_t)msg->header.ancount + msg->header.nscount; i++) {
		struct dns_rr_view rr;

		if (parse_rr_view(&rr, buf, len, offset) < 0)
			return -1;
		offset = rr.next_offset;
	}

	for (uint16_t i = 0; i < msg->header.arcount; i++) {
		struct dns_rr_view rr;

		if (parse_rr_view(&rr, buf, len, offset) < 0)
			return -1;

		/* Extract EDNS info from first OPT, regardless of cacheability */
		if (rr.type == DNS_TYPE_OPT && !msg->has_edns) {
			msg->has_edns     = true;
			msg->edns_version = (uint8_t)((rr.ttl >> 16) & 0xFF);
		}

		if (rr.type != DNS_TYPE_OPT) {
			msg->has_bad_additional = true;
		} else if (msg->cache_key.has_opt) {
			msg->has_bad_additional = true; /* second OPT */
		} else {
			uint16_t opt_rdlen = 0;
			uint64_t opt_hash  = 0;

			if (!normalize_opt_for_cache(buf + rr.rdata_offset, rr.rdlen,
			                             &opt_rdlen, &opt_hash)) {
				msg->has_bad_additional = true;
			} else {
				msg->cache_key.has_opt        = 1;
				msg->cache_key.opt_udp_size   = rr.rrclass;
				msg->cache_key.opt_ttl        = rr.ttl;
				msg->cache_key.opt_rdlen      = opt_rdlen;
				msg->cache_key.opt_rdata_hash = opt_hash;
			}
		}

		offset = rr.next_offset;
	}

	if (offset != len)
		return -1;

	return 0;
}

bool
dns_query_is_cacheable(const struct dns_message *msg)
{
	return ((msg->header.flags & DNS_FLAGS_OPCODE_MASK)
	        == (DNS_OPCODE_QUERY << DNS_FLAGS_OPCODE_SHIFT))
	       && msg->header.qdcount == 1
	       && msg->header.ancount == 0
	       && msg->header.nscount == 0
	       && !msg->has_bad_additional;
}

bool
dns_response_matches_query(const struct dns_message *query,
                           const uint8_t *response, size_t response_len)
{
	char     name[DNS_MAX_NAME_LEN + 1];
	size_t   name_consumed = 0;
	size_t   pos;
	uint16_t flags;

	if (query == NULL)
		return false;
	if (response_len < DNS_HEADER_SIZE)
		return false;

	flags = wire_read_u16(response + 2);
	if ((flags & DNS_FLAG_QR) == 0)
		return false;
	if (wire_read_u16(response) != query->header.id)
		return false;
	if (wire_read_u16(response + 4) != 1)
		return false;
	if ((flags & DNS_FLAGS_OPCODE_MASK)
	    != (query->header.flags & DNS_FLAGS_OPCODE_MASK))
		return false;
	if (dns_parse_name(response, response_len, DNS_HEADER_SIZE,
	                   name, sizeof(name), &name_consumed)
	    < 0)
		return false;

	pos = DNS_HEADER_SIZE + name_consumed;
	if (pos + 4 > response_len)
		return false;
	if (strcasecmp(name, query->question.name) != 0)
		return false;
	if (wire_read_u16(response + pos) != query->question.qtype)
		return false;
	if (wire_read_u16(response + pos + 2) != query->question.qclass)
		return false;

	return true;
}

const char *
dns_type_str(uint16_t type, char *buf, size_t buf_len)
{
	switch (type) {
	case DNS_TYPE_A:
		return "A";
	case DNS_TYPE_NS:
		return "NS";
	case DNS_TYPE_CNAME:
		return "CNAME";
	case DNS_TYPE_SOA:
		return "SOA";
	case DNS_TYPE_PTR:
		return "PTR";
	case DNS_TYPE_MX:
		return "MX";
	case DNS_TYPE_TXT:
		return "TXT";
	case DNS_TYPE_AAAA:
		return "AAAA";
	case DNS_TYPE_SRV:
		return "SRV";
	case DNS_TYPE_OPT:
		return "OPT";
	case DNS_TYPE_DS:
		return "DS";
	case DNS_TYPE_RRSIG:
		return "RRSIG";
	case DNS_TYPE_NSEC:
		return "NSEC";
	case DNS_TYPE_DNSKEY:
		return "DNSKEY";
	case DNS_TYPE_CAA:
		return "CAA";
	default:
		if (buf != NULL && buf_len > 0)
			snprintf(buf, buf_len, "TYPE%u", type);
		return buf != NULL && buf_len > 0 ? buf : "UNKNOWN";
	}
}

const char *
dns_rcode_str(uint16_t rcode, char *buf, size_t buf_len)
{
	switch (rcode) {
	case DNS_RCODE_OK:
		return "NOERROR";
	case DNS_RCODE_FORMERR:
		return "FORMERR";
	case DNS_RCODE_SERVFAIL:
		return "SERVFAIL";
	case DNS_RCODE_NXDOMAIN:
		return "NXDOMAIN";
	case DNS_RCODE_NOTIMP:
		return "NOTIMP";
	case DNS_RCODE_REFUSED:
		return "REFUSED";
	case DNS_RCODE_YXDOMAIN:
		return "YXDOMAIN";
	case DNS_RCODE_YXRRSET:
		return "YXRRSET";
	case DNS_RCODE_NXRRSET:
		return "NXRRSET";
	case DNS_RCODE_NOTAUTH:
		return "NOTAUTH";
	case DNS_RCODE_NOTZONE:
		return "NOTZONE";
	case DNS_RCODE_BADVERS:
		return "BADVERS";
	default:
		if (buf != NULL && buf_len > 0)
			snprintf(buf, buf_len, "RCODE%u", rcode);
		return buf != NULL && buf_len > 0 ? buf : "UNKNOWN";
	}
}
