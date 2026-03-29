/* SPDX-License-Identifier: MIT */

#include <string.h>

#include "dns.h"

static uint16_t
read_u16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
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
		if (jumps > 128)
			return -1;

		uint8_t len = buf[pos];

		if (len == 0) {
			if (!jumped)
				consumed = pos - offset + 1;
			terminated = true;
			break;
		}

		if ((len & 0xC0) == 0xC0) {
			if (pos + 1 >= buf_len)
				return -1;
			if (!jumped)
				consumed = pos - offset + 2;
			uint16_t ptr = ((len & 0x3F) << 8) | buf[pos + 1];
			if (ptr >= buf_len)
				return -1;
			pos    = ptr;
			jumped = true;
			jumps++;
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

		memcpy(out + out_pos, buf + pos, len);
		out_pos += len;
		pos     += len;
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

	msg->header.id      = read_u16(buf);
	msg->header.flags   = read_u16(buf + 2);
	msg->header.qdcount = read_u16(buf + 4);
	msg->header.ancount = read_u16(buf + 6);
	msg->header.nscount = read_u16(buf + 8);
	msg->header.arcount = read_u16(buf + 10);

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

	msg->question.qtype    = read_u16(buf + offset);
	msg->question.qclass   = read_u16(buf + offset + 2);

	msg->question_wire_len = name_consumed + 4;

	return 0;
}

const char *
dns_type_str(uint16_t type)
{
	switch (type) {
	case DNS_TYPE_A:
		return "A";
	case DNS_TYPE_NS:
		return "NS";
	case DNS_TYPE_CNAME:
		return "CNAME";
	case DNS_TYPE_MX:
		return "MX";
	case DNS_TYPE_TXT:
		return "TXT";
	case DNS_TYPE_AAAA:
		return "AAAA";
	default:
		return "UNKNOWN";
	}
}

const char *
dns_rcode_str(uint16_t rcode)
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
	default:
		return "UNKNOWN";
	}
}
