/* SPDX-License-Identifier: MIT */

#ifndef DNSKA_DNS_H
#define DNSKA_DNS_H

#include <stddef.h>
#include <stdint.h>

enum dns_size {
	DNS_MAX_MSG_SIZE  = 4096,
	DNS_MAX_NAME_LEN  = 255,
	DNS_MAX_LABEL_LEN = 63,
	DNS_HEADER_SIZE   = 12,
};

enum dns_qr {
	DNS_QR_QUERY    = 0,
	DNS_QR_RESPONSE = 1,
};

enum dns_opcode {
	DNS_OPCODE_QUERY  = 0,
	DNS_OPCODE_IQUERY = 1,
	DNS_OPCODE_STATUS = 2,
};

enum dns_rcode {
	DNS_RCODE_OK       = 0,
	DNS_RCODE_FORMERR  = 1,
	DNS_RCODE_SERVFAIL = 2,
	DNS_RCODE_NXDOMAIN = 3,
	DNS_RCODE_NOTIMP   = 4,
	DNS_RCODE_REFUSED  = 5,
};

enum dns_type {
	DNS_TYPE_A     = 1,
	DNS_TYPE_NS    = 2,
	DNS_TYPE_CNAME = 5,
	DNS_TYPE_MX    = 15,
	DNS_TYPE_TXT   = 16,
	DNS_TYPE_AAAA  = 28,
};

enum dns_class {
	DNS_CLASS_IN = 1,
};

enum dns_flag {
	DNS_FLAG_QR = 1 << 15,
	DNS_FLAG_AA = 1 << 10,
	DNS_FLAG_TC = 1 << 9,
	DNS_FLAG_RD = 1 << 8,
	DNS_FLAG_RA = 1 << 7,
};

enum dns_flags_mask {
	DNS_FLAGS_OPCODE_SHIFT = 11,
	DNS_FLAGS_OPCODE_MASK  = 0xF << 11,
	DNS_FLAGS_RCODE_MASK   = 0xF,
};

struct dns_header {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
};

struct dns_question {
	char     name[DNS_MAX_NAME_LEN + 1];
	uint16_t qtype;
	uint16_t qclass;
};

struct dns_message {
	struct dns_header   header;
	struct dns_question question;
	size_t              question_wire_len;
};

int
dns_parse_message(struct dns_message *msg, const uint8_t *buf, size_t len);
int
dns_parse_name(const uint8_t *buf, size_t buf_len, size_t offset,
               char *out, size_t out_size, size_t *bytes_consumed);

const char *
dns_type_str(uint16_t type);
const char *
dns_rcode_str(uint16_t rcode);

#endif /* DNSKA_DNS_H */
