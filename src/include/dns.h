/* SPDX-License-Identifier: MIT */

#ifndef DNSKA_DNS_H
#define DNSKA_DNS_H

#include <stdbool.h>
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
	DNS_RCODE_YXDOMAIN = 6,
	DNS_RCODE_YXRRSET  = 7,
	DNS_RCODE_NXRRSET  = 8,
	DNS_RCODE_NOTAUTH  = 9,
	DNS_RCODE_NOTZONE  = 10,
	DNS_RCODE_BADVERS  = 16,
};

enum dns_type {
	DNS_TYPE_A          = 1,
	DNS_TYPE_NS         = 2,
	DNS_TYPE_CNAME      = 5,
	DNS_TYPE_SOA        = 6,
	DNS_TYPE_PTR        = 12,
	DNS_TYPE_MX         = 15,
	DNS_TYPE_TXT        = 16,
	DNS_TYPE_AAAA       = 28,
	DNS_TYPE_SRV        = 33,
	DNS_TYPE_OPT        = 41,
	DNS_TYPE_DS         = 43,
	DNS_TYPE_SSHFP      = 44,
	DNS_TYPE_RRSIG      = 46,
	DNS_TYPE_NSEC       = 47,
	DNS_TYPE_DNSKEY     = 48,
	DNS_TYPE_NSEC3      = 50,
	DNS_TYPE_NSEC3PARAM = 51,
	DNS_TYPE_TLSA       = 52,
	DNS_TYPE_CDS        = 59,
	DNS_TYPE_CDNSKEY    = 60,
	DNS_TYPE_ZONEMD     = 63,
	DNS_TYPE_SVCB       = 64,
	DNS_TYPE_HTTPS      = 65,
	DNS_TYPE_CAA        = 257,
};

enum dns_edns_option {
	DNS_EDNS_OPTION_NSID    = 3,
	DNS_EDNS_OPTION_ECS     = 8,
	DNS_EDNS_OPTION_COOKIE  = 10,
	DNS_EDNS_OPTION_PADDING = 12,
	DNS_EDNS_OPTION_EDE     = 15,
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
	DNS_FLAG_AD = 1 << 5,
	DNS_FLAG_CD = 1 << 4,
};

enum dns_flags_mask {
	DNS_FLAGS_OPCODE_SHIFT = 11,
	DNS_FLAGS_OPCODE_MASK  = 0xF << 11,
	DNS_FLAGS_RCODE_MASK   = 0xF,
	DNS_CACHE_FLAGS_MASK   = DNS_FLAGS_OPCODE_MASK | DNS_FLAG_RD | DNS_FLAG_AD | DNS_FLAG_CD,
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

struct dns_query_cache_key {
	uint16_t flags;
	uint16_t opt_udp_size;
	uint16_t opt_rdlen;
	uint32_t opt_ttl;
	uint64_t opt_rdata_hash;
	uint8_t  has_opt;
};

struct dns_message {
	struct dns_header          header;
	struct dns_question        question;
	size_t                     question_wire_len;
	struct dns_query_cache_key cache_key;
	bool                       has_edns;
	bool                       has_bad_additional; /* non-OPT or >1 OPT in AR */
	uint8_t                    edns_version;
};

int
dns_parse_message(struct dns_message *msg, const uint8_t *buf, size_t len);
bool
dns_query_is_cacheable(const struct dns_message *msg);
int
dns_parse_name(const uint8_t *buf, size_t buf_len, size_t offset,
               char *out, size_t out_size, size_t *bytes_consumed);
bool
dns_response_matches_query(const struct dns_message *query,
                           const uint8_t *response, size_t response_len);

/*
 * Locate the OPT pseudo-RR in the additional section.
 * Returns 0 on found (writes *opt_offset and *opt_total_len which is
 * the wire length of the OPT RR including its name, fixed fields, and
 * RDATA), 1 if no OPT is present, or -1 if the message is malformed.
 */
int
dns_find_opt(const uint8_t *buf, size_t len,
             size_t *opt_offset, size_t *opt_total_len);

/*
 * Ensure the message has an EDNS OPT record with DO=1.
 * If an OPT already exists, sets the DO bit on its flags field.
 * Otherwise appends a 1232-byte payload OPT pseudo-RR with DO=1 and
 * bumps ARCOUNT.  Returns the new wire length, or 0 on failure (e.g.
 * malformed message or insufficient capacity).
 */
size_t
dns_set_outbound_edns(uint8_t *buf, size_t len, size_t max_size);

/*
 * Remove the OPT pseudo-RR from a response (e.g. before delivering to
 * a non-EDNS client per RFC 6891 §6.1.1).  Decrements ARCOUNT.  Returns
 * the new wire length, or the original length if no OPT or on parse
 * failure.
 */
size_t
dns_strip_response_opt(uint8_t *buf, size_t len);

const char *
dns_type_str(uint16_t type, char *buf, size_t buf_len);
const char *
dns_rcode_str(uint16_t rcode, char *buf, size_t buf_len);

#endif /* DNSKA_DNS_H */
