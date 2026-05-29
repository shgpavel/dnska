/* SPDX-License-Identifier: MIT */

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>

#include "dns.h"
#include "dnssec.h"
#include "wire.h"

const char *
dnssec_validation_state_str(enum dnssec_validation_state state)
{
	switch (state) {
	case DNSSEC_VALIDATION_SECURE:
		return "secure";
	case DNSSEC_VALIDATION_INSECURE:
		return "insecure";
	case DNSSEC_VALIDATION_BOGUS:
		return "bogus";
	case DNSSEC_VALIDATION_INDETERMINATE:
		return "indeterminate";
	case DNSSEC_VALIDATION_UNCHECKED:
		return "unchecked";
	}
	return "unknown";
}

int
dnssec_canonical_name_from_text(const char *name, uint8_t *out,
                                size_t out_size, size_t *out_len)
{
	if (name == NULL || out == NULL || out_len == NULL || out_size == 0)
		return DNSSEC_ERR_MALFORMED;

	if (name[0] == '\0' || (name[0] == '.' && name[1] == '\0')) {
		out[0]   = 0;
		*out_len = 1;
		return DNSSEC_OK;
	}

	size_t      pos   = 0;
	const char *label = name;
	while (*label != '\0') {
		const char *dot = strchr(label, '.');
		size_t      len = dot != NULL ? (size_t)(dot - label) : strlen(label);

		if (len == 0 || len > DNS_MAX_LABEL_LEN)
			return DNSSEC_ERR_MALFORMED;
		if (pos + 1 + len >= DNS_MAX_NAME_LEN)
			return DNSSEC_ERR_MALFORMED;
		if (pos + 1 + len + 1 > out_size)
			return DNSSEC_ERR_NOBUFS;

		out[pos++] = (uint8_t)len;
		for (size_t i = 0; i < len; i++)
			out[pos++] = (uint8_t)tolower((unsigned char)label[i]);

		if (dot == NULL)
			break;
		label = dot + 1;
		if (*label == '\0')
			break;
	}

	if (pos + 1 > out_size)
		return DNSSEC_ERR_NOBUFS;
	out[pos++] = 0;
	if (pos > DNS_MAX_NAME_LEN)
		return DNSSEC_ERR_MALFORMED;

	*out_len = pos;
	return DNSSEC_OK;
}

int
dnssec_canonical_name_from_wire(const uint8_t *msg, size_t msg_len,
                                size_t offset, uint8_t *out,
                                size_t out_size, size_t *out_len,
                                size_t *bytes_consumed)
{
	size_t pos        = offset;
	size_t out_pos    = 0;
	size_t consumed   = 0;
	bool   jumped     = false;
	bool   terminated = false;
	int    jumps      = 0;

	if (msg == NULL || out == NULL || out_len == NULL || out_size == 0 || offset >= msg_len)
		return DNSSEC_ERR_MALFORMED;

	while (pos < msg_len) {
		uint8_t len = msg[pos];

		if (len == 0) {
			if (!jumped)
				consumed = pos - offset + 1;
			if (out_pos + 1 > out_size)
				return DNSSEC_ERR_NOBUFS;
			out[out_pos++] = 0;
			terminated     = true;
			break;
		}

		if ((len & 0xC0) == 0xC0) {
			if (pos + 1 >= msg_len || ++jumps > WIRE_NAME_MAX_HOPS)
				return DNSSEC_ERR_MALFORMED;
			if (!jumped)
				consumed = pos - offset + 2;
			uint16_t ptr = (uint16_t)(((uint16_t)(len & 0x3F) << 8)
			                          | msg[pos + 1]);
			if (ptr >= msg_len)
				return DNSSEC_ERR_MALFORMED;
			pos    = ptr;
			jumped = true;
			continue;
		}

		if ((len & 0xC0) != 0 || len > DNS_MAX_LABEL_LEN)
			return DNSSEC_ERR_MALFORMED;

		pos++;
		if (pos + len > msg_len)
			return DNSSEC_ERR_MALFORMED;
		if (out_pos + 1 + len >= DNS_MAX_NAME_LEN)
			return DNSSEC_ERR_MALFORMED;
		if (out_pos + 1 + len + 1 > out_size)
			return DNSSEC_ERR_NOBUFS;

		out[out_pos++] = len;
		for (uint8_t i = 0; i < len; i++)
			out[out_pos++] = (uint8_t)tolower((unsigned char)msg[pos + i]);
		pos += len;
	}

	if (!terminated)
		return DNSSEC_ERR_MALFORMED;

	*out_len = out_pos;
	if (bytes_consumed != NULL)
		*bytes_consumed = consumed;
	return DNSSEC_OK;
}

bool
dnssec_canonical_name_equal(const uint8_t *a, size_t a_len,
                            const uint8_t *b, size_t b_len)
{
	if (a == NULL || b == NULL)
		return false;
	return a_len == b_len && memcmp(a, b, a_len) == 0;
}

int
dnssec_parse_canonical_rr(const uint8_t *msg, size_t msg_len, size_t offset,
                          struct dnssec_canonical_rr *out,
                          size_t                     *rr_wire_len)
{
	size_t owner_consumed = 0;
	size_t pos            = 0;
	size_t rdata_pos      = 0;

	if (msg == NULL || out == NULL)
		return DNSSEC_ERR_MALFORMED;

	memset(out, 0, sizeof(*out));

	int rc = dnssec_canonical_name_from_wire(msg, msg_len, offset,
	                                         out->owner,
	                                         sizeof(out->owner),
	                                         &out->owner_len,
	                                         &owner_consumed);
	if (rc != DNSSEC_OK)
		return rc;

	pos = offset + owner_consumed;
	if (pos + 10 > msg_len)
		return DNSSEC_ERR_MALFORMED;

	out->type      = wire_read_u16(msg + pos);
	out->rrclass   = wire_read_u16(msg + pos + 2);
	out->ttl       = wire_read_u32(msg + pos + 4);
	out->rdata_len = wire_read_u16(msg + pos + 8);
	rdata_pos      = pos + 10;
	if (out->rdata_len > msg_len - rdata_pos)
		return DNSSEC_ERR_MALFORMED;

	out->rdata = msg + rdata_pos;
	if (rr_wire_len != NULL)
		*rr_wire_len = rdata_pos + out->rdata_len - offset;

	return DNSSEC_OK;
}

bool
dnssec_canonical_rr_same_rrset(const struct dnssec_canonical_rr *a,
                               const struct dnssec_canonical_rr *b)
{
	if (a == NULL || b == NULL)
		return false;
	return a->type == b->type
	       && a->rrclass == b->rrclass
	       && dnssec_canonical_name_equal(a->owner, a->owner_len,
	                                      b->owner, b->owner_len);
}

int
dnssec_parse_ds(const uint8_t *rdata, size_t rdlen, struct dnssec_ds *out)
{
	if (rdata == NULL || out == NULL || rdlen < 4)
		return DNSSEC_ERR_MALFORMED;

	out->key_tag     = wire_read_u16(rdata);
	out->algorithm   = rdata[2];
	out->digest_type = rdata[3];
	out->digest      = rdata + 4;
	out->digest_len  = rdlen - 4;
	if (out->digest_len == 0 || out->digest_len > DNSSEC_MAX_DS_DIGEST_LEN)
		return DNSSEC_ERR_MALFORMED;

	return DNSSEC_OK;
}

int
dnssec_parse_dnskey(const uint8_t *rdata, size_t rdlen,
                    struct dnssec_dnskey *out)
{
	if (rdata == NULL || out == NULL || rdlen < 4)
		return DNSSEC_ERR_MALFORMED;

	out->flags          = wire_read_u16(rdata);
	out->protocol       = rdata[2];
	out->algorithm      = rdata[3];
	out->public_key     = rdata + 4;
	out->public_key_len = rdlen - 4;
	if (out->public_key_len == 0)
		return DNSSEC_ERR_MALFORMED;

	return DNSSEC_OK;
}

bool
dnssec_type_bitmap_is_well_formed(const uint8_t *type_bit_maps,
                                  size_t         type_bit_maps_len)
{
	size_t pos         = 0;
	int    last_window = -1;

	if (type_bit_maps == NULL || type_bit_maps_len == 0)
		return false;

	while (pos < type_bit_maps_len) {
		if (type_bit_maps_len - pos < 2)
			return false;

		uint8_t window = type_bit_maps[pos++];
		uint8_t len    = type_bit_maps[pos++];
		if (len == 0 || len > 32)
			return false;
		if ((int)window <= last_window)
			return false;
		if (type_bit_maps_len - pos < len)
			return false;

		pos         += len;
		last_window  = window;
	}

	return true;
}

int
dnssec_parse_rrsig(const uint8_t *rdata, size_t rdlen,
                   struct dnssec_rrsig *out)
{
	if (rdata == NULL || out == NULL || rdlen < 19)
		return DNSSEC_ERR_MALFORMED;

	memset(out, 0, sizeof(*out));
	out->type_covered         = wire_read_u16(rdata);
	out->algorithm            = rdata[2];
	out->labels               = rdata[3];
	out->original_ttl         = wire_read_u32(rdata + 4);
	out->signature_expiration = wire_read_u32(rdata + 8);
	out->signature_inception  = wire_read_u32(rdata + 12);
	out->key_tag              = wire_read_u16(rdata + 16);

	size_t signer_len         = 0;
	if (dns_parse_name(rdata, rdlen, 18, out->signer_name,
	                   sizeof(out->signer_name), &signer_len)
	    < 0)
		return DNSSEC_ERR_MALFORMED;

	size_t sig_pos = 18 + signer_len;
	if (sig_pos >= rdlen)
		return DNSSEC_ERR_MALFORMED;

	out->signature     = rdata + sig_pos;
	out->signature_len = rdlen - sig_pos;
	return DNSSEC_OK;
}

int
dnssec_parse_nsec(const uint8_t *rdata, size_t rdlen,
                  struct dnssec_nsec *out)
{
	if (rdata == NULL || out == NULL || rdlen < 3)
		return DNSSEC_ERR_MALFORMED;

	memset(out, 0, sizeof(*out));

	size_t next_len = 0;
	if (dns_parse_name(rdata, rdlen, 0, out->next_domain_name,
	                   sizeof(out->next_domain_name), &next_len)
	    < 0)
		return DNSSEC_ERR_MALFORMED;
	if (next_len >= rdlen)
		return DNSSEC_ERR_MALFORMED;

	out->type_bit_maps     = rdata + next_len;
	out->type_bit_maps_len = rdlen - next_len;
	if (!dnssec_type_bitmap_is_well_formed(out->type_bit_maps,
	                                       out->type_bit_maps_len))
		return DNSSEC_ERR_MALFORMED;

	return DNSSEC_OK;
}

int
dnssec_parse_nsec3(const uint8_t *rdata, size_t rdlen,
                   struct dnssec_nsec3 *out)
{
	if (rdata == NULL || out == NULL || rdlen < 6)
		return DNSSEC_ERR_MALFORMED;

	memset(out, 0, sizeof(*out));
	out->hash_algorithm = rdata[0];
	out->flags          = rdata[1];
	out->iterations     = wire_read_u16(rdata + 2);
	out->salt_len       = rdata[4];

	size_t pos          = 5;
	if (rdlen - pos < out->salt_len)
		return DNSSEC_ERR_MALFORMED;
	out->salt  = rdata + pos;
	pos       += out->salt_len;
	if (pos >= rdlen)
		return DNSSEC_ERR_MALFORMED;

	out->next_hashed_owner_len = rdata[pos++];
	if (out->next_hashed_owner_len == 0
	    || rdlen - pos < out->next_hashed_owner_len)
		return DNSSEC_ERR_MALFORMED;
	out->next_hashed_owner  = rdata + pos;
	pos                    += out->next_hashed_owner_len;
	if (pos >= rdlen)
		return DNSSEC_ERR_MALFORMED;

	out->type_bit_maps     = rdata + pos;
	out->type_bit_maps_len = rdlen - pos;
	if (!dnssec_type_bitmap_is_well_formed(out->type_bit_maps,
	                                       out->type_bit_maps_len))
		return DNSSEC_ERR_MALFORMED;

	return DNSSEC_OK;
}

int
dnssec_parse_tlsa(const uint8_t *rdata, size_t rdlen,
                  struct dnssec_tlsa *out)
{
	if (rdata == NULL || out == NULL || rdlen < 4)
		return DNSSEC_ERR_MALFORMED;

	memset(out, 0, sizeof(*out));
	out->certificate_usage    = rdata[0];
	out->selector             = rdata[1];
	out->matching_type        = rdata[2];
	out->association_data     = rdata + 3;
	out->association_data_len = rdlen - 3;

	if (out->certificate_usage > DNSSEC_TLSA_USAGE_DANE_EE
	    || out->selector > DNSSEC_TLSA_SELECTOR_SPKI
	    || out->matching_type > DNSSEC_TLSA_MATCHING_SHA512)
		return DNSSEC_ERR_UNSUPPORTED;

	switch (out->matching_type) {
	case DNSSEC_TLSA_MATCHING_FULL:
		if (out->association_data_len == 0)
			return DNSSEC_ERR_MALFORMED;
		break;
	case DNSSEC_TLSA_MATCHING_SHA256:
		if (out->association_data_len != 32)
			return DNSSEC_ERR_MALFORMED;
		break;
	case DNSSEC_TLSA_MATCHING_SHA512:
		if (out->association_data_len != 64)
			return DNSSEC_ERR_MALFORMED;
		break;
	default:
		return DNSSEC_ERR_UNSUPPORTED;
	}

	return DNSSEC_OK;
}

bool
dnssec_type_bitmap_has_type(const uint8_t *type_bit_maps,
                            size_t type_bit_maps_len, uint16_t type)
{
	if (!dnssec_type_bitmap_is_well_formed(type_bit_maps,
	                                       type_bit_maps_len))
		return false;

	uint8_t want_window = (uint8_t)(type >> 8);
	uint8_t want_offset = (uint8_t)(type & 0xFF);
	size_t  pos         = 0;

	while (pos < type_bit_maps_len) {
		uint8_t window = type_bit_maps[pos++];
		uint8_t len    = type_bit_maps[pos++];

		if (window == want_window) {
			size_t byte = want_offset / 8;
			if (byte >= len)
				return false;
			return (type_bit_maps[pos + byte]
			        & (uint8_t)(0x80u >> (want_offset % 8)))
			       != 0;
		}

		pos += len;
	}

	return false;
}

uint16_t
dnssec_dnskey_key_tag(const uint8_t *dnskey_rdata, size_t dnskey_rdata_len)
{
	uint32_t acc = 0;

	if (dnskey_rdata == NULL)
		return 0;

	for (size_t i = 0; i < dnskey_rdata_len; i++)
		acc += (i & 1) ? dnskey_rdata[i] : (uint32_t)dnskey_rdata[i] << 8;

	acc += (acc >> 16) & 0xFFFFu;
	return (uint16_t)(acc & 0xFFFFu);
}

static const EVP_MD *
ds_digest_md(uint8_t digest_type)
{
	switch (digest_type) {
	case DNSSEC_DS_DIGEST_SHA256:
		return EVP_sha256();
	case DNSSEC_DS_DIGEST_SHA384:
		return EVP_sha384();
	default:
		return NULL;
	}
}

int
dnssec_dnskey_ds_digest(const char    *owner_name,
                        const uint8_t *dnskey_rdata,
                        size_t         dnskey_rdata_len,
                        uint8_t        digest_type,
                        uint8_t *digest, size_t digest_size,
                        size_t *digest_len)
{
	uint8_t owner_wire[DNS_MAX_NAME_LEN + 1];
	size_t  owner_wire_len = 0;

	if (dnskey_rdata == NULL || dnskey_rdata_len < 4 || digest == NULL || digest_len == NULL)
		return DNSSEC_ERR_MALFORMED;

	int rc = dnssec_canonical_name_from_text(owner_name, owner_wire,
	                                         sizeof(owner_wire),
	                                         &owner_wire_len);
	if (rc != DNSSEC_OK)
		return rc;

	const EVP_MD *md = ds_digest_md(digest_type);
	if (md == NULL)
		return DNSSEC_ERR_UNSUPPORTED;

	int md_size = EVP_MD_get_size(md);
	if (md_size <= 0)
		return DNSSEC_ERR_UNSUPPORTED;
	if (digest_size < (size_t)md_size)
		return DNSSEC_ERR_NOBUFS;

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
		return DNSSEC_ERR_MALFORMED;

	unsigned int out_len = 0;
	bool         ok      = EVP_DigestInit_ex(ctx, md, NULL) == 1
	                       && EVP_DigestUpdate(ctx, owner_wire,
	                                           owner_wire_len)
	                                  == 1
	                       && EVP_DigestUpdate(ctx, dnskey_rdata,
	                                           dnskey_rdata_len)
	                                  == 1
	                       && EVP_DigestFinal_ex(ctx, digest, &out_len)
	                                  == 1;
	EVP_MD_CTX_free(ctx);
	if (!ok)
		return DNSSEC_ERR_MALFORMED;

	*digest_len = out_len;
	return DNSSEC_OK;
}

int
dnssec_ds_matches_dnskey(const char                 *owner_name,
                         const struct dnssec_ds     *ds,
                         const struct dnssec_dnskey *dnskey,
                         const uint8_t              *dnskey_rdata,
                         size_t                      dnskey_rdata_len,
                         bool                       *matches)
{
	uint8_t digest[DNSSEC_MAX_DS_DIGEST_LEN];
	size_t  digest_len = 0;

	if (ds == NULL || dnskey == NULL || dnskey_rdata == NULL || matches == NULL)
		return DNSSEC_ERR_MALFORMED;

	*matches = false;

	if (dnskey->protocol != 3
	    || ds->algorithm != dnskey->algorithm
	    || ds->key_tag != dnssec_dnskey_key_tag(dnskey_rdata, dnskey_rdata_len))
		return DNSSEC_OK;

	int rc = dnssec_dnskey_ds_digest(owner_name, dnskey_rdata,
	                                 dnskey_rdata_len,
	                                 ds->digest_type,
	                                 digest, sizeof(digest),
	                                 &digest_len);
	if (rc != DNSSEC_OK)
		return rc;

	*matches = digest_len == ds->digest_len
	           && memcmp(digest, ds->digest, digest_len) == 0;
	return DNSSEC_OK;
}

int
dnssec_dane_tlsa_precheck(enum dnssec_validation_state  dnssec_state,
                          bool                          has_tlsa_rrset,
                          enum dnssec_validation_state *dane_state)
{
	if (dane_state == NULL)
		return DNSSEC_ERR_MALFORMED;

	if (!has_tlsa_rrset) {
		*dane_state = DNSSEC_VALIDATION_INDETERMINATE;
		return DNSSEC_OK;
	}

	switch (dnssec_state) {
	case DNSSEC_VALIDATION_SECURE:
		*dane_state = DNSSEC_VALIDATION_SECURE;
		break;
	case DNSSEC_VALIDATION_BOGUS:
		*dane_state = DNSSEC_VALIDATION_BOGUS;
		break;
	case DNSSEC_VALIDATION_INDETERMINATE:
		*dane_state = DNSSEC_VALIDATION_INDETERMINATE;
		break;
	case DNSSEC_VALIDATION_INSECURE:
	case DNSSEC_VALIDATION_UNCHECKED:
		*dane_state = DNSSEC_VALIDATION_INSECURE;
		break;
	default:
		*dane_state = DNSSEC_VALIDATION_INDETERMINATE;
		break;
	}

	return DNSSEC_OK;
}

static int
skip_questions(const uint8_t *msg, size_t len, uint16_t qdcount,
               size_t *pos_out)
{
	size_t pos = DNS_HEADER_SIZE;

	for (uint16_t i = 0; i < qdcount; i++) {
		int n = wire_skip_name(msg, len, pos);
		if (n < 0)
			return DNSSEC_ERR_MALFORMED;
		pos += (size_t)n;
		if (pos + 4 > len)
			return DNSSEC_ERR_MALFORMED;
		pos += 4;
	}

	*pos_out = pos;
	return DNSSEC_OK;
}

static int
parse_dnssec_rdata(uint16_t type, const uint8_t *rdata, size_t rdlen)
{
	switch (type) {
	case DNS_TYPE_DS: {
		struct dnssec_ds ds;
		return dnssec_parse_ds(rdata, rdlen, &ds);
	}
	case DNS_TYPE_DNSKEY: {
		struct dnssec_dnskey dnskey;
		return dnssec_parse_dnskey(rdata, rdlen, &dnskey);
	}
	case DNS_TYPE_RRSIG: {
		struct dnssec_rrsig rrsig;
		return dnssec_parse_rrsig(rdata, rdlen, &rrsig);
	}
	case DNS_TYPE_NSEC: {
		struct dnssec_nsec nsec;
		return dnssec_parse_nsec(rdata, rdlen, &nsec);
	}
	case DNS_TYPE_NSEC3: {
		struct dnssec_nsec3 nsec3;
		return dnssec_parse_nsec3(rdata, rdlen, &nsec3);
	}
	default:
		return DNSSEC_OK;
	}
}

static bool
is_dnssec_type(uint16_t type)
{
	return type == DNS_TYPE_DS
	       || type == DNS_TYPE_DNSKEY
	       || type == DNS_TYPE_RRSIG
	       || type == DNS_TYPE_NSEC
	       || type == DNS_TYPE_NSEC3;
}

int
dnssec_analyze_message(const uint8_t *msg, size_t len,
                       struct dnssec_validation_result *result)
{
	if (result == NULL)
		return DNSSEC_ERR_MALFORMED;

	memset(result, 0, sizeof(*result));
	result->state = DNSSEC_VALIDATION_UNCHECKED;

	if (msg == NULL || len < DNS_HEADER_SIZE) {
		result->state = DNSSEC_VALIDATION_BOGUS;
		return DNSSEC_ERR_MALFORMED;
	}

	uint16_t qdcount   = wire_read_u16(msg + 4);
	uint16_t counts[3] = {
		wire_read_u16(msg + 6),
		wire_read_u16(msg + 8),
		wire_read_u16(msg + 10),
	};

	size_t pos = DNS_HEADER_SIZE;
	if (skip_questions(msg, len, qdcount, &pos) != DNSSEC_OK) {
		result->state = DNSSEC_VALIDATION_BOGUS;
		return DNSSEC_ERR_MALFORMED;
	}

	for (size_t section = 0; section < 3; section++) {
		for (uint16_t i = 0; i < counts[section]; i++) {
			int n = wire_skip_name(msg, len, pos);
			if (n < 0) {
				result->state = DNSSEC_VALIDATION_BOGUS;
				return DNSSEC_ERR_MALFORMED;
			}
			pos += (size_t)n;
			if (pos + 10 > len) {
				result->state = DNSSEC_VALIDATION_BOGUS;
				return DNSSEC_ERR_MALFORMED;
			}

			uint16_t type      = wire_read_u16(msg + pos);
			uint16_t rdlen     = wire_read_u16(msg + pos + 8);
			size_t   rdata_pos = pos + 10;
			size_t   next_pos  = rdata_pos + rdlen;
			if (next_pos > len) {
				result->state = DNSSEC_VALIDATION_BOGUS;
				return DNSSEC_ERR_MALFORMED;
			}

			if (is_dnssec_type(type)) {
				result->dnssec_records++;
				if (parse_dnssec_rdata(type, msg + rdata_pos,
				                       rdlen)
				    != DNSSEC_OK)
					result->malformed_dnssec_records++;
			}

			pos = next_pos;
		}
	}

	if (pos != len) {
		result->state = DNSSEC_VALIDATION_BOGUS;
		return DNSSEC_ERR_MALFORMED;
	}

	if (result->malformed_dnssec_records != 0)
		result->state = DNSSEC_VALIDATION_BOGUS;
	else if (result->dnssec_records != 0)
		result->state = DNSSEC_VALIDATION_INDETERMINATE;
	else
		result->state = DNSSEC_VALIDATION_UNCHECKED;

	return DNSSEC_OK;
}
