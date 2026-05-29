/* SPDX-License-Identifier: MIT */

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

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

static bool
dnssec_time_lte(uint32_t a, uint32_t b)
{
	return a == b || (uint32_t)(b - a) < 0x80000000u;
}

static bool
dnssec_time_in_rrsig_window(uint32_t now, const struct dnssec_rrsig *rrsig)
{
	return dnssec_time_lte(rrsig->signature_inception, now)
	       && dnssec_time_lte(now, rrsig->signature_expiration);
}

static bool
rrsig_algorithm_supported(uint8_t algorithm)
{
	return algorithm == DNSSEC_ALGORITHM_RSASHA256
	       || algorithm == DNSSEC_ALGORITHM_ECDSAP256SHA256
	       || algorithm == DNSSEC_ALGORITHM_ED25519;
}

static bool
rrsig_type_has_opaque_rdata(uint16_t type)
{
	switch (type) {
	case DNS_TYPE_A:
	case DNS_TYPE_AAAA:
	case DNS_TYPE_TXT:
	case DNS_TYPE_SSHFP:
	case DNS_TYPE_DS:
	case DNS_TYPE_DNSKEY:
	case DNS_TYPE_NSEC3:
	case DNS_TYPE_TLSA:
	case DNS_TYPE_CDS:
	case DNS_TYPE_CDNSKEY:
	case DNS_TYPE_ZONEMD:
	case DNS_TYPE_CAA:
		return true;
	default:
		return false;
	}
}

static int
validate_opaque_rdata_rr(const struct dnssec_canonical_rr *rr)
{
	if (rr->rdata == NULL && rr->rdata_len != 0)
		return DNSSEC_ERR_MALFORMED;

	switch (rr->type) {
	case DNS_TYPE_A:
		return rr->rdata_len == 4 ? DNSSEC_OK : DNSSEC_ERR_MALFORMED;
	case DNS_TYPE_AAAA:
		return rr->rdata_len == 16 ? DNSSEC_OK : DNSSEC_ERR_MALFORMED;
	case DNS_TYPE_DS:
	case DNS_TYPE_CDS: {
		struct dnssec_ds ds;
		return dnssec_parse_ds(rr->rdata, rr->rdata_len, &ds);
	}
	case DNS_TYPE_DNSKEY:
	case DNS_TYPE_CDNSKEY: {
		struct dnssec_dnskey dnskey;
		return dnssec_parse_dnskey(rr->rdata, rr->rdata_len,
		                           &dnskey);
	}
	case DNS_TYPE_NSEC3: {
		struct dnssec_nsec3 nsec3;
		return dnssec_parse_nsec3(rr->rdata, rr->rdata_len, &nsec3);
	}
	default:
		return DNSSEC_OK;
	}
}

static bool
dnskey_matches_rdata(const struct dnssec_dnskey *dnskey,
                     const struct dnssec_dnskey *parsed)
{
	if (dnskey->flags != parsed->flags
	    || dnskey->protocol != parsed->protocol
	    || dnskey->algorithm != parsed->algorithm
	    || dnskey->public_key_len != parsed->public_key_len)
		return false;

	return memcmp(dnskey->public_key, parsed->public_key,
	              dnskey->public_key_len)
	       == 0;
}

static int
canonical_name_label_count(const uint8_t *name, size_t name_len,
                           size_t *labels)
{
	size_t pos   = 0;
	size_t count = 0;

	if (name == NULL || labels == NULL || name_len == 0)
		return DNSSEC_ERR_MALFORMED;

	while (pos < name_len) {
		uint8_t len = name[pos];

		if (len == 0) {
			if (pos + 1 != name_len)
				return DNSSEC_ERR_MALFORMED;
			*labels = count;
			return DNSSEC_OK;
		}

		if ((len & 0xC0) != 0 || len > DNS_MAX_LABEL_LEN)
			return DNSSEC_ERR_MALFORMED;
		if (pos + 1 + len >= name_len)
			return DNSSEC_ERR_MALFORMED;

		pos += 1 + len;
		count++;
	}

	return DNSSEC_ERR_MALFORMED;
}

static int
canonical_name_suffix_for_labels(const uint8_t *name, size_t name_len,
                                 size_t labels, const uint8_t **suffix,
                                 size_t *suffix_len)
{
	size_t total_labels = 0;
	int    rc           = canonical_name_label_count(name, name_len,
	                                                 &total_labels);
	if (rc != DNSSEC_OK)
		return rc;
	if (labels > total_labels)
		return DNSSEC_ERR_MALFORMED;
	if (labels == total_labels) {
		*suffix     = name;
		*suffix_len = name_len;
		return DNSSEC_OK;
	}

	size_t skip = total_labels - labels;
	size_t pos  = 0;
	for (size_t i = 0; i < skip; i++)
		pos += 1 + name[pos];

	*suffix     = name + pos;
	*suffix_len = name_len - pos;
	return DNSSEC_OK;
}

static int
rrsig_rr_owner(const struct dnssec_canonical_rr *rr,
               const struct dnssec_rrsig        *rrsig,
               uint8_t *owner, size_t owner_size, size_t *owner_len)
{
	const uint8_t *suffix          = NULL;
	size_t         suffix_len      = 0;
	size_t         rr_owner_labels = 0;

	int            rc              = canonical_name_label_count(rr->owner, rr->owner_len,
	                                                            &rr_owner_labels);
	if (rc != DNSSEC_OK)
		return rc;
	if (rrsig->labels > rr_owner_labels)
		return DNSSEC_ERR_MALFORMED;

	if (rrsig->labels == rr_owner_labels) {
		if (rr->owner_len > owner_size)
			return DNSSEC_ERR_NOBUFS;
		memcpy(owner, rr->owner, rr->owner_len);
		*owner_len = rr->owner_len;
		return DNSSEC_OK;
	}

	rc = canonical_name_suffix_for_labels(rr->owner, rr->owner_len,
	                                      rrsig->labels, &suffix,
	                                      &suffix_len);
	if (rc != DNSSEC_OK)
		return rc;
	if (2 + suffix_len > owner_size)
		return DNSSEC_ERR_NOBUFS;

	owner[0] = 1;
	owner[1] = '*';
	memcpy(owner + 2, suffix, suffix_len);
	*owner_len = 2 + suffix_len;
	return DNSSEC_OK;
}

static int
rrsig_rr_compare(const struct dnssec_canonical_rr *a,
                 const struct dnssec_canonical_rr *b)
{
	size_t min_len = a->rdata_len < b->rdata_len ? a->rdata_len : b->rdata_len;
	int    cmp     = min_len == 0 ? 0 : memcmp(a->rdata, b->rdata, min_len);

	if (cmp != 0)
		return cmp;
	if (a->rdata_len < b->rdata_len)
		return -1;
	if (a->rdata_len > b->rdata_len)
		return 1;
	return 0;
}

static void
sort_rrsig_rrset_indices(const struct dnssec_canonical_rr *rrset,
                         size_t rr_count, size_t *indices)
{
	for (size_t i = 0; i < rr_count; i++)
		indices[i] = i;

	for (size_t i = 1; i < rr_count; i++) {
		size_t idx = indices[i];
		size_t j   = i;
		while (j > 0
		       && rrsig_rr_compare(&rrset[idx],
		                           &rrset[indices[j - 1]])
		                  < 0) {
			indices[j] = indices[j - 1];
			j--;
		}
		indices[j] = idx;
	}
}

static int
add_len(size_t *total, size_t add)
{
	if (add > SIZE_MAX - *total)
		return DNSSEC_ERR_NOBUFS;
	*total += add;
	return DNSSEC_OK;
}

static int
rrsig_signed_data_len(const struct dnssec_canonical_rr *rrset,
                      size_t rr_count, size_t signer_len,
                      size_t  rr_owner_len,
                      size_t *signed_len)
{
	size_t total = 18;

	if (add_len(&total, signer_len) != DNSSEC_OK)
		return DNSSEC_ERR_NOBUFS;

	for (size_t i = 0; i < rr_count; i++) {
		if (rrset[i].rdata_len > UINT16_MAX)
			return DNSSEC_ERR_MALFORMED;
		if (add_len(&total, rr_owner_len) != DNSSEC_OK
		    || add_len(&total, 10) != DNSSEC_OK
		    || add_len(&total, rrset[i].rdata_len) != DNSSEC_OK)
			return DNSSEC_ERR_NOBUFS;
	}

	if (total > DNSSEC_MAX_RRSIG_SIGNED_DATA_LEN)
		return DNSSEC_ERR_NOBUFS;

	*signed_len = total;
	return DNSSEC_OK;
}

static void
append_rrsig_header(uint8_t *buf, const struct dnssec_rrsig *rrsig,
                    const uint8_t *signer, size_t signer_len)
{
	wire_write_u16(buf, rrsig->type_covered);
	buf[2] = rrsig->algorithm;
	buf[3] = rrsig->labels;
	wire_write_u32(buf + 4, rrsig->original_ttl);
	wire_write_u32(buf + 8, rrsig->signature_expiration);
	wire_write_u32(buf + 12, rrsig->signature_inception);
	wire_write_u16(buf + 16, rrsig->key_tag);
	memcpy(buf + 18, signer, signer_len);
}

static int
build_rrsig_signed_data(const struct dnssec_canonical_rr *rrset,
                        size_t                            rr_count,
                        const struct dnssec_rrsig        *rrsig,
                        uint8_t **signed_data, size_t *signed_len)
{
	uint8_t signer[DNS_MAX_NAME_LEN + 1];
	uint8_t rr_owner[DNS_MAX_NAME_LEN + 1];
	size_t  signer_len   = 0;
	size_t  rr_owner_len = 0;
	size_t  indices[DNSSEC_MAX_RRSIG_RRSET_RRS];
	size_t  total_len = 0;

	int     rc        = dnssec_canonical_name_from_text(rrsig->signer_name, signer,
	                                                    sizeof(signer),
	                                                    &signer_len);
	if (rc != DNSSEC_OK)
		return rc;
	rc = rrsig_rr_owner(&rrset[0], rrsig, rr_owner, sizeof(rr_owner),
	                    &rr_owner_len);
	if (rc != DNSSEC_OK)
		return rc;

	rc = rrsig_signed_data_len(rrset, rr_count, signer_len,
	                           rr_owner_len, &total_len);
	if (rc != DNSSEC_OK)
		return rc;

	uint8_t *data = malloc(total_len);
	if (data == NULL)
		return DNSSEC_ERR_NOBUFS;

	append_rrsig_header(data, rrsig, signer, signer_len);
	size_t pos = 18 + signer_len;

	sort_rrsig_rrset_indices(rrset, rr_count, indices);
	for (size_t i = 0; i < rr_count; i++) {
		const struct dnssec_canonical_rr *rr = &rrset[indices[i]];

		memcpy(data + pos, rr_owner, rr_owner_len);
		pos += rr_owner_len;
		wire_write_u16(data + pos, rr->type);
		wire_write_u16(data + pos + 2, rr->rrclass);
		wire_write_u32(data + pos + 4, rrsig->original_ttl);
		wire_write_u16(data + pos + 8, (uint16_t)rr->rdata_len);
		pos += 10;
		if (rr->rdata_len != 0)
			memcpy(data + pos, rr->rdata, rr->rdata_len);
		pos += rr->rdata_len;
	}

	*signed_data = data;
	*signed_len  = total_len;
	return DNSSEC_OK;
}

static EVP_PKEY *
dnssec_rsa_pkey_from_dnskey(const struct dnssec_dnskey *dnskey)
{
	if (dnskey->public_key_len < 3)
		return NULL;

	size_t   pos          = 0;
	uint16_t exponent_len = dnskey->public_key[pos++];

	if (exponent_len == 0) {
		if (dnskey->public_key_len < 3)
			return NULL;
		exponent_len  = wire_read_u16(dnskey->public_key + pos);
		pos          += 2;
	}

	if (exponent_len == 0
	    || exponent_len > dnskey->public_key_len - pos)
		return NULL;

	const uint8_t *exponent     = dnskey->public_key + pos;
	pos                        += exponent_len;
	const uint8_t *modulus      = dnskey->public_key + pos;
	size_t         modulus_len  = dnskey->public_key_len - pos;
	if (modulus_len == 0)
		return NULL;

	BIGNUM *e = BN_bin2bn(exponent, exponent_len, NULL);
	BIGNUM *n = BN_bin2bn(modulus, modulus_len, NULL);
	if (e == NULL || n == NULL) {
		BN_free(e);
		BN_free(n);
		return NULL;
	}

	OSSL_PARAM_BLD *bld    = OSSL_PARAM_BLD_new();
	EVP_PKEY_CTX   *ctx    = NULL;
	OSSL_PARAM     *params = NULL;
	EVP_PKEY       *pkey   = NULL;
	bool            ok     = bld != NULL;

	if (ok)
		ok = OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E,
		                            e)
		             == 1
		     && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N,
		                               n)
		                == 1;
	if (ok) {
		params = OSSL_PARAM_BLD_to_param(bld);
		ok     = params != NULL;
	}
	if (ok) {
		ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
		ok  = ctx != NULL
		      && EVP_PKEY_fromdata_init(ctx) == 1
		      && EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY,
		                           params)
		                 == 1;
	}

	EVP_PKEY_CTX_free(ctx);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	BN_free(e);
	BN_free(n);
	if (!ok) {
		EVP_PKEY_free(pkey);
		return NULL;
	}
	return pkey;
}

static EVP_PKEY *
dnssec_ecdsa_p256_pkey_from_dnskey(const struct dnssec_dnskey *dnskey)
{
	if (dnskey->public_key_len != 64)
		return NULL;

	uint8_t point[65];
	point[0] = 0x04;
	memcpy(point + 1, dnskey->public_key, dnskey->public_key_len);

	char       group[]  = "prime256v1";
	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
		                                 group, 0),
		OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
		                                  point, sizeof(point)),
		OSSL_PARAM_construct_end(),
	};
	EVP_PKEY_CTX *ctx  = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	EVP_PKEY     *pkey = NULL;
	bool          ok   = ctx != NULL
	                     && EVP_PKEY_fromdata_init(ctx) == 1
	                     && EVP_PKEY_fromdata(ctx, &pkey,
	                                          EVP_PKEY_PUBLIC_KEY,
	                                          params)
	                                == 1;
	EVP_PKEY_CTX_free(ctx);
	if (!ok) {
		EVP_PKEY_free(pkey);
		return NULL;
	}
	return pkey;
}

static EVP_PKEY *
dnssec_ed25519_pkey_from_dnskey(const struct dnssec_dnskey *dnskey)
{
	if (dnskey->public_key_len != 32)
		return NULL;
	return EVP_PKEY_new_raw_public_key_ex(NULL, "ED25519", NULL,
	                                      dnskey->public_key,
	                                      dnskey->public_key_len);
}

static int
ecdsa_p1363_to_der(const uint8_t *sig, size_t sig_len,
                   uint8_t **der, size_t *der_len)
{
	if (sig_len != 64)
		return DNSSEC_ERR_MALFORMED;

	ECDSA_SIG *ecdsa_sig = ECDSA_SIG_new();
	BIGNUM    *r         = BN_bin2bn(sig, 32, NULL);
	BIGNUM    *s         = BN_bin2bn(sig + 32, 32, NULL);
	if (ecdsa_sig == NULL || r == NULL || s == NULL) {
		ECDSA_SIG_free(ecdsa_sig);
		BN_free(r);
		BN_free(s);
		return DNSSEC_ERR_NOBUFS;
	}
	if (ECDSA_SIG_set0(ecdsa_sig, r, s) != 1) {
		ECDSA_SIG_free(ecdsa_sig);
		BN_free(r);
		BN_free(s);
		return DNSSEC_ERR_NOBUFS;
	}
	r               = NULL;
	s               = NULL;

	int encoded_len = i2d_ECDSA_SIG(ecdsa_sig, NULL);
	if (encoded_len <= 0) {
		ECDSA_SIG_free(ecdsa_sig);
		return DNSSEC_ERR_MALFORMED;
	}

	uint8_t *encoded = malloc((size_t)encoded_len);
	if (encoded == NULL) {
		ECDSA_SIG_free(ecdsa_sig);
		return DNSSEC_ERR_NOBUFS;
	}

	uint8_t *p = encoded;
	if (i2d_ECDSA_SIG(ecdsa_sig, &p) != encoded_len) {
		free(encoded);
		ECDSA_SIG_free(ecdsa_sig);
		return DNSSEC_ERR_MALFORMED;
	}

	ECDSA_SIG_free(ecdsa_sig);
	*der     = encoded;
	*der_len = (size_t)encoded_len;
	return DNSSEC_OK;
}

static int
verify_digest_signature(EVP_PKEY *pkey, const EVP_MD *md, bool rsa,
                        const uint8_t *signature, size_t signature_len,
                        const uint8_t *signed_data, size_t signed_len,
                        bool *verified)
{
	EVP_MD_CTX   *ctx      = EVP_MD_CTX_new();
	EVP_PKEY_CTX *pkey_ctx = NULL;

	if (ctx == NULL)
		return DNSSEC_ERR_NOBUFS;

	bool ok = EVP_DigestVerifyInit(ctx, &pkey_ctx, md, NULL, pkey) == 1;
	if (ok && rsa)
		ok = EVP_PKEY_CTX_set_rsa_padding(pkey_ctx,
		                                  RSA_PKCS1_PADDING)
		     == 1;
	if (ok)
		ok = EVP_DigestVerifyUpdate(ctx, signed_data, signed_len) == 1;

	int final_rc = 0;
	if (ok)
		final_rc = EVP_DigestVerifyFinal(ctx, signature,
		                                 signature_len);
	EVP_MD_CTX_free(ctx);

	if (!ok)
		return DNSSEC_ERR_MALFORMED;

	*verified = final_rc == 1;
	return DNSSEC_OK;
}

static int
verify_ed25519_signature(EVP_PKEY *pkey, const uint8_t *signature,
                         size_t         signature_len,
                         const uint8_t *signed_data, size_t signed_len,
                         bool *verified)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
		return DNSSEC_ERR_NOBUFS;

	bool ok = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1;
	int  rc = 0;
	if (ok)
		rc = EVP_DigestVerify(ctx, signature, signature_len,
		                      signed_data, signed_len);
	EVP_MD_CTX_free(ctx);

	if (!ok)
		return DNSSEC_ERR_MALFORMED;

	*verified = rc == 1;
	return DNSSEC_OK;
}

static int
verify_rrsig_crypto(const struct dnssec_rrsig  *rrsig,
                    const struct dnssec_dnskey *dnskey,
                    const uint8_t *signed_data, size_t signed_len,
                    bool *verified)
{
	EVP_PKEY *pkey = NULL;
	int       rc   = DNSSEC_OK;

	switch (rrsig->algorithm) {
	case DNSSEC_ALGORITHM_RSASHA256:
		pkey = dnssec_rsa_pkey_from_dnskey(dnskey);
		if (pkey == NULL)
			return DNSSEC_ERR_MALFORMED;
		rc = verify_digest_signature(pkey, EVP_sha256(), true,
		                             rrsig->signature,
		                             rrsig->signature_len,
		                             signed_data, signed_len,
		                             verified);
		break;
	case DNSSEC_ALGORITHM_ECDSAP256SHA256: {
		uint8_t *der_sig = NULL;
		size_t   der_len = 0;

		pkey             = dnssec_ecdsa_p256_pkey_from_dnskey(dnskey);
		if (pkey == NULL)
			return DNSSEC_ERR_MALFORMED;
		rc = ecdsa_p1363_to_der(rrsig->signature,
		                        rrsig->signature_len, &der_sig,
		                        &der_len);
		if (rc == DNSSEC_OK) {
			rc = verify_digest_signature(pkey, EVP_sha256(), false,
			                             der_sig, der_len,
			                             signed_data, signed_len,
			                             verified);
		}
		free(der_sig);
		break;
	}
	case DNSSEC_ALGORITHM_ED25519:
		pkey = dnssec_ed25519_pkey_from_dnskey(dnskey);
		if (pkey == NULL)
			return DNSSEC_ERR_MALFORMED;
		rc = verify_ed25519_signature(pkey, rrsig->signature,
		                              rrsig->signature_len,
		                              signed_data, signed_len,
		                              verified);
		break;
	default:
		rc = DNSSEC_ERR_UNSUPPORTED;
		break;
	}

	EVP_PKEY_free(pkey);
	return rc;
}

int
dnssec_verify_rrsig(const struct dnssec_canonical_rr *rrset,
                    size_t rr_count, const struct dnssec_rrsig *rrsig,
                    const char                 *dnskey_owner_name,
                    const struct dnssec_dnskey *dnskey,
                    const uint8_t *dnskey_rdata, size_t dnskey_rdata_len,
                    uint32_t validation_time, bool *verified)
{
	uint8_t              signer_name[DNS_MAX_NAME_LEN + 1];
	uint8_t              dnskey_owner[DNS_MAX_NAME_LEN + 1];
	size_t               signer_name_len  = 0;
	size_t               dnskey_owner_len = 0;
	uint8_t             *signed_data      = NULL;
	size_t               signed_len       = 0;
	struct dnssec_dnskey parsed_dnskey;

	if (rrset == NULL || rr_count == 0 || rr_count > DNSSEC_MAX_RRSIG_RRSET_RRS || rrsig == NULL || dnskey_owner_name == NULL || dnskey == NULL || dnskey_rdata == NULL || verified == NULL)
		return DNSSEC_ERR_MALFORMED;

	*verified = false;

	if (!rrsig_algorithm_supported(rrsig->algorithm))
		return DNSSEC_ERR_UNSUPPORTED;
	if (!rrsig_type_has_opaque_rdata(rrsig->type_covered))
		return DNSSEC_ERR_UNSUPPORTED;

	if (dnskey_rdata_len < 4
	    || dnskey->public_key == NULL
	    || dnskey->public_key_len == 0)
		return DNSSEC_ERR_MALFORMED;

	int rc = dnssec_parse_dnskey(dnskey_rdata, dnskey_rdata_len,
	                             &parsed_dnskey);
	if (rc != DNSSEC_OK)
		return rc;
	if (!dnskey_matches_rdata(dnskey, &parsed_dnskey))
		return DNSSEC_ERR_MALFORMED;

	rc = dnssec_canonical_name_from_text(rrsig->signer_name,
	                                     signer_name,
	                                     sizeof(signer_name),
	                                     &signer_name_len);
	if (rc != DNSSEC_OK)
		return rc;
	rc = dnssec_canonical_name_from_text(dnskey_owner_name,
	                                     dnskey_owner,
	                                     sizeof(dnskey_owner),
	                                     &dnskey_owner_len);
	if (rc != DNSSEC_OK)
		return rc;

	if (!dnssec_canonical_name_equal(signer_name, signer_name_len,
	                                 dnskey_owner, dnskey_owner_len))
		return DNSSEC_OK;
	if (!dnssec_time_in_rrsig_window(validation_time, rrsig))
		return DNSSEC_OK;
	if (parsed_dnskey.algorithm != rrsig->algorithm
	    || parsed_dnskey.protocol != 3
	    || rrsig->key_tag != dnssec_dnskey_key_tag(dnskey_rdata, dnskey_rdata_len))
		return DNSSEC_OK;

	for (size_t i = 0; i < rr_count; i++) {
		const struct dnssec_canonical_rr *rr = &rrset[i];

		if (!dnssec_canonical_rr_same_rrset(&rrset[0], rr))
			return DNSSEC_ERR_MALFORMED;
		if (rr->type != rrsig->type_covered)
			return DNSSEC_ERR_MALFORMED;
		if (rr->rdata_len > UINT16_MAX)
			return DNSSEC_ERR_MALFORMED;

		rc = validate_opaque_rdata_rr(rr);
		if (rc != DNSSEC_OK)
			return rc;
	}

	rc = build_rrsig_signed_data(rrset, rr_count, rrsig,
	                             &signed_data, &signed_len);
	if (rc == DNSSEC_OK)
		rc = verify_rrsig_crypto(rrsig, &parsed_dnskey, signed_data,
		                         signed_len, verified);
	free(signed_data);
	return rc;
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
