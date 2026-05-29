/* SPDX-License-Identifier: MIT */

#ifndef DNSKA_DNSSEC_H
#define DNSKA_DNSSEC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dns.h"

/*
 * DNSSEC validation plan:
 *
 * 1. Current slice: parse DNSSEC metadata, expose canonical owner/RR
 *    helper views, compute DNSKEY key tags, verify DS SHA-256/SHA-384
 *    digests against DNSKEY RDATA, parse TLSA, and expose a
 *    response-analysis state plus DANE DNSSEC-state prechecks.  This does
 *    not validate RRset signatures or prove denial of existence.
 * 2. Chain validation: build canonical RRsets from a response plus
 *    fetched DNSKEY/DS material, verify RRSIG inception/expiration and
 *    signature algorithms, then walk trust anchors from root to qname.
 * 3. Insecure delegations: prove missing DS with signed parent-side
 *    NSEC/NSEC3 denial and return insecure only for validated opt-outs
 *    or unsigned islands beneath an authenticated denial.
 * 4. Aggressive negative cache: store validated NSEC/NSEC3 proofs with
 *    their covering names, type bit maps, closest-encloser data, and TTLs
 *    so NXDOMAIN/NODATA can be synthesized safely.
 * 5. DANE/TLSA: after full chain validation exists, connect the TLSA
 *    precheck and parser to a certificate verifier that accepts only secure
 *    TLSA RRsets for validated TLSA owner names.
 */

enum dnssec_validation_state {
	DNSSEC_VALIDATION_SECURE,
	DNSSEC_VALIDATION_INSECURE,
	DNSSEC_VALIDATION_BOGUS,
	DNSSEC_VALIDATION_INDETERMINATE,
	DNSSEC_VALIDATION_UNCHECKED,
};

enum dnssec_status {
	DNSSEC_OK              = 0,
	DNSSEC_ERR_MALFORMED   = -1,
	DNSSEC_ERR_UNSUPPORTED = -2,
	DNSSEC_ERR_NOBUFS      = -3,
};

enum dnssec_algorithm {
	DNSSEC_ALGORITHM_RSASHA256       = 8,
	DNSSEC_ALGORITHM_ECDSAP256SHA256 = 13,
	DNSSEC_ALGORITHM_ED25519         = 15,
};

enum dnssec_ds_digest_type {
	DNSSEC_DS_DIGEST_SHA1   = 1,
	DNSSEC_DS_DIGEST_SHA256 = 2,
	DNSSEC_DS_DIGEST_SHA384 = 4,
};

enum dnssec_tlsa_certificate_usage {
	DNSSEC_TLSA_USAGE_PKIX_TA = 0,
	DNSSEC_TLSA_USAGE_PKIX_EE = 1,
	DNSSEC_TLSA_USAGE_DANE_TA = 2,
	DNSSEC_TLSA_USAGE_DANE_EE = 3,
};

enum dnssec_tlsa_selector {
	DNSSEC_TLSA_SELECTOR_CERT = 0,
	DNSSEC_TLSA_SELECTOR_SPKI = 1,
};

enum dnssec_tlsa_matching_type {
	DNSSEC_TLSA_MATCHING_FULL   = 0,
	DNSSEC_TLSA_MATCHING_SHA256 = 1,
	DNSSEC_TLSA_MATCHING_SHA512 = 2,
};

enum {
	DNSSEC_MAX_DS_DIGEST_LEN = 64,
};

struct dnssec_canonical_rr {
	uint8_t        owner[DNS_MAX_NAME_LEN + 1];
	size_t         owner_len;
	uint16_t       type;
	uint16_t       rrclass;
	uint32_t       ttl;
	const uint8_t *rdata;
	size_t         rdata_len;
};

struct dnssec_ds {
	uint16_t       key_tag;
	uint8_t        algorithm;
	uint8_t        digest_type;
	const uint8_t *digest;
	size_t         digest_len;
};

struct dnssec_dnskey {
	uint16_t       flags;
	uint8_t        protocol;
	uint8_t        algorithm;
	const uint8_t *public_key;
	size_t         public_key_len;
};

struct dnssec_rrsig {
	uint16_t       type_covered;
	uint8_t        algorithm;
	uint8_t        labels;
	uint32_t       original_ttl;
	uint32_t       signature_expiration;
	uint32_t       signature_inception;
	uint16_t       key_tag;
	char           signer_name[DNS_MAX_NAME_LEN + 1];
	const uint8_t *signature;
	size_t         signature_len;
};

struct dnssec_nsec {
	char           next_domain_name[DNS_MAX_NAME_LEN + 1];
	const uint8_t *type_bit_maps;
	size_t         type_bit_maps_len;
};

struct dnssec_nsec3 {
	uint8_t        hash_algorithm;
	uint8_t        flags;
	uint16_t       iterations;
	const uint8_t *salt;
	uint8_t        salt_len;
	const uint8_t *next_hashed_owner;
	uint8_t        next_hashed_owner_len;
	const uint8_t *type_bit_maps;
	size_t         type_bit_maps_len;
};

struct dnssec_tlsa {
	uint8_t        certificate_usage;
	uint8_t        selector;
	uint8_t        matching_type;
	const uint8_t *association_data;
	size_t         association_data_len;
};

struct dnssec_validation_result {
	enum dnssec_validation_state state;
	unsigned                     dnssec_records;
	unsigned                     malformed_dnssec_records;
};

const char *
dnssec_validation_state_str(enum dnssec_validation_state state);

int
dnssec_canonical_name_from_text(const char *name, uint8_t *out,
                                size_t out_size, size_t *out_len);
int
dnssec_canonical_name_from_wire(const uint8_t *msg, size_t msg_len,
                                size_t offset, uint8_t *out,
                                size_t out_size, size_t *out_len,
                                size_t *bytes_consumed);
bool
dnssec_canonical_name_equal(const uint8_t *a, size_t a_len,
                            const uint8_t *b, size_t b_len);
int
dnssec_parse_canonical_rr(const uint8_t *msg, size_t msg_len, size_t offset,
                          struct dnssec_canonical_rr *out,
                          size_t                     *rr_wire_len);
bool
dnssec_canonical_rr_same_rrset(const struct dnssec_canonical_rr *a,
                               const struct dnssec_canonical_rr *b);

int
dnssec_parse_ds(const uint8_t *rdata, size_t rdlen, struct dnssec_ds *out);
int
dnssec_parse_dnskey(const uint8_t *rdata, size_t rdlen,
                    struct dnssec_dnskey *out);
int
dnssec_parse_rrsig(const uint8_t *rdata, size_t rdlen,
                   struct dnssec_rrsig *out);
int
dnssec_parse_nsec(const uint8_t *rdata, size_t rdlen,
                  struct dnssec_nsec *out);
int
dnssec_parse_nsec3(const uint8_t *rdata, size_t rdlen,
                   struct dnssec_nsec3 *out);
int
dnssec_parse_tlsa(const uint8_t *rdata, size_t rdlen,
                  struct dnssec_tlsa *out);

bool
dnssec_type_bitmap_is_well_formed(const uint8_t *type_bit_maps,
                                  size_t         type_bit_maps_len);

bool
dnssec_type_bitmap_has_type(const uint8_t *type_bit_maps,
                            size_t type_bit_maps_len, uint16_t type);

uint16_t
dnssec_dnskey_key_tag(const uint8_t *dnskey_rdata, size_t dnskey_rdata_len);

int
dnssec_dnskey_ds_digest(const char    *owner_name,
                        const uint8_t *dnskey_rdata,
                        size_t         dnskey_rdata_len,
                        uint8_t        digest_type,
                        uint8_t *digest, size_t digest_size,
                        size_t *digest_len);

int
dnssec_ds_matches_dnskey(const char                 *owner_name,
                         const struct dnssec_ds     *ds,
                         const struct dnssec_dnskey *dnskey,
                         const uint8_t              *dnskey_rdata,
                         size_t                      dnskey_rdata_len,
                         bool                       *matches);

int
dnssec_dane_tlsa_precheck(enum dnssec_validation_state  dnssec_state,
                          bool                          has_tlsa_rrset,
                          enum dnssec_validation_state *dane_state);

int
dnssec_analyze_message(const uint8_t *msg, size_t len,
                       struct dnssec_validation_result *result);

#endif /* DNSKA_DNSSEC_H */
