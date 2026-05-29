/* SPDX-License-Identifier: MIT */

#ifndef DNSKA_ODOH_H
#define DNSKA_ODOH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum odoh_config_constant {
	ODOH_CONFIG_VERSION              = 0x0001,

	ODOH_HPKE_KEM_X25519_HKDF_SHA256 = 0x0020,
	ODOH_HPKE_KDF_HKDF_SHA256        = 0x0001,
	ODOH_HPKE_AEAD_AES_128_GCM       = 0x0001,
};

enum odoh_message_type {
	ODOH_MESSAGE_TYPE_QUERY    = 0x01,
	ODOH_MESSAGE_TYPE_RESPONSE = 0x02,
};

struct odoh_bytes {
	const uint8_t *data;
	size_t         len;
};

struct odoh_config {
	uint16_t          version;
	struct odoh_bytes contents; /* input to RFC 9230 key-id derivation */
	bool              has_odoh_contents;
	uint16_t          kem_id;
	uint16_t          kdf_id;
	uint16_t          aead_id;
	struct odoh_bytes public_key;
};

struct odoh_config_encode_entry {
	uint16_t       version;
	const uint8_t *contents;
	size_t         contents_len;
};

struct odoh_message {
	uint8_t           message_type;
	struct odoh_bytes key_id;
	struct odoh_bytes encrypted_message;
};

struct odoh_plaintext {
	struct odoh_bytes dns_message;
	struct odoh_bytes padding;
};

bool
odoh_message_type_valid(uint8_t message_type);

size_t
odoh_config_contents_encoded_len(size_t public_key_len);
size_t
odoh_config_encoded_len(size_t contents_len);
size_t
odoh_configs_encoded_len(const struct odoh_config_encode_entry *entries,
                         size_t                                 entry_count);
int
odoh_encode_config_contents(uint16_t kem_id, uint16_t kdf_id,
                            uint16_t aead_id, const uint8_t *public_key,
                            size_t public_key_len, uint8_t *out,
                            size_t out_len, size_t *written);
int
odoh_encode_config(uint16_t version, const uint8_t *contents,
                   size_t contents_len, uint8_t *out, size_t out_len,
                   size_t *written);
int
odoh_encode_configs(const struct odoh_config_encode_entry *entries,
                    size_t entry_count, uint8_t *out, size_t out_len,
                    size_t *written);
int
odoh_parse_configs(const uint8_t *buf, size_t len,
                   struct odoh_config *configs, size_t config_cap,
                   size_t *config_count);
int
odoh_config_key_id_input(const struct odoh_config *config,
                         const uint8_t **data, size_t *len);
const struct odoh_config *
odoh_select_config(const struct odoh_config *configs, size_t config_count,
                   uint16_t kem_id, uint16_t kdf_id, uint16_t aead_id);

size_t
odoh_message_encoded_len(size_t key_id_len, size_t encrypted_message_len);
int
odoh_encode_message(uint8_t message_type, const uint8_t *key_id,
                    size_t key_id_len, const uint8_t *encrypted_message,
                    size_t encrypted_message_len, uint8_t *out,
                    size_t out_len, size_t *written);
int
odoh_parse_message(const uint8_t *buf, size_t len,
                   struct odoh_message *message);

size_t
odoh_plaintext_encoded_len(size_t dns_message_len, size_t padding_len);
int
odoh_encode_plaintext(const uint8_t *dns_message, size_t dns_message_len,
                      size_t padding_len, uint8_t *out, size_t out_len,
                      size_t *written);
int
odoh_parse_plaintext(const uint8_t *buf, size_t len,
                     struct odoh_plaintext *plaintext);

#endif /* DNSKA_ODOH_H */
