/* SPDX-License-Identifier: MIT */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "odoh.h"
#include "test.h"

#undef assert
#define assert(expr) TEST_CHECK(expr)

static void
expect_bytes(const uint8_t *actual, const uint8_t *expected, size_t len)
{
	if (len == 0)
		return;
	TEST_CHECK(actual != NULL);
	TEST_CHECK(memcmp(actual, expected, len) == 0);
}

static size_t
make_contents(uint8_t *out, size_t out_len, uint16_t kem_id, uint16_t kdf_id,
              uint16_t aead_id, const uint8_t *public_key,
              size_t public_key_len)
{
	size_t written = 0;

	assert(odoh_encode_config_contents(kem_id, kdf_id, aead_id, public_key,
	                                   public_key_len, out, out_len,
	                                   &written)
	       == 0);
	return written;
}

static size_t
make_configs(const struct odoh_config_encode_entry *entries,
             size_t entry_count, uint8_t *out, size_t out_len)
{
	size_t written = 0;

	assert(odoh_encode_configs(entries, entry_count, out, out_len, &written)
	       == 0);
	return written;
}

static void
test_parse_single_config(void)
{
	static const uint8_t            public_key[] = { 0xa0, 0xa1, 0xa2 };

	uint8_t                         contents[32];
	uint8_t                         vector[64];
	struct odoh_config_encode_entry entry;
	struct odoh_config              configs[1];
	const uint8_t                  *key_id_input = NULL;
	size_t                          contents_len;
	size_t                          vector_len;
	size_t                          key_id_input_len = 0;
	size_t                          count            = 0;

	contents_len                                     = make_contents(contents, sizeof(contents),
	                                                                 ODOH_HPKE_KEM_X25519_HKDF_SHA256,
	                                                                 ODOH_HPKE_KDF_HKDF_SHA256,
	                                                                 ODOH_HPKE_AEAD_AES_128_GCM,
	                                                                 public_key, sizeof(public_key));
	TEST_EXPECT_SIZE_EQ(contents_len, 11);

	entry.version      = ODOH_CONFIG_VERSION;
	entry.contents     = contents;
	entry.contents_len = contents_len;
	vector_len         = make_configs(&entry, 1, vector, sizeof(vector));
	TEST_EXPECT_SIZE_EQ(vector_len, 17);

	assert(odoh_parse_configs(vector, vector_len, NULL, 0, &count) == 0);
	TEST_EXPECT_SIZE_EQ(count, 1);
	assert(odoh_parse_configs(vector, vector_len, configs, 1, &count) == 0);
	TEST_EXPECT_SIZE_EQ(count, 1);
	TEST_EXPECT_INT_EQ(configs[0].version, ODOH_CONFIG_VERSION);
	TEST_CHECK(configs[0].has_odoh_contents);
	TEST_EXPECT_INT_EQ(configs[0].kem_id,
	                   ODOH_HPKE_KEM_X25519_HKDF_SHA256);
	TEST_EXPECT_INT_EQ(configs[0].kdf_id, ODOH_HPKE_KDF_HKDF_SHA256);
	TEST_EXPECT_INT_EQ(configs[0].aead_id, ODOH_HPKE_AEAD_AES_128_GCM);
	TEST_EXPECT_SIZE_EQ(configs[0].public_key.len, sizeof(public_key));
	expect_bytes(configs[0].public_key.data, public_key, sizeof(public_key));

	assert(odoh_config_key_id_input(&configs[0], &key_id_input,
	                                &key_id_input_len)
	       == 0);
	TEST_EXPECT_SIZE_EQ(key_id_input_len, contents_len);
	expect_bytes(key_id_input, contents, contents_len);
	TEST_CHECK(odoh_select_config(configs, count,
	                              ODOH_HPKE_KEM_X25519_HKDF_SHA256,
	                              ODOH_HPKE_KDF_HKDF_SHA256,
	                              ODOH_HPKE_AEAD_AES_128_GCM)
	           == &configs[0]);
}

static void
test_parse_multiple_configs_preserves_order(void)
{
	static const uint8_t            unsupported_contents[] = { 0xff };
	static const uint8_t            public_key[]           = { 1, 2, 3, 4 };
	static const uint8_t            other_public_key[]     = { 5, 6 };

	uint8_t                         contents[32];
	uint8_t                         other_contents[32];
	uint8_t                         vector[128];
	struct odoh_config_encode_entry entries[3];
	struct odoh_config              configs[3];
	const struct odoh_config       *selected;
	size_t                          count = 0;
	size_t                          vector_len;

	entries[0].version      = 0xff06;
	entries[0].contents     = unsupported_contents;
	entries[0].contents_len = sizeof(unsupported_contents);

	entries[1].version      = ODOH_CONFIG_VERSION;
	entries[1].contents_len
	        = make_contents(contents, sizeof(contents),
	                        ODOH_HPKE_KEM_X25519_HKDF_SHA256,
	                        ODOH_HPKE_KDF_HKDF_SHA256,
	                        ODOH_HPKE_AEAD_AES_128_GCM, public_key,
	                        sizeof(public_key));
	entries[1].contents = contents;

	entries[2].version  = ODOH_CONFIG_VERSION;
	entries[2].contents_len
	        = make_contents(other_contents, sizeof(other_contents),
	                        ODOH_HPKE_KEM_X25519_HKDF_SHA256, 0x9999,
	                        ODOH_HPKE_AEAD_AES_128_GCM, other_public_key,
	                        sizeof(other_public_key));
	entries[2].contents = other_contents;

	vector_len          = make_configs(entries, 3, vector, sizeof(vector));
	assert(odoh_parse_configs(vector, vector_len, configs, 3, &count) == 0);
	TEST_EXPECT_SIZE_EQ(count, 3);
	TEST_EXPECT_INT_EQ(configs[0].version, 0xff06);
	TEST_CHECK(!configs[0].has_odoh_contents);
	TEST_CHECK(configs[1].has_odoh_contents);
	TEST_CHECK(configs[2].has_odoh_contents);

	selected = odoh_select_config(configs, count,
	                              ODOH_HPKE_KEM_X25519_HKDF_SHA256,
	                              ODOH_HPKE_KDF_HKDF_SHA256,
	                              ODOH_HPKE_AEAD_AES_128_GCM);
	TEST_CHECK(selected == &configs[1]);
	TEST_CHECK(odoh_select_config(configs, count,
	                              ODOH_HPKE_KEM_X25519_HKDF_SHA256,
	                              0x7777,
	                              ODOH_HPKE_AEAD_AES_128_GCM)
	           == NULL);
}

static void
test_malformed_config_vectors(void)
{
	static const uint8_t            public_key[] = { 0x42 };

	uint8_t                         contents[32];
	uint8_t                         vector[64];
	struct odoh_config_encode_entry entry;
	struct odoh_config              config;
	size_t                          contents_len;
	size_t                          vector_len;
	size_t                          count = 0;

	contents_len                          = make_contents(contents, sizeof(contents),
	                                                      ODOH_HPKE_KEM_X25519_HKDF_SHA256,
	                                                      ODOH_HPKE_KDF_HKDF_SHA256,
	                                                      ODOH_HPKE_AEAD_AES_128_GCM,
	                                                      public_key, sizeof(public_key));
	entry.version                         = ODOH_CONFIG_VERSION;
	entry.contents                        = contents;
	entry.contents_len                    = contents_len;
	vector_len                            = make_configs(&entry, 1, vector, sizeof(vector));

	TEST_CHECK(odoh_parse_configs((const uint8_t[]){ 0, 0 }, 2, &config, 1,
	                              &count)
	           < 0);
	TEST_CHECK(odoh_parse_configs(vector, vector_len - 1, &config, 1, &count)
	           < 0);
	TEST_CHECK(odoh_parse_configs(vector, vector_len, &config, 0, &count) < 0);

	contents[6]        = 0;
	contents[7]        = 0;
	entry.contents_len = contents_len;
	vector_len         = make_configs(&entry, 1, vector, sizeof(vector));
	TEST_CHECK(odoh_parse_configs(vector, vector_len, &config, 1, &count) < 0);

	contents[6]        = 0;
	contents[7]        = 1;
	entry.contents_len = contents_len + 1;
	vector_len         = make_configs(&entry, 1, vector, sizeof(vector));
	TEST_CHECK(odoh_parse_configs(vector, vector_len, &config, 1, &count) < 0);
}

static void
test_message_round_trips(void)
{
	static const uint8_t key_id[]     = { 0x11, 0x22 };
	static const uint8_t ciphertext[] = { 0xa0, 0xa1, 0xa2 };
	static const uint8_t response[]   = { 0xbb };

	uint8_t              buf[32];
	struct odoh_message  message;
	size_t               written = 0;

	assert(odoh_encode_message(ODOH_MESSAGE_TYPE_QUERY, key_id,
	                           sizeof(key_id), ciphertext,
	                           sizeof(ciphertext), buf, sizeof(buf),
	                           &written)
	       == 0);
	TEST_EXPECT_SIZE_EQ(written, 10);
	assert(odoh_parse_message(buf, written, &message) == 0);
	TEST_EXPECT_INT_EQ(message.message_type, ODOH_MESSAGE_TYPE_QUERY);
	TEST_EXPECT_SIZE_EQ(message.key_id.len, sizeof(key_id));
	expect_bytes(message.key_id.data, key_id, sizeof(key_id));
	TEST_EXPECT_SIZE_EQ(message.encrypted_message.len, sizeof(ciphertext));
	expect_bytes(message.encrypted_message.data, ciphertext,
	             sizeof(ciphertext));

	assert(odoh_encode_message(ODOH_MESSAGE_TYPE_RESPONSE, NULL, 0, response,
	                           sizeof(response), buf, sizeof(buf),
	                           &written)
	       == 0);
	TEST_EXPECT_SIZE_EQ(written, 6);
	assert(odoh_parse_message(buf, written, &message) == 0);
	TEST_EXPECT_INT_EQ(message.message_type, ODOH_MESSAGE_TYPE_RESPONSE);
	TEST_EXPECT_SIZE_EQ(message.key_id.len, 0);
	TEST_EXPECT_SIZE_EQ(message.encrypted_message.len, sizeof(response));
	expect_bytes(message.encrypted_message.data, response, sizeof(response));
}

static void
test_malformed_messages(void)
{
	static const uint8_t key_id[]     = { 0x11 };
	static const uint8_t ciphertext[] = { 0x22, 0x33 };

	uint8_t              buf[16];
	struct odoh_message  message;
	size_t               written = 0;

	assert(odoh_encode_message(ODOH_MESSAGE_TYPE_QUERY, key_id,
	                           sizeof(key_id), ciphertext,
	                           sizeof(ciphertext), buf, sizeof(buf),
	                           &written)
	       == 0);
	for (size_t len = 0; len < written; len++)
		TEST_CHECK(odoh_parse_message(buf, len, &message) < 0);

	buf[0] = 0x7f;
	TEST_CHECK(odoh_parse_message(buf, written, &message) < 0);

	TEST_CHECK(odoh_encode_message(ODOH_MESSAGE_TYPE_QUERY, key_id,
	                               sizeof(key_id), ciphertext, 0, buf,
	                               sizeof(buf), &written)
	           < 0);
	TEST_CHECK(odoh_encode_message(0x7f, key_id, sizeof(key_id), ciphertext,
	                               sizeof(ciphertext), buf, sizeof(buf),
	                               &written)
	           < 0);
}

static void
test_plaintext_round_trip_and_padding_rejection(void)
{
	static const uint8_t dns_message[] = {
		0x12,
		0x34,
		0x01,
		0x00,
		0x00,
		0x01,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
	};

	uint8_t               buf[32];
	struct odoh_plaintext plaintext;
	size_t                written = 0;

	assert(odoh_encode_plaintext(dns_message, sizeof(dns_message), 4, buf,
	                             sizeof(buf), &written)
	       == 0);
	TEST_EXPECT_SIZE_EQ(written, sizeof(dns_message) + 8);
	assert(odoh_parse_plaintext(buf, written, &plaintext) == 0);
	TEST_EXPECT_SIZE_EQ(plaintext.dns_message.len, sizeof(dns_message));
	expect_bytes(plaintext.dns_message.data, dns_message,
	             sizeof(dns_message));
	TEST_EXPECT_SIZE_EQ(plaintext.padding.len, 4);
	expect_bytes(plaintext.padding.data, (const uint8_t[]){ 0, 0, 0, 0 }, 4);

	buf[written - 1] = 1;
	TEST_CHECK(odoh_parse_plaintext(buf, written, &plaintext) < 0);
}

static void
test_malformed_plaintext(void)
{
	static const uint8_t  dns_message[] = { 0xaa };

	uint8_t               buf[8];
	struct odoh_plaintext plaintext;
	size_t                written = 0;

	assert(odoh_encode_plaintext(dns_message, sizeof(dns_message), 0, buf,
	                             sizeof(buf), &written)
	       == 0);
	for (size_t len = 0; len < written; len++)
		TEST_CHECK(odoh_parse_plaintext(buf, len, &plaintext) < 0);

	TEST_CHECK(odoh_encode_plaintext(dns_message, 0, 0, buf, sizeof(buf),
	                                 &written)
	           < 0);
	TEST_CHECK(odoh_parse_plaintext((const uint8_t[]){ 0, 0, 0, 0 }, 4,
	                                &plaintext)
	           < 0);
	TEST_CHECK(odoh_parse_plaintext((const uint8_t[]){ 0, 1, 0xaa, 0, 2, 0 },
	                                6, &plaintext)
	           < 0);
}

int
main(void)
{
	test_parse_single_config();
	test_parse_multiple_configs_preserves_order();
	test_malformed_config_vectors();

	test_message_round_trips();
	test_malformed_messages();

	test_plaintext_round_trip_and_padding_rejection();
	test_malformed_plaintext();

	puts("odoh tests passed");
	return 0;
}
