/* SPDX-License-Identifier: MIT */

#include <string.h>

#include "odoh.h"
#include "wire.h"

enum {
	ODOH_U16_MAX              = 65535,
	ODOH_CONFIG_HEADER_LEN    = 4,
	ODOH_CONFIG_CONTENTS_BASE = 8,
	ODOH_MESSAGE_HEADER_LEN   = 5,
	ODOH_PLAINTEXT_HEADER_LEN = 4,
};

static bool
u16_len_valid(size_t len)
{
	return len <= ODOH_U16_MAX;
}

static bool
bytes_valid(const uint8_t *data, size_t len)
{
	return len == 0 || data != NULL;
}

bool
odoh_message_type_valid(uint8_t message_type)
{
	return message_type == ODOH_MESSAGE_TYPE_QUERY
	       || message_type == ODOH_MESSAGE_TYPE_RESPONSE;
}

size_t
odoh_config_contents_encoded_len(size_t public_key_len)
{
	if (public_key_len == 0
	    || public_key_len > ODOH_U16_MAX - ODOH_CONFIG_CONTENTS_BASE)
		return 0;

	return ODOH_CONFIG_CONTENTS_BASE + public_key_len;
}

size_t
odoh_config_encoded_len(size_t contents_len)
{
	if (!u16_len_valid(contents_len))
		return 0;

	return ODOH_CONFIG_HEADER_LEN + contents_len;
}

size_t
odoh_configs_encoded_len(const struct odoh_config_encode_entry *entries,
                         size_t                                 entry_count)
{
	size_t total = 0;

	if (entries == NULL || entry_count == 0)
		return 0;

	for (size_t i = 0; i < entry_count; i++) {
		size_t entry_len;

		if (!bytes_valid(entries[i].contents, entries[i].contents_len))
			return 0;

		entry_len = odoh_config_encoded_len(entries[i].contents_len);
		if (entry_len == 0 || entry_len > ODOH_U16_MAX - total)
			return 0;
		total += entry_len;
	}

	if (total == 0)
		return 0;

	return 2 + total;
}

int
odoh_encode_config_contents(uint16_t kem_id, uint16_t kdf_id,
                            uint16_t aead_id, const uint8_t *public_key,
                            size_t public_key_len, uint8_t *out,
                            size_t out_len, size_t *written)
{
	size_t need = odoh_config_contents_encoded_len(public_key_len);

	if (written == NULL || need == 0 || public_key == NULL || out == NULL || out_len < need)
		return -1;

	wire_write_u16(out, kem_id);
	wire_write_u16(out + 2, kdf_id);
	wire_write_u16(out + 4, aead_id);
	wire_write_u16(out + 6, (uint16_t)public_key_len);
	memcpy(out + ODOH_CONFIG_CONTENTS_BASE, public_key, public_key_len);

	*written = need;
	return 0;
}

int
odoh_encode_config(uint16_t version, const uint8_t *contents,
                   size_t contents_len, uint8_t *out, size_t out_len,
                   size_t *written)
{
	size_t need = odoh_config_encoded_len(contents_len);

	if (written == NULL || need == 0 || !bytes_valid(contents, contents_len) || out == NULL || out_len < need)
		return -1;

	wire_write_u16(out, version);
	wire_write_u16(out + 2, (uint16_t)contents_len);
	if (contents_len > 0)
		memcpy(out + ODOH_CONFIG_HEADER_LEN, contents, contents_len);

	*written = need;
	return 0;
}

int
odoh_encode_configs(const struct odoh_config_encode_entry *entries,
                    size_t entry_count, uint8_t *out, size_t out_len,
                    size_t *written)
{
	size_t need = odoh_configs_encoded_len(entries, entry_count);
	size_t pos  = 2;

	if (written == NULL || need == 0 || out == NULL || out_len < need)
		return -1;

	wire_write_u16(out, (uint16_t)(need - 2));
	for (size_t i = 0; i < entry_count; i++) {
		size_t entry_written = 0;

		if (odoh_encode_config(entries[i].version, entries[i].contents,
		                       entries[i].contents_len, out + pos,
		                       out_len - pos, &entry_written)
		    < 0)
			return -1;
		pos += entry_written;
	}

	*written = pos;
	return 0;
}

static int
parse_config_contents(struct odoh_config *config)
{
	const uint8_t *contents = config->contents.data;
	size_t         len      = config->contents.len;
	uint16_t       public_key_len;

	config->has_odoh_contents = false;
	config->kem_id            = 0;
	config->kdf_id            = 0;
	config->aead_id           = 0;
	config->public_key.data   = NULL;
	config->public_key.len    = 0;

	if (config->version != ODOH_CONFIG_VERSION)
		return 0;
	if (len < ODOH_CONFIG_CONTENTS_BASE)
		return -1;

	public_key_len = wire_read_u16(contents + 6);
	if (public_key_len == 0
	    || len != ODOH_CONFIG_CONTENTS_BASE + (size_t)public_key_len)
		return -1;

	config->has_odoh_contents = true;
	config->kem_id            = wire_read_u16(contents);
	config->kdf_id            = wire_read_u16(contents + 2);
	config->aead_id           = wire_read_u16(contents + 4);
	config->public_key.data   = contents + ODOH_CONFIG_CONTENTS_BASE;
	config->public_key.len    = public_key_len;
	return 0;
}

int
odoh_parse_configs(const uint8_t *buf, size_t len,
                   struct odoh_config *configs, size_t config_cap,
                   size_t *config_count)
{
	size_t vector_len;
	size_t pos   = 2;
	size_t count = 0;

	if (config_count == NULL || buf == NULL || len < 2)
		return -1;
	if (configs == NULL && config_cap != 0)
		return -1;

	vector_len = wire_read_u16(buf);
	if (vector_len == 0 || vector_len != len - 2)
		return -1;

	while (pos < len) {
		struct odoh_config parsed;
		size_t             contents_len;

		if (len - pos < ODOH_CONFIG_HEADER_LEN)
			return -1;

		parsed.version            = wire_read_u16(buf + pos);
		contents_len              = wire_read_u16(buf + pos + 2);
		parsed.contents.data      = buf + pos + ODOH_CONFIG_HEADER_LEN;
		parsed.contents.len       = contents_len;
		parsed.has_odoh_contents  = false;
		parsed.kem_id             = 0;
		parsed.kdf_id             = 0;
		parsed.aead_id            = 0;
		parsed.public_key.data    = NULL;
		parsed.public_key.len     = 0;
		pos                      += ODOH_CONFIG_HEADER_LEN;

		if (contents_len > len - pos)
			return -1;
		if (parse_config_contents(&parsed) < 0)
			return -1;

		if (configs != NULL) {
			if (count >= config_cap)
				return -1;
			configs[count] = parsed;
		}
		count++;
		pos += contents_len;
	}

	if (pos != len || count == 0)
		return -1;

	*config_count = count;
	return 0;
}

int
odoh_config_key_id_input(const struct odoh_config *config,
                         const uint8_t **data, size_t *len)
{
	if (config == NULL || data == NULL || len == NULL || !config->has_odoh_contents || config->contents.data == NULL || config->contents.len == 0)
		return -1;

	*data = config->contents.data;
	*len  = config->contents.len;
	return 0;
}

const struct odoh_config *
odoh_select_config(const struct odoh_config *configs, size_t config_count,
                   uint16_t kem_id, uint16_t kdf_id, uint16_t aead_id)
{
	if (configs == NULL)
		return NULL;

	for (size_t i = 0; i < config_count; i++) {
		if (configs[i].has_odoh_contents && configs[i].kem_id == kem_id && configs[i].kdf_id == kdf_id && configs[i].aead_id == aead_id)
			return &configs[i];
	}

	return NULL;
}

size_t
odoh_message_encoded_len(size_t key_id_len, size_t encrypted_message_len)
{
	if (!u16_len_valid(key_id_len) || encrypted_message_len == 0 || !u16_len_valid(encrypted_message_len))
		return 0;

	return ODOH_MESSAGE_HEADER_LEN + key_id_len + encrypted_message_len;
}

int
odoh_encode_message(uint8_t message_type, const uint8_t *key_id,
                    size_t key_id_len, const uint8_t *encrypted_message,
                    size_t encrypted_message_len, uint8_t *out,
                    size_t out_len, size_t *written)
{
	size_t need = odoh_message_encoded_len(key_id_len, encrypted_message_len);
	size_t pos  = 0;

	if (written == NULL || need == 0 || !odoh_message_type_valid(message_type) || !bytes_valid(key_id, key_id_len) || encrypted_message == NULL || out == NULL || out_len < need)
		return -1;

	out[pos++] = message_type;
	wire_write_u16(out + pos, (uint16_t)key_id_len);
	pos += 2;
	if (key_id_len > 0) {
		memcpy(out + pos, key_id, key_id_len);
		pos += key_id_len;
	}
	wire_write_u16(out + pos, (uint16_t)encrypted_message_len);
	pos += 2;
	memcpy(out + pos, encrypted_message, encrypted_message_len);
	pos      += encrypted_message_len;

	*written  = pos;
	return 0;
}

int
odoh_parse_message(const uint8_t *buf, size_t len,
                   struct odoh_message *message)
{
	size_t pos = 0;
	size_t key_id_len;
	size_t encrypted_message_len;

	if (buf == NULL || message == NULL || len < ODOH_MESSAGE_HEADER_LEN)
		return -1;
	if (!odoh_message_type_valid(buf[pos]))
		return -1;

	message->message_type  = buf[pos++];
	key_id_len             = wire_read_u16(buf + pos);
	pos                   += 2;
	if (key_id_len > len - pos)
		return -1;
	message->key_id.data  = buf + pos;
	message->key_id.len   = key_id_len;
	pos                  += key_id_len;

	if (len - pos < 2)
		return -1;
	encrypted_message_len  = wire_read_u16(buf + pos);
	pos                   += 2;
	if (encrypted_message_len == 0 || encrypted_message_len > len - pos)
		return -1;
	message->encrypted_message.data  = buf + pos;
	message->encrypted_message.len   = encrypted_message_len;
	pos                             += encrypted_message_len;

	if (pos != len)
		return -1;

	return 0;
}

size_t
odoh_plaintext_encoded_len(size_t dns_message_len, size_t padding_len)
{
	if (dns_message_len == 0 || !u16_len_valid(dns_message_len) || !u16_len_valid(padding_len))
		return 0;

	return ODOH_PLAINTEXT_HEADER_LEN + dns_message_len + padding_len;
}

int
odoh_encode_plaintext(const uint8_t *dns_message, size_t dns_message_len,
                      size_t padding_len, uint8_t *out, size_t out_len,
                      size_t *written)
{
	size_t need = odoh_plaintext_encoded_len(dns_message_len, padding_len);
	size_t pos  = 0;

	if (written == NULL || need == 0 || dns_message == NULL || out == NULL || out_len < need)
		return -1;

	wire_write_u16(out + pos, (uint16_t)dns_message_len);
	pos += 2;
	memcpy(out + pos, dns_message, dns_message_len);
	pos += dns_message_len;
	wire_write_u16(out + pos, (uint16_t)padding_len);
	pos += 2;
	memset(out + pos, 0, padding_len);
	pos      += padding_len;

	*written  = pos;
	return 0;
}

int
odoh_parse_plaintext(const uint8_t *buf, size_t len,
                     struct odoh_plaintext *plaintext)
{
	size_t pos = 0;
	size_t dns_message_len;
	size_t padding_len;

	if (buf == NULL || plaintext == NULL || len < ODOH_PLAINTEXT_HEADER_LEN)
		return -1;

	dns_message_len  = wire_read_u16(buf + pos);
	pos             += 2;
	if (dns_message_len == 0 || dns_message_len > len - pos)
		return -1;
	plaintext->dns_message.data  = buf + pos;
	plaintext->dns_message.len   = dns_message_len;
	pos                         += dns_message_len;

	if (len - pos < 2)
		return -1;
	padding_len  = wire_read_u16(buf + pos);
	pos         += 2;
	if (padding_len > len - pos)
		return -1;
	plaintext->padding.data = buf + pos;
	plaintext->padding.len  = padding_len;
	for (size_t i = 0; i < padding_len; i++) {
		if (buf[pos + i] != 0)
			return -1;
	}
	pos += padding_len;

	if (pos != len)
		return -1;

	return 0;
}
