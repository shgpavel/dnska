/* SPDX-License-Identifier: MIT */

/*
 * Compile-only transport feasibility probe.
 *
 * This file is intentionally not linked into dnska.  Compile it with the
 * repository CFLAGS when checking whether the local OpenSSL headers expose the
 * DoQ and ODoH/OHTTP primitives the roadmap expects.
 */

#include <stddef.h>
#include <stdint.h>

#include <netinet/in.h>
#include <sys/socket.h>

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/hpke.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/quic.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>

static int
probe_openssl_quic_client_api(void)
{
#ifdef OPENSSL_NO_QUIC
	return 77;
#else
	static const unsigned char alpn_doq[] = {
		3,
		'd',
		'o',
		'q',
	};
	static const unsigned char addr4[] = {
		127,
		0,
		0,
		1,
	};

	SSL_CTX  *ctx;
	SSL      *conn;
	SSL      *stream;
	BIO_ADDR *peer;
	BIO      *bio;
	size_t    done         = 0;
	uint64_t  stream_avail = 0;
	uint8_t   in[2];
	int       ok = 1;

	ctx          = SSL_CTX_new(OSSL_QUIC_client_thread_method());
	conn         = ctx != NULL ? SSL_new(ctx) : NULL;
	peer         = BIO_ADDR_new();
	bio          = BIO_new_dgram(-1, BIO_NOCLOSE);

	if (conn == NULL || peer == NULL || bio == NULL)
		ok = 0;
	if (ok && BIO_ADDR_rawmake(peer, AF_INET, addr4, sizeof(addr4), 853) != 1)
		ok = 0;
	if (ok && SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1)
		ok = 0;
	if (ok && SSL_set_alpn_protos(conn, alpn_doq, sizeof(alpn_doq)) != 0)
		ok = 0;
	if (ok && SSL_set1_initial_peer_addr(conn, peer) != 1)
		ok = 0;
	if (ok && SSL_set_blocking_mode(conn, 1) != 1)
		ok = 0;
	if (ok) {
		SSL_set_bio(conn, bio, bio);
		bio = NULL;
	}

	/*
	 * The remaining calls are type probes for the stream boundary.  This
	 * file is not run, so a dummy datagram fd is sufficient here.
	 */
	if (ok && SSL_connect(conn) != 1)
		ok = 0;
	if (ok && SSL_get_quic_stream_bidi_local_avail(conn, &stream_avail) != 1)
		ok = 0;
	stream = ok ? SSL_new_stream(conn, 0) : NULL;
	if (ok && stream == NULL)
		ok = 0;
	if (ok && SSL_write_ex2(stream, in, sizeof(in), SSL_WRITE_FLAG_CONCLUDE, &done) != 1)
		ok = 0;
	if (ok && SSL_read_ex(stream, in, sizeof(in), &done) != 1)
		ok = 0;
	if (ok && SSL_stream_conclude(stream, 0) != 1)
		ok = 0;

	SSL_free(stream);
	SSL_free(conn);
	BIO_free(bio);
	BIO_ADDR_free(peer);
	SSL_CTX_free(ctx);
	return ok ? 0 : 1;
#endif
}

static int
probe_openssl_hpke_api(void)
{
	static const unsigned char odoh_info[] = {
		'o',
		'd',
		'o',
		'h',
		' ',
		'q',
		'u',
		'e',
		'r',
		'y',
	};
	static const unsigned char plaintext[] = {
		0,
		12,
		'e',
		'x',
		'a',
		'm',
		'p',
		'l',
		'e',
	};
	unsigned char   pub[OSSL_HPKE_MAX_PARMLEN];
	unsigned char   enc[OSSL_HPKE_MAX_PARMLEN];
	unsigned char   ct[128];
	unsigned char   exported[32];
	size_t          pub_len = sizeof(pub);
	size_t          enc_len = sizeof(enc);
	size_t          ct_len  = sizeof(ct);
	OSSL_HPKE_SUITE suite   = {
		.kem_id  = OSSL_HPKE_KEM_ID_X25519,
		.kdf_id  = OSSL_HPKE_KDF_ID_HKDF_SHA256,
		.aead_id = OSSL_HPKE_AEAD_ID_AES_GCM_128,
	};
	OSSL_HPKE_CTX *ctx;
	EVP_PKEY      *priv = NULL;
	int            ok   = 1;

	if (OSSL_HPKE_suite_check(suite) != 1)
		ok = 0;
	if (OSSL_HPKE_get_public_encap_size(suite) > sizeof(enc))
		ok = 0;
	if (OSSL_HPKE_get_ciphertext_size(suite, sizeof(plaintext))
	    > sizeof(ct))
		ok = 0;

	if (ok && OSSL_HPKE_keygen(suite, pub, &pub_len, &priv, NULL, 0, NULL, NULL) != 1)
		ok = 0;
	ctx = ok ? OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, suite,
	                             OSSL_HPKE_ROLE_SENDER, NULL,
	                             NULL) :
	           NULL;
	if (ok && ctx == NULL)
		ok = 0;
	if (ok && OSSL_HPKE_encap(ctx, enc, &enc_len, pub, pub_len, odoh_info, sizeof(odoh_info)) != 1)
		ok = 0;
	if (ok && OSSL_HPKE_seal(ctx, ct, &ct_len, enc, enc_len, plaintext, sizeof(plaintext)) != 1)
		ok = 0;
	if (ok && OSSL_HPKE_export(ctx, exported, sizeof(exported), odoh_info, sizeof(odoh_info)) != 1)
		ok = 0;

	OSSL_HPKE_CTX_free(ctx);
	EVP_PKEY_free(priv);
	return ok ? 0 : 1;
}

static int
probe_openssl_hkdf_and_aead_api(void)
{
	static unsigned char salt[] = {
		's',
		'a',
		'l',
		't',
	};
	static unsigned char secret[] = {
		's',
		'e',
		'c',
		'r',
		'e',
		't',
	};
	static unsigned char info[] = {
		'o',
		'h',
		't',
		't',
		'p',
	};
	static unsigned char key[16];
	static unsigned char nonce[12];
	unsigned char        out[32];
	int                  mode    = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
	int                  out_len = 0;
	EVP_KDF             *kdf;
	EVP_KDF_CTX         *kdf_ctx;
	EVP_CIPHER          *cipher;
	EVP_CIPHER_CTX      *cipher_ctx;
	OSSL_PARAM           params[6];
	int                  ok = 1;

	params[0]               = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
	params[1]               = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
	                                                           "SHA256", 0);
	params[2]               = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
	                                                            salt, sizeof(salt));
	params[3]               = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
	                                                            secret,
	                                                            sizeof(secret));
	params[4]               = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
	                                                            info, sizeof(info));
	params[5]               = OSSL_PARAM_construct_end();

	kdf                     = EVP_KDF_fetch(NULL, OSSL_KDF_NAME_HKDF, NULL);
	kdf_ctx                 = kdf != NULL ? EVP_KDF_CTX_new(kdf) : NULL;
	if (kdf_ctx == NULL)
		ok = 0;
	if (ok && EVP_KDF_derive(kdf_ctx, key, sizeof(key), params) != 1)
		ok = 0;

	cipher     = EVP_CIPHER_fetch(NULL, "AES-128-GCM", NULL);
	cipher_ctx = cipher != NULL ? EVP_CIPHER_CTX_new() : NULL;
	if (cipher_ctx == NULL)
		ok = 0;
	if (ok && EVP_CIPHER_get_key_length(cipher) != (int)sizeof(key))
		ok = 0;
	if (ok && EVP_CIPHER_get_iv_length(cipher) != (int)sizeof(nonce))
		ok = 0;
	if (ok && EVP_EncryptInit_ex2(cipher_ctx, cipher, key, nonce, NULL) != 1)
		ok = 0;
	if (ok && EVP_EncryptUpdate(cipher_ctx, out, &out_len, info, (int)sizeof(info)) != 1)
		ok = 0;
	if (ok && EVP_EncryptFinal_ex(cipher_ctx, out + out_len, &out_len) != 1)
		ok = 0;

	EVP_CIPHER_CTX_free(cipher_ctx);
	EVP_CIPHER_free(cipher);
	EVP_KDF_CTX_free(kdf_ctx);
	EVP_KDF_free(kdf);
	return ok ? 0 : 1;
}

int
main(void)
{
	int rc  = 0;

	rc     |= probe_openssl_quic_client_api();
	rc     |= probe_openssl_hpke_api();
	rc     |= probe_openssl_hkdf_and_aead_api();
	return rc;
}
