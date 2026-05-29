# DoQ and ODoH/OHTTP Implementation Design

Status snapshot: 2026-05-30, starting from commit `f94246f`.

This document turns the roadmap transport notes into implementation boundaries
for this repository.  It is written for a low-risk sequence: first add
compile-gated helpers and unit-tested encoders, then wire one transport at a
time through the resolver.

Primary references:

- DoQ: RFC 9250, <https://www.rfc-editor.org/rfc/rfc9250.html>
- ODoH: RFC 9230, <https://www.rfc-editor.org/rfc/rfc9230.html>
- OHTTP: RFC 9458, <https://www.rfc-editor.org/rfc/rfc9458.html>
- HPKE: RFC 9180, <https://www.rfc-editor.org/rfc/rfc9180.html>
- Binary HTTP: RFC 9292, <https://www.rfc-editor.org/rfc/rfc9292.html>

## Local Feasibility Findings

The local `pkg-config` view reports:

- `openssl` 3.6.2
- `libngtcp2` 1.22.1
- `libnghttp3` 1.15.0
- no `libngtcp2_crypto_openssl` package
- no `msquic` package

The standalone compile probe
`test/transport_probe/openssl_quic_hpke_probe.c` compiles with:

```sh
clang -std=c23 -Wall -Wextra -Wpedantic -O2 \
  -D_POSIX_C_SOURCE=200809L -Isrc/include -Itest \
  -c -o /tmp/dnska-openssl-quic-hpke-probe.o \
  test/transport_probe/openssl_quic_hpke_probe.c
```

The probe confirms these OpenSSL QUIC client APIs are visible:

- `<openssl/quic.h>`
- `OSSL_QUIC_client_thread_method`
- `SSL_set1_initial_peer_addr`
- `SSL_set_alpn_protos`
- `SSL_set_blocking_mode`
- `SSL_get_quic_stream_bidi_local_avail`
- `SSL_new_stream`
- `SSL_write_ex2` with `SSL_WRITE_FLAG_CONCLUDE`
- `SSL_read_ex`
- `SSL_stream_conclude`

It also confirms these HPKE and OHTTP-adjacent crypto APIs are visible:

- `<openssl/hpke.h>`
- `OSSL_HPKE_SUITE`, `OSSL_HPKE_CTX_new`, `OSSL_HPKE_keygen`
- `OSSL_HPKE_encap`, `OSSL_HPKE_seal`, `OSSL_HPKE_export`
- `OSSL_HPKE_suite_check`, `OSSL_HPKE_get_public_encap_size`
- `OSSL_HPKE_get_ciphertext_size`
- `EVP_KDF_fetch` with `OSSL_KDF_NAME_HKDF`
- `EVP_KDF_derive`
- `EVP_CIPHER_fetch` with `AES-128-GCM`
- `EVP_EncryptInit_ex2`, `EVP_EncryptUpdate`, `EVP_EncryptFinal_ex`

This is compile-only evidence.  It proves the headers and function signatures
needed for first-pass DoQ and ODoH/OHTTP crypto work are present.  It does not
prove runtime QUIC interoperability, ODoH vector correctness, Binary HTTP
encoding, or OpenSSL provider availability in every deployment.

## Shared Transport Migration

The current public resolver and config surfaces use `upstream_tls` plus
`upstream_doh` booleans.  DoQ, ODoH, and OHTTP need an enum before runtime
wiring; adding another boolean would create ambiguous combinations.

Add this enum to `src/include/config.h`:

```c
enum dns_upstream_transport {
	DNS_UPSTREAM_PLAIN = 0,
	DNS_UPSTREAM_DOT,
	DNS_UPSTREAM_DOH,
	DNS_UPSTREAM_DOQ,
	DNS_UPSTREAM_ODOH,
	DNS_UPSTREAM_OHTTP,
};
```

Migration sequence:

1. Add `enum dns_upstream_transport upstream_transport` to
   `struct dns_config`, while keeping `upstream_tls` and `upstream_doh` as
   compatibility inputs.
2. Add `config_parse_upstream_transport()` for
   `plain|dot|doh|doq|odoh|ohttp`.
3. Add `upstream_transport = ...` config support and
   `--upstream-transport ...` CLI support.
4. Keep `upstream_tls = true`, `upstream_doh = true`, `--upstream-tls`, and
   `--upstream-doh` as aliases that set the enum unless the enum was already
   set inconsistently.  Reject conflicting inputs.
5. Change `resolver_forward()` and `resolver_discover_svcb()` to take a small
   options struct rather than adding more positional arguments:

```c
struct resolver_forward_options {
	enum dns_upstream_transport transport;
	const char                 *upstream_hostname;
	const char                 *doh_path;
	uint16_t                    edns_padding_block;
	const struct resolver_oblivious_options *oblivious;
};
```

6. Update `server.c` and `main.c` call sites to build that struct.
7. Once call sites are enum-based and tests cover legacy aliases, remove the
   booleans from internal dispatch.  Keep config compatibility if desired by
   parsing the old keys into the enum.

Default upstream ports should become:

- plain DNS: 53
- DoT: 853
- DoQ: 853
- DoH: 443
- ODoH: proxy URI port, defaulting to 443 for `https`
- OHTTP: relay URI port, defaulting to 443 for `https`

`config_effective_listen_mode()` should continue to describe inbound listener
mode only.  DoQ/ODoH/OHTTP are upstream transports and must not implicitly add
inbound listener behavior.

## DoQ Design

### Build Gate

DoQ should be behind an explicit feature gate:

- `HAVE_OPENSSL_QUIC=1` only when a compile probe equivalent to
  `test/transport_probe/openssl_quic_hpke_probe.c` passes.
- `src/resolver.c` should include `<openssl/quic.h>` only inside that gate.
- If the gate is missing, selecting DoQ should fail at config/CLI validation
  with a clear error and no runtime fallback to plain DNS.

If OpenSSL QUIC is rejected as the dependency baseline, the next viable path is
`ngtcp2` plus a crypto binding.  This machine has `libngtcp2` and `libnghttp3`,
but lacks a pkg-config visible `libngtcp2_crypto_openssl`, so that path is not
ready without another dependency decision.

### Resolver Boundaries

Keep DoQ in `src/resolver.c` initially, matching DoT and DoH.  The first
implementation does not need connection pooling; one connection and one stream
per forwarded query is slower but keeps the behavior easy to test.

Add these private helpers:

- `init_client_quic_ctx()`: creates `SSL_CTX_new(OSSL_QUIC_client_thread_method())`,
  requires TLS 1.3, loads CA paths like `init_client_tls_ctx()`, and applies
  `tls_insecure`.
- `quic_connect(...)`: creates a UDP socket, applies timeouts, builds a
  `BIO_ADDR` from the selected upstream address and port, attaches a datagram
  BIO, sets ALPN to `doq`, sets SNI and hostname verification using the same
  `tls_auth_name`/`upstream_hostname` policy as DoT/DoH, sets blocking mode,
  and calls `SSL_connect()`.
- `quic_close(SSL *conn, int fd)`: closes the QUIC connection and UDP socket.
- `quic_readn(SSL *stream, uint8_t *buf, size_t len)`.
- `quic_writen_conclude(SSL *stream, const uint8_t *buf, size_t len)`: writes
  the length-prefixed query and sends FIN, using `SSL_write_ex2(...,
  SSL_WRITE_FLAG_CONCLUDE, ...)` for the final chunk or `SSL_stream_conclude()`
  after a complete write loop.
- `forward_doq(...)`: mirrors `forward_tls()` but uses a client-initiated
  bidirectional QUIC stream.

OpenSSL should manage QUIC connection IDs.  dnska only needs to manage DNS
message IDs and stream ownership.

### ALPN and Framing

DoQ connection setup must set ALPN to `doq`.

Each DNS transaction uses one client-initiated bidirectional stream:

1. Open stream with `SSL_new_stream(conn, 0)`.
2. Write a two-octet network-order DNS message length.
3. Write the DNS message.
4. Conclude the write side so servers that wait for STREAM FIN can process the
   query.
5. Read a two-octet response length from the same stream.
6. Reject lengths smaller than `DNS_HEADER_SIZE` or larger than the caller's
   response buffer.
7. Read exactly that many response bytes.
8. Restore the original client DNS ID before returning.

For the current single-response forwarding path, read only one DNS response.
Zone-transfer support over DoQ belongs with the separate XFR work because it
requires a multi-message client.

### DNS ID Handling

RFC 9250 requires DNS Message ID zero for queries sent over DoQ.  Adjust
`forward_one_address()` so the upstream ID is selected by transport:

- DoQ: set `upstream_id = 0`.
- UDP/TCP/DoT/DoH/ODoH/OHTTP: keep the existing randomized upstream ID unless
  a later DoH cleanup deliberately switches DoH to ID zero.

DoQ response validation should require response ID zero, then restore
`orig_query[0..1]`.  The current client EDNS detection, forced upstream DO bit,
EDNS padding, and response OPT stripping should run unchanged.  DoQ is an
encrypted upstream transport, so `edns_padding_block` applies when non-zero.

### Discovery

`parse_svcb_alpn()` already recognizes `doq`.  Once DoQ can be selected:

- If discovery is enabled and the configured transport is DoQ, use an SVCB
  record with `alpn=doq`.
- Apply SVCB `port` to DoQ when no explicit upstream port was configured.
- Do not silently switch from DoT/DoH to DoQ through discovery unless the user
  requested an automatic encrypted transport policy in a later feature.

### DoQ Tests

Add tests in this order:

1. Config tests for `upstream_transport = doq`, `--upstream-transport doq`,
   default port 853, and conflict rejection with legacy booleans.
2. A small resolver helper test that proves the forwarded DoQ DNS message ID is
   zero and the returned client ID is restored.  Extract the current forwarding
   preparation into a compile-gated helper if needed.
3. SVCB parser tests with `alpn=doq` and `port`.
4. Compile probe target for OpenSSL QUIC.
5. Optional loopback QUIC integration test using OpenSSL server APIs.  Keep it
   skipped unless the feature gate passes and local UDP sockets are available.

## ODoH Design

ODoH should be implemented before generic OHTTP because it avoids a Binary HTTP
codec and maps directly to DNS messages.

### Config Model

Add explicit client-side fields:

- `odoh_proxy_uri_template[512]`
- `odoh_target_host[256]`
- `odoh_target_path[128]`, default `/dns-query`
- `odoh_config_file[256]` for local key config bytes
- later: `odoh_config_url[512]` for authenticated config fetches

The first phase should require a local config file or literal config bytes.
Fetching and caching target keys should be a separate patch because key freshness
and authentication policy are security-sensitive.

Validate the proxy template before first use:

- scheme must be `https`
- the template must contain exactly one `targethost` variable and exactly one
  `targetpath` variable
- no other URI template variables are allowed
- variables must appear in the path or query component
- target host must be a hostname, not an empty string
- target path must start with `/`

### Standalone Parser/Crypto Module

Add `src/oblivious.c` and `src/include/oblivious.h` before touching resolver
network behavior.  Keep these helpers deterministic and unit-tested:

- `odoh_parse_configs(const uint8_t *buf, size_t len, ...)`
- `odoh_select_config(...)`
- `odoh_config_key_id(...)`
- `odoh_encode_plaintext(...)`
- `odoh_parse_plaintext(...)`
- `odoh_encode_message(...)`
- `odoh_parse_message(...)`
- `odoh_encrypt_query(...)`
- `odoh_decrypt_response(...)`

`ObliviousDoHConfigs` parsing must follow the TLS-style vectors from RFC 9230:

- outer vector length: 1..65535
- each config: `version`, `length`, `contents`
- supported version: `0x0001`
- contents: `kem_id`, `kdf_id`, `aead_id`, and
  `public_key<1..2^16-1>`

Selection policy:

- process configs in wire order because RFC 9230 orders them by decreasing
  preference
- ignore unsupported versions and unsupported HPKE suites
- use `OSSL_HPKE_suite_check()` for suite availability
- initially accept `X25519/HKDF-SHA256/AES-128-GCM` because the local OpenSSL
  probe confirms that path
- fail if no supported config remains

Compute `key_id` as RFC 9230 specifies:

- HKDF Extract with empty salt and `ObliviousDoHConfigContents` as input keying
  material
- HKDF Expand with label `odoh key id`
- output length `Nh` for the selected KDF digest

For response decryption, OpenSSL HPKE provides the export step but not the full
ODoH response AEAD wrapper.  Implement the remaining derivation with EVP HKDF
and EVP AEAD:

- export `secret = OSSL_HPKE_export(context, "odoh response", Nk)`
- salt is `Q_plain || uint16(resp_nonce_len) || resp_nonce`
- HKDF Extract using that salt and exported secret
- HKDF Expand labels `odoh key` and `odoh nonce`
- AEAD Open with AAD `0x02 || uint16(resp_nonce_len) || resp_nonce`

The code must validate decrypted ODoH padding is all zero before using the DNS
message.

### Resolver Boundary

Add `forward_odoh()` next to `forward_doh()` only after the parser/crypto module
has tests.

`forward_odoh()` should:

1. Prepare the upstream DNS query using the existing resolver path: randomized
   upstream ID, sanitized flags, QNAME 0x20 randomization, forced upstream EDNS,
   and optional EDNS padding.
2. Encode and encrypt the ODoH query.
3. Expand the proxy URI template using `targethost` and `targetpath`.
4. Reuse `tls_connect()`, `read_http_headers()`, `http_parse_status()`, and
   `http_find_header()` for an HTTP/1.1 POST to the proxy.
5. Send `Accept: application/oblivious-dns-message` and
   `Content-Type: application/oblivious-dns-message`.
6. Require a 2xx HTTP status.  Treat DNS SERVFAIL/NXDOMAIN inside a decrypted
   DNS response as normal DNS results, not HTTP failures.
7. Require response `Content-Type: application/oblivious-dns-message`.
8. Require `Content-Length`, bounded by a fixed maximum.
9. Parse and decrypt the ODoH response.
10. Validate decrypted DNS length and upstream DNS ID.
11. Restore the original client DNS ID.
12. Strip the response OPT if the client did not send EDNS.

Do not cache encrypted envelopes.  The existing DNS response cache may continue
to operate on decrypted DNS responses according to the existing local policy.

### ODoH Failure Modes

Return failure without fallback to plain DNS for:

- malformed proxy URI template
- missing target host/path
- malformed ODoH config vector
- no supported HPKE config
- key ID derivation failure
- HPKE encapsulation or seal failure
- proxy TLS failure
- proxy HTTP non-2xx status
- missing or wrong response media type
- missing or excessive content length
- malformed ODoH response structure
- response message type other than `0x02`
- response nonce/key field length invalid for the selected suite
- AEAD open failure
- non-zero ODoH plaintext padding
- decrypted DNS response too small, too large, or ID-mismatched

## Generic OHTTP Design

Generic OHTTP is broader than ODoH.  Keep it as a second phase unless the
project explicitly decides to implement DNS over OHTTP instead of RFC 9230
ODoH.

### Config Model

Add separate OHTTP fields if this phase is selected:

- `ohttp_relay_uri[512]`
- `ohttp_gateway_uri[512]`
- `ohttp_key_config_file[256]`
- later: `ohttp_key_config_url[512]`
- `ohttp_target_host[256]`
- `ohttp_target_path[128]`, default `/dns-query`

The relay URI is the outer HTTP destination.  The gateway URI identifies the
OHTTP gateway key and the relay's forwarding target.  The target host/path are
inside the Binary HTTP request if DNS over OHTTP is implemented as an inner DoH
POST.

### Key Config Parsing

Parse `application/ohttp-keys` as a concatenated list of length-prefixed key
configurations:

- length: two-octet network-order length
- key ID: one octet
- KEM ID: two octets
- public key: fixed length for the KEM
- symmetric algorithm list length: two octets
- symmetric algorithm pairs: KDF ID and AEAD ID

Reject the entire collection on an encoding error.  Select the first config and
algorithm pair supported by `OSSL_HPKE_suite_check()`.

### Binary HTTP and Encapsulation

Generic OHTTP requires a Binary HTTP codec.  Add that as a standalone module,
not inline string construction:

- `bhttp_encode_known_length_request(...)`
- `bhttp_decode_known_length_response(...)`
- tests for method, scheme, authority, path, content headers, and body

For DNS over generic OHTTP, the inner request should be equivalent to a DoH POST
to the target resource:

- method `POST`
- scheme `https`
- authority `ohttp_target_host`
- path `ohttp_target_path`
- `Accept: application/dns-message`
- `Content-Type: application/dns-message`
- body: DNS wire query

Encapsulate with RFC 9458:

- request media type: `message/ohttp-req`
- response media type: `message/ohttp-res`
- request info string: `message/bhttp request` plus a zero byte and the OHTTP
  request header
- response exporter context: `message/bhttp response`
- outer POST goes to the relay URI

### OHTTP Failure Modes

Return failure without fallback to plain DNS for:

- malformed relay or gateway URI
- malformed `application/ohttp-keys`
- unsupported KEM/KDF/AEAD
- HPKE setup or seal failure
- relay TLS failure
- relay HTTP non-2xx status
- missing or wrong `message/ohttp-res` media type
- malformed encapsulated response
- response AEAD open failure
- Binary HTTP decode failure
- inner HTTP status outside 2xx
- inner media type not `application/dns-message`
- decrypted DNS response too small, too large, or ID-mismatched

## Test Vector Needs

Add tests before resolver network wiring:

- ODoH config parser: valid single config, multiple configs in preference
  order, unsupported version ignored, malformed lengths rejected, unsupported
  suite ignored, all-unsupported collection rejected.
- ODoH key ID derivation: fixture with known config contents and expected
  key_id for HKDF-SHA256.
- ODoH message codec: query type `0x01`, response type `0x02`, key vector
  length bounds, encrypted message bounds, malformed truncations.
- ODoH plaintext codec: DNS vector length, padding vector length, non-zero
  padding rejection on decrypt.
- HPKE encryption/decryption: RFC 9180 HPKE vectors for the selected suite,
  then an ODoH round trip fixture using deterministic keys.
- ODoH resolver HTTP handling: status failure, content-type failure,
  content-length failure, decrypt failure, DNS ID mismatch, success.
- OHTTP key parser: valid `application/ohttp-keys`, multiple algorithms,
  malformed collection rejection.
- Binary HTTP: inner DoH POST encode and response decode.
- OHTTP resolver HTTP handling: wrong outer media type, response decrypt
  failure, Binary HTTP failure, inner DNS success.

The existing `test/resolver/resolver_test.c` loopback HTTP/TLS style can be
reused once crypto helpers are deterministic.  Keep live network tests out of
`make check`.

## Immediate Next Implementation Steps

1. Add `make transport-probe` or an equivalent CI-only compile target for
   `test/transport_probe/openssl_quic_hpke_probe.c`.
2. Introduce `enum dns_upstream_transport` and compatibility parsing tests.
3. Change resolver forwarding to take `struct resolver_forward_options`.
4. Add DoQ behind `HAVE_OPENSSL_QUIC`, with one connection and one stream per
   query.
5. Add standalone `oblivious` parser/crypto helpers and tests.
6. Wire ODoH only after those helpers pass fixed vectors.
7. Decide whether generic OHTTP is needed after ODoH, because it requires a
   Binary HTTP module and a distinct key configuration parser.
