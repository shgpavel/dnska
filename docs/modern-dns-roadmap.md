# Modern DNS Roadmap

This file records the low-risk path for features that are larger than the
current forwarder shape.  It is intentionally a roadmap, not a hidden feature
switch: dnska currently builds from a single `Makefile` and links only
`-pthread -lssl -lcrypto`.

Detailed transport design lives in `docs/doq-odoh-design.md`.  The standalone
compile-only local probe for OpenSSL QUIC, HPKE, HKDF, and AEAD APIs is
`test/transport_probe/openssl_quic_hpke_probe.c`.

## Current Transport Shape

- `src/resolver.c` owns outbound forwarding.  `forward_one_address()` chooses
  DoH first, then DoT, then UDP with TCP fallback.
- `src/config.c`, `src/include/config.h`, and `src/main.c` expose the current
  transport model as `upstream_tls`, `upstream_doh`, `doh_path`, EDNS padding,
  resolver SVCB discovery, and TLS verification settings.
- `src/server.c` owns inbound UDP, TCP, and DoT listeners.  It is not an
  authoritative server and does not store zones.
- `src/dns.c`, `src/print.c`, and their tests handle DNS wire parsing and
  dig-style output for single DNS responses, including modern SVCB/HTTPS,
  TLSA, ZONEMD, DNSSEC/NSEC3, and EDNS option presentation.
- `src/dnssec.c` currently provides DNSSEC metadata parsing, canonical
  name/RR helper views, DNSKEY key tags, DS/DNSKEY SHA-256 and SHA-384 digest
  checks, TLSA parsing plus DANE DNSSEC-state prechecks, and non-claiming
  response state analysis.  It is not a full chain validator yet.

## DNSSEC and DANE

Current scope is deliberately below full validation.  DNSSEC helpers can parse
DS, DNSKEY, RRSIG, NSEC, NSEC3, and TLSA RDATA; compute DNSKEY key tags; build
canonical, uncompressed lowercase owner-name views from text or DNS wire names;
and expose RR owner/type/class views for future RRset assembly.  RDATA
canonicalization for signature input is still not implemented.

DANE support is likewise a precondition layer, not TLS transport policy.  A
TLSA RRset is usable for DANE only when the caller supplies
`DNSSEC_VALIDATION_SECURE`; insecure or unchecked DNSSEC state maps to insecure,
indeterminate state stays indeterminate, and bogus state stays bogus.  The
resolver/TLS code still needs a later integration step that obtains a validated
TLSA RRset for `_port._tcp.name`, binds it to the peer certificate according to
TLSA usage/selector/matching rules, and defines fallback behavior.

## DNS over QUIC

Decision: DoQ can be added without a new QUIC dependency only if the project is
willing to make OpenSSL with QUIC support a required baseline.  This workspace
has OpenSSL 3.6.2 and exposes `<openssl/quic.h>`.  The compile-only probe in
`test/transport_probe/openssl_quic_hpke_probe.c` confirms that the local
headers expose `OSSL_QUIC_client_thread_method`, ALPN setup, initial peer
address setup, bidirectional stream creation, FIN-capable writes, and stream
read/conclude APIs.  The repo does not currently detect OpenSSL versions or
feature-test QUIC APIs, so portable DoQ support needs an explicit dependency
gate before implementation.

If OpenSSL QUIC is not made mandatory, add a real QUIC stack dependency instead
of hand-rolling QUIC.  Reasonable C integration candidates are `ngtcp2` plus a
TLS crypto binding, MsQuic, quiche, or lsquic; `ngtcp2`/`nghttp3` are present on
this machine but are not build dependencies today.

Implementation phases:

1. Build gate:
   - Update `Makefile` to probe OpenSSL QUIC support, or add `pkg-config`
     dependencies for the selected QUIC stack.
   - Document the selected minimum dependency in `README.md`.
2. Config and CLI:
   - Replace the `upstream_tls`/`upstream_doh` boolean pair in
     `src/include/config.h` with an upstream transport enum.  Keep the old
     booleans as compatibility inputs while migrating call sites.
   - Add `--upstream-transport doq` and `upstream_transport = doq` in
     `src/main.c` and `src/config.c`.  A short-lived `--upstream-doq` alias is
     acceptable if tests reject conflicts with other transport selectors.
   - Default DoQ to UDP port 853 unless `--upstream-port` is set.
3. Resolver:
   - Add `forward_doq()` in `src/resolver.c` beside `forward_tls()` and
     `forward_doh()`, behind the QUIC feature gate.
   - Use ALPN `doq`, the existing TLS verification names, a client-initiated
     bidirectional QUIC stream per DNS query, the same two-octet DNS length
     prefix used by TCP/DoT, and a DNS message ID of zero on the upstream copy.
   - Restore the original client ID before returning the decrypted response.
   - Preserve the existing EDNS DO-bit and OPT-stripping behavior from
     `forward_one_address()`.
4. Tests:
   - Add resolver unit tests with a fake or loopback QUIC peer if the chosen
     library supports deterministic local tests.
   - Keep UDP/TCP/DoT/DoH tests unchanged; DoQ should be one more transport
     branch, not a rewrite of cache or server code.

## Oblivious DoH / OHTTP

Decision: ODoH is not a small extension of the current DoH branch.  It needs an
HPKE-backed envelope format plus a two-hop HTTP deployment model.  This
workspace's OpenSSL exposes `<openssl/hpke.h>`, and the compile-only probe
confirms local access to HPKE setup/seal/export, HKDF, and AEAD APIs.  The
ODoH/OHTTP message encoding, key configuration parsing, URI template handling,
and relay/target semantics still need new code.

Implementation phases:

1. Scope choice:
   - For RFC 9230 ODoH, implement `application/oblivious-dns-message`, ODoH
     config parsing, the required HPKE suite, proxy URI template expansion, and
     target host/path settings.
   - For generic RFC 9458 OHTTP, implement Binary HTTP wrapping plus
     `message/ohttp-req`, `message/ohttp-res`, and OHTTP gateway key config
     parsing.  This is broader than ODoH and should be a separate phase.
2. Config and CLI:
   - Add explicit client-side fields in `src/include/config.h`, for example
     proxy URI, target host, target path, and key/config bytes or a config URL.
   - Add CLI/config parsing in `src/main.c` and `src/config.c`.
3. Resolver:
   - Add `forward_odoh()` next to `forward_doh()` in `src/resolver.c`.
   - Reuse `tls_connect()`, `read_http_headers()`, status parsing, and
     content-length handling where possible.
   - Encrypt the DNS wire query before the HTTP POST to the proxy, validate the
     `application/oblivious-dns-message` or OHTTP response media type, decrypt
     the returned DNS response, then apply the same ID restore and EDNS response
     policy used by the existing transports.
   - Do not cache encrypted ODoH/OHTTP envelopes.  The existing DNS response
     cache may remain a local policy decision after decryption.
4. Tests:
   - Add standalone encoding tests for key config parsing and HPKE test vectors
     before adding network tests.
   - Add resolver tests for HTTP status, media type, content length, decrypt
     failure, and successful DNS response extraction.
   - Keep RFC 9230 ODoH and RFC 9458 OHTTP tests separate: OHTTP also needs a
     Binary HTTP codec and the `application/ohttp-keys`, `message/ohttp-req`,
     and `message/ohttp-res` media types.

## XFR over TLS

Meaningful forwarder/client subset: a dedicated client command could perform
AXFR or IXFR over TLS and print all returned DNS messages.  The existing
dig-style `-q` path is single-response oriented and `forward_tls()` closes after
one length-prefixed response, so it is not enough for a correct transfer client.

Authoritative scope: serving AXFR/IXFR, enforcing transfer ACLs, TSIG or mTLS
policy, SOA serial policy, NOTIFY, and zone storage are authoritative or
secondary-server work and do not fit dnska's current forwarder core.

Implementation phases:

1. Add type mnemonics for `AXFR` and `IXFR` only if a transfer-aware client mode
   is added; `TYPE252` and `TYPE251` already allow raw experiments.
2. Add a separate client transfer path in `src/main.c` that bypasses
   `resolver_forward()` and reads a sequence of length-prefixed DNS messages.
3. Put shared TLS setup in `src/resolver.c` behind reusable helpers without
   changing normal forwarding behavior.

## Catalog Zones

Meaningful forwarder/client subset: pass-through queries and, if a future XFR
client exists, inspection of catalog zone contents as ordinary DNS data.

Authoritative scope: consuming a catalog zone to create/delete served zones,
member-zone transfer orchestration, catalog state persistence, TSIG/mTLS policy,
and DNS UPDATE handling require authoritative/secondary server architecture.
Those should not be hidden inside `src/server.c`.

Implementation phases:

1. Docs and tests only for dnska as a forwarder.
2. If a zone-transfer client is added, allow printing catalog member records as
   normal RRs; do not implement catalog membership actions.
3. Revisit only after dnska has explicit zone storage and authoritative serving.

## ZONEMD

Meaningful forwarder/client subset: pass through and cache ZONEMD RRsets as
ordinary DNS answers, and print queried ZONEMD RDATA in a useful presentation
format.  This subset is implemented: `ZONEMD` is accepted as a query type and
printed as serial, scheme, hash algorithm, and digest.

Authoritative scope: generating ZONEMD, recomputing it during zone publication,
validating it over complete zone contents, and tying it to DNSSEC validation
require full zone data and DNSSEC validation.  dnska currently has neither.

Implementation phases:

1. Verification:
   - Defer until a transfer client can obtain complete zones and a DNSSEC
     validator exists.
