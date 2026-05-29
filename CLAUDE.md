# CLAUDE.md

This file provides guidance to Claude Code when working in this repository.

## Project Overview

**dnska** is a DNS forwarder with an in-memory response cache, DNS over TLS
(DoT), and DNS over HTTPS (DoH) upstream support. It listens on IPv4 and IPv6
UDP and TCP sockets (plain listener mode) or DoT sockets, parses DNS queries,
forwards cache misses to a single upstream DNS server, and returns raw DNS
responses to the client.

Current scope:

- Implemented: UDP listener, TCP listener, DoT listener (RFC 7858), DoT
  upstream forwarding, DoH upstream forwarding (RFC 8484), config file parsing,
  upstream forwarding, query
  parsing/validation, fixed-size LRU cache, cached negative responses, cached
  upstream SERVFAIL responses, IPv4 and IPv6 upstream support, hostname
  resolution for upstreams with automatic DoT mode, ephemeral self-signed cert
  generation for the DoT listener, SNI on outbound TLS connections, upstream
  certificate verification controls
- Not implemented yet: DNSSEC validation, persistent cache, DoH server
  listener, upstream connection pooling

The `refs/` directory contains reference implementations used for study:

- `refs/dnsproxy/` — AdGuard's `dnsproxy` in Go
- `refs/bind9/` — BIND 9

## Build And Test

```bash
make            # Build build/dnska
make check      # Build and run all test suites
make clean      # Remove build/
```

Compiler/toolchain details:

- `clang`
- `-std=c23`
- `-Wall -Wextra -Wpedantic -O2 -D_POSIX_C_SOURCE=200809L`
- `-pthread -lssl -lcrypto`

`compile_commands.json` is present at the repo root for clangd/LSP support.

## Runtime Behavior

Startup flow:

1. `main.c` seeds defaults: listen port `53`, listener mode `auto`,
   upstream `8.8.8.8:53`
2. Optional config file is loaded from `dnska.conf` or `--config/-c`
3. CLI flags override config values
4. If upstream is a hostname (not a literal IP), it is resolved via
   `getaddrinfo`; the hostname implies DoT upstream (`upstream_tls = true`)
   and the upstream port defaults to `853` unless set explicitly
5. DoH upstream implies TLS upstream and defaults the upstream port to `443`
   unless set explicitly
6. The effective listener mode is resolved from `listen_mode`: `auto` keeps
   legacy behavior (DoT upstream -> DoT listener, otherwise plain), while
   `plain` and `dot` override only the inbound listener
7. If no explicit listen port was given, the listen port defaults to `853`
   for an effective DoT listener and `53` for a plain listener
8. `server_init()` creates the thread pool and cache, then binds either DoT
   sockets (TLS TCP) or plain sockets (UDP + TCP) on the listen port; for DoT,
   a self-signed P-256 cert is generated in memory unless `--tls-cert`/
   `--tls-key` paths are provided
9. `server_run()` enters a `poll()` loop over up to 4 fds
   (IPv4/IPv6 × UDP + TCP in plain mode, or IPv4/IPv6 × DoT in TLS mode)

Config file support:

- Section: `[dns]`
- Keys: `upstream`, `port`/`listen_port`, `listen_mode`, `upstream_port`,
  `upstream_tls`, `upstream_doh`, `doh_path`, `tls_cert`, `tls_key`,
  `tls_ca_file`, `tls_auth_name`, `tls_insecure`
- `#` and `;` comments are accepted

CLI flags:

- `-p/--port`, `-u/--upstream`, `--upstream-port` (long only)
- `--listen-mode auto|plain|dot` — choose inbound listener mode independently
  of upstream transport
- `-t/--upstream-tls` — force DoT upstream when using a literal IP
- `--upstream-doh`, `--doh-path` — force DoH upstream and optional URL path
- `-k/--tls-key`, `--tls-cert` (long only) — custom PEM cert/key for the
  DoT listener (optional; an ephemeral self-signed cert is used if omitted)
- `--tls-ca`, `--tls-auth-name`, `--insecure` — upstream TLS verification
  controls
- `-v/--verbose`, `-h/--help`

Typical invocations:

```bash
# Plain DNS listener (port 53), plain upstream
sudo ./build/dnska -u 8.8.8.8

# DoT listener (port 853 default), DoT upstream — hostname triggers both
sudo ./build/dnska -u dns.shago.dev

# Plain DNS listener, DoT upstream
sudo ./build/dnska -u dns.google --listen-mode plain

# DoT listener, DoH upstream
sudo ./build/dnska -u dns.google --upstream-doh --listen-mode dot

# DoT listener on a custom port, DoT upstream via IP
sudo ./build/dnska -u 8.8.8.8 -t -p 8853
```

## Architecture

The code is split across these modules under `src/`:

| File | Header | Purpose |
|------|--------|---------|
| `main.c` | — | CLI entry point, defaults, config loading, signal handling |
| `config.c` | `include/config.h` | Minimal INI-like parser for `dnska.conf` |
| `dns.c` | `include/dns.h` | DNS wire parsing, name decoding, cacheability checks, response/query matching |
| `cache.c` | `include/cache.h` | Fixed-size LRU cache for DNS responses |
| `server.c` | `include/server.h` | UDP/TCP/DoT listeners, query worker pool, cache lookup/insert path |
| `resolver.c` | `include/resolver.h` | UDP forwarding with TCP fallback on TC; DoT forwarding via `forward_tls()` |
| `random.c` | `include/random.h` | Cryptographic random bytes via `getrandom`/`/dev/urandom` |
| `wire.c` | `include/wire.h` | Low-level DNS wire helpers: `wire_read_u16/u32`, `wire_skip_name` |

Important public structs live in headers directly; there are no typedef aliases.
Useful ones:

- `struct dns_message` in `src/include/dns.h`
- `struct dns_query_cache_key` in `src/include/dns.h`
- `struct cache` in `src/include/cache.h`
- `struct dns_config` in `src/include/config.h`
- `struct server` in `src/include/server.h`

## Cache Behavior

The cache is implemented today and is central to the request path.

Key properties:

- Fixed size: `1024` slots, `1024` hash buckets
- Replacement policy: LRU
- Only cacheable single-question queries are eligible
- Query match is case-insensitive on QNAME, plus exact match on QTYPE/QCLASS
- Cache key also includes selected query flags and EDNS OPT details

Cacheable query shape:

- Opcode must be standard QUERY
- Exactly one question
- No answer or authority records in the request
- At most one OPT record in additional

Cached response classes:

- `NOERROR`
- `NXDOMAIN`
- Upstream `SERVFAIL`

TTL behavior:

- Positive responses use the minimum non-OPT RR TTL as cache lifetime
- Negative responses use the SOA negative TTL, i.e. `min(SOA TTL, SOA MINIMUM)`
- Cached upstream `SERVFAIL` responses use `CACHE_SERVFAIL_TTL` which is
  currently `5` seconds
- Cache hits decrement TTLs before sending the response
- When the cache lifetime is shorter than the wire TTLs, returned TTLs are
  clamped so clients do not cache failures longer than intended

Question-section behavior on cache hits:

- Cache hits do not blindly replay the stored upstream question bytes
- The response is rebuilt with the current client's wire-format question
- This preserves the caller's QNAME casing and keeps 0x20 randomization safe

Insertion safety:

- Responses are cached only after `dns_response_matches_query()` validates that
  the upstream reply matches the original query semantics

## Networking And Concurrency

Server behavior:

- In plain listener mode: binds IPv4 and IPv6 UDP sockets and IPv4 and IPv6
  TCP sockets on the listen port
- In DoT listener mode: binds IPv4 and IPv6 TLS TCP sockets on the listen
  port; no UDP or plain TCP sockets are created
- Listener mode is independent from upstream transport after defaults are
  resolved
- Uses `SO_REUSEADDR`; sets `IPV6_V6ONLY` on IPv6 sockets
- Uses `poll()` to multiplex up to 4 listen fds
- Maintains a fixed worker thread pool of `MAX_CONCURRENT_QUERIES` (64) threads
- Per-source concurrency is capped at `MAX_CONCURRENT_QUERIES_PER_SOURCE` (4)
- TCP idle timeout: 10 seconds (RFC 7766 §6.4)

Resolver behavior:

- Plain UDP: opens a new socket per query, random source port, 0x20 QNAME
  randomization (RFC 5452), retries TCP on TC=1 (RFC 7766 §6.2.1)
- DoT (`upstream_tls = true`, `upstream_doh = false`): skips UDP entirely,
  connects over TLS 1.2+, uses the same 2-byte length-prefix framing as
  DNS-over-TCP; SNI is set when the upstream was given as a hostname or
  `tls_auth_name` is configured
- DoH (`upstream_doh = true`): sends HTTP/1.1 POST requests with
  `application/dns-message` bodies over TLS
- On upstream failure the server synthesizes a SERVFAIL response

DoT listener behavior:

- TLS handshake is performed in the worker thread, not the accept loop
- Minimum TLS version: 1.2 (`TLS1_2_VERSION`)
- If no cert/key paths are configured, `make_selfsigned_cert()` generates a
  P-256 key and self-signed X.509 cert in memory via `EVP_EC_gen`/`X509_*`
- `struct query_task` carries `tls_ctx` (borrowed from `struct server`) and
  `tls` (owned SSL object, freed via `release_task_slot()`)
- The `send_response()` helper dispatches to TLS, TCP, or UDP as appropriate

## Editing Notes

The repository follows `STYLE.md` and the user's `~/.clang-format`.

Important conventions:

- Tabs for indentation
- 80-column wrapping
- Function return type on its own line
- No `//` comments
- Project headers after system headers, with a blank line between groups
- Avoid typedef aliases for ordinary structs

Run `clang-format -i` on edited C files after changes.

## Test Guidance

Tests live under `test/` in per-module subdirectories, each producing a
separate binary under `build/test/`:

| Binary | Source | Covers |
|--------|--------|--------|
| `cache_test` | `test/cache/cache_test.c` | NXDOMAIN/SERVFAIL TTL clamping, mixed-case QNAME rewrite |
| `dns_test` | `test/dns/dns_test.c` | DNS wire parsing, name decoding, cacheability checks |
| `resolver_test` | `test/resolver/resolver_test.c` | Upstream UDP forwarding, 0x20 randomization, TCP fallback |
| `server_test` | `test/server/server_test.c` | End-to-end server request handling, plain and DoT modes |

Run all tests with:

```bash
make check
make
```

## Practical Constraints

Keep these in mind when making changes:

- The cache stores full DNS wire responses, so any change to query matching or
  TTL semantics should be validated against raw packet behavior
- `server.c` is the integration point for parser, cache, and resolver behavior;
  changes there often need end-to-end thinking rather than isolated edits
- DoT upstream uses a module-level `SSL_CTX` (client) initialized via
  `pthread_once`; DoT server uses a per-`struct server` `SSL_CTX` initialized
  in `server_init()`
- Listener mode is explicit (`auto`, `plain`, `dot`) and stored in
  `struct dns_config`; `auto` is resolved by `config_effective_listen_mode()`
  using the legacy upstream-derived behavior
- There is no separate `dot_port` config — the same `listen_port` is used for
  both plain and DoT listeners
