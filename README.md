# dnska

Forwarding DNS server with an in-memory LRU cache, DoT and DoH upstream
support (RFC 7858 / RFC 8484), modern EDNS handling, DNSSEC foundation
parsing, and a built-in `dig`-style client.

## Features

- UDP, TCP, DoT, and HTTP/1.1 DoH listeners on IPv4 and IPv6
- Plain UDP (with TCP fallback on TC=1), DoT (RFC 7858), or DoH (RFC 8484)
  upstream
- Upstream certificate verification by default; system trust paths or
  `--tls-ca`; SNI/verify-name override via `--tls-auth-name`
- Multi-address upstream with failover (up to four resolved addresses)
- DNSSEC pass-through/foundation: client `CD`/`AD` bits forwarded upstream;
  OPT with `DO=1` always sent upstream so RRSIGs can flow back; response
  `AD` is cleared unless a local validator marks the answer secure
- LRU cache with EDNS-aware keys, negative caching via SOA, cached
  upstream `SERVFAIL`, and stale-answer fallback with EDE 3 on upstream
  failure
- Built-in `-q` client mode (no server) with a `dig`-style printer including
  SVCB, HTTPS, TLSA, ZONEMD, DNSSEC/NSEC3, and EDNS option summaries
- Optional EDNS(0) padding for encrypted upstream transports and opt-in
  resolver SVCB discovery for DoT/DoH metadata
- 0x20 QNAME randomization (RFC 5452), random source ports
- Per-source concurrency limits, RFC 7766 idle timeout, BADVERS for
  unsupported EDNS versions

## Build

Requires `clang`, `make`, OpenSSL (libssl + libcrypto).

```
make            # build/dnska
make check      # build and run all test suites
make clean
```

## Server usage

```
sudo ./build/dnska -u 8.8.8.8                  # plain UDP+TCP, port 53
sudo ./build/dnska -u 8.8.8.8 -t               # DoT upstream + DoT listener (853)
sudo ./build/dnska -u dns.shago.dev            # hostname auto-DoT (853)
sudo ./build/dnska -u dns.google --listen-mode plain
                                                # plain listener, DoT upstream
sudo ./build/dnska -u dns.google --upstream-doh --listen-mode dot
                                                # DoT listener, DoH upstream
sudo ./build/dnska -u dns.google --upstream-doh --edns-padding
                                                # DoH upstream with EDNS padding
sudo ./build/dnska -u 8.8.8.8 --listen-doh --doh-listen-port 8053
                                                # add HTTP/1.1 POST /dns-query
sudo ./build/dnska -u dns.google --resolver-discovery
                                                # query _dns.dns.google SVCB
sudo ./build/dnska -u 1.1.1.1 --upstream-doh \
                   --tls-auth-name cloudflare-dns.com  # DoH over IP literal
```

## Client usage

```
./build/dnska -q example.com -u 1.1.1.1
./build/dnska -q example.com --type AAAA -u dns.google
./build/dnska -q example.com --upstream-doh -u dns.google
```

Exit codes: `0` on `NOERROR`, `2` on any other DNS rcode (e.g.
`NXDOMAIN`), `1` on parse/transport failure.

## Configuration

Loads `dnska.conf` from the working directory by default, or the path
given to `-c`/`--config`.  CLI flags override config values.

Section: `[dns]`.  `#` and `;` comments are accepted.  See
`dnska.conf.example` for the full annotated key list.

## CLI flags

| Flag | Description |
|------|-------------|
| `-c FILE` | Config file (default `dnska.conf`) |
| `-p PORT` | Listen port (default 53; 853 for DoT listener) |
| `--listen-mode M` | Listener mode: `auto`, `plain`, or `dot` |
| `--listen-doh` | Enable HTTP/1.1 DoH listener on `/dns-query` |
| `--doh-listen-port N` | DoH listener port (default `8053` when enabled) |
| `-u ADDR` | Upstream IP or hostname (default `8.8.8.8`); hostname implies DoT, port 853 |
| `--upstream-port N` | Override upstream port |
| `-t` | Force DoT upstream when using an IP-literal upstream |
| `--upstream-doh` | DoH (RFC 8484) upstream; implies TLS, default port 443 |
| `--doh-path PATH` | DoH URL path (default `/dns-query`) |
| `--edns-padding` | Pad outbound DoT/DoH DNS messages with EDNS(0) padding |
| `--edns-padding-block N` | Padding block size (default 128, max 512) |
| `--resolver-discovery` | Query `_dns.<name>` SVCB metadata for the configured upstream |
| `--resolver-discovery-name N` | Resolver name for SVCB discovery (default: upstream hostname or TLS auth name) |
| `--tls-cert FILE` | PEM cert for the DoT listener (auto self-signed if omitted) |
| `-k FILE` | PEM private key for the DoT listener (must be mode 0600) |
| `--tls-ca FILE` | CA bundle for upstream verification (default: system paths) |
| `--tls-auth-name N` | Override SNI / verify name for IP-literal DoT/DoH upstream |
| `--insecure` | Skip upstream cert verification (testing only) |
| `-q NAME` | Client mode: look up NAME and exit |
| `--type T` | RR type for `-q` (default A) |
| `--class C` | RR class for `-q` (default IN, only IN supported) |
| `-v` | Debug logging |
| `-h` | Help |

`--listen-mode auto` preserves legacy behavior: a DoT upstream selected by
hostname or `-t` also creates a DoT listener; DoH and plain upstreams create a
plain UDP+TCP listener.  `plain` and `dot` override only the listener side.
`--listen-doh` is independent and adds an HTTP/1.1 `POST /dns-query` listener
without changing the plain or DoT listener choice.

## Limitations

- No full DNSSEC validation yet.  DNSSEC records pass through, foundational
  DS/DNSKEY/RRSIG/NSEC/NSEC3 parsing exists, and the server clears `AD` unless
  a future local validator marks the response secure.
- No DoQ or ODoH transport yet; see `docs/modern-dns-roadmap.md`.
- DoH server listener accepts HTTP/1.1 `POST /dns-query` only; `GET` and other
  methods are rejected.  It is cleartext HTTP, so terminate TLS in front for
  HTTPS/RFC 8484 deployments.
- HTTP/1.1 only for DoH (no HTTP/2).
- DoH upstream connections are not pooled yet (HTTP/1.1 close per query);
  DoT uses a small bounded per-upstream TLS reuse pool.
- Forwarder, not a recursive resolver.
- `--insecure` accepts any upstream certificate; do not use outside
  testing.
