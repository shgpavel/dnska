# dnska

Forwarding DNS server with an in-memory LRU cache, DoT and DoH upstream
support (RFC 7858 / RFC 8484), DNSSEC pass-through, and a built-in
`dig`-style client.

## Features

- UDP, TCP, and DoT listeners on IPv4 and IPv6
- Plain UDP (with TCP fallback on TC=1), DoT (RFC 7858), or DoH (RFC 8484)
  upstream
- Upstream certificate verification by default; system trust paths or
  `--tls-ca`; SNI/verify-name override via `--tls-auth-name`
- Multi-address upstream with failover (up to four resolved addresses)
- DNSSEC pass-through: client `CD`/`AD` bits forwarded; OPT with `DO=1`
  always sent upstream so RRSIGs can flow back
- LRU cache with EDNS-aware keys, negative caching via SOA, cached
  upstream `SERVFAIL`
- Built-in `-q` client mode (no server) with a `dig`-style printer
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
| `-u ADDR` | Upstream IP or hostname (default `8.8.8.8`); hostname implies DoT, port 853 |
| `--upstream-port N` | Override upstream port |
| `-t` | Force DoT upstream when using an IP-literal upstream |
| `--upstream-doh` | DoH (RFC 8484) upstream; implies TLS, default port 443 |
| `--doh-path PATH` | DoH URL path (default `/dns-query`) |
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

## Limitations

- No DNSSEC validation (pass-through only — RRSIGs reach the client but
  signatures are not verified locally; trust the upstream's `AD` bit).
- No DoH server listener (only DoH client/upstream).
- HTTP/1.1 only for DoH (no HTTP/2).
- No upstream connection pooling (one TLS connection per query).
- Forwarder, not a recursive resolver.
- `--insecure` accepts any upstream certificate; do not use outside
  testing.
