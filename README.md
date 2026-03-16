# Nooshdaroo

Censorship-resistant SOCKS5 proxy that tunnels traffic through DNS queries.
One binary. No external dependencies at runtime.

## How it works

Nooshdaroo encodes TCP traffic inside DNS queries (TXT records) and responses,
making it look like normal DNS resolution to network observers. Two transport
modes are available:

```
Application (browser, curl, etc.)
    |  SOCKS5
Nooshdaroo client
    |  smux v2 (stream multiplexing)
    |  Noise_NK (authenticated encryption)
    |  KCP (reliable transport)
    |
    +---> UDP/53 mode: raw DNS queries to recursive resolvers
    |         base32 in QNAME (upstream), TXT RDATA (downstream)
    |
    +---> DoH mode (--doh): HTTPS POST to Google/Cloudflare/Quad9
              same DNS wire format, wrapped in TLS
              indistinguishable from normal encrypted DNS
    |
Recursive DNS resolver / DoH provider
    |
Nooshdaroo server (authoritative for tunnel domain)
    |  SOCKS5 (to destination)
Internet
```

Chrome DNS cover traffic is generated alongside tunnel queries to make the
traffic pattern look like a normal Chromium browser doing DNS lookups.

## Quick Start

### 1. Generate a keypair

```bash
cd server
cargo run --release -- --gen-key
# Output:
# privkey a1b2c3d4...
# pubkey  e5f6a7b8...
```

Save the private key for the server, share the public key with clients.

### 2. Set up DNS

Create an NS record pointing a subdomain to your server:

```
t.example.com.  NS  ns.example.com.
ns.example.com. A   <your-server-ip>
```

### 3. Start the server

```bash
# Using config file (recommended):
cargo run --release -- -c server-config.json

# Or using CLI flags:
cargo run --release -- --udp 0.0.0.0:53 --privkey <hex> t.example.com socks5
```

Example `server-config.json`:
```json
{
  "server_id": "my-server",
  "listen": "0.0.0.0:53",
  "privkey": "<your-private-key-hex>",
  "upstream": "socks5",
  "domains": ["t.example.com"]
}
```

### 4. Start the client

```bash
# Minimal — connect to your server:
nooshdaroo --domain t.example.com --pubkey <server-pubkey-hex> --resolver 8.8.8.8

# With DNS-over-HTTPS (harder to detect):
nooshdaroo --domain t.example.com --pubkey <hex> --doh

# With a config file:
nooshdaroo --config config.json

# Find working resolvers automatically:
nooshdaroo --domain t.example.com --pubkey <hex> --scan-resolvers

# Scan your country's IP space for open resolvers:
nooshdaroo --scan-iran
nooshdaroo --scan-russia
nooshdaroo --scan-isp MCI
```

### 5. Configure your browser

The client starts a SOCKS5 proxy on `127.0.0.1:1080` (configurable with `-p`).

- **Firefox**: Settings > Network > Manual Proxy > SOCKS Host: `127.0.0.1`, Port: `1080`
- **Chrome**: `chrome --proxy-server="socks5://127.0.0.1:1080"`
- **curl**: `curl --proxy socks5h://127.0.0.1:1080 https://example.com`

## Client Options

```
nooshdaroo [OPTIONS]

Transport:
  -c, --config <PATH>          JSON config file path
      --domain <DOMAIN>        DNSTT tunnel domain
      --pubkey <HEX>           Server public key (32 bytes hex)
      --resolver <IP>          Force a specific DNS resolver
      --tunnels <N>            Parallel tunnels [default: 2]
      --doh                    Use DNS-over-HTTPS instead of raw UDP
      --doh-provider <NAME>    DoH provider: google, cloudflare, quad9, or URL

Resolver discovery:
      --scan-resolvers         Scan well-known resolvers for tunnel connectivity
      --scan-iran              Scan Iran IP ranges for open resolvers
      --scan-russia            Scan Russia IP ranges for open resolvers
      --scan-isp <ISP>         Scan a specific ISP (by name or ASN)
      --scan-cidr <CIDR>       Scan a specific CIDR range
      --list-isps              Show all known ISPs with ASN numbers

OTA config:
      --ota-refresh            Fetch OTA config update
      --ota-domain <DOMAIN>    OTA config DNS domain
      --ota-nonce <NONCE>      OTA decryption nonce (12 chars)

General:
  -p, --port <PORT>            SOCKS5 listen port [default: 1080]
  -b, --bind <ADDR>            SOCKS5 listen address [default: 127.0.0.1]
      --no-cover               Disable Chrome DNS cover traffic
      --show-config            Show configuration and exit
  -v, --verbose                Debug logging
  -q, --quiet                  Suppress banner output
  -h, --help                   Print help
  -V, --version                Print version
```

## Server Options

```
nooshdaroo-server [OPTIONS] [DOMAIN UPSTREAM]

Options:
      --gen-key              Generate keypair and exit
  -c, --config <FILE>        JSON config file
      --udp <ADDR>           UDP listen address (legacy mode)
      --privkey <HEX>        Private key as hex
      --privkey-file <FILE>  Read private key from file
      --pubkey-file <FILE>   Write public key to file (with --gen-key)
      --mtu <SIZE>           Max DNS response UDP payload [default: 1232]
      --reuseport            Enable SO_REUSEPORT
      --blocklist <FILE>     Domain blocklist file
```

## Load Balancer (dnstt-lb)

A lightweight UDP proxy for horizontal scaling. Sits between the network
edge and multiple `nooshdaroo-server` workers.

```
Internet --> [dnstt-lb :53] --+--> [nooshdaroo-server :5301]
                              +--> [nooshdaroo-server :5302]
                              +--> [nooshdaroo-server :5303]
                              +--> [nooshdaroo-server :5304]
```

How it works:
- Extracts the 8-byte ClientID from the DNS QNAME
- Uses **rendezvous hashing** (Highest Random Weight) for sticky routing
- Same client always hits the same backend (required for KCP session state)
- On backend failure, only that backend's clients get remapped
- Rewrites DNS transaction IDs to avoid collisions between backends
- Health checks backends periodically

```bash
# 4 backend workers on one machine:
dnstt-lb -l 0.0.0.0:53 \
  -b 127.0.0.1:5301 -b 127.0.0.1:5302 \
  -b 127.0.0.1:5303 -b 127.0.0.1:5304

# With domain filter:
dnstt-lb -l 0.0.0.0:53 -b 127.0.0.1:5301 -b 127.0.0.1:5302 \
  -d t.cdn.example.com

# Multiple listen IPs (multi-homed host):
dnstt-lb -l 203.0.113.1:53 -l 203.0.113.2:53 \
  -b 127.0.0.1:5301 -b 127.0.0.1:5302
```

```
dnstt-lb [OPTIONS]

Options:
  -l, --listen <ADDR>          Listen address [default: 0.0.0.0:53]
  -b, --backend <ADDR>         Backend server address (repeatable)
  -d, --domain <DOMAIN>        Only route queries matching this domain
      --reuseport              Enable SO_REUSEPORT
      --health-interval <SEC>  Health check interval [default: 10]
      --stats-interval <SEC>   Stats log interval [default: 60]
```

## Config File Format

### Client config (`config.json`)

```json
{
  "transport": {
    "dnstt": {
      "domains": [
        {"domain": "t.example.com", "pubkey": "<hex>"},
        {"domain": "t.backup.example.com", "pubkey": "<hex>"}
      ],
      "udp_resolvers": ["8.8.8.8", "1.1.1.1", "9.9.9.9"],
      "doh_resolvers": [
        "https://dns.google/dns-query",
        "https://cloudflare-dns.com/dns-query"
      ]
    }
  },
  "cover_domains": ["www.google.com", "www.youtube.com"]
}
```

When `doh_resolvers` is present, the client uses DNS-over-HTTPS automatically.
This is equivalent to running with `--doh`. The `udp_resolvers` field is
ignored when DoH is active.

### Server config (`server-config.json`)

```json
{
  "server_id": "my-server",
  "listen": "0.0.0.0:53",
  "privkey": "<hex-encoded-32-byte-private-key>",
  "upstream": "socks5",
  "domains": ["t.example.com"],
  "reuseport": false,
  "idle_timeout_sec": 120,
  "max_streams": 4096,
  "listen_addrs": ["203.0.113.1:53", "203.0.113.2:53"],
  "tcp_listen_addrs": ["203.0.113.1:53"],
  "egress_ips": ["203.0.113.1", "203.0.113.2"]
}
```

## OTA Config Updates

Operators can push configuration updates via DNS TXT records. This allows
updating domain lists, resolver lists, and cover domains without releasing
new client binaries.

The config is encrypted with ChaCha20-Poly1305 and chunked into DNS TXT
records. The client fetches and decrypts it with the `--ota-domain` and
`--ota-nonce` flags.

## Building

```bash
# Client
cd client && cargo build --release
# Binary: target/release/nooshdaroo

# Server
cd server && cargo build --release
# Binary: target/release/nooshdaroo-server

# Load balancer
cd lb && cargo build --release
# Binary: target/release/dnstt-lb
```

### Cross-compilation (Linux server from macOS)

```bash
rustup target add x86_64-unknown-linux-gnu
cd server && cargo build --release --target x86_64-unknown-linux-gnu
cd lb && cargo build --release --target x86_64-unknown-linux-gnu
```

## Architecture

### Wire Protocol

The client and server are wire-compatible with the Go
[dnstt](https://www.bamsoftware.com/software/dnstt/) implementation.
You can use a Go dnstt-server with a Nooshdaroo client, or vice versa.

**Protocol stack:**
- **DNS carrier**: base32 encoding in QNAME labels (upstream), TXT RDATA (downstream)
- **DoH carrier** (optional): same DNS wire format over HTTPS POST (RFC 8484)
- **KCP**: ARQ reliable transport over unreliable DNS
- **Noise_NK**: `Noise_NK_25519_ChaChaPoly_BLAKE2s` authenticated encryption
- **smux v2**: Stream multiplexing (multiple TCP connections over one tunnel)
- **SOCKS5**: Server-side SOCKS5 proxy for outbound connections

### DNS-over-HTTPS (DoH)

When `--doh` is enabled, tunnel queries are sent as HTTPS POST requests
to well-known DoH providers instead of raw UDP to recursive resolvers.

| Provider   | Endpoint                              |
|------------|---------------------------------------|
| Google     | `https://dns.google/dns-query`        |
| Cloudflare | `https://cloudflare-dns.com/dns-query`|
| Quad9      | `https://dns.quad9.net:5053/dns-query`|

Queries use `Content-Type: application/dns-message` per RFC 8484 and HTTP/2.
The DoH provider forwards the query to the authoritative nooshdaroo-server
just like any recursive resolver would. No server-side changes needed.

**Trade-offs:**
- Harder to detect and block (looks like normal encrypted DNS)
- ~50-100ms additional latency per query (TLS round-trip)
- Providers are rotated round-robin with automatic fallback

### Chrome DNS Fingerprinting

The cover traffic generator mimics Chrome's DNS behavior:
- **AD=1 flag**: Chrome sets the "Authenticated Data" flag (since ~2020)
- **EDNS0 UDP size 1452**: Chrome's default, not the common 4096
- **A+AAAA+HTTPS query pairs**: Chrome sends all three for most domains
- **Burst timing**: Page-load bursts of 5-15 queries, then silence

### DNS Flux

When multiple domains are configured, the client uses deterministic
time-based selection (DNS Flux) to pick a subset for each 6-hour period.
This spreads load across domains and makes blocking harder.

### Scaling with dnstt-lb

For high-traffic deployments, `dnstt-lb` enables horizontal scaling:

```
                     dnstt-lb
                    +--------+
 UDP :53 ---------> | ClientID |----> worker :5301 (KCP sessions A, D, G)
                    | extract  |----> worker :5302 (KCP sessions B, E, H)
                    | + HRW    |----> worker :5303 (KCP sessions C, F, I)
                    +--------+
```

Each nooshdaroo-server worker maintains independent KCP/Noise session state.
The load balancer ensures the same ClientID always routes to the same worker
using rendezvous hashing (consistent even when workers are added or removed).
Transaction IDs are rewritten to prevent collisions across workers.

## Security

- All tunnel traffic is encrypted with Noise_NK (forward secrecy)
- Server identity verified via pre-shared public key
- No secrets compiled into the binary
- Cover traffic reduces DNS fingerprinting risk
- DoH mode wraps all tunnel queries in TLS

## License

MIT — see [LICENSE](LICENSE).

Copyright (c) 2026 Internet Mastering & Company, Inc.

## Acknowledgments

Wire-compatible with [dnstt](https://www.bamsoftware.com/software/dnstt/)
by David Fifield. Protocol design and Noise integration based on the
original Go implementation.
