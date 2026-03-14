# Nooshdaroo

Censorship-resistant proxy that tunnels internet traffic through invisible channels.
One binary. No external dependencies at runtime.

## Quick Start — Just Run It

The binary works with zero arguments — 10 tunnel domains and 8 resolvers are built in.

```bash
# Linux
curl -LO https://nooshdaroo.net/dist/nooshdaroo-linux-x86_64
chmod +x nooshdaroo-linux-x86_64
./nooshdaroo-linux-x86_64

# macOS (remove quarantine first)
curl -LO https://nooshdaroo.net/dist/nooshdaroo-macos-universal
chmod +x nooshdaroo-macos-universal
xattr -d com.apple.quarantine nooshdaroo-macos-universal
./nooshdaroo-macos-universal

# Then use the SOCKS5 proxy:
curl --proxy socks5h://127.0.0.1:1080 https://icanhazip.com
```

Pre-built binaries for Linux, macOS, and Windows: **[nooshdaroo.net/dist/](https://nooshdaroo.net/dist/)**

### If global resolvers are blocked

In some networks (Iran, Russia, China), public DNS resolvers like 8.8.8.8 are
blocked. Nooshdaroo can scan your local ISP network to find resolvers that work:

```bash
# Auto-detect your ISP and scan for working resolvers:
./nooshdaroo --scan-iran

# Or target a specific subnet:
./nooshdaroo --scan-cidr 5.160.100.0/24
./nooshdaroo --scan-cidr 151.246.0.0/16
```

The scanner detects your local IP, identifies your ISP (MCI, Irancell, TCI, Shatel,
etc.), and probes your /24 first, then expands outward. Working resolvers are cached
for next run.

## How It Works

Nooshdaroo encodes TCP traffic inside DNS queries (TXT records) and responses,
making it look like normal DNS resolution to network observers. The protocol stack:

```
Application (browser, curl, etc.)
    ↓ SOCKS5
Nooshdaroo client (this binary)
    ↓ smux v2 (stream multiplexing)
    ↓ Noise_NK (authenticated encryption)
    ↓ KCP (reliable transport)
    ↓ DNS queries (base32 in QNAME, data in TXT RDATA)
Recursive DNS resolver (8.8.8.8, etc.)
    ↓
Nooshdaroo server (authoritative for tunnel domain)
    ↓ SOCKS5 (to destination)
Internet
```

### Chrome Traffic Mimicry

Cover traffic mimics Chrome's network behavior:
- **AD=1 flag**: Authenticated Data flag (Chrome default since ~2020)
- **EDNS0 UDP size 1452**: Chrome's specific value, not the common 4096
- **A+AAAA+HTTPS query triplets**: Chrome sends all three for most domains
- **Burst timing**: Page-load bursts of 5–15 queries, then silence

### Carrier Flux

When multiple domains are configured, the client uses deterministic
time-based selection to rotate across a subset every 6 hours.
This spreads load and makes static blocking unreliable.

## Self-Host Your Own Server

### 1. Generate a keypair

```bash
./nooshdaroo-server --gen-key
# privkey: a1b2c3d4... (keep secret!)
# pubkey:  e5f6a7b8... (share with clients)
```

### 2. Set up DNS

Create an NS record pointing a subdomain to your server:

```
t.example.com.  NS  ns.example.com.
ns.example.com. A   <your-server-ip>
```

### 3. Start the server

```bash
# Using config file (recommended):
./nooshdaroo-server -c server-config.json

# Or using CLI flags:
./nooshdaroo-server --udp 0.0.0.0:53 --privkey <hex> t.example.com socks5
```

### 4. Connect a client

```bash
./nooshdaroo --domain t.example.com --pubkey <server-pubkey-hex> --resolver 8.8.8.8
```

### 5. Configure your browser

The client starts a SOCKS5 proxy on `127.0.0.1:1080` (configurable with `-p`).

- **Firefox**: Settings > Network > Manual Proxy > SOCKS Host: `127.0.0.1`, Port: `1080`
- **Chrome**: `chrome --proxy-server="socks5://127.0.0.1:1080"`
- **curl**: `curl --proxy socks5h://127.0.0.1:1080 https://example.com`

## Server — Built for Scale

The server handles thousands of concurrent users on a single instance, with
features for horizontal scaling:

- **Multi-IP binding** (`listen_addrs`): Bind multiple public IPs on one instance.
- **TCP + UDP listeners** (`tcp_listen_addrs`): Accept both UDP/53 and TCP/53.
- **Multi-key rotation** (`extra_privkeys`): Accept multiple Noise keypairs
  simultaneously for zero-downtime key rotation.
- **Multi-domain** (`domains`): Serve multiple tunnel domains from one process.
- **SO_REUSEPORT** (`reuseport`): Run multiple server processes on the same port.
- **Egress IP rotation** (`egress_ips`): Rotate outbound connections across IPs.
- **Configurable limits**: `max_streams` (default 4096) and `idle_timeout_sec` (default 120s).

Example production server config:

```json
{
  "server_id": "prod-fra-01",
  "listen": "0.0.0.0:53",
  "privkey": "<primary-key-hex>",
  "extra_privkeys": ["<rotated-key-hex>"],
  "upstream": "socks5",
  "domains": ["t.example.com", "t.backup.example.com"],
  "reuseport": true,
  "max_streams": 4096,
  "idle_timeout_sec": 120,
  "listen_addrs": ["203.0.113.1:53", "203.0.113.2:53"],
  "tcp_listen_addrs": ["203.0.113.1:53"],
  "egress_ips": ["203.0.113.1", "203.0.113.2"]
}
```

## Client Options

```
nooshdaroo [OPTIONS]

Options:
  -p, --port <PORT>          SOCKS5 listen port [default: 1080]
  -b, --bind <ADDR>          SOCKS5 listen address [default: 127.0.0.1]
  -c, --config <PATH>        JSON config file path
      --domain <DOMAIN>      Tunnel domain
      --pubkey <HEX>         Server public key (32 bytes hex)
      --resolver <IP>        Force a specific resolver
      --tunnels <N>          Parallel tunnels [default: 2]
      --scan-resolvers       Scan well-known resolvers for working ones
      --scan-iran            Scan Iran IP ranges for resolvers (auto-detects ISP)
      --scan-cidr <CIDR>     Scan a specific CIDR for resolvers (e.g. "5.160.0.0/16")
      --ota-refresh          Fetch OTA config update
      --ota-domain <DOMAIN>  OTA config domain
      --ota-nonce <NONCE>    OTA decryption nonce (12 chars)
      --no-cover             Disable cover traffic
      --show-config          Show configuration and exit
  -v, --verbose              Debug logging
  -q, --quiet                Suppress banner output
  -h, --help                 Print help
  -V, --version              Print version
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
      --mtu <SIZE>           Max response UDP payload [default: 1232]
      --reuseport            Enable SO_REUSEPORT
      --blocklist <FILE>     Domain blocklist file
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
      "udp_resolvers": ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    }
  },
  "cover_domains": ["www.google.com", "www.youtube.com"]
}
```

## OTA Config Updates

Operators can push configuration updates via encrypted TXT records. This allows
updating domain lists, resolver lists, and settings without releasing
new client binaries.

The config is encrypted with ChaCha20-Poly1305 and chunked into TXT records.
The client fetches and decrypts it with the `--ota-domain` and `--ota-nonce` flags.

```bash
pip3 install cryptography boto3

# Publish config to Route53:
python3 tools/publish-ota.py config.json \
  --zone-id <ROUTE53_ZONE_ID> \
  --domain _cfg.yourdomain.com \
  --nonce "your12charnc"

# Verify published records:
python3 tools/publish-ota.py --verify \
  --domain _cfg.yourdomain.com \
  --nonce "your12charnc"

# Fetch and dump existing config:
python3 tools/publish-ota.py --fetch \
  --domain _cfg.yourdomain.com \
  --nonce "your12charnc"
```

## Building

```bash
# Client
cd client && cargo build --release
# Binary: target/release/nooshdaroo

# Server
cd server && cargo build --release
# Binary: target/release/nooshdaroo-server
```

### Cross-compilation (Linux server from macOS)

```bash
rustup target add x86_64-unknown-linux-musl
cd server && cargo build --release --target x86_64-unknown-linux-musl
```

## Architecture

### Wire Protocol

Wire-compatible with the Go [dnstt](https://www.bamsoftware.com/software/dnstt/)
implementation. You can use a Go dnstt-server with a Nooshdaroo client,
or vice versa.

**Protocol stack:**
- **Carrier**: base32 encoding in QNAME labels (upstream), TXT RDATA (downstream)
- **KCP**: ARQ reliable transport over unreliable carrier
- **Noise_NK**: `Noise_NK_25519_ChaChaPoly_BLAKE2s` authenticated encryption
- **smux v2**: Stream multiplexing (multiple TCP connections over one tunnel)
- **SOCKS5**: Server-side proxy for outbound connections

### Iran Resolver Scanner

The client embeds CIDR ranges for 8 major Iranian ISPs (MCI, Irancell, TCI, DCI,
Rightel, Shatel, ParsOnline, Asiatech). When `--scan-iran` is used:

1. Detects local IP via UDP socket introspection
2. Identifies the user's ISP from embedded CIDR→ASN mapping
3. Scans user's /24 first (254 IPs, <1s)
4. Expands to /16 with common resolver octets (.1, .2, .10, .100, .200)
5. Falls back to 20+ pre-verified Iran resolver IPs
6. Caches working resolvers in `~/.config/nooshdaroo/` for next run

## Security

- All tunnel traffic is encrypted with Noise_NK (forward secrecy)
- Server identity verified via pre-shared public key
- No secrets compiled into the binary
- Cover traffic reduces fingerprinting risk

## Contributing

Nooshdaroo is open source and we welcome contributions. Here are areas where
help is especially valuable:

### Wanted: Multi-Record Type Support

Currently the tunnel uses **TXT records only** for downstream data. Adding
alternative record types would improve resilience when TXT is filtered:

| Record Type | Capacity | Why it helps |
|-------------|----------|--------------|
| **CNAME** | ~200 bytes/response | Looks like normal CDN traffic. Many networks that filter TXT leave CNAME alone. |
| **NULL (type 10)** | ~900 bytes/response | Raw binary payload, same capacity as TXT. Less common so less likely to be filtered. |
| **AAAA** | 16 bytes/response | Ultra-low profile — indistinguishable from IPv6 lookups. Low throughput but very stealthy. |
| **MX** | ~200 bytes/response | Looks like email routing. Rarely filtered. |

The client would negotiate record type with the server during the Noise handshake,
then fall back through types until one works. Server changes needed in `dns.rs`,
client changes in `dns_codec.rs`. See `server/src/dns.rs:568` for where TXT-only
filtering currently happens.

### Wanted: ICMP Carrier

Encode tunnel data inside ICMP Echo (ping) payloads. Useful when UDP/53 is
blocked but ICMP passes freely. Requires `CAP_NET_RAW` on Linux or root on macOS.
Would be a new carrier module alongside the DNS carrier.

### Wanted: DNS-over-HTTPS (DoH) Transport

Use DoH (RFC 8484) as the carrier instead of raw UDP/53. This wraps tunnel queries
inside HTTPS to well-known DoH providers (Cloudflare, Google), making them
indistinguishable from normal encrypted DNS traffic.

### Wanted: Load Balancer (dnstt-lb)

A lightweight UDP proxy that sits between the network edge and multiple
`nooshdaroo-server` workers. Extracts the 8-byte ClientID from the QNAME,
uses rendezvous hashing for sticky routing, and rewrites DNS transaction IDs
to avoid collisions. Enables horizontal scaling to 4–8x capacity per IP.

### How to contribute

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/cname-records`)
3. Implement your changes with tests
4. Submit a PR with a clear description

## License

MIT — see [LICENSE](LICENSE).

Copyright (c) 2025-2026 RostamVPN (Axion Networks Inc.)

## Acknowledgments

Wire-compatible with [dnstt](https://www.bamsoftware.com/software/dnstt/)
by David Fifield. Protocol design and Noise integration based on the
original Go implementation.
