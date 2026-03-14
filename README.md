# Nooshdaroo

Censorship-resistant proxy that tunnels internet traffic through invisible channels.
One binary. No external dependencies at runtime.

## Quick Start — Connect in 3 Commands

```bash
# 1. Download
curl -LO https://nooshdaroo.net/dist/nooshdaroo-linux-x86_64
curl -LO https://nooshdaroo.net/dist/config.json
chmod +x nooshdaroo-linux-x86_64

# 2. Connect
./nooshdaroo-linux-x86_64 -c config.json

# 3. Use it
curl --proxy socks5h://127.0.0.1:1080 https://icanhazip.com
```

Pre-built binaries for Linux, macOS, and Windows: **[nooshdaroo.net/dist/](https://nooshdaroo.net/dist/)**

## How It Works

Nooshdaroo encodes TCP traffic inside ordinary network protocol messages —
primarily DNS queries and responses — making it appear as normal network
activity to observers. The protocol stack:

```
Application (browser, curl, etc.)
    ↓ SOCKS5
Nooshdaroo client (this binary)
    ↓ smux v2 (stream multiplexing)
    ↓ Noise_NK (authenticated encryption)
    ↓ KCP (reliable transport)
    ↓ Carrier encoding (base32 QNAME, TXT/CNAME/NULL RDATA)
Recursive resolver / network path
    ↓
Nooshdaroo server (authoritative endpoint)
    ↓ SOCKS5 (to destination)
Internet
```

### Multi-Record Type Support

The tunnel carrier supports multiple record types to maximize throughput
and evade filtering:

| Record Type | Direction | Capacity | Notes |
|-------------|-----------|----------|-------|
| **TXT** | Downstream | ~900 bytes/response | Primary. Highest capacity per query. |
| **CNAME** | Downstream | ~200 bytes/response | Fallback when TXT is filtered. |
| **NULL** | Downstream | ~900 bytes/response | Raw binary, fewer resolvers support it. |
| **AAAA** | Downstream | 16 bytes/response | Ultra-low profile, mimics IPv6 lookups. |
| **Base32 QNAME** | Upstream | ~150 bytes/query | All upstream data encoded in query names. |

The client automatically negotiates the best available record type based
on what the resolver and network path support.

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

The server is designed to handle thousands of concurrent users on a single
instance, with features for horizontal scaling across multiple IPs and processes:

- **Multi-IP binding** (`listen_addrs`): Bind multiple public IPs on one instance.
  Essential for anycast and multi-homed deployments.
- **TCP + UDP listeners** (`tcp_listen_addrs`): Accept both UDP/53 and TCP/53
  queries. TCP required for responses exceeding MTU.
- **Multi-key rotation** (`extra_privkeys`): Accept multiple Noise keypairs
  simultaneously. Enables zero-downtime key rotation — push a new key via OTA,
  then retire the old one.
- **Multi-domain** (`domains`): Serve multiple tunnel domains from one process.
- **SO_REUSEPORT** (`reuseport`): Run multiple server processes on the same
  port. Kernel distributes packets across workers for linear scaling.
- **Egress IP rotation** (`egress_ips`): Rotate outbound connections across
  multiple IPs to avoid per-IP rate limits on destination sites.
- **Configurable limits**: `max_streams` (default 4096) and `idle_timeout_sec`
  (default 120s) to tune resource usage per deployment.

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
      --scan-resolvers       Scan for working resolvers
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
- **Carrier**: base32 encoding in QNAME labels (upstream), TXT/CNAME/NULL RDATA (downstream)
- **KCP**: ARQ reliable transport over unreliable carrier
- **Noise_NK**: `Noise_NK_25519_ChaChaPoly_BLAKE2s` authenticated encryption
- **smux v2**: Stream multiplexing (multiple TCP connections over one tunnel)
- **SOCKS5**: Server-side proxy for outbound connections

### Roadmap

- **ICMP carrier**: Encode tunnel data inside ICMP Echo payloads. Available on
  desktop platforms where raw sockets are permitted. Useful when UDP/53 is
  blocked but ICMP (ping) passes freely.
- **HTTP carrier**: Encode data in HTTP request/response bodies via CDN front
  domains. Provides a fallback when all other carriers are blocked.

## Security

- All tunnel traffic is encrypted with Noise_NK (forward secrecy)
- Server identity verified via pre-shared public key
- No secrets compiled into the binary
- Cover traffic reduces fingerprinting risk

## License

MIT — see [LICENSE](LICENSE).

Copyright (c) 2025-2026 RostamVPN (Axion Networks Inc.)

## Acknowledgments

Wire-compatible with [dnstt](https://www.bamsoftware.com/software/dnstt/)
by David Fifield. Protocol design and Noise integration based on the
original Go implementation.
