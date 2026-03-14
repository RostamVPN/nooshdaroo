# Nooshdaroo

Censorship-resistant SOCKS5 proxy that tunnels traffic through DNS queries.
One binary. No external dependencies at runtime.

## How it works

Nooshdaroo encodes TCP traffic inside DNS queries (TXT records) and responses,
making it look like normal DNS resolution to network observers. The protocol
stack:

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
cargo run --release -- --domain t.example.com --pubkey <server-pubkey-hex> --resolver 8.8.8.8

# With a config file:
cargo run --release -- --config client-config.json

# Find working resolvers automatically:
cargo run --release -- --domain t.example.com --pubkey <hex> --scan-resolvers
```

### 5. Configure your browser

The client starts a SOCKS5 proxy on `127.0.0.1:1080` (configurable with `-p`).

- **Firefox**: Settings > Network > Manual Proxy > SOCKS Host: `127.0.0.1`, Port: `1080`
- **Chrome**: `chrome --proxy-server="socks5://127.0.0.1:1080"`
- **curl**: `curl --proxy socks5h://127.0.0.1:1080 https://example.com`

## Client Options

```
nooshdaroo [OPTIONS]

Options:
  -p, --port <PORT>          SOCKS5 listen port [default: 1080]
  -b, --bind <ADDR>          SOCKS5 listen address [default: 127.0.0.1]
  -c, --config <PATH>        JSON config file path
      --domain <DOMAIN>      DNSTT tunnel domain
      --pubkey <HEX>         Server public key (32 bytes hex)
      --resolver <IP>        Force a specific DNS resolver
      --tunnels <N>          Parallel tunnels [default: 2]
      --scan-resolvers       Scan for working resolvers
      --ota-refresh          Fetch OTA config update
      --ota-domain <DOMAIN>  OTA config DNS domain
      --ota-nonce <NONCE>    OTA decryption nonce (12 chars)
      --no-cover             Disable Chrome DNS cover traffic
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
      --mtu <SIZE>           Max DNS response UDP payload [default: 1232]
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
```

### Cross-compilation (Linux server from macOS)

```bash
rustup target add x86_64-unknown-linux-gnu
cd server && cargo build --release --target x86_64-unknown-linux-gnu
```

## Architecture

### Wire Protocol

The client and server are wire-compatible with the Go
[dnstt](https://www.bamsoftware.com/software/dnstt/) implementation.
You can use a Go dnstt-server with a Nooshdaroo client, or vice versa.

**Protocol stack:**
- **DNS carrier**: base32 encoding in QNAME labels (upstream), TXT RDATA (downstream)
- **KCP**: ARQ reliable transport over unreliable DNS
- **Noise_NK**: `Noise_NK_25519_ChaChaPoly_BLAKE2s` authenticated encryption
- **smux v2**: Stream multiplexing (multiple TCP connections over one tunnel)
- **SOCKS5**: Server-side SOCKS5 proxy for outbound connections

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

## Security

- All tunnel traffic is encrypted with Noise_NK (forward secrecy)
- Server identity verified via pre-shared public key
- No secrets compiled into the binary
- Cover traffic reduces DNS fingerprinting risk

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

Wire-compatible with [dnstt](https://www.bamsoftware.com/software/dnstt/)
by David Fifield. Protocol design and Noise integration based on the
original Go implementation.
