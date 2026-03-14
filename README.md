# Nooshdaroo

**Censorship-resistant SOCKS5 proxy. Tunnels your internet through DNS.**

Nooshdaroo (نوشدارو — "the antidote") creates a local SOCKS5 proxy on your computer that routes traffic through DNS queries, bypassing internet censorship. Your traffic looks like normal DNS to network observers.

```
You  →  nooshdaroo (localhost:1080)  →  DNS queries  →  Free internet
```

**982 KB binary. No install. No admin rights. No VPN driver.**

---

## Quick Start

### 1. Download

| Platform | Download |
|----------|----------|
| **Windows** | [nooshdaroo-windows-x86_64.exe](https://rostam.app/dist/nooshdaroo/nooshdaroo-windows-x86_64.exe) |
| **macOS (Apple Silicon)** | [nooshdaroo-macos-aarch64](https://rostam.app/dist/nooshdaroo/nooshdaroo-macos-aarch64) |
| **macOS (Intel)** | [nooshdaroo-macos-x86_64](https://rostam.app/dist/nooshdaroo/nooshdaroo-macos-x86_64) |
| **macOS (Universal)** | [nooshdaroo-macos-universal](https://rostam.app/dist/nooshdaroo/nooshdaroo-macos-universal) |
| **Linux x86_64** | [nooshdaroo-linux-x86_64](https://rostam.app/dist/nooshdaroo/nooshdaroo-linux-x86_64) |
| **Android (Termux)** | [nooshdaroo-linux-aarch64](https://rostam.app/dist/nooshdaroo/nooshdaroo-linux-aarch64) |

Mirror: [nooshdaroo.net/dl/](https://nooshdaroo.net/dl/)

[SHA256 checksums](https://rostam.app/dist/nooshdaroo/SHA256SUMS) &nbsp;|&nbsp; GPG key: `F6DFBB0692DEF57F970B982E29665CE0835FADAC`

### 2. Download dnstt-client

Nooshdaroo needs the `dnstt-client` binary alongside it. Download it from:
https://www.bamsoftware.com/software/dnstt/

Place `dnstt-client` (or `dnstt-client.exe` on Windows) in the **same folder** as `nooshdaroo`.

### 3. Run

**Windows:**
```
nooshdaroo.exe
```

**macOS / Linux:**
```bash
chmod +x nooshdaroo dnstt-client
./nooshdaroo
```

**Termux (Android):**
```bash
chmod +x nooshdaroo dnstt-client
./nooshdaroo
```

You'll see:
```
  Nooshdaroo

  v1.0.0  |  https://nooshdaroo.net
  Censorship-resistant SOCKS5 proxy  |  by RostamVPN

  Transport   DNSTT (DNS tunnel over UDP/53)
  Resolver    172.65.191.88
  Domains     27 available

  Connecting...  domain: t.cdn.cdncache-eu.net  resolver: 172.65.191.88

  SOCKS5 proxy ready
  127.0.0.1:1080

  Press Ctrl+C to disconnect.
```

### 4. Configure your browser

#### Firefox (recommended)
1. Open **Settings**
2. Scroll to **Network Settings** → click **Settings...**
3. Select **Manual proxy configuration**
4. Set **SOCKS Host**: `127.0.0.1` &nbsp; **Port**: `1080`
5. Select **SOCKS v5**
6. Check **Proxy DNS when using SOCKS v5** (important!)
7. Click **OK**

#### Chrome / Edge / Brave
Launch with the proxy flag:
```
chrome --proxy-server="socks5://127.0.0.1:1080"
```
Or install a proxy extension like **FoxyProxy** and set SOCKS5 to `127.0.0.1:1080`.

#### System-wide (macOS)
System Settings → Network → Wi-Fi → Proxies → SOCKS Proxy → `127.0.0.1:1080`

#### System-wide (Windows)
Use [Proxifier](https://www.proxifier.com/) or similar to route all traffic through `127.0.0.1:1080`.

### 5. Verify it works

```bash
curl --proxy socks5h://127.0.0.1:1080 https://check.torproject.org/api/ip
```

You should see an IP address that is NOT your real IP.

---

## Usage

```
nooshdaroo [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-p, --port <PORT>` | SOCKS5 listen port (default: 1080) |
| `-b, --bind <ADDR>` | Listen address (default: 127.0.0.1) |
| `--dnstt-client <PATH>` | Path to dnstt-client binary |
| `--domain <DOMAIN>` | Force a specific tunnel domain |
| `--resolver <IP>` | Force a specific DNS resolver |
| `--scan` | Try all domains until one connects |
| `--show-config` | Show embedded server list and exit |
| `-v, --verbose` | Show debug output |
| `-q, --quiet` | Suppress banner |
| `-V, --version` | Print version |

### Examples

```bash
# Default — random domain, Spectrum resolver, port 1080
nooshdaroo

# Use a specific port
nooshdaroo -p 9050

# Try all 27 domains until one works (useful if some are blocked)
nooshdaroo --scan

# Force a specific domain and resolver
nooshdaroo --domain t.f14.1e-100.net --resolver 8.8.8.8

# See what servers are available
nooshdaroo --show-config
```

---

## How it works

```
┌─────────────────────────────────────────────────────────────────┐
│  Your computer                                                  │
│                                                                 │
│  Browser ──► nooshdaroo (SOCKS5 on 127.0.0.1:1080)             │
│                  │                                              │
│                  ▼                                              │
│  dnstt-client ──► DNS queries to resolver (looks like normal    │
│                   DNS traffic to anyone watching)               │
│                                                                 │
│                  │                                              │
│                  ▼                                              │
│  DNS Resolver ──► DNSTT Server ──► Free Internet                │
│                                                                 │
│  Observer sees: DNS queries to 172.65.x.x on port 53           │
│  Observer does NOT see: what websites you visit                 │
└─────────────────────────────────────────────────────────────────┘
```

Nooshdaroo tunnels your internet traffic inside DNS queries. To network observers (ISPs, firewalls, censors), it looks like your computer is making normal DNS lookups. The actual content of your browsing is encrypted and hidden inside those queries.

### What makes it hard to block

- **DNS is essential infrastructure** — blocking all DNS breaks the entire internet
- **27 tunnel domains** — if one is blocked, Nooshdaroo rotates to the next
- **66 DNS resolvers** — including Cloudflare Spectrum anycast IPs that serve millions of regular users
- **Queries look normal** — same port (53), same protocol (DNS), same resolvers everyone uses

---

## Troubleshooting

### "dnstt-client binary not found"

Make sure `dnstt-client` (or `dnstt-client.exe`) is in the same folder as `nooshdaroo`. Or specify the path:
```
nooshdaroo --dnstt-client /path/to/dnstt-client
```

### Connection fails immediately

Try scanning all domains:
```
nooshdaroo --scan
```

Or try a different resolver (some ISPs block specific DNS resolvers):
```
nooshdaroo --resolver 8.8.8.8
nooshdaroo --resolver 1.1.1.1
nooshdaroo --resolver 9.9.9.9
```

### Connected but websites don't load

Make sure you enabled **"Proxy DNS when using SOCKS v5"** in Firefox. Without this, DNS queries bypass the tunnel and may be blocked or reveal your browsing.

### Slow speeds

DNS tunneling has inherent bandwidth limitations (~50-200 KB/s typical). It's designed for text browsing, messaging, and basic web use — not streaming or large downloads. Tips:
- Use Firefox Reader Mode for articles
- Disable images in browser settings for faster text browsing
- Avoid video streaming

### macOS: "cannot be opened because the developer cannot be verified"

```bash
xattr -d com.apple.quarantine ./nooshdaroo
xattr -d com.apple.quarantine ./dnstt-client
```

### Linux: Permission denied

```bash
chmod +x nooshdaroo dnstt-client
```

---

## For Iran users / برای کاربران ایران

### شروع سریع

۱. فایل `nooshdaroo` و `dnstt-client` را دانلود کنید

۲. هر دو فایل را در یک پوشه قرار دهید

۳. اجرا کنید:
```
./nooshdaroo
```

۴. تنظیمات فایرفاکس:
   - تنظیمات ← شبکه ← تنظیمات دستی پروکسی
   - SOCKS Host: `127.0.0.1` &nbsp; Port: `1080`
   - تیک "Proxy DNS when using SOCKS v5" را بزنید

۵. تست:
```
curl --proxy socks5h://127.0.0.1:1080 https://check.torproject.org/api/ip
```

### نکات مهم

- اگر یک دامنه کار نکرد، از `--scan` استفاده کنید تا همه دامنه‌ها امتحان شوند
- سرعت DNS tunneling محدود است (~50-200 KB/s) — برای مرور متن و پیام‌رسانی مناسب است
- برای Termux روی اندروید هم کار می‌کند

### ریزالور‌های ایران

اگر ریزالورهای پیش‌فرض کار نکردند:
```
nooshdaroo --resolver 178.22.122.100
nooshdaroo --resolver 10.202.10.10
```

---

## Verify downloads

```bash
# Check SHA256
sha256sum -c SHA256SUMS

# Verify GPG signature
gpg --keyserver keys.openpgp.org --recv-keys F6DFBB0692DEF57F970B982E29665CE0835FADAC
gpg --verify SHA256SUMS.asc SHA256SUMS
```

## Build from source

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
git clone https://github.com/ArsalanDotMe/nooshdaroo
cd nooshdaroo
cargo build --release

# Binary at: target/release/nooshdaroo
```

Or install from crates.io:
```bash
cargo install nooshdaroo
```

---

## License

GPL-3.0 — Free software for a free internet.

https://nooshdaroo.net &nbsp;|&nbsp; https://rostam.app

Built with love by the RostamVPN team.
