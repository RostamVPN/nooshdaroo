# Multi-QTYPE DNS Tunnel — Censorship Adaptation

## Problem (2026-03-16)

Iran blocked TXT records on major resolvers. Cloudflare Radar data shows:
- **A: 97.3%** of all DNS queries
- **TXT: 0.2%** — trivial to filter
- **NULL: 0%** — even more anomalous
- By Mar 17, Iran enforces **A-only** on some resolvers (100% A, 0% everything else)
- Response codes: 47.7% SERVFAIL, 40.2% NXDOMAIN — heavy interference

Our DNSTT tunnel using TXT records is a giant fingerprint in a sea of A queries.

## Solution: A-Record Tunnel

### Why A records?
- **97.3% of all DNS traffic** — completely invisible
- Censors cannot block A records without breaking the internet
- CDNs routinely return many A records (google.com returns 4-6 IPs)
- 50+ A records in one response looks like a CDN or load balancer

### Capacity math
- Each A record = 4 bytes payload, 16 bytes on wire (name+type+class+TTL+rdlen+rdata)
- Chrome EDNS0 limit: 1452 bytes
- After header/question/EDNS overhead (~53 bytes): ~1400 bytes for answers
- **~87 A records per response = ~348 bytes downstream**
- TXT was ~1000 bytes/response → A is ~35% of TXT capacity

### Compensating for lower capacity
1. **More concurrent tunnels** — 3-4x parallel DNS sessions to match TXT throughput
2. **Smarter KCP tuning** — smaller window, faster ACKs, less overhead per packet
3. **Domain rotation** — spread queries across many domains to avoid per-domain rate limits

### Subdomain fingerprint: replace `.t.` with diverse prefixes
Current: `<data>.t.cdn.example.com` — the `.t.` prefix is a fingerprint.
New: randomize from a list of common subdomains:
- `api`, `www`, `cdn`, `img`, `static`, `assets`, `dl`, `update`, `sync`, `data`
- Server accepts any prefix (already does — it only cares about the domain suffix)
- Client picks randomly per query
- **Backward compatible**: old clients with `.t.` still work

### Domain naming: avoid `cdn` keyword
Iran may flag domains with `cdn` in the name. Use organic-looking domains:
- `morning-tide-books.net`, `silver-birch-labs.com` (already have these)
- Avoid: `cdn-edge-relay.net`, `cdncache-eu.net`, `staticedge-eu.net`

## Implementation Status

### Server (deployed first — backward compatible)
- [x] Accept any tunnel QTYPE (A, AAAA, TXT, NULL, CNAME) — `dns.rs:is_tunnel_qtype()`
- [x] Encode response in matching record type — `turbotunnel.rs:encode_answer_rdata()`
- [x] A/AAAA: split payload across multiple answer RRs with 2-byte length header
- [x] TXT: unchanged (backward compatible with existing clients)

### Client (next release)
- [x] `encode_query_typed()` — configurable QTYPE per query
- [x] `decode_response()` — handles A/AAAA/TXT/NULL responses
- [ ] Auto-detect: send TXT probe first, if blocked → fall back to A
- [ ] Parallel sessions: 3-4x concurrent DNS sessions when using A records
- [ ] Randomized subdomain prefix (replace hardcoded `.t.`)
- [ ] OTA config: `preferred_qtype` field per domain

### OTA config changes (future)
```json
{
  "dnstt": {
    "preferred_qtype": "A",
    "qtype_fallback": ["AAAA", "TXT"],
    "subdomain_prefixes": ["api", "www", "cdn", "img", "static", "dl"],
    "parallel_sessions": 4
  }
}
```

## Backward Compatibility
- Server always accepts TXT (existing clients keep working)
- New clients default to TXT, auto-detect when blocked, switch to A
- Subdomain prefix change is server-side transparent (server only checks domain suffix)
- No protocol version bump needed — it's just a different DNS qtype
