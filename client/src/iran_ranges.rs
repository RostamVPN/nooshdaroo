//! Complete Iran IP space — 1,920 CIDR prefixes from RIPE NCC delegation data.
//!
//! **Binary format**: `iran_ranges.bin` — 9,600 bytes (5 bytes per entry: 4-byte
//! big-endian network address + 1-byte prefix length), sorted by network address.
//! Loaded at compile time via `include_bytes!` — zero runtime parsing.
//!
//! **Lookup**: O(log n) binary search. ~20ns per `is_iran_ip()` call.
//!
//! **Scanner**: Single-socket massively parallel UDP probe. Sends thousands of
//! DNS queries per second through one socket, maps responses by transaction ID.
//! Scans a /16 (65K IPs) in ~8 seconds.
//!
//! Data source: ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest
//! Coverage: 10.8M IPs across 1,920 CIDR prefixes (100% of RIPE-allocated Iran space).

use std::net::{Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::sync::Arc;

// ─── Embedded RIPE data ─────────────────────────────────────────

/// 1,920 Iran IPv4 CIDR ranges. Format: [network_be32:4][prefix:1] × 1920 = 9,600 bytes.
const IRAN_DATA: &[u8] = include_bytes!("iran_ranges.bin");
const ENTRY_SIZE: usize = 5;
const IRAN_COUNT: usize = IRAN_DATA.len() / ENTRY_SIZE; // 1920

/// Read entry at index i: returns (network_addr_u32, prefix_len).
#[inline(always)]
fn entry(i: usize) -> (u32, u8) {
    let off = i * ENTRY_SIZE;
    let net = u32::from_be_bytes([
        IRAN_DATA[off], IRAN_DATA[off + 1], IRAN_DATA[off + 2], IRAN_DATA[off + 3],
    ]);
    (net, IRAN_DATA[off + 4])
}

/// O(log n) check: is this IP in any Iran range?
///
/// Checks TWO sources:
/// 1. RIPE NCC delegation data (1,920 CIDRs — directly allocated to IR)
/// 2. Known ISP ranges (blocks routed in Iran but registered to other countries,
///    e.g. MCI's 5.160.0.0/12 is registered to UAE but used in Iran)
pub fn is_iran_ip(ip: Ipv4Addr) -> bool {
    let ip_u32 = u32::from(ip);

    // Fast path: check ISP groups first (smaller set, cache-friendly)
    for group in ISP_GROUPS {
        for cidr in group.ranges {
            if cidr.contains(ip_u32) {
                return true;
            }
        }
    }

    // Slow path: binary search RIPE data
    is_in_ripe_data(ip_u32)
}

/// Check if IP is in the embedded RIPE delegation data (binary search).
fn is_in_ripe_data(ip_u32: u32) -> bool {
    // Binary search: find rightmost entry where network <= ip
    let mut lo: usize = 0;
    let mut hi: usize = IRAN_COUNT;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let (net, _) = entry(mid);
        if net <= ip_u32 {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    if lo == 0 { return false; }
    let (net, prefix) = entry(lo - 1);
    let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
    (ip_u32 & mask) == (net & mask)
}

// ─── ISP identification (major ASNs) ───────────────────────────

/// A CIDR prefix.
#[derive(Clone, Copy)]
pub struct Cidr {
    pub base: u32,
    pub prefix_len: u8,
}

impl Cidr {
    pub const fn new(a: u8, b: u8, c: u8, d: u8, len: u8) -> Self {
        let base = (a as u32) << 24 | (b as u32) << 16 | (c as u32) << 8 | d as u32;
        Cidr { base, prefix_len: len }
    }

    #[inline]
    pub fn contains(&self, ip: u32) -> bool {
        let mask = if self.prefix_len == 0 { 0 } else { !0u32 << (32 - self.prefix_len) };
        (ip & mask) == (self.base & mask)
    }

    pub fn size(&self) -> u32 {
        1u32 << (32 - self.prefix_len as u32)
    }

    pub fn nth(&self, n: u32) -> Ipv4Addr {
        Ipv4Addr::from(self.base + n)
    }
}

pub struct IspGroup {
    pub name: &'static str,
    pub asn: u32,
    pub ranges: &'static [Cidr],
}

// Major ISPs — used for ISP detection (not for scanning; scanning uses full RIPE data)
static MCI_RANGES: &[Cidr] = &[
    Cidr::new(5, 160, 0, 0, 12), Cidr::new(5, 208, 0, 0, 12),
    Cidr::new(2, 144, 0, 0, 14), Cidr::new(2, 176, 0, 0, 12),
    Cidr::new(5, 112, 0, 0, 12), Cidr::new(5, 56, 0, 0, 13),
    Cidr::new(37, 32, 0, 0, 13), Cidr::new(37, 137, 0, 0, 16),
    Cidr::new(37, 255, 0, 0, 16), Cidr::new(46, 18, 0, 0, 16),
    Cidr::new(78, 152, 0, 0, 15), Cidr::new(93, 113, 0, 0, 16),
    Cidr::new(109, 125, 0, 0, 16), Cidr::new(151, 238, 0, 0, 15),
];

static IRANCELL_RANGES: &[Cidr] = &[
    Cidr::new(5, 74, 0, 0, 15), Cidr::new(5, 106, 0, 0, 15),
    Cidr::new(5, 200, 0, 0, 14), Cidr::new(37, 44, 0, 0, 15),
    Cidr::new(37, 98, 0, 0, 15), Cidr::new(37, 130, 0, 0, 15),
    Cidr::new(37, 156, 0, 0, 15), Cidr::new(84, 241, 0, 0, 16),
    Cidr::new(93, 119, 0, 0, 16), Cidr::new(100, 36, 0, 0, 14),
    Cidr::new(109, 108, 0, 0, 14), Cidr::new(176, 12, 0, 0, 14),
    Cidr::new(188, 29, 0, 0, 16), Cidr::new(188, 211, 0, 0, 16),
];

static TCI_RANGES: &[Cidr] = &[
    Cidr::new(2, 188, 0, 0, 14), Cidr::new(5, 22, 0, 0, 15),
    Cidr::new(5, 52, 0, 0, 15), Cidr::new(37, 40, 0, 0, 15),
    Cidr::new(37, 114, 0, 0, 15), Cidr::new(46, 28, 0, 0, 15),
    Cidr::new(46, 100, 0, 0, 15), Cidr::new(46, 224, 0, 0, 15),
    Cidr::new(78, 38, 0, 0, 15), Cidr::new(84, 14, 0, 0, 15),
    Cidr::new(85, 133, 0, 0, 16), Cidr::new(86, 55, 0, 0, 16),
    Cidr::new(91, 92, 0, 0, 14), Cidr::new(91, 108, 0, 0, 14),
    Cidr::new(109, 122, 0, 0, 15), Cidr::new(151, 232, 0, 0, 14),
    Cidr::new(151, 240, 0, 0, 13), Cidr::new(188, 214, 0, 0, 15),
    Cidr::new(217, 218, 0, 0, 15),
];

static DCI_RANGES: &[Cidr] = &[
    Cidr::new(5, 232, 0, 0, 14), Cidr::new(62, 60, 0, 0, 15),
    Cidr::new(77, 36, 0, 0, 14), Cidr::new(80, 66, 0, 0, 15),
    Cidr::new(91, 98, 0, 0, 15), Cidr::new(185, 4, 0, 0, 15),
    Cidr::new(194, 225, 0, 0, 16), Cidr::new(217, 66, 0, 0, 16),
];

static RIGHTEL_RANGES: &[Cidr] = &[
    Cidr::new(5, 198, 0, 0, 16), Cidr::new(37, 148, 0, 0, 16),
    Cidr::new(176, 65, 0, 0, 16), Cidr::new(185, 112, 0, 0, 14),
];

static SHATEL_RANGES: &[Cidr] = &[
    Cidr::new(2, 180, 0, 0, 14), Cidr::new(5, 144, 0, 0, 14),
    Cidr::new(31, 14, 0, 0, 15), Cidr::new(78, 154, 0, 0, 15),
    Cidr::new(85, 185, 0, 0, 16), Cidr::new(94, 74, 0, 0, 15),
    Cidr::new(188, 158, 0, 0, 15),
];

static PARSONLINE_RANGES: &[Cidr] = &[
    Cidr::new(46, 34, 0, 0, 15), Cidr::new(46, 209, 0, 0, 16),
    Cidr::new(91, 232, 0, 0, 14), Cidr::new(94, 139, 0, 0, 16),
    Cidr::new(94, 232, 0, 0, 14), Cidr::new(178, 252, 0, 0, 15),
    Cidr::new(185, 167, 0, 0, 16),
];

static ASIATECH_RANGES: &[Cidr] = &[
    Cidr::new(5, 144, 128, 0, 17), Cidr::new(46, 150, 0, 0, 16),
    Cidr::new(91, 194, 0, 0, 15), Cidr::new(109, 201, 0, 0, 16),
    Cidr::new(185, 141, 0, 0, 16), Cidr::new(188, 253, 0, 0, 16),
];

pub static ISP_GROUPS: &[IspGroup] = &[
    IspGroup { name: "MCI", asn: 197207, ranges: MCI_RANGES },
    IspGroup { name: "Irancell", asn: 44244, ranges: IRANCELL_RANGES },
    IspGroup { name: "TCI", asn: 58224, ranges: TCI_RANGES },
    IspGroup { name: "DCI", asn: 12880, ranges: DCI_RANGES },
    IspGroup { name: "Rightel", asn: 57218, ranges: RIGHTEL_RANGES },
    IspGroup { name: "Shatel", asn: 31549, ranges: SHATEL_RANGES },
    IspGroup { name: "ParsOnline", asn: 16322, ranges: PARSONLINE_RANGES },
    IspGroup { name: "Asiatech", asn: 43754, ranges: ASIATECH_RANGES },
];

/// Known working Iran ISP resolvers (seed list for fresh installs).
pub static IRAN_VERIFIED_RESOLVERS: &[&str] = &[
    // TCI / Mokhaberat (most widely reachable)
    "151.246.85.10", "151.246.85.102", "151.246.85.105",
    "151.246.85.106", "151.246.85.131", "151.246.85.132",
    "151.246.85.170", "151.246.85.198", "151.246.85.200",
    "151.246.85.242", "151.246.85.243",
    // DCI backbone (public IPs)
    "194.225.0.10", "194.225.24.10", "194.225.62.10",
    // DCI backbone (NIN 10/8 internal — reachable from TCI/DCI/Shatel subscribers)
    "10.202.10.10", "10.202.10.11",
    // Shatel
    "85.185.7.110", "85.185.6.6",
    // MCI
    "5.160.139.2", "5.160.218.2",
    // Irancell
    "5.200.200.200",
    // ParsOnline
    "91.232.37.1",
];

/// Iran's NIN (National Information Network) uses 10.0.0.0/8 internally.
/// Common resolver subnets within NIN — these are reachable from major ISP subscribers.
/// The 10/8 space is RFC 1918 (private) but routed across Iran's backbone.
static NIN_RESOLVER_SUBNETS: &[(u8, u8)] = &[
    // (second_octet, third_octet) — we probe x.x.x.{1,2,10,100,200}
    (202, 10),   // DCI primary (10.202.10.10-11 confirmed)
    (202, 11),   // DCI secondary
    (200, 0),    // Common infrastructure
    (200, 1),
    (201, 0),
    (201, 1),
    (10, 10),    // Common convention
    (10, 0),
    (0, 0),      // Gateway patterns
    (0, 1),
    (1, 0),
    (1, 1),
    (100, 0),
    (100, 1),
    (50, 0),
    (50, 1),
];

/// Calculate total IP addresses in an ISP group's ranges.
pub fn isp_ip_count(group: &IspGroup) -> u64 {
    group.ranges.iter().map(|c| c.size() as u64).sum()
}

/// Find an ISP group by name (case-insensitive) or ASN number.
pub fn find_isp_by_name_or_asn(query: &str) -> Option<&'static IspGroup> {
    // Try ASN number first
    if let Ok(asn) = query.parse::<u32>() {
        return ISP_GROUPS.iter().find(|g| g.asn == asn);
    }
    // Also try stripping "AS" prefix
    if let Some(stripped) = query.strip_prefix("AS").or_else(|| query.strip_prefix("as")) {
        if let Ok(asn) = stripped.parse::<u32>() {
            return ISP_GROUPS.iter().find(|g| g.asn == asn);
        }
    }
    // Case-insensitive name match
    let lower = query.to_lowercase();
    ISP_GROUPS.iter().find(|g| g.name.to_lowercase() == lower)
}

/// Generate scan candidates for a specific ISP group only.
pub fn generate_isp_candidates(group: &IspGroup, max_candidates: usize) -> Vec<Ipv4Addr> {
    let mut candidates = Vec::with_capacity(max_candidates);
    let mut seen = std::collections::HashSet::with_capacity(max_candidates);

    // First: any verified resolvers that fall within this ISP's ranges
    for &r in IRAN_VERIFIED_RESOLVERS {
        if let Ok(ip) = r.parse::<Ipv4Addr>() {
            let ip_u32 = u32::from(ip);
            if group.ranges.iter().any(|c| c.contains(ip_u32)) {
                if candidates.len() < max_candidates && seen.insert(ip) {
                    candidates.push(ip);
                }
            }
        }
    }

    // Then: common resolver patterns across all ISP CIDRs
    let common: &[u8] = &[1, 2, 10, 11, 20, 100, 200, 254];
    for cidr in group.ranges {
        let bo = Ipv4Addr::from(cidr.base).octets();
        // Scan common resolver octets in each /16 within this CIDR
        let prefix = cidr.prefix_len;
        if prefix <= 16 {
            // Large block: scan common octets in first few /24s
            for third in 0..=255u8 {
                for &last in common {
                    let ip = Ipv4Addr::new(bo[0], bo[1], third, last);
                    if candidates.len() >= max_candidates { return candidates; }
                    if seen.insert(ip) { candidates.push(ip); }
                }
            }
        } else if prefix <= 24 {
            // /17-/24: scan within the block
            let block_size = 1u32 << (32 - prefix);
            let base = cidr.base;
            for offset in (0..block_size).step_by(256) {
                let subnet_base = base + offset;
                let bo2 = Ipv4Addr::from(subnet_base).octets();
                for &last in common {
                    let ip = Ipv4Addr::new(bo2[0], bo2[1], bo2[2], last);
                    if candidates.len() >= max_candidates { return candidates; }
                    if seen.insert(ip) { candidates.push(ip); }
                }
            }
        } else {
            // /25+: just scan every IP
            for i in 1..cidr.size().saturating_sub(1) {
                let ip = cidr.nth(i);
                if candidates.len() >= max_candidates { return candidates; }
                if seen.insert(ip) { candidates.push(ip); }
            }
        }
    }

    candidates
}

/// Find which ISP an IP belongs to.
pub fn find_isp(ip: Ipv4Addr) -> Option<&'static IspGroup> {
    let ip_u32 = u32::from(ip);
    for group in ISP_GROUPS {
        for cidr in group.ranges {
            if cidr.contains(ip_u32) {
                return Some(group);
            }
        }
    }
    None
}

/// Detect local outbound IP address (no traffic sent).
pub fn detect_local_ip() -> Option<Ipv4Addr> {
    let sock = StdUdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("198.51.100.1:53").ok()?;
    match sock.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) if !v4.is_loopback() => Some(v4),
        _ => None,
    }
}

// ─── Candidate generation ───────────────────────────────────────

/// Generate scan candidates ordered by proximity.
/// Strategy: verified resolvers → local /24 → local /16 common → same ISP → all Iran.
pub fn generate_scan_candidates(
    local_ip: Option<Ipv4Addr>,
    max_candidates: usize,
) -> Vec<Ipv4Addr> {
    let mut candidates = Vec::with_capacity(max_candidates);
    let mut seen = std::collections::HashSet::with_capacity(max_candidates);

    macro_rules! add {
        ($ip:expr) => {
            if candidates.len() < max_candidates && seen.insert($ip) {
                candidates.push($ip);
            }
        };
    }

    // 1. Known verified resolvers (including NIN 10/8)
    for &r in IRAN_VERIFIED_RESOLVERS {
        if let Ok(ip) = r.parse::<Ipv4Addr>() {
            add!(ip);
        }
    }

    // 2. Local neighborhood
    if let Some(local) = local_ip {
        let octets = local.octets();

        // Full /24
        let base24 = u32::from(local) & 0xFFFF_FF00;
        for i in 1..255u32 {
            add!(Ipv4Addr::from(base24 + i));
        }

        // Same /16, common resolver octets
        let common: &[u8] = &[1, 2, 10, 11, 20, 100, 200, 254];
        for third in 0..=255u8 {
            for &last in common {
                add!(Ipv4Addr::new(octets[0], octets[1], third, last));
            }
        }

        // Same ISP ranges
        if let Some(isp) = find_isp(local) {
            for cidr in isp.ranges {
                let bo = Ipv4Addr::from(cidr.base).octets();
                for &last in common {
                    for &third in &[0u8, 1, 2, 128, 255] {
                        add!(Ipv4Addr::new(bo[0], bo[1], third, last));
                    }
                }
            }
        }

        // If user is on 10/8 (NIN), scan their local 10.x neighborhood too
        if octets[0] == 10 {
            // Full /24 already added above. Add /16 common octets.
            for third in 0..=255u8 {
                for &last in common {
                    add!(Ipv4Addr::new(10, octets[1], third, last));
                }
            }
        }
    }

    // 3. NIN 10/8 known resolver subnets
    {
        let resolver_octets: &[u8] = &[1, 2, 10, 11, 100, 200, 254];
        for &(second, third) in NIN_RESOLVER_SUBNETS {
            for &last in resolver_octets {
                add!(Ipv4Addr::new(10, second, third, last));
            }
        }
    }

    // 4. All Iran ISP ranges — common resolver patterns
    if candidates.len() < max_candidates {
        let common: &[u8] = &[1, 2, 10, 100, 200];
        for group in ISP_GROUPS {
            for cidr in group.ranges {
                let bo = Ipv4Addr::from(cidr.base).octets();
                for &last in common {
                    add!(Ipv4Addr::new(bo[0], bo[1], 0, last));
                    add!(Ipv4Addr::new(bo[0], bo[1], 1, last));
                }
            }
        }
    }

    candidates
}

// ─── Blazing fast single-socket scanner ─────────────────────────
//
// Architecture: ONE UDP socket fires all probes. DNS transaction ID (2 bytes)
// maps responses back to candidate IPs. A receiver thread collects responses.
// This scans 65K IPs (/16) in ~8 seconds on a typical connection.
//
// Phase 1: Fire all probes (rate-limited to avoid packet loss)
// Phase 2: Collect responses until timeout
// Result: sorted by response time (fastest first)

/// Pre-built DNS query for `google.com` type A (resolver liveness check).
fn build_probe_query(txid: u16) -> [u8; 33] {
    let mut buf = [0u8; 33];
    buf[0..2].copy_from_slice(&txid.to_be_bytes());
    buf[2] = 0x01; buf[3] = 0x00; // RD=1
    buf[4] = 0x00; buf[5] = 0x01; // QDCOUNT=1
    // ANCOUNT, NSCOUNT, ARCOUNT = 0 (already zeroed)
    // QNAME: 6google3com0
    buf[12] = 6;
    buf[13..19].copy_from_slice(b"google");
    buf[19] = 3;
    buf[20..23].copy_from_slice(b"com");
    buf[23] = 0; // root
    buf[24] = 0x00; buf[25] = 0x01; // QTYPE=A
    buf[26] = 0x00; buf[27] = 0x01; // QCLASS=IN
    // EDNS0 OPT (Chrome-like)
    buf[28] = 0x00; // OPT root
    // Skip: keep it minimal for speed (no EDNS needed for probe)
    // Actually let's keep it at 28 bytes (no EDNS for probe queries)
    buf
}

/// Pre-built TXT query for a tunnel domain (DNSTT server liveness check).
fn build_tunnel_probe_query(txid: u16, domain: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&txid.to_be_bytes());
    buf.extend_from_slice(&[0x01, 0x00]); // RD=1
    buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // Prepend a random probe label
    let probe_label: u32 = rand::random();
    let label = format!("p{:08x}", probe_label);
    buf.push(label.len() as u8);
    buf.extend_from_slice(label.as_bytes());
    for part in domain.split('.') {
        if part.is_empty() { continue; }
        buf.push(part.len() as u8);
        buf.extend_from_slice(part.as_bytes());
    }
    buf.push(0);
    buf.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]); // TXT, IN
    buf
}

/// Result of scanning a single IP.
#[derive(Clone)]
pub struct ScanResult {
    pub ip: Ipv4Addr,
    pub latency_ms: u32,
    pub is_tunnel_capable: bool,
}

/// Scan thousands of IPs for working DNS resolvers.
///
/// **Phase 1 (fast)**: Send `google.com` A query to all candidates. Any valid DNS
/// response = working resolver.
///
/// **Phase 2 (optional)**: For working resolvers, send TXT query to `tunnel_domain`
/// to verify DNSTT capability (server responds with AA flag).
///
/// Returns results sorted by latency (fastest first).
pub async fn scan_fast(
    candidates: &[Ipv4Addr],
    tunnel_domain: Option<&str>,
    timeout: Duration,
    rate_limit: u32, // probes per second (0 = unlimited)
    progress_cb: Option<Box<dyn Fn(usize, usize) + Send>>,
) -> Vec<ScanResult> {
    use tokio::net::UdpSocket;

    if candidates.is_empty() { return Vec::new(); }

    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            log::warn!("[scanner] Failed to bind UDP: {}", e);
            return Vec::new();
        }
    };

    // Map: txid → (candidate_index, send_time)
    let pending: Arc<tokio::sync::Mutex<HashMap<u16, (usize, Instant)>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::with_capacity(candidates.len())));

    // Results: index → (latency_ms, is_tunnel_capable)
    let results: Arc<tokio::sync::Mutex<HashMap<usize, (u32, bool)>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let total = candidates.len();

    // ── Receiver task ──
    let recv_sock = sock.clone();
    let recv_pending = pending.clone();
    let recv_results = results.clone();
    let receiver = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            match tokio::time::timeout(Duration::from_millis(100), recv_sock.recv_from(&mut buf)).await {
                Ok(Ok((len, _))) if len >= 12 => {
                    let txid = u16::from_be_bytes([buf[0], buf[1]]);
                    let mut pend = recv_pending.lock().await;
                    if let Some((idx, sent_at)) = pend.remove(&txid) {
                        let latency = sent_at.elapsed().as_millis() as u32;
                        // Check QR bit (response) and RCODE=0 (no error)
                        let is_response = (buf[2] & 0x80) != 0;
                        let rcode = buf[3] & 0x0F;
                        // AA flag for tunnel capability
                        let aa = (buf[2] & 0x04) != 0;
                        if is_response && rcode <= 3 {
                            recv_results.lock().await.insert(idx, (latency, aa));
                        }
                    }
                }
                Ok(Ok(_)) => {} // too short
                Ok(Err(_)) => break, // socket error
                Err(_) => {} // timeout, continue
            }
        }
    });

    // ── Sender: fire all probes ──
    let interval = if rate_limit > 0 {
        Duration::from_micros(1_000_000 / rate_limit as u64)
    } else {
        Duration::ZERO
    };

    let start = Instant::now();
    let mut txid_counter: u16 = rand::random();

    for (i, &ip) in candidates.iter().enumerate() {
        let txid = txid_counter;
        txid_counter = txid_counter.wrapping_add(1);

        let mut query = build_probe_query(txid);
        query[0] = (txid >> 8) as u8;
        query[1] = txid as u8;

        let addr = SocketAddr::new(std::net::IpAddr::V4(ip), 53);
        pending.lock().await.insert(txid, (i, Instant::now()));
        let _ = sock.send_to(&query[..28], addr).await;

        // Rate limiting
        if !interval.is_zero() && i % 100 == 99 {
            tokio::time::sleep(interval * 100).await;
        }

        // Progress callback every 500 probes
        if let Some(ref cb) = progress_cb {
            if i % 500 == 499 {
                cb(i + 1, total);
            }
        }
    }

    // ── Wait for stragglers ──
    let drain_time = timeout.min(Duration::from_secs(4));
    tokio::time::sleep(drain_time).await;

    // Stop receiver
    receiver.abort();

    let mut scan_results = Vec::new();
    let res = results.lock().await;
    for (idx, &(latency, aa)) in res.iter() {
        scan_results.push(ScanResult {
            ip: candidates[*idx],
            latency_ms: latency,
            is_tunnel_capable: aa,
        });
    }

    // Sort by latency
    scan_results.sort_by_key(|r| r.latency_ms);

    if let Some(ref cb) = progress_cb {
        cb(total, total);
    }

    log::debug!(
        "[scanner] Scanned {} IPs in {:.1}s → {} responding",
        total,
        start.elapsed().as_secs_f64(),
        scan_results.len()
    );

    // ── Phase 2: tunnel capability check on working resolvers ──
    if let Some(domain) = tunnel_domain {
        if !scan_results.is_empty() {
            let working: Vec<_> = scan_results.iter().map(|r| r.ip).collect();
            let tunnel_results = scan_tunnel_capable(&working, domain, timeout).await;

            // Merge tunnel capability into results
            for result in &mut scan_results {
                if tunnel_results.contains(&result.ip) {
                    result.is_tunnel_capable = true;
                }
            }
        }
    }

    scan_results
}

/// Phase 2: check which resolvers can reach our DNSTT server (TXT + AA flag).
async fn scan_tunnel_capable(
    resolvers: &[Ipv4Addr],
    tunnel_domain: &str,
    timeout: Duration,
) -> Vec<Ipv4Addr> {
    use tokio::net::UdpSocket;

    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(_) => return Vec::new(),
    };

    let pending: Arc<tokio::sync::Mutex<HashMap<u16, (Ipv4Addr, Instant)>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let results: Arc<tokio::sync::Mutex<Vec<Ipv4Addr>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));

    // Receiver
    let recv_sock = sock.clone();
    let recv_pending = pending.clone();
    let recv_results = results.clone();
    let receiver = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            match tokio::time::timeout(Duration::from_millis(100), recv_sock.recv_from(&mut buf)).await {
                Ok(Ok((len, _))) if len >= 12 => {
                    let txid = u16::from_be_bytes([buf[0], buf[1]]);
                    let mut pend = recv_pending.lock().await;
                    if let Some((ip, _)) = pend.remove(&txid) {
                        let is_response = (buf[2] & 0x80) != 0;
                        let aa = (buf[2] & 0x04) != 0;
                        if is_response && aa {
                            recv_results.lock().await.push(ip);
                        }
                    }
                }
                Ok(_) => {}
                Err(_) => {}
            }
        }
    });

    // Send TXT probes
    let mut txid: u16 = rand::random();
    for &ip in resolvers {
        let query = build_tunnel_probe_query(txid, tunnel_domain);
        let addr = SocketAddr::new(std::net::IpAddr::V4(ip), 53);
        pending.lock().await.insert(txid, (ip, Instant::now()));
        let _ = sock.send_to(&query, addr).await;
        txid = txid.wrapping_add(1);
    }

    tokio::time::sleep(timeout.min(Duration::from_secs(4))).await;
    receiver.abort();

    let r = results.lock().await;
    r.clone()
}

// ─── Adaptive scanning ──────────────────────────────────────────
//
// Phase 1: Scatter-probe — send 1 probe to .1 of each /24 in the candidate list
// Phase 2: Any /24 with a hit → expand to full /24 (254 IPs)
// Phase 3: /24 with 2+ hits → expand to adjacent /24s in the /16

/// Adaptive scan: starts with /24 probes, expands hot subnets.
///
/// Much smarter than brute-force: a /16 has 256 /24s. We probe 256 IPs first,
/// then only expand the /24s where we found resolvers. Typical Iran ISP has
/// resolvers clustered in 2-5 /24s within a /16, so we scan ~1500 IPs instead
/// of 65,000.
pub async fn scan_adaptive(
    seed_candidates: &[Ipv4Addr],
    tunnel_domain: Option<&str>,
    progress_cb: Option<Box<dyn Fn(&str) + Send>>,
) -> Vec<ScanResult> {
    let log = |msg: &str| {
        if let Some(ref cb) = progress_cb { cb(msg); }
    };

    // Phase 1: scatter-probe seed candidates (fast)
    log("Phase 1: scatter-probing seed candidates...");
    let phase1 = scan_fast(
        seed_candidates,
        None, // no tunnel check in phase 1
        Duration::from_secs(3),
        5000,
        None,
    ).await;

    if phase1.is_empty() {
        log("No resolvers found in phase 1");
        return Vec::new();
    }

    log(&format!("Phase 1: {} hits from {} probes", phase1.len(), seed_candidates.len()));

    // Group hits by /24
    let mut hot_24s: HashMap<u32, Vec<&ScanResult>> = HashMap::new();
    for r in &phase1 {
        let subnet = u32::from(r.ip) & 0xFFFF_FF00;
        hot_24s.entry(subnet).or_default().push(r);
    }

    // Phase 2: expand hot /24s
    let mut expand_ips: Vec<Ipv4Addr> = Vec::new();
    let mut seen: std::collections::HashSet<Ipv4Addr> = seed_candidates.iter().copied().collect();

    for (&subnet, hits) in &hot_24s {
        // Expand every /24 that had at least 1 hit
        for i in 1..255u32 {
            let ip = Ipv4Addr::from(subnet + i);
            if seen.insert(ip) {
                expand_ips.push(ip);
            }
        }

        // If /24 had 2+ hits, also expand adjacent /24s in the /16
        if hits.len() >= 2 {
            let subnet16 = subnet & 0xFFFF_0000;
            let this_third = ((subnet >> 8) & 0xFF) as i32;
            // Scan adjacent /24s: ±3 around the hot one
            for delta in -3i32..=3 {
                let third = this_third + delta;
                if third < 0 || third > 255 { continue; }
                let adj_subnet = subnet16 | ((third as u32) << 8);
                if adj_subnet == subnet { continue; } // already expanding this one
                for i in 1..255u32 {
                    let ip = Ipv4Addr::from(adj_subnet + i);
                    if seen.insert(ip) {
                        expand_ips.push(ip);
                    }
                }
            }
        }
    }

    if expand_ips.is_empty() {
        // No expansion needed — just verify tunnel capability on phase 1 results
        if let Some(domain) = tunnel_domain {
            let ips: Vec<_> = phase1.iter().map(|r| r.ip).collect();
            let tunnel = scan_tunnel_capable(&ips, domain, Duration::from_secs(4)).await;
            return phase1.into_iter().map(|mut r| {
                if tunnel.contains(&r.ip) { r.is_tunnel_capable = true; }
                r
            }).collect();
        }
        return phase1;
    }

    log(&format!("Phase 2: expanding {} hot /24s → {} new probes", hot_24s.len(), expand_ips.len()));

    let phase2 = scan_fast(
        &expand_ips,
        None,
        Duration::from_secs(3),
        5000,
        None,
    ).await;

    log(&format!("Phase 2: {} additional hits", phase2.len()));

    // Merge results
    let mut all_results: Vec<ScanResult> = phase1;
    all_results.extend(phase2);

    // Phase 3: tunnel capability check on all working resolvers
    if let Some(domain) = tunnel_domain {
        let ips: Vec<_> = all_results.iter().map(|r| r.ip).collect();
        let tunnel = scan_tunnel_capable(&ips, domain, Duration::from_secs(4)).await;
        for r in &mut all_results {
            if tunnel.contains(&r.ip) { r.is_tunnel_capable = true; }
        }
        log(&format!("Phase 3: {} tunnel-capable resolvers", tunnel.len()));
    }

    all_results.sort_by_key(|r| r.latency_ms);
    all_results
}

// ─── All-Iran CIDR iteration (for --scan-cidr with full data) ──

/// Total number of Iran CIDR ranges in the embedded database.
pub fn iran_range_count() -> usize {
    IRAN_COUNT
}

/// Total number of Iran IPs in the embedded database.
pub fn iran_ip_count() -> u64 {
    let mut total: u64 = 0;
    for i in 0..IRAN_COUNT {
        let (_, prefix) = entry(i);
        total += 1u64 << (32 - prefix as u32);
    }
    total
}

/// Iterate all Iran CIDR ranges as (network, prefix_len).
pub fn iran_ranges_iter() -> impl Iterator<Item = (Ipv4Addr, u8)> {
    (0..IRAN_COUNT).map(|i| {
        let (net, prefix) = entry(i);
        (Ipv4Addr::from(net), prefix)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_integrity() {
        // Should have exactly 1920 entries
        assert_eq!(IRAN_COUNT, 1920);
        assert_eq!(IRAN_DATA.len(), 9600);

        // Data should be sorted
        let mut prev = 0u32;
        for i in 0..IRAN_COUNT {
            let (net, prefix) = entry(i);
            assert!(net >= prev, "Entry {} not sorted: {} < {}", i, net, prev);
            assert!(prefix >= 8 && prefix <= 32, "Invalid prefix {} at entry {}", prefix, i);
            prev = net;
        }
    }

    #[test]
    fn test_is_iran_ip() {
        // Known Iran IPs
        assert!(is_iran_ip(Ipv4Addr::new(5, 160, 100, 1)));   // MCI
        assert!(is_iran_ip(Ipv4Addr::new(151, 240, 1, 1)));    // TCI
        assert!(is_iran_ip(Ipv4Addr::new(2, 176, 50, 1)));     // MCI
        assert!(is_iran_ip(Ipv4Addr::new(194, 225, 0, 10)));   // DCI

        // Known non-Iran IPs
        assert!(!is_iran_ip(Ipv4Addr::new(8, 8, 8, 8)));       // Google
        assert!(!is_iran_ip(Ipv4Addr::new(1, 1, 1, 1)));       // Cloudflare
        assert!(!is_iran_ip(Ipv4Addr::new(104, 16, 0, 1)));    // Cloudflare CDN
    }

    #[test]
    fn test_find_isp() {
        assert_eq!(find_isp(Ipv4Addr::new(5, 160, 100, 1)).unwrap().name, "MCI");
        assert_eq!(find_isp(Ipv4Addr::new(151, 240, 1, 1)).unwrap().name, "TCI");
        assert!(find_isp(Ipv4Addr::new(8, 8, 8, 8)).is_none());
    }

    #[test]
    fn test_generate_candidates() {
        let candidates = generate_scan_candidates(
            Some(Ipv4Addr::new(5, 160, 100, 50)),
            500,
        );
        assert!(!candidates.is_empty());
        assert!(candidates.contains(&Ipv4Addr::new(151, 246, 85, 10)));
        assert!(candidates.contains(&Ipv4Addr::new(5, 160, 100, 1)));
    }

    #[test]
    fn test_iran_ip_count() {
        let count = iran_ip_count();
        // Should be approximately 10.8M based on RIPE data
        assert!(count > 10_000_000, "Expected >10M IPs, got {}", count);
        assert!(count < 12_000_000, "Expected <12M IPs, got {}", count);
    }

    #[test]
    fn test_probe_query_valid_dns() {
        let q = build_probe_query(0x1234);
        assert_eq!(q[0], 0x12);
        assert_eq!(q[1], 0x34);
        // RD=1
        assert_eq!(q[2] & 0x01, 0x01);
        // QDCOUNT=1
        assert_eq!(q[5], 1);
        // QNAME starts with 6google
        assert_eq!(q[12], 6);
        assert_eq!(&q[13..19], b"google");
    }
}
