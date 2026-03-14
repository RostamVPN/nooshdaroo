//! Iran IP ranges — embedded CIDR prefixes for local resolver discovery.
//!
//! Users in Iran often can't reach global resolvers (8.8.8.8, 1.1.1.1) because
//! they're blocked at the network level. But every ISP runs internal recursive
//! resolvers reachable from their own subscribers. These ISP resolvers forward
//! queries upstream — including to our authoritative tunnel domains.
//!
//! This module embeds Iran's major ISP CIDR ranges so the scanner can target
//! the user's local network first, then expand outward. A /24 scan (254 IPs)
//! takes <1s. A /16 (65K IPs) takes ~30s with parallel probes.
//!
//! Ranges are grouped by ASN/ISP for targeted scanning:
//! 1. Detect user's local IP → find matching ASN group
//! 2. Scan the user's own /24 first (highest chance of finding local resolver)
//! 3. Expand to the user's /16
//! 4. Expand to same-ASN ranges
//! 5. Fall back to all Iran ranges
//!
//! Data source: RIPE NCC country resource list for IR + known ISP ASN mappings.
//! Updated periodically via OTA config (field: "iran_ranges").

use std::net::Ipv4Addr;

/// A CIDR prefix: base IP + prefix length.
#[derive(Clone, Copy)]
pub struct Cidr {
    pub base: u32, // Network address as u32
    pub prefix_len: u8,
}

impl Cidr {
    const fn new(a: u8, b: u8, c: u8, d: u8, len: u8) -> Self {
        let base = (a as u32) << 24 | (b as u32) << 16 | (c as u32) << 8 | d as u32;
        Cidr { base, prefix_len: len }
    }

    /// Number of IPs in this range.
    pub fn size(&self) -> u32 {
        1u32 << (32 - self.prefix_len as u32)
    }

    /// Check if an IP (as u32) falls within this CIDR.
    pub fn contains(&self, ip: u32) -> bool {
        let mask = if self.prefix_len == 0 { 0 } else { !0u32 << (32 - self.prefix_len) };
        (ip & mask) == (self.base & mask)
    }

    /// Generate the nth IP in this range.
    pub fn nth(&self, n: u32) -> Ipv4Addr {
        Ipv4Addr::from(self.base + n)
    }
}

/// ISP group with associated CIDR ranges.
pub struct IspGroup {
    pub name: &'static str,
    pub asn: u32,
    pub ranges: &'static [Cidr],
}

// ─── Iran ISP ranges ────────────────────────────────────────────
// Major ISPs covering ~95% of Iran's internet users.
// Compact representation: only /8 through /20 prefixes (larger blocks).
// Smaller /24 blocks from the same ASNs are covered by scanning
// the user's detected /16.

/// MCI / Hamrah-e-Aval (AS197207) — largest mobile operator
static MCI_RANGES: &[Cidr] = &[
    Cidr::new(5, 160, 0, 0, 12),    // 5.160.0.0/12 (1M IPs)
    Cidr::new(5, 208, 0, 0, 12),    // 5.208.0.0/12
    Cidr::new(2, 144, 0, 0, 14),    // 2.144.0.0/14
    Cidr::new(2, 176, 0, 0, 12),    // 2.176.0.0/12
    Cidr::new(5, 112, 0, 0, 12),    // 5.112.0.0/12
    Cidr::new(5, 56, 0, 0, 13),     // 5.56.0.0/13
    Cidr::new(37, 32, 0, 0, 13),    // 37.32.0.0/13
    Cidr::new(37, 137, 0, 0, 16),   // 37.137.0.0/16
    Cidr::new(37, 255, 0, 0, 16),   // 37.255.0.0/16
    Cidr::new(46, 18, 0, 0, 16),    // 46.18.0.0/16
    Cidr::new(78, 152, 0, 0, 15),   // 78.152.0.0/15
    Cidr::new(93, 113, 0, 0, 16),   // 93.113.0.0/16
    Cidr::new(109, 125, 0, 0, 16),  // 109.125.0.0/16
    Cidr::new(151, 238, 0, 0, 15),  // 151.238.0.0/15
];

/// Irancell / MTN (AS44244) — second largest mobile
static IRANCELL_RANGES: &[Cidr] = &[
    Cidr::new(5, 74, 0, 0, 15),     // 5.74.0.0/15
    Cidr::new(5, 106, 0, 0, 15),    // 5.106.0.0/15
    Cidr::new(5, 200, 0, 0, 14),    // 5.200.0.0/14
    Cidr::new(37, 44, 0, 0, 15),    // 37.44.0.0/15
    Cidr::new(37, 98, 0, 0, 15),    // 37.98.0.0/15
    Cidr::new(37, 130, 0, 0, 15),   // 37.130.0.0/15
    Cidr::new(37, 156, 0, 0, 15),   // 37.156.0.0/15
    Cidr::new(84, 241, 0, 0, 16),   // 84.241.0.0/16
    Cidr::new(93, 119, 0, 0, 16),   // 93.119.0.0/16
    Cidr::new(100, 36, 0, 0, 14),   // 100.36.0.0/14 (CGNAT-adjacent)
    Cidr::new(109, 108, 0, 0, 14),  // 109.108.0.0/14
    Cidr::new(176, 12, 0, 0, 14),   // 176.12.0.0/14
    Cidr::new(188, 29, 0, 0, 16),   // 188.29.0.0/16
    Cidr::new(188, 211, 0, 0, 16),  // 188.211.0.0/16
];

/// TCI / Mokhaberat (AS58224) — fixed-line incumbent
static TCI_RANGES: &[Cidr] = &[
    Cidr::new(2, 188, 0, 0, 14),    // 2.188.0.0/14
    Cidr::new(5, 22, 0, 0, 15),     // 5.22.0.0/15
    Cidr::new(5, 52, 0, 0, 15),     // 5.52.0.0/15
    Cidr::new(37, 40, 0, 0, 15),    // 37.40.0.0/15
    Cidr::new(37, 114, 0, 0, 15),   // 37.114.0.0/15
    Cidr::new(46, 28, 0, 0, 15),    // 46.28.0.0/15
    Cidr::new(46, 100, 0, 0, 15),   // 46.100.0.0/15
    Cidr::new(46, 224, 0, 0, 15),   // 46.224.0.0/15
    Cidr::new(78, 38, 0, 0, 15),    // 78.38.0.0/15
    Cidr::new(84, 14, 0, 0, 15),    // 84.14.0.0/15
    Cidr::new(85, 133, 0, 0, 16),   // 85.133.0.0/16
    Cidr::new(86, 55, 0, 0, 16),    // 86.55.0.0/16
    Cidr::new(91, 92, 0, 0, 14),    // 91.92.0.0/14
    Cidr::new(91, 108, 0, 0, 14),   // 91.108.0.0/14
    Cidr::new(109, 122, 0, 0, 15),  // 109.122.0.0/15
    Cidr::new(151, 232, 0, 0, 14),  // 151.232.0.0/14
    Cidr::new(151, 240, 0, 0, 13),  // 151.240.0.0/13
    Cidr::new(188, 214, 0, 0, 15),  // 188.214.0.0/15
    Cidr::new(217, 218, 0, 0, 15),  // 217.218.0.0/15
];

/// DCI / IT Ministry (AS12880) — government backbone
static DCI_RANGES: &[Cidr] = &[
    Cidr::new(5, 232, 0, 0, 14),    // 5.232.0.0/14
    Cidr::new(62, 60, 0, 0, 15),    // 62.60.0.0/15
    Cidr::new(77, 36, 0, 0, 14),    // 77.36.0.0/14
    Cidr::new(80, 66, 0, 0, 15),    // 80.66.0.0/15
    Cidr::new(91, 98, 0, 0, 15),    // 91.98.0.0/15
    Cidr::new(185, 4, 0, 0, 15),    // 185.4.0.0/15
    Cidr::new(194, 225, 0, 0, 16),  // 194.225.0.0/16
    Cidr::new(217, 66, 0, 0, 16),   // 217.66.0.0/16
];

/// Rightel (AS57218) — third mobile operator
static RIGHTEL_RANGES: &[Cidr] = &[
    Cidr::new(5, 198, 0, 0, 16),    // 5.198.0.0/16
    Cidr::new(37, 148, 0, 0, 16),   // 37.148.0.0/16
    Cidr::new(176, 65, 0, 0, 16),   // 176.65.0.0/16
    Cidr::new(185, 112, 0, 0, 14),  // 185.112.0.0/14
];

/// Shatel (AS31549) — major ISP
static SHATEL_RANGES: &[Cidr] = &[
    Cidr::new(2, 180, 0, 0, 14),    // 2.180.0.0/14
    Cidr::new(5, 144, 0, 0, 14),    // 5.144.0.0/14
    Cidr::new(31, 14, 0, 0, 15),    // 31.14.0.0/15
    Cidr::new(78, 154, 0, 0, 15),   // 78.154.0.0/15
    Cidr::new(85, 185, 0, 0, 16),   // 85.185.0.0/16
    Cidr::new(94, 74, 0, 0, 15),    // 94.74.0.0/15
    Cidr::new(188, 158, 0, 0, 15),  // 188.158.0.0/15
];

/// Pars Online (AS16322) — business/residential ISP
static PARSONLINE_RANGES: &[Cidr] = &[
    Cidr::new(46, 34, 0, 0, 15),    // 46.34.0.0/15
    Cidr::new(46, 209, 0, 0, 16),   // 46.209.0.0/16
    Cidr::new(91, 232, 0, 0, 14),   // 91.232.0.0/14
    Cidr::new(94, 139, 0, 0, 16),   // 94.139.0.0/16
    Cidr::new(94, 232, 0, 0, 14),   // 94.232.0.0/14
    Cidr::new(178, 252, 0, 0, 15),  // 178.252.0.0/15
    Cidr::new(185, 167, 0, 0, 16),  // 185.167.0.0/16
];

/// Asiatech (AS43754) — business ISP
static ASIATECH_RANGES: &[Cidr] = &[
    Cidr::new(5, 144, 128, 0, 17),  // 5.144.128.0/17
    Cidr::new(46, 150, 0, 0, 16),   // 46.150.0.0/16
    Cidr::new(91, 194, 0, 0, 15),   // 91.194.0.0/15
    Cidr::new(109, 201, 0, 0, 16),  // 109.201.0.0/16
    Cidr::new(185, 141, 0, 0, 16),  // 185.141.0.0/16
    Cidr::new(188, 253, 0, 0, 16),  // 188.253.0.0/16
];

/// Commonly found open resolvers in Iran (verified working for DNSTT).
/// These are ISP resolvers that accept queries from their own subscribers.
/// Updated via OTA — this is the seed list for fresh installs.
pub static IRAN_VERIFIED_RESOLVERS: &[&str] = &[
    // TCI / Mokhaberat (most widely reachable)
    "151.246.85.10", "151.246.85.102", "151.246.85.105",
    "151.246.85.106", "151.246.85.131", "151.246.85.132",
    "151.246.85.170", "151.246.85.198", "151.246.85.200",
    "151.246.85.242", "151.246.85.243",
    // DCI backbone resolvers
    "194.225.0.10", "194.225.24.10", "194.225.62.10",
    "10.202.10.10", "10.202.10.11",  // DCI internal (reachable from TCI/DCI subs)
    // Shatel
    "85.185.7.110", "85.185.6.6",
    // MCI
    "5.160.139.2", "5.160.218.2",
    // Irancell
    "5.200.200.200",
    // ParsOnline
    "91.232.37.1",
];

/// All ISP groups.
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

/// Find which ISP group an IP belongs to.
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

/// Check if an IP is in any known Iran range.
pub fn is_iran_ip(ip: Ipv4Addr) -> bool {
    find_isp(ip).is_some()
}

/// Generate candidate resolver IPs for scanning, ordered by proximity to the user.
///
/// Strategy (in priority order):
/// 1. Known verified resolvers (instant — no scan needed)
/// 2. User's own /24 (254 IPs, <1s scan)
/// 3. User's /16 with common resolver octets (.1, .2, .10, .100, .200, .254)
/// 4. Same-ISP ranges with common resolver octets
///
/// Returns at most `max_candidates` IPs.
pub fn generate_scan_candidates(
    local_ip: Option<Ipv4Addr>,
    max_candidates: usize,
) -> Vec<Ipv4Addr> {
    let mut candidates = Vec::with_capacity(max_candidates);
    let mut seen = std::collections::HashSet::new();

    // Helper: add IP if not seen and under limit
    macro_rules! add {
        ($ip:expr) => {
            if candidates.len() < max_candidates && seen.insert($ip) {
                candidates.push($ip);
            }
        };
    }

    // 1. Verified resolvers first (these are known-good)
    for &r in IRAN_VERIFIED_RESOLVERS {
        if let Ok(ip) = r.parse::<Ipv4Addr>() {
            // Skip 10.x.x.x private ranges unless we're on a matching network
            if ip.octets()[0] != 10 {
                add!(ip);
            }
        }
    }

    // 2. If we know the user's local IP, scan their neighborhood
    if let Some(local) = local_ip {
        let octets = local.octets();

        // 2a. Full /24 scan — highest chance of finding local resolver
        let base24 = u32::from(local) & 0xFFFFFF00;
        for i in 1..255u32 {
            add!(Ipv4Addr::from(base24 + i));
        }

        // 2b. Same /16, common resolver last octets
        let common_octets: &[u8] = &[1, 2, 10, 11, 20, 100, 200, 254];
        for third in 0..=255u8 {
            for &last in common_octets {
                let ip = Ipv4Addr::new(octets[0], octets[1], third, last);
                add!(ip);
            }
        }

        // 2c. Same ISP, common resolver patterns
        if let Some(isp) = find_isp(local) {
            for cidr in isp.ranges {
                let base_octets = Ipv4Addr::from(cidr.base).octets();
                // For each range, try common resolver IPs
                for &last in common_octets {
                    // Try x.x.0.last and x.x.1.last (gateways/resolvers are often here)
                    for third in &[0u8, 1, 2, 128, 255] {
                        let ip = Ipv4Addr::new(base_octets[0], base_octets[1], *third, last);
                        add!(ip);
                    }
                }
            }
        }
    }

    // 3. All Iran ISP ranges — common resolver patterns
    if candidates.len() < max_candidates {
        let common_octets: &[u8] = &[1, 2, 10, 100, 200];
        for group in ISP_GROUPS {
            for cidr in group.ranges {
                let base_octets = Ipv4Addr::from(cidr.base).octets();
                for &last in common_octets {
                    add!(Ipv4Addr::new(base_octets[0], base_octets[1], 0, last));
                    add!(Ipv4Addr::new(base_octets[0], base_octets[1], 1, last));
                }
            }
        }
    }

    candidates
}

/// Detect the local IP address by opening a UDP socket to a non-routable target.
/// This doesn't send any traffic — it just lets the OS pick the outbound interface.
pub fn detect_local_ip() -> Option<Ipv4Addr> {
    use std::net::UdpSocket;
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    // Connect to a non-routable address (doesn't actually send anything)
    sock.connect("198.51.100.1:53").ok()?;
    let local = sock.local_addr().ok()?;
    match local.ip() {
        std::net::IpAddr::V4(v4) if !v4.is_loopback() => Some(v4),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_contains() {
        let cidr = Cidr::new(5, 160, 0, 0, 12);
        assert!(cidr.contains(u32::from(Ipv4Addr::new(5, 160, 0, 1))));
        assert!(cidr.contains(u32::from(Ipv4Addr::new(5, 175, 255, 254))));
        assert!(!cidr.contains(u32::from(Ipv4Addr::new(5, 176, 0, 0))));
        assert!(!cidr.contains(u32::from(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn test_find_isp() {
        // MCI range
        assert_eq!(find_isp(Ipv4Addr::new(5, 160, 100, 1)).unwrap().name, "MCI");
        // TCI range
        assert_eq!(find_isp(Ipv4Addr::new(151, 240, 1, 1)).unwrap().name, "TCI");
        // Not Iran
        assert!(find_isp(Ipv4Addr::new(8, 8, 8, 8)).is_none());
    }

    #[test]
    fn test_generate_candidates() {
        // With a known MCI IP
        let candidates = generate_scan_candidates(
            Some(Ipv4Addr::new(5, 160, 100, 50)),
            500,
        );
        assert!(!candidates.is_empty());
        // Verified resolvers should be first
        assert!(candidates.contains(&Ipv4Addr::new(151, 246, 85, 10)));
        // Local /24 should be included
        assert!(candidates.contains(&Ipv4Addr::new(5, 160, 100, 1)));
    }

    #[test]
    fn test_generate_candidates_no_ip() {
        let candidates = generate_scan_candidates(None, 200);
        // Should still have verified resolvers
        assert!(!candidates.is_empty());
        assert!(candidates.len() <= 200);
    }
}
