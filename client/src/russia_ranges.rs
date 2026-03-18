//! Complete Russia IP space — 11,256 CIDR prefixes from RIPE NCC delegation data.
//!
//! Same architecture as `iran_ranges`: packed binary, O(log n) lookup, ISP groups.
//! Binary: 56,280 bytes (55 KB). Coverage: 45M IPs (100% RIPE-allocated RU space).

use std::net::Ipv4Addr;

const RUSSIA_DATA: &[u8] = include_bytes!("russia_ranges.bin");
const ENTRY_SIZE: usize = 5;
const RUSSIA_COUNT: usize = RUSSIA_DATA.len() / ENTRY_SIZE;

#[inline(always)]
fn entry(i: usize) -> (u32, u8) {
    let off = i * ENTRY_SIZE;
    let net = u32::from_be_bytes([
        RUSSIA_DATA[off], RUSSIA_DATA[off + 1], RUSSIA_DATA[off + 2], RUSSIA_DATA[off + 3],
    ]);
    (net, RUSSIA_DATA[off + 4])
}

/// O(log n) check: is this IP in any Russia CIDR (RIPE + known ISP ranges)?
pub fn is_russia_ip(ip: Ipv4Addr) -> bool {
    let ip_u32 = u32::from(ip);

    // Check ISP groups first
    for group in ISP_GROUPS {
        for cidr in group.ranges {
            if cidr.contains(ip_u32) {
                return true;
            }
        }
    }

    // Binary search RIPE data
    is_in_ripe_data(ip_u32)
}

fn is_in_ripe_data(ip_u32: u32) -> bool {
    let mut lo: usize = 0;
    let mut hi: usize = RUSSIA_COUNT;
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

// ─── ISP identification ─────────────────────────────────────────

use crate::iran_ranges::Cidr;

pub struct IspGroup {
    pub name: &'static str,
    pub asn: u32,
    pub ranges: &'static [Cidr],
}

/// Rostelecom (AS12389) — largest fixed-line + backbone
static ROSTELECOM_RANGES: &[Cidr] = &[
    Cidr::new(5, 3, 0, 0, 16),     Cidr::new(5, 16, 0, 0, 12),
    Cidr::new(5, 100, 0, 0, 14),   Cidr::new(37, 29, 0, 0, 16),
    Cidr::new(46, 39, 0, 0, 16),   Cidr::new(46, 47, 0, 0, 16),
    Cidr::new(77, 37, 0, 0, 16),   Cidr::new(77, 72, 0, 0, 16),
    Cidr::new(79, 133, 0, 0, 16),  Cidr::new(85, 175, 0, 0, 16),
    Cidr::new(87, 226, 0, 0, 15),  Cidr::new(91, 185, 0, 0, 16),
    Cidr::new(95, 167, 0, 0, 16),  Cidr::new(176, 59, 0, 0, 16),
    Cidr::new(188, 168, 0, 0, 14), Cidr::new(213, 24, 0, 0, 14),
    Cidr::new(217, 197, 0, 0, 16),
];

/// MTS (AS8359) — mobile + fixed
static MTS_RANGES: &[Cidr] = &[
    Cidr::new(62, 112, 0, 0, 14),  Cidr::new(62, 118, 0, 0, 15),
    Cidr::new(83, 149, 0, 0, 16),  Cidr::new(83, 234, 0, 0, 15),
    Cidr::new(85, 26, 0, 0, 15),   Cidr::new(95, 153, 0, 0, 16),
    Cidr::new(95, 220, 0, 0, 14),  Cidr::new(176, 14, 0, 0, 15),
    Cidr::new(188, 32, 0, 0, 14),  Cidr::new(213, 87, 0, 0, 16),
    Cidr::new(217, 117, 0, 0, 16),
];

/// Beeline (AS3216) — mobile + fixed
static BEELINE_RANGES: &[Cidr] = &[
    Cidr::new(5, 45, 0, 0, 16),    Cidr::new(37, 144, 0, 0, 14),
    Cidr::new(82, 200, 0, 0, 14),  Cidr::new(85, 21, 0, 0, 16),
    Cidr::new(89, 178, 0, 0, 15),  Cidr::new(95, 24, 0, 0, 14),
    Cidr::new(176, 59, 0, 0, 16),  Cidr::new(178, 64, 0, 0, 14),
    Cidr::new(188, 162, 0, 0, 15), Cidr::new(217, 118, 0, 0, 15),
];

/// Megafon (AS31133) — mobile
static MEGAFON_RANGES: &[Cidr] = &[
    Cidr::new(5, 164, 0, 0, 14),   Cidr::new(77, 94, 0, 0, 15),
    Cidr::new(83, 229, 0, 0, 16),  Cidr::new(92, 242, 0, 0, 15),
    Cidr::new(178, 176, 0, 0, 14), Cidr::new(188, 170, 0, 0, 15),
];

/// Tele2 (AS15378) — mobile
static TELE2_RANGES: &[Cidr] = &[
    Cidr::new(5, 228, 0, 0, 14),   Cidr::new(31, 173, 0, 0, 16),
    Cidr::new(83, 220, 0, 0, 16),  Cidr::new(109, 207, 0, 0, 16),
    Cidr::new(176, 115, 0, 0, 16),
];

/// ER-Telecom / Dom.ru (AS9049) — regional ISP
static ERTELECOM_RANGES: &[Cidr] = &[
    Cidr::new(5, 3, 0, 0, 16),     Cidr::new(5, 79, 0, 0, 16),
    Cidr::new(31, 173, 0, 0, 16),  Cidr::new(37, 113, 0, 0, 16),
    Cidr::new(79, 120, 0, 0, 14),  Cidr::new(92, 50, 0, 0, 15),
    Cidr::new(176, 97, 0, 0, 16),  Cidr::new(178, 46, 0, 0, 15),
    Cidr::new(188, 186, 0, 0, 15),
];

pub static ISP_GROUPS: &[IspGroup] = &[
    IspGroup { name: "Rostelecom", asn: 12389, ranges: ROSTELECOM_RANGES },
    IspGroup { name: "MTS", asn: 8359, ranges: MTS_RANGES },
    IspGroup { name: "Beeline", asn: 3216, ranges: BEELINE_RANGES },
    IspGroup { name: "Megafon", asn: 31133, ranges: MEGAFON_RANGES },
    IspGroup { name: "Tele2", asn: 15378, ranges: TELE2_RANGES },
    IspGroup { name: "ER-Telecom", asn: 9049, ranges: ERTELECOM_RANGES },
];

/// Known working Russian ISP resolvers (seed list).
pub static RUSSIA_VERIFIED_RESOLVERS: &[&str] = &[
    // Rostelecom
    "95.167.120.1", "95.167.120.2",
    // MTS
    "83.149.22.1", "213.87.0.1",
    // Beeline
    "85.21.192.3", "85.21.192.5",
    // Common RU DNS
    "77.88.8.8", "77.88.8.1",       // Yandex DNS
    "77.88.8.88", "77.88.8.2",      // Yandex Safe
    "193.58.251.251",                // SkyDNS
];

/// Calculate total IP addresses in an ISP group's ranges.
pub fn isp_ip_count(group: &IspGroup) -> u64 {
    group.ranges.iter().map(|c| c.size() as u64).sum()
}

/// Find an ISP group by name (case-insensitive) or ASN number.
pub fn find_isp_by_name_or_asn(query: &str) -> Option<&'static IspGroup> {
    if let Ok(asn) = query.parse::<u32>() {
        return ISP_GROUPS.iter().find(|g| g.asn == asn);
    }
    if let Some(stripped) = query.strip_prefix("AS").or_else(|| query.strip_prefix("as")) {
        if let Ok(asn) = stripped.parse::<u32>() {
            return ISP_GROUPS.iter().find(|g| g.asn == asn);
        }
    }
    let lower = query.to_lowercase();
    ISP_GROUPS.iter().find(|g| g.name.to_lowercase() == lower)
}

/// Generate scan candidates for a specific ISP group only.
pub fn generate_isp_candidates(group: &IspGroup, max_candidates: usize) -> Vec<Ipv4Addr> {
    use crate::iran_ranges::Cidr;
    let mut candidates = Vec::with_capacity(max_candidates);
    let mut seen = std::collections::HashSet::with_capacity(max_candidates);

    // Verified resolvers within this ISP's ranges
    for &r in RUSSIA_VERIFIED_RESOLVERS {
        if let Ok(ip) = r.parse::<Ipv4Addr>() {
            let ip_u32 = u32::from(ip);
            if group.ranges.iter().any(|c| c.contains(ip_u32)) {
                if candidates.len() < max_candidates && seen.insert(ip) {
                    candidates.push(ip);
                }
            }
        }
    }

    let common: &[u8] = &[1, 2, 10, 11, 20, 100, 200, 254];
    for cidr in group.ranges {
        let bo = Ipv4Addr::from(cidr.base).octets();
        if cidr.prefix_len <= 16 {
            for third in 0..=255u8 {
                for &last in common {
                    let ip = Ipv4Addr::new(bo[0], bo[1], third, last);
                    if candidates.len() >= max_candidates { return candidates; }
                    if seen.insert(ip) { candidates.push(ip); }
                }
            }
        } else if cidr.prefix_len <= 24 {
            let block_size = 1u32 << (32 - cidr.prefix_len);
            for offset in (0..block_size).step_by(256) {
                let bo2 = Ipv4Addr::from(cidr.base + offset).octets();
                for &last in common {
                    let ip = Ipv4Addr::new(bo2[0], bo2[1], bo2[2], last);
                    if candidates.len() >= max_candidates { return candidates; }
                    if seen.insert(ip) { candidates.push(ip); }
                }
            }
        } else {
            for i in 1..cidr.size().saturating_sub(1) {
                let ip = cidr.nth(i);
                if candidates.len() >= max_candidates { return candidates; }
                if seen.insert(ip) { candidates.push(ip); }
            }
        }
    }

    candidates
}

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

/// Generate scan candidates for Russia, same strategy as Iran.
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

    // 1. Known verified resolvers
    for &r in RUSSIA_VERIFIED_RESOLVERS {
        if let Ok(ip) = r.parse::<Ipv4Addr>() {
            add!(ip);
        }
    }

    // 2. Local neighborhood
    if let Some(local) = local_ip {
        let octets = local.octets();

        let base24 = u32::from(local) & 0xFFFF_FF00;
        for i in 1..255u32 {
            add!(Ipv4Addr::from(base24 + i));
        }

        let common: &[u8] = &[1, 2, 10, 11, 20, 100, 200, 254];
        for third in 0..=255u8 {
            for &last in common {
                add!(Ipv4Addr::new(octets[0], octets[1], third, last));
            }
        }

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
    }

    // 3. All Russia ISP ranges
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

pub fn russia_range_count() -> usize { RUSSIA_COUNT }

pub fn russia_ip_count() -> u64 {
    let mut total: u64 = 0;
    for i in 0..RUSSIA_COUNT {
        let (_, prefix) = entry(i);
        total += 1u64 << (32 - prefix as u32);
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_integrity() {
        assert_eq!(RUSSIA_COUNT, 11256);
        assert_eq!(RUSSIA_DATA.len(), 56280);

        let mut prev = 0u32;
        for i in 0..RUSSIA_COUNT {
            let (net, prefix) = entry(i);
            assert!(net >= prev, "Entry {} not sorted", i);
            assert!(prefix >= 8 && prefix <= 32, "Invalid prefix at {}", i);
            prev = net;
        }
    }

    #[test]
    fn test_is_russia_ip() {
        // Yandex DNS is in Russia
        assert!(is_russia_ip(Ipv4Addr::new(77, 88, 8, 8)));
        // Google DNS is not
        assert!(!is_russia_ip(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn test_russia_ip_count() {
        let count = russia_ip_count();
        assert!(count > 40_000_000, "Expected >40M IPs, got {}", count);
        assert!(count < 50_000_000, "Expected <50M IPs, got {}", count);
    }
}
