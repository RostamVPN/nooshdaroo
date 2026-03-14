//! Chrome DNS Cover Traffic Generator
//!
//! Makes DNSTT tunnel queries blend with normal Chrome browser DNS behavior.
//! Two components:
//!
//! 1. **Cover queries** — A/AAAA/HTTPS queries for popular domains, timed to
//!    mimic real browsing sessions. These go to the same resolver on the same
//!    UDP socket, so an observer sees a mix of tunnel + normal DNS.
//!
//! 2. **Burst shaping** — Instead of sending tunnel queries at a constant rate,
//!    group them into bursts that match Chrome's "page load" DNS pattern:
//!    5-15 queries in 100-300ms, then 2-8 seconds of relative silence.

use rand::Rng;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;

// ─── Cover domain pools ──────────────────────────────────────────
// These domains are what a typical Chrome user would query.
// Mixed global CDN + popular site domains.

/// Domains that Chrome queries on every startup / tab open.
const CHROME_INFRA_DOMAINS: &[&str] = &[
    "clients1.google.com",
    "clients2.google.com",
    "update.googleapis.com",
    "safebrowsing.googleapis.com",
    "accounts.google.com",
    "ssl.gstatic.com",
    "fonts.googleapis.com",
    "www.gstatic.com",
    "play.googleapis.com",
    "translate.googleapis.com",
];

/// Popular sites for browsing cover traffic.
const BROWSING_DOMAINS: &[&str] = &[
    "www.google.com",
    "www.youtube.com",
    "www.instagram.com",
    "www.whatsapp.com",
    "web.telegram.org",
    "www.wikipedia.org",
    "www.amazon.com",
    "www.github.com",
    "stackoverflow.com",
    "www.reddit.com",
    "mail.google.com",
    "drive.google.com",
    "docs.google.com",
    "calendar.google.com",
    "maps.google.com",
    "news.google.com",
    "fonts.gstatic.com",
    "ajax.googleapis.com",
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "i.ytimg.com",
    "yt3.ggpht.com",
    "lh3.googleusercontent.com",
    "scontent.cdninstagram.com",
    "static.cdninstagram.com",
    "graph.instagram.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "avatars.githubusercontent.com",
    "static.xx.fbcdn.net",
    "connect.facebook.net",
];

/// CDN/analytics domains Chrome queries in the background.
const BACKGROUND_DOMAINS: &[&str] = &[
    "www.googletagmanager.com",
    "www.google-analytics.com",
    "pagead2.googlesyndication.com",
    "adservice.google.com",
    "ocsp.digicert.com",
    "ocsp.pki.goog",
    "crl.pki.goog",
    "dns.google",
    "chrome.cloudflare-dns.com",
    "cloudflareinsights.com",
];

// ─── DNS query types ────────────────────────────────────────────

const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
const QTYPE_HTTPS: u16 = 65; // Chrome sends SVCB/HTTPS since ~2022

// ─── Cover query builder ────────────────────────────────────────

/// Build a realistic DNS query for a cover domain.
/// Chrome sends queries with: RD=1, AD=1, EDNS0 with UDP size 1452.
fn build_cover_query(domain: &str, qtype: u16) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let txid: u16 = rng.gen();

    let mut msg = Vec::with_capacity(128);

    // Header
    msg.extend_from_slice(&txid.to_be_bytes());
    msg.extend_from_slice(&[0x01, 0x20]); // flags: RD=1, AD=1 (Chrome sets AD bit)
    msg.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    msg.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
    msg.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    msg.extend_from_slice(&[0x00, 0x01]); // ARCOUNT=1 (EDNS OPT)

    // Question: QNAME
    for label in domain.split('.') {
        if label.is_empty() { continue; }
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0); // root
    msg.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    msg.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

    // EDNS(0) OPT — Chrome style:
    // - UDP payload 1452 (Chrome's default)
    // - DO flag NOT set (Chrome doesn't do DNSSEC validation)
    // - Empty RDATA (no ECS in most cases)
    msg.push(0x00);                       // root name
    msg.extend_from_slice(&[0x00, 0x29]); // type = OPT
    msg.extend_from_slice(&[0x05, 0xac]); // UDP size = 1452 (Chrome default)
    msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // extended RCODE + flags (no DO)
    msg.extend_from_slice(&[0x00, 0x00]); // RDLENGTH = 0

    msg
}

// ─── Page-load burst simulator ──────────────────────────────────

/// Simulate one "page load" burst: 4-12 cover queries spread over 100-500ms.
/// This mimics Chrome resolving all resources for a page.
/// When ota_domains is non-empty, uses those instead of hardcoded BROWSING_DOMAINS.
async fn simulate_page_load(
    sock: &Arc<UdpSocket>,
    resolver: SocketAddr,
    ota_domains: &[String],
) {
    // Pre-generate all queries and timing in one block (ThreadRng isn't Send)
    let queries = {
        let mut rng = rand::thread_rng();
        let mut queries: Vec<(Vec<u8>, u64)> = Vec::new(); // (query_bytes, delay_before_ms)

        // Pick a primary domain — prefer OTA-pushed domains (verified unblocked)
        let primary: &str = if !ota_domains.is_empty() {
            &ota_domains[rng.gen_range(0..ota_domains.len())]
        } else {
            BROWSING_DOMAINS[rng.gen_range(0..BROWSING_DOMAINS.len())]
        };

        // Chrome always sends A + AAAA for the primary domain
        queries.push((build_cover_query(primary, QTYPE_A), 0));
        queries.push((build_cover_query(primary, QTYPE_AAAA), rng.gen_range(1..10)));

        // Sometimes Chrome also sends HTTPS (type 65) for the primary
        if rng.gen_bool(0.6) {
            queries.push((build_cover_query(primary, QTYPE_HTTPS), rng.gen_range(1..5)));
        }

        // Simulate sub-resource lookups (CDNs, analytics, fonts, etc.)
        let sub_count = rng.gen_range(3..10);
        for _ in 0..sub_count {
            let delay = rng.gen_range(10..120u64);

            let pool_choice: f64 = rng.gen();
            let domain: &str = if pool_choice < 0.5 {
                if !ota_domains.is_empty() {
                    &ota_domains[rng.gen_range(0..ota_domains.len())]
                } else {
                    BROWSING_DOMAINS[rng.gen_range(0..BROWSING_DOMAINS.len())]
                }
            } else if pool_choice < 0.8 {
                BACKGROUND_DOMAINS[rng.gen_range(0..BACKGROUND_DOMAINS.len())]
            } else {
                CHROME_INFRA_DOMAINS[rng.gen_range(0..CHROME_INFRA_DOMAINS.len())]
            };

            queries.push((build_cover_query(domain, QTYPE_A), delay));

            // AAAA query (Chrome sends both in ~80% of lookups)
            if rng.gen_bool(0.8) {
                queries.push((build_cover_query(domain, QTYPE_AAAA), rng.gen_range(0..5)));
            }
        }

        queries
    };
    // rng is dropped here — safe to .await below

    for (query, delay_ms) in queries {
        if delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
        let _ = sock.send_to(&query, resolver).await;
    }
}

// ─── Background Chrome activity ─────────────────────────────────

/// Simulate Chrome's background DNS activity:
/// - Safe Browsing updates (every 30 min)
/// - Predictor pre-resolve (based on typed URLs)
/// - Extension update checks
async fn simulate_chrome_background(
    sock: &Arc<UdpSocket>,
    resolver: SocketAddr,
) {
    let queries: Vec<(Vec<u8>, u64)> = {
        let mut rng = rand::thread_rng();
        let count = rng.gen_range(1..4usize);
        (0..count).map(|_| {
            let domain = CHROME_INFRA_DOMAINS[rng.gen_range(0..CHROME_INFRA_DOMAINS.len())];
            (build_cover_query(domain, QTYPE_A), rng.gen_range(50..500u64))
        }).collect()
    };

    for (query, delay_ms) in queries {
        let _ = sock.send_to(&query, resolver).await;
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
}

// ─── Public API ─────────────────────────────────────────────────

/// Configuration for cover traffic generation.
pub struct CoverConfig {
    /// Average seconds between simulated "page loads" (default: 15)
    pub page_load_interval_secs: u64,
    /// Average seconds between background Chrome queries (default: 45)
    pub background_interval_secs: u64,
    /// Enable cover traffic (default: true)
    pub enabled: bool,
    /// OTA-pushed cover domains (verified unblocked in target region).
    /// When non-empty, these REPLACE the hardcoded BROWSING_DOMAINS for page-load simulation.
    pub ota_domains: Vec<String>,
}

impl Default for CoverConfig {
    fn default() -> Self {
        Self {
            page_load_interval_secs: 15,
            background_interval_secs: 45,
            enabled: true,
            ota_domains: Vec::new(),
        }
    }
}

/// Start the Chrome cover traffic generator.
///
/// Runs as a background tokio task. Sends cover DNS queries through the same
/// resolver as the tunnel, so an observer sees a realistic mix of tunnel
/// queries + normal browsing DNS.
pub async fn start_cover_traffic(
    resolver: SocketAddr,
    config: CoverConfig,
    running: Arc<AtomicBool>,
) {
    if !config.enabled {
        log::debug!("[cover] Disabled");
        return;
    }

    // Dedicated socket for cover queries (separate from tunnel socket
    // to avoid interfering with KCP input parsing)
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            log::warn!("[cover] Failed to bind UDP: {}", e);
            return;
        }
    };

    let ota_domains = &config.ota_domains;
    if !ota_domains.is_empty() {
        log::debug!("[cover] Using {} OTA cover domains", ota_domains.len());
    }
    log::debug!("[cover] Starting Chrome DNS cover traffic to {}", resolver);

    // Initial Chrome startup burst — Chrome does this when it launches
    {
        let startup_queries: Vec<(Vec<u8>, u64)> = {
            let mut rng = rand::thread_rng();
            CHROME_INFRA_DOMAINS.iter().take(5).map(|&domain| {
                (build_cover_query(domain, QTYPE_A), rng.gen_range(5..30u64))
            }).collect()
        };
        for (query, delay_ms) in startup_queries {
            let _ = sock.send_to(&query, resolver).await;
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
    }

    loop {
        if !running.load(Ordering::Relaxed) { break; }

        // Simulate a page load burst
        simulate_page_load(&sock, resolver, ota_domains).await;

        // Pre-compute the wait schedule (rng not held across await)
        let schedule = {
            let mut rng = rand::thread_rng();
            let base = config.page_load_interval_secs as f64;
            let jitter: f64 = rng.gen_range(0.5..2.0);
            let wait = ((base * jitter) as u64).max(3).min(90);
            let bg_wait = config.background_interval_secs.max(5);

            // Pre-generate sleep chunks and background decisions
            let mut schedule: Vec<(u64, bool)> = Vec::new();
            let mut elapsed = 0u64;
            while elapsed < wait {
                let upper = bg_wait.min(wait - elapsed + 1).max(4);
                let chunk = rng.gen_range(3..upper);
                let do_bg = rng.gen_bool(0.3);
                schedule.push((chunk, do_bg));
                elapsed += chunk;
            }
            schedule
        };

        // Execute the pre-computed schedule
        for (sleep_secs, do_background) in schedule {
            tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
            if !running.load(Ordering::Relaxed) { return; }
            if do_background {
                simulate_chrome_background(&sock, resolver).await;
            }
        }
    }

    log::debug!("[cover] Stopped");
}

/// Drain and discard responses on the cover socket.
/// We don't care about cover query responses, but we need to read them
/// so the OS doesn't fill up the receive buffer.
pub async fn drain_cover_responses(sock: &UdpSocket, running: Arc<AtomicBool>) {
    let mut buf = [0u8; 512];
    loop {
        if !running.load(Ordering::Relaxed) { break; }
        match tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf)).await {
            Ok(Ok(_)) => {} // discard
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cover_query_is_valid_dns() {
        let q = build_cover_query("www.google.com", QTYPE_A);
        // Must have header (12) + question
        assert!(q.len() > 12);
        // QR bit must be 0 (query)
        assert_eq!(q[2] & 0x80, 0);
        // QDCOUNT must be 1
        assert_eq!(q[4], 0);
        assert_eq!(q[5], 1);
        // ARCOUNT must be 1 (EDNS)
        assert_eq!(q[10], 0);
        assert_eq!(q[11], 1);
    }

    #[test]
    fn test_cover_query_types() {
        let qa = build_cover_query("example.com", QTYPE_A);
        let qaaaa = build_cover_query("example.com", QTYPE_AAAA);
        let qhttps = build_cover_query("example.com", QTYPE_HTTPS);

        // Different transaction IDs (with overwhelming probability)
        let txid_a = u16::from_be_bytes([qa[0], qa[1]]);
        let txid_aaaa = u16::from_be_bytes([qaaaa[0], qaaaa[1]]);
        // They CAN collide with p=1/65536, but almost never
        assert!(txid_a != txid_aaaa || txid_a != u16::from_be_bytes([qhttps[0], qhttps[1]]));
    }

    #[test]
    fn test_chrome_udp_payload_size() {
        // Chrome EDNS0 advertises 1452 bytes
        let q = build_cover_query("www.google.com", QTYPE_A);
        // Find the OPT record — last 11 bytes
        let opt_start = q.len() - 11;
        // OPT type = 0x00 0x29
        assert_eq!(q[opt_start + 1], 0x00);
        assert_eq!(q[opt_start + 2], 0x29);
        // UDP size = 0x05 0xAC = 1452
        assert_eq!(q[opt_start + 3], 0x05);
        assert_eq!(q[opt_start + 4], 0xAC);
    }
}
