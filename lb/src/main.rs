//! dnstt-lb: Lightweight UDP load balancer for nooshdaroo-server.
//!
//! Routes DNS tunnel queries to backend workers using rendezvous hashing
//! on the 8-byte ClientID embedded in the QNAME. This ensures all queries
//! from the same client hit the same backend, preserving KCP session state.

use clap::Parser;
use dashmap::DashMap;
use data_encoding::BASE32_NOPAD;
use log::{debug, info, warn};
use rand::Rng;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::signal;
use tokio::time;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "dnstt-lb",
    about = "DNS tunnel load balancer with ClientID-sticky routing"
)]
struct Args {
    /// Listen address for incoming DNS queries
    #[arg(short, long, default_value = "0.0.0.0:53")]
    listen: String,

    /// Backend server addresses (can specify multiple)
    #[arg(short, long, required = true, num_args = 1..)]
    backend: Vec<String>,

    /// Domain suffix to match (only route matching queries)
    #[arg(short, long)]
    domain: Option<String>,

    /// Enable SO_REUSEPORT for multiple LB instances
    #[arg(long)]
    reuseport: bool,

    /// Health check interval in seconds (0 to disable)
    #[arg(long, default_value = "10")]
    health_interval: u64,

    /// Log stats interval in seconds
    #[arg(long, default_value = "60")]
    stats_interval: u64,
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

struct Backend {
    addr: SocketAddr,
    healthy: AtomicBool,
    socket: Arc<UdpSocket>,
}

// ---------------------------------------------------------------------------
// Transaction ID rewriting
// ---------------------------------------------------------------------------

struct PendingQuery {
    original_txid: u16,
    client_addr: SocketAddr,
    timestamp: Instant,
}

struct TxidRewriter {
    /// Map from (backend_idx, rewritten_txid) -> PendingQuery
    pending: DashMap<(usize, u16), PendingQuery>,
    next_txid: AtomicU16,
}

impl TxidRewriter {
    fn new() -> Self {
        let seed: u16 = rand::thread_rng().gen();
        Self {
            pending: DashMap::with_capacity(8192),
            next_txid: AtomicU16::new(seed),
        }
    }

    /// Rewrite the DNS transaction ID in `packet` before forwarding to a backend.
    /// Stores the original txid + client address so we can restore it on response.
    fn rewrite_forward(
        &self,
        packet: &mut [u8],
        client_addr: SocketAddr,
        backend_idx: usize,
    ) -> Option<u16> {
        if packet.len() < 12 {
            return None;
        }
        let original = u16::from_be_bytes([packet[0], packet[1]]);
        let new_txid = self.next_txid.fetch_add(1, Ordering::Relaxed);
        packet[0] = (new_txid >> 8) as u8;
        packet[1] = new_txid as u8;
        self.pending.insert(
            (backend_idx, new_txid),
            PendingQuery {
                original_txid: original,
                client_addr,
                timestamp: Instant::now(),
            },
        );
        Some(new_txid)
    }

    /// Restore the original transaction ID in a backend response.
    /// Returns the client address to send the response to.
    fn rewrite_response(
        &self,
        packet: &mut [u8],
        backend_idx: usize,
    ) -> Option<SocketAddr> {
        if packet.len() < 12 {
            return None;
        }
        let rewritten = u16::from_be_bytes([packet[0], packet[1]]);
        let entry = self.pending.remove(&(backend_idx, rewritten))?;
        let pq = entry.1;
        packet[0] = (pq.original_txid >> 8) as u8;
        packet[1] = pq.original_txid as u8;
        Some(pq.client_addr)
    }

    /// Remove entries older than `max_age`.
    fn evict_stale(&self, max_age: Duration) {
        let now = Instant::now();
        self.pending.retain(|_, pq| now.duration_since(pq.timestamp) < max_age);
    }

    fn len(&self) -> usize {
        self.pending.len()
    }
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

struct Stats {
    forwarded: AtomicU64,
    responses: AtomicU64,
    non_tunnel: AtomicU64,
    health_ok: AtomicU64,
    health_fail: AtomicU64,
}

impl Stats {
    fn new() -> Self {
        Self {
            forwarded: AtomicU64::new(0),
            responses: AtomicU64::new(0),
            non_tunnel: AtomicU64::new(0),
            health_ok: AtomicU64::new(0),
            health_fail: AtomicU64::new(0),
        }
    }
}

// ---------------------------------------------------------------------------
// QNAME parsing
// ---------------------------------------------------------------------------

/// Parse QNAME labels from a DNS packet starting at `offset`.
/// Returns the list of labels and the position after the QNAME terminator.
fn parse_qname_labels(packet: &[u8], offset: usize) -> Option<(Vec<&[u8]>, usize)> {
    let mut labels: Vec<&[u8]> = Vec::with_capacity(8);
    let mut pos = offset;
    loop {
        if pos >= packet.len() {
            return None;
        }
        let len = packet[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        // Pointer compression — not expected in query QNAME, bail
        if len & 0xc0 == 0xc0 {
            return None;
        }
        if len > 63 {
            return None;
        }
        pos += 1;
        if pos + len > packet.len() {
            return None;
        }
        labels.push(&packet[pos..pos + len]);
        pos += len;
    }
    Some((labels, pos))
}

/// Parse a domain string (e.g. "t.cdn.example.com") into lowercase label bytes.
fn domain_to_labels(domain: &str) -> Vec<Vec<u8>> {
    domain
        .split('.')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase().into_bytes())
        .collect()
}

/// Check if the QNAME labels end with the given domain suffix (case-insensitive).
/// Returns the number of prefix labels (before the suffix).
fn match_domain_suffix(labels: &[&[u8]], suffix: &[Vec<u8>]) -> Option<usize> {
    if labels.len() < suffix.len() {
        return None;
    }
    let prefix_count = labels.len() - suffix.len();
    for (label, suffix_label) in labels[prefix_count..].iter().zip(suffix.iter()) {
        if !label
            .iter()
            .map(|b| b.to_ascii_lowercase())
            .eq(suffix_label.iter().copied())
        {
            return None;
        }
    }
    Some(prefix_count)
}

/// Extract the 8-byte ClientID from a DNS query packet.
///
/// The QNAME prefix labels (before the domain suffix) are concatenated and
/// base32-decoded. The first 8 bytes of the decoded payload are the ClientID.
fn extract_client_id(packet: &[u8], domain_suffix: Option<&[Vec<u8>]>) -> Option<[u8; 8]> {
    // DNS header is 12 bytes minimum
    if packet.len() < 12 {
        return None;
    }
    // QDCOUNT must be >= 1
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return None;
    }

    let (labels, _) = parse_qname_labels(packet, 12)?;
    if labels.is_empty() {
        return None;
    }

    let prefix_count = if let Some(suffix) = domain_suffix {
        match_domain_suffix(&labels, suffix)?
    } else {
        // Without a domain filter, assume the last 2+ labels are domain.
        // Heuristic: prefix labels are base32 (alphanumeric), domain labels
        // usually contain non-base32 chars or are short TLDs. For safety,
        // try decoding all labels and strip from the right until we get
        // enough bytes.
        // Simpler: assume at least 2 domain labels at the end.
        if labels.len() < 3 {
            return None;
        }
        labels.len() - 2
    };

    if prefix_count == 0 {
        return None;
    }

    client_id_from_labels(&labels[..prefix_count])
}

/// Base32-decode the concatenated prefix labels and extract the first 8 bytes.
fn client_id_from_labels(prefix_labels: &[&[u8]]) -> Option<[u8; 8]> {
    // Estimate total encoded length
    let total_len: usize = prefix_labels.iter().map(|l| l.len()).sum();
    if total_len < 2 {
        return None; // way too short to contain 8 bytes after decode
    }

    // Concatenate and uppercase for base32 decode
    let mut encoded = Vec::with_capacity(total_len);
    for label in prefix_labels {
        for &b in *label {
            encoded.push(b.to_ascii_uppercase());
        }
    }

    let decoded = BASE32_NOPAD.decode(&encoded).ok()?;
    if decoded.len() < 8 {
        return None;
    }

    let mut id = [0u8; 8];
    id.copy_from_slice(&decoded[..8]);

    // Zero ClientID is invalid (uninitialized / not a tunnel query)
    if id == [0u8; 8] {
        return None;
    }

    Some(id)
}

// ---------------------------------------------------------------------------
// Rendezvous hashing
// ---------------------------------------------------------------------------

/// Compute FNV-1a weight for rendezvous hashing.
#[inline]
fn rendezvous_weight(client_id: &[u8; 8], backend_idx: u32) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in client_id {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    for b in backend_idx.to_le_bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Pick the best healthy backend for a given ClientID using rendezvous hashing
/// (Highest Random Weight). If all backends are down, fall back to hashing
/// across all of them anyway.
fn pick_backend(client_id: &[u8; 8], backends: &[Backend]) -> usize {
    let mut best_idx = 0;
    let mut best_weight = 0u64;
    let mut any_healthy = false;

    for (i, backend) in backends.iter().enumerate() {
        if !backend.healthy.load(Ordering::Relaxed) {
            continue;
        }
        any_healthy = true;
        let w = rendezvous_weight(client_id, i as u32);
        if w > best_weight {
            best_weight = w;
            best_idx = i;
        }
    }

    if any_healthy {
        return best_idx;
    }

    // All backends unhealthy — last resort: route to any
    warn!("all backends unhealthy, routing to best-effort");
    for (i, _) in backends.iter().enumerate() {
        let w = rendezvous_weight(client_id, i as u32);
        if w > best_weight {
            best_weight = w;
            best_idx = i;
        }
    }
    best_idx
}

// ---------------------------------------------------------------------------
// Health checking
// ---------------------------------------------------------------------------

/// Build a minimal DNS query for "." (root) A record.
/// Used as a liveness probe — any DNS server will respond to this.
fn build_health_probe(txid: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(17);
    // Header
    pkt.extend_from_slice(&txid.to_be_bytes()); // Transaction ID
    pkt.extend_from_slice(&[0x00, 0x00]); // Flags: standard query
    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
    pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0
    // QNAME: root "."
    pkt.push(0x00);
    // QTYPE: A (1)
    pkt.extend_from_slice(&[0x00, 0x01]);
    // QCLASS: IN (1)
    pkt.extend_from_slice(&[0x00, 0x01]);
    pkt
}

async fn health_check_loop(
    backends: Arc<Vec<Backend>>,
    interval: Duration,
    stats: Arc<Stats>,
) {
    if interval.is_zero() {
        return;
    }

    let timeout = Duration::from_secs(2);
    let mut ticker = time::interval(interval);

    loop {
        ticker.tick().await;

        for (i, backend) in backends.iter().enumerate() {
            let txid: u16 = rand::thread_rng().gen();
            let probe = build_health_probe(txid);

            // Send probe through the backend's connected socket
            let sock = &backend.socket;
            if sock.send(&probe).await.is_err() {
                backend.healthy.store(false, Ordering::Relaxed);
                stats.health_fail.fetch_add(1, Ordering::Relaxed);
                warn!("backend {} ({}) health check send failed", i, backend.addr);
                continue;
            }

            // Wait for response with timeout
            let mut buf = [0u8; 512];
            match time::timeout(timeout, sock.recv(&mut buf)).await {
                Ok(Ok(n)) if n >= 12 => {
                    let resp_txid = u16::from_be_bytes([buf[0], buf[1]]);
                    if resp_txid == txid {
                        if !backend.healthy.load(Ordering::Relaxed) {
                            info!("backend {} ({}) is now healthy", i, backend.addr);
                        }
                        backend.healthy.store(true, Ordering::Relaxed);
                        stats.health_ok.fetch_add(1, Ordering::Relaxed);
                    } else {
                        // Got a response but txid mismatch — likely a queued
                        // tunnel response. Still counts as alive.
                        backend.healthy.store(true, Ordering::Relaxed);
                        stats.health_ok.fetch_add(1, Ordering::Relaxed);
                    }
                }
                _ => {
                    if backend.healthy.load(Ordering::Relaxed) {
                        warn!("backend {} ({}) is now unhealthy", i, backend.addr);
                    }
                    backend.healthy.store(false, Ordering::Relaxed);
                    stats.health_fail.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Backend receive loop
// ---------------------------------------------------------------------------

async fn backend_recv_loop(
    backend_idx: usize,
    socket: Arc<UdpSocket>,
    listen_socket: Arc<UdpSocket>,
    txid_rewriter: Arc<TxidRewriter>,
    stats: Arc<Stats>,
) {
    let mut buf = [0u8; 4096];
    loop {
        let n = match socket.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                debug!("backend {} recv error: {}", backend_idx, e);
                continue;
            }
        };
        let mut packet = buf[..n].to_vec();
        if let Some(client_addr) = txid_rewriter.rewrite_response(&mut packet, backend_idx) {
            if let Err(e) = listen_socket.send_to(&packet, client_addr).await {
                debug!("send to client {} failed: {}", client_addr, e);
            }
            stats.responses.fetch_add(1, Ordering::Relaxed);
        } else {
            // Response for an expired/unknown txid — drop it
            debug!(
                "backend {} sent response with unknown txid, dropping",
                backend_idx
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Stats logger
// ---------------------------------------------------------------------------

async fn stats_logger(
    interval: Duration,
    stats: Arc<Stats>,
    txid_rewriter: Arc<TxidRewriter>,
    backends: Arc<Vec<Backend>>,
) {
    if interval.is_zero() {
        return;
    }
    let mut ticker = time::interval(interval);
    loop {
        ticker.tick().await;
        let healthy_count = backends
            .iter()
            .filter(|b| b.healthy.load(Ordering::Relaxed))
            .count();
        info!(
            "[STATS] forwarded={} responses={} non_tunnel={} pending_txid={} backends={}/{}",
            stats.forwarded.load(Ordering::Relaxed),
            stats.responses.load(Ordering::Relaxed),
            stats.non_tunnel.load(Ordering::Relaxed),
            txid_rewriter.len(),
            healthy_count,
            backends.len(),
        );
    }
}

// ---------------------------------------------------------------------------
// Stale entry evictor
// ---------------------------------------------------------------------------

async fn eviction_loop(txid_rewriter: Arc<TxidRewriter>) {
    let max_age = Duration::from_secs(30);
    let mut ticker = time::interval(Duration::from_secs(10));
    loop {
        ticker.tick().await;
        let before = txid_rewriter.len();
        txid_rewriter.evict_stale(max_age);
        let evicted = before.saturating_sub(txid_rewriter.len());
        if evicted > 0 {
            debug!("evicted {} stale pending entries", evicted);
        }
    }
}

// ---------------------------------------------------------------------------
// Socket binding helpers
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
async fn bind_listen_socket(addr: &SocketAddr, reuseport: bool) -> std::io::Result<UdpSocket> {
    use std::os::unix::io::AsRawFd;

    let std_sock = socket2::Socket::new(
        if addr.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        },
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    std_sock.set_reuse_address(true)?;
    if reuseport {
        std_sock.set_reuse_port(true)?;
    }
    std_sock.set_nonblocking(true)?;
    std_sock.bind(&(*addr).into())?;

    // Increase recv buffer for burst absorption
    let _ = std_sock.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = std_sock.set_send_buffer_size(4 * 1024 * 1024);

    UdpSocket::from_std(std_sock.into())
}

#[cfg(not(target_os = "linux"))]
async fn bind_listen_socket(addr: &SocketAddr, _reuseport: bool) -> std::io::Result<UdpSocket> {
    let sock = UdpSocket::bind(addr).await?;
    Ok(sock)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    // Parse domain suffix
    let domain_suffix: Option<Vec<Vec<u8>>> = args.domain.as_ref().map(|d| domain_to_labels(d));

    // Resolve and create backends
    let mut backends = Vec::with_capacity(args.backend.len());
    for addr_str in &args.backend {
        let addr: SocketAddr = addr_str.parse().map_err(|e| {
            format!("invalid backend address '{}': {}", addr_str, e)
        })?;

        // Create a dedicated UDP socket per backend, connected to the backend addr.
        // Connected sockets avoid per-send address lookup overhead.
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(addr).await?;

        info!("backend {}: {}", backends.len(), addr);
        backends.push(Backend {
            addr,
            healthy: AtomicBool::new(true), // assume healthy at start
            socket: Arc::new(sock),
        });
    }

    let backends = Arc::new(backends);

    // Bind listen socket
    let listen_addr: SocketAddr = args.listen.parse().map_err(|e| {
        format!("invalid listen address '{}': {}", args.listen, e)
    })?;
    let listen_socket = Arc::new(bind_listen_socket(&listen_addr, args.reuseport).await?);
    info!("listening on {}", listen_addr);

    if let Some(ref d) = args.domain {
        info!("domain filter: {}", d);
    }

    // Shared state
    let txid_rewriter = Arc::new(TxidRewriter::new());
    let stats = Arc::new(Stats::new());

    // Spawn per-backend receive loops
    for (i, backend) in backends.iter().enumerate() {
        tokio::spawn(backend_recv_loop(
            i,
            Arc::clone(&backend.socket),
            Arc::clone(&listen_socket),
            Arc::clone(&txid_rewriter),
            Arc::clone(&stats),
        ));
    }

    // Spawn health check
    if args.health_interval > 0 {
        tokio::spawn(health_check_loop(
            Arc::clone(&backends),
            Duration::from_secs(args.health_interval),
            Arc::clone(&stats),
        ));
    }

    // Spawn stats logger
    if args.stats_interval > 0 {
        tokio::spawn(stats_logger(
            Duration::from_secs(args.stats_interval),
            Arc::clone(&stats),
            Arc::clone(&txid_rewriter),
            Arc::clone(&backends),
        ));
    }

    // Spawn stale entry evictor
    tokio::spawn(eviction_loop(Arc::clone(&txid_rewriter)));

    // Prepare domain suffix reference for the hot loop
    let domain_ref = domain_suffix.as_deref();

    // Fallback ClientID for non-tunnel queries (route to consistent backend)
    let fallback_id: [u8; 8] = [0xff; 8];

    info!(
        "dnstt-lb ready: {} backends, health_interval={}s, stats_interval={}s",
        backends.len(),
        args.health_interval,
        args.stats_interval,
    );

    // Main receive loop
    let mut buf = [0u8; 4096];
    loop {
        tokio::select! {
            result = listen_socket.recv_from(&mut buf) => {
                let (n, client_addr) = match result {
                    Ok(v) => v,
                    Err(e) => {
                        debug!("recv_from error: {}", e);
                        continue;
                    }
                };

                let mut packet = buf[..n].to_vec();

                // Extract ClientID for routing
                let client_id = match extract_client_id(&packet, domain_ref) {
                    Some(id) => id,
                    None => {
                        stats.non_tunnel.fetch_add(1, Ordering::Relaxed);
                        // Still forward — could be a legit DNS query or a tunnel
                        // query we couldn't parse. Route deterministically.
                        fallback_id
                    }
                };

                let backend_idx = pick_backend(&client_id, &backends);

                if txid_rewriter
                    .rewrite_forward(&mut packet, client_addr, backend_idx)
                    .is_none()
                {
                    continue;
                }

                if let Err(e) = backends[backend_idx].socket.send(&packet).await {
                    debug!(
                        "forward to backend {} ({}) failed: {}",
                        backend_idx, backends[backend_idx].addr, e
                    );
                    continue;
                }

                stats.forwarded.fetch_add(1, Ordering::Relaxed);
            }
            _ = signal::ctrl_c() => {
                info!("shutting down");
                break;
            }
        }
    }

    // Final stats
    info!(
        "[FINAL] forwarded={} responses={} non_tunnel={} pending_txid={}",
        stats.forwarded.load(Ordering::Relaxed),
        stats.responses.load(Ordering::Relaxed),
        stats.non_tunnel.load(Ordering::Relaxed),
        txid_rewriter.len(),
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS query packet with the given QNAME labels.
    fn make_dns_query(labels: &[&str]) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Header: txid=0x1234, flags=0, qdcount=1
        pkt.extend_from_slice(&[0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // QNAME
        for label in labels {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0x00); // root
        // QTYPE=TXT, QCLASS=IN
        pkt.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]);
        pkt
    }

    #[test]
    fn test_parse_qname_labels() {
        let pkt = make_dns_query(&["abc", "def", "example", "com"]);
        let (labels, end) = parse_qname_labels(&pkt, 12).unwrap();
        assert_eq!(labels.len(), 4);
        assert_eq!(labels[0], b"abc");
        assert_eq!(labels[1], b"def");
        assert_eq!(labels[2], b"example");
        assert_eq!(labels[3], b"com");
        // end should be after the 0x00 terminator
        assert_eq!(pkt[end], 0x00); // QTYPE high byte
    }

    #[test]
    fn test_domain_suffix_matching() {
        let suffix = domain_to_labels("example.com");
        let labels: Vec<&[u8]> = vec![b"abc", b"def", b"example", b"com"];
        assert_eq!(match_domain_suffix(&labels, &suffix), Some(2));

        // Case insensitive
        let labels: Vec<&[u8]> = vec![b"abc", b"EXAMPLE", b"COM"];
        assert_eq!(match_domain_suffix(&labels, &suffix), Some(1));

        // No match
        let labels: Vec<&[u8]> = vec![b"abc", b"other", b"org"];
        assert_eq!(match_domain_suffix(&labels, &suffix), None);

        // Too few labels
        let labels: Vec<&[u8]> = vec![b"com"];
        assert_eq!(match_domain_suffix(&labels, &suffix), None);
    }

    #[test]
    fn test_client_id_extraction() {
        // Create a known 8-byte ClientID
        let client_id: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        // Build payload: 8 bytes client_id + 1 byte padding prefix (0xe0 = no padding)
        let mut payload = Vec::new();
        payload.extend_from_slice(&client_id);
        payload.push(0xe0); // padding prefix with 0 padding bytes

        // Base32 encode
        let encoded = BASE32_NOPAD.encode(&payload);

        // Split into DNS labels (max 63 chars each, but our encoded string is short)
        let label = encoded.to_lowercase();

        let suffix = domain_to_labels("example.com");
        let pkt = make_dns_query(&[&label, "example", "com"]);
        let extracted = extract_client_id(&pkt, Some(&suffix));
        assert_eq!(extracted, Some(client_id));
    }

    #[test]
    fn test_client_id_multi_label() {
        // Test with data split across multiple labels
        let client_id: [u8; 8] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22];
        let mut payload = Vec::new();
        payload.extend_from_slice(&client_id);
        payload.push(0xe0);

        let encoded = BASE32_NOPAD.encode(&payload);
        let lower = encoded.to_lowercase();

        // Split into two labels
        let mid = lower.len() / 2;
        let label1 = &lower[..mid];
        let label2 = &lower[mid..];

        let pkt = make_dns_query(&[label1, label2, "example", "com"]);
        let suffix = domain_to_labels("example.com");
        let extracted = extract_client_id(&pkt, Some(&suffix));
        assert_eq!(extracted, Some(client_id));
    }

    #[test]
    fn test_zero_client_id_rejected() {
        let client_id: [u8; 8] = [0; 8];
        let mut payload = Vec::new();
        payload.extend_from_slice(&client_id);
        payload.push(0xe0);

        let encoded = BASE32_NOPAD.encode(&payload).to_lowercase();
        let pkt = make_dns_query(&[&encoded, "example", "com"]);
        let suffix = domain_to_labels("example.com");
        assert_eq!(extract_client_id(&pkt, Some(&suffix)), None);
    }

    #[test]
    fn test_rendezvous_deterministic() {
        let id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let w1 = rendezvous_weight(&id, 0);
        let w2 = rendezvous_weight(&id, 0);
        assert_eq!(w1, w2);
    }

    #[test]
    fn test_rendezvous_different_backends() {
        let id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let w0 = rendezvous_weight(&id, 0);
        let w1 = rendezvous_weight(&id, 1);
        let w2 = rendezvous_weight(&id, 2);
        // Extremely unlikely all three are equal
        assert!(!(w0 == w1 && w1 == w2));
    }

    #[test]
    fn test_rendezvous_different_clients() {
        let id_a = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let id_b = [9u8, 10, 11, 12, 13, 14, 15, 16];
        let w_a = rendezvous_weight(&id_a, 0);
        let w_b = rendezvous_weight(&id_b, 0);
        assert_ne!(w_a, w_b);
    }

    #[test]
    fn test_txid_rewriter() {
        let rewriter = TxidRewriter::new();

        // Simulate a forward + response cycle
        let mut packet = vec![0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let client_addr: SocketAddr = "1.2.3.4:12345".parse().unwrap();

        let new_txid = rewriter.rewrite_forward(&mut packet, client_addr, 0).unwrap();
        assert_eq!(packet[0], (new_txid >> 8) as u8);
        assert_eq!(packet[1], new_txid as u8);

        // Simulate response
        let mut resp = packet.clone();
        let restored_addr = rewriter.rewrite_response(&mut resp, 0).unwrap();
        assert_eq!(restored_addr, client_addr);
        assert_eq!(resp[0], 0x12);
        assert_eq!(resp[1], 0x34);
    }

    #[test]
    fn test_txid_rewriter_unknown_response() {
        let rewriter = TxidRewriter::new();
        let mut resp = vec![0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(rewriter.rewrite_response(&mut resp, 0).is_none());
    }

    #[test]
    fn test_health_probe_format() {
        let probe = build_health_probe(0xabcd);
        assert!(probe.len() >= 12);
        assert_eq!(probe[0], 0xab);
        assert_eq!(probe[1], 0xcd);
        // QDCOUNT = 1
        assert_eq!(probe[4], 0x00);
        assert_eq!(probe[5], 0x01);
    }

    #[test]
    fn test_short_packet_rejected() {
        let short = vec![0x00; 5];
        assert_eq!(extract_client_id(&short, None), None);
    }
}
