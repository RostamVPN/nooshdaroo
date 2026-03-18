//! TTL-aware DNS resolution cache with egress IP round-robin.
//!
//! Caches resolved socket addresses by hostname to avoid repeated DNS lookups
//! through the bandwidth-constrained DNS tunnel. Uses DashMap for lock-free
//! concurrent access.
//!
//! When egress IPs are configured, outbound TCP connections bind to them in
//! round-robin order, distributing port usage across all available IPs.

use dashmap::DashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

const DEFAULT_TTL: Duration = Duration::from_secs(300); // 5 minutes
const MAX_ENTRIES: usize = 10_000;

/// A cached DNS resolution entry.
struct CacheEntry {
    /// Resolved addresses, IPv4 first.
    addrs: Vec<SocketAddr>,
    /// When this entry expires.
    expires: Instant,
    /// Hit count for metrics.
    hits: AtomicU64,
}

/// Thread-safe DNS resolution cache with optional egress IP round-robin.
pub struct DnsCache {
    entries: DashMap<String, CacheEntry>,
    ttl: Duration,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    /// Egress IPs for outbound connections (round-robin).
    egress_ips: Vec<IpAddr>,
    /// Round-robin counter for egress IP selection.
    egress_idx: AtomicUsize,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            ttl: DEFAULT_TTL,
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            egress_ips: Vec::new(),
            egress_idx: AtomicUsize::new(0),
        }
    }

    /// Create with egress IP pool for round-robin outbound binding.
    pub fn with_egress_ips(ips: Vec<IpAddr>) -> Self {
        log::info!("DNS cache: {} egress IPs configured", ips.len());
        for ip in &ips {
            log::info!("  egress: {}", ip);
        }
        Self {
            entries: DashMap::new(),
            ttl: DEFAULT_TTL,
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            egress_ips: ips,
            egress_idx: AtomicUsize::new(0),
        }
    }

    /// Pick the next egress IP (round-robin). Returns None if no egress IPs configured.
    fn next_egress_ip(&self) -> Option<IpAddr> {
        if self.egress_ips.is_empty() {
            return None;
        }
        let idx = self.egress_idx.fetch_add(1, Ordering::Relaxed);
        Some(self.egress_ips[idx % self.egress_ips.len()])
    }

    /// Resolve a hostname with caching. Returns a connected TcpStream.
    /// Uses cached addresses if available and not expired, otherwise resolves
    /// fresh and caches the result.
    pub async fn resolve_and_connect(&self, target: &str) -> anyhow::Result<TcpStream> {
        // Try parsing as a direct socket address first (no caching needed).
        if let Ok(addr) = target.parse::<SocketAddr>() {
            if let Some(ip) = self.next_egress_ip() {
                return Self::connect_with_bind(addr, ip).await;
            }
            return Ok(TcpStream::connect(addr).await?);
        }

        // Check cache.
        if let Some(entry) = self.entries.get(target) {
            if entry.expires > Instant::now() {
                entry.hits.fetch_add(1, Ordering::Relaxed);
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                // Try all cached addresses.
                let addrs = entry.addrs.clone();
                drop(entry); // Release lock before connecting.
                return self.connect_addrs(&addrs, target).await;
            }
            // Expired — will re-resolve below.
        }

        self.cache_misses.fetch_add(1, Ordering::Relaxed);

        // Resolve via system DNS.
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(target).await?.collect();
        if addrs.is_empty() {
            anyhow::bail!("no addresses for {}", target);
        }

        // Sort: IPv4 first (many OCI instances lack IPv6).
        let mut v4: Vec<SocketAddr> = addrs.iter().filter(|a| a.is_ipv4()).copied().collect();
        let v6: Vec<SocketAddr> = addrs.iter().filter(|a| a.is_ipv6()).copied().collect();
        v4.extend(v6);

        // Store in cache.
        // Evict if we're over the limit (simple: just clear old entries).
        if self.entries.len() > MAX_ENTRIES {
            self.evict_expired();
        }

        self.entries.insert(
            target.to_string(),
            CacheEntry {
                addrs: v4.clone(),
                expires: Instant::now() + self.ttl,
                hits: AtomicU64::new(0),
            },
        );

        self.connect_addrs(&v4, target).await
    }

    /// Try connecting to a list of addresses in order, binding to egress IP if configured.
    async fn connect_addrs(&self, addrs: &[SocketAddr], target: &str) -> anyhow::Result<TcpStream> {
        let egress_ip = self.next_egress_ip();
        let mut last_err = None;
        for addr in addrs {
            let result = if let Some(ip) = egress_ip {
                Self::connect_with_bind(*addr, ip).await
            } else {
                TcpStream::connect(addr).await.map_err(Into::into)
            };
            match result {
                Ok(conn) => return Ok(conn),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no addresses for {}", target)))
    }

    /// Connect to a remote address, binding the local socket to a specific egress IP.
    async fn connect_with_bind(remote: SocketAddr, egress: IpAddr) -> anyhow::Result<TcpStream> {
        let socket = if remote.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        socket.set_reuseaddr(true)?;

        // Bind to egress IP with port 0 (kernel picks ephemeral port)
        let bind_addr: SocketAddr = SocketAddr::new(egress, 0);
        socket.bind(bind_addr)?;

        let stream = socket.connect(remote).await?;
        Ok(stream)
    }

    /// Remove expired entries.
    fn evict_expired(&self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| entry.expires > now);
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Cache hit rate as a percentage (0-100).
    pub fn hit_rate_pct(&self) -> f64 {
        let hits = self.cache_hits.load(Ordering::Relaxed) as f64;
        let misses = self.cache_misses.load(Ordering::Relaxed) as f64;
        let total = hits + misses;
        if total == 0.0 {
            0.0
        } else {
            (hits / total) * 100.0
        }
    }
}

/// Spawn periodic eviction (every 60s).
pub fn spawn_eviction_task(cache: std::sync::Arc<DnsCache>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            cache.evict_expired();
        }
    });
}
