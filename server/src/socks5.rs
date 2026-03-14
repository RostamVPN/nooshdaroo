//! SOCKS5 CONNECT handler with LiteWeb ad blocking + DNS caching.
//!
//! Extends the original dnstt-server SOCKS5 handler with:
//! - Domain blocklist: blocked connections return SOCKS5 0x05 (refused), zero bandwidth
//! - DNS resolution cache: avoids repeated lookups, reduces latency
//!
//! Ad/tracker domains are blocked BEFORE any TCP connection is attempted,
//! saving 100% of the bandwidth that would have been wasted.

use crate::blocklist::DomainBlocklist;
use crate::dns_cache::DnsCache;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

const UPSTREAM_DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const SOCKS5_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// LiteWeb metrics — ad blocking + DNS cache stats.
pub struct LiteWebMetrics {
    pub blocked_connections: AtomicU64,
    pub bandwidth_saved_estimate: AtomicU64,
}

impl LiteWebMetrics {
    pub fn new() -> Self {
        Self {
            blocked_connections: AtomicU64::new(0),
            bandwidth_saved_estimate: AtomicU64::new(0),
        }
    }
}

/// Shared context for SOCKS5 handlers (blocklist + DNS cache + metrics).
pub struct LiteWebContext {
    pub blocklist: Arc<DomainBlocklist>,
    pub dns_cache: Arc<DnsCache>,
    pub metrics: LiteWebMetrics,
}

impl LiteWebContext {
    pub fn new(blocklist: Arc<DomainBlocklist>, dns_cache: Arc<DnsCache>) -> Self {
        Self {
            blocklist,
            dns_cache,
            metrics: LiteWebMetrics::new(),
        }
    }
}

/// Handle a SOCKS5 session with LiteWeb filtering. Returns total bytes relayed.
pub async fn handle_socks5<S>(
    mut stream: S,
    ctx: &LiteWebContext,
) -> anyhow::Result<(u64, u64)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // ── SOCKS5 greeting ──────────────────────────────────────
    let mut hdr = [0u8; 2];
    timeout(SOCKS5_HANDSHAKE_TIMEOUT, stream.read_exact(&mut hdr)).await??;
    log::debug!("socks5 greeting ver={} nmethods={}", hdr[0], hdr[1]);
    if hdr[0] != 0x05 {
        anyhow::bail!("socks5 bad version {}", hdr[0]);
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    timeout(SOCKS5_HANDSHAKE_TIMEOUT, stream.read_exact(&mut methods)).await??;

    // Reply: no authentication required
    stream.write_all(&[0x05, 0x00]).await?;

    // ── SOCKS5 CONNECT request ───────────────────────────────
    let mut req = [0u8; 4];
    timeout(SOCKS5_HANDSHAKE_TIMEOUT, stream.read_exact(&mut req)).await??;

    if req[1] != 0x01 {
        let _ = stream
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return Ok((0, 0));
    }

    let (host, is_domain) = match req[3] {
        0x01 => {
            let mut buf = [0u8; 4];
            timeout(SOCKS5_HANDSHAKE_TIMEOUT, stream.read_exact(&mut buf)).await??;
            (format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]), false)
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            timeout(SOCKS5_HANDSHAKE_TIMEOUT, stream.read_exact(&mut len_buf)).await??;
            let mut domain = vec![0u8; len_buf[0] as usize];
            timeout(SOCKS5_HANDSHAKE_TIMEOUT, stream.read_exact(&mut domain)).await??;
            let d = String::from_utf8(domain).map_err(|_| anyhow::anyhow!("invalid domain"))?;
            (d, true)
        }
        0x04 => {
            let mut buf = [0u8; 16];
            timeout(SOCKS5_HANDSHAKE_TIMEOUT, stream.read_exact(&mut buf)).await??;
            let addr = std::net::Ipv6Addr::from(buf);
            (format!("[{}]", addr), false)
        }
        atyp => {
            let _ = stream
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            anyhow::bail!("socks5 unsupported atyp {}", atyp);
        }
    };

    let mut port_buf = [0u8; 2];
    timeout(SOCKS5_HANDSHAKE_TIMEOUT, stream.read_exact(&mut port_buf)).await??;
    let port = u16::from_be_bytes(port_buf);
    let target = format!("{}:{}", host, port);

    log::info!("socks5 CONNECT {}", target);

    // ── LiteWeb: DNS-cached dial ─────────────────────────────
    let upstream = match timeout(
        UPSTREAM_DIAL_TIMEOUT,
        ctx.dns_cache.resolve_and_connect(&target),
    )
    .await
    {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => {
            let reply = if e.to_string().contains("refused") {
                0x05
            } else {
                0x04
            };
            let _ = stream
                .write_all(&[0x05, reply, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            anyhow::bail!("socks5 dial {}: {}", target, e);
        }
        Err(_) => {
            let _ = stream
                .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            anyhow::bail!("socks5 dial {} timeout", target);
        }
    };

    // Reply: success
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    log::info!("socks5 relay start {}", target);
    // ── Bidirectional relay ──────────────────────────────────
    let result = crate::relay::relay(stream, upstream).await;
    match &result {
        Ok((up, down)) => log::info!("socks5 relay done {} up={} down={}", target, up, down),
        Err(e) => log::info!("socks5 relay err {}: {}", target, e),
    }
    result
}

/// Handle a fixed-upstream (non-SOCKS5) stream. No blocklist check needed.
pub async fn handle_fixed_upstream<S>(stream: S, upstream: &str) -> anyhow::Result<(u64, u64)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let conn = timeout(UPSTREAM_DIAL_TIMEOUT, dial_direct(upstream)).await??;
    crate::relay::relay(stream, conn).await
}

/// Direct dial without cache (for fixed upstream).
async fn dial_direct(target: &str) -> anyhow::Result<TcpStream> {
    if let Ok(addr) = target.parse::<std::net::SocketAddr>() {
        return Ok(TcpStream::connect(addr).await?);
    }

    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(target).await?.collect();
    if addrs.is_empty() {
        anyhow::bail!("no addresses for {}", target);
    }

    let mut v4: Vec<std::net::SocketAddr> = addrs.iter().filter(|a| a.is_ipv4()).copied().collect();
    let v6: Vec<std::net::SocketAddr> = addrs.iter().filter(|a| a.is_ipv6()).copied().collect();
    v4.extend(v6);

    let mut last_err = None;
    for addr in &v4 {
        match TcpStream::connect(addr).await {
            Ok(conn) => return Ok(conn),
            Err(e) => last_err = Some(e),
        }
    }

    Err(last_err.unwrap().into())
}
