//! dnstt-server-rs — Wire-compatible Rust reimplementation of dnstt-server.
//!
//! Drop-in replacement for the Go dnstt-server. Eliminates the
//! chacha20poly1305 Go 1.22/1.25 incompatibility by using RustCrypto.
//! Adds true multi-threaded async via tokio.
//!
//! Usage:
//!   dnstt-server-rs -config /etc/dnstt/config.json
//!   dnstt-server-rs -gen-key
//!   dnstt-server-rs -udp :53 -privkey-file server.key t.example.com 127.0.0.1:8000

mod blocklist;
mod config;
mod datadog;
mod dns;
mod dns_cache;
mod kcp_manager;
mod noise_session;
mod relay;
mod smux;
mod socks5;
mod turbotunnel;

use crate::blocklist::DomainBlocklist;
use crate::dns::DnsName;
use crate::dns_cache::DnsCache;
use crate::kcp_manager::{KcpManager, Metrics, StreamTask};
use crate::socks5::LiteWebContext;
use bytes::{Buf, BytesMut};
use clap::Parser;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

// ── CLI ──────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "dnstt-server-rs")]
#[command(about = "Wire-compatible Rust reimplementation of dnstt-server")]
struct Cli {
    /// Generate a server keypair and exit.
    #[arg(long = "gen-key")]
    gen_key: bool,

    /// JSON config file (recommended for production).
    #[arg(short = 'c', long = "config")]
    config: Option<String>,

    /// UDP address to listen on (legacy CLI mode).
    #[arg(long = "udp")]
    udp: Option<String>,

    /// Server private key as hex string.
    #[arg(long = "privkey")]
    privkey: Option<String>,

    /// Read server private key from file.
    #[arg(long = "privkey-file")]
    privkey_file: Option<String>,

    /// Write public key to file (with -gen-key).
    #[arg(long = "pubkey-file")]
    pubkey_file: Option<String>,

    /// Maximum size of DNS response UDP payloads.
    #[arg(long = "mtu", default_value_t = 1232)]
    mtu: usize,

    /// Enable SO_REUSEPORT.
    #[arg(long = "reuseport")]
    reuseport: bool,

    /// Path to domain blocklist file (LiteWeb ad blocking).
    #[arg(long = "blocklist")]
    blocklist: Option<String>,

    /// Positional: DOMAIN UPSTREAMADDR (legacy CLI mode).
    #[arg(trailing_var_arg = true)]
    args: Vec<String>,
}

// ── Constants ────────────────────────────────────────────────────

const METRICS_INTERVAL: Duration = Duration::from_secs(60);
const DEFAULT_MAX_STREAMS: usize = 4096;
const DEFAULT_SMUX_MAX_STREAM_BUFFER: u32 = 1_048_576;
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const RECORD_CHANNEL_SIZE: usize = 4096;

// ── Key I/O ──────────────────────────────────────────────────────

fn read_key_from_file(path: &str) -> anyhow::Result<[u8; 32]> {
    let content = std::fs::read_to_string(path)?.trim().to_string();
    decode_key(&content)
}

fn decode_key(s: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(s.trim())?;
    if bytes.len() != 32 {
        anyhow::bail!("key length is {}, expected 32", bytes.len());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn generate_keypair(privkey_file: Option<&str>, pubkey_file: Option<&str>) -> anyhow::Result<()> {
    let privkey = noise_session::generate_privkey();
    let pubkey = noise_session::pubkey_from_privkey(&privkey);

    if let Some(path) = privkey_file {
        std::fs::write(path, format!("{}\n", hex::encode(privkey)))?;
        println!("privkey written to {}", path);
    } else {
        println!("privkey {}", hex::encode(privkey));
    }

    if let Some(path) = pubkey_file {
        std::fs::write(path, format!("{}\n", hex::encode(pubkey)))?;
        println!("pubkey  written to {}", path);
    } else {
        println!("pubkey  {}", hex::encode(pubkey));
    }

    Ok(())
}

// ── Socket ───────────────────────────────────────────────────────

fn create_udp_socket(addr: &str, reuseport: bool) -> anyhow::Result<std::net::UdpSocket> {
    let socket_addr: SocketAddr = addr.parse().or_else(|_| {
        // Handle ":53" style addresses.
        let addr = if addr.starts_with(':') {
            format!("0.0.0.0{}", addr)
        } else {
            addr.to_string()
        };
        addr.parse()
    })?;

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    if reuseport {
        #[cfg(unix)]
        {
            socket.set_reuse_port(true)?;
        }
        socket.set_reuse_address(true)?;
        log::info!("SO_REUSEPORT enabled on {}", socket_addr);
    }

    socket.bind(&socket_addr.into())?;
    socket.set_nonblocking(true)?;

    Ok(socket.into())
}

// ── Main Server ──────────────────────────────────────────────────

async fn run(
    privkeys: Vec<[u8; 32]>,
    domains: Vec<DnsName>,
    upstream: String,
    sockets: Vec<Arc<UdpSocket>>,
    max_udp_payload: usize,
    idle_timeout: Duration,
    max_streams: usize,
    smux_max_stream_buffer: u32,
    blocklist_file: Option<String>,
    server_id: String,
    egress_ips: Vec<std::net::IpAddr>,
    tcp_listen_addrs: Option<Vec<String>>,
) -> anyhow::Result<()> {
    for (i, pk) in privkeys.iter().enumerate() {
        let pubkey = noise_session::pubkey_from_privkey(pk);
        log::info!("key[{}] pubkey {}", i, hex::encode(pubkey));
    }
    log::info!("upstream mode: {}", upstream);
    log::info!("domains: {}", domains.len());
    for (i, d) in domains.iter().enumerate() {
        log::info!("  domain[{}]: {}", i, d);
    }

    // Compute max encoded payload (same binary search as Go).
    let max_encoded_payload = dns::compute_max_encoded_payload(max_udp_payload);
    let mtu = max_encoded_payload.saturating_sub(2);
    if mtu < 80 {
        anyhow::bail!(
            "maxUDPPayload {} leaves only {} bytes for KCP MTU",
            max_udp_payload,
            mtu
        );
    }
    log::info!("effective MTU {}", mtu);
    log::info!(
        "scale config: idle_timeout={}s max_streams={} smux_buf={}KB",
        idle_timeout.as_secs(),
        max_streams,
        smux_max_stream_buffer / 1024,
    );

    // ── DNS cache (no blocklist — blocking belongs on device) ──
    let blocklist = DomainBlocklist::empty();
    let num_egress = egress_ips.len();

    let dns_cache = if egress_ips.is_empty() {
        Arc::new(DnsCache::new())
    } else {
        Arc::new(DnsCache::with_egress_ips(egress_ips))
    };
    dns_cache::spawn_eviction_task(dns_cache.clone());

    let liteweb_ctx = Arc::new(LiteWebContext::new(blocklist, dns_cache.clone()));
    log::info!("DNS cache initialized (egress_ips={})", num_egress);

    let metrics = Arc::new(Metrics::new());

    // Channel for stream task spawning.
    let (stream_spawn_tx, mut stream_spawn_rx) = mpsc::channel::<StreamTask>(1024);

    // Notify for waking send tasks when data is available.
    let data_notify = Arc::new(tokio::sync::Notify::new());

    // Create KCP manager.
    let kcp_manager = Arc::new(Mutex::new(KcpManager::new(
        privkeys,
        mtu,
        upstream.clone(),
        idle_timeout,
        max_streams,
        smux_max_stream_buffer,
        metrics.clone(),
        stream_spawn_tx,
        data_notify.clone(),
    )));

    // Record channel between recv and send loops.
    let (record_tx, record_rx) = mpsc::channel(RECORD_CHANNEL_SIZE);

    log::info!("bound to {} UDP socket(s)", sockets.len());

    // ── Spawn TCP DNS listener(s) if configured ─────────────
    if let Some(tcp_addrs) = tcp_listen_addrs {
        if !tcp_addrs.is_empty() {
            let tcp_kcp = kcp_manager.clone();
            let tcp_domains = domains.clone();
            let tcp_record_tx = record_tx.clone();
            let tcp_notify = data_notify.clone();
            tokio::spawn(async move {
                if let Err(e) = turbotunnel::tcp_listen(
                    tcp_addrs,
                    tcp_domains,
                    tcp_kcp,
                    tcp_record_tx,
                    max_udp_payload,
                    tcp_notify,
                    max_encoded_payload,
                ).await {
                    log::error!("TCP DNS listen: {}", e);
                }
            });
        }
    }

    // ── Spawn recv task(s) — one per socket ──────────────────
    let recv_kcp = kcp_manager.clone();
    let recv_domains = domains.clone();
    let recv_record_tx = record_tx.clone();
    let recv_sockets = sockets.clone();
    tokio::spawn(async move {
        if let Err(e) = turbotunnel::recv_loop(
            recv_domains,
            recv_sockets,
            recv_kcp,
            recv_record_tx,
            max_udp_payload,
        )
        .await
        {
            log::error!("recv_loop: {}", e);
        }
    });

    // Send loop — dispatches per-record tasks concurrently.
    // Each Record carries its own socket so responses go from the correct IP.
    let send_kcp = kcp_manager.clone();
    let send_notify = data_notify.clone();
    tokio::spawn(async move {
        if let Err(e) = turbotunnel::send_loop(
            send_kcp,
            record_rx,
            max_encoded_payload,
            max_udp_payload,
            send_notify,
        )
        .await
        {
            log::error!("send_loop: {}", e);
        }
    });

    // ── Spawn KCP tick task ──────────────────────────────────
    let tick_kcp = kcp_manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(20));
        loop {
            interval.tick().await;
            let mut mgr = tick_kcp.lock().await;
            mgr.tick();
        }
    });

    // ── Spawn stream task handler ────────────────────────────
    let stream_upstream = upstream.clone();
    let stream_metrics = metrics.clone();
    let stream_kcp = kcp_manager.clone();
    let stream_ctx = liteweb_ctx.clone();
    tokio::spawn(async move {
        while let Some(task) = stream_spawn_rx.recv().await {
            let upstream = stream_upstream.clone();
            let metrics = stream_metrics.clone();
            let kcp = stream_kcp.clone();
            let ctx = stream_ctx.clone();
            tokio::spawn(async move {
                handle_stream_task(task, &upstream, &metrics, &kcp, &ctx).await;
            });
        }
    });

    // ── Spawn metrics task ───────────────────────────────────
    let metrics_clone = metrics.clone();
    let metrics_kcp = kcp_manager.clone();
    let metrics_ctx = liteweb_ctx.clone();
    let metrics_dns = dns_cache.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(METRICS_INTERVAL);
        loop {
            interval.tick().await;
            let (session_count, client_count) = {
                let mgr = metrics_kcp.lock().await;
                (mgr.session_count(), mgr.unique_client_count())
            };
            let blocked = metrics_ctx.metrics.blocked_connections.load(Ordering::Relaxed);
            let bw_saved = metrics_ctx.metrics.bandwidth_saved_estimate.load(Ordering::Relaxed);
            let allowed = metrics_ctx.blocklist.stats.allowlist_overrides.load(Ordering::Relaxed);
            let dns_hits = metrics_dns.cache_hits.load(Ordering::Relaxed);
            let dns_misses = metrics_dns.cache_misses.load(Ordering::Relaxed);
            log::info!(
                "[METRICS] clients={} sessions={} streams={} total={} bytes={} dial_err={} rejected={} blocked={} allowed={} bw_saved={}KB dns_hit={} dns_miss={} dns_entries={} dns_hit_rate={:.0}%",
                client_count,
                session_count,
                metrics_clone.active_streams.load(Ordering::Relaxed),
                metrics_clone.total_streams.load(Ordering::Relaxed),
                metrics_clone.total_bytes.load(Ordering::Relaxed),
                metrics_clone.dial_errors.load(Ordering::Relaxed),
                metrics_clone.stream_rejects.load(Ordering::Relaxed),
                blocked,
                allowed,
                bw_saved / 1024,
                dns_hits,
                dns_misses,
                metrics_dns.len(),
                metrics_dns.hit_rate_pct(),
            );
        }
    });

    // ── Spawn Datadog export (non-blocking, fire-and-forget) ─
    if let Some(dd) = datadog::DatadogExporter::from_env(&server_id) {
        datadog::spawn_export_task(
            dd,
            metrics.clone(),
            kcp_manager.clone(),
            liteweb_ctx.clone(),
            dns_cache.clone(),
        );
    }

    // ── Wait for shutdown signal ─────────────────────────────
    log::info!("dnstt-server-rs running");
    tokio::signal::ctrl_c().await?;
    log::info!("shutting down");

    Ok(())
}

// ── SmuxStreamAdapter ────────────────────────────────────────────

/// Bridges smux stream channels into AsyncRead + AsyncWrite for SOCKS5/relay.
///
/// Read side:  polls `data_rx` (mpsc channel filled by KcpManager when
///             PSH frames arrive from the client through the tunnel).
/// Write side: pushes to `write_tx` (unbounded channel drained by a
///             background task that locks KcpManager and calls stream_write).
struct SmuxStreamAdapter {
    data_rx: mpsc::Receiver<Vec<u8>>,
    write_tx: mpsc::UnboundedSender<Vec<u8>>,
    read_buf: BytesMut,
}

impl AsyncRead for SmuxStreamAdapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // First drain any buffered data from a previous partial read.
        if !self.read_buf.is_empty() {
            let n = std::cmp::min(buf.remaining(), self.read_buf.len());
            buf.put_slice(&self.read_buf[..n]);
            self.read_buf.advance(n);
            return Poll::Ready(Ok(()));
        }

        // Pull from the channel.
        match self.data_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buf.extend_from_slice(&data[n..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF (channel closed)
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for SmuxStreamAdapter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Unbounded send never blocks — background task drains it.
        match self.write_tx.send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "tunnel closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Background task: drains data from the write channel and sends it back
/// through the smux → Noise → KCP → DNS response pipeline.
async fn stream_writer_task(
    mut write_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    conv: u32,
    stream_id: u32,
    kcp: Arc<Mutex<KcpManager>>,
) {
    while let Some(data) = write_rx.recv().await {
        let mut mgr = kcp.lock().await;
        mgr.stream_write(conv, stream_id, &data);
    }
}

/// Handle a single smux stream (SOCKS5 or fixed upstream).
async fn handle_stream_task(
    task: StreamTask,
    upstream: &str,
    metrics: &Metrics,
    kcp: &Arc<Mutex<KcpManager>>,
    ctx: &Arc<LiteWebContext>,
) {
    let conv = task.conv;
    let stream_id = task.stream_id;

    // Create write channel (unbounded so poll_write never blocks).
    let (write_tx, write_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Spawn background writer that feeds data back through the tunnel.
    let writer_kcp = kcp.clone();
    tokio::spawn(stream_writer_task(write_rx, conv, stream_id, writer_kcp));

    // Build the AsyncRead+AsyncWrite adapter.
    let adapter = SmuxStreamAdapter {
        data_rx: task.data_rx,
        write_tx,
        read_buf: BytesMut::new(),
    };

    // Dispatch to SOCKS5 or fixed upstream handler.
    let result = if upstream == "socks5" {
        socks5::handle_socks5(adapter, ctx).await
    } else {
        socks5::handle_fixed_upstream(adapter, upstream).await
    };

    match result {
        Ok((up, down)) => {
            metrics.total_bytes.fetch_add(up + down, Ordering::Relaxed);
            log::debug!(
                "stream {:08x}:{} relay done up={} down={}",
                conv, stream_id, up, down
            );
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("dial") || msg.contains("connect") {
                metrics.dial_errors.fetch_add(1, Ordering::Relaxed);
            }
            log::debug!("stream {:08x}:{} error: {}", conv, stream_id, msg);
        }
    }

    // Send FIN back and clean up smux stream state.
    {
        let mut mgr = kcp.lock().await;
        mgr.stream_close(conv, stream_id);
    }

    metrics.active_streams.fetch_sub(1, Ordering::Relaxed);
}

// ── Entry Point ──────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let cli = Cli::parse();

    // ── Key generation mode ──────────────────────────────────
    if cli.gen_key {
        return generate_keypair(
            cli.privkey_file.as_deref(),
            cli.pubkey_file.as_deref(),
        );
    }

    // ── Config file mode (recommended) ───────────────────────
    if let Some(config_path) = &cli.config {
        let cfg = config::ServerConfig::load(config_path)?;

        let idle_timeout = cfg
            .idle_timeout_sec
            .map(|s| Duration::from_secs(s))
            .unwrap_or(DEFAULT_IDLE_TIMEOUT);
        let max_streams = cfg.max_streams.unwrap_or(DEFAULT_MAX_STREAMS);
        let smux_buf = cfg
            .max_stream_buffer_kb
            .map(|kb| (kb * 1024) as u32)
            .unwrap_or(DEFAULT_SMUX_MAX_STREAM_BUFFER);

        log::info!(
            "server_id={} listen={} upstream={} domains={}",
            cfg.server_id,
            cfg.listen,
            cfg.upstream,
            cfg.domains.len()
        );

        let domains: Vec<DnsName> = cfg
            .domains
            .iter()
            .map(|d| DnsName::parse(d))
            .collect::<Result<Vec<_>, _>>()?;

        let mut privkeys = vec![decode_key(&cfg.privkey)?];
        for extra in &cfg.extra_privkeys {
            privkeys.push(decode_key(extra)?);
        }
        log::info!("{} private key(s) loaded", privkeys.len());
        let reuseport = cli.reuseport || cfg.reuseport;

        // Build list of listen addresses.
        // If listen_addrs is set, use those (one socket per address).
        // Otherwise fall back to single listen address (may have source
        // IP mismatch on multi-homed hosts).
        let listen_addrs: Vec<String> = if let Some(addrs) = &cfg.listen_addrs {
            addrs.clone()
        } else {
            let addr = cli.udp.as_deref().unwrap_or(&cfg.listen);
            vec![addr.to_string()]
        };

        let mut sockets = Vec::new();
        for addr in &listen_addrs {
            let std_socket = create_udp_socket(addr, reuseport)?;
            let socket = UdpSocket::from_std(std_socket)?;
            log::info!("listening on {}", addr);
            sockets.push(Arc::new(socket));
        }

        // Parse egress IPs for outbound SOCKS connection distribution.
        let egress_ips: Vec<std::net::IpAddr> = cfg
            .egress_ips
            .unwrap_or_default()
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        return run(
            privkeys,
            domains,
            cfg.upstream,
            sockets,
            cli.mtu,
            idle_timeout,
            max_streams,
            smux_buf,
            cfg.blocklist_file,
            cfg.server_id,
            egress_ips,
            cfg.tcp_listen_addrs,
        )
        .await;
    }

    // ── Legacy CLI mode ──────────────────────────────────────
    let udp_addr = cli
        .udp
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("the -udp option is required"))?;

    if cli.args.len() < 2 {
        anyhow::bail!("usage: dnstt-server-rs -udp ADDR [-privkey-file KEY] DOMAIN UPSTREAM");
    }

    let domain_str = &cli.args[0];
    let upstream = &cli.args[1];

    let domains: Vec<DnsName> = domain_str
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| DnsName::parse(s))
        .collect::<Result<Vec<_>, _>>()?;

    if domains.is_empty() {
        anyhow::bail!("at least one domain is required");
    }

    let privkey = if let Some(ref file) = cli.privkey_file {
        read_key_from_file(file)?
    } else if let Some(ref key) = cli.privkey {
        decode_key(key)?
    } else {
        log::warn!("generating a temporary one-time keypair");
        noise_session::generate_privkey()
    };

    let std_socket = create_udp_socket(udp_addr, cli.reuseport)?;
    let socket = UdpSocket::from_std(std_socket)?;
    let sockets = vec![Arc::new(socket)];

    run(
        vec![privkey],
        domains,
        upstream.to_string(),
        sockets,
        cli.mtu,
        DEFAULT_IDLE_TIMEOUT,
        DEFAULT_MAX_STREAMS,
        DEFAULT_SMUX_MAX_STREAM_BUFFER,
        cli.blocklist,
        "dnstt-legacy".to_string(),
        vec![],
        None, // no TCP in legacy mode
    )
    .await
}
