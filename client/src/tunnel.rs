//! Native Rust DNSTT tunnel — wire-compatible with dnstt-server (Go and Rust).
//!
//! Protocol stack (bottom to top):
//!   1. UDP DNS transport (tokio UdpSocket)
//!   2. DNS name encoding (base32 QNAME <-> TXT RDATA)
//!   3. KCP ARQ reliable transport (kcp crate)
//!   4. Noise_NK_25519_ChaChaPoly_BLAKE2s (snow crate)
//!   5. smux v2 stream multiplexing (inline impl)
//!   6. Transparent SOCKS5 relay (server handles SOCKS5 parsing)

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kcp::Kcp;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc};

use crate::dns_codec;

// ─── Protocol constants (must match dnstt-server exactly) ─────

const MAX_QNAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

const INIT_POLL_DELAY: Duration = Duration::from_millis(200);
const MAX_POLL_DELAY: Duration = Duration::from_secs(5);
const POLL_DELAY_MULTIPLIER: f64 = 1.5;
const POLL_LIMIT: usize = 32;
const NOISE_PROLOGUE: &[u8] = b"dnstt 2020-04-13";
const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";

const KCP_INTERVAL: i32 = 20;
const KCP_SND_WND: u16 = 128;
const KCP_RCV_WND: u16 = 128;

const NOISE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const TUNNEL_SETUP_TIMEOUT: Duration = Duration::from_secs(20);

// ─── SRTT Priming ─────────────────────────────────────────────
const SRTT_PRIMING_BURST: usize = 8;
const SRTT_PRIMING_INTERVAL: Duration = Duration::from_millis(200);
const SRTT_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(25);
const SRTT_MAINTENANCE_BURST: usize = 3;

const DNS_ENCODING_OVERHEAD: usize = 13;

// ─── MTU calculation ─────────────────────────────────────────────

fn calc_send_mtu(domain: &str) -> usize {
    let domain_labels: Vec<&str> = domain.split('.').filter(|s| !s.is_empty()).collect();
    let domain_wire_len: usize = domain_labels.iter().map(|l| 1 + l.len()).sum::<usize>() + 1;
    let available = MAX_QNAME_LEN.saturating_sub(domain_wire_len);
    let full_labels = available / (MAX_LABEL_LEN + 1);
    let remainder = available % (MAX_LABEL_LEN + 1);
    let partial = if remainder >= 2 { remainder - 1 } else { 0 };
    let b32_capacity = full_labels * MAX_LABEL_LEN + partial;
    let raw_capacity = b32_capacity * 5 / 8;
    raw_capacity.saturating_sub(DNS_ENCODING_OVERHEAD)
}

// ─── KCP output adapter ─────────────────────────────────────────

#[derive(Clone)]
struct KcpOutputSink {
    segments: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
}

impl KcpOutputSink {
    fn new() -> Self {
        Self { segments: Arc::new(std::sync::Mutex::new(Vec::new())) }
    }
    fn take_segments(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.segments.lock().unwrap())
    }
}

impl io::Write for KcpOutputSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.segments.lock().unwrap().push(buf.to_vec());
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

// ─── Noise transport wrapper ────────────────────────────────────

struct NoiseTransport {
    state: snow::TransportState,
}

impl NoiseTransport {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; plaintext.len() + 64];
        let len = self.state.write_message(plaintext, &mut buf)
            .map_err(|e| format!("noise encrypt: {}", e))?;
        buf.truncate(len);
        let mut framed = Vec::with_capacity(2 + len);
        framed.extend_from_slice(&(len as u16).to_be_bytes());
        framed.extend_from_slice(&buf);
        Ok(framed)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; ciphertext.len()];
        let len = self.state.read_message(ciphertext, &mut buf)
            .map_err(|e| format!("noise decrypt: {}", e))?;
        buf.truncate(len);
        Ok(buf)
    }
}

// ─── KCP bundle ─────────────────────────────────────────────────

struct KcpBundle {
    kcp: Kcp<KcpOutputSink>,
    output: KcpOutputSink,
}

impl KcpBundle {
    fn new(mtu: usize) -> Self {
        let output = KcpOutputSink::new();
        let output_clone = output.clone();
        let conv: u32 = loop {
            let c: u32 = rand::thread_rng().gen();
            if c != 0 { break c; }
        };
        log::debug!("[dnstt:kcp] conv={:08x}", conv);
        let mut kcp = Kcp::new_stream(conv, output);
        kcp.set_nodelay(true, KCP_INTERVAL, 2, true);
        kcp.set_wndsize(KCP_SND_WND, KCP_RCV_WND);
        if let Err(e) = kcp.set_mtu(mtu) {
            log::warn!("[dnstt:kcp] set_mtu({}) failed: {:?}", mtu, e);
        }
        Self { kcp, output: output_clone }
    }

    fn update(&mut self, now_ms: u32) { let _ = self.kcp.update(now_ms); }
    fn take_segments(&self) -> Vec<Vec<u8>> { self.output.take_segments() }
    fn input(&mut self, data: &[u8]) { let _ = self.kcp.input(data); }
    fn send(&mut self, data: &[u8]) { let _ = self.kcp.send(data); }
    fn recv(&mut self, buf: &mut [u8]) -> Option<usize> { self.kcp.recv(buf).ok() }
}

// ─── smux v2 ────────────────────────────────────────────────────

const SMUX2_VER: u8 = 2;
const SMUX2_CMD_SYN: u8 = 0;
const SMUX2_CMD_FIN: u8 = 1;
const SMUX2_CMD_PSH: u8 = 2;
const SMUX2_CMD_NOP: u8 = 3;
#[allow(dead_code)]
const SMUX2_CMD_UPD: u8 = 4;
const SMUX2_HDR: usize = 8;

fn smux2_frame(cmd: u8, sid: u32, data: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(SMUX2_HDR + data.len());
    f.push(SMUX2_VER);
    f.push(cmd);
    f.extend_from_slice(&(data.len() as u16).to_le_bytes());
    f.extend_from_slice(&sid.to_le_bytes());
    f.extend_from_slice(data);
    f
}

fn smux2_upd_frame(sid: u32, consumed: u32, window: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8);
    payload.extend_from_slice(&consumed.to_le_bytes());
    payload.extend_from_slice(&window.to_le_bytes());
    smux2_frame(SMUX2_CMD_UPD, sid, &payload)
}

struct Smux2Session {
    frame_tx: mpsc::UnboundedSender<Vec<u8>>,
    streams: Arc<std::sync::Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>>,
    next_sid: AtomicU32,
}

impl Smux2Session {
    fn open_stream(&self) -> Result<Smux2Stream, String> {
        let sid = self.next_sid.fetch_add(2, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel();
        self.streams.lock().unwrap().insert(sid, tx);
        self.frame_tx.send(smux2_frame(SMUX2_CMD_SYN, sid, &[]))
            .map_err(|_| "smux SYN: KCP owner dead".to_string())?;
        self.frame_tx.send(smux2_upd_frame(sid, 0, 1_048_576))
            .map_err(|_| "smux UPD: KCP owner dead".to_string())?;
        Ok(Smux2Stream { sid, frame_tx: self.frame_tx.clone(), rx })
    }
}

struct Smux2Stream {
    sid: u32,
    frame_tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

// ─── Single tunnel ──────────────────────────────────────────────

struct DnsttTunnel {
    client_id: [u8; 8],
    domain: String,
    server_pubkey: [u8; 32],
    resolver_addr: SocketAddr,
}

impl DnsttTunnel {
    fn new(domain: String, server_pubkey: [u8; 32], resolver_addr: SocketAddr) -> Self {
        let mut client_id = [0u8; 8];
        rand::thread_rng().fill(&mut client_id);
        if client_id == [0u8; 8] { client_id[0] = 1; }
        Self { client_id, domain, server_pubkey, resolver_addr }
    }

    async fn connect(&self, running: Arc<AtomicBool>) -> Result<Smux2Session, String> {
        // 1. Bind UDP socket
        let udp = Arc::new(
            UdpSocket::bind("0.0.0.0:0").await
                .map_err(|e| format!("UDP bind: {}", e))?
        );

        // 2. Calculate MTU
        let mtu = calc_send_mtu(&self.domain);
        log::debug!("[dnstt] Domain {} -> KCP MTU={}", self.domain, mtu);

        // 3. Channels
        let (kcp_input_tx, mut kcp_input_rx) = mpsc::channel::<Vec<u8>>(256);
        let (smux_frame_tx, mut smux_frame_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let streams: Arc<std::sync::Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

        // 4. DNS recv loop
        {
            let udp = udp.clone();
            let kcp_input_tx = kcp_input_tx.clone();
            let running = running.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    if !running.load(Ordering::Relaxed) { break; }
                    let recv = tokio::time::timeout(
                        Duration::from_secs(10), udp.recv_from(&mut buf),
                    ).await;
                    let (len, _) = match recv {
                        Ok(Ok(v)) => v,
                        Ok(Err(_)) | Err(_) => continue,
                    };
                    if let Some(packets) = dns_codec::decode_response(&buf[..len]) {
                        for pkt in packets {
                            if pkt.is_empty() { continue; }
                            if kcp_input_tx.send(pkt).await.is_err() { return; }
                        }
                    }
                }
            });
        }

        // 5. SRTT Priming
        {
            let mut primer_id = [0u8; 8];
            rand::thread_rng().fill(&mut primer_id);
            if primer_id == [0u8; 8] { primer_id[0] = 1; }
            log::debug!("[srtt] Priming {} queries to {}", SRTT_PRIMING_BURST, self.resolver_addr);
            for _ in 0..SRTT_PRIMING_BURST {
                let q = dns_codec::encode_query(&primer_id, &[], &self.domain, true);
                let _ = udp.send_to(&q, self.resolver_addr).await;
                let jitter = SRTT_PRIMING_INTERVAL.as_millis() as u64 + (rand::random::<u64>() % 100);
                tokio::time::sleep(Duration::from_millis(jitter)).await;
                let mut drain_buf = [0u8; 4096];
                while let Ok(Ok(_)) = tokio::time::timeout(
                    Duration::from_millis(1), udp.recv_from(&mut drain_buf)
                ).await {}
            }
        }

        // 6. Noise NK handshake
        let mut kcp_bundle = KcpBundle::new(mtu);
        let client_id = self.client_id;
        let domain = self.domain.clone();
        let resolver = self.resolver_addr;

        let flush_kcp_to_udp = |kcp_bundle: &KcpBundle, client_id: &[u8; 8], domain: &str, resolver: SocketAddr| {
            let segments = kcp_bundle.take_segments();
            segments.into_iter().map(|seg| {
                (dns_codec::encode_query(client_id, &seg, domain, false), resolver)
            }).collect::<Vec<_>>()
        };

        let mut noise_hs = snow::Builder::new(NOISE_PATTERN.parse().unwrap())
            .prologue(NOISE_PROLOGUE)
            .remote_public_key(&self.server_pubkey)
            .build_initiator()
            .map_err(|e| format!("noise init: {}", e))?;

        // -> e, es
        let mut msg1 = vec![0u8; 96];
        let len1 = noise_hs.write_message(&[], &mut msg1)
            .map_err(|e| format!("noise msg1: {}", e))?;
        msg1.truncate(len1);

        let mut framed = Vec::with_capacity(2 + len1);
        framed.extend_from_slice(&(len1 as u16).to_be_bytes());
        framed.extend_from_slice(&msg1);
        kcp_bundle.send(&framed);

        let now_ms = get_now_ms();
        kcp_bundle.update(now_ms);
        let dns_pkts = flush_kcp_to_udp(&kcp_bundle, &client_id, &domain, resolver);
        for (pkt, addr) in &dns_pkts {
            let _ = udp.send_to(pkt, addr).await;
        }
        let poll_q = dns_codec::encode_query(&client_id, &[], &domain, true);
        let _ = udp.send_to(&poll_q, resolver).await;

        // <- e, ee
        let mut stream_buf = Vec::new();
        let mut tmp = vec![0u8; 65536];
        let hs_start = Instant::now();
        let mut hs_polls = 0u32;
        let msg2_data = loop {
            if hs_start.elapsed() > NOISE_HANDSHAKE_TIMEOUT {
                return Err(format!("Noise handshake timeout ({}s)", hs_start.elapsed().as_secs()));
            }

            loop {
                match kcp_input_rx.try_recv() {
                    Ok(pkt) => { kcp_bundle.input(&pkt); }
                    Err(_) => break,
                }
            }

            let now_ms = get_now_ms();
            kcp_bundle.update(now_ms);

            let dns_pkts = flush_kcp_to_udp(&kcp_bundle, &client_id, &domain, resolver);
            for (pkt, addr) in &dns_pkts {
                let _ = udp.send_to(pkt, addr).await;
            }

            loop {
                match kcp_bundle.recv(&mut tmp) {
                    Some(n) if n > 0 => stream_buf.extend_from_slice(&tmp[..n]),
                    _ => break,
                }
            }

            if stream_buf.len() >= 2 {
                let frame_len = u16::from_be_bytes([stream_buf[0], stream_buf[1]]) as usize;
                if frame_len > 0 && stream_buf.len() >= 2 + frame_len {
                    break stream_buf[2..2 + frame_len].to_vec();
                }
            }

            hs_polls += 1;
            if hs_polls % 5 == 0 {
                let poll_q = dns_codec::encode_query(&client_id, &[], &domain, true);
                let _ = udp.send_to(&poll_q, resolver).await;
            }

            tokio::select! {
                Some(pkt) = kcp_input_rx.recv() => { kcp_bundle.input(&pkt); }
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        };

        let handshake_consumed = 2 + msg2_data.len();
        let leftover = if stream_buf.len() > handshake_consumed {
            stream_buf[handshake_consumed..].to_vec()
        } else {
            Vec::new()
        };

        let mut payload_buf = [0u8; 128];
        noise_hs.read_message(&msg2_data, &mut payload_buf)
            .map_err(|e| format!("noise msg2: {}", e))?;
        let transport = noise_hs.into_transport_mode()
            .map_err(|e| format!("noise transport: {}", e))?;
        let mut noise = NoiseTransport { state: transport };
        log::info!("[dnstt] Noise handshake complete");

        // 7. KCP owner task
        {
            let udp = udp.clone();
            let streams = streams.clone();
            let running = running.clone();
            let client_id = self.client_id;
            let domain = self.domain.clone();
            let resolver = self.resolver_addr;
            tokio::spawn(async move {
                let mut stream_buf = leftover;
                let mut smux_buf: Vec<u8> = Vec::new();
                let mut poll_delay = INIT_POLL_DELAY;
                let mut polls_without_data: usize = 0;
                let mut last_data_activity = Instant::now();
                let mut srtt_maintenance_timer = tokio::time::interval(SRTT_MAINTENANCE_INTERVAL);
                srtt_maintenance_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let mut primer_id = [0u8; 8];
                rand::thread_rng().fill(&mut primer_id);
                if primer_id == [0u8; 8] { primer_id[0] = 2; }

                let mut kcp_ticker = tokio::time::interval(Duration::from_millis(KCP_INTERVAL as u64));
                kcp_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let poll_sleep = tokio::time::sleep(poll_delay);
                tokio::pin!(poll_sleep);

                loop {
                    if !running.load(Ordering::Relaxed) { break; }

                    tokio::select! {
                        Some(pkt) = kcp_input_rx.recv() => {
                            kcp_bundle.input(&pkt);
                            loop {
                                match kcp_input_rx.try_recv() {
                                    Ok(p) => { kcp_bundle.input(&p); }
                                    Err(_) => break,
                                }
                            }
                            poll_delay = INIT_POLL_DELAY;
                            polls_without_data = 0;
                            last_data_activity = Instant::now();
                            poll_sleep.as_mut().reset(tokio::time::Instant::now() + poll_delay);
                        }
                        Some(frame) = smux_frame_rx.recv() => {
                            match noise.encrypt(&frame) {
                                Ok(encrypted) => { kcp_bundle.send(&encrypted); }
                                Err(e) => { log::error!("[dnstt] Noise encrypt failed: {}", e); break; }
                            }
                            loop {
                                match smux_frame_rx.try_recv() {
                                    Ok(f) => {
                                        if let Ok(enc) = noise.encrypt(&f) {
                                            kcp_bundle.send(&enc);
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                            poll_delay = INIT_POLL_DELAY;
                            polls_without_data = 0;
                            last_data_activity = Instant::now();
                            poll_sleep.as_mut().reset(tokio::time::Instant::now() + poll_delay);
                        }
                        _ = kcp_ticker.tick() => {}
                        _ = srtt_maintenance_timer.tick() => {
                            let idle_secs = last_data_activity.elapsed().as_secs();
                            if idle_secs >= SRTT_MAINTENANCE_INTERVAL.as_secs() {
                                for _ in 0..SRTT_MAINTENANCE_BURST {
                                    let q = dns_codec::encode_query(&primer_id, &[], &domain, true);
                                    let _ = udp.send_to(&q, resolver).await;
                                    let jitter = 50 + (rand::random::<u64>() % 100);
                                    tokio::time::sleep(Duration::from_millis(jitter)).await;
                                }
                            }
                        }
                        _ = &mut poll_sleep => {
                            let q = dns_codec::encode_query(&client_id, &[], &domain, true);
                            let _ = udp.send_to(&q, resolver).await;
                            polls_without_data += 1;
                            if polls_without_data >= POLL_LIMIT {
                                poll_delay = MAX_POLL_DELAY;
                            } else {
                                poll_delay = Duration::from_millis(
                                    (poll_delay.as_millis() as f64 * POLL_DELAY_MULTIPLIER) as u64
                                ).min(MAX_POLL_DELAY);
                            }
                            poll_sleep.as_mut().reset(tokio::time::Instant::now() + poll_delay);
                        }
                    }

                    let now_ms = get_now_ms();
                    kcp_bundle.update(now_ms);

                    let segments = kcp_bundle.take_segments();
                    for seg in segments {
                        let q = dns_codec::encode_query(&client_id, &seg, &domain, false);
                        let _ = udp.send_to(&q, resolver).await;
                    }

                    drain_kcp_to_smux(&mut kcp_bundle, &mut noise, &mut stream_buf, &mut smux_buf, &streams);
                }
            });
        }

        Ok(Smux2Session {
            frame_tx: smux_frame_tx,
            streams,
            next_sid: AtomicU32::new(1),
        })
    }
}

fn get_now_ms() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u32
}

fn drain_kcp_to_smux(
    kcp: &mut KcpBundle,
    noise: &mut NoiseTransport,
    stream_buf: &mut Vec<u8>,
    smux_buf: &mut Vec<u8>,
    streams: &Arc<std::sync::Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>>,
) {
    let mut tmp = [0u8; 65536];
    loop {
        match kcp.recv(&mut tmp) {
            Some(n) if n > 0 => stream_buf.extend_from_slice(&tmp[..n]),
            _ => break,
        }
    }

    while stream_buf.len() >= 2 {
        let frame_len = u16::from_be_bytes([stream_buf[0], stream_buf[1]]) as usize;
        if frame_len == 0 || stream_buf.len() < 2 + frame_len { break; }
        let ciphertext = stream_buf[2..2 + frame_len].to_vec();
        stream_buf.drain(..2 + frame_len);
        match noise.decrypt(&ciphertext) {
            Ok(plaintext) => smux_buf.extend_from_slice(&plaintext),
            Err(e) => { log::error!("[dnstt] Noise decrypt failed: {}", e); break; }
        }
    }

    while smux_buf.len() >= SMUX2_HDR {
        let cmd = smux_buf[1];
        let length = u16::from_le_bytes([smux_buf[2], smux_buf[3]]) as usize;
        let sid = u32::from_le_bytes([smux_buf[4], smux_buf[5], smux_buf[6], smux_buf[7]]);
        if smux_buf.len() < SMUX2_HDR + length { break; }
        let data = smux_buf[SMUX2_HDR..SMUX2_HDR + length].to_vec();
        smux_buf.drain(..SMUX2_HDR + length);
        match cmd {
            SMUX2_CMD_PSH => {
                if let Ok(map) = streams.lock() {
                    if let Some(tx) = map.get(&sid) { let _ = tx.send(data); }
                }
            }
            SMUX2_CMD_FIN => {
                if let Ok(mut map) = streams.lock() { map.remove(&sid); }
            }
            _ => {}
        }
    }
}

// ─── SOCKS5 transparent relay ────────────────────────────────────

async fn handle_socks5(client: TcpStream, session: Arc<Smux2Session>) -> Result<(), String> {
    let stream = session.open_stream()
        .map_err(|e| format!("smux open: {}", e))?;
    let sid = stream.sid;
    let frame_tx = stream.frame_tx;
    let mut smux_rx = stream.rx;
    let (mut tcp_read, mut tcp_write) = client.into_split();

    let tx = frame_tx.clone();
    let tcp_to_smux = tokio::spawn(async move {
        let mut buf = [0u8; 32768];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let frame = smux2_frame(SMUX2_CMD_PSH, sid, &buf[..n]);
                    if tx.send(frame).is_err() { break; }
                }
            }
        }
    });

    let smux_to_tcp = tokio::spawn(async move {
        while let Some(data) = smux_rx.recv().await {
            if tcp_write.write_all(&data).await.is_err() { break; }
        }
    });

    tokio::select! {
        _ = tcp_to_smux => {}
        _ = smux_to_tcp => {}
    }

    let _ = frame_tx.send(smux2_frame(SMUX2_CMD_FIN, sid, &[]));
    Ok(())
}

// ─── Cooldown tracker ───────────────────────────────────────────

const COOLDOWN_DURATION: Duration = Duration::from_secs(60);

struct CooldownTracker {
    domains: std::sync::Mutex<HashMap<String, Instant>>,
    resolvers: std::sync::Mutex<HashMap<SocketAddr, Instant>>,
    pinned: std::sync::Mutex<Option<SocketAddr>>,
}

impl CooldownTracker {
    fn new() -> Self {
        Self {
            domains: std::sync::Mutex::new(HashMap::new()),
            resolvers: std::sync::Mutex::new(HashMap::new()),
            pinned: std::sync::Mutex::new(None),
        }
    }
    fn pin_resolver(&self, resolver: SocketAddr) {
        let mut p = self.pinned.lock().unwrap();
        if p.is_none() { *p = Some(resolver); }
    }
    fn get_pinned(&self) -> Option<SocketAddr> { *self.pinned.lock().unwrap() }
    fn cooldown_resolver(&self, resolver: SocketAddr) {
        self.resolvers.lock().unwrap().insert(resolver, Instant::now() + COOLDOWN_DURATION);
    }
    fn is_resolver_available(&self, resolver: &SocketAddr) -> bool {
        match self.resolvers.lock().unwrap().get(resolver) {
            Some(until) => Instant::now() >= *until,
            None => true,
        }
    }
}

// ─── Session health tracking ────────────────────────────────────

struct TrackedSession {
    session: Arc<Smux2Session>,
    domain: String,
    healthy: AtomicBool,
    failed_at: std::sync::Mutex<Option<Instant>>,
}

impl TrackedSession {
    fn new(session: Arc<Smux2Session>, domain: String) -> Self {
        Self { session, domain, healthy: AtomicBool::new(true), failed_at: std::sync::Mutex::new(None) }
    }
    fn is_usable(&self) -> bool {
        if self.healthy.load(Ordering::Relaxed) { return true; }
        if let Some(failed) = *self.failed_at.lock().unwrap() {
            if Instant::now().duration_since(failed) >= COOLDOWN_DURATION {
                self.healthy.store(true, Ordering::Relaxed);
                return true;
            }
        }
        false
    }
}

// ─── SOCKS5 accept loop ────────────────────────────────────────

async fn pick_session(
    sessions: &Arc<Mutex<Vec<Arc<TrackedSession>>>>,
    idx: &AtomicU64,
) -> Option<Arc<Smux2Session>> {
    let guard = sessions.lock().await;
    if guard.is_empty() { return None; }
    let usable: Vec<_> = guard.iter().filter(|ts| ts.is_usable()).collect();
    if usable.is_empty() { return None; }
    let i = idx.fetch_add(1, Ordering::Relaxed) as usize % usable.len();
    Some(usable[i].session.clone())
}

async fn run_socks5_loop(
    listener: TcpListener,
    sessions: Arc<Mutex<Vec<Arc<TrackedSession>>>>,
    running: Arc<AtomicBool>,
) {
    let idx = AtomicU64::new(0);
    loop {
        if !running.load(Ordering::Relaxed) { break; }
        let accept = tokio::time::timeout(Duration::from_secs(1), listener.accept()).await;
        let (client, _) = match accept {
            Ok(Ok(v)) => v,
            _ => continue,
        };
        let session = match pick_session(&sessions, &idx).await {
            Some(s) => s,
            None => {
                log::warn!("[socks5] No usable session, dropping connection");
                continue;
            }
        };
        tokio::spawn(async move {
            if let Err(e) = handle_socks5(client, session).await {
                log::debug!("[socks5] {}", e);
            }
        });
    }
}

// ─── Public API: start tunnel pool ──────────────────────────────

/// Start the DNSTT tunnel pool with built-in SOCKS5 proxy.
/// Blocks until shutdown. Returns Ok(()) on clean exit, Err on failure.
pub async fn start(
    domains: Vec<(String, String)>,   // (domain, pubkey_hex)
    resolvers: Vec<String>,           // IP or IP:port
    socks_port: u16,
    max_instances: usize,
    running: Arc<AtomicBool>,
    status_tx: Option<mpsc::UnboundedSender<TunnelStatus>>,
) -> Result<(), String> {
    if domains.is_empty() { return Err("No DNSTT domains".into()); }

    let parsed_resolvers: Vec<SocketAddr> = resolvers.iter()
        .filter_map(|r| {
            let r = if r.contains(':') { r.clone() } else { format!("{}:53", r) };
            r.parse().ok()
        })
        .collect();
    if parsed_resolvers.is_empty() { return Err("No valid resolvers".into()); }

    let mut all_domain_keys: Vec<(String, [u8; 32])> = Vec::new();
    for (domain, pubkey_hex) in &domains {
        let pubkey = hex::decode(pubkey_hex)
            .map_err(|e| format!("bad pubkey for {}: {}", domain, e))?;
        if pubkey.len() != 32 {
            return Err(format!("pubkey wrong len for {}: {}", domain, pubkey.len()));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pubkey);
        all_domain_keys.push((domain.clone(), pk));
    }

    let listener = TcpListener::bind(format!("127.0.0.1:{}", socks_port)).await
        .map_err(|e| format!("SOCKS5 bind :{}: {}", socks_port, e))?;

    let cooldown = Arc::new(CooldownTracker::new());
    let all_sessions: Arc<Mutex<Vec<Arc<TrackedSession>>>> = Arc::new(Mutex::new(Vec::new()));

    // Connect tunnels
    {
        let mut handles = Vec::new();
        let mut resolver_offset = 0;
        for tried in 0..max_instances {
            let idx = tried % all_domain_keys.len();
            let (domain, pk) = &all_domain_keys[idx];
            let resolver = parsed_resolvers[resolver_offset % parsed_resolvers.len()];
            resolver_offset += 1;
            let domain = domain.clone();
            let pk = *pk;
            let running = running.clone();
            let sessions = all_sessions.clone();
            let cd = cooldown.clone();
            let stx = status_tx.clone();
            handles.push(tokio::spawn(async move {
                let tunnel = DnsttTunnel::new(domain.clone(), pk, resolver);
                if let Some(ref tx) = stx {
                    let _ = tx.send(TunnelStatus::Connecting(domain.clone(), resolver.to_string()));
                }
                match tokio::time::timeout(TUNNEL_SETUP_TIMEOUT, tunnel.connect(running)).await {
                    Ok(Ok(s)) => {
                        log::info!("[dnstt] {} connected via {}", domain, resolver);
                        cd.pin_resolver(resolver);
                        sessions.lock().await.push(Arc::new(
                            TrackedSession::new(Arc::new(s), domain.clone())
                        ));
                        if let Some(ref tx) = stx {
                            let _ = tx.send(TunnelStatus::Connected(domain, resolver.to_string()));
                        }
                    }
                    Ok(Err(e)) => {
                        log::warn!("[dnstt] {} failed via {}: {}", domain, resolver, e);
                        cd.cooldown_resolver(resolver);
                        if let Some(ref tx) = stx {
                            let _ = tx.send(TunnelStatus::Failed(domain, e));
                        }
                    }
                    Err(_) => {
                        log::warn!("[dnstt] {} timed out via {}", domain, resolver);
                        cd.cooldown_resolver(resolver);
                        if let Some(ref tx) = stx {
                            let _ = tx.send(TunnelStatus::Failed(domain, "timeout".into()));
                        }
                    }
                }
            }));
        }

        // Wait for first tunnel
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if !all_sessions.lock().await.is_empty() { break; }
            if !running.load(Ordering::Relaxed) { return Err("shutdown".into()); }
        }
        if all_sessions.lock().await.is_empty() {
            for h in handles { let _ = h.await; }
            if all_sessions.lock().await.is_empty() {
                return Err("No tunnels connected".into());
            }
        }
    }

    if let Some(ref tx) = status_tx {
        let _ = tx.send(TunnelStatus::Ready(socks_port));
    }

    // SOCKS5 accept loop
    let sd = running.clone();
    tokio::spawn(run_socks5_loop(listener, all_sessions.clone(), sd));

    // Background reconnect + rotation
    {
        let sessions = all_sessions.clone();
        let cd = cooldown.clone();
        let sd = running.clone();
        let dk = all_domain_keys.clone();
        let resolvers = parsed_resolvers.clone();
        tokio::spawn(async move {
            let mut last_rotation = Instant::now();
            let rotation_interval = Duration::from_secs(45 * 60);
            let mut rotation_idx = 0usize;

            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                if !sd.load(Ordering::Relaxed) { break; }

                let healthy_count = {
                    let mut guard = sessions.lock().await;
                    guard.retain(|ts| ts.is_usable());
                    guard.len()
                };

                // Proactive rotation
                if healthy_count >= max_instances && dk.len() > 1
                    && last_rotation.elapsed() >= rotation_interval
                {
                    rotation_idx = (rotation_idx + 1) % dk.len();
                    let (domain, pk) = &dk[rotation_idx];
                    let resolver = cd.get_pinned().unwrap_or(resolvers[0]);
                    let tunnel = DnsttTunnel::new(domain.clone(), *pk, resolver);
                    let sd2 = sd.clone();
                    if let Ok(Ok(s)) = tokio::time::timeout(TUNNEL_SETUP_TIMEOUT, tunnel.connect(sd2)).await {
                        let mut guard = sessions.lock().await;
                        if !guard.is_empty() { guard.remove(0); }
                        guard.push(Arc::new(TrackedSession::new(Arc::new(s), domain.clone())));
                        last_rotation = Instant::now();
                    }
                    continue;
                }

                if healthy_count >= max_instances { continue; }

                let need = max_instances - healthy_count;
                let pinned = cd.get_pinned();
                let mut connected = 0;
                let mut attempts = 0;
                while connected < need && attempts < need * 3 {
                    attempts += 1;
                    let idx = (healthy_count + connected + attempts) % dk.len();
                    let (domain, pk) = &dk[idx];
                    let resolver = if attempts <= dk.len() {
                        pinned.unwrap_or(resolvers[0])
                    } else {
                        resolvers[(attempts - dk.len()) % resolvers.len()]
                    };
                    if !cd.is_resolver_available(&resolver) { continue; }

                    let tunnel = DnsttTunnel::new(domain.clone(), *pk, resolver);
                    let sd2 = sd.clone();
                    match tokio::time::timeout(TUNNEL_SETUP_TIMEOUT, tunnel.connect(sd2)).await {
                        Ok(Ok(s)) => {
                            cd.pin_resolver(resolver);
                            sessions.lock().await.push(Arc::new(
                                TrackedSession::new(Arc::new(s), domain.clone())
                            ));
                            connected += 1;
                        }
                        Ok(Err(_)) | Err(_) => {
                            cd.cooldown_resolver(resolver);
                        }
                    }
                }
            }
        });
    }

    // Block until shutdown
    loop {
        if !running.load(Ordering::Relaxed) { break; }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    Ok(())
}

/// Status updates from the tunnel engine to the UI.
#[derive(Debug, Clone)]
pub enum TunnelStatus {
    Connecting(String, String),  // (domain, resolver)
    Connected(String, String),   // (domain, resolver)
    Failed(String, String),      // (domain, error)
    Ready(u16),                  // SOCKS5 port
}

// ─── Resolver scanner ───────────────────────────────────────────

/// Scan a list of candidate resolver IPs by sending a DNS query for a DNSTT domain.
/// Returns (working_ip, latency_ms) sorted by latency.
pub async fn scan_resolvers(
    candidates: &[String],
    probe_domain: &str,
    timeout_ms: u64,
) -> Vec<(String, u64)> {
    fn build_txt_query(domain: &str) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        let id: u16 = rand::random();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&[0x01, 0x00]); // RD=1
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        for label in domain.split('.') {
            if label.is_empty() { continue; }
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]); // TXT, IN
        buf
    }

    let probe_label: u32 = rand::random();
    let full_domain = format!("p{:08x}.{}", probe_label, probe_domain);
    let query = build_txt_query(&full_domain);

    let mut handles = Vec::new();
    for candidate in candidates {
        let addr: SocketAddr = match (if candidate.contains(':') {
            candidate.clone()
        } else {
            format!("{}:53", candidate)
        }).parse() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let q = query.clone();
        let ip = candidate.clone();
        handles.push(tokio::spawn(async move {
            let sock = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(_) => return (ip, false, 0u64),
            };
            let start = tokio::time::Instant::now();
            let _ = sock.send_to(&q, addr).await;
            let mut buf = [0u8; 512];
            match tokio::time::timeout(
                Duration::from_millis(timeout_ms),
                sock.recv_from(&mut buf),
            ).await {
                Ok(Ok((len, _))) if len > 12 => {
                    let ms = start.elapsed().as_millis() as u64;
                    // Check AA flag — our server sets it
                    let aa = (buf[2] & 0x04) != 0;
                    (ip, aa, ms)
                }
                _ => (ip, false, 0),
            }
        }));
    }

    let mut results = Vec::new();
    for h in handles {
        if let Ok((ip, ok, ms)) = h.await {
            if ok {
                results.push((ip, ms));
            }
        }
    }
    results.sort_by_key(|&(_, ms)| ms);
    results
}

// ─── DNS Flux algorithm ─────────────────────────────────────────

/// Deterministic domain subset selection based on current date.
/// Given a pool of N domains, selects K domains for the current time period.
/// Both client and server know the algorithm — no coordination needed.
///
/// Uses HMAC-like construction: hash(seed || period_counter) -> deterministic shuffle.
pub fn dns_flux_select(
    all_domains: &[(String, String)],
    count: usize,
    seed: &[u8],
) -> Vec<(String, String)> {
    if all_domains.len() <= count {
        return all_domains.to_vec();
    }

    // Period = 6 hours (4 rotations per day)
    let period = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() / (6 * 3600);

    // Simple hash: FNV-1a(seed || period bytes)
    let mut hash = 0xcbf29ce484222325u64;
    for &b in seed {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    for &b in &period.to_le_bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }

    // Fisher-Yates shuffle with deterministic PRNG seeded from hash
    let mut indices: Vec<usize> = (0..all_domains.len()).collect();
    let mut rng_state = hash;
    for i in (1..indices.len()).rev() {
        // Simple LCG
        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let j = (rng_state >> 33) as usize % (i + 1);
        indices.swap(i, j);
    }

    indices.iter().take(count)
        .map(|&i| all_domains[i].clone())
        .collect()
}
