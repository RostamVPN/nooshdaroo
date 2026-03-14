//! KCP session manager — routes raw KCP packets by conv ID to per-session
//! state machines, manages Noise handshake, smux multiplexing, and SOCKS5.
//!
//! Architecture:
//!   recv_task → KcpManager → per-session task (Noise → smux → SOCKS5 → TCP)
//!   per-session task → KcpManager → send queues → send_task → DNS responses

use crate::noise_session::NoiseStream;
use crate::smux::{SmuxFrame, SmuxSession};
use bytes::BytesMut;
use kcp::Kcp;
use std::collections::{HashMap, HashSet};
use std::io::{self, Write};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Notify};

// ── Constants ────────────────────────────────────────────────────

/// Idle timeout for sessions (matches Go's idleTimeout = 2min).
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// KCP update check interval.
const KCP_TICK_INTERVAL: Duration = Duration::from_millis(20);

/// Max streams per client (matches Go default).
const DEFAULT_MAX_STREAMS: usize = 64;

/// smux max stream buffer (matches Go's smuxMaxStreamBuffer = 1MB).
const DEFAULT_SMUX_MAX_STREAM_BUFFER: u32 = 1_048_576;

/// smux keepalive interval.
const SMUX_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

// ── Metrics ──────────────────────────────────────────────────────

pub struct Metrics {
    pub active_sessions: AtomicI64,
    pub active_streams: AtomicI64,
    pub total_streams: AtomicU64,
    pub total_bytes: AtomicU64,
    pub dial_errors: AtomicU64,
    pub stream_rejects: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Metrics {
            active_sessions: AtomicI64::new(0),
            active_streams: AtomicI64::new(0),
            total_streams: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            dial_errors: AtomicU64::new(0),
            stream_rejects: AtomicU64::new(0),
        }
    }
}

// ── ClientID ─────────────────────────────────────────────────────

/// 8-byte client session identifier (matches turbotunnel.ClientID).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClientID(pub [u8; 8]);

impl std::fmt::Display for ClientID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

// ── KCP Output Sink ──────────────────────────────────────────────

/// Shared buffer for collecting raw KCP output packets.
/// Uses Arc<StdMutex> so we can drain packets externally while
/// KCP holds ownership of its Write impl internally.
type SharedPacketBuf = Arc<StdMutex<Vec<Vec<u8>>>>;

/// KCP output writer — wraps a shared buffer.
struct KcpOutput {
    buf: SharedPacketBuf,
}

impl KcpOutput {
    fn new(buf: SharedPacketBuf) -> Self {
        KcpOutput { buf }
    }
}

impl Write for KcpOutput {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.lock().unwrap().push(data.to_vec());
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ── Per-Session State ────────────────────────────────────────────

/// Current phase of a session's lifecycle.
enum SessionPhase {
    /// Waiting for Noise handshake data.
    AwaitingHandshake {
        handshake_buf: BytesMut,
    },
    /// Noise handshake complete, smux session active.
    Active {
        noise: NoiseStream,
        smux: SmuxSession,
    },
    /// Session is dead.
    Dead,
}

/// Per-session KCP + protocol state.
struct Session {
    conv: u32,
    client_id: ClientID,
    kcp: Kcp<KcpOutput>,
    /// Shared output buffer — same Arc as inside kcp's KcpOutput writer.
    output_buf: SharedPacketBuf,
    phase: SessionPhase,
    last_activity: Instant,
    active_streams: usize,
    stream_tasks: HashMap<u32, mpsc::Sender<Vec<u8>>>,
}

impl Session {
    fn new(conv: u32, client_id: ClientID, mtu: usize) -> Self {
        let buf: SharedPacketBuf = Arc::new(StdMutex::new(Vec::new()));
        let output = KcpOutput::new(buf.clone());
        let mut kcp = Kcp::new_stream(conv, output);

        // KCP tuning for DNS tunnel low-latency:
        // - nodelay=true: skip delayed ACK, retransmit immediately
        // - interval=20: 20ms internal update timer
        // - resend=2: fast retransmit after 2 duplicate ACKs
        // - nc=true: no congestion window (DNS tunnel has its own flow control)
        // - wndsize=128: allow more packets in flight (bounded by client's window)
        kcp.set_nodelay(true, 20, 2, true);
        kcp.set_wndsize(128, 128);
        kcp.set_mtu(mtu).expect("invalid MTU");

        Session {
            conv,
            client_id,
            kcp,
            output_buf: buf,
            phase: SessionPhase::AwaitingHandshake {
                handshake_buf: BytesMut::with_capacity(256),
            },
            last_activity: Instant::now(),
            active_streams: 0,
            stream_tasks: HashMap::new(),
        }
    }

    fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() >= timeout
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }
}

// ── KCP Manager ──────────────────────────────────────────────────

/// Central KCP session manager. Owns all session state.
pub struct KcpManager {
    /// Sessions by conv ID.
    sessions: HashMap<u32, Session>,
    /// Privkeys for Noise handshake (try each until one succeeds).
    privkeys: Vec<[u8; 32]>,
    /// KCP MTU.
    mtu: usize,
    /// Upstream mode ("socks5" or "host:port").
    upstream: String,
    /// Idle timeout.
    idle_timeout: Duration,
    /// Max streams per client.
    max_streams: usize,
    /// smux max stream buffer.
    smux_max_stream_buffer: u32,
    /// Metrics.
    metrics: Arc<Metrics>,
    /// Global epoch for KCP timestamps.
    epoch: Instant,
    /// Per-client send queues: ClientID → outgoing raw KCP packets.
    send_queues: HashMap<ClientID, Vec<Vec<u8>>>,
    /// Stash: one-element buffer per ClientID.
    stash: HashMap<ClientID, Vec<u8>>,
    /// Stream task spawner channel.
    stream_spawn_tx: mpsc::Sender<StreamTask>,
    /// Notify send_loop tasks when new packets are available in send_queues.
    data_notify: Arc<Notify>,
}

/// A stream task to be spawned by the stream handler.
pub struct StreamTask {
    pub conv: u32,
    pub stream_id: u32,
    pub data_rx: mpsc::Receiver<Vec<u8>>,
    pub upstream: String,
}

impl KcpManager {
    pub fn new(
        privkeys: Vec<[u8; 32]>,
        mtu: usize,
        upstream: String,
        idle_timeout: Duration,
        max_streams: usize,
        smux_max_stream_buffer: u32,
        metrics: Arc<Metrics>,
        stream_spawn_tx: mpsc::Sender<StreamTask>,
        data_notify: Arc<Notify>,
    ) -> Self {
        KcpManager {
            sessions: HashMap::new(),
            privkeys,
            mtu,
            upstream,
            idle_timeout,
            max_streams,
            smux_max_stream_buffer,
            metrics,
            epoch: Instant::now(),
            send_queues: HashMap::new(),
            stash: HashMap::new(),
            stream_spawn_tx,
            data_notify,
        }
    }

    fn current_ms(&self) -> u32 {
        self.epoch.elapsed().as_millis() as u32
    }

    /// Feed a raw KCP packet (extracted from a DNS query).
    pub fn feed_packet(&mut self, client_id: ClientID, data: &[u8]) {
        if data.len() < 24 {
            return; // Too short for KCP header.
        }

        // Extract conv ID from first 4 bytes (LE).
        let conv = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        // Find or create session.
        let is_new = !self.sessions.contains_key(&conv);
        if is_new {
            let session = Session::new(conv, client_id, self.mtu);
            self.sessions.insert(conv, session);
            self.metrics.active_sessions.fetch_add(1, Ordering::Relaxed);
            log::info!("new session conv={:08x} client={}", conv, client_id);
        }

        let session = self.sessions.get_mut(&conv).unwrap();
        let phase_name = match &session.phase {
            SessionPhase::AwaitingHandshake { .. } => "handshake",
            SessionPhase::Active { .. } => "active",
            SessionPhase::Dead => "dead",
        };
        log::debug!("feed_packet conv={:08x} phase={} data_len={}", conv, phase_name, data.len());
        session.touch();
        session.client_id = client_id;

        // Feed to KCP.
        if let Err(e) = session.kcp.input(data) {
            log::warn!("kcp input conv={:08x}: {:?}", conv, e);
            return;
        }

        // Drain any output generated by input() (ACK packets).
        self.drain_kcp_output(conv);

        // Try to read reliable data from KCP.
        self.process_kcp_recv(conv);

        // Force flush any output generated during processing (e.g., handshake
        // response). Without this, kcp.send() data stays in KCP's snd_queue
        // until the next tick's kcp.update(), which may be too late — the
        // send task may have already timed out waiting for data.
        let now_ms = self.current_ms();
        if let Some(session) = self.sessions.get_mut(&conv) {
            let _ = session.kcp.update(now_ms);
        }
        self.drain_kcp_output(conv);
    }

    /// Drain KCP output packets to the send queue.
    /// Notifies waiting send tasks when new packets are available.
    fn drain_kcp_output(&mut self, conv: u32) {
        if let Some(session) = self.sessions.get_mut(&conv) {
            let client_id = session.client_id;
            let packets: Vec<Vec<u8>> = {
                let mut buf = session.output_buf.lock().unwrap();
                std::mem::take(&mut *buf)
            };
            if !packets.is_empty() {
                let queue = self.send_queues.entry(client_id).or_insert_with(Vec::new);
                queue.extend(packets);
                // Wake all send tasks waiting for data.
                self.data_notify.notify_waiters();
            }
        }
    }

    /// Try to read reliable data from KCP and process through Noise/smux.
    fn process_kcp_recv(&mut self, conv: u32) {
        let mut chunks = Vec::new();
        if let Some(session) = self.sessions.get_mut(&conv) {
            let mut buf = vec![0u8; 65536];
            loop {
                match session.kcp.recv(&mut buf) {
                    Ok(n) if n > 0 => {
                        chunks.push(buf[..n].to_vec());
                    }
                    _ => break,
                }
            }
            if !chunks.is_empty() {
                log::debug!("kcp_recv conv={:08x} chunks={} total_bytes={}",
                    conv, chunks.len(), chunks.iter().map(|c| c.len()).sum::<usize>());
            }
        }

        // Now process each chunk without borrowing sessions.
        for data in chunks {
            self.process_reliable_data(conv, &data);
        }
    }

    /// Process reliable data from KCP through the protocol stack.
    fn process_reliable_data(&mut self, conv: u32, data: &[u8]) {
        // Clone keys upfront to avoid borrow conflict with self.sessions.
        let privkeys = self.privkeys.clone();

        let session = match self.sessions.get_mut(&conv) {
            Some(s) => s,
            None => return,
        };

        match &mut session.phase {
            SessionPhase::AwaitingHandshake { handshake_buf } => {
                handshake_buf.extend_from_slice(data);
                log::debug!(
                    "handshake_buf conv={:08x} now {} bytes",
                    conv, handshake_buf.len()
                );

                // Try Noise handshake with each key until one succeeds.
                let mut handshake_ok = false;
                let mut needs_more = false;
                let mut leftover_data: Option<Vec<u8>> = None;
                let smux_buf = self.smux_max_stream_buffer;
                for privkey in &privkeys {
                    match crate::noise_session::server_handshake(privkey, handshake_buf) {
                        Ok((result, transport)) => {
                            let consumed = u16::from_be_bytes([result[0], result[1]]) as usize;
                            let response = &result[2..];

                            if let Err(e) = session.kcp.send(response) {
                                log::warn!("kcp send handshake response conv={:08x}: {:?}", conv, e);
                                session.phase = SessionPhase::Dead;
                                return;
                            }

                            let leftover = handshake_buf[consumed..].to_vec();
                            let noise = NoiseStream::new(transport);
                            let smux = SmuxSession::new(smux_buf);
                            session.phase = SessionPhase::Active { noise, smux };
                            log::info!("noise handshake complete conv={:08x}", conv);

                            if !leftover.is_empty() {
                                leftover_data = Some(leftover);
                            }
                            handshake_ok = true;
                            break;
                        }
                        Err(snow::Error::Input) => {
                            needs_more = true;
                            break;
                        }
                        Err(_) => {
                            continue;
                        }
                    }
                }
                if !handshake_ok && !needs_more {
                    log::warn!("noise handshake failed conv={:08x}: no key matched", conv);
                    session.phase = SessionPhase::Dead;
                }
                // Process leftover outside the session borrow.
                drop(session);
                if let Some(leftover) = leftover_data {
                    self.process_reliable_data(conv, &leftover);
                    return;
                }
            }
            SessionPhase::Active { noise, smux } => {
                // Guard: KCP retransmission can deliver the handshake initiator
                // message AGAIN after we're already in transport mode. The Noise NK
                // initiator is exactly 48 bytes (32 ephemeral + 16 AEAD tag),
                // length-prefixed as 2+48=50 bytes. If the first reliable data
                // chunk after handshake is 50 bytes and starts with the right
                // length prefix, it's almost certainly a retransmitted handshake.
                // We MUST NOT feed it to Noise — read_message() advances the nonce
                // counter even on failure, permanently desyncing the session.
                if data.len() >= 2 {
                    let frame_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                    if frame_len == 48 && data.len() == 50 {
                        log::debug!("skipping retransmitted handshake conv={:08x} (50B)", conv);
                        return;
                    }
                }

                // Feed encrypted data to Noise.
                noise.feed_encrypted(data);

                // Try to decrypt.
                match noise.try_decrypt() {
                    Ok(_progress) => {}
                    Err(e) => {
                        log::warn!("noise decrypt FATAL conv={:08x}: {} (len={})", conv, e, data.len());
                        session.phase = SessionPhase::Dead;
                        return;
                    }
                }

                // Read decrypted data into smux.
                let mut decrypt_buf = vec![0u8; 65536];
                loop {
                    let n = noise.read_decrypted(&mut decrypt_buf);
                    if n == 0 {
                        break;
                    }
                    smux.feed(&decrypt_buf[..n]);
                }

                // Process smux frames.
                let new_streams = smux.process();
                if !new_streams.is_empty() {
                    log::debug!("new streams conv={:08x}: {:?}", conv, new_streams);
                }

                // Handle new streams.
                for stream_id in new_streams {
                    if session.active_streams >= self.max_streams {
                        self.metrics.stream_rejects.fetch_add(1, Ordering::Relaxed);
                        log::warn!(
                            "stream {:08x}:{} rejected (limit {})",
                            conv,
                            stream_id,
                            self.max_streams
                        );
                        let _ = smux.stream_close(stream_id);
                        continue;
                    }

                    session.active_streams += 1;
                    self.metrics.active_streams.fetch_add(1, Ordering::Relaxed);
                    self.metrics.total_streams.fetch_add(1, Ordering::Relaxed);

                    // Create channel for feeding data to the stream handler.
                    let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);
                    session.stream_tasks.insert(stream_id, data_tx);

                    // Spawn the stream task.
                    let task = StreamTask {
                        conv,
                        stream_id,
                        data_rx,
                        upstream: self.upstream.clone(),
                    };
                    let _ = self.stream_spawn_tx.try_send(task);
                }

                // Feed data to active stream handlers.
                let stream_ids: Vec<u32> = session.stream_tasks.keys().copied().collect();
                for sid in stream_ids {
                    if smux.stream_has_data(sid) {
                        let mut buf = vec![0u8; 65536];
                        let n = smux.stream_read(sid, &mut buf);
                        if n > 0 {
                            if let Some(tx) = session.stream_tasks.get(&sid) {
                                if let Err(_) = tx.try_send(buf[..n].to_vec()) {
                                    log::warn!("data_tx full {:08x}:{}", conv, sid);
                                }
                            }
                        }
                    }

                    // If client sent FIN, drop the data sender to signal EOF
                    // to the stream handler. The handler calls stream_close()
                    // on exit, which sends FIN back and cleans up.
                    if smux.stream_is_closed(sid) {
                        session.stream_tasks.remove(&sid);
                    }
                }

                // Drain outgoing smux frames (UPD, etc.).
                let outgoing = smux.drain_outgoing();
                self.send_smux_frames(conv, outgoing);
            }
            SessionPhase::Dead => {}
        }
    }

    /// Encode smux frames, encrypt via Noise, send via KCP.
    /// Flushes KCP immediately so data is available in the send queue
    /// for the next DNS response (rather than waiting for the 20ms tick).
    fn send_smux_frames(&mut self, conv: u32, frames: Vec<SmuxFrame>) {
        if frames.is_empty() {
            return;
        }

        // Step 1: Encrypt via Noise (borrows session.phase).
        let encrypted = {
            let session = match self.sessions.get_mut(&conv) {
                Some(s) => s,
                None => return,
            };
            if let SessionPhase::Active { noise, .. } = &mut session.phase {
                let mut raw = Vec::new();
                for frame in &frames {
                    raw.extend_from_slice(&frame.encode());
                }
                match noise.encrypt(&raw) {
                    Ok(enc) => Some(enc),
                    Err(e) => {
                        log::warn!("noise encrypt conv={:08x}: {}", conv, e);
                        None
                    }
                }
            } else {
                None
            }
        };

        // Step 2: Send via KCP and flush immediately.
        // kcp.send() only queues in snd_queue; kcp.flush() forces output NOW.
        if let Some(encrypted) = encrypted {
            let now_ms = self.current_ms();
            if let Some(session) = self.sessions.get_mut(&conv) {
                if let Err(e) = session.kcp.send(&encrypted) {
                    log::warn!("kcp send conv={:08x}: {:?}", conv, e);
                }
                let _ = session.kcp.update(now_ms);
            }
        }

        self.drain_kcp_output(conv);
    }

    /// Send data back to a stream (from the stream task).
    pub fn stream_write(&mut self, conv: u32, stream_id: u32, data: &[u8]) {
        log::debug!("stream_write conv={:08x} sid={} len={}", conv, stream_id, data.len());
        // Collect smux frames first, then encrypt+send in a separate borrow.
        let frames = {
            let session = match self.sessions.get_mut(&conv) {
                Some(s) => s,
                None => return,
            };
            if let SessionPhase::Active { smux, .. } = &mut session.phase {
                smux.stream_write(stream_id, data)
            } else {
                return;
            }
        };
        // Borrow of sessions is released — safe to call send_smux_frames.
        self.send_smux_frames(conv, frames);
    }

    /// Close a stream: send FIN back to client, remove from smux, clean up.
    /// Called by the stream handler task when it finishes.
    pub fn stream_close(&mut self, conv: u32, stream_id: u32) {
        let fin_frame = {
            let session = match self.sessions.get_mut(&conv) {
                Some(s) => s,
                None => return, // Session already expired.
            };
            session.stream_tasks.remove(&stream_id);
            session.active_streams = session.active_streams.saturating_sub(1);

            if let SessionPhase::Active { smux, .. } = &mut session.phase {
                // Send FIN only if the client hasn't already closed this stream.
                let frame = if !smux.stream_is_closed(stream_id) {
                    smux.stream_close(stream_id)
                } else {
                    None
                };
                smux.stream_remove(stream_id);
                frame
            } else {
                None
            }
        };

        if let Some(frame) = fin_frame {
            self.send_smux_frames(conv, vec![frame]);
        }
    }

    /// Periodic tick: update all KCP sessions, check expiry, send keepalives.
    pub fn tick(&mut self) {
        let now_ms = self.current_ms();

        // Collect expired sessions.
        let expired: Vec<u32> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.is_expired(self.idle_timeout))
            .map(|(conv, _)| *conv)
            .collect();

        for conv in expired {
            if let Some(session) = self.sessions.remove(&conv) {
                log::debug!("expiring session conv={:08x} client={}", conv, session.client_id);
                self.send_queues.remove(&session.client_id);
                self.stash.remove(&session.client_id);
                self.metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
            }
        }

        // Also remove dead sessions.
        let dead: Vec<u32> = self
            .sessions
            .iter()
            .filter(|(_, s)| matches!(s.phase, SessionPhase::Dead))
            .map(|(conv, _)| *conv)
            .collect();

        for conv in dead {
            if let Some(session) = self.sessions.remove(&conv) {
                self.send_queues.remove(&session.client_id);
                self.stash.remove(&session.client_id);
                self.metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
            }
        }

        // Update all KCP sessions.
        let convs: Vec<u32> = self.sessions.keys().copied().collect();
        for conv in convs {
            if let Some(session) = self.sessions.get_mut(&conv) {
                let check = session.kcp.check(now_ms);
                if now_ms >= check {
                    let _ = session.kcp.update(now_ms);
                    self.drain_kcp_output(conv);

                    // Try to read any newly available data.
                    self.process_kcp_recv(conv);
                }
            }
        }
    }

    /// Get pending send queue for a client ID. Returns None if empty.
    pub fn take_send_queue(&mut self, client_id: &ClientID) -> Option<Vec<Vec<u8>>> {
        self.send_queues.remove(client_id).filter(|q| !q.is_empty())
    }

    /// Get outgoing packet from send queue (single packet).
    pub fn pop_send_packet(&mut self, client_id: &ClientID) -> Option<Vec<u8>> {
        if let Some(queue) = self.send_queues.get_mut(client_id) {
            if !queue.is_empty() {
                return Some(queue.remove(0));
            }
        }
        None
    }

    /// Check if there are any pending packets for a client.
    pub fn has_pending(&self, client_id: &ClientID) -> bool {
        self.send_queues
            .get(client_id)
            .map_or(false, |q| !q.is_empty())
    }

    /// Stash a packet that didn't fit in the last response.
    pub fn stash(&mut self, client_id: ClientID, packet: Vec<u8>) -> bool {
        if self.stash.contains_key(&client_id) {
            false
        } else {
            self.stash.insert(client_id, packet);
            true
        }
    }

    /// Unstash a packet.
    pub fn unstash(&mut self, client_id: &ClientID) -> Option<Vec<u8>> {
        self.stash.remove(client_id)
    }

    /// Check if a client ID has any active session, pending data, or stash.
    /// Unknown clients (random probes, resolver tests) get fast-pathed — no wait.
    pub fn is_known_client(&self, client_id: &ClientID) -> bool {
        // Check send queues
        if self.send_queues.contains_key(client_id) {
            return true;
        }
        // Check stash
        if self.stash.contains_key(client_id) {
            return true;
        }
        // Check if any session belongs to this client
        self.sessions.values().any(|s| s.client_id == *client_id)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Count unique client IDs across all active sessions.
    pub fn unique_client_count(&self) -> usize {
        let clients: HashSet<ClientID> = self.sessions.values().map(|s| s.client_id).collect();
        clients.len()
    }
}
