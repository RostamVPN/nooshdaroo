//! smux v2 multiplexer — wire-compatible with xtaci/smux@v1.5.24.
//!
//! Header format (8 bytes, ALL LITTLE-ENDIAN):
//!   [0]    Version  = 2
//!   [1]    Cmd      = SYN(0) | FIN(1) | PSH(2) | NOP(3) | UPD(4)
//!   [2:4]  Length   uint16 LE (payload size after header)
//!   [4:8]  StreamID uint32 LE
//!
//! V2 UPD payload (8 bytes LE): [consumed: u32][window: u32]

use bytes::{Buf, BytesMut};
use std::collections::HashMap;

// ── Constants ────────────────────────────────────────────────────

const SMUX_VERSION: u8 = 2;
const HEADER_SIZE: usize = 8;

const CMD_SYN: u8 = 0;
const CMD_FIN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_NOP: u8 = 3;
const CMD_UPD: u8 = 4;

const DEFAULT_MAX_FRAME_SIZE: usize = 32768;
const DEFAULT_MAX_STREAM_BUFFER: u32 = 1_048_576; // 1 MB (dnstt override)

// ── Frame ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SmuxFrame {
    pub version: u8,
    pub cmd: u8,
    pub length: u16,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

impl SmuxFrame {
    pub fn new(cmd: u8, stream_id: u32, payload: Vec<u8>) -> Self {
        SmuxFrame {
            version: SMUX_VERSION,
            cmd,
            length: payload.len() as u16,
            stream_id,
            payload,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        buf.push(self.version);
        buf.push(self.cmd);
        buf.extend_from_slice(&self.length.to_le_bytes());
        buf.extend_from_slice(&self.stream_id.to_le_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// NOP keepalive frame.
    pub fn nop() -> Self {
        SmuxFrame::new(CMD_NOP, 0, vec![])
    }

    /// UPD (window update) frame.
    pub fn upd(stream_id: u32, consumed: u32, window: u32) -> Self {
        let mut payload = Vec::with_capacity(8);
        payload.extend_from_slice(&consumed.to_le_bytes());
        payload.extend_from_slice(&window.to_le_bytes());
        SmuxFrame::new(CMD_UPD, stream_id, payload)
    }

    /// FIN (close stream) frame.
    pub fn fin(stream_id: u32) -> Self {
        SmuxFrame::new(CMD_FIN, stream_id, vec![])
    }
}

// ── Frame Parser ─────────────────────────────────────────────────

/// Incremental smux frame parser.
pub struct SmuxParser {
    buf: BytesMut,
}

impl SmuxParser {
    pub fn new() -> Self {
        SmuxParser {
            buf: BytesMut::with_capacity(8192),
        }
    }

    /// Feed raw bytes from the encrypted stream.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Try to parse the next frame. Returns None if incomplete.
    pub fn next_frame(&mut self) -> Option<SmuxFrame> {
        if self.buf.len() < HEADER_SIZE {
            return None;
        }
        let version = self.buf[0];
        let cmd = self.buf[1];
        let length = u16::from_le_bytes([self.buf[2], self.buf[3]]) as usize;
        let stream_id = u32::from_le_bytes([self.buf[4], self.buf[5], self.buf[6], self.buf[7]]);

        if self.buf.len() < HEADER_SIZE + length {
            return None;
        }

        self.buf.advance(HEADER_SIZE);
        let payload = self.buf.split_to(length).to_vec();

        Some(SmuxFrame {
            version,
            cmd,
            length: length as u16,
            stream_id,
            payload,
        })
    }
}

// ── Stream ───────────────────────────────────────────────────────

/// A single smux stream within a session.
pub struct SmuxStream {
    pub id: u32,
    /// Receive buffer: data pushed from PSH frames.
    recv_buf: BytesMut,
    /// Total bytes read by the application (for UPD consumed field).
    num_read: u32,
    /// Increment since last UPD sent.
    incr: u32,
    /// Total bytes written to remote.
    num_written: u32,
    /// Remote's consumed count (from UPD).
    peer_consumed: u32,
    /// Remote's window (from UPD).
    peer_window: u32,
    /// Max stream buffer size.
    max_buffer: u32,
    /// Max frame payload size for writes.
    max_frame_size: usize,
    /// Whether this stream has been closed.
    closed: bool,
}

impl SmuxStream {
    fn new(id: u32, max_buffer: u32, max_frame_size: usize) -> Self {
        SmuxStream {
            id,
            recv_buf: BytesMut::with_capacity(max_buffer as usize),
            num_read: 0,
            incr: 0,
            num_written: 0,
            peer_consumed: 0,
            peer_window: max_buffer, // Initial window = max buffer.
            max_buffer,
            max_frame_size,
            closed: false,
        }
    }

    /// Push data from a PSH frame into the receive buffer.
    fn push_data(&mut self, data: &[u8]) {
        self.recv_buf.extend_from_slice(data);
    }

    /// Update peer window from a UPD frame.
    fn update_window(&mut self, consumed: u32, window: u32) {
        self.peer_consumed = consumed;
        self.peer_window = window;
    }

    /// Read data from the receive buffer.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let n = std::cmp::min(buf.len(), self.recv_buf.len());
        if n > 0 {
            buf[..n].copy_from_slice(&self.recv_buf[..n]);
            self.recv_buf.advance(n);
            self.num_read = self.num_read.wrapping_add(n as u32);
            self.incr += n as u32;
        }
        n
    }

    /// Check if we need to send a window update.
    /// Returns Some((consumed, window)) if update needed.
    pub fn check_window_update(&mut self) -> Option<(u32, u32)> {
        if self.incr >= self.max_buffer / 2 || self.incr >= self.max_frame_size as u32 {
            let consumed = self.num_read;
            self.incr = 0;
            Some((consumed, self.max_buffer))
        } else {
            None
        }
    }

    /// Available space in the remote's receive window.
    pub fn send_window_available(&self) -> usize {
        let in_flight = self.num_written.wrapping_sub(self.peer_consumed);
        if in_flight >= self.peer_window {
            0
        } else {
            (self.peer_window - in_flight) as usize
        }
    }

    /// Prepare data for sending. Returns chunks of data + updates num_written.
    pub fn prepare_write(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        let mut remaining = data;
        while !remaining.is_empty() {
            let available = self.send_window_available();
            if available == 0 {
                break; // Flow control: no window space.
            }
            let sz = std::cmp::min(remaining.len(), std::cmp::min(available, self.max_frame_size));
            frames.push(remaining[..sz].to_vec());
            self.num_written = self.num_written.wrapping_add(sz as u32);
            remaining = &remaining[sz..];
        }
        frames
    }

    pub fn has_data(&self) -> bool {
        !self.recv_buf.is_empty()
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn mark_closed(&mut self) {
        self.closed = true;
    }
}

// ── Session ──────────────────────────────────────────────────────

/// Server-side smux session. Accepts streams from clients.
pub struct SmuxSession {
    /// Active streams by ID.
    streams: HashMap<u32, SmuxStream>,
    /// Frame parser.
    parser: SmuxParser,
    /// Newly accepted stream IDs (from SYN frames).
    accepted: Vec<u32>,
    /// Frames to send (NOP, UPD, FIN, PSH).
    outgoing: Vec<SmuxFrame>,
    /// Max stream buffer.
    max_stream_buffer: u32,
    /// Max frame size.
    max_frame_size: usize,
    /// Whether session is dead.
    dead: bool,
}

impl SmuxSession {
    pub fn new(max_stream_buffer: u32) -> Self {
        SmuxSession {
            streams: HashMap::new(),
            parser: SmuxParser::new(),
            accepted: Vec::new(),
            outgoing: Vec::new(),
            max_stream_buffer,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            dead: false,
        }
    }

    /// Feed decrypted data from the Noise layer.
    pub fn feed(&mut self, data: &[u8]) {
        self.parser.feed(data);
    }

    /// Process all pending frames. Returns newly accepted stream IDs.
    pub fn process(&mut self) -> Vec<u32> {
        let mut new_streams = Vec::new();

        while let Some(frame) = self.parser.next_frame() {
            match frame.cmd {
                CMD_NOP => {
                    // Keepalive — no action needed, just updates "last seen".
                }
                CMD_SYN => {
                    let sid = frame.stream_id;
                    if !self.streams.contains_key(&sid) {
                        let stream = SmuxStream::new(sid, self.max_stream_buffer, self.max_frame_size);
                        self.streams.insert(sid, stream);
                        new_streams.push(sid);
                    }
                }
                CMD_FIN => {
                    let sid = frame.stream_id;
                    if let Some(stream) = self.streams.get_mut(&sid) {
                        stream.mark_closed();
                    }
                }
                CMD_PSH => {
                    let sid = frame.stream_id;
                    if let Some(stream) = self.streams.get_mut(&sid) {
                        stream.push_data(&frame.payload);
                    }
                    // Silently ignore PSH for unknown streams.
                }
                CMD_UPD => {
                    let sid = frame.stream_id;
                    if frame.payload.len() >= 8 {
                        let consumed = u32::from_le_bytes([
                            frame.payload[0], frame.payload[1],
                            frame.payload[2], frame.payload[3],
                        ]);
                        let window = u32::from_le_bytes([
                            frame.payload[4], frame.payload[5],
                            frame.payload[6], frame.payload[7],
                        ]);
                        if let Some(stream) = self.streams.get_mut(&sid) {
                            stream.update_window(consumed, window);
                        }
                    }
                }
                _ => {
                    log::warn!("smux: unknown cmd {}", frame.cmd);
                }
            }
        }

        new_streams
    }

    /// Read data from a specific stream.
    pub fn stream_read(&mut self, stream_id: u32, buf: &mut [u8]) -> usize {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            let n = stream.read(buf);
            // Check if we need to send a window update.
            if let Some((consumed, window)) = stream.check_window_update() {
                self.outgoing.push(SmuxFrame::upd(stream_id, consumed, window));
            }
            n
        } else {
            0
        }
    }

    /// Write data to a specific stream. Returns frames to send.
    pub fn stream_write(&mut self, stream_id: u32, data: &[u8]) -> Vec<SmuxFrame> {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            let chunks = stream.prepare_write(data);
            chunks
                .into_iter()
                .map(|payload| SmuxFrame::new(CMD_PSH, stream_id, payload))
                .collect()
        } else {
            vec![]
        }
    }

    /// Close a stream and return FIN frame.
    pub fn stream_close(&mut self, stream_id: u32) -> Option<SmuxFrame> {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.mark_closed();
            Some(SmuxFrame::fin(stream_id))
        } else {
            None
        }
    }

    /// Remove a closed stream.
    pub fn stream_remove(&mut self, stream_id: u32) {
        self.streams.remove(&stream_id);
    }

    /// Check if a stream has data available.
    pub fn stream_has_data(&self, stream_id: u32) -> bool {
        self.streams.get(&stream_id).map_or(false, |s| s.has_data())
    }

    /// Check if a stream is closed.
    pub fn stream_is_closed(&self, stream_id: u32) -> bool {
        self.streams.get(&stream_id).map_or(true, |s| s.is_closed())
    }

    /// Generate NOP keepalive frame.
    pub fn keepalive(&mut self) -> SmuxFrame {
        SmuxFrame::nop()
    }

    /// Drain pending outgoing frames (UPD, etc.).
    pub fn drain_outgoing(&mut self) -> Vec<SmuxFrame> {
        std::mem::take(&mut self.outgoing)
    }

    pub fn is_dead(&self) -> bool {
        self.dead
    }

    pub fn mark_dead(&mut self) {
        self.dead = true;
    }

    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }
}
