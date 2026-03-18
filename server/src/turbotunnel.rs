//! TurboTunnel bridge — connects DNS queries ↔ KCP packets.
//!
//! Upstream decode: QNAME base32 → ClientID + raw KCP packets.
//! Downstream encode: KCP output → length-prefixed TXT RDATA.
//!
//! Matches the wire format of Go dnstt-server's recvLoop/sendLoop exactly.

use crate::dns::{self, DnsMessage, DnsName, DnsRR, encode_rdata_txt, encode_rdata_for_type, RR_TYPE_A, RR_TYPE_AAAA, RR_TYPE_MX, RR_TYPE_NS, RR_TYPE_SRV};
use crate::kcp_manager::{ClientID, KcpManager};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::time::timeout;

// ── Constants ────────────────────────────────────────────────────

const RESPONSE_TTL: u32 = 60;
/// Maximum time to wait for downstream data before returning empty response.
/// Lower = more responsive but more DNS queries. 200ms is optimal for
/// recursive resolver compatibility (~2-5s chain budget) while keeping
/// query volume reasonable.
const MAX_RESPONSE_DELAY: Duration = Duration::from_millis(200);

// ── Response RDATA encoding (multi-type) ────────────────────────
//
// Encode downstream payload into whatever record type the client asked for.
// For TXT/NULL/CNAME: single answer RR. For A/AAAA: split across multiple RRs.

fn encode_answer_rdata(resp: &mut DnsMessage, payload: &[u8]) {
    if resp.answer.is_empty() {
        return;
    }
    let qtype = resp.answer[0].rr_type;

    match qtype {
        RR_TYPE_A => {
            // Pack payload into multiple A records (4 bytes each).
            // First 2 bytes = total payload length (so client knows real size).
            let mut framed = Vec::with_capacity(2 + payload.len());
            framed.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            framed.extend_from_slice(payload);

            let template = resp.answer[0].clone();
            resp.answer.clear();
            for chunk in framed.chunks(4) {
                let mut rdata = [0u8; 4];
                rdata[..chunk.len()].copy_from_slice(chunk);
                resp.answer.push(DnsRR {
                    name: template.name.clone(),
                    rr_type: template.rr_type,
                    class: template.class,
                    ttl: RESPONSE_TTL,
                    data: rdata.to_vec(),
                });
            }
        }
        RR_TYPE_AAAA => {
            // Pack payload into multiple AAAA records (16 bytes each).
            let mut framed = Vec::with_capacity(2 + payload.len());
            framed.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            framed.extend_from_slice(payload);

            let template = resp.answer[0].clone();
            resp.answer.clear();
            for chunk in framed.chunks(16) {
                let mut rdata = [0u8; 16];
                rdata[..chunk.len()].copy_from_slice(chunk);
                resp.answer.push(DnsRR {
                    name: template.name.clone(),
                    rr_type: template.rr_type,
                    class: template.class,
                    ttl: RESPONSE_TTL,
                    data: rdata.to_vec(),
                });
            }
        }
        RR_TYPE_MX | RR_TYPE_NS | RR_TYPE_SRV => {
            // Name-based types: payload is encoded as base32 domain labels.
            // Each RR can carry ~180 bytes of payload. We split across multiple
            // RRs with a 2-byte total length header (same framing as A/AAAA).
            let mut framed = Vec::with_capacity(2 + payload.len());
            framed.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            framed.extend_from_slice(payload);

            // Each name-based RR can carry ~110 raw bytes (base32 inflates 8/5).
            // Be conservative: 100 bytes per chunk.
            let chunk_size: usize = 100;
            let template = resp.answer[0].clone();
            resp.answer.clear();
            for chunk in framed.chunks(chunk_size) {
                resp.answer.push(DnsRR {
                    name: template.name.clone(),
                    rr_type: template.rr_type,
                    class: template.class,
                    ttl: RESPONSE_TTL,
                    data: encode_rdata_for_type(chunk, qtype),
                });
            }
        }
        _ => {
            // TXT, NULL, CNAME: single answer RR with type-appropriate encoding.
            resp.answer[0].data = encode_rdata_for_type(payload, qtype);
        }
    }
}

// ── Packet framing ───────────────────────────────────────────────

/// Parse the next length-prefixed packet from a payload buffer.
/// Prefix byte B:
///   B < 224 (0xe0): data packet of B bytes
///   B >= 224: padding of (B - 224) bytes
///
/// Returns Ok(Some(packet)) for data, Ok(None) for EOF.
fn next_packet(data: &[u8], pos: &mut usize) -> io::Result<Option<Vec<u8>>> {
    loop {
        if *pos >= data.len() {
            return Ok(None);
        }
        let prefix = data[*pos];
        *pos += 1;

        if prefix >= 224 {
            // Padding.
            let padding_len = (prefix - 224) as usize;
            if *pos + padding_len > data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "padding truncated"));
            }
            *pos += padding_len;
        } else {
            // Data packet.
            let pkt_len = prefix as usize;
            if *pos + pkt_len > data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "packet truncated"));
            }
            let packet = data[*pos..*pos + pkt_len].to_vec();
            *pos += pkt_len;
            return Ok(Some(packet));
        }
    }
}

// ── Record ───────────────────────────────────────────────────────

/// A DNS response record with metadata for sendLoop.
/// Carries the socket reference so the response goes from the same IP
/// that received the query (critical for multi-homed hosts).
pub struct Record {
    pub resp: DnsMessage,
    pub addr: SocketAddr,
    pub client_id: ClientID,
    pub socket: Arc<UdpSocket>,
}

// ── Recv Loop ────────────────────────────────────────────────────

/// Receive loop: read DNS queries from UDP, extract KCP packets, feed to manager.
/// Spawns one task per socket so responses go from the correct source IP.
pub async fn recv_loop(
    domains: Vec<DnsName>,
    sockets: Vec<Arc<UdpSocket>>,
    kcp: Arc<Mutex<KcpManager>>,
    record_tx: tokio::sync::mpsc::Sender<Record>,
    max_udp_payload: usize,
) -> io::Result<()> {
    let domains = Arc::new(domains);
    let mut handles = Vec::new();

    for socket in sockets {
        let domains = domains.clone();
        let kcp = kcp.clone();
        let record_tx = record_tx.clone();
        let handle = tokio::spawn(async move {
            recv_one_socket(socket, &domains, &kcp, &record_tx, max_udp_payload).await
        });
        handles.push(handle);
    }

    // Wait for any socket task to finish (they run forever unless error).
    for handle in handles {
        if let Err(e) = handle.await {
            log::error!("recv socket task panicked: {}", e);
        }
    }

    Ok(())
}

/// Read from one socket, process queries, send records to send_loop.
async fn recv_one_socket(
    socket: Arc<UdpSocket>,
    domains: &[DnsName],
    kcp: &Arc<Mutex<KcpManager>>,
    record_tx: &tokio::sync::mpsc::Sender<Record>,
    max_udp_payload: usize,
) -> io::Result<()> {
    let mut buf = vec![0u8; 4096];

    loop {
        let (n, addr) = socket.recv_from(&mut buf).await?;

        // Parse as DNS message.
        let query = match dns::parse_message(&buf[..n]) {
            Ok(q) => q,
            Err(e) => {
                log::debug!("cannot parse DNS query from {}: {}", addr, e);
                continue;
            }
        };

        // Build response and extract payload.
        let (resp, payload) = match dns::response_for(&query, domains, max_udp_payload) {
            Some(r) => r,
            None => continue, // No response needed.
        };

        // Extract ClientID from the first 8 bytes of payload.
        let mut client_id = ClientID([0u8; 8]);
        if payload.len() >= 8 {
            client_id.0.copy_from_slice(&payload[..8]);
            let remaining = &payload[8..];

            // Parse KCP packets from the remaining payload.
            let mut pos = 0;
            loop {
                match next_packet(remaining, &mut pos) {
                    Ok(Some(pkt)) if !pkt.is_empty() => {
                        let mut mgr = kcp.lock().await;
                        mgr.feed_packet(client_id, &pkt);
                    }
                    _ => break,
                }
            }
        } else if !payload.is_empty() {
            // Payload too short for ClientID.
            let mut err_resp = resp.clone();
            if err_resp.rcode() == dns::RCODE_NO_ERROR {
                err_resp.flags |= dns::RCODE_NAME_ERROR;
            }
            let _ = record_tx
                .try_send(Record {
                    resp: err_resp,
                    addr,
                    client_id,
                    socket: socket.clone(),
                });
            continue;
        }

        // Send response record to send loop.
        let _ = record_tx.try_send(Record {
            resp,
            addr,
            client_id,
            socket: socket.clone(),
        });
    }
}

// ── Send Loop ────────────────────────────────────────────────────

/// Send loop: receive response records, spawn per-record tasks to bundle
/// outgoing KCP packets into DNS TXT responses.
///
/// Each DNS response is handled by its own task (like Go's goroutine-per-response).
/// This eliminates the sequential bottleneck where a 1-second wait for one
/// empty client blocks responses for all other clients.
///
/// Each Record carries its own socket reference, so responses go from the
/// same IP that received the query.
pub async fn send_loop(
    kcp: Arc<Mutex<KcpManager>>,
    mut record_rx: tokio::sync::mpsc::Receiver<Record>,
    max_encoded_payload: usize,
    max_udp_payload: usize,
    data_notify: Arc<Notify>,
) -> io::Result<()> {
    loop {
        let rec = match record_rx.recv().await {
            Some(r) => r,
            None => break, // Channel closed.
        };

        let kcp = kcp.clone();
        let notify = data_notify.clone();

        tokio::spawn(async move {
            send_one_response(
                rec,
                &kcp,
                max_encoded_payload,
                max_udp_payload,
                &notify,
            )
            .await;
        });
    }

    Ok(())
}

/// Handle a single DNS response: bundle downstream data and send.
async fn send_one_response(
    rec: Record,
    kcp: &Arc<Mutex<KcpManager>>,
    max_encoded_payload: usize,
    max_udp_payload: usize,
    data_notify: &Notify,
) {
    let socket = &rec.socket;
    let mut resp = rec.resp;

    if resp.rcode() == dns::RCODE_NO_ERROR && resp.question.len() == 1 {
        // Non-error response: fill Answer section with downstream data.
        let question = &resp.question[0];

        resp.answer = vec![DnsRR {
            name: question.name.clone(),
            rr_type: question.qtype,
            class: question.qclass,
            ttl: RESPONSE_TTL,
            data: vec![], // Will be filled below.
        }];

        let mut payload: Vec<u8> = Vec::new();
        let mut limit = max_encoded_payload as isize;

        // Bundle outgoing KCP packets into the response.
        // Wait up to MAX_RESPONSE_DELAY for the first packet, using Notify
        // instead of polling (no more 5ms sleep loop).
        let mut first = true;

        loop {
            // Try to get a packet immediately.
            let packet = {
                let mut mgr = kcp.lock().await;
                if let Some(p) = mgr.unstash(&rec.client_id) {
                    Some(p)
                } else if let Some(p) = mgr.pop_send_packet(&rec.client_id) {
                    Some(p)
                } else {
                    None
                }
            };

            let packet = if let Some(p) = packet {
                Some(p)
            } else if first {
                // Fast-path: if this client ID has no active session, respond
                // immediately. Unknown clients (recursive resolver probes,
                // health checks) should not wait 1 second — that causes
                // SERVFAIL from resolvers whose recursion timeout is <2s.
                let is_known = {
                    let mgr = kcp.lock().await;
                    mgr.is_known_client(&rec.client_id)
                };

                if !is_known {
                    // Unknown client — instant empty response.
                    None
                } else {
                    // Known client — wait for downstream data (long-poll).
                    match timeout(MAX_RESPONSE_DELAY, async {
                        loop {
                            let notified = data_notify.notified();
                            {
                                let mgr = kcp.lock().await;
                                if mgr.has_pending(&rec.client_id) {
                                    return;
                                }
                            }
                            notified.await;
                        }
                    })
                    .await
                    {
                        Ok(()) => {
                            let mut mgr = kcp.lock().await;
                            mgr.pop_send_packet(&rec.client_id)
                        }
                        Err(_) => None, // Timeout — send empty response.
                    }
                }
            } else {
                None
            };

            first = false;

            let p = match packet {
                Some(p) => p,
                None => break, // No more data.
            };

            // Check if this packet fits.
            let needed = 2 + p.len(); // uint16 BE length + data
            if payload.is_empty() {
                // First packet always included (may be truncated by receiver).
            } else if limit - needed as isize <= 0 {
                // Stash for next response.
                let mut mgr = kcp.lock().await;
                mgr.stash(rec.client_id, p);
                break;
            }

            limit -= needed as isize;

            // Encode: [uint16 BE length][packet data]
            payload.extend_from_slice(&(p.len() as u16).to_be_bytes());
            payload.extend_from_slice(&p);

            // After the first packet, don't wait — drain immediately.
        }

        if !payload.is_empty() {
            log::debug!("send: bundled {} bytes for client={}", payload.len(), rec.client_id);
        }
        encode_answer_rdata(&mut resp, &payload);
    }

    // Serialize to wire format.
    let mut wire = match resp.to_wire() {
        Ok(w) => w,
        Err(e) => {
            log::warn!("resp WireFormat: {}", e);
            return;
        }
    };

    // Truncate if necessary.
    if wire.len() > max_udp_payload {
        wire.truncate(max_udp_payload);
        wire[2] |= 0x02; // TC = 1
    }

    // Send UDP response.
    if let Err(e) = socket.send_to(&wire, rec.addr).await {
        log::warn!("send_to {}: {}", rec.addr, e);
    }
}

// ── TCP DNS Listener ─────────────────────────────────────────────
//
// DNS-over-TCP per RFC 1035 §4.2.2: each message is prefixed with a
// 2-byte big-endian length. This allows DNSTT clients to connect via
// Cloudflare Spectrum on tcp/443, which proxies transparently to us.
//
// Each TCP connection is handled independently — read query, process
// through the same KCP/Noise pipeline as UDP, write response.

/// Spawn TCP DNS listeners on the given addresses.
pub async fn tcp_listen(
    addrs: Vec<String>,
    domains: Vec<DnsName>,
    kcp: Arc<Mutex<KcpManager>>,
    record_tx: mpsc::Sender<Record>,
    max_udp_payload: usize,
    data_notify: Arc<Notify>,
    max_encoded_payload: usize,
) -> io::Result<()> {
    let domains = Arc::new(domains);

    for addr in addrs {
        let listener = TcpListener::bind(&addr).await?;
        log::info!("TCP DNS listening on {}", addr);

        let domains = domains.clone();
        let kcp = kcp.clone();
        let record_tx = record_tx.clone();
        let data_notify = data_notify.clone();

        tokio::spawn(async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!("TCP accept: {}", e);
                        continue;
                    }
                };

                let domains = domains.clone();
                let kcp = kcp.clone();
                let notify = data_notify.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_tcp_conn(
                        stream, peer, &domains, &kcp, max_udp_payload,
                        max_encoded_payload, &notify,
                    ).await {
                        log::debug!("TCP conn {}: {}", peer, e);
                    }
                });
            }
        });
    }

    Ok(())
}

/// Handle one TCP DNS connection: read queries, process, write responses.
async fn handle_tcp_conn(
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
    domains: &[DnsName],
    kcp: &Arc<Mutex<KcpManager>>,
    max_udp_payload: usize,
    max_encoded_payload: usize,
    data_notify: &Notify,
) -> io::Result<()> {
    let (mut reader, mut writer) = stream.split();

    loop {
        // Read 2-byte length prefix.
        let mut len_buf = [0u8; 2];
        match reader.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 65535 {
            return Ok(());
        }

        // Read DNS message.
        let mut msg_buf = vec![0u8; msg_len];
        reader.read_exact(&mut msg_buf).await?;

        // Parse as DNS.
        let query = match dns::parse_message(&msg_buf) {
            Ok(q) => q,
            Err(_) => continue,
        };

        // Build response and extract payload (same as UDP path).
        let (resp, payload) = match dns::response_for(&query, domains, max_udp_payload) {
            Some(r) => r,
            None => continue,
        };

        // Feed KCP packets from the query payload.
        let mut client_id = ClientID([0u8; 8]);
        if payload.len() >= 8 {
            client_id.0.copy_from_slice(&payload[..8]);
            let remaining = &payload[8..];
            let mut pos = 0;
            loop {
                match next_packet(remaining, &mut pos) {
                    Ok(Some(pkt)) if !pkt.is_empty() => {
                        let mut mgr = kcp.lock().await;
                        mgr.feed_packet(client_id, &pkt);
                    }
                    _ => break,
                }
            }
        }

        // Build response with downstream data (same logic as send_one_response).
        let mut final_resp = resp;
        if final_resp.rcode() == dns::RCODE_NO_ERROR && final_resp.question.len() == 1 {
            let question = &final_resp.question[0];
            final_resp.answer = vec![DnsRR {
                name: question.name.clone(),
                rr_type: question.qtype,
                class: question.qclass,
                ttl: RESPONSE_TTL,
                data: vec![],
            }];

            let mut resp_payload: Vec<u8> = Vec::new();
            let mut limit = max_encoded_payload as isize;

            // Check for pending data.
            let is_known = {
                let mgr = kcp.lock().await;
                mgr.is_known_client(&client_id)
            };

            let packet = {
                let mut mgr = kcp.lock().await;
                mgr.unstash(&client_id)
                    .or_else(|| mgr.pop_send_packet(&client_id))
            };

            let packet = if let Some(p) = packet {
                Some(p)
            } else if !is_known {
                None
            } else {
                match timeout(MAX_RESPONSE_DELAY, async {
                    loop {
                        let notified = data_notify.notified();
                        {
                            let mgr = kcp.lock().await;
                            if mgr.has_pending(&client_id) {
                                return;
                            }
                        }
                        notified.await;
                    }
                }).await {
                    Ok(()) => {
                        let mut mgr = kcp.lock().await;
                        mgr.pop_send_packet(&client_id)
                    }
                    Err(_) => None,
                }
            };

            if let Some(p) = packet {
                resp_payload.extend_from_slice(&(p.len() as u16).to_be_bytes());
                resp_payload.extend_from_slice(&p);

                // Drain remaining packets immediately.
                loop {
                    let next = {
                        let mut mgr = kcp.lock().await;
                        mgr.pop_send_packet(&client_id)
                    };
                    match next {
                        Some(p) => {
                            let needed = 2 + p.len();
                            if limit - needed as isize <= 0 {
                                let mut mgr = kcp.lock().await;
                                mgr.stash(client_id, p);
                                break;
                            }
                            limit -= needed as isize;
                            resp_payload.extend_from_slice(&(p.len() as u16).to_be_bytes());
                            resp_payload.extend_from_slice(&p);
                        }
                        None => break,
                    }
                }
            }

            encode_answer_rdata(&mut final_resp, &resp_payload);
        }

        // Serialize and send with TCP length prefix.
        let wire = match final_resp.to_wire() {
            Ok(w) => w,
            Err(_) => continue,
        };

        let len_prefix = (wire.len() as u16).to_be_bytes();
        writer.write_all(&len_prefix).await?;
        writer.write_all(&wire).await?;
    }
}
