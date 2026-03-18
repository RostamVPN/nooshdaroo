//! Minimal DNS wire format parser/builder — RFC 1035 compliant.
//!
//! Faithful Rust port of dnstt/dns/dns.go. Handles name compression,
//! TXT RDATA encoding/decoding, and EDNS(0) OPT records.

use std::collections::HashMap;
use std::io::{self, Cursor, Read, Seek, SeekFrom};

// ── Constants ────────────────────────────────────────────────────

const COMPRESSION_POINTER_LIMIT: usize = 10;

pub const RR_TYPE_A: u16 = 1;
pub const RR_TYPE_NS: u16 = 2;
pub const RR_TYPE_CNAME: u16 = 5;
pub const RR_TYPE_NULL: u16 = 10;
pub const RR_TYPE_MX: u16 = 15;
pub const RR_TYPE_TXT: u16 = 16;
pub const RR_TYPE_AAAA: u16 = 28;
pub const RR_TYPE_SRV: u16 = 33;
pub const RR_TYPE_OPT: u16 = 41;

/// Record types we accept for tunnel data (downstream encoding).
/// Client picks the type; server echoes it. This lets clients adapt
/// when censors block specific qtypes (e.g. TXT blocked in Iran 2026-03).
pub fn is_tunnel_qtype(qtype: u16) -> bool {
    matches!(qtype, RR_TYPE_TXT | RR_TYPE_NULL | RR_TYPE_CNAME | RR_TYPE_A | RR_TYPE_AAAA
        | RR_TYPE_MX | RR_TYPE_NS | RR_TYPE_SRV)
}

pub const CLASS_IN: u16 = 1;

pub const RCODE_NO_ERROR: u16 = 0;
pub const RCODE_FORMAT_ERROR: u16 = 1;
pub const RCODE_NAME_ERROR: u16 = 3;
pub const RCODE_NOT_IMPLEMENTED: u16 = 4;
pub const EXTENDED_RCODE_BAD_VERS: u16 = 16;

// ── Types ────────────────────────────────────────────────────────

/// DNS name as a sequence of labels (without trailing root).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DnsName(pub Vec<Vec<u8>>);

impl DnsName {
    pub fn new(labels: Vec<Vec<u8>>) -> io::Result<Self> {
        for label in &labels {
            if label.is_empty() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "zero-length label"));
            }
            if label.len() > 63 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "label > 63 octets"));
            }
        }
        // Check total encoded length ≤ 255.
        let total: usize = labels.iter().map(|l| l.len() + 1).sum::<usize>() + 1;
        if total > 255 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "name > 255 octets"));
        }
        Ok(DnsName(labels))
    }

    pub fn root() -> Self {
        DnsName(Vec::new())
    }

    pub fn parse(s: &str) -> io::Result<Self> {
        let s = s.strip_suffix('.').unwrap_or(s);
        if s.is_empty() {
            return DnsName::new(Vec::new());
        }
        let labels: Vec<Vec<u8>> = s.split('.').map(|l| l.as_bytes().to_vec()).collect();
        DnsName::new(labels)
    }

    /// Remove `suffix` from the end of this name (case-insensitive).
    /// Returns the prefix if suffix matched, None otherwise.
    pub fn trim_suffix(&self, suffix: &DnsName) -> Option<DnsName> {
        if self.0.len() < suffix.0.len() {
            return None;
        }
        let split = self.0.len() - suffix.0.len();
        let aft = &self.0[split..];
        for (a, b) in aft.iter().zip(suffix.0.iter()) {
            if !a.eq_ignore_ascii_case(b) {
                return None;
            }
        }
        Some(DnsName(self.0[..split].to_vec()))
    }

    /// String key for name compression cache (case-preserving).
    fn cache_key(&self, from: usize) -> String {
        self.0[from..]
            .iter()
            .map(|l| {
                l.iter()
                    .map(|&b| {
                        if b == b'-'
                            || b.is_ascii_alphanumeric()
                        {
                            (b as char).to_string()
                        } else {
                            format!("\\x{:02x}", b)
                        }
                    })
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join(".")
    }

    pub fn to_string_repr(&self) -> String {
        if self.0.is_empty() {
            return ".".to_string();
        }
        self.cache_key(0)
    }
}

impl std::fmt::Display for DnsName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_repr())
    }
}

/// DNS question section entry.
#[derive(Clone, Debug)]
pub struct DnsQuestion {
    pub name: DnsName,
    pub qtype: u16,
    pub qclass: u16,
}

/// DNS resource record.
#[derive(Clone, Debug)]
pub struct DnsRR {
    pub name: DnsName,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
}

/// Complete DNS message.
#[derive(Clone, Debug)]
pub struct DnsMessage {
    pub id: u16,
    pub flags: u16,
    pub question: Vec<DnsQuestion>,
    pub answer: Vec<DnsRR>,
    pub authority: Vec<DnsRR>,
    pub additional: Vec<DnsRR>,
}

impl DnsMessage {
    pub fn opcode(&self) -> u16 {
        (self.flags >> 11) & 0xf
    }

    pub fn rcode(&self) -> u16 {
        self.flags & 0x000f
    }
}

// ── Parsing ──────────────────────────────────────────────────────

fn read_u8(r: &mut Cursor<&[u8]>) -> io::Result<u8> {
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn read_u16_be(r: &mut Cursor<&[u8]>) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

fn read_u32_be(r: &mut Cursor<&[u8]>) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

fn read_name(r: &mut Cursor<&[u8]>) -> io::Result<DnsName> {
    let mut labels: Vec<Vec<u8>> = Vec::new();
    let mut num_pointers = 0usize;
    let mut seek_to: Option<u64> = None;

    loop {
        let label_type = read_u8(r)?;

        match label_type & 0xc0 {
            0x00 => {
                // Ordinary label.
                let length = (label_type & 0x3f) as usize;
                if length == 0 {
                    break; // Root label — end of name.
                }
                let mut label = vec![0u8; length];
                r.read_exact(&mut label)?;
                labels.push(label);
            }
            0xc0 => {
                // Compression pointer.
                let upper = (label_type & 0x3f) as u16;
                let lower = read_u8(r)? as u16;
                let offset = (upper << 8) | lower;

                if num_pointers == 0 {
                    seek_to = Some(r.position());
                }
                num_pointers += 1;
                if num_pointers > COMPRESSION_POINTER_LIMIT {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "too many compression pointers",
                    ));
                }
                r.seek(SeekFrom::Start(offset as u64))?;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "reserved label type",
                ));
            }
        }
    }

    if let Some(pos) = seek_to {
        r.seek(SeekFrom::Start(pos))?;
    }

    DnsName::new(labels)
}

fn read_question(r: &mut Cursor<&[u8]>) -> io::Result<DnsQuestion> {
    let name = read_name(r)?;
    let qtype = read_u16_be(r)?;
    let qclass = read_u16_be(r)?;
    Ok(DnsQuestion { name, qtype, qclass })
}

fn read_rr(r: &mut Cursor<&[u8]>) -> io::Result<DnsRR> {
    let name = read_name(r)?;
    let rr_type = read_u16_be(r)?;
    let class = read_u16_be(r)?;
    let ttl = read_u32_be(r)?;
    let rd_length = read_u16_be(r)? as usize;
    let mut data = vec![0u8; rd_length];
    r.read_exact(&mut data)?;
    Ok(DnsRR { name, rr_type, class, ttl, data })
}

/// Parse a DNS message from wire format.
pub fn parse_message(buf: &[u8]) -> io::Result<DnsMessage> {
    let mut r = Cursor::new(buf);

    let id = read_u16_be(&mut r)?;
    let flags = read_u16_be(&mut r)?;
    let qd_count = read_u16_be(&mut r)?;
    let an_count = read_u16_be(&mut r)?;
    let ns_count = read_u16_be(&mut r)?;
    let ar_count = read_u16_be(&mut r)?;

    let mut question = Vec::with_capacity(qd_count as usize);
    for _ in 0..qd_count {
        question.push(read_question(&mut r)?);
    }

    let mut answer = Vec::with_capacity(an_count as usize);
    for _ in 0..an_count {
        answer.push(read_rr(&mut r)?);
    }

    let mut authority = Vec::with_capacity(ns_count as usize);
    for _ in 0..ns_count {
        authority.push(read_rr(&mut r)?);
    }

    let mut additional = Vec::with_capacity(ar_count as usize);
    for _ in 0..ar_count {
        additional.push(read_rr(&mut r)?);
    }

    // Check for trailing bytes (like Go's implementation).
    if (r.position() as usize) < buf.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "trailing bytes"));
    }

    Ok(DnsMessage { id, flags, question, answer, authority, additional })
}

// ── Serialization ────────────────────────────────────────────────

/// Builder for serializing DNS messages with name compression.
struct MessageBuilder {
    buf: Vec<u8>,
    name_cache: HashMap<String, usize>,
}

impl MessageBuilder {
    fn new() -> Self {
        MessageBuilder {
            buf: Vec::with_capacity(512),
            name_cache: HashMap::new(),
        }
    }

    fn write_u16_be(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    fn write_u32_be(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    fn write_name(&mut self, name: &DnsName) {
        for i in 0..name.0.len() {
            let key = name.cache_key(i);
            if let Some(&ptr) = self.name_cache.get(&key) {
                if ptr & 0x3fff == ptr {
                    // Write compression pointer.
                    self.write_u16_be(0xc000 | ptr as u16);
                    return;
                }
            }
            // Cache this suffix position.
            self.name_cache.insert(key, self.buf.len());
            let label = &name.0[i];
            assert!(!label.is_empty() && label.len() <= 63);
            self.buf.push(label.len() as u8);
            self.buf.extend_from_slice(label);
        }
        self.buf.push(0); // Root label.
    }

    fn write_question(&mut self, q: &DnsQuestion) {
        self.write_name(&q.name);
        self.write_u16_be(q.qtype);
        self.write_u16_be(q.qclass);
    }

    fn write_rr(&mut self, rr: &DnsRR) -> io::Result<()> {
        self.write_name(&rr.name);
        self.write_u16_be(rr.rr_type);
        self.write_u16_be(rr.class);
        self.write_u32_be(rr.ttl);
        let rd_length = rr.data.len();
        if rd_length > u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "RDATA too large"));
        }
        self.write_u16_be(rd_length as u16);
        self.buf.extend_from_slice(&rr.data);
        Ok(())
    }

    fn write_message(&mut self, msg: &DnsMessage) -> io::Result<()> {
        self.write_u16_be(msg.id);
        self.write_u16_be(msg.flags);

        for count in [
            msg.question.len(),
            msg.answer.len(),
            msg.authority.len(),
            msg.additional.len(),
        ] {
            if count > u16::MAX as usize {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "section count overflow"));
            }
            self.write_u16_be(count as u16);
        }

        for q in &msg.question {
            self.write_question(q);
        }
        for rr in &msg.answer {
            self.write_rr(rr)?;
        }
        for rr in &msg.authority {
            self.write_rr(rr)?;
        }
        for rr in &msg.additional {
            self.write_rr(rr)?;
        }

        Ok(())
    }
}

/// Serialize a DNS message to wire format.
impl DnsMessage {
    pub fn to_wire(&self) -> io::Result<Vec<u8>> {
        let mut builder = MessageBuilder::new();
        builder.write_message(self)?;
        Ok(builder.buf)
    }
}

// ── TXT RDATA ────────────────────────────────────────────────────

/// Decode TXT RDATA: concatenate all character-strings.
/// Each character-string is [length_byte][data...].
pub fn decode_rdata_txt(mut p: &[u8]) -> io::Result<Vec<u8>> {
    let mut result = Vec::new();
    loop {
        if p.is_empty() {
            if result.is_empty() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "empty TXT RDATA"));
            }
            break;
        }
        let n = p[0] as usize;
        p = &p[1..];
        if p.len() < n {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "TXT character-string truncated"));
        }
        result.extend_from_slice(&p[..n]);
        p = &p[n..];
    }
    Ok(result)
}

/// Encode data as TXT RDATA: split into ≤255-byte character-strings.
/// Always writes at least one character-string (even if empty).
pub fn encode_rdata_txt(p: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(p.len() + (p.len() / 255) + 2);
    let mut remaining = p;
    while remaining.len() > 255 {
        result.push(255);
        result.extend_from_slice(&remaining[..255]);
        remaining = &remaining[255..];
    }
    // Must write at least one character-string.
    result.push(remaining.len() as u8);
    result.extend_from_slice(remaining);
    result
}

// ── Multi-type RDATA encoding ────────────────────────────────────
//
// When censors block TXT records, the client switches qtype.
// The server encodes the same payload in whichever format the client asked for.
// Upstream is always QNAME (base32 labels) — that's type-agnostic.
// Downstream adapts: TXT (best), NULL (raw bytes), CNAME/A/AAAA (encoded).

/// Encode downstream payload as RDATA for the given record type.
/// Returns (rdata_bytes, rr_type) — rr_type always matches input.
pub fn encode_rdata_for_type(payload: &[u8], qtype: u16) -> Vec<u8> {
    match qtype {
        RR_TYPE_TXT => encode_rdata_txt(payload),
        RR_TYPE_NULL => {
            // NULL (type 10): raw bytes, no framing. Simplest possible encoding.
            // RDATA is just the raw payload — RDLENGTH in the RR header handles sizing.
            payload.to_vec()
        }
        RR_TYPE_CNAME => {
            // Encode payload as a fake domain name: base32 labels + ".x."
            // Each label ≤ 63 bytes, total ≤ 253 bytes.
            encode_rdata_name(payload)
        }
        RR_TYPE_A => {
            // Pack payload into 4-byte A records. Pad last record with zeros.
            // Multiple answer RRs used by caller if payload > 4 bytes.
            // Here we return RDATA for a single RR (4 bytes).
            let mut rdata = vec![0u8; 4];
            let copy_len = payload.len().min(4);
            rdata[..copy_len].copy_from_slice(&payload[..copy_len]);
            rdata
        }
        RR_TYPE_AAAA => {
            // Pack payload into 16-byte AAAA records. Pad with zeros.
            let mut rdata = vec![0u8; 16];
            let copy_len = payload.len().min(16);
            rdata[..copy_len].copy_from_slice(&payload[..copy_len]);
            rdata
        }
        RR_TYPE_MX => {
            // MX: 2-byte preference (0x0001) + domain name with base32 labels.
            let mut rdata = Vec::with_capacity(2 + payload.len() * 2);
            rdata.extend_from_slice(&[0x00, 0x01]); // preference = 1
            rdata.extend_from_slice(&encode_rdata_name(payload));
            rdata
        }
        RR_TYPE_NS => {
            // NS: domain name with base32-encoded payload in labels.
            encode_rdata_name(payload)
        }
        RR_TYPE_SRV => {
            // SRV: 6-byte header (priority=0, weight=0, port=0) + domain name.
            let mut rdata = Vec::with_capacity(6 + payload.len() * 2);
            rdata.extend_from_slice(&[0x00, 0x00]); // priority = 0
            rdata.extend_from_slice(&[0x00, 0x00]); // weight = 0
            rdata.extend_from_slice(&[0x00, 0x00]); // port = 0
            rdata.extend_from_slice(&encode_rdata_name(payload));
            rdata
        }
        _ => encode_rdata_txt(payload), // fallback
    }
}

/// Encode payload as a DNS name in RDATA (for CNAME/NS/MX responses).
/// Uses base32 in labels, ~180 usable bytes per name.
fn encode_rdata_name(payload: &[u8]) -> Vec<u8> {
    let encoded = data_encoding::BASE32_NOPAD.encode(payload).to_lowercase();
    let mut rdata = Vec::with_capacity(encoded.len() + 10);
    let bytes = encoded.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        let end = (pos + 63).min(bytes.len());
        let label = &bytes[pos..end];
        rdata.push(label.len() as u8);
        rdata.extend_from_slice(label);
        pos = end;
    }
    // Terminate with single-label TLD + root
    rdata.push(1);
    rdata.push(b'x');
    rdata.push(0); // root
    rdata
}

// ── Utility ──────────────────────────────────────────────────────

/// Compute the maximum TXT payload that fits within the given UDP limit.
/// Replicates computeMaxEncodedPayload from Go exactly.
pub fn compute_max_encoded_payload(limit: usize) -> usize {
    // Build a worst-case query with maximum-length QNAME (255 bytes).
    // 64+64+64+62 = 254 label bytes + 4 length bytes + 1 root = 259
    let max_length_name = DnsName(vec![
        vec![b'A'; 63],
        vec![b'A'; 63],
        vec![b'A'; 63],
        vec![b'A'; 61],
    ]);

    // Verify it's actually 255 bytes encoded.
    {
        let n: usize = max_length_name.0.iter().map(|l| l.len() + 1).sum::<usize>() + 1;
        assert_eq!(n, 255, "max-length name is {} octets, expected 255", n);
    }

    let query_limit: u16 = if limit > u16::MAX as usize { u16::MAX } else { limit as u16 };

    // Build a fake query message.
    let query = DnsMessage {
        id: 0,
        flags: 0,
        question: vec![DnsQuestion {
            name: max_length_name.clone(),
            qtype: RR_TYPE_TXT,
            qclass: RR_TYPE_TXT, // matches Go code
        }],
        answer: vec![],
        authority: vec![],
        additional: vec![DnsRR {
            name: DnsName::root(),
            rr_type: RR_TYPE_OPT,
            class: query_limit,
            ttl: 0,
            data: vec![],
        }],
    };

    // Build a response matching what responseFor + sendLoop produce.
    let domains = vec![DnsName(vec![])]; // empty domain matches everything
    let resp = response_for_internal(&query, &domains);
    let (mut resp, _) = match resp {
        Some(r) => r,
        None => return 0,
    };

    // As in sendLoop: add an Answer RR.
    resp.answer = vec![DnsRR {
        name: query.question[0].name.clone(),
        rr_type: query.question[0].qtype,
        class: query.question[0].qclass,
        ttl: 60, // responseTTL
        data: vec![], // placeholder
    }];

    // Binary search for the maximum payload size.
    let mut low: usize = 0;
    let mut high: usize = 32768;
    while low + 1 < high {
        let mid = (low + high) / 2;
        resp.answer[0].data = encode_rdata_txt(&vec![0u8; mid]);
        match resp.to_wire() {
            Ok(buf) if buf.len() <= limit => low = mid,
            _ => high = mid,
        }
    }

    low
}

/// Internal version of responseFor used by compute_max_encoded_payload.
fn response_for_internal(query: &DnsMessage, domains: &[DnsName]) -> Option<(DnsMessage, Vec<u8>)> {
    let mut resp = DnsMessage {
        id: query.id,
        flags: 0x8000, // QR = 1
        question: query.question.clone(),
        answer: vec![],
        authority: vec![],
        additional: vec![],
    };

    if query.flags & 0x8000 != 0 {
        return None; // Not a query.
    }

    // Check EDNS(0).
    for rr in &query.additional {
        if rr.rr_type != RR_TYPE_OPT {
            continue;
        }
        if !resp.additional.is_empty() {
            resp.flags |= RCODE_FORMAT_ERROR;
            return Some((resp, vec![]));
        }
        resp.additional.push(DnsRR {
            name: DnsName::root(),
            rr_type: RR_TYPE_OPT,
            class: 4096,
            ttl: 0,
            data: vec![],
        });

        let version = (rr.ttl >> 16) & 0xff;
        if version != 0 {
            resp.flags |= EXTENDED_RCODE_BAD_VERS & 0xf;
            resp.additional[0].ttl = ((EXTENDED_RCODE_BAD_VERS >> 4) as u32) << 24;
            return Some((resp, vec![]));
        }
    }

    if query.question.len() != 1 {
        resp.flags |= RCODE_FORMAT_ERROR;
        return Some((resp, vec![]));
    }
    let question = &query.question[0];

    let mut prefix = None;
    for domain in domains {
        if let Some(p) = question.name.trim_suffix(domain) {
            prefix = Some(p);
            break;
        }
    }
    let prefix = match prefix {
        Some(p) => p,
        None => {
            resp.flags |= RCODE_NAME_ERROR;
            return Some((resp, vec![]));
        }
    };
    resp.flags |= 0x0400; // AA = 1

    if query.opcode() != 0 {
        resp.flags |= RCODE_NOT_IMPLEMENTED;
        return Some((resp, vec![]));
    }

    if !is_tunnel_qtype(question.qtype) {
        resp.flags |= RCODE_NAME_ERROR;
        return Some((resp, vec![]));
    }

    // Decode base32 payload from QNAME prefix.
    let encoded: Vec<u8> = prefix.0.concat();
    let encoded_upper: String = encoded.iter().map(|&b| (b as char).to_ascii_uppercase()).collect();
    let payload = match data_encoding::BASE32_NOPAD.decode(encoded_upper.as_bytes()) {
        Ok(p) => p,
        Err(_) => {
            resp.flags |= RCODE_NAME_ERROR;
            return Some((resp, vec![]));
        }
    };

    Some((resp, payload))
}

/// Build a DNS response for a query. Returns (response, decoded_payload).
/// If response is None, no response should be sent.
/// If rcode != NoError, the payload is empty.
pub fn response_for(query: &DnsMessage, domains: &[DnsName], _max_udp_payload: usize) -> Option<(DnsMessage, Vec<u8>)> {
    let mut resp = DnsMessage {
        id: query.id,
        flags: 0x8000, // QR = 1
        question: query.question.clone(),
        answer: vec![],
        authority: vec![],
        additional: vec![],
    };

    if query.flags & 0x8000 != 0 {
        return None; // Not a query.
    }

    // Check EDNS(0).
    for rr in &query.additional {
        if rr.rr_type != RR_TYPE_OPT {
            continue;
        }
        if !resp.additional.is_empty() {
            resp.flags |= RCODE_FORMAT_ERROR;
            log::warn!("FORMERR: more than one OPT RR");
            return Some((resp, vec![]));
        }
        resp.additional.push(DnsRR {
            name: DnsName::root(),
            rr_type: RR_TYPE_OPT,
            class: 4096,
            ttl: 0,
            data: vec![],
        });

        let version = (rr.ttl >> 16) & 0xff;
        if version != 0 {
            resp.flags |= EXTENDED_RCODE_BAD_VERS & 0xf;
            resp.additional[0].ttl = ((EXTENDED_RCODE_BAD_VERS >> 4) as u32) << 24;
            log::warn!("BADVERS: EDNS version {} != 0", version);
            return Some((resp, vec![]));
        }
    }

    if query.question.len() != 1 {
        resp.flags |= RCODE_FORMAT_ERROR;
        log::warn!("FORMERR: {} questions", query.question.len());
        return Some((resp, vec![]));
    }
    let question = &query.question[0];

    // Try each domain in order.
    let mut prefix = None;
    for domain in domains {
        if let Some(p) = question.name.trim_suffix(domain) {
            prefix = Some(p);
            break;
        }
    }
    let prefix = match prefix {
        Some(p) => p,
        None => {
            resp.flags |= RCODE_NAME_ERROR;
            return Some((resp, vec![]));
        }
    };
    resp.flags |= 0x0400; // AA = 1

    if query.opcode() != 0 {
        resp.flags |= RCODE_NOT_IMPLEMENTED;
        return Some((resp, vec![]));
    }

    // ── Probe report sidechannel ─────────────────────────────────
    //
    // Queries with "report" as the first prefix label carry probe
    // experiment results, not tunnel data. The data is base32-encoded
    // in the remaining labels. We decode it, log it, and respond with
    // NXDOMAIN (no tunnel state involved).
    //
    // Format: <base32_data_labels>.report.t.cdn.example.com
    // The prefix (after trimming domain suffix) is: [data..., "report"]
    //
    // This works even when the tunnel itself is down — it's a single
    // stateless DNS query, fire-and-forget. Clients use it to report
    // DPI experiment results (resolver RTT, throttle detection, ISP info).
    if !prefix.0.is_empty() {
        let first_label = &prefix.0[prefix.0.len() - 1]; // last in prefix = first subdomain
        if first_label.eq_ignore_ascii_case(b"report") {
            // Extract data labels (everything except the "report" label)
            let data_labels = &prefix.0[..prefix.0.len() - 1];
            let encoded: Vec<u8> = data_labels.concat();
            let encoded_upper: String = encoded.iter().map(|&b| (b as char).to_ascii_uppercase()).collect();
            if let Ok(payload) = data_encoding::BASE32_NOPAD.decode(encoded_upper.as_bytes()) {
                // Log the probe report (decoded bytes — caller parses JSON/binary)
                if let Ok(report_str) = std::str::from_utf8(&payload) {
                    log::info!("[report] from={} data={}",
                        query.question.first().map(|q| q.name.to_string()).unwrap_or_default(),
                        report_str);
                } else {
                    log::info!("[report] from={} binary={}B",
                        query.question.first().map(|q| q.name.to_string()).unwrap_or_default(),
                        payload.len());
                }
                // Write to probe report file (append, one JSON line per report)
                let report_path = std::env::var("REPORT_LOG_PATH")
                    .unwrap_or_else(|_| {
                        std::env::temp_dir()
                            .join("dnstt-reports.jsonl")
                            .to_string_lossy()
                            .into_owned()
                    });
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true).append(true)
                    .open(&report_path)
                {
                    use std::io::Write;
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default().as_secs();
                    let _ = writeln!(f, "{{\"ts\":{},\"data\":{:?}}}", ts,
                        std::str::from_utf8(&payload).unwrap_or("(binary)"));
                }
            }
            // Always respond NXDOMAIN — no tunnel session created
            resp.flags |= RCODE_NAME_ERROR;
            return Some((resp, vec![]));
        }
    }
    // ── End report handler ───────────────────────────────────────

    if !is_tunnel_qtype(question.qtype) {
        resp.flags |= RCODE_NAME_ERROR;
        return Some((resp, vec![]));
    }

    // Decode base32 payload from QNAME prefix labels.
    let encoded: Vec<u8> = prefix.0.concat();
    let encoded_upper: String = encoded.iter().map(|&b| (b as char).to_ascii_uppercase()).collect();
    let payload = match data_encoding::BASE32_NOPAD.decode(encoded_upper.as_bytes()) {
        Ok(p) => p,
        Err(_) => {
            resp.flags |= RCODE_NAME_ERROR;
            log::warn!("NXDOMAIN: base32 decode error");
            return Some((resp, vec![]));
        }
    };

    Some((resp, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_trim_suffix() {
        let name = DnsName::parse("foo.bar.example.com").unwrap();
        let suffix = DnsName::parse("example.com").unwrap();
        let prefix = name.trim_suffix(&suffix).unwrap();
        assert_eq!(prefix.0.len(), 2);
        assert_eq!(prefix.0[0], b"foo");
        assert_eq!(prefix.0[1], b"bar");
    }

    #[test]
    fn test_name_trim_suffix_case_insensitive() {
        let name = DnsName::parse("FOO.Example.COM").unwrap();
        let suffix = DnsName::parse("example.com").unwrap();
        assert!(name.trim_suffix(&suffix).is_some());
    }

    #[test]
    fn test_encode_decode_rdata_txt() {
        let data = vec![0u8; 300];
        let encoded = encode_rdata_txt(&data);
        let decoded = decode_rdata_txt(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_rdata_txt_empty() {
        let encoded = encode_rdata_txt(&[]);
        assert_eq!(encoded, vec![0u8]); // one empty character-string
    }

    #[test]
    fn test_max_encoded_payload() {
        let mep = compute_max_encoded_payload(1232);
        assert!(mep > 0);
        assert!(mep < 1232);
        log::info!("maxEncodedPayload for 1232 = {}", mep);
    }

    #[test]
    fn test_roundtrip_message() {
        let msg = DnsMessage {
            id: 0x1234,
            flags: 0x8400,
            question: vec![DnsQuestion {
                name: DnsName::parse("test.example.com").unwrap(),
                qtype: RR_TYPE_TXT,
                qclass: CLASS_IN,
            }],
            answer: vec![DnsRR {
                name: DnsName::parse("test.example.com").unwrap(),
                rr_type: RR_TYPE_TXT,
                class: CLASS_IN,
                ttl: 60,
                data: encode_rdata_txt(b"hello"),
            }],
            authority: vec![],
            additional: vec![],
        };
        let wire = msg.to_wire().unwrap();
        let parsed = parse_message(&wire).unwrap();
        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.flags, 0x8400);
        assert_eq!(parsed.question.len(), 1);
        assert_eq!(parsed.answer.len(), 1);
        let txt = decode_rdata_txt(&parsed.answer[0].data).unwrap();
        assert_eq!(txt, b"hello");
    }
}
