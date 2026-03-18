//! Minimal DNS encoder/decoder for DNSTT wire compatibility.
//!
//! Encodes upstream data into DNS QNAME (base32 labels) and decodes
//! downstream RDATA with 2-byte length-prefixed packets.
//! Supports all record types: TXT, NULL, A, AAAA, CNAME, MX, NS, SRV.
//! Wire-compatible with dnstt-server (Go and Rust implementations).

use rand::Rng;

// ─── Constants ───────────────────────────────────────────────────

/// Max bytes per DNS label (RFC 1035)
const MAX_LABEL_LEN: usize = 63;
/// Max total QNAME length including dots and root (RFC 1035)
const MAX_QNAME_LEN: usize = 253;
/// DNS header is always 12 bytes
const DNS_HEADER_LEN: usize = 12;

// DNS record types — public so tunnel.rs can use them for qtype selection.
pub const QTYPE_A: u16 = 1;
pub const QTYPE_NS: u16 = 2;
pub const QTYPE_CNAME: u16 = 5;
pub const QTYPE_NULL: u16 = 10;
pub const QTYPE_MX: u16 = 15;
pub const QTYPE_TXT: u16 = 16;
pub const QTYPE_AAAA: u16 = 28;
pub const QTYPE_SRV: u16 = 33;

/// EDNS(0) OPT pseudo-RR: type=41, class=1452, ttl=0, rdlen=0
/// Chrome uses UDP payload size 1452 (not 4096) — matching this fingerprint
/// makes our queries look like they came from a Chromium DNS resolver.
const EDNS0_OPT: [u8; 11] = [
    0x00,                   // root name
    0x00, 0x29,             // type = OPT (41)
    0x05, 0xac,             // UDP payload size = 1452 (Chrome default)
    0x00, 0x00, 0x00, 0x00, // extended RCODE + flags (no DO bit — Chrome doesn't DNSSEC)
    0x00, 0x00,             // RDLENGTH = 0
];

/// Mapping from string name to QTYPE value (for CLI / config parsing).
pub fn parse_qtype(s: &str) -> Option<u16> {
    match s.to_uppercase().as_str() {
        "A" => Some(QTYPE_A),
        "NS" => Some(QTYPE_NS),
        "CNAME" => Some(QTYPE_CNAME),
        "NULL" => Some(QTYPE_NULL),
        "MX" => Some(QTYPE_MX),
        "TXT" => Some(QTYPE_TXT),
        "AAAA" => Some(QTYPE_AAAA),
        "SRV" => Some(QTYPE_SRV),
        _ => None,
    }
}

/// Human-readable name for a QTYPE value.
pub fn qtype_name(qtype: u16) -> &'static str {
    match qtype {
        QTYPE_A => "A",
        QTYPE_NS => "NS",
        QTYPE_CNAME => "CNAME",
        QTYPE_NULL => "NULL",
        QTYPE_MX => "MX",
        QTYPE_TXT => "TXT",
        QTYPE_AAAA => "AAAA",
        QTYPE_SRV => "SRV",
        _ => "??",
    }
}

/// Priority order for qtype selection: higher capacity first.
/// TXT (~1000 B/resp) > CNAME (~180 B) > MX (~178 B) > NS (~180 B) > SRV (~174 B) > AAAA (16 B) > A (4 B)
pub const QTYPE_PRIORITY: &[(u16, &str)] = &[
    (QTYPE_TXT,   "TXT"),
    (QTYPE_CNAME, "CNAME"),
    (QTYPE_MX,    "MX"),
    (QTYPE_NS,    "NS"),
    (QTYPE_SRV,   "SRV"),
    (QTYPE_AAAA,  "AAAA"),
    (QTYPE_A,     "A"),
];

/// Record types used in bootstrap probe (subset — skip NULL/SRV which are anomalous).
pub const PROBE_QTYPES: &[u16] = &[QTYPE_A, QTYPE_AAAA, QTYPE_CNAME, QTYPE_MX, QTYPE_TXT];

// ─── Base32 (RFC 4648, lowercase, no padding) ────────────────────

const B32_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

fn base32_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity((data.len() * 8 + 4) / 5);
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        buffer = (buffer << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32_ALPHABET[((buffer >> bits) & 0x1f) as usize]);
        }
    }
    if bits > 0 {
        out.push(B32_ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize]);
    }
    out
}

/// Decode base32 (RFC 4648, case-insensitive, no padding).
fn base32_decode(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() * 5 / 8);
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a',
            b'2'..=b'7' => b - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | val as u64;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

// ─── Public API ──────────────────────────────────────────────────

/// Encode upstream data into a DNS query wire format.
///
/// Format follows dnstt `dnsNameEncode`:
///   1. 8-byte client_id
///   2. Padding prefix: 0xe0+n, then n random bytes (3 for data, 8 for poll)
///   3. If data: 1-byte length + data bytes
///   4. Base32 encode the whole thing
///   5. Split into ≤63-byte labels, append domain labels
///   6. Build DNS query (configurable qtype, Class IN, RD=1, EDNS(0))
///
/// `qtype`: DNS record type to query. Use 16 (TXT) for default,
/// 10 (NULL) if TXT is blocked, or 1/28 (A/AAAA) as last resort.
pub fn encode_query(
    client_id: &[u8; 8],
    payload: &[u8],
    domain: &str,
    is_poll: bool,
) -> Vec<u8> {
    encode_query_typed(client_id, payload, domain, is_poll, QTYPE_TXT)
}

/// Encode query with explicit record type selection.
pub fn encode_query_typed(
    client_id: &[u8; 8],
    payload: &[u8],
    domain: &str,
    is_poll: bool,
    qtype: u16,
) -> Vec<u8> {
    // Build raw payload: client_id + padding + optional data
    let num_padding = if is_poll { 8 } else { 3 };
    let mut raw = Vec::with_capacity(8 + 1 + num_padding + 1 + payload.len());
    raw.extend_from_slice(client_id);
    raw.push(0xe0 | num_padding as u8);
    let mut rng = rand::thread_rng();
    for _ in 0..num_padding {
        raw.push(rng.gen());
    }
    if !payload.is_empty() {
        // Data mode: 1-byte length prefix + data
        raw.push(payload.len() as u8);
        raw.extend_from_slice(payload);
    }

    // Base32 encode
    let encoded = base32_encode(&raw);

    // Split into labels, respecting QNAME limits
    let domain_labels: Vec<&str> = domain.split('.').filter(|s| !s.is_empty()).collect();
    // Domain part of QNAME: sum of (1+label_len) for each label + 1 for root
    let domain_qname_len: usize = domain_labels.iter().map(|l| 1 + l.len()).sum::<usize>() + 1;
    let max_data_qname = MAX_QNAME_LEN.saturating_sub(domain_qname_len);

    let mut labels: Vec<&[u8]> = Vec::new();
    let mut pos = 0;
    let mut total_label_bytes = 0;
    while pos < encoded.len() {
        let remaining_space = max_data_qname.saturating_sub(total_label_bytes);
        if remaining_space < 2 {
            break; // Need at least 1 byte label + 1 length byte
        }
        let max_this = (remaining_space - 1).min(MAX_LABEL_LEN);
        let end = (pos + max_this).min(encoded.len());
        let label = &encoded[pos..end];
        total_label_bytes += 1 + label.len();
        labels.push(label);
        pos = end;
    }

    // Build QNAME wire format
    let mut qname = Vec::new();
    for label in &labels {
        qname.push(label.len() as u8);
        qname.extend_from_slice(label);
    }
    for dl in &domain_labels {
        qname.push(dl.len() as u8);
        qname.extend_from_slice(dl.as_bytes());
    }
    qname.push(0); // root label

    // Build DNS message
    let txid: u16 = rng.gen();
    let mut msg = Vec::with_capacity(DNS_HEADER_LEN + qname.len() + 4 + EDNS0_OPT.len());

    // Header: ID, flags (RD=1, AD=1), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=1 (EDNS)
    // Chrome sets both RD and AD bits in all queries since ~2020
    msg.extend_from_slice(&txid.to_be_bytes());
    msg.extend_from_slice(&[0x01, 0x20]); // flags: RD=1, AD=1 (matches Chrome)
    msg.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    msg.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
    msg.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    msg.extend_from_slice(&[0x00, 0x01]); // ARCOUNT=1 (EDNS OPT)

    // Question section
    msg.extend_from_slice(&qname);
    msg.extend_from_slice(&qtype.to_be_bytes()); // QTYPE (configurable: TXT=16, NULL=10, A=1, ...)
    msg.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

    // Additional section: EDNS(0) OPT
    msg.extend_from_slice(&EDNS0_OPT);

    msg
}

/// Decode a DNS response, extract downstream packets from RDATA.
///
/// Supports all tunnel record types:
///   - TXT: concatenate character-strings
///   - NULL: raw bytes
///   - A/AAAA: concatenate RR data, strip 2-byte length header
///   - CNAME/NS: decode base32 from domain name labels
///   - MX: skip 2-byte preference, decode base32 from domain name labels
///   - SRV: skip 6-byte header, decode base32 from domain name labels
///
/// For name-based types (CNAME/MX/NS/SRV) with multiple RRs, concatenate
/// all decoded data, then strip the 2-byte length header.
pub fn decode_response(wire: &[u8]) -> Option<Vec<Vec<u8>>> {
    if wire.len() < DNS_HEADER_LEN {
        return None;
    }

    // Header
    let flags = u16::from_be_bytes([wire[2], wire[3]]);
    let qr = (flags >> 15) & 1;
    let rcode = flags & 0x0f;
    if qr != 1 {
        return None; // Not a response
    }
    // Accept NOERROR (0) and NXDOMAIN (3) — server may use NXDOMAIN for data
    if rcode != 0 && rcode != 3 {
        return None;
    }

    let qdcount = u16::from_be_bytes([wire[4], wire[5]]) as usize;
    let ancount = u16::from_be_bytes([wire[6], wire[7]]) as usize;

    // Skip question section
    let mut pos = DNS_HEADER_LEN;
    for _ in 0..qdcount {
        pos = skip_name(wire, pos)?;
        pos += 4; // QTYPE + QCLASS
        if pos > wire.len() {
            return None;
        }
    }

    // Parse answer section — extract data from any supported record type.
    let mut raw_data: Vec<u8> = Vec::new();
    let mut answer_rtype: u16 = 0;

    for _ in 0..ancount {
        let name_end = skip_name(wire, pos)?;
        if name_end + 10 > wire.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([wire[name_end], wire[name_end + 1]]);
        let rdlength = u16::from_be_bytes([wire[name_end + 8], wire[name_end + 9]]) as usize;
        let rdata_start = name_end + 10;
        let rdata_end = rdata_start + rdlength;
        if rdata_end > wire.len() {
            return None;
        }

        if answer_rtype == 0 {
            answer_rtype = rtype;
        }

        match rtype {
            QTYPE_TXT => {
                // TXT: concatenate character-strings
                let mut rpos = rdata_start;
                while rpos < rdata_end {
                    let slen = wire[rpos] as usize;
                    rpos += 1;
                    if rpos + slen > rdata_end {
                        break;
                    }
                    raw_data.extend_from_slice(&wire[rpos..rpos + slen]);
                    rpos += slen;
                }
            }
            QTYPE_NULL => {
                // NULL: raw bytes, no framing
                raw_data.extend_from_slice(&wire[rdata_start..rdata_end]);
            }
            QTYPE_A => {
                // A: 4 bytes per record, concatenate all
                raw_data.extend_from_slice(&wire[rdata_start..rdata_end]);
            }
            QTYPE_AAAA => {
                // AAAA: 16 bytes per record, concatenate all
                raw_data.extend_from_slice(&wire[rdata_start..rdata_end]);
            }
            QTYPE_CNAME | QTYPE_NS => {
                // CNAME/NS: payload encoded as base32 in domain name labels.
                // RDATA is a DNS name: [len][label]...[0x00]
                if let Some(decoded) = decode_name_labels_base32(wire, rdata_start, rdata_end) {
                    raw_data.extend_from_slice(&decoded);
                }
            }
            QTYPE_MX => {
                // MX: 2-byte preference + DNS name with base32 labels.
                if rdlength > 2 {
                    let name_start = rdata_start + 2; // skip preference
                    if let Some(decoded) = decode_name_labels_base32(wire, name_start, rdata_end) {
                        raw_data.extend_from_slice(&decoded);
                    }
                }
            }
            QTYPE_SRV => {
                // SRV: 6-byte header (priority + weight + port) + DNS name.
                if rdlength > 6 {
                    let name_start = rdata_start + 6; // skip header
                    if let Some(decoded) = decode_name_labels_base32(wire, name_start, rdata_end) {
                        raw_data.extend_from_slice(&decoded);
                    }
                }
            }
            _ => {
                // Unknown type — skip
            }
        }

        pos = rdata_end;
    }

    if raw_data.is_empty() {
        return Some(Vec::new());
    }

    // For types that use a 2-byte length header to strip padding:
    // A, AAAA, CNAME, MX, NS, SRV (all multi-RR types).
    let payload_data = match answer_rtype {
        QTYPE_A | QTYPE_AAAA | QTYPE_CNAME | QTYPE_MX | QTYPE_NS | QTYPE_SRV => {
            if raw_data.len() < 2 {
                return Some(Vec::new());
            }
            let total_len = u16::from_be_bytes([raw_data[0], raw_data[1]]) as usize;
            let start = 2;
            let end = (start + total_len).min(raw_data.len());
            raw_data[start..end].to_vec()
        }
        _ => raw_data,
    };

    // Split data by 2-byte BE length prefixes → packets
    let mut packets = Vec::new();
    let mut i = 0;
    while i + 2 <= payload_data.len() {
        let pkt_len = u16::from_be_bytes([payload_data[i], payload_data[i + 1]]) as usize;
        i += 2;
        if i + pkt_len > payload_data.len() {
            break;
        }
        packets.push(payload_data[i..i + pkt_len].to_vec());
        i += pkt_len;
    }

    Some(packets)
}

/// Decode base32-encoded payload from DNS name labels in RDATA.
/// Reads labels from `start` up to `end` in the wire buffer.
/// Stops at root label (0x00) or the single-char TLD used as terminator.
/// Handles compression pointers (0xc0xx) that may appear in name-based RDATA.
fn decode_name_labels_base32(wire: &[u8], start: usize, end: usize) -> Option<Vec<u8>> {
    let mut encoded = Vec::new();
    let mut pos = start;

    loop {
        if pos >= end {
            break;
        }
        let len = wire[pos] as usize;
        if len == 0 {
            break; // root label
        }
        if len & 0xc0 == 0xc0 {
            // Compression pointer — follow it (within wire bounds, not rdata bounds)
            if pos + 1 >= wire.len() {
                break;
            }
            let ptr = ((len & 0x3f) << 8 | wire[pos + 1] as usize) as usize;
            // Follow pointer and collect remaining labels
            if let Some(rest) = decode_name_labels_base32(wire, ptr, wire.len()) {
                // But don't include the TLD marker that the recursive call might pick up
                encoded.extend_from_slice(&rest);
            }
            break;
        }
        pos += 1;
        if pos + len > end {
            break;
        }
        let label = &wire[pos..pos + len];
        // Skip single-char TLD terminator (server appends ".x." or similar)
        if len == 1 {
            pos += len;
            continue;
        }
        encoded.extend_from_slice(label);
        pos += len;
    }

    if encoded.is_empty() {
        return Some(Vec::new());
    }

    base32_decode(&encoded)
}

/// Skip a DNS name at `pos` in `wire` (handles compression pointers).
/// Returns the position just past the name.
fn skip_name(wire: &[u8], mut pos: usize) -> Option<usize> {
    let mut jumped = false;
    let mut end_pos = 0;
    loop {
        if pos >= wire.len() {
            return None;
        }
        let len = wire[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            // Compression pointer
            if !jumped {
                end_pos = pos + 2;
            }
            if pos + 1 >= wire.len() {
                return None;
            }
            pos = ((len & 0x3f) << 8 | wire[pos + 1] as usize) as usize;
            jumped = true;
            continue;
        }
        pos += 1 + len;
    }
    Some(if jumped { end_pos } else { pos })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base32_encode() {
        // RFC 4648 test vectors
        assert_eq!(base32_encode(b""), b"");
        assert_eq!(base32_encode(b"f"), b"my");
        assert_eq!(base32_encode(b"fo"), b"mzxq");
        assert_eq!(base32_encode(b"foo"), b"mzxw6");
        assert_eq!(base32_encode(b"foob"), b"mzxw6yq");
        assert_eq!(base32_encode(b"fooba"), b"mzxw6ytb");
        assert_eq!(base32_encode(b"foobar"), b"mzxw6ytboi");
    }

    #[test]
    fn test_base32_roundtrip() {
        let data = b"hello world 1234567890";
        let encoded = base32_encode(data);
        let decoded = base32_decode(&encoded).unwrap();
        assert_eq!(&decoded[..data.len()], data);
    }

    #[test]
    fn test_encode_query_basic() {
        let client_id = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let msg = encode_query(&client_id, &[], "t.cdn.example.com", true);
        // Should be valid DNS: starts with 2-byte txid, flags, counts
        assert!(msg.len() > DNS_HEADER_LEN);
        // QDCOUNT=1
        assert_eq!(msg[4], 0);
        assert_eq!(msg[5], 1);
        // ARCOUNT=1 (EDNS)
        assert_eq!(msg[10], 0);
        assert_eq!(msg[11], 1);
    }

    #[test]
    fn test_encode_query_typed_a() {
        let client_id = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let msg = encode_query_typed(&client_id, &[], "cdn.example.com", true, QTYPE_A);
        assert!(msg.len() > DNS_HEADER_LEN);
        // Find QTYPE in the question section — after QNAME, 2 bytes
        // Skip header (12) + QNAME to find qtype bytes
        let mut pos = DNS_HEADER_LEN;
        loop {
            let len = msg[pos] as usize;
            if len == 0 { pos += 1; break; }
            pos += 1 + len;
        }
        let qt = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        assert_eq!(qt, QTYPE_A);
    }

    #[test]
    fn test_decode_empty_response() {
        // Minimal valid response with no answers
        let msg = [
            0x00, 0x01, // ID
            0x81, 0x00, // flags: QR=1, RD=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
            // Question: \x04test\x03com\x00
            0x04, b't', b'e', b's', b't',
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x10, // QTYPE=TXT
            0x00, 0x01, // QCLASS=IN
        ];
        let packets = decode_response(&msg).unwrap();
        assert!(packets.is_empty());
    }

    #[test]
    fn test_parse_qtype() {
        assert_eq!(parse_qtype("A"), Some(QTYPE_A));
        assert_eq!(parse_qtype("txt"), Some(QTYPE_TXT));
        assert_eq!(parse_qtype("MX"), Some(QTYPE_MX));
        assert_eq!(parse_qtype("cname"), Some(QTYPE_CNAME));
        assert_eq!(parse_qtype("AAAA"), Some(QTYPE_AAAA));
        assert_eq!(parse_qtype("NS"), Some(QTYPE_NS));
        assert_eq!(parse_qtype("srv"), Some(QTYPE_SRV));
        assert_eq!(parse_qtype("bogus"), None);
    }
}
