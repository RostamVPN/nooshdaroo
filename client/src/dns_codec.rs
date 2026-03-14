//! Minimal DNS encoder/decoder for DNSTT wire compatibility.
//!
//! Encodes upstream data into DNS QNAME (base32 labels) and decodes
//! downstream TXT RDATA with 2-byte length-prefixed packets.
//! Wire-compatible with dnstt-server (Go and Rust implementations).

use rand::Rng;

// ─── Constants ───────────────────────────────────────────────────

/// Max bytes per DNS label (RFC 1035)
const MAX_LABEL_LEN: usize = 63;
/// Max total QNAME length including dots and root (RFC 1035)
const MAX_QNAME_LEN: usize = 253;
/// DNS header is always 12 bytes
const DNS_HEADER_LEN: usize = 12;
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

// ─── Public API ──────────────────────────────────────────────────

/// Encode upstream data into a DNS query wire format.
///
/// Format follows dnstt `dnsNameEncode`:
///   1. 8-byte client_id
///   2. Padding prefix: 0xe0+n, then n random bytes (3 for data, 8 for poll)
///   3. If data: 1-byte length + data bytes
///   4. Base32 encode the whole thing
///   5. Split into ≤63-byte labels, append domain labels
///   6. Build DNS query (TXT, Class IN, RD=1, EDNS(0))
pub fn encode_query(
    client_id: &[u8; 8],
    payload: &[u8],
    domain: &str,
    is_poll: bool,
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
    msg.extend_from_slice(&[0x00, 0x10]); // QTYPE=TXT (16)
    msg.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

    // Additional section: EDNS(0) OPT
    msg.extend_from_slice(&EDNS0_OPT);

    msg
}

/// Decode a DNS response, extract downstream packets from TXT RDATA.
///
/// dnstt `dnsResponsePayload`:
///   1. Parse header: verify QR=1, RCODE ∈ {0,3} (NOERROR/NXDOMAIN ok)
///   2. Skip question section
///   3. Find first TXT answer
///   4. Concatenate TXT character-strings
///   5. Split by 2-byte BE length prefixes → Vec of packets
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

    // Parse answer section — find TXT records
    let mut txt_data: Vec<u8> = Vec::new();
    for _ in 0..ancount {
        let name_end = skip_name(wire, pos)?;
        if name_end + 10 > wire.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([wire[name_end], wire[name_end + 1]]);
        // skip class(2) + ttl(4) = 6
        let rdlength = u16::from_be_bytes([wire[name_end + 8], wire[name_end + 9]]) as usize;
        let rdata_start = name_end + 10;
        let rdata_end = rdata_start + rdlength;
        if rdata_end > wire.len() {
            return None;
        }

        if rtype == 16 {
            // TXT: concatenate character-strings
            let mut rpos = rdata_start;
            while rpos < rdata_end {
                let slen = wire[rpos] as usize;
                rpos += 1;
                if rpos + slen > rdata_end {
                    break;
                }
                txt_data.extend_from_slice(&wire[rpos..rpos + slen]);
                rpos += slen;
            }
        }

        pos = rdata_end;
    }

    if txt_data.is_empty() {
        return Some(Vec::new());
    }

    // Split TXT data by 2-byte BE length prefixes → packets
    let mut packets = Vec::new();
    let mut i = 0;
    while i + 2 <= txt_data.len() {
        let pkt_len = u16::from_be_bytes([txt_data[i], txt_data[i + 1]]) as usize;
        i += 2;
        if i + pkt_len > txt_data.len() {
            break;
        }
        packets.push(txt_data[i..i + pkt_len].to_vec());
        i += pkt_len;
    }

    Some(packets)
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
}
