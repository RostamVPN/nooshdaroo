//! Configuration — loaded from JSON config file or CLI arguments.
//!
//! No secrets are compiled into the binary. Everything comes from:
//!   1. A JSON config file (--config path)
//!   2. CLI flags (--domain, --pubkey, --resolver)
//!   3. Optional OTA fetch from a DNS TXT record (--ota-domain, --ota-nonce)

use serde_json::Value;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

/// CLI overrides for OTA parameters (for operators running their own infra)
#[derive(Clone, Default)]
pub struct OtaOverrides {
    /// OTA DNS domain (e.g. "_cfg.example.com")
    pub domain: Option<String>,
    /// ChaCha20-Poly1305 nonce (12 ascii chars)
    pub nonce: Option<String>,
}

/// Parsed configuration
#[derive(Clone)]
pub struct Config {
    raw: Value,
}

pub type DnsttDomain = (String, String);

impl Config {
    /// Create an empty config (no domains, no resolvers).
    pub fn empty() -> Self {
        Config { raw: serde_json::json!({}) }
    }

    fn from_json(raw: Value) -> Self {
        Config { raw }
    }

    pub fn dnstt_domains(&self) -> Vec<DnsttDomain> {
        let mut result = Vec::new();
        if let Some(domains) = self.raw["transport"]["dnstt"]["domains"].as_array() {
            for entry in domains {
                if let (Some(domain), Some(pubkey)) =
                    (entry["domain"].as_str(), entry["pubkey"].as_str())
                {
                    result.push((domain.to_string(), pubkey.to_string()));
                }
            }
        }
        result
    }

    pub fn pubkey_for_domain(&self, domain: &str) -> Option<String> {
        if let Some(domains) = self.raw["transport"]["dnstt"]["domains"].as_array() {
            for entry in domains {
                if entry["domain"].as_str() == Some(domain) {
                    return entry["pubkey"].as_str().map(|s| s.to_string());
                }
            }
        }
        None
    }

    pub fn default_pubkey(&self) -> String {
        self.dnstt_domains()
            .first()
            .map(|(_, pk)| pk.clone())
            .unwrap_or_default()
    }

    pub fn dnstt_resolvers(&self) -> Vec<String> {
        let mut result = Vec::new();
        if let Some(resolvers) = self.raw["transport"]["dnstt"]["udp_resolvers"].as_array() {
            for r in resolvers {
                if let Some(s) = r.as_str() {
                    result.push(s.to_string());
                }
            }
        }
        result
    }

    pub fn pick_resolver(&self) -> String {
        let all = self.dnstt_resolvers();
        if all.is_empty() { return "8.8.8.8".to_string(); }
        all[rand::random::<usize>() % all.len()].clone()
    }

    /// Get OTA domain from config (e.g. embedded defaults).
    pub fn ota_domain(&self) -> Option<String> {
        self.raw["ota"]["domain"].as_str().map(|s| s.to_string())
    }

    /// Get OTA nonce from config (e.g. embedded defaults).
    pub fn ota_nonce(&self) -> Option<String> {
        self.raw["ota"]["nonce"].as_str().map(|s| s.to_string())
    }

    /// Get OTA-pushed cover domains for Chrome DNS mimicry.
    /// Falls back to empty if no OTA data (chrome_cover.rs has hardcoded fallbacks).
    pub fn cover_domains(&self) -> Vec<String> {
        let mut result = Vec::new();
        if let Some(domains) = self.raw["cover_domains"].as_array() {
            for d in domains {
                if let Some(s) = d.as_str() {
                    result.push(s.to_string());
                }
            }
        }
        result
    }
}

/// Well-known open DNS resolvers (global, public).
/// These are ADDITIONAL candidates for --scan-resolvers.
/// Operators should add their own resolvers via config file.
pub const WELL_KNOWN_RESOLVERS: &[&str] = &[
    // Google
    "8.8.8.8", "8.8.4.4",
    // Cloudflare
    "1.1.1.1", "1.0.0.1",
    // Quad9
    "9.9.9.9", "149.112.112.112",
    // OpenDNS
    "208.67.222.222", "208.67.220.220",
    // Verisign
    "64.6.64.6", "64.6.65.6",
    // CleanBrowsing
    "185.228.168.9",
    // Alternate DNS
    "76.76.19.19", "76.223.122.150",
    // AdGuard
    "94.140.14.14", "94.140.15.15",
];

/// Load configuration from a JSON file.
pub fn load_config_file(path: &str) -> Result<Config, String> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config file {}: {}", path, e))?;
    let raw: Value = serde_json::from_str(&data)
        .map_err(|e| format!("Failed to parse config file {}: {}", path, e))?;
    Ok(Config::from_json(raw))
}

/// Built-in default configuration.
/// This allows the binary to work out-of-the-box with zero arguments.
/// Operators deploying their own infrastructure should override with --config.
/// OTA updates will automatically refresh this with the latest server list.
const DEFAULT_CONFIG: &str = r#"{
  "transport": {
    "dnstt": {
      "domains": [
        { "domain": "t.cdn.cdn-relay-eu.com", "pubkey": "5999f891e49ffe4e1e689feab2156a431b6ecc2a61c701ffb58683353b4e744f" },
        { "domain": "t.cdn.cdn-proxy-edge.com", "pubkey": "5999f891e49ffe4e1e689feab2156a431b6ecc2a61c701ffb58683353b4e744f" },
        { "domain": "t.cdn.static-cdn-proxy.com", "pubkey": "5999f891e49ffe4e1e689feab2156a431b6ecc2a61c701ffb58683353b4e744f" },
        { "domain": "t.cdn.edge-cache-proxy.com", "pubkey": "5999f891e49ffe4e1e689feab2156a431b6ecc2a61c701ffb58683353b4e744f" },
        { "domain": "t.cdn.cdnproxy-eu.com", "pubkey": "5999f891e49ffe4e1e689feab2156a431b6ecc2a61c701ffb58683353b4e744f" },
        { "domain": "t.cdn.copper-fern-studio.com", "pubkey": "5999f891e49ffe4e1e689feab2156a431b6ecc2a61c701ffb58683353b4e744f" },
        { "domain": "t.cdn.silver-birch-labs.com", "pubkey": "5999f891e49ffe4e1e689feab2156a431b6ecc2a61c701ffb58683353b4e744f" },
        { "domain": "t.cdn.golden-maple-works.com", "pubkey": "5999f891e49ffe4e1e689feab2156a431b6ecc2a61c701ffb58683353b4e744f" },
        { "domain": "t.cdn.iron-pine-craft.com", "pubkey": "5999f891e49ffe4e1e689feab2156a431b6ecc2a61c701ffb58683353b4e744f" },
        { "domain": "t.cdn.bright-elm-studio.com", "pubkey": "5999f891e49ffe4e1e689feab2156a431b6ecc2a61c701ffb58683353b4e744f" }
      ],
      "udp_resolvers": [
        "8.8.8.8", "8.8.4.4",
        "1.1.1.1", "1.0.0.1",
        "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220"
      ]
    }
  },
  "ota": {
    "domain": "_cfg.nooshdaroo.cdn.cdncache-eu.net",
    "nonce": "rostam-dns-a"
  },
  "cover_domains": [
    "www.google.com", "www.youtube.com", "www.wikipedia.org",
    "www.instagram.com", "www.twitter.com"
  ]
}"#;

/// Load configuration: from file if provided, otherwise use built-in defaults.
pub fn load_config(path: Option<&str>) -> Config {
    match path {
        Some(p) => match load_config_file(p) {
            Ok(cfg) => cfg,
            Err(e) => {
                log::error!("{}", e);
                std::process::exit(1);
            }
        },
        None => {
            // Use embedded default config so the binary works with zero arguments
            let raw: Value = serde_json::from_str(DEFAULT_CONFIG)
                .expect("built-in config is valid JSON");
            Config::from_json(raw)
        }
    }
}

/// DoH resolvers for OTA fetch (public resolvers only)
const OTA_RESOLVERS: &[&str] = &["8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"];

/// Fetch OTA config update from DNS TXT records.
/// Requires explicit --ota-domain and --ota-nonce to be set.
/// Uses raw UDP DNS queries (not DoH) for minimal dependencies.
pub async fn fetch_ota_config(
    overrides: &OtaOverrides,
    base_config: &Config,
) -> Result<Config, String> {
    let ota_domain = overrides.domain.as_deref()
        .ok_or("OTA requires --ota-domain")?;
    let nonce = overrides.nonce.as_deref()
        .ok_or("OTA requires --ota-nonce")?;

    if nonce.len() != 12 {
        return Err(format!("OTA nonce must be 12 bytes, got {}", nonce.len()));
    }

    for resolver_str in OTA_RESOLVERS {
        let resolver: SocketAddr = resolver_str.parse()
            .map_err(|e| format!("bad resolver {}: {}", resolver_str, e))?;

        match fetch_txt_records(ota_domain, resolver).await {
            Ok(txt_records) if !txt_records.is_empty() => {
                match reassemble_config(&txt_records, nonce.as_bytes()) {
                    Ok(config_json) => {
                        // Merge OTA into base config
                        let mut base = base_config.raw.clone();
                        deep_merge(&mut base, &config_json);
                        return Ok(Config::from_json(base));
                    }
                    Err(e) => {
                        log::warn!("OTA parse from {} failed: {}", resolver_str, e);
                        continue;
                    }
                }
            }
            Ok(_) => {
                log::debug!("OTA: no TXT records from {}", resolver_str);
                continue;
            }
            Err(e) => {
                log::debug!("OTA fetch from {} failed: {}", resolver_str, e);
                continue;
            }
        }
    }
    Err("All OTA resolvers failed".into())
}

/// Send a raw DNS TXT query and collect all TXT record strings.
async fn fetch_txt_records(domain: &str, resolver: SocketAddr) -> Result<Vec<String>, String> {
    let sock = UdpSocket::bind("0.0.0.0:0").await
        .map_err(|e| format!("UDP bind: {}", e))?;

    // Build DNS query
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

    sock.send_to(&buf, resolver).await
        .map_err(|e| format!("send: {}", e))?;

    let mut resp = [0u8; 4096];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut resp))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| format!("recv: {}", e))?;

    parse_txt_response(&resp[..len])
}

/// Parse TXT records from a DNS response.
fn parse_txt_response(wire: &[u8]) -> Result<Vec<String>, String> {
    if wire.len() < 12 { return Err("short".into()); }
    let flags = u16::from_be_bytes([wire[2], wire[3]]);
    if (flags >> 15) & 1 != 1 { return Err("not response".into()); }
    let rcode = flags & 0x0f;
    if rcode != 0 && rcode != 3 { return Err(format!("rcode {}", rcode)); }

    let qdcount = u16::from_be_bytes([wire[4], wire[5]]) as usize;
    let ancount = u16::from_be_bytes([wire[6], wire[7]]) as usize;

    let mut pos = 12;
    // Skip questions
    for _ in 0..qdcount {
        pos = skip_dns_name(wire, pos)?;
        pos += 4;
    }

    let mut txt_strings = Vec::new();
    for _ in 0..ancount {
        let name_end = skip_dns_name(wire, pos)?;
        if name_end + 10 > wire.len() { break; }
        let rtype = u16::from_be_bytes([wire[name_end], wire[name_end + 1]]);
        let rdlength = u16::from_be_bytes([wire[name_end + 8], wire[name_end + 9]]) as usize;
        let rdata_start = name_end + 10;
        let rdata_end = rdata_start + rdlength;
        if rdata_end > wire.len() { break; }

        if rtype == 16 {
            let mut rpos = rdata_start;
            while rpos < rdata_end {
                let slen = wire[rpos] as usize;
                rpos += 1;
                if rpos + slen > rdata_end { break; }
                if let Ok(s) = std::str::from_utf8(&wire[rpos..rpos + slen]) {
                    txt_strings.push(s.to_string());
                }
                rpos += slen;
            }
        }
        pos = rdata_end;
    }

    Ok(txt_strings)
}

fn skip_dns_name(wire: &[u8], mut pos: usize) -> Result<usize, String> {
    let mut jumped = false;
    let mut end_pos = 0;
    loop {
        if pos >= wire.len() { return Err("truncated name".into()); }
        let len = wire[pos] as usize;
        if len == 0 { pos += 1; break; }
        if len & 0xc0 == 0xc0 {
            if !jumped { end_pos = pos + 2; }
            if pos + 1 >= wire.len() { return Err("truncated ptr".into()); }
            pos = ((len & 0x3f) << 8 | wire[pos + 1] as usize) as usize;
            jumped = true;
            continue;
        }
        pos += 1 + len;
    }
    Ok(if jumped { end_pos } else { pos })
}

/// Reassemble chunked OTA config from TXT records.
/// Format: "v=1 id=xxx chunks=N chunk=M key=<b64> d=<b64_data>"
fn reassemble_config(txt_records: &[String], nonce_bytes: &[u8]) -> Result<Value, String> {
    use std::collections::BTreeMap;

    struct Chunk {
        #[allow(dead_code)]
        chunk_num: usize,
        key_bytes: Vec<u8>,
        data_b64: String,
    }

    let mut chunks_map: BTreeMap<usize, Chunk> = BTreeMap::new();
    let mut total_chunks = 0usize;

    for txt in txt_records {
        let mut parts = BTreeMap::new();
        let pairs: Box<dyn Iterator<Item = &str>> = if txt.contains(';') && !txt.contains(' ') {
            Box::new(txt.split(';'))
        } else {
            Box::new(txt.split_whitespace())
        };

        for pair in pairs {
            if let Some(eq_pos) = pair.find('=') {
                let key = pair[..eq_pos].trim();
                let value = pair[eq_pos + 1..].trim();
                if !key.is_empty() && !value.is_empty() {
                    parts.insert(key.to_string(), value.to_string());
                }
            }
        }

        let version: u32 = parts.get("v")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if version != 1 { continue; }

        let tc: usize = parts.get("chunks")
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        if tc > 0 { total_chunks = tc; }

        let chunk_num: usize = parts.get("chunk")
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);

        let data_b64 = parts.get("d").cloned().unwrap_or_default();

        let key_bytes = if let Some(key_b64) = parts.get("key") {
            base64_decode(key_b64).unwrap_or_default()
        } else {
            Vec::new()
        };

        chunks_map.insert(chunk_num, Chunk { chunk_num, key_bytes, data_b64 });
    }

    if total_chunks == 0 || chunks_map.len() < total_chunks {
        return Err(format!("incomplete: {}/{} chunks", chunks_map.len(), total_chunks));
    }

    // Get encryption key from chunk 1
    let key = chunks_map.values()
        .find(|c| !c.key_bytes.is_empty())
        .map(|c| c.key_bytes.clone())
        .ok_or("no encryption key in chunks")?;

    if key.len() != 32 {
        return Err(format!("bad key length: {}", key.len()));
    }

    // Reassemble data
    let mut all_data = String::new();
    for i in 1..=total_chunks {
        if let Some(chunk) = chunks_map.get(&i) {
            all_data.push_str(&chunk.data_b64);
        }
    }

    let ciphertext = base64_decode(&all_data)
        .map_err(|e| format!("base64 decode: {}", e))?;

    // Decrypt with ChaCha20-Poly1305
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
    use chacha20poly1305::aead::generic_array::GenericArray;

    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key));
    if nonce_bytes.len() != 12 {
        return Err(format!("nonce must be 12 bytes, got {}", nonce_bytes.len()));
    }
    let nonce = GenericArray::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "decryption failed")?;

    let json_str = String::from_utf8(plaintext)
        .map_err(|e| format!("utf8: {}", e))?;

    serde_json::from_str(&json_str)
        .map_err(|e| format!("json: {}", e))
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    use base64::engine::general_purpose;
    use base64::Engine;
    general_purpose::STANDARD.decode(input)
        .map_err(|e| format!("{}", e))
}

/// Deep merge OTA config into base config.
fn deep_merge(base: &mut Value, overlay: &Value) {
    match (base, overlay) {
        (Value::Object(base_map), Value::Object(overlay_map)) => {
            for (key, val) in overlay_map {
                deep_merge(base_map.entry(key.clone()).or_insert(Value::Null), val);
            }
        }
        (base, overlay) => {
            *base = overlay.clone();
        }
    }
}
