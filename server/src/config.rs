//! JSON config file format — matches Go's serverConfig exactly.

use serde::Deserialize;

/// JSON config file format, compatible with Go dnstt-server's -config.
///
/// Example:
/// ```json
/// {
///   "server_id": "my-server",
///   "listen": "0.0.0.0:53",
///   "privkey": "<hex-encoded-32-byte-private-key>",
///   "upstream": "socks5",
///   "domains": ["t.example.com"],
///   "reuseport": false
/// }
/// ```
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default)]
    pub server_id: String,

    #[serde(default = "default_listen")]
    pub listen: String,

    pub privkey: String,

    /// Additional private keys for multi-key support.
    /// Server tries each key on Noise handshake, uses first that succeeds.
    #[serde(default)]
    pub extra_privkeys: Vec<String>,

    #[serde(default = "default_upstream")]
    pub upstream: String,

    pub domains: Vec<String>,

    #[serde(default)]
    pub max_streams: Option<usize>,

    #[serde(default)]
    pub max_stream_buffer_kb: Option<usize>,

    #[serde(default)]
    pub relay_buf_size: Option<usize>,

    #[serde(default)]
    pub idle_timeout_sec: Option<u64>,

    #[serde(default)]
    pub reuseport: bool,

    /// Additional listen addresses for multi-homed hosts.
    /// When set, creates one UDP socket per address. Responses go from the
    /// socket that received the query — fixes source IP mismatch on hosts
    /// with multiple NS IPs.
    #[serde(default)]
    pub listen_addrs: Option<Vec<String>>,

    /// LiteWeb: path to domain blocklist file (one domain per line).
    /// If set, ad/tracker domains are blocked at the SOCKS5 level with
    /// zero bandwidth cost. File is hot-reloaded every 60 seconds.
    #[serde(default)]
    pub blocklist_file: Option<String>,

    /// TCP DNS listen addresses (for DNS-over-TCP via Cloudflare Spectrum).
    /// When set, accepts DNS queries over TCP (2-byte length prefix per RFC 1035).
    #[serde(default)]
    pub tcp_listen_addrs: Option<Vec<String>>,

    /// Egress IPs for outbound SOCKS connections. When set, outbound TCP
    /// connections bind to these IPs in round-robin order. This distributes
    /// port usage across multiple IPs (each IP has ~64K ephemeral ports).
    /// If unset, the kernel picks the source IP (usually the primary).
    #[serde(default)]
    pub egress_ips: Option<Vec<String>>,
}

fn default_listen() -> String {
    "0.0.0.0:53".to_string()
}

fn default_upstream() -> String {
    "socks5".to_string()
}

impl ServerConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let data = std::fs::read_to_string(path)?;
        let cfg: ServerConfig = serde_json::from_str(&data)?;
        if cfg.domains.is_empty() {
            anyhow::bail!("config has no domains");
        }
        Ok(cfg)
    }
}
