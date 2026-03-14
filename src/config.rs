//! Configuration loader — embedded fallback config with DNSTT domains, resolvers, SushMode servers.
//!
//! The config is embedded at compile time from assets/default-config.json.
//! Future versions will add OTA config fetch from DNS TXT records.

use serde_json::Value;

/// Embedded default config (compiled into the binary)
const EMBEDDED_CONFIG: &str = include_str!("../assets/default-config.json");

/// Parsed configuration for the CLI
#[derive(Clone)]
pub struct Config {
    raw: Value,
}

/// A DNSTT domain + pubkey pair
pub type DnsttDomain = (String, String);

impl Config {
    fn from_json(raw: Value) -> Self {
        Config { raw }
    }

    /// All DNSTT domains with their pubkeys
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

    /// Look up the pubkey for a specific domain
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

    /// Default (EU) pubkey — used when a user-specified domain isn't in the config
    pub fn default_pubkey(&self) -> String {
        // First domain's pubkey, or hardcoded EU key
        self.dnstt_domains()
            .first()
            .map(|(_, pk)| pk.clone())
            .unwrap_or_else(|| {
                "5999f891e49ffe4e1e689feab2156a431b6ecc2a61c701ffb58683353b4e744f".to_string()
            })
    }

    /// All UDP resolvers (Spectrum anycast IPs first, then Iran resolvers, then global)
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

    /// Pick a resolver — prefer Spectrum anycast (172.65.x.x) first, then global, then Iran
    pub fn pick_resolver(&self) -> String {
        let all = self.dnstt_resolvers();
        if all.is_empty() {
            // Hardcoded fallback
            return "8.8.8.8".to_string();
        }

        // Prefer Spectrum anycast IPs (172.65.x.x) — they are Cloudflare and work globally
        let spectrum: Vec<&String> = all.iter().filter(|r| r.starts_with("172.65.")).collect();
        if !spectrum.is_empty() {
            let idx = rand::random::<usize>() % spectrum.len();
            return spectrum[idx].clone();
        }

        // Prefer global resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9) for non-Iran users
        let global: Vec<&String> = all
            .iter()
            .filter(|r| {
                r.as_str() == "8.8.8.8"
                    || r.as_str() == "1.1.1.1"
                    || r.as_str() == "9.9.9.9"
            })
            .collect();
        if !global.is_empty() {
            let idx = rand::random::<usize>() % global.len();
            return global[idx].clone();
        }

        // Fallback: any resolver
        let idx = rand::random::<usize>() % all.len();
        all[idx].clone()
    }

    /// Pick a resolver suitable for Iran (prefer Iran-local resolvers, then Spectrum)
    pub fn pick_iran_resolver(&self) -> String {
        let all = self.dnstt_resolvers();
        if all.is_empty() {
            return "178.22.122.100".to_string(); // Shecan DNS, common in Iran
        }

        // Iran resolvers: IPs that aren't 172.65.x, 8.8.8.8, 1.1.1.1, 9.9.9.9, 10.x
        let iran: Vec<&String> = all
            .iter()
            .filter(|r| {
                !r.starts_with("172.65.")
                    && !r.starts_with("10.")
                    && r.as_str() != "8.8.8.8"
                    && r.as_str() != "1.1.1.1"
                    && r.as_str() != "9.9.9.9"
            })
            .collect();
        if !iran.is_empty() {
            let idx = rand::random::<usize>() % iran.len();
            return iran[idx].clone();
        }

        self.pick_resolver()
    }

    /// SushMode server IPs
    pub fn sushmode_servers(&self) -> Vec<String> {
        let mut result = Vec::new();
        if let Some(servers) = self.raw["transport"]["sushmode"]["servers"].as_array() {
            for s in servers {
                if let Some(ip) = s.as_str() {
                    result.push(ip.to_string());
                }
            }
        }
        result
    }

    /// SushMode pubkey
    #[allow(dead_code)]
    pub fn sushmode_pubkey(&self) -> String {
        self.raw["transport"]["sushmode"]["pubkey"]
            .as_str()
            .unwrap_or("ef70c421b806340f0218973c0b6cfa464c30dc893350f179bf9ec5f303f2c461")
            .to_string()
    }

    /// SushMode port (default 53)
    #[allow(dead_code)]
    pub fn sushmode_port(&self) -> u16 {
        self.raw["transport"]["sushmode"]["ports"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.as_u64())
            .unwrap_or(53) as u16
    }
}

/// Load configuration: embedded config only (OTA fetch planned for v1.1)
pub fn load_config() -> Config {
    log::debug!("Loading embedded config...");

    let raw: Value = serde_json::from_str(EMBEDDED_CONFIG).unwrap_or_else(|e| {
        log::error!("Failed to parse embedded config: {}", e);
        std::process::exit(1);
    });

    let version = raw["version"].as_str().unwrap_or("unknown");
    log::info!("Config version: {}", version);

    Config::from_json(raw)
}
