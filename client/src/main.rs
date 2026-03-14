use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

mod chrome_cover;
mod config;
mod dns_codec;
mod tunnel;
mod ui;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const CACHE_FILE: &str = ".nooshdaroo-cache.json";

#[derive(Parser)]
#[command(
    name = "nooshdaroo",
    version = VERSION,
    about = "Nooshdaroo — Censorship-resistant SOCKS5 proxy over DNS tunneling. One binary.",
    long_about = None,
    after_help = "EXAMPLES:\n  \
        nooshdaroo --domain t.example.com --pubkey <hex>   Connect to your server\n  \
        nooshdaroo --config config.json                    Use a config file\n  \
        nooshdaroo -p 9050                                 Listen on port 9050\n  \
        nooshdaroo --scan-resolvers                        Find working DNS resolvers\n  \
        nooshdaroo --resolver 8.8.8.8                      Use Google DNS as resolver\n  \
        nooshdaroo --tunnels 4                             Open 4 parallel tunnels\n\n\
        BROWSER SETUP:\n  \
        Firefox:  Settings > Network > Manual Proxy > SOCKS Host: 127.0.0.1  Port: 1080\n  \
        Chrome:   chrome --proxy-server=\"socks5://127.0.0.1:1080\"\n  \
        curl:     curl --proxy socks5h://127.0.0.1:1080 https://example.com"
)]
struct Args {
    /// SOCKS5 listen port
    #[arg(short, long, default_value = "1080", value_name = "PORT")]
    port: u16,

    /// SOCKS5 listen address
    #[arg(short = 'b', long, default_value = "127.0.0.1", value_name = "ADDR")]
    bind: String,

    /// JSON config file path
    #[arg(short, long, value_name = "PATH")]
    config: Option<String>,

    /// Force a specific DNSTT domain
    #[arg(long, value_name = "DOMAIN")]
    domain: Option<String>,

    /// Force a specific DNS resolver
    #[arg(long, value_name = "IP")]
    resolver: Option<String>,

    /// Number of parallel tunnels (default: 2)
    #[arg(long, default_value = "2", value_name = "N")]
    tunnels: usize,

    /// Scan for working DNS resolvers before connecting
    #[arg(long)]
    scan_resolvers: bool,

    /// Fetch fresh config from OTA before connecting
    #[arg(long)]
    ota_refresh: bool,

    /// Verbose output (show debug logs)
    #[arg(short, long)]
    verbose: bool,

    /// Suppress banner and decorative output
    #[arg(short, long)]
    quiet: bool,

    /// Show configuration and exit
    #[arg(long)]
    show_config: bool,

    /// Disable Chrome DNS cover traffic (not recommended — makes tunnel easier to fingerprint)
    #[arg(long)]
    no_cover: bool,

    /// Server public key (hex, 32 bytes) — overrides config file
    #[arg(long, value_name = "HEX")]
    pubkey: Option<String>,

    /// OTA config domain — fetch dynamic server/resolver updates from this DNS TXT record
    #[arg(long, value_name = "DOMAIN")]
    ota_domain: Option<String>,

    /// OTA decryption nonce (12 ascii chars) — for ChaCha20-Poly1305
    #[arg(long, value_name = "NONCE")]
    ota_nonce: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Setup logging
    let log_level = if args.verbose { "debug" } else { "warn" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .format_timestamp_secs()
        .init();

    // Ctrl+C handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        eprintln!("\n  Shutting down...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set Ctrl+C handler");

    // Print banner
    if !args.quiet {
        ui::print_banner();
    }

    // Load config from file (or empty if no --config)
    let mut cfg = config::load_config(args.config.as_deref());

    // Build OTA overrides from CLI args
    let ota_overrides = config::OtaOverrides {
        domain: args.ota_domain.clone(),
        nonce: args.ota_nonce.clone(),
    };

    // OTA refresh — fetches latest domains, resolvers, and cover domains
    if args.ota_refresh {
        if ota_overrides.domain.is_none() || ota_overrides.nonce.is_none() {
            ui::print_error("--ota-refresh requires both --ota-domain and --ota-nonce");
            std::process::exit(1);
        }
        if !args.quiet {
            ui::print_status("OTA", "Fetching fresh config...");
        }
        match config::fetch_ota_config(&ota_overrides, &cfg).await {
            Ok(ota_cfg) => {
                cfg = ota_cfg;
                if !args.quiet {
                    ui::print_status("OTA", &format!(
                        "Updated: {} domains, {} resolvers",
                        cfg.dnstt_domains().len(),
                        cfg.dnstt_resolvers().len()
                    ));
                }
            }
            Err(e) => {
                if !args.quiet {
                    ui::print_dim(&format!("OTA fetch failed (using base config): {}", e));
                }
            }
        }
    }

    // Show config and exit
    if args.show_config {
        ui::print_config_info(&cfg);
        return;
    }

    // Build domain list
    let all_domains = cfg.dnstt_domains();

    // If --domain is specified, use that; otherwise use config file domains
    let domains = if let Some(ref d) = args.domain {
        let pk = args.pubkey.clone()
            .or_else(|| cfg.pubkey_for_domain(d))
            .unwrap_or_else(|| {
                ui::print_error("No pubkey for domain. Use --pubkey <hex> or add it to the config file.");
                std::process::exit(1);
            });
        vec![(d.clone(), pk)]
    } else if !all_domains.is_empty() {
        // DNS flux: select a subset of domains for this time period
        let flux_seed = b"nooshdaroo-flux-v2";
        let count = args.tunnels.max(4).min(all_domains.len());
        tunnel::dns_flux_select(&all_domains, count, flux_seed)
    } else {
        ui::print_error("No DNSTT domains configured.");
        ui::print_hint("Use --domain <domain> --pubkey <hex> or --config <file>");
        std::process::exit(1);
    };

    // Build resolver list
    let resolvers = if let Some(ref r) = args.resolver {
        vec![r.clone()]
    } else if args.scan_resolvers {
        if !args.quiet {
            ui::print_status("Scan", "Searching for working resolvers...");
        }

        // Combine config resolvers + well-known open resolvers (deduplicated)
        let mut candidates: Vec<String> = cfg.dnstt_resolvers();
        for &r in config::WELL_KNOWN_RESOLVERS {
            let s = r.to_string();
            if !candidates.contains(&s) { candidates.push(s); }
        }

        let probe_domain = domains.first()
            .map(|(d, _)| d.as_str())
            .unwrap_or("t.example.com");

        let results = tunnel::scan_resolvers(&candidates, probe_domain, 4000).await;

        if results.is_empty() {
            ui::print_error("No working resolvers found.");
            ui::print_hint("Your network may be blocking DNS to the server.");
            ui::print_hint("Try a different network or use --resolver <IP> manually.");
            std::process::exit(1);
        }

        if !args.quiet {
            ui::print_status("Scan", &format!(
                "{}/{} resolvers can reach the server", results.len(), candidates.len()
            ));
            for (ip, ms) in results.iter().take(5) {
                ui::print_dim(&format!("  {} ({}ms)", ip, ms));
            }
        }

        // Cache successful resolvers for next run
        let working: Vec<String> = results.iter().map(|(ip, _)| ip.clone()).collect();
        save_resolver_cache(&working);

        working
    } else {
        // Default: try cached resolvers first, then pick from config
        let cached = load_resolver_cache();
        if !cached.is_empty() {
            if !args.quiet {
                ui::print_dim(&format!("  Using {} cached resolvers from last scan", cached.len()));
            }
            cached
        } else {
            let all_resolvers = cfg.dnstt_resolvers();
            if all_resolvers.is_empty() {
                // Fall back to Google DNS if nothing else configured
                vec!["8.8.8.8".to_string()]
            } else {
                all_resolvers.into_iter().take(5).collect()
            }
        }
    };

    // Get OTA-pushed cover domains
    let ota_cover_domains = cfg.cover_domains();

    if !args.quiet {
        ui::print_status("Transport", "DNSTT (native Rust)");
        ui::print_status("Tunnels", &format!("{} parallel", args.tunnels));
        ui::print_status("Resolvers", &format!("{} available", resolvers.len()));
        ui::print_status("Domains", &format!("{} selected (DNS flux)", domains.len()));
        if !args.no_cover {
            if ota_cover_domains.is_empty() {
                ui::print_status("Cover", "Chrome DNS mimicry (hardcoded domains)");
            } else {
                ui::print_status("Cover", &format!(
                    "Chrome DNS mimicry ({} OTA domains)", ota_cover_domains.len()
                ));
            }
        }
        eprintln!();
    }

    // Start Chrome cover traffic BEFORE tunnel — so cover queries are already
    // flowing when tunnel queries begin (looks like Chrome was already running)
    if !args.no_cover {
        let cover_resolver: std::net::SocketAddr = {
            let r = &resolvers[0];
            let r = if r.contains(':') { r.clone() } else { format!("{}:53", r) };
            r.parse().unwrap_or_else(|_| "8.8.8.8:53".parse().unwrap())
        };
        let cover_running = running.clone();
        let cover_cfg = chrome_cover::CoverConfig {
            ota_domains: ota_cover_domains,
            ..chrome_cover::CoverConfig::default()
        };
        tokio::spawn(async move {
            chrome_cover::start_cover_traffic(
                cover_resolver,
                cover_cfg,
                cover_running,
            ).await;
        });
    }

    // Create status channel for UI updates
    let (status_tx, mut status_rx) = tokio::sync::mpsc::unbounded_channel();

    // Spawn UI update task
    let quiet = args.quiet;
    let ui_running = running.clone();
    let port_for_hint = args.port;
    tokio::spawn(async move {
        let mut first_domain: Option<String> = None;
        let mut first_resolver: Option<String> = None;

        while let Some(status) = status_rx.recv().await {
            if !ui_running.load(Ordering::Relaxed) { break; }
            if quiet { continue; }
            match status {
                tunnel::TunnelStatus::Connecting(domain, resolver) => {
                    ui::print_connecting(&domain, &resolver);
                }
                tunnel::TunnelStatus::Connected(domain, resolver) => {
                    ui::print_dim(&format!("  Connected: {} via {}", domain, resolver));
                    if first_domain.is_none() {
                        first_domain = Some(domain.clone());
                        // Strip :53 port suffix for cleaner hint
                        first_resolver = Some(
                            resolver.split(':').next().unwrap_or(&resolver).to_string()
                        );
                    }
                }
                tunnel::TunnelStatus::Failed(domain, err) => {
                    ui::print_dim(&format!("  Failed: {} ({})", domain, err));
                }
                tunnel::TunnelStatus::Ready(port) => {
                    ui::print_ready(&format!("127.0.0.1:{}", port));

                    // Print shortcut command for next time
                    if let (Some(ref d), Some(ref r)) = (&first_domain, &first_resolver) {
                        eprintln!();
                        ui::print_dim("  Next time, reconnect faster with:");
                        let mut cmd = format!("  nooshdaroo --domain {} --resolver {}", d, r);
                        if port_for_hint != 1080 {
                            cmd.push_str(&format!(" -p {}", port_for_hint));
                        }
                        ui::print_hint(&cmd);
                    }
                }
            }
        }
    });

    // Start tunnel pool
    match tunnel::start(
        domains,
        resolvers,
        args.port,
        args.tunnels,
        running.clone(),
        Some(status_tx),
    ).await {
        Ok(()) => {}
        Err(e) => {
            ui::print_error(&format!("Tunnel failed: {}", e));
            ui::print_hint("Try: nooshdaroo --scan-resolvers");
            ui::print_hint("Or:  nooshdaroo --resolver 8.8.8.8");
            std::process::exit(1);
        }
    }

    if !args.quiet {
        eprintln!();
        ui::print_dim("Session ended. Stay safe.");
    }
}

/// Save working resolvers to disk for next run.
fn save_resolver_cache(resolvers: &[String]) {
    let cache_path = cache_file_path();
    let json = serde_json::json!({
        "resolvers": resolvers,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    if let Ok(data) = serde_json::to_string_pretty(&json) {
        let _ = std::fs::write(&cache_path, data);
        log::debug!("Saved {} resolvers to {}", resolvers.len(), cache_path);
    }
}

/// Load cached resolvers (max 24h old).
fn load_resolver_cache() -> Vec<String> {
    let cache_path = cache_file_path();
    let data = match std::fs::read_to_string(&cache_path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let json: serde_json::Value = match serde_json::from_str(&data) {
        Ok(j) => j,
        Err(_) => return Vec::new(),
    };

    // Check age — expire after 24 hours
    if let Some(ts) = json["timestamp"].as_str() {
        if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(ts) {
            let age = chrono::Utc::now().signed_duration_since(parsed);
            if age.num_hours() > 24 {
                log::debug!("Resolver cache expired ({}h old)", age.num_hours());
                return Vec::new();
            }
        }
    }

    json["resolvers"].as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default()
}

fn cache_file_path() -> String {
    // Try XDG config dir, fall back to current directory
    if let Ok(home) = std::env::var("HOME") {
        let dir = format!("{}/.config/nooshdaroo", home);
        let _ = std::fs::create_dir_all(&dir);
        format!("{}/{}", dir, CACHE_FILE)
    } else {
        CACHE_FILE.to_string()
    }
}
