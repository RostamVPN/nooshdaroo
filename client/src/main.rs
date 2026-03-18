use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

mod chrome_cover;
mod config;
mod dns_codec;
mod doh;
mod iran_ranges;
mod russia_ranges;
mod spirit;
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
        nooshdaroo --tunnels 4                             Open 4 parallel tunnels\n  \
        nooshdaroo --list-isps                             Show all known ISPs\n  \
        nooshdaroo --scan-isp MCI                          Scan only MCI ranges\n  \
        nooshdaroo --scan-isp AS44244                      Scan by ASN number\n\n\
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

    /// Scan Iran IP ranges for working resolvers (auto-detects your ISP)
    #[arg(long)]
    scan_iran: bool,

    /// Scan Russia IP ranges for working resolvers (auto-detects your ISP)
    #[arg(long)]
    scan_russia: bool,

    /// Limit scan to a specific CIDR (e.g. "5.160.100.0/24" or "5.160.0.0/16")
    #[arg(long, value_name = "CIDR")]
    scan_cidr: Option<String>,

    /// List all known ISPs with ASN numbers and IP ranges, then exit
    #[arg(long)]
    list_isps: bool,

    /// Scan only a specific ISP's ranges (by name or ASN, e.g. "MCI" or "197207" or "AS44244")
    #[arg(long, value_name = "ISP")]
    scan_isp: Option<String>,

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

    /// Use DNS-over-HTTPS instead of raw UDP (harder to detect, slightly slower)
    #[arg(long)]
    doh: bool,

    /// DoH provider: "google", "cloudflare", "quad9", or a custom URL
    #[arg(long, value_name = "PROVIDER")]
    doh_provider: Option<String>,

    /// DNS record type for tunnel queries: auto, A, AAAA, CNAME, MX, TXT, NS, SRV.
    /// Default "auto" probes at startup to find what the censor allows.
    /// Iran (Mar 2026): TXT is blocked, auto-detects and uses A records.
    #[arg(long, default_value = "auto", value_name = "TYPE")]
    qtype: String,
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

    // --list-isps: show all ISP groups and exit
    if args.list_isps {
        print_isp_table();
        return;
    }

    // Load config from file (or empty if no --config)
    let mut cfg = config::load_config(args.config.as_deref());

    // Build OTA overrides: CLI args take priority, then config file / embedded defaults
    let ota_overrides = config::OtaOverrides {
        domain: args.ota_domain.clone().or_else(|| cfg.ota_domain()),
        nonce: args.ota_nonce.clone().or_else(|| cfg.ota_nonce()),
    };

    // OTA refresh — fetches latest domains, resolvers, and cover domains
    // Auto-refresh if OTA is configured (embedded or file) unless explicitly skipped
    let should_ota = args.ota_refresh || (ota_overrides.domain.is_some() && ota_overrides.nonce.is_some());
    if should_ota {
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
        ui::print_error("No tunnel domains configured.");
        ui::print_hint("Run with no arguments to use built-in servers, or use --config <file>");
        std::process::exit(1);
    };

    // Build resolver list
    let resolvers = if let Some(ref r) = args.resolver {
        vec![r.clone()]
    } else if args.scan_isp.is_some() || args.scan_iran || args.scan_russia || args.scan_cidr.is_some() {
        // Country-specific resolver scan: blazing fast adaptive single-socket scanner
        let probe_domain = domains.first()
            .map(|(d, _)| d.as_str())
            .unwrap_or("t.example.com");

        let country = if args.scan_russia { "Russia" } else { "Iran" };

        let candidates: Vec<std::net::Ipv4Addr> = if let Some(ref isp_query) = args.scan_isp {
            // --scan-isp: targeted ISP scan
            // Try Iran ISPs first, then Russia
            let (isp_name, isp_asn, cands) =
                if let Some(group) = iran_ranges::find_isp_by_name_or_asn(isp_query) {
                    let c = iran_ranges::generate_isp_candidates(group, 10000);
                    (group.name, group.asn, c)
                } else if let Some(group) = russia_ranges::find_isp_by_name_or_asn(isp_query) {
                    let c = russia_ranges::generate_isp_candidates(group, 10000);
                    (group.name, group.asn, c)
                } else {
                    ui::print_error(&format!("Unknown ISP: \"{}\"", isp_query));
                    ui::print_hint("Use --list-isps to see available ISPs");
                    std::process::exit(1);
                };
            if !args.quiet {
                ui::print_status("ISP", &format!("{} (AS{})", isp_name, isp_asn));
                ui::print_dim(&format!("  {} scan candidates generated", cands.len()));
            }
            cands
        } else if let Some(ref cidr_str) = args.scan_cidr {
            if !args.quiet {
                ui::print_status("Scan", &format!("Scanning {} for resolvers...", cidr_str));
            }
            parse_cidr_candidates(cidr_str, 65536)
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect()
        } else {
            let local_ip = iran_ranges::detect_local_ip();
            if !args.quiet {
                if let Some(ip) = local_ip {
                    if args.scan_russia {
                        let isp_name = russia_ranges::find_isp(ip)
                            .map(|g| g.name)
                            .unwrap_or("Unknown ISP");
                        ui::print_status("Detected", &format!("{} ({})", ip, isp_name));
                        print_isp_breakdown_russia();
                    } else {
                        let isp_name = iran_ranges::find_isp(ip)
                            .map(|g| g.name)
                            .unwrap_or("Unknown ISP");
                        ui::print_status("Detected", &format!("{} ({})", ip, isp_name));
                        if iran_ranges::is_iran_ip(ip) {
                            print_isp_breakdown_iran();
                        }
                    }
                } else {
                    ui::print_status("Scan", &format!(
                        "Could not detect local IP, scanning all {} ranges", country
                    ));
                    if args.scan_russia {
                        print_isp_breakdown_russia();
                    } else {
                        print_isp_breakdown_iran();
                    }
                }
                ui::print_hint("  Tip: scan a specific ISP with --scan-isp <name|ASN>");
            }
            if args.scan_russia {
                russia_ranges::generate_scan_candidates(local_ip, 10000)
            } else {
                iran_ranges::generate_scan_candidates(local_ip, 10000)
            }
        };

        if !args.quiet {
            ui::print_status("Scan", &format!(
                "Probing {} seed candidates (adaptive single-socket scanner)...",
                candidates.len()
            ));
        }

        let quiet_for_cb = args.quiet;
        let progress: Option<Box<dyn Fn(&str) + Send>> = if !quiet_for_cb {
            Some(Box::new(move |msg: &str| {
                ui::print_dim(&format!("  {}", msg));
            }))
        } else {
            None
        };

        let results = iran_ranges::scan_adaptive(
            &candidates,
            Some(probe_domain),
            progress,
        ).await;

        if results.is_empty() {
            ui::print_error("No working resolvers found in scan range.");
            ui::print_hint("Try a larger range: --scan-cidr 5.160.0.0/16");
            ui::print_hint("Or specify a resolver manually: --resolver <IP>");
            std::process::exit(1);
        }

        // Show results: tunnel-capable first, then generic resolvers
        let tunnel_capable: Vec<_> = results.iter().filter(|r| r.is_tunnel_capable).collect();
        let generic: Vec<_> = results.iter().filter(|r| !r.is_tunnel_capable).collect();

        if !args.quiet {
            ui::print_status("Found", &format!(
                "{} resolvers ({} tunnel-capable) from {} scanned",
                results.len(), tunnel_capable.len(), candidates.len()
            ));
            for r in tunnel_capable.iter().take(5) {
                ui::print_dim(&format!("  {} ({}ms) ★ tunnel verified", r.ip, r.latency_ms));
            }
            for r in generic.iter().take(5) {
                ui::print_dim(&format!("  {} ({}ms)", r.ip, r.latency_ms));
            }
        }

        // Prefer tunnel-capable resolvers, fall back to generic
        let working: Vec<String> = if !tunnel_capable.is_empty() {
            tunnel_capable.iter().map(|r| r.ip.to_string()).collect()
        } else {
            results.iter().map(|r| r.ip.to_string()).collect()
        };
        save_resolver_cache(&working);
        working
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
            ui::print_hint("If you're in Iran, try: --scan-iran");
            ui::print_hint("Or specify a resolver manually: --resolver <IP>");
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

    // Build DoH transport if requested (CLI flag, CLI provider, or config file)
    let doh_transport = if args.doh {
        let providers: Vec<&str> = if let Some(ref p) = args.doh_provider {
            vec![p.as_str()]
        } else {
            vec![] // use all defaults
        };
        Some(Arc::new(doh::DohTransport::new(&providers)))
    } else if !cfg.doh_resolvers().is_empty() {
        Some(Arc::new(doh::DohTransport::from_urls(&cfg.doh_resolvers())))
    } else {
        None
    };

    if !args.quiet {
        if doh_transport.is_some() {
            ui::print_status("Transport", "DNSTT over DoH (DNS-over-HTTPS)");
        } else {
            ui::print_status("Transport", "DNSTT (native Rust)");
        }
        ui::print_status("Tunnels", &format!("{} parallel", args.tunnels));
        if doh_transport.is_some() {
            let doh_ref = doh_transport.as_ref().unwrap();
            ui::print_status("DoH", &format!(
                "{} providers ({})",
                doh_ref.provider_count(),
                doh_ref.provider_urls().join(", ")
            ));
        } else {
            ui::print_status("Resolvers", &format!("{} available", resolvers.len()));
        }
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

    // Parse --qtype flag: "auto" = 0, or specific type
    let forced_qtype: u16 = if args.qtype.eq_ignore_ascii_case("auto") {
        0 // auto-detect via bootstrap probe
    } else {
        match dns_codec::parse_qtype(&args.qtype) {
            Some(qt) => qt,
            None => {
                ui::print_error(&format!("Unknown qtype: {}. Use: auto, A, AAAA, CNAME, MX, TXT, NS, SRV", args.qtype));
                std::process::exit(1);
            }
        }
    };

    if !args.quiet && forced_qtype != 0 {
        ui::print_status("QTYPE", &format!("{} (forced)", dns_codec::qtype_name(forced_qtype)));
    } else if !args.quiet {
        ui::print_status("QTYPE", "auto (probe at startup)");
    }

    // Start tunnel pool
    match tunnel::start(
        domains,
        resolvers,
        args.port,
        args.tunnels,
        running.clone(),
        Some(status_tx),
        doh_transport,
        forced_qtype,
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

/// Print ISP breakdown table for Iran.
fn print_isp_breakdown_iran() {
    ui::print_dim(&format!(
        "  Iran IP space: {} ranges, {:.1}M IPs",
        iran_ranges::iran_range_count(),
        iran_ranges::iran_ip_count() as f64 / 1e6,
    ));
    eprintln!();
    ui::print_dim("  ISP                ASN        Ranges   IPs");
    ui::print_dim("  ─────────────────  ─────────  ──────   ──────────");
    for group in iran_ranges::ISP_GROUPS {
        let ip_count = iran_ranges::isp_ip_count(group);
        ui::print_dim(&format!(
            "  {:<19} AS{:<7}  {:>4}     {:.1}M",
            group.name, group.asn, group.ranges.len(),
            ip_count as f64 / 1e6,
        ));
    }
    eprintln!();
}

/// Print ISP breakdown table for Russia.
fn print_isp_breakdown_russia() {
    ui::print_dim(&format!(
        "  Russia IP space: {} ranges, {:.1}M IPs",
        russia_ranges::russia_range_count(),
        russia_ranges::russia_ip_count() as f64 / 1e6,
    ));
    eprintln!();
    ui::print_dim("  ISP                ASN        Ranges   IPs");
    ui::print_dim("  ─────────────────  ─────────  ──────   ──────────");
    for group in russia_ranges::ISP_GROUPS {
        let ip_count = russia_ranges::isp_ip_count(group);
        ui::print_dim(&format!(
            "  {:<19} AS{:<7}  {:>4}     {:.1}M",
            group.name, group.asn, group.ranges.len(),
            ip_count as f64 / 1e6,
        ));
    }
    eprintln!();
}

/// Print full ISP table for --list-isps and exit.
fn print_isp_table() {
    eprintln!("  \x1b[1mIran ISPs\x1b[0m");
    eprintln!();
    eprintln!("  {:<19} {:<12} {:>6}   {:>10}", "ISP", "ASN", "Ranges", "IPs");
    eprintln!("  {}", "─".repeat(55));
    for group in iran_ranges::ISP_GROUPS {
        let ip_count = iran_ranges::isp_ip_count(group);
        let ip_str = if ip_count >= 1_000_000 {
            format!("{:.1}M", ip_count as f64 / 1e6)
        } else {
            format!("{:.0}K", ip_count as f64 / 1e3)
        };
        eprintln!(
            "  {:<19} AS{:<9} {:>4}     {:>8}",
            group.name, group.asn, group.ranges.len(), ip_str,
        );
    }

    eprintln!();
    eprintln!("  \x1b[1mRussia ISPs\x1b[0m");
    eprintln!();
    eprintln!("  {:<19} {:<12} {:>6}   {:>10}", "ISP", "ASN", "Ranges", "IPs");
    eprintln!("  {}", "─".repeat(55));
    for group in russia_ranges::ISP_GROUPS {
        let ip_count = russia_ranges::isp_ip_count(group);
        let ip_str = if ip_count >= 1_000_000 {
            format!("{:.1}M", ip_count as f64 / 1e6)
        } else {
            format!("{:.0}K", ip_count as f64 / 1e3)
        };
        eprintln!(
            "  {:<19} AS{:<9} {:>4}     {:>8}",
            group.name, group.asn, group.ranges.len(), ip_str,
        );
    }

    eprintln!();
    eprintln!("  \x1b[2mScan a specific ISP: nooshdaroo --scan-isp MCI\x1b[0m");
    eprintln!("  \x1b[2mScan by ASN:         nooshdaroo --scan-isp 197207\x1b[0m");
    eprintln!("  \x1b[2mScan by ASN prefix:  nooshdaroo --scan-isp AS44244\x1b[0m");
}

/// Parse a CIDR string (e.g. "5.160.100.0/24") and generate all host IPs.
fn parse_cidr_candidates(cidr_str: &str, max: usize) -> Vec<String> {
    let parts: Vec<&str> = cidr_str.split('/').collect();
    if parts.len() != 2 { return Vec::new(); }

    let base_ip: std::net::Ipv4Addr = match parts[0].parse() {
        Ok(ip) => ip,
        Err(_) => return Vec::new(),
    };
    let prefix_len: u8 = match parts[1].parse() {
        Ok(p) if p <= 32 => p,
        _ => return Vec::new(),
    };

    let base = u32::from(base_ip);
    let mask = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
    let network = base & mask;
    let host_count = 1u32 << (32 - prefix_len);

    let mut candidates = Vec::new();
    // Skip network address (.0) and broadcast (.255 for /24)
    for i in 1..host_count.saturating_sub(1).min(max as u32) {
        candidates.push(std::net::Ipv4Addr::from(network + i).to_string());
    }
    candidates
}
