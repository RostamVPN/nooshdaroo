use clap::Parser;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

mod config;
mod dnstt;
mod socks5;
mod sushmode;
mod ui;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_DATE: &str = env!("CARGO_PKG_VERSION"); // Will be overridden by build.rs if present

#[derive(Parser)]
#[command(
    name = "nooshdaroo",
    version = VERSION,
    about = "Nooshdaroo — Censorship-resistant SOCKS5 proxy via DNS tunneling",
    long_about = None,
    after_help = "EXAMPLES:\n  \
        nooshdaroo                        Start with default settings (SOCKS5 on 127.0.0.1:1080)\n  \
        nooshdaroo -p 9050               Listen on port 9050\n  \
        nooshdaroo --scan                 Try all available domains until one connects\n  \
        nooshdaroo --domain t.f14.1e-100.net  Force a specific tunnel domain\n  \
        nooshdaroo --resolver 8.8.8.8     Use Google DNS as resolver\n\n\
        BROWSER SETUP:\n  \
        Firefox:  Settings > Network > Manual Proxy > SOCKS Host: 127.0.0.1  Port: 1080\n  \
        Chrome:   chrome --proxy-server=\"socks5://127.0.0.1:1080\"\n  \
        curl:     curl --proxy socks5h://127.0.0.1:1080 https://example.com\n\n\
        https://nooshdaroo.net  |  https://rostam.app"
)]
struct Args {
    /// SOCKS5 listen port
    #[arg(short, long, default_value = "1080", value_name = "PORT")]
    port: u16,

    /// SOCKS5 listen address
    #[arg(short = 'b', long, default_value = "127.0.0.1", value_name = "ADDR")]
    bind: String,

    /// Path to dnstt-client binary
    #[arg(long, value_name = "PATH")]
    dnstt_client: Option<String>,

    /// Force a specific DNSTT domain
    #[arg(long, value_name = "DOMAIN")]
    domain: Option<String>,

    /// Force a specific DNS resolver
    #[arg(long, value_name = "IP")]
    resolver: Option<String>,

    /// Use SushMode transport instead of DNSTT
    #[arg(long)]
    sushmode: bool,

    /// Scan all domains sequentially until one connects
    #[arg(long)]
    scan: bool,

    /// Verbose output (show debug logs)
    #[arg(short, long)]
    verbose: bool,

    /// Suppress banner and decorative output
    #[arg(short, long)]
    quiet: bool,

    /// Show configuration and exit
    #[arg(long)]
    show_config: bool,
}

fn main() {
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
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set Ctrl+C handler");

    // Print banner
    if !args.quiet {
        ui::print_banner();
    }

    // Load config
    let cfg = config::load_config();

    // Show config and exit
    if args.show_config {
        ui::print_config_info(&cfg);
        return;
    }

    let listen_addr = format!("{}:{}", args.bind, args.port);

    if args.sushmode {
        let servers = cfg.sushmode_servers();
        if servers.is_empty() {
            ui::print_error("No SushMode servers available in configuration.");
            process::exit(1);
        }
        ui::print_status("Transport", "SushMode (Noise_NK over UDP/53)");
        sushmode::run(&listen_addr, &servers, &running);
    } else {
        // DNSTT path (default)
        let dnstt_bin = dnstt::find_binary(args.dnstt_client.as_deref());
        if dnstt_bin.is_none() {
            ui::print_error("dnstt-client binary not found.");
            eprintln!();
            ui::print_hint("Place dnstt-client next to this binary, or specify its path:");
            eprintln!("         nooshdaroo --dnstt-client /path/to/dnstt-client");
            #[cfg(target_os = "windows")]
            {
                eprintln!();
                ui::print_hint("On Windows, the binary should be named dnstt-client.exe");
            }
            eprintln!();

            // Try SushMode fallback
            let servers = cfg.sushmode_servers();
            if !servers.is_empty() {
                ui::print_status("Fallback", "Trying SushMode...");
                sushmode::run(&listen_addr, &servers, &running);
                return;
            }

            process::exit(1);
        }
        let dnstt_bin = dnstt_bin.unwrap();

        // Build domain list
        let domains = if let Some(ref d) = args.domain {
            let pk = cfg
                .pubkey_for_domain(d)
                .unwrap_or_else(|| cfg.default_pubkey());
            vec![(d.clone(), pk)]
        } else if args.scan {
            cfg.dnstt_domains()
        } else {
            let all = cfg.dnstt_domains();
            if all.is_empty() {
                ui::print_error("No DNSTT domains in configuration.");
                process::exit(1);
            }
            let idx = rand::random::<usize>() % all.len();
            vec![all[idx].clone()]
        };

        let resolver = args
            .resolver
            .unwrap_or_else(|| cfg.pick_resolver());

        if !args.quiet {
            ui::print_status("Transport", "DNSTT (DNS tunnel over UDP/53)");
            ui::print_status("Resolver", &resolver);
            ui::print_status("Domains", &format!("{} available", domains.len()));
            eprintln!();
        }

        let params = dnstt::DnsttParams {
            binary: dnstt_bin,
            listen: listen_addr.clone(),
            domains,
            resolver,
            quiet: args.quiet,
        };

        dnstt::run(&params, &running, &cfg);
    }

    if !args.quiet {
        eprintln!();
        ui::print_dim("Session ended. Stay safe.");
    }
}
