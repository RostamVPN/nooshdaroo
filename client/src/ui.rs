//! Terminal UI — banner, status messages, colors, progress indicators.
//!
//! Designed to look clean and professional in any terminal.
//! Uses ANSI colors when stderr is a TTY, plain text otherwise.

use crate::config::Config;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// ANSI color codes (only used when TTY is detected)
struct Colors {
    bold: &'static str,
    dim: &'static str,
    green: &'static str,
    cyan: &'static str,
    yellow: &'static str,
    red: &'static str,
    magenta: &'static str,
    reset: &'static str,
}

const COLORS_ON: Colors = Colors {
    bold: "\x1b[1m",
    dim: "\x1b[2m",
    green: "\x1b[32m",
    cyan: "\x1b[36m",
    yellow: "\x1b[33m",
    red: "\x1b[31m",
    magenta: "\x1b[35m",
    reset: "\x1b[0m",
};

const COLORS_OFF: Colors = Colors {
    bold: "",
    dim: "",
    green: "",
    cyan: "",
    yellow: "",
    red: "",
    magenta: "",
    reset: "",
};

fn colors() -> &'static Colors {
    // Simple TTY detection: check TERM env var and NO_COLOR
    if std::env::var("NO_COLOR").is_ok() {
        return &COLORS_OFF;
    }
    if std::env::var("TERM").unwrap_or_default() == "dumb" {
        return &COLORS_OFF;
    }
    // On Windows without TERM set, disable colors by default
    #[cfg(target_os = "windows")]
    {
        if std::env::var("TERM").is_err() && std::env::var("WT_SESSION").is_err() {
            // Not Windows Terminal — might not support ANSI
            return &COLORS_OFF;
        }
    }
    &COLORS_ON
}

/// Print the startup banner
pub fn print_banner() {
    let c = colors();

    eprintln!();
    eprintln!(
        "{}{}  _   _                 _         _                    {}",
        c.bold, c.cyan, c.reset
    );
    eprintln!(
        "{}{}  | \\ | | ___   ___  ___| |__   __| | __ _ _ __ ___   ___{}",
        c.bold, c.cyan, c.reset
    );
    eprintln!(
        "{}{}  |  \\| |/ _ \\ / _ \\/ __| '_ \\ / _` |/ _` | '__/ _ \\ / _ \\{}",
        c.bold, c.cyan, c.reset
    );
    eprintln!(
        "{}{}  | |\\  | (_) | (_) \\__ \\ | | | (_| | (_| | | | (_) | (_) |{}",
        c.bold, c.cyan, c.reset
    );
    eprintln!(
        "{}{}  |_| \\_|\\___/ \\___/|___/_| |_|\\__,_|\\__,_|_|  \\___/ \\___/{}",
        c.bold, c.cyan, c.reset
    );
    eprintln!();
    eprintln!(
        "  {}{}v{}{}",
        c.bold, c.green, VERSION, c.reset
    );
    eprintln!(
        "  {}Censorship-resistant SOCKS5 proxy over DNS tunneling{}",
        c.dim, c.reset
    );
    eprintln!();
}

/// Print a key-value status line
pub fn print_status(key: &str, value: &str) {
    let c = colors();
    eprintln!(
        "  {}{}{}  {}{}{}",
        c.cyan, key, c.reset, c.bold, value, c.reset
    );
}

/// Print a success message (proxy ready)
pub fn print_ready(listen_addr: &str) {
    let c = colors();
    let host = listen_addr.split(':').next().unwrap_or("127.0.0.1");
    let port = listen_addr.split(':').nth(1).unwrap_or("1080");

    eprintln!();
    eprintln!(
        "  {}{}SOCKS5 proxy ready{}{}",
        c.bold, c.green, c.reset, ""
    );
    eprintln!(
        "  {}{}{}:{}{}", c.bold, c.green, host, port, c.reset
    );
    eprintln!();
    eprintln!(
        "  {}Browser setup:{}",
        c.dim, c.reset
    );
    eprintln!(
        "  {}  Firefox:  Settings > Network > SOCKS Host: {}  Port: {}{}",
        c.dim, host, port, c.reset
    );
    eprintln!(
        "  {}  Chrome:   --proxy-server=\"socks5://{}:{}\"{}",
        c.dim, host, port, c.reset
    );
    eprintln!(
        "  {}  curl:     --proxy socks5h://{}:{}{}",
        c.dim, host, port, c.reset
    );
    eprintln!();
    eprintln!(
        "  {}Verify:  curl --proxy socks5h://{}:{} https://check.torproject.org/api/ip{}",
        c.dim, host, port, c.reset
    );
    eprintln!();
    eprintln!(
        "  {}Press Ctrl+C to disconnect.{}",
        c.dim, c.reset
    );
    eprintln!();
}

/// Print a connection attempt
pub fn print_connecting(domain: &str, resolver: &str) {
    let c = colors();
    eprintln!(
        "  {}{}Connecting...{}  {}domain:{}  {}{}{}  {}resolver:{}  {}{}{}",
        c.bold, c.yellow, c.reset,
        c.dim, c.reset, c.bold, domain, c.reset,
        c.dim, c.reset, c.bold, resolver, c.reset,
    );
}

/// Print a reconnection attempt
pub fn print_reconnecting(reason: &str, domain: &str) {
    let c = colors();
    eprintln!(
        "  {}{}Reconnecting...{}  {}{}{}  {}({}){}",
        c.bold, c.yellow, c.reset,
        c.bold, domain, c.reset,
        c.dim, reason, c.reset
    );
}

/// Print an error
pub fn print_error(msg: &str) {
    let c = colors();
    eprintln!(
        "  {}{}Error:{}  {}",
        c.bold, c.red, c.reset, msg
    );
}

/// Print a hint
pub fn print_hint(msg: &str) {
    let c = colors();
    eprintln!(
        "  {}{}Hint:{}   {}",
        c.bold, c.magenta, c.reset, msg
    );
}

/// Print a dim info line
pub fn print_dim(msg: &str) {
    let c = colors();
    eprintln!("  {}{}{}", c.dim, msg, c.reset);
}

/// Print config info (--show-config)
pub fn print_config_info(cfg: &Config) {
    let c = colors();
    let domains = cfg.dnstt_domains();
    let resolvers = cfg.dnstt_resolvers();

    eprintln!(
        "  {}{}Configuration{}",
        c.bold, c.cyan, c.reset
    );
    eprintln!();
    eprintln!(
        "  {}DNSTT Domains ({}):{}", c.dim, domains.len(), c.reset
    );
    for (domain, _pubkey) in &domains {
        eprintln!("    {}{}{}", c.green, domain, c.reset);
    }
    eprintln!();
    eprintln!(
        "  {}UDP Resolvers ({}):{}", c.dim, resolvers.len(), c.reset
    );
    for r in resolvers.iter().take(10) {
        eprintln!("    {}", r);
    }
    if resolvers.len() > 10 {
        eprintln!(
            "    {}... and {} more{}", c.dim, resolvers.len() - 10, c.reset
        );
    }
    eprintln!();
    let pubkey = cfg.default_pubkey();
    if !pubkey.is_empty() {
        eprintln!(
            "  {}Default pubkey: {}...{}",
            c.dim, &pubkey[..16.min(pubkey.len())], c.reset
        );
    }
}

/// Print shutdown message
pub fn print_shutdown() {
    let c = colors();
    eprintln!();
    eprintln!(
        "  {}{}Disconnecting...{}",
        c.bold, c.yellow, c.reset
    );
}
