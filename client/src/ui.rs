//! Terminal UI — banner, status messages, colors, progress indicators.
//!
//! Designed to look clean and professional in any terminal.
//! Uses ANSI colors when stderr is a TTY, plain text otherwise.

use crate::config::Config;

const VERSION: &str = env!("CARGO_PKG_VERSION");

// ─── In memory of those who paid the ultimate price ─────────────
// Names of verified martyrs of Iran's freedom movement.
// Displayed on each connection as a tribute.

struct Tribute {
    name_fa: &'static str,
    name_en: &'static str,
    age: Option<u8>,
    year: u16,
}

static TRIBUTES: &[Tribute] = &[
    // ─── Woman, Life, Freedom (2022-2023) ───
    Tribute { name_fa: "مهسا (ژینا) امینی", name_en: "Mahsa (Jina) Amini", age: Some(22), year: 2022 },
    Tribute { name_fa: "نیکا شاکرمی", name_en: "Nika Shakarami", age: Some(16), year: 2022 },
    Tribute { name_fa: "حدیث نجفی", name_en: "Hadis Najafi", age: Some(20), year: 2022 },
    Tribute { name_fa: "سارینا اسماعیل‌زاده", name_en: "Sarina Esmailzadeh", age: Some(16), year: 2022 },
    Tribute { name_fa: "کیان پیرفلک", name_en: "Kian Pirfalak", age: Some(9), year: 2022 },
    Tribute { name_fa: "محسن شکاری", name_en: "Mohsen Shekari", age: Some(23), year: 2022 },
    Tribute { name_fa: "مجیدرضا رهنورد", name_en: "Majidreza Rahnavard", age: Some(23), year: 2022 },
    Tribute { name_fa: "محمدمهدی کرمی", name_en: "Mohammad Mehdi Karami", age: Some(22), year: 2023 },
    Tribute { name_fa: "سیدمحمد حسینی", name_en: "Seyed Mohammad Hosseini", age: Some(39), year: 2023 },
    Tribute { name_fa: "حنانه کیا", name_en: "Hannaneh Kia", age: Some(23), year: 2022 },
    Tribute { name_fa: "غزاله چلاوی", name_en: "Ghazaleh Chelavi", age: Some(32), year: 2022 },
    Tribute { name_fa: "مینو مجیدی", name_en: "Minoo Majidi", age: Some(62), year: 2022 },
    Tribute { name_fa: "محمدحسین ترکمن", name_en: "Mohammad Hossein Torkaman", age: Some(16), year: 2022 },
    Tribute { name_fa: "آیلار حقی", name_en: "Aylar Haghi", age: Some(21), year: 2022 },
    Tribute { name_fa: "آرمیتا گراوند", name_en: "Armita Geravand", age: Some(16), year: 2023 },
    Tribute { name_fa: "ابوالفضل عالی‌پور", name_en: "Abolfazl Alidoust", age: Some(17), year: 2022 },
    Tribute { name_fa: "جاوید دهقان", name_en: "Javad Dehghan", age: Some(31), year: 2022 },
    // ─── Dey 1404 / January 8-9, 2026 — deadliest massacre in modern history ───
    // 30,000-36,500 killed in two days. Too many to name. We remember them all.
    Tribute { name_fa: "روبینا امینیان", name_en: "Robina Aminian", age: Some(23), year: 2026 },
    Tribute { name_fa: "رها بهلولی‌پور", name_en: "Raha Bohlouli-Pour", age: None, year: 2026 },
    Tribute { name_fa: "شهدای ۸ و ۹ دی ۱۴۰۴ — بیش از ۳۰ هزار نفر", name_en: "The 30,000+ souls of January 8-9, 2026", age: None, year: 2026 },
    Tribute { name_fa: "قتل‌عام رشت ۱۴۰۴", name_en: "The Rasht massacre victims", age: None, year: 2026 },
    // ─── PS752 — shot down by IRGC, January 8, 2020 ───
    Tribute { name_fa: "قربانیان پرواز ۷۵۲", name_en: "The 176 souls of Flight PS752", age: None, year: 2020 },
    // ─── Aban 98 — November 2019 massacre (1,500+ killed) ───
    Tribute { name_fa: "پویا بختیاری", name_en: "Pouya Bakhtiari", age: Some(27), year: 2019 },
    Tribute { name_fa: "نیکیتا اسفندانی", name_en: "Nikita Esfandani", age: Some(14), year: 2019 },
    Tribute { name_fa: "محسن محمدپور", name_en: "Mohsen Mohammadpour", age: Some(18), year: 2019 },
    Tribute { name_fa: "امیرحسین حاتمی", name_en: "Amirhossein Hatami", age: Some(15), year: 2019 },
    // ─── 2009 Green Movement ───
    Tribute { name_fa: "ندا آقاسلطان", name_en: "Neda Agha-Soltan", age: Some(26), year: 2009 },
    // ─── Executed for their beliefs ───
    Tribute { name_fa: "نوید افکاری", name_en: "Navid Afkari", age: Some(27), year: 2020 },
    Tribute { name_fa: "ستار بهشتی", name_en: "Sattar Beheshti", age: Some(35), year: 2012 },
    // ─── The unnamed tens of thousands across all years ───
    Tribute { name_fa: "ده‌ها هزار قهرمان بی‌نام", name_en: "The tens of thousands of unnamed heroes", age: None, year: 2026 },
];

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
    eprintln!(
        "  {}{}پاینده ایران{}",
        c.bold, c.green, c.reset
    );
    eprintln!(
        "  {}Payandeh Iran{}",
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

    // Honor a martyr — rotate daily
    print_tribute();
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

/// Print a tribute to a martyr of Iran's freedom movement.
/// Rotates through names — a different person honored each day.
fn print_tribute() {
    let c = colors();

    // Day-based rotation: different tribute each day
    let days_since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() / 86400;
    let idx = (days_since_epoch as usize) % TRIBUTES.len();
    let t = &TRIBUTES[idx];

    let age_str = t.age
        .map(|a| format!(", age {}", a))
        .unwrap_or_default();

    eprintln!(
        "  {}{}  \u{1F56F}  In memory of {} — {}{} ({}){}",
        c.dim, c.reset,
        t.name_en, t.name_fa, age_str, t.year, c.reset
    );
    eprintln!(
        "  {}     and all who gave their lives for a free Iran.{}",
        c.dim, c.reset
    );
    eprintln!();
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
