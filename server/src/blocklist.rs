//! Domain blocklist — blocks ad/tracker domains at the SOCKS5 level.
//!
//! Loads domains from a flat text file (one domain per line).
//! Supports exact match and wildcard suffix match.
//! Hot-reload: watches file mtime, reloads without restart.
//!
//! **Allowlist**: A hardcoded set of first-party service domains that must
//! NEVER be blocked, even if they match a blocklist pattern. This prevents
//! breaking sites like news.google.com that depend on *.googletagmanager.com
//! for core rendering (not just analytics). An optional allowlist file can
//! extend the hardcoded set.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

// ── Hardcoded allowlist ────────────────────────────────────────
// First-party service domains that blocklist wildcards must never kill.
// These are critical CDN / API / rendering domains used by major sites.
// The blocklist can still block SPECIFIC subdomains via exact match
// (e.g., "adservice.google.com") — the allowlist only protects suffix patterns.
const ALLOWLIST_SUFFIXES: &[&str] = &[
    // Google first-party (News, Maps, Drive, YouTube, etc.)
    ".google.com",
    ".google.co.uk",
    ".google.de",
    ".google.fr",
    ".google.co.in",
    ".google.co.jp",
    ".googleapis.com",
    ".gstatic.com",
    ".googleusercontent.com",
    ".googlevideo.com",
    ".youtube.com",
    ".ytimg.com",
    ".ggpht.com",
    // Microsoft first-party (Bing, Outlook, Office, Teams)
    ".microsoft.com",
    ".microsoftonline.com",
    ".office.com",
    ".office365.com",
    ".live.com",
    ".outlook.com",
    ".windows.net",
    ".azure.com",
    ".bing.com",
    // Apple
    ".apple.com",
    ".icloud.com",
    // Amazon (shopping, not ad network)
    ".amazon.com",
    ".amazon.co.uk",
    ".amazon.de",
    // Major services
    ".wikipedia.org",
    ".wikimedia.org",
    ".github.com",
    ".githubusercontent.com",
    ".cloudflare.com",
    ".whatsapp.com",
    ".whatsapp.net",
    ".telegram.org",
    ".t.me",
    ".signal.org",
    // Iranian services (must never break)
    ".digikala.com",
    ".aparat.com",
    ".shaparak.ir",
    ".snapp.ir",
    ".divar.ir",
    ".bale.ai",
];

/// Blocklist statistics.
pub struct BlocklistStats {
    pub blocked_total: AtomicU64,
    pub domains_loaded: AtomicU64,
    pub allowlist_overrides: AtomicU64,
}

impl BlocklistStats {
    pub fn new() -> Self {
        Self {
            blocked_total: AtomicU64::new(0),
            domains_loaded: AtomicU64::new(0),
            allowlist_overrides: AtomicU64::new(0),
        }
    }
}

/// Thread-safe domain blocklist with hot-reload support.
pub struct DomainBlocklist {
    inner: RwLock<BlocklistInner>,
    file_path: Option<PathBuf>,
    allowlist_path: Option<PathBuf>,
    pub stats: BlocklistStats,
}

struct BlocklistInner {
    /// Exact match set: "ads.example.com"
    exact: HashSet<String>,
    /// Suffix patterns: ".doubleclick.net" (stored without leading dot)
    suffixes: Vec<String>,
    /// Allowlist: domains that override blocklist (suffix match).
    allowlist_suffixes: Vec<String>,
    /// Allowlist: exact domain matches.
    allowlist_exact: HashSet<String>,
    /// File mtime at last load (for hot-reload).
    last_mtime: Option<std::time::SystemTime>,
}

impl DomainBlocklist {
    /// Create an empty blocklist (no file).
    pub fn empty() -> Arc<Self> {
        Arc::new(Self {
            inner: RwLock::new(BlocklistInner {
                exact: HashSet::new(),
                suffixes: Vec::new(),
                allowlist_suffixes: ALLOWLIST_SUFFIXES.iter().map(|s| s.to_string()).collect(),
                allowlist_exact: HashSet::new(),
                last_mtime: None,
            }),
            file_path: None,
            allowlist_path: None,
            stats: BlocklistStats::new(),
        })
    }

    /// Load blocklist from a file. One domain per line.
    /// Lines starting with '#' or empty are skipped.
    /// Lines starting with '*.' are treated as wildcard suffixes.
    ///
    /// Also loads an optional allowlist from `<blocklist_dir>/allowlist.txt`.
    pub async fn from_file(path: &Path) -> Arc<Self> {
        // Look for allowlist.txt next to blocklist.txt
        let allowlist_path = path.parent().map(|dir| dir.join("allowlist.txt"));

        let bl = Arc::new(Self {
            inner: RwLock::new(BlocklistInner {
                exact: HashSet::new(),
                suffixes: Vec::new(),
                allowlist_suffixes: ALLOWLIST_SUFFIXES.iter().map(|s| s.to_string()).collect(),
                allowlist_exact: HashSet::new(),
                last_mtime: None,
            }),
            file_path: Some(path.to_path_buf()),
            allowlist_path,
            stats: BlocklistStats::new(),
        });
        bl.reload().await;
        bl
    }

    /// Reload the blocklist from disk if the file has changed.
    pub async fn reload(&self) {
        let path = match &self.file_path {
            Some(p) => p,
            None => return,
        };

        // Check mtime.
        let mtime = match std::fs::metadata(path) {
            Ok(m) => m.modified().ok(),
            Err(e) => {
                log::warn!("blocklist: cannot stat {}: {}", path.display(), e);
                return;
            }
        };

        {
            let inner = self.inner.read().await;
            if inner.last_mtime == mtime && !inner.exact.is_empty() {
                return; // No change.
            }
        }

        // Read and parse.
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                log::warn!("blocklist: cannot read {}: {}", path.display(), e);
                return;
            }
        };

        let mut exact = HashSet::new();
        let mut suffixes = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Hosts file format: "0.0.0.0 domain" or "127.0.0.1 domain"
            let domain = if line.starts_with("0.0.0.0 ") || line.starts_with("127.0.0.1 ") {
                line.split_whitespace().nth(1).unwrap_or("")
            } else if line.starts_with("*.") {
                // Wildcard: "*.doubleclick.net"
                let suffix = &line[1..]; // ".doubleclick.net"
                suffixes.push(suffix.to_lowercase());
                continue;
            } else {
                line
            };

            if !domain.is_empty() && domain != "localhost" {
                exact.insert(domain.to_lowercase());
            }
        }

        let count = exact.len() + suffixes.len();
        self.stats.domains_loaded.store(count as u64, Ordering::Relaxed);

        // Load optional allowlist file (extends hardcoded ALLOWLIST_SUFFIXES).
        let mut allowlist_suffixes: Vec<String> =
            ALLOWLIST_SUFFIXES.iter().map(|s| s.to_string()).collect();
        let mut allowlist_exact: HashSet<String> = HashSet::new();

        if let Some(al_path) = &self.allowlist_path {
            if let Ok(content) = std::fs::read_to_string(al_path) {
                for line in content.lines() {
                    let line = line.trim().to_lowercase();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    if line.starts_with("*.") {
                        allowlist_suffixes.push(line[1..].to_string());
                    } else {
                        allowlist_exact.insert(line);
                    }
                }
                log::info!(
                    "allowlist: loaded {} extra entries from {}",
                    allowlist_exact.len() + allowlist_suffixes.len() - ALLOWLIST_SUFFIXES.len(),
                    al_path.display()
                );
            }
        }

        let mut inner = self.inner.write().await;
        inner.exact = exact;
        inner.suffixes = suffixes;
        inner.allowlist_suffixes = allowlist_suffixes;
        inner.allowlist_exact = allowlist_exact;
        inner.last_mtime = mtime;

        log::info!(
            "blocklist: loaded {} domains ({} exact, {} wildcard), allowlist: {} suffixes + {} exact",
            count,
            inner.exact.len(),
            inner.suffixes.len(),
            inner.allowlist_suffixes.len(),
            inner.allowlist_exact.len(),
        );
    }

    /// Check if a domain is on the allowlist (must never be blocked).
    fn is_allowed(domain: &str, inner: &BlocklistInner) -> bool {
        // Exact allowlist match.
        if inner.allowlist_exact.contains(domain) {
            return true;
        }
        // Suffix allowlist match (e.g., ".google.com" allows "news.google.com").
        for suffix in &inner.allowlist_suffixes {
            if domain.ends_with(suffix.as_str()) {
                return true;
            }
        }
        false
    }

    /// Check if a domain is blocked.
    ///
    /// Order: allowlist (never block) → exact blocklist → wildcard blocklist.
    /// The allowlist protects first-party service domains from overzealous
    /// wildcard patterns (e.g., *.googletagmanager.com killing news.google.com).
    pub async fn is_blocked(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        let inner = self.inner.read().await;

        // 1. Allowlist check — if domain is on the allowlist, NEVER block it.
        if Self::is_allowed(&domain, &inner) {
            // But still block specific ad subdomains even on allowed parent domains.
            // E.g., "adservice.google.com" is in the exact blocklist AND matches
            // the ".google.com" allowlist. The exact blocklist wins for these.
            if inner.exact.contains(&domain) {
                return true;
            }
            // Wildcard blocklist patterns are overridden by allowlist.
            // Log at debug level so we can see what the allowlist is saving.
            log::trace!("allowlist override: {}", domain);
            self.stats.allowlist_overrides.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // 2. Exact blocklist match.
        if inner.exact.contains(&domain) {
            return true;
        }

        // 3. Suffix blocklist match: check if domain ends with any wildcard pattern.
        // E.g., ".doubleclick.net" matches "ads.doubleclick.net".
        for suffix in &inner.suffixes {
            if domain.ends_with(suffix.as_str()) {
                return true;
            }
        }

        false
    }

    /// Record a blocked connection.
    pub fn record_block(&self) {
        self.stats.blocked_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Number of loaded domains.
    pub fn domain_count(&self) -> u64 {
        self.stats.domains_loaded.load(Ordering::Relaxed)
    }
}

/// Spawn a background task that reloads the blocklist every 60 seconds.
pub fn spawn_reload_task(blocklist: Arc<DomainBlocklist>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            blocklist.reload().await;
        }
    });
}
