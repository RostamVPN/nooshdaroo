//! LiteWeb: server-side content proxy for bandwidth-constrained tunnels.
//!
//! Fetches pages, extracts readable content, sanitizes HTML, optimizes images,
//! and returns minimal HTML suitable for delivery over DNS tunnels (~50 KB/s).

pub mod config;
pub mod fetch;
pub mod image_opt;
pub mod readability;
pub mod sanitize;
pub mod template;
pub mod tracker_list;

use crate::config::LiteWebConfig;
use crate::tracker_list::TRACKER_DOMAINS;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A processed page ready for delivery through the tunnel.
pub struct ProcessedPage {
    pub html: String,
    pub title: String,
    pub original_size: usize,
    pub processed_size: usize,
    pub image_count: usize,
}

/// Cache entry with TTL.
struct CacheEntry {
    page: ProcessedPage,
    inserted: Instant,
}

/// The main LiteWeb proxy. Thread-safe, holds config and page cache.
pub struct LiteWebProxy {
    config: LiteWebConfig,
    client: reqwest::Client,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

impl LiteWebProxy {
    /// Create a new LiteWeb proxy with the given configuration.
    pub fn new(config: LiteWebConfig) -> Self {
        let client = fetch::build_client(config.fetch_timeout_secs)
            .expect("failed to build HTTP client");
        Self {
            config,
            client,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Process a URL: fetch, extract, sanitize, optimize, template.
    ///
    /// Returns the processed page or an error. On error, the caller should
    /// fall back to raw SOCKS5 passthrough.
    pub async fn process_url(&self, url: &str) -> Result<ProcessedPage> {
        // 1. Check cache.
        if let Some(page) = self.cache_get(url) {
            return Ok(page);
        }

        // 2. Check for passthrough extensions.
        let url_lower = url.to_lowercase();
        for ext in &self.config.passthrough_extensions {
            if url_lower.ends_with(ext) {
                anyhow::bail!("passthrough extension: {}", ext);
            }
        }

        // 3. Fetch the page.
        let fetch_result = fetch::fetch_page(&self.client, url, self.config.max_page_size).await?;
        let original_size = fetch_result.body_bytes;

        // 4. Run readability extraction.
        let readable = readability::extract(&fetch_result.body, &fetch_result.final_url);

        // 5. Sanitize the extracted content.
        let sanitized = sanitize::sanitize(
            &readable.content_html,
            &fetch_result.final_url,
            &TRACKER_DOMAINS,
        );

        // 6. Optimize images (download, resize, inline as data URIs).
        let (html_with_images, optimized_images) = image_opt::optimize_images(
            &self.client,
            &sanitized,
            &fetch_result.final_url,
            &self.config,
        )
        .await;

        let image_count = optimized_images.len();

        // 7. Wrap in minimal HTML template.
        let final_html = template::wrap(
            &readable.title,
            readable.byline.as_deref(),
            &html_with_images,
        );

        // 8. Enforce output size limit.
        let processed_size = final_html.len();
        if processed_size > self.config.max_output_size {
            log::warn!(
                "liteweb output {}KB exceeds limit {}KB for {}",
                processed_size / 1024,
                self.config.max_output_size / 1024,
                url,
            );
            // Still return it — better than nothing. Caller can decide.
        }

        let page = ProcessedPage {
            html: final_html,
            title: readable.title,
            original_size,
            processed_size,
            image_count,
        };

        // 9. Cache the result.
        self.cache_put(url, &page);

        log::info!(
            "liteweb processed {} => {}KB -> {}KB ({} images)",
            url,
            original_size / 1024,
            processed_size / 1024,
            image_count,
        );

        Ok(page)
    }

    fn cache_get(&self, url: &str) -> Option<ProcessedPage> {
        let mut cache = self.cache.lock().ok()?;
        let ttl = Duration::from_secs(self.config.cache_ttl_secs);

        if let Some(entry) = cache.get(url) {
            if entry.inserted.elapsed() < ttl {
                return Some(ProcessedPage {
                    html: entry.page.html.clone(),
                    title: entry.page.title.clone(),
                    original_size: entry.page.original_size,
                    processed_size: entry.page.processed_size,
                    image_count: entry.page.image_count,
                });
            } else {
                cache.remove(url);
            }
        }
        None
    }

    fn cache_put(&self, url: &str, page: &ProcessedPage) {
        if let Ok(mut cache) = self.cache.lock() {
            // Evict oldest if at capacity.
            if cache.len() >= self.config.cache_max_entries {
                let oldest_key = cache
                    .iter()
                    .min_by_key(|(_, v)| v.inserted)
                    .map(|(k, _)| k.clone());
                if let Some(key) = oldest_key {
                    cache.remove(&key);
                }
            }

            cache.insert(
                url.to_string(),
                CacheEntry {
                    page: ProcessedPage {
                        html: page.html.clone(),
                        title: page.title.clone(),
                        original_size: page.original_size,
                        processed_size: page.processed_size,
                        image_count: page.image_count,
                    },
                    inserted: Instant::now(),
                },
            );
        }
    }
}
