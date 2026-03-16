//! DNS-over-HTTPS (DoH) transport — RFC 8484.
//!
//! Wraps tunnel DNS queries inside HTTPS POST requests to well-known DoH
//! providers (Google, Cloudflare, Quad9). Makes tunnel traffic indistinguishable
//! from normal encrypted DNS lookups.
//!
//! The DNS wire format is identical to raw UDP — same `dns_codec::encode_query()`
//! and `dns_codec::decode_response()`. Only the carrier changes from UDP to HTTPS.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::dns_codec;

// ─── DoH provider definitions ────────────────────────────────────

/// A well-known DNS-over-HTTPS endpoint.
pub struct DohProvider {
    pub name: &'static str,
    pub url: &'static str,
    /// SNI/Host for domain fronting potential (reserved for future use).
    #[allow(dead_code)]
    pub host: &'static str,
}

/// Built-in DoH providers. All support RFC 8484 POST with application/dns-message.
pub const DOH_PROVIDERS: &[DohProvider] = &[
    DohProvider {
        name: "Google",
        url: "https://dns.google/dns-query",
        host: "dns.google",
    },
    DohProvider {
        name: "Cloudflare",
        url: "https://cloudflare-dns.com/dns-query",
        host: "cloudflare-dns.com",
    },
    DohProvider {
        name: "Quad9",
        url: "https://dns.quad9.net:5053/dns-query",
        host: "dns.quad9.net",
    },
];

/// Resolve a provider name (case-insensitive) to its URL.
fn resolve_provider_name(name: &str) -> Option<&'static str> {
    let lower = name.to_lowercase();
    for p in DOH_PROVIDERS {
        if p.name.to_lowercase() == lower {
            return Some(p.url);
        }
    }
    None
}

// ─── Per-provider error tracking ─────────────────────────────────

struct ProviderState {
    url: String,
    errors: AtomicUsize,
}

// ─── DohTransport ────────────────────────────────────────────────

/// Async DNS-over-HTTPS transport.
///
/// Sends DNS wire-format queries as HTTP POST with `Content-Type: application/dns-message`
/// (RFC 8484). Responses are the same DNS wire format returned in the HTTP body.
///
/// Rotates across providers round-robin. On failure, tries the next provider.
pub struct DohTransport {
    client: reqwest::Client,
    providers: Vec<ProviderState>,
    next_idx: AtomicUsize,
}

impl DohTransport {
    /// Create a DohTransport from a list of provider names or URLs.
    ///
    /// Each entry can be:
    /// - A provider name: "google", "cloudflare", "quad9"
    /// - A full URL: "https://dns.google/dns-query"
    ///
    /// If the list is empty, all built-in providers are used.
    pub fn new(providers: &[&str]) -> Self {
        let urls: Vec<String> = if providers.is_empty() {
            DOH_PROVIDERS.iter().map(|p| p.url.to_string()).collect()
        } else {
            providers
                .iter()
                .map(|&p| {
                    if p.starts_with("https://") {
                        p.to_string()
                    } else {
                        resolve_provider_name(p)
                            .map(|u| u.to_string())
                            .unwrap_or_else(|| p.to_string())
                    }
                })
                .collect()
        };

        Self::from_urls(&urls)
    }

    /// Create a DohTransport from a list of DoH endpoint URLs.
    pub fn from_urls(urls: &[String]) -> Self {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .http2_prior_knowledge()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(2)
            .build()
            .expect("failed to build reqwest client");

        let providers = urls
            .iter()
            .map(|url| ProviderState {
                url: url.clone(),
                errors: AtomicUsize::new(0),
            })
            .collect();

        DohTransport {
            client,
            providers,
            next_idx: AtomicUsize::new(0),
        }
    }

    /// Send a DNS wire-format query via HTTPS POST. Returns the DNS wire-format response.
    ///
    /// Tries the primary provider first (round-robin), then falls back to others.
    pub async fn send_query(&self, dns_wire: &[u8]) -> Result<Vec<u8>, String> {
        if self.providers.is_empty() {
            return Err("no DoH providers configured".into());
        }

        let start_idx = self.next_idx.fetch_add(1, Ordering::Relaxed) % self.providers.len();
        let mut last_err = String::new();

        for offset in 0..self.providers.len() {
            let idx = (start_idx + offset) % self.providers.len();
            let provider = &self.providers[idx];

            match self.do_post(&provider.url, dns_wire).await {
                Ok(response) => {
                    // Reset error count on success
                    provider.errors.store(0, Ordering::Relaxed);
                    return Ok(response);
                }
                Err(e) => {
                    provider.errors.fetch_add(1, Ordering::Relaxed);
                    log::debug!(
                        "[doh] {} failed (errors={}): {}",
                        provider.url,
                        provider.errors.load(Ordering::Relaxed),
                        e
                    );
                    last_err = e;
                }
            }
        }

        Err(format!(
            "all {} DoH providers failed, last: {}",
            self.providers.len(),
            last_err
        ))
    }

    /// Send a DNS wire-format query and decode the TXT RDATA packets from the response.
    ///
    /// This is a convenience wrapper: send_query() + dns_codec::decode_response().
    #[allow(dead_code)]
    pub async fn send_and_decode(&self, dns_wire: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let response = self.send_query(dns_wire).await?;
        dns_codec::decode_response(&response)
            .ok_or_else(|| "failed to decode DNS response".to_string())
    }

    /// POST dns_wire to a DoH endpoint and return the response body.
    async fn do_post(&self, url: &str, dns_wire: &[u8]) -> Result<Vec<u8>, String> {
        let resp = self
            .client
            .post(url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(dns_wire.to_vec())
            .send()
            .await
            .map_err(|e| format!("HTTP POST to {}: {}", url, e))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(format!("HTTP {} from {}", status, url));
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| format!("read body from {}: {}", url, e))?;

        if body.len() < 12 {
            return Err(format!("response too short from {}: {} bytes", url, body.len()));
        }

        Ok(body.to_vec())
    }

    /// Return the number of configured providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Return provider URLs for display/logging.
    pub fn provider_urls(&self) -> Vec<&str> {
        self.providers.iter().map(|p| p.url.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_provider_name() {
        assert_eq!(
            resolve_provider_name("google"),
            Some("https://dns.google/dns-query")
        );
        assert_eq!(
            resolve_provider_name("Cloudflare"),
            Some("https://cloudflare-dns.com/dns-query")
        );
        assert_eq!(
            resolve_provider_name("QUAD9"),
            Some("https://dns.quad9.net:5053/dns-query")
        );
        assert_eq!(resolve_provider_name("unknown"), None);
    }

    #[test]
    fn test_new_empty_uses_all_providers() {
        let transport = DohTransport::new(&[]);
        assert_eq!(transport.provider_count(), DOH_PROVIDERS.len());
    }

    #[test]
    fn test_new_with_names() {
        let transport = DohTransport::new(&["google", "cloudflare"]);
        assert_eq!(transport.provider_count(), 2);
        let urls = transport.provider_urls();
        assert_eq!(urls[0], "https://dns.google/dns-query");
        assert_eq!(urls[1], "https://cloudflare-dns.com/dns-query");
    }

    #[test]
    fn test_new_with_custom_url() {
        let transport = DohTransport::new(&["https://custom.example.com/dns-query"]);
        assert_eq!(transport.provider_count(), 1);
        assert_eq!(
            transport.provider_urls()[0],
            "https://custom.example.com/dns-query"
        );
    }

    #[test]
    fn test_from_urls() {
        let urls = vec![
            "https://dns.google/dns-query".to_string(),
            "https://cloudflare-dns.com/dns-query".to_string(),
        ];
        let transport = DohTransport::from_urls(&urls);
        assert_eq!(transport.provider_count(), 2);
    }
}
