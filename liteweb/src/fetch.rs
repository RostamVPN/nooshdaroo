//! HTTP page fetcher with Chrome UA, compression, redirect following.

use anyhow::{bail, Result};
use reqwest::Client;
use std::time::Duration;

/// Result of fetching a page.
pub struct FetchResult {
    pub final_url: String,
    pub status: u16,
    pub content_type: String,
    pub body: String,
    pub body_bytes: usize,
}

/// Build a reusable reqwest client with Chrome-like headers.
pub fn build_client(timeout_secs: u64) -> Result<Client> {
    let client = Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        .timeout(Duration::from_secs(timeout_secs))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;
    Ok(client)
}

/// Fetch a page, rejecting non-HTML responses.
pub async fn fetch_page(client: &Client, url: &str, max_size: usize) -> Result<FetchResult> {
    let resp = client.get(url).send().await?;

    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    if !content_type.contains("text/html") && !content_type.contains("application/xhtml") {
        bail!(
            "not HTML: content-type={} (url={})",
            content_type,
            final_url
        );
    }

    let bytes = resp.bytes().await?;
    let body_bytes = bytes.len();
    if body_bytes > max_size {
        bail!(
            "page too large: {} bytes (max {})",
            body_bytes,
            max_size
        );
    }

    let body = String::from_utf8_lossy(&bytes).into_owned();

    Ok(FetchResult {
        final_url,
        status,
        content_type,
        body,
        body_bytes,
    })
}
