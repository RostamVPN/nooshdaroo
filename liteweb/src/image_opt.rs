//! Image download, resize, and WebP optimization with base64 inlining.

use crate::config::LiteWebConfig;
use anyhow::Result;
use base64::Engine;
use regex::Regex;
use reqwest::Client;
use std::io::Cursor;
use std::time::Duration;

/// An optimized image ready for inlining.
pub struct OptimizedImage {
    pub data: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub original_size: usize,
}

/// Find all <img src="..."> in HTML, download and optimize images,
/// return modified HTML with images inlined as data URIs.
pub async fn optimize_images(
    client: &Client,
    html: &str,
    base_url: &str,
    config: &LiteWebConfig,
) -> (String, Vec<OptimizedImage>) {
    let img_re = Regex::new(r#"<img\s+src="([^"]+)"\s*(?:alt="([^"]*)")?\s*>"#).unwrap();

    let base = url::Url::parse(base_url).ok();

    // Collect image URLs (up to max_images_per_page).
    let mut img_entries: Vec<(String, String, String)> = Vec::new(); // (full_match, url, alt)
    for cap in img_re.captures_iter(html) {
        if img_entries.len() >= config.max_images_per_page {
            break;
        }
        let full_match = cap[0].to_string();
        let src = cap[1].to_string();
        let alt = cap.get(2).map_or("", |m| m.as_str()).to_string();

        // Resolve relative URLs.
        let resolved = if src.starts_with("http://") || src.starts_with("https://") || src.starts_with("data:") {
            src
        } else if let Some(ref b) = base {
            b.join(&src).map(|u| u.to_string()).unwrap_or(src)
        } else {
            src
        };

        img_entries.push((full_match, resolved, alt));
    }

    if img_entries.is_empty() {
        return (html.to_string(), Vec::new());
    }

    // Download and optimize concurrently.
    let mut handles = Vec::new();
    for (full_match, url, alt) in &img_entries {
        let client = client.clone();
        let url = url.clone();
        let alt = alt.clone();
        let full_match = full_match.clone();
        let max_width = config.image_max_width;
        let quality = config.image_quality;

        let handle = tokio::spawn(async move {
            let result = download_and_optimize(&client, &url, max_width, quality).await;
            (full_match, url, alt, result)
        });
        handles.push(handle);
    }

    let mut output_html = html.to_string();
    let mut optimized = Vec::new();

    for handle in handles {
        match handle.await {
            Ok((full_match, _url, alt, Ok(opt))) => {
                let b64 = base64::engine::general_purpose::STANDARD.encode(&opt.data);
                let data_uri = format!("data:image/webp;base64,{}", b64);
                let replacement = format!(
                    "<img src=\"{}\" alt=\"{}\" width=\"{}\" height=\"{}\">",
                    data_uri,
                    html_escape_attr(&alt),
                    opt.width,
                    opt.height,
                );
                output_html = output_html.replacen(&full_match, &replacement, 1);
                optimized.push(opt);
            }
            Ok((full_match, _url, alt, Err(e))) => {
                log::debug!("image optimization failed: {}", e);
                let alt_text = if alt.is_empty() {
                    "[Image]".to_string()
                } else {
                    format!("[Image: {}]", alt)
                };
                output_html = output_html.replacen(&full_match, &alt_text, 1);
            }
            Err(e) => {
                log::debug!("image task join error: {}", e);
            }
        }
    }

    (output_html, optimized)
}

async fn download_and_optimize(
    client: &Client,
    url: &str,
    max_width: u32,
    quality: u8,
) -> Result<OptimizedImage> {
    // Skip data URIs.
    if url.starts_with("data:") {
        anyhow::bail!("skipping data URI");
    }

    let resp = client
        .get(url)
        .timeout(Duration::from_secs(5))
        .send()
        .await?;

    let bytes = resp.bytes().await?;
    let original_size = bytes.len();

    // Limit: 10MB per image.
    if original_size > 10 * 1024 * 1024 {
        anyhow::bail!("image too large: {} bytes", original_size);
    }

    let img = image::load_from_memory(&bytes)?;

    // Resize if wider than max_width.
    let img = if img.width() > max_width {
        img.resize(max_width, u32::MAX, image::imageops::FilterType::Lanczos3)
    } else {
        img
    };

    let width = img.width();
    let height = img.height();

    // Encode to WebP.
    let mut buf = Cursor::new(Vec::new());
    let encoder = image::codecs::webp::WebPEncoder::new_lossless(&mut buf);
    // Try lossy encoding by writing as RGBA and letting WebP handle it.
    // The `image` crate WebP encoder supports lossless; for lossy with quality
    // control we encode to JPEG first as a fallback if WebP is too large.
    img.write_with_encoder(encoder)?;
    let webp_data = buf.into_inner();

    // If WebP lossless is too big, fall back to JPEG.
    let (data, final_width, final_height) = if webp_data.len() > 100_000 {
        let mut jpeg_buf = Cursor::new(Vec::new());
        let jpeg_encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpeg_buf, quality);
        img.write_with_encoder(jpeg_encoder)?;
        let jpeg_data = jpeg_buf.into_inner();
        // Use whichever is smaller.
        if jpeg_data.len() < webp_data.len() {
            (jpeg_data, width, height)
        } else {
            (webp_data, width, height)
        }
    } else {
        (webp_data, width, height)
    };

    Ok(OptimizedImage {
        data,
        width: final_width,
        height: final_height,
        original_size,
    })
}

fn html_escape_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
