//! Lightweight, non-blocking Datadog metrics exporter.
//!
//! Posts gauge metrics directly to the Datadog HTTP API every 60 seconds.
//! Completely fire-and-forget — never blocks the server event loop.
//!
//! Enable by setting DD_API_KEY (env var or config). Metrics are tagged with
//! host:<server_id> and ip:<host_ip>.

use crate::dns_cache::DnsCache;
use crate::kcp_manager::{KcpManager, Metrics};
use crate::socks5::LiteWebContext;
use serde::Serialize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

const DD_SERIES_URL: &str = "https://api.datadoghq.com/api/v1/series";
const POST_TIMEOUT: Duration = Duration::from_secs(10);
const EXPORT_INTERVAL: Duration = Duration::from_secs(60);

// ── Datadog payload types ────────────────────────────────────────

#[derive(Serialize)]
struct SeriesPayload {
    series: Vec<MetricPoint>,
}

#[derive(Serialize)]
struct MetricPoint {
    metric: String,
    #[serde(rename = "type")]
    metric_type: String,
    points: Vec<[f64; 2]>,
    tags: Vec<String>,
}

// ── Exporter ─────────────────────────────────────────────────────

/// Fire-and-forget Datadog metrics poster.
pub struct DatadogExporter {
    client: reqwest::Client,
    api_key: String,
    tags: Vec<String>,
}

impl DatadogExporter {
    /// Try to create from env vars. Returns None if DD_API_KEY is not set.
    pub fn from_env(server_id: &str) -> Option<Arc<Self>> {
        let api_key = std::env::var("DD_API_KEY").ok()?;
        if api_key.is_empty() {
            return None;
        }

        let host_ip = std::env::var("DD_HOST_IP").unwrap_or_default();

        let mut tags = vec![
            format!("host:{}", server_id),
            "service:dnstt-server".to_string(),
        ];
        if !host_ip.is_empty() {
            tags.push(format!("ip:{}", host_ip));
        }

        let client = reqwest::Client::builder()
            .timeout(POST_TIMEOUT)
            .pool_max_idle_per_host(1)
            .build()
            .ok()?;

        log::info!(
            "[DD] exporter enabled for host={} ip={}",
            server_id,
            if host_ip.is_empty() { "auto" } else { &host_ip }
        );

        Some(Arc::new(Self {
            client,
            api_key,
            tags,
        }))
    }

    /// Post a batch of metrics. Non-blocking — call from a spawned task.
    async fn post(&self, metrics: Vec<(&str, f64)>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as f64;

        let series: Vec<MetricPoint> = metrics
            .into_iter()
            .map(|(name, value)| MetricPoint {
                metric: format!("dnstt.{}", name),
                metric_type: "gauge".to_string(),
                points: vec![[now, value]],
                tags: self.tags.clone(),
            })
            .collect();

        let count = series.len();
        let payload = SeriesPayload { series };

        match self
            .client
            .post(DD_SERIES_URL)
            .header("DD-API-KEY", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                log::debug!("[DD] posted {} metrics", count);
            }
            Ok(resp) => {
                log::warn!("[DD] API returned {}", resp.status());
            }
            Err(e) => {
                log::warn!("[DD] post failed: {}", e);
            }
        }
    }
}

// ── Background export task ───────────────────────────────────────

/// Spawn a non-blocking background task that posts metrics to Datadog every 60s.
/// The task is fully detached — if the POST hangs or fails, it does not affect
/// the server. Each POST is itself spawned as a fire-and-forget subtask.
pub fn spawn_export_task(
    dd: Arc<DatadogExporter>,
    metrics: Arc<Metrics>,
    kcp: Arc<Mutex<KcpManager>>,
    ctx: Arc<LiteWebContext>,
    dns_cache: Arc<DnsCache>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(EXPORT_INTERVAL);
        loop {
            interval.tick().await;

            // Snapshot all metrics (fast — just atomic loads).
            let (session_count, client_count) = {
                let mgr = kcp.lock().await;
                (mgr.session_count(), mgr.unique_client_count())
            };

            let active_streams = metrics.active_streams.load(Ordering::Relaxed) as f64;
            let total_streams = metrics.total_streams.load(Ordering::Relaxed) as f64;
            let total_bytes = metrics.total_bytes.load(Ordering::Relaxed) as f64;
            let dial_errors = metrics.dial_errors.load(Ordering::Relaxed) as f64;
            let stream_rejects = metrics.stream_rejects.load(Ordering::Relaxed) as f64;
            let blocked = ctx.metrics.blocked_connections.load(Ordering::Relaxed) as f64;
            let bw_saved = ctx.metrics.bandwidth_saved_estimate.load(Ordering::Relaxed) as f64;
            let allowlist_overrides = ctx.blocklist.stats.allowlist_overrides.load(Ordering::Relaxed) as f64;
            let dns_hits = dns_cache.cache_hits.load(Ordering::Relaxed) as f64;
            let dns_misses = dns_cache.cache_misses.load(Ordering::Relaxed) as f64;
            let dns_entries = dns_cache.len() as f64;
            let dns_hit_rate = dns_cache.hit_rate_pct();

            let batch = vec![
                ("clients", client_count as f64),
                ("sessions", session_count as f64),
                ("active_streams", active_streams),
                ("total_streams", total_streams),
                ("bytes", total_bytes),
                ("dial_errors", dial_errors),
                ("stream_rejects", stream_rejects),
                ("blocked", blocked),
                ("bw_saved_bytes", bw_saved),
                ("allowlist_overrides", allowlist_overrides),
                ("dns_cache_hits", dns_hits),
                ("dns_cache_misses", dns_misses),
                ("dns_cache_entries", dns_entries),
                ("dns_hit_rate", dns_hit_rate),
            ];

            // Fire-and-forget: spawn a detached task for the HTTP POST
            // so it never blocks the metric collection loop.
            let dd = dd.clone();
            tokio::spawn(async move {
                dd.post(batch).await;
            });
        }
    });
}
