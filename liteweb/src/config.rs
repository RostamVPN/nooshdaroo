//! LiteWeb configuration.

/// Configuration for the LiteWeb content proxy.
#[derive(Clone, Debug)]
pub struct LiteWebConfig {
    /// Maximum width for optimized images (pixels).
    pub image_max_width: u32,
    /// WebP quality (0-100).
    pub image_quality: u8,
    /// Maximum width for thumbnail images (pixels).
    pub thumbnail_width: u32,
    /// Maximum size of fetched page body (bytes).
    pub max_page_size: usize,
    /// Maximum size of processed output (bytes).
    pub max_output_size: usize,
    /// Maximum number of images to process per page.
    pub max_images_per_page: usize,
    /// Page cache TTL in seconds.
    pub cache_ttl_secs: u64,
    /// Maximum number of cached pages.
    pub cache_max_entries: usize,
    /// HTTP fetch timeout in seconds.
    pub fetch_timeout_secs: u64,
    /// File extensions that should be passed through (not processed).
    pub passthrough_extensions: Vec<String>,
}

impl Default for LiteWebConfig {
    fn default() -> Self {
        Self {
            image_max_width: 800,
            image_quality: 75,
            thumbnail_width: 150,
            max_page_size: 5 * 1024 * 1024,
            max_output_size: 200 * 1024,
            max_images_per_page: 10,
            cache_ttl_secs: 300,
            cache_max_entries: 200,
            fetch_timeout_secs: 15,
            passthrough_extensions: vec![
                ".pdf".into(),
                ".zip".into(),
                ".apk".into(),
                ".mp4".into(),
                ".mp3".into(),
            ],
        }
    }
}
