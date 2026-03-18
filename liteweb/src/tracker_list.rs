//! Embedded tracker/ad domain blocklist for image filtering.

use once_cell::sync::Lazy;
use std::collections::HashSet;

pub static TRACKER_DOMAINS: Lazy<HashSet<String>> = Lazy::new(|| {
    let domains = [
        // Google
        "google-analytics.com",
        "googletagmanager.com",
        "googleadservices.com",
        "googlesyndication.com",
        "doubleclick.net",
        "googletagservices.com",
        "adservice.google.com",
        "pagead2.googlesyndication.com",
        "tpc.googlesyndication.com",
        "stats.g.doubleclick.net",
        "cm.g.doubleclick.net",
        // Facebook
        "facebook.net",
        "connect.facebook.net",
        "pixel.facebook.com",
        // Twitter/X
        "analytics.twitter.com",
        "ads-twitter.com",
        "static.ads-twitter.com",
        // Microsoft
        "bat.bing.com",
        "ads.linkedin.com",
        "snap.licdn.com",
        // Yandex
        "mc.yandex.ru",
        "metrika.yandex.ru",
        // Session replay
        "hotjar.com",
        "fullstory.com",
        "mouseflow.com",
        "luckyorange.com",
        // APM
        "newrelic.com",
        "nr-data.net",
        "bam.nr-data.net",
        // Analytics platforms
        "segment.io",
        "segment.com",
        "cdn.segment.com",
        "mixpanel.com",
        "api.mixpanel.com",
        "cdn.mxpnl.com",
        "amplitude.com",
        "api.amplitude.com",
        "heapanalytics.com",
        "app.pendo.io",
        // Error tracking
        "sentry.io",
        "browser.sentry-cdn.com",
        "bugsnag.com",
        // CRO
        "crazyegg.com",
        "optimizely.com",
        "cdn.optimizely.com",
        // Cloudflare analytics
        "cloudflareinsights.com",
        // Privacy-friendly (still trackers)
        "plausible.io",
        "matomo.cloud",
        // Chat widgets
        "intercom.io",
        "widget.intercom.io",
        "crisp.chat",
        "drift.com",
        "tawk.to",
        // Notifications
        "onesignal.com",
        "pusher.com",
        // Ad exchanges
        "adsrvr.org",
        "adnxs.com",
        "openx.net",
        "pubmatic.com",
        "rubiconproject.com",
        "contextweb.com",
        "indexexchange.com",
        "casalemedia.com",
        // Ad verification
        "moatads.com",
        "doubleverify.com",
        "adsafeprotected.com",
        // Content analytics
        "chartbeat.com",
        "parsely.com",
        "scorecardresearch.com",
        "sb.scorecardresearch.com",
        "b.scorecardresearch.com",
        // Audience measurement
        "quantserve.com",
        "secure.quantserve.com",
        "pixel.quantserve.com",
        "serving-sys.com",
        "turn.com",
        // Content recommendation
        "taboola.com",
        "outbrain.com",
        "mgid.com",
        "revcontent.com",
        // Ad networks
        "amazon-adsystem.com",
        "media.net",
        "criteo.com",
        "criteo.net",
        // Retargeting
        "adroll.com",
        "perfectaudience.com",
        "steelhousemedia.com",
        // Social sharing (tracking)
        "sharethis.com",
        "addthis.com",
        "shareaholic.com",
        // Comments (tracking)
        "disqus.com",
        "spot.im",
        // CAPTCHA
        "recaptcha.net",
        // Cookie consent (tracking)
        "cookiebot.com",
        "cookieinformation.com",
        "onetrust.com",
        "cookielaw.org",
        "trustarc.com",
        "evidon.com",
        // Mobile attribution
        "branch.io",
        "app.link",
        "adjust.com",
        "appsflyer.com",
        "kochava.com",
        "singular.net",
        // Adobe
        "demdex.net",
        "omtrdc.net",
        "2o7.net",
        "sc.omtrdc.net",
    ];

    domains.iter().map(|d| d.to_string()).collect()
});

/// Check if a domain is in the tracker list.
/// Matches exact domain or with "www." prefix stripped.
pub fn is_tracker(domain: &str) -> bool {
    let lower = domain.to_lowercase();
    if TRACKER_DOMAINS.contains(&lower) {
        return true;
    }
    let stripped = lower.strip_prefix("www.").unwrap_or(&lower);
    TRACKER_DOMAINS.contains(stripped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_trackers() {
        assert!(is_tracker("google-analytics.com"));
        assert!(is_tracker("www.google-analytics.com"));
        assert!(is_tracker("doubleclick.net"));
        assert!(is_tracker("pixel.facebook.com"));
    }

    #[test]
    fn test_non_trackers() {
        assert!(!is_tracker("example.com"));
        assert!(!is_tracker("wikipedia.org"));
        assert!(!is_tracker("cdn.example.com"));
    }
}
