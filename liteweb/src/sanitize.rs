//! HTML sanitization: allowed elements/attributes, tracker removal, URL cleaning.

use scraper::{Html, Node};
use std::collections::HashSet;
use url::Url;

/// Tracking query parameters to strip from URLs.
const TRACKING_PARAMS: &[&str] = &[
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "mc_cid", "mc_eid", "_ga", "_gl", "ref", "source", "ocid",
];

/// Tracking image URL patterns (any img src containing these gets removed).
const TRACKING_IMG_PATTERNS: &[&str] = &[
    "/pixel", "/beacon", "1x1", "__utm", "tr.gif", "spacer.gif",
];

/// Elements allowed in sanitized output.
const ALLOWED_ELEMENTS: &[&str] = &[
    "p", "h1", "h2", "h3", "h4", "h5", "h6",
    "a", "img", "ul", "ol", "li",
    "blockquote", "pre", "code",
    "table", "thead", "tbody", "tr", "th", "td",
    "br", "hr",
    "strong", "em", "b", "i",
    "figure", "figcaption",
    "sup", "sub",
];

/// Sanitize HTML content: keep only allowed elements/attributes,
/// strip trackers, clean URLs.
pub fn sanitize(html: &str, base_url: &str, tracker_domains: &HashSet<String>) -> String {
    let base = Url::parse(base_url).ok();
    let fragment = Html::parse_fragment(html);
    let allowed: HashSet<&str> = ALLOWED_ELEMENTS.iter().copied().collect();

    let mut output = String::with_capacity(html.len());
    walk_node(
        fragment.tree.root(),
        &fragment,
        &allowed,
        &base,
        tracker_domains,
        &mut output,
    );

    collapse_br(&output)
}

fn walk_node(
    node_ref: ego_tree::NodeRef<'_, Node>,
    _doc: &Html,
    allowed: &HashSet<&str>,
    base: &Option<Url>,
    tracker_domains: &HashSet<String>,
    out: &mut String,
) {
    for child in node_ref.children() {
        match child.value() {
            Node::Text(text) => {
                out.push_str(&html_escape(&text));
            }
            Node::Element(el) => {
                let tag = el.name();

                if tag == "script" || tag == "style" || tag == "noscript" || tag == "iframe" {
                    // Skip entirely.
                    continue;
                }

                if allowed.contains(tag) {
                    // Special handling for <img>.
                    if tag == "img" {
                        if let Some(src) = el.attr("src") {
                            let resolved = resolve_url(src, base);

                            // Check tracker domain.
                            if is_tracker_img(&resolved, tracker_domains) {
                                continue;
                            }

                            // Check tracking URL patterns.
                            let src_lower = resolved.to_lowercase();
                            if TRACKING_IMG_PATTERNS.iter().any(|p| src_lower.contains(p)) {
                                continue;
                            }

                            let alt = el.attr("alt").unwrap_or("");
                            out.push_str(&format!(
                                "<img src=\"{}\" alt=\"{}\">",
                                html_escape_attr(&resolved),
                                html_escape_attr(alt)
                            ));
                        }
                        continue;
                    }

                    // Special handling for <a>.
                    if tag == "a" {
                        let href = el.attr("href").map(|h| {
                            let resolved = resolve_url(h, base);
                            strip_tracking_params(&resolved)
                        });

                        if let Some(ref href) = href {
                            out.push_str(&format!("<a href=\"{}\">", html_escape_attr(href)));
                        } else {
                            out.push_str("<a>");
                        }
                        walk_node(child, _doc, allowed, base, tracker_domains, out);
                        out.push_str("</a>");
                        continue;
                    }

                    // Self-closing tags.
                    if tag == "br" {
                        out.push_str("<br>");
                        continue;
                    }
                    if tag == "hr" {
                        out.push_str("<hr>");
                        continue;
                    }

                    // Normal allowed element: no attributes (except a/img handled above).
                    out.push_str(&format!("<{}>", tag));
                    walk_node(child, _doc, allowed, base, tracker_domains, out);
                    out.push_str(&format!("</{}>", tag));
                } else {
                    // Not allowed: extract text content, discard tag.
                    walk_node(child, _doc, allowed, base, tracker_domains, out);
                }
            }
            _ => {
                // Comments, processing instructions, etc. — skip.
            }
        }
    }
}

fn resolve_url(href: &str, base: &Option<Url>) -> String {
    if href.starts_with("http://") || href.starts_with("https://") || href.starts_with("data:") {
        return href.to_string();
    }
    if let Some(base) = base {
        if let Ok(resolved) = base.join(href) {
            return resolved.to_string();
        }
    }
    href.to_string()
}

fn strip_tracking_params(url: &str) -> String {
    if let Ok(mut parsed) = Url::parse(url) {
        let pairs: Vec<(String, String)> = parsed
            .query_pairs()
            .filter(|(k, _)| !TRACKING_PARAMS.contains(&k.as_ref()))
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        if pairs.is_empty() {
            parsed.set_query(None);
        } else {
            let qs: Vec<String> = pairs.iter().map(|(k, v)| {
                if v.is_empty() {
                    k.clone()
                } else {
                    format!("{}={}", k, v)
                }
            }).collect();
            parsed.set_query(Some(&qs.join("&")));
        }
        parsed.to_string()
    } else {
        url.to_string()
    }
}

fn is_tracker_img(src: &str, tracker_domains: &HashSet<String>) -> bool {
    if let Ok(parsed) = Url::parse(src) {
        if let Some(host) = parsed.host_str() {
            let host_lower = host.to_lowercase();
            // Check exact domain match.
            if tracker_domains.contains(&host_lower) {
                return true;
            }
            // Check with www. stripped.
            let stripped = host_lower.strip_prefix("www.").unwrap_or(&host_lower);
            if tracker_domains.contains(stripped) {
                return true;
            }
        }
    }
    false
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn html_escape_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Collapse runs of <br> to max 2 consecutive.
fn collapse_br(html: &str) -> String {
    let re = regex::Regex::new(r"(<br>\s*){3,}").unwrap();
    re.replace_all(html, "<br><br>").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_trackers() -> HashSet<String> {
        HashSet::new()
    }

    #[test]
    fn test_sanitize_basic() {
        let html = r#"<p>Hello <strong>world</strong></p><script>alert('xss')</script>"#;
        let result = sanitize(html, "https://example.com", &empty_trackers());
        assert!(result.contains("<p>Hello <strong>world</strong></p>"));
        assert!(!result.contains("script"));
        assert!(!result.contains("alert"));
    }

    #[test]
    fn test_strip_tracking_params() {
        let url = "https://example.com/page?id=1&utm_source=twitter&utm_medium=social&real=yes";
        let result = strip_tracking_params(url);
        assert!(result.contains("id=1"));
        assert!(result.contains("real=yes"));
        assert!(!result.contains("utm_source"));
        assert!(!result.contains("utm_medium"));
    }

    #[test]
    fn test_remove_tracker_img() {
        let mut trackers = HashSet::new();
        trackers.insert("google-analytics.com".to_string());

        let html = r#"<p>Text</p><img src="https://google-analytics.com/collect?v=1" alt="tracker"><p>More</p>"#;
        let result = sanitize(html, "https://example.com", &trackers);
        assert!(!result.contains("google-analytics"));
        assert!(result.contains("Text"));
        assert!(result.contains("More"));
    }

    #[test]
    fn test_resolve_relative_url() {
        let html = r#"<a href="/about">About</a>"#;
        let result = sanitize(html, "https://example.com/page", &empty_trackers());
        assert!(result.contains("https://example.com/about"));
    }

    #[test]
    fn test_collapse_br() {
        let html = "<br><br><br><br><br>";
        let result = collapse_br(html);
        assert_eq!(result, "<br><br>");
    }
}
