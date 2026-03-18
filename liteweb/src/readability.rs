//! Mozilla Readability-inspired content extraction using the `scraper` crate.

use scraper::{Html, Selector, ElementRef};

/// Result of readability extraction.
pub struct ReadabilityResult {
    pub title: String,
    pub byline: Option<String>,
    pub content_html: String,
    pub text_length: usize,
}

/// Positive class/id patterns that indicate article content.
const POSITIVE_PATTERNS: &[&str] = &[
    "article", "body", "content", "entry", "main", "post", "text", "blog", "story",
];

/// Negative class/id patterns that indicate non-content.
const NEGATIVE_PATTERNS: &[&str] = &[
    "hidden", "banner", "combx", "comment", "community", "cover-wrap", "disqus", "extra",
    "foot", "header", "legends", "menu", "related", "remark", "replies", "rss", "sharedaddy",
    "sidebar", "skyscraper", "social", "sponsor", "supplemental", "ad-break", "agegate",
    "pagination", "pager", "popup", "yom-", "nav", "widget",
];

/// Container elements eligible as top-level content candidates.
const CANDIDATE_TAGS: &[&str] = &["div", "section", "article", "td", "body", "main"];

/// Extract readable content from raw HTML.
pub fn extract(html: &str, url: &str) -> ReadabilityResult {
    let document = Html::parse_document(html);

    let title = extract_title(&document, url);
    let byline = extract_byline(&document);

    // Score candidate containers.
    let mut best_score: i64 = -1;
    let mut best_html = String::new();
    let mut best_text_len: usize = 0;

    for tag in CANDIDATE_TAGS {
        let sel = match Selector::parse(tag) {
            Ok(s) => s,
            Err(_) => continue,
        };
        for el in document.select(&sel) {
            let score = score_element(&el);
            if score > best_score {
                let inner = el.inner_html();
                let text_len = el.text().collect::<String>().len();
                best_score = score;
                best_html = inner;
                best_text_len = text_len;
            }
        }
    }

    // Fallback: if best candidate has very little text, use <body>.
    if best_text_len < 50 {
        if let Ok(sel) = Selector::parse("body") {
            if let Some(body) = document.select(&sel).next() {
                best_html = body.inner_html();
                best_text_len = body.text().collect::<String>().len();
            }
        }
    }

    ReadabilityResult {
        title,
        byline,
        content_html: best_html,
        text_length: best_text_len,
    }
}

fn score_element(el: &ElementRef) -> i64 {
    let mut score: i64 = 0;

    // Score based on class and id attributes.
    let class_id = format!(
        "{} {}",
        el.value().attr("class").unwrap_or(""),
        el.value().attr("id").unwrap_or("")
    ).to_lowercase();

    for pat in POSITIVE_PATTERNS {
        if class_id.contains(pat) {
            score += 25;
        }
    }
    for pat in NEGATIVE_PATTERNS {
        if class_id.contains(pat) {
            score -= 25;
        }
    }

    // Bonus for text length.
    let text: String = el.text().collect();
    let text_len = text.len();
    score += (text_len / 100) as i64;

    // Bonus for commas (indicates prose).
    let comma_count = text.matches(',').count();
    score += comma_count as i64;

    score
}

fn extract_title(doc: &Html, _url: &str) -> String {
    // Try og:title meta tag first.
    if let Ok(sel) = Selector::parse("meta[property=\"og:title\"]") {
        if let Some(el) = doc.select(&sel).next() {
            if let Some(content) = el.value().attr("content") {
                let t = content.trim();
                if !t.is_empty() {
                    return t.to_string();
                }
            }
        }
    }

    // Try <title> tag.
    if let Ok(sel) = Selector::parse("title") {
        if let Some(el) = doc.select(&sel).next() {
            let t = el.text().collect::<String>();
            let t = t.trim();
            if !t.is_empty() {
                // Strip site name after " - " or " | ".
                let cleaned = t
                    .split(" - ")
                    .next()
                    .unwrap_or(t)
                    .split(" | ")
                    .next()
                    .unwrap_or(t)
                    .trim();
                return cleaned.to_string();
            }
        }
    }

    // Try <h1>.
    if let Ok(sel) = Selector::parse("h1") {
        if let Some(el) = doc.select(&sel).next() {
            let t = el.text().collect::<String>();
            let t = t.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }

    "Untitled".to_string()
}

fn extract_byline(doc: &Html) -> Option<String> {
    // Try meta author.
    if let Ok(sel) = Selector::parse("meta[name=\"author\"]") {
        if let Some(el) = doc.select(&sel).next() {
            if let Some(content) = el.value().attr("content") {
                let t = content.trim();
                if !t.is_empty() {
                    return Some(t.to_string());
                }
            }
        }
    }

    // Try article:author meta.
    if let Ok(sel) = Selector::parse("meta[property=\"article:author\"]") {
        if let Some(el) = doc.select(&sel).next() {
            if let Some(content) = el.value().attr("content") {
                let t = content.trim();
                if !t.is_empty() {
                    return Some(t.to_string());
                }
            }
        }
    }

    // Try .author class.
    if let Ok(sel) = Selector::parse(".author") {
        if let Some(el) = doc.select(&sel).next() {
            let t = el.text().collect::<String>();
            let t = t.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }

    // Try [rel=author].
    if let Ok(sel) = Selector::parse("[rel=\"author\"]") {
        if let Some(el) = doc.select(&sel).next() {
            let t = el.text().collect::<String>();
            let t = t.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_simple_article() {
        let html = r#"
        <html>
        <head><title>Test Article - Example Site</title>
        <meta name="author" content="Jane Doe"></head>
        <body>
            <nav>Navigation stuff</nav>
            <div class="sidebar">Sidebar stuff</div>
            <article class="post-content">
                <h1>Test Article</h1>
                <p>This is a test article with enough text to be recognized as content.
                It has multiple sentences, commas, and various punctuation marks that
                help the scoring algorithm identify it as the main content area.
                Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do
                eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
                <p>Another paragraph of content here, with more text, more commas,
                and enough length to score well in the readability algorithm.</p>
            </article>
            <footer>Footer stuff</footer>
        </body>
        </html>"#;

        let result = extract(html, "https://example.com/test");
        assert_eq!(result.title, "Test Article");
        assert_eq!(result.byline, Some("Jane Doe".to_string()));
        assert!(result.content_html.contains("test article with enough text"));
        assert!(result.text_length > 50);
    }

    #[test]
    fn test_extract_fallback_body() {
        let html = r#"
        <html>
        <head><title>Short Page</title></head>
        <body><p>Short text.</p></body>
        </html>"#;

        let result = extract(html, "https://example.com/short");
        assert_eq!(result.title, "Short Page");
        assert!(result.content_html.contains("Short text"));
    }

    #[test]
    fn test_title_strip_site_name() {
        let html = r#"<html><head><title>My Article - The News Site</title></head>
        <body><p>Content</p></body></html>"#;
        let result = extract(html, "https://example.com");
        assert_eq!(result.title, "My Article");
    }
}
