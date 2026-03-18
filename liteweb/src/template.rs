//! Minimal HTML template wrapper for processed content.

/// Wrap extracted content in a complete, minimal HTML document.
pub fn wrap(title: &str, byline: Option<&str>, content: &str) -> String {
    let byline_html = if let Some(author) = byline {
        format!(
            "<div class=\"byline\">{}</div>",
            html_escape(author)
        )
    } else {
        String::new()
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
body{{max-width:680px;margin:0 auto;padding:16px;font-family:system-ui,-apple-system,sans-serif;font-size:18px;line-height:1.6;color:#222;background:#fff}}
h1{{font-size:1.5em;line-height:1.2;margin:0 0 8px}}
h2{{font-size:1.3em;margin:24px 0 8px}}
h3,h4,h5,h6{{font-size:1.1em;margin:20px 0 8px}}
a{{color:#1a73e8;text-decoration:none}}
a:hover{{text-decoration:underline}}
img{{max-width:100%;height:auto;border-radius:4px;margin:8px 0}}
blockquote{{border-left:3px solid #ddd;margin:16px 0;padding:4px 16px;color:#555}}
pre{{background:#f5f5f5;padding:12px;overflow-x:auto;border-radius:4px;font-size:14px}}
code{{background:#f5f5f5;padding:2px 4px;border-radius:2px;font-size:0.9em}}
pre code{{background:none;padding:0}}
table{{border-collapse:collapse;width:100%;margin:16px 0}}
th,td{{border:1px solid #ddd;padding:8px;text-align:left}}
.byline{{color:#666;font-size:0.9em;margin-bottom:16px}}
@media(prefers-color-scheme:dark){{body{{background:#1a1a1a;color:#e0e0e0}}a{{color:#8ab4f8}}blockquote{{border-color:#444;color:#aaa}}pre,code{{background:#2a2a2a}}th,td{{border-color:#444}}.byline{{color:#999}}}}
</style>
</head>
<body>
<h1>{title}</h1>
{byline_html}
{content}
<p style="color:#999;font-size:0.8em;margin-top:32px;border-top:1px solid #eee;padding-top:8px">LiteWeb &mdash; optimized for low-bandwidth</p>
</body>
</html>"#,
        title = html_escape(title),
        byline_html = byline_html,
        content = content,
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
