//! The public statistics page.
//!
//! A self-contained HTML document: inline CSS, no JavaScript, no external
//! resources. A Content-Security-Policy with the hash of the inline style is
//! embedded, so it holds even when the web server sends no header. The page
//! renders aggregate counts only (Section 11): no individual IP, prefix or
//! domain is ever shown.

use std::fmt::Write;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::stats::Stats;

const CSS: &str = r#"
:root { color-scheme: light dark; --fg:#182230; --muted:#5b6675; --line:#d5dbe3; --bg:#f4f6f8; --card:#ffffff; --accent:#0b6e4f; }
@media (prefers-color-scheme: dark) { :root { --fg:#e6ebf2; --muted:#9aa6b5; --line:#2a333f; --bg:#12161c; --card:#1a212b; --accent:#3fb88f; } }
* { box-sizing: border-box; }
body { margin:0; font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; color:var(--fg); background:var(--bg); }
.wrap { max-width: 960px; margin:0 auto; padding:28px 20px 56px; }
header { margin-bottom:24px; }
h1 { font-size:26px; margin:0 0 6px; letter-spacing:-.01em; }
.meta { color:var(--muted); margin:0; font-size:14px; }
.badge { display:inline-block; margin-top:10px; padding:3px 10px; border-radius:999px; font-size:12.5px; font-weight:600; letter-spacing:.02em; background:color-mix(in srgb, var(--accent) 15%, transparent); color:var(--accent); border:1px solid color-mix(in srgb, var(--accent) 40%, transparent); }
.stale { margin-top:10px; padding:8px 12px; border-radius:8px; font-size:14px; background:color-mix(in srgb, #b45309 12%, transparent); border:1px solid color-mix(in srgb, #b45309 40%, transparent); }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:14px; margin:0 0 26px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px 18px; }
.card .n { font-size:30px; font-weight:700; line-height:1.1; }
.card .l { color:var(--muted); font-size:13.5px; margin-top:4px; }
section { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:18px 20px; margin:0 0 20px; }
h2 { font-size:17px; margin:0 0 14px; }
table { width:100%; border-collapse:collapse; font-size:14px; }
th, td { text-align:left; padding:7px 10px; border-bottom:1px solid var(--line); }
th { color:var(--muted); font-weight:600; font-size:12.5px; text-transform:uppercase; letter-spacing:.04em; }
td.n, th.n { text-align:right; font-variant-numeric:tabular-nums; }
tr:last-child td { border-bottom:none; }
.bar { display:inline-block; height:8px; border-radius:4px; background:var(--accent); vertical-align:middle; }
.note { color:var(--muted); font-size:13px; margin:6px 0 0; }
footer { color:var(--muted); font-size:13px; margin-top:28px; line-height:1.6; }
.empty { color:var(--muted); }
"#;

pub struct Page<'a> {
    pub title: &'a str,
    /// When the underlying data was last fetched from the hub.
    pub generated: DateTime<Utc>,
    /// Set when the hub is unreachable and the last snapshot is shown.
    pub stale: bool,
    pub stats: &'a Stats,
    pub window_days: u32,
    pub interval_secs: u64,
}

/// Escape text for inclusion in HTML.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// CSP source expression for an inline element's content.
pub fn csp_hash(content: &str) -> String {
    let h = Sha256::digest(content.as_bytes());
    let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
    format!("'sha256-{hex}'")
}

pub fn content_security_policy() -> String {
    format!(
        "default-src 'none'; style-src {}; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'self'",
        csp_hash(CSS)
    )
}

fn fmt_time(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// A behaviour distribution table with relative bars.
fn behavior_table(rows: &[(apti_core::Behavior, usize)], empty: &str) -> String {
    if rows.is_empty() {
        return format!("<p class=\"empty\">{empty}</p>");
    }
    let max = rows.iter().map(|(_, n)| *n).max().unwrap_or(1).max(1);
    let mut h = String::from(
        "<table><thead><tr><th>Behaviour</th><th class=\"n\">Count</th><th style=\"width:38%\"></th></tr></thead><tbody>",
    );
    for (b, n) in rows {
        let width = *n as f64 / max as f64 * 100.0;
        let _ = write!(
            h,
            "<tr><td>{}</td><td class=\"n\">{n}</td><td><span class=\"bar\" style=\"width:{:.0}%\"></span></td></tr>",
            escape(b.as_str()),
            width
        );
    }
    h.push_str("</tbody></table>");
    h
}

fn type_row(label: &str, n: usize) -> String {
    format!("<tr><td>{label}</td><td class=\"n\">{n}</td></tr>")
}

pub fn page(p: &Page) -> String {
    let s = p.stats;
    let generated = escape(&fmt_time(p.generated));
    let stale = if p.stale {
        "<p class=\"stale\">The hub is currently unreachable; these are the last successfully \
         fetched figures.</p>"
    } else {
        ""
    };
    let c = |label: &str, n: u64| {
        format!(
            "<div class=\"card\"><div class=\"n\">{n}</div><div class=\"l\">{label}</div></div>"
        )
    };

    let mut h = String::with_capacity(32 * 1024);
    let title = escape(p.title);
    let _ = write!(
        h,
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{csp}">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow">
<title>{title}</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
<header>
<h1>{title}</h1>
<p class="meta">Data as of {generated} UTC &middot; refreshed every {interval}s</p>
<p><span class="badge">TLP:CLEAR only</span></p>
{stale}
</header>
<div class="grid">
{nodes_card}
{evidence_card}
{active_card}
{findings_card}
</div>"#,
        csp = escape(&content_security_policy()),
        interval = p.interval_secs,
        nodes_card = c("connected nodes", s.nodes as u64),
        evidence_card = c("evidence ingested", s.evidence_ingested),
        active_card = c("active observables", s.active_total as u64),
        findings_card = c(
            &format!("findings in last {} days", p.window_days),
            s.findings_total as u64
        ),
    );

    let _ = write!(
        h,
        r#"<section>
<h2>Active observables</h2>
<table>
{type_rows}
</table>
<p class="note">{flagged_note}</p>
<h2 style="margin-top:20px">By behaviour</h2>
{active_behaviors}
</section>
<section>
<h2>Findings in the last {window} days</h2>
<table>
{findings_types}
</table>
<h2 style="margin-top:20px">By behaviour</h2>
{findings_behaviors}
</section>
<footer>
<p>Figures are aggregates over the hub&rsquo;s TLP:CLEAR dataset. Individual IP addresses,
prefixes and domains are personal data even at TLP:CLEAR and are therefore never published.
An observable is active once enough connected nodes of distinct operators report it to meet the
hub&rsquo;s quorum. Operators are self-declared, so this means &ldquo;reported by several
feeds&rdquo;, not a verdict.</p>
<p>Generated by apti-statsd {version}.</p>
</footer>
</div>
</body>
</html>
"#,
        type_rows = [
            type_row("IPv4 addresses", s.active_ipv4),
            type_row("IPv6 addresses", s.active_ipv6),
            type_row("Domains", s.active_domains),
        ]
        .join("\n"),
        flagged_note = if s.active_flagged > 0 {
            format!(
                "{} active observable(s) are under dispute.",
                s.active_flagged
            )
        } else {
            "No active observable is currently under dispute.".to_string()
        },
        active_behaviors = behavior_table(&s.active_by_behavior, "No active observables."),
        window = p.window_days,
        findings_types = [
            type_row("IPv4 addresses", s.findings_ipv4),
            type_row("IPv6 addresses", s.findings_ipv6),
            type_row("Domains", s.findings_domains),
        ]
        .join("\n"),
        findings_behaviors = behavior_table(&s.findings_by_behavior, "No findings in this window."),
        version = env!("CARGO_PKG_VERSION"),
    );
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ActiveEntry, NodeInfo, TimelineEntry, TimelineOrigin};
    use apti_core::{Behavior, EvidenceKind, ObservableType, Tlp};
    use chrono::Utc;

    fn sample() -> Stats {
        let active = vec![
            ActiveEntry {
                observable_type: ObservableType::Ipv4Addr,
                observable_value: "45.13.7.9".into(),
                behavior: Behavior::Scan,
                include_subdomains: false,
                effective_expiry: Utc::now(),
                ttl: 1,
                tlp: Tlp::Clear,
                flagged: false,
                ports: vec![],
                services: vec![],
            },
            ActiveEntry {
                observable_type: ObservableType::DomainName,
                observable_value: "evil.example".into(),
                behavior: Behavior::Phishing,
                include_subdomains: false,
                effective_expiry: Utc::now(),
                ttl: 1,
                tlp: Tlp::Clear,
                flagged: true,
                ports: vec![],
                services: vec![],
            },
        ];
        let findings = vec![TimelineEntry {
            observable_type: ObservableType::Ipv4Addr,
            observable_value: "45.13.7.10".into(),
            behavior: Behavior::Scan,
            kind: EvidenceKind::Sighting,
            origin: TimelineOrigin::Federated,
            actor: "a".into(),
            start: Utc::now(),
            end: Utc::now(),
            count: None,
            tlp: Tlp::Clear,
        }];
        Stats::compute(
            &active,
            &findings,
            &[NodeInfo {
                actor: "a".into(),
                handle: None,
                name: None,
                summary: None,
                operator: None,
                evidence: 7,
                state: "accepted".into(),
            }],
        )
    }

    fn render(stale: bool) -> String {
        page(&Page {
            title: "Hub <stats> \"x\"",
            generated: Utc::now(),
            stale,
            stats: &sample(),
            window_days: 30,
            interval_secs: 60,
        })
    }

    #[test]
    fn no_observables_are_exposed() {
        let html = render(false);
        // The raw values only exist in the hub's data, never on the page.
        for v in ["45.13.7.9", "45.13.7.10", "evil.example", "45.13.7"] {
            assert!(!html.contains(v), "{v} leaked onto the page");
        }
        assert!(html.contains("<title>Hub &lt;stats&gt; &quot;x&quot;</title>"));
        assert!(html.contains("TLP:CLEAR only"));
        // Self-contained: no script, no external references.
        assert!(!html.contains("<script"));
        assert!(!html.contains("src="));
        assert!(!html.contains("href="));
    }

    #[test]
    fn csp_matches_inline_style() {
        let html = render(false);
        let style_start = html.find("<style>").unwrap() + 7;
        let style_end = style_start + html[style_start..].find("</style>").unwrap();
        let csp = content_security_policy();
        assert!(csp.contains(&csp_hash(&html[style_start..style_end])));
        assert!(html.contains(&escape(&csp)));
        assert!(csp.starts_with("default-src 'none'"));
    }

    #[test]
    fn renders_counts_and_stale_banner() {
        let html = render(true);
        assert!(html.contains("unreachable"));
        assert!(html.contains("<div class=\"n\">1</div>")); // nodes
        assert!(html.contains("under dispute"));
        let fresh = render(false);
        assert!(!fresh.contains("unreachable"));
    }
}
