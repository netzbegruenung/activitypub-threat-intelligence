//! The public statistics page.
//!
//! A self-contained HTML document: inline CSS, no JavaScript, no external
//! resources. A Content-Security-Policy with the hash of the inline style is
//! embedded, so it holds even when the web server sends no header. The page
//! renders aggregate counts only (Section 11): no individual IP, prefix or
//! domain is ever shown.

use std::fmt::Write;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::stats::Stats;

const CSS: &str = r#"
:root { color-scheme: dark; --bg:#04070a; --fg:#33ff99; --dim:#1d7a52; --amber:#ffb000; --line:#0e2a1e; --card:#060b0e; }
* { box-sizing: border-box; }
html { background:var(--bg); color:var(--fg); font:16px/1.6 "DejaVu Sans Mono","Liberation Mono","Courier New",monospace; }
body { margin:0; text-shadow:0 0 6px rgba(51,255,153,.35); }
body::after { content:""; position:fixed; inset:0; pointer-events:none; z-index:1; background:radial-gradient(ellipse at center, rgba(0,0,0,0) 55%, rgba(0,0,0,.75) 100%); }
.wrap { max-width:56rem; margin-inline:auto; padding:2.5rem 1.25rem 5rem; }
pre.banner { color:var(--fg); font-size:clamp(.4rem,1.75vw,.85rem); line-height:1.1; margin:0 0 .75rem; overflow-x:clip; }
header { margin-bottom:2rem; }
h1 { font-size:1rem; font-weight:normal; color:var(--amber); margin:0 0 .35rem; }
.meta { color:var(--dim); margin:0; font-size:.85rem; }
.badge { display:inline-block; margin-top:.6rem; padding:.1rem .6rem; font-size:.8rem; color:var(--amber); border:1px solid var(--amber); }
.stale { margin-top:.6rem; padding:.5rem .75rem; font-size:.9rem; color:var(--amber); border:1px solid var(--amber); border-left-width:3px; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(11rem,1fr)); gap:.75rem; margin:0 0 1.5rem; }
.card { background:#000; border:1px solid var(--line); border-left:3px solid var(--dim); padding:.9rem 1rem; }
.card .n { font-size:1.9rem; line-height:1.1; color:var(--amber); }
.card .l { color:var(--dim); font-size:.8rem; margin-top:.25rem; }
section { margin:0 0 1.5rem; }
h2 { font-size:1rem; font-weight:normal; color:var(--amber); border-bottom:1px solid var(--line); padding-bottom:.35rem; margin:2rem 0 1rem; }
h2::before { content:"[ "; color:var(--dim); }
h2::after { content:" ]"; color:var(--dim); }
table { width:100%; border-collapse:collapse; font-size:.9rem; }
th, td { text-align:left; padding:.45rem .7rem; border:1px solid var(--line); vertical-align:top; }
th { color:var(--amber); font-weight:normal; }
td.n, th.n { text-align:right; font-variant-numeric:tabular-nums; }
h2.sub { margin-top:1.5rem; }
td.bar { color:var(--amber); white-space:nowrap; width:1%; }
td.bar .o { color:var(--dim); opacity:.5; }
.note { color:var(--dim); font-size:.85rem; margin:.5rem 0 0; }
footer { color:var(--dim); font-size:.85rem; margin-top:4rem; padding-top:1rem; border-top:1px solid var(--line); }
footer p { margin:0 0 .75rem; }
.empty { color:var(--dim); }
"#;

const BANNER: &str = r#" ██████╗ ██╗   ██╗██████╗ ███████╗███████╗ ██████╗
 ██╔══██╗██║   ██║██╔══██╗██╔════╝██╔════╝██╔════╝
 ██████╔╝██║   ██║██████╔╝███████╗█████╗  ██║
 ██╔═══╝ ██║   ██║██╔══██╗╚════██║██╔══╝  ██║
 ██║     ╚██████╔╝██████╔╝███████║███████╗╚██████╗
 ╚═╝      ╚═════╝ ╚═════╝ ╚══════╝╚══════╝ ╚═════╝"#;

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
    format!(
        "'sha256-{}'",
        STANDARD.encode(Sha256::digest(content.as_bytes()))
    )
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

/// Width of a distribution bar, in characters.
const BAR_CELLS: usize = 24;

/// A bar drawn with block characters, so no per-element style attribute is
/// needed and the page stays within its style-src hash.
fn bar(n: usize, max: usize) -> String {
    let filled = ((n as f64 / max as f64) * BAR_CELLS as f64).round() as usize;
    let filled = filled.clamp(if n > 0 { 1 } else { 0 }, BAR_CELLS);
    format!(
        "{}<span class=\"o\">{}</span>",
        "\u{2588}".repeat(filled),
        "\u{2591}".repeat(BAR_CELLS - filled)
    )
}

/// A behaviour distribution table with relative bars.
fn behavior_table(rows: &[(pubsec_core::Behavior, usize)], empty: &str) -> String {
    if rows.is_empty() {
        return format!("<p class=\"empty\">{empty}</p>");
    }
    let max = rows.iter().map(|(_, n)| *n).max().unwrap_or(1).max(1);
    let mut h = String::from(
        "<table><thead><tr><th>Behaviour</th><th class=\"n\">Count</th><th></th></tr></thead><tbody>",
    );
    for (b, n) in rows {
        let _ = write!(
            h,
            "<tr><td>{}</td><td class=\"n\">{n}</td><td class=\"bar\">{}</td></tr>",
            escape(b.as_str()),
            bar(*n, max)
        );
    }
    h.push_str("</tbody></table>");
    h
}

/// The connected nodes, with the evidence each contributed.
fn node_table(rows: &[crate::stats::NodeRow]) -> String {
    if rows.is_empty() {
        return "<p class=\"empty\">No node is connected.</p>".to_string();
    }
    let mut h = String::from(
        "<table><thead><tr><th>Node</th><th>Operator</th><th class=\"n\">Evidence</th></tr></thead><tbody>",
    );
    for r in rows {
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td class=\"n\">{}</td></tr>",
            escape(&r.label),
            escape(r.operator.as_deref().unwrap_or("—")),
            r.evidence
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
<link rel="icon" href="data:,">
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
<pre class="banner">{banner}</pre>
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
        banner = BANNER,
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
<h2 class="sub">By behaviour</h2>
{active_behaviors}
</section>
<section>
<h2>Findings in the last {window} days</h2>
<table>
{findings_types}
</table>
<h2 class="sub">By behaviour</h2>
{findings_behaviors}
</section>
<section>
<h2>Connected nodes</h2>
{nodes_table}
<p class="note">Nodes the hub has accepted a follow from, as they describe themselves. The
operator is self-declared and is not verified.</p>
</section>
<footer>
<p>Figures are aggregates over the hub&rsquo;s TLP:CLEAR dataset. Individual IP addresses,
prefixes and domains are personal data even at TLP:CLEAR and are therefore never published.
An observable is active once enough connected nodes of distinct operators report it to meet the
hub&rsquo;s quorum. Operators are self-declared, so this means &ldquo;reported by several
feeds&rdquo;, not a verdict.</p>
<p>Generated by pubsec-statsd {version}.</p>
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
        nodes_table = node_table(&s.node_list),
        version = env!("CARGO_PKG_VERSION"),
    );
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ActiveEntry, NodeInfo, TimelineEntry, TimelineOrigin};
    use chrono::Utc;
    use pubsec_core::{Behavior, EvidenceKind, ObservableType, Tlp};

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
                handle: Some("feed@peer.example".into()),
                name: None,
                summary: None,
                operator: Some("Peer Org".into()),
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
        // The empty inline icon is the only href, and it fetches nothing.
        assert_eq!(html.matches("href=").count(), 1);
        assert!(html.contains(r#"<link rel="icon" href="data:,">"#));
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
        // Style attributes are not covered by a style-src hash, so the page
        // must not use any.
        assert!(!html.contains("style=\""));
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

    #[test]
    fn lists_connected_nodes() {
        let html = render(false);
        assert!(html.contains("Connected nodes"));
        assert!(html.contains("feed@peer.example"));
        assert!(html.contains("Peer Org"));
        assert!(page(&Page {
            title: "Hub",
            generated: Utc::now(),
            stale: false,
            stats: &Stats::default(),
            window_days: 30,
            interval_secs: 60,
        })
        .contains("No node is connected."));
    }
}
