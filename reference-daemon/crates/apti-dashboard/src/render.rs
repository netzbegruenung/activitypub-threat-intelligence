//! Self-contained HTML page: inline SVG map, CSS, data and script.
//!
//! The page loads nothing from elsewhere. A Content-Security-Policy with
//! hashes of the inline script and style is embedded, so it also holds when
//! the web server sends no header. Without JavaScript, the map and table show
//! the latest window for all behaviours and origins.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;
use std::sync::OnceLock;

use apti_core::Tlp;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::details::Details;
use crate::frames::{self, Frames, CLASSES};
use crate::geo::UNKNOWN;

const CSS: &str = include_str!("../assets/dashboard.css");
const JS: &str = include_str!("../assets/dashboard.js");
const WORLD: &str = include_str!("../assets/world.tsv");

/// Countries of the vendored map (Natural Earth 1:110m).
pub struct WorldMap {
    pub view_box: &'static str,
    /// `(code, name, path)`, sorted by code.
    pub countries: Vec<(&'static str, &'static str, &'static str)>,
}

pub fn world() -> &'static WorldMap {
    static MAP: OnceLock<WorldMap> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut lines = WORLD.lines();
        let view_box = lines
            .next()
            .and_then(|l| l.strip_prefix("#viewBox "))
            .expect("world.tsv starts with #viewBox");
        let countries = lines
            .filter_map(|l| {
                let mut f = l.splitn(3, '\t');
                Some((f.next()?, f.next()?, f.next()?))
            })
            .collect();
        WorldMap {
            view_box,
            countries,
        }
    })
}

pub struct Page<'a> {
    pub title: &'a str,
    pub generated: DateTime<Utc>,
    pub frames: &'a Frames,
    /// Country names from the GeoIP database, for countries not on the map.
    pub names: &'a HashMap<String, String>,
    /// Most restrictive TLP of the data shown; `None` if there is none.
    pub tlp: Option<Tlp>,
    /// Extra lines for the footer.
    pub notes: Vec<String>,
    /// Observables behind the counts; `None` = counts only.
    pub details: Option<&'a Details>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Data<'a> {
    #[serde(flatten)]
    frames: &'a Frames,
    names: BTreeMap<&'a str, &'a str>,
    classes: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<&'a Details>,
}

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

/// JSON that can sit inside a `<script>` element: `<`, `>` and `&` only
/// occur in strings and are written as Unicode escapes.
pub fn script_json<T: Serialize>(v: &T) -> String {
    serde_json::to_string(v)
        .expect("serialisable")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
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
        "default-src 'none'; script-src {}; style-src {}; img-src data:; base-uri 'none'; form-action 'none'",
        csp_hash(JS),
        csp_hash(CSS)
    )
}

fn fmt_time(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M").to_string()
}

/// `(class, lowest, highest)` count of each colour class that occurs.
pub fn legend(max: u32) -> Vec<(u8, u32, u32)> {
    let mut out: Vec<(u8, u32, u32)> = Vec::new();
    for n in 1..=max {
        let c = frames::class(n, max);
        match out.last_mut() {
            Some(last) if last.0 == c => last.2 = n,
            _ => out.push((c, n, n)),
        }
    }
    out
}

pub fn page(p: &Page) -> String {
    let f = p.frames;
    let map = world();
    let last = f.frames.len() - 1;
    let series = f.series(0, 0);
    let counts = frames::frame_counts(f, series, last);

    let mut names: BTreeMap<&str, &str> = BTreeMap::new();
    for c in &f.countries {
        if let Some(n) = p.names.get(c) {
            names.insert(c, n);
        }
    }
    for (code, name, _) in &map.countries {
        if f.countries.iter().any(|c| c == code) {
            names.insert(code, name);
        }
    }
    names.insert(UNKNOWN, "Unknown");
    let name_of = |c: &str| names.get(c).copied().unwrap_or(c).to_string();

    let data = script_json(&Data {
        frames: f,
        names: names.clone(),
        classes: CLASSES,
        details: p.details,
    });
    let (tlp_class, tlp_text) = match p.tlp {
        Some(t) => (
            t.as_str().replace('+', "-"),
            format!("TLP:{}", t.as_str().to_ascii_uppercase()),
        ),
        None => ("none".into(), "No data".into()),
    };
    let window_end = f.frames[last];
    let window_start = window_end - chrono::TimeDelta::hours(f.window_hours);

    let mut h = String::with_capacity(256 * 1024);
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
<header>
<h1>{title}</h1>
<p class="meta">Generated {generated} UTC &middot; window {window} &middot; step {step}</p>
<p class="tlp tlp-{tlp_class}" title="Most restrictive TLP of the data on this page">{tlp_text}</p>
</header>
<main>
<section class="panel" aria-label="Map">
<div class="controls" id="controls" hidden>
<label>Behaviour <select id="behavior">"#,
        csp = escape(&content_security_policy()),
        generated = escape(&fmt_time(p.generated)),
        window = escape(&duration(f.window_hours)),
        step = escape(&duration(step_hours(f))),
    );
    for (i, b) in f.behaviors.iter().enumerate() {
        let label = if i == 0 { "All" } else { b };
        let _ = write!(h, r#"<option value="{i}">{}</option>"#, escape(label));
    }
    h.push_str(
        r#"</select></label>
<label>Origin <select id="origin">"#,
    );
    for (i, label) in ["All", "Own sightings", "Federated"].iter().enumerate() {
        let _ = write!(h, r#"<option value="{i}">{label}</option>"#);
    }
    let _ = write!(
        h,
        r#"</select></label>
</div>
<svg id="map" viewBox="{}" role="img" aria-label="Findings per country">
"#,
        map.view_box
    );
    for (code, name, d) in &map.countries {
        let n = counts.get(*code).copied().unwrap_or(0);
        let _ = writeln!(
            h,
            r#"<path data-cc="{code}" class="q{}" d="{d}"><title>{}: {n}</title></path>"#,
            frames::class(n, series.max),
            escape(name),
        );
    }
    h.push_str("</svg>\n<ul class=\"legend\" id=\"legend\">");
    h.push_str("<li class=\"q0\">0</li>");
    for (c, lo, hi) in legend(series.max) {
        if lo == hi {
            let _ = write!(h, r#"<li class="q{c}">{lo}</li>"#);
        } else {
            let _ = write!(h, r#"<li class="q{c}">{lo}–{hi}</li>"#);
        }
    }
    let _ = write!(
        h,
        r#"</ul>
<div class="timeline" id="timeline" hidden>
<svg id="spark" preserveAspectRatio="none" aria-hidden="true"></svg>
<button id="play" type="button" aria-pressed="false">Play</button>
<input id="frame" type="range" min="0" max="{last}" value="{last}" step="1" aria-label="Time window">
<output id="window-label" for="frame">{} – {} UTC</output>
</div>
</section>
<aside class="panel" aria-label="Top countries">
<h2>Findings in window</h2>
<p class="total"><strong id="total">{}</strong>distinct IPs, prefixes and domains</p>
<h2>Top countries</h2>
<table>
<thead><tr><th>Country</th><th class="n">Findings</th><th class="n">Share</th></tr></thead>
<tbody id="top">"#,
        escape(&fmt_time(window_start)),
        escape(&fmt_time(window_end)),
        series.totals[last],
    );
    let mut ranked: Vec<(&String, &u32)> = counts.iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let total = series.totals[last].max(1);
    for (code, n) in ranked.iter().take(10) {
        let _ = write!(
            h,
            r#"<tr><td>{}</td><td class="n">{n}</td><td class="n">{:.1}%</td></tr>"#,
            escape(&name_of(code)),
            f64::from(**n) * 100.0 / f64::from(total)
        );
    }
    if ranked.is_empty() {
        h.push_str(r#"<tr><td class="empty" colspan="3">No findings in this window.</td></tr>"#);
    }
    let unknown = series.counts[last]
        .chunks(2)
        .find(|c| f.countries[c[0] as usize] == UNKNOWN)
        .map_or(0, |c| c[1]);
    let _ = write!(
        h,
        r#"</tbody>
</table>
<p class="note" id="unknown">{}</p>
</aside>
{}</main>
<footer>
<p>A finding is an IP address, prefix or domain with a behaviour, counted in a frame if its observation period (Sighting: first to last seen; indicator: validity) overlaps the window. Each country is coloured on a log scale relative to the busiest country across all frames of the selected filter. Locations are where the address is registered or announced, not necessarily where an attacker is.</p>
"#,
        if unknown > 0 {
            format!("{unknown} without a known country.")
        } else {
            String::new()
        },
        if p.details.is_some() { DETAILS } else { "" }
    );
    for n in &p.notes {
        let _ = writeln!(h, "<p>{}</p>", escape(n));
    }
    let _ = write!(
        h,
        r#"<p>Map: Natural Earth (public domain). Generated by apti-dashboard {}.</p>
</footer>
<script type="application/json" id="apti-data">{data}</script>
<script>{JS}</script>
</body>
</html>
"#,
        env!("CARGO_PKG_VERSION")
    );
    h
}

/// Table of the selected country's observables, filled by the script.
const DETAILS: &str = r#"<section class="panel details" id="details" aria-labelledby="details-title" hidden>
<div class="details-head">
<h2 id="details-title">Observables</h2>
<button id="details-clear" type="button" hidden>Clear selection</button>
</div>
<p class="note" id="details-summary">Select a country on the map or in the table.</p>
<div class="scroll">
<table>
<thead><tr><th>Observable</th><th>Country</th><th>Behaviours</th><th>Reported by</th><th class="n">Count</th><th>Last seen / valid until (UTC)</th></tr></thead>
<tbody id="details-rows"></tbody>
</table>
</div>
</section>
"#;

fn step_hours(f: &Frames) -> i64 {
    match f.frames.as_slice() {
        [a, b, ..] => (*b - *a).num_hours(),
        _ => 0,
    }
}

fn duration(hours: i64) -> String {
    match hours {
        h if h > 0 && h % 24 == 0 => format!("{} d", h / 24),
        h => format!("{h} h"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Origin;
    use crate::frames::{compute, Finding, FrameSpec};
    use apti_core::Behavior;
    use chrono::{TimeDelta, TimeZone};

    fn sample(countries: &[&str]) -> Frames {
        let now = Utc.with_ymd_and_hms(2026, 10, 5, 12, 0, 0).unwrap();
        let spec = FrameSpec {
            first: now - TimeDelta::days(3),
            step: TimeDelta::days(1),
            window: TimeDelta::days(2),
            count: 4,
        };
        let findings: Vec<Finding> = countries
            .iter()
            .enumerate()
            .map(|(i, c)| Finding {
                key: i,
                behavior: Behavior::Scan,
                origin: Origin::Federated,
                start: now - TimeDelta::hours(5),
                end: now,
                countries: if c.is_empty() {
                    vec![]
                } else {
                    vec![c.to_string()]
                },
            })
            .collect();
        compute(&spec, &findings)
    }

    fn render(f: &Frames, names: &HashMap<String, String>) -> String {
        page(&Page {
            title: "Map <&> \"test\"",
            generated: Utc::now(),
            frames: f,
            names,
            tlp: Some(Tlp::AmberStrict),
            notes: vec!["note </script>".into()],
            details: None,
        })
    }

    #[test]
    fn world_map_is_complete() {
        let m = world();
        assert!(m.countries.len() > 170);
        for code in ["DE", "US", "FR", "NO", "CN", "RU", "BR", "XK", "TW"] {
            assert!(
                m.countries.iter().any(|(c, _, _)| *c == code),
                "{code} missing"
            );
        }
        assert!(m
            .countries
            .iter()
            .all(|(c, n, d)| c.len() == 2 && !n.is_empty() && d.starts_with('M')));
    }

    #[test]
    fn page_is_self_contained_and_escaped() {
        let f = sample(&["DE", "DE", "US", "SG", ""]);
        let names = HashMap::from([
            ("SG".to_string(), "Singapore</script><b>".to_string()),
            ("XX".to_string(), "unused".to_string()),
        ]);
        let html = render(&f, &names);
        assert!(html.contains("<title>Map &lt;&amp;&gt; &quot;test&quot;</title>"));
        assert!(html.contains("note &lt;/script&gt;"));
        assert!(html.contains(r#"class="tlp tlp-amber-strict""#));
        assert!(html.contains("TLP:AMBER+STRICT"));
        // Exactly the two own script elements; no external resources.
        assert_eq!(html.matches("<script").count(), 2);
        assert_eq!(html.matches("</script>").count(), 2);
        assert!(!html.contains("src="));
        assert!(!html.contains("href="));
        assert!(!html.contains("style=\""));

        // Static fallback: latest frame of all/all.
        assert!(html.contains(r#"<path data-cc="DE" class="q6""#));
        assert!(html.contains("<title>Germany: 2</title>"));
        assert!(html.contains(r#"<path data-cc="BR" class="q0""#));
        assert!(html.contains(r#"<strong id="total">5</strong>"#));
        assert!(html.contains("Singapore\\u003c/script\\u003e"));
        assert!(html.contains("1 without a known country."));

        // The embedded data round-trips.
        let start = html.find(r#"id="apti-data">"#).unwrap() + 15;
        let end = start + html[start..].find("</script>").unwrap();
        let data: serde_json::Value = serde_json::from_str(&html[start..end]).unwrap();
        assert_eq!(
            data["countries"],
            serde_json::json!(["DE", "SG", "US", "ZZ"])
        );
        assert_eq!(data["names"]["SG"], "Singapore</script><b>");
        assert_eq!(data["names"]["DE"], "Germany");
        assert!(data["names"].get("XX").is_none());
        assert_eq!(data["classes"], 6);
        assert_eq!(data["behaviors"], serde_json::json!(["all", "scan"]));
        assert_eq!(data["series"].as_array().unwrap().len(), 6);
        assert_eq!(data["series"][0]["totals"], serde_json::json!([0, 0, 0, 5]));
        assert_eq!(data["windowHours"], 48);
    }

    #[test]
    fn csp_matches_inline_content() {
        let html = render(&sample(&["DE"]), &HashMap::new());
        let script_start = html.find("<script>").unwrap() + 8;
        let script_end = script_start + html[script_start..].find("</script>").unwrap();
        let style_start = html.find("<style>").unwrap() + 7;
        let style_end = style_start + html[style_start..].find("</style>").unwrap();
        let csp = content_security_policy();
        assert!(csp.contains(&csp_hash(&html[script_start..script_end])));
        assert!(csp.contains(&csp_hash(&html[style_start..style_end])));
        assert!(html.contains(&escape(&csp)));
        assert!(csp.starts_with("default-src 'none'"));
    }

    #[test]
    fn empty_data() {
        let f = sample(&[]);
        let html = page(&Page {
            title: "t",
            generated: Utc::now(),
            frames: &f,
            names: &HashMap::new(),
            tlp: None,
            notes: vec![],
            details: None,
        });
        assert!(html.contains("No findings in this window."));
        assert!(html.contains("tlp-none"));
    }

    #[test]
    fn legend_ranges() {
        assert_eq!(legend(0), []);
        assert_eq!(legend(1), [(6, 1, 1)]);
        let l = legend(1000);
        assert_eq!(l.len(), 6);
        assert_eq!(l[0].1, 1);
        assert_eq!(l[5].2, 1000);
        assert!(l.windows(2).all(|w| w[0].2 + 1 == w[1].1));
    }
}
