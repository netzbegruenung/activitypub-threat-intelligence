//! Sliding-window counts per country.
//!
//! The slider has one frame per step. Frame `t` counts the distinct
//! observables whose observation period overlaps `[t - window, t]`, for every
//! combination of behaviour filter and origin filter.

use std::collections::{BTreeMap, HashMap, HashSet};

use apti_core::Behavior;
use chrono::{DateTime, SubsecRound, TimeDelta, Utc};
use serde::Serialize;

use crate::client::Origin;
use crate::config::Dashboard;
use crate::geo::UNKNOWN;

/// Number of colour classes on the map.
pub const CLASSES: u8 = 6;

/// Origin filters, in the order of [`Series`] indices.
pub const ORIGINS: [&str; 3] = ["all", "local", "federated"];

#[derive(Debug, Clone, Copy)]
pub struct FrameSpec {
    /// End of the first frame.
    pub first: DateTime<Utc>,
    pub step: TimeDelta,
    pub window: TimeDelta,
    /// Number of frames; the last one ends at `now`.
    pub count: usize,
}

impl FrameSpec {
    pub fn new(cfg: &Dashboard, now: DateTime<Utc>) -> Self {
        // Whole seconds (rounded up, so nothing seen until now is cut), so
        // that the window test of the page's script agrees with the counts.
        let now = match now.timestamp_subsec_nanos() {
            0 => now,
            _ => now.trunc_subsecs(0) + TimeDelta::seconds(1),
        };
        let step = TimeDelta::hours(cfg.step_hours.into());
        let steps = i64::from(cfg.range_days) * 24 / i64::from(cfg.step_hours);
        Self {
            first: now - step * steps as i32,
            step,
            window: TimeDelta::days(cfg.window_days.into()),
            count: steps as usize + 1,
        }
    }

    pub fn end(&self, i: usize) -> DateTime<Utc> {
        self.first + self.step * i as i32
    }

    /// Start of the earliest window, i.e. what to fetch from aptid.
    pub fn since(&self) -> DateTime<Utc> {
        self.first - self.window
    }

    fn overlaps(&self, i: usize, start: DateTime<Utc>, end: DateTime<Utc>) -> bool {
        let hi = self.end(i);
        start <= hi && end >= hi - self.window
    }
}

/// One finding: an observable with a behaviour, seen by one origin.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Identifies the observable; equal keys are counted once.
    pub key: usize,
    pub behavior: Behavior,
    pub origin: Origin,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// Country codes; empty = unknown.
    pub countries: Vec<String>,
}

/// Counts for one behaviour/origin combination.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct Series {
    /// Largest per-country count over all frames, for the colour scale.
    pub max: u32,
    /// Distinct observables per frame (a domain in two countries counts once).
    pub totals: Vec<u32>,
    /// Per frame: flat `[country index, count, ...]`, by descending count.
    pub counts: Vec<Vec<u32>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Frames {
    /// End of each window.
    pub frames: Vec<DateTime<Utc>>,
    pub window_hours: i64,
    /// Behaviour filters; index 0 is "all".
    pub behaviors: Vec<String>,
    pub origins: [&'static str; 3],
    /// Country codes referenced by `counts`.
    pub countries: Vec<String>,
    /// Indexed by `behaviour * 3 + origin`.
    pub series: Vec<Series>,
}

impl Frames {
    pub fn series(&self, behavior: usize, origin: usize) -> &Series {
        &self.series[behavior * ORIGINS.len() + origin]
    }
}

pub fn compute(spec: &FrameSpec, findings: &[Finding]) -> Frames {
    let behaviors: Vec<Behavior> = findings
        .iter()
        .map(|f| f.behavior)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let b_index: HashMap<Behavior, usize> = behaviors
        .iter()
        .enumerate()
        .map(|(i, b)| (*b, i + 1))
        .collect();
    let mut countries: Vec<String> = findings
        .iter()
        .flat_map(|f| f.countries.iter().cloned())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    countries.push(UNKNOWN.to_string());
    let c_index: HashMap<&str, u32> = countries
        .iter()
        .enumerate()
        .map(|(i, c)| (c.as_str(), i as u32))
        .collect();
    let unknown = c_index[UNKNOWN];

    let combos = (behaviors.len() + 1) * ORIGINS.len();
    let mut series = vec![Series::default(); combos];
    for i in 0..spec.count {
        let mut per_country: Vec<HashMap<u32, HashSet<usize>>> = vec![HashMap::new(); combos];
        let mut totals: Vec<HashSet<usize>> = vec![HashSet::new(); combos];
        for f in findings.iter().filter(|f| spec.overlaps(i, f.start, f.end)) {
            let o = match f.origin {
                Origin::Local => 1,
                Origin::Federated => 2,
            };
            let cs: Vec<u32> = if f.countries.is_empty() {
                vec![unknown]
            } else {
                f.countries.iter().map(|c| c_index[c.as_str()]).collect()
            };
            for b in [0, b_index[&f.behavior]] {
                for o in [0, o] {
                    let k = b * ORIGINS.len() + o;
                    totals[k].insert(f.key);
                    for &c in &cs {
                        per_country[k].entry(c).or_default().insert(f.key);
                    }
                }
            }
        }
        for (k, s) in series.iter_mut().enumerate() {
            let mut counts: Vec<(u32, u32)> = per_country[k]
                .iter()
                .map(|(c, keys)| (*c, keys.len() as u32))
                .collect();
            counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            if let Some(&(_, n)) = counts.iter().find(|(c, _)| *c != unknown) {
                s.max = s.max.max(n);
            }
            s.totals.push(totals[k].len() as u32);
            s.counts
                .push(counts.into_iter().flat_map(|(c, n)| [c, n]).collect());
        }
    }
    Frames {
        frames: (0..spec.count).map(|i| spec.end(i)).collect(),
        window_hours: spec.window.num_hours(),
        behaviors: std::iter::once("all".to_string())
            .chain(behaviors.iter().map(|b| b.as_str().to_string()))
            .collect(),
        origins: ORIGINS,
        countries,
        series,
    }
}

/// Colour class 0 (none) to [`CLASSES`] on a log scale up to `max`. The
/// page script uses the same formula.
pub fn class(n: u32, max: u32) -> u8 {
    if n == 0 {
        return 0;
    }
    if max <= 1 {
        return CLASSES;
    }
    let c = (f64::from(CLASSES) * f64::from(n).ln_1p() / f64::from(max).ln_1p()).ceil();
    (c as u8).clamp(1, CLASSES)
}

/// Country → count of one frame, without the unknown bucket.
pub fn frame_counts(f: &Frames, s: &Series, frame: usize) -> BTreeMap<String, u32> {
    s.counts[frame]
        .chunks(2)
        .map(|p| (f.countries[p[0] as usize].clone(), p[1]))
        .filter(|(c, _)| c != UNKNOWN)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn spec() -> FrameSpec {
        // Frames end at day 0, 1, ..., 4; windows of 2 days.
        FrameSpec {
            first: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            step: TimeDelta::days(1),
            window: TimeDelta::days(2),
            count: 5,
        }
    }

    fn hour(h: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap() + TimeDelta::hours(h)
    }

    fn finding(key: usize, b: Behavior, o: Origin, h: (i64, i64), cs: &[&str]) -> Finding {
        Finding {
            key,
            behavior: b,
            origin: o,
            start: hour(h.0),
            end: hour(h.1),
            countries: cs.iter().map(|c| c.to_string()).collect(),
        }
    }

    #[test]
    fn frame_spec_from_config() {
        let cfg = crate::config::Config::parse(
            r#"
[aptid]
url = "http://x"
read_token = "t"
[geoip]
country_db = "/x"
[dashboard]
output = "/x"
range_days = 2
window_days = 1
step_hours = 12
"#,
        )
        .unwrap();
        let now = hour(100);
        let s = FrameSpec::new(&cfg.dashboard, now);
        assert_eq!(s.count, 5);
        assert_eq!(s.end(4), now);
        assert_eq!(s.end(0), now - TimeDelta::days(2));
        assert_eq!(s.since(), now - TimeDelta::days(3));
        // Rounded up to whole seconds.
        let s = FrameSpec::new(&cfg.dashboard, now + TimeDelta::milliseconds(1));
        assert_eq!(s.end(4), now + TimeDelta::seconds(1));
    }

    #[test]
    fn window_boundaries() {
        let s = spec();
        // Frame 2 ends at hour 48 and covers [0 h, 48 h].
        assert!(s.overlaps(2, hour(48), hour(48)));
        assert!(s.overlaps(2, hour(-10), hour(0)));
        assert!(!s.overlaps(2, hour(-10), hour(-1)));
        assert!(!s.overlaps(2, hour(49), hour(50)));
        assert!(s.overlaps(2, hour(-100), hour(100)));
    }

    #[test]
    fn counts_distinct_observables_per_combination() {
        use Behavior::*;
        use Origin::*;
        let findings = vec![
            // The same observable from both origins counts once in "all".
            finding(1, Scan, Local, (0, 0), &["DE"]),
            finding(1, Scan, Federated, (0, 1), &["DE"]),
            finding(2, SshBruteforce, Federated, (24, 30), &["DE"]),
            // A domain in two countries.
            finding(3, Phishing, Federated, (24, 24), &["US", "DE"]),
            finding(4, Scan, Local, (96, 96), &[]),
        ];
        let f = compute(&spec(), &findings);
        assert_eq!(f.behaviors, ["all", "scan", "ssh-bruteforce", "phishing"]);
        assert_eq!(f.countries, ["DE", "US", "ZZ"]);
        assert_eq!(f.series.len(), 4 * 3);

        let all = f.series(0, 0);
        assert_eq!(all.totals, [1, 3, 3, 2, 1]);
        assert_eq!(
            frame_counts(&f, all, 1),
            [("DE".into(), 3), ("US".into(), 1)].into()
        );
        // Sorted by count, unknown included in the raw data.
        assert_eq!(all.counts[4], [2, 1]);
        assert_eq!(all.max, 3);

        let local = f.series(0, 1);
        assert_eq!(local.totals, [1, 1, 1, 0, 1]);
        let fed_scan = f.series(1, 2);
        assert_eq!(fed_scan.totals, [1, 1, 1, 0, 0]);
        let phishing = f.series(3, 0);
        assert_eq!(phishing.totals, [0, 1, 1, 1, 0]);
        assert_eq!(phishing.max, 1);
        assert_eq!(f.frames.len(), 5);
        assert_eq!(f.window_hours, 48);
    }

    #[test]
    fn colour_classes() {
        assert_eq!(class(0, 100), 0);
        assert_eq!(class(1, 1), CLASSES);
        assert_eq!(class(1, 1000), 1);
        assert_eq!(class(1000, 1000), CLASSES);
        assert_eq!(class(5000, 1000), CLASSES);
        let mut last = 0;
        for n in 1..=1000 {
            let c = class(n, 1000);
            assert!(c >= last);
            last = c;
        }
    }
}
