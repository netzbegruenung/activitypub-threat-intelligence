//! Per-observable data for the country table: which observables, behaviours
//! and actors make up a country's count.

use std::collections::HashMap;

use serde::Serialize;

use crate::client::{Origin, TimelineActor};
use crate::frames::{Finding, Frames};
use crate::geo::UNKNOWN;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Details {
    /// Observable values, indexed by [`Finding::key`].
    pub observables: Vec<String>,
    /// Indices into [`Frames::countries`] per observable; unknown is `ZZ`.
    pub observable_countries: Vec<Vec<u32>>,
    /// Display labels of the publishing actors.
    pub actors: Vec<String>,
    /// One row per finding: observable, behaviour (index
    /// into [`Frames::behaviors`]), origin (1 local, 2 federated), actor,
    /// start rounded up and end rounded down to Unix seconds, count (-1 for
    /// indicators). With frame ends in whole seconds, the rounding keeps the
    /// overlap test exact.
    pub findings: Vec<[i64; 7]>,
}

/// What a finding adds to [`Finding`]: actor index and Sighting count.
#[derive(Debug, Clone, Copy)]
pub struct Extra {
    pub actor: usize,
    pub count: Option<u64>,
}

/// `Name (handle)`, falling back to the handle, the host or the id.
pub fn actor_label(id: &str, info: Option<&TimelineActor>) -> String {
    let info = info.cloned().unwrap_or_default();
    match (info.name, info.handle) {
        (Some(n), Some(h)) => format!("{n} ({h})"),
        (Some(n), None) => n,
        (None, Some(h)) => h,
        (None, None) => id
            .split_once("://")
            .and_then(|(_, rest)| rest.split('/').next())
            .filter(|h| !h.is_empty())
            .unwrap_or(id)
            .to_string(),
    }
}

pub fn build(
    frames: &Frames,
    findings: &[Finding],
    extras: &[Extra],
    observables: Vec<String>,
    actors: Vec<String>,
) -> Details {
    let country: HashMap<&str, u32> = frames
        .countries
        .iter()
        .enumerate()
        .map(|(i, c)| (c.as_str(), i as u32))
        .collect();
    let behavior: HashMap<&str, i64> = frames
        .behaviors
        .iter()
        .enumerate()
        .map(|(i, b)| (b.as_str(), i as i64))
        .collect();
    let mut observable_countries = vec![Vec::new(); observables.len()];
    for f in findings {
        let cs = &mut observable_countries[f.key];
        if cs.is_empty() {
            *cs = if f.countries.is_empty() {
                vec![country[UNKNOWN]]
            } else {
                f.countries.iter().map(|c| country[c.as_str()]).collect()
            };
        }
    }
    let findings = findings
        .iter()
        .zip(extras)
        .map(|(f, x)| {
            [
                f.key as i64,
                behavior[f.behavior.as_str()],
                match f.origin {
                    Origin::Local => 1,
                    Origin::Federated => 2,
                },
                x.actor as i64,
                f.start.timestamp() + i64::from(f.start.timestamp_subsec_nanos() > 0),
                f.end.timestamp(),
                x.count.map_or(-1, |c| c.min(i64::MAX as u64) as i64),
            ]
        })
        .collect();
    Details {
        observables,
        observable_countries,
        actors,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frames::{compute, FrameSpec};
    use apti_core::Behavior;
    use chrono::{TimeDelta, TimeZone, Utc};

    #[test]
    fn labels() {
        let full = TimelineActor {
            handle: Some("feed@a.example".into()),
            name: Some("Org A".into()),
        };
        assert_eq!(
            actor_label("https://a.example/actor", Some(&full)),
            "Org A (feed@a.example)"
        );
        assert_eq!(actor_label("https://b.example/actor", None), "b.example");
        assert_eq!(actor_label("odd", None), "odd");
    }

    #[test]
    fn rows_reference_frames() {
        let t = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let spec = FrameSpec {
            first: t,
            step: TimeDelta::days(1),
            window: TimeDelta::days(1),
            count: 2,
        };
        let findings = vec![
            Finding {
                key: 0,
                behavior: Behavior::SshBruteforce,
                origin: Origin::Federated,
                start: t,
                end: t,
                countries: vec!["DE".into()],
            },
            Finding {
                key: 1,
                behavior: Behavior::Scan,
                origin: Origin::Local,
                start: t + TimeDelta::milliseconds(1),
                end: t + TimeDelta::hours(1) + TimeDelta::milliseconds(1),
                countries: vec![],
            },
        ];
        let frames = compute(&spec, &findings);
        let extras = [
            Extra {
                actor: 1,
                count: None,
            },
            Extra {
                actor: 0,
                count: Some(7),
            },
        ];
        let d = build(
            &frames,
            &findings,
            &extras,
            vec!["45.1.1.1".into(), "47.1.1.1".into()],
            vec!["us".into(), "peer".into()],
        );
        assert_eq!(frames.behaviors, ["all", "scan", "ssh-bruteforce"]);
        assert_eq!(frames.countries, ["DE", "ZZ"]);
        assert_eq!(d.observable_countries, [vec![0], vec![1]]);
        let ts = t.timestamp();
        assert_eq!(
            d.findings,
            [[0, 2, 2, 1, ts, ts, -1], [1, 1, 1, 0, ts + 1, ts + 3600, 7]]
        );
    }
}
