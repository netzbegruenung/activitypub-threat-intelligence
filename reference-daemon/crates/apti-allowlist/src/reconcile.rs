//! File parsing and the reconcile plan (pure, no I/O).

use std::collections::BTreeSet;

use apti_core::normalize::{self, NormPolicy};
use apti_core::{ObservableType, Tlp};
use chrono::{DateTime, TimeDelta, Utc};

use crate::client::Entry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Only add values from the file.
    Append,
    /// Also remove managed entries whose value is no longer in the file.
    SourceOfTruth,
}

/// A line that is not a valid value.
#[derive(Debug, Clone, PartialEq)]
pub struct Invalid {
    /// 1-based line number.
    pub line: usize,
    pub text: String,
    pub error: String,
}

#[derive(Debug, Default, PartialEq)]
pub struct Parsed {
    /// Normalised values (deduplicated).
    pub values: BTreeSet<(ObservableType, String)>,
    pub invalid: Vec<Invalid>,
}

/// Parse the allowlist file: one IP address, prefix or domain per line;
/// `#` starts a comment, blank lines are ignored. Values are normalised the
/// way aptid stores local entries.
pub fn parse(text: &str) -> Parsed {
    let norm = NormPolicy::lenient();
    let mut out = Parsed::default();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let invalid = |error: String| Invalid {
            line: i + 1,
            text: line.to_string(),
            error,
        };
        if line.contains(char::is_whitespace) {
            out.invalid
                .push(invalid("one value per line expected".into()));
            continue;
        }
        match normalize::normalise(line, None, &norm) {
            Ok(v) => {
                out.values.insert(v);
            }
            Err(e) => out.invalid.push(invalid(e.to_string())),
        }
    }
    out
}

/// The entries the file stands for.
#[derive(Debug, Clone)]
pub struct Target {
    pub mode: Mode,
    /// Source of the entries this tool manages.
    pub source: String,
    /// Source of truth: also remove entries without `source`.
    pub prune_all: bool,
    /// TLP of published entries; `None` for local entries.
    pub tlp: Option<Tlp>,
    /// Entries expiring within this window are renewed (zero for local).
    pub renew_before: TimeDelta,
}

#[derive(Debug, Default, PartialEq)]
pub struct Plan {
    /// Normalised values to add.
    pub add: Vec<String>,
    /// Normalised values whose entry expires soon and is extended.
    pub renew: Vec<String>,
    /// Entries to remove.
    pub remove: Vec<Entry>,
}

/// Which entries to add, renew and remove so that the allowlist (all
/// entries of the target's scope in `current`) matches the file.
///
/// An entry stands for a value only if it is unexpired, applies to all
/// behaviours and has the target TLP (the rule aptid uses for idempotent
/// adds). It is renewed if it expires within `renew_before`.
/// Entries are removed only in source-of-truth mode, only if they carry
/// `source` (or `prune_all`), and only if their value is not in the file or
/// their TLP is not the target TLP.
pub fn plan(
    desired: &BTreeSet<(ObservableType, String)>,
    current: &[Entry],
    target: &Target,
    now: DateTime<Utc>,
) -> Plan {
    let matching = |e: &&Entry| {
        e.behaviors.is_empty() && e.tlp == target.tlp && e.valid_until.is_none_or(|u| u > now)
    };
    let renew_at = now + target.renew_before;
    let mut plan = Plan::default();
    for (ty, v) in desired {
        let mut entries = current
            .iter()
            .filter(matching)
            .filter(|e| e.observable_type == *ty && e.observable_value == *v)
            .peekable();
        if entries.peek().is_none() {
            plan.add.push(v.clone());
        } else if entries.all(|e| e.valid_until.is_some_and(|u| u <= renew_at)) {
            plan.renew.push(v.clone());
        }
    }
    if target.mode == Mode::SourceOfTruth {
        plan.remove = current
            .iter()
            .filter(|e| target.prune_all || e.source.as_deref() == Some(target.source.as_str()))
            .filter(|e| {
                e.tlp != target.tlp
                    || !desired.contains(&(e.observable_type, e.observable_value.clone()))
            })
            .cloned()
            .collect();
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;

    const M: &str = "apti-allowlist:/f";

    fn target(mode: Mode, prune_all: bool) -> Target {
        Target {
            mode,
            source: M.into(),
            prune_all,
            tlp: None,
            renew_before: TimeDelta::zero(),
        }
    }

    fn published(mode: Mode, tlp: Tlp) -> Target {
        Target {
            tlp: Some(tlp),
            renew_before: TimeDelta::days(9),
            ..target(mode, false)
        }
    }

    fn entry(id: i64, value: &str, source: Option<&str>) -> Entry {
        let (ty, v) = normalize::normalise(value, None, &NormPolicy::lenient()).unwrap();
        Entry {
            id,
            observable_type: ty,
            observable_value: v,
            behaviors: vec![],
            tlp: None,
            valid_until: None,
            summary: None,
            source: source.map(String::from),
        }
    }

    fn ids(p: &Plan) -> Vec<i64> {
        p.remove.iter().map(|e| e.id).collect()
    }

    #[test]
    fn parses_lines() {
        let p = parse(
            "# office\n\n 45.13.7.9 \n45.13.7.9/32\n2001:DB8:0:0::1\nExample.ORG.\n\
             10.0.0.0/8 # internal\nnot a value\n300.1.1.1\n",
        );
        let values: Vec<&str> = p.values.iter().map(|(_, v)| v.as_str()).collect();
        assert_eq!(
            values,
            vec!["10.0.0.0/8", "45.13.7.9", "2001:db8::1", "example.org"],
            "{p:?}"
        );
        assert_eq!(
            p.invalid.iter().map(|i| i.line).collect::<Vec<_>>(),
            vec![8, 9]
        );
    }

    #[test]
    fn append_adds_missing_only() {
        let desired = parse("45.13.7.9\n45.13.7.10\n").values;
        let current = [entry(1, "45.13.7.9", None), entry(2, "1.2.3.4", Some(M))];
        let p = plan(&desired, &current, &target(Mode::Append, false), Utc::now());
        assert_eq!(p.add, vec!["45.13.7.10"]);
        assert!(p.renew.is_empty() && p.remove.is_empty());
    }

    #[test]
    fn restricted_or_expired_entries_do_not_count() {
        let now = Utc::now();
        let desired = parse("45.13.7.9\n45.13.7.10\n").values;
        let mut restricted = entry(1, "45.13.7.9", None);
        restricted.behaviors = vec!["scan".into()];
        let mut expired = entry(2, "45.13.7.10", None);
        expired.valid_until = Some(now - TimeDelta::seconds(1));
        let p = plan(
            &desired,
            &[restricted, expired],
            &target(Mode::Append, false),
            now,
        );
        assert_eq!(p.add, vec!["45.13.7.10", "45.13.7.9"]);
    }

    #[test]
    fn source_of_truth_removes_managed_only() {
        let desired = parse("45.13.7.9\n").values;
        let current = [
            entry(1, "45.13.7.9", Some(M)),
            entry(2, "1.2.3.4", Some(M)),
            entry(3, "5.6.7.8", None),
            entry(4, "5.6.7.9", Some("other file")),
        ];
        let p = plan(
            &desired,
            &current,
            &target(Mode::SourceOfTruth, false),
            Utc::now(),
        );
        assert!(p.add.is_empty());
        assert_eq!(ids(&p), vec![2]);

        let p = plan(
            &desired,
            &current,
            &target(Mode::SourceOfTruth, true),
            Utc::now(),
        );
        assert_eq!(ids(&p), vec![2, 3, 4]);
    }

    #[test]
    fn published_tlp_and_renewal() {
        let now = Utc::now();
        let desired = parse("45.13.7.1\n45.13.7.2\n45.13.7.3\n45.13.7.4\n").values;
        let with = |id, v, tlp, days| Entry {
            tlp: Some(tlp),
            valid_until: Some(now + TimeDelta::days(days)),
            ..entry(id, v, Some(M))
        };
        let current = [
            with(1, "45.13.7.1", Tlp::Green, 60), // fine
            with(2, "45.13.7.2", Tlp::Green, 3),  // expires soon
            with(3, "45.13.7.3", Tlp::Amber, 60), // other TLP
            with(4, "45.13.7.4", Tlp::Green, 3),  // expires soon, but
            with(5, "45.13.7.4", Tlp::Green, 80), // a fresh one exists
        ];
        let p = plan(
            &desired,
            &current,
            &published(Mode::SourceOfTruth, Tlp::Green),
            now,
        );
        assert_eq!(p.add, vec!["45.13.7.3"]);
        assert_eq!(p.renew, vec!["45.13.7.2"]);
        assert_eq!(ids(&p), vec![3], "replaced TLP");

        // Append mode keeps the entry with the old TLP.
        let p = plan(
            &desired,
            &current,
            &published(Mode::Append, Tlp::Green),
            now,
        );
        assert_eq!(p.add, vec!["45.13.7.3"]);
        assert!(p.remove.is_empty());
    }
}
