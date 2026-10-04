//! File parsing and the reconcile plan (pure, no I/O).

use std::collections::BTreeSet;

use apti_core::normalize::{self, NormPolicy};
use apti_core::ObservableType;
use chrono::{DateTime, Utc};

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

#[derive(Debug, Default, PartialEq)]
pub struct Plan {
    /// Normalised values to add.
    pub add: Vec<String>,
    /// Entries to remove.
    pub remove: Vec<Entry>,
}

/// Which entries to add and remove so that the allowlist matches the file.
///
/// A value counts as present only if an unexpired local entry for all
/// behaviours exists (the same rule aptid uses for idempotent adds).
/// Entries are removed only in source-of-truth mode, only if their value is
/// not in the file, and only if they carry `marker` (or `prune_all`).
pub fn plan(
    desired: &BTreeSet<(ObservableType, String)>,
    current: &[Entry],
    mode: Mode,
    marker: &str,
    prune_all: bool,
    now: DateTime<Utc>,
) -> Plan {
    let covered: BTreeSet<(ObservableType, &str)> = current
        .iter()
        .filter(|e| e.behaviors.is_empty() && e.valid_until.is_none_or(|u| u > now))
        .map(|e| (e.observable_type, e.observable_value.as_str()))
        .collect();
    let add = desired
        .iter()
        .filter(|(ty, v)| !covered.contains(&(*ty, v.as_str())))
        .map(|(_, v)| v.clone())
        .collect();
    let remove = match mode {
        Mode::Append => vec![],
        Mode::SourceOfTruth => current
            .iter()
            .filter(|e| prune_all || e.summary.as_deref() == Some(marker))
            .filter(|e| !desired.contains(&(e.observable_type, e.observable_value.clone())))
            .cloned()
            .collect(),
    };
    Plan { add, remove }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;

    const M: &str = "apti-allowlist:/f";

    fn entry(id: i64, value: &str, summary: Option<&str>) -> Entry {
        let (ty, v) = normalize::normalise(value, None, &NormPolicy::lenient()).unwrap();
        Entry {
            id,
            observable_type: ty,
            observable_value: v,
            behaviors: vec![],
            valid_until: None,
            summary: summary.map(String::from),
        }
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
        let p = plan(&desired, &current, Mode::Append, M, false, Utc::now());
        assert_eq!(p.add, vec!["45.13.7.10"]);
        assert!(p.remove.is_empty());
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
            Mode::Append,
            M,
            false,
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
            Mode::SourceOfTruth,
            M,
            false,
            Utc::now(),
        );
        assert!(p.add.is_empty());
        assert_eq!(p.remove.iter().map(|e| e.id).collect::<Vec<_>>(), vec![2]);

        let p = plan(&desired, &current, Mode::SourceOfTruth, M, true, Utc::now());
        assert_eq!(
            p.remove.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![2, 3, 4]
        );
    }
}
