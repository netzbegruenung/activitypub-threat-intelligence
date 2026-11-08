//! Local consumer policy (Section 7).

use std::collections::HashMap;

use chrono::TimeDelta;
use serde::{Deserialize, Serialize};

use crate::model::{Behavior, ObservableType};

/// Sighting activation threshold `k(b)`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Threshold {
    /// Sightings never activate on their own.
    Off,
    /// Summed operator weight required.
    Quorum(f64),
}

impl Default for Threshold {
    fn default() -> Self {
        Self::Quorum(2.0)
    }
}

impl std::fmt::Display for Threshold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Off => f.write_str("off"),
            Self::Quorum(k) => write!(f, "{k}"),
        }
    }
}

impl std::str::FromStr for Threshold {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("off") {
            return Ok(Self::Off);
        }
        let k: f64 = s.parse().map_err(|_| format!("invalid threshold `{s}`"))?;
        if !k.is_finite() || k <= 0.0 {
            return Err("threshold must be > 0 or `off`".into());
        }
        Ok(Self::Quorum(k))
    }
}

/// Maximum evidence age for IP observables (Section 7: SHOULD NOT exceed 90 d).
pub const MAX_IP_AGE_DAYS: i64 = 90;

/// Default Sighting TTL `T(b)` and maximum evidence age `M(b)` (Table 1).
pub fn default_ttl_max(b: Behavior, ty: ObservableType) -> (TimeDelta, TimeDelta) {
    let (t, m) = match b {
        Behavior::Scan | Behavior::DdosSource => (1, 7),
        Behavior::SshBruteforce | Behavior::AuthBruteforce => (1, 14),
        Behavior::SmtpSpam => (2, 30),
        Behavior::ExploitAttempt => (3, 30),
        Behavior::Phishing | Behavior::MalwareHosting => (7, 30),
        Behavior::CommandAndControl if ty == ObservableType::DomainName => (30, 180),
        Behavior::CommandAndControl => (7, 90),
        Behavior::Other => (1, 14),
    };
    (TimeDelta::days(t), TimeDelta::days(m))
}

/// Trust settings for one operator (optionally scoped to one behaviour).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct OperatorPolicy {
    pub trusted: bool,
    pub weight: f64,
}

impl Default for OperatorPolicy {
    /// Section 7 defaults: untrusted, weight 1.
    fn default() -> Self {
        Self {
            trusted: false,
            weight: 1.0,
        }
    }
}

/// Per-behaviour overrides; `None` means "use the default".
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
pub struct BehaviorOverride {
    pub k: Option<Threshold>,
    pub ttl_secs: Option<i64>,
    pub max_age_secs: Option<i64>,
}

/// The complete policy used by the expiry engine.
#[derive(Debug, Clone, Default)]
pub struct PolicySet {
    pub default_k: Threshold,
    /// Keyed by operator id and behaviour; `None` is the operator-wide default.
    pub operators: HashMap<(String, Option<Behavior>), OperatorPolicy>,
    pub behaviors: HashMap<Behavior, BehaviorOverride>,
}

impl PolicySet {
    pub fn operator(&self, op: &str, b: Behavior) -> OperatorPolicy {
        self.operators
            .get(&(op.to_string(), Some(b)))
            .or_else(|| self.operators.get(&(op.to_string(), None)))
            .copied()
            .unwrap_or_default()
    }

    pub fn trusted(&self, op: &str, b: Behavior) -> bool {
        self.operator(op, b).trusted
    }

    pub fn weight(&self, op: &str, b: Behavior) -> f64 {
        self.operator(op, b).weight.max(0.0)
    }

    pub fn k(&self, b: Behavior) -> Threshold {
        self.behaviors
            .get(&b)
            .and_then(|o| o.k)
            .unwrap_or(self.default_k)
    }

    pub fn ttl(&self, b: Behavior, ty: ObservableType) -> TimeDelta {
        self.behaviors
            .get(&b)
            .and_then(|o| o.ttl_secs)
            .map(TimeDelta::seconds)
            .unwrap_or_else(|| default_ttl_max(b, ty).0)
    }

    pub fn max_age(&self, b: Behavior, ty: ObservableType) -> TimeDelta {
        let m = self
            .behaviors
            .get(&b)
            .and_then(|o| o.max_age_secs)
            .map(TimeDelta::seconds)
            .unwrap_or_else(|| default_ttl_max(b, ty).1);
        if ty.is_ip() {
            m.min(TimeDelta::days(MAX_IP_AGE_DAYS))
        } else {
            m
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_overrides() {
        let mut p = PolicySet::default();
        assert_eq!(p.k(Behavior::Scan), Threshold::Quorum(2.0));
        assert!(!p.trusted("op", Behavior::Scan));
        assert_eq!(p.weight("op", Behavior::Scan), 1.0);
        assert_eq!(
            p.max_age(Behavior::CommandAndControl, ObservableType::DomainName),
            TimeDelta::days(180)
        );
        assert_eq!(
            p.max_age(Behavior::CommandAndControl, ObservableType::Ipv4Addr),
            TimeDelta::days(90)
        );
        p.operators.insert(
            ("op".into(), None),
            OperatorPolicy {
                trusted: true,
                weight: 1.0,
            },
        );
        p.operators.insert(
            ("op".into(), Some(Behavior::Scan)),
            OperatorPolicy {
                trusted: false,
                weight: 3.0,
            },
        );
        assert!(p.trusted("op", Behavior::SmtpSpam));
        assert!(!p.trusted("op", Behavior::Scan));
        p.behaviors.insert(
            Behavior::Scan,
            BehaviorOverride {
                k: Some(Threshold::Off),
                ttl_secs: Some(60),
                max_age_secs: Some(200 * 86400),
            },
        );
        assert_eq!(p.k(Behavior::Scan), Threshold::Off);
        assert_eq!(
            p.ttl(Behavior::Scan, ObservableType::Ipv4Addr),
            TimeDelta::seconds(60)
        );
        // IP max age capped at 90 days.
        assert_eq!(
            p.max_age(Behavior::Scan, ObservableType::Ipv4Addr),
            TimeDelta::days(90)
        );
        assert_eq!("off".parse::<Threshold>(), Ok(Threshold::Off));
        assert!("0".parse::<Threshold>().is_err());
    }
}
