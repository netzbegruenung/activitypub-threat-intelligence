//! AP-TI data model (Section 4).

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Datelike, TimeDelta, Utc};
use serde::{Deserialize, Deserializer, Serialize};

use crate::normalize::{self, NormError};
use crate::{FUTURE_TOLERANCE_SECS, MAX_YEAR, MIN_YEAR};

/// `observableType` (Section 4.1). Unknown types deserialise to `Unknown`
/// so that consumers can ignore them instead of failing the whole activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ObservableType {
    #[serde(rename = "ipv4-addr")]
    Ipv4Addr,
    #[serde(rename = "ipv6-addr")]
    Ipv6Addr,
    #[serde(rename = "domain-name")]
    DomainName,
    #[serde(other, skip_serializing)]
    Unknown,
}

impl ObservableType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4Addr => "ipv4-addr",
            Self::Ipv6Addr => "ipv6-addr",
            Self::DomainName => "domain-name",
            Self::Unknown => "unknown",
        }
    }

    pub fn is_ip(self) -> bool {
        matches!(self, Self::Ipv4Addr | Self::Ipv6Addr)
    }
}

impl fmt::Display for ObservableType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ObservableType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ipv4-addr" => Ok(Self::Ipv4Addr),
            "ipv6-addr" => Ok(Self::Ipv6Addr),
            "domain-name" => Ok(Self::DomainName),
            _ => Err(format!("unknown observable type `{s}`")),
        }
    }
}

/// `observedBehavior` (Section 4.2). Unknown values are treated as `other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Behavior {
    Scan,
    SshBruteforce,
    AuthBruteforce,
    SmtpSpam,
    ExploitAttempt,
    DdosSource,
    Phishing,
    MalwareHosting,
    CommandAndControl,
    #[serde(other)]
    Other,
}

impl Behavior {
    pub const ALL: [Behavior; 10] = [
        Self::Scan,
        Self::SshBruteforce,
        Self::AuthBruteforce,
        Self::SmtpSpam,
        Self::ExploitAttempt,
        Self::DdosSource,
        Self::Phishing,
        Self::MalwareHosting,
        Self::CommandAndControl,
        Self::Other,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scan => "scan",
            Self::SshBruteforce => "ssh-bruteforce",
            Self::AuthBruteforce => "auth-bruteforce",
            Self::SmtpSpam => "smtp-spam",
            Self::ExploitAttempt => "exploit-attempt",
            Self::DdosSource => "ddos-source",
            Self::Phishing => "phishing",
            Self::MalwareHosting => "malware-hosting",
            Self::CommandAndControl => "command-and-control",
            Self::Other => "other",
        }
    }

    /// Lenient parse: unknown values map to `Other` (Section 4.2).
    pub fn parse_lenient(s: &str) -> Self {
        Self::ALL
            .into_iter()
            .find(|b| b.as_str() == s)
            .unwrap_or(Self::Other)
    }
}

impl fmt::Display for Behavior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Behavior {
    type Err = String;
    /// Strict parse, used for local input (config, API, TUI).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|b| b.as_str() == s)
            .ok_or_else(|| format!("unknown behaviour `{s}`"))
    }
}

/// Traffic Light Protocol 2.0 label. Ordered from least to most restrictive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Tlp {
    #[serde(rename = "clear")]
    Clear,
    #[serde(rename = "green")]
    Green,
    #[serde(rename = "amber")]
    Amber,
    #[serde(rename = "amber+strict")]
    AmberStrict,
    /// Never shared via this profile (Section 5.2); present only so that
    /// receivers can recognise and reject it.
    #[serde(rename = "red")]
    Red,
}

impl Tlp {
    pub const SHAREABLE: [Tlp; 4] = [Self::Clear, Self::Green, Self::Amber, Self::AmberStrict];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Green => "green",
            Self::Amber => "amber",
            Self::AmberStrict => "amber+strict",
            Self::Red => "red",
        }
    }
}

impl fmt::Display for Tlp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Tlp {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "clear" => Ok(Self::Clear),
            "green" => Ok(Self::Green),
            "amber" => Ok(Self::Amber),
            "amber+strict" => Ok(Self::AmberStrict),
            "red" => Ok(Self::Red),
            _ => Err(format!("unknown TLP `{s}`")),
        }
    }
}

/// `opinion` value (Section 4.5), matching STIX `opinion-enum`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OpinionValue {
    StronglyDisagree,
    Disagree,
    Neutral,
    Agree,
    StronglyAgree,
}

impl OpinionValue {
    pub fn is_dispute(self) -> bool {
        matches!(self, Self::Disagree | Self::StronglyDisagree)
    }

    pub fn is_support(self) -> bool {
        matches!(self, Self::Agree | Self::StronglyAgree)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::StronglyDisagree => "strongly-disagree",
            Self::Disagree => "disagree",
            Self::Neutral => "neutral",
            Self::Agree => "agree",
            Self::StronglyAgree => "strongly-agree",
        }
    }
}

/// Evidence object type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceKind {
    ThreatIndicator,
    Sighting,
    Opinion,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ThreatIndicator => "ThreatIndicator",
            Self::Sighting => "Sighting",
            Self::Opinion => "Opinion",
        }
    }
}

impl FromStr for EvidenceKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ThreatIndicator" => Ok(Self::ThreatIndicator),
            "Sighting" => Ok(Self::Sighting),
            "Opinion" => Ok(Self::Opinion),
            _ => Err(format!("not an evidence type: `{s}`")),
        }
    }
}

/// An AP-TI evidence object (`ThreatIndicator`, `Sighting` or `Opinion`).
///
/// One struct carries all three kinds; [`EvidenceObject::validate`] checks
/// the per-kind requirements of Sections 4.3–4.5.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceObject {
    #[serde(rename = "type")]
    pub kind: EvidenceKind,
    pub id: String,
    pub attributed_to: String,
    pub published: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<DateTime<Utc>>,
    pub tlp: Tlp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observable_type: Option<ObservableType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observable_value: Option<String>,
    #[serde(
        default,
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub observed_behavior: Vec<Behavior>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,

    // ThreatIndicator
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_subdomains: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,
    #[serde(
        default,
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub infrastructure_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<bool>,
    #[serde(
        default,
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub tag: Vec<serde_json::Value>,

    // Sighting
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,

    // Sighting / Opinion
    #[serde(
        default,
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub indicator_refs: Vec<String>,

    // Opinion
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opinion: Option<OpinionValue>,
}

/// Accept both a single value and an array (AS2 functional vs. non-functional).
fn one_or_many<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany<T> {
        Many(Vec<T>),
        One(T),
    }
    Ok(match Option::<OneOrMany<T>>::deserialize(d)? {
        None => Vec::new(),
        Some(OneOrMany::Many(v)) => v,
        Some(OneOrMany::One(v)) => vec![v],
    })
}

/// Reasons an evidence object is rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("missing required property `{0}`")]
    Missing(&'static str),
    #[error("unknown observable type")]
    UnknownType,
    #[error("observable: {0}")]
    Observable(#[from] NormError),
    #[error("TLP:RED must not be shared via AP-TI")]
    TlpRed,
    #[error("validFrom must be before validUntil")]
    ValidityOrder,
    #[error("firstSeen must not be after lastSeen")]
    SeenOrder,
    #[error("count must be >= 1")]
    Count,
    #[error("confidence must be 0..=100")]
    Confidence,
    #[error("includeSubdomains is only allowed for domain-name")]
    IncludeSubdomains,
    #[error("evidence is dated more than 5 minutes in the future")]
    Future,
    #[error("timestamp outside the years {MIN_YEAR}..={MAX_YEAR}")]
    DateRange,
    #[error("`{0}` contains control characters")]
    ControlCharacters(&'static str),
}

impl EvidenceObject {
    /// `base(x)` of Section 7: `updated` if present, else `published`.
    pub fn base(&self) -> DateTime<Utc> {
        self.updated.unwrap_or(self.published)
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked.unwrap_or(false)
    }

    /// End of validity of an Opinion (default `published` + 90 d).
    pub fn opinion_valid_until(&self) -> DateTime<Utc> {
        self.valid_until
            .unwrap_or_else(|| crate::saturating_add(self.published, TimeDelta::days(90)))
    }

    fn timestamps(&self) -> impl Iterator<Item = DateTime<Utc>> + '_ {
        [
            Some(self.published),
            self.updated,
            self.valid_from,
            self.valid_until,
            self.first_seen,
            self.last_seen,
        ]
        .into_iter()
        .flatten()
    }

    /// Whether this object applies to behaviour `b`. Opinions without
    /// `observedBehavior` apply to all behaviours.
    pub fn covers_behavior(&self, b: Behavior) -> bool {
        if self.kind == EvidenceKind::Opinion && self.observed_behavior.is_empty() {
            return true;
        }
        self.observed_behavior.contains(&b)
    }

    /// An allowlist entry: `strongly-disagree` on an observable with no
    /// `indicatorRefs` (Section 4.5).
    pub fn is_allowlist_entry(&self) -> bool {
        self.kind == EvidenceKind::Opinion
            && self.opinion == Some(OpinionValue::StronglyDisagree)
            && self.indicator_refs.is_empty()
            && self.observable_value.is_some()
    }

    /// Validate the object as a consumer must (Sections 4, 7).
    /// `policy` controls prefix and special-purpose checks.
    pub fn validate(
        &self,
        now: DateTime<Utc>,
        policy: &normalize::NormPolicy,
    ) -> Result<(), ValidationError> {
        if self.tlp == Tlp::Red {
            return Err(ValidationError::TlpRed);
        }
        // Remote strings end up in logs and terminal UIs; control characters
        // would allow escape-sequence injection there.
        let control = |s: &str| s.chars().any(char::is_control);
        let fields: [(&'static str, bool); 6] = [
            ("id", control(&self.id)),
            ("attributedTo", control(&self.attributed_to)),
            (
                "summary",
                self.summary
                    .as_deref()
                    .is_some_and(|s| s.chars().any(|c| c.is_control() && c != '\n')),
            ),
            ("service", self.service.as_deref().is_some_and(control)),
            (
                "indicatorRefs",
                self.indicator_refs.iter().any(|r| control(r)),
            ),
            (
                "infrastructureTypes",
                self.infrastructure_types.iter().any(|t| control(t)),
            ),
        ];
        if let Some((name, _)) = fields.iter().find(|(_, bad)| *bad) {
            return Err(ValidationError::ControlCharacters(name));
        }
        if self
            .timestamps()
            .any(|t| !(MIN_YEAR..=MAX_YEAR).contains(&t.year()))
        {
            return Err(ValidationError::DateRange);
        }
        // `published`/`updated` are the base of every expiry computation
        // (Section 7); future values would extend the evidence's lifetime.
        let future = now + TimeDelta::seconds(FUTURE_TOLERANCE_SECS);
        if self.published > future || self.updated.is_some_and(|u| u > future) {
            return Err(ValidationError::Future);
        }
        let has_observable = self.observable_type.is_some() || self.observable_value.is_some();
        if has_observable || self.kind != EvidenceKind::Opinion {
            let ty = self
                .observable_type
                .ok_or(ValidationError::Missing("observableType"))?;
            if ty == ObservableType::Unknown {
                return Err(ValidationError::UnknownType);
            }
            let value = self
                .observable_value
                .as_deref()
                .ok_or(ValidationError::Missing("observableValue"))?;
            normalize::check_normal(ty, value, policy)?;
            if self.include_subdomains == Some(true) && ty != ObservableType::DomainName {
                return Err(ValidationError::IncludeSubdomains);
            }
        }
        match self.kind {
            EvidenceKind::ThreatIndicator => {
                if self.observed_behavior.is_empty() {
                    return Err(ValidationError::Missing("observedBehavior"));
                }
                let from = self
                    .valid_from
                    .ok_or(ValidationError::Missing("validFrom"))?;
                let until = self
                    .valid_until
                    .ok_or(ValidationError::Missing("validUntil"))?;
                if from >= until {
                    return Err(ValidationError::ValidityOrder);
                }
                if self.confidence.is_some_and(|c| c > 100) {
                    return Err(ValidationError::Confidence);
                }
            }
            EvidenceKind::Sighting => {
                if self.observed_behavior.is_empty() {
                    return Err(ValidationError::Missing("observedBehavior"));
                }
                let first = self
                    .first_seen
                    .ok_or(ValidationError::Missing("firstSeen"))?;
                let last = self.last_seen.ok_or(ValidationError::Missing("lastSeen"))?;
                if first > last {
                    return Err(ValidationError::SeenOrder);
                }
                if self.count == Some(0) {
                    return Err(ValidationError::Count);
                }
                if last > future {
                    return Err(ValidationError::Future);
                }
            }
            EvidenceKind::Opinion => {
                if !has_observable && self.indicator_refs.is_empty() {
                    return Err(ValidationError::Missing("observableValue or indicatorRefs"));
                }
                if self.opinion.is_none() {
                    return Err(ValidationError::Missing("opinion"));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::NormPolicy;

    fn doc_policy() -> NormPolicy {
        NormPolicy {
            allow_documentation: true,
            ..NormPolicy::default()
        }
    }

    #[test]
    fn parses_spec_sighting_example() {
        let json = r#"{
          "type": "Sighting",
          "id": "https://ti.example.net/s/101",
          "attributedTo": "https://ti.example.net/actor",
          "published": "2026-10-03T10:15:00Z",
          "observableType": "ipv4-addr",
          "observableValue": "198.51.100.23",
          "observedBehavior": ["ssh-bruteforce"],
          "service": "ssh",
          "port": 22,
          "firstSeen": "2026-10-03T10:01:12Z",
          "lastSeen": "2026-10-03T10:14:40Z",
          "count": 412,
          "tlp": "green"
        }"#;
        let o: EvidenceObject = serde_json::from_str(json).unwrap();
        assert_eq!(o.kind, EvidenceKind::Sighting);
        assert_eq!(o.observed_behavior, vec![Behavior::SshBruteforce]);
        let now = "2026-10-03T10:20:00Z".parse().unwrap();
        o.validate(now, &doc_policy()).unwrap();
        // Documentation ranges are special-purpose and rejected by default.
        assert!(o.validate(now, &NormPolicy::default()).is_err());
    }

    #[test]
    fn unknown_behaviour_is_other_and_single_value_accepted() {
        let json = r#"{"type":"ThreatIndicator","id":"https://a.example/i/1",
          "attributedTo":"https://a.example/actor","published":"2026-10-01T00:00:00Z",
          "observableType":"domain-name","observableValue":"evil.example",
          "observedBehavior":"cryptomining","validFrom":"2026-10-01T00:00:00Z",
          "validUntil":"2026-10-02T00:00:00Z","tlp":"clear"}"#;
        let o: EvidenceObject = serde_json::from_str(json).unwrap();
        assert_eq!(o.observed_behavior, vec![Behavior::Other]);
    }

    #[test]
    fn rejects_bad_objects() {
        let now: DateTime<Utc> = "2026-10-03T10:00:00Z".parse().unwrap();
        let mut o = EvidenceObject {
            kind: EvidenceKind::Sighting,
            id: "https://a.example/s/1".into(),
            attributed_to: "https://a.example/actor".into(),
            published: now,
            updated: None,
            tlp: Tlp::Green,
            summary: None,
            observable_type: Some(ObservableType::Ipv4Addr),
            observable_value: Some("8.8.4.4".into()),
            observed_behavior: vec![Behavior::Scan],
            port: None,
            service: None,
            include_subdomains: None,
            valid_from: None,
            valid_until: None,
            confidence: None,
            infrastructure_types: vec![],
            revoked: None,
            tag: vec![],
            first_seen: Some(now),
            last_seen: Some(now),
            count: Some(1),
            indicator_refs: vec![],
            opinion: None,
        };
        let p = NormPolicy::default();
        o.validate(now, &p).unwrap();

        o.last_seen = Some(now + TimeDelta::minutes(10));
        assert_eq!(o.validate(now, &p), Err(ValidationError::Future));
        o.last_seen = Some(now - TimeDelta::minutes(10));
        assert_eq!(o.validate(now, &p), Err(ValidationError::SeenOrder));
        o.last_seen = Some(now);

        o.observable_value = Some("008.8.4.4".into());
        assert!(matches!(
            o.validate(now, &p),
            Err(ValidationError::Observable(_))
        ));
        o.observable_value = Some("8.8.4.4".into());

        o.tlp = Tlp::Red;
        assert_eq!(o.validate(now, &p), Err(ValidationError::TlpRed));
        o.tlp = Tlp::Green;

        o.observable_type = Some(ObservableType::Unknown);
        assert_eq!(o.validate(now, &p), Err(ValidationError::UnknownType));
        o.observable_type = Some(ObservableType::Ipv4Addr);

        o.id = "https://a.example/s/\u{1b}]0;x\u{7}".into();
        assert_eq!(
            o.validate(now, &p),
            Err(ValidationError::ControlCharacters("id"))
        );
        o.id = "https://a.example/s/1".into();
        o.summary = Some("two\nlines".into());
        o.validate(now, &p).unwrap();
        o.summary = Some("\u{9b}31m".into());
        assert_eq!(
            o.validate(now, &p),
            Err(ValidationError::ControlCharacters("summary"))
        );
    }

    /// Extended years parse but overflow date arithmetic in the engine.
    #[test]
    fn rejects_out_of_range_and_future_dates() {
        let now: DateTime<Utc> = "2026-10-03T10:00:00Z".parse().unwrap();
        let p = NormPolicy::default();
        let indicator = |published: &str, until: &str| -> EvidenceObject {
            serde_json::from_str(&format!(
                r#"{{"type":"ThreatIndicator","id":"https://a.example/i/1",
                  "attributedTo":"https://a.example/actor","published":"{published}",
                  "observableType":"ipv4-addr","observableValue":"8.8.4.4",
                  "observedBehavior":"scan","validFrom":"2026-10-01T00:00:00Z",
                  "validUntil":"{until}","tlp":"clear"}}"#
            ))
            .unwrap()
        };
        let ok = indicator("2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z");
        ok.validate(now, &p).unwrap();
        assert_eq!(
            indicator("+262142-12-31T00:00:00Z", "2026-10-02T00:00:00Z").validate(now, &p),
            Err(ValidationError::DateRange)
        );
        assert_eq!(
            indicator("2026-10-01T00:00:00Z", "+262142-12-31T00:00:00Z").validate(now, &p),
            Err(ValidationError::DateRange)
        );
        assert_eq!(
            indicator("2030-01-01T00:00:00Z", "2031-01-01T00:00:00Z").validate(now, &p),
            Err(ValidationError::Future)
        );
        let mut updated = ok.clone();
        updated.updated = Some(now + TimeDelta::days(1));
        assert_eq!(updated.validate(now, &p), Err(ValidationError::Future));
    }
}
