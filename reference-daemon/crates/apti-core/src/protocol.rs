//! Control socket protocol between `aptid` and `apti-tui`.
//!
//! Framing: one JSON [`Request`] per line, answered by one JSON [`Reply`]
//! per line.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::expiry::Assessment;
use crate::model::{Behavior, ObservableType, Tlp};
use crate::policy::{BehaviorOverride, OperatorPolicy, Threshold};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Status,

    ListFollowing,
    /// Follow a foreign actor given as `user@host` (WebFinger) or actor URL.
    Follow {
        handle: String,
    },
    Unfollow {
        actor: String,
    },
    Resync {
        actor: String,
    },

    ListFollowers,
    ApproveFollower {
        actor: String,
    },
    RejectFollower {
        actor: String,
    },

    ListOperators,
    /// `behavior: None` sets the operator-wide default.
    SetOperatorPolicy {
        operator: String,
        behavior: Option<Behavior>,
        policy: OperatorPolicy,
    },
    ClearOperatorPolicy {
        operator: String,
        behavior: Option<Behavior>,
    },
    /// Override the operator of an actor; `operator: None` removes the override.
    MapActor {
        actor: String,
        operator: Option<String>,
    },

    ListBehaviorPolicies,
    SetBehaviorPolicy {
        behavior: Behavior,
        overrides: BehaviorOverride,
        /// TLP for locally published Sightings of this behaviour.
        default_tlp: Option<Tlp>,
    },

    GetTlpSettings,
    SetTlpSettings(TlpSettings),

    ListReview {
        include_resolved: bool,
    },
    ResolveReview {
        id: i64,
        action: ReviewAction,
    },

    ListAllowlist,
    AddAllowlist(NewAllowlistEntry),
    RemoveAllowlist {
        id: i64,
    },

    ListActive {
        observable_type: Option<ObservableType>,
        behavior: Option<Behavior>,
        include_inactive: bool,
    },
    Lookup {
        value: String,
    },

    /// Trigger an immediate recompute of the active list.
    Recompute,

    ListTokens,
    /// Create a REST API token; answered with [`Reply::TokenCreated`].
    CreateToken(NewApiToken),
    UpdateToken {
        id: i64,
        scopes: Vec<ApiScope>,
        max_tlp: Tlp,
    },
    /// Replace the secret of a token; answered with [`Reply::TokenCreated`].
    RotateToken {
        id: i64,
    },
    DeleteToken {
        id: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum Reply {
    Done,
    Error(String),
    Status(StatusInfo),
    Following(Vec<FollowingInfo>),
    Followers(Vec<FollowerInfo>),
    Operators(Vec<OperatorInfo>),
    BehaviorPolicies(Vec<BehaviorPolicyInfo>),
    TlpSettings(TlpSettings),
    Review(Vec<ReviewItem>),
    Allowlist(Vec<AllowlistEntry>),
    Active(Vec<Assessment>),
    Lookup(LookupResult),
    Tokens(Vec<ApiTokenInfo>),
    /// The only time the daemon reveals a token secret; it stores just the
    /// SHA-512 hash.
    TokenCreated {
        token: ApiTokenInfo,
        secret: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusInfo {
    pub version: String,
    pub actor_id: String,
    pub operator_id: String,
    pub following: u64,
    pub followers: u64,
    pub pending_followers: u64,
    pub evidence: u64,
    pub active: u64,
    pub flagged: u64,
    pub review_open: u64,
    pub pending_observations: u64,
    pub delivery_queue: u64,
    pub last_recompute: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FollowingInfo {
    pub actor: String,
    pub handle: Option<String>,
    /// `pending`, `accepted` or `rejected`.
    pub state: String,
    pub operator: Option<String>,
    pub last_sync: Option<DateTime<Utc>>,
    pub last_full_sync: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub evidence: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FollowerInfo {
    pub actor: String,
    /// `pending` or `accepted`.
    pub state: String,
    pub since: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperatorInfo {
    pub id: String,
    /// How the actor→operator mapping was established: `verified`, `psl`,
    /// `manual` or `local`.
    pub source: String,
    pub actors: Vec<String>,
    pub default_policy: Option<OperatorPolicy>,
    pub behavior_policies: Vec<(Behavior, OperatorPolicy)>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BehaviorPolicyInfo {
    pub behavior: Behavior,
    pub overrides: BehaviorOverride,
    pub k: Threshold,
    pub ttl_ip_secs: i64,
    pub max_age_ip_secs: i64,
    pub ttl_domain_secs: i64,
    pub max_age_domain_secs: i64,
    pub default_tlp: Option<Tlp>,
    pub effective_tlp: Tlp,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TlpSettings {
    /// Default TLP for locally published evidence.
    pub default_tlp: Tlp,
    /// Named recipients for TLP:AMBER and AMBER+STRICT (actor URLs).
    pub amber_recipients: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewAction {
    /// Close the item without action.
    Dismiss,
    /// Add a local allowlist entry for the item's observable and behaviour.
    Suspend,
    /// Add a local allowlist entry for the observable (all behaviours).
    Allowlist,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewItem {
    pub id: i64,
    /// `dispute`, `untrusted` or `broad-allowlist`.
    pub kind: String,
    pub observable_type: ObservableType,
    pub observable_value: String,
    pub behavior: Option<Behavior>,
    pub detail: String,
    pub created: DateTime<Utc>,
    pub resolution: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowlistScope {
    /// Only affects this consumer.
    Local,
    /// Published as a `strongly-disagree` Opinion (Section 4.5).
    Published,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AllowlistEntry {
    pub id: i64,
    pub scope: AllowlistScope,
    pub observable_type: ObservableType,
    pub observable_value: String,
    /// Empty = all behaviours.
    pub behaviors: Vec<Behavior>,
    pub tlp: Option<Tlp>,
    pub valid_until: Option<DateTime<Utc>>,
    pub summary: Option<String>,
    /// Id of the published Opinion.
    pub object_id: Option<String>,
    pub created: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NewAllowlistEntry {
    pub scope: AllowlistScope,
    pub value: String,
    pub behaviors: Vec<Behavior>,
    pub tlp: Option<Tlp>,
    pub valid_until: Option<DateTime<Utc>>,
    pub summary: Option<String>,
}

/// Permission of a REST API token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiScope {
    /// Submit observations.
    Push,
    /// Read the active list and the allowlist.
    Read,
    /// Manage local allowlist entries.
    Allowlist,
    /// Additionally manage published (federated) allowlist entries.
    Publish,
}

impl ApiScope {
    pub const ALL: [ApiScope; 4] = [Self::Push, Self::Read, Self::Allowlist, Self::Publish];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::Read => "read",
            Self::Allowlist => "allowlist",
            Self::Publish => "publish",
        }
    }
}

impl fmt::Display for ApiScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ApiScope {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|x| x.as_str() == s)
            .ok_or_else(|| format!("unknown scope `{s}` (push, read, allowlist, publish)"))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApiTokenInfo {
    pub id: i64,
    pub name: String,
    pub scopes: Vec<ApiScope>,
    /// Most restrictive TLP this client may receive.
    pub max_tlp: Tlp,
    pub created: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NewApiToken {
    pub name: String,
    pub scopes: Vec<ApiScope>,
    pub max_tlp: Tlp,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceSummary {
    pub id: String,
    pub kind: String,
    pub operator: String,
    pub publisher: String,
    pub tlp: Tlp,
    pub behaviors: Vec<Behavior>,
    pub detail: String,
    pub withdrawn: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LookupResult {
    pub observable_type: ObservableType,
    pub observable_value: String,
    pub assessments: Vec<Assessment>,
    pub evidence: Vec<EvidenceSummary>,
    pub local_allowlist: Vec<AllowlistEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let r = Request::SetOperatorPolicy {
            operator: "https://example.net/org".into(),
            behavior: Some(Behavior::Scan),
            policy: OperatorPolicy {
                trusted: true,
                weight: 2.0,
            },
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains(r#""cmd":"set_operator_policy""#));
        assert_eq!(serde_json::from_str::<Request>(&s).unwrap(), r);
        let s = serde_json::to_string(&Reply::Error("x".into())).unwrap();
        assert_eq!(s, r#"{"type":"error","data":"x"}"#);
        let s = serde_json::to_string(&Request::Status).unwrap();
        assert_eq!(s, r#"{"cmd":"status"}"#);
        let r = Request::CreateToken(NewApiToken {
            name: "fw".into(),
            scopes: vec![ApiScope::Read],
            max_tlp: Tlp::Amber,
        });
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains(r#""scopes":["read"]"#));
        assert_eq!(serde_json::from_str::<Request>(&s).unwrap(), r);
    }

    #[test]
    fn scope_parse() {
        assert_eq!("allowlist".parse::<ApiScope>(), Ok(ApiScope::Allowlist));
        assert!("admin".parse::<ApiScope>().is_err());
    }
}
