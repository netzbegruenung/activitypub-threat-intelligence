//! Modal input forms.

use apti_core::policy::{BehaviorOverride, OperatorPolicy, Threshold};
use apti_core::protocol::{
    AllowlistScope, ApiScope, ApiTokenInfo, BehaviorPolicyInfo, NewAllowlistEntry, NewApiToken,
    OperatorInfo, Request, TlpSettings,
};
use apti_core::{Behavior, Tlp};
use chrono::{TimeDelta, Utc};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::{centered, fmt_secs};

pub enum FormKind {
    Follow,
    OperatorPolicy { operator: String },
    ClearOperatorPolicy { operator: String },
    MapActor,
    Behavior { behavior: Behavior },
    Tlp,
    Allowlist,
    Lookup,
    CreateToken,
    EditToken { id: i64 },
}

pub struct Field {
    pub label: &'static str,
    pub value: String,
    pub hint: &'static str,
}

pub struct Form {
    pub title: String,
    pub fields: Vec<Field>,
    pub focus: usize,
    pub kind: FormKind,
    pub error: Option<String>,
}

fn field(label: &'static str, value: impl Into<String>, hint: &'static str) -> Field {
    Field {
        label,
        value: value.into(),
        hint,
    }
}

/// Parse `90`, `90s`, `15m`, `2h`, `7d`; empty means "default".
pub fn parse_duration(s: &str) -> Result<Option<i64>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86400),
        _ => (s, 1),
    };
    let n: i64 = num
        .trim()
        .parse()
        .map_err(|_| format!("invalid duration `{s}`"))?;
    if n <= 0 {
        return Err("duration must be positive".into());
    }
    Ok(Some(n * mult))
}

fn parse_bool(s: &str) -> Result<bool, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" | "true" | "1" => Ok(true),
        "n" | "no" | "false" | "0" => Ok(false),
        other => Err(format!("expected yes/no, got `{other}`")),
    }
}

fn parse_behavior_opt(s: &str) -> Result<Option<Behavior>, String> {
    match s.trim() {
        "" | "*" => Ok(None),
        b => b.parse().map(Some),
    }
}

fn parse_tlp_opt(s: &str) -> Result<Option<Tlp>, String> {
    match s.trim().to_ascii_lowercase().trim_start_matches("tlp:") {
        "" => Ok(None),
        t => t.parse().map(Some),
    }
}

fn parse_scopes(s: &str) -> Result<Vec<ApiScope>, String> {
    let scopes = s
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase().parse())
        .collect::<Result<Vec<ApiScope>, _>>()?;
    if scopes.is_empty() {
        return Err("at least one scope is required".into());
    }
    Ok(scopes)
}

fn join_scopes(scopes: &[ApiScope]) -> String {
    scopes
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

impl Form {
    fn new(title: impl Into<String>, kind: FormKind, fields: Vec<Field>) -> Self {
        Self {
            title: title.into(),
            fields,
            focus: 0,
            kind,
            error: None,
        }
    }

    pub fn follow() -> Self {
        Self::new(
            " Follow actor ",
            FormKind::Follow,
            vec![field("Actor", "", "user@host (WebFinger) or actor URL")],
        )
    }

    pub fn operator_policy(o: &OperatorInfo) -> Self {
        let p = o.default_policy.unwrap_or_default();
        Self::new(
            format!(" Trust policy: {} ", o.id),
            FormKind::OperatorPolicy {
                operator: o.id.clone(),
            },
            vec![
                field(
                    "Behaviour",
                    "*",
                    "* = operator default, or e.g. ssh-bruteforce",
                ),
                field("Trusted", if p.trusted { "yes" } else { "no" }, "yes / no"),
                field(
                    "Weight",
                    p.weight.to_string(),
                    "w(p, b) >= 0; w = k lets this operator activate alone",
                ),
            ],
        )
    }

    pub fn clear_operator_policy(operator: &str) -> Self {
        Self::new(
            format!(" Clear policy: {operator} "),
            FormKind::ClearOperatorPolicy {
                operator: operator.to_string(),
            },
            vec![field(
                "Behaviour",
                "*",
                "* = operator default, or a behaviour",
            )],
        )
    }

    pub fn map_actor(actor: &str) -> Self {
        Self::new(
            " Map actor to operator ",
            FormKind::MapActor,
            vec![
                field("Actor", actor, "actor URL"),
                field(
                    "Operator",
                    "",
                    "operator id (Organization URL or domain:...); empty = remove override",
                ),
            ],
        )
    }

    pub fn behavior(b: &BehaviorPolicyInfo) -> Self {
        let o = b.overrides;
        Self::new(
            format!(" Behaviour policy: {} ", b.behavior),
            FormKind::Behavior {
                behavior: b.behavior,
            },
            vec![
                field(
                    "k",
                    o.k.map(|k| k.to_string()).unwrap_or_default(),
                    "quorum weight, `off`, or empty for default",
                ),
                field(
                    "T",
                    o.ttl_secs.map(fmt_secs).unwrap_or_default(),
                    "Sighting TTL, e.g. 1d; empty = Table 1 default",
                ),
                field(
                    "M",
                    o.max_age_secs.map(fmt_secs).unwrap_or_default(),
                    "max evidence age, e.g. 14d; empty = default (IP ≤ 90d)",
                ),
                field(
                    "Publish TLP",
                    b.default_tlp
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_default(),
                    "clear / green / amber / amber+strict; empty = global default",
                ),
            ],
        )
    }

    pub fn tlp(t: &TlpSettings) -> Self {
        Self::new(
            " TLP settings ",
            FormKind::Tlp,
            vec![
                field(
                    "Default TLP",
                    t.default_tlp.as_str(),
                    "clear / green / amber / amber+strict",
                ),
                field(
                    "AMBER recipients",
                    t.amber_recipients.join(", "),
                    "comma-separated actor URLs",
                ),
            ],
        )
    }

    pub fn allowlist() -> Self {
        Self::new(
            " Add allowlist entry ",
            FormKind::Allowlist,
            vec![
                field("Value", "", "IP, prefix or domain"),
                field(
                    "Scope",
                    "local",
                    "local (only us) / published (strongly-disagree Opinion)",
                ),
                field("Behaviours", "", "comma-separated; empty = all"),
                field("TLP", "", "published only; empty = default TLP"),
                field(
                    "Valid for",
                    "",
                    "e.g. 90d; empty = unlimited (local) / 90d (published)",
                ),
                field("Summary", "", "rationale; must not identify victims"),
            ],
        )
    }

    pub fn create_token() -> Self {
        Self::new(
            " Create API token ",
            FormKind::CreateToken,
            vec![
                field("Name", "", "e.g. firewall; [A-Za-z0-9_.-], unique"),
                field(
                    "Scopes",
                    "read",
                    "comma-separated: push, read, allowlist, publish",
                ),
                field(
                    "Max TLP",
                    "green",
                    "highest TLP readable: clear / green / amber / amber+strict / red",
                ),
            ],
        )
    }

    pub fn edit_token(t: &ApiTokenInfo) -> Self {
        Self::new(
            format!(" Edit API token: {} ", t.name),
            FormKind::EditToken { id: t.id },
            vec![
                field(
                    "Scopes",
                    join_scopes(&t.scopes),
                    "comma-separated: push, read, allowlist, publish",
                ),
                field(
                    "Max TLP",
                    t.max_tlp.as_str(),
                    "clear / green / amber / amber+strict / red",
                ),
            ],
        )
    }

    pub fn lookup() -> Self {
        Self::new(
            " Lookup ",
            FormKind::Lookup,
            vec![field("Value", "", "IP address, prefix or domain")],
        )
    }

    pub fn done_message(&self) -> &'static str {
        match self.kind {
            FormKind::Follow => "follow request sent",
            FormKind::OperatorPolicy { .. } => "operator policy saved",
            FormKind::ClearOperatorPolicy { .. } => "operator policy cleared",
            FormKind::MapActor => "operator mapping saved",
            FormKind::Behavior { .. } => "behaviour policy saved",
            FormKind::Tlp => "TLP settings saved",
            FormKind::Allowlist => "allowlist entry added",
            FormKind::Lookup => "",
            FormKind::CreateToken => "token created",
            FormKind::EditToken { .. } => "token updated",
        }
    }

    fn v(&self, i: usize) -> &str {
        self.fields[i].value.trim()
    }

    pub fn to_request(&self) -> Result<Request, String> {
        Ok(match &self.kind {
            FormKind::Follow => {
                if self.v(0).is_empty() {
                    return Err("enter user@host or an actor URL".into());
                }
                Request::Follow {
                    handle: self.v(0).to_string(),
                }
            }
            FormKind::OperatorPolicy { operator } => {
                let weight: f64 = self
                    .v(2)
                    .parse()
                    .map_err(|_| "weight must be a number".to_string())?;
                if !weight.is_finite() || weight < 0.0 {
                    return Err("weight must be >= 0".into());
                }
                Request::SetOperatorPolicy {
                    operator: operator.clone(),
                    behavior: parse_behavior_opt(self.v(0))?,
                    policy: OperatorPolicy {
                        trusted: parse_bool(self.v(1))?,
                        weight,
                    },
                }
            }
            FormKind::ClearOperatorPolicy { operator } => Request::ClearOperatorPolicy {
                operator: operator.clone(),
                behavior: parse_behavior_opt(self.v(0))?,
            },
            FormKind::MapActor => {
                if self.v(0).is_empty() {
                    return Err("actor is required".into());
                }
                Request::MapActor {
                    actor: self.v(0).to_string(),
                    operator: (!self.v(1).is_empty()).then(|| self.v(1).to_string()),
                }
            }
            FormKind::Behavior { behavior } => {
                let k = match self.v(0) {
                    "" => None,
                    k => Some(k.parse::<Threshold>()?),
                };
                Request::SetBehaviorPolicy {
                    behavior: *behavior,
                    overrides: BehaviorOverride {
                        k,
                        ttl_secs: parse_duration(self.v(1))?,
                        max_age_secs: parse_duration(self.v(2))?,
                    },
                    default_tlp: parse_tlp_opt(self.v(3))?,
                }
            }
            FormKind::Tlp => {
                let default_tlp = parse_tlp_opt(self.v(0))?.ok_or("default TLP is required")?;
                if default_tlp == Tlp::Red {
                    return Err("TLP:RED is never shared".into());
                }
                Request::SetTlpSettings(TlpSettings {
                    default_tlp,
                    amber_recipients: self
                        .v(1)
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect(),
                })
            }
            FormKind::Allowlist => {
                if self.v(0).is_empty() {
                    return Err("value is required".into());
                }
                let scope = match self.v(1) {
                    "local" | "" => AllowlistScope::Local,
                    "published" | "publish" => AllowlistScope::Published,
                    s => return Err(format!("scope must be local or published, got `{s}`")),
                };
                let behaviors = self
                    .v(2)
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::parse)
                    .collect::<Result<Vec<Behavior>, _>>()?;
                let valid_until =
                    parse_duration(self.v(4))?.map(|s| Utc::now() + TimeDelta::seconds(s));
                Request::AddAllowlist(NewAllowlistEntry {
                    scope,
                    value: self.v(0).to_string(),
                    behaviors,
                    tlp: parse_tlp_opt(self.v(3))?,
                    valid_until,
                    summary: (!self.v(5).is_empty()).then(|| self.v(5).to_string()),
                })
            }
            FormKind::Lookup => {
                if self.v(0).is_empty() {
                    return Err("value is required".into());
                }
                Request::Lookup {
                    value: self.v(0).to_string(),
                }
            }
            FormKind::CreateToken => {
                if self.v(0).is_empty() {
                    return Err("name is required".into());
                }
                Request::CreateToken(NewApiToken {
                    name: self.v(0).to_string(),
                    scopes: parse_scopes(self.v(1))?,
                    max_tlp: parse_tlp_opt(self.v(2))?.ok_or("max TLP is required")?,
                })
            }
            FormKind::EditToken { id } => Request::UpdateToken {
                id: *id,
                scopes: parse_scopes(self.v(0))?,
                max_tlp: parse_tlp_opt(self.v(1))?.ok_or("max TLP is required")?,
            },
        })
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        self.error = None;
        let n = self.fields.len();
        match key.code {
            KeyCode::Tab | KeyCode::Down => self.focus = (self.focus + 1) % n,
            KeyCode::BackTab | KeyCode::Up => self.focus = (self.focus + n - 1) % n,
            KeyCode::Backspace => {
                self.fields[self.focus].value.pop();
            }
            KeyCode::Char(c) => self.fields[self.focus].value.push(c),
            _ => {}
        }
    }

    pub fn draw(&self, f: &mut Frame) {
        let height = self.fields.len() as u16 * 3 + 4;
        let area = centered(f.area(), 80, height);
        f.render_widget(Clear, area);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(self.title.as_str())
            .title_bottom(" ⏎ submit  Tab next field  Esc cancel ");
        let inner = block.inner(area);
        f.render_widget(block, area);
        let mut constraints: Vec<Constraint> =
            self.fields.iter().map(|_| Constraint::Length(3)).collect();
        constraints.push(Constraint::Length(1));
        let rows = Layout::vertical(constraints).split(inner);
        for (i, fl) in self.fields.iter().enumerate() {
            let focused = i == self.focus;
            let style = if focused {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            };
            let cursor = if focused { "▏" } else { "" };
            let p = Paragraph::new(vec![
                Line::from(vec![
                    Span::raw(fl.value.clone()),
                    Span::styled(cursor, Style::default().add_modifier(Modifier::SLOW_BLINK)),
                ]),
                Line::from(Span::styled(fl.hint, Style::default().fg(Color::DarkGray))),
            ])
            .block(
                Block::default()
                    .borders(Borders::LEFT)
                    .border_style(style)
                    .title(Span::styled(fl.label, style)),
            );
            f.render_widget(p, rows[i]);
        }
        if let Some(e) = &self.error {
            f.render_widget(
                Paragraph::new(e.as_str()).style(Style::default().fg(Color::Red)),
                rows[self.fields.len()],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration(""), Ok(None));
        assert_eq!(parse_duration("90"), Ok(Some(90)));
        assert_eq!(parse_duration("15m"), Ok(Some(900)));
        assert_eq!(parse_duration("2h"), Ok(Some(7200)));
        assert_eq!(parse_duration("7d"), Ok(Some(604_800)));
        assert!(parse_duration("0").is_err());
        assert!(parse_duration("x").is_err());
    }

    #[test]
    fn behaviour_form_builds_request() {
        let mut f = Form::new(
            " t ",
            FormKind::Behavior {
                behavior: Behavior::Scan,
            },
            vec![
                field("k", "off", ""),
                field("T", "2d", ""),
                field("M", "", ""),
                field("TLP", "amber", ""),
            ],
        );
        let Request::SetBehaviorPolicy {
            overrides,
            default_tlp,
            ..
        } = f.to_request().unwrap()
        else {
            panic!()
        };
        assert_eq!(overrides.k, Some(Threshold::Off));
        assert_eq!(overrides.ttl_secs, Some(172_800));
        assert_eq!(overrides.max_age_secs, None);
        assert_eq!(default_tlp, Some(Tlp::Amber));
        f.fields[0].value = "0".into();
        assert!(f.to_request().is_err());
    }

    #[test]
    fn allowlist_form() {
        let mut f = Form::allowlist();
        f.fields[0].value = "203.0.113.0/24".into();
        f.fields[1].value = "published".into();
        f.fields[2].value = "smtp-spam, scan".into();
        let Request::AddAllowlist(e) = f.to_request().unwrap() else {
            panic!()
        };
        assert_eq!(e.scope, AllowlistScope::Published);
        assert_eq!(e.behaviors, vec![Behavior::SmtpSpam, Behavior::Scan]);
        f.fields[2].value = "nope".into();
        assert!(f.to_request().is_err());
    }

    #[test]
    fn token_form() {
        let mut f = Form::create_token();
        f.fields[0].value = "firewall".into();
        f.fields[1].value = "Read, allowlist".into();
        f.fields[2].value = "TLP:AMBER".into();
        let Request::CreateToken(t) = f.to_request().unwrap() else {
            panic!()
        };
        assert_eq!(t.scopes, vec![ApiScope::Read, ApiScope::Allowlist]);
        assert_eq!(t.max_tlp, Tlp::Amber);
        f.fields[1].value = "".into();
        assert!(f.to_request().is_err());
        f.fields[1].value = "admin".into();
        assert!(f.to_request().is_err());
    }
}
