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
    OperatorPolicy {
        operator: String,
    },
    ClearOperatorPolicy {
        operator: String,
    },
    MapActor,
    Behavior {
        behavior: Behavior,
    },
    Tlp,
    Allowlist,
    Lookup,
    CreateToken,
    EditToken {
        id: i64,
    },
    /// Column filter of the current table; applied locally, not a request.
    Filter,
}

pub struct Field {
    pub label: &'static str,
    pub value: String,
    pub hint: &'static str,
    /// Allowed values; non-empty makes this a select instead of free text.
    /// An empty option stands for "use the default".
    pub options: Vec<String>,
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
        options: Vec::new(),
    }
}

/// A select field; falls back to the first option if `current` is not one.
fn select(label: &'static str, options: Vec<String>, current: &str, hint: &'static str) -> Field {
    let value = if options.iter().any(|o| o == current) {
        current.to_string()
    } else {
        options.first().cloned().unwrap_or_default()
    };
    Field {
        label,
        value,
        hint,
        options,
    }
}

/// TLP options; `default` prepends an empty "use the default" option.
fn tlp_options(tlps: &[Tlp], default: bool) -> Vec<String> {
    default
        .then(String::new)
        .into_iter()
        .chain(tlps.iter().map(|t| t.as_str().to_string()))
        .collect()
}

/// `*` (operator default) followed by every behaviour.
fn behavior_options() -> Vec<String> {
    std::iter::once("*".to_string())
        .chain(Behavior::ALL.iter().map(|b| b.as_str().to_string()))
        .collect()
}

fn strings(options: &[&str]) -> Vec<String> {
    options.iter().map(|s| s.to_string()).collect()
}

/// All TLP levels, including RED (token read limits only).
const ALL_TLP: [Tlp; 5] = [
    Tlp::Clear,
    Tlp::Green,
    Tlp::Amber,
    Tlp::AmberStrict,
    Tlp::Red,
];

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
                select(
                    "Behaviour",
                    behavior_options(),
                    "*",
                    "* = operator default, or a specific behaviour",
                ),
                select(
                    "Trusted",
                    strings(&["yes", "no"]),
                    if p.trusted { "yes" } else { "no" },
                    "only trusted operators count towards the quorum",
                ),
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
            vec![select(
                "Behaviour",
                behavior_options(),
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
                select(
                    "Publish TLP",
                    tlp_options(&Tlp::SHAREABLE, true),
                    b.default_tlp.map(Tlp::as_str).unwrap_or_default(),
                    "(default) = global default TLP",
                ),
            ],
        )
    }

    pub fn tlp(t: &TlpSettings) -> Self {
        Self::new(
            " TLP settings ",
            FormKind::Tlp,
            vec![
                select(
                    "Default TLP",
                    tlp_options(&Tlp::SHAREABLE, false),
                    t.default_tlp.as_str(),
                    "TLP:RED is never shared",
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
                select(
                    "Scope",
                    strings(&["local", "published"]),
                    "local",
                    "local (only us) / published (strongly-disagree Opinion)",
                ),
                field("Behaviours", "", "comma-separated; empty = all"),
                select(
                    "TLP",
                    tlp_options(&Tlp::SHAREABLE, true),
                    "",
                    "published only; (default) = default TLP",
                ),
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
                select(
                    "Max TLP",
                    tlp_options(&ALL_TLP, false),
                    "green",
                    "highest TLP this token can read",
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
                select(
                    "Max TLP",
                    tlp_options(&ALL_TLP, false),
                    t.max_tlp.as_str(),
                    "highest TLP this token can read",
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

    pub fn filter(columns: &[&'static str], current: &[String]) -> Self {
        Self::new(
            " Filter (case-insensitive substring per column; empty = any) ",
            FormKind::Filter,
            columns
                .iter()
                .enumerate()
                .map(|(i, c)| field(c, current.get(i).cloned().unwrap_or_default(), ""))
                .collect(),
        )
    }

    /// Trimmed values of all fields.
    pub fn values(&self) -> Vec<String> {
        (0..self.fields.len())
            .map(|i| self.v(i).to_string())
            .collect()
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
            FormKind::Lookup | FormKind::Filter => "",
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
                    source: None,
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
            FormKind::Filter => return Err("filters are applied locally".into()),
        })
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        self.error = None;
        let n = self.fields.len();
        match key.code {
            KeyCode::Tab | KeyCode::Down => self.focus = (self.focus + 1) % n,
            KeyCode::BackTab | KeyCode::Up => self.focus = (self.focus + n - 1) % n,
            _ if !self.fields[self.focus].options.is_empty() => self.on_select_key(key),
            KeyCode::Backspace => {
                self.fields[self.focus].value.pop();
            }
            KeyCode::Char(c) => self.fields[self.focus].value.push(c),
            _ => {}
        }
    }

    fn on_select_key(&mut self, key: KeyEvent) {
        let fl = &mut self.fields[self.focus];
        let n = fl.options.len();
        let i = fl.options.iter().position(|o| *o == fl.value).unwrap_or(0);
        let i = match key.code {
            KeyCode::Right | KeyCode::Char(' ') => (i + 1) % n,
            KeyCode::Left => (i + n - 1) % n,
            KeyCode::Home => 0,
            KeyCode::End => n - 1,
            _ => return,
        };
        fl.value = fl.options[i].clone();
    }

    pub fn draw(&self, f: &mut Frame) {
        // Input line, optional hint line, spacing.
        let heights: Vec<u16> = self
            .fields
            .iter()
            .map(|fl| if fl.hint.is_empty() { 2 } else { 3 })
            .collect();
        let height = heights.iter().sum::<u16>() + 4;
        let area = centered(f.area(), 80, height);
        f.render_widget(Clear, area);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(self.title.as_str())
            .title_bottom(" ⏎ submit  Tab next field  ←/→ change option  Esc cancel ");
        let inner = block.inner(area);
        f.render_widget(block, area);
        let mut constraints: Vec<Constraint> =
            heights.iter().map(|h| Constraint::Length(*h)).collect();
        constraints.push(Constraint::Length(1));
        let rows = Layout::vertical(constraints).split(inner);
        for (i, fl) in self.fields.iter().enumerate() {
            let focused = i == self.focus;
            let style = if focused {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            };
            let input = if fl.options.is_empty() {
                let cursor = if focused { "▏" } else { "" };
                Line::from(vec![
                    Span::raw(fl.value.clone()),
                    Span::styled(cursor, Style::default().add_modifier(Modifier::SLOW_BLINK)),
                ])
            } else {
                let value = if fl.value.is_empty() {
                    "(default)"
                } else {
                    fl.value.as_str()
                };
                if focused {
                    Line::from(vec![
                        Span::styled("◀ ", style),
                        Span::raw(value.to_string()),
                        Span::styled(" ▶", style),
                    ])
                } else {
                    Line::from(value.to_string())
                }
            };
            let p = Paragraph::new(vec![
                input,
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
        // Max TLP select starts at green; one step right is amber.
        f.focus = 2;
        f.on_key(KeyEvent::from(KeyCode::Right));
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

    #[test]
    fn select_keys() {
        let mut f = Form::create_token();
        f.focus = 2;
        let key = |f: &mut Form, code| {
            f.on_key(KeyEvent::from(code));
            f.fields[2].value.clone()
        };
        assert_eq!(f.fields[2].value, "green");
        assert_eq!(key(&mut f, KeyCode::Left), "clear");
        assert_eq!(key(&mut f, KeyCode::Left), "red");
        assert_eq!(key(&mut f, KeyCode::Right), "clear");
        assert_eq!(key(&mut f, KeyCode::Char(' ')), "green");
        assert_eq!(key(&mut f, KeyCode::End), "red");
        assert_eq!(key(&mut f, KeyCode::Home), "clear");
        assert_eq!(key(&mut f, KeyCode::Char('x')), "clear");
        assert_eq!(key(&mut f, KeyCode::Backspace), "clear");
    }

    #[test]
    fn selects_start_at_current_value() {
        let f = Form::edit_token(&ApiTokenInfo {
            id: 1,
            name: "fw".into(),
            scopes: vec![ApiScope::Read],
            max_tlp: Tlp::AmberStrict,
            created: Utc::now(),
            last_used: None,
        });
        assert_eq!(f.fields[1].value, "amber+strict");
        let f = Form::allowlist();
        assert_eq!(f.fields[1].value, "local");
        assert_eq!(f.fields[3].value, "");
        assert_eq!(f.fields[3].options[0], "");
        assert!(!f.fields[3].options.contains(&"red".to_string()));
    }
}
