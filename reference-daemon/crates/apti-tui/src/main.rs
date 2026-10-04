//! Terminal UI for aptid (Appendix D): follow actors, set per-operator trust,
//! per-behaviour k/T/M and TLP, approve followers, work the review queue and
//! manage allowlists and REST API tokens.

mod client;
mod form;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use apti_core::expiry::Assessment;
use apti_core::policy::OperatorPolicy;
use apti_core::protocol::*;
use apti_core::Tlp;
use chrono::{DateTime, Utc};
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
    Table, TableState, Tabs, Wrap,
};
use ratatui::{DefaultTerminal, Frame};

use crate::client::Client;
use crate::form::{Form, FormKind};

/// Terminal UI for the AP-TI reference daemon.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the aptid control socket.
    #[arg(short, long, default_value = "/run/aptid/control.sock")]
    socket: PathBuf,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Dashboard,
    Following,
    Followers,
    Operators,
    Behaviors,
    Tokens,
    Review,
    Allowlist,
    Active,
    Lookup,
}

const TABS: [(Tab, &str); 10] = [
    (Tab::Dashboard, "Status"),
    (Tab::Following, "Following"),
    (Tab::Followers, "Followers"),
    (Tab::Operators, "Operators"),
    (Tab::Behaviors, "Behaviours"),
    (Tab::Tokens, "Tokens"),
    (Tab::Review, "Review"),
    (Tab::Allowlist, "Allowlist"),
    (Tab::Active, "Active"),
    (Tab::Lookup, "Lookup"),
];

enum Modal {
    Form(Form),
    Confirm {
        text: String,
        request: Request,
    },
    /// A newly created token secret, shown exactly once.
    Secret {
        name: String,
        secret: String,
    },
}

#[derive(Default)]
struct Data {
    status: Option<StatusInfo>,
    following: Vec<FollowingInfo>,
    followers: Vec<FollowerInfo>,
    operators: Vec<OperatorInfo>,
    behaviors: Vec<BehaviorPolicyInfo>,
    tlp: Option<TlpSettings>,
    tokens: Vec<ApiTokenInfo>,
    review: Vec<ReviewItem>,
    show_resolved: bool,
    allowlist: Vec<AllowlistEntry>,
    active: Vec<Assessment>,
    include_inactive: bool,
    lookup: Option<LookupResult>,
}

struct App {
    client: Client,
    tab: usize,
    table: TableState,
    data: Data,
    /// Per-tab column filters, indexed like [`TABS`] and by column.
    filters: Vec<Vec<String>>,
    modal: Option<Modal>,
    message: Option<(String, bool)>,
    last_refresh: Instant,
    quit: bool,
}

fn ago(t: Option<DateTime<Utc>>) -> String {
    let Some(t) = t else { return "never".into() };
    let s = (Utc::now() - t).num_seconds();
    match s {
        s if s < 0 => "in the future".into(),
        s if s < 120 => format!("{s}s ago"),
        s if s < 7200 => format!("{}m ago", s / 60),
        s if s < 172_800 => format!("{}h ago", s / 3600),
        s => format!("{}d ago", s / 86400),
    }
}

fn until(t: Option<DateTime<Utc>>) -> String {
    let Some(t) = t else { return "-".into() };
    let s = (t - Utc::now()).num_seconds();
    match s {
        s if s <= 0 => "expired".into(),
        s if s < 7200 => format!("{}m", s / 60),
        s if s < 172_800 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86400),
    }
}

pub fn fmt_secs(s: i64) -> String {
    if s % 86400 == 0 {
        format!("{}d", s / 86400)
    } else if s % 3600 == 0 {
        format!("{}h", s / 3600)
    } else if s % 60 == 0 {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}

fn tlp_style(t: Tlp) -> Style {
    match t {
        Tlp::Clear => Style::default().fg(Color::White),
        Tlp::Green => Style::default().fg(Color::Green),
        Tlp::Amber | Tlp::AmberStrict => Style::default().fg(Color::Yellow),
        Tlp::Red => Style::default().fg(Color::Red),
    }
}

fn tlp_span(t: Tlp) -> Span<'static> {
    Span::styled(format!("TLP:{}", t.as_str().to_uppercase()), tlp_style(t))
}

/// Whether a row matches all column filters (case-insensitive substring).
fn row_matches(cells: &[Span], filter: &[String]) -> bool {
    filter.iter().enumerate().all(|(i, f)| {
        f.is_empty()
            || cells
                .get(i)
                .is_some_and(|c| c.content.to_lowercase().contains(&f.to_lowercase()))
    })
}

fn policy_str(p: Option<OperatorPolicy>) -> String {
    match p {
        None => "untrusted (default)".into(),
        Some(p) if p.trusted => format!("trusted, w={}", p.weight),
        Some(p) => format!("untrusted, w={}", p.weight),
    }
}

impl App {
    fn new(client: Client) -> Self {
        Self {
            client,
            tab: 0,
            table: TableState::default().with_selected(Some(0)),
            data: Data::default(),
            filters: vec![Vec::new(); TABS.len()],
            modal: None,
            message: None,
            last_refresh: Instant::now(),
            quit: false,
        }
    }

    fn current(&self) -> Tab {
        TABS[self.tab].0
    }

    fn info(&mut self, msg: impl Into<String>) {
        self.message = Some((msg.into(), false));
    }

    fn error(&mut self, msg: impl Into<String>) {
        self.message = Some((msg.into(), true));
    }

    /// Send a request; reports errors in the status line.
    fn call(&mut self, req: Request) -> Option<Reply> {
        match self.client.request(req) {
            Ok(Reply::Error(e)) => {
                self.error(e);
                None
            }
            Ok(r) => Some(r),
            Err(e) => {
                self.error(format!("{e:#}"));
                None
            }
        }
    }

    fn refresh(&mut self) {
        self.last_refresh = Instant::now();
        match self.current() {
            Tab::Dashboard => {
                if let Some(Reply::Status(s)) = self.call(Request::Status) {
                    self.data.status = Some(s);
                }
                if let Some(Reply::TlpSettings(t)) = self.call(Request::GetTlpSettings) {
                    self.data.tlp = Some(t);
                }
            }
            Tab::Following => {
                if let Some(Reply::Following(f)) = self.call(Request::ListFollowing) {
                    self.data.following = f;
                }
            }
            Tab::Followers => {
                if let Some(Reply::Followers(f)) = self.call(Request::ListFollowers) {
                    self.data.followers = f;
                }
            }
            Tab::Operators => {
                if let Some(Reply::Operators(o)) = self.call(Request::ListOperators) {
                    self.data.operators = o;
                }
            }
            Tab::Behaviors => {
                if let Some(Reply::BehaviorPolicies(b)) = self.call(Request::ListBehaviorPolicies) {
                    self.data.behaviors = b;
                }
            }
            Tab::Tokens => {
                if let Some(Reply::Tokens(t)) = self.call(Request::ListTokens) {
                    self.data.tokens = t;
                }
            }
            Tab::Review => {
                let include_resolved = self.data.show_resolved;
                if let Some(Reply::Review(r)) = self.call(Request::ListReview { include_resolved })
                {
                    self.data.review = r;
                }
            }
            Tab::Allowlist => {
                if let Some(Reply::Allowlist(a)) = self.call(Request::ListAllowlist) {
                    self.data.allowlist = a;
                }
            }
            Tab::Active => {
                let include_inactive = self.data.include_inactive;
                if let Some(Reply::Active(a)) = self.call(Request::ListActive {
                    observable_type: None,
                    behavior: None,
                    include_inactive,
                }) {
                    self.data.active = a;
                }
            }
            Tab::Lookup => {
                if let Some(l) = &self.data.lookup {
                    let value = l.observable_value.clone();
                    if let Some(Reply::Lookup(l)) = self.call(Request::Lookup { value }) {
                        self.data.lookup = Some(l);
                    }
                }
            }
        }
        self.clamp_selection();
    }

    fn clamp_selection(&mut self) {
        let n = self.rows();
        let sel = self.table.selected().unwrap_or(0).min(n.saturating_sub(1));
        self.table.select(Some(sel));
    }

    /// Displayed cells of all rows of the current tab's table (unfiltered).
    fn cells(&self) -> Vec<Vec<Span<'static>>> {
        let d = &self.data;
        match self.current() {
            Tab::Following => d.following.iter().map(following_cells).collect(),
            Tab::Followers => d.followers.iter().map(follower_cells).collect(),
            Tab::Operators => d.operators.iter().map(operator_cells).collect(),
            Tab::Behaviors => d.behaviors.iter().map(behavior_cells).collect(),
            Tab::Tokens => d.tokens.iter().map(token_cells).collect(),
            Tab::Review => d.review.iter().map(review_cells).collect(),
            Tab::Allowlist => d.allowlist.iter().map(allowlist_cells).collect(),
            Tab::Active => d.active.iter().map(assessment_cells).collect(),
            Tab::Lookup => d
                .lookup
                .iter()
                .flat_map(|l| l.evidence.iter().map(evidence_cells))
                .collect(),
            Tab::Dashboard => Vec::new(),
        }
    }

    fn filter(&self) -> &[String] {
        &self.filters[self.tab]
    }

    /// Indices of the rows that pass the current tab's filter.
    fn visible_of(&self, cells: &[Vec<Span>]) -> Vec<usize> {
        cells
            .iter()
            .enumerate()
            .filter(|(_, c)| row_matches(c, self.filter()))
            .map(|(i, _)| i)
            .collect()
    }

    fn visible(&self) -> Vec<usize> {
        self.visible_of(&self.cells())
    }

    fn rows(&self) -> usize {
        self.visible().len()
    }

    fn selected(&self) -> usize {
        self.table.selected().unwrap_or(0)
    }

    /// Data index of the selected row, taking the filter into account.
    fn item(&self) -> Option<usize> {
        self.visible().get(self.selected()).copied()
    }

    fn set_filter(&mut self, filter: Vec<String>) {
        let active = filter.iter().any(|f| !f.is_empty());
        self.filters[self.tab] = if active { filter } else { Vec::new() };
        self.table.select(Some(0));
        self.clamp_selection();
        if active {
            self.info(format!("{} matching rows", self.rows()));
        } else {
            self.info("filter cleared");
        }
    }

    fn switch(&mut self, tab: usize) {
        self.tab = tab % TABS.len();
        self.table.select(Some(0));
        self.message = None;
        self.refresh();
    }

    /// Execute an action request and refresh on success. Returns false if
    /// the request failed.
    fn act(&mut self, req: Request, ok: &str) -> bool {
        match self.call(req) {
            Some(Reply::Done) => self.info(ok),
            Some(Reply::TokenCreated { token, secret }) => {
                self.info(format!("{ok}: {}", token.name));
                self.modal = Some(Modal::Secret {
                    name: token.name,
                    secret,
                });
            }
            Some(_) => {
                self.error("unexpected reply from daemon");
                return false;
            }
            None => return false,
        }
        self.refresh();
        true
    }

    fn confirm(&mut self, text: String, request: Request) {
        self.modal = Some(Modal::Confirm { text, request });
    }

    fn on_key(&mut self, key: KeyEvent) {
        if let Some(modal) = self.modal.take() {
            self.on_modal_key(modal, key);
            return;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => self.quit = true,
            KeyCode::Tab | KeyCode::Right => self.switch(self.tab + 1),
            KeyCode::BackTab | KeyCode::Left => self.switch(self.tab + TABS.len() - 1),
            KeyCode::Char(c @ '0'..='9') => {
                let i = if c == '0' {
                    9
                } else {
                    c as usize - '1' as usize
                };
                self.switch(i);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let n = self.rows();
                if n > 0 {
                    self.table.select(Some((self.selected() + 1).min(n - 1)));
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.table.select(Some(self.selected().saturating_sub(1)));
            }
            KeyCode::PageDown => {
                let n = self.rows();
                self.table
                    .select(Some((self.selected() + 20).min(n.saturating_sub(1))));
            }
            KeyCode::PageUp => self.table.select(Some(self.selected().saturating_sub(20))),
            KeyCode::Home => self.table.select(Some(0)),
            KeyCode::End => self.table.select(Some(self.rows().saturating_sub(1))),
            KeyCode::Char('r') => {
                self.refresh();
                self.info("refreshed");
            }
            KeyCode::Char('R') => {
                self.act(Request::Recompute, "recomputed active list");
            }
            KeyCode::Char('f') if !header(self.current()).is_empty() => {
                let form = Form::filter(header(self.current()), self.filter());
                self.modal = Some(Modal::Form(form));
            }
            KeyCode::Char('F') if !header(self.current()).is_empty() => self.set_filter(Vec::new()),
            KeyCode::Char(c) => self.tab_action(c),
            KeyCode::Enter => self.tab_action('\n'),
            _ => {}
        }
    }

    fn tab_action(&mut self, c: char) {
        // Out of range (no row selected) makes every `get(i)` below miss.
        let i = self.item().unwrap_or(usize::MAX);
        match (self.current(), c) {
            (Tab::Following, 'a') => self.modal = Some(Modal::Form(Form::follow())),
            (Tab::Following, 'd') => {
                if let Some(f) = self.data.following.get(i) {
                    let actor = f.actor.clone();
                    self.confirm(format!("Unfollow {actor}?"), Request::Unfollow { actor });
                }
            }
            (Tab::Following, 's') => {
                if let Some(f) = self.data.following.get(i) {
                    let actor = f.actor.clone();
                    self.act(Request::Resync { actor }, "full resync scheduled");
                }
            }
            (Tab::Followers, 'a') => {
                if let Some(f) = self.data.followers.get(i) {
                    let actor = f.actor.clone();
                    self.act(Request::ApproveFollower { actor }, "follower approved");
                }
            }
            (Tab::Followers, 'x') => {
                if let Some(f) = self.data.followers.get(i) {
                    let actor = f.actor.clone();
                    self.confirm(
                        format!("Reject / remove follower {actor}?"),
                        Request::RejectFollower { actor },
                    );
                }
            }
            (Tab::Operators, 't') => {
                if let Some(o) = self.data.operators.get(i) {
                    let cur = o.default_policy.unwrap_or_default();
                    let policy = OperatorPolicy {
                        trusted: !cur.trusted,
                        weight: cur.weight,
                    };
                    let operator = o.id.clone();
                    self.act(
                        Request::SetOperatorPolicy {
                            operator,
                            behavior: None,
                            policy,
                        },
                        if policy.trusted {
                            "operator trusted"
                        } else {
                            "operator untrusted"
                        },
                    );
                }
            }
            (Tab::Operators, 'e' | '\n') => {
                if let Some(o) = self.data.operators.get(i) {
                    self.modal = Some(Modal::Form(Form::operator_policy(o)));
                }
            }
            (Tab::Operators, 'c') => {
                if let Some(o) = self.data.operators.get(i) {
                    self.modal = Some(Modal::Form(Form::clear_operator_policy(&o.id)));
                }
            }
            (Tab::Operators, 'm') => {
                let actor = self
                    .data
                    .operators
                    .get(i)
                    .and_then(|o| o.actors.first().cloned())
                    .unwrap_or_default();
                self.modal = Some(Modal::Form(Form::map_actor(&actor)));
            }
            (Tab::Behaviors, 'e' | '\n') => {
                if let Some(b) = self.data.behaviors.get(i) {
                    self.modal = Some(Modal::Form(Form::behavior(b)));
                }
            }
            (Tab::Dashboard, 'e' | '\n') => {
                if let Some(t) = &self.data.tlp {
                    self.modal = Some(Modal::Form(Form::tlp(t)));
                }
            }
            (Tab::Tokens, 'a') => self.modal = Some(Modal::Form(Form::create_token())),
            (Tab::Tokens, 'e' | '\n') => {
                if let Some(t) = self.data.tokens.get(i) {
                    self.modal = Some(Modal::Form(Form::edit_token(t)));
                }
            }
            (Tab::Tokens, 'n') => {
                if let Some(t) = self.data.tokens.get(i) {
                    self.confirm(
                        format!(
                            "Generate a new secret for token {}? The current secret stops working immediately.",
                            t.name
                        ),
                        Request::RotateToken { id: t.id },
                    );
                }
            }
            (Tab::Tokens, 'd') => {
                if let Some(t) = self.data.tokens.get(i) {
                    self.confirm(
                        format!("Delete token {}? Clients using it lose access.", t.name),
                        Request::DeleteToken { id: t.id },
                    );
                }
            }
            (Tab::Review, 'd') => self.resolve(i, ReviewAction::Dismiss),
            (Tab::Review, 's') => self.resolve(i, ReviewAction::Suspend),
            (Tab::Review, 'w') => self.resolve(i, ReviewAction::Allowlist),
            (Tab::Review, 'h') => {
                self.data.show_resolved = !self.data.show_resolved;
                self.refresh();
            }
            (Tab::Review, '\n') => {
                if let Some(r) = self.data.review.get(i) {
                    let v = r.observable_value.clone();
                    self.lookup(v);
                }
            }
            (Tab::Allowlist, 'a') => self.modal = Some(Modal::Form(Form::allowlist())),
            (Tab::Allowlist, 'd') => {
                if let Some(e) = self.data.allowlist.get(i) {
                    let what = if e.scope == AllowlistScope::Published {
                        " (sends Delete to followers)"
                    } else {
                        ""
                    };
                    self.confirm(
                        format!("Remove allowlist entry {}{what}?", e.observable_value),
                        Request::RemoveAllowlist { id: e.id },
                    );
                }
            }
            (Tab::Active, 'i') => {
                self.data.include_inactive = !self.data.include_inactive;
                self.refresh();
            }
            (Tab::Active, 'd') => {
                if let Some(a) = self.data.active.get(i) {
                    if a.allowlisted {
                        self.info("already allowlisted");
                    } else {
                        self.confirm(
                            format!(
                                "Dismiss {} for {}? Adds a local allowlist entry \
                                 (remove it in the Allowlist tab to undo).",
                                a.observable_value, a.behavior
                            ),
                            dismiss_request(a),
                        );
                    }
                }
            }
            (Tab::Active, '\n') => {
                if let Some(a) = self.data.active.get(i) {
                    let v = a.observable_value.clone();
                    self.lookup(v);
                }
            }
            (Tab::Lookup, '/' | '\n' | 'l') => self.modal = Some(Modal::Form(Form::lookup())),
            _ => {}
        }
    }

    fn resolve(&mut self, i: usize, action: ReviewAction) {
        if let Some(r) = self.data.review.get(i) {
            let id = r.id;
            self.act(
                Request::ResolveReview { id, action },
                "review item resolved",
            );
        }
    }

    fn lookup(&mut self, value: String) {
        if let Some(Reply::Lookup(l)) = self.call(Request::Lookup { value }) {
            self.data.lookup = Some(l);
            self.tab = TABS
                .iter()
                .position(|(t, _)| *t == Tab::Lookup)
                .unwrap_or(0);
            self.table.select(Some(0));
        }
    }

    fn on_modal_key(&mut self, modal: Modal, key: KeyEvent) {
        match modal {
            Modal::Confirm { text, request } => match key.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    self.act(request, "done");
                }
                KeyCode::Char('n') | KeyCode::Esc => self.info("cancelled"),
                _ => self.modal = Some(Modal::Confirm { text, request }),
            },
            // Require an explicit key so the secret is not dismissed by accident.
            Modal::Secret { name, secret } => match key.code {
                KeyCode::Enter | KeyCode::Esc => self.info(format!("token {name}: secret hidden")),
                _ => self.modal = Some(Modal::Secret { name, secret }),
            },
            Modal::Form(mut form) => match key.code {
                KeyCode::Esc => self.info("cancelled"),
                KeyCode::Enter if matches!(form.kind, FormKind::Filter) => {
                    self.set_filter(form.values())
                }
                KeyCode::Enter => match form.to_request() {
                    Ok(req) => {
                        let is_lookup = matches!(form.kind, FormKind::Lookup);
                        if is_lookup {
                            if let Request::Lookup { value } = req {
                                self.lookup(value);
                            }
                        } else if !self.act(req, form.done_message()) {
                            // Keep the form open so the input can be corrected.
                            self.modal = Some(Modal::Form(form));
                        }
                    }
                    Err(e) => {
                        form.error = Some(e);
                        self.modal = Some(Modal::Form(form));
                    }
                },
                _ => {
                    form.on_key(key);
                    self.modal = Some(Modal::Form(form));
                }
            },
        }
    }
}

/// Suspend an active (O, b) pair with a local allowlist entry.
fn dismiss_request(a: &Assessment) -> Request {
    Request::AddAllowlist(NewAllowlistEntry {
        scope: AllowlistScope::Local,
        value: a.observable_value.clone(),
        behaviors: vec![a.behavior],
        tlp: None,
        valid_until: None,
        summary: Some("dismissed in apti-tui".into()),
        source: None,
    })
}

// ------------------------------------------------------------------ drawing

const FOLLOWING_HEADER: [&str; 6] = [
    "Actor",
    "State",
    "Operator",
    "Evidence",
    "Last sync",
    "Error",
];
const FOLLOWERS_HEADER: [&str; 3] = ["Actor", "State", "Since"];
const OPERATORS_HEADER: [&str; 5] = [
    "Operator",
    "Source",
    "Default policy",
    "Per behaviour",
    "Actors",
];
const BEHAVIORS_HEADER: [&str; 7] = [
    "Behaviour",
    "k",
    "T (IP)",
    "M (IP)",
    "T (domain)",
    "M (domain)",
    "Publish TLP",
];
const TOKENS_HEADER: [&str; 5] = ["Name", "Scopes", "Max TLP", "Created", "Last used"];
const REVIEW_HEADER: [&str; 6] = ["#", "Kind", "Observable", "Behaviour", "Detail", "Status"];
const ALLOWLIST_HEADER: [&str; 7] = [
    "#",
    "Scope",
    "Observable",
    "Behaviours",
    "TLP",
    "Expires",
    "Summary",
];
const EVIDENCE_HEADER: [&str; 6] = ["Kind", "Operator", "Behaviours", "TLP", "Detail", "Id"];

/// Column headers of a tab's (filterable) table.
fn header(tab: Tab) -> &'static [&'static str] {
    match tab {
        Tab::Dashboard => &[],
        Tab::Following => &FOLLOWING_HEADER,
        Tab::Followers => &FOLLOWERS_HEADER,
        Tab::Operators => &OPERATORS_HEADER,
        Tab::Behaviors => &BEHAVIORS_HEADER,
        Tab::Tokens => &TOKENS_HEADER,
        Tab::Review => &REVIEW_HEADER,
        Tab::Allowlist => &ALLOWLIST_HEADER,
        Tab::Active => &ASSESSMENT_HEADER,
        Tab::Lookup => &EVIDENCE_HEADER,
    }
}

fn header_row(cells: &[&'static str]) -> Row<'static> {
    Row::new(cells.iter().map(|c| Cell::from(*c))).style(
        Style::default()
            .add_modifier(Modifier::BOLD)
            .fg(Color::Cyan),
    )
}

fn to_row(cells: Vec<Span<'static>>) -> Row<'static> {
    Row::new(cells.into_iter().map(Cell::from))
}

/// Draw the current tab's table with its filter applied, a scroll bar and
/// the position of the selected row.
fn draw_table(f: &mut Frame, app: &mut App, area: Rect, widths: Vec<Constraint>, title: &str) {
    let cells = app.cells();
    let total = cells.len();
    let visible = app.visible_of(&cells);
    let n = visible.len();
    let mut cells: Vec<Option<Vec<Span<'static>>>> = cells.into_iter().map(Some).collect();
    let rows: Vec<Row> = visible
        .iter()
        .filter_map(|&i| cells[i].take())
        .map(to_row)
        .collect();

    let filter: Vec<String> = header(app.current())
        .iter()
        .zip(app.filter())
        .filter(|(_, v)| !v.is_empty())
        .map(|(h, v)| format!("{h}~{v}"))
        .collect();
    let title = if filter.is_empty() {
        Line::from(title.to_string())
    } else {
        Line::from(vec![
            Span::raw(title.trim_end().to_string()),
            Span::styled(
                format!(" — filter: {} ", filter.join(" ")),
                Style::default().fg(Color::Yellow),
            ),
        ])
    };
    let sel = app.selected().min(n.saturating_sub(1));
    let position = match (n, total) {
        (0, _) => " 0/0 ".to_string(),
        (n, t) if n == t => format!(" {}/{n} ", sel + 1),
        (n, t) => format!(" {}/{n} ({t}) ", sel + 1),
    };
    let t = Table::new(rows, widths)
        .header(header_row(header(app.current())))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .title_bottom(Line::from(position).right_aligned()),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    f.render_stateful_widget(t, area, &mut app.table);

    // Scroll bar on the right border, below the header row.
    let track = area.inner(Margin {
        vertical: 1,
        horizontal: 0,
    });
    let track = Rect {
        y: track.y + 1,
        height: track.height.saturating_sub(1),
        ..track
    };
    if n > 0 && track.height > 0 {
        let mut state = ScrollbarState::new(n).position(sel);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("▲"))
                .end_symbol(Some("▼")),
            track,
            &mut state,
        );
    }
}

fn draw(f: &mut Frame, app: &mut App) {
    let [tabs_area, main, help, msg] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(5),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(f.area());

    let titles: Vec<Line> = TABS
        .iter()
        .enumerate()
        .map(|(i, (_, t))| Line::from(format!("{} {t}", (i + 1) % 10)))
        .collect();
    f.render_widget(
        Tabs::new(titles)
            .select(app.tab)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" apti-tui — {} ", app.client.path().display())),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        tabs_area,
    );

    match app.current() {
        Tab::Dashboard => draw_dashboard(f, app, main),
        Tab::Following => draw_following(f, app, main),
        Tab::Followers => draw_followers(f, app, main),
        Tab::Operators => draw_operators(f, app, main),
        Tab::Behaviors => draw_behaviors(f, app, main),
        Tab::Tokens => draw_tokens(f, app, main),
        Tab::Review => draw_review(f, app, main),
        Tab::Allowlist => draw_allowlist(f, app, main),
        Tab::Active => draw_active(f, app, main),
        Tab::Lookup => draw_lookup(f, app, main),
    }

    let keys = match app.current() {
        Tab::Dashboard => "e edit default TLP and AMBER recipients",
        Tab::Following => "a follow  d unfollow  s resync",
        Tab::Followers => "a approve  x reject/remove",
        Tab::Operators => {
            "e edit trust/weight  t toggle trusted  c clear behaviour policy  m map actor→operator"
        }
        Tab::Behaviors => "e edit k / T / M / TLP",
        Tab::Tokens => "a create  e edit scopes/TLP  n new secret  d delete",
        Tab::Review => "d dismiss  s suspend (b)  w allowlist (O)  h show resolved  ⏎ lookup",
        Tab::Allowlist => "a add  d remove",
        Tab::Active => "d dismiss (O, b)  i toggle inactive  ⏎ lookup",
        Tab::Lookup => "/ lookup value",
    };
    let filter = if header(app.current()).is_empty() {
        ""
    } else {
        "  f filter  F clear filter"
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(keys, Style::default().fg(Color::Gray)),
            Span::styled(filter, Style::default().fg(Color::Gray)),
            Span::styled(
                "   ←/→ tabs  Home/End first/last  r refresh  R recompute  q quit",
                Style::default().fg(Color::DarkGray),
            ),
        ])),
        help,
    );
    if let Some((m, err)) = &app.message {
        let style = if *err {
            Style::default().fg(Color::Red)
        } else {
            Style::default().fg(Color::Green)
        };
        f.render_widget(Paragraph::new(m.as_str()).style(style), msg);
    }

    match &app.modal {
        Some(Modal::Form(form)) => form.draw(f),
        Some(Modal::Confirm { text, .. }) => {
            let area = centered(f.area(), 60, 7);
            f.render_widget(Clear, area);
            f.render_widget(
                Paragraph::new(vec![
                    Line::from(text.as_str()),
                    Line::from(""),
                    Line::from("[y]es / [n]o").bold(),
                ])
                .wrap(Wrap { trim: true })
                .block(Block::default().borders(Borders::ALL).title(" Confirm ")),
                area,
            );
        }
        Some(Modal::Secret { name, secret }) => {
            let area = centered(f.area(), 80, 9);
            f.render_widget(Clear, area);
            f.render_widget(
                Paragraph::new(vec![
                    Line::from(format!("Secret of API token {name}:")),
                    Line::from(""),
                    Line::from(secret.as_str()).yellow().bold(),
                    Line::from(""),
                    Line::from(
                        "Copy it now. Only its SHA-512 hash is stored; it cannot be shown again.",
                    ),
                    Line::from("⏎ / Esc close").dark_gray(),
                ])
                .wrap(Wrap { trim: false })
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Token created "),
                ),
                area,
            );
        }
        None => {}
    }
}

pub fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    )
}

fn draw_dashboard(f: &mut Frame, app: &mut App, area: Rect) {
    let [status, tlp] = Layout::vertical([Constraint::Length(15), Constraint::Min(5)]).areas(area);
    draw_status(f, app, status);
    draw_tlp(f, app, tlp);
}

fn draw_status(f: &mut Frame, app: &mut App, area: Rect) {
    let Some(s) = &app.data.status else {
        f.render_widget(
            Paragraph::new("no data").block(Block::default().borders(Borders::ALL)),
            area,
        );
        return;
    };
    let kv = |k: &'static str, v: String| {
        Line::from(vec![
            Span::styled(format!("{k:<24}"), Style::default().fg(Color::Cyan)),
            Span::raw(v),
        ])
    };
    let lines = vec![
        kv("Daemon version", s.version.clone()),
        kv("Actor", s.actor_id.clone()),
        kv("Operator", s.operator_id.clone()),
        Line::from(""),
        kv("Following", s.following.to_string()),
        kv(
            "Followers",
            format!(
                "{} (+{} pending approval)",
                s.followers, s.pending_followers
            ),
        ),
        kv("Evidence objects", s.evidence.to_string()),
        kv("Active (O, b) pairs", s.active.to_string()),
        kv("Flagged (disputed)", s.flagged.to_string()),
        kv("Open review items", s.review_open.to_string()),
        kv("Pending observations", s.pending_observations.to_string()),
        kv("Delivery queue", s.delivery_queue.to_string()),
        kv("Last recompute", ago(s.last_recompute)),
    ];
    f.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" Status ")),
        area,
    );
}

fn following_cells(x: &FollowingInfo) -> Vec<Span<'static>> {
    let state = match x.state.as_str() {
        "accepted" => Span::from("accepted").green(),
        "rejected" => Span::from("rejected").red(),
        s => Span::from(s.to_string()).yellow(),
    };
    vec![
        Span::from(x.handle.clone().unwrap_or_else(|| x.actor.clone())),
        state,
        Span::from(x.operator.clone().unwrap_or_default()),
        Span::from(x.evidence.to_string()),
        Span::from(ago(x.last_sync)),
        Span::from(x.last_error.clone().unwrap_or_default()).red(),
    ]
}

fn draw_following(f: &mut Frame, app: &mut App, area: Rect) {
    let widths = vec![
        Constraint::Percentage(28),
        Constraint::Length(9),
        Constraint::Percentage(25),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Fill(1),
    ];
    draw_table(f, app, area, widths, " Following (following ≠ trusting) ");
}

fn follower_cells(x: &FollowerInfo) -> Vec<Span<'static>> {
    let state = if x.state == "accepted" {
        Span::from("accepted").green()
    } else {
        Span::from("pending").yellow()
    };
    vec![
        Span::from(x.actor.clone()),
        state,
        Span::from(ago(Some(x.since))),
    ]
}

fn draw_followers(f: &mut Frame, app: &mut App, area: Rect) {
    let widths = vec![
        Constraint::Fill(1),
        Constraint::Length(9),
        Constraint::Length(10),
    ];
    draw_table(
        f,
        app,
        area,
        widths,
        " Followers (accepted followers receive TLP:GREEN) ",
    );
}

fn operator_cells(o: &OperatorInfo) -> Vec<Span<'static>> {
    let default = Span::styled(
        policy_str(o.default_policy),
        match o.default_policy {
            Some(p) if p.trusted => Style::default().fg(Color::Green),
            _ => Style::default().fg(Color::DarkGray),
        },
    );
    let per: Vec<String> = o
        .behavior_policies
        .iter()
        .map(|(b, p)| format!("{b}:{}{}", if p.trusted { "✓" } else { "✗" }, p.weight))
        .collect();
    vec![
        Span::from(o.id.clone()),
        Span::from(o.source.clone()),
        default,
        Span::from(per.join(" ")),
        Span::from(o.actors.join(", ")),
    ]
}

fn draw_operators(f: &mut Frame, app: &mut App, area: Rect) {
    let widths = vec![
        Constraint::Percentage(25),
        Constraint::Length(9),
        Constraint::Length(20),
        Constraint::Percentage(25),
        Constraint::Fill(1),
    ];
    draw_table(
        f,
        app,
        area,
        widths,
        " Operators — trust and weight w(p, b) ",
    );
}

fn behavior_cells(b: &BehaviorPolicyInfo) -> Vec<Span<'static>> {
    let mark = |overridden: bool, s: String| {
        if overridden {
            Span::from(format!("{s}*")).yellow()
        } else {
            Span::from(s)
        }
    };
    vec![
        Span::from(b.behavior.as_str()),
        mark(b.overrides.k.is_some(), b.k.to_string()),
        mark(b.overrides.ttl_secs.is_some(), fmt_secs(b.ttl_ip_secs)),
        mark(
            b.overrides.max_age_secs.is_some(),
            fmt_secs(b.max_age_ip_secs),
        ),
        mark(b.overrides.ttl_secs.is_some(), fmt_secs(b.ttl_domain_secs)),
        mark(
            b.overrides.max_age_secs.is_some(),
            fmt_secs(b.max_age_domain_secs),
        ),
        tlp_span(b.effective_tlp),
    ]
}

fn draw_behaviors(f: &mut Frame, app: &mut App, area: Rect) {
    let widths = vec![
        Constraint::Length(22),
        Constraint::Length(6),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(11),
        Constraint::Length(11),
        Constraint::Fill(1),
    ];
    draw_table(f, app, area, widths, " Behaviour policy (* = override) ");
}

fn draw_tlp(f: &mut Frame, app: &mut App, area: Rect) {
    let Some(t) = &app.data.tlp else {
        f.render_widget(
            Paragraph::new("no data").block(Block::default().borders(Borders::ALL)),
            area,
        );
        return;
    };
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                "Default TLP for published evidence: ",
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(
                format!("TLP:{}", t.default_tlp.as_str().to_uppercase()),
                tlp_style(t.default_tlp).bold(),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Addressing (Section 5.2):",
            Style::default().fg(Color::Cyan),
        )),
        Line::from("  TLP:CLEAR        public + followers"),
        Line::from("  TLP:GREEN        followers only (approve them in the Followers tab)"),
        Line::from("  TLP:AMBER(+STRICT) named recipients only:"),
    ];
    if t.amber_recipients.is_empty() {
        lines
            .push(Line::from("    (none — AMBER evidence is not delivered to anyone)").dark_gray());
    }
    for r in &t.amber_recipients {
        lines.push(Line::from(format!("    {r}")));
    }
    lines.push(Line::from(""));
    lines.push(
        Line::from(
            "TLP:RED is never shared via AP-TI. Per-behaviour TLP is set in the Behaviours tab. \
             Press e to edit.",
        )
        .dark_gray(),
    );
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Traffic Light Protocol "),
        ),
        area,
    );
}

fn token_cells(t: &ApiTokenInfo) -> Vec<Span<'static>> {
    vec![
        Span::from(t.name.clone()),
        Span::from(
            t.scopes
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        ),
        tlp_span(t.max_tlp),
        Span::from(ago(Some(t.created))),
        Span::from(ago(t.last_used)),
    ]
}

fn draw_tokens(f: &mut Frame, app: &mut App, area: Rect) {
    let widths = vec![
        Constraint::Percentage(30),
        Constraint::Fill(1),
        Constraint::Length(18),
        Constraint::Length(10),
        Constraint::Length(10),
    ];
    draw_table(
        f,
        app,
        area,
        widths,
        " REST API tokens (only SHA-512 hashes are stored) ",
    );
}

fn review_cells(r: &ReviewItem) -> Vec<Span<'static>> {
    let kind = match r.kind.as_str() {
        "dispute" => Span::from("dispute").red(),
        "broad-allowlist" => Span::from("broad-allowlist").yellow(),
        k => Span::from(k.to_string()),
    };
    vec![
        Span::from(r.id.to_string()),
        kind,
        Span::from(r.observable_value.clone()),
        Span::from(
            r.behavior
                .map(|b| b.to_string())
                .unwrap_or_else(|| "*".into()),
        ),
        Span::from(r.detail.clone()),
        Span::from(r.resolution.clone().unwrap_or_else(|| ago(Some(r.created)))),
    ]
}

fn draw_review(f: &mut Frame, app: &mut App, area: Rect) {
    let title = if app.data.show_resolved {
        " Review queue (all) "
    } else {
        " Review queue (open) "
    };
    let widths = vec![
        Constraint::Length(5),
        Constraint::Length(16),
        Constraint::Length(24),
        Constraint::Length(20),
        Constraint::Fill(1),
        Constraint::Length(12),
    ];
    draw_table(f, app, area, widths, title);
}

fn allowlist_cells(e: &AllowlistEntry) -> Vec<Span<'static>> {
    let scope = match e.scope {
        AllowlistScope::Local => Span::from("local"),
        AllowlistScope::Published => Span::from("published").cyan(),
    };
    let behaviors = if e.behaviors.is_empty() {
        "all".to_string()
    } else {
        e.behaviors
            .iter()
            .map(|b| b.as_str())
            .collect::<Vec<_>>()
            .join(",")
    };
    vec![
        Span::from(e.id.to_string()),
        scope,
        Span::from(e.observable_value.clone()),
        Span::from(behaviors),
        e.tlp.map(tlp_span).unwrap_or_else(|| Span::from("-")),
        Span::from(until(e.valid_until)),
        Span::from(e.summary.clone().unwrap_or_default()),
    ]
}

fn draw_allowlist(f: &mut Frame, app: &mut App, area: Rect) {
    let widths = vec![
        Constraint::Length(5),
        Constraint::Length(10),
        Constraint::Length(28),
        Constraint::Length(20),
        Constraint::Length(18),
        Constraint::Length(8),
        Constraint::Fill(1),
    ];
    draw_table(
        f,
        app,
        area,
        widths,
        " Allowlist (local entries affect only us; published = strongly-disagree Opinion) ",
    );
}

fn assessment_cells(a: &Assessment) -> Vec<Span<'static>> {
    let state = if a.active {
        Span::from("active").green()
    } else if a.allowlisted {
        Span::from("allowlisted").cyan()
    } else if a.suspended {
        Span::from("suspended").red()
    } else {
        Span::from("inactive").dark_gray()
    };
    vec![
        Span::from(a.observable_value.clone()),
        Span::from(a.behavior.as_str()),
        state,
        Span::from(until(a.effective_expiry)),
        tlp_span(a.tlp),
        Span::styled(
            format!("S={} D={}", a.support_weight, a.dispute_weight),
            if a.flagged {
                Style::default().fg(Color::Red)
            } else {
                Style::default()
            },
        ),
        Span::from(a.supporting_operators.join(", ")),
    ]
}

const ASSESSMENT_HEADER: [&str; 7] = [
    "Observable",
    "Behaviour",
    "State",
    "Expires",
    "TLP",
    "Weights",
    "Supporting operators",
];

fn assessment_widths() -> Vec<Constraint> {
    vec![
        Constraint::Length(28),
        Constraint::Length(20),
        Constraint::Length(11),
        Constraint::Length(8),
        Constraint::Length(18),
        Constraint::Length(12),
        Constraint::Fill(1),
    ]
}

fn draw_active(f: &mut Frame, app: &mut App, area: Rect) {
    let title = if app.data.include_inactive {
        " Assessments (all) "
    } else {
        " Active list "
    };
    draw_table(f, app, area, assessment_widths(), title);
}

fn evidence_cells(e: &EvidenceSummary) -> Vec<Span<'static>> {
    let cells = vec![
        Span::from(e.kind.clone()),
        Span::from(e.operator.clone()),
        Span::from(
            e.behaviors
                .iter()
                .map(|b| b.as_str())
                .collect::<Vec<_>>()
                .join(","),
        ),
        tlp_span(e.tlp),
        Span::from(e.detail.clone()),
        Span::from(e.id.clone()),
    ];
    if !e.withdrawn {
        return cells;
    }
    let withdrawn = Style::default()
        .fg(Color::DarkGray)
        .add_modifier(Modifier::CROSSED_OUT);
    cells
        .into_iter()
        .map(|c| {
            let style = withdrawn.patch(c.style);
            c.style(style)
        })
        .collect()
}

fn draw_lookup(f: &mut Frame, app: &mut App, area: Rect) {
    let Some(l) = &app.data.lookup else {
        f.render_widget(
            Paragraph::new("Press / to look up an IP address, prefix or domain.")
                .block(Block::default().borders(Borders::ALL).title(" Lookup ")),
            area,
        );
        return;
    };
    let n = l.assessments.len() as u16;
    let [top, mid, bottom] = Layout::vertical([
        Constraint::Length(n.max(1) + 3),
        Constraint::Min(4),
        Constraint::Length((l.local_allowlist.len() as u16).max(1) + 2),
    ])
    .areas(area);
    let title = format!(" {} ({}) ", l.observable_value, l.observable_type);
    let rows: Vec<Row> = l
        .assessments
        .iter()
        .map(|a| to_row(assessment_cells(a)))
        .collect();
    f.render_widget(
        Table::new(rows, assessment_widths())
            .header(header_row(&ASSESSMENT_HEADER))
            .block(Block::default().borders(Borders::ALL).title(title)),
        top,
    );
    let lines: Vec<Line> = if l.local_allowlist.is_empty() {
        vec![Line::from("none").dark_gray()]
    } else {
        l.local_allowlist
            .iter()
            .map(|a| {
                Line::from(format!(
                    "#{} {} {:?} {}",
                    a.id,
                    a.observable_value,
                    a.scope,
                    a.summary.clone().unwrap_or_default()
                ))
            })
            .collect()
    };
    let widths = vec![
        Constraint::Length(15),
        Constraint::Percentage(20),
        Constraint::Length(18),
        Constraint::Length(18),
        Constraint::Percentage(30),
        Constraint::Fill(1),
    ];
    draw_table(f, app, mid, widths, " Evidence ");
    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Covering allowlist entries "),
        ),
        bottom,
    );
}

fn run(terminal: &mut DefaultTerminal, app: &mut App) -> anyhow::Result<()> {
    app.refresh();
    while !app.quit {
        terminal.draw(|f| draw(f, app))?;
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.on_key(key);
                }
            }
        } else if app.modal.is_none() && app.last_refresh.elapsed() > Duration::from_secs(5) {
            app.refresh();
        }
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut client = Client::new(args.socket);
    // Fail early with a readable message if the daemon is not reachable.
    client.request(Request::Status)?;
    let mut app = App::new(client);
    let mut terminal = ratatui::init();
    let result = run(&mut terminal, &mut app);
    ratatui::restore();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn app_with_followers(actors: &[&str]) -> App {
        let mut app = App::new(Client::new("/nonexistent".into()));
        app.tab = TABS.iter().position(|(t, _)| *t == Tab::Followers).unwrap();
        app.data.followers = actors
            .iter()
            .map(|a| FollowerInfo {
                actor: a.to_string(),
                state: "accepted".into(),
                since: Utc::now(),
            })
            .collect();
        app
    }

    fn screen(app: &mut App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(120, 20)).unwrap();
        terminal.draw(|f| draw(f, app)).unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect()
    }

    #[test]
    fn filter_matching() {
        let cells = [Span::from("Host.Example"), Span::from("active")];
        assert!(row_matches(&cells, &[]));
        assert!(row_matches(&cells, &["example".into()]));
        assert!(row_matches(&cells, &["".into(), "ACT".into()]));
        assert!(!row_matches(&cells, &["example".into(), "inactive".into()]));
        assert!(!row_matches(&cells, &["".into(), "".into(), "x".into()]));
    }

    #[test]
    fn filter_maps_selection_to_data() {
        let mut app = app_with_followers(&["a.example", "b.test", "c.example", "d.test"]);
        assert_eq!(app.rows(), 4);
        app.set_filter(vec!["EXAMPLE".into(), "".into(), "".into()]);
        assert_eq!(app.rows(), 2);
        app.table.select(Some(1));
        assert_eq!(app.item(), Some(2));
        app.set_filter(vec!["".into(), "pending".into(), "".into()]);
        assert_eq!(app.rows(), 0);
        assert_eq!(app.item(), None);
        // An all-empty filter is the same as no filter.
        app.set_filter(vec![String::new(); 3]);
        assert!(app.filter().is_empty());
        assert_eq!(app.rows(), 4);
    }

    #[test]
    fn filter_form_roundtrip() {
        let mut f = Form::filter(&FOLLOWERS_HEADER, &["x".into()]);
        assert!(matches!(f.kind, FormKind::Filter));
        assert_eq!(f.fields.len(), 3);
        f.focus = 1;
        f.on_key(KeyEvent::from(KeyCode::Char('p')));
        assert_eq!(f.values(), vec!["x", "p", ""]);
    }

    #[test]
    fn draws_filter_position_and_scrollbar() {
        let mut app =
            app_with_followers(&["a.example", "b.test", "c.example", "d.test", "e.example"]);
        app.set_filter(vec!["example".into()]);
        app.table.select(Some(1));
        let s = screen(&mut app);
        assert!(s.contains("filter: Actor~example"), "{s}");
        assert!(s.contains(" 2/3 (5) "), "{s}");
        assert!(s.contains('▲') && s.contains('▼'), "{s}");
        assert!(!s.contains("b.test"));
    }

    #[test]
    fn dismiss_adds_local_entry_for_pair() {
        let a = Assessment {
            observable_type: apti_core::ObservableType::Ipv4Addr,
            observable_value: "192.0.2.1".into(),
            behavior: apti_core::Behavior::Scan,
            e_ind: None,
            e_sig: None,
            effective_expiry: None,
            active: true,
            flagged: false,
            suspended: false,
            allowlisted: false,
            support_weight: 1.0,
            dispute_weight: 0.0,
            supporting_operators: vec![],
            disputing_operators: vec![],
            untrusted_operators: vec![],
            tlp: Tlp::Clear,
            include_subdomains: false,
            ports: vec![],
            services: vec![],
        };
        let Request::AddAllowlist(e) = dismiss_request(&a) else {
            panic!()
        };
        assert_eq!(e.scope, AllowlistScope::Local);
        assert_eq!(e.value, "192.0.2.1");
        assert_eq!(e.behaviors, vec![apti_core::Behavior::Scan]);
        assert_eq!(e.valid_until, None);
    }
}
