//! Terminal UI for aptid (Appendix D): follow actors and set trust for their
//! operators, per-behaviour k/T/M and TLP, approve followers, work the review
//! queue and manage allowlists and REST API tokens.

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
    Behaviors,
    Tokens,
    Review,
    Allowlist,
    Active,
    Lookup,
}

const TABS: [(Tab, &str); 9] = [
    (Tab::Dashboard, "Status"),
    (Tab::Following, "Following"),
    (Tab::Followers, "Followers"),
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
    /// Read-only details of an actor. Action keys of the tab apply to the
    /// selected row and close the popup.
    Details {
        title: String,
        rows: Vec<(&'static str, String)>,
        keys: &'static str,
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

/// Default policy of an operator followed by its per-behaviour exceptions.
fn trust_str(o: &OperatorInfo) -> String {
    let s = policy_str(o.default_policy);
    if o.behavior_policies.is_empty() {
        return s;
    }
    let except: Vec<String> = o
        .behavior_policies
        .iter()
        .map(|(b, p)| {
            let t = if p.trusted { "trusted" } else { "untrusted" };
            format!("{b}: {t} w={}", p.weight)
        })
        .collect();
    format!("{s} — except {}", except.join(", "))
}

/// One row of the Following tab: an operator followed by its actors.
#[derive(Clone, Debug, PartialEq)]
enum SourceRow {
    /// Index into [`Data::operators`]; `None` groups followed actors whose
    /// operator is not known yet.
    Operator(Option<usize>),
    Actor {
        op: Option<usize>,
        /// Index into [`Data::following`]; `None` if the actor is not followed.
        follow: Option<usize>,
        actor: String,
    },
}

impl SourceRow {
    fn op(&self) -> Option<usize> {
        match self {
            SourceRow::Operator(op) | SourceRow::Actor { op, .. } => *op,
        }
    }
}

/// Group actors under their operators. Followed actors without a known
/// operator come last.
fn source_rows(operators: &[OperatorInfo], following: &[FollowingInfo]) -> Vec<SourceRow> {
    let follow = |a: &str| following.iter().position(|f| f.actor == a);
    let mut rows = Vec::new();
    for (i, o) in operators.iter().enumerate() {
        rows.push(SourceRow::Operator(Some(i)));
        rows.extend(o.actors.iter().map(|a| SourceRow::Actor {
            op: Some(i),
            follow: follow(a),
            actor: a.clone(),
        }));
    }
    let unknown: Vec<SourceRow> = following
        .iter()
        .enumerate()
        .filter(|(_, f)| !operators.iter().any(|o| o.actors.contains(&f.actor)))
        .map(|(i, f)| SourceRow::Actor {
            op: None,
            follow: Some(i),
            actor: f.actor.clone(),
        })
        .collect();
    if !unknown.is_empty() {
        rows.push(SourceRow::Operator(None));
        rows.extend(unknown);
    }
    rows
}

/// Rows of a tree to show given which rows match the filter: a matching
/// header shows its whole group, a matching child also shows its header.
/// `header_of[i]` is the header row of row `i` (itself for headers).
fn tree_visible(hit: &[bool], header_of: &[usize]) -> Vec<usize> {
    let mut show = vec![false; hit.len()];
    for (i, &h) in header_of.iter().enumerate() {
        if hit[i] || hit[h] {
            show[i] = true;
            show[h] = true;
        }
    }
    (0..hit.len()).filter(|&i| show[i]).collect()
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
                if let Some(Reply::Operators(o)) = self.call(Request::ListOperators) {
                    self.data.operators = o;
                }
            }
            Tab::Followers => {
                if let Some(Reply::Followers(f)) = self.call(Request::ListFollowers) {
                    self.data.followers = f;
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
            Tab::Following => source_cells(d, &self.source_rows()),
            Tab::Followers => d.followers.iter().map(follower_cells).collect(),
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
        let hit: Vec<bool> = cells
            .iter()
            .map(|c| row_matches(c, self.filter()))
            .collect();
        if self.current() != Tab::Following {
            return (0..hit.len()).filter(|&i| hit[i]).collect();
        }
        let mut header = 0;
        let header_of: Vec<usize> = self
            .source_rows()
            .iter()
            .enumerate()
            .map(|(i, r)| {
                if matches!(r, SourceRow::Operator(_)) {
                    header = i;
                }
                header
            })
            .collect();
        tree_visible(&hit, &header_of)
    }

    fn source_rows(&self) -> Vec<SourceRow> {
        source_rows(&self.data.operators, &self.data.following)
    }

    /// The operator a Following row belongs to.
    fn row_operator(&self, row: &SourceRow) -> Option<&OperatorInfo> {
        row.op().and_then(|i| self.data.operators.get(i))
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
                if i < TABS.len() {
                    self.switch(i);
                }
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
            (Tab::Following, _) => self.following_action(i, c),
            (Tab::Followers, 'i' | '\n') => {
                if let Some(f) = self.data.followers.get(i) {
                    self.modal = Some(follower_details(f));
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

    /// Actions on the Following tab. Trust actions on an actor row apply to
    /// its operator.
    fn following_action(&mut self, i: usize, c: char) {
        let Some(row) = self.source_rows().into_iter().nth(i) else {
            return;
        };
        let followed = match &row {
            SourceRow::Actor {
                follow: Some(f), ..
            } => self.data.following.get(*f).map(|f| f.actor.clone()),
            _ => None,
        };
        match (c, followed) {
            ('d', Some(actor)) => {
                self.confirm(format!("Unfollow {actor}?"), Request::Unfollow { actor })
            }
            ('s', Some(actor)) => {
                self.act(
                    Request::Resync { actor },
                    "actor refreshed, full resync scheduled",
                );
            }
            ('i', _) => match &row {
                SourceRow::Actor {
                    follow: Some(f), ..
                } => {
                    if let Some(f) = self.data.following.get(*f) {
                        self.modal = Some(following_details(f, self.row_operator(&row)));
                    }
                }
                SourceRow::Actor { .. } => self.info("actor not followed; no details known"),
                SourceRow::Operator(_) => self.info("select an actor row for details"),
            },
            ('m', _) => {
                let actor = match &row {
                    SourceRow::Actor { actor, .. } => actor.clone(),
                    SourceRow::Operator(_) => self
                        .row_operator(&row)
                        .and_then(|o| o.actors.first().cloned())
                        .unwrap_or_default(),
                };
                self.modal = Some(Modal::Form(Form::map_actor(&actor)));
            }
            ('t' | 'e' | '\n' | 'c', _) => {
                let Some(o) = self.row_operator(&row) else {
                    self.info("operator not known yet; map the actor with m");
                    return;
                };
                let modal = match c {
                    't' => {
                        let (text, request) = trust_toggle(o);
                        Modal::Confirm { text, request }
                    }
                    'c' => Modal::Form(Form::clear_operator_policy(&o.id)),
                    _ => Modal::Form(Form::operator_policy(o)),
                };
                self.modal = Some(modal);
            }
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
            Modal::Details { .. } => match key.code {
                KeyCode::Enter | KeyCode::Esc | KeyCode::Char('i' | 'q') => {}
                KeyCode::Char(c) => self.tab_action(c),
                _ => self.modal = Some(modal),
            },
            Modal::Form(mut form) => match key.code {
                KeyCode::Esc => self.info("cancelled"),
                KeyCode::Enter if matches!(form.kind, FormKind::Filter) => {
                    self.set_filter(form.values())
                }
                KeyCode::Enter => match form.to_request() {
                    Ok(req) => {
                        let is_lookup = matches!(form.kind, FormKind::Lookup);
                        if let Some(text) = tlp_change(&form.kind, &req) {
                            self.confirm(text, req);
                        } else if is_lookup {
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

/// Confirmation text if a behaviour policy form changes the publish TLP.
fn tlp_change(kind: &FormKind, req: &Request) -> Option<String> {
    let (
        FormKind::Behavior { tlp: old, .. },
        Request::SetBehaviorPolicy {
            behavior,
            default_tlp: new,
            ..
        },
    ) = (kind, req)
    else {
        return None;
    };
    if old == new {
        return None;
    }
    let name = |t: &Option<Tlp>| {
        t.map_or("(default)".to_string(), |t| {
            format!("TLP:{}", t.as_str().to_uppercase())
        })
    };
    Some(format!(
        "Change publish TLP for {behavior} from {} to {}? This changes who receives evidence published for this behaviour.",
        name(old),
        name(new)
    ))
}

/// Confirmation text and request to flip an operator's default trust.
fn trust_toggle(o: &OperatorInfo) -> (String, Request) {
    let cur = o.default_policy.unwrap_or_default();
    let policy = OperatorPolicy {
        trusted: !cur.trusted,
        weight: cur.weight,
    };
    let (verb, effect) = if policy.trusted {
        ("Trust", "counts towards the quorum")
    } else {
        ("Untrust", "no longer counts towards the quorum")
    };
    let mut actors: Vec<&str> = o.actors.iter().take(3).map(String::as_str).collect();
    let more = o.actors.len().saturating_sub(actors.len());
    let more = if more > 0 {
        format!(" and {more} more")
    } else {
        String::new()
    };
    if actors.is_empty() {
        actors.push("none yet");
    }
    let text = format!(
        "{verb} operator {}? Its evidence then {effect} (behaviour exceptions stay). \
         Applies to {} actor(s): {}{more}.",
        o.id,
        o.actors.len(),
        actors.join(", ")
    );
    let request = Request::SetOperatorPolicy {
        operator: o.id.clone(),
        behavior: None,
        policy,
    };
    (text, request)
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

/// The actor's summary, which carries the removal-request contact of aptid
/// peers, or a hint if there is none.
fn summary_or_hint(summary: &Option<String>) -> String {
    summary
        .clone()
        .unwrap_or_else(|| "(none; refreshed daily or with s resync)".into())
}

fn following_details(f: &FollowingInfo, op: Option<&OperatorInfo>) -> Modal {
    let operator = match op {
        Some(o) => format!("{} ({})", o.id, source_label(&o.source)),
        None => "(not yet known)".into(),
    };
    let mut rows = vec![
        ("Actor", f.actor.clone()),
        ("Handle", f.handle.clone().unwrap_or_else(|| "-".into())),
        ("Name", f.name.clone().unwrap_or_else(|| "-".into())),
        ("Summary / contact", summary_or_hint(&f.summary)),
        ("Operator", operator),
        ("State", f.state.clone()),
        ("Evidence", f.evidence.to_string()),
        ("Last sync", ago(f.last_sync)),
        ("Last full sync", ago(f.last_full_sync)),
    ];
    if let Some(e) = &f.last_error {
        rows.push(("Last error", e.clone()));
    }
    Modal::Details {
        title: " Followed actor ".into(),
        rows,
        keys: "d unfollow  s resync  ⏎/Esc close",
    }
}

fn follower_details(f: &FollowerInfo) -> Modal {
    Modal::Details {
        title: " Follower ".into(),
        rows: vec![
            ("Actor", f.actor.clone()),
            ("Name", f.name.clone().unwrap_or_else(|| "-".into())),
            ("Summary / contact", summary_or_hint(&f.summary)),
            ("State", f.state.clone()),
            ("Since", ago(Some(f.since))),
        ],
        keys: "a approve  x reject/remove  ⏎/Esc close",
    }
}

// ------------------------------------------------------------------ drawing

const FOLLOWING_HEADER: [&str; 6] = [
    "Operator / actor",
    "State",
    "Trust",
    "Evidence",
    "Last sync",
    "Error",
];
const FOLLOWERS_HEADER: [&str; 3] = ["Actor", "State", "Since"];
const BEHAVIORS_HEADER: [&str; 5] = [
    "Behaviour",
    "Threshold (k)",
    "Sighting TTL",
    "Max evidence age",
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
        Tab::Behaviors => draw_behaviors(f, app, main),
        Tab::Tokens => draw_tokens(f, app, main),
        Tab::Review => draw_review(f, app, main),
        Tab::Allowlist => draw_allowlist(f, app, main),
        Tab::Active => draw_active(f, app, main),
        Tab::Lookup => draw_lookup(f, app, main),
    }

    let keys = match app.current() {
        Tab::Dashboard => "e edit default TLP and AMBER recipients",
        Tab::Following => match app.item().and_then(|i| app.source_rows().into_iter().nth(i)) {
            Some(SourceRow::Actor { follow: Some(_), .. }) => {
                "i details  a follow  d unfollow  s resync  t/e trust of its operator  m map to operator"
            }
            Some(SourceRow::Actor { .. }) => {
                "a follow  t/e trust of its operator  m map to operator"
            }
            _ => "a follow  t toggle trust  e edit trust/exception  c remove exception/default  m map actor",
        },
        Tab::Followers => "⏎/i details  a approve  x reject/remove",
        Tab::Behaviors => "e edit threshold / TTL / max age / TLP",
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
            // Grow with the text; word wrapping needs some slack per line.
            let lines = text.chars().count() / 60 + 1;
            let area = centered(f.area(), 72, lines as u16 + 5);
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
        Some(Modal::Details { title, rows, keys }) => {
            const LABEL: usize = 20;
            let width = 90u16;
            let text_width = (width.min(f.area().width) as usize)
                .saturating_sub(LABEL + 2)
                .max(1);
            // Wrapped lines per row; word wrapping needs some slack.
            let height: usize = rows
                .iter()
                .map(|(_, v)| v.chars().count() * 6 / 5 / text_width + 1)
                .sum();
            let area = centered(f.area(), width, height as u16 + 4);
            let mut lines: Vec<Line> = rows
                .iter()
                .map(|(k, v)| {
                    Line::from(vec![
                        Span::styled(format!("{k:<LABEL$}"), Style::default().fg(Color::Cyan)),
                        Span::raw(v.clone()),
                    ])
                })
                .collect();
            lines.push(Line::from(""));
            lines.push(Line::from(*keys).dark_gray());
            f.render_widget(Clear, area);
            f.render_widget(
                Paragraph::new(lines)
                    .wrap(Wrap { trim: false })
                    .block(Block::default().borders(Borders::ALL).title(title.as_str())),
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

/// How the actor→operator mapping of an operator was established.
fn source_label(source: &str) -> String {
    match source {
        "verified" => "verified",
        "psl" => "by domain",
        "manual" => "manual",
        "local" => "this node",
        "policy" => "policy only",
        s => s,
    }
    .into()
}

fn source_cells(d: &Data, rows: &[SourceRow]) -> Vec<Vec<Span<'static>>> {
    let ops = &d.operators;
    let follow = |i: Option<usize>| i.and_then(|i| d.following.get(i));
    rows.iter()
        .enumerate()
        .map(|(n, row)| match row {
            SourceRow::Operator(None) => vec![
                Span::from("(operator not yet known)").dark_gray(),
                Span::from(""),
                Span::from(""),
                Span::from(""),
                Span::from(""),
                Span::from(""),
            ],
            SourceRow::Operator(Some(i)) => {
                let o = &ops[*i];
                let evidence: u64 = d
                    .following
                    .iter()
                    .filter(|f| o.actors.contains(&f.actor))
                    .map(|f| f.evidence)
                    .sum();
                let trusted = o.default_policy.is_some_and(|p| p.trusted);
                vec![
                    Span::from(o.id.clone()).bold(),
                    Span::from(source_label(&o.source)),
                    Span::styled(
                        trust_str(o),
                        Style::default().fg(if trusted {
                            Color::Green
                        } else {
                            Color::DarkGray
                        }),
                    ),
                    Span::from(evidence.to_string()),
                    Span::from(""),
                    Span::from(""),
                ]
            }
            SourceRow::Actor {
                op,
                follow: fi,
                actor,
            } => {
                let last = !matches!(rows.get(n + 1), Some(SourceRow::Actor { .. }));
                let branch = if last { "└ " } else { "├ " };
                let f = follow(*fi);
                let local = op.is_some_and(|i| ops[i].source == "local");
                let state = match f.map(|f| f.state.as_str()) {
                    Some("accepted") => Span::from("accepted").green(),
                    Some("rejected") => Span::from("rejected").red(),
                    Some(s) => Span::from(s.to_string()).yellow(),
                    None if local => Span::from("this node").dark_gray(),
                    None => Span::from("not followed").dark_gray(),
                };
                let trust = op
                    .map(|i| format!("↑ {}", trust_str(&ops[i])))
                    .unwrap_or_default();
                let name = f
                    .and_then(|f| f.handle.clone())
                    .unwrap_or_else(|| actor.clone());
                vec![
                    Span::from(format!("{branch}{name}")),
                    state,
                    Span::from(trust).dark_gray(),
                    Span::from(f.map(|f| f.evidence.to_string()).unwrap_or_default()),
                    Span::from(f.map(|f| ago(f.last_sync)).unwrap_or_default()),
                    Span::from(f.and_then(|f| f.last_error.clone()).unwrap_or_default()).red(),
                ]
            }
        })
        .collect()
}

fn draw_following(f: &mut Frame, app: &mut App, area: Rect) {
    let widths = vec![
        Constraint::Percentage(30),
        Constraint::Length(12),
        Constraint::Percentage(30),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Fill(1),
    ];
    draw_table(
        f,
        app,
        area,
        widths,
        " Following — actors grouped by operator; trust is set per operator ",
    );
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
        mark(
            b.overrides.ttl_secs.is_some(),
            ip_domain(b.ttl_ip_secs, b.ttl_domain_secs),
        ),
        mark(
            b.overrides.max_age_secs.is_some(),
            ip_domain(b.max_age_ip_secs, b.max_age_domain_secs),
        ),
        tlp_span(b.effective_tlp),
    ]
}

/// One duration if IP and domain observables agree, else `IP / domain`
/// (Table 1 defaults for C2, and the 90 d cap on M for IPs).
fn ip_domain(ip: i64, domain: i64) -> String {
    if ip == domain {
        fmt_secs(ip)
    } else {
        format!("{} / {}", fmt_secs(ip), fmt_secs(domain))
    }
}

fn draw_behaviors(f: &mut Frame, app: &mut App, area: Rect) {
    let widths = vec![
        Constraint::Length(22),
        Constraint::Length(14),
        Constraint::Length(14),
        Constraint::Length(18),
        Constraint::Fill(1),
    ];
    draw_table(
        f,
        app,
        area,
        widths,
        " Behaviour policy (* = override, a / b = IP / domain) ",
    );
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
                name: None,
                summary: None,
            })
            .collect();
        app
    }

    #[test]
    fn follower_details_show_contact_and_keep_actions() {
        let mut app = app_with_followers(&["https://a.example/actor", "https://b.test/actor"]);
        app.data.followers[1].state = "pending".into();
        app.data.followers[1].summary =
            Some("AP-TI feed operated by B. Removal requests: abuse@b.test".into());
        app.table.select(Some(1));
        app.on_key(KeyEvent::from(KeyCode::Enter));
        assert!(matches!(app.modal, Some(Modal::Details { .. })));
        let s = screen(&mut app);
        assert!(s.contains("Removal requests: abuse@b.test"), "{s}");
        assert!(s.contains("a approve"), "{s}");
        // Esc only closes the popup.
        app.on_key(KeyEvent::from(KeyCode::Esc));
        assert!(app.modal.is_none() && !app.quit);
        // Reject from the popup asks for confirmation of the selected row.
        app.on_key(KeyEvent::from(KeyCode::Char('i')));
        app.on_key(KeyEvent::from(KeyCode::Char('x')));
        assert!(matches!(
            &app.modal,
            Some(Modal::Confirm { request: Request::RejectFollower { actor }, .. })
                if actor == "https://b.test/actor"
        ));
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

    fn operator(id: &str, source: &str, actors: &[&str], trusted: bool) -> OperatorInfo {
        OperatorInfo {
            id: id.into(),
            source: source.into(),
            actors: actors.iter().map(|a| a.to_string()).collect(),
            default_policy: Some(OperatorPolicy {
                trusted,
                weight: 1.0,
            }),
            behavior_policies: vec![],
        }
    }

    fn followed(actor: &str, evidence: u64) -> FollowingInfo {
        FollowingInfo {
            actor: actor.into(),
            handle: None,
            state: "accepted".into(),
            operator: None,
            last_sync: None,
            last_full_sync: None,
            last_error: None,
            evidence,
            name: None,
            summary: None,
        }
    }

    #[test]
    fn following_details_show_contact() {
        let mut app = app_with_sources();
        app.data.following[1].summary = Some("Removal requests: abuse@a.example".into());
        // Row 1 is the followed actor a1 under operator A.
        app.table.select(Some(1));
        app.on_key(KeyEvent::from(KeyCode::Char('i')));
        let s = screen(&mut app);
        assert!(s.contains("Removal requests: abuse@a.example"), "{s}");
        assert!(s.contains("https://a.example/org (verified)"), "{s}");
        app.on_key(KeyEvent::from(KeyCode::Esc));
        // The unfollowed actor a2 has no details.
        app.table.select(Some(2));
        app.on_key(KeyEvent::from(KeyCode::Char('i')));
        assert!(app.modal.is_none());
    }

    /// Operator A runs a1 (followed) and a2 (not followed), the local
    /// operator runs the own actor, and x is followed with no operator yet.
    fn app_with_sources() -> App {
        let mut app = App::new(Client::new("/nonexistent".into()));
        app.tab = TABS.iter().position(|(t, _)| *t == Tab::Following).unwrap();
        app.data.operators = vec![
            operator(
                "https://a.example/org",
                "verified",
                &["https://a.example/a1", "https://a.example/a2"],
                true,
            ),
            operator(
                "https://self.test/org",
                "local",
                &["https://self.test/actor"],
                false,
            ),
        ];
        app.data.following = vec![
            followed("https://x.test/actor", 1),
            followed("https://a.example/a1", 5),
        ];
        app
    }

    #[test]
    fn groups_actors_under_operators() {
        let app = app_with_sources();
        let rows = app.source_rows();
        let actor = |op, follow, a: &str| SourceRow::Actor {
            op,
            follow,
            actor: a.into(),
        };
        assert_eq!(
            rows,
            vec![
                SourceRow::Operator(Some(0)),
                actor(Some(0), Some(1), "https://a.example/a1"),
                actor(Some(0), None, "https://a.example/a2"),
                SourceRow::Operator(Some(1)),
                actor(Some(1), None, "https://self.test/actor"),
                SourceRow::Operator(None),
                actor(None, Some(0), "https://x.test/actor"),
            ]
        );
        let cells = app.cells();
        let text = |r: usize, c: usize| cells[r][c].content.to_string();
        assert_eq!(text(0, 3), "5");
        assert_eq!(text(1, 0), "├ https://a.example/a1");
        assert_eq!(text(2, 0), "└ https://a.example/a2");
        assert_eq!(text(2, 1), "not followed");
        assert_eq!(text(2, 2), "↑ trusted, w=1");
        assert_eq!(text(4, 1), "this node");
    }

    #[test]
    fn filter_keeps_groups_together() {
        let mut app = app_with_sources();
        // A matching actor brings its operator along.
        app.set_filter(vec!["a2".into()]);
        assert_eq!(app.visible(), vec![0, 2]);
        // A matching operator shows all of its actors.
        app.set_filter(vec!["self.test/org".into()]);
        assert_eq!(app.visible(), vec![3, 4]);
        app.set_filter(vec!["".into(), "not followed".into()]);
        assert_eq!(app.visible(), vec![0, 2]);
    }

    #[test]
    fn trust_on_actor_row_targets_its_operator() {
        let mut app = app_with_sources();
        app.table.select(Some(2));
        app.tab_action('t');
        let Some(Modal::Confirm { text, request }) = app.modal.take() else {
            panic!("expected confirmation")
        };
        assert!(
            text.starts_with("Untrust operator https://a.example/org?"),
            "{text}"
        );
        assert!(
            text.contains("2 actor(s): https://a.example/a1, https://a.example/a2."),
            "{text}"
        );
        assert_eq!(
            request,
            Request::SetOperatorPolicy {
                operator: "https://a.example/org".into(),
                behavior: None,
                policy: OperatorPolicy {
                    trusted: false,
                    weight: 1.0
                },
            }
        );
        // Unfollow only applies to followed actors.
        app.tab_action('d');
        assert!(app.modal.is_none());
        app.table.select(Some(1));
        app.tab_action('d');
        assert!(matches!(app.modal, Some(Modal::Confirm { .. })));
        // Trust needs a known operator.
        app.modal = None;
        app.table.select(Some(6));
        app.tab_action('t');
        assert!(app.modal.is_none());
    }

    #[test]
    fn trust_shows_behaviour_exceptions() {
        let mut o = operator("op", "psl", &[], true);
        o.behavior_policies = vec![(
            apti_core::Behavior::Scan,
            OperatorPolicy {
                trusted: false,
                weight: 0.0,
            },
        )];
        assert_eq!(trust_str(&o), "trusted, w=1 — except scan: untrusted w=0");
    }

    #[test]
    fn draws_following_tree() {
        let mut app = app_with_sources();
        let s = screen(&mut app);
        assert!(s.contains("https://a.example/org"), "{s}");
        assert!(s.contains("(operator not yet known)"), "{s}");
        assert!(s.contains(" 1/7 "), "{s}");
    }

    #[test]
    fn merges_ip_and_domain_durations() {
        assert_eq!(ip_domain(86_400, 86_400), "1d");
        assert_eq!(ip_domain(7 * 86_400, 30 * 86_400), "7d / 30d");
    }

    #[test]
    fn confirms_only_tlp_changes() {
        let kind = FormKind::Behavior {
            behavior: apti_core::Behavior::Scan,
            tlp: None,
        };
        let req = |default_tlp| Request::SetBehaviorPolicy {
            behavior: apti_core::Behavior::Scan,
            overrides: Default::default(),
            default_tlp,
        };
        assert_eq!(tlp_change(&kind, &req(None)), None);
        let text = tlp_change(&kind, &req(Some(Tlp::Amber))).unwrap();
        assert!(text.contains("from (default) to TLP:AMBER"), "{text}");
        assert_eq!(tlp_change(&FormKind::Tlp, &req(Some(Tlp::Amber))), None);
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
