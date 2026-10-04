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
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Tabs, Wrap,
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

fn tlp_cell(t: Tlp) -> Cell<'static> {
    Cell::from(format!("TLP:{}", t.as_str().to_uppercase())).style(tlp_style(t))
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
        let n = self.rows();
        let sel = self.table.selected().unwrap_or(0).min(n.saturating_sub(1));
        self.table.select(Some(sel));
    }

    fn rows(&self) -> usize {
        match self.current() {
            Tab::Following => self.data.following.len(),
            Tab::Followers => self.data.followers.len(),
            Tab::Operators => self.data.operators.len(),
            Tab::Behaviors => self.data.behaviors.len(),
            Tab::Tokens => self.data.tokens.len(),
            Tab::Review => self.data.review.len(),
            Tab::Allowlist => self.data.allowlist.len(),
            Tab::Active => self.data.active.len(),
            Tab::Lookup => self.data.lookup.as_ref().map_or(0, |l| l.evidence.len()),
            Tab::Dashboard => 0,
        }
    }

    fn selected(&self) -> usize {
        self.table.selected().unwrap_or(0)
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
            KeyCode::Char(c) => self.tab_action(c),
            KeyCode::Enter => self.tab_action('\n'),
            _ => {}
        }
    }

    fn tab_action(&mut self, c: char) {
        let i = self.selected();
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

// ------------------------------------------------------------------ drawing

fn header_row(cells: &[&'static str]) -> Row<'static> {
    Row::new(cells.iter().map(|c| Cell::from(*c))).style(
        Style::default()
            .add_modifier(Modifier::BOLD)
            .fg(Color::Cyan),
    )
}

fn table<'a>(
    rows: Vec<Row<'a>>,
    header: Row<'a>,
    widths: Vec<Constraint>,
    title: &'a str,
) -> Table<'a> {
    Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ")
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
        Tab::Active => "i toggle inactive  ⏎ lookup",
        Tab::Lookup => "/ lookup value",
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(keys, Style::default().fg(Color::Gray)),
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
            let area = centered(f.area(), 60, 5);
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

fn draw_following(f: &mut Frame, app: &mut App, area: Rect) {
    let rows = app
        .data
        .following
        .iter()
        .map(|x| {
            let state = match x.state.as_str() {
                "accepted" => Cell::from("accepted").green(),
                "rejected" => Cell::from("rejected").red(),
                s => Cell::from(s.to_string()).yellow(),
            };
            Row::new(vec![
                Cell::from(x.handle.clone().unwrap_or_else(|| x.actor.clone())),
                state,
                Cell::from(x.operator.clone().unwrap_or_default()),
                Cell::from(x.evidence.to_string()),
                Cell::from(ago(x.last_sync)),
                Cell::from(x.last_error.clone().unwrap_or_default()).red(),
            ])
        })
        .collect();
    let t = table(
        rows,
        header_row(&[
            "Actor",
            "State",
            "Operator",
            "Evidence",
            "Last sync",
            "Error",
        ]),
        vec![
            Constraint::Percentage(28),
            Constraint::Length(9),
            Constraint::Percentage(25),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Fill(1),
        ],
        " Following (following ≠ trusting) ",
    );
    f.render_stateful_widget(t, area, &mut app.table);
}

fn draw_followers(f: &mut Frame, app: &mut App, area: Rect) {
    let rows = app
        .data
        .followers
        .iter()
        .map(|x| {
            let state = if x.state == "accepted" {
                Cell::from("accepted").green()
            } else {
                Cell::from("pending").yellow()
            };
            Row::new(vec![
                Cell::from(x.actor.clone()),
                state,
                Cell::from(ago(Some(x.since))),
            ])
        })
        .collect();
    let t = table(
        rows,
        header_row(&["Actor", "State", "Since"]),
        vec![
            Constraint::Fill(1),
            Constraint::Length(9),
            Constraint::Length(10),
        ],
        " Followers (accepted followers receive TLP:GREEN) ",
    );
    f.render_stateful_widget(t, area, &mut app.table);
}

fn draw_operators(f: &mut Frame, app: &mut App, area: Rect) {
    let rows = app
        .data
        .operators
        .iter()
        .map(|o| {
            let default = Cell::from(policy_str(o.default_policy)).style(match o.default_policy {
                Some(p) if p.trusted => Style::default().fg(Color::Green),
                _ => Style::default().fg(Color::DarkGray),
            });
            let per: Vec<String> = o
                .behavior_policies
                .iter()
                .map(|(b, p)| format!("{b}:{}{}", if p.trusted { "✓" } else { "✗" }, p.weight))
                .collect();
            Row::new(vec![
                Cell::from(o.id.clone()),
                Cell::from(o.source.clone()),
                default,
                Cell::from(per.join(" ")),
                Cell::from(o.actors.join(", ")),
            ])
        })
        .collect();
    let t = table(
        rows,
        header_row(&[
            "Operator",
            "Source",
            "Default policy",
            "Per behaviour",
            "Actors",
        ]),
        vec![
            Constraint::Percentage(25),
            Constraint::Length(9),
            Constraint::Length(20),
            Constraint::Percentage(25),
            Constraint::Fill(1),
        ],
        " Operators — trust and weight w(p, b) ",
    );
    f.render_stateful_widget(t, area, &mut app.table);
}

fn draw_behaviors(f: &mut Frame, app: &mut App, area: Rect) {
    let rows = app
        .data
        .behaviors
        .iter()
        .map(|b| {
            let mark = |overridden: bool, s: String| {
                if overridden {
                    Cell::from(format!("{s}*")).yellow()
                } else {
                    Cell::from(s)
                }
            };
            Row::new(vec![
                Cell::from(b.behavior.as_str()),
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
                tlp_cell(b.effective_tlp),
            ])
        })
        .collect();
    let t = table(
        rows,
        header_row(&[
            "Behaviour",
            "k",
            "T (IP)",
            "M (IP)",
            "T (domain)",
            "M (domain)",
            "Publish TLP",
        ]),
        vec![
            Constraint::Length(22),
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(11),
            Constraint::Length(11),
            Constraint::Fill(1),
        ],
        " Behaviour policy (* = override) ",
    );
    f.render_stateful_widget(t, area, &mut app.table);
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

fn draw_tokens(f: &mut Frame, app: &mut App, area: Rect) {
    let rows = app
        .data
        .tokens
        .iter()
        .map(|t| {
            Row::new(vec![
                Cell::from(t.name.clone()),
                Cell::from(
                    t.scopes
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
                tlp_cell(t.max_tlp),
                Cell::from(ago(Some(t.created))),
                Cell::from(ago(t.last_used)),
            ])
        })
        .collect();
    let t = table(
        rows,
        header_row(&["Name", "Scopes", "Max TLP", "Created", "Last used"]),
        vec![
            Constraint::Percentage(30),
            Constraint::Fill(1),
            Constraint::Length(18),
            Constraint::Length(10),
            Constraint::Length(10),
        ],
        " REST API tokens (only SHA-512 hashes are stored) ",
    );
    f.render_stateful_widget(t, area, &mut app.table);
}

fn draw_review(f: &mut Frame, app: &mut App, area: Rect) {
    let rows = app
        .data
        .review
        .iter()
        .map(|r| {
            let kind = match r.kind.as_str() {
                "dispute" => Cell::from("dispute").red(),
                "broad-allowlist" => Cell::from("broad-allowlist").yellow(),
                k => Cell::from(k.to_string()),
            };
            Row::new(vec![
                Cell::from(r.id.to_string()),
                kind,
                Cell::from(r.observable_value.clone()),
                Cell::from(
                    r.behavior
                        .map(|b| b.to_string())
                        .unwrap_or_else(|| "*".into()),
                ),
                Cell::from(r.detail.clone()),
                Cell::from(r.resolution.clone().unwrap_or_else(|| ago(Some(r.created)))),
            ])
        })
        .collect();
    let title = if app.data.show_resolved {
        " Review queue (all) "
    } else {
        " Review queue (open) "
    };
    let t = table(
        rows,
        header_row(&["#", "Kind", "Observable", "Behaviour", "Detail", "Status"]),
        vec![
            Constraint::Length(5),
            Constraint::Length(16),
            Constraint::Length(24),
            Constraint::Length(20),
            Constraint::Fill(1),
            Constraint::Length(12),
        ],
        title,
    );
    f.render_stateful_widget(t, area, &mut app.table);
}

fn draw_allowlist(f: &mut Frame, app: &mut App, area: Rect) {
    let rows = app
        .data
        .allowlist
        .iter()
        .map(|e| {
            let scope = match e.scope {
                AllowlistScope::Local => Cell::from("local"),
                AllowlistScope::Published => Cell::from("published").cyan(),
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
            Row::new(vec![
                Cell::from(e.id.to_string()),
                scope,
                Cell::from(e.observable_value.clone()),
                Cell::from(behaviors),
                e.tlp.map(tlp_cell).unwrap_or_else(|| Cell::from("-")),
                Cell::from(until(e.valid_until)),
                Cell::from(e.summary.clone().unwrap_or_default()),
            ])
        })
        .collect();
    let t = table(
        rows,
        header_row(&[
            "#",
            "Scope",
            "Observable",
            "Behaviours",
            "TLP",
            "Expires",
            "Summary",
        ]),
        vec![
            Constraint::Length(5),
            Constraint::Length(10),
            Constraint::Length(28),
            Constraint::Length(20),
            Constraint::Length(18),
            Constraint::Length(8),
            Constraint::Fill(1),
        ],
        " Allowlist (local entries affect only us; published = strongly-disagree Opinion) ",
    );
    f.render_stateful_widget(t, area, &mut app.table);
}

fn assessment_row(a: &Assessment) -> Row<'static> {
    let state = if a.active {
        Cell::from("active").green()
    } else if a.allowlisted {
        Cell::from("allowlisted").cyan()
    } else if a.suspended {
        Cell::from("suspended").red()
    } else {
        Cell::from("inactive").dark_gray()
    };
    Row::new(vec![
        Cell::from(a.observable_value.clone()),
        Cell::from(a.behavior.as_str()),
        state,
        Cell::from(until(a.effective_expiry)),
        tlp_cell(a.tlp),
        Cell::from(format!("S={} D={}", a.support_weight, a.dispute_weight)).style(if a.flagged {
            Style::default().fg(Color::Red)
        } else {
            Style::default()
        }),
        Cell::from(a.supporting_operators.join(", ")),
    ])
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
    let rows = app.data.active.iter().map(assessment_row).collect();
    let title = if app.data.include_inactive {
        " Assessments (all) "
    } else {
        " Active list "
    };
    let t = table(
        rows,
        header_row(&ASSESSMENT_HEADER),
        assessment_widths(),
        title,
    );
    f.render_stateful_widget(t, area, &mut app.table);
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
    let rows: Vec<Row> = l.assessments.iter().map(assessment_row).collect();
    f.render_widget(
        Table::new(rows, assessment_widths())
            .header(header_row(&ASSESSMENT_HEADER))
            .block(Block::default().borders(Borders::ALL).title(title)),
        top,
    );
    let rows = l
        .evidence
        .iter()
        .map(|e| {
            let style = if e.withdrawn {
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::CROSSED_OUT)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(e.kind.clone()),
                Cell::from(e.operator.clone()),
                Cell::from(
                    e.behaviors
                        .iter()
                        .map(|b| b.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                tlp_cell(e.tlp),
                Cell::from(e.detail.clone()),
                Cell::from(e.id.clone()),
            ])
            .style(style)
        })
        .collect();
    let t = table(
        rows,
        header_row(&["Kind", "Operator", "Behaviours", "TLP", "Detail", "Id"]),
        vec![
            Constraint::Length(15),
            Constraint::Percentage(20),
            Constraint::Length(18),
            Constraint::Length(18),
            Constraint::Percentage(30),
            Constraint::Fill(1),
        ],
        " Evidence ",
    );
    f.render_stateful_widget(t, mid, &mut app.table);
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
