//! SQLite storage.
//!
//! All timestamps are stored as RFC 3339 UTC strings with millisecond
//! precision so that lexicographic order equals chronological order.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use apti_core::expiry::Assessment;
use apti_core::policy::{BehaviorOverride, OperatorPolicy, Threshold};
use apti_core::protocol::{
    AllowlistEntry, AllowlistScope, ApiScope, ApiTokenInfo, FollowerInfo, ReviewItem,
};
use apti_core::{Behavior, EvidenceObject, ObservableType, Tlp};
use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{params, Connection, OptionalExtension, Row};

pub fn ts(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub fn parse_ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_default()
}

fn opt_ts(s: Option<String>) -> Option<DateTime<Utc>> {
    s.as_deref().map(parse_ts)
}

const MIGRATIONS: &[&str] = &[
    r#"
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE remote_actors (
    id TEXT PRIMARY KEY,
    inbox TEXT NOT NULL,
    shared_inbox TEXT,
    followers TEXT,
    active_objects TEXT,
    key_id TEXT,
    public_key_pem TEXT,
    operator_claim TEXT,
    preferred_username TEXT,
    fetched_at TEXT NOT NULL
);
CREATE INDEX remote_actors_key ON remote_actors(key_id);

CREATE TABLE actor_operator (
    actor TEXT PRIMARY KEY,
    operator TEXT NOT NULL,
    source TEXT NOT NULL
);
CREATE TABLE actor_operator_override (
    actor TEXT PRIMARY KEY,
    operator TEXT NOT NULL
);

CREATE TABLE operator_policy (
    operator TEXT NOT NULL,
    behavior TEXT NOT NULL,
    trusted INTEGER NOT NULL,
    weight REAL NOT NULL,
    PRIMARY KEY (operator, behavior)
);

CREATE TABLE behavior_policy (
    behavior TEXT PRIMARY KEY,
    k TEXT,
    ttl_secs INTEGER,
    max_age_secs INTEGER,
    default_tlp TEXT
);

CREATE TABLE following (
    actor TEXT PRIMARY KEY,
    handle TEXT,
    state TEXT NOT NULL,
    follow_id TEXT NOT NULL,
    sync_point TEXT,
    last_sync TEXT,
    last_full_sync TEXT,
    last_error TEXT,
    created TEXT NOT NULL
);

CREATE TABLE followers (
    actor TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    follow_id TEXT NOT NULL,
    created TEXT NOT NULL
);

CREATE TABLE evidence (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    publisher TEXT NOT NULL,
    local INTEGER NOT NULL,
    observable_type TEXT,
    observable_value TEXT,
    tlp TEXT NOT NULL,
    sort_key TEXT NOT NULL,
    listed_until TEXT,
    deleted TEXT,
    audience TEXT NOT NULL DEFAULT '[]',
    object TEXT NOT NULL,
    received TEXT NOT NULL
);
CREATE INDEX evidence_obs ON evidence(observable_type, observable_value);
CREATE INDEX evidence_local ON evidence(local, sort_key);
CREATE INDEX evidence_publisher ON evidence(publisher);

CREATE TABLE processed_activities (id TEXT PRIMARY KEY, received TEXT NOT NULL);

CREATE TABLE observations (
    observable_type TEXT NOT NULL,
    observable_value TEXT NOT NULL,
    behavior TEXT NOT NULL,
    port INTEGER,
    service TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    count INTEGER NOT NULL,
    pending INTEGER NOT NULL,
    sighting_id TEXT,
    PRIMARY KEY (observable_type, observable_value, behavior)
);

CREATE TABLE activities (
    id TEXT PRIMARY KEY,
    tlp TEXT NOT NULL,
    audience TEXT NOT NULL,
    json TEXT NOT NULL,
    created TEXT NOT NULL
);

CREATE TABLE deliveries (
    id INTEGER PRIMARY KEY,
    activity_id TEXT NOT NULL,
    inbox TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt TEXT NOT NULL,
    last_error TEXT
);

CREATE TABLE allowlist (
    id INTEGER PRIMARY KEY,
    scope TEXT NOT NULL,
    observable_type TEXT NOT NULL,
    observable_value TEXT NOT NULL,
    behaviors TEXT NOT NULL,
    tlp TEXT,
    valid_until TEXT,
    summary TEXT,
    object_id TEXT,
    created TEXT NOT NULL
);

CREATE TABLE review (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    observable_type TEXT NOT NULL,
    observable_value TEXT NOT NULL,
    behavior TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL,
    created TEXT NOT NULL,
    resolution TEXT,
    resolved TEXT,
    UNIQUE (kind, observable_type, observable_value, behavior)
);

CREATE TABLE active (
    observable_type TEXT NOT NULL,
    observable_value TEXT NOT NULL,
    behavior TEXT NOT NULL,
    effective_expiry TEXT,
    active INTEGER NOT NULL,
    flagged INTEGER NOT NULL,
    tlp TEXT NOT NULL,
    assessment TEXT NOT NULL,
    PRIMARY KEY (observable_type, observable_value, behavior)
);
"#,
    r#"
CREATE TABLE api_tokens (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    hash TEXT NOT NULL UNIQUE,
    scopes TEXT NOT NULL,
    max_tlp TEXT NOT NULL,
    created TEXT NOT NULL,
    last_used TEXT
);
"#,
    r#"
ALTER TABLE allowlist ADD COLUMN source TEXT;

-- Activities for own Opinions, sent with the next publish batch. At most one
-- per object: Create absorbs later Updates, Delete absorbs everything.
CREATE TABLE pending_opinions (
    object_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    queued TEXT NOT NULL
);
"#,
    r#"
-- TLP requested by the sensor; NULL = the behaviour's publish TLP.
ALTER TABLE observations ADD COLUMN tlp TEXT;
"#,
    r#"
-- Shown in the TUI, e.g. for the removal-request contact in the summary.
ALTER TABLE remote_actors ADD COLUMN name TEXT;
ALTER TABLE remote_actors ADD COLUMN summary TEXT;
"#,
];

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

impl Db {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("creating {}", dir.display()))?;
            }
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        // The database holds non-public (TLP) evidence. SQLite creates the
        // -wal/-shm files with the database file's permissions.
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> anyhow::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(mut conn: Connection) -> anyhow::Result<Self> {
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let version: usize = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(version) {
            let tx = conn.transaction()?;
            tx.execute_batch(sql)
                .with_context(|| format!("migration {}", i + 1))?;
            tx.pragma_update(None, "user_version", i + 1)?;
            tx.commit()?;
        }
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Run a closure on the connection in a blocking task.
    pub async fn call<R, F>(&self, f: F) -> anyhow::Result<R>
    where
        R: Send + 'static,
        F: FnOnce(&mut Connection) -> anyhow::Result<R> + Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut c = conn.lock().unwrap_or_else(|e| e.into_inner());
            f(&mut c)
        })
        .await?
    }
}

// ---------------------------------------------------------------- settings

pub fn get_setting(c: &Connection, key: &str) -> anyhow::Result<Option<String>> {
    Ok(
        c.query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| {
            r.get(0)
        })
        .optional()?,
    )
}

pub fn set_setting(c: &Connection, key: &str, value: &str) -> anyhow::Result<()> {
    c.execute(
        "INSERT INTO settings (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

// ----------------------------------------------------------- remote actors

#[derive(Debug, Clone, PartialEq)]
pub struct RemoteActor {
    pub id: String,
    pub inbox: String,
    pub shared_inbox: Option<String>,
    pub followers: Option<String>,
    pub active_objects: Option<String>,
    pub key_id: Option<String>,
    pub public_key_pem: Option<String>,
    pub operator_claim: Option<String>,
    pub preferred_username: Option<String>,
    pub name: Option<String>,
    pub summary: Option<String>,
    pub fetched_at: DateTime<Utc>,
}

impl RemoteActor {
    pub fn delivery_inbox(&self) -> &str {
        self.shared_inbox.as_deref().unwrap_or(&self.inbox)
    }
}

fn remote_actor_row(r: &Row) -> rusqlite::Result<RemoteActor> {
    Ok(RemoteActor {
        id: r.get(0)?,
        inbox: r.get(1)?,
        shared_inbox: r.get(2)?,
        followers: r.get(3)?,
        active_objects: r.get(4)?,
        key_id: r.get(5)?,
        public_key_pem: r.get(6)?,
        operator_claim: r.get(7)?,
        preferred_username: r.get(8)?,
        fetched_at: parse_ts(&r.get::<_, String>(9)?),
        name: r.get(10)?,
        summary: r.get(11)?,
    })
}

const REMOTE_ACTOR_COLS: &str = "id, inbox, shared_inbox, followers, active_objects, key_id, \
     public_key_pem, operator_claim, preferred_username, fetched_at, name, summary";

pub fn upsert_remote_actor(c: &Connection, a: &RemoteActor) -> anyhow::Result<()> {
    c.execute(
        "INSERT INTO remote_actors (id, inbox, shared_inbox, followers, active_objects, key_id,
             public_key_pem, operator_claim, preferred_username, fetched_at, name, summary)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT(id) DO UPDATE SET inbox = excluded.inbox, shared_inbox = excluded.shared_inbox,
             followers = excluded.followers, active_objects = excluded.active_objects,
             key_id = excluded.key_id, public_key_pem = excluded.public_key_pem,
             operator_claim = excluded.operator_claim,
             preferred_username = excluded.preferred_username, fetched_at = excluded.fetched_at,
             name = excluded.name, summary = excluded.summary",
        params![
            a.id,
            a.inbox,
            a.shared_inbox,
            a.followers,
            a.active_objects,
            a.key_id,
            a.public_key_pem,
            a.operator_claim,
            a.preferred_username,
            ts(a.fetched_at),
            a.name,
            a.summary
        ],
    )?;
    Ok(())
}

pub fn get_remote_actor(c: &Connection, id: &str) -> anyhow::Result<Option<RemoteActor>> {
    Ok(c.query_row(
        &format!("SELECT {REMOTE_ACTOR_COLS} FROM remote_actors WHERE id = ?1"),
        [id],
        remote_actor_row,
    )
    .optional()?)
}

pub fn find_actor_by_key_id(c: &Connection, key_id: &str) -> anyhow::Result<Option<RemoteActor>> {
    Ok(c.query_row(
        &format!("SELECT {REMOTE_ACTOR_COLS} FROM remote_actors WHERE key_id = ?1"),
        [key_id],
        remote_actor_row,
    )
    .optional()?)
}

// --------------------------------------------------------------- operators

pub fn set_actor_operator(
    c: &Connection,
    actor: &str,
    operator: &str,
    source: &str,
) -> anyhow::Result<()> {
    c.execute(
        "INSERT INTO actor_operator (actor, operator, source) VALUES (?1, ?2, ?3)
         ON CONFLICT(actor) DO UPDATE SET operator = excluded.operator, source = excluded.source",
        params![actor, operator, source],
    )?;
    Ok(())
}

pub fn set_operator_override(
    c: &Connection,
    actor: &str,
    operator: Option<&str>,
) -> anyhow::Result<()> {
    match operator {
        Some(op) => c.execute(
            "INSERT INTO actor_operator_override (actor, operator) VALUES (?1, ?2)
             ON CONFLICT(actor) DO UPDATE SET operator = excluded.operator",
            params![actor, op],
        )?,
        None => c.execute(
            "DELETE FROM actor_operator_override WHERE actor = ?1",
            [actor],
        )?,
    };
    Ok(())
}

/// actor -> (operator, source); manual overrides win.
pub fn actor_operator_map(c: &Connection) -> anyhow::Result<HashMap<String, (String, String)>> {
    let mut map = HashMap::new();
    let mut stmt = c.prepare("SELECT actor, operator, source FROM actor_operator")?;
    for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?)))? {
        let (a, o, s) = row?;
        map.insert(a, (o, s));
    }
    let mut stmt = c.prepare("SELECT actor, operator FROM actor_operator_override")?;
    for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
        let (a, o) = row?;
        map.insert(a, (o, "manual".to_string()));
    }
    Ok(map)
}

fn behavior_key(b: Option<Behavior>) -> String {
    b.map(|b| b.as_str().to_string())
        .unwrap_or_else(|| "*".into())
}

fn parse_behavior_key(s: &str) -> Option<Behavior> {
    if s == "*" {
        None
    } else {
        Some(Behavior::parse_lenient(s))
    }
}

pub fn list_operator_policies(
    c: &Connection,
) -> anyhow::Result<Vec<(String, Option<Behavior>, OperatorPolicy)>> {
    let mut stmt = c.prepare("SELECT operator, behavior, trusted, weight FROM operator_policy ORDER BY operator, behavior")?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                parse_behavior_key(&r.get::<_, String>(1)?),
                OperatorPolicy {
                    trusted: r.get::<_, i64>(2)? != 0,
                    weight: r.get(3)?,
                },
            ))
        })?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

pub fn set_operator_policy(
    c: &Connection,
    operator: &str,
    behavior: Option<Behavior>,
    p: OperatorPolicy,
) -> anyhow::Result<()> {
    c.execute(
        "INSERT INTO operator_policy (operator, behavior, trusted, weight) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(operator, behavior) DO UPDATE SET trusted = excluded.trusted, weight = excluded.weight",
        params![operator, behavior_key(behavior), p.trusted as i64, p.weight],
    )?;
    Ok(())
}

pub fn clear_operator_policy(
    c: &Connection,
    operator: &str,
    behavior: Option<Behavior>,
) -> anyhow::Result<()> {
    c.execute(
        "DELETE FROM operator_policy WHERE operator = ?1 AND behavior = ?2",
        params![operator, behavior_key(behavior)],
    )?;
    Ok(())
}

// --------------------------------------------------------- behaviour policy

pub fn list_behavior_policies(
    c: &Connection,
) -> anyhow::Result<HashMap<Behavior, (BehaviorOverride, Option<Tlp>)>> {
    let mut stmt =
        c.prepare("SELECT behavior, k, ttl_secs, max_age_secs, default_tlp FROM behavior_policy")?;
    let mut map = HashMap::new();
    for row in stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, Option<i64>>(2)?,
            r.get::<_, Option<i64>>(3)?,
            r.get::<_, Option<String>>(4)?,
        ))
    })? {
        let (b, k, ttl, max, tlp) = row?;
        let k = k.and_then(|k| k.parse::<Threshold>().ok());
        map.insert(
            Behavior::parse_lenient(&b),
            (
                BehaviorOverride {
                    k,
                    ttl_secs: ttl,
                    max_age_secs: max,
                },
                tlp.and_then(|t| t.parse().ok()),
            ),
        );
    }
    Ok(map)
}

pub fn set_behavior_policy(
    c: &Connection,
    b: Behavior,
    o: &BehaviorOverride,
    tlp: Option<Tlp>,
) -> anyhow::Result<()> {
    c.execute(
        "INSERT INTO behavior_policy (behavior, k, ttl_secs, max_age_secs, default_tlp)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(behavior) DO UPDATE SET k = excluded.k, ttl_secs = excluded.ttl_secs,
             max_age_secs = excluded.max_age_secs, default_tlp = excluded.default_tlp",
        params![
            b.as_str(),
            o.k.map(|k| k.to_string()),
            o.ttl_secs,
            o.max_age_secs,
            tlp.map(|t| t.as_str())
        ],
    )?;
    Ok(())
}

// --------------------------------------------------------------- following

#[derive(Debug, Clone)]
pub struct FollowingRow {
    pub actor: String,
    pub handle: Option<String>,
    pub state: String,
    pub follow_id: String,
    pub sync_point: Option<String>,
    pub last_sync: Option<DateTime<Utc>>,
    pub last_full_sync: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

pub fn upsert_following(
    c: &Connection,
    actor: &str,
    handle: Option<&str>,
    follow_id: &str,
    state: &str,
) -> anyhow::Result<()> {
    c.execute(
        "INSERT INTO following (actor, handle, state, follow_id, created) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(actor) DO UPDATE SET handle = COALESCE(excluded.handle, handle),
             state = excluded.state, follow_id = excluded.follow_id",
        params![actor, handle, state, follow_id, ts(Utc::now())],
    )?;
    Ok(())
}

/// Set the state of our Follow, identified by actor and optionally Follow id.
pub fn set_following_state(
    c: &Connection,
    actor: &str,
    follow_id: Option<&str>,
    state: &str,
) -> anyhow::Result<bool> {
    let n = match follow_id {
        Some(fid) => c.execute(
            "UPDATE following SET state = ?3 WHERE actor = ?1 AND follow_id = ?2",
            params![actor, fid, state],
        )?,
        None => c.execute(
            "UPDATE following SET state = ?2 WHERE actor = ?1",
            params![actor, state],
        )?,
    };
    Ok(n > 0)
}

pub fn list_following(c: &Connection) -> anyhow::Result<Vec<FollowingRow>> {
    let mut stmt = c.prepare(
        "SELECT actor, handle, state, follow_id, sync_point, last_sync, last_full_sync, last_error
         FROM following ORDER BY actor",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok(FollowingRow {
                actor: r.get(0)?,
                handle: r.get(1)?,
                state: r.get(2)?,
                follow_id: r.get(3)?,
                sync_point: r.get(4)?,
                last_sync: opt_ts(r.get(5)?),
                last_full_sync: opt_ts(r.get(6)?),
                last_error: r.get(7)?,
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

pub fn get_following(c: &Connection, actor: &str) -> anyhow::Result<Option<FollowingRow>> {
    Ok(list_following(c)?.into_iter().find(|f| f.actor == actor))
}

pub fn is_following(c: &Connection, actor: &str) -> anyhow::Result<bool> {
    Ok(
        c.query_row("SELECT 1 FROM following WHERE actor = ?1", [actor], |_| {
            Ok(())
        })
        .optional()?
        .is_some(),
    )
}

pub fn record_sync(
    c: &Connection,
    actor: &str,
    sync_point: Option<&str>,
    full: bool,
    error: Option<&str>,
) -> anyhow::Result<()> {
    let now = ts(Utc::now());
    if let Some(e) = error {
        c.execute(
            "UPDATE following SET last_error = ?2 WHERE actor = ?1",
            params![actor, e],
        )?;
        return Ok(());
    }
    c.execute(
        "UPDATE following SET last_error = NULL, last_sync = ?2,
             sync_point = COALESCE(?3, sync_point),
             last_full_sync = CASE WHEN ?4 THEN ?2 ELSE last_full_sync END
         WHERE actor = ?1",
        params![actor, now, sync_point, full],
    )?;
    Ok(())
}

pub fn reset_full_sync(c: &Connection, actor: &str) -> anyhow::Result<()> {
    c.execute(
        "UPDATE following SET last_full_sync = NULL WHERE actor = ?1",
        [actor],
    )?;
    Ok(())
}

pub fn delete_following(c: &Connection, actor: &str) -> anyhow::Result<Option<FollowingRow>> {
    let row = get_following(c, actor)?;
    c.execute("DELETE FROM following WHERE actor = ?1", [actor])?;
    Ok(row)
}

// --------------------------------------------------------------- followers

pub fn upsert_follower(
    c: &Connection,
    actor: &str,
    follow_id: &str,
    state: &str,
) -> anyhow::Result<()> {
    c.execute(
        "INSERT INTO followers (actor, state, follow_id, created) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(actor) DO UPDATE SET follow_id = excluded.follow_id,
             state = CASE WHEN state = 'accepted' THEN state ELSE excluded.state END",
        params![actor, state, follow_id, ts(Utc::now())],
    )?;
    Ok(())
}

pub fn get_follower(c: &Connection, actor: &str) -> anyhow::Result<Option<(String, String)>> {
    Ok(c.query_row(
        "SELECT follow_id, state FROM followers WHERE actor = ?1",
        [actor],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()?)
}

pub fn set_follower_state(c: &Connection, actor: &str, state: &str) -> anyhow::Result<bool> {
    Ok(c.execute(
        "UPDATE followers SET state = ?2 WHERE actor = ?1",
        params![actor, state],
    )? > 0)
}

pub fn delete_follower(c: &Connection, actor: &str) -> anyhow::Result<bool> {
    Ok(c.execute("DELETE FROM followers WHERE actor = ?1", [actor])? > 0)
}

pub fn list_followers(c: &Connection) -> anyhow::Result<Vec<FollowerInfo>> {
    let mut stmt = c.prepare(
        "SELECT f.actor, f.state, f.created, a.name, a.summary FROM followers f
         LEFT JOIN remote_actors a ON a.id = f.actor ORDER BY f.state DESC, f.actor",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok(FollowerInfo {
                actor: r.get(0)?,
                state: r.get(1)?,
                since: parse_ts(&r.get::<_, String>(2)?),
                name: r.get(3)?,
                summary: r.get(4)?,
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

pub fn accepted_followers(c: &Connection) -> anyhow::Result<Vec<String>> {
    let mut stmt = c.prepare("SELECT actor FROM followers WHERE state = 'accepted'")?;
    let rows = stmt
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

pub fn is_accepted_follower(c: &Connection, actor: &str) -> anyhow::Result<bool> {
    Ok(get_follower(c, actor)?.is_some_and(|(_, s)| s == "accepted"))
}

// ---------------------------------------------------------------- evidence

#[derive(Debug, Clone)]
pub struct StoredEvidence {
    pub object: EvidenceObject,
    pub local: bool,
    pub deleted: Option<DateTime<Utc>>,
    pub audience: Vec<String>,
    pub sort_key: String,
}

fn evidence_row(r: &Row) -> rusqlite::Result<(String, bool, Option<String>, String, String)> {
    Ok((
        r.get::<_, String>(0)?,
        r.get::<_, i64>(1)? != 0,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
    ))
}

fn to_stored(
    (object, local, deleted, audience, sort_key): (String, bool, Option<String>, String, String),
) -> anyhow::Result<StoredEvidence> {
    Ok(StoredEvidence {
        object: serde_json::from_str(&object)?,
        local,
        deleted: opt_ts(deleted),
        audience: serde_json::from_str(&audience).unwrap_or_default(),
        sort_key,
    })
}

const EVIDENCE_COLS: &str = "object, local, deleted, audience, sort_key";

pub fn get_evidence(c: &Connection, id: &str) -> anyhow::Result<Option<StoredEvidence>> {
    c.query_row(
        &format!("SELECT {EVIDENCE_COLS} FROM evidence WHERE id = ?1"),
        [id],
        evidence_row,
    )
    .optional()?
    .map(to_stored)
    .transpose()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upsert {
    Inserted,
    Updated,
    Ignored,
}

/// Store an evidence object (Create or Update semantics, Sections 5.1, 6, 8).
/// Existing objects are replaced only if the new copy is newer, from the same
/// publisher, not withdrawn, and does not un-revoke an indicator.
pub fn upsert_evidence(
    c: &Connection,
    o: &EvidenceObject,
    local: bool,
    audience: &[String],
    listed_until: Option<DateTime<Utc>>,
) -> anyhow::Result<Upsert> {
    let existing = get_evidence(c, &o.id)?;
    if let Some(old) = &existing {
        if old.deleted.is_some()
            || old.object.attributed_to != o.attributed_to
            || o.base() <= old.object.base()
            || (old.object.is_revoked() && !o.is_revoked())
        {
            return Ok(Upsert::Ignored);
        }
    }
    let json = serde_json::to_string(o)?;
    c.execute(
        "INSERT INTO evidence (id, kind, publisher, local, observable_type, observable_value, tlp,
             sort_key, listed_until, audience, object, received)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT(id) DO UPDATE SET kind = excluded.kind, observable_type = excluded.observable_type,
             observable_value = excluded.observable_value, tlp = excluded.tlp,
             sort_key = excluded.sort_key, listed_until = excluded.listed_until,
             audience = excluded.audience, object = excluded.object, received = excluded.received",
        params![
            o.id,
            o.kind.as_str(),
            o.attributed_to,
            local as i64,
            o.observable_type.map(|t| t.as_str()),
            o.observable_value,
            o.tlp.as_str(),
            ts(o.base()),
            listed_until.map(ts),
            serde_json::to_string(audience)?,
            json,
            ts(Utc::now())
        ],
    )?;
    Ok(if existing.is_some() {
        Upsert::Updated
    } else {
        Upsert::Inserted
    })
}

/// Withdraw an object (Delete / Tombstone). Only the publisher may do so.
pub fn mark_deleted(
    c: &Connection,
    id: &str,
    publisher: &str,
    when: DateTime<Utc>,
    tombstone_until: DateTime<Utc>,
) -> anyhow::Result<bool> {
    let n = c.execute(
        "UPDATE evidence SET deleted = ?3, sort_key = ?3, listed_until = ?4
         WHERE id = ?1 AND publisher = ?2 AND deleted IS NULL",
        params![id, publisher, ts(when), ts(tombstone_until)],
    )?;
    Ok(n > 0)
}

/// All non-withdrawn evidence.
pub fn live_evidence(c: &Connection) -> anyhow::Result<Vec<EvidenceObject>> {
    let mut stmt = c.prepare("SELECT object FROM evidence WHERE deleted IS NULL")?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .filter_map(|r| r.ok())
        .filter_map(|s| serde_json::from_str(&s).ok())
        .collect();
    Ok(rows)
}

pub fn evidence_for_observable(
    c: &Connection,
    ty: ObservableType,
    value: &str,
) -> anyhow::Result<Vec<StoredEvidence>> {
    let mut stmt = c.prepare(&format!(
        "SELECT {EVIDENCE_COLS} FROM evidence
         WHERE observable_type = ?1 AND observable_value = ?2 ORDER BY sort_key DESC"
    ))?;
    let rows: Vec<_> = stmt
        .query_map(params![ty.as_str(), value], evidence_row)?
        .collect::<Result<_, _>>()?;
    rows.into_iter().map(to_stored).collect()
}

/// Local objects still listed in `activeObjects`, newest first, keyset-paged.
pub fn local_listed(
    c: &Connection,
    now: DateTime<Utc>,
    before: Option<(&str, &str)>,
    limit: usize,
) -> anyhow::Result<Vec<StoredEvidence>> {
    let (bk, bid) = before.unwrap_or(("\u{10ffff}", ""));
    let mut stmt = c.prepare(&format!(
        "SELECT {EVIDENCE_COLS} FROM evidence
         WHERE local = 1 AND listed_until > ?1 AND (sort_key < ?2 OR (sort_key = ?2 AND id < ?3))
         ORDER BY sort_key DESC, id DESC LIMIT ?4"
    ))?;
    let rows: Vec<_> = stmt
        .query_map(params![ts(now), bk, bid, limit as i64], evidence_row)?
        .collect::<Result<_, _>>()?;
    rows.into_iter().map(to_stored).collect()
}

pub fn count_evidence(c: &Connection) -> anyhow::Result<u64> {
    Ok(c.query_row(
        "SELECT COUNT(*) FROM evidence WHERE deleted IS NULL",
        [],
        |r| r.get::<_, i64>(0),
    )? as u64)
}

pub fn count_evidence_by_publisher(c: &Connection, publisher: &str) -> anyhow::Result<u64> {
    Ok(c.query_row(
        "SELECT COUNT(*) FROM evidence WHERE deleted IS NULL AND publisher = ?1",
        [publisher],
        |r| r.get::<_, i64>(0),
    )? as u64)
}

/// Delete old records (Section 11). Remote evidence is removed once it can
/// no longer contribute (`aged_out` computed by the caller); withdrawn local
/// objects after their Tombstone period.
pub fn delete_evidence_ids(c: &mut Connection, ids: &[String]) -> anyhow::Result<usize> {
    let tx = c.transaction()?;
    let mut n = 0;
    for id in ids {
        n += tx.execute("DELETE FROM evidence WHERE id = ?1", [id])?;
    }
    tx.commit()?;
    Ok(n)
}

pub fn purge_expired(
    c: &Connection,
    now: DateTime<Utc>,
    retention_cutoff: DateTime<Utc>,
) -> anyhow::Result<usize> {
    let mut n = c.execute(
        "DELETE FROM evidence WHERE deleted IS NOT NULL AND listed_until < ?1",
        [ts(now)],
    )?;
    n += c.execute(
        "DELETE FROM evidence WHERE deleted IS NOT NULL AND local = 0 AND deleted < ?1",
        [ts(retention_cutoff)],
    )?;
    c.execute(
        "DELETE FROM processed_activities WHERE received < ?1",
        [ts(retention_cutoff)],
    )?;
    c.execute(
        "DELETE FROM observations WHERE pending = 0 AND last_seen < ?1",
        [ts(retention_cutoff)],
    )?;
    c.execute(
        "DELETE FROM review WHERE resolved IS NOT NULL AND resolved < ?1",
        [ts(retention_cutoff)],
    )?;
    Ok(n)
}

// ----------------------------------------------------- processed activities

/// Returns `true` if the activity id was not seen before (Section 8, replay).
pub fn mark_processed(c: &Connection, id: &str) -> anyhow::Result<bool> {
    Ok(c.execute(
        "INSERT OR IGNORE INTO processed_activities (id, received) VALUES (?1, ?2)",
        params![id, ts(Utc::now())],
    )? > 0)
}

// ------------------------------------------------------------ observations

#[derive(Debug, Clone)]
pub struct Observation {
    pub observable_type: ObservableType,
    pub observable_value: String,
    pub behavior: Behavior,
    pub port: Option<u16>,
    pub service: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub count: u64,
    pub sighting_id: Option<String>,
    /// TLP requested by the sensor, or the behaviour's publish TLP if it
    /// sent none. `None` only on rows stored before the push API resolved it.
    pub tlp: Option<Tlp>,
}

/// SQL rank of a TLP column, ordered like [`Tlp`].
fn tlp_rank_sql(col: &str) -> String {
    format!(
        "CASE {col} WHEN 'clear' THEN 0 WHEN 'green' THEN 1 WHEN 'amber' THEN 2 \
         WHEN 'amber+strict' THEN 3 ELSE 4 END"
    )
}

pub fn add_observation(c: &Connection, o: &Observation) -> anyhow::Result<()> {
    // Within one batch the most restrictive requested TLP wins; once
    // published, the next observation's TLP starts afresh. The push API
    // always sets a TLP; NULL only remains on rows stored before that.
    let sql = format!(
        "INSERT INTO observations (observable_type, observable_value, behavior, port, service,
             first_seen, last_seen, count, pending, tlp)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9)
         ON CONFLICT(observable_type, observable_value, behavior) DO UPDATE SET
             port = COALESCE(excluded.port, port), service = COALESCE(excluded.service, service),
             first_seen = MIN(first_seen, excluded.first_seen),
             last_seen = MAX(last_seen, excluded.last_seen),
             count = count + excluded.count,
             tlp = CASE
                 WHEN pending = 0 OR tlp IS NULL THEN excluded.tlp
                 WHEN excluded.tlp IS NULL THEN tlp
                 WHEN {} > {} THEN excluded.tlp
                 ELSE tlp END,
             pending = 1",
        tlp_rank_sql("excluded.tlp"),
        tlp_rank_sql("tlp")
    );
    c.execute(
        &sql,
        params![
            o.observable_type.as_str(),
            o.observable_value,
            o.behavior.as_str(),
            o.port,
            o.service,
            ts(o.first_seen),
            ts(o.last_seen),
            o.count as i64,
            o.tlp.map(Tlp::as_str)
        ],
    )?;
    Ok(())
}

pub fn pending_observations(c: &Connection) -> anyhow::Result<Vec<Observation>> {
    let mut stmt = c.prepare(
        "SELECT observable_type, observable_value, behavior, port, service, first_seen, last_seen,
             count, sighting_id, tlp FROM observations WHERE pending = 1",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok(Observation {
                observable_type: r
                    .get::<_, String>(0)?
                    .parse()
                    .unwrap_or(ObservableType::Unknown),
                observable_value: r.get(1)?,
                behavior: Behavior::parse_lenient(&r.get::<_, String>(2)?),
                port: r.get(3)?,
                service: r.get(4)?,
                first_seen: parse_ts(&r.get::<_, String>(5)?),
                last_seen: parse_ts(&r.get::<_, String>(6)?),
                count: r.get::<_, i64>(7)? as u64,
                sighting_id: r.get(8)?,
                tlp: r.get::<_, Option<String>>(9)?.and_then(|t| t.parse().ok()),
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

pub fn mark_observation_published(
    c: &Connection,
    o: &Observation,
    sighting_id: &str,
) -> anyhow::Result<()> {
    // Observations merged in since `o` was read stay pending for the next
    // batch instead of being dropped.
    c.execute(
        "UPDATE observations SET sighting_id = ?4,
             pending = CASE WHEN first_seen = ?5 AND last_seen = ?6 AND count = ?7
                 THEN 0 ELSE 1 END
         WHERE observable_type = ?1 AND observable_value = ?2 AND behavior = ?3",
        params![
            o.observable_type.as_str(),
            o.observable_value,
            o.behavior.as_str(),
            sighting_id,
            ts(o.first_seen),
            ts(o.last_seen),
            o.count as i64
        ],
    )?;
    Ok(())
}

pub fn count_pending_observations(c: &Connection) -> anyhow::Result<u64> {
    Ok(c.query_row(
        "SELECT COUNT(*) FROM observations WHERE pending = 1",
        [],
        |r| r.get::<_, i64>(0),
    )? as u64)
}

// ---------------------------------------------------- activities/deliveries

pub fn insert_activity(
    c: &Connection,
    id: &str,
    tlp: Tlp,
    audience: &[String],
    json: &serde_json::Value,
) -> anyhow::Result<()> {
    c.execute(
        "INSERT INTO activities (id, tlp, audience, json, created) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            id,
            tlp.as_str(),
            serde_json::to_string(audience)?,
            json.to_string(),
            ts(Utc::now())
        ],
    )?;
    Ok(())
}

pub struct StoredActivity {
    pub json: serde_json::Value,
    pub tlp: Tlp,
    pub audience: Vec<String>,
}

pub fn get_activity(c: &Connection, id: &str) -> anyhow::Result<Option<StoredActivity>> {
    let row = c
        .query_row(
            "SELECT json, tlp, audience FROM activities WHERE id = ?1",
            [id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    row.map(|(j, t, a)| {
        Ok(StoredActivity {
            json: serde_json::from_str(&j)?,
            tlp: t.parse().map_err(anyhow::Error::msg)?,
            audience: serde_json::from_str(&a)?,
        })
    })
    .transpose()
}

pub fn recent_activities(c: &Connection, limit: usize) -> anyhow::Result<Vec<StoredActivity>> {
    let mut stmt = c.prepare("SELECT id FROM activities ORDER BY created DESC LIMIT ?1")?;
    let ids: Vec<String> = stmt
        .query_map([limit as i64], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    Ok(ids
        .iter()
        .filter_map(|id| get_activity(c, id).ok().flatten())
        .collect())
}

pub fn enqueue_delivery(c: &Connection, activity_id: &str, inbox: &str) -> anyhow::Result<()> {
    c.execute(
        "INSERT INTO deliveries (activity_id, inbox, next_attempt) VALUES (?1, ?2, ?3)",
        params![activity_id, inbox, ts(Utc::now())],
    )?;
    Ok(())
}

pub struct Delivery {
    pub id: i64,
    pub inbox: String,
    pub attempts: u32,
    pub json: serde_json::Value,
}

pub fn due_deliveries(
    c: &Connection,
    now: DateTime<Utc>,
    limit: usize,
) -> anyhow::Result<Vec<Delivery>> {
    let mut stmt = c.prepare(
        "SELECT d.id, d.inbox, d.attempts, a.json FROM deliveries d
         JOIN activities a ON a.id = d.activity_id
         WHERE d.next_attempt <= ?1 ORDER BY d.next_attempt LIMIT ?2",
    )?;
    let rows = stmt
        .query_map(params![ts(now), limit as i64], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?
        .filter_map(|r| r.ok())
        .filter_map(|(id, inbox, attempts, json)| {
            Some(Delivery {
                id,
                inbox,
                attempts: attempts as u32,
                json: serde_json::from_str(&json).ok()?,
            })
        })
        .collect();
    Ok(rows)
}

pub fn delivery_done(c: &Connection, id: i64) -> anyhow::Result<()> {
    c.execute("DELETE FROM deliveries WHERE id = ?1", [id])?;
    Ok(())
}

pub fn delivery_failed(
    c: &Connection,
    id: i64,
    attempts: u32,
    next: DateTime<Utc>,
    error: &str,
    max_attempts: u32,
) -> anyhow::Result<()> {
    if attempts >= max_attempts {
        c.execute("DELETE FROM deliveries WHERE id = ?1", [id])?;
    } else {
        c.execute(
            "UPDATE deliveries SET attempts = ?2, next_attempt = ?3, last_error = ?4 WHERE id = ?1",
            params![id, attempts, ts(next), error],
        )?;
    }
    Ok(())
}

pub fn count_deliveries(c: &Connection) -> anyhow::Result<u64> {
    Ok(c.query_row("SELECT COUNT(*) FROM deliveries", [], |r| {
        r.get::<_, i64>(0)
    })? as u64)
}

// --------------------------------------------------------------- allowlist

fn allowlist_row(r: &Row) -> rusqlite::Result<AllowlistEntry> {
    let scope: String = r.get(1)?;
    Ok(AllowlistEntry {
        id: r.get(0)?,
        scope: if scope == "published" {
            AllowlistScope::Published
        } else {
            AllowlistScope::Local
        },
        observable_type: r
            .get::<_, String>(2)?
            .parse()
            .unwrap_or(ObservableType::Unknown),
        observable_value: r.get(3)?,
        behaviors: serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or_default(),
        tlp: r.get::<_, Option<String>>(5)?.and_then(|t| t.parse().ok()),
        valid_until: opt_ts(r.get(6)?),
        summary: r.get(7)?,
        object_id: r.get(8)?,
        created: parse_ts(&r.get::<_, String>(9)?),
        source: r.get(10)?,
    })
}

const ALLOWLIST_COLS: &str =
    "id, scope, observable_type, observable_value, behaviors, tlp, valid_until, summary, object_id, created, source";

pub fn insert_allowlist(c: &Connection, e: &AllowlistEntry) -> anyhow::Result<i64> {
    c.execute(
        "INSERT INTO allowlist (scope, observable_type, observable_value, behaviors, tlp, valid_until,
             summary, object_id, created, source) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            match e.scope {
                AllowlistScope::Local => "local",
                AllowlistScope::Published => "published",
            },
            e.observable_type.as_str(),
            e.observable_value,
            serde_json::to_string(&e.behaviors)?,
            e.tlp.map(|t| t.as_str()),
            e.valid_until.map(ts),
            e.summary,
            e.object_id,
            ts(e.created),
            e.source
        ],
    )?;
    Ok(c.last_insert_rowid())
}

/// Queue a `Create`, `Update` or `Delete` of an own Opinion for the next
/// publish batch.
pub fn queue_opinion(c: &Connection, object_id: &str, kind: &str) -> anyhow::Result<()> {
    c.execute(
        "INSERT INTO pending_opinions (object_id, kind, queued) VALUES (?1, ?2, ?3)
         ON CONFLICT(object_id) DO UPDATE SET version = version + 1,
             kind = CASE WHEN excluded.kind = 'Delete' THEN 'Delete' ELSE kind END",
        params![object_id, kind, ts(Utc::now())],
    )?;
    Ok(())
}

pub struct PendingOpinion {
    pub object_id: String,
    pub kind: String,
    pub version: i64,
}

pub fn pending_opinions(c: &Connection) -> anyhow::Result<Vec<PendingOpinion>> {
    let mut stmt = c.prepare(
        "SELECT object_id, kind, version FROM pending_opinions ORDER BY queued, object_id",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok(PendingOpinion {
                object_id: r.get(0)?,
                kind: r.get(1)?,
                version: r.get(2)?,
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

/// Remove sent entries, unless they were queued again meanwhile.
pub fn clear_pending_opinions(c: &Connection, sent: &[(String, i64)]) -> anyhow::Result<()> {
    for (id, version) in sent {
        c.execute(
            "DELETE FROM pending_opinions WHERE object_id = ?1 AND version = ?2",
            params![id, version],
        )?;
    }
    Ok(())
}

pub fn set_allowlist_valid_until(
    c: &Connection,
    id: i64,
    until: DateTime<Utc>,
) -> anyhow::Result<()> {
    c.execute(
        "UPDATE allowlist SET valid_until = ?2 WHERE id = ?1",
        params![id, ts(until)],
    )?;
    Ok(())
}

pub fn list_allowlist(c: &Connection) -> anyhow::Result<Vec<AllowlistEntry>> {
    let mut stmt = c.prepare(&format!(
        "SELECT {ALLOWLIST_COLS} FROM allowlist ORDER BY id"
    ))?;
    let rows = stmt
        .query_map([], allowlist_row)?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

pub fn get_allowlist(c: &Connection, id: i64) -> anyhow::Result<Option<AllowlistEntry>> {
    Ok(c.query_row(
        &format!("SELECT {ALLOWLIST_COLS} FROM allowlist WHERE id = ?1"),
        [id],
        allowlist_row,
    )
    .optional()?)
}

pub fn delete_allowlist(c: &Connection, id: i64) -> anyhow::Result<Option<AllowlistEntry>> {
    let e = c
        .query_row(
            &format!("SELECT {ALLOWLIST_COLS} FROM allowlist WHERE id = ?1"),
            [id],
            allowlist_row,
        )
        .optional()?;
    c.execute("DELETE FROM allowlist WHERE id = ?1", [id])?;
    Ok(e)
}

// -------------------------------------------------------------- api tokens

fn api_token_row(r: &Row) -> rusqlite::Result<ApiTokenInfo> {
    Ok(ApiTokenInfo {
        id: r.get(0)?,
        name: r.get(1)?,
        scopes: serde_json::from_str(&r.get::<_, String>(2)?).unwrap_or_default(),
        // Unknown values fall back to the most restrictive choice.
        max_tlp: r.get::<_, String>(3)?.parse().unwrap_or(Tlp::Clear),
        created: parse_ts(&r.get::<_, String>(4)?),
        last_used: opt_ts(r.get(5)?),
    })
}

const API_TOKEN_COLS: &str = "id, name, scopes, max_tlp, created, last_used";

/// Store a token. `hash` is the hex SHA-512 of the secret; the secret
/// itself is never stored.
pub fn insert_api_token(
    c: &Connection,
    name: &str,
    hash: &str,
    scopes: &[ApiScope],
    max_tlp: Tlp,
) -> anyhow::Result<ApiTokenInfo> {
    let exists = c
        .query_row("SELECT 1 FROM api_tokens WHERE name = ?1", [name], |_| {
            Ok(())
        })
        .optional()?
        .is_some();
    if exists {
        anyhow::bail!("a token named `{name}` already exists");
    }
    c.execute(
        "INSERT INTO api_tokens (name, hash, scopes, max_tlp, created) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            name,
            hash,
            serde_json::to_string(scopes)?,
            max_tlp.as_str(),
            ts(Utc::now())
        ],
    )?;
    get_api_token(c, c.last_insert_rowid())?.context("token vanished after insert")
}

pub fn list_api_tokens(c: &Connection) -> anyhow::Result<Vec<ApiTokenInfo>> {
    let mut stmt = c.prepare(&format!(
        "SELECT {API_TOKEN_COLS} FROM api_tokens ORDER BY name"
    ))?;
    let rows = stmt
        .query_map([], api_token_row)?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

pub fn get_api_token(c: &Connection, id: i64) -> anyhow::Result<Option<ApiTokenInfo>> {
    Ok(c.query_row(
        &format!("SELECT {API_TOKEN_COLS} FROM api_tokens WHERE id = ?1"),
        [id],
        api_token_row,
    )
    .optional()?)
}

pub fn update_api_token(
    c: &Connection,
    id: i64,
    scopes: &[ApiScope],
    max_tlp: Tlp,
) -> anyhow::Result<Option<ApiTokenInfo>> {
    c.execute(
        "UPDATE api_tokens SET scopes = ?2, max_tlp = ?3 WHERE id = ?1",
        params![id, serde_json::to_string(scopes)?, max_tlp.as_str()],
    )?;
    get_api_token(c, id)
}

/// Replace the secret hash; the old secret stops working immediately.
pub fn set_api_token_hash(
    c: &Connection,
    id: i64,
    hash: &str,
) -> anyhow::Result<Option<ApiTokenInfo>> {
    c.execute(
        "UPDATE api_tokens SET hash = ?2, last_used = NULL WHERE id = ?1",
        params![id, hash],
    )?;
    get_api_token(c, id)
}

pub fn delete_api_token(c: &Connection, id: i64) -> anyhow::Result<Option<ApiTokenInfo>> {
    let t = get_api_token(c, id)?;
    c.execute("DELETE FROM api_tokens WHERE id = ?1", [id])?;
    Ok(t)
}

/// Look up a token by the hash of the presented secret and record its use
/// (at most once a minute, to limit writes).
pub fn authenticate_api_token(
    c: &Connection,
    hash: &str,
    now: DateTime<Utc>,
) -> anyhow::Result<Option<ApiTokenInfo>> {
    let Some(mut t) = c
        .query_row(
            &format!("SELECT {API_TOKEN_COLS} FROM api_tokens WHERE hash = ?1"),
            [hash],
            api_token_row,
        )
        .optional()?
    else {
        return Ok(None);
    };
    if t.last_used
        .is_none_or(|u| now - u >= chrono::TimeDelta::minutes(1))
    {
        c.execute(
            "UPDATE api_tokens SET last_used = ?2 WHERE id = ?1",
            params![t.id, ts(now)],
        )?;
        t.last_used = Some(now);
    }
    Ok(Some(t))
}

// ------------------------------------------------------------------ review

pub fn insert_review(
    c: &Connection,
    kind: &str,
    ty: ObservableType,
    value: &str,
    behavior: Option<Behavior>,
    detail: &str,
) -> anyhow::Result<bool> {
    Ok(c.execute(
        "INSERT OR IGNORE INTO review (kind, observable_type, observable_value, behavior, detail, created)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            kind,
            ty.as_str(),
            value,
            behavior.map(|b| b.as_str()).unwrap_or(""),
            detail,
            ts(Utc::now())
        ],
    )? > 0)
}

fn review_row(r: &Row) -> rusqlite::Result<ReviewItem> {
    let b: String = r.get(4)?;
    Ok(ReviewItem {
        id: r.get(0)?,
        kind: r.get(1)?,
        observable_type: r
            .get::<_, String>(2)?
            .parse()
            .unwrap_or(ObservableType::Unknown),
        observable_value: r.get(3)?,
        behavior: (!b.is_empty()).then(|| Behavior::parse_lenient(&b)),
        detail: r.get(5)?,
        created: parse_ts(&r.get::<_, String>(6)?),
        resolution: r.get(7)?,
    })
}

const REVIEW_COLS: &str =
    "id, kind, observable_type, observable_value, behavior, detail, created, resolution";

pub fn list_review(c: &Connection, include_resolved: bool) -> anyhow::Result<Vec<ReviewItem>> {
    let sql = if include_resolved {
        format!("SELECT {REVIEW_COLS} FROM review ORDER BY id DESC LIMIT 1000")
    } else {
        format!(
            "SELECT {REVIEW_COLS} FROM review WHERE resolution IS NULL ORDER BY id DESC LIMIT 1000"
        )
    };
    let mut stmt = c.prepare(&sql)?;
    let rows = stmt.query_map([], review_row)?.collect::<Result<_, _>>()?;
    Ok(rows)
}

pub fn resolve_review(
    c: &Connection,
    id: i64,
    resolution: &str,
) -> anyhow::Result<Option<ReviewItem>> {
    c.execute(
        "UPDATE review SET resolution = ?2, resolved = ?3 WHERE id = ?1",
        params![id, resolution, ts(Utc::now())],
    )?;
    Ok(c.query_row(
        &format!("SELECT {REVIEW_COLS} FROM review WHERE id = ?1"),
        [id],
        review_row,
    )
    .optional()?)
}

pub fn count_open_review(c: &Connection) -> anyhow::Result<u64> {
    Ok(c.query_row(
        "SELECT COUNT(*) FROM review WHERE resolution IS NULL",
        [],
        |r| r.get::<_, i64>(0),
    )? as u64)
}

// ------------------------------------------------------------------ active

pub fn replace_active(c: &mut Connection, list: &[Assessment]) -> anyhow::Result<()> {
    let tx = c.transaction()?;
    tx.execute("DELETE FROM active", [])?;
    {
        let mut stmt = tx.prepare(
            "INSERT INTO active (observable_type, observable_value, behavior, effective_expiry,
                 active, flagged, tlp, assessment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;
        for a in list {
            stmt.execute(params![
                a.observable_type.as_str(),
                a.observable_value,
                a.behavior.as_str(),
                a.effective_expiry.map(ts),
                a.active as i64,
                a.flagged as i64,
                a.tlp.as_str(),
                serde_json::to_string(a)?
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Entries of the active list. Unless `include_inactive`, only entries that
/// are active and not yet expired at `now`.
pub fn list_active(
    c: &Connection,
    now: DateTime<Utc>,
    ty: Option<ObservableType>,
    behavior: Option<Behavior>,
    include_inactive: bool,
) -> anyhow::Result<Vec<Assessment>> {
    let mut stmt = c.prepare(
        "SELECT assessment FROM active
         WHERE (?1 IS NULL OR observable_type = ?1) AND (?2 IS NULL OR behavior = ?2)
           AND (?3 OR (active = 1 AND effective_expiry > ?4))
         ORDER BY observable_type, observable_value, behavior",
    )?;
    let rows = stmt
        .query_map(
            params![
                ty.map(|t| t.as_str()),
                behavior.map(|b| b.as_str()),
                include_inactive,
                ts(now)
            ],
            |r| r.get::<_, String>(0),
        )?
        .filter_map(|r| r.ok())
        .filter_map(|s| serde_json::from_str(&s).ok())
        .collect();
    Ok(rows)
}

pub fn count_active(c: &Connection, now: DateTime<Utc>) -> anyhow::Result<(u64, u64)> {
    let active = c.query_row(
        "SELECT COUNT(*) FROM active WHERE active = 1 AND effective_expiry > ?1",
        [ts(now)],
        |r| r.get::<_, i64>(0),
    )? as u64;
    let flagged = c.query_row("SELECT COUNT(*) FROM active WHERE flagged = 1", [], |r| {
        r.get::<_, i64>(0)
    })? as u64;
    Ok((active, flagged))
}

#[cfg(test)]
mod tests {
    use super::*;
    use apti_core::EvidenceKind;
    use chrono::TimeDelta;

    fn sighting(id: &str, published: DateTime<Utc>) -> EvidenceObject {
        serde_json::from_value(serde_json::json!({
            "type": "Sighting", "id": id, "attributedTo": "https://a.example/actor",
            "published": published, "observableType": "ipv4-addr", "observableValue": "8.8.4.4",
            "observedBehavior": ["scan"], "firstSeen": published, "lastSeen": published,
            "count": 1, "tlp": "green"
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn observation_merged_during_batch_stays_pending() {
        let db = Db::open_in_memory().unwrap();
        db.call(|c| {
            let now: DateTime<Utc> = "2026-10-03T10:00:00.123Z".parse()?;
            let obs = Observation {
                observable_type: ObservableType::Ipv4Addr,
                observable_value: "8.8.4.4".into(),
                behavior: Behavior::Scan,
                port: None,
                service: None,
                first_seen: now,
                last_seen: now,
                count: 1,
                sighting_id: None,
                tlp: None,
            };
            add_observation(c, &obs)?;
            let read = pending_observations(c)?.remove(0);
            // Arrives after the batch read the row.
            add_observation(
                c,
                &Observation {
                    last_seen: now + TimeDelta::seconds(5),
                    ..obs.clone()
                },
            )?;
            mark_observation_published(c, &read, "https://a.example/s/1")?;
            let again = pending_observations(c)?;
            assert_eq!(again.len(), 1);
            assert_eq!(again[0].count, 2);
            assert_eq!(
                again[0].sighting_id.as_deref(),
                Some("https://a.example/s/1")
            );
            mark_observation_published(c, &again[0], "https://a.example/s/1")?;
            assert!(pending_observations(c)?.is_empty());
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn followers_carry_actor_summary() {
        let db = Db::open_in_memory().unwrap();
        db.call(|c| {
            let actor = RemoteActor {
                id: "https://b.example/actor".into(),
                inbox: "https://b.example/actor/inbox".into(),
                shared_inbox: None,
                followers: None,
                active_objects: None,
                key_id: None,
                public_key_pem: None,
                operator_claim: None,
                preferred_username: Some("ti".into()),
                name: Some("B TI".into()),
                summary: Some("Removal requests: abuse@b.example".into()),
                fetched_at: parse_ts("2026-10-03T10:00:00Z"),
            };
            upsert_remote_actor(c, &actor)?;
            assert_eq!(get_remote_actor(c, &actor.id)?, Some(actor.clone()));
            upsert_follower(c, &actor.id, "https://b.example/f/1", "pending")?;
            // Followers whose actor document is not cached have no summary.
            upsert_follower(
                c,
                "https://c.example/actor",
                "https://c.example/f/1",
                "pending",
            )?;
            let f = list_followers(c)?;
            assert_eq!(f.len(), 2);
            assert_eq!(f[0].name.as_deref(), Some("B TI"));
            assert_eq!(f[0].summary, actor.summary);
            assert_eq!(f[1].summary, None);
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn evidence_upsert_rules() {
        let db = Db::open_in_memory().unwrap();
        db.call(|c| {
            let now = Utc::now();
            let mut s = sighting("https://a.example/s/1", now);
            assert_eq!(upsert_evidence(c, &s, false, &[], None)?, Upsert::Inserted);
            assert_eq!(upsert_evidence(c, &s, false, &[], None)?, Upsert::Ignored);
            s.updated = Some(now + TimeDelta::seconds(1));
            assert_eq!(upsert_evidence(c, &s, false, &[], None)?, Upsert::Updated);
            // Different publisher cannot overwrite.
            let mut evil = s.clone();
            evil.attributed_to = "https://b.example/actor".into();
            evil.updated = Some(now + TimeDelta::seconds(5));
            assert_eq!(
                upsert_evidence(c, &evil, false, &[], None)?,
                Upsert::Ignored
            );
            assert!(!mark_deleted(
                c,
                &s.id,
                "https://b.example/actor",
                now,
                now
            )?);
            assert!(mark_deleted(
                c,
                &s.id,
                "https://a.example/actor",
                now,
                now + TimeDelta::days(1)
            )?);
            s.updated = Some(now + TimeDelta::seconds(10));
            assert_eq!(upsert_evidence(c, &s, false, &[], None)?, Upsert::Ignored);
            assert!(live_evidence(c)?.is_empty());
            assert_eq!(
                get_evidence(c, &s.id)?.unwrap().object.kind,
                EvidenceKind::Sighting
            );
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn local_listing_pages() {
        let db = Db::open_in_memory().unwrap();
        db.call(|c| {
            let now = Utc::now();
            for i in 0..5 {
                let s = sighting(
                    &format!("https://a.example/s/{i}"),
                    now - TimeDelta::minutes(i),
                );
                upsert_evidence(c, &s, true, &[], Some(now + TimeDelta::days(1)))?;
            }
            let p1 = local_listed(c, now, None, 2)?;
            assert_eq!(p1.len(), 2);
            assert_eq!(p1[0].object.id, "https://a.example/s/0");
            let last = p1.last().unwrap();
            let p2 = local_listed(c, now, Some((&last.sort_key, &last.object.id)), 10)?;
            assert_eq!(p2.len(), 3);
            assert_eq!(p2[0].object.id, "https://a.example/s/2");
            Ok(())
        })
        .await
        .unwrap();
    }
}
