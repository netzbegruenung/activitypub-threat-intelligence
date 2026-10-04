//! Rspamd connector for aptid.
//!
//! - **ingest**: a Lua plugin in Rspamd posts the result of every scanned
//!   message to `/v1/report`. IPs that keep sending bad messages are
//!   reported to aptid as observations (`POST /api/v1/observations`).
//! - **maps**: the active list (`GET /api/v1/active`) is served as multimap
//!   files at `/maps/<name>`, so Rspamd scores IPs and domains listed by
//!   aptid.

pub mod client;
pub mod config;
pub mod maps;
pub mod push;
pub mod reputation;
pub mod server;
