//! fail2ban connector for aptid.
//!
//! - **push**: follow the fail2ban log and submit bans as observations
//!   (`POST /api/v1/observations`).
//! - **pull**: poll the active list (`GET /api/v1/active`) and write ban
//!   lines to files that fail2ban jails follow with the `apti` filter.

pub mod client;
pub mod config;
pub mod parse;
pub mod pull;
pub mod push;
pub mod tail;
