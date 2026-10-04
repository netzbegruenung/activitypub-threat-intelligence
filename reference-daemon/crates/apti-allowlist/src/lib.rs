//! Keeps aptid's local allowlist in sync with a hand-edited text file.
//!
//! The whole file is read and reconciled against `GET /api/v1/allowlist`
//! whenever its content changes (and periodically). Two modes:
//!
//! - **append**: values in the file are added; nothing is removed.
//! - **source of truth**: additionally, entries this tool created are
//!   removed once their value is no longer in the file.

pub mod client;
pub mod config;
pub mod reconcile;
pub mod sync;
