//! Public statistics page for the AP-TI reference daemon.
//!
//! Sits in front of a hub and publishes aggregate statistics over its
//! TLP:CLEAR dataset: a statistics page (no individual observables,
//! Section 11) plus a JSON endpoint listing the hub's connected nodes. Data
//! is polled from the hub's internal API with a `read` token capped at
//! `max_tlp = "clear"`. By default both are rendered into a directory for a
//! web server to serve ([`render`]); with `server.bind` set they are served
//! directly instead, with ETag caching and per-client rate limiting
//! ([`server`]). Either way the last snapshot is kept on hub outages.

pub mod client;
pub mod config;
pub mod page;
pub mod poll;
pub mod render;
pub mod server;
pub mod stats;
