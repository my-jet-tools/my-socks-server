//! SOCKS5 proxy (RFC 1928 `CONNECT`, RFC 1929 username/password authentication) built to
//! run unattended on an internet-facing port: every connection phase is bounded by a
//! timeout, descriptors are released on every path, and destinations are checked against
//! an SSRF policy on the actually resolved address.
#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod auth;
pub mod config;
pub mod limits;
pub mod policy;
pub mod relay;
pub mod server;
pub mod socks;
