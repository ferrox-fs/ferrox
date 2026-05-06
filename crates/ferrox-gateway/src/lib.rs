//! HTTP gateway for Ferrox.
//!
//! Hosts the axum router, SigV4 authentication middleware, rate limiting,
//! request-ID injection, and the per-endpoint S3 handlers. Composition of
//! the full router happens in [`router::build_router`] (Step 9).
//!
//! Submodule layout:
//! - [`auth`]      — SigV4 header parsing + HMAC verification
//! - [`middleware`] — tower layers (auth, request-id, tracing)
//! - [`handlers`]  — per-endpoint S3 handlers
//! - [`router`]    — axum [`Router`](axum::Router) wiring
//! - [`state`]     — shared application state ([`AppState`](state::AppState))

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod admin;
pub mod auth;
pub mod error;
pub mod handlers;
pub mod metrics;
pub mod middleware;
pub mod notify;
pub mod ratelimit;
pub mod router;
pub mod state;
