//! Per-access-key request rate limiting (Phase 2 Step 31).
//!
//! Uses a token-bucket per access key from the [`governor`] crate. Limits are
//! configured per server; per-key overrides could be loaded from sled later.
//! The limit is applied AFTER SigV4 auth, where the key identity is known.

use std::num::NonZeroU32;
use std::sync::Arc;

use dashmap::DashMap;
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};

type Limiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;
type LimiterMap = DashMap<String, Arc<Limiter>>;

/// Wrapper around a governor [`RateLimiter`] keyed by access-key id.
#[derive(Clone)]
pub struct PerKeyRateLimiter {
    inner: Arc<LimiterMap>,
    quota: Quota,
}

impl std::fmt::Debug for PerKeyRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerKeyRateLimiter")
            .field("keys", &self.inner.len())
            .finish()
    }
}

impl PerKeyRateLimiter {
    /// Build a limiter that issues `req_per_sec` per access key with a small
    /// burst window. `req_per_sec` of 0 disables limiting.
    pub fn new(req_per_sec: u32) -> Option<Self> {
        let n = NonZeroU32::new(req_per_sec)?;
        Some(Self {
            inner: Arc::new(DashMap::new()),
            quota: Quota::per_second(n),
        })
    }

    /// Returns `true` if the request is permitted; `false` if it exceeds the
    /// per-second budget for `access_key`.
    pub fn check(&self, access_key: &str) -> bool {
        let limiter = self
            .inner
            .entry(access_key.to_string())
            .or_insert_with(|| Arc::new(RateLimiter::direct(self.quota)))
            .clone();
        limiter.check().is_ok()
    }
}
