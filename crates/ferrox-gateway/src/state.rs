//! Shared application state passed to every axum handler.

use std::sync::Arc;

use ferrox_meta::MetaStore;
use ferrox_storage::StorageBackend;

use crate::metrics::Metrics;
use crate::ratelimit::PerKeyRateLimiter;

/// Static gateway configuration. Cheap to clone.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// Root data directory (used by storage + meta).
    pub data_dir: std::path::PathBuf,
    /// Single-tenant access key (Phase 0). Multi-key IAM lands in Phase 1+.
    pub access_key: String,
    /// Secret bound to `access_key`.
    pub secret_key: String,
    /// Whether to fsync object writes.
    pub fsync: bool,
    /// Allowed clock skew between client and server, in seconds.
    pub clock_skew_secs: i64,
    /// AWS region this gateway represents. SigV4 requires the request scope's
    /// region segment to match (case-insensitive). SigV4A uses this value to
    /// match against the signed `x-amz-region-set`.
    pub region: String,
    /// Optional 32-byte master key for SSE-S3. `None` disables SSE-S3.
    pub sse_master_key: Option<ferrox_crypto::SseMasterKey>,
    /// Per-access-key requests/second limit. `0` disables rate limiting.
    pub max_req_per_sec: u32,
}

/// Shared, generic application state held inside the axum router.
pub struct AppState<S: StorageBackend, M: MetaStore> {
    /// Storage backend (disk by default).
    pub storage: Arc<S>,
    /// Metadata store (sled by default).
    pub meta: Arc<M>,
    /// Static config.
    pub config: Arc<GatewayConfig>,
    /// Prometheus metrics registry.
    pub metrics: Metrics,
    /// Per-access-key rate limiter (`None` disables).
    pub rate_limiter: Option<PerKeyRateLimiter>,
}

impl<S: StorageBackend, M: MetaStore> Clone for AppState<S, M> {
    fn clone(&self) -> Self {
        Self {
            storage: Arc::clone(&self.storage),
            meta: Arc::clone(&self.meta),
            config: Arc::clone(&self.config),
            metrics: self.metrics.clone(),
            rate_limiter: self.rate_limiter.clone(),
        }
    }
}
