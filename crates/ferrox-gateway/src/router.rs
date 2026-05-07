//! axum router wiring for the Ferrox gateway.
//!
//! [`build_router`] constructs the axum [`Router`] hosting every S3 endpoint,
//! mounted under generic [`AppState<S, M>`](crate::state::AppState).
//!
//! Middleware stack (outermost first):
//! 1. [`MetricsLayer`](crate::metrics::MetricsLayer) — request counter + latency histogram
//! 2. [`TraceLayer`](tower_http::trace::TraceLayer) — request/response logging
//! 3. [`SigV4AuthLayer`] — SigV4 verification + per-key rate limiting
//! 4. [`RequestIdLayer`] — UUIDv4 attached as `x-amz-request-id`

use axum::routing::{get, head, options, put};
use axum::Router;
use ferrox_meta::MetaStore;
use ferrox_storage::StorageBackend;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

use crate::handlers::bucket::{delete_bucket, head_bucket, list_buckets};
use crate::handlers::dispatch::{
    delete_dispatch, get_bucket_dispatch, get_object_dispatch, post_bucket_dispatch, post_dispatch,
    put_bucket_dispatch, put_dispatch,
};
use crate::handlers::health;
use crate::handlers::object::head_object;
use crate::handlers::preflight::cors_preflight;
use crate::metrics::MetricsLayer;
use crate::middleware::auth::AuthConfig;
use crate::middleware::{RequestIdLayer, SigV4AuthLayer};
use crate::state::AppState;

/// Build the axum router for an [`AppState<S, M>`]. Health endpoints and
/// `/metrics` are mounted without auth; all S3 routes go through SigV4.
pub fn build_router<S, M>(state: AppState<S, M>) -> Router
where
    S: StorageBackend,
    M: MetaStore,
{
    let auth = SigV4AuthLayer::new(AuthConfig {
        access_key: state.config.access_key.clone(),
        secret_key: state.config.secret_key.clone(),
        clock_skew_secs: state.config.clock_skew_secs,
    })
    .with_rate_limiter(state.rate_limiter.clone());

    let s3_routes = Router::new()
        .route("/", get(list_buckets::<S, M>))
        .route(
            "/{bucket}",
            put(put_bucket_dispatch::<S, M>)
                .head(head_bucket::<S, M>)
                .delete(delete_bucket::<S, M>)
                .get(get_bucket_dispatch::<S, M>)
                .post(post_bucket_dispatch::<S, M>),
        )
        .route(
            "/{bucket}/{*key}",
            put(put_dispatch::<S, M>)
                .get(get_object_dispatch::<S, M>)
                .delete(delete_dispatch::<S, M>)
                .post(post_dispatch::<S, M>),
        )
        .route("/{bucket}/{*key}", head(head_object::<S, M>))
        .route("/{bucket}/{*key}", options(cors_preflight::<S, M>))
        .route("/{bucket}", options(cors_preflight::<S, M>))
        .with_state(state.clone());

    // Request flow (outermost → innermost):
    //   1. RequestIdLayer  — assigns a UUIDv4 *before* auth runs, so even
    //      rejected requests carry a non-zero `x-amz-request-id`.
    //   2. MetricsLayer    — records duration/status for every response.
    //   3. TraceLayer      — structured request/response logging.
    //   4. SigV4AuthLayer  — verifies signature, applies rate limit.
    let s3_layered = s3_routes.layer(
        ServiceBuilder::new()
            .layer(RequestIdLayer)
            .layer(MetricsLayer::new(state.metrics.clone()))
            .layer(TraceLayer::new_for_http())
            .layer(auth),
    );

    Router::new()
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready::<S, M>))
        .route("/health/version", get(health::version))
        .route("/metrics", get(health::metrics::<S, M>))
        .with_state(state)
        .merge(s3_layered)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use ferrox_meta::SledMeta;
    use ferrox_storage::disk::DiskBackend;
    use tempfile::TempDir;
    use tower::util::ServiceExt;

    use super::*;
    use crate::metrics::Metrics;
    use crate::state::GatewayConfig;

    async fn make_state() -> (TempDir, AppState<DiskBackend, SledMeta>) {
        let tmp = TempDir::new().unwrap();
        let storage = Arc::new(
            DiskBackend::new(tmp.path().join("data"), false)
                .await
                .unwrap(),
        );
        let meta = Arc::new(SledMeta::open(tmp.path().join("meta")).unwrap());
        let config = Arc::new(GatewayConfig {
            data_dir: tmp.path().to_path_buf(),
            access_key: "AKID".into(),
            secret_key: "SECRET".into(),
            fsync: false,
            clock_skew_secs: 900,
            sse_master_key: None,
            max_req_per_sec: 0,
        });
        (
            tmp,
            AppState {
                storage,
                meta,
                config,
                metrics: Metrics::new(),
                rate_limiter: None,
            },
        )
    }

    #[tokio::test]
    async fn test_unauthenticated_request_returns_403_not_501() {
        let (_t, st) = make_state().await;
        let app = build_router(st);
        let req = Request::builder()
            .uri("/some-bucket/some-key")
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_health_live_bypasses_auth() {
        let (_t, st) = make_state().await;
        let app = build_router(st);
        let req = Request::builder()
            .uri("/health/live")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_metrics_endpoint_returns_prometheus_format() {
        let (_t, st) = make_state().await;
        let app = build_router(st);
        let req = Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.starts_with("text/plain"));
    }

    #[tokio::test]
    async fn test_request_with_bogus_signature_returns_403() {
        let (_t, st) = make_state().await;
        let app = build_router(st);
        let req = Request::builder()
            .uri("/b/k")
            .method("GET")
            .header(
                "authorization",
                "AWS4-HMAC-SHA256 Credential=AK/20260506/testregion/s3/aws4_request, \
                 SignedHeaders=host, Signature=abc",
            )
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
