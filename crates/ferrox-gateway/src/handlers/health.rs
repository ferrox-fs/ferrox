//! Unauthenticated health endpoints (`/health/live`, `/health/ready`,
//! `/health/version`) and the Prometheus `/metrics` scrape endpoint.

use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ferrox_meta::MetaStore;
use ferrox_storage::StorageBackend;
use serde_json::json;

use crate::state::AppState;

/// `GET /health/live` — process is up.
pub async fn live() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}

/// `GET /health/ready` — checks metadata store and disk write/delete.
///
/// Returns 200 when both probes succeed; 503 otherwise. Each probe is run
/// concurrently with [`tokio::join!`].
pub async fn ready<S, M>(State(state): State<AppState<S, M>>) -> impl IntoResponse
where
    S: StorageBackend,
    M: MetaStore,
{
    let meta_probe = async {
        // Touch a known path: list_buckets is cheap and exercises sled read.
        tokio::time::timeout(
            Duration::from_secs(2),
            state.meta.list_buckets("__readiness_probe__"),
        )
        .await
        .ok()
        .and_then(|r| r.ok())
        .is_some()
    };
    let disk_probe = async {
        let dir = state.config.data_dir.join(".ready");
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::fs::create_dir_all(&dir).await.ok();
            let f = dir.join("probe");
            tokio::fs::write(&f, b"ok").await.is_ok() && tokio::fs::remove_file(&f).await.is_ok()
        })
        .await
        .unwrap_or(false)
    };

    let (meta_ok, disk_ok) = tokio::join!(meta_probe, disk_probe);
    let body = json!({
        "status": if meta_ok && disk_ok { "ready" } else { "not_ready" },
        "checks": {
            "metadata": if meta_ok { "ok" } else { "fail" },
            "disk":     if disk_ok { "ok" } else { "fail" },
        }
    });
    if meta_ok && disk_ok {
        (StatusCode::OK, Json(body))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(body))
    }
}

/// `GET /health/version` — build version + commit + build timestamp.
pub async fn version() -> impl IntoResponse {
    let v = env!("CARGO_PKG_VERSION");
    let commit = option_env!("FERROX_GIT_COMMIT").unwrap_or("unknown");
    let built = option_env!("FERROX_BUILD_TIMESTAMP").unwrap_or("unknown");
    (
        StatusCode::OK,
        Json(json!({
            "version": v,
            "commit": commit,
            "built_at": built,
        })),
    )
}

/// `GET /metrics` — Prometheus scrape endpoint, no auth.
pub async fn metrics<S, M>(State(state): State<AppState<S, M>>) -> Response
where
    S: StorageBackend,
    M: MetaStore,
{
    let body = state.metrics.render();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; version=0.0.4")
        .body(Body::from(body))
        .unwrap()
}
