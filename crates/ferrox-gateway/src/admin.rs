//! Admin API (Phase 3 Step 38) — runs on a separate port (default 9444),
//! protected by mTLS with a CA generated on first boot.
//!
//! Endpoints (all under `/admin`):
//!
//! | Method | Path | Description |
//! |---|---|---|
//! | `POST` | `/admin/access-keys` | create new access-key pair |
//! | `DELETE` | `/admin/access-keys/{id}` | revoke key |
//! | `GET` | `/admin/access-keys` | list keys |
//! | `PUT` | `/admin/rate-limits/{id}` | per-key rate-limit override |
//! | `GET` | `/admin/stats` | aggregate stats JSON |

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::ratelimit::PerKeyRateLimiter;

/// Shared admin state.
#[derive(Clone, Default)]
pub struct AdminState {
    /// Access key id → secret. v1 keeps these in memory; persistent storage
    /// lands when the IAM crate is built out.
    pub keys: Arc<dashmap::DashMap<String, String>>,
    /// Optional per-key rate limiter (so admin overrides write through).
    pub rate_limiter: Option<PerKeyRateLimiter>,
}

/// Build the admin axum [`Router`].
pub fn build_admin_router(state: AdminState) -> Router {
    Router::new()
        .route("/admin/access-keys", post(create_key).get(list_keys))
        .route("/admin/access-keys/{id}", delete(revoke_key))
        .route("/admin/rate-limits/{id}", put(set_rate_limit))
        .route("/admin/stats", get(stats))
        .with_state(state)
}

#[derive(Serialize)]
struct KeyResp {
    access_key: String,
    secret_key: String,
}

async fn create_key(State(s): State<AdminState>) -> impl IntoResponse {
    let ak = format!("AKIA{}", uuid::Uuid::new_v4().simple());
    let sk = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    s.keys.insert(ak.clone(), sk.clone());
    (
        StatusCode::CREATED,
        Json(KeyResp {
            access_key: ak,
            secret_key: sk,
        }),
    )
}

async fn list_keys(State(s): State<AdminState>) -> impl IntoResponse {
    let ids: Vec<String> = s.keys.iter().map(|kv| kv.key().clone()).collect();
    Json(serde_json::json!({ "access_keys": ids }))
}

async fn revoke_key(State(s): State<AdminState>, Path(id): Path<String>) -> impl IntoResponse {
    if s.keys.remove(&id).is_some() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

#[derive(Deserialize)]
struct RateLimitReq {
    #[allow(dead_code)]
    req_per_sec: u32,
}

async fn set_rate_limit(
    State(_s): State<AdminState>,
    Path(_id): Path<String>,
    Json(_req): Json<RateLimitReq>,
) -> impl IntoResponse {
    // Per-key overrides are not yet persisted; v1 returns 202 Accepted.
    StatusCode::ACCEPTED
}

async fn stats(State(s): State<AdminState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "access_keys_count": s.keys.len(),
    }))
}
