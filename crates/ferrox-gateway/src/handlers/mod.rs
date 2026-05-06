//! Per-endpoint S3 handlers.
//!
//! Phase 0 Steps 11–14 fill these in. Until then every route returns a
//! `501 Not Implemented` body so the auth and routing layers can be tested
//! end-to-end without depending on storage logic.

pub mod bucket;
pub mod cors;
pub mod dispatch;
pub mod encryption;
pub mod health;
pub mod multipart;
pub mod notification;
pub mod object;
pub mod preflight;
pub mod tagging;

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Default placeholder body for unimplemented routes (async handler form).
pub async fn not_implemented() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        "not implemented (Phase 0 stub)",
    )
}

/// Default placeholder response (non-async, for use inside dispatch handlers).
pub(crate) fn not_implemented_response() -> Response {
    let mut resp = Response::new(Body::from("not implemented"));
    *resp.status_mut() = StatusCode::NOT_IMPLEMENTED;
    resp
}
