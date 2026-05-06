//! `OPTIONS` preflight handler — looks up the bucket CORS rules and emits
//! `Access-Control-Allow-*` headers when a rule matches.

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::Response;
use ferrox_meta::MetaStore;
use ferrox_storage::StorageBackend;

use crate::handlers::cors::lookup_cors_rule;
use crate::state::AppState;

/// Handle `OPTIONS /{bucket}` and `OPTIONS /{bucket}/{*key}`.
///
/// Returns 200 with `Access-Control-*` headers when the bucket has a matching
/// CORS rule for the request `Origin` and `Access-Control-Request-Method`.
/// Returns 403 when no rule matches or `Origin` is missing.
pub async fn cors_preflight<S, M>(
    State(state): State<AppState<S, M>>,
    uri: Uri,
    headers: HeaderMap,
) -> Response
where
    S: StorageBackend,
    M: MetaStore,
{
    let path = uri.path().trim_start_matches('/');
    let bucket = path.split('/').next().unwrap_or("").to_string();
    if bucket.is_empty() {
        return error_403();
    }
    let origin = match headers.get("origin").and_then(|v| v.to_str().ok()) {
        Some(o) if !o.is_empty() => o.to_string(),
        _ => return error_403(),
    };
    let method = headers
        .get("access-control-request-method")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("GET")
        .to_string();

    let Some((methods_csv, max_age, expose_csv)) =
        lookup_cors_rule(state.meta.as_ref(), &bucket, &origin, &method).await
    else {
        return error_403();
    };

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("vary", "origin")
        .header("access-control-allow-origin", origin)
        .header("access-control-allow-methods", methods_csv);
    if let Some(s) = max_age {
        builder = builder.header("access-control-max-age", s.to_string());
    }
    if !expose_csv.is_empty() {
        builder = builder.header("access-control-expose-headers", expose_csv);
    }
    builder.body(Body::empty()).unwrap_or_else(|_| error_403())
}

fn error_403() -> Response {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::FORBIDDEN;
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml"),
    );
    resp
}
