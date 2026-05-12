//! Bucket CORS configuration handlers + preflight (Phase 2 Step 26).

use axum::body::{to_bytes, Body};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ferrox_error::FerroxError;
use ferrox_meta::{CorsRule, MetaStore};
use ferrox_s3_api::names::validate_bucket_name;
use ferrox_s3_api::xml::{cors_configuration, parse_cors_config_xml, CorsRuleXml};
use ferrox_storage::StorageBackend;

use crate::error::{empty_response, xml_response, AppError};
use crate::middleware::RequestId;
use crate::state::AppState;

const MAX_CORS_BODY: usize = 64 * 1024;

/// `PUT /{bucket}?cors` — replace CORS configuration.
pub async fn put_bucket_cors<S, M>(
    State(state): State<AppState<S, M>>,
    Path(bucket): Path<String>,
    rid: axum::extract::Extension<RequestId>,
    body: Body,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    let resource = format!("/{bucket}");
    let rid = rid.0 .0;
    let to_app = |e: FerroxError| AppError::new(e, resource.clone(), rid.clone());

    validate_bucket_name(&bucket).map_err(to_app)?;

    let raw = to_bytes(body, MAX_CORS_BODY)
        .await
        .map_err(|e| to_app(FerroxError::Internal(format!("body read: {e}"))))?;
    let parsed = parse_cors_config_xml(&raw)
        .map_err(|m| to_app(FerroxError::InvalidRequest(format!("MalformedXML: {m}"))))?;

    let rules: Vec<CorsRule> = parsed
        .into_iter()
        .map(|p| CorsRule {
            allowed_origins: p.allowed_origins,
            allowed_methods: p.allowed_methods,
            allowed_headers: p.allowed_headers,
            expose_headers: p.expose_headers,
            max_age_seconds: p.max_age_seconds,
        })
        .collect();

    state
        .meta
        .set_bucket_cors(&bucket, rules)
        .await
        .map_err(to_app)?;

    Ok(empty_response(StatusCode::OK, &rid))
}

/// `GET /{bucket}?cors` — fetch CORS configuration.
pub async fn get_bucket_cors<S, M>(
    State(state): State<AppState<S, M>>,
    Path(bucket): Path<String>,
    rid: axum::extract::Extension<RequestId>,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    let resource = format!("/{bucket}");
    let rid = rid.0 .0;
    let to_app = |e: FerroxError| AppError::new(e, resource.clone(), rid.clone());

    validate_bucket_name(&bucket).map_err(to_app)?;
    let meta = state.meta.get_bucket(&bucket).await.map_err(to_app)?;

    let rules: Vec<CorsRuleXml<'_>> = meta
        .cors_rules
        .iter()
        .map(|r| CorsRuleXml {
            allowed_origins: &r.allowed_origins,
            allowed_methods: &r.allowed_methods,
            allowed_headers: &r.allowed_headers,
            expose_headers: &r.expose_headers,
            max_age_seconds: r.max_age_seconds,
        })
        .collect();
    let xml = cors_configuration(&rules);
    Ok(xml_response(StatusCode::OK, &rid, xml))
}

/// Look up the matching CORS rule for `(origin, method)` on `bucket`.
/// Returns the `(allowed_methods_csv, max_age, expose_headers_csv)` tuple
/// to use in response headers, or `None` if no rule matches.
pub async fn lookup_cors_rule<M: MetaStore>(
    meta: &M,
    bucket: &str,
    origin: &str,
    method: &str,
) -> Option<(String, Option<u32>, String)> {
    let m = meta.get_bucket(bucket).await.ok()?;
    for r in &m.cors_rules {
        let origin_ok = r
            .allowed_origins
            .iter()
            .any(|o| o == "*" || o.eq_ignore_ascii_case(origin));
        let method_ok = r
            .allowed_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method));
        if origin_ok && method_ok {
            return Some((
                r.allowed_methods.join(","),
                r.max_age_seconds,
                r.expose_headers.join(","),
            ));
        }
    }
    None
}
