//! Bucket-level default encryption configuration (Phase 2 Step 28).

use axum::body::{to_bytes, Body};
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use bytes::Bytes;
use ferrox_error::FerroxError;
use ferrox_meta::{EncryptionConfig, MetaStore};
use ferrox_s3_api::names::validate_bucket_name;
use ferrox_s3_api::xml::{encryption_configuration, parse_encryption_configuration};
use ferrox_storage::StorageBackend;
use http_body_util::Full;

use crate::error::AppError;
use crate::middleware::RequestId;
use crate::state::AppState;

/// `PUT /{bucket}?encryption` — set default SSE policy.
pub async fn put_bucket_encryption<S, M>(
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

    let raw = to_bytes(body, 16 * 1024)
        .await
        .map_err(|e| to_app(FerroxError::Internal(format!("body read: {e}"))))?;
    let alg = parse_encryption_configuration(&raw)
        .map_err(|m| to_app(FerroxError::InvalidRequest(format!("MalformedXML: {m}"))))?;
    if alg != "AES256" {
        return Err(to_app(FerroxError::InvalidRequest(format!(
            "unsupported SSEAlgorithm: {alg}"
        ))));
    }

    let cfg = EncryptionConfig {
        algorithm: alg,
        enforced: true,
    };
    state
        .meta
        .set_bucket_encryption(&bucket, Some(cfg))
        .await
        .map_err(to_app)?;

    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut()
        .insert("x-amz-request-id", HeaderValue::from_str(&rid).unwrap());
    Ok(resp)
}

/// `GET /{bucket}?encryption` — fetch default SSE policy.
pub async fn get_bucket_encryption<S, M>(
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

    let cfg = meta.encryption.ok_or_else(|| {
        to_app(FerroxError::NotFound {
            bucket: bucket.clone(),
            key: Some("encryption-config".into()),
        })
    })?;

    let xml = encryption_configuration(&cfg.algorithm);
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .header("x-amz-request-id", &rid)
        .body(Body::new(Full::new(Bytes::from(xml))))
        .unwrap())
}
