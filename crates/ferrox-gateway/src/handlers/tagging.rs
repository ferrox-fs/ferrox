//! Object and bucket tagging handlers (Phase 2 Step 25).

use std::collections::BTreeMap;

use axum::body::{to_bytes, Body};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ferrox_error::FerroxError;
use ferrox_meta::MetaStore;
use ferrox_s3_api::names::{validate_bucket_name, validate_object_key};
use ferrox_s3_api::xml::{parse_tagging, tagging, validate_tag_set};
use ferrox_storage::StorageBackend;

use crate::error::{empty_response, xml_response, AppError};
use crate::middleware::RequestId;
use crate::state::AppState;

const MAX_TAGGING_BODY: usize = 64 * 1024;

/// `PUT /{bucket}/{*key}?tagging` — replace the object tag set.
pub async fn put_object_tagging<S, M>(
    State(state): State<AppState<S, M>>,
    Path((bucket, key)): Path<(String, String)>,
    rid: axum::extract::Extension<RequestId>,
    body: Body,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    let resource = format!("/{bucket}/{key}");
    let rid = rid.0 .0;
    let to_app = |e: FerroxError| AppError::new(e, resource.clone(), rid.clone());

    validate_bucket_name(&bucket).map_err(to_app)?;
    validate_object_key(&key).map_err(to_app)?;

    let raw = to_bytes(body, MAX_TAGGING_BODY)
        .await
        .map_err(|e| to_app(FerroxError::Internal(format!("body read: {e}"))))?;
    let parsed = parse_tagging(&raw)
        .map_err(|m| to_app(FerroxError::InvalidRequest(format!("MalformedXML: {m}"))))?;
    validate_tag_set(&parsed).map_err(|m| to_app(FerroxError::InvalidRequest(m)))?;

    let mut record = state
        .meta
        .get_object_meta(&bucket, &key)
        .await
        .map_err(to_app)?;
    record.tags = parsed.into_iter().collect::<BTreeMap<_, _>>();
    state
        .meta
        .put_object_meta(&bucket, &key, record)
        .await
        .map_err(to_app)?;

    Ok(empty_response(StatusCode::OK, &rid))
}

/// `GET /{bucket}/{*key}?tagging` — fetch the object tag set.
pub async fn get_object_tagging<S, M>(
    State(state): State<AppState<S, M>>,
    Path((bucket, key)): Path<(String, String)>,
    rid: axum::extract::Extension<RequestId>,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    let resource = format!("/{bucket}/{key}");
    let rid = rid.0 .0;
    let to_app = |e: FerroxError| AppError::new(e, resource.clone(), rid.clone());

    validate_bucket_name(&bucket).map_err(to_app)?;
    validate_object_key(&key).map_err(to_app)?;

    let record = state
        .meta
        .get_object_meta(&bucket, &key)
        .await
        .map_err(to_app)?;
    let pairs: Vec<(&str, &str)> = record
        .tags
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let xml = tagging(&pairs);
    Ok(xml_response(StatusCode::OK, &rid, xml))
}

/// `PUT /{bucket}?tagging` — replace bucket-level tags.
pub async fn put_bucket_tagging<S, M>(
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

    let raw = to_bytes(body, MAX_TAGGING_BODY)
        .await
        .map_err(|e| to_app(FerroxError::Internal(format!("body read: {e}"))))?;
    let parsed = parse_tagging(&raw)
        .map_err(|m| to_app(FerroxError::InvalidRequest(format!("MalformedXML: {m}"))))?;
    validate_tag_set(&parsed).map_err(|m| to_app(FerroxError::InvalidRequest(m)))?;

    let map: BTreeMap<String, String> = parsed.into_iter().collect();
    state
        .meta
        .set_bucket_tags(&bucket, map)
        .await
        .map_err(to_app)?;

    Ok(empty_response(StatusCode::OK, &rid))
}

/// `GET /{bucket}?tagging` — fetch bucket-level tags.
pub async fn get_bucket_tagging<S, M>(
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

    let pairs: Vec<(&str, &str)> = meta
        .tags
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let xml = tagging(&pairs);
    Ok(xml_response(StatusCode::OK, &rid, xml))
}
