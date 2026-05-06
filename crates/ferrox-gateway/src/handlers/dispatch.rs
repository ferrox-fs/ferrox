//! Query-param–based dispatch handlers for endpoints that multiplex on `?uploads`,
//! `?uploadId=X`, `?partNumber=N`, and `?delete`.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use ferrox_meta::MetaStore;
use ferrox_storage::StorageBackend;

use super::bucket::{delete_object, delete_objects, get_bucket_versioning, put_bucket_versioning};
use super::cors::{get_bucket_cors, put_bucket_cors};
use super::encryption::{get_bucket_encryption, put_bucket_encryption};
use super::multipart::{
    abort_multipart_upload, complete_multipart_upload, initiate_multipart_upload,
    list_multipart_uploads, list_parts, upload_part,
};
use super::notification::{get_bucket_notification, put_bucket_notification};
use super::object::{get_object, put_object};
use super::tagging::{
    get_bucket_tagging, get_object_tagging, put_bucket_tagging, put_object_tagging,
};
use crate::error::AppError;
use crate::middleware::RequestId;
use crate::state::AppState;

/// `PUT /{bucket}/{*key}` — dispatch to:
/// - [`upload_part`] when `?partNumber=N&uploadId=X`
/// - [`put_object`] otherwise (regular put or CopyObject)
pub async fn put_dispatch<S, M>(
    State(state): State<AppState<S, M>>,
    Path(bk): Path<(String, String)>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    headers: HeaderMap,
    rid: axum::extract::Extension<RequestId>,
    body: Body,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    let qs = query.clone().unwrap_or_default();
    if has_query_key(&qs, "tagging") {
        put_object_tagging(State(state), Path(bk), rid, body).await
    } else if qs.contains("uploadId") && qs.contains("partNumber") {
        upload_part(
            State(state),
            Path(bk),
            axum::extract::RawQuery(query),
            headers,
            rid,
            body,
        )
        .await
    } else {
        put_object(State(state), Path(bk), headers, rid, body).await
    }
}

/// `POST /{bucket}/{*key}` — dispatch to:
/// - [`initiate_multipart_upload`] when `?uploads`
/// - [`complete_multipart_upload`] when `?uploadId=X`
pub async fn post_dispatch<S, M>(
    State(state): State<AppState<S, M>>,
    Path(bk): Path<(String, String)>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    headers: HeaderMap,
    rid: axum::extract::Extension<RequestId>,
    body: Body,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    let qs = query.clone().unwrap_or_default();
    if has_query_key(&qs, "uploads") {
        initiate_multipart_upload(
            State(state),
            Path(bk),
            axum::extract::RawQuery(query),
            headers,
            rid,
        )
        .await
    } else if qs.contains("uploadId") {
        complete_multipart_upload(
            State(state),
            Path(bk),
            axum::extract::RawQuery(query),
            rid,
            body,
        )
        .await
    } else {
        // Unknown POST — 501.
        Ok(super::not_implemented_response())
    }
}

/// `DELETE /{bucket}/{*key}` — dispatch to:
/// - [`abort_multipart_upload`] when `?uploadId=X`
/// - [`delete_object`] otherwise
pub async fn delete_dispatch<S, M>(
    State(state): State<AppState<S, M>>,
    Path(bk): Path<(String, String)>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    rid: axum::extract::Extension<RequestId>,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    let qs = query.clone().unwrap_or_default();
    if qs.contains("uploadId") {
        abort_multipart_upload(State(state), Path(bk), axum::extract::RawQuery(query), rid).await
    } else {
        delete_object(State(state), Path(bk), rid).await
    }
}

/// `POST /{bucket}` — dispatch to:
/// - [`delete_objects`] when `?delete`
/// - 501 otherwise
pub async fn post_bucket_dispatch<S, M>(
    State(state): State<AppState<S, M>>,
    Path(bucket): Path<String>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    rid: axum::extract::Extension<RequestId>,
    body: Body,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    let qs = query.unwrap_or_default();
    if has_query_key(&qs, "delete") {
        delete_objects(State(state), Path(bucket), rid, body).await
    } else {
        Ok(super::not_implemented_response())
    }
}

/// True if `qs` contains `key` as a query parameter, with or without `=value`.
/// Matches `key`, `key=`, `key=v`, `...&key`, `...&key=`, `...&key=v`.
fn has_query_key(qs: &str, key: &str) -> bool {
    qs.split('&').any(|p| {
        let name = p.split_once('=').map(|(k, _)| k).unwrap_or(p);
        name == key
    })
}

/// `PUT /{bucket}` — dispatch to:
/// - [`put_bucket_versioning`] when `?versioning`
/// - `create_bucket` otherwise
pub async fn put_bucket_dispatch<S, M>(
    State(state): State<AppState<S, M>>,
    Path(bucket): Path<String>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    rid: axum::extract::Extension<RequestId>,
    body: Body,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    use super::bucket::create_bucket;
    let qs = query.unwrap_or_default();
    if has_query_key(&qs, "versioning") {
        put_bucket_versioning(State(state), Path(bucket), rid, body).await
    } else if has_query_key(&qs, "tagging") {
        put_bucket_tagging(State(state), Path(bucket), rid, body).await
    } else if has_query_key(&qs, "cors") {
        put_bucket_cors(State(state), Path(bucket), rid, body).await
    } else if has_query_key(&qs, "encryption") {
        put_bucket_encryption(State(state), Path(bucket), rid, body).await
    } else if has_query_key(&qs, "notification") {
        put_bucket_notification(State(state), Path(bucket), rid, body).await
    } else {
        create_bucket(State(state), Path(bucket), rid).await
    }
}

/// `GET /{bucket}` — dispatch to:
/// - [`get_bucket_versioning`] when `?versioning`
/// - [`list_multipart_uploads`] when `?uploads`
/// - `list_objects` otherwise
pub async fn get_bucket_dispatch<S, M>(
    State(state): State<AppState<S, M>>,
    Path(bucket): Path<String>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    rid: axum::extract::Extension<RequestId>,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    use super::bucket::list_objects;
    let qs = query.clone().unwrap_or_default();
    if has_query_key(&qs, "versioning") {
        get_bucket_versioning(State(state), Path(bucket), rid).await
    } else if has_query_key(&qs, "uploads") {
        list_multipart_uploads(State(state), Path(bucket), rid).await
    } else if has_query_key(&qs, "tagging") {
        get_bucket_tagging(State(state), Path(bucket), rid).await
    } else if has_query_key(&qs, "cors") {
        get_bucket_cors(State(state), Path(bucket), rid).await
    } else if has_query_key(&qs, "encryption") {
        get_bucket_encryption(State(state), Path(bucket), rid).await
    } else if has_query_key(&qs, "notification") {
        get_bucket_notification(State(state), Path(bucket), rid).await
    } else {
        list_objects(
            State(state),
            Path(bucket),
            axum::extract::RawQuery(query),
            rid,
        )
        .await
    }
}

/// `GET /{bucket}/{*key}` — dispatch to:
/// - [`list_parts`] when `?uploadId=X`
/// - [`get_object`] otherwise
pub async fn get_object_dispatch<S, M>(
    State(state): State<AppState<S, M>>,
    Path(bk): Path<(String, String)>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    headers: HeaderMap,
    rid: axum::extract::Extension<RequestId>,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    let qs = query.clone().unwrap_or_default();
    if has_query_key(&qs, "tagging") {
        get_object_tagging(State(state), Path(bk), rid).await
    } else if qs.contains("uploadId") && !qs.contains("partNumber") {
        list_parts(State(state), Path(bk), axum::extract::RawQuery(query), rid).await
    } else {
        get_object(State(state), Path(bk), headers, rid).await
    }
}
