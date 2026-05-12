//! Bucket-level S3 handlers: `CreateBucket`, `HeadBucket`, `DeleteBucket`,
//! `ListBuckets`, `DeleteObject`, and `DeleteObjects` (batch).

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use bytes::Bytes;
use ferrox_error::FerroxError;
use ferrox_meta::MetaStore;
use ferrox_s3_api::xml::{list_all_my_buckets, BucketEntry};
use ferrox_storage::StorageBackend;
use http_body_util::Full;

use crate::error::AppError;
use crate::middleware::{rid_header, RequestId};
use crate::state::AppState;
use ferrox_s3_api::names::validate_bucket_name;

/// `PUT /{bucket}` — create a bucket. Idempotent if the same owner recreates.
pub async fn create_bucket<S, M>(
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

    state.storage.create_bucket(&bucket).await.map_err(to_app)?;

    // Owner is the access key for Phase 0 (single-tenant).
    state
        .meta
        .create_bucket(&bucket, &state.config.access_key)
        .await
        .map_err(to_app)?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("location", format!("/{bucket}"))
        .header("x-amz-request-id", &rid)
        .body(Body::empty())
        .map_err(|e| to_app(FerroxError::Internal(format!("response build: {e}"))))?;
    Ok(response)
}

/// `HEAD /{bucket}` — check whether a bucket exists; 200 if yes, 404 if not.
pub async fn head_bucket<S, M>(
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

    let exists = state.storage.bucket_exists(&bucket).await.map_err(to_app)?;
    if !exists {
        return Err(to_app(FerroxError::NotFound { bucket, key: None }));
    }

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("x-amz-request-id", &rid)
        .body(Body::empty())
        .map_err(|e| to_app(FerroxError::Internal(format!("response build: {e}"))))?;
    Ok(response)
}

/// `DELETE /{bucket}` — delete an empty bucket.
pub async fn delete_bucket<S, M>(
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

    // Reject if any objects remain (AWS BucketNotEmpty).
    let listing = state
        .meta
        .list_objects(&bucket, None, 1, None)
        .await
        .map_err(to_app)?;
    if !listing.objects.is_empty() {
        return Err(to_app(FerroxError::InvalidRequest(format!(
            "bucket {bucket} is not empty"
        ))));
    }

    state.storage.delete_bucket(&bucket).await.map_err(to_app)?;
    state.meta.delete_bucket(&bucket).await.map_err(to_app)?;

    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::NO_CONTENT;
    resp.headers_mut()
        .insert("x-amz-request-id", rid_header(&rid));
    Ok(resp)
}

/// `GET /` — list all buckets owned by the authenticated identity.
pub async fn list_buckets<S, M>(
    State(state): State<AppState<S, M>>,
    rid: axum::extract::Extension<RequestId>,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    let rid = rid.0 .0;
    let to_app = |e: FerroxError| AppError::new(e, "/", rid.clone());

    let buckets = state
        .meta
        .list_buckets(&state.config.access_key)
        .await
        .map_err(to_app)?;

    let entries: Vec<BucketEntry<'_>> = buckets
        .iter()
        .map(|b| BucketEntry {
            name: &b.name,
            creation_date: b.created,
        })
        .collect();

    let owner = &state.config.access_key;
    let xml = list_all_my_buckets(owner, owner, &entries);

    let body = Body::new(Full::new(Bytes::from(xml)));
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .header("x-amz-request-id", &rid)
        .body(body)
        .map_err(|e| to_app(FerroxError::Internal(format!("response build: {e}"))))?;
    Ok(response)
}

/// `DELETE /{bucket}/{*key}` — delete a single object.
pub async fn delete_object<S, M>(
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
    ferrox_s3_api::names::validate_object_key(&key).map_err(to_app)?;

    // S3 DELETE Object is idempotent: missing object → 204. Missing bucket
    // is still a hard 404 (NoSuchBucket), so check bucket existence first.
    state.meta.get_bucket(&bucket).await.map_err(to_app)?;

    match state.storage.delete(&bucket, &key).await {
        Ok(()) => {}
        // Object already absent — that's fine; the desired post-state holds.
        Err(FerroxError::NotFound { key: Some(_), .. }) => {}
        Err(other) => return Err(to_app(other)),
    }
    // Best-effort meta removal — record may already be absent.
    let _ = state.meta.delete_object_meta(&bucket, &key).await;

    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::NO_CONTENT;
    resp.headers_mut()
        .insert("x-amz-request-id", rid_header(&rid));
    Ok(resp)
}

/// `GET /{bucket}` — list objects in a bucket using the ListBucketResult XML.
///
/// Supports `?list-type=2` query, `prefix`, `max-keys`, `continuation-token`.
/// Falls back to ListObjectsV1 envelope when `list-type` is absent or `1`.
pub async fn list_objects<S, M>(
    State(state): State<AppState<S, M>>,
    Path(bucket): Path<String>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
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

    let qs = query.unwrap_or_default();
    let params = parse_query_string(&qs);
    let prefix = params.get("prefix").map(|s| s.as_str());
    let max_keys: u32 = params
        .get("max-keys")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000)
        .min(1000);
    let continuation = params.get("continuation-token").map(|s| s.as_str());

    let result = state
        .meta
        .list_objects(&bucket, prefix, max_keys, continuation)
        .await
        .map_err(to_app)?;

    let entries: Vec<ferrox_s3_api::xml::ContentsEntry<'_>> = result
        .objects
        .iter()
        .map(|(key, rec)| ferrox_s3_api::xml::ContentsEntry {
            key: key.as_str(),
            last_modified: rec.last_modified,
            etag: rec.etag.as_str(),
            size: rec.size,
        })
        .collect();

    let xml = ferrox_s3_api::xml::list_bucket_v2(
        &bucket,
        prefix,
        &entries,
        result.is_truncated,
        result.next_continuation_token.as_deref(),
        continuation,
        max_keys,
    );

    let body = Body::new(Full::new(Bytes::from(xml)));
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .header("x-amz-request-id", &rid)
        .body(body)
        .map_err(|e| to_app(FerroxError::Internal(format!("response build: {e}"))))?;
    Ok(response)
}

/// `POST /{bucket}?delete` — batch delete up to 1 000 objects.
///
/// Parses the `<Delete>` XML body, attempts each deletion independently, and
/// returns `<DeleteResult>` with `<Deleted>` / `<Error>` child elements.
pub async fn delete_objects<S, M>(
    State(state): State<AppState<S, M>>,
    Path(bucket): Path<String>,
    rid: axum::extract::Extension<RequestId>,
    body: axum::body::Body,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    use axum::body::to_bytes;
    use ferrox_s3_api::xml::{delete_result, parse_delete_request};

    let resource = format!("/{bucket}");
    let rid = rid.0 .0;
    let to_app = |e: FerroxError| AppError::new(e, resource.clone(), rid.clone());

    validate_bucket_name(&bucket).map_err(to_app)?;

    let raw = to_bytes(body, 5 * 1024 * 1024)
        .await
        .map_err(|e| to_app(FerroxError::Internal(format!("body read: {e}"))))?;

    let keys = parse_delete_request(&raw)
        .map_err(|msg| to_app(FerroxError::InvalidRequest(format!("MalformedXML: {msg}"))))?;

    let mut deleted: Vec<String> = Vec::new();
    let mut errors: Vec<(String, String, String)> = Vec::new();

    for key in keys {
        let del_res = state.storage.delete(&bucket, &key).await;
        match del_res {
            Ok(()) => {
                let _ = state.meta.delete_object_meta(&bucket, &key).await;
                deleted.push(key);
            }
            Err(FerroxError::NotFound { .. }) => {
                // AWS reports non-existent keys as deleted.
                deleted.push(key);
            }
            Err(e) => {
                errors.push((key, "InternalError".into(), e.to_string()));
            }
        }
    }

    let del_refs: Vec<&str> = deleted.iter().map(String::as_str).collect();
    let err_refs: Vec<(&str, &str, &str)> = errors
        .iter()
        .map(|(k, c, m)| (k.as_str(), c.as_str(), m.as_str()))
        .collect();

    let xml = delete_result(&del_refs, &err_refs);
    let body = Body::new(Full::new(Bytes::from(xml)));
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .header("x-amz-request-id", &rid)
        .body(body)
        .map_err(|e| to_app(FerroxError::Internal(format!("response build: {e}"))))?;
    Ok(response)
}

/// `PUT /{bucket}?versioning` — set versioning configuration.
pub async fn put_bucket_versioning<S, M>(
    State(state): State<AppState<S, M>>,
    Path(bucket): Path<String>,
    rid: axum::extract::Extension<RequestId>,
    body: axum::body::Body,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    use axum::body::to_bytes;
    use ferrox_meta::types::VersioningState;
    use ferrox_s3_api::xml::parse_versioning_configuration;

    let resource = format!("/{bucket}");
    let rid = rid.0 .0;
    let to_app = |e: FerroxError| AppError::new(e, resource.clone(), rid.clone());

    validate_bucket_name(&bucket).map_err(to_app)?;

    let raw = to_bytes(body, 64 * 1024)
        .await
        .map_err(|e| to_app(FerroxError::Internal(format!("body read: {e}"))))?;
    let status = parse_versioning_configuration(&raw)
        .map_err(|msg| to_app(FerroxError::InvalidRequest(format!("MalformedXML: {msg}"))))?;

    let vs = match status.as_str() {
        "Enabled" => VersioningState::Enabled,
        "Suspended" => VersioningState::Suspended,
        other => {
            return Err(to_app(FerroxError::InvalidRequest(format!(
                "invalid versioning status: {other}"
            ))))
        }
    };
    state
        .meta
        .set_bucket_versioning(&bucket, vs)
        .await
        .map_err(to_app)?;

    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut()
        .insert("x-amz-request-id", rid_header(&rid));
    Ok(resp)
}

/// `GET /{bucket}?versioning` — get versioning configuration.
pub async fn get_bucket_versioning<S, M>(
    State(state): State<AppState<S, M>>,
    Path(bucket): Path<String>,
    rid: axum::extract::Extension<RequestId>,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    use ferrox_meta::types::VersioningState;
    use ferrox_s3_api::xml::versioning_configuration;

    let resource = format!("/{bucket}");
    let rid = rid.0 .0;
    let to_app = |e: FerroxError| AppError::new(e, resource.clone(), rid.clone());

    validate_bucket_name(&bucket).map_err(to_app)?;

    let meta = state.meta.get_bucket(&bucket).await.map_err(to_app)?;
    let status = match meta.versioning {
        VersioningState::Disabled => "",
        VersioningState::Enabled => "Enabled",
        VersioningState::Suspended => "Suspended",
    };

    let xml = versioning_configuration(status);
    let body = Body::new(Full::new(Bytes::from(xml)));
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .header("x-amz-request-id", &rid)
        .body(body)
        .map_err(|e| to_app(FerroxError::Internal(format!("response build: {e}"))))?;
    Ok(response)
}

/// Parse a URL query string into `(key, value)` pairs.
fn parse_query_string(qs: &str) -> std::collections::HashMap<String, String> {
    qs.split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let k = parts.next()?;
            let v = parts.next().unwrap_or("");
            if k.is_empty() {
                None
            } else {
                Some((url_decode(k), url_decode(v)))
            }
        })
        .collect()
}

/// Minimal percent-decoding for query string values (+→space, %xx).
fn url_decode(s: &str) -> String {
    let s = s.replace('+', " ");
    let mut out = String::with_capacity(s.len());
    let mut iter = s.chars().peekable();
    while let Some(c) = iter.next() {
        if c == '%' {
            let h1 = iter.next().unwrap_or('0');
            let h2 = iter.next().unwrap_or('0');
            let hex = format!("{h1}{h2}");
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                out.push(byte as char);
            } else {
                out.push('%');
                out.push(h1);
                out.push(h2);
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_query_string_basic() {
        let m = parse_query_string("prefix=foo&max-keys=10");
        assert_eq!(m.get("prefix").unwrap(), "foo");
        assert_eq!(m.get("max-keys").unwrap(), "10");
    }

    #[test]
    fn test_parse_query_string_empty() {
        let m = parse_query_string("");
        assert!(m.is_empty());
    }

    #[test]
    fn test_url_decode_plus_space() {
        assert_eq!(url_decode("hello+world"), "hello world");
    }

    #[test]
    fn test_url_decode_percent_hex() {
        assert_eq!(url_decode("foo%2Fbar"), "foo/bar");
    }
}
