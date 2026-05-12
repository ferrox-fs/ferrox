//! Multipart upload handlers (Step 17):
//! `InitiateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`,
//! `AbortMultipartUpload`.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use bytes::Bytes;
use ferrox_error::FerroxError;
use ferrox_meta::{MetaStore, MultipartMeta, ObjectRecord};
use ferrox_s3_api::names::{validate_bucket_name, validate_object_key};
use ferrox_storage::StorageBackend;
use futures::TryStreamExt;
use http_body_util::Full;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::AppError;
use crate::middleware::{rid_header, RequestId};
use crate::state::AppState;

/// AWS S3 multipart constraints (single source of truth — referenced by
/// `upload_part` and `complete_multipart_upload`).
mod limits {
    /// Smallest non-final part. 5 MiB.
    pub const MIN_PART_BYTES: u64 = 5 * 1024 * 1024;
    /// Largest single part. 5 GiB.
    pub const MAX_PART_BYTES: u64 = 5 * 1024 * 1024 * 1024;
    /// Largest completed multipart object. 5 TiB.
    pub const MAX_OBJECT_BYTES: u64 = 5 * 1024 * 1024 * 1024 * 1024;
    /// Maximum part number (and therefore parts per upload).
    pub const MAX_PART_NUMBER: u32 = 10_000;
}

/// `POST /{bucket}/{*key}?uploads` — initiate a multipart upload.
pub async fn initiate_multipart_upload<S, M>(
    State(state): State<AppState<S, M>>,
    Path((bucket, key)): Path<(String, String)>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    headers: axum::http::HeaderMap,
    rid: axum::extract::Extension<RequestId>,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    let resource = format!("/{bucket}/{key}");
    let rid = rid.0 .0;
    let to_app = |e: FerroxError| AppError::new(e, resource.clone(), rid.clone());

    // Only trigger on ?uploads query param.
    if !query.as_deref().unwrap_or("").contains("uploads") {
        return Err(to_app(FerroxError::InvalidRequest(
            "missing ?uploads parameter".into(),
        )));
    }

    validate_bucket_name(&bucket).map_err(to_app)?;
    validate_object_key(&key).map_err(to_app)?;

    if !state.storage.bucket_exists(&bucket).await.map_err(to_app)? {
        return Err(to_app(FerroxError::NotFound {
            bucket: bucket.clone(),
            key: None,
        }));
    }

    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    let upload_id = Uuid::new_v4().simple().to_string();
    let meta = MultipartMeta {
        bucket: bucket.clone(),
        key: key.clone(),
        content_type,
        initiated: OffsetDateTime::now_utc(),
    };
    state
        .meta
        .create_multipart_upload(&upload_id, meta)
        .await
        .map_err(to_app)?;

    let xml = ferrox_s3_api::xml::initiate_multipart_upload_result(&bucket, &key, &upload_id);
    let body = Body::new(Full::new(Bytes::from(xml)));
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .header("x-amz-request-id", &rid)
        .body(body)
        .map_err(|e| to_app(FerroxError::Internal(format!("response build: {e}"))))?;
    Ok(response)
}

/// `PUT /{bucket}/{*key}?partNumber=N&uploadId=X` — upload one part.
pub async fn upload_part<S, M>(
    State(state): State<AppState<S, M>>,
    Path((bucket, key)): Path<(String, String)>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    headers: axum::http::HeaderMap,
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

    let qs = query.unwrap_or_default();
    let params = parse_qs(&qs);
    let upload_id = params
        .get("uploadId")
        .cloned()
        .ok_or_else(|| to_app(FerroxError::InvalidRequest("missing uploadId".into())))?;
    let part_number: u32 = params
        .get("partNumber")
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| to_app(FerroxError::InvalidRequest("invalid partNumber".into())))?;

    if !(1..=limits::MAX_PART_NUMBER).contains(&part_number) {
        return Err(to_app(FerroxError::InvalidRequest(format!(
            "partNumber must be 1-{}",
            limits::MAX_PART_NUMBER
        ))));
    }

    // Verify upload exists.
    state
        .meta
        .get_multipart_upload(&upload_id)
        .await
        .map_err(to_app)?;

    let size: u64 = headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // S3 caps a single part at 5 GiB. Reject before streaming so the client
    // sees the failure immediately rather than after a long upload.
    if size > limits::MAX_PART_BYTES {
        return Err(to_app(FerroxError::EntityTooLarge(format!(
            "part exceeds maximum size of {} bytes",
            limits::MAX_PART_BYTES
        ))));
    }

    let stream = body
        .into_data_stream()
        .map_err(|e| FerroxError::Internal(format!("body: {e}")));
    let stream: ferrox_storage::ByteStream = Box::pin(stream.map_ok(|b| -> Bytes { b }));

    let etag = state
        .storage
        .write_part(&upload_id, part_number, stream, size)
        .await
        .map_err(to_app)?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("etag", &etag)
        .header("x-amz-request-id", &rid)
        .body(Body::empty())
        .map_err(|e| to_app(FerroxError::Internal(format!("response build: {e}"))))?;
    Ok(response)
}

/// `POST /{bucket}/{*key}?uploadId=X` — complete a multipart upload.
pub async fn complete_multipart_upload<S, M>(
    State(state): State<AppState<S, M>>,
    Path((bucket, key)): Path<(String, String)>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    rid: axum::extract::Extension<RequestId>,
    body: Body,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    use axum::body::to_bytes;

    let resource = format!("/{bucket}/{key}");
    let rid = rid.0 .0;
    let to_app = |e: FerroxError| AppError::new(e, resource.clone(), rid.clone());

    let qs = query.unwrap_or_default();
    let params = parse_qs(&qs);
    let upload_id = params
        .get("uploadId")
        .cloned()
        .ok_or_else(|| to_app(FerroxError::InvalidRequest("missing uploadId".into())))?;

    let upload_meta = state
        .meta
        .get_multipart_upload(&upload_id)
        .await
        .map_err(to_app)?;

    let raw = to_bytes(body, 5 * 1024 * 1024)
        .await
        .map_err(|e| to_app(FerroxError::Internal(format!("body read: {e}"))))?;
    let parts = ferrox_s3_api::xml::parse_complete_multipart(&raw)
        .map_err(|msg| to_app(FerroxError::InvalidRequest(format!("MalformedXML: {msg}"))))?;

    // Verify parts are in ascending order, with valid part numbers.
    for w in parts.windows(2) {
        if w[0].0 >= w[1].0 {
            return Err(to_app(FerroxError::InvalidRequest(
                "parts must be in ascending order".into(),
            )));
        }
    }
    if parts.is_empty() {
        return Err(to_app(FerroxError::InvalidRequest(
            "CompleteMultipartUpload requires at least one part".into(),
        )));
    }
    if let Some(&(n, _)) = parts
        .iter()
        .find(|&&(n, _)| !(1..=limits::MAX_PART_NUMBER).contains(&n))
    {
        return Err(to_app(FerroxError::InvalidRequest(format!(
            "invalid partNumber {n}: must be 1-{}",
            limits::MAX_PART_NUMBER
        ))));
    }

    // Walk the staged parts to enforce S3 size constraints. Every part except
    // the LAST must be at least 5 MiB; total must not exceed 5 TiB.
    let staged = state.storage.list_parts(&upload_id).await.map_err(to_app)?;
    let staged_by_number: std::collections::HashMap<u32, u64> =
        staged.iter().map(|(n, sz, _, _)| (*n, *sz)).collect();
    let mut total: u64 = 0;
    for (i, (part_no, _etag)) in parts.iter().enumerate() {
        let size = *staged_by_number.get(part_no).ok_or_else(|| {
            to_app(FerroxError::InvalidRequest(format!(
                "part {part_no} listed in CompleteMultipartUpload was never uploaded"
            )))
        })?;
        let is_last = i + 1 == parts.len();
        if !is_last && size < limits::MIN_PART_BYTES {
            return Err(to_app(FerroxError::EntityTooSmall(format!(
                "part {part_no} is {size} bytes; non-final parts must be at least {} bytes",
                limits::MIN_PART_BYTES
            ))));
        }
        // Per-part max already enforced at upload time; re-check here in case
        // an older client predates that gate.
        if size > limits::MAX_PART_BYTES {
            return Err(to_app(FerroxError::EntityTooLarge(format!(
                "part {part_no} is {size} bytes; max is {}",
                limits::MAX_PART_BYTES
            ))));
        }
        total = total.saturating_add(size);
        if total > limits::MAX_OBJECT_BYTES {
            return Err(to_app(FerroxError::EntityTooLarge(format!(
                "completed object would exceed max size of {} bytes",
                limits::MAX_OBJECT_BYTES
            ))));
        }
    }

    let put_res = state
        .storage
        .complete_multipart(&bucket, &key, &upload_id, &parts, &upload_meta.content_type)
        .await
        .map_err(to_app)?;

    let record = ObjectRecord {
        etag: put_res.etag.clone(),
        size: put_res.size,
        content_type: upload_meta.content_type,
        last_modified: put_res.last_modified,
        sha256: put_res.sha256,
        crc32c: put_res.crc32c,
        version_id: None,
        sse_algorithm: None,
        sse_key_encrypted: None,
        sse_c_key_hmac: None,
        tags: Default::default(),
    };
    state
        .meta
        .put_object_meta(&bucket, &key, record)
        .await
        .map_err(to_app)?;
    state
        .meta
        .delete_multipart_upload(&upload_id)
        .await
        .map_err(to_app)?;

    let location = format!("http://localhost/{bucket}/{key}");
    let xml = ferrox_s3_api::xml::complete_multipart_upload_result(
        &bucket,
        &key,
        &location,
        &put_res.etag,
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

/// `DELETE /{bucket}/{*key}?uploadId=X` — abort a multipart upload.
pub async fn abort_multipart_upload<S, M>(
    State(state): State<AppState<S, M>>,
    Path((bucket, key)): Path<(String, String)>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    rid: axum::extract::Extension<RequestId>,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    let resource = format!("/{bucket}/{key}");
    let rid = rid.0 .0;
    let to_app = |e: FerroxError| AppError::new(e, resource.clone(), rid.clone());

    let qs = query.unwrap_or_default();
    let params = parse_qs(&qs);
    let upload_id = params
        .get("uploadId")
        .cloned()
        .ok_or_else(|| to_app(FerroxError::InvalidRequest("missing uploadId".into())))?;

    state
        .storage
        .abort_multipart(&upload_id)
        .await
        .map_err(to_app)?;
    let _ = state.meta.delete_multipart_upload(&upload_id).await;

    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::NO_CONTENT;
    resp.headers_mut()
        .insert("x-amz-request-id", rid_header(&rid));
    Ok(resp)
}

/// `GET /{bucket}?uploads` — list all in-progress multipart uploads for the bucket.
pub async fn list_multipart_uploads<S, M>(
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
    if !state.storage.bucket_exists(&bucket).await.map_err(to_app)? {
        return Err(to_app(FerroxError::NotFound {
            bucket: bucket.clone(),
            key: None,
        }));
    }

    let uploads = state
        .meta
        .list_multipart_uploads(&bucket)
        .await
        .map_err(to_app)?;

    let entries: Vec<ferrox_s3_api::xml::UploadEntry<'_>> = uploads
        .iter()
        .map(|(id, m)| ferrox_s3_api::xml::UploadEntry {
            key: &m.key,
            upload_id: id,
            initiated: m.initiated,
        })
        .collect();

    let xml = ferrox_s3_api::xml::list_multipart_uploads_result(&bucket, &entries);
    let body = Body::new(Full::new(Bytes::from(xml)));
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .header("x-amz-request-id", &rid)
        .body(body)
        .map_err(|e| to_app(FerroxError::Internal(format!("response build: {e}"))))?;
    Ok(response)
}

/// `GET /{bucket}/{*key}?uploadId=X` — list parts for an in-progress multipart upload.
pub async fn list_parts<S, M>(
    State(state): State<AppState<S, M>>,
    Path((bucket, key)): Path<(String, String)>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    rid: axum::extract::Extension<RequestId>,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    let resource = format!("/{bucket}/{key}");
    let rid = rid.0 .0;
    let to_app = |e: FerroxError| AppError::new(e, resource.clone(), rid.clone());

    let qs = query.unwrap_or_default();
    let params = parse_qs(&qs);
    let upload_id = params
        .get("uploadId")
        .cloned()
        .ok_or_else(|| to_app(FerroxError::InvalidRequest("missing uploadId".into())))?;

    // Verify the upload exists in meta.
    state
        .meta
        .get_multipart_upload(&upload_id)
        .await
        .map_err(to_app)?;

    let raw_parts = state.storage.list_parts(&upload_id).await.map_err(to_app)?;

    let entries: Vec<ferrox_s3_api::xml::PartEntry> = raw_parts
        .into_iter()
        .map(
            |(part_number, size, etag, last_modified)| ferrox_s3_api::xml::PartEntry {
                part_number,
                size,
                etag,
                last_modified,
            },
        )
        .collect();

    let xml = ferrox_s3_api::xml::list_parts_result(&bucket, &key, &upload_id, &entries);
    let body = Body::new(Full::new(Bytes::from(xml)));
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .header("x-amz-request-id", &rid)
        .body(body)
        .map_err(|e| to_app(FerroxError::Internal(format!("response build: {e}"))))?;
    Ok(response)
}

fn parse_qs(qs: &str) -> std::collections::HashMap<String, String> {
    qs.split('&')
        .filter_map(|pair| {
            let mut it = pair.splitn(2, '=');
            let k = it.next()?;
            let v = it.next().unwrap_or("");
            if k.is_empty() {
                None
            } else {
                Some((k.to_string(), v.to_string()))
            }
        })
        .collect()
}
