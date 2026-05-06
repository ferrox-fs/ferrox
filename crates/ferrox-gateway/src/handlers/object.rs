//! Object-level S3 handlers: `PutObject`, `GetObject`, `HeadObject`, `CopyObject`.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::{Bytes, BytesMut};
use ferrox_error::FerroxError;
use ferrox_meta::{MetaStore, ObjectRecord};
use ferrox_s3_api::names::{validate_bucket_name, validate_object_key};
use ferrox_storage::StorageBackend;
use futures::TryStreamExt;
use http_body_util::Full;
use md5::Digest as _;
use time::OffsetDateTime;

use crate::error::AppError;
use crate::middleware::RequestId;
use crate::state::AppState;

/// `PUT /{bucket}/{*key}` — store an object.
///
/// When the `x-amz-copy-source` header is present, delegates to
/// [`copy_object_inner`] for a server-side copy without reading the request body.
/// When `x-amz-server-side-encryption: AES256` is present, encrypts the body
/// with AES-256-GCM (SSE-S3) before writing.
pub async fn put_object<S, M>(
    State(state): State<AppState<S, M>>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
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

    // CopyObject — detected by x-amz-copy-source header.
    if let Some(copy_src) = headers
        .get("x-amz-copy-source")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
    {
        let directive = headers
            .get("x-amz-metadata-directive")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("COPY")
            .to_string();
        return copy_object_inner(state, &bucket, &key, &copy_src, &directive, &rid).await;
    }

    if !state.storage.bucket_exists(&bucket).await.map_err(to_app)? {
        return Err(to_app(FerroxError::NotFound { bucket, key: None }));
    }

    // Content-Length is required by AWS — return 411 if missing.
    let size: u64 = match headers.get(header::CONTENT_LENGTH) {
        Some(v) => v
            .to_str()
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| to_app(FerroxError::InvalidRequest("invalid Content-Length".into())))?,
        None => {
            let mut resp = (StatusCode::LENGTH_REQUIRED, "Length Required").into_response();
            resp.headers_mut()
                .insert("x-amz-request-id", HeaderValue::from_str(&rid).unwrap());
            return Ok(resp);
        }
    };

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    let expected_md5_b64 = headers
        .get("content-md5")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let sse_requested = headers
        .get("x-amz-server-side-encryption")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("AES256"))
        .unwrap_or(false);

    let sse_c_alg = headers
        .get("x-amz-server-side-encryption-customer-algorithm")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Bucket default-encryption enforcement (Step 28).
    if !sse_requested && sse_c_alg.is_none() {
        if let Ok(bm) = state.meta.get_bucket(&bucket).await {
            if let Some(cfg) = bm.encryption {
                if cfg.enforced {
                    return Err(to_app(FerroxError::InvalidRequest(
                        "InvalidEncryptionAlgorithmError: bucket requires SSE".into(),
                    )));
                }
            }
        }
    }

    if let Some(alg) = sse_c_alg {
        if !alg.eq_ignore_ascii_case("AES256") {
            return Err(to_app(FerroxError::InvalidRequest(format!(
                "unsupported SSE-C algorithm: {alg}"
            ))));
        }
        return put_object_sse_c(
            state,
            &bucket,
            &key,
            &content_type,
            size,
            expected_md5_b64,
            &headers,
            body,
            &rid,
        )
        .await;
    }

    if sse_requested {
        return put_object_sse(
            state,
            &bucket,
            &key,
            &content_type,
            size,
            expected_md5_b64,
            body,
            &rid,
        )
        .await;
    }

    let stream = body
        .into_data_stream()
        .map_err(|e| FerroxError::Internal(format!("body stream: {e}")));
    let stream: ferrox_storage::ByteStream = Box::pin(stream.map_ok(|b| -> Bytes { b }));

    let put_res = state
        .storage
        .put(&bucket, &key, stream, size, &content_type)
        .await
        .map_err(to_app)?;

    if let Some(b64) = expected_md5_b64 {
        let hex_md5 = put_res.etag.trim_matches('"');
        let md5_bytes = hex::decode(hex_md5)
            .map_err(|_| FerroxError::Internal("etag is not hex".into()))
            .map_err(to_app)?;
        use base64::Engine;
        let computed = base64::engine::general_purpose::STANDARD.encode(&md5_bytes);
        if computed != b64 {
            let _ = state.storage.delete(&bucket, &key).await;
            return Err(to_app(FerroxError::ChecksumMismatch {
                expected: b64,
                got: computed,
            }));
        }
    }

    let record = ObjectRecord {
        etag: put_res.etag.clone(),
        size: put_res.size,
        content_type,
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

    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        HeaderName::from_static("etag"),
        HeaderValue::from_str(&put_res.etag)
            .map_err(|e| to_app(FerroxError::Internal(format!("etag header build: {e}"))))?,
    );
    resp.headers_mut()
        .insert("x-amz-request-id", HeaderValue::from_str(&rid).unwrap());
    Ok(resp)
}

/// Read SSE-C key headers; return `(CustomerKey, key_b64_for_response, md5_b64)`
/// or an error on missing/invalid headers.
fn parse_sse_c_headers(
    headers: &HeaderMap,
) -> Result<(ferrox_crypto::CustomerKey, String, String), FerroxError> {
    let key_b64 = headers
        .get("x-amz-server-side-encryption-customer-key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            FerroxError::InvalidRequest("missing x-amz-server-side-encryption-customer-key".into())
        })?
        .to_string();
    let md5_b64 = headers
        .get("x-amz-server-side-encryption-customer-key-MD5")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            FerroxError::InvalidRequest(
                "missing x-amz-server-side-encryption-customer-key-MD5".into(),
            )
        })?
        .to_string();
    let ck = ferrox_crypto::CustomerKey::from_headers(&key_b64, &md5_b64)?;
    Ok((ck, key_b64, md5_b64))
}

/// Inner handler for SSE-C PutObject. Buffers, encrypts under caller key,
/// stores ciphertext + key fingerprint (never the raw key).
#[allow(clippy::too_many_arguments)]
async fn put_object_sse_c<S, M>(
    state: AppState<S, M>,
    bucket: &str,
    key: &str,
    content_type: &str,
    declared_size: u64,
    expected_md5_b64: Option<String>,
    headers: &HeaderMap,
    body: Body,
    rid: &str,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    let resource = format!("/{bucket}/{key}");
    let to_app = |e: FerroxError| AppError::new(e, resource.clone(), rid.to_string());
    let (ck, _key_b64, md5_b64) = parse_sse_c_headers(headers).map_err(to_app)?;

    let plain_bytes: Bytes = body
        .into_data_stream()
        .map_err(|e| FerroxError::Internal(format!("body read: {e}")))
        .try_fold(BytesMut::new(), |mut acc, chunk| async move {
            acc.extend_from_slice(&chunk);
            Ok(acc)
        })
        .await
        .map_err(to_app)?
        .freeze();

    if plain_bytes.len() as u64 != declared_size {
        return Err(to_app(FerroxError::InvalidRequest(
            "Content-Length does not match body size".into(),
        )));
    }

    let etag = format!("\"{}\"", hex::encode(md5::Md5::digest(&plain_bytes)));
    let sha256 = hex::encode(sha2::Sha256::digest(&plain_bytes));
    let crc32c_val = hex::encode(crc32c::crc32c(&plain_bytes).to_le_bytes());

    if let Some(b64) = expected_md5_b64 {
        let hex_md5 = etag.trim_matches('"');
        let md5_bytes = hex::decode(hex_md5).unwrap_or_default();
        use base64::Engine;
        let computed = base64::engine::general_purpose::STANDARD.encode(&md5_bytes);
        if computed != b64 {
            return Err(to_app(FerroxError::ChecksumMismatch {
                expected: b64,
                got: computed,
            }));
        }
    }

    let ciphertext = ferrox_crypto::sse_c::encrypt(&ck, &plain_bytes).map_err(to_app)?;
    let ct_len = ciphertext.len() as u64;
    let fingerprint = ck.fingerprint();
    drop(ck); // zeroes immediately

    let ct_bytes = Bytes::from(ciphertext);
    let ct_stream: ferrox_storage::ByteStream = Box::pin(futures::stream::once(async move {
        Ok::<Bytes, FerroxError>(ct_bytes)
    }));
    let put_res = state
        .storage
        .put(bucket, key, ct_stream, ct_len, content_type)
        .await
        .map_err(to_app)?;

    let record = ObjectRecord {
        etag: etag.clone(),
        size: declared_size,
        content_type: content_type.to_string(),
        last_modified: put_res.last_modified,
        sha256,
        crc32c: crc32c_val,
        version_id: None,
        sse_algorithm: Some("AES256-C".into()),
        sse_key_encrypted: None,
        sse_c_key_hmac: Some(fingerprint),
        tags: Default::default(),
    };
    state
        .meta
        .put_object_meta(bucket, key, record)
        .await
        .map_err(to_app)?;

    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        HeaderName::from_static("etag"),
        HeaderValue::from_str(&etag).unwrap(),
    );
    resp.headers_mut().insert(
        HeaderName::from_static("x-amz-server-side-encryption-customer-algorithm"),
        HeaderValue::from_static("AES256"),
    );
    resp.headers_mut().insert(
        HeaderName::from_static("x-amz-server-side-encryption-customer-key-md5"),
        HeaderValue::from_str(&md5_b64).unwrap(),
    );
    resp.headers_mut()
        .insert("x-amz-request-id", HeaderValue::from_str(rid).unwrap());
    Ok(resp)
}

/// Inner handler for SSE-S3 `PutObject`. Buffers the body, encrypts it, stores
/// the ciphertext, and records plaintext checksums in the meta store.
#[allow(clippy::too_many_arguments)]
async fn put_object_sse<S, M>(
    state: AppState<S, M>,
    bucket: &str,
    key: &str,
    content_type: &str,
    declared_size: u64,
    expected_md5_b64: Option<String>,
    body: Body,
    rid: &str,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    let resource = format!("/{bucket}/{key}");
    let to_app = |e: FerroxError| AppError::new(e, resource.clone(), rid.to_string());

    let kek = state
        .config
        .sse_master_key
        .as_ref()
        .ok_or_else(|| {
            to_app(FerroxError::InvalidRequest(
                "SSE-S3 is not configured on this server (no master key)".into(),
            ))
        })?
        .clone();

    // Buffer the full plaintext body.
    let plain_bytes: Bytes = body
        .into_data_stream()
        .map_err(|e| FerroxError::Internal(format!("body read: {e}")))
        .try_fold(BytesMut::new(), |mut acc, chunk| async move {
            acc.extend_from_slice(&chunk);
            Ok(acc)
        })
        .await
        .map_err(to_app)?
        .freeze();

    if plain_bytes.len() as u64 != declared_size {
        return Err(to_app(FerroxError::InvalidRequest(
            "Content-Length does not match body size".into(),
        )));
    }

    // Compute plaintext checksums.
    let etag = format!("\"{}\"", hex::encode(md5::Md5::digest(&plain_bytes)));
    let sha256 = hex::encode(sha2::Sha256::digest(&plain_bytes));
    let crc32c_val = hex::encode(crc32c::crc32c(&plain_bytes).to_le_bytes());

    // Verify Content-MD5 if supplied.
    if let Some(b64) = expected_md5_b64 {
        let hex_md5 = etag.trim_matches('"');
        let md5_bytes = hex::decode(hex_md5).unwrap_or_default();
        use base64::Engine;
        let computed = base64::engine::general_purpose::STANDARD.encode(&md5_bytes);
        if computed != b64 {
            return Err(to_app(FerroxError::ChecksumMismatch {
                expected: b64,
                got: computed,
            }));
        }
    }

    // Encrypt.
    let (ciphertext, dek_hex) = ferrox_crypto::encrypt(&kek, &plain_bytes).map_err(to_app)?;
    let ct_len = ciphertext.len() as u64;

    // Store ciphertext.
    let ct_bytes = Bytes::from(ciphertext);
    let ct_stream: ferrox_storage::ByteStream = Box::pin(futures::stream::once(async move {
        Ok::<Bytes, FerroxError>(ct_bytes)
    }));
    let put_res = state
        .storage
        .put(bucket, key, ct_stream, ct_len, content_type)
        .await
        .map_err(to_app)?;

    // Store plaintext-based metadata (not ciphertext checksums).
    let record = ObjectRecord {
        etag: etag.clone(),
        size: declared_size,
        content_type: content_type.to_string(),
        last_modified: put_res.last_modified,
        sha256,
        crc32c: crc32c_val,
        version_id: None,
        sse_algorithm: Some("AES256".into()),
        sse_key_encrypted: Some(dek_hex),
        sse_c_key_hmac: None,
        tags: Default::default(),
    };
    state
        .meta
        .put_object_meta(bucket, key, record)
        .await
        .map_err(to_app)?;

    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        HeaderName::from_static("etag"),
        HeaderValue::from_str(&etag)
            .map_err(|e| to_app(FerroxError::Internal(format!("etag header: {e}"))))?,
    );
    resp.headers_mut().insert(
        HeaderName::from_static("x-amz-server-side-encryption"),
        HeaderValue::from_static("AES256"),
    );
    resp.headers_mut()
        .insert("x-amz-request-id", HeaderValue::from_str(rid).unwrap());
    Ok(resp)
}

/// `GET /{bucket}/{*key}` — retrieve an object, with optional `Range` support.
///
/// Transparent SSE-S3 decryption: if the object was stored with
/// `x-amz-server-side-encryption: AES256`, the gateway decrypts it before
/// streaming.
pub async fn get_object<S, M>(
    State(state): State<AppState<S, M>>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
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

    let range_hdr = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Meta store is the authoritative source for size/checksums (handles SSE).
    let record = state
        .meta
        .get_object_meta(&bucket, &key)
        .await
        .map_err(to_app)?;
    let result = state.storage.get(&bucket, &key).await.map_err(to_app)?;

    let mut resp = Response::builder()
        .header("etag", &record.etag)
        .header(header::CONTENT_TYPE, &record.content_type)
        .header("last-modified", imf_fixdate(record.last_modified))
        .header("x-amz-request-id", &rid);

    // Whole-object checksums must be omitted on Range responses — they describe
    // the full object, not the returned slice, and the SDK rejects mismatches.
    if range_hdr.is_none() {
        resp = resp
            .header("x-amz-checksum-sha256", hex_to_b64(&record.sha256))
            .header("x-amz-checksum-crc32c", &record.crc32c);
    }

    if record.sse_algorithm.as_deref() == Some("AES256") {
        resp = resp.header("x-amz-server-side-encryption", "AES256");
    }

    // SSE-C verification: must present the same key (verified by HMAC fingerprint).
    let is_sse_c = record.sse_algorithm.as_deref() == Some("AES256-C");
    let mut sse_c_key: Option<ferrox_crypto::CustomerKey> = None;
    if is_sse_c {
        let (ck, _kb64, md5_b64) = parse_sse_c_headers(&headers).map_err(to_app)?;
        let stored = record.sse_c_key_hmac.as_deref().ok_or_else(|| {
            to_app(FerroxError::Internal(
                "SSE-C object missing fingerprint".into(),
            ))
        })?;
        if ck.fingerprint() != stored {
            return Err(to_app(FerroxError::AuthFailed(
                "SSE-C key does not match the key used to encrypt the object".into(),
            )));
        }
        sse_c_key = Some(ck);
        resp = resp
            .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
            .header("x-amz-server-side-encryption-customer-key-md5", md5_b64);
    }

    let total = record.size;
    let is_sse = record.sse_algorithm.as_deref() == Some("AES256");

    // For SSE-* or Range requests, buffer the raw storage bytes first.
    if is_sse || is_sse_c || range_hdr.is_some() {
        let raw: Bytes = result
            .stream
            .try_fold(BytesMut::new(), |mut acc, chunk| async move {
                acc.extend_from_slice(&chunk);
                Ok(acc)
            })
            .await
            .map_err(to_app)?
            .freeze();

        let plain: Bytes = if is_sse {
            let dek_hex = record.sse_key_encrypted.as_deref().ok_or_else(|| {
                to_app(FerroxError::Internal(
                    "SSE object missing encrypted DEK".into(),
                ))
            })?;
            let kek = state
                .config
                .sse_master_key
                .as_ref()
                .ok_or_else(|| {
                    to_app(FerroxError::Internal(
                        "SSE master key not configured".into(),
                    ))
                })?
                .clone();
            Bytes::from(ferrox_crypto::decrypt(&kek, &raw, dek_hex).map_err(to_app)?)
        } else if is_sse_c {
            let ck = sse_c_key
                .as_ref()
                .ok_or_else(|| to_app(FerroxError::Internal("SSE-C key missing".into())))?;
            Bytes::from(ferrox_crypto::sse_c::decrypt(ck, &raw).map_err(to_app)?)
        } else {
            raw
        };

        if let Some(range_str) = range_hdr {
            let range = parse_range(&range_str, total)
                .map_err(|msg| to_app(FerroxError::InvalidRequest(msg)))?;
            let end_inclusive = range.1.min(total.saturating_sub(1));
            let slice = plain.slice(range.0 as usize..=end_inclusive as usize);
            let content_length = slice.len();
            let response = resp
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_LENGTH, content_length.to_string())
                .header(
                    header::CONTENT_RANGE,
                    format!("bytes {}-{}/{}", range.0, end_inclusive, total),
                )
                .body(Body::new(Full::new(slice)))
                .map_err(|e| to_app(FerroxError::Internal(format!("response build: {e}"))))?;
            return Ok(response);
        }

        let response = resp
            .status(StatusCode::OK)
            .header(header::CONTENT_LENGTH, plain.len().to_string())
            .body(Body::new(Full::new(plain)))
            .map_err(|e| to_app(FerroxError::Internal(format!("response build: {e}"))))?;
        return Ok(response);
    }

    // Plain streaming GET (no SSE, no Range).
    let body = Body::from_stream(
        result
            .stream
            .map_err(|e| std::io::Error::other(e.to_string())),
    );
    let response = resp
        .status(StatusCode::OK)
        .header(header::CONTENT_LENGTH, total.to_string())
        .body(body)
        .map_err(|e| to_app(FerroxError::Internal(format!("response build: {e}"))))?;
    Ok(response)
}

/// `HEAD /{bucket}/{*key}` — return object metadata with no body.
pub async fn head_object<S, M>(
    State(state): State<AppState<S, M>>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
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

    // Use meta store as authority (gives plaintext size/checksums for SSE objects).
    let record = state
        .meta
        .get_object_meta(&bucket, &key)
        .await
        .map_err(to_app)?;

    // SSE-C: 403 if wrong key (per AWS), 400 if missing key headers.
    let is_sse_c = record.sse_algorithm.as_deref() == Some("AES256-C");
    if is_sse_c {
        let (ck, _, _md5) = parse_sse_c_headers(&headers).map_err(to_app)?;
        let stored = record.sse_c_key_hmac.as_deref().ok_or_else(|| {
            to_app(FerroxError::Internal(
                "SSE-C object missing fingerprint".into(),
            ))
        })?;
        if ck.fingerprint() != stored {
            return Err(to_app(FerroxError::AuthFailed(
                "SSE-C key does not match".into(),
            )));
        }
    }

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("etag", &record.etag)
        .header(header::CONTENT_TYPE, &record.content_type)
        .header(header::CONTENT_LENGTH, record.size.to_string())
        .header("last-modified", imf_fixdate(record.last_modified))
        .header("x-amz-request-id", &rid)
        .header("x-amz-checksum-sha256", hex_to_b64(&record.sha256))
        .header("x-amz-checksum-crc32c", &record.crc32c);

    if record.sse_algorithm.as_deref() == Some("AES256") {
        builder = builder.header("x-amz-server-side-encryption", "AES256");
    }
    if is_sse_c {
        builder = builder.header("x-amz-server-side-encryption-customer-algorithm", "AES256");
    }

    let response = builder
        .body(Body::empty())
        .map_err(|e| to_app(FerroxError::Internal(format!("response build: {e}"))))?;
    Ok(response)
}

/// Parse an HTTP `Range: bytes=<start>-[<end>]` header.
/// Returns `(start, end_inclusive)` where `end` defaults to `total - 1`.
/// Returns `Err` with a human-readable message on invalid syntax.
fn parse_range(range: &str, total: u64) -> Result<(u64, u64), String> {
    let s = range
        .strip_prefix("bytes=")
        .ok_or("Range must start with 'bytes='")?;

    if let Some(suffix_len) = s.strip_prefix('-') {
        let n: u64 = suffix_len
            .parse()
            .map_err(|_| "invalid suffix-length in Range")?;
        let start = total.saturating_sub(n);
        return Ok((start, total.saturating_sub(1)));
    }

    let (start_s, end_s) = s.split_once('-').ok_or("Range missing '-' separator")?;
    let start: u64 = start_s.parse().map_err(|_| "invalid start in Range")?;
    let end: u64 = if end_s.is_empty() {
        total.saturating_sub(1)
    } else {
        end_s.parse().map_err(|_| "invalid end in Range")?
    };

    if start > end || start >= total {
        return Err(format!(
            "Range {start}-{end} is not satisfiable for size {total}"
        ));
    }
    Ok((start, end))
}

/// Inner logic for server-side copy (`x-amz-copy-source` present on a PUT).
///
/// `copy_src` has the form `/{bucket}/{key}` or `{bucket}/{key}`.
/// SSE metadata is propagated from the source to the destination.
async fn copy_object_inner<S, M>(
    state: AppState<S, M>,
    dest_bucket: &str,
    dest_key: &str,
    copy_src: &str,
    _directive: &str,
    rid: &str,
) -> Result<Response, AppError>
where
    S: StorageBackend,
    M: MetaStore,
{
    let resource = format!("/{dest_bucket}/{dest_key}");
    let to_app = |e: FerroxError| AppError::new(e, resource.clone(), rid.to_string());

    let src = copy_src.trim_start_matches('/');
    let (src_bucket, src_key) = src.split_once('/').ok_or_else(|| {
        to_app(FerroxError::InvalidRequest(
            "invalid x-amz-copy-source".into(),
        ))
    })?;

    validate_bucket_name(src_bucket).map_err(to_app)?;
    validate_object_key(src_key).map_err(to_app)?;
    validate_bucket_name(dest_bucket).map_err(to_app)?;
    validate_object_key(dest_key).map_err(to_app)?;

    let put_res = state
        .storage
        .copy_object(src_bucket, src_key, dest_bucket, dest_key)
        .await
        .map_err(to_app)?;

    let src_meta = state
        .meta
        .get_object_meta(src_bucket, src_key)
        .await
        .map_err(to_app)?;

    let record = ObjectRecord {
        etag: src_meta.etag.clone(),
        size: src_meta.size,
        content_type: src_meta.content_type,
        last_modified: put_res.last_modified,
        sha256: src_meta.sha256,
        crc32c: src_meta.crc32c,
        version_id: None,
        sse_algorithm: src_meta.sse_algorithm,
        sse_key_encrypted: src_meta.sse_key_encrypted,
        sse_c_key_hmac: src_meta.sse_c_key_hmac,
        tags: src_meta.tags,
    };
    state
        .meta
        .put_object_meta(dest_bucket, dest_key, record)
        .await
        .map_err(to_app)?;

    let xml = ferrox_s3_api::xml::copy_object_result(&src_meta.etag, put_res.last_modified);
    let body = Body::new(Full::new(Bytes::from(xml)));
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .header("x-amz-request-id", rid)
        .body(body)
        .map_err(|e| to_app(FerroxError::Internal(format!("response build: {e}"))))?;
    Ok(response)
}

/// Convert a lower-case hex SHA-256 digest to standard-padded base64 for the
/// `x-amz-checksum-sha256` header (AWS spec: base64, not hex).
pub(crate) fn hex_to_b64(hex_str: &str) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    match hex::decode(hex_str) {
        Ok(bytes) => STANDARD.encode(bytes),
        Err(_) => hex_str.to_string(),
    }
}

/// Format a `Last-Modified` header value as RFC 7231 IMF-fixdate.
///
/// Example: `Sun, 06 Nov 1994 08:49:37 GMT`. AWS SDKs require this exact form
/// — Rfc2822's `+0000` zone is rejected by the JS SDK's HttpDate parser.
pub(crate) fn imf_fixdate(t: OffsetDateTime) -> String {
    let utc = t.to_offset(time::UtcOffset::UTC);
    let weekday = match utc.weekday() {
        time::Weekday::Monday => "Mon",
        time::Weekday::Tuesday => "Tue",
        time::Weekday::Wednesday => "Wed",
        time::Weekday::Thursday => "Thu",
        time::Weekday::Friday => "Fri",
        time::Weekday::Saturday => "Sat",
        time::Weekday::Sunday => "Sun",
    };
    let month = match utc.month() {
        time::Month::January => "Jan",
        time::Month::February => "Feb",
        time::Month::March => "Mar",
        time::Month::April => "Apr",
        time::Month::May => "May",
        time::Month::June => "Jun",
        time::Month::July => "Jul",
        time::Month::August => "Aug",
        time::Month::September => "Sep",
        time::Month::October => "Oct",
        time::Month::November => "Nov",
        time::Month::December => "Dec",
    };
    format!(
        "{weekday}, {day:02} {month} {year:04} {hour:02}:{minute:02}:{second:02} GMT",
        day = utc.day(),
        year = utc.year(),
        hour = utc.hour(),
        minute = utc.minute(),
        second = utc.second(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_range_explicit_start_end() {
        assert_eq!(parse_range("bytes=0-499", 1000), Ok((0, 499)));
    }

    #[test]
    fn test_parse_range_open_end() {
        assert_eq!(parse_range("bytes=500-", 1000), Ok((500, 999)));
    }

    #[test]
    fn test_parse_range_suffix_length() {
        assert_eq!(parse_range("bytes=-500", 1000), Ok((500, 999)));
    }

    #[test]
    fn test_parse_range_invalid_returns_err() {
        assert!(parse_range("invalid", 1000).is_err());
    }

    #[test]
    fn test_parse_range_out_of_bounds_returns_err() {
        assert!(parse_range("bytes=1000-1500", 1000).is_err());
    }

    #[test]
    fn test_parse_range_start_greater_than_end_returns_err() {
        assert!(parse_range("bytes=500-100", 1000).is_err());
    }
}
