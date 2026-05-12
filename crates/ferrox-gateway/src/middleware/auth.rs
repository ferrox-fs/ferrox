//! SigV4 authentication middleware (Step 10).
//!
//! - Extracts the SigV4 credentials from either the `Authorization` header
//!   OR the query string (pre-signed URL — Phase 1 Step 19 also routes here).
//! - Looks up the secret bound to the access key (Phase 0: single key from
//!   [`AuthConfig`]; Phase 1+: from the IAM crate).
//! - Recomputes the canonical request and runs
//!   [`verify_sigv4`] in constant time.
//! - On failure: returns HTTP 403 with a SigV4 `<Error>` XML envelope.
//!
//! Health endpoints (`/health/live`, `/health/ready`, `/health/version`)
//! bypass auth entirely (Step 10 spec).

use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use bytes::Bytes;
use ferrox_error::FerroxError;
use futures::future::BoxFuture;
use http_body_util::Full;
use tower::{Layer, Service};

use sha2::{Digest, Sha256};

use crate::auth::{
    parse_sigv4a_query, verify_presigned_sigv4a, verify_presigned_url, verify_sigv4, verify_sigv4a,
    SigV4AHeader, SigV4Header,
};
use crate::middleware::RequestId;
use crate::ratelimit::PerKeyRateLimiter;

/// Maximum body size we will buffer for `x-amz-content-sha256` verification.
/// Matches S3's 5 GiB single-PUT cap; larger uploads must use multipart, where
/// each part is bounded by the same limit.
const MAX_VERIFY_BODY_BYTES: usize = 5 * 1024 * 1024 * 1024;

/// SigV4 algorithm prefix, as it appears in the `Authorization` header.
const SIGV4_ALGO: &str = "AWS4-HMAC-SHA256";
/// SigV4A algorithm prefix.
const SIGV4A_ALGO: &str = "AWS4-ECDSA-P256-SHA256";

/// Configuration shared by every auth invocation.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Single access key recognized in Phase 0.
    pub access_key: String,
    /// Secret bound to `access_key`.
    pub secret_key: String,
    /// Allowed clock skew in seconds.
    pub clock_skew_secs: i64,
    /// AWS region this gateway represents. Used by both SigV4 (scope match)
    /// and SigV4A (region-set match).
    pub region: String,
}

/// Layer that constructs [`SigV4AuthMiddleware`].
#[derive(Debug, Clone)]
pub struct SigV4AuthLayer {
    inner: Arc<AuthConfig>,
    rate_limiter: Option<PerKeyRateLimiter>,
}

impl SigV4AuthLayer {
    /// Build a new layer using the provided [`AuthConfig`].
    pub fn new(cfg: AuthConfig) -> Self {
        Self {
            inner: Arc::new(cfg),
            rate_limiter: None,
        }
    }

    /// Attach a per-access-key rate limiter to this layer.
    pub fn with_rate_limiter(mut self, rl: Option<PerKeyRateLimiter>) -> Self {
        self.rate_limiter = rl;
        self
    }
}

impl<S> Layer<S> for SigV4AuthLayer {
    type Service = SigV4AuthMiddleware<S>;
    fn layer(&self, inner: S) -> Self::Service {
        SigV4AuthMiddleware {
            inner,
            cfg: Arc::clone(&self.inner),
            rate_limiter: self.rate_limiter.clone(),
        }
    }
}

/// Tower service performing SigV4 verification.
#[derive(Debug, Clone)]
pub struct SigV4AuthMiddleware<S> {
    inner: S,
    cfg: Arc<AuthConfig>,
    rate_limiter: Option<PerKeyRateLimiter>,
}

/// Original URI captured before any path normalisation (trailing-slash strip).
/// SigV4 auth uses this to compute the canonical request against the path the
/// client actually signed.
#[derive(Debug, Clone)]
pub struct OriginalSignedUri(pub axum::http::Uri);

fn is_health_path(path: &str) -> bool {
    matches!(path, "/health/live" | "/health/ready" | "/health/version")
}

fn s3_error_xml(code: &str, msg: &str, request_id: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <Error><Code>{code}</Code><Message>{msg}</Message><RequestId>{request_id}</RequestId></Error>"
    )
}

fn forbidden(rid: &str, msg: &str) -> Response {
    let body = s3_error_xml("SignatureDoesNotMatch", msg, rid);
    let mut resp = Response::new(axum::body::Body::new(Full::new(Bytes::from(body))));
    *resp.status_mut() = StatusCode::FORBIDDEN;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml"),
    );
    resp
}

fn s3_error(code: &str, msg: &str, status: StatusCode, rid: &str) -> Response {
    let body = s3_error_xml(code, msg, rid);
    let mut resp = Response::new(axum::body::Body::new(Full::new(Bytes::from(body))));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml"),
    );
    resp
}

fn content_sha256_mismatch(rid: &str) -> Response {
    s3_error(
        "XAmzContentSHA256Mismatch",
        "The provided 'x-amz-content-sha256' header does not match what was computed.",
        StatusCode::BAD_REQUEST,
        rid,
    )
}

fn missing_content_sha256(rid: &str) -> Response {
    s3_error(
        "MissingSecurityHeader",
        "Request is missing the required 'x-amz-content-sha256' header.",
        StatusCode::BAD_REQUEST,
        rid,
    )
}

fn invalid_content_sha256(rid: &str) -> Response {
    s3_error(
        "InvalidArgument",
        "x-amz-content-sha256 must be UNSIGNED-PAYLOAD, STREAMING-*, or a 64-char lower-case hex SHA-256 digest.",
        StatusCode::BAD_REQUEST,
        rid,
    )
}

fn entity_too_large(rid: &str) -> Response {
    s3_error(
        "EntityTooLarge",
        "Request body exceeds the maximum size for hash verification (5 GiB).",
        StatusCode::PAYLOAD_TOO_LARGE,
        rid,
    )
}

fn unsupported_streaming(rid: &str, mode: &str) -> Response {
    let msg = format!(
        "x-amz-content-sha256 mode '{mode}' (chunked SigV4) is not yet \
         supported by this server; disable chunked uploads or use \
         UNSIGNED-PAYLOAD"
    );
    s3_error("NotImplemented", &msg, StatusCode::NOT_IMPLEMENTED, rid)
}

/// Classification of the `x-amz-content-sha256` header value.
enum BodyHashCheck {
    /// Hash the body and compare against this 64-char hex digest.
    Verify(String),
    /// Caller declared `UNSIGNED-PAYLOAD`; skip body hashing entirely.
    Skip,
    /// Header missing — reject (header auth only).
    MissingHeader,
    /// Header present but neither hex nor an allowed sentinel.
    InvalidValue,
    /// `STREAMING-*` chunked-payload mode that Ferrox does not yet verify
    /// per-chunk. Reject rather than silently accept — the chunk signatures
    /// commit to body integrity, and skipping them would re-open the same
    /// trust gap that body-hash verification just closed.
    UnsupportedStreaming(String),
}

/// Decide what to do with the body for a request whose signature has already
/// been verified.
fn classify_body_hash(claimed: &str, is_presigned: bool) -> BodyHashCheck {
    // Presigned URLs always carry UNSIGNED-PAYLOAD per AWS spec; the URL's
    // signature does not commit to the body.
    if is_presigned {
        return BodyHashCheck::Skip;
    }
    if claimed.is_empty() {
        return BodyHashCheck::MissingHeader;
    }
    if claimed == "UNSIGNED-PAYLOAD" {
        return BodyHashCheck::Skip;
    }
    // STREAMING-AWS4-HMAC-SHA256-PAYLOAD and STREAMING-UNSIGNED-PAYLOAD-TRAILER
    // commit to body integrity via per-chunk signatures / trailing checksums.
    // We don't implement per-chunk verification yet, so reject explicitly
    // rather than silently accept (which would let any payload through under
    // a valid SigV4 header). AWS SDK clients can be configured to disable
    // chunked uploads (`disable_request_compression` / similar knobs).
    if claimed.starts_with("STREAMING-") {
        return BodyHashCheck::UnsupportedStreaming(claimed.to_string());
    }
    if claimed.len() == 64
        && claimed
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return BodyHashCheck::Verify(claimed.to_string());
    }
    BodyHashCheck::InvalidValue
}

fn hex_sha256(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// Constant-time slice equality. Avoids early-exit timing leaks even when the
/// inputs are textual (hex) — defence in depth against future re-uses.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn slow_down(rid: &str) -> Response {
    let body = s3_error_xml("SlowDown", "Reduce your request rate", rid);
    let mut resp = Response::new(axum::body::Body::new(Full::new(Bytes::from(body))));
    *resp.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml"),
    );
    resp.headers_mut()
        .insert("retry-after", HeaderValue::from_static("1"));
    resp
}

/// Collect every request header into a `Vec<(name, value)>` for the SigV4
/// canonicalizer. Names are lower-cased per spec.
fn collect_headers(req: &Request) -> Vec<(String, String)> {
    req.headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|s| (k.as_str().to_ascii_lowercase(), s.to_string()))
        })
        .collect()
}

/// Phase 0 single-tenant secret lookup. Returns `None` for unknown keys so
/// the caller emits `InvalidAccessKeyId` semantics. Phase 1 swaps in IAM.
fn lookup_secret(cfg: &AuthConfig, access_key: &str) -> Option<String> {
    if access_key == cfg.access_key {
        Some(cfg.secret_key.clone())
    } else {
        None
    }
}

/// Parsed credentials, abstracted over SigV4 vs SigV4A.
enum ParsedAuth {
    SigV4(SigV4Header),
    SigV4A(SigV4AHeader),
}

impl ParsedAuth {
    fn access_key(&self) -> &str {
        match self {
            Self::SigV4(h) => &h.access_key,
            Self::SigV4A(h) => &h.access_key,
        }
    }
}

/// Detect the algorithm prefix in an `Authorization` header value, then
/// dispatch to the matching parser. Unknown algorithms produce
/// [`FerroxError::InvalidRequest`].
fn parse_authorization_header(value: &str) -> Result<ParsedAuth, FerroxError> {
    let trimmed = value.trim_start();
    if trimmed.starts_with(SIGV4A_ALGO) {
        SigV4AHeader::from_authorization_header(trimmed).map(ParsedAuth::SigV4A)
    } else if trimmed.starts_with(SIGV4_ALGO) {
        SigV4Header::from_authorization_header(trimmed).map(ParsedAuth::SigV4)
    } else {
        Err(FerroxError::InvalidRequest(
            "unsupported Authorization algorithm (expected AWS4-HMAC-SHA256 or AWS4-ECDSA-P256-SHA256)".into(),
        ))
    }
}

/// Detect the SigV4/SigV4A algorithm in a presigned-URL query string.
fn parse_query_signed_request(query: &str) -> Result<ParsedAuth, FerroxError> {
    // Find X-Amz-Algorithm without bothering with full parsing.
    let algo = query
        .split('&')
        .filter_map(|p| p.split_once('='))
        .find_map(|(k, v)| (k == "X-Amz-Algorithm").then_some(v))
        .map(|v| {
            percent_encoding::percent_decode_str(v)
                .decode_utf8_lossy()
                .into_owned()
        });
    match algo.as_deref() {
        Some(SIGV4A_ALGO) => parse_sigv4a_query(query).map(ParsedAuth::SigV4A),
        Some(SIGV4_ALGO) => parse_sigv4_query(query).map(ParsedAuth::SigV4),
        Some(other) => Err(FerroxError::InvalidRequest(format!(
            "unsupported X-Amz-Algorithm: {other}"
        ))),
        None => Err(FerroxError::InvalidRequest(
            "missing X-Amz-Algorithm in presigned URL".into(),
        )),
    }
}

/// Build a [`SigV4Header`] from `X-Amz-…` query parameters.
fn parse_sigv4_query(query: &str) -> Result<SigV4Header, FerroxError> {
    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v_dec = percent_encoding::percent_decode_str(v)
            .decode_utf8_lossy()
            .into_owned();
        match k {
            "X-Amz-Credential" => credential = Some(v_dec),
            "X-Amz-SignedHeaders" => signed_headers = Some(v_dec),
            "X-Amz-Signature" => signature = Some(v_dec),
            _ => {}
        }
    }
    let auth_value = format!(
        "AWS4-HMAC-SHA256 Credential={},SignedHeaders={},Signature={}",
        credential.ok_or_else(|| FerroxError::InvalidRequest("missing X-Amz-Credential".into()))?,
        signed_headers
            .ok_or_else(|| FerroxError::InvalidRequest("missing X-Amz-SignedHeaders".into()))?,
        signature.ok_or_else(|| FerroxError::InvalidRequest("missing X-Amz-Signature".into()))?,
    );
    SigV4Header::from_authorization_header(&auth_value)
}

impl<S> Service<Request> for SigV4AuthMiddleware<S>
where
    S: Service<Request, Response = Response> + Send + Clone + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let path = req.uri().path().to_string();
        let mut inner = self.inner.clone();
        if is_health_path(&path) {
            return Box::pin(async move { inner.call(req).await });
        }

        let cfg = Arc::clone(&self.cfg);
        let self_rate_limiter_clone = self.rate_limiter.clone();
        Box::pin(async move {
            let rid = req
                .extensions()
                .get::<RequestId>()
                .map(|r| r.0.clone())
                .unwrap_or_else(|| "00000000-0000-0000-0000-000000000000".to_string());

            let method = req.method().as_str().to_string();
            let query = req.uri().query().unwrap_or("").to_string();
            let headers = collect_headers(&req);

            let is_presigned = query.contains("X-Amz-Signature=");

            // 1. Parse credentials (SigV4 or SigV4A) from header OR query.
            let parsed = match req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
            {
                Some(v) => parse_authorization_header(v),
                None if is_presigned => parse_query_signed_request(&query),
                _ => return Ok(forbidden(&rid, "missing SigV4 credentials")),
            };
            let parsed = match parsed {
                Ok(p) => p,
                Err(e) => return Ok(forbidden(&rid, &e.to_string())),
            };

            // 2. Look up secret.
            let secret = match lookup_secret(&cfg, parsed.access_key()) {
                Some(s) => s,
                None => return Ok(forbidden(&rid, "InvalidAccessKeyId")),
            };

            // 3. Verify.
            let now = chrono::Utc::now().timestamp();
            // Use the original (pre-normalisation) URI for canonical-request
            // construction so the signature matches what the client signed.
            let path_for_sig = req
                .extensions()
                .get::<OriginalSignedUri>()
                .map(|u| u.0.path().to_string())
                .unwrap_or_else(|| req.uri().path().to_string());

            // The hash *claimed* by the caller in `x-amz-content-sha256`. The
            // signature verifier uses this value verbatim — that's how the
            // canonical request was constructed by the client. After the
            // signature passes we *separately* hash the actual body and verify
            // it equals the claimed hash, closing the trust gap that pre-Phase-3
            // builds had (commit history shows the hash was previously
            // accepted blindly from the header).
            let claimed_body_hash = headers
                .iter()
                .find(|(k, _)| k == "x-amz-content-sha256")
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            // SigV4 requires *some* value in the canonical request even when
            // the caller used UNSIGNED-PAYLOAD or omitted the header (in which
            // case the SDK sends the empty-body hash). Mirror that here so the
            // signature verifier sees what the client actually signed.
            let body_hash_for_sig = if claimed_body_hash.is_empty() {
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()
            } else {
                claimed_body_hash.clone()
            };

            let res = match (&parsed, is_presigned) {
                (ParsedAuth::SigV4(h), false) => verify_sigv4(
                    &method,
                    &path_for_sig,
                    &query,
                    &headers,
                    &body_hash_for_sig,
                    &secret,
                    h,
                    now,
                    cfg.clock_skew_secs,
                ),
                (ParsedAuth::SigV4(h), true) => {
                    verify_presigned_url(&method, &path_for_sig, &query, &headers, &secret, h, now)
                }
                (ParsedAuth::SigV4A(h), false) => verify_sigv4a(
                    &method,
                    &path_for_sig,
                    &query,
                    &headers,
                    &body_hash_for_sig,
                    &secret,
                    h,
                    now,
                    cfg.clock_skew_secs,
                    &cfg.region,
                ),
                (ParsedAuth::SigV4A(h), true) => verify_presigned_sigv4a(
                    &method,
                    &path_for_sig,
                    &query,
                    &headers,
                    &secret,
                    h,
                    now,
                    &cfg.region,
                ),
            };
            if let Err(e) = res {
                return Ok(forbidden(&rid, &e.to_string()));
            }

            // 4. Rate limit (after auth — key identity is now known).
            if let Some(rl) = self_rate_limiter_clone.as_ref() {
                if !rl.check(parsed.access_key()) {
                    return Ok(slow_down(&rid));
                }
            }

            // 5. Body integrity: now that the signature is good, verify the
            // body actually hashes to what the caller claimed. Skipping this
            // would let a MITM swap the body without invalidating the SigV4
            // signature (which only commits to the *claimed* hash).
            let req = match classify_body_hash(&claimed_body_hash, is_presigned) {
                BodyHashCheck::MissingHeader => return Ok(missing_content_sha256(&rid)),
                BodyHashCheck::InvalidValue => return Ok(invalid_content_sha256(&rid)),
                BodyHashCheck::UnsupportedStreaming(mode) => {
                    return Ok(unsupported_streaming(&rid, &mode))
                }
                BodyHashCheck::Skip => req,
                BodyHashCheck::Verify(claimed) => {
                    let (parts, body) = req.into_parts();
                    let body_bytes = match axum::body::to_bytes(body, MAX_VERIFY_BODY_BYTES).await {
                        Ok(b) => b,
                        Err(_) => return Ok(entity_too_large(&rid)),
                    };
                    let actual = hex_sha256(&body_bytes);
                    if !ct_eq(actual.as_bytes(), claimed.as_bytes()) {
                        return Ok(content_sha256_mismatch(&rid));
                    }
                    Request::from_parts(parts, axum::body::Body::from(body_bytes))
                }
            };

            inner.call(req).await
        })
    }
}
