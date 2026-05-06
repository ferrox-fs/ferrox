//! SigV4 authentication middleware (Step 10).
//!
//! - Extracts the SigV4 credentials from either the `Authorization` header
//!   OR the query string (pre-signed URL — Phase 1 Step 19 also routes here).
//! - Looks up the secret bound to the access key (Phase 0: single key from
//!   [`AuthConfig`]; Phase 1+: from the IAM crate).
//! - Recomputes the canonical request and runs
//!   [`verify_sigv4`](crate::auth::verify_sigv4) in constant time.
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

use crate::auth::{verify_presigned_url, verify_sigv4, SigV4Header};
use crate::middleware::RequestId;
use crate::ratelimit::PerKeyRateLimiter;

/// Configuration shared by every auth invocation.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Single access key recognized in Phase 0.
    pub access_key: String,
    /// Secret bound to `access_key`.
    pub secret_key: String,
    /// Allowed clock skew in seconds.
    pub clock_skew_secs: i64,
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

fn parse_query_signed_request(query: &str) -> Result<SigV4Header, FerroxError> {
    let mut algorithm = None;
    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    let mut date = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v_dec = percent_encoding::percent_decode_str(v)
            .decode_utf8_lossy()
            .into_owned();
        match k {
            "X-Amz-Algorithm" => algorithm = Some(v_dec),
            "X-Amz-Credential" => credential = Some(v_dec),
            "X-Amz-SignedHeaders" => signed_headers = Some(v_dec),
            "X-Amz-Signature" => signature = Some(v_dec),
            "X-Amz-Date" => date = Some(v_dec),
            _ => {}
        }
    }
    if algorithm.as_deref() != Some("AWS4-HMAC-SHA256") {
        return Err(FerroxError::InvalidRequest(
            "X-Amz-Algorithm must be AWS4-HMAC-SHA256".into(),
        ));
    }
    let auth_value = format!(
        "AWS4-HMAC-SHA256 Credential={},SignedHeaders={},Signature={}",
        credential.ok_or_else(|| FerroxError::InvalidRequest("missing X-Amz-Credential".into()))?,
        signed_headers
            .ok_or_else(|| FerroxError::InvalidRequest("missing X-Amz-SignedHeaders".into()))?,
        signature.ok_or_else(|| FerroxError::InvalidRequest("missing X-Amz-Signature".into()))?,
    );
    let _ = date; // X-Amz-Date is read separately from canonical headers/query
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

            // 1. Parse SigV4 from header OR query.
            let parsed = match req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
            {
                Some(v) => SigV4Header::from_authorization_header(v),
                None if is_presigned => parse_query_signed_request(&query),
                _ => return Ok(forbidden(&rid, "missing SigV4 credentials")),
            };
            let parsed = match parsed {
                Ok(p) => p,
                Err(e) => return Ok(forbidden(&rid, &e.to_string())),
            };

            // 2. Look up secret.
            let secret = match lookup_secret(&cfg, &parsed.access_key) {
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
            let res = if is_presigned {
                verify_presigned_url(
                    &method,
                    &path_for_sig,
                    &query,
                    &headers,
                    &secret,
                    &parsed,
                    now,
                )
            } else {
                // Body hash — trust X-Amz-Content-Sha256 (set by every AWS SDK).
                let body_hash = headers
                    .iter()
                    .find(|(k, _)| k == "x-amz-content-sha256")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_else(|| {
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                            .to_string()
                    });
                verify_sigv4(
                    &method,
                    &path_for_sig,
                    &query,
                    &headers,
                    &body_hash,
                    &secret,
                    &parsed,
                    now,
                    cfg.clock_skew_secs,
                )
            };
            if let Err(e) = res {
                return Ok(forbidden(&rid, &e.to_string()));
            }

            // 4. Rate limit (after auth — key identity is now known).
            if let Some(rl) = self_rate_limiter_clone.as_ref() {
                if !rl.check(&parsed.access_key) {
                    return Ok(slow_down(&rid));
                }
            }

            inner.call(req).await
        })
    }
}
