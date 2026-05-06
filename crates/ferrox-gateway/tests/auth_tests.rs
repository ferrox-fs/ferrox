//! Integration tests for the SigV4 auth middleware (Step 10).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ferrox_gateway::router::build_router;
use ferrox_gateway::state::{AppState, GatewayConfig};
use ferrox_meta::SledMeta;
use ferrox_storage::disk::DiskBackend;
use ring::hmac;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tower::util::ServiceExt;

const ACCESS_KEY: &str = "AKIDEXAMPLE";
const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const REGION: &str = "us-east-1";
const SERVICE: &str = "s3";
const EMPTY_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

async fn make_app() -> (TempDir, axum::Router) {
    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(
        DiskBackend::new(tmp.path().join("data"), false)
            .await
            .unwrap(),
    );
    let meta = Arc::new(SledMeta::open(tmp.path().join("meta")).unwrap());
    let config = Arc::new(GatewayConfig {
        data_dir: tmp.path().to_path_buf(),
        access_key: ACCESS_KEY.into(),
        secret_key: SECRET_KEY.into(),
        fsync: false,
        clock_skew_secs: 900,
        sse_master_key: None,
        max_req_per_sec: 0,
    });
    let app = build_router(AppState {
        storage,
        meta,
        config,
        metrics: ferrox_gateway::metrics::Metrics::new(),
        rate_limiter: None,
    });
    (tmp, app)
}

fn hex_sha256(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    hex::encode(h.finalize())
}

fn mac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&k, data).as_ref().to_vec()
}

/// Sign a GET request to `path` with `host` and `x-amz-date`, returning the
/// `Authorization` header value.
fn sign_get(path: &str, host: &str, amz_date: &str) -> String {
    let date = &amz_date[..8];
    let scope = format!("{date}/{REGION}/{SERVICE}/aws4_request");
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical = format!(
        "GET\n{path}\n\nhost:{host}\nx-amz-content-sha256:{EMPTY_SHA}\nx-amz-date:{amz_date}\n\n{signed_headers}\n{EMPTY_SHA}"
    );
    let canonical_hash = hex_sha256(canonical.as_bytes());
    let sts = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{canonical_hash}");
    let k_date = mac(format!("AWS4{SECRET_KEY}").as_bytes(), date.as_bytes());
    let k_region = mac(&k_date, REGION.as_bytes());
    let k_service = mac(&k_region, SERVICE.as_bytes());
    let k_signing = mac(&k_service, b"aws4_request");
    let sig = hex::encode(mac(&k_signing, sts.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/{scope}, \
         SignedHeaders={signed_headers}, Signature={sig}"
    )
}

#[tokio::test]
async fn test_valid_sigv4_request_passes_auth() {
    let (_t, app) = make_app().await;
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let host = "localhost";
    let path = "/valid-bucket/some-key";
    let auth = sign_get(path, host, &amz_date);
    let req = Request::builder()
        .uri(path)
        .method("GET")
        .header("host", host)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", EMPTY_SHA)
        .header("authorization", auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Auth passes; bucket doesn't exist → 404 NoSuchBucket.
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_missing_auth_header_returns_403() {
    let (_t, app) = make_app().await;
    let req = Request::builder()
        .uri("/b/k")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_expired_timestamp_returns_403() {
    let (_t, app) = make_app().await;
    // 16 minutes in the past.
    let past = chrono::Utc::now() - chrono::Duration::minutes(16);
    let amz_date = past.format("%Y%m%dT%H%M%SZ").to_string();
    let host = "localhost";
    let path = "/b/k";
    let auth = sign_get(path, host, &amz_date);
    let req = Request::builder()
        .uri(path)
        .method("GET")
        .header("host", host)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", EMPTY_SHA)
        .header("authorization", auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_wrong_signature_returns_403() {
    let (_t, app) = make_app().await;
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let host = "localhost";
    let path = "/b/k";
    let date = &amz_date[..8];
    let scope = format!("{date}/{REGION}/{SERVICE}/aws4_request");
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/{scope}, \
         SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
         Signature=0000000000000000000000000000000000000000000000000000000000000000"
    );
    let req = Request::builder()
        .uri(path)
        .method("GET")
        .header("host", host)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", EMPTY_SHA)
        .header("authorization", auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
