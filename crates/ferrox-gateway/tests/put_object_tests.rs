//! Integration tests for the `PutObject` handler (Step 11).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ferrox_gateway::router::build_router;
use ferrox_gateway::state::{AppState, GatewayConfig};
use ferrox_meta::SledMeta;
use ferrox_storage::disk::DiskBackend;
use ferrox_storage::StorageBackend;
use ring::hmac;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tower::util::ServiceExt;

const ACCESS_KEY: &str = "AKIDEXAMPLE";
const SECRET_KEY: &str = "MOCKxSECRETxKEYxFORxTESTSxONLYx123456789";
const REGION: &str = "testregion";
const SERVICE: &str = "s3";

struct TestEnv {
    _tmp: TempDir,
    storage: Arc<DiskBackend>,
    meta: Arc<SledMeta>,
    config: Arc<ferrox_gateway::state::GatewayConfig>,
}

async fn make_env() -> TestEnv {
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
    TestEnv {
        _tmp: tmp,
        storage,
        meta,
        config,
    }
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

/// Build Authorization header for a PUT request with a known body.
fn sign_put(
    path: &str,
    host: &str,
    amz_date: &str,
    body_sha256: &str,
    content_len: usize,
) -> String {
    let date = &amz_date[..8];
    let scope = format!("{date}/{REGION}/{SERVICE}/aws4_request");
    let signed_headers = "content-length;host;x-amz-content-sha256;x-amz-date";
    let canonical = format!(
        "PUT\n{path}\n\ncontent-length:{content_len}\nhost:{host}\nx-amz-content-sha256:{body_sha256}\nx-amz-date:{amz_date}\n\n{signed_headers}\n{body_sha256}"
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
async fn test_put_object_success_returns_200_with_etag() {
    let env = make_env().await;
    env.storage.create_bucket("my-bucket").await.unwrap();

    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new(),
        rate_limiter: None,
    });

    let body_bytes = b"hello world";
    let body_sha = hex_sha256(body_bytes);
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let host = "localhost";
    let path = "/my-bucket/test-key.txt";
    let auth = sign_put(path, host, &amz_date, &body_sha, body_bytes.len());

    let req = Request::builder()
        .uri(path)
        .method("PUT")
        .header("host", host)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", &body_sha)
        .header("content-length", body_bytes.len().to_string())
        .header("content-type", "text/plain")
        .header("authorization", auth)
        .body(Body::from(body_bytes.as_ref()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().contains_key("etag"));
}

#[tokio::test]
async fn test_put_object_missing_content_length_returns_411() {
    let env = make_env().await;
    env.storage.create_bucket("my-bucket").await.unwrap();

    let body_bytes = b"hello";
    let body_sha = hex_sha256(body_bytes);
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let host = "localhost";
    let path = "/my-bucket/k";

    // Build auth without content-length in signed headers to test 411 path.
    let date = &amz_date[..8];
    let scope = format!("{date}/{REGION}/{SERVICE}/aws4_request");
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical = format!(
        "PUT\n{path}\n\nhost:{host}\nx-amz-content-sha256:{body_sha}\nx-amz-date:{amz_date}\n\n{signed_headers}\n{body_sha}"
    );
    let canonical_hash = hex_sha256(canonical.as_bytes());
    let sts = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{canonical_hash}");
    let k_date = mac(format!("AWS4{SECRET_KEY}").as_bytes(), date.as_bytes());
    let k_region = mac(&k_date, REGION.as_bytes());
    let k_service = mac(&k_region, SERVICE.as_bytes());
    let k_signing = mac(&k_service, b"aws4_request");
    let sig = hex::encode(mac(&k_signing, sts.as_bytes()));
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/{scope}, \
         SignedHeaders={signed_headers}, Signature={sig}"
    );

    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new(),
        rate_limiter: None,
    });

    let req = Request::builder()
        .uri(path)
        .method("PUT")
        .header("host", host)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", &body_sha)
        .header("authorization", auth)
        .body(Body::from(body_bytes.as_ref()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::LENGTH_REQUIRED);
}

#[tokio::test]
async fn test_put_object_nonexistent_bucket_returns_404() {
    let env = make_env().await;
    // Do NOT create the bucket.
    let body_bytes = b"data";
    let body_sha = hex_sha256(body_bytes);
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let path = "/no-such-bucket/key";
    let auth = sign_put(path, "localhost", &amz_date, &body_sha, body_bytes.len());

    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new(),
        rate_limiter: None,
    });

    let req = Request::builder()
        .uri(path)
        .method("PUT")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", &body_sha)
        .header("content-length", body_bytes.len().to_string())
        .header("authorization", auth)
        .body(Body::from(body_bytes.as_ref()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_put_object_invalid_bucket_name_returns_400() {
    let env = make_env().await;
    let body_bytes = b"data";
    let body_sha = hex_sha256(body_bytes);
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    // Bucket name with uppercase → invalid.
    let path = "/INVALID_BUCKET/key";
    let auth = sign_put(path, "localhost", &amz_date, &body_sha, body_bytes.len());

    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new(),
        rate_limiter: None,
    });

    let req = Request::builder()
        .uri(path)
        .method("PUT")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", &body_sha)
        .header("content-length", body_bytes.len().to_string())
        .header("authorization", auth)
        .body(Body::from(body_bytes.as_ref()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
