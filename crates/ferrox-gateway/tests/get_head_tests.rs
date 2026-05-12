//! Integration tests for `GetObject` and `HeadObject` handlers (Step 12).

use std::sync::Arc;

use axum::body::{to_bytes, Body};
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
const EMPTY_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

struct TestEnv {
    _tmp: TempDir,
    storage: Arc<DiskBackend>,
    meta: Arc<SledMeta>,
    config: Arc<GatewayConfig>,
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
        region: "testregion".into(),
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

fn sign_request(
    method: &str,
    path: &str,
    host: &str,
    amz_date: &str,
    body_sha: &str,
    extra_headers: &[(&str, &str)],
) -> String {
    let date = &amz_date[..8];
    let scope = format!("{date}/{REGION}/{SERVICE}/aws4_request");

    let mut header_pairs: Vec<(String, String)> = vec![
        ("host".into(), host.into()),
        ("x-amz-content-sha256".into(), body_sha.into()),
        ("x-amz-date".into(), amz_date.into()),
    ];
    for (k, v) in extra_headers {
        header_pairs.push((k.to_lowercase(), v.to_string()));
    }
    header_pairs.sort_by(|a, b| a.0.cmp(&b.0));

    let canonical_headers: String = header_pairs
        .iter()
        .map(|(k, v)| format!("{k}:{v}\n"))
        .collect();
    let signed_headers: String = header_pairs
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let canonical =
        format!("{method}\n{path}\n\n{canonical_headers}\n{signed_headers}\n{body_sha}");
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

/// PUT a small object directly through the router for test setup.
async fn put_test_object(app: axum::Router, path: &str, body_bytes: &[u8]) -> axum::Router {
    let body_sha = hex_sha256(body_bytes);
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let auth = sign_request(
        "PUT",
        path,
        "localhost",
        &amz_date,
        &body_sha,
        &[("content-length", &body_bytes.len().to_string())],
    );
    let req = Request::builder()
        .uri(path)
        .method("PUT")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", &body_sha)
        .header("content-length", body_bytes.len().to_string())
        .header("content-type", "text/plain")
        .header("authorization", auth)
        .body(Body::from(body_bytes.to_vec()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "setup PUT failed");
    app
}

#[tokio::test]
async fn test_get_object_returns_200_with_body() {
    let env = make_env().await;
    env.storage.create_bucket("test-bucket").await.unwrap();

    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new().unwrap(),
        rate_limiter: None,
    });

    let body_bytes = b"hello from ferrox";
    let app = put_test_object(app, "/test-bucket/hello.txt", body_bytes).await;

    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let auth = sign_request(
        "GET",
        "/test-bucket/hello.txt",
        "localhost",
        &amz_date,
        EMPTY_SHA,
        &[],
    );
    let req = Request::builder()
        .uri("/test-bucket/hello.txt")
        .method("GET")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", EMPTY_SHA)
        .header("authorization", auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().contains_key("etag"));
    assert!(resp.headers().contains_key("content-type"));
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(body.as_ref(), body_bytes);
}

#[tokio::test]
async fn test_get_object_range_returns_206() {
    let env = make_env().await;
    env.storage.create_bucket("test-bucket").await.unwrap();

    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new().unwrap(),
        rate_limiter: None,
    });

    let body_bytes = b"0123456789"; // 10 bytes
    let app = put_test_object(app, "/test-bucket/numbers.txt", body_bytes).await;

    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let auth = sign_request(
        "GET",
        "/test-bucket/numbers.txt",
        "localhost",
        &amz_date,
        EMPTY_SHA,
        &[("range", "bytes=2-5")],
    );
    let req = Request::builder()
        .uri("/test-bucket/numbers.txt")
        .method("GET")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", EMPTY_SHA)
        .header("range", "bytes=2-5")
        .header("authorization", auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert!(resp.headers().contains_key("content-range"));
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(body.as_ref(), b"2345");
}

#[tokio::test]
async fn test_head_object_returns_200_no_body() {
    let env = make_env().await;
    env.storage.create_bucket("test-bucket").await.unwrap();

    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new().unwrap(),
        rate_limiter: None,
    });

    let body_bytes = b"some content";
    let app = put_test_object(app, "/test-bucket/obj.bin", body_bytes).await;

    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let auth = sign_request(
        "HEAD",
        "/test-bucket/obj.bin",
        "localhost",
        &amz_date,
        EMPTY_SHA,
        &[],
    );
    let req = Request::builder()
        .uri("/test-bucket/obj.bin")
        .method("HEAD")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", EMPTY_SHA)
        .header("authorization", auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().contains_key("etag"));
    assert_eq!(
        resp.headers()
            .get("content-length")
            .unwrap()
            .to_str()
            .unwrap(),
        body_bytes.len().to_string()
    );
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert!(body.is_empty());
}

#[tokio::test]
async fn test_get_object_not_found_returns_404() {
    let env = make_env().await;
    env.storage.create_bucket("test-bucket").await.unwrap();

    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new().unwrap(),
        rate_limiter: None,
    });

    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let auth = sign_request(
        "GET",
        "/test-bucket/missing.txt",
        "localhost",
        &amz_date,
        EMPTY_SHA,
        &[],
    );
    let req = Request::builder()
        .uri("/test-bucket/missing.txt")
        .method("GET")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", EMPTY_SHA)
        .header("authorization", auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
