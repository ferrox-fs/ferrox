//! Integration tests for SSE-S3 (AES-256-GCM server-side encryption, Step 20).

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use ferrox_crypto::SseMasterKey;
use ferrox_gateway::router::build_router;
use ferrox_gateway::state::{AppState, GatewayConfig};
use ferrox_meta::SledMeta;
use ferrox_storage::disk::DiskBackend;
use ring::hmac;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tower::util::ServiceExt;

const ACCESS_KEY: &str = "AKIDEXAMPLE";
const SECRET_KEY: &str = "MOCKxSECRETxKEYxFORxTESTSxONLYx123456789";
const REGION: &str = "testregion";
const SERVICE: &str = "s3";
const EMPTY_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const TEST_MASTER_KEY_HEX: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct TestEnv {
    _tmp: TempDir,
    storage: Arc<DiskBackend>,
    meta: Arc<SledMeta>,
    config: Arc<GatewayConfig>,
}

async fn make_env_with_sse() -> TestEnv {
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
        sse_master_key: Some(SseMasterKey::from_hex(TEST_MASTER_KEY_HEX).unwrap()),
        max_req_per_sec: 0,
    });
    TestEnv {
        _tmp: tmp,
        storage,
        meta,
        config,
    }
}

async fn make_env_no_sse() -> TestEnv {
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

fn sign(
    method: &str,
    path: &str,
    host: &str,
    amz_date: &str,
    body_sha: &str,
    extra: &[(&str, &str)],
) -> String {
    let date = &amz_date[..8];
    let scope = format!("{date}/{REGION}/{SERVICE}/aws4_request");
    let mut hdrs: Vec<(String, String)> = vec![
        ("host".into(), host.into()),
        ("x-amz-content-sha256".into(), body_sha.into()),
        ("x-amz-date".into(), amz_date.into()),
    ];
    for (k, v) in extra {
        hdrs.push((k.to_lowercase(), v.to_string()));
    }
    hdrs.sort_by(|a, b| a.0.cmp(&b.0));
    let canonical_headers: String = hdrs.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers: String = hdrs
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
    format!("AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/{scope}, SignedHeaders={signed_headers}, Signature={sig}")
}

async fn create_bucket(app: axum::Router, bucket: &str) {
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let path = format!("/{bucket}");
    let auth = sign("PUT", &path, "localhost", &amz_date, EMPTY_SHA, &[]);
    let req = Request::builder()
        .uri(&path)
        .method("PUT")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", EMPTY_SHA)
        .header("authorization", auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_sse_put_returns_sse_header() {
    let env = make_env_with_sse().await;
    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new().unwrap(),
        rate_limiter: None,
    });

    create_bucket(app.clone(), "enc-bucket").await;

    let data = b"secret plaintext";
    let body_sha = hex_sha256(data);
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let auth = sign(
        "PUT",
        "/enc-bucket/secret-key",
        "localhost",
        &amz_date,
        &body_sha,
        &[
            ("content-length", &data.len().to_string()),
            ("x-amz-server-side-encryption", "AES256"),
        ],
    );
    let req = Request::builder()
        .uri("/enc-bucket/secret-key")
        .method("PUT")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", &body_sha)
        .header("content-length", data.len().to_string())
        .header("x-amz-server-side-encryption", "AES256")
        .header("authorization", auth)
        .body(Body::from(data.as_ref()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-amz-server-side-encryption")
            .and_then(|v| v.to_str().ok()),
        Some("AES256"),
        "response must echo SSE header"
    );
}

#[tokio::test]
async fn test_sse_get_returns_plaintext() {
    let env = make_env_with_sse().await;
    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new().unwrap(),
        rate_limiter: None,
    });

    create_bucket(app.clone(), "enc-bucket").await;

    let data = b"the quick brown fox";
    let body_sha = hex_sha256(data);
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();

    // PUT with SSE.
    let auth = sign(
        "PUT",
        "/enc-bucket/fox",
        "localhost",
        &amz_date,
        &body_sha,
        &[
            ("content-length", &data.len().to_string()),
            ("x-amz-server-side-encryption", "AES256"),
        ],
    );
    let put_req = Request::builder()
        .uri("/enc-bucket/fox")
        .method("PUT")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", &body_sha)
        .header("content-length", data.len().to_string())
        .header("x-amz-server-side-encryption", "AES256")
        .header("authorization", auth)
        .body(Body::from(data.as_ref()))
        .unwrap();
    let put_resp = app.clone().oneshot(put_req).await.unwrap();
    assert_eq!(put_resp.status(), StatusCode::OK);

    // GET — must decrypt transparently.
    let amz_date2 = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let auth2 = sign(
        "GET",
        "/enc-bucket/fox",
        "localhost",
        &amz_date2,
        EMPTY_SHA,
        &[],
    );
    let get_req = Request::builder()
        .uri("/enc-bucket/fox")
        .method("GET")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date2)
        .header("x-amz-content-sha256", EMPTY_SHA)
        .header("authorization", auth2)
        .body(Body::empty())
        .unwrap();
    let get_resp = app.oneshot(get_req).await.unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK);
    assert_eq!(
        get_resp
            .headers()
            .get("x-amz-server-side-encryption")
            .and_then(|v| v.to_str().ok()),
        Some("AES256")
    );
    let body_bytes = to_bytes(get_resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        body_bytes.as_ref(),
        data,
        "decrypted content must equal original plaintext"
    );
}

#[tokio::test]
async fn test_sse_head_reports_plaintext_size() {
    let env = make_env_with_sse().await;
    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new().unwrap(),
        rate_limiter: None,
    });

    create_bucket(app.clone(), "enc-bucket").await;

    let data = b"exact size test";
    let body_sha = hex_sha256(data);
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();

    let auth = sign(
        "PUT",
        "/enc-bucket/sizedkey",
        "localhost",
        &amz_date,
        &body_sha,
        &[
            ("content-length", &data.len().to_string()),
            ("x-amz-server-side-encryption", "AES256"),
        ],
    );
    let put_req = Request::builder()
        .uri("/enc-bucket/sizedkey")
        .method("PUT")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", &body_sha)
        .header("content-length", data.len().to_string())
        .header("x-amz-server-side-encryption", "AES256")
        .header("authorization", auth)
        .body(Body::from(data.as_ref()))
        .unwrap();
    app.clone().oneshot(put_req).await.unwrap();

    let amz_date2 = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let auth2 = sign(
        "HEAD",
        "/enc-bucket/sizedkey",
        "localhost",
        &amz_date2,
        EMPTY_SHA,
        &[],
    );
    let head_req = Request::builder()
        .uri("/enc-bucket/sizedkey")
        .method("HEAD")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date2)
        .header("x-amz-content-sha256", EMPTY_SHA)
        .header("authorization", auth2)
        .body(Body::empty())
        .unwrap();
    let head_resp = app.oneshot(head_req).await.unwrap();
    assert_eq!(head_resp.status(), StatusCode::OK);
    let content_length: u64 = head_resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert_eq!(
        content_length,
        data.len() as u64,
        "HEAD must report plaintext size, not ciphertext size"
    );
}

#[tokio::test]
async fn test_sse_request_without_master_key_returns_400() {
    let env = make_env_no_sse().await;
    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new().unwrap(),
        rate_limiter: None,
    });

    create_bucket(app.clone(), "enc-bucket").await;

    let data = b"should fail";
    let body_sha = hex_sha256(data);
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let auth = sign(
        "PUT",
        "/enc-bucket/key",
        "localhost",
        &amz_date,
        &body_sha,
        &[
            ("content-length", &data.len().to_string()),
            ("x-amz-server-side-encryption", "AES256"),
        ],
    );
    let req = Request::builder()
        .uri("/enc-bucket/key")
        .method("PUT")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", &body_sha)
        .header("content-length", data.len().to_string())
        .header("x-amz-server-side-encryption", "AES256")
        .header("authorization", auth)
        .body(Body::from(data.as_ref()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_sse_encrypted_bytes_differ_from_plaintext() {
    // Reads raw bytes from disk via storage directly to confirm ciphertext ≠ plaintext.
    let env = make_env_with_sse().await;
    let storage = env.storage.clone();
    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new().unwrap(),
        rate_limiter: None,
    });

    create_bucket(app.clone(), "enc-bucket").await;

    let data = b"verify on disk encryption";
    let body_sha = hex_sha256(data);
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let auth = sign(
        "PUT",
        "/enc-bucket/disk-check",
        "localhost",
        &amz_date,
        &body_sha,
        &[
            ("content-length", &data.len().to_string()),
            ("x-amz-server-side-encryption", "AES256"),
        ],
    );
    let req = Request::builder()
        .uri("/enc-bucket/disk-check")
        .method("PUT")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", &body_sha)
        .header("content-length", data.len().to_string())
        .header("x-amz-server-side-encryption", "AES256")
        .header("authorization", auth)
        .body(Body::from(data.as_ref()))
        .unwrap();
    app.oneshot(req).await.unwrap();

    // Read raw bytes from storage (bypasses decryption).
    use ferrox_storage::StorageBackend;
    use futures::TryStreamExt;
    let result = storage.get("enc-bucket", "disk-check").await.unwrap();
    let raw: bytes::Bytes = result
        .stream
        .try_fold(bytes::BytesMut::new(), |mut acc, chunk| async move {
            acc.extend_from_slice(&chunk);
            Ok(acc)
        })
        .await
        .unwrap()
        .freeze();
    assert_ne!(
        raw.as_ref(),
        data.as_ref(),
        "on-disk bytes must differ from plaintext"
    );
    assert!(
        raw.len() > data.len(),
        "ciphertext must be larger than plaintext (nonce + tag overhead)"
    );
}
