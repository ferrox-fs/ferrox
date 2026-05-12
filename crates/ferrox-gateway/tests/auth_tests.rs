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
const SECRET_KEY: &str = "MOCKxSECRETxKEYxFORxTESTSxONLYx123456789";
const REGION: &str = "testregion";
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
        region: "testregion".into(),
        sse_master_key: None,
        max_req_per_sec: 0,
    });
    let app = build_router(AppState {
        storage,
        meta,
        config,
        metrics: ferrox_gateway::metrics::Metrics::new().unwrap(),
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

/// Build an authorization header for a PUT request whose canonical-request
/// body hash is `body_hash`. The caller decides whether the actual request
/// body matches that hash — that's the whole point of these tests.
fn sign_put(path: &str, host: &str, amz_date: &str, body_hash: &str) -> String {
    let date = &amz_date[..8];
    let scope = format!("{date}/{REGION}/{SERVICE}/aws4_request");
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical = format!(
        "PUT\n{path}\n\nhost:{host}\nx-amz-content-sha256:{body_hash}\nx-amz-date:{amz_date}\n\n{signed_headers}\n{body_hash}"
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
async fn test_signed_body_hash_matches_passes_auth() {
    let (_t, app) = make_app().await;
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let host = "localhost";
    // Bucket must exist for PUT-object to reach the storage layer cleanly,
    // but for this test we only care that auth + body hash gate passes —
    // anything past the gate (404 NoSuchBucket) confirms middleware accepted.
    let path = "/no-such-bucket/k";
    let body = b"hello world";
    let body_hash = hex_sha256(body);
    let auth = sign_put(path, host, &amz_date, &body_hash);
    let req = Request::builder()
        .uri(path)
        .method("PUT")
        .header("host", host)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", &body_hash)
        .header("content-length", body.len().to_string())
        .header("authorization", auth)
        .body(Body::from(body.as_slice()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Auth + hash gate passed; bucket absent → 404 from handler.
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_signed_body_hash_mismatch_rejected() {
    let (_t, app) = make_app().await;
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let host = "localhost";
    let path = "/b/k";
    // Caller signs a hash for body "hello world" but actually sends "tampered".
    let claimed = hex_sha256(b"hello world");
    let auth = sign_put(path, host, &amz_date, &claimed);
    let actual = b"tampered payload";
    let req = Request::builder()
        .uri(path)
        .method("PUT")
        .header("host", host)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", &claimed)
        .header("content-length", actual.len().to_string())
        .header("authorization", auth)
        .body(Body::from(actual.as_slice()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Signature was valid for the claimed hash, but the body doesn't match it.
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(
        xml.contains("XAmzContentSHA256Mismatch"),
        "expected XAmzContentSHA256Mismatch, got: {xml}"
    );
}

#[tokio::test]
async fn test_missing_content_sha256_header_auth_rejected() {
    let (_t, app) = make_app().await;
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let host = "localhost";
    let path = "/b/k";
    // Sign as if the body hash were the empty-body sentinel, but DON'T send
    // the x-amz-content-sha256 header. Header auth requires it.
    let date = &amz_date[..8];
    let scope = format!("{date}/{REGION}/{SERVICE}/aws4_request");
    let signed_headers = "host;x-amz-date";
    let canonical = format!(
        "GET\n{path}\n\nhost:{host}\nx-amz-date:{amz_date}\n\n{signed_headers}\n{EMPTY_SHA}"
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
    let req = Request::builder()
        .uri(path)
        .method("GET")
        .header("host", host)
        .header("x-amz-date", &amz_date)
        // x-amz-content-sha256 deliberately omitted
        .header("authorization", auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(
        xml.contains("MissingSecurityHeader"),
        "expected MissingSecurityHeader, got: {xml}"
    );
}

#[tokio::test]
async fn test_unsigned_payload_skips_body_hash_check() {
    // UNSIGNED-PAYLOAD is permitted by AWS for clients that opt in; verify
    // the gateway accepts it and does not attempt to hash the body.
    let (_t, app) = make_app().await;
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let host = "localhost";
    let path = "/no-such-bucket/k";
    let body = b"some payload, hash NOT signed";
    let auth = sign_put(path, host, &amz_date, "UNSIGNED-PAYLOAD");
    let req = Request::builder()
        .uri(path)
        .method("PUT")
        .header("host", host)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
        .header("content-length", body.len().to_string())
        .header("authorization", auth)
        .body(Body::from(body.as_slice()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Reaches the handler — bucket missing → 404.
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
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

// ---- SigV4A integration tests (Phase 3 — multi-region ECDSA) ----

/// Build canonical request + string-to-sign + sign with the SigV4A KDF, then
/// return the `Authorization` header value.
fn sign_get_sigv4a(path: &str, host: &str, amz_date: &str, region_set: &str) -> String {
    use ferrox_gateway::auth::derive_sigv4a_signing_key;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{DerSignature, SigningKey};

    let date = &amz_date[..8];
    let scope = format!("{date}/{SERVICE}/aws4_request");
    let signed_headers = "host;x-amz-content-sha256;x-amz-date;x-amz-region-set";
    let canonical = format!(
        "GET\n{path}\n\nhost:{host}\nx-amz-content-sha256:{EMPTY_SHA}\nx-amz-date:{amz_date}\nx-amz-region-set:{region_set}\n\n{signed_headers}\n{EMPTY_SHA}"
    );
    let canonical_hash = hex_sha256(canonical.as_bytes());
    let sts = format!("AWS4-ECDSA-P256-SHA256\n{amz_date}\n{scope}\n{canonical_hash}");

    let secret = derive_sigv4a_signing_key(SECRET_KEY, ACCESS_KEY).unwrap();
    let signer = SigningKey::from(&secret);
    let sig: DerSignature = signer.sign(sts.as_bytes());
    let sig_hex = hex::encode(sig.as_bytes());

    format!(
        "AWS4-ECDSA-P256-SHA256 Credential={ACCESS_KEY}/{scope}, \
         SignedHeaders={signed_headers}, Signature={sig_hex}"
    )
}

#[tokio::test]
async fn test_valid_sigv4a_request_passes_auth() {
    let (_t, app) = make_app().await;
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let host = "localhost";
    let path = "/valid-bucket/some-key";
    let region_set = "*"; // matches anything (gateway region is "testregion")
    let auth = sign_get_sigv4a(path, host, &amz_date, region_set);
    let req = Request::builder()
        .uri(path)
        .method("GET")
        .header("host", host)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", EMPTY_SHA)
        .header("x-amz-region-set", region_set)
        .header("authorization", auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Auth passes; bucket doesn't exist → 404 NoSuchBucket.
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_sigv4a_wrong_region_returns_403() {
    let (_t, app) = make_app().await;
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let host = "localhost";
    let path = "/b/k";
    let region_set = "eu-*"; // gateway is "testregion" → no match
    let auth = sign_get_sigv4a(path, host, &amz_date, region_set);
    let req = Request::builder()
        .uri(path)
        .method("GET")
        .header("host", host)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", EMPTY_SHA)
        .header("x-amz-region-set", region_set)
        .header("authorization", auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_sigv4a_missing_region_set_header_returns_403() {
    let (_t, app) = make_app().await;
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let host = "localhost";
    let path = "/b/k";
    let region_set = "*";
    // Sign as if region-set were present, then drop it from the request.
    let auth = sign_get_sigv4a(path, host, &amz_date, region_set);
    let req = Request::builder()
        .uri(path)
        .method("GET")
        .header("host", host)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", EMPTY_SHA)
        // x-amz-region-set deliberately omitted
        .header("authorization", auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_sigv4a_unsigned_region_set_returns_403() {
    let (_t, app) = make_app().await;
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let host = "localhost";
    let path = "/b/k";
    // Build a SigV4A header that does NOT list x-amz-region-set in SignedHeaders.
    let auth = format!(
        "AWS4-ECDSA-P256-SHA256 Credential={ACCESS_KEY}/{}/{SERVICE}/aws4_request, \
         SignedHeaders=host;x-amz-date, Signature=304402deadbeef",
        &amz_date[..8]
    );
    let req = Request::builder()
        .uri(path)
        .method("GET")
        .header("host", host)
        .header("x-amz-date", &amz_date)
        .header("x-amz-region-set", "*")
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
