//! Integration tests for PutBucketVersioning and GetBucketVersioning (Step 18).

use std::sync::Arc;

use axum::body::{to_bytes, Body};
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
const REGION: &str = "us-east-1";
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

#[allow(clippy::too_many_arguments)]
fn sign_with_query(
    method: &str,
    path: &str,
    query: &str,
    host: &str,
    amz_date: &str,
    body_sha: &str,
    body: &[u8],
    extra: &[(&str, &str)],
) -> String {
    let _ = body; // body_sha already computed by caller
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
    let canonical_query = canonical_query_string(query);
    let canonical = format!(
        "{method}\n{path}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{body_sha}"
    );
    let canonical_hash = hex_sha256(canonical.as_bytes());
    let sts = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{canonical_hash}");
    let k_date = mac(format!("AWS4{SECRET_KEY}").as_bytes(), date.as_bytes());
    let k_region = mac(&k_date, REGION.as_bytes());
    let k_service = mac(&k_region, SERVICE.as_bytes());
    let k_signing = mac(&k_service, b"aws4_request");
    let sig = hex::encode(mac(&k_signing, sts.as_bytes()));
    format!("AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/{scope}, SignedHeaders={signed_headers}, Signature={sig}")
}

fn canonical_query_string(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .map(|pair| {
            let mut it = pair.splitn(2, '=');
            let k = it.next().unwrap_or("").to_string();
            let v = it.next().unwrap_or("").to_string();
            (k, v)
        })
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn sign(
    method: &str,
    path: &str,
    host: &str,
    amz_date: &str,
    body_sha: &str,
    extra: &[(&str, &str)],
) -> String {
    sign_with_query(method, path, "", host, amz_date, body_sha, &[], extra)
}

/// Helper: create a bucket synchronously (PUT /{bucket}).
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
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "pre-condition: create_bucket"
    );
}

#[tokio::test]
async fn test_get_bucket_versioning_unset_returns_empty_status() {
    let env = make_env().await;
    let meta = env.meta.clone();
    let app = build_router(AppState {
        storage: env.storage,
        meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new(),
        rate_limiter: None,
    });

    create_bucket(app.clone(), "ver-bucket").await;

    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let auth = sign_with_query(
        "GET",
        "/ver-bucket",
        "versioning",
        "localhost",
        &amz_date,
        EMPTY_SHA,
        &[],
        &[],
    );
    let req = Request::builder()
        .uri("/ver-bucket?versioning")
        .method("GET")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", EMPTY_SHA)
        .header("authorization", auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let xml = String::from_utf8(body.to_vec()).unwrap();
    assert!(xml.contains("<VersioningConfiguration"), "got: {xml}");
    // No <Status> when versioning was never set
    assert!(!xml.contains("<Status>"), "got: {xml}");
}

#[tokio::test]
async fn test_put_bucket_versioning_enabled_roundtrip() {
    let env = make_env().await;
    let meta = env.meta.clone();
    let app = build_router(AppState {
        storage: env.storage,
        meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new(),
        rate_limiter: None,
    });

    create_bucket(app.clone(), "ver-bucket2").await;

    // Enable versioning
    let xml_body = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
<Status>Enabled</Status>\
</VersioningConfiguration>";
    let body_sha = hex_sha256(xml_body);
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let auth = sign_with_query(
        "PUT",
        "/ver-bucket2",
        "versioning",
        "localhost",
        &amz_date,
        &body_sha,
        xml_body,
        &[("content-type", "application/xml")],
    );
    let req = Request::builder()
        .uri("/ver-bucket2?versioning")
        .method("PUT")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", &body_sha)
        .header("content-type", "application/xml")
        .header("authorization", auth)
        .body(Body::from(xml_body.as_ref()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "PUT versioning Enabled");

    // Read it back
    let amz_date2 = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let auth2 = sign_with_query(
        "GET",
        "/ver-bucket2",
        "versioning",
        "localhost",
        &amz_date2,
        EMPTY_SHA,
        &[],
        &[],
    );
    let req2 = Request::builder()
        .uri("/ver-bucket2?versioning")
        .method("GET")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date2)
        .header("x-amz-content-sha256", EMPTY_SHA)
        .header("authorization", auth2)
        .body(Body::empty())
        .unwrap();
    let resp2 = app.oneshot(req2).await.unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::OK,
        "GET versioning after enable"
    );
    let body2 = to_bytes(resp2.into_body(), usize::MAX).await.unwrap();
    let xml2 = String::from_utf8(body2.to_vec()).unwrap();
    assert!(xml2.contains("<Status>Enabled</Status>"), "got: {xml2}");
}

#[tokio::test]
async fn test_put_bucket_versioning_nonexistent_bucket_returns_404() {
    let env = make_env().await;
    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new(),
        rate_limiter: None,
    });

    let xml_body = b"<?xml version=\"1.0\"?><VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>";
    let body_sha = hex_sha256(xml_body);
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let auth = sign_with_query(
        "PUT",
        "/no-such-bucket",
        "versioning",
        "localhost",
        &amz_date,
        &body_sha,
        xml_body,
        &[],
    );
    let req = Request::builder()
        .uri("/no-such-bucket?versioning")
        .method("PUT")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", &body_sha)
        .header("authorization", auth)
        .body(Body::from(xml_body.as_ref()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
