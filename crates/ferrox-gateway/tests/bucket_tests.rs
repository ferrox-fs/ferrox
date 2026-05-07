//! Integration tests for bucket CRUD and DeleteObject handlers (Step 13).

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use ferrox_gateway::router::build_router;
use ferrox_gateway::state::{AppState, GatewayConfig};
use ferrox_meta::{MetaStore, SledMeta};
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

#[tokio::test]
async fn test_create_bucket_returns_200() {
    let env = make_env().await;
    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new(),
        rate_limiter: None,
    });

    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let auth = sign("PUT", "/new-bucket", "localhost", &amz_date, EMPTY_SHA, &[]);
    let req = Request::builder()
        .uri("/new-bucket")
        .method("PUT")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", EMPTY_SHA)
        .header("authorization", auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().contains_key("location"));
}

#[tokio::test]
async fn test_head_bucket_exists_returns_200() {
    let env = make_env().await;
    env.storage.create_bucket("my-bucket").await.unwrap();

    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new(),
        rate_limiter: None,
    });

    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let auth = sign("HEAD", "/my-bucket", "localhost", &amz_date, EMPTY_SHA, &[]);
    let req = Request::builder()
        .uri("/my-bucket")
        .method("HEAD")
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
async fn test_head_bucket_missing_returns_404() {
    let env = make_env().await;
    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new(),
        rate_limiter: None,
    });

    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let auth = sign("HEAD", "/no-bucket", "localhost", &amz_date, EMPTY_SHA, &[]);
    let req = Request::builder()
        .uri("/no-bucket")
        .method("HEAD")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", EMPTY_SHA)
        .header("authorization", auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_empty_bucket_returns_204() {
    let env = make_env().await;
    env.storage.create_bucket("empty-bucket").await.unwrap();
    env.meta
        .create_bucket("empty-bucket", ACCESS_KEY)
        .await
        .unwrap();

    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new(),
        rate_limiter: None,
    });

    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let auth = sign(
        "DELETE",
        "/empty-bucket",
        "localhost",
        &amz_date,
        EMPTY_SHA,
        &[],
    );
    let req = Request::builder()
        .uri("/empty-bucket")
        .method("DELETE")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", EMPTY_SHA)
        .header("authorization", auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_list_buckets_returns_xml() {
    let env = make_env().await;
    env.storage.create_bucket("alpha-bucket").await.unwrap();
    env.meta
        .create_bucket("alpha-bucket", ACCESS_KEY)
        .await
        .unwrap();

    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new(),
        rate_limiter: None,
    });

    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let auth = sign("GET", "/", "localhost", &amz_date, EMPTY_SHA, &[]);
    let req = Request::builder()
        .uri("/")
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
    let xml = std::str::from_utf8(&body).unwrap();
    assert!(xml.contains("ListAllMyBucketsResult"));
    assert!(xml.contains("alpha-bucket"));
}

#[tokio::test]
async fn test_delete_object_returns_204() {
    let env = make_env().await;
    env.storage.create_bucket("del-bucket").await.unwrap();
    env.meta
        .create_bucket("del-bucket", ACCESS_KEY)
        .await
        .unwrap();

    let body_bytes = b"delete me";
    let body_sha = hex_sha256(body_bytes);
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let put_auth = sign(
        "PUT",
        "/del-bucket/obj.txt",
        "localhost",
        &amz_date,
        &body_sha,
        &[("content-length", &body_bytes.len().to_string())],
    );

    let app = build_router(AppState {
        storage: env.storage.clone(),
        meta: env.meta.clone(),
        config: env.config.clone(),
        metrics: ferrox_gateway::metrics::Metrics::new(),
        rate_limiter: None,
    });

    let put_req = Request::builder()
        .uri("/del-bucket/obj.txt")
        .method("PUT")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", &body_sha)
        .header("content-length", body_bytes.len().to_string())
        .header("authorization", put_auth)
        .body(Body::from(body_bytes.as_ref()))
        .unwrap();
    let put_resp = app.clone().oneshot(put_req).await.unwrap();
    assert_eq!(put_resp.status(), StatusCode::OK);

    let del_auth = sign(
        "DELETE",
        "/del-bucket/obj.txt",
        "localhost",
        &amz_date,
        EMPTY_SHA,
        &[],
    );
    let del_req = Request::builder()
        .uri("/del-bucket/obj.txt")
        .method("DELETE")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", EMPTY_SHA)
        .header("authorization", del_auth)
        .body(Body::empty())
        .unwrap();
    let del_resp = app.oneshot(del_req).await.unwrap();
    assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);
}
