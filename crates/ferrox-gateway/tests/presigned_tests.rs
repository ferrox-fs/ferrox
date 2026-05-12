//! Integration tests for pre-signed URL SigV4 authentication (Step 19).

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

/// Build a presigned query string for the given method + path + expires.
/// Returns the query string (without leading '?').
fn presign(method: &str, path: &str, host: &str, amz_date: &str, expires: u64) -> String {
    let date = &amz_date[..8];
    let scope = format!("{date}/{REGION}/{SERVICE}/aws4_request");
    let credential = format!("{ACCESS_KEY}/{scope}");
    let signed_headers = "host";

    // Build the canonical query WITHOUT X-Amz-Signature (per spec).
    let mut pre_query = format!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256\
         &X-Amz-Credential={}\
         &X-Amz-Date={}\
         &X-Amz-Expires={}\
         &X-Amz-SignedHeaders={}",
        percent_encode(&credential),
        amz_date,
        expires,
        signed_headers,
    );

    // Sort pairs for canonical query.
    let mut pairs: Vec<(String, String)> = pre_query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (k.to_string(), v.to_string())
        })
        .collect();
    pairs.sort();
    let canonical_query: String = pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");

    let canonical_headers = format!("host:{host}\n");
    let canonical = format!(
        "{method}\n{path}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\nUNSIGNED-PAYLOAD"
    );
    let canonical_hash = hex_sha256(canonical.as_bytes());
    let sts = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{canonical_hash}");

    let k_date = mac(format!("AWS4{SECRET_KEY}").as_bytes(), date.as_bytes());
    let k_region = mac(&k_date, REGION.as_bytes());
    let k_service = mac(&k_region, SERVICE.as_bytes());
    let k_signing = mac(&k_service, b"aws4_request");
    let sig = hex::encode(mac(&k_signing, sts.as_bytes()));

    // Re-build pre_query with sorted canonical form + append Signature at end.
    pre_query = canonical_query;
    format!("{pre_query}&X-Amz-Signature={sig}")
}

fn percent_encode(s: &str) -> String {
    use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
    // Same set as verifier::QUERY_ESCAPE: encode everything except unreserved
    // (A-Z a-z 0-9 - _ . ~) and also encode /.
    const AWS_QS: &AsciiSet = &CONTROLS
        .add(b' ')
        .add(b'!')
        .add(b'"')
        .add(b'#')
        .add(b'$')
        .add(b'%')
        .add(b'&')
        .add(b'\'')
        .add(b'(')
        .add(b')')
        .add(b'*')
        .add(b'+')
        .add(b',')
        .add(b':')
        .add(b';')
        .add(b'<')
        .add(b'=')
        .add(b'>')
        .add(b'?')
        .add(b'@')
        .add(b'[')
        .add(b'\\')
        .add(b']')
        .add(b'^')
        .add(b'`')
        .add(b'{')
        .add(b'|')
        .add(b'}')
        .add(b'/');
    utf8_percent_encode(s, AWS_QS).to_string()
}

/// Helper: PUT an object using header auth (not presigned) so we can GET it later.
async fn put_object_header_auth(app: axum::Router, bucket: &str, key: &str, data: &[u8]) {
    // First create the bucket.
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let date = &amz_date[..8];
    let _scope = format!("{date}/{REGION}/{SERVICE}/aws4_request");

    let bucket_path = format!("/{bucket}");
    let auth_bucket = make_auth("PUT", &bucket_path, "localhost", &amz_date, EMPTY_SHA, &[]);
    let req = Request::builder()
        .uri(&bucket_path)
        .method("PUT")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", EMPTY_SHA)
        .header("authorization", auth_bucket)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "create bucket");

    // Put the object.
    let body_sha = hex_sha256(data);
    let obj_path = format!("/{bucket}/{key}");
    let auth_put = make_auth(
        "PUT",
        &obj_path,
        "localhost",
        &amz_date,
        &body_sha,
        &[("content-length", &data.len().to_string())],
    );
    let req2 = Request::builder()
        .uri(&obj_path)
        .method("PUT")
        .header("host", "localhost")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", &body_sha)
        .header("content-length", data.len().to_string())
        .header("authorization", auth_put)
        .body(Body::from(data.to_vec()))
        .unwrap();
    let resp2 = app.oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK, "put object");
}

fn make_auth(
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
async fn test_presigned_get_object_returns_200() {
    let env = make_env().await;
    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new().unwrap(),
        rate_limiter: None,
    });

    let data = b"hello presigned";
    put_object_header_auth(app.clone(), "mybucket", "mykey", data).await;

    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let qs = presign("GET", "/mybucket/mykey", "localhost", &amz_date, 3600);
    let uri = format!("/mybucket/mykey?{qs}");
    let req = Request::builder()
        .uri(&uri)
        .method("GET")
        .header("host", "localhost")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(body.as_ref(), data);
}

#[tokio::test]
async fn test_presigned_expired_url_returns_403() {
    let env = make_env().await;
    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new().unwrap(),
        rate_limiter: None,
    });

    // Use a date 2 hours in the past with expires=1 second.
    let past = chrono::Utc::now() - chrono::Duration::hours(2);
    let amz_date = past.format("%Y%m%dT%H%M%SZ").to_string();
    let qs = presign("GET", "/any-bucket/any-key", "localhost", &amz_date, 1);
    let uri = format!("/any-bucket/any-key?{qs}");
    let req = Request::builder()
        .uri(&uri)
        .method("GET")
        .header("host", "localhost")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_presigned_wrong_signature_returns_403() {
    let env = make_env().await;
    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new().unwrap(),
        rate_limiter: None,
    });

    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let date = &amz_date[..8];
    let credential = percent_encode(&format!(
        "{ACCESS_KEY}/{date}/{REGION}/{SERVICE}/aws4_request"
    ));
    let qs = format!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256\
         &X-Amz-Credential={credential}\
         &X-Amz-Date={amz_date}\
         &X-Amz-Expires=3600\
         &X-Amz-SignedHeaders=host\
         &X-Amz-Signature={}",
        "0".repeat(64)
    );
    let uri = format!("/any-bucket/any-key?{qs}");
    let req = Request::builder()
        .uri(&uri)
        .method("GET")
        .header("host", "localhost")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
