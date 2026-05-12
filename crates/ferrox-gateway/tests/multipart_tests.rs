//! Integration tests for multipart upload (Step 17).

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
        region: "testregion".into(),
        sse_master_key: None,
        max_sse_inline_bytes: 100 * 1024 * 1024,
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

fn canonical_query(qs: &str) -> String {
    if qs.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(String, String)> = qs
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (p.to_string(), String::new()),
        })
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn sign(
    method: &str,
    path_and_query: &str,
    host: &str,
    amz_date: &str,
    body_sha: &str,
    extra: &[(&str, &str)],
) -> String {
    let (path, query) = path_and_query
        .split_once('?')
        .unwrap_or((path_and_query, ""));
    let canon_query = canonical_query(query);
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
    let canonical = format!(
        "{method}\n{path}\n{canon_query}\n{canonical_headers}\n{signed_headers}\n{body_sha}"
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

fn extract_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml.find(&close)?;
    Some(xml[start..end].to_string())
}

#[tokio::test]
async fn test_full_multipart_upload_three_parts() {
    let env = make_env().await;
    env.storage.create_bucket("mp-bucket").await.unwrap();

    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new().unwrap(),
        rate_limiter: None,
    });

    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();

    // 1. Initiate
    let init_auth = sign(
        "POST",
        "/mp-bucket/big.bin?uploads",
        "localhost",
        &amz_date,
        EMPTY_SHA,
        &[],
    );
    let init_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/mp-bucket/big.bin?uploads")
                .method("POST")
                .header("host", "localhost")
                .header("x-amz-date", &amz_date)
                .header("x-amz-content-sha256", EMPTY_SHA)
                .header("authorization", init_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(init_resp.status(), StatusCode::OK);
    let body = to_bytes(init_resp.into_body(), usize::MAX).await.unwrap();
    let xml = String::from_utf8(body.to_vec()).unwrap();
    let upload_id = extract_text(&xml, "UploadId").expect("UploadId in XML");

    // 2. Upload 3 parts.
    //
    // Production rule (AWS-spec): every non-final part must be at least 5 MiB.
    // Parts 1 and 2 are sized to the minimum; part 3 (the last) can be small.
    let mut part_etags = Vec::new();
    for i in 1u32..=3 {
        let part_size = if i < 3 { 5 * 1024 * 1024 } else { 1024 };
        let part_data: Vec<u8> = vec![b'A' + (i as u8 - 1); part_size];
        let part_sha = hex_sha256(&part_data);
        let uri = format!("/mp-bucket/big.bin?partNumber={i}&uploadId={upload_id}");
        let auth = sign(
            "PUT",
            &uri,
            "localhost",
            &amz_date,
            &part_sha,
            &[("content-length", &part_data.len().to_string())],
        );
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&uri)
                    .method("PUT")
                    .header("host", "localhost")
                    .header("x-amz-date", &amz_date)
                    .header("x-amz-content-sha256", &part_sha)
                    .header("content-length", part_data.len().to_string())
                    .header("authorization", auth)
                    .body(Body::from(part_data))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "upload part {i}");
        let etag = resp
            .headers()
            .get("etag")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        part_etags.push((i, etag));
    }

    // 3. Complete
    let complete_xml = format!(
        "<CompleteMultipartUpload>{}</CompleteMultipartUpload>",
        part_etags
            .iter()
            .map(|(n, e)| format!("<Part><PartNumber>{n}</PartNumber><ETag>{e}</ETag></Part>"))
            .collect::<String>()
    );
    let complete_sha = hex_sha256(complete_xml.as_bytes());
    let complete_uri = format!("/mp-bucket/big.bin?uploadId={upload_id}");
    let complete_auth = sign(
        "POST",
        &complete_uri,
        "localhost",
        &amz_date,
        &complete_sha,
        &[("content-length", &complete_xml.len().to_string())],
    );
    let complete_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&complete_uri)
                .method("POST")
                .header("host", "localhost")
                .header("x-amz-date", &amz_date)
                .header("x-amz-content-sha256", &complete_sha)
                .header("content-length", complete_xml.len().to_string())
                .header("authorization", complete_auth)
                .body(Body::from(complete_xml))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(complete_resp.status(), StatusCode::OK);
    let cbody = to_bytes(complete_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let cxml = String::from_utf8(cbody.to_vec()).unwrap();
    assert!(cxml.contains("CompleteMultipartUploadResult"));

    // 4. GET the assembled object — should be 5 MiB + 5 MiB + 1024 bytes.
    let get_auth = sign(
        "GET",
        "/mp-bucket/big.bin",
        "localhost",
        &amz_date,
        EMPTY_SHA,
        &[],
    );
    let get_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/mp-bucket/big.bin")
                .method("GET")
                .header("host", "localhost")
                .header("x-amz-date", &amz_date)
                .header("x-amz-content-sha256", EMPTY_SHA)
                .header("authorization", get_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK);
    let gbody = to_bytes(get_resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(gbody.len(), 2 * 5 * 1024 * 1024 + 1024);
}

#[tokio::test]
async fn test_complete_multipart_rejects_small_non_final_part() {
    // AWS-spec: every multipart part except the LAST must be at least 5 MiB.
    // Two parts at 1 KiB → the first is non-final and too small → EntityTooSmall.
    let env = make_env().await;
    env.storage
        .create_bucket("small-part-bucket")
        .await
        .unwrap();
    env.meta
        .create_bucket("small-part-bucket", ACCESS_KEY)
        .await
        .unwrap();

    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new().unwrap(),
        rate_limiter: None,
    });

    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();

    // Initiate.
    let init_auth = sign(
        "POST",
        "/small-part-bucket/obj?uploads",
        "localhost",
        &amz_date,
        EMPTY_SHA,
        &[],
    );
    let init_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/small-part-bucket/obj?uploads")
                .method("POST")
                .header("host", "localhost")
                .header("x-amz-date", &amz_date)
                .header("x-amz-content-sha256", EMPTY_SHA)
                .header("authorization", init_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = to_bytes(init_resp.into_body(), usize::MAX).await.unwrap();
    let xml = String::from_utf8(body.to_vec()).unwrap();
    let upload_id = extract_text(&xml, "UploadId").unwrap();

    // Upload two 1 KiB parts.
    let mut part_etags = Vec::new();
    for i in 1u32..=2 {
        let part_data: Vec<u8> = vec![b'A' + (i as u8 - 1); 1024];
        let part_sha = hex_sha256(&part_data);
        let uri = format!("/small-part-bucket/obj?partNumber={i}&uploadId={upload_id}");
        let auth = sign(
            "PUT",
            &uri,
            "localhost",
            &amz_date,
            &part_sha,
            &[("content-length", &part_data.len().to_string())],
        );
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&uri)
                    .method("PUT")
                    .header("host", "localhost")
                    .header("x-amz-date", &amz_date)
                    .header("x-amz-content-sha256", &part_sha)
                    .header("content-length", part_data.len().to_string())
                    .header("authorization", auth)
                    .body(Body::from(part_data))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "upload part {i}");
        let etag = resp
            .headers()
            .get("etag")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        part_etags.push((i, etag));
    }

    // Complete — must be rejected because part 1 is non-final and < 5 MiB.
    let complete_xml = format!(
        "<CompleteMultipartUpload>{}</CompleteMultipartUpload>",
        part_etags
            .iter()
            .map(|(n, e)| format!("<Part><PartNumber>{n}</PartNumber><ETag>{e}</ETag></Part>"))
            .collect::<String>()
    );
    let complete_sha = hex_sha256(complete_xml.as_bytes());
    let complete_uri = format!("/small-part-bucket/obj?uploadId={upload_id}");
    let complete_auth = sign(
        "POST",
        &complete_uri,
        "localhost",
        &amz_date,
        &complete_sha,
        &[("content-length", &complete_xml.len().to_string())],
    );
    let complete_resp = app
        .oneshot(
            Request::builder()
                .uri(&complete_uri)
                .method("POST")
                .header("host", "localhost")
                .header("x-amz-date", &amz_date)
                .header("x-amz-content-sha256", &complete_sha)
                .header("content-length", complete_xml.len().to_string())
                .header("authorization", complete_auth)
                .body(Body::from(complete_xml))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(complete_resp.status(), StatusCode::BAD_REQUEST);
    let cbody = to_bytes(complete_resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let cxml = String::from_utf8_lossy(&cbody);
    assert!(
        cxml.contains("EntityTooSmall"),
        "expected EntityTooSmall, got: {cxml}"
    );
}

#[tokio::test]
async fn test_upload_part_rejects_invalid_part_number() {
    let env = make_env().await;
    env.storage.create_bucket("pn-bucket").await.unwrap();
    env.meta
        .create_bucket("pn-bucket", ACCESS_KEY)
        .await
        .unwrap();

    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new().unwrap(),
        rate_limiter: None,
    });
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let init_auth = sign(
        "POST",
        "/pn-bucket/obj?uploads",
        "localhost",
        &amz_date,
        EMPTY_SHA,
        &[],
    );
    let init_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/pn-bucket/obj?uploads")
                .method("POST")
                .header("host", "localhost")
                .header("x-amz-date", &amz_date)
                .header("x-amz-content-sha256", EMPTY_SHA)
                .header("authorization", init_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = to_bytes(init_resp.into_body(), usize::MAX).await.unwrap();
    let xml = String::from_utf8(body.to_vec()).unwrap();
    let upload_id = extract_text(&xml, "UploadId").unwrap();

    // partNumber 10001 is one past the AWS-spec maximum.
    let part_data = vec![0u8; 16];
    let part_sha = hex_sha256(&part_data);
    let uri = format!("/pn-bucket/obj?partNumber=10001&uploadId={upload_id}");
    let auth = sign(
        "PUT",
        &uri,
        "localhost",
        &amz_date,
        &part_sha,
        &[("content-length", &part_data.len().to_string())],
    );
    let resp = app
        .oneshot(
            Request::builder()
                .uri(&uri)
                .method("PUT")
                .header("host", "localhost")
                .header("x-amz-date", &amz_date)
                .header("x-amz-content-sha256", &part_sha)
                .header("content-length", part_data.len().to_string())
                .header("authorization", auth)
                .body(Body::from(part_data))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_abort_multipart_cleans_staging() {
    let env = make_env().await;
    env.storage.create_bucket("abort-bucket").await.unwrap();

    let app = build_router(AppState {
        storage: env.storage,
        meta: env.meta,
        config: env.config,
        metrics: ferrox_gateway::metrics::Metrics::new().unwrap(),
        rate_limiter: None,
    });

    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();

    // Initiate
    let init_auth = sign(
        "POST",
        "/abort-bucket/obj?uploads",
        "localhost",
        &amz_date,
        EMPTY_SHA,
        &[],
    );
    let init_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/abort-bucket/obj?uploads")
                .method("POST")
                .header("host", "localhost")
                .header("x-amz-date", &amz_date)
                .header("x-amz-content-sha256", EMPTY_SHA)
                .header("authorization", init_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(init_resp.status(), StatusCode::OK);
    let body = to_bytes(init_resp.into_body(), usize::MAX).await.unwrap();
    let xml = String::from_utf8(body.to_vec()).unwrap();
    let upload_id = extract_text(&xml, "UploadId").unwrap();

    // Abort
    let abort_uri = format!("/abort-bucket/obj?uploadId={upload_id}");
    let abort_auth = sign("DELETE", &abort_uri, "localhost", &amz_date, EMPTY_SHA, &[]);
    let abort_resp = app
        .oneshot(
            Request::builder()
                .uri(&abort_uri)
                .method("DELETE")
                .header("host", "localhost")
                .header("x-amz-date", &amz_date)
                .header("x-amz-content-sha256", EMPTY_SHA)
                .header("authorization", abort_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(abort_resp.status(), StatusCode::NO_CONTENT);
}
