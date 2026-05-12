//! Integration tests for ListMultipartUploads and ListParts (Step 24).

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use ferrox_gateway::router::build_router;
use ferrox_gateway::state::{AppState, GatewayConfig};
use ferrox_meta::SledMeta;
use ferrox_storage::disk::DiskBackend;
use tempfile::TempDir;
use tower::util::ServiceExt;

// ── shared test infra ────────────────────────────────────────────────────────

const AK: &str = "AKID";
const SK: &str = "SECRET";
const REGION: &str = "testregion";

async fn make_state() -> (TempDir, AppState<DiskBackend, SledMeta>) {
    let tmp = TempDir::new().unwrap();
    let storage = Arc::new(
        DiskBackend::new(tmp.path().join("data"), false)
            .await
            .unwrap(),
    );
    let meta = Arc::new(SledMeta::open(tmp.path().join("meta")).unwrap());
    let config = Arc::new(GatewayConfig {
        data_dir: tmp.path().to_path_buf(),
        access_key: AK.into(),
        secret_key: SK.into(),
        fsync: false,
        clock_skew_secs: 900,
        region: "testregion".into(),
        sse_master_key: None,
        max_sse_inline_bytes: 100 * 1024 * 1024,
        max_req_per_sec: 0,
    });
    (
        tmp,
        AppState {
            storage,
            meta,
            config,
            metrics: ferrox_gateway::metrics::Metrics::new().unwrap(),
            rate_limiter: None,
        },
    )
}

/// Build a SigV4-signed request. `body_bytes` used as body + for hash.
fn signed_request(
    method: &str,
    path_and_query: &str,
    headers_extra: Vec<(&str, &str)>,
    body_bytes: &[u8],
) -> Request<Body> {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    let now = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        time::OffsetDateTime::from_unix_timestamp(secs as i64).unwrap()
    };
    let date_str = format!("{:04}{:02}{:02}", now.year(), now.month() as u8, now.day());
    let datetime_str = format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );

    let body_hash = hex::encode(Sha256::digest(body_bytes));

    let (path, query) = if let Some(pos) = path_and_query.find('?') {
        (&path_and_query[..pos], &path_and_query[pos + 1..])
    } else {
        (path_and_query, "")
    };

    let host = "localhost";
    let mut all_headers: Vec<(String, String)> = vec![
        ("host".into(), host.into()),
        ("x-amz-date".into(), datetime_str.clone()),
        ("x-amz-content-sha256".into(), body_hash.clone()),
    ];
    for (k, v) in &headers_extra {
        all_headers.push((k.to_lowercase(), v.to_string()));
    }
    all_headers.sort_by(|a, b| a.0.cmp(&b.0));
    all_headers.dedup_by(|a, b| a.0 == b.0);

    let signed_headers: String = all_headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let canonical_headers: String = all_headers
        .iter()
        .map(|(k, v)| format!("{k}:{v}\n"))
        .collect();

    let canonical_query = if query.is_empty() {
        String::new()
    } else {
        let mut pairs: Vec<(&str, &str)> = query
            .split('&')
            .filter_map(|p| {
                let mut it = p.splitn(2, '=');
                let k = it.next()?;
                let v = it.next().unwrap_or("");
                Some((k, v))
            })
            .collect();
        pairs.sort();
        pairs
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&")
    };

    let canonical_request = format!(
        "{method}\n{path}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{body_hash}"
    );

    let scope = format!("{date_str}/{REGION}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{datetime_str}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    let signing_key = hmac_sha256(
        &hmac_sha256(
            &hmac_sha256(
                &hmac_sha256(format!("AWS4{SK}").as_bytes(), date_str.as_bytes()),
                REGION.as_bytes(),
            ),
            b"s3",
        ),
        b"aws4_request",
    );
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={AK}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    );

    let uri = if query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{query}")
    };

    let mut builder = Request::builder()
        .method(method)
        .uri(&uri)
        .header("host", host)
        .header("x-amz-date", &datetime_str)
        .header("x-amz-content-sha256", &body_hash)
        .header("authorization", &auth);
    for (k, v) in &headers_extra {
        builder = builder.header(*k, *v);
    }
    builder.body(Body::from(body_bytes.to_vec())).unwrap()
}

// ── tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_list_multipart_uploads_returns_empty_for_new_bucket() {
    let (_tmp, state) = make_state().await;
    let app = build_router(state);

    // Create bucket.
    let req = signed_request("PUT", "/test-bucket", vec![], b"");
    app.clone().oneshot(req).await.unwrap();

    // List uploads.
    let req = signed_request("GET", "/test-bucket?uploads", vec![], b"");
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 65536).await.unwrap();
    let xml = std::str::from_utf8(&body).unwrap();
    assert!(xml.contains("<ListMultipartUploadsResult"));
    assert!(xml.contains("<Bucket>test-bucket</Bucket>"));
    // No <Upload> elements expected.
    assert!(!xml.contains("<Upload>"));
}

#[tokio::test]
async fn test_list_multipart_uploads_shows_initiated_upload() {
    let (_tmp, state) = make_state().await;
    let app = build_router(state);

    // Create bucket.
    let req = signed_request("PUT", "/test-bucket", vec![], b"");
    app.clone().oneshot(req).await.unwrap();

    // Initiate upload.
    let req = signed_request("POST", "/test-bucket/my-key?uploads", vec![], b"");
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 65536).await.unwrap();
    let xml = std::str::from_utf8(&body).unwrap();
    let upload_id = xml
        .split("<UploadId>")
        .nth(1)
        .unwrap()
        .split("</UploadId>")
        .next()
        .unwrap()
        .to_string();

    // List uploads.
    let req = signed_request("GET", "/test-bucket?uploads", vec![], b"");
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 65536).await.unwrap();
    let xml = std::str::from_utf8(&body).unwrap();
    assert!(xml.contains("<Upload>"), "should contain an <Upload> entry");
    assert!(xml.contains(&upload_id), "should contain the upload ID");
    assert!(xml.contains("<Key>my-key</Key>"), "should contain the key");
}

#[tokio::test]
async fn test_list_parts_returns_uploaded_parts() {
    let (_tmp, state) = make_state().await;
    let app = build_router(state);

    // Create bucket.
    let req = signed_request("PUT", "/test-bucket", vec![], b"");
    app.clone().oneshot(req).await.unwrap();

    // Initiate upload.
    let req = signed_request("POST", "/test-bucket/my-key?uploads", vec![], b"");
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = to_bytes(resp.into_body(), 65536).await.unwrap();
    let xml = std::str::from_utf8(&body).unwrap();
    let upload_id = xml
        .split("<UploadId>")
        .nth(1)
        .unwrap()
        .split("</UploadId>")
        .next()
        .unwrap()
        .to_string();

    // Upload a part (5 MiB minimum in production, but our implementation
    // doesn't enforce minimum part size for testing purposes).
    let part_data = vec![b'A'; 1024];
    let req = signed_request(
        "PUT",
        &format!("/test-bucket/my-key?partNumber=1&uploadId={upload_id}"),
        vec![("content-length", &part_data.len().to_string())],
        &part_data,
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // List parts.
    let req = signed_request(
        "GET",
        &format!("/test-bucket/my-key?uploadId={upload_id}"),
        vec![],
        b"",
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 65536).await.unwrap();
    let xml = std::str::from_utf8(&body).unwrap();
    assert!(
        xml.contains("<ListPartsResult"),
        "XML should be ListPartsResult"
    );
    assert!(
        xml.contains("<PartNumber>1</PartNumber>"),
        "should list part 1"
    );
    assert!(
        xml.contains(&format!("<Size>{}</Size>", part_data.len())),
        "should show correct size"
    );
    assert!(xml.contains("<ETag>"), "should include ETag");
}

#[tokio::test]
async fn test_list_parts_unknown_upload_id_returns_not_found() {
    let (_tmp, state) = make_state().await;
    let app = build_router(state);

    // Create bucket.
    let req = signed_request("PUT", "/test-bucket", vec![], b"");
    app.clone().oneshot(req).await.unwrap();

    // List parts for non-existent upload.
    let req = signed_request(
        "GET",
        "/test-bucket/my-key?uploadId=does-not-exist",
        vec![],
        b"",
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_list_uploads_removed_after_complete() {
    let (_tmp, state) = make_state().await;
    let app = build_router(state);

    // Create bucket.
    let req = signed_request("PUT", "/test-bucket", vec![], b"");
    app.clone().oneshot(req).await.unwrap();

    // Initiate.
    let req = signed_request("POST", "/test-bucket/my-key?uploads", vec![], b"");
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = to_bytes(resp.into_body(), 65536).await.unwrap();
    let xml = std::str::from_utf8(&body).unwrap();
    let upload_id = xml
        .split("<UploadId>")
        .nth(1)
        .unwrap()
        .split("</UploadId>")
        .next()
        .unwrap()
        .to_string();

    // Upload one part.
    let part_data = vec![b'X'; 512];
    let req = signed_request(
        "PUT",
        &format!("/test-bucket/my-key?partNumber=1&uploadId={upload_id}"),
        vec![("content-length", &part_data.len().to_string())],
        &part_data,
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    let etag = resp
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Complete.
    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></CompleteMultipartUpload>"
    );
    let req = signed_request(
        "POST",
        &format!("/test-bucket/my-key?uploadId={upload_id}"),
        vec![("content-type", "application/xml")],
        complete_xml.as_bytes(),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // List uploads — should be empty now.
    let req = signed_request("GET", "/test-bucket?uploads", vec![], b"");
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 65536).await.unwrap();
    let xml = std::str::from_utf8(&body).unwrap();
    assert!(
        !xml.contains("<Upload>"),
        "completed upload should not appear in listing"
    );
}
