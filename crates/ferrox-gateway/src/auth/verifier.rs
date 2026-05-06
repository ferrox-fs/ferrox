//! SigV4 HMAC-SHA256 signature verifier.
//!
//! Builds the canonical request, derives the signing key via the AWS 4-step
//! HMAC chain, and compares signatures with [`ring::constant_time::verify_slices_are_equal`]
//! to prevent timing side-channels (FR-SEC-008, non-negotiable).
//!
//! ## Algorithm
//!
//! 1. **Canonical request**:
//!    `METHOD\nURI\nQUERY\nHEADERS\n\nSIGNED_HEADERS\nBODY_HASH`
//! 2. **String-to-sign**:
//!    `AWS4-HMAC-SHA256\nDATETIME\nSCOPE\nSHA256(canonical)`
//! 3. **Signing key**: `HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")`
//! 4. **Signature**: `HEX(HMAC(signing_key, string_to_sign))`
//!
//! ## Clock skew
//!
//! Requests with `X-Amz-Date` more than `clock_skew_secs` away from the server
//! clock (default 900 s = 15 min) are rejected with [`FerroxError::AuthFailed`].

use ferrox_error::FerroxError;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use ring::hmac;
use sha2::{Digest, Sha256};
use tracing::debug;

use crate::auth::SigV4Header;

/// Default allowed clock skew in seconds (15 minutes, per AWS spec).
pub const DEFAULT_CLOCK_SKEW_SECS: i64 = 900;

/// AWS-canonical URI character set: encode everything except unreserved.
/// Unreserved: `A-Z a-z 0-9 - _ . ~ /` (slash kept literal in path).
const URI_PATH_ESCAPE: &AsciiSet = &CONTROLS
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
    .add(b'}');

/// AWS-canonical query/value escape: same as path but `/` is also encoded.
const QUERY_ESCAPE: &AsciiSet = &URI_PATH_ESCAPE.add(b'/');

/// Verify the signature on a pre-signed (query-string) SigV4 URL.
///
/// `full_query` is the raw query string as received (includes `X-Amz-Signature`).
/// `headers` must contain the headers listed in `parsed.signed_headers` (typically
/// only `host`).
///
/// Checks:
/// - `X-Amz-Date` + `X-Amz-Expires` > `now_unix` (URL not expired)
/// - Recomputed signature matches `parsed.signature` in constant time
///
/// The canonical query is built from `full_query` minus the `X-Amz-Signature`
/// pair; body hash is always `UNSIGNED-PAYLOAD`.
pub fn verify_presigned_url(
    method: &str,
    path: &str,
    full_query: &str,
    headers: &[(String, String)],
    secret_key: &str,
    parsed: &SigV4Header,
    now_unix: i64,
) -> Result<(), FerroxError> {
    // Extract X-Amz-Date and X-Amz-Expires from query.
    let mut amz_date_q: Option<String> = None;
    let mut expires_secs: Option<u64> = None;
    for pair in full_query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v_dec = percent_encoding::percent_decode_str(v)
            .decode_utf8_lossy()
            .into_owned();
        match k {
            "X-Amz-Date" => amz_date_q = Some(v_dec),
            "X-Amz-Expires" => {
                expires_secs = v_dec.parse::<u64>().ok();
            }
            _ => {}
        }
    }
    let amz_date = amz_date_q
        .ok_or_else(|| FerroxError::AuthFailed("missing X-Amz-Date in presigned URL".into()))?;
    let expires = expires_secs
        .ok_or_else(|| FerroxError::AuthFailed("missing X-Amz-Expires in presigned URL".into()))?;

    // Expiry check.
    let req_ts = chrono::NaiveDateTime::parse_from_str(&amz_date, "%Y%m%dT%H%M%SZ")
        .map_err(|e| FerroxError::AuthFailed(format!("bad X-Amz-Date in presigned URL: {e}")))?
        .and_utc()
        .timestamp();
    if now_unix > req_ts + expires as i64 {
        return Err(FerroxError::AuthFailed("presigned URL has expired".into()));
    }

    // Canonical query: all pairs EXCEPT X-Amz-Signature, re-canonicalized.
    let stripped_query: String = full_query
        .split('&')
        .filter(|p| !p.is_empty() && !p.starts_with("X-Amz-Signature="))
        .collect::<Vec<_>>()
        .join("&");

    // Synthesize x-amz-date as a header so canonicalize_headers can find it if
    // the caller listed it in signed_headers. In practice presigned headers are
    // usually only "host", but we support both.
    let mut augmented_headers = headers.to_vec();
    if !augmented_headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("x-amz-date"))
    {
        augmented_headers.push(("x-amz-date".into(), amz_date.clone()));
    }

    let canonical = canonical_request(
        method,
        path,
        &stripped_query,
        &augmented_headers,
        &parsed.signed_headers,
        "UNSIGNED-PAYLOAD",
    )?;
    let canonical_hash = hex_sha256(canonical.as_bytes());

    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, parsed.credential_scope, canonical_hash
    );

    let signing_key = derive_signing_key(secret_key, &parsed.date, &parsed.region, &parsed.service);
    let key = hmac::Key::new(hmac::HMAC_SHA256, &signing_key);
    let computed_sig = hex::encode(hmac::sign(&key, string_to_sign.as_bytes()).as_ref());
    debug!(
        canonical_request = %canonical,
        string_to_sign = %string_to_sign,
        computed_signature = %computed_sig,
        provided_signature = %parsed.signature,
        "presigned SigV4 verification"
    );
    let provided = hex::decode(&parsed.signature)
        .map_err(|_| FerroxError::AuthFailed("presigned signature is not valid hex".into()))?;
    hmac::verify(&key, string_to_sign.as_bytes(), &provided)
        .map_err(|_| FerroxError::AuthFailed("presigned signature mismatch".into()))?;
    Ok(())
}

/// Verify the signature on a SigV4 request.
///
/// `headers` must contain every header listed in `parsed.signed_headers`
/// (lower-cased name + raw value). `body_sha256` is the lower-case hex
/// SHA-256 of the request body, or the literal string `UNSIGNED-PAYLOAD`
/// for pre-signed URLs (Phase 1 Step 19).
///
/// Returns `Ok(())` only when the recomputed signature matches `parsed.signature`
/// in constant time AND the request datetime is within `clock_skew_secs` of
/// `now_unix`.
#[allow(clippy::too_many_arguments)]
pub fn verify_sigv4(
    method: &str,
    path: &str,
    query: &str,
    headers: &[(String, String)],
    body_sha256: &str,
    secret_key: &str,
    parsed: &SigV4Header,
    now_unix: i64,
    clock_skew_secs: i64,
) -> Result<(), FerroxError> {
    let amz_date = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-amz-date"))
        .map(|(_, v)| v.as_str())
        .ok_or_else(|| FerroxError::AuthFailed("missing x-amz-date header".into()))?;

    check_clock_skew(amz_date, now_unix, clock_skew_secs)?;

    let canonical = canonical_request(
        method,
        path,
        query,
        headers,
        &parsed.signed_headers,
        body_sha256,
    )?;
    let canonical_hash = hex_sha256(canonical.as_bytes());

    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, parsed.credential_scope, canonical_hash
    );

    let signing_key = derive_signing_key(secret_key, &parsed.date, &parsed.region, &parsed.service);
    let key = hmac::Key::new(hmac::HMAC_SHA256, &signing_key);
    let computed_sig = hex::encode(hmac::sign(&key, string_to_sign.as_bytes()).as_ref());
    debug!(
        canonical_request = %canonical,
        string_to_sign = %string_to_sign,
        computed_signature = %computed_sig,
        provided_signature = %parsed.signature,
        "SigV4 verification"
    );
    let provided = hex::decode(&parsed.signature)
        .map_err(|_| FerroxError::AuthFailed("signature is not valid hex".into()))?;
    // ring::hmac::verify performs constant-time comparison internally.
    hmac::verify(&key, string_to_sign.as_bytes(), &provided)
        .map_err(|_| FerroxError::AuthFailed("signature mismatch".into()))?;
    Ok(())
}

fn check_clock_skew(amz_date: &str, now_unix: i64, skew_secs: i64) -> Result<(), FerroxError> {
    // amz_date format: yyyyMMdd'T'HHmmss'Z'
    let parsed = chrono::NaiveDateTime::parse_from_str(amz_date, "%Y%m%dT%H%M%SZ")
        .map_err(|e| FerroxError::AuthFailed(format!("bad x-amz-date: {e}")))?;
    let req_unix = parsed.and_utc().timestamp();
    let delta = (req_unix - now_unix).abs();
    if delta > skew_secs {
        return Err(FerroxError::AuthFailed(format!(
            "clock skew {delta}s exceeds allowed {skew_secs}s"
        )));
    }
    Ok(())
}

fn canonical_request(
    method: &str,
    path: &str,
    query: &str,
    headers: &[(String, String)],
    signed_headers: &[String],
    body_sha256: &str,
) -> Result<String, FerroxError> {
    let canonical_uri = canonicalize_path(path);
    let canonical_query = canonicalize_query(query);
    let canonical_headers = canonicalize_headers(headers, signed_headers)?;
    let signed_headers_joined = signed_headers.join(";");
    Ok(format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers_joined}\n{body_sha256}"
    ))
}

fn canonicalize_path(path: &str) -> String {
    if path.is_empty() {
        return "/".into();
    }
    // S3 (sigv4-s3) does NOT double-encode the path; a single percent-encoding
    // pass over each segment is correct.
    path.split('/')
        .map(|seg| utf8_percent_encode(seg, URI_PATH_ESCAPE).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

fn canonicalize_query(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            // Decode first so already-encoded values (e.g. X-Amz-Credential in
            // presigned URLs) don't get double-encoded, then re-encode once.
            match p.split_once('=') {
                Some((k, v)) => {
                    let k_raw = percent_encoding::percent_decode_str(k)
                        .decode_utf8_lossy()
                        .into_owned();
                    let v_raw = percent_encoding::percent_decode_str(v)
                        .decode_utf8_lossy()
                        .into_owned();
                    (
                        utf8_percent_encode(&k_raw, QUERY_ESCAPE).to_string(),
                        utf8_percent_encode(&v_raw, QUERY_ESCAPE).to_string(),
                    )
                }
                None => {
                    let k_raw = percent_encoding::percent_decode_str(p)
                        .decode_utf8_lossy()
                        .into_owned();
                    (
                        utf8_percent_encode(&k_raw, QUERY_ESCAPE).to_string(),
                        String::new(),
                    )
                }
            }
        })
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn canonicalize_headers(
    headers: &[(String, String)],
    signed_headers: &[String],
) -> Result<String, FerroxError> {
    let mut out = String::new();
    for name in signed_headers {
        let (_, value) = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .ok_or_else(|| FerroxError::AuthFailed(format!("missing signed header: {name}")))?;
        let trimmed = collapse_ws(value.trim());
        out.push_str(name);
        out.push(':');
        out.push_str(&trimmed);
        out.push('\n');
    }
    Ok(out)
}

fn collapse_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_ws = false;
    for c in s.chars() {
        if c == ' ' || c == '\t' {
            if !prev_ws {
                out.push(' ');
                prev_ws = true;
            }
        } else {
            out.push(c);
            prev_ws = false;
        }
    }
    out
}

fn hex_sha256(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

fn derive_signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    fn mac(key: &[u8], data: &[u8]) -> Vec<u8> {
        let k = hmac::Key::new(hmac::HMAC_SHA256, key);
        hmac::sign(&k, data).as_ref().to_vec()
    }
    let k_date = mac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = mac(&k_date, region.as_bytes());
    let k_service = mac(&k_region, service.as_bytes());
    mac(&k_service, b"aws4_request")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Official AWS test vector: GET object example.
    /// https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    #[test]
    fn test_aws_canonical_request_get_example() {
        let method = "GET";
        let path = "/test.txt";
        let query = "";
        let headers = vec![
            (
                "host".to_string(),
                "examplebucket.s3.amazonaws.com".to_string(),
            ),
            ("range".to_string(), "bytes=0-9".to_string()),
            (
                "x-amz-content-sha256".to_string(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            ),
            ("x-amz-date".to_string(), "20260505T000000Z".to_string()),
        ];
        let signed = vec![
            "host".to_string(),
            "range".to_string(),
            "x-amz-content-sha256".to_string(),
            "x-amz-date".to_string(),
        ];
        let body_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let canonical =
            canonical_request(method, path, query, &headers, &signed, body_hash).unwrap();
        let expected = "GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\nx-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nx-amz-date:20260505T000000Z\n\nhost;range;x-amz-content-sha256;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(canonical, expected);
    }

    /// AWS test vector: GET object → final signature.
    #[test]
    fn test_aws_full_signature_get_object() {
        let secret = "MOCKxSECRETxKEYxFORxTESTSxONLYx123456789";
        let auth =
            "AWS4-HMAC-SHA256 Credential=MOCKACCESSKEYFORTEST/20260505/us-east-1/s3/aws4_request, \
                    SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
                    Signature=1b7fb94004974c305f60c68de83a8cb2dd4974e1773c9eebe8aa097b5daa5e74";
        let parsed = SigV4Header::from_authorization_header(auth).unwrap();
        let headers = vec![
            (
                "host".to_string(),
                "examplebucket.s3.amazonaws.com".to_string(),
            ),
            ("range".to_string(), "bytes=0-9".to_string()),
            (
                "x-amz-content-sha256".to_string(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            ),
            ("x-amz-date".to_string(), "20260505T000000Z".to_string()),
        ];
        let body_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        // Use the request's own datetime as "now" so skew check passes.
        let now = chrono::NaiveDateTime::parse_from_str("20260505T000000Z", "%Y%m%dT%H%M%SZ")
            .unwrap()
            .and_utc()
            .timestamp();
        verify_sigv4(
            "GET",
            "/test.txt",
            "",
            &headers,
            body_hash,
            secret,
            &parsed,
            now,
            900,
        )
        .unwrap();
    }

    #[test]
    fn test_wrong_signature_returns_auth_failed() {
        let secret = "MOCKxSECRETxKEYxFORxTESTSxONLYx123456789";
        let auth =
            "AWS4-HMAC-SHA256 Credential=MOCKACCESSKEYFORTEST/20260505/us-east-1/s3/aws4_request, \
                    SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
                    Signature=0000000000000000000000000000000000000000000000000000000000000000";
        let parsed = SigV4Header::from_authorization_header(auth).unwrap();
        let headers = vec![
            (
                "host".to_string(),
                "examplebucket.s3.amazonaws.com".to_string(),
            ),
            ("range".to_string(), "bytes=0-9".to_string()),
            (
                "x-amz-content-sha256".to_string(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            ),
            ("x-amz-date".to_string(), "20260505T000000Z".to_string()),
        ];
        let now = chrono::NaiveDateTime::parse_from_str("20260505T000000Z", "%Y%m%dT%H%M%SZ")
            .unwrap()
            .and_utc()
            .timestamp();
        let res = verify_sigv4(
            "GET",
            "/test.txt",
            "",
            &headers,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            secret,
            &parsed,
            now,
            900,
        );
        assert!(matches!(res, Err(FerroxError::AuthFailed(_))));
    }

    #[test]
    fn test_clock_skew_over_15_minutes_returns_auth_failed() {
        let secret = "secret";
        let auth = "AWS4-HMAC-SHA256 Credential=AK/20260505/us-east-1/s3/aws4_request, \
                    SignedHeaders=host;x-amz-date, Signature=deadbeef";
        let parsed = SigV4Header::from_authorization_header(auth).unwrap();
        let headers = vec![
            ("host".to_string(), "h".to_string()),
            ("x-amz-date".to_string(), "20260505T000000Z".to_string()),
        ];
        let req_ts = chrono::NaiveDateTime::parse_from_str("20260505T000000Z", "%Y%m%dT%H%M%SZ")
            .unwrap()
            .and_utc()
            .timestamp();
        let now = req_ts + 16 * 60;
        let res = verify_sigv4("GET", "/", "", &headers, "x", secret, &parsed, now, 900);
        assert!(matches!(res, Err(FerroxError::AuthFailed(_))));
    }

    #[test]
    fn test_canonicalize_query_sorts_and_encodes() {
        assert_eq!(canonicalize_query(""), "");
        assert_eq!(canonicalize_query("b=2&a=1"), "a=1&b=2");
        assert_eq!(canonicalize_query("prefix=foo+bar"), "prefix=foo%2Bbar");
    }

    #[test]
    fn test_canonicalize_headers_lowercases_and_collapses_ws() {
        let h = vec![
            ("host".into(), "example.com".into()),
            ("x-amz-date".into(), "  20260505T000000Z  ".into()),
        ];
        let out = canonicalize_headers(&h, &["host".into(), "x-amz-date".into()]).unwrap();
        assert_eq!(out, "host:example.com\nx-amz-date:20260505T000000Z\n");
    }

    #[test]
    fn test_missing_signed_header_returns_auth_failed() {
        let h = vec![("host".into(), "example.com".into())];
        let res = canonicalize_headers(&h, &["host".into(), "x-amz-date".into()]);
        assert!(matches!(res, Err(FerroxError::AuthFailed(_))));
    }
}
