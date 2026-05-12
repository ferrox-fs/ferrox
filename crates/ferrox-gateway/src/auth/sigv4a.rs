//! SigV4A — multi-region ECDSA P-256 / SHA-256 AWS request signing.
//!
//! SigV4A differs from SigV4 in three ways:
//!
//! 1. The signing key is an ECDSA P-256 keypair derived deterministically
//!    from `(secret_access_key, access_key_id)` via the AWS SP800-108
//!    counter-mode KDF (see [`derive_sigv4a_signing_key`]). One signature
//!    is therefore valid across multiple regions.
//! 2. The credential scope drops the region:
//!    `AKID/YYYYMMDD/{service}/aws4_request`.
//! 3. The request region travels in the signed `x-amz-region-set` header
//!    (or `X-Amz-Region-Set` query param for presigned URLs). The header
//!    accepts a comma-separated list, with `*` and trailing `*` wildcards.
//!
//! Verification flow:
//!
//! 1. Parse `Authorization: AWS4-ECDSA-P256-SHA256 …` (or query params).
//! 2. Require `x-amz-date` and `x-amz-region-set` to be present **and**
//!    listed in `SignedHeaders`.
//! 3. Reject clock skew over the configured limit.
//! 4. Match the request region against the signed region-set.
//! 5. Build the canonical request using the same construction as SigV4
//!    (shared via [`crate::auth::verifier`]).
//! 6. Build the string-to-sign with the `AWS4-ECDSA-P256-SHA256` prefix.
//! 7. Derive the P-256 verifying key from the secret + access key id.
//! 8. Verify the DER-encoded ECDSA signature.

use ferrox_error::FerroxError;
use hmac::{Hmac, Mac};
use p256::ecdsa::{signature::Verifier, DerSignature, VerifyingKey};
use p256::SecretKey;
use sha2::Sha256;

use crate::auth::verifier::{
    canonical_request, canonicalize_query, check_clock_skew, hex_sha256, DEFAULT_CLOCK_SKEW_SECS,
};

/// Authorization-header algorithm prefix.
pub const ALGORITHM: &str = "AWS4-ECDSA-P256-SHA256";

/// KDF label, per the AWS SigV4A spec (SP800-108 counter mode, HMAC-SHA256).
const KDF_LABEL: &[u8] = b"AWS4-ECDSA-P256-SHA256";

/// Parsed SigV4A `Authorization` header.
///
/// SigV4A scope is `AKID/YYYYMMDD/{service}/aws4_request` — region is **not**
/// part of the credential and arrives via the signed `x-amz-region-set` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigV4AHeader {
    /// Caller's access key (component 0 of `Credential=`).
    pub access_key: String,
    /// Lower-cased header names that participated in the signature.
    pub signed_headers: Vec<String>,
    /// Hex-encoded ECDSA P-256 SHA-256 DER signature.
    pub signature: String,
    /// Credential scope: `{date}/{service}/aws4_request` (no region).
    pub credential_scope: String,
    /// Scope date component (yyyymmdd).
    pub date: String,
    /// Scope service component (always `s3` for Ferrox).
    pub service: String,
}

impl SigV4AHeader {
    /// Parse the value of an `Authorization: AWS4-ECDSA-P256-SHA256 …` header.
    ///
    /// # Example
    ///
    /// ```
    /// use ferrox_gateway::auth::SigV4AHeader;
    /// let v = "AWS4-ECDSA-P256-SHA256 \
    ///          Credential=AKID/20260506/s3/aws4_request, \
    ///          SignedHeaders=host;x-amz-date;x-amz-region-set, \
    ///          Signature=304402";
    /// let h = SigV4AHeader::from_authorization_header(v).unwrap();
    /// assert_eq!(h.access_key, "AKID");
    /// assert_eq!(h.service, "s3");
    /// ```
    pub fn from_authorization_header(value: &str) -> Result<Self, FerroxError> {
        let value = value.trim();
        let rest = value
            .strip_prefix(ALGORITHM)
            .ok_or_else(|| FerroxError::InvalidRequest("not a SigV4A header".into()))?
            .trim_start();

        let mut credential: Option<&str> = None;
        let mut signed_headers: Option<&str> = None;
        let mut signature: Option<&str> = None;

        for part in rest.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (k, v) = part
                .split_once('=')
                .ok_or_else(|| FerroxError::InvalidRequest(format!("malformed kv pair: {part}")))?;
            match k.trim() {
                "Credential" => credential = Some(v.trim()),
                "SignedHeaders" => signed_headers = Some(v.trim()),
                "Signature" => signature = Some(v.trim()),
                other => {
                    return Err(FerroxError::InvalidRequest(format!(
                        "unknown SigV4A field: {other}"
                    )))
                }
            }
        }

        let credential = credential
            .ok_or_else(|| FerroxError::InvalidRequest("SigV4A: missing Credential".into()))?;
        let signed_headers = signed_headers
            .ok_or_else(|| FerroxError::InvalidRequest("SigV4A: missing SignedHeaders".into()))?;
        let signature = signature
            .ok_or_else(|| FerroxError::InvalidRequest("SigV4A: missing Signature".into()))?;

        if signature.is_empty() {
            return Err(FerroxError::InvalidRequest("empty SigV4A Signature".into()));
        }

        // SigV4A scope: AKID/YYYYMMDD/{service}/aws4_request — exactly 4 parts.
        let parts: Vec<&str> = credential.split('/').collect();
        if parts.len() != 4 {
            return Err(FerroxError::InvalidRequest(format!(
                "SigV4A credential scope must have 4 parts (AKID/date/service/aws4_request), got {}",
                parts.len()
            )));
        }
        if parts[3] != "aws4_request" {
            return Err(FerroxError::InvalidRequest(
                "SigV4A credential scope must end with aws4_request".into(),
            ));
        }
        let access_key = parts[0].to_string();
        let date = parts[1].to_string();
        let service = parts[2].to_string();
        if access_key.is_empty() {
            return Err(FerroxError::InvalidRequest(
                "empty SigV4A access key".into(),
            ));
        }
        let credential_scope = format!("{date}/{service}/aws4_request");

        let signed_headers: Vec<String> = signed_headers
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase)
            .collect();
        if signed_headers.is_empty() {
            return Err(FerroxError::InvalidRequest(
                "empty SigV4A SignedHeaders".into(),
            ));
        }

        Ok(Self {
            access_key,
            signed_headers,
            signature: signature.to_string(),
            credential_scope,
            date,
            service,
        })
    }
}

/// Returns `true` when `request_region` is matched by the signed
/// `x-amz-region-set` value.
///
/// Region-set syntax (per AWS SigV4A spec):
/// - `*` matches any region.
/// - An exact region name matches itself (case-insensitive).
/// - `prefix*` (single trailing `*`) matches any region starting with `prefix`.
/// - Comma-separated entries are OR'd together (match if any entry matches).
pub fn region_matches_set(region_set: &str, request_region: &str) -> bool {
    region_set
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .any(|pat| region_matches_one(pat, request_region))
}

fn region_matches_one(pattern: &str, wanted: &str) -> bool {
    if pattern == "*" || pattern.eq_ignore_ascii_case(wanted) {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return wanted
            .to_ascii_lowercase()
            .starts_with(&prefix.to_ascii_lowercase());
    }
    false
}

/// Derive the SigV4A P-256 ECDSA signing key from `(secret, access_key_id)`.
///
/// Implements the AWS SigV4A KDF: NIST SP 800-108 counter-mode HMAC-SHA256
/// with an outer counter that retries until the resulting scalar is in
/// `[1, n-1]` (where `n` is the P-256 group order).
///
/// The algorithm:
///
/// ```text
/// input_key = "AWS4A" || secret_access_key
/// label     = "AWS4-ECDSA-P256-SHA256"
/// for outer_counter in 1..=254:
///     fixed = i32be(1) || label || 0x00 || access_key_id || outer_counter || L_be(256)
///     k     = HMAC-SHA256(input_key, fixed)
///     c     = big_endian_int(k)
///     if c <= n - 2:
///         scalar = c + 1
///         return P-256 keypair for `scalar`
/// ```
///
/// Returns [`FerroxError::Internal`] if the loop is exhausted (cryptographically
/// negligible probability — included for completeness).
pub fn derive_sigv4a_signing_key(
    secret_access_key: &str,
    access_key_id: &str,
) -> Result<SecretKey, FerroxError> {
    type HmacSha256 = Hmac<Sha256>;

    let mut input_key = Vec::with_capacity(5 + secret_access_key.len());
    input_key.extend_from_slice(b"AWS4A");
    input_key.extend_from_slice(secret_access_key.as_bytes());

    for outer_counter in 1u8..=254 {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&input_key)
            .map_err(|e| FerroxError::Internal(format!("SigV4A HMAC init: {e}")))?;
        // SP800-108 counter mode fixed input:
        //   i32be(counter=1) || label || 0x00 || context || L_be(256)
        mac.update(&[0x00, 0x00, 0x00, 0x01]);
        mac.update(KDF_LABEL);
        mac.update(&[0x00]);
        mac.update(access_key_id.as_bytes());
        mac.update(&[outer_counter]);
        mac.update(&[0x00, 0x00, 0x01, 0x00]);
        let mut bytes: [u8; 32] = mac.finalize().into_bytes().into();

        // scalar = c + 1, computed as 256-bit big-endian add.
        let mut carry: u16 = 1;
        for byte in bytes.iter_mut().rev() {
            let sum = u16::from(*byte) + carry;
            *byte = (sum & 0xff) as u8;
            carry = sum >> 8;
            if carry == 0 {
                break;
            }
        }
        if carry != 0 {
            // c == 2^256 - 1, way over the curve order. Retry.
            continue;
        }

        // SecretKey::from_slice rejects zero and values >= n. So a successful
        // construction is exactly the AWS spec's `c + 1 ∈ [1, n-1]` predicate.
        if let Ok(sk) = SecretKey::from_slice(&bytes) {
            return Ok(sk);
        }
    }

    Err(FerroxError::Internal(
        "SigV4A KDF: 254-counter limit exhausted".into(),
    ))
}

/// Verify a SigV4A request signature.
///
/// `headers` must contain every header listed in `parsed.signed_headers` —
/// in particular `x-amz-date` and `x-amz-region-set`, which are mandatory.
/// `body_sha256` is the lower-case hex SHA-256 of the body, or
/// `UNSIGNED-PAYLOAD` for streaming/presigned requests.
///
/// Returns `Ok(())` only when:
/// - `x-amz-date` is present and inside `clock_skew_secs` of `now_unix`
/// - `x-amz-region-set` is present **and** signed
/// - `request_region` is matched by the signed region-set
/// - the recomputed canonical request hashes to the value the client signed
/// - the DER ECDSA P-256 SHA-256 signature verifies under the derived key
#[allow(clippy::too_many_arguments)]
pub fn verify_sigv4a(
    method: &str,
    path: &str,
    query: &str,
    headers: &[(String, String)],
    body_sha256: &str,
    secret_key: &str,
    parsed: &SigV4AHeader,
    now_unix: i64,
    clock_skew_secs: i64,
    request_region: &str,
) -> Result<(), FerroxError> {
    let amz_date = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-amz-date"))
        .map(|(_, v)| v.as_str())
        .ok_or_else(|| FerroxError::AuthFailed("SigV4A: missing x-amz-date header".into()))?;

    let region_set = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-amz-region-set"))
        .map(|(_, v)| v.as_str())
        .ok_or_else(|| FerroxError::AuthFailed("SigV4A: missing x-amz-region-set header".into()))?;

    if !parsed
        .signed_headers
        .iter()
        .any(|h| h.eq_ignore_ascii_case("x-amz-region-set"))
    {
        return Err(FerroxError::AuthFailed(
            "SigV4A: x-amz-region-set must be in SignedHeaders".into(),
        ));
    }

    check_clock_skew(amz_date, now_unix, clock_skew_secs)?;

    if !region_matches_set(region_set, request_region) {
        return Err(FerroxError::AuthFailed(format!(
            "SigV4A: request region '{request_region}' not covered by signed region-set '{region_set}'"
        )));
    }

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
        "{ALGORITHM}\n{amz_date}\n{}\n{canonical_hash}",
        parsed.credential_scope
    );

    let secret = derive_sigv4a_signing_key(secret_key, &parsed.access_key)?;
    let verifying_key = VerifyingKey::from(secret.public_key());

    let sig_bytes = hex::decode(&parsed.signature)
        .map_err(|_| FerroxError::AuthFailed("SigV4A signature is not valid hex".into()))?;
    let signature = DerSignature::from_bytes(&sig_bytes)
        .map_err(|_| FerroxError::AuthFailed("SigV4A signature is not valid DER".into()))?;

    // Do NOT log canonical_request / string_to_sign here: signed headers can
    // include SSE-C keys (x-amz-server-side-encryption-customer-key), and the
    // string-to-sign is suitable input for an offline signature-recovery oracle
    // if it leaks to operator logs alongside the secret-key store.
    verifying_key
        .verify(string_to_sign.as_bytes(), &signature)
        .map_err(|_| FerroxError::AuthFailed("SigV4A signature mismatch".into()))?;
    Ok(())
}

/// Verify a presigned SigV4A URL.
///
/// All SigV4A query parameters travel under the standard `X-Amz-…` prefix:
///
/// ```text
/// X-Amz-Algorithm     = AWS4-ECDSA-P256-SHA256
/// X-Amz-Credential    = AKID/YYYYMMDD/s3/aws4_request
/// X-Amz-Date          = YYYYMMDDTHHMMSSZ
/// X-Amz-Expires       = <seconds>
/// X-Amz-SignedHeaders = host;x-amz-region-set
/// X-Amz-Region-Set    = us-*,eu-west-1
/// X-Amz-Signature     = <hex DER>
/// ```
///
/// Body hash is always `UNSIGNED-PAYLOAD` for presigned URLs.
#[allow(clippy::too_many_arguments)]
pub fn verify_presigned_sigv4a(
    method: &str,
    path: &str,
    full_query: &str,
    headers: &[(String, String)],
    secret_key: &str,
    parsed: &SigV4AHeader,
    now_unix: i64,
    request_region: &str,
) -> Result<(), FerroxError> {
    // Pull the time/expiry/region from the query.
    let mut amz_date_q: Option<String> = None;
    let mut expires_secs: Option<u64> = None;
    let mut region_set_q: Option<String> = None;
    for pair in full_query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v_dec = percent_encoding::percent_decode_str(v)
            .decode_utf8_lossy()
            .into_owned();
        match k {
            "X-Amz-Date" => amz_date_q = Some(v_dec),
            "X-Amz-Expires" => expires_secs = v_dec.parse::<u64>().ok(),
            "X-Amz-Region-Set" => region_set_q = Some(v_dec),
            _ => {}
        }
    }

    let amz_date = amz_date_q
        .ok_or_else(|| FerroxError::AuthFailed("SigV4A presigned: missing X-Amz-Date".into()))?;
    let expires = expires_secs
        .ok_or_else(|| FerroxError::AuthFailed("SigV4A presigned: missing X-Amz-Expires".into()))?;
    let region_set = region_set_q.ok_or_else(|| {
        FerroxError::AuthFailed("SigV4A presigned: missing X-Amz-Region-Set".into())
    })?;

    let req_ts = chrono::NaiveDateTime::parse_from_str(&amz_date, "%Y%m%dT%H%M%SZ")
        .map_err(|e| FerroxError::AuthFailed(format!("SigV4A presigned: bad X-Amz-Date: {e}")))?
        .and_utc()
        .timestamp();
    if now_unix > req_ts + expires as i64 {
        return Err(FerroxError::AuthFailed(
            "SigV4A presigned URL has expired".into(),
        ));
    }

    if !parsed
        .signed_headers
        .iter()
        .any(|h| h.eq_ignore_ascii_case("x-amz-region-set"))
    {
        return Err(FerroxError::AuthFailed(
            "SigV4A presigned: x-amz-region-set must be in SignedHeaders".into(),
        ));
    }
    if !region_matches_set(&region_set, request_region) {
        return Err(FerroxError::AuthFailed(format!(
            "SigV4A presigned: request region '{request_region}' not covered by '{region_set}'"
        )));
    }

    // Strip X-Amz-Signature; canonicalize the rest.
    let stripped_query: String = full_query
        .split('&')
        .filter(|p| !p.is_empty() && !p.starts_with("X-Amz-Signature="))
        .collect::<Vec<_>>()
        .join("&");
    let canonical_query = canonicalize_query(&stripped_query);

    // x-amz-region-set is signed via headers; the SDK sends it as a header
    // even on presigned URLs (the SignedHeaders list mandates this). We
    // augment from the query value if absent so canonicalization succeeds.
    let mut augmented = headers.to_vec();
    if !augmented
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("x-amz-region-set"))
    {
        augmented.push(("x-amz-region-set".into(), region_set.clone()));
    }
    if !augmented
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("x-amz-date"))
    {
        augmented.push(("x-amz-date".into(), amz_date.clone()));
    }

    let canonical = canonical_request(
        method,
        path,
        &canonical_query,
        &augmented,
        &parsed.signed_headers,
        "UNSIGNED-PAYLOAD",
    )?;
    let canonical_hash = hex_sha256(canonical.as_bytes());

    let string_to_sign = format!(
        "{ALGORITHM}\n{amz_date}\n{}\n{canonical_hash}",
        parsed.credential_scope
    );

    let secret = derive_sigv4a_signing_key(secret_key, &parsed.access_key)?;
    let verifying_key = VerifyingKey::from(secret.public_key());

    let sig_bytes = hex::decode(&parsed.signature)
        .map_err(|_| FerroxError::AuthFailed("SigV4A presigned signature not hex".into()))?;
    let signature = DerSignature::from_bytes(&sig_bytes)
        .map_err(|_| FerroxError::AuthFailed("SigV4A presigned signature not valid DER".into()))?;

    verifying_key
        .verify(string_to_sign.as_bytes(), &signature)
        .map_err(|_| FerroxError::AuthFailed("SigV4A presigned signature mismatch".into()))?;
    Ok(())
}

/// Build a SigV4A [`SigV4AHeader`] from the `X-Amz-…` query parameters of a
/// presigned URL.
///
/// `query` is the raw query string (everything after `?`), already
/// percent-encoded as the client sent it.
pub fn parse_sigv4a_query(query: &str) -> Result<SigV4AHeader, FerroxError> {
    let mut algorithm = None;
    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v_dec = percent_encoding::percent_decode_str(v)
            .decode_utf8_lossy()
            .into_owned();
        match k {
            "X-Amz-Algorithm" => algorithm = Some(v_dec),
            "X-Amz-Credential" => credential = Some(v_dec),
            "X-Amz-SignedHeaders" => signed_headers = Some(v_dec),
            "X-Amz-Signature" => signature = Some(v_dec),
            _ => {}
        }
    }
    if algorithm.as_deref() != Some(ALGORITHM) {
        return Err(FerroxError::InvalidRequest(format!(
            "X-Amz-Algorithm must be {ALGORITHM}"
        )));
    }
    let credential =
        credential.ok_or_else(|| FerroxError::InvalidRequest("missing X-Amz-Credential".into()))?;
    let signed_headers = signed_headers
        .ok_or_else(|| FerroxError::InvalidRequest("missing X-Amz-SignedHeaders".into()))?;
    let signature =
        signature.ok_or_else(|| FerroxError::InvalidRequest("missing X-Amz-Signature".into()))?;
    let auth_value = format!(
        "{ALGORITHM} Credential={credential},SignedHeaders={signed_headers},Signature={signature}"
    );
    SigV4AHeader::from_authorization_header(&auth_value)
}

/// Default clock-skew window for SigV4A (re-exported from SigV4 for symmetry).
pub const SIGV4A_DEFAULT_CLOCK_SKEW_SECS: i64 = DEFAULT_CLOCK_SKEW_SECS;

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{DerSignature as TestDerSig, SigningKey};

    fn fixed_now() -> i64 {
        chrono::NaiveDateTime::parse_from_str("20260506T000000Z", "%Y%m%dT%H%M%SZ")
            .unwrap()
            .and_utc()
            .timestamp()
    }

    fn sign_string_to_sign(secret: &str, akid: &str, sts: &[u8]) -> String {
        let sk = derive_sigv4a_signing_key(secret, akid).unwrap();
        let signer = SigningKey::from(&sk);
        let sig: TestDerSig = signer.sign(sts);
        hex::encode(sig.as_bytes())
    }

    #[test]
    fn test_parse_well_formed_no_region_in_scope() {
        let h = SigV4AHeader::from_authorization_header(
            "AWS4-ECDSA-P256-SHA256 Credential=AKIA/20260506/s3/aws4_request, \
             SignedHeaders=host;x-amz-date;x-amz-region-set, Signature=deadbeef",
        )
        .unwrap();
        assert_eq!(h.access_key, "AKIA");
        assert_eq!(h.date, "20260506");
        assert_eq!(h.service, "s3");
        assert_eq!(h.credential_scope, "20260506/s3/aws4_request");
        assert_eq!(
            h.signed_headers,
            vec!["host", "x-amz-date", "x-amz-region-set"]
        );
    }

    #[test]
    fn test_parse_rejects_legacy_5_part_scope_with_region() {
        // The old (incorrect) format included a region segment.
        let res = SigV4AHeader::from_authorization_header(
            "AWS4-ECDSA-P256-SHA256 Credential=AKIA/20260506/us-east-1/s3/aws4_request, \
             SignedHeaders=host, Signature=deadbeef",
        );
        assert!(matches!(res, Err(FerroxError::InvalidRequest(_))));
    }

    #[test]
    fn test_parse_invalid_prefix_rejected() {
        assert!(SigV4AHeader::from_authorization_header("AWS4-HMAC-SHA256 stuff").is_err());
    }

    #[test]
    fn test_region_matches_exact_wildcard_list() {
        assert!(region_matches_set("us-east-1", "us-east-1"));
        assert!(region_matches_set("us-*", "us-east-1"));
        assert!(region_matches_set("*", "anywhere"));
        assert!(region_matches_set("eu-west-1, us-*", "us-east-2"));
        assert!(!region_matches_set("us-*", "eu-west-1"));
        assert!(!region_matches_set("", "us-east-1"));
    }

    #[test]
    fn test_kdf_is_deterministic_and_returns_valid_p256_key() {
        let a =
            derive_sigv4a_signing_key("MOCKxSECRETxKEYxFORxTESTSxONLYx123456789", "AKIA").unwrap();
        let b =
            derive_sigv4a_signing_key("MOCKxSECRETxKEYxFORxTESTSxONLYx123456789", "AKIA").unwrap();
        assert_eq!(a.to_bytes(), b.to_bytes());
        // Different access key → different scalar.
        let c =
            derive_sigv4a_signing_key("MOCKxSECRETxKEYxFORxTESTSxONLYx123456789", "OTHER").unwrap();
        assert_ne!(a.to_bytes(), c.to_bytes());
    }

    /// AWS-reference SigV4A interop using the official `get-vanilla` test
    /// fixture from <https://github.com/awslabs/aws-c-auth/tree/main/tests/aws-signing-test-suite/v4a/get-vanilla>.
    ///
    /// Two assertions:
    /// 1. Our KDF derives the same P-256 public key (X, Y) as AWS publishes
    ///    in `public-key.json`. If this fails, our KDF differs from AWS's and
    ///    every real SigV4A signature will fail to verify.
    /// 2. AWS's recorded DER signature verifies against AWS's recorded
    ///    string-to-sign under the derived public key. Confirms our DER
    ///    decoding + ECDSA verification path is wire-compatible.
    #[test]
    fn sigv4a_aws_reference_get_vanilla() {
        use p256::ecdsa::signature::Verifier;

        // From context.json (public AWS test fixture, not real credentials).
        const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        const AKID: &str = "AKIDEXAMPLE";

        let sk = derive_sigv4a_signing_key(SECRET, AKID).unwrap();
        let vk = VerifyingKey::from(sk.public_key());

        // (1) Public key must match AWS's published expected values.
        let point = vk.to_encoded_point(false);
        let bytes = point.as_bytes();
        // Uncompressed SEC1: 0x04 || X(32) || Y(32).
        assert_eq!(bytes.len(), 65, "expected uncompressed SEC1 point");
        assert_eq!(bytes[0], 0x04, "expected uncompressed tag");
        let x_hex = hex::encode(&bytes[1..33]);
        let y_hex = hex::encode(&bytes[33..65]);
        assert_eq!(
            x_hex, "b6618f6a65740a99e650b33b6b4b5bd0d43b176d721a3edfea7e7d2d56d936b1",
            "KDF-derived public-key X disagrees with AWS reference"
        );
        assert_eq!(
            y_hex, "865ed22a7eadc9c5cb9d2cbaca1b3699139fedc5043dc6661864218330c8e518",
            "KDF-derived public-key Y disagrees with AWS reference"
        );

        // (2) AWS-recorded DER signature must verify against AWS-recorded
        // string-to-sign under the derived public key.
        let string_to_sign = "AWS4-ECDSA-P256-SHA256\n\
                              20150830T123600Z\n\
                              20150830/service/aws4_request\n\
                              cf59db423e841c8b7e3444158185aa261b724a5c27cbe762676f3eed19f4dc02";
        let sig_hex = "3045022018b4e277d0281864beb51d3600e23f88510ea5031d68ddfbb68614b82a5eb7d2\
                       022100effb9c5f22ed9ef3ae0ab243d21f06bce82365bbb79529a07b6888c343ae5f8c";
        let sig_bytes = hex::decode(sig_hex).unwrap();
        let sig = DerSignature::from_bytes(&sig_bytes).unwrap();
        vk.verify(string_to_sign.as_bytes(), &sig)
            .expect("AWS get-vanilla signature must verify under derived key");
    }

    /// Second AWS-reference vector: `post-vanilla`. Same credentials, POST
    /// method, different canonical-request hash. Confirms wire-compat across
    /// methods.
    #[test]
    fn sigv4a_aws_reference_post_vanilla() {
        use p256::ecdsa::signature::Verifier;

        let sk =
            derive_sigv4a_signing_key("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "AKIDEXAMPLE")
                .unwrap();
        let vk = VerifyingKey::from(sk.public_key());

        let string_to_sign = "AWS4-ECDSA-P256-SHA256\n\
                              20150830T123600Z\n\
                              20150830/service/aws4_request\n\
                              806a9b01b76472cc6b66fff02630726d55f8b4ada6d2fd9b36eb0d710e215861";
        let sig_hex = "3044022051fe398025aafbfc21d054bc78e5edfb96c9acb7fd272795565181d757815e47\
                       02202e7b8d2b92324290b1d95f8b0fc5e333bb8b5e333f6160bcab39d7258156d224";
        let sig_bytes = hex::decode(sig_hex).unwrap();
        let sig = DerSignature::from_bytes(&sig_bytes).unwrap();
        vk.verify(string_to_sign.as_bytes(), &sig)
            .expect("AWS post-vanilla signature must verify under derived key");
    }

    fn build_request_headers(region_set: &str) -> Vec<(String, String)> {
        vec![
            ("host".into(), "examplebucket.s3.amazonaws.com".into()),
            (
                "x-amz-content-sha256".into(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            ),
            ("x-amz-date".into(), "20260506T000000Z".into()),
            ("x-amz-region-set".into(), region_set.into()),
        ]
    }

    fn signed_headers() -> Vec<String> {
        vec![
            "host".into(),
            "x-amz-content-sha256".into(),
            "x-amz-date".into(),
            "x-amz-region-set".into(),
        ]
    }

    fn build_string_to_sign(headers: &[(String, String)], scope: &str) -> String {
        let canonical = canonical_request(
            "GET",
            "/test.txt",
            "",
            headers,
            &signed_headers(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .unwrap();
        let canonical_hash = hex_sha256(canonical.as_bytes());
        format!("{ALGORITHM}\n20260506T000000Z\n{scope}\n{canonical_hash}")
    }

    #[test]
    fn test_verify_sigv4a_round_trip_succeeds() {
        let secret = "MOCKxSECRETxKEYxFORxTESTSxONLYx123456789";
        let akid = "AKIA";
        let scope = "20260506/s3/aws4_request";
        let headers = build_request_headers("us-*");
        let sts = build_string_to_sign(&headers, scope);
        let sig_hex = sign_string_to_sign(secret, akid, sts.as_bytes());

        let auth = format!(
            "AWS4-ECDSA-P256-SHA256 Credential={akid}/20260506/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-region-set, \
             Signature={sig_hex}"
        );
        let parsed = SigV4AHeader::from_authorization_header(&auth).unwrap();

        verify_sigv4a(
            "GET",
            "/test.txt",
            "",
            &headers,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            secret,
            &parsed,
            fixed_now(),
            900,
            "us-east-1",
        )
        .unwrap();
    }

    #[test]
    fn test_verify_sigv4a_rejects_wrong_signature() {
        let secret = "MOCKxSECRETxKEYxFORxTESTSxONLYx123456789";
        // Construct a syntactically-valid DER ECDSA signature that won't match.
        let bogus_signer =
            SigningKey::from(derive_sigv4a_signing_key(secret, "DIFFERENT").unwrap());
        let bogus_sig: TestDerSig = bogus_signer.sign(b"unrelated payload");
        let auth = format!(
            "AWS4-ECDSA-P256-SHA256 Credential=AKIA/20260506/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-region-set, \
             Signature={}",
            hex::encode(bogus_sig.as_bytes())
        );
        let parsed = SigV4AHeader::from_authorization_header(&auth).unwrap();
        let headers = build_request_headers("us-*");
        let res = verify_sigv4a(
            "GET",
            "/test.txt",
            "",
            &headers,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            secret,
            &parsed,
            fixed_now(),
            900,
            "us-east-1",
        );
        assert!(matches!(res, Err(FerroxError::AuthFailed(_))));
    }

    #[test]
    fn test_verify_sigv4a_rejects_wrong_region() {
        let secret = "MOCKxSECRETxKEYxFORxTESTSxONLYx123456789";
        let akid = "AKIA";
        let scope = "20260506/s3/aws4_request";
        let headers = build_request_headers("us-*");
        let sts = build_string_to_sign(&headers, scope);
        let sig_hex = sign_string_to_sign(secret, akid, sts.as_bytes());
        let auth = format!(
            "AWS4-ECDSA-P256-SHA256 Credential={akid}/20260506/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-region-set, \
             Signature={sig_hex}"
        );
        let parsed = SigV4AHeader::from_authorization_header(&auth).unwrap();
        let res = verify_sigv4a(
            "GET",
            "/test.txt",
            "",
            &headers,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            secret,
            &parsed,
            fixed_now(),
            900,
            "eu-west-1",
        );
        assert!(matches!(res, Err(FerroxError::AuthFailed(_))));
    }

    #[test]
    fn test_verify_sigv4a_accepts_global_wildcard() {
        let secret = "MOCKxSECRETxKEYxFORxTESTSxONLYx123456789";
        let akid = "AKIA";
        let scope = "20260506/s3/aws4_request";
        let headers = build_request_headers("*");
        let sts = build_string_to_sign(&headers, scope);
        let sig_hex = sign_string_to_sign(secret, akid, sts.as_bytes());
        let auth = format!(
            "AWS4-ECDSA-P256-SHA256 Credential={akid}/20260506/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-region-set, \
             Signature={sig_hex}"
        );
        let parsed = SigV4AHeader::from_authorization_header(&auth).unwrap();
        verify_sigv4a(
            "GET",
            "/test.txt",
            "",
            &headers,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            secret,
            &parsed,
            fixed_now(),
            900,
            "ap-south-1",
        )
        .unwrap();
    }

    #[test]
    fn test_verify_sigv4a_rejects_missing_region_set_header() {
        let secret = "MOCKxSECRETxKEYxFORxTESTSxONLYx123456789";
        let akid = "AKIA";
        let scope = "20260506/s3/aws4_request";
        let signed_headers_v = vec![
            "host".into(),
            "x-amz-date".into(),
            "x-amz-region-set".into(),
        ];
        let mut headers = vec![
            ("host".to_string(), "examplebucket.s3.amazonaws.com".into()),
            ("x-amz-date".to_string(), "20260506T000000Z".into()),
        ];
        // sign as if region-set header existed
        headers.push(("x-amz-region-set".into(), "us-*".into()));
        let canonical =
            canonical_request("GET", "/", "", &headers, &signed_headers_v, "x").unwrap();
        let canonical_hash = hex_sha256(canonical.as_bytes());
        let sts = format!("{ALGORITHM}\n20260506T000000Z\n{scope}\n{canonical_hash}");
        let sig_hex = sign_string_to_sign(secret, akid, sts.as_bytes());

        // Now drop x-amz-region-set from the headers we actually pass in.
        headers.retain(|(k, _)| k != "x-amz-region-set");

        let auth = format!(
            "AWS4-ECDSA-P256-SHA256 Credential={akid}/20260506/s3/aws4_request, \
             SignedHeaders=host;x-amz-date;x-amz-region-set, \
             Signature={sig_hex}"
        );
        let parsed = SigV4AHeader::from_authorization_header(&auth).unwrap();
        let res = verify_sigv4a(
            "GET",
            "/",
            "",
            &headers,
            "x",
            secret,
            &parsed,
            fixed_now(),
            900,
            "us-east-1",
        );
        assert!(matches!(res, Err(FerroxError::AuthFailed(_))));
    }

    #[test]
    fn test_verify_sigv4a_rejects_unsigned_region_set() {
        let secret = "MOCKxSECRETxKEYxFORxTESTSxONLYx123456789";
        // x-amz-region-set IS present as a header but NOT in SignedHeaders.
        let auth = "AWS4-ECDSA-P256-SHA256 Credential=AKIA/20260506/s3/aws4_request, \
                    SignedHeaders=host;x-amz-date, Signature=deadbeef";
        let parsed = SigV4AHeader::from_authorization_header(auth).unwrap();
        let headers = build_request_headers("us-*");
        let res = verify_sigv4a(
            "GET",
            "/",
            "",
            &headers,
            "x",
            secret,
            &parsed,
            fixed_now(),
            900,
            "us-east-1",
        );
        assert!(matches!(res, Err(FerroxError::AuthFailed(_))));
    }

    #[test]
    fn test_verify_sigv4a_rejects_clock_skew() {
        let secret = "MOCKxSECRETxKEYxFORxTESTSxONLYx123456789";
        let auth = "AWS4-ECDSA-P256-SHA256 Credential=AKIA/20260506/s3/aws4_request, \
                    SignedHeaders=host;x-amz-date;x-amz-region-set, Signature=deadbeef";
        let parsed = SigV4AHeader::from_authorization_header(auth).unwrap();
        let headers = build_request_headers("us-*");
        let now = fixed_now() + 16 * 60;
        let res = verify_sigv4a(
            "GET",
            "/",
            "",
            &headers,
            "x",
            secret,
            &parsed,
            now,
            900,
            "us-east-1",
        );
        assert!(matches!(res, Err(FerroxError::AuthFailed(_))));
    }

    #[test]
    fn test_presigned_sigv4a_round_trip_succeeds() {
        let secret = "MOCKxSECRETxKEYxFORxTESTSxONLYx123456789";
        let akid = "AKIA";

        let host_header = vec![("host".to_string(), "examplebucket.s3.amazonaws.com".into())];
        let signed_h = vec!["host".into(), "x-amz-region-set".into()];
        let stripped_query = "X-Amz-Algorithm=AWS4-ECDSA-P256-SHA256\
             &X-Amz-Credential=AKIA%2F20260506%2Fs3%2Faws4_request\
             &X-Amz-Date=20260506T000000Z\
             &X-Amz-Expires=900\
             &X-Amz-Region-Set=us-%2A\
             &X-Amz-SignedHeaders=host%3Bx-amz-region-set";

        // Build canonical with augmented x-amz-region-set + x-amz-date headers.
        let mut augmented = host_header.clone();
        augmented.push(("x-amz-region-set".into(), "us-*".into()));
        augmented.push(("x-amz-date".into(), "20260506T000000Z".into()));
        let canon = canonical_request(
            "GET",
            "/test.txt",
            &canonicalize_query(stripped_query),
            &augmented,
            &signed_h,
            "UNSIGNED-PAYLOAD",
        )
        .unwrap();
        let canon_hash = hex_sha256(canon.as_bytes());
        let sts = format!("{ALGORITHM}\n20260506T000000Z\n20260506/s3/aws4_request\n{canon_hash}");
        let sig_hex = sign_string_to_sign(secret, akid, sts.as_bytes());

        let full_query = format!("{stripped_query}&X-Amz-Signature={sig_hex}");
        let parsed = parse_sigv4a_query(&full_query).unwrap();

        verify_presigned_sigv4a(
            "GET",
            "/test.txt",
            &full_query,
            &host_header,
            secret,
            &parsed,
            fixed_now(),
            "us-east-1",
        )
        .unwrap();
    }

    #[test]
    fn test_presigned_sigv4a_rejects_wrong_signature() {
        let secret = "MOCKxSECRETxKEYxFORxTESTSxONLYx123456789";
        let host_header = vec![("host".to_string(), "examplebucket.s3.amazonaws.com".into())];
        // 0x30, 0x06 is a syntactically valid (but content-bogus) DER seq.
        let bogus_signer = SigningKey::from(derive_sigv4a_signing_key(secret, "OTHER").unwrap());
        let bogus_sig: TestDerSig = bogus_signer.sign(b"unrelated");
        let bogus_hex = hex::encode(bogus_sig.as_bytes());
        let full_query = format!(
            "X-Amz-Algorithm=AWS4-ECDSA-P256-SHA256\
             &X-Amz-Credential=AKIA%2F20260506%2Fs3%2Faws4_request\
             &X-Amz-Date=20260506T000000Z\
             &X-Amz-Expires=900\
             &X-Amz-Region-Set=us-%2A\
             &X-Amz-SignedHeaders=host%3Bx-amz-region-set\
             &X-Amz-Signature={bogus_hex}"
        );
        let parsed = parse_sigv4a_query(&full_query).unwrap();
        let res = verify_presigned_sigv4a(
            "GET",
            "/test.txt",
            &full_query,
            &host_header,
            secret,
            &parsed,
            fixed_now(),
            "us-east-1",
        );
        assert!(matches!(res, Err(FerroxError::AuthFailed(_))));
    }
}
