//! SigV4 `Authorization` header parsing.
//!
//! AWS sends a single header of the form:
//!
//! ```text
//! Authorization: AWS4-HMAC-SHA256 Credential=AKID/20260504/us-east-1/s3/aws4_request,
//!                SignedHeaders=host;x-amz-date,Signature=hex64
//! ```
//!
//! Whitespace handling, comma placement, and `=` quoting all follow the
//! [SigV4 spec](https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html).
//! This module returns [`FerroxError::InvalidRequest`] on any deviation.

use ferrox_error::FerroxError;

const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// Parsed SigV4 `Authorization` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigV4Header {
    /// Caller's access key (the part before `/` in `Credential=`).
    pub access_key: String,
    /// Lower-cased header names that participated in the signature.
    pub signed_headers: Vec<String>,
    /// Hex-encoded HMAC-SHA256 signature.
    pub signature: String,
    /// Credential scope: `{date}/{region}/{service}/aws4_request`.
    pub credential_scope: String,
    /// Scope date component (yyyymmdd).
    pub date: String,
    /// Scope region component.
    pub region: String,
    /// Scope service component (always `s3` for Ferrox).
    pub service: String,
}

impl SigV4Header {
    /// Parse the value of an `Authorization` header.
    ///
    /// Returns [`FerroxError::InvalidRequest`] if any required field is
    /// missing, the algorithm is wrong, or the credential scope is malformed.
    ///
    /// # Example
    ///
    /// ```
    /// use ferrox_gateway::auth::SigV4Header;
    /// let v = "AWS4-HMAC-SHA256 \
    ///          Credential=AKID/20260504/us-east-1/s3/aws4_request, \
    ///          SignedHeaders=host;x-amz-date, \
    ///          Signature=abcd";
    /// let h = SigV4Header::from_authorization_header(v).unwrap();
    /// assert_eq!(h.access_key, "AKID");
    /// assert_eq!(h.region, "us-east-1");
    /// ```
    pub fn from_authorization_header(value: &str) -> Result<Self, FerroxError> {
        let value = value.trim();
        let rest = value
            .strip_prefix(ALGORITHM)
            .ok_or_else(|| FerroxError::InvalidRequest("missing AWS4-HMAC-SHA256 prefix".into()))?
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
                        "unknown sigv4 field: {other}"
                    )));
                }
            }
        }

        let credential = credential
            .ok_or_else(|| FerroxError::InvalidRequest("missing Credential field".into()))?;
        let signed_headers = signed_headers
            .ok_or_else(|| FerroxError::InvalidRequest("missing SignedHeaders field".into()))?;
        let signature = signature
            .ok_or_else(|| FerroxError::InvalidRequest("missing Signature field".into()))?;

        if signature.is_empty() {
            return Err(FerroxError::InvalidRequest("empty Signature".into()));
        }

        let parts: Vec<&str> = credential.split('/').collect();
        if parts.len() != 5 {
            return Err(FerroxError::InvalidRequest(format!(
                "credential scope must have 5 parts, got {}",
                parts.len()
            )));
        }
        if parts[4] != "aws4_request" {
            return Err(FerroxError::InvalidRequest(
                "credential scope must end with aws4_request".into(),
            ));
        }
        let access_key = parts[0].to_string();
        let date = parts[1].to_string();
        let region = parts[2].to_string();
        let service = parts[3].to_string();
        if access_key.is_empty() {
            return Err(FerroxError::InvalidRequest("empty access key".into()));
        }
        let credential_scope = format!("{date}/{region}/{service}/aws4_request");

        let signed_headers: Vec<String> = signed_headers
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase)
            .collect();
        if signed_headers.is_empty() {
            return Err(FerroxError::InvalidRequest("empty SignedHeaders".into()));
        }

        Ok(Self {
            access_key,
            signed_headers,
            signature: signature.to_string(),
            credential_scope,
            date,
            region,
            service,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "AWS4-HMAC-SHA256 \
        Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
        SignedHeaders=host;range;x-amz-date, \
        Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024";

    #[test]
    fn test_parse_valid_authorization_header() {
        let h = SigV4Header::from_authorization_header(VALID).unwrap();
        assert_eq!(h.access_key, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(h.date, "20130524");
        assert_eq!(h.region, "us-east-1");
        assert_eq!(h.service, "s3");
        assert_eq!(h.signed_headers, vec!["host", "range", "x-amz-date"]);
        assert_eq!(
            h.signature,
            "fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024"
        );
        assert_eq!(h.credential_scope, "20130524/us-east-1/s3/aws4_request");
    }

    #[test]
    fn test_missing_credential_field_returns_invalid_request() {
        let v = "AWS4-HMAC-SHA256 SignedHeaders=host, Signature=abc";
        let err = SigV4Header::from_authorization_header(v).unwrap_err();
        assert!(matches!(err, FerroxError::InvalidRequest(_)));
    }

    #[test]
    fn test_missing_signature_field_returns_invalid_request() {
        let v = "AWS4-HMAC-SHA256 Credential=AK/20130524/us-east-1/s3/aws4_request, \
                 SignedHeaders=host";
        let err = SigV4Header::from_authorization_header(v).unwrap_err();
        assert!(matches!(err, FerroxError::InvalidRequest(_)));
    }

    #[test]
    fn test_malformed_credential_scope_returns_invalid_request() {
        let v = "AWS4-HMAC-SHA256 Credential=AK/20130524/us-east-1, \
                 SignedHeaders=host, Signature=abc";
        let err = SigV4Header::from_authorization_header(v).unwrap_err();
        assert!(matches!(err, FerroxError::InvalidRequest(_)));
    }

    #[test]
    fn test_credential_scope_wrong_terminator_returns_invalid_request() {
        let v = "AWS4-HMAC-SHA256 Credential=AK/20130524/us-east-1/s3/wrong, \
                 SignedHeaders=host, Signature=abc";
        let err = SigV4Header::from_authorization_header(v).unwrap_err();
        assert!(matches!(err, FerroxError::InvalidRequest(_)));
    }

    #[test]
    fn test_empty_signed_headers_returns_invalid_request() {
        let v = "AWS4-HMAC-SHA256 Credential=AK/20130524/us-east-1/s3/aws4_request, \
                 SignedHeaders=, Signature=abc";
        let err = SigV4Header::from_authorization_header(v).unwrap_err();
        assert!(matches!(err, FerroxError::InvalidRequest(_)));
    }

    #[test]
    fn test_wrong_algorithm_prefix_returns_invalid_request() {
        let v = "Bearer abc";
        let err = SigV4Header::from_authorization_header(v).unwrap_err();
        assert!(matches!(err, FerroxError::InvalidRequest(_)));
    }

    #[test]
    fn test_signed_headers_lowercased_and_trimmed() {
        let v = "AWS4-HMAC-SHA256 Credential=AK/20130524/us-east-1/s3/aws4_request, \
                 SignedHeaders=Host; X-Amz-Date , Signature=abc";
        let h = SigV4Header::from_authorization_header(v).unwrap();
        assert_eq!(h.signed_headers, vec!["host", "x-amz-date"]);
    }
}
