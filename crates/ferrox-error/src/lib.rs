//! Shared error types for the Ferrox object storage server.
//!
//! Every crate in the workspace returns [`FerroxError`] (or a [`Result`] alias
//! over it). The variants map 1:1 to AWS S3 error codes via
//! [`FerroxError::s3_error_code`], so the gateway layer can emit a spec-compliant
//! `<Error><Code>…</Code></Error>` XML envelope without inspecting variant data.
//!
//! # Example
//!
//! ```
//! use ferrox_error::FerroxError;
//!
//! let err = FerroxError::NotFound {
//!     bucket: "photos".into(),
//!     key: Some("cat.jpg".into()),
//! };
//! assert_eq!(err.s3_error_code(), "NoSuchKey");
//! ```

#![deny(missing_docs)]
#![forbid(unsafe_code)]

use thiserror::Error;

/// Canonical error type returned across the Ferrox workspace.
///
/// Map each variant to the AWS S3 wire-format error code with
/// [`FerroxError::s3_error_code`]. Map to an HTTP status with
/// [`FerroxError::http_status`].
#[derive(Debug, Error)]
pub enum FerroxError {
    /// I/O failure in the storage backend (disk, FS, network FS, …).
    #[error("storage I/O error: {0}")]
    StorageIo(#[from] std::io::Error),

    /// Failure inside the metadata store (sled, RocksDB, …).
    #[error("metadata store error: {0}")]
    MetaStore(String),

    /// Resource not found.
    ///
    /// `key = None` represents a missing bucket (`NoSuchBucket`); `key = Some(_)`
    /// represents a missing object key (`NoSuchKey`).
    #[error("{}", match key {
        Some(_) => "The specified key does not exist.",
        None => "The specified bucket does not exist.",
    })]
    NotFound {
        /// Bucket name that was looked up.
        bucket: String,
        /// Object key, if any. `None` means the bucket itself is missing.
        key: Option<String>,
    },

    /// Bucket creation conflicted with an existing bucket.
    #[error("bucket already exists: {0}")]
    BucketAlreadyExists(String),

    /// Authentication failure: bad signature, unknown access key, expired clock skew.
    #[error("The request signature we calculated does not match the signature you provided. Check your key and signing method.")]
    AuthFailed(String),

    /// Caller-supplied request was malformed or violated the S3 spec.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// Computed checksum did not match the caller-supplied or stored checksum.
    #[error("checksum mismatch: expected={expected}, got={got}")]
    ChecksumMismatch {
        /// Checksum the caller sent (or the value stored on disk).
        expected: String,
        /// Checksum recomputed by the server.
        got: String,
    },

    /// Request body or part is smaller than allowed by the S3 spec.
    /// In particular, every multipart part except the last must be at least 5 MiB.
    #[error("entity too small: {0}")]
    EntityTooSmall(String),

    /// Request body or part exceeds the maximum size allowed by the S3 spec
    /// (5 GiB per part, 5 TiB per object).
    #[error("entity too large: {0}")]
    EntityTooLarge(String),

    /// Catch-all for unexpected internal failures.
    #[error("internal error: {0}")]
    Internal(String),
}

impl FerroxError {
    /// Returns the AWS S3 error code string corresponding to this variant.
    ///
    /// The mapping follows the AWS S3 REST API
    /// [error code reference](https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html).
    ///
    /// `NotFound` is split based on whether a key is present:
    /// - `key = Some(_)` → `NoSuchKey`
    /// - `key = None` → `NoSuchBucket`
    ///
    /// # Example
    ///
    /// ```
    /// use ferrox_error::FerroxError;
    ///
    /// let e = FerroxError::AuthFailed("bad sig".into());
    /// assert_eq!(e.s3_error_code(), "InvalidSignature");
    /// ```
    pub fn s3_error_code(&self) -> &'static str {
        match self {
            Self::StorageIo(_) => "InternalError",
            Self::MetaStore(_) => "InternalError",
            Self::NotFound { key: None, .. } => "NoSuchBucket",
            Self::NotFound { key: Some(_), .. } => "NoSuchKey",
            Self::BucketAlreadyExists(_) => "BucketAlreadyExists",
            Self::AuthFailed(_) => "InvalidSignature",
            Self::InvalidRequest(_) => "InvalidArgument",
            Self::ChecksumMismatch { .. } => "BadDigest",
            Self::EntityTooSmall(_) => "EntityTooSmall",
            Self::EntityTooLarge(_) => "EntityTooLarge",
            Self::Internal(_) => "InternalError",
        }
    }

    /// Returns the HTTP status code corresponding to this variant, matching
    /// AWS S3 wire behaviour.
    ///
    /// Wrong status codes silently break SDK clients, so this mapping is
    /// authoritative — handlers should not pick their own codes.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::StorageIo(_) => 500,
            Self::MetaStore(_) => 500,
            Self::NotFound { .. } => 404,
            Self::BucketAlreadyExists(_) => 409,
            Self::AuthFailed(_) => 403,
            Self::InvalidRequest(_) => 400,
            Self::ChecksumMismatch { .. } => 400,
            Self::EntityTooSmall(_) => 400,
            Self::EntityTooLarge(_) => 400,
            Self::Internal(_) => 500,
        }
    }
}

/// Convenience alias for results returned by Ferrox crates.
pub type Result<T> = core::result::Result<T, FerroxError>;

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    #[test]
    fn test_s3_error_code_storage_io_returns_internal_error() {
        let err = FerroxError::StorageIo(io::Error::other("disk full"));
        assert_eq!(err.s3_error_code(), "InternalError");
    }

    #[test]
    fn test_s3_error_code_meta_store_returns_internal_error() {
        let err = FerroxError::MetaStore("sled crashed".into());
        assert_eq!(err.s3_error_code(), "InternalError");
    }

    #[test]
    fn test_s3_error_code_not_found_with_key_returns_no_such_key() {
        let err = FerroxError::NotFound {
            bucket: "b".into(),
            key: Some("k".into()),
        };
        assert_eq!(err.s3_error_code(), "NoSuchKey");
    }

    #[test]
    fn test_s3_error_code_not_found_without_key_returns_no_such_bucket() {
        let err = FerroxError::NotFound {
            bucket: "b".into(),
            key: None,
        };
        assert_eq!(err.s3_error_code(), "NoSuchBucket");
    }

    #[test]
    fn test_s3_error_code_bucket_already_exists() {
        let err = FerroxError::BucketAlreadyExists("dupe".into());
        assert_eq!(err.s3_error_code(), "BucketAlreadyExists");
    }

    #[test]
    fn test_s3_error_code_auth_failed_returns_invalid_signature() {
        let err = FerroxError::AuthFailed("bad sig".into());
        assert_eq!(err.s3_error_code(), "InvalidSignature");
    }

    #[test]
    fn test_s3_error_code_invalid_request_returns_invalid_argument() {
        let err = FerroxError::InvalidRequest("oops".into());
        assert_eq!(err.s3_error_code(), "InvalidArgument");
    }

    #[test]
    fn test_s3_error_code_checksum_mismatch_returns_bad_digest() {
        let err = FerroxError::ChecksumMismatch {
            expected: "abc".into(),
            got: "def".into(),
        };
        assert_eq!(err.s3_error_code(), "BadDigest");
    }

    #[test]
    fn test_s3_error_code_internal_returns_internal_error() {
        let err = FerroxError::Internal("boom".into());
        assert_eq!(err.s3_error_code(), "InternalError");
    }

    #[test]
    fn test_http_status_mapping_matches_aws_spec() {
        assert_eq!(
            FerroxError::NotFound {
                bucket: "b".into(),
                key: None
            }
            .http_status(),
            404
        );
        assert_eq!(
            FerroxError::BucketAlreadyExists("b".into()).http_status(),
            409
        );
        assert_eq!(FerroxError::AuthFailed("x".into()).http_status(), 403);
        assert_eq!(FerroxError::InvalidRequest("x".into()).http_status(), 400);
        assert_eq!(
            FerroxError::ChecksumMismatch {
                expected: "a".into(),
                got: "b".into()
            }
            .http_status(),
            400
        );
        assert_eq!(FerroxError::Internal("x".into()).http_status(), 500);
        assert_eq!(FerroxError::MetaStore("x".into()).http_status(), 500);
        assert_eq!(
            FerroxError::StorageIo(io::Error::other("x")).http_status(),
            500
        );
    }

    #[test]
    fn test_io_error_converts_via_from() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "nope");
        let ferrox: FerroxError = io_err.into();
        assert!(matches!(ferrox, FerroxError::StorageIo(_)));
        assert_eq!(ferrox.s3_error_code(), "InternalError");
    }

    #[test]
    fn test_display_uses_aws_compatible_message() {
        // AWS clients show this exact phrasing; a Debug-leaking
        // "key=Some(\"cat.jpg\")" would surprise SDK users.
        let key_err = FerroxError::NotFound {
            bucket: "photos".into(),
            key: Some("cat.jpg".into()),
        };
        assert_eq!(key_err.to_string(), "The specified key does not exist.");

        let bucket_err = FerroxError::NotFound {
            bucket: "photos".into(),
            key: None,
        };
        assert_eq!(
            bucket_err.to_string(),
            "The specified bucket does not exist."
        );
    }
}
