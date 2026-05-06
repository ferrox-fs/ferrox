//! Persisted record types: [`BucketMeta`], [`ObjectRecord`], [`ListResult`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// A single bucket record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BucketMeta {
    /// Bucket name (DNS-compatible, 3–63 chars).
    pub name: String,
    /// Access key of the owner.
    pub owner: String,
    /// Creation timestamp.
    #[serde(with = "time::serde::rfc3339")]
    pub created: OffsetDateTime,
    /// Versioning state — `Disabled` until Phase 1 Step 18 sets it otherwise.
    #[serde(default)]
    pub versioning: VersioningState,
    /// Bucket-level tags (Phase 2 Step 25). Up to 10 keys.
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
    /// CORS configuration rules (Phase 2 Step 26). Empty = no rules.
    #[serde(default)]
    pub cors_rules: Vec<CorsRule>,
    /// Default server-side encryption policy (Phase 2 Step 28).
    #[serde(default)]
    pub encryption: Option<EncryptionConfig>,
    /// Bucket notification configuration (Phase 3 Step 41).
    #[serde(default)]
    pub notifications: Vec<NotificationRule>,
}

/// Bucket versioning state. Persisted on the [`BucketMeta`] record so the
/// storage and gateway layers can branch on it without a second lookup.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersioningState {
    /// No versioning. Default for newly created buckets.
    #[default]
    Disabled,
    /// Enabled — every put generates a new version id.
    Enabled,
    /// Suspended — new puts use the literal version id `null`.
    Suspended,
}

/// One CORS rule (subset of the AWS spec we honour).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CorsRule {
    /// Allowed origins (`*` is permitted).
    pub allowed_origins: Vec<String>,
    /// Allowed HTTP methods (validated up-front).
    pub allowed_methods: Vec<String>,
    /// Allowed request headers (`*` permitted).
    pub allowed_headers: Vec<String>,
    /// Headers exposed to the browser via `Access-Control-Expose-Headers`.
    pub expose_headers: Vec<String>,
    /// `Access-Control-Max-Age` value, if set.
    pub max_age_seconds: Option<u32>,
}

/// Default bucket encryption policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptionConfig {
    /// Algorithm name; only `AES256` (SSE-S3) is supported in v1.
    pub algorithm: String,
    /// When `true`, PutObject without an SSE header is rejected with 400.
    pub enforced: bool,
}

/// One bucket-notification rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationRule {
    /// Identifier for this rule.
    pub id: String,
    /// Event prefixes to match (e.g. `s3:ObjectCreated:*`).
    pub events: Vec<String>,
    /// Destination — generic webhook URL or SNS topic ARN.
    pub destination: NotificationDestination,
}

/// Where to deliver a notification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NotificationDestination {
    /// HTTP(S) webhook URL — JSON body POSTed.
    Webhook(String),
    /// SNS topic ARN — POST with SigV4.
    Sns(String),
}

/// A single object metadata record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectRecord {
    /// AWS-compatible ETag (quoted hex MD5).
    pub etag: String,
    /// Object byte size.
    pub size: u64,
    /// Content-Type header value.
    pub content_type: String,
    /// Last-modified timestamp.
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    /// Hex-encoded SHA-256 of the body.
    pub sha256: String,
    /// Hex-encoded CRC32C of the body.
    pub crc32c: String,
    /// Version id, if versioning is `Enabled`/`Suspended`. `None` for
    /// `Disabled` buckets (Phase 0 default).
    #[serde(default)]
    pub version_id: Option<String>,
    /// SSE algorithm, e.g. `"AES256"` (SSE-S3) or `"AES256-C"` (SSE-C).
    /// `None` for unencrypted objects.
    #[serde(default)]
    pub sse_algorithm: Option<String>,
    /// Hex-encoded wrapped DEK for SSE-S3 (nonce + ciphertext + tag), or
    /// hex-encoded random nonce for SSE-C. `None` for unencrypted.
    #[serde(default)]
    pub sse_key_encrypted: Option<String>,
    /// Hex-encoded HMAC-SHA256 of the customer key, used to verify the same
    /// key is presented on subsequent GETs. SSE-C only.
    #[serde(default)]
    pub sse_c_key_hmac: Option<String>,
    /// Object-level tags (Phase 2 Step 25).
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
}

/// Metadata for an in-progress multipart upload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MultipartMeta {
    /// Destination bucket.
    pub bucket: String,
    /// Destination object key.
    pub key: String,
    /// Content-Type supplied at `InitiateMultipartUpload` time.
    pub content_type: String,
    /// When the upload was initiated.
    #[serde(with = "time::serde::rfc3339")]
    pub initiated: OffsetDateTime,
}

/// Page of object records returned by [`MetaStore::list_objects`](crate::MetaStore::list_objects).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListResult {
    /// One [`ObjectRecord`] per matching key, paired with its key string.
    pub objects: Vec<(String, ObjectRecord)>,
    /// `true` when the underlying scan stopped before reaching the end.
    pub is_truncated: bool,
    /// Continuation token to pass on the next request when truncated.
    pub next_continuation_token: Option<String>,
}
