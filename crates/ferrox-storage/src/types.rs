//! Public value types returned by [`StorageBackend`](crate::StorageBackend).

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::ByteStream;

/// Result of a successful `put`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PutResult {
    /// AWS-compatible ETag — hex-encoded MD5 of the body, wrapped in `"`.
    pub etag: String,
    /// Final on-disk byte size.
    pub size: u64,
    /// Hex-encoded SHA-256 of the body.
    pub sha256: String,
    /// Hex-encoded CRC32C of the body.
    pub crc32c: String,
    /// Wall-clock time the object was committed.
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
}

/// Persisted metadata for an object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectMeta {
    /// AWS-compatible ETag.
    pub etag: String,
    /// Stored byte size.
    pub size: u64,
    /// Caller-supplied Content-Type (default `application/octet-stream`).
    pub content_type: String,
    /// Wall-clock time the object was committed.
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    /// Hex-encoded SHA-256 of the body.
    pub sha256: String,
    /// Hex-encoded CRC32C of the body.
    pub crc32c: String,
}

/// Result of a successful `get`.
pub struct GetResult {
    /// Streaming body. Driven by the storage backend.
    pub stream: ByteStream,
    /// Metadata for the object being streamed.
    pub meta: ObjectMeta,
}

impl std::fmt::Debug for GetResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetResult")
            .field("meta", &self.meta)
            .field("stream", &"<ByteStream>")
            .finish()
    }
}
