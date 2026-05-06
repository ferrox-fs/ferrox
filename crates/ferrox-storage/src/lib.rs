//! Object storage backends for Ferrox.
//!
//! [`StorageBackend`] is the abstraction every gateway handler is written
//! against. The default impl is [`DiskBackend`](disk::DiskBackend); future
//! backends (S3 mirror, Azure Blob, in-memory test fake) plug into the same
//! trait.
//!
//! Streaming model: `put` consumes a `Stream<Item = Result<Bytes, _>>` so the
//! gateway can pipe the request body straight to disk without buffering.
//! `get` returns the same shape so the gateway can pipe to the response body.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod disk;
#[cfg(feature = "erasure")]
pub mod erasure;
pub mod types;

use std::pin::Pin;

use async_trait::async_trait;
use bytes::Bytes;
use ferrox_error::FerroxError;
use futures::Stream;

pub use crate::types::{GetResult, ObjectMeta, PutResult};

/// Boxed byte stream used for streaming object payloads in and out.
pub type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, FerroxError>> + Send + 'static>>;

/// Pluggable object storage backend.
///
/// Implementations must be cheaply cloneable (`Send + Sync + 'static`) so the
/// axum router can stash an `Arc<dyn StorageBackend>` in shared state.
#[async_trait]
pub trait StorageBackend: Send + Sync + 'static {
    /// Stream `data` into `bucket/key`. `size` is the declared content length;
    /// `content_type` is stored as object metadata.
    async fn put(
        &self,
        bucket: &str,
        key: &str,
        data: ByteStream,
        size: u64,
        content_type: &str,
    ) -> Result<PutResult, FerroxError>;

    /// Stream the bytes of `bucket/key` back out, alongside its metadata.
    async fn get(&self, bucket: &str, key: &str) -> Result<GetResult, FerroxError>;

    /// Remove `bucket/key`. Returns [`FerroxError::NotFound`] if missing.
    async fn delete(&self, bucket: &str, key: &str) -> Result<(), FerroxError>;

    /// Return metadata for `bucket/key` without streaming the body.
    async fn head(&self, bucket: &str, key: &str) -> Result<ObjectMeta, FerroxError>;

    /// Create the storage-side container for a bucket (e.g. directory).
    async fn create_bucket(&self, bucket: &str) -> Result<(), FerroxError>;

    /// Remove the storage-side container for a bucket. Caller must ensure empty.
    async fn delete_bucket(&self, bucket: &str) -> Result<(), FerroxError>;

    /// Whether the storage container for `bucket` exists.
    async fn bucket_exists(&self, bucket: &str) -> Result<bool, FerroxError>;

    /// Server-side copy: duplicate `src_bucket/src_key` as `dest_bucket/dest_key`
    /// without streaming through the gateway. Returns the new object's metadata.
    async fn copy_object(
        &self,
        src_bucket: &str,
        src_key: &str,
        dest_bucket: &str,
        dest_key: &str,
    ) -> Result<PutResult, FerroxError>;

    /// Write one part (1-based `part_number`) of a multipart upload to staging.
    /// Returns the ETag of the written part.
    async fn write_part(
        &self,
        upload_id: &str,
        part_number: u32,
        data: ByteStream,
        size: u64,
    ) -> Result<String, FerroxError>;

    /// Assemble all parts in order and commit as a regular object.
    ///
    /// `parts` is `(part_number, expected_etag)` in ascending order.
    /// The staging directory is removed on success.
    async fn complete_multipart(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: &[(u32, String)],
        content_type: &str,
    ) -> Result<PutResult, FerroxError>;

    /// Remove the staging directory for an aborted multipart upload.
    async fn abort_multipart(&self, upload_id: &str) -> Result<(), FerroxError>;

    /// List the parts written for an in-progress multipart upload.
    ///
    /// Returns `(part_number, byte_size, etag, last_modified)` in ascending
    /// part-number order. Returns an empty vec if no parts have been written yet.
    async fn list_parts(
        &self,
        upload_id: &str,
    ) -> Result<Vec<(u32, u64, String, time::OffsetDateTime)>, FerroxError>;
}
