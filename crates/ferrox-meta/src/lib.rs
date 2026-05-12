//! Metadata store for Ferrox.
//!
//! [`MetaStore`] is the abstraction the gateway speaks to whenever it needs
//! bucket or object metadata that *isn't* derivable from the storage backend
//! alone — owner, creation time, custom headers, list-pagination state.
//!
//! The default impl is [`SledMeta`], an embedded ACID
//! key-value store. RocksDB joins as an opt-in backend in Phase 3.
//!
//! ## Key schema
//!
//! - `buckets` tree:  `bucket_name` → [`BucketMeta`]
//! - `objects` tree:  `bucket\x00key` → [`ObjectRecord`]
//!
//! The null-byte separator guarantees prefix scans on
//! `{bucket}\x00{prefix}` don't bleed across buckets.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(feature = "rocksdb")]
pub mod rocks_store;
pub mod sled_store;
pub mod types;

#[cfg(feature = "rocksdb")]
pub use crate::rocks_store::RocksMeta;

use async_trait::async_trait;
use ferrox_error::FerroxError;

pub use crate::sled_store::SledMeta;
pub use crate::types::{
    BucketMeta, CorsRule, EncryptionConfig, ListResult, MultipartMeta, NotificationDestination,
    NotificationRule, ObjectRecord, VersioningState,
};

/// Pluggable metadata store backing every bucket/object lookup.
#[async_trait]
pub trait MetaStore: Send + Sync + 'static {
    /// Register a new bucket. Errors with [`FerroxError::BucketAlreadyExists`]
    /// if `name` is taken.
    async fn create_bucket(&self, name: &str, owner: &str) -> Result<(), FerroxError>;

    /// Fetch a single bucket record.
    async fn get_bucket(&self, name: &str) -> Result<BucketMeta, FerroxError>;

    /// List all buckets owned by `owner`.
    async fn list_buckets(&self, owner: &str) -> Result<Vec<BucketMeta>, FerroxError>;

    /// Remove a bucket. Caller must ensure no objects remain.
    async fn delete_bucket(&self, name: &str) -> Result<(), FerroxError>;

    /// Persist (or overwrite) the metadata for a single object.
    async fn put_object_meta(
        &self,
        bucket: &str,
        key: &str,
        meta: ObjectRecord,
    ) -> Result<(), FerroxError>;

    /// Fetch a single object record.
    async fn get_object_meta(&self, bucket: &str, key: &str) -> Result<ObjectRecord, FerroxError>;

    /// Remove a single object record.
    async fn delete_object_meta(&self, bucket: &str, key: &str) -> Result<(), FerroxError>;

    /// Paginated, prefix-filtered list of object metadata records.
    async fn list_objects(
        &self,
        bucket: &str,
        prefix: Option<&str>,
        max_keys: u32,
        continuation: Option<&str>,
    ) -> Result<ListResult, FerroxError>;

    /// Record a new in-progress multipart upload.
    async fn create_multipart_upload(
        &self,
        upload_id: &str,
        meta: MultipartMeta,
    ) -> Result<(), FerroxError>;

    /// Retrieve the metadata for an in-progress multipart upload.
    async fn get_multipart_upload(&self, upload_id: &str) -> Result<MultipartMeta, FerroxError>;

    /// Remove the tracking record for a multipart upload (complete or abort).
    async fn delete_multipart_upload(&self, upload_id: &str) -> Result<(), FerroxError>;

    /// List all in-progress multipart uploads for a bucket.
    async fn list_multipart_uploads(
        &self,
        bucket: &str,
    ) -> Result<Vec<(String, MultipartMeta)>, FerroxError>;

    /// Update the versioning state on a bucket.
    async fn set_bucket_versioning(
        &self,
        bucket: &str,
        state: crate::types::VersioningState,
    ) -> Result<(), FerroxError>;

    /// Replace the bucket-level tag set.
    async fn set_bucket_tags(
        &self,
        bucket: &str,
        tags: std::collections::BTreeMap<String, String>,
    ) -> Result<(), FerroxError>;

    /// Replace the bucket CORS rule list.
    async fn set_bucket_cors(
        &self,
        bucket: &str,
        rules: Vec<crate::types::CorsRule>,
    ) -> Result<(), FerroxError>;

    /// Replace the bucket default-encryption policy. `None` clears it.
    async fn set_bucket_encryption(
        &self,
        bucket: &str,
        cfg: Option<crate::types::EncryptionConfig>,
    ) -> Result<(), FerroxError>;

    /// Replace the bucket notification rules.
    async fn set_bucket_notifications(
        &self,
        bucket: &str,
        rules: Vec<crate::types::NotificationRule>,
    ) -> Result<(), FerroxError>;
}
