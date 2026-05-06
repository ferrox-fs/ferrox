//! Erasure-coded backend interface (Phase 3 Step 44 — proposed v2).
//!
//! Defined now to lock in the API shape so v2's distributed mode doesn't
//! require breaking changes. All methods currently return
//! `Err(FerroxError::Internal("erasure backend not implemented"))`.
//!
//! The choice of Reed-Solomon (4 data + 2 parity by default) is documented in
//! `docs/adr/003-erasure-coding.md`.

#![cfg(feature = "erasure")]

use async_trait::async_trait;
use ferrox_error::FerroxError;

use crate::{ByteStream, GetResult, ObjectMeta, PutResult, StorageBackend};

/// Address of one storage node in an erasure group.
#[derive(Debug, Clone)]
pub struct NodeAddr {
    /// Hostname:port.
    pub addr: String,
    /// Optional zone hint for failure-domain placement.
    pub zone: Option<String>,
}

/// Configuration for a Reed-Solomon erasure group.
#[derive(Debug, Clone)]
pub struct ErasureConfig {
    /// Number of data shards (e.g. 4).
    pub data_shards: u8,
    /// Number of parity shards (e.g. 2). `data + parity` must equal `nodes.len()`.
    pub parity_shards: u8,
    /// Backing nodes, one shard per node.
    pub nodes: Vec<NodeAddr>,
}

/// Erasure-coded backend. Stub — every method returns `Unimplemented`.
pub struct ErasureBackend {
    _cfg: ErasureConfig,
}

impl ErasureBackend {
    /// Create a new `ErasureBackend` placeholder.
    pub fn new(cfg: ErasureConfig) -> Self {
        Self { _cfg: cfg }
    }
}

fn unimpl<T>() -> Result<T, FerroxError> {
    Err(FerroxError::Internal(
        "erasure backend not implemented (v2)".into(),
    ))
}

#[async_trait]
impl StorageBackend for ErasureBackend {
    async fn put(
        &self,
        _bucket: &str,
        _key: &str,
        _data: ByteStream,
        _size: u64,
        _content_type: &str,
    ) -> Result<PutResult, FerroxError> {
        unimpl()
    }
    async fn get(&self, _bucket: &str, _key: &str) -> Result<GetResult, FerroxError> {
        unimpl()
    }
    async fn delete(&self, _bucket: &str, _key: &str) -> Result<(), FerroxError> {
        unimpl()
    }
    async fn head(&self, _bucket: &str, _key: &str) -> Result<ObjectMeta, FerroxError> {
        unimpl()
    }
    async fn create_bucket(&self, _bucket: &str) -> Result<(), FerroxError> {
        unimpl()
    }
    async fn delete_bucket(&self, _bucket: &str) -> Result<(), FerroxError> {
        unimpl()
    }
    async fn bucket_exists(&self, _bucket: &str) -> Result<bool, FerroxError> {
        unimpl()
    }
    async fn copy_object(
        &self,
        _src_bucket: &str,
        _src_key: &str,
        _dst_bucket: &str,
        _dst_key: &str,
    ) -> Result<PutResult, FerroxError> {
        unimpl()
    }
    async fn write_part(
        &self,
        _upload_id: &str,
        _part_number: u32,
        _data: ByteStream,
        _size: u64,
    ) -> Result<String, FerroxError> {
        unimpl()
    }
    async fn complete_multipart(
        &self,
        _bucket: &str,
        _key: &str,
        _upload_id: &str,
        _parts: &[(u32, String)],
        _content_type: &str,
    ) -> Result<PutResult, FerroxError> {
        unimpl()
    }
    async fn abort_multipart(&self, _upload_id: &str) -> Result<(), FerroxError> {
        unimpl()
    }
}
