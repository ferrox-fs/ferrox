//! On-disk [`StorageBackend`] implementation.
//!
//! ## Layout
//!
//! ```text
//! {data_dir}/{bucket}/{first2_chars_of_sha256(key)}/{percent_encoded_key}
//! {data_dir}/{bucket}/{first2_chars_of_sha256(key)}/{percent_encoded_key}.meta.json
//! ```
//!
//! The two-char prefix shards keep directory fan-out manageable on common
//! filesystems (ext4/xfs/apfs). Object key collisions are impossible because
//! the percent-encoded key follows the prefix.
//!
//! ## Atomicity
//!
//! `put` writes to `{final}.tmp`, fsyncs (if `fsync` config is on), then
//! renames into place — atomic on POSIX. Sidecar `.meta.json` is written
//! the same way before the rename of the data file completes.
//!
//! ## Checksums
//!
//! While streaming the body to disk, the backend computes SHA-256, MD5, and
//! CRC32C in a single pass. The hex digests + content type land in the
//! `.meta.json` sidecar. `get` re-checks SHA-256 against the sidecar and
//! returns [`FerroxError::ChecksumMismatch`] if the file has been tampered with.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use bytes::Bytes;
use crc32c::Crc32cHasher;
use ferrox_error::FerroxError;
use futures::StreamExt;
use md5::Md5;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::hash::Hasher;
use time::OffsetDateTime;
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{ByteStream, GetResult, ObjectMeta, PutResult, StorageBackend};

/// Characters NOT allowed in a single filename component on common
/// filesystems. We percent-encode any of these inside the on-disk key.
const FILENAME_ESCAPE: &AsciiSet = &CONTROLS
    .add(b'/')
    .add(b'\\')
    .add(b':')
    .add(b'*')
    .add(b'?')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'|')
    .add(b'%');

#[derive(Debug, Serialize, Deserialize)]
struct Sidecar {
    etag: String,
    size: u64,
    content_type: String,
    sha256: String,
    crc32c: String,
    #[serde(with = "time::serde::rfc3339")]
    last_modified: OffsetDateTime,
}

/// Local-disk backend. Cheap to clone; the `Arc<DiskBackend>` pattern lets
/// the gateway router own one and hand `&self` references to handlers.
#[derive(Debug, Clone)]
pub struct DiskBackend {
    root: PathBuf,
    fsync: bool,
}

impl DiskBackend {
    /// Create a new [`DiskBackend`] rooted at `root`. The directory is
    /// created (with `mkdir -p` semantics) if it does not exist.
    pub async fn new(root: impl Into<PathBuf>, fsync: bool) -> Result<Self, FerroxError> {
        let root = root.into();
        fs::create_dir_all(&root).await?;
        Ok(Self { root, fsync })
    }

    fn bucket_dir(&self, bucket: &str) -> PathBuf {
        self.root.join(bucket)
    }

    fn object_paths(&self, bucket: &str, key: &str) -> (PathBuf, PathBuf, PathBuf) {
        let mut h = Sha256::new();
        h.update(key.as_bytes());
        let digest = h.finalize();
        let prefix = hex::encode(&digest[..1]); // first 2 hex chars = 1 byte
        let filename = utf8_percent_encode(key, FILENAME_ESCAPE).to_string();
        let dir = self.root.join(bucket).join(&prefix);
        let data = dir.join(&filename);
        let meta = dir.join(format!("{filename}.meta.json"));
        (dir, data, meta)
    }
}

#[async_trait]
impl StorageBackend for DiskBackend {
    async fn put(
        &self,
        bucket: &str,
        key: &str,
        mut data: ByteStream,
        size_hint: u64,
        content_type: &str,
    ) -> Result<PutResult, FerroxError> {
        if !self.bucket_exists(bucket).await? {
            return Err(FerroxError::NotFound {
                bucket: bucket.into(),
                key: None,
            });
        }
        let (dir, data_path, meta_path) = self.object_paths(bucket, key);
        fs::create_dir_all(&dir).await?;
        let tmp = data_path.with_extension("tmp");

        let mut file = File::create(&tmp).await?;
        let mut sha = Sha256::new();
        let mut md5 = Md5::new();
        let mut crc = Crc32cHasher::default();
        let mut written: u64 = 0;

        while let Some(chunk) = data.next().await {
            let chunk: Bytes = chunk?;
            sha.update(&chunk);
            md5.update(&chunk);
            crc.write(&chunk);
            file.write_all(&chunk).await?;
            written += chunk.len() as u64;
        }
        if self.fsync {
            file.sync_all().await?;
        }
        drop(file);

        if size_hint != 0 && written != size_hint {
            let _ = fs::remove_file(&tmp).await;
            return Err(FerroxError::InvalidRequest(format!(
                "content-length mismatch: declared={size_hint}, actual={written}"
            )));
        }

        let sha_hex = hex::encode(sha.finalize());
        let md5_hex = hex::encode(md5.finalize());
        let crc_hex = format!("{:08x}", crc.finish() as u32);
        let etag = format!("\"{md5_hex}\"");
        let last_modified = OffsetDateTime::now_utc();

        let sidecar = Sidecar {
            etag: etag.clone(),
            size: written,
            content_type: content_type.to_string(),
            sha256: sha_hex.clone(),
            crc32c: crc_hex.clone(),
            last_modified,
        };
        let sidecar_bytes = serde_json::to_vec(&sidecar)
            .map_err(|e| FerroxError::Internal(format!("sidecar serialize: {e}")))?;
        let meta_tmp = meta_path.with_extension("json.tmp");
        let mut mf = File::create(&meta_tmp).await?;
        mf.write_all(&sidecar_bytes).await?;
        if self.fsync {
            mf.sync_all().await?;
        }
        drop(mf);

        fs::rename(&tmp, &data_path).await?;
        fs::rename(&meta_tmp, &meta_path).await?;

        Ok(PutResult {
            etag,
            size: written,
            sha256: sha_hex,
            crc32c: crc_hex,
            last_modified,
        })
    }

    async fn get(&self, bucket: &str, key: &str) -> Result<GetResult, FerroxError> {
        if !self.bucket_exists(bucket).await? {
            return Err(FerroxError::NotFound {
                bucket: bucket.into(),
                key: None,
            });
        }
        let (_, data_path, meta_path) = self.object_paths(bucket, key);
        let sidecar = read_sidecar(&meta_path).await.map_err(|e| match e {
            FerroxError::StorageIo(io) if io.kind() == std::io::ErrorKind::NotFound => {
                FerroxError::NotFound {
                    bucket: bucket.into(),
                    key: Some(key.into()),
                }
            }
            other => other,
        })?;

        // Verify SHA-256 of file matches sidecar before streaming.
        let mut f = File::open(&data_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                FerroxError::NotFound {
                    bucket: bucket.into(),
                    key: Some(key.into()),
                }
            } else {
                FerroxError::StorageIo(e)
            }
        })?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = f.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let actual = hex::encode(hasher.finalize());
        if actual != sidecar.sha256 {
            return Err(FerroxError::ChecksumMismatch {
                expected: sidecar.sha256,
                got: actual,
            });
        }

        let meta = ObjectMeta {
            etag: sidecar.etag,
            size: sidecar.size,
            content_type: sidecar.content_type,
            last_modified: sidecar.last_modified,
            sha256: sidecar.sha256,
            crc32c: sidecar.crc32c,
        };
        let stream = file_to_stream(data_path).await?;
        Ok(GetResult { stream, meta })
    }

    async fn delete(&self, bucket: &str, key: &str) -> Result<(), FerroxError> {
        let (_, data_path, meta_path) = self.object_paths(bucket, key);
        let res = fs::remove_file(&data_path).await;
        match res {
            Ok(_) => {
                let _ = fs::remove_file(&meta_path).await;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(FerroxError::NotFound {
                bucket: bucket.into(),
                key: Some(key.into()),
            }),
            Err(e) => Err(e.into()),
        }
    }

    async fn head(&self, bucket: &str, key: &str) -> Result<ObjectMeta, FerroxError> {
        let (_, _, meta_path) = self.object_paths(bucket, key);
        let sidecar = read_sidecar(&meta_path).await.map_err(|e| match e {
            FerroxError::StorageIo(io) if io.kind() == std::io::ErrorKind::NotFound => {
                FerroxError::NotFound {
                    bucket: bucket.into(),
                    key: Some(key.into()),
                }
            }
            other => other,
        })?;
        Ok(ObjectMeta {
            etag: sidecar.etag,
            size: sidecar.size,
            content_type: sidecar.content_type,
            last_modified: sidecar.last_modified,
            sha256: sidecar.sha256,
            crc32c: sidecar.crc32c,
        })
    }

    async fn create_bucket(&self, bucket: &str) -> Result<(), FerroxError> {
        let dir = self.bucket_dir(bucket);
        if fs::try_exists(&dir).await? {
            return Err(FerroxError::BucketAlreadyExists(bucket.into()));
        }
        fs::create_dir_all(&dir).await?;
        Ok(())
    }

    async fn delete_bucket(&self, bucket: &str) -> Result<(), FerroxError> {
        let dir = self.bucket_dir(bucket);
        if !fs::try_exists(&dir).await? {
            return Err(FerroxError::NotFound {
                bucket: bucket.into(),
                key: None,
            });
        }
        fs::remove_dir_all(&dir).await?;
        Ok(())
    }

    async fn bucket_exists(&self, bucket: &str) -> Result<bool, FerroxError> {
        Ok(fs::try_exists(self.bucket_dir(bucket)).await?)
    }

    async fn write_part(
        &self,
        upload_id: &str,
        part_number: u32,
        mut data: ByteStream,
        _size: u64,
    ) -> Result<String, FerroxError> {
        let staging = self.root.join(".multipart").join(upload_id);
        fs::create_dir_all(&staging).await?;
        let part_path = staging.join(format!("part_{part_number:05}"));
        let tmp = part_path.with_extension("tmp");

        let mut file = File::create(&tmp).await?;
        let mut md5 = Md5::new();
        while let Some(chunk) = data.next().await {
            let chunk: Bytes = chunk?;
            md5.update(&chunk);
            file.write_all(&chunk).await?;
        }
        if self.fsync {
            file.sync_all().await?;
        }
        drop(file);
        fs::rename(&tmp, &part_path).await?;

        let etag = format!("\"{}\"", hex::encode(md5.finalize()));
        // Persist ETag so list_parts can read it without re-hashing.
        let etag_path = staging.join(format!("part_{part_number:05}.etag"));
        fs::write(&etag_path, etag.as_bytes()).await?;
        Ok(etag)
    }

    async fn list_parts(
        &self,
        upload_id: &str,
    ) -> Result<Vec<(u32, u64, String, time::OffsetDateTime)>, FerroxError> {
        let staging = self.root.join(".multipart").join(upload_id);
        if !fs::try_exists(&staging).await? {
            return Ok(Vec::new());
        }
        let mut entries = fs::read_dir(&staging).await?;
        let mut parts: Vec<(u32, u64, String, time::OffsetDateTime)> = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // Only look at part data files (not .etag or .tmp sidecars).
            if !name.starts_with("part_") || name.contains('.') {
                continue;
            }
            let part_number: u32 = name
                .strip_prefix("part_")
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| {
                    FerroxError::Internal(format!("unexpected staging file name: {name}"))
                })?;
            let meta = entry.metadata().await?;
            let size = meta.len();
            let modified = meta
                .modified()
                .map(time::OffsetDateTime::from)
                .unwrap_or_else(|_| time::OffsetDateTime::UNIX_EPOCH);
            let etag_path = staging.join(format!("part_{part_number:05}.etag"));
            let etag = if fs::try_exists(&etag_path).await? {
                String::from_utf8_lossy(&fs::read(&etag_path).await?).into_owned()
            } else {
                String::from("\"\"")
            };
            parts.push((part_number, size, etag, modified));
        }
        parts.sort_by_key(|(n, _, _, _)| *n);
        Ok(parts)
    }

    async fn complete_multipart(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: &[(u32, String)],
        content_type: &str,
    ) -> Result<PutResult, FerroxError> {
        let staging = self.root.join(".multipart").join(upload_id);
        let (dir, data_path, meta_path) = self.object_paths(bucket, key);
        fs::create_dir_all(&dir).await?;

        let tmp = data_path.with_extension("tmp");
        let mut out_file = File::create(&tmp).await?;
        let mut sha = Sha256::new();
        let mut crc = Crc32cHasher::default();
        let mut combined_md5 = Md5::new();
        let mut total_size: u64 = 0;

        // Stream each part through a fixed-size buffer: read part bytes,
        // feed all hashers and the output file inline. The previous impl
        // accumulated the whole part in a Vec (up to 5 GiB) and then
        // re-read it for the combined-ETag pass — both gone now.
        let mut buf = vec![0u8; 256 * 1024];
        for (part_number, expected_etag) in parts {
            let part_path = staging.join(format!("part_{part_number:05}"));
            let mut part_file = File::open(&part_path).await.map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    FerroxError::InvalidRequest(format!("part {part_number} not found"))
                } else {
                    FerroxError::StorageIo(e)
                }
            })?;
            let mut part_md5 = Md5::new();
            loop {
                let n = part_file.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                let chunk = &buf[..n];
                part_md5.update(chunk);
                sha.update(chunk);
                crc.write(chunk);
                out_file.write_all(chunk).await?;
                total_size += n as u64;
            }
            let part_md5_bytes = part_md5.finalize();
            let part_etag = format!("\"{}\"", hex::encode(part_md5_bytes));
            if &part_etag != expected_etag {
                return Err(FerroxError::ChecksumMismatch {
                    expected: expected_etag.clone(),
                    got: part_etag,
                });
            }
            combined_md5.update(part_md5_bytes.as_slice());
        }

        if self.fsync {
            out_file.sync_all().await?;
        }
        drop(out_file);

        let sha_hex = hex::encode(sha.finalize());
        let crc_hex = format!("{:08x}", crc.finish() as u32);
        let last_modified = OffsetDateTime::now_utc();
        // Multi-part ETag: md5 of concatenated part MD5s + "-{parts_count}".
        let parts_count = parts.len();
        let etag = format!("\"{}-{parts_count}\"", hex::encode(combined_md5.finalize()));

        let sidecar = Sidecar {
            etag: etag.clone(),
            size: total_size,
            content_type: content_type.to_string(),
            sha256: sha_hex.clone(),
            crc32c: crc_hex.clone(),
            last_modified,
        };
        let sidecar_bytes = serde_json::to_vec(&sidecar)
            .map_err(|e| FerroxError::Internal(format!("sidecar serialize: {e}")))?;
        let meta_tmp = meta_path.with_extension("json.tmp");
        let mut mf = File::create(&meta_tmp).await?;
        mf.write_all(&sidecar_bytes).await?;
        if self.fsync {
            mf.sync_all().await?;
        }
        drop(mf);

        fs::rename(&tmp, &data_path).await?;
        fs::rename(&meta_tmp, &meta_path).await?;

        // Clean up staging directory.
        let _ = fs::remove_dir_all(&staging).await;

        Ok(PutResult {
            etag,
            size: total_size,
            sha256: sha_hex,
            crc32c: crc_hex,
            last_modified,
        })
    }

    async fn abort_multipart(&self, upload_id: &str) -> Result<(), FerroxError> {
        let staging = self.root.join(".multipart").join(upload_id);
        if fs::try_exists(&staging).await? {
            fs::remove_dir_all(&staging).await?;
        }
        Ok(())
    }

    async fn copy_object(
        &self,
        src_bucket: &str,
        src_key: &str,
        dest_bucket: &str,
        dest_key: &str,
    ) -> Result<PutResult, FerroxError> {
        let (_, src_data, src_meta) = self.object_paths(src_bucket, src_key);
        let (dest_dir, dest_data, dest_meta) = self.object_paths(dest_bucket, dest_key);

        // Verify source sidecar exists (gives NotFound if missing).
        let sidecar = read_sidecar(&src_meta).await.map_err(|e| match e {
            FerroxError::StorageIo(io) if io.kind() == std::io::ErrorKind::NotFound => {
                FerroxError::NotFound {
                    bucket: src_bucket.into(),
                    key: Some(src_key.into()),
                }
            }
            other => other,
        })?;

        if !self.bucket_exists(dest_bucket).await? {
            return Err(FerroxError::NotFound {
                bucket: dest_bucket.into(),
                key: None,
            });
        }
        fs::create_dir_all(&dest_dir).await?;

        let data_tmp = dest_data.with_extension("tmp");
        let meta_tmp = dest_meta.with_extension("json.tmp");

        // Atomic copy: tmp → rename.
        fs::copy(&src_data, &data_tmp).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                FerroxError::NotFound {
                    bucket: src_bucket.into(),
                    key: Some(src_key.into()),
                }
            } else {
                FerroxError::StorageIo(e)
            }
        })?;

        if self.fsync {
            let f = File::open(&data_tmp).await?;
            f.sync_all().await?;
        }

        let last_modified = OffsetDateTime::now_utc();
        let new_sidecar = Sidecar {
            etag: sidecar.etag.clone(),
            size: sidecar.size,
            content_type: sidecar.content_type.clone(),
            sha256: sidecar.sha256.clone(),
            crc32c: sidecar.crc32c.clone(),
            last_modified,
        };
        let meta_bytes = serde_json::to_vec(&new_sidecar)
            .map_err(|e| FerroxError::Internal(format!("sidecar serialize: {e}")))?;
        let mut mf = File::create(&meta_tmp).await?;
        mf.write_all(&meta_bytes).await?;
        if self.fsync {
            mf.sync_all().await?;
        }
        drop(mf);

        fs::rename(&data_tmp, &dest_data).await?;
        fs::rename(&meta_tmp, &dest_meta).await?;

        Ok(PutResult {
            etag: sidecar.etag,
            size: sidecar.size,
            sha256: sidecar.sha256,
            crc32c: sidecar.crc32c,
            last_modified,
        })
    }
}

async fn read_sidecar(path: &Path) -> Result<Sidecar, FerroxError> {
    let bytes = fs::read(path).await?;
    serde_json::from_slice(&bytes).map_err(|e| FerroxError::Internal(format!("sidecar parse: {e}")))
}

async fn file_to_stream(path: PathBuf) -> Result<ByteStream, FerroxError> {
    let file = File::open(&path).await?;
    let stream = tokio_util::io::ReaderStream::new(file).map(|r| r.map_err(FerroxError::StorageIo));
    Ok(Box::pin(stream))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures::stream;
    use tempfile::TempDir;

    use super::*;

    async fn make() -> (TempDir, DiskBackend) {
        let tmp = TempDir::new().unwrap();
        let backend = DiskBackend::new(tmp.path(), true).await.unwrap();
        backend.create_bucket("b").await.unwrap();
        (tmp, backend)
    }

    fn body(bytes: &'static [u8]) -> ByteStream {
        Box::pin(stream::iter(vec![Ok::<Bytes, FerroxError>(
            Bytes::from_static(bytes),
        )]))
    }

    async fn collect(mut s: ByteStream) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(c) = s.next().await {
            out.extend_from_slice(&c.unwrap());
        }
        out
    }

    #[tokio::test]
    async fn test_put_then_get_returns_same_bytes() {
        let (_t, b) = make().await;
        let payload = b"hello ferrox";
        let put = b
            .put("b", "k", body(payload), payload.len() as u64, "text/plain")
            .await
            .unwrap();
        assert_eq!(put.size, payload.len() as u64);
        let got = b.get("b", "k").await.unwrap();
        assert_eq!(got.meta.size, payload.len() as u64);
        assert_eq!(collect(got.stream).await, payload);
    }

    #[tokio::test]
    async fn test_put_then_delete_then_get_returns_not_found() {
        let (_t, b) = make().await;
        b.put("b", "k", body(b"x"), 1, "text/plain").await.unwrap();
        b.delete("b", "k").await.unwrap();
        let res = b.get("b", "k").await;
        assert!(matches!(res, Err(FerroxError::NotFound { .. })));
    }

    #[tokio::test]
    async fn test_checksum_validation_catches_corrupt_file() {
        let (_t, b) = make().await;
        b.put("b", "k", body(b"abcd"), 4, "text/plain")
            .await
            .unwrap();
        // Corrupt the data file directly.
        let (_, data_path, _) = b.object_paths("b", "k");
        tokio::fs::write(&data_path, b"XXXX").await.unwrap();
        let res = b.get("b", "k").await;
        assert!(matches!(res, Err(FerroxError::ChecksumMismatch { .. })));
    }

    #[tokio::test]
    async fn test_head_returns_meta_without_streaming() {
        let (_t, b) = make().await;
        let put = b
            .put("b", "k", body(b"abcd"), 4, "text/plain")
            .await
            .unwrap();
        let head = b.head("b", "k").await.unwrap();
        assert_eq!(head.size, 4);
        assert_eq!(head.etag, put.etag);
    }

    #[tokio::test]
    async fn test_put_bucket_missing_returns_not_found() {
        let (_t, b) = make().await;
        let res = b.put("nope", "k", body(b"x"), 1, "text/plain").await;
        assert!(matches!(res, Err(FerroxError::NotFound { .. })));
    }

    #[tokio::test]
    async fn test_create_bucket_twice_returns_already_exists() {
        let (_t, b) = make().await;
        let res = b.create_bucket("b").await;
        assert!(matches!(res, Err(FerroxError::BucketAlreadyExists(_))));
    }

    #[tokio::test]
    async fn test_content_length_mismatch_rejected() {
        let (_t, b) = make().await;
        // declare 100 but stream only 4
        let res = b.put("b", "k", body(b"abcd"), 100, "text/plain").await;
        assert!(matches!(res, Err(FerroxError::InvalidRequest(_))));
    }
}
