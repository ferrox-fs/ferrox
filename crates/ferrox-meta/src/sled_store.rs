//! Default [`MetaStore`] implementation backed by [`sled`].
//!
//! sled is sync, so every method shells out to [`tokio::task::spawn_blocking`]
//! to keep the gateway runtime responsive under heavy I/O.

use async_trait::async_trait;
use ferrox_error::FerroxError;
use sled::Db;
use time::OffsetDateTime;

use crate::types::{
    BucketMeta, CorsRule, EncryptionConfig, ListResult, MultipartMeta, NotificationRule,
    ObjectRecord, VersioningState,
};
use crate::MetaStore;

const BUCKETS_TREE: &str = "buckets";
const OBJECTS_TREE: &str = "objects";
const MULTIPART_TREE: &str = "multipart_uploads";
const SEP: u8 = 0;

/// sled-backed metadata store.
#[derive(Clone, Debug)]
pub struct SledMeta {
    db: Db,
}

impl SledMeta {
    /// Open a sled database rooted at `path`.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, FerroxError> {
        let db = sled::open(path).map_err(map_sled)?;
        Ok(Self { db })
    }

    /// Open an in-memory sled (test only).
    pub fn in_memory() -> Result<Self, FerroxError> {
        let cfg = sled::Config::new().temporary(true);
        let db = cfg.open().map_err(map_sled)?;
        Ok(Self { db })
    }

    fn buckets(&self) -> Result<sled::Tree, FerroxError> {
        self.db.open_tree(BUCKETS_TREE).map_err(map_sled)
    }

    fn objects(&self) -> Result<sled::Tree, FerroxError> {
        self.db.open_tree(OBJECTS_TREE).map_err(map_sled)
    }

    fn multipart(&self) -> Result<sled::Tree, FerroxError> {
        self.db.open_tree(MULTIPART_TREE).map_err(map_sled)
    }
}

fn map_sled(e: sled::Error) -> FerroxError {
    FerroxError::MetaStore(e.to_string())
}

fn enc<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, FerroxError> {
    bincode::serde::encode_to_vec(v, bincode::config::standard())
        .map_err(|e| FerroxError::MetaStore(format!("encode: {e}")))
}

fn dec<T: for<'de> serde::Deserialize<'de>>(b: &[u8]) -> Result<T, FerroxError> {
    let (v, _) = bincode::serde::decode_from_slice(b, bincode::config::standard())
        .map_err(|e| FerroxError::MetaStore(format!("decode: {e}")))?;
    Ok(v)
}

fn obj_key(bucket: &str, key: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(bucket.len() + 1 + key.len());
    out.extend_from_slice(bucket.as_bytes());
    out.push(SEP);
    out.extend_from_slice(key.as_bytes());
    out
}

fn obj_key_prefix(bucket: &str, prefix: Option<&str>) -> Vec<u8> {
    let mut out = Vec::with_capacity(bucket.len() + 1 + prefix.map_or(0, str::len));
    out.extend_from_slice(bucket.as_bytes());
    out.push(SEP);
    if let Some(p) = prefix {
        out.extend_from_slice(p.as_bytes());
    }
    out
}

fn split_obj_key(full: &[u8]) -> Option<(&[u8], &[u8])> {
    full.iter()
        .position(|b| *b == SEP)
        .map(|i| (&full[..i], &full[i + 1..]))
}

#[async_trait]
impl MetaStore for SledMeta {
    async fn create_bucket(&self, name: &str, owner: &str) -> Result<(), FerroxError> {
        let me = self.clone();
        let name = name.to_string();
        let owner = owner.to_string();
        tokio::task::spawn_blocking(move || -> Result<(), FerroxError> {
            let tree = me.buckets()?;
            if tree.contains_key(name.as_bytes()).map_err(map_sled)? {
                return Err(FerroxError::BucketAlreadyExists(name));
            }
            let meta = BucketMeta {
                name: name.clone(),
                owner,
                created: OffsetDateTime::now_utc(),
                versioning: VersioningState::Disabled,
                tags: Default::default(),
                cors_rules: Vec::new(),
                encryption: None,
                notifications: Vec::new(),
            };
            tree.insert(name.as_bytes(), enc(&meta)?)
                .map_err(map_sled)?;
            tree.flush().map_err(map_sled)?;
            Ok(())
        })
        .await
        .map_err(|e| FerroxError::Internal(format!("join: {e}")))?
    }

    async fn get_bucket(&self, name: &str) -> Result<BucketMeta, FerroxError> {
        let me = self.clone();
        let name = name.to_string();
        tokio::task::spawn_blocking(move || -> Result<BucketMeta, FerroxError> {
            let tree = me.buckets()?;
            let v = tree
                .get(name.as_bytes())
                .map_err(map_sled)?
                .ok_or_else(|| FerroxError::NotFound {
                    bucket: name.clone(),
                    key: None,
                })?;
            dec(&v)
        })
        .await
        .map_err(|e| FerroxError::Internal(format!("join: {e}")))?
    }

    async fn list_buckets(&self, owner: &str) -> Result<Vec<BucketMeta>, FerroxError> {
        let me = self.clone();
        let owner = owner.to_string();
        tokio::task::spawn_blocking(move || -> Result<Vec<BucketMeta>, FerroxError> {
            let tree = me.buckets()?;
            let mut out = Vec::new();
            for kv in tree.iter() {
                let (_, v) = kv.map_err(map_sled)?;
                let m: BucketMeta = dec(&v)?;
                if m.owner == owner {
                    out.push(m);
                }
            }
            Ok(out)
        })
        .await
        .map_err(|e| FerroxError::Internal(format!("join: {e}")))?
    }

    async fn delete_bucket(&self, name: &str) -> Result<(), FerroxError> {
        let me = self.clone();
        let name = name.to_string();
        tokio::task::spawn_blocking(move || -> Result<(), FerroxError> {
            let tree = me.buckets()?;
            let removed = tree.remove(name.as_bytes()).map_err(map_sled)?;
            if removed.is_none() {
                return Err(FerroxError::NotFound {
                    bucket: name,
                    key: None,
                });
            }
            tree.flush().map_err(map_sled)?;
            Ok(())
        })
        .await
        .map_err(|e| FerroxError::Internal(format!("join: {e}")))?
    }

    async fn put_object_meta(
        &self,
        bucket: &str,
        key: &str,
        meta: ObjectRecord,
    ) -> Result<(), FerroxError> {
        let me = self.clone();
        let k = obj_key(bucket, key);
        tokio::task::spawn_blocking(move || -> Result<(), FerroxError> {
            let tree = me.objects()?;
            tree.insert(k, enc(&meta)?).map_err(map_sled)?;
            tree.flush().map_err(map_sled)?;
            Ok(())
        })
        .await
        .map_err(|e| FerroxError::Internal(format!("join: {e}")))?
    }

    async fn get_object_meta(&self, bucket: &str, key: &str) -> Result<ObjectRecord, FerroxError> {
        let me = self.clone();
        let k = obj_key(bucket, key);
        let bucket_s = bucket.to_string();
        let key_s = key.to_string();
        tokio::task::spawn_blocking(move || -> Result<ObjectRecord, FerroxError> {
            let tree = me.objects()?;
            let v = tree
                .get(&k)
                .map_err(map_sled)?
                .ok_or(FerroxError::NotFound {
                    bucket: bucket_s,
                    key: Some(key_s),
                })?;
            dec(&v)
        })
        .await
        .map_err(|e| FerroxError::Internal(format!("join: {e}")))?
    }

    async fn delete_object_meta(&self, bucket: &str, key: &str) -> Result<(), FerroxError> {
        let me = self.clone();
        let k = obj_key(bucket, key);
        tokio::task::spawn_blocking(move || -> Result<(), FerroxError> {
            let tree = me.objects()?;
            tree.remove(&k).map_err(map_sled)?;
            tree.flush().map_err(map_sled)?;
            Ok(())
        })
        .await
        .map_err(|e| FerroxError::Internal(format!("join: {e}")))?
    }

    async fn list_objects(
        &self,
        bucket: &str,
        prefix: Option<&str>,
        max_keys: u32,
        continuation: Option<&str>,
    ) -> Result<ListResult, FerroxError> {
        let me = self.clone();
        let bucket = bucket.to_string();
        let prefix = prefix.map(str::to_string);
        let continuation = continuation.map(str::to_string);
        tokio::task::spawn_blocking(move || -> Result<ListResult, FerroxError> {
            let tree = me.objects()?;
            let scan_prefix = obj_key_prefix(&bucket, prefix.as_deref());
            let start_key = match continuation {
                Some(c) => obj_key(&bucket, &c),
                None => scan_prefix.clone(),
            };

            let mut out = Vec::new();
            let mut is_truncated = false;
            let mut next_token = None;
            let max = max_keys.max(1) as usize;

            for kv in tree.range(start_key..) {
                let (k, v) = kv.map_err(map_sled)?;
                if !k.starts_with(&scan_prefix) {
                    break;
                }
                if out.len() >= max {
                    is_truncated = true;
                    let (_b, key_bytes) = split_obj_key(&k)
                        .ok_or_else(|| FerroxError::MetaStore("malformed object key".into()))?;
                    next_token = Some(String::from_utf8_lossy(key_bytes).into_owned());
                    break;
                }
                let (_b, key_bytes) = split_obj_key(&k)
                    .ok_or_else(|| FerroxError::MetaStore("malformed object key".into()))?;
                let key_s = String::from_utf8_lossy(key_bytes).into_owned();
                let rec: ObjectRecord = dec(&v)?;
                out.push((key_s, rec));
            }

            Ok(ListResult {
                objects: out,
                is_truncated,
                next_continuation_token: next_token,
            })
        })
        .await
        .map_err(|e| FerroxError::Internal(format!("join: {e}")))?
    }

    async fn create_multipart_upload(
        &self,
        upload_id: &str,
        meta: MultipartMeta,
    ) -> Result<(), FerroxError> {
        let me = self.clone();
        let uid = upload_id.to_string();
        tokio::task::spawn_blocking(move || -> Result<(), FerroxError> {
            let tree = me.multipart()?;
            tree.insert(uid.as_bytes(), enc(&meta)?).map_err(map_sled)?;
            tree.flush().map_err(map_sled)?;
            Ok(())
        })
        .await
        .map_err(|e| FerroxError::Internal(format!("join: {e}")))?
    }

    async fn get_multipart_upload(&self, upload_id: &str) -> Result<MultipartMeta, FerroxError> {
        let me = self.clone();
        let uid = upload_id.to_string();
        tokio::task::spawn_blocking(move || -> Result<MultipartMeta, FerroxError> {
            let tree = me.multipart()?;
            let v = tree.get(uid.as_bytes()).map_err(map_sled)?.ok_or_else(|| {
                FerroxError::NotFound {
                    bucket: String::new(),
                    key: Some(uid.clone()),
                }
            })?;
            dec(&v)
        })
        .await
        .map_err(|e| FerroxError::Internal(format!("join: {e}")))?
    }

    async fn delete_multipart_upload(&self, upload_id: &str) -> Result<(), FerroxError> {
        let me = self.clone();
        let uid = upload_id.to_string();
        tokio::task::spawn_blocking(move || -> Result<(), FerroxError> {
            let tree = me.multipart()?;
            tree.remove(uid.as_bytes()).map_err(map_sled)?;
            tree.flush().map_err(map_sled)?;
            Ok(())
        })
        .await
        .map_err(|e| FerroxError::Internal(format!("join: {e}")))?
    }

    async fn list_multipart_uploads(
        &self,
        bucket: &str,
    ) -> Result<Vec<(String, MultipartMeta)>, FerroxError> {
        let me = self.clone();
        let bucket = bucket.to_string();
        tokio::task::spawn_blocking(
            move || -> Result<Vec<(String, MultipartMeta)>, FerroxError> {
                let tree = me.multipart()?;
                let mut out = Vec::new();
                for kv in tree.iter() {
                    let (k, v) = kv.map_err(map_sled)?;
                    let uid = String::from_utf8_lossy(&k).into_owned();
                    let meta: MultipartMeta = dec(&v)?;
                    if meta.bucket == bucket {
                        out.push((uid, meta));
                    }
                }
                Ok(out)
            },
        )
        .await
        .map_err(|e| FerroxError::Internal(format!("join: {e}")))?
    }

    async fn set_bucket_versioning(
        &self,
        bucket: &str,
        versioning: VersioningState,
    ) -> Result<(), FerroxError> {
        self.mutate_bucket(bucket, move |m| m.versioning = versioning)
            .await
    }

    async fn set_bucket_tags(
        &self,
        bucket: &str,
        tags: std::collections::BTreeMap<String, String>,
    ) -> Result<(), FerroxError> {
        self.mutate_bucket(bucket, move |m| m.tags = tags).await
    }

    async fn set_bucket_cors(&self, bucket: &str, rules: Vec<CorsRule>) -> Result<(), FerroxError> {
        self.mutate_bucket(bucket, move |m| m.cors_rules = rules)
            .await
    }

    async fn set_bucket_encryption(
        &self,
        bucket: &str,
        cfg: Option<EncryptionConfig>,
    ) -> Result<(), FerroxError> {
        self.mutate_bucket(bucket, move |m| m.encryption = cfg)
            .await
    }

    async fn set_bucket_notifications(
        &self,
        bucket: &str,
        rules: Vec<NotificationRule>,
    ) -> Result<(), FerroxError> {
        self.mutate_bucket(bucket, move |m| m.notifications = rules)
            .await
    }
}

impl SledMeta {
    /// Read-modify-write a `BucketMeta`. Returns `NotFound` if the bucket
    /// is absent.
    async fn mutate_bucket<F>(&self, bucket: &str, f: F) -> Result<(), FerroxError>
    where
        F: FnOnce(&mut BucketMeta) + Send + 'static,
    {
        let me = self.clone();
        let bucket = bucket.to_string();
        tokio::task::spawn_blocking(move || -> Result<(), FerroxError> {
            let tree = me.buckets()?;
            let v = tree
                .get(bucket.as_bytes())
                .map_err(map_sled)?
                .ok_or_else(|| FerroxError::NotFound {
                    bucket: bucket.clone(),
                    key: None,
                })?;
            let mut meta: BucketMeta = dec(&v)?;
            f(&mut meta);
            tree.insert(bucket.as_bytes(), enc(&meta)?)
                .map_err(map_sled)?;
            tree.flush().map_err(map_sled)?;
            Ok(())
        })
        .await
        .map_err(|e| FerroxError::Internal(format!("join: {e}")))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(etag: &str) -> ObjectRecord {
        ObjectRecord {
            etag: etag.into(),
            size: 1,
            content_type: "text/plain".into(),
            last_modified: OffsetDateTime::now_utc(),
            sha256: "x".into(),
            crc32c: "y".into(),
            version_id: None,
            sse_algorithm: None,
            sse_key_encrypted: None,
            sse_c_key_hmac: None,
            tags: Default::default(),
        }
    }

    #[tokio::test]
    async fn test_create_bucket_and_get_returns_record() {
        let s = SledMeta::in_memory().unwrap();
        s.create_bucket("b", "owner").await.unwrap();
        let m = s.get_bucket("b").await.unwrap();
        assert_eq!(m.name, "b");
        assert_eq!(m.owner, "owner");
    }

    #[tokio::test]
    async fn test_create_bucket_twice_returns_already_exists() {
        let s = SledMeta::in_memory().unwrap();
        s.create_bucket("b", "owner").await.unwrap();
        let res = s.create_bucket("b", "owner").await;
        assert!(matches!(res, Err(FerroxError::BucketAlreadyExists(_))));
    }

    #[tokio::test]
    async fn test_get_missing_bucket_returns_not_found() {
        let s = SledMeta::in_memory().unwrap();
        let res = s.get_bucket("nope").await;
        assert!(matches!(res, Err(FerroxError::NotFound { key: None, .. })));
    }

    #[tokio::test]
    async fn test_list_buckets_filters_by_owner() {
        let s = SledMeta::in_memory().unwrap();
        s.create_bucket("a", "alice").await.unwrap();
        s.create_bucket("b", "bob").await.unwrap();
        let alices = s.list_buckets("alice").await.unwrap();
        assert_eq!(alices.len(), 1);
        assert_eq!(alices[0].name, "a");
    }

    #[tokio::test]
    async fn test_delete_bucket_removes_record() {
        let s = SledMeta::in_memory().unwrap();
        s.create_bucket("b", "owner").await.unwrap();
        s.delete_bucket("b").await.unwrap();
        assert!(matches!(
            s.get_bucket("b").await,
            Err(FerroxError::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn test_put_get_delete_object_meta() {
        let s = SledMeta::in_memory().unwrap();
        s.create_bucket("b", "owner").await.unwrap();
        s.put_object_meta("b", "k", rec("\"e\"")).await.unwrap();
        let r = s.get_object_meta("b", "k").await.unwrap();
        assert_eq!(r.etag, "\"e\"");
        s.delete_object_meta("b", "k").await.unwrap();
        let res = s.get_object_meta("b", "k").await;
        assert!(matches!(
            res,
            Err(FerroxError::NotFound { key: Some(_), .. })
        ));
    }

    #[tokio::test]
    async fn test_list_objects_returns_in_lex_order_with_prefix() {
        let s = SledMeta::in_memory().unwrap();
        s.create_bucket("b", "o").await.unwrap();
        for k in ["aaa", "abb", "abc", "zzz"] {
            s.put_object_meta("b", k, rec("\"e\"")).await.unwrap();
        }
        let r = s.list_objects("b", Some("ab"), 100, None).await.unwrap();
        let keys: Vec<_> = r.objects.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["abb", "abc"]);
        assert!(!r.is_truncated);
    }

    #[tokio::test]
    async fn test_list_objects_pagination_via_continuation_token() {
        let s = SledMeta::in_memory().unwrap();
        s.create_bucket("b", "o").await.unwrap();
        for k in ["k1", "k2", "k3", "k4", "k5"] {
            s.put_object_meta("b", k, rec("\"e\"")).await.unwrap();
        }
        let p1 = s.list_objects("b", None, 2, None).await.unwrap();
        assert_eq!(p1.objects.len(), 2);
        assert!(p1.is_truncated);
        let token = p1.next_continuation_token.clone().unwrap();
        let p2 = s.list_objects("b", None, 2, Some(&token)).await.unwrap();
        assert_eq!(p2.objects.len(), 2);
        // Confirm we don't repeat keys.
        let p1k: Vec<_> = p1.objects.iter().map(|(k, _)| k).collect();
        let p2k: Vec<_> = p2.objects.iter().map(|(k, _)| k).collect();
        for k in &p2k {
            assert!(!p1k.contains(k));
        }
    }

    #[tokio::test]
    async fn test_list_objects_does_not_bleed_across_buckets() {
        let s = SledMeta::in_memory().unwrap();
        s.create_bucket("a", "o").await.unwrap();
        s.create_bucket("b", "o").await.unwrap();
        s.put_object_meta("a", "shared", rec("\"e\""))
            .await
            .unwrap();
        s.put_object_meta("b", "other", rec("\"e\"")).await.unwrap();
        let r = s.list_objects("a", None, 100, None).await.unwrap();
        let keys: Vec<_> = r.objects.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["shared"]);
    }
}
