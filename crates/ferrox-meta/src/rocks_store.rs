//! RocksDB-backed [`MetaStore`] implementation (Phase 3 Step 37).
//!
//! Built only when the `rocksdb` cargo feature is enabled. Behaves identically
//! to [`SledMeta`](crate::sled_store::SledMeta) — the only difference is the
//! underlying engine (RocksDB column families vs sled trees).

use async_trait::async_trait;
use ferrox_error::FerroxError;
use rocksdb::{ColumnFamilyDescriptor, Options, DB};
use std::sync::Arc;
use time::OffsetDateTime;

use crate::types::{
    BucketMeta, CorsRule, EncryptionConfig, ListResult, MultipartMeta, NotificationRule,
    ObjectRecord, VersioningState,
};
use crate::MetaStore;

const CF_BUCKETS: &str = "buckets";
const CF_OBJECTS: &str = "objects";
const CF_MULTIPART: &str = "multipart_uploads";
const SEP: u8 = 0;

/// RocksDB-backed metadata store.
#[derive(Clone)]
pub struct RocksMeta {
    db: Arc<DB>,
}

impl RocksMeta {
    /// Open (or create) a RocksDB database rooted at `path`.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, FerroxError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_BUCKETS, Options::default()),
            ColumnFamilyDescriptor::new(CF_OBJECTS, Options::default()),
            ColumnFamilyDescriptor::new(CF_MULTIPART, Options::default()),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cfs).map_err(map_rocks)?;
        Ok(Self { db: Arc::new(db) })
    }
}

fn map_rocks(e: rocksdb::Error) -> FerroxError {
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

#[async_trait]
impl MetaStore for RocksMeta {
    async fn create_bucket(&self, name: &str, owner: &str) -> Result<(), FerroxError> {
        let me = self.clone();
        let name = name.to_string();
        let owner = owner.to_string();
        tokio::task::spawn_blocking(move || -> Result<(), FerroxError> {
            let cf = me.db.cf_handle(CF_BUCKETS).expect("buckets CF");
            if me
                .db
                .get_cf(cf, name.as_bytes())
                .map_err(map_rocks)?
                .is_some()
            {
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
            me.db
                .put_cf(cf, name.as_bytes(), enc(&meta)?)
                .map_err(map_rocks)
        })
        .await
        .map_err(|e| FerroxError::Internal(format!("join: {e}")))?
    }

    async fn get_bucket(&self, name: &str) -> Result<BucketMeta, FerroxError> {
        let me = self.clone();
        let name = name.to_string();
        tokio::task::spawn_blocking(move || -> Result<BucketMeta, FerroxError> {
            let cf = me.db.cf_handle(CF_BUCKETS).expect("buckets CF");
            let v = me
                .db
                .get_cf(cf, name.as_bytes())
                .map_err(map_rocks)?
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
            let cf = me.db.cf_handle(CF_BUCKETS).expect("buckets CF");
            let mut out = Vec::new();
            for kv in me.db.iterator_cf(cf, rocksdb::IteratorMode::Start) {
                let (_, v) = kv.map_err(map_rocks)?;
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
            let cf = me.db.cf_handle(CF_BUCKETS).expect("buckets CF");
            if me
                .db
                .get_cf(cf, name.as_bytes())
                .map_err(map_rocks)?
                .is_none()
            {
                return Err(FerroxError::NotFound {
                    bucket: name,
                    key: None,
                });
            }
            me.db.delete_cf(cf, name.as_bytes()).map_err(map_rocks)
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
            let cf = me.db.cf_handle(CF_OBJECTS).expect("objects CF");
            me.db.put_cf(cf, k, enc(&meta)?).map_err(map_rocks)
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
            let cf = me.db.cf_handle(CF_OBJECTS).expect("objects CF");
            let v = me
                .db
                .get_cf(cf, &k)
                .map_err(map_rocks)?
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
            let cf = me.db.cf_handle(CF_OBJECTS).expect("objects CF");
            me.db.delete_cf(cf, k).map_err(map_rocks)
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
            let cf = me.db.cf_handle(CF_OBJECTS).expect("objects CF");
            let mut scan_prefix = bucket.as_bytes().to_vec();
            scan_prefix.push(SEP);
            if let Some(p) = &prefix {
                scan_prefix.extend_from_slice(p.as_bytes());
            }
            let start = match &continuation {
                Some(c) => obj_key(&bucket, c),
                None => scan_prefix.clone(),
            };

            let mut out = Vec::new();
            let mut is_truncated = false;
            let mut next_token = None;
            let max = max_keys.max(1) as usize;

            let it = me.db.iterator_cf(
                cf,
                rocksdb::IteratorMode::From(&start, rocksdb::Direction::Forward),
            );
            for kv in it {
                let (k, v) = kv.map_err(map_rocks)?;
                if !k.starts_with(&scan_prefix) {
                    break;
                }
                if out.len() >= max {
                    is_truncated = true;
                    let key_bytes =
                        &k[scan_prefix.len() - prefix.as_ref().map_or(0, String::len)..];
                    let _ = key_bytes;
                    let s = std::str::from_utf8(&k[bucket.len() + 1..])
                        .unwrap_or("")
                        .to_string();
                    next_token = Some(s);
                    break;
                }
                let s = std::str::from_utf8(&k[bucket.len() + 1..])
                    .map(str::to_string)
                    .unwrap_or_default();
                let rec: ObjectRecord = dec(&v)?;
                out.push((s, rec));
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
            let cf = me.db.cf_handle(CF_MULTIPART).expect("multipart CF");
            me.db
                .put_cf(cf, uid.as_bytes(), enc(&meta)?)
                .map_err(map_rocks)
        })
        .await
        .map_err(|e| FerroxError::Internal(format!("join: {e}")))?
    }

    async fn get_multipart_upload(&self, upload_id: &str) -> Result<MultipartMeta, FerroxError> {
        let me = self.clone();
        let uid = upload_id.to_string();
        tokio::task::spawn_blocking(move || -> Result<MultipartMeta, FerroxError> {
            let cf = me.db.cf_handle(CF_MULTIPART).expect("multipart CF");
            let v = me
                .db
                .get_cf(cf, uid.as_bytes())
                .map_err(map_rocks)?
                .ok_or_else(|| FerroxError::NotFound {
                    bucket: String::new(),
                    key: Some(uid),
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
            let cf = me.db.cf_handle(CF_MULTIPART).expect("multipart CF");
            me.db.delete_cf(cf, uid.as_bytes()).map_err(map_rocks)
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
                let cf = me.db.cf_handle(CF_MULTIPART).expect("multipart CF");
                let mut out = Vec::new();
                for kv in me.db.iterator_cf(cf, rocksdb::IteratorMode::Start) {
                    let (k, v) = kv.map_err(map_rocks)?;
                    let uid = String::from_utf8_lossy(&k).into_owned();
                    let m: MultipartMeta = dec(&v)?;
                    if m.bucket == bucket {
                        out.push((uid, m));
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
        state: VersioningState,
    ) -> Result<(), FerroxError> {
        self.mutate_bucket(bucket, move |m| m.versioning = state)
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

impl RocksMeta {
    async fn mutate_bucket<F>(&self, bucket: &str, f: F) -> Result<(), FerroxError>
    where
        F: FnOnce(&mut BucketMeta) + Send + 'static,
    {
        let me = self.clone();
        let bucket = bucket.to_string();
        tokio::task::spawn_blocking(move || -> Result<(), FerroxError> {
            let cf = me.db.cf_handle(CF_BUCKETS).expect("buckets CF");
            let v = me
                .db
                .get_cf(cf, bucket.as_bytes())
                .map_err(map_rocks)?
                .ok_or_else(|| FerroxError::NotFound {
                    bucket: bucket.clone(),
                    key: None,
                })?;
            let mut meta: BucketMeta = dec(&v)?;
            f(&mut meta);
            me.db
                .put_cf(cf, bucket.as_bytes(), enc(&meta)?)
                .map_err(map_rocks)
        })
        .await
        .map_err(|e| FerroxError::Internal(format!("join: {e}")))?
    }
}
