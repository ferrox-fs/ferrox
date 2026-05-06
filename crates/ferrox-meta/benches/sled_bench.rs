//! Microbenchmarks for the sled metadata store.

use criterion::{criterion_group, criterion_main, Criterion};
use ferrox_meta::{MetaStore, ObjectRecord, SledMeta};
use time::OffsetDateTime;

fn rec(i: usize) -> ObjectRecord {
    ObjectRecord {
        etag: format!("\"{:08x}\"", i),
        size: 1024,
        content_type: "application/octet-stream".into(),
        last_modified: OffsetDateTime::now_utc(),
        sha256: "00".repeat(32),
        crc32c: "deadbeef".into(),
        version_id: None,
        sse_algorithm: None,
        sse_key_encrypted: None,
        sse_c_key_hmac: None,
        tags: Default::default(),
    }
}

fn bench_put_object_meta(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let store = SledMeta::in_memory().unwrap();
    rt.block_on(store.create_bucket("b", "o")).unwrap();

    let mut i = 0usize;
    c.bench_function("put_object_meta", |b| {
        b.iter(|| {
            i += 1;
            rt.block_on(store.put_object_meta("b", &format!("k{}", i), rec(i)))
                .unwrap();
        });
    });
}

fn bench_get_object_meta(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let store = SledMeta::in_memory().unwrap();
    rt.block_on(store.create_bucket("b", "o")).unwrap();
    for i in 0..10_000 {
        rt.block_on(store.put_object_meta("b", &format!("k{}", i), rec(i)))
            .unwrap();
    }
    let mut i = 0usize;
    c.bench_function("get_object_meta", |b| {
        b.iter(|| {
            i = (i + 1) % 10_000;
            rt.block_on(store.get_object_meta("b", &format!("k{}", i)))
                .unwrap();
        });
    });
}

criterion_group!(benches, bench_put_object_meta, bench_get_object_meta);
criterion_main!(benches);
