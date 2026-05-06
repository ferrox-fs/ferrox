//! Microbenchmark: SigV4 verification on a pre-built canonical request.

use criterion::{criterion_group, criterion_main, Criterion};
use ferrox_gateway::auth::SigV4Header;

const SAMPLE_AUTH: &str = "AWS4-HMAC-SHA256 \
    Credential=MOCKACCESSKEYFORTEST/20260505/us-east-1/s3/aws4_request, \
    SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
    Signature=4e8e2c7d1bd0c0c0aa6c1bf0a0c0c0c0aa6c1bf0a0c0c0c0aa6c1bf0a0c0c0c0";

fn bench_parse(c: &mut Criterion) {
    c.bench_function("sigv4_header_parse", |b| {
        b.iter(|| {
            let _ = SigV4Header::from_authorization_header(SAMPLE_AUTH).unwrap();
        });
    });
}

criterion_group!(benches, bench_parse);
criterion_main!(benches);
