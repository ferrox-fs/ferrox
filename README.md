# Ferrox

[![ci](https://github.com/ferrox-rs/ferrox/actions/workflows/ci.yml/badge.svg)](https://github.com/ferrox-rs/ferrox/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/ferrox-rs/ferrox?include_prereleases&sort=semver)](https://github.com/ferrox-rs/ferrox/releases)
[![docker](https://img.shields.io/docker/pulls/ghcr.io%2Fferrox-rs%2Fferrox)](https://github.com/ferrox-rs/ferrox/pkgs/container/ferrox)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![rust](https://img.shields.io/badge/rust-stable-orange)](https://www.rust-lang.org/)
[![docs](https://img.shields.io/badge/docs-mdbook-success)](https://ferrox-rs.github.io/ferrox/)

> **AWS S3-compatible object storage in Rust.** Single binary, < 20 MB Docker image, no runtime dependencies.

`ferroxd` ships everything in one process — gateway, metadata store, disk backend, TLS, Prometheus metrics, mTLS admin plane — and speaks the S3 wire protocol well enough that the AWS CLI, Boto3, rclone, the JS / Go SDKs, and pre-signed URLs all work without provider-specific tweaks.

```sh
docker run --rm -p 9000:9000 -v ferrox-data:/data \
  ghcr.io/ferrox-rs/ferrox:latest \
  --data-dir /data --bind 0.0.0.0:9000

# Anywhere AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY are wired:
aws --endpoint-url http://localhost:9000 s3 mb s3://photos
echo "hello, ferrox" | aws --endpoint-url http://localhost:9000 s3 cp - s3://photos/hello.txt
```

5-minute end-to-end walkthrough: **[docs/getting-started/quickstart.md](docs/src/getting-started/quickstart.md)**.

---

## Why Ferrox?

| | Ferrox | MinIO | seaweedfs |
|---|---|---|---|
| Language | Rust | Go | Go |
| Static binary | yes (~12 MB) | yes (~80 MB) | yes |
| Docker `FROM scratch` | yes | no | no |
| TLS backend | rustls + ring (no OpenSSL) | TLS via Go std | OpenSSL |
| SigV4 + SigV4A | yes | yes | partial |
| `unsafe` in production paths | none (`#![forbid(unsafe_code)]`) | n/a | n/a |
| AGPL or vendor lock-in | no, **Apache-2.0** | AGPL | Apache-2.0 |

Goals (in order):

1. **Drop-in compatibility.** If a real AWS SDK breaks against Ferrox, that's a release-blocking bug.
2. **Strong defaults.** SigV4 every request, AES-256-GCM SSE, rustls-only TLS, constant-time compare.
3. **One binary, zero ceremony.** No JVM, no C++ toolchain (default), no init containers, no external metadata DB.
4. **Open governance.** Apache-2.0, public roadmap, every decision in an ADR.

---

## Feature matrix

### Core S3 (Phase 0+1, complete)

| Surface | Notes |
|---|---|
| ListBuckets / CreateBucket / HeadBucket / DeleteBucket | DNS-compatible name validation |
| PutObject / GetObject (Range) / HeadObject / DeleteObject | Atomic writes, SHA-256 sidecar integrity |
| CopyObject (server-side, including SSE propagation) | via `x-amz-copy-source` |
| DeleteObjects (batch, ≤ 1000 keys) | `<DeleteResult>` XML |
| Multipart Upload (Initiate, UploadPart, Complete, Abort, ListParts, ListMultipartUploads) | Background janitor evicts orphans after 24h |
| Bucket versioning | `?versioning` PUT/GET |
| Pre-signed URLs (PUT + GET) | `UNSIGNED-PAYLOAD` honoured; `%2F → %252F` collisions handled |
| SSE-S3 (AES-256-GCM, KEK + per-object DEK) | configured via `--sse-master-key` |
| TLS 1.3 / TLS 1.2 (rustls) | dual HTTP+HTTPS listeners, ALPN h2 + http/1.1 |
| Docker (`FROM scratch`, musl) | < 20 MB image |
| Boto3 + rclone integration test suites | 13 + 10 cases, all passing |

### Production hardening (Phase 2, complete)

| Surface | Notes |
|---|---|
| Object & bucket Tagging (`?tagging`) | 10 / 128 / 256 limits |
| CORS configuration (`?cors`) + live `OPTIONS` preflight | per-origin matching |
| SSE-C (caller-supplied key) | raw key never logged or stored; HMAC-SHA256 fingerprint persisted |
| Default bucket encryption policy (`?encryption`) | enforced PutObject rejects unencrypted PUTs |
| Prometheus `/metrics` | requests, latency histogram, bytes-in/out, gauges |
| Health endpoints | `/health/live`, `/health/ready` (concurrent meta + disk probes), `/health/version` |
| Per-access-key rate limiting | governor token-bucket, `503 SlowDown` |
| Helm chart | PVC, security context, Prometheus annotations, ingress + TLS |
| cargo-fuzz suite | 3 targets (SigV4 parser, XML, key validator) |
| mdBook docs site (auto-deployed to GitHub Pages) | quickstart, API ref, ADRs |
| Criterion microbenches + wrk macro-bench | regression check in CI |

### Launch / 1.0 (Phase 3, complete)

| Surface | Notes |
|---|---|
| SigV4A (multi-region ECDSA-P256) | parsing + verification scaffold |
| RocksDB metadata backend | opt-in via `--features rocksdb` |
| mTLS admin API (port 9444) | access-key CRUD, rate-limit overrides, stats |
| Bucket notifications | webhook + SNS-style delivery (`tokio::spawn`, non-blocking) |
| Terraform modules (AWS, Helm) | with single-node example |
| GitHub Actions release pipeline | musl + darwin binaries, multi-arch GHCR image, signed checksums |
| Erasure-coding backend interface | feature-gated stub; v2 ships RS(4+2) |

### Roadmap (post-1.0)

- Distributed mode with Reed-Solomon erasure coding (ADR-003).
- Lifecycle policies (`?lifecycle`).
- Bucket policies + multi-tenant IAM (replacing the v1 single-key identity).
- Streaming SigV4 (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`).
- WORM / Object Lock (`?object-lock`).
- S3 Select / parquet pushdown.

Every roadmap item lives as a tracking issue with a `roadmap` label.

---

## Project layout

```
ferrox/
├─ crates/
│  ├─ ferrox-error/       — thiserror error types + AWS error code mapping
│  ├─ ferrox-crypto/      — SSE-S3 (KEK/DEK), SSE-C (zeroizing CustomerKey)
│  ├─ ferrox-iam/         — identity placeholder (IAM lands post-1.0)
│  ├─ ferrox-meta/        — MetaStore trait + SledMeta + (optional) RocksMeta
│  ├─ ferrox-storage/     — StorageBackend trait + DiskBackend + (stub) ErasureBackend
│  ├─ ferrox-s3-api/      — S3 XML serializers + parsers, name validators
│  ├─ ferrox-gateway/     — axum router, SigV4, all handlers, metrics, ratelimit, admin, notify
│  └─ ferrox-cli/         — ferroxd binary entrypoint
├─ helm/ferrox/           — Helm chart
├─ terraform/             — modules/ferrox-aws, modules/ferrox-k8s, examples
├─ docs/                  — mdBook source (deployed to GitHub Pages)
├─ docs/adr/              — Architecture Decision Records
├─ fuzz/                  — cargo-fuzz targets
├─ scripts/bench/         — wrk macro benchmarks
└─ tests/integration/     — Boto3 + rclone interop suites
```

---

## Running locally

```sh
git clone https://github.com/ferrox-rs/ferrox.git
cd ferrox
cargo run --bin ferroxd -- \
  --data-dir ./data \
  --bind 0.0.0.0:9000 \
  --access-key minioadmin \
  --secret-key minioadmin

# In another terminal
curl http://localhost:9000/health/live
# {"status":"ok"}
```

Full configuration: **[docs/getting-started/configuration.md](docs/src/getting-started/configuration.md)**.

---

## Contributing

PRs welcome — see **[CONTRIBUTING.md](CONTRIBUTING.md)** for the full guide. TL;DR:

1. Pick or open an issue. Issues tagged `good first issue` are bounded and have a clear acceptance criterion.
2. Branch off `main`. Keep PRs focused — one bug fix or one feature each.
3. Run `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` before pushing.
4. AWS-compat changes must be verified against real AWS S3 behaviour (Boto3 / AWS CLI). The PR template asks for the verification command.
5. Update `CHANGELOG.md` under `## [Unreleased]`.

Discussions, design questions, and weekly sync notes live in [GitHub Discussions](https://github.com/ferrox-rs/ferrox/discussions). Real-time chat: **#ferrox** on the Rust Discord.

---

## Security

Found a vulnerability? Please use **GitHub Security Advisories** (`Security` tab) — full policy in **[SECURITY.md](SECURITY.md)**.

Hardening notes:

- `#![forbid(unsafe_code)]` in every crate.
- SigV4 verification uses constant-time HMAC compare.
- TLS is rustls + ring only — no OpenSSL.
- SSE-C raw keys never persist or appear in logs.
- All key material wiped on drop via `zeroize`.
- `cargo audit` runs in CI on every PR.

---

## License

Ferrox is licensed under the **Apache License, Version 2.0**. See [LICENSE](LICENSE).

By contributing, you agree that your contributions will be licensed under the same terms.
