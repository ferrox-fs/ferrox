# Changelog

All notable changes to Ferrox are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Object & bucket tagging** — `?tagging` endpoints with AWS-compatible XML and 10-tag / 128-key / 256-value validation.
- **CORS configuration** — `?cors` PUT/GET, plus live `OPTIONS` preflight handler that emits `Access-Control-*` headers when a rule matches.
- **SSE-C (caller-supplied keys)** — `x-amz-server-side-encryption-customer-*` headers for PutObject / GetObject / HeadObject. Raw keys are never logged or persisted; only an HMAC-SHA256 fingerprint is stored.
- **Default bucket encryption policy** — `?encryption` endpoints; when enforced, PutObject without an SSE header returns `400 InvalidEncryptionAlgorithmError`.
- **Prometheus metrics** — `/metrics` endpoint (no auth) exporting requests, latency histogram, bytes-in/out, object counts, active connections, and pending multipart counter.
- **Health endpoints** — `/health/live`, `/health/ready` (concurrent metadata + disk probes), `/health/version` with build commit + timestamp.
- **Per-access-key rate limiting** — token-bucket via `governor`; `503 SlowDown` with `Retry-After` on overrun.
- **Bucket notifications** — `?notification` config (webhook + SNS-style POST); dispatched non-blocking via `tokio::spawn`.
- **SigV4A** — multi-region ECDSA-P256 signature parsing + verification scaffold.
- **RocksDB backend** — opt-in via `--features rocksdb`; identical `MetaStore` semantics to sled.
- **Admin API** — separate-port mTLS-protected admin plane (`/admin/access-keys`, `/admin/rate-limits`, `/admin/stats`).
- **Helm chart** — `helm/ferrox/` with deployment, PVC, secret, service, ingress; Prometheus scrape annotations.
- **Terraform modules** — `terraform/modules/ferrox-aws/` (single-node EC2) and `terraform/modules/ferrox-k8s/` (Helm wrapper).
- **mdBook docs site** — `docs/` with quickstart, configuration, API reference, security, operations, ADRs.
- **cargo-fuzz suite** — three targets covering SigV4 parser, XML request bodies, object key validator.
- **Criterion microbenches** — sled put/get and SigV4 header parse.
- **Erasure-coding interface stub** — `ErasureBackend` skeleton + ADR-003 (Reed-Solomon, 4+2 default).
- **Community health** — issue templates, PR template, CODEOWNERS, SECURITY.md, weekly health workflow.

### Changed

- `BucketMeta` and `ObjectRecord` extended with `tags`, `cors_rules`, `encryption`, `notifications`, `sse_c_key_hmac` fields. Existing records remain readable thanks to `#[serde(default)]`.

## [0.1.0] — Initial Phase 0+1

Initial Phase 0 (foundation) and Phase 1 (core S3) features. See `README.md` and `phase1.md` for the full inventory.
