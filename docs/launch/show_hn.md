# Show HN: Ferrox — AWS S3-compatible object storage in Rust (single binary, < 20 MB Docker image)

I've been building **Ferrox**, an AWS S3-compatible object storage server in Rust. One static binary (~12 MB), `FROM scratch` Docker image, no runtime dependencies, no JVM, no C++ build toolchain.

**Why another S3 server?** I wanted something I could:
- Run on a t3.medium without burning RAM on the JVM.
- Drop into existing AWS CLI / Boto3 / rclone workflows without flag changes.
- Trust at the auth layer — every request goes through a constant-time HMAC compare, every encryption path is rustls + ring, no OpenSSL.

**What's in v1**

- Full SigV4 + SigV4A (multi-region ECDSA-P256).
- PutObject / GetObject (with Range), HeadObject, CopyObject, DeleteObjects (batch), Multipart, Versioning, Pre-signed URLs.
- Object & bucket Tagging, CORS, default encryption policy.
- SSE-S3 (server-managed key) and SSE-C (caller-managed key, never logged or persisted — only HMAC fingerprint stored).
- Prometheus `/metrics`, `/health/live` & `/health/ready`, per-access-key rate limiting.
- Helm chart + Terraform modules + GitHub Pages docs.
- AWS CLI, Boto3, rclone, JS SDK v3, Go SDK v2 all work without `--no-verify-ssl` or any provider tweak.

**Benchmarks (vs MinIO, same EBS gp3 / t3.medium)**

| Op | Ferrox p99 | MinIO p99 |
|---|---:|---:|
| ListObjectsV2 (1K keys) | TBD | TBD |
| PutObject 4 KB | TBD | TBD |
| GetObject 4 KB | TBD | TBD |
| CopyObject 4 KB (server-side) | TBD | TBD |

(Numbers being collected on the 1.0 release hardware — replace before posting.)

**5-minute quickstart**: <https://ferrox-rs.github.io/ferrox/getting-started/quickstart.html>

**Repo**: <https://github.com/ferrox-rs/ferrox>

Apache-2.0. PRs welcome — `good first issue` labels are populated. The roadmap (distributed mode, erasure coding, lifecycle policies) is in the README.
