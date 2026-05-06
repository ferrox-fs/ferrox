# Ferrox

AWS S3-compatible object storage in Rust. Single binary, < 20 MB Docker image, no runtime dependencies.

## What it is

- **Drop-in S3 endpoint**: AWS CLI, Boto3, rclone, and the JS / Go SDKs all work without modification.
- **One binary**: `ferroxd` ships everything — gateway, sled metadata store, disk backend, TLS termination, Prometheus metrics.
- **Strong defaults**: SigV4 auth on every request, AES-256-GCM SSE-S3 / SSE-C, rustls-only TLS (no OpenSSL), constant-time signature compare.

## Where to next

- New here? Read **[Quickstart](getting-started/quickstart.md)** — zero to PutObject in 5 minutes.
- Deploying? Jump to **[Docker](operations/docker.md)** or **[Kubernetes](operations/kubernetes.md)**.
- Wiring observability? See **[Observability](operations/observability.md)**.
- Curious how it works? Read the **[Architecture Decision Records](architecture/adr.md)**.

## Compatibility

| Surface | Status |
|---|---|
| AWS CLI / Boto3 / rclone / aws-sdk-go-v2 / aws-sdk-js-v3 | works |
| SigV4 + SigV4A (cross-region) | works |
| Versioning / Multipart / CopyObject / Tagging / CORS | works |
| SSE-S3 (server-managed key) / SSE-C (caller-supplied key) | works |
| Bucket notifications (webhook + SNS POST) | works |
| Per-access-key rate limiting | works |

See **[API Reference](api/buckets.md)** for the complete endpoint catalogue.
