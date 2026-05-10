<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/ferrox-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/ferrox-light.svg">
  <img alt="Ferrox" src="docs/ferrox-dark.svg" height="72">
</picture>

[![ci](https://github.com/ferrox-rs/ferrox/actions/workflows/ci.yml/badge.svg)](https://github.com/ferrox-rs/ferrox/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/ferrox-rs/ferrox?include_prereleases&sort=semver)](https://github.com/ferrox-rs/ferrox/releases)
[![docker](https://img.shields.io/docker/pulls/ghcr.io%2Fferrox-rs%2Fferrox)](https://github.com/ferrox-rs/ferrox/pkgs/container/ferrox)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Lightweight S3-compatible object storage server built in Rust.

- Single binary
- Tiny Docker image (< 20 MB)
- AWS SDK compatible
- Easy self-hosting
- No external dependencies

**Get started in under 2 minutes.**

---

## Quickstart

```sh
docker run --rm -p 9000:9000 -v ferrox-data:/data \
  ghcr.io/ferrox-rs/ferrox:latest \
  --data-dir /data --bind 0.0.0.0:9000 \
  --access-key minioadmin --secret-key minioadmin
```

That's it. Ferrox is running.

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│                    ferroxd                        │
│                                                   │
│  ┌─────────────┐   ┌──────────────────────────┐  │
│  │  axum HTTP  │──▶│   SigV4 Auth Middleware  │  │
│  │  gateway    │   └──────────────────────────┘  │
│  └──────┬──────┘              │                   │
│         │              ┌──────▼──────┐            │
│         │              │  S3 Router  │            │
│         │              └──────┬──────┘            │
│         │         ┌───────────┼───────────┐       │
│         │         ▼           ▼           ▼       │
│  ┌──────▼─────┐ ┌──────┐ ┌───────┐ ┌──────────┐  │
│  │  ferrox-   │ │ meta │ │crypto │ │  notify  │  │
│  │  storage   │ │ sled │ │AES-GCM│ │ webhooks │  │
│  │  (disk)    │ │      │ │       │ │          │  │
│  └────────────┘ └──────┘ └───────┘ └──────────┘  │
└──────────────────────────────────────────────────┘
```

Everything runs in a single process. No sidecars, no external metadata DB, no init containers.

---

## Example Usage

Works with any AWS SDK, CLI, or tool — no provider-specific config needed.

**AWS CLI**

```sh
export AWS_ACCESS_KEY_ID=minioadmin
export AWS_SECRET_ACCESS_KEY=minioadmin
export AWS_DEFAULT_REGION=us-east-1

aws --endpoint-url http://localhost:9000 s3 mb s3://my-bucket
aws --endpoint-url http://localhost:9000 s3 cp ./file.txt s3://my-bucket/
aws --endpoint-url http://localhost:9000 s3 ls s3://my-bucket
```

**Python (Boto3)**

```python
import boto3

s3 = boto3.client(
    "s3",
    endpoint_url="http://localhost:9000",
    aws_access_key_id="minioadmin",
    aws_secret_access_key="minioadmin",
    region_name="us-east-1",
)

s3.create_bucket(Bucket="my-bucket")
s3.put_object(Bucket="my-bucket", Key="hello.txt", Body=b"hello, ferrox")
```

**JavaScript (AWS SDK v3)**

```js
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";

const s3 = new S3Client({
  endpoint: "http://localhost:9000",
  region: "us-east-1",
  credentials: { accessKeyId: "minioadmin", secretAccessKey: "minioadmin" },
  forcePathStyle: true,
});

await s3.send(
  new PutObjectCommand({
    Bucket: "my-bucket",
    Key: "hello.txt",
    Body: "hello",
  }),
);
```

**Build from source**

```sh
git clone https://github.com/ferrox-rs/ferrox.git
cd ferrox
cargo run --bin ferroxd -- \
  --data-dir ./data \
  --bind 0.0.0.0:9000 \
  --access-key minioadmin \
  --secret-key minioadmin
```

Full configuration reference: [docs/getting-started/configuration.md](docs/src/getting-started/configuration.md)

---

## Compatibility

Ferrox speaks the S3 wire protocol. These clients work without modification.

| Client                    | Status                          |
| ------------------------- | ------------------------------- |
| AWS CLI v2                | Verified                        |
| Boto3                     | Verified (13 integration tests) |
| rclone                    | Verified (10 integration tests) |
| AWS SDK for JavaScript v3 | Verified                        |
| AWS SDK for Go v2         | Verified                        |
| Pre-signed URLs           | Verified                        |

### Supported S3 Operations

| Operation                                              | Notes                                           |
| ------------------------------------------------------ | ----------------------------------------------- |
| ListBuckets / CreateBucket / HeadBucket / DeleteBucket | DNS-compatible name validation                  |
| PutObject / GetObject / HeadObject / DeleteObject      | Range requests, SHA-256 integrity               |
| CopyObject                                             | Server-side, SSE propagation                    |
| DeleteObjects                                          | Batch up to 1000 keys                           |
| Multipart Upload                                       | Initiate / UploadPart / Complete / Abort / List |
| Bucket Versioning                                      | `?versioning`                                   |
| Pre-signed URLs                                        | PUT + GET, `UNSIGNED-PAYLOAD`                   |
| Object & Bucket Tagging                                | `?tagging`                                      |
| CORS                                                   | `?cors`, live `OPTIONS` preflight               |
| SSE-S3                                                 | AES-256-GCM, per-object DEK                     |
| SSE-C                                                  | Caller-supplied key, never stored               |
| Default Encryption Policy                              | `?encryption`                                   |
| SigV4                                                  | All requests                                    |
| SigV4A                                                 | Parsing + verification scaffold                 |

---

## Why Ferrox?

Most self-hosted S3-compatible stores are either heavy (JVM, CGo, OpenSSL) or incomplete (missing SigV4, broken multipart, wrong error XML).

Ferrox is built around three rules:

1. **Drop-in compatibility.** If the AWS CLI breaks against Ferrox, that's a bug.
2. **Strong defaults.** SigV4 on every request. AES-256-GCM encryption. rustls-only TLS. Constant-time signature comparison.
3. **Single binary.** No runtime dependencies. No C toolchain required. `FROM scratch` Docker image.

**vs. the alternatives**

|                       | Ferrox                           | MinIO     | SeaweedFS  |
| --------------------- | -------------------------------- | --------- | ---------- |
| Language              | Rust                             | Go        | Go         |
| Binary size           | ~12 MB                           | ~80 MB    | varies     |
| `FROM scratch` Docker | yes                              | no        | no         |
| TLS                   | rustls + ring                    | Go stdlib | OpenSSL    |
| `unsafe` in hot paths | none (`#![forbid(unsafe_code)]`) | n/a       | n/a        |
| License               | Apache-2.0                       | AGPL      | Apache-2.0 |

---

## Benchmarks

Benchmark results coming soon. Criterion micro-benchmarks and wrk macro-benchmarks run in CI — see [scripts/bench/](scripts/bench/).

---

## Project Layout

```
ferrox/
├─ crates/
│  ├─ ferrox-error/       — thiserror error types + AWS error code mapping
│  ├─ ferrox-crypto/      — SSE-S3 (KEK/DEK), SSE-C (zeroizing CustomerKey)
│  ├─ ferrox-iam/         — identity placeholder (IAM lands post-1.0)
│  ├─ ferrox-meta/        — MetaStore trait + SledMeta + (optional) RocksMeta
│  ├─ ferrox-storage/     — StorageBackend trait + DiskBackend
│  ├─ ferrox-s3-api/      — S3 XML serializers + parsers, name validators
│  ├─ ferrox-gateway/     — axum router, SigV4, all handlers, metrics, rate limiting
│  └─ ferrox-cli/         — ferroxd binary entrypoint
├─ helm/ferrox/           — Helm chart
├─ terraform/             — AWS + Kubernetes modules
├─ docs/                  — mdBook docs (deployed to GitHub Pages)
├─ fuzz/                  — cargo-fuzz targets (SigV4 parser, XML, key validator)
└─ tests/integration/     — Boto3 + rclone interop suites
```

---

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

```sh
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

AWS-compat changes must include verification against real S3 behavior. The PR template asks for the command.

Discussions: [GitHub Discussions](https://github.com/ferrox-rs/ferrox/discussions)  
Chat: **#ferrox** on the Rust Discord

---

## Security

Report vulnerabilities via **GitHub Security Advisories** (`Security` tab). Full policy: [SECURITY.md](SECURITY.md).

- `#![forbid(unsafe_code)]` in every crate
- SigV4 uses constant-time HMAC comparison
- TLS is rustls + ring only — no OpenSSL
- SSE-C keys never persist or appear in logs
- Key material wiped on drop via `zeroize`
- `cargo audit` runs on every PR

---

## License

Apache License, Version 2.0. See [LICENSE](LICENSE).
