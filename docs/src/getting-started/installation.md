# Installation

## From source

```sh
git clone https://github.com/ferrox-rs/ferrox.git
cd ferrox
cargo build --release
./target/release/ferroxd --help
```

Requires Rust 1.75+.

## Docker

```sh
docker pull ghcr.io/ferrox-rs/ferrox:latest
docker run --rm -p 9000:9000 -v ferrox-data:/data ghcr.io/ferrox-rs/ferrox:latest \
  --data-dir /data --bind 0.0.0.0:9000
```

## Pre-built binaries

Download from the [Releases page](https://github.com/ferrox-rs/ferrox/releases). Binaries are statically linked against musl on Linux and signed.

| Platform | Target |
|---|---|
| Linux x86_64 | `ferroxd-x86_64-unknown-linux-musl` |
| Linux aarch64 | `ferroxd-aarch64-unknown-linux-musl` |
| macOS x86_64 | `ferroxd-x86_64-apple-darwin` |
| macOS aarch64 | `ferroxd-aarch64-apple-darwin` |

## Helm

```sh
helm install ferrox ./helm/ferrox \
  --set credentials.accessKey=mykey \
  --set credentials.secretKey=mysecret
```

See **[Kubernetes / Helm](../operations/kubernetes.md)** for the full chart reference.
