# ADR 002 — rustls + ring exclusively (no OpenSSL)

- Status: Accepted
- Date: 2026-05-05

## Context

The TLS layer needs to:

1. Build cleanly in `FROM scratch` Docker images (no shared libs).
2. Cross-compile to `aarch64-unknown-linux-musl` and `x86_64-apple-darwin` without surprises.
3. Stay aligned with the same crypto backend SigV4 already uses (`ring`).

OpenSSL drags in a C build dependency, vendor / linker headaches, and a divergent crypto backend.

## Decision

Use **rustls** with the **ring** crypto backend, exclusively. `tokio-rustls` for the listener bridge; `rustls-pemfile` for cert loading.

We pin `rustls = { version = "0.23", default-features = false, features = ["ring", "std", "logging", "tls12"] }` and `tokio-rustls = { version = "0.26", default-features = false, features = ["ring"] }` in the workspace `Cargo.toml`.

## Consequences

- **Positive**: pure-Rust crypto, single backend (`ring`) for both signing and TLS, deterministic static builds, < 20 MB Docker image.
- **Negative**: rustls doesn't support TLS 1.0/1.1 (we don't want to). Some legacy clients with broken cipher suite negotiation may fail; documented in the operations guide.

## Open questions

- When rustls switches default backend to `aws-lc-rs`, do we follow? Probably yes once the C-build / static-linking story matches `ring` quality.
