# ADR 001 — `sled` as the default metadata store; RocksDB as an optional backend

- Status: Accepted
- Date: 2026-05-05

## Context

Ferrox needs an embedded ACID key-value store for bucket and object metadata. Two viable options:

1. **sled** — pure-Rust, async-friendly via `spawn_blocking`, single dependency.
2. **RocksDB** — mature, battle-tested, but requires a C++ toolchain at build time.

We want the default Ferrox build to compile with `cargo build` on a clean machine without `cmake`, `clang`, or system libraries.

## Decision

- **Default**: `sled`. Always built, tested, and exercised by the integration suite.
- **Opt-in**: RocksDB, behind the `rocksdb` cargo feature. Enabled with `cargo build --features rocksdb`. Tests assert behavioural parity via a shared test macro.

A `ferroxctl migrate --from sled --to rocksdb` command moves data atomically between backends.

## Consequences

- **Positive**: zero-toolchain default build. CI matrix can run the C++-free path on every PR; the RocksDB path runs on a separate job that pre-installs `cmake` and `clang`.
- **Negative**: sled has known long-term durability quirks under heavy mixed workloads. The opt-in path is the recommended choice for production fleets > 10 nodes; this is documented in the ops guide.

## Open questions

- Can we ship pre-built static binaries for both backends side by side, or do we publish a separate `-rocksdb` artifact?
