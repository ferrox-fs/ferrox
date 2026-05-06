# ADR 003 — Reed-Solomon erasure coding for v2 distributed mode

- Status: Proposed
- Date: 2026-05-05

## Context

v1 Ferrox is single-node: one disk, one metadata store, one process. Production deployments above ~50 TB or with a > 99.9% availability SLO need a multi-node story.

Two well-trodden options for replicating object data across nodes:

1. **Replication** — write each object to N nodes. Simple, large storage overhead (3x for N=3 — losing two of three is tolerable).
2. **Erasure coding** — split object into K data + M parity shards across N=K+M nodes. Lower overhead (e.g. 4+2 = 1.5x) for the same fault tolerance.

Erasure coding wins on long-term cost for cold object storage workloads (which is the common case for S3 deployments).

## Decision

Adopt **Reed-Solomon** erasure coding via the [`reed-solomon-erasure`](https://crates.io/crates/reed-solomon-erasure) crate.

- Default config: **4 data shards + 2 parity shards** (1.5x overhead, tolerates 2 node failures).
- Min cluster size for production erasure: **6 nodes** spread across at least 3 failure domains.
- Smaller objects (< 16 KiB after Phase 0 PUTs) bypass erasure and are mirrored 3x — encoding overhead dominates for tiny objects.
- Replication remains an option (`backend: replicated`) for write-heavy / latency-sensitive deployments.

The `ErasureBackend` interface is defined in v1 (feature-gated, returns `Unimplemented`) so v2 lands without breaking changes.

## Consequences

- **Positive**: 50% lower storage cost vs 3x replication at the same fault tolerance; standard in modern object stores (Ceph, MinIO, Cloudflare R2).
- **Negative**: encoding/decoding CPU cost on PUT/GET (mitigated by SIMD via the `reed-solomon-erasure` simd feature). Read amplification on a single failed node (decoder must fetch K shards).

## Open questions

- Single-node failure-domain awareness: do we expose `topology.kubernetes.io/zone` to the placement strategy, or rely on operator hints?
- Background reconstruction (heal) — pull-based or push-based? Likely pull, gossip-driven.
- Atomicity of writes: Pull-based two-phase commit across N shards is already complex; PUT semantics need careful spec before v2 work begins.
