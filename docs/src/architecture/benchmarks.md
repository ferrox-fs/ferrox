# Benchmarks

Microbenchmarks live in `crates/*/benches/` and are driven by `cargo bench` (criterion).

## Targets

| Bench | Target |
|---|---|
| `ferrox-gateway::sigv4_bench` | < 50 µs per verification |
| `ferrox-meta::sled_bench::put_object_meta` | < 200 µs p99 |
| `ferrox-meta::sled_bench::get_object_meta` | < 200 µs p99 |

## Macro benchmarks

`scripts/bench/wrk_bench.sh` drives `wrk` against a running ferroxd:

| Scenario | Target p99 |
|---|---|
| ListObjectsV2 (1K pre-loaded) | < 5 ms |
| PutObject 4 KB | < 1 ms (excl. network) |

Hardware used for the published baseline: TBD on first 1.0 release.
