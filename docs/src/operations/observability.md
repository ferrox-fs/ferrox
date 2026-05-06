# Observability

## Prometheus metrics

`GET /metrics` (no auth) returns the standard Prometheus text exposition format. The following metric families are exported:

| Metric | Type | Labels |
|---|---|---|
| `ferrox_requests_total` | Counter | `method`, `endpoint`, `status` |
| `ferrox_request_duration_seconds` | Histogram | `method`, `endpoint` |
| `ferrox_bytes_in_total` | Counter | `bucket` |
| `ferrox_bytes_out_total` | Counter | `bucket` |
| `ferrox_objects_total` | Gauge | `bucket` |
| `ferrox_storage_bytes` | Gauge | `bucket` |
| `ferrox_active_connections` | Gauge | — |
| `ferrox_multipart_pending_total` | Gauge | — |

Histograms use the buckets `[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]`.

## Health endpoints

- `GET /health/live` — process is up.
- `GET /health/ready` — concurrent probes of the metadata store and the data dir; returns 503 if either fails.
- `GET /health/version` — JSON with `version`, `commit`, `built_at`.

## Logging

Tracing is configured via the `RUST_LOG` env var. Default is `info`. JSON output:

```sh
RUST_LOG=info ferroxd | jq .
```

## Admin API

The admin plane runs on a separate port (default 9444) with mTLS — see [mTLS](../security/iam.md).
