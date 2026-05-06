# Configuration Reference

Configuration is layered; later sources override earlier ones:

1. CLI flags (highest priority)
2. `ferrox.toml` in the working directory
3. `FERROX_*` environment variables

## Flags / env vars

| Flag | Env | Default | Description |
|---|---|---|---|
| `--data-dir` | `FERROX_DATA_DIR` | `./data` | Directory for objects + sled metadata |
| `--bind` | `FERROX_BIND` | `0.0.0.0:9000` | Plain HTTP listen address |
| `--tls-bind` | `FERROX_TLS_BIND` | _unset_ | HTTPS listen address (must include cert + key) |
| `--tls-cert` | `FERROX_TLS_CERT` | _unset_ | PEM cert chain |
| `--tls-key` | `FERROX_TLS_KEY` | _unset_ | PEM private key |
| `--access-key` | `FERROX_ACCESS_KEY` | `minioadmin` | Single-tenant access key |
| `--secret-key` | `FERROX_SECRET_KEY` | `minioadmin` | Secret bound to access key |
| `--clock-skew-secs` | `FERROX_CLOCK_SKEW_SECS` | `900` | SigV4 clock skew tolerance |
| `--fsync` | `FERROX_FSYNC` | `true` | Call `fsync` after every write |
| `--sse-master-key` | `FERROX_SSE_MASTER_KEY` | _unset_ | 64-hex master key for SSE-S3 |
| `--max-req-per-sec` | `FERROX_MAX_REQ_PER_SEC` | `0` | Per-access-key budget; 0 disables |

## Example `ferrox.toml`

```toml
data_dir = "/var/lib/ferrox"
bind = "0.0.0.0:9000"
tls_bind = "0.0.0.0:9443"
tls_cert = "/etc/ferrox/server.crt"
tls_key  = "/etc/ferrox/server.key"
access_key = "MOCKACCESSKEYFORTEST"
secret_key = "MOCKxSECRETxKEYxFORxTESTSxONLYx123456789"
clock_skew_secs = 900
fsync = true
sse_master_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
max_req_per_sec = 1000
```
