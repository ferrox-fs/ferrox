# Kubernetes / Helm

```sh
helm install ferrox ./helm/ferrox \
  --set credentials.accessKey=mykey \
  --set credentials.secretKey=mysecret \
  --set persistence.size=50Gi
```

Probes are wired:

- `livenessProbe` → `GET /health/live`
- `readinessProbe` → `GET /health/ready` (probes sled + disk)

Pod-level security context:

- `runAsNonRoot: true`
- `readOnlyRootFilesystem: true`
- All capabilities dropped

Prometheus annotations are set so a scrape config with `prometheus.io/scrape: "true"` will pick `/metrics` automatically on port 9000.

See `helm/ferrox/values.yaml` for every tunable.
