# TLS Setup

Ferrox uses **rustls** with the **ring** crypto backend exclusively. There is no OpenSSL dependency.

## Generate a self-signed cert (dev)

```sh
openssl req -x509 -newkey rsa:4096 -nodes -keyout server.key -out server.crt \
  -subj "/CN=ferrox.local" -days 365
```

## Run with TLS

```sh
ferroxd \
  --bind 0.0.0.0:9000 \
  --tls-bind 0.0.0.0:9443 \
  --tls-cert ./server.crt \
  --tls-key  ./server.key
```

Both listeners run concurrently. ALPN advertises `h2` and `http/1.1`.

## Production (ACME / cert-manager)

In Kubernetes, use the Helm chart with `tls.enabled=true` and point `tls.secretName` at a `kubernetes.io/tls` Secret managed by [cert-manager](https://cert-manager.io/).
