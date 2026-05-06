# Encryption at Rest

Ferrox supports two server-side encryption modes:

## SSE-S3 (server-managed key)

A 32-byte master key (the **KEK**) wraps a per-object **DEK** (also 32 bytes), generated fresh at every PutObject. Both the wrapped DEK and the object body use AES-256-GCM with independent random 96-bit nonces.

Wire format on disk:

```
ciphertext_blob = nonce(12B) || ciphertext || GCM tag(16B)
wrapped_DEK     = nonce(12B) || encrypted_DEK(32B) || GCM tag(16B)   // hex-encoded in metadata
```

The KEK is read from `--sse-master-key` (64 hex chars). Without one, SSE-S3 is disabled.

## SSE-C (caller-managed key)

The caller supplies a fresh 32-byte AES-256 key on every request:

- `x-amz-server-side-encryption-customer-algorithm: AES256`
- `x-amz-server-side-encryption-customer-key: base64(key)`
- `x-amz-server-side-encryption-customer-key-MD5: base64(md5(key))`

Ferrox **never** logs, persists, or echoes the raw key. Only an HMAC-SHA256 fingerprint is stored alongside the object so subsequent GETs / HEADs verify the same key. Wrong key → `403 InvalidArgument`.

## Bucket default policy

`PUT /{bucket}?encryption` accepts a `ServerSideEncryptionConfiguration` body. When set, requests without an SSE header are rejected with `400 InvalidEncryptionAlgorithmError`.
