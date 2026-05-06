# Object Operations

| Endpoint | Description |
|---|---|
| `PUT /{bucket}/{key}` | PutObject — body is the object body |
| `PUT /{bucket}/{key}` + `x-amz-copy-source` | CopyObject (server-side) |
| `GET /{bucket}/{key}` | GetObject — supports `Range:` |
| `HEAD /{bucket}/{key}` | HeadObject |
| `DELETE /{bucket}/{key}` | DeleteObject |
| `PUT /{bucket}/{key}?tagging` | PutObjectTagging |
| `GET /{bucket}/{key}?tagging` | GetObjectTagging |

## Server-side encryption

| Header(s) | Mode |
|---|---|
| `x-amz-server-side-encryption: AES256` | SSE-S3 (server-managed key) |
| `x-amz-server-side-encryption-customer-algorithm`, `-customer-key`, `-customer-key-MD5` | SSE-C (caller-managed key) |

SSE-C keys are never logged, returned, or persisted — only an HMAC fingerprint is stored, used to verify the same key is presented on subsequent reads.
