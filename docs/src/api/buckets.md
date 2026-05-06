# Bucket Operations

| Endpoint | Description |
|---|---|
| `GET /` | ListBuckets |
| `PUT /{bucket}` | CreateBucket |
| `HEAD /{bucket}` | HeadBucket |
| `DELETE /{bucket}` | DeleteBucket (must be empty) |
| `GET /{bucket}` | ListObjectsV2 (`?prefix=`, `?max-keys=`, `?continuation-token=`) |
| `POST /{bucket}?delete` | DeleteObjects (batch, up to 1000 keys) |
| `PUT /{bucket}?versioning` | PutBucketVersioning |
| `GET /{bucket}?versioning` | GetBucketVersioning |
| `PUT /{bucket}?tagging` | PutBucketTagging |
| `GET /{bucket}?tagging` | GetBucketTagging |
| `PUT /{bucket}?cors` | PutBucketCors |
| `GET /{bucket}?cors` | GetBucketCors |
| `PUT /{bucket}?encryption` | PutBucketEncryption |
| `GET /{bucket}?encryption` | GetBucketEncryption |
| `PUT /{bucket}?notification` | PutBucketNotification |
| `GET /{bucket}?notification` | GetBucketNotification |
| `OPTIONS /{bucket}` | CORS preflight |
