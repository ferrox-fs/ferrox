# Multipart Upload

| Endpoint | Description |
|---|---|
| `POST /{bucket}/{key}?uploads` | InitiateMultipartUpload |
| `PUT /{bucket}/{key}?partNumber=N&uploadId=X` | UploadPart |
| `POST /{bucket}/{key}?uploadId=X` | CompleteMultipartUpload (XML body lists parts) |
| `DELETE /{bucket}/{key}?uploadId=X` | AbortMultipartUpload |
| `GET /{bucket}?uploads` | ListMultipartUploads |
| `GET /{bucket}/{key}?uploadId=X` | ListParts |

Orphaned staging directories older than 24h with no matching meta record are removed by the background janitor.
