# SigV4 Authentication

Every request to Ferrox (except `/health/*` and `/metrics`) must carry an AWS Signature Version 4 signature.

## How it works

1. Client builds a **canonical request** from the HTTP method, path, query string, headers, and the SHA-256 of the body.
2. Client builds a **string-to-sign** combining the canonical request hash with the credential scope (`AWS4-HMAC-SHA256\n{date}\n{date}/{region}/s3/aws4_request\n{canonical-hash}`).
3. Client derives a per-request signing key by HMAC-chaining the secret access key with `(date, region, service, "aws4_request")`.
4. The hex-encoded HMAC-SHA256 of the string-to-sign with the signing key is sent as `Signature=` in the `Authorization` header.

Ferrox repeats the same construction on the server and compares with constant-time HMAC comparison.

## Where SigV4 lives in headers

```
Authorization: AWS4-HMAC-SHA256
  Credential=AKIA…/20260505/us-east-1/s3/aws4_request,
  SignedHeaders=host;x-amz-content-sha256;x-amz-date,
  Signature=4e8e2…
```

`x-amz-date` and `x-amz-content-sha256` MUST be sent and signed. Ferrox uses `x-amz-content-sha256` directly as the body hash — there is no streaming-payload re-hash.

## curl example

```sh
aws --endpoint-url http://localhost:9000 \
    --debug s3 ls s3://my-bucket 2>&1 | grep "Authorization"
```

That tells the AWS CLI to print the signed Authorization header it built.

## Pre-signed URLs

Ferrox accepts SigV4 in the query string (`X-Amz-Algorithm=AWS4-HMAC-SHA256`, `X-Amz-Credential`, `X-Amz-SignedHeaders`, `X-Amz-Signature`, `X-Amz-Date`, `X-Amz-Expires`). The `UNSIGNED-PAYLOAD` body hash convention is honoured.

## SigV4A (multi-region)

SigV4A uses ECDSA-P256 instead of HMAC-chaining, which lets one signature cover multiple regions. Ferrox accepts `Authorization: AWS4-ECDSA-P256-SHA256` headers and verifies against an HKDF-derived P-256 key. Used primarily for cross-region `CopyObject`.

## Clock skew

Requests with `X-Amz-Date` more than `--clock-skew-secs` (default 900s = 15 min) from server time are rejected with `403 RequestTimeTooSkewed`.
