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
  Credential=AKIA…/20260506/testregion/s3/aws4_request,
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

SigV4A uses ECDSA-P256 / SHA-256 instead of HMAC-chaining, so one signature can cover multiple regions. Ferrox accepts `Authorization: AWS4-ECDSA-P256-SHA256 …` and `X-Amz-Algorithm=AWS4-ECDSA-P256-SHA256` (presigned URLs). SigV4 remains the default; SigV4A is opt-in for clients that need multi-region scope.

### Differences from SigV4

| | SigV4 | SigV4A |
|---|---|---|
| Algorithm | `AWS4-HMAC-SHA256` | `AWS4-ECDSA-P256-SHA256` |
| Credential scope | `AKID/YYYYMMDD/{region}/{service}/aws4_request` | `AKID/YYYYMMDD/{service}/aws4_request` (no region) |
| Region source | Credential scope | Signed `x-amz-region-set` header (or `X-Amz-Region-Set` query param) |
| Key derivation | HMAC-chain over secret + (date, region, service) | NIST SP 800-108 counter-mode HMAC-SHA256 over `("AWS4A" \|\| secret)`, retrying for a valid P-256 scalar in `[1, n-1]` |
| Signature wire format | hex(HMAC-SHA256) — 64 hex chars | hex(DER ECDSA) — variable length |

### Required headers / query params

`x-amz-region-set` MUST be present **and** listed in `SignedHeaders`. It accepts:

- exact regions: `us-east-1`
- comma-separated lists: `us-east-1,eu-west-1`
- trailing wildcard: `us-*`
- global wildcard: `*`

The gateway's configured `--region` (default `us-east-1`) must be matched by at least one entry.

### Service scope

Ferrox supports `s3` only. Other service scopes are rejected.

### Wire example

```
Authorization: AWS4-ECDSA-P256-SHA256
  Credential=AKIA…/20260506/s3/aws4_request,
  SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-region-set,
  Signature=3045022100…
x-amz-region-set: us-*
x-amz-date: 20260506T000000Z
```

### Presigned SigV4A

```
?X-Amz-Algorithm=AWS4-ECDSA-P256-SHA256
&X-Amz-Credential=AKIA%2F20260506%2Fs3%2Faws4_request
&X-Amz-Date=20260506T000000Z
&X-Amz-Expires=900
&X-Amz-Region-Set=us-%2A
&X-Amz-SignedHeaders=host%3Bx-amz-region-set
&X-Amz-Signature=3045022100…
```

Body hash is always `UNSIGNED-PAYLOAD`. Expiry is enforced against `X-Amz-Date + X-Amz-Expires`.

## Clock skew

Requests with `X-Amz-Date` more than `--clock-skew-secs` (default 900s = 15 min) from server time are rejected with `403 RequestTimeTooSkewed`.
