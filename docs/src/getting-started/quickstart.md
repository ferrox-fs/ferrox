# Quickstart

Get a running Ferrox endpoint and PutObject in under 5 minutes.

## 1. Start ferroxd

```sh
cargo run --release --bin ferroxd -- \
  --data-dir ./data \
  --bind 0.0.0.0:9000 \
  --access-key minioadmin \
  --secret-key minioadmin
```

Verify the daemon is up:

```sh
curl http://localhost:9000/health/live
# {"status":"ok"}
```

## 2. Create a bucket and put an object (curl)

```sh
# Helper to sign with the AWS CLI
export AWS_ACCESS_KEY_ID=minioadmin
export AWS_SECRET_ACCESS_KEY=minioadmin
export AWS_DEFAULT_REGION=testregion
export ENDPOINT=http://localhost:9000

aws --endpoint-url $ENDPOINT s3 mb s3://photos
echo "hello, ferrox" > hello.txt
aws --endpoint-url $ENDPOINT s3 cp hello.txt s3://photos/hello.txt
aws --endpoint-url $ENDPOINT s3 ls s3://photos/
```

## 3. Put an object (Boto3)

```python
import boto3

s3 = boto3.client(
    "s3",
    endpoint_url="http://localhost:9000",
    aws_access_key_id="minioadmin",
    aws_secret_access_key="minioadmin",
    region_name="testregion",
)

s3.create_bucket(Bucket="photos")
s3.put_object(Bucket="photos", Key="cat.jpg", Body=b"\xff\xd8\xff...")
print(s3.list_objects_v2(Bucket="photos"))
```

## 4. Put an object (rclone)

```sh
rclone config create ferrox s3 \
  provider Other \
  endpoint http://localhost:9000 \
  access_key_id minioadmin \
  secret_access_key minioadmin

rclone copy ./hello.txt ferrox:photos/
rclone ls ferrox:photos/
```

## 5. Enable encryption (SSE-S3)

Generate a 64-hex-char master key and pass it via `--sse-master-key`:

```sh
openssl rand -hex 32
# 8a2c... (64 chars)

ferroxd --sse-master-key 8a2c...
```

Then add `--sse aes256` to your AWS CLI calls or `ServerSideEncryption='AES256'` to Boto3.

## Next

- **[Configuration Reference](configuration.md)** — every CLI flag and env var.
- **[Authentication](../api/sigv4.md)** — how SigV4 verification works.
- **[TLS Setup](../security/tls.md)** — terminate HTTPS on `:9443`.
