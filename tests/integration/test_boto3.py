#!/usr/bin/env python3
"""
Boto3 compatibility test suite for Ferrox.

Requires a running ferroxd at http://localhost:9000 and the boto3 package.

Usage:
    pip install boto3
    ferroxd --data-dir /tmp/ferrox-test --access-key testkey --secret-key testsecret &
    python3 tests/integration/test_boto3.py
"""

import hashlib
import io
import os
import sys
import unittest

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

ENDPOINT = os.getenv("FERROX_ENDPOINT", "http://localhost:9000")
ACCESS_KEY = os.getenv("FERROX_ACCESS_KEY", "testkey")
SECRET_KEY = os.getenv("FERROX_SECRET_KEY", "testsecret")
REGION = "testregion"

BUCKET = "boto3-compat-test"


def make_client():
    return boto3.client(
        "s3",
        endpoint_url=ENDPOINT,
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
        region_name=REGION,
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


class TestBucketOps(unittest.TestCase):
    def setUp(self):
        self.s3 = make_client()
        self.s3.create_bucket(Bucket=BUCKET)

    def tearDown(self):
        # Delete all objects then the bucket.
        try:
            paginator = self.s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=BUCKET):
                for obj in page.get("Contents", []):
                    self.s3.delete_object(Bucket=BUCKET, Key=obj["Key"])
            self.s3.delete_bucket(Bucket=BUCKET)
        except Exception:
            pass

    def test_create_and_head_bucket(self):
        resp = self.s3.head_bucket(Bucket=BUCKET)
        self.assertEqual(resp["ResponseMetadata"]["HTTPStatusCode"], 200)

    def test_put_and_get_object(self):
        body = b"hello, ferrox!"
        self.s3.put_object(Bucket=BUCKET, Key="hello.txt", Body=body)
        resp = self.s3.get_object(Bucket=BUCKET, Key="hello.txt")
        self.assertEqual(resp["Body"].read(), body)

    def test_get_object_range(self):
        body = b"0123456789"
        self.s3.put_object(Bucket=BUCKET, Key="range.bin", Body=body)
        resp = self.s3.get_object(Bucket=BUCKET, Key="range.bin", Range="bytes=3-6")
        self.assertEqual(resp["Body"].read(), b"3456")

    def test_delete_object(self):
        self.s3.put_object(Bucket=BUCKET, Key="to-delete.txt", Body=b"bye")
        self.s3.delete_object(Bucket=BUCKET, Key="to-delete.txt")
        with self.assertRaises(ClientError) as ctx:
            self.s3.head_object(Bucket=BUCKET, Key="to-delete.txt")
        self.assertEqual(ctx.exception.response["Error"]["Code"], "404")

    def test_list_objects_v2(self):
        keys = ["a/b/c.txt", "a/d.txt", "e.txt"]
        for k in keys:
            self.s3.put_object(Bucket=BUCKET, Key=k, Body=b"x")
        resp = self.s3.list_objects_v2(Bucket=BUCKET)
        listed = [o["Key"] for o in resp.get("Contents", [])]
        for k in keys:
            self.assertIn(k, listed)

    def test_list_objects_v2_prefix_filter(self):
        self.s3.put_object(Bucket=BUCKET, Key="pfx/a.txt", Body=b"1")
        self.s3.put_object(Bucket=BUCKET, Key="pfx/b.txt", Body=b"2")
        self.s3.put_object(Bucket=BUCKET, Key="other.txt", Body=b"3")
        resp = self.s3.list_objects_v2(Bucket=BUCKET, Prefix="pfx/")
        listed = [o["Key"] for o in resp.get("Contents", [])]
        self.assertIn("pfx/a.txt", listed)
        self.assertIn("pfx/b.txt", listed)
        self.assertNotIn("other.txt", listed)

    def test_head_object_returns_correct_content_length(self):
        body = b"size check"
        self.s3.put_object(Bucket=BUCKET, Key="sized.bin", Body=body)
        resp = self.s3.head_object(Bucket=BUCKET, Key="sized.bin")
        self.assertEqual(resp["ContentLength"], len(body))

    def test_copy_object(self):
        src = b"copy source"
        self.s3.put_object(Bucket=BUCKET, Key="src.txt", Body=src)
        self.s3.copy_object(
            CopySource={"Bucket": BUCKET, "Key": "src.txt"},
            Bucket=BUCKET,
            Key="dst.txt",
        )
        resp = self.s3.get_object(Bucket=BUCKET, Key="dst.txt")
        self.assertEqual(resp["Body"].read(), src)

    def test_batch_delete_objects(self):
        keys = [f"del-{i}.txt" for i in range(5)]
        for k in keys:
            self.s3.put_object(Bucket=BUCKET, Key=k, Body=b"x")
        self.s3.delete_objects(
            Bucket=BUCKET,
            Delete={"Objects": [{"Key": k} for k in keys]},
        )
        resp = self.s3.list_objects_v2(Bucket=BUCKET)
        remaining = [o["Key"] for o in resp.get("Contents", [])]
        for k in keys:
            self.assertNotIn(k, remaining)

    def test_multipart_upload(self):
        # Minimum part size is 5 MiB; use 6 MiB parts.
        part_size = 6 * 1024 * 1024
        data = os.urandom(part_size * 2 + 100)

        mpu = self.s3.create_multipart_upload(Bucket=BUCKET, Key="mpu.bin")
        uid = mpu["UploadId"]

        parts = []
        for i, offset in enumerate(range(0, len(data), part_size), start=1):
            chunk = data[offset : offset + part_size]
            r = self.s3.upload_part(
                Bucket=BUCKET, Key="mpu.bin", UploadId=uid, PartNumber=i, Body=chunk
            )
            parts.append({"PartNumber": i, "ETag": r["ETag"]})

        self.s3.complete_multipart_upload(
            Bucket=BUCKET, Key="mpu.bin", UploadId=uid, MultipartUpload={"Parts": parts}
        )

        resp = self.s3.get_object(Bucket=BUCKET, Key="mpu.bin")
        got = resp["Body"].read()
        self.assertEqual(got, data)

    def test_presigned_url_get(self):
        body = b"presigned content"
        self.s3.put_object(Bucket=BUCKET, Key="presigned.txt", Body=body)
        url = self.s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": BUCKET, "Key": "presigned.txt"},
            ExpiresIn=60,
        )
        import urllib.request
        with urllib.request.urlopen(url) as r:
            self.assertEqual(r.read(), body)

    def test_list_buckets(self):
        resp = self.s3.list_buckets()
        names = [b["Name"] for b in resp["Buckets"]]
        self.assertIn(BUCKET, names)


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestBucketOps)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
