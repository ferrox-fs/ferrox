#!/usr/bin/env bash
# scripts/bench/wrk_bench.sh — drive wrk against a running ferroxd.
#
# Prereqs: ferroxd running on $ENDPOINT, AWS credentials exported, wrk + jq.
set -euo pipefail

ENDPOINT="${ENDPOINT:-http://127.0.0.1:9000}"
BUCKET="${BUCKET:-ferrox-bench}"
DURATION="${DURATION:-30s}"
THREADS="${THREADS:-2}"
CONNECTIONS="${CONNECTIONS:-32}"

echo "Pre-loading 1000 objects into s3://$BUCKET ..."
aws --endpoint-url "$ENDPOINT" s3 mb "s3://$BUCKET" 2>/dev/null || true
for i in $(seq 1 1000); do
  printf "obj-%04d" "$i" | aws --endpoint-url "$ENDPOINT" \
    s3 cp - "s3://$BUCKET/obj-$(printf "%04d" $i).txt" >/dev/null
done

echo "Running ListObjectsV2 wrk ..."
LIST_OUT=$(wrk -t"$THREADS" -c"$CONNECTIONS" -d"$DURATION" --latency \
  "$ENDPOINT/$BUCKET?list-type=2&max-keys=1000" 2>&1)
echo "$LIST_OUT"

echo "Running PutObject 4KB wrk ..."
dd if=/dev/urandom of=/tmp/4k.bin bs=4096 count=1 status=none
PUT_OUT=$(wrk -t"$THREADS" -c"$CONNECTIONS" -d"$DURATION" --latency \
  -s scripts/bench/wrk_put.lua "$ENDPOINT/$BUCKET/" 2>&1)
echo "$PUT_OUT"

mkdir -p scripts/bench
cat > scripts/bench/baseline.json <<EOF
{
  "endpoint": "$ENDPOINT",
  "bucket":   "$BUCKET",
  "duration": "$DURATION",
  "list_objects_v2": $(echo "$LIST_OUT"  | grep -E "Latency|Req/Sec" | head -1 | tr -s ' ' | jq -R .),
  "put_object_4kb":  $(echo "$PUT_OUT"   | grep -E "Latency|Req/Sec" | head -1 | tr -s ' ' | jq -R .)
}
EOF
echo "Wrote scripts/bench/baseline.json"
