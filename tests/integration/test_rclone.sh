#!/usr/bin/env bash
# rclone S3 compatibility smoke-test for Ferrox.
#
# Prerequisites:
#   - ferroxd running at http://localhost:9000
#   - rclone installed and on PATH
#   - FERROX_ACCESS_KEY / FERROX_SECRET_KEY set (defaults below)
#
# Usage:
#   bash tests/integration/test_rclone.sh

set -euo pipefail

ENDPOINT="${FERROX_ENDPOINT:-http://localhost:9000}"
ACCESS_KEY="${FERROX_ACCESS_KEY:-testkey}"
SECRET_KEY="${FERROX_SECRET_KEY:-testsecret}"
BUCKET="rclone-compat-test-$$"
REMOTE="ferrox-test"

PASS=0
FAIL=0

pass() { echo "  PASS: $1"; ((PASS++)) || true; }
fail() { echo "  FAIL: $1 — $2"; ((FAIL++)) || true; }

# ── Configure a temporary rclone remote ──────────────────────────────────────
RCLONE_CFG="$(mktemp)"
trap 'rm -f "$RCLONE_CFG"' EXIT

cat > "$RCLONE_CFG" <<CFG
[$REMOTE]
type = s3
provider = Other
endpoint = $ENDPOINT
access_key_id = $ACCESS_KEY
secret_access_key = $SECRET_KEY
acl = private
force_path_style = true
CFG

RCLONE="rclone --config $RCLONE_CFG"

echo "=== Ferrox rclone compatibility tests ==="
echo "    endpoint : $ENDPOINT"
echo "    bucket   : $BUCKET"
echo ""

# ── Helpers ──────────────────────────────────────────────────────────────────
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir" "$RCLONE_CFG"' EXIT

# ── Tests ────────────────────────────────────────────────────────────────────

# 1. Create bucket
if $RCLONE mkdir "$REMOTE:$BUCKET" 2>/dev/null; then
    pass "mkdir (create bucket)"
else
    fail "mkdir (create bucket)" "rclone mkdir failed"
fi

# 2. Upload a small file
echo "hello rclone" > "$tmpdir/hello.txt"
if $RCLONE copy "$tmpdir/hello.txt" "$REMOTE:$BUCKET/hello.txt" 2>/dev/null; then
    pass "copy upload"
else
    fail "copy upload" "rclone copy failed"
fi

# 3. List objects
if $RCLONE ls "$REMOTE:$BUCKET" 2>/dev/null | grep -q "hello.txt"; then
    pass "ls (list objects)"
else
    fail "ls (list objects)" "hello.txt not found in listing"
fi

# 4. Download and verify content
dl="$tmpdir/hello_dl.txt"
if $RCLONE copy "$REMOTE:$BUCKET/hello.txt" "$tmpdir" --no-traverse 2>/dev/null && \
   [ "$(cat "$tmpdir/hello.txt")" = "hello rclone" ]; then
    pass "copy download + content match"
else
    fail "copy download + content match" "downloaded content mismatch"
fi

# 5. Upload a larger file (1 MiB) — tests streaming
dd if=/dev/urandom of="$tmpdir/big.bin" bs=1024 count=1024 2>/dev/null
checksum_up="$(md5sum "$tmpdir/big.bin" | awk '{print $1}')"
if $RCLONE copy "$tmpdir/big.bin" "$REMOTE:$BUCKET/big.bin" 2>/dev/null; then
    pass "copy upload (1 MiB)"
else
    fail "copy upload (1 MiB)" "upload failed"
fi

# 6. Download and verify large file checksum
$RCLONE copy "$REMOTE:$BUCKET/big.bin" "$tmpdir/dl" --no-traverse 2>/dev/null || true
if [ -f "$tmpdir/dl/big.bin" ]; then
    checksum_dl="$(md5sum "$tmpdir/dl/big.bin" | awk '{print $1}')"
    if [ "$checksum_up" = "$checksum_dl" ]; then
        pass "copy download + checksum (1 MiB)"
    else
        fail "copy download + checksum (1 MiB)" "checksum mismatch ($checksum_up vs $checksum_dl)"
    fi
else
    fail "copy download + checksum (1 MiB)" "downloaded file not found"
fi

# 7. Delete a single object
if $RCLONE deletefile "$REMOTE:$BUCKET/hello.txt" 2>/dev/null; then
    pass "deletefile"
else
    fail "deletefile" "rclone deletefile failed"
fi

# 8. Confirm it's gone
if $RCLONE ls "$REMOTE:$BUCKET" 2>/dev/null | grep -q "hello.txt"; then
    fail "verify deletion" "hello.txt still listed after delete"
else
    pass "verify deletion"
fi

# 9. Sync a local directory to bucket
mkdir -p "$tmpdir/sync_src"
for i in 1 2 3; do echo "file$i" > "$tmpdir/sync_src/file$i.txt"; done
if $RCLONE sync "$tmpdir/sync_src" "$REMOTE:$BUCKET/sync/" 2>/dev/null; then
    count=$($RCLONE ls "$REMOTE:$BUCKET/sync/" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$count" -eq 3 ]; then
        pass "sync (3 files)"
    else
        fail "sync (3 files)" "expected 3 objects, got $count"
    fi
else
    fail "sync" "rclone sync failed"
fi

# 10. Clean up — purge bucket
if $RCLONE purge "$REMOTE:$BUCKET" 2>/dev/null; then
    pass "purge (cleanup)"
else
    fail "purge (cleanup)" "rclone purge failed"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
