# CLAUDE.md — Ferrox AI Build Guide

## 🧠 PROJECT CONTEXT

You are building **Ferrox** — an AWS S3-compatible object storage server.

* Language: Rust (2021)
* Runtime: tokio
* HTTP: axum
* TLS: rustls ONLY (no OpenSSL)
* Metadata: sled (default), RocksDB later
* Crypto: ring + aes-gcm
* Goal: Full S3 API compatibility

---

## 🚫 NON-NEGOTIABLE RULES

* No `unwrap()` / `expect()` (except tests)
* All errors → `ferrox-error` (thiserror)
* Every public fn → rustdoc + example
* Every feature → unit + integration tests
* Must pass:

  * `cargo fmt`
  * `cargo clippy -D warnings`
* No C FFI ever
* HTTP + XML must match AWS exactly

---

## 📁 PROJECT STRUCTURE (STRICT)

```
ferrox/
├── Cargo.toml
├── crates/
│   ├── ferrox-gateway
│   ├── ferrox-s3-api
│   ├── ferrox-storage
│   ├── ferrox-meta
│   ├── ferrox-iam
│   ├── ferrox-crypto
│   ├── ferrox-error
│   └── ferrox-cli
├── tests/
├── docs/
├── scripts/
```

---

## ⚙️ HOW YOU MUST WORK

1. Work step-by-step (never skip ahead)
2. Implement ONLY current step
3. After each step:

   * Build passes
   * Tests pass
4. Then STOP

---

## 📦 OUTPUT FORMAT

Always return:

* Files created/updated
* Full working code (no pseudo)
* Tests
* Run/verify steps

---

## 🧪 TEST RULES

* Unit tests: inside file (`#[cfg(test)]`)
* Integration: `/tests`
* Naming:
  `test_{action}_{condition}_{result}`

---

## 🧾 COMMITS

Use Conventional Commits:

* feat(), fix(), test(), docs(), refactor(), chore(), perf()

---

## 🔄 PHASE FLOW

### 🟢 Phase 0 — Foundation

Goal: working binary + auth + storage

Steps:

1. Workspace scaffold
2. Error system
3. CI pipeline
4. SigV4 parser
5. SigV4 verifier ⚠️ critical
6. Storage trait
7. Disk backend
8. Metadata (sled)
9. HTTP router
10. Auth middleware

---

### 🔵 Phase 1 — Core S3

Goal: full S3 functionality

* CopyObject
* Batch delete
* Multipart upload
* Versioning
* Pre-signed URLs
* SSE-S3
* TLS (rustls)
* Docker

---

### 🟡 Phase 2 — Production

Goal: production-ready system

* Tagging + CORS
* SSE-C
* Metrics (Prometheus)
* Health endpoints
* Rate limiting
* Helm chart
* Fuzz testing

---

### 🔴 Phase 3 — Launch

Goal: 1.0 release

* SigV4A
* RocksDB backend
* mTLS admin API
* Terraform
* Release pipeline
* Notifications

---

## 🔐 SECURITY RULES

* SigV4 must use constant-time comparison
* Reject clock skew > 15 min
* AES-256-GCM for encryption
* Never log secrets
* Never store plaintext if encrypted

---

## 🧠 DECISION RULES

* Correctness > performance
* Match AWS behavior strictly
* Don’t guess — ask if unclear

---

## 🚀 START BEHAVIOR

When loaded, ask:

> Which phase and step should I start?

Then execute ONLY that step.

---

## ❌ FAILURE CONDITIONS

Invalid if:

* Uses unwrap in production
* Missing tests
* Wrong HTTP codes
* Breaks S3 compatibility
* Skips steps

---

## ✅ SUCCESS

* AWS CLI works without changes
* Boto3 tests pass
* Docker runs
* All phases complete

---
