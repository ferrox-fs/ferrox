# Security policy

Thanks for taking the time to report. Ferrox handles auth, encryption, and arbitrary user data — we treat security reports as priority work.

## Reporting a vulnerability

**Do not open a public GitHub issue for security bugs.** Instead, use **GitHub Security Advisories**:

1. Go to <https://github.com/ferrox-rs/ferrox/security/advisories/new>.
2. Fill in the details. Include a minimal reproducer and the impact you observe.
3. We'll respond within the SLA below.

Encrypted email is also accepted: `security@ferrox-rs.dev` (PGP key on the same page).

## SLA

| Severity | Acknowledge | Patch released |
|---|---|---|
| Critical (data loss, RCE, auth bypass) | < 24 h | ≤ 7 days |
| High (info disclosure, integrity) | < 48 h | ≤ 14 days |
| Medium / Low | < 5 business days | next minor |

We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure). After a fix ships, we publish a GitHub Security Advisory and credit the reporter (unless you ask us not to).

## Scope

In scope:
- Anything in this repository.
- The published Docker images at `ghcr.io/ferrox-rs/ferrox`.
- The Helm chart at `helm/ferrox/`.

Out of scope:
- Third-party dependencies — please report those upstream and link the advisory back.
- Test infrastructure / CI workflows.

## Hardening notes

- No `unsafe` in production code (`#![forbid(unsafe_code)]` in every crate).
- SigV4 verification uses constant-time HMAC comparison.
- TLS is rustls + ring only — no OpenSSL.
- SSE-C raw keys never persist or appear in logs; only an HMAC fingerprint is stored.
- All secrets are wiped on drop via `zeroize`.

## Past advisories

None yet — this section is updated as advisories are published.
