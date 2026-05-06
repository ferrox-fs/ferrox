# Governance

Ferrox is a community-led, Apache-2.0 project. This document describes how decisions are made, who makes them, and how that changes as the project grows.

## Roles

### Contributor

Anyone who has had a PR merged. Contributors get the `Contributor` role on the repo.

### Reviewer

Trusted contributors with strong domain knowledge in one or more crates. Reviewers can approve PRs but cannot merge them. Promoted by maintainer consensus after a sustained pattern of high-signal reviews.

### Maintainer (`@ferrox-rs/maintainers`)

Maintainers can:

- Merge PRs.
- Cut releases.
- Edit any branch protection or repo setting.
- Publish to crates.io / GHCR under the project's identity.
- Add/remove labels, milestones, project columns.

### Security Committee (`@ferrox-rs/security`)

A subset of maintainers, named explicitly, who handle private vulnerability reports per [SECURITY.md](SECURITY.md). Required reviewers for PRs touching `ferrox-crypto`, `ferrox-gateway/src/auth/`, or `ferrox-gateway/src/middleware/auth.rs`.

### Conduct Committee

A subset of maintainers handling Code of Conduct reports. Reachable at `conduct@ferrox-rs.dev`. Membership is public; deliberations are not.

## Decision-making

Decisions follow a **lazy consensus** model:

1. A change is proposed (PR or issue).
2. Anyone — maintainer or not — can object with reasoning.
3. If no objection within a reasonable period (5 business days for substantive changes, 48h for routine), the change goes forward.
4. Maintainer-merge approvals follow the matrix below.

### Merge approvals

| Change scope | Required approvals |
|---|---|
| Auth, crypto, persistence | 2 maintainers (one from `@ferrox-rs/security` for crypto/auth) |
| New top-level dependency | 2 maintainers + ADR if non-trivial |
| Public API breaking change | 2 maintainers + ADR + `## [Unreleased]` entry |
| New endpoint / feature | 1 maintainer |
| Bug fix | 1 maintainer |
| Docs / tests / CI | 1 reviewer or 1 maintainer |

### Architecture Decision Records

Any decision that:

- Adds a top-level dependency,
- Changes a public trait surface,
- Has cross-crate consequences,
- Or creates a long-term operational expectation,

requires an ADR under `docs/adr/`. ADRs are append-only — if a decision is reversed, write a new ADR that supersedes the old one.

## Changing this document

Changes to `GOVERNANCE.md`, `CODE_OF_CONDUCT.md`, the `LICENSE`, or the maintainer set itself require:

- A PR with the proposed change.
- Approval from a 2/3 majority of the current maintainer set.
- 7-day public comment window before merge.

## Stepping down

Maintainers can step down by opening a PR removing themselves from `CODEOWNERS` and the `@ferrox-rs/maintainers` GitHub team. No drama needed.

If a maintainer becomes inactive (no PR review or merge for 6 months) and is unreachable for 4 weeks after an outreach, the remaining maintainers may move them to a `Maintainer Emeritus` role by simple majority. They retain their commit history and any role can be re-granted on return.
