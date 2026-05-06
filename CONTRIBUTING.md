# Contributing to Ferrox

Thanks for your interest. Ferrox is an Apache-2.0, contributor-friendly project — we want to make the path from "I noticed something" to "merged PR" as short as possible.

If anything below is unclear or wrong, that itself is a bug worth filing.

---

## TL;DR

```sh
git clone https://github.com/ferrox-rs/ferrox.git
cd ferrox
cargo build
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

If those four commands pass, you have a clean baseline. Find a `good first issue`, pick it up, and open a PR.

---

## Code of conduct

This project follows the [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). See **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)**. Reports of harassment go to **conduct@ferrox-rs.dev** (a small, named committee, not a global mailing list).

---

## What we welcome

- **Bug fixes** — always.
- **S3 compatibility gaps** — file an `s3-compat` issue first if you're unsure of scope, but the bar for "fix this" is low.
- **Performance improvements** with reproducible benchmarks. Numbers > vibes.
- **Documentation improvements**, especially for parts of the system you found confusing as a new contributor — those are the highest-signal docs PRs.
- **New backends / integrations** — talk to maintainers in an issue first; the abstraction surface matters.
- **Test coverage**, integration test additions, fuzz target ideas.

## What we'd rather you discuss first

Before sinking a weekend into these, open an issue:

- New top-level dependencies, especially with C build requirements.
- Architectural changes — anything touching `MetaStore`, `StorageBackend`, the auth trait surface.
- New endpoint families that aren't part of the AWS S3 spec.
- Config flag additions.

A 200-word "I'm thinking of doing X, here's why, here's the rough shape" comment will save you a rewrite.

---

## How a change goes from issue to merged

1. **Find or open an issue.** Use one of the issue templates in [`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/). For S3-compat gaps, link the AWS reference page so we have a single source of truth.
2. **Claim it.** Comment "I'd like to work on this" — or just open a draft PR. We don't lock issues to people because life gets in the way; if it's been 2 weeks of silence, it's fair game for someone else.
3. **Branch from `main`.** Keep one PR focused on one logical change. PRs > 800 lines of meaningful diff are hard to review well; consider splitting.
4. **Run the local checks** (`fmt`, `clippy`, `test`). They run again in CI; failing locally just slows you down.
5. **Open a PR**, fill in the template, link the issue. Mark it `Ready for review` when CI is green.
6. **Address review feedback** by pushing more commits to the same branch. Don't force-push during review — it loses comment anchors. We squash on merge so commit hygiene on the branch matters less than thread readability.
7. **Maintainer merges.** A maintainer will press the button once approvals + CI line up. Two approvals are required for changes touching auth, crypto, or persistence; one is enough for everything else.

## Local development

```sh
# Run the daemon
cargo run --bin ferroxd -- --access-key minioadmin --secret-key minioadmin

# Watch + rebuild on change
cargo install cargo-watch
cargo watch -x 'run --bin ferroxd'

# Run the full test suite (workspace)
cargo test --workspace --all-targets

# Run only one crate's tests
cargo test -p ferrox-gateway

# Run one specific test
cargo test -p ferrox-gateway test_unauthenticated_request_returns_403_not_501 -- --nocapture
```

### Integration tests

The Boto3 + rclone interop suites live in `tests/integration/`:

```sh
# Boto3 — needs a running ferroxd on :9000
python3 -m pip install boto3 pytest
ferroxd --data-dir /tmp/ferrox-it &
pytest tests/integration/test_boto3.py -v

# rclone
brew install rclone
bash tests/integration/test_rclone.sh
```

### Building the docs

```sh
cargo install mdbook
mdbook serve docs --open
```

### Running benchmarks

```sh
cargo bench --workspace
# or one crate:
cargo bench -p ferrox-meta
```

### Running fuzz targets

```sh
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run fuzz_sigv4_parser -- -max_total_time=60
```

---

## Style and conventions

### Rust

- `#![forbid(unsafe_code)]` is non-negotiable in every crate. If you need `unsafe` for a perf reason, file an issue first.
- **No `unwrap()` / `expect()` in production paths.** Tests, benches, and `build.rs` are fine.
- Errors flow through `ferrox_error::FerroxError`. New error categories require updating both `s3_error_code()` and `http_status()` mappings.
- All public items get rustdoc with at least one example. `#![deny(missing_docs)]` enforces this.
- Comments answer **why**, not **what**. The code already tells you what.
- Don't add abstractions until at least the third call site. Three similar lines beat a premature trait.

### Commits

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(gateway): add ?lifecycle bucket policy parser

Adds parse_lifecycle_configuration() with rules + filters per the AWS
LifecycleConfiguration XML schema.

Closes #142
```

Allowed types: `feat`, `fix`, `test`, `docs`, `refactor`, `chore`, `perf`. Scope is the crate name (gateway, meta, storage, s3-api, crypto, cli, error, iam) or `repo` for cross-cutting changes.

### AWS compatibility changes

Any PR that changes the wire surface of an S3 endpoint must include a verification command in the PR description:

```sh
# What did you run against real AWS to confirm parity?
aws s3api put-bucket-tagging --bucket my-real-bucket \
  --tagging file:///tmp/tags.xml
```

Wrong status codes silently break SDK clients. The status code mapping in `FerroxError::http_status` is authoritative; handlers must not pick their own codes.

### Tests

- **Unit tests** live in the same file (`#[cfg(test)] mod tests`).
- **Integration tests** live under `tests/integration/`.
- Naming convention: `test_{action}_{condition}_{result}`, e.g. `test_put_object_with_wrong_md5_returns_400`.
- New features need both unit and integration coverage. The PR template's "Test plan" section asks how you verified.

### Security-sensitive code

Touching anything in `ferrox-crypto/`, `ferrox-gateway/src/auth/`, or `ferrox-gateway/src/middleware/auth.rs`:

- Constant-time comparisons only (`ring::constant_time::verify_slices_are_equal`).
- New key material wrapped in a `Zeroize`-implementing type. Never `Display` or `Debug`-print key bytes.
- No new entropy sources outside `ring::rand::SystemRandom` / `aes_gcm::aead::OsRng`.
- The PR will be reviewed by someone in `@ferrox-rs/security`.

---

## Reporting bugs vs requesting features

| | Bug | Feature |
|---|---|---|
| What's broken / what's missing? | "X gives Y, but I expected Z" | "I'd like to do X, but Ferrox doesn't support it" |
| Reproducer required? | yes | helpful |
| Repro template | [`bug_report.yml`](.github/ISSUE_TEMPLATE/bug_report.yml) | [`feature_request.yml`](.github/ISSUE_TEMPLATE/feature_request.yml) |
| Triage SLA | 48h to acknowledge | best-effort, no SLA |

S3 compatibility issues use a dedicated template — they need both the AWS reference and a side-by-side AWS-vs-Ferrox response capture: [`s3_compat_gap.yml`](.github/ISSUE_TEMPLATE/s3_compat_gap.yml).

---

## Releases

Maintainers release on demand, not on a fixed cadence. The release process:

1. Bump `version` in workspace `Cargo.toml`.
2. Move `## [Unreleased]` → `## [vX.Y.Z]` in `CHANGELOG.md`.
3. Tag: `git tag -s vX.Y.Z -m "..."` then `git push --tags`.
4. The `release` workflow builds binaries for all 4 platforms, pushes a multi-arch Docker image to `ghcr.io/ferrox-rs/ferrox:vX.Y.Z`, and publishes a GitHub Release.

---

## Governance

Decisions are made by maintainers (`@ferrox-rs/maintainers` on GitHub). Material decisions — license changes, breaking API changes, dependency policy changes — are documented in an ADR under `docs/adr/`.

Becoming a maintainer: be active for 6+ months (regular, high-quality PRs and reviews) and demonstrate sound judgement on contentious calls. An existing maintainer nominates; majority approval from the current maintainer set.

See **[GOVERNANCE.md](GOVERNANCE.md)** for the longer version.

---

## License

By contributing, you agree your contributions are licensed under the **Apache License, Version 2.0** (the project license). No CLA. The `Signed-off-by` line per the [Developer Certificate of Origin](https://developercertificate.org/) is appreciated but not required.

---

## Thanks

Every contribution — from typo fixes to new backends — moves Ferrox forward. We try to make the review experience low-friction; if it ever feels otherwise, please tell us in the issue or the discord.
