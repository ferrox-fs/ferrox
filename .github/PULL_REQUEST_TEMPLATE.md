## Summary

<!-- One paragraph: what does this PR do, and why? -->

## Linked issue

<!-- Closes #123 -->

## Checklist

- [ ] `cargo fmt` clean
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] `cargo test --workspace` green
- [ ] Public APIs documented with rustdoc + at least one example
- [ ] AWS-compat changes verified against the real AWS SDK behaviour (Boto3 / AWS CLI)
- [ ] `CHANGELOG.md` updated under `## [Unreleased]`
- [ ] No `unwrap()` / `expect()` introduced in production paths
- [ ] No new `unsafe` introduced

## Test plan

<!-- How did you verify this? Boto3 script, integration test name, manual curl, etc. -->

## Out-of-scope

<!-- Anything you considered but deliberately left out. -->
