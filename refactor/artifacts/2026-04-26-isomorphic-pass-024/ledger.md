# Isomorphic Simplification Pass 024

## Candidate

- File: `src/types/budget.rs`
- Lever: collapse equivalent one-sided `cost_quota` match arms in `Budget::combine`.
- Score: `(LOC_saved 1 * confidence 5) / risk 1 = 5.0`

## Isomorphism Proof

- For two finite quotas, both versions return the smaller quota via `a.min(b)`.
- For exactly one finite quota, the old arms returned that finite `Some(u64)`.
- The new or-pattern binds and returns the same `Some(u64)` for both `(Some(_), None)` and `(None, Some(_))`.
- `(None, None)` remains `None`.
- Deadline, poll quota, priority, tracing, and all public APIs are unchanged.

## Metrics

- Source LOC before: 1882
- Source LOC after: 1881
- Source LOC delta: -1
- Diff numstat: `1 insertion, 2 deletions`

## Validation

- `rustfmt --edition 2024 --check src/types/budget.rs`: passed
- `git diff --check -- src/types/budget.rs refactor/artifacts/2026-04-26-isomorphic-pass-024/ledger.md`: passed
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-types-budget-pass024-test -p asupersync --lib types::budget`: pending
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-pass024-check -p asupersync --lib`: pending
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-pass024-clippy-lib -p asupersync --lib -- -D warnings`: pending
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-pass024-clippy-tests -p asupersync --lib --tests -- -D warnings`: pending
