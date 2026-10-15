# Isomorphic Simplification Pass 021

## Candidate

- File: `src/time/interval.rs`
- Lever: collapse manual `Duration` nanosecond saturation into an equivalent `min` expression.
- Score: `(LOC_saved 1 * confidence 5) / risk 1 = 5.0`

## Isomorphism Proof

- The old branch returned `u64::MAX` when `duration.as_nanos() > u64::MAX`.
- Otherwise it returned `duration.as_nanos() as u64`.
- `duration.as_nanos().min(u128::from(u64::MAX)) as u64` maps both cases to the same output, including equality at `u64::MAX`.
- All callers still receive the same saturated `u64` for interval period and reset-after arithmetic.

## Metrics

- Source LOC before: 1151
- Source LOC after: 1146
- Source LOC delta: -5
- Diff numstat: `1 insertion, 6 deletions`

## Validation

- `rustfmt --edition 2024 --check src/time/interval.rs`: passed
- `git diff --check -- src/time/interval.rs refactor/artifacts/2026-04-25-isomorphic-pass-021/ledger.md`: passed
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-time-interval-pass021-test -p asupersync --lib time::interval`: passed, 33 tests
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-pass021-check -p asupersync --lib`: passed
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-pass021-clippy-tests -p asupersync --lib --tests -- -D warnings`: passed
