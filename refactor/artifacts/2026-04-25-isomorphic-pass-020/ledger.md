# Isomorphic Simplification Pass 020

## Candidate

- File: `src/time/driver.rs`
- Lever: replace a manual `Time` clamp with `Ord::max`.
- Score: `(LOC_saved 1 * confidence 5) / risk 1 = 5.0`

## Isomorphism Proof

- `Time` derives `Copy`, `PartialOrd`, and `Ord`.
- The removed expression returned `now` when `deadline < now`, otherwise `deadline`.
- `deadline.max(now)` returns the greater of the same two ordered values, preserving equality behavior by returning `deadline` when equal.
- The wheel synchronization, optional deadline handling, and clock sampling remain unchanged.

## Metrics

- Source LOC before: 2320
- Source LOC after: 2318
- Source LOC delta: -2
- Diff numstat: `1 insertion, 3 deletions`

## Validation

- `rustfmt --edition 2024 --check src/time/driver.rs`: passed
- `git diff --check -- src/time/driver.rs refactor/artifacts/2026-04-25-isomorphic-pass-020/ledger.md`: passed
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-time-driver-pass020-test -p asupersync --lib time::driver`: passed, 46 tests
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-pass020-check -p asupersync --lib`: passed
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-pass020-clippy-tests -p asupersync --lib --tests -- -D warnings`: passed
