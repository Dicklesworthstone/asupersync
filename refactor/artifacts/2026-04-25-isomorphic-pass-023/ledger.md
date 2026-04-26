# Isomorphic Simplification Pass 023

## Candidate

- File: `src/types/budget.rs`
- Lever: collapse equivalent one-sided deadline match arms in `Budget::combine`.
- Score: `(LOC_saved 1 * confidence 5) / risk 1 = 5.0`

## Isomorphism Proof

- For two finite deadlines, the old branch returned `a` when `a < b` and `b` otherwise; `a.min(b)` is identical for `Time: Ord`.
- For exactly one finite deadline, the old branches returned that finite deadline.
- The new or-pattern binds and returns the same `Some(Time)` for both `(Some(_), None)` and `(None, Some(_))`.
- `(None, None)` remains `None`.
- Poll quota, cost quota, priority, tracing, and all public APIs are unchanged.

## Rejected Candidate

- `src/util/arena.rs`: deriving `Default` for `Arena<T>` looked equivalent to the manual impl but is not isomorphic.
- A direct Rust check showed derive would add a public `T: Default` bound to `Arena<T>::default()`.
- The manual impl intentionally supports `Arena<NonDefault>::default()`, so the source edit was reverted and not shipped.

## Metrics

- Source LOC before: 1883
- Source LOC after: 1882
- Source LOC delta: -1
- Diff numstat: `2 insertions, 3 deletions`

## Validation

- `rustfmt --edition 2024 --check src/types/budget.rs`: passed
- `git diff --check -- src/types/budget.rs refactor/artifacts/2026-04-25-isomorphic-pass-023/ledger.md`: passed
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-types-budget-pass023-test -p asupersync --lib types::budget`: passed (84 passed; 14,509 filtered)
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-pass023-check -p asupersync --lib`: passed
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-pass023-clippy-lib -p asupersync --lib -- -D warnings`: passed
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-pass023-clippy-tests -p asupersync --lib --tests -- -D warnings`: blocked by unrelated pre-existing test-target failure: `tests/database_e2e.rs:1:1` missing crate docs under `-D missing-docs`
