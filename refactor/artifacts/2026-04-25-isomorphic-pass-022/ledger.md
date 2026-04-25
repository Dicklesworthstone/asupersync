# Isomorphic Simplification Pass 022

## Candidate

- File: `src/util/cache.rs`
- Lever: derive `Default` for `CachePadded<T>` instead of spelling the single-field implementation manually.
- Score: `(LOC_saved 7 * confidence 5) / risk 1 = 35.0`

## Isomorphism Proof

- `CachePadded<T>` has one field: `value: T`.
- The removed manual impl required `T: Default` and constructed `Self::new(T::default())`, which is `Self { value: T::default() }`.
- Derived `Default` for a single-field struct requires the same `T: Default` bound and initializes `value` with `T::default()`.
- `repr(C, align(64))`, `new`, `into_inner`, deref, equality, and layout behavior remain unchanged.

## Metrics

- Source LOC before: 177
- Source LOC after: 170
- Source LOC delta: -7
- Diff numstat: `1 insertion, 8 deletions`

## Validation

- `rustfmt --edition 2024 --check src/util/cache.rs`: passed
- `git diff --check -- src/util/cache.rs refactor/artifacts/2026-04-25-isomorphic-pass-022/ledger.md`: passed
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-util-cache-pass022-test -p asupersync --lib util::cache`: passed (8 passed; 14,584 filtered)
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-pass022-check -p asupersync --lib`: passed
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-pass022-clippy-tests -p asupersync --lib --tests -- -D warnings`: passed
