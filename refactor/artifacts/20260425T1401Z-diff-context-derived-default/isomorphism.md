# Isomorphism Card: DiffContext Derived Default

## Change

Replace the hand-written `Default` impl for `DiffContext` with derived `Default`.

## Equivalence Contract

- Inputs covered: all `DiffContext::default()` construction paths.
- Ordering preserved: unchanged; the recent-entry map starts empty, so no diff ordering exists at construction.
- Error semantics: unchanged; construction remains infallible.
- Laziness: unchanged; construction creates an empty map only.
- Short-circuit eval: not applicable.
- Floating-point: not applicable.
- RNG/hash order: not applicable; `BTreeMap` remains deterministic and starts empty.
- Observable side-effects: unchanged; construction performs no I/O, logging, tracing, or serialization.
- Rust type behavior: `DiffContext` already implemented `Default`; this preserves the trait and its value.
- Drop/reclaim behavior: unchanged; default contexts own no ledger entries.

## Proof Notes

- The removed `Default` implementation delegates to `DiffContext::new()`.
- `DiffContext::new()` initializes `recent` to `BTreeMap::new()`.
- Derived `Default` initializes `recent` with `BTreeMap::default()`, which is an empty map.
- `DiffContext::new()` and `DiffContext::level3()` behavior remain unchanged.

## Verification Plan

- `rustfmt --edition 2024 --check franken_evidence/src/render.rs`
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-diff-context-default-1401-check -p franken-evidence --lib`
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-diff-context-default-1401-test -p franken-evidence render::tests::level3_deterministic`
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-diff-context-default-1401-clippy -p franken-evidence --lib -- -D warnings`

## Verification Results

- Passed: `rustfmt --edition 2024 --check franken_evidence/src/render.rs`.
- Passed: `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-diff-context-default-1401-check -p franken-evidence --lib`.
- Passed: `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-diff-context-default-1401-test -p franken-evidence render::tests::level3_deterministic`.
- Passed: `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-diff-context-default-1401-clippy -p franken-evidence --lib -- -D warnings`.

## Fresh-Eyes Review

- Re-read the changed struct, `new()`, and `level3()` after validation.
- Confirmed derived `Default` constructs the same empty `BTreeMap` as the old `Self::new()` delegation.
- Confirmed `level3()` still updates and reads the same `recent` map, preserving first-entry and repeated-entry diff behavior.
