# Isomorphism Card: Generalized Ledger Empty Constructor

## Change

Delegate `GeneralizedLedger::new` to its existing derived `Default`
implementation.

## Equivalence Contract

- Inputs covered: all empty `GeneralizedLedger::new` construction paths.
- Ordering preserved: yes; the ledger still starts with an empty insertion-ordered `Vec`.
- Tie-breaking: unchanged; no rendering, filtering, or iteration logic changes.
- Error semantics: unchanged; constructor remains infallible.
- Laziness: unchanged; the empty `Vec` field remains empty/lazily allocated.
- Short-circuit eval: not applicable.
- Floating-point: not applicable.
- RNG/hash order: unchanged; no randomized collections are involved.
- Observable side-effects: unchanged; no logging, tracing, I/O, atomics, or runtime interaction.
- Rust type behavior: unchanged public constructor and no new trait bounds.
- Serialization behavior: unchanged; derived serde fields and stored entries are untouched.

## Proof Notes

- `GeneralizedLedger` already derives `Default`, which initializes `entries` to the same empty `Vec` as the removed literal.
- The changed constructor only reuses that existing derived implementation.
- Push, query, render, display, clone, and serialization logic are untouched.

## Verification Plan

- `rustfmt --edition 2024 --check src/evidence.rs`
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-generalized-ledger-default-1051-check -p asupersync --lib`
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-generalized-ledger-default-1051-test-a -p asupersync --lib evidence::tests::generalized_ledger_debug_clone_default`
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-generalized-ledger-default-1051-test-b -p asupersync --lib evidence::tests::generalized_ledger_push_and_query`
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-generalized-ledger-default-1051-clippy -p asupersync --lib -- -D warnings`
