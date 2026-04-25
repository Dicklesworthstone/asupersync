# Isomorphism Card: Link Empty Constructors

## Change

Delegate `LinkExitBatch::new`, `LinkSet::new`, and `ExitBatch::new` to their
existing derived `Default` implementations.

## Equivalence Contract

- Inputs covered: all empty construction paths for link-exit batches, link sets, and exit-signal batches.
- Ordering preserved: yes; all structures still begin empty, so later deterministic ordering code sees identical state.
- Tie-breaking: unchanged; sort keys and action ranks are untouched.
- Error semantics: unchanged; constructors remain infallible.
- Laziness: unchanged; empty `BTreeMap` and `Vec` fields remain empty/lazily allocated.
- Short-circuit eval: not applicable.
- Floating-point: not applicable.
- RNG/hash order: unchanged; no randomized collections are involved.
- Observable side-effects: unchanged; no logging, tracing, I/O, atomics, or runtime interaction.
- Rust type behavior: unchanged public constructors and no new trait bounds.
- Cancellation/runtime behavior: unchanged; pure synchronous initialization only.

## Proof Notes

- `LinkExitBatch` already derives `Default`, which initializes `entries` to the same empty `Vec` as the removed literal.
- `LinkSet` already derives `Default`, which initializes all three `BTreeMap` indexes to the same empty values as the removed literal.
- `ExitBatch` already derives `Default`, which initializes `entries` to the same empty `Vec` as the removed literal.
- No link establishment, cleanup, exit resolution, or sorting logic changes.

## Verification Plan

- `rustfmt --edition 2024 --check src/link.rs`
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-link-default-1023-check -p asupersync --lib`
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-link-default-1023-test -p asupersync --lib link::tests::peers_of_empty`
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-link-default-1023-test-exit-batch -p asupersync --lib link::tests::exit_batch_empty`
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-link-default-1023-clippy -p asupersync --lib -- -D warnings`
