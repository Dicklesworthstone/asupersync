# Isomorphism Card: Monitor Empty Constructors

## Change

Delegate `MonitorSet::new` and `DownBatch::new` to their existing derived
`Default` implementations.

## Equivalence Contract

- Inputs covered: all `MonitorSet::new` and `DownBatch::new` construction paths.
- Ordering preserved: yes; both constructors still create empty ordered collections.
- Tie-breaking: unchanged; no sorting or notification delivery logic changes.
- Error semantics: unchanged; constructors remain infallible.
- Laziness: unchanged; empty `BTreeMap` and `Vec` allocations remain lazy/empty.
- Short-circuit eval: not applicable.
- Floating-point: not applicable.
- RNG/hash order: unchanged; no randomized collections are involved.
- Observable side-effects: unchanged; no logging, tracing, I/O, atomics, or runtime interaction.
- Rust type behavior: unchanged public constructors and no new trait bounds.
- Cancellation/runtime behavior: unchanged; pure synchronous initialization only.

## Proof Notes

- `MonitorSet` already derives `Default`, which initializes each `BTreeMap` field to the same empty value as the removed literal.
- `DownBatch` already derives `Default`, which initializes `entries` to the same empty `Vec` as the removed literal.
- The changed constructors only reuse those existing derived implementations.

## Verification Plan

- `rustfmt --edition 2024 --check src/monitor.rs`
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-monitor-default-0959-check -p asupersync --lib`
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-monitor-default-0959-test -p asupersync --lib monitor`
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-monitor-default-0959-clippy -p asupersync --lib -- -D warnings`
