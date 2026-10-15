# Isomorphism Card: LatencyAnalyzer Default State

## Change

Derive `Default` for `LatencyAnalyzer`, make `new` delegate to `Default`, and make
`with_defaults` start from `new` before assigning the two default-curve fields.

## Equivalence Contract

- Inputs covered: all `LatencyAnalyzer::new`, `LatencyAnalyzer::default`, and `LatencyAnalyzer::with_defaults` construction paths.
- Ordering preserved: yes; construction is synchronous and no annotations exist yet.
- Tie-breaking: unchanged; no analysis or map iteration logic changes.
- Error semantics: unchanged; constructors remain infallible.
- Laziness: unchanged; the annotation map is still empty at construction.
- Short-circuit eval: not applicable.
- Floating-point: unchanged; arrival/service curve values are moved into the same fields.
- RNG/hash order: unchanged; `BTreeMap` default and `BTreeMap::new()` both create an empty deterministic map.
- Observable side-effects: unchanged; no logging, tracing, I/O, or runtime interaction.
- Rust type behavior: unchanged public constructors and no generic trait-bound surface.
- Cancellation/runtime behavior: unchanged; pure synchronous initialization only.

## Proof Notes

- The removed manual `Default` returned `Self::new()`.
- The old `new` literal was exactly field-default state: empty `BTreeMap`, `None`, `None`.
- `#[derive(Default)]` produces that same field-default state for this non-generic struct.
- The old `with_defaults` literal matched `new` for the annotation map and only differed by setting `default_arrival` and `default_service` to `Some(...)`.
- Assigning those two fields after `new()` yields the same final analyzer state.

## Verification Plan

- `rustfmt --edition 2024 --check src/plan/latency_algebra.rs`
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-latency-analyzer-0937-check -p asupersync --lib`
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-latency-analyzer-0937-test -p asupersync --lib plan::latency_algebra`
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-latency-analyzer-0937-clippy -p asupersync --lib -- -D warnings`
