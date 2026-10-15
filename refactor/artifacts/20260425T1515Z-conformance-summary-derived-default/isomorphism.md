# Isomorphism Card: Conformance Summary Derived Defaults

## Change

Replace hand-written `Default` impls for `RunSummary` and `ComparisonSummary` with derived `Default`.

## Equivalence Contract

- Inputs covered: all `RunSummary::default()` and `ComparisonSummary::default()` construction paths.
- Counter state preserved: all `usize` counters start at `0`.
- Duration state preserved: `duration_ms` starts at `0`.
- Result collections preserved: `Vec` fields start empty.
- Error semantics: unchanged; construction remains infallible.
- Laziness: unchanged; construction only initializes scalar counters and empty vectors.
- Short-circuit eval: not applicable.
- Floating-point: not applicable.
- RNG/hash order: not applicable.
- Observable side-effects: unchanged; construction performs no I/O, logging, tracing, wake registration, or time reads.
- Rust type behavior: both structs already implemented `Default`; this preserves the trait and its value.

## Proof Notes

- The removed impls delegate to `RunSummary::new()` and `ComparisonSummary::new()`.
- `RunSummary::new()` initializes five numeric fields to `0` and `results` to `Vec::new()`.
- `ComparisonSummary::new()` initializes eight numeric fields to `0` and `results` to `Vec::new()`.
- Derived `Default` initializes integer fields to `0` and `Vec` fields to an empty vector.
- The public `new()`, `all_passed`, `all_acceptable`, and `add_result` methods remain unchanged.

## Verification Plan

- `rustfmt --edition 2024 --check conformance/src/runner.rs`
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-conformance-summary-default-1515-check -p asupersync-conformance --lib`
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-conformance-summary-default-1515-test -p asupersync-conformance --lib runner::tests::run_summary_new_empty`
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-conformance-summary-default-1515-clippy -p asupersync-conformance --lib -- -D warnings`
