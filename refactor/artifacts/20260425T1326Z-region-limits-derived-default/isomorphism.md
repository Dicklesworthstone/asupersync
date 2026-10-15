# Isomorphism Card: RegionLimits Derived Default

## Change

Replace the hand-written `Default` impl for `RegionLimits` with derived `Default`.

## Equivalence Contract

- Inputs covered: all `RegionLimits::default()` construction paths.
- Ordering preserved: unchanged; no collection or iteration order is involved.
- Tie-breaking: not applicable.
- Error semantics: unchanged; default construction remains infallible.
- Laziness: unchanged; construction still only initializes five `Option` fields.
- Short-circuit eval: not applicable.
- Floating-point: not applicable.
- RNG/hash order: not applicable.
- Observable side-effects: unchanged; construction performs no I/O, logging, tracing, locking, wake registration, or allocation.
- Rust type behavior: `RegionLimits` already implemented `Default`; this preserves the trait and its value.
- Drop/reclaim behavior: unchanged; default limits own no curve budget.

## Proof Notes

- The removed `Default` implementation returned `RegionLimits::UNLIMITED`.
- `RegionLimits::UNLIMITED` sets `max_children`, `max_tasks`, `max_obligations`, `max_heap_bytes`, and `curve_budget` to `None`.
- Derived `Default` for `RegionLimits` initializes each `Option` field to `None`, producing the same value.
- `RegionLimits::unlimited()` still returns the explicit `UNLIMITED` associated constant.

## Verification Results

- PASS `rustfmt --edition 2024 --check src/record/region.rs`
- PASS `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-region-limits-default-1326-check -p asupersync --lib`
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-region-limits-default-1326-test -p asupersync --lib record::region::tests::region_limits_debug_clone_default_eq`
  - `1 passed; 0 failed; 14547 filtered out`
- PASS `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-region-limits-default-1326-clippy -p asupersync --lib -- -D warnings`
