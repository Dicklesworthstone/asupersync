# Isomorphism Card: ResourcePressure Derived Default

## Change

Replace the hand-written `Default` impl for `ResourcePressure` with derived `Default`.

## Equivalence Contract

- Inputs covered: all `ResourcePressure::default()` construction paths.
- Ordering preserved: unchanged; the three maps start empty.
- Tie-breaking: not applicable.
- Error semantics: unchanged; construction remains infallible.
- Laziness: unchanged; empty maps still allocate no entries, and the shared `SystemPressure` is still allocated at construction.
- Short-circuit eval: not applicable.
- Floating-point: unchanged; default system headroom remains `1.0`.
- RNG/hash order: unchanged; no random state is exposed and all maps start empty.
- Observable side-effects: unchanged; construction performs no I/O, logging, tracing, wake registration, or measurement update.
- Rust type behavior: `ResourcePressure` already implemented `Default`; this preserves the trait and its value.
- Drop/reclaim behavior: unchanged; a default tracker owns empty locks, one system-pressure handle, and a zero counter.

## Proof Notes

- The removed `Default` implementation delegated to `ResourcePressure::new()`.
- `ResourcePressure::new()` initializes empty `HashMap`s behind `RwLock`s, `Arc::new(SystemPressure::new())`, and `AtomicU64::new(0)`.
- Derived `Default` initializes the locks with empty default maps, the `Arc<SystemPressure>` with `SystemPressure::default()`, and the counter with `AtomicU64::default()`.
- `SystemPressure::default()` delegates to `SystemPressure::new()`, preserving the full-headroom `1.0` initial state.

## Verification Results

- PASS `rustfmt --edition 2024 --check src/runtime/resource_monitor.rs`
- PASS `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-resource-pressure-default-1310-check -p asupersync --lib`
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-resource-pressure-default-1310-test -p asupersync --lib runtime::resource_monitor::tests::test_resource_pressure_system_pressure_matches_degradation_band`
  - `1 passed; 0 failed; 14547 filtered out`
- PASS `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-resource-pressure-default-1310-clippy -p asupersync --lib -- -D warnings`
