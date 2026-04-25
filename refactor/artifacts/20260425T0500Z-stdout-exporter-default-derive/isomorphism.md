## Change: derive `StdoutExporter` default

### Equivalence Contract
- Inputs covered: `StdoutExporter::new()`, `StdoutExporter::default()`, and metric exporter construction callsites.
- Ordering preserved: yes; construction has no iteration or side effects.
- Tie-breaking: N/A.
- Error semantics: unchanged; construction is infallible before and after.
- Laziness: N/A.
- Short-circuit eval: N/A.
- Floating-point: N/A.
- RNG / hash order: N/A.
- Observable side-effects: unchanged; stdout output only happens in `export()`, not during construction.
- Type narrowing: N/A.
- Rerender behavior: N/A.

### Proof
- The sole field is `prefix: String`.
- `String::default()` and `String::new()` both construct an empty string.
- `StdoutExporter::new()` now delegates to the derived `Default`, so constructor semantics remain identical.

### Fresh-Eyes Fix
- Feature-aware clippy exposed a pre-existing `needless_collect` lint in the metrics concurrency test.
- Replaced `collect::<Vec<_>>()` with `let handles: [_; 8] = std::array::from_fn(...)`.
- This preserves the important behavior: all eight worker threads are spawned before any handle is joined, so the barrier can release.

### Candidate Score
- LOC_saved: 1
- Confidence: 5
- Risk: 1
- Score: 5.0

### Verification
- [x] `rustfmt --edition 2024 --check src/observability/otel.rs`
- [x] `rch exec -- cargo test -p asupersync --lib --features metrics stdout_exporter_debug_default --no-fail-fast`
- [x] `rch exec -- cargo test -p asupersync --lib --features metrics cardinality_enforcement_is_atomic_under_concurrency --no-fail-fast`
- [x] `rch exec -- cargo check -p asupersync --all-targets --features metrics`
- [x] `rch exec -- cargo clippy -p asupersync --all-targets --features metrics -- -D warnings`
- [x] LOC delta recorded in `ledger.md`
