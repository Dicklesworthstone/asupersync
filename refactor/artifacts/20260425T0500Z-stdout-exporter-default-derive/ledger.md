## LOC Ledger

### Baseline
- `src/observability/otel.rs`: 3316 lines before edit.
- Existing diff for `src/observability/otel.rs`: clean before edit.

### Candidate
- Pattern: manual `Default` implementation delegates to a constructor that builds only field-default values.
- Decision: accepted.
- Rationale: `String::new()` is equivalent to `String::default()` for the sole `prefix` field.
- Fresh-eyes fix: feature-aware clippy exposed a metrics-test `needless_collect`; replaced it with fixed-size array construction so all barrier participants are still spawned before joining.
- Result: `src/observability/otel.rs` is 3306 lines after edit.
- LOC delta: -10 lines.

### Verification
- `rustfmt --edition 2024 --check src/observability/otel.rs`: passed.
- `rch exec -- cargo test -p asupersync --lib --features metrics stdout_exporter_debug_default --no-fail-fast`: 1 passed, 0 failed.
- `rch exec -- cargo test -p asupersync --lib --features metrics cardinality_enforcement_is_atomic_under_concurrency --no-fail-fast`: 1 passed, 0 failed.
- `rch exec -- cargo check -p asupersync --all-targets --features metrics`: passed.
- `rch exec -- cargo clippy -p asupersync --all-targets --features metrics -- -D warnings`: passed.

### Rejections
- `SpanId` and cancellation `TraceId`: rejected because their defaults allocate monotonic IDs.
- `Http1ListenerStats`: rejected because its default stores a non-default time getter function pointer.
