## LOC Ledger

### Baseline
- `src/database/pool.rs`: 2447 lines before edit.
- Existing diff for `src/database/pool.rs`: clean before edit.

### Candidate
- Pattern: private manual `Default` implementation initializes all atomic counters to zero.
- Decision: accepted.
- Rationale: `AtomicU64::default()` is equivalent to `AtomicU64::new(0)` for each field.
- Result: `src/database/pool.rs` is 2436 lines after edit.
- LOC delta: -11 lines.

### Verification
- `rustfmt --edition 2024 --check src/database/pool.rs`: passed.
- `rch exec -- cargo check -p asupersync --lib`: passed.
- `rch exec -- cargo clippy -p asupersync --lib -- -D warnings`: passed.

### Blocked Broader Gates
- `rch exec -- cargo test -p asupersync --lib database::pool --no-fail-fast`: compiled but matched 0 tests.
- `rch exec -- cargo test -p asupersync --lib pool_new --no-fail-fast`: cancelled after a stale worker artifact-lock wait.
- `cargo check -p asupersync --all-targets`: blocked by unrelated dirty `src/cancel/protocol_validator_test_suite.rs` `new_for_test` type errors at lines 593, 610, and 632.

### Rejections
- `LogCollector`: rejected because `Default` intentionally uses capacity `1000`, not field defaults.
- `MultipartForm`: rejected because `Default` uses a deterministic non-empty boundary.
