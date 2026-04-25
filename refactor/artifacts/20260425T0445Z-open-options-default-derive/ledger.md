## LOC Ledger

### Baseline
- `src/fs/open_options.rs`: 285 lines before edit.
- Existing diff for `src/fs/open_options.rs`: clean before edit.

### Candidate
- Pattern: manual `Default` implementation delegates to type-default field values.
- Decision: accepted.
- Rationale: all fields have Rust defaults identical to the explicit constructor fields.
- Result: `src/fs/open_options.rs` is 268 lines after edit.
- LOC delta: -17 lines.

### Verification
- `rustfmt --edition 2024 --check src/fs/open_options.rs`: passed.
- `rch exec -- cargo test -p asupersync --lib fs::open_options --no-fail-fast`: 6 passed, 0 failed.
- `rch exec -- cargo check -p asupersync --all-targets`: passed.
- `rch exec -- cargo clippy -p asupersync --all-targets -- -D warnings`: passed.

### Rejections
- `src/time/intrusive_wheel.rs::TimerNode`: rejected because `new()` initializes `deadline` with `Instant::now()`, not a field default.
- Generic CRDT defaults: rejected because deriving would add public `T: Default` bounds and break API equivalence.
