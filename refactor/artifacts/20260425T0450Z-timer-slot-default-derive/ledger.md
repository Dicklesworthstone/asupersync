## LOC Ledger

### Baseline
- `src/time/intrusive_wheel.rs`: 1898 lines before edit.
- Existing diff for `src/time/intrusive_wheel.rs`: clean before edit.

### Candidate
- Pattern: private manual `Default` implementation delegates to type-default field values.
- Decision: accepted.
- Rationale: all `TimerSlot` fields have defaults identical to `TimerSlot::new()`, while `new()` must remain explicit because it is `const fn`.
- Result: `src/time/intrusive_wheel.rs` is 1892 lines after edit.
- LOC delta: -6 lines.

### Verification
- `rustfmt --edition 2024 --check src/time/intrusive_wheel.rs`: passed.
- `rch exec -- cargo test -p asupersync --lib time::intrusive_wheel --no-fail-fast`: 17 passed, 0 failed.
- `rch exec -- cargo check -p asupersync --all-targets`: passed.
- `rch exec -- cargo clippy -p asupersync --all-targets -- -D warnings`: passed.

### Rejections
- `TimerNode`: rejected because `new()` initializes `deadline` with `Instant::now()`, not a field default.
- `HierarchicalTimerWheel`: rejected because `new()` seeds nonzero hierarchical level resolutions and `Instant::now()`.
