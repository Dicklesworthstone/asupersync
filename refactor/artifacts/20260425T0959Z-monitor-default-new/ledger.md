# Refactor Ledger: Monitor Empty Constructors

## Candidate

- File: `src/monitor.rs`
- Lever: reuse already-derived defaults for empty monitor collection constructors.
- Score: `(LOC_saved 2 * Confidence 5) / Risk 1 = 10.0`
- Decision: accepted.

## Baseline

- Source LOC before: `1427 src/monitor.rs`
- Git state before edit: `src/monitor.rs` had no local modifications.
- Existing tests covering this surface: `monitor` module tests cover monitor-set and down-batch behavior.

## Expected Delta

- Replace repeated empty collection literals in `MonitorSet::new` and `DownBatch::new`.
- Source LOC after edit: `1421 src/monitor.rs`
- Source LOC reduction: `6`
- Preserve public APIs: both `new` constructors and derived `Default` implementations remain.
- Preserve final empty collection state.

## Verification

- PASS `rustfmt --edition 2024 --check src/monitor.rs`
- PASS `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-monitor-default-0959-check -p asupersync --lib`
- BASELINE BLOCKER `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-monitor-default-0959-test -p asupersync --lib monitor`
  - Result: 177 passed, 2 failed, 14354 filtered.
  - Unrelated failures outside the edited file:
    - `observability::cancellation_debt_monitor::tests::test_emergency_cleanup` at `src/observability/cancellation_debt_monitor.rs:866:9`, assertion `cleaned > 0`.
    - `supervision::tests::restart_tracker_aligns_default_storm_monitor_with_threshold` at `src/supervision.rs:8739:9`, default storm-monitor threshold assertion.
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-monitor-default-0959-narrow-a -p asupersync --lib monitor::tests::watchers_of_empty`
  - Result: 1 passed, 0 failed, 14532 filtered.
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-monitor-default-0959-narrow-b -p asupersync --lib monitor::tests::down_batch_empty`
  - Result: 1 passed, 0 failed, 14532 filtered.
- PASS `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-monitor-default-0959-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Re-read the exact `src/monitor.rs` diff after verification.
- `MonitorSet` already derives `Default`; derived initialization covers the same three empty `BTreeMap` fields as the removed literal.
- `DownBatch` already derives `Default`; derived initialization covers the same empty `Vec` field as the removed literal.
- No new trait impls, bounds, public APIs, side effects, allocation timing differences beyond equivalent empty collection construction, or ordering changes were introduced.
