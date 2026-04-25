# Refactor Ledger: Global Queue Empty Constructor

## Candidate

- File: `src/runtime/scheduler/global_queue.rs`
- Lever: reuse already-derived default for the empty global queue constructor.
- Score: `(LOC_saved 2 * Confidence 5) / Risk 1 = 10.0`
- Decision: accepted.

## Baseline

- Source LOC before: `560 src/runtime/scheduler/global_queue.rs`
- Git state before edit: `src/runtime/scheduler/global_queue.rs` had no local modifications.
- Existing tests covering this surface: global queue tests cover default construction and push/pop behavior.

## Expected Delta

- Replace the repeated empty struct literal in `GlobalQueue::new`.
- Expected source LOC after edit: `558 src/runtime/scheduler/global_queue.rs`
- Expected source LOC reduction: `2`
- Preserve public API: `GlobalQueue::new` and derived `Default` remain.
- Preserve final empty queue state.

## Verification

- PASS `rustfmt --edition 2024 --check src/runtime/scheduler/global_queue.rs`
- PASS `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-global-queue-default-1122-check -p asupersync --lib`
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-global-queue-default-1122-test-a -p asupersync --lib runtime::scheduler::global_queue::tests::test_global_queue_default`
  - Result: 1 passed, 0 failed, 14535 filtered.
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-global-queue-default-1122-test-b -p asupersync --lib runtime::scheduler::global_queue::tests::test_global_queue_push_pop_basic`
  - Result: 1 passed, 0 failed, 14535 filtered.
- PASS `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-global-queue-default-1122-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Re-read the exact `src/runtime/scheduler/global_queue.rs` diff after verification.
- `GlobalQueue` already derives `Default`, and `crossbeam-queue 0.3.12` implements `Default` for `SegQueue<T>` by calling `SegQueue::new()`.
- No new trait impls, public APIs, scheduler ordering changes, allocation eagerness, task wakeups, tracing/logging side effects, or queue drop behavior were introduced.
