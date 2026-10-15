# Refactor Ledger: Intrusive Heap Derived Default

## Candidate

- File: `src/runtime/scheduler/intrusive_heap.rs`
- Lever: derive the existing empty-heap `Default` and reuse it from `new`.
- Score: `(LOC_saved 9 * Confidence 5) / Risk 1 = 45.0`
- Decision: accepted.

## Baseline

- Source LOC before: `771 src/runtime/scheduler/intrusive_heap.rs`
- Git state before edit: `src/runtime/scheduler/intrusive_heap.rs` had no local modifications.
- Existing tests covering this surface: intrusive heap tests cover empty construction, priority ordering, FIFO tie-breaking, mutation, removal, and metamorphic ordering behavior.

## Expected Delta

- Remove the hand-written `Default` impl that only called `new`.
- Delegate `IntrusivePriorityHeap::new` to derived `Default`.
- Expected source LOC after edit: `762 src/runtime/scheduler/intrusive_heap.rs`
- Expected source LOC reduction: `9`
- Preserve public API: `IntrusivePriorityHeap::new`, `IntrusivePriorityHeap::default`, and `with_capacity` remain.
- Preserve final empty heap state: empty `Vec<TaskId>` and `next_generation == 0`.

## Verification

- PASS `rustfmt --edition 2024 --check src/runtime/scheduler/intrusive_heap.rs`
- PASS `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-intrusive-heap-default-1136-check -p asupersync --lib`
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-intrusive-heap-default-1136-test -p asupersync --lib runtime::scheduler::intrusive_heap::tests::`
  - Result: 18 passed, 0 failed, 14522 filtered.
- PASS `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-intrusive-heap-default-1136-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Re-read the exact `src/runtime/scheduler/intrusive_heap.rs` diff after verification.
- The derived `Default` initializes `heap` to an empty `Vec<TaskId>` and `next_generation` to `0`, matching the removed `new` literal.
- No new public APIs, trait bounds, allocation eagerness, priority ordering changes, FIFO tie-breaking changes, task-record metadata mutation changes, or heap removal behavior changes were introduced.
