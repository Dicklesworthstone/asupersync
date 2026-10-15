# Isomorphism Card: Intrusive Heap Derived Default

## Change

Replace the hand-written `Default` impl for `IntrusivePriorityHeap` with derived `Default`, and delegate `new` to that derived implementation.

## Equivalence Contract

- Inputs covered: all empty `IntrusivePriorityHeap::new` and `IntrusivePriorityHeap::default` construction paths.
- Ordering preserved: yes; heap ordering, sift operations, and generation comparisons are untouched.
- Tie-breaking: unchanged; `next_generation` still starts at `0`, so FIFO ties among equal priorities start identically.
- Error semantics: unchanged; constructors remain infallible.
- Laziness: unchanged; the heap vector remains an empty `Vec` with no pre-allocation.
- Short-circuit eval: not applicable.
- Floating-point: not applicable.
- RNG/hash order: unchanged; no randomized collections are involved.
- Observable side-effects: unchanged; construction performs no logging, tracing, I/O, atomics, task mutation, or scheduler interaction.
- Rust type behavior: unchanged public `Default` implementation and unchanged public constructor; no generic bounds are introduced.
- Drop/reclaim behavior: unchanged; no heap entries or task-record metadata exist in the empty state.

## Proof Notes

- The removed manual `Default` implementation returned `Self::new()`.
- The removed `new` literal initialized `heap` with `Vec::new()` and `next_generation` with `0`.
- Derived `Default` for this concrete struct initializes `Vec<TaskId>` with `Vec::default()` and `u64` with `0`, matching the removed literal exactly.
- `with_capacity`, push/pop/remove/clear, task metadata mutation, and heap ordering logic are untouched.

## Verification Plan

- `rustfmt --edition 2024 --check src/runtime/scheduler/intrusive_heap.rs`
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-intrusive-heap-default-1136-check -p asupersync --lib`
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-intrusive-heap-default-1136-test -p asupersync --lib runtime::scheduler::intrusive_heap::tests::`
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-intrusive-heap-default-1136-clippy -p asupersync --lib -- -D warnings`
