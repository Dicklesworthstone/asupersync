# Isomorphism Card: Region Heap Empty Constructor

## Change

Delegate `RegionHeap::new` to its existing derived `Default` implementation.

## Equivalence Contract

- Inputs covered: all empty `RegionHeap::new` construction paths.
- Ordering preserved: yes; the slots vector still starts empty and free-list state is unchanged.
- Tie-breaking: unchanged; allocation reuse order and generation logic are untouched.
- Error semantics: unchanged; constructor remains infallible.
- Laziness: unchanged; `slots` remains an empty `Vec` with no pre-allocation.
- Short-circuit eval: not applicable.
- Floating-point: not applicable.
- RNG/hash order: unchanged; no randomized collections are involved.
- Observable side-effects: unchanged; no logging, tracing, I/O, atomics, allocation of entries, or runtime interaction.
- Rust type behavior: unchanged public constructor and no new trait bounds.
- Drop/reclaim behavior: unchanged; heap entries, free-list, and stats mutation paths are untouched.

## Proof Notes

- `RegionHeap` already derives `Default`.
- Derived `Default` initializes `slots` to `Vec::new()`, `free_head` to `None`, `len` to `0`, and `stats` to `HeapStats::default()`, matching the removed literal exactly.
- Allocation, deallocation, generation, reclaim, stats, and debug behavior are untouched.

## Verification Plan

- `rustfmt --edition 2024 --check src/runtime/region_heap.rs`
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-region-heap-default-1109-check -p asupersync --lib`
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-region-heap-default-1109-test-a -p asupersync --lib runtime::region_heap::tests::region_heap_debug_default`
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-region-heap-default-1109-test-b -p asupersync --lib runtime::region_heap::tests::alloc_and_get`
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-region-heap-default-1109-clippy -p asupersync --lib -- -D warnings`
