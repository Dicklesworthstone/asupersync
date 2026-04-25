# Refactor Ledger: Region Heap Empty Constructor

## Candidate

- File: `src/runtime/region_heap.rs`
- Lever: reuse already-derived default for the empty region heap constructor.
- Score: `(LOC_saved 2 * Confidence 5) / Risk 1 = 10.0`
- Decision: accepted.

## Baseline

- Source LOC before: `905 src/runtime/region_heap.rs`
- Git state before edit: `src/runtime/region_heap.rs` had no local modifications.
- Existing tests covering this surface: region heap tests cover default/debug and allocation behavior.

## Expected Delta

- Replace the repeated empty struct literal in `RegionHeap::new`.
- Expected source LOC after edit: `900 src/runtime/region_heap.rs`
- Expected source LOC reduction: `5`
- Preserve public API: `RegionHeap::new` and derived `Default` remain.
- Preserve final empty heap state.

## Verification

- PASS `rustfmt --edition 2024 --check src/runtime/region_heap.rs`
- PASS `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-region-heap-default-1109-check -p asupersync --lib`
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-region-heap-default-1109-test-a -p asupersync --lib runtime::region_heap::tests::region_heap_debug_default`
  - Result: 1 passed, 0 failed, 14535 filtered.
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-region-heap-default-1109-test-b -p asupersync --lib runtime::region_heap::tests::alloc_and_get`
  - Result: 1 passed, 0 failed, 14535 filtered.
- PASS `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-region-heap-default-1109-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Re-read the exact `src/runtime/region_heap.rs` diff after verification.
- `RegionHeap` already derives `Default`; derived initialization covers the same empty `Vec`, `None`, `0`, and `HeapStats::default()` values as the removed literal.
- No new trait impls, bounds, public APIs, side effects, allocation pre-sizing, free-list state, generation behavior, stats behavior, drop/reclaim behavior, or debug formatting behavior were introduced.
