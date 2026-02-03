# Scheduler Hot-Path Allocation Audit + Arena Plan

**Bead:** bd-1p8g
**Status:** Completed
**Author:** TealCreek (claude-code/opus-4.5)
**Date:** 2026-02-03

## Allocation Census Summary

### Critical (P0) - Per-Poll Allocations (FIXED)

| Location | Allocation | Frequency | Fix Applied |
|----------|-----------|-----------|-------------|
| `three_lane.rs:576` | `Arc::new(ThreeLaneWaker)` | Every poll | ✅ Waker caching in TaskRecord |
| `three_lane.rs:584` | `Arc::new(CancelLaneWaker)` | Every poll | ✅ Waker caching in TaskRecord |

**Implementation:** Added `cached_waker: Option<(Waker, u8)>` and `cached_cancel_waker: Option<(Waker, u8)>` to `TaskRecord`. On each poll, if the priority hasn't changed, the cached waker is reused instead of allocating a new one. Wakers are cached back after `Poll::Pending`.

### High (P1) - Per-Completion Allocations

| Location | Allocation | Frequency | Status |
|----------|-----------|-----------|--------|
| `state.rs:1601` | `task.waiters.clone()` | Every completion | Future: SmallVec |
| `state.rs:1582` | `task_completed() -> Vec<TaskId>` | Every completion | Future: SmallVec |
| `state.rs:1635` | `orphaned.collect::<Vec<_>>()` | Every completion | Future: inline iterator |

**Plan:** Replace `Vec<TaskId>` with `SmallVec<[TaskId; 4]>` to avoid heap allocation for common cases (0-4 waiters).

### Medium (P2) - Amortized Allocations

| Location | Allocation | Frequency | Status |
|----------|-----------|-----------|--------|
| `state.rs:1159,1178` | HashMap stored_futures | Twice per pending poll | Future: Arena slot |
| `priority.rs:85` | HashSet for dedup | Per schedule/pop | Future: Bitmap |
| `priority.rs:79-83` | BinaryHeap growth | Per schedule | Future: Pre-size |

**Plan:** Replace `HashMap<TaskId, StoredTask>` with an arena-indexed slot storage to eliminate hash operations on the hot path.

### Low (P3) - Rare Allocations

| Location | Allocation | Frequency | Status |
|----------|-----------|-----------|--------|
| `global_injector.rs` | SegQueue segments | Per cross-thread inject | Acceptable |
| `priority.rs:278-363` | Heap rebuilds in cancel promotion | Per cancel promotion | Future: Lazy-delete |

## Existing Good Patterns

1. **`Arena<TaskRecord>` / `Arena<RegionRecord>`** - Task and region records already use arena allocation
2. **`steal_buffer: Vec::with_capacity(8)`** - Pre-allocated scratch buffer for work stealing
3. **`scratch_entries` / `scratch_timed`** - Pre-allocated scratch vectors for RNG tie-breaking

## Implementation Summary

### Phase 1 (Completed)
- **Waker caching:** Eliminated 2x `Arc::new` per poll via `cached_waker` and `cached_cancel_waker` fields in `TaskRecord`
- **Benefit:** Reduces allocations from 2 per poll to 1 per task lifetime (or when priority changes)

### Phase 2 (Planned)
- Replace `Vec<TaskId>` with `SmallVec<[TaskId; 4]>` in waiters and task_completed return
- Replace `HashMap<TaskId, StoredTask>` with arena-indexed slot storage
- Pre-size BinaryHeap allocations based on expected task count

### Phase 3 (Future)
- Consider lazy-delete pattern for cancel lane promotion to avoid O(n) heap rebuilds
- Evaluate bitmap-based dedup for `scheduled` set in PriorityScheduler

## Metrics

To measure allocation reduction, run with DHAT or similar allocator profiler:

```bash
# With DHAT (requires nightly)
RUSTFLAGS="-Z sanitizer=memory" cargo bench scheduler

# With custom allocator tracking
cargo test --lib scheduler -- --nocapture
```

Expected reduction: 90%+ on per-poll allocations (2 → 0 per poll for steady-state tasks).

## Files Changed

- `src/record/task.rs`: Added `cached_waker` and `cached_cancel_waker` fields
- `src/runtime/scheduler/three_lane.rs`: Waker reuse logic in `execute()`
