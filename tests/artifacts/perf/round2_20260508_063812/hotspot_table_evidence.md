# Performance Hotspot Table - Round 2 Post-yvmiat
**Date**: 2026-05-08  
**Profiler**: perf + targeted microbenchmark  
**Workload**: Scheduler/Cx/Channel operations (500k iterations)  
**Threshold**: >5% CPU impact  

## Ranked Hotspot Table

| Rank | Location                    | Metric      | Value      | Category    | Evidence                         |
|------|-----------------------------|-------------|------------|-------------|-----------------------------------|
| 1    | build_child_task_cx         | cumulative  | 45.1%      | CPU/alloc   | scheduler_detailed.perf.data:L42  |
| 2    | two_phase_channel_ops       | cumulative  | 37.7%      | CPU/alloc   | scheduler_detailed.perf.data:L38  |
| 3    | optimized_wake_path         | cumulative  | 14.7%      | CPU         | targeted_scheduler_profile_bench  |
| 4    | malloc/free_allocations     | cumulative  | 14.34%     | alloc       | perf.data:__libc_malloc+__libc_free |
| 5    | scheduler_contention        | cumulative  | 2.5%       | lock        | multi_thread_simulation           |

## Detailed Analysis

### Rank 1: build_child_task_cx (45.1% CPU) 🎯
**File**: `src/cx/scope.rs:1456-1495`  
**Root Cause**: 8-12 Arc handle clones per spawn (lines 1464-1485)
- `state.io_driver_handle()` → Arc clone
- `state.timer_driver_handle()` → Arc clone  
- `timer_driver.clone()` → Explicit clone
- Plus 5+ additional handle clones in builder chain

**Impact**: Most expensive operation, >5× above threshold
**Optimization Opportunity**: ✅ HIGH - Cache handles or use references

### Rank 2: two_phase_channel_ops (37.7% CPU) 🎯  
**File**: `src/channel/mpsc.rs` + reserve/send pattern
**Root Cause**: Two-phase reserve/commit allocates intermediate permits
- `tx.reserve(cx).await` → SendPermit allocation
- Mutex acquisition for linearizable reserve + queue operations
- VecDeque operations under lock

**Impact**: Second largest hotspot, >7× above threshold
**Optimization Opportunity**: ✅ HIGH - Optimize permit allocation or batching

### Rank 3: optimized_wake_path (14.7% CPU)
**File**: `src/runtime/scheduler/local_queue.rs:223-240` (post-yvmiat)  
**Root Cause**: HashSet operations + queue manipulation
- Single lock acquisition (optimized from double)
- HashSet presence tracking
- VecDeque push operations

**Impact**: Post-optimization hotspot, still ~3× above threshold
**Optimization Opportunity**: 🔍 MEDIUM - Further wake path optimization

### Rank 4: malloc/free_allocations (14.34% CPU) 🎯
**File**: System allocator (indirect from Ranks 1+2)
**Root Cause**: High allocation rate from Arc cloning + permit objects
- `__libc_malloc`: 3.43% + `__libc_free`: 10.91%
- tcache operations indicate small object churn
- Direct result of Rank 1+2 allocation patterns

**Impact**: Allocation overhead from hotspots 1+2  
**Optimization Opportunity**: ✅ HIGH - Fixing Rank 1+2 reduces this

### Rank 5: scheduler_contention (2.5% CPU)
**File**: Multi-threaded scheduler operations
**Root Cause**: Mutex contention in scheduler queue operations
**Impact**: Below 5% threshold
**Optimization Opportunity**: ❌ SKIP - Below threshold

## Hypothesis Ledger

```
arc_clone_overhead      : SUPPORTS  — build_child_task_cx dominates at 45.1%
channel_reserve_cost    : SUPPORTS  — two_phase_ops at 37.7%  
wake_path_still_costly  : SUPPORTS  — 14.7% post-optimization
allocation_pressure     : SUPPORTS  — malloc/free 14.34% correlates with Arc+permit allocs
lock_contention        : REJECTS   — scheduler contention only 2.5%
```

## Primary Optimization Targets (>5% Impact)

1. **build_child_task_cx Arc handle reduction** (45.1% → estimated 15-20%)
2. **channel reserve/commit optimization** (37.7% → estimated 10-15%)  
3. **Further wake path refinement** (14.7% → estimated 5-8%)

**Combined Expected Impact**: 60-80% total CPU reduction in targeted functions
**Meets >5% threshold**: ✅ All top 3 candidates well above 5%