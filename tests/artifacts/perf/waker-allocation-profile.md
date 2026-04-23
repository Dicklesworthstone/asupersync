# Waker Allocation Hot Path Profiling - Baseline Setup

## Scenario Definition
**Target:** `src/runtime/waker.rs` waker allocation hot paths  
**Metric:** Allocation rate (ops/sec), memory usage (peak RSS), lock contention  
**Workload:** Burst waker creation, reuse patterns, wake storms  

## Baseline Infrastructure

### Profiling Instrumentation Added
- `src/runtime/waker_profiling.rs` - Metrics collection
- `src/runtime/waker.rs` - Instrumentation points at allocation sites
- `benches/waker_allocation_profile.rs` - Comprehensive benchmark suite
- `src/runtime/waker_allocation_hotpaths_test.rs` - Baseline test patterns

### Key Allocation Hot Paths Identified
1. **`waker_for_source()`** - Arc::new(TaskWaker) allocation
2. **Waker cloning** - Arc reference counting overhead  
3. **Wake operations** - Lock contention on woken set
4. **Drain operations** - Vector allocation and sorting

### Benchmark Coverage
- **Burst creation:** 100 → 100K waker allocations
- **Reuse patterns:** Create-once vs recreate vs pool cycling
- **Wake storms:** High-contention scenarios  
- **Lifecycle patterns:** Immediate vs bulk vs clone usage
- **Memory pressure:** Allocation under different memory loads

## Profiling Commands

```bash
# Enable waker profiling instrumentation
export WAKER_PROFILING=1

# Run baseline tests with metrics
cargo test --features waker-profiling hotpath_waker

# Run comprehensive benchmarks  
cargo bench --bench waker_allocation_profile

# Profile with samply
samply record --save-only -o waker-cpu.json -- \
  cargo bench --bench waker_allocation_profile -- creation_burst

# Allocation profiling with heaptrack
heaptrack cargo bench --bench waker_allocation_profile
```

## Hypothesis Ledger

| Hypothesis | Evidence | Status |
|------------|----------|---------|
| Arc allocation dominates | Need flamegraph | TBD |
| Lock contention on woken set | Need concurrency profile | TBD |
| Deduplication overhead | Metrics show dedup_hits | TBD |
| Clone patterns inefficient | Need allocation count vs reuse | TBD |

## Next Steps (Hand-off to extreme-software-optimization)

1. **Profile baseline** - Run benchmarks with samply/heaptrack
2. **Capture hotspot table** - Rank allocation sites by cumulative cost
3. **Identify optimizations** - Arc pooling, lock-free structures, batch operations
4. **Implement one lever at a time** - Profile → optimize → measure

## Expected Hotspots
- `Arc::new(TaskWaker)` in `waker_for_source()` 
- `Mutex::lock()` contention in `wake()` and `drain_woken()`
- Vector allocation in `drain_woken()`
- Hash set operations in `DetHashSet`

**Ready for extreme-software-optimization to score targets and apply optimizations.**