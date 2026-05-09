# Memory Ordering Optimization Audit

## Overview

This document describes the memory ordering optimization audit performed on the asupersync codebase to optimize atomic operations while maintaining correctness.

## Audit Results Summary

### Optimization Categories

#### 1. Simple Counters (SeqCst → Relaxed)

**Optimized locations:**
- `src/bin/asupersync.rs`: Test result counters
- `src/actor.rs`: Wake counting, test counters
- `src/database/sqlite.rs`: Phase counters, ID generation
- `src/record/task.rs`: Test success counters
- `src/runtime/builder.rs`: Bootstrap call counters
- `src/runtime/blocking_pool.rs`: Task tracking counters

**Rationale:** Simple statistical counters don't require strong ordering guarantees. 
The exact order of increments doesn't affect correctness, only the final count matters.

**Example:**
```rust
// Before: Strong ordering for simple counter
counter.fetch_add(1, Ordering::SeqCst);

// After: Relaxed ordering sufficient for statistics
counter.fetch_add(1, Ordering::Relaxed);
```

#### 2. Flag Operations (SeqCst → Release/Acquire)

**Optimized locations:**
- `src/transport/mod.rs`: FlagWake implementation
- `src/transport/sink.rs`: Wake flag operations  
- `src/transport/mock.rs`: Test wake flags

**Rationale:** Flag-based waker patterns only need to ensure the wake store happens-before
the subsequent wake check. Release/Acquire pairs provide sufficient synchronization.

**Example:**
```rust
// Before: Strong ordering for flag
flag.store(true, Ordering::SeqCst);
// Read with
flag.load(Ordering::Acquire); 

// After: Proper Release/Acquire pairing
flag.store(true, Ordering::Release);  // Optimized store
flag.load(Ordering::Acquire);         // Unchanged load
```

### Performance Impact

Created benchmark suite at `benches/atomic_ordering_bench.rs` to measure:
- Counter increment patterns (single/multi-threaded)
- Flag operation patterns (store/load pairs)
- Scheduler-like multi-counter workloads

**Expected improvements:**
- Relaxed counters: 10-30% faster than SeqCst on x86-64
- Release/Acquire flags: 5-15% faster than SeqCst
- Reduced memory barrier overhead in scheduler hot paths

### Files Optimized

**Statistics/Test Counters:**
- `src/bin/asupersync.rs` (5 fetch_add, 2 load operations)
- `src/actor.rs` (4 fetch_add operations)  
- `src/database/sqlite.rs` (3 fetch_add operations)
- `src/record/task.rs` (1 fetch_add operation)
- `src/runtime/builder.rs` (4 fetch_add operations)
- `src/runtime/blocking_pool.rs` (multiple load operations)

**Wake/Flag Operations:**
- `src/transport/mod.rs` (1 store operation)
- `src/transport/sink.rs` (1 store operation)
- `src/transport/mock.rs` (1 store operation)

## Memory Ordering Guidelines

### When to Use Each Ordering

#### Relaxed
- **Use for:** Simple counters, statistics, monotonic IDs
- **Pattern:** Operations where only the final value matters
- **Example:** Task completion counters, wake counts

#### Acquire/Release  
- **Use for:** Producer/consumer patterns, flag synchronization
- **Pattern:** One thread signals (Release), another waits (Acquire)
- **Example:** Waker flags, completion notifications

#### SeqCst
- **Use for:** Complex synchronization requiring global ordering
- **Pattern:** Multiple related atomic operations that must appear in consistent order
- **Example:** Scheduler state machines, complex protocols

### Optimization Principles

1. **Start with weakest correct ordering** - Use Relaxed unless synchronization is needed
2. **Pair Release with Acquire** - Don't mix with SeqCst unnecessarily  
3. **Profile hot paths first** - Focus optimization on scheduler/runtime critical sections
4. **Preserve correctness** - When in doubt, keep stronger ordering and document why

## Hot Path Analysis

### Scheduler Hot Paths (Remaining SeqCst Usage)

**Still to investigate:**
- `src/runtime/scheduler/worker.rs`: Park/unpark synchronization
- `src/runtime/state.rs`: Runtime state transitions
- Complex multi-atomic protocols

**Analysis needed:**
- Memory ordering requirements for park/unpark
- State machine synchronization patterns
- Cross-component coordination protocols

## Testing & Validation

### Benchmarking
- Created comprehensive atomic ordering benchmarks
- Measures single/multi-threaded counter performance  
- Compares Release/Acquire vs SeqCst for flags
- Tests scheduler-like workload patterns

### Correctness
- All optimizations maintain existing test coverage
- Only weakened ordering where synchronization semantics allow
- No functional behavior changes

## Future Work

1. **Complete scheduler optimization** - Analyze remaining worker.rs SeqCst usage
2. **Runtime state optimization** - Review state machine synchronization
3. **Cross-module patterns** - Audit complex multi-atomic protocols  
4. **Performance measurement** - Establish before/after benchmarks
5. **Documentation** - Document complex ordering rationale for maintenance

## References

- [Rust Nomicon - Atomics](https://doc.rust-lang.org/nomicon/atomics.html)
- [C++ Memory Ordering](https://en.cppreference.com/w/cpp/atomic/memory_order)
- [Memory Barriers on x86](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)