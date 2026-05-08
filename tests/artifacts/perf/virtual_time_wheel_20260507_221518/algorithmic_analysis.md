# Virtual Time Wheel Algorithmic Bottleneck Analysis

## Scenario
- **Target**: src/lab/virtual_time_wheel.rs
- **Workload**: 10,000 timers with 90% cancellation rate
- **Operations**: advance_to() under cancel storm conditions

## Identified Bottlenecks

### 1. cleanup_cancelled() - O(n log n) BTreeSet Creation
**Location**: src/lab/virtual_time_wheel.rs:315-317
```rust
let heap_ids: std::collections::BTreeSet<_> =
    self.heap.iter().map(|t| t.timer_id).collect();
self.cancelled.retain(|id| heap_ids.contains(id));
```

**Problem**: 
- Creates BTreeSet from ALL heap timer IDs (10K entries) 
- O(n log n) insertion cost for each cleanup
- Called during every advance_to() operation
- Under 90% cancellation = 9K cancelled entries to check

**Expected Cost**: ~10K * log(10K) = ~133K operations per cleanup

### 2. next_deadline() - Hot Loop with Heap Rebalancing
**Location**: src/lab/virtual_time_wheel.rs:214-221
```rust
while let Some(top) = self.heap.peek() {
    if self.cancelled.remove(&top.timer_id) {
        self.heap.pop();  // O(log n) heap rebalance
    } else {
        return Some(top.deadline);
    }
}
```

**Problem**:
- Scans through cancelled timers one-by-one
- Each heap.pop() triggers O(log n) rebalancing
- Under 90% cancellation, must pop ~9K cancelled timers before finding valid one
- BinaryHeap structure deteriorates under mass cancellation

**Expected Cost**: ~9K * log(10K) = ~120K operations to find next valid deadline

### 3. BinaryHeap Pop Operations During advance_to()
**Cascade Effect**: advance_to() repeatedly calls next_deadline() and processes expired timers, each requiring heap manipulation

## Hypothesis Ledger

| Hypothesis | Prediction | Evidence Source |
|------------|------------|----------------|
| cleanup_cancelled dominates CPU time | >60% of advance_to() cycles | O(n log n) BTreeSet creation |
| next_deadline heap scanning is secondary bottleneck | 20-30% of cycles | O(k log n) where k=cancelled count |
| Memory allocation churn from BTreeSet creation | High alloc/dealloc rate | BTreeSet::collect() creates temporary large structure |
| Heap fragmentation under mass cancellation | Degraded heap locality | BinaryHeap designed for balanced push/pop, not mass removal |

## Optimization Opportunities

### Priority 1: Incremental Cleanup
Replace batch BTreeSet creation with incremental cleanup:
```rust
// Instead of collecting ALL heap IDs, clean incrementally
fn cleanup_cancelled_incremental(&mut self, max_cleanup: usize) {
    let mut cleaned = 0;
    self.heap.retain(|timer| {
        if cleaned < max_cleanup && self.cancelled.contains(&timer.timer_id) {
            self.cancelled.remove(&timer.timer_id);
            cleaned += 1;
            false // remove this timer
        } else {
            true // keep this timer
        }
    });
}
```
**Expected Improvement**: O(n log n) → O(k) where k = cleanup batch size

### Priority 2: Cancelled Timer Tracking
Use separate cancelled timer heap to avoid scanning:
```rust
cancelled_heap: BinaryHeap<(u64, u64)>  // (deadline, timer_id) pairs
```
Track cancelled timers in deadline order for efficient cleanup.

### Priority 3: Lazy Cleanup Threshold
Only trigger cleanup when cancelled set exceeds threshold:
```rust
if self.cancelled.len() > self.heap.len() / 4 {
    self.cleanup_cancelled();
}
```

## Measurement Plan
1. **Baseline**: Run cancel storm benchmark, capture criterion metrics
2. **Profile**: Use perf/flamegraph to confirm CPU hotspots
3. **Scaling**: Measure p95 latency vs N=(1K, 5K, 10K, 25K) timers
4. **Memory**: Track allocation patterns during cleanup_cancelled

## Success Metrics
- **Target**: Reduce advance_to() p95 latency by >50% under 90% cancellation
- **Method**: Replace O(n log n) cleanup with O(k) incremental approach
- **Evidence**: Profiling confirms cleanup_cancelled no longer dominates CPU