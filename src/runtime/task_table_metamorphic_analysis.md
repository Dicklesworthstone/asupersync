# TaskTable Metamorphic Testing Analysis

## Oracle Problem Confirmation ✓

TaskTable represents a classic oracle problem in runtime systems:
- Complex concurrent state management (arena + recycling pool + counters)
- Parallel indexing between tasks arena and stored_futures vector  
- Incremental bookkeeping with potential drift between cached and derived values
- Impossible to predict exact internal state for arbitrary operation sequences

## Metamorphic Relations Strength Matrix

| MR | Description | Fault Sensitivity (1-5) | Independence (1-5) | Cost (1-5) | Score (F×I/C) |
|----|-------------|------------------------|--------------------:|------------|---------------|
| MR1 | Operation order invariance | 3 | 4 | 3 | 4.0 |
| MR2 | Capacity monotonicity | 4 | 5 | 2 | 10.0 |
| MR3 | Live task count consistency | 5 | 4 | 2 | 10.0 |
| MR4 | Remove task cleans future | 5 | 4 | 1 | 20.0 |
| MR5 | Arena-future parallel indexing | 5 | 5 | 2 | 12.5 |
| MR6 | Pool stats conservation | 3 | 3 | 3 | 3.0 |
| MR7 | Deadline sum scaling | 4 | 3 | 2 | 6.0 |
| MR8 | Insert-remove round trip | 4 | 4 | 2 | 8.0 |
| MR9 | ID canonicalization | 5 | 5 | 1 | 25.0 |
| MR10 | Phase transition consistency | 4 | 3 | 2 | 6.0 |
| MR11 | Pool capacity bounds | 4 | 4 | 2 | 8.0 |
| MR12 | Future count accuracy | 4 | 4 | 2 | 8.0 |

**All implemented MRs have Score ≥ 3.0** ✓

## MR Categories Coverage

### Equivalence Relations (6/12)
- **MR1**: Operation order invariance (commutative operations)
- **MR3**: Live task count consistency (cached vs computed)
- **MR5**: Arena-future parallel indexing (structural invariant)  
- **MR8**: Insert-remove round trip (state restoration)
- **MR9**: ID canonicalization (identity preservation)
- **MR12**: Future count accuracy (accounting consistency)

### Additive Relations (2/12) 
- **MR2**: Capacity monotonicity (never decreases)
- **MR6**: Pool stats conservation (hits + misses)

### Multiplicative Relations (1/12)
- **MR7**: Deadline sum scaling (linear scaling property)

### Inclusive Relations (2/12)
- **MR4**: Remove task cleans future (cleanup inclusion)
- **MR11**: Pool capacity bounds (containment constraint)

### Permutative Relations (1/12)
- **MR10**: Phase transition consistency (state machine)

### Invertive Relations (0/12)
- None implemented - opportunity for extension

## Bug Classes Detected

### High-Impact Bugs (MRs 3,4,5,9)
- **Arena corruption**: MR9 catches TaskId/slot misalignment  
- **Memory leaks**: MR4 catches orphaned stored futures
- **State drift**: MR3 catches cached vs actual count divergence
- **Index corruption**: MR5 catches parallel structure violations

### Medium-Impact Bugs (MRs 2,7,8,10,11,12)
- **Capacity management**: MR2 catches shrinking arena bugs
- **Bookkeeping errors**: MR7,12 catch incremental accounting bugs
- **State machine violations**: MR10 catches invalid transitions
- **Resource bounds**: MR11 catches pool overflow

### Low-Impact Bugs (MRs 1,6)
- **Race conditions**: MR1 catches non-commutativity where expected
- **Pool statistics**: MR6 catches recycling telemetry drift

## Independence Analysis

**High Independence (Score 4-5):**
- MR2 (capacity) vs MR4 (future cleanup) - different subsystems
- MR5 (indexing) vs MR9 (canonicalization) - different invariants  
- MR3 (count consistency) vs MR11 (pool bounds) - different domains

**Medium Independence (Score 3):**
- MR6 (pool stats) vs MR7 (deadline scaling) - both bookkeeping
- MR10 (transitions) vs MR7 (deadlines) - both task metadata

**Composition Potential:**
- MR4 + MR8 = MR_composite_insert_store_remove (implemented)
- MR2 + MR3 = Capacity growth with live count tracking
- MR5 + MR9 = Full indexing integrity (arena + ID + futures)

## Property-Based Generation

**Input Strategies:**
- `arb_table_operation()`: 6 operation types with bounded parameters
- `arb_region_id()`: Valid RegionIds for ownership
- `arb_deadline()`: Optional timestamps avoiding overflow
- Operation sequences limited to 10-20 ops for performance

**Edge Cases Covered:**
- Empty tables (round-trip testing)
- Pool exhaustion (capacity bounds)
- Non-existent task operations (defensive programming)
- Phase transition sequences (state machine stress)

## Validation Plan

### Mutation Testing (Next Step)
Plant these bugs and verify MR detection:

```rust
// 1. ID canonicalization bug (should trigger MR9)
record.id = stale_id; // Don't canonicalize

// 2. Future cleanup bug (should trigger MR4)  
// Skip: self.stored_futures[slot].take()

// 3. Live count bug (should trigger MR3)
// Skip: self.live_task_count update

// 4. Capacity shrinkage bug (should trigger MR2)
self.tasks.shrink_to_fit(); // Force capacity reduction

// 5. Pool overflow bug (should trigger MR11)
pool.force_insert_beyond_capacity(record);
```

### Integration Testing
- Run full MR suite during normal task scheduler operations
- Verify MRs hold under realistic concurrent workloads  
- Test composition chains with longer operation sequences

### Performance Impact
- Metamorphic tests run in debug/test builds only
- Property-based generation bounded to reasonable input sizes
- Can be disabled via feature flags for production builds

## Next Steps

1. **Add module reference** to `task_table.rs` 
2. **Run test suite** and fix any compilation issues
3. **Implement mutation testing** to validate MR effectiveness
4. **Add more invertive relations** (encrypt-decrypt style)
5. **Extend composition testing** with longer MR chains
6. **Performance tuning** of proptest strategies