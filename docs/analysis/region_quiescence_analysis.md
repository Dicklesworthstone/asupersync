# Region Close → Quiescence Invariant Analysis

**Bead ID:** asupersync-doewj2  
**Date:** 2026-04-28  
**Scope:** src/runtime/region_table.rs + src/record/region.rs region close logic  

## Executive Summary

**FINDING: NO CRITICAL INVARIANT VIOLATIONS DETECTED**

After analyzing all code paths that decrement `pending_obligations` and their interaction with `complete_close()`, the region quiescence invariant appears correctly implemented. The specific concerns raised are either **mitigated by design** or **do not constitute actual vulnerabilities**.

---

## Detailed Analysis

### 1. ABA Problem on Pending Counter

**CHECKED: No ABA vulnerability detected**

The `pending_obligations` counter uses proper write-lock synchronization:

```rust
// resolve_obligation() - Lines 686-706 in record/region.rs
pub fn resolve_obligation(&self) {
    let mut inner = self.inner.write();  // EXCLUSIVE LOCK
    match inner.pending_obligations.checked_sub(1) {
        Some(n) => inner.pending_obligations = n,
        None => {
            // Saturation + debug detection
            self.double_resolve_count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// complete_close() - Lines 936-972 in record/region.rs  
pub fn complete_close(&self) -> bool {
    let mut inner = self.inner.write();  // SAME EXCLUSIVE LOCK
    if !(inner.pending_obligations == 0 && /* other conditions */) {
        return false;
    }
    // Close logic continues under lock...
}
```

**WHY NO ABA:**
- Both decrement (`resolve_obligation`) and check (`complete_close`) acquire the **same write lock** (`inner.write()`)
- Write locks are **exclusive** - no concurrent access possible
- The `pending_obligations` field is **only modified under this lock**
- **sequencing guarantee**: Any `resolve_obligation` that decrements to 0 will be observed by `complete_close` when it acquires the same lock

### 2. Race Between Cancel-Finalize and Close-Poll

**CHECKED: No race condition vulnerability detected**

The state transition protocol enforces proper sequencing:

```rust
// State transitions are atomic and ordered:
// Open → Closing (begin_close) → Draining → Finalizing (begin_finalize) → Closed (complete_close)

pub fn complete_close(&self) -> bool {
    let mut inner = self.inner.write();
    
    // CRITICAL: This check happens UNDER LOCK
    if !(inner.children.is_empty()
        && inner.tasks.is_empty()  
        && inner.pending_obligations == 0  // ← Atomic observation under lock
        && inner.finalizers.is_empty()) 
    {
        return false;  // Cannot close - live work remains
    }
    
    // Atomic state transition to Closed
    let transitioned = self.state.transition(RegionState::Finalizing, RegionState::Closed);
    // ... rest of close logic
}
```

**WHY NO RACE:**
- **Write lock serialization**: The live work check and state transition happen atomically under `inner.write()`
- **State machine invariant**: `complete_close()` only succeeds from `Finalizing` state 
- **Cancel safety**: Cancellation sets state to `Closing` but doesn't affect the pending count directly
- **Finalize ordering**: `begin_finalize()` must complete before `complete_close()` can run
- **No TOCTOU**: Check and transition are in the same critical section

### 3. Missing Memory Fence Analysis

**CHECKED: Memory ordering is correctly implemented**

The atomic state operations use appropriate ordering:

```rust
// AtomicRegionState implementation - Lines 284-302 in record/region.rs
pub fn load(&self) -> RegionState {
    RegionState::from_u8(self.inner.load(Ordering::Acquire))  // ← ACQUIRE
}

pub fn store(&self, state: RegionState) {  
    self.inner.store(state.as_u8(), Ordering::Release);      // ← RELEASE
}

pub fn transition(&self, from: RegionState, to: RegionState) -> bool {
    self.inner.compare_exchange(
        from.as_u8(), to.as_u8(),
        Ordering::AcqRel,    // ← ACQUIRE-RELEASE on success
        Ordering::Acquire    // ← ACQUIRE on failure  
    ).is_ok()
}
```

**Memory ordering analysis:**
- **Acquire on load**: Ensures all writes by the releasing thread are visible
- **Release on store**: Ensures all prior writes are visible to acquiring threads
- **AcqRel on CAS**: Provides full bidirectional synchronization
- **RwLock provides implicit memory barriers**: Write lock acquisition acts as an acquire fence, release acts as a release fence

**No additional memory fences needed** because:
1. All critical `pending_obligations` access is under RwLock (provides full memory barriers)
2. State transitions use proper acquire-release ordering
3. The combination provides sufficient synchronization for the quiescence invariant

---

## Code Path Analysis

### All paths that decrement `pending_obligations`:

1. **`resolve_obligation()`** (Lines 686-706)
   - **Synchronization**: `inner.write()` exclusive lock
   - **Safety**: Uses `checked_sub()` with saturation to prevent underflow
   - **Detection**: Double-resolve detection via `double_resolve_count` counter

### Critical observation point:

1. **`complete_close()`** (Lines 936-972)  
   - **Synchronization**: Same `inner.write()` exclusive lock as decrement paths
   - **Invariant check**: `inner.pending_obligations == 0` under lock
   - **Atomicity**: Check + state transition in single critical section

### State transition verification:

- **`begin_close()`**: Open → Closing (atomic CAS)
- **`begin_finalize()`**: Closing/Draining → Finalizing (atomic CAS)  
- **`complete_close()`**: Finalizing → Closed (atomic CAS + live work check)

**Invariant preservation:** A region cannot transition to `Closed` while `pending_obligations > 0` because the check happens under the same lock that protects the counter.

---

## Specific Vulnerability Scenarios Examined

### Scenario 1: Concurrent resolve + close
```
Thread A: resolve_obligation() decrements to 0
Thread B: complete_close() checks pending count
RESULT: Write lock serialization prevents race
```

### Scenario 2: Cancel during close
```
Thread A: begin_close() sets Closing state  
Thread B: resolve_obligation() runs
Thread C: complete_close() checks quiescence
RESULT: State machine prevents premature closure; finalize must complete first
```

### Scenario 3: Double-resolve ABA
```
Thread A: resolve_obligation() when count=1 → sets to 0
Thread B: resolve_obligation() when count=0 → saturates, increments error counter  
Thread C: complete_close() observes count=0
RESULT: Safe - double-resolve is detected but doesn't break quiescence invariant
```

---

## Implementation Strengths

1. **Exclusive locking**: All `pending_obligations` mutations under same write lock
2. **Atomic state transitions**: State changes use proper memory ordering  
3. **Saturation arithmetic**: `checked_sub()` prevents underflow wraparound
4. **Double-resolve detection**: Debug builds panic, release builds count violations
5. **State machine enforcement**: Invalid transitions rejected by atomic CAS
6. **Proper memory ordering**: Acquire-release semantics on state operations

---

## Recommendations

1. **NONE REQUIRED** - The implementation is secure
2. **Optional enhancement**: Add tracing to `complete_close()` to log when close is blocked by live work
3. **Optional hardening**: Consider adding memory barriers around `close_notify` waker operations (currently relies on parking_lot's internal barriers)

---

## Conclusion

The region close → quiescence invariant is **correctly implemented**. The specific concerns (ABA, cancel-finalize race, missing memory fences) are **mitigated by the existing synchronization design**. No code changes required.

**Status**: INVARIANT VERIFIED ✓