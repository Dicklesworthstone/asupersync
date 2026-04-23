# Metamorphic Testing Analysis: borrow_and_update After Shutdown

## Oracle Problem Diagnosis

**Domain:** Watch channel `borrow_and_update()` behavior after sender shutdown  
**Oracle Problem:** Cannot compute exact "correct" output because:

1. **Timing uncertainty:** The relative timing of `borrow_and_update()` calls vs sender drop is non-deterministic
2. **Multiple receivers:** Different receivers may call at different times with different expectations  
3. **Version semantics:** What `seen_version` should be updated to in shutdown state is not immediately obvious
4. **No reference implementation:** We are implementing the specification

**Solution:** Metamorphic testing - verify how outputs relate under transformations instead of testing absolute correctness.

## MR Strength Matrix

| MR | Description | Fault Sensitivity (1-5) | Independence (1-5) | Cost (1-5) | Score | Bug Classes Detected |
|----|-----------|-----------------------|-------------------|------------|-------|-------------------|
| MR1 | Value equivalence across calls | 4 | 5 | 1 | 20.0 | Value corruption, inconsistent final state retention |
| MR2 | Version monotonicity | 4 | 4 | 1 | 16.0 | Version regression, rollback bugs |  
| MR3 | Receiver isolation | 4 | 4 | 2 | 8.0 | Cross-receiver interference, shared state corruption |
| MR4 | State consistency (borrow vs borrow_and_update) | 3 | 3 | 1 | 9.0 | Method inconsistency, update side-effects |
| MR5 | Timing independence | 3 | 3 | 2 | 4.5 | Race conditions, timing dependencies |
| MR6 | Closure invariant preservation | 2 | 2 | 1 | 4.0 | Channel state corruption, lifecycle violations |

**Analysis:** All MRs score ≥ 4.0 (well above the 2.0 threshold), indicating strong fault detection capability with good independence.

## The Six Metamorphic Relations

### MR1: Equivalence Pattern
**Property:** `borrow_and_update()` after shutdown always returns the same value  
**Transformation:** Multiple calls to the same method  
**Relation:** `f(shutdown_then_call1) = f(shutdown_then_call2) = f(shutdown_then_callN)`  
**Detects:** Value corruption bugs, inconsistent state retention

### MR2: Additive Pattern (Version Monotonicity)
**Property:** `seen_version` never decreases, even after shutdown  
**Transformation:** Sequential `borrow_and_update()` calls  
**Relation:** `version(call_n+1) >= version(call_n)` for all n  
**Detects:** Version rollback bugs, counter underflow

### MR3: Permutative Pattern (Receiver Isolation)  
**Property:** Multiple receivers don't interfere with each other  
**Transformation:** Permute order of receiver operations  
**Relation:** Results independent of call order across receivers  
**Detects:** Cross-receiver interference, shared state corruption

### MR4: Equivalence Pattern (State Consistency)
**Property:** `borrow_and_update()` and `borrow()` return same value after shutdown  
**Transformation:** Method substitution  
**Relation:** `f(borrow_and_update)` value == `f(borrow)` value  
**Detects:** Method inconsistency, unintended side-effects

### MR5: Invertive Pattern (Timing Independence)
**Property:** Result shouldn't depend on exact shutdown timing  
**Transformation:** Vary shutdown timing relative to call  
**Relation:** `f(shutdown_before_call) == f(shutdown_concurrent_with_call)`  
**Detects:** Race conditions, timing-dependent bugs

### MR6: Inclusive Pattern (Closure Invariant)
**Property:** Channel closure state preserved across calls  
**Transformation:** Multiple `borrow_and_update()` calls  
**Relation:** `is_closed()` remains true throughout  
**Detects:** Channel state corruption, lifecycle violations

## Composition Effects

**Composite MR:** Multi-receiver + Timing + State Consistency  
Tests interaction between MR1, MR3, MR4, and MR5 simultaneously.  
**Power Multiplication:** Individual MRs might miss bugs that only manifest under specific combinations of conditions.

## Mutation Testing Validation

Planted mutations to verify MR fault sensitivity:

1. **Corrupted Value Bug:** Return wrong value (999) after shutdown → Caught by MR1
2. **Version Regression Bug:** Reset `seen_version` to 0 after shutdown → Caught by MR2  
3. **Receiver Interference Bug:** Use global counter to corrupt values → Caught by MR3
4. **State Inconsistency Bug:** Make `borrow()` and `borrow_and_update()` diverge → Caught by MR4
5. **Timing Dependency Bug:** Return different values based on shutdown timing → Caught by MR5
6. **Closure Violation Bug:** Make `is_closed()` return false after shutdown → Caught by MR6

**Coverage Result:** All planted mutations caught by at least one MR (100% coverage).

## Implementation Strategy

### Test Organization
- **Primary module:** `watch_borrow_update_shutdown_metamorphic_tests.rs`
- **Validation module:** `watch_borrow_update_mutation_validation.rs`  
- **Integration:** Included via `#[path]` directives in `watch.rs`

### Property-Based Input Generation
- Uses varied channel initial values (0, 42, 100, 200, etc.)
- Tests with multiple receivers (1-3 per scenario)  
- Applies concurrent shutdown timing via `thread::spawn` and `thread::sleep`

### Test Execution
```bash
cargo test --lib channel::watch::watch_borrow_update_shutdown_metamorphic_tests
cargo test --lib channel::watch::watch_borrow_update_mutation_validation
```

## Relationship to Existing Tests

**Complements existing tests:** The watch module already has 60+ conventional unit tests that verify specific behaviors. These metamorphic tests fill the gap for:

1. **Complex timing scenarios** that are hard to test deterministically
2. **Multi-receiver interactions** under shutdown conditions  
3. **Cross-method consistency** that conventional tests might miss
4. **Emergent behaviors** that arise from combinations of operations

**Does not replace:** Conventional tests for basic functionality, error cases, and well-defined behaviors where oracles exist.

## Expected Bug Classes

Based on the MR design, this suite should catch:

- **Value corruption** during shutdown state transitions
- **Version management bugs** in edge cases  
- **Receiver interference** under concurrent access
- **Method inconsistencies** between `borrow()` and `borrow_and_update()`
- **Race conditions** in shutdown handling
- **State lifecycle violations** during channel closure

## Integration with CI

These tests run as part of the standard test suite and will catch regressions in shutdown-related behavior that might not be visible to conventional testing approaches.