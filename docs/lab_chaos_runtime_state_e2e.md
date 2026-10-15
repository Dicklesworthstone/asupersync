# Lab Chaos ↔ Runtime State E2E Integration

This document describes the comprehensive e2e test implementation for lab/chaos ↔ runtime/state integration, focusing on verification that lab chaos injection preserves the core region close=quiescence invariant and all structured concurrency guarantees.

## Module Integration

Located in: `src/real_lab_chaos_runtime_state_e2e_tests.rs`

### Core Subsystems

1. **`lab::chaos`** - Chaos engineering for testing
   - Deterministic chaos injection during runtime operations
   - Scheduling delays and timing perturbations
   - Resource pressure simulation and CPU starvation
   - Configurable failure probability and duration
   - Operation-specific chaos targeting

2. **`runtime::state`** - Runtime state management
   - Region lifecycle management and hierarchy tracking
   - Task ownership and structured concurrency enforcement
   - Obligation tracking and leak prevention
   - State machine transitions and invariant validation
   - Quiescence detection and close completion

## Key Integration Features

### Chaos-Resilient Runtime

Tests runtime state integrity under chaotic conditions:
1. **Chaos Injection** → Random delays, resource pressure, timing perturbations
2. **Operation Execution** → Runtime operations proceed under chaos conditions
3. **Invariant Preservation** → Core invariants maintained despite chaos
4. **State Validation** → Continuous verification of runtime state consistency
5. **Quiescence Guarantee** → Region close=quiescence invariant preserved
6. **Resource Cleanup** → No leaks or corruption under chaotic conditions

### Core Invariant Enforcement

**Invariant Flow:** `Chaos Injection → Runtime Operation → State Validation → Invariant Verification`

**Critical Invariants Verified:**
- **Structured Concurrency**: Every task owned by exactly one region
- **Region Close=Quiescence**: Closed regions have no live children + all finalizers done
- **No Obligation Leaks**: All obligations committed or aborted before task completion
- **Task Ownership**: Consistent bidirectional task-region ownership tracking
- **Resource Cleanup**: No resource leaks under chaos conditions

### Chaos Engineering Integration

Verifies runtime resilience under systematic chaos injection:
- **Scheduling Perturbations**: Random delays in operation execution
- **Resource Pressure**: Memory and CPU resource exhaustion simulation
- **Timing Chaos**: Perturbation of timing-sensitive state transitions
- **Operation Targeting**: Chaos injection at critical runtime operations
- **Deterministic Chaos**: Reproducible chaos patterns for debugging

## Test Scenarios

### `test_basic_region_lifecycle_with_chaos()`
**Core Lifecycle Resilience**

Tests basic region lifecycle under chaos injection:
1. Enable chaos injection with default configuration
2. Create region, spawn task, create obligation
3. Request region close triggering drain sequence
4. Verify quiescence achieved despite chaos injection
5. Validate all core invariants preserved

**Verification Points:**
- Region lifecycle completes successfully under chaos
- Task and obligation cleanup occurs properly
- Quiescence state achieved with chaos perturbations
- No invariant violations detected during operations
- Chaos events successfully injected during lifecycle

### `test_nested_region_quiescence_with_chaos()`
**Hierarchical Quiescence Under Chaos**

Tests core requirement: nested region quiescence propagation under chaos:
1. Create parent region with child region hierarchy
2. Spawn tasks and create obligations in child regions
3. Inject chaos during region close operations
4. Verify quiescence propagates from children to parent
5. Confirm hierarchical close ordering preserved

**Quiescence Properties:**
- Child regions achieve quiescence before parents
- Parent regions wait for all children to close
- Chaos injection doesn't disrupt close ordering
- Task ownership properly tracked through hierarchy
- Obligation resolution completes at each level

### `test_high_concurrency_chaos_resilience()`
**Concurrent Operations Under Heavy Chaos**

Tests system resilience under concurrent operations with heavy chaos:
1. Create multiple regions with complex task hierarchies
2. Enable aggressive chaos injection (high probability, long delays)
3. Perform concurrent operations across multiple regions
4. Verify independent operation completion
5. Confirm no cross-region interference under chaos

**Concurrency Properties:**
- Independent regions process concurrently under chaos
- Chaos injection isolated between regions
- Invariants maintained across concurrent operations
- Resource usage bounded under chaos load
- No deadlocks or race conditions introduced

### `test_chaos_engine_isolation()`
**Chaos Engine Behavioral Verification**

Tests chaos engine operation isolation and configuration:
1. Initialize chaos engine with specific configuration
2. Verify chaos injection patterns and timing
3. Test chaos event generation and execution
4. Validate chaos statistics collection
5. Confirm chaos enabling/disabling controls

**Chaos Engine Properties:**
- Chaos injection follows configured probability distribution
- Chaos events have appropriate duration and timing
- Chaos statistics accurately track injection events
- Engine state properly controlled by enable/disable
- Injection patterns deterministic for reproducibility

### `test_region_close_quiescence_invariant_preservation()`
**Critical Invariant Verification Under Maximum Chaos**

Tests the critical region close=quiescence invariant under maximum chaos:
1. Configure maximum chaos injection rate (50% probability)
2. Create region with multiple tasks and obligations
3. Request region close with chaos injection active
4. Verify complete drain and quiescence achievement
5. Validate no invariant violations despite chaos

**Critical Properties:**
- Region close=quiescence invariant NEVER violated
- All tasks properly drained and completed
- All obligations resolved (committed or aborted)
- No orphaned resources or state corruption
- Complete cleanup despite timing chaos

### `test_obligation_leak_prevention_under_chaos()`
**Obligation Leak Prevention**

Tests obligation lifecycle integrity under chaos conditions:
1. Create multiple regions with tasks and obligations
2. Enable chaos injection during obligation operations
3. Trigger region close sequence with active obligations
4. Verify all obligations properly resolved
5. Confirm no obligation leaks or orphaned state

**Leak Prevention Properties:**
- All obligations resolved before task completion
- No orphaned obligations after region close
- Obligation state consistent with task state
- Chaos doesn't disrupt obligation tracking
- Resource cleanup completes for all obligations

### `test_structured_concurrency_under_extreme_chaos()`
**Extreme Chaos Resilience**

Tests structured concurrency guarantees under extreme chaos:
1. Configure extreme chaos (80% probability, high delays)
2. Create complex nested region hierarchy
3. Spawn tasks across all hierarchy levels
4. Close regions from leaves to root under extreme chaos
5. Verify structured concurrency maintained throughout

**Extreme Chaos Properties:**
- Structured concurrency never violated
- Task ownership tracking remains consistent
- Region hierarchy properly maintained
- Close ordering respects parent-child relationships
- No state corruption under extreme timing stress

### `test_chaos_injection_determinism()`
**Deterministic Chaos Verification**

Tests deterministic and reproducible chaos injection:
1. Configure chaos with specific seed for determinism
2. Execute identical operation sequences multiple times
3. Verify chaos injection patterns are reproducible
4. Confirm same chaos events occur at same points
5. Validate deterministic debugging capability

**Determinism Properties:**
- Chaos injection patterns reproducible across runs
- Same operations trigger same chaos events
- Timing perturbations follow deterministic patterns
- Statistics collection consistent across runs
- Debugging scenarios reproducible with same chaos

## Test Infrastructure

### `ChaosAwareRuntimeState`
Runtime state manager with integrated chaos injection:
- Region, task, and obligation lifecycle management
- Chaos injection at critical operation points
- Continuous invariant validation during operations
- Performance statistics and timing collection

### `ChaosEngine`
Chaos injection engine with configurable behavior:
- Deterministic chaos generation based on operation context
- Multiple chaos types (scheduling, resource, timing, CPU)
- Configurable probability, duration, and intensity
- Event history tracking and statistics collection

### `InvariantValidator`
Comprehensive validator for all core runtime invariants:
- Structured concurrency validation (task ownership)
- Region close=quiescence verification
- Obligation leak detection and prevention
- Task-region ownership consistency checking

### `ChaosRuntimeHarness`
Integration test harness for chaos scenarios:
- Scenario definition and execution framework
- Complex test case generation and management
- Performance measurement and chaos statistics
- Result validation and reporting

## Real-Service E2E Benefits

### No Mock-Reality Divergence
- Uses actual runtime state machine and lifecycle management
- Authentic chaos injection patterns and timing effects
- Production-representative resource pressure scenarios
- Real structured concurrency enforcement mechanisms

### Integration Bug Detection
- Chaos injection exposing timing-dependent race conditions
- Invariant violations under resource pressure
- State machine corruption under scheduling delays
- Resource leaks in chaos recovery paths

### Production Scenario Modeling
- Realistic system stress and resource contention
- Authentic timing perturbation and scheduling interference
- Production-scale chaos injection and recovery patterns
- Real-world failure mode simulation and testing

## Key Properties Verified

### Invariant Preservation
- Region close=quiescence invariant NEVER violated under chaos
- Structured concurrency maintained under all chaos conditions
- No obligation leaks regardless of timing perturbations
- Task ownership consistency preserved throughout chaos

### Chaos Resilience
- Runtime operations complete successfully under chaos injection
- State machine transitions robust to timing perturbations
- Resource cleanup completes despite chaos interference
- System stability maintained under extreme chaos conditions

### Deterministic Testing
- Chaos injection patterns reproducible for debugging
- Invariant violations consistently detected and reported
- Performance characteristics predictable under chaos
- Test scenarios reliably reproduce chaos conditions

### Performance Characteristics
- Chaos injection overhead bounded and measurable
- Runtime performance degrades gracefully under chaos
- Resource usage remains controlled despite chaos pressure
- Recovery times predictable after chaos cessation

## Usage

Run the e2e tests with:

```bash
# Run all lab chaos runtime state e2e tests
cargo test --lib --features real-service-e2e real_lab_chaos_runtime_state_e2e_tests

# Run specific invariant preservation test
cargo test --lib --features real-service-e2e test_region_close_quiescence_invariant_preservation

# Run extreme chaos resilience test
cargo test --lib --features real-service-e2e test_structured_concurrency_under_extreme_chaos

# Run with detailed logging
cargo test --lib --features real-service-e2e test_high_concurrency_chaos_resilience -- --nocapture
```

### Debugging Failed Tests

When lab chaos runtime integration fails, the structured logging provides:
- Chaos injection event timing and operation targeting
- Runtime state transitions and invariant validation results
- Region lifecycle progression and quiescence achievement
- Task and obligation state changes and cleanup verification

Example debugging workflow:
1. Review chaos injection logs for event patterns and timing
2. Check runtime state logs for lifecycle and transition issues
3. Verify invariant validation logs for specific violation details
4. Analyze performance logs for resource pressure and timing

## Advanced Scenarios

### Adaptive Chaos Injection
Tests intelligent chaos adaptation based on system state:
- Higher chaos injection during complex operations
- Reduced chaos during critical state transitions
- Adaptive timing based on system performance
- Context-aware chaos selection and targeting

### Long-Running Chaos Testing
Tests system stability under extended chaos exposure:
- Hours-long chaos injection with varied intensity
- Memory usage stability over extended periods
- Performance degradation and recovery patterns
- System stability metrics under sustained chaos

### Chaos Recovery Verification
Tests system recovery behavior after chaos cessation:
- Performance return to baseline after chaos ends
- Resource usage normalization and cleanup
- State machine recovery and invariant restoration
- System stability after chaos-induced perturbations

### Multi-Dimensional Chaos
Tests system behavior under multiple simultaneous chaos types:
- Combined scheduling, resource, and timing chaos
- Layered chaos with different probability distributions
- Correlated chaos events across multiple subsystems
- Complex chaos interaction effects and system response

This comprehensive e2e testing ensures that the runtime's lab chaos engineering and runtime state management integration maintains all critical invariants, particularly the region close=quiescence guarantee, under all realistic chaos and failure scenarios.