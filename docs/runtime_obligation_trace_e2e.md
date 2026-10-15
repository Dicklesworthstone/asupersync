# Runtime State ↔ Obligation Ledger ↔ Trace Recorder E2E Integration

This document describes the comprehensive e2e test implementation for the integration of three critical runtime subsystems with verifiable causality DAG tracking.

## Module Integration

Located in: `src/real_runtime_obligation_trace_e2e_tests.rs`

### Core Subsystems

1. **`runtime::state`** - Global runtime state management
   - Region ownership tree
   - Task lifecycle management
   - Obligation tracking integration
   - Runtime metrics and monitoring

2. **`obligation::ledger`** - Central obligation lifecycle tracking
   - Linear token tracking (acquire/commit/abort)
   - Region-scoped obligation ownership
   - Leak detection and prevention
   - Resolution state transitions

3. **`trace::recorder`** - Deterministic trace recording
   - Event capture for replay debugging
   - Causality relationship tracking
   - DAG construction and verification
   - Timeline reconstruction

## Key Integration Features

### Causality DAG Construction

The e2e tests build and verify a complete causality DAG showing the happens-before relationships between:
- Region creation and closure events
- Task spawning and completion
- Obligation acquisition, commitment, and abortion
- Runtime state transitions

### Verifiable Invariants

1. **Temporal Causality**: Events respect happens-before ordering
2. **Obligation Lifecycle**: All obligations follow valid state transitions
3. **Region Quiescence**: Regions close only after all obligations resolved
4. **Trace Integrity**: Complete audit trail maintained throughout execution

## Test Scenarios

### `test_runtime_obligation_trace_integration()`
**Single Workflow Causality Verification**

Tests a complete workflow that exercises all three subsystems:

```
Region Creation → Task Spawn → Obligation Acquisition → 
Resolution → Region Closure
```

**Causality Chain Verified:**
1. Root region creation enables coordinator task spawn
2. Coordinator task enables permit obligation acquisition  
3. Child region creation enables worker task spawn
4. Worker task enables ack obligation acquisition
5. Obligation resolutions enable region closures
6. All events recorded with proper causality links

### `test_obligation_lifecycle_with_trace_verification()`
**Multi-Path Lifecycle Verification**

Tests different obligation resolution paths within the same workflow:
- Permit obligations committed successfully
- Ack obligations aborted due to cancellation
- Lease obligations committed after coordination

**Trace Verification:**
- Acquisition events precede resolution events in DAG
- Different resolution paths maintain causality invariants
- Timeline ordering preserved across obligation types

### `test_concurrent_workflows_with_shared_trace()`
**Concurrent Causality Isolation**

Tests multiple concurrent workflows sharing the same trace recorder:
- Separate region/task hierarchies for each workflow
- Independent obligation lifecycles
- Shared trace collection without interference

**Verification Points:**
- No causality violations between concurrent workflows
- Complete trace coverage of all concurrent activity
- Proper event interleaving in shared timeline

### `test_error_propagation_with_trace_integrity()`
**Error Handling with Audit Trail**

Tests error scenarios while maintaining trace integrity:
- Failed operations recorded in trace
- Graceful error recovery
- Causality invariants preserved despite failures

## Test Infrastructure

### `WorkflowFactory`
Generates realistic workflow scenarios with deterministic steps:
- Complex dependency graphs
- Multiple region hierarchies
- Various obligation types and resolution patterns
- Deterministic step ordering for reproducible tests

### `CausalityAnalyzer`
Comprehensive DAG analysis and verification:
- Happens-before relationship validation
- Cycle detection in dependency graphs
- Critical path analysis
- Obligation lifecycle ordering verification

### `RuntimeObligationTraceHarness`
Integrated test harness combining all three subsystems:
- Real `RuntimeState` instance (no mocks)
- Real `ObligationLedger` with full tracking
- Real `TraceRecorder` with event capture
- Structured workflow execution
- Metrics collection and verification

### `WorkflowLogger`
Structured logging for complex workflow debugging:
- JSON-line event format
- Phase-based execution tracking
- Runtime, obligation, and trace event correlation
- Execution context preservation

## Causality DAG Properties Verified

### Structural Properties
- **Acyclic**: No cycles in the dependency graph
- **Connected**: All events reachable from workflow start
- **Ordered**: Events respect temporal ordering constraints

### Domain Properties
- **Obligation Ordering**: Acquisition precedes resolution
- **Region Lifecycle**: Creation precedes spawning, spawning precedes closure
- **Task Dependencies**: Parent task creation enables child task creation
- **Resource Cleanup**: All obligations resolved before region closure

### Verification Algorithms
- **Topological Sort**: Validates DAG structure
- **Critical Path Analysis**: Identifies workflow bottlenecks
- **Reachability Analysis**: Ensures complete event coverage
- **Invariant Checking**: Domain-specific property verification

## Real-Service E2E Benefits

### No Mock-Reality Divergence
- Uses actual runtime state management
- Real obligation lifecycle tracking
- Authentic trace event generation
- Production-representative performance characteristics

### Cross-Module Bug Detection
- Integration bugs between runtime and obligation systems
- Trace recording accuracy under complex workflows
- State consistency across subsystem boundaries
- Resource cleanup verification

### Production Scenario Modeling
- Realistic workflow complexity
- Concurrent execution patterns
- Error handling and recovery
- Performance impact of trace recording

## Usage

Run the e2e tests with:

```bash
# Run all runtime-obligation-trace e2e tests
cargo test --lib --features real-service-e2e real_runtime_obligation_trace_e2e_tests

# Run specific causality verification test
cargo test --lib --features real-service-e2e test_runtime_obligation_trace_integration

# Run with detailed trace output
cargo test --lib --features real-service-e2e test_obligation_lifecycle_with_trace_verification -- --nocapture
```

### Debugging Failed Tests

When causality verification fails, the structured logging provides:
- Complete event timeline with timestamps
- Dependency relationship visualization  
- Runtime state snapshots at failure points
- Obligation lifecycle state transitions

Example debugging workflow:
1. Review JSON-line logs for event sequence
2. Analyze causality analyzer output for violations
3. Check obligation ledger state for inconsistencies
4. Verify trace recorder captured all expected events

## Integration with Other Testing Approaches

This e2e approach complements:
- **Unit Tests**: Verify individual subsystem behavior
- **Property Tests**: Check invariants under generated scenarios  
- **Conformance Tests**: Validate against formal specifications
- **Golden Artifact Tests**: Ensure deterministic output stability

The causality DAG verification provides unique value by ensuring the runtime's fundamental correctness properties hold across subsystem boundaries in realistic execution scenarios.