# Channel ↔ Supervision E2E Integration

This document describes the comprehensive e2e test implementation for channel/* ↔ supervision/* integration, focusing on channel close propagation through supervisor decisions and forced restart scenarios on broadcast errors.

## Module Integration

Located in: `src/real_channel_supervision_e2e_tests.rs`

### Core Subsystems

1. **`channel/*`** - Two-phase channel primitives
   - Broadcast channels for fan-out communication
   - MPSC channels for actor mailboxes
   - Watch channels for state observation
   - Channel close semantics and error propagation

2. **`supervision/*`** - Actor supervision trees
   - Supervision strategies (Stop, Restart, Escalate)
   - Restart policies with rate limiting and backoff
   - Child process lifecycle management
   - Error escalation and decision propagation

3. **`actor`** - Message-driven concurrency
   - Actor mailbox integration with channels
   - Lifecycle hooks (on_start, on_stop)
   - Error handling and restart coordination
   - Message processing and state management

## Key Integration Features

### Channel Close Propagation

Tests how channel closures trigger supervisor decisions:
1. **Broadcast Channel Closure** → Supervisor detects affected actors
2. **Error Classification** → Determines restart vs escalation strategy  
3. **Decision Propagation** → Commands sent through actor mailboxes
4. **Coordinated Restart** → Actors restarted with fresh channel subscriptions

### Supervisor Decision Flow

```
Channel Error → Supervisor Analysis → Decision → Mailbox Command → Actor Restart
```

**Error Types Handled:**
- `BroadcastError::Closed` → Force restart affected actors
- `BroadcastError::Lagged` → Continue with monitoring
- `MpscError::Full` → Backpressure handling
- `MpscError::Closed` → Escalate to parent supervisor

### Actor Mailbox Integration

Verifies that supervisor decisions properly flow through actor mailboxes:
- Commands delivered reliably despite channel failures
- Mailbox capacity management during restart scenarios  
- Message ordering preserved across restart boundaries
- No message loss during supervision transitions

## Test Scenarios

### `test_channel_supervision_integration()`
**Complete Integration Flow**

Tests the full workflow from channel error to actor restart:
1. Start multiple workers under supervision
2. Establish broadcast communication channels
3. Trigger broadcast channel closure
4. Verify supervisor detects and responds to error
5. Confirm affected workers are restarted
6. Validate new workers receive fresh channel subscriptions

**Verification Points:**
- Supervision events properly logged
- Channel errors propagated to supervisor
- Restart sequence executed correctly
- Worker count maintained after restart

### `test_forced_restart_on_broadcast_error()`
**Broadcast Error Restart Scenario**

Specifically tests the forced restart mechanism when broadcast channels fail:
1. Create actor hierarchy with broadcast subscriptions
2. Simulate broadcast channel unexpected closure
3. Verify supervisor forces restart of affected actors
4. Confirm restart count and error tracking

**Error Simulation:**
- `BroadcastError { error: "channel closed unexpectedly", affected_children: [...] }`
- Channel closure propagation through actor mailboxes
- Supervisor decision to force restart specific children
- Fresh channel subscriptions for restarted actors

### `test_mailbox_integration_with_supervision()`
**Mailbox Lifecycle During Restart**

Tests actor mailbox behavior during supervision operations:
1. Send messages to actor mailbox before restart
2. Trigger supervised restart
3. Verify mailbox properly reset for new actor instance
4. Send messages after restart and verify delivery

**Mailbox Properties Verified:**
- Mailbox capacity respected during restart
- Message ordering preserved
- No phantom messages from previous actor instance
- Proper cleanup of mailbox state

### `test_concurrent_channel_supervision()`
**Concurrent Operations**

Tests supervision under concurrent channel activity:
1. Multiple workers with independent broadcast subscriptions
2. Concurrent broadcast sending and supervision operations
3. Periodic restart commands during active communication
4. Verification of isolation between concurrent operations

**Concurrency Properties:**
- No race conditions between channel operations and supervision
- Proper isolation of restart operations
- Message delivery guarantees maintained
- Supervision decisions don't interfere with ongoing communication

### `test_supervision_decision_propagation()`
**Decision Flow Verification**

Tests that supervisor decisions properly propagate through the actor hierarchy:
1. Create multi-level actor hierarchy
2. Trigger failure in primary actor
3. Verify decision propagates to secondary actors via channels
4. Confirm coordination between supervision levels

**Propagation Chain:**
- Primary actor failure detected
- Supervisor analysis and decision
- Decision broadcast to secondary actors
- Coordinated response across actor hierarchy

## Test Infrastructure

### `TestSupervisor`
Real supervisor actor implementing supervision logic:
- Child process management with real `ActorHandle`s
- Broadcast error handling with forced restart logic
- Status tracking (restart counts, error history, active children)
- Integration with real channel primitives

### `TestWorker`
Worker actors with real mailbox and channel integration:
- Broadcast message processing with error handling
- Simulated error scenarios for testing supervision
- Status reporting for test verification
- Real actor lifecycle with proper cleanup

### `ChannelSupervisionHarness`
Integrated test harness combining all subsystems:
- Real broadcast and MPSC channels (no mocks)
- Actual supervisor-worker actor hierarchies
- Command and status communication channels
- Event sequence analysis and verification

### `SupervisionFactory`
Test data factory for realistic supervision scenarios:
- Configurable restart policies and strategies
- Various error types for comprehensive testing
- Deterministic child specifications
- Realistic supervision tree configurations

### `ChannelSupervisionAnalysis`
Event sequence analyzer for verification:
- Supervision event tracking
- Channel operation monitoring
- Restart sequence detection
- Error propagation verification

## Real-Service E2E Benefits

### No Mock-Reality Divergence
- Uses actual broadcast and MPSC channels
- Real supervision strategy implementation
- Authentic actor lifecycle management
- Production-representative error handling

### Integration Bug Detection
- Channel-supervision coordination issues
- Mailbox state management during restarts
- Error propagation timing problems
- Resource cleanup verification across restarts

### Production Scenario Modeling
- Realistic channel failure modes
- Concurrent supervision operations
- Multi-level actor hierarchies
- Complex error propagation patterns

## Key Properties Verified

### Temporal Correctness
- Channel errors detected before timeout
- Supervision decisions applied within restart window
- Actor restart completes before next error
- Message ordering preserved across restart boundaries

### Resource Management
- No channel handle leaks during restart
- Proper mailbox cleanup for terminated actors
- Subscription state correctly transferred to new actors
- Supervision state consistency maintained

### Error Resilience
- Supervision continues despite channel failures
- Actor hierarchy maintains stability during errors
- Graceful degradation when escalation required
- Complete recovery from broadcast channel loss

## Usage

Run the e2e tests with:

```bash
# Run all channel-supervision e2e tests
cargo test --lib --features real-service-e2e real_channel_supervision_e2e_tests

# Run specific integration test
cargo test --lib --features real-service-e2e test_channel_supervision_integration

# Run broadcast error restart test
cargo test --lib --features real-service-e2e test_forced_restart_on_broadcast_error

# Run with detailed logging
cargo test --lib --features real-service-e2e test_concurrent_channel_supervision -- --nocapture
```

### Debugging Failed Tests

When supervision integration fails, the structured logging provides:
- Complete supervision event timeline
- Channel operation sequences with error details
- Actor restart progression with timing
- Mailbox state transitions and message flow

Example debugging workflow:
1. Review JSON-line logs for event sequence
2. Check supervision event timing and decisions
3. Verify channel error propagation path
4. Analyze mailbox state during restart transitions

## Integration with Other Testing Approaches

This e2e approach complements:
- **Unit Tests**: Individual channel and supervision behavior
- **Property Tests**: Supervision invariants under generated scenarios
- **Conformance Tests**: Channel semantics against specifications
- **Golden Artifact Tests**: Supervision decision determinism

The channel-supervision integration provides unique value by ensuring correct coordination between communication infrastructure and fault tolerance mechanisms in realistic failure scenarios.

## Advanced Scenarios

### Cascade Failure Handling
Tests supervision response to cascading channel failures:
- Primary broadcast channel failure triggers secondary channel errors
- Supervision prevents cascade from bringing down entire actor tree
- Selective restart of affected subsystems only
- Restoration of communication channels with minimal disruption

### Backpressure Integration
Tests supervision behavior under channel backpressure:
- Slow consumers causing channel pressure
- Supervision decisions based on mailbox utilization
- Restart policies adjusted for backpressure conditions
- Channel capacity management during supervision operations

### Multi-Channel Coordination
Tests supervision of actors using multiple channel types:
- Actor with both broadcast subscription and MPSC mailbox
- Coordination of channel lifecycle during restart
- Proper cleanup of all channel resources
- Re-establishment of multi-channel subscriptions

This comprehensive e2e testing ensures that the runtime's communication infrastructure and fault tolerance systems work together correctly under all realistic operational scenarios.