# Real-Service E2E Testing Examples

This document demonstrates the real-service E2E testing approach implemented in asupersync, following the `/testing-real-service-e2e-no-mocks` pattern.

## Example: Server Connection + Session Types + Evidence Collection

Located in: `src/real_server_session_evidence_e2e_tests.rs`

This e2e test demonstrates integration of three core runtime subsystems:

- **Server Connection Management** (`server::connection`): Connection tracking and lifecycle
- **Session Types** (`session`): Protocol-safe typed communication channels  
- **Evidence Collection** (`evidence_sink`): Runtime decision tracing and audit

### Key Integration Points Tested

1. **Connection Lifecycle with Evidence**
   - Connection registration and tracking through `ConnectionManager`
   - Evidence emission for connection acceptance decisions
   - Connection capacity limits and rejection handling
   - RAII cleanup through `ConnectionGuard`

2. **Protocol-Safe Communication**
   - Typed session channels with `Send`/`Recv`/`Choose`/`Offer` protocol states
   - Bidirectional client-server communication
   - Protocol compliance enforced at compile time through session types

3. **Runtime Decision Tracing**
   - Evidence collection through `EvidenceSink` during all operations
   - Deterministic evidence timestamps for replay debugging
   - Evidence aggregation across concurrent sessions

### Test Scenarios

#### `test_server_connection_session_evidence_integration()`
Tests the happy path integration where a client establishes a session, exchanges messages through typed channels, and all decisions are traced via evidence collection.

**Protocol Flow:**
```
Client                           Server
------                           ------
Send(TestClientRequest) ────────► Recv(TestClientRequest)
Recv(TestServerResponse) ◄──────── Send(TestServerResponse)  
Choose(Left) ────────────────────► Offer(Left|Right)
Send(SecondRequest) ─────────────► Recv(SecondRequest)
Close ───────────────────────────► Close
```

#### `test_connection_capacity_limits_with_evidence()`
Tests connection capacity enforcement where the server rejects connections beyond its limit, with evidence collected about capacity decisions.

**Verification Points:**
- First N connections succeed and are tracked
- Connection N+1 fails with capacity error
- Evidence includes capacity enforcement decisions
- Dropping connection guards frees capacity for new connections

#### `test_backpressure_handling_with_evidence()`
Tests server behavior under high-volume message scenarios that could cause backpressure in the communication channels.

**Backpressure Simulation:**
- Client sends large messages (10KB+ payloads)
- Session channels handle flow control gracefully
- Evidence collection continues during high load
- Server processes all messages without dropping data

#### `test_connection_idle_timeout_with_evidence()`
Tests connection idle timeout handling where connections that exceed idle thresholds are eligible for cleanup.

**Timeout Simulation:**
- Connection established with short idle timeout
- Simulated idle period exceeds timeout threshold
- Evidence collected about timeout monitoring decisions
- Connection cleanup occurs when guard is dropped

#### `test_session_protocol_error_handling_with_evidence()`
Tests error handling when session protocol violations occur (e.g., client drops connection unexpectedly).

**Error Scenarios:**
- Client endpoint dropped mid-protocol
- Server handles session errors gracefully
- Evidence still collected despite protocol failures
- No resource leaks or panics on error paths

#### `test_concurrent_sessions_with_shared_evidence()`
Tests multiple concurrent sessions sharing the same evidence sink, verifying thread safety and evidence aggregation.

**Concurrency Properties:**
- Multiple sessions run simultaneously
- Shared evidence sink handles concurrent access
- Evidence from all sessions is properly aggregated
- No evidence loss or corruption under concurrency

### Test Infrastructure

#### `TestDataFactory`
Provides realistic test data generation:
- Deterministic client IDs and request IDs
- Various request types (Subscribe, Unsubscribe, PublishMessage)
- Configurable payload sizes for backpressure testing

#### `TestLogger` 
Structured logging for debugging test failures:
- JSON-line format for machine parsing
- Phase-based test progression tracking
- Connection, session, and evidence event logging
- Event aggregation for post-test analysis

#### `TestServer`
Real server implementation integrating all components:
- Uses actual `ConnectionManager` (no mocks)
- Real `CollectorSink` for evidence collection
- Actual session type protocol handling
- Realistic subscription/publication logic

### Advantages of Real-Service E2E Testing

1. **No Mock-Reality Divergence**
   - Tests use actual `ConnectionManager`, session channels, and evidence sinks
   - Catches integration bugs that unit tests with mocks would miss
   - Verifies real performance characteristics and resource usage

2. **Structured Test Isolation**
   - Each test uses fresh component instances
   - No shared state between tests (similar to transaction rollback pattern)
   - Deterministic test execution through lab runtime

3. **Comprehensive Integration Coverage**
   - Tests actual data flow through all three subsystems
   - Verifies error propagation across module boundaries  
   - Validates evidence collection under various operational scenarios

4. **Production-Representative Scenarios**
   - Connection capacity limits match real server constraints
   - Message sizes and concurrency levels reflect production usage
   - Error conditions based on actual failure modes

### Usage

Run the e2e tests with:

```bash
# Run all e2e tests in the module
cargo test --lib --features real-service-e2e real_server_session_evidence_e2e_tests

# Run specific test scenario
cargo test --lib --features real-service-e2e test_server_connection_session_evidence_integration

# Run with detailed output for debugging
cargo test --lib --features real-service-e2e test_connection_capacity_limits_with_evidence -- --nocapture
```

The tests run in the lab runtime with virtual time, providing deterministic execution suitable for CI/CD pipelines while testing actual runtime behavior.