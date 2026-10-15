# ATP Test Contract

This document defines what "done" means for unit-level proof in every ATP module. A transfer platform this broad cannot rely on final e2e tests to discover local invariants.

## Test Classification

### Unit Tests
- **Purpose**: Validate individual function/struct behavior in isolation
- **Scope**: Single module, mocked dependencies
- **Requirements**: 
  - All public APIs must have unit tests
  - Critical private functions with complex logic
  - Error path coverage for all failure modes
  - Cancellation behavior for async functions

### Property Tests
- **Purpose**: Validate invariants across input space using generated data
- **Scope**: Module-level properties that must hold for any valid input
- **Requirements**:
  - Codec round-trip properties (serialize → deserialize = identity)
  - Commutative/associative operations
  - Monotonicity properties (e.g., manifest sizes, chunk ordering)
  - Resource cleanup under arbitrary cancellation

### Metamorphic Tests  
- **Purpose**: Validate that equivalent operations produce equivalent results
- **Scope**: Cross-module consistency and protocol correctness
- **Requirements**:
  - Transfer resumption produces identical final state
  - Path selection yields equivalent transfer outcomes
  - Repair reconstruction equals original data
  - Verification determinism across implementations

### Integration Tests
- **Purpose**: Validate module interactions and protocol state machines
- **Scope**: Multi-module workflows with controlled environment
- **Requirements**:
  - Session negotiation end-to-end
  - Transfer lifecycle with cancellation/resume
  - Path racing and fallback behavior
  - Repair coordination across multiple sources

### Lab Tests
- **Purpose**: Deterministic testing under controlled network/disk/timing models
- **Scope**: Full protocol behavior with environmental variation
- **Requirements**:
  - Adversarial network conditions (loss, delay, reordering)
  - Disk pressure and failure scenarios
  - Timing variations and deadlines
  - Malicious peer behavior

## Test Requirements by Module Type

### Protocol Codec Modules
**Modules**: `protocol/frames.rs`, `protocol/codec.rs`, `protocol/varint.rs`

**Required Tests**:
- **Unit**: Frame encoding/decoding for all frame types
- **Property**: Round-trip encoding preserves data
- **Metamorphic**: Different encoding paths produce identical frames
- **Edge Cases**: 
  - Maximum size frames
  - Empty/minimal frames
  - Invalid/malformed input rejection
- **Error Cases**: Truncated data, invalid varint sequences, size limits
- **Cancellation**: Partial frame handling during cancellation

### Data Model Modules
**Modules**: `object.rs`, `manifest.rs`, `path.rs`

**Required Tests**:
- **Unit**: Object graph validation, manifest creation/parsing
- **Property**: Graph cycle detection, manifest integrity
- **Metamorphic**: Equivalent object graphs have identical content hashes
- **Edge Cases**:
  - Empty graphs, single-node graphs
  - Maximum depth/breadth graphs
  - Unicode edge cases in paths/names
- **Error Cases**: Circular references, missing dependencies, invalid metadata
- **Leak Check**: Object handle cleanup, manifest reference counting

### Network Transport Modules  
**Modules**: `quic_native/endpoint.rs`, `quic_native/connection.rs`, `quic_native/streams.rs`

**Required Tests**:
- **Unit**: Endpoint creation, connection establishment, stream lifecycle
- **Property**: Flow control invariants, sequence number ordering
- **Metamorphic**: Connection migration preserves stream state
- **Edge Cases**:
  - Connection limits, stream exhaustion
  - MTU discovery boundaries
  - Key update during transfer
- **Error Cases**: Network partitions, invalid packets, protocol violations
- **Cancellation**: Graceful connection close, stream cancellation propagation
- **Leak Check**: Connection cleanup, stream resource disposal

### Verification Modules
**Modules**: `verifier.rs`, `proof/bundle.rs`, `repair_receiver.rs`

**Required Tests**:
- **Unit**: Proof validation, signature verification, repair symbol processing
- **Property**: Verification determinism, proof completeness
- **Metamorphic**: Multiple verification paths yield identical results
- **Edge Cases**:
  - Empty proofs, maximum proof size
  - Boundary conditions for repair symbols
- **Error Cases**: Invalid signatures, corrupted proofs, malicious repair data
- **Security**: Constant-time operations, side-channel resistance

### State Machine Modules
**Modules**: `protocol/session.rs`, `actor/mod.rs`, `transfer/mod.rs`

**Required Tests**:
- **Unit**: State transitions, event handling, timeout behavior  
- **Property**: State machine reachability, liveness properties
- **Metamorphic**: Equivalent event sequences reach same final state
- **Edge Cases**:
  - Rapid state transitions, concurrent events
  - Timeout edge conditions
- **Error Cases**: Invalid state transitions, protocol violations
- **Cancellation**: State machine cleanup, pending operation cancellation
- **Leak Check**: State cleanup, resource disposal on termination

### Storage/Journal Modules
**Modules**: `disk/mod.rs`, `journal/mod.rs`, `writer.rs`

**Required Tests**:
- **Unit**: File operations, journal append/replay, atomic writes
- **Property**: ACID properties, crash consistency
- **Metamorphic**: Journal replay produces identical state
- **Edge Cases**:
  - Disk space exhaustion, permission failures
  - Large file handling, sparse file operations
- **Error Cases**: I/O failures, filesystem corruption, write conflicts
- **Crash Safety**: Interrupted writes, power failure simulation
- **Leak Check**: File handle cleanup, temporary file removal

## Test Infrastructure Requirements

### Test Harness Features
- **Deterministic Time**: Controllable clock for timeout testing
- **Network Simulation**: Configurable loss/delay/reordering
- **Filesystem Mocking**: Disk pressure and failure injection  
- **Memory Tracking**: Leak detection and allocation limits
- **Cancellation Hooks**: Interrupt operations at arbitrary points

### Evidence Collection
- **Coverage Reporting**: Line/branch coverage per module
- **Performance Metrics**: Latency/throughput benchmarks
- **Resource Usage**: Memory/file handle/connection tracking
- **Failure Analysis**: Automatic minimization of failing inputs

### Test Organization
- **Naming Convention**: `{module}_test.rs` for unit tests, `test_{feature}.rs` for integration
- **Documentation**: Each test documents what invariant it validates
- **Categorization**: Tags for unit/property/metamorphic/integration/lab
- **Dependencies**: Test-only dependencies in `[dev-dependencies]`

## Quality Gates

Every ATP module must pass these gates before being considered "done":

1. **Unit Test Coverage**: ≥95% line coverage, 100% public API coverage
2. **Property Test Validation**: No failures across 10,000+ generated inputs  
3. **Error Path Testing**: All error types have dedicated test cases
4. **Cancellation Safety**: Async functions tested with arbitrary cancellation points
5. **Resource Leak Detection**: No leaked handles/connections/memory in test runs
6. **Performance Bounds**: Established baseline performance and no regressions
7. **Documentation**: Module purpose, invariants, and testing approach documented

## Integration with Release Process

- **Pre-commit**: Fast unit and property tests must pass
- **CI Pipeline**: Full test suite including lab and integration tests
- **Release Gates**: Test ledger must show "TESTED" for all modules in release
- **Regression Prevention**: New tests required for all bug fixes
- **Performance Monitoring**: Continuous benchmarking with alerting on regressions

## Maintenance and Evolution

- **Test Review**: Test changes require same review rigor as production code
- **Test Debt**: Missing tests are tracked as technical debt with priority levels
- **Tool Evolution**: Test infrastructure evolves alongside module requirements
- **Metrics Tracking**: Test execution time, flakiness, and coverage trends monitored