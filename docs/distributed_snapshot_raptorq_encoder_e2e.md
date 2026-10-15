# Distributed Snapshot ↔ RaptorQ Encoder E2E Integration

This document describes the comprehensive e2e test implementation for distributed/snapshot ↔ raptorq/encoder integration, focusing on state snapshot erasure encoding for replication resilience across distributed nodes.

## Module Integration

Located in: `src/real_distributed_snapshot_raptorq_encoder_e2e_tests.rs`

### Core Subsystems

1. **`distributed::snapshot`** - State snapshot management
   - State serialization and snapshot creation
   - Snapshot metadata and versioning
   - Compression and optimization for storage
   - Distributed replication coordination

2. **`raptorq::encoder`** - Erasure coding for resilience
   - Forward error correction encoding (RFC 6330)
   - Systematic encoding preserving original data
   - Repair symbol generation for redundancy
   - Configurable source and repair symbol parameters

## Key Integration Features

### Snapshot-to-Erasure Pipeline

Tests complete snapshot-to-erasure-coding processing:
1. **Snapshot Creation** → State snapshots serialized with metadata
2. **Data Preparation** → Snapshot data padded and split into source symbols
3. **Erasure Encoding** → RaptorQ encoding generates repair symbols
4. **Distributed Replication** → Encoded symbols replicated across nodes
5. **Resilience Verification** → Recovery from partial node failures
6. **Data Integrity** → Recovered snapshots match original data

### Erasure Coding Resilience

**Resilience Flow:** `State Snapshot → RaptorQ Encoding → Distributed Storage → Recovery from Failures`

**Resilience Patterns:**
- **Source Symbol Distribution**: Original snapshot data split across systematic symbols
- **Repair Symbol Generation**: Additional symbols enable recovery from node failures
- **Threshold Recovery**: Minimum K symbols required for complete recovery
- **Replication Strategy**: Symbols distributed across multiple nodes for availability

### Distributed Storage Integration

Verifies proper integration of erasure coding and distributed storage:
- **Node Failure Tolerance**: Recovery possible with subset of nodes available
- **Symbol Distribution**: Optimal placement of symbols across storage nodes
- **Metadata Preservation**: Snapshot metadata maintained through encode/decode cycle
- **Performance Optimization**: Efficient encoding and recovery operations

## Test Scenarios

### `test_basic_snapshot_encoding_replication()`
**Core Encoding and Replication**

Tests basic snapshot encoding and distributed replication:
1. Create test snapshot with metadata
2. Encode snapshot using RaptorQ with K source symbols
3. Generate repair symbols for redundancy
4. Replicate encoded symbols across distributed nodes
5. Verify successful replication to target number of nodes

**Verification Points:**
- Snapshot properly encoded with systematic symbols
- Repair symbols generated for error correction
- Symbols successfully replicated to required nodes
- Encoding parameters match configuration
- Recovery possible from replicated symbols

### `test_erasure_coding_resilience()`
**Node Failure Recovery**

Tests core requirement: recovery from node failures using erasure coding:
1. Create and replicate snapshot across multiple nodes
2. Simulate failure of subset of storage nodes
3. Attempt snapshot recovery from remaining nodes
4. Verify complete recovery despite node failures
5. Confirm data integrity after recovery

**Resilience Properties:**
- Recovery succeeds with minimum threshold of nodes
- Data integrity preserved through failure scenarios
- Repair symbols enable recovery from systematic symbol loss
- Failed nodes don't prevent successful recovery
- Resilience threshold properly enforced

### `test_insufficient_nodes_recovery_failure()`
**Recovery Threshold Enforcement**

Tests failure when insufficient nodes available for recovery:
1. Replicate snapshot with normal redundancy
2. Fail nodes beyond recovery threshold
3. Attempt recovery with insufficient symbols
4. Verify recovery fails gracefully with clear error
5. Confirm threshold enforcement prevents data corruption

**Threshold Properties:**
- Recovery fails when K symbols not available
- Clear error messages indicate insufficient data
- System fails closed rather than returning corrupted data
- Threshold calculation matches RaptorQ parameters
- Error handling preserves system stability

### `test_concurrent_snapshot_operations()`
**Concurrent Processing**

Tests multiple simultaneous snapshot operations:
1. Create multiple snapshots with different data
2. Encode and replicate snapshots concurrently
3. Simulate partial node failures during operations
4. Recover all snapshots from available nodes
5. Verify isolation between concurrent operations

**Concurrency Properties:**
- Independent encoding operations don't interfere
- Concurrent replication maintains data integrity
- Recovery operations work independently
- Node failures affect only relevant snapshots
- Resource usage bounded under concurrent load

### `test_large_snapshot_handling()`
**Large Data Volume Processing**

Tests handling of large snapshots exceeding single symbol:
1. Create snapshot with large state data (64KB+)
2. Encode snapshot requiring multiple source symbols
3. Replicate across distributed nodes
4. Verify efficient handling of large data volumes
5. Confirm recovery preserves complete large dataset

**Large Data Properties:**
- Efficient handling of multi-symbol snapshots
- Memory usage bounded during large data processing
- Encoding performance scales with data size
- Recovery maintains complete data integrity
- Symbol boundaries properly managed

### `test_snapshot_metadata_preservation()`
**Metadata Integrity**

Tests preservation of snapshot metadata through encode/decode cycle:
1. Create snapshot with detailed metadata (version, checksum, compression)
2. Encode snapshot including metadata
3. Replicate and recover snapshot
4. Verify metadata exactly preserved
5. Confirm metadata consistency across operations

**Metadata Properties:**
- Version information preserved through operations
- Checksums maintained for integrity verification
- Compression type information retained
- Size and timing metadata accurate
- Metadata available for recovery validation

### `test_encoding_performance_metrics()`
**Performance Characteristics**

Tests encoding performance and timing metrics:
1. Process multiple snapshots with timing measurements
2. Verify encoding performance within acceptable bounds
3. Check memory usage during encoding operations
4. Validate performance statistics collection
5. Confirm scalability with multiple operations

**Performance Properties:**
- Encoding operations complete within time limits
- Memory usage remains bounded during processing
- Performance scales predictably with data size
- Statistics accurately track operation timing
- Throughput meets system requirements

### `test_replication_factor_enforcement()`
**Replication Strategy**

Tests enforcement of replication factor requirements:
1. Configure system with specific replication factor
2. Simulate node availability scenarios
3. Verify replication achieves target factor when possible
4. Test graceful degradation with limited nodes
5. Confirm recovery possible with achieved replication

**Replication Properties:**
- Target replication factor achieved when nodes available
- Graceful degradation when insufficient nodes
- Recovery guaranteed with successful replications
- Symbol distribution optimized across available nodes
- Replication strategy adapts to node availability

## Test Infrastructure

### `DistributedSnapshotSystem`
Complete distributed snapshot system with RaptorQ encoding:
- Snapshot creation and serialization
- RaptorQ encoding with configurable parameters
- Distributed replication across multiple nodes
- Recovery operations with resilience testing

### `ReplicationNode`
Mock distributed storage node with failure simulation:
- Symbol storage and retrieval operations
- Configurable failure simulation for testing
- Performance statistics and monitoring
- Resource usage tracking and management

### `DistributedSnapshotHarness`
Integration test harness for snapshot operations:
- Test snapshot generation and management
- System configuration and node setup
- Integration test orchestration and validation
- Performance measurement and analysis

### `EncodedSnapshot`
RaptorQ encoded snapshot representation:
- Systematic symbols (original data)
- Repair symbols for error correction
- Encoding configuration and metadata
- Performance metrics and timing data

## Real-Service E2E Benefits

### No Mock-Reality Divergence
- Uses actual RaptorQ encoding algorithms and parameters
- Authentic distributed storage patterns and timing
- Production-representative failure scenarios
- Real symbol distribution and recovery algorithms

### Integration Bug Detection
- Snapshot serialization affecting symbol boundaries
- RaptorQ parameter misalignment with snapshot sizes
- Node failure scenarios not properly handled
- Resource leaks in encoding or recovery paths

### Production Scenario Modeling
- Realistic snapshot sizes and encoding complexity
- Authentic distributed node failure patterns
- Production-scale concurrent operation loads
- Real-world recovery timing and resource usage

## Key Properties Verified

### Data Integrity
- Snapshots recovered exactly match original data
- Metadata preserved through encode/decode cycle
- Checksums and versioning maintained correctly
- No data corruption during failure scenarios

### Resilience Guarantees
- Recovery possible with K of N symbols available
- System degrades gracefully with node failures
- Repair symbols enable recovery from systematic loss
- Threshold enforcement prevents partial data return

### Performance Characteristics
- Encoding performance scales with snapshot size
- Memory usage bounded during large data processing
- Replication timing meets distributed system requirements
- Recovery performance adequate for operational needs

### Distributed Storage
- Symbols efficiently distributed across nodes
- Replication factor requirements properly enforced
- Node failure tolerance matches erasure coding parameters
- Concurrent operations maintain isolation and consistency

## Usage

Run the e2e tests with:

```bash
# Run all distributed snapshot RaptorQ e2e tests
cargo test --lib --features real-service-e2e real_distributed_snapshot_raptorq_encoder_e2e_tests

# Run specific resilience test
cargo test --lib --features real-service-e2e test_erasure_coding_resilience

# Run large snapshot handling test
cargo test --lib --features real-service-e2e test_large_snapshot_handling

# Run with detailed logging
cargo test --lib --features real-service-e2e test_concurrent_snapshot_operations -- --nocapture
```

### Debugging Failed Tests

When distributed snapshot RaptorQ integration fails, the structured logging provides:
- Encoding operation timing and symbol generation
- Replication success/failure rates across nodes
- Recovery operation results and error conditions
- Symbol distribution patterns and node utilization

Example debugging workflow:
1. Review encoding logs for symbol generation issues
2. Check replication logs for node connectivity problems
3. Verify recovery logs for insufficient symbol scenarios
4. Analyze performance logs for timing and resource issues

## Advanced Scenarios

### Dynamic Node Management
Tests adaptive behavior with changing node availability:
- Node addition during active replication
- Graceful node removal and symbol redistribution
- Load balancing across heterogeneous nodes
- Automatic failover and recovery mechanisms

### Compression Integration
Tests snapshot compression before erasure coding:
- Compressed snapshot encoding efficiency
- Compression ratio impact on symbol count
- Recovery performance with compressed data
- Metadata handling for compression information

### Large-Scale Resilience
Tests system behavior under extreme conditions:
- Hundreds of concurrent snapshots
- Massive state data requiring many symbols
- Extended node failure scenarios
- Resource exhaustion and recovery

### Security and Validation
Tests security aspects of distributed snapshots:
- Snapshot integrity verification
- Symbol tampering detection
- Access control for snapshot recovery
- Audit logging for distributed operations

This comprehensive e2e testing ensures that the runtime's distributed snapshot and RaptorQ encoder integration maintains proper data integrity, efficient erasure coding, and robust failure recovery under all realistic operational scenarios.