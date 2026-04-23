# Real Kafka Broker Integration Tests

This directory contains **mock-free integration tests** for the Kafka producer and consumer implementations. These tests require a real Kafka broker and exercise the complete message lifecycle including network serialization, broker-side persistence, consumer group coordination, and transactional semantics.

## Why Mock-Free Testing?

The `StubBroker` implementation hides critical production behaviors:

- **Network failures** - Connection drops, timeouts, DNS resolution
- **Serialization edge cases** - Wire protocol compatibility, schema evolution
- **Consumer group coordination** - Rebalancing, partition assignment, heartbeats
- **Transactional semantics** - Transaction coordinator, zombie producers, isolation levels
- **Broker-side persistence** - Disk I/O, replication, log compaction

Mock-based tests would pass while these real-world scenarios fail in production.

## Test Environment Setup

### Prerequisites

- Docker and Docker Compose
- Rust nightly (for the provision script)
- `kafka` feature enabled in Cargo.toml

### Quick Setup

```bash
# 1. Set up Kafka test environment
cargo +nightly -Zscript scripts/provision_kafka_test_env.rs --setup-docker

# 2. Run real broker tests
export REAL_KAFKA_TESTS=true
cargo test kafka_real_broker --features kafka -- --nocapture

# 3. Clean up
cargo +nightly -Zscript scripts/provision_kafka_test_env.rs --stop-docker
```

### Manual Setup

If you have an existing Kafka broker:

```bash
export REAL_KAFKA_TESTS=true
export KAFKA_BOOTSTRAP_SERVERS=your-broker:9092
cargo test kafka_real_broker --features kafka
```

## Test Coverage

### 1. Producer Message Delivery (`test_real_broker_producer_send_and_metadata`)

**Pattern:** Transaction Isolation + Structured Logging

- Sends real messages to Kafka broker
- Validates broker-assigned metadata (offset, timestamp, partition)
- Verifies message serialization over wire protocol
- Tests producer configuration (compression, acks, retries)

**Real Behaviors Tested:**
- Wire protocol serialization
- Broker-assigned offsets and timestamps
- Network round-trip latency
- Producer configuration validation

### 2. End-to-End Round-Trip (`test_real_broker_consumer_producer_round_trip`)

**Pattern:** Factory + Real Infrastructure + Content Verification

- Producer sends batch of realistic messages
- Consumer polls with real consumer group coordination
- Verifies exact message content preservation
- Tests offset commit persistence

**Real Behaviors Tested:**
- Consumer group subscription and assignment
- Message serialization/deserialization fidelity
- Offset management and persistence
- Timeout handling for consumer group coordination

### 3. Transactional Exactly-Once (`test_real_broker_transaction_exactly_once`)

**Pattern:** Real Transaction Coordinator + Isolation Levels

- Commits transaction → message visible to consumers
- Aborts transaction → message NOT visible to consumers
- Uses `ReadCommitted` isolation level
- Verifies exactly-once semantics

**Real Behaviors Tested:**
- Transaction coordinator integration
- Idempotent producer behavior
- Isolation level enforcement
- Transaction state persistence

### 4. Consumer Group Rebalancing (`test_real_broker_consumer_group_rebalancing`)

**Pattern:** Multi-Consumer + Real Coordination Protocol

- Two consumers join same consumer group
- Verifies rebalancing triggers and completes
- Checks partition assignment doesn't overlap
- Tests consumer group generation tracking

**Real Behaviors Tested:**
- Consumer group coordination protocol
- Partition rebalancing algorithm
- Consumer heartbeat and session management
- Assignment conflict resolution

### 5. Network Resilience (`test_real_broker_network_failure_recovery`)

**Pattern:** Stress Testing + Error Classification

- Rapid-fire message sending under load
- Validates retry and idempotence behavior
- Classifies transient vs. permanent errors
- Measures real broker throughput limits

**Real Behaviors Tested:**
- Network timeout and retry logic
- Broker backpressure handling
- Idempotent producer duplicate detection
- Connection pool management

## Structured Test Logging

All tests emit structured JSON logs for CI analysis:

```json
{"test":"real_broker_producer_send","event":"test_start","ts":"2026-04-23T08:00:00Z"}
{"test":"real_broker_producer_send","event":"phase","phase":"setup","phase_num":0,"elapsed_ms":5}
{"test":"real_broker_producer_send","event":"kafka_operation","operation":"send","metadata":{"topic":"test-topic","partition":0,"offset":42},"ts":"2026-04-23T08:00:01Z"}
{"test":"real_broker_producer_send","event":"assertion","field":"topic","expected":"test-topic","actual":"test-topic","matches":true}
{"test":"real_broker_producer_send","event":"test_end","result":"pass","duration_ms":1205}
```

### Parsing Test Results

```bash
# Run tests with JSON output
REAL_KAFKA_TESTS=true cargo test kafka_real_broker 2>&1 | grep '{' | jq

# Extract only failures
REAL_KAFKA_TESTS=true cargo test kafka_real_broker 2>&1 | grep '{' | jq 'select(.event == "assertion" and .matches == false)'

# Performance analysis
REAL_KAFKA_TESTS=true cargo test kafka_real_broker 2>&1 | grep '{' | jq 'select(.event == "kafka_operation")' | jq -s 'group_by(.operation) | map({operation: .[0].operation, count: length})'
```

## Safety Guards

**Production URL Blocklist:**
- Tests fail if `KAFKA_BOOTSTRAP_SERVERS` contains production hostnames
- `NODE_ENV=production` blocks all real broker tests
- Docker setup only uses localhost test ports

**Environment Validation:**
- Validates Docker availability before setup
- Checks Kafka connectivity before running tests
- Fails fast with clear error messages for misconfigurations

## Test Data Factories

### KafkaMessageFactory

Generates realistic test messages with:
- Sequential message IDs for ordering verification
- JSON payloads with timestamps and user data
- Proper key distribution for partitioning
- Batch generation for load testing

```rust
let factory = KafkaMessageFactory::new();
let (key, payload) = factory.create_order_message();
let batch = factory.create_batch_messages(100, "orders");
```

## CI Integration

### GitHub Actions

```yaml
- name: Setup Kafka Test Environment
  run: cargo +nightly -Zscript scripts/provision_kafka_test_env.rs --setup-docker

- name: Run Real Broker Tests
  run: |
    export REAL_KAFKA_TESTS=true
    cargo test kafka_real_broker --features kafka -- --nocapture
  env:
    RUST_LOG: info

- name: Parse Test Results
  run: |
    # Extract structured logs and validate no assertion failures
    cargo test kafka_real_broker 2>&1 | grep '{' | jq -e 'select(.event == "assertion" and .matches == false) | length == 0'

- name: Cleanup
  if: always()
  run: cargo +nightly -Zscript scripts/provision_kafka_test_env.rs --stop-docker
```

## Troubleshooting

### Common Issues

**1. "Real broker not available"**
```bash
# Check environment status
cargo +nightly -Zscript scripts/provision_kafka_test_env.rs --check

# Set up if needed
cargo +nightly -Zscript scripts/provision_kafka_test_env.rs --setup-docker
```

**2. Tests timeout on consumer group coordination**
- Real consumer group joins take 10-30 seconds
- Increase test timeouts for consumer operations
- Check Kafka logs: `docker logs test-kafka`

**3. Transaction tests fail**
- Ensure `enable_idempotence=true` in producer config
- Transaction timeout should be longer than test duration
- Check transaction coordinator logs

**4. Network failure test unstable**
- Real broker behavior varies by load and configuration
- Adjust success rate thresholds based on broker capacity
- Use longer retry timeouts for overloaded brokers

### Debug Mode

```bash
# Enable detailed Kafka logging
export RUST_LOG=kafka=debug
REAL_KAFKA_TESTS=true cargo test kafka_real_broker -- --nocapture

# Check Docker container health
docker ps | grep kafka
docker logs test-kafka --tail 50
docker logs test-zookeeper --tail 50
```

## Migration from Mock Tests

When replacing StubBroker tests with real broker tests:

1. **Identify StubBroker usage:**
   ```rust
   // Old: Mock behavior
   #[cfg(not(feature = "kafka"))]
   consumer.poll() // Uses StubBroker
   
   // New: Real broker
   ConsumerConfig::default().force_real_kafka(true)
   ```

2. **Add realistic timeouts:**
   ```rust
   // Old: Instant mock responses
   consumer.poll(&cx, Duration::ZERO)
   
   // New: Real broker coordination time
   consumer.poll(&cx, Duration::from_secs(30))
   ```

3. **Update assertions for real broker behavior:**
   ```rust
   // Old: Predictable mock offsets
   assert_eq!(metadata.offset, 0);
   
   // New: Broker-assigned offsets
   assert!(metadata.offset >= 0);
   assert!(metadata.timestamp.is_some());
   ```

4. **Add structured logging:**
   ```rust
   let log = KafkaTestLogger::new("test_name");
   log.phase("setup");
   log.kafka_operation("send", Some(&metadata), None);
   log.test_end("pass");
   ```

## Performance Benchmarks

Real broker tests also serve as performance baselines:

| Operation | Target Latency | Target Throughput |
|-----------|----------------|-------------------|
| Single message send | < 10ms p95 | 1000 msg/sec |
| Batch send (100 msgs) | < 50ms p95 | 10000 msg/sec |
| Consumer poll | < 100ms p95 | 5000 msg/sec |
| Transaction commit | < 500ms p95 | 100 tx/sec |

Use structured logs to extract timing data:
```bash
REAL_KAFKA_TESTS=true cargo test kafka_real_broker 2>&1 | grep kafka_operation | jq '.duration_ms' | sort -n
```