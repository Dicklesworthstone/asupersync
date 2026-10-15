# T6.10 — Deterministic Integration and Fault-Injection Suites for Database and Messaging

**Bead**: `asupersync-2oh2u.6.10`
**Track**: T6 (Database and messaging ecosystem closure)
**Depends on**: T6.5 (pool/transaction contracts), T6.9 (retry/idempotency/failure contracts)
**Unblocks**: T6.12 (exhaustive unit-test matrix), T8.11 (cross-track quality thresholds)
**Status**: In progress

## Purpose

Define and enforce deterministic integration test scenarios and fault-injection patterns
that validate cross-module behavior across the database and messaging subsystems. While
T6.5 defines pool/transaction contracts and T6.9 defines retry/failure contracts, this
bead proves those contracts hold under integrated use and adversarial fault injection.

## Scope

| Domain | Scope |
|--------|-------|
| Pool integration | Acquire/release/evict lifecycle across mock backends |
| Transaction integration | Commit/rollback/savepoint across closure wrappers |
| Retry integration | Exponential backoff, cancel-aware retry, retry eligibility |
| Error classification | Cross-backend normalization, transient vs permanent |
| Messaging contracts | Delivery guarantees, ack/nack, dedup, DLQ semantics |
| Fault injection | Connection failure, validation failure, capacity exhaustion |
| Cancel safety | Cancellation during acquire, hold, transaction, retry |
| Observability | Stats accuracy under concurrent operations |

## 1. Pool Integration Scenarios

### INT-POOL-01: Acquire-Use-Release Lifecycle

Validate the full connection lifecycle through a mock `ConnectionManager`:

1. Pool creates connection on first acquire.
2. Connection is returned to idle set on release (drop).
3. Second acquire reuses the idle connection (no new create).
4. Stats reflect: 1 create, 2 acquisitions, 0 discards.

### INT-POOL-02: Validation Failure Recovery

1. Create pool with `validate_on_checkout = true`.
2. Acquire and return a connection.
3. Configure mock to fail validation on next checkout.
4. Acquire again: pool discards invalid connection, creates new one.
5. Stats: 2 creates, 1 validation failure, 1 discard.

### INT-POOL-03: Capacity Enforcement

1. Create pool with `max_size = 2`.
2. Acquire two connections (hold both).
3. Third acquire must fail with `DbPoolError::Full`.
4. Release one connection.
5. Next acquire succeeds (reuses released connection).

### INT-POOL-04: Stale Connection Eviction

1. Create pool with short `idle_timeout` and `max_lifetime`.
2. Acquire and return connection.
3. Call `evict_stale()`.
4. Verify connection was evicted (stats show discard).
5. Next acquire creates fresh connection.

### INT-POOL-05: Graceful Close and Drain

1. Create pool, acquire and return connection.
2. Call `pool.close()`.
3. Verify subsequent acquire fails with `DbPoolError::Closed`.
4. Verify idle connections were drained.

### INT-POOL-06: Connection Failure During Acquire

1. Create pool with mock manager that fails `connect()`.
2. Acquire must fail with `DbPoolError::Connect(E)`.
3. Pool total count must not leak (stays at 0).
4. Stats: 0 acquisitions, connect error propagated.

### INT-POOL-07: Warm-up Pre-population

1. Create pool with `min_idle = 3`, `max_size = 5`.
2. Call `warm_up()`.
3. Verify pool has exactly `min_idle` idle connections.
4. Stats: 3 creates, 0 acquisitions.

## 2. Transaction Integration Scenarios

### INT-TXN-01: Retry Policy Backoff Calculation

Validate `RetryPolicy::delay_for()` produces correct exponential backoff:

| Attempt | Base 50ms, Mult 2x | Expected |
|---------|---------------------|----------|
| 0 | 50ms * 2^0 = 50ms | 50ms |
| 1 | 50ms * 2^1 = 100ms | 100ms |
| 2 | 50ms * 2^2 = 200ms | 200ms |
| 3 | 50ms * 2^3 = 400ms | 400ms |
| 10 | 50ms * 2^10 = 51200ms | capped at max_delay |

### INT-TXN-02: Retry Policy Edge Cases

1. `RetryPolicy::none()` — delay is always zero, max_retries is 0.
2. Overflow: attempt = u32::MAX should not panic (saturating).
3. Zero base delay: all delays are zero.
4. Max delay cap: delays never exceed `max_delay`.

### INT-TXN-03: Retry Eligibility Classification

For each backend, verify error classification methods:

| Backend | Method | True Cases | False Cases |
|---------|--------|------------|-------------|
| PostgreSQL | `is_serialization_failure()` | SQLSTATE 40001 | 23505, 42601 |
| PostgreSQL | `is_deadlock()` | SQLSTATE 40P01 | 40001, 23505 |
| PostgreSQL | `is_unique_violation()` | SQLSTATE 23505 | 40001, 42601 |
| MySQL | `server_code() == 1213` | Deadlock | Lock wait |
| MySQL | `server_code() == 1205` | Lock wait timeout | Deadlock |
| SQLite | `SQLITE_BUSY` | Busy | Locked |

## 3. Error Classification Scenarios

### INT-ERR-01: Cross-Backend Error Normalization

All database error types MUST expose consistent classification:

```
is_connection_error() → true for: Io, ConnectionClosed
is_retryable()        → true for: serialization, deadlock, busy
is_constraint()       → true for: unique violation, check constraint
```

### INT-ERR-02: Messaging Error Classification

| System | Error | is_transient | is_capacity |
|--------|-------|-------------|-------------|
| Kafka | QueueFull | true | true |
| Kafka | MessageTooLarge | false | false |
| Kafka | Broker(transient) | true | false |
| Redis | PoolExhausted | true | true |
| NATS | Closed | false | false |
| JetStream | NotAcked | true | false |

### INT-ERR-03: Error Display Formatting

All error types MUST produce human-readable `Display` output that includes:
1. The error category (e.g., "I/O error", "protocol error").
2. Specific detail (e.g., the IO error message, SQL state code).
3. Source chain via `std::error::Error::source()`.

## 4. Messaging Contract Scenarios

### INT-MSG-01: Delivery Guarantee Matrix

| System | Guarantee | Mechanism |
|--------|-----------|-----------|
| Redis pub/sub | At-most-once | Fire-and-forget |
| NATS core | At-most-once | Fire-and-forget |
| JetStream | At-least-once | PubAck + explicit consumer ack |
| Kafka (non-idem) | At-least-once | Broker acks |
| Kafka (idempotent) | Exactly-once | Sequence number dedup |
| Kafka (transactional) | Exactly-once | Atomic batch commit |

### INT-MSG-02: Kafka Error Variant Coverage

All `KafkaError` variants must be constructible and display correctly:
- `Io`, `Protocol`, `Broker`, `QueueFull`, `MessageTooLarge`, `InvalidTopic`,
  `Transaction`, `Cancelled`, `Config`.

### INT-MSG-03: NATS Error Variant Coverage

All `NatsError` variants must be constructible and display correctly:
- `Io`, `Protocol`, `Server`, `InvalidUrl`, `Cancelled`, `Closed`,
  `SubscriptionNotFound`, `NotConnected`.

### INT-MSG-04: JetStream Error Variant Coverage

All `JsError` variants must be constructible and display correctly:
- `Nats`, `Api`, `StreamNotFound`, `ConsumerNotFound`, `NotAcked`,
  `InvalidConfig`, `ParseError`.

### INT-MSG-05: Redis Error Variant Coverage

All `RedisError` variants must be constructible and display correctly:
- `Io`, `Protocol`, `Redis`, `PoolExhausted`, `InvalidUrl`, `Cancelled`.

## 5. Fault-Injection Scenarios

### FI-01: Connection Failure on First Acquire

Mock manager returns `Err` from `connect()`. Pool must:
1. Propagate the error.
2. Not increment total count.
3. Not leave phantom entries in idle set.

### FI-02: Validation Failure After Idle

Mock manager returns `false` from `is_valid()`. Pool must:
1. Discard the connection.
2. Create a new connection.
3. Increment validation_failures stat.
4. Not leak capacity (total stays correct).

### FI-03: Intermittent Connection Failure

Mock manager alternates success/failure:
1. First connect: success.
2. Second connect (after discard): failure.
3. Third connect: success.
Validate pool recovers and stats are accurate.

### FI-04: Capacity Leak Prevention

Simulate failure during connect after total was incremented:
1. Verify total is decremented on connect failure.
2. Verify pool does not permanently lose capacity.

### FI-05: Pool Stats Accuracy Under Churned Connections

1. Create/acquire/release/discard multiple connections.
2. After each operation, verify `stats()` is internally consistent:
   - `total == idle + active`
   - `total <= max_size`
   - `total_acquisitions >= total_creates`

## 6. Cancel Safety Scenarios

### CS-01: Cancel During Pool Acquire (Wait Phase)

When pool is at capacity and acquire is waiting:
1. Cancel the waiting task.
2. Verify no resource leak (total count unchanged).
3. Verify the cancellation does not corrupt pool state.

### CS-02: Cancel During Hold Phase

When a connection is checked out:
1. Drop the `PooledConnection` (simulating cancel).
2. Verify connection is returned to idle set.
3. Verify pool total is correct.

### CS-03: Cancel During Transaction

When a transaction is in progress:
1. Cancel the task.
2. Verify transaction is rolled back (not committed).
3. Verify connection is returned to pool.

## 7. Document and Artifact Requirements

### DOC-01: Contract Document Structure

The contract document MUST contain:
1. All numbered sections (1-6 above).
2. References to upstream T6.5 and T6.9 contracts.
3. References to source modules for pool, transaction, and messaging.
4. Integration scenario IDs (INT-*, FI-*, CS-*).

### DOC-02: JSON Artifact

A machine-readable JSON artifact MUST contain:
1. `schema_version` field.
2. `scenarios` array with `id`, `category`, `description`, `systems`, `status`.
3. `fault_injection` array with fault types and expected behaviors.
4. `coverage_matrix` mapping systems to scenario categories.
5. `upstream_dependencies` listing T6.5 and T6.9 bead IDs.

### DOC-03: Source Module References

The contract document MUST reference these implementation files:
- `src/database/pool.rs`
- `src/database/transaction.rs`
- `src/database/postgres.rs`
- `src/database/mysql.rs`
- `src/database/sqlite.rs`
- `src/messaging/redis.rs`
- `src/messaging/nats.rs`
- `src/messaging/jetstream.rs`
- `src/messaging/kafka.rs`
- `src/messaging/kafka_consumer.rs`

## 8. Implementation Status

| Scenario Category | Count | Status |
|-------------------|-------|--------|
| Pool integration (INT-POOL-*) | 7 | Enforced |
| Transaction integration (INT-TXN-*) | 3 | Enforced |
| Error classification (INT-ERR-*) | 3 | Enforced |
| Messaging contracts (INT-MSG-*) | 5 | Enforced |
| Fault injection (FI-*) | 5 | Enforced |
| Cancel safety (CS-*) | 3 | Enforced |
| Document requirements (DOC-*) | 3 | Enforced |
| **Total** | **29** | |

## 9. Contract Dependencies

```
T6.5 (pool/transaction contracts)
  ↓
T6.9 (retry/idempotency/failure contracts)
  ↓
T6.10 (THIS: integration + fault injection)    ← you are here
  ↓
T6.12 (exhaustive unit-test matrix)
  ↓
T8.11 (cross-track unit-test thresholds)
  ↓
T8.12 (cross-track e2e logging gates)
```
