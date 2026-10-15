# T6.9 — Retry, Idempotency, and Failure Contracts for Data and Messaging Paths

**Bead**: `asupersync-2oh2u.6.9`
**Track**: T6 (Database and messaging ecosystem closure)
**Status**: Draft (pre-T6.5/T6.6/T6.8 closure)

## Purpose

Unify retry semantics, idempotency guarantees, and failure classification across all
database backends (PostgreSQL, MySQL, SQLite) and messaging systems (NATS/JetStream,
Kafka, Redis). These contracts ensure callers get consistent, predictable behavior for
transient-failure recovery regardless of the underlying transport.

## Scope

| Domain | Scope |
|--------|-------|
| Retry policy | Shared policy structure, per-backend eligibility, exponential backoff |
| Error classification | Transient vs permanent, retryable predicate, cross-backend normalization |
| Idempotency | Producer dedup, consumer dedup, request-level idempotency keys |
| Delivery guarantees | At-most-once, at-least-once, exactly-once semantics per system |
| Failure propagation | Cancel-aware failure chains, circuit-breaker integration |
| Backpressure | Rate limiting, queue depth, connection pool exhaustion |

## 1. Retry Contracts

### C-RTY-01: Shared Retry Policy Structure

All retry-capable operations MUST use a common policy structure:

| Field | Type | Default | Semantics |
|-------|------|---------|-----------|
| `max_attempts` | `u32` | 3 | Total attempts including the initial call |
| `initial_delay` | `Duration` | 100ms | Delay before first retry |
| `max_delay` | `Duration` | 30s | Cap on exponential growth |
| `multiplier` | `f64` | 2.0 | Backoff multiplier per attempt |
| `jitter` | `f64` | 0.1 | Jitter factor (0.0 = none, 1.0 = full) |

Delay formula: `min(initial_delay * multiplier^(attempt-1), max_delay) * (1 + random(jitter))`

Reference implementation: `src/combinator/retry.rs`

### C-RTY-02: Transaction Retry Eligibility

Each database backend MUST define which errors are eligible for automatic
transaction retry:

| Backend | Retryable Errors | SQL State / Code |
|---------|-----------------|-----------------|
| PostgreSQL | Serialization failure | SQLSTATE `40001` |
| PostgreSQL | Deadlock detected | SQLSTATE `40P01` |
| MySQL | Deadlock detected | Error 1213 |
| MySQL | Lock wait timeout | Error 1205 |
| SQLite | Database busy | `SQLITE_BUSY` |
| SQLite | Database locked | `SQLITE_LOCKED` |

Non-retryable errors (all backends): constraint violations, syntax errors,
authentication failures, connection failures.

### C-RTY-03: Connection Retry

Pool acquire operations MUST support retry with backoff:

1. First attempt: immediate.
2. On connection failure: retry with `initial_delay`.
3. Total attempts bounded by `max_attempts`.
4. Total time bounded by `connection_timeout`.
5. Cancel-safe: cancellation between attempts causes no resource leak.

### C-RTY-04: Messaging Retry

Each messaging system MUST document its retry semantics:

| System | Producer Retry | Consumer Retry | Mechanism |
|--------|---------------|----------------|-----------|
| Kafka | Internal (rdkafka) | Rebalance + offset replay | Broker-managed |
| JetStream | Application-level | Server redelivery via `ack_wait` | `max_deliver` limit |
| NATS core | None (fire-and-forget) | None | At-most-once |
| Redis pub/sub | None | None | At-most-once |

### C-RTY-05: Cancel-Aware Retry

All retry loops MUST respect the `Cx` cancellation protocol:

1. Check cancellation before each attempt.
2. Check cancellation during inter-attempt delay.
3. On cancellation: propagate `Outcome::Cancelled` without further retries.
4. Budget integration: retry delays count against the `Cx` budget.

## 2. Error Classification Contracts

### C-ERR-03: Transient Error Predicate

All backends MUST provide a method to classify errors as transient:

```rust
fn is_transient(&self) -> bool;
```

Transient errors are those that may succeed if retried with the same input.

| Backend | Transient Conditions |
|---------|---------------------|
| PostgreSQL | SQLSTATE 40001, 40P01, 08xxx (connection), 53xxx (resource) |
| MySQL | Error 1213 (deadlock), 1205 (lock wait), 2006/2013 (connection lost) |
| SQLite | SQLITE_BUSY, SQLITE_LOCKED, I/O error (transient media) |
| Kafka | QueueFull, broker unavailable |
| JetStream | Timeout, temporary server error |
| NATS | I/O error, server -ERR (transient) |
| Redis | I/O error, connection reset |

### C-ERR-04: Error Method Parity (Extended)

Building on C-ERR-02, all database error types MUST provide:

```rust
fn is_transient(&self) -> bool;
fn is_connection_error(&self) -> bool;
fn is_serialization_failure(&self) -> bool;
fn is_deadlock(&self) -> bool;
fn is_unique_violation(&self) -> bool;
fn is_constraint_violation(&self) -> bool;
fn is_retryable(&self) -> bool;  // = is_transient() for databases
fn error_code(&self) -> Option<&str>;
```

Current status:
- PostgreSQL: Implemented (all methods)
- MySQL: Implemented (all methods)
- SQLite: Implemented (all applicable methods; `is_serialization_failure`/`is_deadlock` N/A)

### C-ERR-05: Messaging Error Classification

Messaging error types MUST provide:

```rust
fn is_transient(&self) -> bool;
fn is_connection_error(&self) -> bool;
fn is_capacity_error(&self) -> bool;  // queue full, rate limited
fn is_timeout(&self) -> bool;
fn is_retryable(&self) -> bool;
```

Current status:
- NATS: Implemented (`src/messaging/nats.rs`)
- JetStream: Implemented (`src/messaging/jetstream.rs`)
- Kafka: Implemented (`src/messaging/kafka.rs`)
- Redis: Implemented (`src/messaging/redis.rs`)

## 3. Idempotency Contracts

### C-IMP-01: Producer Idempotency

Systems with at-least-once delivery MUST support deduplication:

| System | Mechanism | Scope | Configuration |
|--------|-----------|-------|--------------|
| Kafka | Sequence numbers | Per-partition, per-producer session | `enable.idempotence=true` |
| JetStream | Duplicate window | Per-stream | `duplicate_window: Duration` |
| Redis | None built-in | N/A | Application-level |
| Database | None built-in | N/A | Application-level |

### C-IMP-02: Consumer Idempotency

Consumers of at-least-once systems MUST handle redelivery:

1. **Kafka**: Consumer offset tracking + application-level dedup.
2. **JetStream**: Explicit ack + `max_deliver` limit + dead-letter on exhaust.
3. **Database transactions**: Natural idempotency via UPSERT or conditional INSERT.

### C-IMP-03: Request-Level Idempotency Keys

For application-level idempotency, a shared contract:

| Field | Type | Semantics |
|-------|------|-----------|
| `idempotency_key` | `String` | Caller-provided unique identifier |
| `ttl` | `Duration` | How long to remember the key |
| `result_cache` | `bool` | Whether to cache and return previous result |

This contract is NOT implemented at the framework level. Applications must
implement using database UPSERT or a dedicated key-value store.

## 4. Delivery Guarantee Contracts

### C-DLV-01: Delivery Semantics Matrix

Each system MUST document its delivery guarantees:

| System | Default | Best Available | Mechanism |
|--------|---------|---------------|-----------|
| PostgreSQL | Exactly-once (per transaction) | Exactly-once | ACID transactions |
| MySQL | Exactly-once (per transaction) | Exactly-once | ACID transactions |
| SQLite | Exactly-once (per transaction) | Exactly-once | ACID transactions |
| Kafka | At-least-once | Exactly-once | Idempotent + transactional producer |
| JetStream | At-least-once | Effectively-once | Explicit ack + dedup window |
| NATS core | At-most-once | At-most-once | Fire-and-forget |
| Redis pub/sub | At-most-once | At-most-once | No persistence |

### C-DLV-02: Acknowledgement Contract

Systems with explicit acknowledgement MUST define:

| System | Ack Type | Timeout | Redelivery |
|--------|---------|---------|-----------|
| Kafka | Offset commit | Configurable | From last committed offset |
| JetStream | Explicit/None/All | `ack_wait` duration | Up to `max_deliver` times |
| Database | Transaction commit | Connection timeout | N/A (rollback on failure) |

### C-DLV-03: Dead Letter Contract

Systems with bounded redelivery MUST define dead-letter behavior:

1. **JetStream**: After `max_deliver` attempts, message is dropped or moved to advisory subject.
2. **Kafka**: Application-level dead-letter topic (not built into protocol).
3. **Database**: Failed transactions surface error to caller; no built-in DLQ.

## 5. Failure Propagation Contracts

### C-FPR-01: Circuit Breaker Integration

The circuit breaker combinator MUST integrate with retry:

1. Retry attempts that trigger circuit-breaker open MUST stop retrying.
2. Circuit-breaker half-open probes MUST NOT count as retry attempts.
3. Circuit-breaker metrics MUST track retry-exhausted failures separately.

Reference: `src/combinator/circuit_breaker.rs`

### C-FPR-02: Rate Limiter Integration

Rate limiting MUST integrate with retry:

1. Rate-limited rejections are NOT retryable errors (backpressure signal).
2. Retry delay MUST respect rate-limiter token availability.
3. `WaitStrategy::Block` integrates naturally with retry delay.
4. `WaitStrategy::Reject` should surface as a distinct error category.

Reference: `src/combinator/rate_limit.rs`

### C-FPR-03: Failure Escalation Chain

Failures MUST escalate through a defined chain:

```text
Operation Error
  -> Retry (if eligible, up to max_attempts)
    -> Circuit Breaker (if open, reject immediately)
      -> Pool Exhaustion (if no connections, timeout)
        -> Caller Error (with full causal chain)
```

Each level MUST preserve the original error for diagnostics.

## 6. Backpressure Contracts

### C-BPR-01: Queue Depth Signals

All queued operations MUST expose depth for backpressure:

| System | Signal | Threshold | Action |
|--------|--------|-----------|--------|
| Connection pool | `waiters` count | Configurable | Shed load or scale |
| Kafka producer | Queue size | `queue.buffering.max.messages` | `QueueFull` error |
| Rate limiter | Token count | Configured rate | Wait or reject |

### C-BPR-02: Timeout as Backpressure

Timeouts MUST act as backpressure release valves:

1. Connection timeout prevents unbounded pool waits.
2. Query timeout prevents long-running queries from starving the pool.
3. Retry budget prevents retry storms.
4. All timeouts respect `Cx` cancellation.

## 7. Implementation Status

### Retry Status

| Feature | Status | Location |
|---------|--------|----------|
| Generic retry combinator | Implemented | `src/combinator/retry.rs` |
| PostgreSQL transaction retry | Implemented | `src/database/transaction.rs` |
| MySQL transaction retry | Implemented | `src/database/transaction.rs` |
| SQLite transaction retry | Implemented | `src/database/transaction.rs` |
| Connection pool retry | Implemented | `src/database/pool.rs` (`get_with_retry`) |

### Error Classification Status

| Backend | `is_transient` | `is_connection_error` | `is_serialization_failure` | `is_deadlock` | `is_retryable` |
|---------|---------------|----------------------|---------------------------|---------------|----------------|
| PostgreSQL | Implemented | Implemented | Implemented | Implemented | Implemented |
| MySQL | Implemented | Implemented | Implemented | Implemented | Implemented |
| SQLite | Implemented | Implemented | N/A | N/A | Implemented |

### Messaging Error Classification Status (C-ERR-05)

| Backend | `is_transient` | `is_connection_error` | `is_capacity_error` | `is_timeout` | `is_retryable` |
|---------|---------------|----------------------|---------------------|--------------|----------------|
| NATS | Implemented | Implemented | Implemented | Implemented | Implemented |
| JetStream | Implemented | Implemented | Implemented | Implemented | Implemented |
| Kafka | Implemented | Implemented | Implemented | Implemented | Implemented |
| Redis | Implemented | Implemented | Implemented | Implemented | Implemented |

### Idempotency Status

| Feature | Status |
|---------|--------|
| Kafka idempotent producer | Documented, delegates to rdkafka |
| JetStream duplicate window | Configured in stream config |
| Request-level idempotency keys | NOT IMPLEMENTED |

## 8. Contract Dependencies

| Contract | Depends On | Blocks |
|----------|-----------|--------|
| C-RTY-01..05 | T6.5 (pool/txn contracts), combinator/retry.rs | T6.10, T6.12 |
| C-ERR-03..05 | T6.2 (PG), T6.3 (MySQL), T6.4 (SQLite) error types | T6.10 |
| C-IMP-01..03 | T6.6 (Redis), T6.7 (NATS), T6.8 (Kafka) | T6.12 |
| C-DLV-01..03 | All messaging beads | T6.12, T9.3 |
| C-FPR-01..03 | combinator/circuit_breaker.rs, rate_limit.rs | T6.10 |
| C-BPR-01..02 | T6.5 (pool contracts), T6.8 (Kafka) | T6.10 |

## References

- `src/combinator/retry.rs` — Generic retry combinator
- `src/combinator/circuit_breaker.rs` — Circuit breaker state machine
- `src/combinator/rate_limit.rs` — Rate limiter
- `src/database/transaction.rs` — Transaction retry helpers
- `src/database/postgres.rs` — PostgreSQL error classification
- `src/database/mysql.rs` — MySQL error types
- `src/database/sqlite.rs` — SQLite error types
- `src/messaging/kafka.rs` — Kafka producer/consumer
- `src/messaging/jetstream.rs` — JetStream delivery semantics
- `src/messaging/nats.rs` — NATS core pub/sub
- `src/messaging/redis.rs` — Redis commands and pub/sub
- `docs/tokio_db_pool_transaction_observability_contracts.md` — T6.5 contracts
