# T6.12 — Exhaustive Unit-Test Matrix for Database and Messaging Semantics

**Bead**: `asupersync-2oh2u.6.12`
**Track**: T6 (Database and messaging ecosystem closure)
**Depends on**: T6.2-T6.10 (all database/messaging beads)
**Unblocks**: T6.13 (end-to-end data-path scripts), T6.11 (migration packs), T8.11 (cross-track thresholds)
**Status**: In progress

## Purpose

Define and enforce an exhaustive unit-test coverage matrix that validates every T6.2-T6.10
behavior with boundary, error, cancellation, and idempotency assertions. This bead serves
as the quality gate: no downstream T6 beads (T6.13, T6.11) or cross-track thresholds (T8.11)
can be closed without this matrix passing.

## Scope

| Domain | Coverage Requirements |
|--------|----------------------|
| PostgreSQL (T6.2) | Error classification, connection lifecycle, serialization/deadlock detection |
| MySQL (T6.3) | Error classification, server code mapping, connection lifecycle |
| SQLite (T6.4) | Error classification, busy/locked detection, async wrapper |
| Pool contracts (T6.5) | Lifecycle, config parity, stats, health check, cancel safety, eviction |
| Redis parity (T6.6) | Error variants, pub/sub, commands, connection management |
| NATS/JetStream (T6.7) | Error variants, delivery semantics, consumer lifecycle |
| Kafka (T6.8) | Error variants, producer/consumer lifecycle, transactional stubs |
| Retry/failure (T6.9) | Backoff calculation, eligibility, cancel-aware retry, error predicates |
| Integration (T6.10) | Cross-module fault injection, cancel safety, stats accuracy |

## 1. Coverage Matrix by Bead

### UM-6.2: PostgreSQL Client Tests

| ID | Assertion | Category |
|----|-----------|----------|
| UM-PG-01 | `is_serialization_failure()` true for SQLSTATE 40001 | error_classification |
| UM-PG-02 | `is_deadlock()` true for SQLSTATE 40P01 | error_classification |
| UM-PG-03 | `is_unique_violation()` true for SQLSTATE 23505 | error_classification |
| UM-PG-04 | `is_constraint_violation()` true for 23xxx family | error_classification |
| UM-PG-05 | `is_connection_error()` true for Io/ConnectionClosed | error_classification |
| UM-PG-06 | `is_transient()` consistent with `is_retryable()` | error_classification |
| UM-PG-07 | `error_code()` returns SQLSTATE string | error_classification |
| UM-PG-08 | Error Display includes category and detail | display_format |

### UM-6.3: MySQL Client Tests

| ID | Assertion | Category |
|----|-----------|----------|
| UM-MY-01 | `is_serialization_failure()` true for server code in serialization set | error_classification |
| UM-MY-02 | `is_deadlock()` true for error 1213 | error_classification |
| UM-MY-03 | `is_unique_violation()` true for duplicate-entry codes | error_classification |
| UM-MY-04 | `is_constraint_violation()` true for constraint family | error_classification |
| UM-MY-05 | `is_connection_error()` true for Io/ConnectionClosed | error_classification |
| UM-MY-06 | `is_transient()` consistent with `is_retryable()` | error_classification |
| UM-MY-07 | Error Display includes server code and message | display_format |

### UM-6.4: SQLite Client Tests

| ID | Assertion | Category |
|----|-----------|----------|
| UM-SQ-01 | `is_constraint_violation()` true for constraint errors | error_classification |
| UM-SQ-02 | `is_unique_violation()` true for UNIQUE constraint | error_classification |
| UM-SQ-03 | `is_connection_error()` true for Io/ConnectionClosed | error_classification |
| UM-SQ-04 | `is_transient()` true for SQLITE_BUSY | error_classification |
| UM-SQ-05 | `is_retryable()` consistent with `is_transient()` | error_classification |
| UM-SQ-06 | Error Display includes error category | display_format |

### UM-6.5: Pool/Transaction/Observability Tests

| ID | Assertion | Category |
|----|-----------|----------|
| UM-POOL-01 | Acquire-release lifecycle preserves total count | pool_lifecycle |
| UM-POOL-02 | Validation failure triggers discard + recreate | pool_lifecycle |
| UM-POOL-03 | Capacity enforcement at max_size | pool_lifecycle |
| UM-POOL-04 | Stale eviction respects idle_timeout/max_lifetime | pool_lifecycle |
| UM-POOL-05 | Close rejects new acquires | pool_lifecycle |
| UM-POOL-06 | Connect failure propagates cleanly | pool_lifecycle |
| UM-POOL-07 | Warm-up populates min_idle connections | pool_lifecycle |
| UM-POOL-08 | Stats: total == idle + active | pool_stats |
| UM-POOL-09 | Stats: total <= max_size always | pool_stats |
| UM-POOL-10 | Stats: total_acquisitions >= total_creates | pool_stats |
| UM-TXN-01 | RetryPolicy exponential backoff formula | transaction |
| UM-TXN-02 | RetryPolicy edge cases (none, overflow, zero, cap) | transaction |

### UM-6.6: Redis Error and Command Tests

| ID | Assertion | Category |
|----|-----------|----------|
| UM-RD-01 | All 6 RedisError variants constructible | error_variants |
| UM-RD-02 | `is_transient()` correct for each variant | error_classification |
| UM-RD-03 | `is_connection_error()` correct for Io variant | error_classification |
| UM-RD-04 | `is_capacity_error()` true for PoolExhausted | error_classification |
| UM-RD-05 | Error Display non-empty for all variants | display_format |
| UM-RD-06 | Error source chain correct for Io variant | error_chain |

### UM-6.7: NATS and JetStream Tests

| ID | Assertion | Category |
|----|-----------|----------|
| UM-NT-01 | All 8 NatsError variants constructible | error_variants |
| UM-NT-02 | `is_transient()` correct for each variant | error_classification |
| UM-NT-03 | Error Display non-empty for all variants | display_format |
| UM-JS-01 | All 7 JsError variants constructible | error_variants |
| UM-JS-02 | `is_transient()` correct for each variant | error_classification |
| UM-JS-03 | Error Display non-empty for all variants | display_format |
| UM-JS-04 | JsError::Nats wraps NatsError correctly | error_chain |

### UM-6.8: Kafka Error and Lifecycle Tests

| ID | Assertion | Category |
|----|-----------|----------|
| UM-KF-01 | All 9 KafkaError variants constructible | error_variants |
| UM-KF-02 | `is_transient()` correct (QueueFull=true, Config=false) | error_classification |
| UM-KF-03 | `is_capacity_error()` true for QueueFull | error_classification |
| UM-KF-04 | Error Display non-empty for all variants | display_format |
| UM-KF-05 | Producer config validates non-empty bootstrap | config_validation |
| UM-KF-06 | Consumer config validates group_id required | config_validation |

### UM-6.9: Retry and Failure Contract Tests

| ID | Assertion | Category |
|----|-----------|----------|
| UM-RTY-01 | Shared retry policy structure complete | retry_policy |
| UM-RTY-02 | Exponential backoff formula correct | retry_policy |
| UM-RTY-03 | Max delay cap enforced | retry_policy |
| UM-RTY-04 | Zero base delay produces zero delays | retry_policy |
| UM-RTY-05 | Overflow safety (u32::MAX attempt) | retry_policy |
| UM-RTY-06 | RetryPolicy::none() returns zero delay, 0 retries | retry_policy |

### UM-6.10: Integration and Fault Injection Tests

| ID | Assertion | Category |
|----|-----------|----------|
| UM-INT-01 | Contract doc covers all 29 scenarios | doc_completeness |
| UM-INT-02 | JSON artifact matches doc | artifact_consistency |
| UM-INT-03 | Fault injection tests present for pool failures | fault_injection |
| UM-INT-04 | Cancel safety tests present | cancel_safety |
| UM-INT-05 | Cross-backend error normalization tested | error_normalization |

## 2. Cross-Backend Parity Requirements

All database backends MUST have equivalent test coverage for:

| Property | PostgreSQL | MySQL | SQLite |
|----------|-----------|-------|--------|
| `is_connection_error()` | UM-PG-05 | UM-MY-05 | UM-SQ-03 |
| `is_transient()` | UM-PG-06 | UM-MY-06 | UM-SQ-04 |
| `is_retryable()` | UM-PG-06 | UM-MY-06 | UM-SQ-05 |
| `is_constraint_violation()` | UM-PG-04 | UM-MY-04 | UM-SQ-01 |
| `is_unique_violation()` | UM-PG-03 | UM-MY-03 | UM-SQ-02 |
| Error Display | UM-PG-08 | UM-MY-07 | UM-SQ-06 |

## 3. Messaging Error Parity Requirements

All messaging backends MUST have equivalent test coverage for:

| Property | Kafka | Redis | NATS | JetStream |
|----------|-------|-------|------|-----------|
| Variant constructibility | UM-KF-01 | UM-RD-01 | UM-NT-01 | UM-JS-01 |
| `is_transient()` | UM-KF-02 | UM-RD-02 | UM-NT-02 | UM-JS-02 |
| Error Display | UM-KF-04 | UM-RD-05 | UM-NT-03 | UM-JS-03 |

## 4. Coverage Threshold Gates

| Metric | Threshold | Enforcement |
|--------|-----------|-------------|
| Total T6 test functions (tests/ dir) | >= 150 | CI gate |
| Total T6 inline tests (src/ dir) | >= 100 | CI gate |
| Contract doc completeness (T6.5/T6.9/T6.10) | 3/3 | CI gate |
| JSON artifact consistency | All scenarios present | CI gate |
| Cross-backend error parity | 6 properties x 3 backends | CI gate |
| Messaging error parity | 3 properties x 4 systems | CI gate |
| Pool lifecycle scenarios | >= 7 | CI gate |
| Fault injection scenarios | >= 5 | CI gate |
| Cancel safety scenarios | >= 3 | CI gate |

## 5. Test File Inventory Requirements

The following test files MUST exist and contain non-zero tests:

| File | Purpose | Min Tests |
|------|---------|-----------|
| `tests/tokio_db_pool_transaction_observability_contracts.rs` | T6.5 contracts | 20 |
| `tests/tokio_retry_idempotency_failure_contracts.rs` | T6.9 contracts | 10 |
| `tests/tokio_db_messaging_integration.rs` | T6.10 integration | 30 |
| `tests/database_pool_integration.rs` | Pool lifecycle | 15 |
| `tests/e2e_database.rs` | Database E2E | 3 |
| `tests/e2e_database_migration.rs` | Migration/SQLite | 10 |

## 6. Inline Test Requirements

Source modules MUST contain inline unit tests:

| Module | Min Inline Tests |
|--------|-----------------|
| `src/database/pool.rs` | 10 |
| `src/database/postgres.rs` | 3 |
| `src/database/mysql.rs` | 10 |
| `src/database/sqlite.rs` | 3 |
| `src/messaging/kafka.rs` | 5 |
| `src/messaging/kafka_consumer.rs` | 3 |
| `src/messaging/nats.rs` | 10 |
| `src/messaging/jetstream.rs` | 5 |
| `src/messaging/redis.rs` | 5 |

## 7. Document and Artifact Requirements

### DOC-M-01: This contract document MUST contain:
1. Coverage matrix by bead (sections 1-6).
2. Cross-backend parity tables.
3. Threshold gates.
4. File inventory requirements.

### DOC-M-02: JSON artifact MUST contain:
1. `schema_version` field.
2. `assertions` array with UM-* IDs, categories, and systems.
3. `thresholds` object with min test counts.
4. `file_inventory` with required test files.
5. `upstream_dependencies` listing T6.2-T6.10.

### DOC-M-03: Source module references:
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

| Category | Assertions | Status |
|----------|-----------|--------|
| PostgreSQL (UM-PG-*) | 8 | Enforced |
| MySQL (UM-MY-*) | 7 | Enforced |
| SQLite (UM-SQ-*) | 6 | Enforced |
| Pool/Transaction (UM-POOL/TXN-*) | 12 | Enforced |
| Redis (UM-RD-*) | 6 | Enforced |
| NATS (UM-NT-*) | 3 | Enforced |
| JetStream (UM-JS-*) | 4 | Enforced |
| Kafka (UM-KF-*) | 6 | Enforced |
| Retry (UM-RTY-*) | 6 | Enforced |
| Integration (UM-INT-*) | 5 | Enforced |
| Document (DOC-M-*) | 3 | Enforced |
| **Total** | **66** | |

## 9. Contract Dependencies

```
T6.2 (PostgreSQL) ─────────────────┐
T6.3 (MySQL) ──────────────────────┤
T6.4 (SQLite) ─────────────────────┤
T6.5 (Pool/Transaction) ───────────┤
T6.6 (Redis) ──────────────────────┼──> T6.12 (THIS: unit-test matrix)
T6.7 (NATS/JetStream) ─────────────┤       ↓
T6.8 (Kafka) ──────────────────────┤   T6.13 (e2e scripts)
T6.9 (Retry/Failure) ──────────────┤   T6.11 (migration packs)
T6.10 (Integration/FI) ────────────┘   T8.11 (cross-track thresholds)
```
