# T6.5 — Pool, Transaction, and Observability Contracts Across Databases

**Bead**: `asupersync-2oh2u.6.5`
**Track**: T6 (Database and messaging ecosystem closure)
**Status**: Draft (pre-T6.2 closure)

## Purpose

Define shared, executable contracts for connection pooling, transaction lifecycle,
timeout semantics, and telemetry across all supported database backends (PostgreSQL,
MySQL, SQLite). These contracts ensure users get consistent, predictable behavior
regardless of the underlying database engine.

## Scope

| Domain | Scope |
|--------|-------|
| Pool lifecycle | acquire, release, eviction, health checks, warm-up, drain |
| Transaction lifecycle | begin, commit, rollback, savepoint, auto-rollback, retry |
| Timeout semantics | connection timeout, query timeout, idle timeout, max lifetime |
| Telemetry | connection events, query metrics, transaction metrics, pool stats |
| Cancel-safety | cancellation during wait, hold, and transaction |
| Error normalization | common error categories across backends |

## 1. Pool Contracts

### C-POOL-01: Acquire/Release Lifecycle

Every pool implementation MUST support:

1. **Acquire**: `pool.acquire(cx)` returns a `PooledResource` or errors with timeout.
2. **Release**: Dropping `PooledResource` returns the connection to the pool.
3. **Discard**: Connections that fail validation are discarded, not returned.
4. **Eviction**: Idle connections beyond `idle_timeout` are evicted on next sweep.
5. **Lifetime**: Connections exceeding `max_lifetime` are discarded on return.

### C-POOL-02: Configuration Parity

All pool implementations MUST accept these configuration parameters with
consistent semantics:

| Parameter | Type | Default | Semantics |
|-----------|------|---------|-----------|
| `min_idle` | `usize` | 1 | Minimum idle connections maintained |
| `max_size` | `usize` | 10 | Maximum total connections |
| `connection_timeout` | `Duration` | 30s | Max wait for acquire |
| `idle_timeout` | `Duration` | 600s | Max idle before eviction |
| `max_lifetime` | `Duration` | 3600s | Max connection lifetime |
| `validate_on_checkout` | `bool` | true | Run health check before return |

### C-POOL-03: Health Check Protocol

Each backend MUST implement a lightweight health check:

- **PostgreSQL**: Execute `SELECT 1` or empty query (`;`).
- **MySQL**: Execute `SELECT 1` or `COM_PING`.
- **SQLite**: Execute `SELECT 1` (verifies file and WAL are intact).

Health checks MUST:
- Complete within `connection_timeout` or be treated as failure.
- NOT hold locks that prevent concurrent pool operations.
- Discard the connection on failure (NOT return to idle set).

### C-POOL-04: Statistics Contract

All pools MUST expose a `PoolStats` structure with AT MINIMUM:

| Field | Type | Description |
|-------|------|-------------|
| `active` | `usize` | Currently checked-out connections |
| `idle` | `usize` | Available idle connections |
| `total` | `usize` | Total managed connections |
| `max_size` | `usize` | Configured maximum |
| `waiters` | `usize` | Tasks waiting to acquire |
| `total_acquisitions` | `u64` | Lifetime acquire count |
| `total_timeouts` | `u64` | Lifetime timeout count |
| `total_validation_failures` | `u64` | Lifetime validation failure count |

### C-POOL-05: Cancel-Safety

1. **Wait-phase cancellation**: If a task is cancelled while waiting for a
   connection, no resource is leaked. The waiter is removed from the queue.
2. **Hold-phase cancellation**: If a task is cancelled while holding a
   connection, `Drop` returns the connection to the pool.
3. **Transaction-phase cancellation**: If cancelled during a transaction,
   the transaction is rolled back before the connection is returned.

### C-POOL-06: Backpressure

When the pool is at capacity:

1. New acquire requests MUST queue with FIFO ordering.
2. Queued requests MUST respect `connection_timeout`.
3. On timeout, acquire MUST return `PoolError::Timeout`.
4. The pool MUST NOT create connections beyond `max_size`.

### C-POOL-07: Graceful Drain

`pool.close()` MUST:

1. Stop accepting new acquire requests.
2. Wait for all active connections to be returned.
3. Disconnect all connections via `ConnectionManager::disconnect`.
4. Return only after all connections are destroyed.

## 2. Transaction Contracts

### C-TXN-01: Lifecycle

All transaction wrappers MUST follow this lifecycle:

```text
begin() -> [execute statements] -> commit() | rollback()
```

If the transaction is dropped without explicit commit/rollback, it MUST
be rolled back (implicit rollback).

### C-TXN-02: Closure-Based Wrapper

Each backend MUST provide a closure-based transaction helper:

```rust
async fn with_transaction<T, F, Fut>(
    conn: &mut Connection,
    cx: &Cx,
    f: F,
) -> Outcome<T, DbError>
```

Semantics:
- `Outcome::Ok(v)` -> commit, return `Ok(v)`
- `Outcome::Err(e)` -> rollback, return `Err(e)`
- `Outcome::Cancelled(r)` -> rollback, propagate cancellation

### C-TXN-03: Savepoint Support

All backends MUST support nested savepoints:

- **PostgreSQL**: `SAVEPOINT name` / `RELEASE SAVEPOINT name` / `ROLLBACK TO SAVEPOINT name`
- **MySQL**: `SAVEPOINT name` / `RELEASE SAVEPOINT name` / `ROLLBACK TO SAVEPOINT name`
- **SQLite**: `SAVEPOINT name` / `RELEASE name` / `ROLLBACK TO name`

Savepoints MUST be released on success and rolled back on error/cancel.

### C-TXN-04: Retry Policy

A shared `RetryPolicy` MUST be available for transaction retries:

| Field | Type | Semantics |
|-------|------|-----------|
| `max_retries` | `u32` | 0 = no retries |
| `base_delay` | `Duration` | Initial delay |
| `max_delay` | `Duration` | Cap on exponential backoff |

Delay formula: `min(base_delay * 2^attempt, max_delay)`

Retry eligibility:
- **PostgreSQL**: SQLSTATE `40001` (serialization failure)
- **MySQL**: Error 1213 (deadlock), Error 1205 (lock wait timeout)
- **SQLite**: `SQLITE_BUSY` (database locked)

### C-TXN-05: Isolation Level Contract

Backends MUST document supported isolation levels:

| Level | PostgreSQL | MySQL | SQLite |
|-------|-----------|-------|--------|
| `ReadUncommitted` | Yes (maps to ReadCommitted) | Yes | No |
| `ReadCommitted` | Yes (default) | Yes | No |
| `RepeatableRead` | Yes | Yes (default) | No |
| `Serializable` | Yes | Yes | Yes (default) |

SQLite MUST use `DEFERRED` by default and `IMMEDIATE` for write transactions.

## 3. Timeout Contracts

### C-TMO-01: Connection Timeout

Applies during pool acquire when all connections are busy:
- Default: 30 seconds
- Error: `PoolError::Timeout`
- Must respect `Cx` cancellation (shorter effective deadline)

### C-TMO-02: Query Timeout

Not yet implemented at the pool/contract layer. When added:
- Must be per-statement configurable
- Must be enforced via `Cx` budget or explicit deadline
- Must cancel the in-flight query on timeout (PostgreSQL: cancel key, MySQL: KILL QUERY)

### C-TMO-03: Idle Timeout

Connections idle beyond `idle_timeout` are evicted:
- Eviction happens on periodic sweep or next acquire
- Eviction is best-effort (not precise to the millisecond)
- Evicted connections are passed to `ConnectionManager::disconnect`

### C-TMO-04: Max Lifetime

Connections older than `max_lifetime` are discarded on return:
- Prevents connection state accumulation (temp tables, SET variables)
- Checked on every release, not on periodic sweep
- Uses monotonic clock (`Instant`) for comparison

## 4. Observability Contracts

### C-OBS-01: Connection Lifecycle Events

Pools SHOULD emit structured events for:

| Event | Fields | When |
|-------|--------|------|
| `connection.created` | backend, pool_id, conn_id | New connection established |
| `connection.acquired` | pool_id, conn_id, wait_ms | Connection checked out |
| `connection.released` | pool_id, conn_id, held_ms | Connection returned |
| `connection.evicted` | pool_id, conn_id, reason | Connection discarded |
| `connection.validation_failed` | pool_id, conn_id | Health check failed |

### C-OBS-02: Transaction Lifecycle Events

Transaction wrappers SHOULD emit:

| Event | Fields | When |
|-------|--------|------|
| `transaction.begin` | backend, isolation, conn_id | Transaction started |
| `transaction.commit` | conn_id, duration_ms | Successfully committed |
| `transaction.rollback` | conn_id, duration_ms, reason | Rolled back |
| `transaction.retry` | conn_id, attempt, error | Retrying after failure |

### C-OBS-03: Pool Health Metrics

The following metrics MUST be derivable from `PoolStats`:

| Metric | Formula |
|--------|---------|
| Pool utilization | `active / max_size` |
| Wait queue depth | `waiters` |
| Timeout rate | `total_timeouts / total_acquisitions` |
| Validation failure rate | `total_validation_failures / total_acquisitions` |

### C-OBS-04: Slow Query Detection

When query timeout support is added, slow queries SHOULD be flagged:

- Threshold: configurable, default 1 second
- Log: query text (sanitized), duration, backend, connection_id
- Counter: `slow_queries_total` metric

## 5. Error Normalization Contract

### C-ERR-01: Common Error Categories

All database errors MUST be classifiable into these categories:

| Category | PostgreSQL | MySQL | SQLite |
|----------|-----------|-------|--------|
| `ConnectionFailed` | TCP/TLS error | TCP/TLS error | File I/O error |
| `AuthenticationFailed` | SQLSTATE 28xxx | Error 1045 | N/A |
| `QuerySyntax` | SQLSTATE 42xxx | Error 1064 | `SQLITE_ERROR` |
| `ConstraintViolation` | SQLSTATE 23xxx | Error 1062/1451/1452 | `SQLITE_CONSTRAINT` |
| `SerializationFailure` | SQLSTATE 40001 | Error 1213 | `SQLITE_BUSY` |
| `DeadlockDetected` | SQLSTATE 40P01 | Error 1205 | `SQLITE_BUSY` |
| `Timeout` | Pool timeout | Pool timeout | Pool/busy timeout |
| `PoolExhausted` | All in use | All in use | All in use |
| `Cancelled` | `Outcome::Cancelled` | `Outcome::Cancelled` | `Outcome::Cancelled` |

### C-ERR-02: Error Method Parity

Each backend error type MUST provide these classification methods:

```rust
fn is_connection_error(&self) -> bool;
fn is_serialization_failure(&self) -> bool;
fn is_deadlock(&self) -> bool;
fn is_unique_violation(&self) -> bool;
fn is_constraint_violation(&self) -> bool;
fn is_retryable(&self) -> bool;
```

## 6. Implementation Status

### Pool Integration Status

| Backend | Wire Protocol | Pool Integration | Health Check | Stats |
|---------|--------------|-----------------|--------------|-------|
| PostgreSQL | Complete | NOT WIRED (PG-G4) | Not wired | Not wired |
| MySQL | Complete | NOT WIRED (MY-G3) | Not wired | Not wired |
| SQLite | Complete (via blocking pool) | Internal pool only | SELECT 1 | Basic |

### Transaction Helper Status

| Backend | Closure wrapper | Savepoints | Retry policy | Cancel-safety |
|---------|----------------|------------|-------------|---------------|
| PostgreSQL | `with_pg_transaction` | `PgSavepoint` | `with_pg_transaction_retry` | Full |
| MySQL | `with_mysql_transaction` | `MySqlSavepoint` | None (MySQL-specific) | Full |
| SQLite | `with_sqlite_transaction` | `SqliteSavepoint` | None | Full |

### Observability Status

| Feature | Status |
|---------|--------|
| Connection events | NOT IMPLEMENTED |
| Transaction events | NOT IMPLEMENTED |
| Pool stats | Partial (sync pool only) |
| Slow query detection | NOT IMPLEMENTED |

## 7. Contract Dependencies

| Contract | Depends On | Blocks |
|----------|-----------|--------|
| C-POOL-01..07 | T6.2 (Postgres), T6.3 (MySQL), T6.4 (SQLite) | T6.9, T6.12 |
| C-TXN-01..05 | Existing transaction.rs | T6.9 |
| C-TMO-01..04 | C-POOL-02 | T6.10 |
| C-OBS-01..04 | C-POOL-04 | T6.10, T6.13 |
| C-ERR-01..02 | T6.2, T6.3, T6.4 | T6.9 |

## References

- `src/database/pool.rs` — Synchronous database pool
- `src/sync/pool.rs` — Async generic pool trait
- `src/database/transaction.rs` — Transaction helpers
- `src/database/postgres.rs` — PostgreSQL wire protocol
- `src/database/mysql.rs` — MySQL wire protocol
- `src/database/sqlite.rs` — SQLite async wrapper
- `docs/tokio_db_messaging_gap_baseline.md` — T6.1 gap baseline
