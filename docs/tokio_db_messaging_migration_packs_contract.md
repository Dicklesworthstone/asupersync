# T6.11 — Migration Packs for Database and Messaging Ecosystems

**Bead**: `asupersync-2oh2u.6.11`
**Track**: T6 (Database and messaging ecosystem closure)
**Depends on**: T6.10 (integration and fault injection), T6.12 (unit-test matrix)
**Unblocks**: T9.2 (domain-specific migration cookbooks), T8.9 (replacement-readiness gate)
**Status**: In progress

## Purpose

Deliver self-contained migration guides that translate common usage patterns from
tokio-ecosystem database and messaging crates to equivalent Asupersync patterns.
Each migration pack includes before/after code, error-handling changes, and
operational caveats.

## Scope

| Source Crate | Asupersync Target | Migration Pack ID |
|-------------|-------------------|-------------------|
| `sqlx` (PostgreSQL) | `database::postgres` | MIG-PG |
| `tokio-postgres` | `database::postgres` | MIG-PG-TOKIO |
| `sqlx` (MySQL) | `database::mysql` | MIG-MY |
| `mysql_async` | `database::mysql` | MIG-MY-TOKIO |
| `sqlx` (SQLite) | `database::sqlite` | MIG-SQ |
| `bb8` / `deadpool` | `database::pool` | MIG-POOL |
| `redis` (crate) | `messaging::redis` | MIG-RD |
| `async-nats` | `messaging::nats` + `messaging::jetstream` | MIG-NT |
| `rdkafka` | `messaging::kafka` + `messaging::kafka_consumer` | MIG-KF |

## 1. PostgreSQL Migration (MIG-PG)

### MIG-PG-01: Connection Setup

| Before (`sqlx`) | After (Asupersync) |
|-----------------|-------------------|
| `PgPoolOptions::new().connect(url).await?` | `PgConnection::connect(&cx, url).resolved()?` |
| `PgConnectOptions::from_str(url)?` | `PgConnectOptions::parse(url)?` |

Key differences:
- Asupersync requires a `Cx` capability for all I/O operations.
- `Outcome<T, E>` replaces `Result<T, E>` for cancel-aware error handling.
- `.resolved()?` unwraps the `Outcome` into a `Result`.

### MIG-PG-02: Query Execution

| Before (`sqlx`) | After (Asupersync) |
|-----------------|-------------------|
| `sqlx::query("SELECT ...").fetch_all(&pool).await?` | `conn.query(&cx, "SELECT ...").resolved()?` |
| `sqlx::query("SELECT ...").fetch_one(&pool).await?` | `conn.query_one(&cx, "SELECT ...").resolved()?` |
| `sqlx::query("INSERT ...").execute(&pool).await?` | `conn.execute(&cx, "INSERT ...").resolved()?` |

### MIG-PG-03: Parameterized Queries

| Before (`sqlx`) | After (Asupersync) |
|-----------------|-------------------|
| `sqlx::query("... $1").bind(val).fetch_all(&pool).await?` | `conn.query_params(&cx, "... $1", &[&val]).resolved()?` |

### MIG-PG-04: Transactions

| Before (`sqlx`) | After (Asupersync) |
|-----------------|-------------------|
| `let tx = pool.begin().await?; ... tx.commit().await?` | `with_pg_transaction(&mut conn, &cx, \|tx, cx\| async { ... }).resolved()?` |
| Manual retry loop | `with_pg_transaction_retry(&mut conn, &cx, &policy, \|tx, cx\| async { ... })` |

### MIG-PG-05: Prepared Statements

| Before (`sqlx`) | After (Asupersync) |
|-----------------|-------------------|
| Implicit via `sqlx::query` | `let stmt = conn.prepare(&cx, sql).resolved()?; conn.query_prepared(&cx, &stmt, &params).resolved()?` |

### MIG-PG-06: Error Handling

| Before (`sqlx`) | After (Asupersync) |
|-----------------|-------------------|
| `match err.as_database_error()` | `if err.is_unique_violation()` |
| Check SQLSTATE manually | `err.is_serialization_failure()`, `err.is_deadlock()` |
| `err.code()` returns `Option<Cow<str>>` | `err.error_code()` returns `Option<&str>` |

### MIG-PG-07: Row Access

| Before (`sqlx`) | After (Asupersync) |
|-----------------|-------------------|
| `row.get::<i32, _>("col")` | `row.get_i32("col")` or `row.get_typed::<i32>("col")` |
| `row.try_get("col")?` | `row.get("col")` returns `Option<&PgValue>` |

## 2. PostgreSQL Migration — tokio-postgres (MIG-PG-TOKIO)

### MIG-PG-TOKIO-01: Connection

| Before (`tokio-postgres`) | After (Asupersync) |
|--------------------------|-------------------|
| `let (client, conn) = tokio_postgres::connect(url, NoTls).await?; tokio::spawn(conn);` | `let conn = PgConnection::connect(&cx, url).resolved()?;` |

Key difference: Asupersync manages the connection lifecycle internally; no need to
spawn a separate connection task.

### MIG-PG-TOKIO-02: Queries

| Before (`tokio-postgres`) | After (Asupersync) |
|--------------------------|-------------------|
| `client.query("SELECT ...", &[&val]).await?` | `conn.query_params(&cx, "SELECT ...", &[&val]).resolved()?` |
| `client.execute("INSERT ...", &[]).await?` | `conn.execute(&cx, "INSERT ...").resolved()?` |

## 3. MySQL Migration (MIG-MY)

### MIG-MY-01: Connection Setup

| Before (`sqlx`) | After (Asupersync) |
|-----------------|-------------------|
| `MySqlPoolOptions::new().connect(url).await?` | `MySqlConnection::connect(&cx, url).resolved()?` |

### MIG-MY-02: Query Execution

| Before (`sqlx`) | After (Asupersync) |
|-----------------|-------------------|
| `sqlx::query("...").fetch_all(&pool).await?` | `conn.query(&cx, "...").resolved()?` |
| `sqlx::query("...").execute(&pool).await?.rows_affected()` | `conn.execute(&cx, "...").resolved()?` (returns `u64` directly) |

### MIG-MY-03: Transactions

| Before (`sqlx`) | After (Asupersync) |
|-----------------|-------------------|
| `let tx = pool.begin().await?; ... tx.commit().await?` | `with_mysql_transaction(&mut conn, &cx, \|tx, cx\| async { ... }).resolved()?` |
| Manual retry | `with_mysql_transaction_retry(&mut conn, &cx, &policy, ...)` |

### MIG-MY-04: Error Handling

| Before (`sqlx`) | After (Asupersync) |
|-----------------|-------------------|
| `err.as_database_error().unwrap().code()` | `err.server_code()` or `err.error_code()` |
| Manual deadlock check | `err.is_deadlock()` |

## 4. MySQL Migration — mysql_async (MIG-MY-TOKIO)

### MIG-MY-TOKIO-01: Connection

| Before (`mysql_async`) | After (Asupersync) |
|-----------------------|-------------------|
| `Pool::new(url); let conn = pool.get_conn().await?;` | `MySqlConnection::connect(&cx, url).resolved()?` |

### MIG-MY-TOKIO-02: Queries

| Before (`mysql_async`) | After (Asupersync) |
|-----------------------|-------------------|
| `conn.query_drop("...").await?` | `conn.execute(&cx, "...").resolved()?` |
| `conn.query_map("...", \|row\| ...).await?` | `conn.query(&cx, "...").resolved()?.iter().map(...)` |

## 5. SQLite Migration (MIG-SQ)

### MIG-SQ-01: Connection Setup

| Before (`sqlx`) | After (Asupersync) |
|-----------------|-------------------|
| `SqlitePoolOptions::new().connect("sqlite::memory:").await?` | `SqliteConnection::open_in_memory(&cx).resolved()?` |
| `SqlitePoolOptions::new().connect("sqlite:path.db").await?` | `SqliteConnection::open(&cx, "path.db").resolved()?` |

### MIG-SQ-02: Query Execution

| Before (`sqlx`) | After (Asupersync) |
|-----------------|-------------------|
| `sqlx::query("...").execute(&pool).await?` | `conn.execute(&cx, "...", &[]).resolved()?` |
| `sqlx::query("...").fetch_all(&pool).await?` | `conn.query(&cx, "...", &[]).resolved()?` |
| `sqlx::query_scalar("SELECT count(*)...").fetch_one(&pool).await?` | `conn.query_row(&cx, "SELECT count(*)...", &[]).resolved()?` |

### MIG-SQ-03: Transactions

| Before (`sqlx`) | After (Asupersync) |
|-----------------|-------------------|
| `pool.begin().await?` | `with_sqlite_transaction(&conn, &cx, ...)` |
| N/A | `with_sqlite_transaction_immediate(&conn, &cx, ...)` (IMMEDIATE lock) |
| Manual retry | `with_sqlite_transaction_retry(&conn, &cx, &policy, ...)` |

### MIG-SQ-04: Row Access

| Before (`sqlx`) | After (Asupersync) |
|-----------------|-------------------|
| `row.get::<i64, _>("col")` | `row.get_i64("col")` |
| `row.get::<String, _>("col")` | `row.get_str("col").map(String::from)` |
| `row.get::<Vec<u8>, _>("col")` | `row.get_blob("col")` |

### MIG-SQ-05: Error Handling

| Before (`sqlx`) | After (Asupersync) |
|-----------------|-------------------|
| `DatabaseError::code()` | `err.error_code()` |
| Manual SQLITE_BUSY check | `err.is_busy()` / `err.is_transient()` |
| Manual constraint check | `err.is_constraint_violation()` / `err.is_unique_violation()` |

## 6. Connection Pool Migration (MIG-POOL)

### MIG-POOL-01: Pool Creation

| Before (`bb8`) | After (Asupersync) |
|----------------|-------------------|
| `Pool::builder().max_size(10).build(manager).await?` | `DbPool::new(manager, DbPoolConfig::default().max_size(10))` |

| Before (`deadpool`) | After (Asupersync) |
|---------------------|-------------------|
| `Pool::builder(manager).max_size(10).build()?` | `DbPool::new(manager, DbPoolConfig::default().max_size(10))` |

### MIG-POOL-02: Connection Checkout

| Before (`bb8` / `deadpool`) | After (Asupersync) |
|-----------------------------|-------------------|
| `pool.get().await?` | `pool.get()?` (synchronous; the pool manages async internally) |
| `pool.get_timeout(dur).await?` | `pool.get()?` (uses `DbPoolConfig::connection_timeout`) |
| Try immediate acquire | `pool.try_get()` returns `Result<Option<_>, DbPoolError<_>>` |

### MIG-POOL-03: Pool Configuration

| Before | After (Asupersync `DbPoolConfig`) |
|--------|----------------------------------|
| `max_size(n)` | `.max_size(n)` |
| `min_idle(n)` | `.min_idle(n)` |
| `idle_timeout(dur)` | `.idle_timeout(dur)` |
| `max_lifetime(dur)` | `.max_lifetime(dur)` |
| `connection_timeout(dur)` | `.connection_timeout(dur)` |
| `test_on_checkout(true)` | `.validate_on_checkout(true)` |

### MIG-POOL-04: Pool Stats

| Before | After (`DbPoolStats`) |
|--------|----------------------|
| `pool.state().connections` | `pool.stats().total` |
| `pool.state().idle_connections` | `pool.stats().idle` |
| N/A | `pool.stats().total_acquisitions`, `.total_creates`, `.total_discards` |

### MIG-POOL-05: Pool Lifecycle

| Before | After (Asupersync) |
|--------|-------------------|
| Drop pool | `pool.close()` then drop |
| N/A | `pool.evict_stale()` — explicit stale connection cleanup |
| N/A | `pool.warm_up()` — pre-populate to `min_idle` |

### MIG-POOL-06: Retry with Pool

| Before (manual loop) | After (Asupersync) |
|---------------------|-------------------|
| Custom retry loop over `pool.get()` | `pool.get_with_retry(&RetryPolicy::default_retry())?` |

## 7. Redis Migration (MIG-RD)

### MIG-RD-01: Connection

| Before (`redis` crate) | After (Asupersync) |
|------------------------|-------------------|
| `let client = redis::Client::open(url)?; let mut con = client.get_multiplexed_async_connection().await?;` | `let client = RedisClient::connect(&cx, url)?;` |

### MIG-RD-02: Commands

| Before (`redis` crate) | After (Asupersync) |
|------------------------|-------------------|
| `con.get::<_, String>("key").await?` | `client.get(&cx, "key")?` returns `Option<Vec<u8>>` |
| `con.set::<_, _, ()>("key", "val").await?` | `client.set(&cx, "key", b"val", None)?` |
| `con.del::<_, i64>("key").await?` | `client.del(&cx, &["key"])?` |
| `con.incr::<_, _, i64>("key", 1).await?` | `client.incr(&cx, "key")?` |
| `redis::pipe().cmd("SET")...query_async(&mut con).await?` | `client.pipeline().cmd(&["SET", ...]).exec(&cx)?` |

### MIG-RD-03: Pub/Sub

| Before (`redis` crate) | After (Asupersync) |
|------------------------|-------------------|
| `let mut pubsub = con.into_pubsub(); pubsub.subscribe("ch").await?;` | `let mut ps = client.pubsub(&cx)?; ps.subscribe(&cx, "ch")?;` |
| `pubsub.on_message().next().await` | `ps.next_event(&cx)?` |
| `con.publish("ch", data).await?` | `client.publish(&cx, "ch", data)?` |

### MIG-RD-04: Transactions

| Before (`redis` crate) | After (Asupersync) |
|------------------------|-------------------|
| `redis::transaction(&mut con, &["key"], \|pipe\| ...)` | `client.watch(&cx, &["key"])?; let mut tx = client.transaction(&cx)?; tx.cmd(&["SET", ...]); tx.exec(&cx)?;` |

### MIG-RD-05: Error Handling

| Before (`redis` crate) | After (Asupersync) |
|------------------------|-------------------|
| `err.kind()` / `err.is_io_error()` | `err.is_connection_error()` / `err.is_transient()` |
| Manual timeout detection | `err.is_timeout()` |
| N/A | `err.is_capacity_error()` (pool exhausted) |

## 8. NATS and JetStream Migration (MIG-NT)

### MIG-NT-01: NATS Connection

| Before (`async-nats`) | After (Asupersync) |
|----------------------|-------------------|
| `async_nats::connect(url).await?` | `NatsClient::connect(&cx, url)?` |

### MIG-NT-02: Publish/Subscribe

| Before (`async-nats`) | After (Asupersync) |
|----------------------|-------------------|
| `client.publish("subj", payload.into()).await?` | `client.publish(&cx, "subj", payload)?` |
| `let sub = client.subscribe("subj").await?; sub.next().await` | `let sub = client.subscribe(&cx, "subj")?; sub.next(&cx)?` |
| `client.request("subj", payload.into()).await?` | `client.request(&cx, "subj", payload, timeout)?` |
| `client.queue_subscribe("subj", "q").await?` | `client.queue_subscribe(&cx, "subj", "q")?` |

### MIG-NT-03: JetStream

| Before (`async-nats::jetstream`) | After (Asupersync) |
|---------------------------------|-------------------|
| `let js = async_nats::jetstream::new(client)` | `let js = JetStreamContext::new(client)` |
| `js.create_stream(config).await?` | `js.create_stream(&cx, config)?` |
| `js.publish("subj", data).await?` | `js.publish(&cx, "subj", data)?` |
| `stream.create_consumer(config).await?; consumer.messages().await?` | `js.create_consumer(&cx, "stream", config)?; consumer.pull(&mut client, &cx, batch)?` |
| `msg.ack().await?` | `consumer.ack(&mut client, &cx)?` |

### MIG-NT-04: Error Handling

| Before (`async-nats`) | After (Asupersync) |
|----------------------|-------------------|
| Match on error variants | `err.is_transient()` / `err.is_connection_error()` |

## 9. Kafka Migration (MIG-KF)

### MIG-KF-01: Producer Setup

| Before (`rdkafka`) | After (Asupersync) |
|--------------------|-------------------|
| `ClientConfig::new().set("bootstrap.servers", url).create::<FutureProducer>()?` | `KafkaProducer::new(ProducerConfig::new(vec![url.to_string()]))?` |

### MIG-KF-02: Producing Messages

| Before (`rdkafka`) | After (Asupersync) |
|--------------------|-------------------|
| `producer.send(FutureRecord::to("topic").payload(data).key(key), Duration::from_secs(5)).await?` | `producer.send("topic", Some(key), data)?` |
| `producer.flush(Duration::from_secs(5))?` | `producer.flush(&cx, Duration::from_secs(5))?` |

### MIG-KF-03: Consumer Setup

| Before (`rdkafka`) | After (Asupersync) |
|--------------------|-------------------|
| `ClientConfig::new().set("group.id", "g").set("bootstrap.servers", url).create::<StreamConsumer>()?` | `KafkaConsumer::new(ConsumerConfig::new(vec![url.to_string()], "g"))?` |

### MIG-KF-04: Consuming Messages

| Before (`rdkafka`) | After (Asupersync) |
|--------------------|-------------------|
| `consumer.subscribe(&["topic"])?; consumer.stream().next().await` | `consumer.subscribe(&cx, &["topic"])?; consumer.poll(&cx, timeout)?` |
| `consumer.commit_message(&msg, CommitMode::Async)?` | `consumer.commit_offsets(&cx, &[TopicPartitionOffset::new("topic", partition, offset)])?` |

### MIG-KF-05: Transactional Producer

| Before (`rdkafka`) | After (Asupersync) |
|--------------------|-------------------|
| `producer.init_transactions(timeout)?; producer.begin_transaction()?; ... producer.commit_transaction(timeout)?` | `let tx = producer.begin_transaction(&cx)?; tx.send(...)?; tx.commit(&cx)?;` |

### MIG-KF-06: Error Handling

| Before (`rdkafka`) | After (Asupersync) |
|--------------------|-------------------|
| `match err { KafkaError::MessageProduction(RDKafkaErrorCode::QueueFull) => ...` | `err.is_capacity_error()` |
| Manual transient detection | `err.is_transient()` |

## 10. Cross-Cutting Differences

### CX-01: Cancellation Semantics

All Asupersync database and messaging operations take a `&Cx` parameter. This enables:
- Structured cancellation propagation (cancel-correct by construction).
- `Outcome<T, E>` result type with `Cancelled` variant.
- No silent cancellation or leaked resources.

**Migration pattern**: Replace `.await?` with `.resolved()?` for bridging,
or use native `Outcome` matching for full cancel awareness.

### CX-02: Error Classification Parity

All error types implement a consistent classification API:
- `is_transient()` — safe to retry
- `is_connection_error()` — connection-level failure
- `is_retryable()` — eligible for retry (may be broader than transient)

Database errors additionally provide:
- `is_serialization_failure()`, `is_deadlock()` (PG, MySQL)
- `is_constraint_violation()`, `is_unique_violation()` (all backends)

Messaging errors additionally provide:
- `is_capacity_error()` — backpressure signal
- `is_timeout()` — operation timeout

### CX-03: Pool vs Direct Connection

Asupersync separates pool management (`DbPool<M>`) from connection types.
The `ConnectionManager` trait bridges them. Most tokio-ecosystem crates bundle
pool + connection; Asupersync keeps them orthogonal.

### CX-04: Transaction Helpers

Asupersync provides `with_*_transaction` and `with_*_transaction_retry` free
functions that handle begin/commit/rollback automatically. These replace
manual transaction management patterns common in sqlx and tokio-postgres.

## 11. Operational Caveats

### CAV-01: Feature Flags

Database modules require feature flags: `sqlite`, `postgres`, or `mysql`.
Messaging modules are always available (except on `wasm32`).

### CAV-02: Outcome vs Result

`Outcome<T, E>` is a four-valued type: `Success(T)`, `Error(E)`, `Cancelled`,
`Pending`. Use `.resolved()?` for quick migration from `Result`-based code.
For full cancel-awareness, match on `Outcome` variants directly.

### CAV-03: No Global Runtime

Asupersync has no global runtime. All operations require explicit `Cx` context.
This is the single largest migration friction point.

### CAV-04: Synchronous Pool API

`DbPool::get()` is synchronous (blocking). The pool manages internal async
operations. This differs from `bb8`/`deadpool` where `get()` is async.

## 12. Implementation Status

| Pack | Scenarios | Status |
|------|----------|--------|
| MIG-PG | 7 | Defined |
| MIG-PG-TOKIO | 2 | Defined |
| MIG-MY | 4 | Defined |
| MIG-MY-TOKIO | 2 | Defined |
| MIG-SQ | 5 | Defined |
| MIG-POOL | 6 | Defined |
| MIG-RD | 5 | Defined |
| MIG-NT | 4 | Defined |
| MIG-KF | 6 | Defined |
| Cross-cutting (CX-*) | 4 | Defined |
| Caveats (CAV-*) | 4 | Defined |
| **Total** | **49** | |

## 13. Contract Dependencies

```
T6.10 (Integration/FI) ────────┐
T6.12 (Unit-test matrix) ──────┼──> T6.11 (THIS: migration packs)
                                │       ↓
                                │   T9.2 (domain cookbooks)
                                └   T8.9 (readiness gate)
```

## 14. Source Module References

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
