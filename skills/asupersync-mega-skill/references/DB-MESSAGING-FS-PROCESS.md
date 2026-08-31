# Database, Messaging, Filesystem, Process, Signal

This file covers the broad system-integration surfaces beyond the core runtime.

## Table of Contents

- [Database](#database)
- [Messaging](#messaging)
- [Filesystem](#filesystem)
- [Process](#process)
- [Signal](#signal)

## Database

Native database surfaces exist behind features:

- `database::sqlite` — blocking-pool bridge over bundled `rusqlite` with
  cancel-safe wrappers that respect region deadlines; row streams are
  connection-exclusive and dropped transactions roll back eagerly (v0.4.0),
- `database::postgres` — native binary protocol v3 directly over `TcpStream`,
  SCRAM-SHA-256 auth,
- `database::mysql` — native wire protocol, native + `caching_sha2` auth.

Feature map: `sqlite`, `postgres`, and `mysql` independently enable their
backend modules; `database` itself is compiled only when at least one is on.
PostgreSQL accepts SCRAM-SHA-256/SCRAM-SHA-256-PLUS and rejects legacy
cleartext/MD5 auth. MySQL deliberately disables `mysql_native_password`; its
two public insecure-compatibility fields remain only so v0.4.3 struct literals
keep compiling and cannot enable the SHA-1 plugin on either the initial or
server-switch path. Migrate the account to `caching_sha2_password`. The current
native client has no completed TLS upgrade path, so TLS-required or preferred
modes fail closed rather than silently continuing in plaintext.

The clients expose prepared-statement, transaction, and connection-reuse
machinery, but they are separate implementations with separate feature gates
and backend-specific cancellation paths. Validate the exact backend operations
you use rather than treating this sentence as cross-backend parity evidence.

During query cancellation/drain, PostgreSQL sends `CancelRequest` on a fresh
socket and MySQL uses `KILL QUERY` on a fresh connection. SQLite tracks queued
versus connection-owning work: cancelling a queued waiter deliberately avoids
connection-global `sqlite3_interrupt`, while a running owner may use the native
interrupt path. `SqliteConnection::interrupt` is also an explicit public
low-level operation and is not a substitute for structured `Cx` cancellation.
Outcome resolution remains backend-specific and should be tested with the exact
query/transaction sequence. SQLite row streams borrow a connection exclusively;
dropping a managed transaction schedules rollback.

Published v0.4.9 strengthens the SQLite terminal boundary in additive ways:

- `with_sqlite_transaction` and `_immediate` poll rollback inside a bounded,
  cancellation-masked commit section before propagating a body error,
  cancellation, panic, or rollback-required result. The original body outcome
  remains primary and `Drop` remains the final best-effort safety net if
  rollback itself does not complete. The focused real-disk cancellation case
  proves that an independent zero-busy-timeout writer can acquire
  `BEGIN IMMEDIATE` immediately after the helper returns.
- `SqliteRow::{column_names_in_order,column_name,column_index}` preserve
  result-set order, duplicate names, and SQLite-style first
  ASCII-case-insensitive lookup. The established `get(name)` and
  `column_names()` behavior remains exact-case/last-duplicate and
  sorted-unique for v0.4.3 compatibility. Use the additive methods when
  projection order or duplicates matter.

`SqliteValue::as_real` and `SqliteRow::get_f64` also retain v0.4.3's possibly
lossy INTEGER-to-binary64 widening. Use `as_real_strict` or `get_f64_strict`
when only SQLite's REAL storage class is acceptable. Do not silently rewrite
the legacy methods: that would be an observable 0.4.x behavior break.

Published v0.4.9 routes SQLite's established `execute`, `query`,
`query_row`, and `query_stream` paths through checked SQL admission and keeps
the explicitly named `*_unchecked` compatibility escape hatches. Public
`validate_checked_sql_statement` and
`validate_checked_sql_batch` helpers expose the shared policy, which now has
parser/resource and statement-cardinality caps plus `VACUUM` rejection. The
policy also rejects extension loading, `PRAGMA`, `ATTACH`/`DETACH`, and
transaction-control SQL that would bypass typed APIs; `ATTACH`/`DETACH` remain
denied even on unchecked paths.

For operators that need stable machine-readable failures, import the v0.4.9
diagnostic family from `asupersync::database::sqlite`:

- `SqliteOperation`, `SqliteErrorCategory`, `SqliteRetryDisposition`,
  and `SqliteErrorDiagnostic` are non-exhaustive, engine-neutral public types;
  `SqliteOperationError` is their private-field wrapper;
- separately named `*_diagnosed` connection and transaction methods cover
  open, execute/query/query-row/batch, begin variants, busy-timeout, close,
  commit, and rollback paths;
- established methods and signatures still return v0.4.3-compatible
  `SqliteError`; do not replace or reinterpret them;
- `SqliteOperationError::diagnostic()` exposes operation/category/retry and
  SQLite primary/extended codes. `Busy` and `Locked` can permit operation retry,
  while interruption and structured cancellation do not become retryable
  database prose;
- parser-originated `rusqlite::Error::SqlInputError` retains its structured
  SQLite codes, and malformed transaction-begin SQL remains `InvalidInput`
  rather than degrading to an unclassified internal failure;
- structured `Cx` cancellation remains outer `Outcome::Cancelled`; ordinary
  `Debug`, `Display`, and automatic error chaining redact SQL, values, paths,
  and engine prose. Call `legacy_error()`, `into_legacy()`, or
  `engine_source()` only at an explicit policy boundary.

The final v0.4.9 neutral-consumer aggregate runs 47 common public-surface cases
across P2-P8 plus eight native-only P5 cancellation cases, reports zero
unexplained divergences, and proves runtime-local pool cleanup on Linux. Its P3
prepared-statement family is the seven-case matrix: positional/named binding,
repeat/reset, schema rebuild, malformed/too-few binds, pre-cancelled reuse, and
contention. Keep the differences explicit: Asupersync rejects a surplus bind
that pinned FrankenSQLite ignores, and Asupersync returns typed busy/locked plus
reuse while the pinned FrankenSQLite call is bounded by a kill-and-reap
watchdog. The terminal decision is `KEEP_CURRENT_RUSQLITE_AND_SQLPARSER`, not a
FrankenSQLite cutover. The evidence does not establish arbitrary-SQL or
performance equivalence, macOS/Windows execution, browser-Wasm support, or
process-global quiescence.

Migration guidance:

- prefer native clients when doing full replacement,
- pass `&Cx` through transactional and query code,
- treat cancellation and deadlines as part of the API contract,
- make connection ownership and pooling explicit.

Important limitation:

- SQLx compile-time `query!` style macros are explicitly unsupported in the repo's migration matrix.
- The compat crate is not a generic SQLx runtime. If you depend on SQLx today,
  retain its existing Tokio runtime boundary until a representative compile and
  runtime test proves a narrower adapter, or redesign around native query paths.

## Messaging

Public external-service messaging surfaces exist under
`src/messaging/` for Redis, NATS, JetStream, Kafka producer, and Kafka consumer
paths. Redis, NATS, and JetStream are native default surfaces. Kafka's public
API is also visible by default, but real broker operations require the `kafka`
feature; without it they fail explicitly with `KafkaError::FeatureDisabled`
(the deterministic broker is test/test-internals only). The README coverage
map classifies messaging clients as In progress / Early. Redis PubSub validates
control acknowledgements as of v0.4.0.

Kafka auto-commit defaults off. If a consumer explicitly enables it, offsets
are stored when polling, before application processing completes, so that mode
can be at-most-once. Choose it only when that delivery contract is acceptable.

The native brokerless FABRIC work is a different support class. Modules such as
`fabric`, `subject`, `consumer`, `service`, `session`, `federation`, `policy`,
and `snapshot` are exposed only with the experimental `messaging-fabric`
feature. They contain substantial public compiler/control/data-model
machinery, but feature-gated source presence is not a production broker,
durability, federation, or interoperability claim. Evaluate the exact layer and
its focused tests before adoption.

Redis RESP3 parsing was hardened in v0.4.5: incremental frame scanning is
linear, nested attribute frames are skipped without consuming aggregate value
slots, and the public attribute decoder remains available. Preserve the
distinction between protocol metadata and response values; do not "fix" the
client path by deleting public attribute support.

The security module also exposes owned typed/raw NKey forms with explicit
secret export and redaction behavior. This is not a full first-party production
identity cutover: the owned text codec remains staged under test configuration,
the incumbent `nkeys::KeyPair` compatibility surface remains, and no generic
Asupersync-owned transcript signer has shipped.

Good external-client fits to inspect first:

- in-process pub/sub,
- request/reply,
- bounded backpressure and lifecycle tests.

Be conservative with:

- native FABRIC durability, federation, mobility, or control-plane claims
  unless current source and focused tests prove the exact layer,
- Kafka advanced consumers,
- Redis cluster failover,
- NATS JetStream.
- generic first-party NKey transcript signing or retained-artifact E2E claims.

If your workload depends on a feature that the repo classifies as partial, either:

- validate it carefully before adopting it,
- or keep that slice behind a boundary bridge until the native surface is sufficient.

## Filesystem

Prefer `fs::*` over `tokio::fs`, but note the deliberately conservative scope:
`src/fs/` is a partial blocking-backed facade, not full `tokio::fs` parity.
It currently exposes `File`, buffered readers/writers, metadata,
directory/path helpers, `try_exists`, `write_atomic`, `UnixVfs`, and platform
capability reports. Most operations are async facades over
`spawn_blocking_io`; poll-based `File` traits still use direct blocking I/O,
recursive directory removal and large copies inherit standard-library
partial-state semantics, and Linux `io_uring` support is limited to
feature-gated helper paths.

Migration checklist:

- replace file reads/writes/metadata/path ops,
- test cleanup and rename semantics,
- validate any niche behavior such as symlink handling or platform quirks,
- keep deterministic or isolated fixtures in tests.

## Process

Prefer `process::*` over `tokio::process`.

Migration checklist:

- replace command spawning,
- handle structured exit and shutdown,
- verify stdio flows,
- test cancellation and reaping behavior.

Known caveat:

- PTY-oriented workflows are explicitly unsupported and need an external crate or a kept boundary.

## Signal

Prefer `signal::*` over `tokio::signal`.

Important caveat:

- Unix coverage is the strongest path,
- Windows signal coverage is still partial in the repo's matrix.

If Windows signal semantics are central to the app, validate them explicitly before claiming full native parity.
