# Cycle-safe SQLite parity harness

`asupersync-ym2wtv.2.1` established the executable starting point for the
FrankenSQLite parity campaign, and `asupersync-ym2wtv.2.2` extends it through
the open/configuration, pool-admission, blocking-bridge, cancellation, and
quiescence family without reversing the existing dependency direction. The
harness is the standalone Cargo workspace at
`tests/fixtures/sqlite-parity-consumer`. It is a neutral consumer of both
engines, not an Asupersync workspace member and not a dev-dependency of the
Asupersync crate.

## Dependency boundary

FrankenSQLite depends on Asupersync, so adding `fsqlite` to Asupersync's normal
or dev graph would create a cycle. The neutral manifest instead points its
direct Asupersync dependency at this checkout, pins the public FrankenSQLite Git
source to release `v0.1.18`
(`92f9e9833f859ebcbe27e9fef16d9cad4372bbd7`). That release depends on
Asupersync 0.3.x, whose public `Cx` and runtime types are not interchangeable
with the current 0.4.9 types. The consumer therefore names the published
0.3.10 package explicitly as `asupersync-compat`, resolves the current path
dependency as Asupersync 0.4.9, runs each adapter inside its own matching
runtime, and compares only the declared public lifecycle outcome.
P2 enables the pinned `fsqlite` `async-api` feature and directly names its
matching `fsqlite-types` package so the two runtime boundaries remain visible
rather than being hidden behind an ineffective Cargo patch.

The first clean attempt used the newer remote tip
`31fc4a3b3a108dc49243157ea29fb1ddfcb06fdc`. That selected native graph did not
compile: synchronous `fsqlite-btree` cursor adapters received Future-returning
pager operations. The receipt is retained as `BLOCKED_UPSTREAM_COMPILE` in the
harness artifact. Pinning the checked release makes the smoke reproducible
without claiming that every feature profile or later revision is unbuildable.

The consumer owns an independent `Cargo.lock`. Root `Cargo.toml` and
`Cargo.lock` contain no `fsqlite` or FrankenSQLite package. The checked contract
fails if that direction changes or if the fixture stops being a standalone
workspace.

## Vector schema v2

`artifacts/sqlite_conformance_vectors_v1.json` remains dependency-free data
usable by either adapter. Schema v2 replaces the P1 operation-list smoke shape
with six lifecycle scenarios. Every scenario declares its stable status and
error class, open/configuration/admission/blocking/cancellation/close states,
and a complete resource-state receipt. Raw engine error text and private worker
topology are excluded; only behavior promised by both public adapters is
normalized.

The six scenarios are:

- `SQLITE-PARITY-P2-MEMORY-CONFIG-001`: private in-memory open, common PRAGMA
  application/readback, typed query probe, explicit close, and blocking-worker
  shutdown.
- `SQLITE-PARITY-P2-PATH-OPEN-002`: file-path round trip through an
  engine-specific scratch database.
- `SQLITE-PARITY-P2-OPEN-FAILURE-003`: deterministic rejection when a unique
  database path has a missing parent directory.
- `SQLITE-PARITY-P2-CANCELLED-OPEN-004`: pre-cancelled open, including native
  `Cx` propagation from the matching 0.3.10 compatibility runtime into the
  FrankenSQLite context.
- `SQLITE-PARITY-P2-POOL-CANCEL-005`: a consumer-owned admission semaphore is
  saturated, the second checkout is proven parked, the live connection closes,
  an isolated cancellation-only `Cx` drains the waiter through the engine's
  public `AcquireError::Cancelled` result, and the sole permit is restored
  exactly once. The harness polls the acquire future directly to `Pending`
  before closing the connection, so the parked-state witness does not depend
  on executor scheduling or a bounded yield loop.
- `SQLITE-PARITY-P2-URI-UNSUPPORTED-006`: the harness records that neither P2
  adapter exposes a common SQLite URI-filename contract. It does not pretend a
  `Path` or `String` filename API carries URI flag semantics.

The consumer-owned admission semaphore is the shared pool contract. It avoids
the false comparison that both engines must have identical private thread or
connection-pool topology. The terminal resource receipt instead requires the
connection to be closed or never opened, zero transactions and waiters, full
permit recovery, zero blocking-pool pending/busy/active work after runtime
shutdown, and a closed region state.

The original schema-v1 smoke execution remains historical evidence in
`artifacts/sqlite_parity_harness_v1.json`; it is not relabeled as P2 evidence.

## SQLite P3 prepared-statement matrix

`asupersync-ym2wtv.2.3` extends the neutral consumer with seven executable
prepared-statement cases on both pinned engines. The common observations cover
positional binding for every public `SqliteValue`, named SQL placeholders
bound by SQLite parameter index through the existing positional value slice,
repeated execution/reset, schema invalidation, malformed SQL and too-few bind
errors, pre-cancellation without mutation, connection reuse, and
two-connection write contention. Both ordinary runtimes close with zero
pending, busy, or active blocking work.

The named-binding row is deliberately precise: Asupersync does not publish a
name-to-value map API. A statement may contain `:name` placeholders, but the
public `&[SqliteValue]` is bound in SQLite parameter-index order. The tests do
not imply that parameter names reorder caller values.

The neutral repeated-execution case uses an A/B/missing/A sequence and proves
the same result and released statement state on both engines. Asupersync's
separate capacity-one A/A/B/A test additionally proves cache hit, eviction,
and reprepare behavior. FrankenSQLite's pinned async API exposes no public
prepared-statement object, cache-capacity control, or cache telemetry, so the
neutral evidence does not infer equivalent cache internals from equal query
results.

Two observed differences stay explicit. Asupersync rejects a surplus bind
parameter with a typed SQL error; pinned FrankenSQLite accepts the same call
and ignores the surplus value. Under a real two-connection write lock,
Asupersync returns a typed busy-or-locked error and remains reusable, while the
pinned FrankenSQLite call does not return despite `PRAGMA busy_timeout = 0`.
The neutral harness executes that call in an isolated child process, applies a
five-second watchdog, then kills and reaps the child. This bounds the proof
lane but does not claim cooperative cleanup of the child connection.

The executable common cancellation case proves pre-cancelled no-mutation and
same-connection reuse. Asupersync's native row-stream test separately proves
partial-stream drop finalization; FrankenSQLite materializes `Vec<Row>` and has
no corresponding public async row-stream boundary. These unsupported cache and
row-stream cells, and the two intentional differences above, are not relabeled
as parity. The P3 tranche is complete for the pinned public surfaces, but it
does not authorize dependency cutover or public API removal.

## SQLite P4 transaction and savepoint matrix

`asupersync-ym2wtv.2.4` extends the neutral consumer with five executable
transaction cases on both pinned engines. The cases cover deferred commit,
immediate rollback, exclusive commit, savepoint partial rollback, and
constraint-conflict recovery. Each adapter runs through its own matching
runtime and public transaction surface. The comparison retains the exact
terminal state, ordered visible labels, connection-reuse result, and zero-open-
transaction count; only each engine's primary-key/unique error is normalized to
`constraint_violation`.

The savepoint case commits `base`, creates a savepoint, writes `discarded`, rolls
back and releases that savepoint, writes `after`, and commits the outer
transaction. Both engines must expose exactly `base, after`. The conflict case
writes two rows with the same primary key inside one transaction, observes a
constraint error, rolls the transaction back, then proves that the same
connection can begin and roll back another transaction. Every case closes its
connection, shuts down its runtime, and requires zero pending, busy, or active
blocking work.

RCH job `j-29984462414544915` ran the locked standalone consumer at exact base
`1127d64d300a2a52524b7bb4870c7a521f7d55aa` plus only the consumer-source
overlay. It returned exit 0 with five matching Asupersync/FrankenSQLite rows and
no mismatches. The machine-readable receipt is `phase4.execution.evidence` in
the harness artifact.

Cancellation has a deliberately separate authority. The native cancellation
evidence in `tests/sqlite_real_disk_cancel_rollback.rs` proves both deferred and
immediate helper cancellation wait for physical rollback before returning: a
zero-timeout reference `BEGIN IMMEDIATE` succeeds immediately afterward, the
cancelled row is absent, and the database remains writable. The pinned
FrankenSQLite async adapter has no equivalent closure-based cancellation hook,
so that native cancellation evidence is not relabeled as cross-engine parity.
The deterministic constraint case likewise does not replace P3's separate
two-connection evidence: Asupersync returns a typed busy/locked result and
recovers, while the pinned FrankenSQLite call is bounded by the external
five-second kill-and-reap watchdog and remains an explicit difference.

This is a bounded common transaction matrix, not a claim that every drop,
panic, timeout, pool, or concurrency schedule is equivalent. It does not
authorize dependency cutover or public API removal.

The machine-readable `phase4.coverage_matrix` makes the remaining boundaries
explicit. Asupersync's RAII transaction-drop and native cancellation paths are
backed by named source and real-disk tests. The pinned FrankenSQLite adapter
does not expose an equivalent RAII transaction guard or closure-based
cancellation hook, so those cells are `UNSUPPORTED`, not green. Both common
adapters prove same-connection reuse and runtime quiescence; neither claims a
shared pool-eviction policy or injected commit/rollback I/O-failure parity.

## SQLite P5 cancellation matrix

`asupersync-ym2wtv.2.5` adds a bounded second proof layer without rewriting the
historical neutral-consumer receipt. The current Asupersync adapter has
deterministic in-repository tests for queued operation and queued row-stream
cancellation, cancellation before result-channel admission, cancellation of a
signalled running statement, the committed-result-versus-late-cancellation
window, statement and row-stream timeouts, explicit native interruption, and
post-operation connection reuse. The exact eight-row map and the terminal RCH
receipts live in `phase5.coverage_matrix` and `phase5.verification` of the
harness artifact.

This split is deliberate. FrankenSQLite v0.1.18 accepts a cancellable `Cx` and
publishes `AsyncConnection::close`, but it does not expose a public
statement-timeout setting, explicit interrupt handle, row-stream API, queued
worker phase witness, or hook between engine completion and async result
publication. A timing-based loop would not prove those race boundaries.
Accordingly, unsupported cells stay unsupported; the matrix does not convert
missing public hooks into parity by sleeping, guessing that work started, or
normalizing unlike outcomes.

The retained P2 neutral execution still supplies the shared public-API proof
for pre-cancelled open, a structurally parked admission waiter, explicit
connection close, full permit recovery, and runtime shutdown with zero pending,
busy, or active blocking work. Together, the layers prove the current
Asupersync repair and identify the exact pinned-FrankenSQLite gaps. They do not
claim full cross-engine interrupt/timeout parity or authorize dependency
cutover.

## SQLite P6 value and row matrix

`asupersync-ym2wtv.2.6` extends the same neutral consumer with fourteen exact
value cases executed by both pinned engines. The common matrix covers NULL;
signed 64-bit extrema; the integer `2^53 + 1`, which is beyond binary64's exact
integer range; negative zero; positive and negative infinity; SQLite's shared
NaN-to-NULL behavior;
empty text and blobs; Unicode text containing an embedded NUL; binary bytes;
and a bounded 1 MiB text/blob profile. Integers and IEEE-754 bits are compared
exactly. Text and blob bytes are compared directly; their lengths and FNV-1a
fingerprints are compact diagnostics, not the equality authority.

Both adapters retain the owned result row until after explicit connection
close, then validate it and shut down their matching runtimes with no pending,
busy, or active blocking work. Wrong-type and out-of-bounds indexed reads are
also classified on both engines. RCH job `j-29984462414544922` ran the locked
consumer at exact base `285174b6814f22782c5aeb92b5b7d310a3ad3b56` plus only
the consumer-source overlay on worker `vmi1153651`; it returned exit 0 with all
fourteen normalized values equal and no mismatches.

Row metadata remains an intentional, visible difference. Asupersync proves
ordered duplicate-preserving names, its legacy sorted/unique name view,
first-match ASCII-case-insensitive indexing, and its legacy last-wins exact-name
lookup. The pinned FrankenSQLite async `Row` exposes owned values by index but
no public column-name metadata or name lookup, so that cell is
`UNSUPPORTED_NO_PUBLIC_ASYNC_ROW_METADATA`. The harness does not infer aliases
from SQL text or call the missing observation green.

The 1 MiB cases are a campaign profile, not a claimed hard maximum. This phase
does not authorize dependency cutover, public API removal, or complete SQLite
engine parity.

## SQLite P7 checked-SQL security parity

`asupersync-ym2wtv.2.7` makes the checked-SQL boundary reusable and executable
without weakening the established checked-by-default API. The additive
`validate_checked_sql_statement` and `validate_checked_sql_batch` functions use
the exact policy called by `execute`, `execute_batch`, `query`, `query_row`, and
`query_stream`; transaction `execute` and `query` delegate to those same checked
connection methods. A companion adapter can therefore reject unsafe input
before it reaches another SQLite engine instead of maintaining a second keyword
parser.

The machine policy in `phase7.policy` denies parser failure, inputs above one
MiB, syntax deeper than 128 parser recursion levels, multiple statements on a
single-statement API, PRAGMA and transaction control, ATTACH/DETACH, VACUUM and
VACUUM INTO, and `load_extension(...)` calls. The extension call check uses SQL
tokens, so comments, whitespace, case, and quoted function identifiers cannot
bypass it, while the same words inside string literals remain data. The explicit
extension rule is defense in depth: the current rusqlite feature set does not
enable dynamic extension loading, but checked admission must not depend on that
ambient build fact. Bound parameter values remain data and are never reparsed as
SQL syntax; the public-entry-point regression includes control-looking text in a
bound value.

The neutral consumer runs thirteen allow/deny cases through the real
Asupersync checked query path and through the FrankenSQLite adapter after that
adapter applies the shared validator. Its corpus covers multi-statement
smuggling, comments, quoted control words, Unicode data, ATTACH, DETACH, PRAGMA,
VACUUM INTO, transaction control, extension loading, malformed SQL, the byte
limit, and the recursion limit. Both connections are then closed and both
runtime blocking pools must report shutdown with zero pending, busy, or active
work. The in-crate deterministic fuzz test adds 4,096 bounded variants and fails
on any panic or allow/deny drift.

This proves the declared adapter policy and corpus, not that unchecked APIs are
safe for untrusted SQL. The `_unchecked` APIs intentionally retain trusted
migration and connection-control compatibility; ATTACH/DETACH remain disabled
even there. P7 does not authorize a dependency cutover or claim arbitrary SQL
equivalence between the two engines.

## SQLite P8 stable diagnostics and quiescence

`asupersync-ym2wtv.2.8` adds a structured error surface without changing the
v0.4.3-compatible `SqliteError` enum or any established method signature. The
existing methods retain their behavior. Callers that need stable diagnostics
opt into separately named `*_diagnosed` methods and receive
`SqliteOperationError`, whose non-exhaustive operation, category, and retry
types expose SQLite primary and extended result codes captured before
rusqlite renders an error into prose.

The classified path covers open, prepare, bind, step, batch, transaction
begin/commit/rollback, configuration, close, blocking-pool, and validation
boundaries. `Debug` and `Display` for `SqliteOperationError` omit SQL text,
bound values, paths, and engine messages. The original rusqlite error remains
available only through the explicit `engine_source` accessor, and the legacy
value is exposed only through its separate compatibility accessor. Automatic
error-chain traversal is redacted as well. Consequently callers can inspect
useful source information deliberately without putting raw engine messages
into ordinary structured evidence.

The native focused tests execute real malformed SQL, constraint, binding,
checked-policy, nested-transaction, busy-lock, explicit interrupt, caller
cancellation, closed-connection, reuse, and blocking-pool shutdown paths.
They distinguish a retryable `SQLITE_BUSY`/`SQLITE_LOCKED` result from
`SQLITE_INTERRUPT` and from outer `Outcome::Cancelled`; cancellation is not
collapsed into a retryable database error. The dedicated pool must terminate
with zero pending, busy, and active workers.

The neutral consumer executes four real P8 rows per engine and compares the
prepare and constraint operation/category/symbolic-primary-code/retry tuples.
Backend-specific extended numeric codes remain evidence but are not mistaken
for a portable cross-engine contract. The harness also preserves two
differences instead of normalizing them away: Asupersync returns caller
cancellation as outer `Outcome::Cancelled`, whereas FrankenSQLite exposes its
typed interrupt error; and the inherited P3 lock row may end for
FrankenSQLite as a five-second killed-and-reaped watchdog refusal rather than
cooperative connection reuse. Ordinary connections are explicitly closed and
both runtime-local blocking pools must be quiescent. This evidence
does not claim process-global task/resource quiescence, arbitrary engine
equivalence, or permission to remove rusqlite/sqlparser or perform a dependency
cutover.

## SQLite P9 aggregate signoff

P9 runs the real neutral consumer once and treats its single structured output
as the aggregate matrix, rather than manufacturing a second set of synthetic
rows. The terminal remote-only run covers all executable P2-P8 families in one
process: 47 directly compared cases (6 P2, 7 P3, 5 P4, 14 P6, 13 P7, and 2 P8)
plus the 8 native P5 cancellation/interrupt cases. Every directly compared row
is explained and the aggregate carries zero unexplained divergences.

Unsupported cells stay unsupported. P5 does not claim cross-engine parity when
the pinned FrankenSQLite public API has no deterministic queue, statement-start,
or result-publication witness. P3 and P8 preserve the bounded killed-and-reaped
busy observation and the two runtimes' different cancellation result lattices.
The target matrix records Linux x86-64 as executed, macOS and Windows as
`BLOCKED_NOT_EXECUTED`, and browser Wasm as unsupported for these native SQLite
engines. A green Linux cell is not portable-host evidence.

The replayable entry point is:

```bash
RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
  --scenario sqlite-parity-aggregate \
  --run-id <run-id> \
  --timeout 1800
```

The runner emits `summary.json`, `events.ndjson`, `scenarios.ndjson`,
`validation_stages.ndjson`, `artifact_manifest.ndjson`, `environment.json`,
`repro_manifest.json`, and the redacted RCH log. Exit 103 with `RCH-I003` is
classified as a pre-admission `BLOCKED_RCH` receipt, not as local fallback or
test evidence. An RCH-E309 retrieval failure after remote exit 0 remains an
incomplete packet; only a wrapper exit 0 with `observed_outcome=PASSED` is the
P9 terminal authority. The scenario uses an exact-base clean overlay containing
only the neutral consumer fixture and executes that fixture through `cargo
test`. RCH classifies this as a stream-only test lane, so the result comes back
over stdout without requesting the remote target directory. The scenario also
unsets an inherited host `CARGO_TARGET_DIR`, and passes the same timeout to
RCH's build and test envelopes, so the outer runner and remote command share one
explicit bound.

The outcome is deliberately `KEEP_CURRENT_RUSQLITE_AND_SQLPARSER`, with the
combined graph budget still terminal `DEFER`. The aggregate signoff does not
authorize dependency cutover, does not convert the P5 unsupported cells into
parity, and does not claim process-global task/resource quiescence, arbitrary
SQL equivalence, performance parity, FrankenSQLite maturity, or release
readiness outside this scoped campaign.

## Reproduction

From a clean Asupersync source commit, run:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env \
  ASUPERSYNC_SOURCE_REVISION=<source-commit> \
  SQLITE_PARITY_TARGET=x86_64-unknown-linux-gnu \
  SQLITE_PARITY_HOST=linux-x86_64-rch-worker \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_sqlite_parity_consumer" \
  CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_DEV_DEBUG=0 \
  cargo run --locked \
  --manifest-path tests/fixtures/sqlite-parity-consumer/Cargo.toml
```

The source revision, FrankenSQLite revision, feature sets, Cargo profile,
target, host class, vector schema version, normalized lifecycle outcomes, P4
transaction evidence, and comparison are all included in stdout. The admitted
receipt is copied into `artifacts/sqlite_parity_harness_v1.json`; the contract
test verifies its shape against the vector and consumer source rather than
accepting a free-form success note.

## Interpretation boundary

The combined-graph prerequisite remains terminal `DEFER`: the proposal added
33 unique crates and its binary-size/compile-time cells remained blocked under
the recorded RCH root constraint. The P2 consumer's explicit compatibility
runtime is test-fixture isolation, not approval to add FrankenSQLite to the
Asupersync workspace graph. A successful P2 run proves only the six declared
open/configuration/admission/bridge lifecycle scenarios in this neutral
consumer. It does not authorize dependency cutover, remove
`rusqlite`/`sqlparser`, prove transaction/statement/value/interrupt parity owned
by later children, establish process-global resource quiescence, or claim
FrankenSQLite performance, maturity, or release readiness.
