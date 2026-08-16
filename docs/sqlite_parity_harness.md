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
with the current 0.4.4 types. The consumer therefore names the published
0.3.10 package explicitly as `asupersync-compat`, runs each adapter inside its
own matching runtime, and compares only the declared public lifecycle outcome.
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
  the waiter is aborted and drained as the engine's public cancellation form,
  and the sole permit is restored exactly once. The 0.4.4 path requires the
  graceful inner `AcquireError::Cancelled`; the pinned 0.3.10 compatibility
  path may report the legacy outer task-cancelled join, which is normalized
  only after the waiter and permit cleanup checks pass.
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
target, host class, vector schema version, normalized lifecycle outcomes, and
comparison are all included in stdout. The admitted receipt is copied into
`artifacts/sqlite_parity_harness_v1.json`; the contract test verifies its shape
against the vector rather than accepting a free-form success note.

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
