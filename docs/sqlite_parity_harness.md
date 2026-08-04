# Cycle-safe SQLite parity harness

`asupersync-ym2wtv.2.1` establishes the executable starting point for the
FrankenSQLite parity campaign without reversing the existing dependency
direction. The harness is the standalone Cargo workspace at
`tests/fixtures/sqlite-parity-consumer`. It is a neutral consumer of both
engines, not an Asupersync workspace member and not a dev-dependency of the
Asupersync crate.

## Dependency boundary

FrankenSQLite depends on Asupersync, so adding `fsqlite` to Asupersync's normal
or dev graph would create a cycle. The neutral manifest instead points its
direct Asupersync dependency at this checkout, pins the public FrankenSQLite Git
source to release `v0.1.18`
(`92f9e9833f859ebcbe27e9fef16d9cad4372bbd7`), and patches the crates.io
Asupersync edge in FrankenSQLite onto that same local package. This is the
coherent combined-graph shape identified by the graph-budget prerequisite:
there is one Asupersync package and one `Cx`/runtime type identity.

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

## Vector schema v1

`artifacts/sqlite_conformance_vectors_v1.json` is dependency-free data usable by
either adapter. Each vector has stable suite, capability, family, vector, setup,
and ordered operation identifiers. Every operation declares its status,
affected-row count or normalized values, stable error class, transaction state,
cancellation state, and resource state. Suite-level normalization covers all
five SQLite value classes, errors, column order, and row order. Unsupported
capabilities are explicit engine/capability/reason records; an empty list means
the current vector requires no exception.

Schema v1 deliberately starts with only `execute_batch`, `execute`, and
`query_one`, which both public APIs support. New operation kinds or changed
semantics require a schema-version decision rather than silent adapter
guesswork.

The smoke case `SQLITE-PARITY-SMOKE-001` creates an in-memory table, inserts two
rows, queries the integer/text pair `(2, "beta")`, and drops the connection with
no transaction opened. The runner emits both engine records plus a deterministic
comparison. Raw engine error text is excluded; errors normalize to declared
stable classes.

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
target, host class, vector schema version, operations, normalized outcomes, and
comparison are all included in stdout. The admitted receipt is copied into
`artifacts/sqlite_parity_harness_v1.json`; the contract test verifies its shape
against the vector rather than accepting a free-form success note.

## Interpretation boundary

The combined-graph prerequisite remains terminal `DEFER`: the patched graph
fixes the duplicate-runtime coherence defect, but the proposal added 33 unique
crates and its binary-size/compile-time cells remained blocked under the
recorded RCH root constraint. A successful smoke case proves only that this
cycle-safe harness, schema, and common operation can produce comparable
structured evidence. It does not authorize dependency cutover, remove
`rusqlite`/`sqlparser`, prove all eight semantic families, establish global
resource quiescence, or claim FrankenSQLite performance, maturity, or release
readiness.
