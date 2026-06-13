# Memory Residency Accounting Snapshot

`src/runtime/memory_residency.rs` defines the M3 read-only accounting snapshot
for `asupersync-memory-residency-control-ho2itz.3`. The checked contract is
`artifacts/memory_residency_accounting_snapshot_v1.json`, and the focused
verifier is `tests/memory_residency_accounting_snapshot_contract.rs`.

The snapshot is a point-in-time observation. It does not start a continuous
accounting loop, does not mutate runtime state, and does not change
`RuntimeConfig::default()`, `RuntimeBuilder`, scheduler execution,
artifact-cache eviction, allocator selection, task cancellation, or task
migration.

## Surface

`MemoryResidencyAccountingSnapshot` is schema-versioned as
`asupersync.memory-residency-accounting-snapshot.v1`. It includes resolved
runtime capacities, fixed byte estimates for hot runtime records, hot trace
bytes from the existing trace-storage budget, retained evidence bytes from the
M2 decision, optional record-pool hit/miss/recycle counters, stable tier rows,
stable aggregation rows, M2 reason codes, and M2 no-claim boundaries.

Tier rows are always emitted in this order: `hot`, `warm`, `cold`, `fallback`,
`no_win`. Aggregation rows are always emitted in this order: `runtime_total`,
`task_records`, `region_records`, `obligation_records`, `retained_evidence`,
`artifact_cache`.

## Inspector And Debug Server

The debug server exposes an additive `GET /debug/memory-residency` endpoint. It
is implemented in `src/web/debug.rs` and does not replace `GET /debug/snapshot`;
the existing runtime snapshot callback continues to serve the runtime state
payload. If a caller does not install a memory-residency provider, the endpoint
returns a schema-versioned `unknown` snapshot with zero capacities and explicit
fail-closed reason codes.

Runtime-inspector consumers should treat the payload as a transportable,
schema-versioned JSON section. Missing counters or missing artifact-cache
evidence fail closed as `unknown`. Stale topology evidence fails closed as
`stale`. Default-disabled policy evaluation reports `disabled`.

## Consumers

Consumers are `GET /debug/memory-residency`, runtime-inspector payload adapters
that already carry schema-versioned JSON, the M4 replay/e2e proof lane, and the
M5 operator runbook and rollback gates.

Non-consumers are runtime defaults, scheduler hot paths, artifact-cache eviction,
task cancellation/migration, allocator selection/replacement, and
release readiness signoff.

## Proof

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_memory_residency_accounting_snapshot_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test memory_residency_accounting_snapshot_contract -- --nocapture
```

This proof covers the M3 snapshot contract only. It does not prove runtime
correctness, throughput improvement, p999 improvement, allocator replacement,
live-task migration, cache eviction behavior, broad workspace health, release
readiness, or live RCH fleet availability.
