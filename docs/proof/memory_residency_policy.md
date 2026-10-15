# Memory Residency Policy

`src/runtime/memory_residency.rs` defines the M2 pure decision engine for
`asupersync-memory-residency-control-ho2itz.2`. The checked contract is
`artifacts/memory_residency_policy_contract_v1.json`, and the focused verifier
is `tests/memory_residency_policy_contract.rs`.

The policy is off by default. `MemoryResidencyPolicy::default()` is the same as
`MemoryResidencyPolicy::disabled()` and emits a fallback recommendation with
`policy_enabled = false`. It does not change `RuntimeConfig::default()`,
`RuntimeBuilder`, scheduler execution, artifact-cache eviction, allocator
selection, task cancellation, or task migration.

## Inputs

The decision engine consumes existing evidence only:

| Input | Source |
| --- | --- |
| Capacity hints | `RuntimeCapacityHints` |
| Trace profile | `TraceStorageProfile` |
| Arena temperature request | `ArenaTemperaturePolicy` |
| Topology/locality evidence | `ArenaLocalityReport` |
| Runtime pressure | `RuntimePressureSnapshot` from `ResourceMonitor` |
| Artifact cache pressure | `ArtifactMemoryPressureSnapshot` |
| Proof-pack warmth | `ProofPackWarmthTelemetry` |

## Consumers

The intended consumers are the later memory-residency children:
`asupersync-memory-residency-control-ho2itz.3` for live hot/warm/cold
accounting snapshots, `asupersync-memory-residency-control-ho2itz.4` for
64C/256G replay and e2e evidence, and
`asupersync-memory-residency-control-ho2itz.5` for operator runbook and rollback
gates.

Non-consumers are equally important: runtime defaults, scheduler hot paths,
artifact-cache eviction, task cancellation/migration, allocator selection, and
release-readiness signoff do not consume this M2 decision directly.

## Decisions

The engine returns one of `hot`, `warm`, `cold`, `fallback`, or `no_win`.
Reasons are emitted in deterministic priority order. Fresh topology selects a
`warm` recommendation by default. High artifact-cache pressure can select
`cold` when spill budget is available. Stale topology, exhausted cold-evidence
budget, proof-pack warmth mismatch, and unsupported large-page assumptions fail
closed to `fallback`. No-win locality evidence and critical memory pressure
return `no_win`. Cache warmth is not correctness evidence.

## Proof

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_memory_residency_policy_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test memory_residency_policy_contract -- --nocapture
```

This proof covers the pure policy surface only. It does not prove runtime
correctness, throughput improvement, p999 improvement, allocator replacement,
live RCH fleet availability, production-on-by-default behavior, cache eviction
behavior, or release readiness.
