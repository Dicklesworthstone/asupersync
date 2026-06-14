# Memory Residency Policy Engine

This page is the contract companion for
`asupersync-memory-residency-control-ho2itz.2`.

M2 adds a pure, deterministic recommendation engine in
`src/runtime/memory_residency.rs`. It consumes existing evidence from:

- `RuntimeCapacityHints`
- `TraceStorageProfile`
- `ArenaTemperaturePolicy`
- `ArenaLocalityReport`
- `RuntimePressureSnapshot`
- proof-pack warmth telemetry supplied by operator tooling or fixtures
- `ArtifactMemoryPressureSnapshot`

## Contract

The policy is off by default. `MemoryResidencyPolicy::default()` uses
`MemoryResidencyProfile::Disabled`, emits a `fallback` recommendation, and does
not alter runtime construction, allocator paths, scheduler selection, task
ownership, cancellation, or cache eviction.

When explicitly enabled with `MemoryResidencyPolicy::experimental_opt_in()`, the
engine returns one of:

| Decision | Meaning |
| --- | --- |
| `hot` | Keep the hot baseline path. |
| `warm` | Use fresh locality/capacity evidence as a recommendation. |
| `cold` | Prefer cold retained-evidence or spill-eligible artifact handling. |
| `fallback` | Stay on the conservative fallback path. |
| `no_win` | Refuse the recommendation because evidence is unsafe or has no win. |

Each decision carries stable reason codes, explicit no-claim boundaries, and a
stable line renderer for future golden artifacts and operator logs.

## Consumers

Current consumers are unit tests and future M3/M4/M5 memory-residency children.
The engine is safe for dry-run tooling and lab fixtures because it is pure and
does not hold references to live runtime state beyond caller-owned snapshots.

## Non-Consumers

The runtime builder, allocator, scheduler, artifact cache, cancellation paths,
and task/region/obligation tables do not consume this policy yet. M2 does not
enable a control loop.

## No-Claim Boundaries

M2 does not claim:

- default runtime behavior changed
- allocator replacement or allocator universality
- task migration, cancellation, dropping, or rescheduling
- throughput, latency, p999, cache-hit-rate, NUMA, or memory-use improvement
- release readiness, broad workspace health, or RCH fleet availability

Performance or p999 claims require the later M4 measured proof lane.

## Focused Proof

Cargo validation must run through RCH:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_memory_residency_policy_engine CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --lib runtime::memory_residency --features test-internals -- --nocapture
```

Local non-Cargo checks may verify formatting and whitespace only.
