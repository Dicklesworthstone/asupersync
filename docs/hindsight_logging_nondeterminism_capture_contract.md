# Hindsight Logging and Minimal Nondeterminism Capture Contract

Bead: `asupersync-1508v.6.4`

## Purpose

This contract defines exactly which nondeterministic inputs must be recorded for deterministic replay, which runtime state is derivable and must NOT be redundantly logged, and how to emit compact replay artifacts that preserve Asupersync's deterministic debugging advantages without waste.

## Contract Artifacts

1. Canonical artifact: `artifacts/hindsight_logging_nondeterminism_capture_v1.json`
2. Comparator-smoke runner: `scripts/run_hindsight_logging_smoke.sh`
3. Invariant suite: `tests/hindsight_logging_nondeterminism_capture_contract.rs`

## Required Nondeterminism Sources

Every execution has exactly these categories of true nondeterminism that must be captured for faithful replay:

### Category 1: Scheduling Decisions

| Source | ReplayEvent | Why Nondeterministic |
|--------|-------------|---------------------|
| Task selection from ready queue | `TaskScheduled` | Multiple tasks may be ready; choice depends on queue ordering and steal patterns |
| Task yield points | `TaskYielded` | Cooperative yield timing affects interleaving |
| Task completion ordering | `TaskCompleted` | Concurrent tasks may complete in any order |
| Task spawn ordering | `TaskSpawned` | Spawn timing relative to other events is nondeterministic |

### Category 2: Time Progression

| Source | ReplayEvent | Why Nondeterministic |
|--------|-------------|---------------------|
| Virtual time advances | `TimeAdvanced` | Wall-clock-derived time differs across runs |
| Timer creation | `TimerCreated` | Timer deadlines depend on wall-clock |
| Timer firing order | `TimerFired` | Timers with equal deadlines may fire in any order |
| Timer cancellation | `TimerCancelled` | Cancellation timing relative to fire is nondeterministic |

### Category 3: I/O Results

| Source | ReplayEvent | Why Nondeterministic |
|--------|-------------|---------------------|
| I/O readiness notifications | `IoReady` | Reactor event ordering is OS-dependent |
| I/O result sizes | `IoResult` | Read/write byte counts depend on OS buffering |
| I/O errors | `IoError` | Network/disk errors are inherently nondeterministic |

### Category 4: Entropy

| Source | ReplayEvent | Why Nondeterministic |
|--------|-------------|---------------------|
| RNG seed | `RngSeed` | Initial seed may come from OS entropy |
| RNG values | `RngValue` | Verification checkpoints for deterministic PRNG streams |

### Category 5: Fault Injection

| Source | ReplayEvent | Why Nondeterministic |
|--------|-------------|---------------------|
| Chaos injection | `ChaosInjection` | Lab-mode fault decisions are probabilistic |

### Category 6: Region Lifecycle

| Source | ReplayEvent | Why Nondeterministic |
|--------|-------------|---------------------|
| Region creation order | `RegionCreated` | Concurrent region creation is nondeterministic |
| Region close ordering | `RegionClosed` | Drain ordering depends on child completion |
| Region cancellation | `RegionCancelled` | External cancel delivery timing is nondeterministic |

### Category 7: Waker Delivery

| Source | ReplayEvent | Why Nondeterministic |
|--------|-------------|---------------------|
| Waker invocation | `WakerWake` | Cross-thread wakeup delivery order varies |
| Batch wakeups | `WakerBatchWake` | Batch size depends on timing |

### Category 8: Checkpoints

| Source | ReplayEvent | Why Nondeterministic |
|--------|-------------|---------------------|
| Sync checkpoints | `Checkpoint` | Verification and restart points |

## Excluded Derived State (MUST NOT Log)

The following runtime state is deterministically derivable from the required nondeterminism sources above and MUST NOT be redundantly captured:

| Derived State | Derivation Source | Why Excludable |
|---------------|-------------------|----------------|
| Ready queue length | Scheduling + completion events | Sum of spawns minus completions minus yields |
| Cancel lane length | Region cancellation events | Count of active cancellations |
| Finalize lane length | Region close events | Count of closing regions |
| Total task count | Spawn + completion events | Running counter |
| Active region count | Region create + close events | Running counter |
| Cancel streak counters | Sequential scheduling events | Derived from task selection sequence |
| Outstanding obligations | Task lifecycle events | Derived from obligation create/commit/abort |
| Obligation leak count | Obligation lifecycle events | Cumulative derivable counter |
| Governor/adaptive state | Configuration + epoch events | Deterministic state machine given config |
| Worker park/unpark state | Scheduling events | Derivable from task availability |
| Blocking pool state | Spawn-blocking events | Running counter |
| Timer heap structure | Timer create/fire/cancel events | Rebuild from events |
| Calibration scores | Controller decision events | Computed from evidence |

### Derivability Invariant

For any excluded field `F` and captured event sequence `E`:

```
F(t) = derive(E[0..t], config)
```

If this invariant cannot be maintained for a field, it MUST be promoted to a required nondeterminism source.

## Replay Artifact Format

### Envelope

Every replay artifact is a `ReplayTrace` containing:

1. **Metadata header** (`TraceMetadata`):
   - `version`: Schema version (`REPLAY_SCHEMA_VERSION = 1`)
   - `seed`: Original RNG seed
   - `recorded_at`: Wall-clock timestamp (informational only, not used in replay)
   - `config_hash`: Runtime configuration hash for compatibility checking
   - `description`: Optional human-readable description

2. **Event stream**: Ordered sequence of `ReplayEvent` values

3. **Correlation**: Each artifact is tied to a workload ID and correlation ID from the workload corpus

### Versioning

- Schema version is `REPLAY_SCHEMA_VERSION` (currently 1)
- Backward compatibility checked via `TraceMetadata::is_compatible()`
- Config hash mismatch produces a warning, not a hard failure
- Forward-incompatible changes require major version bump

### Size Budget

Target capture overhead per event:

| Event Category | Target Size (bytes) | Actual Max (bytes) |
|---------------|--------------------|--------------------|
| Scheduling | ≤ 24 | 25 (TaskSpawned) |
| Time | ≤ 24 | 17 (TimeAdvanced) |
| I/O | ≤ 24 | 17 (IoResult) |
| RNG | ≤ 16 | 9 (RngSeed/RngValue) |
| Chaos | ≤ 24 | 19 (with task) |
| Region | ≤ 24 | 25 (RegionCreated) |
| Waker | ≤ 16 | 9 (WakerWake) |
| Checkpoint | ≤ 32 | 25 (Checkpoint) |

Aggregate budget: Trace overhead MUST be less than 10% of total runtime memory for typical workloads (≤100K events).

## Structured Logging Contract

Capture and replay diagnostics MUST include these structured log fields:

- `trace_id`: Correlation identifier for the trace
- `workload_id`: Workload corpus identifier
- `replay_schema_version`: Schema version of the replay artifact
- `config_hash`: Runtime configuration hash
- `capture_event_count`: Total events captured
- `capture_bytes`: Total bytes used by captured events
- `excluded_fields`: List of derived fields intentionally not captured
- `missing_source_fields`: List of nondeterminism sources that failed to capture (MUST be empty for valid traces)
- `replay_divergence_point`: Event index where replay diverged (if applicable)
- `replay_status`: One of `success`, `diverged`, `incomplete`, `schema_mismatch`

### Missing-Source Failure Contract

If any required nondeterminism source fails to capture, the trace MUST:

1. Log a structured warning with `missing_source_fields` populated
2. Mark the trace as `incomplete` in metadata
3. Continue capturing remaining sources (best-effort)
4. Never silently produce a trace that appears complete but has gaps

## Comparator-Smoke Runner

Canonical runner: `scripts/run_hindsight_logging_smoke.sh`

The runner reads `artifacts/hindsight_logging_nondeterminism_capture_v1.json`, supports deterministic dry-run or execute modes, and emits:

1. Per-scenario manifests with schema `hindsight-logging-smoke-bundle-v1`
2. Aggregate run report with schema `hindsight-logging-smoke-run-report-v1`

Examples:

```bash
# List scenarios
bash ./scripts/run_hindsight_logging_smoke.sh --list

# Dry-run one scenario
bash ./scripts/run_hindsight_logging_smoke.sh --scenario AA06-SMOKE-NONDETERMINISM-CATALOG --dry-run

# Execute one scenario
bash ./scripts/run_hindsight_logging_smoke.sh --scenario AA06-SMOKE-NONDETERMINISM-CATALOG --execute
```

## Validation

Focused invariant test command (routed through `rch`):

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa061 cargo test --test hindsight_logging_nondeterminism_capture_contract -- --nocapture
```

Invariant coverage locks:

1. Doc section and cross-reference stability
2. Artifact schema/version invariants
3. Nondeterminism source catalog completeness (every ReplayEvent variant covered)
4. Excluded derived state catalog stability
5. Size budget enforcement
6. Structured log field completeness
7. Smoke command `rch` routing and report schema stability
8. Missing-source failure contract enforcement

## Cross-References

- `src/trace/replay.rs` — ReplayEvent enum and trace format
- `src/trace/recorder.rs` — TraceRecorder capture implementation
- `src/trace/replayer.rs` — TraceReplayer deterministic replay
- `src/trace/event.rs` — Observability trace events
- `src/trace/mod.rs` — Trace module overview
- `artifacts/hindsight_logging_nondeterminism_capture_v1.json`
- `scripts/run_hindsight_logging_smoke.sh`
- `tests/hindsight_logging_nondeterminism_capture_contract.rs`
- `artifacts/runtime_workload_corpus_v1.json`
- `docs/runtime_kernel_snapshot_contract.md`
