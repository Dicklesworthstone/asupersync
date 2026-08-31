# Lab Runtime, DPOR, and Trace Infrastructure

## Table of Contents

- [LabRuntime](#labruntime)
- [Oracle Suite](#oracle-suite)
- [Virtual Time Wheel](#virtual-time-wheel)
- [DPOR Schedule Explorer](#dpor-schedule-explorer)
- [Trace Infrastructure](#trace-infrastructure)
- [Scenario-Based Testing](#scenario-based-testing)
- [Test Artifact Outputs](#test-artifact-outputs)
- [Practical Test Shapes](#practical-test-shapes)

## LabRuntime

Source: `src/lab/runtime.rs`, `src/lab/config.rs`

Deterministic runtime for testing when scheduling inputs and effects remain
Lab-controlled. The same seed then reproduces the same controlled execution;
wall clock, ambient randomness, real sockets, and other external effects can
still introduce drift.

### Configuration

```rust
use asupersync::lab::run_async_under_lab;

let (_value, report) = run_async_under_lab(42, |cx| async move {
    task_under_test(cx).await
});

assert!(report.quiescent);
assert!(report.oracle_report.all_passed());
assert!(report.oracle_report.entry("obligation_leak").is_some());
assert!(report.oracle_report.entry("quiescence").is_some());
```

### Futurelock Detection

Not time-based -- obligation-based. Detects tasks that:
- Still hold pending obligations
- Are not making poll progress
- Have crossed `futurelock_max_idle_steps` threshold

Emits `TraceEventKind::FuturelockDetected` with task, region, and held-obligation details. Can panic immediately via `panic_on_futurelock`.

### Chaos Injection

Source: `src/lab/chaos.rs`

Deterministic and seed-bound. Pre-poll and post-poll injection points:
- Cancellation injection
- Delay injection
- Budget exhaustion
- Wakeup storms

Presets: `with_light_chaos()`, `with_heavy_chaos()`, `with_chaos(...)` for focused campaigns.

Targeted await-point cancellation injection (`CancellationInjector`, `AwaitPoint`) is defined in `src/lab/instrumented_future.rs` (re-exported from `lab`) and driven by `src/lab/injection.rs`.

### Snapshots

Source: `src/lab/snapshot_restore.rs`

Restorable snapshots with deterministic content hashes. Structural validation checks:
- Reference validity
- Region-tree acyclicity
- Closed-region quiescence
- Timestamp consistency

### Crashpacks

Source: `src/trace/crashpack.rs`

Deterministic crashpack linkage: stable id/path/fingerprint plus replay command metadata. Auto-attached on failing lab runs.

### Exact Dispatch Recording And Replay

Source: `src/lab/runtime.rs` (public family under
`asupersync::lab::runtime::*`).

- `start_forced_schedule_recording(max_dispatches)` must run on a fresh Lab
  runtime before schedule-relevant steps.
- `finish_forced_schedule_recording()` binds dispatches to source config, seed,
  terminal steps/time, schedule certificate, and quiescence; a truncated source
  returns an error rather than a partial artifact.
- `ForcedSchedule::to_canonical_bytes()` emits the strict canonical form.
- `ForcedSchedule::try_from_canonical_bytes(...,
  ForcedScheduleDecodeLimits)` rejects hostile size/count inputs, malformed or
  non-canonical encoding, checksum failure, and semantic inconsistency.
- `run_forced_schedule(..., ForcedScheduleLimits)` on a fresh compatible runtime
  consumes the exact task-generation/worker/lane/step/time sequence and refuses
  missing, stale, extra, or reordered work without RNG fallback.
- `ForcedSchedule::derive_candidate(...)` plus
  `run_forced_schedule_candidate(...)` supports deletion-only diagnostic
  candidates with caller-owned work limits.

No-claims: this is not production scheduler control, artifact authentication, a
workload/action codec, universal replay, an automatic failure classifier, or a
completed minimizer. A candidate report does not establish that the source
failure persists. Native scheduler/cancellation defects still need native
runtime tests.

## Oracle Suite

Source: `src/lab/oracle/`

### Available Oracles

- **Quiescence oracle**: verifies region close implies no live children
- **Obligation leak oracle**: verifies all obligations resolved
- **Loser drain oracle**: verifies race losers fully drained
- **Cancellation protocol oracle**: verifies request -> drain -> finalize sequence
- **Task leak / region leak oracles**: entry names `task_leak`, `region_leak`

The registry carries further specialized oracles (determinism, waker dedup,
priority inversion, ...); see `src/lab/oracle/mod.rs` for entry names.

### E-Process Monitoring

Source: `src/lab/oracle/eprocess.rs` (runtime-side: `src/obligation/eprocess.rs`)

Anytime-valid monitoring using supermartingale-based testing. Can peek after every scheduling step with controlled type-I error (Ville's inequality).

### Evidence Ledger

Source: `src/lab/oracle/evidence.rs`

Structured evidence with Bayes factors and log-likelihood contributions for subtle failures.

### Conformal Calibration

Source: `src/lab/conformal.rs`

Split conformal prediction for oracle anomaly thresholds. Distribution-free, finite-sample coverage guarantees under exchangeability.

## Virtual Time Wheel

Source: `src/lab/virtual_time_wheel.rs`

Deterministic virtual time with explicit tie-breaking. The Lab scheduler
advances virtual time to the next eligible event; this avoids real waiting but
does not mean every sleep is immediately ready at its creation point.

## DPOR Schedule Explorer

Source: `src/lab/explorer.rs` (public types: `ExplorerConfig`, `ScheduleExplorer`, `DporExplorer`)

DPOR-style schedule exploration treating executions as Mazurkiewicz traces:
- Track coverage by equivalence class fingerprints (Foata normal form)
- Seed-sweep plus race-guided derivation of new deterministic seeds
- Deterministic, replayable concurrency debugging with coverage semantics

This is race-guided seed exploration, not certified-optimal DPOR: there is no
exact-prefix backtracking, so equivalence-class counts are campaign metrics,
not a completeness guarantee.

## Trace Infrastructure

### Canonicalization

Source: `src/trace/canonicalize.rs`

Mazurkiewicz trace monoid: two traces differing only by swapping adjacent independent events are equivalent. Canonicalized to Foata normal form for stable fingerprints.

### Geodesic Normalization

Source: `src/trace/geodesic.rs`

Constructs valid linear extensions that reduce owner switches. Bounded small
traces use the exact A* path; larger traces use deterministic beam/greedy
heuristics and may fall back to topological order when the work budget is
exhausted. The heuristic paths do not claim global optimality.

### Race Detection

Source: `src/trace/dpor.rs`, `src/trace/independence.rs`

Vector clocks per task plus resource-footprint conflicts. Detected races yield backtrack points that feed the explorer's race-guided seed derivation (no exact-prefix backtracking is replayed).

### Persistent Homology

Source: `src/trace/boundary.rs`, `src/trace/gf2.rs`, `src/trace/scoring.rs`

Topological signals from commuting diamond complexes. Betti numbers quantify scheduling freedom. GF(2) bitset algebra.

### Sheaf Consistency

Source: `src/trace/distributed/sheaf.rs`

Detects global inconsistency in distributed obligation tracking that evades pairwise checks.

### TLA+ Export

Source: `src/trace/tla_export.rs`

Export traces as TLA+ behaviors for bounded TLC model checking of core invariants.

### Vector Clocks

Source: `src/trace/distributed/vclock.rs`

Causal ordering for distributed tracing. Lamport, Vector, and Hybrid logical clock modes.

Do not infer complete runtime causality from those types alone. Default-runtime
producer coverage for every spawn, wake, cancel, and obligation edge is still an
open integration boundary; reports without the necessary producer metadata must
remain conservative rather than inventing a happens-before edge.

## Scenario-Based Testing

Source: `src/lab/scenario.rs`, `src/lab/scenario_runner.rs`

Reusable scenario YAML for: heavy chaos, partitions, host crash/restart, clock skew/lease behavior, cancellation campaigns.

```yaml
# examples/scenarios/partition_heal.yaml
# examples/scenarios/clock_skew_lease.yaml
```

## Test Artifact Outputs

`ASUPERSYNC_TEST_ARTIFACTS_DIR` names an artifact **root**, not one universal
layout. Inspect the harness you are using before constructing paths:

- `TestHarness` (`src/test_logging.rs`) writes failure artifacts beneath a
  sanitized test/scenario name: `event_log.txt`, `failed_assertions.json`, and
  `repro_manifest.json`. Its JSON test summary is written at the configured root
  as `<sanitized_test>_summary.json`.
- The NDJSON bundle writer (`src/test_ndjson.rs`) uses
  `<test_id>/<seed:016x>/` and writes `manifest.json`, `events.ndjson`,
  `environment.json`, and optional summary, trace, and failure files.
- Lab auto-forensics (`src/lab/runtime.rs`) writes a crashpack under
  `<sanitized_test>/seed-<seed>-trace-<fingerprint>/`. It is enabled by default;
  set `ASUPERSYNC_AUTO_ARTIFACTS=0` to disable it.

## Practical Test Shapes

### Minimal Deterministic Test

```rust
#[test]
fn test_cancel_safety() {
    let (_value, report) = run_async_under_lab(42, |cx| async move {
        /* test logic */
    });
    assert!(report.lab_test_passed());
    assert!(report.oracle_report.all_passed());
}
```

### Using Test Helpers

```rust
test_utils::run_test(|| async { /* simple async test */ });
test_utils::run_test_with_cx(|cx| async move { /* test with Cx */ });
```

Attribute macros: `#[asupersync::test]` (production runtime), `#[lab_test]`
(deterministic lab runtime; `#[asupersync::lab_test(seeds = A..B)]` runs a
seed matrix). `run_async_under_lab_with_config(LabConfig, ...)` accepts a full
`LabConfig` when the default seed-only entry point is not enough.

### Determinism Rules

- Never use `std::time::Instant::now()` -- use `cx.now()`
- Never use ambient RNG -- use `cx.random_u64()`
- Prefer `util::DetHashMap/DetHashSet` over `std::collections::HashMap/HashSet`
- Use `VirtualTcp` for deterministic protocol/model tests. Keep native socket,
  reactor, wakeup, and cancellation regressions on the production runtime;
  VirtualTcp is not a substitute for those execution-class boundaries.
