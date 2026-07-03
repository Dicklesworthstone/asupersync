# Lab Runtime, DPOR, and Trace Infrastructure

## LabRuntime

Source: `src/lab/runtime.rs`, `src/lab/config.rs`

Deterministic runtime for testing. Same seed = same execution = reproducible bugs.

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

## Oracle Suite

Source: `src/lab/oracle/`

### Available Oracles

- **Quiescence oracle**: verifies region close implies no live children
- **Obligation leak oracle**: verifies all obligations resolved
- **Loser drain oracle**: verifies race losers fully drained
- **Cancellation protocol oracle**: verifies request -> drain -> finalize sequence

### E-Process Monitoring

Source: `src/lab/oracle/eprocess.rs`

Anytime-valid monitoring using supermartingale-based testing. Can peek after every scheduling step with controlled type-I error (Ville's inequality).

### Evidence Ledger

Source: `src/lab/oracle/evidence.rs`

Structured evidence with Bayes factors and log-likelihood contributions for subtle failures.

### Conformal Calibration

Source: `src/lab/conformal.rs`

Split conformal prediction for oracle anomaly thresholds. Distribution-free, finite-sample coverage guarantees under exchangeability.

## Virtual Time Wheel

Source: `src/lab/virtual_time_wheel.rs`

Deterministic virtual time with explicit tie-breaking. Sleeps complete instantly; time is controlled by the lab scheduler.

## DPOR Schedule Explorer

Source: `src/lab/explorer.rs`

DPOR-style schedule exploration treating executions as Mazurkiewicz traces:
- Track coverage by equivalence class fingerprints
- Prioritize exploration based on trace topology
- Deterministic, replayable concurrency debugging with coverage semantics

## Trace Infrastructure

### Canonicalization

Source: `src/trace/canonicalize.rs`

Mazurkiewicz trace monoid: two traces differing only by swapping adjacent independent events are equivalent. Canonicalized to Foata normal form for stable fingerprints.

### Geodesic Normalization

Source: `src/trace/geodesic.rs`

Constructs valid linear extensions minimizing owner switches via A* solver. Smaller, more canonical traces for diff/replay/minimize.

### Race Detection

Source: `src/trace/dpor.rs`, `src/trace/independence.rs`

Vector clocks per task plus resource-footprint conflicts. Backtracking point extraction for systematic interleaving exploration.

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

## Scenario-Based Testing

Source: `src/lab/scenario.rs`, `src/lab/scenario_runner.rs`

Reusable scenario YAML for: heavy chaos, partitions, host crash/restart, clock skew/lease behavior, cancellation campaigns.

```yaml
# examples/scenarios/partition_heal.yaml
# examples/scenarios/clock_skew_lease.yaml
```

## Test Artifact Outputs

When `ASUPERSYNC_TEST_ARTIFACTS_DIR` is set:
- `event_log.txt`
- `failed_assertions.json`
- `repro_manifest.json`
- JSON summaries for replay automation

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

### Determinism Rules

- Never use `std::time::Instant::now()` -- use `cx.now()`
- Never use ambient RNG -- use `cx.random_u64()`
- Prefer `util::DetHashMap/DetHashSet` over `std::collections::HashMap/HashSet`
- Use `VirtualTcp` for network tests instead of real sockets
