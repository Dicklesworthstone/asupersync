# Bounded Latency Regression Contract

Bead: `asupersync-1508v.4.6`

## Purpose

This contract defines how the kernel fast-path prototype is validated against fairness, wakeup correctness, obligation safety, and tail-latency regression bounds. Every regression dimension has explicit invariants that must pass before the fast-path can be promoted from fallback-gated to default.

## Contract Artifacts

1. Canonical artifact: `artifacts/bounded_latency_regression_v1.json`
2. Smoke runner: `scripts/run_bounded_latency_regression_smoke.sh`
3. Invariant suite: `tests/bounded_latency_regression_contract.rs`

## Regression Dimensions

| Dimension | Profile | Invariants | Fail Action |
|-----------|---------|------------|-------------|
| FAIRNESS-CANCEL-STORM | cancel-heavy | no starvation, fairness >= 0.3 | rollback |
| FAIRNESS-STEAL-PRESSURE | steal-asymmetric | imbalance <= 3x, no starvation | rollback |
| WAKEUP-RACE-CORRECTNESS | wake-park-race | zero lost wakeups, 100% completion | rollback |
| WAKEUP-COALESCE-CORRECTNESS | duplicate-wake-burst | all unique wakes delivered | disable coalescing |
| OBLIGATION-NO-LEAK | region-lifecycle | zero leaks at region close | rollback |
| QUIESCENCE-SHUTDOWN | graceful-shutdown | zero tasks/workers at shutdown | rollback |
| TAIL-LATENCY-P99 | mixed-realistic | p99 delta <= 5%, p999 delta <= 10% | rollback |
| TAIL-LATENCY-CANCEL-LANE | cancel-epoch-transition | cancel p99 <= 500us | widen streak |

## Tail Latency Table

Before/after comparison table columns:

| workload_id | substrate | p50_us | p95_us | p99_us | p999_us | verdict |

Verdict is `pass`, `regressed`, or `improved`. Any `regressed` verdict on a safety-critical dimension triggers the dimension's `fail_action`.

## Fallback Surfaces

Each prototype surface has an independent fallback flag:

| Surface | Flag | Rollback Action |
|---------|------|-----------------|
| shard-local-dispatch | `shard_local_dispatch` | Revert to Mutex<IntrusiveStack> |
| wake-coalescing | `wake_coalescing` | Revert to direct Mutex<HashSet<TaskId>> |
| adaptive-steal | `adaptive_steal` | Revert to fixed power-of-two-choices |

Rollback is per-surface: a wakeup regression disables only wake-coalescing without affecting shard-local dispatch.

## Structured Logging Contract

Regression and validation logs MUST include:

- `dimension_id`: Which regression dimension
- `workload_id`: Replay workload driving the test
- `substrate`: `incumbent` or `prototype`
- `invariant_name`, `invariant_value`, `invariant_threshold`, `invariant_pass`: Per-invariant results
- `p50_us`, `p95_us`, `p99_us`, `p999_us`: Tail latency percentiles
- `fairness_ratio`, `steal_imbalance_ratio`: Fairness metrics
- `lost_wakeup_count`, `obligation_leak_count`: Safety counters
- `fallback_surface`, `rollback_triggered`: Fallback state
- `verdict`: Pass/regress/improve

## Comparator-Smoke Runner

Canonical runner: `scripts/run_bounded_latency_regression_smoke.sh`

The runner reads `artifacts/bounded_latency_regression_v1.json` and emits:

1. Per-scenario bundle manifests with schema `bounded-latency-regression-smoke-bundle-v1`
2. Aggregate run report with schema `bounded-latency-regression-smoke-run-report-v1`

Examples:

```bash
bash ./scripts/run_bounded_latency_regression_smoke.sh --list
bash ./scripts/run_bounded_latency_regression_smoke.sh --scenario BLR-SMOKE-FAIRNESS --dry-run
bash ./scripts/run_bounded_latency_regression_smoke.sh --execute
```

## Validation

Focused invariant test command (routed through `rch`):

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa043 cargo test --test bounded_latency_regression_contract -- --nocapture
```

## Cross-References

- `artifacts/bounded_latency_regression_v1.json`
- `scripts/run_bounded_latency_regression_smoke.sh`
- `tests/bounded_latency_regression_contract.rs`
- `artifacts/kernel_fast_path_prototype_v1.json` -- AA-04.2 prototype surfaces
- `artifacts/kernel_fast_path_substrate_comparison_v1.json` -- AA-04.1 substrate candidates
- `artifacts/controller_interference_validation_v1.json` -- AA-03.3 interference model
- `src/runtime/kernel.rs` -- ControllerRegistry, decision plane
- `src/runtime/scheduler/local_queue.rs` -- Shard-local dispatch
