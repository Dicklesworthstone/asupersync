# Digital Twin Contract

Bead: `asupersync-1508v.3.4`

## Purpose

This contract defines a queueing/network-calculus digital twin for the runtime's hot paths. The twin models the scheduler ready queue, cancel lane drain, finalize lane, obligation settlement, I/O reactor dispatch, admission control, retry backoff, and work-stealing as explicit queue stages with service curve parameters tied to `RuntimeKernelSnapshot` fields and AA-01 workload IDs.

The twin is approximate by design. All predictions carry disclosed error bounds and can be compared against replayed workload evidence.

## Contract Artifacts

1. Canonical artifact: `artifacts/digital_twin_v1.json`
2. Smoke runner: `scripts/run_digital_twin_smoke.sh`
3. Invariant suite: `tests/digital_twin_contract.rs`

## Queue Stage Model

Each runtime hot path is modeled as a named queue stage:

| Stage ID | Name | Service Curve | Key Parameters |
|----------|------|---------------|----------------|
| DT-READY-QUEUE | Scheduler Ready Queue | rate-latency | worker_count, queue_depth |
| DT-CANCEL-LANE | Cancel Lane Drain | token-bucket | streak_limit, burst |
| DT-FINALIZE-LANE | Finalize Lane | rate-latency | queue_depth |
| DT-OBLIGATION-SETTLE | Obligation Settlement | batch | outstanding, leak_count |
| DT-IO-REACTOR | I/O Reactor Dispatch | rate-latency | pending_io, timers |
| DT-ADMISSION-GATE | Admission Control | leaky-bucket | total_tasks, regions |
| DT-RETRY-BACKOFF | Retry Backoff Queue | rate-latency | (time-varying) |
| DT-STEAL-PATH | Work-Stealing Path | batch | worker_count |

## Service Curve Types

- **rate-latency**: `beta(t) = R * max(0, t - T)` — constant rate R after latency T
- **token-bucket**: `alpha(t) = min(P*t, B + r*t)` — peak P, burst B, sustained r
- **leaky-bucket**: `alpha(t) = r*t + b` — rate r, burst b
- **batch**: Periodic batch service with size B and period P

## Snapshot Field Mapping

Each twin stage parameter is mapped to a `RuntimeKernelSnapshot` field, ensuring the twin can be driven from live runtime observations. The mapping is declared in `artifacts/digital_twin_v1.json` under `snapshot_field_mapping`.

## Error Budget

Twin predictions carry disclosed approximation error:

| Metric | Max Relative Error |
|--------|--------------------|
| p50 delay prediction | 15% |
| p99 delay prediction | 30% |
| Throughput prediction | 10% |

Predictions outside these bounds are flagged as `within_error_budget: false`.

## Structured Logging Contract

Twin diagnostic logs MUST include:

- `stage_id`: Queue stage being evaluated
- `model_version`: Twin model version
- `workload_id`: Workload driving the evaluation
- `snapshot_id`: Runtime snapshot ID
- `predicted_p50_us` / `predicted_p99_us`: Twin predictions
- `observed_p50_us` / `observed_p99_us`: Observed values
- `relative_error_p50` / `relative_error_p99`: Error metrics
- `service_curve_type`: Curve type for this stage
- `parameters_json`: Curve parameters
- `within_error_budget`: Whether prediction meets budget
- `replay_command`: Exact command to reproduce

## Comparator-Smoke Runner

Canonical runner: `scripts/run_digital_twin_smoke.sh`

The runner reads `artifacts/digital_twin_v1.json` and emits:

1. Per-scenario bundle manifests with schema `digital-twin-smoke-bundle-v1`
2. Aggregate run report with schema `digital-twin-smoke-run-report-v1`

Examples:

```bash
# List scenarios
bash ./scripts/run_digital_twin_smoke.sh --list

# Dry-run
bash ./scripts/run_digital_twin_smoke.sh --scenario DT-SMOKE-STAGES --dry-run

# Execute
bash ./scripts/run_digital_twin_smoke.sh --scenario DT-SMOKE-STAGES --execute
```

## Validation

Focused invariant test command (routed through `rch`):

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_digital_twin cargo test -p asupersync --test digital_twin_contract --features test-internals -- --nocapture
```

## Cross-References

- `artifacts/digital_twin_v1.json`
- `scripts/run_digital_twin_smoke.sh`
- `tests/digital_twin_contract.rs`
- `src/runtime/kernel.rs` -- RuntimeKernelSnapshot fields
- `artifacts/runtime_control_seam_inventory_v1.json` -- Seam IDs
- `artifacts/runtime_workload_corpus_v1.json` -- Workload IDs
- `docs/runtime_control_seam_inventory_contract.md`
