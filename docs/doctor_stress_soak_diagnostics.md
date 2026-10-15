# doctor Stress/Soak Diagnostics

Bead: `asupersync-2b4jj.6.8`

## Purpose

Define the deterministic soak and stress diagnostics surface for
`doctor_asupersync`, covering sustained-conformance budget gates,
workload catalogs, checkpoint-based progress tracking, and failure
output quality standards.

## Workload Catalog

### Pressure Classes

| Class | Description | Duration | Concurrency |
|-------|-------------|----------|-------------|
| `high_volume` | Sustained high finding volume with constant operator pressure | Long (100+ steps) | 8 |
| `concurrent_ops` | Concurrent operator actions with moderate finding load | Medium (80 steps) | 16 |
| `cancel_recovery` | Cancellation and recovery pressure with bursty workloads | Short (60 steps) | 4 |
| `steady_state` | Long-duration steady-state workload for saturation detection | Extended (500+ steps) | 4 |

### Scenario Catalog

Four canonical scenarios exercise the pressure classes:

1. **stress-high-volume**: exercises `scan-large` budget envelope under
   sustained high finding throughput.
2. **stress-concurrent-ops**: exercises `analyze-medium` budget under
   concurrent operator actions.
3. **stress-cancel-recovery**: exercises `remediate-medium` budget under
   30% cancellation rate—expected to trigger budget failure.
4. **soak-steady-state**: exercises `scan-medium` budget over 500 steps
   to detect slow saturation drift.

## Sustained Budget Policy

Budget conformance is not a single-point check; it must be sustained
across all post-warmup checkpoints:

| Policy | Metric | Warmup | Threshold | Action |
|--------|--------|--------|-----------|--------|
| SBP-01 | `latency_p99_ms` | 1 checkpoint | Budget envelope ceiling | `budget_failed` |
| SBP-02 | `memory_peak_mb` | 0 checkpoints | Budget envelope ceiling | `budget_failed` |
| SBP-03 | `error_rate_bps` | 1 checkpoint | 500 basis points | `budget_failed` |
| SBP-04 | `drift_basis_points` | 1 checkpoint | 2000 basis points | `budget_failed` |

## Checkpoint Metrics

Each checkpoint captures:

| Field | Type | Description |
|-------|------|-------------|
| `checkpoint_index` | `usize` | Zero-based checkpoint sequence number |
| `latency_p50_ms` | `u64` | p50 latency at this checkpoint |
| `latency_p95_ms` | `u64` | p95 latency at this checkpoint |
| `latency_p99_ms` | `u64` | p99 latency at this checkpoint |
| `memory_peak_mb` | `u64` | Peak memory at this checkpoint |
| `error_rate_bps` | `u64` | Error rate in basis points |
| `drift_basis_points` | `u64` | Latency drift from baseline checkpoint |

## Failure Output Quality

When a run's status is `budget_failed`, the `failure_output` must include:

1. **`saturation_indicators`**: sorted list of human-readable strings
   identifying which thresholds were breached, with measured vs. threshold
   values and the governing policy ID.
2. **`trace_correlation`**: a `trace-` prefixed identifier linking the
   failure to the specific checkpoint and scenario for diagnosis.
3. **`rerun_command`**: a deterministic CLI command that reproduces the
   exact failure scenario.

## Determinism Invariants

1. Same seed + same scenario produces identical checkpoint_metrics.
2. Same seed + same scenario produces identical violation list.
3. Same seed + same scenario produces identical quality score.
4. Checkpoint metrics are ordered by `checkpoint_index` ascending.
5. Runs are ordered by `scenario_id` lexically.
6. Saturation indicators are sorted lexically within `failure_output`.

## Profile Modes

| Mode | Duration | Purpose |
|------|----------|---------|
| `fast` | Shortened durations (10% of steps) | CI smoke check |
| `soak` | Full durations | Nightly sustained conformance |

## Artifact Index

Each run produces three artifacts:

| Class | Description |
|-------|-------------|
| `structured_log` | JSONL structured event stream |
| `summary` | JSON summary with checkpoint metrics |
| `transcript` | Human-readable log transcript |

## CI Integration

```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_doctor_stress_docs cargo test --test doctor_stress_soak_diagnostics -- --nocapture
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_doctor_stress_docs cargo check --all-targets
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_doctor_stress_docs cargo clippy --all-targets -- -D warnings
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_doctor_stress_docs cargo fmt --check
```

E2E runner:

```bash
./scripts/test_doctor_stress_soak_e2e.sh
```

## Cross-References

- `docs/doctor_performance_budget_contract.md` — budget envelope definitions
- `docs/doctor_logging_contract.md` — structured logging contract
- `docs/doctor_logging_quality_governance.md` — logging quality rules
- `tests/fixtures/doctor_stress_soak/workload_catalog.json` — canonical catalog
- `tests/fixtures/doctor_stress_soak/smoke_report.json` — golden smoke report
- `scripts/test_doctor_stress_soak_e2e.sh` — E2E stress/soak runner
