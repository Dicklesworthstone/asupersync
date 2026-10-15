# doctor_asupersync Performance Budget and Instrumentation Gate Contract

**Bead**: `asupersync-2b4jj.6.2`
**Parent**: Track 6: Quality gates, packaging, and rollout
**Date**: 2026-03-02
**Author**: SapphireHill

---

## 1. Purpose

This document defines the performance budget matrix, gate evaluation model, and instrumentation contract for `doctor_asupersync` workflows. It establishes deterministic latency, memory, and render-cost targets with automated fail conditions, structured diagnostics for regressions, and CI-compatible validation gates routed through the rch execution adapter.

---

## 2. Budget Data Model

### 2.1 Performance Budget

A `DoctorPerformanceBudget` defines the complete budget matrix for a workflow category:

| Field | Type | Purpose |
|-------|------|---------|
| `budget_id` | `String` | Stable budget identifier |
| `workflow_category` | `String` | One of: `scan`, `analyze`, `ingest`, `remediate`, `render` |
| `dataset_profile` | `String` | Dataset size class: `small`, `medium`, `large` |
| `latency_p50_ms` | `u64` | p50 latency ceiling in milliseconds |
| `latency_p95_ms` | `u64` | p95 latency ceiling in milliseconds |
| `latency_p99_ms` | `u64` | p99 latency ceiling in milliseconds |
| `memory_ceiling_mb` | `u32` | Peak resident memory ceiling in megabytes |
| `render_cost_max` | `u32` | Maximum render/update cost units per frame |
| `update_cost_max` | `u32` | Maximum state-update cost units per cycle |

### 2.2 Performance Metric

A `DoctorPerformanceMetric` captures one measured data point:

| Field | Type | Purpose |
|-------|------|---------|
| `metric_id` | `String` | Stable metric identifier |
| `metric_class` | `String` | One of: `latency`, `memory`, `render_cost`, `update_cost` |
| `workflow_category` | `String` | Workflow that produced this metric |
| `dataset_profile` | `String` | Dataset size class used |
| `value` | `u64` | Measured value |
| `unit` | `String` | Unit of measurement (`ms`, `mb`, `cost_units`) |
| `percentile` | `String` | Percentile tag: `p50`, `p95`, `p99`, or `peak` |
| `correlation_id` | `String` | Links to execution run |

### 2.3 Gate Evaluation

A `DoctorPerformanceGateEvaluation` records the outcome of one budget check:

| Field | Type | Purpose |
|-------|------|---------|
| `gate_id` | `String` | Stable gate identifier |
| `budget_id` | `String` | Budget that was evaluated |
| `metric_id` | `String` | Metric that was measured |
| `threshold` | `u64` | Budget ceiling value |
| `measured` | `u64` | Actual measured value |
| `outcome` | `String` | One of: `pass`, `warn`, `fail` |
| `headroom_pct` | `i32` | Percentage below ceiling (negative = over budget) |
| `confidence` | `u8` | Confidence score (0..=100) |
| `correlation_id` | `String` | Links to execution run |

### 2.4 Gate Report

A `DoctorPerformanceGateReport` aggregates all gate evaluations for a run:

| Field | Type | Purpose |
|-------|------|---------|
| `schema_version` | `String` | `doctor-performance-gate-report-v1` |
| `run_id` | `String` | Deterministic run identifier |
| `scenario_id` | `String` | Scenario identifier |
| `budgets` | `Vec<PerformanceBudget>` | Budget matrix evaluated |
| `metrics` | `Vec<PerformanceMetric>` | Collected metrics |
| `evaluations` | `Vec<GateEvaluation>` | Gate outcomes |
| `overall_outcome` | `String` | Worst-case outcome: `pass`, `warn`, or `fail` |
| `reproduction_command` | `String` | Deterministic rerun pointer |
| `correlation_id` | `String` | Links to harness run |

---

## 3. Budget Matrix

### 3.1 Workflow Categories

| Category | Description | Key Metric |
|----------|-------------|-----------|
| `scan` | Workspace scanning and member enumeration | Latency |
| `analyze` | Invariant and lock-contention analysis | Latency + Memory |
| `ingest` | Evidence ingestion and normalization | Latency |
| `remediate` | Fix preview, apply, and verification | Latency + Render |
| `render` | TUI panel rendering and update cycles | Render cost |

### 3.2 Dataset Profiles

| Profile | Members | Artifacts | Lock Acquisitions |
|---------|---------|-----------|-------------------|
| `small` | 1-10 | 1-5 | < 50 |
| `medium` | 10-50 | 5-25 | 50-500 |
| `large` | 50-200 | 25-100 | > 500 |

### 3.3 Baseline Budgets

| Workflow | Dataset | p50 (ms) | p95 (ms) | p99 (ms) | Memory (MB) | Render Cost | Update Cost |
|----------|---------|----------|----------|----------|-------------|-------------|-------------|
| `scan` | `small` | 50 | 100 | 200 | 32 | — | — |
| `scan` | `medium` | 200 | 500 | 1000 | 64 | — | — |
| `scan` | `large` | 500 | 1500 | 3000 | 128 | — | — |
| `analyze` | `small` | 100 | 250 | 500 | 48 | — | — |
| `analyze` | `medium` | 500 | 1500 | 3000 | 96 | — | — |
| `analyze` | `large` | 2000 | 5000 | 10000 | 256 | — | — |
| `ingest` | `small` | 25 | 50 | 100 | 16 | — | — |
| `ingest` | `medium` | 100 | 250 | 500 | 32 | — | — |
| `ingest` | `large` | 250 | 750 | 1500 | 64 | — | — |
| `remediate` | `small` | 100 | 250 | 500 | 32 | 50 | 25 |
| `remediate` | `medium` | 500 | 1500 | 3000 | 64 | 100 | 50 |
| `remediate` | `large` | 2000 | 5000 | 10000 | 128 | 200 | 100 |
| `render` | `small` | 8 | 16 | 33 | 16 | 25 | 10 |
| `render` | `medium` | 16 | 33 | 50 | 32 | 50 | 25 |
| `render` | `large` | 33 | 50 | 100 | 64 | 100 | 50 |

### 3.4 Warning Thresholds

Budget gates produce `warn` when measured values exceed 80% of the ceiling but remain within budget, and `fail` when measured values exceed the ceiling.

| Outcome | Condition |
|---------|-----------|
| `pass` | measured <= threshold * 0.80 |
| `warn` | threshold * 0.80 < measured <= threshold |
| `fail` | measured > threshold |

---

## 4. Gate Evaluation Logic

### 4.1 Evaluation Algorithm

```
for each (budget, metric) pair where budget matches metric category:
  headroom = ((threshold - measured) * 100) / threshold
  if measured > threshold:
    outcome = fail
  elif measured > threshold * 0.80:
    outcome = warn
  else:
    outcome = pass
  emit GateEvaluation { outcome, headroom_pct, ... }

overall_outcome = worst(all evaluations)
```

### 4.2 Confidence Scoring

Gate evaluations carry a deterministic confidence score:

| Condition | Confidence |
|-----------|-----------|
| Single measurement, synthetic data | 50 |
| Repeated measurements (3+), synthetic data | 70 |
| Single measurement, production-scale data | 80 |
| Repeated measurements (3+), production-scale data | 95 |
| Baseline from golden fixtures | 100 |

### 4.3 Failure Diagnostics

When a gate evaluation produces `fail`, the structured log must include:

1. **Breached metric**: metric class, percentile, measured value, threshold
2. **Baseline comparison**: difference from budget ceiling as percentage
3. **Trace identifiers**: correlation_id, run_id, scenario_id
4. **Reproducible rerun command**: deterministic command for local reproduction
5. **Remediation guidance**: actionable next step for operator

---

## 5. Structured Log Integration

### 5.1 Event Kinds

Performance gate events extend the structured logging taxonomy:

| Event Kind | Flow | Description |
|-----------|------|-------------|
| `perf_metric_collected` | `execution` | Raw metric measurement recorded |
| `perf_gate_evaluated` | `execution` | Budget gate check completed |
| `perf_gate_report_emitted` | `execution` | Aggregate gate report produced |
| `perf_regression_detected` | `execution` | Gate failure indicating regression |

### 5.2 Event Fields

Performance events include these structured fields:

| Field | Type | Event Kinds |
|-------|------|------------|
| `budget_id` | `string` | `perf_gate_evaluated`, `perf_regression_detected` |
| `metric_class` | `string` | `perf_metric_collected`, `perf_gate_evaluated` |
| `measured_value` | `string` | `perf_metric_collected`, `perf_gate_evaluated` |
| `threshold_value` | `string` | `perf_gate_evaluated`, `perf_regression_detected` |
| `outcome` | `string` | `perf_gate_evaluated` |
| `headroom_pct` | `string` | `perf_gate_evaluated` |
| `overall_outcome` | `string` | `perf_gate_report_emitted` |
| `reproduction_command` | `string` | `perf_regression_detected` |

---

## 6. CI Integration

### 6.1 rch-Compatible Commands

Performance gates are invoked through the execution adapter with `prefer_remote: true`:

```bash
# Run performance gate validation
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_doctor_performance_docs cargo test --test doctor_performance_budget_gates --features cli -- --nocapture

# Run via rch for heavy workloads
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_doctor_performance_docs cargo test --test doctor_performance_budget_gates --features cli -- --nocapture
```

### 6.2 Artifact Retention

Gate report artifacts follow the visual harness retention policy:

| Artifact Class | Retention | Purpose |
|---------------|-----------|---------|
| `perf_report` | `hot` | Active gate report for regression tracking |
| `perf_metrics` | `warm` | Raw metrics archive for trend analysis |
| `perf_baseline` | `hot` | Golden baseline for comparison |

---

## 7. Determinism Invariants

1. **Budget determinism**: given the same `(workflow_category, dataset_profile)`, budget ceilings are identical.
2. **Metric determinism**: given the same synthetic workload and seed, measured values are identical.
3. **Gate determinism**: given the same `(budget, metric)`, evaluation outcome is identical.
4. **Headroom determinism**: `headroom_pct = ((threshold - measured) * 100) / threshold` (integer division, clamped to i32).
5. **Outcome ordering**: `pass < warn < fail` for worst-case aggregation.
6. **Report ordering**: evaluations in gate reports are sorted by `gate_id` lexically.
7. **Metric ordering**: metrics in gate reports are sorted by `metric_id` lexically.
8. **Confidence determinism**: confidence score is fully determined by measurement methodology.

---

## 8. CI Validation

### 8.1 Automated Gates

| Gate | Test File | Checks |
|------|----------|--------|
| Budget construction | `tests/doctor_performance_budget_gates.rs` | Budget matrix completeness and field validity |
| Metric collection | `tests/doctor_performance_budget_gates.rs` | Metric struct invariants and serde roundtrip |
| Gate evaluation | `tests/doctor_performance_budget_gates.rs` | Outcome logic (pass/warn/fail thresholds) |
| Report assembly | `tests/doctor_performance_budget_gates.rs` | Report ordering, correlation, and diagnostics |
| Fixture schema | `tests/doctor_performance_budget_gates.rs` | Golden fixture validation |
| Document coverage | `tests/doctor_performance_budget_gates.rs` | All sections and invariants documented |

### 8.2 Reproduction

```bash
# Run performance budget gate tests
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_doctor_performance_docs cargo test --test doctor_performance_budget_gates --features cli -- --nocapture

# Run visual regression harness (dependency)
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_doctor_performance_docs cargo test --test doctor_visual_regression_harness --features cli -- --nocapture
```

---

## 9. Cross-References

- Visual regression harness: `docs/doctor_visual_regression_harness.md`
- E2E harness contract: `docs/doctor_e2e_harness_contract.md`
- Logging contract: `docs/doctor_logging_contract.md`
- Execution adapter: `docs/doctor_execution_adapter_contract.md`
- Analyzer fixture harness: `docs/doctor_analyzer_fixture_harness.md`
- Implementation: `src/cli/doctor/mod.rs`
- Performance gate tests: `tests/doctor_performance_budget_gates.rs`
- Visual harness tests: `tests/doctor_visual_regression_harness.rs`
