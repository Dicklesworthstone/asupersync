# Track-Level Performance Regression Budgets and Alarm Policy

**Bead**: `asupersync-2oh2u.10.7` ([T8.7])  
**Program**: `asupersync-2oh2u` ([TOKIO-REPLACE])  
**Date**: 2026-03-03  
**Dependencies**: `asupersync-2oh2u.10.3`, `asupersync-2oh2u.10.4`, `asupersync-2oh2u.10.5`, `docs/tokio_differential_behavior_suites.md`, `docs/tokio_ci_quality_gate_enforcement.md`  
**Purpose**: define deterministic, track-level performance regression budgets and alarm semantics that gate promotion when Tokio-replacement behavior regresses beyond approved thresholds.

---

## 1. Scope and Intent

T8.7 establishes objective regression budgets over deterministic workloads for tracks T2-T7 and cross-track scheduler/cancel paths. This policy is not a microbenchmark vanity layer; it is a release-risk control system tied to migration safety.

This contract governs:

- baseline sourcing from deterministic differential suites,
- numeric budget thresholds for latency, throughput, memory, and cancellation-drain overhead,
- alarm escalation and release-block semantics,
- required artifacts and reproducible rerun commands.

This contract does not replace track-specific bench harnesses; it provides common policy that those harnesses must satisfy.

---

## 2. Canonical Metric Schema

Every evaluated metric entry in `tokio_track_performance_regression_manifest.json` MUST include:

| Field | Required | Description |
|---|---|---|
| `track_id` | yes | `T2`..`T7` or `Cross` |
| `suite_id` | yes | source differential suite (`DS-*`) |
| `scenario_id` | yes | deterministic scenario token |
| `metric_id` | yes | stable metric identifier (`PM-*`) |
| `metric_kind` | yes | `latency_p95_ms`, `latency_p99_ms`, `throughput_ops_per_sec`, `memory_peak_mb`, `cancel_drain_ms` |
| `baseline_value` | yes | accepted baseline metric |
| `candidate_value` | yes | current run metric |
| `regression_pct` | yes | computed relative drift |
| `budget_id` | yes | policy row id (`PB-*`) |
| `decision` | yes | `PASS`, `WARN`, `FAIL`, or `BLOCKED` |
| `alarm_ids` | yes | triggered alarm rules (`AL-*`) |
| `artifact_paths` | yes | pointers to logs/traces/bench output |
| `repro_command` | yes | deterministic rerun command |
| `generated_at` | yes | timestamp for deterministic policy evaluation |

Missing required fields is a hard policy failure.

---

## 3. Budget Catalog (Normative)

### 3.1 Decision States

Allowed decision states:

- `PASS`: within budget.
- `WARN`: exceeded warning threshold, below fail threshold.
- `FAIL`: exceeded hard-fail threshold.
- `BLOCKED`: infrastructure incident prevented valid measurement; must include incident id and rerun command.

`BLOCKED` is never equivalent to `PASS` and cannot be used to satisfy promotion gates.

### 3.2 Budget Rows

| Budget ID | Track | Metric Kind | Warning Threshold | Hard-Fail Threshold |
|---|---|---|---|---|
| `PB-01` | `T2` | `latency_p95_ms` | `+8%` | `+15%` |
| `PB-02` | `T2` | `cancel_drain_ms` | `+10%` | `+20%` |
| `PB-03` | `T3` | `latency_p99_ms` | `+8%` | `+15%` |
| `PB-04` | `T3` | `throughput_ops_per_sec` | `-8%` | `-15%` |
| `PB-05` | `T4` | `latency_p99_ms` | `+10%` | `+18%` |
| `PB-06` | `T4` | `memory_peak_mb` | `+10%` | `+20%` |
| `PB-07` | `T5` | `latency_p95_ms` | `+8%` | `+15%` |
| `PB-08` | `T5` | `throughput_ops_per_sec` | `-8%` | `-15%` |
| `PB-09` | `T6` | `latency_p99_ms` | `+10%` | `+20%` |
| `PB-10` | `T6` | `cancel_drain_ms` | `+10%` | `+20%` |
| `PB-11` | `T7` | `latency_p95_ms` | `+8%` | `+15%` |
| `PB-12` | `Cross` | `cancel_drain_ms` | `+10%` | `+20%` |
| `PB-13` | `Cross` | `memory_peak_mb` | `+10%` | `+20%` |
| `PB-14` | `Cross` | `throughput_ops_per_sec` | `-8%` | `-15%` |

Negative thresholds indicate throughput drop relative to baseline.

---

## 4. Alarm Rules

| Alarm ID | Trigger | Severity | Gate Effect |
|---|---|---|---|
| `AL-01` | Any `FAIL` on a `PB-*` row | critical | hard-fail promotion |
| `AL-02` | 2+ `WARN` in same track within one run | high | promote only with owner-approved waiver artifact |
| `AL-03` | `BLOCKED` without incident id | high | hard-fail policy integrity |
| `AL-04` | Missing `repro_command` for `WARN`/`FAIL`/`BLOCKED` | high | hard-fail policy integrity |
| `AL-05` | Baseline older than staleness window | high | hard-fail (`stale_baseline`) |
| `AL-06` | Candidate run missing deterministic seed metadata | high | hard-fail (`non_deterministic_measurement`) |
| `AL-07` | Differential suite result is non-reproducible | high | exclude metric from budget pass and mark gate `BLOCKED` |
| `AL-08` | Metric schema drift vs required fields | critical | hard-fail policy |

Alarm processing is deterministic over the manifest and does not depend on ambient state.

---

## 5. Baseline and Staleness Policy

| Rule ID | Rule |
|---|---|
| `BG-01` | Baselines MUST be sourced from deterministic differential suites (`DS-T*`/`DS-X-*`) produced by `asupersync-2oh2u.10.3`. |
| `BG-02` | Non-reproducible fuzz/race outcomes from `asupersync-2oh2u.10.4` are excluded from baseline updates. |
| `BG-03` | Baseline staleness window is 14 days or 500 commits, whichever occurs first. |
| `BG-04` | Baseline update requires explicit artifact digest + owner in manifest metadata. |
| `BG-05` | Mixed-baseline runs (different `commit_sha` sources per track) are invalid and hard-fail. |

---

## 6. Required Artifact Bundle

Every T8.7 run MUST emit:

- `tokio_track_performance_regression_manifest.json`
- `tokio_track_performance_regression_report.md`
- `tokio_track_performance_regression_alarms.json`
- `tokio_track_performance_regression_repro_commands.txt`

Missing artifacts fail this policy contract.

---

## 7. Runner Contract and Commands

Heavy commands MUST be run through `rch exec --`.

Required command tokens:

- `rch exec -- cargo check --all-targets`
- `rch exec -- cargo clippy --all-targets -- -D warnings`
- `rch exec -- cargo fmt --check`
- `rch exec -- cargo test --test tokio_differential_behavior_suites -- --nocapture`
- `rch exec -- cargo test --test tokio_ci_quality_gate_enforcement -- --nocapture`
- `rch exec -- cargo test --test tokio_track_performance_regression_budgets -- --nocapture`

---

## 8. Gate Integration

T8.7 evaluation outputs are consumed by quality-gate policy in `QG-06` release decisions, with additional policy-derived checks:

- `QG-07` Performance budget compliance (all required `PB-*` rows evaluated, no unresolved `FAIL`),
- `QG-08` Alarm hygiene (all triggered alarms resolved or accompanied by explicit waiver record).

`QG-07` and `QG-08` are hard-fail for replacement readiness and cannot be bypassed silently.

---

## 9. Downstream Binding

| Downstream Bead | Binding |
|---|---|
| `asupersync-2oh2u.10.9` | readiness aggregator consumes `QG-07`/`QG-08` and alarm outputs as release blockers |
| `asupersync-2oh2u.10.12` | cross-track logging gate consumes alarm + repro schema requirements |
| `asupersync-2oh2u.11.9` | migration GA policy consumes performance budget state as promotion evidence |

T8.7 is complete only when this budget+alarm policy is explicit, deterministic, reproducible, and covered by executable contract tests.
