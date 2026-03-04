# I/O Track Conformance and Performance Gate Contract

**Bead**: `asupersync-2oh2u.2.8` ([T2.8])  
**Program**: `asupersync-2oh2u` ([TOKIO-REPLACE])  
**Date**: 2026-03-04  
**Dependencies**: `asupersync-2oh2u.2.5`, `asupersync-2oh2u.2.6`, `docs/tokio_io_parity_audit.md`, `docs/tokio_io_codec_cancellation_correctness.md`  
**Purpose**: define deterministic conformance and performance gates for the T2 I/O+codec track so closure and promotion claims are blocked on explicit, reproducible, machine-verifiable evidence.

---

## 1. Scope and Gate Intent

T2.8 introduces hard gates for hot-path I/O and codec behavior. The contract must prevent "done" claims that rely on ad hoc notes or partial test evidence.

This contract governs:

- protocol correctness evidence for read/write/codec surfaces,
- cancellation and loser-drain behavior evidence,
- backend parity checks across reactor paths required by T2.6,
- deterministic performance budget checks for hot-path operations,
- owner-routed diagnostics for fast failure triage.

This contract does not replace implementation tests; it defines the gate layer those tests must satisfy.

---

## 2. Canonical Evidence Schema

Every gate evaluation run MUST emit a deterministic evidence manifest for T2.

| Field | Required | Description |
|---|---|---|
| `run_id` | yes | stable run identifier |
| `commit_sha` | yes | source revision for all artifacts |
| `track_id` | yes | must be `T2` |
| `contract_id` | yes | gate contract token (`IOCG-*`/`IOPG-*`) |
| `scenario_id` | yes | deterministic scenario token |
| `backend` | yes | reactor backend (`epoll`/`kqueue`/`io_uring`/`poll`) |
| `transport_surface` | yes | `read`, `write`, `copy`, `framed_read`, `framed_write`, `codec` |
| `cancellation_path` | yes | `none`, `request_drain_finalize`, `race_loser_drop` |
| `failure_class` | yes | normalized failure class (`protocol_mismatch`, `cancel_leak`, `stale_token`, etc.) |
| `owning_bead` | yes | bead that owns remediation |
| `owning_module` | yes | module path owning the behavior |
| `artifact_path` | yes | location of raw trace/log/test output |
| `latency_p95_us` | yes | p95 latency metric for scenario |
| `throughput_bytes_per_sec` | yes | throughput metric for scenario |
| `regression_pct` | yes | relative drift versus accepted baseline |
| `verdict` | yes | `PASS`, `FAIL`, or `BLOCKED` |
| `generated_at` | yes | evidence generation timestamp |
| `repro_command` | yes | deterministic rerun command |

Missing required schema fields is a hard gate failure.

---

## 3. Conformance Gate Set (Normative)

| Gate ID | Gate Name | Inputs | Hard-Fail Conditions |
|---|---|---|---|
| `IOCG-01` | Core protocol parity | read/write/copy/framed contract tests | behavioral mismatch against Tokio-equivalent contract |
| `IOCG-02` | Cancellation-correctness | T2.5 cancellation corpus | obligation leak, task leak, or loser not drained |
| `IOCG-03` | Reactor backend parity | T2.6 backend readiness tests | backend-specific divergence, stale-token safety failure |
| `IOCG-04` | Codec framing correctness | framed + codec decode/encode suites | framing boundary corruption or decode state drift |
| `IOCG-05` | Evidence reproducibility | rerun of selected failing/passing cases | non-deterministic verdict for identical manifest |
| `IOCG-06` | Diagnostics owner routing | failure mapping bundle | missing owner mapping (`owning_bead`/`owning_module`) |

Conformance gates are blocking gates. Any unresolved `FAIL` blocks track closure.

---

## 4. Performance Budget Gate Set (Normative)

| Gate ID | Metric Class | Budget Threshold | Hard-Fail Condition |
|---|---|---|---|
| `IOPG-01` | hot-path read latency p95 | `<= +10%` drift | `regression_pct > 10` |
| `IOPG-02` | hot-path write latency p95 | `<= +10%` drift | `regression_pct > 10` |
| `IOPG-03` | framed decode/encode latency p95 | `<= +12%` drift | `regression_pct > 12` |
| `IOPG-04` | copy/copy_buf throughput | `>= -8%` drift | throughput drop below `-8%` |
| `IOPG-05` | cancel/drain overhead | `<= +12%` drift | cancel/drain overhead above `+12%` |

Budget checks are deterministic over accepted baseline snapshots and measured candidate values.

---

## 5. Required Artifact Bundle

Every T2.8 gate run MUST emit:

- `tokio_t2_conformance_matrix.json`
- `tokio_t2_performance_budget_report.json`
- `tokio_t2_gate_failures.json`
- `tokio_t2_gate_summary.md`
- `tokio_t2_gate_repro_commands.txt`

### 5.1 Artifact Requirements

`tokio_t2_gate_failures.json` MUST include:

- `failure_id`
- `failure_class`
- `owning_bead`
- `owning_module`
- `recommended_test`
- `repro_command`

Missing artifact files or missing required failure fields is a hard gate failure.

---

## 6. Deterministic Evaluation Semantics

Allowed statuses:

- `PASS`
- `FAIL`
- `BLOCKED`

`BLOCKED` is allowed only for infrastructure incidents and MUST include incident reference plus `repro_command`.  
`BLOCKED` is never equivalent to `PASS`.

Evaluation purity rule: identical evidence manifests must produce identical gate outputs.

---

## 7. Diagnostics Mapping Contract

All failures must map to the owning bead/module with deterministic routing.

| Failure Class | Owning Bead | Owning Module | Required Recommended Test |
|---|---|---|---|
| `protocol_mismatch` | `asupersync-2oh2u.2.1` | `src/io/**` + `src/codec/**` | `cargo test --test tokio_io_parity_audit -- --nocapture` |
| `cancel_leak` | `asupersync-2oh2u.2.5` | `src/io/**` + `src/codec/**` | `cargo test --test tokio_io_codec_cancellation_correctness -- --nocapture` |
| `reactor_parity_drift` | `asupersync-2oh2u.2.6` | `src/runtime/**` + `src/io/**` | `cargo test --test io_cancellation -- --nocapture` |
| `codec_boundary_violation` | `asupersync-2oh2u.2.4` | `src/codec/**` | `cargo test --test tokio_io_utility_operators_parity -- --nocapture` |
| `perf_budget_breach` | `asupersync-2oh2u.2.8` | `benches/**` + `tests/**` | `cargo test --test t2_track_conformance_and_performance_gates -- --nocapture` |

Diagnostic rows are part of policy and must be present in the emitted artifact bundle.

---

## 8. Runner Contract and Commands

Heavy checks MUST be executed via `rch exec --`.

Required command tokens:

- `rch exec -- cargo check --all-targets`
- `rch exec -- cargo clippy --all-targets -- -D warnings`
- `rch exec -- cargo fmt --check`
- `rch exec -- cargo test --test tokio_io_codec_cancellation_correctness -- --nocapture`
- `rch exec -- cargo test --test io_cancellation -- --nocapture`
- `rch exec -- cargo test --test t2_track_conformance_and_performance_gates -- --nocapture`

If any required command is omitted from evidence, gate verdict is `FAIL`.

---

## 9. Acceptance Criteria Binding

T2.8 acceptance criteria are satisfied only when:

1. Contracts are executable with unambiguous pass/fail semantics tied to capability invariants.
2. Coverage includes protocol correctness, cancellation behavior, and failure semantics.
3. Conformance artifacts are reproducible and archived for auditability.
4. Contract violations produce clear diagnostics mapped to owning beads/modules.

Any missing criterion keeps T2.8 open.

---

## 10. Downstream Binding

| Downstream Bead | Binding |
|---|---|
| `asupersync-2oh2u.2.10` | consumes T2.8 gate artifacts as prerequisites for end-to-end I/O protocol scripts |
| `asupersync-2oh2u.2.7` | migration guidance references T2.8 gate outcomes as readiness evidence |
| `asupersync-2oh2u.10.9` | readiness aggregator consumes T2 gate pass/fail signals as closure input |

T2.8 is complete only when this policy is explicit, deterministic, executable, and covered by contract tests.
