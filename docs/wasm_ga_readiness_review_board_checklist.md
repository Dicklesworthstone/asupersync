# WASM GA Readiness Review Board and Go/No-Go Checklist

**Bead**: `asupersync-umelq.17.4`  
**Contract ID**: `wasm-ga-readiness-review-board-checklist-v1`  
**Program**: `asupersync-umelq.17` (WASM-16 Pilot Program, GA Readiness, and Launch Governance)

## Purpose

Define a deterministic, fail-closed GA decision process for Browser Edition
promotion. The review board consumes upstream evidence artifacts, applies
objective thresholds, records waiver rationale when allowed, and emits a
machine-readable decision packet.

This checklist is operational policy, not narrative guidance.

## Prerequisite Beads and Evidence Inputs

This checklist is blocked until the following dependencies have executable
evidence available:

| Bead | Scope | Required Evidence |
|---|---|---|
| `asupersync-umelq.17.2` | pilot telemetry and SLO contract | `docs/wasm_pilot_observability_contract.md`, `artifacts/pilot/pilot_observability_summary.json` |
| `asupersync-umelq.15.5` | release rollback and incident response | `docs/wasm_release_rollback_incident_playbook.md`, `artifacts/wasm_release_rollback_playbook_summary.json` |
| `asupersync-umelq.14.5` | security release blocking criteria | `scripts/check_security_release_gate.py`, `artifacts/security_release_gate_report.json` |
| `asupersync-umelq.13.5` | continuous performance regression gates | `.github/wasm_perf_budgets.json`, `artifacts/wasm_perf_regression_report.json` |
| `asupersync-umelq.16.5` | rationale index and design traceability | `docs/wasm_rationale_index.md`, `tests/wasm_rationale_index.rs` |
| `asupersync-umelq.12.5` | incident forensics and replay workflow | `docs/replay-debugging.md`, replay artifact pointer in decision packet |
| `asupersync-umelq.18.10` | nightly stress/soak and flake-burndown | `docs/nightly_stress_soak_automation.md`, `target/nightly-stress/<run_id>/trend_report.json` |

## Mandatory Evidence Fields

Every gate row in the review packet must define all fields below.

| Field | Description |
|---|---|
| `gate_id` | Stable identifier (`GA-GATE-xx`) |
| `source_bead` | Upstream bead ID |
| `artifact_path` | Relative artifact path |
| `generated_at_utc` | Evidence generation timestamp |
| `repro_command` | Deterministic rerun command |
| `threshold_rule` | Objective pass criterion |
| `observed_value` | Measured result |
| `gate_status` | `pass` / `fail` / `waived` |
| `owner_role` | Responsible sign-off role |
| `log_pointer` | Structured log artifact |
| `trace_pointer` | Replay trace pointer when applicable |
| `waiver_reason` | Mandatory when status is `waived` |
| `waiver_approver` | Mandatory when status is `waived` |
| `unresolved_risk_ids` | Residual risks linked by ID |

## Sign-Off Roles and Quorum

Required roles:

1. Review Board Chair
2. Runtime Semantics Lead
3. Security Lead
4. Performance Lead
5. Observability Lead
6. Release Operations Lead
7. Support Readiness Lead

Minimum quorum:

- Review Board Chair plus 5 of 6 remaining roles.
- Runtime Semantics Lead, Security Lead, and Release Operations Lead are
  mandatory participants and cannot be absent.

## Objective Gate Model

### Hard-Blocking Gates

The following conditions are always release-blocking:

1. Missing mandatory evidence field on any gate row.
2. Any upstream blocker artifact missing or unreadable.
3. `security_release_gate_report.json` indicates release-blocking finding.
4. `wasm_perf_regression_report.json` indicates budget violation.
5. Pilot observability summary indicates `status = fail`.
6. Stress/soak trend report indicates `regression_detected = true`.
7. Rollback playbook certification missing or failing.

### Aggregate Decision Rule

Decision status is computed with fail-closed logic:

- `NO_GO` if any hard-blocking gate triggers.
- `NO_GO` if quorum is not satisfied.
- `NO_GO` if unresolved critical risk remains open.
- `GO` only when all gates pass or are validly waived and aggregate score is
  `>= 0.90`.

## Waiver Policy

Waivers are allowed only for non-critical gates.

Waiver requirements:

1. `waiver_reason` is concrete and evidence-linked.
2. `waiver_approver` is the Review Board Chair plus one mandatory role lead.
3. Waiver expiry timestamp is defined.
4. Follow-up bead ID is recorded.

Waivers are forbidden for:

- security blockers,
- missing rollback controls,
- missing deterministic replay pointers,
- unresolved critical risks.

## Deterministic Review Rehearsal

Primary contract test:

```bash
rch exec -- cargo test -p asupersync --test wasm_ga_readiness_review_board_checklist -- --nocapture
```

Replay-focused preflight:

```bash
rch exec -- cargo test -p asupersync --test wasm_release_rollback_incident_playbook -- --nocapture
python3 scripts/check_security_release_gate.py --policy .github/security_release_policy.json
python3 scripts/check_perf_regression.py --budgets .github/wasm_perf_budgets.json --profile core-min
```

Evidence synchronization expectation:

- artifacts used in the board packet must be generated from the same CI run or
  from explicitly version-pinned artifacts with matching commit SHA.

## Decision Packet Schema

The board must emit:

- `artifacts/wasm_ga_readiness_decision_packet.json`
- `artifacts/wasm_ga_readiness_review_board_test.log`

Packet contract:

```json
{
  "schema_version": "wasm-ga-readiness-decision-packet-v1",
  "bead": "asupersync-umelq.17.4",
  "decision_status": "GO | NO_GO",
  "aggregate_score": 0.0,
  "quorum_satisfied": true,
  "gate_rows": [],
  "signoffs": [],
  "waivers": [],
  "residual_risks": [],
  "replay_bundle": {
    "repro_command": "",
    "trace_pointer": ""
  }
}
```

## CI Certification Contract

`.github/workflows/ci.yml` must include a review-board certification step that:

1. Runs `wasm_ga_readiness_review_board_checklist` test target.
2. Emits `artifacts/wasm_ga_readiness_review_board_summary.json`.
3. Uploads a dedicated artifact bundle for audit and rerun linkage.

## Cross-References

- `docs/wasm_pilot_observability_contract.md`
- `docs/wasm_release_rollback_incident_playbook.md`
- `docs/wasm_rationale_index.md`
- `docs/nightly_stress_soak_automation.md`
- `docs/replay-debugging.md`
