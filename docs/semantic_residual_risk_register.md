# Semantic Residual Risk Register and Follow-up Action Plan (SEM-09.4)

**Bead**: `asupersync-3cddg.9.4`  
**Parent**: SEM-09 Verification Bundle and Readiness Gates  
**Date**: 2026-03-02  
**Scope**: Residual risks that remain after SEM-09.3 gate evaluation.

---

## 1. Purpose

This artifact is the canonical SEM-09 residual-risk ledger. It turns gate
outcomes into bounded, trackable risk records with explicit ownership,
expiration, mitigation, and follow-up beads so unresolved verification risk
cannot disappear from planning.

---

## 2. Readiness Criteria and Evaluation Method

The criteria below are reproducible and map directly to SEM-09.1 gates.

| Gate | Reproducible pass criterion | Primary command(s) | Required evidence class |
|------|-----------------------------|--------------------|-------------------------|
| G1 | 47/47 rule IDs documented, docs lint passing | `scripts/assemble_evidence_bundle.sh --json --phase 1` | docs |
| G2 | Lean validation suite passing with inventory coverage | `scripts/run_lean_regression.sh --json` | Lean |
| G3 | TLC model check pass with no safety violations | `scripts/run_model_check.sh --ci` | TLA |
| G4 | 0 unresolved CODE-GAPs with runtime conformance checks passing | `scripts/assemble_evidence_bundle.sh --json --phase 1 --skip-runner` | runtime |
| G5 | Semantic law/property tests passing | `cargo test --test algebraic_laws` | runtime |
| G6 | Witness/adversarial replay scenarios passing | `cargo test --test semantic_witness_replay_e2e --test adversarial_witness_corpus` | e2e |
| G7 | Logging schema checks passing with stable diagnostics output | `cargo test --test semantic_log_schema_validation` | logging |

Current objective signal (from `target/semantic-verification/verification_report.json`):
- Profile: `smoke`
- Overall: `passed`
- Suites present: `docs=passed`, `golden=passed`, `coverage_gate=skipped`
- Missing full-profile signals are tracked as residual risks below.

---

## 3. Evidence Link Index by Class

| Evidence class | Canonical artifacts |
|----------------|---------------------|
| docs | `docs/semantic_readiness_gates.md`, `docs/semantic_gate_evaluation_report.md`, `docs/semantic_verification_matrix.md` |
| Lean | `formal/lean/Asupersync.lean`, `formal/lean/coverage/theorem_surface_inventory.json`, `formal/lean/coverage/baseline_report_v1.json` |
| TLA | `formal/tla/Asupersync.tla`, `formal/tla/Asupersync_MC.cfg`, `formal/tla/output/result.json` |
| runtime | `docs/semantic_runtime_gap_matrix.md`, `target/semantic-verification/verification_report.json` |
| e2e | `tests/semantic_witness_replay_e2e.rs`, `tests/adversarial_witness_corpus.rs` |
| logging | `docs/semantic_verification_log_schema.md`, `tests/semantic_log_schema_validation.rs` |

---

## 4. Residual Risk Register

| Risk ID | Gate/check | Current bounded impact | Owner bead | Mitigation now | Expiry | Follow-up bead |
|---------|------------|------------------------|------------|----------------|--------|----------------|
| `SEM-RISK-09-01` | G2 Lean validation suite not present in latest smoke report | Full sign-off cannot claim machine-checked regression freshness; Phase-1 docs/runtime confidence remains intact | `asupersync-3cddg.12.3` | Run Lean regression in full profile and attach artifact bundle | 2026-03-16 | `asupersync-3cddg.9.5` |
| `SEM-RISK-09-02` | G3 TLA validation suite not present in latest smoke report | No fresh end-to-end confirmation that model-check pipeline remains green in current runner context | `asupersync-3cddg.12.4` | Execute TLA validation suite in full profile; publish state/violation metrics | 2026-03-16 | `asupersync-3cddg.9.5` |
| `SEM-RISK-09-03` | G6 witness/adversarial suite evidence absent from latest smoke report | Cross-artifact replay confidence is partial; runtime behavior can still regress without immediate gate signal | `asupersync-3cddg.12.6` | Run witness + adversarial suites and attach deterministic rerun pointers | 2026-03-16 | `asupersync-3cddg.9.5` |
| `SEM-RISK-09-04` | G7 logging schema suite evidence absent from latest smoke report | Failures could become less explainable if logging contracts regress without detection | `asupersync-3cddg.12.7` | Run logging schema validation and store structured diagnostics artifacts | 2026-03-16 | `asupersync-3cddg.9.5` |
| `SEM-RISK-09-05` | Coverage gate skipped in smoke profile | Full closure cannot be asserted because coverage quality gate was not enforced in latest report | `asupersync-3cddg.12.14` | Run full profile (non-skipped coverage gate) and publish pass/fail verdict | 2026-03-16 | `asupersync-3cddg.9.5` |

---

## 5. Exception Ledger (Bounded Deferrals)

Each active residual risk is also an explicit SEM exception record:

```yaml
exception:
  gate: "<G2|G3|G6|G7>"
  check: "<suite/artifact not yet validated in full profile>"
  owner: "<owner bead listed in risk register>"
  reason: "latest available verification artifact is smoke profile only"
  expiry: "2026-03-16"
  risk_assessment: "MEDIUM"
  mitigation: "run full-profile gate command and attach deterministic artifacts"
  follow_up: "asupersync-3cddg.9.5"
```

Policy conformance:
- Active exceptions: 5 (within SEM governance only if treated as temporary and tracked).
- No G4 CODE-GAP exceptions.
- No G6 capability-audit exception.
- Every exception has owner + expiry + follow-up bead.

---

## 6. Objective Go/No-Go Decision Rules

`GO` requires all of the following:
1. No open risk with expired expiry date.
2. No open risk without owner bead and follow-up bead.
3. G1 and G4 pass with current artifacts.
4. Full-profile evidence exists for G2, G3, G6, and G7.
5. Coverage gate is not skipped.

`NO-GO` if any rule above is false.

Current decision (2026-03-02): **NO-GO for full SEM closure**, **GO for Phase-1 maintenance**.

Rationale:
- Required Phase-1 foundation (G1 + G4) is satisfied.
- Full-profile verification evidence remains incomplete for G2/G3/G6/G7 and coverage gate enforcement.

---

## 7. Follow-up Action Plan

| Step | Action | Owner bead | Output required |
|------|--------|------------|-----------------|
| 1 | Run full semantic verification profile and publish report | `asupersync-3cddg.12.10` | Updated `target/semantic-verification/verification_report.json` with full suite statuses |
| 2 | Close Lean/TLA/full-profile missing evidence items | `asupersync-3cddg.12.3`, `asupersync-3cddg.12.4` | Artifactized suite outputs with rerun commands |
| 3 | Close witness/logging/coverage gate evidence items | `asupersync-3cddg.12.6`, `asupersync-3cddg.12.7`, `asupersync-3cddg.12.14` | Passing suite results and schema-valid logs |
| 4 | Re-evaluate all open risks and publish closure packet | `asupersync-3cddg.9.5` | Sign-off packet with objective GO decision or updated bounded exceptions |

