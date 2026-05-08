# doctor_asupersync Remediation and Trust Visual Regression Suite

**Bead**: `asupersync-2b4jj.6.1`
**Parent**: Track 6: Quality gates, packaging, and rollout
**Date**: 2026-03-04
**Author**: SapphireHill
**Dependencies**: 6.9 (baseline visual harness), 4.3 (remediation engine), 5.9 (report extensions)

---

## 1. Purpose

This document defines the remediation-specific visual regression layer that builds on the baseline harness (6.9). It covers visual states for fix-preview/apply workflows, verification outcomes, trust-score transition views, rollback/failure states, and cancellation scenarios. All assertions are deterministic and produce replay-linked artifacts for triage.

---

## 2. Remediation Visual State Model

### 2.1 Remediation Outcome Classes

Remediation workflows produce outcome classes beyond the baseline success/cancelled/failed:

| Outcome Class | Visual Profile | Focused Panel | Description |
|--------------|---------------|--------------|-------------|
| `fix_preview` | `frankentui-preview` | `remediation_panel` | Patch plan displayed for operator review |
| `fix_applied` | `frankentui-stable` | `remediation_panel` | Fix applied successfully, pending verification |
| `fix_rejected` | `frankentui-cancel` | `remediation_panel` | Operator rejected the fix at a checkpoint |
| `verification_pass` | `frankentui-stable` | `trust_panel` | Post-apply verification succeeded |
| `verification_fail` | `frankentui-alert` | `trust_panel` | Post-apply verification failed |
| `trust_improved` | `frankentui-stable` | `trust_panel` | Trust score improved above acceptance threshold |
| `trust_degraded` | `frankentui-alert` | `trust_panel` | Trust score degraded below escalation threshold |
| `rollback_initiated` | `frankentui-alert` | `remediation_panel` | Rollback triggered due to apply failure or trust regression |
| `rollback_complete` | `frankentui-cancel` | `remediation_panel` | Rollback completed successfully |

### 2.2 Visual Profile Extensions

New profiles beyond the baseline set:

- `frankentui-preview`: neutral inspection mode for patch/diff review

Existing profiles reused with remediation semantics:
- `frankentui-stable`: successful apply/verify/trust-improved
- `frankentui-cancel`: rejected or rolled-back
- `frankentui-alert`: verification failure, trust degradation, rollback in progress

### 2.3 Panel Extensions

New panels beyond the baseline `summary_panel` and `triage_panel`:

- `remediation_panel`: fix preview, apply, reject, rollback states
- `trust_panel`: verification outcomes and trust score transitions

---

## 3. Remediation Snapshot Extensions

### 3.1 Extended Snapshot Fields

Remediation snapshots reuse `DoctorVisualHarnessSnapshot` with domain-specific `stage_digest` and `visual_profile` values. The digest encodes the remediation flow progression:

```
len:<N>|<stage1_status>|<stage2_status>|...
```

Example digests:
- `len:3|preview|approved|applied` — successful fix-apply
- `len:3|preview|approved|verify_pass` — verified fix
- `len:2|preview|rejected` — operator rejected at checkpoint
- `len:4|preview|approved|applied|rollback` — rollback after apply

### 3.2 Trust Transition Snapshot

Trust score transitions are captured in the `stage_digest` as trust delta annotations:

```
len:2|verify_pass|trust:+15
len:2|verify_fail|trust:-8
```

---

## 4. Golden Fixture Management

### 4.1 Fixture Location

Remediation visual regression fixtures live at:

```
tests/fixtures/doctor_remediation_visual/
  manifest.json                    # Fixture pack manifest
  snapshot_fix_preview.json        # Fix preview state
  snapshot_fix_applied.json        # Fix applied state
  snapshot_fix_rejected.json       # Fix rejected state
  snapshot_verify_pass.json        # Verification success
  snapshot_verify_fail.json        # Verification failure
  snapshot_trust_improved.json     # Trust score improved
  snapshot_trust_degraded.json     # Trust score degraded
  snapshot_rollback.json           # Rollback initiated
  manifest_remediation.json        # Artifact manifest for remediation run
```

### 4.2 Fixture Pack Schema

```json
{
  "schema_version": "doctor-remediation-visual-fixture-pack-v1",
  "description": "Golden fixtures for remediation and trust visual regression",
  "fixtures": [
    {
      "fixture_id": "visual-fix-preview-baseline",
      "outcome_class": "fix_preview",
      "expected_visual_profile": "frankentui-preview",
      "expected_focused_panel": "remediation_panel",
      "viewport_width": 132,
      "viewport_height": 44
    }
  ]
}
```

---

## 5. Trust Score Transition Assertions

### 5.1 Scorecard Visual Mapping

| Recommendation | Visual Profile | Panel | Condition |
|---------------|---------------|-------|-----------|
| `accept` | `frankentui-stable` | `trust_panel` | Score >= accept_min, delta >= accept_min_delta, no unresolved |
| `monitor` | `frankentui-stable` | `trust_panel` | Not accept/escalate/rollback |
| `escalate` | `frankentui-alert` | `trust_panel` | Score < escalate_below or unresolved persists |
| `rollback` | `frankentui-alert` | `trust_panel` | Delta <= rollback threshold or explicit rollback request |

### 5.2 Trust Delta Invariants

1. `trust_delta = trust_score_after - trust_score_before` (signed)
2. `confidence_shift` is deterministic: `improved` if delta > 0, `degraded` if delta < 0, `stable` if delta == 0
3. `recommendation` is deterministic given thresholds and scorecard inputs

---

## 6. Remediation Session State Reducers

State transitions follow a strict ordering:

```
preview → (approved | rejected)
approved → applied → (verify_pass | verify_fail)
verify_pass → trust_assessment → (accept | monitor | escalate)
verify_fail → (rollback_initiated | escalate)
rollback_initiated → rollback_complete
rejected → (end)
```

### 6.1 Transition Guards

- `preview → approved`: requires all checkpoint IDs approved
- `approved → applied`: requires no unapproved checkpoints
- `applied → verify_pass/fail`: requires verification loop completion
- `verify_fail → rollback`: automatic if trust delta <= rollback threshold

---

## 7. Determinism Invariants

1. **Outcome-to-profile**: remediation outcome class deterministically selects visual profile
2. **Outcome-to-panel**: remediation outcome class deterministically selects focused panel
3. **Trust delta determinism**: same before/after scores always produce same delta, shift, and recommendation
4. **Stage digest determinism**: same flow progression always produces same digest string
5. **Fixture ordering**: manifest fixture entries sorted lexically by `fixture_id`
6. **Snapshot ordering**: manifest records sorted lexically by `artifact_id`
7. **Transition guard determinism**: given same checkpoint approvals, same transition path is taken
8. **Rollback determinism**: given same trust delta and threshold, rollback decision is identical
9. **Scorecard ordering**: entries sorted lexically by `scenario_id`
10. **Evidence pointer stability**: same run/scenario always produces same evidence pointer format

---

## 8. CI Validation

### 8.1 Automated Gates

| Gate | Test File | Checks |
|------|----------|--------|
| Doc coverage | `tests/doctor_remediation_visual_regression.rs` | All sections documented |
| Fixture schema | `tests/doctor_remediation_visual_regression.rs` | Pack schema, outcome coverage |
| Golden snapshots | `tests/doctor_remediation_visual_regression.rs` | Profile/panel/digest correctness |
| Trust transitions | `tests/doctor_remediation_visual_regression.rs` | Delta/shift/recommendation determinism |
| State reducers | `tests/doctor_remediation_visual_regression.rs` | Transition guard enforcement |
| Drift detection | `tests/doctor_remediation_visual_regression.rs` | Profile/panel/digest drift flagged |

### 8.2 Reproduction

```bash
# Run remediation visual regression tests
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_doctor_remediation_visual_docs cargo test --test doctor_remediation_visual_regression --features cli -- --nocapture
```

---

## 9. Cross-References

- Baseline visual harness: `docs/doctor_visual_regression_harness.md`
- Remediation recipe DSL: `docs/doctor_remediation_recipe_contract.md`
- Visual language contract: `docs/doctor_visual_language_contract.md`
- Logging contract: `docs/doctor_logging_contract.md`
- Implementation: `src/cli/doctor/mod.rs`
- Baseline visual tests: `tests/doctor_visual_regression_harness.rs`
- Remediation unit tests: `tests/doctor_remediation_unit_harness.rs`
- Remediation visual tests: `tests/doctor_remediation_visual_regression.rs`
