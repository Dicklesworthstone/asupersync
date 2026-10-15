# Recurring Semantic Audit Cadence and Ownership (SEM-11.4)

**Bead**: `asupersync-3cddg.11.4`
**Parent**: SEM-11 Rollout, Enablement, and Recurring Semantic Audits
**Date**: 2026-03-02
**Author**: SapphireHill

---

## 1. Purpose

This document defines the recurring audit schedule, assigns ownership, and specifies lightweight checks that measure semantic drift health over time. It ensures the harmonization gains from SEM-00 are maintained through sustained, evidence-driven verification.

---

## 2. Audit Tiers

### 2.1 Tier 1: Per-PR Gate (Continuous)

**Trigger**: Every pull request or commit to main.
**Owner**: PR author.
**Scope**: Quality gates only.

Checklist:
- [ ] `cargo check --all-targets` passes
- [ ] `cargo clippy --all-targets -- -D warnings` passes
- [ ] `cargo fmt --check` passes
- [ ] Unit tests pass for changed modules

**Automation**: CI pipeline runs these checks automatically. Failures block merge.

### 2.2 Tier 2: Weekly Verification Sweep

**Trigger**: Weekly (recommended: Monday).
**Owner**: Rotating among active semantic contributors.
**Scope**: Full verification suite with summary generation.

Procedure:
```bash
# Step 1: Run full verification
scripts/run_semantic_verification.sh --profile full --json

# Step 2: Generate summary with triage
scripts/generate_verification_summary.sh --json --verbose

# Step 3: Review triage report
cat target/verification-summary/triage_report.md

# Step 4: Post results to coordination thread
# Include: suite pass/fail counts, new gaps, gate status
```

Checklist:
- [ ] Full verification suite executed
- [ ] Triage report reviewed
- [ ] New failures triaged (bead filed if new regression)
- [ ] Results posted to coordination thread
- [ ] Risk register updated if needed

**Expected duration**: 15-30 minutes (mostly automated).

### 2.3 Tier 3: Monthly Evidence Audit

**Trigger**: Monthly (first week of month).
**Owner**: Designated audit lead (see §4).
**Scope**: Full evidence bundle assembly, gate evaluation, drift delta comparison.

Procedure:
```bash
# Step 1: Full verification
scripts/run_semantic_verification.sh --profile forensics --json

# Step 2: Evidence bundle assembly
scripts/assemble_evidence_bundle.sh --json --phase 1

# Step 3: Summary generation
scripts/generate_verification_summary.sh --json --verbose

# Step 4: Gate evaluation comparison
# Compare against docs/semantic_gate_evaluation_report.md

# Step 5: Risk register review
# Check docs/semantic_residual_risk_register.md for expired risks
```

Checklist:
- [ ] Forensics-profile verification executed
- [ ] Evidence bundle assembled and reviewed
- [ ] Gate status compared against last month's baseline
- [ ] Coverage matrix reviewed for regressions (`docs/semantic_verification_matrix.md`)
- [ ] Residual risk register reviewed — expired risks escalated or renewed
- [ ] Harmonization report updated if drift deltas changed (`docs/semantic_harmonization_report.md`)
- [ ] Audit findings documented in coordination thread
- [ ] Follow-up beads filed for any new regressions

**Expected duration**: 1-2 hours.

### 2.4 Tier 4: Quarterly Deep Review

**Trigger**: Quarterly (start of quarter).
**Owner**: Audit lead + runtime maintainer.
**Scope**: Full drift analysis, deferred gate progress, formal projection health.

Checklist:
- [ ] All Tier 3 items completed
- [ ] Deferred gates (G2, G3, G5, G6) progress assessed
- [ ] Lean proof coverage reviewed (`formal/lean/coverage/`)
- [ ] TLA+ model state space checked (`formal/tla/output/result.json`)
- [ ] ADR decisions reviewed for staleness (`docs/semantic_adr_decisions.md`)
- [ ] Change freeze policy reviewed (`docs/semantic_change_freeze_workflow.md`)
- [ ] Enablement FAQ updated with new recurring questions
- [ ] Audit cadence document itself reviewed for effectiveness

**Expected duration**: 2-4 hours.

---

## 3. Drift Health Indicators

### 3.1 Green (Healthy)

- All Tier 1 gates pass on every PR.
- Weekly sweep shows no new failures.
- Monthly evidence shows stable or improving coverage.
- Risk register has no expired unrenewed risks.

### 3.2 Yellow (Attention Needed)

- Weekly sweep shows new failures in non-critical suites.
- Coverage regression in 1-2 evidence classes.
- Risk register has risks expiring within 7 days without renewal plan.
- Gate status unchanged for deferred gates (no progress on SEM-06/07).

Response: File a bead, assign ownership, set 2-week remediation target.

### 3.3 Red (Immediate Action)

- Tier 1 gate fails on main branch.
- Weekly sweep shows failures in critical suites (docs, golden, conformance).
- Previously-passing gate (G1, G4, G7) regresses to FAIL.
- Coverage drops below minimum thresholds (UT < 95%, E2E < 50%).

Response: Stop normal development on affected domain. File urgent bead. Remediate within 48 hours.

---

## 4. Ownership Rotation

### 4.1 Audit Lead Role

The audit lead is responsible for:
- Executing Tier 2 (weekly) and Tier 3 (monthly) audits.
- Filing beads for discovered regressions.
- Updating the risk register.
- Posting audit results to the coordination thread.

### 4.2 Rotation Schedule

| Period | Audit Lead | Backup |
|--------|-----------|--------|
| Week 1-2 (current) | SapphireHill | ScarletCrane |
| Week 3-4 | ScarletCrane | NavyMoose |
| Week 5-6 | NavyMoose | SapphireHill |
| Subsequent | Rotate in order | Previous lead as backup |

Rotation continues cyclically. If the scheduled lead is unavailable, the backup assumes responsibility and documents the substitution.

### 4.3 Handoff Protocol

At each rotation:
1. Outgoing lead posts final audit summary to coordination thread.
2. Incoming lead acknowledges and confirms access to audit tools.
3. Any in-progress remediation beads are explicitly transferred or documented.

---

## 5. Audit Artifacts

Each audit tier produces artifacts:

| Tier | Artifact | Location |
|------|----------|----------|
| Tier 1 | CI gate results | CI pipeline logs |
| Tier 2 | Verification summary | `target/verification-summary/verification_summary.json` |
| Tier 2 | Triage report | `target/verification-summary/triage_report.md` |
| Tier 3 | Evidence bundle | `target/evidence-bundle/metadata/bundle_manifest.json` |
| Tier 3 | Gate evaluation | `docs/semantic_gate_evaluation_report.md` |
| Tier 3 | Updated risk register | `docs/semantic_residual_risk_register.md` |
| Tier 4 | Quarterly review notes | Coordination thread |

---

## 6. Escalation Thresholds

| Condition | Escalation Target |
|-----------|-------------------|
| Gate regression (G1, G4, G7) | Runtime maintainer + all active SEM contributors |
| Coverage drop > 10% in any class | Audit lead + domain owner |
| Risk register has 3+ expired risks | Audit lead + governance board |
| Deferred gate (G2-G6) blocked > 1 quarter | Quarterly deep review agenda item |
| No audit executed for 2+ weeks | Any active contributor should self-assign |

---

## 7. Success Metrics

The audit cadence is effective when:
1. **Zero undetected regressions**: No gate regression goes unnoticed for more than 1 week.
2. **Risk register freshness**: All active risks have expiry dates within 30 days.
3. **Steady coverage**: Evidence coverage trends upward or holds stable quarter-over-quarter.
4. **Audit completion rate**: > 90% of scheduled audits executed on time.
5. **Mean time to remediation**: Regressions resolved within 2 weeks of detection.

---

## 8. Integration with CI

### 8.1 Current CI Gates

Phase 1 requires:
- G1 (Documentation Alignment): PASS
- G4 (Runtime Conformance): PASS

### 8.2 Future CI Integration

As deferred gates are achieved:
- G7 (Logging): Add to CI when full-profile evidence is available.
- G2 (Lean): Add when Lean toolchain is available in CI.
- G3 (TLA+): Add when TLC is available in CI.
- G5 (Property/Law): Add when law test count reaches threshold.
- G6 (E2E): Add when witness corpus is stable.

### 8.3 CI Anti-Drift Checks

Already installed by SEM-10:
- Contract/projection consistency checks (`scripts/check_semantic_consistency.sh`).
- Rule traceability completeness checks (`scripts/check_rule_traceability.sh`).
- Semantic change policy gate (`scripts/check_semantic_change_policy.sh`).

---

## 9. Review of This Document

This audit cadence document should be reviewed:
- At each quarterly deep review (Tier 4).
- When a new gate transitions from DEFER to PASS.
- When the audit rotation changes.
- When a significant process failure occurs.

Any changes require updating both this document and `docs/semantic_maintainer_playbook.md` §8.
