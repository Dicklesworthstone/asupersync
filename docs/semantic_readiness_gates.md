# Semantic Readiness Gate Matrix and Thresholds (SEM-09.1)

**Bead**: `asupersync-3cddg.9.1`
**Parent**: SEM-09 Verification Bundle and Readiness Gates
**Author**: SapphireHill
**Date**: 2026-03-02
**Inputs**:
- `docs/semantic_contract_versioning.md` (SEM-04.5, change policy)
- `docs/semantic_runtime_gap_matrix.md` (SEM-08.1, gap inventory)
- `docs/semantic_contract_invariants.md` (SEM-04.4, invariant catalog)

---

## 1. Purpose

This document defines the readiness gates that must pass before the semantic
harmonization program can declare a phase complete. Each gate specifies
evidence requirements, pass/fail thresholds, and exception policy.

---

## 2. Gate Structure

```
Gate → Evidence Class → Threshold → Verdict
```

Verdicts: PASS, FAIL, EXCEPTION (bounded deferral with owner + expiry).

---

## 3. Gate Matrix

### G1: Documentation Alignment

| Check | Threshold | Evidence |
|-------|:---------:|---------|
| All 47 rule IDs appear in contract docs | 47/47 | Grep of `semantic_contract_*.md` |
| Glossary covers all disambiguation entries | 11/11 | Manual review |
| Transition rules have PRE/POST for all 15 rules | 15/15 | Grep of transitions doc |
| Invariant clauses cover all 14 invariants | 14/14 | Grep of invariants doc |
| No conflicting synonyms in contract docs | 0 conflicts | Automated synonym checker |

**Pass threshold**: All checks at 100%.
**Fail-fast**: Any missing rule ID blocks downstream.

### G2: LEAN Proof Coverage

| Check | Threshold | Evidence |
|-------|:---------:|---------|
| Invariants marked `proved` have proof file | 100% | Citation verification script |
| Proof files compile without error | 0 errors | `lean --make` |
| ADR-001 proof exists (loser drain) | exists | File check |
| ADR-005 proofs exist (3 laws) | 3/3 | File check |
| No proof regressions since last gate | 0 regressions | Diff against baseline |

**Pass threshold**: All proofs compile. ADR-001 and ADR-005 proofs exist.
**Exception policy**: Lean proofs in progress may defer with 4-week window.

### G3: TLA+ Model Checking

| Check | Threshold | Evidence |
|-------|:---------:|---------|
| Rules marked `modeled`/`checked` have TLA+ spec | 100% | Citation verification |
| TLC runs without error for all scenarios | 0 errors | `tlc` output |
| State-space within bound (< 10M states) | < 10M | TLC stats |
| No new safety violations | 0 violations | TLC safety check |
| Documented abstractions have justification | 100% | Manual review |

**Pass threshold**: All TLC scenarios pass. No safety violations.
**Exception policy**: State-space growth may warrant scenario reduction (bounded).

### G4: Runtime Conformance

| Check | Threshold | Evidence |
|-------|:---------:|---------|
| CODE-GAPs from SEM-08.1 matrix | 0 remaining | Gap matrix re-scan |
| DOC-GAP annotations added | 7/7 | Grep for rule-ID comments |
| TEST-GAP tests added | 6/6 | Test list verification |
| Oracle checks pass for all scenarios | 100% | `cargo test oracle` |
| Conformance harness (SEM-08.4) passes | 100% | Harness output |

**Pass threshold**: 0 CODE-GAPs, all DOC/TEST-GAPs resolved.
**Fail-fast**: Any CODE-GAP blocks release.

### G5: Property and Law Tests

| Check | Threshold | Evidence |
|-------|:---------:|---------|
| Join associativity property test | PASS | `cargo test law_join_assoc` |
| Race commutativity property test | PASS | `cargo test law_race_comm` |
| Timeout-min property test | PASS | `cargo test law_timeout_min` |
| Loser drain metamorphic test | PASS | `cargo test metamorphic_drain` |
| Race never-abandon property test | PASS | `cargo test law_race_abandon` |

**Pass threshold**: All 5 tests pass.

### G6: Cross-Artifact E2E

| Check | Threshold | Evidence |
|-------|:---------:|---------|
| Witness replay scenarios (W1-W7) | 7/7 | E2E script output |
| Adversarial scenarios (S1-S7) | 7/7 | Scenario script output |
| Deterministic replay certification | 100% | Replay suite |
| Capability audit (no unsafe in cx/) | 0 files | Grep CI gate |

**Pass threshold**: All scenarios pass.

### G7: Logging and Diagnostics

| Check | Threshold | Evidence |
|-------|:---------:|---------|
| Failures emit rule-ID in log message | 100% of conformance failures | Log audit |
| Witness inputs are logged for failures | 100% | Log audit |
| Rerun instructions included in failure output | yes | Manual verification |
| Structured log format consistent | yes | Schema validation |
| Deterministic replay variance dashboard is stable | 0 unstable suites in CI baseline | `target/semantic-verification/flake/*/variance_dashboard.json` |

**Pass threshold**: All conformance failures include rule-ID + witness + rerun, and CI flake dashboards report no unstable deterministic replay suites.

---

## 4. Gate Dependencies

```
G1 (Docs) ─────────────────────────────────► G6 (E2E)
G2 (LEAN) ─────────────────────────────────► G6 (E2E)
G3 (TLA+) ─────────────────────────────────► G6 (E2E)
G4 (RT) ──► G5 (Laws) ────────────────────► G6 (E2E)
                                            G7 (Logging)
```

G1-G4 can run in parallel. G5 depends on G4. G6 depends on all others. G7
is independent but must pass for final sign-off.

---

## 5. Exception Policy

### 5.1 Exception Structure

```yaml
exception:
  gate: "<G1-G7>"
  check: "<specific check>"
  owner: "<agent or person>"
  reason: "<why deferral is acceptable>"
  expiry: "<ISO-8601 date>"
  risk_assessment: "<LOW|MEDIUM|HIGH>"
  mitigation: "<what compensates for the gap>"
```

### 5.2 Exception Rules

1. **Maximum 3 active exceptions** at any time.
2. **No exceptions for G4 CODE-GAPs** (these are absolute requirements).
3. **No exceptions for G6 capability audit** (type-system enforcement is binary).
4. **Exceptions expire after 30 days** unless renewed with justification.
5. **HIGH-risk exceptions require 2 reviewers**.

---

## 6. Phase Completion Criteria

### 6.1 SEM Phase 1 (Current)

**Required gates**: G1, G4 (CODE-GAPs only)
**Optional gates**: G2-G3 (LEAN/TLA+ proofs may be in progress)
**Minimum**: All docs aligned, zero code gaps, annotations in place.

### 6.2 SEM Phase 2 (Full Verification)

**Required gates**: G1-G7 (all gates)
**Maximum exceptions**: 2 (LEAN proofs for deferred laws only)
**Minimum**: All tests pass, proofs for ADR-001/005 priority items exist.

### 6.3 SEM Phase 3 (Steady State)

**Required gates**: G1-G7 in CI (continuous)
**Maximum exceptions**: 0
**Minimum**: All gates pass on every commit.

---

## 7. Downstream Usage

1. **SEM-12**: Verification fabric implements automated gate checks.
2. **SEM-10**: CI enforcement uses gate thresholds as policy.
3. **SEM-08.5/06**: Property tests target G5 checks.
4. **SEM-04.5**: Versioning policy references gates for change approval.
5. **SEM-12.15**: Deterministic replay flake detector feeds G7 stability signals and CI signal-quality tuning.
