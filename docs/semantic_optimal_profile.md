# Global Optimal Semantic Profile and Rationale Bundle (SEM-03.8)

**Bead**: `asupersync-3cddg.3.8`
**Parent**: SEM-03 Decision Framework and ADR Resolution
**Author**: SapphireHill
**Date**: 2026-03-02
**Inputs**:
- `docs/semantic_option_portfolio.md` (SEM-03.7, Pareto frontiers + portfolio)
- `docs/semantic_optimality_model.md` (SEM-03.6, weighting model)
- `docs/semantic_adr_decisions.md` (SEM-03.4, ADR records)

---

## 1. Purpose

This document selects the globally optimal semantic profile from the Pareto
frontier analysis, documents the rationale against all alternatives, provides
sensitivity analysis showing stability range, and defines explicit
fallback/rollback conditions.

This is the decision gate for SEM-04 contract encoding.

---

## 2. Selected Profile: "Safety-Anchored Pragmatism"

The selected profile combines Safety-First selections for charter-critical
invariants with Pragmatic acceptances where formal assurance already exists.

### 2.1 Profile Composition

| ADR | Decision | Design Class | Rationale Summary |
|-----|----------|:------------:|-------------------|
| ADR-001 | A: Lean proof + oracle | Safety-First | SEM-INV-004 non-negotiable; proof required |
| ADR-005 | B: Incremental 3 laws | Safety-First | 70% law coverage; manages proof maintenance |
| ADR-002 | B: Canonical 5 + extension | Base | Clean extension policy; zero safety risk |
| ADR-003 | Accept TLA+ abstraction | Base | LEAN proofs sufficient |
| ADR-004 | Accept TLA+ abstraction | Base | LEAN proofs sufficient |
| ADR-006 | C: Type-system property | Pragmatic | Compiler IS the verifier |
| ADR-007 | C: Implementation property | Pragmatic | Test suite IS the evidence |
| ADR-008 | Accept TLA+ abstraction | Base | LEAN proofs sufficient |

### 2.2 Profile Characteristics

**Aggregate O1 (Safety Risk)**: 0.094 (weighted mean across 8 ADRs)
- Charter threshold: O1 < 0.25 per decision, aggregate < 0.15
- Profile meets both thresholds.

**Aggregate O3 (Proof Burden)**: 0.188 (weighted mean)
- Manageable: ~5-7 weeks total Lean formalization effort.

**Aggregate O5+O6 (Implementation + Maintenance)**: 0.094
- Low: Most decisions require documentation, not code changes.

---

## 3. Justification Against Alternatives

### 3.1 Alternative: Pure Safety-First Profile

Would select A (Lean proof) for ADR-005, -006, -007 in addition to ADR-001.

| Metric | Selected Profile | Pure Safety-First |
|--------|:---------------:|:-----------------:|
| Aggregate O1 | 0.094 | 0.000 |
| Aggregate O3 | 0.188 | 0.563 |
| Total Lean effort | ~5-7 weeks | ~6+ months |
| Feasibility | High | Low (research-level) |

**Rejection**: Pure Safety-First achieves perfect O1 but at 3x proof burden.
ADR-006 and ADR-007's O1=0.25 residuals represent type-system and test-suite
coverage — not genuine safety gaps. The marginal O1 reduction (0.094→0.000)
does not justify ~4 additional months of Lean work.

### 3.2 Alternative: Pure Pragmatic Profile

Would select C (cheapest option) for ADR-001, -005.

| Metric | Selected Profile | Pure Pragmatic |
|--------|:---------------:|:--------------:|
| Aggregate O1 | 0.094 | 0.219 |
| Aggregate O3 | 0.188 | 0.000 |
| Charter compliance | Full | Violated (O1 > 0.15) |

**Rejection**: Pure Pragmatic violates the charter's safety mandate
(SEM-GOV-001). ADR-001's O1=0.50 (Oracle-only) exceeds the per-decision
threshold. This profile is inadmissible.

### 3.3 Alternative: TLA+-Heavy Profile

Would select B (TLA+ encoding) for ADR-001, -006, -007 instead of Lean/Accept.

| Metric | Selected Profile | TLA+-Heavy |
|--------|:---------------:|:----------:|
| Aggregate O1 | 0.094 | 0.094 |
| Aggregate O4 | 0.063 | 0.219 |
| Assurance type | Machine-checked proofs | Bounded model checking |

**Rejection**: TLA+-Heavy provides the same O1 at 3.5x the model-checking
cost, with weaker assurance (bounded vs universal). Lean proofs are
strictly preferred when available.

---

## 4. Sensitivity Analysis

### 4.1 Weight Perturbation

For each weight Wi, the profile's optimality is tested under Wi ± 0.10:

| Weight Perturbed | Range Tested | Profile Stable? | Flip Point |
|-----------------|:------------:|:---------------:|:----------:|
| W1 (Safety) | 0.20 — 0.40 | Yes | Flips at W1 < 0.15 |
| W2 (Determinism) | 0.05 — 0.25 | Yes | Never flips |
| W3 (Proof Burden) | 0.05 — 0.25 | Yes | Flips at W3 > 0.30 |
| W4 (Model-Check) | 0.00 — 0.20 | Yes | Never flips |
| W5 (Runtime) | 0.05 — 0.25 | Yes | Never flips |
| W6 (Maintenance) | 0.05 — 0.25 | Yes | Never flips |

**Stability verdict**: Profile is stable under all ±0.10 perturbations.
Only extreme weight shifts (W1 < 0.15 or W3 > 0.30) cause flips — both
violate charter constraints (SEM-GOV-001 mandates safety primacy;
SEM-GOV-002 mandates formal verification as a goal).

### 4.2 Scenario Profile Robustness

| Profile | ADR-001 Winner | ADR-005 Winner | Portfolio Valid? |
|---------|:--------------:|:--------------:|:---------------:|
| Base (0.30/0.15/0.15/0.10/0.15/0.15) | A (Lean) | B (Incremental) | Yes |
| Safety-First (0.50/0.10/0.10/0.05/0.15/0.10) | A (Lean) | B (Incremental) | Yes |
| Pragmatic (0.20/0.10/0.10/0.10/0.25/0.25) | C (Oracle) | C (PropTest) | **No** (O1 breach) |

The profile is valid under Base and Safety-First, which are the charter-compliant
weight profiles. The Pragmatic profile is charter-inadmissible.

### 4.3 Brittle Assumptions

The profile depends on these assumptions remaining true:

1. **Lean proof feasibility**: Combinators can be decomposed into existing
   Step constructors. If Step model requires extension, proof effort increases.
   - Indicator: Lean bead effort exceeds 3 weeks → revisit ADR-001.

2. **Type-system soundness**: `#![deny(unsafe_code)]` provides capability
   enforcement. If unsafe code is introduced in capability modules,
   ADR-006 must be revisited.
   - Indicator: Any `#[allow(unsafe_code)]` in `src/cx/` → escalate.

3. **Replay suite coverage**: Determinism is empirically verified.
   If replay failures increase to > 1% of test corpus, ADR-007 must be
   revisited.
   - Indicator: `src/lab/replay.rs` validation failures > 1%.

4. **TLA+ abstraction adequacy**: Accepted TLA+ simplifications (ADR-003,
   -004, -008) rely on Lean proofs covering the gaps. If Lean coverage
   regresses, these acceptances must be revisited.
   - Indicator: `formal/lean/coverage/` metrics drop below 90%.

---

## 5. Fallback and Rollback Conditions

### 5.1 Rollback Triggers

| Trigger | Affected ADR | Rollback Action |
|---------|-------------|-----------------|
| Lean proof infeasible (> 3 weeks, no progress) | ADR-001 | Escalate to TLA+ encoding (option B) as interim |
| Lean combinator definition incompatible with RT | ADR-005 | Fall back to property tests (option C) + document gap |
| Unsafe code introduced in `src/cx/` | ADR-006 | Elevate to Lean capability parameter (option A) |
| Replay failure rate > 1% | ADR-007 | Elevate to TLA+ fairness checking (option B) |
| Lean coverage < 90% | ADR-003, -004, -008 | Elevate TLA+ encoding for affected invariants |

### 5.2 Escalation Path

1. Engineer detects rollback trigger.
2. Create new bead referencing this document and the affected ADR.
3. Re-run Pareto analysis (SEM-03.7) with updated O1 scores.
4. Select new design from the Pareto frontier.
5. Update contract (SEM-04) and alignment tracks (SEM-08).

### 5.3 Non-Rollback Conditions

These situations do NOT require profile changes:
- Lean proof takes longer than estimated but makes steady progress.
- Property tests for deferred laws pass (this is expected, not assurance).
- TLC state-space grows but remains tractable (< 10M states).
- New RT features added that follow existing semantic patterns.

---

## 6. Decision Packet for Downstream Consumers

### 6.1 For SEM-04 (Contract Encoding)

The contract must encode:
1. **SEM-INV-004**: Reference Lean proof as primary assurance for loser drain.
2. **LAW-JOIN-ASSOC, LAW-RACE-COMM, LAW-TIMEOUT-MIN**: Reference Lean proofs.
3. **Cancel kinds**: Define canonical 5 with integer severity levels (0-5).
4. **Capability scope**: Reference Rust type system as enforcement layer.
5. **Determinism scope**: Reference LabRuntime + replay suite as evidence.
6. **TLA+ simplifications**: Document as accepted abstractions with Lean coverage.

### 6.2 For SEM-08 (Runtime Alignment)

Runtime alignment must:
1. **ADR-001**: Strengthen oracle metamorphic tests during Lean proof window.
2. **ADR-002**: Implement canonical-to-extension severity mapping in documentation.
3. **ADR-005**: Add property-based tests for 3 proven laws as regression guards.
4. **ADR-006**: Add CI check: `grep '#[allow(unsafe_code)]' src/cx/` must return empty.
5. **ADR-007**: Add CI check: replay suite failure rate < 1%.

### 6.3 For SEM-09 (Readiness Gate)

The readiness gate must verify:
1. Lean bead for combinator formalization is created and scheduled.
2. Lean bead for loser drain proof is created and scheduled.
3. Contract (SEM-04) encodes all 8 ADR decisions.
4. CI gates for ADR-006 and ADR-007 indicators are active.

---

## 7. Approval

This profile is recommended for ratification in SEM-03.5. It satisfies:
- Charter safety mandate (aggregate O1 = 0.094 < 0.15 threshold)
- Formal verification goal (Lean proofs for critical invariants)
- Feasibility constraint (~5-7 weeks, not months)
- Stability requirement (robust under ±0.10 weight perturbation)
- Coherence requirement (cross-ADR dependencies verified by S6, S7 scenarios)
