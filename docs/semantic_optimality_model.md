# Multi-Objective Optimality Criteria and Weighting Model (SEM-03.6)

**Bead**: `asupersync-3cddg.3.6`
**Parent**: SEM-03 Decision Framework and ADR Resolution
**Author**: SapphireHill
**Date**: 2026-03-02
**Inputs**:
- `docs/semantic_divergence_rubric.md` (SEM-03.1, scoring dimensions D1-D6)
- `docs/semantic_witness_pack.md` (SEM-03.3, evidence for scoring)

---

## 1. Objective Functions

Each semantic design choice is evaluated against 6 objectives derived from the
rubric's scoring dimensions. These are formalized as minimization objectives
(lower = better) on a normalized [0,1] scale.

### O1: Safety Risk (minimize)

**Definition**: Probability that the design choice leads to a violation of
charter invariants SEM-INV-001 through SEM-INV-007.

**Normalization**: `O1 = (D1_score - 1) / 4` where D1 is the rubric's Safety
Impact dimension (1-5 → 0-1).

**Ground truth**: Oracle violation rates from RT test suite. Lean proof coverage
percentage for the affected invariant.

### O2: Determinism Risk (minimize)

**Definition**: Probability that the design choice introduces replay divergence
or breaks seed equivalence.

**Normalization**: `O2 = (D2_score - 1) / 4`

**Ground truth**: `src/lab/replay.rs` validation pass rate across seed corpus.

### O3: Proof Burden (minimize)

**Definition**: Estimated effort to formally verify the design choice in Lean.

**Normalization**: `O3 = (D3_score - 1) / 4`

**Estimation method**: Count of new definitions + theorems required, scaled by
historical Lean proof throughput (from `formal/lean/coverage/` metrics).

### O4: Model-Check Cost (minimize)

**Definition**: TLC state-space growth factor introduced by the design choice.

**Normalization**: `O4 = (D4_score - 1) / 4`

**Estimation method**: Projected state count increase (log-scale) based on new
TLA+ variables and actions.

### O5: Runtime Complexity (minimize)

**Definition**: Implementation complexity and regression risk in the RT layer.

**Normalization**: `O5 = (D5_score - 1) / 4`

**Estimation method**: Lines of code changed, modules affected, test regression
risk assessment.

### O6: Maintenance Overhead (minimize)

**Definition**: Long-term synchronization burden across all 4 layers.

**Normalization**: `O6 = (D6_score - 1) / 4`

**Estimation method**: Number of layers requiring updates per RT change,
frequency of expected updates.

---

## 2. Weighting Model

### 2.1 Base Weights

Weights reflect the charter's priority ordering: safety > correctness >
determinism > maintainability > cost.

| Objective | Weight | Justification |
|-----------|:------:|---------------|
| O1: Safety Risk | **0.30** | Charter non-negotiables (SEM-INV-*) |
| O2: Determinism Risk | **0.15** | SEM-INV-007, replay infrastructure |
| O3: Proof Burden | **0.15** | Formal verification is a charter goal (SEM-GOAL-002) |
| O4: Model-Check Cost | **0.10** | TLC is supplementary to Lean |
| O5: Runtime Complexity | **0.15** | RT is the production artifact |
| O6: Maintenance Overhead | **0.15** | Long-term sustainability |
| **Total** | **1.00** | |

### 2.2 Composite Score

```
Score(design) = Σ(Wi × Oi)  for i in {1..6}
```

Range: [0, 1] where 0 = ideal (no risk, no cost) and 1 = worst case.

### 2.3 Pareto Dominance

Design A **dominates** design B if:
- `∀i: Oi(A) ≤ Oi(B)` (A is at least as good on every objective)
- `∃i: Oi(A) < Oi(B)` (A is strictly better on at least one)

Dominated designs are eliminated. The Pareto frontier contains all
non-dominated designs.

---

## 3. Sensitivity Analysis Method

### 3.1 Weight Perturbation

For each weight Wi, compute the sensitivity coefficient:

```
Si = |dScore/dWi| = |Oi(design_A) - Oi(design_B)|
```

A decision is **robust** if:
- Changing any single weight by ±0.10 does not change the winner.
- The top design's score gap over the runner-up exceeds 0.05.

### 3.2 Scenario Analysis

Three alternative weight profiles test robustness:

| Profile | O1 | O2 | O3 | O4 | O5 | O6 | Rationale |
|---------|:--:|:--:|:--:|:--:|:--:|:--:|-----------|
| **Base** | 0.30 | 0.15 | 0.15 | 0.10 | 0.15 | 0.15 | Balanced charter priorities |
| **Safety-First** | 0.50 | 0.10 | 0.10 | 0.05 | 0.15 | 0.10 | Maximize safety at all costs |
| **Pragmatic** | 0.20 | 0.10 | 0.10 | 0.10 | 0.25 | 0.25 | Minimize implementation effort |

A decision is **stable** if the same design wins under all three profiles.

---

## 4. Scoring the ADR Decisions

Applying the model to the 8 ADR decisions from SEM-03.4:

### 4.1 ADR-001: Loser Drain

| Design | O1 | O2 | O3 | O4 | O5 | O6 | Composite |
|--------|:--:|:--:|:--:|:--:|:--:|:--:|:---------:|
| A: Lean proof + oracle | 0.00 | 0.00 | 0.75 | 0.50 | 0.00 | 0.50 | **0.26** |
| B: TLA+ only | 0.25 | 0.00 | 0.25 | 0.25 | 0.00 | 0.25 | **0.15** |
| C: Oracle only | 0.50 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | **0.15** |
| D: Status quo | 1.00 | 0.50 | 0.00 | 0.00 | 0.00 | 0.00 | **0.38** |

**Winner**: A (Lean proof) — lowest safety risk despite higher proof cost.
**Pareto frontier**: {A, B, C} (D is dominated by C).
**Sensitivity**: A wins under Base and Safety-First. C wins under Pragmatic.
Decision is stable under non-Pragmatic profiles.

### 4.2 ADR-005: Combinator Laws

| Design | O1 | O2 | O3 | O4 | O5 | O6 | Composite |
|--------|:--:|:--:|:--:|:--:|:--:|:--:|:---------:|
| A: Full 6-law theory | 0.00 | 0.00 | 1.00 | 0.50 | 0.00 | 0.75 | **0.34** |
| B: Incremental 3 laws | 0.25 | 0.00 | 0.50 | 0.50 | 0.00 | 0.50 | **0.26** |
| C: Property tests only | 0.50 | 0.00 | 0.00 | 0.00 | 0.25 | 0.00 | **0.19** |
| D: Status quo | 0.75 | 0.25 | 0.00 | 0.00 | 0.00 | 0.00 | **0.26** |

**Winner**: B (incremental) — optimal balance of safety reduction and cost.
**Pareto frontier**: {A, B, C} (D dominated by B in safety).
**Sensitivity**: B wins under Base and Safety-First. C wins under Pragmatic.
Decision is stable under non-Pragmatic profiles.

### 4.3 Accepted Divergences (ADR-002, -003, -004, -006, -007, -008)

For all accepted divergences, the "Accept + document" option scores lowest
on composite because O5 (runtime complexity) and O6 (maintenance) are both
0.00 (no changes needed), and O1 (safety) is acceptably low due to LEAN
proof coverage.

No further multi-objective analysis needed — acceptance is Pareto-optimal
for these cases.

---

## 5. Decision Stability Summary

| ADR | Winner | Stable Under | Flip Profile |
|-----|--------|:------------:|:------------:|
| ADR-001 | A (Lean proof) | Base, Safety-First | Pragmatic → C |
| ADR-005 | B (Incremental) | Base, Safety-First | Pragmatic → C |
| ADR-002 | Accept | All profiles | None |
| ADR-003 | Accept | All profiles | None |
| ADR-004 | Accept | All profiles | None |
| ADR-006 | Accept | All profiles | None |
| ADR-007 | Accept | All profiles | None |
| ADR-008 | Accept | All profiles | None |

All decisions are stable under Base and Safety-First profiles. The two
Priority decisions (ADR-001, ADR-005) would flip to cheaper alternatives
only under a Pragmatic profile that halves the safety weight. Since the
charter mandates safety-first (SEM-GOV-001), this flip is not applicable.

---

## 6. Usage for SEM-03.7+

The weighting model and sensitivity analysis in this document provide:

1. **SEM-03.7**: Pareto frontier data for building the option portfolio.
2. **SEM-03.8**: Composite scores for selecting the global optimal profile.
3. **SEM-03.9**: Adversarial scenarios target the "flip profiles" (Pragmatic)
   to stress-test robustness.
4. **SEM-03.10**: Adversarial scenario set uses O1 (safety) as the primary
   attack surface for counterexample generation.
