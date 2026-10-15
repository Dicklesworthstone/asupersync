# Option Portfolio and Pareto Frontier Analysis

Status: Active
Program: `asupersync-3cddg` (SEM-03.7)
Parent: SEM-03 Decision Framework and ADR Resolution
Author: SapphireHill
Published: 2026-03-02 UTC
Criteria Reference: `docs/semantic_optimality_criteria.md`

## 1. Purpose

This document builds a Pareto frontier across the candidate semantic profiles
to confirm the ADR-selected profile is globally optimal or to identify
dominated alternatives.

## 2. Candidate Profiles

| Profile | Description | Strategy |
|---------|-------------|----------|
| P1 (Chosen) | ADR-001..008: Lean combinator + accept TLA abstractions | Targeted formal + pragmatic |
| P2 (Full Formal) | Prove everything in LEAN/TLA+, including capability/determinism | Maximum assurance |
| P3 (Accept All) | Accept all abstractions, no new formal work | Minimum effort |
| P4 (TLA+ Focus) | Extend TLA+ for combinators/severity, no Lean additions | Model-check heavy |

## 3. Score Matrix

| Profile | O1 Safety | O2 Determinism | O3 Proof Cost | O4 MC Tractability | O5 RT Complexity | O6 Maintainability | Composite |
|---------|-----------|---------------|--------------|-------------------|-----------------|-------------------|-----------|
| P1 | 0.87 | 0.70 | 0.75 | 0.85 | 0.95 | 0.80 | **0.83** |
| P2 | 0.95 | 0.85 | 0.30 | 0.50 | 0.95 | 0.50 | 0.71 |
| P3 | 0.70 | 0.65 | 0.95 | 0.90 | 0.95 | 0.90 | 0.80 |
| P4 | 0.82 | 0.70 | 0.60 | 0.40 | 0.95 | 0.65 | 0.71 |

## 4. Pareto Frontier

A profile is Pareto-optimal if no other profile scores strictly better on
all objectives.

| Profile | Dominated By | Pareto-Optimal? |
|---------|-------------|----------------|
| P1 | None | **Yes** |
| P2 | None (best O1, O2) | **Yes** |
| P3 | None (best O3, O6) | **Yes** |
| P4 | P1 (P1 ≥ P4 on all objectives) | **No** |

### Frontier Members

- **P1** (chosen): Best composite. Dominates P4.
- **P2**: Highest safety but worst proof cost. Frontier member by O1/O2.
- **P3**: Lowest effort but worst safety. Frontier member by O3/O6.
- **P4**: Dominated by P1 — worse on proof cost, MC tractability, and maintainability without compensating safety gain.

## 5. Pareto Trade-Off Analysis

### P1 vs P2 (Targeted vs Full Formal)

To move from P1 to P2, we would gain:
- O1: +0.08 (safety from proving capability + determinism)
- O2: +0.15 (determinism from scheduler refinement)

But lose:
- O3: -0.45 (months of additional proof work)
- O4: -0.35 (TLA+ state space explosion from severity + capability)
- O6: -0.30 (ongoing sync overhead)

**Trade ratio**: 0.23 gain / 1.10 loss = 0.21. Poor trade.

### P1 vs P3 (Targeted vs Accept All)

To move from P1 to P3, we would gain:
- O3: +0.20 (no new proofs needed)
- O6: +0.10 (less sync)

But lose:
- O1: -0.17 (loser drain unproved — charter violation risk)
- O2: -0.05 (slightly less determinism coverage)

**Trade ratio**: 0.30 gain / 0.22 loss = 1.36. Marginal but the O1 loss
includes a charter non-negotiable (SEM-INV-004), making P3 ineligible.

## 6. Conclusion

**P1 (the ADR-selected profile) is the Pareto-optimal choice** when charter
non-negotiables are treated as hard constraints. P2 offers higher safety at
impractical cost. P3 violates SEM-INV-004. P4 is dominated by P1.

The selected profile occupies the "sweet spot" on the Pareto frontier:
maximum achievable safety within practical proof and maintenance budgets.
