# Decision Set Ratification and Escalation Record (SEM-03.5)

**Bead**: `asupersync-3cddg.3.5`
**Parent**: SEM-03 Decision Framework and ADR Resolution
**Author**: SapphireHill
**Date**: 2026-03-02
**Inputs**:
- `docs/semantic_adr_decisions.md` (SEM-03.4, ADR records)
- `docs/semantic_stress_test_results.md` (SEM-03.9, stress-test results)
- `docs/semantic_optimal_profile.md` (SEM-03.8, selected profile)
- `docs/semantic_option_portfolio.md` (SEM-03.7, Pareto analysis)
- `docs/semantic_optimality_model.md` (SEM-03.6, scoring model)
- `docs/semantic_adversarial_scenarios.md` (SEM-03.10, adversarial set)

---

## 1. Ratification Statement

All 8 ADR decisions from the SEM-03 decision framework are hereby **ratified**
as the normative design choices for semantic contract encoding (SEM-04) and
runtime alignment (SEM-08).

The selected profile ("Safety-Anchored Pragmatism") has been:
1. Scored against 6 multi-objective criteria (SEM-03.6)
2. Evaluated for Pareto dominance across all candidates (SEM-03.7)
3. Selected as the global optimum with alternatives rejected (SEM-03.8)
4. Stress-tested against 7 adversarial scenarios — 7/7 PASS (SEM-03.9)

No unresolved blockers. No C0 escalations required.

---

## 2. Ratified Decisions

### 2.1 Priority Decisions (Formal Proof Required)

#### ADR-001: Loser Drain — Lean Proof + Oracle

| Field | Value |
|-------|-------|
| **Status** | RATIFIED |
| **Decision** | Lean proof for `race_ensures_loser_drained` + runtime oracle |
| **Charter** | SEM-INV-004 (non-negotiable) |
| **Residual O1** | 0.00 |
| **Stress-test** | S4 confirms Lean proof required (unbounded mask depth) |
| **Follow-up** | New LEAN bead: combinator formalization + drain proof |
| **Rule IDs** | #40 (`inv.combinator.loser_drained`) |

**Rejected alternatives**:
- B (TLA+ only): Bounded, not a proof. O1=0.25.
- C (Oracle only): Finite coverage. O1=0.50. Pragmatic flip inadmissible.
- D (Status quo): Dominated by C. O1=1.00.

#### ADR-005: Combinator Laws — Incremental 3 Laws

| Field | Value |
|-------|-------|
| **Status** | RATIFIED |
| **Decision** | Lean proofs for LAW-JOIN-ASSOC, LAW-RACE-COMM, LAW-TIMEOUT-MIN |
| **Charter** | SEM-INV-004, SEM-INV-007 |
| **Residual O1** | 0.25 (3 deferred laws) |
| **Stress-test** | S1 confirms deferred law (DIST) correctly deferred; S5 confirms Lean preferred |
| **Follow-up** | New LEAN bead: Join/Race definitions + 3 law proofs |
| **Rule IDs** | #37-39, #41-43 |

**Rejected alternatives**:
- A (Full 6-law theory): 4-6 weeks effort. O3=1.00.
- C (Property tests only): No formal guarantee. O1=0.50.
- D (Status quo): O1=0.75.

### 2.2 Standard Decisions (Scope Documentation)

#### ADR-006: Capability Security — Type-System Property

| Field | Value |
|-------|-------|
| **Status** | RATIFIED |
| **Decision** | Document as Rust type-system enforcement via sealed generics + Cx |
| **Charter** | SEM-INV-006 |
| **Residual O1** | 0.25 (type-system soundness assumption) |
| **Stress-test** | S2 confirms no `#[allow(unsafe_code)]` in `src/cx/` |
| **Follow-up** | SEM-04 contract section on capability scope |
| **Rule IDs** | #44 (`inv.capability.no_ambient`), #45 (`def.capability.cx_scope`) |

#### ADR-007: Determinism — Implementation Property

| Field | Value |
|-------|-------|
| **Status** | RATIFIED |
| **Decision** | Document as LabRuntime implementation property with replay suite evidence |
| **Charter** | SEM-INV-007 |
| **Residual O1** | 0.25 (test suite coverage bound) |
| **Stress-test** | S3 confirms no time leaks in task paths; S7 confirms ADR-006 dependency |
| **Follow-up** | SEM-04 contract section on determinism scope |
| **Rule IDs** | #46 (`inv.determinism.replayable`), #47 (`def.determinism.seed_equivalence`) |

### 2.3 Accepted Decisions (TLA+ Abstractions)

| ADR | Decision | Charter | LEAN Coverage | Stress-test |
|-----|----------|---------|:------------:|:-----------:|
| ADR-002 | Canonical 5 cancel kinds + extension policy | SEM-DEF-003 | Full | N/A |
| ADR-003 | Cancel propagation: TLA+ abstraction accepted | SEM-INV-003 | `cancelPropagate`, `cancelChild` | N/A |
| ADR-004 | Finalizer step: TLA+ abstraction accepted | SEM-INV-002 | `closeRunFinalizer` | N/A |
| ADR-008 | Outcome severity: TLA+ abstraction accepted | SEM-DEF-001 | Total order, transitivity | N/A |

All accepted decisions have LEAN proof coverage as primary assurance.
TLA+ simplifications are documented, not deficiencies.

---

## 3. Escalation Record

### 3.1 Unresolved Blockers

**None.** All 8 ADRs resolved without C0 escalation.

### 3.2 Observations

**OBS-1** (from SEM-03.9): `src/lab/config.rs:185` uses `SystemTime::now()`
for seed generation when the user doesn't provide an explicit seed. This is
correct behavior but should be documented in the SEM-04 contract's determinism
section to prevent future confusion.

**Action**: SEM-04.3 must include a note that seed selection is pre-execution
and outside the determinism boundary.

---

## 4. Fallback Triggers (Inherited from SEM-03.8)

| Trigger | Affected ADR | Rollback Action |
|---------|-------------|-----------------|
| Lean proof infeasible (> 3 weeks, no progress) | ADR-001 | Interim TLA+ encoding |
| Lean combinator incompatible with RT | ADR-005 | Fall back to property tests |
| `#[allow(unsafe_code)]` in `src/cx/` | ADR-006 | Elevate to Lean capability model |
| Replay failure rate > 1% | ADR-007 | Elevate to TLA+ fairness checking |
| Lean coverage < 90% | ADR-003, -004, -008 | Elevate TLA+ encoding |

---

## 5. Downstream Contract Input

### 5.1 SEM-04.1 — Contract Schema

The contract must define a stable rule-ID namespace covering all 47 required
semantic concepts. Rule IDs from the drift matrix (SEM-02.6) are canonical.

### 5.2 SEM-04.2 — Glossary

Must define:
- 5 canonical cancel kinds with integer severity levels (0-5)
- Extension mapping policy for RT's additional 6 kinds
- Outcome severity lattice (4-valued: Ok < Cancelled < Err < Panicked)

### 5.3 SEM-04.3 — Transition Rules

Must encode:
- Region lifecycle (spawn → running → close → quiescent → completed)
- Task lifecycle (spawn → running → cancel protocol → finalize → completed)
- Cancel propagation (parent → child, downward only)
- Loser drain requirement (reference Lean proof as assurance)
- 3 combinator laws (ASSOC, COMM, TIMEOUT-MIN) with Lean proof references

### 5.4 SEM-04.4 — Invariant Section

Must encode all 7 charter invariants (SEM-INV-001 through SEM-INV-007)
as checkable clauses with enforcement layer references:
- SEM-INV-001 through -005: Lean proofs (primary) + TLA+ checking (bounded)
- SEM-INV-006: Rust type system (`#![deny(unsafe_code)]`)
- SEM-INV-007: LabRuntime replay test suite

### 5.5 SEM-04.5 — Versioning Policy

Must define:
- Semantic versioning for contract changes
- Required review for invariant modifications
- Extension policy for new RT cancel kinds

---

## 6. Action Items with Owners and Deadlines

| # | Action | Owner | Deadline | Bead |
|---|--------|-------|----------|------|
| 1 | Create LEAN bead: combinator formalization (Race, Join, Timeout) | TBD | SEM-08 phase | New bead |
| 2 | Create LEAN bead: prove `race_ensures_loser_drained` | TBD | SEM-08 phase | New bead |
| 3 | Create LEAN bead: prove LAW-JOIN-ASSOC, LAW-RACE-COMM, LAW-TIMEOUT-MIN | TBD | SEM-08 phase | New bead |
| 4 | Author SEM-04.2 glossary (canonical kinds + extension policy) | SapphireHill | SEM-04 phase | asupersync-3cddg.4.2 |
| 5 | Encode SEM-04.3 transition rules with rule IDs | SapphireHill | SEM-04 phase | asupersync-3cddg.4.3 |
| 6 | Encode SEM-04.4 invariant section | SapphireHill | SEM-04 phase | asupersync-3cddg.4.4 |
| 7 | Add CI gate: `grep '#[allow(unsafe_code)]' src/cx/` must be empty | TBD | SEM-12 phase | asupersync-3cddg.12.* |
| 8 | Add CI gate: replay failure rate < 1% | TBD | SEM-12 phase | asupersync-3cddg.12.* |
| 9 | Document OBS-1 in SEM-04.3 determinism section | SapphireHill | SEM-04 phase | asupersync-3cddg.4.3 |

---

## 7. Ratification Approval

**Decision**: All 8 ADRs are **RATIFIED** as of 2026-03-02.
**Profile**: Safety-Anchored Pragmatism (aggregate O1 = 0.094).
**Stress-test**: 7/7 PASS, 0 failures, 0 exceptions.
**Escalations**: None.
**Gate**: SEM-04 contract encoding may proceed.
