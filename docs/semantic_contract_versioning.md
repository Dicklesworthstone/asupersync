# Versioning and Change Policy for Contract Evolution (SEM-04.5)

**Bead**: `asupersync-3cddg.4.5`
**Parent**: SEM-04 Canonical Semantic Contract (Normative Source)
**Author**: SapphireHill
**Date**: 2026-03-02
**Inputs**:
- `docs/semantic_contract_schema.md` (SEM-04.1, stability guarantees)
- `docs/semantic_contract_invariants.md` (SEM-04.4, invariant catalog)
- `docs/semantic_ratification.md` (SEM-03.5, fallback triggers)

---

## 1. Purpose

This document defines the change policy for the semantic contract. It ensures
that contract evolution does not silently reintroduce cross-artifact drift,
and that all modifications are traceable, reviewed, and propagated to all
affected layers.

---

## 2. Contract Version Scheme

### 2.1 Semantic Versioning

The contract follows `MAJOR.MINOR.PATCH` versioning:

| Level | When | Effect | Review Required |
|-------|------|--------|:---------------:|
| **PATCH** (1.0.x) | Clarification of existing rules, typo fixes, citation updates | No semantic change | 1 reviewer |
| **MINOR** (1.x.0) | New rules added (#48+), new enforcement citations, new witnesses | Backward-compatible | 2 reviewers |
| **MAJOR** (x.0.0) | Existing rule semantics changed, rule split/merge, type prefix change | Breaking change | Full ADR process |

### 2.2 Current Version

```
version: 1.0.0
effective_date: 2026-03-02
rules: 47
invariants: 14
laws: 4
progress_properties: 3
```

---

## 3. Change Categories

### 3.1 Non-Breaking Changes (PATCH or MINOR)

| Change | Version Bump | Required Artifacts |
|--------|:----------:|-------------------|
| Fix typo in rule description | PATCH | Diff only |
| Update LEAN/TLA+ citation (proof completed) | PATCH | Citation link |
| Add new witness to existing rule | PATCH | Witness reference |
| Add new rule (ID #48+) | MINOR | Full rule entry per schema |
| Add new enforcement layer for existing rule | MINOR | Layer status entry |
| Add new algebraic law | MINOR | Full law entry + proof plan |

### 3.2 Breaking Changes (MAJOR)

| Change | Required Process |
|--------|-----------------|
| Modify existing rule PRE/POST conditions | Full ADR (SEM-03 rubric) |
| Change invariant clause | Full ADR + re-run stress tests |
| Split rule into multiple rules | New IDs + retirement of old ID |
| Merge rules | New ID + retirement of merged IDs |
| Change type prefix of a rule | Schema version bump |
| Remove a rule | Retirement (never delete) |

---

## 4. Change Request Process

### 4.1 Proposal

1. Author creates a bead referencing this document and the affected rules.
2. Proposal includes: motivation, affected rule IDs, proposed change, impact
   assessment across all 4 layers.
3. For MAJOR changes: proposal includes scoring against the SEM-03.6
   optimality model (6 objectives).

### 4.2 Review

| Change Level | Reviewers | Process |
|-------------|:---------:|---------|
| PATCH | 1 engineer | Code review |
| MINOR | 2 engineers (1 from each of: RT, formal) | Code review + impact check |
| MAJOR | Full ADR process | SEM-03 rubric scoring + stress test |

### 4.3 Propagation

After approval, changes must be propagated to all affected layers:

```
Contract change approved
  ↓
  ├─ SEM-05: Update formal documentation projections
  ├─ SEM-06: Update LEAN projections (if LEAN-enforced rule)
  ├─ SEM-07: Update TLA+ projections (if TLA-enforced rule)
  ├─ SEM-08: Update RT conformance tests
  ├─ SEM-10: Update CI drift detection
  └─ SEM-12: Update verification fabric
```

### 4.4 Propagation Deadline

- PATCH changes: propagated within 1 sprint (2 weeks).
- MINOR changes: propagated within 2 sprints (4 weeks).
- MAJOR changes: propagated before next release gate.

If propagation is incomplete at deadline, the contract change is marked
`Pending-Propagation` and downstream gates block.

---

## 5. Rule Lifecycle

### 5.1 States

```
Draft → Active → Deprecated → Retired
```

| State | Meaning | Enforcement |
|-------|---------|-------------|
| **Draft** | Proposed, not yet ratified | Not enforced |
| **Active** | Ratified, enforced | All layers must comply |
| **Deprecated** | Superseded, enforcement relaxed | Warning in CI |
| **Retired** | Removed, no enforcement | Archived for traceability |

### 5.2 Retirement Protocol

Retired rules are NEVER deleted. They receive:
1. `status: Retired`
2. `superseded_by: <new-rule-id>` (if applicable)
3. `retired_date: <ISO-8601>`
4. `retired_reason: <text>`

The rule ID is permanently reserved and cannot be reused.

---

## 6. Extension Policy (Cancel Kinds)

Per ADR-002, the RT may add extension cancel kinds provided:

1. Each extension maps to an integer severity level from {0, 1, 2, 3, 4, 5}.
2. The extension is documented with its severity mapping in a PATCH update.
3. The extension participates in the `strengthen` monotonic lattice.
4. No new severity levels are introduced (no 1.5, no level 6+).

Extensions do NOT require a MINOR version bump — they are implementation
refinements within the existing semantic framework.

---

## 7. Invariant Modification Policy

Invariant modifications are the highest-risk contract changes.

### 7.1 Protected Invariants

The following invariants are charter non-negotiables. Modifying them
requires charter amendment (not just contract versioning):

| Rule ID | Invariant | Protection Level |
|---------|-----------|:----------------:|
| #33, #34 | Ownership (SEM-INV-001) | Charter-protected |
| #27 | Quiescence (SEM-INV-002) | Charter-protected |
| #5, #6 | Cancellation (SEM-INV-003) | Charter-protected |
| #40 | Loser drain (SEM-INV-004) | Charter-protected |
| #17 | No leak (SEM-INV-005) | Charter-protected |
| #44 | No ambient authority (SEM-INV-006) | Charter-protected |
| #46 | Determinism (SEM-INV-007) | Charter-protected |

### 7.2 Modifiable Invariants

Non-charter invariants (#11, #12, #18, #19, #20) can be modified through
the standard MAJOR change process.

---

## 8. Drift Prevention Mechanisms

### 8.1 CI Gate: Contract-Projection Consistency (SEM-10)

A CI check validates that each layer's projection matches the contract:
- LEAN citations are current (proof exists at cited location).
- TLA+ model includes all rules marked as `modeled` or `checked`.
- RT implementation covers all rules marked as `implemented`.

### 8.2 Pre-Commit Guard: Semantic Change Detection

Any modification to files matching `docs/semantic_contract_*.md` triggers
a pre-commit check that:
1. Validates the version field was bumped.
2. Validates the changelog entry exists.
3. For MAJOR changes: validates an ADR bead reference.

### 8.3 Periodic Review

Every 3 months (quarterly), a drift audit runs the full SEM-02 inventory
pipeline to detect any silent drift since the last contract version.

---

## 9. Changelog Format

```markdown
## [1.1.0] - YYYY-MM-DD

### Added
- Rule #48: <description> (bead: <bead-id>)

### Changed
- Rule #5: Updated clause to include <detail> (bead: <bead-id>)

### Deprecated
- Rule #12: Superseded by #48 (bead: <bead-id>)

### Propagation Status
- [ ] SEM-05 (docs)
- [ ] SEM-06 (LEAN)
- [ ] SEM-07 (TLA+)
- [ ] SEM-08 (RT)
- [x] SEM-10 (CI)
```

---

## 10. Fallback Trigger Integration

From SEM-03.8 section 5.1, these triggers require contract modification:

| Trigger | Contract Action | Change Level |
|---------|---------------|:------------:|
| Lean proof infeasible | Update ADR-001 enforcement to TLA+ interim | MAJOR |
| Lean combinator incompatible | Update ADR-005 enforcement to property tests | MAJOR |
| Unsafe code in `src/cx/` | Escalate ADR-006 to Lean capability model | MAJOR |
| Replay failure rate > 1% | Escalate ADR-007 to TLA+ fairness | MAJOR |
| Lean coverage < 90% | Escalate ADR-003/004/008 to TLA+ encoding | MINOR |

All fallback triggers produce MAJOR changes because they modify enforcement
layers for existing rules.

---

## 11. Summary

The versioning policy ensures:
1. **Traceability**: Every change is versioned, reviewed, and linked to a bead.
2. **Propagation**: Changes flow to all affected layers within defined deadlines.
3. **Protection**: Charter invariants require charter-level amendment.
4. **Prevention**: CI gates detect drift before it reaches production.
5. **Evolution**: New rules and citations can be added without breaking changes.
