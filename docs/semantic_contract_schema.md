# Contract Schema and Stable Rule-ID Namespace (SEM-04.1)

**Bead**: `asupersync-3cddg.4.1`
**Parent**: SEM-04 Canonical Semantic Contract (Normative Source)
**Author**: SapphireHill
**Date**: 2026-03-02
**Inputs**:
- `docs/semantic_ratification.md` (SEM-03.5, ratified decisions)
- `docs/semantic_inventory_schema.md` (SEM-02.1, ID namespace)
- `docs/semantic_drift_matrix.md` (SEM-02.6, concept catalog)

---

## 1. Purpose

This document defines the machine-readable schema for the canonical semantic
contract and establishes the stable rule-ID namespace. All downstream
projections (LEAN, TLA+, RT, CI) consume this schema deterministically.

---

## 2. Schema Version

```
schema_version: "1.0.0"
schema_format: "semantic-contract-v1"
ratification_ref: "docs/semantic_ratification.md"
ratification_date: "2026-03-02"
```

### 2.1 Versioning Rules

- **Patch** (1.0.x): Clarification of existing rules without semantic change.
- **Minor** (1.x.0): Addition of new rules or concepts. No existing ID changes.
- **Major** (x.0.0): Breaking change to existing rule semantics or ID format.

Rule: Once published, a rule-ID is permanent. Retired rules get status
`Retired` with a `superseded_by` field.

---

## 3. Rule-ID Namespace

### 3.1 Format

```
<type_prefix>.<domain>.<area>[.<qualifier>]
```

### 3.2 Type Prefixes

| Prefix | Type | Description |
|--------|------|-------------|
| `rule` | `transition_rule` | State transition with preconditions and effects |
| `inv` | `invariant` | Property that must hold in all reachable states |
| `def` | `definition` | Type, lattice, or structural definition |
| `prog` | `progress_property` | Liveness/bounded-termination guarantee |
| `law` | `algebraic_law` | Equational law over combinator compositions |
| `comb` | `derived_combinator` | Combinator defined as derived Step sequence |

### 3.3 Domains

| Domain | Scope | Concept Count |
|--------|-------|:------------:|
| `cancel` | Cancellation protocol + masking | 12 |
| `obligation` | Obligation lifecycle + ledger | 9 |
| `region` | Region lifecycle + quiescence | 7 |
| `outcome` | Outcome type + severity lattice | 4 |
| `ownership` | Structured ownership + region tree | 4 |
| `combinator` | Join, Race, Timeout + laws | 7 |
| `capability` | Cx token + authority model | 2 |
| `determinism` | Replay + seed equivalence | 2 |
| **Total** | | **47** |

### 3.4 Complete ID Registry

| # | Rule ID | Type | Charter Anchor | Enforcement Layer |
|---|---------|------|----------------|-------------------|
| 1 | `rule.cancel.request` | transition_rule | SEM-INV-003 | LEAN+TLA+RT |
| 2 | `rule.cancel.acknowledge` | transition_rule | SEM-INV-003 | LEAN+TLA+RT |
| 3 | `rule.cancel.drain` | transition_rule | SEM-INV-003 | LEAN+TLA+RT |
| 4 | `rule.cancel.finalize` | transition_rule | SEM-INV-003 | LEAN+TLA+RT |
| 5 | `inv.cancel.idempotence` | invariant | SEM-INV-003 | LEAN+TLA |
| 6 | `inv.cancel.propagates_down` | invariant | SEM-INV-003 | LEAN (ADR-003) |
| 7 | `def.cancel.reason_kinds` | definition | SEM-DEF-003 | DOC+RT (ADR-002) |
| 8 | `def.cancel.severity_ordering` | definition | SEM-DEF-003 | DOC+RT (ADR-002) |
| 9 | `prog.cancel.drains` | progress_property | SEM-INV-003 | LEAN |
| 10 | `rule.cancel.checkpoint_masked` | transition_rule | SEM-INV-003 | LEAN+TLA+RT |
| 11 | `inv.cancel.mask_bounded` | invariant | INV-MASK-BOUNDED | LEAN+TLA |
| 12 | `inv.cancel.mask_monotone` | invariant | INV-MASK-BOUNDED | LEAN |
| 13 | `rule.obligation.reserve` | transition_rule | SEM-INV-005 | LEAN+TLA+RT |
| 14 | `rule.obligation.commit` | transition_rule | SEM-INV-005 | LEAN+TLA+RT |
| 15 | `rule.obligation.abort` | transition_rule | SEM-INV-005 | LEAN+TLA+RT |
| 16 | `rule.obligation.leak` | transition_rule | SEM-INV-005 | LEAN+TLA+RT |
| 17 | `inv.obligation.no_leak` | invariant | SEM-INV-005 | LEAN+TLA |
| 18 | `inv.obligation.linear` | invariant | INV-OBLIGATION-LINEAR | LEAN |
| 19 | `inv.obligation.bounded` | invariant | INV-OBLIGATION-BOUNDED | LEAN+TLA |
| 20 | `inv.obligation.ledger_empty_on_close` | invariant | INV-LEDGER-EMPTY | LEAN+TLA |
| 21 | `prog.obligation.resolves` | progress_property | SEM-DEF-004 | LEAN |
| 22 | `rule.region.close_begin` | transition_rule | SEM-INV-002 | LEAN+TLA+RT |
| 23 | `rule.region.close_cancel_children` | transition_rule | SEM-INV-002 | LEAN+TLA+RT |
| 24 | `rule.region.close_children_done` | transition_rule | SEM-INV-002 | LEAN+TLA+RT |
| 25 | `rule.region.close_run_finalizer` | transition_rule | SEM-INV-002 | LEAN (ADR-004) |
| 26 | `rule.region.close_complete` | transition_rule | SEM-INV-002 | LEAN+TLA+RT |
| 27 | `inv.region.quiescence` | invariant | SEM-INV-002 | LEAN+TLA+RT |
| 28 | `prog.region.close_terminates` | progress_property | SEM-INV-002 | LEAN |
| 29 | `def.outcome.four_valued` | definition | foundational | LEAN+RT |
| 30 | `def.outcome.severity_lattice` | definition | foundational | LEAN+RT (ADR-008) |
| 31 | `def.outcome.join_semantics` | definition | foundational | LEAN+RT (ADR-008) |
| 32 | `def.cancel.reason_ordering` | definition | SEM-DEF-003 | DOC+RT (ADR-002) |
| 33 | `inv.ownership.single_owner` | invariant | SEM-INV-001 | LEAN+TLA+RT |
| 34 | `inv.ownership.task_owned` | invariant | SEM-INV-001 | LEAN+TLA+RT |
| 35 | `def.ownership.region_tree` | definition | SEM-DEF-002 | LEAN+TLA+RT |
| 36 | `rule.ownership.spawn` | transition_rule | SEM-INV-001 | LEAN+TLA+RT |
| 37 | `comb.join` | derived_combinator | foundational | DOC+RT (ADR-005) |
| 38 | `comb.race` | derived_combinator | SEM-INV-004 | DOC+RT (ADR-005) |
| 39 | `comb.timeout` | derived_combinator | foundational | DOC+RT (ADR-005) |
| 40 | `inv.combinator.loser_drained` | invariant | SEM-INV-004 | LEAN+RT (ADR-001) |
| 41 | `law.race.never_abandon` | algebraic_law | SEM-INV-004 | DOC+RT (deferred) |
| 42 | `law.join.assoc` | algebraic_law | foundational | LEAN (ADR-005) |
| 43 | `law.race.comm` | algebraic_law | foundational | LEAN (ADR-005) |
| 44 | `inv.capability.no_ambient` | invariant | SEM-INV-006 | Rust type system (ADR-006) |
| 45 | `def.capability.cx_scope` | definition | SEM-INV-006 | Rust type system (ADR-006) |
| 46 | `inv.determinism.replayable` | invariant | SEM-INV-007 | RT test suite (ADR-007) |
| 47 | `def.determinism.seed_equivalence` | definition | SEM-DEF-001 | RT test suite (ADR-007) |

---

## 4. Contract Structure

The canonical contract is organized into 5 sections, each corresponding
to a SEM-04 sub-bead.

### 4.1 Section Map

```
semantic_contract/
  01_schema.md          ← This document (SEM-04.1)
  02_glossary.md        ← SEM-04.2: Canonical terms + cancel kind policy
  03_transitions.md     ← SEM-04.3: Transition rules with pre/post/effects
  04_invariants.md      ← SEM-04.4: Invariants and laws with checkable clauses
  05_versioning.md      ← SEM-04.5: Change policy and evolution rules
```

### 4.2 Rule Entry Schema

Each rule in the contract follows this schema:

```yaml
rule_entry:
  id: "<rule-id>"               # Stable, permanent
  type: "<type_prefix>"         # One of: rule, inv, def, prog, law, comb
  domain: "<domain>"            # One of: cancel, obligation, region, ...
  charter_anchor: "<SEM-INV-*>" # Charter invariant or definition reference
  enforcement_layers:            # Which layers enforce this rule
    - layer: "LEAN"
      status: "proved" | "defined" | "partial" | "absent"
      citation: "<file:line>"
    - layer: "TLA"
      status: "checked" | "modeled" | "absent"
      citation: "<file:line>"
    - layer: "RT"
      status: "implemented" | "oracle-checked" | "absent"
      citation: "<file:line>"
    - layer: "DOC"
      status: "documented" | "absent"
      citation: "<file:section>"
  adr_ref: "<ADR-NNN>"          # If this rule was subject to an ADR decision
  preconditions: [...]           # For transition rules
  effects: [...]                 # For transition rules
  formal_statement: "..."        # Checkable clause (for inv/law/prog)
  witnesses: ["<W-ref>"]        # References to witness pack
  notes: "..."                   # Edge cases, tie-breaking, absorption
```

### 4.3 Enforcement Layer Status Values

| Layer | Status | Meaning |
|-------|--------|---------|
| LEAN | `proved` | Mechanized proof exists |
| LEAN | `defined` | Definition exists, no proof yet |
| LEAN | `partial` | Structural approximation |
| LEAN | `absent` | Not modeled |
| TLA | `checked` | TLC model-checked (bounded) |
| TLA | `modeled` | Encoded in spec, not separately checked |
| TLA | `absent` | Not modeled (documented abstraction) |
| RT | `implemented` | Production code with tests |
| RT | `oracle-checked` | Verified by runtime oracle |
| RT | `absent` | Not implemented |
| DOC | `documented` | Appears in formal documentation |
| DOC | `absent` | Not documented |

---

## 5. Cross-Reference Index

### 5.1 Rule-ID → ADR Mapping

| Rule ID(s) | ADR | Decision |
|------------|-----|----------|
| #40 | ADR-001 | Lean proof required |
| #7, #8, #32 | ADR-002 | Canonical 5 + extension policy |
| #6 | ADR-003 | TLA+ abstraction accepted |
| #25 | ADR-004 | TLA+ abstraction accepted |
| #37-39, #41-43 | ADR-005 | Incremental 3 Lean law proofs |
| #44, #45 | ADR-006 | Type-system enforcement |
| #46, #47 | ADR-007 | Implementation property |
| #29-31 | ADR-008 | TLA+ abstraction accepted |

### 5.2 Charter Invariant → Rule Mapping

| Charter Invariant | Rule IDs | Status |
|-------------------|----------|--------|
| SEM-INV-001 (Ownership) | #33, #34, #35, #36 | All layers aligned |
| SEM-INV-002 (Region Close) | #22-28 | LEAN+TLA+RT (ADR-004: finalizer in LEAN only) |
| SEM-INV-003 (Cancellation) | #1-6, #9-12 | LEAN+TLA+RT (ADR-003: propagation in LEAN only) |
| SEM-INV-004 (Loser Drain) | #38, #40-43 | ADR-001: Lean proof pending; ADR-005: 3 laws pending |
| SEM-INV-005 (Obligations) | #13-21 | All layers aligned |
| SEM-INV-006 (Capability) | #44, #45 | Type-system enforcement (ADR-006) |
| SEM-INV-007 (Determinism) | #46, #47 | Implementation property (ADR-007) |

---

## 6. Stability Guarantees

### 6.1 What Cannot Change

- Rule IDs #1-47 are permanent once published.
- Type prefixes (`rule`, `inv`, `def`, `prog`, `law`, `comb`) are permanent.
- Domain names are permanent.

### 6.2 What Can Be Added

- New rule IDs (#48+) with minor version bump.
- New enforcement layer citations as proofs/implementations complete.
- New witness references as evidence accumulates.

### 6.3 What Requires Major Version

- Changing the semantics of an existing rule.
- Splitting or merging existing rule IDs.
- Changing the type prefix of an existing rule.

---

## 7. Machine-Readable Output

The contract schema is designed to be serializable to JSON for CI consumption:

```json
{
  "schema_version": "1.0.0",
  "rules": [
    {
      "id": "rule.cancel.request",
      "number": 1,
      "type": "transition_rule",
      "domain": "cancel",
      "charter_anchor": "SEM-INV-003",
      "enforcement": {
        "LEAN": { "status": "proved", "citation": "L123-145" },
        "TLA": { "status": "modeled", "citation": "Spec.tla:45" },
        "RT": { "status": "implemented", "citation": "cancel.rs:100-120" }
      },
      "adr_ref": null,
      "formal_statement": "CancelRequest(task) requires task.state = Running",
      "witnesses": []
    }
  ]
}
```

This format is consumed by:
- SEM-08 conformance harness (rule-by-rule verification)
- SEM-10 CI checker (projection consistency)
- SEM-12 verification fabric (coverage gate)

---

## 8. Downstream Usage

1. **SEM-04.2**: Glossary references this schema for term definitions.
2. **SEM-04.3**: Transition rules follow the `rule_entry` schema.
3. **SEM-04.4**: Invariants and laws follow the `rule_entry` schema.
4. **SEM-04.5**: Versioning policy inherits stability guarantees from section 6.
5. **SEM-08**: Conformance harness maps rules to test cases using `enforcement` field.
6. **SEM-10**: CI checker validates that each layer's projection covers all rules.
