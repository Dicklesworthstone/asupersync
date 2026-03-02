# Semantic Inventory Schema and Row Taxonomy

Status: Active
Program: `asupersync-3cddg` (SEM-02.1)
Parent: SEM-02 Semantic Inventory and Drift Matrix
Author: SapphireHill
Published: 2026-03-02 UTC
Charter Reference: `docs/semantic_harmonization_charter.md`

## 1. Purpose

This document defines the canonical row schema for the semantic drift
inventory. Every row in the drift matrix follows this schema, enabling
reproducible comparison of semantic concepts across four artifact layers:

| Layer | Abbreviation | Root artifacts |
|-------|-------------|----------------|
| Runtime implementation | `RT` | `src/` (Rust source) |
| Documentation & specs | `DOC` | `asupersync_v4_formal_semantics.md`, `asupersync_plan_v4.md`, `docs/` |
| Lean formalization | `LEAN` | `formal/lean/Asupersync.lean`, `formal/lean/coverage/` |
| TLA+ model | `TLA` | `formal/tla/Asupersync.tla` |

The schema is the factual substrate for SEM-03 decision work and SEM-04
canonical contract authoring. Without rule-level precision here, downstream
decisions become opinion-driven.

## 2. Row Schema

Every inventory row is a single semantic concept with the following fields:

### 2.1 Identity Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `concept_id` | string | yes | Stable hierarchical ID. Format: `<domain>.<area>.<specific>` (e.g., `cancel.request.idempotence`). Once assigned, never reused. |
| `title` | string | yes | Human-readable name (max 120 chars). |
| `row_type` | enum | yes | Taxonomy classification (see Section 3). |
| `domain` | enum | yes | Semantic domain (see Section 4). |

### 2.2 Intent and Specification

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `rule_intent` | string | yes | What this concept guarantees, defines, or constrains. Written as a falsifiable claim, not a wish. |
| `charter_refs` | string[] | no | References to charter invariants/definitions (e.g., `SEM-INV-003`, `SEM-DEF-003`). |
| `formal_rule_refs` | string[] | no | References to formal semantics rules (e.g., `CANCEL-REQUEST`, `INV-QUIESCENCE`). |

### 2.3 Artifact Citations

Each citation locates the concept in a specific artifact layer. A concept
may have zero or more citations per layer.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `citations` | Citation[] | yes | Array of artifact citations (see Section 5). |

### 2.4 Alignment Classification

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `alignment_status` | enum | yes | Cross-artifact alignment (see Section 6). |
| `alignment_detail` | AlignmentDetail[] | no | Per-layer-pair alignment when overall status is not `Aligned` (see Section 6.2). |
| `divergence_description` | string | conditional | Required when status is `Divergent` or `Ambiguous`. Precise description of the semantic gap. |

### 2.5 Impact Assessment

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `impact_level` | enum | yes | Severity of misalignment or importance of concept (see Section 7). |
| `impact_rationale` | string | yes | Why this impact level was assigned. References specific downstream consequences. |
| `downstream_concepts` | string[] | no | `concept_id` values that depend on this concept being correct. |
| `escalation_class` | enum | no | Charter escalation class if divergent: `C0`, `C1`, `C2` (see `SEM-ESC-001`). |

### 2.6 Metadata

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `notes` | string | no | Additional context, caveats, or analyst observations. |
| `last_verified` | date | no | ISO-8601 date of last manual verification. |
| `verified_by` | string | no | Agent or reviewer who last verified the row. |

## 3. Row Type Taxonomy

Every concept is classified into exactly one row type:

| Row Type | ID Prefix | Description | Examples |
|----------|-----------|-------------|----------|
| `invariant` | `inv.*` | Safety property that must hold in every reachable state. | `inv.tree.single_owner`, `inv.quiescence`, `inv.obligation.no_leak` |
| `transition_rule` | `rule.*` | A named state transition in the operational semantics. | `rule.cancel.request`, `rule.spawn`, `rule.close.begin` |
| `definition` | `def.*` | A named concept, type, or domain definition. | `def.outcome`, `def.budget`, `def.cancel_reason` |
| `progress_property` | `prog.*` | Liveness property: something eventually happens. | `prog.task.terminates`, `prog.cancel.drains` |
| `algebraic_law` | `law.*` | Equational or refinement law relating combinators. | `law.join.assoc`, `law.race.comm`, `law.race.never` |
| `derived_combinator` | `comb.*` | Composite operation defined in terms of primitives. | `comb.join`, `comb.race`, `comb.timeout` |
| `operational_gate` | `gate.*` | CI/testing enforcement mechanism. | `gate.ci.lean_proof`, `gate.ci.oracle_suite` |

## 4. Semantic Domains

Every concept belongs to exactly one domain:

| Domain | Description | Charter Anchors |
|--------|-------------|-----------------|
| `ownership` | Structured concurrency: task/region ownership tree. | `SEM-INV-001`, `SEM-DEF-002` |
| `cancel` | Cancellation protocol: request, drain, finalize, masking. | `SEM-INV-003`, `SEM-DEF-003` |
| `region` | Region lifecycle: open, closing, draining, finalizing, closed. | `SEM-INV-002` |
| `obligation` | Obligation tracking: reserve, commit, abort, leak detection. | `SEM-INV-005`, `SEM-DEF-004` |
| `scheduling` | Scheduler lanes, fairness, preemption, admission. | (runtime-specific) |
| `outcome` | Four-valued outcome lattice and severity ordering. | (foundational) |
| `budget` | Cleanup budgets: deadline, poll/cost quota, priority. | (foundational) |
| `combinator` | Derived operations: join, race, timeout, bulkhead, retry. | `SEM-INV-004` |
| `capability` | Cx capability system: no ambient authority. | `SEM-INV-006` |
| `determinism` | Replayability, virtual time, trace equivalence. | `SEM-INV-007`, `SEM-DEF-001` |
| `distributed` | Idempotency, saga compensation, remote structured concurrency. | (extension) |
| `time` | Virtual time, sleep, deadline, timer wheel. | (runtime-specific) |

## 5. Citation Format

Each citation identifies where a concept appears in a specific artifact layer.

```
Citation {
    layer:       "RT" | "DOC" | "LEAN" | "TLA"
    file_path:   string       // Relative to repo root
    line_start:  integer?     // First relevant line (1-indexed)
    line_end:    integer?     // Last relevant line (inclusive)
    anchor:      string?      // Named anchor (function, theorem, rule name)
    excerpt:     string?      // Key text (max 200 chars) for quick identification
    confidence:  "high" | "medium" | "low"  // Analyst confidence in citation accuracy
}
```

**Citation rules:**

1. Every citation must include `layer` and `file_path`.
2. Line ranges are strongly preferred; omit only for whole-file scope.
3. `anchor` should use the canonical name from that layer (e.g., Rust function
   name, Lean theorem name, TLA+ action name, formal semantics rule name).
4. `confidence` reflects whether the citation was mechanically verified
   (`high`), manually reviewed (`medium`), or inferred from naming/structure
   (`low`).

**Layer-specific citation conventions:**

| Layer | `file_path` examples | `anchor` convention |
|-------|---------------------|---------------------|
| `RT` | `src/cancel/protocol.rs`, `src/cx/scope.rs` | `fn cancel_request`, `struct CancelToken` |
| `DOC` | `asupersync_v4_formal_semantics.md`, `docs/semantic_harmonization_charter.md` | Section/rule name: `CANCEL-REQUEST`, `INV-QUIESCENCE` |
| `LEAN` | `formal/lean/Asupersync.lean` | `theorem requestCancel_preserves_wellformed` |
| `TLA` | `formal/tla/Asupersync.tla` | `RequestCancel`, `CancelTerminates` |

## 6. Alignment Classification

### 6.1 Overall Status

Each concept receives exactly one overall alignment status:

| Status | Code | Meaning | Action Required |
|--------|------|---------|-----------------|
| **Aligned** | `A` | All artifact layers that address this concept express equivalent semantics. Minor notation differences are acceptable if meaning is preserved. | None (monitor for drift). |
| **Divergent** | `D` | At least two layers express contradictory semantics for the same concept. The contradiction is not an abstraction-level difference. | Mandatory ADR in SEM-03. |
| **Ambiguous** | `X` | The concept is present in multiple layers but its precise meaning differs or is underspecified in at least one layer. Reasonable analysts could disagree on alignment. | Clarification in SEM-03; may become `A` or `D` after investigation. |
| **Missing** | `M` | The concept is present in one or more layers but absent from at least one layer where it should appear. | Gap-fill task in SEM-03 or later phase. |

### 6.2 Per-Layer-Pair Detail

When overall status is not `Aligned`, provide pairwise detail:

```
AlignmentDetail {
    layer_a:    "RT" | "DOC" | "LEAN" | "TLA"
    layer_b:    "RT" | "DOC" | "LEAN" | "TLA"
    status:     "A" | "D" | "X" | "M"
    note:       string    // Precise description of the pairwise gap
}
```

Layer pairs are unordered: `(RT, DOC)` is the same as `(DOC, RT)`.
There are six possible pairs: RT-DOC, RT-LEAN, RT-TLA, DOC-LEAN, DOC-TLA, LEAN-TLA.

### 6.3 Classification Decision Rules

To prevent status conflation, apply these rules in order:

1. If a concept has zero citations in a layer where it should appear:
   that pair is `Missing`.
2. If two layers express contradictory claims (e.g., "cancel is idempotent"
   vs. runtime code that panics on double-cancel): `Divergent`.
3. If the concept is present but underspecified or uses different terminology
   such that equivalence is not mechanically verifiable: `Ambiguous`.
4. If all present layers agree on semantics (accounting for abstraction level
   differences): `Aligned`.

Abstraction-level differences are NOT divergences. Example: TLA+ models a
three-state obligation lifecycle while runtime has additional intermediate
states for performance. If the observable behavior is equivalent, this is
`Aligned` with a note.

## 7. Impact Levels

| Level | Code | Criteria | Charter Mapping |
|-------|------|----------|-----------------|
| **Critical** | `I0` | Misalignment could violate a non-negotiable invariant (`SEM-INV-*`). Affects safety, data integrity, or correctness under cancellation. | `C0` escalation |
| **High** | `I1` | Misalignment blocks multiple downstream SEM tasks or affects core combinator semantics. | `C1` escalation |
| **Medium** | `I2` | Misalignment is bounded in scope (single module, edge case) but still needs resolution. | `C2` escalation |
| **Low** | `I3` | Cosmetic, naming, or documentation-only issue. No behavioral impact. | No escalation needed |
| **Informational** | `I4` | Noted for completeness. Layer intentionally omits this concept (e.g., TLA+ does not model scheduling details). | No action required |

**Impact assessment rules:**

1. Anything touching `SEM-INV-001` through `SEM-INV-007` starts at `I0`
   unless the analyst can demonstrate bounded blast radius.
2. Concepts with >3 downstream dependents start at `I1` minimum.
3. Missing citations in the `RT` layer are always >= `I1` (runtime is
   the production artifact).
4. Missing citations in only `TLA` or `LEAN` are >= `I2` if the concept
   is safety-critical, else `I3`.

## 8. Concept ID Namespace

### 8.1 Naming Convention

```
<row_type_prefix>.<domain>.<area>[.<qualifier>]
```

Examples:
- `inv.ownership.single_owner` — Invariant: every task owned by exactly one region
- `rule.cancel.request` — Transition rule: cancellation request
- `def.outcome.severity_lattice` — Definition: four-valued outcome ordering
- `prog.region.close_terminates` — Progress: closing regions eventually close
- `law.race.never_abandon` — Law: race never abandons losers
- `comb.timeout` — Derived combinator: timeout

### 8.2 Stability Contract

- Once a `concept_id` is published in a drift matrix row, it is permanent.
- Retired concepts get status `Retired` with a `superseded_by` field.
- ID format changes require a schema version bump.

## 9. Required Semantic Areas

Per acceptance criteria, the inventory must achieve completeness for these
areas before SEM-02 can close. Each area maps to a set of concept IDs that
must be present in the drift matrix.

### 9.1 Cancellation (domain: `cancel`)

| Required Concept | Type | Charter Anchor |
|-----------------|------|----------------|
| `rule.cancel.request` | transition_rule | SEM-INV-003 |
| `rule.cancel.acknowledge` | transition_rule | SEM-INV-003 |
| `rule.cancel.drain` | transition_rule | SEM-INV-003 |
| `rule.cancel.finalize` | transition_rule | SEM-INV-003 |
| `inv.cancel.idempotence` | invariant | SEM-INV-003 |
| `inv.cancel.propagates_down` | invariant | SEM-INV-003 |
| `def.cancel.reason_kinds` | definition | SEM-DEF-003 |
| `def.cancel.severity_ordering` | definition | SEM-DEF-003 |
| `prog.cancel.drains` | progress_property | SEM-INV-003 |

### 9.2 Masking (domain: `cancel`)

| Required Concept | Type | Charter Anchor |
|-----------------|------|----------------|
| `rule.cancel.checkpoint_masked` | transition_rule | SEM-INV-003 |
| `inv.cancel.mask_bounded` | invariant | (INV-MASK-BOUNDED) |
| `inv.cancel.mask_monotone` | invariant | (INV-MASK-BOUNDED) |

### 9.3 Obligations (domain: `obligation`)

| Required Concept | Type | Charter Anchor |
|-----------------|------|----------------|
| `rule.obligation.reserve` | transition_rule | SEM-INV-005, SEM-DEF-004 |
| `rule.obligation.commit` | transition_rule | SEM-INV-005, SEM-DEF-004 |
| `rule.obligation.abort` | transition_rule | SEM-INV-005, SEM-DEF-004 |
| `rule.obligation.leak` | transition_rule | SEM-INV-005 |
| `inv.obligation.no_leak` | invariant | SEM-INV-005 |
| `inv.obligation.linear` | invariant | (INV-OBLIGATION-LINEAR) |
| `inv.obligation.bounded` | invariant | (INV-OBLIGATION-BOUNDED) |
| `inv.obligation.ledger_empty_on_close` | invariant | (INV-LEDGER-EMPTY-ON-CLOSE) |
| `prog.obligation.resolves` | progress_property | SEM-DEF-004 |

### 9.4 Region Close and Quiescence (domain: `region`)

| Required Concept | Type | Charter Anchor |
|-----------------|------|----------------|
| `rule.region.close_begin` | transition_rule | SEM-INV-002 |
| `rule.region.close_cancel_children` | transition_rule | SEM-INV-002 |
| `rule.region.close_children_done` | transition_rule | SEM-INV-002 |
| `rule.region.close_run_finalizer` | transition_rule | SEM-INV-002 |
| `rule.region.close_complete` | transition_rule | SEM-INV-002 |
| `inv.region.quiescence` | invariant | SEM-INV-002 |
| `prog.region.close_terminates` | progress_property | SEM-INV-002 |

### 9.5 Severity Ordering (domain: `outcome`)

| Required Concept | Type | Charter Anchor |
|-----------------|------|----------------|
| `def.outcome.four_valued` | definition | (foundational) |
| `def.outcome.severity_lattice` | definition | (foundational) |
| `def.outcome.join_semantics` | definition | (foundational) |
| `def.cancel.reason_ordering` | definition | SEM-DEF-003 |

### 9.6 Structured Ownership (domain: `ownership`)

| Required Concept | Type | Charter Anchor |
|-----------------|------|----------------|
| `inv.ownership.single_owner` | invariant | SEM-INV-001 |
| `inv.ownership.task_owned` | invariant | SEM-INV-001 |
| `def.ownership.region_tree` | definition | SEM-DEF-002 |
| `rule.ownership.spawn` | transition_rule | SEM-INV-001 |

### 9.7 Combinators and Loser Drain (domain: `combinator`)

| Required Concept | Type | Charter Anchor |
|-----------------|------|----------------|
| `comb.join` | derived_combinator | (foundational) |
| `comb.race` | derived_combinator | SEM-INV-004 |
| `comb.timeout` | derived_combinator | (foundational) |
| `inv.combinator.loser_drained` | invariant | SEM-INV-004 |
| `law.race.never_abandon` | algebraic_law | SEM-INV-004 |
| `law.join.assoc` | algebraic_law | (foundational) |
| `law.race.comm` | algebraic_law | (foundational) |

### 9.8 Capability and Authority (domain: `capability`)

| Required Concept | Type | Charter Anchor |
|-----------------|------|----------------|
| `inv.capability.no_ambient` | invariant | SEM-INV-006 |
| `def.capability.cx_scope` | definition | SEM-INV-006 |

### 9.9 Determinism (domain: `determinism`)

| Required Concept | Type | Charter Anchor |
|-----------------|------|----------------|
| `inv.determinism.replayable` | invariant | SEM-INV-007 |
| `def.determinism.seed_equivalence` | definition | SEM-DEF-001 |

## 10. Machine-Readable Schema

For tooling integration, the drift matrix should be stored as JSON following
this JSON Schema. This extends the existing Lean coverage matrix schema
(`formal/lean/coverage/lean_coverage_matrix.schema.json`) with cross-artifact
drift dimensions.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://asupersync.dev/schemas/semantic-inventory-1.0.0.json",
  "title": "Asupersync Semantic Inventory Row",
  "type": "object",
  "required": [
    "concept_id", "title", "row_type", "domain",
    "rule_intent", "citations", "alignment_status",
    "impact_level", "impact_rationale"
  ],
  "properties": {
    "concept_id": {
      "type": "string",
      "pattern": "^(inv|rule|def|prog|law|comb|gate)\\.[a-z][a-z0-9_.]*$"
    },
    "title": { "type": "string", "maxLength": 120 },
    "row_type": {
      "enum": [
        "invariant", "transition_rule", "definition",
        "progress_property", "algebraic_law",
        "derived_combinator", "operational_gate"
      ]
    },
    "domain": {
      "enum": [
        "ownership", "cancel", "region", "obligation",
        "scheduling", "outcome", "budget", "combinator",
        "capability", "determinism", "distributed", "time"
      ]
    },
    "rule_intent": { "type": "string", "minLength": 10 },
    "charter_refs": {
      "type": "array",
      "items": { "type": "string", "pattern": "^SEM-" }
    },
    "formal_rule_refs": {
      "type": "array",
      "items": { "type": "string" }
    },
    "citations": {
      "type": "array",
      "items": { "$ref": "#/$defs/citation" }
    },
    "alignment_status": { "enum": ["Aligned", "Divergent", "Ambiguous", "Missing"] },
    "alignment_detail": {
      "type": "array",
      "items": { "$ref": "#/$defs/alignment_detail" }
    },
    "divergence_description": { "type": "string" },
    "impact_level": { "enum": ["I0", "I1", "I2", "I3", "I4"] },
    "impact_rationale": { "type": "string", "minLength": 5 },
    "downstream_concepts": {
      "type": "array",
      "items": { "type": "string" }
    },
    "escalation_class": { "enum": ["C0", "C1", "C2"] },
    "notes": { "type": "string" },
    "last_verified": { "type": "string", "format": "date" },
    "verified_by": { "type": "string" }
  },
  "$defs": {
    "citation": {
      "type": "object",
      "required": ["layer", "file_path"],
      "properties": {
        "layer": { "enum": ["RT", "DOC", "LEAN", "TLA"] },
        "file_path": { "type": "string" },
        "line_start": { "type": "integer", "minimum": 1 },
        "line_end": { "type": "integer", "minimum": 1 },
        "anchor": { "type": "string" },
        "excerpt": { "type": "string", "maxLength": 200 },
        "confidence": { "enum": ["high", "medium", "low"] }
      }
    },
    "alignment_detail": {
      "type": "object",
      "required": ["layer_a", "layer_b", "status"],
      "properties": {
        "layer_a": { "enum": ["RT", "DOC", "LEAN", "TLA"] },
        "layer_b": { "enum": ["RT", "DOC", "LEAN", "TLA"] },
        "status": { "enum": ["Aligned", "Divergent", "Ambiguous", "Missing"] },
        "note": { "type": "string" }
      }
    }
  }
}
```

## 11. Example Row

```json
{
  "concept_id": "inv.cancel.idempotence",
  "title": "Cancel request is idempotent",
  "row_type": "invariant",
  "domain": "cancel",
  "rule_intent": "Repeated cancel requests on the same task or region are safe and produce no additional side effects beyond the first request. The cancel reason is strengthened (max severity) but never weakened.",
  "charter_refs": ["SEM-INV-003"],
  "formal_rule_refs": ["CANCEL-REQUEST"],
  "citations": [
    {
      "layer": "RT",
      "file_path": "src/cancel/protocol.rs",
      "line_start": 145,
      "line_end": 178,
      "anchor": "fn request_cancel",
      "excerpt": "if current_severity >= new_severity { return; }",
      "confidence": "high"
    },
    {
      "layer": "DOC",
      "file_path": "asupersync_v4_formal_semantics.md",
      "anchor": "CANCEL-REQUEST",
      "excerpt": "Idempotent: if task is already in CancelRequested or later state, strengthen reason but do not re-enter",
      "confidence": "high"
    },
    {
      "layer": "LEAN",
      "file_path": "formal/lean/Asupersync.lean",
      "line_start": 2321,
      "anchor": "theorem requestCancel_preserves_wellformed",
      "confidence": "medium"
    },
    {
      "layer": "TLA",
      "file_path": "formal/tla/Asupersync.tla",
      "anchor": "RequestCancel",
      "excerpt": "taskState'[t] = IF taskState[t] \\in ... THEN CancelRequested ELSE taskState[t]",
      "confidence": "high"
    }
  ],
  "alignment_status": "Aligned",
  "impact_level": "I0",
  "impact_rationale": "Cancel idempotence is foundational to SEM-INV-003 and affects every cancel-aware path in the runtime. Violation would break structured concurrency guarantees.",
  "downstream_concepts": [
    "rule.cancel.drain",
    "rule.cancel.finalize",
    "inv.combinator.loser_drained",
    "comb.race"
  ],
  "last_verified": "2026-03-02",
  "verified_by": "SapphireHill"
}
```

## 12. Completeness Checklist

Before SEM-02 can close, the drift matrix must contain rows covering every
concept in Section 9 (Required Semantic Areas). The minimum required rows:

| Domain | Required Row Count | Section |
|--------|--------------------|---------|
| Cancellation | 9 | 9.1 |
| Masking | 3 | 9.2 |
| Obligations | 9 | 9.3 |
| Region close / quiescence | 7 | 9.4 |
| Severity ordering | 4 | 9.5 |
| Structured ownership | 4 | 9.6 |
| Combinators / loser drain | 7 | 9.7 |
| Capability / authority | 2 | 9.8 |
| Determinism | 2 | 9.9 |
| **Total minimum** | **47** | |

Additional rows beyond the minimum are expected as analysts discover concepts
during extraction (SEM-02.2 through SEM-02.5).

## 13. Relationship to Existing Schemas

This schema extends but does not replace the Lean coverage matrix schema
(`formal/lean/coverage/lean_coverage_matrix.schema.json`).

| Concern | Lean Coverage Schema | This Schema |
|---------|---------------------|-------------|
| Scope | Lean proof coverage tracking | Cross-artifact semantic drift |
| Row types | `semantic_rule`, `invariant`, `refinement_obligation`, `operational_gate` | 7 types (adds `progress_property`, `algebraic_law`, `derived_combinator`) |
| Status values | `not-started`, `in-progress`, `blocked`, `proven`, `validated-in-ci` | `Aligned`, `Divergent`, `Ambiguous`, `Missing` |
| Citation scope | Lean/CI artifacts only | All 4 layers (RT, DOC, LEAN, TLA) |
| Blocker tracking | Proof-specific blocker codes | Impact levels + escalation classes |

Rows in the Lean coverage matrix can be cross-referenced via `concept_id`
to rows in the semantic inventory. The `concept_id` namespace is shared.

## 14. Governance

Changes to this schema require:
- A bead in the `asupersync-3cddg` program with `sem-harmonization` label.
- Review by at least one SEM contributor listed in `SEM-COMM-002`.
- Schema version bump in Section 10 if structural fields change.

Field additions that do not change existing required fields are minor
version bumps. Changes to required fields, enum values, or ID format are
major version bumps.
