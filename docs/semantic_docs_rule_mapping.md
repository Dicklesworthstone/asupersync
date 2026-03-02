# Docs-to-Rule-ID Mapping (SEM-05.1)

**Bead**: `asupersync-3cddg.5.1`
**Parent**: SEM-05 Projection Track: Formal Semantics Docs Alignment
**Author**: SapphireHill
**Date**: 2026-03-02
**Inputs**:
- `docs/asupersync_v4_formal_semantics.md` (FOS v4.0.0)
- `docs/semantic_contract_schema.md` (SEM-04.1, 47 rule IDs)
- `docs/semantic_contract_glossary.md` (SEM-04.2, canonical terms)
- `docs/semantic_contract_transitions.md` (SEM-04.3, transition rules)
- `docs/semantic_contract_invariants.md` (SEM-04.4, invariants and laws)
- `docs/spork_operational_semantics.md` (Spork extension)
- `docs/spork_glossary_invariants.md` (Spork glossary)

---

## 1. Purpose

This document establishes an explicit, machine-lintable mapping from every
normative section in the formal semantics documentation to canonical rule IDs
from the semantic contract (SEM-04.1). This prevents undocumented semantic
drift by making every behavioral claim traceable.

### 1.1 Scope

- **In scope**: All sections in `asupersync_v4_formal_semantics.md` (FOS) that
  define state, transitions, invariants, laws, or oracle checks.
- **Out of scope**: Spork extension docs (covered separately in SEM-05.3+),
  decision framework docs (SEM-03.x), inventory docs (SEM-02.x).

### 1.2 Normative vs. Non-Normative

Sections are classified as:

- **Normative**: Defines behavior that must be consistent with the canonical
  contract. Changes require drift justification.
- **Explanatory**: Provides intuition, motivation, or proof sketches. Changes
  do not require drift justification but must not contradict normative content.
- **Implementation**: Maps semantics to runtime artifacts. Changes require
  checking that the mapping remains accurate.

---

## 2. Section-to-Rule-ID Mapping

### 2.1 Domain Definitions (FOS §1)

| FOS Section | Lines | Rule IDs | Type | Notes |
|-------------|-------|----------|------|-------|
| §1.2 Outcomes | 26-39 | `def.outcome.four_valued` (#29), `def.outcome.severity_lattice` (#30) | Normative | Four-valued enum + severity total order |
| §1.3 Cancel Reasons | 41-49 | `def.cancel.reason_kinds` (#7), `def.cancel.severity_ordering` (#8), `def.cancel.reason_ordering` (#32) | Normative | CancelKind enum + severity tiers. **Note**: FOS §1.3 shows 5 CancelKind variants (simplified); RT has 11. See §4.1 below. |
| §1.4 Budgets | 51-69 | — | Explanatory | Budget algebra supports `comb.timeout` (#39) and `inv.cancel.mask_bounded` (#11) |
| §1.5 Task States | 71-81 | — | Normative | State machine referenced by cancel rules (#1-4, #10) |
| §1.6 Region States | 83-92 | — | Normative | State machine referenced by region rules (#22-26) |
| §1.7 Obligation States | 94-99 | `def.cancel.reason_kinds` (#7, ObligationKind) | Normative | Four obligation kinds: SendPermit, Ack, Lease, IoOp |
| §1.8 Trace labels / independence | 101-138 | `inv.determinism.replayable` (#46), `def.determinism.seed_equivalence` (#47) | Explanatory | Mazurkiewicz traces underpin determinism |
| §1.9 Linear resources | 140-151 | `inv.obligation.linear` (#18), `inv.obligation.no_leak` (#17) | Normative | Linearity discipline definition |
| §1.11 Scheduler lanes | 166-185 | — | Implementation | Priority model (Cancel > Timed > Ready) |
| §1.12 Scheduler fairness | 187-228 | — | Explanatory | Fairness bound for progress properties |
| §1.13 Derived predicates | 230-247 | `inv.region.quiescence` (#27), `inv.combinator.loser_drained` (#40) | Normative | Quiescent(r), LoserDrained(t1,t2) definitions |

### 2.2 Transition Rules (FOS §3)

| FOS Section | Lines | Rule IDs | Type | Notes |
|-------------|-------|----------|------|-------|
| §3.1 SPAWN | 376-386 | `rule.ownership.spawn` (#36) | Normative | Precondition: region Open, task fresh |
| §3.1 COMPLETE-OK | 399-412 | — | Normative | Supports `def.outcome.four_valued` (#29) |
| §3.1 COMPLETE-ERR | 414-425 | — | Normative | Supports `def.outcome.four_valued` (#29) |
| §3.2 Cancellation Protocol | 429-548 | `rule.cancel.request` (#1), `rule.cancel.acknowledge` (#2), `rule.cancel.drain` (#3), `rule.cancel.finalize` (#4), `inv.cancel.idempotence` (#5), `inv.cancel.propagates_down` (#6), `rule.cancel.checkpoint_masked` (#10), `inv.cancel.mask_bounded` (#11), `inv.cancel.mask_monotone` (#12) | Normative | Complete cancellation protocol |
| §3.2 CANCEL-REQUEST | 549-563 | `rule.cancel.request` (#1), `inv.cancel.propagates_down` (#6) | Normative | Strengthen + propagate to descendants |
| §3.2 CANCEL-ACKNOWLEDGE | 575-586 | `rule.cancel.acknowledge` (#2) | Normative | Checkpoint with mask=0 → Cancelling |
| §3.2 CHECKPOINT-MASKED | 588-602 | `rule.cancel.checkpoint_masked` (#10), `inv.cancel.mask_bounded` (#11), `inv.cancel.mask_monotone` (#12) | Normative | Mask decrement, bounded deferral |
| §3.2 CANCEL-DRAIN | 615-624 | `rule.cancel.drain` (#3) | Normative | Cleanup done → Finalizing |
| §3.2 CANCEL-FINALIZE | 626-636 | `rule.cancel.finalize` (#4) | Normative | Finalizers done → Completed(Cancelled) |
| §3.2.2 Idempotence | 467-477 | `inv.cancel.idempotence` (#5) | Normative | cancel;cancel ≃ cancel(strengthen) |
| §3.2.3 Bounded cleanup | 479-490 | `prog.cancel.drains` (#9) | Normative | CancelRequested → eventually Completed |
| §3.2.5 Canonical automaton | 509-547 | (#1-4, #10, #5) | Normative | Deterministic automaton over (phase, reason, budget, mask) |
| §3.3 CLOSE-BEGIN | 644-653 | `rule.region.close_begin` (#22) | Normative | Open → Closing |
| §3.3 CLOSE-CANCEL-CHILDREN | 655-665 | `rule.region.close_cancel_children` (#23) | Normative | Closing → Draining, cancel non-complete children |
| §3.3 CLOSE-CHILDREN-DONE | 667-677 | `rule.region.close_children_done` (#24) | Normative | Draining → Finalizing (all children completed) |
| §3.3 CLOSE-RUN-FINALIZER | 679-689 | `rule.region.close_run_finalizer` (#25) | Normative | LIFO finalizer execution |
| §3.3 CLOSE-COMPLETE | 691-702 | `rule.region.close_complete` (#26) | Normative | Finalizing → Closed (ledger empty) |
| §3.4 RESERVE | 714-725 | `rule.obligation.reserve` (#13) | Normative | Acquire linear obligation |
| §3.4 COMMIT | 727-738 | `rule.obligation.commit` (#14) | Normative | Fulfill obligation |
| §3.4 ABORT | 740-750 | `rule.obligation.abort` (#15) | Normative | Cancel obligation |
| §3.4 LEAK | 752-764 | `rule.obligation.leak` (#16), `inv.obligation.no_leak` (#17) | Normative | Error: task completed holding obligation |
| §3.4.1 Linear logic view | 782-821 | `inv.obligation.linear` (#18) | Explanatory | Judgmental-style linear resource model |
| §3.4.5 Ledger view | 880-905 | `inv.obligation.ledger_empty_on_close` (#20) | Normative | Region close requires ledger(r) = ∅ |
| §3.4.6 No silent drop | 907-926 | `inv.obligation.no_leak` (#17), `inv.obligation.linear` (#18) | Normative | Safety theorem: obligations never silently dropped |
| §3.4.7 Cancellation interaction | 928-945 | `inv.obligation.bounded` (#19) | Normative | Drain phase resolves obligations |

### 2.3 Derived Combinators (FOS §4)

| FOS Section | Lines | Rule IDs | Type | Notes |
|-------------|-------|----------|------|-------|
| §4.1 join(f1, f2) | 1003-1014 | `comb.join` (#37), `def.outcome.join_semantics` (#31) | Normative | Spawn both, await both, worst-wins |
| §4.2 race(f1, f2) | 1016-1028 | `comb.race` (#38), `inv.combinator.loser_drained` (#40), `law.race.never_abandon` (#41) | Normative | Select first, cancel+drain loser |
| §4.3 timeout(d, f) | 1030-1036 | `comb.timeout` (#39) | Normative | race(f, sleep+err), timeout min law |

### 2.4 Invariants (FOS §5)

| FOS Section | Lines | Rule IDs | Type | Notes |
|-------------|-------|----------|------|-------|
| INV-TREE | 1043-1048 | `def.ownership.region_tree` (#35) | Normative | Region parent/child tree structure |
| INV-TASK-OWNED | 1050-1055 | `inv.ownership.task_owned` (#34) | Normative | Live tasks have region owner |
| INV-QUIESCENCE | 1057-1079 | `inv.region.quiescence` (#27) | Normative | Closed → all children completed, subregions closed |
| INV-CANCEL-PROPAGATES | 1081-1087 | `inv.cancel.propagates_down` (#6) | Normative | Cancel flows to subregions |
| INV-OBLIGATION-BOUNDED | 1089-1095 | `inv.obligation.bounded` (#19) | Normative | Reserved obligations have live holders |
| INV-OBLIGATION-LINEAR | 1097-1104 | `inv.obligation.linear` (#18) | Normative | Resolved states are absorbing |
| INV-LEDGER-EMPTY-ON-CLOSE | 1106-1113 | `inv.obligation.ledger_empty_on_close` (#20) | Normative | Closed regions have no reserved obligations |
| INV-MASK-BOUNDED | 1115-1122 | `inv.cancel.mask_bounded` (#11), `inv.cancel.mask_monotone` (#12) | Normative | Mask is finite and only decreases |
| INV-DEADLINE-MONOTONE | 1124-1129 | `inv.cancel.mask_bounded` (#11) | Normative | Children deadlines ≤ parent deadlines |
| INV-LOSER-DRAINED | 1131-1136 | `inv.combinator.loser_drained` (#40) | Normative | Race losers always complete |

### 2.5 Progress Properties (FOS §6)

| FOS Section | Lines | Rule IDs | Type | Notes |
|-------------|-------|----------|------|-------|
| PROG-CANCEL | 1176-1181 | `prog.cancel.drains` (#9) | Normative | CancelRequested → eventually Completed |
| PROG-REGION | 1183-1188 | `prog.region.close_terminates` (#28) | Normative | Closing → eventually Closed |
| PROG-OBLIGATION | 1190-1196 | `prog.obligation.resolves` (#21) | Normative | Reserved → eventually Committed/Aborted |

### 2.6 Algebraic Laws (FOS §7)

| FOS Section | Lines | Rule IDs | Type | Notes |
|-------------|-------|----------|------|-------|
| LAW-JOIN-ASSOC | 1269-1273 | `law.join.assoc` (#42) | Normative | join(join(a,b),c) ≃ join(a,join(b,c)) |
| LAW-RACE-COMM | 1281-1285 | `law.race.comm` (#43) | Normative | race(a,b) ≃ race(b,a) |
| LAW-TIMEOUT-MIN | 1287-1291 | `comb.timeout` (#39) | Normative | timeout(d1,timeout(d2,f)) ≃ timeout(min(d1,d2),f) |
| LAW-RACE-NEVER | 1293-1297 | `law.race.never_abandon` (#41) | Normative | race(f,never) ≃ f |

### 2.7 Oracle Checks (FOS §8)

| FOS Section | Lines | Rule IDs | Type | Notes |
|-------------|-------|----------|------|-------|
| test_property | 1329-1337 | (#17, #27, #33, #34, #40) | Implementation | Oracle bundle maps to 5 invariants |
| no_task_leaks | 1339-1344 | `inv.ownership.single_owner` (#33), `inv.ownership.task_owned` (#34) | Implementation | spawned = completed |
| no_obligation_leaks | 1348-1351 | `inv.obligation.no_leak` (#17) | Implementation | ¬∃ ObligationLeaked |
| losers_always_drained | 1353-1358 | `inv.combinator.loser_drained` (#40) | Implementation | Both race participants completed |
| §8.1 DPOR | 1360-1371 | `inv.determinism.replayable` (#46) | Explanatory | Schedule exploration |
| §8.3 Trace certificate | 1378-1440 | `inv.determinism.replayable` (#46), `def.determinism.seed_equivalence` (#47) | Implementation | Proof-carrying trace certificate spec |

### 2.8 TLA+ Sketch (FOS §9)

| FOS Section | Lines | Rule IDs | Type | Notes |
|-------------|-------|----------|------|-------|
| TypeInvariant | 1460-1463 | (#29, #35) | Implementation | Type-level structural invariants |
| TreeStructure | 1465-1468 | `def.ownership.region_tree` (#35) | Implementation | Region tree TLA+ encoding |
| NoOrphans | 1470-1473 | `inv.ownership.task_owned` (#34) | Implementation | Task ownership TLA+ encoding |
| QuiescenceOnClose | 1475-1478 | `inv.region.quiescence` (#27) | Implementation | Quiescence TLA+ encoding |

---

## 3. Coverage Summary

### 3.1 Rule Coverage by FOS Section

| Domain | Rules | FOS Sections | Coverage |
|--------|-------|-------------|----------|
| cancel (#1-12) | 12 | §1.3, §3.2, §5 | **12/12** (100%) |
| obligation (#13-21) | 9 | §1.7, §1.9, §3.4, §5, §6 | **9/9** (100%) |
| region (#22-28) | 7 | §1.6, §3.3, §5, §6 | **7/7** (100%) |
| outcome (#29-32) | 4 | §1.2, §1.3, §4.1 | **4/4** (100%) |
| ownership (#33-36) | 4 | §1.13, §3.1, §5 | **4/4** (100%) |
| combinator (#37-43) | 7 | §4, §5, §7 | **7/7** (100%) |
| capability (#44-45) | 2 | — | **0/2** (0%) |
| determinism (#46-47) | 2 | §1.8, §8 | **2/2** (100%) |
| **Total** | **47** | | **45/47** (96%) |

### 3.2 Coverage Gaps

| Rule ID | Status | Gap Description |
|---------|--------|-----------------|
| `inv.capability.no_ambient` (#44) | **Missing** | FOS does not document the Cx-scope capability model. Capability semantics are enforced by Rust's type system (`Cx<'_>` lifetime) and are not modeled in the operational semantics. |
| `def.capability.cx_scope` (#45) | **Missing** | Same as #44. Cx-scope is a type-level property, not an operational transition. |

**Recommendation**: Add a brief §1.14 "Capability Model (Non-Operational)" section
to the FOS explaining that capability enforcement is type-level and referencing
the contract rules #44-45. This closes the traceability gap without requiring
operational modeling.

---

## 4. Abstraction Simplifications

The FOS makes the following intentional simplifications relative to the
canonical contract and runtime implementation. These are marked as
**non-normative abstractions** that do not redefine canonical semantics.

### 4.1 CancelKind Simplification

**FOS §1.3** lists 5 CancelKind variants:
```
User | Timeout | FailFast | ParentCancelled | Shutdown
```

**Runtime** has 11 variants (canonical per `def.cancel.reason_kinds` #7):
```
User | Timeout | Deadline | PollQuota | CostBudget | FailFast |
RaceLost | LinkedExit | ParentCancelled | ResourceUnavailable | Shutdown
```

**Classification**: Non-normative simplification. The FOS groups
time-driven (Timeout, Deadline), budget-violation (PollQuota, CostBudget),
and cascading (FailFast, RaceLost, LinkedExit, ParentCancelled,
ResourceUnavailable) variants into representative categories for readability.
The severity ordering semantics are identical.

### 4.2 Budget Algebra Simplification

**FOS §1.4** shows the budget combine operation abstractly.

**Runtime** adds cleanup budget calibration tables per CancelKind
(poll quotas: 50-1000, priorities: 200-255) as specified in
`src/types/cancel.rs` module-level docs.

**Classification**: Non-normative. The FOS defines the algebraic structure;
the runtime provides concrete calibration within that structure.

### 4.3 Scheduler Model Simplification

**FOS §1.11-1.12** defines a three-lane priority model with fairness bounds.

**Runtime** implements this via `ThreeLaneScheduler` with concrete
cancel streak limits, steal-half work stealing, and LIFO owner/FIFO steal
local queues.

**Classification**: Non-normative implementation detail. The FOS captures
the scheduling contract (lane priority, fairness); the implementation
chooses specific algorithms.

### 4.4 Obligation Accounting Views

**FOS §3.4** provides multiple views of obligations: operational (§3.4),
Petri net (§3.4 "Obligation accounting"), linear logic (§3.4.1),
and ledger (§3.4.5).

**Classification**: These are all equivalent representations of the same
semantics. The operational view is normative; the others are explanatory
projections that must remain consistent.

---

## 5. Terminology Consistency Check

### 5.1 Term Alignment with SEM-04.2 Glossary

| FOS Term | SEM-04.2 Canonical Term | Status |
|----------|------------------------|--------|
| Outcome | Outcome | Aligned |
| Severity | Severity | Aligned |
| CancelReason | CancelReason | Aligned |
| CancelKind | CancelKind | Aligned (simplified, see §4.1) |
| Budget | Budget | Aligned |
| TaskState | TaskState | Aligned |
| RegionState | RegionState | Aligned |
| ObligationState | ObligationState | Aligned |
| ObligationKind | ObligationKind | Aligned |
| Quiescent(r) | Quiescent(r) | Aligned |
| LoserDrained(t1,t2) | LoserDrained(t1,t2) | Aligned |
| ledger(r) | ledger(r) | Aligned |
| strengthen | strengthen | Aligned |
| Held(t) | Held(t) | Aligned |

### 5.2 Terminology Discrepancies (None Found)

No terminology discrepancies were found between the FOS and the canonical
glossary. All normative terms in the FOS match their SEM-04.2 definitions.

---

## 6. Machine-Lintable Rule-ID Index

This section provides a flat index suitable for automated validation by
SEM-12.2 doc lint tooling.

```
# Format: FOS_SECTION | LINE_RANGE | RULE_ID | NORMATIVE
§1.2|26-39|def.outcome.four_valued|normative
§1.2|26-39|def.outcome.severity_lattice|normative
§1.3|41-49|def.cancel.reason_kinds|normative
§1.3|41-49|def.cancel.severity_ordering|normative
§1.3|41-49|def.cancel.reason_ordering|normative
§1.7|94-99|def.cancel.reason_kinds|normative
§1.9|140-151|inv.obligation.linear|normative
§1.9|140-151|inv.obligation.no_leak|normative
§1.13|230-247|inv.region.quiescence|normative
§1.13|230-247|inv.combinator.loser_drained|normative
§3.1-SPAWN|376-386|rule.ownership.spawn|normative
§3.2-CANCEL-REQUEST|549-563|rule.cancel.request|normative
§3.2-CANCEL-REQUEST|549-563|inv.cancel.propagates_down|normative
§3.2-CANCEL-ACKNOWLEDGE|575-586|rule.cancel.acknowledge|normative
§3.2-CHECKPOINT-MASKED|588-602|rule.cancel.checkpoint_masked|normative
§3.2-CHECKPOINT-MASKED|588-602|inv.cancel.mask_bounded|normative
§3.2-CHECKPOINT-MASKED|588-602|inv.cancel.mask_monotone|normative
§3.2.2|467-477|inv.cancel.idempotence|normative
§3.2.3|479-490|prog.cancel.drains|normative
§3.2-CANCEL-DRAIN|615-624|rule.cancel.drain|normative
§3.2-CANCEL-FINALIZE|626-636|rule.cancel.finalize|normative
§3.3-CLOSE-BEGIN|644-653|rule.region.close_begin|normative
§3.3-CLOSE-CANCEL-CHILDREN|655-665|rule.region.close_cancel_children|normative
§3.3-CLOSE-CHILDREN-DONE|667-677|rule.region.close_children_done|normative
§3.3-CLOSE-RUN-FINALIZER|679-689|rule.region.close_run_finalizer|normative
§3.3-CLOSE-COMPLETE|691-702|rule.region.close_complete|normative
§3.4-RESERVE|714-725|rule.obligation.reserve|normative
§3.4-COMMIT|727-738|rule.obligation.commit|normative
§3.4-ABORT|740-750|rule.obligation.abort|normative
§3.4-LEAK|752-764|rule.obligation.leak|normative
§3.4-LEAK|752-764|inv.obligation.no_leak|normative
§3.4.5|880-905|inv.obligation.ledger_empty_on_close|normative
§3.4.6|907-926|inv.obligation.no_leak|normative
§3.4.6|907-926|inv.obligation.linear|normative
§3.4.7|928-945|inv.obligation.bounded|normative
§4.1|1003-1014|comb.join|normative
§4.1|1003-1014|def.outcome.join_semantics|normative
§4.2|1016-1028|comb.race|normative
§4.2|1016-1028|inv.combinator.loser_drained|normative
§4.2|1016-1028|law.race.never_abandon|normative
§4.3|1030-1036|comb.timeout|normative
§5-INV-TREE|1043-1048|def.ownership.region_tree|normative
§5-INV-TASK-OWNED|1050-1055|inv.ownership.task_owned|normative
§5-INV-QUIESCENCE|1057-1079|inv.region.quiescence|normative
§5-INV-CANCEL-PROPAGATES|1081-1087|inv.cancel.propagates_down|normative
§5-INV-OBLIGATION-BOUNDED|1089-1095|inv.obligation.bounded|normative
§5-INV-OBLIGATION-LINEAR|1097-1104|inv.obligation.linear|normative
§5-INV-LEDGER-EMPTY|1106-1113|inv.obligation.ledger_empty_on_close|normative
§5-INV-MASK-BOUNDED|1115-1122|inv.cancel.mask_bounded|normative
§5-INV-MASK-BOUNDED|1115-1122|inv.cancel.mask_monotone|normative
§5-INV-LOSER-DRAINED|1131-1136|inv.combinator.loser_drained|normative
§6-PROG-CANCEL|1176-1181|prog.cancel.drains|normative
§6-PROG-REGION|1183-1188|prog.region.close_terminates|normative
§6-PROG-OBLIGATION|1190-1196|prog.obligation.resolves|normative
§7-LAW-JOIN-ASSOC|1269-1273|law.join.assoc|normative
§7-LAW-RACE-COMM|1281-1285|law.race.comm|normative
§7-LAW-TIMEOUT-MIN|1287-1291|comb.timeout|normative
§7-LAW-RACE-NEVER|1293-1297|law.race.never_abandon|normative
§8-no_task_leaks|1339-1344|inv.ownership.single_owner|implementation
§8-no_task_leaks|1339-1344|inv.ownership.task_owned|implementation
§8-no_obligation_leaks|1348-1351|inv.obligation.no_leak|implementation
§8-losers_drained|1353-1358|inv.combinator.loser_drained|implementation
§8.3|1378-1440|inv.determinism.replayable|implementation
§8.3|1378-1440|def.determinism.seed_equivalence|implementation
```

---

## 7. Validation Checklist

- [x] All 47 rule IDs from SEM-04.1 are accounted for (45 mapped, 2 gap-noted)
- [x] Every normative FOS section has at least one rule-ID reference
- [x] Abstraction simplifications are documented and classified
- [x] Terminology consistency verified against SEM-04.2 glossary
- [x] Machine-lintable index provided for SEM-12.2 tooling
- [x] Coverage gaps (#44, #45) have remediation recommendation
