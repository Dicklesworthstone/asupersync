# Runtime-vs-Contract Gap Matrix by Rule ID (SEM-08.1)

**Bead**: `asupersync-3cddg.8.1`
**Parent**: SEM-08 Runtime Alignment and Differential Conformance
**Author**: SapphireHill
**Date**: 2026-03-02
**Inputs**:
- `docs/semantic_contract_schema.md` (SEM-04.1, 47 rule IDs)
- `docs/semantic_contract_transitions.md` (SEM-04.3, PRE/POST specs)
- `docs/semantic_contract_invariants.md` (SEM-04.4, checkable clauses)

---

## 1. Purpose

This document maps each of the 47 canonical contract rules to its runtime
implementation status. Each entry shows: implementation file, test coverage,
gap classification, and required action.

---

## 2. Gap Classification

| Class | Meaning | Action Required |
|-------|---------|:---------------:|
| **ALIGNED** | RT behavior matches contract. Tests exist. | None |
| **TEST-GAP** | RT behavior correct, but no targeted contract test. | Add test |
| **DOC-GAP** | RT behavior correct, but no rule-ID annotation. | Add annotation |
| **CODE-GAP** | RT behavior differs from contract or is missing. | Code change |
| **SCOPE-OUT** | Rule not applicable to RT (type-system or formal only). | None |

---

## 3. Cancellation Domain (Rules #1-12)

| # | Rule ID | RT Status | Source | Tests | Gap | Action |
|---|---------|-----------|--------|-------|-----|--------|
| 1 | `rule.cancel.request` | ALIGNED | `cancel.rs:request_cancel()` | unit + oracle | ALIGNED | None |
| 2 | `rule.cancel.acknowledge` | ALIGNED | `cancel.rs:acknowledge()` | unit + oracle | ALIGNED | None |
| 3 | `rule.cancel.drain` | ALIGNED | `cancel.rs:drain_complete()` | unit + oracle | ALIGNED | None |
| 4 | `rule.cancel.finalize` | ALIGNED | `cancel.rs:finalize()` | unit + oracle | ALIGNED | None |
| 5 | `inv.cancel.idempotence` | ALIGNED | `cancel.rs:strengthen()` | unit | DOC-GAP | Add rule-ID comment |
| 6 | `inv.cancel.propagates_down` | ALIGNED | `region.rs:cancel_children()` | unit | DOC-GAP | Add rule-ID comment |
| 7 | `def.cancel.reason_kinds` | ALIGNED | `cancel.rs:CancelKind` enum | — | TEST-GAP | Add canonical-5 mapping test |
| 8 | `def.cancel.severity_ordering` | ALIGNED | `cancel.rs:severity()` | unit | ALIGNED | None |
| 9 | `prog.cancel.drains` | ALIGNED | cancel protocol impl | oracle | ALIGNED | None |
| 10 | `rule.cancel.checkpoint_masked` | ALIGNED | `cancel.rs:checkpoint()` | unit | DOC-GAP | Add rule-ID comment |
| 11 | `inv.cancel.mask_bounded` | ALIGNED | mask_depth is u32 | unit | ALIGNED | None |
| 12 | `inv.cancel.mask_monotone` | ALIGNED | checkpoint decrements only | unit | DOC-GAP | Add rule-ID comment |

**Summary**: 12/12 implemented. 4 DOC-GAPs (missing rule-ID annotations), 1 TEST-GAP.

---

## 4. Obligation Domain (Rules #13-21)

| # | Rule ID | RT Status | Source | Tests | Gap | Action |
|---|---------|-----------|--------|-------|-----|--------|
| 13 | `rule.obligation.reserve` | ALIGNED | `obligation.rs:reserve()` | unit | ALIGNED | None |
| 14 | `rule.obligation.commit` | ALIGNED | `obligation.rs:commit()` | unit | ALIGNED | None |
| 15 | `rule.obligation.abort` | ALIGNED | `obligation.rs:abort()` | unit | ALIGNED | None |
| 16 | `rule.obligation.leak` | ALIGNED | `obligation.rs:leak detection` | unit + oracle | ALIGNED | None |
| 17 | `inv.obligation.no_leak` | ALIGNED | region close check | unit + oracle | ALIGNED | None |
| 18 | `inv.obligation.linear` | ALIGNED | state machine enforced | unit | DOC-GAP | Add rule-ID comment |
| 19 | `inv.obligation.bounded` | ALIGNED | bounded by region tasks | — | TEST-GAP | Add bounded count test |
| 20 | `inv.obligation.ledger_empty_on_close` | ALIGNED | `region.rs:is_quiescent()` | unit | ALIGNED | None |
| 21 | `prog.obligation.resolves` | ALIGNED | cancel protocol ensures resolution | oracle | ALIGNED | None |

**Summary**: 9/9 implemented. 1 DOC-GAP, 1 TEST-GAP.

---

## 5. Region Domain (Rules #22-28)

| # | Rule ID | RT Status | Source | Tests | Gap | Action |
|---|---------|-----------|--------|-------|-----|--------|
| 22 | `rule.region.close_begin` | ALIGNED | `region.rs:close()` | unit + e2e | ALIGNED | None |
| 23 | `rule.region.close_cancel_children` | ALIGNED | `region.rs:cancel_children()` | unit + e2e | ALIGNED | None |
| 24 | `rule.region.close_children_done` | ALIGNED | `region.rs:check_quiescence()` | unit | ALIGNED | None |
| 25 | `rule.region.close_run_finalizer` | ALIGNED | `region.rs:run_finalizer()` | unit | DOC-GAP | Add rule-ID + ADR-004 ref |
| 26 | `rule.region.close_complete` | ALIGNED | `region.rs:complete()` | unit + e2e | ALIGNED | None |
| 27 | `inv.region.quiescence` | ALIGNED | `region.rs:is_quiescent()` | unit + oracle | ALIGNED | None |
| 28 | `prog.region.close_terminates` | ALIGNED | bounded by cancel drain | oracle | ALIGNED | None |

**Summary**: 7/7 implemented. 1 DOC-GAP.

---

## 6. Outcome Domain (Rules #29-32)

| # | Rule ID | RT Status | Source | Tests | Gap | Action |
|---|---------|-----------|--------|-------|-----|--------|
| 29 | `def.outcome.four_valued` | ALIGNED | `outcome.rs:Outcome` enum | unit | ALIGNED | None |
| 30 | `def.outcome.severity_lattice` | ALIGNED | `outcome.rs:severity()` | unit | ALIGNED | None |
| 31 | `def.outcome.join_semantics` | ALIGNED | `outcome.rs:join()` | unit | DOC-GAP | Add left-bias note |
| 32 | `def.cancel.reason_ordering` | ALIGNED | `cancel.rs:severity()` | unit | ALIGNED | None |

**Summary**: 4/4 implemented. 1 DOC-GAP.

---

## 7. Ownership Domain (Rules #33-36)

| # | Rule ID | RT Status | Source | Tests | Gap | Action |
|---|---------|-----------|--------|-------|-----|--------|
| 33 | `inv.ownership.single_owner` | ALIGNED | `region.rs:TaskEntry.region_id` | unit | ALIGNED | None |
| 34 | `inv.ownership.task_owned` | ALIGNED | spawn requires RegionHandle | unit | ALIGNED | None |
| 35 | `def.ownership.region_tree` | ALIGNED | `region.rs:RegionTree` | unit | ALIGNED | None |
| 36 | `rule.ownership.spawn` | ALIGNED | `region.rs:spawn()` | unit + e2e | ALIGNED | None |

**Summary**: 4/4 implemented. 0 gaps.

---

## 8. Combinator Domain (Rules #37-43)

| # | Rule ID | RT Status | Source | Tests | Gap | Action |
|---|---------|-----------|--------|-------|-----|--------|
| 37 | `comb.join` | ALIGNED | `combinator/join.rs:JoinAll` | unit + e2e | ALIGNED | None |
| 38 | `comb.race` | ALIGNED | `combinator/race.rs:RaceAll` | unit + e2e | ALIGNED | None |
| 39 | `comb.timeout` | ALIGNED | `combinator/timeout.rs` | unit + e2e | ALIGNED | None |
| 40 | `inv.combinator.loser_drained` | ALIGNED | oracle: `loser_drain.rs` | oracle | TEST-GAP | Add metamorphic tests (ADR-001) |
| 41 | `law.race.never_abandon` | ALIGNED | oracle check | oracle | TEST-GAP | Add property test |
| 42 | `law.join.assoc` | ALIGNED | severity-based join | — | TEST-GAP | Add property test for associativity |
| 43 | `law.race.comm` | ALIGNED | index-based winner | — | TEST-GAP | Add property test for commutativity |

**Summary**: 7/7 implemented. 4 TEST-GAPs (laws need property tests, drain needs metamorphic).

---

## 9. Capability Domain (Rules #44-45)

| # | Rule ID | RT Status | Source | Tests | Gap | Action |
|---|---------|-----------|--------|-------|-----|--------|
| 44 | `inv.capability.no_ambient` | SCOPE-OUT | Rust type system | compile-time | SCOPE-OUT | CI audit gate only |
| 45 | `def.capability.cx_scope` | SCOPE-OUT | `cx/cx.rs:Cx<C>` | compile-time | SCOPE-OUT | CI audit gate only |

**Summary**: 2/2 enforced by type system. No RT gaps.

---

## 10. Determinism Domain (Rules #46-47)

| # | Rule ID | RT Status | Source | Tests | Gap | Action |
|---|---------|-----------|--------|-------|-----|--------|
| 46 | `inv.determinism.replayable` | ALIGNED | `lab/runtime.rs` + `lab/replay.rs` | replay suite | ALIGNED | None |
| 47 | `def.determinism.seed_equivalence` | ALIGNED | `lab/config.rs:seed` | replay suite | ALIGNED | None |

**Summary**: 2/2 implemented. 0 gaps.

---

## 11. Gap Summary

| Gap Class | Count | Rules |
|-----------|:-----:|-------|
| ALIGNED | 32 | #1-4, #8-9, #11, #13-17, #20-24, #26-30, #32-39, #46-47 |
| DOC-GAP | 7 | #5, #6, #10, #12, #18, #25, #31 |
| TEST-GAP | 6 | #7, #19, #40, #41, #42, #43 |
| CODE-GAP | 0 | — |
| SCOPE-OUT | 2 | #44, #45 |
| **Total** | **47** | |

### Key Finding

**Zero code gaps.** The RT implementation already matches all 47 contract rules.
The gaps are documentation annotations (7 rules) and test coverage (6 rules).
No code-level changes are required for semantic alignment.

---

## 12. Risk Assessment

| Gap | Risk | Impact if Unresolved |
|-----|:----:|---------------------|
| DOC-GAP (#5,6,10,12,18,25,31) | LOW | Traceability loss; harder CI auditing |
| TEST-GAP #7 (canonical-5 mapping) | LOW | Extension policy violations undetected |
| TEST-GAP #19 (obligation bounded) | LOW | Unbounded obligation count undetected |
| TEST-GAP #40 (loser drain metamorphic) | MEDIUM | ADR-001 oracle coverage insufficient |
| TEST-GAP #41-43 (law property tests) | MEDIUM | ADR-005 coverage gap before Lean proofs |

---

## 13. Required Actions by Priority

### Priority 1: Test Gaps for ADR-001/005 (MEDIUM risk)

| Action | Rule IDs | Type | Estimate |
|--------|----------|------|:--------:|
| Add metamorphic tests for loser drain | #40 | Metamorphic | 2h |
| Add property test for join associativity | #42 | Property | 1h |
| Add property test for race commutativity | #43 | Property | 1h |
| Add property test for race never-abandon | #41 | Property | 1h |

### Priority 2: Test Gaps (LOW risk)

| Action | Rule IDs | Type | Estimate |
|--------|----------|------|:--------:|
| Add canonical-5 mapping test | #7 | Unit | 30m |
| Add obligation bounded count test | #19 | Unit | 30m |

### Priority 3: Documentation Annotations

| Action | Rule IDs | Estimate |
|--------|----------|:--------:|
| Add rule-ID comments to cancel module | #5, #6, #10, #12 | 1h |
| Add rule-ID comment to obligation linear | #18 | 15m |
| Add rule-ID + ADR-004 ref to finalizer | #25 | 15m |
| Add left-bias note to outcome join | #31 | 15m |

### CI Gate Actions

| Action | Rule IDs | Estimate |
|--------|----------|:--------:|
| Add `grep '#[allow(unsafe_code)]' src/cx/` CI check | #44, #45 | 30m |
| Add replay failure rate threshold CI check | #46, #47 | 30m |

---

## 14. Downstream Usage

1. **SEM-08.2**: Runtime patches address any CODE-GAPs (currently: none).
2. **SEM-08.3**: Rule-ID annotations address DOC-GAPs.
3. **SEM-08.4**: Conformance harness uses this matrix as test target list.
4. **SEM-08.5**: Property/metamorphic tests address TEST-GAPs for laws.
5. **SEM-08.6**: Regression tests target ADR-001/005 coverage gaps.
6. **SEM-12**: Verification fabric uses gap counts as release gate metric.
