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
| 5 | `inv.cancel.idempotence` | ALIGNED | `cancel.rs:strengthen()` | unit | ALIGNED | SEM-08.3 |
| 6 | `inv.cancel.propagates_down` | ALIGNED | `state.rs:cancel_sibling_tasks()` | unit | ALIGNED | SEM-08.3 |
| 7 | `def.cancel.reason_kinds` | ALIGNED | `cancel.rs:CancelKind` enum | unit | ALIGNED | SEM-08.5 |
| 8 | `def.cancel.severity_ordering` | ALIGNED | `cancel.rs:severity()` | unit | ALIGNED | None |
| 9 | `prog.cancel.drains` | ALIGNED | cancel protocol impl | oracle | ALIGNED | None |
| 10 | `rule.cancel.checkpoint_masked` | ALIGNED | `cx.rs:checkpoint()` | unit | ALIGNED | SEM-08.3 |
| 11 | `inv.cancel.mask_bounded` | ALIGNED | `cx.rs:masked()` assert | unit | ALIGNED | None |
| 12 | `inv.cancel.mask_monotone` | ALIGNED | `cx.rs:MaskGuard::drop()` | unit | ALIGNED | SEM-08.3 |

**Summary**: 12/12 implemented. 0 gaps.

---

## 4. Obligation Domain (Rules #13-21)

| # | Rule ID | RT Status | Source | Tests | Gap | Action |
|---|---------|-----------|--------|-------|-----|--------|
| 13 | `rule.obligation.reserve` | ALIGNED | `obligation.rs:reserve()` | unit | ALIGNED | None |
| 14 | `rule.obligation.commit` | ALIGNED | `obligation.rs:commit()` | unit | ALIGNED | None |
| 15 | `rule.obligation.abort` | ALIGNED | `obligation.rs:abort()` | unit | ALIGNED | None |
| 16 | `rule.obligation.leak` | ALIGNED | `obligation.rs:leak detection` | unit + oracle | ALIGNED | None |
| 17 | `inv.obligation.no_leak` | ALIGNED | region close check | unit + oracle | ALIGNED | None |
| 18 | `inv.obligation.linear` | ALIGNED | `obligation.rs:ObligationState` | unit | ALIGNED | SEM-08.3 |
| 19 | `inv.obligation.bounded` | ALIGNED | `region.rs:max_obligations` | unit | ALIGNED | SEM-08.5 |
| 20 | `inv.obligation.ledger_empty_on_close` | ALIGNED | `region.rs:is_quiescent()` | unit | ALIGNED | None |
| 21 | `prog.obligation.resolves` | ALIGNED | cancel protocol ensures resolution | oracle | ALIGNED | None |

**Summary**: 9/9 implemented. 0 gaps.

---

## 5. Region Domain (Rules #22-28)

| # | Rule ID | RT Status | Source | Tests | Gap | Action |
|---|---------|-----------|--------|-------|-----|--------|
| 22 | `rule.region.close_begin` | ALIGNED | `region.rs:close()` | unit + e2e | ALIGNED | None |
| 23 | `rule.region.close_cancel_children` | ALIGNED | `region.rs:cancel_children()` | unit + e2e | ALIGNED | None |
| 24 | `rule.region.close_children_done` | ALIGNED | `region.rs:check_quiescence()` | unit | ALIGNED | None |
| 25 | `rule.region.close_run_finalizer` | ALIGNED | `region.rs:Finalizing` + ADR-004 | unit | ALIGNED | SEM-08.3 |
| 26 | `rule.region.close_complete` | ALIGNED | `region.rs:complete()` | unit + e2e | ALIGNED | None |
| 27 | `inv.region.quiescence` | ALIGNED | `region.rs:is_quiescent()` | unit + oracle | ALIGNED | None |
| 28 | `prog.region.close_terminates` | ALIGNED | bounded by cancel drain | oracle | ALIGNED | None |

**Summary**: 7/7 implemented. 0 DOC-GAPs (resolved by SEM-08.3).

---

## 6. Outcome Domain (Rules #29-32)

| # | Rule ID | RT Status | Source | Tests | Gap | Action |
|---|---------|-----------|--------|-------|-----|--------|
| 29 | `def.outcome.four_valued` | ALIGNED | `outcome.rs:Outcome` enum | unit | ALIGNED | None |
| 30 | `def.outcome.severity_lattice` | ALIGNED | `outcome.rs:severity()` | unit | ALIGNED | None |
| 31 | `def.outcome.join_semantics` | ALIGNED | `outcome.rs:join()` + left-bias | unit | ALIGNED | SEM-08.3 |
| 32 | `def.cancel.reason_ordering` | ALIGNED | `cancel.rs:severity()` | unit | ALIGNED | None |

**Summary**: 4/4 implemented. 0 DOC-GAPs (resolved by SEM-08.3).

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
| 40 | `inv.combinator.loser_drained` | ALIGNED | oracle: `loser_drain.rs` | oracle + metamorphic | ALIGNED | Pre-existing metamorphic |
| 41 | `law.race.never_abandon` | ALIGNED | oracle check | property + exhaustive | ALIGNED | SEM-08.5 |
| 42 | `law.join.assoc` | ALIGNED | severity-based join | proptest | ALIGNED | Pre-existing proptest |
| 43 | `law.race.comm` | ALIGNED | index-based winner | proptest | ALIGNED | Pre-existing proptest |

**Summary**: 7/7 implemented. 0 gaps.

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
| ALIGNED | 45 | #1-43, #46-47 |
| DOC-GAP | 0 | — (all 7 resolved by SEM-08.3) |
| TEST-GAP | 0 | — (all 6 resolved by SEM-08.5 + pre-existing) |
| CODE-GAP | 0 | — |
| SCOPE-OUT | 2 | #44, #45 |
| **Total** | **47** | |

### Key Finding

**All 45 RT-applicable rules are fully ALIGNED.** Zero code gaps, zero doc gaps,
zero test gaps. The remaining 2 rules (#44, #45) are SCOPE-OUT (Rust type system).
- DOC-GAPs resolved by SEM-08.3 (2026-03-02): #5, #6, #10, #12, #18, #25, #31.
- TEST-GAPs resolved by SEM-08.5 (2026-03-02): #7, #19, #41.
- TEST-GAPs pre-existing: #40 (metamorphic), #42 (proptest), #43 (proptest).

---

## 12. Risk Assessment

| Gap | Risk | Impact if Unresolved |
|-----|:----:|---------------------|
| ~~DOC-GAP (#5,6,10,12,18,25,31)~~ | ~~LOW~~ | RESOLVED by SEM-08.3 |
| ~~TEST-GAP #7 (canonical-5 mapping)~~ | ~~LOW~~ | RESOLVED by SEM-08.5 |
| ~~TEST-GAP #19 (obligation bounded)~~ | ~~LOW~~ | RESOLVED by SEM-08.5 |
| ~~TEST-GAP #40 (loser drain metamorphic)~~ | ~~MEDIUM~~ | RESOLVED (pre-existing metamorphic) |
| ~~TEST-GAP #41-43 (law property tests)~~ | ~~MEDIUM~~ | RESOLVED by SEM-08.5 + pre-existing proptest |

---

## 13. Required Actions by Priority

### ~~Priority 1: Test Gaps for ADR-001/005~~ (RESOLVED)

- #40: Pre-existing metamorphic tests in `lab/meta/mutation.rs`
- #42: Pre-existing proptest in `tests/algebraic_laws.rs:480`
- #43: Pre-existing proptest in `tests/algebraic_laws.rs:529`
- #41: Property + exhaustive tests added by SEM-08.5 in `tests/algebraic_laws.rs`

### ~~Priority 2: Test Gaps~~ (RESOLVED)

- #7: Unit test added by SEM-08.5 in `types/cancel.rs:canonical_5_mapping_and_extension_policy`
- #19: Unit test added by SEM-08.5 in `record/region.rs:obligation_bounded_by_region_limit`

### ~~Priority 3: Documentation Annotations~~ (RESOLVED)

All 7 DOC-GAPs resolved by SEM-08.3 (2026-03-02):
- #5: `cancel.rs:strengthen()` — `inv.cancel.idempotence` annotation
- #6: `state.rs:cancel_sibling_tasks()` — `inv.cancel.propagates_down` annotation
- #10: `cx.rs:checkpoint()` — `rule.cancel.checkpoint_masked` annotation
- #12: `cx.rs:masked()/MaskGuard::drop()` — `inv.cancel.mask_monotone` annotation
- #18: `obligation.rs:ObligationState` — `inv.obligation.linear` annotation
- #25: `region.rs:Finalizing` — `rule.region.close_run_finalizer` + ADR-004 annotation
- #31: `outcome.rs:join()` — `def.outcome.join_semantics` + left-bias annotation

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
5. **SEM-08.6**: ADR regression tests in `tests/semantic_adr_regression.rs` (10 tests, all 8 ADRs covered).
6. **SEM-12**: Verification fabric uses gap counts as release gate metric.
