# Semantic Inventory: Formal Documentation Layer (DOC)

Status: Active
Program: `asupersync-3cddg` (SEM-02.3)
Parent: SEM-02 Semantic Inventory and Drift Matrix
Author: SapphireHill
Published: 2026-03-02 UTC
Charter Reference: `docs/semantic_harmonization_charter.md`
Schema Reference: `docs/semantic_inventory_schema.md`

## 1. Purpose

This document provides the DOC-layer citation map for the semantic drift
inventory. Every concept from the schema's completeness checklist is mapped to
its precise location in the two canonical specification documents:

| Document | Path | Abbreviation |
|----------|------|-------------|
| Formal Operational Semantics | `asupersync_v4_formal_semantics.md` (root) | FOS |
| Design Bible (Plan v4) | `asupersync_plan_v4.md` | PV4 |

Line numbers are stable as of commit `cd8068f2` (2026-03-02). Citations use the
format `DOC:<file_abbrev>:<line>` per the schema's four-layer citation spec.

## 2. Domain Definitions

| Concept ID | Title | FOS Location | PV4 Location |
|-----------|-------|-------------|-------------|
| `def.id.identifiers` | Identifier domains (TaskId, RegionId, ObligationId) | FOS §1.1 :17 | — |
| `def.outcome.severity_lattice` | Outcomes: Ok \| Err \| Cancelled \| Panicked | FOS §1.2 :26 | PV4 §3.1 :82–92 |
| `def.cancel.reasons` | CancelReasons enumeration | FOS §1.3 :41 | PV4 §I3 :357 |
| `def.budget.semiring` | Budget = (deadline, poll_quota, cost_quota) | FOS §1.4 :51 | PV4 §3 :78 |
| `def.scheduling.task_states` | TaskState: Created → Running → … → Completed | FOS §1.5 :71 | — |
| `def.region.states` | RegionState: Open → Closing → Draining → Finalizing → Closed | FOS §1.6 :83 | PV4 §I2 :349–355 |
| `def.obligation.states` | ObligationState: Reserved → Committed \| Aborted \| Leaked | FOS §1.7 :94 | PV4 §8.1 :541–550 |
| `def.determinism.trace_independence` | Trace labels, independence, true concurrency | FOS §1.8 :101 | PV4 §I6 :369 |
| `def.obligation.linear_discipline` | Linear resources (obligations) as a discipline | FOS §1.9 :140 | PV4 §8 :552–566 |
| `def.time.causal_order` | Distributed time as causal partial order | FOS §1.10 :153 | — |
| `def.scheduling.lanes` | Scheduler lanes: Cancel > Timed > Ready | FOS §1.11 :166 | — |
| `def.scheduling.fairness` | Scheduler fairness bound (implementation model) | FOS §1.12 :187 | — |
| `def.scheduling.derived_predicates` | Derived predicates: Quiescent, ledger, etc. | FOS §1.13 :230 | — |

## 3. Global State

| Concept ID | Title | FOS Location |
|-----------|-------|-------------|
| `def.region.record` | RegionRecord (parent, children, subregions, cancel, finalizers, budget) | FOS §2.1 :265 |
| `def.ownership.task_record` | TaskRecord (region, state, cont, mask, budget) | FOS §2.2 :280 |
| `def.obligation.record` | ObligationRecord (kind, holder, region, state) | FOS §2.3 :292 |
| `def.scheduling.scheduler_state` | SchedulerState (lanes, running, tick_count) | FOS §2.4 :303 |

## 4. Transition Rules

### 4.1 Scheduling

| Concept ID | Title | FOS Location |
|-----------|-------|-------------|
| `tr.scheduling.enqueue` | ENQUEUE — put runnable task into correct lane | FOS §3.0 :348 |
| `tr.scheduling.schedule_step` | SCHEDULE-STEP — pick next runnable task | FOS §3.0 :359 |

### 4.2 Task Lifecycle

| Concept ID | Title | FOS Location | PV4 Location |
|-----------|-------|-------------|-------------|
| `tr.ownership.spawn` | SPAWN — create task in region | FOS §3.1 :376 | PV4 §I1 :345 |
| `tr.scheduling.schedule` | SCHEDULE — task begins running | FOS §3.1 :388 | — |
| `tr.outcome.complete_ok` | COMPLETE-OK — task finishes successfully | FOS §3.1 :399 | — |
| `tr.outcome.complete_err` | COMPLETE-ERR — task finishes with error | FOS §3.1 :414 | — |

### 4.3 Cancellation Protocol

| Concept ID | Title | FOS Location | PV4 Location |
|-----------|-------|-------------|-------------|
| `tr.cancel.request` | CANCEL-REQUEST — initiate cancellation | FOS §3.2 :549 | PV4 §I3 :357–359 |
| `tr.cancel.strengthen` | strengthen — combine cancel reasons (monotone) | FOS §3.2 :565 | — |
| `tr.cancel.acknowledge` | CANCEL-ACKNOWLEDGE — task observes cancel at checkpoint | FOS §3.2 :575 | — |
| `tr.cancel.checkpoint_masked` | CHECKPOINT-MASKED — defer cancellation (bounded masking) | FOS §3.2 :588 | — |
| `tr.cancel.drain` | CANCEL-DRAIN — task finishes cleanup | FOS §3.2 :615 | — |
| `tr.cancel.finalize` | CANCEL-FINALIZE — task runs local finalizers | FOS §3.2 :626 | — |
| `def.cancel.budget_guard` | Budget guards and cleanup budget model | FOS §3.2.1 :437–443 | — |
| `def.cancel.state_machine` | Cancel state machine (Running → CancelRequested → Cancelling → Finalizing → Completed) | FOS §3.2 :429–435 | PV4 §I3 :357 |

### 4.4 Region Lifecycle

| Concept ID | Title | FOS Location | PV4 Location |
|-----------|-------|-------------|-------------|
| `tr.region.close_begin` | CLOSE-BEGIN — region starts closing | FOS §3.3 :644 | PV4 §I2 :349 |
| `tr.region.close_cancel_children` | CLOSE-CANCEL-CHILDREN — cancel remaining children | FOS §3.3 :655 | — |
| `tr.region.close_children_done` | CLOSE-CHILDREN-DONE — all children terminated | FOS §3.3 :667 | — |
| `tr.region.close_run_finalizer` | CLOSE-RUN-FINALIZER — execute finalizer (LIFO) | FOS §3.3 :679 | — |
| `tr.region.close_complete` | CLOSE-COMPLETE — region fully closed | FOS §3.3 :691 | PV4 §I2 :349–355 |

### 4.5 Obligations (Two-Phase Effects)

| Concept ID | Title | FOS Location | PV4 Location |
|-----------|-------|-------------|-------------|
| `tr.obligation.reserve` | RESERVE — acquire obligation (linear resource introduction) | FOS §3.4 :714 | PV4 §8.1 :543–548 |
| `tr.obligation.commit` | COMMIT — fulfill obligation | FOS §3.4 :727 | PV4 §8 :558 |
| `tr.obligation.abort` | ABORT — cancel obligation | FOS §3.4 :740 | PV4 §8 :558 |
| `tr.obligation.leak` | LEAK — obligation lost (error state) | FOS §3.4 :752 | PV4 §8 :559 |

### 4.6 Joining and Waiting

| Concept ID | Title | FOS Location |
|-----------|-------|-------------|
| `tr.combinator.join_block` | JOIN-BLOCK — wait for incomplete task | FOS §3.5 :951 |
| `tr.combinator.join_ready` | JOIN-READY — immediate completion | FOS §3.5 :964 |

### 4.7 Time

| Concept ID | Title | FOS Location |
|-----------|-------|-------------|
| `tr.time.tick` | TICK — advance virtual time | FOS §3.6 :980 |

## 5. Derived Combinators

| Concept ID | Title | FOS Location | PV4 Location |
|-----------|-------|-------------|-------------|
| `dc.combinator.join` | join(f1, f2) — parallel, both complete | FOS §4.1 :1003 | PV4 §1.1-5 :38 |
| `dc.combinator.race` | race(f1, f2) — first wins, loser drained | FOS §4.2 :1016 | PV4 §I5 :365 |
| `dc.combinator.timeout` | timeout(duration, f) — deadline wrapper | FOS §4.3 :1030 | PV4 §1.1-5 :38 |

## 6. Invariants

| Concept ID | Title | FOS Location | PV4 Invariant | PV4 Location |
|-----------|-------|-------------|--------------|-------------|
| `inv.ownership.tree` | INV-TREE: ownership tree structure | FOS §5 :1043 | I1 | PV4 :345 |
| `inv.ownership.task_owned` | INV-TASK-OWNED: every live task has an owner | FOS §5 :1050 | I1 | PV4 :345 |
| `inv.region.quiescence` | INV-QUIESCENCE: closed regions have no live children | FOS §5 :1057 | I2 | PV4 :349 |
| `inv.cancel.propagation` | INV-CANCEL-PROPAGATES: cancel flows downward | FOS §5 :1081 | I3 | PV4 :357 |
| `inv.obligation.bounded` | INV-OBLIGATION-BOUNDED: reserved obligations have live holders | FOS §5 :1089 | I4 | PV4 :361 |
| `inv.obligation.linear` | INV-OBLIGATION-LINEAR: obligations resolve at most once | FOS §5 :1097 | I4 | PV4 :361 |
| `inv.obligation.ledger_close` | INV-LEDGER-EMPTY-ON-CLOSE: closed regions have no reserved obligations | FOS §5 :1106 | I4 | PV4 :361 |
| `inv.cancel.mask_bounded` | INV-MASK-BOUNDED: masking is finite and monotone | FOS §5 :1115 | I3 | PV4 :357 |
| `inv.budget.deadline_monotone` | INV-DEADLINE-MONOTONE: children can't outlive parents | FOS §5 :1124 | — | — |
| `inv.combinator.loser_drained` | INV-LOSER-DRAINED: race losers always complete | FOS §5 :1131 | I5 | PV4 :365 |
| `inv.scheduling.lane_consistent` | INV-SCHED-LANES: runnable tasks are lane-consistent | FOS §5 :1138 | — | — |
| `inv.determinism.replayable` | (implicit via §1.8 trace independence + §8 oracle) | FOS §1.8 :101 | I6 | PV4 :369 |
| `inv.capability.no_ambient` | (implicit via capability scope in §5 Cx) | — | I7 | PV4 :373 |

### Quiescence Proof Sketch

FOS provides a 4-step proof sketch at lines 1066–1079 demonstrating that
`CLOSE-BEGIN → CLOSE-CANCEL-CHILDREN → CLOSE-CHILDREN-DONE → CLOSE-COMPLETE`
is a safety invariant (every `Closed` region satisfies quiescence).

### Compositional Specs (Meta)

FOS §5 :1147 describes separation + rely/guarantee compositional reasoning.

## 7. Progress Properties

| Concept ID | Title | FOS Location |
|-----------|-------|-------------|
| `prog.scheduling.task_terminates` | PROG-TASK: tasks eventually terminate (under fair scheduling) | FOS §6 :1169 |
| `prog.cancel.drain` | PROG-CANCEL: cancelled tasks drain | FOS §6 :1176 |
| `prog.region.close` | PROG-REGION: closing regions close | FOS §6 :1183 |
| `prog.obligation.resolve` | PROG-OBLIGATION: obligations resolve | FOS §6 :1190 |

## 8. Algebraic Laws

| Concept ID | Title | FOS Location | PV4 Location |
|-----------|-------|-------------|-------------|
| `law.combinator.join_assoc` | LAW-JOIN-ASSOC: join(join(a,b),c) ≃ join(a,join(b,c)) | FOS §7 :1269 | — |
| `law.combinator.join_comm` | LAW-JOIN-COMM: join(a,b) ≃ join(b,a) (when policy allows) | FOS §7 :1275 | — |
| `law.combinator.race_comm` | LAW-RACE-COMM: race(a,b) ≃ race(b,a) | FOS §7 :1281 | — |
| `law.combinator.timeout_min` | LAW-TIMEOUT-MIN: timeout(d1,timeout(d2,f)) ≃ timeout(min(d1,d2),f) | FOS §7 :1287 | — |
| `law.combinator.race_never` | LAW-RACE-NEVER: race(f,never) ≃ f | FOS §7 :1293 | — |
| `law.combinator.race_join_dist` | LAW-RACE-JOIN-DIST: race(join(a,b),join(a,c)) ≃ join(a,race(b,c)) | FOS §7 :1299 | — |

### Equivalence Definitions

| Concept ID | Title | FOS Location |
|-----------|-------|-------------|
| `def.determinism.observational_equiv` | ≃ = trace quotient, not raw interleavings | FOS §7.0 :1204 |
| `def.determinism.trace_equiv` | Trace-equivalence for Plan IR (lab oracle target) | FOS §7.1 :1214 |
| `def.determinism.side_condition_schema` | Side-condition schema for rewrite rules | FOS §7.2 :1230 |

## 9. Test Oracle

| Concept ID | Title | FOS Location |
|-----------|-------|-------------|
| `og.determinism.oracle_usage` | Test oracle usage overview | FOS §8 :1325 |
| `og.ownership.no_task_leaks` | Oracle: no_task_leaks | FOS §8 :1339 |
| `og.obligation.no_obligation_leaks` | Oracle: no_obligation_leaks | FOS §8 :1347 |
| `og.combinator.losers_drained` | Oracle: losers_always_drained | FOS §8 :1353 |
| `og.determinism.dpor` | Schedule exploration: optimal DPOR | FOS §8.1 :1360 |
| `og.obligation.abstract_interp` | Static complement: abstract interpretation for obligation leaks | FOS §8.2 :1373 |
| `og.determinism.proof_carrying_trace` | Proof-carrying trace certificate | FOS §8.3 :1378 |

## 10. TLA+ Sketch

| Concept ID | Title | FOS Location |
|-----------|-------|-------------|
| `def.tla.sketch` | TLA+ state-machine sketch of core semantics | FOS §9 :1443 |

## 11. Plan v4 Unique Concepts

These concepts appear in PV4 but have no direct FOS transition-rule counterpart:

| Concept ID | Title | PV4 Location |
|-----------|-------|-------------|
| `def.capability.cx_surface` | Core Cx surface (kernel): identity, budgets, cancellation, scheduling, timers, tracing | PV4 §5.2 :401–408 |
| `def.capability.algebraic_effects` | Cx as algebraic effects + handlers (spec level) | PV4 §5.1 :387–399 |
| `def.capability.cx_laws` | Cx equational laws (trace/checkpoint/sleep commutativity) | PV4 §5.1 :395–399 |
| `def.obligation.session_types` | Session type notation for two-phase send | PV4 §8 :561–566 |
| `def.region.quiescent_reclamation` | Quiescent reclamation invariant | PV4 §10.2 :790 |
| `def.obligation.proof_obligations` | Proof obligations (memory/resource safety) | PV4 §10.5 :821 |
| `def.obligation.graded_types` | Graded/quantitative types for obligations and budgets | PV4 §3 :274 |
| `def.obligation.static_leak_checker` | Static obligation leak checker (prototype) | PV4 §3 :237 |

## 12. Coverage Summary

| Category | Count | FOS Coverage | PV4 Coverage |
|----------|-------|-------------|-------------|
| Domain definitions | 13 | 13/13 | 5/13 |
| Global state | 4 | 4/4 | 0/4 |
| Transition rules | 22 | 22/22 | 6/22 |
| Derived combinators | 3 | 3/3 | 2/3 |
| Invariants | 13 | 11/13 | 7/13 |
| Progress properties | 4 | 4/4 | 0/4 |
| Algebraic laws | 6 | 6/6 | 0/6 |
| Equivalence defs | 3 | 3/3 | 0/3 |
| Test oracle | 7 | 7/7 | 0/7 |
| PV4-unique concepts | 8 | 0/8 | 8/8 |
| **Total** | **83** | **73/83** | **28/83** |

### Charter Invariant Cross-Reference

| Charter Invariant | FOS Invariant(s) | PV4 Invariant |
|-------------------|-----------------|--------------|
| SEM-INV-001 Structured Ownership | INV-TREE :1043, INV-TASK-OWNED :1050 | I1 :345 |
| SEM-INV-002 Region Close = Quiescence | INV-QUIESCENCE :1057 | I2 :349 |
| SEM-INV-003 Cancellation Protocol | INV-CANCEL-PROPAGATES :1081, INV-MASK-BOUNDED :1115 | I3 :357 |
| SEM-INV-004 Loser Drain | INV-LOSER-DRAINED :1131 | I5 :365 |
| SEM-INV-005 No Obligation Leak | INV-OBLIGATION-BOUNDED :1089, INV-OBLIGATION-LINEAR :1097, INV-LEDGER-EMPTY-ON-CLOSE :1106 | I4 :361 |
| SEM-INV-006 No Ambient Authority | (implicit, Cx scoping) | I7 :373 |
| SEM-INV-007 Deterministic Replayability | (§1.8 :101, §8 :1325) | I6 :369 |
