# TLA+ Bounded Model-Check Scenario Configuration (SEM-07.4)

**Bead**: `asupersync-3cddg.7.4`
**Parent**: SEM-07 Projection Track: TLA Model and Invariant Alignment
**Date**: 2026-03-02
**Author**: SapphireHill

---

## 1. Purpose

This document defines the TLC model-check scenario set, parameter bounds, expected invariant outcomes, and reproduction instructions. It ensures model checking is reproducible without hidden environment assumptions.

---

## 2. Model Overview

**Spec file**: `formal/tla/Asupersync.tla`
**Config file**: `formal/tla/Asupersync_MC.cfg`
**Runner script**: `scripts/run_model_check.sh`

The TLA+ model covers three interacting state machines:
1. **Task lifecycle**: Spawned → Running → [CancelRequested → CancelMasked → CancelAcknowledged → Finalizing →] Completed
2. **Region lifecycle**: Open → Closing → ChildrenDone → Finalizing → Quiescent → Closed
3. **Obligation lifecycle**: Reserved → Committed | Aborted | Leaked

---

## 3. Scenario Configurations

### 3.1 Scenario S1: Minimal (Default CI)

**Purpose**: Smallest configuration exercising all state machines.

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| TaskIds | {1, 2} | Two tasks enable cancel interleaving |
| RegionIds | {1, 2} | Two regions enable parent/child nesting |
| ObligationIds | {1} | One obligation exercises full lifecycle |
| RootRegion | 1 | Designates region 1 as root |
| MAX_MASK | 2 | Minimum depth for nested cancel masking |

**Expected outcome**:
- Status: PASS (0 violations)
- Approximate state space: ~14,000 distinct states
- Runtime: < 30 seconds on 4 workers

**Reproduction command**:
```bash
TLC_WORKERS=auto TLC_DEPTH=100 scripts/run_model_check.sh --ci
```

**Output artifacts**:
- `formal/tla/output/result.json` — structured result
- `formal/tla/output/tlc_*.log` — full TLC output log

### 3.2 Scenario S2: Extended Task Set

**Purpose**: Increased task count for richer cancel interleavings.

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| TaskIds | {1, 2, 3} | Three tasks exercise concurrent cancel races |
| RegionIds | {1, 2} | Same two-region nesting |
| ObligationIds | {1} | Same single obligation |
| RootRegion | 1 | Same root |
| MAX_MASK | 2 | Same mask depth |

**Expected outcome**:
- Status: PASS (0 violations)
- Approximate state space: ~100,000-500,000 distinct states
- Runtime: 1-5 minutes on 4 workers

**Reproduction**:
```bash
# Create a modified config file or override constants via TLC CLI:
TLC_CONSTANTS="TaskIds={1,2,3} RegionIds={1,2} ObligationIds={1} RootRegion=1 MAX_MASK=2" \
  scripts/run_model_check.sh
```

### 3.3 Scenario S3: Extended Region Set

**Purpose**: Three-level region nesting for deeper structured concurrency coverage.

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| TaskIds | {1, 2} | Same two tasks |
| RegionIds | {1, 2, 3} | Three regions enable root→child→grandchild |
| ObligationIds | {1} | Same single obligation |
| RootRegion | 1 | Same root |
| MAX_MASK | 2 | Same mask depth |

**Expected outcome**:
- Status: PASS (0 violations)
- Approximate state space: ~50,000-200,000 distinct states
- Runtime: 1-3 minutes on 4 workers

### 3.4 Scenario S4: Extended Obligations

**Purpose**: Multiple obligations to exercise concurrent obligation resolution.

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| TaskIds | {1, 2} | Same two tasks |
| RegionIds | {1, 2} | Same two regions |
| ObligationIds | {1, 2} | Two obligations exercise concurrent lifecycle |
| RootRegion | 1 | Same root |
| MAX_MASK | 2 | Same mask depth |

**Expected outcome**:
- Status: PASS (0 violations)
- Approximate state space: ~50,000-200,000 distinct states
- Runtime: 1-3 minutes on 4 workers

### 3.5 Scenario S5: Deep Mask

**Purpose**: Extended mask depth for nested cancel masking correctness.

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| TaskIds | {1, 2} | Same two tasks |
| RegionIds | {1, 2} | Same two regions |
| ObligationIds | {1} | Same single obligation |
| RootRegion | 1 | Same root |
| MAX_MASK | 3 | Deeper nesting exercises mask overflow bounds |

**Expected outcome**:
- Status: PASS (0 violations)
- Approximate state space: ~20,000-50,000 distinct states
- Runtime: < 1 minute on 4 workers

### 3.6 Scenario S6: Full (Stress)

**Purpose**: Maximum tractable configuration for thorough state-space coverage.

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| TaskIds | {1, 2, 3} | Three tasks |
| RegionIds | {1, 2, 3} | Three regions |
| ObligationIds | {1, 2} | Two obligations |
| RootRegion | 1 | Same root |
| MAX_MASK | 3 | Deep mask |

**Expected outcome**:
- Status: PASS (0 violations)
- Approximate state space: 1M-10M distinct states
- Runtime: 10-60 minutes on 8 workers
- Bounded by 10M state space limit

**Reproduction**:
```bash
TLC_WORKERS=8 TLC_DEPTH=200 \
  TLC_CONSTANTS="TaskIds={1,2,3} RegionIds={1,2,3} ObligationIds={1,2} RootRegion=1 MAX_MASK=3" \
  scripts/run_model_check.sh
```

---

## 4. Checked Invariants

All scenarios check the same invariant set:

| Invariant | Canonical Rule | Type |
|-----------|---------------|------|
| TypeInvariant | (structural) | Safety |
| WellFormedInvariant | (structural) | Safety |
| NoOrphanTasks | #34 (inv.ownership.no_orphan_task) | Safety |
| NoLeakedObligations | #17, #20 (rule.obligation.leak_on_close, rule.obligation.close_gate) | Safety |
| CloseImpliesQuiescent | #27 (rule.region.close_implies_quiescent) | Safety |
| MaskBoundedInvariant | #11 (rule.cancel.mask_bounded) | Safety |
| MaskMonotoneInvariant | #12 (rule.cancel.mask_monotone) | Safety |
| CancelIdempotenceStructural | #5 (rule.cancel.idempotent) | Safety |
| ReplyLinearityInvariant | SINV-1 (spork) | Safety |
| RegistryLeaseInvariant | SINV-3 (spork) | Safety |
| AssumptionEnvelopeInvariant | (model assumption check) | Meta |

### 4.1 Temporal Property (Liveness)

| Property | Canonical Rule | Type |
|----------|---------------|------|
| CancelTerminates | #4 (rule.cancel.eventually_ack) | Liveness |

**Note**: Liveness checking requires `LiveSpec` with `WF_vars(Next)` fairness. This is defined in the spec but not checked in the default `Asupersync_MC.cfg` (safety-only configuration). To check liveness:

```
SPECIFICATION LiveSpec
PROPERTY CancelTerminates
```

Liveness checking significantly increases state space and runtime.

---

## 5. Assumption Envelope

The model operates under bounded assumptions (not safety guarantees):

| Assumption | Bounded By | Impact |
|------------|-----------|--------|
| Finite task set | TaskIds constant | No dynamic task creation |
| Finite region set | RegionIds constant | No dynamic region nesting |
| Finite obligation set | ObligationIds constant | No dynamic obligation spawning |
| Mask depth bounded | MAX_MASK constant | No unbounded cancel mask nesting |
| Single cancel reason | ADR-003 | No cancel kind distinction |
| No wall-clock time | Abstracted | No deadline/timeout modeling |
| No obligation kinds | Abstracted | Only state transitions matter |
| Outcome severity abstracted | ADR-008 | No severity tags |
| Combinator rules not modeled | ADR-005 | Runtime oracle coverage |
| Determinism not modeled | ADR-007 | LabRuntime coverage |

The `AssumptionEnvelopeInvariant` validates that model execution stays within these bounds.

---

## 6. Abstraction Decisions (ADR Cross-Reference)

| ADR | Decision | Scope Impact |
|-----|----------|-------------|
| ADR-003 | Cancel propagation projected to direct children only | TLA models direct-child cancel; Lean is primary assurance |
| ADR-004 | Finalizer body abstracted | State transitions modeled; body content abstracted |
| ADR-005 | Combinator rules not modeled | Runtime law tests provide coverage |
| ADR-007 | Determinism scoped to LabRuntime | Not a TLA concern |
| ADR-008 | Outcome severity abstracted | No severity tags in TLA model |

---

## 7. Reproduction Guide

### 7.1 Prerequisites

- TLC model checker (Java-based)
- `scripts/run_model_check.sh` in PATH or run from project root

### 7.2 Running Scenarios

```bash
# S1 (CI default — runs automatically)
scripts/run_model_check.sh --ci

# Validate result
cat formal/tla/output/result.json

# Run scenario validation tests (no TLC required)
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_semantic_tla_docs cargo test --test semantic_tla_scenarios -- --nocapture
scripts/run_tla_scenarios.sh --json
```

### 7.3 Output Validation

After any TLC run, verify:
1. `formal/tla/output/result.json` has `"status": "pass"` and `"violations": 0`.
2. State space is within expected bounds (see scenario tables above).
3. All listed invariants are in `invariants_checked` array.
4. Log file exists at `formal/tla/output/tlc_*.log`.

### 7.4 Failure Diagnosis

If a scenario fails:
1. Check the TLC log for the counterexample trace.
2. Identify which invariant was violated.
3. Map the invariant to its canonical rule ID (see §4 table).
4. Use `docs/semantic_failure_replay_cookbook.md` §2.4 for TLA+ failure recipes.
5. Run targeted rerun: `scripts/semantic_rerun.sh tla --verbose`.

---

## 8. Scenario Coverage Matrix

| Rule ID | Rule Name | Scenario Coverage |
|:-------:|-----------|:-----------------:|
| #5 | cancel_idempotent | S1-S6 (CancelIdempotenceStructural) |
| #11 | cancel_mask_bounded | S1-S6 (MaskBoundedInvariant) |
| #12 | cancel_mask_monotone | S1-S6 (MaskMonotoneInvariant) |
| #17 | obligation_leak_on_close | S1-S6 (NoLeakedObligations) |
| #20 | obligation_close_gate | S1-S6 (NoLeakedObligations) |
| #27 | region_close_implies_quiescent | S1-S6 (CloseImpliesQuiescent) |
| #34 | ownership_no_orphan_task | S1-S6 (NoOrphanTasks) |

Additional structural coverage:
- Task lifecycle transitions: All scenarios
- Region lifecycle transitions: All scenarios (S3 adds 3-level nesting)
- Obligation lifecycle transitions: S4 adds concurrent obligation coverage
- Cancel mask nesting: S5 adds deeper mask coverage
- Cancel interleaving: S2 adds 3-task race coverage
