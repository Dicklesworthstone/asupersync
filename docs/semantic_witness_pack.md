# Witness and Counterexample Pack for Disputed Semantics

Status: Active
Program: `asupersync-3cddg` (SEM-03.3)
Parent: SEM-03 Decision Framework and ADR Resolution
Author: SapphireHill
Published: 2026-03-02 UTC
Options Reference: `docs/semantic_divergence_options.md`

## 1. Purpose

This document provides concrete witnesses and counterexamples that demonstrate
the operational consequences of each divergence option. Witnesses make abstract
arguments observable and testable.

## 2. HOTSPOT-1: Loser Drain — Witness Scenarios

### W1.1: Race with Slow Loser (Demonstrates Why Formal Proof Matters)

```
Setup:
  Region R1 (root)
  race(fast_task, slow_task) in R1

Schedule:
  t=0: spawn fast_task (T1), spawn slow_task (T2)
  t=1: T1 completes Ok(42)
  t=2: race detects winner = T1
  t=3: race cancels T2 (loser)
  t=4: T2 enters CancelRequested
  t=5: T2 checkpoint → CancelAcknowledge (mask=0)
  t=6: T2 cleanup_done → Finalizing
  t=7: T2 finalize_done → Completed(Cancelled)
  t=8: race returns Ok(42), both tasks completed ✓

Invariant: LoserDrained(T1, T2) holds — both in Completed state.
```

**Oracle verification**: `src/lab/oracle/loser_drain.rs:155-199` checks
`all_losers_completed_before(race_complete_time)`.

### W1.2: Race with Masked Loser (Edge Case — Deep Masking)

```
Setup:
  race(fast_task, masked_task) where masked_task has mask_depth=3

Schedule:
  t=0: spawn T1, T2
  t=1: T1 completes Ok
  t=2: race cancels T2
  t=3: T2.state = CancelRequested, mask=3
  t=4: checkpoint → CancelMasked (mask=2)
  t=5: checkpoint → CancelMasked (mask=1)
  t=6: checkpoint → CancelMasked (mask=0)
  t=7: checkpoint → CancelAcknowledge
  t=8: cleanup_done → Finalizing
  t=9: finalize_done → Completed(Cancelled)
  t=10: race completes, LoserDrained holds ✓

Bounded by: mask + 3 steps (from cancel_protocol_terminates)
```

**Why Option A (Lean proof) matters**: This scenario works for mask <= 64.
But the proof must hold for ALL mask depths. Runtime testing can only cover
finite cases; the Lean proof covers the inductive argument.

### W1.3: Counterexample — What Happens Without Loser Drain

```
Hypothetical: If race did NOT drain losers:

  t=0: spawn T1, T2 in R1
  t=1: T1 completes Ok
  t=2: race returns Ok, T2 still Running (VIOLATION)
  t=3: R1 begins close
  t=4: is_quiescent() = false (T2 still alive)
  t=5: R1 cannot close → DEADLOCK or PANIC

Consequence: Region close blocks forever. Parent regions block.
Cascading deadlock up the ownership tree.
```

**Evidence**: `src/record/region.rs:690-698` — `is_quiescent()` requires
`tasks.is_empty()`. An undrained loser prevents quiescence.

## 3. HOTSPOT-5: Algebraic Laws — Witness Scenarios

### W5.1: LAW-JOIN-ASSOC Violation Would Cause Optimizer Bug

```
Optimization rewrite:
  join(join(a, b), c) → join(a, join(b, c))

If this law does NOT hold, consider:
  a = task returning Ok(1)
  b = task returning Err("fail")
  c = task returning Ok(3)

  LHS: join(join(a, b), c)
    inner = join(a, b) = Err("fail") (severity join: Err > Ok)
    outer = join(Err("fail"), c) = Err("fail") (Err > Ok)
    Result: Err("fail")

  RHS: join(a, join(b, c))
    inner = join(b, c) = Err("fail") (Err > Ok)
    outer = join(a, Err("fail")) = Err("fail") (Err > Ok)
    Result: Err("fail")

Both sides agree because severity join is associative (max operation).
```

**Proof obligation**: Show that `Outcome.join` is associative. This follows
from the severity lattice being a total order with max as join.

**Code witness**: `src/types/outcome.rs:519-555` (join implementation uses
severity comparison).

### W5.2: LAW-RACE-COMM — Schedule-Dependent but Observationally Equivalent

```
race(a, b) vs race(b, a):

Schedule S1: a finishes first → winner = a
  race(a, b) returns a_result
  race(b, a) returns a_result (same winner regardless of argument order)

Schedule S2: b finishes first → winner = b
  race(a, b) returns b_result
  race(b, a) returns b_result

Commutativity holds: for any fixed schedule, the winner is determined
by completion time, not argument position.
```

**Code witness**: `src/combinator/race.rs:195-219` — RaceAll uses
index-based tracking, winner selected by poll order.

### W5.3: LAW-TIMEOUT-MIN — Nested Timeout Collapse

```
timeout(5s, timeout(3s, f)):
  Inner timeout fires at t=3s.
  Outer timeout would fire at t=5s but inner already triggered.
  Effective deadline = min(5, 3) = 3s.

timeout(min(5, 3), f) = timeout(3s, f):
  Single timeout fires at t=3s.

Both sides produce identical behavior.
```

**Code witness**: `src/combinator/timeout.rs:261-266` (`effective_deadline`
takes min of nested timeouts).

## 4. HOTSPOT-2: CancelReason Granularity — Witness

### W2.1: RT-Only Kind Maps to Canonical Kind

```
RT CancelKind::Deadline (severity level 1)
  → Maps to canonical "Timeout" (severity level 1)
  → strengthen(Deadline, Timeout) = Deadline (same severity, RT-specific)
  → strengthen(Deadline, Shutdown) = Shutdown (Shutdown wins, severity 5)

Monotonicity preserved: RT extension kinds participate in the
same severity lattice as canonical kinds.
```

**Code witness**: `src/types/cancel.rs:340-380` — severity() maps
all 11 RT kinds to 6 levels; levels 0-5 are a total order.

### W2.2: Counterexample — Ordering Violation Would Break Monotonicity

```
Hypothetical: If RT added a kind with severity between existing levels:

  CancelKind::Custom (severity 1.5)
  strengthen(Custom, Timeout) = ???

  If strengthen picked Custom (1.5 > 1): violates idempotence
  If strengthen picked Timeout (1 < 1.5): correct but fragile

Contract must require: extension kinds have integer severity levels
from the existing lattice (0-5). No intermediate levels.
```

## 5. HOTSPOT-6: Capability — Witness

### W6.1: Cx Bypass Would Allow Ambient Authority

```
Hypothetical: If code could call sleep() without Cx:

  async fn malicious_task() {
    // No Cx parameter → ambient authority
    sleep(Duration::from_secs(999999)).await; // blocks scheduler
  }

  // In RT, this is prevented:
  async fn correct_task(cx: &Cx<cap::Timer>) {
    crate::time::sleep(cx.now(), Duration::from_secs(1)).await; // requires Timer capability
  }
```

**Code witness**: `src/cx/cap.rs:76-96` — CapSet generic prevents
constructing a Cx with capabilities the caller doesn't have.
`src/cx/cx.rs:440-445` — `restrict()` enforces SubsetOf at compile time.

### W6.2: `#[allow(unsafe_code)]` Audit Surface

```
Potential bypass vectors:
  1. Direct unsafe block accessing runtime internals
  2. FFI call that performs effects without Cx
  3. Internal crate API that doesn't require Cx parameter

Mitigation: `#![deny(unsafe_code)]` globally. Any unsafe requires
explicit allow annotation (auditable grep target).
```

**Audit command**: `grep -rn '#\[allow(unsafe_code)\]' src/`

## 6. HOTSPOT-7: Determinism — Witness

### W6.1: Seed Equivalence Demonstration

```
Run 1: seed=42, schedule=[T1, T2, T3]
  → outcomes: [Ok(1), Err("fail"), Cancelled(Timeout)]
  → trace hash: 0xABCD1234

Run 2: seed=42, schedule=[T1, T2, T3]
  → outcomes: [Ok(1), Err("fail"), Cancelled(Timeout)]
  → trace hash: 0xABCD1234

Same seed + same ordered stimuli → identical outcomes + trace.
```

**Code witness**: `src/lab/runtime.rs:191` (seed config).
`src/lab/replay.rs:150-171` (ReplayValidation with certificate hashes).

### W6.2: Counterexample — Different Seeds May Produce Different Outcomes

```
Run 1: seed=42 → schedule=[T1, T2, T3] → winner of race = T1
Run 2: seed=99 → schedule=[T2, T1, T3] → winner of race = T2

Different seeds may explore different schedules, yielding different
race winners. This is by design — DPOR explores the schedule space.

Determinism claim: same seed → same outcome. NOT: all seeds → same outcome.
```

## 7. Summary: Evidence Index

| Hotspot | Witnesses | Counterexamples | Code Pointers |
|---------|-----------|----------------|--------------|
| HOTSPOT-1 | W1.1 (normal drain), W1.2 (masked drain) | W1.3 (deadlock without drain) | `loser_drain.rs:155-199`, `region.rs:690-698` |
| HOTSPOT-5 | W5.1 (join assoc), W5.2 (race comm), W5.3 (timeout min) | — | `outcome.rs:519-555`, `race.rs:195-219`, `timeout.rs:261-266` |
| HOTSPOT-2 | W2.1 (kind mapping) | W2.2 (ordering violation) | `cancel.rs:340-380` |
| HOTSPOT-6 | W6.1 (Cx bypass), W6.2 (audit surface) | — | `cap.rs:76-96`, `cx.rs:440-445` |
| HOTSPOT-7 | W7.1 (seed equivalence) | W7.2 (different seeds) | `runtime.rs:191`, `replay.rs:150-171` |
