# Transition Rules: Preconditions, Effects, and Observables (SEM-04.3)

**Bead**: `asupersync-3cddg.4.3`
**Parent**: SEM-04 Canonical Semantic Contract (Normative Source)
**Author**: SapphireHill
**Date**: 2026-03-02
**Inputs**:
- `docs/semantic_contract_schema.md` (SEM-04.1, rule-ID namespace)
- `docs/semantic_contract_glossary.md` (SEM-04.2, canonical terms)
- `docs/semantic_ratification.md` (SEM-03.5, ADR decisions)

---

## 1. Purpose

This document encodes every transition rule in the semantic contract as a
formal triple: (Precondition, Action, Effect). Each rule has a stable ID,
explicit guards, observable state changes, and cross-layer citations.

---

## 2. Notation

```
RULE <rule-id>: <name>
  PRE:    <guard condition>
  ACTION: <what happens>
  POST:   <state after transition>
  OBS:    <observable side effects>
  LAYERS: <enforcement layers with citations>
```

- State variables use glossary terms (SEM-04.2).
- `task.state`, `region.state`, `obligation.state` are the primary state fields.
- `↦` denotes state transition.

---

## 3. Ownership and Spawn Rules

### RULE #36: `rule.ownership.spawn`

```
RULE rule.ownership.spawn
  PRE:    region.state = Open
  ACTION: Create task T in region R
  POST:   T.state = Spawned
          T.owner = R
          R.tasks = R.tasks ∪ {T}
  OBS:    Task count in R incremented by 1
  LAYERS: LEAN (proved), TLA (modeled), RT (implemented: region.rs:spawn)
```

**Edge case**: Spawning into a Closing region is a precondition violation.
The RT enforces this at runtime (`region.rs` checks `is_open()`).

---

## 4. Cancellation Protocol Rules

### RULE #1: `rule.cancel.request`

```
RULE rule.cancel.request
  PRE:    task.state = Running
          cancel_kind.severity >= 0
  ACTION: Send cancel signal to task with given CancelKind
  POST:   task.state = CancelRequested
          task.cancel_kind = cancel_kind
  OBS:    Task transitions to CancelRequested
  LAYERS: LEAN (proved), TLA (modeled), RT (implemented: cancel.rs)
```

**Edge case — idempotence**: If task is already CancelRequested, the
`strengthen` operation applies: the higher-severity kind wins.
`strengthen(existing, new) = max_severity(existing, new)`.
Rule ID #5 (`inv.cancel.idempotence`) guarantees this is safe.

### RULE #2: `rule.cancel.acknowledge`

```
RULE rule.cancel.acknowledge
  PRE:    task.state = CancelRequested
          task.mask_depth = 0
  ACTION: Task acknowledges cancellation
  POST:   task.state = CancelAcknowledged
  OBS:    Task stops executing user code, begins cleanup
  LAYERS: LEAN (proved), TLA (modeled), RT (implemented)
```

### RULE #3: `rule.cancel.drain`

```
RULE rule.cancel.drain
  PRE:    task.state = CancelAcknowledged
  ACTION: Task completes cleanup
  POST:   task.state = Finalizing
  OBS:    Task resources released, cleanup callbacks invoked
  LAYERS: LEAN (proved), TLA (modeled), RT (implemented)
```

### RULE #4: `rule.cancel.finalize`

```
RULE rule.cancel.finalize
  PRE:    task.state = Finalizing
  ACTION: Task finalizer runs to completion
  POST:   task.state = Completed
          task.outcome = Cancelled(cancel_kind)
  OBS:    Task produces Cancelled outcome, removed from active set
  LAYERS: LEAN (proved), TLA (modeled), RT (implemented)
```

---

## 5. Masking Rules

### RULE #10: `rule.cancel.checkpoint_masked`

```
RULE rule.cancel.checkpoint_masked
  PRE:    task.state = CancelRequested OR task.state = CancelMasked
          task.mask_depth > 0
  ACTION: Task reaches checkpoint
  POST:   task.mask_depth = task.mask_depth - 1
          IF task.mask_depth = 0:
            task.state = CancelAcknowledged
          ELSE:
            task.state = CancelMasked
  OBS:    Mask depth decremented. Task continues if depth > 0.
  LAYERS: LEAN (proved), TLA (modeled), RT (implemented)
```

**Invariant link**: #11 (`inv.cancel.mask_bounded`) guarantees mask_depth
is bounded. #12 (`inv.cancel.mask_monotone`) guarantees mask_depth is
monotonically non-increasing during cancel processing.

---

## 6. Region Close Ladder

### RULE #22: `rule.region.close_begin`

```
RULE rule.region.close_begin
  PRE:    region.state = Open
  ACTION: Initiate region close
  POST:   region.state = Closing
  OBS:    No new tasks can be spawned. Existing tasks continue.
  LAYERS: LEAN (proved), TLA (modeled), RT (implemented: region.rs)
```

### RULE #23: `rule.region.close_cancel_children`

```
RULE rule.region.close_cancel_children
  PRE:    region.state = Closing
  ACTION: Send CancelKind::ParentCancelled to all non-Completed children
  POST:   ∀ child ∈ region.tasks:
            IF child.state ≠ Completed:
              child.state = CancelRequested
              child.cancel_kind = strengthen(child.cancel_kind, ParentCancelled)
  OBS:    All active children receive cancel signal
  LAYERS: LEAN (proved), TLA (modeled), RT (implemented)
```

### RULE #24: `rule.region.close_children_done`

```
RULE rule.region.close_children_done
  PRE:    region.state = Closing
          ∀ child ∈ region.tasks: child.state = Completed
  ACTION: Transition region past child phase
  POST:   region.state = ChildrenDone
  OBS:    All children completed. Obligations may still be pending.
  LAYERS: LEAN (proved), TLA (modeled), RT (implemented)
```

### RULE #25: `rule.region.close_run_finalizer`

```
RULE rule.region.close_run_finalizer
  PRE:    region.state = ChildrenDone
          region.obligations all resolved
  ACTION: Run region finalizer
  POST:   region.state = Finalizing → Quiescent
  OBS:    Region finalizer executes (cleanup, resource release)
  LAYERS: LEAN (proved, ADR-004). TLA omits this step (documented abstraction).
  NOTE:   TLA+ models close_children_done → Closed directly.
```

### RULE #26: `rule.region.close_complete`

```
RULE rule.region.close_complete
  PRE:    region.state = Quiescent (LEAN) or ChildrenDone (TLA+)
  ACTION: Region reaches terminal state
  POST:   region.state = Closed
  OBS:    Region removed from region tree
  LAYERS: LEAN (proved), TLA (modeled), RT (implemented)
```

---

## 7. Obligation Lifecycle Rules

### RULE #13: `rule.obligation.reserve`

```
RULE rule.obligation.reserve
  PRE:    region.state = Open OR region.state = Closing
          task.state ∈ {Running, CancelRequested, CancelMasked}
  ACTION: Create obligation O in region R
  POST:   O.state = Reserved
          R.obligations = R.obligations ∪ {O}
  OBS:    Obligation ledger incremented
  LAYERS: LEAN (proved), TLA (modeled), RT (implemented: obligation.rs)
```

### RULE #14: `rule.obligation.commit`

```
RULE rule.obligation.commit
  PRE:    obligation.state = Reserved
  ACTION: Fulfill the obligation
  POST:   obligation.state = Committed
  OBS:    Obligation removed from pending set
  LAYERS: LEAN (proved), TLA (modeled), RT (implemented)
```

### RULE #15: `rule.obligation.abort`

```
RULE rule.obligation.abort
  PRE:    obligation.state = Reserved
  ACTION: Cancel the obligation without fulfillment
  POST:   obligation.state = Aborted
  OBS:    Obligation removed from pending set (compensating action may run)
  LAYERS: LEAN (proved), TLA (modeled), RT (implemented)
```

### RULE #16: `rule.obligation.leak`

```
RULE rule.obligation.leak
  PRE:    obligation.state = Reserved
          owning task reaches Completed without resolving obligation
  ACTION: Obligation becomes leaked
  POST:   obligation.state = Leaked
  OBS:    INVARIANT VIOLATION — detected by region close check.
          RT may panic (configurable: panic_on_obligation_leak).
  LAYERS: LEAN (proved), TLA (modeled), RT (implemented: oracle check)
```

**Note**: This rule exists to define the violation condition. The invariant
`inv.obligation.no_leak` (#17) states this transition should never occur
in correct programs.

---

## 8. Determinism Boundary Note (OBS-1)

Per SEM-03.9 observation OBS-1:

**Seed selection is outside the determinism boundary.** The function
`LabConfig::from_time()` (`src/lab/config.rs:185`) uses `SystemTime::now()`
to generate a seed when the user doesn't provide one. This is pre-execution
configuration, not part of the deterministic run.

The determinism guarantee (Rule #46, `inv.determinism.replayable`) states:
> Given the same seed and the same ordered stimuli, LabRuntime produces
> identical outcomes and trace certificates.

Seed generation is an input to this guarantee, not covered by it.

---

## 9. Transition Completeness Matrix

| Rule ID | Domain | Pre | Post | Edge Cases | Layers |
|---------|--------|:---:|:----:|:----------:|:------:|
| #1 | cancel | Running | CancelRequested | Idempotent strengthen | L+T+R |
| #2 | cancel | CancelReq, mask=0 | CancelAck | — | L+T+R |
| #3 | cancel | CancelAck | Finalizing | — | L+T+R |
| #4 | cancel | Finalizing | Completed(Cancelled) | — | L+T+R |
| #10 | cancel | CancelReq/Masked, mask>0 | mask-1 | mask=0 → CancelAck | L+T+R |
| #13 | obligation | Reserved(new) | Reserved | — | L+T+R |
| #14 | obligation | Reserved | Committed | — | L+T+R |
| #15 | obligation | Reserved | Aborted | — | L+T+R |
| #16 | obligation | Reserved + task done | Leaked | VIOLATION | L+T+R |
| #22 | region | Open | Closing | — | L+T+R |
| #23 | region | Closing | children cancelled | Idempotent cancel | L+T+R |
| #24 | region | Closing, all done | ChildrenDone | — | L+T+R |
| #25 | region | ChildrenDone | Quiescent | TLA omits (ADR-004) | L+R |
| #26 | region | Quiescent/ChildDone | Closed | — | L+T+R |
| #36 | ownership | Region Open | Task Spawned | Closed region → reject | L+T+R |

L=LEAN, T=TLA+, R=RT

---

## 10. Downstream Usage

1. **SEM-04.4**: Invariants reference these transitions as the state-change
   operations they constrain.
2. **SEM-08**: Conformance harness generates test cases from PRE/POST pairs.
3. **SEM-10**: CI checker validates that RT code paths match the transition
   rules defined here.
4. **SEM-12**: Verification fabric uses the completeness matrix to ensure
   every rule has at least one test.
