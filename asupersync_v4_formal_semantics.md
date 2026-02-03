# Asupersync 4.0: Operational Semantics (Plan v4 Edition)

**Version:** `v4.0.0` (stable semantics tag)

## A Practical Small-Step Semantics for Implementation and Testing

This document defines the operational semantics of Asupersync 4.0 in a style suitable for:
1. Implementing the lab runtime exactly
2. Writing property-based test oracles
3. Translation to TLA+ for model checking
4. Reasoning about correctness without excessive formalism

---

## 1. Domains

### 1.1 Identifiers

```
r ∈ RegionId    = ℕ
t ∈ TaskId      = ℕ
o ∈ ObligationId = ℕ
τ ∈ Time        = ℕ (discrete ticks in lab; real instants in prod)
```

### 1.2 Outcomes

Four-valued, severity-ordered:

```
Outcome ::= Ok(value)
          | Err(error)
          | Cancelled(reason)
          | Panicked(payload)

Severity: Ok < Err < Cancelled < Panicked
```

When combining outcomes, **worst wins** (monotone aggregation).

### 1.3 Cancel Reasons

```
CancelReason ::= { kind: CancelKind, message: Option<String> }

CancelKind ::= User | Timeout | FailFast | ParentCancelled | Shutdown

Severity: User < Timeout < FailFast < ParentCancelled < Shutdown
```

### 1.4 Budgets

Product semiring with componentwise min (except priority: max):

```
Budget ::= {
  deadline: Option<Time>,
  poll_quota: ℕ,
  cost_quota: Option<ℕ>,
  priority: ℕ
}

combine(b1, b2) = {
  deadline:   min_opt(b1.deadline, b2.deadline),
  poll_quota: min(b1.poll_quota, b2.poll_quota),
  cost_quota: min_opt(b1.cost_quota, b2.cost_quota),
  priority:   max(b1.priority, b2.priority)
}
```

### 1.5 Task States

```
TaskState ::= 
  | Created
  | Running
  | CancelRequested(reason, cleanup_budget)
  | Cancelling(cleanup_budget)
  | Finalizing(cleanup_budget)
  | Completed(outcome)
```

### 1.6 Region States

```
RegionState ::=
  | Open
  | Closing
  | Draining
  | Finalizing
  | Closed(outcome)
```

### 1.7 Obligation States

```
ObligationState ::= Reserved | Committed | Aborted | Leaked
ObligationKind  ::= SendPermit | Ack | Lease | IoOp
```

### 1.8 Trace labels, independence, and true concurrency

Small-step semantics is written as interleavings, but Asupersync’s *spec* is intentionally stronger:
many interleavings are observationally the same because they differ only by reordering **independent** actions.

We model this with a standard trace theory.

#### Labels and traces

Let `Label` be the set of observable labels already used below (`spawn`, `complete`, `cancel`, `reserve`, `commit`, …).
An execution produces a trace by projecting out silent steps:

```
trace(Σ —[l1]→ … —[ln]→ Σn) = [ li | li ≠ τ ]
```

#### Independence relation

Define an independence relation `I ⊆ Label × Label` (symmetric, irreflexive) that encodes commutation:
two labels are independent if swapping them cannot change the observable meaning (outcomes, traces up to renaming, obligation resolution).
Examples (informal):

* actions in different regions often commute,
* `reserve(o)` never commutes with `commit(o)` or `abort(o)`,
* `cancel(r,_)` does not commute with `spawn(r,_)` (because close/cancel forbids new children).

#### Mazurkiewicz traces (equivalence classes)

Two traces are equivalent (`~`) when they are related by a finite sequence of adjacent swaps of independent actions:

```
… a b …  ~  … b a …   whenever (a,b) ∈ I
```

Asupersync’s “observational equivalence” (`≃`) is intended to respect this quotient:
we care about equivalence classes (partial orders), not raw interleavings.

This is the semantic backbone for “optimal DPOR” and stable trace replay (§8).

### 1.9 Linear resources (obligations) as a discipline

Obligations are *linear* resources: each reserved obligation must be resolved exactly once.

Concretely, define the set of currently-held obligations for a task:

```
Held(t) = { o ∈ dom(O) | O[o].holder = t ∧ O[o].state = Reserved }
```

The intended rule is: reaching `Completed(_)` with `Held(t) ≠ ∅` is a semantic error (a leak).
The operational rule `LEAK` below is the runtime witness of this linearity violation.

### 1.10 (Optional extension) Distributed time as causal partial order

For distributed structured concurrency, traces should be **causally ordered**, not totally ordered.
A standard representation is a vector clock:

```
VC : NodeId → ℕ
e1 → e2  iff  VC(e1) < VC(e2)   (componentwise)
e1 ∥ e2  iff  neither VC(e1) ≤ VC(e2) nor VC(e2) ≤ VC(e1)
```

This lets remote traces remain honest: concurrent events stay unordered until causality forces an order.

### 1.11 Scheduler lanes (priority model)

Asupersync scheduling is modeled as **three priority lanes**:

```
Lane ::= Cancel | Timed | Ready
Priority order: Cancel > Timed > Ready
```

The lane selection function is:

```
lane(t) =
  Cancel  if T[t].state ∈ {CancelRequested, Cancelling, Finalizing}
  Timed   if deadline(T[t].region) is defined
  Ready   otherwise
```

Timed lane ordering is Earliest-Deadline-First (EDF). When deadlines tie,
deterministic task-id ordering breaks ties.

---

## 2. Global State

The machine state Σ consists of:

```
Σ = ⟨R, T, O, S, τ_now⟩

R: RegionId → RegionRecord
T: TaskId → TaskRecord
O: ObligationId → ObligationRecord
S: SchedulerState
τ_now: Time
```

### 2.1 RegionRecord

```
RegionRecord = {
  parent:      Option<RegionId>,
  children:    Set<TaskId>,          // Owned tasks
  subregions:  Set<RegionId>,        // Child regions
  state:       RegionState,
  budget:      Budget,
  cancel:      Option<CancelReason>,
  finalizers:  List<Finalizer>,      // LIFO
  policy:      Policy
}
```

### 2.2 TaskRecord

```
TaskRecord = {
  region:   RegionId,
  state:    TaskState,
  cont:     Continuation,            // Abstract: remaining work
  mask:     ℕ,                       // Remaining cancellation deferrals
  waiters:  Set<TaskId>              // Tasks awaiting this one
}
```

### 2.3 ObligationRecord

```
ObligationRecord = {
  kind:    ObligationKind,
  holder:  TaskId,
  region:  RegionId,
  state:   ObligationState
}
```

### 2.4 SchedulerState

```
SchedulerState = {
  cancel_lane: Queue<TaskId>,
  timed_lane:  EDFQueue<TaskId>,
  ready_lane:  Queue<TaskId>
}
```

Queues are abstract; the only requirements are:

- Tasks appear at most once across all lanes.
- `cancel_lane` has strict priority over `timed_lane`, which has strict priority over `ready_lane`.
- `timed_lane` is ordered by deadline, with deterministic tie-breaking.

---

## 3. Transition Rules

Transitions have the form: `Σ —[label]→ Σ'`

Labels track observable actions for tracing:
```
label ::= τ                        // Silent/internal
        | spawn(r, t)
        | complete(t, outcome)
        | cancel(r, reason)
        | reserve(o)
        | commit(o)
        | abort(o)
        | leak(o)                  // Error case
        | defer(r, f)
        | finalize(r, f)
        | close(r, outcome)
        | tick
```

---

### 3.0 Scheduling

Scheduling is factored from task semantics to highlight the priority lanes.
Task readiness is abstracted by `is_ready(t)` (e.g., a waker fires or a poll yields).

#### ENQUEUE — Put a runnable task into the correct lane

```
Preconditions:
  is_ready(t)
  T[t].state ∈ {Created, Running, CancelRequested(_), Cancelling(_), Finalizing(_)}

Σ —[τ]→ Σ' where:
  S'[lane(t)].push(t)
```

#### SCHEDULE-STEP — Pick next runnable task

```
Preconditions:
  S.cancel_lane ∪ S.timed_lane ∪ S.ready_lane ≠ ∅

Σ —[τ]→ Σ' where:
  t = pick_next(S)
  // pick_next obeys lane priority and EDF within timed lane
  // t is polled once; it may complete or yield
```

If `t` yields, it is re-enqueued via `ENQUEUE`. If `t` completes, it is not re-enqueued.
This captures the lane priority model without committing to a specific queue implementation.

### 3.1 Task Lifecycle

#### SPAWN — Create task in region

```
Preconditions:
  R[r].state = Open
  t ∉ dom(T)

Σ —[spawn(r,t)]→ Σ' where:
  T'[t] = { region: r, state: Created, cont: body, mask: 0, waiters: ∅ }
  R'[r].children = R[r].children ∪ {t}
```

#### SCHEDULE — Task begins running

```
Preconditions:
  T[t].state = Created
  R[T[t].region].state ∈ {Open, Closing, Draining}

Σ —[τ]→ Σ' where:
  T'[t].state = Running
```

#### COMPLETE-OK — Task finishes successfully

```
Preconditions:
  T[t].state = Running
  T[t].cont = done(v)

Σ —[complete(t, Ok(v))]→ Σ' where:
  T'[t].state = Completed(Ok(v))
  // Wake waiters
  ∀w ∈ T[t].waiters: T'[w].cont = resume(T[w].cont, Ok(v))
  // Apply policy
  apply_policy(T[t].region, t, Ok(v))
```

#### COMPLETE-ERR — Task finishes with error

```
Preconditions:
  T[t].state = Running
  T[t].cont = error(e)

Σ —[complete(t, Err(e))]→ Σ' where:
  T'[t].state = Completed(Err(e))
  ∀w ∈ T[t].waiters: T'[w].cont = resume(T[w].cont, Err(e))
  apply_policy(T[t].region, t, Err(e))
```

---

### 3.2 Cancellation Protocol

Cancellation flows through a well-defined state machine:

```
Running → CancelRequested → Cancelling → Finalizing → Completed(Cancelled)
```

#### CANCEL-REQUEST — Initiate cancellation

```
Σ —[cancel(r, reason)]→ Σ' where:
  // Strengthen or set cancel reason
  R'[r].cancel = strengthen(R[r].cancel, reason)
  
  // Propagate to all descendant regions
  ∀r' ∈ descendants(r):
    R'[r'].cancel = strengthen(R[r'].cancel, ParentCancelled)
  
  // Mark tasks for cancellation
  ∀t ∈ R[r].children where T[t].state ∈ {Created, Running}:
    T'[t].state = CancelRequested(reason, cleanup_budget(reason))
```

#### strengthen — Combine cancel reasons

```
strengthen(None, new) = Some(new)
strengthen(Some(old), new) = Some({
  kind: max(old.kind, new.kind),      // More severe wins
  // Tighter deadline wins
})
```

#### CANCEL-ACKNOWLEDGE — Task observes cancellation at checkpoint

```
Preconditions:
  T[t].state = CancelRequested(reason, budget)
  T[t].mask = 0
  T[t].cont = await(checkpoint)

Σ —[τ]→ Σ' where:
  T'[t].state = Cancelling(budget)
  T'[t].cont = resume(T[t].cont, Cancelled(reason))
```

#### CHECKPOINT-MASKED — Defer cancellation (bounded masking)

```
Preconditions:
  T[t].state = CancelRequested(reason, budget)
  T[t].mask > 0
  T[t].cont = await(checkpoint)

Σ —[τ]→ Σ' where:
  T'[t].mask = T[t].mask - 1
  T'[t].cont = resume(T[t].cont, Ok(()))
```

Masking is never “free”: it consumes a finite mask budget.
Primitives that use masking must account for it explicitly (via budgets/policy) so cancellation has a quantitative bound.

#### Game-theoretic view (spec): cancellation as an adversarial, budgeted protocol

For reasoning (and eventually mechanized proofs), it is useful to interpret cancellation as a two-player, quantitative game:

* **System** chooses which runnable task to schedule and when to request cancellation.
* **Task** chooses how it responds at checkpoints: acknowledge, or spend limited mask budget to defer.

Winning condition: System wins iff every cancellation request is eventually acknowledged and the task reaches a terminal state within the provided budget under fairness assumptions.

This perspective turns “bounded masking” into a mathematical promise: if every primitive has a known bound on its cancellation deferrals (mask depth) and checkpoint frequency, then there exists a computable budget that makes System’s winning strategy guaranteed.

#### CANCEL-DRAIN — Task finishes cleanup

```
Preconditions:
  T[t].state = Cancelling(_)
  T[t].cont ∈ {done(_), cancelled}

Σ —[τ]→ Σ' where:
  T'[t].state = Finalizing(default_finalizer_budget)
```

#### CANCEL-FINALIZE — Task runs local finalizers

```
Preconditions:
  T[t].state = Finalizing(_)
  // All task-local cleanup done

Σ —[complete(t, Cancelled(reason))]→ Σ' where:
  T'[t].state = Completed(Cancelled(reason))
  ∀w ∈ T[t].waiters: T'[w].cont = resume(T[w].cont, Cancelled(reason))
```

---

### 3.3 Region Lifecycle

Regions close in phases: Closing → Draining → Finalizing → Closed

#### CLOSE-BEGIN — Region starts closing

```
Preconditions:
  R[r].state = Open
  // Region body completed or explicit close

Σ —[τ]→ Σ' where:
  R'[r].state = Closing
```

#### CLOSE-CANCEL-CHILDREN — Cancel remaining children

```
Preconditions:
  R[r].state = Closing
  ∃t ∈ R[r].children: T[t].state ∉ {Completed(_)}

Σ —[cancel(r, implicit_close)]→ Σ' where:
  R'[r].state = Draining
  // CANCEL-REQUEST applied to all non-complete children
```

#### CLOSE-CHILDREN-DONE — All children terminated

```
Preconditions:
  R[r].state = Draining
  ∀t ∈ R[r].children: T[t].state = Completed(_)
  ∀r' ∈ R[r].subregions: R[r'].state = Closed(_)

Σ —[τ]→ Σ' where:
  R'[r].state = Finalizing
```

#### CLOSE-RUN-FINALIZER — Execute finalizer (LIFO)

```
Preconditions:
  R[r].state = Finalizing
  R[r].finalizers = f :: rest

Σ —[finalize(r, f)]→ Σ' where:
  // Run f as masked task
  R'[r].finalizers = rest
```

#### CLOSE-COMPLETE — Region fully closed

```
Preconditions:
  R[r].state = Finalizing
  R[r].finalizers = []
  // All obligations in region resolved

Σ —[close(r, outcome)]→ Σ' where:
  outcome = R[r].policy.aggregate(child_outcomes, finalizer_outcomes)
  R'[r].state = Closed(outcome)
```

---

### 3.4 Obligations (Two-Phase Effects)

The obligation registry gives operational teeth to the linear resource discipline (§1.9):

* `reserve` introduces a linear resource (a `Reserved` obligation),
* `commit/abort` resolve it,
* `leak` is the explicit error transition when a task terminates while still holding one.

#### RESERVE — Acquire obligation

```
Preconditions:
  T[t].state = Running
  T[t].cont = await(reserve(...))
  o ∉ dom(O)

Σ —[reserve(o)]→ Σ' where:
  O'[o] = { kind: k, holder: t, region: T[t].region, state: Reserved }
  T'[t].cont = resume(T[t].cont, Ok(o))
```

#### COMMIT — Fulfill obligation

```
Preconditions:
  O[o].state = Reserved
  O[o].holder = t
  T[t].cont = do(commit(o, _))

Σ —[commit(o)]→ Σ' where:
  O'[o].state = Committed
  // Effect takes place (message sent, etc.)
```

#### ABORT — Cancel obligation

```
Preconditions:
  O[o].state = Reserved
  // Either explicit abort or drop

Σ —[abort(o)]→ Σ' where:
  O'[o].state = Aborted
  // Capacity released, no effect occurred
```

#### LEAK — Obligation lost (error state)

```
Preconditions:
  O[o].state = Reserved
  T[O[o].holder].state = Completed(_)
  // Obligation not committed or aborted

Σ —[leak(o)]→ Σ' where:
  O'[o].state = Leaked
  // In lab: panic or record error
  // In prod: log, recover, continue
```

#### Obligation accounting (Petri net / VASS view)

For verification, it is often convenient to project the obligation registry into a *marking* (token counts):

```
marking(r, k) = |{ o ∈ dom(O) | O[o].region = r ∧ O[o].kind = k ∧ O[o].state = Reserved }|
```

Then:

* `reserve(kind=k)` increments `marking(r,k)`,
* `commit/abort` decrements it,
* region close requires `∀k. marking(r,k) = 0`.

This provides simple linear invariants and fast trace checks for “no leaks.”

#### 3.4.1 Linear logic view (affine, single-use tokens)

We model obligations as **linear resources** in a judgmental style:

```
Γ; Δ ⊢ e ⇓ v; Δ'
```

Where:

- `Γ` is the unrestricted context (regular values),
- `Δ` is the linear context (obligation tokens),
- `Δ'` is the linear context after evaluation.

Define a linear token type `Obl(k, o)` meaning “obligation `o` of kind `k` is held”.

Rules (informal):

```
RESERVE:
  Γ; Δ ⊢ reserve(k) ⇓ o; Δ, Obl(k, o)

COMMIT:
  Γ; Δ, Obl(k, o) ⊢ commit(o) ⇓ (); Δ

ABORT:
  Γ; Δ, Obl(k, o) ⊢ abort(o) ⇓ (); Δ
```

Linearity means **no rule duplicates or discards** `Obl(k, o)` except `COMMIT` or `ABORT`.
The system is **affine** only in the sense that *leaks are explicit errors*:
attempting to terminate with a non-empty linear context triggers the `LEAK` transition.

```
LEAK:
  Γ; Δ, Obl(k, o) ⊢ return v  ⇓  error(ObligationLeak(o))
```

This matches the runtime behavior: uncommitted obligations are detected and reported
when a task completes.

#### 3.4.2 Mapping to runtime state

The linear context `Δ` is *represented concretely* by the obligation registry `O`:

```
Obl(k, o) ∈ Δ   ⟺   O[o] = { kind: k, state: Reserved, holder: t, ... }
```

Transitions in §3.4 correspond directly to mutations of `O`:

- `reserve` adds a `Reserved` record,
- `commit/abort` set the record state to `Committed` or `Aborted`,
- `leak` sets `Leaked` (error state) when a task completes while still holding.

This is the concrete embedding of linear logic into the runtime’s operational state.

#### 3.4.3 Mapping to oracles and tests

The lab runtime’s **ObligationLeakOracle** and trace checks implement the same rule:

```
Held(t) = { o | O[o].holder = t ∧ O[o].state = Reserved }
TaskComplete(t) ∧ Held(t) ≠ ∅  ⇒  ObligationLeak(o) for each o ∈ Held(t)
```

This is the runtime witness for the linearity invariant and is the test-level
assertion that "no obligation leaks" holds for any execution.

#### 3.4.4 Obligation lifecycle state machine

Obligations are **one-shot** resources with a simple state machine:

```
Reserved  ──commit──▶  Committed
    │
    ├─abort─────────▶  Aborted
    │
    └─(task completes holding)──▶  Leaked   // error
```

Legal transitions:

```
Reserved → Committed | Aborted | Leaked
Committed / Aborted / Leaked are absorbing
```

Only the **holder task** may commit/abort:

```
O[o].holder = t  ⇒  only t may trigger commit(o) or abort(o)
```

Cancellation does **not** resolve obligations; it only changes task states.
Therefore, cancellation correctness depends on draining tasks to points where
they can commit or abort any held obligations.

#### 3.4.5 Ledger view (region close precondition)

Define the region obligation ledger:

```
ledger(r) = { o | O[o].region = r ∧ O[o].state = Reserved }
```

Then a necessary precondition for `CLOSE-COMPLETE` is:

```
ledger(r) = ∅
```

This is the operational form of “no obligation leaks” at the region boundary:
region close implies all obligations have been resolved.

Lemma (sketch):

If all tasks in region `r` complete **without leak transitions**, then
`ledger(r) = ∅`. (Because every `Reserved` obligation is linearly consumed
by `commit` or `abort`, and leaks are the only way for a `Reserved` obligation
to survive task completion.)

This lemma underpins the lab-runtime oracle: when the oracle reports no leaks,
region close is safe w.r.t. obligations.

---

### 3.5 Joining and Waiting

#### JOIN-BLOCK — Wait for incomplete task

```
Preconditions:
  T[t1].state = Running
  T[t1].cont = await(join(t2))
  T[t2].state ≠ Completed(_)

Σ —[τ]→ Σ' where:
  T'[t2].waiters = T[t2].waiters ∪ {t1}
  // t1 is now suspended
```

#### JOIN-READY — Immediate completion

```
Preconditions:
  T[t1].state = Running
  T[t1].cont = await(join(t2))
  T[t2].state = Completed(outcome)

Σ —[τ]→ Σ' where:
  T'[t1].cont = resume(T[t1].cont, outcome)
```

---

### 3.6 Time

#### TICK — Advance virtual time

```
Preconditions:
  // No task can make immediate progress
  ∀t: T[t].state = Running ⟹ T[t].cont = await(sleep(_))

Σ —[tick]→ Σ' where:
  τ'_now = τ_now + 1
  // Wake tasks whose sleep expired
  ∀t where T[t].cont = await(sleep(d)) ∧ d ≤ τ'_now:
    T'[t].cont = resume(T[t].cont, ())
  // Check deadline expiries
  ∀r where R[r].budget.deadline = Some(d) ∧ d ≤ τ'_now:
    apply CANCEL-REQUEST(r, Timeout)
```

---

## 4. Derived Combinators

Combinators are defined in terms of primitives:

### 4.1 join(f1, f2)

```
join(r, f1, f2) =
  t1 ← spawn(r, f1)
  t2 ← spawn(r, f2)
  o1 ← await(t1)
  o2 ← await(t2)
  return (o1, o2)
```

Policy handles fail-fast: if o1 errors and policy = FailFast, t2 is cancelled.

### 4.2 race(f1, f2)

```
race(r, f1, f2) =
  t1 ← spawn(r, f1)
  t2 ← spawn(r, f2)
  (winner, loser) ← select_first(t1, t2)
  cancel(loser)
  await(loser)              // IMPORTANT: drain loser
  return winner.outcome
```

**Critical invariant**: losers are always drained, never abandoned.

### 4.3 timeout(duration, f)

```
timeout(r, d, f) =
  race(r, f, async { sleep(d); Err(TimeoutError) })
```

---

## 5. Invariants

These must hold in all reachable states:

### INV-TREE: Ownership tree structure

```
∀r ∈ dom(R):
  r = root ∨ (R[r].parent ∈ dom(R) ∧ r ∈ R[R[r].parent].subregions)
```

### INV-TASK-OWNED: Every live task has an owner

```
∀t ∈ dom(T):
  T[t].state ≠ Completed(_) ⟹ t ∈ R[T[t].region].children
```

### INV-QUIESCENCE: Closed regions have no live children

```
∀r ∈ dom(R):
  R[r].state = Closed(_) ⟹
    (∀t ∈ R[r].children: T[t].state = Completed(_)) ∧
    (∀r' ∈ R[r].subregions: R[r'].state = Closed(_))
```

### INV-CANCEL-PROPAGATES: Cancel flows downward

```
∀r ∈ dom(R):
  R[r].cancel = Some(_) ⟹
    ∀r' ∈ R[r].subregions: R[r'].cancel = Some(_)
```

### INV-OBLIGATION-BOUNDED: Reserved obligations have live holders

```
∀o ∈ dom(O):
  O[o].state = Reserved ⟹
    T[O[o].holder].state ∈ {Running, CancelRequested(_), Cancelling(_), Finalizing(_)}
```

### INV-OBLIGATION-LINEAR: Obligations resolve at most once

```
∀o ∈ dom(O):
  O[o].state ∈ {Committed, Aborted, Leaked} is absorbing
```

Equivalently: once an obligation is resolved, it cannot be “resolved again” by any transition.

### INV-LEDGER-EMPTY-ON-CLOSE: Closed regions have no reserved obligations

```
∀r ∈ dom(R):
  R[r].state = Closed(_) ⟹ ledger(r) = ∅
```

This follows from linearity plus the `CLOSE-COMPLETE` precondition.

### INV-MASK-BOUNDED: Masking is finite and monotone

```
∀t ∈ dom(T):
  T[t].mask ∈ ℕ  and only decreases at CHECKPOINT-MASKED
```

This ensures cancellation is not indefinitely deferrable without consuming an explicit budget.

### INV-DEADLINE-MONOTONE: Children can't outlive parents

```
∀r ∈ dom(R), ∀r' ∈ R[r].subregions:
  deadline(R[r']) ≤ deadline(R[r])    // Tighter or equal
```

### INV-LOSER-DRAINED: Race losers always complete

```
After race(f1, f2) returns:
  both t1 and t2 are in Completed(_) state
```

### INV-SCHED-LANES: Runnable tasks are lane-consistent

```
∀t:
  t ∈ S.cancel_lane  ⇒ lane(t) = Cancel
  t ∈ S.timed_lane   ⇒ lane(t) = Timed
  t ∈ S.ready_lane   ⇒ lane(t) = Ready
```

### Meta: Compositional specs (separation + rely/guarantee)

The invariants above are global; in practice we want *local* reasoning that composes.
A standard approach is:

* **Separation logic**: model owned runtime resources (tasks/obligations/finalizers) with separating conjunction `*` and `emp`.
  * Frame rule (informal): if command `C` doesn’t touch resource `R`, then `{P} C {Q}` implies `{P * R} C {Q * R}`.
* **Rely/Guarantee**: attach to each primitive what it assumes from the environment (rely) and what it promises (guarantee).

Example spec shape (illustrative):

* `close(r)` requires ownership of region `r` plus proofs that children are complete and obligations are zero-marked;
  it guarantees `r` becomes `Closed(_)` and transfers its owned resources back to `emp`.

This is the natural formal home for “structured concurrency is local reasoning,” and it aligns directly with the region ownership tree.

---

## 6. Progress Properties

Under fair scheduling:

### PROG-TASK: Tasks eventually terminate

```
T[t].state ∈ {Created, Running} ∧ fair
  ⟹ eventually T[t].state = Completed(_)
```

### PROG-CANCEL: Cancelled tasks drain

```
T[t].state = CancelRequested(_) ∧ fair
  ⟹ eventually T[t].state = Completed(Cancelled(_))
```

### PROG-REGION: Closing regions close

```
R[r].state = Closing ∧ fair
  ⟹ eventually R[r].state = Closed(_)
```

### PROG-OBLIGATION: Obligations resolve

```
O[o].state = Reserved ∧ fair
  ⟹ eventually O[o].state ∈ {Committed, Aborted}
  // Leaked is an error state that triggers detection
```

---

## 7. Algebraic Laws (Observational Equivalences)

These enable optimizations and test oracles:

### 7.0 What `≃` means (trace quotient, not raw interleavings)

When we write `p ≃ q`, we mean observational equivalence **up to**:

1. eliding silent steps (`τ`),
2. quotienting traces by swaps of independent actions (`~` from §1.8),
3. renaming fresh ids (`TaskId`, `ObligationId`) consistently.

This is the “right” notion for lawful rewrites and for schedule exploration: differences that only permute independent work should not matter.

### LAW-JOIN-ASSOC

```
join(join(a, b), c) ≃ join(a, join(b, c))
```

### LAW-JOIN-COMM (when policy allows)

```
join(a, b) ≃ join(b, a)   // Outcomes may be reordered
```

### LAW-RACE-COMM

```
race(a, b) ≃ race(b, a)   // Winner depends on schedule
```

### LAW-TIMEOUT-MIN

```
timeout(d1, timeout(d2, f)) ≃ timeout(min(d1, d2), f)
```

### LAW-RACE-NEVER

```
race(f, never) ≃ f
```

### LAW-RACE-JOIN-DIST (speculative execution)

```
race(join(a, b), join(a, c)) ≃ join(a, race(b, c))
// Don't run 'a' twice
```

### 7.8 Denotational sketch (powerdomains for nondeterminism)

Operational semantics is the executable truth; still, it is useful to keep a denotational picture in mind.
Interpret a closed computation as a set of possible outcomes (nondeterminism from scheduling):

```
⟦p⟧ ⊆ Outcome
```

Then (schematically):

* `⟦join(p,q)⟧ = { (o1,o2) | o1 ∈ ⟦p⟧ ∧ o2 ∈ ⟦q⟧ }`
* `⟦race(p,q)⟧ = ⟦p⟧ ∪ ⟦q⟧` (plus the *requirement* that losers are cancelled+drained)

This is the powerdomain intuition: “programs denote sets,” and schedulers choose an element.
Adequacy (“operational steps generate exactly the denotation”) is the target property for the lab runtime and rewrite engine.

---

## 8. Test Oracle Usage

The lab runtime implements these semantics exactly. Property tests verify:

```rust
fn test_property(trace: &[TraceEvent]) -> bool {
    no_task_leaks(trace) &&
    no_obligation_leaks(trace) &&
    all_finalizers_ran(trace) &&
    quiescence_on_close(trace) &&
    losers_always_drained(trace)
}
```

### Checking no_task_leaks

```
spawned = { t | TaskSpawned{t} ∈ trace }
completed = { t | TaskCompleted{t} ∈ trace }
spawned = completed
```

### Checking no_obligation_leaks

```
¬∃o: ObligationLeaked{o} ∈ trace
```

### Checking losers_always_drained

```
∀(t1, t2) in race:
  TaskCompleted{t1} ∈ trace ∧ TaskCompleted{t2} ∈ trace
```

### 8.1 Schedule exploration: optimal DPOR (one trace per equivalence class)

Because `≃` quotients by independence, the right exploration target is **one execution per Mazurkiewicz trace** (not per interleaving).
This is exactly what *optimal DPOR* algorithms achieve.

At a high level:

* record a happens-before / dependence relation during an execution,
* when a dependent reordering is discovered, add a backtrack point,
* use source sets / sleep sets / wakeup trees to avoid redundant schedules.

Result: exploration cost becomes proportional to the number of equivalence classes, not factorial in the number of steps.

### 8.2 Static complement: abstract interpretation for obligation leaks

Dynamic traces catch real bugs; static analysis catches *likely* bugs early.
A sound (possibly conservative) abstract interpreter can track “may hold unresolved obligations” per scope/task and warn on scope exit.

---

## 9. TLA+ Sketch

For model checking, translate to TLA+:

```tla
---------------------------- MODULE AsupersyncV4 ----------------------------
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS TASKS, REGIONS, MAX_TIME

VARIABLES tasks, regions, obligations, now

TaskStates == {"Created", "Running", "CancelRequested", 
               "Cancelling", "Finalizing", "Completed"}

RegionStates == {"Open", "Closing", "Draining", "Finalizing", "Closed"}

TypeInvariant ==
    /\ tasks \in [TASKS -> [state: TaskStates, region: REGIONS]]
    /\ regions \in [REGIONS -> [state: RegionStates, children: SUBSET TASKS]]
    /\ now \in 0..MAX_TIME

TreeStructure ==
    \A r \in REGIONS:
        r = "root" \/ 
        \E parent \in REGIONS: r \in regions[parent].subregions

NoOrphans ==
    \A t \in TASKS:
        tasks[t].state /= "Completed" =>
        t \in regions[tasks[t].region].children

QuiescenceOnClose ==
    \A r \in REGIONS:
        regions[r].state = "Closed" =>
        \A t \in regions[r].children: tasks[t].state = "Completed"

\* Actions...
Spawn(r, t) == ...
Complete(t, outcome) == ...
CancelRequest(r, reason) == ...
\* etc.

=============================================================================
```

---

## 10. Summary

This semantics provides:

| Goal | How Achieved |
|------|--------------|
| Precision | Every operation has one meaning |
| Testability | Lab runtime implements rules exactly |
| Verifiability | TLA+ translation for model checking |
| Practicality | Matches Rust implementation closely |

The key design invariant:

> **Never allow a primitive to stop being polled while holding an obligation**
> without transferring it, aborting it, or escalating.

This single rule, enforced by the obligation system and verified by the lab runtime,
is what makes Asupersync's cancel-correctness guarantees real.
