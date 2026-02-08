# SPORK Deterministic Ordering Contracts

> Defines replay-stable tie-break rules for mailbox ordering, down-notification
> delivery, registry name acquisition, and app shutdown system-message ordering.
>
> Bead: bd-12qan | Parent: bd-11z9a

---

## 0. Scope and Conventions

This document specifies deterministic ordering rules for three SPORK
subsystems that, under concurrent execution, face inherent races:

1. **Mailbox delivery** — when multiple senders target the same actor/GenServer
2. **Down notifications** — when multiple monitored processes die in the same
   scheduling quantum
3. **Registry name acquisition** — when multiple processes race to register
   the same name
4. **App shutdown system messages** — when `Down`/`Exit`/`Timeout` notifications
   are batched during shutdown/drain paths

All rules must produce identical orderings when executed under `LabRuntime`
with the same seed. Production mode need not enforce total ordering, but must
be *compatible* with the contracts (i.e., never contradict a guarantee
specified here, even if real scheduling is non-deterministic).

**Key principle**: ordering is determined by data already present at the
decision point. No new fields are introduced for tie-breaking; existing
generation counters, task IDs, and timestamps suffice.

### Notation

- `gen(x)` — the monotone generation counter assigned when item `x` was
  created (scheduler entry generation, obligation ID, etc.)
- `tid(p)` — the `TaskId` of process `p` (ArenaIndex: `(generation, slot)`)
- `vt(e)` — the virtual-time timestamp at which event `e` was recorded
- `<` — "is ordered before" (earlier = first)

---

## 1. Mailbox Ordering

### 1.1 Single-Sender Guarantee (FIFO)

Messages from a single sender to a single receiver are delivered in send
order. This is inherited from the MPSC channel's `VecDeque` FIFO semantics
(`src/channel/mpsc.rs`).

**Contract (MAIL-FIFO)**:
```
∀ sender S, receiver R:
  if S sends m1 before m2 to R,
  then R receives m1 before m2.
```

This holds because a single sender cannot interleave its own sends (sends are
sequential within a task), and the VecDeque preserves insertion order.

### 1.2 Multi-Sender Ordering

When multiple senders target the same mailbox, the delivery order is
determined by the order in which `SendPermit::send()` (commit) executes. In
lab mode, this is controlled by the deterministic scheduler.

**Contract (MAIL-MULTI)**:
```
∀ senders S1, S2, receiver R:
  if S1.permit.send(m1) is scheduled before S2.permit.send(m2),
  then R receives m1 before m2.
```

The scheduler controls interleaving. Under lab mode with a fixed seed, the
interleaving is deterministic (via `ScheduleCertificate`). Under production
mode, ordering between senders is non-deterministic but the FIFO guarantee
per sender is maintained.

### 1.3 Reserve/Commit Atomicity

A `SendPermit` is a reservation. The permit holds the slot; the send commits
the message. If the permit is dropped without sending (e.g., the sender is
cancelled), the slot is released and no message is delivered. This is the
two-phase reserve/commit contract.

**Contract (MAIL-RESERVE)**:
```
∀ permit P:
  P is either committed (message delivered to queue)
  or aborted (slot released, no message visible to receiver).
  No partial message is ever visible.
```

### 1.4 GenServer Call/Cast Ordering

Calls and casts share the same mailbox (they are both `Envelope<S>` variants).
Therefore, calls and casts interleave in mailbox FIFO order. The GenServer
processes them sequentially in `dispatch_envelope`.

**Contract (GS-ORDER)**:
```
∀ GenServer G:
  G processes envelopes in mailbox FIFO order.
  A call's reply is produced after the call is processed but before
  the next envelope is dispatched (sequential handler execution).
```

### 1.5 Drain-Phase Ordering

During actor/GenServer shutdown, the drain phase processes all committed
messages remaining in the mailbox, in FIFO order, up to the mailbox capacity
bound.

**Contract (DRAIN-ORDER)**:
```
∀ actor/GenServer A stopping with messages [m1, m2, ..., mk] in mailbox:
  drain processes m1, m2, ..., mk in that order.
  k ≤ mailbox_capacity (bounded drain).
```

---

## 2. Down-Notification Ordering

When a process monitors other processes and multiple monitored processes
terminate in the same scheduling quantum, the order in which down
notifications are delivered must be deterministic.

### 2.1 Ordering Key

Down notifications are ordered by the *completion virtual timestamp* of the
terminated process, with task ID as tie-breaker.

**Contract (DOWN-ORDER)**:
```
∀ monitor M observing processes P1, P2:
  if vt(completion(P1)) < vt(completion(P2)),
    then M receives down(P1) before down(P2).
  if vt(completion(P1)) = vt(completion(P2)),
    then order by tid(P1) < tid(P2)
    (ArenaIndex comparison: generation first, then slot).
```

**Rationale**: Virtual time is the primary ordering key because it captures
causal ordering. Task ID tie-breaking is stable across replays (same seed
produces same TaskId assignments).

### 2.2 Batch Delivery

When multiple down notifications become ready in a single scheduler step,
they are sorted by the (vt, tid) key and enqueued into the monitor's
notification channel in that order.

**Contract (DOWN-BATCH)**:
```
∀ scheduler step S producing down-notifications D = {d1, d2, ..., dn}
  for monitor M:
  D is sorted by (vt(di), tid(di)) before enqueue.
  M receives them in sorted order.
```

### 2.3 Down-Notification Content

Each down notification carries:
- `monitored: TaskId` — the process that terminated
- `reason: Outcome` — the termination outcome (Ok/Err/Cancelled/Panicked)
- `monitor_ref: MonitorRef` — the reference returned when the monitor was
  established

**Contract (DOWN-CONTENT)**:
```
∀ down notification D for terminated process P:
  D.monitored = tid(P)
  D.reason = P.completion_outcome
  D.monitor_ref = the ref returned by monitor(P)
```

### 2.4 Monitor Cleanup on Region Close

When a region closes, all monitors established by tasks in that region are
automatically cleaned up. Pending down notifications for not-yet-terminated
monitored processes are discarded (the monitor ceases to exist).

**Contract (DOWN-CLEANUP)**:
```
∀ region R closing:
  All monitors held by tasks in R are released.
  No further down notifications are delivered to tasks in R.
```

---

## 3. Registry Name Acquisition Ordering

When multiple processes race to register the same name, the registry must
resolve the contention deterministically.

### 3.1 First-Commit Wins

Name acquisition follows first-commit semantics: the first `register(name)`
call that the scheduler executes wins. Subsequent attempts for the same name
either fail, replace, or wait (depending on the `NameCollisionPolicy`).

**Contract (REG-FIRST)**:
```
∀ processes P1, P2 registering name N:
  if register(P1, N) is scheduled before register(P2, N),
    then P1 holds N.
  P2's outcome depends on NameCollisionPolicy:
    Fail    → P2 receives RegistrationError::NameTaken
    Replace → P2 takes N, P1 receives a name-lost notification
    Wait    → P2 blocks until N is released (budget-bounded)
```

### 3.2 Deterministic Contention Resolution (Lab Mode)

Under lab mode, the scheduler determines which `register` call executes
first. Given the same seed, the same process wins. The deterministic
tie-break follows the scheduler's existing priority/generation ordering.

**Contract (REG-DET)**:
```
∀ lab execution with seed S, processes P1, P2 racing for name N:
  the winner is determined by the scheduler's pick_next ordering
  (lane priority > generation > RNG(S)).
  Replaying with the same seed produces the same winner.
```

### 3.3 Registry Lease Semantics

A registered name is a lease obligation. The lease is tied to:
- The owning process's lifetime (process termination releases the name)
- The owning region's lifetime (region close releases all names)
- Optional explicit TTL (virtual-time-based expiry)

**Contract (REG-LEASE)**:
```
∀ name N held by process P:
  N is released when any of:
    (a) P explicitly calls unregister(N)
    (b) P's task completes (any Outcome)
    (c) P's owning region closes
    (d) lease TTL expires (if configured)
  Release is visible to subsequent register(N) calls.
```

### 3.4 Lookup Consistency

Registry lookups return the *current* holder at the point the lookup is
scheduled. There is no snapshot isolation; a lookup followed by a message send
may race with the holder's termination.

**Contract (REG-LOOKUP)**:
```
∀ lookup(N) at scheduler step T:
  returns Some(holder) if N is registered at step T,
  returns None otherwise.
  The returned holder may terminate before the caller uses it
  (this is inherent to any naming system; callers must handle errors).
```

### 3.5 No HashMap Iteration Order Dependence

The registry implementation must not depend on HashMap iteration order for any
externally observable behavior. Internal data structures must use BTreeMap,
Vec with explicit sort, or similar deterministic containers.

**Contract (REG-NOHASH)**:
```
∀ registry operations:
  No externally observable behavior depends on HashMap iteration order.
  All enumeration/scan operations return results sorted by name (lexicographic).
```

---

## 4. Cross-Cutting: Supervisor Ordering Contracts

Supervisors interact with all three ordering domains. These contracts specify
how supervision decisions respect ordering.

### 4.1 Child Start Order

Children are started in the compiled topological order (as computed by
`SupervisorBuilder::compile()`). Within the same topological level,
`StartTieBreak` policy applies (InsertionOrder or NameLex).

**Contract (SUP-START)**:
```
∀ compiled supervisor with start_order [c1, c2, ..., cn]:
  children are started in exactly that order.
  start(ci) completes before start(c_{i+1}) begins.
```

### 4.2 Restart Decision Ordering

When multiple children fail in the same scheduling quantum, the supervisor
processes failures in task-completion order: (vt, tid).

**Contract (SUP-RESTART)**:
```
∀ failures F1, F2 in the same quantum:
  if vt(F1) < vt(F2), process F1 first.
  if vt(F1) = vt(F2), process tid(F1) < tid(F2) first.
```

### 4.3 OneForAll / RestForOne Shutdown Ordering

When a restart policy requires stopping siblings, they are stopped in
*reverse* start order. This mirrors OTP's behavior and ensures that
dependencies are unwound correctly.

**Contract (SUP-STOP)**:
```
∀ one_for_all or rest_for_one restart affecting children [ci, ..., cn]:
  children are stopped in order cn, c_{n-1}, ..., ci (reverse start order).
  stop(ck) completes before stop(c_{k-1}) begins.
```

### 4.4 App/GenServer Shutdown System-Message Ordering

Shutdown and drain paths may produce mixed batches of system notifications
(`Down`, `Exit`, `Timeout`). Delivery order must be replay-stable and
independent of container insertion order.

**Contract (SYS-ORDER)**:
```
∀ system messages M batched for shutdown/drain:
  sort by key K(m) = (vt(m), kind_rank(m), subject_key(m))
  where:
    kind_rank(Down)=0, kind_rank(Exit)=1, kind_rank(Timeout)=2
    subject_key(Down)=monitored_tid
    subject_key(Exit)=from_tid
    subject_key(Timeout)=timeout_id
```

This is implemented by `SystemMsg::sort_key()` and
`SystemMsgBatch::into_sorted()` in `src/gen_server.rs`.

**Contract (SYS-LINK-MONITOR)**:
```
For equal vt:
  monitor Down notifications are delivered before link Exit notifications,
  and both are delivered before Timeout ticks.
```

This aligns monitor/link behavior with the shared deterministic ordering
contract and avoids hidden races in shutdown traces.

### 4.5 App Harness Trace Canonicalization

App-harness trace fingerprinting/canonicalization must preserve the
`SYS-ORDER` contract for shutdown-phase system messages. Canonicalization may
reorder trace events only when it preserves `(vt, kind_rank, subject_key)`
ordering for `Down`/`Exit`/`Timeout` batches.

---

## 5. Replay Stability Requirements

All contracts in this document must satisfy:

### 5.1 Seed Determinism

**Requirement (REPLAY-SEED)**:
```
∀ program P, seed S, configuration C:
  LabRuntime::new(S, C).run(P) produces identical traces T1, T2
  on successive runs.
  ScheduleCertificate(T1) = ScheduleCertificate(T2).
```

### 5.2 Trace Equivalence

Two traces are equivalent if they produce the same sequence of
externally-observable events (message deliveries, down notifications,
registry state changes, supervision decisions) in the same order.

**Requirement (REPLAY-EQUIV)**:
```
∀ traces T1, T2 from the same (seed, config):
  observable_events(T1) = observable_events(T2)
  (element-wise equality, not set equality).
```

### 5.3 Certificate Divergence Detection

The `ScheduleCertificate` hash captures all scheduling decisions. Any
ordering contract violation would produce a different hash on replay.

**Requirement (REPLAY-CERT)**:
```
∀ replay R of trace T:
  if ScheduleCertificate(R) ≠ ScheduleCertificate(T),
    then a determinism violation occurred.
  The divergence_step field pinpoints the first divergent decision.
```

---

## 6. Implementation Notes

### 6.1 Existing Infrastructure

These ordering contracts build on infrastructure already in place:

| Mechanism | Location | Used For |
|-----------|----------|----------|
| Generation counter | `scheduler/priority.rs:295` | FIFO tie-breaking in scheduler |
| RNG tie-break | `scheduler/priority.rs:373-491` | Deterministic selection among equal tasks |
| VecDeque FIFO | `channel/mpsc.rs` | Mailbox ordering |
| ScheduleCertificate | `scheduler/priority.rs:774-858` | Replay divergence detection |
| Virtual time | `lab/runtime.rs` | Lab-mode timestamps |
| TaskId (ArenaIndex) | `types/id.rs` | Stable tie-break key |
| BTreeSet for toposort | `supervision.rs` | Deterministic start ordering |

### 6.2 New Infrastructure Needed

| Need | For | Bead |
|------|-----|------|
| MonitorRef type + notification channel | Down-notification delivery | bd-4r1ep |
| Registry data structure (BTreeMap-based) | Name acquisition | bd-133q8 |
| Down-notification sort + enqueue | Batched delivery ordering | bd-4r1ep |
| Supervisor failure queue with (vt, tid) sort | Restart decision ordering | bd-3ddsi |

### 6.3 Testing Strategy

Each contract should have at least one lab-mode test that:
1. Creates a scenario where the ordering matters (concurrent senders, simultaneous failures, name races)
2. Runs with a fixed seed
3. Asserts the exact ordering specified by the contract
4. Replays and asserts `ScheduleCertificate` equality
