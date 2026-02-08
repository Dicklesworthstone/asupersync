# Spork Operational Semantics Extension

**Extends:** `asupersync_v4_formal_semantics.md` (base semantics)
**Bead:** bd-3ofnk | Parent: bd-3ccru

This document extends the base Asupersync operational semantics with
transition rules for the Spork OTP-grade layer: GenServer, supervision,
registry, and monitoring/linking constructs.

All Spork constructs are layered on top of the base primitives (regions,
tasks, obligations, cancellation). No new runtime mechanisms are introduced;
Spork is a *compilation target* that maps OTP-style patterns into the
existing semantic framework.

---

## S1. Additional Domains

### S1.1 GenServer Identifiers

```
s ∈ ServerId    = TaskId      // A GenServer is a task with a mailbox
m ∈ MailboxSlot = ℕ           // Position in bounded MPSC
```

### S1.2 GenServer States

```
ServerState ::=
  | Init                              // on_start phase
  | Running                           // processing call/cast/info
  | Draining(remaining: ℕ)            // bounded mailbox drain
  | Stopping                          // on_stop phase
  | Stopped(outcome: Outcome)
```

### S1.3 Message Types

```
Envelope ::=
  | Call(request, reply_channel, obligation_id)
  | Cast(message)
  | Info(system_msg)

SystemMsg ::=
  | Down(completion_vt: Time, notification: DownNotification)
  | Exit(exit_vt: Time, from: TaskId, reason: DownReason)
  | Timeout(deadline: Time, timeout_id: ℕ)
```

### S1.4 Reply Obligations

GenServer calls create reply obligations (a specialization of the base
obligation system):

```
ReplyObligation ::= {
  kind:      Lease,           // Base obligation type
  holder:    ServerId,        // Server that must reply
  caller:    TaskId,          // Task waiting for reply
  channel:   OneshotChannel,  // Delivery channel
  state:     ObligationState  // Reserved → {Committed, Aborted}
}
```

### S1.5 Supervisor Domains

```
sup ∈ SupervisorId  = RegionId    // A supervisor owns a region
cs  ∈ ChildSpec     = { name: ChildName, start: StartFn, restart: Strategy }

SupervisorStrategy ::= Stop | Restart(config) | Escalate

RestartPolicy ::= OneForOne | OneForAll | RestForOne

RestartPlan ::= {
  policy:        RestartPolicy,
  cancel_order:  [ChildName],     // dependents-first
  restart_order: [ChildName]      // dependencies-first
}
```

### S1.6 Registry Domains

```
RegistryEntry ::= {
  name:    String,
  holder:  TaskId,
  region:  RegionId,
  lease:   ObligationId,
  ttl:     Option<Time>
}
```

### S1.7 Monitor Domains

```
MonitorRef  = ℕ
LinkRef     = ℕ

DownNotification ::= {
  monitored:    TaskId,
  reason:       DownReason,
  monitor_ref:  MonitorRef
}

DownReason ::= Normal | Error | Cancelled | Panicked

ExitPolicy ::= Propagate | Trap | Ignore
```

---

## S2. Extended Global State

The Spork state extends the base state `Σ`:

```
Σ_spork = Σ ∪ {
  GS:  ServerId  → GenServerRecord,
  SUP: RegionId  → SupervisorRecord,
  REG: String    → RegistryEntry,
  MON: MonitorRef → MonitorRecord,
  LNK: LinkRef   → LinkRecord
}

GenServerRecord ::= {
  state:         ServerState,
  mailbox:       BoundedQueue<Envelope>,
  capacity:      ℕ,
  overflow:      CastOverflowPolicy,
  init_budget:   Budget,
  stop_budget:   Budget
}

SupervisorRecord ::= {
  children:      [ChildSpec],
  start_order:   [ℕ],              // topological sort indices
  restart_policy: RestartPolicy,
  restart_history: [Time],
  config:        RestartConfig
}

MonitorRecord ::= {
  watcher:   TaskId,
  monitored: TaskId,
  active:    Bool
}

LinkRecord ::= {
  task_a:  TaskId,
  task_b:  TaskId,
  policy:  ExitPolicy,
  active:  Bool
}
```

---

## S3. GenServer Transition Rules

Labels for GenServer-specific transitions:

```
label ::= ...                          // base labels
        | gs_init(s)
        | gs_call(s, request, o)
        | gs_cast(s, message)
        | gs_info(s, system_msg)
        | gs_reply(s, o, value)
        | gs_drain(s, n)
        | gs_stop(s)
```

### S3.1 Server Lifecycle

#### GS-INIT — Server starts processing

```
Preconditions:
  GS[s].state = Init
  T[s].state = Running

Σ —[gs_init(s)]→ Σ' where:
  // Apply init budget (tightened from task budget)
  b_init = combine(T[s].budget, GS[s].init_budget)
  // Run on_start under b_init
  // If cancelled before init: skip to Stopping
  if cancel_requested(s):
    GS'[s].state = Stopping
  else:
    GS'[s].state = Running
```

#### GS-STOP-BEGIN — Server enters drain phase

```
Preconditions:
  GS[s].state = Running
  cancel_requested(s) ∨ mailbox_disconnected(s)

Σ —[gs_drain(s, |GS[s].mailbox|)]→ Σ' where:
  n = min(|GS[s].mailbox|, GS[s].capacity)
  GS'[s].state = Draining(n)
  // Apply stop budget (masked: cancellation ignored during drain)
  T'[s].mask = T[s].mask + 1
```

#### GS-DRAIN-MSG — Process one message during drain

```
Preconditions:
  GS[s].state = Draining(n)
  n > 0
  GS[s].mailbox ≠ ∅

Σ —[τ]→ Σ' where:
  env = GS[s].mailbox.dequeue()
  match env:
    // Calls during drain: abort reply obligation (do not process)
    Call(_, _, o) → O'[o].state = Aborted
    // Casts and info during drain: process normally
    Cast(msg) → apply handle_cast(s, msg)
    Info(msg) → apply handle_info(s, msg)
  GS'[s].state = Draining(n - 1)
```

#### GS-DRAIN-DONE — Drain complete, enter on_stop

```
Preconditions:
  GS[s].state = Draining(0)

Σ —[gs_stop(s)]→ Σ' where:
  GS'[s].state = Stopping
  // Run on_stop under stop budget (still masked)
```

#### GS-STOPPED — Server completes

```
Preconditions:
  GS[s].state = Stopping
  on_stop(s) completed

Σ —[complete(s, outcome)]→ Σ' where:
  GS'[s].state = Stopped(outcome)
  T'[s].mask = T[s].mask - 1
  T'[s].state = Completed(outcome)
```

### S3.2 Call Protocol (Request-Response)

#### GS-CALL-SEND — Caller sends a call request

```
Preconditions:
  GS[s].state = Running
  |GS[s].mailbox| < GS[s].capacity
  ¬cancel_requested(caller)
  o ∉ dom(O)

Σ —[gs_call(s, request, o)]→ Σ' where:
  // Create reply obligation
  O'[o] = { kind: Lease, holder: s, caller: caller,
             channel: fresh_oneshot(), state: Reserved }
  // Enqueue call envelope
  GS'[s].mailbox.enqueue(Call(request, O[o].channel, o))
```

#### GS-CALL-HANDLE — Server processes a call

```
Preconditions:
  GS[s].state = Running
  GS[s].mailbox.peek() = Call(request, channel, o)
  O[o].state = Reserved

Σ —[τ]→ Σ' where:
  GS'[s].mailbox.dequeue()
  // Server must call reply.send(value) inside handle_call
  // This transitions the obligation via GS-REPLY
```

#### GS-REPLY — Server replies to a call

```
Preconditions:
  O[o].state = Reserved
  O[o].holder = s

Σ —[gs_reply(s, o, value)]→ Σ' where:
  O'[o].state = Committed
  send(O[o].channel, Ok(value))
  // Caller's continuation resumes with Ok(value)
```

#### GS-REPLY-LEAK — Reply obligation leaked (error)

```
Preconditions:
  O[o].state = Reserved
  O[o].holder = s
  GS[s].state = Stopped(_)

Σ —[leak(o)]→ Σ' where:
  O'[o].state = Leaked
  send(O[o].channel, Err(ServerStopped))
  // Detected by ObligationLeakOracle in lab mode
```

### S3.3 Cast Protocol (Fire-and-Forget)

#### GS-CAST-TRY — Non-blocking cast

```
Preconditions:
  GS[s].state ∈ {Init, Running}
  |GS[s].mailbox| < GS[s].capacity

Σ —[gs_cast(s, message)]→ Σ' where:
  GS'[s].mailbox.enqueue(Cast(message))
```

#### GS-CAST-FULL — Mailbox full (backpressure)

```
Preconditions:
  GS[s].state ∈ {Init, Running}
  |GS[s].mailbox| = GS[s].capacity

Result: Err(CastError::Full)
  // No state change. Caller observes explicit backpressure.
```

#### GS-CAST-HANDLE — Server processes a cast

```
Preconditions:
  GS[s].state = Running
  GS[s].mailbox.peek() = Cast(message)

Σ —[τ]→ Σ' where:
  GS'[s].mailbox.dequeue()
  apply handle_cast(s, message)
  // No obligation created; no reply expected.
```

### S3.4 Info Protocol (System Messages)

#### GS-INFO-DELIVER — System message enqueued

```
Preconditions:
  GS[s].state ∈ {Init, Running}

Σ —[gs_info(s, sys_msg)]→ Σ' where:
  GS'[s].mailbox.enqueue(Info(sys_msg))
```

#### GS-INFO-SORT — Deterministic delivery ordering

System messages accumulated in a single scheduler step are sorted before
delivery:

```
sort_key(Down(vt, notif))     = (vt, 0, notif.monitored)
sort_key(Exit(vt, from, _))   = (vt, 1, from)
sort_key(Timeout(deadline, id)) = (deadline, 2, id)

Ordering: lexicographic on (time, kind_rank, subject_key)
```

This ensures identical delivery order across replay with the same seed.

---

## S4. Supervisor Transition Rules

Labels:

```
label ::= ...
        | sup_child_failed(sup, child_name, outcome)
        | sup_restart_plan(sup, plan)
        | sup_cancel_child(sup, child_name)
        | sup_restart_child(sup, child_name)
        | sup_escalate(sup, outcome)
```

### S4.1 Failure Detection

#### SUP-CHILD-FAILED — Supervisor observes child completion

```
Preconditions:
  T[child].state = Completed(outcome)
  outcome ≠ Ok(_)
  child ∈ SUP[sup].children[i]

Σ —[sup_child_failed(sup, name_i, outcome)]→ Σ' where:
  // Determine strategy from ChildSpec
  strategy = SUP[sup].children[i].restart

  match strategy:
    Stop     → apply SUP-STOP-CHILD
    Escalate → apply SUP-ESCALATE
    Restart(config) →
      match severity(outcome):
        Panicked  → apply SUP-STOP-CHILD    // INV-6: panics never restart
        Cancelled → apply SUP-STOP-CHILD    // INV-6: cancellation is not transient
        Err       → apply SUP-PLAN-RESTART
```

### S4.2 Restart Planning

#### SUP-PLAN-RESTART — Compute restart plan

```
Preconditions:
  SUP[sup].children[failed_idx].restart = Restart(config)
  severity(outcome) = Err
  within_restart_budget(sup, config)

Σ —[sup_restart_plan(sup, plan)]→ Σ' where:
  plan = compute_restart_plan(SUP[sup], failed_idx)

  // Plan computation depends on restart policy:
  match SUP[sup].restart_policy:
    OneForOne →
      plan.cancel_order  = [name_failed]
      plan.restart_order = [name_failed]
    OneForAll →
      plan.cancel_order  = reverse(start_order_names)
      plan.restart_order = start_order_names
    RestForOne →
      // All children started at or after the failed child
      rest = start_order_names[failed_position..]
      plan.cancel_order  = reverse(rest)
      plan.restart_order = rest
```

#### SUP-CANCEL-CHILD — Cancel a child per the plan

```
Preconditions:
  plan.cancel_order ≠ ∅
  child = plan.cancel_order.pop_front()

Σ —[sup_cancel_child(sup, child)]→ Σ' where:
  cancel(T[child].region, Shutdown)
  // Child enters cancellation protocol (base semantics)
  // Bounded by child's shutdown_budget
```

#### SUP-RESTART-CHILD — Restart a child per the plan

```
Preconditions:
  plan.restart_order ≠ ∅
  child = plan.restart_order.pop_front()
  all cancelled children have reached Completed(_)

Σ —[sup_restart_child(sup, child)]→ Σ' where:
  // Create fresh task via child.start(scope, state, cx)
  // Old instance remains in trace (immutable fact)
  // New instance has fresh obligations, no inherited state
  SUP'[sup].restart_history.push(now)
```

### S4.3 Restart Budget Exhaustion

#### SUP-BUDGET-EXCEEDED — Too many restarts

```
Preconditions:
  |{ τ ∈ SUP[sup].restart_history | τ > now - config.window }|
    >= config.max_restarts

Σ —[sup_escalate(sup, RestartBudgetExhausted)]→ Σ' where:
  match config.escalation:
    Stop     → cancel all children, supervisor stops
    Escalate → propagate failure to parent supervisor
    Reset    → clear restart history, retry
```

### S4.4 Severity Monotonicity (INV-6)

The supervisor decision function preserves the severity lattice:

```
decision(outcome) =
  match severity(outcome):
    Ok        → NoAction
    Err       → strategy(child)      // may Restart
    Cancelled → Stop                 // external directive, not transient
    Panicked  → Stop                 // programming error, never restart
```

**Invariant**: `Panicked` outcomes never produce `Restart` decisions.
**Invariant**: `Cancelled` outcomes never produce `Restart` decisions.
**Invariant**: Restart creates a *new* child instance; the old instance's
outcome is an immutable trace fact.

---

## S5. Registry Transition Rules

Labels:

```
label ::= ...
        | reg_register(name, holder, region)
        | reg_unregister(name)
        | reg_lookup(name)
        | reg_expire(name)
```

### S5.1 Name Registration

#### REG-REGISTER — Acquire a name lease

```
Preconditions:
  name ∉ dom(REG)
  R[region].state = Open
  o ∉ dom(O)

Σ —[reg_register(name, holder, region)]→ Σ' where:
  // Create lease obligation
  O'[o] = { kind: Lease, holder: holder, state: Reserved }
  REG'[name] = { name, holder, region, lease: o, ttl: ttl_opt }
```

#### REG-COLLISION — Name already taken

```
Preconditions:
  name ∈ dom(REG)
  REG[name].holder ≠ holder

Result: Err(NameTaken { name, current_holder })
  // No state change. First-commit wins.
  // Tie-break in lab: scheduler priority (deterministic with seed)
```

### S5.2 Name Lookup

#### REG-LOOKUP — Find holder by name

```
Preconditions: (none)

Σ —[reg_lookup(name)]→ Σ where:
  // Pure query, no state mutation
  if name ∈ dom(REG):
    return Some(REG[name].holder)
  else:
    return None
```

### S5.3 Name Release

#### REG-UNREGISTER — Release a name

```
Preconditions:
  name ∈ dom(REG)
  REG[name].lease = o

Σ —[reg_unregister(name)]→ Σ' where:
  O'[o].state = Committed      // resolve lease obligation
  REG' = REG \ {name}
```

#### REG-EXPIRE — TTL-based expiry

```
Preconditions:
  name ∈ dom(REG)
  REG[name].ttl = Some(deadline)
  now ≥ deadline

Σ —[reg_expire(name)]→ Σ' where:
  O'[REG[name].lease].state = Aborted
  REG' = REG \ {name}
```

### S5.4 Region Close Interaction

When a region closes, all name leases held by tasks in that region must be
resolved:

```
∀ name ∈ dom(REG):
  if REG[name].region = r ∧ R[r].state = Closed(_):
    O[REG[name].lease].state ∈ {Committed, Aborted}
```

This is enforced by INV-3 (no obligation leaks) from the base semantics.

---

## S6. Monitor Transition Rules

Labels:

```
label ::= ...
        | monitor(watcher, monitored, ref)
        | demonitor(ref)
        | down(ref, reason)
```

### S6.1 Monitor Establishment

#### MON-CREATE — Establish a monitor

```
Preconditions:
  ref ∉ dom(MON)

Σ —[monitor(watcher, monitored, ref)]→ Σ' where:
  MON'[ref] = { watcher, monitored, active: true }
```

### S6.2 Down Notification

#### MON-DOWN — Monitored task completes

```
Preconditions:
  T[monitored].state = Completed(outcome)
  MON[ref].monitored = monitored
  MON[ref].active = true

Σ —[down(ref, reason)]→ Σ' where:
  reason = outcome_to_down_reason(outcome)
  notification = { monitored, reason, monitor_ref: ref }
  vt = completion_vt(monitored)
  // Deliver as SystemMsg::Down to watcher's mailbox
  GS'[watcher].mailbox.enqueue(Info(Down(vt, notification)))
  MON'[ref].active = false
```

### S6.3 Deterministic Down Ordering

When multiple monitors fire in the same scheduler step:

```
sort_key(down_notification) = (completion_vt, monitored_tid)
```

Notifications are sorted by this key before delivery. This ensures identical
delivery order across replay.

### S6.4 Region Close Cleanup

```
∀ ref ∈ dom(MON):
  if MON[ref].watcher ∈ R[r].children ∧ R[r].state = Closed(_):
    MON'[ref].active = false
```

---

## S7. Link Transition Rules

Labels:

```
label ::= ...
        | link(a, b, ref, policy)
        | unlink(ref)
        | exit_signal(ref, from, reason)
```

### S7.1 Link Establishment

#### LINK-CREATE — Establish a bidirectional link

```
Preconditions:
  ref ∉ dom(LNK)

Σ —[link(a, b, ref, policy)]→ Σ' where:
  LNK'[ref] = { task_a: a, task_b: b, policy, active: true }
```

### S7.2 Exit Signal Propagation

#### LINK-EXIT — Linked task fails

```
Preconditions:
  T[from].state = Completed(outcome)
  severity(outcome) > Ok
  LNK[ref].active = true
  (LNK[ref].task_a = from ∧ to = LNK[ref].task_b) ∨
  (LNK[ref].task_b = from ∧ to = LNK[ref].task_a)

Σ —[exit_signal(ref, from, reason)]→ Σ' where:
  reason = outcome_to_down_reason(outcome)
  match LNK[ref].policy:
    Propagate →
      // Cancel the linked task
      cancel(to, ExitSignal(from, reason))
    Trap →
      // Deliver as SystemMsg::Exit to linked task's mailbox
      GS'[to].mailbox.enqueue(Info(Exit(exit_vt, from, reason)))
    Ignore →
      // No action
  LNK'[ref].active = false
```

### S7.3 Deterministic Exit Signal Ordering

When multiple exit signals fire in the same scheduler step:

```
sort_key(exit_signal) = (exit_vt, from_tid, to_tid, link_ref)
```

Signals are sorted by this key before processing. Per-link exit policy
(not global `process_flag(trap_exit)`) ensures deterministic per-link behavior.

### S7.4 Severity Monotonicity for Exit Signals

Exit signal reasons are monotone: if multiple exit signals arrive for the
same target, the worst reason wins:

```
effective_reason(signals) = max_severity({ s.reason | s ∈ signals })
```

---

## S8. Invariants (Spork-Specific)

These extend the base invariants from the core semantics.

### SINV-1: GenServer Reply Linearity

Every call obligation must reach a terminal state:

```
∀ o ∈ dom(O):
  O[o].kind = Lease ∧ O[o].context = "call" →
    eventually(O[o].state ∈ {Committed, Aborted, Leaked})
```

`Leaked` is an error case detected by the `ObligationLeakOracle`.

### SINV-2: Supervisor Severity Monotonicity

```
∀ sup, child, outcome:
  severity(outcome) ∈ {Cancelled, Panicked} →
    decision(sup, child, outcome) ≠ Restart
```

### SINV-3: Registry Lease Resolution on Region Close

```
∀ r, name:
  R[r].state = Closed(_) ∧ REG[name].region = r →
    O[REG[name].lease].state ∈ {Committed, Aborted}
```

### SINV-4: Deterministic System Message Ordering

```
∀ s, step:
  let msgs = system_messages_accumulated_in(s, step)
  delivery_order(msgs) = sort_by(msgs, sort_key)
```

### SINV-5: No Orphan Servers

```
∀ s ∈ dom(GS):
  GS[s].state ≠ Stopped(_) →
    R[T[s].region].state ∈ {Open, Closing, Draining}
```

A running GenServer cannot exist in a closed region.

### SINV-6: ChildName Clone Cost

```
∀ name ∈ ChildName:
  cost(clone(name)) = O(1)     // Arc refcount bump, not string copy
```

This is a performance invariant enforced by gate tests.

---

## S9. Independence Extensions (Trace Theory)

Spork adds the following to the base independence relation:

```
// GenServer call and cast to different servers are independent
(gs_call(s1, _, _), gs_call(s2, _, _))  ∈ I  when s1 ≠ s2
(gs_cast(s1, _),    gs_cast(s2, _))     ∈ I  when s1 ≠ s2
(gs_call(s1, _, _), gs_cast(s2, _))     ∈ I  when s1 ≠ s2

// Reply to different obligations are independent
(gs_reply(_, o1, _), gs_reply(_, o2, _)) ∈ I  when o1 ≠ o2

// Monitor notifications to different watchers are independent
(down(ref1, _), down(ref2, _))  ∈ I
  when MON[ref1].watcher ≠ MON[ref2].watcher

// Registry operations on different names are independent
(reg_register(n1, _, _), reg_register(n2, _, _))  ∈ I  when n1 ≠ n2
(reg_lookup(n1), reg_lookup(n2))                    ∈ I  when n1 ≠ n2

// Supervisor restart plans for different supervisors are independent
(sup_restart_plan(sup1, _), sup_restart_plan(sup2, _))  ∈ I  when sup1 ≠ sup2
```

These independence rules enable Spork-aware DPOR exploration: the explorer
can skip interleavings that differ only by reordering independent Spork
operations.

---

## S10. Test Oracle Predicates

Spork adds the following oracle checks (extending base section 8):

```
// No leaked reply obligations after quiescence
oracle_reply_linearity(Σ) =
  ∀ o ∈ dom(O): O[o].context = "call" → O[o].state ≠ Reserved

// No stale registry entries after region close
oracle_registry_clean(Σ) =
  ∀ name ∈ dom(REG):
    R[REG[name].region].state ≠ Closed(_)

// Supervisor restart decisions are severity-monotone
oracle_restart_monotone(trace) =
  ∀ (sup_child_failed(_, _, outcome), decision) ∈ trace:
    severity(outcome) ∈ {Cancelled, Panicked} → decision ≠ Restart

// System message delivery order is deterministic
oracle_system_msg_order(trace, seed) =
  ∀ s, step:
    delivery_order(s, step, seed) = delivery_order(s, step, seed)
    // Tautology by construction; verified by comparing across seeds
```

---

## S11. Summary

The Spork operational semantics extend the base Asupersync semantics with
four construct families:

| Construct | Key Rules | Invariants |
|-----------|-----------|------------|
| GenServer | Call/Cast/Reply with obligation linearity | SINV-1: reply obligations always resolved |
| Supervisor | Restart planning with severity monotonicity | SINV-2: panics/cancellations never restart |
| Registry | Name leases tied to region lifetime | SINV-3: leases resolved on region close |
| Monitor/Link | Deterministic notification ordering | SINV-4: stable sort by (vt, kind, subject) |

All Spork constructs preserve the base invariants (region quiescence,
obligation linearity, cancellation protocol, loser draining, no ambient
authority). Spork is a compilation target, not a new runtime — it maps
OTP-style patterns into the existing semantic framework and inherits all
base correctness guarantees.
