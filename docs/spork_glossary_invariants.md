# SPORK Glossary, Invariants, and Non-Goals

> Single-source-of-truth spec section for the SPORK OTP-grade layer on Asupersync.
> Bead: bd-1xdfe | Parent: bd-11z9a

---

## 1. Glossary

### Core Entities

**Process (Spork Process)**
A region-owned concurrent unit of execution. Unlike Erlang processes, Spork processes are *always* owned by a region and cannot exist as detached entities. A Spork process is the umbrella term for any supervised unit: actors, servers, or bare tasks running under a supervision tree.

Mapped to: `TaskRecord` + `RegionRecord` ownership in `src/runtime/state.rs`.

**Actor**
A message-driven Spork process that owns mutable state and processes messages sequentially from a bounded mailbox. Actors implement the `Actor` trait (`src/actor.rs`), providing `handle`, `on_start`, and `on_stop` lifecycle hooks. Each actor runs as a single task within its owning region.

Mapped to: `Actor` trait, `ActorHandle<A>`, `ActorRef<M>` in `src/actor.rs`.

**GenServer (Generic Server)**
A specialized actor pattern providing synchronous call (request-response) and asynchronous cast (fire-and-forget) message handling. GenServer wraps the `Actor` trait with a typed message protocol that distinguishes calls (which create a reply obligation) from casts (which do not).

Status: Planned (bd-2fh3z). Will build on existing `Actor` + `oneshot` channel for reply.

**Supervisor**
A Spork process responsible for starting, monitoring, and restarting child processes according to a configured strategy. Supervisors form the backbone of fault tolerance. They are themselves region-owned and participate in the region's quiescence protocol.

Mapped to: `Supervisor` struct, `SupervisionStrategy`, `SupervisionConfig` in `src/supervision.rs`. Supervised actor spawning via `Scope::spawn_supervised_actor` in `src/actor.rs`.

**Supervision Tree**
A hierarchical arrangement of supervisors and workers where each supervisor owns a set of child processes. The tree structure maps directly onto Asupersync's region ownership tree: each supervisor corresponds to a region (or sub-region), and each child is a task within that region.

Mapped to: Region ownership tree in `src/runtime/state.rs` (RegionRecord.children, RegionRecord.subregions).

### Communication

**Mailbox**
A bounded MPSC channel attached to an actor for receiving messages. The mailbox uses two-phase reserve/send semantics: senders first reserve a slot, then commit the message. This makes sends cancel-safe (uncommitted reservations are automatically released on drop).

Mapped to: `mpsc::channel<M>` in `src/channel/mpsc.rs`, configured via `MailboxConfig` in `src/actor.rs`. Default capacity: 64 messages.

**Call**
A synchronous request-response interaction with a GenServer. The caller sends a message and receives a reply. Calls create a *reply obligation*: the server must either reply or the obligation is detected as leaked. Calls are inherently bounded by the caller's budget (deadline, poll quota).

Status: Planned. Will use `oneshot::channel` for reply delivery + `ObligationToken` for linearity.

**Cast**
An asynchronous fire-and-forget message to a GenServer. The sender does not wait for a reply. Casts flow through the mailbox with standard backpressure (bounded channel blocks when full). No reply obligation is created.

Status: Planned. Maps directly to existing `ActorRef::send()`.

**Reply Obligation**
A linear token created when a call message is received by a GenServer. The server *must* consume this token by sending a reply. If the token is dropped without reply (e.g., due to a bug or panic), the obligation system detects the leak. In lab mode, leaked reply obligations trigger a diagnostic; in production, the caller's oneshot receives an error.

Mapped to: `ObligationToken` in `src/record/obligation.rs`, `ObligationTable` in `src/runtime/obligation_table.rs`. State machine: Reserved -> {Committed | Aborted | Leaked}.

### Failure Handling

**Linking**
A bidirectional failure propagation relationship between two processes. When a linked process fails, the failure is propagated to all linked peers. In Spork, linking maps to the region ownership model: a child process failing triggers the supervisor's `on_failure` handler, which may restart, stop, or escalate.

Mapped to: Region parent-child relationship + `SupervisionDecision` in `src/supervision.rs`. Actor-level linking via `ActorContext.parent` and `SupervisorMessage::ChildFailed`.

**Monitoring**
A unidirectional observation of another process's lifecycle. Monitors receive a notification when the monitored process terminates but are not themselves affected by the termination. This is a lighter-weight alternative to linking.

Status: Planned. Will use a watch-style channel or callback registration on `ActorHandle::is_finished()`.

**Supervision Strategy**
The policy a supervisor follows when a child fails:

| Strategy | Behavior | Use When |
|----------|----------|----------|
| `Stop` | Stop the failed child permanently | Unrecoverable failures |
| `Restart(config)` | Restart within rate limits | Transient failures |
| `Escalate` | Propagate to parent supervisor | Cannot handle locally |

Mapped to: `SupervisionStrategy` enum in `src/supervision.rs`.

**Restart Policy**
Determines how a single child's failure affects siblings:

| Policy | Behavior | Use When |
|--------|----------|----------|
| `OneForOne` | Only the failed child restarts | Independent children |
| `OneForAll` | All children restart | Shared state dependencies |
| `RestForOne` | Failed child + all children started after it restart | Ordered dependencies |

Mapped to: `RestartPolicy` enum in `src/supervision.rs`.

**Restart Budget**
Rate-limited restart allowance: at most `max_restarts` within a sliding `window`. When exhausted, the `EscalationPolicy` determines the next action (Stop, Escalate, or ResetCounter). Restart timestamps use virtual time for determinism.

Mapped to: `RestartHistory` in `src/supervision.rs`.

**Backoff Strategy**
Delay between restart attempts: None, Fixed(duration), or Exponential(initial, max, multiplier). Prevents thundering herd on transient failures.

Mapped to: `BackoffStrategy` enum in `src/supervision.rs`.

### Naming and Discovery

**Registry**
A capability-scoped naming service that maps names to process references. Registry entries are *lease obligations*: they must be explicitly released or they expire. No ambient global registry exists; registry access flows through `Cx` capabilities.

Status: Planned (bd-3rpp8). Will use `ObligationToken` for lease semantics.

**Registry Lease**
A time-bounded obligation granting a process the right to hold a name in the registry. When the lease expires or the process terminates, the name is automatically released. Lease renewal is explicit and budget-aware.

Status: Planned. Maps to `Lease` obligation type in design bible section 8.

### Lifecycle and Shutdown

**Shutdown Semantics**
Spork processes shut down through Asupersync's cancellation protocol:

1. **Cancel request**: `cx.cancel_requested` is set (or mailbox is closed)
2. **Drain phase**: Actor processes remaining buffered messages (capped at mailbox capacity)
3. **on_stop**: Cleanup hook runs (finalizers, obligation discharge)
4. **Completion**: Task completes with an `Outcome` (Ok/Err/Cancelled/Panicked)

Region close ensures quiescence: all children must complete before the region reports closed.

Mapped to: `run_actor_loop` phases in `src/actor.rs` lines 679-744, cancellation protocol in `src/types/cancel.rs`.

**Graceful Stop vs Abort**
- `stop()`: Signals the actor to finish processing and exit. Currently identical to abort; future improvement will drain buffered messages before exiting.
- `abort()`: Requests immediate cancellation. The actor exits at the next checkpoint, then drains and calls on_stop.

Mapped to: `ActorHandle::stop()` and `ActorHandle::abort()` in `src/actor.rs`.

### Determinism

**Lab Runtime**
A deterministic execution environment with virtual time, seeded scheduling, and trace capture. All Spork constructs must be testable under the lab runtime with reproducible behavior given the same seed.

Mapped to: `LabRuntime` in `src/lab/`.

**Trace Replay**
The ability to capture a concurrent execution trace and replay it deterministically. Supervision decisions, message deliveries, and failure handling must produce identical traces when replayed with the same seed.

Mapped to: Trace infrastructure in `src/observability/`, lab runtime replay in `src/lab/`.

**Virtual Time**
A logical clock that advances only when the scheduler explicitly ticks it. All timeouts, restart windows, backoff delays, and lease expirations use virtual time. No wall-clock dependencies in core Spork logic.

Mapped to: `TimerDriver` and `Time` type in `src/types/`.

---

## 2. Non-Negotiable Invariants

These invariants are inherited from Asupersync and apply to all Spork constructs without exception.

### INV-1: Region Close Implies Quiescence

When a region closes, *all* children (tasks, actors, sub-regions) must have completed and *all* registered finalizers must have run. No live Spork process can outlive its owning region.

**For Spork**: A supervisor's region cannot close until all supervised children have stopped (either normally or via the supervision protocol).

### INV-2: Cancellation Is a Protocol

Cancellation follows the sequence: request -> drain -> finalize. It is:
- **Idempotent**: Multiple cancel requests do not compound; the strongest reason wins.
- **Budgeted**: Cleanup has a finite time/poll budget. Exceeded budgets escalate.
- **Monotone**: A cancelled outcome cannot become "better" (Ok) through supervision; it can only be *replaced* by restarting a fresh instance.

**For Spork**: Supervisor restart creates a *new* actor instance; it does not un-cancel the failed one. The failed instance's outcome remains in the trace.

### INV-3: No Obligation Leaks

Every obligation token (send permit, reply token, registry lease, ack) must reach a terminal state: Committed or Aborted. Dropping a token without resolution is detectable in lab mode and triggers the `ObligationLeakOracle`.

**For Spork**: GenServer call creates a reply obligation. If the server panics before replying, the obligation is aborted (caller receives error). If the server is restarted, pending calls to the old instance fail; the new instance starts with no inherited obligations.

### INV-4: Losers Are Drained

When a race (or select, or timeout) completes, all losing branches must be cancelled and their cleanup must run to completion before the combinator returns.

**For Spork**: If a call has a timeout and the timeout fires, the call future is cancelled, but the server-side processing (if already started) runs its cleanup path. The reply obligation for the cancelled call is aborted.

### INV-5: No Ambient Authority

All effects flow through explicit capabilities (`Cx`, `Scope`, `ActorContext`). There is no global registry, no static process table, no ambient scheduler access. Spork features (supervision, naming, monitoring) are capabilities obtained from the context.

**For Spork**: `ActorContext` extends `Cx` with actor-specific capabilities (self_ref, parent, children). Registry access will be a capability obtained from the supervision context.

### INV-6: Supervision Decisions Are Monotone

A supervision decision cannot downgrade severity:
- `Outcome::Panicked` always results in `Stop` (panics are not restartable; they represent programming errors).
- `Outcome::Err` may trigger `Restart` if budget allows.
- `Outcome::Cancelled` triggers `Stop` (cancellation is an external directive, not a transient fault).

Mapped to: `Supervisor::on_failure` in `src/supervision.rs` lines 655-712.

### INV-7: Mailbox Drain Guarantee

When an actor stops (normally or via cancellation), all messages that were successfully committed into the mailbox are processed during the drain phase before `on_stop` runs. The drain is bounded by mailbox capacity to prevent unbounded work during shutdown.

Mapped to: `run_actor_loop` drain phase in `src/actor.rs` lines 719-737.

### INV-8: Deterministic Under Lab Runtime

All Spork constructs (supervision decisions, restart timing, backoff delays, registry lease expirations, message ordering) must be deterministic when executed under the lab runtime with a given seed. No wall-clock, no thread-local randomness, no HashMap iteration order dependencies in core paths.

---

## 3. Non-Goals (v1)

These are explicitly out of scope for the initial SPORK release. They may be addressed in future versions.

### NG-1: Distributed Registry

v1 provides only a local, in-process registry. Distributed naming (across machines/processes) requires consensus protocols and partition handling that are out of scope. The registry API is designed to be *extensible* to distributed backends, but v1 ships with local-only.

### NG-2: Hot Code Reload

Erlang's ability to upgrade running code (hot code swap) is not supported. Actor restarts always use the factory closure provided at spawn time. Live code upgrade would require runtime-level support for replacing actor implementations, which conflicts with Rust's static dispatch model.

### NG-3: Distribution Transparency

Spork does not pretend that remote actors behave identically to local ones. Remote communication uses the explicit `remote::invoke` API with leases and idempotency keys (Asupersync tier 4). Message passing to remote actors is not transparently proxied through local mailboxes.

### NG-4: Process Groups / pg Module

Erlang's `pg` (process groups) for pub/sub style communication is not in v1. Spork actors communicate through explicit `ActorRef` handles obtained via the registry or direct spawning. Group-based broadcast can be built on top using a supervisor that manages a set of actors.

### NG-5: Dynamic Supervision (add_child at runtime)

v1 supervisors have a fixed set of children defined at startup. Dynamic child management (adding/removing children to a running supervisor) requires careful handling of restart ordering and is deferred to v2.

### NG-6: Application / Release Structure

Erlang's OTP application and release concepts (bundling multiple supervision trees into deployable units with ordered startup/shutdown) are not in v1. Spork provides the building blocks (supervisors, registries) but not the packaging layer.

### NG-7: sys / Debug Protocol

Erlang's `sys` module for runtime introspection of GenServer state (get_state, replace_state, trace) is not in v1. Spork provides observability through Asupersync's trace infrastructure, but not OTP's specific sys protocol.

### NG-8: Distributed Erlang Compatibility

Spork is not wire-compatible with Erlang/BEAM. It does not implement Erlang's distribution protocol, EPMD, or cookie-based authentication. Interop with Erlang systems requires explicit bridge code.

---

## 4. Mapping: OTP Concepts to Asupersync Primitives

| OTP Concept | Spork / Asupersync Equivalent | Status |
|-------------|-------------------------------|--------|
| Process | Region-owned task (TaskRecord) | Implemented |
| Mailbox | Bounded MPSC with two-phase send | Implemented |
| `gen_server` | `Actor` trait + GenServer wrapper | Actor: implemented, GenServer: planned |
| `handle_call` | GenServer call handler + reply obligation | Planned |
| `handle_cast` | GenServer cast handler (no reply) | Planned |
| `handle_info` | Out-of-band message handling | Planned |
| Supervisor | `Supervisor` + `SupervisionStrategy` | Implemented |
| `one_for_one` | `RestartPolicy::OneForOne` | Implemented |
| `one_for_all` | `RestartPolicy::OneForAll` | Implemented |
| `rest_for_one` | `RestartPolicy::RestForOne` | Implemented |
| Link | Region parent-child + cancel propagation | Implemented (structural) |
| Monitor | Watch-style lifecycle observation | Planned |
| Registry | Capability-scoped naming with lease obligations | Planned |
| Application | (Not in v1 - see NG-6) | Out of scope |
| `sys` debug | Trace infrastructure via Cx | Partial |
| Hot code swap | (Not supported - see NG-2) | Out of scope |

---

## 5. Key Differences from Erlang/OTP

1. **Ownership, not convention**: OTP relies on convention for process management. Spork uses Rust's type system + region ownership to *enforce* that processes cannot outlive their supervisor.

2. **Obligations are linear**: OTP trusts processes to reply. Spork tracks reply obligations as linear tokens, detecting leaks at the type/runtime level.

3. **Cancellation is budgeted**: Erlang sends exit signals that processes can trap. Spork's cancellation is a multi-phase protocol with explicit time/poll budgets, preventing cleanup from running indefinitely.

4. **No ambient process table**: Erlang has a global process table. Spork requires explicit capability-scoped registry access. This prevents the "spooky action at a distance" pattern of `whereis/1` + `!`.

5. **Deterministic testing first**: Erlang tests run on the BEAM with real scheduling. Spork's lab runtime provides deterministic execution with trace replay, making concurrency bugs reproducible.

6. **Two-phase mailbox sends**: Erlang's `!` is fire-and-forget. Spork's mailbox uses reserve/commit, making sends cancel-safe and backpressure-aware.

7. **Supervision is monotone**: Erlang can restart after any crash. Spork distinguishes panics (always stop) from errors (restartable), enforcing severity monotonicity.
