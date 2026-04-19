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

Status: Implemented. Mapped to `GenServer`, `GenServerHandle`, `Reply`, and `SystemMsg` in `src/gen_server.rs`.

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

Status: Implemented. Uses tracked oneshot reply permits and obligation-aware send/abort paths in `src/gen_server.rs`.

**Cast**
An asynchronous fire-and-forget message to a GenServer. The sender does not wait for a reply. Casts flow through the mailbox with standard backpressure (bounded channel blocks when full). No reply obligation is created.

Status: Implemented. Maps to `GenServerHandle::cast` / `try_cast` with bounded-mailbox backpressure in `src/gen_server.rs`.

**Reply Obligation**
A linear token created when a call message is received by a GenServer. The server *must* consume this token by sending a reply. If the token is dropped without reply (e.g., due to a bug or panic), the obligation system detects the leak. In lab mode, leaked reply obligations trigger a diagnostic; in production, the caller's oneshot receives an error.

Mapped to: `ObligationToken` in `src/record/obligation.rs`, `ObligationTable` in `src/runtime/obligation_table.rs`. State machine: Reserved -> {Committed | Aborted | Leaked}.

### Failure Handling

**Linking**
A bidirectional failure propagation relationship between two processes. When a linked process fails, the failure is propagated to all linked peers. In Spork, linking maps to the region ownership model: a child process failing triggers the supervisor's `on_failure` handler, which may restart, stop, or escalate.

Mapped to: Region parent-child relationship + `SupervisionDecision` in `src/supervision.rs`. Actor-level linking via `ActorContext.parent` and `SupervisorMessage::ChildFailed`.

**Monitoring**
A unidirectional observation of another process's lifecycle. Monitors receive a notification when the monitored process terminates but are not themselves affected by the termination. This is a lighter-weight alternative to linking.

Status: Implemented. Mapped to `MonitorRef`, `DownNotification`, and deterministic `SystemMsg::Down` delivery.

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
3. **Stop hook**: Cleanup hook runs (finalizers, obligation discharge)
4. **Completion**: Task completes with an `Outcome` (Ok/Err/Cancelled/Panicked)

Region close ensures quiescence: all children must complete before the region reports closed.

Mapped to: `run_actor_loop` phases in `src/actor.rs` lines 679-744, cancellation protocol in `src/types/cancel.rs`.

**GenServer init/terminate (Spork)**

GenServer lifecycle is OTP-style, with init/terminate semantics expressed through
`GenServer::on_start` / `GenServer::on_stop`:

1. **init**: `on_start(&Cx)` runs once before processing any messages.
2. **loop**: calls/casts/info are processed sequentially.
3. **stop requested**: cancellation requested or mailbox disconnected.
4. **drain**: bounded drain of buffered mailbox entries.
   - Calls are *not* executed during drain; their reply obligations are aborted deterministically.
   - Cast/info may still run during drain (bounded by mailbox capacity).
5. **terminate**: `on_stop(&Cx)` runs once after drain.

**Budgets**

- **init budget**: `GenServer::on_start_budget()` is met with the task/region budget and applied only
  for the duration of `on_start`. Budget consumption during init is preserved when restoring the
  original budget for the message loop.
- **terminate budget**: `GenServer::on_stop_budget()` is applied for drain + `on_stop`, yielding
  bounded cleanup.

**Masking Rules**

- **init is unmasked**: if cancellation is already requested before init begins, init is skipped.
- **drain + on_stop are masked**: cancellation is masked for cleanup so drain and `on_stop` can run
  deterministically under the terminate budget.

Mapped to: `run_gen_server_loop` phases in `src/gen_server.rs`.

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

### INV-6A: Outcome Mapping Tables (Spork)

Spork builds new OTP-grade surfaces (GenServer, Supervisor, Link/Monitor, Registry) on top of
Asupersync's 4-valued `Outcome` lattice:

```text
Ok < Err < Cancelled < Panicked
```

This section specifies the mapping from common Spork events and API results into that lattice.
The guiding rule is: the lattice is for immutable facts about completed executions. Recovery is
modeled by spawning new executions (restarts), not by rewriting old outcomes.

#### Mapping: Task Completion -> Outcome

| Observed Completion | Maps To | Notes |
|---|---|---|
| Task returns successfully | `Outcome::Ok(_)` | Normal completion. |
| Task returns application error | `Outcome::Err(_)` | Potentially restartable (policy-dependent). |
| Task is cancelled | `Outcome::Cancelled(reason)` | External directive; not restartable by default. |
| Task panics | `Outcome::Panicked(payload)` | Programming error; never restartable. |

#### Mapping: `TaskHandle::join()` / `JoinError` -> Outcome

| Join Result | Maps To | Notes |
|---|---|---|
| `Ok(value)` | `Outcome::Ok(value)` | The task produced `value`. |
| `Err(JoinError::Cancelled(r))` | `Outcome::Cancelled(r)` | Join observes task cancellation. |
| `Err(JoinError::Panicked(p))` | `Outcome::Panicked(p)` | Join observes task panic. |

#### Mapping: GenServer `call` / `cast` -> Outcome (Severity)

GenServer surfaces are `Result`-typed for ergonomics. When a caller or supervisor needs to reason
in lattice terms, use this mapping:

| API Result | Maps To | Notes |
|---|---|---|
| `Ok(reply)` (call) | `Outcome::Ok(reply)` | Normal reply delivery. |
| `Err(CallError::Cancelled(r))` | `Outcome::Cancelled(r)` | Caller-side cancellation. |
| `Err(CallError::ServerStopped)` | `Outcome::Err(CallError::ServerStopped)` | Deterministic stop signal; not a panic. |
| `Err(CallError::NoReply)` | `Outcome::Panicked(_)` | Protocol violation. Treat as panicked severity (must be trace-visible). |
| `Ok(())` (cast) | `Outcome::Ok(())` | Cast enqueued/processed normally. |
| `Err(CastError::Cancelled(r))` | `Outcome::Cancelled(r)` | Caller-side cancellation. |
| `Err(CastError::ServerStopped)` | `Outcome::Err(CastError::ServerStopped)` | Server not running / mailbox disconnected. |
| `Err(CastError::Full)` | `Outcome::Err(CastError::Full)` | Backpressure outcome; deterministic and explicit (never silent drop). |

Note: `CallError::NoReply` is expected to be structurally prevented by reply-obligation linearity.
If it occurs, treat it as a correctness violation at the panicked level and escalate.

#### Mapping: Supervision Decision -> Supervisor Outcome

Supervisor decisions are actions; they do not rewrite the child's outcome. The supervisor's own
`Outcome` depends on whether the failure was handled locally or escalated:

| Child Outcome | Local Decision | Supervisor Outcome | Notes |
|---|---|---|---|
| `Ok` | (none) | `Ok` | Normal steady-state. |
| `Err` | `Restart` | `Ok` | Recovery via fresh child instance; old `Err` remains in trace. |
| `Err` | `Stop` | `Ok` or `Err` (policy-specific) | If stopping is an acceptable terminal for a child, supervisor can remain `Ok`. If child is required, supervisor may fail with `Err`. |
| `Err` | `Escalate` | `Err` | Escalation propagates failure upward. |
| `Cancelled` | `Stop` | `Cancelled` (or `Ok` if fully contained) | Cancellation is an external directive; default is to stop and propagate unless explicitly contained. |
| `Panicked` | `Stop`/`Escalate` | `Panicked` | Panic is not recoverable; treat as fatal. |

The exact policy choice for "stop child but supervisor continues Ok" must be explicit per child
spec (`ChildSpec`) and deterministic.

### INV-6B: Monotone Severity Rules (Spork)

Severity monotonicity has two layers:

1. Within a single execution (a single task/server instance):
- A completed `Outcome` is immutable.
- Cancellation reasons are monotone: if multiple cancellations race, the strongest reason wins.

2. Across supervision and restart (multiple executions over time):
- A restart creates a fresh child instance; it does not "heal" the failed one.
- Panics are never treated as restartable.
- Cancellation is never treated as a transient error; default is stop and drain.
- Any externally reported aggregate outcome (region close, supervisor join) must be computed as a
  monotone function over observed outcomes (e.g., max severity) plus explicit containment rules.

### INV-6C: Unit-Test Checklist (Spec)

These are the minimum tests that should exist alongside the eventual code implementing this spec:

- `join_outcomes` is monotone and selects the worst outcome by `Severity`.
- GenServer `call()` maps cancellation to `CallError::Cancelled` deterministically (no spurious `ServerStopped`).
- GenServer `CallError::NoReply` never occurs in normal operation; if forced, it is trace-visible and treated as panicked severity.
- Supervisor never restarts a `Panicked` child outcome.
- Supervisor never treats `Cancelled` as restartable; it stops/drains deterministically.
- Restart does not mutate the prior child's outcome; traces show both the failure and the new instance start.
- Any "containment" rule (child stop while supervisor remains `Ok`) is explicitly encoded in child specs and is deterministic under lab seeds.

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

---

## 6. Public API Surface Map (Spork)

This section defines the **intended public module layout** for the SPORK layer and the
**capability contracts** that prevent ambient authority and preserve lab determinism.

Status: planned (bd-24wd7). This is the API shape that downstream work (Supervisor builder,
GenServer, Registry, Link/Monitor, Crash artifacts, Lab harness) should converge on.

### 6.1 Modules (Planned)

Spork lives under a single module root:

- `asupersync::spork` (feature-gated; see 6.2)

Submodules and responsibilities:

| Module | Responsibility | Maps To / Builds On |
|--------|----------------|---------------------|
| `spork::genserver` | `GenServer` trait, `call/cast`, reply-obligation linearity, budget-driven timeouts | `actor`, `channel`, `obligation`, `types::{Budget, Outcome}` |
| `spork::supervisor` | `Supervisor` builder + `ChildSpec`, compiled topology over regions, deterministic restart semantics | `supervision`, `cx::{Scope, Cx}`, `runtime::RuntimeState` |
| `spork::registry` | capability-scoped naming, name ownership as lease obligations, deterministic collision semantics | `obligation`, `types::{Time, Budget}`, planned in bd-3rpp8 |
| `spork::link` | linking/monitoring, down events, deterministic ordering contracts | `supervision` + planned monitor/Down delivery |
| `spork::crash` | deterministic crash packs, canonical traces, replay hooks | `trace`, `lab`, `record` (internal) |
| `spork::lab` | app harness + conformance suites (seed-sweep, DPOR, oracles) | `lab::{LabRuntime, LabConfig}`, `trace` |

Design constraints:
- No new executors/runtimes inside Spork. Spork is strictly an API layer over asupersync.
- Spork may expose new **types**, but effects must still flow through `Cx` or explicit handles.

### 6.2 Cargo Feature Gating (Planned)

Spork should not be on the hot path for users who only want the runtime kernel. The intended
feature map is:

| Feature | Enables | Notes |
|---------|---------|-------|
| `spork` | `pub mod spork` | Default-off (proposed). No new executor deps; pure library code. |
| `spork-lab` | `spork::lab` helpers and conformance scaffolding | May depend on `lab` internals; remains deterministic. |
| `spork-crash` | `spork::crash` crash pack writers + golden tests | Should reuse existing `trace` canonicalization. |

Non-goals for feature gating:
- Spork features MUST NOT introduce ambient singletons (global registry, global process table).
- Spork features MUST NOT require wall-clock time for semantics (lab uses virtual time).

### 6.3 Capability Contracts

Spork APIs must be capability-driven. Any API that can cause effects must require either:
- a `Cx<Caps>` where `Caps` includes the needed effect bits, or
- an explicit handle/capability object obtained from `Cx` or a region-local constructor.

**Base effect bits** (implemented today): `spawn`, `time`, `random`, `io`, `remote`
(`src/cx/cap.rs`). Spork adds *domain* capabilities (GenServer/Supervisor/Registry/Link/Crash/Lab)
that are derived from these base effects and region ownership.

Capability shape (planned):

| Capability | Acquire From | Lifetime / Ownership | Determinism Contract |
|------------|--------------|----------------------|----------------------|
| `GenServerCap` | `Cx` (or a `SporkCx` wrapper) with `spawn + time` | Region-scoped; cannot outlive owning region | timeouts/backoff use `Time`/timer driver; no wall-clock; mailbox ordering tie-breaks are stable |
| `SupervisorCap` | `Scope` / region builder (`Scope::spork_supervisor(...)`) | Region-scoped; compiled topology determines region tree | restarts use lab time; decisions are trace-visible; no global restarter state |
| `RegistryCap` | `Cx`-derived handle, stored explicitly (no global singleton) | Lease obligation ties ownership to region/task; name release on close | deterministic collision rules; no HashMap iteration order dependence |
| `LinkCap` | `Cx`-derived handle | link state owned by region/supervisor; cleaned on close | Down delivery ordering is stable (explicit tie-break key) |
| `CrashCap` | `Cx`-derived handle (requires trace buffer) | scoped to runtime/lab harness; writes deterministic artifacts | crash packs are stable across same seed + trace equivalence canonicalization |
| `LabCap` | `LabRuntime` / harness entrypoint | test-only orchestration; not for production execution paths | schedule is seed-driven and replayable; oracles are deterministic |

Notes:
- `Cx` is clonable and shared; *authority* is type-level (capability set), and *ownership* is
  region-level (region close implies quiescence).
- `Cx::current()` exists as **runtime plumbing** (thread-local set while polling) and must not be
  required by Spork APIs. If used, it must be a convenience only, not a capability acquisition path.

### 6.4 No Ambient Globals (Hard Rule)

Spork must not require any of the following:
- a global registry or global name table
- a static process table
- ambient access to the scheduler

Allowed patterns:
- explicit handles stored in app state and passed through constructors
- capability objects derived from `Cx` / `Scope` and scoped to a region
- trace/log collection only via `Cx::trace` or structured observability hooks

---

## 7. Deterministic Failure Triage Playbook (Humans + Agents)

This is the standard Spork incident workflow for replayable failures. It is
explicitly optimized for human+agent handoff and deterministic reproduction.

### 7.1 Required Artifacts

Primary artifacts:
- `target/test-artifacts/<safe_test_id>/repro_manifest.json`
- `target/test-artifacts/<safe_test_id>/event_log.txt`
- `target/test-artifacts/<safe_test_id>/failed_assertions.json`
- `target/test-artifacts/<safe_test_id>/trace.async` (if replay recording enabled)
- `target/test-artifacts/<safe_test_id>_summary.json`

Optional crash artifact:
- `crashpack-<seed>-<fingerprint>-v1.json` (if crashpack attachment is present)

### 7.2 Exact Commands (Copy/Paste)

```bash
# Inputs
TEST_ID=<cargo-test-selector>
ART=target/test-artifacts
SAFE_TEST_ID=$(printf '%s' "$TEST_ID" | sed 's/[^[:alnum:]]/_/g')

# (1) Read report fingerprint first (and seed/config)
jq '{scenario_id,seed,schema_version,config_hash,trace_fingerprint,trace_file,input_file}' \
  "$ART/$SAFE_TEST_ID/repro_manifest.json"

# (2) Re-run exactly with same seed + artifact dir
SEED=$(jq -r '.seed' "$ART/$SAFE_TEST_ID/repro_manifest.json")
ASUPERSYNC_SEED="$SEED" ASUPERSYNC_TEST_ARTIFACTS_DIR="$ART" \
  cargo test "$TEST_ID" -- --nocapture

# (3) Verify trace + inspect divergence
TRACE_FILE=$(jq -r '.trace_file // "trace.async"' "$ART/$SAFE_TEST_ID/repro_manifest.json")
cargo run --features cli --bin asupersync -- trace info "$ART/$SAFE_TEST_ID/$TRACE_FILE"
cargo run --features cli --bin asupersync -- trace verify --strict "$ART/$SAFE_TEST_ID/$TRACE_FILE"
# optional compare against baseline
cargo run --features cli --bin asupersync -- trace diff <trace_a> <trace_b>

# (4) If crashpack exists, inspect + replay metadata
CRASHPACK=$(jq -r '.failure_artifacts[]? | select(test("crashpack-.*\\.json$"))' \
  "$ART/${SAFE_TEST_ID}_summary.json" | head -n1)

if [ -n "$CRASHPACK" ]; then
  jq '{fingerprint:.manifest.fingerprint,replay:.replay.command_line,attachments:.manifest.attachments}' "$CRASHPACK"
  jq '.supervision_log[]? | {virtual_time,task,region,decision,context}' "$CRASHPACK"
  jq '.evidence[]? | {birth,death,is_novel,persistence}' "$CRASHPACK"
fi

# (5) DPOR exploration + minimal counterexample diagnostics
cargo test --test dpor_exploration explorer_discovers_classes_for_concurrent_tasks -- --nocapture
cargo test --test replay_divergence_diagnostics e2e_divergence_diagnostics_structured_report -- --nocapture
```

### 7.3 Four-Step Triage Protocol

1. Read fingerprint first:
`repro_manifest.json` is the source of truth for `seed`, `scenario_id`, and
`trace_fingerprint` (when present). Do not start from logs.
2. If crashpack exists, replay from crashpack metadata:
use `crashpack.manifest.fingerprint` + `crashpack.replay.command_line` as the
repro anchor and keep the crashpack path in handoff notes.
3. Inspect evidence cards:
`crashpack.supervision_log` is the restart/cancel decision ledger and
`crashpack.evidence` is the canonical evidence snapshot set. Triage decisions
must reference one of these, not intuition.
4. Run DPOR and minimize:
use `dpor_exploration` to enumerate schedule classes and
`replay_divergence_diagnostics` to extract the minimal divergent prefix.

### 7.4 Real Failing Example (Repository-Backed)

Use the crashpack walkthrough suite in `src/trace/crashpack.rs`:

```bash
cargo test --lib crashpack::tests::walkthrough -- --nocapture
```

What this demonstrates (deterministic and currently passing in-tree):
1. `walkthrough_01_forced_failure_and_emission` models a real panic outcome
   (`assertion failed: balance >= 0`) and emits crashpack data.
2. `walkthrough_03_fingerprint_interpretation` proves equivalent schedules map
   to the same canonical fingerprint.
3. `walkthrough_04_replay_command` validates replay command metadata generation.
4. `walkthrough_05_minimization` shows prefix minimization from 50 events down
   to a 15-event reproducer.

### 7.5 Bead Handoff Template

Use this structure in bead notes for deterministic handoff:

```text
[spork-triage]
seed=<u64>
test_id=<cargo test selector>
fingerprint=<manifest.trace_fingerprint or crashpack.manifest.fingerprint>
invariant=<INV-* or contract id>
first_divergence_step=<n or none>
crashpack=<path or none>
dpor_command=cargo test --test dpor_exploration explorer_discovers_classes_for_concurrent_tasks -- --nocapture
artifacts=
  - target/test-artifacts/<safe_test_id>/repro_manifest.json
  - target/test-artifacts/<safe_test_id>/event_log.txt
  - target/test-artifacts/<safe_test_id>/failed_assertions.json
  - target/test-artifacts/<safe_test_id>/trace.async
  - target/test-artifacts/<safe_test_id>_summary.json
```

---

## 8. Agent-First Work Loop (Operational Contract)

This is the canonical work loop for humans and coding agents collaborating on
Spork incidents and feature tasks.

### 8.1 Identity and Threading Rules

Every unit of work must map to one stable identifier:

- Bead issue id: `bd-...`
- Mail thread id: same bead id (for example `thread_id="bd-1h1hp"`)
- Mail subjects: prefix with `[bd-...]`

This gives one deterministic audit trail across:
- bead status history
- mail conversation
- artifact paths

### 8.2 Start-of-Work Checklist

```bash
# 1) Claim ownership
br update <bd-id> --status in_progress --assignee <agent-name>

# 2) Announce in-thread
# subject: [<bd-id>] Start: <short scope>
# thread_id: <bd-id>

# 3) Reproduce deterministically (see Section 7.2)
ASUPERSYNC_SEED=<seed> ASUPERSYNC_TEST_ARTIFACTS_DIR=target/test-artifacts \
  cargo test <test_id> -- --nocapture
```

Minimum start message fields:
- scope being changed
- files intended for edit
- expected acceptance target

### 8.3 Artifact Bundle Contract

Every progress or completion message must include enough data for a zero-guess
handoff:

- bead id / thread id
- seed
- test id
- fingerprint (`repro_manifest.trace_fingerprint` or crashpack fingerprint)
- first divergence step (or `none`)
- crashpack path (or `none`)
- exact commands used
- concrete artifact paths

If any field is unknown, write `unknown` explicitly. Never omit required fields.

### 8.4 Evidence-First Decision Rule

Operational decisions must reference deterministic artifacts:

- restart/cancel reasoning from `crashpack.supervision_log`
- invariant reasoning from `failed_assertions.json` and evidence ledger entries
- schedule-class reasoning from DPOR output and replay divergence diagnostics

No decision should be justified only by intuition or non-replayable logs.

### 8.5 Completion Checklist

```bash
# 1) Mark issue complete when acceptance is met
br close <bd-id> --reason "<deterministic acceptance summary>"

# 2) Post final in-thread summary
# subject: [<bd-id>] Completed: <what landed>
# include artifact bundle contract fields
```

Completion summary must include:
- exact file paths edited
- validation commands run
- what remains open (if anything)
