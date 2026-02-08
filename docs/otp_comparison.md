# Spork vs OTP: Comparison Matrix and Non-Goals

> What Spork replicates from OTP, what it intentionally does not, and where it
> is strictly stronger.
>
> Bead: bd-2ser2 | Parent: bd-2rm8l

---

## 1. Feature Comparison Matrix

### 1.1 Core Abstractions

| OTP Concept | Spork Equivalent | Status | Structural Difference |
|---|---|---|---|
| Process (`pid`) | Region-owned task (`TaskRecord`) | Implemented | Tasks cannot orphan; region close implies quiescence |
| Mailbox (`!`) | Bounded MPSC with two-phase reserve/commit | Implemented | Sends are cancel-safe; backpressure is explicit, never silent drop |
| `gen_server` | `GenServer` trait (`src/gen_server.rs`) | Implemented | Typed requests; reply obligations are linear tokens |
| `handle_call` | `GenServer::handle_call` + reply obligation | Implemented | Leaked replies are detected deterministically in lab mode |
| `handle_cast` | `GenServer::handle_cast` (bounded mailbox) | Implemented | Backpressure via bounded channel, not unbounded accumulation |
| `handle_info` | `GenServer::handle_info` (Down, Exit, Timeout) | Implemented | System messages deterministically ordered by `(vt, kind_rank, subject_key)` |
| `init` / `terminate` | `on_start` / `on_stop` with separate budgets | Implemented | Init unmasked (skipped if cancelled); drain + on_stop masked with bounded budget |
| Supervisor | `SupervisorBuilder` + compiled topology | Implemented | Deterministic child ordering; restart decisions are immutable trace facts |
| `one_for_one` | `RestartPolicy::OneForOne` | Implemented | Identical semantics |
| `one_for_all` | `RestartPolicy::OneForAll` | Implemented | Identical semantics; sibling stop in reverse start order |
| `rest_for_one` | `RestartPolicy::RestForOne` | Implemented | Identical semantics |
| `max_restarts` / `max_seconds` | `RestartConfig { max_restarts, window }` | Implemented | Window uses virtual time (deterministic in lab) |
| Backoff | `BackoffStrategy::None \| Fixed \| Exponential` | Implemented | Virtual-time delays; deterministic under replay |
| Link (bidirectional) | Per-link `ExitPolicy` (Propagate / Trap / Ignore) | Implemented | Policy is per-link, not global `process_flag(trap_exit)` |
| Monitor (unidirectional) | `MonitorRef` + `DownNotification` | Implemented | Delivery order deterministic: `(completion_vt, monitored_tid)` |
| Registry (`register/2`) | Capability-scoped naming with lease obligations | Partial | No global singleton; names are obligations tied to region lifetime |
| Application (`application`) | `AppSpec` + `CompiledApp` + `AppHandle` | Implemented | Cancel-correct shutdown; drop bomb prevents silent abandonment |

### 1.2 Supervision Strategies

| OTP Strategy | Spork Equivalent | Notes |
|---|---|---|
| `permanent` | `SupervisionStrategy::Restart(config)` | Restart on any error (within rate limits) |
| `transient` | (composable via ChildSpec) | Can be expressed with restart + outcome filtering |
| `temporary` | `SupervisionStrategy::Stop` | Never restart |
| Escalation (`{stop, Reason}` from init) | `SupervisionStrategy::Escalate` | Propagate failure to parent supervisor |

### 1.3 Severity and Restart Eligibility

OTP can restart after any crash. Spork enforces a severity lattice:

```
Ok < Err < Cancelled < Panicked
```

| Child Outcome | OTP Behavior | Spork Behavior |
|---|---|---|
| Normal exit | No restart | No restart |
| Error | Restart (if policy allows) | Restart (if policy allows) |
| Cancelled | (No direct equivalent) | **Stop only** — cancellation is an external directive, not a transient fault |
| Panic | Restart (if policy allows) | **Stop always** — panics represent programming errors; never restartable |

This is a deliberate strengthening: severity is monotone and supervision decisions are immutable facts in traces.

---

## 2. Where Spork Is Strictly Stronger

### 2.1 Determinism

| Aspect | OTP | Spork |
|---|---|---|
| Scheduling | BEAM real-time; non-deterministic | Lab runtime: seeded scheduling, virtual time, trace replay |
| Message ordering | Non-deterministic across senders | Deterministic in lab (scheduler-determined, seed-stable) |
| Down notifications | Delivery order unspecified | Sorted by `(completion_vt, monitored_tid)` |
| Exit signals | Delivery order unspecified | Sorted by `(exit_vt, from_tid, to_tid, link_ref)` |
| System messages at shutdown | Implementation-dependent order | Sorted by `(vt, kind_rank, subject_key)` |
| Registry collision | Race-dependent | First-commit wins; tie-break via scheduler priority (deterministic in lab) |
| Restart decisions | Dependent on OS scheduling | Process failures by `(vt, tid)` order |

All ordering contracts are trace-visible and testable via `ScheduleCertificate` fingerprints.

### 2.2 Ownership and Safety

| Aspect | OTP | Spork |
|---|---|---|
| Process lifecycle | Convention-based (can detach, leak) | Ownership-enforced: region close guarantees quiescence |
| Reply obligations | Trusted convention | Linear tokens: leaked replies detected at runtime |
| Name ownership | Ambient global table; stale names possible | Lease obligations: region cannot close with unresolved leases |
| Authority model | Global process table (`whereis/1`, `!`) | No ambient authority: all effects flow through `Cx` capabilities |

### 2.3 Cancellation and Cleanup

| Aspect | OTP | Spork |
|---|---|---|
| Cancellation mechanism | Exit signals (trappable) | Multi-phase protocol: request -> drain -> finalize |
| Cleanup bounds | Unbounded (process can trap and run forever) | Budget-driven: init, drain, and on_stop each have time/poll quotas |
| Loser draining | Not enforced | All losing race/select branches drain to completion before combinator returns |
| Mailbox drain | Not guaranteed on shutdown | Bounded drain: committed messages processed before `on_stop` runs |

### 2.4 Observability

| Aspect | OTP | Spork |
|---|---|---|
| Debugging | `observer`, `sys:get_state/1` | Trace infrastructure with canonical fingerprints |
| Crash analysis | Crash dumps (often large, hard to parse) | Crash packs: minimal repro artifacts with replay commands |
| Test exploration | Property-based (random interleaving) | DPOR-style exploration: systematic, seed-stable, targets distinct behaviors |
| Invariant monitoring | Manual assertions | Oracle framework: obligation leaks, futurelock detection, anytime-valid monitoring |

---

## 3. Non-Goals (Explicit v1 Exclusions)

These are intentionally out of scope. They prevent "rebuild OTP" scope creep while
keeping the API extensible for future versions.

### NG-1: Distributed Registry

v1 provides local-only naming. Distributed consensus and partition handling are out
of scope. The registry API is designed to be extensible to distributed backends, but
ships with local-only.

**OTP equivalent**: `global`, `pg2` (distributed process groups).

### NG-2: Hot Code Reload

No live code upgrade while running. Restarts always use the factory closure provided
at spawn time. Conflicts with Rust's static dispatch model.

**OTP equivalent**: Release handler, `code_change/3` callback in `gen_server`.

### NG-3: Distribution Transparency

Remote actors do NOT appear identical to local ones. Remote communication uses the
explicit `remote::invoke` API with leases and idempotency keys. No transparent
proxying of messages to remote mailboxes.

**OTP equivalent**: Erlang distribution (transparent `Pid ! Msg` across nodes).

### NG-4: Process Groups (`pg` module)

No pub/sub broadcast primitive. Actors communicate through explicit `ActorRef`
handles obtained via the registry or direct spawning. Group-based broadcast can be
built on top.

**OTP equivalent**: `pg` (process groups), `pg2`.

### NG-5: Dynamic Supervision (`start_child` at runtime)

v1 supervisors have fixed children defined at startup. Dynamic child management
requires careful restart ordering and is deferred to v2.

**OTP equivalent**: `supervisor:start_child/2`, `simple_one_for_one`.

### NG-6: Application / Release Structure

No bundling of supervision trees into deployable units with ordered
startup/shutdown across applications.

**OTP equivalent**: `application` behaviour, `.app` resource files, release handler.

### NG-7: `sys` Debug Protocol

No OTP-style `sys` module for runtime introspection (`get_state`, `replace_state`,
`trace`). Observability through Asupersync's trace infrastructure instead.

**OTP equivalent**: `sys:get_state/1`, `sys:trace/2`, `dbg`.

### NG-8: Distributed Erlang Compatibility

Not wire-compatible with BEAM. No Erlang distribution protocol, EPMD, or
cookie-based authentication.

---

## 4. Design Principles Behind the Differences

### Why no global registry?

OTP's global `whereis/1` creates implicit dependencies between processes. Any
process can send a message to any registered name without the type system knowing
about the dependency. In Spork, registry access is a capability: you must hold a
`RegistryHandle` to look up names. This makes dependencies explicit and prevents
"spooky action at a distance."

### Why panics are never restartable?

In Erlang, all crashes look the same to the supervisor (`{'EXIT', Pid, Reason}`).
In Rust, a panic indicates a programming error (array bounds, unwrap on None, etc.)
rather than a transient operational failure. Restarting after a panic would just
re-execute the same bug. Spork encodes this in the severity lattice: `Panicked` is
strictly worse than `Err` and never triggers a `Restart` decision.

### Why budgeted cleanup?

OTP processes that trap exits can run cleanup code indefinitely. If a process hangs
during cleanup, the supervisor hangs waiting for it. In Spork, cleanup phases
(`on_stop`, mailbox drain) have explicit budgets. If the budget is exceeded, the
runtime escalates rather than waiting forever. This prevents deadlocked shutdown
cascades.

### Why two-phase sends?

Erlang's `!` is fire-and-forget: the send succeeds even if the mailbox is
overflowing (Erlang mailboxes are unbounded). Spork uses bounded channels with
two-phase reserve/commit. The reserve step can fail or block with backpressure,
making overload visible and cancel-safe (uncommitted reservations are released on
drop).

### Why deterministic ordering contracts?

OTP makes few guarantees about message ordering across processes. This means
concurrency bugs are often non-reproducible: the same test may pass or fail
depending on OS scheduling. Spork specifies deterministic ordering for all system
events (down notifications, exit signals, shutdown messages) and provides a lab
runtime where the entire schedule is seed-determined and replayable.

---

## 5. Migration Guide: OTP Patterns to Spork

| OTP Pattern | Spork Equivalent |
|---|---|
| `gen_server:start_link({local, Name}, Mod, Args, [])` | `SupervisorBuilder::new("name").child(ChildSpec::new("name", start_fn))` |
| `gen_server:call(Pid, Request)` | `server_handle.call(&cx, request).await` |
| `gen_server:cast(Pid, Msg)` | `server_handle.cast(&cx, msg).await` |
| `supervisor:start_link(Mod, Args)` | `SupervisorBuilder::new("sup").with_restart_policy(policy).child(...).compile()` |
| `erlang:monitor(process, Pid)` | Monitor via `Cx` capability (deterministic down ordering) |
| `erlang:link(Pid)` | Link with per-link `ExitPolicy` (Propagate / Trap / Ignore) |
| `whereis(Name)` | `registry_handle.whereis("name")` (capability-scoped, zero-alloc lookup) |
| `application:start(App)` | `AppSpec::builder("app").supervisor(sup_spec).compile()?.start(&cx).await` |

---

## 6. Summary

Spork replicates the *ergonomic patterns* of OTP (GenServer, supervision trees,
monitoring, linking, naming) while enforcing *structural guarantees* that OTP leaves
to convention:

- **No orphan processes**: region ownership, not convention
- **No leaked replies**: linear obligations, not trust
- **No stale names**: lease obligations with automatic cleanup
- **No unbounded cleanup**: budgeted cancellation protocol
- **No flaky tests**: deterministic lab runtime with trace replay

The trade-offs are intentional: no hot code reload (Rust is statically dispatched),
no distribution transparency (explicit is better than implicit), no dynamic
supervision in v1 (correct restart ordering first). These non-goals keep scope
focused while preserving API extensibility for future versions.
