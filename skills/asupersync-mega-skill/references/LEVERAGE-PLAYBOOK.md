# Leverage Playbook

Most of Asupersync's value appears only after you stop thinking in terms of
"what replaces `tokio::spawn`?" and start thinking in terms of ownership,
budgets, obligations, and replayable lifecycle control.

## 1. Treat `Budget` And `Outcome` As Design Inputs

Do not treat `Budget` and `Outcome<T, E>` as decorative metadata.

- Use tighter child-region budgets for risky or secondary work: hedges, retries, adapter bridges, cleanup, background replication.
- Keep `Outcome::Cancelled` and `Outcome::Panicked` visible at orchestration boundaries. Flattening them into `Err` throws away shutdown, retry, and diagnostic meaning.
- Use cancellation masking only for short, cleanup-critical sections. A wide masked region is usually a design smell.
- Prefer explicit shutdown policies over "best effort" drop behavior.

Relevant paths:

- `README.md`
- `src/types/`
- `src/cancel/`
- `src/cx/cx.rs`

## 2. Choose The Right Concurrency Surface

Do not force everything into one abstraction.

| Workload shape | Prefer | Why |
|----------------|--------|-----|
| Short-lived fork/join tree | `Scope` + child regions | Lowest-friction structured concurrency |
| Stateful mailbox with sequential mutation | `actor` | Single-owner state and bounded mailbox |
| Stateful request/reply protocol | `GenServer` | `call`/`cast`, reply obligations, lifecycle budgets |
| Long-lived service topology | `AppSpec` + `supervision` | Deterministic start order, restart policy, explicit stop/join |
| Internal named workers | registry capability + name leases | No ambient global registry, deterministic cleanup |
| Distributed step | `remote` + lease/idempotency model | Region-owned remote work instead of closure shipping |

Rule of thumb:

- use plain `Scope` when work is local and tree-shaped,
- use `actor` when state ownership is the main issue,
- use `GenServer` when reply semantics and lifecycle discipline matter,
- use `AppSpec` when the program has a real application topology.

Relevant paths:

- `src/app.rs`
- `src/actor.rs`
- `src/gen_server.rs`
- `src/supervision.rs`
- `examples/spork_minimal_supervised_app.rs`

## 2.5 Promotion Triggers: When To Upgrade Your Design

Agents often underuse Asupersync by staying on the smallest surface too long.
Use these symptom-to-upgrade rules.

| If you see this... | Upgrade to... | Why |
|--------------------|---------------|-----|
| Long-lived named workers, restart policy, or explicit startup/shutdown topology | `AppSpec` + `supervision` | The system has become an application tree, not just a scoped task bundle |
| One natural state owner currently hidden behind `Arc<Mutex<...>>` | `actor` or `GenServer` | Single-owner mailbox semantics are clearer and usually safer than shared mutable state |
| Internal request/reply over ad hoc `mpsc + oneshot` bundles | session channels or `GenServer::call` | Reply ownership and protocol obligations become explicit |
| Tail-latency pain on duplicated reads or fallback calls | `hedge` | Backup work plus loser-drain semantics should be deliberate |
| Overload in one dependency poisoning unrelated paths | `bulkhead`, `ServiceBuilder::concurrency_limit`, `ServiceBuilder::load_shed` | Failure domains and backpressure should be explicit |
| Retry loops growing hand-written and hard to reason about | `retry`, `timeout`, `ServiceBuilder`, or plan/rewrite surfaces | Budget, drain, and policy become testable and composable |
| Handlers receiving full-power `Cx` everywhere | request/call regions + `cx_narrow()` / `cx_readonly()` | Capability security is one of Asupersync's core advantages; use it |
| Shutdown bugs, leak bugs, or race losers that disappear into logs | `Outcome`/`Budget` discipline + deterministic tests + diagnostics | The runtime's diagnostic advantage only appears if you keep the semantics visible |

## 3. Model Long-Lived Apps Explicitly

For long-lived services, `RuntimeBuilder + block_on` is not enough by itself.

`AppSpec` buys you:

- a region-owned supervision tree,
- deterministic child start order,
- root-budget propagation,
- registry capability injection,
- explicit `AppHandle` lifecycle (`stop` / `join`) instead of silent leaks.

Design advice:

- Put always-on workers, replication loops, sidecar observers, and control-plane services under `AppSpec`.
- Treat `AppHandle` and named-server handles as obligation-like lifecycle handles: resolve them explicitly, do not casually drop them.
- Use restart policy and supervision strategy to encode failure domains instead of rebuilding custom watchdog threads.

Relevant paths:

- `src/app.rs`
- `src/supervision.rs`
- `docs/spork_glossary_invariants.md`

## 4. Use Capability-Scoped Boundaries

The service boundary pattern is:

- request/call gets its own region,
- handler receives metadata plus `Cx`,
- handler narrows capability set,
- spawned child work stays owned by that boundary region.

Use:

- `web::request_region::{RequestRegion, RequestContext}`
- `RequestContext::cx_narrow::<...>()`
- `RequestContext::cx_readonly()`
- `grpc::CallContext::with_cx(...)`
- `CallContextWithCx::cx_narrow::<...>()`

Important guidance:

- Production `Cx` values should come from runtime/request/call boundaries.
  `Cx::for_request()` belongs in test/internal harnesses, not as the center of a
  production architecture.
- Do not pass full-capability `Cx` through every handler if most handlers only need trace/time/spawn.
- Do not rebuild ambient registries, global service locators, or hidden runtime handles.

Relevant paths:

- `docs/integration.md`
- `src/web/request_region.rs`
- `src/grpc/server.rs`

## 5. Prefer Native Orchestration Over Hand-Rolled `select!` Forests

Asupersync has a richer orchestration story than "manually race futures."

Use service layers for boundary resilience:

- `ServiceBuilder::timeout(...)`
- `ServiceBuilder::load_shed()`
- `ServiceBuilder::concurrency_limit(...)`
- `ServiceBuilder::rate_limit(...)`
- `ServiceBuilder::retry(...)`

Use combinators when the orchestration itself is the design:

- `hedge` for latency tails,
- `quorum` for M-of-N workflows,
- `bracket` for acquire/use/release correctness,
- `join` / `race` / `timeout` where loser-drain behavior is part of the contract.

Use the plan/rewrite layer when orchestration becomes a real DAG and you want
lawful rewrites instead of hand-maintained nesting.

Important guidance:

- Only permit aggressive rewrites when branches are independent and cancel-safe.
- Losers must drain before the combinator returns when semantics require it.
- Prefer native streams over carrying `tokio-stream` forward out of habit.

Relevant paths:

- `src/service/builder.rs`
- `src/combinator/`
- `src/plan/rewrite.rs`
- `src/combinator/laws.rs`
- `src/stream/`

## 6. Use Obligation-Tracked Protocol Edges

If a protocol edge has "must send", "must reply", "must release", or
"must unregister" semantics, use the tracked surface instead of pretending a
plain channel send is sufficient.

Examples:

- reserve/commit sends for cancel-safe messaging,
- session channels for typed request/reply flows,
- GenServer calls for reply-obligation semantics,
- name leases for named worker registration,
- permit-backed semaphores and pools where release discipline matters.

Important guidance:

- Do not hold permits or leases across unrelated awaits.
- Prefer `call` over `cast` when the protocol requires acknowledgement or reply ownership.
- Use `CastOverflowPolicy` deliberately. Mailbox overflow policy is part of system semantics, not a default you should ignore.

Relevant paths:

- `src/channel/mpsc.rs`
- `src/channel/session.rs`
- `src/gen_server.rs`
- `src/cx/registry.rs`
- `README.md`

## 7. Understand The Distributed Model Correctly

The distributed story is not "ship arbitrary futures to another machine."

It is:

- named computation,
- serialized input,
- explicit remote capability,
- lease- and idempotency-backed lifecycle,
- saga/compensation-aware workflow recovery,
- logical-clock-aware tracing.

Design advice:

- Build a registry of remote computations instead of attempting closure shipping.
- Treat remote work as an obligation-backed child of local structured concurrency.
- Model compensations and idempotency keys up front for multi-step workflows.
- Test partition, heal, retry, and lease-expiry behavior under deterministic harnesses.

Relevant paths:

- `src/remote.rs`
- `src/distributed/`
- `tests/calm_saga_integration.rs`
- `examples/scenarios/partition_heal.yaml`
- `examples/scenarios/clock_skew_lease.yaml`

## 8. Build For Replay, Not Just Success

Asupersync is strongest when you lean into replayability and diagnostics.

Use:

- fixed seeds,
- trace capture,
- quiescence and obligation-leak oracles,
- futurelock detection,
- deterministic chaos injection,
- crashpacks and replay manifests,
- task inspector and structured explanations,
- evidence ledgers when failures are subtle.

Do this early:

- add deterministic tests for each migrated slice,
- keep artifact pointers and seeds for failures,
- treat "can replay the bad run" as a quality bar.

## 9. Do Not Overshoot Into Advanced Surfaces

Some Asupersync surfaces are real but should not be the default starting point
for ordinary service work.

Do **not** lead with these unless the target requirements justify them:

- Browser Edition
- QUIC / HTTP3
- messaging integrations
- remote / distributed execution
- RaptorQ snapshot distribution

For most projects, the highest-leverage path is still:

- `RuntimeBuilder` + `Cx` + `Scope`
- request/call regions
- native `service` / `web` / `grpc`
- native channels/sync/combinators
- deterministic tests and diagnostics from the start

Relevant paths:

- `src/lab/`
- `src/trace/crashpack.rs`
- `src/observability/diagnostics.rs`
- `src/observability/task_inspector.rs`
- `src/lab/oracle/evidence.rs`
