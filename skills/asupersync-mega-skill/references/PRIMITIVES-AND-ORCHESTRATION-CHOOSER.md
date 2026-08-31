# Primitive And Orchestration Chooser

## Table of Contents

- [First Choose The Ownership Model](#first-choose-the-ownership-model)
- [Channel Chooser](#channel-chooser)
- [Sync Primitive Chooser](#sync-primitive-chooser)
- [Service Layer Vs Combinator Vs Actor](#service-layer-vs-combinator-vs-actor)
- [Combinator Chooser](#combinator-chooser)
- [Practical Selection Rules](#practical-selection-rules)
- [Primitive Choice By Common Migration Problem](#primitive-choice-by-common-migration-problem)
- [Anti-Patterns](#anti-patterns)
- [Read Next](#read-next)

One of the biggest ways to underuse Asupersync is to treat every problem as
"spawn a task, stick a mutex around state, and maybe add a timeout."

Asupersync gives you more precise tools. Use them precisely.

## First Choose The Ownership Model

Before choosing a channel or lock, decide who owns the state and lifecycle.

| Problem Shape | Prefer |
|--------------|--------|
| short-lived fork/join request work | `Scope` + child regions |
| dynamic fan-out with per-task results | `JoinSet` (`JoinSet::in_cx(cx)` or `JoinSet::new(&scope)`; `join_next` / `join_all` / `cancel_all` keep drain ownership) |
| single-owner mailbox state | `actor` |
| request/reply stateful service | `GenServer` |
| many long-lived children with restart topology | `AppSpec` + `supervision` + optional `spork` |
| protocol edge with linear reply/resource semantics | session channels / tracked obligations |

If state already has one natural owner, do not turn it into shared-state-plus-locks
just because that is what Tokio code often did.

## Channel Chooser

| Primitive | Use It When | Avoid It When |
|----------|-------------|---------------|
| `mpsc` | many producers, one consumer owns the queue | you need typed request/reply or per-subscriber fan-out |
| `oneshot` | one result, one waiter, one resolution | you actually have multi-step protocol or streaming |
| `broadcast` | many subscribers each need to see each event | consumers need only the latest state |
| `watch` | readers need the current latest value, not full history | every update must be individually observed |
| `session` | request/reply or protocol edges need linear reply obligations | you only need a dumb fire-and-forget queue |

Critical Asupersync distinction:

- bounded `mpsc` has an asynchronous capacity reservation:
  `tx.reserve(&cx).await`,
- `oneshot` and `broadcast` reserve synchronously:
  `tx.reserve(&cx)?` (`oneshot` reservation consumes its sender),
- one-call sugar preserves those shapes: bounded `mpsc`
  `tx.send(&cx, value).await`; `oneshot` and `broadcast`
  `tx.send(&cx, value)` without `.await`,
- use explicit reserve/commit when the send right must be established separately
  from value publication,
- reserve/commit exists to keep work from being half-sent,
- session reply handles are linear resources and should be treated that way;
  tracked session wrappers return `CommittedProof` receipts (v0.4.0 API).

Good uses:

- `watch` for config snapshot / current status
- `broadcast` for event fan-out
- `session` for typed internal RPC where "forgot to reply" must become visible

Bad uses:

- `watch` as a durable event stream
- `broadcast` for linear reply protocols
- `oneshot` chains as a substitute for a real protocol

## Sync Primitive Chooser

| Primitive | Use It When | Avoid It When |
|----------|-------------|---------------|
| `Mutex` | one piece of mutable shared state with clear exclusive sections | state actually wants a single mailbox owner |
| `RwLock` | reads dominate and writer preference is acceptable | writes are frequent or fairness is unclear |
| `Semaphore` | concurrency or resource permits need explicit accounting | you need a queue or lock instead of permits |
| `Barrier` | fixed-size phase rendezvous | dynamic participant counts or loose coordination |
| `Notify` | wake one or more waiters without storing data | you actually need data transfer or state snapshots |
| `OnceCell` | async one-time initialization | init may need repeated refresh or hot swapping |
| `Pool` / `GenericPool` | reusable objects/resources with explicit checkout lifecycle | object ownership is ambiguous or resources are tiny |
| `ContendedMutex` | you need lock-contention evidence or hot-path contention auditing | you do not care about contention metrics |

`Notify::notified()` is drop-cancel-safe: dropping the future removes its waiter.
`Notify::wait_until(predicate)` additionally closes the usual
condition-check/register race. Neither accepts `&Cx`, observes context
cancellation, or returns a typed cancelled result. If a wait must acknowledge
`Cx` cancellation, choose a cancel-aware primitive/combinator or arrange an
explicit wake and checkpoint; do not infer that behavior from `Notify`.

Borrowed `MutexGuard` is deliberately `!Send`; use `OwnedMutexGuard` when it
must move with a worker task. Borrowed RwLock guards are `Send` under their
documented `T` bounds, while owned RwLock guards solve the separate problem of
owning an `Arc`-backed lock without a borrowed lifetime. None of these guard
choices proves cancellation delivery: the wait still needs an actual
`&Cx`-aware path and a test that proves waiter cleanup.

Practical rule:

- if the invariant is "exactly N concurrent uses", think `Semaphore`
- if the invariant is "single mutable state cell", think `Mutex`
- if the invariant is "resource checkout must resolve cleanly", think `Pool`
- if the invariant is "someone must answer this request", think `session` or
  `GenServer`, not raw locks

## Service Layer Vs Combinator Vs Actor

These are different tools, not substitutes.

| Need | Prefer | Why |
|-----|--------|-----|
| request path middleware | `service::ServiceBuilder` | timeout, load shed, retry, concurrency limit, rate limit around a request service |
| orchestration graph is the domain | combinators | hedge, quorum, bracket, pipeline, map_reduce, first_ok |
| single-owner long-lived state | `actor` or `GenServer` | mailbox ownership and lifecycle are explicit |
| restart topology | `AppSpec` + `supervision` | startup/shutdown/restart become modeled instead of ad hoc |

Use `ServiceBuilder` when you want layered request semantics.

Use combinators when the graph itself matters:

- quorum writes
- hedged reads
- structured retries
- staged pipelines
- bulkhead isolation

Use actors or `GenServer` when there is one natural state owner and mailbox
semantics matter more than middleware layering.

## Combinator Chooser

| Combinator | Best For | Key Semantic Advantage |
|-----------|----------|------------------------|
| `timeout` | bounding one operation | explicit timeout semantics instead of ad hoc cancellation |
| `retry` | transient failure with bounded total cost | budget-aware total retry control |
| `hedge` | tail-latency control | explicit backup branch and loser outcome; standalone future drops rather than drains the loser |
| `hedge` + `PeakEwmaHedgeController` | adaptive tail-latency control | peak-EWMA controller supplies a dynamic `HedgeConfig` |
| `hedge` + `AdaptiveHedgePolicy` | calibrated tail-latency control | conformal sliding-window policy supplies a dynamic `HedgeConfig` |
| `quorum` | M-of-N success requirements | policy matches consensus-style flows |
| `bulkhead` | isolate overload domains | one bad dependency stops poisoning siblings |
| `rate_limit` | token-bucket throughput control | explicit backpressure and retry-after data |
| `circuit_breaker` | protect failing dependencies | operationally explicit open/half-open/closed states |
| `pipeline` | staged transforms with backpressure | structure is explicit and optimizable |
| `map_reduce` | parallel work plus lawful reduction | clearer than bespoke spawn/join forests |
| `bracket` | acquire/use/release | cleanup stays first-class |
| `first_ok` | fallback chain | avoid open-coded nested retries/selects |

## Practical Selection Rules

### Use `GenServer` instead of raw channels when:

- callers need typed `call` and `cast` semantics,
- reply obligations must never be forgotten,
- mailbox policy, stop semantics, or restart behavior matter.

### Use session channels instead of `mpsc + oneshot` bundles when:

- you want the protocol itself to be linear and visible,
- reply resolution should participate in obligation accounting,
- cancellation behavior must be testable end to end.

### Use `Pool` instead of ad hoc resource vectors when:

- checkout/release semantics matter,
- resources are expensive,
- cancellation during checkout/use must stay correct.

### Use `ContendedMutex` on suspected hot locks when:

- you need evidence about wait/hold time,
- you are tuning sharded state or cache hot spots,
- you want lock metrics rather than intuition.

## Primitive Choice By Common Migration Problem

| Tokio-Era Pattern | Better Asupersync Choice |
|------------------|--------------------------|
| background task + shared `Arc<Mutex<State>>` | `actor` or `GenServer` if there is a single state owner |
| `tokio::sync::mpsc` for request/reply | session channel or `GenServer` |
| open-coded `select!` retry/timeout | `retry`, `timeout`, `hedge`, `bulkhead`, `quorum` |
| ad hoc connection pool | `Pool` / `GenericPool` |
| global broadcast of latest config | `watch` |
| event fan-out via polling a shared map | `broadcast` |

## Anti-Patterns

- using `Mutex` because ownership was not designed explicitly
- stuffing long-lived service topology into naked spawned tasks
- hand-writing Tokio-`select!`-style spaghetti for timeout/retry/race logic --
  the native `race!` and N-ary heterogeneous `select!` macros are
  drain-correct (`Cx::race_drained*` / `Scope::race_all`); the `select!`
  `else` form, direct `Cx::race*`, and `race!`'s elapsed `timeout:` path are
  drop-on-cancel
- using `watch` to represent must-process event history
- using `broadcast` when consumers only need the latest snapshot
- building internal RPC with loose `mpsc` messages and no reply obligation
- choosing primitives by familiarity instead of protocol semantics

## Read Next

- `GREENFIELD-PATTERNS.md`
- `SUPERVISION-OTP.md`
- `WEB-GRPC-HTTP.md`
- `ADVANCED-FEATURES.md`
