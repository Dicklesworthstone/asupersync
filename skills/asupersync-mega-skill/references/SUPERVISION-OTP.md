# Supervision And OTP-Style Design

If the target system has long-lived workers, stateful services, restart domains,
or named internal components, this is where Asupersync stops looking like a
Tokio replacement and starts looking like a stronger application model.

## Table of Contents

- [Promote At The Right Time](#promote-at-the-right-time)
- [`AppSpec` Is The Real App Boundary](#appspec-is-the-real-app-boundary)
- [Supervision Strategy And Restart Policy](#supervision-strategy-and-restart-policy)
- [Mailbox Fairness And Extreme Backoff](#mailbox-fairness-and-extreme-backoff)
- [Designing `GenServer` Correctly](#designing-genserver-correctly)
- [Registry And Name Leases](#registry-and-name-leases)
- [Deterministic Ordering Matters](#deterministic-ordering-matters)
- [Migration Rule](#migration-rule)

## Promote At The Right Time

Use this escalation path:

| Need | Prefer |
|------|--------|
| local concurrent step | `Scope` |
| single-owner mailbox state | `actor` |
| typed request/reply service | `GenServer` |
| application topology with restart policy | `AppSpec` + `supervision` |

Do not leave a real service topology encoded as loose tasks plus incidental channels.

## `AppSpec` Is The Real App Boundary

Use `AppSpec` when the process has:

- always-on internal services,
- restart domains,
- explicit startup ordering,
- registry-backed naming,
- coordinated stop/join behavior.

What it buys:

- compiled supervision topology before touching runtime state,
- deterministic child start order,
- root-region budgeting,
- optional registry capability injection,
- explicit `AppHandle` lifecycle.

Important guidance:

- Treat `AppHandle` as obligation-like. Resolve it with `stop` / `join`; do not casually drop it.
- Put caches, control loops, pumps, and replication workers under the app tree instead of creating them from request handlers.

Current lifecycle mechanics are synchronous Phase 0:
`stop(&mut RuntimeState)` requests root-region cancellation, while
`join(&RuntimeState)` checks terminal state but does not drive the runtime.
Dropping an unresolved handle logs a leak only with `tracing-integration`.

Relevant paths:

- `src/app.rs`
- `examples/spork_minimal_supervised_app.rs`
- `examples/appspec_reference_journey.rs` (declarative `AppSpecV1` manifest ->
  compile -> deterministic lab proof, with the e2e artifact runner
  `scripts/run_appspec_reference_journey_e2e.sh`)

## Supervision Strategy And Restart Policy

These are different decisions:

- `SupervisionStrategy` answers what happens to the failed child itself.
- `RestartPolicy` answers what happens to siblings and ordering relationships.

Use restart policy to encode dependency shape:

- `OneForOne` for independent children,
- `OneForAll` when siblings share critical state,
- `RestForOne` when later children depend on earlier ones.

Know the current restart boundary: `CompiledSupervisor` compiles the topology
and computes deterministic restart plans (`restart_plan_for`), but tree-level
live restart-on-failure is still pending -- a child crash under a
`CompiledSupervisor` tree is not restarted automatically today. Live restart
is per-actor via `Scope::spawn_supervised_actor` (`src/actor.rs`), where the
mailbox persists across restarts and a restart budget bounds retries.

Do not fake this with manual restart loops hidden inside children.

Relevant paths:

- `src/supervision.rs`
- `docs/spork_glossary_invariants.md`

## Mailbox Fairness And Extreme Backoff

Published v0.4.9 closes two pathological liveness edges without changing the
public surface:

- Actor and `GenServer` receive and drain loops perform a real
  `runtime::yield_now().await` after each batch of eight continuously ready
  messages. Merely inspecting poll quota is not a scheduling point; a hot
  mailbox must actually return `Pending` so peer work can run.
- `BackoffStrategy::Exponential` sanitizes invalid multipliers and saturates
  conversion at the configured `max`, including `Duration::MAX`, instead of
  allowing an extreme floating-point duration to panic during conversion.

Do not infer priority fairness, a wall-clock latency bound, or live
tree-supervisor restarts from these repairs. The focused actor oracle proves a
bounded yield point after eight ready messages; the backoff oracle proves
non-panicking saturation.

The live `asupersync-9jygqo` actor/GenServer frontier still tracks stricter
waker-dedup oracle thresholds, GenServer keepalive behavior, buffered-message
loss if drain panics, and DPOR backtrack coverage. Treat those as open
validation boundaries and re-check Beads before making a completeness claim.

Relevant paths:

- `src/actor.rs`
- `src/gen_server.rs`
- `src/supervision.rs`

## Designing `GenServer` Correctly

`GenServer` is not merely "actor but with call/cast."

Important semantics:

- `call` creates a reply obligation,
- `cast` does not,
- `on_start` and `on_stop` have distinct budgets,
- drain and `on_stop` run masked so cleanup completes deterministically,
- mailbox overflow policy is explicit via `CastOverflowPolicy`.

Design advice:

- use `call` when the protocol requires acknowledgement or ownership transfer,
- use `cast` only when fire-and-forget is actually acceptable,
- choose overflow policy deliberately,
- shape API and state transitions so stop/drain semantics are unsurprising.

Relevant paths:

- `src/gen_server.rs`
- `docs/spork_glossary_invariants.md`

## Registry And Name Leases

There is no ambient global registry.

Use registry capability when you need named internal services. Names behave like
leases:

- they must be released or aborted,
- they clean up deterministically on termination,
- they should not outlive the owning region.

Important guidance:

- inject registry capability through `AppSpec` / `Cx`,
- avoid rebuilding a global singleton service locator,
- resolve named handles explicitly: `NamedGenServerHandle::stop()` plus
  `release_name(...)`, or `abort_lease(...)` when the name should be dropped.

Relevant paths:

- `src/cx/registry.rs`
- `src/app.rs`
- `src/gen_server.rs`
- `examples/spork_minimal_supervised_app.rs`

## Deterministic Ordering Matters

One hidden benefit of this layer is deterministic ordering for:

- child startup,
- restart behavior,
- registry cleanup,
- shutdown/drain sequencing,
- supervised trace analysis.

That is what makes "why did this worker restart before that one?" answerable from
artifacts rather than folklore.

Relevant paths:

- `docs/spork_deterministic_ordering.md`
- `docs/spork_glossary_invariants.md`

## Migration Rule

If a migrated service has:

- background task soup,
- shared mutable state hidden behind random channels,
- hand-rolled restart loops,
- ad hoc service discovery,

then promote it into `actor`, `GenServer`, or `AppSpec`/supervision instead of
trying to keep the old structure intact.
