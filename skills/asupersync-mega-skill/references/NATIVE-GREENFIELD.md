# Native Greenfield Asupersync

This is the preferred path when you control the architecture.

## Table of Contents

- [Build Around The Real Core](#build-around-the-real-core)
- [Process Bootstrap](#process-bootstrap)
- [API Design Rules](#api-design-rules)
- [Request / Service Shape](#request--service-shape)
- [Concurrency Guidance](#concurrency-guidance)
- [Supervision / OTP-Style Systems](#supervision--otp-style-systems)
- [Greenfield Default Stack](#greenfield-default-stack)
- [Greenfield Validation Checklist](#greenfield-validation-checklist)

## Build Around The Real Core

- `#[asupersync::main]` is the default entry point; `RuntimeBuilder` owns explicit runtime bootstrap and process-level configuration.
- `Cx` is the capability token that carries cancellation, tracing, time, randomness, budget, and scoped authority.
- `Scope` owns spawned work and child regions.
- `LabRuntime` gives deterministic execution, replay, and invariant checks.
- `AppSpec` / supervision / actors / spork are higher-level composition layers when you need long-lived supervised systems.

## Process Bootstrap

Default pattern (README Quick Example / `examples/onramp_level0.rs`):

```rust
use asupersync::{main, prelude::*};

#[main]
async fn main(cx: &Cx) -> Result<(), Error> {
    cx.checkpoint()?;
    Ok(())
}
```

`#[main]` builds and drives the production runtime. The `cx: &Cx` parameter
and the `Result` return are both optional. It requires the default
`proc-macros` feature; `#[asupersync::test]` and `#[lab_test]` are the test
counterparts. The graduated on-ramp (`docs/onramp.md`,
the `examples/onramp_level0.rs` through `examples/onramp_level3.rs` series)
layers in prelude, `Cx`, `Outcome`, `Budget`,
scopes/`JoinSet`, and lab oracles one level at a time.

When you need explicit runtime construction (embedding, custom knobs), use
`RuntimeBuilder::current_thread().build()?` plus `runtime.block_on(...)` /
`runtime.handle().spawn(...)`. Production `Cx` values come from
runtime/request/service boundaries. Current source also provides
`Runtime::request_cx_with_budget(...)` and
`RuntimeHandle::{request_cx_with_budget,try_request_cx_with_budget}` for
externally initiated operations; the handle methods ship in v0.4.9. Keep
`Cx::for_request()` /
`Cx::for_testing()` in test-internals or local harnesses, not in production
bootstrap examples. `RuntimeHandle::spawn` is the compact orientation path;
use `try_spawn` / `try_spawn_with_cx` when admission failure must be handled
explicitly.

Useful runtime builder levers:

- worker count
- blocking pool bounds
- observability hooks
- deadline monitoring
- env or config-file overrides
- logical clock mode
- root-region limits

## API Design Rules

- Put `&Cx` first in async APIs you own.
- Use `Scope` or child-region APIs for owned concurrency.
- Add checkpoints in loops, long retries, and handler bodies.
- Surface cancellation, panic, or cleanup semantics at orchestration boundaries.
- Narrow `Cx` capabilities at framework boundaries instead of passing full power everywhere.

## Request / Service Shape

Good pattern:

- per-request region or per-call region,
- wrap request metadata and `Cx` together,
- narrow capabilities for handlers,
- let handler-spawned work live inside the request region.

Relevant repo patterns:

- `web::request_region::{RequestRegion, RequestContext}`
- `grpc::CallContext::with_cx(...)`

## Concurrency Guidance

Prefer:

- `Cx::spawn` for current-region child work
- `Cx::spawn_in` for targeting an existing scope's region
- `cx.scope()` / `cx.scope_with_budget(...)` for a current-region scope; `JoinSet::new(&scope)` or `JoinSet::in_cx(cx)` for dynamic fan-out
- `Scope::region(...)` for explicit child-region boundaries and tighter budgets
- explicit race/join semantics that preserve loser draining where needed (`race!(cx, ...)`, `cx.race_drained(...)`)
- native channel and sync primitives

Be careful with:

- `Scope::spawn_registered`, which is a lower-level boot/test path for callers
  already holding `&mut RuntimeState`
- `Cx::race` / `race_named` / `race_timeout`, which do not prove losers drained;
  prefer the `race_drained*` family when drain is part of the contract

If loser drain matters, use the manual scope/task APIs that preserve the stronger semantics.

## Supervision / OTP-Style Systems

Reach for:

- `app::AppSpec`
- `actor`
- `gen_server`
- `supervision`
- `spork`

Use these when your system has:

- long-lived workers,
- named processes or registries,
- restart strategies,
- explicit application startup/shutdown trees.

Supervision status: per-actor live restart is real today
(`Scope::spawn_supervised_actor` in `src/actor.rs`); the Spork
`CompiledSupervisor` computes deterministic restart plans, but tree-level live
restart-on-failure is still pending.

The best repo examples are `examples/spork_minimal_supervised_app.rs` and
`examples/appspec_reference_journey.rs` (declarative `AppSpecV1` topology run
through the lab runtime).

## Greenfield Default Stack

For a fully native app, prefer this stack:

- runtime: `RuntimeBuilder`
- app/task model: `Cx`, `Scope`, child regions
- channels/sync: `channel::*`, `sync::*`
- time: `time::*`
- networking: `net::*`, `tls::*`, `web::websocket::*`
- web: `web::*`, `service::*`
- grpc: `grpc::*`
- database: `database::*`
- testing: `test_utils`, `LabRuntime`
- observability: `observability::*`

## Greenfield Validation Checklist

- all owned async APIs accept `&Cx`,
- no detached tasks,
- checkpoints exist in long-running loops,
- service boundaries narrow capabilities,
- tests use deterministic helpers,
- no Tokio dependency is present in core code.
