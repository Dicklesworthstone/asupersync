# Greenfield Patterns

## Golden Rules

1. Every effectful async function that matters should accept `&Cx`.
2. Concurrency belongs in regions/scopes, not detached executors.
3. Cancellation checkpoints belong in loops and long-running work.
4. Message and resource lifecycles should resolve obligations explicitly.
5. Deterministic tests are part of the design, not a later add-on.
6. Budgets belong to failure domains; do not make everything `Budget::INFINITE`.
7. Preserve `Outcome::Cancelled` and `Outcome::Panicked` until a real policy boundary.

## Choose The Right Level

Do not make every greenfield app a pile of naked spawned tasks.

| Need | Preferred Level |
|------|-----------------|
| Request-local orchestration | `Cx` + `Scope` |
| HTTP / gRPC edge | `web::*`, `service::*`, `grpc::*`, request/call contexts |
| Stateful mailbox worker | `actor.rs` |
| Stateful request/reply service | `gen_server.rs` |
| Multi-child application lifecycle | `AppSpec` + `supervision` + optional `spork` |
| Retry / hedge / quorum / pipeline orchestration | native combinators + plan rewrite |

If the system has named workers, restart policy, or explicit startup/shutdown topology, graduate to `AppSpec` early instead of bolting those concerns onto raw task spawning later.

## Minimal Bootstrap

Current bootstrap pattern from the README:

```rust,ignore
use asupersync::{Cx, Error};
use asupersync::runtime::RuntimeBuilder;

async fn run(cx: &Cx) -> Result<(), Error> {
    cx.trace("worker running");
    cx.checkpoint()?;
    Ok(())
}

fn main() -> Result<(), Error> {
    let runtime = RuntimeBuilder::current_thread().build()?;
    let result = runtime.block_on(runtime.handle().spawn(async {
        let cx = Cx::current().expect("runtime task Cx");
        run(&cx).await
    }));
    result?;
    Ok(())
}
```

Use this as the production orientation example. Keep `Cx::for_request()` and
`Cx::for_testing()` in test/internal harnesses. `RuntimeHandle::spawn` is the
small teaching shape; use `try_spawn` / `try_spawn_with_cx` when bootstrap
admission failure must be handled without panicking.

## Long-Lived Service Skeleton

If the process has real always-on topology, graduate quickly from `block_on(...)`
to `AppSpec`:

```rust,ignore
use asupersync::app::AppSpec;
use asupersync::supervision::RestartPolicy;

let app = AppSpec::new("api")
    .with_budget(app_budget)
    .with_registry(registry_cap)
    .with_restart_policy(RestartPolicy::OneForOne)
    .child(http_child())
    .child(replication_child())
    .start(&mut state, &cx, parent_region)?;

// later: stop / join explicitly
```

Important guidance:

- `AppSpec` is the right unit for long-lived service trees.
- `AppHandle` is a real lifecycle handle; resolve it explicitly.
- Put background loops and internal services under the app tree instead of
  smuggling them out through detached tasks.

## Runtime Shape Is Part Of The Design

Choose runtime preset and knobs intentionally.

- `current_thread()` for simple services, CLIs, or deterministic-first builds
- `low_latency()` for request/response systems
- `high_throughput()` for queue-heavy or batch-heavy servers

Then tune only what the workload actually needs:

- blocking pool bounds,
- deadline monitoring,
- root-region limits,
- observability/metrics,
- cancel-streak and governor controls if cancellation pressure matters.

## Native Function Shape

Preferred shape for effectful operations:

```rust,ignore
async fn do_work(cx: &Cx, input: Input) -> Result<Output, Error> {
    cx.checkpoint()?;
    // effectful logic here
    Ok(output)
}
```

If the function is pure, keep `Cx` out of it.

## Capability-Narrowed Edge Pattern

At framework or handler boundaries, narrow `Cx` instead of passing full authority everywhere.

```rust,ignore
async fn handler(ctx: &RequestContext<'_>) -> Response {
    let cx = ctx.cx_narrow::<RequestCaps>();
    cx.checkpoint().ok();
    // handler logic with only the capabilities it actually needs
}
```

This is the practical shape behind capability security in downstream apps.

## Owned Concurrency Pattern

```rust,ignore
let mut a = cx.spawn(|task_cx| async move { worker_a(&task_cx).await })?;
let mut b = cx.spawn(|task_cx| async move { worker_b(&task_cx).await })?;
let ra = a.join(cx).await?;
let rb = b.join(cx).await?;
```

`scope!` binds the current-region scope; it does not create a fresh child-region
boundary. `Cx::spawn_in` targets an existing scope's region. Use
`Scope::region(...)` when a new structural child region must close to
quiescence before you proceed.

## Cancellation-Safe Send Pattern

```rust,ignore
let permit = tx.reserve(cx).await?;
permit.send(message)?;
```

Do not reserve and then await unrelated work while holding the permit unless
you fully understand the failure mode.

## Orchestration Pattern

When the system needs retries, quorums, hedging, bulkheads, or structured cleanup, prefer native combinators over open-coded orchestration.

Good fit:

- fan-out request paths,
- external API integrations,
- consensus-ish flows,
- multi-stage processing pipelines.

Why:

- loser drain is explicit,
- budget behavior is explicit,
- the plan rewrite layer can optimize while preserving invariants.

## Web-App Pattern

Native high-level web API from `src/web/mod.rs`:

```rust,ignore
use asupersync::web::{Router, Json, State, get, post};

async fn list_users(State(db): State<Db>) -> Json<Vec<User>> {
    Json(db.list_users().await)
}

async fn create_user(State(db): State<Db>, Json(input): Json<CreateUser>) -> StatusCode {
    db.insert(input).await;
    StatusCode::CREATED
}

let app = Router::new()
    .route("/users", get(list_users).post(create_user))
    .with_state(db);
```

For framework authors, prefer `Cx` wrappers instead of exposing the whole effect
surface to handlers.

## Actor / Supervision Pattern

If the app wants OTP-style components:

- use `actor.rs` for bounded mailbox actors
- use `gen_server.rs` for request/reply servers
- use `supervision.rs` for restart topology
- inspect `examples/spork_minimal_supervised_app.rs`

## Pick The Right Surface

| Need | Prefer |
|------|--------|
| local fork/join work | `Scope` + child regions |
| single-owner mailbox state | `actor` |
| typed request/reply state machine | `GenServer` |
| restartable service topology | `AppSpec` + `supervision` |
| protocol edge with linear reply/resource semantics | session / tracked channels |

Do not force all concurrency through one pattern.

## Budget And Outcome Discipline

Good default posture:

- give adapters, hedges, and cleanup phases tighter budgets than core request handling,
- keep `Cancelled` distinct from ordinary error for shutdown and retry policy,
- keep `Panicked` distinct from recoverable error,
- use masked cleanup sparingly and only for bounded release/finalize sections.

This is where Asupersync becomes structurally different from ad hoc async code.

## Capability-Boundary Pattern

Prefer boundaries that narrow authority:

- request region + narrowed `Cx` for HTTP,
- call context + narrowed `Cx` for gRPC,
- registry capability injection for named internal services,
- no ambient singleton service locators.

Read next:

- `WEB-GRPC-HTTP.md`
- `LEVERAGE-PLAYBOOK.md`

## Resilience Composition

Do not hand-write every timeout/retry/select pattern.

Reach for:

- `service::ServiceBuilder` for timeout, load shedding, concurrency limit, rate limit, and retry,
- combinators like `hedge`, `quorum`, and `bracket` when orchestration itself is part of the design,
- plan/rewrite surfaces when the orchestration graph becomes large enough to justify lawful rewriting.

If loser cleanup matters, prefer surfaces that make drain behavior explicit and testable.

If the app has multiple long-lived children or named services, prefer `AppSpec` as the root of the application instead of manual boot code.

## Greenfield Defaults By App Type

| App Type | Default Stack |
|----------|---------------|
| Internal HTTP API | `RuntimeBuilder` + `web` + `service` + `http` + `database` |
| gRPC service | `RuntimeBuilder` + `grpc` + `service` + `database` |
| Agent / worker system | `RuntimeBuilder` + `channel` + `sync` + `actor` / `GenServer` / `spork` |
| Protocol server | `RuntimeBuilder` + `io` + `net` + `codec` |
| Deterministic test harness | `LabRuntime` + targeted channels/sync/combinators |
| Browser runtime | Browser Edition lane only; use the browser / wasm reference in this skill |

## Greenfield Upgrade Triggers

Move from "basic native runtime" to the richer Asupersync stack when you see any of these:

- background tasks that really want ownership and restart policy,
- request handlers spawning child work that must drain cleanly,
- need for named workers or registry leases,
- repeated retry/timeout/select logic that wants combinators,
- operator need to explain stuck work or stalled shutdown,
- distributed or quorum-aware coordination requirements.
