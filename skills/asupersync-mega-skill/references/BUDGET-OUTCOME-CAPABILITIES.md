# Budget, Outcome, And Capability Security

These three concepts are not side details in Asupersync. They are the control
plane for application semantics.

If a migration keeps `Cx` but still thinks in terms of "plain `Result`,
ambient authority, and best-effort cleanup", it has not really adopted
Asupersync yet.

## Outcome Discipline

`Outcome<T, E>` is deliberately four-valued:

- `Ok(T)`
- `Err(E)`
- `Cancelled(CancelReason)`
- `Panicked(PanicPayload)`

The repo treats this as a severity lattice:

- `Ok < Err < Cancelled < Panicked`

Practical downstream rule:

- preserve all four states as long as you can,
- collapse them only at a real policy boundary such as HTTP, CLI, RPC, queue
  ack, or supervision policy.

Why this matters:

- `Cancelled` is not "just another error". It changes retry, shutdown,
  observability, and drain behavior.
- `Panicked` is not a recoverable domain error. It is a stronger failure that
  should usually page supervision, emit heavier evidence, or map to a hard
  service failure.
- outcome severity composes across joins, races, retries, and supervision in a
  way a flattened `Result<T, anyhow::Error>` cannot.

Good policy boundary examples:

- HTTP: `Cancelled -> 499`, `Panicked -> 500`
- gRPC/service edge: map `Cancelled` to caller-aborted/deadline semantics,
  not generic internal failure
- worker/queue loop: distinguish retryable application error from shutdown or
  sibling fail-fast cancellation

Bad pattern:

- converting everything to `Err(String)` at the first adapter boundary

## Budget Discipline

`Budget` is not a timeout convenience; it is the explicit statement of how much
work a failure domain may consume.

Key fields in the repo's model:

- deadline
- poll quota
- cost quota
- priority

The important algebraic rule is `meet()`:

- outer budget and inner budget combine by taking the tighter constraint,
- child work should usually inherit a stricter effective budget than the caller,
- budget propagation is part of correctness, not only performance tuning.

Practical downstream rules:

- give cleanup a bounded budget,
- give hedged or speculative work a tighter budget than the main request,
- give backoff/retry loops a total budget, not just per-attempt sleeps,
- do not use `Budget::INFINITE` for every request path just because it is easy.

Use budget deliberately by surface:

| Surface | Default Posture |
|--------|------------------|
| user request | clear deadline + moderate poll quota |
| retry wrapper | total retry budget tighter than caller |
| hedge / quorum branch | smaller budget than primary branch |
| cleanup/finalize | short bounded budget |
| root background service | broader budget, but still finite where possible |

Good pattern:

- parent request gets the SLA budget,
- DB fallback or hedge gets a smaller child budget,
- shutdown/finalizer path gets a short masked cleanup budget.

Bad patterns:

- `Budget::INFINITE` everywhere
- using timeout wrappers without reasoning about the cleanup budget of the
  cancelled work
- unbounded retry loops that ignore budget exhaustion

## Cancellation Severity Matters

`CancelReason` is structured, not decorative. Examples in the repo include:

- `User`
- `Timeout`
- `FailFast`
- `RaceLost`
- `ParentCancelled`
- `Shutdown`

Use that structure.

Practical policy advice:

- `RaceLost` usually means "loser must drain quietly", not "error the request"
- `Timeout` often means retry or degrade
- `Shutdown` means stop acquiring new work and prioritize bounded cleanup
- `FailFast` often means sibling topology or supervision policy is in charge,
  not local recovery

## Capabilities Are The Security Model

The capability row is type-level and compile-time enforced:

- `[SPAWN, TIME, RANDOM, IO, REMOTE]`

The core repo model in `src/cx/cap.rs` matters for downstream design:

- capability rows are zero-cost marker types,
- `SubsetOf` encodes monotone narrowing,
- widening is compile-time rejected,
- marker traits are sealed to prevent external capability forgery.

That means least privilege is not just documentation. It can be part of the
Rust type system.

What this buys downstream:

- handlers can get only the effects they actually need,
- framework wrappers can offer `cx_readonly()` or narrowly scoped `cx_narrow()`,
- application services can prevent accidental spawning, I/O, randomness, or
  remote execution from the wrong layer,
- ambient service-locator style design becomes structurally harder.

## Common Capability Shapes

Representative patterns visible in repo docs and wrappers:

| Boundary | Typical Shape | Why |
|---------|----------------|-----|
| pure domain logic | no `Cx` or `cap::None` | no effects at all |
| read-only request logic | `cx_readonly()` | inspect cancel/budget without effectful authority |
| HTTP/gRPC handler | narrowed request caps | allow only spawn/time or other explicitly required effects |
| background orchestration | spawn/time, maybe remote | no accidental I/O or random unless intended |
| entropy-specific subsystem | random-only narrow | keep randomness explicit |

Do not default to full `All` capabilities in every layer.

## Framework Boundary Rule

The best Asupersync wrappers do this:

1. receive a real runtime-managed `Cx`,
2. wrap it in a framework-specific context,
3. narrow capability exposure at the boundary,
4. let deeper layers accept only the narrowed `Cx` they actually need.

Good examples to model:

- HTTP request regions via `web::request_region`
- gRPC call wrappers via `grpc::CallContext::with_cx(...)`

## Masking Rule

`mask()` is for bounded release/finalize sections, not general control flow.

Use masking only when all of these are true:

- the code is in a narrow cleanup/reply/finalize section,
- the work has a bounded budget,
- you understand exactly what invariant must be preserved before cancellation
  becomes observable again.

Do not use masking to hide sloppy cancellation handling.

## Design Patterns That Actually Pay Off

### Pattern 1: Preserve Outcome To The Edge

- internal services return `Outcome` or preserve equivalent information
- transport adapter decides how to map it
- retry/supervision policy sees the real failure class

### Pattern 2: Budget The Whole Flow

- request gets a budget
- retry/hedge branches inherit tighter child budgets
- finalizers get separate bounded cleanup budgets
- tests assert exhaustion and cleanup behavior explicitly

### Pattern 3: Narrow Authority Early

- handlers do not receive global singletons
- boundary wrapper exposes limited `Cx`
- pure domain code remains pure

## Anti-Patterns

- passing a full-power `Cx` through the whole program "for convenience"
- flattening `Cancelled` and `Panicked` into ordinary error early
- using timeout as policy while ignoring loser-drain and finalization cost
- making `Budget::INFINITE` the default for all request paths
- masking wide sections of business logic instead of fixing protocol edges

## When To Read Next

- For concrete request/call boundary patterns: `WEB-GRPC-HTTP.md`
- For runtime knobs: `RUNTIME-CONTROLS.md`
- For diagnostics and forensics: `OBSERVABILITY-FORENSICS.md`
- For supervision and long-lived apps: `SUPERVISION-OTP.md`
- For migration mistakes: `ANTI-PATTERNS.md`
