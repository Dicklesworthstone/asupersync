# Advanced Features Worth Exploiting

Once the basic migration is native, the next gains come from using Asupersync as more than a runtime replacement.

## Start With The Three High-Leverage Deep Dives

- runtime shaping and operator controls,
- supervised/stateful application design,
- diagnostics, metrics, and failure forensics.

Those are where most "we switched runtimes but still think like Tokio" gaps show up.

Read:

- `LEVERAGE-PLAYBOOK.md`
- `RUNTIME-CONTROLS.md`
- `OBSERVABILITY-FORENSICS.md`
- `GREENFIELD-PATTERNS.md`

## Supervision, AppSpec, And Spork

The highest-value advanced app-model story is:

- `AppSpec` for application topology,
- `supervision` for restart policy and deterministic child ordering,
- `actor` / `GenServer` / Spork for stateful internal services,
- registry capability plus name leases for named components.

This is the right promotion path when a system has always-on workers, caches,
control loops, subscription pumps, or restart domains. It is usually cleaner
than trying to fake those concerns with detached tasks and ad hoc channels.

## Resilience Combinators And Plan Rewrites

Do not reimplement resilience policy with open-coded loops and ad hoc `select!` logic if the system needs real orchestration.

High-value native surfaces include:

- `quorum`
- `hedge`
- `adaptive_hedge`
- `bulkhead`
- `rate_limit`
- `retry`
- `bracket`
- `pipeline`
- `map_reduce`
- `circuit_breaker`

Why they matter:

- they are already cancel-aware,
- loser-drain semantics are part of the design,
- budget and outcome behavior are explicit,
- the plan rewrite engine can optimize combinator DAGs without silently breaking cancel/drain/quiescence invariants.

Use these when building:

- gateways,
- parallel fan-out request paths,
- consensus/quorum workflows,
- data pipelines,
- rate-limited external integrations.

Relevant sources:

- `src/combinator/`
- `src/combinator/laws.rs`
- `src/plan/rewrite.rs`
- `src/plan/analysis.rs`

Also remember:

- keep `Outcome::Cancelled` and `Outcome::Panicked` distinct at policy boundaries,
- use tighter budgets for hedges, cleanup, and adapters,
- prefer lawful orchestration surfaces over open-coded select forests.

## Remote / Distributed Surfaces

Asupersync has more than local task orchestration.

Important advanced surfaces include:

- named remote spawn instead of closure shipping,
- obligation-backed leases,
- idempotency store for retry-safe remote execution,
- session-typed protocol state machines,
- logical-time envelopes for causal correlation,
- saga compensation flow,
- distribution with quorum and optional hedging,
- RaptorQ-backed snapshot/distribution machinery.

Use these only when the target system actually has distributed semantics. They are not decorative features.

Relevant sources:

- `src/remote.rs`
- `src/distributed/`
- `src/raptorq/`

## Advanced Service Edge Design

At the service edge, the high-value move is not just "port the router." It is:

- request-as-region isolation,
- least-privilege `Cx` narrowing,
- service/combinator composition instead of tower-first thinking,
- deadlines and cancellation made visible at the boundary.

Relevant references live in the skill entrypoint:

- web and gRPC patterns,
- runtime controls.

This is also where capability security becomes real instead of rhetorical:

- narrowed `Cx` for handlers,
- read-only contexts where appropriate,
- no hidden runtime globals or service locators,
- background components promoted into supervised app structure rather than booted from handlers.

## Protocol Breadth And Maturity

Broadly strong native surfaces:

- HTTP/1.1
- HTTP/2
- TLS
- WebSocket
- database clients
- service/middleware composition

Surfaces to validate before promising downstream parity:

- QUIC / HTTP3
- some messaging integrations
- some browser/wasm adapters
- niche distributed paths

That means the skill should steer users toward native breadth confidently, but still verify the exact advanced path they need.

## Guidance For Ambitious Systems

- Use child-region budgets and root-region limits deliberately.
- Promote long-lived state into supervised structures instead of background task soup.
- Use diagnostics and lab forensics before issues become production folklore.
- Prefer native combinators and service layers over carrying tower/Tokio-era abstractions forever.
- Measure with real metrics or benches when tuning runtime knobs.
- Treat obligation-tracked channels, reply obligations, and lease cleanup as application-design tools, not only runtime internals.
