# Tokio Compat Boundary

`asupersync-tokio-compat` is real and useful, but it is not the preferred architecture.

## When To Use It

Use compat only when a dependency still requires one of these:

- `tokio::runtime::Handle::current()`
- Tokio I/O traits
- hyper runtime traits
- a Tokio-hosted future that cannot be removed yet

Typical examples:

- `reqwest`
- `axum`
- `tonic`
- `sqlx`
- other crates that still assume Tokio is present

## Hard Rules

- the main `asupersync` crate must not depend on compat,
- Tokio must never become the primary executor for the application,
- `Cx` must cross the boundary explicitly,
- adapter-spawned work must still be region-owned and cancellation-aware.

## What Compat Actually Provides

- runtime bridge: `runtime::with_tokio_context(...)` and `AsupersyncRuntime::new(&cx).enter(...)`
- sync context bridges for construction paths that need a Tokio handle: `with_tokio_context_sync(...)`, `blocking::with_cx_sync(...)`
- Tokio <-> Asupersync IO adapters (`tokio-io` feature): `io::TokioIo<T>` (Asupersync stream -> Tokio/hyper traits), `io::AsupersyncIo<T>` (the reverse)
- hyper executor/timer/body bridges (`hyper-bridge` feature): `hyper_bridge::{AsupersyncExecutor, AsupersyncTimer}`, `body_bridge`
- tower bridge (`tower-bridge` feature): `tower_bridge::{FromTower, IntoTower}`
- cancellation policies for wrapped Tokio futures: `AdapterConfig` with `CancellationMode::{BestEffort, Strict, TimeoutFallback}` (default is `BestEffort`)

## Recommended Boundary Shape

Keep the whole thing in one module or crate.

Pattern:

- core domain code exposes native Asupersync interfaces,
- adapter module owns the Tokio-specific client/service,
- adapter functions accept `&Cx`,
- compat is the only place where Tokio types appear.

## Cancellation Policy Guidance

Compat exposes cancellation modes because Tokio-originated futures may not respect Asupersync semantics.

Prefer:

- strict handling when correctness matters (`Strict` returns `AdapterError::CancellationIgnored` if the future completes after cancel),
- explicit timeout fallback only when you understand the operational tradeoff,
- best-effort only for low-risk glue where native semantics are impossible — note this is the crate default, so set the mode deliberately.

## Removal Plan

Compat is successful only if it shrinks over time.

Good end state:

- domain and service code are fully native,
- one or two boundary modules remain for genuinely unavoidable third-party crates,
- or the compat layer is gone entirely.

Bad end state:

- compat spreads across the codebase,
- Tokio types leak into business logic,
- new features keep being built on the bridge instead of on native surfaces.
