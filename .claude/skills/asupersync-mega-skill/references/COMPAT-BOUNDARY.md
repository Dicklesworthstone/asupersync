# Tokio Compat Boundary

This is the canonical compatibility reference for the skill.
`asupersync-tokio-compat` is a separate, opt-in workspace crate containing
specific trait adapters and cancellation wrappers. It is **not** a Tokio
runtime, does not install a Tokio runtime handle, and does not by itself make a
Tokio-hosted application or library runnable on Asupersync.

## Table of Contents

- [When To Use It](#when-to-use-it)
- [Hard Rules](#hard-rules)
- [What Compat Actually Provides](#what-compat-actually-provides)
- [Recommended Boundary Shape](#recommended-boundary-shape)
- [Cancellation Policy Guidance](#cancellation-policy-guidance)
- [Removal Plan](#removal-plan)

## When To Use It

Use compat only when the remaining blocker matches an adapter that the crate
actually implements:

- Tokio `AsyncRead` / `AsyncWrite` trait compatibility,
- hyper executor, timer, or body traits,
- Tower `Service` conversion,
- an explicitly wrapped future whose cancellation behavior is tested at the
  boundary.

Do not infer support merely because a dependency uses one of those traits.
Libraries such as reqwest, axum, tonic, and SQLx can also depend on Tokio
runtime services, timers, spawning, networking, or `Handle::current()`. The
compat crate does not satisfy those requirements generically. Keep such a
dependency only after a representative downstream compile **and runtime** test
proves the exact path you use.

## Hard Rules

- the main `asupersync` crate must not depend on compat,
- Tokio must never become the primary executor for the application,
- `Cx` must cross the boundary explicitly,
- adapter-spawned work must still be region-owned and cancellation-aware.

## What Compat Actually Provides

- Asupersync-context helpers: `AsupersyncRuntime::new(&cx).enter(...)`,
  `runtime::with_tokio_context(...)`,
  `runtime::with_tokio_context_sync(...)`, and
  `blocking::{block_on_sync, block_with_cx, with_cx_sync}`;
  despite the historical name, these install or preserve `Cx`, not a Tokio
  `Handle`
- Tokio <-> Asupersync IO adapters (`tokio-io` feature): `io::TokioIo<T>` (Asupersync stream -> Tokio/hyper traits), `io::AsupersyncIo<T>` (the reverse)
- hyper executor/timer/body bridges (`hyper-bridge` feature): `hyper_bridge::{AsupersyncExecutor, AsupersyncTimer}`, `body_bridge`
- tower bridge (`tower-bridge` feature): `tower_bridge::{FromTower, IntoTower}`
- cancellation primitives for explicitly wrapped futures: `CancelAware` and
  `CancellationMode::{BestEffort, Strict, TimeoutFallback}`; `AdapterConfig`
  stores policy, but `with_tokio_context(...)` currently constructs
  `CancelAware` with `BestEffort` directly, so do not claim that changing
  `AdapterConfig` changes that helper

The `full` feature enables the three feature-gated adapter families above; it
does not add a Tokio runtime.

`AsupersyncExecutor::default()` / `noop()` intentionally drops submitted
futures. Production hyper use must install an owned spawn path explicitly with
`AsupersyncExecutor::with_spawn_fn(...)`; the default is a structural adapter,
not a working executor. The body helpers collect complete bodies (optionally
with a byte limit); they are not proof of an unbounded streaming-body bridge.
`AsupersyncTimer` currently starts one background OS thread per sleep and is
documented for moderate adapter timer counts, not a high-cardinality timer
wheel. Treat load behavior as part of the boundary proof.

The authoritative implementation is
`asupersync-tokio-compat/src/runtime.rs`, `cancel.rs`, and the feature-gated
adapter modules. Architecture and migration documents are useful intent, but
source plus downstream execution evidence determines current support.

## Recommended Boundary Shape

Keep the whole thing in one module or crate.

Pattern:

- core domain code exposes native Asupersync interfaces,
- adapter module owns the Tokio-specific client/service,
- adapter functions accept `&Cx`,
- compat is the only place where Tokio types appear.

## Cancellation Policy Guidance

Compat exposes cancellation modes because wrapped futures may not respect
Asupersync semantics.

Prefer:

- explicit `CancelAware` handling when correctness matters (`Strict` returns
  `CancelResult::CancellationIgnored(value)` if the wrapped future completes
  after cancellation),
- explicit timeout fallback only when you understand the operational tradeoff,
- best-effort only for low-risk glue where native semantics are impossible.

Test cancellation, timer behavior, task ownership, and shutdown at the real
adapter boundary. A trait-level compile is not proof that the dependency's
runtime assumptions have been met.

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
