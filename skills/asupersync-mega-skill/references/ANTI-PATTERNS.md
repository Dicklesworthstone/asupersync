# Asupersync Anti-Patterns

These are the fastest ways to sabotage a migration.

## Architecture Mistakes

- Treating Asupersync as a drop-in executor swap.
- Keeping Tokio as a silent co-runtime in core code.
- Hiding `Cx` in globals, thread-locals, or hidden framework state.
- Building new features on compat because it is easier than going native.
- Treating `RuntimeBuilder + block_on` as the final architecture for a long-lived service that really wants `AppSpec` / supervision.
- Recreating a global process registry or service locator instead of using capability-scoped naming.

## Concurrency Mistakes

- Leaving `tokio::spawn` or detached equivalents inside handlers and services.
- Starting request-local or task-local work with no owning region.
- Using race/select patterns that abandon losers without proving cleanup.
  The `race!` and blocking `select!` macros are drain-correct (they expand to
  `Cx::race_drained*`; the drop-only expansion is no longer emitted), but
  `race!`'s `timeout:` path abandons the whole race by drop on elapsed, the
  `select!` `else` form never drains, and calling `Cx::race` directly is
  drop-on-cancel.
- Forgetting checkpoints in loops, retries, or long handlers.
- Calling `spawn_local` from plain `block_on`, an entry-macro body, or
  `run_test_with_cx` and treating ASUP-E004 as a runtime bug. Those contexts do
  not install a worker-local lane; enter a real owning worker first.
- Routing a local task or cancellation by numeric worker id without verifying
  runtime/scheduler ownership.
- Holding wide cancellation masks around normal business logic instead of short cleanup-critical sections.

## Resource / Cleanup Mistakes

- Holding permits, locks, or leases across indefinite waits.
- Expecting borrowed `MutexGuard<'_, T>` to migrate between workers. Use an
  owned guard for movable work or acquire the borrowed guard inside a true local
  task; do not make the guard unsafely Send.
- Assuming drop-based cleanup is good enough.
- Failing to verify quiescence and leak behavior after migration.
- Dropping `AppHandle`, named-server lease handles, or other obligation-like lifecycle handles without explicit resolution.
- Using plain channels where reply obligations or typed protocol edges should be explicit.

## Testing Mistakes

- Converting runtime code but leaving `#[tokio::test]` patterns untouched.
- Using wall clock or ambient randomness in deterministic tests.
- Accepting non-deterministic flakes as normal after adopting Asupersync.
- Only testing happy-path completion and never testing cancel/drain/finalize behavior.
- Ignoring replay artifacts, futurelock warnings, or leak oracles because "the test usually passes."
- Treating a Lab `ForcedSchedule` checksum as authentication, a deletion-only
  candidate as proof that the failure persists, or exact Lab replay as a
  substitute for a native scheduler/cancellation regression.

## API / Ergonomics Mistakes

- Assuming proc macros are more authoritative than manual APIs. Current
  contract: `scope!` does not create a fresh child-region boundary (use
  `Scope::region(...)` for quiescence on exit), `join!` / `join_all!` poll
  branches concurrently in one `poll_fn`, and `race!` / blocking `select!`
  drain losers (branches must be `Send + 'static` with spawn authority).
- Working around cancellation by smuggling results out of tasks: since v0.4.4,
  ordinary `Cx::spawn*` preserves a task's typed result after it acknowledges
  cancellation, so a concurrent abort does not erase it.
- Overusing `Cx::for_testing()` or `Cx::for_request()` instead of designing the real ownership flow.
- Passing full-capability `Cx` everywhere instead of narrowing at boundaries.
- Flattening `Outcome::Cancelled` and `Outcome::Panicked` into generic `Err` too early.
- Using `Budget::INFINITE` everywhere because budget design feels inconvenient.

## Status / Capability Mistakes

- Assuming every feature documented in the repo is equally mature.
- Ignoring bounded classifications: QUIC/H3 is feature-gated with an explicitly
  scoped threat model, messaging (Redis/NATS/Kafka) is still early, the
  filesystem layer is a blocking-backed facade rather than full `tokio::fs`
  parity, the web layer is native primitives rather than axum/warp parity, and
  Windows/BSD reactors are intentionally narrower than Linux epoll/io_uring.
  Check the README "Tokio Ecosystem Coverage Map" and
  `docs/platform_capability_matrix.md` for the current row before promising a
  surface.

## Recovery Rule

If you notice any of the above, stop optimizing for low churn. Rework the design around:

- explicit `Cx`,
- region-owned work,
- native replacements,
- deterministic validation,
- explicit boundary bridges only where unavoidable.
