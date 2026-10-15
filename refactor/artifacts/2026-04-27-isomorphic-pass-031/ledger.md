# Isomorphic Simplification Pass 031

## Candidate

- File: `src/trace/event.rs`
- Lever: generate repeated `TraceEvent` constructor wrappers with local macros.
- Score: `(LOC_saved 4 * confidence 5) / risk 1 = 20.0`

## Isomorphism Proof

- Inputs covered: public `TraceEvent::{spawn,schedule,yield_task,wake,poll,complete,cancel_request,worker_cancel_requested,worker_cancel_acknowledged,worker_drain_started,worker_drain_completed,worker_finalize_completed,region_created,region_cancelled,time_advance,timer_scheduled,timer_fired,timer_cancelled,io_requested,io_ready,io_result,io_error,rng_seed,rng_value,checkpoint,obligation_reserve,obligation_commit,obligation_abort,obligation_leak,monitor_created,monitor_dropped,down_delivered,link_created,link_dropped,exit_delivered,user_trace}` keep the same names, visibility, argument order, argument types, and return type.
- Ordering preserved: every generated constructor still makes exactly one call to `Self::new(seq, time, TraceEventKind::..., TraceData::...)` or `Self::worker_lifecycle(...)` with arguments in the same order.
- Tie-breaking: unchanged / N/A.
- Error semantics: unchanged; constructors are infallible and retain the same `TraceData` payload variants and option fields.
- Laziness: unchanged; only `worker_id.into()` and `message.into()` conversions remain at the same constructor boundary.
- Short-circuit eval: N/A.
- Floating-point: N/A.
- RNG / hash order: unchanged / N/A.
- Observable side effects: none; constructors only allocate payload values as before.
- Public docs and attributes: existing doc comments, `#[must_use]`, and `#[allow(clippy::too_many_arguments)]` on high-arity constructors are preserved through macro expansion.

## Metrics

- Source LOC before: 4412
- Source LOC after: 3987
- Source LOC delta: -425
- Source diff numstat: 199 insertions, 624 deletions

## Validation

- `rustfmt --edition 2024 --check src/trace/event.rs`: pass
- `git diff --check -- src/trace/event.rs refactor/artifacts/2026-04-27-isomorphic-pass-031/ledger.md`: pass
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-pass031-trace-event-test -p asupersync --lib trace::event`: blocked by 3 pre-existing worker redaction expectation failures. Constructor tests in the same run passed, including `worker_lifecycle_constructors_preserve_payload_shape`; HEAD already has `browser_trace_log_fields_with_capture` redacting worker IDs while tests assert unredacted `worker_id`.
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-pass031-constructor-test2 -p asupersync --lib constructor`: inconclusive; local stream ended without a captured cargo summary while the remote job later cleared from the queue.
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-pass031-worker-constructor-exact -p asupersync --lib worker_lifecycle_constructors_preserve_payload_shape`: pass, 1 passed, 0 failed, 15167 filtered out.
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-pass031-check2 -p asupersync --lib`: pass.
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-pass031-clippy-lib2 -p asupersync --lib -- -D warnings`: pass.

## Fresh-Eyes Review

- Re-read the source diff after rustfmt; the macro only emits the same public constructor wrappers and keeps payload construction expressions unchanged.
- Rechecked `git diff --name-only --diff-filter=U`; the shared index is no longer unmerged.
- Reservations for `src/trace/event.rs` and this ledger were renewed through `2026-04-27T06:32:23Z`.
- `src/trace/snapshots/asupersync__trace__event__tests__browser_trace_log_fields_worker_scrubbed.snap.new` was produced by the failed insta assertion and was intentionally not deleted.
