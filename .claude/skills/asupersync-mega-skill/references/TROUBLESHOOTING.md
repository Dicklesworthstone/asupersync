# Troubleshooting

Runtime diagnostics carry stable `ASUP-Exxx` error-code tokens. The canonical
registry (with probable causes and remediation per code) is
`docs/error_codes/registry.json`, with per-code pages under `docs/error_codes/`.

## Contents

- [Obligation Leaks](#obligationleak-detected-asup-e101)
- [Local Scheduler Unavailable](#local-scheduler-unavailable-asup-e004)
- [Runtime-Handle Request Context](#runtime-handle-request-context-failed)
- [Bounded Shutdown](#bounded-shutdown-returned-false)
- [Cancellation and Futurelock](#cancel-drain-timeout-canceltimeout--asup-e301)
- [Deterministic Drift](#deterministic-drift-asup-e403-lab-seed-nondeterminism)
- [Compat and Browser Boundaries](#compat-bridge-trouble)
- [Advanced Surface Caution](#advanced-surface-caution)

## "ObligationLeak detected" (ASUP-E101)

Meaning:

- A permit, ack, lease, or similar obligation was not committed or aborted.

Typical cause:

- reserving a send or resource and returning early

Fix:

- always resolve the obligation explicitly
- avoid holding it across unrelated awaits unless that is the protocol

## Local Scheduler Unavailable (ASUP-E004)

Meaning:

- `spawn_local` was called without an active owning scheduler-worker lane, or
  the visible lane belongs to another runtime.

Common trap:

- a direct `Runtime::block_on`, entry-macro body, `run_test`, or
  `run_test_with_cx` has an ambient `Cx` but is not itself a worker-local lane.

Fix:

- enter a real worker with `runtime.block_on(runtime.handle().spawn(async {
  ... }))`, obtain `Cx::current()` there, and create the `!Send` future/guard
  inside the worker-local task;
- do not bypass the ownership check or convert borrowed guards to unsafe Send.

## Runtime-Handle Request Context Failed

This API ships in v0.4.9; older 0.4.x crates do not expose it.

Meaning:

- `RuntimeHandle::try_request_cx_with_budget` returned
  `SpawnError::RuntimeUnavailable` because a weak handle outlived its runtime.

Fix:

- stop admitting new requests and finish teardown; do not manufacture a
  harness `Cx` as a production fallback;
- use the infallible handle method only when runtime lifetime is structurally
  guaranteed, because it panics on the same stale-handle condition.

## Bounded Shutdown Returned `false`

Meaning:

- final runtime teardown did not complete within the requested bound, or the
  detached reaper could not be created. State may remain retained;
- runtime-owned spawn gateways and blocking-pool admission are already closed.
  `false` is not permission to submit or retry new work through retained
  handles or runtime-backed contexts.

Fix:

- stop admission and drain application regions before consuming the runtime,
- find futures blocking inside `poll` or cleanup that never completes,
- alert on the result; do not reinterpret `false` as successful best effort.

## Cancel Drain Timeout (`CancelTimeout` / ASUP-E301)

Meaning:

- Cancellation was requested but drain did not complete within budget: a region
  is trying to close but descendants or finalizers are not finishing.

Typical cause:

- loop without checkpoints
- child work that never observes cancellation

Fix:

- add `cx.checkpoint()?` in loops and long-running work
- make ownership and join paths explicit

## Futurelock Detected (ASUP-E402)

Meaning:

- A task is holding obligations but has stopped making observable progress
  (reported as `InvariantViolation::Futurelock` /
  `TraceEventKind::FuturelockDetected`).

Typical cause:

- await while holding a permit/lock/resource that should have been resolved first

Fix:

- shorten the critical section
- restructure to avoid waiting while holding obligation-bearing state

## Deterministic Drift (ASUP-E403 lab-seed-nondeterminism)

Symptom:

- same seed does not produce the same behavior

Check:

- wall-clock time usage
- ambient randomness
- nondeterministic collection usage in deterministic-sensitive code

## Compat-Bridge Trouble

Symptoms:

- deadlock between runtimes
- timers or cancellation do not behave consistently
- tasks outlive the owning region

Fix:

- narrow the compat surface
- ensure `Cx` crosses the boundary explicitly
- do not keep ad hoc Tokio task ownership alive
- remember that `with_tokio_context` installs an Asupersync `Cx`; it does not
  start a Tokio runtime or satisfy `tokio::runtime::Handle::current()`
- require downstream compile and runtime evidence before claiming a
  Tokio-locked framework works through the bridge

## Browser Edition Unsupported Runtime

Symptoms:

- runtime constructors rejected in server, edge, or SSR contexts

Fix:

- move runtime creation to browser main-thread or client component code
- keep server/edge lanes bridge-only

## Advanced Surface Caution

If the user asks for:

- QUIC / HTTP3
- remote/distributed runtime
- messaging
- Browser Edition packaging/release details

Then verify the current repo state in source/docs before claiming feature completeness.
