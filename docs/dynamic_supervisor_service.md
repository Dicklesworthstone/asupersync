# Bounded multi-producer dynamic supervision

`cx::supervisor_service` turns the existing single-owner `DynamicSupervisor`
into a region-owned service with cloneable submission capabilities. It uses the
existing MPSC/oneshot primitives and managed worker controllers. It adds no
runtime, thread pool, global registry, unsafe block or dependency.

This owned-receipt API uses `Cx::spawn_dynamic_supervisor_mailbox`. The existing
`cx::dynamic_service` request-credit API and `Cx::spawn_dynamic_supervisor_service`
remain unchanged. Import this module's `DynamicSupervisorClient` explicitly when
naming its type; `cx::DynamicSupervisorClient` continues to name the existing API.

## Submit, observe admission, and join

```rust,ignore
use asupersync::cx::{DynamicSupervisorConfig, DynamicWorkerConfig};
use asupersync::supervision::{ManagedRestartMode, SupervisionConfig};
use asupersync::types::Outcome;
use std::time::Duration;

// `cx` is the owning task's existing runtime-wired context.
let (client, mut service) = cx.spawn_dynamic_supervisor_mailbox::<String>(
    DynamicSupervisorConfig::new(64), // admitted + quarantined names
    16,                              // queued admission requests
)?;
let policy = DynamicWorkerConfig::new(
    ManagedRestartMode::Temporary,
    SupervisionConfig::new(0, Duration::from_secs(60)),
);
let mut admission = client.submit_worker(
    &cx,
    "index-refresh",
    policy,
    |worker_cx, generation| async move {
        // Use worker_cx and generation for the real operation.
        worker_cx.trace("index-refresh");
        let _ = generation;
        Outcome::Ok(())
    },
)?;
let mut child = admission.admitted(&cx).await?;
let completion = child.join().await?;
// Inspect completion.supervisor and completion.close, not just join success.
service.begin_drain();
let report = service.join().await?;
// Inspect report.task_outcome, report.supervision and its root close result.
```

`submit_child` accepts a complete, already-bound `ManagedSupervisor` tree.
`submit_worker` accepts a retained factory and `DynamicWorkerConfig`, preserving
its restart eligibility, intensity, backoff, escalation and budget semantics.
Clones of `client` can be moved into separate tasks; errors/results need `Send`,
not `Sync` or `Clone`. The single service owns all mutable lifecycle state.

Possession of a client delegates admission into the service's existing region
and budgets. The per-request context supplies caller cancellation; it does not
replace the service's authority or allow a child to relax its parent envelope.

## Three distinct acknowledgements

A successful `submit_*` means only bounded mailbox admission. A full queue
returns `MailboxFull` immediately; there is no internal population of waiting
submitters. A rejected call consumes the supplied factory/tree without invoking
it. A successful `admitted` means child-region admission and controller
submission, not application readiness. A successful child `join` returns the
actual managed outcome AND enclosing-region close result. An application error
or panic remains an application outcome, not a fabricated service success.

Every child has its own stop channel. `request_stop` and dropping a child handle
therefore work even with a saturated admission mailbox. IDs contain the exact
owner, region and admission generation; old handles do not stop a reused name.
The driver continues polling all child waits while accepting requests. One
pending cleanup or quarantined child cannot monopolize the completion scan.

## Cancellation and shutdown

Dropping a borrowing `admitted` wait retains the request in `DynamicAdmission`.
An interrupted cancellation-aware wait can be repeated with a live context.
Dropping the receipt itself abandons admission. A still-queued request is skipped;
a request already being processed may have effects before its lost receipt is
noticed. Any resulting child is stopped and drained, not detached. This is not
an atomic rollback of application effects.

Dropping a borrowing child `join` preserves the one-shot result. Dropping the
child handle requests stop and relinquishes its result. Completed results can
then be discarded, but only after the owner has attempted the required cleanup.
`join` does not use the caller's cancellation as an excuse to skip child cleanup.

`service.begin_drain()` monotonically seals admission without cancelling already
dispatched children. Unprocessed queued requests are closed; an admission
already in progress can finish and is included in the drain. Retained clients do
not keep an explicitly drained service alive. Permanent or uncooperative workers
can keep graceful drain pending; no arbitrary-future completion deadline exists.

`service.abort()` escalates to cancellation and stops every child. A subsequent
weaker drain request cannot reopen admission or undo that cancellation. The
control notification has its own one-slot coalescing channel, independent of
admission capacity. Its monotone atomic mode is published before the wake and
rechecked after wake registration. The stopped driver does not repeatedly poll
a cancellation-rejecting notification receiver or repeatedly re-register an
already observed cancellation and manufacture busy-loop wakes.

Dropping the last client eventually disconnects the mailbox and stops/drains
remaining children. Queued requests can be processed before disconnection is
observed; explicitly seal/drain to refuse unprocessed requests. Dropping the
service handle requests cancellation. Only joining, or later draining the
owning runtime region, establishes the corresponding quiescence boundary.

## Bounded ownership and failure evidence

Mailbox capacity bounds queued commands; at most one additional command is in
admission. Child capacity bounds live, draining and quarantined reservations.
One single-consumer completion channel is associated with each admitted child.
After clean completion is sent, the result belongs to its caller and the name is
reusable. Caller-retained unread results, captured factory data and descendants
inside an individual supplied tree are separately owned, not a byte-memory
promise implied by these counts. There is no unbounded service result history.

A cleanup failure keeps the original dynamic-owner reservation quarantined.
The child handle receives the typed refusal; its full unclean report remains in
the service's terminal `DynamicSupervisorReport`. Other tickets continue to be
driven. Root-close failure is separately represented. A service task's own
cancellation/panic result is separate from a report published before termination.

The adapter uses existing in-memory `send_blocking` oneshot commits to publish
lifecycle receipts even after cancellation. This bridge does not block or acquire
ambient I/O authority. Long-lived task and region ownership, rather than a new
untracked detached task or a fabricated runtime, drives the operation.

## Validation status and commands

Thirteen focused unit/lab regressions and two public native-runtime journeys are supplied.
They cover independent task callers, Send-only errors, queued abandonment,
mailbox and child ceilings, stop while saturated, independent progress during
blocked cleanup, idle task-only cancellation, generation-safe name reuse,
graceful sealing, escalation, resumable admission observation, and factory panic.
The native journeys target current-thread and two-worker runtimes. Their host
watchdog is a test timeout, not a runtime responsiveness guarantee. Native cleanup
callbacks are described as application cleanup, not registered region finalizers.

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --lib cx::supervisor_service::
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --test dynamic_supervisor_service_native
```

These commands have NOT been run in the authoring environment. It lacks Rust,
Cargo, rustfmt and RCH. Source/API review and patch-application checks are not
compiler evidence, native execution evidence, a benchmark, or release approval.

This does not implement cross-entry restart dependencies, live mutation of a
compiled child topology, durable supervision recovery, or complete OTP semantics.
