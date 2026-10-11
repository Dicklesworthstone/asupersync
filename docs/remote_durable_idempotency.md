# Restart-durable remote idempotency

`remote::durable` provides an opt-in journal and runtime adapter for one named
remote computation. It addresses `asupersync-bi2462.125` and the remote
idempotency requirement in the comprehensive plan. Existing registrations and
V1–V3 wire formats keep their current behavior.

The adapter syncs a reservation before calling the application handler and
syncs its terminal outcome before returning that outcome. An authenticated
retry with the same peer, key, and input can therefore recover a completed
result after a process restart, including when the original connection failed
before delivering the response.

## What a retry means

| Retained state | Same peer, key, and input | Different input for the retained key |
| --- | --- | --- |
| No reservation | Reserve capacity, sync a reservation, then execute once | A new key has no retained input to conflict with |
| Reservation without a terminal outcome | Refuse with `InDoubt`; the handler may already have performed effects | Refuse with `Conflict` |
| Unexpired terminal outcome | Return the exact decoded terminal outcome without executing the handler | Refuse with `Conflict` |
| Expired terminal outcome | A new reservation and execution are permitted | A new reservation and execution are permitted |

Pending reservations **never expire automatically**, including after restart.
A crash between an external effect and the terminal journal write cannot prove
whether the effect happened. Such a reservation remains an in-doubt fence. The
application must reconcile the effect with its own authoritative state; this
API does not clear that fence, reconstruct a future, or retry the effect.
Changing the key or discarding the journal would remove that protection.

The identity includes the certificate-bound `invocation.peer_node()`, the
idempotency key, and a domain- and length-bound SHA-256 input digest. Origin
metadata, remote task IDs, budgets, leases, and transport reconnects do not
change it. Each journal also binds its computation name, complete input/output
schema fingerprint, an independently provisioned 32-byte application version,
and every immutable limit in its authenticated header. Change the application
version when effect semantics change even if the payload schemas stay the same.

## Registering a computation

Create or reopen the journal during provisioning, before exposing the service.
Both operations perform synchronous I/O. The caller supplies the already-open
regular read/write file, authentication key, and clock. The adapter acquires no
ambient path, clock, entropy, or blocking-pool authority.

```rust,no_run
use asupersync::distributed::{HasSchema, SchemaDescriptor};
use asupersync::remote::durable::{
    DurableRemoteComputation, DurableRemoteError, DurableRemoteJournal,
    DurableRemoteLimits,
};
use asupersync::remote::{RemoteComputationRegistry, RemoteOutcome};
use asupersync::security::AuthKey;
use std::fs::File;
use std::sync::Arc;

struct Input;
struct Output;

impl HasSchema for Input {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::primitive("example.record-input.v1")
    }
}

impl HasSchema for Output {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::primitive("example.record-output.v1")
    }
}

// Run synchronous provisioning on an appropriate blocking worker or before
// starting the runtime. The caller has already durably linked `file`.
fn provision(
    file: File,
    create: bool,
    application_version: [u8; 32],
    journal_key: AuthKey,
    epoch_millis: impl Fn() -> u64 + Send + Sync + 'static,
) -> Result<(RemoteComputationRegistry, Arc<DurableRemoteComputation>), DurableRemoteError> {
    let limits = DurableRemoteLimits {
        max_entries: 128,
        max_peer_entries: 32,
        max_input_bytes: 64 * 1024,
        max_outcome_bytes: 64 * 1024,
        max_retained_bytes: 8 * 1024 * 1024,
        max_journal_bytes: 64 * 1024 * 1024,
        retention_ms: 24 * 60 * 60 * 1000,
    };
    let journal = if create {
        DurableRemoteJournal::create::<Input, Output>(
            file, "example.record.v1", application_version, journal_key, limits,
        )?
    } else {
        DurableRemoteJournal::open::<Input, Output>(
            file, "example.record.v1", application_version, journal_key, limits,
        )?
    };
    let owner = Arc::new(DurableRemoteComputation::new(journal, epoch_millis));
    let mut registry = RemoteComputationRegistry::new();
    owner.register::<Input, Output, _, _>(&mut registry, |_cx, invocation| async move {
        // Application work belongs here. The example returns a small receipt;
        // an effectful handler should await its own owned operations and return
        // an outcome only when it can describe their terminal result.
        RemoteOutcome::Success(invocation.request().input.data()
            .iter().copied().take(16).collect())
    })?;
    Ok((registry, owner))
}
```

Bind this registry with the existing `RemoteComputationService`, TLS acceptor,
and certificate-bound `RemotePeerAdmissionPolicy`. Grant the named computation
only to the intended peers. The invocation's `Cx` must carry an explicit
blocking pool, for example from a runtime configured with
`RuntimeBuilder::current_thread().blocking_threads(0, 2)`. Missing capability
refuses the call before a reservation is written. There is no inline disk-I/O
or detached-thread fallback.

`register` verifies the handler's schemas against the journal before installing
it. `call` exposes the same adapter path for applications that compose a custom
registered handler. A handler returns an explicit `RemoteOutcome`; success,
failure, cancellation, and panic *outcomes* can be persisted if they round-trip
through the existing strict wire codec. An actual future panic or a dropped
future after reservation leaves an in-doubt fence.

The registered wrapper maps journal and admission errors to the existing remote
execution-failure response. The wire does not attest which persistence backend
an operator installed. Existing clients keep their conservative automatic retry
policy; this adapter does not advertise a new retry capability or alter the
framework's separate in-memory idempotency cache. A custom local wrapper can
inspect the typed `DurableRemoteError` from `call` when it needs a more specific
application response.

## Ownership, bounds, and recovery

One invocation owns the journal at a time, including across cloned registration
closures. Concurrent calls return `Busy` without allocating a waiter queue.
Reservation and terminal writes run through `spawn_blocking_drained`; their
independent joins retain actual queued/running disk ownership after a network
waiter is dropped. The application future is awaited inline. Completed durable
receipts survive an observed late invocation cancellation through the normal
native task completion policy. A non-preemptible filesystem call can still
delay region drain.

Each pending key reserves the full `max_outcome_bytes` allowance in memory and
the largest possible terminal record on disk before execution is admitted.
Another request cannot spend that terminal capacity. The outcome bound counts
encoded JSON bytes, including its framing and escaped or numeric payload
representation; it is not a raw success-payload bound. Oversized or unencodable
outcomes leave their reservation in doubt and are never reported as committed.
The remote service's frame limit separately bounds the complete response
envelope; provision it consistently with the journal's encoded-outcome limit.

The retained-entry and per-peer limits bound index metadata. The retained-byte
limit counts cached encoded allocation capacity and pending outcome allowances;
transient record buffers, decoded/returned outcomes, and caller-owned tokens have
separate lifetimes. Expiring a completed result frees its retained key and cache charge.
It does not reclaim append-only disk space. The journal has no compaction,
rotation, deletion, or truncation operation; reaching the disk bound refuses
new reservations while preserving capacity already reserved for completion.

The clock must return trusted milliseconds from a consistent epoch across
restarts. A backward observation refuses work. Completion time starts the
positive retention interval; forward jumps can expire completed results.
Reopening restores the last persisted timestamp. A later timestamp seen only
by a replay or refused call is an in-process floor, so a fresh runtime's relative
clock or a peer-supplied timestamp is not an acceptable clock source.

The caller is responsible for durable directory linkage, access controls, and
exclusive ownership of the supplied file. The journal retains an exclusive
file lock; cloned handles or writers ignoring the lock violate that ownership.
Its authentication protects the provisioned header, record lengths, sequence,
and chained contents. It does not encrypt outcomes or detect replacement with
an older authenticated prefix without an independently retained head.

On reopen, every complete bounded record is authenticated and replayed before
the recovered state is exposed. An incomplete trailing record is preserved and
puts the owner in `ReadOnlyTail`: exact unexpired terminal replay remains
available, while new writes are refused. A complete corrupt record rejects the
whole open. Write/sync uncertainty or an external length change poisons the
current owner, including cached replay, until it is reopened. A failed append
is not evidence of rollback; reopening can recover a complete synced result or
an unresolved reservation.

## Validation targets

The journal unit module covers authenticated reopen, exact replay identity,
retention and in-doubt fences, reserved completion capacity, and injected
write/sync uncertainty using the same journal engine. Adapter tests exercise
real native pool ownership and task cancellation. `remote_durable_process`
terminates and restarts an actual authenticated service process at two distinct
boundaries: after durable completion but before its response, and after an
effect but before durable completion. Process termination establishes restart
behavior; it does not establish power-loss or filesystem conformance.

Execution receipts for this feature must include the default all-target check,
the `tls,test-internals` feature check, the complete `remote::durable` unit
module, unfiltered `remote_durable_process`, the existing remote wire/codec
compatibility targets, and unfiltered `runtime_abort_vs_cancel_semantics_audit`.
