# Observe persisted receiver state without taking ownership away from a service

`ReceiverJournalFile::observer()` returns a cloneable `ReceiverJournalObserver`
that remains useful after the file pair moves into a standalone receiver or a
shared `JournaledSession`. `JournaledFileReceiver::observer()` provides the same
view for an already-bound standalone owner.

This supplements the existing shared journaled receiver and `into_service_session`
file handoff. It does not implement another transfer engine, file backend, wire
format, listener, or restart catalog. The observer does not read or synchronize
files and cannot mutate a journal, deliver a byte, or initiate/retry publication.

## Why the persisted view is separate

A receiver may have flushed an epoch but failed to persist its new checkpoint.
It can also finish application commit and then fail the committed-state append
or final Proof write. `ResumeReport.prefix`, `sink_written_bytes`, and `completed`
preserve those actual local observations; they are not all durability assertions.

The observer reports the most recent completed append/reopen observation from
the paired storage owner. In particular, it does not derive persisted progress
from a live byte counter, file existence, or a successful socket write. It can
show `Receiving`, unresolved `Finalizing`, or historical `Committed` state without
consuming the connection result or moving the sink out of its owner.

A saved checkpoint still is not a sender acknowledgment. A committed record is
local history, not evidence that the sender received Proof. On reopening a journal,
its metadata view also does not replace the normal retained-data hash verification
that the authenticated restoration worker performs before replying.

## Using the existing shared-file factory

Create or reopen the original file pair according to a protected application
catalog, before the runtime or on its blocking pool. Never create new files merely
because an old journal failed to open. Retain an observer before transferring
ownership. A schematic single-key factory is:

```rust
use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};
use asupersync::Cx;
use asupersync::net::atp::sdk::native_auth::live::commit::resume::receiver_journal::file::ReceiverJournalFile;

// Outside runtime workers: retain the original journal, data inode and key.
let journal = ReceiverJournalFile::open_existing(journal_path, data_path)?;
let observer = journal.observer();
let files = Arc::new(Mutex::new(BTreeMap::from([(original_key, journal)])));

// Inside the owning task: the shared service supplies the listener and credits.
let scope = cx.scope();
let mut service = authority
    .bind_resumable_service::<_>(&cx, bind_address, service_limits)
    .await?;
let factory = move |_: Cx, authenticated_key| {
    let files = Arc::clone(&files);
    async move {
        let journal = files.lock().unwrap().remove(&authenticated_key)
            .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
        journal.into_service_session().await
    }
};
let completion = service.next_journaled(&cx, &scope, factory).await?;
// Inspect the canonical completion independently of observer.checkpoint().
// Continue driving, then stop/cancel and drain_next until None as usual.
```

A real application keeps the exact certificate/nonce-to-file mapping under its
own durable policy. The example's map is only an ownership handoff, not a durable
catalog implementation. Fresh keys need their own explicit admission and quota
reservation. A prepared file pair is not permission to use a different client,
nonce, original attempt budget, or negotiated limit.

The existing service authenticates and admits the key before factory execution,
rehashes the stable prefix and checks every surviving pending byte before its
reply, and retains the journal for later attempts. Calling ordinary `next` for a
subsequent connection cannot silently turn an existing journaled session into an
unjournaled one. Revocation still cancels the actual scoped worker and must drain
started persistence rather than abandon its effects.

## Observer outcomes and lifetime

`ReceiverJournalObserver::checkpoint()` returns an owned `ReceiverCheckpoint`.
That copy can be retained independently of the receiver and its locks. Its pending
payload is sensitive plaintext, bounded by the existing checkpoint format; protect
retained and exported copies. Collecting an unlimited history of snapshots is the
caller's memory responsibility.

The accessor never waits on the storage mutex:

| Result | Meaning |
|---|---|
| `Ok(checkpoint)` | The most recent completed storage observation; it may predate current queued or active work. |
| `WouldBlock` | No checkpoint exists yet, or the storage state is currently locked for an update. |
| `NotConnected` | The paired storage owner no longer exists; this does not establish that all descriptor-owned I/O finished. |
| Other error | Storage marked persistence unconfirmed; do not use a possibly advanced record as confirmation. |

This is a synchronous observation API, not an asynchronous readiness future. It
registers no waker; do not spin on `WouldBlock`. Inspect again after an application
progress event, a collected result, or an independently owned monitoring interval.
There is no progress guarantee for an operation whose syscall never returns.

The handle uses weak ownership. Merely retaining it or cloning it does not keep
file locks, SDK credits, sinks, or listeners alive. A single accessor call briefly
retains storage while copying the snapshot, then releases it. After service drain,
retain any already-returned checkpoint needed for diagnostics; the observer does
not reopen a file or keep completed sessions alive behind the caller's back.

A successful read does not prove there is no pending write. A queued operation
may not yet have started, and another operation can begin immediately afterwards.
The observer's historical checkpoint and the transfer's actual terminal result
must therefore remain distinct. A later persistence error does not retroactively
turn an earlier returned checkpoint into rollback evidence.

The accessor does not rehash data or detect a malicious same-user writer. Existing
protected-directory, inode, permissions, exclusive ownership, trusted history,
and no-rollback obligations continue to apply. Checksums and synchronization calls
are not universal power-loss or exactly-once guarantees.

## Regression coverage and execution boundary

Two new unit tests exercise no-checkpoint versus committed states, a same-thread
locked-state read that must return `WouldBlock` rather than deadlock, observer and
snapshot lifetime after the owner drops, and refusal of poisoned persistence.
All pre-existing file and shared-handoff tests remain unchanged.

Seven native integration tests in `tests/atp_shared_journal_observation.rs` use real
TCP/mTLS, independently driven wire peers, current-thread/sharded runtimes, and
real private journals. They cover two distinct clients using the same nonce;
eight stable bytes plus a three-byte pending tail; original inode, hash and attempt
preservation through a fresh runtime; final-Proof reuse; insufficient journal
capacity despite switching next APIs; exact cancellation while persistence is
parked; wrong-key/current-policy refusals before retained reads; and changed bytes.

The concrete file-handoff tests include an empty transfer and require actual
committed WAL state, not merely application byte counters. Observer checks around
a cancelled persistence barrier distinguish the previous empty stable checkpoint,
a subsequently persisted pending epoch, and owner retirement. No observer may
keep the pair locked after its service has drained.

A finalization test parks the committed-checkpoint store only after the sink's
actual commit succeeds. Revocation then drains that store, with both successful
and failed persistence variants. The domain result must retain the local commit;
the observer must report Committed only in the successful-persistence variant;
and the peer must receive no final Proof in either cancelled variant. A previously
returned Finalizing snapshot remains unchanged.

These are authored scenarios, not passing test evidence. Rust, Cargo, rustfmt and
RCH are unavailable in the authoring environment; the RCH attempt stops at command
not found. Source/hash/patch checks do not establish Rust typing, native runtime
correctness, cancellation correctness, or filesystem durability. The integration
suite uses complete runtime teardown/reconstruction, not OS crash/power-loss proof.

Shared CLI catalog selection and atomic destination publication remain separate
work. This change neither claims to implement those integrations nor permits
restoration of an unresolved `Finalizing` checkpoint.
