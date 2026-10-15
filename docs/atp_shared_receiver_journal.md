# Journaled receiver restoration on a shared authenticated port

`ResumableService::next_journaled` admits fresh or restored receiver journals on
its existing socket. It uses the same certificate/nonce registry, mutual TLS,
revocation checks, receiver codec, write-ahead barriers, scoped workers and drain
operations as the established shared service. It does not open a per-session
listener, allocate another SDK transfer credit, or introduce a wire version.

**This implementation and its Rust tests were not compiled or executed in the
authoring environment.** Source checks and Git publication do not establish
runtime, cancellation, performance or power-loss correctness.

## Owned factory results

The new factory has this shape:

```rust
Fn(Cx, ResumeSessionKey) -> Future<Output = io::Result<JournaledSession<W>>>
```

`JournaledSession` is under
`native_auth::live::commit::resume::receiver_journal::shared`. Its `new(sink, store)`
constructor owns a genuinely new sink and its associated checkpoint store.
`restore(sink, store, retained_reader, checkpoint)` additionally owns protected
history and a reader positioned at zero of that exact sink. Constructors do not
poll providers. A restored sink must append at its actual retained end and must
not be accessed concurrently through another handle.

The factory is invoked only after fresh mutual TLS, the complete certificate/nonce
key, client revocation, and registry limits have been checked. One deadline covers
both the factory and retained-byte revalidation. Timeout, cancellation, bad local
history, or factory failure tombstones the admitted key; there is no fresh-sink
fallback. After successful initialization the service retains the same sink and
store across reconnects and uncollected joins. Even a subsequent `next` or
`next_restoring` call cannot turn off journaling for that retained session.

The existing public `ResumeSessionInit::{Fresh, Committed}` enum remains unchanged
and exhaustively matchable. Its existing factories and receipt-only behavior are
not silently converted to WAL-based receivers.

## Concrete paired-file adapter

`ReceiverJournalFile::into_service_session()` consumes either a newly created
empty data/WAL owner or a successfully reopened owner. It returns the same opaque
sink type in both cases, so one service can contain both new and restored files.
Descriptor and metadata preparation runs on the runtime blocking pool. The
result retains the original data inode, journal, exclusive locks and pending-I/O
ownership. No data file is created by this conversion.

An application can reopen a catalog-selected pair inside its factory:

```rust
let owner = spawn_blocking_io(move || {
    ReceiverJournalFile::open_existing(&journal_path, &data_path)
}).await?;
owner.into_service_session().await
```

For a genuinely new catalog entry, explicitly select `create_new` with finite
`ReceiverFileLimits` instead. Never choose between creation and recovery merely
by checking whether an old path exists. Missing history is a refusal, not a new
operation. Do not derive filesystem paths or grants directly from peer input.

**The application must maintain a protected key-to-file catalog and aggregate
storage policy.** This API does not create that catalog, enumerate old journals,
persist service-wide tombstones, or provide a new CLI mode. Existing journaled
single-client commands and shared CLI commands keep their prior behavior.

## Restoration checks and persistence

Initialization validates the exact authenticated certificate and nonce, original
negotiation and current resource policy. It reuses the standalone restoration
validator to rehash the stable prefix and compare every surviving pending-epoch
byte. A partially written epoch keeps its actual write cursor; the peer must
retransmit the identical epoch, and only the missing suffix is written.

The original cumulative attempt count and ceiling remain in the WAL. A service
with a larger ceiling cannot reset or enlarge them; one whose current ceiling
cannot cover the saved ceiling refuses restoration. Authenticated routed attempts
are checkpointed before a resumed offer is answered. Failed TLS or a session key
rejected before initialization does not charge a journal it never owned.

Every pending epoch is persisted before sink writes, the synchronized prefix
before its ACK, finalization intent before application commit, and the successful
commit observation before final Proof. `Finalizing` remains unresolved and is not
restored. `Committed` restores only the original final exchange: no additional
data or application commit is accepted. A local receipt is not proof that the
sender received the final response.

Reports retain cumulative sink-byte counts, including revalidated historical
bytes. Do not interpret `sink_written_bytes` as new writes performed by the latest
connection. A restored committed report marks `receipt_reused`; file/inode checks
and journal state are distinct from transmission success.

## Resource ownership and cancellation

Existing connection, resident-session, per-client, lifetime-key, attempt and
revocation limits remain in force. Restored sessions consume resident capacity
including while idle or holding completed receipts. Explicit retirement drops
that sink/store while retaining the existing service-lifetime refusal tombstone.
It does not delete files, refund disk reservations, or remove durable history.

Revocation requests cancellation without discarding joins. A started WAL operation
is drained with its actual storage result and interruption reported separately.
A successful store after cancellation does not allow an ACK to escape or turn an
incomplete transfer into a success. Native workers can keep running after a
manager wait is dropped; drive the same owner and collect its results. Stop or
cancel admission, then call `drain_next` until `None` before dropping the service.

Blocking filesystem work can outlive a timed-out factory. Paired descriptors and
locks remain owned by started operations, but the service's connection count is
not a bound on arbitrary application allocation or every blocking-pool job.
Configure bounded factories, a suitable blocking pool and aggregate disk budgets.
There is no hard termination guarantee for a syscall or user operation that does
not return. The store wrapper preserves otherwise available Sync auto-traits
without requiring a Sync implementation from an exclusively owned provider.

The file profile still commits private in-place data, not an atomically published
destination. Pending payloads remain plaintext in retained journals. No journal
compaction, file deletion, corruption repair, malicious-rollback defense, or
exactly-once arbitrary-effect guarantee is added.

## Acceptance coverage

Three constructor/policy unit tests and two real-file handoff tests accompany
six native scenarios plus a subprocess worker. They cover two clients sharing a
nonce, same-inode restoration, journal retention through legacy `next`, altered
history, wrong-key mapping, revocation before factory access, snapshot exhaustion,
and exact cancellation while a prefix checkpoint is demonstrably pending.

The subprocess scenario kills its own shared receiver only after two independent
mTLS peers receive real prefix ACKs and the test verifies data, WAL checksums and
held locks. A new process restores both original inodes on the same address;
a third process exchanges the committed Proofs without new data. Both runtime
shapes are exercised. A successful worker exit alone is insufficient: the parent
requires a witness written after assertions and confirmed native runtime drain.
All test-created files and diagnostic logs remain retained.

These are authored acceptance cases, not executed evidence. The required RCH check
could not start because `rch` is absent; no local Cargo fallback or GitHub Actions
were used. Shared CLI catalog integration, durable service-wide admission history,
atomic publication and uncertain-commit reconciliation remain separate work.
