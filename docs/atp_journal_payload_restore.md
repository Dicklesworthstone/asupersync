# Restore an ATP writer from journaled payload bytes

`ScopedSparseWriter::restore_from_journal` connects reopened journal receipts to
an actual usable sparse writer. It copies authenticated ranges from an explicitly
supplied whole-object `std::fs::File` into newly acquired private staging. It does
not open journal-supplied path strings, modify/adopt the source file, or publish a
destination. Existing journal and bitmap formats are unchanged.

Reopen `AppendJournal` with the trusted key, supply its `Arc`, the transfer ID,
source file, destination, writer configuration, and explicit `JournalRestoreLimits`.
The source stores bytes at logical object offsets, not as individually packed
chunk files. A transfer needs a resumable authenticated summary and consistent
object identity, root, and offered length. Unknown and terminal states refuse.

Each verified/written receipt is checked against the actual source bytes before
being sent to the canonical sparse writer. Missing or corrupt ranges do not gain
progress merely because they were recorded. Unreceipted tails and sparse holes
are not imported. The journal's signatures authenticate receipts; they do not
prove completeness of the journal or network-peer authorization.

The returned writer has Pending verification. Use its normal out-of-order writes
to fill sparse holes, or `checked_receive_offset` followed by `resume_exact_at`
for a contiguous prefix. The suffix source must already be positioned at that
negotiated offset. Completed and empty restores still require fresh canonical
manifest verification before commit. Pinned chunk-only authorization and final
on-disk verification retain their existing requirements.

## Ownership, cancellation and limits

The entire restore is one job through the existing region-owned filesystem
gateway: journal checks, source reads, writer construction, writes and failed-
restore cleanup. There is no nested executor or independent pool. An unpolled
call does not create a writer. The job owns the source handle and new staging;
checkpoints occur between reads of at most 8 KiB and receipt writes. A syscall
cannot be preempted. Region close waits for actual job retirement. Cancellation
late enough to follow the final write may still return the completed writer.

Object size, restored receipt count and maximum receipt/buffer length have
explicit limits. One buffer is reused across receipts, preserving their original
boundaries. Summary/index allocations and caller-owned journal history are not
covered by the payload buffer limit. A very large caller-selected limit can still
exhaust process resources. Restoration uses additional local I/O and disk space;
no speedup or bounded total-history memory claim is made.

A failed restore cancels only its new private writer using the configured cleanup
or quarantine policy. Ordinary cleanup failures include the retained staging path
in the error. Cleanup on checkpoint failure or panic is best effort; the original
source is never a cleanup target. A successful writer has the normal explicit
commit/cancel lifecycle; abandoning its result is not an automatic rollback of
its named staging file. Another restore can use the unchanged original source.

This is reconstruction by copying verified ranges, not in-place adoption of an
old staging pathname. It avoids extending cleanup authority to that pathname.
It does not coordinate concurrent writers to the journal, prevent external file
mutation, confine hostile parent-path changes, or automatically negotiate a
restart with the daemon/network protocol. The supplied descriptor must not be
concurrently consumed through aliases sharing its seek position.

## Validation

Eight authored Rust tests exercise actual journal compaction/reopen, both native
scheduler flavors, all publication policies, suffix framing, sparse holes, empty
and complete restores, corruption/truncation, quota and offer-identity refusal,
terminal/unknown/wrong-key journals, checkpoint failure after a copied prefix,
and lazy Send ownership. Existing scoped-writer source and tests are unchanged
apart from one module declaration.

Rust, Cargo, rustfmt and RCH are unavailable in the authoring environment. These
Rust tests have not been compiled or executed. Source/blob and whitespace checks
are not native-runtime, cross-platform, performance or release-readiness proof.

## Fully offloaded startup

`ScopedSparseWriter::restore_from_storage(&cx, request)` also owns journal
reconstruction and source-file acquisition. Its `JournalRestoreRequest` carries
the application-selected journal configuration, trusted key, transfer ID, source
path, destination, writer policies and limits. No synchronous setup is required
on the caller's scheduler thread. The descriptor-based entry point remains
available for applications that already own a reopened journal and source.

Both entry points use the same authenticated restore plan and private-staging
copy implementation. The path-based entry requires an existing journal directory;
it does not initialize absent storage as an empty history. Transfer status,
authentication, identity and limits are checked before opening the payload path.
Journal-record filenames never become source-opening authority. Normal host path
semantics still apply, and a slow open or journal parse cannot be preempted.

Restoration does not automatically journal later writes or delete the old journal
and source. Applications still own subsequent durability ordering and checkpoint
production. Four additional authored tests cover path-based startup and shared
finalization on both schedulers, refusals before source opening, missing storage,
capability/cancellation refusal and lazy Send ownership. These tests are also
uncompiled and unexecuted in this environment.

## Automatic checkpoints for a known-manifest live receiver

`native_auth::live::commit::ManifestFileSink::new_journaled` connects the existing
live TLS receiver to the checkpoint producer and journaled finalizer. The ordinary
`ManifestFileSink::new` remains unjournaled. Neither constructor changes the wire,
TLS authorization, legacy flush-only receiver behavior, or CLI configuration.

Provision an `AppendJournal` with the trusted key and exclusive directory ownership,
then pass it in `ManifestFileJournalConfig` with a previously unused transfer ID and
an application timestamp. Construct the sink with a durability-enabled writer policy
and a lossless UTF-8 destination. Manifest byte and receipt ceilings also bound the
checkpoint/restore inputs; write buffers remain capped at 64 KiB.

```rust
let mut sink = ManifestFileSink::new_journaled(
    &cx,
    expected_file,
    ManifestFileJournalConfig { journal, transfer_id, timestamp },
).await?;
let initial = sink.journal_checkpoint().expect("initial checkpoint").clone();
// Persist initial.source_path, the transfer ID, trusted key reference and expected
// manifest in an application-owned recovery catalog before exposing the listener.
let report = listener.receive_committing(&cx, &mut sink).await;
let retirement = sink.drain_pending(&cx).await;
let publication = sink.journal_publication().cloned();
let retained_journal = sink.release_journal()?;
// Inspect report.outcome, retirement and publication separately. Never turn a
// failed peer exchange or completion record into permission to publish again.
```

The constructor persists an initial empty checkpoint before returning. Its staging
path is therefore available for cataloging before reception, including for an empty
file. Each subsequent `flush` rehashes/synchronizes actual staging and persists its
missing progress records through `checkpoint_to_journal`; the live receiver cannot
ACK that epoch before the flush completes. Repeated unchanged flushes add no records.
A write receipt or synchronized prefix alone is not final content authorization.

Final commit validates the live receipt and calls `verify_and_commit_to_journal`:
fresh manifest authentication, durable checkpoint, synchronized CommitIntent,
canonical publication, then synchronized CommitComplete. A missing completion result
withholds final Proof even when the publisher actually succeeded. `published_path`
and `journal_publication` retain a Confirmed publisher observation independently of
that persistence error. `ManifestFileJournalError` also retains that observation in
the I/O error source chain when an owned receiver drops its sink before returning
its report. None is not proof of rollback. Backend errors stay in the
existing I/O error chain; failed operations are not retried through an unjournaled
fallback. Ordinary domain failures restore journal ownership inside the sink.

A dropped borrowing wait retains its pending journal job. `drain_pending` drives
only that retained operation, using its captured context; it never starts a fresh
flush or commit. `release_journal` requires a quiescent, available owner and permanently
seals the sink against all further writes, flushes and commits. An outer gateway
error or abandoned result may lose the owner; reopen retained storage after region
drain. Late cancellation does not preempt publication. Journaled `cancel` deliberately
refuses staging deletion: no durable cancellation-record/cleanup protocol is added.
Drop/ownership handoff retain files for explicit recovery, not implicit rollback.

The initial path mapping is sufficient to select the payload when reopening the
latest journal; progress comes from authenticated current records, not that initial
zero-byte summary. `restore_from_storage` rechecks actual bytes and produces a normal
writer for separately authorized suffix reception. This does NOT recover the live
connection's nonce, epoch chain, retry budget, or final peer-Proof exchange. Do not
present these payload records as a complete `atp-live-resume` session checkpoint.
Automatic daemon adoption, trusted catalog persistence, and unresolved-commit
reconciliation remain application responsibilities.

Every checkpoint currently rereads all retained payload and inspects journal history.
Many small flushes can therefore incur quadratic local I/O; this is not a throughput
optimization or a total-memory bound. Existing publication policy, external mutation,
path-race, non-Unix directory-sync, and storage-device durability limits still apply.
Journal files contain sensitive metadata and must remain in trusted storage.

Nine additional Rust tests are authored for prefix/terminal record ordering on both
native scheduler flavors and all publication policies, physical prefix restoration,
preflight/cancellation refusal, dropped checkpoint waits, handoff fencing, real journal
storage failure, independent publication reporting, and real TCP/mTLS backpressure.
The completion-error observation test deliberately faults the adapter report after
real publication; it is not a power-loss or failed-storage simulation. Rust, Cargo,
rustfmt and RCH are unavailable in the authoring environment, so these tests have not
been compiled or executed. Source preservation and delimiter checks are not native
runtime, downstream compatibility, performance, or release-readiness evidence.
