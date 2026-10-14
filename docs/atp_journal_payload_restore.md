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
