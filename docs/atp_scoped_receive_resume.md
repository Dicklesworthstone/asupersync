# Retry a disconnected receive without discarding its staged prefix

`ScopedSparseWriter` supports explicit in-process suffix recovery after a
receive fails or is abandoned. It uses the original writer, its live receipt
ledger, the existing bounded chunk reader, and the existing verifier/publisher.
It does not reconstruct a writer from disk or automatically reconnect a peer.

## Negotiate, revalidate, then read

Finish or drop the old `ScopedReceive` owner first. Dropping only its borrowing
`wait()` leaves it alive and holding admission; awaiting a competing operation
in that state can deadlock application control flow.

```text
let offset = writer.checked_receive_offset(&cx).await?.unwrap();
// Arrange an authenticated replacement source positioned at `offset`.
let mut receive = writer.resume_exact_at(
    &cx, replacement_source, trusted_manifest, options, offset,
)?;
let outcome = receive.wait().await?;
// Only after Outcome::Ok may take_source() recover following protocol bytes.
```

Handle both the gateway/read error and the inner writer Outcome in real code;
the sketch's unwrap is not an error-handling recommendation. A new authorized,
noncancelled context can own the retry after the old context is cancelled.

`checked_receive_offset` waits behind earlier admitted disk operations and
re-reads every recorded local chunk. It verifies contiguous receipts, agreement
with the range tracker, storage length and each recorded SHA-256. File length
alone is not progress: preallocation and unreceipted partial writes can extend
beyond the valid prefix. Such tail bytes are not skipped; a retry supplies them
again. Corrupt/truncated prefixes refuse and revoke prior verification without
rewriting bytes or fabricating repaired receipts.

The returned offset is a snapshot, not a reservation, sender-authentication
proof, fsync receipt or cross-process recovery checkpoint. The resumed session
rechecks the supplied offset, declared length, limits and actual prefix under
its single FIFO admission slot before any replacement-source poll. A clone's
intervening write or resize makes a stale restart refuse. The slot then remains
held through suffix ingestion and finalization. There is no check/read window
for another clone to alter the writer.

A source error may leave a partial chunk only in the old reader, whereas a
short successful EOF can produce a recorded short chunk before truncation is
reported. Negotiate from the checked ledger, not from how many network bytes
the old connection appeared to consume or its last observed progress value.

## Authentication, quotas and framing

For manifest-addressed objects with chunk hashes only, call
`resume_exact_at_with_chunk_commitment` with the independently trusted
`ManifestChunkCommitment`. A missing or wrong pin cannot fall back to the legacy
root. Local receipt hashes only detect changes to recorded local bytes; the
complete object is always freshly authenticated against the selected identity
and expected manifest before publication, even when the prefix is already full.
A rejected resumed expectation revokes prior successful verification.

`max_bytes` bounds the entire object, not just the requested suffix.
`max_chunks` includes all old receipts plus the ceiling-divided suffix count.
Repeated retries and smaller chunk sizes cannot silently grow the ledger beyond
that explicit limit. An early EOF can leave a short receipt, so a retry may need
a larger explicitly chosen limit than the original uninterrupted layout.

Only `declared_length - offset` bytes are requested from the replacement source.
The receiver neither seeks nor discards a prefix: the application must position
that source correctly. A full or empty prefix requires no source poll. Following
successful publication, `take_source()` preserves subsequent protocol bytes and
source-owned read-ahead buffers. The replacement peer need not close. Premature
EOF or wrong bytes cannot publish a complete object.

`accepted_bytes()` remains zero until preflight succeeds, then includes the
checked prefix and successful observed suffix writes. It is not a durable or
terminal-success receipt. Borrowing waits can still be dropped and resumed
without losing partial bytes or replaying an in-flight disk operation.

## Boundaries and validation

A committed, cancelled or unresolved-publication writer cannot restart. A late
cancellation can still arrive after finalization has started; the region drains
the real operation and publication may succeed. Existing pathname races,
external file mutation, synchronous syscall duration and CopyAndVerify visibility
limitations remain. Prefix validation costs a read of the retained bytes and
adds no cancellation latency bound. Caller-owned source/manifest memory is not
covered by the payload and ledger limits.

Thirteen Rust tests are authored across offset inspection and suffix recovery.
They cover 24 disconnect/retry scheduler/policy combinations, quota and stale
snapshot refusals before source polling, prefix corruption and tail replacement,
chunk-only pins, full/empty prefix authentication, borrowing-wait abandonment,
clone backpressure and cancellation followed by a live-context retry. A native
TCP scenario on both schedulers truncates one connection, resumes only its
suffix on another connection, leaves that peer open and reads its next frame.
These tests have NOT been compiled or executed in the authoring environment,
which lacks Rust/Cargo/rustfmt/RCH. Source/hash and whitespace checks do not
substitute for native execution or downstream compatibility testing. No test
gate is weakened, and no release or performance claim is made.
