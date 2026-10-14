# Bounded, verified stream-to-file ingestion

`ScopedSparseWriter::receive_exact` connects the native `AsyncRead` interface,
ATP's incremental chunk reader, and the existing region-owned file writer.
It ingests a length-delimited file body without buffering the complete object,
then freshly verifies and publishes it through the canonical writer lifecycle.
This is a reusable ingestion API, not a new wire protocol or an automatically
selected daemon/CLI mode.

## Establish authority before consuming a body

The writer selects an object ID. The independently trusted manifest must
contain that exact file object with a declared length. The explicit context
must carry I/O and spawn authority and belong to a usable native runtime with
a blocking pool. Construction and every disk operation use the existing
`ScopedFs` gateway.

Create the writer with `ScopedSparseWriter::new`, then construct a lazy receive
session. Public types are exported from `asupersync::atp::journal`:

```rust,ignore
use asupersync::atp::journal::{ScopedReceiveOptions, ScopedReceiveError};

let mut receive = writer.receive_exact(
    &cx,
    source,                   // Owned AsyncRead + Unpin + Send + 'static.
    manifest,                 // Arc<Manifest>, authenticated independently.
    ScopedReceiveOptions {
        max_bytes: 64 * 1024 * 1024,
        max_chunks: 1024,
        chunk_size: 64 * 1024,
    },
)?;
let terminal = receive.wait().await;
// Handle both the outer read/gateway error and the inner writer Outcome.
// A successful Outcome contains the published destination PathBuf.
```

A manifest-addressed file authenticated only by chunk hashes requires
`receive_exact_with_chunk_commitment(&cx, source, manifest, options, expected)`.
The expected `ManifestChunkCommitment` must come from an independently trusted
producer, never from recomputing untrusted received metadata. The legacy root
alone does not authenticate those descriptors. Content-addressed IDs and
whole-file hashes keep the existing verification rules.

Preflight runs on the pool before any source poll or staging-file creation.
It rejects a nonfresh writer, missing or mismatched object identity, a nonfile
object, absent size, exceeded byte/chunk limits, an invalid manifest, or a wrong
pin. Chunk-only manifests must cover the complete declared body. This does not
bound memory already owned by the source or the supplied manifest, nor does it
constrain the existing manifest validator's work. Writer construction may have
already created its ordinary quarantine directory or run filesystem probes.

## Backpressure and framing

One fixed-size payload chunk is assembled and its write result is observed
before the next source poll. `chunk_size` is in `1..=1_048_576`. The declared
length cannot exceed `max_bytes`, and its ceiling-divided chunk count cannot
exceed `max_chunks`. A zero chunk limit permits only an empty object. These
limits bound the new receive payload buffer and number of writer ledger
entries, not total process memory or global concurrent-transfer storage.

The input is wrapped in the existing bounded `Take` adapter. Exactly the
manifest's declared length is consumed through `AsyncRead`, not one byte more.
The peer need not close or half-close. On successful verified publication,
`receive.take_source()` returns the original source once, preserving any
following protocol message and the source's own read-ahead buffers. Extra bytes
are deliberately *not* a body error; an unframed application that forbids them
must impose its own trailing-data check. Premature EOF is an explicit
`UnexpectedEof` failure and never reaches publication.

All clones of this writer share one admission slot held across preflight,
reading, writes and finalization. Waiting for source bytes occupies no blocking
worker. The unique permit moves into each submitted disk closure and returns
with its real result; abandoning the caller cannot free a running job's slot
early. Another clone cannot mutate the writer between body chunks or replace
its verification before publication. Do not await a competing clone operation
while leaving a receive session unpolled: finish or drop the session first.
`accepted_bytes()` observes progress without acquiring that slot.

## Borrowing waits, cancellation and results

The receive session owns the source and ongoing future. Dropping only
`receive.wait()` preserves its partial chunk, pending write and finalization.
A subsequent wait resumes the same operation rather than replaying consumed
bytes. No background task, prefetch thread, retry loop or executor is created.
A completed result can be consumed once; later waits return `Completed`.

Dropping the entire session abandons the source under its own cleanup contract
and requests cancellation of an admitted disk job. The job remains region-owned
until it retires, including destruction of an abandoned result and admission
permit. Region close drains admitted jobs; it does not poll or destroy a receive
session still owned by application code. A source poll panic propagates; a
caught panic leaves the session poisoned so another wait cannot replay unknown
source progress. Drop the poisoned session to release its retained owners.

Context cancellation is observed while a source is parked, even when another
task is polling the session. The chunk reader's read-stage checkpoint refusal
is `ScopedReceiveError::Source` carrying `Interrupted`. Filesystem admission or
checkpoint failures remain `ScopedReceiveError::Gateway`. The inner
`Outcome<_, SparseWriterError>` preserves the canonical writer's domain result.
A source error, actual cancellation refusal, or domain error is terminal: this
API does not claim reconnect, replay or cross-process resume.

Once a finalization job starts, it may publish after a late cancellation or
session drop. It retains the actual outcome, not an invented rollback. An error
can follow destination visibility. `accepted_bytes()` counts observed complete
chunk-write receipts only: failed or in-flight writes may have additional
effects, and accepted bytes are neither a durable checkpoint nor whole-transfer
success. Failed/abandoned ingestion keeps staging for explicit authorized
cleanup. Use `writer.cancel` only after the session has terminated or been
dropped and the relevant jobs drained. Sources are not returned after failure
with ambiguous body progress.

## Validation boundary

Thirteen authored Rust tests cover 36 public scheduler/publication/size/read-
fragmentation combinations, a real TCP peer that remains open after the body,
partial-read borrowing-wait abandonment, clone admission and spare-worker
progress, byte/ledger limits, object/pin rejection, source errors and truncation,
content corruption, source poll panic, terminal consumption, explicit-context
cancellation, and retained admission through a dropped running pool step.
The pool-step gate is supplemental helper coverage; the file and TCP scenarios
exercise the public receive methods. No existing tests are removed or weakened.

These Rust tests have not been compiled or executed in the authoring environment:
Rust, Cargo, rustfmt and RCH are unavailable. Source review and exact uploaded
blob/unchanged-baseline comparisons are not native runtime proof or a measured
performance improvement. Run the focused `receive` library tests through the
repository's authorized RCH lane before deployment.

Existing pathname races, external filesystem modification, best-effort probe
cleanup and `CopyAndVerify`'s non-atomic visibility remain unchanged. No universal
power-loss guarantee, protocol authentication, automatic SDK/daemon adoption,
exactly-once network transfer or release-readiness claim is made.
