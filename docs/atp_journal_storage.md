# Journal storage: uncertain appends and lossless generation retention

`AppendJournal` keeps its existing public methods and record framing. Appends,
manual compaction and automatic rotation now share failure-aware storage and a
carry-forward history implementation. This is synchronous, single-writer host
filesystem code. It adds no executor, dependency, background retry or payload
recovery protocol.

## Failed appends are not safe to repeat in place

A failed write may leave part of a frame. A failed synchronization may follow a
complete record, including cancellation or commit intent. In either case the
old in-memory sequence/index is not a reliable description of disk state.

After a write, flush, synchronization error or storage panic, the instance
refuses mutation and resume summaries until it is dropped and reopened through
normal journal recovery. The original error is returned. Statistics, cached
entries and raw disk reads remain diagnostic observations, not authorization to
resume a transfer. Do not blindly resend the operation that returned an error:
a complete record may already exist and an automatic-compaction error may
follow a successfully persisted caller append.

A private buffer owner dismantles an abandoned `BufWriter` without flushing it.
Dropping a failed operation therefore does not retry buffered bytes behind its
unreported partial frame. Bytes already handed to the operating system remain
untouched. Reopen uses the existing torn-tail recovery behavior and reconstructs
the actual sequence frontier, rather than resetting or appending behind damage.
The writer also rejects a serialized frame exceeding the reader's existing
16 MiB limit before opening/writing a generation. This does not bound memory
already owned by the caller or allocation during record serialization.

## Compaction carries history before deleting generations

The old rotation created an empty generation and later deleted old files. It
could lose offers, progress and terminal state while an in-memory transfer index
still appeared complete. Rotation now performs this ordered operation:

1. Flush and synchronize the current writer; read and reconcile retained disk
   history against the live transfer index. Authenticate every carried record.
2. Exclusively create the next generation without appending to or truncating an
   existing candidate. Copy original records, signatures and sequence numbers in
   order, then append one new signed compaction boundary.
3. Synchronize the entire candidate inode and, on Unix, its directory, including when
   ordinary appends use `force_sync: false`.
4. Install the new writer/frontier and only then run retention cleanup. On Unix,
   a final directory synchronization follows removal of expired files.

Before both candidate barriers succeed, every original generation remains.
Write errors, barrier errors and panics retain the new candidate as evidence
and fence the instance; they do not authorize cleanup. Reopen merges exact
copies by sequence, so an interrupted snapshot cannot replay every copied
record twice. Contradictory copies at the same sequence fail rather than silently
choosing one, including conflicts between different transfer IDs. A truncated
latest generation rotates under the existing recovery rule. Torn generations
are retained beyond the normal retention window instead of discarding their
unparsed evidence.

A complete candidate may exist even when compaction reported a synchronization
error. Reopening observes it alongside the originals, not as proof that the
failed barrier became durable. An error during post-publication cleanup can
follow a fully installed snapshot. Neither result implies rollback.

The end marker is used to distinguish carried bytes from new append growth,
including after reopen. It never authorizes ignoring earlier files. Automatic
rotation applies `max_journal_size` to new bytes after that prefix, avoiding a
full-history rewrite after every small append to an already-large snapshot.

## Scope and compatibility

All complete retained records are carried, including cancellation, rollback,
commit intent, completion, proofs and earlier compaction boundaries. This is
lossless consolidation of generations, not semantic garbage collection. An
application cannot infer that a completed transfer has been forgotten merely
because its first generation expired. It also cannot recover history already
deleted by an older implementation.

`max_generations` retains previous clean generations in addition to the current
snapshot; damaged evidence may exceed the window. Snapshot size and total
retained history are not bounded by `max_journal_size`. Carry-forward work uses
an ordered in-memory record map plus ordinary encoding buffers, not constant
memory or a claimed throughput improvement. A future history-expiration policy
must explicitly define which transfer/terminal evidence may be forgotten.

Wire formats, public signatures and error variants are unchanged. Exact-copy
deduplication now applies to full reads as well as indexed lookups. A conflict
that was previously silently deduplicated now refuses. Record payload tags do
not authenticate the existing sequence header or prove absence of deletion or
reordering by an attacker. This is crash preservation in a trusted directory,
not cryptographic log completeness, multi-writer coordination, pathname
confinement or protection against external file mutation. Payload fsync before
progress journaling and final object verification remain producer duties.
The existing non-Unix directory-sync helper is a no-op; no Windows directory-
entry durability or universal power-loss guarantee is added.

## Validation boundary

Seven storage and twelve compaction Rust tests are authored. They cover partial
and complete uncertain appends, destructor behavior, real descriptor failure,
every byte cut of a candidate, repeated retention/reopen with a one-entry cache,
automatic rotation, terminal preservation, both candidate durability barriers,
sequence conflicts, wrong keys, malformed canonical lengths, missing history,
empty journals and the public native bitmap recovery path on both schedulers.
All 26 original journal tests and the first seven storage test bodies are kept.

Rust, Cargo, rustfmt and RCH are unavailable in the authoring environment. These
Rust tests have NOT been compiled or executed. An independent byte-framing model
passed 7,120 truncation/reappend cases and 120 retention rounds, with conflicting-
copy and old-data-loss controls; this is not execution of the Rust code. Source
hashes and whitespace checks are structural validation, not native-runtime,
clean-clippy, physical power-loss, downstream compatibility or release proof.
