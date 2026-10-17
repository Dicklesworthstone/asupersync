# Sparse-writer content authentication

`SparseWriter` separates local write accounting from content authorization.
A hash of bytes received by this writer detects later local corruption; it does
not establish which bytes the sender was authorized to supply.

## Existing roots remain unchanged

The legacy `MerkleRoot::from_manifest_components` does not include per-object
chunk boundaries. Its format, `ManifestVersion`, and persisted roots remain
unchanged. Do not treat successful legacy manifest validation alone as proof
that a chunk ledger is authentic.

`atp::manifest_chunk_commitment::ManifestChunkCommitment` is an explicit,
versioned SHA-256 supplement. It binds the legacy root, manifest version,
ordered roots, namespaced object identities, kinds, optional sizes and content
hashes, and each chunk's index, offset, length, hash and strategy. Counts and
option-presence tags make the new framing explicit. Profile-only chunk metadata
and other fields omitted by the legacy root are outside this format's claim.
It is neither a signature nor a capability grant.

The trusted producer calls `ManifestChunkCommitment::from_manifest` after
finalizing its manifest, then exports `hash()` through an authenticated
application channel. A receiver imports those independently trusted 32 bytes
with `ManifestChunkCommitment::new`. Recomputing the expected commitment from
an untrusted received manifest is not authentication. Existing CLI and wire
profiles do not automatically transport or negotiate this supplement.

## Verification and migration

The existing `verify(&cx, &manifest)` signature is preserved. It requires a
trusted expected manifest and independently checks bytes against the selected
content-addressed object ID. A manifest-addressed file can continue to use a
whole-object content hash. Optional chunk hints may describe only part of a
file when a whole-object hash authenticates every byte.

**Security behavior change:** a manifest-addressed file with only chunk hashes
can no longer pass `verify` using a legacy root alone. Callers must either use
a trusted whole-object content hash or supply an independently authenticated
`ManifestChunkCommitment` to:

```text
writer.verify_with_chunk_commitment(&cx, &manifest, &expected).await
```

This routes through the same serialized verification and publication lifecycle,
not a separate writer. It checks the commitment before file I/O, including
creation of an empty staging inode. Chunk-only manifests must cover exactly
`[0, file_length)`: no gaps, overlaps, excess bytes, overflow, or zero-length
entries. A pinned empty ledger covers an empty file only. Selected content IDs
remain an independent check even when a manifest supplies a different hash.

A rejected commitment invalidates previous verification. It cannot be ignored
by retrying a chunk-only file through the unpinned method. Verification refusal
leaves staging bytes available for an explicitly authorized retry; successful
publication remains sealed and idempotent. No destination is published by a
verification operation.

## Region-owned execution and backpressure

`atp::journal::sparse_writer::ScopedSparseWriter::new` constructs a writer
through the existing region-owned blocking gateway. Destination-filesystem
probes, their temporary files, and path-manager setup run on the pool, not on
the calling scheduler thread. It uses the same constructor and probe logic as
the historical API; no second executor or platform policy is introduced.

Construction checks authority, cancellation and native runtime/pool admission
before starting the job. An unpolled call performs no I/O. Dropping a started
wait requests cancellation while its region retains the job and destroys an
abandoned writer before close finishes. OS probes cannot be preempted, and
their existing cleanup remains best-effort. The path manager may create its
quarantine directory; cancellation is not rollback of completed setup effects.
The constructor does not publish a destination or staging file.

`SparseWriter::into_scoped()` still consumes an already prepared writer without
filesystem work or changes to ranges, verification evidence, staging files or
terminal state. The historical `SparseWriter::new` and unscoped methods keep
their synchronous host-boundary placement for existing callers. Native async
callers can now use the scoped constructor instead of preparing outside the
runtime and adopting afterwards.

The adapter's `set_expected_size`, `write_chunk`, `verify`,
`verify_with_chunk_commitment`, `commit`, `cancel`, `get_stats`, and `is_complete`
all take an explicit `Cx` with I/O and spawn authority. They use the existing
`ScopedFs::run_io` gateway, requiring native runtime wiring and a blocking pool,
without an inline fallback, detached thread, or nested executor. The same core
writer implements verification, fsync, and publication. Writes take an owned
`Vec<u8>` without a second payload copy; verification takes `Arc<Manifest>`.
Even progress observations run through the pool rather than taking a possibly
contended writer lock on a scheduler thread.

Every clone shares one FIFO admission semaphore. Calls contend asynchronously
before submitting work, so one busy writer does not occupy additional pool
threads waiting for its own operation lock. Admission observes cancellation of
the supplied context, even when a different task polls the wait. Cancelled or
dropped waiters leave the queue; a failed dispatch returns capacity. This is an
internal execution gate, not an extra application obligation: the actual
admitted pool task owns the filesystem operation.

The owned permit moves into the submitted closure and is retained until the
core operation returns or unwinds. Dropping the calling future cannot release
a running operation's slot early. A panic or queued cancellation also returns
capacity. This bounds simultaneous core execution per writer, not the number of
subsequently retiring runtime tasks or total memory retained by callers waiting
with their own buffers. It provides no global transfer-memory quota.

`ScopedWriterResult<T>` keeps the gateway result separate from the actual
`Outcome<T, SparseWriterError>`. A pre-dispatch authority or checkpoint refusal
is an outer error. A running operation's exact outcome survives later caller
cancellation; success is not rewritten as cancellation, and an I/O error is not
proof that a visible publication was rolled back. Dropping a wait requests
cancellation while the owning region still drains the running job and its
captures/results. OS calls themselves are not preemptible.

Cancelling a wait does not implicitly discard the transfer's staging file.
`cancel` is explicit filesystem cleanup and needs a live, authorized,
non-cancelled cleanup context. A failed cleanup retains evidence for retry;
an unresolved publication cannot be discarded by this operation. The adapter
is opt-in: existing daemon/SDK callers are not automatically changed to use it.

## Verification and publication without clone interleaving

Separate `verify(...).await` and `commit(...).await` calls each own one
admission slot. Another clone can run between them, so they do not mean that
the first caller's verification and its publication form one operation.

After setting the expected size and writing chunks, scoped callers can use:

```text
writer.verify_and_commit(&cx, manifest).await
writer.verify_and_commit_with_chunk_commitment(&cx, manifest, expected).await
```

Here `manifest` is an `Arc<Manifest>` and `expected` is an independently trusted
`ManifestChunkCommitment`. Both APIs use one driver, one FIFO admission slot,
and one region-owned blocking job across the real verifier, final durability
barriers, configured publication operation, and staging cleanup. Other clones
wait asynchronously until it returns or unwinds. No extra payload copy,
parallel verifier, executor or publication algorithm is introduced.

Every combined call performs fresh verification of the supplied expectation.
It never relies on a previous successful verification. A rejected manifest,
wrong pin, incomplete object or corrupt content cannot reach publication or
its final fsync. A failed verification retains staging for an authorized retry;
publication errors and panics retain the core's existing sealed uncertainty.

Once this combined job starts, cancellation means drain, not rollback: a
successful verification can still be followed by publication after a late
cancellation request or dropped wait. The exact terminal outcome is preserved,
and the admission slot remains held until the core operation ends. Applications
that require an explicit decision point before publication can keep using the
separate methods and coordinate exclusive ownership of their clones.

Successful combined finalization is one-shot: retrying it refuses rather than
claiming to reverify a consumed staging inode. `commit` can retrieve the already
committed path without publishing again. This serialization covers operations
through the same adapter, not external filesystem writers or pathname races.
`CopyAndVerify` still has its existing non-atomic destination visibility.

## Validation and limits

Seven commitment tests and twelve writer tests cover tampering invisible to the
legacy root, object substitution, incomplete coverage, wrong-pin refusal before
empty-file staging, downgrade attempts, corrupt local bytes, and successful
publication under all three existing policies. Old inline writer tests and the
lifecycle and durability tests are retained unchanged.

Thirteen additional scoped-writer Rust tests cover real-file workflows under
current-thread and multi-thread runtimes, all three publication policies,
empty files, exact domain and gateway errors, pre-cancellation, authority
attenuation, unpolled Send futures, retained ownership during drain, and late
results. State-witnessed backpressure tests cover spare-pool-worker progress,
FIFO admission, supplied-context wakeups, dropped waiters, and capacity recovery
after refusal or panic. Gated dispatcher tests invoke the actual core writer;
they are supplemental to the public-method file-workflow tests.

Six construction tests add twelve public constructor-to-publication workflows,
pre-dispatch refusals, actual probe-error parity, off-thread execution and
destruction of an abandoned constructor result after a witnessed region drain.
Nine finalization tests include twenty-four public policy/scheduler/pin/size
combinations, fresh revalidation after content changes, refusal before the
publication continuation, competing clone admission at the witnessed boundary,
late cancellation, dropped waits, and sealed errors/panics at the actual final
sync barrier. Empty and nonempty manifest-addressed, chunk-only files require
the trusted pin and cannot finalize via a legacy-root fallback. These additions
also remain uncompiled and unexecuted here.

These Rust tests were authored but not compiled or executed in the authoring
environment, which lacks Rust, Cargo, rustfmt and RCH. Source/blob hashes,
whitespace, and preservation of existing test bodies were checked. The earlier
content-authentication work also compared an independent finite-domain Python
coverage model with a per-byte oracle in 287,934 cases; that is not execution
of the Rust implementation or native runtime proof. Run the focused commitment
and sparse-writer library tests through the repository-authorized RCH lane
before deployment. No measured throughput or latency improvement is claimed.

Host path-race confinement and external modification between verification and
publication are not solved here. Historical unscoped placement is unchanged.
`CopyAndVerify` retains its documented non-atomic destination visibility.
No universal power-loss guarantee, automatic protocol migration, complete
manifest authentication, or release-readiness claim is made.
