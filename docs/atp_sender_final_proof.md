# Persisted sender EOF state and source-free final-Proof recovery

The native SDK can now persist the sender's final state before sending
`ObjectComplete`, and recover a missing final Proof after the sender process
exits. This uses the existing `atp-live-resume/1` protocol and current mandatory
mutual TLS. It adds no bulk-transfer engine, source spool, hidden retries, or
new receiver-side publication operation.

Types live under
`asupersync::net::atp::sdk::native_auth::live::commit::resume::finalization`.

## Capture before the first possible remote final commit

Provision an authenticated `LiveStreamSender`, source, explicit endpoint, and
private checkpoint path as usual. On Unix, create the file store before entering
the runtime. It refuses existing files rather than overwriting another operation.

```rust
use asupersync::net::atp::sdk::native_auth::live::commit::resume::finalization::file::FinalProofFile;

// Before runtime startup; the parent must already exist and be private.
let mut journal = FinalProofFile::create_new(checkpoint_path)?;

// Inside the owning task. Drive sender attempts with this same journal.
let mut transfer = authority.resumable_reader(&cx, remote, source, 4)?;
let report = transfer.send_checkpointed(&cx, &mut journal).await;
// Inspect report.outcome. File existence and source EOF are NOT success.
```

All data epochs must be acknowledged and the real source must return EOF before
the store receives a checkpoint. The ordinary `send` method is unchanged and
persists nothing. Use `send_checkpointed` for every attempt of an operation that
requires this boundary; switching to ordinary `send` bypasses it explicitly.

The checkpoint contains the original offered/negotiated limits, endpoint and TLS
name, pinned server leaf certificate digest, nonce, exact final chain, byte/epoch
counts, and source SHA-256. It contains no source data, private key, live TLS state,
or delivery-success bit. Its canonical version-1 encoding is at most 554 bytes.
Decoding checks full length, checksum, canonical address padding, name validity,
nonce/limit/count consistency, and the exact empty-stream chain/hash.

`FinalProofStore` supports other persistence backends. A store must retain pending
state, reject a different intent, and define what successful persistence means.
A storage failure prevents `ObjectComplete` on that attempt. It does not undo
previous epoch writes at the receiver. A started store is drained on cooperative
cancellation or timeout before finalization is withheld. `ResumeError::Checkpoint`
retains actual storage failure, interruption, and whether storage ultimately
succeeded separately. A store that never completes can outlive the operation
limit; it cannot be safely preempted. Hard drop supplies no terminal report.

## Recover without a source

Reprovision current credentials using the same client identity and explicit TLS
roots/name. Reopen and validate the protected checkpoint before runtime startup.
Do not treat a changed source, new nonce, or different identity as continuation.

```rust
// Before runtime startup. Keep the exclusive file owner alive during recovery.
let journal = FinalProofFile::open_existing(checkpoint_path)?;
let saved = journal.checkpoint()?;

// Inside the owning task. The caller must explicitly agree to saved.remote().
let mut recovery = authority.restore_final_proof(&cx, remote, saved, 4)?;
let report = recovery.send(&cx).await;
// Only an exact verified Proof makes report.outcome successful.
```

The recovered owner has no source field and cannot emit `ObjectData`. Each attempt
uses fresh mutual TLS, current server validation AND the saved server leaf pin,
the original endpoint/name, and current size/epoch limits. It requires the exact
saved negotiated hello, prefix, whole-stream hash, and a **committed** remote flag.
It then sends the matching final commitment and checks the exact returned Proof.
A completion flag without matching content, or matching content without commitment,
is refused. This applies to empty streams too: recovery must not accidentally
start another empty publication under changed credentials.

After success, the same owner returns a marked cached receipt without networking.
The checkpoint itself remains an intent and is never rewritten as a success flag.
Attempts are bounded per explicitly created owner (1–1,024), not by a persistent
cross-process retry counter. Admission is held for that owner's entire lifetime.
Keep it within a scope-owned task and join the task to observe its actual result.

## Receiver requirements and limits

The receiver must already have committed the exact transfer. An in-memory retained
receiver can resend its Proof. After receiver restart, the existing protected
ledger and `serve-durable --recover-committed` path can provide the historical
receipt after its own file verification. Neither side's checkpoint grants remote
authority or bypasses current certificate authorization.

A sender crash before EOF is not recovered. A crash after saving intent but before
the receiver commits remains unresolved: source-free recovery refuses incomplete
remote state rather than initiating publication. Partial receiver continuations
are not reconstructed, and a new receiver with an empty registry is not a valid
replacement. The checkpoint checksum is corruption detection, not encryption,
authenticity, or malicious-rollback protection. Protect the file and its ancestry.

The Unix store uses a private single-link regular file, no-follow open, exclusive
OS lock, identity checks, a single bounded blocking-pool write, and file plus parent
directory synchronization. A queued/running write retains its file/lock owner.
Reopening bounds and verifies reads and synchronizes again. Missing, empty, torn,
oversized, aliased, or public files are refused; no replacement, truncation, repair,
file deletion, or automatic storage reclamation occurs. Synchronization success is
not a universal filesystem or power-loss guarantee. Exported metadata is plaintext.

This session adds SDK APIs and a concrete store, not new CLI sender options.
Existing foreground commands do not automatically checkpoint their sender state.

## Validation boundary

Four codec/reconciliation tests and three real-file unit tests accompany the code.
The integration suite drives an independent synchronous mutual-TLS peer that
withholds the first Proof and checks checkpoint bytes before observing the final
request. It checks both native runtime shapes, storage failure, drain after storage
timeout, malformed/uncommitted peer state, wrong Proof, empty streams, and an actual
second sender subprocess. Subprocess results require explicit witness files after
assertions, not exit status alone. Fixtures are public test material and retained.

These Rust tests have not been compiled or run in the authoring environment.
Source preservation, encoding models, and Git hashes do not establish runtime or
power-loss behavior. Use the repository-authorized RCH validation path before
relying on this implementation in production.
