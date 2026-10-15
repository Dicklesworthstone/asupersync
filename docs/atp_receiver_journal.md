# Partial receiver restart with a write-ahead journal

The opt-in receiver journal records an exact pending epoch before its first sink
write and a synchronized completed prefix before its acknowledgment. A new receiver
process can verify the surviving sink bytes and continue the same session, including
an epoch that was only partly written. It never truncates data, assumes an arbitrary
remote offset, or treats an unconfirmed application commit as permission to retry it.

This uses the existing `atp-live-resume/1` wire profile, mandatory mutual TLS, sender
continuity checks, and receiver implementation. Existing `receive`, shared-service
factories, CLI commands, sender APIs, and the `LiveFileSink` publication contract
are not automatically switched to journaling.

**Compilation and the new Rust tests have not run in the authoring environment.**
Source review and Git-object checks are not native execution or power-loss evidence.
Use the repository-authorized RCH validation before deployment.

## A concrete private file receiver

Types are under
`native_auth::live::commit::resume::receiver_journal::file`.
Provision the journal and data file in existing trusted private Unix directories
before starting the runtime. The paths must be distinct and previously absent.

```rust
let journal = ReceiverJournalFile::create_new(
    journal_path,
    data_path,
    ReceiverFileLimits {
        max_data_bytes: 8 * 1024 * 1024,
        max_snapshots: 4096,
        max_journal_bytes: 16 * 1024 * 1024,
    },
)?;

// Inside the owning task, with an explicitly authenticated receiver authority:
let mut incoming = journal
    .bind_new(&authority, &cx, bind_address, client_certificate_id, 8)
    .await?;
let report = incoming.receive(&cx).await;
// Inspect report.outcome; a saved prefix is not whole-transfer success.
```

`JournaledFileReceiver` owns the listener, session, data inode, and journal. Every
attempt through this wrapper journals; it exposes no unjournaled receive method or
mutable sink. Keep the owner within a scope-owned task and join that task. Eligible
connection retries reuse this same owner rather than creating another pair of files.

After process exit, reopen the existing pair and restore:

```rust
// Before runtime startup; no missing file is recreated and no history is repaired.
let journal = ReceiverJournalFile::open_existing(journal_path, data_path)?;

// Inside the owning task. Bind the endpoint retained by the original sender.
let mut incoming = journal
    .bind_restored(&authority, &cx, bind_address, client_certificate_id)
    .await?;
let report = incoming.receive(&cx).await;
```

Reopen requires the original private, single-link data inode and parent directory,
not a copied or newly created file that happens to contain matching bytes. Both
files are exclusively locked. Started data I/O keeps its descriptor; journal and
commit jobs retain the paired owner. Reacquisition cannot run a second writer while
an old process's outstanding operation still holds the original data lock.

The selected client must exactly match the saved complete-certificate fingerprint.
Current transfer limits must cover the saved negotiation, and the original attempt
budget is not reset. Every new connection still authenticates under current TLS
policy. The sender retains its original endpoint, nonce, negotiated limits and
server-certificate pin. A fresh sender/session is not continuation of the old one.

## Recovering a partially written epoch

A checkpoint stores the complete pending epoch, its predecessor prefix, and both
prefix and pending-content commitments. Restoration first rehashes the complete
persisted prefix. It then compares every actual tail byte with the corresponding
pending-epoch byte. No tail, a partial tail, or the entire pending epoch can survive;
changed bytes, a shortened stable prefix, and extra unrecorded bytes are refused.

The restored receiver advertises the saved stable prefix, retains the actual tail
write cursor, and accepts only an identical retransmitted pending epoch. It writes
only the missing suffix. Once flushed and checkpointed, the ordinary ACK advances
the sender. If the stable checkpoint survived but its ACK did not, the existing
sender's one-epoch reconciliation handles that state without repeating sink writes.

Revalidation uses a 64 KiB scratch buffer, yields between reads, and has one overall
configured operation deadline. It reads the already received prefix locally; it
does not require retransmission of that entire prefix. This is not a 64 KiB bound
on all live memory: the pending epoch, codec, TLS, file adapter, and queued checkpoint
can each own additional buffers. No performance result is claimed.

## Commit uncertainty is preserved

The lifecycle is `Receiving` -> `Finalizing` -> `Committed`. The receiver persists
Finalizing before invoking application commit, and persists Committed only after
that operation reports success. Final Proof is withheld until the successful-commit
checkpoint completes. A started persistence operation drains after cooperative
cancellation/timeout, with its actual storage result and interruption kept separate.

A Finalizing checkpoint is deliberately **not restorable**, even when all data bytes
look complete. A crash may have occurred before, during, or after an external effect;
this journal cannot infer rollback or safely invoke it again. A Committed checkpoint
can restore the exact final-Proof exchange without another sink write or commit.
A torn journal is also refused as a whole rather than silently selecting an older
apparently usable prefix. These are explicit unresolved cases, not universal crash
recovery or an exactly-once claim.

`ResumeError::ReceiverJournal` retains whether persistence ultimately succeeded,
the original store error, and any cancellation/timeout. `ResumeReport.completed`
remains an actual local commit observation even when subsequent persistence or
Proof fails. A report's flushed prefix can be ahead of its last durable checkpoint;
inspect the journal separately instead of treating all local progress as durable.

## Storage and publication boundaries

The paired file profile commits by rehashing and synchronizing its private data
file. **It does not perform atomic destination publication or create a hard-link
alias.** The data path exists while partial. Consumers must not treat file existence
as completion; require the committed checkpoint or exact final transfer receipt.
The existing `LiveFileSink` keeps its separate no-overwrite publication semantics.

A journal has a 96-byte header binding the data inode, directory, and immutable
budgets. Records have sequence, length, reserved fields, an exact canonical checkpoint,
and a hash-chain checksum. The maximum checkpoint is 65,933 bytes, including a full
64 KiB pending epoch. The maximum record is 65,981 bytes. Budgets independently cap
data-file length, journal bytes (at most 128 MiB), and snapshots (at most 65,536).
Negotiation, retries, prefix completion, and finalization consume snapshots too.
An identical snapshot is idempotent; exhaustion blocks the next effect, not history
recycling. Reopen validates the complete bounded chain while retaining only the
latest checkpoint in memory.

Pending payloads are plaintext, so the journal can retain substantial source content
in addition to the data file. Owned pending/export buffers are zeroized on drop;
files, copied buffers, and filesystem caches are not erased. Checksums detect
corruption, not malicious edits or rollback. Protect file ancestry, ACLs, backups,
client configuration, and exclusive ownership. No file deletion, truncation, tail
repair, history compaction, or portability across replacement inodes is supplied.
Synchronization success is not proof of durability on every filesystem or device.

Custom sinks can implement `ReceiverCheckpointStore` and use `receive_journaled`
with `bind_restored_receiver`. Their store must synchronize the actual associated
sink prefix before the checkpoint, preserve pending work, reject invalid successor
states, and bound history. An unrelated reader or a fabricated receipt cannot
establish a sink's provenance. The convenience file wrapper couples these owners.

## Acceptance coverage and remaining integration

Six core tests cover codec/transition rules, every surviving tail length in a sample
epoch, modified or excess data, and unconfirmed commits. Four file tests cover exact
inode ownership, append/reopen, immutable capacity, idempotence, torn history, and
sticky append uncertainty.

Four native integration scenarios plus a subprocess worker exercise real TCP/mTLS,
independent wire and journal parsing, and current-thread/sharded runtimes. The crash
scenario kills the test-owned receiver only after an actual ACK or a parked sink
witness at eight acknowledged bytes plus three bytes of the next epoch. A new process
must complete the same data inode with the exact bytes/hash and preserved attempt
count; a third process recovers its completed Proof. Other cases cover changed data,
wrong client selection, a parked unconfirmed commit, capacity failure before a sink
write, and ordinary/empty transfers from the real SDK sender. Successful subprocess
exit alone is insufficient: tests require post-assertion, post-drain witness files.
These tests are authored but uncompiled and unexecuted here.

This is a standalone one-client SDK receiver path. Shared multi-client restoration,
existing CLI selection, atomic-publication sink integration, and recovery of an
unconfirmed application commit remain separate work. A surviving resumable sender
or its protected replayable-source journal is still required; receiver state alone
cannot reconstruct a lost nonreplayable producer.
