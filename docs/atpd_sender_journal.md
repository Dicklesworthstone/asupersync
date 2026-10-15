# Resume a journaled sender after process loss before EOF

`atpd-live send-journaled` records each pending epoch before transmitting it.
`atpd-live resume-journaled` reopens that history in a new sender process,
revalidates the consumed source prefix, and continues the same authenticated
session. Both commands use the existing `atp-live-resume/1` protocol and SDK
`send_journaled` / `restore_journaled_reader` APIs, not another transfer engine.

**The receiver must retain the original partial session.** Keep its process
alive and resume before its idle retention, revocation, attempt, or explicit
retirement policy ends that session. The durable receiver ledger alone cannot
restore partial sink state after a receiver crash. Starting a fresh receiver or
changing the client identity is not a supported replacement for continuation.

## Create and resume

Use the existing strict sender JSON configuration and an existing private Unix
directory for the journal. Supply a stable, replayable regular source file.

```sh
atpd-live send-journaled \
  --config /srv/atp/sender.json \
  --input /srv/atp/input.bin \
  --journal /srv/atp/state/upload.journal \
  --attempts 8 --max-snapshots 65536 --retry-delay-ms 250

# After the original sender process has exited and released its journal lock:
atpd-live resume-journaled \
  --config /srv/atp/sender.json \
  --input /srv/atp/input.bin \
  --journal /srv/atp/state/upload.journal \
  --retry-delay-ms 250
```

Creation validates configuration, credentials, the input, and both explicit
budgets before creating a new journal. Existing paths are refused. Resume
requires an existing complete history; it never creates a replacement, new
nonce, new attempt budget, or an unjournaled fallback. It deliberately accepts
neither `--attempts` nor `--max-snapshots`: those ceilings remain fixed by the
original operation. `--retry-delay-ms` is 1 through 60,000, default 250.

Receiver configuration is unchanged. A shared `serve-resumable` or
`serve-durable` process can retain the original sink across sender attempts.
Reconnects reuse that sink and its storage reservation; they do not publish a
second file. A saved prefix or a successfully reopened journal is not delivery.
Successful command exit still requires the actual exact final peer Proof.

## The write-ahead boundary

The first negotiated state is saved before reading the source. Before each
`ObjectData`, the journal saves the acknowledged prefix plus the next pending
epoch's length, hash, and chain. The final source-EOF state is saved before
`ObjectComplete`. A reconnect's cumulative attempt is saved before its socket
connect. A failed persistence barrier withholds that next transmission; earlier
receiver writes are not rolled back.

If a sender loses an epoch acknowledgment, the saved pending epoch may already
have been flushed by the receiver. After revalidation, the SDK accepts only the
saved acknowledged prefix or exactly that pending next prefix, with matching
hashes. The latter advances without writing those bytes again. An arbitrary
remote offset, changed negotiated limits, or changed server certificate is not
accepted as continuation.

Resume rereads the acknowledged source prefix and pending epoch locally, using
at most 64 KiB of revalidation buffering, and verifies their hashes and chain
before networking. It reconstructs the hash state rather than trusting a stored
byte count. This local prefix read is proportional to bytes already consumed;
it is not remote retransmission. A changed or shortened consumed prefix is
refused. A saved EOF additionally requires that the source still ends there.

**Unread suffix stability remains the caller's responsibility.** The journal
contains no original copy or hash of bytes the producer had not read. Do not
mutate or replace the source while any attempt or recovery is possible. Keep
the same provisioned client certificate, endpoint, TLS name, server identity,
and receiver. The saved server leaf pin supplements current TLS validation;
current receiver client authorization and local size/epoch limits still apply.
The checkpoint itself does not grant remote authority.

## File-store API and resource bounds

The SDK store is
`native_auth::live::commit::resume::journal::file::SenderJournalFile`.

```rust
// Before runtime startup; parent exists and is private. Never overwrites.
let mut journal = SenderJournalFile::create_new(path, 65536)?;
// Inside the owning task, use this same journal for every attempt.
let report = sender.send_journaled(&cx, &mut journal).await;

// In a later process, before runtime startup:
let mut journal = SenderJournalFile::open_existing(path)?;
let saved = journal.checkpoint()?;
// Inside the owning task, source is positioned at byte zero:
let mut sender = authority
    .restore_journaled_reader(&cx, remote, source, saved).await?;
let report = sender.send_journaled(&cx, &mut journal).await;
```

The fixed header is 48 bytes. Each append is a 720-byte record containing the
canonical checkpoint (at most 667 bytes), a sequence, reserved zero padding, and
a chained checksum. The explicit lifetime ceiling is 1 through 65,536 snapshots:
maximum logical file size is **47,185,968 bytes**. Identical snapshots are
idempotent and consume no record. A snapshot also occurs for negotiation and
admitted retries; the limit is not a guaranteed number of transferable epochs.
No automatic compaction, overwrite, truncation, file deletion, or tail repair
occurs. Snapshot exhaustion fails before the next network effect rather than
recycling earlier history.

Opening checks the complete bounded file, every checksum and legal checkpoint
transition, and the final input boundary. Only the latest checkpoint is retained
in memory; validation storage does not grow with the number of records. A torn
or inconsistent suffix refuses the whole journal, not a convenient earlier
prefix. A header with no snapshot also refuses recovery: no negotiated operation
was captured. Failures before the first successful negotiation are bounded by
the original process, but no pre-negotiation identity is reconstructed on restart.

One exclusive private single-link file and one pending blocking-pool append are
owned at a time. Queued/running I/O retains its descriptor and lock even when an
awaiting wrapper is dropped. An uncertain append permanently poisons that owner;
later writes cannot hide it. Successful append and reopen include file and parent
directory synchronization. These syscall results are not a universal guarantee
against power loss on every filesystem/device.

This implementation pays a synchronization barrier per new snapshot. Throughput
and storage latency have not been benchmarked. The 64 KiB revalidation buffer is
not a bound on total TLS, runtime, socket, or filesystem-cache memory.

## Ownership, cancellation, and output

The command creates a scope-owned child that owns both source revalidation and
transmission, and returns the same source/session/journal through its actual
join. The existing signal controller handles SIGINT/SIGTERM and parent
cancellation without dropping that transfer future. Started persistence retains
the SDK's cooperative drain semantics, which can outlive the operation timeout.
There are no detached workers or automatic process-restart loops.

`journal_attempt` records keep original transport and storage outcomes separate.
`send_result` is emitted only after canonical joins and confirmed runtime drain.
It reports `journaled`, `resumed`, the latest available snapshot metadata, actual
transfer result, and whether final Proof was received. A failure during source
revalidation is `preparation_refused` with `network_attempt_started: false`.
Journal exhaustion is `journal_blocked`, not a successful partial transfer.
Unknown state after a failed join is null, not a fabricated durable snapshot.

Stdout must be drained by the caller. A blocked output consumer, nonreturning
syscall, or user operation can delay shutdown. No hard signal-to-exit bound is
claimed. Journals contain plaintext sensitive metadata; their hash chains detect
corruption, not malicious rewriting or rollback. Protect the file, source,
inbox, ancestry, and backups. Copying or rolling back history can invalidate
single-owner and continuation guarantees.

## Validation and remaining boundaries

Five real-file unit tests cover reopen, transition checks, snapshot limits,
idempotence, exclusive lock retention, torn/corrupt history, permissions, aliases,
and sticky uncertain append failure. Three CLI unit tests cover explicit budgets,
resume arguments, and independent storage-error reporting.

Three executable integration tests use actual sender/receiver processes, public
TLS identities, independently parsed journal checksums, and an opaque TCP relay.
The main case cuts a response after 4,096 or 8,192 actual staged bytes, kills the
sender while its journal still records a pending epoch and no EOF, rejects a
changed source without networking, then resumes from a new process. Assertions
require exact final bytes/hash, the same receiver inode and session, original
attempt budget, and a single publication reservation. Other cases cover empty
and ordinary delivery, create-only paths, and snapshot exhaustion before data.
Both native runtime shapes are exercised by the recovery scenario.

**Compilation and these Rust tests have not run in the authoring environment.**
Source preservation, patch checks, hashes, and a successful Git commit do not
establish Rust typing, runtime behavior, cancellation correctness, or crash
recovery. Use the repository-authorized RCH validation before deployment.

This adds sender-process continuation while the receiver survives. It does not
restore a partial receiver after its process exits, recover a nonreplayable
producer, or promise exactly-once arbitrary external effects. The separate
`send-checkpointed` / `recover-proof` workflow remains appropriate for source-free
recovery of already-committed finalization; journaled resume explicitly requires
the original replayable source.
