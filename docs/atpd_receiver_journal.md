# Executable partial-receiver restart

`atpd-live receive-journaled` and `atpd-live resume-receiver` expose the existing
paired-file and compact receiver WAL profiles through the executable. They
compose with `send-journaled` / `resume-journaled`, so both endpoint processes can
exit before source EOF and continue using their original journals and stable
source.

This is an opt-in **single-client, single-transfer** command. It uses the existing
`atp-live-resume/1` protocol, mandatory mutual TLS, byte revalidation, persistence
barriers, and private file store. It does not change the shared receiver, its
revocation policy, the legacy commands, or the SDK wire format. The code and tests
are committed, but were not compiled or executed in the authoring environment.

## Creation and restart

Use the existing strict receiver JSON settings with exactly one `clients` entry,
`max_connections: 1`, explicit identities/roots, and bounded runtime settings.
Every parent directory must already be a private Unix directory. The data path
must be immediately inside that client's configured inbox; the WAL must be outside
it because its growth is accounted against its own independent budget.

```sh
atpd-live receive-journaled \
  --config /srv/atp/receiver.json \
  --journal /srv/atp/state/receiver.wal \
  --data /srv/atp/inbox/transfer.data \
  --attempts 16 --max-snapshots 4096 --max-journal-bytes 16777216 \
  --retry-delay-ms 250 --proof-recovery-secs 30
```

Both files are create-only. Existing files are never overwritten or treated as
permission to begin another session. Partial creation failures retain whichever
files were created; there is no cleanup, deletion, or automatic repair. The
explicitly selected data file exists before the first authenticated transfer,
but a header-only WAL contains no recoverable negotiated session.

After the original receiver exits, restart on its original nonzero endpoint:

```sh
atpd-live resume-receiver \
  --config /srv/atp/receiver.json \
  --journal /srv/atp/state/receiver.wal \
  --data /srv/atp/inbox/transfer.data \
  --retry-delay-ms 250 --proof-recovery-secs 30
```

If initial binding used port zero, preserve the actual `ready.address` in the
receiver settings before restarting. The sender retains its original endpoint;
recovery does not redirect it. Missing, torn, unresolved, identity-mismatched, or
exhausted history is refused without creating replacement files. Resume has no
`--attempts`, `--max-snapshots`, or `--max-journal-bytes` override.

Reprovision the same client selector and server identity with current trust policy.
The current receiver configuration must cover the saved negotiation; it cannot
renegotiate an old integrity chain. The original client must still authenticate,
and the sender retains its verified server-certificate pin. These commands do not
accept the shared service's `--revocations` reload option.

## Compact journals for large files

Pass `--intent` at creation to select the existing SDK compact profile. This
keeps pending payloads in two reusable slots in a fixed **131,328-byte** private
intent file; the WAL records metadata and cryptographic commitments. Completed
historical payloads are revalidated against their original data offsets on
reopen. This avoids accumulating a second payload copy throughout WAL history.

```sh
atpd-live receive-journaled \
  --config /srv/atp/receiver.json \
  --journal /srv/atp/state/receiver.wal \
  --intent /srv/atp/state/receiver.intent \
  --data /srv/atp/inbox/transfer.data \
  --attempts 16 --max-snapshots 262144 --max-journal-bytes 67108864 \
  --retry-delay-ms 250 --proof-recovery-secs 30

atpd-live resume-receiver \
  --config /srv/atp/receiver.json \
  --journal /srv/atp/state/receiver.wal \
  --intent /srv/atp/state/receiver.intent \
  --data /srv/atp/inbox/transfer.data \
  --retry-delay-ms 250 --proof-recovery-secs 30
```

With full 64 KiB epochs, the compact format needs 131,075 snapshots and
55,182,535 WAL bytes for a 4 GiB file before extra retries. Configure
`epoch_bytes`, `max_transfer_bytes`, and the client's retained-data limits to
cover the intended transfer. These are format bounds, not an executed 4 GiB
transfer measurement. Smaller epochs and reconnects consume more records.

The intent path must be distinct from the WAL and data paths, outside the inbox,
and inside an already private directory. All three files are create-only and
remain pinned to their original inodes. The intent file's fixed allocation is
additional to the WAL limit and the inbox data reservation. Its slots contain
plaintext and require the same protection as the data and WAL.

Supply the same original `--intent` file on every restart. Omitting it, supplying
a copied file with a different inode, or mixing profiles refuses recovery. No
format is selected by guessing, no existing journal is migrated, and no WAL
history or persistent budget is reset. Commands without `--intent` retain the
original V1 profile and its original limits.

## Both endpoint processes can restart

The sender must retain its own in-memory session or protected sender journal and
original stable source. For a journaled sender, run `resume-journaled` after the
restored receiver emits readiness. Do not run a fresh `send-journaled` with a new
nonce against an old receiver session.

The receiver validates the complete persisted prefix and every surviving byte of
a pending epoch before binding. It appends only the missing suffix of an identical
retransmitted epoch; it never truncates the file or guesses a remote offset. The
sender independently verifies its consumed source prefix before reconnecting and
accepts only its retained acknowledgment window. No full-source network restart
or second receiver file is introduced. The source's unread suffix must remain
stable; neither journal can reconstruct an arbitrary lost producer.

`Finalizing` remains unresolved. A crash after publication intent but before its
successful durable observation is not automatically retried, even when the data
looks complete. `Committed` can restore the final-Proof exchange. Torn journals
are refused as a whole. This is not universal crash recovery or exactly-once
execution of arbitrary application effects.

## Disk admission remains valid after restart

The inbox is scanned under its existing process-lifetime exclusive lock. Creation
reserves one data entry and its full configured maximum size. It does not charge
the two aliases used by the separate atomic-publication profile. The lock file
itself still counts as a retained entry.

Restoring a receiving file reserves only the difference between its already
inventoried length and the current configured transfer ceiling. Existing bytes
and entries are not charged twice, and other retained files are not ignored.
This prevents both false quota refusals and a restart-based quota bypass. A
committed restore needs no data-growth reservation. A wider current ceiling may
reserve conservatively; the original file-store limit remains enforced.

Connection retries reuse the same reservation. No space is refunded for an
interrupted operation. Restart rescans actual files but cannot discard existing
usage or override the journal's immutable limits. The WAL has independent byte
and snapshot ceilings. V1 includes plaintext pending-epoch payloads; the compact
profile uses the separately budgeted intent file. Both profiles reserve room for
the durable `Committed` record before admitting `Finalizing`, so exhausted
journal capacity cannot newly authorize a commit whose receipt will not fit.
Files and history are retained on every success/failure path.

## Ownership, stopping, and observations

Preparation and every receive attempt run in scope-owned children. Preparation
rehashes the retained data before returning its bound receiver. Each attempt
returns the same paired owner and complete report through its canonical join.
Signal polling drops only temporary join waits, never a transfer or started WAL
write. No detached worker or replacement sink is introduced.

SIGINT/SIGTERM stops subsequent attempts. The currently admitted attempt, which
may still be awaiting accept, can finish within the configured shutdown grace;
a later signal or grace expiration requests attributed cancellation. Parent
cancellation also propagates. Started persistence and commit operations retain
the SDK's drain semantics. A blocked syscall or stdout consumer can delay shutdown;
there is no hard process-exit deadline.

After a committed checkpoint is observed, the process keeps a fixed-duration
final-Proof recovery window. Reconnects do not renew that process's deadline.
Restoring a committed file starts a new explicitly selected process window, but
the original cumulative attempt limit still applies and may end it sooner.
This is not a persisted wall-clock expiry policy.

`ready` is emitted after preparation, ownership, and actual binding. It reports
`mode: journaled_single`, `restored`, `attempt_limit`, and the saved checkpoint.
It does not establish delivery. `receiver_journal_attempt` separates the actual
transfer result from the durable checkpoint and independent storage interruption.
The receiver may know locally flushed bytes beyond its last persisted prefix.

`receive_result` follows canonical joins and confirmed runtime drain. Its
`durable_receipt` is the last confirmed local committed checkpoint;
`proof_write_confirmed` records whether this process completed a Proof write.
`sender_receipt_observed` is always false: writing Proof does not acknowledge its
receipt. Successful receiver exit means verified durable local completion with
no fatal operation/ownership failure, not that the sender received Proof. The
sender must independently require its exact final Proof before reporting delivery.
Unknown state after a failed join is null, not fabricated rollback.

**The data path is private and in place, not atomically published.** It exists
while incomplete. Consumers must require committed journal evidence or an exact
successful transfer receipt. No destination rename, hard-link publication,
decryption, file deletion, journal compaction, or new receiver-wide catalog is
added. Protect the paths, ancestry, ACLs and backups; checksums detect corruption,
not malicious rewriting or rollback, and synchronization does not prove power-loss
behavior for every filesystem/device.

## Validation scope

Unit tests cover CLI budgets, explicit profile selection, non-renewing Proof
retention, persistence-result projection, original two-alias accounting,
single-file reservation, and remaining growth in the presence of unrelated
retained data. Executable tests cover
both peers restarting before EOF, unchanged original data inode and exact hash,
changed-data and quota refusal before readiness, ordinary/empty completion,
persistent snapshot exhaustion, missing history, and mandatory client TLS refusal.
The compact command case transfers a 512 KiB file under a 16 KiB WAL ceiling,
kills both processes at a durable receiver prefix after discarding its ACK,
resumes from the original files, and verifies exact content and all three
inode identities. Omitted/foreign intent files and invalid path placement must
refuse without rewriting retained history or creating replacement data.

The crash test uses an opaque relay, witnessed WAL/data progress, exclusive file
locks, and independently checked WAL checksums before killing its own processes.
It exercises current-thread and sharded runtime configurations. Full WAL inspection
is performed after the owner is quiescent except at the deliberately parked retry
boundary. No existing test is removed or weakened; all test artifacts are retained.

Rust/Cargo/rustfmt/RCH are unavailable in the authoring environment. The attempted
RCH check stopped at command-not-found, not at a Rust compilation result. Source
preservation, whitespace and Git blob checks do not establish passing native tests.
Shared multi-client partial restoration, atomic destination publication, and
reconciliation of an uncertain application commit remain separate integrations.
