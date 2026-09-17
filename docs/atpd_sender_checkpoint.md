# Checkpointed sender commands and source-free Proof recovery

`atpd-live send-checkpointed` persists the SDK's finalization intent before
sending `ObjectComplete`. `atpd-live recover-proof` reopens that protected intent
in a new sender process, with no source argument, and recovers only an already
committed transfer's exact final Proof. Both use the existing `atp-live-resume/1`
wire profile, TLS authorities, and SDK implementation. Existing `send`,
`send-resumable`, and receiver commands are unchanged.

## Send with an explicit checkpoint

Use the existing strict sender JSON settings, explicit client identity, server
roots/name, endpoint, size limit, epoch limit, and runtime settings. The checkpoint
must be a new file in an existing private Unix directory. Configure a receiver
that retains completed sessions; recovery after receiver restart additionally
requires `serve-durable --recover-committed` with its original ledger and inboxes.

```sh
atpd-live send-checkpointed \
  --config /srv/atp/sender.json \
  --input /srv/atp/input.bin \
  --checkpoint /srv/atp/state/upload.final \
  --attempts 4 --retry-delay-ms 250
```

The command validates settings, credentials, and input before creating the store.
Existing checkpoint paths are refused, never overwritten or silently reused.
The source is opened once; in-process retries retain the same source, integrity
state, session, and file-store owner. The SDK requires all epochs acknowledged
and actual source EOF before storing the intent. A failed or interrupted store
withholds finalization for that attempt and is not automatically bypassed by
another send. Earlier receiver writes are not rolled back.

The checkpoint's maximum canonical size remains 554 bytes. It contains endpoint,
TLS name, server leaf pin, nonce, offered/agreed limits, final chain, length, and
source SHA-256, not source bytes, private keys, or a success flag. A created but
empty file means the checkpoint barrier never completed; file existence alone
is not useful delivery evidence. No whole-source spool is added.

## Recover after sender exit

Retain the same protected file and reprovision the original client identity and
explicit sender configuration. There is deliberately no `--input` option:

```sh
atpd-live recover-proof \
  --config /srv/atp/sender.json \
  --checkpoint /srv/atp/state/upload.final \
  --attempts 4 --retry-delay-ms 250
```

The command exclusively opens and validates an existing complete checkpoint; it
never creates a replacement. The SDK requires caller agreement with the saved
endpoint and TLS name, current size/epoch policy, fresh server validation plus
the saved server-certificate pin, and current receiver-side client authorization.
Changing credentials does not turn the saved nonce into permission.

Recovery has no source object and cannot transmit `ObjectData`. It requires the
exact negotiated state, prefix/hash and committed flag, then the matching final
Proof. A fresh or unresolved receiver is refused even for an empty stream. A
valid local intent does not authorize initiating or repeating publication.

If both processes exited, restart the receiver with its original protected
ledger, inbox mapping, identity and endpoint, and explicitly enable committed
recovery. Its existing recovery path rehashes the published file before supplying
a historical receipt. Then run `recover-proof`. Neither command creates another
publication or rewrites its saved history merely to make recovery succeed.

## Ownership, retries, cancellation and output

`--attempts` is required and limited to 1 through 1,024; `--retry-delay-ms` is
1 through 60,000, defaulting to 250. Only eligible transport failures are retried,
under the same owner. Certificate/continuity refusal, local failure, and storage
barrier errors are not retry permissions. Each new explicit process receives a
new finite attempt budget; this is not a persisted cross-process retry counter.
There is no automatic process restart or new-session fallback.

One canonical scope child owns each attempt and returns both the same transfer
and store through its join. Signal polling drops only a join wait, never that
child's transfer. SIGINT/SIGTERM and parent-context cancellation stop further
attempts, request attributed cancellation, and join the active child. A started
store retains the SDK's drain semantics, which can outlive its operation timeout.
A nonreturning syscall or user operation cannot be safely preempted.

`checkpoint_attempt` records preserve actual transfer and persistence observations.
The final `send_result` is emitted only after runtime shutdown confirms drain.
It reports `source_free`, `checkpoint_persisted`, `checkpoint_kind`, transfer
receipt, stopping state, and whether final Proof was received. Only a validated
Proof yields successful command exit. A stored intent, source EOF, receiver
presence or successful runtime teardown does not establish delivery.

A checkpoint-blocked report keeps `stored`, `storage_failed`, and interruption
separate. Join/spawn failure reports unknown checkpoint state as null rather
than guessing whether an in-flight write finished. Arbitrary sink, certificate,
path and cancellation messages are omitted from these structured records.
Preflight failure emits no attempt record; stderr and unsuccessful exit identify
that no worker was admitted. The checkpoint remains on every exit path.

Stdout must be drained by the caller. Blocking output can delay the control loop;
there is no hard signal-to-exit deadline. Attempt output is written after its
child joins, and final output after runtime drain. No detached signal thread,
new dependency, file deletion, or ledger compaction is introduced.

## Validation and remaining boundaries

Six command/policy unit tests accompany six executable integration tests in
`tests/atpd_sender_checkpoint.rs`. The latter use independent processes, public
TLS fixtures, real published bytes/inodes, an independently parsed checkpoint
and ledger checksum, and an opaque fault relay. They cover both runtime shapes,
empty transfers, lost Proof followed by sender/receiver restart, unavailable
original input, unchanged history, uncommitted receiver refusal, configuration
and client-authorization changes, create-only paths, and SIGTERM only after
observing real TLS bytes and exclusive file ownership.

**These Rust tests have not been compiled or executed in the authoring
environment.** Source preservation, whitespace and Git-object checks are not
native execution or power-loss proof. Run the repository-authorized validation
route before deployment.

This does not recover a sender interrupted before EOF or a receiver that never
committed. A crash after saving intent but before remote commit remains unresolved.
No exactly-once guarantee for arbitrary effects is added. The file/ledger checksums
provide corruption detection, not encryption, malicious-rollback protection or
remote authority. Retain protected plaintext metadata and publication aliases;
changing or restoring older history invalidates the original recovery contract.
