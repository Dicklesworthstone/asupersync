# Final-Proof recovery after receiver restart

`serve-durable --recover-committed` can answer a reconnect for a previously
committed transfer without uploading or publishing that file again. This is
**final-Proof recovery**, not restoration of an interrupted source or partial
sink. The existing `atp-live-resume/1` protocol is unchanged. The sender process
must retain its original session, observed EOF, agreed limits and final receipt.

This implementation and its twelve new tests have not been compiled or executed
in the authoring environment. Source/patch checks are not runtime validation.

## Explicit opt-in

```sh
atpd-live serve-durable \
  --config /srv/atp/receiver.json \
  --session-ledger /srv/atp/state/sessions.log \
  --recover-committed \
  --max-sessions 32 --max-sessions-per-client 8 \
  --max-session-keys 4096 --attempts-per-session 16 \
  --idle-retention-secs 300 --proof-recovery-secs 60
```

The existing JSON model and create-only ledger initialization remain unchanged.
Without the flag, `serve-durable` continues refusing all prior durable claims,
including committed claims. Other commands do not enable recovery implicitly.
Use the same protected ledger, client-to-inbox mapping, server certificate and
reachable endpoint after restart. This command does not migrate or repair old
state. A fresh sender session or nonce is not continuation of the original one.

The saved ledger receipt does not encode the old negotiated limits. The receiver
narrows the reconnect's offer under its current policy. The retained sender still
requires the agreement to match its original one. Changing a policy, certificate
or address can therefore prevent transparent recovery; no check is weakened to
make a changed configuration look like the old session.

## Admission and read-only verification

A connection first passes fresh mandatory mutual TLS, the resume hello, and the
existing per-client, resident, connection and lifetime-key admission checks.
Only then does the recovery factory consult the ledger for that exact verified
client certificate and stream nonce.

An absent key enters normal durable claim admission. A claim without a saved
commit remains refused, even when a complete-looking destination exists. A saved
commit is eligible only if its length fits the current transfer ceiling and its
locally recorded destination is a private, regular, non-symlink file. The factory
rehashes the entire file, checks exact length and SHA-256, then checks that the
file, its name and parent identity remained consistent during the read. The
ledger must still be unpoisoned, with the same receipt and expected length.

These reads do not append claims or receipts, reserve more inbox storage, create
staging files, change permissions, synchronize files, or delete anything. A full
durable key budget or full retained-storage quota can therefore still serve a
valid committed receipt, subject to the independent live-service limits. Existing
startup ledger validation/synchronization and inbox scans remain unchanged.

Rehashing uses the blocking-I/O path, a 64 KiB zeroized buffer per read, and a
separate limit of 64 queued or active recovery reads per ledger. An abandoned
factory requests cancellation between reads, but its blocking operation retains
its read credit and ledger reference until it finishes or is discarded before
execution. An individual nonreturning OS call cannot be preempted. The existing
factory timeout can refuse a large-file rehash; it does not fabricate success or
start another detached rehash. A failed factory leaves a refusal tombstone for
that key in the current service, as in the existing service contract.

These checks are not a hostile-filesystem sandbox. Keep directories, ancestors,
ACLs, aliases, ledger and destination content trusted and unchanged while serving.
A privileged rewrite/rollback or changed client-to-inbox mapping invalidates the
protected-local-state contract. The v1 journal has no authenticated external
rollback anchor. A file rehash establishes current content, not new publication
or universal power-loss durability.

## A restored receipt has no writable sink

The implementation uses the existing SDK `ResumableService::next_restoring`.
Its application factory returns `ResumeSessionInit::Fresh(sink)` or
`ResumeSessionInit::Committed(receipt)`. The normal `next` method always wraps
its existing factory as Fresh,
preserving its behavior. The ledger lookup binds the client and nonce. The SDK validates nonce,
lengths and receipt shape; applications using this generic API must establish trustworthy persisted
commit provenance and any required file verification themselves.

A Committed seed creates no sink. The session retains the exact completed prefix
and final digest, not a fabricated running SHA-256 state. Every ObjectData frame
is refused. The peer must send the exact ObjectComplete before the receiver can
write Proof. The sender must still receive and validate that Proof before success;
a saved receipt or completed flag alone is insufficient.

Recovery reports use `receipt_reused: true` and `sink_written_bytes: 0`. Their
`completed_receipt` is historical local evidence, even when that attempt fails.
`publication` is null because the new owner created no file-publication handle.
The receiver's `proof_write_confirmed` never implies that the sender received it.
Readiness adds `committed_proof_recovery`; `continuation_restored` remains false
because no writable partial continuation has been restored.

The recovered owner uses the same explicit attempt, retention and tombstone
rules as other sessions. First collection of its completed report opens its
one non-renewable in-process Proof recovery window. Neither the attempt count
nor that timer is persisted by the v1 ledger; a deliberate process restart can
open another bounded historical-receipt serving window. It cannot create another
publication for that key. Retirement still cannot resurrect a key within the
same service owner or refund retained storage charges.

## Tests and remaining gaps

Six new ledger/command unit tests cover real-file
rehash after reopen, unresolved claims, modified/truncated/missing/symlinked or
public files, tighter limits, poisoned history, independent read ownership and
explicit CLI selection.

Six executable tests use independent processes and mutual-TLS peers. The main
journey drops encrypted final-response bytes through an opaque relay, confirms
the actual synchronized receipt and destination, stops the still-alive sender,
kills the test-owned receiver, and restarts it on the same address and ledger.
After resuming the original sender it checks exact Proof, unchanged journal,
one existing destination inode, no additional quota reservation or publication,
and zero recovered sink writes. Changing the source only after observed EOF is
a test negative control for accidental rereads. Other tests cover empty receipts,
wrong final commitments, new data after completion, old refusal-mode compatibility,
unresolved history, modified files and current certificate authorization.

The existing SDK restoration implementation is preserved, not rewritten.
All twelve new tests remain unexecuted. Use the authorized RCH validation route
before deployment. Partial-stream crash recovery, durable sender continuation,
publication-to-ledger failure reconciliation, hostile rollback resistance and
exactly-once arbitrary external effects remain separate unfinished work.
