# Durable session refusal and publication evidence

`atpd-live serve-durable` runs the existing shared resumable receiver with an
additional disk-backed admission and final-commit barrier. Its network profile
is still `atp-live-resume/1`. Existing senders need no protocol change. Existing
`serve`, `serve-resumable`, `receive-resumable`, and `send-resumable` command
schemas remain available; only the explicit durable receiver uses this ledger.

This is **duplicate suppression for the same authenticated certificate/nonce
key across receiver restart**, not restoration of a live stream after a process
crash. Restart refuses every previously claimed key, whether committed or still
unresolved. It does not regenerate a sink, retransmit a saved Proof, or fabricate
continuation from a byte counter. A new nonce is a new operation, not deduplicated
content. A sender losing the receiver process must reconcile instead of starting
a replacement upload with a fresh nonce and assuming exactly-once delivery.

## Provision and run

Use an existing private Unix directory outside every configured inbox. Protect
its ancestors and ACLs as well as its permission bits. Provision the ledger
once, explicitly, while it is not in use:

```sh
atpd-live init-session-ledger \
  --path /srv/atp/state/sessions.log --max-keys 4096

atpd-live serve-durable \
  --config /srv/atp/receiver.json \
  --session-ledger /srv/atp/state/sessions.log \
  --max-sessions 32 --max-sessions-per-client 8 \
  --max-session-keys 4096 --attempts-per-session 16 \
  --idle-retention-secs 300 --proof-recovery-secs 60

# After the receiver has exited and released exclusive ownership:
atpd-live inspect-session-ledger --path /srv/atp/state/sessions.log
```

The JSON receiver configuration is the same explicit TLS/client/inbox model
used by `serve-resumable`. The new receiver rejects a missing ledger; it never
creates an empty replacement during restart. Initialization is create-only and
refuses any existing file or symlink. An incomplete initialization remains on
disk for operator reconciliation, not automatic deletion or overwrite.

Use the same protected ledger for every restart of this durable service. Turning
off this profile, selecting another ledger, deleting records, rolling back a
backup, or editing either journal or inbox content invalidates its guarantee.
No migration from prior memory-only sessions is inferred. Adopt the profile for
new operations after reconciling previous ones.

## Ordered effects

For each newly authenticated key, the once-per-key SDK factory chooses a local
filename, appends and synchronizes a claim, then reserves inbox capacity and
creates the staging file. No file creation or storage reservation follows a
refused claim. A failed storage reservation can therefore leave a claim without
any file; it is deliberately not automatically refundable or reusable.

Existing in-memory reconnects use the retained sink without appending another
claim or charging storage again. The final commit first invokes the existing
`LiveFileSink`: verify staged bytes, synchronize the file, publish without
clobbering an existing destination, and synchronize its directory. Only after
that succeeds is a matching full receipt appended and synchronized to the
ledger. Only after **both** barriers succeed can final Proof be transmitted.

A publication may succeed while receipt persistence fails. Such an outcome
remains `commit_unconfirmed` at the composite barrier, with the independently
observed local publication still `durable`; it must not be interpreted as
rollback. Proof is withheld, and uncertain ledger writes permanently poison
that in-process ledger owner. Started commit work keeps the existing cooperative
cancellation drain behavior and retains ownership until its real result arrives.

Inspection takes the same exclusive lock, validates all records, and emits
bounded JSON records. `claimed_unresolved` means neither success nor rollback;
`committed` is historical local file-and-ledger synchronization evidence. Records
include the verified client selector, nonce, locally chosen filename, byte ceiling,
and saved final receipt where present. They never claim that the sender received
Proof. Inspection does not rehash current destination files or authenticate a
remote peer, and never changes a claim into an admission permission.

## Bounds and filesystem requirements

The persistent lifetime budget is fixed at initialization: 1 through 65,536
keys, with one 256-byte claim and at most one 256-byte commit record per key.
The header occupies 48 bytes, so the largest logical journal is 33,554,480 bytes.
One claim also reserves its eventual commit-record capacity. Completed keys are
not evicted to admit new ones. In-memory service limits and per-client inbox
limits remain independently enforced; restarting does not reset the ledger's
budget. The ledger sits outside inboxes so its bounded growth cannot silently
consume an unreserved inbox allowance. Quota-related refusals use the existing
`retention_refused` result category; an old durable key is `durable_session_refused`.

Startup rejects excessive length before allocating an index, validates every
record and legal transition, and uses a bounded read buffer. The index and an
inspection snapshot are bounded by the configured key count. Records have a
monotonic sequence and chain to the preceding checksum. Unknown types, invalid
reserved bytes, changed filenames, impossible receipts, duplicate claims,
unclaimed commits, checksum errors and incomplete trailing records fail closed.
No truncation, replay of a usable prefix, automatic repair, or file deletion is
performed. Full-record suffix rollback by a privileged writer is not detectable
without an external anchor and is outside the protected-local-state contract.

The journal must remain a private, single-link regular file. Open uses no-follow
and nonblocking flags, checks descriptor/path and directory identity, and takes
an exclusive OS lock. The running foreground process retains that lock even if
runtime teardown cannot confirm that all blocking work has finished. Each
outstanding append also owns a reference. Locks coordinate cooperating processes;
they do not make same-user malicious writes safe. Metadata checks are not a
hostile-directory or hostile-ACL sandbox.

File and directory synchronization results are recorded honestly, but are not
proof of power-loss durability on every filesystem or storage device. The ledger
contains sensitive transfer metadata in plaintext. Its hash chain detects
corruption, not authenticity, encryption, or malicious rollback. Protect and
retain it with the corresponding plaintext staging/final files. The existing
stdout-draining and nonpreemptible-commit shutdown boundaries still apply.

## Validation boundary

Seven unit tests exercise real private files: restart claims/receipts, create-only
initialization, locking, torn/corrupt history, illegal record transitions, sticky
append failure, and receipt consistency. Nine executable integration tests use
independent synchronous mutual-TLS peers, actual file progress, process termination,
restart with identical authenticated keys, persistent capacity, concurrent clients,
authorization refusal, offline inspection, and publication followed by receipt
failure. All test-created fixtures and logs are retained.

**These Rust tests have not been compiled or executed in the authoring environment.**
Use the repository-authorized RCH route before deployment. Source, checksum and
Git-object checks are not runtime, cancellation, or power-loss proof. Restoration
of partial streams, automatic final-Proof recovery after receiver process death,
durable source continuation, and exactly-once external effects remain unfinished.
