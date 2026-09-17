# Revoke active shared-receiver clients with a protected policy file

`serve-resumable` and `serve-durable` accept an optional `--revocations` path.
They load this policy before readiness and reload it on SIGHUP. Each valid
update tightens both the shared TLS allowlist and the running service's client
denials. It cancels matching routed workers without stopping unrelated clients
or replacing the listening socket. The transfer protocols and JSON receiver
settings remain unchanged; the flag is not enabled by other commands.

```sh
atpd-live serve-durable \
  --config /srv/atp/receiver.json \
  --session-ledger /srv/atp/state/sessions.log \
  --recover-committed \
  --revocations /srv/atp/state/revocations.json \
  --max-sessions 32 --max-sessions-per-client 8 \
  --max-session-keys 4096 --attempts-per-session 16
```

## Provisioned snapshots, never implicit grants

The policy must already exist as a private, single-link regular file in an
existing private Unix directory outside the inboxes. The receiver never creates,
repairs, truncates, or deletes it. Protect the directory's ancestors and ACLs as
well as the file's permission bits. A missing or invalid initial policy fails
startup before inbox admission and listener readiness.

```json
{
  "schema_version": 1,
  "generation": 1,
  "revoked_certificates": [
    "1111111111111111111111111111111111111111111111111111111111111111"
  ]
}
```

The selector is the SHA-256 of the complete client leaf certificate, not merely
its public key. Use explicitly provisioned real selectors, not the example value.
An empty initial list revokes nobody; it does not authorize clients absent from
the existing receiver configuration. Roots, server identity, client inbox mapping,
and resource limits cannot be changed through this policy.

Each later snapshot needs a greater nonzero generation and must include every
previous denial. Reapplying an identical logical snapshot at the same generation
is idempotent. A lower generation, changed same-generation snapshot, removed
denial, duplicate selector, unknown field, or invalid selector is refused. Input
is bounded to 128 KiB and 1,024 distinct denied certificates. Denials are not
evicted or recycled to admit more policy entries.

Provision and synchronize the complete replacement before signalling the process:

```sh
kill -HUP "$RECEIVER_PID"
```

Retain the previous snapshot for diagnosis rather than deleting history. Do not
signal during a partial write. An atomic replacement within the same protected
directory is supported; replacement of the directory itself is refused by the
live owner. This feature does not install a file watcher: file changes take effect
only at startup or after a successful requested reload. Without `--revocations`,
these commands do not install a new SIGHUP handler.

## Applied authority is not completed cancellation

The read uses the blocking pool, bounds the bytes, checks file/directory identity,
and synchronizes the file and its parent before application. No manager admission
is driven while awaiting that read. Existing workers still run; revocation is not
instantaneous at the moment a file changes or a signal is sent.

After validation, the manager replaces the TLS allowlist with the configured
clients minus all denials, then installs service denials without an intervening
await. A handshake that passed earlier verification still faces the service's
routing check before any new sink, storage claim, or historical receipt factory.
Every new nonce for the revoked certificate is denied. Current authorization
also applies to restored final Proofs, not only uploads.

The `revocation_policy_applied` record identifies the generation and reports new
denials, signalled connections, and retained sessions. `drained: false` is
intentional: it does not assert that cancellation, publication, or cleanup ended.
Collect subsequent `resume_completion` and `session_retired` records. A started
application commit is drained and may succeed; neither that success nor a prior
uncollected success is rewritten into rollback. Idle affected sinks are retired
with reason `client_revoked`, preserving snapshots and refusal tombstones. Files
and staging aliases remain, and retained-storage charges are not refunded.

## Invalid reloads fail closed

An unreadable, malformed, oversized, non-private, stale, or authority-restoring
requested snapshot is a service failure, not permission to keep silently using
the old grants. The receiver empties future TLS admission, cancels the service,
closes its listener, and collects actual child results before returning failure.
Its `revocation_policy_rejected` record names the last accepted generation and
states that admission closed; it does not claim children already drained.
Joined transfer/publication results remain emitted unless stdout itself fails.

Only one policy read is queued or active in this owner. Its wait uses the existing
operation timeout. A timed-out blocking read cannot later change policy; the
owner is already failing closed. Runtime teardown must still account for that
read. A nonreturning syscall or commit, or a blocked stdout consumer, can delay
shutdown. There is no hard signal-to-exit or universal filesystem durability claim.

## Restart and trust boundary

Restart with the same protected snapshot to reapply denials before readiness.
The generation high-water mark is in memory: replacing the policy with an older
valid snapshot while stopped is not detected by an external freshness anchor.
Selecting another file, omitting the flag, or restoring older backups invalidates
the policy's continuity. The session ledger is not a revocation-generation ledger.
Protect and retain both when using durable receipt recovery.

This is an operator-controlled certificate denial policy, not issuer CRL/OCSP,
signed distributed revocation, hot reload of trust roots, or an API for restoring
a revoked certificate. It adds no global authority across unrelated service
processes. Permission and identity checks are not a hostile same-user filesystem
sandbox. File/directory synchronization success is not proof against every device
failure or malicious local rollback.

## Validation boundary

Four parser/real-file unit tests accompany four executable integration tests.
The latter use independent synchronous mTLS peers, real epoch ACKs and staged
bytes before signalling, two client inboxes, unchanged published inode/history,
receiver restart, monotonic-policy refusals, and startup failure cases. The
active-client isolation scenario targets current-thread and sharded runtimes.
Test-created files and old policy snapshots are retained, not deleted.

These tests have not been compiled or executed in the authoring environment.
Successful Git publication, source preservation, and file hashes are not Rust,
native cancellation, handshake, or power-loss validation. Run the repository's
authorized RCH validation before relying on this implementation in production.
