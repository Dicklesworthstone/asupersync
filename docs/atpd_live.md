# Foreground authenticated live-transfer command

`atpd-live` connects the native live-stream sender, reusable receiver, and
application-committing file sink in one executable. It is a separate opt-in
foreground profile, **not** a replacement for `atpd start` or its configuration,
PID-file, diagnostics HTTP, identity-store, or RPC protocols. It does not start
the legacy plaintext listener or the QUIC bulk-transfer listener.

The source-tree binary is automatically discovered at `src/bin/atpd-live.rs`.
Enable `atp-cli` on a native Unix target; that feature already enables TLS and
Clap. Use the repository-authorized RCH build/test route. Unsupported targets
or missing features get an explicit nonzero-exit stub, not a pretend listener.
The implementation and tests were added without an available Rust/RCH runner;
this document is an interface description, **not release-validation evidence**.

## Commands

Once the feature-enabled binary has been built:

```sh
atpd-live serve --config /srv/atp/receiver.json
atpd-live send --config /srv/atp/sender.json --input /srv/atp/input.bin
```

`serve` stays in the foreground for an external process supervisor. A `ready`
JSON line is emitted only after credentials, inbox ownership/quota scans, and
the actual TCP bind succeed. Bind port zero is supported; use the actual address
from that line in the sender configuration. No fixed-port reservation/rebind
sequence is used.

`send` reads a regular, non-symlink file using the native asynchronous file
adapter. It does not create a whole-source spool. It exits successfully only
when the native sender receives the exact final Proof and runtime shutdown is
confirmed. There is no implicit retransmission after failure or lost Proof.
Do not edit the source while sending: the protocol commits the actual bytes
read, not a separately snapshotted source inode.

## Receiver configuration

All fields below are required. Unknown fields, unsupported schema versions,
invalid types, missing files, invalid PEM, and unsupported bounds fail startup.
There is no fallback to a default config or ambient/system certificate roots.
Replace the certificate selector placeholder with the **64 hexadecimal digits
of SHA-256 over the complete client leaf certificate's DER encoding**, not its
PEM text or just its public key.

```json
{
  "schema_version": 1,
  "bind": "127.0.0.1:9443",
  "identity": {
    "certificate": "/srv/atp/server-chain.pem",
    "private_key": "/srv/atp/server.key"
  },
  "client_ca": "/srv/atp/client-ca.pem",
  "clients": [
    {
      "certificate_sha256": "REPLACE_WITH_64_HEXADECIMAL_DIGITS",
      "directory": "/srv/atp/inbox/client-a",
      "max_retained_bytes": 107374182400,
      "max_retained_entries": 1000
    }
  ],
  "max_connections": 16,
  "workers": 4,
  "epoch_bytes": 65536,
  "max_transfer_bytes": 1073741824,
  "operation_timeout_secs": 30,
  "shutdown_grace_secs": 30
}
```

Each inbox must already exist as an absolute, private Unix directory with no
group/other permission bits. The directory itself cannot be a symlink. Its
ancestors, ACLs, and same-user processes remain trusted: mode checks and
cooperative file locks are not isolation against a hostile local account.
Do not rename, replace, mutate, or externally write inbox files while serving.

Credentials and settings must be regular non-symlink files. Private-key files
must deny group/other permissions and contain exactly one key. The loader
bounds JSON to 1 MiB, each PEM input to 256 KiB, identity chains to 32
certificates, and root bundles to 128 certificates. It never prints raw config
fragments or key material on parse failures.

Both certificate-chain verification and the exact client-leaf allowlist must
succeed before a sink factory runs. The verified certificate selects its local
inbox. The peer cannot choose a filesystem path. Each admitted sink receives a
random local `.bin` filename and uses no-overwrite publication. Renewing a
client certificate requires updating its selector; this executable does not
hot-reload policy. Gracefully restart to change credentials or settings.

## Sender configuration

The `server_name` is the expected TLS identity, independently of the numeric
routing endpoint in `remote`. Provision a matching server certificate; disabling
name or certificate verification is not supported.

```json
{
  "schema_version": 1,
  "remote": "127.0.0.1:9443",
  "server_name": "atp.example.test",
  "server_ca": "/srv/atp/server-ca.pem",
  "identity": {
    "certificate": "/srv/atp/client-chain.pem",
    "private_key": "/srv/atp/client.key"
  },
  "workers": 2,
  "epoch_bytes": 65536,
  "max_transfer_bytes": 1073741824,
  "operation_timeout_secs": 30
}
```

Worker counts are 1..=32, connection capacity is 1..=1024, epochs are
1..=65536 bytes, and operation/grace durations are 1..=86400 seconds. A zero
transfer-byte limit permits only an explicitly finalized empty stream. The
receiver may narrow the sender's epoch and total-byte limits. The protocol
keeps one epoch in flight, waiting for its sink-flush acknowledgment before the
next source read. This is bounded read-ahead, not a throughput benchmark.

## Retention admission and restart

The service holds an exclusive `.atpd-live.lock` in each inbox until the
**process exits**, including an unconfirmed runtime-teardown path. A second
cooperating owner cannot start a separate quota domain over the same directory.
The lock file is retained, must be a private regular file with one link, and
counts as one directory entry. Do not remove it to bypass a live owner.

Startup scans direct entries, rejects subdirectories/symlinks/special files,
and charges each regular entry's logical length. The sum of configured entry
ceilings cannot exceed one million, bounding the startup scan. Each certificate
and each inbox ownership domain must be unique in the configuration.

Before creating a new sink, admission reserves **two entries and twice the
configured maximum transfer bytes**, covering a full staging file and its final
hard-link alias. It intentionally counts aliases twice even though they share
one inode; this is conservative logical accounting, not physical disk billing.
For example, a 1 GiB transfer ceiling requires 2 GiB of unreserved retained-byte
budget before any new upload is admitted, even for a small incoming stream.
An empty upload still reserves two entries.

Reservations are not refunded during a process lifetime, including after
failed/cancelled creation. A started filesystem operation can finish after its
awaiter disappears. Restart reconciles usage from actual retained files after
the previous process releases its lock. Restart does not delete data or reset
retained-byte usage to zero. This deliberately trades utilization for a simple,
conservative bound; it is not a multi-tenant storage billing ledger.

No staging or published file is automatically deleted. Staging aliases contain
plaintext and remain aliases of the final inode after publication. Protect both
names and never mutate either after commit. An operator must arrange any
retention maintenance while the service is stopped; no cleanup command is
provided by this profile.

## Publication and terminal observations

The receiver checks the final stream commitment and then uses `LiveFileSink`
to rehash the actual staging inode, synchronize the file, create a no-clobber
hard link at the destination, and synchronize the directory. Only after that
commit succeeds can the final Proof be written. Epoch flush acknowledgments
are not complete-file publication receipts.

Stdout is newline-delimited JSON with `schema_version: 1`:

- `ready` identifies the bound address, process, profile, and admitted limits.
- `completion` contains the canonical connection result, verified client
  selector when available, transfer status/receipt, and local publication state.
- `send_result` contains the sender's actual transfer result.
- `stopped` with `drained: true` is emitted only after service and runtime drain
  have been confirmed.

Receipt fields retain bytes, epoch count, stream nonce, chain, and SHA-256.
`flushed_prefix_bytes` and `sink_written_bytes` remain separate from completion.
Publication state is `staged`, `committing`, `published`, or `durable`; `durable`
records successful synchronization calls, not proof of power-loss behavior on
every filesystem. A directory-sync failure may leave a visible complete file.

`committed_without_proof` means the sink acknowledged local commit but final
Proof transmission was interrupted. `commit_unconfirmed` retains verified
stream metadata without asserting rollback or successful publication. A
`receipt` field on an error must therefore be interpreted with `status`.
`final_proof_direction` describes the endpoint role; it is not a separate
success flag. Receiver success records Proof write, **not** acknowledgment
that the sender received it. None of these records is exactly-once delivery,
a signed durable audit journal, or authority to retry automatically.

The output pipe must be drained by the supervisor. JSON output is synchronous;
a permanently blocked stdout sink can delay service polling and signal
observation. A returned output error stops admission and drains existing work
before failure exit. Output retention and log rotation are external concerns.

## Shutdown and remaining boundaries

The first observed SIGINT or SIGTERM closes admission and begins graceful
drain. A later observed shutdown signal or expiry of `shutdown_grace_secs`
requests attributed cancellation of remaining children. Idle signal checks use
a 50 ms timer, without a detached signal thread; OS signals may coalesce.

A commit already started is still drained to its actual result. The grace
period is **not a hard process-exit deadline**: a nonreturning user poll or
filesystem operation cannot be safely undone by abandoning its waiter. An
external hard kill forfeits terminal evidence and requires reconciliation of
retained staging/destination files on restart. There is no automatic rollback.

This profile does not implement legacy daemon RPC, peer discovery, hot reload,
remote-offset resume, live-stream continuation after process failure, mailbox
semantics, or exactly-once publication after a lost acknowledgment. It is
Unix-only and uses the existing `atp-live/1` TCP/mTLS wire profile, not the QUIC
bulk-transfer protocol.

## Executable test coverage (not execution evidence)

`tests/atpd_live_cli.rs` launches independent sender and receiver binaries and
checks real bytes, hashes, and inode identity. It includes current-thread and
sharded runtime configurations, repeated delivery, refused client/name checks,
retention refusal after restart, concurrent inbox-owner refusal, configuration
failure, SIGTERM drain, and a silent peer that actually receives TLS bytes.
Unit tests in `src/bin/atpd_live/tests.rs` cover bounded configuration and
retention arithmetic. All fixtures/logs are retained. These tests must be run
through the authorized Rust/RCH lane before claiming runtime validation.
