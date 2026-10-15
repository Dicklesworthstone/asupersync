# Retained-session live transfer resumption

The SDK can reconnect an interrupted live transfer while retaining the source,
sink, verified prefix and pending application commit. This is **connection
recovery while both session objects remain alive**, not process-crash recovery.
It is an opt-in `atp-live-resume/1` profile. The existing `atp-live/1`, QUIC
bulk-transfer, and `atpd-live` command paths are unchanged.

## Public entry points

Types live under
`asupersync::net::atp::sdk::native_auth::live::commit::resume`:
`ResumableSender<R>`, `ResumableReceiver<W>`, `ResumeReport`, and `ResumeError`.
The constructors are methods on the existing authenticated live authorities.
The following sketch assumes those authorities, the expected client certificate,
source and committing sink have already been provisioned:

```rust
let mut receiving = receiver.bind_resumable_committing(
    &cx, bind_address, expected_client_certificate, sink, 4,
).await?;
let address = receiving.local_addr()?;
let mut sending = sender.resumable_reader(&cx, address, source, 4)?;

// Drive these on their respective peers. For a same-runtime example:
let (sent, received) = futures_lite::future::zip(
    sending.send(&cx), receiving.receive(&cx),
).await;
```

Each `send` or `receive` call performs at most one connection attempt. To recover
a network interruption, retain these same objects and explicitly call the method
again with valid context authority. Do not construct another producer or another
sink, rewind the producer, clear a cancelled context, or restart a transaction.
A session can be moved into a scope-owned task and returned with its report;
join that task before handing its session to another owner. There is no detached
worker or automatic reconnect loop.

The receiver requires `LiveStreamCommitSink`; the existing Unix `LiveFileSink`
is one implementation. Sink construction and destination selection are local.
The remote peer supplies no filesystem path. A nonce does not grant permission
to write to the sink.

## Shared-port receiver service

The `resume::service` module adds `ResumableService<W>` and
`ResumeServiceConfig`. Call `receiver.bind_resumable_service::<W>(...)` to bind
one real listener for multiple sessions. Its constructor reserves the complete
resident-session budget from the existing receiver's SDK admission domain;
configure that domain large enough before binding. For example:

```rust
use asupersync::net::atp::sdk::native_auth::live::commit::resume::service::ResumeServiceConfig;

let limits = ResumeServiceConfig {
    max_connections: 4,
    max_sessions: 16,
    max_sessions_per_client: 4,
    max_session_keys: 1024,
    max_attempts_per_session: 8,
};
```

Drive `service.next(&cx, &scope, make_sink)` repeatedly. The cloneable factory
has signature `Fn(Cx, ResumeSessionKey) -> Future<Output = io::Result<W>>` and
runs in a scoped child only after mutual TLS, ALPN, hello validation and registry
admission. It receives the **verified client certificate fingerprint** and nonce.
Use the supplied child context, choose destinations locally, and impose any
additional application authorization/storage policy there. No peer address is
an authorization selector. Keep the factory's policy stable across calls.

Reconnects route to the original sink by `(certificate, nonce)` and do not invoke
the factory again. A concurrent same-key connection is refused while its worker
or uncollected join owns the sink. Different authenticated certificates cannot
access each other's session, even with identical nonces. The protocol engine,
buffered wire input, partial-write cursor, running hash and commit receipt are
the same ones used by the standalone receiver; there is no alternate codec.

`ResumeServiceCompletion` separates transfer reports, connection/admission
refusals and canonical runtime join failures. Failed authentication creates no
session and calls no factory. A failed factory/spawn/join leaves a refusal
tombstone, rather than allowing another connection to repeat uncertain effects.
`session_snapshot` describes the last collected result, not concurrent worker
progress. The per-session attempt budget counts authenticated routed attempts;
failed TLS/initial hello cannot charge a session that has not been identified.

Resident sinks include completed sessions retained for lost-Proof recovery.
Explicitly `retire(&key)` only after collecting its active result and reconciling
application effects. Retirement drops that sink and releases its resident and
per-client slots, but retains its key and last snapshot. A later reconnect to
the retired key is refused, never treated as a new upload. Retirement removes
neither files nor application storage charges. It also ends that key's ability
to recover a lost Proof, so do not retire solely because local commit succeeded.

**The lifetime distinct-key budget is finite.** Tombstones count against
`max_session_keys` and are not automatically evicted. When full, new keys are
refused while admitted sessions can still reconnect. This is not an indefinitely
running unbounded registry. Restart discards these memory-only records; it does
not establish deduplication across crashes. Reclaiming keys safely across such
restarts requires an application-owned durable registry, not a timeout guess.

`stop_accepting()` closes the listening socket; already routed workers may
finish. `cancel(reason)` additionally requests attributed worker cancellation.
Then call `drain_next()` until it returns `None`, including when the managing Cx
is cancelled or `next` returns an admission error. A dropped pending `next` or
drain wait loses no retained jobs/results. Do not use an early `?` that skips this
drain. Once drained, idle sinks and registry records are dropped and the service
reservation is released. Dropping the service only requests cancellation; its
owning regions must still drain. A started application commit retains the
existing non-abandonment contract and can outlive the operation deadline.

Connection limits cover active handshakes/transfers and uncollected results;
resident limits cover retained sinks; per-client limits constrain their owner;
lifetime-key limits bound tombstone metadata. They are not rate limits, physical
memory accounting, storage quotas, or protection against an authorized client
that consumes the entire permitted lifetime budget. Kernel backlog, TLS buffers,
user sinks and external filesystem work retain their own resource contracts.

## What survives a connection loss

The sender reads no additional epoch until the previous epoch is acknowledged.
Its retained window contains either no pending data or one unacknowledged epoch.
On reconnect it accepts exactly one of two remote positions:

1. Its already acknowledged prefix, with the matching running SHA-256. It
   retransmits only its one pending epoch, if present.
2. The exact next prefix represented by that pending epoch, with the matching
   running SHA-256. The receiver already flushed it but its ACK was lost, so
   the sender consumes that acknowledgment locally without retransmission.

Other offsets, hashes, chain commitments, changed negotiated limits, changed
nonces, and premature completion claims are refused before another source read.
The prefix is not inferred from a bare byte counter.

The receiver stores a partially written epoch and its successful write count in
the session. Reconnection must retransmit that **same complete epoch** before
its unfinished suffix is written. A changed epoch is rejected without another
sink write. A fully flushed prefix is never written again. The running hash and
prefix advance only after the whole epoch is written and flushed.

A dropped Pending attempt future discards the connection but not these fields.
Sources and sinks must retain their underlying Pending-operation state across
such dropped waits; the same operation is polled again. Do not access an
underlying handle concurrently. A source that appends bytes while reporting
Pending is rejected. Source/sink errors and panics mark the session locally
failed; subsequent standalone attempts fail without opening another connection
or replaying unknown side effects. The shared service rejects that key after
authentication instead of creating another sink.

## Application publication and lost final Proof

The receiver validates the complete length, integrity chain, and whole-stream
SHA-256 before final flushing and application commit. Epoch acknowledgments
still describe a flushed prefix, not a committed whole object.

A started commit is drained after cooperative timeout or cancellation, even
beyond the operation timeout. Its actual success/failure is preserved using the
existing commit error types. A dropped attempt retains pending commit state;
it does not start another commit transaction on reconnect. Once the commit
returns success, the session records completion **before** awaiting Proof I/O.

When final Proof is lost, a later authenticated attempt can exchange that exact
final commitment and Proof again without writing or committing the sink again.
The sender must already have observed source EOF and must still validate the
final Proof; a receiver's completion flag alone cannot establish delivery.

`ResumeReport.completed` and `completed_receipt()` retain the local observation
independently of a failed attempt. `receipt_reused` distinguishes historical
completion from a newly completed transaction. After validated Proof, later
sender calls return its marked cached receipt without new network activity.
Receiver calls still authenticate a new connection before retransmitting Proof.

## Authentication and bounds

Every connection uses fresh mandatory mutual TLS inherited from the original
live authority, with TLS resumption and early data still disabled. The standalone
receiver additionally requires its explicitly selected full client-certificate
SHA-256; the shared service binds each admitted sink to the actual authenticated
certificate and nonce. The sender pins the first WebPKI-verified server leaf
certificate. Certificate renewal, address migration, or replacement of either
process is not transparent session continuation.

For standalone endpoints, an explicit bound of 1 through 1024 attempts covers
failed connect, accept, handshake and protocol attempts, including idle accept
timeouts. There is no hidden retry inside an attempt. Each standalone session
retains one SDK admission credit until dropped, including idle and completed
states. Holding a receiver alive to recover lost Proof therefore deliberately
retains its slot and listening socket. A dropped attempt alone does not release
admission. The shared service instead owns one listener and its whole configured
resident-session reservation until drain or final owner destruction.

Epoch data remains bounded by the negotiated native limit, at most 64 KiB.
This is a logical one-epoch window, not a 64 KiB total-memory claim: the source
buffer, encoded frame copies, codec, TLS, socket and application sink have their
own storage. No unbounded epoch history or whole-source spool is introduced.

## Wire profile

Outbound messages use the existing canonical ATP frame codec and no extensions.
Integers below are big-endian. The distinct ALPN prevents legacy-profile fallback.

- `Handshake`: exactly 60 bytes: `ATPRSM01 || ATPLIVE1 || nonce[32] ||
  epoch_limit:u32 || byte_limit:u64`.
- `HandshakeAck`: exactly 141 bytes: the agreed 60-byte hello, followed by
  `epochs:u64 || bytes:u64 || chain[32] || prefix_sha256[32] || completed:u8`.
  The last byte must be zero or one. The receiver can only narrow initial limits;
  thereafter both the offer and the negotiated limits remain fixed.
- The initial chain is SHA-256 of
  `asupersync.atp.live.resume.hello.v1 || agreed_hello`.
- `ObjectData`, `Control`, `ObjectComplete`, and `Proof` reuse the existing
  live epoch, acknowledgment, final-commitment and final-proof encodings. Epoch
  chaining keeps the existing `asupersync.atp.live.epoch.v1` separator, anchored
  to the resume-specific initial chain.

## Validation and remaining boundary

`tests/atp_live_resume.rs` contains eleven native journeys with independent
mTLS wire peers, partial writes, lost ACK/Proof, identity and continuity refusal,
local failure, finite attempts, and cancelled/pending commit recovery.
`tests/atp_live_resume_file.rs` interrupts the actual file sink after 4096 flushed
bytes plus thirteen partial bytes, then checks actual final bytes, hash, inode
publication, one commit, and admission release on both native runtime shapes.
`tests/atp_resume_service.rs` adds thirteen shared-port native journeys covering
multiple identities, partial-write reconnect, busy routing, quotas, tombstones,
failed factories, authentication refusal, changed offers, lost Proof, commit
drain, actual file publication, and buffered hello/epoch handoff. Three additional
unit tests cover configuration, retained credit ownership and key separation.

These tests were authored without an available Rust/Cargo/RCH runner and have
**not been compiled or executed** in that environment. Execute the repository's
authorized validation lanes before treating this as runtime or durability proof.
Shared-port routing is implemented, but the `atpd-live` CLI is not yet a resume
route. The profile does not serialize session state, resume after process exit,
recover arbitrary application side effects, or guarantee exactly-once effects
across crashes. The file sink's trusted-directory and retained-plaintext-alias
requirements remain unchanged.
