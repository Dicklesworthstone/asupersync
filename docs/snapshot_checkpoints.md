# Publisher checkpoints and authenticated recovery manifests

The `distributed::symbol_service::checkpoint` module closes the gap between
successful replication and restartable recovery instructions. Enable `tls` on a
native target. Existing storage, transport and recovery APIs remain unchanged.

## Publish, retain, restore

Start with the normal independently signed `RegionSnapshot` and `StateEncoder`.
Supply its `EncodedState`, authorized `ReplicaInfo` targets, signing
`SecurityContext`, and your existing `SymbolDistributor` to
`RemoteSymbolTransport::replicate_checkpoint`. `CheckpointAuthority` carries the
exact expected snapshot identity, snapshot authentication key and separate
manifest-author key. `CheckpointConfig` supplies metadata/decode bounds, a sealed
minimum recovery replica count and a whole-operation timeout.

The method checks target labels/routes/authorization, admitted sizes and decoder
dimensions. It reconstructs the supplied encoding with the existing RaptorQ
pipeline, verifies the snapshot's independent authentication, and checks exact
region generation/origin/epoch/sequence BEFORE network dispatch. This rejects a
wrong or unrecoverable source instead of discovering it only during recovery.
This extra synchronous verification costs CPU/memory and cannot be preempted in a
poll; explicitly bound the source and block dimensions. Peak memory includes the
bounded source, signing copies, canonical batch and decoder, not merely metadata.

The existing distributor performs the actual full-copy replication, including
its opt-in hedging, acknowledgement deadlines and metrics. Each outgoing batch
is checked against the prevalidated digest; the existing authenticated transport
still verifies the remote receipt. Only acknowledged replica labels enter the
resulting manifest. Failed/skipped/retired replicas do not become confirmed
copies. The original write denominator is retained even if authorization changes
while preparing the operation. Local-only distribution is not a checkpoint.
The minimum recovery replica count cannot exceed the configured write quorum.

A `ReplicatedCheckpoint` provides the original distribution report, immutable
`RecoveryManifest`, and authenticated `encoded_manifest()` bytes. Persist these
bytes in an explicitly owned, durably linked destination before discarding the
publisher's source state. Returning bytes does NOT persist them or atomically
commit publisher metadata with remote stores. Any failure after dispatch may
leave successful remote writes; no automatic retry or rollback is introduced.
The full operation deadline is checked after synchronous preparation and sealing,
and all owned distribution futures/timers are destroyed before output.

After restart, import with `RecoveryManifest::from_canonical_bytes`. Supply the
independently retained exact `SnapshotIdentity`, authenticated service `NodeId`,
manifest-author key, and metadata limits. The record contains all ObjectParams
and exact replica batch keys, but no addresses, TLS credentials, symbol keys or
snapshot keys. Route/certificate provisioning remains an independent authority.
Use a checked, bounded read for untrusted manifest files before calling import.

Call `RemoteSymbolTransport::recover_checkpoint` with the imported manifest,
normal network/decode limits, and snapshot key. The transport's authenticated
origin must match the sealed storage namespace. The recovery configuration must
not weaken the manifest's minimum replica count. The existing bounded fetch,
symbol authentication, RaptorQ decode and exact snapshot checks remain in force.
No method applies a snapshot, resurrects arbitrary futures or discovers the
latest authority. Independently trust the expected identity; do not take it from
an unverified file or a convenient responding replica.

## Metadata contract and limits

V1 uses the existing domain-framed `AuthenticationTag` primitive. Every field is
authenticated: service origin, generation-safe snapshot identity, object decoder
parameters, minimum responses and sorted unique replica/digest pairs. Import
validates the whole encoding and labels before allocating the decoded vector.
Count, encoded-byte and logical decoded-storage bounds are independent. Bad
framing, impossible dimensions/thresholds, duplicates, noncanonical order, mixed
objects, invalid UTF-8, truncation and trailing bytes are rejected. Encoded owners
zeroize on drop and Debug redacts labels/digests. Authentication is not encryption.

`RecoveryManifest::new` also supports existing integrations that already own
trusted metadata and confirmed receipts. It is explicitly an author assertion;
it does not contact replicas or establish their storage state. Neither the author
MAC nor an ordinary V1 storage receipt proves peer durability to a third party.
Use the durable backend through operator provisioning when restart survival is
required. Old authenticated checkpoints remain authentic: without separately
trusted current identity, signatures cannot select latest state or prevent rollback.

Validation targets (tests are authored until executed):

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --features tls --lib distributed::symbol_service::native::checkpoint::
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --features tls,test-internals --test symbol_durable_process -- --nocapture
```

The existing disk/mTLS process harness now also saves a publisher manifest,
forgets all batch/decoder/source owners, terminates the acknowledging replica,
reopens it in a new process and restores the exact snapshot using only that file
plus independent authority/credentials. A wrong-key source must cause no remote
journal append. These are process-restart regressions, not power-loss validation
or a native pass claim. All preexisting durable-process tests remain intact.
