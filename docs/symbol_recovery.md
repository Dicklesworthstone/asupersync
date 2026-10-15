# Authenticated network snapshot recovery

With `tls` on native targets, use the existing
`distributed::symbol_service::RemoteSymbolTransport` for both replication and
recovery. Its `new_bounded` constructor adds a clone-shared in-flight ceiling
covering puts AND fetches before encoding/request construction. `new` retains its
prior effectively-unbounded admission behavior. Zero bounded capacity denies all
operations. Per-client connection/attempt and per-batch byte/count limits remain
independent. Returned values and retained server storage are not in-flight work.

The recovery types are in `distributed::symbol_service::recovery`.

1. Retain trusted `ObjectParams`, the exact `SnapshotIdentity` (region slot and
   generation, origin, epoch and sequence), and each replica's `SymbolBatchKey`.
   Compute batch keys from the same signed assignments used for replication.
   Do not let an arbitrary responding peer choose authoritative metadata.
2. Build `ReplicaFetch` entries using provisioned replica labels and exact keys.
   Duplicate labels, mixed object IDs, unknown routes and impossible thresholds
   are rejected before dispatch. Different replicas may hold different subsets
   of the same object's symbols, with different exact batch digests.
3. Call `collect_symbols` with `RemoteRecoveryConfig` for bounded parallel fetch,
   or `recover_snapshot` with that config, trusted parameters/provenance,
   `SnapshotDecodeLimits` and the independent snapshot authentication key.

Collection contacts every planned replica at most once at this layer. Each
admitted request has its own deadline; a separate total deadline bounds the
collection. A stalled first peer cannot prevent other admitted peers from being
polled. The transport's existing pre-delivery retry policy is unchanged; collection
adds no retry. Shared-capacity conflicts refuse instead of adding a hidden queue.

A success requires the configured number of distinct successful responses, not a
threshold reduced after failures. Symbol identities are deduplicated canonically;
conflicting bytes/tags for the same block/ESI refuse the entire collection. Every
received symbol and payload byte is charged BEFORE deduplication, so redundant
replies cannot bypass the aggregate work budget. Active responses are additionally
bounded by transport limits. These limits are not exact allocator/RSS limits.

`RecoveredSymbols` exposes symbols, responding replicas, redacted failures and
collection duration. `decode_snapshot` re-verifies symbols with `StateDecoder`,
uses the existing RaptorQ pipeline, authenticates the reconstructed snapshot with
the independent snapshot key, then checks its exact region/origin/epoch/sequence.
The decoder's object size, block count and source-symbol block dimension are
admitted before decoder construction. A synchronous decode cannot be preempted
inside a poll; `recover_snapshot` also checks cancellation/deadline after it.

No method applies the snapshot, resurrects Rust futures, establishes latest-state
consensus, grants region authority, or certifies durable storage. A signature alone
cannot select the correct authority branch. Every fetch future/timer is owned by
the invocation and destroyed before success/refusal; timeout/drop does not roll
back remote side effects or certify remote quiescence.

Focused validation (through the repository-authorized RCH lane):

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --features tls --lib distributed::symbol_service::native::
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --features tls,test-internals --test symbol_recovery_native
```

The authored native scenarios use the actual mTLS computation service and store,
real snapshot encoding, and network fetch after dropping original encoder/snapshot
owners. They are not evidence of successful execution until those commands run.
