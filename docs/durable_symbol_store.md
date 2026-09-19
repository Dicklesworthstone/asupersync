# Restartable symbol replica storage

`distributed::symbol_service::durable::DurableSymbolReplicaStore` is an opt-in
append-only disk backend. Existing `SymbolReplicaStore` and its registration
remain in-memory and unchanged. Neither backend resurrects task futures.

Supply a regular read/write `std::fs::File`, the expected replica label, the
symbol-verification key, a separate journal-authentication key, and
`DurableSymbolLimits` to `create` or `open`. Creation requires an empty file;
opening never creates or repairs one. The caller owns pathname authorization,
permissions, encryption at rest, and durable directory linkage. When creating a
file, persist its directory entry as required by the chosen filesystem before
publishing the service. Do startup/open work off the async executor.

An exclusive file lock lasts until the store is dropped. Do not retain cloned
or inherited descriptors, unlock the descriptor elsewhere, or modify the file
using noncooperating writers. The lock is not a defense against an actor already
authorized to ignore it or replace the pathname. Unsupported locking/sync fails.

Each put checks canonical batch structure, all existing symbol tags, immutable
origin/object identity and aggregate/per-origin storage quotas. New bytes are
appended as one journal record and `sync_all` must succeed BEFORE the in-memory
index or a successful receipt is published. Identical puts do not grow the log,
even at capacity. Conflicts cannot replace retained bytes. Disk size, retained
batch count/bytes and per-batch decode bounds are independent.

The V1 journal has an authenticated replica header, individually authenticated
length prefixes and chained sequence/previous-tag/peer/batch records. All use the
existing domain-separated authentication primitive. A corrupt length cannot pose
as an interrupted append. On open, every complete record and every symbol is
reverified, limits are reapplied, and the file is synced before data is exposed.
A partial last record is preserved verbatim and yields `ReadOnlyTail`: existing
committed keys can be fetched or repeated idempotently, but new objects refuse.
Complete corrupt records reject the open. Failed appends/syncs poison the live
owner. Reopening may discover a complete record from an unacknowledged append;
failure is never proof that nothing committed. No automatic truncation, deletion,
renaming, compaction or eviction is performed.

Authentication does not encrypt disk contents and cannot detect rollback to a
complete authenticated prefix without an external trusted head. Process-restart
recovery is not a proof of power-loss durability across every filesystem/device.
The filesystem must honor sync and the caller must retain the durably linked file.

## Use the existing authenticated network service

Register with `register_durable_symbol_service(&mut registry, Arc::clone(&store))`
instead of `register_symbol_service`. It returns a `DurableSymbolServiceHandle`
whose `in_flight()` reports the registered handler's single admission credit.
Build the usual certificate-bound peer policy from that registry and use the
existing mTLS computation listener and `RemoteSymbolTransport`. No wire or schema
change is needed, so existing exact-batch fetch and snapshot recovery compose
with restartable storage. The V1 receipt does not negotiate backend durability;
operator provisioning determines which implementation the authenticated server
runs. V1 transport usage avoids stale process-local V2/V3 lifecycle receipts.

Configure a real blocking pool, for example `.blocking_threads(0, 2)`. Missing
blocking-pool/spawn authority refuses; disk I/O never falls back to an executor
thread. One job per registered handler is admitted before copies or spawn; other
requests refuse rather than building a hidden queue. The job's credit remains
held through request/store destruction, including spawn failure, cancellation
before start and unwinding. Separate registrations and synchronous administrative
calls are separate admission domains. Frame/connection/pool bounds still apply.

Once a synchronous disk transaction starts it cannot be preempted by cancellation.
The runtime-owned blocking task retains the data and credit if the network handler
is dropped; the owning region must drain it. A stuck filesystem can delay drain.
Connection loss can follow a completed commit. There is no rollback or exactly-once
network guarantee, and this API introduces no automatic retry.

## Validation targets

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --lib distributed::symbol_service::
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --features tls,test-internals --test symbol_durable_process -- --nocapture
```

The unit tests cover real files plus injected write/sync failures in the same
journal engine. The Unix native parent test replicates a signed snapshot through
the public distributor, terminates the storing process AFTER its acknowledgement,
then starts an independent process that reopens the file and serves authenticated
RaptorQ snapshot recovery. The other parent refuses a server lacking a blocking
pool. Their ignored worker is explicitly invoked by the parents, not an omitted
acceptance test. File artifacts are retained; forced watchdog cleanup fails
acceptance. Authored tests are not execution evidence until the targets run.
