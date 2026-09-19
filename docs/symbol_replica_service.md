# Authenticated symbol replica service

`distributed::symbol_service` connects the existing `SymbolDistributor` to the
native authenticated named-computation service. With `tls` on a non-browser
target, `RemoteSymbolTransport` implements `DistributorTransport` and also
fetches exact batches back as verified `AuthenticatedSymbol` values.

## Receiver

Construct a `SymbolReplicaStore` with a replica label, an explicit `AuthKey`,
`SymbolBatchLimits`, and `SymbolStoreLimits`. Register it with
`register_symbol_service(&mut registry, Arc::clone(&store))`. Build the existing
`RemotePeerAdmissionPolicy` from that registry's **complete** schema registry,
select `RemoteProtocolVersion::V1`, and grant each allowed origin's certificate
pins the `SYMBOL_SERVICE_COMPUTATION` capability using `grant_tls_peer`.

Serve the registry with `RemoteComputationService`. Its TLS acceptor must require
client certificates; its connection, frame, initial-read and drain limits remain
in force. Registration does not create grants, bind a socket, spawn a listener,
or grant access to arbitrary claimed origin names. Use distinct certificate
bindings when distinct logical origins must not impersonate each other.

The handler derives the storage namespace from the admitted peer identity. Both
put and fetch requests also name their intended replica, which is checked before
storage. Every symbol tag is reverified with the receiver key. A failed last tag,
capacity refusal, wrong target, duplicate identity, mixed object, or malformed
encoding cannot publish a partial batch. A successful put returns an exact
replica/object/batch-digest/symbol-count receipt after in-memory publication.

## Sender and readback

Construct one `RemoteComputationClient` per logical replica using its trusted TLS
server name, roots/enforcing pins as appropriate, client identity, and finite
connection/attempt/retry limits. Pass those clients, a V1 hello for the complete
service registry, the owning `Cx`, the verification key, and batch limits to
`RemoteSymbolTransport::new`. Use the same owning context with
`SymbolDistributor::distribute`. The distributor's bounded fanout and per-attempt
acknowledgement deadlines apply unchanged. Unknown routes never acquire a
resolver or contact an ambient destination.

Before discarding the source symbols, retain the exact key:

```rust,ignore
let signed: Vec<_> = encoded.symbols.iter()
    .map(|symbol| security.sign_symbol(symbol)).collect();
let key = encode_symbol_batch(&signed, batch_limits)?.key();
let result = distributor.distribute(
    &cx, &encoded, &replicas, &transport, &security,
).await;
assert!(result.quorum_achieved);
let symbols = transport.fetch_symbols("replica-a", key).await?;
```

Fetches name an exact object **and digest**, are restricted to the same admitted
origin's namespace, and reverify every symbol tag at the client before exposing
any vector. The returned symbols can feed the existing recovery pipeline. Retain
the matching object/encoding parameters and snapshot provenance separately;
this service does not infer missing RaptorQ parameters or apply region state.

## Resource and failure boundaries

Batch limits independently cap canonical binary bytes, symbol count, aggregate
payload bytes, and logical decoded storage. The service's JSON frame limit is
separate: a binary payload serialized as an array of byte values can need roughly
four times its binary size plus envelope metadata. Configure both ends' frame
limits deliberately. A response-frame failure after storage is still a failed,
delivery-ambiguous call; it is not evidence that nothing was stored.

The store independently caps retained batches and encoded bytes globally and per
origin. Counts also bound map and bounded identity overhead. Decoding, network
frames, serialization copies and simultaneous calls are additional transient
memory controlled by per-batch and service connection/frame limits. Read handles
share stored bytes; they do not create duplicate retained payload allocations.

An origin/object key is immutable. Identical canonical retries share storage even
at capacity; different bytes under the same key conflict. New snapshots or
changed full batches must use new object IDs. There is no implicit eviction,
overwrite, expiry, disk persistence, or destructive maintenance API. Store-owned
encoded buffers are zeroized on final drop; caller copies and existing remote
wire envelopes are separate owners and must be treated as sensitive data.

A receipt means **in-memory retention**, not durable storage, successful recovery,
or remote quiescence. A receiver restart loses the store. The native client uses
one-shot V1 requests and preserves the existing remote client's refusal to retry
ambiguous delivery. V2/V3 cached outcomes are not silently used as durable store
receipts. Timeout, cancellation or dropping local I/O cannot undo remote bytes
already published. This does not implement continuation migration, scheduler
replay, automatic recovery orchestration, hedging, or an end-to-end durability
protocol.

## Validation targets

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --lib distributed::symbol_service::
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --features tls,test-internals --test symbol_service_native
```

The native tests use the production mTLS listener, computation client, distributor,
store and fetch decoder. They cover current-thread and multithread sender runtimes,
wrong targets, wrong symbol keys, absent client certificates and ungranted peers.
These tests were authored with this implementation but have not been executed in
the authoring environment, where RCH and the Rust toolchain were unavailable.
