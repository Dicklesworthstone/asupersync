# Stack Surface Guidance

## Table of Contents

- [Practical Inventory](#practical-inventory)
- [Web / Service / gRPC Detail](#web--service--grpc-detail)
- [Database Detail](#database-detail)
- [Actor / Spork Detail](#actor--spork-detail)
- [Recommendation Order](#recommendation-order)

## Practical Inventory

Support labels in this table are part of the claim. “Public” says an API is
exported; it does not by itself prove protocol interoperability, operational
maturity, or parity with a Tokio ecosystem crate.

| Surface | Where / feature | Support class | Default guidance | Truthful boundary |
|---------|-----------------|---------------|------------------|-------------------|
| Core runtime / `Cx` / `Scope` | `src/runtime/`, `src/cx/` | Public, default | Lead with this | Default integration target |
| Cancellation / obligations | `src/cancel/`, `src/obligation/` | Public, default | Lead with this | Teach the operation-specific request/drain/finalize contract |
| Lab runtime / deterministic testing | `src/lab/`, `TESTING.md` | Public, default | Lead with this | Exact `ForcedSchedule` artifacts are bounded Lab evidence, not production scheduler control |
| Channels / sync / time | `src/channel/`, `src/sync/`, `src/time/` | Public, default | Lead with this | Contracts differ by primitive; not every wait takes `Cx` |
| I/O / net / bytes / codec | `src/io/`, `src/net/`, `src/bytes/`, `src/codec/` | Public, default plus platform gates | Strong candidate; verify edge cases | Broad native surface, not every niche operation or platform behavior |
| HTTP/1.1 | `src/http/h1/`, `src/http/client.rs` | Public, default | Strong candidate | High-level `http::Client` is the pooled H1 client |
| HTTP/2 | `src/http/h2/` | Public, default protocol/server machinery | Requirement-driven validation | Frame/HPACK/flow-control/multiplexing machinery; no demonstrated shared H1/H2 high-level client pool |
| Web framework | `src/web/` | Public, default | Strong candidate | Native bounded primitives, not axum/warp/tower-http parity |
| Service / middleware | `src/service/`; optional `tower` | Public, default; adapter feature | Strong candidate | Native service model; Tower adapter is a trait boundary, not a Tokio runtime |
| gRPC | `src/grpc/` | Public, default | Strong candidate when needed | Native unary/streaming/client/server surfaces; use auth-gated reflection in production |
| TLS | `src/tls/`; `tls`, root-store features | Public, feature-gated | Requirement-driven | Interrupted handshakes are not cancel-safe; drop the connection |
| Databases | `src/database/`; `sqlite`, `postgres`, `mysql` | Public, separately feature-gated | Requirement-driven native candidate | Native clients; SQLite has additive checked and `*_diagnosed` paths, while legacy methods remain; no SQLx `query!` parity or generic SQLx compat-hosting claim |
| Actors / GenServer / supervision / Spork | `src/actor.rs`, `src/gen_server.rs`, `src/supervision.rs` | Public, default | Use when topology/state demands it | `CompiledSupervisor` plans restarts; tree-level live automatic restart is not generally wired |
| Observability | `src/observability/`; `runtime-metrics`, `metrics`, `tracing-integration`, `debug-server` | Public with distinct opt-ins | Turn on deliberately | Runtime counters, OTel metrics, trace export, and test harnesses are separate claims |
| QUIC / HTTP3 | `net::{quic_core,quic_native}`, `http::h3_native`; rollout aliases `quic`, `http3` | Low-level native modules public by default on native; curated aliases feature-gated | Only if required | Fail-closed pieces; exported source is not generic interop or operational-readiness proof |
| Filesystem | `src/fs/`; optional `io-uring` helpers | Public, default/feature mix | Requirement-driven; extra caution | Blocking-backed facade, not full `tokio::fs` parity |
| External messaging clients | `messaging::{redis,nats,jetstream,kafka,...}` | Public, mixed maturity; Kafka real-broker operations need `kafka` | Only when required | Redis/NATS/JetStream are default native; Kafka without its feature returns `FeatureDisabled`; validate failover and consumer behavior |
| Native FABRIC | `messaging-fabric` modules under `src/messaging/` | Experimental, feature-gated | Specialist evaluation only | Brokerless fabric/compiler/control surfaces are not the maturity claim of the external clients |
| ATP object transfer | `src/net/atp/`; `atp-cli` for CLI | Public specialized surface | Object-transfer requirements only | Performance claims require current, comparable matrix evidence |
| Remote / distributed | `src/remote.rs`, `src/distributed/` | Public primitives, bounded proof | Requirement-driven | Not a turnkey authenticated WAN runtime |
| Browser Rust runtime | wasm/browser profile features, `asupersync-browser-core` | Preview/profile-gated | Requirement-driven | Main/dedicated browser contexts differ from service/shared worker broker lanes |
| Browser JS/TS packages | `packages/` and browser readiness artifacts | Scoped repository GA, not npm-published | Requirement-driven | Main thread and dedicated worker only for direct runtime |
| RaptorQ / advanced math | `src/raptorq/`; optional SIMD | Public specialized surface | Only if required | Auth, transport, and proof boundaries must be named; not generic distributed correctness |
| Tokio compatibility | `asupersync-tokio-compat` | Separate opt-in adapter crate | Quarantine only | Specific I/O/hyper/Tower/context adapters; no Tokio runtime or generic reqwest/axum/tonic/SQLx hosting |
| Legacy/proof harness flags | `test-internals`, legacy/serialization/real-service flags | Internal/test only | Never production architecture | Proof-lane inclusion does not make an API supported for consumers |

## Web / Service / gRPC Detail

### `web`

High-level router surface:

- `Router`
- `get`, `post`, `put`, `patch`, `delete`
- `Path`, `Query`, `Json`, `State`, `Cookie`, `CookieJar`
- `Json`, `Html`, `Redirect`, `Response`, `StatusCode`
- `Router::routes()` and `RouteInfo` for route inventory surfaces
- `middleware::{TimeoutLayer, CompressionLayer, RequestTraceLayer,
  CatchPanicLayer}`
- `Sse` (finite bounded batches) and `StreamingSse` (pull API with
  request-region and HTTP/1 drain proofs)
- error-handler panics surface as `ASUP-E502` redacted 500 responses

### `http`

Client/server surfaces:

- `http::Client`
- `http::HttpClient`
- fluent `get` / `post` / `put` / `patch` / `delete` request builders
- pooled HTTP/1 client and HTTP/1 body/streaming machinery
- native HTTP/2 frame, HPACK, flow-control, listener, and multiplexing
  machinery, separate from the H1 high-level client pool
- v0.4.4: streaming request bodies run under the request-region `Cx`;
  additive `Http1StreamingConfig` bounds body queues and unread-body drain
  (`Http1Config` v0.4.3 struct literals keep compiling)
- v0.4.5-v0.4.6: additive borrowed request-head inspection plus exact RFC OWS,
  ASCII-port, and bounded CONNECT parsing; retain the source buffer while using
  borrowed views

### `service`

Middleware / service surfaces:

- `Service`, `Layer`, `ServiceBuilder`
- `ServiceBuilder` conveniences for timeout, load shed, concurrency limit, rate
  limit, and retry
- explicit composable layers/services for buffer, hedge, load balancing,
  circuit breaking, and reconnect
- optional Tower adapter

### `grpc`

Exports include:

- `GrpcClient`
- `Server`, `ServerBuilder`
- `Channel`, `ChannelBuilder`
- request/response/streaming types
- interceptors
- health checking
- auth-gated reflection for production; anonymous reflection only for explicit
  test/dev harnesses
- gRPC-web

The native `grpc` module is excluded on `wasm32`; gRPC-web support does not
turn the native server/client stack into a browser runtime.

## Database Detail

### Native database surfaces

- SQLite (`sqlite`): blocking-pool bridge
- Postgres (`postgres`): async TCP wire protocol
- MySQL (`mysql`): async TCP wire protocol

Cancellation is backend-specific during the drain phase: PostgreSQL sends a
wire `CancelRequest`, MySQL uses `KILL QUERY`, and SQLite distinguishes queued
waiters from running connection owners. Queued cancellation must not issue the
connection-global `sqlite3_interrupt` against unrelated running work; the
native interrupt belongs to the operation that owns the connection, or to an
explicit `SqliteConnection::interrupt` caller. A feature being enabled is not
evidence that every auth, TLS, or cancellation path is equivalent across
backends.

SQLite v0.4.9 adds opt-in structured `SqliteOperationError` diagnostics through
separately named `*_diagnosed` methods. Established methods keep
returning `SqliteError`, structured cancellation remains an outer `Outcome`,
and raw legacy/engine prose is available only through explicit accessors.

Pool surfaces:

- `DbPool`
- `AsyncDbPool`
- transaction helpers in `src/database/transaction.rs`

Important caveat:

- SQLx compile-time query checking remains a notable gap in native replacement docs.

## Actor / Spork Detail

Use these when the target system is naturally stateful or supervision-driven:

- `src/actor.rs`
- `src/gen_server.rs`
- `src/supervision.rs`
- `examples/spork_minimal_supervised_app.rs`

## Recommendation Order

Default recommendation order:

1. Core runtime, cancellation, lab runtime
2. channels/sync/time
3. io/net/http/service/web
4. gRPC and database
5. actors/spork
6. a proven compat boundary only for an unavoidable exact trait adapter
7. Browser, QUIC/H3, ATP, external messaging, experimental FABRIC,
   remote/distributed, and RaptorQ only when explicitly needed
