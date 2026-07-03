# Stack Surface Guidance

## Practical Inventory

| Surface | Where | Default Guidance | What To Say |
|---------|-------|------------------|-------------|
| Core runtime / `Cx` / `Scope` | `src/runtime/`, `src/cx/`, `src/lib.rs` | Lead with this | Default integration target |
| Cancellation / obligations | `src/cancel/`, `src/obligation/` | Lead with this | Core differentiator; teach explicitly |
| Lab runtime / deterministic testing | `src/lab/`, `TESTING.md` | Lead with this | Make it part of normal adoption |
| Channels / sync / time | `src/channel/`, `src/sync/`, `src/time/` | Lead with this | Strong replacement story |
| I/O / net / bytes / codec | `src/io/`, `src/net/`, `src/bytes/`, `src/codec/` | Good default; verify edge cases | Strong default for native services |
| HTTP/1.1 + HTTP/2 | `src/http/` | Good default | Native replacement exists and is broad |
| Web framework | `src/web/` | Good default | axum-like API, but avoid promising ecosystem identity |
| Service / middleware | `src/service/` | Good default | Native Tower-style story |
| gRPC | `src/grpc/` | Good default when needed | Rich surface for real service work |
| Databases | `src/database/` | Good default when needed | Feature-gated, native wire protocols for Pg/MySQL |
| Actors / GenServer / supervision / Spork | `src/actor.rs`, `src/gen_server.rs`, `src/supervision.rs` | Use when topology/state demands it | Good fit for stateful concurrency |
| Observability | `src/observability/` | Turn on early | Much deeper than just tracing integration |
| QUIC / HTTP3 | `src/net/quic_*`, `src/http/h3_native.rs` | Only if the requirement exists | Native fail-closed pieces exist; verify exact interoperability/protocol need |
| ATP object transfer | `src/net/atp/`, `scripts/atp_bench/` | Only for object-transfer / benchmark lanes | Claims require matrix evidence against tuned rsync |
| Messaging | `src/messaging/` | Only when required; verify exact feature needs | In-process pub/sub/request-reply surfaces are useful; durable/fabric compiler claims need source checks |
| Remote / distributed | `src/remote.rs`, `src/distributed/` | Requirement-driven | Require extra source inspection |
| Browser Edition | `asupersync-browser-core`, browser docs, wasm profiles | Requirement-driven | Supported direct runtime only in explicit browser contexts |
| RaptorQ / advanced math stack | `src/raptorq/` | Only if the requirement exists | Proof-carrying and fail-closed; lead with it only when the target problem actually needs it |

## Web / Service / gRPC Detail

### `web`

High-level router surface:

- `Router`
- `get`, `post`, `put`, `patch`, `delete`
- `Path`, `Query`, `Json`, `State`, `Cookie`, `CookieJar`
- `Json`, `Html`, `Redirect`, `Response`, `StatusCode`

### `service`

Middleware / service surfaces:

- `Service`, `Layer`, `ServiceBuilder`
- timeout
- concurrency limit
- rate limit
- retry
- buffer
- hedge
- load shed
- load balancing
- reconnect
- optional Tower adapter

### `grpc`

Exports include:

- `GrpcClient`
- `Server`, `ServerBuilder`
- `Channel`, `ChannelBuilder`
- request/response/streaming types
- interceptors
- health checking
- reflection
- gRPC-web

## Database Detail

### Native database surfaces

- SQLite: blocking-pool bridge
- Postgres: async TCP wire protocol
- MySQL: async TCP wire protocol

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
6. browser or compat bridge
7. QUIC/H3, ATP, messaging, remote/distributed, Browser Edition, RaptorQ only when explicitly needed
