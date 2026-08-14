# Tokio And Tokio-Ecosystem Mapping

Use this as the first-pass replacement matrix.

## Core Runtime

| Tokio surface | Native Asupersync surface | Guidance |
| --- | --- | --- |
| `#[tokio::main]` | `runtime::RuntimeBuilder` + `Runtime::block_on` | Replace bootstrap first. |
| `tokio::spawn(fut)` | `cx.spawn(\|cx\| async move { fut.await })`, `cx.spawn_in(&scope, \|cx\| fut)`, `RuntimeHandle::{spawn,spawn_with_cx}` | Prefer region-owned work; the factory receives its own `Cx`. Use `Scope::spawn_registered` only when you already hold `&mut RuntimeState`. |
| `tokio::task::JoinHandle<T>` | `TaskHandle<T>` | `.join(cx).await` returns `Result<T, JoinError>`; cancellation and panic remain distinct. |
| `tokio::task::JoinSet<T>` | `JoinSet<T, E, P>` via `JoinSet::in_cx(cx)` or `JoinSet::new(&scope)` | Region-owned dynamic fan-out; `join_next`, `join_all`, `cancel_all` retain drain ownership. |
| `tokio::select!` | `race!(cx, { a, b })` or `cx.race_drained(...)` | Returns only after the winner is selected and every loser is protocol-cancelled and drained. |
| `tokio::join!` | `join!(a, b)`; `JoinSet::join_all(cx)` for dynamic arity | Inline branches complete together; spawned members stay region-owned. |
| `tokio::task::spawn_blocking(f)` | `spawn_blocking(f)` | Same idea; runs the closure on a blocking pool thread. Keep blocking work explicit and bounded. |
| `tokio::task::yield_now()` | `yield_now()` | Identical concept. |
| `tokio::runtime::Handle` | `RuntimeHandle`, `Cx`, scoped spawn paths | Avoid ambient runtime discovery when possible. |

## Sync / Channels / Time

| Tokio surface | Native Asupersync surface | Guidance |
| --- | --- | --- |
| `tokio::sync::mpsc` | `channel::mpsc` | Two-phase send: `tx.reserve(&cx).await?.send(val)`. Reserve is cancel-safe; commit cannot fail. |
| `tokio::sync::oneshot` | `channel::oneshot` | Two-phase: `tx.reserve(&cx)` then `permit.send(val)`. Cancel-aware rendezvous semantics preserved. |
| `tokio::sync::broadcast` | `channel::broadcast` | Two-phase send; lagging receivers get `RecvError::Lagged`. |
| `tokio::sync::watch` | `channel::watch` | `rx.changed(&cx).await?` then `rx.borrow_and_clone()`. |
| `tokio::sync::{Mutex,RwLock,Semaphore,Notify,Barrier,OnceCell}` | `sync::*` | Cancel-aware: lock/read/write/acquire/wait take `&Cx` and return `Result`. |
| `tokio::time::{sleep,interval,timeout,Instant}` | `time::*` | Explicit time source: `sleep(now, dur)`, `timeout(now, dur, fut)`, `interval(now, dur)`; same `MissedTickBehavior` options. Works with virtual time in the lab runtime. |

## I/O / Networking

| Tokio surface | Native Asupersync surface | Guidance |
| --- | --- | --- |
| `tokio::io::*` | `io::*` | Native async IO traits/extensions. |
| `tokio-util::codec` | `codec::*` | Native encoder/decoder framework. |
| `tokio::net::{Tcp, Udp, Unix}` | `net::*` | Prefer native sockets and listeners. |
| `tokio-rustls` / native TLS glue | `tls::*` | Feature-gated native TLS. |
| `tokio-tungstenite` | `net::websocket::*` | Native WebSocket stack. |

## Web / gRPC / Middleware

| Tokio ecosystem surface | Native Asupersync surface | Guidance |
| --- | --- | --- |
| `hyper` runtime stack | `http::*`, `http::Client`, `http::HttpClient` | Prefer native HTTP stack and explicit-`Cx` client builders if you control the app. |
| `axum::Router` | `web::Router` | Native routing path. |
| `axum` extractors | `web::{Json, Path, Query, ...}` | Prefer native extractors. |
| `tower` / `tower-http` layers | `service::*`, `web::*` middleware | Native layering path; optional tower feature exists too. |
| `tonic` | `grpc::*` | Prefer native gRPC if the app is being fully migrated. |
| `tonic-web` | `grpc::web` | Native browser gRPC bridge. |
| `tonic-reflection` | built-in reflection service via `grpc::reflection` and `ServerBuilder::enable_reflection_with_auth(...)` | Use auth-gated reflection in production. Anonymous reflection belongs only in deliberate test/dev harnesses. |

## Database / Messaging / System

| Tokio ecosystem surface | Native Asupersync surface | Guidance |
| --- | --- | --- |
| `tokio-postgres`, native PG clients | `database::postgres` | Feature-gated native path. |
| MySQL async clients | `database::mysql` | Feature-gated native path. |
| SQLite async wrappers | `database::sqlite` | Feature-gated native path. |
| `tokio::fs` | `fs::*` | Partial blocking-backed facade, not full `tokio::fs` parity; validate niche ops. |
| `tokio::process` | `process::*` | Native process path. |
| `tokio::signal` | `signal::*` | Native signal path; validate exact Windows behavior if that platform matters. |
| Redis / NATS / Kafka async crates | `messaging::*` | Use only when those integrations are truly needed, and validate exact feature needs. |

## Compat / Boundary Cases

Use `asupersync-tokio-compat` when you still need:

- `reqwest`
- `axum`
- `tonic`
- `sqlx`
- hyper runtime traits
- Tokio I/O trait bridges
- a Tokio-only future that panics without `Handle::current()`

Compat gives you (features: `hyper-bridge`, `tokio-io`, `tower-bridge`, `full`):

- `runtime::with_tokio_context(...)` (and `with_tokio_context_sync`)
- Tokio/asupersync IO adapters: `io::TokioIo<T>`, `io::AsupersyncIo<T>` (`tokio-io`)
- hyper executor/timer/body bridges: `hyper_bridge::{AsupersyncExecutor, AsupersyncTimer}`, `body_bridge` (`hyper-bridge`)
- tower bridges: `tower_bridge::{FromTower, IntoTower}` (`tower-bridge`)
- explicit cancellation modes for wrapped Tokio futures: `CancellationMode::{BestEffort, Strict, TimeoutFallback}` via `AdapterConfig`

## Partial / Unsupported Areas To Remember

- QUIC / HTTP3 work is feature-gated and materially stronger than the old
  "prototype" posture, but still requirement-driven. Validate exact protocol
  needs and fail-closed security posture case by case.
- SQLx compile-time `query!` macros are unsupported.
- `fs::*` is an early blocking-backed facade (most ops route through the
  blocking pool), not comprehensive `tokio::fs` parity.
- `rdkafka` `StreamConsumer` still needs case-specific validation.
- Redis cluster failover still needs case-specific validation.
- NATS JetStream still needs case-specific validation.
- Windows signal behavior should be validated if it matters to the deployment.
- PTY support is unsupported.
- gRPC reflection exists natively; production guidance is
  `ServerBuilder::enable_reflection_with_auth(...)`. Use
  `ReflectionService::allow_anonymous()` only for deliberate test/dev harnesses,
  and validate grpcurl/grpc_cli-style tooling if that workflow is central.

When these matter, either stay on a boundary bridge or redesign deliberately. Do not hand-wave them away.
