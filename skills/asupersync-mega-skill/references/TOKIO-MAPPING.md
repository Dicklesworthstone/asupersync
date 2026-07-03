# Tokio And Tokio-Ecosystem Mapping

Use this as the first-pass replacement matrix.

## Core Runtime

| Tokio surface | Native Asupersync surface | Guidance |
| --- | --- | --- |
| `#[tokio::main]` | `runtime::RuntimeBuilder` + `Runtime::block_on` | Replace bootstrap first. |
| `tokio::spawn` | `Cx::spawn`, `Cx::spawn_in`, `RuntimeHandle::{spawn,spawn_with_cx}` | Prefer region-owned work. Use `Scope::spawn_registered` only when you already hold `&mut RuntimeState`. |
| `tokio::task::spawn_blocking` | Asupersync blocking pool / runtime blocking helpers | Keep blocking work explicit and bounded. |
| `tokio::runtime::Handle` | `RuntimeHandle`, `Cx`, scoped spawn paths | Avoid ambient runtime discovery when possible. |

## Sync / Channels / Time

| Tokio surface | Native Asupersync surface | Guidance |
| --- | --- | --- |
| `tokio::sync::mpsc` | `channel::mpsc` | Use reserve/commit patterns where offered. |
| `tokio::sync::oneshot` | `channel::oneshot` | Preserve cancel-aware rendezvous semantics. |
| `tokio::sync::broadcast` | `channel::broadcast` | Native fan-out path. |
| `tokio::sync::watch` | `channel::watch` | Native latest-value propagation. |
| `tokio::sync::{Mutex,RwLock,Semaphore,Notify,Barrier,OnceCell}` | `sync::*` | Prefer native cancel-aware primitives. |
| `tokio::time::{sleep,interval,timeout,Instant}` | `time::*` | Prefer native time and budget-aware cancellation. |

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
| `hyper` runtime stack | `http::*` | Prefer native HTTP stack if you control the app. |
| `axum::Router` | `web::Router` | Native routing path. |
| `axum` extractors | `web::{Json, Path, Query, ...}` | Prefer native extractors. |
| `tower` / `tower-http` layers | `service::*`, `web::*` middleware | Native layering path; optional tower feature exists too. |
| `tonic` | `grpc::*` | Prefer native gRPC if the app is being fully migrated. |
| `tonic-web` | `grpc::web` | Native browser gRPC bridge. |
| `tonic-reflection` | built-in reflection service via `grpc::reflection` and `ServerBuilder::enable_reflection()` | Native server reflection exists; validate exact tooling/interoperability workflow if central. |

## Database / Messaging / System

| Tokio ecosystem surface | Native Asupersync surface | Guidance |
| --- | --- | --- |
| `tokio-postgres`, native PG clients | `database::postgres` | Feature-gated native path. |
| MySQL async clients | `database::mysql` | Feature-gated native path. |
| SQLite async wrappers | `database::sqlite` | Feature-gated native path. |
| `tokio::fs` | `fs::*` | Native fs path; validate niche ops. |
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

Compat gives you:

- `with_tokio_context(...)`
- Tokio/asupersync IO adapters
- hyper executor/timer/body bridges
- tower bridges
- explicit cancellation modes for wrapped Tokio futures

## Partial / Unsupported Areas To Remember

- QUIC / HTTP3 work is feature-gated and materially stronger than the old
  "prototype" posture, but still requirement-driven. Validate exact protocol
  needs and fail-closed security posture case by case.
- SQLx compile-time `query!` macros are unsupported.
- `rdkafka` `StreamConsumer` still needs case-specific validation.
- Redis cluster failover still needs case-specific validation.
- NATS JetStream still needs case-specific validation.
- Windows signal behavior should be validated if it matters to the deployment.
- PTY support is unsupported.
- gRPC reflection exists natively; if grpcurl/grpc_cli-style development tooling is central to the workflow, validate the exact reflection/tooling path you need instead of assuming every external workflow is identical.

When these matter, either stay on a boundary bridge or redesign deliberately. Do not hand-wave them away.
