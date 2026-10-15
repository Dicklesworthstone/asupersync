# Tokio And Tokio-Ecosystem Mapping

Use this as the first-pass replacement matrix.

## Table of Contents

- [Core Runtime](#core-runtime)
- [Sync / Channels / Time](#sync--channels--time)
- [I/O / Networking](#io--networking)
- [Web / gRPC / Middleware](#web--grpc--middleware)
- [Database / Messaging / System](#database--messaging--system)
- [Compat / Boundary Cases](#compat--boundary-cases)
- [Partial / Unsupported Areas To Remember](#partial--unsupported-areas-to-remember)

## Core Runtime

| Tokio surface | Native Asupersync surface | Guidance |
| --- | --- | --- |
| `#[tokio::main]` | `#[asupersync::main]`; explicit `RuntimeBuilder` + `Runtime::block_on` when the app owns the runtime | Replace bootstrap first; use the graduated on-ramp rather than inventing an executor shim. |
| `tokio::spawn(fut)` | `cx.spawn(\|cx\| async move { fut.await })`, `cx.spawn_in(&scope, \|cx\| fut)` | Prefer region-owned work; the factory receives its own `Cx`. Use `Scope::spawn_registered` only when you already hold `&mut RuntimeState`. |
| `tokio::task::spawn_local(fut)` | `cx.spawn_local(\|cx\| fut)`, `cx.spawn_local_in(...)` | The future may be `!Send`, but the call must run on a scheduler worker's local lane owned by the same runtime. A direct `block_on`, entry-macro body, or `run_test_with_cx` is not enough and returns ASUP-E004. |
| structured task join | `TaskHandle<T>` | `Cx::spawn*` returns a region-owned handle; `.join(cx).await` returns `Result<T, JoinError>`. |
| runtime-level checked join | `RuntimeHandle::{spawn_checked,try_spawn_checked}` -> `CheckedJoinHandle<T>` | Future output is `Result<T, JoinError>`. Prefer `try_spawn_checked` when admission failure, cancellation, and panic must be explicit. |
| legacy runtime join | `RuntimeHandle::spawn` -> `JoinHandle<T>` | Preserved for v0.4.3 compatibility; its future output is `T` and task panic remains panic-propagating. Do not silently describe it as a checked join. |
| `tokio::task::JoinSet<T>` | `JoinSet<T, E, P>` via `JoinSet::in_cx(cx)` or `JoinSet::new(&scope)` | Region-owned dynamic fan-out; `join_next`, `join_all`, `cancel_all` retain drain ownership. |
| `tokio::select!` | `race!(cx, { a, b })` or `cx.race_drained(...)` | Returns only after the winner is selected and every loser is protocol-cancelled and drained. |
| `tokio::join!` | `join!(a, b)`; `JoinSet::join_all(cx)` for dynamic arity | Inline branches complete together; spawned members stay region-owned. |
| `tokio::task::spawn_blocking(f)` | `cx.spawn_blocking(\|child_cx\| f())`, `cx.spawn_blocking_in(...)` | Prefer the `Cx` forms so blocking work remains region-owned; the closure receives a child `Cx`. Keep it explicit and bounded. |
| `tokio::task::yield_now()` | `yield_now()` | Identical concept. |
| `tokio::runtime::Handle` | `RuntimeHandle`, `Cx`, scoped spawn paths | Avoid ambient runtime discovery when possible. |
| externally initiated request/task context | `Runtime::request_cx_with_budget` and `RuntimeHandle::{request_cx_with_budget,try_request_cx_with_budget}` | Mint a production request `Cx` with an explicit budget; do not substitute test-only `Cx` constructors. The handle methods ship in v0.4.9. |
| bounded runtime teardown | `Runtime::{shutdown_timeout,shutdown_background}` | Drain application regions first. `shutdown_timeout(false)` means teardown is incomplete; `shutdown_background` performs no wait. |

## Sync / Channels / Time

| Tokio surface | Native Asupersync surface | Guidance |
| --- | --- | --- |
| `tokio::sync::mpsc` | `channel::mpsc` | Two-phase send: reserve asynchronously, then handle `SendPermit::send`'s `Outcome` or call `permit.try_send(val)?`. Reserve is cancel-safe; receiver closure after reservation returns `Disconnected(value)`, preserving the unsent value. |
| `tokio::sync::oneshot` | `channel::oneshot` | Two-phase: `tx.reserve(&cx)` then `permit.send(val)`. Cancel-aware rendezvous semantics preserved. |
| `tokio::sync::broadcast` | `channel::broadcast` | Two-phase send; lagging receivers get `RecvError::Lagged`. |
| `tokio::sync::watch` | `channel::watch` | `rx.changed(&cx).await?` then `rx.borrow_and_clone()`. |
| `tokio::sync::{Mutex,RwLock,Semaphore,Barrier,OnceCell}` | corresponding `sync::*` types | Use each primitive's documented `Cx`/cancellation contract. Borrowed `MutexGuard<'_, T>` is intentionally `!Send`; use `Arc<Mutex<T>>` + `OwnedMutexGuard::lock` for movable tasks, or acquire the borrowed guard inside a true local task. |
| `tokio::sync::Notify` | `sync::Notify` | `notified()` does not take `Cx`; surrounding code must provide any required cancellation selection and cleanup. Do not generalize other cancel-aware wait APIs to it. |
| `tokio::time::{sleep,interval,timeout,Instant}` | `time::*` | Explicit time source: `sleep(now, dur)`, `timeout(now, dur, fut)`, `interval(now, dur)`; same `MissedTickBehavior` options. Works with virtual time in the lab runtime. |

## I/O / Networking

| Tokio surface | Native Asupersync surface | Guidance |
| --- | --- | --- |
| `tokio::io::*` | `io::*` | Native async IO traits/extensions. |
| `tokio-util::codec` | `codec::*` | Native encoder/decoder framework. |
| `tokio::net::{Tcp, Udp, Unix}` | `net::*` | Prefer native sockets and listeners. |
| `tokio-rustls` / native TLS glue | `tls::*` | Feature-gated native TLS. A cancelled handshake leaves the connection unusable; drop it. Post-handshake I/O follows the underlying operation's cancel-safety contract. |
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
| Redis / NATS / JetStream / Kafka async crates | `messaging::{redis,nats,jetstream,kafka,...}` | Redis/NATS/JetStream clients are default native surfaces. Kafka's public API exists by default, but real broker operations require `kafka`; otherwise they fail with `KafkaError::FeatureDisabled`. Validate the exact protocol path. |
| brokerless/native messaging design | `messaging-fabric` modules under `messaging::*` | Experimental, feature-gated FABRIC lane. Do not present it as the maturity or contract of the default external-service clients. |

## Compat / Boundary Cases

`asupersync-tokio-compat` is an opt-in trait/context adapter crate, not a Tokio
runtime. Use it only when the exact blocker is one of the implemented bridges
(features: `hyper-bridge`, `tokio-io`, `tower-bridge`, `full`):

- `runtime::with_tokio_context(...)` and `with_tokio_context_sync(...)`, which
  install or preserve Asupersync `Cx`, not a Tokio `Handle`
- Tokio/asupersync IO adapters: `io::TokioIo<T>`, `io::AsupersyncIo<T>` (`tokio-io`)
- hyper executor/timer/body bridges: `hyper_bridge::{AsupersyncExecutor, AsupersyncTimer}`, `body_bridge` (`hyper-bridge`)
- tower bridges: `tower_bridge::{FromTower, IntoTower}` (`tower-bridge`)
- explicit `CancelAware` modes for wrapped futures:
  `CancellationMode::{BestEffort, Strict, TimeoutFallback}`; note that
  `with_tokio_context(...)` currently selects `BestEffort` directly rather than
  consulting `AdapterConfig`

Do not infer generic reqwest, axum, tonic, or SQLx hosting from these adapters.
Those stacks may require Tokio spawning, networking, timers, or
`Handle::current()`, none of which this crate installs generically. Require a
representative downstream compile and runtime test for the exact retained path.
See `COMPAT-BOUNDARY.md`.

Hyper note: `AsupersyncExecutor::default()` / `noop()` drops submitted futures.
Real use must supply an owned spawn callback via `with_spawn_fn(...)`.

## Partial / Unsupported Areas To Remember

- Low-level native QUIC (`net::quic_core`, native `net::quic_native`) and
  HTTP/3 (`http::h3_native`) modules are public on native targets. The curated
  `net::quic` and `http::h3` rollout aliases are gated by `quic` / `http3`.
  Either way, validate exact interoperability and fail-closed security posture.
- SQLx compile-time `query!` macros are unsupported by the native database
  clients; the compat crate is not a generic SQLx runtime.
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

When these matter, retain the existing runtime boundary or redesign
deliberately until the exact alternative is proven. Do not label an untested
compat composition as supported.
