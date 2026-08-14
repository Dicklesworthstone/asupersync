# Tokio Replacement Matrix

## Core Mapping

| Tokio / Ecosystem Surface | Native Asupersync Surface | Recommendation | Notes |
|---------------------------|---------------------------|---------|-------|
| `tokio::runtime::Runtime` | `runtime::RuntimeBuilder` | Default | Use builder presets like `current_thread`, `high_throughput`, `low_latency`; `Runtime::block_on` is the entry point |
| `tokio::spawn` | `Cx::spawn`, `Cx::spawn_in`, `RuntimeHandle::{spawn,spawn_with_cx}` | Default | Region ownership is the real replacement; `Scope::spawn_registered` is for state-threaded boot/test internals |
| `JoinHandle` / `abort()` | `runtime::TaskHandle`, `Cx` cancellation protocol | Default | v0.4.4: abort no longer erases an acknowledged `Cancelled` result; parked-task cancellation is a release-gated native contract |
| `tokio::task::spawn_blocking` | `runtime::spawn_blocking`, blocking pool | Default | Keep `Cx` and budgets explicit |
| `tokio::sync::mpsc` | `channel::mpsc` | Default | Two-phase reserve/send |
| `tokio::sync::oneshot` | `channel::oneshot` | Default | Cancel-aware |
| `tokio::sync::broadcast` | `channel::broadcast` | Default | Waiter cleanup built in |
| `tokio::sync::watch` | `channel::watch` | Default | Last-value multicast |
| `tokio::sync::{Mutex,RwLock,Semaphore,Notify,Barrier,OnceCell}` | `sync::*` | Default | Deterministic + cancel-aware |
| `tokio::time::{sleep,timeout,interval}` | `time/*`, budgets, combinators | Default | Prefer explicit budgets and deadlines |
| `tokio::io::*` | `io/*` | Default | Trait-level parity plus cancel-safety |
| `tokio-util::codec` | `codec/*` | Default | Framing/encoder/decoder surface |
| `tokio::net::*` | `net/*` | Default | TCP/UDP/Unix + DNS |
| `bytes` | `bytes/*` | Default | Built in |
| `hyper` client/server | `http/*`, `web/*`, `service/*` | Default when you control the app | Also bridgeable via compat crate |
| `axum` | `web/*` + `service/*` | Default when you control the app | Router, extractors, middleware |
| `tower`, `tower-http` | `service/*` and optional `tower` adapter | Default when you control the app | Tower adapter exists, but native layering is primary |
| `tonic` | `grpc/*` | Default when you control the app | gRPC-web and interceptors included |
| `reqwest` | native `http/*` client stack | Default when you control the app | Compat bridge is available if needed |
| `tokio-postgres`, `mysql_async`, `sqlx` | `database/*` | Default when native migration is viable | Some SQLx compile-time-checking features remain a gap |
| `deadpool`, `bb8` | `database::DbPool`, `AsyncDbPool` | Default when native migration is viable | Pool/connection separation is explicit |
| `tokio::fs` | `fs/*` | Use with normal validation | Early blocking-backed facade (`spawn_blocking_io`), not full `tokio::fs` parity |
| `tokio::process` | `process` (src/process.rs) | Use with normal validation | Structured process lifecycle |
| `tokio::signal` | `signal/*` | Use with platform-specific validation | Explicit signal handling |
| `quinn`, `h3` | `net/quic_*`, `http/h3_native.rs` | Requirement-driven | Native TLS handshake verifies X.509 fail-closed (no skip-verify default); still verify exact protocol/interop needs; do not oversell |
| `tokio-test`, custom harnesses | `lab/*`, `frankenlab`, conformance | Strong reason to adopt | One of the strongest reasons to adopt Asupersync |

## Compat-Bridge Cases

Use `asupersync-tokio-compat` if one of these is the blocker:

- reqwest
- axum
- tonic
- hyper
- SQLx / selected DB stack dependencies
- tower / tower-http

Read:

- the compat-bridge reference in this skill

## Recommendation Legend

| Label | Meaning |
|-------|---------|
| Default | Strong default recommendation |
| Default when you control the app | Recommended path, but framework migration still deserves care |
| Use with normal or platform-specific validation | Native path exists, but verify exact behavior you depend on |
| Requirement-driven | Only lead with it when the project explicitly needs that capability |
| Strong reason to adopt | Surface that is itself a high-leverage reason to choose Asupersync |
| Compat bridge | Available through `asupersync-tokio-compat` |
