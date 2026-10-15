# Web, HTTP, And gRPC Integration

This is where agents often accidentally preserve Tokio-era habits. Do not.

## Table of Contents

- [Native Web Pattern](#native-web-pattern)
- [Least-Privilege Handlers](#least-privilege-handlers)
- [Service Layers And Backpressure](#service-layers-and-backpressure)
- [HTTP Client Pattern](#http-client-pattern)
- [HTTP/1 Streaming Request Bodies (v0.4.4)](#http1-streaming-request-bodies-v044)
- [Borrowed Request-Head Inspection And Strict Framing (v0.4.5-v0.4.6)](#borrowed-request-head-inspection-and-strict-framing-v045-v046)
- [gRPC Pattern](#grpc-pattern)
- [Callable Registered gRPC Services (unreleased after v0.4.9)](#callable-registered-grpc-services-unreleased-after-v049)
- [Long-Lived Components Belong Outside Handlers](#long-lived-components-belong-outside-handlers)
- [Migration Shape For Existing Axum / Tonic Apps](#migration-shape-for-existing-axum--tonic-apps)
- [Watch For These Mistakes](#watch-for-these-mistakes)
- [Useful Native Targets](#useful-native-targets)

## Native Web Pattern

Prefer:

- `web::Router`
- native extractors
- native middleware/layering
- request-region isolation
- route metadata via `web::Router::routes()` and `web::RouteInfo` when an
  operator, docs, or audit surface needs to enumerate routes.
- bounded SSE via `web::sse::Sse` (finite bounded batch responses) and
  `StreamingSse` (pull API, proof-backed for request-region E2E and HTTP/1
  transport drain).

Scope note: the web layer is deliberately bounded native primitives (router,
typed extractors, local `Handler` middleware, request-region helpers, SSE,
health/static/multipart/session/security utilities) on top of the HTTP and
service modules. It is not axum/warp/tower-http parity; see the README
coverage-map paragraph for the exact boundary.

The important architectural pattern is request-as-region:

- each request gets its own region,
- handler-local spawned work belongs to that region,
- cancellation, panic, finalizers, and outstanding obligations all resolve with the request.

Relevant types:

- `web::request_region::RequestRegion`
- `web::request_region::RequestContext`

The point is not only isolation. It is ownership:

- request-local spawned work drains with the request,
- cleanup and finalizers stay inside the request budget,
- handler bugs do not silently leak long-lived work.

## Least-Privilege Handlers

At handler boundaries, do not hand the entire system context everywhere.

Use:

- `ctx.cx_narrow::<...>()`
- `ctx.cx_readonly()`

This lets handlers keep only the capabilities they actually need.

Practical rule:

- default handlers to narrowed or read-only context,
- only widen when the handler genuinely owns spawn/time/io/remote work.

Do not normalize "full power everywhere" just because it is easier.

## Service Layers And Backpressure

Do not reimplement middleware logic with ad hoc wrapper futures if the native
service stack already models it.

High-value layers:

- `ServiceBuilder::timeout(...)`
- `ServiceBuilder::load_shed()`
- `ServiceBuilder::concurrency_limit(...)`
- `ServiceBuilder::rate_limit(...)`
- `ServiceBuilder::retry(...)`

Use these to make overload and tail behavior explicit instead of implicit.

Concrete web middleware anchors include `web::middleware::TimeoutLayer`,
`CompressionLayer`, `RequestTraceLayer`, and `CatchPanicLayer`, plus
`web::Router::layer` for native composition. Since v0.4.3,
`web::negotiate::ErrorHandlerMiddleware` converts handler/middleware
construction and poll panics into redacted `[ASUP-E502]` 500 responses
(structured trace events when `tracing-integration` is enabled).

`CompressionLayer` is always a public type, but actual gzip/deflate/Brotli
encoding is compiled only with the `compression` feature.

## HTTP Client Pattern

For outbound HTTP, prefer the native explicit-`Cx` client path:

- `http::Client` for high-level pooled **HTTP/1** client usage
  (capability-gated handle, no ambient global; see
  `Client::default_for_runtime`),
- `http::HttpClient` / `HttpClientBuilder` and fluent request builders for
  `get`, `post`, `put`, `patch`, and `delete`,
- explicit timeout, header, query, body, and response handling at the request
  boundary.

Do not keep `reqwest` just because the old app used it. The current high-level
pool is H1 machinery: native H2 supplies frame, HPACK, flow-control, listener,
connection, and multiplexing surfaces, but is not wired into a shared H1/H2
high-level client pool.

If a Tokio-only client must remain temporarily, retain its existing Tokio
runtime boundary and schedule its removal. `asupersync-tokio-compat` does not
install a Tokio runtime or generically prove reqwest hosting; use a narrower
adapter only after representative downstream compile and runtime tests.

## HTTP/1 Streaming Request Bodies (v0.4.4)

The HTTP/1 server hardened streaming request-body cancellation and connection
reuse in v0.4.4:

- streaming bodies execute under the request-region capability context, so
  backpressure waits, cancellation, budgets, and body-channel limits observe
  the request lifetime rather than the connection lifetime;
- if a handler leaves a segmented body unread, the server drains decoded
  frames and chunk trailers within explicit frame, byte, and time bounds
  before reusing the connection; malformed, truncated, over-limit, or
  cancelled drains close it fail-closed;
- `Http1Config` keeps its v0.4.3 shape; the new body-queue and
  unread-body-drain limits live in the additive `Http1StreamingConfig`
  (`src/http/h1/server.rs`).

## Borrowed Request-Head Inspection And Strict Framing (v0.4.5-v0.4.6)

`Http1Codec::inspect_request_head` is an additive allocation-avoiding path for
routing, admission, and protocol checks. It returns public borrowed method,
header, and request-head views; those values remain valid only while the source
buffer remains alive. Materialize the established owned request type before
retaining the head or moving it beyond that buffer's lifetime.

The corresponding parser boundary is deliberately ASCII-exact:

- HTTP optional whitespace is only SP or HTAB, never Unicode whitespace,
- explicit URL/proxy ports contain ASCII digits only,
- CONNECT status is exactly three digits and serialized headers stay bounded,
- malformed inputs fail closed rather than being normalized into a different
  request interpretation.

The owned decoder remains supported; this is an additive inspection surface,
not a replacement that breaks v0.4.3 callers.

## gRPC Pattern

Prefer:

- native `grpc::*` service stack
- `CallContext::with_cx(...)`
- narrowed `Cx` inside handlers/interceptors
- `ServerBuilder::enable_reflection_with_auth(...)` for production reflection

Important point:

- gRPC handlers should follow the same capability-discipline as HTTP handlers,
- deadlines and call metadata should remain explicit,
- cancellation should be visible and testable.

Use the call wrapper as the boundary object:

- `let ctx = call.with_cx(cx);`
- narrow capabilities from there,
- preserve deadline and metadata semantics instead of hiding them in ambient state.

The native `grpc` module is not compiled for `wasm32`. `grpc::web` is a native
server-side bridge, not a claim that the full gRPC stack runs in a browser.

## Callable Registered gRPC Services (unreleased after v0.4.9)

Current `main` closes the registered-unary gap between service registration and
native H2 serving. Implement `ServiceHandler::call_unary` with the public
`ServiceHandlerFuture` return alias for a descriptor-declared unary method,
then use one of these additive paths:

- `Server::dispatch_registered_unary` for in-process decoded dispatch with an
  empty request-trailer block;
- `Server::dispatch_registered_unary_with_trailers` for in-process decoded
  dispatch when the caller has request trailers;
- `Server::bind_registered_http2` when the owner needs the listener's shutdown
  signal or connection manager before calling `Http2Listener::run`;
- `Server::serve_http2` to bind and run the registered-service listener under a
  `RuntimeHandle` in one operation.

`call_unary` receives `&Cx`, the exact method path, initial metadata on the
`Request<Bytes>`, and request trailers as a separate `Metadata` block. Keep
those boundaries separate and pass the supplied `Cx` into downstream effects.
The dispatch layer resolves the service and unary method from the descriptor,
then applies the existing metadata limits, interceptors, deadline-derived
request region, cancellation checks, response framing, and status trailers.

Compatibility is deliberate:

- the new trait hook has a default implementation, so an impl block that
  supplies only the formerly required items needs no new item and returns gRPC
  `UNIMPLEMENTED` when dispatched; an in-repo legacy-shaped implementation
  proves this bounded case, not universal downstream source compatibility;
- `Server::serve` remains the v0.4.3-compatible bind-and-drop readiness probe;
- `Server::bind_http2` remains the explicit catch-all closure seam;
- malformed paths, unknown services/methods, and streaming-only descriptors
  fail closed with gRPC status 12 rather than HTTP 404 or accidental dispatch.

This is live-HEAD behavior from commit `3c73a334c`, not part of the published
v0.4.9 crate. The real transport regression sends TCP/H2 frames through a
registered callable service and directly proves success, request-trailer
delivery, response framing, and unknown-method `UNIMPLEMENTED` through
`bind_registered_http2`. `serve_http2` is source-verified delegation to that
listener path. Helper-only dispatch tests are supporting evidence, not a
substitute for the real-H2 case; streaming-only and malformed-route branches
are source-inspected behavior rather than claims about those focused tests.

## Long-Lived Components Belong Outside Handlers

If a service needs:

- caches,
- replication loops,
- subscription pumps,
- internal named workers,
- supervision/restart policy,

then put those components under `AppSpec` / supervision and let handlers talk to
them through explicit references or registry-backed names.

Do not spawn them lazily from request handlers.

## Migration Shape For Existing Axum / Tonic Apps

Recommended phases:

1. Inventory routes, extractors, middleware, interceptors, health checks, and streaming behavior.
2. If a legacy vertical slice must remain, keep its existing runtime boundary;
   use compat only when its exact required traits match implemented adapters
   and downstream execution proves the composition.
3. Replace router/extractors/middleware/service composition with native Asupersync surfaces.
4. Replace gRPC stack and streaming behavior natively.
5. Remove compat.

## Watch For These Mistakes

- direct `tokio::spawn` inside handlers,
- middleware that swallows correlation or cancel context,
- request work that outlives the request without an owning region,
- "fire-and-forget" audit/log tasks detached from request lifetime,
- hidden background components booted from first request,
- preserving tower/axum structure mechanically when native Asupersync boundaries would be cleaner.

## Useful Native Targets

- HTTP stack: `http::*`
- Router and extractors: `web::*`
- Middleware/service composition: `service::*`
- Server connection/shutdown plumbing: `server::*`
- HTTP client: `http::Client`, `http::HttpClient`
- SSE: `web::sse::{Sse, StreamingSse}`
- gRPC: `grpc::*`
- per-request isolation: `web::request_region::*`

Do not assume compat can host a Tokio-only web/gRPC stack. The compat crate
provides specific I/O, hyper-trait, Tower-service, `Cx`, and cancellation
adapters, not Tokio spawning, networking, timers, or `Handle::current()`.
Prefer native web/gRPC surfaces; otherwise retain a clearly owned existing
runtime boundary until the exact narrower bridge is proven.
