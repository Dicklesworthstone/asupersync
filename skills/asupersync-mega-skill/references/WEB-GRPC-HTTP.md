# Web, HTTP, And gRPC Integration

This is where agents often accidentally preserve Tokio-era habits. Do not.

## Native Web Pattern

Prefer:

- `web::Router`
- native extractors
- native middleware/layering
- request-region isolation
- route metadata via `web::Router::routes()` and `web::RouteInfo` when an
  operator, docs, or audit surface needs to enumerate routes.

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
`web::Router::layer` for native composition.

## HTTP Client Pattern

For outbound HTTP, prefer the native explicit-`Cx` client path:

- `http::Client` for high-level pooled client usage,
- `http::HttpClient` / fluent request builders for `get`, `post`, `put`,
  `patch`, and `delete`,
- explicit timeout, header, query, body, and response handling at the request
  boundary.

Do not keep `reqwest` just because the old app used it. If a Tokio-only client
must remain temporarily, keep it behind a compat boundary and schedule its
removal.

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
2. If needed, temporarily bridge through compat.
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
- HTTP client: `http::Client`, `http::HttpClient`
- gRPC: `grpc::*`
- per-request isolation: `web::request_region::*`

Use compat only if the app still depends on a Tokio-only web/gRPC library you cannot cut out yet.
