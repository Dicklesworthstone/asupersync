//! High-level pooled HTTP [`Client`] facade — the capability-gated entry point
//! to the runtime's default client.
//!
//! [`Client`] is the ergonomic, public name for the pooled
//! [`HttpClient`](super::h1::HttpClient): a cheap-clone handle (every field is
//! an [`Arc`](std::sync::Arc)) over a shared connection pool, idle-connection
//! map, and cookie jar. Cloning a `Client` is a refcount bump and shares the
//! same pool, so the idiomatic pattern is *obtain once, clone freely*.
//!
//! # Why there is no ambient global client
//!
//! Many HTTP stacks expose a free function — `reqwest::get(url)`, a process
//! `static DEFAULT_CLIENT`, a thread-local — that performs network I/O without
//! the caller ever proving they were granted I/O authority. That is **ambient
//! authority**: any code path (a `Drop` impl, a panic handler, a deep library
//! call) can reach the network invisibly, which is exactly what Asupersync's
//! capability model forbids (see the no-ambient-authority invariant in
//! `AGENTS.md`).
//!
//! Asupersync therefore provides **no** free `Client::get()` and **no** global
//! `Client` singleton. The only way to obtain the default client is
//! [`Client::default_for_runtime`], which **demands a [`Cx`] whose capability
//! set carries I/O authority** (`Caps: HasIo`). The capability flows through
//! the `Cx` parameter and is checked by the compiler at the call site — a
//! context that cannot prove I/O authority cannot even name the accessor.
//!
//! This mirrors how every other effect is reached in this runtime: timers
//! through [`Cx::timer_driver`](crate::Cx::timer_driver), raw I/O through
//! [`Cx::io`](crate::Cx::io). The HTTP client is just another capability-gated
//! handle.
//!
//! # Example
//!
//! ```
//! use asupersync::Cx;
//! use asupersync::http::{Client, ClientError};
//!
//! async fn fetch(cx: &Cx) -> Result<u16, ClientError> {
//!     // Obtain the runtime's default pooled client. You must hand it a `Cx`
//!     // that carries I/O authority — there is no ambient `Client::get()`.
//!     let client = Client::default_for_runtime(cx);
//!     let resp = client.get("http://example.invalid/").send(cx).await?;
//!     Ok(resp.status)
//! }
//! # let _ = fetch; // documents the call shape; not executed (no network here)
//! ```
//!
//! # Capability proof (compile-fail)
//!
//! A context carrying *no* capabilities does not satisfy `Caps: HasIo`, so the
//! accessor is unreachable from it — there is no ambient escape hatch:
//!
//! ```compile_fail
//! use asupersync::Cx;
//! use asupersync::cx::NoCaps;
//! use asupersync::http::Client;
//!
//! // ERROR[E0277]: the trait bound `NoCaps: HasIo` is not satisfied.
//! fn requires_io(cx: &Cx<NoCaps>) {
//!     let _ = Client::default_for_runtime(cx);
//! }
//! # let _ = requires_io;
//! ```

use crate::cx::Cx;
use crate::cx::cap::HasIo;

/// Cheap-clone handle over a shared HTTP connection pool.
///
/// `Client` is the public, ergonomic alias for
/// [`HttpClient`](super::h1::HttpClient). See the [module docs](self) for the
/// no-ambient-global philosophy and the capability-gated
/// [`Client::default_for_runtime`] accessor.
pub use super::h1::HttpClient as Client;

impl super::h1::HttpClient {
    /// Obtain the runtime's default pooled HTTP client.
    ///
    /// This is the capability-gated entry point to a ready-to-use,
    /// default-configured [`Client`]. The `cx` parameter is a **capability
    /// witness**: the `Caps: HasIo` bound means callers must present a [`Cx`]
    /// that carries I/O authority, so client access flows through the
    /// capability system instead of an ambient global (see the
    /// [module docs](self) for *why* there is deliberately no free
    /// `Client::get()`).
    ///
    /// The returned value is a cheap-clone handle over a runtime-owned shared
    /// pool. The underlying client is built lazily on the first call for this
    /// runtime context, then cloned on subsequent calls.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::Cx;
    /// use asupersync::http::Client;
    ///
    /// fn build(cx: &Cx) -> Client {
    ///     Client::default_for_runtime(cx)
    /// }
    /// # let _ = build;
    /// ```
    #[must_use]
    pub fn default_for_runtime<Caps>(cx: &Cx<Caps>) -> Self
    where
        Caps: HasIo,
    {
        cx.default_http_client()
    }
}
