//! Effect-safe framework wrappers.
//!
//! Provides context types for web, gRPC, and background task frameworks
//! that supply narrowed capabilities following the principle of least privilege.
//!
//! # Design
//!
//! Each framework wrapper holds a `Cx<C>` with a capability set appropriate
//! for its use case:
//!
//! - Web request handlers: time + IO (no spawn, no random, no remote)
//! - gRPC handlers: time + IO + spawn (for streaming)
//! - Background tasks: spawn + time (no IO, no random)
//! - Pure computations: no capabilities
//!
//! Wrappers enforce that handlers cannot access effects they don't need,
//! preventing ambient authority leaks.

use crate::cx::Cx;
use crate::cx::cap::CapSet;
use std::sync::Arc;

/// Capability set for web request handlers: time + IO only.
pub type WebCaps = CapSet<false, true, false, true, false>;

/// Capability set for gRPC handlers: spawn + time + IO.
pub type GrpcCaps = CapSet<true, true, false, true, false>;

/// Capability set for background tasks: spawn + time only.
pub type BackgroundCaps = CapSet<true, true, false, false, false>;

/// Capability set for pure computations: no capabilities.
pub type PureCaps = CapSet<false, false, false, false, false>;

/// Capability set for tasks needing entropy: random only.
pub type EntropyCaps = CapSet<false, false, true, false, false>;

/// Web request context with narrowed capabilities.
///
/// Provides time and IO capabilities but prevents spawning tasks,
/// accessing entropy, or making remote calls.
///
/// # Example
///
/// ```ignore
/// async fn handle_request(ctx: &WebContext) {
///     // ctx.cx() provides time + IO but NOT spawn/random/remote
///     let deadline = ctx.cx().deadline();
///     // ctx.cx().spawn(...) — compile error!
/// }
/// ```
#[derive(Debug, Clone)]
pub struct WebContext {
    cx: Arc<Cx<WebCaps>>,
    request_id: u64,
}

impl WebContext {
    /// Create a new web context from any capability superset that can be
    /// narrowed to [`WebCaps`].
    #[must_use]
    pub fn new<Caps>(cx: &Arc<Cx<Caps>>, request_id: u64) -> Self
    where
        WebCaps: crate::cx::cap::SubsetOf<Caps>,
    {
        Self {
            cx: narrow(cx),
            request_id,
        }
    }

    /// Access the narrowed capability context.
    #[must_use]
    #[inline]
    pub fn cx(&self) -> &Cx<WebCaps> {
        &self.cx
    }

    /// The request ID for tracing.
    #[must_use]
    #[inline]
    pub fn request_id(&self) -> u64 {
        self.request_id
    }
}

/// gRPC handler context with spawn + time + IO.
#[derive(Debug, Clone)]
pub struct GrpcContext {
    cx: Arc<Cx<GrpcCaps>>,
    method: String,
}

impl GrpcContext {
    /// Create a new gRPC context.
    #[must_use]
    pub fn new<Caps>(cx: &Arc<Cx<Caps>>, method: String) -> Self
    where
        GrpcCaps: crate::cx::cap::SubsetOf<Caps>,
    {
        Self {
            cx: narrow(cx),
            method,
        }
    }

    /// Access the narrowed capability context.
    #[must_use]
    #[inline]
    pub fn cx(&self) -> &Cx<GrpcCaps> {
        &self.cx
    }

    /// The gRPC method name.
    #[must_use]
    #[inline]
    pub fn method(&self) -> &str {
        &self.method
    }
}

/// Background task context with spawn + time only.
#[derive(Debug, Clone)]
pub struct BackgroundContext {
    cx: Arc<Cx<BackgroundCaps>>,
    task_name: String,
}

impl BackgroundContext {
    /// Create a new background task context.
    #[must_use]
    pub fn new<Caps>(cx: &Arc<Cx<Caps>>, task_name: String) -> Self
    where
        BackgroundCaps: crate::cx::cap::SubsetOf<Caps>,
    {
        Self {
            cx: narrow(cx),
            task_name,
        }
    }

    /// Access the narrowed capability context.
    #[must_use]
    #[inline]
    pub fn cx(&self) -> &Cx<BackgroundCaps> {
        &self.cx
    }

    /// The task name for tracing.
    #[must_use]
    #[inline]
    pub fn task_name(&self) -> &str {
        &self.task_name
    }
}

/// Narrow a full-capability Cx to a specific capability set.
///
/// This is the primary mechanism for least-privilege: framework code
/// creates a narrowed context before passing it to user handlers.
///
/// # Safety invariant
///
/// The narrowing is safe because `CapSet` is a ZST marker — the actual
/// runtime behavior is unchanged, but the type system prevents calling
/// methods gated on capabilities not present in the narrowed set.
///
/// # Example
///
/// ```ignore
/// use asupersync::cx::wrappers::{narrow, WebCaps};
///
/// // Full-capability Cx from runtime
/// let full_cx: Arc<Cx<All>> = runtime.create_cx();
///
/// // Narrow to web handler capabilities
/// let web_cx: Arc<Cx<WebCaps>> = narrow(&full_cx);
/// ```
#[must_use]
#[inline]
pub fn narrow<From, To: crate::cx::cap::SubsetOf<From>>(cx: &Arc<Cx<From>>) -> Arc<Cx<To>> {
    Arc::new(cx.as_ref().retype::<To>())
}

#[cfg(test)]
#[path = "wrappers_inline_tests.rs"]
mod tests;
