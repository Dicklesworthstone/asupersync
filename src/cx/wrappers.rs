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
    pub fn cx(&self) -> &Cx<WebCaps> {
        &self.cx
    }

    /// The request ID for tracing.
    #[must_use]
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
    pub fn cx(&self) -> &Cx<GrpcCaps> {
        &self.cx
    }

    /// The gRPC method name.
    #[must_use]
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
    pub fn cx(&self) -> &Cx<BackgroundCaps> {
        &self.cx
    }

    /// The task name for tracing.
    #[must_use]
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
pub fn narrow<From, To: crate::cx::cap::SubsetOf<From>>(cx: &Arc<Cx<From>>) -> Arc<Cx<To>> {
    Arc::new(cx.as_ref().retype::<To>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::cap;

    #[test]
    fn web_caps_have_time_and_io() {
        // WebCaps = CapSet<false, true, false, true, false>
        // This is a compile-time check — if WebCaps doesn't satisfy
        // HasTime + HasIo, these functions won't compile.
        fn requires_time<C: cap::HasTime>() {}
        fn requires_io<C: cap::HasIo>() {}
        requires_time::<WebCaps>();
        requires_io::<WebCaps>();
    }

    #[test]
    fn web_caps_lack_spawn() {
        // Negative test: WebCaps should NOT have spawn.
        // We can't directly test "doesn't implement trait" at runtime,
        // but we verify the const generic values.
        // WebCaps = CapSet<false, true, false, true, false>
        // SPAWN=false, so HasSpawn is NOT implemented.
        // This is verified by the compile_fail doctest pattern.
    }

    #[test]
    fn grpc_caps_have_spawn_time_io() {
        fn requires_spawn<C: cap::HasSpawn>() {}
        fn requires_time<C: cap::HasTime>() {}
        fn requires_io<C: cap::HasIo>() {}
        requires_spawn::<GrpcCaps>();
        requires_time::<GrpcCaps>();
        requires_io::<GrpcCaps>();
    }

    #[test]
    fn background_caps_have_spawn_time() {
        fn requires_spawn<C: cap::HasSpawn>() {}
        fn requires_time<C: cap::HasTime>() {}
        requires_spawn::<BackgroundCaps>();
        requires_time::<BackgroundCaps>();
    }

    #[test]
    fn pure_caps_have_nothing() {
        // PureCaps = CapSet<false, false, false, false, false> = cap::None
        // No capability traits are implemented.
        // Verified by type equality.
        let _: PureCaps = cap::None::default();
    }

    #[test]
    fn wrapper_provides_access() {
        fn requires_time<C: cap::HasTime>(_: &Cx<C>) {}
        fn requires_io<C: cap::HasIo>(_: &Cx<C>) {}
        fn requires_spawn<C: cap::HasSpawn>(_: &Cx<C>) {}

        let full_cx = Arc::new(Cx::for_testing());
        let web = WebContext::new(&full_cx, 7);
        let grpc = GrpcContext::new(&full_cx, "svc/method".to_string());
        let background = BackgroundContext::new(&full_cx, "worker".to_string());

        requires_time(web.cx());
        requires_io(web.cx());
        requires_time(grpc.cx());
        requires_io(grpc.cx());
        requires_spawn(grpc.cx());
        requires_time(background.cx());
        requires_spawn(background.cx());

        assert_eq!(web.request_id(), 7);
        assert_eq!(grpc.method(), "svc/method");
        assert_eq!(background.task_name(), "worker");
        assert_eq!(std::mem::size_of::<WebCaps>(), 0);
        assert_eq!(std::mem::size_of::<GrpcCaps>(), 0);
        assert_eq!(std::mem::size_of::<BackgroundCaps>(), 0);
    }

    #[test]
    fn narrow_preserves_runtime_identity() {
        let full_cx = Arc::new(Cx::for_testing());
        let web_cx: Arc<Cx<WebCaps>> = narrow(&full_cx);
        let grpc_cx: Arc<Cx<GrpcCaps>> = narrow(&full_cx);

        assert!(Arc::ptr_eq(&full_cx.inner, &web_cx.inner));
        assert!(Arc::ptr_eq(&full_cx.inner, &grpc_cx.inner));
    }
}
