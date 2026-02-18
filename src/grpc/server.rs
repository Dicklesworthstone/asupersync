//! gRPC server implementation.
//!
//! Provides the server-side infrastructure for hosting gRPC services.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::bytes::Bytes;
use crate::cx::{Cx, cap};

use super::service::{NamedService, ServiceHandler};
use super::status::{GrpcError, Status};
use super::streaming::{Metadata, Request, Response};

/// gRPC server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Maximum message size for receiving.
    pub max_recv_message_size: usize,
    /// Maximum message size for sending.
    pub max_send_message_size: usize,
    /// Initial connection window size.
    pub initial_connection_window_size: u32,
    /// Initial stream window size.
    pub initial_stream_window_size: u32,
    /// Maximum concurrent streams per connection.
    pub max_concurrent_streams: u32,
    /// Keep-alive interval.
    pub keepalive_interval_ms: Option<u64>,
    /// Keep-alive timeout.
    pub keepalive_timeout_ms: Option<u64>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_recv_message_size: 4 * 1024 * 1024, // 4 MB
            max_send_message_size: 4 * 1024 * 1024, // 4 MB
            initial_connection_window_size: 1024 * 1024,
            initial_stream_window_size: 1024 * 1024,
            max_concurrent_streams: 100,
            keepalive_interval_ms: None,
            keepalive_timeout_ms: None,
        }
    }
}

/// Builder for configuring a gRPC server.
pub struct ServerBuilder {
    /// Server configuration.
    config: ServerConfig,
    /// Registered services.
    services: BTreeMap<String, Arc<dyn ServiceHandler>>,
}

impl std::fmt::Debug for ServerBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerBuilder")
            .field("config", &self.config)
            .field("services", &format!("[{} services]", self.services.len()))
            .finish()
    }
}

impl ServerBuilder {
    /// Create a new server builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: ServerConfig::default(),
            services: BTreeMap::new(),
        }
    }

    /// Set the maximum receive message size.
    #[must_use]
    pub fn max_recv_message_size(mut self, size: usize) -> Self {
        self.config.max_recv_message_size = size;
        self
    }

    /// Set the maximum send message size.
    #[must_use]
    pub fn max_send_message_size(mut self, size: usize) -> Self {
        self.config.max_send_message_size = size;
        self
    }

    /// Set the initial connection window size.
    #[must_use]
    pub fn initial_connection_window_size(mut self, size: u32) -> Self {
        self.config.initial_connection_window_size = size;
        self
    }

    /// Set the initial stream window size.
    #[must_use]
    pub fn initial_stream_window_size(mut self, size: u32) -> Self {
        self.config.initial_stream_window_size = size;
        self
    }

    /// Set the maximum concurrent streams.
    #[must_use]
    pub fn max_concurrent_streams(mut self, max: u32) -> Self {
        self.config.max_concurrent_streams = max;
        self
    }

    /// Set the keep-alive interval.
    #[must_use]
    pub fn keepalive_interval(mut self, ms: u64) -> Self {
        self.config.keepalive_interval_ms = Some(ms);
        self
    }

    /// Set the keep-alive timeout.
    #[must_use]
    pub fn keepalive_timeout(mut self, ms: u64) -> Self {
        self.config.keepalive_timeout_ms = Some(ms);
        self
    }

    /// Add a service to the server.
    #[must_use]
    pub fn add_service<S>(mut self, service: S) -> Self
    where
        S: NamedService + ServiceHandler + 'static,
    {
        self.services.insert(S::NAME.to_string(), Arc::new(service));
        self
    }

    /// Build the server.
    #[must_use]
    pub fn build(self) -> Server {
        Server {
            config: self.config,
            services: self.services,
        }
    }
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A gRPC server.
pub struct Server {
    /// Server configuration.
    config: ServerConfig,
    /// Registered services.
    services: BTreeMap<String, Arc<dyn ServiceHandler>>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("config", &self.config)
            .field("services", &format!("[{} services]", self.services.len()))
            .finish()
    }
}

impl Server {
    /// Create a new server builder.
    #[must_use]
    pub fn builder() -> ServerBuilder {
        ServerBuilder::new()
    }

    /// Get the server configuration.
    #[must_use]
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Get the registered services.
    #[must_use]
    pub fn services(&self) -> &BTreeMap<String, Arc<dyn ServiceHandler>> {
        &self.services
    }

    /// Get a service by name.
    #[must_use]
    pub fn get_service(&self, name: &str) -> Option<&Arc<dyn ServiceHandler>> {
        self.services.get(name)
    }

    /// Returns the list of service names.
    pub fn service_names(&self) -> Vec<&str> {
        self.services.keys().map(String::as_str).collect()
    }

    /// Serve on the given address.
    ///
    /// This is a placeholder - actual implementation would use async networking.
    #[allow(clippy::unused_async)]
    pub async fn serve(self, _addr: &str) -> Result<(), GrpcError> {
        // Placeholder implementation
        // In a real implementation, this would:
        // 1. Bind to the address
        // 2. Accept HTTP/2 connections
        // 3. Route requests to the appropriate service
        Ok(())
    }
}

/// A gRPC call context.
///
/// Use [`CallContext::with_cx`] to attach a capability context for
/// effect-safe handlers.
#[derive(Debug)]
pub struct CallContext {
    /// Request metadata.
    metadata: Metadata,
    /// Deadline for the call.
    deadline: Option<std::time::Instant>,
    /// Peer address.
    peer_addr: Option<String>,
}

impl CallContext {
    /// Create a new call context.
    #[must_use]
    pub fn new() -> Self {
        Self {
            metadata: Metadata::new(),
            deadline: None,
            peer_addr: None,
        }
    }

    /// Get the request metadata.
    #[must_use]
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// Get the deadline.
    #[must_use]
    pub fn deadline(&self) -> Option<std::time::Instant> {
        self.deadline
    }

    /// Get the peer address.
    #[must_use]
    pub fn peer_addr(&self) -> Option<&str> {
        self.peer_addr.as_deref()
    }

    /// Check if the deadline has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.deadline.is_some_and(|d| std::time::Instant::now() > d)
    }

    /// Attach a capability context to this call.
    ///
    /// This is a lightweight wrapper that exposes `Cx` access without
    /// granting additional authority beyond what the caller provides.
    #[must_use]
    pub fn with_cx<'a>(&'a self, cx: &'a Cx) -> CallContextWithCx<'a> {
        CallContextWithCx { call: self, cx }
    }
}

impl Default for CallContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Call context with an attached capability context.
///
/// This wrapper is intended for framework integrations that need to thread
/// `Cx` through gRPC handlers while retaining the base call metadata.
///
/// ```ignore
/// use asupersync::cx::cap::CapSet;
/// use asupersync::grpc::CallContext;
///
/// type GrpcCaps = CapSet<true, true, false, false, false>;
///
/// fn handle(ctx: &CallContext, cx: &asupersync::Cx) {
///     let ctx = ctx.with_cx(cx);
///     let limited = ctx.cx_narrow::<GrpcCaps>();
///     limited.checkpoint().ok();
/// }
/// ```
pub struct CallContextWithCx<'a> {
    call: &'a CallContext,
    cx: &'a Cx,
}

impl CallContextWithCx<'_> {
    /// Returns the underlying call context.
    #[must_use]
    pub fn call(&self) -> &CallContext {
        self.call
    }
    /// Returns the underlying call metadata.
    #[must_use]
    pub fn metadata(&self) -> &Metadata {
        self.call.metadata()
    }

    /// Returns the call deadline, if set.
    #[must_use]
    pub fn deadline(&self) -> Option<std::time::Instant> {
        self.call.deadline()
    }

    /// Returns the peer address, if available.
    #[must_use]
    pub fn peer_addr(&self) -> Option<&str> {
        self.call.peer_addr()
    }

    /// Returns true if the call deadline has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.call.is_expired()
    }

    /// Returns the full capability context.
    #[must_use]
    pub fn cx(&self) -> &Cx {
        self.cx
    }

    /// Returns a narrowed capability context (least privilege).
    #[must_use]
    pub fn cx_narrow<Caps>(&self) -> Cx<Caps>
    where
        Caps: cap::SubsetOf<cap::All>,
    {
        self.cx.restrict::<Caps>()
    }

    /// Returns a fully restricted context (no capabilities).
    #[must_use]
    pub fn cx_readonly(&self) -> Cx<cap::None> {
        self.cx.restrict::<cap::None>()
    }
}

/// Interceptor for processing requests and responses.
pub trait Interceptor: Send + Sync {
    /// Intercept a request before it is processed.
    fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status>;

    /// Intercept a response before it is sent.
    fn intercept_response(&self, response: &mut Response<Bytes>) -> Result<(), Status>;
}

/// A no-op interceptor that passes through all requests.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopInterceptor;

impl Interceptor for NoopInterceptor {
    fn intercept_request(&self, _request: &mut Request<Bytes>) -> Result<(), Status> {
        Ok(())
    }

    fn intercept_response(&self, _response: &mut Response<Bytes>) -> Result<(), Status> {
        Ok(())
    }
}

/// Authentication interceptor.
#[derive(Debug)]
pub struct AuthInterceptor<F> {
    /// The validation function.
    validator: F,
}

impl<F> AuthInterceptor<F>
where
    F: Fn(&Metadata) -> Result<(), Status> + Send + Sync,
{
    /// Create a new authentication interceptor.
    #[must_use]
    pub fn new(validator: F) -> Self {
        Self { validator }
    }
}

impl<F> Interceptor for AuthInterceptor<F>
where
    F: Fn(&Metadata) -> Result<(), Status> + Send + Sync,
{
    fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        (self.validator)(request.metadata())
    }

    fn intercept_response(&self, _response: &mut Response<Bytes>) -> Result<(), Status> {
        Ok(())
    }
}

/// Unary service handler function type.
pub type UnaryHandler<Req, Resp> =
    Box<dyn Fn(Request<Req>) -> UnaryFuture<Resp> + Send + Sync + 'static>;

/// Future type for unary handlers.
pub type UnaryFuture<Resp> =
    Pin<Box<dyn Future<Output = Result<Response<Resp>, Status>> + Send + 'static>>;

/// Utility function to create an OK response.
pub fn ok<T>(message: T) -> Result<Response<T>, Status> {
    Ok(Response::new(message))
}

/// Utility function to create a status error.
pub fn err<T>(status: Status) -> Result<Response<T>, Status> {
    Err(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::service::ServiceDescriptor;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    struct TestService;

    impl NamedService for TestService {
        const NAME: &'static str = "test.TestService";
    }

    impl ServiceHandler for TestService {
        fn descriptor(&self) -> &ServiceDescriptor {
            static DESC: ServiceDescriptor = ServiceDescriptor::new("TestService", "test", &[]);
            &DESC
        }

        fn method_names(&self) -> Vec<&str> {
            vec![]
        }
    }

    #[test]
    fn test_server_builder() {
        init_test("test_server_builder");
        let server = Server::builder()
            .max_recv_message_size(1024 * 1024)
            .max_concurrent_streams(50)
            .add_service(TestService)
            .build();

        let max_recv = server.config().max_recv_message_size;
        crate::assert_with_log!(max_recv == 1024 * 1024, "max_recv", 1024 * 1024, max_recv);
        let max_streams = server.config().max_concurrent_streams;
        crate::assert_with_log!(max_streams == 50, "max_streams", 50, max_streams);
        let has_service = server.get_service("test.TestService").is_some();
        crate::assert_with_log!(has_service, "service exists", true, has_service);
        crate::test_complete!("test_server_builder");
    }

    #[test]
    fn test_server_service_names() {
        init_test("test_server_service_names");
        let server = Server::builder().add_service(TestService).build();

        let names = server.service_names();
        let contains = names.contains(&"test.TestService");
        crate::assert_with_log!(contains, "contains service name", true, contains);
        crate::test_complete!("test_server_service_names");
    }

    #[test]
    fn test_call_context() {
        init_test("test_call_context");
        let ctx = CallContext::new();
        let meta_empty = ctx.metadata().is_empty();
        crate::assert_with_log!(meta_empty, "metadata empty", true, meta_empty);
        let deadline_none = ctx.deadline().is_none();
        crate::assert_with_log!(deadline_none, "deadline none", true, deadline_none);
        let peer_none = ctx.peer_addr().is_none();
        crate::assert_with_log!(peer_none, "peer none", true, peer_none);
        let expired = ctx.is_expired();
        crate::assert_with_log!(!expired, "not expired", false, expired);

        let cx = Cx::for_testing();
        let wrapped = ctx.with_cx(&cx);
        let _readonly = wrapped.cx_readonly();
        let _narrow = wrapped.cx_narrow::<cap::CapSet<true, true, false, false, false>>();
        crate::test_complete!("test_call_context");
    }

    #[test]
    fn test_noop_interceptor() {
        init_test("test_noop_interceptor");
        let interceptor = NoopInterceptor;
        let mut request = Request::new(Bytes::new());
        let ok = interceptor.intercept_request(&mut request).is_ok();
        crate::assert_with_log!(ok, "request ok", true, ok);

        let mut response = Response::new(Bytes::new());
        let ok = interceptor.intercept_response(&mut response).is_ok();
        crate::assert_with_log!(ok, "response ok", true, ok);
        crate::test_complete!("test_noop_interceptor");
    }

    #[test]
    fn test_auth_interceptor() {
        init_test("test_auth_interceptor");
        let interceptor = AuthInterceptor::new(|metadata| {
            if metadata.get("authorization").is_some() {
                Ok(())
            } else {
                Err(Status::unauthenticated("missing authorization"))
            }
        });

        // Request without auth
        let mut request = Request::new(Bytes::new());
        let err = interceptor.intercept_request(&mut request).is_err();
        crate::assert_with_log!(err, "missing auth err", true, err);

        // Request with auth
        request
            .metadata_mut()
            .insert("authorization", "Bearer token");
        let ok = interceptor.intercept_request(&mut request).is_ok();
        crate::assert_with_log!(ok, "auth ok", true, ok);
        crate::test_complete!("test_auth_interceptor");
    }
}
