//! gRPC server implementation.
//!
//! Provides the server-side infrastructure for hosting gRPC services.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::bytes::Bytes;

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
    services: HashMap<String, Arc<dyn ServiceHandler>>,
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
            services: HashMap::new(),
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
    services: HashMap<String, Arc<dyn ServiceHandler>>,
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
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Get the registered services.
    pub fn services(&self) -> &HashMap<String, Arc<dyn ServiceHandler>> {
        &self.services
    }

    /// Get a service by name.
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
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// Get the deadline.
    pub fn deadline(&self) -> Option<std::time::Instant> {
        self.deadline
    }

    /// Get the peer address.
    pub fn peer_addr(&self) -> Option<&str> {
        self.peer_addr.as_deref()
    }

    /// Check if the deadline has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.deadline
            .map(|d| std::time::Instant::now() > d)
            .unwrap_or(false)
    }
}

impl Default for CallContext {
    fn default() -> Self {
        Self::new()
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
        let server = Server::builder()
            .max_recv_message_size(1024 * 1024)
            .max_concurrent_streams(50)
            .add_service(TestService)
            .build();

        assert_eq!(server.config().max_recv_message_size, 1024 * 1024);
        assert_eq!(server.config().max_concurrent_streams, 50);
        assert!(server.get_service("test.TestService").is_some());
    }

    #[test]
    fn test_server_service_names() {
        let server = Server::builder().add_service(TestService).build();

        let names = server.service_names();
        assert!(names.contains(&"test.TestService"));
    }

    #[test]
    fn test_call_context() {
        let ctx = CallContext::new();
        assert!(ctx.metadata().is_empty());
        assert!(ctx.deadline().is_none());
        assert!(ctx.peer_addr().is_none());
        assert!(!ctx.is_expired());
    }

    #[test]
    fn test_noop_interceptor() {
        let interceptor = NoopInterceptor;
        let mut request = Request::new(Bytes::new());
        assert!(interceptor.intercept_request(&mut request).is_ok());

        let mut response = Response::new(Bytes::new());
        assert!(interceptor.intercept_response(&mut response).is_ok());
    }

    #[test]
    fn test_auth_interceptor() {
        let interceptor = AuthInterceptor::new(|metadata| {
            if metadata.get("authorization").is_some() {
                Ok(())
            } else {
                Err(Status::unauthenticated("missing authorization"))
            }
        });

        // Request without auth
        let mut request = Request::new(Bytes::new());
        assert!(interceptor.intercept_request(&mut request).is_err());

        // Request with auth
        request
            .metadata_mut()
            .insert("authorization", "Bearer token");
        assert!(interceptor.intercept_request(&mut request).is_ok());
    }
}
