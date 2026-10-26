//! gRPC service traits and definitions.
//!
//! Provides the core traits for implementing gRPC services.

use std::future::Future;
use std::pin::Pin;

use crate::bytes::Bytes;
use crate::cx::Cx;

use super::status::Status;
use super::streaming::{Metadata, Request, Response, Streaming};

mod server_stream;
pub use server_stream::{RegisteredServerStream, ServiceStreamingFuture};

/// A gRPC service method.
pub trait Method: Send + Sync + 'static {
    /// The request type.
    type Request: Send + 'static;
    /// The response type.
    type Response: Send + 'static;
    /// The future type returned by the method.
    type Future: Future<Output = Result<Response<Self::Response>, Status>> + Send;

    /// Handle the request.
    fn call(&self, request: Request<Self::Request>) -> Self::Future;
}

/// A named service with a full service name.
pub trait NamedService {
    /// The service name (e.g., "helloworld.Greeter").
    const NAME: &'static str;
}

/// A unary RPC method.
pub trait UnaryMethod<Req, Resp>: Send + Sync + 'static
where
    Req: Send + 'static,
    Resp: Send + 'static,
{
    /// Handle the unary request.
    fn call(
        &self,
        request: Request<Req>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<Resp>, Status>> + Send>>;
}

/// A server streaming RPC method.
#[allow(clippy::type_complexity)]
pub trait ServerStreamingMethod<Req, Resp>: Send + Sync + 'static
where
    Req: Send + 'static,
    Resp: Send + 'static,
{
    /// The stream type returned.
    type Stream: Streaming<Message = Resp> + Send + 'static;

    /// Handle the request and return a stream.
    fn call(
        &self,
        request: Request<Req>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<Self::Stream>, Status>> + Send>>;
}

/// A client streaming RPC method.
pub trait ClientStreamingMethod<Req, Resp>: Send + Sync + 'static
where
    Req: Send + 'static,
    Resp: Send + 'static,
{
    /// The stream type for receiving requests.
    type Stream: Streaming<Message = Req> + Send + 'static;

    /// Handle the streaming request.
    fn call(
        &self,
        request: Request<Self::Stream>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<Resp>, Status>> + Send>>;
}

/// A bidirectional streaming RPC method.
#[allow(clippy::type_complexity)]
pub trait BidiStreamingMethod<Req, Resp>: Send + Sync + 'static
where
    Req: Send + 'static,
    Resp: Send + 'static,
{
    /// The stream type for receiving requests.
    type RequestStream: Streaming<Message = Req> + Send + 'static;
    /// The stream type for sending responses.
    type ResponseStream: Streaming<Message = Resp> + Send + 'static;

    /// Handle the bidirectional stream.
    fn call(
        &self,
        request: Request<Self::RequestStream>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<Self::ResponseStream>, Status>> + Send>>;
}

/// Method descriptor containing method metadata.
#[derive(Debug, Clone)]
pub struct MethodDescriptor {
    /// The method name (e.g., "SayHello").
    pub name: &'static str,
    /// The full path (e.g., "/helloworld.Greeter/SayHello").
    pub path: &'static str,
    /// Whether this is a client streaming method.
    pub client_streaming: bool,
    /// Whether this is a server streaming method.
    pub server_streaming: bool,
}

impl MethodDescriptor {
    /// Create a unary method descriptor.
    #[must_use]
    pub const fn unary(name: &'static str, path: &'static str) -> Self {
        Self {
            name,
            path,
            client_streaming: false,
            server_streaming: false,
        }
    }

    /// Create a server streaming method descriptor.
    #[must_use]
    pub const fn server_streaming(name: &'static str, path: &'static str) -> Self {
        Self {
            name,
            path,
            client_streaming: false,
            server_streaming: true,
        }
    }

    /// Create a client streaming method descriptor.
    #[must_use]
    pub const fn client_streaming(name: &'static str, path: &'static str) -> Self {
        Self {
            name,
            path,
            client_streaming: true,
            server_streaming: false,
        }
    }

    /// Create a bidirectional streaming method descriptor.
    #[must_use]
    pub const fn bidi_streaming(name: &'static str, path: &'static str) -> Self {
        Self {
            name,
            path,
            client_streaming: true,
            server_streaming: true,
        }
    }

    /// Returns true if this is a unary method.
    #[must_use]
    pub const fn is_unary(&self) -> bool {
        !self.client_streaming && !self.server_streaming
    }
}

/// Service descriptor containing service metadata.
#[derive(Debug, Clone)]
pub struct ServiceDescriptor {
    /// The service name.
    pub name: &'static str,
    /// The package name.
    pub package: &'static str,
    /// The methods in this service.
    pub methods: &'static [MethodDescriptor],
}

impl ServiceDescriptor {
    /// Create a new service descriptor.
    #[must_use]
    pub const fn new(
        name: &'static str,
        package: &'static str,
        methods: &'static [MethodDescriptor],
    ) -> Self {
        Self {
            name,
            package,
            methods,
        }
    }

    /// Get the full service name (package.name).
    #[must_use]
    pub fn full_name(&self) -> String {
        if self.package.is_empty() {
            self.name.to_string()
        } else {
            format!("{}.{}", self.package, self.name)
        }
    }
}

/// Function pointer type for unary methods.
pub type UnaryHandler<Req, Resp> = Box<
    dyn Fn(Request<Req>) -> Pin<Box<dyn Future<Output = Result<Response<Resp>, Status>> + Send>>
        + Send
        + Sync,
>;

/// Future returned by a callable registered unary service.
///
/// The lifetime permits generated service implementations to borrow their
/// handler state and the explicit request [`Cx`] while the call is in flight.
pub type ServiceHandlerFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Response<Bytes>, Status>> + Send + 'a>>;

/// A registered service handler.
pub trait ServiceHandler: Send + Sync {
    /// Get the service descriptor.
    fn descriptor(&self) -> &ServiceDescriptor;

    /// Get method names.
    fn method_names(&self) -> Vec<&str>;

    /// Opt a response-streaming method into application initial metadata.
    ///
    /// Returning `true` delays response headers until the server-streaming or
    /// bidirectional factory returns its [`RegisteredServerStream`]. This lets
    /// the transport validate and publish that stream's initial metadata before
    /// any response message. The native H2 and gRPC-Web streaming adapters honor
    /// this choice for the exact registered `path`; unary and client-streaming
    /// methods always retain their existing header timing.
    ///
    /// The default preserves eager response headers for existing registrations,
    /// including bidirectional factories that wait for request input. Such a
    /// method must return empty initial metadata; a nonempty block fails with
    /// `INTERNAL` before source polling instead of being dropped or moved into
    /// trailers. An opted-in factory must not wait for input from a peer that
    /// itself waits for response headers before uploading.
    fn defer_response_headers(&self, _path: &str) -> bool {
        false
    }

    /// Dispatch one decoded unary request for `path`.
    ///
    /// [`crate::grpc::Server::bind_registered_http2`] calls this hook only
    /// after resolving `path` against [`Self::descriptor`] and confirming that
    /// the descriptor marks the method as unary. The explicit [`Cx`] carries
    /// the request region's cancellation, deadline, and capabilities. Initial
    /// metadata remains on `request`; HTTP/2 request trailers are supplied
    /// separately so their wire ordering is not collapsed.
    ///
    /// The default preserves source compatibility for metadata-only service
    /// implementations shipped before callable routing existed. Such a
    /// service fails closed with gRPC `UNIMPLEMENTED` instead of being mistaken
    /// for a callable handler.
    fn call_unary<'a>(
        &'a self,
        _cx: &'a Cx,
        path: &'a str,
        _request: Request<Bytes>,
        _trailing_metadata: Metadata,
    ) -> ServiceHandlerFuture<'a> {
        let message = format!("registered service has no callable unary handler for '{path}'");
        Box::pin(async move { Err(Status::unimplemented(message)) })
    }

    /// Create an owned response stream for one decoded request.
    ///
    /// Native server-streaming dispatch resolves the exact descriptor path and
    /// admits only unary-input, server-streaming methods here. The factory runs
    /// in the live response-producer context, not a context retained from an
    /// earlier HTTP handler. Request trailers remain separate from the initial
    /// request metadata.
    ///
    /// The default keeps existing implementations source-compatible and fails
    /// closed with `UNIMPLEMENTED`. The returned [`RegisteredServerStream`]
    /// carries initial metadata separately from successful application trailers;
    /// neither block is silently moved into the other.
    fn call_server_streaming<'a>(
        &'a self,
        _cx: &'a Cx,
        path: &'a str,
        _request: Request<Bytes>,
        _trailing_metadata: Metadata,
    ) -> ServiceStreamingFuture<'a> {
        let message =
            format!("registered service has no callable server-streaming handler for '{path}'");
        Box::pin(async move { Err(Status::unimplemented(message)) })
    }

    /// Consume a live request stream and return one response message.
    ///
    /// The native duplex listener invokes this hook in the actual request
    /// child region. Initial request metadata remains on `request`; request
    /// trailers become available from the stream only after validated EOF.
    /// Response metadata is **terminal trailing metadata** in this additive
    /// produced-response lane; initial response headers are transport-owned.
    /// The default preserves existing service implementations.
    #[cfg(all(feature = "http2-streaming", not(target_arch = "wasm32")))]
    fn call_client_streaming<'a>(
        &'a self,
        _cx: &'a Cx,
        path: &'a str,
        _request: Request<super::server::RegisteredRequestStream>,
    ) -> ServiceHandlerFuture<'a> {
        let message =
            format!("registered service has no callable client-streaming handler for '{path}'");
        Box::pin(async move { Err(Status::unimplemented(message)) })
    }

    /// Create a response stream that may own and incrementally consume the
    /// request stream, allowing responses before request EOF.
    ///
    /// The request and response remain in the same actual child region through
    /// response completion and descendant drain. Reset, connection loss, and
    /// deadline cancellation reach both directions. The default preserves
    /// existing service implementations and refuses this method explicitly.
    #[cfg(all(feature = "http2-streaming", not(target_arch = "wasm32")))]
    fn call_bidirectional_streaming<'a>(
        &'a self,
        _cx: &'a Cx,
        path: &'a str,
        _request: Request<super::server::RegisteredRequestStream>,
    ) -> ServiceStreamingFuture<'a> {
        let message =
            format!("registered service has no callable bidirectional handler for '{path}'");
        Box::pin(async move { Err(Status::unimplemented(message)) })
    }
}

#[cfg(test)]
#[path = "service_inline_tests.rs"]
mod tests;
