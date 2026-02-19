//! gRPC service traits and definitions.
//!
//! Provides the core traits for implementing gRPC services.

use std::future::Future;
use std::pin::Pin;

use super::status::Status;
use super::streaming::{Request, Response, Streaming};

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

/// A registered service handler.
pub trait ServiceHandler: Send + Sync {
    /// Get the service descriptor.
    fn descriptor(&self) -> &ServiceDescriptor;

    /// Get method names.
    fn method_names(&self) -> Vec<&str>;
}

#[cfg(test)]
mod tests {
    use super::*;

    static METHODS_GREETER: &[MethodDescriptor] = &[MethodDescriptor::unary(
        "SayHello",
        "/helloworld.Greeter/SayHello",
    )];
    static METHODS_EMPTY: &[MethodDescriptor] = &[];

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_method_descriptor_unary() {
        init_test("test_method_descriptor_unary");
        let desc = MethodDescriptor::unary("SayHello", "/helloworld.Greeter/SayHello");
        let unary = desc.is_unary();
        crate::assert_with_log!(unary, "is_unary", true, unary);
        crate::assert_with_log!(
            !desc.client_streaming,
            "client_streaming",
            false,
            desc.client_streaming
        );
        crate::assert_with_log!(
            !desc.server_streaming,
            "server_streaming",
            false,
            desc.server_streaming
        );
        crate::test_complete!("test_method_descriptor_unary");
    }

    #[test]
    fn test_method_descriptor_server_streaming() {
        init_test("test_method_descriptor_server_streaming");
        let desc =
            MethodDescriptor::server_streaming("ListFeatures", "/route.RouteGuide/ListFeatures");
        let unary = desc.is_unary();
        crate::assert_with_log!(!unary, "not unary", false, unary);
        crate::assert_with_log!(
            !desc.client_streaming,
            "client_streaming",
            false,
            desc.client_streaming
        );
        crate::assert_with_log!(
            desc.server_streaming,
            "server_streaming",
            true,
            desc.server_streaming
        );
        crate::test_complete!("test_method_descriptor_server_streaming");
    }

    #[test]
    fn test_method_descriptor_bidi() {
        init_test("test_method_descriptor_bidi");
        let desc = MethodDescriptor::bidi_streaming("RouteChat", "/route.RouteGuide/RouteChat");
        crate::assert_with_log!(
            desc.client_streaming,
            "client_streaming",
            true,
            desc.client_streaming
        );
        crate::assert_with_log!(
            desc.server_streaming,
            "server_streaming",
            true,
            desc.server_streaming
        );
        crate::test_complete!("test_method_descriptor_bidi");
    }

    #[test]
    fn test_service_descriptor() {
        init_test("test_service_descriptor");
        let desc = ServiceDescriptor::new("Greeter", "helloworld", METHODS_GREETER);
        let name = desc.full_name();
        crate::assert_with_log!(
            name == "helloworld.Greeter",
            "full_name",
            "helloworld.Greeter",
            name
        );
        let len = desc.methods.len();
        crate::assert_with_log!(len == 1, "methods len", 1, len);
        crate::test_complete!("test_service_descriptor");
    }

    #[test]
    fn test_service_descriptor_no_package() {
        init_test("test_service_descriptor_no_package");
        let desc = ServiceDescriptor::new("Service", "", METHODS_EMPTY);
        let name = desc.full_name();
        crate::assert_with_log!(name == "Service", "full_name", "Service", name);
        crate::test_complete!("test_service_descriptor_no_package");
    }

    // =========================================================================
    // Wave 46 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn method_descriptor_debug_clone() {
        let md = MethodDescriptor::unary("Hello", "/pkg.Svc/Hello");
        let dbg = format!("{md:?}");
        assert!(dbg.contains("MethodDescriptor"), "{dbg}");
        assert!(dbg.contains("Hello"), "{dbg}");
        let cloned = md.clone();
        assert_eq!(cloned.name, md.name);
        assert_eq!(cloned.path, md.path);
        assert_eq!(cloned.client_streaming, md.client_streaming);
        assert_eq!(cloned.server_streaming, md.server_streaming);
    }

    #[test]
    fn method_descriptor_client_streaming() {
        let md = MethodDescriptor::client_streaming("Upload", "/pkg.Svc/Upload");
        assert!(md.client_streaming);
        assert!(!md.server_streaming);
        assert!(!md.is_unary());
    }

    #[test]
    fn service_descriptor_debug_clone() {
        let desc = ServiceDescriptor::new("Greeter", "helloworld", METHODS_GREETER);
        let dbg = format!("{desc:?}");
        assert!(dbg.contains("ServiceDescriptor"), "{dbg}");
        let cloned = desc.clone();
        assert_eq!(cloned.name, "Greeter");
        assert_eq!(cloned.package, "helloworld");
        assert_eq!(cloned.methods.len(), 1);
    }
}
