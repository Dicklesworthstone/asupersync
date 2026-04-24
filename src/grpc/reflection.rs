//! gRPC reflection service support.
//!
//! This module provides an in-process reflection registry that can expose
//! service and method descriptors for discovery-oriented tooling.

use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use super::service::{MethodDescriptor, NamedService, ServiceDescriptor, ServiceHandler};
use super::status::Status;
use super::streaming::{Request, Response};

/// Reflection metadata for a single gRPC method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReflectedMethod {
    /// Method name (e.g. `Check`).
    pub name: String,
    /// Fully-qualified RPC path (e.g. `/grpc.health.v1.Health/Check`).
    pub path: String,
    /// Whether this method accepts a request stream.
    pub client_streaming: bool,
    /// Whether this method returns a response stream.
    pub server_streaming: bool,
}

/// Reflection metadata for a single gRPC service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReflectedService {
    /// Fully-qualified service name (e.g. `grpc.health.v1.Health`).
    pub name: String,
    /// Methods exposed by this service.
    pub methods: Vec<ReflectedMethod>,
}

/// Request for listing all known services.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReflectionListServicesRequest;

/// Response containing all known service names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReflectionListServicesResponse {
    /// Sorted list of fully-qualified service names.
    pub services: Vec<String>,
}

/// Request for describing a specific service.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReflectionDescribeServiceRequest {
    /// Fully-qualified service name.
    pub service: String,
}

impl ReflectionDescribeServiceRequest {
    /// Create a new describe request.
    #[must_use]
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }
}

/// Response containing descriptor information for a single service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReflectionDescribeServiceResponse {
    /// Reflected service details.
    pub service: ReflectedService,
}

/// Reflection registry and service facade.
///
/// The registry stores a deterministic snapshot of service descriptors and can
/// be used directly or registered in [`crate::grpc::ServerBuilder`] via
/// `enable_reflection()`.
#[derive(Debug, Clone, Default)]
pub struct ReflectionService {
    services: Arc<RwLock<BTreeMap<String, ReflectedService>>>,
}

impl ReflectionService {
    /// Create an empty reflection registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            services: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    /// Build a reflection registry from existing handlers.
    #[must_use]
    pub fn from_handlers<'a, I>(handlers: I) -> Self
    where
        I: IntoIterator<Item = &'a dyn ServiceHandler>,
    {
        let reflection = Self::new();
        for handler in handlers {
            reflection.register_handler(handler);
        }
        reflection
    }

    /// Register descriptor metadata for a service.
    pub fn register_descriptor(&self, descriptor: &ServiceDescriptor) {
        let reflected = ReflectedService {
            name: descriptor.full_name(),
            methods: descriptor
                .methods
                .iter()
                .map(|method| ReflectedMethod {
                    name: method.name.to_string(),
                    path: method.path.to_string(),
                    client_streaming: method.client_streaming,
                    server_streaming: method.server_streaming,
                })
                .collect(),
        };
        self.services
            .write()
            .insert(reflected.name.clone(), reflected);
    }

    /// Register a handler's descriptor metadata.
    pub fn register_handler(&self, handler: &dyn ServiceHandler) {
        self.register_descriptor(handler.descriptor());
    }

    /// Returns all registered service names in deterministic order.
    #[must_use]
    pub fn list_services(&self) -> Vec<String> {
        self.services.read().keys().cloned().collect()
    }

    /// Returns reflection metadata for one service.
    pub fn describe_service(&self, service: &str) -> Result<ReflectedService, Status> {
        self.services
            .read()
            .get(service)
            .cloned()
            .ok_or_else(|| Status::not_found(format!("service '{service}' not found")))
    }

    /// Async helper for list-services RPC-style usage.
    #[must_use]
    pub fn list_services_async(
        &self,
        _request: &Request<ReflectionListServicesRequest>,
    ) -> Pin<
        Box<dyn Future<Output = Result<Response<ReflectionListServicesResponse>, Status>> + Send>,
    > {
        let response = ReflectionListServicesResponse {
            services: self.list_services(),
        };
        Box::pin(async move { Ok(Response::new(response)) })
    }

    /// Async helper for describe-service RPC-style usage.
    #[must_use]
    pub fn describe_service_async(
        &self,
        request: &Request<ReflectionDescribeServiceRequest>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Response<ReflectionDescribeServiceResponse>, Status>> + Send,
        >,
    > {
        let result = self
            .describe_service(&request.get_ref().service)
            .map(|service| ReflectionDescribeServiceResponse { service });
        Box::pin(async move { result.map(Response::new) })
    }
}

impl NamedService for ReflectionService {
    const NAME: &'static str = "grpc.reflection.v1alpha.ServerReflection";
}

impl ServiceHandler for ReflectionService {
    fn descriptor(&self) -> &ServiceDescriptor {
        static METHODS: &[MethodDescriptor] = &[MethodDescriptor::bidi_streaming(
            "ServerReflectionInfo",
            "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
        )];
        static DESC: ServiceDescriptor =
            ServiceDescriptor::new("ServerReflection", "grpc.reflection.v1alpha", METHODS);
        &DESC
    }

    fn method_names(&self) -> Vec<&str> {
        vec!["ServerReflectionInfo"]
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use insta::assert_json_snapshot;
    use serde_json::{Value, json};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    struct EchoService;

    impl ServiceHandler for EchoService {
        fn descriptor(&self) -> &ServiceDescriptor {
            static METHODS: &[MethodDescriptor] = &[
                MethodDescriptor::unary("Ping", "/pkg.Echo/Ping"),
                MethodDescriptor::server_streaming("Watch", "/pkg.Echo/Watch"),
            ];
            static DESC: ServiceDescriptor = ServiceDescriptor::new("Echo", "pkg", METHODS);
            &DESC
        }

        fn method_names(&self) -> Vec<&str> {
            vec!["Ping", "Watch"]
        }
    }

    struct EnumShapeService;

    impl ServiceHandler for EnumShapeService {
        fn descriptor(&self) -> &ServiceDescriptor {
            static METHODS: &[MethodDescriptor] = &[
                MethodDescriptor::unary("Unary", "/pkg.EnumShape/Unary"),
                MethodDescriptor::server_streaming("ServerStream", "/pkg.EnumShape/ServerStream"),
                MethodDescriptor::client_streaming("ClientStream", "/pkg.EnumShape/ClientStream"),
                MethodDescriptor::bidi_streaming("BidiStream", "/pkg.EnumShape/BidiStream"),
            ];
            static DESC: ServiceDescriptor = ServiceDescriptor::new("EnumShape", "pkg", METHODS);
            &DESC
        }

        fn method_names(&self) -> Vec<&str> {
            vec!["Unary", "ServerStream", "ClientStream", "BidiStream"]
        }
    }

    fn method_kind(method: &ReflectedMethod) -> &'static str {
        match (method.client_streaming, method.server_streaming) {
            (false, false) => "unary",
            (false, true) => "server_streaming",
            (true, false) => "client_streaming",
            (true, true) => "bidi_streaming",
        }
    }

    fn reflected_service_snapshot(service: &ReflectedService) -> Value {
        json!({
            "service": service.name,
            "methods": service.methods.iter().map(|method| {
                json!({
                    "name": method.name,
                    "path": method.path,
                    "kind": method_kind(method),
                })
            }).collect::<Vec<_>>(),
        })
    }

    #[test]
    fn reflection_register_list_and_describe() {
        init_test("reflection_register_list_and_describe");
        let reflection = ReflectionService::new();
        let echo = EchoService;
        reflection.register_handler(&echo);

        let services = reflection.list_services();
        crate::assert_with_log!(
            services == vec!["pkg.Echo".to_string()],
            "service list",
            vec!["pkg.Echo".to_string()],
            services
        );

        let described = reflection
            .describe_service("pkg.Echo")
            .expect("service exists");
        crate::assert_with_log!(
            described.methods.len() == 2,
            "method count",
            2,
            described.methods.len()
        );
        crate::assert_with_log!(
            described.methods[0].name == "Ping",
            "first method name",
            "Ping",
            &described.methods[0].name
        );
        crate::assert_with_log!(
            described.methods[1].server_streaming,
            "server streaming flag",
            true,
            described.methods[1].server_streaming
        );
        crate::test_complete!("reflection_register_list_and_describe");
    }

    #[test]
    fn reflection_describe_missing_service() {
        init_test("reflection_describe_missing_service");
        let reflection = ReflectionService::new();
        let err = reflection
            .describe_service("pkg.Missing")
            .expect_err("missing service should fail");
        crate::assert_with_log!(
            err.code() == super::super::status::Code::NotFound,
            "not found code",
            super::super::status::Code::NotFound,
            err.code()
        );
        crate::test_complete!("reflection_describe_missing_service");
    }

    #[test]
    fn reflection_async_helpers() {
        init_test("reflection_async_helpers");
        let reflection = ReflectionService::new();
        let echo = EchoService;
        reflection.register_handler(&echo);

        let list = futures_lite::future::block_on(
            reflection.list_services_async(&Request::new(ReflectionListServicesRequest)),
        )
        .expect("list succeeds");
        crate::assert_with_log!(
            list.get_ref().services == vec!["pkg.Echo".to_string()],
            "async list",
            vec!["pkg.Echo".to_string()],
            &list.get_ref().services
        );

        let describe = futures_lite::future::block_on(reflection.describe_service_async(
            &Request::new(ReflectionDescribeServiceRequest::new("pkg.Echo")),
        ))
        .expect("describe succeeds");
        crate::assert_with_log!(
            describe.get_ref().service.name == "pkg.Echo",
            "async describe name",
            "pkg.Echo",
            &describe.get_ref().service.name
        );
        crate::test_complete!("reflection_async_helpers");
    }

    #[test]
    fn reflection_service_traits() {
        init_test("reflection_service_traits");
        let reflection = ReflectionService::new();
        crate::assert_with_log!(
            ReflectionService::NAME == "grpc.reflection.v1alpha.ServerReflection",
            "service name",
            "grpc.reflection.v1alpha.ServerReflection",
            ReflectionService::NAME
        );
        let desc = reflection.descriptor();
        crate::assert_with_log!(
            desc.full_name() == "grpc.reflection.v1alpha.ServerReflection",
            "descriptor full name",
            "grpc.reflection.v1alpha.ServerReflection",
            desc.full_name()
        );
        let methods = reflection.method_names();
        crate::assert_with_log!(
            methods == vec!["ServerReflectionInfo"],
            "method names match the descriptor-exposed RPCs",
            vec!["ServerReflectionInfo"],
            methods
        );
        crate::test_complete!("reflection_service_traits");
    }

    #[test]
    fn reflection_descriptor_enum_output_snapshot() {
        init_test("reflection_descriptor_enum_output_snapshot");
        let reflection = ReflectionService::new();
        let enum_shape = EnumShapeService;
        reflection.register_handler(&enum_shape);

        let described = reflection
            .describe_service("pkg.EnumShape")
            .expect("enum-shape service exists");

        assert_json_snapshot!(
            "grpc_reflection_descriptor_enum_output",
            reflected_service_snapshot(&described)
        );
        crate::test_complete!("reflection_descriptor_enum_output_snapshot");
    }
}
