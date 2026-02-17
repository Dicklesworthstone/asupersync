//! gRPC Health Checking Protocol implementation.
//!
//! Implements the standard gRPC health checking protocol as defined in
//! [grpc/grpc-proto](https://github.com/grpc/grpc-proto/blob/master/grpc/health/v1/health.proto).
//!
//! # Example
//!
//! ```ignore
//! use asupersync::grpc::health::{HealthService, ServingStatus};
//!
//! // Create health service
//! let health = HealthService::new();
//!
//! // Set service status
//! health.set_status("my.service.Name", ServingStatus::Serving);
//!
//! // Register with gRPC server
//! let server = Server::builder()
//!     .add_service(health.clone())
//!     .build();
//! ```

use parking_lot::RwLock;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use super::service::{NamedService, ServiceDescriptor, ServiceHandler};
use super::status::Status;
use super::streaming::{Request, Response};

/// Service status for health checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(i32)]
pub enum ServingStatus {
    /// Status is unknown.
    #[default]
    Unknown = 0,
    /// Service is healthy and serving requests.
    Serving = 1,
    /// Service is not serving requests.
    NotServing = 2,
    /// Used only by Watch. Indicates the service is in a transient state.
    ServiceUnknown = 3,
}

impl ServingStatus {
    /// Returns true if the service is healthy.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Serving)
    }

    /// Convert from i32.
    #[must_use]
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Unknown),
            1 => Some(Self::Serving),
            2 => Some(Self::NotServing),
            3 => Some(Self::ServiceUnknown),
            _ => None,
        }
    }
}

impl std::fmt::Display for ServingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "UNKNOWN"),
            Self::Serving => write!(f, "SERVING"),
            Self::NotServing => write!(f, "NOT_SERVING"),
            Self::ServiceUnknown => write!(f, "SERVICE_UNKNOWN"),
        }
    }
}

/// Request for health check.
#[derive(Debug, Clone, Default)]
pub struct HealthCheckRequest {
    /// The service name to check.
    ///
    /// Empty string means check the overall server health.
    pub service: String,
}

impl HealthCheckRequest {
    /// Create a new request for a specific service.
    #[must_use]
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    /// Create a request for overall server health.
    #[must_use]
    pub fn server() -> Self {
        Self::default()
    }
}

/// Response from health check.
#[derive(Debug, Clone)]
pub struct HealthCheckResponse {
    /// The serving status.
    pub status: ServingStatus,
}

impl HealthCheckResponse {
    /// Create a new response.
    #[must_use]
    pub fn new(status: ServingStatus) -> Self {
        Self { status }
    }
}

impl Default for HealthCheckResponse {
    fn default() -> Self {
        Self {
            status: ServingStatus::Unknown,
        }
    }
}

/// Health checking service.
///
/// This service implements the gRPC Health Checking Protocol, allowing
/// clients to query the health status of services.
///
/// # Thread Safety
///
/// The service is thread-safe and can be cloned to share between handlers.
#[derive(Debug, Clone)]
pub struct HealthService {
    /// Service statuses.
    statuses: Arc<RwLock<HashMap<String, ServingStatus>>>,
}

impl HealthService {
    /// Create a new health service.
    #[must_use]
    pub fn new() -> Self {
        Self {
            statuses: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Set the status of a service.
    ///
    /// Use an empty string for the overall server status.
    pub fn set_status(&self, service: impl Into<String>, status: ServingStatus) {
        let mut statuses = self.statuses.write();
        statuses.insert(service.into(), status);
    }

    /// Set the status of the overall server.
    pub fn set_server_status(&self, status: ServingStatus) {
        self.set_status("", status);
    }

    /// Get the status of a service.
    ///
    /// Returns `None` if the service is not registered.
    #[must_use]
    pub fn get_status(&self, service: &str) -> Option<ServingStatus> {
        let statuses = self.statuses.read();
        statuses.get(service).copied()
    }

    /// Check if a service is serving.
    #[must_use]
    pub fn is_serving(&self, service: &str) -> bool {
        self.get_status(service).is_some_and(|s| s.is_healthy())
    }

    /// Clear all service statuses.
    pub fn clear(&self) {
        let mut statuses = self.statuses.write();
        statuses.clear();
    }

    /// Remove a service from health tracking.
    pub fn clear_status(&self, service: &str) {
        let mut statuses = self.statuses.write();
        statuses.remove(service);
    }

    /// Get all registered services.
    #[must_use]
    pub fn services(&self) -> Vec<String> {
        let statuses = self.statuses.read();
        statuses.keys().cloned().collect()
    }

    /// Handle a health check request.
    pub fn check(&self, request: &HealthCheckRequest) -> Result<HealthCheckResponse, Status> {
        let statuses = self.statuses.read();

        if let Some(&status) = statuses.get(&request.service) {
            drop(statuses);
            Ok(HealthCheckResponse::new(status))
        } else if request.service.is_empty() {
            // No explicit server status set, default to SERVING if any services are registered
            if statuses.is_empty() {
                drop(statuses);
                Ok(HealthCheckResponse::new(ServingStatus::ServiceUnknown))
            } else {
                // Check if all services are healthy
                let all_healthy = statuses.values().all(ServingStatus::is_healthy);
                drop(statuses);
                if all_healthy {
                    Ok(HealthCheckResponse::new(ServingStatus::Serving))
                } else {
                    Ok(HealthCheckResponse::new(ServingStatus::NotServing))
                }
            }
        } else {
            drop(statuses);
            Err(Status::not_found(format!(
                "service '{}' not registered for health checking",
                request.service
            )))
        }
    }

    /// Async check handler for use with gRPC server.
    #[must_use]
    pub fn check_async(
        &self,
        request: &Request<HealthCheckRequest>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<HealthCheckResponse>, Status>> + Send>> {
        let result = self.check(request.get_ref());
        Box::pin(async move { result.map(Response::new) })
    }
}

impl Default for HealthService {
    fn default() -> Self {
        Self::new()
    }
}

impl NamedService for HealthService {
    const NAME: &'static str = "grpc.health.v1.Health";
}

impl ServiceHandler for HealthService {
    fn descriptor(&self) -> &ServiceDescriptor {
        static METHODS: &[super::service::MethodDescriptor] = &[
            super::service::MethodDescriptor::unary("Check", "/grpc.health.v1.Health/Check"),
            super::service::MethodDescriptor::server_streaming(
                "Watch",
                "/grpc.health.v1.Health/Watch",
            ),
        ];
        static DESC: ServiceDescriptor =
            ServiceDescriptor::new("Health", "grpc.health.v1", METHODS);
        &DESC
    }

    fn method_names(&self) -> Vec<&str> {
        vec!["Check", "Watch"]
    }
}

/// Health reporter for tracking service lifecycle.
///
/// Provides a convenient way to manage health status during service
/// initialization and shutdown.
#[derive(Debug)]
pub struct HealthReporter {
    service: HealthService,
    service_name: String,
}

impl HealthReporter {
    /// Create a new health reporter for a service.
    #[must_use]
    pub fn new(service: HealthService, service_name: impl Into<String>) -> Self {
        Self {
            service,
            service_name: service_name.into(),
        }
    }

    /// Mark the service as serving.
    pub fn set_serving(&self) {
        self.service
            .set_status(&self.service_name, ServingStatus::Serving);
    }

    /// Mark the service as not serving.
    pub fn set_not_serving(&self) {
        self.service
            .set_status(&self.service_name, ServingStatus::NotServing);
    }

    /// Get the current status.
    #[must_use]
    pub fn status(&self) -> ServingStatus {
        self.service
            .get_status(&self.service_name)
            .unwrap_or(ServingStatus::Unknown)
    }
}

impl Drop for HealthReporter {
    fn drop(&mut self) {
        // Clear the service status when the reporter is dropped
        self.service.clear_status(&self.service_name);
    }
}

/// Builder for creating health services with initial statuses.
#[derive(Debug, Default)]
pub struct HealthServiceBuilder {
    statuses: HashMap<String, ServingStatus>,
}

impl HealthServiceBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a service with a status.
    #[must_use]
    pub fn add(mut self, service: impl Into<String>, status: ServingStatus) -> Self {
        self.statuses.insert(service.into(), status);
        self
    }

    /// Add multiple services all set to SERVING.
    #[must_use]
    pub fn add_serving(mut self, services: impl IntoIterator<Item = impl Into<String>>) -> Self {
        for service in services {
            self.statuses.insert(service.into(), ServingStatus::Serving);
        }
        self
    }

    /// Build the health service.
    #[must_use]
    pub fn build(self) -> HealthService {
        let service = HealthService::new();
        for (name, status) in self.statuses {
            service.set_status(name, status);
        }
        service
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn serving_status_from_i32() {
        init_test("serving_status_from_i32");
        crate::assert_with_log!(
            ServingStatus::from_i32(0) == Some(ServingStatus::Unknown),
            "0",
            Some(ServingStatus::Unknown),
            ServingStatus::from_i32(0)
        );
        crate::assert_with_log!(
            ServingStatus::from_i32(1) == Some(ServingStatus::Serving),
            "1",
            Some(ServingStatus::Serving),
            ServingStatus::from_i32(1)
        );
        crate::assert_with_log!(
            ServingStatus::from_i32(2) == Some(ServingStatus::NotServing),
            "2",
            Some(ServingStatus::NotServing),
            ServingStatus::from_i32(2)
        );
        crate::assert_with_log!(
            ServingStatus::from_i32(3) == Some(ServingStatus::ServiceUnknown),
            "3",
            Some(ServingStatus::ServiceUnknown),
            ServingStatus::from_i32(3)
        );
        let none = ServingStatus::from_i32(4).is_none();
        crate::assert_with_log!(none, "4 none", true, none);
        crate::test_complete!("serving_status_from_i32");
    }

    #[test]
    fn serving_status_is_healthy() {
        init_test("serving_status_is_healthy");
        let unknown = ServingStatus::Unknown.is_healthy();
        crate::assert_with_log!(!unknown, "unknown healthy", false, unknown);
        let serving = ServingStatus::Serving.is_healthy();
        crate::assert_with_log!(serving, "serving healthy", true, serving);
        let not_serving = ServingStatus::NotServing.is_healthy();
        crate::assert_with_log!(!not_serving, "not serving healthy", false, not_serving);
        let service_unknown = ServingStatus::ServiceUnknown.is_healthy();
        crate::assert_with_log!(
            !service_unknown,
            "service unknown healthy",
            false,
            service_unknown
        );
        crate::test_complete!("serving_status_is_healthy");
    }

    #[test]
    fn serving_status_display() {
        init_test("serving_status_display");
        let serving = ServingStatus::Serving.to_string();
        crate::assert_with_log!(serving == "SERVING", "serving", "SERVING", serving);
        let not_serving = ServingStatus::NotServing.to_string();
        crate::assert_with_log!(
            not_serving == "NOT_SERVING",
            "not serving",
            "NOT_SERVING",
            not_serving
        );
        crate::test_complete!("serving_status_display");
    }

    #[test]
    fn health_service_set_and_get() {
        init_test("health_service_set_and_get");
        let service = HealthService::new();

        service.set_status("test.Service", ServingStatus::Serving);
        let status = service.get_status("test.Service");
        crate::assert_with_log!(
            status == Some(ServingStatus::Serving),
            "serving",
            Some(ServingStatus::Serving),
            status
        );

        service.set_status("test.Service", ServingStatus::NotServing);
        let status = service.get_status("test.Service");
        crate::assert_with_log!(
            status == Some(ServingStatus::NotServing),
            "not serving",
            Some(ServingStatus::NotServing),
            status
        );
        crate::test_complete!("health_service_set_and_get");
    }

    #[test]
    fn health_service_is_serving() {
        init_test("health_service_is_serving");
        let service = HealthService::new();

        let unknown = service.is_serving("unknown");
        crate::assert_with_log!(!unknown, "unknown not serving", false, unknown);

        service.set_status("test", ServingStatus::Serving);
        let serving = service.is_serving("test");
        crate::assert_with_log!(serving, "test serving", true, serving);

        service.set_status("test", ServingStatus::NotServing);
        let serving = service.is_serving("test");
        crate::assert_with_log!(!serving, "test not serving", false, serving);
        crate::test_complete!("health_service_is_serving");
    }

    #[test]
    fn health_service_check() {
        init_test("health_service_check");
        let service = HealthService::new();
        service.set_status("test.Service", ServingStatus::Serving);

        let req = HealthCheckRequest::new("test.Service");
        let resp = service.check(&req).unwrap();
        crate::assert_with_log!(
            resp.status == ServingStatus::Serving,
            "serving",
            ServingStatus::Serving,
            resp.status
        );

        let req = HealthCheckRequest::new("unknown.Service");
        let err = service.check(&req).unwrap_err();
        let code = err.code();
        crate::assert_with_log!(
            code == super::super::status::Code::NotFound,
            "not found",
            super::super::status::Code::NotFound,
            code
        );
        crate::test_complete!("health_service_check");
    }

    #[test]
    fn health_service_server_status() {
        init_test("health_service_server_status");
        let service = HealthService::new();

        // No services registered
        let req = HealthCheckRequest::server();
        let resp = service.check(&req).unwrap();
        crate::assert_with_log!(
            resp.status == ServingStatus::ServiceUnknown,
            "service unknown",
            ServingStatus::ServiceUnknown,
            resp.status
        );

        // Add a healthy service
        service.set_status("test", ServingStatus::Serving);
        let resp = service.check(&req).unwrap();
        crate::assert_with_log!(
            resp.status == ServingStatus::Serving,
            "serving",
            ServingStatus::Serving,
            resp.status
        );

        // Add an unhealthy service
        service.set_status("test2", ServingStatus::NotServing);
        let resp = service.check(&req).unwrap();
        crate::assert_with_log!(
            resp.status == ServingStatus::NotServing,
            "not serving",
            ServingStatus::NotServing,
            resp.status
        );

        // Explicit server status overrides
        service.set_server_status(ServingStatus::Serving);
        let resp = service.check(&req).unwrap();
        crate::assert_with_log!(
            resp.status == ServingStatus::Serving,
            "server serving",
            ServingStatus::Serving,
            resp.status
        );
        crate::test_complete!("health_service_server_status");
    }

    #[test]
    fn health_service_clear() {
        init_test("health_service_clear");
        let service = HealthService::new();
        service.set_status("a", ServingStatus::Serving);
        service.set_status("b", ServingStatus::Serving);

        service.clear_status("a");
        let a_none = service.get_status("a").is_none();
        crate::assert_with_log!(a_none, "a cleared", true, a_none);
        let b_some = service.get_status("b").is_some();
        crate::assert_with_log!(b_some, "b still set", true, b_some);

        service.clear();
        let b_none = service.get_status("b").is_none();
        crate::assert_with_log!(b_none, "b cleared", true, b_none);
        crate::test_complete!("health_service_clear");
    }

    #[test]
    fn health_service_services() {
        init_test("health_service_services");
        let service = HealthService::new();
        service.set_status("a", ServingStatus::Serving);
        service.set_status("b", ServingStatus::NotServing);

        let services = service.services();
        let has_a = services.contains(&"a".to_string());
        crate::assert_with_log!(has_a, "has a", true, has_a);
        let has_b = services.contains(&"b".to_string());
        crate::assert_with_log!(has_b, "has b", true, has_b);
        crate::test_complete!("health_service_services");
    }

    #[test]
    fn health_reporter() {
        init_test("health_reporter");
        let service = HealthService::new();
        {
            let reporter = HealthReporter::new(service.clone(), "my.Service");
            reporter.set_serving();
            let status = reporter.status();
            crate::assert_with_log!(
                status == ServingStatus::Serving,
                "serving",
                ServingStatus::Serving,
                status
            );
            let serving = service.is_serving("my.Service");
            crate::assert_with_log!(serving, "service serving", true, serving);
        }
        // Service status cleared on drop
        let none = service.get_status("my.Service").is_none();
        crate::assert_with_log!(none, "cleared on drop", true, none);
        crate::test_complete!("health_reporter");
    }

    #[test]
    fn health_service_builder() {
        init_test("health_service_builder");
        let service = HealthServiceBuilder::new()
            .add("explicit", ServingStatus::NotServing)
            .add_serving(["a", "b", "c"])
            .build();

        let explicit = service.get_status("explicit");
        crate::assert_with_log!(
            explicit == Some(ServingStatus::NotServing),
            "explicit",
            Some(ServingStatus::NotServing),
            explicit
        );
        let a = service.get_status("a");
        crate::assert_with_log!(
            a == Some(ServingStatus::Serving),
            "a",
            Some(ServingStatus::Serving),
            a
        );
        let b = service.get_status("b");
        crate::assert_with_log!(
            b == Some(ServingStatus::Serving),
            "b",
            Some(ServingStatus::Serving),
            b
        );
        let c = service.get_status("c");
        crate::assert_with_log!(
            c == Some(ServingStatus::Serving),
            "c",
            Some(ServingStatus::Serving),
            c
        );
        crate::test_complete!("health_service_builder");
    }

    #[test]
    fn health_service_named_service() {
        init_test("health_service_named_service");
        let name = HealthService::NAME;
        crate::assert_with_log!(
            name == "grpc.health.v1.Health",
            "name",
            "grpc.health.v1.Health",
            name
        );
        crate::test_complete!("health_service_named_service");
    }

    #[test]
    fn health_service_descriptor() {
        init_test("health_service_descriptor");
        let service = HealthService::new();
        let desc = service.descriptor();
        crate::assert_with_log!(desc.name == "Health", "name", "Health", desc.name);
        crate::assert_with_log!(
            desc.package == "grpc.health.v1",
            "package",
            "grpc.health.v1",
            desc.package
        );
        let len = desc.methods.len();
        crate::assert_with_log!(len == 2, "methods len", 2, len);
        crate::test_complete!("health_service_descriptor");
    }

    #[test]
    fn health_service_method_names() {
        init_test("health_service_method_names");
        let service = HealthService::new();
        let names = service.method_names();
        let has_check = names.contains(&"Check");
        crate::assert_with_log!(has_check, "has Check", true, has_check);
        let has_watch = names.contains(&"Watch");
        crate::assert_with_log!(has_watch, "has Watch", true, has_watch);
        crate::test_complete!("health_service_method_names");
    }

    #[test]
    fn health_check_request_constructors() {
        init_test("health_check_request_constructors");
        let req = HealthCheckRequest::new("my.Service");
        crate::assert_with_log!(
            req.service == "my.Service",
            "service",
            "my.Service",
            req.service
        );

        let req = HealthCheckRequest::server();
        crate::assert_with_log!(req.service.is_empty(), "service", "", req.service);
        crate::test_complete!("health_check_request_constructors");
    }

    #[test]
    fn health_service_clone() {
        init_test("health_service_clone");
        let service1 = HealthService::new();
        let service2 = service1.clone();

        service1.set_status("test", ServingStatus::Serving);
        let status = service2.get_status("test");
        crate::assert_with_log!(
            status == Some(ServingStatus::Serving),
            "serving",
            Some(ServingStatus::Serving),
            status
        );
        crate::test_complete!("health_service_clone");
    }
}
