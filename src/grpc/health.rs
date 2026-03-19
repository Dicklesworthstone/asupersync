//! gRPC Health Checking Protocol implementation.
//!
//! Implements the standard gRPC health checking protocol as defined in
//! [grpc/grpc-proto](https://github.com/grpc/grpc-proto/blob/main/grpc/health/v1/health.proto).
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
use std::sync::atomic::{AtomicU64, Ordering};

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
    /// Monotonic change counters for individual watched services.
    watch_versions: Arc<RwLock<HashMap<String, u64>>>,
    /// Number of active reporters per service.
    reporter_counts: Arc<RwLock<HashMap<String, usize>>>,
    /// Monotonic version counter, bumped on every status change.
    version: Arc<AtomicU64>,
}

impl HealthService {
    /// Create a new health service.
    #[must_use]
    pub fn new() -> Self {
        Self {
            statuses: Arc::new(RwLock::new(HashMap::new())),
            watch_versions: Arc::new(RwLock::new(HashMap::new())),
            reporter_counts: Arc::new(RwLock::new(HashMap::new())),
            version: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Returns the current version counter. Bumped on every status change.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// Set the status of a service.
    ///
    /// Use an empty string for the overall server status.
    pub fn set_status(&self, service: impl Into<String>, status: ServingStatus) {
        let service = service.into();
        let mut statuses = self.statuses.write();
        let changed = statuses.insert(service.clone(), status) != Some(status);
        if changed {
            // Bump version while still holding statuses lock so that
            // concurrent readers see a consistent (status, version) pair.
            self.bump_watch_version(&service);
            self.version.fetch_add(1, Ordering::Release);
        }
        drop(statuses);
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
        let changed = !statuses.is_empty();
        let affected_services = if changed {
            statuses.keys().cloned().collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        if changed {
            statuses.clear();
            // Bump versions while still holding statuses lock so that
            // concurrent readers see a consistent (status, version) pair.
            self.bump_watch_versions(affected_services);
            self.version.fetch_add(1, Ordering::Release);
        }
        drop(statuses);
    }

    /// Remove a service from health tracking.
    pub fn clear_status(&self, service: &str) {
        let mut statuses = self.statuses.write();
        let changed = statuses.remove(service).is_some();
        if changed {
            self.bump_watch_version(service);
            self.version.fetch_add(1, Ordering::Release);
        }
        drop(statuses);
    }

    /// Get all registered services.
    #[must_use]
    pub fn services(&self) -> Vec<String> {
        let mut services: Vec<_> = {
            let statuses = self.statuses.read();
            statuses.keys().cloned().collect()
        };
        services.sort();
        services
    }

    fn watched_status(&self, service: &str) -> ServingStatus {
        if service.is_empty() {
            self.check(&HealthCheckRequest::server())
                .map_or(ServingStatus::ServiceUnknown, |response| response.status)
        } else {
            self.get_status(service)
                .unwrap_or(ServingStatus::ServiceUnknown)
        }
    }

    fn watched_version(&self, service: &str) -> u64 {
        if service.is_empty() {
            self.version()
        } else {
            let watch_versions = self.watch_versions.read();
            watch_versions.get(service).copied().unwrap_or(0)
        }
    }

    /// Read status and version atomically for a named service.
    ///
    /// Both the statuses lock and watch_versions lock are held simultaneously
    /// so that a concurrent `set_status` cannot interleave between the two
    /// reads, which would cause the watcher to record a stale status with an
    /// advanced version, permanently missing the real transition.
    #[allow(clippy::significant_drop_tightening)]
    fn watched_status_and_version(&self, service: &str) -> (ServingStatus, u64) {
        if service.is_empty() {
            // Server-level watcher uses the global atomic version.
            // MUST hold the statuses lock while reading the version to prevent
            // interleaving set_status() from pairing a stale status with a new version.
            let statuses = self.statuses.read();
            let status = if statuses.is_empty() {
                ServingStatus::ServiceUnknown
            } else if statuses.values().all(ServingStatus::is_healthy) {
                ServingStatus::Serving
            } else {
                ServingStatus::NotServing
            };
            let version = self.version();
            drop(statuses);
            (status, version)
        } else {
            // CORRECTNESS: Both locks MUST be held simultaneously so that a
            // concurrent set_status() cannot interleave between the status
            // read and the version read. Do NOT let a linter tighten these
            // scopes — the atomicity is load-bearing.
            let statuses = self.statuses.read();
            let watch_versions = self.watch_versions.read();
            let status = statuses
                .get(service)
                .copied()
                .unwrap_or(ServingStatus::ServiceUnknown);
            let version = watch_versions.get(service).copied().unwrap_or(0);
            drop(watch_versions);
            drop(statuses);
            (status, version)
        }
    }

    fn bump_watch_version(&self, service: &str) {
        self.watch_versions
            .write()
            .entry(service.to_string())
            .and_modify(|version| *version = version.saturating_add(1))
            .or_insert(1);
    }

    #[allow(clippy::significant_drop_tightening)]
    fn bump_watch_versions<I>(&self, services: I)
    where
        I: IntoIterator<Item = String>,
    {
        let mut watch_versions = self.watch_versions.write();
        for service in services {
            watch_versions
                .entry(service)
                .and_modify(|version| *version = version.saturating_add(1))
                .or_insert(1);
        }
    }

    fn acquire_reporter(&self, service: &str) {
        let mut reporter_counts = self.reporter_counts.write();
        *reporter_counts.entry(service.to_string()).or_insert(0) += 1;
    }

    fn release_reporter_and_maybe_clear_status(&self, service: &str) {
        self.release_reporter_and_maybe_clear_status_with_hook(service, || {});
    }

    #[allow(clippy::significant_drop_tightening)]
    fn release_reporter_and_maybe_clear_status_with_hook<F>(
        &self,
        service: &str,
        before_final_clear: F,
    ) where
        F: FnOnce(),
    {
        let mut reporter_counts = self.reporter_counts.write();
        let std::collections::hash_map::Entry::Occupied(mut entry) =
            reporter_counts.entry(service.to_string())
        else {
            return;
        };

        if *entry.get() > 1 {
            *entry.get_mut() -= 1;
            return;
        }

        // Hold reporter_counts across the final clear so a replacement reporter
        // cannot slip in between count release and status removal.
        let mut statuses = self.statuses.write();
        before_final_clear();
        let changed = statuses.remove(service).is_some();
        entry.remove();
        if changed {
            self.bump_watch_version(service);
            self.version.fetch_add(1, Ordering::Release);
        }
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

    /// Create a watcher that can poll for status changes on a specific service.
    ///
    /// The watcher captures the current status snapshot for that service;
    /// subsequent calls to [`HealthWatcher::changed`] return `true` only when
    /// the watched service's effective status changes.
    #[must_use]
    pub fn watch(&self, service: impl Into<String>) -> HealthWatcher {
        let service_name = service.into();
        HealthWatcher {
            service: self.clone(),
            last_status: self.watched_status(&service_name),
            last_version: self.watched_version(&service_name),
            service_name,
        }
    }
}

impl Default for HealthService {
    fn default() -> Self {
        Self::new()
    }
}

/// A watcher that can detect status changes for a particular service.
///
/// Implements the polling-based Watch semantic from the gRPC Health
/// Checking Protocol. Call [`changed`](HealthWatcher::changed) to check
/// whether the service status has changed since the last poll, and
/// [`status`](HealthWatcher::status) to retrieve the current value.
#[derive(Debug)]
pub struct HealthWatcher {
    service: HealthService,
    service_name: String,
    last_status: ServingStatus,
    last_version: u64,
}

impl HealthWatcher {
    /// Returns `true` if the health service has been modified since the
    /// last call to `changed` (or since construction) in a way that affects
    /// this watcher's service.
    pub fn changed(&mut self) -> bool {
        let (current_status, current_version) =
            self.service.watched_status_and_version(&self.service_name);
        let changed = current_version != self.last_version;
        self.last_status = current_status;
        self.last_version = current_version;
        changed
    }

    /// Returns the current status for the watched service.
    ///
    /// This returns the status snapshotted during the watcher's creation,
    /// or during the most recent call to `changed` or `poll_status`.
    /// Unregistered named services report [`ServingStatus::ServiceUnknown`],
    /// matching the gRPC health `Watch` contract.
    #[must_use]
    pub fn status(&self) -> ServingStatus {
        self.last_status
    }

    /// Returns a single-read snapshot: `(changed, current_status)`.
    pub fn poll_status(&mut self) -> (bool, ServingStatus) {
        let (current_status, current_version) =
            self.service.watched_status_and_version(&self.service_name);
        let changed = current_version != self.last_version;
        self.last_status = current_status;
        self.last_version = current_version;
        (changed, current_status)
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
        let service_name = service_name.into();
        service.acquire_reporter(&service_name);
        Self {
            service,
            service_name,
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
        self.service
            .release_reporter_and_maybe_clear_status(&self.service_name);
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
    fn health_version_only_tracks_real_changes() {
        init_test("health_version_only_tracks_real_changes");
        let service = HealthService::new();

        let v0 = service.version();
        service.clear();
        crate::assert_with_log!(
            service.version() == v0,
            "clear empty is no-op",
            v0,
            service.version()
        );
        service.clear_status("missing");
        crate::assert_with_log!(
            service.version() == v0,
            "clear missing is no-op",
            v0,
            service.version()
        );

        service.set_status("svc", ServingStatus::Serving);
        let v1 = service.version();
        crate::assert_with_log!(v1 > v0, "initial set increments", true, v1 > v0);

        service.set_status("svc", ServingStatus::Serving);
        crate::assert_with_log!(
            service.version() == v1,
            "idempotent set does not increment",
            v1,
            service.version()
        );

        service.set_status("svc", ServingStatus::NotServing);
        crate::assert_with_log!(
            service.version() > v1,
            "real status transition increments",
            true,
            service.version() > v1
        );
        crate::test_complete!("health_version_only_tracks_real_changes");
    }

    #[test]
    fn health_watcher_ignores_unrelated_service_changes() {
        init_test("health_watcher_ignores_unrelated_service_changes");
        let service = HealthService::new();
        service.set_status("a", ServingStatus::Serving);
        service.set_status("b", ServingStatus::Serving);

        let mut watcher_a = service.watch("a");
        let mut watcher_b = service.watch("b");

        service.set_status("a", ServingStatus::NotServing);

        let changed_a = watcher_a.changed();
        crate::assert_with_log!(changed_a, "watcher a sees change", true, changed_a);

        let changed_b = watcher_b.changed();
        crate::assert_with_log!(
            !changed_b,
            "watcher b ignores unrelated change",
            false,
            changed_b
        );
        crate::assert_with_log!(
            watcher_b.status() == ServingStatus::Serving,
            "watcher b status unchanged",
            ServingStatus::Serving,
            watcher_b.status()
        );
        crate::test_complete!("health_watcher_ignores_unrelated_service_changes");
    }

    #[test]
    fn health_watcher_unknown_service_reports_service_unknown() {
        init_test("health_watcher_unknown_service_reports_service_unknown");
        let service = HealthService::new();
        let mut watcher = service.watch("missing");

        crate::assert_with_log!(
            watcher.status() == ServingStatus::ServiceUnknown,
            "unknown service reports watch sentinel",
            ServingStatus::ServiceUnknown,
            watcher.status()
        );
        let (changed, status) = watcher.poll_status();
        crate::assert_with_log!(!changed, "initial unknown poll is stable", false, changed);
        crate::assert_with_log!(
            status == ServingStatus::ServiceUnknown,
            "poll_status reports service unknown",
            ServingStatus::ServiceUnknown,
            status
        );

        service.set_status("missing", ServingStatus::Serving);
        let (changed, status) = watcher.poll_status();
        crate::assert_with_log!(changed, "registration is observed", true, changed);
        crate::assert_with_log!(
            status == ServingStatus::Serving,
            "watcher sees serving after registration",
            ServingStatus::Serving,
            status
        );
        crate::test_complete!("health_watcher_unknown_service_reports_service_unknown");
    }

    #[test]
    fn health_watcher_reports_named_service_transient_round_trip() {
        init_test("health_watcher_reports_named_service_transient_round_trip");
        let service = HealthService::new();
        service.set_status("svc", ServingStatus::Serving);

        let mut changed_watcher = service.watch("svc");
        let mut poll_watcher = service.watch("svc");

        service.set_status("svc", ServingStatus::NotServing);
        service.set_status("svc", ServingStatus::Serving);

        let changed = changed_watcher.changed();
        crate::assert_with_log!(
            changed,
            "changed() observes transient round trip",
            true,
            changed
        );
        crate::assert_with_log!(
            changed_watcher.status() == ServingStatus::Serving,
            "effective status returns to serving",
            ServingStatus::Serving,
            changed_watcher.status()
        );

        let (poll_changed, polled_status) = poll_watcher.poll_status();
        crate::assert_with_log!(
            poll_changed,
            "poll_status observes transient round trip",
            true,
            poll_changed
        );
        crate::assert_with_log!(
            polled_status == ServingStatus::Serving,
            "poll_status reports current effective status",
            ServingStatus::Serving,
            polled_status
        );
        crate::test_complete!("health_watcher_reports_named_service_transient_round_trip");
    }

    #[test]
    fn health_watcher_reports_server_transient_round_trip() {
        init_test("health_watcher_reports_server_transient_round_trip");
        let service = HealthService::new();
        service.set_status("svc", ServingStatus::Serving);

        let mut watcher = service.watch("");

        service.set_status("svc", ServingStatus::NotServing);
        service.set_status("svc", ServingStatus::Serving);

        let (changed, status) = watcher.poll_status();
        crate::assert_with_log!(
            changed,
            "server watcher observes aggregate transient round trip",
            true,
            changed
        );
        crate::assert_with_log!(
            status == ServingStatus::Serving,
            "server watcher reports recovered aggregate status",
            ServingStatus::Serving,
            status
        );
        crate::test_complete!("health_watcher_reports_server_transient_round_trip");
    }

    #[test]
    fn health_service_services() {
        init_test("health_service_services");
        let service = HealthService::new();
        service.set_status("b", ServingStatus::NotServing);
        service.set_status("a", ServingStatus::Serving);

        let services = service.services();
        crate::assert_with_log!(
            services == vec!["a".to_string(), "b".to_string()],
            "services are returned in deterministic sorted order",
            vec!["a".to_string(), "b".to_string()],
            services
        );
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
    fn health_reporter_only_final_drop_clears_shared_service_status() {
        init_test("health_reporter_only_final_drop_clears_shared_service_status");
        let service = HealthService::new();
        let reporter_a = HealthReporter::new(service.clone(), "shared.Service");
        let reporter_b = HealthReporter::new(service.clone(), "shared.Service");

        reporter_a.set_serving();
        let version_after_set = service.version();

        drop(reporter_a);
        crate::assert_with_log!(
            service.get_status("shared.Service") == Some(ServingStatus::Serving),
            "first drop preserves shared registration",
            Some(ServingStatus::Serving),
            service.get_status("shared.Service")
        );
        crate::assert_with_log!(
            service.version() == version_after_set,
            "non-final drop does not clear or bump version",
            version_after_set,
            service.version()
        );

        reporter_b.set_not_serving();
        crate::assert_with_log!(
            service.get_status("shared.Service") == Some(ServingStatus::NotServing),
            "remaining reporter still controls shared service state",
            Some(ServingStatus::NotServing),
            service.get_status("shared.Service")
        );

        drop(reporter_b);
        crate::assert_with_log!(
            service.get_status("shared.Service").is_none(),
            "final drop clears shared registration",
            true,
            service.get_status("shared.Service").is_none()
        );
        crate::test_complete!("health_reporter_only_final_drop_clears_shared_service_status");
    }

    #[test]
    fn health_reporter_final_drop_does_not_clear_replacement_reporter_status() {
        init_test("health_reporter_final_drop_does_not_clear_replacement_reporter_status");
        let service = HealthService::new();
        let reporter = HealthReporter::new(service.clone(), "race.Service");
        reporter.set_serving();
        let _reporter = std::mem::ManuallyDrop::new(reporter);

        let (attempt_tx, attempt_rx) = std::sync::mpsc::channel();
        let (created_tx, created_rx) = std::sync::mpsc::channel();
        let service_for_thread = service.clone();
        let handle = std::thread::spawn(move || {
            attempt_rx.recv().unwrap();
            let replacement = HealthReporter::new(service_for_thread.clone(), "race.Service");
            replacement.set_not_serving();
            created_tx.send(()).unwrap();
            replacement
        });

        service.release_reporter_and_maybe_clear_status_with_hook("race.Service", || {
            attempt_tx.send(()).unwrap();
            std::thread::yield_now();
        });

        created_rx.recv().unwrap();
        crate::assert_with_log!(
            service.get_status("race.Service") == Some(ServingStatus::NotServing),
            "replacement reporter survives final-drop clear window",
            Some(ServingStatus::NotServing),
            service.get_status("race.Service")
        );

        let replacement = handle.join().unwrap();
        drop(replacement);
        crate::assert_with_log!(
            service.get_status("race.Service").is_none(),
            "replacement final drop still clears registration",
            true,
            service.get_status("race.Service").is_none()
        );
        crate::test_complete!(
            "health_reporter_final_drop_does_not_clear_replacement_reporter_status"
        );
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

    // =========================================================================
    // Wave 45 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn serving_status_debug_clone_copy_eq_hash_default() {
        use std::collections::HashSet;

        let def = ServingStatus::default();
        assert_eq!(def, ServingStatus::Unknown);

        let statuses = [
            ServingStatus::Unknown,
            ServingStatus::Serving,
            ServingStatus::NotServing,
            ServingStatus::ServiceUnknown,
        ];
        for s in &statuses {
            let copied = *s;
            let cloned = *s;
            assert_eq!(copied, cloned);
            assert!(!format!("{s:?}").is_empty());
        }

        let mut set = HashSet::new();
        for s in &statuses {
            set.insert(*s);
        }
        assert_eq!(set.len(), 4);
        set.insert(ServingStatus::Serving);
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn health_check_request_debug_clone_default() {
        let def = HealthCheckRequest::default();
        assert!(def.service.is_empty());
        let dbg = format!("{def:?}");
        assert!(dbg.contains("HealthCheckRequest"), "{dbg}");
        let cloned = def;
        assert_eq!(cloned.service, "");
    }

    #[test]
    fn health_check_response_debug_clone_default() {
        let def = HealthCheckResponse::default();
        assert_eq!(def.status, ServingStatus::Unknown);
        let dbg = format!("{def:?}");
        assert!(dbg.contains("HealthCheckResponse"), "{dbg}");
        let resp = HealthCheckResponse::new(ServingStatus::Serving);
        let cloned = resp;
        assert_eq!(cloned.status, ServingStatus::Serving);
    }
}
