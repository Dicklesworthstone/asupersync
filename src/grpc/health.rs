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

use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

use super::service::{NamedService, ServiceDescriptor, ServiceHandler};
use super::status::Status;
use super::streaming::{Metadata, Request, Response, Streaming};

/// Maximum permitted byte length of a gRPC service name passed to
/// [`HealthService::set_status`] / [`HealthService::try_set_status`].
///
/// gRPC service names are dot-separated identifiers (`package.Service`)
/// and are conventionally short. The cap defends against unbounded
/// memory growth from attacker-controlled callers and matches the
/// 256-byte limit used by other production gRPC servers.
/// (br-asupersync-sdljgj)
pub const MAX_SERVICE_NAME_LEN: usize = 256;

/// Errors returned by the health service registration API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthError {
    /// The provided service name exceeds [`MAX_SERVICE_NAME_LEN`].
    ServiceNameTooLong {
        /// The actual byte length of the rejected name.
        len: usize,
        /// The cap that was exceeded.
        max: usize,
    },
}

impl std::fmt::Display for HealthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServiceNameTooLong { len, max } => write!(
                f,
                "gRPC health: service name too long ({len} bytes, max {max})"
            ),
        }
    }
}

impl std::error::Error for HealthError {}

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
#[derive(Debug, Clone, Default)]
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

/// Validator for transport-level gRPC health authentication.
pub trait HealthAuthValidator: Send + Sync {
    /// Validate request metadata for the named RPC method.
    fn validate(&self, metadata: &Metadata, method: &str) -> Result<(), Status>;
}

impl<F> HealthAuthValidator for F
where
    F: Fn(&Metadata, &str) -> Result<(), Status> + Send + Sync,
{
    fn validate(&self, metadata: &Metadata, method: &str) -> Result<(), Status> {
        self(metadata, method)
    }
}

/// Shared callback type for custom gRPC health authentication.
pub type HealthAuthCallback = Arc<dyn HealthAuthValidator>;

/// Transport-level authentication mode for gRPC health RPCs.
#[derive(Clone, Default)]
pub enum HealthAuthMode {
    /// Explicit opt-in to unauthenticated health checks.
    None,
    /// Fail closed until a concrete token or custom validator is configured.
    ///
    /// This variant is the default so RPC-facing health endpoints are not
    /// accidentally exposed. Use [`Self::bearer_token`] or [`Self::Custom`]
    /// for authenticated deployments.
    #[default]
    RequireAuth,
    /// Require an exact bearer token match.
    BearerToken(String),
    /// Delegate to a caller-provided validator.
    Custom(HealthAuthCallback),
}

impl HealthAuthMode {
    /// Require an exact bearer token for RPC-facing health endpoints.
    #[must_use]
    pub fn bearer_token(token: impl Into<String>) -> Self {
        Self::BearerToken(token.into())
    }
}

impl std::fmt::Debug for HealthAuthMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("HealthAuthMode::None"),
            Self::RequireAuth => f.write_str("HealthAuthMode::RequireAuth"),
            Self::BearerToken(_) => f.write_str("HealthAuthMode::BearerToken(<redacted>)"),
            Self::Custom(_) => f.write_str("HealthAuthMode::Custom(<validator>)"),
        }
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    let max_len = left.len().max(right.len());
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(left_byte ^ right_byte);
    }
    diff == 0
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
    /// Pending async watch waiters keyed by watched service name.
    watch_waiters: Arc<Mutex<HashMap<String, HashMap<u64, Waker>>>>,
    /// Monotonic waiter identifier source.
    next_waiter_id: Arc<AtomicU64>,
    /// Monotonic version counter, bumped on every status change.
    version: Arc<AtomicU64>,
    /// Transport auth mode for async gRPC health entrypoints.
    auth_mode: HealthAuthMode,
}

impl HealthService {
    /// Create a new health service.
    #[must_use]
    pub fn new() -> Self {
        Self {
            statuses: Arc::new(RwLock::new(HashMap::new())),
            watch_versions: Arc::new(RwLock::new(HashMap::new())),
            reporter_counts: Arc::new(RwLock::new(HashMap::new())),
            watch_waiters: Arc::new(Mutex::new(HashMap::new())),
            next_waiter_id: Arc::new(AtomicU64::new(1)),
            version: Arc::new(AtomicU64::new(0)),
            auth_mode: HealthAuthMode::RequireAuth,
        }
    }

    /// Create a health service with an explicit transport auth mode.
    #[must_use]
    pub fn with_auth_mode(auth_mode: HealthAuthMode) -> Self {
        Self {
            auth_mode,
            ..Self::new()
        }
    }

    /// Returns the current version counter. Bumped on every status change.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// Extract required bearer authentication metadata from a gRPC request.
    fn bearer_token_from_metadata(metadata: &Metadata) -> Result<&str, Status> {
        let auth_header = metadata.get("authorization").ok_or_else(|| {
            Status::unauthenticated("health check endpoint requires authentication")
        })?;

        // Extract string value from MetadataValue enum
        let auth_str = match auth_header {
            super::streaming::MetadataValue::Ascii(s) => s.as_str(),
            super::streaming::MetadataValue::Binary(_) => {
                return Err(Status::unauthenticated(
                    "authorization header must be ASCII",
                ));
            }
        };

        // Basic validation: must be non-empty and follow Bearer token pattern
        if auth_str.is_empty() {
            return Err(Status::unauthenticated("empty authorization header"));
        }

        let Some(bearer_token) = auth_str.strip_prefix("Bearer ") else {
            return Err(Status::unauthenticated(
                "invalid authorization format - Bearer token required",
            ));
        };

        if bearer_token.is_empty() {
            return Err(Status::unauthenticated("empty bearer token"));
        }

        Ok(bearer_token)
    }

    /// Validate required bearer authentication metadata from a gRPC request.
    fn validate_bearer_token_metadata(
        metadata: &Metadata,
        expected_token: &str,
    ) -> Result<(), Status> {
        if expected_token.is_empty() {
            return Err(Status::unauthenticated(
                "health check bearer token is not configured",
            ));
        }

        let bearer_token = Self::bearer_token_from_metadata(metadata)?;
        if constant_time_eq(bearer_token.as_bytes(), expected_token.as_bytes()) {
            Ok(())
        } else {
            Err(Status::unauthenticated("invalid bearer token"))
        }
    }

    /// Validate transport authentication for a health RPC.
    fn validate_auth_metadata(&self, metadata: &Metadata, method: &str) -> Result<(), Status> {
        match &self.auth_mode {
            HealthAuthMode::None => {
                crate::tracing_compat::warn!(
                    method,
                    auth_mode = "None",
                    metadata_count = metadata.len(),
                    "gRPC health authentication disabled"
                );
                Ok(())
            }
            HealthAuthMode::RequireAuth => Err(Status::unauthenticated(
                "health check endpoint requires configured authentication",
            )),
            HealthAuthMode::BearerToken(expected_token) => {
                Self::validate_bearer_token_metadata(metadata, expected_token)?;
                crate::tracing_compat::debug!(
                    method,
                    auth_mode = "BearerToken",
                    metadata_count = metadata.len(),
                    "gRPC health authentication accepted"
                );
                Ok(())
            }
            HealthAuthMode::Custom(validator) => {
                validator.validate(metadata, method)?;
                crate::tracing_compat::debug!(
                    method,
                    auth_mode = "Custom",
                    metadata_count = metadata.len(),
                    "gRPC health custom authentication accepted"
                );
                Ok(())
            }
        }
    }

    /// Set the status of a service.
    ///
    /// Use an empty string for the overall server status. Names exceeding
    /// [`MAX_SERVICE_NAME_LEN`] are silently dropped with a `tracing::warn!`
    /// (br-asupersync-sdljgj). For callers that want to surface the
    /// rejection, use [`Self::try_set_status`] which returns a typed
    /// [`HealthError`].
    pub fn set_status(&self, service: impl Into<String>, status: ServingStatus) {
        if let Err(_err) = self.try_set_status(service, status) {
            crate::tracing_compat::warn!(
                error = %_err,
                "gRPC health: rejecting set_status call"
            );
        }
    }

    /// Set the status of a service, surfacing length-cap violations.
    ///
    /// Equivalent to [`Self::set_status`] but returns
    /// `Err(HealthError::ServiceNameTooLong)` if the name exceeds
    /// [`MAX_SERVICE_NAME_LEN`]. (br-asupersync-sdljgj)
    pub fn try_set_status(
        &self,
        service: impl Into<String>,
        status: ServingStatus,
    ) -> Result<(), HealthError> {
        let service = service.into();
        if service.len() > MAX_SERVICE_NAME_LEN {
            return Err(HealthError::ServiceNameTooLong {
                len: service.len(),
                max: MAX_SERVICE_NAME_LEN,
            });
        }
        let mut statuses = self.statuses.write();
        let changed = statuses.insert(service.clone(), status) != Some(status);
        if changed {
            // Bump version while still holding statuses lock so that
            // concurrent readers see a consistent (status, version) pair.
            self.bump_watch_version(&service);
            self.version.fetch_add(1, Ordering::Release);
        }
        drop(statuses);
        if changed {
            self.notify_watch_waiters(&service);
        }
        Ok(())
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
            self.bump_watch_versions(affected_services.iter().cloned());
            self.version.fetch_add(1, Ordering::Release);
        }
        drop(statuses);
        if changed {
            self.notify_watch_waiters_for_services(affected_services);
        }
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
        if changed {
            self.notify_watch_waiters(service);
        }
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
        drop(statuses);
        drop(reporter_counts);
        if changed {
            self.notify_watch_waiters(service);
        }
    }

    /// Handle a health check request.
    ///
    /// This direct in-process API does not inspect transport metadata.
    ///
    /// Use [`Self::check_async`] / [`Self::watch_async`] for RPC-facing
    /// entrypoints that enforce [`HealthAuthMode`].
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
            // Security fix (br-asupersync-doa4lv): Prevent service enumeration attacks
            // by using a generic error that doesn't reveal whether the service exists.
            // While the gRPC health spec suggests NotFound for missing services, this
            // enables enumeration attacks. Using PermissionDenied provides security
            // without revealing service topology to unauthorized clients.
            Err(Status::permission_denied("health check access denied"))
        }
    }

    /// Async check handler for use with gRPC server.
    #[must_use]
    pub fn check_async(
        &self,
        request: &Request<HealthCheckRequest>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<HealthCheckResponse>, Status>> + Send>> {
        let auth_result = self.validate_auth_metadata(request.metadata(), "Check");
        if let Err(error) = auth_result {
            return Box::pin(async move { Err(error) });
        }

        let result = self.check(request.get_ref());
        Box::pin(async move { result.map(Response::new) })
    }

    /// Async watch handler for use with server-streaming gRPC integrations.
    ///
    /// The returned stream emits the initial effective status immediately, then
    /// yields subsequent changes as they are published through the health service.
    #[must_use]
    pub fn watch_async(
        &self,
        request: &Request<HealthCheckRequest>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<HealthWatchStream>, Status>> + Send>> {
        let auth_result = self.validate_auth_metadata(request.metadata(), "Watch");
        if let Err(error) = auth_result {
            return Box::pin(async move { Err(error) });
        }

        let stream = HealthWatchStream::new(self.clone(), request.get_ref().service.clone());
        Box::pin(async move { Ok(Response::new(stream)) })
    }

    /// Create a watcher that can poll for status changes on a specific service.
    ///
    /// The watcher captures the current status snapshot for that service;
    /// subsequent calls to [`HealthWatcher::changed`] return `true` only when
    /// the watched service's effective status changes.
    #[must_use]
    pub fn watch(&self, service: impl Into<String>) -> HealthWatcher {
        let service_name = service.into();
        let (last_status, last_version) = self.watched_status_and_version(&service_name);
        HealthWatcher {
            service: self.clone(),
            last_status,
            last_version,
            service_name,
        }
    }

    fn register_watch_waiter(&self, service: &str, waiter_id: &mut Option<u64>, waker: &Waker) {
        let id =
            *waiter_id.get_or_insert_with(|| self.next_waiter_id.fetch_add(1, Ordering::Relaxed));
        let mut waiters = self.watch_waiters.lock();
        waiters
            .entry(service.to_string())
            .or_default()
            .insert(id, waker.clone());
    }

    fn unregister_watch_waiter(&self, service: &str, waiter_id: &mut Option<u64>) {
        let Some(id) = waiter_id.take() else {
            return;
        };
        let mut waiters = self.watch_waiters.lock();
        let remove_service_entry = waiters.get_mut(service).is_some_and(|service_waiters| {
            service_waiters.remove(&id);
            service_waiters.is_empty()
        });
        if remove_service_entry {
            waiters.remove(service);
        }
    }

    fn notify_watch_waiters(&self, service: &str) {
        self.notify_watch_waiters_for_services(std::iter::once(service.to_string()));
    }

    fn notify_watch_waiters_for_services<I>(&self, services: I)
    where
        I: IntoIterator<Item = String>,
    {
        let mut keys = Vec::new();
        for service in services {
            if !keys.iter().any(|existing| existing == &service) {
                keys.push(service.clone());
            }
            if !service.is_empty() && !keys.iter().any(|existing| existing.is_empty()) {
                keys.push(String::new());
            }
        }
        if keys.is_empty() {
            return;
        }

        let mut waiters = self.watch_waiters.lock();
        let mut wake_list = Vec::new();
        for key in keys {
            if let Some(service_waiters) = waiters.get_mut(&key) {
                wake_list.extend(service_waiters.values().cloned());
            }
        }
        drop(waiters);

        for waker in wake_list {
            waker.wake();
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

/// Async health watch stream suitable for server-streaming gRPC handlers.
#[derive(Debug)]
pub struct HealthWatchStream {
    watcher: HealthWatcher,
    emitted_initial: bool,
    waiter_id: Option<u64>,
}

impl HealthWatchStream {
    fn new(service: HealthService, service_name: String) -> Self {
        Self {
            watcher: service.watch(service_name),
            emitted_initial: false,
            waiter_id: None,
        }
    }

    fn clear_waiter_registration(&mut self) {
        self.watcher
            .service
            .unregister_watch_waiter(&self.watcher.service_name, &mut self.waiter_id);
    }

    fn poll_next_with_hook<F>(
        &mut self,
        cx: &mut Context<'_>,
        after_first_status_check: F,
    ) -> Poll<Option<Result<HealthCheckResponse, Status>>>
    where
        F: FnOnce(&mut Self),
    {
        if !self.emitted_initial {
            self.emitted_initial = true;
            self.clear_waiter_registration();
            return Poll::Ready(Some(Ok(HealthCheckResponse::new(self.watcher.status()))));
        }

        let (changed, status) = self.watcher.poll_status();
        if changed {
            self.clear_waiter_registration();
            return Poll::Ready(Some(Ok(HealthCheckResponse::new(status))));
        }

        after_first_status_check(self);

        let service_name = self.watcher.service_name.clone();
        self.watcher
            .service
            .register_watch_waiter(&service_name, &mut self.waiter_id, cx.waker());

        // Re-check after registration to avoid losing a transition that lands
        // after the first status read but before the waiter becomes visible.
        let (changed, status) = self.watcher.poll_status();
        if changed {
            self.clear_waiter_registration();
            return Poll::Ready(Some(Ok(HealthCheckResponse::new(status))));
        }

        Poll::Pending
    }
}

impl Drop for HealthWatchStream {
    fn drop(&mut self) {
        self.clear_waiter_registration();
    }
}

impl Streaming for HealthWatchStream {
    type Message = HealthCheckResponse;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Message, Status>>> {
        self.as_mut().get_mut().poll_next_with_hook(cx, |_| {})
    }
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
    auth_mode: HealthAuthMode,
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

    /// Configure transport auth mode for async health RPC entrypoints.
    #[must_use]
    pub fn auth_mode(mut self, auth_mode: HealthAuthMode) -> Self {
        self.auth_mode = auth_mode;
        self
    }

    /// Build the health service.
    #[must_use]
    pub fn build(self) -> HealthService {
        let service = HealthService::with_auth_mode(self.auth_mode);
        for (name, status) in self.statuses {
            service.set_status(name, status);
        }
        service
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
    use serde_json::json;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn health_response_snapshot(service: &HealthService, query: &str) -> serde_json::Value {
        let request = if query.is_empty() {
            HealthCheckRequest::server()
        } else {
            HealthCheckRequest::new(query)
        };
        let response = service
            .check(&request)
            .expect("health snapshot queries should succeed");

        json!({
            "query": request.service,
            "status_code": response.status as i32,
            "status_text": response.status.to_string(),
        })
    }

    #[derive(Default)]
    struct CountingWake {
        wakes: AtomicUsize,
    }

    impl Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counting_waker(counter: &Arc<CountingWake>) -> Waker {
        Waker::from(counter.clone())
    }

    fn authed_health_request(service: &str) -> Request<HealthCheckRequest> {
        let mut request = Request::new(HealthCheckRequest::new(service));
        let inserted = request
            .metadata_mut()
            .insert("authorization", "Bearer test-token");
        crate::assert_with_log!(inserted, "test auth metadata inserted", true, inserted);
        request
    }

    fn bearer_token_health_service() -> HealthService {
        HealthService::with_auth_mode(HealthAuthMode::bearer_token("test-token"))
    }

    fn health_auth_token_request(
        service: &str,
        key: &str,
        value: &str,
    ) -> Request<HealthCheckRequest> {
        let mut request = Request::new(HealthCheckRequest::new(service));
        let inserted = request.metadata_mut().insert(key, value);
        crate::assert_with_log!(inserted, "test auth metadata inserted", true, inserted);
        request
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
            code == super::super::status::Code::PermissionDenied,
            "unknown service is hidden from enumeration",
            super::super::status::Code::PermissionDenied,
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
    fn health_check_response_statuses_snapshot() {
        init_test("health_check_response_statuses_snapshot");
        let service = HealthService::new();
        service.set_server_status(ServingStatus::Unknown);
        service.set_status("svc.serving", ServingStatus::Serving);
        service.set_status("svc.not_serving", ServingStatus::NotServing);
        service.set_status("svc.unknown", ServingStatus::Unknown);

        let snapshot = json!({
            "server": health_response_snapshot(&service, ""),
            "service_queries": [
                health_response_snapshot(&service, "svc.serving"),
                health_response_snapshot(&service, "svc.not_serving"),
                health_response_snapshot(&service, "svc.unknown"),
            ],
        });

        assert_json_snapshot!("health_check_response_statuses", snapshot);
        crate::test_complete!("health_check_response_statuses_snapshot");
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
    fn health_auth_mode_default_requires_auth_for_async_endpoints() {
        init_test("health_auth_mode_default_requires_auth_for_async_endpoints");
        let service = HealthService::new();
        service.set_status("svc", ServingStatus::Serving);

        let request = Request::new(HealthCheckRequest::new("svc"));
        let check_err = futures_lite::future::block_on(service.check_async(&request))
            .expect_err("default auth mode must reject unauthenticated Check");
        let watch_err = futures_lite::future::block_on(service.watch_async(&request))
            .expect_err("default auth mode must reject unauthenticated Watch");

        crate::assert_with_log!(
            check_err.code() == super::super::status::Code::Unauthenticated,
            "default check code",
            super::super::status::Code::Unauthenticated,
            check_err.code()
        );
        crate::assert_with_log!(
            watch_err.code() == super::super::status::Code::Unauthenticated,
            "default watch code",
            super::super::status::Code::Unauthenticated,
            watch_err.code()
        );
        crate::assert_with_log!(
            check_err.message() == "health check endpoint requires configured authentication",
            "default check message",
            "health check endpoint requires configured authentication",
            check_err.message()
        );
        crate::assert_with_log!(
            watch_err.message() == "health check endpoint requires configured authentication",
            "default watch message",
            "health check endpoint requires configured authentication",
            watch_err.message()
        );

        let arbitrary_bearer = authed_health_request("svc");
        let token_err = futures_lite::future::block_on(service.check_async(&arbitrary_bearer))
            .expect_err("default RequireAuth must not accept arbitrary bearer tokens");
        crate::assert_with_log!(
            token_err.message() == "health check endpoint requires configured authentication",
            "default arbitrary bearer message",
            "health check endpoint requires configured authentication",
            token_err.message()
        );
        crate::test_complete!("health_auth_mode_default_requires_auth_for_async_endpoints");
    }

    #[test]
    fn health_auth_mode_bearer_token_requires_exact_secret() {
        init_test("health_auth_mode_bearer_token_requires_exact_secret");
        let service = bearer_token_health_service();
        service.set_status("svc", ServingStatus::Serving);

        let allowed = authed_health_request("svc");
        let check = futures_lite::future::block_on(service.check_async(&allowed))
            .expect("configured bearer token must allow Check");
        let allowed_status = check.into_inner().status;
        crate::assert_with_log!(
            allowed_status == ServingStatus::Serving,
            "configured bearer token check status",
            ServingStatus::Serving,
            allowed_status
        );

        let wrong = health_auth_token_request("svc", "authorization", "Bearer wrong-token");
        let err = futures_lite::future::block_on(service.watch_async(&wrong))
            .expect_err("wrong bearer token must fail closed");
        crate::assert_with_log!(
            err.message() == "invalid bearer token",
            "wrong bearer token rejected",
            "invalid bearer token",
            err.message()
        );
        crate::test_complete!("health_auth_mode_bearer_token_requires_exact_secret");
    }

    #[test]
    fn health_auth_mode_none_allows_async_check_and_watch_without_metadata() {
        init_test("health_auth_mode_none_allows_async_check_and_watch_without_metadata");
        let service = HealthService::with_auth_mode(HealthAuthMode::None);
        service.set_status("svc", ServingStatus::Serving);

        let request = Request::new(HealthCheckRequest::new("svc"));
        let check = futures_lite::future::block_on(service.check_async(&request))
            .expect("auth mode None must allow Check without metadata");
        let check_status = check.into_inner().status;
        crate::assert_with_log!(
            check_status == ServingStatus::Serving,
            "none auth check status",
            ServingStatus::Serving,
            check_status
        );

        let response = futures_lite::future::block_on(service.watch_async(&request))
            .expect("auth mode None must allow Watch without metadata");
        let mut stream = response.into_inner();
        let first = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        let first_ok = matches!(
            first,
            Some(Ok(HealthCheckResponse {
                status: ServingStatus::Serving
            }))
        );
        crate::assert_with_log!(
            first_ok,
            "none auth watch first item",
            true,
            format!("{first:?}")
        );
        crate::test_complete!(
            "health_auth_mode_none_allows_async_check_and_watch_without_metadata"
        );
    }

    #[test]
    fn health_auth_mode_custom_validator_controls_check_and_watch() {
        init_test("health_auth_mode_custom_validator_controls_check_and_watch");
        let validator_calls = Arc::new(AtomicUsize::new(0));
        let validator_calls_for_closure = Arc::clone(&validator_calls);
        let service = HealthService::with_auth_mode(HealthAuthMode::Custom(Arc::new(
            move |metadata: &Metadata, method: &str| {
                validator_calls_for_closure.fetch_add(1, Ordering::SeqCst);
                let Some(super::super::streaming::MetadataValue::Ascii(token)) =
                    metadata.get("x-health-token")
                else {
                    return Err(Status::permission_denied(format!("{method} denied")));
                };
                if token == "allow" {
                    Ok(())
                } else {
                    Err(Status::permission_denied(format!("{method} denied")))
                }
            },
        )));
        service.set_status("svc", ServingStatus::Serving);

        let allowed = health_auth_token_request("svc", "x-health-token", "allow");
        let check = futures_lite::future::block_on(service.check_async(&allowed))
            .expect("custom validator must allow matching Check metadata");
        let check_status = check.into_inner().status;
        crate::assert_with_log!(
            check_status == ServingStatus::Serving,
            "custom auth check status",
            ServingStatus::Serving,
            check_status
        );

        let denied = health_auth_token_request("svc", "x-health-token", "deny");
        let watch_err = futures_lite::future::block_on(service.watch_async(&denied))
            .expect_err("custom validator must reject denied Watch metadata");
        crate::assert_with_log!(
            watch_err.code() == super::super::status::Code::PermissionDenied,
            "custom watch code",
            super::super::status::Code::PermissionDenied,
            watch_err.code()
        );
        crate::assert_with_log!(
            watch_err.message() == "Watch denied",
            "custom watch message",
            "Watch denied",
            watch_err.message()
        );
        crate::assert_with_log!(
            validator_calls.load(Ordering::SeqCst) == 2,
            "custom validator called once per async endpoint",
            2,
            validator_calls.load(Ordering::SeqCst)
        );
        crate::test_complete!("health_auth_mode_custom_validator_controls_check_and_watch");
    }

    #[test]
    fn health_auth_mode_builder_propagates_configured_mode() {
        init_test("health_auth_mode_builder_propagates_configured_mode");
        let service = HealthServiceBuilder::new()
            .auth_mode(HealthAuthMode::None)
            .add("svc", ServingStatus::Serving)
            .build();

        let request = Request::new(HealthCheckRequest::new("svc"));
        let check = futures_lite::future::block_on(service.check_async(&request))
            .expect("builder auth mode None must allow Check without metadata");
        let check_status = check.into_inner().status;
        crate::assert_with_log!(
            check_status == ServingStatus::Serving,
            "builder none auth check status",
            ServingStatus::Serving,
            check_status
        );
        crate::test_complete!("health_auth_mode_builder_propagates_configured_mode");
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
    fn health_watch_initial_snapshot_is_atomic_for_named_services() {
        init_test("health_watch_initial_snapshot_is_atomic_for_named_services");
        let service = HealthService::new();
        service.set_status("svc", ServingStatus::Serving);

        let version_guard = service.watch_versions.write();
        let watch_service = service.clone();
        let (watcher_tx, watcher_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let watcher = watch_service.watch("svc");
            watcher_tx.send(watcher).unwrap();
        });

        let mut status_lock_held = false;
        for _ in 0..10_000 {
            if service.statuses.try_write().is_none() {
                status_lock_held = true;
                break;
            }
            std::thread::yield_now();
        }

        crate::assert_with_log!(
            status_lock_held,
            "watch constructor must hold statuses lock until version snapshot completes",
            true,
            status_lock_held
        );

        drop(version_guard);
        let mut watcher = watcher_rx.recv().unwrap();
        handle.join().unwrap();

        crate::assert_with_log!(
            watcher.status() == ServingStatus::Serving,
            "initial status snapshot preserved",
            ServingStatus::Serving,
            watcher.status()
        );

        service.set_status("svc", ServingStatus::NotServing);
        let changed = watcher.changed();
        crate::assert_with_log!(
            changed,
            "watcher still observes later transition",
            true,
            changed
        );
        crate::assert_with_log!(
            watcher.status() == ServingStatus::NotServing,
            "watcher reports new status after transition",
            ServingStatus::NotServing,
            watcher.status()
        );
        crate::test_complete!("health_watch_initial_snapshot_is_atomic_for_named_services");
    }

    #[test]
    fn health_watch_async_emits_initial_status_and_wakes_on_change() {
        init_test("health_watch_async_emits_initial_status_and_wakes_on_change");
        let service = bearer_token_health_service();
        service.set_status("svc", ServingStatus::Serving);

        let request = authed_health_request("svc");
        let response = futures_lite::future::block_on(service.watch_async(&request))
            .expect("watch_async should construct a stream");
        let mut stream = response.into_inner();

        let first = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        let first_ok = matches!(
            first,
            Some(Ok(HealthCheckResponse {
                status: ServingStatus::Serving
            }))
        );
        crate::assert_with_log!(
            first_ok,
            "initial watch snapshot is emitted immediately",
            true,
            first_ok
        );

        let wake_counter = Arc::new(CountingWake::default());
        let waker = counting_waker(&wake_counter);
        let mut cx = Context::from_waker(&waker);
        let pending = matches!(
            Streaming::poll_next(Pin::new(&mut stream), &mut cx),
            Poll::Pending
        );
        crate::assert_with_log!(
            pending,
            "stream waits for the next health transition",
            true,
            pending
        );

        service.set_status("svc", ServingStatus::NotServing);
        crate::assert_with_log!(
            wake_counter.wakes.load(Ordering::SeqCst) == 1,
            "status change wakes pending async watch",
            1,
            wake_counter.wakes.load(Ordering::SeqCst)
        );

        let next = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        let next_ok = matches!(
            next,
            Some(Ok(HealthCheckResponse {
                status: ServingStatus::NotServing
            }))
        );
        crate::assert_with_log!(
            next_ok,
            "watch stream emits changed status after wake",
            true,
            next_ok
        );
        crate::test_complete!("health_watch_async_emits_initial_status_and_wakes_on_change");
    }

    /// GRPC-DIFF-HWATCH-HALFCLOSE: grpc-go keeps Health/Watch open after the
    /// client sends its single request message and half-closes the send side.
    /// The server stream must stay pending for future updates instead of
    /// terminating when no more client request bytes can arrive.
    #[test]
    fn differential_health_watch_send_half_close_semantics_vs_grpc_go() {
        init_test("differential_health_watch_send_half_close_semantics_vs_grpc_go");
        let service = bearer_token_health_service();
        service.set_status("svc", ServingStatus::Serving);

        let request = authed_health_request("svc");
        let response = futures_lite::future::block_on(service.watch_async(&request))
            .expect("watch_async should construct a stream");
        drop(request);
        let mut stream = response.into_inner();

        let first = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        let first_ok = matches!(
            first,
            Some(Ok(HealthCheckResponse {
                status: ServingStatus::Serving
            }))
        );
        crate::assert_with_log!(
            first_ok,
            "grpc-go: initial watch snapshot is emitted before half-close matters",
            true,
            first_ok
        );

        let wake_counter = Arc::new(CountingWake::default());
        let waker = counting_waker(&wake_counter);
        let mut cx = Context::from_waker(&waker);
        let pending_after_half_close = matches!(
            Streaming::poll_next(Pin::new(&mut stream), &mut cx),
            Poll::Pending
        );
        crate::assert_with_log!(
            pending_after_half_close,
            "grpc-go: send-half-close must not terminate Health/Watch",
            true,
            pending_after_half_close
        );

        let waiter_count = service
            .watch_waiters
            .lock()
            .get("svc")
            .map_or(0, std::collections::HashMap::len);
        crate::assert_with_log!(
            waiter_count == 1,
            "grpc-go: pending Watch keeps exactly one waiter after half-close",
            1,
            waiter_count
        );

        service.set_status("svc", ServingStatus::NotServing);
        crate::assert_with_log!(
            wake_counter.wakes.load(Ordering::SeqCst) == 1,
            "grpc-go: status transition wakes half-closed watch",
            1,
            wake_counter.wakes.load(Ordering::SeqCst)
        );

        let next = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        let next_ok = matches!(
            next,
            Some(Ok(HealthCheckResponse {
                status: ServingStatus::NotServing
            }))
        );
        crate::assert_with_log!(
            next_ok,
            "grpc-go: half-closed watch still emits later status changes",
            true,
            next_ok
        );

        crate::test_complete!("differential_health_watch_send_half_close_semantics_vs_grpc_go");
    }

    #[test]
    fn health_watch_async_missing_auth_matches_check_async_and_registers_no_waiter() {
        init_test("health_watch_async_missing_auth_matches_check_async_and_registers_no_waiter");
        let service = HealthService::new();
        service.set_status("svc", ServingStatus::Serving);

        let request = Request::new(HealthCheckRequest::new("svc"));

        let check_err = futures_lite::future::block_on(service.check_async(&request))
            .expect_err("grpc-health-probe style Check must fail closed without auth");
        let watch_err = futures_lite::future::block_on(service.watch_async(&request))
            .expect_err("Watch must enforce the same auth gate before constructing a stream");

        crate::assert_with_log!(
            watch_err.code() == check_err.code(),
            "watch auth code matches check auth code",
            check_err.code(),
            watch_err.code()
        );
        crate::assert_with_log!(
            watch_err.message() == check_err.message(),
            "watch auth message matches check auth message",
            check_err.message(),
            watch_err.message()
        );

        let waiter_count = service
            .watch_waiters
            .lock()
            .get("svc")
            .map_or(0, std::collections::HashMap::len);
        crate::assert_with_log!(
            waiter_count == 0,
            "unauthenticated watch must not register any streaming waiter state",
            0,
            waiter_count
        );
        crate::test_complete!(
            "health_watch_async_missing_auth_matches_check_async_and_registers_no_waiter"
        );
    }

    #[test]
    fn health_check_async_rejects_empty_bearer_token() {
        init_test("health_check_async_rejects_empty_bearer_token");
        let service = bearer_token_health_service();
        service.set_status("svc", ServingStatus::Serving);

        let mut request = Request::new(HealthCheckRequest::new("svc"));
        let inserted = request.metadata_mut().insert("authorization", "Bearer ");
        crate::assert_with_log!(inserted, "empty bearer metadata inserted", true, inserted);

        let err = futures_lite::future::block_on(service.check_async(&request))
            .expect_err("empty bearer tokens must fail closed");
        crate::assert_with_log!(
            err.message() == "empty bearer token",
            "empty bearer token rejected",
            "empty bearer token",
            err.message()
        );
        crate::test_complete!("health_check_async_rejects_empty_bearer_token");
    }

    #[test]
    fn health_watch_async_drop_unregisters_pending_waiter() {
        init_test("health_watch_async_drop_unregisters_pending_waiter");
        let service = bearer_token_health_service();
        service.set_status("svc", ServingStatus::Serving);

        let request = authed_health_request("svc");
        let response = futures_lite::future::block_on(service.watch_async(&request))
            .expect("watch_async should construct a stream");
        let mut stream = response.into_inner();

        let _ = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));

        let wake_counter = Arc::new(CountingWake::default());
        let waker = counting_waker(&wake_counter);
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(
            Streaming::poll_next(Pin::new(&mut stream), &mut cx),
            Poll::Pending
        ));

        let waiter_count_before_drop = service
            .watch_waiters
            .lock()
            .get("svc")
            .map_or(0, std::collections::HashMap::len);
        crate::assert_with_log!(
            waiter_count_before_drop == 1,
            "pending watch registers exactly one waiter",
            1,
            waiter_count_before_drop
        );

        drop(stream);

        let waiter_count_after_drop = service
            .watch_waiters
            .lock()
            .get("svc")
            .map_or(0, std::collections::HashMap::len);
        crate::assert_with_log!(
            waiter_count_after_drop == 0,
            "dropping a pending watch unregisters waiter state",
            0,
            waiter_count_after_drop
        );
        crate::test_complete!("health_watch_async_drop_unregisters_pending_waiter");
    }

    #[test]
    fn health_watch_async_rechecks_after_waiter_registration() {
        init_test("health_watch_async_rechecks_after_waiter_registration");
        let service = bearer_token_health_service();
        service.set_status("svc", ServingStatus::Serving);

        let request = authed_health_request("svc");
        let response = futures_lite::future::block_on(service.watch_async(&request))
            .expect("watch_async should construct a stream");
        let mut stream = response.into_inner();

        let _ = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));

        let wake_counter = Arc::new(CountingWake::default());
        let waker = counting_waker(&wake_counter);
        let mut cx = Context::from_waker(&waker);

        let poll = stream.poll_next_with_hook(&mut cx, |stream| {
            stream
                .watcher
                .service
                .set_status("svc", ServingStatus::NotServing);
        });

        let changed = matches!(
            poll,
            Poll::Ready(Some(Ok(HealthCheckResponse {
                status: ServingStatus::NotServing
            })))
        );
        crate::assert_with_log!(
            changed,
            "watch stream must not miss transition between status check and waiter registration",
            true,
            format!("{poll:?}")
        );

        let waiter_count = service
            .watch_waiters
            .lock()
            .get("svc")
            .map_or(0, std::collections::HashMap::len);
        crate::assert_with_log!(
            waiter_count == 0,
            "caught transition clears waiter registration instead of parking forever",
            0,
            waiter_count
        );
        crate::assert_with_log!(
            wake_counter.wakes.load(Ordering::SeqCst) == 0,
            "recheck path resolves inline without depending on an out-of-band wake",
            0,
            wake_counter.wakes.load(Ordering::SeqCst)
        );

        crate::test_complete!("health_watch_async_rechecks_after_waiter_registration");
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
