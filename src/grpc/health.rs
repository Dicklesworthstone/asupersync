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
#[path = "health_inline_tests.rs"]
mod tests;
