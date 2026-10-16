//! Health check endpoints for Kubernetes-style probes.
//!
//! Provides configurable health check handlers that implement the common
//! liveness, readiness, and startup probe patterns used by container
//! orchestrators.
//!
//! # Probe Types
//!
//! | Probe | Purpose | Typical Path |
//! |-------|---------|-------------|
//! | Liveness | Is the process alive? | `/healthz` |
//! | Readiness | Can it serve traffic? | `/readyz` |
//! | Startup | Has it finished starting? | `/startupz` |
//!
//! # Example
//!
//! ```
//! use asupersync::web::health::{HealthCheck, HealthStatus};
//! use asupersync::web::{Router, get};
//!
//! let health = HealthCheck::new()
//!     .check("database", || HealthStatus::Healthy)
//!     .check("cache", || HealthStatus::Degraded("high latency".into()));
//!
//! let app = Router::new()
//!     .route("/healthz", get(health.liveness_handler()))
//!     .route("/readyz", get(health.readiness_handler()));
//! ```

use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::sync::Arc;

use super::handler::FnHandler;
use super::response::{IntoResponse, Response, StatusCode};

// ─── HealthStatus ────────────────────────────────────────────────────────────

/// Status of an individual health check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthStatus {
    /// The component is fully healthy.
    Healthy,
    /// The component is operational but degraded.
    Degraded(String),
    /// The component is unhealthy and not operational.
    Unhealthy(String),
}

impl HealthStatus {
    /// Returns `true` if the status is [`Healthy`](HealthStatus::Healthy).
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    /// Returns `true` if the status is at least operational (healthy or degraded).
    #[must_use]
    pub fn is_operational(&self) -> bool {
        !matches!(self, Self::Unhealthy(_))
    }

    /// Returns the status name as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded(_) => "degraded",
            Self::Unhealthy(_) => "unhealthy",
        }
    }

    /// Returns the detail message, if any.
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Healthy => None,
            Self::Degraded(msg) | Self::Unhealthy(msg) => Some(msg),
        }
    }
}

impl fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::Degraded(msg) => write!(f, "degraded: {msg}"),
            Self::Unhealthy(msg) => write!(f, "unhealthy: {msg}"),
        }
    }
}

// ─── HealthResponse ──────────────────────────────────────────────────────────

/// Aggregated health check response.
#[derive(Debug, Clone)]
pub struct HealthResponse {
    /// Overall status.
    pub status: HealthStatus,
    /// Individual check results.
    pub checks: BTreeMap<String, HealthStatus>,
}

impl HealthResponse {
    /// Serialize to JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut buf = String::from("{\"status\":\"");
        buf.push_str(self.status.as_str());
        buf.push('"');
        if let Some(detail) = self.status.detail() {
            buf.push_str(",\"detail\":\"");
            json_escape_into(&mut buf, detail);
            buf.push('"');
        }

        if !self.checks.is_empty() {
            buf.push_str(",\"checks\":{");
            for (i, (name, status)) in self.checks.iter().enumerate() {
                if i > 0 {
                    buf.push(',');
                }
                buf.push('"');
                json_escape_into(&mut buf, name);
                buf.push_str("\":{\"status\":\"");
                buf.push_str(status.as_str());
                buf.push('"');
                if let Some(detail) = status.detail() {
                    buf.push_str(",\"detail\":\"");
                    json_escape_into(&mut buf, detail);
                    buf.push('"');
                }
                buf.push('}');
            }
            buf.push('}');
        }

        buf.push('}');
        buf
    }

    /// Serialize to the public probe JSON form.
    ///
    /// Liveness/readiness probe endpoints are intentionally coarse and do not
    /// expose per-check names or failure detail to unauthenticated callers.
    #[must_use]
    pub fn to_probe_json(&self) -> String {
        format!("{{\"status\":\"{}\"}}", self.status.as_str())
    }

    fn into_probe_response(self) -> Response {
        let status_code = if self.status.is_operational() {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };

        Response::new(status_code, self.to_probe_json().into_bytes())
            .header("content-type", "application/json")
    }
}

impl IntoResponse for HealthResponse {
    fn into_response(self) -> Response {
        let status_code = if self.status.is_operational() {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };

        Response::new(status_code, self.to_json().into_bytes())
            .header("content-type", "application/json")
    }
}

/// Minimal JSON string escaping.
fn json_escape_into(buf: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => buf.push_str("\\\""),
            '\\' => buf.push_str("\\\\"),
            '\n' => buf.push_str("\\n"),
            '\r' => buf.push_str("\\r"),
            '\t' => buf.push_str("\\t"),
            c if c < '\x20' => {
                let _ = write!(buf, "\\u{:04x}", c as u32);
            }
            c => buf.push(c),
        }
    }
}

// ─── HealthCheck ─────────────────────────────────────────────────────────────

/// A named health check function.
type CheckFn = Arc<dyn Fn() -> HealthStatus + Send + Sync>;

/// Configurable health check system.
///
/// Holds a set of named health checks and provides handler factories
/// for liveness and readiness probes.
///
/// # Thread Safety
///
/// `HealthCheck` is `Clone` and internally reference-counted. All
/// clones share the same check registry.
#[derive(Clone)]
pub struct HealthCheck {
    inner: Arc<HealthCheckInner>,
}

struct HealthCheckInner {
    checks: Mutex<Vec<(String, CheckFn)>>,
    ready: Arc<Mutex<bool>>,
}

impl fmt::Debug for HealthCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<String> = {
            let checks = self.inner.checks.lock();
            checks.iter().map(|(name, _)| name.clone()).collect()
        };
        let ready = *self.inner.ready.lock();
        f.debug_struct("HealthCheck")
            .field("checks", &names)
            .field("ready", &ready)
            .finish()
    }
}

impl HealthCheck {
    /// Create a new health check system with no checks.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(HealthCheckInner {
                checks: Mutex::new(Vec::new()),
                ready: Arc::new(Mutex::new(true)),
            }),
        }
    }

    /// Register a named health check.
    #[must_use]
    pub fn check(
        self,
        name: impl Into<String>,
        f: impl Fn() -> HealthStatus + Send + Sync + 'static,
    ) -> Self {
        self.inner.checks.lock().push((name.into(), Arc::new(f)));
        self
    }

    /// Set the readiness state.
    ///
    /// When `false`, the readiness endpoint returns 503 Service Unavailable.
    /// Use this during startup/shutdown to drain traffic.
    pub fn set_ready(&self, ready: bool) {
        *self.inner.ready.lock() = ready;
    }

    /// Get the current readiness state.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        *self.inner.ready.lock()
    }

    /// Run all health checks and return the aggregated response.
    #[must_use]
    pub fn run_checks(&self) -> HealthResponse {
        let checks = self.inner.checks.lock().clone();
        let mut results = BTreeMap::new();
        let mut overall = HealthStatus::Healthy;

        for (name, check_fn) in checks {
            let status = check_fn();
            match (&overall, &status) {
                (HealthStatus::Healthy, HealthStatus::Degraded(_)) => {
                    overall = HealthStatus::Degraded("one or more checks degraded".to_string());
                }
                (_, HealthStatus::Unhealthy(_)) => {
                    overall = HealthStatus::Unhealthy("one or more checks unhealthy".to_string());
                }
                _ => {}
            }
            results.insert(name, status);
        }

        HealthResponse {
            status: overall,
            checks: results,
        }
    }

    /// Create a liveness probe handler.
    ///
    /// Liveness checks answer "is the process alive?" and always return
    /// 200 OK unless all checks fail. Liveness probes typically don't
    /// run dependency checks.
    #[must_use]
    pub fn liveness_handler(&self) -> FnHandler<impl Fn() -> Response + Send + Sync + 'static> {
        let health = self.clone();
        FnHandler::new(move || {
            let response = health.run_checks();
            response.into_probe_response()
        })
    }

    /// Create a readiness probe handler.
    ///
    /// Readiness checks answer "can it serve traffic?" and return
    /// 503 when the service is not ready (e.g., during startup or
    /// when draining for shutdown).
    #[must_use]
    pub fn readiness_handler(&self) -> FnHandler<impl Fn() -> Response + Send + Sync + 'static> {
        let health = self.clone();
        FnHandler::new(move || {
            if !health.is_ready() {
                return Response::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    b"{\"status\":\"not_ready\"}".to_vec(),
                )
                .header("content-type", "application/json");
            }
            let response = health.run_checks();
            response.into_probe_response()
        })
    }

    /// Create a startup probe handler.
    ///
    /// Startup probes answer "has the process finished starting?"
    /// Returns 200 once `set_ready(true)` has been called, 503 otherwise.
    #[must_use]
    pub fn startup_handler(&self) -> FnHandler<impl Fn() -> Response + Send + Sync + 'static> {
        let ready = Arc::clone(&self.inner.ready);
        FnHandler::new(move || {
            let is_ready = *ready.lock();
            if is_ready {
                Response::new(StatusCode::OK, b"{\"status\":\"started\"}".to_vec())
                    .header("content-type", "application/json")
            } else {
                Response::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    b"{\"status\":\"starting\"}".to_vec(),
                )
                .header("content-type", "application/json")
            }
        })
    }
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "health_inline_tests.rs"]
mod tests;
