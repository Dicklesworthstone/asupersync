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
//! ```ignore
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

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use parking_lot::Mutex;
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
type CheckFn = Box<dyn Fn() -> HealthStatus + Send + Sync>;

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
        self.inner
            .checks
            .lock()
            .push((name.into(), Box::new(f)));
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
        let (overall, results) = {
            let checks = self.inner.checks.lock();
            let mut results = BTreeMap::new();
            let mut overall = HealthStatus::Healthy;

            for (name, check_fn) in checks.iter() {
                let status = check_fn();
                match (&overall, &status) {
                    (HealthStatus::Healthy, HealthStatus::Degraded(_)) => {
                        overall = HealthStatus::Degraded("one or more checks degraded".to_string());
                    }
                    (_, HealthStatus::Unhealthy(_)) => {
                        overall =
                            HealthStatus::Unhealthy("one or more checks unhealthy".to_string());
                    }
                    _ => {}
                }
                results.insert(name.clone(), status);
            }
            drop(checks);

            (overall, results)
        };

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
            response.into_response()
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
            response.into_response()
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
mod tests {
    use super::super::handler::Handler;
    use super::*;

    // ================================================================
    // HealthStatus
    // ================================================================

    #[test]
    fn health_status_healthy() {
        let s = HealthStatus::Healthy;
        assert!(s.is_healthy());
        assert!(s.is_operational());
        assert_eq!(s.as_str(), "healthy");
        assert_eq!(s.detail(), None);
        assert_eq!(s.to_string(), "healthy");
    }

    #[test]
    fn health_status_degraded() {
        let s = HealthStatus::Degraded("slow".into());
        assert!(!s.is_healthy());
        assert!(s.is_operational());
        assert_eq!(s.as_str(), "degraded");
        assert_eq!(s.detail(), Some("slow"));
        assert_eq!(s.to_string(), "degraded: slow");
    }

    #[test]
    fn health_status_unhealthy() {
        let s = HealthStatus::Unhealthy("down".into());
        assert!(!s.is_healthy());
        assert!(!s.is_operational());
        assert_eq!(s.as_str(), "unhealthy");
        assert_eq!(s.detail(), Some("down"));
        assert_eq!(s.to_string(), "unhealthy: down");
    }

    // ================================================================
    // HealthResponse serialization
    // ================================================================

    #[test]
    fn health_response_healthy_json() {
        let resp = HealthResponse {
            status: HealthStatus::Healthy,
            checks: BTreeMap::new(),
        };
        assert_eq!(resp.to_json(), r#"{"status":"healthy"}"#);
    }

    #[test]
    fn health_response_with_checks_json() {
        let mut checks = BTreeMap::new();
        checks.insert("db".to_string(), HealthStatus::Healthy);
        checks.insert(
            "cache".to_string(),
            HealthStatus::Degraded("high latency".into()),
        );

        let resp = HealthResponse {
            status: HealthStatus::Degraded("one or more checks degraded".into()),
            checks,
        };
        let json = resp.to_json();
        assert!(json.contains(r#""status":"degraded""#));
        assert!(json.contains(r#""db":{"status":"healthy"}"#));
        assert!(json.contains(r#""cache":{"status":"degraded","detail":"high latency"}"#));
    }

    #[test]
    fn health_response_json_escaping() {
        let mut checks = BTreeMap::new();
        checks.insert(
            "test".to_string(),
            HealthStatus::Unhealthy("error: \"bad\"".into()),
        );

        let resp = HealthResponse {
            status: HealthStatus::Unhealthy("fail".into()),
            checks,
        };
        let json = resp.to_json();
        assert!(json.contains(r#"\"bad\""#));
    }

    // ================================================================
    // HealthResponse IntoResponse
    // ================================================================

    #[test]
    fn health_response_into_response_healthy() {
        let resp = HealthResponse {
            status: HealthStatus::Healthy,
            checks: BTreeMap::new(),
        };
        let http = resp.into_response();
        assert_eq!(http.status, StatusCode::OK);
        assert_eq!(
            http.headers.get("content-type").unwrap(),
            "application/json"
        );
    }

    #[test]
    fn health_response_into_response_unhealthy() {
        let resp = HealthResponse {
            status: HealthStatus::Unhealthy("fail".into()),
            checks: BTreeMap::new(),
        };
        let http = resp.into_response();
        assert_eq!(http.status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn health_response_into_response_degraded() {
        let resp = HealthResponse {
            status: HealthStatus::Degraded("slow".into()),
            checks: BTreeMap::new(),
        };
        let http = resp.into_response();
        // Degraded is still operational → 200 OK.
        assert_eq!(http.status, StatusCode::OK);
    }

    // ================================================================
    // HealthCheck system
    // ================================================================

    #[test]
    fn health_check_no_checks() {
        let hc = HealthCheck::new();
        let result = hc.run_checks();
        assert_eq!(result.status, HealthStatus::Healthy);
        assert!(result.checks.is_empty());
    }

    #[test]
    fn health_check_all_healthy() {
        let hc = HealthCheck::new()
            .check("db", || HealthStatus::Healthy)
            .check("cache", || HealthStatus::Healthy);

        let result = hc.run_checks();
        assert_eq!(result.status, HealthStatus::Healthy);
        assert_eq!(result.checks.len(), 2);
    }

    #[test]
    fn health_check_one_degraded() {
        let hc = HealthCheck::new()
            .check("db", || HealthStatus::Healthy)
            .check("cache", || HealthStatus::Degraded("slow".into()));

        let result = hc.run_checks();
        assert!(matches!(result.status, HealthStatus::Degraded(_)));
        assert_eq!(result.checks.get("cache").unwrap().as_str(), "degraded");
    }

    #[test]
    fn health_check_one_unhealthy() {
        let hc = HealthCheck::new()
            .check("db", || {
                HealthStatus::Unhealthy("connection refused".into())
            })
            .check("cache", || HealthStatus::Healthy);

        let result = hc.run_checks();
        assert!(matches!(result.status, HealthStatus::Unhealthy(_)));
    }

    #[test]
    fn health_check_unhealthy_overrides_degraded() {
        let hc = HealthCheck::new()
            .check("db", || HealthStatus::Degraded("slow".into()))
            .check("cache", || HealthStatus::Unhealthy("down".into()));

        let result = hc.run_checks();
        assert!(matches!(result.status, HealthStatus::Unhealthy(_)));
    }

    // ================================================================
    // Readiness control
    // ================================================================

    #[test]
    fn health_check_readiness_default() {
        let hc = HealthCheck::new();
        assert!(hc.is_ready());
    }

    #[test]
    fn health_check_set_ready() {
        let hc = HealthCheck::new();
        hc.set_ready(false);
        assert!(!hc.is_ready());

        hc.set_ready(true);
        assert!(hc.is_ready());
    }

    #[test]
    fn health_check_clone_shares_state() {
        let hc = HealthCheck::new();
        let hc2 = hc.clone();
        hc.set_ready(false);
        assert!(!hc2.is_ready());
    }

    // ================================================================
    // Handler integration
    // ================================================================

    #[test]
    fn liveness_handler_returns_200() {
        let hc = HealthCheck::new().check("db", || HealthStatus::Healthy);
        let handler = hc.liveness_handler();

        let req = super::super::extract::Request::new("GET", "/healthz");
        let resp = handler.call(req);
        assert_eq!(resp.status, StatusCode::OK);
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("healthy"));
    }

    #[test]
    fn liveness_handler_unhealthy_returns_503() {
        let hc = HealthCheck::new().check("db", || {
            HealthStatus::Unhealthy("connection refused".into())
        });
        let handler = hc.liveness_handler();

        let req = super::super::extract::Request::new("GET", "/healthz");
        let resp = handler.call(req);
        assert_eq!(resp.status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn readiness_handler_ready() {
        let hc = HealthCheck::new().check("db", || HealthStatus::Healthy);
        let handler = hc.readiness_handler();

        let req = super::super::extract::Request::new("GET", "/readyz");
        let resp = handler.call(req);
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn readiness_handler_not_ready() {
        let hc = HealthCheck::new().check("db", || HealthStatus::Healthy);
        hc.set_ready(false);
        let handler = hc.readiness_handler();

        let req = super::super::extract::Request::new("GET", "/readyz");
        let resp = handler.call(req);
        assert_eq!(resp.status, StatusCode::SERVICE_UNAVAILABLE);
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("not_ready"));
    }

    #[test]
    fn startup_handler_started() {
        let hc = HealthCheck::new();
        let handler = hc.startup_handler();

        let req = super::super::extract::Request::new("GET", "/startupz");
        let resp = handler.call(req);
        assert_eq!(resp.status, StatusCode::OK);
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("started"));
    }

    #[test]
    fn startup_handler_not_started() {
        let hc = HealthCheck::new();
        hc.set_ready(false);
        let handler = hc.startup_handler();

        let req = super::super::extract::Request::new("GET", "/startupz");
        let resp = handler.call(req);
        assert_eq!(resp.status, StatusCode::SERVICE_UNAVAILABLE);
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("starting"));
    }

    // ================================================================
    // Data type coverage
    // ================================================================

    #[test]
    fn health_status_debug_clone_eq() {
        let s = HealthStatus::Healthy;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Healthy"));
        let cloned = s.clone();
        assert_eq!(s, cloned);

        let d1 = HealthStatus::Degraded("a".into());
        let d2 = HealthStatus::Degraded("b".into());
        assert_ne!(d1, d2);
    }

    #[test]
    fn health_response_debug_clone() {
        let resp = HealthResponse {
            status: HealthStatus::Healthy,
            checks: BTreeMap::new(),
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("HealthResponse"));
    }

    #[test]
    fn health_check_debug() {
        let hc = HealthCheck::new().check("db", || HealthStatus::Healthy);
        let dbg = format!("{hc:?}");
        assert!(dbg.contains("HealthCheck"));
        assert!(dbg.contains("db"));
    }

    #[test]
    fn health_check_default() {
        let hc = HealthCheck::default();
        assert!(hc.is_ready());
        let result = hc.run_checks();
        assert_eq!(result.status, HealthStatus::Healthy);
    }
}
