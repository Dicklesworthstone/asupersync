//! Test harness integrating virtual server, client, and lab runtime.

use std::fmt;

use super::server::VirtualServer;
use crate::bytes::Bytes;
use crate::lab::config::LabConfig;
use crate::lab::runtime::LabRuntime;
use crate::types::Time;
use crate::util::DetRng;
use crate::web::extract::Request;
use crate::web::response::Response;
use crate::web::router::Router;

/// A traced client bound to a [`TestHarness`].
///
/// Requests sent through this client use the harness's deterministic batch RNG
/// and are recorded in the harness request trace.
pub struct TestHarnessClient<'a> {
    harness: &'a mut TestHarness,
}

impl TestHarnessClient<'_> {
    /// Send a GET request and record it in the harness trace.
    #[must_use]
    pub fn get(&mut self, path: &str) -> Response {
        self.harness.get(path)
    }

    /// Send a POST request with a binary body and record it in the harness trace.
    pub fn post(&mut self, path: &str, body: impl Into<Bytes>) -> Response {
        let mut req = Request::new("POST", path);
        req.body = body.into();
        req.headers.insert(
            "content-type".to_string(),
            "application/octet-stream".to_string(),
        );
        self.harness.send_traced(req)
    }

    /// Send a POST request with a JSON body and record it in the harness trace.
    #[must_use]
    pub fn post_json(&mut self, path: &str, json: &str) -> Response {
        let mut req = Request::new("POST", path);
        req.body = Bytes::from(json.to_string());
        req.headers
            .insert("content-type".to_string(), "application/json".to_string());
        self.harness.send_traced(req)
    }

    /// Send a PUT request with a body and record it in the harness trace.
    pub fn put(&mut self, path: &str, body: impl Into<Bytes>) -> Response {
        let mut req = Request::new("PUT", path);
        req.body = body.into();
        self.harness.send_traced(req)
    }

    /// Send a DELETE request and record it in the harness trace.
    #[must_use]
    pub fn delete(&mut self, path: &str) -> Response {
        self.harness.send_traced(Request::new("DELETE", path))
    }

    /// Send a batch of GET requests using the harness RNG and trace recorder.
    pub fn get_batch(&mut self, paths: &[&str]) -> Vec<Response> {
        self.harness.get_batch(paths)
    }

    /// Send a custom request and record it in the harness trace.
    #[must_use]
    pub fn send(&mut self, req: Request) -> Response {
        self.harness.send_traced(req)
    }
}

/// Integrated test harness for deterministic HTTP testing.
///
/// Combines a [`LabRuntime`], [`VirtualServer`], and
/// [`VirtualClient`](crate::lab::http::VirtualClient) with
/// request tracing and virtual time control.
///
/// # Example
///
/// ```
/// use asupersync::lab::http::TestHarness;
/// use asupersync::lab::LabConfig;
/// use asupersync::web::{Router, get};
/// use asupersync::web::handler::FnHandler;
///
/// let router = Router::new()
///     .route("/health", get(FnHandler::new(|| "ok")));
///
/// let mut harness = TestHarness::new(LabConfig::new(42), router);
///
/// let resp = harness.get("/health");
/// assert_eq!(resp.status.as_u16(), 200);
///
/// // Check trace
/// assert_eq!(harness.trace().len(), 1);
/// assert_eq!(harness.trace()[0].method, "GET");
/// assert_eq!(harness.trace()[0].path, "/health");
/// assert_eq!(harness.trace()[0].status, 200);
/// ```
pub struct TestHarness {
    runtime: LabRuntime,
    server: VirtualServer,
    rng: DetRng,
    trace: RequestTrace,
}

impl TestHarness {
    /// Create a new test harness.
    #[must_use]
    pub fn new(config: LabConfig, router: Router) -> Self {
        let seed = config.seed;
        Self {
            runtime: LabRuntime::new(config),
            server: VirtualServer::new(router),
            rng: DetRng::new(seed),
            trace: RequestTrace::new(),
        }
    }

    /// Create a harness with a specific seed (convenience).
    #[must_use]
    pub fn with_seed(seed: u64, router: Router) -> Self {
        Self::new(LabConfig::new(seed), router)
    }

    /// Get a traced client bound to the harness.
    ///
    /// Requests sent through this client are recorded in [`RequestTrace`] and
    /// batched GETs use the harness's deterministic RNG ordering.
    #[must_use]
    pub fn client(&mut self) -> TestHarnessClient<'_> {
        TestHarnessClient { harness: self }
    }

    /// Send a GET request and record it in the trace.
    pub fn get(&mut self, path: &str) -> Response {
        self.send_traced(Request::new("GET", path))
    }

    /// Send a POST request with body and record it.
    pub fn post(&mut self, path: &str, body: &[u8]) -> Response {
        let mut req = Request::new("POST", path);
        req.body = crate::bytes::Bytes::copy_from_slice(body);
        self.send_traced(req)
    }

    /// Send a custom request and record it.
    pub fn send(&mut self, req: Request) -> Response {
        self.send_traced(req)
    }

    /// Send a batch of GET requests in deterministic order.
    ///
    /// The ordering is controlled by the harness's seed-derived RNG.
    /// Returns responses in the original path order (not execution order).
    pub fn get_batch(&mut self, paths: &[&str]) -> Vec<Response> {
        let mut indices: Vec<usize> = (0..paths.len()).collect();
        self.rng.shuffle(&mut indices);

        let mut responses = vec![None; paths.len()];
        for &idx in &indices {
            let resp = self.send_traced(Request::new("GET", paths[idx]));
            responses[idx] = Some(resp);
        }
        responses
            .into_iter()
            .map(|r| r.expect("response should be present"))
            .collect()
    }

    /// Advance virtual time by the given duration.
    pub fn advance_time(&mut self, nanos: u64) {
        self.runtime.advance_time(nanos);
    }

    /// Get the current virtual time.
    #[must_use]
    pub fn now(&self) -> Time {
        self.runtime.now()
    }

    /// Get the request trace.
    #[must_use]
    pub fn trace(&self) -> &[TraceEntry] {
        self.trace.entries()
    }

    /// Clear the request trace.
    pub fn clear_trace(&mut self) {
        self.trace.clear();
    }

    /// Returns the total number of requests processed.
    #[must_use]
    pub fn request_count(&self) -> u64 {
        self.server.request_count()
    }

    /// Returns a reference to the lab runtime.
    #[must_use]
    pub fn runtime(&self) -> &LabRuntime {
        &self.runtime
    }

    /// Returns a mutable reference to the lab runtime.
    pub fn runtime_mut(&mut self) -> &mut LabRuntime {
        &mut self.runtime
    }

    /// Returns a reference to the virtual server.
    #[must_use]
    pub fn server(&self) -> &VirtualServer {
        &self.server
    }

    /// Assert that all traced requests returned a success status (2xx).
    ///
    /// # Panics
    ///
    /// Panics with a detailed message if any request failed.
    pub fn assert_all_success(&self) {
        for entry in self.trace.entries() {
            assert!(
                (200..300).contains(&entry.status),
                "Request {} {} returned {} (expected 2xx)\nFull trace:\n{}",
                entry.method,
                entry.path,
                entry.status,
                self.trace
            );
        }
    }

    /// Assert that a specific number of requests were processed.
    ///
    /// # Panics
    ///
    /// Panics if the count doesn't match.
    pub fn assert_request_count(&self, expected: u64) {
        let actual = self.server.request_count();
        assert_eq!(
            actual, expected,
            "Expected {expected} requests, got {actual}"
        );
    }

    fn send_traced(&mut self, req: Request) -> Response {
        let method = req.method.clone();
        let path = req.path.clone();
        let virtual_time = self.runtime.now();

        let resp = self.server.handle(req);

        self.trace.record(TraceEntry {
            method,
            path,
            status: resp.status.as_u16(),
            virtual_time,
        });

        resp
    }
}

// ─── Request Trace ──────────────────────────────────────────────────────────

/// A trace of HTTP requests and their outcomes.
///
/// Used for test assertions and debugging.
#[derive(Debug, Clone, Default)]
pub struct RequestTrace {
    entries: Vec<TraceEntry>,
}

impl RequestTrace {
    /// Create an empty trace.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a trace entry.
    pub fn record(&mut self, entry: TraceEntry) {
        self.entries.push(entry);
    }

    /// Get all entries.
    #[must_use]
    pub fn entries(&self) -> &[TraceEntry] {
        &self.entries
    }

    /// Get entry count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Filter entries by status code class (e.g., 2 for 2xx).
    #[must_use]
    pub fn by_status_class(&self, class: u16) -> Vec<&TraceEntry> {
        let lo = class.saturating_mul(100);
        let hi = lo.saturating_add(100);
        self.entries
            .iter()
            .filter(|e| e.status >= lo && e.status < hi)
            .collect()
    }

    /// Filter entries by path prefix.
    #[must_use]
    pub fn by_path_prefix(&self, prefix: &str) -> Vec<&TraceEntry> {
        self.entries
            .iter()
            .filter(|e| e.path.starts_with(prefix))
            .collect()
    }

    /// Count successes (2xx responses).
    #[must_use]
    pub fn success_count(&self) -> usize {
        self.by_status_class(2).len()
    }

    /// Count errors (4xx + 5xx responses).
    #[must_use]
    pub fn error_count(&self) -> usize {
        self.by_status_class(4).len() + self.by_status_class(5).len()
    }
}

impl fmt::Display for RequestTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, entry) in self.entries.iter().enumerate() {
            writeln!(f, "  [{i}] {entry}")?;
        }
        Ok(())
    }
}

/// A single traced HTTP request/response.
#[derive(Debug, Clone)]
pub struct TraceEntry {
    /// HTTP method.
    pub method: String,
    /// Request path.
    pub path: String,
    /// Response status code.
    pub status: u16,
    /// Virtual time when the request was processed.
    pub virtual_time: Time,
}

impl fmt::Display for TraceEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} → {} (t={}ms)",
            self.method,
            self.path,
            self.status,
            self.virtual_time.as_millis()
        )
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "harness_inline_tests.rs"]
mod tests;
