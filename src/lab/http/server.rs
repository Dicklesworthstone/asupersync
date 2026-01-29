//! Virtual HTTP server for lab runtime testing.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::types::Time;
use crate::web::extract::Request;
use crate::web::response::Response;
use crate::web::router::Router;

/// A virtual HTTP server backed by a [`Router`].
///
/// Processes requests synchronously without any network I/O. Tracks request
/// counts and timing for test assertions.
///
/// # Example
///
/// ```ignore
/// let router = Router::new()
///     .route("/health", get(FnHandler::new(|| "ok")));
///
/// let server = VirtualServer::new(router);
/// let resp = server.handle(Request::new("GET", "/health"));
/// assert_eq!(resp.status.as_u16(), 200);
/// ```
pub struct VirtualServer {
    router: Router,
    request_count: AtomicU64,
}

impl VirtualServer {
    /// Create a virtual server with the given router.
    #[must_use]
    pub fn new(router: Router) -> Self {
        Self {
            router,
            request_count: AtomicU64::new(0),
        }
    }

    /// Handle a request and return a response.
    ///
    /// This dispatches the request through the router synchronously.
    /// The request count is incremented.
    pub fn handle(&self, req: Request) -> Response {
        self.request_count.fetch_add(1, Ordering::SeqCst);
        self.router.handle(req)
    }

    /// Handle a request, recording virtual timestamps.
    ///
    /// Returns the response along with the virtual time at which the request
    /// was processed. Useful for deterministic timing assertions.
    pub fn handle_at(&self, req: Request, now: Time) -> (Response, Time) {
        let resp = self.handle(req);
        (resp, now)
    }

    /// Returns the total number of requests processed.
    #[must_use]
    pub fn request_count(&self) -> u64 {
        self.request_count.load(Ordering::SeqCst)
    }

    /// Returns a reference to the underlying router.
    #[must_use]
    pub fn router(&self) -> &Router {
        &self.router
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::handler::FnHandler;
    use crate::web::response::StatusCode;
    use crate::web::router::get;

    #[test]
    fn server_handles_request() {
        let router = Router::new().route("/hello", get(FnHandler::new(|| "world")));
        let server = VirtualServer::new(router);

        let resp = server.handle(Request::new("GET", "/hello"));
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(server.request_count(), 1);
    }

    #[test]
    fn server_404_for_unknown_route() {
        let router = Router::new();
        let server = VirtualServer::new(router);

        let resp = server.handle(Request::new("GET", "/missing"));
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn server_counts_requests() {
        let router = Router::new().route("/", get(FnHandler::new(|| "ok")));
        let server = VirtualServer::new(router);

        for _ in 0..5 {
            server.handle(Request::new("GET", "/"));
        }
        assert_eq!(server.request_count(), 5);
    }

    #[test]
    fn server_handle_at_returns_time() {
        let router = Router::new().route("/", get(FnHandler::new(|| "ok")));
        let server = VirtualServer::new(router);

        let now = Time::from_millis(1000);
        let (resp, time) = server.handle_at(Request::new("GET", "/"), now);
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(time, now);
    }
}
