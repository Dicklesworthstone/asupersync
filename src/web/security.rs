//! Security headers middleware.
//!
//! Provides [`SecurityHeadersMiddleware`] which applies standard HTTP
//! security headers to every response. This bundles common headers like
//! HSTS, X-Frame-Options, and Content-Security-Policy into a single
//! middleware layer.
//!
//! # Headers Applied
//!
//! | Header | Default Value | Purpose |
//! |--------|---------------|---------|
//! | `x-content-type-options` | `nosniff` | Prevent MIME sniffing |
//! | `x-frame-options` | `DENY` | Prevent clickjacking |
//! | `referrer-policy` | `strict-origin-when-cross-origin` | Control referrer leakage |
//! | `strict-transport-security` | `max-age=31536000; includeSubDomains` | Enforce HTTPS (HSTS) |
//! | `content-security-policy` | *(none by default)* | Restrict content sources |
//! | `permissions-policy` | *(none by default)* | Control browser features |

use super::extract::Request;
use super::handler::Handler;
use super::response::Response;

/// Configuration for security headers.
///
/// Provides sensible defaults for common security headers. All headers
/// can be individually customized or disabled by setting them to `None`.
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Value for `X-Content-Type-Options`. Default: `"nosniff"`.
    pub content_type_options: Option<String>,

    /// Value for `X-Frame-Options`. Default: `"DENY"`.
    /// Common values: `"DENY"`, `"SAMEORIGIN"`.
    pub frame_options: Option<String>,

    /// Value for `Referrer-Policy`. Default: `"strict-origin-when-cross-origin"`.
    pub referrer_policy: Option<String>,

    /// Value for `Strict-Transport-Security` (HSTS).
    /// Default: `"max-age=31536000; includeSubDomains"`.
    /// Set to `None` to disable (e.g., for non-HTTPS deployments).
    pub hsts: Option<String>,

    /// Value for `Content-Security-Policy`. Default: `None` (not set).
    /// Example: `"default-src 'self'; script-src 'self'"`.
    pub content_security_policy: Option<String>,

    /// Value for `Permissions-Policy`. Default: `None` (not set).
    /// Example: `"camera=(), microphone=(), geolocation=()"`.
    pub permissions_policy: Option<String>,

    /// Whether to remove the `Server` header from responses. Default: `true`.
    pub hide_server_header: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            content_type_options: Some("nosniff".to_string()),
            frame_options: Some("DENY".to_string()),
            referrer_policy: Some("strict-origin-when-cross-origin".to_string()),
            hsts: Some("max-age=31536000; includeSubDomains".to_string()),
            content_security_policy: None,
            permissions_policy: None,
            hide_server_header: true,
        }
    }
}

impl SecurityPolicy {
    /// Create a policy with all headers disabled.
    #[must_use]
    pub fn none() -> Self {
        Self {
            content_type_options: None,
            frame_options: None,
            referrer_policy: None,
            hsts: None,
            content_security_policy: None,
            permissions_policy: None,
            hide_server_header: false,
        }
    }

    /// Set the Content-Security-Policy header.
    #[must_use]
    pub fn with_csp(mut self, csp: impl Into<String>) -> Self {
        self.content_security_policy = Some(csp.into());
        self
    }

    /// Set the Permissions-Policy header.
    #[must_use]
    pub fn with_permissions_policy(mut self, policy: impl Into<String>) -> Self {
        self.permissions_policy = Some(policy.into());
        self
    }

    /// Set the X-Frame-Options header.
    #[must_use]
    pub fn with_frame_options(mut self, value: impl Into<String>) -> Self {
        self.frame_options = Some(value.into());
        self
    }

    /// Disable HSTS (for non-HTTPS deployments).
    #[must_use]
    pub fn without_hsts(mut self) -> Self {
        self.hsts = None;
        self
    }
}

/// Middleware that applies standard security headers to every response.
///
/// Wraps an inner [`Handler`] and adds configured security headers to
/// every response. Headers are set without overwriting values already
/// present in the response.
///
/// # Example
///
/// ```ignore
/// use asupersync::web::security::{SecurityHeadersMiddleware, SecurityPolicy};
/// use asupersync::web::handler::FnHandler;
///
/// let handler = FnHandler::new(|| "hello");
/// let secured = SecurityHeadersMiddleware::new(
///     handler,
///     SecurityPolicy::default().with_csp("default-src 'self'"),
/// );
/// ```
pub struct SecurityHeadersMiddleware<H> {
    inner: H,
    policy: SecurityPolicy,
}

impl<H: Handler> SecurityHeadersMiddleware<H> {
    /// Wrap a handler with security headers.
    #[must_use]
    pub fn new(inner: H, policy: SecurityPolicy) -> Self {
        Self { inner, policy }
    }
}

impl<H: Handler> Handler for SecurityHeadersMiddleware<H> {
    fn call(&self, req: Request) -> Response {
        let mut resp = self.inner.call(req);

        // Apply each configured header, only if not already set.
        if let Some(ref val) = self.policy.content_type_options {
            resp.ensure_header("x-content-type-options", val.clone());
        }

        if let Some(ref val) = self.policy.frame_options {
            resp.ensure_header("x-frame-options", val.clone());
        }

        if let Some(ref val) = self.policy.referrer_policy {
            resp.ensure_header("referrer-policy", val.clone());
        }

        if let Some(ref val) = self.policy.hsts {
            resp.ensure_header("strict-transport-security", val.clone());
        }

        if let Some(ref val) = self.policy.content_security_policy {
            resp.ensure_header("content-security-policy", val.clone());
        }

        if let Some(ref val) = self.policy.permissions_policy {
            resp.ensure_header("permissions-policy", val.clone());
        }

        if self.policy.hide_server_header {
            let _ = resp.remove_header("server");
        }

        resp
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::*;
    use crate::web::handler::FnHandler;
    use crate::web::response::StatusCode;

    fn ok_handler() -> &'static str {
        "ok"
    }

    fn make_request() -> Request {
        Request::new("GET", "/test")
    }

    fn handler_with_server_header() -> Response {
        Response::new(StatusCode::OK, b"ok".to_vec()).header("server", "asupersync/0.2.6")
    }

    fn handler_with_mixed_case_server_header() -> Response {
        let mut resp = Response::new(StatusCode::OK, b"ok".to_vec());
        resp.headers
            .insert("Server".to_string(), "asupersync/0.2.6".to_string());
        resp
    }

    fn handler_with_existing_headers() -> Response {
        Response::new(StatusCode::OK, b"ok".to_vec())
            .header("x-frame-options", "SAMEORIGIN")
            .header("referrer-policy", "no-referrer")
    }

    fn handler_with_mixed_case_existing_headers() -> Response {
        let mut resp = Response::new(StatusCode::OK, b"ok".to_vec());
        resp.headers
            .insert("X-Frame-Options".to_string(), "SAMEORIGIN".to_string());
        resp.headers
            .insert("Referrer-Policy".to_string(), "no-referrer".to_string());
        resp
    }

    // --- Default policy ---

    #[test]
    fn default_policy_sets_standard_headers() {
        let mw =
            SecurityHeadersMiddleware::new(FnHandler::new(ok_handler), SecurityPolicy::default());
        let resp = mw.call(make_request());

        assert_eq!(
            resp.headers.get("x-content-type-options").unwrap(),
            "nosniff"
        );
        assert_eq!(resp.headers.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(
            resp.headers.get("referrer-policy").unwrap(),
            "strict-origin-when-cross-origin"
        );
        assert_eq!(
            resp.headers.get("strict-transport-security").unwrap(),
            "max-age=31536000; includeSubDomains"
        );
    }

    #[test]
    fn default_policy_no_csp_or_permissions() {
        let mw =
            SecurityHeadersMiddleware::new(FnHandler::new(ok_handler), SecurityPolicy::default());
        let resp = mw.call(make_request());

        assert!(!resp.headers.contains_key("content-security-policy"));
        assert!(!resp.headers.contains_key("permissions-policy"));
    }

    #[test]
    fn default_policy_removes_server_header() {
        let mw = SecurityHeadersMiddleware::new(
            FnHandler::new(handler_with_server_header),
            SecurityPolicy::default(),
        );
        let resp = mw.call(make_request());

        assert!(!resp.headers.contains_key("server"));
    }

    #[test]
    fn default_policy_removes_mixed_case_server_header() {
        let mw = SecurityHeadersMiddleware::new(
            FnHandler::new(handler_with_mixed_case_server_header),
            SecurityPolicy::default(),
        );
        let resp = mw.call(make_request());

        assert!(!resp.headers.contains_key("server"));
        assert!(!resp.headers.contains_key("Server"));
    }

    // --- Custom policy ---

    #[test]
    fn custom_csp_applied() {
        let policy = SecurityPolicy::default().with_csp("default-src 'self'");
        let mw = SecurityHeadersMiddleware::new(FnHandler::new(ok_handler), policy);
        let resp = mw.call(make_request());

        assert_eq!(
            resp.headers.get("content-security-policy").unwrap(),
            "default-src 'self'"
        );
    }

    #[test]
    fn custom_permissions_policy_applied() {
        let policy = SecurityPolicy::default().with_permissions_policy("camera=(), microphone=()");
        let mw = SecurityHeadersMiddleware::new(FnHandler::new(ok_handler), policy);
        let resp = mw.call(make_request());

        assert_eq!(
            resp.headers.get("permissions-policy").unwrap(),
            "camera=(), microphone=()"
        );
    }

    #[test]
    fn custom_frame_options() {
        let policy = SecurityPolicy::default().with_frame_options("SAMEORIGIN");
        let mw = SecurityHeadersMiddleware::new(FnHandler::new(ok_handler), policy);
        let resp = mw.call(make_request());

        assert_eq!(resp.headers.get("x-frame-options").unwrap(), "SAMEORIGIN");
    }

    #[test]
    fn without_hsts() {
        let policy = SecurityPolicy::default().without_hsts();
        let mw = SecurityHeadersMiddleware::new(FnHandler::new(ok_handler), policy);
        let resp = mw.call(make_request());

        assert!(!resp.headers.contains_key("strict-transport-security"));
    }

    // --- No-overwrite behavior ---

    #[test]
    fn does_not_overwrite_existing_headers() {
        let mw = SecurityHeadersMiddleware::new(
            FnHandler::new(handler_with_existing_headers),
            SecurityPolicy::default(),
        );
        let resp = mw.call(make_request());

        // Existing headers should be preserved, not overwritten.
        assert_eq!(resp.headers.get("x-frame-options").unwrap(), "SAMEORIGIN");
        assert_eq!(resp.headers.get("referrer-policy").unwrap(), "no-referrer");

        // Headers not set by the handler should be added.
        assert_eq!(
            resp.headers.get("x-content-type-options").unwrap(),
            "nosniff"
        );
    }

    #[test]
    fn canonicalizes_existing_mixed_case_headers_without_overwriting_values() {
        let mw = SecurityHeadersMiddleware::new(
            FnHandler::new(handler_with_mixed_case_existing_headers),
            SecurityPolicy::default(),
        );
        let resp = mw.call(make_request());

        assert_eq!(resp.headers.get("x-frame-options").unwrap(), "SAMEORIGIN");
        assert_eq!(resp.headers.get("referrer-policy").unwrap(), "no-referrer");
        assert!(!resp.headers.contains_key("X-Frame-Options"));
        assert!(!resp.headers.contains_key("Referrer-Policy"));
    }

    // --- None policy ---

    #[test]
    fn none_policy_sets_no_headers() {
        let mw = SecurityHeadersMiddleware::new(FnHandler::new(ok_handler), SecurityPolicy::none());
        let resp = mw.call(make_request());

        assert!(!resp.headers.contains_key("x-content-type-options"));
        assert!(!resp.headers.contains_key("x-frame-options"));
        assert!(!resp.headers.contains_key("referrer-policy"));
        assert!(!resp.headers.contains_key("strict-transport-security"));
        assert!(!resp.headers.contains_key("content-security-policy"));
        assert!(!resp.headers.contains_key("permissions-policy"));
    }

    #[test]
    fn none_policy_preserves_server_header() {
        let mw = SecurityHeadersMiddleware::new(
            FnHandler::new(handler_with_server_header),
            SecurityPolicy::none(),
        );
        let resp = mw.call(make_request());

        assert_eq!(
            resp.headers.get("server").unwrap(),
            "asupersync/0.2.6",
            "none policy should not strip server header"
        );
    }

    // --- Data type coverage ---

    #[test]
    fn security_policy_debug_clone() {
        let policy = SecurityPolicy::default();
        let dbg = format!("{policy:?}");
        assert!(dbg.contains("SecurityPolicy"), "{dbg}");
        let cloned = policy;
        assert_eq!(
            cloned.content_type_options.as_deref(),
            Some("nosniff"),
            "clone should preserve values"
        );
    }
}
