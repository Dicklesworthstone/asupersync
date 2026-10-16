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
//! | `content-security-policy` | `default-src 'self'; script-src 'self'; ...` | Restrict content sources (XSS protection) |
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

    /// Value for `Content-Security-Policy`. Default: `"default-src 'self';
    /// script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'
    /// data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'"`.
    /// Set to `None` to send no CSP.
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
            // asupersync-7kjtmf: provide safe CSP default to prevent XSS
            content_security_policy: Some("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'".to_string()),
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
/// ```
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
    fn call(
        &self,
        cx: &crate::Cx,
        req: Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            let mut resp = self.inner.call(&cx, req).await;

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
        })
    }
}

#[cfg(test)]
#[path = "security_inline_tests.rs"]
mod tests;
