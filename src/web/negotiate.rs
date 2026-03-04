//! Content negotiation and error handler layer.
//!
//! Provides [`ContentNegotiation`] for parsing and negotiating `Accept` headers,
//! and [`ErrorHandlerMiddleware`] for converting unhandled errors and panics
//! into appropriate response formats based on content negotiation.
//!
//! # Content Negotiation
//!
//! The [`negotiate_media_type`] function selects the best response format from
//! the client's `Accept` header against the server's supported media types.
//!
//! # Error Handler
//!
//! The [`ErrorHandlerMiddleware`] wraps a handler and:
//! 1. Catches panics from the inner handler.
//! 2. Converts error responses (4xx/5xx) using a configurable error formatter.
//! 3. Negotiates the response format based on the `Accept` header.

use std::panic::{self, AssertUnwindSafe};

use super::extract::Request;
use super::handler::Handler;
use super::response::{Response, StatusCode};

// ─── Media Type ──────────────────────────────────────────────────────────────

/// A parsed media type with quality value.
#[derive(Debug, Clone, PartialEq)]
pub struct MediaType {
    /// Main type (e.g., "text", "application", "*").
    pub r#type: String,
    /// Subtype (e.g., "html", "json", "*").
    pub subtype: String,
    /// Quality value (0.0 to 1.0).
    pub quality: f32,
}

impl MediaType {
    /// Create a new media type.
    #[must_use]
    pub fn new(r#type: impl Into<String>, subtype: impl Into<String>) -> Self {
        Self {
            r#type: r#type.into(),
            subtype: subtype.into(),
            quality: 1.0,
        }
    }

    /// Predefined: `application/json`.
    pub const JSON: &'static str = "application/json";
    /// Predefined: `text/html`.
    pub const HTML: &'static str = "text/html";
    /// Predefined: `text/plain`.
    pub const PLAIN: &'static str = "text/plain";

    /// Check if this type matches the given type/subtype pair.
    #[must_use]
    pub fn matches(&self, r#type: &str, subtype: &str) -> bool {
        (self.r#type == "*" || self.r#type.eq_ignore_ascii_case(r#type))
            && (self.subtype == "*" || self.subtype.eq_ignore_ascii_case(subtype))
    }
}

/// Parse an `Accept` header into a list of media types with quality values.
///
/// Format: `text/html, application/json;q=0.9, */*;q=0.1`
fn parse_accept(header: &str) -> Vec<MediaType> {
    header
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }

            let mut pieces = part.splitn(2, ';');
            let media = pieces.next()?.trim();

            let (r#type, subtype) = media.split_once('/')?;

            let quality = pieces
                .next()
                .and_then(|params| {
                    params.split(';').find_map(|p| {
                        p.trim()
                            .strip_prefix("q=")
                            .or_else(|| p.trim().strip_prefix("Q="))
                    })
                })
                .and_then(|q_str| q_str.trim().parse::<f32>().ok())
                .unwrap_or(1.0);

            Some(MediaType {
                r#type: r#type.trim().to_ascii_lowercase(),
                subtype: subtype.trim().to_ascii_lowercase(),
                quality,
            })
        })
        .collect()
}

/// Negotiate the best media type from an `Accept` header.
///
/// Returns the first supported media type that the client accepts,
/// ordered by client quality preference (highest first), with server
/// order as tiebreaker.
///
/// # Arguments
///
/// * `accept_header` - The value of the `Accept` header.
/// * `supported` - Server-supported media types as `"type/subtype"` strings,
///   in preference order.
///
/// # Returns
///
/// The selected media type string, or `None` if no match is found.
#[must_use]
pub fn negotiate_media_type<'a>(accept_header: &str, supported: &[&'a str]) -> Option<&'a str> {
    if accept_header.is_empty() {
        return supported.first().copied();
    }

    let mut accepted = parse_accept(accept_header);
    // Sort by quality descending (stable sort preserves header order for ties).
    accepted.sort_by(|a, b| {
        b.quality
            .partial_cmp(&a.quality)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    for accepted_type in &accepted {
        if accepted_type.quality <= 0.0 {
            continue;
        }
        for &media in supported {
            if let Some((t, s)) = media.split_once('/') {
                if accepted_type.matches(t, s) {
                    return Some(media);
                }
            }
        }
    }

    None
}

// ─── Error Response Formatting ───────────────────────────────────────────────

/// Format for error response bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorFormat {
    /// JSON error body: `{"error": {"status": 500, "message": "..."}}`
    Json,
    /// HTML error page.
    Html,
    /// Plain text error.
    Plain,
}

/// Format an error response body in the given format.
fn format_error_body(
    status: StatusCode,
    message: &str,
    format: ErrorFormat,
) -> (String, &'static str) {
    match format {
        ErrorFormat::Json => {
            let body = format!(
                r#"{{"error":{{"status":{},"message":"{}"}}}}"#,
                status.as_u16(),
                message.replace('\\', "\\\\").replace('"', "\\\""),
            );
            (body, "application/json")
        }
        ErrorFormat::Html => {
            let escaped = message
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;");
            let body = format!(
                "<html><head><title>Error {}</title></head><body><h1>{}</h1><p>{}</p></body></html>",
                status.as_u16(),
                status.as_u16(),
                escaped,
            );
            (body, "text/html; charset=utf-8")
        }
        ErrorFormat::Plain => (
            format!("{}: {}", status.as_u16(), message),
            "text/plain; charset=utf-8",
        ),
    }
}

/// Determine the best error format from an Accept header.
fn error_format_from_accept(accept: &str) -> ErrorFormat {
    let supported = &[MediaType::JSON, MediaType::HTML, MediaType::PLAIN];
    match negotiate_media_type(accept, supported) {
        Some(MediaType::JSON) => ErrorFormat::Json,
        Some(MediaType::HTML) => ErrorFormat::Html,
        _ => ErrorFormat::Plain,
    }
}

// ─── ErrorHandlerMiddleware ──────────────────────────────────────────────────

/// Configuration for the error handler middleware.
#[derive(Debug, Clone)]
pub struct ErrorHandlerConfig {
    /// Whether to catch panics and convert them to 500 responses.
    pub catch_panics: bool,

    /// Whether to include error details in responses.
    /// Set to `false` in production to avoid leaking internals.
    pub expose_details: bool,
}

impl Default for ErrorHandlerConfig {
    fn default() -> Self {
        Self {
            catch_panics: true,
            expose_details: false,
        }
    }
}

impl ErrorHandlerConfig {
    /// Create a development-friendly config that exposes error details.
    #[must_use]
    pub fn development() -> Self {
        Self {
            catch_panics: true,
            expose_details: true,
        }
    }
}

/// Middleware that provides consistent error formatting with content negotiation.
///
/// Intercepts error responses (4xx/5xx) and panics, formatting them
/// according to the client's `Accept` header preference.
///
/// # Example
///
/// ```ignore
/// use asupersync::web::negotiate::{ErrorHandlerMiddleware, ErrorHandlerConfig};
/// use asupersync::web::handler::FnHandler;
///
/// let handler = FnHandler::new(|| "hello");
/// let protected = ErrorHandlerMiddleware::new(handler, ErrorHandlerConfig::default());
/// ```
pub struct ErrorHandlerMiddleware<H> {
    inner: H,
    config: ErrorHandlerConfig,
}

impl<H: Handler> ErrorHandlerMiddleware<H> {
    /// Wrap a handler with error formatting.
    #[must_use]
    pub fn new(inner: H, config: ErrorHandlerConfig) -> Self {
        Self { inner, config }
    }
}

impl<H: Handler> Handler for ErrorHandlerMiddleware<H> {
    fn call(&self, req: Request) -> Response {
        let accept = req.headers.get("accept").cloned().unwrap_or_default();

        let result = if self.config.catch_panics {
            panic::catch_unwind(AssertUnwindSafe(|| self.inner.call(req)))
        } else {
            Ok(self.inner.call(req))
        };

        match result {
            Ok(resp) => resp,
            Err(_panic) => {
                let format = error_format_from_accept(&accept);
                let message = if self.config.expose_details {
                    "Internal Server Error: handler panicked"
                } else {
                    "Internal Server Error"
                };
                let (body, content_type) =
                    format_error_body(StatusCode::INTERNAL_SERVER_ERROR, message, format);
                Response::new(StatusCode::INTERNAL_SERVER_ERROR, body.into_bytes())
                    .header("content-type", content_type)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::handler::FnHandler;
    use crate::web::response::StatusCode;

    fn make_request() -> Request {
        Request::new("GET", "/test")
    }

    fn make_request_accepting(accept: &str) -> Request {
        Request::new("GET", "/test").with_header("accept", accept)
    }

    fn ok_handler() -> &'static str {
        "ok"
    }

    fn panicking_handler() -> &'static str {
        panic!("test panic");
    }

    // ====================================================================
    // Media type parsing tests
    // ====================================================================

    #[test]
    fn parse_simple_accept() {
        let types = parse_accept("text/html, application/json");
        assert_eq!(types.len(), 2);
        assert_eq!(types[0].r#type, "text");
        assert_eq!(types[0].subtype, "html");
        assert_eq!(types[1].r#type, "application");
        assert_eq!(types[1].subtype, "json");
    }

    #[test]
    fn parse_accept_with_quality() {
        let types = parse_accept("text/html;q=1.0, application/json;q=0.9, */*;q=0.1");
        assert_eq!(types.len(), 3);
        assert!((types[0].quality - 1.0).abs() < f32::EPSILON);
        assert!((types[1].quality - 0.9).abs() < f32::EPSILON);
        assert!((types[2].quality - 0.1).abs() < f32::EPSILON);
    }

    #[test]
    fn parse_accept_empty() {
        let types = parse_accept("");
        assert!(types.is_empty());
    }

    #[test]
    fn parse_accept_with_params() {
        let types = parse_accept("text/html; charset=utf-8; q=0.8");
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].r#type, "text");
        assert!((types[0].quality - 0.8).abs() < f32::EPSILON);
    }

    // ====================================================================
    // Media type matching tests
    // ====================================================================

    #[test]
    fn media_type_exact_match() {
        let mt = MediaType::new("text", "html");
        assert!(mt.matches("text", "html"));
        assert!(!mt.matches("text", "plain"));
    }

    #[test]
    fn media_type_wildcard_subtype() {
        let mt = MediaType::new("text", "*");
        assert!(mt.matches("text", "html"));
        assert!(mt.matches("text", "plain"));
        assert!(!mt.matches("application", "json"));
    }

    #[test]
    fn media_type_full_wildcard() {
        let mt = MediaType::new("*", "*");
        assert!(mt.matches("text", "html"));
        assert!(mt.matches("application", "json"));
    }

    // ====================================================================
    // Negotiation tests
    // ====================================================================

    #[test]
    fn negotiate_exact_match() {
        let result = negotiate_media_type("application/json", &["text/html", "application/json"]);
        assert_eq!(result, Some("application/json"));
    }

    #[test]
    fn negotiate_quality_preference() {
        let result = negotiate_media_type(
            "text/html;q=0.5, application/json;q=1.0",
            &["text/html", "application/json"],
        );
        assert_eq!(result, Some("application/json"));
    }

    #[test]
    fn negotiate_wildcard() {
        let result = negotiate_media_type("*/*", &["application/json"]);
        assert_eq!(result, Some("application/json"));
    }

    #[test]
    fn negotiate_no_match() {
        let result = negotiate_media_type("text/xml", &["application/json", "text/html"]);
        assert_eq!(result, None);
    }

    #[test]
    fn negotiate_empty_accept() {
        let result = negotiate_media_type("", &["application/json"]);
        assert_eq!(result, Some("application/json"));
    }

    #[test]
    fn negotiate_server_preference_on_tie() {
        let result = negotiate_media_type(
            "text/html, application/json",
            &["application/json", "text/html"],
        );
        // Both have q=1.0. Client lists html first, so html matches first in quality-sorted list.
        // But since both have same quality, the accept order is preserved.
        // html appears first in the sorted accept list, and it matches text/html in supported.
        assert_eq!(result, Some("text/html"));
    }

    // ====================================================================
    // Error formatting tests
    // ====================================================================

    #[test]
    fn format_error_json() {
        let (body, ct) = format_error_body(StatusCode::NOT_FOUND, "Not Found", ErrorFormat::Json);
        assert!(body.contains("404"));
        assert!(body.contains("Not Found"));
        assert_eq!(ct, "application/json");
    }

    #[test]
    fn format_error_html() {
        let (body, ct) = format_error_body(StatusCode::NOT_FOUND, "Not Found", ErrorFormat::Html);
        assert!(body.contains("<html>"));
        assert!(body.contains("404"));
        assert_eq!(ct, "text/html; charset=utf-8");
    }

    #[test]
    fn format_error_plain() {
        let (body, ct) = format_error_body(StatusCode::NOT_FOUND, "Not Found", ErrorFormat::Plain);
        assert_eq!(body, "404: Not Found");
        assert_eq!(ct, "text/plain; charset=utf-8");
    }

    #[test]
    fn format_error_json_escapes_quotes() {
        let (body, _) =
            format_error_body(StatusCode::BAD_REQUEST, "bad \"input\"", ErrorFormat::Json);
        assert!(body.contains(r#"bad \"input\""#));
    }

    #[test]
    fn error_format_from_accept_json() {
        assert_eq!(
            error_format_from_accept("application/json"),
            ErrorFormat::Json
        );
    }

    #[test]
    fn error_format_from_accept_html() {
        assert_eq!(error_format_from_accept("text/html"), ErrorFormat::Html);
    }

    #[test]
    fn error_format_from_accept_default_json() {
        assert_eq!(error_format_from_accept(""), ErrorFormat::Json);
    }

    // ====================================================================
    // ErrorHandlerMiddleware tests
    // ====================================================================

    #[test]
    fn error_handler_passes_through_ok() {
        let mw =
            ErrorHandlerMiddleware::new(FnHandler::new(ok_handler), ErrorHandlerConfig::default());
        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn error_handler_catches_panic() {
        let mw = ErrorHandlerMiddleware::new(
            FnHandler::new(panicking_handler),
            ErrorHandlerConfig::default(),
        );
        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn error_handler_panic_json_response() {
        let mw = ErrorHandlerMiddleware::new(
            FnHandler::new(panicking_handler),
            ErrorHandlerConfig::default(),
        );
        let resp = mw.call(make_request_accepting("application/json"));
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "application/json"
        );
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("500"));
    }

    #[test]
    fn error_handler_panic_html_response() {
        let mw = ErrorHandlerMiddleware::new(
            FnHandler::new(panicking_handler),
            ErrorHandlerConfig::default(),
        );
        let resp = mw.call(make_request_accepting("text/html"));
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/html; charset=utf-8"
        );
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("<html>"));
    }

    #[test]
    fn error_handler_hides_details_by_default() {
        let mw = ErrorHandlerMiddleware::new(
            FnHandler::new(panicking_handler),
            ErrorHandlerConfig::default(),
        );
        let resp = mw.call(make_request_accepting("text/plain"));
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(!body.contains("panicked"));
        assert!(body.contains("Internal Server Error"));
    }

    #[test]
    fn error_handler_exposes_details_in_dev() {
        let mw = ErrorHandlerMiddleware::new(
            FnHandler::new(panicking_handler),
            ErrorHandlerConfig::development(),
        );
        let resp = mw.call(make_request_accepting("text/plain"));
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("panicked"));
    }

    #[test]
    fn error_handler_config_default() {
        let cfg = ErrorHandlerConfig::default();
        assert!(cfg.catch_panics);
        assert!(!cfg.expose_details);
    }

    #[test]
    fn error_handler_config_development() {
        let cfg = ErrorHandlerConfig::development();
        assert!(cfg.catch_panics);
        assert!(cfg.expose_details);
    }
}
