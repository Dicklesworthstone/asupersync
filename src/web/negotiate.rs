//! Content negotiation and error handler layer.
//!
//! Provides content-negotiation helpers for parsing and negotiating `Accept` headers,
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

use super::extract::Request;
use super::handler::Handler;
use super::response::{Response, StatusCode};
use crate::tracing_compat::error;
use std::cmp::Ordering;
use std::panic::AssertUnwindSafe;

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

    #[must_use]
    fn specificity_for(&self, r#type: &str, subtype: &str) -> Option<u8> {
        if !self.matches(r#type, subtype) {
            return None;
        }

        Some(if self.r#type == "*" {
            0
        } else if self.subtype == "*" {
            1
        } else {
            2
        })
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

            let mut pieces = part.split(';');
            let media = pieces.next()?.trim();

            let (r#type, subtype) = media.split_once('/')?;

            let mut quality = 1.0;
            for param in pieces {
                let param = param.trim();
                let Some(q_str) = param
                    .strip_prefix("q=")
                    .or_else(|| param.strip_prefix("Q="))
                else {
                    continue;
                };

                let parsed_quality = q_str.trim().parse::<f32>().ok()?;
                if !parsed_quality.is_finite() || !(0.0..=1.0).contains(&parsed_quality) {
                    return None;
                }
                quality = parsed_quality;
                break;
            }

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
/// Returns the best supported media type that the client accepts.
///
/// For a given supported media type, more specific client ranges override
/// broader wildcards even when the wildcard has a higher `q` value. Across
/// equally acceptable supported media types, client header order breaks ties,
/// with server order as the final fallback.
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
    let accept_header = accept_header.trim();
    if accept_header.is_empty() {
        return supported.first().copied();
    }

    let accepted = parse_accept(accept_header);
    if accepted.is_empty() {
        return supported.first().copied();
    }
    let mut best_match: Option<(&str, f32, usize)> = None;

    for &media in supported {
        let Some((r#type, subtype)) = media.split_once('/') else {
            continue;
        };

        let mut best_quality_for_media: Option<(u8, f32, usize)> = None;
        for (index, accepted_type) in accepted.iter().enumerate() {
            let Some(specificity) = accepted_type.specificity_for(r#type, subtype) else {
                continue;
            };

            match best_quality_for_media {
                Some((best_specificity, best_quality, best_index))
                    if best_specificity > specificity
                        || (best_specificity == specificity
                            && match best_quality
                                .partial_cmp(&accepted_type.quality)
                                .unwrap_or(Ordering::Equal)
                            {
                                Ordering::Greater => true,
                                Ordering::Equal => best_index <= index,
                                Ordering::Less => false,
                            }) => {}
                _ => best_quality_for_media = Some((specificity, accepted_type.quality, index)),
            }
        }

        let Some((_, quality, accept_index)) = best_quality_for_media else {
            continue;
        };
        if quality <= 0.0 {
            continue;
        }

        match best_match {
            Some((_, best_quality, best_index))
                if match best_quality
                    .partial_cmp(&quality)
                    .unwrap_or(Ordering::Equal)
                {
                    Ordering::Greater => true,
                    Ordering::Equal => best_index <= accept_index,
                    Ordering::Less => false,
                } => {}
            _ => best_match = Some((media, quality, accept_index)),
        }
    }

    best_match.map(|(media, _, _)| media)
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
            let escaped = serde_json::to_string(message)
                .unwrap_or_else(|_| r#""Internal Server Error""#.to_string());
            let body = format!(
                r#"{{"error":{{"status":{},"message":{}}}}}"#,
                status.as_u16(),
                escaped,
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

fn default_error_message(status: StatusCode) -> &'static str {
    match status {
        StatusCode::BAD_REQUEST => "Bad Request",
        StatusCode::UNAUTHORIZED => "Unauthorized",
        StatusCode::FORBIDDEN => "Forbidden",
        StatusCode::NOT_FOUND => "Not Found",
        StatusCode::METHOD_NOT_ALLOWED => "Method Not Allowed",
        StatusCode::CONFLICT => "Conflict",
        StatusCode::PAYLOAD_TOO_LARGE => "Payload Too Large",
        StatusCode::UNSUPPORTED_MEDIA_TYPE => "Unsupported Media Type",
        StatusCode::UNPROCESSABLE_ENTITY => "Unprocessable Entity",
        StatusCode::TOO_MANY_REQUESTS => "Too Many Requests",
        StatusCode::CLIENT_CLOSED_REQUEST => "Client Closed Request",
        StatusCode::INTERNAL_SERVER_ERROR => "Internal Server Error",
        StatusCode::NOT_IMPLEMENTED => "Not Implemented",
        StatusCode::BAD_GATEWAY => "Bad Gateway",
        StatusCode::SERVICE_UNAVAILABLE => "Service Unavailable",
        StatusCode::GATEWAY_TIMEOUT => "Gateway Timeout",
        _ if status.is_client_error() => "Client Error",
        _ if status.is_server_error() => "Internal Server Error",
        _ => "Error",
    }
}

fn error_message_from_response(resp: &Response, expose_details: bool) -> String {
    if expose_details {
        if let Ok(message) = std::str::from_utf8(&resp.body) {
            let trimmed = message.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }

    default_error_message(resp.status).to_string()
}

fn format_error_response(resp: Response, accept: &str, expose_details: bool) -> Response {
    if !(resp.status.is_client_error() || resp.status.is_server_error()) {
        return resp;
    }

    let message = error_message_from_response(&resp, expose_details);
    format_error_response_with_message(resp, accept, &message)
}

fn format_error_response_with_message(mut resp: Response, accept: &str, message: &str) -> Response {
    let format = error_format_from_accept(accept);
    let (body, content_type) = format_error_body(resp.status, message, format);
    resp.body = body.into_bytes().into();
    let _ = resp.remove_header("content-length");
    let _ = resp.remove_header("content-encoding");
    let _ = resp.remove_header("etag");
    resp.set_header("content-type", content_type);
    resp
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
/// ```
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
    fn call(
        &self,
        cx: &crate::Cx,
        req: Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            let method = req.method.clone();
            let path = req.path.clone();
            let trace_id = super::middleware::resolve_trace_id(&req);
            let accept = req
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("accept"))
                .map(|(_, v)| v.clone())
                .unwrap_or_default();

            let result = if self.config.catch_panics {
                match std::panic::catch_unwind(AssertUnwindSafe(|| self.inner.call(&cx, req))) {
                    Ok(future) => crate::util::future::catch_unwind(AssertUnwindSafe(future)).await,
                    Err(payload) => Err(payload),
                }
            } else {
                Ok(self.inner.call(&cx, req).await)
            };

            match result {
                Ok(resp) => format_error_response(resp, &accept, self.config.expose_details),
                Err(payload) => {
                    let panic_message = super::middleware::panic_payload_message(payload.as_ref());
                    let _panic_log_fields = (&method, &path, &trace_id, &panic_message);
                    error!(
                        method = %method,
                        path = %path,
                        trace_id = trace_id.as_deref().unwrap_or(""),
                        panic_message = %panic_message,
                        "[ASUP-E502] web handler panic recovered"
                    );
                    let message = if self.config.expose_details {
                        "[ASUP-E502] Internal Server Error: handler panicked"
                    } else {
                        "[ASUP-E502] Internal Server Error"
                    };
                    format_error_response_with_message(
                        Response::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            message.as_bytes().to_vec(),
                        ),
                        &accept,
                        message,
                    )
                }
            }
        })
    }
}

#[cfg(test)]
#[path = "negotiate_inline_tests.rs"]
mod tests;
