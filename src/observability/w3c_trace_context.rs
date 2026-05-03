//! W3C Trace Context propagation for cross-runtime boundaries.
//!
//! Implements W3C Trace Context specification (https://w3c.github.io/trace-context/)
//! for span-context propagation between HTTP servers and gRPC clients.
//!
//! # Key Features
//!
//! - **traceparent header extraction** from HTTP requests
//! - **tracestate preservation** across service boundaries
//! - **Span context injection** into gRPC metadata
//! - **Format validation** with security bounds
//! - **Error resilience** (graceful degradation on invalid context)
//!
//! # Usage
//!
//! ```ignore
//! use asupersync::observability::w3c_trace_context::{W3CTraceContext, extract_from_http, inject_to_grpc};
//!
//! // Extract from incoming HTTP request
//! let ctx = extract_from_http(request.headers())?;
//!
//! // Create child span for downstream operation
//! let child_ctx = ctx.create_child();
//!
//! // Inject into outbound gRPC call
//! inject_to_grpc(&child_ctx, &mut grpc_request.metadata_mut());
//! ```

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

/// Maximum length for trace context values to prevent amplification attacks.
/// Aligned with web middleware bounds (br-asupersync-pol3ps).
const MAX_TRACE_CONTEXT_LENGTH: usize = 128;

/// W3C Trace Context representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct W3CTraceContext {
    /// 16-byte trace ID (32 hex chars)
    pub trace_id: TraceId,
    /// 8-byte span ID (16 hex chars)
    pub parent_span_id: SpanId,
    /// Current span ID (16 hex chars)
    pub span_id: SpanId,
    /// Trace flags (sampled, debug, etc.)
    pub flags: TraceFlags,
    /// Optional tracestate for vendor-specific data
    pub tracestate: Option<String>,
}

/// 16-byte trace identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceId([u8; 16]);

/// 8-byte span identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpanId([u8; 8]);

/// W3C trace flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceFlags(u8);

impl TraceFlags {
    /// No flags set.
    pub const NONE: Self = Self(0);
    /// Trace is sampled.
    pub const SAMPLED: Self = Self(0x01);

    /// Returns true if sampled flag is set.
    #[must_use]
    pub const fn is_sampled(self) -> bool {
        self.0 & 0x01 != 0
    }

    /// Returns the raw trace-flags byte.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone)]
pub enum TraceContextError {
    /// Invalid traceparent format.
    InvalidFormat(String),
    /// Trace ID is all zeros (invalid).
    InvalidTraceId,
    /// Span ID is all zeros (invalid).
    InvalidSpanId,
    /// Header value too long (security bound).
    ValueTooLong(usize),
}

impl fmt::Display for TraceContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat(msg) => write!(f, "invalid traceparent format: {msg}"),
            Self::InvalidTraceId => write!(f, "trace ID cannot be all zeros"),
            Self::InvalidSpanId => write!(f, "span ID cannot be all zeros"),
            Self::ValueTooLong(len) => write!(
                f,
                "trace context too long: {len} > {MAX_TRACE_CONTEXT_LENGTH}"
            ),
        }
    }
}

impl std::error::Error for TraceContextError {}

impl TraceId {
    /// Creates a new random trace ID.
    #[must_use]
    pub fn new_random() -> Self {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).expect("failed to generate random trace ID");
        Self(bytes)
    }

    /// Returns trace ID as hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl FromStr for TraceId {
    type Err = TraceContextError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 32 {
            return Err(TraceContextError::InvalidFormat(
                "trace ID must be 32 hex chars".into(),
            ));
        }

        let bytes = hex::decode(s)
            .map_err(|_| TraceContextError::InvalidFormat("invalid hex in trace ID".into()))?;

        if bytes == [0u8; 16] {
            return Err(TraceContextError::InvalidTraceId);
        }

        let mut array = [0u8; 16];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
}

impl SpanId {
    /// Creates a new random span ID.
    #[must_use]
    pub fn new_random() -> Self {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).expect("failed to generate random span ID");
        Self(bytes)
    }

    /// Returns span ID as hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl FromStr for SpanId {
    type Err = TraceContextError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 16 {
            return Err(TraceContextError::InvalidFormat(
                "span ID must be 16 hex chars".into(),
            ));
        }

        let bytes = hex::decode(s)
            .map_err(|_| TraceContextError::InvalidFormat("invalid hex in span ID".into()))?;

        if bytes == [0u8; 8] {
            return Err(TraceContextError::InvalidSpanId);
        }

        let mut array = [0u8; 8];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
}

impl W3CTraceContext {
    /// Creates a new root trace context.
    #[must_use]
    pub fn new_root() -> Self {
        Self {
            trace_id: TraceId::new_random(),
            parent_span_id: SpanId::new_random(),
            span_id: SpanId::new_random(),
            flags: TraceFlags::SAMPLED,
            tracestate: None,
        }
    }

    /// Creates a child context with new span ID.
    #[must_use]
    pub fn create_child(&self) -> Self {
        Self {
            trace_id: self.trace_id,
            parent_span_id: self.span_id,
            span_id: SpanId::new_random(),
            flags: self.flags,
            tracestate: self.tracestate.clone(),
        }
    }

    /// Formats as W3C traceparent header value.
    #[must_use]
    pub fn to_traceparent(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            self.trace_id.to_hex(),
            self.span_id.to_hex(),
            self.flags.0
        )
    }
}

impl FromStr for W3CTraceContext {
    type Err = TraceContextError;

    fn from_str(traceparent: &str) -> Result<Self, Self::Err> {
        // Security: Bound input length to prevent amplification
        if traceparent.len() > MAX_TRACE_CONTEXT_LENGTH {
            return Err(TraceContextError::ValueTooLong(traceparent.len()));
        }

        let parts: Vec<&str> = traceparent.split('-').collect();
        if parts.len() != 4 {
            return Err(TraceContextError::InvalidFormat(
                "must have 4 dash-separated parts".into(),
            ));
        }

        // Parse version (must be 00)
        if parts[0] != "00" {
            return Err(TraceContextError::InvalidFormat(
                "unsupported version".into(),
            ));
        }

        // Parse trace ID
        let trace_id = TraceId::from_str(parts[1])?;

        // Parse span ID
        let span_id = SpanId::from_str(parts[2])?;

        // Parse flags
        let flags_byte = u8::from_str_radix(parts[3], 16)
            .map_err(|_| TraceContextError::InvalidFormat("invalid flags hex".into()))?;

        Ok(Self {
            trace_id,
            parent_span_id: span_id, // Current span becomes parent of future child
            span_id,
            flags: TraceFlags(flags_byte),
            tracestate: None,
        })
    }
}

/// Extracts W3C trace context from HTTP headers.
///
/// Returns `None` if no trace context headers present (not an error).
/// Returns `Err` only on malformed context that should be logged.
pub fn extract_from_http(
    headers: &HashMap<String, String>,
) -> Result<Option<W3CTraceContext>, TraceContextError> {
    let traceparent = match headers.get("traceparent") {
        Some(value) => value,
        None => return Ok(None), // No trace context present
    };

    let mut context = W3CTraceContext::from_str(traceparent)?;

    // Extract tracestate if present
    if let Some(tracestate) = headers.get("tracestate") {
        if tracestate.len() <= MAX_TRACE_CONTEXT_LENGTH {
            context.tracestate = Some(tracestate.clone());
        }
    }

    Ok(Some(context))
}

/// Injects W3C trace context into gRPC metadata.
pub fn inject_to_grpc(context: &W3CTraceContext, metadata: &mut HashMap<String, String>) {
    metadata.insert("traceparent".to_string(), context.to_traceparent());

    if let Some(ref tracestate) = context.tracestate {
        metadata.insert("tracestate".to_string(), tracestate.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_context_round_trip() {
        let original = W3CTraceContext::new_root();
        let traceparent = original.to_traceparent();
        let parsed = W3CTraceContext::from_str(&traceparent).expect("parse failed");

        assert_eq!(original.trace_id, parsed.trace_id);
        assert_eq!(original.span_id, parsed.span_id);
        assert_eq!(original.flags.0, parsed.flags.0);
    }

    #[test]
    fn extract_from_http_missing_headers() {
        let headers = HashMap::new();
        let result = extract_from_http(&headers).expect("extraction failed");
        assert!(result.is_none());
    }

    #[test]
    fn extract_from_http_valid_context() {
        let mut headers = HashMap::new();
        headers.insert(
            "traceparent".to_string(),
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string(),
        );

        let result = extract_from_http(&headers).expect("extraction failed");
        let context = result.expect("context should be present");

        assert!(context.flags.is_sampled());
        assert_eq!(
            context.to_traceparent(),
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        );
    }

    #[test]
    fn inject_to_grpc_includes_headers() {
        let context = W3CTraceContext::new_root();
        let mut metadata = HashMap::new();

        inject_to_grpc(&context, &mut metadata);

        assert!(metadata.contains_key("traceparent"));
        assert_eq!(metadata["traceparent"], context.to_traceparent());
    }

    #[test]
    fn child_context_preserves_trace_id() {
        let parent = W3CTraceContext::new_root();
        let child = parent.create_child();

        assert_eq!(parent.trace_id, child.trace_id);
        assert_eq!(parent.span_id, child.parent_span_id);
        assert_ne!(parent.span_id, child.span_id);
    }

    #[test]
    fn security_bounds_prevent_amplification() {
        let long_traceparent = "00-".to_string() + &"a".repeat(200);
        let result = W3CTraceContext::from_str(&long_traceparent);

        assert!(matches!(result, Err(TraceContextError::ValueTooLong(_))));
    }

    #[test]
    fn invalid_trace_id_rejected() {
        let invalid = "00-00000000000000000000000000000000-00f067aa0ba902b7-01";
        let result = W3CTraceContext::from_str(invalid);

        assert!(matches!(result, Err(TraceContextError::InvalidTraceId)));
    }
}
