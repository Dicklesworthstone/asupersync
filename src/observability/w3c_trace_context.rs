//! W3C Trace Context propagation for cross-runtime boundaries.
//!
//! Implements the W3C Trace Context specification (<https://w3c.github.io/trace-context/>)
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
//! ```
//! use asupersync::observability::w3c_trace_context::{
//!     TraceContextError, W3CTraceContext, extract_from_http, inject_to_grpc,
//! };
//! use std::collections::HashMap;
//!
//! // Headers of an incoming HTTP request (lower-case names).
//! let upstream = W3CTraceContext::new_root();
//! let mut headers = HashMap::new();
//! headers.insert("traceparent".to_string(), upstream.to_traceparent());
//!
//! // Extract from incoming HTTP request (`None` when it carries no context)
//! let ctx = extract_from_http(&headers)?.unwrap_or_else(W3CTraceContext::new_root);
//!
//! // Create child span for downstream operation
//! let child_ctx = ctx.create_child();
//! assert_eq!(child_ctx.trace_id, upstream.trace_id);
//!
//! // Inject into outbound gRPC metadata
//! let mut metadata = HashMap::new();
//! inject_to_grpc(&child_ctx, &mut metadata);
//! assert!(metadata.contains_key("traceparent"));
//! # Ok::<(), TraceContextError>(())
//! ```

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::hash::BuildHasher;
use std::str::FromStr;

/// Maximum length for trace context values to prevent amplification attacks.
/// Aligned with web middleware bounds (br-asupersync-pol3ps).
const MAX_TRACE_CONTEXT_LENGTH: usize = 128;
const MAX_BAGGAGE_HEADER_LENGTH: usize = 8192;
const MAX_BAGGAGE_ITEMS: usize = 64;

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
    /// W3C baggage entries propagated alongside, but independent from, trace context.
    pub baggage: W3CBaggage,
}

/// W3C propagation data extracted from headers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct W3CPropagationContext {
    /// Optional trace context. Baggage can be present without it.
    pub trace_context: Option<W3CTraceContext>,
    /// Baggage entries from the `baggage` header.
    pub baggage: W3CBaggage,
}

/// W3C Baggage entries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct W3CBaggage {
    entries: BTreeMap<String, W3CBaggageEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct W3CBaggageEntry {
    value: String,
    metadata: Option<String>,
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

/// Errors raised while parsing or formatting W3C trace context and baggage headers.
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
    /// Invalid W3C baggage member.
    InvalidBaggage(String),
    /// Too many baggage members.
    TooManyBaggageItems(usize),
}

impl fmt::Display for TraceContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat(msg) => write!(f, "invalid traceparent format: {msg}"),
            Self::InvalidTraceId => write!(f, "trace ID cannot be all zeros"),
            Self::InvalidSpanId => write!(f, "span ID cannot be all zeros"),
            Self::ValueTooLong(len) => write!(f, "header value too long: {len} bytes"),
            Self::InvalidBaggage(msg) => write!(f, "invalid baggage header: {msg}"),
            Self::TooManyBaggageItems(count) => {
                write!(f, "too many baggage members: {count} > {MAX_BAGGAGE_ITEMS}")
            }
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

impl W3CBaggage {
    /// Creates empty baggage.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true when no entries are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of baggage entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns a baggage value by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(|entry| entry.value.as_str())
    }

    /// Returns a baggage metadata property string by key.
    #[must_use]
    pub fn metadata(&self, key: &str) -> Option<&str> {
        self.entries
            .get(key)
            .and_then(|entry| entry.metadata.as_deref())
    }

    /// Iterates entries in deterministic key order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries
            .iter()
            .map(|(key, entry)| (key.as_str(), entry.value.as_str()))
    }

    /// Iterates entries with optional metadata in deterministic key order.
    pub fn iter_with_metadata(&self) -> impl Iterator<Item = (&str, &str, Option<&str>)> {
        self.entries.iter().map(|(key, entry)| {
            (
                key.as_str(),
                entry.value.as_str(),
                entry.metadata.as_deref(),
            )
        })
    }

    /// Inserts or replaces a baggage entry.
    pub fn insert(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), TraceContextError> {
        self.insert_with_metadata(key, value, Option::<String>::None)
    }

    /// Inserts or replaces a baggage entry with metadata.
    pub fn insert_with_metadata(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
        metadata: Option<impl Into<String>>,
    ) -> Result<(), TraceContextError> {
        let key = key.into();
        let value = value.into();
        let metadata = metadata.map(Into::into).filter(|value| !value.is_empty());
        validate_baggage_key(&key)?;
        validate_baggage_value(&value)?;
        if let Some(metadata) = metadata.as_deref() {
            validate_baggage_metadata(metadata)?;
        }
        if !self.entries.contains_key(&key) && self.entries.len() >= MAX_BAGGAGE_ITEMS {
            return Err(TraceContextError::TooManyBaggageItems(
                self.entries.len() + 1,
            ));
        }
        self.entries
            .insert(key, W3CBaggageEntry { value, metadata });
        Ok(())
    }

    /// Parses a W3C `baggage` header.
    pub fn from_header(header: &str) -> Result<Self, TraceContextError> {
        if header.len() > MAX_BAGGAGE_HEADER_LENGTH {
            return Err(TraceContextError::ValueTooLong(header.len()));
        }

        let mut baggage = Self::new();
        let mut valid_members = 0usize;
        for raw_member in header.split(',') {
            let member = raw_member.trim();
            if member.is_empty() {
                continue;
            }

            valid_members += 1;
            if valid_members > MAX_BAGGAGE_ITEMS {
                return Err(TraceContextError::TooManyBaggageItems(valid_members));
            }

            let (key, value_with_metadata) = member.split_once('=').ok_or_else(|| {
                TraceContextError::InvalidBaggage(format!("missing '=' in member `{member}`"))
            })?;
            let key = key.trim();
            validate_baggage_key(key)?;

            let (raw_value, metadata) = value_with_metadata
                .split_once(';')
                .map_or((value_with_metadata, None), |(value, metadata)| {
                    (value, Some(metadata.trim()))
                });
            let raw_value = raw_value.trim();
            let value = percent_decode_baggage_value(raw_value)?;
            validate_baggage_value(&value)?;
            let metadata = metadata
                .filter(|value| !value.is_empty())
                .map(ToString::to_string);
            if let Some(metadata) = metadata.as_deref() {
                validate_baggage_metadata(metadata)?;
            }
            baggage
                .entries
                .insert(key.to_string(), W3CBaggageEntry { value, metadata });
        }

        Ok(baggage)
    }

    /// Formats as a W3C `baggage` header.
    pub fn to_header(&self) -> Result<String, TraceContextError> {
        let header = self
            .entries
            .iter()
            .map(|(key, entry)| {
                let mut member = format!("{key}={}", percent_encode_baggage_value(&entry.value));
                if let Some(metadata) = &entry.metadata {
                    member.push(';');
                    member.push_str(metadata);
                }
                member
            })
            .collect::<Vec<_>>()
            .join(",");
        if header.len() > MAX_BAGGAGE_HEADER_LENGTH {
            return Err(TraceContextError::ValueTooLong(header.len()));
        }
        Ok(header)
    }
}

fn validate_baggage_key(key: &str) -> Result<(), TraceContextError> {
    if key.is_empty() {
        return Err(TraceContextError::InvalidBaggage(
            "member key is empty".to_string(),
        ));
    }
    if key.bytes().all(is_baggage_key_byte) {
        Ok(())
    } else {
        Err(TraceContextError::InvalidBaggage(format!(
            "invalid member key `{key}`"
        )))
    }
}

fn validate_baggage_value(value: &str) -> Result<(), TraceContextError> {
    if value.bytes().any(|byte| matches!(byte, 0x00..=0x1f | 0x7f)) {
        return Err(TraceContextError::InvalidBaggage(
            "member value contains control characters".to_string(),
        ));
    }
    Ok(())
}

fn validate_baggage_metadata(metadata: &str) -> Result<(), TraceContextError> {
    if metadata
        .bytes()
        .any(|byte| matches!(byte, 0x00..=0x1f | 0x7f))
    {
        return Err(TraceContextError::InvalidBaggage(
            "metadata contains control characters".to_string(),
        ));
    }
    if metadata.contains(',') {
        return Err(TraceContextError::InvalidBaggage(
            "metadata contains a list-member delimiter".to_string(),
        ));
    }
    Ok(())
}

fn is_baggage_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn percent_decode_baggage_value(value: &str) -> Result<String, TraceContextError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let Some(hex) = bytes.get(index + 1..index + 3) else {
                return Err(TraceContextError::InvalidBaggage(
                    "truncated percent escape".to_string(),
                ));
            };
            let hex = std::str::from_utf8(hex).map_err(|_| {
                TraceContextError::InvalidBaggage("invalid percent escape".to_string())
            })?;
            let byte = u8::from_str_radix(hex, 16).map_err(|_| {
                TraceContextError::InvalidBaggage("invalid percent escape".to_string())
            })?;
            decoded.push(byte);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded)
        .map_err(|_| TraceContextError::InvalidBaggage("value is not UTF-8".to_string()))
}

fn percent_encode_baggage_value(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'/'
                    | b':'
                    | b'<'
                    | b'>'
                    | b'?'
                    | b'@'
                    | b'['
                    | b']'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'{'
                    | b'|'
                    | b'}'
                    | b'~'
            )
        {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
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
            baggage: W3CBaggage::new(),
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
            baggage: self.baggage.clone(),
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

        // Parse flags. Like trace_id/parent_id above, the W3C version-00
        // traceparent format requires the flags to be exactly two hex digits.
        // `u8::from_str_radix` is too lenient here — it accepts a `+` sign and
        // shorter/odd input (e.g. "1" or "+f") — so validate the length and
        // decode with `hex::decode` to keep field parsing consistently strict on
        // untrusted headers.
        if parts[3].len() != 2 {
            return Err(TraceContextError::InvalidFormat(
                "flags must be 2 hex digits".into(),
            ));
        }
        let flags_byte = *hex::decode(parts[3])
            .map_err(|_| TraceContextError::InvalidFormat("invalid flags hex".into()))?
            .first()
            .ok_or_else(|| TraceContextError::InvalidFormat("invalid flags hex".into()))?;

        Ok(Self {
            trace_id,
            parent_span_id: span_id, // Current span becomes parent of future child
            span_id,
            flags: TraceFlags(flags_byte),
            tracestate: None,
            baggage: W3CBaggage::new(),
        })
    }
}

/// Extracts W3C trace context and baggage from HTTP headers.
///
/// Baggage is independent of trace context; callers can receive baggage even
/// when no `traceparent` header exists.
pub fn extract_propagation_from_http<S: BuildHasher>(
    headers: &HashMap<String, String, S>,
) -> Result<W3CPropagationContext, TraceContextError> {
    let baggage = extract_baggage_from_http(headers)?;
    let trace_context = match headers.get("traceparent") {
        Some(traceparent) => {
            let mut context = W3CTraceContext::from_str(traceparent)?;

            if let Some(tracestate) = headers.get("tracestate") {
                context.tracestate = forwardable_tracestate(tracestate);
            }
            context.baggage = baggage.clone();
            Some(context)
        }
        None => None,
    };

    Ok(W3CPropagationContext {
        trace_context,
        baggage,
    })
}

/// Extracts W3C baggage from HTTP headers.
pub fn extract_baggage_from_http<S: BuildHasher>(
    headers: &HashMap<String, String, S>,
) -> Result<W3CBaggage, TraceContextError> {
    headers.get("baggage").map_or_else(
        || Ok(W3CBaggage::new()),
        |value| W3CBaggage::from_header(value),
    )
}

/// Extracts W3C trace context from HTTP headers.
///
/// Returns `None` if no trace context headers present (not an error).
/// Returns `Err` only on malformed context that should be logged.
pub fn extract_from_http<S: BuildHasher>(
    headers: &HashMap<String, String, S>,
) -> Result<Option<W3CTraceContext>, TraceContextError> {
    extract_propagation_from_http(headers).map(|propagation| propagation.trace_context)
}

/// Injects W3C baggage into HTTP headers.
pub fn inject_baggage_to_http(
    baggage: &W3CBaggage,
    headers: &mut HashMap<String, String, impl BuildHasher>,
) -> Result<(), TraceContextError> {
    if !baggage.is_empty() {
        headers.insert("baggage".to_string(), baggage.to_header()?);
    }
    Ok(())
}

/// Injects W3C trace context and baggage into HTTP headers.
pub fn inject_to_http(
    context: &W3CTraceContext,
    headers: &mut HashMap<String, String, impl BuildHasher>,
) -> Result<(), TraceContextError> {
    headers.insert("traceparent".to_string(), context.to_traceparent());

    if let Some(ref tracestate) = context.tracestate {
        headers.insert("tracestate".to_string(), tracestate.clone());
    }

    inject_baggage_to_http(&context.baggage, headers)
}

/// Injects W3C trace context into gRPC metadata.
pub fn inject_to_grpc(
    context: &W3CTraceContext,
    metadata: &mut HashMap<String, String, impl BuildHasher>,
) {
    metadata.insert("traceparent".to_string(), context.to_traceparent());

    if let Some(ref tracestate) = context.tracestate {
        metadata.insert("tracestate".to_string(), tracestate.clone());
    }

    let _ = inject_baggage_to_http(&context.baggage, metadata);
}

/// Longest `tracestate` kept. W3C Trace Context asks vendors to propagate at
/// least 512 characters, and multi-vendor values routinely pass 128.
const MAX_TRACESTATE_LENGTH: usize = 512;

/// The incoming `tracestate` as kept and forwarded, if any. It is sent again
/// on every outgoing request of the trace, so it must be a value an outgoing
/// header can carry:
/// - spaces and tabs around it are trimmed (HTTP/2 refuses them, RFC 9113
///   §8.2.1);
/// - a value holding a control character other than a tab, or DEL, is
///   dropped, like an over-long one (more than [`MAX_TRACESTATE_LENGTH`]
///   bytes) and an empty one. An HTTP/2 peer can send such a byte, and
///   forwarding it would fail every request made under the trace.
fn forwardable_tracestate(tracestate: &str) -> Option<String> {
    let trimmed = tracestate.trim_matches([' ', '\t']);
    let carries = trimmed
        .bytes()
        .all(|byte| byte == b'\t' || !byte.is_ascii_control());
    (carries && !trimmed.is_empty() && trimmed.len() <= MAX_TRACESTATE_LENGTH)
        .then(|| trimmed.to_owned())
}

/// Returns the context one hop of a request runs under.
///
/// A valid incoming `traceparent` is continued as a child span, keeping its
/// `tracestate` and the request's `baggage`. A missing or invalid
/// `traceparent` starts a new trace and drops `tracestate`, as the W3C Trace
/// Context specification requires; valid baggage is kept either way. A
/// malformed `baggage` header is ignored instead of discarding a valid trace.
/// Header names are expected in lower case.
///
/// New trace and span ids come from the operating system's random source;
/// [`continue_or_start_trace_with`] takes them from the caller's instead.
#[must_use]
pub fn continue_or_start_trace<S: BuildHasher>(
    headers: &HashMap<String, String, S>,
) -> W3CTraceContext {
    continue_or_start(headers, None)
}

/// Like [`continue_or_start_trace`], with new ids filled by `fill`.
///
/// Pass a context's entropy, for example `|bytes| cx.random_bytes(bytes)`,
/// so a run under a deterministic entropy source replays the same ids. An
/// all-zero id, which W3C Trace Context forbids, gets its last byte set to 1.
#[must_use]
pub fn continue_or_start_trace_with<S: BuildHasher>(
    headers: &HashMap<String, String, S>,
    mut fill: impl FnMut(&mut [u8]),
) -> W3CTraceContext {
    continue_or_start(headers, Some(&mut fill))
}

fn continue_or_start<S: BuildHasher>(
    headers: &HashMap<String, String, S>,
    fill: Option<&mut dyn FnMut(&mut [u8])>,
) -> W3CTraceContext {
    let baggage = extract_baggage_from_http(headers).unwrap_or_default();
    let incoming = headers
        .get("traceparent")
        .and_then(|traceparent| W3CTraceContext::from_str(traceparent).ok());
    match incoming {
        Some(parent) => W3CTraceContext {
            trace_id: parent.trace_id,
            parent_span_id: parent.span_id,
            span_id: fill.map_or_else(SpanId::new_random, |fill| SpanId(filled_id(fill))),
            flags: parent.flags,
            tracestate: headers
                .get("tracestate")
                .and_then(|tracestate| forwardable_tracestate(tracestate)),
            baggage,
        },
        None => {
            let (trace_id, parent_span_id, span_id) = match fill {
                Some(fill) => (
                    TraceId(filled_id(fill)),
                    SpanId(filled_id(fill)),
                    SpanId(filled_id(fill)),
                ),
                None => (
                    TraceId::new_random(),
                    SpanId::new_random(),
                    SpanId::new_random(),
                ),
            };
            W3CTraceContext {
                trace_id,
                parent_span_id,
                span_id,
                flags: TraceFlags::SAMPLED,
                tracestate: None,
                baggage,
            }
        }
    }
}

/// An id of `N` bytes from `fill`, never all zero.
fn filled_id<const N: usize>(fill: &mut dyn FnMut(&mut [u8])) -> [u8; N] {
    let mut bytes = [0u8; N];
    fill(&mut bytes);
    if bytes == [0u8; N] {
        bytes[N - 1] = 1;
    }
    bytes
}

#[cfg(test)]
#[path = "w3c_trace_context_inline_tests.rs"]
mod tests;
