//! Span types representing symbol operations.

use super::context::SymbolTraceContext;
use crate::types::Time;
use crate::types::symbol::{ObjectId, SymbolId};
use std::collections::{BTreeMap, btree_map::Entry};

/// Status of a symbol span.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolSpanStatus {
    /// Operation in progress.
    InProgress,
    /// Operation completed successfully.
    Ok,
    /// Operation failed with error.
    Error,
    /// Operation was cancelled.
    Cancelled,
    /// Symbol was dropped (lost in transmission).
    Dropped,
}

/// Kind of symbol operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolSpanKind {
    /// Encoding an object into symbols.
    Encode,
    /// Generating repair symbols.
    GenerateRepair,
    /// Transmitting a symbol.
    Transmit,
    /// Receiving a symbol.
    Receive,
    /// Verifying symbol authentication.
    Verify,
    /// Decoding symbols into an object.
    Decode,
    /// Retransmitting a symbol.
    Retransmit,
    /// Acknowledging symbol receipt.
    Acknowledge,
}

/// A span representing a symbol-related operation.
#[derive(Clone, Debug)]
pub struct SymbolSpan {
    context: SymbolTraceContext,
    #[allow(dead_code)] // retained for debug/tracing diagnostics
    name: String,
    kind: SymbolSpanKind,
    start_time: Time,
    end_time: Option<Time>,
    status: SymbolSpanStatus,
    object_id: Option<ObjectId>,
    symbol_id: Option<SymbolId>,
    symbol_count: Option<u32>,
    attributes: BTreeMap<String, String>,
    error_message: Option<String>,
}

impl SymbolSpan {
    /// Creates a new span for encoding.
    #[must_use]
    pub fn new_encode(context: SymbolTraceContext, object_id: ObjectId, start_time: Time) -> Self {
        Self {
            context,
            name: "encode".into(),
            kind: SymbolSpanKind::Encode,
            start_time,
            end_time: None,
            status: SymbolSpanStatus::InProgress,
            object_id: Some(object_id),
            symbol_id: None,
            symbol_count: None,
            attributes: BTreeMap::new(),
            error_message: None,
        }
    }

    /// Creates a new span for transmission.
    #[must_use]
    pub fn new_transmit(
        context: SymbolTraceContext,
        symbol_id: SymbolId,
        start_time: Time,
    ) -> Self {
        Self {
            context,
            name: "transmit".into(),
            kind: SymbolSpanKind::Transmit,
            start_time,
            end_time: None,
            status: SymbolSpanStatus::InProgress,
            object_id: Some(symbol_id.object_id()),
            symbol_id: Some(symbol_id),
            symbol_count: None,
            attributes: BTreeMap::new(),
            error_message: None,
        }
    }

    /// Creates a new span for receiving.
    #[must_use]
    pub fn new_receive(context: SymbolTraceContext, symbol_id: SymbolId, start_time: Time) -> Self {
        Self {
            context,
            name: "receive".into(),
            kind: SymbolSpanKind::Receive,
            start_time,
            end_time: None,
            status: SymbolSpanStatus::InProgress,
            object_id: Some(symbol_id.object_id()),
            symbol_id: Some(symbol_id),
            symbol_count: None,
            attributes: BTreeMap::new(),
            error_message: None,
        }
    }

    /// Creates a new span for decoding.
    #[must_use]
    pub fn new_decode(
        // ubs:ignore - false positive, not a JWT decode
        context: SymbolTraceContext,
        object_id: ObjectId,
        symbol_count: u32,
        start_time: Time,
    ) -> Self {
        Self {
            context,
            name: "decode".into(),
            kind: SymbolSpanKind::Decode,
            start_time,
            end_time: None,
            status: SymbolSpanStatus::InProgress,
            object_id: Some(object_id),
            symbol_id: None,
            symbol_count: Some(symbol_count),
            attributes: BTreeMap::new(),
            error_message: None,
        }
    }

    /// Returns the trace context.
    #[must_use]
    pub fn context(&self) -> &SymbolTraceContext {
        &self.context
    }

    /// Returns the span kind.
    #[must_use]
    pub const fn kind(&self) -> SymbolSpanKind {
        self.kind
    }

    /// Returns the span status.
    #[must_use]
    pub const fn status(&self) -> SymbolSpanStatus {
        self.status
    }

    /// Returns the start time.
    #[must_use]
    pub const fn start_time(&self) -> Time {
        self.start_time
    }

    /// Returns the end time.
    #[must_use]
    pub const fn end_time(&self) -> Option<Time> {
        self.end_time
    }

    /// Returns the duration of the span.
    #[must_use]
    pub fn duration(&self) -> Option<Time> {
        self.end_time
            .map(|end| Time::from_nanos(end.duration_since(self.start_time)))
    }

    /// Returns the object ID.
    #[must_use]
    pub const fn object_id(&self) -> Option<ObjectId> {
        self.object_id
    }

    /// Returns the symbol ID.
    #[must_use]
    pub const fn symbol_id(&self) -> Option<SymbolId> {
        self.symbol_id
    }

    /// Returns the symbol count.
    #[must_use]
    pub const fn symbol_count(&self) -> Option<u32> {
        self.symbol_count
    }

    /// Sets the symbol count.
    pub fn set_symbol_count(&mut self, count: u32) {
        self.symbol_count = Some(count);
    }

    /// Sets an attribute on the span.
    ///
    /// br-asupersync-65gy5c: every attribute write is bounded and
    /// redacted before storage. The pre-fix surface accepted
    /// arbitrary `impl Into<String>` for both key and value with NO
    /// length cap, NO sensitive-keyword denylist, NO control-character
    /// scrubbing, and NO cardinality cap on the per-span attribute
    /// map — sufficient for an attacker who can influence ANY string
    /// reaching set_attribute (HTTP header values, SQL bodies,
    /// cancel reasons containing stack frame paths) to exfiltrate
    /// sensitive bytes through every downstream span consumer
    /// (crashpacks, distributed bridges, OTEL collectors).
    ///
    /// The fix routes the value through `sanitize_span_value` (caps
    /// to [`MAX_SPAN_ATTRIBUTE_VALUE_LEN`] = 1024 bytes; replaces
    /// values whose key matches the `SENSITIVE_KEY_DENYLIST` with
    /// `"<redacted>"` regardless of length; scrubs control bytes to
    /// `_`) and gates the insert on
    /// [`MAX_SPAN_ATTRIBUTES_PER_SPAN`] = 64 — overflow inserts land
    /// in a single sentinel key
    /// `_overflow_<count>` so the cardinality DoS surface is closed.
    pub fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = value.into();
        let sanitized = sanitize_span_value(&key, value);

        let at_capacity = self.attributes.len() >= MAX_SPAN_ATTRIBUTES_PER_SPAN;
        match self.attributes.entry(key) {
            Entry::Occupied(mut entry) => {
                // Replacing an existing attribute does not change cardinality.
                entry.insert(sanitized);
            }
            Entry::Vacant(entry) if !at_capacity => {
                entry.insert(sanitized);
            }
            Entry::Vacant(_) => {
                // Cardinality cap reached. Aggregate further inserts into
                // a single overflow bucket rather than refusing the call
                // (callers should not silently lose telemetry, but they
                // should also not be able to drive the BTreeMap to
                // arbitrary size).
                let overflow_key = "_overflow_attributes";
                let entry = self
                    .attributes
                    .entry(overflow_key.to_string())
                    .or_insert_with(|| "0".to_string());
                let n: u64 = entry.parse::<u64>().unwrap_or(0).saturating_add(1);
                *entry = n.to_string();
            }
        }
    }

    /// Returns attributes.
    #[must_use]
    pub fn attributes(&self) -> &BTreeMap<String, String> {
        &self.attributes
    }

    /// Returns the error message.
    #[must_use]
    pub fn error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }

    /// Completes the span successfully.
    pub fn complete_ok(&mut self, end_time: Time) {
        self.end_time = Some(end_time);
        self.status = SymbolSpanStatus::Ok;
    }

    /// Completes the span with an error.
    pub fn complete_error(&mut self, end_time: Time, message: impl Into<String>) {
        self.end_time = Some(end_time);
        self.status = SymbolSpanStatus::Error;
        self.error_message = Some(message.into());
    }

    /// Completes the span with a cancellation.
    pub fn complete_cancelled(&mut self, end_time: Time) {
        self.end_time = Some(end_time);
        self.status = SymbolSpanStatus::Cancelled;
    }

    /// Marks the span as dropped.
    pub fn mark_dropped(&mut self, end_time: Time) {
        self.end_time = Some(end_time);
        self.status = SymbolSpanStatus::Dropped;
    }
}

/// br-asupersync-65gy5c: hard cap on the value bytes stored per span attribute.
///
/// Values longer than this are truncated and suffixed with a stable hash so
/// diagnostic continuity is preserved without leaking the entire payload.
pub const MAX_SPAN_ATTRIBUTE_VALUE_LEN: usize = 1024;

/// br-asupersync-65gy5c: cardinality cap on the per-span attribute map.
///
/// Subsequent set_attribute calls for new keys are aggregated into a single
/// `_overflow_attributes` counter rather than growing the BTreeMap unboundedly.
pub const MAX_SPAN_ATTRIBUTES_PER_SPAN: usize = 64;

/// br-asupersync-65gy5c: case-insensitive substring matches that
/// trigger replacement of the attribute value with `<redacted>`
/// regardless of length. This catches the common
/// HTTP-header / SQL / config-secret shapes that operators
/// frequently splice into spans without realising the trace path
/// crosses trust boundaries.
const SENSITIVE_KEY_DENYLIST: &[&str] = &[
    "authorization",
    "auth_token",
    "auth-token",
    "cookie",
    "set-cookie",
    "session",
    "password",
    "passwd",
    "secret",
    "private_key",
    "private-key",
    "api_key",
    "api-key",
    "x-api-key",
    "x-amz-security-token",
    "credentials",
    "bearer",
    "token",
];

/// br-asupersync-65gy5c: sanitize a single span-attribute value:
///   1. If the key matches any entry in [`SENSITIVE_KEY_DENYLIST`]
///      (case-insensitive substring), replace with `<redacted>`.
///   2. Replace any control byte (b < 0x20 except tab) and DEL
///      (0x7F) with `_`. These bytes are log-injection vectors
///      downstream.
///   3. Truncate at [`MAX_SPAN_ATTRIBUTE_VALUE_LEN`] bytes; append a
///      `…#hash` suffix so consumers can deduplicate identical
///      values that were truncated to the same prefix.
fn sanitize_span_value(key: &str, value: String) -> String {
    if is_sensitive_key(key) {
        return "<redacted>".to_string();
    }

    let mut scrubbed = String::with_capacity(value.len());
    for c in value.chars() {
        let needs_scrub = (c.is_ascii_control() && c != '\t') || c == '\u{7f}';
        scrubbed.push(if needs_scrub { '_' } else { c });
    }

    if scrubbed.len() <= MAX_SPAN_ATTRIBUTE_VALUE_LEN {
        return scrubbed;
    }

    let hash = stable_attribute_hash(scrubbed.as_bytes());
    let suffix = format!("…#{:016x}", hash);
    let mut cut = MAX_SPAN_ATTRIBUTE_VALUE_LEN.saturating_sub(suffix.len());
    while cut > 0 && !scrubbed.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut out = scrubbed[..cut].to_string();
    out.push_str(&suffix);
    out
}

fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SENSITIVE_KEY_DENYLIST
        .iter()
        .any(|&needle| lower.contains(needle))
}

fn stable_attribute_hash(bytes: &[u8]) -> u64 {
    // FNV-1a — deterministic, no_std-friendly, sufficient for diagnostic dedup.
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

#[cfg(test)]
#[path = "span_inline_tests.rs"]
mod tests;
