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
    /// The fix routes the value through [`sanitize_span_value`] (caps
    /// to [`MAX_SPAN_ATTRIBUTE_VALUE_LEN`] = 1024 bytes; replaces
    /// values whose key matches the [`SENSITIVE_KEY_DENYLIST`] with
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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::trace::distributed::context::{RegionTag, SymbolTraceContext};
    use crate::trace::distributed::id::{DistTraceId, SymbolSpanId};
    use crate::util::DetRng;

    fn fresh_span() -> SymbolSpan {
        let mut rng = DetRng::new(42);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(1),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        SymbolSpan::new_encode(ctx, ObjectId::new_for_test(1), Time::from_millis(0))
    }

    // br-asupersync-65gy5c: sensitive-keyword denylist — values
    // whose key matches any denylist entry (case-insensitive
    // substring) are stored as <redacted>.
    #[test]
    fn set_attribute_redacts_authorization_header_65gy5c() {
        let mut span = fresh_span();
        span.set_attribute("Authorization", "Bearer sk_live_ABC123_secret");
        assert_eq!(
            span.attributes().get("Authorization").map(String::as_str),
            Some("<redacted>")
        );
    }

    #[test]
    fn set_attribute_redacts_cookie_x_api_key_password_65gy5c() {
        for key in &[
            "cookie",
            "Set-Cookie",
            "x-api-key",
            "X-Api-Key",
            "password",
            "PASSWORD",
            "session",
        ] {
            let mut span = fresh_span();
            span.set_attribute(*key, "sensitive-value-that-must-not-leak");
            assert_eq!(
                span.attributes().get(*key).map(String::as_str),
                Some("<redacted>"),
                "key {key} should be redacted"
            );
        }
    }

    #[test]
    fn set_attribute_truncates_long_value_65gy5c() {
        let mut span = fresh_span();
        let big = "A".repeat(MAX_SPAN_ATTRIBUTE_VALUE_LEN * 2);
        span.set_attribute("blob", big.clone());
        let stored = span.attributes().get("blob").expect("stored");
        assert!(
            stored.len() <= MAX_SPAN_ATTRIBUTE_VALUE_LEN,
            "stored len {} exceeds cap {}",
            stored.len(),
            MAX_SPAN_ATTRIBUTE_VALUE_LEN,
        );
        // Truncation must include a stable hash suffix so two
        // truncated values from the same input compare equal.
        assert!(stored.contains('…'));
        assert!(stored.contains('#'));
    }

    #[test]
    fn set_attribute_scrubs_control_bytes_65gy5c() {
        let mut span = fresh_span();
        // Newlines + NULs in the value would enable log-injection
        // downstream; they must be replaced with '_'.
        span.set_attribute("path", "/api/v1\n\rINJECTED: HEADER\0\u{1b}[31m");
        let stored = span.attributes().get("path").expect("stored");
        assert!(!stored.contains('\n'));
        assert!(!stored.contains('\r'));
        assert!(!stored.contains('\0'));
        assert!(!stored.contains('\u{1b}'));
        assert!(stored.contains('_'));
    }

    #[test]
    fn set_attribute_caps_cardinality_at_64_65gy5c() {
        let mut span = fresh_span();
        // Insert 100 distinct keys; only the first 64 should occupy
        // their own slots, the rest land in _overflow_attributes.
        for i in 0..100 {
            span.set_attribute(format!("key_{i}"), format!("v_{i}"));
        }
        // Per-key cap is 64; overflow bucket adds 1 more (so total
        // distinct keys is at most 65).
        assert!(
            span.attributes().len() <= MAX_SPAN_ATTRIBUTES_PER_SPAN + 1,
            "cardinality leak: {} attributes",
            span.attributes().len()
        );
        let overflow = span
            .attributes()
            .get("_overflow_attributes")
            .expect("overflow bucket present");
        let n: u64 = overflow.parse().expect("overflow is numeric");
        assert!(n >= 36, "overflow count too low: {n}");
    }

    #[test]
    fn set_attribute_replacing_existing_key_does_not_count_against_cardinality_65gy5c() {
        let mut span = fresh_span();
        // Fill exactly to cap.
        for i in 0..MAX_SPAN_ATTRIBUTES_PER_SPAN {
            span.set_attribute(format!("key_{i}"), "v");
        }
        let len_before = span.attributes().len();
        // Replacing key_0 with a new value must NOT push us into the
        // overflow path even though we're at cap.
        span.set_attribute("key_0", "new_value");
        assert_eq!(span.attributes().len(), len_before);
        assert_eq!(
            span.attributes().get("key_0").map(String::as_str),
            Some("new_value")
        );
    }

    #[test]
    fn span_duration_calculates() {
        let mut rng = DetRng::new(42);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(1),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let mut span =
            SymbolSpan::new_encode(ctx, ObjectId::new_for_test(1), Time::from_millis(100));
        assert!(span.duration().is_none());
        span.complete_ok(Time::from_millis(150));
        assert_eq!(span.duration(), Some(Time::from_millis(50)));
    }

    #[test]
    fn span_error_recording() {
        let mut rng = DetRng::new(7);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(2),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let mut span =
            SymbolSpan::new_decode(ctx, ObjectId::new_for_test(2), 4, Time::from_millis(10));
        span.complete_error(Time::from_millis(20), "decode failed");
        assert_eq!(span.status(), SymbolSpanStatus::Error);
        assert_eq!(span.error_message(), Some("decode failed"));
    }

    #[test]
    fn span_cancelled_status_transition() {
        let mut rng = DetRng::new(10);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(3),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let mut span = SymbolSpan::new_encode(ctx, ObjectId::new_for_test(3), Time::from_millis(0));
        assert_eq!(span.status(), SymbolSpanStatus::InProgress);

        span.complete_cancelled(Time::from_millis(5));
        assert_eq!(span.status(), SymbolSpanStatus::Cancelled);
        assert!(span.end_time().is_some());
        assert!(span.error_message().is_none());
    }

    #[test]
    fn span_dropped_status_transition() {
        let mut rng = DetRng::new(11);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(4),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let sid = SymbolId::new(ObjectId::new_for_test(4), 0, 0);
        let mut span = SymbolSpan::new_transmit(ctx, sid, Time::from_millis(100));
        assert_eq!(span.kind(), SymbolSpanKind::Transmit);

        span.mark_dropped(Time::from_millis(200));
        assert_eq!(span.status(), SymbolSpanStatus::Dropped);
        assert_eq!(span.duration(), Some(Time::from_millis(100)));
    }

    #[test]
    fn span_receive_kind_and_symbol_id() {
        let mut rng = DetRng::new(12);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(5),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let oid = ObjectId::new_for_test(5);
        let sid = SymbolId::new(oid, 3, 0);
        let span = SymbolSpan::new_receive(ctx, sid, Time::from_millis(50));

        assert_eq!(span.kind(), SymbolSpanKind::Receive);
        assert_eq!(span.symbol_id(), Some(sid));
        assert_eq!(span.object_id(), Some(oid));
        assert_eq!(span.status(), SymbolSpanStatus::InProgress);
    }

    #[test]
    fn span_decode_has_symbol_count() {
        let mut rng = DetRng::new(13);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(6),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let span = SymbolSpan::new_decode(ctx, ObjectId::new_for_test(6), 10, Time::from_millis(0));
        assert_eq!(span.kind(), SymbolSpanKind::Decode);
        assert_eq!(span.symbol_count(), Some(10));
        assert!(span.symbol_id().is_none());
    }

    #[test]
    fn span_set_symbol_count() {
        let mut rng = DetRng::new(14);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(7),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let mut span = SymbolSpan::new_encode(ctx, ObjectId::new_for_test(7), Time::from_millis(0));
        assert!(span.symbol_count().is_none());

        span.set_symbol_count(42);
        assert_eq!(span.symbol_count(), Some(42));
    }

    #[test]
    fn span_attributes_set_and_retrieve() {
        let mut rng = DetRng::new(15);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(8),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let mut span = SymbolSpan::new_encode(ctx, ObjectId::new_for_test(8), Time::from_millis(0));

        assert!(span.attributes().is_empty());

        span.set_attribute("codec", "raptorq");
        span.set_attribute("overhead", "1.05");

        assert_eq!(span.attributes().len(), 2);
        assert_eq!(
            span.attributes().get("codec").map(String::as_str),
            Some("raptorq")
        );
        assert_eq!(
            span.attributes().get("overhead").map(String::as_str),
            Some("1.05")
        );
    }

    #[test]
    fn span_attributes_overwrite_existing_key() {
        let mut rng = DetRng::new(16);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(9),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let mut span = SymbolSpan::new_encode(ctx, ObjectId::new_for_test(9), Time::from_millis(0));

        span.set_attribute("retry", "0");
        span.set_attribute("retry", "1");

        assert_eq!(span.attributes().len(), 1);
        assert_eq!(
            span.attributes().get("retry").map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn span_ok_completion_clears_in_progress() {
        let mut rng = DetRng::new(17);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(10),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let mut span =
            SymbolSpan::new_encode(ctx, ObjectId::new_for_test(10), Time::from_millis(0));

        assert_eq!(span.status(), SymbolSpanStatus::InProgress);
        assert!(span.end_time().is_none());
        assert!(span.error_message().is_none());

        span.complete_ok(Time::from_millis(50));

        assert_eq!(span.status(), SymbolSpanStatus::Ok);
        assert_eq!(span.end_time(), Some(Time::from_millis(50)));
        assert!(span.error_message().is_none());
    }

    #[test]
    fn span_context_is_accessible() {
        let mut rng = DetRng::new(18);
        let trace_id = DistTraceId::new_for_test(11);
        let ctx = SymbolTraceContext::new_for_encoding(
            trace_id,
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let span = SymbolSpan::new_encode(ctx, ObjectId::new_for_test(11), Time::from_millis(0));

        assert_eq!(span.context().trace_id(), trace_id);
    }

    // =========================================================================
    // Wave 53 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn symbol_span_status_debug_clone_copy() {
        let s = SymbolSpanStatus::InProgress;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("InProgress"), "{dbg}");
        let copied = s;
        let cloned = s;
        assert_eq!(copied, cloned);
    }

    #[test]
    fn symbol_span_kind_debug_clone_copy() {
        let k = SymbolSpanKind::Encode;
        let dbg = format!("{k:?}");
        assert!(dbg.contains("Encode"), "{dbg}");
        let copied = k;
        let cloned = k;
        assert_eq!(copied, cloned);
    }

    #[test]
    fn symbol_span_debug_clone() {
        let mut rng = DetRng::new(99);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(99),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let span = SymbolSpan::new_encode(ctx, ObjectId::new_for_test(99), Time::from_millis(0));
        let dbg = format!("{span:?}");
        assert!(dbg.contains("SymbolSpan"), "{dbg}");
        let cloned = span;
        assert_eq!(cloned.kind(), SymbolSpanKind::Encode);
    }
}
