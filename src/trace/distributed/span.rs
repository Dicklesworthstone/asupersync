//! Span types representing symbol operations.

use super::context::SymbolTraceContext;
use crate::types::symbol::{ObjectId, SymbolId};
use crate::types::Time;
use std::collections::HashMap;

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
    name: String,
    kind: SymbolSpanKind,
    start_time: Time,
    end_time: Option<Time>,
    status: SymbolSpanStatus,
    object_id: Option<ObjectId>,
    symbol_id: Option<SymbolId>,
    symbol_count: Option<u32>,
    attributes: HashMap<String, String>,
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
            attributes: HashMap::new(),
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
            attributes: HashMap::new(),
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
            attributes: HashMap::new(),
            error_message: None,
        }
    }

    /// Creates a new span for decoding.
    #[must_use]
    pub fn new_decode(
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
            attributes: HashMap::new(),
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
    pub fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.attributes.insert(key.into(), value.into());
    }

    /// Returns attributes.
    #[must_use]
    pub fn attributes(&self) -> &HashMap<String, String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::distributed::context::{RegionTag, SymbolTraceContext};
    use crate::trace::distributed::id::{SymbolSpanId, TraceId};
    use crate::util::DetRng;

    #[test]
    fn span_duration_calculates() {
        let mut rng = DetRng::new(42);
        let ctx = SymbolTraceContext::new_for_encoding(
            TraceId::new_for_test(1),
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
            TraceId::new_for_test(2),
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
            TraceId::new_for_test(3),
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
            TraceId::new_for_test(4),
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
            TraceId::new_for_test(5),
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
            TraceId::new_for_test(6),
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
            TraceId::new_for_test(7),
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
            TraceId::new_for_test(8),
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
            TraceId::new_for_test(9),
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
            TraceId::new_for_test(10),
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
        let trace_id = TraceId::new_for_test(11);
        let ctx = SymbolTraceContext::new_for_encoding(
            trace_id,
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let span = SymbolSpan::new_encode(ctx, ObjectId::new_for_test(11), Time::from_millis(0));

        assert_eq!(span.context().trace_id(), trace_id);
    }
}
