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
    pub fn new_transmit(context: SymbolTraceContext, symbol_id: SymbolId, start_time: Time) -> Self {
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
        self.end_time.map(|end| Time::from_nanos(end.duration_since(self.start_time)))
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
        let mut span = SymbolSpan::new_encode(
            ctx,
            ObjectId::new_for_test(1),
            Time::from_millis(100),
        );
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
        let mut span = SymbolSpan::new_decode(
            ctx,
            ObjectId::new_for_test(2),
            4,
            Time::from_millis(10),
        );
        span.complete_error(Time::from_millis(20), "decode failed");
        assert_eq!(span.status(), SymbolSpanStatus::Error);
        assert_eq!(span.error_message(), Some("decode failed"));
    }
}
