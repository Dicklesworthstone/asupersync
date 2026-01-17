//! Diagnostic context for hierarchical operation tracking.
//!
//! Provides span-based context tracking similar to distributed tracing,
//! but designed for single-runtime observability and debugging.

use crate::types::Time;
use core::fmt;
use std::collections::HashMap;

/// Unique identifier for a span.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpanId(u64);

impl SpanId {
    /// Creates a new span ID.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the raw ID value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// The nil (zero) span ID.
    pub const NIL: Self = Self(0);
}

impl fmt::Debug for SpanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SpanId({:016x})", self.0)
    }
}

impl fmt::Display for SpanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08x}", (self.0 & 0xFFFF_FFFF) as u32)
    }
}

/// A span represents a unit of work with a name, timing, and context.
///
/// Spans form a tree structure where child spans are nested within parent
/// spans. This enables hierarchical timing and debugging.
#[derive(Clone)]
pub struct Span {
    /// Unique identifier for this span.
    id: SpanId,
    /// Parent span ID, if any.
    parent_id: Option<SpanId>,
    /// Name of the operation.
    name: String,
    /// When the span started.
    start_time: Time,
    /// When the span ended (if finished).
    end_time: Option<Time>,
    /// Structured attributes.
    attributes: HashMap<String, String>,
    /// Status of the span.
    status: SpanStatus,
}

/// Status of a span.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpanStatus {
    /// Span is still in progress.
    InProgress,
    /// Span completed successfully.
    Ok,
    /// Span completed with an error.
    Error,
    /// Span was cancelled.
    Cancelled,
}

impl Span {
    /// Creates a new span with the given ID, name, and start time.
    #[must_use]
    pub fn new(id: SpanId, name: impl Into<String>, start_time: Time) -> Self {
        Self {
            id,
            parent_id: None,
            name: name.into(),
            start_time,
            end_time: None,
            attributes: HashMap::new(),
            status: SpanStatus::InProgress,
        }
    }

    /// Sets the parent span ID.
    #[must_use]
    pub fn with_parent(mut self, parent_id: SpanId) -> Self {
        self.parent_id = Some(parent_id);
        self
    }

    /// Adds an attribute to the span.
    #[must_use]
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Returns the span ID.
    #[must_use]
    pub const fn id(&self) -> SpanId {
        self.id
    }

    /// Returns the parent span ID, if any.
    #[must_use]
    pub const fn parent_id(&self) -> Option<SpanId> {
        self.parent_id
    }

    /// Returns the span name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the start time.
    #[must_use]
    pub const fn start_time(&self) -> Time {
        self.start_time
    }

    /// Returns the end time, if the span has ended.
    #[must_use]
    pub const fn end_time(&self) -> Option<Time> {
        self.end_time
    }

    /// Returns the duration of the span, if ended.
    #[must_use]
    pub fn duration(&self) -> Option<Time> {
        self.end_time
            .map(|end| Time::from_nanos(end.duration_since(self.start_time)))
    }

    /// Returns the span status.
    #[must_use]
    pub const fn status(&self) -> SpanStatus {
        self.status
    }

    /// Returns true if the span is still in progress.
    #[must_use]
    pub const fn is_in_progress(&self) -> bool {
        matches!(self.status, SpanStatus::InProgress)
    }

    /// Gets an attribute by key.
    #[must_use]
    pub fn get_attribute(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).map(String::as_str)
    }

    /// Returns an iterator over attributes.
    pub fn attributes(&self) -> impl Iterator<Item = (&str, &str)> {
        self.attributes
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Ends the span with the given time and status.
    pub fn end(&mut self, end_time: Time, status: SpanStatus) {
        self.end_time = Some(end_time);
        self.status = status;
    }

    /// Ends the span successfully.
    pub fn end_ok(&mut self, end_time: Time) {
        self.end(end_time, SpanStatus::Ok);
    }

    /// Ends the span with an error.
    pub fn end_error(&mut self, end_time: Time) {
        self.end(end_time, SpanStatus::Error);
    }

    /// Ends the span as cancelled.
    pub fn end_cancelled(&mut self, end_time: Time) {
        self.end(end_time, SpanStatus::Cancelled);
    }

    /// Adds an attribute after creation.
    pub fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.attributes.insert(key.into(), value.into());
    }
}

impl fmt::Debug for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Span")
            .field("id", &self.id)
            .field("parent_id", &self.parent_id)
            .field("name", &self.name)
            .field("status", &self.status)
            .field("start_time", &self.start_time)
            .field("end_time", &self.end_time)
            .field("attributes", &self.attributes)
            .finish()
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} ({:?})", self.id, self.name, self.status)?;
        if let Some(duration) = self.duration() {
            write!(f, " {}ms", duration.as_millis())?;
        }
        Ok(())
    }
}

/// Context for tracking diagnostic information across operations.
///
/// `DiagnosticContext` manages a stack of spans and provides methods
/// for creating and managing hierarchical operation traces.
#[derive(Debug, Clone)]
pub struct DiagnosticContext {
    /// Active span stack (most recent at end).
    span_stack: Vec<Span>,
    /// Completed spans for inspection.
    completed_spans: Vec<Span>,
    /// Next span ID to allocate.
    next_span_id: u64,
    /// Maximum number of completed spans to retain.
    max_completed: usize,
    /// Global attributes applied to all spans.
    global_attributes: HashMap<String, String>,
}

impl DiagnosticContext {
    /// Creates a new diagnostic context.
    #[must_use]
    pub fn new() -> Self {
        Self {
            span_stack: Vec::new(),
            completed_spans: Vec::new(),
            next_span_id: 1,
            max_completed: 1000,
            global_attributes: HashMap::new(),
        }
    }

    /// Sets the maximum number of completed spans to retain.
    #[must_use]
    pub fn with_max_completed(mut self, max: usize) -> Self {
        self.max_completed = max;
        self
    }

    /// Adds a global attribute applied to all new spans.
    pub fn set_global_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.global_attributes.insert(key.into(), value.into());
    }

    /// Starts a new span with the given name.
    ///
    /// The span becomes the current span until `end_span` is called.
    pub fn start_span(&mut self, name: impl Into<String>, start_time: Time) -> SpanId {
        let id = SpanId::new(self.next_span_id);
        self.next_span_id += 1;

        let parent_id = self.current_span_id();
        let mut span = Span::new(id, name, start_time);

        if let Some(parent) = parent_id {
            span = span.with_parent(parent);
        }

        // Apply global attributes
        for (k, v) in &self.global_attributes {
            span.set_attribute(k.clone(), v.clone());
        }

        self.span_stack.push(span);
        id
    }

    /// Ends the current span with the given status.
    ///
    /// Returns the completed span, or None if no span is active.
    pub fn end_span(&mut self, end_time: Time, status: SpanStatus) -> Option<Span> {
        let mut span = self.span_stack.pop()?;
        span.end(end_time, status);

        // Add to completed spans
        self.completed_spans.push(span.clone());

        // Trim if needed
        if self.completed_spans.len() > self.max_completed {
            self.completed_spans.remove(0);
        }

        Some(span)
    }

    /// Ends the current span as successful.
    pub fn end_span_ok(&mut self, end_time: Time) -> Option<Span> {
        self.end_span(end_time, SpanStatus::Ok)
    }

    /// Ends the current span as error.
    pub fn end_span_error(&mut self, end_time: Time) -> Option<Span> {
        self.end_span(end_time, SpanStatus::Error)
    }

    /// Returns the ID of the current span, if any.
    #[must_use]
    pub fn current_span_id(&self) -> Option<SpanId> {
        self.span_stack.last().map(Span::id)
    }

    /// Returns a reference to the current span, if any.
    #[must_use]
    pub fn current_span(&self) -> Option<&Span> {
        self.span_stack.last()
    }

    /// Returns a mutable reference to the current span, if any.
    pub fn current_span_mut(&mut self) -> Option<&mut Span> {
        self.span_stack.last_mut()
    }

    /// Adds an attribute to the current span.
    pub fn add_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
        if let Some(span) = self.span_stack.last_mut() {
            span.set_attribute(key, value);
        }
    }

    /// Returns the depth of the span stack.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.span_stack.len()
    }

    /// Returns true if there are no active spans.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.span_stack.is_empty()
    }

    /// Returns the completed spans.
    #[must_use]
    pub fn completed_spans(&self) -> &[Span] {
        &self.completed_spans
    }

    /// Clears all completed spans.
    pub fn clear_completed(&mut self) {
        self.completed_spans.clear();
    }

    /// Returns the active spans (for debugging).
    #[must_use]
    pub fn active_spans(&self) -> &[Span] {
        &self.span_stack
    }
}

impl Default for DiagnosticContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_lifecycle() {
        let mut span = Span::new(SpanId::new(1), "test_op", Time::from_millis(100));
        assert!(span.is_in_progress());
        assert_eq!(span.name(), "test_op");
        assert_eq!(span.start_time(), Time::from_millis(100));

        span.end_ok(Time::from_millis(200));
        assert!(!span.is_in_progress());
        assert_eq!(span.status(), SpanStatus::Ok);
        assert_eq!(span.duration(), Some(Time::from_millis(100)));
    }

    #[test]
    fn span_with_attributes() {
        let span = Span::new(SpanId::new(1), "test", Time::ZERO)
            .with_attribute("key1", "value1")
            .with_attribute("key2", "value2");

        assert_eq!(span.get_attribute("key1"), Some("value1"));
        assert_eq!(span.get_attribute("key2"), Some("value2"));
        assert_eq!(span.get_attribute("missing"), None);
    }

    #[test]
    fn span_with_parent() {
        let span = Span::new(SpanId::new(2), "child", Time::ZERO).with_parent(SpanId::new(1));

        assert_eq!(span.parent_id(), Some(SpanId::new(1)));
    }

    #[test]
    fn context_span_stack() {
        let mut ctx = DiagnosticContext::new();

        let id1 = ctx.start_span("outer", Time::from_millis(0));
        let id2 = ctx.start_span("inner", Time::from_millis(10));

        assert_eq!(ctx.depth(), 2);
        assert_eq!(ctx.current_span_id(), Some(id2));

        // Inner span's parent should be outer
        let inner = ctx.current_span().unwrap();
        assert_eq!(inner.parent_id(), Some(id1));

        ctx.end_span_ok(Time::from_millis(20));
        assert_eq!(ctx.depth(), 1);
        assert_eq!(ctx.current_span_id(), Some(id1));

        ctx.end_span_ok(Time::from_millis(30));
        assert!(ctx.is_empty());

        assert_eq!(ctx.completed_spans().len(), 2);
    }

    #[test]
    fn context_global_attributes() {
        let mut ctx = DiagnosticContext::new();
        ctx.set_global_attribute("service", "test-service");

        ctx.start_span("op1", Time::ZERO);
        assert_eq!(
            ctx.current_span().unwrap().get_attribute("service"),
            Some("test-service")
        );
    }

    #[test]
    fn context_add_attribute() {
        let mut ctx = DiagnosticContext::new();
        ctx.start_span("op", Time::ZERO);
        ctx.add_attribute("dynamic", "value");

        assert_eq!(
            ctx.current_span().unwrap().get_attribute("dynamic"),
            Some("value")
        );
    }

    #[test]
    fn span_id_display() {
        let id = SpanId::new(0x1234_5678_9ABC_DEF0);
        assert!(format!("{id}").contains("9abcdef0"));
        assert!(format!("{id:?}").contains("SpanId"));
    }

    #[test]
    fn span_status_variants() {
        let statuses = [
            SpanStatus::InProgress,
            SpanStatus::Ok,
            SpanStatus::Error,
            SpanStatus::Cancelled,
        ];
        for status in statuses {
            assert!(!format!("{status:?}").is_empty());
        }
    }
}
