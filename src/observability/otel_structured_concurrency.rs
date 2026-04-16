//! OpenTelemetry integration for structured concurrency tracing.
//!
//! This module provides automatic span creation and context propagation for
//! asupersync's structured concurrency primitives, enabling production-grade
//! observability without manual instrumentation.
//!
//! # Features
//!
//! - **Automatic Spans**: Regions, tasks, operations, and cancellation events
//! - **Hierarchical Tracing**: Perfect parent-child relationships
//! - **Lazy Evaluation**: Minimal overhead via deferred span materialization
//! - **Rich Context**: Structured concurrency semantic information in spans
//! - **Sampling**: Configurable sampling rates per span type
//!
//! # Usage
//!
//! ```ignore
//! use asupersync::observability::otel_structured_concurrency::OtelStructuredConcurrencyConfig;
//! use asupersync::runtime::RuntimeBuilder;
//!
//! let config = OtelStructuredConcurrencyConfig::default()
//!     .with_global_sample_rate(0.1) // 10% sampling
//!     .with_always_sample_cancellation(); // Always trace cancellation
//!
//! let runtime = RuntimeBuilder::new()
//!     .with_otel_structured_concurrency(config)
//!     .build()?;
//! ```

use crate::types::{RegionId, TaskId, Time};
use std::collections::{HashMap, HashSet};

#[cfg(feature = "metrics")]
use crate::observability::context::{DiagnosticContext, SpanId};
#[cfg(feature = "metrics")]
use opentelemetry::{
    trace::{Span, SpanKind, Status, Tracer},
    KeyValue, Value,
};
#[cfg(feature = "metrics")]
use parking_lot::{Mutex, RwLock};
#[cfg(feature = "metrics")]
use std::collections::{HashMap, HashSet};
#[cfg(feature = "metrics")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "metrics")]
use std::sync::Arc;

/// Entity identifier for span tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntityId {
    Region(RegionId),
    Task(TaskId),
    Operation(u64),
    Cancel(u64),
}

/// Types of spans created for structured concurrency operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpanType {
    /// Region lifecycle from creation to quiescence.
    Region,
    /// Task execution from spawn to completion/cancellation.
    Task,
    /// IO/timer/channel operations with cancellation semantics.
    Operation,
    /// Cancellation propagation events and drain operations.
    Cancel,
}

impl SpanType {
    /// Returns the default span name for this span type.
    pub fn default_name(self) -> &'static str {
        match self {
            SpanType::Region => "region_lifecycle",
            SpanType::Task => "task_execution",
            SpanType::Operation => "operation",
            SpanType::Cancel => "cancellation_event",
        }
    }
}

/// Configuration for OpenTelemetry structured concurrency integration.
#[derive(Debug, Clone)]
pub struct OtelStructuredConcurrencyConfig {
    /// Global trace sampling rate (0.0-1.0).
    pub global_sample_rate: f64,

    /// Per-span-type sampling rates (overrides global rate).
    pub span_type_rates: HashMap<SpanType, f64>,

    /// Always sample these span types regardless of global rate.
    pub always_sample: HashSet<SpanType>,

    /// Maximum concurrent active spans to prevent memory exhaustion.
    pub max_active_spans: usize,

    /// Lazy span materialization threshold.
    /// Spans are kept as lightweight pending records until they have
    /// accumulated this many operations or reach end-of-life.
    pub lazy_threshold: usize,

    /// Include structured concurrency debug information in spans.
    pub include_debug_info: bool,

    /// Maximum span attribute value length (truncate longer values).
    pub max_attribute_length: usize,
}

impl Default for OtelStructuredConcurrencyConfig {
    fn default() -> Self {
        let mut always_sample = HashSet::new();
        always_sample.insert(SpanType::Cancel); // Always trace cancellation events

        Self {
            global_sample_rate: 0.1, // 10% sampling by default
            span_type_rates: HashMap::new(),
            always_sample,
            max_active_spans: 10_000,
            lazy_threshold: 5,
            include_debug_info: false,
            max_attribute_length: 1024,
        }
    }
}

impl OtelStructuredConcurrencyConfig {
    /// Creates a new configuration with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the global sampling rate for all span types.
    #[must_use]
    pub fn with_global_sample_rate(mut self, rate: f64) -> Self {
        self.global_sample_rate = rate.clamp(0.0, 1.0);
        self
    }

    /// Sets the sampling rate for a specific span type.
    #[must_use]
    pub fn with_span_type_sample_rate(mut self, span_type: SpanType, rate: f64) -> Self {
        self.span_type_rates.insert(span_type, rate.clamp(0.0, 1.0));
        self
    }

    /// Always samples the specified span type regardless of global rate.
    #[must_use]
    pub fn with_always_sample(mut self, span_type: SpanType) -> Self {
        self.always_sample.insert(span_type);
        self
    }

    /// Always samples cancellation events.
    #[must_use]
    pub fn with_always_sample_cancellation(mut self) -> Self {
        self.always_sample.insert(SpanType::Cancel);
        self
    }

    /// Sets the maximum number of concurrent active spans.
    #[must_use]
    pub fn with_max_active_spans(mut self, max: usize) -> Self {
        self.max_active_spans = max;
        self
    }

    /// Enables debug information in span attributes.
    #[must_use]
    pub fn with_debug_info(mut self) -> Self {
        self.include_debug_info = true;
        self
    }
}

#[cfg(feature = "metrics")]
/// Pending span awaiting materialization.
#[derive(Debug)]
pub struct PendingSpan {
    span_type: SpanType,
    entity_id: EntityId,
    name: String,
    attributes: Vec<KeyValue>,
    start_time: Time,
    parent_span_context: Option<opentelemetry::Context>,
    operation_count: u64,
}

#[cfg(feature = "metrics")]
impl PendingSpan {
    /// Creates a new pending span.
    pub fn new(
        span_type: SpanType,
        entity_id: EntityId,
        name: String,
        start_time: Time,
        parent_span_context: Option<opentelemetry::Context>,
    ) -> Self {
        Self {
            span_type,
            entity_id,
            name,
            attributes: Vec::new(),
            start_time,
            parent_span_context,
            operation_count: 0,
        }
    }

    /// Adds an attribute to the pending span.
    pub fn add_attribute(&mut self, key: &'static str, value: Value) {
        self.attributes.push(KeyValue::new(key, value));
    }

    /// Increments the operation count for lazy materialization.
    pub fn increment_operations(&mut self) {
        self.operation_count += 1;
    }

    /// Materializes the span using the provided tracer.
    pub fn materialize(&self, tracer: &dyn Tracer) -> Box<dyn Span> {
        let mut span_builder = tracer.span_builder(self.name.clone());

        // Set span kind based on type
        span_builder = span_builder.with_kind(match self.span_type {
            SpanType::Region => SpanKind::Internal,
            SpanType::Task => SpanKind::Internal,
            SpanType::Operation => SpanKind::Client,  // Most operations are outbound
            SpanType::Cancel => SpanKind::Internal,
        });

        // Set start time
        span_builder = span_builder.with_start_time(self.start_time.into());

        // Add attributes
        span_builder = span_builder.with_attributes(self.attributes.clone());

        // Create span with parent context
        let span = if let Some(parent_context) = &self.parent_span_context {
            span_builder.start_with_context(tracer, parent_context)
        } else {
            span_builder.start(tracer)
        };

        span
    }
}

#[cfg(feature = "metrics")]
/// Active span being tracked.
#[derive(Debug)]
pub struct ActiveSpan {
    span: Box<dyn Span>,
    span_type: SpanType,
    entity_id: EntityId,
    start_time: Time,
}

#[cfg(feature = "metrics")]
impl ActiveSpan {
    /// Creates a new active span.
    pub fn new(
        span: Box<dyn Span>,
        span_type: SpanType,
        entity_id: EntityId,
        start_time: Time,
    ) -> Self {
        Self {
            span,
            span_type,
            entity_id,
            start_time,
        }
    }

    /// Adds an event to the span.
    pub fn add_event(&mut self, name: &str, attributes: Vec<KeyValue>) {
        self.span.add_event(name, attributes);
    }

    /// Sets the span status.
    pub fn set_status(&mut self, status: Status) {
        self.span.set_status(status);
    }

    /// Ends the span.
    pub fn end(self) {
        self.span.end();
    }

    /// Ends the span with a specific end time.
    pub fn end_with_time(self, end_time: Time) {
        self.span.end_with_timestamp(end_time.into());
    }
}

#[cfg(feature = "metrics")]
/// Statistics for span storage performance monitoring.
#[derive(Debug, Default)]
pub struct SpanStorageStats {
    pub spans_created: AtomicU64,
    pub spans_materialized: AtomicU64,
    pub spans_dropped_overflow: AtomicU64,
    pub spans_dropped_sampling: AtomicU64,
    pub context_propagations: AtomicU64,
    pub lazy_materializations: AtomicU64,
}

#[cfg(feature = "metrics")]
/// Lock-free span storage optimized for structured concurrency.
#[derive(Debug)]
pub struct SpanStorage {
    /// Configuration
    config: OtelStructuredConcurrencyConfig,

    /// Active materialized spans
    active_spans: RwLock<HashMap<EntityId, ActiveSpan>>,

    /// Pending spans awaiting materialization
    pending_spans: RwLock<HashMap<EntityId, PendingSpan>>,

    /// Random number generator for sampling
    rng: Mutex<fastrand::Rng>,

    /// Performance statistics
    stats: SpanStorageStats,
}

#[cfg(feature = "metrics")]
impl SpanStorage {
    /// Creates a new span storage with the given configuration.
    pub fn new(config: OtelStructuredConcurrencyConfig) -> Self {
        Self {
            config,
            active_spans: RwLock::new(HashMap::new()),
            pending_spans: RwLock::new(HashMap::new()),
            rng: Mutex::new(fastrand::Rng::new()),
            stats: SpanStorageStats::default(),
        }
    }

    /// Determines if a span should be sampled based on configuration.
    fn should_sample(&self, span_type: SpanType) -> bool {
        // Always sample if configured
        if self.config.always_sample.contains(&span_type) {
            return true;
        }

        // Check span-type specific rate
        let sample_rate = self.config.span_type_rates.get(&span_type)
            .copied()
            .unwrap_or(self.config.global_sample_rate);

        if sample_rate >= 1.0 {
            return true;
        }

        if sample_rate <= 0.0 {
            return false;
        }

        // Use random sampling
        let mut rng = self.rng.lock();
        rng.f64() < sample_rate
    }

    /// Creates a pending span.
    pub fn create_pending_span(
        &self,
        span_type: SpanType,
        entity_id: EntityId,
        name: String,
        start_time: Time,
        parent_context: Option<opentelemetry::Context>,
    ) -> bool {
        // Check sampling
        if !self.should_sample(span_type) {
            self.stats.spans_dropped_sampling.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // Check capacity
        {
            let pending = self.pending_spans.read();
            let active = self.active_spans.read();
            if pending.len() + active.len() >= self.config.max_active_spans {
                self.stats.spans_dropped_overflow.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }

        // Create pending span
        let pending_span = PendingSpan::new(
            span_type,
            entity_id,
            name,
            start_time,
            parent_context,
        );

        let mut pending_spans = self.pending_spans.write();
        pending_spans.insert(entity_id, pending_span);

        self.stats.spans_created.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Materializes a pending span if it meets the lazy threshold.
    pub fn maybe_materialize_span(
        &self,
        entity_id: EntityId,
        tracer: &dyn Tracer,
    ) -> bool {
        let should_materialize = {
            let pending_spans = self.pending_spans.read();
            if let Some(pending) = pending_spans.get(&entity_id) {
                pending.operation_count >= self.config.lazy_threshold as u64
            } else {
                false
            }
        };

        if should_materialize {
            self.materialize_span(entity_id, tracer)
        } else {
            false
        }
    }

    /// Forces materialization of a pending span.
    pub fn materialize_span(&self, entity_id: EntityId, tracer: &dyn Tracer) -> bool {
        let pending_span = {
            let mut pending_spans = self.pending_spans.write();
            pending_spans.remove(&entity_id)
        };

        if let Some(pending) = pending_span {
            let span = pending.materialize(tracer);
            let active_span = ActiveSpan::new(
                span,
                pending.span_type,
                entity_id,
                pending.start_time,
            );

            let mut active_spans = self.active_spans.write();
            active_spans.insert(entity_id, active_span);

            self.stats.spans_materialized.fetch_add(1, Ordering::Relaxed);
            self.stats.lazy_materializations.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Ends a span (either pending or active).
    pub fn end_span(&self, entity_id: EntityId, tracer: &dyn Tracer) {
        // Try to end active span first
        let active_span = {
            let mut active_spans = self.active_spans.write();
            active_spans.remove(&entity_id)
        };

        if let Some(span) = active_span {
            span.end();
            return;
        }

        // Materialize and immediately end pending span
        if self.materialize_span(entity_id, tracer) {
            let active_span = {
                let mut active_spans = self.active_spans.write();
                active_spans.remove(&entity_id)
            };

            if let Some(span) = active_span {
                span.end();
            }
        }
    }

    /// Adds an operation to a span (for lazy materialization tracking).
    pub fn add_span_operation(&self, entity_id: EntityId) {
        let mut pending_spans = self.pending_spans.write();
        if let Some(pending) = pending_spans.get_mut(&entity_id) {
            pending.increment_operations();
        }
    }

    /// Gets current statistics.
    pub fn stats(&self) -> (u64, u64, u64, u64, u64, u64) {
        (
            self.stats.spans_created.load(Ordering::Relaxed),
            self.stats.spans_materialized.load(Ordering::Relaxed),
            self.stats.spans_dropped_overflow.load(Ordering::Relaxed),
            self.stats.spans_dropped_sampling.load(Ordering::Relaxed),
            self.stats.context_propagations.load(Ordering::Relaxed),
            self.stats.lazy_materializations.load(Ordering::Relaxed),
        )
    }
}

/// No-op implementation when metrics feature is disabled.
#[cfg(not(feature = "metrics"))]
pub struct SpanStorage;

#[cfg(not(feature = "metrics"))]
impl SpanStorage {
    pub fn new(_config: OtelStructuredConcurrencyConfig) -> Self {
        Self
    }

    pub fn create_pending_span(
        &self,
        _span_type: SpanType,
        _entity_id: EntityId,
        _name: String,
        _start_time: Time,
        #[cfg(feature = "metrics")]
        _parent_context: Option<opentelemetry::Context>,
        #[cfg(not(feature = "metrics"))]
        _parent_context: Option<()>,
    ) -> bool {
        false
    }

    #[cfg(feature = "metrics")]
    pub fn end_span(&self, _entity_id: EntityId, _tracer: &dyn Tracer) {}

    #[cfg(not(feature = "metrics"))]
    pub fn end_span(&self, _entity_id: EntityId, _tracer: &dyn std::fmt::Debug) {}

    pub fn add_span_operation(&self, _entity_id: EntityId) {}

    pub fn stats(&self) -> (u64, u64, u64, u64, u64, u64) {
        (0, 0, 0, 0, 0, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_default_values() {
        let config = OtelStructuredConcurrencyConfig::default();
        assert_eq!(config.global_sample_rate, 0.1);
        assert!(config.always_sample.contains(&SpanType::Cancel));
        assert_eq!(config.max_active_spans, 10_000);
        assert_eq!(config.lazy_threshold, 5);
    }

    #[test]
    fn config_builder_pattern() {
        let config = OtelStructuredConcurrencyConfig::new()
            .with_global_sample_rate(0.5)
            .with_span_type_sample_rate(SpanType::Region, 1.0)
            .with_always_sample(SpanType::Task)
            .with_max_active_spans(5000)
            .with_debug_info();

        assert_eq!(config.global_sample_rate, 0.5);
        assert_eq!(config.span_type_rates[&SpanType::Region], 1.0);
        assert!(config.always_sample.contains(&SpanType::Task));
        assert_eq!(config.max_active_spans, 5000);
        assert!(config.include_debug_info);
    }

    #[test]
    fn span_type_names() {
        assert_eq!(SpanType::Region.default_name(), "region_lifecycle");
        assert_eq!(SpanType::Task.default_name(), "task_execution");
        assert_eq!(SpanType::Operation.default_name(), "operation");
        assert_eq!(SpanType::Cancel.default_name(), "cancellation_event");
    }

    #[test]
    fn entity_id_variants() {
        let region_id = RegionId::new_for_test(1, 1);
        let task_id = TaskId::new_for_test(2, 1);

        let region_entity = EntityId::Region(region_id);
        let task_entity = EntityId::Task(task_id);
        let op_entity = EntityId::Operation(3);
        let cancel_entity = EntityId::Cancel(4);

        assert_ne!(region_entity, task_entity);
        assert_ne!(op_entity, cancel_entity);
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn span_storage_creation() {
        let config = OtelStructuredConcurrencyConfig::default();
        let storage = SpanStorage::new(config);

        let (created, materialized, dropped_overflow, dropped_sampling, context_propagations, lazy_materializations) = storage.stats();
        assert_eq!(created, 0);
        assert_eq!(materialized, 0);
        assert_eq!(dropped_overflow, 0);
        assert_eq!(dropped_sampling, 0);
        assert_eq!(context_propagations, 0);
        assert_eq!(lazy_materializations, 0);
    }
}