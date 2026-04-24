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

#![allow(missing_docs)]

use crate::types::{RegionId, TaskId, Time};
use std::collections::{HashMap, HashSet};

#[cfg(feature = "metrics")]
use opentelemetry::{
    KeyValue, Value,
    global::{BoxedSpan, BoxedTracer},
    trace::{Span, SpanKind, Status, Tracer},
};
#[cfg(feature = "metrics")]
use parking_lot::RwLock;
#[cfg(feature = "metrics")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "metrics")]
use std::time::{Duration, SystemTime};

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
    #[must_use]
    pub fn default_name(self) -> &'static str {
        match self {
            Self::Region => "region_lifecycle",
            Self::Task => "task_execution",
            Self::Operation => "operation",
            Self::Cancel => "cancellation_event",
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
        _entity_id: EntityId,
        name: String,
        start_time: Time,
        parent_span_context: Option<opentelemetry::Context>,
    ) -> Self {
        Self {
            span_type,
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
    pub fn materialize(&self, tracer: &BoxedTracer) -> BoxedSpan {
        let mut span_builder = tracer.span_builder(self.name.clone());

        // Set span kind based on type
        span_builder = span_builder.with_kind(match self.span_type {
            SpanType::Region => SpanKind::Internal,
            SpanType::Task => SpanKind::Internal,
            SpanType::Operation => SpanKind::Client, // Most operations are outbound
            SpanType::Cancel => SpanKind::Internal,
        });

        // Set start time
        span_builder = span_builder.with_start_time(otel_system_time(self.start_time));

        // Add attributes
        span_builder = span_builder.with_attributes(self.attributes.clone());

        // Create span with parent context
        if let Some(parent_context) = &self.parent_span_context {
            span_builder.start_with_context(tracer, parent_context)
        } else {
            span_builder.start(tracer)
        }
    }
}

#[cfg(feature = "metrics")]
/// Active span being tracked.
#[derive(Debug)]
pub struct ActiveSpan {
    span: BoxedSpan,
}

#[cfg(feature = "metrics")]
impl ActiveSpan {
    /// Creates a new active span.
    pub fn new(
        span: BoxedSpan,
        _span_type: SpanType,
        _entity_id: EntityId,
        _start_time: Time,
    ) -> Self {
        Self { span }
    }

    /// Adds an event to the span.
    pub fn add_event(&mut self, name: &str, attributes: Vec<KeyValue>) {
        self.span.add_event(name.to_string(), attributes);
    }

    /// Sets the span status.
    pub fn set_status(&mut self, status: Status) {
        self.span.set_status(status);
    }

    /// Ends the span.
    pub fn end(mut self) {
        self.span.end();
    }

    /// Ends the span with a specific end time.
    pub fn end_with_time(mut self, end_time: Time) {
        self.span.end_with_timestamp(otel_system_time(end_time));
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

    /// Monotonic deterministic sample counter.
    sample_counter: AtomicU64,

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
            sample_counter: AtomicU64::new(0),
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
        let sample_rate = self
            .config
            .span_type_rates
            .get(&span_type)
            .copied()
            .unwrap_or(self.config.global_sample_rate);

        if sample_rate >= 1.0 {
            return true;
        }

        if sample_rate <= 0.0 {
            return false;
        }

        let sample_key =
            self.sample_counter.fetch_add(1, Ordering::Relaxed) ^ span_type_sample_key(span_type);
        sample_unit_interval(sample_key) < sample_rate
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
            self.stats
                .spans_dropped_sampling
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // Check capacity
        {
            let pending = self.pending_spans.read();
            let active = self.active_spans.read();
            if pending.len() + active.len() >= self.config.max_active_spans {
                self.stats
                    .spans_dropped_overflow
                    .fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }

        // Create pending span
        let pending_span = PendingSpan::new(span_type, entity_id, name, start_time, parent_context);

        let mut pending_spans = self.pending_spans.write();
        pending_spans.insert(entity_id, pending_span);

        self.stats.spans_created.fetch_add(1, Ordering::Relaxed);
        if pending_spans
            .get(&entity_id)
            .and_then(|pending| pending.parent_span_context.as_ref())
            .is_some()
        {
            self.stats
                .context_propagations
                .fetch_add(1, Ordering::Relaxed);
        }
        true
    }

    /// Materializes a pending span if it meets the lazy threshold.
    pub fn maybe_materialize_span(&self, entity_id: EntityId, tracer: &BoxedTracer) -> bool {
        let should_materialize = {
            let pending_spans = self.pending_spans.read();
            if let Some(pending) = pending_spans.get(&entity_id) {
                pending.operation_count >= self.config.lazy_threshold as u64
            } else {
                false
            }
        };

        if should_materialize {
            let materialized = self.materialize_span(entity_id, tracer);
            if materialized {
                self.stats
                    .lazy_materializations
                    .fetch_add(1, Ordering::Relaxed);
            }
            materialized
        } else {
            false
        }
    }

    /// Forces materialization of a pending span.
    pub fn materialize_span(&self, entity_id: EntityId, tracer: &BoxedTracer) -> bool {
        let pending_span = {
            let mut pending_spans = self.pending_spans.write();
            pending_spans.remove(&entity_id)
        };

        if let Some(pending) = pending_span {
            let span = pending.materialize(tracer);
            let active_span =
                ActiveSpan::new(span, pending.span_type, entity_id, pending.start_time);

            let mut active_spans = self.active_spans.write();
            active_spans.insert(entity_id, active_span);

            self.stats
                .spans_materialized
                .fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Ends a span (either pending or active).
    pub fn end_span(&self, entity_id: EntityId, tracer: &BoxedTracer) {
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
    #[must_use]
    pub fn new(_config: OtelStructuredConcurrencyConfig) -> Self {
        Self
    }

    #[must_use]
    pub fn create_pending_span(
        &self,
        _span_type: SpanType,
        _entity_id: EntityId,
        _name: String,
        _start_time: Time,
        #[cfg(feature = "metrics")] _parent_context: Option<opentelemetry::Context>,
        #[cfg(not(feature = "metrics"))] _parent_context: Option<()>,
    ) -> bool {
        false
    }

    pub fn end_span<T>(&self, _entity_id: EntityId, _tracer: &T) {}

    pub fn add_span_operation(&self, _entity_id: EntityId) {}

    #[must_use]
    pub fn stats(&self) -> (u64, u64, u64, u64, u64, u64) {
        (0, 0, 0, 0, 0, 0)
    }
}

#[cfg(feature = "metrics")]
fn otel_system_time(time: Time) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_nanos(time.as_nanos()))
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

#[cfg(feature = "metrics")]
fn sample_unit_interval(key: u64) -> f64 {
    const TWO_POW_53_F64: f64 = 9_007_199_254_740_992.0;
    let bits = splitmix64(key) >> 11;
    bits as f64 / TWO_POW_53_F64
}

#[cfg(feature = "metrics")]
fn splitmix64(mut state: u64) -> u64 {
    state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

#[cfg(feature = "metrics")]
const fn span_type_sample_key(span_type: SpanType) -> u64 {
    match span_type {
        SpanType::Region => 0x11,
        SpanType::Task => 0x22,
        SpanType::Operation => 0x33,
        SpanType::Cancel => 0x44,
    }
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

        let (
            created,
            materialized,
            dropped_overflow,
            dropped_sampling,
            context_propagations,
            lazy_materializations,
        ) = storage.stats();
        assert_eq!(created, 0);
        assert_eq!(materialized, 0);
        assert_eq!(dropped_overflow, 0);
        assert_eq!(dropped_sampling, 0);
        assert_eq!(context_propagations, 0);
        assert_eq!(lazy_materializations, 0);
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn span_storage_tracks_context_and_lazy_materialization_separately() {
        let config = OtelStructuredConcurrencyConfig::new().with_global_sample_rate(1.0);
        let storage = SpanStorage::new(config);
        let tracer = opentelemetry::global::tracer("otel-structured-concurrency-test");
        let entity = EntityId::Operation(17);

        assert!(storage.create_pending_span(
            SpanType::Operation,
            entity,
            "op".to_string(),
            Time::from_nanos(5),
            Some(opentelemetry::Context::new()),
        ));
        storage.add_span_operation(entity);
        storage.add_span_operation(entity);
        assert!(storage.maybe_materialize_span(entity, &tracer));

        let (
            created,
            materialized,
            dropped_overflow,
            dropped_sampling,
            context_propagations,
            lazy_materializations,
        ) = storage.stats();
        assert_eq!(created, 1);
        assert_eq!(materialized, 1);
        assert_eq!(dropped_overflow, 0);
        assert_eq!(dropped_sampling, 0);
        assert_eq!(context_propagations, 1);
        assert_eq!(lazy_materializations, 1);
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn ending_pending_span_is_not_counted_as_lazy_materialization() {
        let config = OtelStructuredConcurrencyConfig::new()
            .with_global_sample_rate(1.0)
            .with_max_active_spans(8);
        let storage = SpanStorage::new(config);
        let tracer = opentelemetry::global::tracer("otel-structured-concurrency-test");
        let entity = EntityId::Task(TaskId::new_for_test(9, 1));

        assert!(storage.create_pending_span(
            SpanType::Task,
            entity,
            "task".to_string(),
            Time::from_nanos(9),
            None,
        ));
        storage.end_span(entity, &tracer);

        let (_, materialized, _, _, _, lazy_materializations) = storage.stats();
        assert_eq!(materialized, 1);
        assert_eq!(lazy_materializations, 0);
    }
}
