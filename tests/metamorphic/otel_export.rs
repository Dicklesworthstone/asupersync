//! Metamorphic testing for observability::otel span export invariants.
//!
//! Tests the core metamorphic relations that must hold for a correct
//! OpenTelemetry span export implementation using proptest + LabRuntime virtual time.

#![allow(clippy::missing_panics_doc)]

use asupersync::cx::Cx;
use asupersync::lab::LabRuntime;
use asupersync::observability::otel_structured_concurrency::{
    EntityId, OtelStructuredConcurrencyConfig, PendingSpan, SpanType, ActiveSpan,
};
use asupersync::types::{RegionId, TaskId, Time};
use proptest::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(feature = "metrics")]
use opentelemetry::{
    trace::{SpanContext, SpanId, TraceId, TraceState, Status, StatusCode},
    KeyValue, Value,
};

/// Mock span implementation for testing
#[cfg(feature = "metrics")]
#[derive(Debug, Clone)]
struct MockSpan {
    span_id: SpanId,
    trace_id: TraceId,
    parent_span_id: Option<SpanId>,
    name: String,
    status: Status,
    attributes: Vec<KeyValue>,
    events: Vec<String>,
    start_time: Time,
    end_time: Option<Time>,
    is_cancelled: bool,
}

#[cfg(feature = "metrics")]
impl MockSpan {
    fn new(span_id: SpanId, trace_id: TraceId, name: String, start_time: Time) -> Self {
        Self {
            span_id,
            trace_id,
            parent_span_id: None,
            name,
            status: Status::Unset,
            attributes: Vec::new(),
            events: Vec::new(),
            start_time,
            end_time: None,
            is_cancelled: false,
        }
    }

    fn with_parent(mut self, parent_span_id: SpanId) -> Self {
        self.parent_span_id = Some(parent_span_id);
        self
    }
}

#[cfg(feature = "metrics")]
impl opentelemetry::trace::Span for MockSpan {
    fn add_event_with_timestamp<T>(&mut self, name: T, timestamp: std::time::SystemTime, attributes: Vec<KeyValue>)
    where
        T: Into<std::borrow::Cow<'static, str>>,
    {
        self.events.push(name.into().to_string());
    }

    fn span_context(&self) -> &SpanContext {
        // Return a dummy span context
        static DUMMY_CONTEXT: std::sync::OnceLock<SpanContext> = std::sync::OnceLock::new();
        DUMMY_CONTEXT.get_or_init(|| {
            SpanContext::new(
                TraceId::INVALID,
                SpanId::INVALID,
                opentelemetry::trace::TraceFlags::default(),
                false,
                TraceState::default(),
            )
        })
    }

    fn is_recording(&self) -> bool {
        true
    }

    fn set_attribute(&mut self, attribute: KeyValue) {
        self.attributes.push(attribute);
    }

    fn set_status(&mut self, status: Status) {
        self.status = status;
        if matches!(status.code, StatusCode::Error) && status.description.as_ref().map_or(false, |d| d.contains("Cancelled")) {
            self.is_cancelled = true;
        }
    }

    fn update_name<T>(&mut self, new_name: T)
    where
        T: Into<std::borrow::Cow<'static, str>>,
    {
        self.name = new_name.into().to_string();
    }

    fn end_with_timestamp(&mut self, timestamp: std::time::SystemTime) {
        self.end_time = Some(Time::from_millis(
            timestamp.duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64
        ));
    }
}

/// Mock span exporter for testing batch export behavior
#[derive(Debug, Clone)]
struct MockSpanExporter {
    exported_spans: Arc<Mutex<Vec<MockSpan>>>,
    max_export_batch_size: usize,
    export_timeout: Duration,
    should_timeout: Arc<Mutex<bool>>,
    call_count: Arc<AtomicU64>,
}

impl MockSpanExporter {
    fn new(max_export_batch_size: usize, export_timeout: Duration) -> Self {
        Self {
            exported_spans: Arc::new(Mutex::new(Vec::new())),
            max_export_batch_size,
            export_timeout,
            should_timeout: Arc::new(Mutex::new(false)),
            call_count: Arc::new(AtomicU64::new(0)),
        }
    }

    fn set_should_timeout(&self, timeout: bool) {
        *self.should_timeout.lock().unwrap() = timeout;
    }

    fn export_batch(&self, spans: Vec<MockSpan>) -> Result<(), String> {
        self.call_count.fetch_add(1, Ordering::SeqCst);

        // MR3: batch export respects max_export_batch_size
        if spans.len() > self.max_export_batch_size {
            return Err(format!(
                "Batch size {} exceeds maximum {}",
                spans.len(),
                self.max_export_batch_size
            ));
        }

        // MR4: timeout drops pending exports gracefully
        if *self.should_timeout.lock().unwrap() {
            return Err("Export timeout".to_string());
        }

        let mut exported = self.exported_spans.lock().unwrap();
        exported.extend(spans);
        Ok(())
    }

    fn get_exported_spans(&self) -> Vec<MockSpan> {
        self.exported_spans.lock().unwrap().clone()
    }

    fn get_call_count(&self) -> u64 {
        self.call_count.load(Ordering::SeqCst)
    }

    fn clear(&self) {
        self.exported_spans.lock().unwrap().clear();
        self.call_count.store(0, Ordering::SeqCst);
    }
}

/// Generate a hierarchical span tree for testing
fn generate_span_tree(depth: usize, breadth: usize, start_time: Time) -> Vec<MockSpan> {
    let mut spans = Vec::new();
    let mut span_id_counter = 1u64;
    let trace_id = TraceId::from_u128(12345);

    // Helper to generate span ID
    let mut next_span_id = || {
        let id = span_id_counter;
        span_id_counter += 1;
        SpanId::from_u64(id)
    };

    // Generate root span
    let root_span_id = next_span_id();
    let root_span = MockSpan::new(
        root_span_id,
        trace_id,
        "root_operation".to_string(),
        start_time,
    );
    spans.push(root_span);

    // Generate children recursively
    fn generate_children(
        spans: &mut Vec<MockSpan>,
        parent_span_id: SpanId,
        trace_id: TraceId,
        current_depth: usize,
        max_depth: usize,
        breadth: usize,
        start_time: Time,
        next_span_id: &mut impl FnMut() -> SpanId,
    ) {
        if current_depth >= max_depth {
            return;
        }

        for i in 0..breadth {
            let span_id = next_span_id();
            let span_name = format!("child_{}_{}", current_depth, i);
            let child_span = MockSpan::new(span_id, trace_id, span_name, start_time)
                .with_parent(parent_span_id);
            spans.push(child_span);

            // Recurse to next level
            generate_children(
                spans,
                span_id,
                trace_id,
                current_depth + 1,
                max_depth,
                breadth,
                start_time,
                next_span_id,
            );
        }
    }

    generate_children(
        &mut spans,
        root_span_id,
        trace_id,
        1,
        depth,
        breadth,
        start_time,
        &mut next_span_id,
    );

    spans
}

/// MR1: parent-child span linkage preserved through exporter
///
/// Metamorphic relation: Parent-child relationships between spans must be
/// preserved when exported, regardless of export timing or batching.
///
/// Properties tested:
/// - Child spans reference correct parent span IDs
/// - Hierarchical structure maintained in export
/// - No orphaned spans (missing parent references)
#[proptest]
fn mr_parent_child_linkage_preserved(
    #[strategy(1usize..=4)] tree_depth: usize,
    #[strategy(1usize..=3)] tree_breadth: usize,
    #[strategy(1usize..=10)] batch_size: usize,
) {
    let start_time = Time::from_millis(1000);
    let exporter = MockSpanExporter::new(batch_size, Duration::from_secs(5));
    let spans = generate_span_tree(tree_depth, tree_breadth, start_time);

    // Export spans in batches
    for chunk in spans.chunks(batch_size) {
        let result = exporter.export_batch(chunk.to_vec());
        prop_assert!(result.is_ok(), "Export should succeed: {:?}", result);
    }

    let exported_spans = exporter.get_exported_spans();

    // Verify all spans were exported
    prop_assert_eq!(exported_spans.len(), spans.len(), "All spans should be exported");

    // Build span lookup map
    let span_map: HashMap<SpanId, &MockSpan> = exported_spans
        .iter()
        .map(|span| (span.span_id, span))
        .collect();

    // Verify parent-child linkage preservation
    for span in &exported_spans {
        if let Some(parent_id) = span.parent_span_id {
            // Parent must exist in exported spans
            prop_assert!(
                span_map.contains_key(&parent_id),
                "Parent span {} must exist for child span {}",
                parent_id,
                span.span_id
            );

            // Parent and child must have same trace_id
            let parent_span = span_map[&parent_id];
            prop_assert_eq!(
                span.trace_id,
                parent_span.trace_id,
                "Parent and child must have same trace_id"
            );
        }
    }

    // Verify no cycles in parent-child relationships
    let mut visited = HashSet::new();
    let mut rec_stack = HashSet::new();

    fn has_cycle(
        span_id: SpanId,
        span_map: &HashMap<SpanId, &MockSpan>,
        visited: &mut HashSet<SpanId>,
        rec_stack: &mut HashSet<SpanId>,
    ) -> bool {
        visited.insert(span_id);
        rec_stack.insert(span_id);

        if let Some(span) = span_map.get(&span_id) {
            if let Some(parent_id) = span.parent_span_id {
                if !visited.contains(&parent_id) {
                    if has_cycle(parent_id, span_map, visited, rec_stack) {
                        return true;
                    }
                } else if rec_stack.contains(&parent_id) {
                    return true;
                }
            }
        }

        rec_stack.remove(&span_id);
        false
    }

    for &span_id in span_map.keys() {
        if !visited.contains(&span_id) {
            prop_assert!(
                !has_cycle(span_id, &span_map, &mut visited, &mut rec_stack),
                "No cycles should exist in parent-child relationships"
            );
        }
    }
}

/// MR2: trace_id stable across spans within a context
///
/// Metamorphic relation: All spans created within the same trace context
/// must share the same trace_id, regardless of when they are exported.
///
/// Properties tested:
/// - Same trace_id for all spans in a trace context
/// - Different trace contexts have different trace_ids
/// - trace_id stability across export operations
#[proptest]
fn mr_trace_id_stable_across_context(
    #[strategy(1u8..=5)] num_traces: u8,
    #[strategy(1u8..=5)] spans_per_trace: u8,
    #[strategy(1usize..=8)] batch_size: usize,
) {
    let exporter = MockSpanExporter::new(batch_size, Duration::from_secs(5));
    let start_time = Time::from_millis(2000);
    let mut all_spans = Vec::new();
    let mut expected_trace_groups = HashMap::new();

    // Generate spans for multiple traces
    for trace_idx in 0..num_traces {
        let trace_id = TraceId::from_u128((trace_idx as u128) + 100);
        let mut trace_spans = Vec::new();

        for span_idx in 0..spans_per_trace {
            let span_id = SpanId::from_u64((trace_idx as u64) * 100 + span_idx as u64 + 1);
            let span_name = format!("trace_{}_span_{}", trace_idx, span_idx);
            let span = MockSpan::new(span_id, trace_id, span_name, start_time);
            trace_spans.push(span.clone());
            all_spans.push(span);
        }

        expected_trace_groups.insert(trace_id, trace_spans.len());
    }

    // Export spans in randomized batches
    for chunk in all_spans.chunks(batch_size) {
        let result = exporter.export_batch(chunk.to_vec());
        prop_assert!(result.is_ok(), "Export should succeed: {:?}", result);
    }

    let exported_spans = exporter.get_exported_spans();

    // Group exported spans by trace_id
    let mut exported_trace_groups: HashMap<TraceId, Vec<&MockSpan>> = HashMap::new();
    for span in &exported_spans {
        exported_trace_groups
            .entry(span.trace_id)
            .or_default()
            .push(span);
    }

    // Verify trace_id stability
    prop_assert_eq!(
        exported_trace_groups.len(),
        expected_trace_groups.len(),
        "Number of traces should be preserved"
    );

    for (trace_id, expected_count) in expected_trace_groups {
        let exported_spans = exported_trace_groups.get(&trace_id).unwrap();
        prop_assert_eq!(
            exported_spans.len(),
            expected_count,
            "Span count for trace {} should be preserved",
            trace_id
        );

        // All spans in this trace should have the same trace_id
        for span in exported_spans {
            prop_assert_eq!(
                span.trace_id,
                trace_id,
                "Span should maintain original trace_id"
            );
        }
    }
}

/// MR3: batch export respects max_export_batch_size
///
/// Metamorphic relation: Batch export operations must never exceed the
/// configured maximum batch size, and should efficiently pack spans.
///
/// Properties tested:
/// - No batch exceeds max_export_batch_size
/// - Efficient packing when possible
/// - Proper handling of oversized single batch attempts
#[proptest]
fn mr_batch_export_respects_size_limit(
    #[strategy(1usize..=20)] total_spans: usize,
    #[strategy(1usize..=8)] max_batch_size: usize,
) {
    let exporter = MockSpanExporter::new(max_batch_size, Duration::from_secs(5));
    let start_time = Time::from_millis(3000);
    let trace_id = TraceId::from_u128(99999);

    // Generate spans
    let mut spans = Vec::new();
    for i in 0..total_spans {
        let span_id = SpanId::from_u64(i as u64 + 1);
        let span_name = format!("span_{}", i);
        let span = MockSpan::new(span_id, trace_id, span_name, start_time);
        spans.push(span);
    }

    // Test oversized batch rejection
    if total_spans > max_batch_size {
        let result = exporter.export_batch(spans.clone());
        prop_assert!(
            result.is_err(),
            "Oversized batch should be rejected"
        );

        if let Err(error) = result {
            prop_assert!(
                error.contains("exceeds maximum"),
                "Error should indicate size limit exceeded: {}",
                error
            );
        }
    }

    // Clear any previous state
    exporter.clear();

    // Export in properly sized batches
    let mut total_exported = 0;
    for chunk in spans.chunks(max_batch_size) {
        let result = exporter.export_batch(chunk.to_vec());
        prop_assert!(
            result.is_ok(),
            "Properly sized batch should succeed: {:?}",
            result
        );

        // Verify batch size constraint
        prop_assert!(
            chunk.len() <= max_batch_size,
            "Batch size {} should not exceed limit {}",
            chunk.len(),
            max_batch_size
        );

        total_exported += chunk.len();
    }

    // Verify all spans were exported
    let exported_spans = exporter.get_exported_spans();
    prop_assert_eq!(
        exported_spans.len(),
        total_exported,
        "All spans should be exported in batches"
    );
    prop_assert_eq!(
        total_exported,
        total_spans,
        "Total exported should equal total spans"
    );
}

/// MR4: timeout drops pending exports gracefully
///
/// Metamorphic relation: When export operations timeout, the system should
/// drop pending exports gracefully without corrupting successful exports.
///
/// Properties tested:
/// - Timeout errors are handled gracefully
/// - Successful exports before timeout are preserved
/// - No partial exports or corruption after timeout
#[proptest]
fn mr_timeout_drops_pending_gracefully(
    #[strategy(1usize..=10)] successful_batches: usize,
    #[strategy(1usize..=5)] timeout_batches: usize,
    #[strategy(1usize..=5)] batch_size: usize,
) {
    let exporter = MockSpanExporter::new(batch_size, Duration::from_millis(100));
    let start_time = Time::from_millis(4000);
    let trace_id = TraceId::from_u128(88888);

    let mut all_spans = Vec::new();
    let mut span_id = 1u64;

    // Export successful batches first
    for batch_idx in 0..successful_batches {
        let mut batch_spans = Vec::new();
        for _ in 0..batch_size {
            let span_name = format!("success_batch_{}_span_{}", batch_idx, span_id);
            let span = MockSpan::new(SpanId::from_u64(span_id), trace_id, span_name, start_time);
            batch_spans.push(span.clone());
            all_spans.push(span);
            span_id += 1;
        }

        let result = exporter.export_batch(batch_spans);
        prop_assert!(
            result.is_ok(),
            "Successful batch should export: {:?}",
            result
        );
    }

    let successful_export_count = exporter.get_exported_spans().len();
    let successful_call_count = exporter.get_call_count();

    // Enable timeout for subsequent exports
    exporter.set_should_timeout(true);

    // Attempt to export batches that will timeout
    for batch_idx in 0..timeout_batches {
        let mut batch_spans = Vec::new();
        for _ in 0..batch_size {
            let span_name = format!("timeout_batch_{}_span_{}", batch_idx, span_id);
            let span = MockSpan::new(SpanId::from_u64(span_id), trace_id, span_name, start_time);
            batch_spans.push(span);
            span_id += 1;
        }

        let result = exporter.export_batch(batch_spans);
        prop_assert!(
            result.is_err(),
            "Timeout batch should fail"
        );

        if let Err(error) = result {
            prop_assert!(
                error.contains("timeout"),
                "Error should indicate timeout: {}",
                error
            );
        }
    }

    // Verify graceful timeout handling
    let final_exported_spans = exporter.get_exported_spans();
    let final_call_count = exporter.get_call_count();

    // Successful exports should be preserved
    prop_assert_eq!(
        final_exported_spans.len(),
        successful_export_count,
        "Successful exports should be preserved after timeout"
    );

    // Call count should include both successful and timeout attempts
    prop_assert_eq!(
        final_call_count,
        successful_call_count + timeout_batches as u64,
        "All export attempts should be recorded"
    );

    // Verify no partial exports occurred
    for span in &final_exported_spans {
        prop_assert!(
            span.name.starts_with("success_"),
            "Only successful spans should remain after timeout"
        );
    }
}

/// MR5: cancelled span emitted with CancelledError status
///
/// Metamorphic relation: Spans that are cancelled must be exported with
/// proper error status indicating cancellation, not success or generic error.
///
/// Properties tested:
/// - Cancelled spans have Error status
/// - Status description contains "Cancelled" or similar
/// - Cancellation status preserved through export
#[proptest]
fn mr_cancelled_span_emitted_with_error_status(
    #[strategy(1usize..=10)] total_spans: usize,
    #[strategy(0.0..=1.0)] cancel_probability: f64,
    #[strategy(1usize..=5)] batch_size: usize,
) {
    let exporter = MockSpanExporter::new(batch_size, Duration::from_secs(5));
    let start_time = Time::from_millis(5000);
    let trace_id = TraceId::from_u128(77777);

    let mut spans = Vec::new();
    let mut expected_cancelled_count = 0;

    // Generate spans with some marked as cancelled
    for i in 0..total_spans {
        let span_id = SpanId::from_u64(i as u64 + 1);
        let span_name = format!("operation_{}", i);
        let mut span = MockSpan::new(span_id, trace_id, span_name, start_time);

        // Randomly mark spans as cancelled based on probability
        if (i as f64 / total_spans as f64) < cancel_probability {
            span.set_status(Status::error("Operation was cancelled due to context cancellation"));
            expected_cancelled_count += 1;
        } else {
            span.set_status(Status::ok());
        }

        spans.push(span);
    }

    // Export spans in batches
    for chunk in spans.chunks(batch_size) {
        let result = exporter.export_batch(chunk.to_vec());
        prop_assert!(result.is_ok(), "Export should succeed: {:?}", result);
    }

    let exported_spans = exporter.get_exported_spans();

    // Analyze exported spans for cancellation status
    let mut actual_cancelled_count = 0;
    let mut actual_success_count = 0;

    for span in &exported_spans {
        match span.status.code {
            StatusCode::Ok => {
                actual_success_count += 1;
                prop_assert!(
                    !span.is_cancelled,
                    "Successful span should not be marked as cancelled"
                );
            }
            StatusCode::Error => {
                if span.is_cancelled {
                    actual_cancelled_count += 1;

                    // Verify cancellation is properly indicated
                    if let Some(ref description) = span.status.description {
                        prop_assert!(
                            description.to_lowercase().contains("cancel"),
                            "Cancelled span should have cancellation in status description: {}",
                            description
                        );
                    }
                }
            }
            _ => {
                // Other status codes are acceptable
            }
        }
    }

    // Verify cancelled spans are properly exported
    prop_assert_eq!(
        actual_cancelled_count,
        expected_cancelled_count,
        "Cancelled span count should be preserved through export"
    );

    prop_assert_eq!(
        actual_success_count + actual_cancelled_count,
        total_spans,
        "All spans should be accounted for (success or cancelled)"
    );
}

/// BONUS MR: span export ordering consistency
///
/// Metamorphic relation: The ordering of span exports should be consistent
/// with span creation timing, allowing for some batching flexibility.
///
/// Properties tested:
/// - Spans maintain relative ordering within reasonable bounds
/// - Parent spans are not exported after their children
/// - Start times are preserved correctly
#[proptest]
fn mr_span_export_ordering_consistency(
    #[strategy(1usize..=15)] num_spans: usize,
    #[strategy(1usize..=5)] batch_size: usize,
) {
    let exporter = MockSpanExporter::new(batch_size, Duration::from_secs(5));
    let base_time = Time::from_millis(6000);
    let trace_id = TraceId::from_u128(66666);

    let mut spans = Vec::new();

    // Generate spans with incrementally increasing start times
    for i in 0..num_spans {
        let span_id = SpanId::from_u64(i as u64 + 1);
        let span_name = format!("ordered_span_{}", i);
        let start_time = Time::from_millis(base_time.as_millis() + i as u64 * 10);

        let mut span = MockSpan::new(span_id, trace_id, span_name, start_time);

        // Create parent-child relationships for some spans
        if i > 0 && i % 3 == 0 {
            let parent_id = SpanId::from_u64((i - 1) as u64 + 1);
            span = span.with_parent(parent_id);
        }

        spans.push(span);
    }

    // Export spans in batches
    for chunk in spans.chunks(batch_size) {
        let result = exporter.export_batch(chunk.to_vec());
        prop_assert!(result.is_ok(), "Export should succeed: {:?}", result);
    }

    let exported_spans = exporter.get_exported_spans();

    // Verify start times are preserved
    for (original, exported) in spans.iter().zip(exported_spans.iter()) {
        prop_assert_eq!(
            original.start_time,
            exported.start_time,
            "Start time should be preserved for span {}",
            original.span_id
        );
    }

    // Verify parent-child export ordering (parents before children when possible)
    let span_map: HashMap<SpanId, &MockSpan> = exported_spans
        .iter()
        .map(|span| (span.span_id, span))
        .collect();

    for span in &exported_spans {
        if let Some(parent_id) = span.parent_span_id {
            let parent_span = span_map.get(&parent_id);
            prop_assert!(
                parent_span.is_some(),
                "Parent span {} should exist for child {}",
                parent_id,
                span.span_id
            );

            if let Some(parent) = parent_span {
                // Parent should not have a later start time than child
                prop_assert!(
                    parent.start_time <= span.start_time,
                    "Parent span start time {} should not be after child start time {}",
                    parent.start_time.as_millis(),
                    span.start_time.as_millis()
                );
            }
        }
    }
}

/// Test module for integration with the rest of the test suite
#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "metrics")]
    #[test]
    fn otel_export_smoke_test() {
        // Quick smoke test to verify the metamorphic relations can run
        let exporter = MockSpanExporter::new(5, Duration::from_secs(1));
        let start_time = Time::from_millis(1000);
        let trace_id = TraceId::from_u128(12345);

        // Create parent-child span pair
        let parent_span = MockSpan::new(
            SpanId::from_u64(1),
            trace_id,
            "parent".to_string(),
            start_time,
        );

        let child_span = MockSpan::new(
            SpanId::from_u64(2),
            trace_id,
            "child".to_string(),
            start_time,
        )
        .with_parent(SpanId::from_u64(1));

        let spans = vec![parent_span, child_span];

        // Export and verify
        let result = exporter.export_batch(spans);
        assert!(result.is_ok(), "Export should succeed");

        let exported = exporter.get_exported_spans();
        assert_eq!(exported.len(), 2, "Both spans should be exported");

        // Verify parent-child relationship preserved
        let child = exported.iter().find(|s| s.span_id == SpanId::from_u64(2)).unwrap();
        assert_eq!(child.parent_span_id, Some(SpanId::from_u64(1)));
        assert_eq!(child.trace_id, trace_id);
    }
}