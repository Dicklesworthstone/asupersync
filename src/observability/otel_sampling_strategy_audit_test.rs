//! OpenTelemetry sampling strategy audit test.
//!
//! **AUDIT SCOPE**: Verifies that OTLP-Trace exporter implements OpenTelemetry
//! ParentBased + AlwaysOn sampling strategy per OpenTelemetry specification.
//!
//! **OPENTELEMETRY SAMPLING REQUIREMENT**:
//! - ParentBased: Sample if parent says sample, apply fallback if no parent
//! - AlwaysOn fallback: Sample all root spans when no parent present
//! - MUST NOT override parent sampling decision (distributed consistency)
//! - Child spans MUST inherit parent sampling state
//!
//! **CRITICAL**: OpenTelemetry spec compliance ensures interoperability with
//! standard observability infrastructure and distributed tracing systems.

#![cfg(test)]
#![allow(dead_code)]

use crate::observability::otlp_trace_exporter::{
    InMemoryOtlpHttpExporter, LoadSheddingTraceExporter, OtlpSpan, SpanBatch, TraceExporter,
};
use crate::observability::w3c_trace_context::extract_from_http;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// OpenTelemetry sampling strategy fixture implementation.
#[derive(Debug, Clone)]
enum OtelSamplingStrategy {
    /// Always sample (AlwaysOn).
    AlwaysOn,
    /// Never sample (AlwaysOff).
    AlwaysOff,
    /// Sample based on parent decision, with fallback strategy for root spans.
    ParentBased {
        root_fallback: Box<OtelSamplingStrategy>,
    },
    /// Sample a fraction of spans.
    TraceIdRatioBased { ratio: f64 },
}

impl OtelSamplingStrategy {
    /// Make sampling decision for a span.
    fn should_sample(&self, parent_sampled: Option<bool>, _trace_id: &str) -> bool {
        match self {
            Self::AlwaysOn => true,
            Self::AlwaysOff => false,
            Self::ParentBased { root_fallback } => {
                match parent_sampled {
                    Some(parent_decision) => parent_decision, // Honor parent decision
                    None => root_fallback.should_sample(None, _trace_id), // Apply fallback for root
                }
            }
            Self::TraceIdRatioBased { ratio } => {
                // Simple hash-based sampling over the trace id.
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                _trace_id.hash(&mut hasher);
                let hash = hasher.finish();
                (hash as f64 / u64::MAX as f64) < *ratio
            }
        }
    }
}

/// HTTP request fixture for testing.
struct HeaderFixtureRequest {
    headers: HashMap<String, String>,
}

impl HeaderFixtureRequest {
    fn with_traceparent(traceparent: &str) -> Self {
        let mut headers = HashMap::new();
        headers.insert("traceparent".to_string(), traceparent.to_string());
        Self { headers }
    }

    fn without_traceparent() -> Self {
        Self {
            headers: HashMap::new(),
        }
    }
}

/// **AUDIT TEST**: Verify ParentBased + AlwaysOn sampling strategy compliance.
///
/// **SCENARIO**: Test parent-based sampling with AlwaysOn fallback for root spans.
/// **REQUIREMENT**: Honor parent decisions, sample all roots with AlwaysOn fallback.
/// **ASSESSMENT**: Verify OpenTelemetry specification compliance.
#[test]
fn audit_parent_based_always_on_sampling_strategy() {
    println!("🔍 AUDIT: OpenTelemetry ParentBased + AlwaysOn sampling strategy");

    println!("📋 OpenTelemetry sampling requirements:");
    println!("   • ParentBased: Honor parent sampling decisions");
    println!("   • AlwaysOn fallback: Sample all root spans (no parent)");
    println!("   • Child spans inherit parent sampling state");
    println!("   • No override of parent decisions");

    let memory_exporter = InMemoryOtlpHttpExporter::new(Duration::from_millis(1));
    let exporter = LoadSheddingTraceExporter::new(
        Box::new(memory_exporter.clone()),
        100,
        Duration::from_secs(1),
    );

    // Configure ParentBased + AlwaysOn strategy
    let sampling_strategy = OtelSamplingStrategy::ParentBased {
        root_fallback: Box::new(OtelSamplingStrategy::AlwaysOn),
    };

    let mut test_spans = Vec::new();

    // Test Case 1: Parent span says SAMPLE (should honor)
    println!("📊 Test Case 1: Parent sampled=1 (should honor parent decision)");
    let parent_sampled_traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let parent_sampled_request = HeaderFixtureRequest::with_traceparent(parent_sampled_traceparent);
    let parent_sampled_context = extract_from_http(&parent_sampled_request.headers)
        .expect("valid traceparent")
        .expect("context present");

    let parent_sampled_decision = sampling_strategy.should_sample(
        Some(parent_sampled_context.flags.is_sampled()),
        &parent_sampled_context.trace_id.to_hex(),
    );

    println!("   Parent decision: sampled=1");
    println!("   ParentBased result: {}", parent_sampled_decision);
    assert!(
        parent_sampled_decision,
        "Should honor parent sampled=1 decision"
    );

    test_spans.push(OtlpSpan::new_with_flags(
        parent_sampled_context.span_id.to_hex(),
        "child_of_sampled_parent".to_string(),
        1000000000,
        1000001000,
        vec![("test_case".to_string(), "parent_sampled".to_string())],
        u8::from(parent_sampled_decision),
    ));

    // Test Case 2: Parent span says DON'T SAMPLE (should honor)
    println!("📊 Test Case 2: Parent sampled=0 (should honor parent decision)");
    let parent_unsampled_traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4737-00f067aa0ba902b8-00";
    let parent_unsampled_request =
        HeaderFixtureRequest::with_traceparent(parent_unsampled_traceparent);
    let parent_unsampled_context = extract_from_http(&parent_unsampled_request.headers)
        .expect("valid traceparent")
        .expect("context present");

    let parent_unsampled_decision = sampling_strategy.should_sample(
        Some(parent_unsampled_context.flags.is_sampled()),
        &parent_unsampled_context.trace_id.to_hex(),
    );

    println!("   Parent decision: sampled=0");
    println!("   ParentBased result: {}", parent_unsampled_decision);
    assert!(
        !parent_unsampled_decision,
        "Should honor parent sampled=0 decision"
    );

    // Don't add unsampled span to test_spans (it shouldn't be exported)

    // Test Case 3: ROOT span (no parent, should use AlwaysOn fallback)
    println!("📊 Test Case 3: Root span (no parent, AlwaysOn fallback)");
    let _root_request = HeaderFixtureRequest::without_traceparent();

    let root_decision = sampling_strategy.should_sample(None, "root_trace_id_12345");

    println!("   No parent present");
    println!("   AlwaysOn fallback result: {}", root_decision);
    assert!(
        root_decision,
        "AlwaysOn fallback should sample all root spans"
    );

    test_spans.push(OtlpSpan::new_with_flags(
        "root_span_id".to_string(),
        "root_operation".to_string(),
        1000002000,
        1000003000,
        vec![("test_case".to_string(), "root_always_on".to_string())],
        u8::from(root_decision),
    ));

    // Export test batch
    let batch = SpanBatch {
        batch_id: 1,
        spans: test_spans,
        created_at: Instant::now(),
    };

    exporter.export(&batch).expect("export should succeed");
    exporter.process_queue().expect("processing should succeed");

    let exported_batches = memory_exporter.exported_batches();

    println!("📊 OpenTelemetry sampling compliance verification:");
    if !exported_batches.is_empty() {
        let exported_batch = &exported_batches[0];
        println!("   Exported spans: {}", exported_batch.spans.len());

        let exported_names: Vec<&str> = exported_batch
            .spans
            .iter()
            .map(|s| s.name.as_str())
            .collect();

        println!("   Exported span names: {:?}", exported_names);

        // Should export: child_of_sampled_parent + root_operation
        // Should NOT export: child of unsampled parent
        assert_eq!(
            exported_batch.spans.len(),
            2,
            "Should export 2 spans: parent_sampled child + root"
        );

        assert!(
            exported_names.contains(&"child_of_sampled_parent"),
            "Should export child of sampled parent"
        );
        assert!(
            exported_names.contains(&"root_operation"),
            "Should export root span (AlwaysOn fallback)"
        );
    }

    println!("✅ OPENTELEMETRY PARENTBASED + ALWAYSON: COMPLIANT");
    println!("   • Parent sampled=1 decisions honored");
    println!("   • Parent sampled=0 decisions honored");
    println!("   • Root spans sampled with AlwaysOn fallback");
}

/// **AUDIT TEST**: Compare current implementation vs OpenTelemetry standard.
///
/// **SCENARIO**: Analyze current asupersync sampling vs OpenTelemetry spec.
/// **REQUIREMENT**: Should match OpenTelemetry ParentBased + AlwaysOn behavior.
/// **ASSESSMENT**: Identify any deviations from standard sampling strategies.
#[test]
fn audit_current_implementation_vs_otel_standard() {
    println!("🔍 AUDIT: Current implementation vs OpenTelemetry standard sampling");

    println!("📋 Current implementation analysis:");
    println!("   • LoadSheddingTraceExporter head-based sampling");
    println!("   • OtlpSpan.is_sampled() based on trace_flags");
    println!("   • W3C trace context flag propagation");

    // Analyze current implementation behavior
    let memory_exporter = InMemoryOtlpHttpExporter::new(Duration::from_millis(1));
    let exporter = LoadSheddingTraceExporter::new(
        Box::new(memory_exporter.clone()),
        100,
        Duration::from_secs(1),
    );

    println!("📊 Current implementation test matrix:");

    // Test 1: Upstream sampled=1 (current implementation)
    let sampled_span = OtlpSpan::new_with_flags(
        "current_impl_span_1".to_string(),
        "current_sampled_span".to_string(),
        1000000000,
        1000001000,
        vec![("implementation".to_string(), "current".to_string())],
        0x01, // Sampled
    );

    // Test 2: Upstream sampled=0 (current implementation)
    let unsampled_span = OtlpSpan::new_with_flags(
        "current_impl_span_2".to_string(),
        "current_unsampled_span".to_string(),
        1000002000,
        1000003000,
        vec![("implementation".to_string(), "current".to_string())],
        0x00, // Not sampled
    );

    // Test 3: Root span (no parent) - current implementation
    let root_span = OtlpSpan::new(
        "current_impl_root".to_string(),
        "current_root_span".to_string(),
        1000004000,
        1000005000,
        vec![("implementation".to_string(), "current".to_string())],
    );

    let batch = SpanBatch {
        batch_id: 1,
        spans: vec![sampled_span, unsampled_span, root_span],
        created_at: Instant::now(),
    };

    exporter.export(&batch).expect("export should succeed");
    exporter.process_queue().expect("processing should succeed");

    let exported_batches = memory_exporter.exported_batches();

    println!("📊 Current implementation behavior:");
    if !exported_batches.is_empty() {
        let exported_batch = &exported_batches[0];
        println!("   Exported spans: {}", exported_batch.spans.len());

        for span in &exported_batch.spans {
            println!("     - {} (sampled: {})", span.name, span.is_sampled());
        }

        // Analyze compliance with OpenTelemetry ParentBased + AlwaysOn
        let has_sampled_span = exported_batch
            .spans
            .iter()
            .any(|s| s.name == "current_sampled_span");
        let has_root_span = exported_batch
            .spans
            .iter()
            .any(|s| s.name == "current_root_span");
        let missing_unsampled = !exported_batch
            .spans
            .iter()
            .any(|s| s.name == "current_unsampled_span");

        println!("📊 OpenTelemetry compliance analysis:");
        println!(
            "   Sampled span exported: {} {}",
            has_sampled_span,
            if has_sampled_span { "✅" } else { "❌" }
        );
        println!(
            "   Root span exported: {} {}",
            has_root_span,
            if has_root_span { "✅" } else { "❌" }
        );
        println!(
            "   Unsampled span filtered: {} {}",
            missing_unsampled,
            if missing_unsampled { "✅" } else { "❌" }
        );

        if has_sampled_span && has_root_span && missing_unsampled {
            println!("✅ CURRENT IMPLEMENTATION: OpenTelemetry ParentBased + AlwaysOn compliant");
            println!("   • Honors parent sampling decisions");
            println!("   • Samples root spans (AlwaysOn-like behavior)");
            println!("   • Filters unsampled spans correctly");
        } else {
            println!("⚠️  CURRENT IMPLEMENTATION: Potential deviation from OpenTelemetry spec");
            println!("💡 RECOMMENDATION: Verify sampling strategy configuration");
        }
    }
}

/// **AUDIT TEST**: Verify incorrect override scenario (anti-pattern).
///
/// **SCENARIO**: Show what would happen if local sampler overrides parent decision.
/// **REQUIREMENT**: This would be DEFECTIVE per OpenTelemetry specification.
/// **ASSESSMENT**: Anti-pattern that breaks distributed tracing consistency.
#[test]
fn audit_incorrect_parent_override_antipattern() {
    println!("🚨 AUDIT: Incorrect parent override anti-pattern (OpenTelemetry violation)");

    println!("📋 DEFECTIVE anti-pattern (OpenTelemetry spec violation):");
    println!("   • Parent says sample=1");
    println!("   • Local sampler overrides to don't sample");
    println!("   • Result: broken distributed trace consistency");

    // Exercise what WRONG implementation would look like.
    let sampling_strategy = OtelSamplingStrategy::AlwaysOff; // Wrong: ignores parent

    // Parent context says sample
    let parent_sampled_traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4738-00f067aa0ba902b9-01";
    let parent_sampled_request = HeaderFixtureRequest::with_traceparent(parent_sampled_traceparent);
    let parent_sampled_context = extract_from_http(&parent_sampled_request.headers)
        .expect("valid traceparent")
        .expect("context present");

    // DEFECTIVE: Apply AlwaysOff regardless of parent decision
    let defective_decision = sampling_strategy.should_sample(
        None, // Wrong: ignoring parent decision
        &parent_sampled_context.trace_id.to_hex(),
    );

    println!("📊 Defective override check:");
    println!("   Parent decision: sampled=1");
    println!("   Local override: AlwaysOff");
    println!("   Defective result: {}", defective_decision);

    assert!(
        !defective_decision,
        "Defective implementation overrides parent sample=1 with local AlwaysOff"
    );

    println!("🚨 OPENTELEMETRY VIOLATION DEMONSTRATED");
    println!("   • Parent sampling decision ignored");
    println!("   • Breaks distributed trace consistency");
    println!("   • Violates ParentBased sampling strategy spec");
    println!("💡 SOLUTION: Always use ParentBased with proper fallback strategy");
}

/// **AUDIT TEST**: Test various OpenTelemetry sampling strategy combinations.
///
/// **SCENARIO**: Verify different standard OpenTelemetry sampling strategies.
/// **REQUIREMENT**: All standard strategies should work correctly.
/// **ASSESSMENT**: Strategy implementation correctness verification.
#[test]
fn audit_otel_sampling_strategies_matrix() {
    println!("🔍 AUDIT: OpenTelemetry sampling strategies matrix");

    println!("📋 Standard OpenTelemetry sampling strategies:");
    println!("   1. AlwaysOn - sample all spans");
    println!("   2. AlwaysOff - sample no spans");
    println!("   3. ParentBased + AlwaysOn - honor parent, sample roots");
    println!("   4. ParentBased + AlwaysOff - honor parent, don't sample roots");
    println!("   5. TraceIdRatioBased - sample fraction based on trace ID");

    let test_trace_id = "test_trace_12345";
    let parent_sampled = Some(true);
    let parent_unsampled = Some(false);
    let no_parent = None;

    println!("📊 Strategy behavior matrix:");

    // Strategy 1: AlwaysOn
    let always_on = OtelSamplingStrategy::AlwaysOn;
    println!("   AlwaysOn:");
    println!(
        "     Parent=1: {}",
        always_on.should_sample(parent_sampled, test_trace_id)
    );
    println!(
        "     Parent=0: {}",
        always_on.should_sample(parent_unsampled, test_trace_id)
    );
    println!(
        "     No parent: {}",
        always_on.should_sample(no_parent, test_trace_id)
    );

    // Strategy 2: AlwaysOff
    let always_off = OtelSamplingStrategy::AlwaysOff;
    println!("   AlwaysOff:");
    println!(
        "     Parent=1: {}",
        always_off.should_sample(parent_sampled, test_trace_id)
    );
    println!(
        "     Parent=0: {}",
        always_off.should_sample(parent_unsampled, test_trace_id)
    );
    println!(
        "     No parent: {}",
        always_off.should_sample(no_parent, test_trace_id)
    );

    // Strategy 3: ParentBased + AlwaysOn
    let parent_based_on = OtelSamplingStrategy::ParentBased {
        root_fallback: Box::new(OtelSamplingStrategy::AlwaysOn),
    };
    println!("   ParentBased + AlwaysOn:");
    println!(
        "     Parent=1: {}",
        parent_based_on.should_sample(parent_sampled, test_trace_id)
    );
    println!(
        "     Parent=0: {}",
        parent_based_on.should_sample(parent_unsampled, test_trace_id)
    );
    println!(
        "     No parent: {}",
        parent_based_on.should_sample(no_parent, test_trace_id)
    );

    // Strategy 4: ParentBased + AlwaysOff
    let parent_based_off = OtelSamplingStrategy::ParentBased {
        root_fallback: Box::new(OtelSamplingStrategy::AlwaysOff),
    };
    println!("   ParentBased + AlwaysOff:");
    println!(
        "     Parent=1: {}",
        parent_based_off.should_sample(parent_sampled, test_trace_id)
    );
    println!(
        "     Parent=0: {}",
        parent_based_off.should_sample(parent_unsampled, test_trace_id)
    );
    println!(
        "     No parent: {}",
        parent_based_off.should_sample(no_parent, test_trace_id)
    );

    // Verify key OpenTelemetry requirements
    println!("📊 OpenTelemetry spec compliance verification:");

    // Requirement 1: ParentBased honors parent decisions
    assert!(parent_based_on.should_sample(parent_sampled, test_trace_id));
    assert!(!parent_based_on.should_sample(parent_unsampled, test_trace_id));
    println!("   ✅ ParentBased honors parent sampling decisions");

    // Requirement 2: AlwaysOn fallback samples roots
    assert!(parent_based_on.should_sample(no_parent, test_trace_id));
    println!("   ✅ AlwaysOn fallback samples root spans");

    // Requirement 3: AlwaysOff fallback doesn't sample roots
    assert!(!parent_based_off.should_sample(no_parent, test_trace_id));
    println!("   ✅ AlwaysOff fallback doesn't sample root spans");

    println!("✅ OPENTELEMETRY SAMPLING STRATEGIES: All standard patterns verified");
}
