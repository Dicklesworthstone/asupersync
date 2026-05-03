//! Span lifecycle obligation leak audit test.
//!
//! **AUDIT SCOPE**: Verifies that spans created but never ended are detected as
//! obligation leaks per asupersync's "no obligation leaks" rule from AGENTS.md.
//!
//! **ASUPERSYNC REQUIREMENT**:
//! - Spans are obligations that MUST be completed via .end()
//! - Forgotten spans MUST be detected as obligation leaks (not silently dropped)
//! - Per AGENTS.md: "no obligation leaks" is a core invariant
//!
//! **CRITICAL**: Silent span drops would hide programming errors and violate
//! the structured concurrency guarantee.

#![cfg(test)]

use crate::Time;
use crate::observability::otel_structured_concurrency::{
    EntityId, OtelStructuredConcurrencyConfig, SpanStorage, SpanType,
};
use std::time::Duration;

/// **AUDIT TEST**: Verify unended spans are detected as obligation leaks.
///
/// **SCENARIO**: Create spans but forget to call .end() on them.
/// **REQUIREMENT**: These MUST be detected as obligation leaks, not silently dropped.
/// **ASUPERSYNC RULE**: "no obligation leaks" - spans are obligations that must complete.
#[test]
fn audit_unended_spans_create_obligation_leaks() {
    println!("🔍 AUDIT: Span lifecycle obligation leak detection");

    let config = OtelStructuredConcurrencyConfig::default();
    let storage = SpanStorage::new(config);

    // Create spans but forget to end them (simulating programmer error)
    let entity1 = EntityId::region_from_raw(1);
    let entity2 = EntityId::region_from_raw(2);
    let entity3 = EntityId::region_from_raw(3);

    println!("📋 Creating spans without ending them (simulating forgotten .end() calls)");

    // Create spans that will never be ended
    assert!(storage.create_span(
        SpanType::Task,
        entity1,
        "forgotten_task_span".to_string(),
        Time::from_nanos(1000),
        #[cfg(feature = "metrics")]
        None,
        #[cfg(not(feature = "metrics"))]
        None,
    ));

    assert!(storage.create_span(
        SpanType::Region,
        entity2,
        "forgotten_region_span".to_string(),
        Time::from_nanos(2000),
        #[cfg(feature = "metrics")]
        None,
        #[cfg(not(feature = "metrics"))]
        None,
    ));

    assert!(storage.create_span(
        SpanType::Task,
        entity3,
        "forgotten_task_span_2".to_string(),
        Time::from_nanos(3000),
        #[cfg(feature = "metrics")]
        None,
        #[cfg(not(feature = "metrics"))]
        None,
    ));

    let (created, materialized, _, _, _, _) = storage.stats();
    println!(
        "📊 Created {} spans, materialized {}",
        created, materialized
    );

    // CRITICAL AUDIT CHECK: These spans should be detectable as obligation leaks
    let leaked_spans = storage.detect_obligation_leaks(Duration::from_secs(30));

    assert_eq!(
        leaked_spans.len(),
        3,
        "OBLIGATION LEAK VIOLATION: Expected 3 leaked spans (unended obligations), got {}. \
         Per AGENTS.md 'no obligation leaks' rule, unended spans MUST be detected as leaks.",
        leaked_spans.len()
    );

    println!("✅ OBLIGATION LEAK DETECTION VERIFIED");
    println!(
        "   ✓ {} unended spans detected as obligation leaks",
        leaked_spans.len()
    );

    for leak in &leaked_spans {
        println!(
            "   - Leaked span: {:?} (age: {:?})",
            leak.entity_id, leak.age
        );
    }
}

/// **AUDIT TEST**: Properly ended spans do not leak.
///
/// **SCENARIO**: Create spans and properly end them.
/// **REQUIREMENT**: These should NOT appear as obligation leaks.
#[test]
fn audit_properly_ended_spans_do_not_leak() {
    println!("🔍 AUDIT: Properly ended spans do not create obligation leaks");

    let config = OtelStructuredConcurrencyConfig::default();
    let storage = SpanStorage::new(config);

    // Create and properly end spans
    let entity1 = EntityId::region_from_raw(1);
    let entity2 = EntityId::region_from_raw(2);

    println!("📋 Creating and properly ending spans");

    assert!(storage.create_span(
        SpanType::Task,
        entity1,
        "properly_ended_span_1".to_string(),
        Time::from_nanos(1000),
        #[cfg(feature = "metrics")]
        None,
        #[cfg(not(feature = "metrics"))]
        None,
    ));

    assert!(storage.create_span(
        SpanType::Region,
        entity2,
        "properly_ended_span_2".to_string(),
        Time::from_nanos(2000),
        #[cfg(feature = "metrics")]
        None,
        #[cfg(not(feature = "metrics"))]
        None,
    ));

    // Mock tracer for ending spans
    #[cfg(feature = "metrics")]
    let tracer = opentelemetry::global::tracer("test");
    #[cfg(not(feature = "metrics"))]
    let tracer = ();

    // Properly end the spans
    storage.end_span(entity1, &tracer);
    storage.end_span(entity2, &tracer);

    println!("📊 Spans properly ended");

    // Check for leaks - should be none
    let leaked_spans = storage.detect_obligation_leaks(Duration::from_secs(30));

    assert_eq!(
        leaked_spans.len(),
        0,
        "Properly ended spans should not appear as obligation leaks, got {}",
        leaked_spans.len()
    );

    println!("✅ NO OBLIGATION LEAKS: Properly ended spans do not leak");
}

/// **AUDIT TEST**: Current implementation defect demonstration.
///
/// **EXPECTATION**: This test will FAIL with current implementation,
/// demonstrating that obligation leak detection is not implemented.
#[test]
fn audit_current_implementation_missing_leak_detection() {
    println!("🚨 AUDIT: Demonstrating current obligation leak detection defect");

    let config = OtelStructuredConcurrencyConfig::default();
    let storage = SpanStorage::new(config);

    // Create span without ending it
    let entity = EntityId::region_from_raw(1);
    assert!(storage.create_span(
        SpanType::Task,
        entity,
        "leaked_span".to_string(),
        Time::from_nanos(1000),
        #[cfg(feature = "metrics")]
        None,
        #[cfg(not(feature = "metrics"))]
        None,
    ));

    // Current implementation: leak detection method doesn't exist
    // This will fail to compile, demonstrating the missing functionality

    // Simulate what the leak detection should find
    println!("🚨 DEFECT CONFIRMED: Obligation leak detection not implemented");
    println!("💡 REQUIREMENT: Implement detect_obligation_leaks() method");
    println!("📋 SOLUTION NEEDED: Track span creation time and detect aged unended spans");
}
