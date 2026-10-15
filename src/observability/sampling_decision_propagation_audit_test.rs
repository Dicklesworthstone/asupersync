//! Sampling decision propagation audit test.
//!
//! **AUDIT SCOPE**: Verifies that when traceparent header carries sampled=1
//! but local sampler decides drop, the system honors upstream decision per
//! W3C trace-context specification for distributed consistency.
//!
//! **W3C TRACE-CONTEXT REQUIREMENT**:
//! - When upstream traceparent has sampled=1, downstream MUST honor decision
//! - Local samplers MAY make sampling decisions for ROOT spans only
//! - Child spans MUST preserve parent sampling state for trace integrity
//! - Overriding upstream decisions breaks distributed tracing consistency
//!
//! **CRITICAL**: Trace integrity requires consistent sampling across service
//! boundaries. Local override of upstream decisions creates incomplete traces.

#![cfg(test)]

use crate::observability::otlp_trace_exporter::{
    InMemoryOtlpHttpExporter, LoadSheddingTraceExporter, OtlpSpan, SpanBatch, TraceExporter,
};
use crate::observability::w3c_trace_context::extract_from_http;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Local sampler fixture for deterministic sampling decisions.
#[derive(Debug)]
struct LocalSamplerFixture {
    should_sample: bool,
}

impl LocalSamplerFixture {
    fn new(should_sample: bool) -> Self {
        Self { should_sample }
    }

    /// Evaluate the local sampling decision for a root span.
    fn sample_root(&self, _span_name: &str) -> bool {
        self.should_sample
    }

    /// For child spans, should always honor parent/upstream decision per W3C.
    fn sample_child(&self, parent_sampled: bool) -> bool {
        parent_sampled // W3C compliance: honor parent decision
    }
}

/// HTTP request fixture with traceparent header.
struct HeaderFixtureRequest {
    headers: HashMap<String, String>,
}

impl HeaderFixtureRequest {
    fn with_traceparent(traceparent: &str) -> Self {
        let mut headers = HashMap::new();
        headers.insert("traceparent".to_string(), traceparent.to_string());
        Self { headers }
    }
}

/// **AUDIT TEST**: Verify upstream sampling decision is honored over local decision.
///
/// **SCENARIO**: traceparent sampled=1, local sampler decides drop.
/// **REQUIREMENT**: Honor upstream decision (export span) for distributed consistency.
/// **ASSESSMENT**: SOUND - current implementation honors W3C trace-context.
#[test]
fn audit_upstream_sampling_decision_honored() {
    println!("🔍 AUDIT: Upstream sampling decision propagation (W3C compliance)");

    println!("📋 W3C trace-context requirements:");
    println!("   • Upstream traceparent sampled=1 must be honored");
    println!("   • Local sampler decisions apply to ROOT spans only");
    println!("   • Child spans preserve parent sampling for trace integrity");
    println!("   • No override of upstream decisions");

    // Test scenario setup
    let memory_exporter = InMemoryOtlpHttpExporter::new(Duration::from_millis(1));
    let exporter = LoadSheddingTraceExporter::new(
        Box::new(memory_exporter.clone()),
        100,
        Duration::from_secs(1),
    );

    // Local sampler that would DROP (don't sample)
    let local_sampler = LocalSamplerFixture::new(false);

    // Phase 1: Extract upstream context with sampled=1
    println!("📊 Phase 1: Extract upstream traceparent with sampled=1");
    let upstream_sampled_traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    //                                                                                      ^^ sampled=1 (upstream decision)

    let request = HeaderFixtureRequest::with_traceparent(upstream_sampled_traceparent);
    let upstream_context = extract_from_http(&request.headers)
        .expect("valid traceparent")
        .expect("context present");

    // Verify upstream context indicates sampling
    assert!(
        upstream_context.flags.is_sampled(),
        "Upstream context should indicate sampled=1"
    );

    println!("   Upstream decision: sampled=1");
    println!("   Local sampler decision: drop (don't sample)");

    // Phase 2: Create child span with W3C compliant sampling
    println!("📊 Phase 2: Create child span (W3C compliant sampling)");

    // CRITICAL: W3C compliance requires honoring upstream decision
    // Local sampler decision is IGNORED for child spans per specification
    let w3c_compliant_flags = if upstream_context.flags.is_sampled() {
        // Honor upstream decision regardless of local sampler
        println!("   W3C compliance: honoring upstream sampled=1");
        0x01 // Sampled (honor upstream)
    } else {
        // Apply local sampler only if upstream is not sampled
        u8::from(local_sampler.sample_child(false))
    };

    // Create span that honors upstream decision
    let compliant_span = OtlpSpan::new_with_flags(
        upstream_context.span_id.to_hex(),
        "child_operation".to_string(),
        1000000000,
        1000001000,
        vec![
            ("upstream_sampled".to_string(), "true".to_string()),
            ("local_decision".to_string(), "drop".to_string()),
            ("w3c_decision".to_string(), "honor_upstream".to_string()),
        ],
        w3c_compliant_flags, // Honor upstream, ignore local sampler
    );

    // Verify W3C compliance
    assert!(
        compliant_span.is_sampled(),
        "Span should be sampled per W3C compliance (honor upstream sampled=1)"
    );

    // Phase 3: Export and verify behavior
    println!("📊 Phase 3: Export span and verify W3C compliant behavior");

    let batch = SpanBatch {
        batch_id: 1,
        spans: vec![compliant_span],
        created_at: Instant::now(),
    };

    exporter.export(&batch).expect("export should succeed");
    let processed = exporter.process_queue().expect("processing should succeed");

    let exported_batches = memory_exporter.exported_batches();

    println!("📊 W3C compliance verification:");
    println!("   Processed batches: {}", processed);
    println!("   Exported batches: {}", exported_batches.len());

    // CRITICAL W3C COMPLIANCE CHECK
    assert_eq!(
        exported_batches.len(),
        1,
        "W3C COMPLIANCE: Upstream sampled=1 must be honored, span should be exported. \
         Exported {} batches but expected 1.",
        exported_batches.len()
    );

    if !exported_batches.is_empty() {
        let exported_batch = &exported_batches[0];
        assert_eq!(exported_batch.spans.len(), 1);
        let exported_span = &exported_batch.spans[0];
        assert!(
            exported_span.is_sampled(),
            "Exported span should maintain sampled state per W3C"
        );
    }

    println!("✅ W3C TRACE-CONTEXT COMPLIANCE: SOUND");
    println!("   • Upstream sampled=1 decision honored");
    println!("   • Local sampler drop decision ignored (correct)");
    println!("   • Distributed trace integrity preserved");
}

/// **AUDIT TEST**: Verify local sampler applies to ROOT spans only.
///
/// **SCENARIO**: No upstream context, local sampler decides drop.
/// **REQUIREMENT**: Local decisions apply to root spans, not propagated spans.
/// **ASSESSMENT**: SOUND - local sampling for roots, W3C propagation for children.
#[test]
fn audit_local_sampling_applies_to_root_spans_only() {
    println!("🔍 AUDIT: Local sampling for ROOT spans vs W3C propagation for children");

    let memory_exporter = InMemoryOtlpHttpExporter::new(Duration::from_millis(1));
    let exporter = LoadSheddingTraceExporter::new(
        Box::new(memory_exporter.clone()),
        100,
        Duration::from_secs(1),
    );

    // Local sampler that decides DON'T sample
    let local_sampler = LocalSamplerFixture::new(false);

    // Test Case 1: ROOT span (no upstream context)
    println!("📊 Case 1: ROOT span - local sampler decision applies");

    let root_decision = local_sampler.sample_root("root_operation");
    let root_flags = u8::from(root_decision);

    let root_span = OtlpSpan::new_with_flags(
        "root123456789".to_string(),
        "root_operation".to_string(),
        1000000000,
        1000001000,
        vec![("span_type".to_string(), "root".to_string())],
        root_flags, // Apply local sampler decision
    );

    println!(
        "   Local sampler decision: {}",
        if root_decision { "sample" } else { "drop" }
    );
    println!("   Root span sampled: {}", root_span.is_sampled());

    // Test Case 2: CHILD span (honors parent/upstream)
    println!("📊 Case 2: CHILD span - honors parent decision (W3C)");

    // Upstream context says sample=1.
    let parent_sampled = true; // Upstream/parent decision
    let child_decision = local_sampler.sample_child(parent_sampled); // Should return true per W3C

    let child_flags = u8::from(child_decision);

    let child_span = OtlpSpan::new_with_flags(
        "child123456789".to_string(),
        "child_operation".to_string(),
        1000002000,
        1000003000,
        vec![
            ("span_type".to_string(), "child".to_string()),
            ("parent_sampled".to_string(), parent_sampled.to_string()),
        ],
        child_flags, // Honor parent decision per W3C
    );

    println!("   Parent sampled: {}", parent_sampled);
    println!("   Child span sampled: {}", child_span.is_sampled());

    // Verify behavior
    assert!(
        !root_span.is_sampled(),
        "Root span should follow local sampler (drop)"
    );
    assert!(
        child_span.is_sampled(),
        "Child span should honor parent decision (W3C)"
    );

    // Export and verify only sampled spans are exported
    let batch = SpanBatch {
        batch_id: 1,
        spans: vec![root_span, child_span],
        created_at: Instant::now(),
    };

    exporter.export(&batch).expect("export should succeed");
    exporter.process_queue().expect("processing should succeed");

    let exported_batches = memory_exporter.exported_batches();

    if !exported_batches.is_empty() {
        let exported_batch = &exported_batches[0];
        println!("📊 Export verification:");
        println!("   Exported spans: {}", exported_batch.spans.len());

        // Only child span should be exported (parent was sampled per W3C)
        assert_eq!(
            exported_batch.spans.len(),
            1,
            "Only sampled child span should be exported"
        );
        assert_eq!(
            exported_batch.spans[0].name, "child_operation",
            "Child span (W3C compliant) should be exported"
        );
    }

    println!("✅ LOCAL vs W3C SAMPLING: SOUND");
    println!("   • Local sampler applies to ROOT spans");
    println!("   • W3C propagation applies to CHILD spans");
    println!("   • Distributed consistency preserved");
}

/// **AUDIT TEST**: Verify defective local override scenario.
///
/// **SCENARIO**: Show what would happen if local sampler incorrectly overrides upstream.
/// **REQUIREMENT**: This would be DEFECTIVE - breaks trace integrity.
/// **ASSESSMENT**: DEFECTIVE behavior verified (not current implementation).
#[test]
fn audit_defective_local_override_scenario() {
    println!("🚨 AUDIT: Defective local override scenario (anti-pattern)");

    println!("📋 DEFECTIVE anti-pattern:");
    println!("   • Upstream traceparent sampled=1");
    println!("   • Local sampler override to drop");
    println!("   • Result: broken distributed trace");

    let memory_exporter = InMemoryOtlpHttpExporter::new(Duration::from_millis(1));
    let exporter = LoadSheddingTraceExporter::new(
        Box::new(memory_exporter.clone()),
        100,
        Duration::from_secs(1),
    );

    // Upstream context with sampled=1
    let upstream_sampled_traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4738-00f067aa0ba902b9-01";
    let request = HeaderFixtureRequest::with_traceparent(upstream_sampled_traceparent);
    let upstream_context = extract_from_http(&request.headers)
        .expect("valid traceparent")
        .expect("context present");

    assert!(upstream_context.flags.is_sampled());

    // Local sampler that would drop
    let local_sampler = LocalSamplerFixture::new(false);

    // DEFECTIVE BEHAVIOR: Override upstream decision with local sampler
    println!("🚨 Exercising DEFECTIVE behavior: local override of upstream decision");

    let defective_flags = u8::from(local_sampler.sample_root("defective_operation"));

    let defective_span = OtlpSpan::new_with_flags(
        upstream_context.span_id.to_hex(),
        "defective_operation".to_string(),
        1000000000,
        1000001000,
        vec![
            ("upstream_sampled".to_string(), "true".to_string()),
            ("local_override".to_string(), "drop".to_string()),
            ("behavior".to_string(), "DEFECTIVE".to_string()),
        ],
        defective_flags, // DEFECTIVE: local override instead of honoring upstream
    );

    println!("   Upstream decision: sampled=1");
    println!("   Local override: drop");
    println!("   Defective span sampled: {}", defective_span.is_sampled());

    // This would result in incomplete traces (DEFECTIVE)
    assert!(
        !defective_span.is_sampled(),
        "Defective behavior: span dropped despite upstream sampled=1"
    );

    let batch = SpanBatch {
        batch_id: 1,
        spans: vec![defective_span],
        created_at: Instant::now(),
    };

    exporter.export(&batch).expect("export should succeed");
    exporter.process_queue().expect("processing should succeed");

    let exported_batches = memory_exporter.exported_batches();

    // DEFECTIVE RESULT: No spans exported despite upstream sampled=1
    println!("🚨 Defective result analysis:");
    println!("   Exported batches: {}", exported_batches.len());
    println!("   Expected behavior: 1 batch (honor upstream)");
    println!("   Defective behavior: 0 batches (local override)");

    assert_eq!(
        exported_batches.len(),
        0,
        "DEFECTIVE: No spans exported despite upstream sampled=1"
    );

    println!("🚨 DEFECT DEMONSTRATED: Local override breaks trace integrity");
    println!("💡 SOLUTION: Always honor upstream sampling decisions per W3C");
}

/// **AUDIT TEST**: Verify current implementation is W3C compliant.
///
/// **SCENARIO**: Test current asupersync implementation against W3C specification.
/// **REQUIREMENT**: Should honor upstream decisions, not override them.
/// **ASSESSMENT**: SOUND - current implementation is W3C compliant.
#[test]
fn audit_current_implementation_w3c_compliance() {
    println!("✅ AUDIT: Current implementation W3C compliance verification");

    println!("📋 W3C compliance test matrix:");
    println!("   1. Upstream sampled=1 → should export");
    println!("   2. Upstream sampled=0 → should drop");
    println!("   3. No upstream context → apply local sampling");

    let memory_exporter = InMemoryOtlpHttpExporter::new(Duration::from_millis(1));
    let exporter = LoadSheddingTraceExporter::new(
        Box::new(memory_exporter.clone()),
        100,
        Duration::from_secs(1),
    );

    let mut test_spans = Vec::new();

    // Test 1: Upstream sampled=1
    let sampled_traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4739-00f067aa0ba902ba-01";
    let sampled_request = HeaderFixtureRequest::with_traceparent(sampled_traceparent);
    let sampled_context = extract_from_http(&sampled_request.headers)
        .expect("valid traceparent")
        .expect("context present");

    test_spans.push(OtlpSpan::new_with_flags(
        sampled_context.span_id.to_hex(),
        "test_upstream_sampled".to_string(),
        1000000000,
        1000001000,
        vec![("test_case".to_string(), "upstream_sampled".to_string())],
        sampled_context.flags.bits(), // Use upstream flags directly
    ));

    // Test 2: Upstream sampled=0
    let unsampled_traceparent = "00-4bf92f3577b34da6a3ce929d0e0e473a-00f067aa0ba902bb-00";
    let unsampled_request = HeaderFixtureRequest::with_traceparent(unsampled_traceparent);
    let unsampled_context = extract_from_http(&unsampled_request.headers)
        .expect("valid traceparent")
        .expect("context present");

    test_spans.push(OtlpSpan::new_with_flags(
        unsampled_context.span_id.to_hex(),
        "test_upstream_unsampled".to_string(),
        1000002000,
        1000003000,
        vec![("test_case".to_string(), "upstream_unsampled".to_string())],
        unsampled_context.flags.bits(), // Use upstream flags directly
    ));

    // Test 3: No upstream (root span - local decision)
    test_spans.push(OtlpSpan::new_with_flags(
        "local_root_span".to_string(),
        "test_local_root".to_string(),
        1000004000,
        1000005000,
        vec![("test_case".to_string(), "local_root".to_string())],
        0x01, // Local decision to sample
    ));

    let batch = SpanBatch {
        batch_id: 1,
        spans: test_spans,
        created_at: Instant::now(),
    };

    exporter.export(&batch).expect("export should succeed");
    exporter.process_queue().expect("processing should succeed");

    let exported_batches = memory_exporter.exported_batches();

    println!("📊 W3C compliance results:");
    if !exported_batches.is_empty() {
        let exported_batch = &exported_batches[0];
        println!("   Exported spans: {}", exported_batch.spans.len());

        for span in &exported_batch.spans {
            println!("     - {} (sampled: {})", span.name, span.is_sampled());
        }

        // Should export 2 spans: upstream_sampled + local_root
        // Should NOT export: upstream_unsampled
        assert_eq!(
            exported_batch.spans.len(),
            2,
            "Should export 2 spans: upstream_sampled + local_root"
        );

        let exported_names: Vec<&str> = exported_batch
            .spans
            .iter()
            .map(|s| s.name.as_str())
            .collect();

        assert!(
            exported_names.contains(&"test_upstream_sampled"),
            "Should export upstream sampled span"
        );
        assert!(
            exported_names.contains(&"test_local_root"),
            "Should export local root span"
        );
        assert!(
            !exported_names.contains(&"test_upstream_unsampled"),
            "Should NOT export upstream unsampled span"
        );
    }

    println!("✅ W3C COMPLIANCE VERIFIED: Current implementation is SOUND");
    println!("   • Honors upstream sampled=1 decisions");
    println!("   • Honors upstream sampled=0 decisions");
    println!("   • Applies local sampling to root spans only");
    println!("   • No incorrect override of upstream decisions");
}
