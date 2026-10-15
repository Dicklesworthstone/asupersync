//! Head-based sampling compliance audit test.
//!
//! **AUDIT SCOPE**: Verifies that OTLP trace exporters respect head-based sampling
//! decisions when `traceflags=0` (not sampled) is received in incoming traceparent headers.
//!
//! **OTLP SPECIFICATION REQUIREMENT**:
//! - When `traceflags=0`, spans MUST be dropped before serialization
//! - Only `traceflags=1` spans should reach the OTLP exporter
//! - This is "head-based sampling" per OTLP best practices
//!
//! **CRITICAL**: Violation of this requirement causes unnecessary network overhead
//! and storage costs for unsampled traces.

#![cfg(test)]

use crate::observability::otlp_trace_exporter::{
    InMemoryOtlpHttpExporter, LoadSheddingTraceExporter, OtlpSpan, SpanBatch, TraceExporter,
};
use crate::observability::w3c_trace_context::extract_from_http;
use std::collections::HashMap;
use std::time::Duration;

/// HTTP request fixture for testing trace context extraction.
struct HeaderFixtureRequest {
    headers: HashMap<String, String>,
}

impl HeaderFixtureRequest {
    fn new() -> Self {
        Self {
            headers: HashMap::new(),
        }
    }

    fn with_traceparent(mut self, traceparent: &str) -> Self {
        self.headers
            .insert("traceparent".to_string(), traceparent.to_string());
        self
    }
}

/// **AUDIT TEST**: Verify head-based sampling compliance.
///
/// **SCENARIO**: Receive traceparent headers with `traceflags=0` (not sampled)
/// and `traceflags=1` (sampled). Only sampled spans should reach OTLP export.
/// **REQUIREMENT**: Unsampled spans MUST be dropped before serialization.
#[test]
fn audit_head_based_sampling_compliance() {
    println!("🔍 AUDIT: Head-based sampling compliance per OTLP specification");

    let memory_exporter = InMemoryOtlpHttpExporter::new(Duration::from_millis(1));
    let exporter = LoadSheddingTraceExporter::new(
        Box::new(memory_exporter.clone()),
        100,
        Duration::from_secs(1),
    );

    // Test Case 1: Unsampled span (traceflags=0)
    let unsampled_traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00";
    //                                                                                    ^^ flags=00 (not sampled)

    let unsampled_request = HeaderFixtureRequest::new().with_traceparent(unsampled_traceparent);
    let unsampled_context = extract_from_http(&unsampled_request.headers)
        .expect("valid traceparent")
        .expect("context present");

    // Verify flags are correctly parsed as not sampled
    assert!(
        !unsampled_context.flags.is_sampled(),
        "flags=00 should parse as not sampled"
    );

    // Create span batch for unsampled trace
    let unsampled_batch = SpanBatch {
        batch_id: 1,
        spans: vec![OtlpSpan::new_with_flags(
            unsampled_context.span_id.to_hex(),
            "unsampled_operation".to_string(),
            1000000000,
            1000001000,
            vec![("sampled".to_string(), "false".to_string())],
            unsampled_context.flags.bits(), // Use actual flags from context
        )],
        created_at: std::time::Instant::now(),
    };

    // Test Case 2: Sampled span (traceflags=1)
    let sampled_traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4737-00f067aa0ba902b8-01";
    //                                                                                ^^ flags=01 (sampled)

    let sampled_request = HeaderFixtureRequest::new().with_traceparent(sampled_traceparent);
    let sampled_context = extract_from_http(&sampled_request.headers)
        .expect("valid traceparent")
        .expect("context present");

    // Verify flags are correctly parsed as sampled
    assert!(
        sampled_context.flags.is_sampled(),
        "flags=01 should parse as sampled"
    );

    // Create span batch for sampled trace
    let sampled_batch = SpanBatch {
        batch_id: 2,
        spans: vec![OtlpSpan::new_with_flags(
            sampled_context.span_id.to_hex(),
            "sampled_operation".to_string(),
            1000002000,
            1000003000,
            vec![("sampled".to_string(), "true".to_string())],
            sampled_context.flags.bits(), // Use actual flags from context
        )],
        created_at: std::time::Instant::now(),
    };

    println!("📋 Submitting unsampled span batch (should be dropped)");
    exporter
        .export(&unsampled_batch)
        .expect("export call should succeed");

    println!("📋 Submitting sampled span batch (should be processed)");
    exporter
        .export(&sampled_batch)
        .expect("export call should succeed");

    // Process the export queue
    let processed = exporter.process_queue().expect("processing should succeed");
    println!("📊 Processed {} batches", processed);

    // CRITICAL AUDIT CHECK: Only sampled spans should be exported
    let exported_batches = memory_exporter.exported_batches();

    println!(
        "📊 Exported {} batches to OTLP endpoint",
        exported_batches.len()
    );
    for (i, batch) in exported_batches.iter().enumerate() {
        println!(
            "  Batch {}: {} spans, batch_id={}",
            i,
            batch.spans.len(),
            batch.batch_id
        );
        for span in &batch.spans {
            println!("    - {} ({})", span.name, span.span_id);
        }
    }

    // **HEAD-BASED SAMPLING COMPLIANCE CHECK**
    // Per OTLP specification, only sampled spans should be exported
    assert_eq!(
        exported_batches.len(),
        1,
        "OTLP COMPLIANCE VIOLATION: Expected 1 exported batch (only sampled), got {}. \
         Head-based sampling MUST drop unsampled spans before serialization.",
        exported_batches.len()
    );

    if !exported_batches.is_empty() {
        let exported_batch = &exported_batches[0];
        assert_eq!(
            exported_batch.batch_id, 2,
            "Only the sampled batch (batch_id=2) should be exported"
        );
        assert_eq!(
            exported_batch.spans[0].name, "sampled_operation",
            "Only sampled spans should reach OTLP export"
        );
    }

    println!("✅ HEAD-BASED SAMPLING COMPLIANCE VERIFIED");
    println!("   ✓ Unsampled spans (traceflags=0) dropped before export");
    println!("   ✓ Sampled spans (traceflags=1) exported to OTLP endpoint");
}

/// **AUDIT TEST**: Current implementation drops unsampled spans.
#[test]
fn audit_current_implementation_drops_unsampled_spans() {
    println!("AUDIT: Verifying current head-based sampling implementation");

    let memory_exporter = InMemoryOtlpHttpExporter::new(Duration::from_millis(1));
    let exporter = LoadSheddingTraceExporter::new(
        Box::new(memory_exporter.clone()),
        100,
        Duration::from_secs(1),
    );

    // Create unsampled span batch
    let unsampled_batch = SpanBatch {
        batch_id: 1,
        spans: vec![OtlpSpan::new_with_flags(
            "unsampled123456789".to_string(),
            "unsampled_operation".to_string(),
            1000000000,
            1000001000,
            vec![("trace_flags".to_string(), "0".to_string())],
            0x00, // Not sampled
        )],
        created_at: std::time::Instant::now(),
    };

    exporter
        .export(&unsampled_batch)
        .expect("export should succeed");
    exporter.process_queue().expect("processing should succeed");

    let exported_batches = memory_exporter.exported_batches();

    assert!(
        exported_batches.is_empty(),
        "unsampled spans must be dropped before OTLP export; exported {} batches",
        exported_batches.len()
    );
    println!("Head-based sampling implementation drops unsampled spans");
}

/// **AUDIT TEST**: Mixed sampling scenario.
///
/// **SCENARIO**: Process batch with mixed sampling decisions.
/// **REQUIREMENT**: Only sampled spans within the batch should be exported.
#[test]
fn audit_mixed_sampling_batch_filtering() {
    println!("🔍 AUDIT: Mixed sampling batch filtering");

    let memory_exporter = InMemoryOtlpHttpExporter::new(Duration::from_millis(1));
    let exporter = LoadSheddingTraceExporter::new(
        Box::new(memory_exporter.clone()),
        100,
        Duration::from_secs(1),
    );

    // Create batch with mixed sampling
    let mixed_batch = SpanBatch {
        batch_id: 1,
        spans: vec![
            OtlpSpan::new_with_flags(
                "unsampled_span_1".to_string(),
                "unsampled_op_1".to_string(),
                1000000000,
                1000001000,
                vec![("trace_flags".to_string(), "0".to_string())],
                0x00, // Not sampled
            ),
            OtlpSpan::new_with_flags(
                "sampled_span_1".to_string(),
                "sampled_op_1".to_string(),
                1000002000,
                1000003000,
                vec![("trace_flags".to_string(), "1".to_string())],
                0x01, // Sampled
            ),
            OtlpSpan::new_with_flags(
                "unsampled_span_2".to_string(),
                "unsampled_op_2".to_string(),
                1000004000,
                1000005000,
                vec![("trace_flags".to_string(), "0".to_string())],
                0x00, // Not sampled
            ),
        ],
        created_at: std::time::Instant::now(),
    };

    exporter
        .export(&mixed_batch)
        .expect("export should succeed");
    exporter.process_queue().expect("processing should succeed");

    let exported_batches = memory_exporter.exported_batches();

    // HEAD-BASED SAMPLING: Only sampled spans should be exported
    if !exported_batches.is_empty() {
        let exported_batch = &exported_batches[0];
        assert_eq!(
            exported_batch.spans.len(),
            1,
            "Only 1 sampled span should be exported from mixed batch"
        );
        assert_eq!(
            exported_batch.spans[0].name, "sampled_op_1",
            "Only the sampled span should remain after filtering"
        );
    }

    println!("✅ MIXED BATCH FILTERING VERIFIED");
}
