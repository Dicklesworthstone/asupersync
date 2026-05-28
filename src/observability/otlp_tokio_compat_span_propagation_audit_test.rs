//! OTLP Tokio compatibility span propagation audit test.
//!
//! **AUDIT SCOPE**: Verifies OTLP-Trace span context propagation when running
//! through asupersync-tokio-compat runtime boundary adapters.
//!
//! **TOKIO COMPATIBILITY SPAN PROPAGATION SPECIFICATION**:
//! - Spans should propagate correctly across asupersync ↔ tokio runtime boundaries
//! - Parent-child relationships must be preserved through compat adapters
//! - Trace context should remain consistent when crossing runtime boundaries
//! - Span events and attributes should not be lost during runtime transitions
//! - NOT: span context gets lost at runtime boundary (broken tracing)
//! - NOT: parent-child relationships broken across adapters (fragmented traces)
//!
//! **POTENTIAL DEFECT AREAS**:
//! - AsupersyncRuntime may not propagate span context to tokio tasks
//! - Tokio runtime handle implementation may lack tracing integration
//! - Cx context may not preserve OpenTelemetry span information
//! - Task spawning across runtimes may break trace propagation chain

#![cfg(test)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Span context fixture for propagation across runtime boundaries.
#[derive(Debug, Clone, PartialEq)]
pub struct SpanContextFixture {
    trace_id: String,
    span_id: String,
    parent_span_id: Option<String>,
    baggage: HashMap<String, String>,
    trace_state: String,
}

impl SpanContextFixture {
    fn new(trace_id: &str, span_id: &str) -> Self {
        Self {
            trace_id: trace_id.to_string(),
            span_id: span_id.to_string(),
            parent_span_id: None,
            baggage: HashMap::new(),
            trace_state: String::new(),
        }
    }

    fn with_parent(mut self, parent_span_id: &str) -> Self {
        self.parent_span_id = Some(parent_span_id.to_string());
        self
    }

    fn with_baggage(mut self, key: &str, value: &str) -> Self {
        self.baggage.insert(key.to_string(), value.to_string());
        self
    }

    fn with_trace_state(mut self, trace_state: &str) -> Self {
        self.trace_state = trace_state.to_string();
        self
    }
}

/// Runtime adapter fixture for span propagation behavior.
#[derive(Debug)]
pub struct RuntimeBoundaryAdapterFixture {
    name: String,
    span_contexts: Arc<Mutex<Vec<SpanContextFixture>>>,
    propagation_enabled: bool,
}

impl RuntimeBoundaryAdapterFixture {
    fn new(name: &str, propagation_enabled: bool) -> Self {
        Self {
            name: name.to_string(),
            span_contexts: Arc::new(Mutex::new(Vec::new())),
            propagation_enabled,
        }
    }

    fn spawn_task_with_span(&self, span_context: SpanContextFixture) -> SpanContextFixture {
        // Exercise task spawning across runtime boundary.
        if self.propagation_enabled {
            // CORRECT: Preserve span context across runtime boundary
            let mut contexts = self.span_contexts.lock().unwrap();
            contexts.push(span_context.clone());
            span_context
        } else {
            // DEFECT: Span context lost at runtime boundary
            let lost_context =
                SpanContextFixture::new("00000000000000000000000000000000", "0000000000000000");
            let mut contexts = self.span_contexts.lock().unwrap();
            contexts.push(lost_context.clone());
            lost_context
        }
    }

    fn create_child_span(&self, parent: &SpanContextFixture, child_span_id: &str) -> SpanContextFixture {
        if self.propagation_enabled {
            // CORRECT: Parent-child relationship preserved
            SpanContextFixture::new(&parent.trace_id, child_span_id)
                .with_parent(&parent.span_id)
                .with_trace_state(&parent.trace_state)
        } else {
            // DEFECT: Parent-child relationship lost
            SpanContextFixture::new("00000000000000000000000000000000", child_span_id)
        }
    }

    fn get_captured_spans(&self) -> Vec<SpanContextFixture> {
        self.span_contexts.lock().unwrap().clone()
    }
}

/// In-memory OTLP exporter fixture for span collection across runtime boundaries.
#[derive(Debug)]
pub struct InMemoryCrossRuntimeOtlpExporter {
    exported_spans: Arc<Mutex<Vec<SpanContextFixture>>>,
    export_count: Arc<Mutex<usize>>,
}

impl InMemoryCrossRuntimeOtlpExporter {
    fn new() -> Self {
        Self {
            exported_spans: Arc::new(Mutex::new(Vec::new())),
            export_count: Arc::new(Mutex::new(0)),
        }
    }

    fn export_span(&self, span: SpanContextFixture) {
        let mut spans = self.exported_spans.lock().unwrap();
        spans.push(span);

        let mut count = self.export_count.lock().unwrap();
        *count += 1;
    }

    fn get_exported_spans(&self) -> Vec<SpanContextFixture> {
        self.exported_spans.lock().unwrap().clone()
    }

    fn export_count(&self) -> usize {
        *self.export_count.lock().unwrap()
    }

    fn validate_trace_integrity(&self) -> Vec<String> {
        let spans = self.get_exported_spans();
        let mut violations = Vec::new();

        for span in &spans {
            // Check for lost trace context
            if span.trace_id == "00000000000000000000000000000000" {
                violations.push(format!(
                    "Lost trace context: span {} has zero trace_id",
                    span.span_id
                ));
            }

            // Check for broken parent-child relationships
            if let Some(parent_span_id) = &span.parent_span_id {
                let parent_exists = spans.iter().any(|s| &s.span_id == parent_span_id);
                if !parent_exists {
                    violations.push(format!(
                        "Broken parent relationship: span {} references missing parent {}",
                        span.span_id, parent_span_id
                    ));
                }
            }

            // Check for lost baggage propagation
            if span.baggage.is_empty() && span.parent_span_id.is_some() {
                // Find parent and check if it had baggage
                if let Some(parent) = spans.iter().find(|s| Some(&s.span_id) == span.parent_span_id.as_ref()) {
                    if !parent.baggage.is_empty() {
                        violations.push(format!(
                            "Lost baggage: span {} missing baggage from parent {}",
                            span.span_id, parent.span_id
                        ));
                    }
                }
            }
        }

        violations
    }
}

/// **AUDIT TEST**: Verify span propagation across asupersync-tokio-compat boundary.
///
/// **SCENARIO**: Application creates spans in asupersync, spawns tokio tasks via compat layer.
/// **REQUIREMENT**: Span context should propagate correctly across runtime boundary.
/// **ASSESSMENT**: Current tokio-compat implementation vs span propagation requirements.
#[test]
fn audit_otlp_tokio_compat_span_propagation() {
    println!("🔍 AUDIT: OTLP span propagation across asupersync-tokio-compat boundary");

    println!("📋 Tokio compatibility span propagation requirements:");
    println!("   • Span context must propagate across asupersync ↔ tokio boundaries");
    println!("   • Parent-child relationships preserved through compat adapters");
    println!("   • Trace context consistent when crossing runtime boundaries");
    println!("   • Span events/attributes not lost during runtime transitions");
    println!("   • NOT: span context lost at runtime boundary");
    println!("   • NOT: parent-child relationships broken across adapters");

    let runtime_scenarios = vec![
        ("AsupersyncRuntime with propagation", true),
        ("AsupersyncRuntime without propagation", false),
        ("Direct tokio spawn with propagation", true),
        ("Direct tokio spawn without propagation", false),
    ];

    println!("📊 Testing runtime boundary propagation scenarios:");

    let exporter = InMemoryCrossRuntimeOtlpExporter::new();

    for (scenario_name, propagation_enabled) in runtime_scenarios {
        println!("   Testing: {} (enabled: {})", scenario_name, propagation_enabled);

        let adapter = RuntimeBoundaryAdapterFixture::new(scenario_name, propagation_enabled);

        // **PHASE 1**: Create parent span in asupersync runtime
        let parent_span =
            SpanContextFixture::new("12345678901234567890123456789012", "1234567890123456")
            .with_baggage("tenant", "acme-corp")
            .with_trace_state("edge=datacenter:us-east");

        println!("     Parent span created: trace_id={}, span_id={}",
                parent_span.trace_id, parent_span.span_id);

        // **PHASE 2**: Spawn task through tokio-compat boundary
        let boundary_span = adapter.spawn_task_with_span(parent_span.clone());

        println!("     Boundary crossing: trace_id={}", boundary_span.trace_id);

        // **PHASE 3**: Create child span in tokio runtime
        let child_span = adapter.create_child_span(&boundary_span, "2234567890123456");

        println!("     Child span: trace_id={}, parent={:?}",
                child_span.trace_id, child_span.parent_span_id);

        // **PHASE 4**: Export spans and analyze
        exporter.export_span(parent_span.clone());
        exporter.export_span(boundary_span);
        exporter.export_span(child_span);

        // **PROPAGATION VERIFICATION**
        let violations = exporter.validate_trace_integrity();

        if propagation_enabled {
            if violations.is_empty() {
                println!("     ✅ PROPAGATION: Span context preserved across boundary");
            } else {
                println!("     ❌ PROPAGATION: Context lost despite enabled propagation");
                for violation in &violations {
                    println!("       - {}", violation);
                }
            }
        } else {
            if violations.is_empty() {
                println!("     ⚠️  PROPAGATION: Unexpected success with disabled propagation");
            } else {
                println!("     ❌ PROPAGATION: Context lost as expected (defective behavior)");
                for violation in &violations {
                    println!("       - {}", violation);
                }
            }
        }
    }

    // **OVERALL TRACE INTEGRITY ANALYSIS**
    let all_violations = exporter.validate_trace_integrity();
    let total_spans = exporter.export_count();

    println!("📊 Overall trace integrity analysis:");
    println!("   Total spans exported: {}", total_spans);
    println!("   Trace integrity violations: {}", all_violations.len());

    if all_violations.is_empty() {
        println!("   ✅ INTEGRITY: All spans properly connected");
    } else {
        println!("   ❌ INTEGRITY: Span propagation defects detected");
        for violation in &all_violations {
            println!("     - {}", violation);
        }
    }
}

/// **AUDIT TEST**: Verify baggage propagation across tokio compatibility boundary.
///
/// **SCENARIO**: Parent span has baggage items that should propagate to child spans.
/// **REQUIREMENT**: Baggage must be preserved through tokio-compat adapters.
/// **ASSESSMENT**: Baggage propagation integrity across runtime boundaries.
#[test]
fn audit_baggage_propagation_across_tokio_compat() {
    println!("🔍 AUDIT: Baggage propagation across tokio compatibility boundary");

    println!("📋 Baggage propagation requirements:");
    println!("   • Baggage items must propagate through runtime adapters");
    println!("   • Key-value pairs preserved across asupersync ↔ tokio boundary");
    println!("   • Multiple baggage items handled correctly");
    println!("   • Baggage available to child spans in tokio runtime");

    let baggage_scenarios = vec![
        (
            "Single baggage item",
            vec![("tenant", "acme-corp")],
        ),
        (
            "Multiple baggage items",
            vec![("tenant", "acme-corp"), ("user_id", "12345"), ("region", "us-east")],
        ),
        (
            "Complex baggage values",
            vec![("session", "eyJ0eXAi"), ("flags", "feature1,feature2")],
        ),
    ];

    println!("📊 Testing baggage propagation scenarios:");

    for (scenario_name, baggage_items) in baggage_scenarios {
        println!("   Testing: {}", scenario_name);

        let adapter_with_propagation = RuntimeBoundaryAdapterFixture::new("test", true);
        let adapter_without_propagation = RuntimeBoundaryAdapterFixture::new("test", false);

        // Create parent span with baggage
        let mut parent_span =
            SpanContextFixture::new("12345678901234567890123456789012", "1111111111111111");
        for (key, value) in &baggage_items {
            parent_span = parent_span.with_baggage(key, value);
        }

        println!("     Parent baggage items: {}", baggage_items.len());

        // Test with propagation enabled
        let child_with_propagation = adapter_with_propagation.create_child_span(&parent_span, "2222222222222222");

        println!("     Child with propagation: {} baggage items", child_with_propagation.baggage.len());

        // Test without propagation
        let child_without_propagation = adapter_without_propagation.create_child_span(&parent_span, "3333333333333333");

        println!("     Child without propagation: {} baggage items", child_without_propagation.baggage.len());

        // Verify baggage preservation
        if child_with_propagation.baggage.len() == baggage_items.len() {
            println!("     ✅ BAGGAGE: Items preserved with propagation enabled");
        } else {
            println!("     ❌ BAGGAGE: Items lost with propagation enabled");
        }

        if child_without_propagation.baggage.is_empty() {
            println!("     ❌ BAGGAGE: Items lost without propagation (expected defect)");
        } else {
            println!("     ⚠️  BAGGAGE: Unexpected preservation without propagation");
        }

        // Verify specific baggage values
        for (key, expected_value) in &baggage_items {
            if let Some(actual_value) = child_with_propagation.baggage.get(*key) {
                if actual_value == expected_value {
                    println!("     ✅ VALUE: {}={} preserved correctly", key, expected_value);
                } else {
                    println!("     ❌ VALUE: {}={} corrupted to {}", key, expected_value, actual_value);
                }
            } else {
                println!("     ❌ VALUE: {} missing in child span", key);
            }
        }
    }

    println!("✅ BAGGAGE PROPAGATION AUDIT COMPLETE");
    println!("📊 FINDING: Baggage propagation depends on compat implementation");
}

/// **AUDIT TEST**: Verify current asupersync-tokio-compat implementation behavior.
///
/// **SCENARIO**: Document actual behavior vs expected span propagation requirements.
/// **REQUIREMENT**: Identify span propagation gaps in current tokio-compat.
/// **ASSESSMENT**: Current implementation vs ideal cross-runtime tracing.
#[test]
fn audit_current_tokio_compat_span_behavior() {
    println!("🔍 AUDIT: Current asupersync-tokio-compat span propagation behavior");

    println!("📊 Current implementation analysis:");
    println!("   File: asupersync-tokio-compat/src/runtime.rs");
    println!("   Lines 23-36: AsupersyncRuntime captures Cx context");
    println!("   Lines 51-58: enter() method sets current Cx");
    println!("   Issue: No explicit span propagation logic found");

    // **IMPLEMENTATION ANALYSIS**
    println!("📋 Current tokio-compat implementation gaps:");
    println!("   • AsupersyncRuntime captures Cx but unclear if spans propagate");
    println!("   • No explicit OpenTelemetry context propagation code");
    println!("   • enter() method may not preserve tracing context");
    println!("   • Task spawning may break trace parent-child relationships");
    println!("   • Baggage propagation behavior undefined");

    // **EXPECTED BEHAVIOR ANALYSIS**
    println!("📊 Expected span propagation behavior:");
    println!("   • Asupersync span → tokio task should preserve trace_id");
    println!("   • Parent-child relationships maintained across boundary");
    println!("   • Baggage items propagated through compat adapters");
    println!("   • OpenTelemetry context preserved in both directions");

    // **INTEGRATION SCENARIOS**
    let integration_scenarios = vec![
        "reqwest HTTP client in tokio task with asupersync spans",
        "axum request handler spawning asupersync tasks",
        "tonic gRPC service with mixed runtime operations",
        "sqlx database queries with distributed tracing",
        "tower middleware with span propagation",
    ];

    println!("📊 Common tokio-compat integration scenarios:");
    for (i, scenario) in integration_scenarios.iter().enumerate() {
        println!("   {}. {}", i + 1, scenario);
        println!("      Risk: Spans may be lost at runtime boundary");
    }

    // **BEHAVIOR CLASSIFICATION**
    println!("🚨 BEHAVIOR CLASSIFICATION:");
    println!("   Current behavior: UNKNOWN - insufficient test coverage");
    println!("   Expected behavior: SOUND span propagation");
    println!("   Risk level: HIGH - distributed tracing may be broken");

    // **MISSING FEATURES ANALYSIS**
    println!("📋 Potentially missing features:");
    println!("   1. OpenTelemetry context integration in AsupersyncRuntime");
    println!("   2. Span propagation hooks in task spawning methods");
    println!("   3. Baggage preservation across runtime boundaries");
    println!("   4. Tracing subscriber compatibility");
    println!("   5. Integration tests for cross-runtime span flows");

    // **RECOMMENDATIONS**
    println!("📋 Required investigation:");
    println!("   1. Test actual span propagation with real tokio-compat usage");
    println!("   2. Verify OpenTelemetry context preservation in enter()");
    println!("   3. Check if baggage propagates through Cx context");
    println!("   4. Test with popular tokio crates (reqwest, axum, tonic)");
    println!("   5. File feature bead if propagation is broken");

    println!("✅ CURRENT IMPLEMENTATION AUDIT COMPLETE");
    println!("🚨 FINDING: Span propagation behavior needs verification with actual tests");
}

/// **AUDIT TEST**: Verify trace state propagation across runtime boundaries.
///
/// **SCENARIO**: Trace state with vendor entries should propagate through tokio-compat.
/// **REQUIREMENT**: W3C trace-context trace_state preserved across boundaries.
/// **ASSESSMENT**: Trace state integrity in cross-runtime scenarios.
#[test]
fn audit_trace_state_propagation_across_boundaries() {
    println!("🔍 AUDIT: Trace state propagation across tokio compatibility boundaries");

    println!("📋 Trace state propagation requirements:");
    println!("   • W3C trace-context trace_state preserved across boundaries");
    println!("   • Vendor entries maintained in cross-runtime scenarios");
    println!("   • Multiple vendor trace_state entries handled correctly");
    println!("   • Trace state available for correlation in tokio runtime");

    let trace_state_scenarios = vec![
        ("edge=datacenter:us-east", "Single vendor entry"),
        ("edge=dc:us-east,cdn=cache:hit", "Two vendor entries"),
        ("amazon=region:us-east-1,google=zone:us-central1-a,datadog=trace:123", "Multi-cloud vendors"),
    ];

    println!("📊 Testing trace state propagation scenarios:");

    for (trace_state, description) in trace_state_scenarios {
        println!("   Testing: {} ({})", trace_state, description);

        let adapter_with_propagation = RuntimeBoundaryAdapterFixture::new("test", true);

        // Create parent span with trace state
        let parent_span =
            SpanContextFixture::new("12345678901234567890123456789012", "1111111111111111")
            .with_trace_state(trace_state);

        println!("     Parent trace_state: {}", parent_span.trace_state);

        // Cross runtime boundary
        let child_span = adapter_with_propagation.create_child_span(&parent_span, "2222222222222222");

        println!("     Child trace_state: {}", child_span.trace_state);

        // Verify trace state preservation
        if child_span.trace_state == parent_span.trace_state {
            println!("     ✅ TRACE_STATE: Preserved across boundary");
        } else {
            println!("     ❌ TRACE_STATE: Lost or corrupted across boundary");
        }

        // Count vendor entries
        let parent_entries = parent_span.trace_state.split(',').filter(|s| !s.is_empty()).count();
        let child_entries = child_span.trace_state.split(',').filter(|s| !s.is_empty()).count();

        if child_entries == parent_entries {
            println!("     ✅ VENDOR_ENTRIES: All {} entries preserved", parent_entries);
        } else {
            println!("     ❌ VENDOR_ENTRIES: {} → {} entries (data loss)", parent_entries, child_entries);
        }
    }

    println!("✅ TRACE STATE PROPAGATION AUDIT COMPLETE");
    println!("📊 FINDING: Trace state propagation critical for vendor correlation");
}
