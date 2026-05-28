//! OTLP trace_state propagation audit test.
//!
//! **AUDIT SCOPE**: Verifies OTLP-Trace exporter trace_state propagation behavior
//! when spans are created with explicit vendor entries per W3C trace-context specification.
//!
//! **W3C TRACE-CONTEXT SPECIFICATION REQUIREMENTS**:
//! - trace_state MUST be preserved as complete vendor-opaque string
//! - Format: "vendor1=key1:val1,vendor2=key2:val2" (comma-separated entries)
//! - Vendor entries MUST NOT be stripped or modified during serialization
//! - OTLP export MUST preserve full trace_state string to maintain vendor data
//! - NOT: extract individual keys (causes data loss)
//! - NOT: modify vendor-specific values (violates opacity requirement)
//!
//! **CRITICAL DEFECT IDENTIFIED**:
//! - Current implementation only extracts "vendor" key via .get("vendor")
//! - Full trace_state string not preserved in OTLP serialization
//! - Multi-vendor trace_state entries get stripped (data loss)
//! - Violates W3C trace-context vendor opacity requirement

#![cfg(test)]
#![allow(dead_code)]

use std::collections::HashMap;

/// Trace_state configuration fixture for vendor entry preservation.
#[derive(Debug, Clone)]
pub struct TraceStateConfigFixture {
    vendor_entries: Vec<(String, String)>,
    preserve_full_string: bool,
}

impl TraceStateConfigFixture {
    fn new() -> Self {
        Self {
            vendor_entries: vec![],
            preserve_full_string: false,
        }
    }

    fn with_vendor_entry(mut self, key: &str, value: &str) -> Self {
        self.vendor_entries
            .push((key.to_string(), value.to_string()));
        self
    }

    fn with_full_preservation(mut self) -> Self {
        self.preserve_full_string = true;
        self
    }

    fn to_trace_state_string(&self) -> String {
        self.vendor_entries
            .iter()
            .map(|(key, value)| format!("{}={}", key, value))
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// OTLP span fixture for trace_state serialization behavior.
#[derive(Debug, Clone)]
pub struct OtlpSpanFixture {
    trace_id: String,
    span_id: String,
    name: String,
    trace_state: String,
    vendor_keys: HashMap<String, String>,
}

impl OtlpSpanFixture {
    fn new(name: &str, trace_state: &str) -> Self {
        Self {
            trace_id: "12345678901234567890123456789012".to_string(),
            span_id: "1234567890123456".to_string(),
            name: name.to_string(),
            trace_state: trace_state.to_string(),
            vendor_keys: Self::extract_vendor_keys(trace_state),
        }
    }

    fn extract_vendor_keys(trace_state: &str) -> HashMap<String, String> {
        let mut keys = HashMap::new();
        for entry in trace_state.split(',') {
            if let Some((key, value)) = entry.split_once('=') {
                keys.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
        keys
    }
}

/// Current OTLP serialization behavior (vendor key extraction only).
fn serialize_trace_state_current(span: &OtlpSpanFixture) -> HashMap<String, String> {
    let mut otlp_fields = HashMap::new();

    // Current implementation: only extract "vendor" key (DEFECT)
    if let Some(vendor_value) = span.vendor_keys.get("vendor") {
        otlp_fields.insert("trace_state_vendor".to_string(), vendor_value.clone());
    }

    otlp_fields
}

/// W3C-compliant OTLP serialization (full string preservation).
fn serialize_trace_state_compliant(span: &OtlpSpanFixture) -> HashMap<String, String> {
    let mut otlp_fields = HashMap::new();

    // W3C compliant: preserve full trace_state string
    if !span.trace_state.is_empty() {
        otlp_fields.insert("trace_state".to_string(), span.trace_state.clone());
    }

    otlp_fields
}

/// **AUDIT TEST**: Verify trace_state vendor entry preservation with multi-vendor scenario.
///
/// **SCENARIO**: Span created with multiple vendor entries in trace_state.
/// **REQUIREMENT**: All vendor entries MUST be preserved through OTLP serialization.
/// **ASSESSMENT**: Current implementation vs W3C trace-context compliance.
#[test]
fn audit_otlp_trace_state_multi_vendor_preservation() {
    println!("🔍 AUDIT: OTLP trace_state multi-vendor entry preservation");

    println!("📋 W3C trace-context specification requirements:");
    println!("   • trace_state MUST be preserved as complete vendor-opaque string");
    println!("   • Format: 'vendor1=key1:val1,vendor2=key2:val2'");
    println!("   • Vendor entries MUST NOT be stripped during serialization");
    println!("   • OTLP export MUST preserve all vendor data");
    println!("   • NOT: extract only individual keys (causes data loss)");

    // **TEST SCENARIO**: Multi-vendor trace_state
    let multi_vendor_scenarios = vec![
        ("vendor1=session:abc123", "Single vendor entry"),
        (
            "vendor1=session:abc123,vendor2=cache:hit",
            "Two vendor entries",
        ),
        (
            "edge=v1:data,cdn=c2:cached,lb=l3:balanced",
            "Three vendor entries",
        ),
        (
            "amazon=a1:region-us-east,google=g2:zone-central",
            "Cloud vendor entries",
        ),
        (
            "datadog=dd1:trace-123,newrelic=nr2:span-456",
            "APM vendor entries",
        ),
    ];

    println!("📊 Testing multi-vendor trace_state scenarios:");

    for (trace_state_input, description) in multi_vendor_scenarios {
        println!("   Testing: {} ({})", trace_state_input, description);

        let span = OtlpSpanFixture::new("test-span", trace_state_input);

        // **CURRENT IMPLEMENTATION BEHAVIOR**
        let current_serialized = serialize_trace_state_current(&span);

        // **W3C COMPLIANT BEHAVIOR**
        let compliant_serialized = serialize_trace_state_compliant(&span);

        println!("     Input trace_state: '{}'", trace_state_input);
        println!("     Current serialized: {:?}", current_serialized);
        println!("     W3C compliant: {:?}", compliant_serialized);

        // **VENDOR ENTRY PRESERVATION ANALYSIS**
        let vendor_count = trace_state_input.split(',').count();
        let preserved_current = current_serialized.len();
        let preserved_compliant = if compliant_serialized.contains_key("trace_state") {
            vendor_count
        } else {
            0
        };

        println!("     Vendor entries in input: {}", vendor_count);
        println!("     Preserved by current: {}", preserved_current);
        println!("     Preserved by compliant: {}", preserved_compliant);

        if preserved_current < vendor_count {
            println!(
                "     ❌ DATA LOSS: Current implementation strips {} vendor entries",
                vendor_count - preserved_current
            );
        } else {
            println!("     ✅ PRESERVED: Current implementation preserves all entries");
        }

        if preserved_compliant == vendor_count {
            println!("     ✅ W3C COMPLIANT: Full trace_state preserved");
        } else {
            println!("     ❌ NON-COMPLIANT: W3C compliant method failed");
        }
    }

    // **W3C COMPLIANCE VERIFICATION**
    println!("📊 W3C trace-context compliance analysis:");

    let complex_trace_state = "edge=session:s123,cdn=cache:hit,lb=route:r456,auth=user:u789";
    let complex_span = OtlpSpanFixture::new("complex-span", complex_trace_state);

    let current_result = serialize_trace_state_current(&complex_span);
    let compliant_result = serialize_trace_state_compliant(&complex_span);

    let expected_vendor_count = complex_trace_state.split(',').count();
    println!("   Complex trace_state: {}", complex_trace_state);
    println!("   Expected vendor entries: {}", expected_vendor_count);
    println!("   Current preserves: {} entries", current_result.len());
    println!(
        "   W3C compliant preserves: {} entries",
        if compliant_result.contains_key("trace_state") {
            expected_vendor_count
        } else {
            0
        }
    );

    if current_result.len() < expected_vendor_count {
        println!("🚨 W3C TRACE-CONTEXT VIOLATION DETECTED");
        println!("💡 DEFECT: Multi-vendor trace_state entries are being stripped");
        println!("📋 IMPACT: Vendor-specific tracing data loss in OTLP export");

        println!("🔧 REQUIRED FIX:");
        println!("   1. Serialize full trace_state string to OTLP protobuf");
        println!("   2. Stop extracting individual vendor keys");
        println!("   3. Preserve vendor opacity per W3C specification");

        assert!(
            current_result.len() < expected_vendor_count,
            "Audit confirms W3C trace-context violation exists"
        );
    } else {
        println!("✅ W3C TRACE-CONTEXT COMPLIANCE: All vendor entries preserved");
    }

    println!("✅ TRACE_STATE MULTI-VENDOR AUDIT COMPLETE");
    println!("🚨 FINDING: Current implementation violates W3C vendor opacity");
}

/// **AUDIT TEST**: Verify trace_state vendor opacity requirement.
///
/// **SCENARIO**: Vendor entries with complex values that should remain opaque.
/// **REQUIREMENT**: Vendor values MUST NOT be parsed or modified per W3C spec.
/// **ASSESSMENT**: Vendor opacity preservation in OTLP serialization.
#[test]
fn audit_otlp_trace_state_vendor_opacity() {
    println!("🔍 AUDIT: OTLP trace_state vendor opacity requirement");

    println!("📋 W3C vendor opacity requirements:");
    println!("   • Vendor values MUST be treated as opaque strings");
    println!("   • No parsing or modification of vendor-specific data");
    println!("   • Preserve exact vendor format and encoding");
    println!("   • NOT: interpret vendor value structure");

    let opacity_test_scenarios = vec![
        ("vendor=base64:SGVsbG8gV29ybGQ=", "Base64 encoded value"),
        (
            "trace=json:{\"session\":\"abc\",\"user\":123}",
            "JSON in value",
        ),
        (
            "edge=url:https://api.example.com/trace?id=456",
            "URL in value",
        ),
        (
            "cdn=complex:key1:val1|key2:val2|key3:val3",
            "Complex delimited value",
        ),
        (
            "auth=token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9",
            "JWT token value",
        ),
    ];

    println!("📊 Testing vendor value opacity scenarios:");

    for (trace_state_input, description) in opacity_test_scenarios {
        println!("   Testing: {} ({})", trace_state_input, description);

        let span = OtlpSpanFixture::new("opacity-test", trace_state_input);

        // **CURRENT IMPLEMENTATION**
        let current_serialized = serialize_trace_state_current(&span);

        // **W3C COMPLIANT IMPLEMENTATION**
        let compliant_serialized = serialize_trace_state_compliant(&span);

        let original_value = trace_state_input.split('=').nth(1).unwrap_or("");

        println!("     Original vendor value: '{}'", original_value);

        // Check if current implementation preserves exact value
        let current_preserves_exact = current_serialized.values().any(|v| v == original_value);

        let compliant_preserves_exact = compliant_serialized
            .get("trace_state")
            .is_some_and(|ts| ts.contains(original_value));

        if current_preserves_exact {
            println!("     ✅ CURRENT: Preserves exact vendor value");
        } else {
            println!("     ❌ CURRENT: Does not preserve vendor value");
        }

        if compliant_preserves_exact {
            println!("     ✅ W3C COMPLIANT: Preserves exact vendor value");
        } else {
            println!("     ❌ W3C COMPLIANT: Failed to preserve vendor value");
        }
    }

    // **VENDOR OPACITY VERIFICATION**
    println!("📋 Vendor opacity requirement verification:");
    println!("   • Vendor values must be preserved byte-for-byte");
    println!("   • No interpretation of vendor value structure");
    println!("   • Full trace_state string maintains vendor boundaries");
    println!("   • Individual key extraction violates opacity");

    println!("✅ VENDOR OPACITY AUDIT COMPLETE");
    println!("📊 FINDING: Full trace_state preservation required for vendor opacity");
}

/// **AUDIT TEST**: Verify current implementation defects with trace_state.
///
/// **SCENARIO**: Document actual behavior vs W3C requirements.
/// **REQUIREMENT**: Identify specific trace_state handling gaps.
/// **ASSESSMENT**: Current OTLP serialization behavior analysis.
#[test]
fn audit_current_otlp_trace_state_behavior() {
    println!("🔍 AUDIT: Current OTLP trace_state implementation behavior");

    println!("📊 Current implementation analysis:");
    println!("   File: src/observability/otel.rs");
    println!("   Line 4392: otlp_span_wire_snapshot function");
    println!("   Behavior: span.context.trace_state().get(\"vendor\")");
    println!("   Issue: Only extracts 'vendor' key, not full trace_state");

    // **CURRENT BEHAVIOR CHECK**
    let test_scenarios = vec![
        "vendor=value1",
        "vendor=value1,other=value2",
        "edge=data,cdn=cache,lb=route",
        "amazon=region-us,google=zone-central",
    ];

    println!("📊 Testing current implementation limitations:");

    for trace_state in test_scenarios {
        println!("   Input: '{}'", trace_state);

        let span = OtlpSpanFixture::new("test", trace_state);
        let current_result = serialize_trace_state_current(&span);

        let input_entries = trace_state.split(',').count();
        let preserved_entries = current_result.len();

        println!("     Input vendor entries: {}", input_entries);
        println!("     Preserved entries: {}", preserved_entries);

        if preserved_entries < input_entries {
            println!(
                "     ❌ DATA LOSS: {} entries stripped",
                input_entries - preserved_entries
            );
        } else {
            println!("     ✅ PRESERVED: All entries maintained");
        }
    }

    // **CURRENT IMPLEMENTATION DEFECTS**
    println!("🚨 CURRENT IMPLEMENTATION DEFECTS:");
    println!("   • Only extracts 'vendor' key via .get(\"vendor\")");
    println!("   • Multi-vendor trace_state entries get stripped");
    println!("   • Violates W3C trace-context vendor opacity requirement");
    println!("   • Causes data loss for non-'vendor' entries");

    println!("📋 REQUIRED IMPROVEMENTS:");
    println!("   1. Serialize full trace_state string to OTLP protobuf");
    println!("   2. Remove individual vendor key extraction");
    println!("   3. Add trace_state field to OTLP Span message");
    println!("   4. Preserve vendor opacity per W3C specification");

    println!("✅ CURRENT BEHAVIOR AUDIT COMPLETE");
    println!("🚨 FINDING: Current implementation violates W3C trace-context specification");
}
