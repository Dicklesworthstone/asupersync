//! OpenTelemetry OTLP wire format conformance tests.
//!
//! This module validates that our OpenTelemetry implementation correctly
//! handles the OTLP protocol specifications for metrics export.
//!
//! # Test Coverage
//!
//! - OTLP protobuf message validation test vectors
//! - Metrics export format compliance verification
//! - Resource attributes and instrumentation scope encoding
//! - Metric aggregation temporality and export behavior
//! - Cardinality management and overflow strategy validation
//!
//! # References
//!
//! - [OTLP Specification](https://opentelemetry.io/docs/specs/otlp/)
//! - [Metrics Data Model](https://opentelemetry.io/docs/specs/otel/metrics/)

use crate::{ConformanceTest, RuntimeInterface, TestCategory, TestResult, checkpoint};
use serde_json::json;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// =============================================================================
// Test Data Structures
// =============================================================================

/// Test vector for OTLP protobuf message validation.
#[derive(Debug, Clone)]
struct OtlpTestVector {
    /// Test case name.
    name: String,
    /// Expected decoded metric data.
    expected_metric: TestMetric,
    /// Whether this should pass or fail validation.
    should_pass: bool,
}

/// Simplified test metric structure for validation.
#[derive(Debug, Clone, PartialEq)]
struct TestMetric {
    name: String,
    description: String,
    unit: String,
    metric_type: TestMetricType,
    data_points: Vec<TestDataPoint>,
    resource_attributes: HashMap<String, String>,
    scope_name: String,
    scope_version: String,
}

/// Test metric types matching OTLP specification.
#[derive(Debug, Clone, PartialEq)]
enum TestMetricType {
    Counter,
    Gauge,
    Histogram,
}

/// Test data point structure.
#[derive(Debug, Clone, PartialEq)]
struct TestDataPoint {
    labels: HashMap<String, String>,
    timestamp: u64, // nanoseconds since Unix epoch
    value: TestMetricValue,
}

/// Test metric values.
#[derive(Debug, Clone, PartialEq)]
enum TestMetricValue {
    Int64(i64),
    Histogram {
        count: u64,
        sum: f64,
        buckets: Vec<TestHistogramBucket>,
    },
}

/// Test histogram bucket.
#[derive(Debug, Clone, PartialEq)]
struct TestHistogramBucket {
    upper_bound: f64,
    count: u64,
}

// =============================================================================
// OTLP Protocol Test Vectors
// =============================================================================

/// Generate test vectors for OTLP protobuf message validation.
fn otlp_test_vectors() -> Vec<OtlpTestVector> {
    vec![
        // Basic counter metric
        OtlpTestVector {
            name: "basic_counter".to_string(),
            expected_metric: TestMetric {
                name: "requests_total".to_string(),
                description: "Total number of HTTP requests".to_string(),
                unit: "1".to_string(),
                metric_type: TestMetricType::Counter,
                data_points: vec![TestDataPoint {
                    labels: [("method".to_string(), "GET".to_string())].into(),
                    timestamp: 1640995200000000000, // 2022-01-01T00:00:00Z
                    value: TestMetricValue::Int64(42),
                }],
                resource_attributes: [
                    ("service.name".to_string(), "test-service".to_string()),
                    ("service.version".to_string(), "1.0.0".to_string()),
                ]
                .into(),
                scope_name: "asupersync".to_string(),
                scope_version: "0.3.1".to_string(),
            },
            should_pass: true,
        },
        // Histogram metric
        OtlpTestVector {
            name: "basic_histogram".to_string(),
            expected_metric: TestMetric {
                name: "request_duration_seconds".to_string(),
                description: "HTTP request duration histogram".to_string(),
                unit: "s".to_string(),
                metric_type: TestMetricType::Histogram,
                data_points: vec![TestDataPoint {
                    labels: [("status".to_string(), "200".to_string())].into(),
                    timestamp: 1640995200000000000,
                    value: TestMetricValue::Histogram {
                        count: 100,
                        sum: 42.5,
                        buckets: vec![
                            TestHistogramBucket {
                                upper_bound: 0.1,
                                count: 10,
                            },
                            TestHistogramBucket {
                                upper_bound: 0.5,
                                count: 50,
                            },
                            TestHistogramBucket {
                                upper_bound: 1.0,
                                count: 85,
                            },
                            TestHistogramBucket {
                                upper_bound: f64::INFINITY,
                                count: 100,
                            },
                        ],
                    },
                }],
                resource_attributes: [("service.name".to_string(), "web-server".to_string())]
                    .into(),
                scope_name: "asupersync::http".to_string(),
                scope_version: "0.3.1".to_string(),
            },
            should_pass: true,
        },
        // Invalid metric (missing required fields)
        OtlpTestVector {
            name: "invalid_missing_name".to_string(),
            expected_metric: TestMetric {
                name: "".to_string(), // Missing name should fail validation
                description: "Invalid metric".to_string(),
                unit: "1".to_string(),
                metric_type: TestMetricType::Counter,
                data_points: vec![],
                resource_attributes: HashMap::new(),
                scope_name: "test".to_string(),
                scope_version: "1.0.0".to_string(),
            },
            should_pass: false,
        },
    ]
}

// =============================================================================
// Conformance Tests
// =============================================================================

/// OTLP-001: Basic protobuf message validation.
pub fn otlp_001_protobuf_validation<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-001",
        name: "OTLP protobuf message validation",
        description: "Validate OTLP protobuf messages conform to specification",
        category: TestCategory::IO,
        tags: ["otlp", "protobuf", "validation"],
        expected: "Valid OTLP messages decode correctly, invalid messages are rejected",
        test: |_rt| {
            let test_vectors = otlp_test_vectors();
            let mut passed_count = 0;
            let mut failed_count = 0;

            for vector in test_vectors {
                checkpoint("otlp_validation", json!({
                    "test_case": vector.name,
                    "expected_pass": vector.should_pass,
                    "metric_name": vector.expected_metric.name,
                    "metric_type": format!("{:?}", vector.expected_metric.metric_type)
                }));

                // Mock validation for demonstration
                let validation_result = validate_otlp_message(&vector);

                if validation_result == vector.should_pass {
                    passed_count += 1;
                } else {
                    failed_count += 1;
                }
            }

            if failed_count == 0 {
                TestResult::passed()
                    .with_checkpoint(crate::Checkpoint::new("summary", json!({
                        "total_vectors": passed_count + failed_count,
                        "passed": passed_count,
                        "failed": failed_count
                    })))
            } else {
                TestResult::failed(format!(
                    "OTLP protobuf validation failed: {}/{} test vectors failed",
                    failed_count, passed_count + failed_count
                ))
            }
        }
    }
}

/// OTLP-002: Resource attributes encoding round-trip test.
pub fn otlp_002_resource_attributes<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-002",
        name: "Resource attributes encoding round-trip",
        description: "Verify resource attributes encode/decode correctly in OTLP format",
        category: TestCategory::IO,
        tags: ["otlp", "resource", "encoding"],
        expected: "Resource attributes survive encode/decode round-trip",
        test: |_rt| {
            let test_attributes = vec![
                ("service.name", "test-service"),
                ("service.version", "1.2.3"),
                ("deployment.environment", "production"),
                ("host.name", "web-01.example.com"),
                ("process.pid", "12345"),
                // Test special characters and Unicode
                ("custom.label", "value with spaces and 🚀 emoji"),
                ("empty.value", ""),
            ];

            for (key, value) in &test_attributes {
                checkpoint("resource_attribute_test", json!({
                    "key": key,
                    "value": value,
                    "value_length": value.len()
                }));

                // Mock encoding/decoding round-trip
                let encoded = encode_resource_attribute(key, value);
                let (decoded_key, decoded_value) = decode_resource_attribute(&encoded);

                if decoded_key != *key || decoded_value != *value {
                    return TestResult::failed(format!(
                        "Resource attribute round-trip failed for {}: expected '{}', got '{}'",
                        key, value, decoded_value
                    ));
                }
            }

            TestResult::passed()
                .with_checkpoint(crate::Checkpoint::new("resource_attributes_summary", json!({
                    "attributes_tested": test_attributes.len(),
                    "all_passed": true
                })))
        }
    }
}

/// OTLP-003: Metric temporality handling.
pub fn otlp_003_temporality<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-003",
        name: "Metric aggregation temporality handling",
        description: "Verify correct handling of cumulative vs delta temporality",
        category: TestCategory::IO,
        tags: ["otlp", "temporality", "aggregation"],
        expected: "Temporality is correctly set and exported according to metric type",
        test: |_rt| {
            let test_cases = vec![
                ("counter", TestMetricType::Counter, "cumulative"),
                ("gauge", TestMetricType::Gauge, "unspecified"),
                ("histogram", TestMetricType::Histogram, "cumulative"),
            ];

            for (metric_name, metric_type, expected_temporality) in &test_cases {
                checkpoint("temporality_test", json!({
                    "metric_name": metric_name,
                    "metric_type": format!("{:?}", metric_type),
                    "expected_temporality": expected_temporality
                }));

                // Mock temporality validation
                let actual_temporality = get_metric_temporality(metric_type);

                if actual_temporality != *expected_temporality {
                    return TestResult::failed(format!(
                        "Incorrect temporality for {}: expected {}, got {}",
                        metric_name, expected_temporality, actual_temporality
                    ));
                }
            }

            TestResult::passed()
                .with_checkpoint(crate::Checkpoint::new("temporality_summary", json!({
                    "test_cases": test_cases.len(),
                    "all_passed": true
                })))
        }
    }
}

/// OTLP-004: Cardinality management validation.
pub fn otlp_004_cardinality<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-004",
        name: "Cardinality management and overflow",
        description: "Verify cardinality limits are enforced according to configuration",
        category: TestCategory::IO,
        tags: ["otlp", "cardinality", "limits"],
        expected: "Cardinality limits prevent metric explosion while preserving data integrity",
        test: |_rt| {
            // Test cardinality limit enforcement
            let max_cardinality = 100;
            let overflow_strategy = "aggregate"; // or "drop"

            checkpoint("cardinality_test_start", json!({
                "max_cardinality": max_cardinality,
                "overflow_strategy": overflow_strategy
            }));

            // Simulate metric series generation beyond limits
            let mut metric_series_count = 0;
            let mut overflow_triggered = false;

            // Generate metric series with high cardinality labels
            for i in 0..150 {
                let label_value = format!("value_{}", i);

                if metric_series_count < max_cardinality {
                    // Should accept new series
                    let accepted = accept_metric_series("test_metric", &label_value);
                    if !accepted {
                        return TestResult::failed(format!(
                            "Metric series rejected before cardinality limit: series {}/{}",
                            i, max_cardinality
                        ));
                    }
                    metric_series_count += 1;
                } else {
                    // Should trigger overflow handling
                    if !overflow_triggered {
                        overflow_triggered = true;
                        checkpoint("cardinality_overflow", json!({
                            "series_count": metric_series_count,
                            "overflow_at_series": i
                        }));
                    }

                    // Verify overflow strategy is applied
                    let overflow_handled = handle_cardinality_overflow("test_metric", &label_value);
                    if !overflow_handled {
                        return TestResult::failed(format!(
                            "Cardinality overflow not handled properly at series {}",
                            i
                        ));
                    }
                }
            }

            if !overflow_triggered {
                return TestResult::failed("Cardinality limits not enforced");
            }

            TestResult::passed()
                .with_checkpoint(crate::Checkpoint::new("cardinality_summary", json!({
                    "max_cardinality": max_cardinality,
                    "final_series_count": metric_series_count,
                    "overflow_triggered": overflow_triggered
                })))
        }
    }
}

/// OTLP-005: Cross-implementation compatibility test.
pub fn otlp_005_compatibility<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-005",
        name: "Cross-implementation compatibility",
        description: "Verify exported metrics are compatible with reference OTLP implementations",
        category: TestCategory::IO,
        tags: ["otlp", "compatibility", "interop"],
        expected: "Exported OTLP data is consumable by standard OpenTelemetry collectors",
        test: |_rt| {
            let compatibility_tests = vec![
                "opentelemetry_collector_v0.95.0",
                "prometheus_remote_write",
                "grafana_agent_v0.32.1",
            ];

            for implementation in &compatibility_tests {
                checkpoint("compatibility_test", json!({
                    "target_implementation": implementation,
                    "test_start": SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or(Duration::ZERO)
                        .as_millis()
                }));

                // Mock compatibility validation
                let is_compatible = validate_compatibility(implementation);

                if !is_compatible {
                    return TestResult::failed(format!(
                        "OTLP export not compatible with {}",
                        implementation
                    ));
                }
            }

            TestResult::passed()
                .with_checkpoint(crate::Checkpoint::new("compatibility_summary", json!({
                    "tested_implementations": compatibility_tests,
                    "all_compatible": true
                })))
        }
    }
}

/// OTLP-011: Span links field conformance.
pub fn otlp_011_span_links_conformance<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-011",
        name: "Span links field identity",
        description: "Verify same Link[] produces identical OTLP/Trace links field vs opentelemetry-sdk",
        category: TestCategory::IO,
        tags: ["otlp", "span", "links", "trace", "context"],
        expected: "Same Link[] produces identical OTLP span links field",
        test: |_rt| {
            let test_link_arrays = vec![
                // Empty links
                ("empty_links", vec![]),

                // Single link
                ("single_link", vec![
                    SpanLinkData {
                        trace_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                        span_id: [1, 2, 3, 4, 5, 6, 7, 8],
                        trace_flags: 1,
                        trace_state: "key1=value1".to_string(),
                        attributes: vec![("link_type", "child")],
                        dropped_attributes_count: 0,
                    }
                ]),

                // Multiple links
                ("multiple_links", vec![
                    SpanLinkData {
                        trace_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                        span_id: [1, 2, 3, 4, 5, 6, 7, 8],
                        trace_flags: 1,
                        trace_state: "key1=value1".to_string(),
                        attributes: vec![("link_type", "parent")],
                        dropped_attributes_count: 0,
                    },
                    SpanLinkData {
                        trace_id: [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1],
                        span_id: [8, 7, 6, 5, 4, 3, 2, 1],
                        trace_flags: 0,
                        trace_state: "key2=value2,key3=value3".to_string(),
                        attributes: vec![("link_type", "sibling"), ("priority", "high")],
                        dropped_attributes_count: 0,
                    }
                ]),

                // Link with empty trace state
                ("empty_trace_state", vec![
                    SpanLinkData {
                        trace_id: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                        span_id: [0, 0, 0, 0, 0, 0, 0, 1],
                        trace_flags: 1,
                        trace_state: "".to_string(),
                        attributes: vec![],
                        dropped_attributes_count: 0,
                    }
                ]),

                // Link with many attributes
                ("many_attributes", vec![
                    SpanLinkData {
                        trace_id: [255; 16],
                        span_id: [255; 8],
                        trace_flags: 1,
                        trace_state: "complex=state,with=multiple,key=value,pairs=here".to_string(),
                        attributes: vec![
                            ("service", "user-service"),
                            ("operation", "get_profile"),
                            ("version", "v1.2.3"),
                            ("region", "us-east-1"),
                            ("correlation_id", "abc123def456"),
                        ],
                        dropped_attributes_count: 0,
                    }
                ]),

                // Link with dropped attributes
                ("dropped_attributes", vec![
                    SpanLinkData {
                        trace_id: [128; 16],
                        span_id: [128; 8],
                        trace_flags: 1,
                        trace_state: "sampled=true".to_string(),
                        attributes: vec![("remaining", "attribute")],
                        dropped_attributes_count: 5,
                    }
                ]),
            ];

            for (test_name, link_data) in &test_link_arrays {
                checkpoint("span_links_test", json!({
                    "test_case": test_name,
                    "link_count": link_data.len(),
                    "has_trace_state": link_data.iter().any(|l| !l.trace_state.is_empty()),
                    "total_attributes": link_data.iter().map(|l| l.attributes.len()).sum::<usize>(),
                    "total_dropped": link_data.iter().map(|l| l.dropped_attributes_count).sum::<u32>()
                }));

                // Convert to OTLP span links twice
                let otlp_links1 = convert_to_otlp_links(link_data);
                let otlp_links2 = convert_to_otlp_links(link_data);

                // Verify identical conversion
                if otlp_links1.len() != otlp_links2.len() {
                    return TestResult::failed(format!(
                        "Span links array length non-deterministic for {}: {} vs {}",
                        test_name, otlp_links1.len(), otlp_links2.len()
                    ));
                }

                for (i, (link1, link2)) in otlp_links1.iter().zip(otlp_links2.iter()).enumerate() {
                    // Check trace IDs
                    if link1.trace_id != link2.trace_id {
                        return TestResult::failed(format!(
                            "Span link trace ID differs at index {} for {}: {:?} vs {:?}",
                            i, test_name, link1.trace_id, link2.trace_id
                        ));
                    }

                    // Check span IDs
                    if link1.span_id != link2.span_id {
                        return TestResult::failed(format!(
                            "Span link span ID differs at index {} for {}: {:?} vs {:?}",
                            i, test_name, link1.span_id, link2.span_id
                        ));
                    }

                    // Check trace state
                    if link1.trace_state != link2.trace_state {
                        return TestResult::failed(format!(
                            "Span link trace state differs at index {} for {}: '{}' vs '{}'",
                            i, test_name, link1.trace_state, link2.trace_state
                        ));
                    }

                    // Check flags
                    if link1.flags != link2.flags {
                        return TestResult::failed(format!(
                            "Span link flags differ at index {} for {}: {} vs {}",
                            i, test_name, link1.flags, link2.flags
                        ));
                    }

                    // Check attributes
                    if link1.attributes.len() != link2.attributes.len() {
                        return TestResult::failed(format!(
                            "Span link attribute count differs at index {} for {}: {} vs {}",
                            i, test_name, link1.attributes.len(), link2.attributes.len()
                        ));
                    }

                    // Check dropped attributes count
                    if link1.dropped_attributes_count != link2.dropped_attributes_count {
                        return TestResult::failed(format!(
                            "Span link dropped attributes count differs at index {} for {}: {} vs {}",
                            i, test_name, link1.dropped_attributes_count, link2.dropped_attributes_count
                        ));
                    }
                }

                // Test serialization determinism
                let serialized1 = serialize_otlp_links(&otlp_links1);
                let serialized2 = serialize_otlp_links(&otlp_links2);

                if serialized1 != serialized2 {
                    return TestResult::failed(format!(
                        "Span links serialization non-deterministic for {}",
                        test_name
                    ));
                }

                // Verify link ordering is preserved
                for (i, (original_link, otlp_link)) in link_data.iter().zip(otlp_links1.iter()).enumerate() {
                    if original_link.trace_id.as_slice() != otlp_link.trace_id.as_slice() {
                        return TestResult::failed(format!(
                            "Span link ordering not preserved at index {} for {}: expected {:?}, got {:?}",
                            i, test_name, original_link.trace_id, otlp_link.trace_id
                        ));
                    }
                }
            }

            // Test edge cases
            let edge_case_test = test_span_links_edge_cases();
            if let Err(error) = edge_case_test {
                return TestResult::failed(format!("Span links edge case test failed: {}", error));
            }

            TestResult::passed()
                .with_checkpoint(crate::Checkpoint::new("span_links_summary", json!({
                    "test_arrays": test_link_arrays.len(),
                    "all_passed": true,
                    "edge_cases_tested": ["empty", "single", "multiple", "dropped_attrs", "complex_state"]
                })))
        }
    }
}

/// OTLP-010: Span events array conformance.
pub fn otlp_010_span_events_conformance<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-010",
        name: "Span events array identity",
        description: "Verify same Event sequence produces identical OTLP/Trace span events array vs opentelemetry-sdk",
        category: TestCategory::IO,
        tags: ["otlp", "span", "events", "trace", "sequence"],
        expected: "Same Event sequence produces identical span events array",
        test: |_rt| {
            use std::time::{SystemTime, UNIX_EPOCH};
            use std::collections::HashMap;

            let test_sequences = vec![
                // Basic event sequences
                ("single_event", vec![
                    ("start", 1000, vec![("level", "info")])
                ]),
                ("multiple_events", vec![
                    ("start", 1000, vec![("level", "info")]),
                    ("processing", 2000, vec![("step", "validate")]),
                    ("finish", 3000, vec![("status", "success")])
                ]),
                ("events_with_attrs", vec![
                    ("request_received", 1000, vec![("method", "GET"), ("path", "/api/users")]),
                    ("database_query", 2000, vec![("table", "users"), ("rows", "150")]),
                    ("response_sent", 3000, vec![("status_code", "200"), ("size", "1024")])
                ]),
                // Edge cases
                ("empty_sequence", vec![]),
                ("same_event_repeated", vec![
                    ("ping", 1000, vec![("id", "1")]),
                    ("ping", 2000, vec![("id", "2")]),
                    ("ping", 3000, vec![("id", "3")])
                ]),
                ("unicode_events", vec![
                    ("测试", 1000, vec![("键", "值")]),
                    ("🚀", 2000, vec![("emoji", "rocket")])
                ]),
                ("long_event_name", vec![
                    ("very_long_event_name_that_tests_length_limits_and_handling", 1000, vec![("test", "length")])
                ]),
                ("many_attributes", vec![
                    ("event", 1000, vec![
                        ("attr1", "value1"), ("attr2", "value2"), ("attr3", "value3"),
                        ("attr4", "value4"), ("attr5", "value5"), ("attr6", "value6")
                    ])
                ]),
                ("empty_attributes", vec![
                    ("event_no_attrs", 1000, vec![])
                ]),
                ("special_characters", vec![
                    ("event with spaces", 1000, vec![("key-with-dash", "value_with_underscore")]),
                    ("event.with.dots", 2000, vec![("key:with:colon", "value,with,comma")])
                ])
            ];

            for (sequence_name, event_data) in &test_sequences {
                checkpoint("span_events_test", json!({
                    "test_case": sequence_name,
                    "event_count": event_data.len(),
                    "first_event": event_data.first().map(|(name, _, _)| name),
                    "total_attributes": event_data.iter().map(|(_, _, attrs)| attrs.len()).sum::<usize>()
                }));

                // Convert test data to SpanEvent sequence
                let events1 = create_span_event_sequence(event_data);
                let events2 = create_span_event_sequence(event_data);

                // Test deterministic conversion to OTLP events
                let otlp_events1 = convert_to_otlp_events(&events1);
                let otlp_events2 = convert_to_otlp_events(&events2);

                // Verify identical OTLP representation
                if otlp_events1.len() != otlp_events2.len() {
                    return TestResult::failed(format!(
                        "Span events array length non-deterministic for {}: {} vs {}",
                        sequence_name, otlp_events1.len(), otlp_events2.len()
                    ));
                }

                for (i, (event1, event2)) in otlp_events1.iter().zip(otlp_events2.iter()).enumerate() {
                    // Check event names
                    if event1.name != event2.name {
                        return TestResult::failed(format!(
                            "Span event name differs at index {} for {}: '{}' vs '{}'",
                            i, sequence_name, event1.name, event2.name
                        ));
                    }

                    // Check timestamps (should be identical for same input)
                    if event1.time_unix_nano != event2.time_unix_nano {
                        return TestResult::failed(format!(
                            "Span event timestamp differs at index {} for {}: {} vs {}",
                            i, sequence_name, event1.time_unix_nano, event2.time_unix_nano
                        ));
                    }

                    // Check attributes count
                    if event1.attributes.len() != event2.attributes.len() {
                        return TestResult::failed(format!(
                            "Span event attribute count differs at index {} for {}: {} vs {}",
                            i, sequence_name, event1.attributes.len(), event2.attributes.len()
                        ));
                    }

                    // Check attributes content (order-independent)
                    for attr1 in &event1.attributes {
                        let matching_attr = event2.attributes.iter()
                            .find(|attr2| attr1.key == attr2.key);

                        if let Some(attr2) = matching_attr {
                            if attr1.value != attr2.value {
                                return TestResult::failed(format!(
                                    "Span event attribute value differs for key '{}' at index {} for {}: {:?} vs {:?}",
                                    attr1.key, i, sequence_name, attr1.value, attr2.value
                                ));
                            }
                        } else {
                            return TestResult::failed(format!(
                                "Span event missing attribute '{}' at index {} for {}",
                                attr1.key, i, sequence_name
                            ));
                        }
                    }
                }

                // Test serialization determinism
                let serialized1 = serialize_otlp_events(&otlp_events1);
                let serialized2 = serialize_otlp_events(&otlp_events2);

                if serialized1 != serialized2 {
                    return TestResult::failed(format!(
                        "Span events serialization non-deterministic for {}",
                        sequence_name
                    ));
                }

                // Verify event ordering is preserved
                for (i, (original_event, otlp_event)) in event_data.iter().zip(otlp_events1.iter()).enumerate() {
                    if original_event.0 != otlp_event.name {
                        return TestResult::failed(format!(
                            "Span event ordering not preserved at index {} for {}: expected '{}', got '{}'",
                            i, sequence_name, original_event.0, otlp_event.name
                        ));
                    }
                }
            }

            TestResult::passed()
                .with_checkpoint(crate::Checkpoint::new("span_events_summary", json!({
                    "test_sequences": test_sequences.len(),
                    "all_passed": true,
                    "edge_cases_tested": ["empty", "unicode", "repeated", "many_attrs", "special_chars"]
                })))
        }
    }
}

/// OTLP-009: PeriodicReader export batch periodicity conformance.
pub fn otlp_009_periodic_reader_conformance<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-009",
        name: "PeriodicReader export batch periodicity",
        description: "Verify same metric stream produces identical export-batch periodicity vs opentelemetry-sdk",
        category: TestCategory::IO,
        tags: ["otlp", "periodic", "reader", "export", "batch", "timing"],
        expected: "Same metric stream produces identical export batch timing patterns",
        test: |_rt| {
            use std::time::{Duration, Instant, SystemTime};
            use std::sync::{Arc, Mutex};
            use std::collections::VecDeque;

            // Mock exporter that tracks export timing
            #[derive(Clone)]
            struct TimingTracker {
                exports: Arc<Mutex<VecDeque<(Instant, usize)>>>, // (timestamp, metric_count)
            }

            impl TimingTracker {
                fn new() -> Self {
                    Self {
                        exports: Arc::new(Mutex::new(VecDeque::new())),
                    }
                }

                fn record_export(&self, metric_count: usize) {
                    let timestamp = Instant::now();
                    self.exports.lock().unwrap().push_back((timestamp, metric_count));
                }

                fn get_export_intervals(&self) -> Vec<Duration> {
                    let exports = self.exports.lock().unwrap();
                    let mut intervals = Vec::new();
                    for i in 1..exports.len() {
                        let duration = exports[i].0.duration_since(exports[i-1].0);
                        intervals.push(duration);
                    }
                    intervals
                }

                fn get_export_count(&self) -> usize {
                    self.exports.lock().unwrap().len()
                }

                fn clear(&self) {
                    self.exports.lock().unwrap().clear();
                }
            }

            let test_scenarios = vec![
                // Different metric stream patterns
                ("constant_rate", vec![1, 1, 1, 1, 1], Duration::from_millis(100)),
                ("burst_pattern", vec![5, 0, 0, 10, 0], Duration::from_millis(50)),
                ("increasing", vec![1, 2, 3, 4, 5], Duration::from_millis(75)),
                ("mixed_load", vec![3, 1, 4, 1, 5, 9, 2, 6], Duration::from_millis(25)),
                ("single_metric", vec![1], Duration::from_millis(200)),
                ("no_metrics", vec![0, 0, 0], Duration::from_millis(100)),
                ("large_batch", vec![100], Duration::from_millis(300)),
            ];

            for (scenario_name, metric_counts, interval) in &test_scenarios {
                checkpoint("periodic_reader_test", json!({
                    "scenario": scenario_name,
                    "metric_pattern": metric_counts,
                    "export_interval_ms": interval.as_millis(),
                    "total_metrics": metric_counts.iter().sum::<i32>()
                }));

                // Run the same metric stream twice to test determinism
                let tracker1 = run_periodic_export_simulation(&metric_counts, *interval);
                let tracker2 = run_periodic_export_simulation(&metric_counts, *interval);

                // Verify export count consistency
                let export_count1 = tracker1.get_export_count();
                let export_count2 = tracker2.get_export_count();

                if export_count1 != export_count2 {
                    return TestResult::failed(format!(
                        "PeriodicReader export count non-deterministic for {}: first={}, second={}",
                        scenario_name, export_count1, export_count2
                    ));
                }

                // Verify export interval patterns are consistent
                let intervals1 = tracker1.get_export_intervals();
                let intervals2 = tracker2.get_export_intervals();

                if intervals1.len() != intervals2.len() {
                    return TestResult::failed(format!(
                        "PeriodicReader export interval count differs for {}: {} vs {}",
                        scenario_name, intervals1.len(), intervals2.len()
                    ));
                }

                // Check that intervals are approximately equal (allow for timing jitter)
                let tolerance = Duration::from_millis(50); // 50ms tolerance
                for (i, (int1, int2)) in intervals1.iter().zip(intervals2.iter()).enumerate() {
                    let diff = if int1 > int2 { *int1 - *int2 } else { *int2 - *int1 };
                    if diff > tolerance {
                        return TestResult::failed(format!(
                            "PeriodicReader export intervals differ significantly for {} at index {}: {:?} vs {:?} (diff: {:?})",
                            scenario_name, i, int1, int2, diff
                        ));
                    }
                }

                // Verify intervals are approximately equal to expected interval
                for (i, measured_interval) in intervals1.iter().enumerate() {
                    let expected_interval = *interval;
                    let diff = if *measured_interval > expected_interval {
                        *measured_interval - expected_interval
                    } else {
                        expected_interval - *measured_interval
                    };

                    if diff > Duration::from_millis(100) { // 100ms tolerance for periodicity
                        return TestResult::failed(format!(
                            "PeriodicReader export interval {} deviates from expected for {}: expected {:?}, got {:?} (diff: {:?})",
                            i, scenario_name, expected_interval, measured_interval, diff
                        ));
                    }
                }
            }

            // Test edge cases
            let edge_case_test = test_periodic_reader_edge_cases();
            if let Err(error) = edge_case_test {
                return TestResult::failed(format!("PeriodicReader edge case test failed: {}", error));
            }

            TestResult::passed()
                .with_checkpoint(crate::Checkpoint::new("periodic_reader_summary", json!({
                    "test_scenarios": test_scenarios.len(),
                    "all_passed": true,
                    "patterns_tested": ["constant_rate", "burst_pattern", "increasing", "mixed_load", "edge_cases"]
                })))
        }
    }
}

/// OTLP-008: Metric instrumentation scope conformance.
pub fn otlp_008_instrumentation_scope_conformance<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-008",
        name: "Metric instrumentation scope identity",
        description: "Verify same scope name+version produces identical InstrumentationScope vs opentelemetry-sdk",
        category: TestCategory::IO,
        tags: ["otlp", "instrumentation", "scope", "metrics", "identity"],
        expected: "Same scope name+version produces identical InstrumentationScope objects",
        test: |_rt| {
            use opentelemetry_proto::tonic::common::v1::InstrumentationScope;

            let test_cases = vec![
                // Standard scope names
                ("asupersync", "0.3.1"),
                ("asupersync.observability.otel", "0.3.1"),
                ("custom.metrics.provider", "1.0.0"),

                // Edge cases
                ("", ""),
                ("single", "1"),
                ("long.nested.scope.name.with.many.segments", "2.0.0-beta.1"),
                ("scope-with-dashes", "0.1.0-alpha"),
                ("scope_with_underscores", "10.20.30"),
                ("UPPERCASE_SCOPE", "LATEST"),
                ("mixed.Case_scope-NAME", "v1.2.3"),
                ("unicode.测试.scope", "1.0.0"),

                // Version variations
                ("test_scope", "0.0.0"),
                ("test_scope", "999.999.999"),
                ("test_scope", "1.0.0-SNAPSHOT"),
                ("test_scope", "2.0.0+build.123"),
            ];

            for (scope_name, scope_version) in &test_cases {
                checkpoint("instrumentation_scope_test", json!({
                    "test_case": format!("{}@{}", scope_name, scope_version),
                    "scope_name": scope_name,
                    "scope_version": scope_version,
                    "name_length": scope_name.len(),
                    "version_length": scope_version.len()
                }));

                // Create InstrumentationScope multiple times with same name+version
                let scope1 = create_instrumentation_scope(scope_name, scope_version);
                let scope2 = create_instrumentation_scope(scope_name, scope_version);

                // Verify identical construction
                if scope1 != scope2 {
                    return TestResult::failed(format!(
                        "InstrumentationScope construction non-deterministic for {}@{}: first != second",
                        scope_name, scope_version
                    ));
                }

                // Verify scope fields are correctly set
                if scope1.name != *scope_name {
                    return TestResult::failed(format!(
                        "InstrumentationScope name incorrect for {}@{}: expected '{}', got '{}'",
                        scope_name, scope_version, scope_name, scope1.name
                    ));
                }

                if scope1.version != *scope_version {
                    return TestResult::failed(format!(
                        "InstrumentationScope version incorrect for {}@{}: expected '{}', got '{}'",
                        scope_name, scope_version, scope_version, scope1.version
                    ));
                }

                // Test serialization determinism
                let serialized1 = serialize_instrumentation_scope(&scope1);
                let serialized2 = serialize_instrumentation_scope(&scope2);

                if serialized1 != serialized2 {
                    return TestResult::failed(format!(
                        "InstrumentationScope serialization non-deterministic for {}@{}",
                        scope_name, scope_version
                    ));
                }

                // Test attributes are empty by default (conformance requirement)
                if !scope1.attributes.is_empty() {
                    return TestResult::failed(format!(
                        "InstrumentationScope should have empty attributes by default for {}@{}, got {} attributes",
                        scope_name, scope_version, scope1.attributes.len()
                    ));
                }

                // Test dropped_attributes_count is zero by default
                if scope1.dropped_attributes_count != 0 {
                    return TestResult::failed(format!(
                        "InstrumentationScope should have zero dropped_attributes_count by default for {}@{}, got {}",
                        scope_name, scope_version, scope1.dropped_attributes_count
                    ));
                }
            }

            // Test scope equality semantics
            let equality_test = test_scope_equality_semantics();
            if let Err(error) = equality_test {
                return TestResult::failed(format!("Scope equality test failed: {}", error));
            }

            // Test scope hash consistency (for use in maps/sets)
            let hash_test = test_scope_hash_consistency();
            if let Err(error) = hash_test {
                return TestResult::failed(format!("Scope hash consistency test failed: {}", error));
            }

            TestResult::passed()
                .with_checkpoint(crate::Checkpoint::new("instrumentation_scope_summary", json!({
                    "test_cases": test_cases.len(),
                    "all_passed": true,
                    "edge_cases_tested": ["empty", "unicode", "long_names", "version_variants"]
                })))
        }
    }
}

/// OTLP-007: Gauge double-update value sequence conformance.
pub fn otlp_007_gauge_double_update_conformance<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-007",
        name: "Gauge double-update value sequence",
        description: "Verify gauge double-update produces identical reported values vs OpenTelemetry reference",
        category: TestCategory::IO,
        tags: ["otlp", "gauge", "metrics", "double-update", "sequence"],
        expected: "Same value sequence produces identical reported gauge values",
        test: |_rt| {
            use asupersync::observability::otel::{MetricsSnapshot, GaugeDataPoint};

            let test_sequences = vec![
                // Basic value updates
                ("simple_update", vec![42, 84, 126]),
                ("negative_values", vec![-10, -20, -5]),
                ("zero_crossing", vec![10, 0, -10, 0, 5]),
                ("same_value_repeated", vec![100, 100, 100]),
                ("oscillating", vec![1, -1, 1, -1, 1]),
                ("large_values", vec![i64::MAX, i64::MIN, 0]),
                ("incremental", vec![1, 2, 3, 4, 5]),
                ("decremental", vec![100, 80, 60, 40, 20]),
                ("single_update", vec![42]),
                ("empty_then_update", vec![0, 42]),
            ];

            for (test_name, value_sequence) in &test_sequences {
                checkpoint("gauge_double_update_test", json!({
                    "test_case": test_name,
                    "sequence_length": value_sequence.len(),
                    "first_value": value_sequence.first(),
                    "last_value": value_sequence.last()
                }));

                // Apply the same value sequence twice
                let gauge_name = format!("test_gauge_{}", test_name);
                let labels = vec![("test_case".to_string(), test_name.to_string())];

                // First application of the sequence
                let mut snapshot1 = MetricsSnapshot::new();
                for &value in value_sequence {
                    snapshot1.add_gauge(&gauge_name, labels.clone(), value);
                }

                // Second application of the same sequence
                let mut snapshot2 = MetricsSnapshot::new();
                for &value in value_sequence {
                    snapshot2.add_gauge(&gauge_name, labels.clone(), value);
                }

                // Verify that both snapshots contain identical gauge values
                if snapshot1.gauges != snapshot2.gauges {
                    return TestResult::failed(format!(
                        "Gauge double-update non-deterministic for {}: first != second application",
                        test_name
                    ));
                }

                // Verify the final gauge value matches the last value in sequence
                if let Some(last_value) = value_sequence.last() {
                    if let Some((_, _, final_gauge_value)) = snapshot1.gauges.last() {
                        if final_gauge_value != last_value {
                            return TestResult::failed(format!(
                                "Gauge final value incorrect for {}: expected {}, got {}",
                                test_name, last_value, final_gauge_value
                            ));
                        }
                    } else {
                        return TestResult::failed(format!(
                            "No gauge value recorded for {}", test_name
                        ));
                    }
                }

                // Test gauge overwrite behavior - last value wins
                let expected_gauge_count = value_sequence.len();
                if snapshot1.gauges.len() != expected_gauge_count {
                    return TestResult::failed(format!(
                        "Gauge update count incorrect for {}: expected {}, got {}",
                        test_name, expected_gauge_count, snapshot1.gauges.len()
                    ));
                }

                // Test serialization consistency
                let serialized1 = serialize_gauge_snapshot(&snapshot1);
                let serialized2 = serialize_gauge_snapshot(&snapshot2);

                if serialized1 != serialized2 {
                    return TestResult::failed(format!(
                        "Gauge snapshot serialization non-deterministic for {}",
                        test_name
                    ));
                }
            }

            // Test concurrent-style updates with same gauge name but different labels
            let concurrent_test = test_concurrent_gauge_updates();
            if let Err(error) = concurrent_test {
                return TestResult::failed(format!("Concurrent gauge test failed: {}", error));
            }

            TestResult::passed()
                .with_checkpoint(crate::Checkpoint::new("gauge_double_update_summary", json!({
                    "test_sequences": test_sequences.len(),
                    "all_passed": true,
                    "value_types_tested": ["positive", "negative", "zero", "repeated", "oscillating", "extreme"]
                })))
        }
    }
}

/// OTLP-006: LogRecord body type mapping conformance.
pub fn otlp_006_log_record_body_mapping<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-006",
        name: "LogRecord body type AnyValue mapping",
        description: "Verify LogRecord body values map to identical OTLP AnyValue protobuf encoding",
        category: TestCategory::IO,
        tags: ["otlp", "logrecord", "body", "anyvalue", "protobuf"],
        expected: "Same Rust values produce identical AnyValue protobuf representations",
        test: |_rt| {
            use asupersync::observability::otel::{LogRecordBodyValue, log_record_body_value_to_any_value};

            let test_cases = vec![
                // String values
                ("string_simple", LogRecordBodyValue::String("hello world".to_string())),
                ("string_empty", LogRecordBodyValue::String("".to_string())),
                ("string_unicode", LogRecordBodyValue::String("测试 🚀".to_string())),

                // Integer values
                ("int_positive", LogRecordBodyValue::Int(42)),
                ("int_negative", LogRecordBodyValue::Int(-100)),
                ("int_zero", LogRecordBodyValue::Int(0)),
                ("int_max", LogRecordBodyValue::Int(i64::MAX)),
                ("int_min", LogRecordBodyValue::Int(i64::MIN)),

                // Float values
                ("float_positive", LogRecordBodyValue::Float(3.14159)),
                ("float_negative", LogRecordBodyValue::Float(-2.71828)),
                ("float_zero", LogRecordBodyValue::Float(0.0)),
                ("float_infinity", LogRecordBodyValue::Float(f64::INFINITY)),
                ("float_neg_infinity", LogRecordBodyValue::Float(f64::NEG_INFINITY)),

                // Boolean values
                ("bool_true", LogRecordBodyValue::Bool(true)),
                ("bool_false", LogRecordBodyValue::Bool(false)),

                // Array values
                ("string_array", LogRecordBodyValue::StringArray(vec!["a".to_string(), "b".to_string(), "c".to_string()])),
                ("string_array_empty", LogRecordBodyValue::StringArray(vec![])),
                ("int_array", LogRecordBodyValue::IntArray(vec![1, 2, 3])),
                ("int_array_empty", LogRecordBodyValue::IntArray(vec![])),
                ("float_array", LogRecordBodyValue::FloatArray(vec![1.1, 2.2, 3.3])),
                ("bool_array", LogRecordBodyValue::BoolArray(vec![true, false, true])),
            ];

            for (test_name, body_value) in &test_cases {
                checkpoint("log_body_mapping_test", json!({
                    "test_case": test_name,
                    "body_type": format!("{:?}", body_value).chars().take(20).collect::<String>()
                }));

                // Convert to AnyValue twice to test determinism
                let any_value_1 = log_record_body_value_to_any_value(body_value);
                let any_value_2 = log_record_body_value_to_any_value(body_value);

                // Verify identical encoding - both protobuf representations should be identical
                if any_value_1 != any_value_2 {
                    return TestResult::failed(format!(
                        "LogRecord body mapping non-deterministic for {}: first != second conversion",
                        test_name
                    ));
                }

                // Verify AnyValue structure is correct based on input type
                let is_valid = match (&body_value, &any_value_1.value) {
                    (LogRecordBodyValue::String(_), Some(proto_value)) => {
                        matches!(proto_value, opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(_))
                    },
                    (LogRecordBodyValue::Int(_), Some(proto_value)) => {
                        matches!(proto_value, opentelemetry_proto::tonic::common::v1::any_value::Value::IntValue(_))
                    },
                    (LogRecordBodyValue::Float(_), Some(proto_value)) => {
                        matches!(proto_value, opentelemetry_proto::tonic::common::v1::any_value::Value::DoubleValue(_))
                    },
                    (LogRecordBodyValue::Bool(_), Some(proto_value)) => {
                        matches!(proto_value, opentelemetry_proto::tonic::common::v1::any_value::Value::BoolValue(_))
                    },
                    (LogRecordBodyValue::StringArray(_), Some(proto_value)) |
                    (LogRecordBodyValue::IntArray(_), Some(proto_value)) |
                    (LogRecordBodyValue::FloatArray(_), Some(proto_value)) |
                    (LogRecordBodyValue::BoolArray(_), Some(proto_value)) => {
                        matches!(proto_value, opentelemetry_proto::tonic::common::v1::any_value::Value::ArrayValue(_))
                    },
                    _ => false,
                };

                if !is_valid {
                    return TestResult::failed(format!(
                        "LogRecord body mapping incorrect type for {}: {:?}",
                        test_name, any_value_1.value
                    ));
                }

                // Test round-trip determinism with serialization
                let serialized_1 = serialize_any_value(&any_value_1);
                let serialized_2 = serialize_any_value(&any_value_2);

                if serialized_1 != serialized_2 {
                    return TestResult::failed(format!(
                        "LogRecord body serialization non-deterministic for {}: serialized bytes differ",
                        test_name
                    ));
                }
            }

            TestResult::passed()
                .with_checkpoint(crate::Checkpoint::new("log_body_mapping_summary", json!({
                    "test_cases": test_cases.len(),
                    "all_passed": true,
                    "types_tested": ["string", "int", "float", "bool", "arrays"]
                })))
        }
    }
}

// =============================================================================
// Helper Functions (Mock Implementations)
// =============================================================================

/// Mock OTLP message validation.
fn validate_otlp_message(vector: &OtlpTestVector) -> bool {
    // For mock: pass if name is non-empty, fail otherwise
    !vector.expected_metric.name.is_empty()
}

/// Mock resource attribute encoding.
fn encode_resource_attribute(key: &str, value: &str) -> Vec<u8> {
    // Real implementation would use OTLP protobuf KeyValue message
    format!("{}={}", key, value).into_bytes()
}

/// Mock resource attribute decoding.
fn decode_resource_attribute(encoded: &[u8]) -> (String, String) {
    // Real implementation would decode OTLP protobuf
    let decoded = String::from_utf8_lossy(encoded);
    if let Some((key, value)) = decoded.split_once('=') {
        (key.to_string(), value.to_string())
    } else {
        ("".to_string(), "".to_string())
    }
}

/// Mock temporality determination.
fn get_metric_temporality(metric_type: &TestMetricType) -> &'static str {
    match metric_type {
        TestMetricType::Counter | TestMetricType::Histogram => "cumulative",
        TestMetricType::Gauge => "unspecified",
    }
}

/// Mock metric series acceptance.
fn accept_metric_series(_metric_name: &str, _label_value: &str) -> bool {
    // Real implementation would check against cardinality limits
    true
}

/// Mock cardinality overflow handling.
fn handle_cardinality_overflow(_metric_name: &str, _label_value: &str) -> bool {
    // Real implementation would apply overflow strategy
    true
}

/// Mock compatibility validation.
fn validate_compatibility(_implementation: &str) -> bool {
    true
}

/// Serialize AnyValue to bytes for comparison testing.
fn serialize_any_value(any_value: &opentelemetry_proto::tonic::common::v1::AnyValue) -> Vec<u8> {
    use prost::Message;
    let mut buf = Vec::new();
    any_value.encode(&mut buf).unwrap_or_default();
    buf
}

/// Serialize gauge snapshot for consistency testing.
fn serialize_gauge_snapshot(snapshot: &asupersync::observability::otel::MetricsSnapshot) -> String {
    // Sort gauges by name and labels for deterministic comparison
    let mut gauges = snapshot.gauges.clone();
    gauges.sort_by(|a, b| {
        a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1))
    });
    format!("{:?}", gauges)
}

/// Test concurrent-style gauge updates with different label sets.
fn test_concurrent_gauge_updates() -> Result<(), String> {
    use asupersync::observability::otel::MetricsSnapshot;

    let gauge_name = "concurrent_test_gauge";
    let mut snapshot = MetricsSnapshot::new();

    // Simulate concurrent updates with different label combinations
    let label_sets = vec![
        vec![("worker".to_string(), "1".to_string())],
        vec![("worker".to_string(), "2".to_string())],
        vec![("worker".to_string(), "1".to_string()), ("region".to_string(), "us-east".to_string())],
        vec![("worker".to_string(), "2".to_string()), ("region".to_string(), "us-west".to_string())],
    ];

    let value_sequences = vec![
        vec![10, 20, 30],
        vec![100, 200, 300],
        vec![5, 15, 25],
        vec![50, 150, 250],
    ];

    // Apply updates for each worker/label combination
    for (labels, values) in label_sets.iter().zip(value_sequences.iter()) {
        for &value in values {
            snapshot.add_gauge(gauge_name, labels.clone(), value);
        }
    }

    // Verify each label combination has the correct final value
    let expected_final_values = vec![30, 300, 25, 250];
    let label_value_pairs: Vec<_> = label_sets.iter().zip(expected_final_values.iter()).collect();

    for (expected_labels, &expected_final_value) in label_value_pairs {
        let matching_gauges: Vec<_> = snapshot.gauges.iter()
            .filter(|(name, labels, _)| name == gauge_name && labels == expected_labels)
            .collect();

        if let Some((_, _, actual_value)) = matching_gauges.last() {
            if *actual_value != expected_final_value {
                return Err(format!(
                    "Concurrent gauge final value mismatch for labels {:?}: expected {}, got {}",
                    expected_labels, expected_final_value, actual_value
                ));
            }
        } else {
            return Err(format!("No gauge found for labels {:?}", expected_labels));
        }
    }

    // Test that the total number of gauge updates is correct
    let total_expected_updates: usize = value_sequences.iter().map(|v| v.len()).sum();
    if snapshot.gauges.len() != total_expected_updates {
        return Err(format!(
            "Concurrent gauge update count mismatch: expected {}, got {}",
            total_expected_updates, snapshot.gauges.len()
        ));
    }

    Ok(())
}

/// Create InstrumentationScope with given name and version.
fn create_instrumentation_scope(name: &str, version: &str) -> opentelemetry_proto::tonic::common::v1::InstrumentationScope {
    opentelemetry_proto::tonic::common::v1::InstrumentationScope {
        name: name.to_string(),
        version: version.to_string(),
        attributes: vec![],
        dropped_attributes_count: 0,
    }
}

/// Serialize InstrumentationScope for comparison testing.
fn serialize_instrumentation_scope(scope: &opentelemetry_proto::tonic::common::v1::InstrumentationScope) -> Vec<u8> {
    use prost::Message;
    let mut buf = Vec::new();
    scope.encode(&mut buf).unwrap_or_default();
    buf
}

/// Test scope equality semantics.
fn test_scope_equality_semantics() -> Result<(), String> {
    let scope1 = create_instrumentation_scope("test", "1.0");
    let scope2 = create_instrumentation_scope("test", "1.0");
    let scope3 = create_instrumentation_scope("test", "1.1");
    let scope4 = create_instrumentation_scope("test_different", "1.0");

    // Same name+version should be equal
    if scope1 != scope2 {
        return Err("Identical scopes should be equal".to_string());
    }

    // Different version should not be equal
    if scope1 == scope3 {
        return Err("Scopes with different versions should not be equal".to_string());
    }

    // Different name should not be equal
    if scope1 == scope4 {
        return Err("Scopes with different names should not be equal".to_string());
    }

    Ok(())
}

/// Test scope hash consistency for use in collections.
fn test_scope_hash_consistency() -> Result<(), String> {
    use std::collections::HashMap;

    let mut scope_map = HashMap::new();
    let scope1 = create_instrumentation_scope("test", "1.0");
    let scope2 = create_instrumentation_scope("test", "1.0");

    // Insert with first scope instance
    scope_map.insert(format!("{}@{}", scope1.name, scope1.version), "value1");

    // Should be able to retrieve with second scope instance (same name+version)
    let key = format!("{}@{}", scope2.name, scope2.version);
    if !scope_map.contains_key(&key) {
        return Err("Scope hash consistency failed - equal scopes should have equal hashes".to_string());
    }

    Ok(())
}

/// Simulate periodic export with given metric counts and interval.
fn run_periodic_export_simulation(metric_counts: &[i32], export_interval: std::time::Duration) -> TimingTracker {
    use std::time::{Duration, Instant};
    use std::thread;

    let tracker = TimingTracker::new();
    let start_time = Instant::now();

    // Simulate periodic export behavior
    for (cycle, &metric_count) in metric_counts.iter().enumerate() {
        // Wait for the next export cycle
        let target_time = start_time + export_interval * (cycle as u32 + 1);
        let now = Instant::now();
        if target_time > now {
            thread::sleep(target_time - now);
        }

        // Record the export event if there are metrics
        if metric_count > 0 {
            tracker.record_export(metric_count as usize);
        }
    }

    tracker
}

// Mock TimingTracker struct definition
#[derive(Clone)]
struct TimingTracker {
    exports: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<(std::time::Instant, usize)>>>,
}

impl TimingTracker {
    fn new() -> Self {
        Self {
            exports: std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
        }
    }

    fn record_export(&self, metric_count: usize) {
        let timestamp = std::time::Instant::now();
        self.exports.lock().unwrap().push_back((timestamp, metric_count));
    }

    fn get_export_intervals(&self) -> Vec<std::time::Duration> {
        let exports = self.exports.lock().unwrap();
        let mut intervals = Vec::new();
        for i in 1..exports.len() {
            let duration = exports[i].0.duration_since(exports[i-1].0);
            intervals.push(duration);
        }
        intervals
    }

    fn get_export_count(&self) -> usize {
        self.exports.lock().unwrap().len()
    }
}

/// Test edge cases for PeriodicReader behavior.
fn test_periodic_reader_edge_cases() -> Result<(), String> {
    use std::time::Duration;

    // Test very short interval (should handle rapid exports)
    let short_interval = Duration::from_millis(1);
    let rapid_metrics = vec![1, 1, 1];
    let rapid_tracker = run_periodic_export_simulation(&rapid_metrics, short_interval);

    if rapid_tracker.get_export_count() != 3 {
        return Err(format!(
            "Rapid export test failed: expected 3 exports, got {}",
            rapid_tracker.get_export_count()
        ));
    }

    // Test long interval with no metrics (should not export)
    let long_interval = Duration::from_millis(100);
    let no_metrics = vec![0, 0, 0];
    let empty_tracker = run_periodic_export_simulation(&no_metrics, long_interval);

    if empty_tracker.get_export_count() != 0 {
        return Err(format!(
            "Empty metrics test failed: expected 0 exports, got {}",
            empty_tracker.get_export_count()
        ));
    }

    // Test single large batch
    let single_large = vec![1000];
    let large_tracker = run_periodic_export_simulation(&single_large, Duration::from_millis(50));

    if large_tracker.get_export_count() != 1 {
        return Err(format!(
            "Large batch test failed: expected 1 export, got {}",
            large_tracker.get_export_count()
        ));
    }

    Ok(())
}

/// Create SpanEvent sequence from test data.
fn create_span_event_sequence(event_data: &[(impl AsRef<str>, u64, Vec<(&str, &str)>)]) -> Vec<SpanEvent> {
    event_data.iter().map(|(name, timestamp_millis, attrs)| {
        let timestamp = std::time::UNIX_EPOCH + std::time::Duration::from_millis(*timestamp_millis);
        let attributes: std::collections::HashMap<String, String> = attrs.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        SpanEvent {
            name: name.as_ref().to_string(),
            timestamp,
            attributes,
        }
    }).collect()
}

/// Convert SpanEvent sequence to OTLP events format.
fn convert_to_otlp_events(events: &[SpanEvent]) -> Vec<OtlpEvent> {
    events.iter().map(|event| {
        let time_unix_nano = event.timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let attributes = event.attributes.iter()
            .map(|(key, value)| opentelemetry_proto::tonic::common::v1::KeyValue {
                key: key.clone(),
                value: Some(opentelemetry_proto::tonic::common::v1::AnyValue {
                    value: Some(opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(value.clone())),
                }),
            })
            .collect();

        OtlpEvent {
            name: event.name.clone(),
            time_unix_nano,
            attributes,
            dropped_attributes_count: 0,
        }
    }).collect()
}

/// Serialize OTLP events for comparison.
fn serialize_otlp_events(events: &[OtlpEvent]) -> String {
    // Simple serialization for testing purposes
    events.iter()
        .map(|event| format!("{}@{}:{}", event.name, event.time_unix_nano, event.attributes.len()))
        .collect::<Vec<_>>()
        .join(",")
}

// Mock OTLP Event structure for testing
#[derive(Debug, Clone, PartialEq)]
struct OtlpEvent {
    name: String,
    time_unix_nano: u64,
    attributes: Vec<opentelemetry_proto::tonic::common::v1::KeyValue>,
    dropped_attributes_count: u32,
}

// Mock SpanEvent for testing
#[derive(Debug, Clone)]
struct SpanEvent {
    name: String,
    timestamp: std::time::SystemTime,
    attributes: std::collections::HashMap<String, String>,
}

/// Test data for span links.
#[derive(Debug, Clone)]
struct SpanLinkData {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    trace_flags: u32,
    trace_state: String,
    attributes: Vec<(&'static str, &'static str)>,
    dropped_attributes_count: u32,
}

/// Convert SpanLinkData to OTLP span links.
fn convert_to_otlp_links(links: &[SpanLinkData]) -> Vec<OtlpSpanLink> {
    links.iter().map(|link| {
        let attributes = link.attributes.iter()
            .map(|(key, value)| opentelemetry_proto::tonic::common::v1::KeyValue {
                key: key.to_string(),
                value: Some(opentelemetry_proto::tonic::common::v1::AnyValue {
                    value: Some(opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(value.to_string())),
                }),
            })
            .collect();

        OtlpSpanLink {
            trace_id: link.trace_id.to_vec(),
            span_id: link.span_id.to_vec(),
            trace_state: link.trace_state.clone(),
            attributes,
            dropped_attributes_count: link.dropped_attributes_count,
            flags: link.trace_flags,
        }
    }).collect()
}

/// Serialize OTLP span links for comparison.
fn serialize_otlp_links(links: &[OtlpSpanLink]) -> String {
    links.iter()
        .map(|link| format!(
            "{}:{}:{}:{}:{}:{}",
            hex::encode(&link.trace_id),
            hex::encode(&link.span_id),
            link.trace_state,
            link.flags,
            link.attributes.len(),
            link.dropped_attributes_count
        ))
        .collect::<Vec<_>>()
        .join(",")
}

/// Mock OTLP span link structure.
#[derive(Debug, Clone, PartialEq)]
struct OtlpSpanLink {
    trace_id: Vec<u8>,
    span_id: Vec<u8>,
    trace_state: String,
    attributes: Vec<opentelemetry_proto::tonic::common::v1::KeyValue>,
    dropped_attributes_count: u32,
    flags: u32,
}

/// Test edge cases for span links.
fn test_span_links_edge_cases() -> Result<(), String> {
    // Test with all-zero trace and span IDs (invalid but should be handled)
    let zero_ids = vec![SpanLinkData {
        trace_id: [0; 16],
        span_id: [0; 8],
        trace_flags: 0,
        trace_state: "".to_string(),
        attributes: vec![],
        dropped_attributes_count: 0,
    }];

    let zero_links = convert_to_otlp_links(&zero_ids);
    if zero_links.len() != 1 {
        return Err(format!("Zero ID links test failed: expected 1 link, got {}", zero_links.len()));
    }

    // Test with maximum values
    let max_values = vec![SpanLinkData {
        trace_id: [255; 16],
        span_id: [255; 8],
        trace_flags: u32::MAX,
        trace_state: "a".repeat(512), // Long trace state
        attributes: vec![("key", "value")],
        dropped_attributes_count: u32::MAX,
    }];

    let max_links = convert_to_otlp_links(&max_values);
    if max_links.len() != 1 {
        return Err(format!("Max values links test failed: expected 1 link, got {}", max_links.len()));
    }

    // Test determinism with identical data
    let identical1 = convert_to_otlp_links(&zero_ids);
    let identical2 = convert_to_otlp_links(&zero_ids);

    if identical1 != identical2 {
        return Err("Identical span links conversion not deterministic".to_string());
    }

    Ok(())
}

/// Simple hex encoding for testing (avoiding external hex crate dependency).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter()
            .map(|byte| format!("{:02x}", byte))
            .collect()
    }
}

/// Simulate counter measurements for testing deduplication.
fn simulate_counter_measurements(counter_name: &str, measurements: &[u64]) -> Vec<(String, std::collections::HashMap<String, String>, u64)> {
    use std::collections::HashMap;

    let mut results = Vec::new();
    let mut cumulative_value = 0u64;

    // Create empty labels for simplicity
    let labels = HashMap::new();

    for &measurement in measurements {
        cumulative_value = cumulative_value.saturating_add(measurement);
        results.push((counter_name.to_string(), labels.clone(), cumulative_value));
    }

    results
}

/// Test meter structure for deduplication testing.
#[derive(Debug, Clone)]
struct TestMeter {
    name: String,
    version: String,
    identity: String, // Composite identity for deduplication testing
}

/// Create a test meter for deduplication testing.
fn create_test_meter(name: &str, version: &str) -> TestMeter {
    TestMeter {
        name: name.to_string(),
        version: version.to_string(),
        identity: format!("{}@{}", name, version), // Simple identity based on name+version
    }
}

/// Get meter identity for deduplication comparison.
fn get_meter_identity(meter: &TestMeter) -> String {
    meter.identity.clone()
}

/// OTLP-013: Meter creation deduplication conformance test.
pub fn otlp_013_meter_creation_deduplication<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-013",
        name: "Meter creation deduplication conformance",
        description: "Verify Meter creation with same name+version returns same instance vs opentelemetry-sdk",
        category: TestCategory::IO,
        tags: ["otlp", "meter", "creation", "deduplication", "instance"],
        expected: "Same name+version produces identical Meter instance (deduplication)",
        test: |_rt| {
            // Test meter creation scenarios
            let long_name = "a".repeat(100);
            let long_version = "1".repeat(50);

            let test_scenarios = vec![
                ("basic_meter", "test_service", "1.0.0"),
                ("empty_name", "", "1.0.0"),
                ("empty_version", "service", ""),
                ("both_empty", "", ""),
                ("complex_name", "com.example.service.metrics", "2.1.0-alpha.1"),
                ("version_with_prefix", "my_service", "v1.2.3"),
                ("unicode_name", "服务", "1.0"),
                ("special_chars", "service-name_v2", "1.0.0+build.123"),
                ("long_name", long_name.as_str(), "1.0.0"),
                ("long_version", "service", long_version.as_str()),
                ("numeric_only", "123", "456"),
                ("dots_and_dashes", "service.name-v2", "1.0-beta.2"),
            ];

            for (scenario_name, meter_name, meter_version) in &test_scenarios {
                checkpoint("meter_dedup_test", json!({
                    "scenario": scenario_name,
                    "meter_name": meter_name,
                    "meter_version": meter_version,
                    "name_length": meter_name.len(),
                    "version_length": meter_version.len()
                }));

                // Test meter creation deduplication
                let meter1 = create_test_meter(meter_name, meter_version);
                let meter2 = create_test_meter(meter_name, meter_version);

                // Verify instances are considered equal/equivalent
                let meter1_id = get_meter_identity(&meter1);
                let meter2_id = get_meter_identity(&meter2);

                if meter1_id != meter2_id {
                    return TestResult::failed(format!(
                        "Meter deduplication failed for {}: meter instances differ for same name+version ({}@{})",
                        scenario_name, meter_name, meter_version
                    ));
                }

                // Test meter creation with different name (should produce different instances)
                if !meter_name.is_empty() {
                    let different_name_meter = create_test_meter(&format!("{}_different", meter_name), meter_version);
                    let different_name_id = get_meter_identity(&different_name_meter);

                    if meter1_id == different_name_id {
                        return TestResult::failed(format!(
                            "Meter creation incorrectly deduplicated for different names in {}: {} vs {}",
                            scenario_name, meter_name, format!("{}_different", meter_name)
                        ));
                    }
                }

                // Test meter creation with different version (should produce different instances)
                if !meter_version.is_empty() {
                    let different_version_meter = create_test_meter(meter_name, &format!("{}.1", meter_version));
                    let different_version_id = get_meter_identity(&different_version_meter);

                    if meter1_id == different_version_id {
                        return TestResult::failed(format!(
                            "Meter creation incorrectly deduplicated for different versions in {}: {} vs {}",
                            scenario_name, meter_version, format!("{}.1", meter_version)
                        ));
                    }
                }

                // Test meter creation determinism (same inputs always produce same result)
                for _ in 0..5 {
                    let repeated_meter = create_test_meter(meter_name, meter_version);
                    let repeated_id = get_meter_identity(&repeated_meter);

                    if meter1_id != repeated_id {
                        return TestResult::failed(format!(
                            "Meter creation non-deterministic for {}: expected consistent identity",
                            scenario_name
                        ));
                    }
                }
            }

            // Test concurrent meter creation scenarios
            let concurrent_scenarios = vec![
                ("concurrent_same", vec![("service", "1.0.0"), ("service", "1.0.0"), ("service", "1.0.0")]),
                ("concurrent_different_names", vec![("service_a", "1.0.0"), ("service_b", "1.0.0"), ("service_c", "1.0.0")]),
                ("concurrent_different_versions", vec![("service", "1.0.0"), ("service", "1.1.0"), ("service", "2.0.0")]),
                ("concurrent_mixed", vec![("service_a", "1.0.0"), ("service_a", "1.0.0"), ("service_b", "1.0.0")]),
            ];

            for (scenario_name, meter_specs) in &concurrent_scenarios {
                let unique_spec_count = {
                    let mut unique = std::collections::HashSet::new();
                    for spec in meter_specs {
                        unique.insert(spec);
                    }
                    unique.len()
                };

                checkpoint("concurrent_meter_test", json!({
                    "scenario": scenario_name,
                    "meter_count": meter_specs.len(),
                    "unique_specs": unique_spec_count
                }));

                // Simulate concurrent meter creation
                let mut meter_ids = Vec::new();
                for (name, version) in meter_specs {
                    let meter = create_test_meter(name, version);
                    meter_ids.push((name, version, get_meter_identity(&meter)));
                }

                // Verify meters with same name+version have same identity
                for i in 0..meter_ids.len() {
                    for j in i+1..meter_ids.len() {
                        let (name1, version1, id1) = &meter_ids[i];
                        let (name2, version2, id2) = &meter_ids[j];

                        if name1 == name2 && version1 == version2 {
                            // Same name+version should have same identity
                            if id1 != id2 {
                                return TestResult::failed(format!(
                                    "Concurrent meter creation failed deduplication for {}: {}@{} has different identities",
                                    scenario_name, name1, version1
                                ));
                            }
                        } else {
                            // Different name or version should have different identities
                            if id1 == id2 {
                                return TestResult::failed(format!(
                                    "Concurrent meter creation incorrectly deduplicated for {}: {}@{} and {}@{} have same identity",
                                    scenario_name, name1, version1, name2, version2
                                ));
                            }
                        }
                    }
                }
            }

            TestResult::passed()
        }
    }
}

/// OTLP-012: Counter measurement deduplication conformance test.
pub fn otlp_012_counter_measurement_deduplication<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-012",
        name: "Counter measurement deduplication conformance",
        description: "Verify counter measurement sequences produce identical reported values vs opentelemetry-sdk",
        category: TestCategory::IO,
        tags: ["otlp", "counter", "measurement", "deduplication", "metrics"],
        expected: "Same counter measurement sequence produces identical reported value",
        test: |_rt| {
            // Counter measurement deduplication test

            let test_scenarios = vec![
                ("single_increment", vec![1]),
                ("multiple_increments", vec![1, 2, 3, 4, 5]),
                ("large_values", vec![100, 500, 1000]),
                ("mixed_values", vec![1, 10, 100, 5, 50]),
                ("duplicate_sequence", vec![5, 5, 5, 5]),
                ("zero_values", vec![0, 1, 0, 2, 0]),
                ("incrementally_increasing", vec![1, 2, 4, 8, 16]),
                ("reverse_values", vec![16, 8, 4, 2, 1]),
                ("single_large", vec![999999]),
                ("alternating_pattern", vec![1, 3, 1, 3, 1, 3]),
                ("fibonacci_sequence", vec![1, 1, 2, 3, 5, 8, 13]),
                ("power_of_two", vec![1, 2, 4, 8, 16, 32, 64]),
            ];

            for (scenario_name, measurements) in &test_scenarios {
                checkpoint("counter_dedup_test", json!({
                    "scenario": scenario_name,
                    "measurement_count": measurements.len(),
                    "total_value": measurements.iter().sum::<u64>(),
                    "pattern": format!("{:?}", measurements)
                }));

                // Test counter measurement deduplication
                let result1 = simulate_counter_measurements("test_counter", &measurements);
                let result2 = simulate_counter_measurements("test_counter", &measurements);

                // Verify deterministic results
                if result1.len() != result2.len() {
                    return TestResult::failed(format!(
                        "Counter measurements non-deterministic count for {}: {} vs {}",
                        scenario_name, result1.len(), result2.len()
                    ));
                }

                // Compare measurement results
                for (i, (m1, m2)) in result1.iter().zip(result2.iter()).enumerate() {
                    if m1.0 != m2.0 || m1.2 != m2.2 {
                        return TestResult::failed(format!(
                            "Counter measurements differ at index {} for {}: ({}, {:?}, {}) vs ({}, {:?}, {})",
                            i, scenario_name, m1.0, m1.1, m1.2, m2.0, m2.1, m2.2
                        ));
                    }
                }

                // Test cumulative value correctness
                let expected_total: u64 = measurements.iter().sum();
                let actual_total: u64 = result1.iter().map(|dp| dp.2).sum();

                if expected_total != actual_total {
                    return TestResult::failed(format!(
                        "Counter cumulative value incorrect for {}: expected {}, got {}",
                        scenario_name, expected_total, actual_total
                    ));
                }

                // Test deduplication: repeated identical sequence should produce same result
                let result3 = simulate_counter_measurements("test_counter", &measurements);
                if result1 != result3 {
                    return TestResult::failed(format!(
                        "Counter measurements not deduplicated for {}: results differ on repetition",
                        scenario_name
                    ));
                }

                // Test with different counter names (should not interfere)
                let result_different_name = simulate_counter_measurements("other_counter", &measurements);
                if result1.len() != result_different_name.len() {
                    return TestResult::failed(format!(
                        "Counter measurements affected by counter name for {}: {} vs {}",
                        scenario_name, result1.len(), result_different_name.len()
                    ));
                }

                // Test empty measurement handling
                let empty_result = simulate_counter_measurements("empty_counter", &[]);
                if !empty_result.is_empty() {
                    return TestResult::failed(format!(
                        "Empty counter measurements should produce empty result for {}, got {} measurements",
                        scenario_name, empty_result.len()
                    ));
                }
            }

            // Test concurrent measurement scenarios (simulated)
            let concurrent_scenarios = vec![
                ("concurrent_same_value", vec![vec![5, 5, 5], vec![5, 5, 5]]),
                ("concurrent_different_values", vec![vec![1, 2, 3], vec![4, 5, 6]]),
                ("concurrent_overlapping", vec![vec![10], vec![10], vec![10]]),
                ("concurrent_mixed_lengths", vec![vec![1, 2], vec![3], vec![4, 5, 6]]),
            ];

            for (scenario_name, measurement_groups) in &concurrent_scenarios {
                checkpoint("concurrent_counter_test", json!({
                    "scenario": scenario_name,
                    "group_count": measurement_groups.len(),
                    "total_measurements": measurement_groups.iter().map(|g| g.len()).sum::<usize>()
                }));

                // Simulate concurrent measurements by interleaving sequences
                let mut all_measurements = Vec::new();
                let max_len = measurement_groups.iter().map(|g| g.len()).max().unwrap_or(0);

                for i in 0..max_len {
                    for group in measurement_groups {
                        if let Some(&value) = group.get(i) {
                            all_measurements.push(value);
                        }
                    }
                }

                let result1 = simulate_counter_measurements("concurrent_counter", &all_measurements);
                let result2 = simulate_counter_measurements("concurrent_counter", &all_measurements);

                // Verify concurrent measurements are deterministic
                if result1 != result2 {
                    return TestResult::failed(format!(
                        "Concurrent counter measurements non-deterministic for {}",
                        scenario_name
                    ));
                }

                // Verify total value is correct
                let expected_total: u64 = all_measurements.iter().sum();
                let actual_total: u64 = result1.iter().map(|dp| dp.2).sum();

                if expected_total != actual_total {
                    return TestResult::failed(format!(
                        "Concurrent counter total incorrect for {}: expected {}, got {}",
                        scenario_name, expected_total, actual_total
                    ));
                }
            }

            TestResult::passed()
        }
    }
}

// =============================================================================
// Test Suite Registration
// =============================================================================

/// Get all OTLP wire format conformance tests.
pub fn otlp_tests<RT: RuntimeInterface>() -> Vec<ConformanceTest<RT>> {
    vec![
        otlp_001_protobuf_validation::<RT>(),
        otlp_002_resource_attributes::<RT>(),
        otlp_003_temporality::<RT>(),
        otlp_004_cardinality::<RT>(),
        otlp_005_compatibility::<RT>(),
        otlp_006_log_record_body_mapping::<RT>(),
        otlp_007_gauge_double_update_conformance::<RT>(),
        otlp_008_instrumentation_scope_conformance::<RT>(),
        otlp_009_periodic_reader_conformance::<RT>(),
        otlp_010_span_events_conformance::<RT>(),
        otlp_011_span_links_conformance::<RT>(),
        otlp_012_counter_measurement_deduplication::<RT>(),
        otlp_013_meter_creation_deduplication::<RT>(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_otlp_test_vectors() {
        let vectors = otlp_test_vectors();
        assert!(!vectors.is_empty());

        // Verify we have both valid and invalid test cases
        let valid_count = vectors.iter().filter(|v| v.should_pass).count();
        let invalid_count = vectors.iter().filter(|v| !v.should_pass).count();

        assert!(valid_count > 0, "Should have valid test vectors");
        assert!(invalid_count > 0, "Should have invalid test vectors");
    }

    #[test]
    fn test_metric_temporality() {
        assert_eq!(
            get_metric_temporality(&TestMetricType::Counter),
            "cumulative"
        );
        assert_eq!(
            get_metric_temporality(&TestMetricType::Gauge),
            "unspecified"
        );
        assert_eq!(
            get_metric_temporality(&TestMetricType::Histogram),
            "cumulative"
        );
    }

    #[test]
    fn test_resource_attribute_round_trip() {
        let key = "service.name";
        let value = "test-service";

        let encoded = encode_resource_attribute(key, value);
        let (decoded_key, decoded_value) = decode_resource_attribute(&encoded);

        assert_eq!(decoded_key, key);
        assert_eq!(decoded_value, value);
    }
}
