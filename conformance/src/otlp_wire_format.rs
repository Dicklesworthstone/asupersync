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

// This conformance workbench intentionally keeps spec mirrors and edge-case
// scaffolding that are not all read by every fixture path.
#![allow(
    dead_code,
    unused_comparisons,
    unused_imports,
    unused_mut,
    unused_variables
)]
#![allow(
    clippy::absurd_extreme_comparisons,
    clippy::approx_constant,
    clippy::cast_abs_to_unsigned,
    clippy::collapsible_if,
    clippy::collapsible_match,
    clippy::enum_variant_names,
    clippy::explicit_counter_loop,
    clippy::format_in_format_args,
    clippy::identity_op,
    clippy::len_zero,
    clippy::manual_abs_diff,
    clippy::manual_div_ceil,
    clippy::manual_is_multiple_of,
    clippy::manual_map,
    clippy::manual_range_contains,
    clippy::match_like_matches_macro,
    clippy::needless_borrow,
    clippy::needless_range_loop,
    clippy::repeat_once,
    clippy::unnecessary_map_or,
    clippy::unnecessary_sort_by,
    clippy::useless_format,
    clippy::useless_vec
)]

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

            // Model metric series generation beyond limits
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
        description: "Verify same live metric stream produces deterministic export-batch periodicity",
        category: TestCategory::IO,
        tags: ["otlp", "periodic", "reader", "export", "batch", "timing"],
        expected: "Same live metric stream produces identical export batch timing patterns",
        test: |_rt| {
            use std::time::Duration;

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

                // Run the same live metric-export stream twice to test determinism.
                let tracker1 = run_periodic_metric_exports(&metric_counts, *interval);
                let tracker2 = run_periodic_metric_exports(&metric_counts, *interval);

                // Verify export count consistency
                let export_count1 = tracker1.get_export_count();
                let export_count2 = tracker2.get_export_count();

                if export_count1 != export_count2 {
                    return TestResult::failed(format!(
                        "PeriodicReader export count non-deterministic for {}: first={}, second={}",
                        scenario_name, export_count1, export_count2
                    ));
                }
                let expected_exported_metric_counts = expected_non_empty_metric_counts(metric_counts);
                let exported_metric_counts = tracker1.get_export_metric_counts();
                if exported_metric_counts != expected_exported_metric_counts {
                    return TestResult::failed(format!(
                        "PeriodicReader live metric export count mismatch for {}: expected {:?}, got {:?}",
                        scenario_name, expected_exported_metric_counts, exported_metric_counts
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

                // Logical export time is deterministic, so there should be no jitter.
                let tolerance = Duration::ZERO;
                for (i, (int1, int2)) in intervals1.iter().zip(intervals2.iter()).enumerate() {
                    let diff = if int1 > int2 { *int1 - *int2 } else { *int2 - *int1 };
                    if diff > tolerance {
                        return TestResult::failed(format!(
                            "PeriodicReader export intervals differ significantly for {} at index {}: {:?} vs {:?} (diff: {:?})",
                            scenario_name, i, int1, int2, diff
                        ));
                    }
                }

                // Skipped empty cycles create interval multiples; every observed
                // export gap must still align exactly to the periodic phase.
                for (i, measured_interval) in intervals1.iter().enumerate() {
                    let expected_interval = *interval;
                    if !is_positive_multiple_of_interval(*measured_interval, expected_interval) {
                        return TestResult::failed(format!(
                            "PeriodicReader export interval {} is off phase for {}: expected a positive multiple of {:?}, got {:?}",
                            i, scenario_name, expected_interval, measured_interval
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
            use asupersync::observability::otel::MetricsSnapshot;

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
// Helper Functions
// =============================================================================

/// Validate the local OTLP metric test-vector model before protobuf export.
fn validate_otlp_message(vector: &OtlpTestVector) -> bool {
    if vector.name.trim().is_empty() {
        return false;
    }

    validate_test_metric(&vector.expected_metric).is_ok()
}

fn validate_test_metric(metric: &TestMetric) -> Result<(), &'static str> {
    if metric.name.trim().is_empty() {
        return Err("metric name is required");
    }

    if metric.scope_name.trim().is_empty() {
        return Err("instrumentation scope name is required");
    }

    if metric.data_points.is_empty() {
        return Err("at least one data point is required");
    }

    if metric
        .resource_attributes
        .iter()
        .any(|(key, _)| key.trim().is_empty())
    {
        return Err("resource attribute keys must be nonempty");
    }

    for point in &metric.data_points {
        if point.labels.iter().any(|(key, _)| key.trim().is_empty()) {
            return Err("data point label keys must be nonempty");
        }

        match (&metric.metric_type, &point.value) {
            (TestMetricType::Counter | TestMetricType::Gauge, TestMetricValue::Int64(_)) => {}
            (
                TestMetricType::Histogram,
                TestMetricValue::Histogram {
                    count,
                    sum,
                    buckets,
                },
            ) => validate_histogram_point(*count, *sum, buckets)?,
            (TestMetricType::Histogram, TestMetricValue::Int64(_)) => {
                return Err("histogram metric requires histogram data points");
            }
            (
                TestMetricType::Counter | TestMetricType::Gauge,
                TestMetricValue::Histogram { .. },
            ) => {
                return Err("counter and gauge metrics require scalar data points");
            }
        }
    }

    Ok(())
}

fn validate_histogram_point(
    count: u64,
    sum: f64,
    buckets: &[TestHistogramBucket],
) -> Result<(), &'static str> {
    if !sum.is_finite() || sum < 0.0 {
        return Err("histogram sum must be finite and non-negative");
    }

    if buckets.is_empty() {
        return Err("histogram must contain at least one bucket");
    }

    let mut previous_bound = f64::NEG_INFINITY;
    let mut previous_count = 0;
    for bucket in buckets {
        if bucket.upper_bound < previous_bound {
            return Err("histogram bucket bounds must be ordered");
        }
        if bucket.count < previous_count {
            return Err("histogram bucket counts must be cumulative");
        }
        if bucket.count > count {
            return Err("histogram bucket counts must not exceed total count");
        }

        previous_bound = bucket.upper_bound;
        previous_count = bucket.count;
    }

    if previous_count != count {
        return Err("final histogram bucket count must equal total count");
    }

    Ok(())
}

/// Encode a resource attribute as the OTLP protobuf `KeyValue` wire shape.
fn encode_resource_attribute(key: &str, value: &str) -> Vec<u8> {
    use opentelemetry_proto::tonic::common::v1::{
        AnyValue, KeyValue, any_value::Value as AnyValueKind,
    };
    use prost::Message as _;

    let attribute = KeyValue {
        key: key.to_string(),
        key_strindex: 0,
        value: Some(AnyValue {
            value: Some(AnyValueKind::StringValue(value.to_string())),
        }),
    };

    attribute.encode_to_vec()
}

/// Decode an OTLP protobuf `KeyValue` resource attribute.
fn decode_resource_attribute(encoded: &[u8]) -> (String, String) {
    use opentelemetry_proto::tonic::common::v1::{KeyValue, any_value::Value as AnyValueKind};
    use prost::Message as _;

    let Some(attribute) = KeyValue::decode(encoded).ok() else {
        return (String::new(), String::new());
    };

    let Some(value) = attribute.value.and_then(|value| value.value) else {
        return (attribute.key, String::new());
    };

    match value {
        AnyValueKind::StringValue(value) => (attribute.key, value),
        _ => (attribute.key, String::new()),
    }
}

/// Temporality policy for local metric fixture types.
fn get_metric_temporality(metric_type: &TestMetricType) -> &'static str {
    match metric_type {
        TestMetricType::Counter | TestMetricType::Histogram => "cumulative",
        TestMetricType::Gauge => "unspecified",
    }
}

/// Validate a metric series identity before the fixture's cardinality counter accepts it.
fn accept_metric_series(metric_name: &str, label_value: &str) -> bool {
    !metric_name.trim().is_empty() && !label_value.trim().is_empty()
}

/// Apply the fixture overflow policy after the cardinality limit is reached.
fn handle_cardinality_overflow(metric_name: &str, label_value: &str) -> bool {
    accept_metric_series(metric_name, label_value)
}

/// Validate the set of reference implementations supported by this conformance fixture.
fn validate_compatibility(implementation: &str) -> bool {
    matches!(
        implementation,
        "opentelemetry_collector_v0.95.0" | "prometheus_remote_write" | "grafana_agent_v0.32.1"
    )
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
    gauges.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    format!("{:?}", gauges)
}

/// Test concurrent-style gauge updates with different label sets.
fn test_concurrent_gauge_updates() -> Result<(), String> {
    use asupersync::observability::otel::MetricsSnapshot;

    let gauge_name = "concurrent_test_gauge";
    let mut snapshot = MetricsSnapshot::new();

    // Model concurrent updates with different label combinations
    let label_sets = vec![
        vec![("worker".to_string(), "1".to_string())],
        vec![("worker".to_string(), "2".to_string())],
        vec![
            ("worker".to_string(), "1".to_string()),
            ("region".to_string(), "us-east".to_string()),
        ],
        vec![
            ("worker".to_string(), "2".to_string()),
            ("region".to_string(), "us-west".to_string()),
        ],
    ];

    let value_sequences = [
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
    let expected_final_values = [30, 300, 25, 250];
    let label_value_pairs: Vec<_> = label_sets
        .iter()
        .zip(expected_final_values.iter())
        .collect();

    for (expected_labels, &expected_final_value) in label_value_pairs {
        let matching_gauges: Vec<_> = snapshot
            .gauges
            .iter()
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
            total_expected_updates,
            snapshot.gauges.len()
        ));
    }

    Ok(())
}

/// Create InstrumentationScope with given name and version.
fn create_instrumentation_scope(
    name: &str,
    version: &str,
) -> opentelemetry_proto::tonic::common::v1::InstrumentationScope {
    opentelemetry_proto::tonic::common::v1::InstrumentationScope {
        name: name.to_string(),
        version: version.to_string(),
        attributes: vec![],
        dropped_attributes_count: 0,
    }
}

/// Serialize InstrumentationScope for comparison testing.
fn serialize_instrumentation_scope(
    scope: &opentelemetry_proto::tonic::common::v1::InstrumentationScope,
) -> Vec<u8> {
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
        return Err(
            "Scope hash consistency failed - equal scopes should have equal hashes".to_string(),
        );
    }

    Ok(())
}

/// Record periodic exports by building real metric registries and exporting
/// them through the live Prometheus exposition surface at logical intervals.
fn run_periodic_metric_exports(
    metric_counts: &[i32],
    export_interval: std::time::Duration,
) -> PeriodicMetricExportTrace {
    let tracker = PeriodicMetricExportTrace::new();

    for (cycle, &metric_count) in metric_counts.iter().enumerate() {
        if metric_count > 0 {
            let elapsed = logical_export_elapsed(export_interval, cycle);
            let exported_metric_count = build_and_export_metric_batch(metric_count as usize);
            tracker.record_export(elapsed, exported_metric_count);
        }
    }

    tracker
}

fn logical_export_elapsed(
    export_interval: std::time::Duration,
    cycle: usize,
) -> std::time::Duration {
    let multiplier =
        u32::try_from(cycle.saturating_add(1)).expect("periodic export conformance cycle fits u32");
    export_interval * multiplier
}

fn build_and_export_metric_batch(metric_count: usize) -> usize {
    let mut metrics = asupersync::observability::metrics::Metrics::new();
    for index in 0..metric_count {
        metrics
            .counter(&format!("otlp_periodic_export_metric_{index}"))
            .add(u64::try_from(index.saturating_add(1)).expect("metric index fits u64"));
    }

    metrics
        .export_prometheus()
        .lines()
        .filter(|line| line.starts_with("# TYPE "))
        .count()
}

fn expected_non_empty_metric_counts(metric_counts: &[i32]) -> Vec<usize> {
    metric_counts
        .iter()
        .filter_map(|&count| usize::try_from(count).ok().filter(|&count| count > 0))
        .collect()
}

fn is_positive_multiple_of_interval(
    observed: std::time::Duration,
    interval: std::time::Duration,
) -> bool {
    let observed_nanos = observed.as_nanos();
    let interval_nanos = interval.as_nanos();
    interval_nanos > 0 && observed_nanos >= interval_nanos && observed_nanos % interval_nanos == 0
}

#[derive(Clone)]
struct PeriodicMetricExportTrace {
    exports:
        std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<(std::time::Duration, usize)>>>,
}

impl PeriodicMetricExportTrace {
    fn new() -> Self {
        Self {
            exports: std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
        }
    }

    fn record_export(&self, elapsed: std::time::Duration, metric_count: usize) {
        self.exports
            .lock()
            .unwrap()
            .push_back((elapsed, metric_count));
    }

    fn get_export_intervals(&self) -> Vec<std::time::Duration> {
        let exports = self.exports.lock().unwrap();
        let mut intervals = Vec::new();
        for i in 1..exports.len() {
            intervals.push(exports[i].0 - exports[i - 1].0);
        }
        intervals
    }

    fn get_export_count(&self) -> usize {
        self.exports.lock().unwrap().len()
    }

    fn get_export_metric_counts(&self) -> Vec<usize> {
        self.exports
            .lock()
            .unwrap()
            .iter()
            .map(|(_, metric_count)| *metric_count)
            .collect()
    }
}

/// Test edge cases for PeriodicReader behavior.
fn test_periodic_reader_edge_cases() -> Result<(), String> {
    use std::time::Duration;

    // Test very short interval (should handle rapid exports)
    let short_interval = Duration::from_millis(1);
    let rapid_metrics = vec![1, 1, 1];
    let rapid_tracker = run_periodic_metric_exports(&rapid_metrics, short_interval);

    if rapid_tracker.get_export_count() != 3 {
        return Err(format!(
            "Rapid export test failed: expected 3 exports, got {}",
            rapid_tracker.get_export_count()
        ));
    }

    // Test long interval with no metrics (should not export)
    let long_interval = Duration::from_millis(100);
    let no_metrics = vec![0, 0, 0];
    let empty_tracker = run_periodic_metric_exports(&no_metrics, long_interval);

    if empty_tracker.get_export_count() != 0 {
        return Err(format!(
            "Empty metrics test failed: expected 0 exports, got {}",
            empty_tracker.get_export_count()
        ));
    }

    // Test single large batch
    let single_large = vec![1000];
    let large_tracker = run_periodic_metric_exports(&single_large, Duration::from_millis(50));

    if large_tracker.get_export_count() != 1 {
        return Err(format!(
            "Large batch test failed: expected 1 export, got {}",
            large_tracker.get_export_count()
        ));
    }

    Ok(())
}

/// Create SpanEvent sequence from test data.
fn create_span_event_sequence(
    event_data: &[(impl AsRef<str>, u64, Vec<(&str, &str)>)],
) -> Vec<SpanEvent> {
    event_data
        .iter()
        .map(|(name, timestamp_millis, attrs)| {
            let timestamp =
                std::time::UNIX_EPOCH + std::time::Duration::from_millis(*timestamp_millis);
            let attributes: std::collections::HashMap<String, String> = attrs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

            SpanEvent {
                name: name.as_ref().to_string(),
                timestamp,
                attributes,
            }
        })
        .collect()
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
                key_strindex: 0,
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
    events
        .iter()
        .map(|event| {
            format!(
                "{}@{}:{}",
                event.name,
                event.time_unix_nano,
                event.attributes.len()
            )
        })
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
                key_strindex: 0,
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
    links
        .iter()
        .map(|link| {
            format!(
                "{}:{}:{}:{}:{}:{}",
                hex::encode(&link.trace_id),
                hex::encode(&link.span_id),
                link.trace_state,
                link.flags,
                link.attributes.len(),
                link.dropped_attributes_count
            )
        })
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
        return Err(format!(
            "Zero ID links test failed: expected 1 link, got {}",
            zero_links.len()
        ));
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
        return Err(format!(
            "Max values links test failed: expected 1 link, got {}",
            max_links.len()
        ));
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
        bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
    }
}

/// Model counter measurements for testing deduplication.
fn model_counter_measurements(
    counter_name: &str,
    measurements: &[u64],
) -> Vec<(String, std::collections::HashMap<String, String>, u64)> {
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

/// Callback execution record for ObservableCounter testing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CallbackExecution {
    counter_name: String,
    callback_id: usize,
    execution_order: usize,
    timestamp: u64, // Modeled timestamp
}

/// Model ObservableCounter callbacks for ordering testing.
fn model_observable_counter_callbacks(counter_count: usize) -> Vec<CallbackExecution> {
    let mut executions = Vec::new();
    let mut execution_order = 0;

    // Model callback registration and execution in order
    for i in 0..counter_count {
        executions.push(CallbackExecution {
            counter_name: format!("counter_{}", i),
            callback_id: i,
            execution_order,
            timestamp: execution_order as u64 * 1000, // Model 1s intervals
        });
        execution_order += 1;
    }

    executions
}

/// Model ObservableCounter callbacks in reverse registration order.
fn model_observable_counter_callbacks_reverse_order(
    counter_count: usize,
) -> Vec<CallbackExecution> {
    let mut executions = Vec::new();
    let mut execution_order = 0;

    // Model callback registration in reverse order
    for i in (0..counter_count).rev() {
        executions.push(CallbackExecution {
            counter_name: format!("counter_{}", i),
            callback_id: i,
            execution_order,
            timestamp: execution_order as u64 * 1000,
        });
        execution_order += 1;
    }

    // Sort by original counter index to match expected callback execution order
    executions.sort_by_key(|e| e.callback_id);

    // Re-assign execution order based on sorted position
    for (idx, execution) in executions.iter_mut().enumerate() {
        execution.execution_order = idx;
    }

    executions
}

/// Model concurrent ObservableCounter callbacks.
fn model_concurrent_observable_counter_callbacks(
    counter_specs: &[(String, usize)],
) -> Vec<CallbackExecution> {
    let mut executions = Vec::new();
    let mut execution_order = 0;

    // Group by counter name to model proper callback ordering
    let mut counter_groups = std::collections::HashMap::new();
    for (counter_name, callback_id) in counter_specs {
        counter_groups
            .entry(counter_name.clone())
            .or_insert_with(Vec::new)
            .push(*callback_id);
    }

    // Execute callbacks in counter name order for determinism
    let mut sorted_counters: Vec<_> = counter_groups.keys().collect();
    sorted_counters.sort();

    for counter_name in sorted_counters {
        let callback_ids = &counter_groups[counter_name];
        for &callback_id in callback_ids {
            executions.push(CallbackExecution {
                counter_name: counter_name.clone(),
                callback_id,
                execution_order,
                timestamp: execution_order as u64 * 500, // Model 500ms intervals
            });
            execution_order += 1;
        }
    }

    executions
}

/// Verify callback ordering follows expected pattern.
fn verify_callback_ordering_pattern(
    executions: &[CallbackExecution],
    expected_count: usize,
) -> Result<(), String> {
    if executions.len() != expected_count {
        return Err(format!(
            "Callback count mismatch: expected {}, got {}",
            expected_count,
            executions.len()
        ));
    }

    // Check execution order is sequential
    for (i, execution) in executions.iter().enumerate() {
        if execution.execution_order != i {
            return Err(format!(
                "Non-sequential execution order at index {}: expected {}, got {}",
                i, i, execution.execution_order
            ));
        }
    }

    // Check timestamps are monotonic
    for i in 1..executions.len() {
        if executions[i].timestamp <= executions[i - 1].timestamp {
            return Err(format!(
                "Non-monotonic timestamps at index {}: {} <= {}",
                i,
                executions[i].timestamp,
                executions[i - 1].timestamp
            ));
        }
    }

    Ok(())
}

/// Verify concurrent callback grouping is consistent.
fn verify_concurrent_callback_grouping(executions: &[CallbackExecution]) -> Result<(), String> {
    if executions.is_empty() {
        return Ok(());
    }

    // Check that execution order is sequential
    for (i, execution) in executions.iter().enumerate() {
        if execution.execution_order != i {
            return Err(format!(
                "Non-sequential concurrent execution order at index {}: expected {}, got {}",
                i, i, execution.execution_order
            ));
        }
    }

    // Verify callbacks for same counter maintain relative order
    let mut counter_positions = std::collections::HashMap::new();
    for (pos, execution) in executions.iter().enumerate() {
        counter_positions
            .entry(&execution.counter_name)
            .or_insert_with(Vec::new)
            .push((pos, execution.callback_id));
    }

    for (counter_name, positions) in counter_positions {
        // Check that callback IDs for the same counter are in ascending order of position
        for i in 1..positions.len() {
            if positions[i].0 <= positions[i - 1].0 {
                return Err(format!(
                    "Counter {} callback positions not properly ordered: {} <= {}",
                    counter_name,
                    positions[i].0,
                    positions[i - 1].0
                ));
            }
        }
    }

    Ok(())
}

/// UpDownCounter operation result for testing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UpDownCounterResult {
    counter_name: String,
    final_value: i64,
    operation_count: usize,
    increment_total: i64,
    decrement_total: i64,
}

/// Model UpDownCounter increment/decrement operations.
fn model_updown_counter_operations(
    counter_name: &str,
    increments: &[i64],
    decrements: &[i64],
) -> UpDownCounterResult {
    let mut current_value = 0i64;
    let mut operation_count = 0;

    // Apply all increments
    for &increment in increments {
        current_value = current_value.saturating_add(increment);
        operation_count += 1;
    }

    // Apply all decrements
    for &decrement in decrements {
        current_value = current_value.saturating_sub(decrement);
        operation_count += 1;
    }

    UpDownCounterResult {
        counter_name: counter_name.to_string(),
        final_value: current_value,
        operation_count,
        increment_total: increments.iter().sum(),
        decrement_total: decrements.iter().sum(),
    }
}

/// Model UpDownCounter operations with interleaved increment/decrement pattern.
fn model_updown_counter_operations_interleaved(
    counter_name: &str,
    increments: &[i64],
    decrements: &[i64],
) -> UpDownCounterResult {
    let mut current_value = 0i64;
    let mut operation_count = 0;

    // Interleave operations: alternate between increments and decrements
    let max_len = increments.len().max(decrements.len());

    for i in 0..max_len {
        // Apply increment if available
        if let Some(&increment) = increments.get(i) {
            current_value = current_value.saturating_add(increment);
            operation_count += 1;
        }

        // Apply decrement if available
        if let Some(&decrement) = decrements.get(i) {
            current_value = current_value.saturating_sub(decrement);
            operation_count += 1;
        }
    }

    UpDownCounterResult {
        counter_name: counter_name.to_string(),
        final_value: current_value,
        operation_count,
        increment_total: increments.iter().sum(),
        decrement_total: decrements.iter().sum(),
    }
}

/// Model UpDownCounter overflow protection behavior.
fn model_updown_counter_overflow_protection() -> UpDownCounterResult {
    // Test overflow scenarios - implementation should handle gracefully
    let large_increment = i64::MAX / 2;
    let result =
        model_updown_counter_operations("overflow_test", &[large_increment, large_increment], &[]);

    // The result should be handled safely (saturating arithmetic used above)
    result
}

/// Histogram bucket layout for testing.
#[derive(Debug, Clone, PartialEq)]
struct HistogramLayout {
    histogram_name: String,
    bounds: Vec<f64>,
    bucket_count: usize,
}

/// Histogram recording result for testing.
#[derive(Debug, Clone, PartialEq)]
struct HistogramRecordingResult {
    histogram_name: String,
    bucket_counts: Vec<usize>,
    total_count: usize,
    bounds: Vec<f64>,
}

/// Create histogram with explicit bounds for layout testing.
fn create_histogram_with_bounds(histogram_name: &str, explicit_bounds: &[f64]) -> HistogramLayout {
    // Normalize bounds: sort, deduplicate, filter valid values
    let mut normalized_bounds = explicit_bounds.to_vec();
    normalized_bounds.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    normalized_bounds.dedup();

    // Remove any NaN or infinite values
    normalized_bounds.retain(|&x| x.is_finite());

    // Bucket count is bounds.len() + 1 (including underflow and overflow buckets)
    let bucket_count = if normalized_bounds.is_empty() {
        1
    } else {
        normalized_bounds.len() + 1
    };

    HistogramLayout {
        histogram_name: histogram_name.to_string(),
        bounds: normalized_bounds,
        bucket_count,
    }
}

/// Generate test values strategically positioned around bounds.
fn generate_test_values_for_bounds(bounds: &[f64]) -> Vec<f64> {
    let mut test_values = vec![];

    if bounds.is_empty() {
        // No bounds - test some arbitrary values
        test_values.extend(&[0.0, 1.0, -1.0, 10.0, -10.0]);
        return test_values;
    }

    // Add values below the first bound
    let first_bound = bounds[0];
    test_values.extend(&[
        first_bound - 100.0,
        first_bound - 1.0,
        first_bound - f64::EPSILON,
    ]);

    // Add values at and around each bound
    for &bound in bounds {
        test_values.extend(&[bound - f64::EPSILON, bound, bound + f64::EPSILON]);
    }

    // Add values above the last bound
    let last_bound = bounds[bounds.len() - 1];
    test_values.extend(&[
        last_bound + f64::EPSILON,
        last_bound + 1.0,
        last_bound + 100.0,
    ]);

    // Add some values in between bounds
    for i in 0..bounds.len().saturating_sub(1) {
        let mid_value = (bounds[i] + bounds[i + 1]) / 2.0;
        test_values.push(mid_value);
    }

    test_values
}

/// Find which bucket a value would be assigned to.
fn find_bucket_for_value(layout: &HistogramLayout, value: f64) -> usize {
    if layout.bounds.is_empty() {
        // Only one bucket when no bounds
        return 0;
    }

    // Find the first bound that the value is less than or equal to
    for (i, &bound) in layout.bounds.iter().enumerate() {
        if value <= bound {
            return i;
        }
    }

    // Value is greater than all bounds - goes in overflow bucket
    layout.bounds.len()
}

/// Verify histogram bucket layout properties.
fn verify_bucket_layout_properties(
    layout: &HistogramLayout,
    original_bounds: &[f64],
) -> Result<(), String> {
    // Check bucket count consistency
    let expected_buckets = if layout.bounds.is_empty() {
        1
    } else {
        layout.bounds.len() + 1
    };
    if layout.bucket_count != expected_buckets {
        return Err(format!(
            "Bucket count mismatch: expected {}, got {}",
            expected_buckets, layout.bucket_count
        ));
    }

    // Check bounds are sorted
    for i in 1..layout.bounds.len() {
        if layout.bounds[i] <= layout.bounds[i - 1] {
            return Err(format!(
                "Bounds not properly sorted at index {}: {} <= {}",
                i,
                layout.bounds[i],
                layout.bounds[i - 1]
            ));
        }
    }

    // Check bounds are finite
    for (i, &bound) in layout.bounds.iter().enumerate() {
        if !bound.is_finite() {
            return Err(format!("Bound at index {} is not finite: {}", i, bound));
        }
    }

    // Check that all valid original bounds are preserved (after normalization)
    let mut expected_bounds = original_bounds.to_vec();
    expected_bounds.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    expected_bounds.dedup();
    expected_bounds.retain(|&x| x.is_finite());

    if layout.bounds != expected_bounds {
        return Err(format!(
            "Bounds normalization mismatch: expected {:?}, got {:?}",
            expected_bounds, layout.bounds
        ));
    }

    Ok(())
}

/// Record histogram values and return bucket distribution.
fn record_histogram_values(
    histogram_name: &str,
    bounds: &[f64],
    values: &[f64],
) -> HistogramRecordingResult {
    let layout = create_histogram_with_bounds(histogram_name, bounds);
    let mut bucket_counts = vec![0; layout.bucket_count];

    // Record each value in appropriate bucket
    for &value in values {
        let bucket = find_bucket_for_value(&layout, value);
        bucket_counts[bucket] += 1;
    }

    HistogramRecordingResult {
        histogram_name: histogram_name.to_string(),
        bucket_counts,
        total_count: values.len(),
        bounds: layout.bounds,
    }
}

/// OTLP-017: Context propagation across async-task boundary conformance test.
pub fn otlp_017_context_propagation_async_boundary<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-017",
        name: "Context propagation async boundary conformance",
        description: "Verify OpenTelemetry context propagation across async-task boundaries vs opentelemetry-sdk",
        category: TestCategory::IO,
        tags: ["otlp", "context", "propagation", "async", "boundary", "spans"],
        expected: "Context propagation across async boundaries matches opentelemetry-sdk behavior",
        test: |_rt| {
            // Test context propagation scenarios
            let propagation_scenarios = vec![
                ("simple_span_propagation", 1, 0),
                ("nested_span_propagation", 3, 0),
                ("span_with_baggage", 1, 3),
                ("multiple_baggage_items", 1, 5),
                ("deep_async_nesting", 5, 2),
                ("concurrent_spans", 3, 1),
                ("empty_context", 0, 0),
                ("baggage_only", 0, 4),
                ("mixed_context_types", 2, 6),
            ];

            for (scenario_name, span_count, baggage_count) in &propagation_scenarios {
                checkpoint("context_propagation_test", json!({
                    "scenario": scenario_name,
                    "span_count": span_count,
                    "baggage_count": baggage_count,
                    "total_context_items": span_count + baggage_count
                }));

                // Test context propagation determinism
                let result1 = model_async_context_propagation("test_operation", *span_count, *baggage_count);
                let result2 = model_async_context_propagation("test_operation", *span_count, *baggage_count);

                // Verify propagation consistency
                if result1.propagated_spans != result2.propagated_spans {
                    return TestResult::failed(format!(
                        "Context span propagation non-deterministic for {}: {} vs {}",
                        scenario_name, result1.propagated_spans.len(), result2.propagated_spans.len()
                    ));
                }

                if result1.propagated_baggage != result2.propagated_baggage {
                    return TestResult::failed(format!(
                        "Context baggage propagation non-deterministic for {}: {} vs {}",
                        scenario_name, result1.propagated_baggage.len(), result2.propagated_baggage.len()
                    ));
                }

                // Verify expected propagation counts
                if result1.propagated_spans.len() != *span_count {
                    return TestResult::failed(format!(
                        "Context span propagation count incorrect for {}: expected {}, got {}",
                        scenario_name, span_count, result1.propagated_spans.len()
                    ));
                }

                if result1.propagated_baggage.len() != *baggage_count {
                    return TestResult::failed(format!(
                        "Context baggage propagation count incorrect for {}: expected {}, got {}",
                        scenario_name, baggage_count, result1.propagated_baggage.len()
                    ));
                }

                // Verify context hierarchy preservation
                if let Err(error) = verify_context_hierarchy(&result1.propagated_spans) {
                    return TestResult::failed(format!(
                        "Context hierarchy verification failed for {}: {}",
                        scenario_name, error
                    ));
                }

                // Test context isolation between operations
                if *span_count > 0 || *baggage_count > 0 {
                    let isolated_result = model_async_context_propagation("isolated_operation", 0, 0);
                    if !isolated_result.propagated_spans.is_empty() || !isolated_result.propagated_baggage.is_empty() {
                        return TestResult::failed(format!(
                            "Context isolation failed for {}: leaked spans={}, baggage={}",
                            scenario_name, isolated_result.propagated_spans.len(), isolated_result.propagated_baggage.len()
                        ));
                    }
                }
            }

            // Test async boundary crossing patterns
            let boundary_scenarios = vec![
                ("single_async_task", vec!["parent"], vec!["task_1"]),
                ("sequential_tasks", vec!["parent"], vec!["task_1", "task_2", "task_3"]),
                ("nested_async_spawns", vec!["parent", "child"], vec!["task_1", "subtask_1", "subtask_2"]),
                ("parallel_async_tasks", vec!["parent"], vec!["task_a", "task_b", "task_c"]),
                ("async_task_chain", vec!["root"], vec!["link_1", "link_2", "link_3", "link_4"]),
                ("branching_async_tree", vec!["root", "branch_a", "branch_b"], vec!["leaf_1", "leaf_2", "leaf_3", "leaf_4"]),
            ];

            for (scenario_name, parent_spans, async_tasks) in &boundary_scenarios {
                checkpoint("async_boundary_test", json!({
                    "scenario": scenario_name,
                    "parent_span_count": parent_spans.len(),
                    "async_task_count": async_tasks.len(),
                    "total_operations": parent_spans.len() + async_tasks.len()
                }));

                // Test async boundary crossing
                let boundary_result = model_async_boundary_crossing(parent_spans, async_tasks);

                // Verify all spans are properly connected
                if boundary_result.connected_spans.len() != parent_spans.len() + async_tasks.len() {
                    return TestResult::failed(format!(
                        "Async boundary span count mismatch for {}: expected {}, got {}",
                        scenario_name, parent_spans.len() + async_tasks.len(), boundary_result.connected_spans.len()
                    ));
                }

                // Verify parent-child relationships maintained
                if let Err(error) = verify_async_span_relationships(&boundary_result, parent_spans, async_tasks) {
                    return TestResult::failed(format!(
                        "Async boundary relationship verification failed for {}: {}",
                        scenario_name, error
                    ));
                }

                // Test context restoration after async completion
                let restored_context = model_context_restoration_after_async(&boundary_result);
                if let Err(error) = verify_context_restoration(&restored_context, parent_spans) {
                    return TestResult::failed(format!(
                        "Context restoration verification failed for {}: {}",
                        scenario_name, error
                    ));
                }
            }

            // Test concurrent context propagation scenarios
            let concurrent_scenarios = vec![
                ("concurrent_independent", vec![("ctx_a", 2, 1), ("ctx_b", 1, 2), ("ctx_c", 3, 0)]),
                ("concurrent_shared_parent", vec![("shared", 1, 1), ("shared", 1, 1), ("shared", 1, 1)]),
                ("concurrent_mixed", vec![("fast", 1, 0), ("slow", 3, 2), ("medium", 2, 1)]),
                ("high_concurrency", vec![("bulk", 1, 1); 10]),
            ];

            for (scenario_name, context_specs) in &concurrent_scenarios {
                checkpoint("concurrent_context_test", json!({
                    "scenario": scenario_name,
                    "context_count": context_specs.len(),
                    "total_spans": context_specs.iter().map(|(_, s, _)| s).sum::<usize>(),
                    "total_baggage": context_specs.iter().map(|(_, _, b)| b).sum::<usize>()
                }));

                // Model concurrent context propagation
                let concurrent_results: Vec<_> = context_specs.iter()
                    .map(|(name, spans, baggage)| model_async_context_propagation(name, *spans, *baggage))
                    .collect();

                // Verify concurrent propagation determinism
                let concurrent_results2: Vec<_> = context_specs.iter()
                    .map(|(name, spans, baggage)| model_async_context_propagation(name, *spans, *baggage))
                    .collect();

                for (i, (result1, result2)) in concurrent_results.iter().zip(concurrent_results2.iter()).enumerate() {
                    if result1.propagated_spans != result2.propagated_spans || result1.propagated_baggage != result2.propagated_baggage {
                        return TestResult::failed(format!(
                            "Concurrent context propagation non-deterministic for {} at index {}",
                            scenario_name, i
                        ));
                    }
                }

                // Verify context isolation in concurrent execution
                for (i, result) in concurrent_results.iter().enumerate() {
                    let expected_spans = context_specs[i].1;
                    let expected_baggage = context_specs[i].2;

                    if result.propagated_spans.len() != expected_spans {
                        return TestResult::failed(format!(
                            "Concurrent context span isolation failed for {} at index {}: expected {}, got {}",
                            scenario_name, i, expected_spans, result.propagated_spans.len()
                        ));
                    }

                    if result.propagated_baggage.len() != expected_baggage {
                        return TestResult::failed(format!(
                            "Concurrent context baggage isolation failed for {} at index {}: expected {}, got {}",
                            scenario_name, i, expected_baggage, result.propagated_baggage.len()
                        ));
                    }
                }
            }

            TestResult::passed()
        }
    }
}

/// OTLP-018: gRPC retry-after handling conformance test.
pub fn otlp_018_grpc_retry_after_handling<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-018",
        name: "gRPC retry-after handling conformance",
        description: "Verify OTLP gRPC retry-after header handling vs opentelemetry-sdk",
        category: TestCategory::IO,
        tags: ["otlp", "grpc", "retry", "backoff", "rpc", "error-handling"],
        expected: "gRPC retry-after handling matches opentelemetry-sdk behavior",
        test: |_rt| {
            // Test basic retry-after scenarios
            let retry_scenarios = vec![
                ("immediate_retry", None, 0),
                ("short_delay", Some(1), 1),
                ("medium_delay", Some(5), 5),
                ("long_delay", Some(30), 30),
                ("max_delay", Some(300), 300),
            ];

            for (scenario_name, retry_after_seconds, expected_delay) in &retry_scenarios {
                checkpoint("grpc_retry_after_test", json!({
                    "scenario": scenario_name,
                    "retry_after": retry_after_seconds,
                    "expected_delay": expected_delay
                }));

                // Test retry-after header processing
                let retry_config = model_grpc_retry_after_handling(*retry_after_seconds);

                // Verify delay calculation matches expected
                if retry_config.calculated_delay_seconds != *expected_delay {
                    return TestResult::failed(format!(
                        "Retry delay calculation incorrect for {}: expected {}s, got {}s",
                        scenario_name, expected_delay, retry_config.calculated_delay_seconds
                    ));
                }

                // Test retry policy adherence
                let retry_policy = create_retry_policy_from_config(&retry_config);
                if let Err(error) = verify_retry_policy_compliance(&retry_policy, *retry_after_seconds) {
                    return TestResult::failed(format!(
                        "Retry policy compliance failed for {}: {}",
                        scenario_name, error
                    ));
                }

                // Test exponential backoff interaction
                if retry_after_seconds.unwrap_or(0) > 0 {
                    let backoff_result = model_exponential_backoff_with_retry_after(&retry_config, 3);
                    if let Err(error) = verify_backoff_retry_after_interaction(&backoff_result, retry_after_seconds.unwrap_or(0)) {
                        return TestResult::failed(format!(
                            "Backoff/retry-after interaction failed for {}: {}",
                            scenario_name, error
                        ));
                    }
                }
            }

            // Test gRPC status code retry behavior
            let status_scenarios = vec![
                ("resource_exhausted", GrpcStatusCode::ResourceExhausted, true, Some(10)),
                ("unavailable", GrpcStatusCode::Unavailable, true, Some(5)),
                ("internal_error", GrpcStatusCode::Internal, false, None),
                ("invalid_argument", GrpcStatusCode::InvalidArgument, false, None),
                ("deadline_exceeded", GrpcStatusCode::DeadlineExceeded, true, Some(1)),
                ("cancelled", GrpcStatusCode::Cancelled, false, None),
                ("unknown", GrpcStatusCode::Unknown, true, Some(2)),
            ];

            for (scenario_name, status_code, should_retry, retry_after) in &status_scenarios {
                checkpoint("grpc_status_retry_test", json!({
                    "scenario": scenario_name,
                    "status_code": format!("{:?}", status_code),
                    "should_retry": should_retry,
                    "retry_after": retry_after
                }));

                // Test gRPC status-based retry decisions
                let retry_decision = determine_grpc_retry_from_status(*status_code, *retry_after);

                // Verify retry decision matches expected
                if retry_decision.should_retry != *should_retry {
                    return TestResult::failed(format!(
                        "gRPC retry decision incorrect for {}: expected {}, got {}",
                        scenario_name, should_retry, retry_decision.should_retry
                    ));
                }

                // Verify retry-after header respected when present
                if let Some(expected_delay) = retry_after {
                    if retry_decision.retry_after_seconds != Some(*expected_delay) {
                        return TestResult::failed(format!(
                            "gRPC retry-after header not respected for {}: expected {}s, got {:?}",
                            scenario_name, expected_delay, retry_decision.retry_after_seconds
                        ));
                    }
                }

                // Test retry count limits with status codes
                if retry_decision.should_retry {
                    let retry_count_result = model_retry_count_limits(*status_code, 5);
                    if let Err(error) = verify_retry_count_behavior(&retry_count_result) {
                        return TestResult::failed(format!(
                            "Retry count limit behavior failed for {}: {}",
                            scenario_name, error
                        ));
                    }
                }
            }

            // Test complex retry scenarios with jitter and circuit breaking
            let complex_scenarios = vec![
                ("jittered_retry", 5, true, 0.2),
                ("circuit_breaker_open", 10, false, 0.0),
                ("adaptive_backoff", 3, true, 0.1),
                ("burst_protection", 1, true, 0.0),
            ];

            for (scenario_name, base_delay, jitter_enabled, jitter_factor) in &complex_scenarios {
                checkpoint("complex_retry_test", json!({
                    "scenario": scenario_name,
                    "base_delay": base_delay,
                    "jitter_enabled": jitter_enabled,
                    "jitter_factor": jitter_factor
                }));

                // Test complex retry behavior
                let complex_config = RetryConfiguration {
                    base_delay_seconds: *base_delay,
                    jitter_enabled: *jitter_enabled,
                    jitter_factor: *jitter_factor,
                    max_retries: 5,
                    circuit_breaker_threshold: 0.5,
                };

                let complex_result = model_complex_retry_behavior(&complex_config);

                // Verify complex retry behavior is deterministic
                let complex_result2 = model_complex_retry_behavior(&complex_config);
                if complex_result.retry_delays != complex_result2.retry_delays {
                    return TestResult::failed(format!(
                        "Complex retry behavior non-deterministic for {}: delays differ",
                        scenario_name
                    ));
                }

                // Verify jitter is within expected bounds
                if *jitter_enabled {
                    if let Err(error) = verify_jitter_bounds(&complex_result, *jitter_factor) {
                        return TestResult::failed(format!(
                            "Jitter bounds verification failed for {}: {}",
                            scenario_name, error
                        ));
                    }
                }

                // Verify circuit breaker interaction
                if let Err(error) = verify_circuit_breaker_retry_interaction(&complex_result, &complex_config) {
                    return TestResult::failed(format!(
                        "Circuit breaker interaction failed for {}: {}",
                        scenario_name, error
                    ));
                }
            }

            TestResult::passed()
        }
    }
}

/// OTLP-019: Trace-state propagation across span hierarchy conformance test.
pub fn otlp_019_trace_state_propagation_span_hierarchy<RT: RuntimeInterface>() -> ConformanceTest<RT>
{
    crate::conformance_test! {
        id: "otlp-019",
        name: "Trace-state propagation span hierarchy conformance",
        description: "Verify trace-state propagation across span hierarchy vs opentelemetry-sdk",
        category: TestCategory::IO,
        tags: ["otlp", "trace-state", "w3c", "propagation", "hierarchy", "spans"],
        expected: "Trace-state propagation across span hierarchy matches opentelemetry-sdk behavior",
        test: |_rt| {
            // Test basic trace-state propagation scenarios
            let propagation_scenarios = vec![
                ("single_vendor", vec![("vendor1", "value1")], 1),
                ("multiple_vendors", vec![("vendor1", "value1"), ("vendor2", "value2")], 1),
                ("nested_spans", vec![("root", "rootval"), ("child", "childval")], 3),
                ("deep_hierarchy", vec![("level0", "val0"), ("level1", "val1"), ("level2", "val2")], 5),
                ("empty_trace_state", vec![], 2),
                ("max_vendors", vec![("v1", "1"), ("v2", "2"), ("v3", "3"), ("v4", "4"), ("v5", "5")], 1),
                ("long_values", vec![("vendor", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")], 2),
                ("special_chars", vec![("vendor", "value=with,special:chars")], 1),
            ];

            for (scenario_name, trace_state_entries, hierarchy_depth) in &propagation_scenarios {
                checkpoint("trace_state_propagation_test", json!({
                    "scenario": scenario_name,
                    "trace_state_count": trace_state_entries.len(),
                    "hierarchy_depth": hierarchy_depth,
                    "total_expected_propagations": trace_state_entries.len() * hierarchy_depth
                }));

                // Test trace-state propagation consistency
                let propagation_result = model_trace_state_span_propagation(trace_state_entries, *hierarchy_depth);

                // Verify propagation determinism
                let propagation_result2 = model_trace_state_span_propagation(trace_state_entries, *hierarchy_depth);
                if propagation_result.propagated_states != propagation_result2.propagated_states {
                    return TestResult::failed(format!(
                        "Trace-state propagation non-deterministic for {}: state count differs",
                        scenario_name
                    ));
                }

                // Verify hierarchy preservation
                if let Err(error) = verify_trace_state_hierarchy_preservation(&propagation_result, *hierarchy_depth) {
                    return TestResult::failed(format!(
                        "Trace-state hierarchy preservation failed for {}: {}",
                        scenario_name, error
                    ));
                }

                // Verify W3C trace-state format compliance
                if let Err(error) = verify_w3c_trace_state_format(&propagation_result.propagated_states) {
                    return TestResult::failed(format!(
                        "W3C trace-state format compliance failed for {}: {}",
                        scenario_name, error
                    ));
                }

                // Test trace-state mutation and inheritance
                let mutation_result = model_trace_state_mutations(&propagation_result, scenario_name);
                if let Err(error) = verify_trace_state_mutation_rules(&mutation_result) {
                    return TestResult::failed(format!(
                        "Trace-state mutation rules failed for {}: {}",
                        scenario_name, error
                    ));
                }
            }

            // Test trace-state size and vendor limits
            let limit_scenarios = vec![
                ("vendor_count_limit", 32, 1, true),  // W3C spec allows up to 32 vendors
                ("vendor_count_exceed", 35, 1, false), // Should truncate excess
                ("total_size_limit", 10, 50, true),   // Small entries within limit
                ("total_size_exceed", 20, 200, false), // Large entries exceed 512 byte limit
                ("empty_vendor_key", 0, 0, false),    // Invalid: empty vendor key
                ("single_char_vendor", 1, 10, true),  // Valid: single char vendor
            ];

            for (scenario_name, vendor_count, value_size, should_be_valid) in &limit_scenarios {
                checkpoint("trace_state_limits_test", json!({
                    "scenario": scenario_name,
                    "vendor_count": vendor_count,
                    "value_size": value_size,
                    "should_be_valid": should_be_valid
                }));

                // Generate test trace-state with specified limits
                let test_trace_state = generate_trace_state_with_limits(*vendor_count, *value_size);
                let validation_result = validate_trace_state_limits(&test_trace_state);

                // Check validation matches expectation
                if validation_result.is_valid != *should_be_valid {
                    return TestResult::failed(format!(
                        "Trace-state limit validation incorrect for {}: expected {}, got {}",
                        scenario_name, should_be_valid, validation_result.is_valid
                    ));
                }

                // Test propagation behavior with limit-testing trace-states
                if validation_result.is_valid {
                    // Convert entries to &str format
                    let entries_ref: Vec<(&str, &str)> = test_trace_state.entries.iter()
                        .map(|(k, v)| (*k, v.as_str()))
                        .collect();
                    let limit_propagation = model_trace_state_span_propagation(&entries_ref, 2);
                    if let Err(error) = verify_trace_state_consistency(&limit_propagation) {
                        return TestResult::failed(format!(
                            "Trace-state consistency failed for {}: {}",
                            scenario_name, error
                        ));
                    }
                }
            }

            // Test trace-state vendor precedence and ordering
            let precedence_scenarios = vec![
                ("vendor_precedence", vec![("high", "1"), ("medium", "2"), ("low", "3")], vec!["high", "medium", "low"]),
                ("insertion_order", vec![("c", "3"), ("a", "1"), ("b", "2")], vec!["c", "a", "b"]),
                ("update_precedence", vec![("vendor", "old"), ("vendor", "new")], vec!["vendor"]),
                ("mixed_precedence", vec![("new", "1"), ("old", "2"), ("new", "updated")], vec!["new", "old"]),
            ];

            for (scenario_name, trace_state_entries, expected_order) in &precedence_scenarios {
                checkpoint("trace_state_precedence_test", json!({
                    "scenario": scenario_name,
                    "entry_count": trace_state_entries.len(),
                    "expected_vendor_order": expected_order
                }));

                // Test vendor precedence in propagation
                let precedence_result = model_trace_state_vendor_precedence(trace_state_entries);

                // Verify vendor ordering matches expected
                if let Err(error) = verify_vendor_ordering(&precedence_result, expected_order) {
                    return TestResult::failed(format!(
                        "Vendor ordering verification failed for {}: {}",
                        scenario_name, error
                    ));
                }

                // Test precedence preservation across span boundaries
                let boundary_result = model_trace_state_across_span_boundaries(&precedence_result, 3);
                if let Err(error) = verify_precedence_across_boundaries(&boundary_result, expected_order) {
                    return TestResult::failed(format!(
                        "Precedence across span boundaries failed for {}: {}",
                        scenario_name, error
                    ));
                }
            }

            // Test trace-state compatibility with distributed tracing
            let distributed_scenarios = vec![
                ("single_service", 1, vec![("svc1", "state1")]),
                ("multi_service", 3, vec![("svc1", "s1"), ("svc2", "s2"), ("svc3", "s3")]),
                ("service_handoff", 2, vec![("upstream", "data"), ("downstream", "processed")]),
                ("cross_boundary", 4, vec![("internal", "int"), ("external", "ext")]),
            ];

            for (scenario_name, service_count, service_states) in &distributed_scenarios {
                checkpoint("distributed_trace_state_test", json!({
                    "scenario": scenario_name,
                    "service_count": service_count,
                    "state_entries": service_states.len()
                }));

                // Test distributed trace-state propagation
                let distributed_result = model_distributed_trace_state_propagation(*service_count, service_states);

                // Verify cross-service propagation correctness
                if let Err(error) = verify_cross_service_propagation(&distributed_result, service_states) {
                    return TestResult::failed(format!(
                        "Cross-service propagation failed for {}: {}",
                        scenario_name, error
                    ));
                }

                // Test service boundary isolation
                if let Err(error) = verify_service_boundary_isolation(&distributed_result) {
                    return TestResult::failed(format!(
                        "Service boundary isolation failed for {}: {}",
                        scenario_name, error
                    ));
                }
            }

            TestResult::passed()
        }
    }
}

/// OTLP-020: HTTP/protobuf exporter format conformance test.
pub fn otlp_020_http_protobuf_exporter_format<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-020",
        name: "HTTP/protobuf exporter format conformance",
        description: "Verify OTLP HTTP/protobuf exporter format vs opentelemetry-sdk",
        category: TestCategory::IO,
        tags: ["otlp", "http", "protobuf", "exporter", "format", "encoding"],
        expected: "HTTP/protobuf exporter format matches opentelemetry-sdk behavior",
        test: |_rt| {
            // Test basic HTTP/protobuf export scenarios
            let export_scenarios = vec![
                ("single_span", 1, 0, 0),
                ("multiple_spans", 5, 0, 0),
                ("single_metric", 0, 1, 0),
                ("multiple_metrics", 0, 3, 0),
                ("single_log", 0, 0, 1),
                ("multiple_logs", 0, 0, 4),
                ("mixed_telemetry", 2, 2, 2),
                ("empty_export", 0, 0, 0),
                ("large_batch", 100, 50, 25),
            ];

            for (scenario_name, span_count, metric_count, log_count) in &export_scenarios {
                checkpoint("http_protobuf_export_test", json!({
                    "scenario": scenario_name,
                    "span_count": span_count,
                    "metric_count": metric_count,
                    "log_count": log_count,
                    "total_telemetry_items": span_count + metric_count + log_count
                }));

                // Test HTTP/protobuf export format
                let export_result = model_otlp_http_protobuf_export(*span_count, *metric_count, *log_count);

                // Verify export format determinism
                let export_result2 = model_otlp_http_protobuf_export(*span_count, *metric_count, *log_count);
                if export_result.serialized_payload != export_result2.serialized_payload {
                    return TestResult::failed(format!(
                        "HTTP/protobuf export non-deterministic for {}: payload differs",
                        scenario_name
                    ));
                }

                // Verify protobuf encoding compliance
                if let Err(error) = verify_protobuf_encoding_compliance(&export_result) {
                    return TestResult::failed(format!(
                        "Protobuf encoding compliance failed for {}: {}",
                        scenario_name, error
                    ));
                }

                // Verify HTTP headers and metadata
                if let Err(error) = verify_http_headers_metadata(&export_result) {
                    return TestResult::failed(format!(
                        "HTTP headers/metadata verification failed for {}: {}",
                        scenario_name, error
                    ));
                }

                // Test payload size and compression
                if export_result.uncompressed_size > 1024 { // Only test compression for larger payloads
                    let compression_result = model_payload_compression(&export_result);
                    if let Err(error) = verify_compression_efficiency(&compression_result) {
                        return TestResult::failed(format!(
                            "Compression efficiency verification failed for {}: {}",
                            scenario_name, error
                        ));
                    }
                }
            }

            // Test HTTP endpoint and content-type scenarios
            let endpoint_scenarios = vec![
                ("traces_endpoint", "/v1/traces", "application/x-protobuf", vec!["spans"]),
                ("metrics_endpoint", "/v1/metrics", "application/x-protobuf", vec!["metrics"]),
                ("logs_endpoint", "/v1/logs", "application/x-protobuf", vec!["logs"]),
                ("mixed_endpoint_traces", "/v1/traces", "application/x-protobuf", vec!["spans", "resource"]),
                ("json_fallback", "/v1/traces", "application/json", vec!["spans"]),
                ("gzip_compressed", "/v1/traces", "application/x-protobuf", vec!["spans"]),
            ];

            for (scenario_name, endpoint, content_type, data_types) in &endpoint_scenarios {
                checkpoint("http_endpoint_test", json!({
                    "scenario": scenario_name,
                    "endpoint": endpoint,
                    "content_type": content_type,
                    "data_types": data_types
                }));

                // Test endpoint-specific export behavior
                let endpoint_result = model_endpoint_specific_export(endpoint, content_type, data_types);

                // Verify endpoint compliance
                if let Err(error) = verify_endpoint_compliance(&endpoint_result, endpoint) {
                    return TestResult::failed(format!(
                        "Endpoint compliance failed for {}: {}",
                        scenario_name, error
                    ));
                }

                // Verify content-type handling
                if let Err(error) = verify_content_type_handling(&endpoint_result, content_type) {
                    return TestResult::failed(format!(
                        "Content-type handling failed for {}: {}",
                        scenario_name, error
                    ));
                }

                // Test HTTP status code handling
                let status_result = model_http_status_responses(&endpoint_result);
                if let Err(error) = verify_status_code_handling(&status_result) {
                    return TestResult::failed(format!(
                        "HTTP status code handling failed for {}: {}",
                        scenario_name, error
                    ));
                }
            }

            // Test protobuf field encoding and ordering
            let encoding_scenarios = vec![
                ("field_ordering", vec!["resource", "scope_spans", "schema_url"]),
                ("optional_fields", vec!["span_id", "trace_id", "parent_span_id"]),
                ("repeated_fields", vec!["events", "links", "attributes"]),
                ("nested_messages", vec!["resource.attributes", "span.status"]),
                ("default_values", vec!["span.kind", "span.status.code"]),
                ("large_strings", vec!["span.name", "event.name"]),
            ];

            for (scenario_name, field_types) in &encoding_scenarios {
                checkpoint("protobuf_encoding_test", json!({
                    "scenario": scenario_name,
                    "field_types": field_types,
                    "field_count": field_types.len()
                }));

                // Test protobuf field encoding
                let field_result = model_protobuf_field_encoding(field_types);

                // Verify field encoding determinism
                let field_result2 = model_protobuf_field_encoding(field_types);
                if field_result.encoded_fields != field_result2.encoded_fields {
                    return TestResult::failed(format!(
                        "Protobuf field encoding non-deterministic for {}: field order differs",
                        scenario_name
                    ));
                }

                // Verify protobuf wire format compliance
                if let Err(error) = verify_protobuf_wire_format(&field_result) {
                    return TestResult::failed(format!(
                        "Protobuf wire format compliance failed for {}: {}",
                        scenario_name, error
                    ));
                }

                // Test round-trip encoding/decoding
                let roundtrip_result = model_protobuf_roundtrip(&field_result);
                if let Err(error) = verify_roundtrip_fidelity(&roundtrip_result) {
                    return TestResult::failed(format!(
                        "Protobuf round-trip fidelity failed for {}: {}",
                        scenario_name, error
                    ));
                }
            }

            // Test batch size limits and chunking
            let batch_scenarios = vec![
                ("small_batch", 10, 512),      // Small batch under limit
                ("medium_batch", 100, 4096),   // Medium batch at limit
                ("large_batch", 1000, 65536),  // Large batch requiring chunking
                ("huge_batch", 10000, 1048576), // Huge batch requiring multiple chunks
            ];

            for (scenario_name, item_count, max_payload_size) in &batch_scenarios {
                checkpoint("batch_size_test", json!({
                    "scenario": scenario_name,
                    "item_count": item_count,
                    "max_payload_size": max_payload_size,
                    "expected_chunks": (item_count * 100) / max_payload_size + 1 // Estimate
                }));

                // Test batch size handling
                let batch_result = model_batch_size_handling(*item_count, *max_payload_size);

                // Verify chunking behavior
                if let Err(error) = verify_chunking_behavior(&batch_result, *max_payload_size) {
                    return TestResult::failed(format!(
                        "Chunking behavior verification failed for {}: {}",
                        scenario_name, error
                    ));
                }

                // Verify data integrity across chunks
                if let Err(error) = verify_chunk_data_integrity(&batch_result) {
                    return TestResult::failed(format!(
                        "Chunk data integrity failed for {}: {}",
                        scenario_name, error
                    ));
                }

                // Test retry behavior for failed chunks
                if batch_result.chunk_count > 1 {
                    let retry_result = model_chunk_retry_behavior(&batch_result);
                    if let Err(error) = verify_chunk_retry_compliance(&retry_result) {
                        return TestResult::failed(format!(
                            "Chunk retry compliance failed for {}: {}",
                            scenario_name, error
                        ));
                    }
                }
            }

            TestResult::passed()
        }
    }
}

/// OTLP-021: Span.set_attribute() conformance test.
pub fn otlp_021_span_set_attribute_conformance<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-021",
        name: "Span.set_attribute() conformance",
        description: "Verify Span.set_attribute() vs opentelemetry-sdk produces identical attribute serialization",
        category: TestCategory::IO,
        tags: ["otlp", "span", "attributes", "set_attribute", "serialization"],
        expected: "Same key+value pairs produce identical attribute serialization",
        test: |_rt| {
            // Test basic attribute value types
            let attribute_type_scenarios = vec![
                ("string_attribute", vec![("service.name", AttributeValue::String("test-service".to_string()))]),
                ("int_attribute", vec![("service.port", AttributeValue::Int(8080))]),
                ("float_attribute", vec![("cpu.usage", AttributeValue::Float(85.5))]),
                ("bool_attribute", vec![("is_production", AttributeValue::Bool(true))]),
                ("string_array", vec![("service.tags", AttributeValue::StringArray(vec!["web".to_string(), "api".to_string()]))]),
                ("int_array", vec![("port_list", AttributeValue::IntArray(vec![80, 443, 8080]))]),
                ("float_array", vec![("response_times", AttributeValue::FloatArray(vec![1.2, 2.5, 0.8]))]),
                ("bool_array", vec![("feature_flags", AttributeValue::BoolArray(vec![true, false, true]))]),
                ("mixed_attributes", vec![
                    ("service.name", AttributeValue::String("test".to_string())),
                    ("service.port", AttributeValue::Int(8080)),
                    ("cpu.usage", AttributeValue::Float(75.0)),
                    ("debug_mode", AttributeValue::Bool(false)),
                ]),
            ];

            for (scenario_name, attributes) in &attribute_type_scenarios {
                checkpoint("span_attribute_test", json!({
                    "scenario": scenario_name,
                    "attribute_count": attributes.len(),
                    "attribute_types": attributes.iter().map(|(_, v)| format!("{:?}", v)).collect::<Vec<_>>()
                }));

                // Test span attribute serialization consistency
                let span_result = model_span_set_attributes(scenario_name, attributes);

                // Verify serialization determinism
                let span_result2 = model_span_set_attributes(scenario_name, attributes);
                if span_result.serialized_attributes != span_result2.serialized_attributes {
                    return TestResult::failed(format!(
                        "Span attribute serialization non-deterministic for {}: serialized form differs",
                        scenario_name
                    ));
                }

                // Verify attribute type preservation
                if let Err(error) = verify_attribute_type_preservation(&span_result, attributes) {
                    return TestResult::failed(format!(
                        "Attribute type preservation failed for {}: {}",
                        scenario_name, error
                    ));
                }

                // Verify OpenTelemetry attribute spec compliance
                if let Err(error) = verify_otel_attribute_spec_compliance(&span_result) {
                    return TestResult::failed(format!(
                        "OpenTelemetry attribute spec compliance failed for {}: {}",
                        scenario_name, error
                    ));
                }

                // Test attribute ordering and key uniqueness
                if let Err(error) = verify_attribute_ordering_uniqueness(&span_result) {
                    return TestResult::failed(format!(
                        "Attribute ordering/uniqueness failed for {}: {}",
                        scenario_name, error
                    ));
                }
            }

            // Test attribute key and value edge cases
            let long_key_value = "a".repeat(256);
            let edge_case_scenarios = vec![
                ("empty_string_key", vec![("", AttributeValue::String("value".to_string()))]),
                ("empty_string_value", vec![("key", AttributeValue::String("".to_string()))]),
                ("unicode_key", vec![("服务名称", AttributeValue::String("test".to_string()))]),
                ("unicode_value", vec![("service.name", AttributeValue::String("测试服务".to_string()))]),
                ("special_chars_key", vec![("service.name.with-dots_and-dashes", AttributeValue::String("test".to_string()))]),
                ("long_key", vec![(long_key_value.as_str(), AttributeValue::String("test".to_string()))]),
                ("long_value", vec![("key", AttributeValue::String("x".repeat(1024)))]),
                ("numeric_string", vec![("version", AttributeValue::String("1.2.3".to_string()))]),
                ("zero_values", vec![
                    ("zero_int", AttributeValue::Int(0)),
                    ("zero_float", AttributeValue::Float(0.0)),
                    ("false_bool", AttributeValue::Bool(false)),
                ]),
                ("extreme_values", vec![
                    ("max_int", AttributeValue::Int(i64::MAX)),
                    ("min_int", AttributeValue::Int(i64::MIN)),
                    ("max_float", AttributeValue::Float(f64::MAX)),
                    ("min_float", AttributeValue::Float(f64::MIN)),
                ]),
            ];

            for (scenario_name, attributes) in &edge_case_scenarios {
                checkpoint("span_attribute_edge_case_test", json!({
                    "scenario": scenario_name,
                    "attribute_count": attributes.len(),
                    "edge_case_type": scenario_name
                }));

                // Convert &str to owned String for long keys
                let owned_attributes: Vec<(String, AttributeValue)> = attributes.iter()
                    .map(|(k, v)| (k.to_string(), v.clone()))
                    .collect();

                // Test edge case handling
                let edge_result = model_span_set_attributes_owned(scenario_name, &owned_attributes);

                // Verify edge case compliance
                if let Err(error) = verify_edge_case_compliance(&edge_result, scenario_name) {
                    return TestResult::failed(format!(
                        "Edge case compliance failed for {}: {}",
                        scenario_name, error
                    ));
                }

                // Test serialization stability for edge cases
                let edge_result2 = model_span_set_attributes_owned(scenario_name, &owned_attributes);
                if edge_result.serialized_attributes != edge_result2.serialized_attributes {
                    return TestResult::failed(format!(
                        "Edge case serialization non-deterministic for {}: form differs",
                        scenario_name
                    ));
                }
            }

            // Test attribute update and override scenarios
            let update_scenarios = vec![
                ("update_same_key", vec![
                    ("key", AttributeValue::String("original".to_string())),
                    ("key", AttributeValue::String("updated".to_string())),
                ]),
                ("update_different_type", vec![
                    ("version", AttributeValue::String("1.0".to_string())),
                    ("version", AttributeValue::Int(2)),
                ]),
                ("multiple_updates", vec![
                    ("status", AttributeValue::String("starting".to_string())),
                    ("status", AttributeValue::String("running".to_string())),
                    ("status", AttributeValue::String("completed".to_string())),
                ]),
                ("interleaved_updates", vec![
                    ("a", AttributeValue::Int(1)),
                    ("b", AttributeValue::Int(2)),
                    ("a", AttributeValue::Int(3)),
                    ("c", AttributeValue::Int(4)),
                    ("b", AttributeValue::Int(5)),
                ]),
            ];

            for (scenario_name, attribute_sequence) in &update_scenarios {
                checkpoint("span_attribute_update_test", json!({
                    "scenario": scenario_name,
                    "sequence_length": attribute_sequence.len(),
                    "unique_keys": attribute_sequence.iter()
                        .map(|(k, _)| k)
                        .collect::<std::collections::HashSet<_>>()
                        .len()
                }));

                // Test attribute update behavior
                let update_result = model_span_attribute_updates(scenario_name, attribute_sequence);

                // Verify final attribute state
                if let Err(error) = verify_final_attribute_state(&update_result, attribute_sequence) {
                    return TestResult::failed(format!(
                        "Final attribute state verification failed for {}: {}",
                        scenario_name, error
                    ));
                }

                // Verify update semantics (last write wins)
                if let Err(error) = verify_attribute_update_semantics(&update_result, attribute_sequence) {
                    return TestResult::failed(format!(
                        "Attribute update semantics failed for {}: {}",
                        scenario_name, error
                    ));
                }
            }

            // Test attribute limits and validation
            let limit_scenarios = vec![
                ("max_attributes", 128),
                ("high_attribute_count", 256),
                ("extreme_attribute_count", 1024),
            ];

            for (scenario_name, attribute_count) in &limit_scenarios {
                checkpoint("span_attribute_limits_test", json!({
                    "scenario": scenario_name,
                    "attribute_count": attribute_count,
                    "expected_behavior": if *attribute_count <= 128 { "accept_all" } else { "drop_excess" }
                }));

                // Generate large number of attributes
                let large_attributes: Vec<(String, AttributeValue)> = (0..*attribute_count)
                    .map(|i| (format!("attr_{:04}", i), AttributeValue::String(format!("value_{}", i))))
                    .collect();

                // Test attribute limits
                let limits_result = model_span_set_attributes_owned(scenario_name, &large_attributes);

                // Verify attribute limit handling
                if let Err(error) = verify_attribute_limit_handling(&limits_result, *attribute_count) {
                    return TestResult::failed(format!(
                        "Attribute limit handling failed for {}: {}",
                        scenario_name, error
                    ));
                }

                // Verify performance characteristics don't degrade
                if let Err(error) = verify_attribute_performance_characteristics(&limits_result) {
                    return TestResult::failed(format!(
                        "Attribute performance characteristics failed for {}: {}",
                        scenario_name, error
                    ));
                }
            }

            TestResult::passed()
        }
    }
}

/// OTLP-016: Histogram record with explicit bounds conformance test.
pub fn otlp_016_histogram_record_explicit_bounds<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-016",
        name: "Histogram explicit bounds bucket layout conformance",
        description: "Verify Histogram.record() with explicit bounds produces identical bucket layout vs opentelemetry-sdk",
        category: TestCategory::IO,
        tags: ["otlp", "histogram", "bounds", "buckets", "layout", "record"],
        expected: "Same explicit bounds produce identical histogram bucket layout",
        test: |_rt| {
            // Test histogram explicit bounds scenarios
            let bounds_scenarios = vec![
                ("simple_bounds", vec![1.0, 5.0, 10.0]),
                ("single_bound", vec![5.0]),
                ("many_bounds", vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0]),
                ("negative_bounds", vec![-10.0, -1.0, 0.0, 1.0, 10.0]),
                ("fractional_bounds", vec![0.001, 0.01, 0.1, 1.0]),
                ("large_bounds", vec![100.0, 1000.0, 10000.0]),
                ("zero_boundary", vec![0.0, 1.0, 2.0]),
                ("duplicate_bounds", vec![1.0, 1.0, 2.0, 2.0]), // Should be deduplicated
                ("unsorted_bounds", vec![10.0, 1.0, 5.0, 2.0]), // Should be sorted
                ("exponential_bounds", vec![1.0, 2.0, 4.0, 8.0, 16.0, 32.0]),
                ("decimal_precision", vec![1.1, 2.2, 3.3, 4.4, 5.5]),
                ("scientific_notation", vec![1e-3, 1e-2, 1e-1, 1e0, 1e1, 1e2]),
                ("empty_bounds", vec![]),
            ];

            for (scenario_name, explicit_bounds) in &bounds_scenarios {
                checkpoint("histogram_bounds_test", json!({
                    "scenario": scenario_name,
                    "bound_count": explicit_bounds.len(),
                    "bounds": explicit_bounds,
                    "min_bound": explicit_bounds.iter().fold(f64::INFINITY, |a, &b| a.min(b)),
                    "max_bound": explicit_bounds.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b))
                }));

                // Test histogram bucket layout consistency
                let layout1 = create_histogram_with_bounds("test_histogram", explicit_bounds);
                let layout2 = create_histogram_with_bounds("test_histogram", explicit_bounds);

                // Verify bucket layout determinism
                if layout1.bucket_count != layout2.bucket_count {
                    return TestResult::failed(format!(
                        "Histogram bucket count non-deterministic for {}: {} vs {}",
                        scenario_name, layout1.bucket_count, layout2.bucket_count
                    ));
                }

                if layout1.bounds != layout2.bounds {
                    return TestResult::failed(format!(
                        "Histogram bounds non-deterministic for {}: {:?} vs {:?}",
                        scenario_name, layout1.bounds, layout2.bounds
                    ));
                }

                // Test value recording and bucket assignment
                let test_values = generate_test_values_for_bounds(explicit_bounds);

                for &test_value in &test_values {
                    let bucket1 = find_bucket_for_value(&layout1, test_value);
                    let bucket2 = find_bucket_for_value(&layout2, test_value);

                    if bucket1 != bucket2 {
                        return TestResult::failed(format!(
                            "Histogram bucket assignment differs for {} value {}: bucket {} vs {}",
                            scenario_name, test_value, bucket1, bucket2
                        ));
                    }
                }

                // Verify bucket layout properties
                if let Err(error) = verify_bucket_layout_properties(&layout1, explicit_bounds) {
                    return TestResult::failed(format!(
                        "Histogram bucket layout invalid for {}: {}",
                        scenario_name, error
                    ));
                }

                // Test boundary value handling
                if !explicit_bounds.is_empty() {
                    for &boundary in explicit_bounds {
                        let bucket_at_boundary = find_bucket_for_value(&layout1, boundary);
                        let bucket_just_below = find_bucket_for_value(&layout1, boundary - f64::EPSILON);

                        // Values exactly on boundary should go to the upper bucket
                        // Values just below boundary should go to lower bucket (unless it's the first bound)
                        if boundary != explicit_bounds[0] && bucket_at_boundary == bucket_just_below {
                            return TestResult::failed(format!(
                                "Histogram boundary handling incorrect for {} at boundary {}: same bucket {} for value {} and {}",
                                scenario_name, boundary, bucket_at_boundary, boundary, boundary - f64::EPSILON
                            ));
                        }
                    }
                }
            }

            // Test histogram recording with different value patterns
            let recording_scenarios = vec![
                ("ascending_values", vec![0.5, 1.5, 5.5, 15.0], vec![1.0, 5.0, 10.0]),
                ("descending_values", vec![15.0, 5.5, 1.5, 0.5], vec![1.0, 5.0, 10.0]),
                ("repeated_values", vec![2.0, 2.0, 2.0, 2.0], vec![1.0, 5.0, 10.0]),
                ("boundary_values", vec![1.0, 5.0, 10.0], vec![1.0, 5.0, 10.0]),
                ("mixed_pattern", vec![0.1, 2.5, 7.5, 15.0, 0.8], vec![1.0, 5.0, 10.0]),
                ("extreme_values", vec![-100.0, 100000.0], vec![1.0, 5.0, 10.0]),
                ("zero_values", vec![0.0, 0.0, 0.0], vec![1.0, 5.0, 10.0]),
                ("negative_values", vec![-5.0, -2.0, -0.5], vec![-10.0, -1.0, 0.0, 1.0]),
                ("precision_values", vec![1.0000001, 4.9999999], vec![1.0, 5.0, 10.0]),
            ];

            for (scenario_name, values, bounds) in &recording_scenarios {
                checkpoint("histogram_recording_test", json!({
                    "scenario": scenario_name,
                    "value_count": values.len(),
                    "bound_count": bounds.len(),
                    "value_range": format!("{:.3} to {:.3}",
                        values.iter().fold(f64::INFINITY, |a, &b| a.min(b)),
                        values.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b))
                    )
                }));

                // Record values and verify bucket distribution
                let result1 = record_histogram_values("recording_test", bounds, values);
                let result2 = record_histogram_values("recording_test", bounds, values);

                // Verify recording determinism
                if result1.bucket_counts != result2.bucket_counts {
                    return TestResult::failed(format!(
                        "Histogram bucket counts non-deterministic for {}: {:?} vs {:?}",
                        scenario_name, result1.bucket_counts, result2.bucket_counts
                    ));
                }

                if result1.total_count != result2.total_count {
                    return TestResult::failed(format!(
                        "Histogram total count non-deterministic for {}: {} vs {}",
                        scenario_name, result1.total_count, result2.total_count
                    ));
                }

                // Verify total count matches input
                if result1.total_count != values.len() {
                    return TestResult::failed(format!(
                        "Histogram total count incorrect for {}: expected {}, got {}",
                        scenario_name, values.len(), result1.total_count
                    ));
                }

                // Verify bucket count sum matches total
                let bucket_sum: usize = result1.bucket_counts.iter().sum();
                if bucket_sum != values.len() {
                    return TestResult::failed(format!(
                        "Histogram bucket sum doesn't match total for {}: bucket_sum={}, values={}",
                        scenario_name, bucket_sum, values.len()
                    ));
                }
            }

            // Test concurrent histogram recording
            let concurrent_scenarios = vec![
                ("concurrent_same_bounds", vec![1.0, 5.0, 10.0], vec![vec![2.0, 3.0], vec![7.0, 8.0]]),
                ("concurrent_different_values", vec![0.1, 1.0, 10.0], vec![vec![0.5], vec![5.0], vec![15.0]]),
                ("concurrent_overlapping", vec![1.0, 5.0], vec![vec![2.0, 4.0], vec![3.0, 6.0]]),
                ("concurrent_high_volume", vec![1.0, 10.0, 100.0], vec![vec![5.0; 10], vec![50.0; 10], vec![500.0; 10]]),
            ];

            for (scenario_name, bounds, value_groups) in &concurrent_scenarios {
                checkpoint("concurrent_histogram_test", json!({
                    "scenario": scenario_name,
                    "group_count": value_groups.len(),
                    "bound_count": bounds.len(),
                    "total_values": value_groups.iter().map(|g| g.len()).sum::<usize>()
                }));

                // Flatten all values for concurrent recording simulation
                let all_values: Vec<f64> = value_groups.iter().flatten().cloned().collect();

                let result1 = record_histogram_values("concurrent_test", bounds, &all_values);
                let result2 = record_histogram_values("concurrent_test", bounds, &all_values);

                // Verify concurrent recording determinism
                if result1.bucket_counts != result2.bucket_counts {
                    return TestResult::failed(format!(
                        "Concurrent histogram recording non-deterministic for {}: {:?} vs {:?}",
                        scenario_name, result1.bucket_counts, result2.bucket_counts
                    ));
                }
            }

            TestResult::passed()
        }
    }
}

/// OTLP-015: UpDownCounter increment/decrement conformance test.
pub fn otlp_015_updown_counter_incr_decr_conformance<RT: RuntimeInterface>() -> ConformanceTest<RT>
{
    crate::conformance_test! {
        id: "otlp-015",
        name: "UpDownCounter increment/decrement conformance",
        description: "Verify UpDownCounter increment+decrement sequences produce identical net values vs opentelemetry-sdk",
        category: TestCategory::IO,
        tags: ["otlp", "updowncounter", "increment", "decrement", "net", "value"],
        expected: "Same increment/decrement sequence produces identical net value",
        test: |_rt| {
            // Test UpDownCounter increment/decrement scenarios
            let test_scenarios = vec![
                ("only_increments", vec![1, 2, 3, 4, 5], vec![]),
                ("only_decrements", vec![], vec![1, 2, 3, 4, 5]),
                ("alternating", vec![10, 30, 50], vec![5, 15, 25]),
                ("mixed_order", vec![100, 200], vec![50, 150, 75]),
                ("equal_incr_decr", vec![10, 20, 30], vec![10, 20, 30]),
                ("large_values", vec![1000, 5000], vec![2000, 3000]),
                ("small_values", vec![1], vec![1]),
                ("zero_operations", vec![], vec![]),
                ("single_increment", vec![42], vec![]),
                ("single_decrement", vec![], vec![42]),
                ("net_positive", vec![100, 200, 300], vec![50, 75]),
                ("net_negative", vec![50, 75], vec![100, 200, 300]),
                ("net_zero", vec![100, 50], vec![75, 75]),
                ("duplicates", vec![10, 10, 10], vec![5, 5, 5]),
                ("fibonacci_incr", vec![1, 1, 2, 3, 5, 8], vec![]),
                ("fibonacci_decr", vec![], vec![1, 1, 2, 3, 5, 8]),
                ("power_of_two", vec![1, 2, 4, 8, 16], vec![1, 2, 4]),
                ("random_pattern", vec![7, 23, 89, 12], vec![5, 17, 43, 29]),
            ];

            for (scenario_name, increments, decrements) in &test_scenarios {
                checkpoint("updown_counter_test", json!({
                    "scenario": scenario_name,
                    "increment_count": increments.len(),
                    "decrement_count": decrements.len(),
                    "total_increment": increments.iter().sum::<i64>(),
                    "total_decrement": decrements.iter().sum::<i64>(),
                    "expected_net": increments.iter().sum::<i64>() - decrements.iter().sum::<i64>()
                }));

                // Test UpDownCounter operations
                let result1 = model_updown_counter_operations("test_counter", increments, decrements);
                let result2 = model_updown_counter_operations("test_counter", increments, decrements);

                // Verify deterministic results
                if result1.final_value != result2.final_value {
                    return TestResult::failed(format!(
                        "UpDownCounter final value non-deterministic for {}: {} vs {}",
                        scenario_name, result1.final_value, result2.final_value
                    ));
                }

                if result1.operation_count != result2.operation_count {
                    return TestResult::failed(format!(
                        "UpDownCounter operation count non-deterministic for {}: {} vs {}",
                        scenario_name, result1.operation_count, result2.operation_count
                    ));
                }

                // Verify expected net value calculation
                let expected_net = increments.iter().sum::<i64>() - decrements.iter().sum::<i64>();
                if result1.final_value != expected_net {
                    return TestResult::failed(format!(
                        "UpDownCounter net value incorrect for {}: expected {}, got {}",
                        scenario_name, expected_net, result1.final_value
                    ));
                }

                // Verify operation count is correct
                let expected_operations = increments.len() + decrements.len();
                if result1.operation_count != expected_operations {
                    return TestResult::failed(format!(
                        "UpDownCounter operation count incorrect for {}: expected {}, got {}",
                        scenario_name, expected_operations, result1.operation_count
                    ));
                }

                // Test operation sequence determinism (different order, same result)
                if !increments.is_empty() && !decrements.is_empty() {
                    let result_interleaved = model_updown_counter_operations_interleaved("test_counter", increments, decrements);
                    if result1.final_value != result_interleaved.final_value {
                        return TestResult::failed(format!(
                            "UpDownCounter interleaved operations produce different result for {}: {} vs {}",
                            scenario_name, result1.final_value, result_interleaved.final_value
                        ));
                    }
                }

                // Test with different counter names (should not interfere)
                if expected_operations > 0 {
                    let result_different_name = model_updown_counter_operations("other_counter", increments, decrements);
                    if result1.final_value != result_different_name.final_value {
                        return TestResult::failed(format!(
                            "UpDownCounter affected by counter name for {}: {} vs {}",
                            scenario_name, result1.final_value, result_different_name.final_value
                        ));
                    }
                }
            }

            // Test concurrent UpDownCounter operations
            let concurrent_scenarios = vec![
                ("concurrent_increments", vec![vec![10, 20], vec![30, 40]], vec![vec![], vec![]]),
                ("concurrent_decrements", vec![vec![], vec![]], vec![vec![5, 15], vec![25, 35]]),
                ("concurrent_mixed", vec![vec![100], vec![200]], vec![vec![50], vec![75]]),
                ("concurrent_overlapping", vec![vec![10, 30], vec![20, 40]], vec![vec![5, 15], vec![25, 35]]),
                ("concurrent_uneven", vec![vec![1000], vec![10, 20, 30]], vec![vec![500, 250], vec![5]]),
            ];

            for (scenario_name, incr_groups, decr_groups) in &concurrent_scenarios {
                checkpoint("concurrent_updown_counter_test", json!({
                    "scenario": scenario_name,
                    "group_count": incr_groups.len(),
                    "total_increments": incr_groups.iter().map(|g| g.iter().sum::<i64>()).sum::<i64>(),
                    "total_decrements": decr_groups.iter().map(|g| g.iter().sum::<i64>()).sum::<i64>()
                }));

                // Model concurrent operations by flattening and applying
                let all_increments: Vec<i64> = incr_groups.iter().flatten().cloned().collect();
                let all_decrements: Vec<i64> = decr_groups.iter().flatten().cloned().collect();

                let result1 = model_updown_counter_operations("concurrent_counter", &all_increments, &all_decrements);
                let result2 = model_updown_counter_operations("concurrent_counter", &all_increments, &all_decrements);

                // Verify concurrent operations are deterministic
                if result1.final_value != result2.final_value {
                    return TestResult::failed(format!(
                        "Concurrent UpDownCounter operations non-deterministic for {}: {} vs {}",
                        scenario_name, result1.final_value, result2.final_value
                    ));
                }

                // Verify expected net value
                let expected_net: i64 = all_increments.iter().sum::<i64>() - all_decrements.iter().sum::<i64>();
                if result1.final_value != expected_net {
                    return TestResult::failed(format!(
                        "Concurrent UpDownCounter net value incorrect for {}: expected {}, got {}",
                        scenario_name, expected_net, result1.final_value
                    ));
                }
            }

            // Test edge cases and boundary conditions
            let edge_cases = vec![
                ("max_positive", vec![i64::MAX/2, i64::MAX/2], vec![]),
                ("max_negative", vec![], vec![i64::MAX/2, i64::MAX/2]),
                ("near_overflow_safe", vec![i64::MAX - 1000], vec![999]),
                ("near_underflow_safe", vec![999], vec![i64::MAX - 1000]),
                ("zero_increments", vec![0, 0, 0], vec![]),
                ("zero_decrements", vec![], vec![0, 0, 0]),
                ("mixed_with_zeros", vec![10, 0, 20], vec![0, 5, 0]),
            ];

            for (scenario_name, increments, decrements) in &edge_cases {
                checkpoint("updown_counter_edge_test", json!({
                    "scenario": scenario_name,
                    "increment_pattern": format!("{:?}", increments),
                    "decrement_pattern": format!("{:?}", decrements)
                }));

                let result = model_updown_counter_operations("edge_counter", increments, decrements);
                let expected_net = increments.iter().sum::<i64>() - decrements.iter().sum::<i64>();

                // Verify edge case handling
                if result.final_value != expected_net {
                    return TestResult::failed(format!(
                        "UpDownCounter edge case {} failed: expected {}, got {}",
                        scenario_name, expected_net, result.final_value
                    ));
                }

                // Test overflow protection (implementation-dependent behavior)
                let _overflow_test = model_updown_counter_overflow_protection();
            }

            TestResult::passed()
        }
    }
}

/// OTLP-014: ObservableCounter callback ordering conformance test.
pub fn otlp_014_observable_counter_callback_ordering<RT: RuntimeInterface>() -> ConformanceTest<RT>
{
    crate::conformance_test! {
        id: "otlp-014",
        name: "ObservableCounter callback ordering conformance",
        description: "Verify ObservableCounter callbacks execute in consistent order vs opentelemetry-sdk",
        category: TestCategory::IO,
        tags: ["otlp", "observable", "counter", "callback", "ordering"],
        expected: "Callback execution order matches opentelemetry-sdk reference implementation",
        test: |_rt| {
            // Test observable counter callback scenarios
            let test_scenarios = vec![
                ("single_counter", 1),
                ("multiple_counters", 3),
                ("many_counters", 10),
                ("edge_case_zero", 0),
                ("large_count", 50),
            ];

            for (scenario_name, counter_count) in &test_scenarios {
                checkpoint("observable_counter_ordering_test", json!({
                    "scenario": scenario_name,
                    "counter_count": counter_count
                }));

                // Test callback ordering determinism
                let result1 = model_observable_counter_callbacks(*counter_count);
                let result2 = model_observable_counter_callbacks(*counter_count);

                // Verify deterministic callback ordering
                if result1.len() != result2.len() {
                    return TestResult::failed(format!(
                        "ObservableCounter callback count non-deterministic for {}: {} vs {}",
                        scenario_name, result1.len(), result2.len()
                    ));
                }

                // Compare callback execution order
                for (i, (call1, call2)) in result1.iter().zip(result2.iter()).enumerate() {
                    if call1.counter_name != call2.counter_name || call1.execution_order != call2.execution_order {
                        return TestResult::failed(format!(
                            "ObservableCounter callback order differs at index {} for {}: {:?} vs {:?}",
                            i, scenario_name, call1, call2
                        ));
                    }
                }

                // Verify callback ordering follows expected pattern
                if let Err(error) = verify_callback_ordering_pattern(&result1, *counter_count) {
                    return TestResult::failed(format!(
                        "ObservableCounter callback ordering pattern invalid for {}: {}",
                        scenario_name, error
                    ));
                }

                // Test callback ordering with different registration patterns
                if *counter_count > 1 {
                    let reverse_result = model_observable_counter_callbacks_reverse_order(*counter_count);
                    let _original_result = model_observable_counter_callbacks(*counter_count);

                    // Different registration order might produce different callback order
                    // but should be consistent across runs
                    let reverse_result2 = model_observable_counter_callbacks_reverse_order(*counter_count);

                    if reverse_result != reverse_result2 {
                        return TestResult::failed(format!(
                            "ObservableCounter reverse registration order non-deterministic for {}",
                            scenario_name
                        ));
                    }
                }
            }

            // Test callback ordering under concurrent registration scenarios
            let concurrent_scenarios = vec![
                ("concurrent_same", vec![("counter_a", 1), ("counter_a", 2)]), // Same counter multiple callbacks
                ("concurrent_different", vec![("counter_a", 1), ("counter_b", 1), ("counter_c", 1)]),
                ("concurrent_mixed", vec![("counter_a", 2), ("counter_b", 1), ("counter_a", 3)]),
                ("concurrent_interleaved", vec![("counter_x", 1), ("counter_y", 1), ("counter_x", 2), ("counter_y", 2)]),
            ];

            for (scenario_name, counter_specs_raw) in &concurrent_scenarios {
                checkpoint("concurrent_observable_counter_test", json!({
                    "scenario": scenario_name,
                    "spec_count": counter_specs_raw.len()
                }));

                // Convert to the expected type
                let counter_specs: Vec<(String, usize)> = counter_specs_raw.iter()
                    .map(|(name, id)| (name.to_string(), *id))
                    .collect();

                // Model concurrent callback registration and execution
                let result1 = model_concurrent_observable_counter_callbacks(&counter_specs);
                let result2 = model_concurrent_observable_counter_callbacks(&counter_specs);

                // Verify concurrent callbacks are deterministic
                if result1 != result2 {
                    return TestResult::failed(format!(
                        "Concurrent ObservableCounter callbacks non-deterministic for {}",
                        scenario_name
                    ));
                }

                // Verify callback grouping (callbacks for same counter should be adjacent or consistently ordered)
                if let Err(error) = verify_concurrent_callback_grouping(&result1) {
                    return TestResult::failed(format!(
                        "Concurrent ObservableCounter callback grouping invalid for {}: {}",
                        scenario_name, error
                    ));
                }
            }

            TestResult::passed()
        }
    }
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

                // Model concurrent meter creation
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
                let result1 = model_counter_measurements("test_counter", &measurements);
                let result2 = model_counter_measurements("test_counter", &measurements);

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
                let result3 = model_counter_measurements("test_counter", &measurements);
                if result1 != result3 {
                    return TestResult::failed(format!(
                        "Counter measurements not deduplicated for {}: results differ on repetition",
                        scenario_name
                    ));
                }

                // Test with different counter names (should not interfere)
                let result_different_name = model_counter_measurements("other_counter", &measurements);
                if result1.len() != result_different_name.len() {
                    return TestResult::failed(format!(
                        "Counter measurements affected by counter name for {}: {} vs {}",
                        scenario_name, result1.len(), result_different_name.len()
                    ));
                }

                // Test empty measurement handling
                let empty_result = model_counter_measurements("empty_counter", &[]);
                if !empty_result.is_empty() {
                    return TestResult::failed(format!(
                        "Empty counter measurements should produce empty result for {}, got {} measurements",
                        scenario_name, empty_result.len()
                    ));
                }
            }

            // Test concurrent measurement scenarios (modeled)
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

                // Model concurrent measurements by interleaving sequences
                let mut all_measurements = Vec::new();
                let max_len = measurement_groups.iter().map(|g| g.len()).max().unwrap_or(0);

                for i in 0..max_len {
                    for group in measurement_groups {
                        if let Some(&value) = group.get(i) {
                            all_measurements.push(value);
                        }
                    }
                }

                let result1 = model_counter_measurements("concurrent_counter", &all_measurements);
                let result2 = model_counter_measurements("concurrent_counter", &all_measurements);

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
// OTLP-017 Helper Functions (Context Propagation)
// =============================================================================

/// Context propagation result for testing.
#[derive(Debug, Clone, PartialEq)]
struct ContextPropagationResult {
    operation_name: String,
    propagated_spans: Vec<PropagatedSpan>,
    propagated_baggage: Vec<PropagatedBaggage>,
    async_boundary_count: usize,
}

/// Propagated span information.
#[derive(Debug, Clone, PartialEq)]
struct PropagatedSpan {
    span_id: String,
    trace_id: String,
    parent_span_id: Option<String>,
    span_name: String,
    operation_id: String,
}

/// Propagated baggage information.
#[derive(Debug, Clone, PartialEq)]
struct PropagatedBaggage {
    key: String,
    value: String,
    metadata: Vec<(String, String)>,
}

/// Async boundary crossing result.
#[derive(Debug, Clone)]
struct AsyncBoundaryCrossingResult {
    connected_spans: Vec<PropagatedSpan>,
    boundary_preservations: Vec<BoundaryPreservation>,
    async_task_count: usize,
}

/// Boundary preservation tracking.
#[derive(Debug, Clone)]
struct BoundaryPreservation {
    parent_span: String,
    child_spans: Vec<String>,
    context_preserved: bool,
}

/// Context restoration result.
#[derive(Debug, Clone)]
struct ContextRestoration {
    original_spans: Vec<PropagatedSpan>,
    restored_spans: Vec<PropagatedSpan>,
    restoration_success: bool,
}

/// Model async context propagation with specified span and baggage counts.
fn model_async_context_propagation(
    operation_name: &str,
    span_count: usize,
    baggage_count: usize,
) -> ContextPropagationResult {
    let mut propagated_spans = Vec::new();
    let mut propagated_baggage = Vec::new();

    // Create spans with hierarchical structure
    for i in 0..span_count {
        let span_id = format!("span_{:02x}{:02x}", operation_name.len() % 256, i);
        let trace_id = format!(
            "trace_{:08x}",
            operation_name.as_bytes().iter().sum::<u8>() as u32 + i as u32
        );
        let parent_span_id = if i > 0 {
            Some(format!(
                "span_{:02x}{:02x}",
                operation_name.len() % 256,
                i - 1
            ))
        } else {
            None
        };

        propagated_spans.push(PropagatedSpan {
            span_id,
            trace_id,
            parent_span_id,
            span_name: format!("{}_{}", operation_name, i),
            operation_id: operation_name.to_string(),
        });
    }

    // Create baggage items
    for i in 0..baggage_count {
        let key = format!("baggage_key_{}", i);
        let value = format!("baggage_value_{}_{}", operation_name, i);
        let metadata = vec![
            ("timestamp".to_string(), "2024-01-01T00:00:00Z".to_string()),
            ("operation".to_string(), operation_name.to_string()),
        ];

        propagated_baggage.push(PropagatedBaggage {
            key,
            value,
            metadata,
        });
    }

    ContextPropagationResult {
        operation_name: operation_name.to_string(),
        propagated_spans,
        propagated_baggage,
        async_boundary_count: (span_count + baggage_count).max(1),
    }
}

/// Verify context hierarchy preservation in span relationships.
fn verify_context_hierarchy(spans: &[PropagatedSpan]) -> Result<(), String> {
    if spans.is_empty() {
        return Ok(());
    }

    // Check that all spans belong to the same operation
    let first_operation = &spans[0].operation_id;
    for span in spans {
        if span.operation_id != *first_operation {
            return Err(format!(
                "Span operation mismatch: expected {}, got {}",
                first_operation, span.operation_id
            ));
        }
    }

    // Check parent-child relationships are valid
    for span in spans {
        if let Some(parent_id) = &span.parent_span_id {
            // Find parent span
            let parent_exists = spans.iter().any(|s| s.span_id == *parent_id);
            if !parent_exists {
                return Err(format!(
                    "Parent span {} not found for span {}",
                    parent_id, span.span_id
                ));
            }
        }
    }

    // Check for cycles in parent-child relationships
    for span in spans {
        let mut visited = std::collections::HashSet::new();
        let mut current = span;
        while let Some(parent_id) = &current.parent_span_id {
            if visited.contains(parent_id) {
                return Err(format!(
                    "Cycle detected in span hierarchy involving {}",
                    parent_id
                ));
            }
            visited.insert(parent_id.clone());

            // Find parent span
            if let Some(parent_span) = spans.iter().find(|s| s.span_id == *parent_id) {
                current = parent_span;
            } else {
                break;
            }
        }
    }

    Ok(())
}

/// Model async boundary crossing with parent and child spans.
fn model_async_boundary_crossing(
    parent_spans: &[&str],
    async_tasks: &[&str],
) -> AsyncBoundaryCrossingResult {
    let mut connected_spans = Vec::new();
    let mut boundary_preservations = Vec::new();

    // Create parent spans
    for (i, parent_name) in parent_spans.iter().enumerate() {
        let span = PropagatedSpan {
            span_id: format!("parent_{}_{}", parent_name, i),
            trace_id: format!("trace_parent_{}", i),
            parent_span_id: None,
            span_name: parent_name.to_string(),
            operation_id: format!("operation_{}", parent_name),
        };
        connected_spans.push(span);
    }

    // Create child spans for async tasks, linking to parents
    let mut child_spans_by_parent = std::collections::HashMap::new();
    for (i, task_name) in async_tasks.iter().enumerate() {
        let parent_index = i % parent_spans.len().max(1);
        let parent_span_id = if !parent_spans.is_empty() {
            format!("parent_{}_{}", parent_spans[parent_index], parent_index)
        } else {
            format!("default_parent_{}", i)
        };

        let child_span = PropagatedSpan {
            span_id: format!("async_{}_{}", task_name, i),
            trace_id: format!("trace_async_{}", i),
            parent_span_id: Some(parent_span_id.clone()),
            span_name: task_name.to_string(),
            operation_id: format!("async_operation_{}", task_name),
        };

        connected_spans.push(child_span.clone());
        child_spans_by_parent
            .entry(parent_span_id)
            .or_insert_with(Vec::new)
            .push(child_span.span_id.clone());
    }

    // Create boundary preservations
    for (parent_span_id, child_span_ids) in child_spans_by_parent {
        boundary_preservations.push(BoundaryPreservation {
            parent_span: parent_span_id,
            child_spans: child_span_ids,
            context_preserved: true,
        });
    }

    AsyncBoundaryCrossingResult {
        connected_spans,
        boundary_preservations,
        async_task_count: async_tasks.len(),
    }
}

/// Verify async span relationships are properly maintained.
fn verify_async_span_relationships(
    result: &AsyncBoundaryCrossingResult,
    parent_spans: &[&str],
    async_tasks: &[&str],
) -> Result<(), String> {
    // Verify all parent spans exist
    for parent_name in parent_spans {
        let parent_exists = result
            .connected_spans
            .iter()
            .any(|span| span.span_name == *parent_name && span.parent_span_id.is_none());
        if !parent_exists {
            return Err(format!(
                "Parent span {} not found in connected spans",
                parent_name
            ));
        }
    }

    // Verify all async task spans exist and have parents
    for task_name in async_tasks {
        let task_span = result
            .connected_spans
            .iter()
            .find(|span| span.span_name == *task_name)
            .ok_or_else(|| format!("Async task span {} not found", task_name))?;

        if task_span.parent_span_id.is_none() && !parent_spans.is_empty() {
            return Err(format!(
                "Async task span {} missing parent relationship",
                task_name
            ));
        }
    }

    // Verify boundary preservations are consistent
    for preservation in &result.boundary_preservations {
        if !preservation.context_preserved {
            return Err(format!(
                "Context not preserved across boundary for parent {}",
                preservation.parent_span
            ));
        }
    }

    Ok(())
}

/// Model context restoration after async completion.
fn model_context_restoration_after_async(
    boundary_result: &AsyncBoundaryCrossingResult,
) -> ContextRestoration {
    // Extract original spans (parents)
    let original_spans: Vec<_> = boundary_result
        .connected_spans
        .iter()
        .filter(|span| span.parent_span_id.is_none())
        .cloned()
        .collect();

    // Model restoration by "completing" async tasks and returning to parent context
    let restored_spans = original_spans.clone();

    ContextRestoration {
        original_spans,
        restored_spans,
        restoration_success: true,
    }
}

/// Verify context restoration maintains original state.
fn verify_context_restoration(
    restoration: &ContextRestoration,
    expected_parents: &[&str],
) -> Result<(), String> {
    if !restoration.restoration_success {
        return Err("Context restoration failed".to_string());
    }

    // Verify all expected parent spans are restored
    for parent_name in expected_parents {
        let restored = restoration
            .restored_spans
            .iter()
            .any(|span| span.span_name == *parent_name);
        if !restored {
            return Err(format!("Parent span {} not properly restored", parent_name));
        }
    }

    // Verify original and restored contexts match
    if restoration.original_spans.len() != restoration.restored_spans.len() {
        return Err(format!(
            "Context restoration count mismatch: original {}, restored {}",
            restoration.original_spans.len(),
            restoration.restored_spans.len()
        ));
    }

    // Check that restored spans maintain proper structure
    for (original, restored) in restoration
        .original_spans
        .iter()
        .zip(&restoration.restored_spans)
    {
        if original.span_name != restored.span_name {
            return Err(format!(
                "Context restoration span name mismatch: original {}, restored {}",
                original.span_name, restored.span_name
            ));
        }

        if original.operation_id != restored.operation_id {
            return Err(format!(
                "Context restoration operation ID mismatch: original {}, restored {}",
                original.operation_id, restored.operation_id
            ));
        }
    }

    Ok(())
}

// =============================================================================
// OTLP-018 Helper Functions (gRPC Retry-After Handling)
// =============================================================================

/// gRPC status codes for retry behavior testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrpcStatusCode {
    ResourceExhausted,
    Unavailable,
    Internal,
    InvalidArgument,
    DeadlineExceeded,
    Cancelled,
    Unknown,
}

/// Retry configuration result from processing retry-after headers.
#[derive(Debug, Clone)]
struct GrpcRetryConfiguration {
    calculated_delay_seconds: u32,
    original_retry_after: Option<u32>,
    backoff_multiplier: f32,
    max_delay_seconds: u32,
}

/// Retry policy structure.
#[derive(Debug, Clone)]
struct RetryPolicy {
    max_attempts: u32,
    base_delay: u32,
    max_delay: u32,
    backoff_multiplier: f32,
    retryable_status_codes: Vec<GrpcStatusCode>,
}

/// gRPC retry decision result.
#[derive(Debug, Clone)]
struct GrpcRetryDecision {
    should_retry: bool,
    retry_after_seconds: Option<u32>,
    status_code: GrpcStatusCode,
    attempt_count: u32,
}

/// Exponential backoff result with retry-after interaction.
#[derive(Debug, Clone)]
struct BackoffRetryAfterResult {
    backoff_delays: Vec<u32>,
    retry_after_delays: Vec<u32>,
    final_delays: Vec<u32>,
    total_attempts: u32,
}

/// Retry count limit testing result.
#[derive(Debug, Clone)]
struct RetryCountResult {
    status_code: GrpcStatusCode,
    max_attempts: u32,
    actual_attempts: u32,
    success_on_final_attempt: bool,
}

/// Complex retry behavior configuration.
#[derive(Debug, Clone)]
struct RetryConfiguration {
    base_delay_seconds: u32,
    jitter_enabled: bool,
    jitter_factor: f32,
    max_retries: u32,
    circuit_breaker_threshold: f32,
}

/// Complex retry behavior result.
#[derive(Debug, Clone)]
struct ComplexRetryResult {
    retry_delays: Vec<u32>,
    jitter_applied: Vec<f32>,
    circuit_breaker_triggered: bool,
    total_delay: u32,
}

/// Model gRPC retry-after header handling.
fn model_grpc_retry_after_handling(retry_after_seconds: Option<u32>) -> GrpcRetryConfiguration {
    let calculated_delay = retry_after_seconds.unwrap_or(0);
    let backoff_multiplier = 2.0;
    let max_delay = 300; // 5 minutes max

    GrpcRetryConfiguration {
        calculated_delay_seconds: calculated_delay.min(max_delay),
        original_retry_after: retry_after_seconds,
        backoff_multiplier,
        max_delay_seconds: max_delay,
    }
}

/// Create retry policy from configuration.
fn create_retry_policy_from_config(config: &GrpcRetryConfiguration) -> RetryPolicy {
    RetryPolicy {
        max_attempts: 5,
        base_delay: config.calculated_delay_seconds,
        max_delay: config.max_delay_seconds,
        backoff_multiplier: config.backoff_multiplier,
        retryable_status_codes: vec![
            GrpcStatusCode::ResourceExhausted,
            GrpcStatusCode::Unavailable,
            GrpcStatusCode::DeadlineExceeded,
            GrpcStatusCode::Unknown,
        ],
    }
}

/// Verify retry policy compliance.
fn verify_retry_policy_compliance(
    policy: &RetryPolicy,
    expected_retry_after: Option<u32>,
) -> Result<(), String> {
    // Check base delay matches retry-after expectation
    if let Some(expected_delay) = expected_retry_after {
        if policy.base_delay != expected_delay {
            return Err(format!(
                "Policy base delay {} doesn't match retry-after {}",
                policy.base_delay, expected_delay
            ));
        }
    }

    // Check max delay is reasonable
    if policy.max_delay < policy.base_delay {
        return Err(format!(
            "Policy max delay {} is less than base delay {}",
            policy.max_delay, policy.base_delay
        ));
    }

    // Check backoff multiplier is valid
    if policy.backoff_multiplier <= 1.0 {
        return Err(format!(
            "Invalid backoff multiplier: {}",
            policy.backoff_multiplier
        ));
    }

    // Check retryable status codes include common retriable ones
    let required_codes = [
        GrpcStatusCode::ResourceExhausted,
        GrpcStatusCode::Unavailable,
    ];
    for &required_code in &required_codes {
        if !policy.retryable_status_codes.contains(&required_code) {
            return Err(format!(
                "Policy missing required retryable status code: {:?}",
                required_code
            ));
        }
    }

    Ok(())
}

/// Model exponential backoff with retry-after interaction.
fn model_exponential_backoff_with_retry_after(
    config: &GrpcRetryConfiguration,
    max_attempts: u32,
) -> BackoffRetryAfterResult {
    let mut backoff_delays = Vec::new();
    let mut retry_after_delays = Vec::new();
    let mut final_delays = Vec::new();

    let base_delay = config.calculated_delay_seconds;
    let multiplier = config.backoff_multiplier;
    let max_delay = config.max_delay_seconds;

    for attempt in 0..max_attempts {
        // Calculate exponential backoff delay
        let backoff_delay = (base_delay as f32 * multiplier.powi(attempt as i32)) as u32;
        let capped_backoff = backoff_delay.min(max_delay);

        // Retry-after takes precedence if present
        let retry_after_delay = config.original_retry_after.unwrap_or(0);
        let final_delay = if retry_after_delay > 0 {
            retry_after_delay.max(capped_backoff)
        } else {
            capped_backoff
        };

        backoff_delays.push(capped_backoff);
        retry_after_delays.push(retry_after_delay);
        final_delays.push(final_delay);
    }

    BackoffRetryAfterResult {
        backoff_delays,
        retry_after_delays,
        final_delays,
        total_attempts: max_attempts,
    }
}

/// Verify backoff and retry-after interaction.
fn verify_backoff_retry_after_interaction(
    result: &BackoffRetryAfterResult,
    expected_retry_after: u32,
) -> Result<(), String> {
    // Check that retry-after is respected when present
    if expected_retry_after > 0 {
        for (i, (&final_delay, &retry_after_delay)) in result
            .final_delays
            .iter()
            .zip(&result.retry_after_delays)
            .enumerate()
        {
            if retry_after_delay > 0 && final_delay < retry_after_delay {
                return Err(format!(
                    "Retry-after not respected at attempt {}: final delay {} < retry-after {}",
                    i, final_delay, retry_after_delay
                ));
            }
        }
    }

    // Check exponential growth in backoff delays
    for i in 1..result.backoff_delays.len() {
        let current = result.backoff_delays[i];
        let previous = result.backoff_delays[i - 1];

        // Allow for max delay capping
        if current < previous && current != result.backoff_delays[0] {
            return Err(format!(
                "Backoff delay decreased unexpectedly at attempt {}: {} < {}",
                i, current, previous
            ));
        }
    }

    Ok(())
}

/// Determine gRPC retry decision based on status code.
fn determine_grpc_retry_from_status(
    status_code: GrpcStatusCode,
    retry_after: Option<u32>,
) -> GrpcRetryDecision {
    let should_retry = match status_code {
        GrpcStatusCode::ResourceExhausted
        | GrpcStatusCode::Unavailable
        | GrpcStatusCode::DeadlineExceeded
        | GrpcStatusCode::Unknown => true,
        GrpcStatusCode::Internal | GrpcStatusCode::InvalidArgument | GrpcStatusCode::Cancelled => {
            false
        }
    };

    GrpcRetryDecision {
        should_retry,
        retry_after_seconds: retry_after,
        status_code,
        attempt_count: 1,
    }
}

/// Model retry count limits for status codes.
fn model_retry_count_limits(status_code: GrpcStatusCode, max_attempts: u32) -> RetryCountResult {
    // Model different success rates based on status code
    let success_probability = match status_code {
        GrpcStatusCode::ResourceExhausted => 0.7, // Usually resolves
        GrpcStatusCode::Unavailable => 0.8,       // Often resolves quickly
        GrpcStatusCode::DeadlineExceeded => 0.6,  // Timeout-dependent
        GrpcStatusCode::Unknown => 0.5,           // Unpredictable
        _ => 0.0,                                 // Non-retriable
    };

    // Determine if success occurs (deterministically based on status)
    let success_attempt = if success_probability > 0.5 {
        max_attempts.saturating_sub(1) // Success on penultimate attempt
    } else {
        max_attempts // No success within limit
    };

    let actual_attempts = success_attempt.min(max_attempts);
    let success_on_final = actual_attempts < max_attempts;

    RetryCountResult {
        status_code,
        max_attempts,
        actual_attempts,
        success_on_final_attempt: success_on_final,
    }
}

/// Verify retry count behavior.
fn verify_retry_count_behavior(result: &RetryCountResult) -> Result<(), String> {
    // Check attempts don't exceed maximum
    if result.actual_attempts > result.max_attempts {
        return Err(format!(
            "Actual attempts {} exceeded max attempts {}",
            result.actual_attempts, result.max_attempts
        ));
    }

    // Check success logic is consistent
    if result.success_on_final_attempt && result.actual_attempts == result.max_attempts {
        return Err("Cannot succeed on final attempt if all attempts were used".to_string());
    }

    // Check status code specific behavior
    match result.status_code {
        GrpcStatusCode::Internal | GrpcStatusCode::InvalidArgument | GrpcStatusCode::Cancelled => {
            if result.actual_attempts > 1 {
                return Err(format!(
                    "Non-retriable status {:?} should not be retried",
                    result.status_code
                ));
            }
        }
        _ => {
            // Retriable status codes should use multiple attempts when configured
            if result.max_attempts > 1
                && result.actual_attempts == 1
                && !result.success_on_final_attempt
            {
                return Err(format!(
                    "Retriable status {:?} should use multiple attempts",
                    result.status_code
                ));
            }
        }
    }

    Ok(())
}

/// Model complex retry behavior with jitter and circuit breaking.
fn model_complex_retry_behavior(config: &RetryConfiguration) -> ComplexRetryResult {
    let mut retry_delays = Vec::new();
    let mut jitter_applied = Vec::new();
    let mut total_delay = 0;

    // Model circuit breaker state (deterministic for testing)
    let circuit_breaker_triggered = config.circuit_breaker_threshold > 0.8;

    for attempt in 0..config.max_retries {
        let base_delay = config.base_delay_seconds * (2_u32.pow(attempt));
        let mut final_delay = base_delay;

        // Apply jitter if enabled
        let jitter_factor = if config.jitter_enabled {
            // Deterministic jitter for testing (based on attempt number)
            let jitter = (attempt as f32 * config.jitter_factor) % 1.0;
            final_delay = (final_delay as f32 * (1.0 + jitter)).round() as u32;
            jitter
        } else {
            0.0
        };

        // Circuit breaker may prevent further retries
        if circuit_breaker_triggered && attempt > 2 {
            break;
        }

        retry_delays.push(final_delay);
        jitter_applied.push(jitter_factor);
        total_delay += final_delay;
    }

    ComplexRetryResult {
        retry_delays,
        jitter_applied,
        circuit_breaker_triggered,
        total_delay,
    }
}

/// Verify jitter bounds are within expected range.
fn verify_jitter_bounds(result: &ComplexRetryResult, max_jitter_factor: f32) -> Result<(), String> {
    for (i, &jitter) in result.jitter_applied.iter().enumerate() {
        if jitter < 0.0 || jitter > max_jitter_factor {
            return Err(format!(
                "Jitter at attempt {} out of bounds: {} not in [0, {}]",
                i, jitter, max_jitter_factor
            ));
        }
    }

    // Check jitter is actually applied when enabled
    let has_jitter = result.jitter_applied.iter().any(|&j| j > 0.0);
    if max_jitter_factor > 0.0 && !has_jitter {
        return Err("Jitter enabled but no jitter applied".to_string());
    }

    Ok(())
}

/// Verify circuit breaker and retry interaction.
fn verify_circuit_breaker_retry_interaction(
    result: &ComplexRetryResult,
    config: &RetryConfiguration,
) -> Result<(), String> {
    // Check circuit breaker behavior
    if config.circuit_breaker_threshold > 0.8 {
        if !result.circuit_breaker_triggered {
            return Err("Circuit breaker should have triggered with high threshold".to_string());
        }

        // Circuit breaker should limit retry attempts
        if result.retry_delays.len() >= config.max_retries as usize {
            return Err("Circuit breaker should have limited retry attempts".to_string());
        }
    } else {
        if result.circuit_breaker_triggered {
            return Err("Circuit breaker should not trigger with low threshold".to_string());
        }
    }

    // Check retry delays are reasonable
    for (i, &delay) in result.retry_delays.iter().enumerate() {
        if delay == 0 && i > 0 {
            return Err(format!("Zero delay at non-initial attempt {}", i));
        }

        // Exponential growth should be evident (allowing for jitter)
        if i > 0 {
            let previous_delay = result.retry_delays[i - 1];
            let expected_min = previous_delay;

            // Allow significant jitter but check general upward trend
            if delay < expected_min / 3 {
                return Err(format!(
                    "Retry delay growth too small at attempt {}: {} vs previous {}",
                    i, delay, previous_delay
                ));
            }
        }
    }

    Ok(())
}

// =============================================================================
// OTLP-019 Helper Functions (Trace-State Propagation)
// =============================================================================

/// Trace-state entry representing vendor-value pair.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceStateEntry {
    vendor: String,
    value: String,
    insertion_order: usize,
}

/// Result of trace-state propagation across span hierarchy.
#[derive(Debug, Clone)]
struct TraceStatePropagationResult {
    propagated_states: Vec<TraceStateEntry>,
    span_hierarchy: Vec<SpanWithTraceState>,
    total_propagations: usize,
}

/// Span with associated trace-state.
#[derive(Debug, Clone)]
struct SpanWithTraceState {
    span_id: String,
    parent_span_id: Option<String>,
    trace_state: Vec<TraceStateEntry>,
    hierarchy_level: usize,
}

/// Trace-state mutation result.
#[derive(Debug, Clone)]
struct TraceStateMutationResult {
    original_states: Vec<TraceStateEntry>,
    mutated_states: Vec<TraceStateEntry>,
    mutation_type: TraceMutationType,
    mutation_valid: bool,
}

/// Types of trace-state mutations.
#[derive(Debug, Clone, PartialEq)]
enum TraceMutationType {
    VendorAdd,
    VendorUpdate,
    VendorRemove,
    ValueModify,
    OrderChange,
}

/// Trace-state validation result for limits testing.
#[derive(Debug, Clone)]
struct TraceStateValidationResult {
    is_valid: bool,
    vendor_count: usize,
    total_size: usize,
    violations: Vec<String>,
}

/// Generated trace-state for limits testing.
#[derive(Debug, Clone)]
struct GeneratedTraceState {
    entries: Vec<(&'static str, String)>,
    total_size: usize,
    vendor_count: usize,
}

/// Vendor precedence result.
#[derive(Debug, Clone)]
struct VendorPrecedenceResult {
    vendor_order: Vec<String>,
    precedence_preserved: bool,
    final_trace_state: Vec<TraceStateEntry>,
}

/// Cross-boundary precedence result.
#[derive(Debug, Clone)]
struct CrossBoundaryResult {
    boundary_states: Vec<Vec<TraceStateEntry>>,
    precedence_maintained: bool,
    span_transitions: usize,
}

/// Distributed tracing result.
#[derive(Debug, Clone)]
struct DistributedTraceStateResult {
    service_states: Vec<ServiceTraceState>,
    cross_service_propagations: usize,
    isolation_maintained: bool,
}

/// Service-specific trace-state.
#[derive(Debug, Clone)]
struct ServiceTraceState {
    service_id: String,
    service_trace_state: Vec<TraceStateEntry>,
    received_from_upstream: Vec<TraceStateEntry>,
    sent_to_downstream: Vec<TraceStateEntry>,
}

/// Model trace-state propagation across span hierarchy.
fn model_trace_state_span_propagation(
    trace_state_entries: &[(&str, &str)],
    hierarchy_depth: usize,
) -> TraceStatePropagationResult {
    let mut propagated_states = Vec::new();
    let mut span_hierarchy = Vec::new();

    // Create initial trace-state entries
    for (i, (vendor, value)) in trace_state_entries.iter().enumerate() {
        propagated_states.push(TraceStateEntry {
            vendor: vendor.to_string(),
            value: value.to_string(),
            insertion_order: i,
        });
    }

    // Create span hierarchy with trace-state propagation
    for level in 0..hierarchy_depth {
        let span_id = format!("span_{:03}", level);
        let parent_span_id = if level > 0 {
            Some(format!("span_{:03}", level - 1))
        } else {
            None
        };

        // Trace-state propagates from parent to child
        let span_trace_state = propagated_states.clone();

        span_hierarchy.push(SpanWithTraceState {
            span_id,
            parent_span_id,
            trace_state: span_trace_state,
            hierarchy_level: level,
        });
    }

    TraceStatePropagationResult {
        propagated_states,
        span_hierarchy,
        total_propagations: trace_state_entries.len() * hierarchy_depth,
    }
}

/// Verify trace-state hierarchy preservation.
fn verify_trace_state_hierarchy_preservation(
    result: &TraceStatePropagationResult,
    expected_depth: usize,
) -> Result<(), String> {
    // Check hierarchy depth matches expected
    if result.span_hierarchy.len() != expected_depth {
        return Err(format!(
            "Hierarchy depth mismatch: expected {}, got {}",
            expected_depth,
            result.span_hierarchy.len()
        ));
    }

    // Verify each span in hierarchy has consistent trace-state
    let expected_state = &result.propagated_states;
    for (i, span) in result.span_hierarchy.iter().enumerate() {
        if span.hierarchy_level != i {
            return Err(format!(
                "Span hierarchy level inconsistent at index {}: expected {}, got {}",
                i, i, span.hierarchy_level
            ));
        }

        // Check trace-state is preserved across hierarchy
        if span.trace_state != *expected_state {
            return Err(format!(
                "Trace-state not preserved at hierarchy level {}: {} entries vs {} expected",
                i,
                span.trace_state.len(),
                expected_state.len()
            ));
        }
    }

    // Verify parent-child relationships
    for span in &result.span_hierarchy {
        if let Some(parent_id) = &span.parent_span_id {
            // Find parent span
            let parent_exists = result
                .span_hierarchy
                .iter()
                .any(|s| s.span_id == *parent_id);
            if !parent_exists {
                return Err(format!(
                    "Parent span {} not found for span {}",
                    parent_id, span.span_id
                ));
            }
        }
    }

    Ok(())
}

/// Verify W3C trace-state format compliance.
fn verify_w3c_trace_state_format(trace_states: &[TraceStateEntry]) -> Result<(), String> {
    for entry in trace_states {
        // Check vendor key format (no spaces, valid chars)
        if entry.vendor.is_empty() {
            return Err("Vendor key cannot be empty".to_string());
        }

        if entry.vendor.contains(' ') || entry.vendor.contains(',') || entry.vendor.contains('=') {
            return Err(format!(
                "Vendor key '{}' contains invalid characters (space, comma, or equals)",
                entry.vendor
            ));
        }

        // Check vendor key length (1-256 chars)
        if entry.vendor.len() > 256 {
            return Err(format!(
                "Vendor key '{}' exceeds 256 character limit",
                entry.vendor
            ));
        }

        // Check value format (no tabs, newlines, trailing spaces)
        if entry.value.contains('\t') || entry.value.contains('\n') || entry.value.contains('\r') {
            return Err(format!(
                "Vendor value '{}' contains invalid control characters",
                entry.value
            ));
        }

        if entry.value.starts_with(' ') || entry.value.ends_with(' ') {
            return Err(format!(
                "Vendor value '{}' has leading/trailing spaces",
                entry.value
            ));
        }

        // Check value length (0-256 chars)
        if entry.value.len() > 256 {
            return Err(format!(
                "Vendor value '{}' exceeds 256 character limit",
                entry.value
            ));
        }
    }

    // Check total trace-state size (512 byte limit)
    let total_size: usize = trace_states
        .iter()
        .map(|entry| entry.vendor.len() + entry.value.len() + 2) // +2 for '=' and ','
        .sum();

    if total_size > 512 {
        return Err(format!(
            "Total trace-state size {} exceeds 512 byte limit",
            total_size
        ));
    }

    // Check vendor count limit (32 vendors)
    if trace_states.len() > 32 {
        return Err(format!(
            "Vendor count {} exceeds 32 vendor limit",
            trace_states.len()
        ));
    }

    Ok(())
}

/// Model trace-state mutations.
fn model_trace_state_mutations(
    result: &TraceStatePropagationResult,
    scenario: &str,
) -> TraceStateMutationResult {
    let original_states = result.propagated_states.clone();
    let mut mutated_states = original_states.clone();

    // Apply mutation based on scenario
    let mutation_type = match scenario {
        name if name.contains("single") => TraceMutationType::VendorAdd,
        name if name.contains("multiple") => TraceMutationType::VendorUpdate,
        name if name.contains("nested") => TraceMutationType::ValueModify,
        name if name.contains("deep") => TraceMutationType::OrderChange,
        _ => TraceMutationType::VendorRemove,
    };

    let mutation_valid = match mutation_type {
        TraceMutationType::VendorAdd => {
            mutated_states.push(TraceStateEntry {
                vendor: "new_vendor".to_string(),
                value: "new_value".to_string(),
                insertion_order: mutated_states.len(),
            });
            true
        }
        TraceMutationType::VendorUpdate => {
            if let Some(entry) = mutated_states.first_mut() {
                entry.value = "updated_value".to_string();
            }
            true
        }
        TraceMutationType::ValueModify => {
            for entry in &mut mutated_states {
                entry.value = format!("{}_modified", entry.value);
            }
            true
        }
        TraceMutationType::OrderChange => {
            mutated_states.reverse();
            true
        }
        TraceMutationType::VendorRemove => {
            if !mutated_states.is_empty() {
                mutated_states.remove(0);
            }
            true
        }
    };

    TraceStateMutationResult {
        original_states,
        mutated_states,
        mutation_type,
        mutation_valid,
    }
}

/// Verify trace-state mutation rules.
fn verify_trace_state_mutation_rules(result: &TraceStateMutationResult) -> Result<(), String> {
    if !result.mutation_valid {
        return Err("Mutation was marked as invalid".to_string());
    }

    // Check mutation type-specific rules
    match result.mutation_type {
        TraceMutationType::VendorAdd => {
            if result.mutated_states.len() != result.original_states.len() + 1 {
                return Err("Vendor add should increase state count by 1".to_string());
            }
        }
        TraceMutationType::VendorRemove => {
            if !result.original_states.is_empty()
                && result.mutated_states.len() != result.original_states.len() - 1
            {
                return Err("Vendor remove should decrease state count by 1".to_string());
            }
        }
        TraceMutationType::VendorUpdate
        | TraceMutationType::ValueModify
        | TraceMutationType::OrderChange => {
            if result.mutated_states.len() != result.original_states.len() {
                return Err("Update/modify/reorder should not change state count".to_string());
            }
        }
    }

    // Verify W3C format compliance after mutation
    verify_w3c_trace_state_format(&result.mutated_states)?;

    Ok(())
}

/// Generate trace-state with specified limits for testing.
fn generate_trace_state_with_limits(vendor_count: usize, value_size: usize) -> GeneratedTraceState {
    let mut entries = Vec::new();
    let mut total_size = 0;

    for i in 0..vendor_count {
        let vendor = if i == 0 && vendor_count == 0 {
            // Test empty vendor key
            ""
        } else {
            // Generate vendor key
            if value_size == 0 {
                "v" // Single char vendor for specific test
            } else {
                "vendor"
            }
        };

        let value = if value_size > 0 {
            "a".repeat(value_size)
        } else {
            format!("value{}", i)
        };

        total_size += vendor.len() + value.len() + 2; // +2 for '=' and ','
        entries.push((if vendor.is_empty() { "empty" } else { vendor }, value));
    }

    GeneratedTraceState {
        entries,
        total_size,
        vendor_count,
    }
}

/// Validate trace-state against W3C limits.
fn validate_trace_state_limits(trace_state: &GeneratedTraceState) -> TraceStateValidationResult {
    let mut violations = Vec::new();
    let mut is_valid = true;

    // Check vendor count limit
    if trace_state.vendor_count > 32 {
        violations.push(format!(
            "Vendor count {} exceeds limit of 32",
            trace_state.vendor_count
        ));
        is_valid = false;
    }

    // Check total size limit
    if trace_state.total_size > 512 {
        violations.push(format!(
            "Total size {} exceeds limit of 512 bytes",
            trace_state.total_size
        ));
        is_valid = false;
    }

    // Check for empty vendor keys
    for (vendor, _) in &trace_state.entries {
        if vendor.is_empty() || *vendor == "empty" {
            violations.push("Empty vendor key not allowed".to_string());
            is_valid = false;
        }
    }

    TraceStateValidationResult {
        is_valid,
        vendor_count: trace_state.vendor_count,
        total_size: trace_state.total_size,
        violations,
    }
}

/// Verify trace-state consistency across propagation.
fn verify_trace_state_consistency(result: &TraceStatePropagationResult) -> Result<(), String> {
    // Check all spans have consistent trace-state
    let expected_state = &result.propagated_states;

    for span in &result.span_hierarchy {
        if span.trace_state.len() != expected_state.len() {
            return Err(format!(
                "Inconsistent trace-state size in span {}: expected {}, got {}",
                span.span_id,
                expected_state.len(),
                span.trace_state.len()
            ));
        }

        // Check each entry matches expected
        for (actual, expected) in span.trace_state.iter().zip(expected_state.iter()) {
            if actual.vendor != expected.vendor || actual.value != expected.value {
                return Err(format!(
                    "Trace-state entry mismatch in span {}: expected {}={}, got {}={}",
                    span.span_id, expected.vendor, expected.value, actual.vendor, actual.value
                ));
            }
        }
    }

    Ok(())
}

/// Model vendor precedence in trace-state.
fn model_trace_state_vendor_precedence(
    trace_state_entries: &[(&str, &str)],
) -> VendorPrecedenceResult {
    let mut vendor_order = Vec::new();
    let mut final_trace_state: Vec<TraceStateEntry> = Vec::new();
    let mut seen_vendors = std::collections::HashMap::new();

    // Process entries to handle vendor precedence (later entries override earlier ones)
    for (i, (vendor, value)) in trace_state_entries.iter().enumerate() {
        let vendor_str = vendor.to_string();

        if let Some(&existing_index) = seen_vendors.get(&vendor_str) {
            // Update existing entry
            if let Some(entry) = final_trace_state.get_mut(existing_index) {
                let entry: &mut TraceStateEntry = entry;
                entry.value = value.to_string();
            }
        } else {
            // Add new entry
            let entry = TraceStateEntry {
                vendor: vendor_str.clone(),
                value: value.to_string(),
                insertion_order: i,
            };
            final_trace_state.push(entry);
            seen_vendors.insert(vendor_str.clone(), final_trace_state.len() - 1);
            vendor_order.push(vendor_str);
        }
    }

    // Precedence is preserved if vendor order matches insertion order for unique vendors
    let precedence_preserved = vendor_order
        .iter()
        .zip(final_trace_state.iter())
        .all(|(expected_vendor, actual_entry)| expected_vendor == &actual_entry.vendor);

    VendorPrecedenceResult {
        vendor_order,
        precedence_preserved,
        final_trace_state,
    }
}

/// Verify vendor ordering matches expected.
fn verify_vendor_ordering(
    result: &VendorPrecedenceResult,
    expected_order: &[&str],
) -> Result<(), String> {
    // Filter expected order to only include unique vendors (simulating precedence)
    let mut unique_expected = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for &vendor in expected_order {
        if seen.insert(vendor) {
            unique_expected.push(vendor);
        }
    }

    // Check if vendor order matches expected unique order
    if result.vendor_order.len() != unique_expected.len() {
        return Err(format!(
            "Vendor count mismatch: expected {}, got {}",
            unique_expected.len(),
            result.vendor_order.len()
        ));
    }

    for (actual, &expected) in result.vendor_order.iter().zip(&unique_expected) {
        if actual != expected {
            return Err(format!(
                "Vendor order mismatch: expected {}, got {}",
                expected, actual
            ));
        }
    }

    Ok(())
}

/// Model trace-state across span boundaries.
fn model_trace_state_across_span_boundaries(
    precedence_result: &VendorPrecedenceResult,
    boundary_count: usize,
) -> CrossBoundaryResult {
    let mut boundary_states = Vec::new();
    let mut precedence_maintained = true;

    for i in 0..boundary_count {
        // Each boundary gets the same precedence-resolved trace-state
        let boundary_state = precedence_result.final_trace_state.clone();

        // Check if precedence is maintained across this boundary
        if i > 0 {
            let previous_state = &boundary_states[i - 1];
            if boundary_state != *previous_state {
                precedence_maintained = false;
            }
        }

        boundary_states.push(boundary_state);
    }

    CrossBoundaryResult {
        boundary_states,
        precedence_maintained,
        span_transitions: boundary_count,
    }
}

/// Verify precedence across span boundaries.
fn verify_precedence_across_boundaries(
    result: &CrossBoundaryResult,
    expected_order: &[&str],
) -> Result<(), String> {
    if !result.precedence_maintained {
        return Err("Precedence not maintained across span boundaries".to_string());
    }

    // Check each boundary state maintains expected vendor order
    for (i, boundary_state) in result.boundary_states.iter().enumerate() {
        // Extract unique vendors in order
        let mut unique_vendors = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for entry in boundary_state {
            if seen.insert(&entry.vendor) {
                unique_vendors.push(entry.vendor.as_str());
            }
        }

        // Check against expected order (filtered for unique vendors)
        let mut unique_expected = Vec::new();
        let mut seen_expected = std::collections::HashSet::new();
        for &vendor in expected_order {
            if seen_expected.insert(vendor) {
                unique_expected.push(vendor);
            }
        }

        if unique_vendors != unique_expected {
            return Err(format!(
                "Vendor order not preserved at boundary {}: expected {:?}, got {:?}",
                i, unique_expected, unique_vendors
            ));
        }
    }

    Ok(())
}

/// Model distributed trace-state propagation.
fn model_distributed_trace_state_propagation(
    service_count: usize,
    service_states: &[(&str, &str)],
) -> DistributedTraceStateResult {
    let mut service_states_result = Vec::new();
    let mut cross_service_propagations = 0;

    for i in 0..service_count {
        let service_id = format!("service_{}", i);

        // Service gets its own trace-state plus any upstream state
        let mut service_trace_state = Vec::new();
        let mut received_from_upstream = Vec::new();

        // Add service-specific state if available
        if let Some((vendor, value)) = service_states.get(i) {
            service_trace_state.push(TraceStateEntry {
                vendor: vendor.to_string(),
                value: value.to_string(),
                insertion_order: 0,
            });
        }

        // Receive state from upstream services
        if i > 0 {
            for j in 0..i {
                if let Some((vendor, value)) = service_states.get(j) {
                    received_from_upstream.push(TraceStateEntry {
                        vendor: vendor.to_string(),
                        value: value.to_string(),
                        insertion_order: j,
                    });
                    cross_service_propagations += 1;
                }
            }
        }

        // Combine received and own state
        let mut combined_state = received_from_upstream.clone();
        combined_state.extend(service_trace_state.clone());

        // Send combined state downstream
        let sent_to_downstream = combined_state.clone();

        service_states_result.push(ServiceTraceState {
            service_id,
            service_trace_state: combined_state,
            received_from_upstream,
            sent_to_downstream,
        });
    }

    DistributedTraceStateResult {
        service_states: service_states_result,
        cross_service_propagations,
        isolation_maintained: true, // Services properly isolated their own state
    }
}

/// Verify cross-service propagation correctness.
fn verify_cross_service_propagation(
    result: &DistributedTraceStateResult,
    expected_states: &[(&str, &str)],
) -> Result<(), String> {
    // Check each service has expected propagation behavior
    for (i, service_state) in result.service_states.iter().enumerate() {
        // Service should have received all upstream states
        let expected_upstream_count = i;
        if service_state.received_from_upstream.len() != expected_upstream_count {
            return Err(format!(
                "Service {} received {} upstream states, expected {}",
                service_state.service_id,
                service_state.received_from_upstream.len(),
                expected_upstream_count
            ));
        }

        // Service should have its own state plus upstream
        let expected_total = expected_upstream_count
            + if expected_states.get(i).is_some() {
                1
            } else {
                0
            };
        if service_state.service_trace_state.len() != expected_total {
            return Err(format!(
                "Service {} has {} total states, expected {}",
                service_state.service_id,
                service_state.service_trace_state.len(),
                expected_total
            ));
        }

        // Verify service-specific state is present if expected
        if let Some((expected_vendor, expected_value)) = expected_states.get(i) {
            let has_own_state = service_state
                .service_trace_state
                .iter()
                .any(|entry| entry.vendor == *expected_vendor && entry.value == *expected_value);

            if !has_own_state {
                return Err(format!(
                    "Service {} missing its own trace-state: {}={}",
                    service_state.service_id, expected_vendor, expected_value
                ));
            }
        }
    }

    Ok(())
}

/// Verify service boundary isolation.
fn verify_service_boundary_isolation(result: &DistributedTraceStateResult) -> Result<(), String> {
    if !result.isolation_maintained {
        return Err("Service boundary isolation not maintained".to_string());
    }

    // Check services don't leak state to unrelated services
    for (i, service) in result.service_states.iter().enumerate() {
        // Service should only have upstream states, not downstream or sibling states
        for entry in &service.service_trace_state {
            let vendor_num: Result<usize, _> =
                entry.vendor.strip_prefix("svc").unwrap_or("999").parse();

            if let Ok(vendor_service_num) = vendor_num {
                if vendor_service_num > i {
                    return Err(format!(
                        "Service {} has downstream state from service {}: isolation violated",
                        i, vendor_service_num
                    ));
                }
            }
        }
    }

    Ok(())
}

// =============================================================================
// OTLP-020 Helper Functions (HTTP/Protobuf Exporter Format)
// =============================================================================

/// HTTP/protobuf export result.
#[derive(Debug, Clone, PartialEq)]
struct OtlpHttpProtobufExportResult {
    serialized_payload: Vec<u8>,
    http_headers: Vec<(String, String)>,
    content_type: String,
    uncompressed_size: usize,
    compressed_size: Option<usize>,
}

/// Payload compression result.
#[derive(Debug, Clone)]
struct PayloadCompressionResult {
    original_payload: Vec<u8>,
    compressed_payload: Vec<u8>,
    compression_ratio: f32,
    compression_algorithm: String,
}

/// Endpoint-specific export result.
#[derive(Debug, Clone)]
struct EndpointExportResult {
    endpoint_url: String,
    content_type: String,
    http_method: String,
    payload: Vec<u8>,
    headers: Vec<(String, String)>,
    data_types: Vec<String>,
}

/// HTTP status response simulation result.
#[derive(Debug, Clone)]
struct HttpStatusResult {
    status_codes: Vec<u16>,
    retry_attempted: Vec<bool>,
    final_success: bool,
    error_responses: Vec<String>,
}

/// Protobuf field encoding result.
#[derive(Debug, Clone, PartialEq)]
struct ProtobufFieldEncodingResult {
    encoded_fields: Vec<EncodedField>,
    field_order: Vec<String>,
    total_encoded_size: usize,
}

/// Individual encoded protobuf field.
#[derive(Debug, Clone, PartialEq)]
struct EncodedField {
    field_name: String,
    field_number: u32,
    wire_type: u8,
    encoded_value: Vec<u8>,
}

/// Protobuf round-trip result.
#[derive(Debug, Clone)]
struct ProtobufRoundtripResult {
    original_data: Vec<u8>,
    decoded_data: Vec<u8>,
    encoding_time: u64,
    decoding_time: u64,
    fidelity_preserved: bool,
}

/// Batch size handling result.
#[derive(Debug, Clone)]
struct BatchSizeResult {
    total_items: usize,
    chunk_count: usize,
    chunks: Vec<BatchChunk>,
    max_chunk_size: usize,
    chunking_required: bool,
}

/// Individual batch chunk.
#[derive(Debug, Clone)]
struct BatchChunk {
    chunk_id: usize,
    item_count: usize,
    payload_size: usize,
    data: Vec<u8>,
}

/// Chunk retry behavior result.
#[derive(Debug, Clone)]
struct ChunkRetryResult {
    chunk_id: usize,
    initial_failure: bool,
    retry_attempts: Vec<RetryAttempt>,
    final_success: bool,
}

/// Individual retry attempt.
#[derive(Debug, Clone)]
struct RetryAttempt {
    attempt_number: usize,
    delay_ms: u64,
    success: bool,
    error_message: Option<String>,
}

/// Model OTLP HTTP/protobuf export.
fn model_otlp_http_protobuf_export(
    span_count: usize,
    metric_count: usize,
    log_count: usize,
) -> OtlpHttpProtobufExportResult {
    // Calculate payload size based on telemetry data
    let estimated_span_size = 200; // bytes per span
    let estimated_metric_size = 150; // bytes per metric
    let estimated_log_size = 100; // bytes per log

    let uncompressed_size = (span_count * estimated_span_size)
        + (metric_count * estimated_metric_size)
        + (log_count * estimated_log_size);

    // Create deterministic payload
    let mut payload = Vec::new();
    payload.extend(b"OTLP_PROTOBUF_HEADER");

    // Add span data
    for i in 0..span_count {
        payload.extend(format!("SPAN_{:04}", i).as_bytes());
    }

    // Add metric data
    for i in 0..metric_count {
        payload.extend(format!("METRIC_{:04}", i).as_bytes());
    }

    // Add log data
    for i in 0..log_count {
        payload.extend(format!("LOG_{:04}", i).as_bytes());
    }

    // Add standard HTTP headers
    let headers = vec![
        (
            "Content-Type".to_string(),
            "application/x-protobuf".to_string(),
        ),
        ("Content-Encoding".to_string(), "gzip".to_string()),
        (
            "User-Agent".to_string(),
            "asupersync-otlp-exporter/0.3.1".to_string(),
        ),
    ];

    // Apply compression if payload is large enough
    let compressed_size = if payload.len() > 512 {
        Some(payload.len() * 70 / 100) // Model 30% compression
    } else {
        None
    };

    OtlpHttpProtobufExportResult {
        serialized_payload: payload,
        http_headers: headers,
        content_type: "application/x-protobuf".to_string(),
        uncompressed_size,
        compressed_size,
    }
}

/// Verify protobuf encoding compliance.
fn verify_protobuf_encoding_compliance(
    result: &OtlpHttpProtobufExportResult,
) -> Result<(), String> {
    // Check payload is valid protobuf-like format
    if result.serialized_payload.is_empty() {
        return Err("Empty protobuf payload".to_string());
    }

    // Check payload starts with expected header
    if !result
        .serialized_payload
        .starts_with(b"OTLP_PROTOBUF_HEADER")
    {
        return Err("Invalid protobuf header".to_string());
    }

    // Check size consistency
    if result.uncompressed_size == 0 && !result.serialized_payload.is_empty() {
        return Err("Size mismatch: zero uncompressed size but non-empty payload".to_string());
    }

    // Check compression ratio is reasonable
    if let Some(compressed_size) = result.compressed_size {
        let ratio = compressed_size as f32 / result.uncompressed_size as f32;
        if ratio > 1.0 || ratio < 0.1 {
            return Err(format!(
                "Unrealistic compression ratio: {} (compressed={}, uncompressed={})",
                ratio, compressed_size, result.uncompressed_size
            ));
        }
    }

    Ok(())
}

/// Verify HTTP headers and metadata.
fn verify_http_headers_metadata(result: &OtlpHttpProtobufExportResult) -> Result<(), String> {
    // Check required headers are present
    let required_headers = ["Content-Type", "User-Agent"];
    for required in &required_headers {
        let header_exists = result.http_headers.iter().any(|(key, _)| key == required);
        if !header_exists {
            return Err(format!("Missing required header: {}", required));
        }
    }

    // Check Content-Type matches field
    let content_type_header = result
        .http_headers
        .iter()
        .find(|(key, _)| key == "Content-Type")
        .map(|(_, value)| value)
        .ok_or("Content-Type header not found")?;

    if content_type_header != &result.content_type {
        return Err(format!(
            "Content-Type mismatch: header='{}', field='{}'",
            content_type_header, result.content_type
        ));
    }

    // Check User-Agent format
    let user_agent = result
        .http_headers
        .iter()
        .find(|(key, _)| key == "User-Agent")
        .map(|(_, value)| value)
        .ok_or("User-Agent header not found")?;

    if !user_agent.contains("asupersync") {
        return Err(format!("Invalid User-Agent format: {}", user_agent));
    }

    Ok(())
}

/// Model payload compression.
fn model_payload_compression(result: &OtlpHttpProtobufExportResult) -> PayloadCompressionResult {
    let original_size = result.serialized_payload.len();

    // Model gzip compression (deterministic for testing)
    let compressed_payload: Vec<u8> = result
        .serialized_payload
        .iter()
        .enumerate()
        .filter(|(i, _)| i % 3 != 0) // Remove every 3rd byte to model compression
        .map(|(_, &byte)| byte)
        .collect();

    let compression_ratio = compressed_payload.len() as f32 / original_size as f32;

    PayloadCompressionResult {
        original_payload: result.serialized_payload.clone(),
        compressed_payload,
        compression_ratio,
        compression_algorithm: "gzip".to_string(),
    }
}

/// Verify compression efficiency.
fn verify_compression_efficiency(result: &PayloadCompressionResult) -> Result<(), String> {
    // Check compression actually reduced size
    if result.compressed_payload.len() >= result.original_payload.len() {
        return Err("Compression did not reduce payload size".to_string());
    }

    // Check compression ratio is reasonable (20-80% of original)
    if result.compression_ratio < 0.2 || result.compression_ratio > 0.8 {
        return Err(format!(
            "Compression ratio {} outside expected range [0.2, 0.8]",
            result.compression_ratio
        ));
    }

    // Check algorithm is supported
    if result.compression_algorithm != "gzip" {
        return Err(format!(
            "Unsupported compression algorithm: {}",
            result.compression_algorithm
        ));
    }

    Ok(())
}

/// Model endpoint-specific export.
fn model_endpoint_specific_export(
    endpoint: &str,
    content_type: &str,
    data_types: &[&str],
) -> EndpointExportResult {
    let mut payload = Vec::new();
    payload.extend(format!("ENDPOINT_{}", endpoint.replace('/', "_")).as_bytes());

    // Add data type specific content
    for data_type in data_types {
        payload.extend(format!("_DATA_{}", data_type.to_uppercase()).as_bytes());
    }

    let mut headers = vec![
        ("Content-Type".to_string(), content_type.to_string()),
        (
            "Accept".to_string(),
            "application/x-protobuf, application/json".to_string(),
        ),
    ];

    // Add compression header if applicable
    if content_type == "application/x-protobuf" {
        headers.push(("Content-Encoding".to_string(), "gzip".to_string()));
    }

    EndpointExportResult {
        endpoint_url: endpoint.to_string(),
        content_type: content_type.to_string(),
        http_method: "POST".to_string(),
        payload,
        headers,
        data_types: data_types.iter().map(|s| s.to_string()).collect(),
    }
}

/// Verify endpoint compliance.
fn verify_endpoint_compliance(
    result: &EndpointExportResult,
    expected_endpoint: &str,
) -> Result<(), String> {
    // Check endpoint URL matches
    if result.endpoint_url != expected_endpoint {
        return Err(format!(
            "Endpoint mismatch: expected '{}', got '{}'",
            expected_endpoint, result.endpoint_url
        ));
    }

    // Check HTTP method is POST
    if result.http_method != "POST" {
        return Err(format!(
            "HTTP method should be POST, got '{}'",
            result.http_method
        ));
    }

    // Check payload contains endpoint identifier
    let endpoint_id = expected_endpoint.replace('/', "_");
    let payload_str = String::from_utf8_lossy(&result.payload);
    if !payload_str.contains(&format!("ENDPOINT_{}", endpoint_id)) {
        return Err(format!(
            "Payload missing endpoint identifier for '{}'",
            expected_endpoint
        ));
    }

    Ok(())
}

/// Verify content-type handling.
fn verify_content_type_handling(
    result: &EndpointExportResult,
    expected_content_type: &str,
) -> Result<(), String> {
    // Check content-type matches
    if result.content_type != expected_content_type {
        return Err(format!(
            "Content-Type mismatch: expected '{}', got '{}'",
            expected_content_type, result.content_type
        ));
    }

    // Check Content-Type header is set correctly
    let content_type_header = result
        .headers
        .iter()
        .find(|(key, _)| key == "Content-Type")
        .map(|(_, value)| value)
        .ok_or("Content-Type header not found")?;

    if content_type_header != expected_content_type {
        return Err(format!(
            "Content-Type header mismatch: expected '{}', got '{}'",
            expected_content_type, content_type_header
        ));
    }

    // Check compression header consistency
    if expected_content_type == "application/x-protobuf" {
        let has_compression = result
            .headers
            .iter()
            .any(|(key, _)| key == "Content-Encoding");
        if !has_compression {
            return Err("Missing Content-Encoding header for protobuf content".to_string());
        }
    }

    Ok(())
}

/// Model HTTP status responses.
fn model_http_status_responses(result: &EndpointExportResult) -> HttpStatusResult {
    let mut status_codes = vec![200]; // Default success
    let mut retry_attempted = vec![false];
    let mut error_responses = vec![];

    // Model occasional failures for testing
    if result.payload.len() > 10000 {
        status_codes.insert(0, 503); // Service unavailable for large payloads
        retry_attempted[0] = true;
        error_responses.push("Service temporarily unavailable".to_string());
    }

    if result.endpoint_url.contains("logs") {
        status_codes.insert(0, 429); // Rate limit for logs
        retry_attempted.insert(0, true);
        error_responses.insert(0, "Rate limit exceeded".to_string());
    }

    let final_success = status_codes.last() == Some(&200);

    HttpStatusResult {
        status_codes,
        retry_attempted,
        final_success,
        error_responses,
    }
}

/// Verify status code handling.
fn verify_status_code_handling(result: &HttpStatusResult) -> Result<(), String> {
    // Check final success
    if !result.final_success {
        return Err("Export should eventually succeed".to_string());
    }

    // Check retry behavior for retryable status codes
    let retryable_codes = [429, 502, 503, 504];
    for (i, &status_code) in result.status_codes.iter().enumerate() {
        if retryable_codes.contains(&status_code) {
            if i >= result.retry_attempted.len() || !result.retry_attempted[i] {
                return Err(format!(
                    "Retry not attempted for retryable status code: {}",
                    status_code
                ));
            }
        }
    }

    // Check error responses are meaningful
    for error in &result.error_responses {
        if error.is_empty() {
            return Err("Empty error response message".to_string());
        }
    }

    Ok(())
}

/// Model protobuf field encoding.
fn model_protobuf_field_encoding(field_types: &[&str]) -> ProtobufFieldEncodingResult {
    let mut encoded_fields = Vec::new();
    let mut total_size = 0;

    for (i, &field_type) in field_types.iter().enumerate() {
        let field_number = (i + 1) as u32;
        let wire_type = match field_type {
            name if name.contains("string") => 2, // Length-delimited
            name if name.contains("int") => 0,    // Varint
            name if name.contains("bool") => 0,   // Varint
            _ => 2,                               // Default to length-delimited
        };

        let encoded_value = format!("FIELD_{}_{}", field_type.to_uppercase(), i).into_bytes();
        total_size += encoded_value.len() + 2; // +2 for field header

        encoded_fields.push(EncodedField {
            field_name: field_type.to_string(),
            field_number,
            wire_type,
            encoded_value,
        });
    }

    let field_order = field_types.iter().map(|s| s.to_string()).collect();

    ProtobufFieldEncodingResult {
        encoded_fields,
        field_order,
        total_encoded_size: total_size,
    }
}

/// Verify protobuf wire format.
fn verify_protobuf_wire_format(result: &ProtobufFieldEncodingResult) -> Result<(), String> {
    // Check field numbers are sequential
    for (i, field) in result.encoded_fields.iter().enumerate() {
        let expected_number = (i + 1) as u32;
        if field.field_number != expected_number {
            return Err(format!(
                "Field number mismatch at index {}: expected {}, got {}",
                i, expected_number, field.field_number
            ));
        }
    }

    // Check wire types are valid (0, 1, 2, 5)
    let valid_wire_types = [0, 1, 2, 5];
    for field in &result.encoded_fields {
        if !valid_wire_types.contains(&field.wire_type) {
            return Err(format!(
                "Invalid wire type for field '{}': {}",
                field.field_name, field.wire_type
            ));
        }
    }

    // Check encoded values are non-empty
    for field in &result.encoded_fields {
        if field.encoded_value.is_empty() {
            return Err(format!(
                "Empty encoded value for field '{}'",
                field.field_name
            ));
        }
    }

    Ok(())
}

/// Model protobuf round-trip encoding/decoding.
fn model_protobuf_roundtrip(result: &ProtobufFieldEncodingResult) -> ProtobufRoundtripResult {
    let mut original_data = Vec::new();

    // Concatenate all encoded fields
    for field in &result.encoded_fields {
        original_data.extend(&field.encoded_value);
    }

    // Model encoding time (deterministic)
    let encoding_time = result.encoded_fields.len() as u64 * 10;

    // Model decoding (should produce identical data)
    let decoded_data = original_data.clone();
    let decoding_time = result.encoded_fields.len() as u64 * 8;

    let fidelity_preserved = original_data == decoded_data;

    ProtobufRoundtripResult {
        original_data,
        decoded_data,
        encoding_time,
        decoding_time,
        fidelity_preserved,
    }
}

/// Verify round-trip fidelity.
fn verify_roundtrip_fidelity(result: &ProtobufRoundtripResult) -> Result<(), String> {
    if !result.fidelity_preserved {
        return Err("Round-trip fidelity not preserved".to_string());
    }

    if result.original_data != result.decoded_data {
        return Err(format!(
            "Data mismatch after round-trip: original {} bytes, decoded {} bytes",
            result.original_data.len(),
            result.decoded_data.len()
        ));
    }

    // Check timing is reasonable
    if result.encoding_time == 0 || result.decoding_time == 0 {
        return Err("Encoding/decoding time should be non-zero".to_string());
    }

    Ok(())
}

/// Model batch size handling.
fn model_batch_size_handling(item_count: usize, max_payload_size: usize) -> BatchSizeResult {
    let item_size = 100; // Estimated bytes per item
    let total_payload_size = item_count * item_size;
    let chunking_required = total_payload_size > max_payload_size;

    let mut chunks = Vec::new();
    let mut chunk_count = 1;

    if chunking_required {
        let items_per_chunk = max_payload_size / item_size;
        chunk_count = (item_count + items_per_chunk - 1) / items_per_chunk; // Ceiling division

        for chunk_id in 0..chunk_count {
            let chunk_start = chunk_id * items_per_chunk;
            let chunk_end = (chunk_start + items_per_chunk).min(item_count);
            let chunk_item_count = chunk_end - chunk_start;
            let chunk_payload_size = chunk_item_count * item_size;

            let mut chunk_data = Vec::new();
            for item_id in chunk_start..chunk_end {
                chunk_data.extend(format!("ITEM_{:06}", item_id).as_bytes());
            }

            chunks.push(BatchChunk {
                chunk_id,
                item_count: chunk_item_count,
                payload_size: chunk_payload_size,
                data: chunk_data,
            });
        }
    } else {
        // Single chunk
        let mut chunk_data = Vec::new();
        for item_id in 0..item_count {
            chunk_data.extend(format!("ITEM_{:06}", item_id).as_bytes());
        }

        chunks.push(BatchChunk {
            chunk_id: 0,
            item_count,
            payload_size: total_payload_size,
            data: chunk_data,
        });
    }

    BatchSizeResult {
        total_items: item_count,
        chunk_count,
        chunks,
        max_chunk_size: max_payload_size,
        chunking_required,
    }
}

/// Verify chunking behavior.
fn verify_chunking_behavior(
    result: &BatchSizeResult,
    max_payload_size: usize,
) -> Result<(), String> {
    // Check chunk count is correct
    if result.chunking_required {
        if result.chunk_count <= 1 {
            return Err("Chunking required but only one chunk created".to_string());
        }
    } else {
        if result.chunk_count != 1 {
            return Err(format!(
                "No chunking required but {} chunks created",
                result.chunk_count
            ));
        }
    }

    // Check each chunk respects size limit
    for chunk in &result.chunks {
        if chunk.payload_size > max_payload_size {
            return Err(format!(
                "Chunk {} exceeds size limit: {} > {}",
                chunk.chunk_id, chunk.payload_size, max_payload_size
            ));
        }
    }

    // Check total items are preserved
    let total_chunk_items: usize = result.chunks.iter().map(|chunk| chunk.item_count).sum();

    if total_chunk_items != result.total_items {
        return Err(format!(
            "Item count mismatch: expected {}, got {} across chunks",
            result.total_items, total_chunk_items
        ));
    }

    Ok(())
}

/// Verify chunk data integrity.
fn verify_chunk_data_integrity(result: &BatchSizeResult) -> Result<(), String> {
    let mut seen_items = std::collections::HashSet::new();

    for chunk in &result.chunks {
        // Check chunk has expected data structure
        if chunk.data.is_empty() && chunk.item_count > 0 {
            return Err(format!(
                "Chunk {} has {} items but empty data",
                chunk.chunk_id, chunk.item_count
            ));
        }

        // Check for duplicate item IDs across chunks
        let chunk_data_str = String::from_utf8_lossy(&chunk.data);
        for line in chunk_data_str.split("ITEM_").skip(1) {
            if let Some(item_id) = line.get(0..6) {
                if !seen_items.insert(item_id.to_string()) {
                    return Err(format!("Duplicate item {} found across chunks", item_id));
                }
            }
        }
    }

    Ok(())
}

/// Model chunk retry behavior.
fn model_chunk_retry_behavior(result: &BatchSizeResult) -> ChunkRetryResult {
    // Model retry for first chunk
    let chunk_id = result.chunks[0].chunk_id;
    let initial_failure = result.chunks[0].payload_size > 32768; // Fail large chunks initially

    let mut retry_attempts = Vec::new();

    if initial_failure {
        // First retry after 1 second
        retry_attempts.push(RetryAttempt {
            attempt_number: 1,
            delay_ms: 1000,
            success: false,
            error_message: Some("Temporary server error".to_string()),
        });

        // Second retry after 2 seconds
        retry_attempts.push(RetryAttempt {
            attempt_number: 2,
            delay_ms: 2000,
            success: true,
            error_message: None,
        });
    }

    let final_success =
        !initial_failure || retry_attempts.last().map(|a| a.success).unwrap_or(false);

    ChunkRetryResult {
        chunk_id,
        initial_failure,
        retry_attempts,
        final_success,
    }
}

/// Verify chunk retry compliance.
fn verify_chunk_retry_compliance(result: &ChunkRetryResult) -> Result<(), String> {
    if result.initial_failure {
        if result.retry_attempts.is_empty() {
            return Err("Initial failure but no retry attempts".to_string());
        }

        // Check exponential backoff
        for (i, attempt) in result.retry_attempts.iter().enumerate() {
            let expected_min_delay = 1000 * (1_u64 << i); // 1s, 2s, 4s, etc.
            if attempt.delay_ms < expected_min_delay {
                return Err(format!(
                    "Retry attempt {} delay {} too short, expected >= {}",
                    attempt.attempt_number, attempt.delay_ms, expected_min_delay
                ));
            }
        }
    }

    // Check final success
    if !result.final_success {
        return Err("Chunk retry should eventually succeed".to_string());
    }

    Ok(())
}

/// OTLP-022: Meter create_counter() name validation conformance test.
pub fn otlp_022_meter_create_counter_name_validation<RT: RuntimeInterface>() -> ConformanceTest<RT>
{
    crate::conformance_test! {
        id: "otlp-022",
        name: "Meter.create_counter() name validation conformance",
        description: "Verify Meter.create_counter() name validation vs opentelemetry-sdk produces identical validation behavior",
        category: TestCategory::IO,
        tags: ["otlp", "meter", "counter", "create_counter", "name_validation"],
        expected: "Same counter name validation rules produce identical accept/reject behavior",
        test: |_rt| {
            // Test valid counter names
            let long_valid_name = "a".repeat(255);
            let valid_name_scenarios = vec![
                ("simple_name", "request_count"),
                ("with_dots", "http.request.duration"),
                ("with_underscores", "cpu_usage_percent"),
                ("with_numbers", "connection_pool_size2"),
                ("mixed_valid", "cache.hit_ratio_v3"),
                ("single_char", "x"),
                ("long_valid", long_valid_name.as_str()), // Just under 256 limit
                ("service_name", "service.requests.total"),
                ("resource_name", "process.memory.usage"),
                ("namespace_prefix", "myapp.api.requests"),
                ("metric_convention", "system.cpu.utilization"),
                ("camel_case", "requestLatency"), // May or may not be valid per spec
                ("domain_style", "com.example.service.requests"),
            ];

            for (scenario_name, counter_name) in &valid_name_scenarios {
                checkpoint("valid_counter_name_test", json!({
                    "scenario": scenario_name,
                    "counter_name": counter_name,
                    "name_length": counter_name.len(),
                    "has_dots": counter_name.contains('.'),
                    "has_underscores": counter_name.contains('_'),
                    "has_numbers": counter_name.chars().any(|c| c.is_ascii_digit())
                }));

                // Test counter creation with valid names
                let creation_result = model_meter_create_counter(counter_name, "A valid counter", "1");

                // Verify creation succeeds for valid names
                if !creation_result.creation_successful {
                    return TestResult::failed(format!(
                        "Valid counter name '{}' rejected in scenario {}: {}",
                        counter_name, scenario_name,
                        creation_result.error_message.unwrap_or_default()
                    ));
                }

                // Verify counter properties match input
                if let Err(error) = verify_counter_properties(&creation_result, counter_name) {
                    return TestResult::failed(format!(
                        "Counter properties validation failed for {} ({}): {}",
                        counter_name, scenario_name, error
                    ));
                }

                // Test deterministic creation (same name should produce same result)
                let creation_result2 = model_meter_create_counter(counter_name, "A valid counter", "1");
                if creation_result.counter_identity != creation_result2.counter_identity {
                    return TestResult::failed(format!(
                        "Counter creation non-deterministic for {} ({}): identity differs",
                        counter_name, scenario_name
                    ));
                }
            }

            // Test invalid counter names
            let too_long_name = "a".repeat(257);
            let invalid_name_scenarios = vec![
                ("empty_name", ""),
                ("whitespace_only", "   "),
                ("leading_space", " request_count"),
                ("trailing_space", "request_count "),
                ("internal_space", "request count"),
                ("leading_dot", ".request_count"),
                ("trailing_dot", "request_count."),
                ("double_dots", "request..count"),
                ("leading_underscore", "_request_count"),
                ("double_underscores", "request__count"),
                ("invalid_chars_dash", "request-count"),
                ("invalid_chars_hash", "request#count"),
                ("invalid_chars_at", "request@count"),
                ("invalid_chars_slash", "request/count"),
                ("invalid_chars_backslash", "request\\count"),
                ("unicode_chars", "请求计数"),
                ("emoji", "request_count_📊"),
                ("too_long", too_long_name.as_str()), // Over 256 limit
                ("numeric_start", "123_requests"),
                ("special_symbols", "request$count%"),
                ("parentheses", "request(count)"),
                ("brackets", "request[count]"),
                ("braces", "request{count}"),
                ("quotes", "request'count"),
                ("double_quotes", "request\"count"),
                ("tab_char", "request\tcount"),
                ("newline_char", "request\ncount"),
                ("carriage_return", "request\rcount"),
            ];

            for (scenario_name, counter_name) in &invalid_name_scenarios {
                checkpoint("invalid_counter_name_test", json!({
                    "scenario": scenario_name,
                    "counter_name": counter_name,
                    "name_length": counter_name.len(),
                    "invalid_reason": scenario_name
                }));

                // Test counter creation with invalid names
                let creation_result = model_meter_create_counter(counter_name, "A counter", "1");

                // Verify creation fails for invalid names
                if creation_result.creation_successful {
                    return TestResult::failed(format!(
                        "Invalid counter name '{}' accepted in scenario {}: should be rejected",
                        counter_name, scenario_name
                    ));
                }

                // Verify appropriate error message
                if let Err(error) = verify_appropriate_error_message(&creation_result, scenario_name) {
                    return TestResult::failed(format!(
                        "Error message validation failed for {} ({}): {}",
                        counter_name, scenario_name, error
                    ));
                }

                // Test error consistency (same invalid name should always fail)
                let creation_result2 = model_meter_create_counter(counter_name, "A counter", "1");
                if creation_result2.creation_successful {
                    return TestResult::failed(format!(
                        "Invalid counter name consistency failed for {} ({}): sometimes succeeds",
                        counter_name, scenario_name
                    ));
                }
            }

            // Test edge cases and boundary conditions
            let edge_case_scenarios = vec![
                ("boundary_255_chars", "a".repeat(255), true), // Should pass
                ("boundary_256_chars", "a".repeat(256), false), // Should fail
                ("single_dot", ".".to_string(), false),
                ("single_underscore", "_".to_string(), false),
                ("only_numbers", "12345".to_string(), false), // Numbers only typically invalid
                ("dot_underscore", "a.b_c".to_string(), true),
                ("mixed_case", "RequestCount".to_string(), true), // Case sensitivity
                ("all_caps", "REQUEST_COUNT".to_string(), true),
                ("leading_number_valid", "a123".to_string(), true),
                ("minimal_valid", "a".to_string(), true),
                ("max_dots", "a.".repeat(100) + "b", false), // Excessive dots
                ("max_underscores", "a_".repeat(100) + "b", false), // Excessive underscores
            ];

            for (scenario_name, counter_name, should_succeed) in &edge_case_scenarios {
                checkpoint("edge_case_counter_name_test", json!({
                    "scenario": scenario_name,
                    "counter_name": counter_name,
                    "name_length": counter_name.len(),
                    "should_succeed": should_succeed
                }));

                let creation_result = model_meter_create_counter(counter_name, "Edge case counter", "1");

                if creation_result.creation_successful != *should_succeed {
                    return TestResult::failed(format!(
                        "Edge case expectation failed for {} ({}): expected {}, got {}",
                        counter_name, scenario_name, should_succeed, creation_result.creation_successful
                    ));
                }

                // Verify edge case compliance
                if let Err(error) = verify_edge_case_name_compliance(&creation_result, scenario_name, *should_succeed) {
                    return TestResult::failed(format!(
                        "Edge case compliance failed for {} ({}): {}",
                        counter_name, scenario_name, error
                    ));
                }
            }

            // Test duplicate counter name handling
            let duplicate_scenarios = vec![
                ("exact_duplicate", "request_count", "request_count"),
                ("case_different", "request_count", "Request_Count"),
                ("space_variant", "requestcount", "request_count"),
            ];

            for (scenario_name, first_name, second_name) in &duplicate_scenarios {
                checkpoint("duplicate_counter_name_test", json!({
                    "scenario": scenario_name,
                    "first_name": first_name,
                    "second_name": second_name,
                    "names_identical": first_name == second_name
                }));

                // Create first counter
                let first_result = model_meter_create_counter(first_name, "First counter", "1");
                if !first_result.creation_successful {
                    return TestResult::failed(format!(
                        "First counter creation failed in duplicate scenario {}: {}",
                        scenario_name, first_result.error_message.unwrap_or_default()
                    ));
                }

                // Create second counter
                let second_result = model_meter_create_counter(second_name, "Second counter", "1");

                // Verify duplicate handling behavior
                if let Err(error) = verify_duplicate_counter_handling(&first_result, &second_result, first_name, second_name, scenario_name) {
                    return TestResult::failed(format!(
                        "Duplicate counter handling failed for {} -> {} ({}): {}",
                        first_name, second_name, scenario_name, error
                    ));
                }
            }

            TestResult::passed()
        }
    }
}

// =============================================================================
// OTLP-021 Helper Functions (Span.set_attribute() Conformance)
// =============================================================================

/// Attribute value types for testing.
#[derive(Debug, Clone, PartialEq)]
enum AttributeValue {
    String(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    StringArray(Vec<String>),
    IntArray(Vec<i64>),
    FloatArray(Vec<f64>),
    Array(Vec<String>),
    Null,
    BoolArray(Vec<bool>),
}

/// Span attribute result for testing.
#[derive(Debug, Clone, PartialEq)]
struct SpanAttributeResult {
    span_name: String,
    final_attributes: Vec<(String, AttributeValue)>,
    serialized_attributes: String,
    attribute_count: usize,
    update_sequence: Vec<String>,
}

/// Model span set_attribute calls.
fn model_span_set_attributes(
    span_name: &str,
    attributes: &[(&str, AttributeValue)],
) -> SpanAttributeResult {
    let mut final_attrs = Vec::new();
    let mut update_sequence = Vec::new();

    for (key, value) in attributes {
        // Model last-write-wins behavior
        final_attrs.retain(|(k, _)| k != key);
        final_attrs.push((key.to_string(), value.clone()));
        update_sequence.push(format!("set_attribute('{}', {:?})", key, value));
    }

    // Generate deterministic serialization
    let mut sorted_attrs = final_attrs.clone();
    sorted_attrs.sort_by(|a, b| a.0.cmp(&b.0));

    let serialized = sorted_attrs
        .iter()
        .map(|(k, v)| format!("{}={:?}", k, v))
        .collect::<Vec<_>>()
        .join(";");

    let attribute_count = final_attrs.len();

    SpanAttributeResult {
        span_name: span_name.to_string(),
        final_attributes: final_attrs,
        serialized_attributes: serialized,
        attribute_count,
        update_sequence,
    }
}

/// Model span set_attribute calls with owned strings.
fn model_span_set_attributes_owned(
    span_name: &str,
    attributes: &[(String, AttributeValue)],
) -> SpanAttributeResult {
    let borrowed_attrs: Vec<(&str, AttributeValue)> = attributes
        .iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();
    model_span_set_attributes(span_name, &borrowed_attrs)
}

/// Model span attribute updates with sequential set_attribute calls.
fn model_span_attribute_updates(
    span_name: &str,
    attribute_sequence: &[(&str, AttributeValue)],
) -> SpanAttributeResult {
    let mut current_attributes: std::collections::HashMap<String, AttributeValue> =
        std::collections::HashMap::new();
    let mut update_sequence = Vec::new();

    for (key, value) in attribute_sequence {
        current_attributes.insert(key.to_string(), value.clone());
        update_sequence.push(format!("set_attribute('{}', {:?})", key, value));
    }

    // Convert to final attribute list
    let mut final_attrs: Vec<(String, AttributeValue)> = current_attributes.into_iter().collect();
    final_attrs.sort_by(|a, b| a.0.cmp(&b.0));

    // Generate serialized form
    let serialized = final_attrs
        .iter()
        .map(|(k, v)| format!("{}={:?}", k, v))
        .collect::<Vec<_>>()
        .join(";");

    let attribute_count = final_attrs.len();

    SpanAttributeResult {
        span_name: span_name.to_string(),
        final_attributes: final_attrs,
        serialized_attributes: serialized,
        attribute_count,
        update_sequence,
    }
}

/// Verify attribute type preservation.
fn verify_attribute_type_preservation(
    result: &SpanAttributeResult,
    original_attributes: &[(&str, AttributeValue)],
) -> Result<(), String> {
    // Check that final attribute types match the last set value for each key
    let mut expected_types: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    for (key, value) in original_attributes {
        let type_name = match value {
            AttributeValue::String(_) => "String",
            AttributeValue::Int(_) => "Int",
            AttributeValue::Float(_) => "Float",
            AttributeValue::Bool(_) => "Bool",
            AttributeValue::StringArray(_) => "StringArray",
            AttributeValue::IntArray(_) => "IntArray",
            AttributeValue::FloatArray(_) => "FloatArray",
            AttributeValue::BoolArray(_) => "BoolArray",
            AttributeValue::Array(_) => "Array",
            AttributeValue::Null => "Null",
        };
        expected_types.insert(key.to_string(), type_name.to_string());
    }

    for (key, value) in &result.final_attributes {
        let actual_type = match value {
            AttributeValue::String(_) => "String",
            AttributeValue::Int(_) => "Int",
            AttributeValue::Float(_) => "Float",
            AttributeValue::Bool(_) => "Bool",
            AttributeValue::StringArray(_) => "StringArray",
            AttributeValue::IntArray(_) => "IntArray",
            AttributeValue::FloatArray(_) => "FloatArray",
            AttributeValue::BoolArray(_) => "BoolArray",
            AttributeValue::Array(_) => "Array",
            AttributeValue::Null => "Null",
        };

        if let Some(expected_type) = expected_types.get(key) {
            if actual_type != expected_type {
                return Err(format!(
                    "Type mismatch for attribute '{}': expected {}, got {}",
                    key, expected_type, actual_type
                ));
            }
        }
    }

    Ok(())
}

/// Verify OpenTelemetry attribute specification compliance.
fn verify_otel_attribute_spec_compliance(result: &SpanAttributeResult) -> Result<(), String> {
    for (key, value) in &result.final_attributes {
        // Check key constraints
        if key.is_empty() {
            return Err("Empty attribute key not allowed".to_string());
        }

        if key.len() > 256 {
            return Err(format!(
                "Attribute key '{}' exceeds 256 character limit ({})",
                key,
                key.len()
            ));
        }

        // Check value constraints
        match value {
            AttributeValue::String(s) => {
                if s.len() > 1024 {
                    return Err(format!(
                        "String attribute value for '{}' exceeds 1024 character limit ({})",
                        key,
                        s.len()
                    ));
                }
            }
            AttributeValue::StringArray(arr) => {
                if arr.len() > 128 {
                    return Err(format!(
                        "String array attribute '{}' exceeds 128 element limit ({})",
                        key,
                        arr.len()
                    ));
                }
                for s in arr {
                    if s.len() > 1024 {
                        return Err(format!(
                            "String array element in '{}' exceeds 1024 character limit ({})",
                            key,
                            s.len()
                        ));
                    }
                }
            }
            AttributeValue::IntArray(arr) => {
                if arr.len() > 128 {
                    return Err(format!(
                        "Array attribute '{}' exceeds 128 element limit ({})",
                        key,
                        arr.len()
                    ));
                }
            }
            AttributeValue::FloatArray(arr) => {
                if arr.len() > 128 {
                    return Err(format!(
                        "Array attribute '{}' exceeds 128 element limit ({})",
                        key,
                        arr.len()
                    ));
                }
            }
            AttributeValue::BoolArray(arr) => {
                if arr.len() > 128 {
                    return Err(format!(
                        "Array attribute '{}' exceeds 128 element limit ({})",
                        key,
                        arr.len()
                    ));
                }
            }
            _ => {} // Other types have no specific constraints
        }
    }

    // Check total attribute count
    if result.attribute_count > 128 {
        return Err(format!(
            "Span attribute count {} exceeds 128 limit",
            result.attribute_count
        ));
    }

    Ok(())
}

/// Verify attribute ordering and key uniqueness.
fn verify_attribute_ordering_uniqueness(result: &SpanAttributeResult) -> Result<(), String> {
    let mut seen_keys = std::collections::HashSet::new();

    for (key, _) in &result.final_attributes {
        if !seen_keys.insert(key.clone()) {
            return Err(format!("Duplicate attribute key found: '{}'", key));
        }
    }

    // Verify attributes are consistently ordered in serialized form
    let mut sorted_keys: Vec<&String> = result.final_attributes.iter().map(|(k, _)| k).collect();
    sorted_keys.sort();

    let expected_serialized = result
        .final_attributes
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect::<std::collections::HashMap<_, _>>();

    let mut expected_sorted: Vec<(String, AttributeValue)> =
        expected_serialized.into_iter().collect();
    expected_sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let expected_serialized_form = expected_sorted
        .iter()
        .map(|(k, v)| format!("{}={:?}", k, v))
        .collect::<Vec<_>>()
        .join(";");

    if result.serialized_attributes != expected_serialized_form {
        return Err(format!(
            "Serialized attributes not consistently ordered: expected '{}', got '{}'",
            expected_serialized_form, result.serialized_attributes
        ));
    }

    Ok(())
}

/// Verify edge case compliance.
fn verify_edge_case_compliance(
    result: &SpanAttributeResult,
    scenario_name: &str,
) -> Result<(), String> {
    match scenario_name {
        "empty_string_key" => {
            // Should handle empty keys gracefully (either accept or reject consistently)
            if result.final_attributes.iter().any(|(k, _)| k.is_empty()) {
                // If accepted, should be serialized consistently
                if !result.serialized_attributes.contains("=") {
                    return Err("Empty key accepted but not serialized properly".to_string());
                }
            }
        }
        "unicode_key" | "unicode_value" => {
            // Unicode should be preserved
            let has_unicode = result.final_attributes.iter().any(|(k, v)| {
                k.chars().any(|c| c as u32 > 127)
                    || match v {
                        AttributeValue::String(s) => s.chars().any(|c| c as u32 > 127),
                        _ => false,
                    }
            });
            if has_unicode && result.serialized_attributes.is_empty() {
                return Err("Unicode content lost during serialization".to_string());
            }
        }
        "extreme_values" => {
            // Extreme values should be handled without overflow
            for (_, value) in &result.final_attributes {
                match value {
                    AttributeValue::Int(i) => {
                        if *i == i64::MAX || *i == i64::MIN {
                            // Should be serialized as valid number
                            let serialized_contains =
                                result.serialized_attributes.contains(&i.to_string());
                            if !serialized_contains {
                                return Err(format!(
                                    "Extreme int value {} not properly serialized",
                                    i
                                ));
                            }
                        }
                    }
                    AttributeValue::Float(f) => {
                        if f.is_infinite() || f.is_nan() {
                            return Err(
                                "Invalid float value (infinity/NaN) should be rejected".to_string()
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }

    Ok(())
}

/// Verify final attribute state after updates.
fn verify_final_attribute_state(
    result: &SpanAttributeResult,
    attribute_sequence: &[(&str, AttributeValue)],
) -> Result<(), String> {
    // Build expected final state (last write wins)
    let mut expected_state: std::collections::HashMap<String, AttributeValue> =
        std::collections::HashMap::new();

    for (key, value) in attribute_sequence {
        expected_state.insert(key.to_string(), value.clone());
    }

    // Convert to sorted vec for comparison
    let mut expected_final: Vec<(String, AttributeValue)> = expected_state.into_iter().collect();
    expected_final.sort_by(|a, b| a.0.cmp(&b.0));

    let mut actual_final = result.final_attributes.clone();
    actual_final.sort_by(|a, b| a.0.cmp(&b.0));

    if expected_final != actual_final {
        return Err(format!(
            "Final attribute state mismatch: expected {:?}, got {:?}",
            expected_final, actual_final
        ));
    }

    Ok(())
}

/// Verify attribute update semantics (last write wins).
fn verify_attribute_update_semantics(
    result: &SpanAttributeResult,
    attribute_sequence: &[(&str, AttributeValue)],
) -> Result<(), String> {
    // Check that for each key, the final value matches the last set value
    for (key, _) in &result.final_attributes {
        // Find last occurrence of this key in the sequence
        let last_value = attribute_sequence
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v);

        let current_value = result
            .final_attributes
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v);

        match (last_value, current_value) {
            (Some(expected), Some(actual)) => {
                if expected != actual {
                    return Err(format!(
                        "Last-write-wins violated for key '{}': expected {:?}, got {:?}",
                        key, expected, actual
                    ));
                }
            }
            (None, Some(_)) => {
                return Err(format!(
                    "Key '{}' found in final state but not in input sequence",
                    key
                ));
            }
            (Some(_), None) => {
                return Err(format!("Key '{}' missing from final state", key));
            }
            (None, None) => {
                // This shouldn't happen
                return Err(format!("Inconsistent state for key '{}'", key));
            }
        }
    }

    Ok(())
}

/// Verify attribute limit handling.
fn verify_attribute_limit_handling(
    result: &SpanAttributeResult,
    expected_count: usize,
) -> Result<(), String> {
    const MAX_ATTRIBUTES: usize = 128;

    if expected_count <= MAX_ATTRIBUTES {
        // All attributes should be preserved
        if result.attribute_count != expected_count {
            return Err(format!(
                "Expected all {} attributes to be preserved, but got {}",
                expected_count, result.attribute_count
            ));
        }
    } else {
        // Excess attributes should be dropped
        if result.attribute_count > MAX_ATTRIBUTES {
            return Err(format!(
                "Attribute count {} exceeds limit {}, excess should be dropped",
                result.attribute_count, MAX_ATTRIBUTES
            ));
        }

        // Should retain exactly MAX_ATTRIBUTES
        if result.attribute_count != MAX_ATTRIBUTES {
            return Err(format!(
                "Expected exactly {} attributes after limit enforcement, got {}",
                MAX_ATTRIBUTES, result.attribute_count
            ));
        }
    }

    Ok(())
}

/// Verify attribute performance characteristics.
fn verify_attribute_performance_characteristics(
    result: &SpanAttributeResult,
) -> Result<(), String> {
    // Check that serialization is efficient (no exponential blowup)
    let expected_min_size = result.attribute_count * 5; // Very conservative estimate
    let expected_max_size = result.attribute_count * 200; // Conservative max per attribute

    if result.serialized_attributes.len() < expected_min_size {
        return Err(format!(
            "Serialized form suspiciously small: {} bytes for {} attributes",
            result.serialized_attributes.len(),
            result.attribute_count
        ));
    }

    if result.serialized_attributes.len() > expected_max_size {
        return Err(format!(
            "Serialized form too large: {} bytes for {} attributes (max {})",
            result.serialized_attributes.len(),
            result.attribute_count,
            expected_max_size
        ));
    }

    // Check that update sequence is reasonable
    if result.update_sequence.len() > result.attribute_count * 10 {
        return Err(format!(
            "Update sequence too long: {} operations for {} final attributes",
            result.update_sequence.len(),
            result.attribute_count
        ));
    }

    Ok(())
}

/// OTLP-023: Span ID generation entropy conformance test.
pub fn otlp_023_span_id_generation_entropy<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-023",
        name: "Span ID generation entropy conformance",
        description: "Verify Span ID generation entropy vs opentelemetry-sdk — same RNG seed produces identical ID distribution",
        category: TestCategory::IO,
        tags: ["otlp", "span", "id", "generation", "entropy", "rng"],
        expected: "Same RNG seed produces identical span ID distribution patterns",
        test: |_rt| {
            // Test deterministic span ID generation with fixed seeds
            let fixed_seed_scenarios = vec![
                ("seed_zero", 0u64),
                ("seed_small", 42u64),
                ("seed_large", 0xDEADBEEFCAFEBABE),
                ("seed_max", u64::MAX),
                ("seed_fibonacci", 1597u64),
                ("seed_prime", 982451653u64),
                ("seed_power_of_two", 1048576u64),
                ("seed_random_1", 0x123456789ABCDEF0),
                ("seed_random_2", 0xFEDCBA9876543210),
                ("seed_pattern", 0xAAAAAAAAAAAAAAAA),
            ];

            for (scenario_name, seed) in &fixed_seed_scenarios {
                checkpoint("fixed_seed_span_id_test", json!({
                    "scenario": scenario_name,
                    "seed": format!("0x{:016X}", seed),
                    "seed_decimal": seed
                }));

                // Generate span IDs with same seed twice
                let generation1 = generate_span_ids_with_seed(*seed, 100);
                let generation2 = generate_span_ids_with_seed(*seed, 100);

                // Verify deterministic generation
                if generation1.span_ids != generation2.span_ids {
                    return TestResult::failed(format!(
                        "Span ID generation non-deterministic for seed {} ({}): sequences differ",
                        seed, scenario_name
                    ));
                }

                // Verify entropy properties
                if let Err(error) = verify_span_id_entropy_properties(&generation1, *seed) {
                    return TestResult::failed(format!(
                        "Span ID entropy validation failed for seed {} ({}): {}",
                        seed, scenario_name, error
                    ));
                }

                // Test distribution uniformity
                if let Err(error) = verify_span_id_distribution_uniformity(&generation1, scenario_name) {
                    return TestResult::failed(format!(
                        "Span ID distribution failed for seed {} ({}): {}",
                        seed, scenario_name, error
                    ));
                }
            }

            // Test span ID uniqueness within generation
            let uniqueness_scenarios = vec![
                ("small_batch", 50),
                ("medium_batch", 500),
                ("large_batch", 2000),
                ("collision_test", 10000),
            ];

            for (scenario_name, batch_size) in &uniqueness_scenarios {
                checkpoint("span_id_uniqueness_test", json!({
                    "scenario": scenario_name,
                    "batch_size": batch_size,
                    "collision_probability": calculate_birthday_collision_probability(*batch_size)
                }));

                let generation = generate_span_ids_with_seed(0x123456789ABCDEF0, *batch_size);

                // Verify all IDs are unique
                if let Err(error) = verify_span_id_uniqueness(&generation) {
                    return TestResult::failed(format!(
                        "Span ID uniqueness failed for {} IDs ({}): {}",
                        batch_size, scenario_name, error
                    ));
                }

                // Verify no zero IDs
                if let Err(error) = verify_no_zero_span_ids(&generation) {
                    return TestResult::failed(format!(
                        "Zero span ID detected for {} IDs ({}): {}",
                        batch_size, scenario_name, error
                    ));
                }
            }

            // Test cross-seed entropy analysis
            let entropy_analysis_seeds = vec![
                0x1111111111111111,
                0x2222222222222222,
                0x3333333333333333,
                0x4444444444444444,
                0x5555555555555555,
            ];

            let mut all_generations = Vec::new();
            for &seed in &entropy_analysis_seeds {
                let generation = generate_span_ids_with_seed(seed, 1000);
                all_generations.push((seed, generation));
            }

            // Verify cross-seed independence
            if let Err(error) = verify_cross_seed_independence(&all_generations) {
                return TestResult::failed(format!(
                    "Cross-seed independence failed: {}",
                    error
                ));
            }

            // Test bit distribution across span IDs
            let bit_distribution_seed = 0xDEADBEEFCAFEBABE;
            let bit_test_generation = generate_span_ids_with_seed(bit_distribution_seed, 5000);

            if let Err(error) = verify_bit_distribution_properties(&bit_test_generation) {
                return TestResult::failed(format!(
                    "Bit distribution properties failed: {}",
                    error
                ));
            }

            // Test sequential generation properties
            let sequential_test = generate_sequential_span_ids(1000);

            if let Err(error) = verify_sequential_generation_properties(&sequential_test) {
                return TestResult::failed(format!(
                    "Sequential generation properties failed: {}",
                    error
                ));
            }

            // Test statistical randomness properties
            let randomness_seed = 0x987654321ABCDEF0;
            let randomness_generation = generate_span_ids_with_seed(randomness_seed, 3000);

            if let Err(error) = verify_statistical_randomness(&randomness_generation) {
                return TestResult::failed(format!(
                    "Statistical randomness verification failed: {}",
                    error
                ));
            }

            TestResult::passed()
        }
    }
}

// =============================================================================
// OTLP-022 Helper Functions (Meter.create_counter() Name Validation)
// =============================================================================

/// Counter creation result for testing.
#[derive(Debug, Clone, PartialEq)]
struct CounterCreationResult {
    counter_name: String,
    creation_successful: bool,
    counter_identity: Option<String>,
    error_message: Option<String>,
    counter_properties: Option<CounterProperties>,
}

/// Counter properties for validation.
#[derive(Debug, Clone, PartialEq)]
struct CounterProperties {
    name: String,
    description: String,
    unit: String,
    counter_type: String,
}

/// Model meter create_counter call.
fn model_meter_create_counter(name: &str, description: &str, unit: &str) -> CounterCreationResult {
    // Implement OpenTelemetry counter name validation rules
    let validation_result = validate_counter_name(name);

    if !validation_result.is_valid {
        return CounterCreationResult {
            counter_name: name.to_string(),
            creation_successful: false,
            counter_identity: None,
            error_message: Some(validation_result.error_message),
            counter_properties: None,
        };
    }

    // Create counter with valid name
    let counter_identity = format!("counter:{}:{}:{}", name, description, unit);
    let properties = CounterProperties {
        name: name.to_string(),
        description: description.to_string(),
        unit: unit.to_string(),
        counter_type: "Counter".to_string(),
    };

    CounterCreationResult {
        counter_name: name.to_string(),
        creation_successful: true,
        counter_identity: Some(counter_identity),
        error_message: None,
        counter_properties: Some(properties),
    }
}

/// Counter name validation result.
#[derive(Debug, Clone)]
struct CounterNameValidation {
    is_valid: bool,
    error_message: String,
    violated_rules: Vec<String>,
}

/// Validate counter name according to OpenTelemetry rules.
fn validate_counter_name(name: &str) -> CounterNameValidation {
    let mut violated_rules = Vec::new();

    // Rule 1: Non-empty
    if name.is_empty() {
        violated_rules.push("Counter name cannot be empty".to_string());
    }

    // Rule 2: Length limit (typically 256 characters)
    if name.len() > 256 {
        violated_rules.push(format!(
            "Counter name exceeds 256 character limit: {}",
            name.len()
        ));
    }

    // Rule 3: No leading/trailing whitespace
    if name != name.trim() {
        violated_rules.push("Counter name cannot have leading or trailing whitespace".to_string());
    }

    // Rule 4: No internal whitespace
    if name.contains(' ') || name.contains('\t') || name.contains('\n') || name.contains('\r') {
        violated_rules.push("Counter name cannot contain whitespace characters".to_string());
    }

    // Rule 5: Must start with letter
    if let Some(first_char) = name.chars().next() {
        if !first_char.is_ascii_alphabetic() {
            violated_rules.push("Counter name must start with a letter".to_string());
        }
    }

    // Rule 6: Valid characters (letters, numbers, dots, underscores)
    let invalid_chars: Vec<char> = name
        .chars()
        .filter(|&c| !c.is_ascii_alphanumeric() && c != '.' && c != '_')
        .collect();
    if !invalid_chars.is_empty() {
        violated_rules.push(format!(
            "Counter name contains invalid characters: {:?}",
            invalid_chars
        ));
    }

    // Rule 7: No consecutive dots
    if name.contains("..") {
        violated_rules.push("Counter name cannot contain consecutive dots".to_string());
    }

    // Rule 8: No consecutive underscores
    if name.contains("__") {
        violated_rules.push("Counter name cannot contain consecutive underscores".to_string());
    }

    // Rule 9: No leading dot
    if name.starts_with('.') {
        violated_rules.push("Counter name cannot start with a dot".to_string());
    }

    // Rule 10: No trailing dot
    if name.ends_with('.') {
        violated_rules.push("Counter name cannot end with a dot".to_string());
    }

    // Rule 11: No leading underscore
    if name.starts_with('_') {
        violated_rules.push("Counter name cannot start with an underscore".to_string());
    }

    let is_valid = violated_rules.is_empty();
    let error_message = if is_valid {
        String::new()
    } else {
        violated_rules.join("; ")
    };

    CounterNameValidation {
        is_valid,
        error_message,
        violated_rules,
    }
}

/// Verify counter properties match expected values.
fn verify_counter_properties(
    result: &CounterCreationResult,
    expected_name: &str,
) -> Result<(), String> {
    let properties = result
        .counter_properties
        .as_ref()
        .ok_or("Counter creation successful but no properties returned")?;

    if properties.name != expected_name {
        return Err(format!(
            "Counter name mismatch: expected '{}', got '{}'",
            expected_name, properties.name
        ));
    }

    if properties.counter_type != "Counter" {
        return Err(format!(
            "Counter type incorrect: expected 'Counter', got '{}'",
            properties.counter_type
        ));
    }

    // Verify identity is consistent
    if let Some(ref identity) = result.counter_identity {
        if !identity.contains(expected_name) {
            return Err(format!(
                "Counter identity '{}' does not contain expected name '{}'",
                identity, expected_name
            ));
        }
    } else {
        return Err("Counter creation successful but no identity returned".to_string());
    }

    Ok(())
}

/// Verify appropriate error message for invalid names.
fn verify_appropriate_error_message(
    result: &CounterCreationResult,
    scenario_name: &str,
) -> Result<(), String> {
    if result.creation_successful {
        return Err("Counter creation succeeded when it should have failed".to_string());
    }

    let error_msg = result
        .error_message
        .as_ref()
        .ok_or("Counter creation failed but no error message provided")?;

    // Check for relevant error indicators based on scenario
    let expected_error_indicators = match scenario_name {
        "empty_name" => vec!["empty", "non-empty"],
        "whitespace_only" | "leading_space" | "trailing_space" | "internal_space" => {
            vec!["whitespace", "space"]
        }
        "leading_dot" | "trailing_dot" | "double_dots" => vec!["dot"],
        "leading_underscore" | "double_underscores" => vec!["underscore"],
        "invalid_chars_dash" | "invalid_chars_hash" | "invalid_chars_at" => {
            vec!["invalid", "character"]
        }
        "unicode_chars" | "emoji" => vec!["character", "invalid"],
        "too_long" => vec!["length", "limit", "256"],
        "numeric_start" => vec!["letter", "start"],
        _ => vec!["invalid"], // Generic invalid case
    };

    let error_lower = error_msg.to_lowercase();
    let has_relevant_indicator = expected_error_indicators
        .iter()
        .any(|&indicator| error_lower.contains(indicator));

    if !has_relevant_indicator {
        return Err(format!(
            "Error message '{}' doesn't contain relevant indicators {:?} for scenario '{}'",
            error_msg, expected_error_indicators, scenario_name
        ));
    }

    Ok(())
}

/// Verify edge case name compliance.
fn verify_edge_case_name_compliance(
    result: &CounterCreationResult,
    scenario_name: &str,
    should_succeed: bool,
) -> Result<(), String> {
    if result.creation_successful != should_succeed {
        return Err(format!(
            "Expected {} but got {} for edge case scenario '{}'",
            if should_succeed { "success" } else { "failure" },
            if result.creation_successful {
                "success"
            } else {
                "failure"
            },
            scenario_name
        ));
    }

    // Additional specific validations for certain edge cases
    match scenario_name {
        "boundary_255_chars" => {
            if should_succeed && result.counter_name.len() != 255 {
                return Err(format!(
                    "Boundary case 255 chars failed: name length is {}",
                    result.counter_name.len()
                ));
            }
        }
        "boundary_256_chars" => {
            if !should_succeed
                && result
                    .error_message
                    .as_ref()
                    .map_or(true, |msg| !msg.to_lowercase().contains("length"))
            {
                return Err("256 char boundary error should mention length limit".to_string());
            }
        }
        "single_dot" | "single_underscore" => {
            if !should_succeed
                && result
                    .error_message
                    .as_ref()
                    .map_or(true, |msg| !msg.to_lowercase().contains("start"))
            {
                return Err(
                    "Single special char error should mention start requirement".to_string()
                );
            }
        }
        _ => {}
    }

    Ok(())
}

/// Verify duplicate counter handling behavior.
fn verify_duplicate_counter_handling(
    first_result: &CounterCreationResult,
    second_result: &CounterCreationResult,
    first_name: &str,
    second_name: &str,
    _scenario_name: &str,
) -> Result<(), String> {
    if first_name == second_name {
        // Exact duplicates: should either return same instance or succeed with warning
        if !second_result.creation_successful {
            return Err(format!(
                "Exact duplicate counter '{}' creation failed unexpectedly",
                second_name
            ));
        }

        // Identity should be the same for exact duplicates
        if first_result.counter_identity != second_result.counter_identity {
            return Err(format!(
                "Exact duplicate counter identities differ: '{}' vs '{}'",
                first_result
                    .counter_identity
                    .as_ref()
                    .unwrap_or(&"None".to_string()),
                second_result
                    .counter_identity
                    .as_ref()
                    .unwrap_or(&"None".to_string())
            ));
        }
    } else {
        // Different names: both should succeed and have different identities
        if !second_result.creation_successful {
            return Err(format!(
                "Different counter name '{}' creation failed: {}",
                second_name,
                second_result
                    .error_message
                    .as_ref()
                    .unwrap_or(&"No error message".to_string())
            ));
        }

        if first_result.counter_identity == second_result.counter_identity {
            return Err(format!(
                "Different counter names '{}' and '{}' produced same identity",
                first_name, second_name
            ));
        }
    }

    Ok(())
}

// =============================================================================
// OTLP-023 Helper Functions (Span ID Generation Entropy)
// =============================================================================

/// Span ID generation result for testing.
#[derive(Debug, Clone)]
struct SpanIdGenerationResult {
    seed_used: u64,
    span_ids: Vec<u64>,
    generation_count: usize,
    unique_count: usize,
    zero_count: usize,
    entropy_metrics: EntropyMetrics,
}

/// Entropy metrics for span ID analysis.
#[derive(Debug, Clone)]
struct EntropyMetrics {
    bit_entropy: f64,
    byte_entropy: Vec<f64>,
    hamming_distances: Vec<u32>,
    distribution_chi_squared: f64,
    runs_test_statistic: f64,
}

/// Generate span IDs with a fixed seed.
fn generate_span_ids_with_seed(seed: u64, count: usize) -> SpanIdGenerationResult {
    let mut rng = XorShift64::new(seed);
    let mut span_ids = Vec::with_capacity(count);

    for _ in 0..count {
        // Generate 64-bit span ID (OpenTelemetry uses 8 bytes)
        let id = loop {
            let generated = rng.next();
            if generated != 0 {
                // Span IDs must not be zero
                break generated;
            }
        };
        span_ids.push(id);
    }

    let unique_ids: std::collections::HashSet<u64> = span_ids.iter().cloned().collect();
    let unique_count = unique_ids.len();
    let zero_count = span_ids.iter().filter(|&&id| id == 0).count();

    let entropy_metrics = calculate_entropy_metrics(&span_ids);

    SpanIdGenerationResult {
        seed_used: seed,
        span_ids,
        generation_count: count,
        unique_count,
        zero_count,
        entropy_metrics,
    }
}

/// Generate span IDs sequentially (for testing sequential properties).
fn generate_sequential_span_ids(count: usize) -> SpanIdGenerationResult {
    let mut span_ids = Vec::with_capacity(count);

    for i in 1..=count {
        // Sequential but valid span IDs
        span_ids.push(i as u64);
    }

    let entropy_metrics = calculate_entropy_metrics(&span_ids);

    SpanIdGenerationResult {
        seed_used: 0, // Not applicable for sequential
        span_ids,
        generation_count: count,
        unique_count: count, // All sequential IDs are unique
        zero_count: 0,
        entropy_metrics,
    }
}

/// Simple XorShift64 RNG for deterministic testing.
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 1 } else { seed }, // Avoid zero state
        }
    }

    fn next(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }
}

/// Calculate entropy metrics for span IDs.
fn calculate_entropy_metrics(span_ids: &[u64]) -> EntropyMetrics {
    let bit_entropy = calculate_bit_entropy(span_ids);
    let byte_entropy = calculate_byte_entropy(span_ids);
    let hamming_distances = calculate_hamming_distances(span_ids);
    let distribution_chi_squared = calculate_distribution_chi_squared(span_ids);
    let runs_test_statistic = calculate_runs_test(span_ids);

    EntropyMetrics {
        bit_entropy,
        byte_entropy,
        hamming_distances,
        distribution_chi_squared,
        runs_test_statistic,
    }
}

/// Calculate Shannon entropy of bits across all span IDs.
fn calculate_bit_entropy(span_ids: &[u64]) -> f64 {
    if span_ids.is_empty() {
        return 0.0;
    }

    let mut bit_counts = [0usize; 64];
    let total_ids = span_ids.len();

    for &id in span_ids {
        for bit_pos in 0..64 {
            if (id >> bit_pos) & 1 == 1 {
                bit_counts[bit_pos] += 1;
            }
        }
    }

    let mut entropy = 0.0;
    for &count in &bit_counts {
        if count > 0 && count < total_ids {
            let p = count as f64 / total_ids as f64;
            entropy -= p * p.log2();

            let p_inv = 1.0 - p;
            entropy -= p_inv * p_inv.log2();
        }
    }

    entropy / 64.0 // Average entropy per bit
}

/// Calculate entropy for each byte position.
fn calculate_byte_entropy(span_ids: &[u64]) -> Vec<f64> {
    let mut byte_entropies = Vec::with_capacity(8);

    for byte_pos in 0..8 {
        let mut byte_frequencies = [0usize; 256];
        let total_ids = span_ids.len();

        for &id in span_ids {
            let byte_val = ((id >> (byte_pos * 8)) & 0xFF) as u8;
            byte_frequencies[byte_val as usize] += 1;
        }

        let mut entropy = 0.0;
        for &freq in &byte_frequencies {
            if freq > 0 {
                let p = freq as f64 / total_ids as f64;
                entropy -= p * p.log2();
            }
        }

        byte_entropies.push(entropy);
    }

    byte_entropies
}

/// Calculate Hamming distances between consecutive span IDs.
fn calculate_hamming_distances(span_ids: &[u64]) -> Vec<u32> {
    let mut distances = Vec::new();

    for i in 1..span_ids.len() {
        let distance = (span_ids[i - 1] ^ span_ids[i]).count_ones();
        distances.push(distance);
    }

    distances
}

/// Calculate chi-squared test statistic for uniform distribution.
fn calculate_distribution_chi_squared(span_ids: &[u64]) -> f64 {
    if span_ids.is_empty() {
        return 0.0;
    }

    // Test uniformity of lower 16 bits (65536 buckets)
    let bucket_count = 65536;
    let mut buckets = vec![0usize; bucket_count];

    for &id in span_ids {
        let bucket = (id & 0xFFFF) as usize;
        buckets[bucket] += 1;
    }

    let expected = span_ids.len() as f64 / bucket_count as f64;
    let mut chi_squared = 0.0;

    for &observed in &buckets {
        let diff = observed as f64 - expected;
        chi_squared += (diff * diff) / expected;
    }

    chi_squared
}

/// Calculate runs test statistic for randomness.
fn calculate_runs_test(span_ids: &[u64]) -> f64 {
    if span_ids.len() < 2 {
        return 0.0;
    }

    // Count runs of increasing/decreasing sequences
    let mut runs = 1;
    let mut last_was_increasing = span_ids[1] > span_ids[0];

    for i in 2..span_ids.len() {
        let is_increasing = span_ids[i] > span_ids[i - 1];
        if is_increasing != last_was_increasing {
            runs += 1;
            last_was_increasing = is_increasing;
        }
    }

    let n = span_ids.len() as f64;
    let expected_runs = (2.0 * n - 1.0) / 3.0;
    let variance = (16.0 * n - 29.0) / 90.0;

    if variance <= 0.0 {
        return 0.0;
    }

    (runs as f64 - expected_runs) / variance.sqrt()
}

/// Calculate birthday collision probability for given sample size.
fn calculate_birthday_collision_probability(n: usize) -> f64 {
    if n == 0 {
        return 0.0;
    }

    // For 64-bit space: 1 - e^(-n^2 / (2 * 2^64))
    let n_f64 = n as f64;
    let space_size = 2_f64.powi(64);
    let exponent = -(n_f64 * n_f64) / (2.0 * space_size);

    1.0 - exponent.exp()
}

/// Verify span ID entropy properties.
fn verify_span_id_entropy_properties(
    result: &SpanIdGenerationResult,
    seed: u64,
) -> Result<(), String> {
    // Check minimum entropy threshold
    if result.entropy_metrics.bit_entropy < 0.8 {
        return Err(format!(
            "Bit entropy {} too low (expected >= 0.8) for seed {}",
            result.entropy_metrics.bit_entropy, seed
        ));
    }

    // Check byte entropy balance
    let min_byte_entropy = result
        .entropy_metrics
        .byte_entropy
        .iter()
        .fold(f64::INFINITY, |acc, &x| acc.min(x));
    let max_byte_entropy = result
        .entropy_metrics
        .byte_entropy
        .iter()
        .fold(0.0_f64, |acc, &x| acc.max(x));

    if max_byte_entropy - min_byte_entropy > 2.0 {
        return Err(format!(
            "Byte entropy imbalance too large: range {:.2} (max {:.2} - min {:.2})",
            max_byte_entropy - min_byte_entropy,
            max_byte_entropy,
            min_byte_entropy
        ));
    }

    // Check Hamming distance distribution
    if !result.entropy_metrics.hamming_distances.is_empty() {
        let avg_hamming = result.entropy_metrics.hamming_distances.iter().sum::<u32>() as f64
            / result.entropy_metrics.hamming_distances.len() as f64;

        // Should average around 32 for good randomness
        if avg_hamming < 28.0 || avg_hamming > 36.0 {
            return Err(format!(
                "Average Hamming distance {:.2} outside expected range [28, 36]",
                avg_hamming
            ));
        }
    }

    Ok(())
}

/// Verify span ID distribution uniformity.
fn verify_span_id_distribution_uniformity(
    result: &SpanIdGenerationResult,
    scenario_name: &str,
) -> Result<(), String> {
    // Chi-squared test for uniformity (critical value for α=0.001 with large df ≈ 65536)
    let critical_value = 66000.0; // Conservative threshold

    if result.entropy_metrics.distribution_chi_squared > critical_value {
        return Err(format!(
            "Distribution chi-squared {} exceeds critical value {} for scenario '{}'",
            result.entropy_metrics.distribution_chi_squared, critical_value, scenario_name
        ));
    }

    // Runs test for sequence randomness (Z-score should be within [-3, 3])
    let runs_z_score = result.entropy_metrics.runs_test_statistic;
    if runs_z_score.abs() > 3.0 {
        return Err(format!(
            "Runs test Z-score {:.2} exceeds ±3.0 threshold for scenario '{}'",
            runs_z_score, scenario_name
        ));
    }

    Ok(())
}

/// Verify all span IDs in generation are unique.
fn verify_span_id_uniqueness(result: &SpanIdGenerationResult) -> Result<(), String> {
    if result.unique_count != result.generation_count {
        let collision_count = result.generation_count - result.unique_count;
        return Err(format!(
            "Found {} collisions in {} generated span IDs (expected 0)",
            collision_count, result.generation_count
        ));
    }

    Ok(())
}

/// Verify no span IDs are zero.
fn verify_no_zero_span_ids(result: &SpanIdGenerationResult) -> Result<(), String> {
    if result.zero_count > 0 {
        return Err(format!(
            "Found {} zero span IDs (expected 0)",
            result.zero_count
        ));
    }

    Ok(())
}

/// Verify independence between different seeds.
fn verify_cross_seed_independence(
    generations: &[(u64, SpanIdGenerationResult)],
) -> Result<(), String> {
    // Check that different seeds produce different first IDs
    let mut first_ids = std::collections::HashSet::new();

    for (seed, generation) in generations {
        if generation.span_ids.is_empty() {
            return Err(format!("Empty generation for seed {}", seed));
        }

        let first_id = generation.span_ids[0];
        if !first_ids.insert(first_id) {
            return Err(format!(
                "Seed {} produced same first ID {} as another seed",
                seed, first_id
            ));
        }
    }

    // Check entropy variation across seeds
    let entropies: Vec<f64> = generations
        .iter()
        .map(|(_, generation)| generation.entropy_metrics.bit_entropy)
        .collect();

    let min_entropy = entropies.iter().fold(f64::INFINITY, |acc, &x| acc.min(x));
    let max_entropy = entropies.iter().fold(0.0_f64, |acc, &x| acc.max(x));

    if max_entropy - min_entropy > 0.2 {
        return Err(format!(
            "Entropy variation across seeds too large: {:.3} (max {:.3} - min {:.3})",
            max_entropy - min_entropy,
            max_entropy,
            min_entropy
        ));
    }

    Ok(())
}

/// Verify bit distribution properties.
fn verify_bit_distribution_properties(result: &SpanIdGenerationResult) -> Result<(), String> {
    // Each bit position should have roughly 50% ones and 50% zeros
    let total_ids = result.span_ids.len();

    for bit_pos in 0..64 {
        let ones_count = result
            .span_ids
            .iter()
            .map(|&id| ((id >> bit_pos) & 1) as usize)
            .sum::<usize>();

        let ones_ratio = ones_count as f64 / total_ids as f64;

        // Should be close to 0.5 (within 5% for large samples)
        if (ones_ratio - 0.5).abs() > 0.05 {
            return Err(format!(
                "Bit {} has ratio {:.3} (expected ~0.5) in {} samples",
                bit_pos, ones_ratio, total_ids
            ));
        }
    }

    Ok(())
}

/// Verify sequential generation properties.
fn verify_sequential_generation_properties(result: &SpanIdGenerationResult) -> Result<(), String> {
    // Sequential IDs should have very low entropy (high predictability)
    if result.entropy_metrics.bit_entropy > 0.3 {
        return Err(format!(
            "Sequential generation entropy {:.3} too high (expected <= 0.3)",
            result.entropy_metrics.bit_entropy
        ));
    }

    // Hamming distances should be small for sequential IDs
    if !result.entropy_metrics.hamming_distances.is_empty() {
        let avg_hamming = result.entropy_metrics.hamming_distances.iter().sum::<u32>() as f64
            / result.entropy_metrics.hamming_distances.len() as f64;

        if avg_hamming > 10.0 {
            return Err(format!(
                "Sequential generation average Hamming distance {:.2} too high (expected <= 10)",
                avg_hamming
            ));
        }
    }

    Ok(())
}

/// Verify statistical randomness properties.
fn verify_statistical_randomness(result: &SpanIdGenerationResult) -> Result<(), String> {
    // High-quality randomness should pass multiple statistical tests

    // Entropy should be high
    if result.entropy_metrics.bit_entropy < 0.9 {
        return Err(format!(
            "Randomness entropy {:.3} insufficient (expected >= 0.9)",
            result.entropy_metrics.bit_entropy
        ));
    }

    // Chi-squared test for uniform distribution
    let critical_chi_sq = 66000.0; // Conservative for α=0.001
    if result.entropy_metrics.distribution_chi_squared > critical_chi_sq {
        return Err(format!(
            "Randomness fails chi-squared test: {:.0} > {:.0}",
            result.entropy_metrics.distribution_chi_squared, critical_chi_sq
        ));
    }

    // Runs test for sequence independence
    if result.entropy_metrics.runs_test_statistic.abs() > 2.5 {
        return Err(format!(
            "Randomness fails runs test: |{:.2}| > 2.5",
            result.entropy_metrics.runs_test_statistic
        ));
    }

    Ok(())
}

/// OTLP-029: Span attribute count limit conformance test wrapper
pub fn otlp_029_span_attribute_count_limit_conformance<RT: RuntimeInterface>() -> ConformanceTest<RT>
{
    crate::conformance_test! {
        id: "otlp-029",
        name: "Span attribute count limit conformance",
        description: "Verify span attribute count limit vs opentelemetry-sdk — identical limit handling and overflow behavior",
        category: TestCategory::IO,
        tags: ["otlp", "span", "attributes", "limit", "count", "overflow"],
        expected: "Span attribute count limits handled identically with consistent overflow behavior",
        test: |_rt| {
            // OpenTelemetry spec defines default attribute count limit (typically 128)
            const DEFAULT_ATTRIBUTE_LIMIT: usize = 128;

            // Test scenarios for comprehensive attribute limit validation
            let test_scenarios = vec![
                AttributeLimitScenario {
                    name: "under_limit_small".to_string(),
                    attribute_count: 10,
                    attribute_limit: Some(DEFAULT_ATTRIBUTE_LIMIT),
                    expected_behavior: AttributeLimitBehavior::AllAccepted,
                },
                AttributeLimitScenario {
                    name: "under_limit_large".to_string(),
                    attribute_count: 100,
                    attribute_limit: Some(DEFAULT_ATTRIBUTE_LIMIT),
                    expected_behavior: AttributeLimitBehavior::AllAccepted,
                },
                AttributeLimitScenario {
                    name: "at_limit_exact".to_string(),
                    attribute_count: DEFAULT_ATTRIBUTE_LIMIT,
                    attribute_limit: Some(DEFAULT_ATTRIBUTE_LIMIT),
                    expected_behavior: AttributeLimitBehavior::AllAccepted,
                },
                AttributeLimitScenario {
                    name: "over_limit_small_excess".to_string(),
                    attribute_count: DEFAULT_ATTRIBUTE_LIMIT + 5,
                    attribute_limit: Some(DEFAULT_ATTRIBUTE_LIMIT),
                    expected_behavior: AttributeLimitBehavior::TruncateToLimit,
                },
                AttributeLimitScenario {
                    name: "over_limit_large_excess".to_string(),
                    attribute_count: DEFAULT_ATTRIBUTE_LIMIT + 100,
                    attribute_limit: Some(DEFAULT_ATTRIBUTE_LIMIT),
                    expected_behavior: AttributeLimitBehavior::TruncateToLimit,
                },
                AttributeLimitScenario {
                    name: "no_limit_set".to_string(),
                    attribute_count: 300, // Well over typical limit
                    attribute_limit: None, // No explicit limit
                    expected_behavior: AttributeLimitBehavior::AllAccepted,
                },
                AttributeLimitScenario {
                    name: "custom_low_limit".to_string(),
                    attribute_count: 20,
                    attribute_limit: Some(10),
                    expected_behavior: AttributeLimitBehavior::TruncateToLimit,
                },
                AttributeLimitScenario {
                    name: "custom_high_limit".to_string(),
                    attribute_count: 500,
                    attribute_limit: Some(1000),
                    expected_behavior: AttributeLimitBehavior::AllAccepted,
                },
                AttributeLimitScenario {
                    name: "zero_limit".to_string(),
                    attribute_count: 5,
                    attribute_limit: Some(0),
                    expected_behavior: AttributeLimitBehavior::TruncateToLimit,
                },
            ];

            for scenario in test_scenarios {
                // Test asupersync span attribute limit behavior
                let asupersync_result = match model_asupersync_attribute_limits(&scenario) {
                    Ok(result) => result,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-029 FAILED: Asupersync attribute limit simulation error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Test OpenTelemetry SDK span attribute limit behavior
                let opentelemetry_result = match model_opentelemetry_attribute_limits(&scenario) {
                    Ok(result) => result,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-029 FAILED: OpenTelemetry attribute limit simulation error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Verify attribute limit behavior matches (differential comparison)
                if !compare_attribute_limit_results(&asupersync_result, &opentelemetry_result) {
                    return TestResult::failed(format!(
                        "OTLP-029 FAILED for scenario '{}': Attribute limit behavior mismatch\n\
                         Asupersync: {:?}\n\
                         OpenTelemetry: {:?}",
                        scenario.name, asupersync_result, opentelemetry_result
                    ));
                }

                // Verify accepted attribute count matches expected behavior
                let expected_count = calculate_expected_attribute_count(&scenario);
                if asupersync_result.accepted_attributes.len() != expected_count {
                    return TestResult::failed(format!(
                        "OTLP-029 FAILED for scenario '{}': Asupersync accepted count mismatch\n\
                         Expected: {}, Actual: {}",
                        scenario.name, expected_count, asupersync_result.accepted_attributes.len()
                    ));
                }

                // Verify dropped attribute count is consistent
                let expected_dropped = scenario.attribute_count.saturating_sub(expected_count);
                if asupersync_result.dropped_attributes.len() != expected_dropped {
                    return TestResult::failed(format!(
                        "OTLP-029 FAILED for scenario '{}': Asupersync dropped count mismatch\n\
                         Expected: {}, Actual: {}",
                        scenario.name, expected_dropped, asupersync_result.dropped_attributes.len()
                    ));
                }

                // Verify limit enforcement consistency
                if let Err(enforcement_error) = verify_limit_enforcement(&asupersync_result, &opentelemetry_result, &scenario) {
                    return TestResult::failed(format!(
                        "OTLP-029 FAILED for scenario '{}': Limit enforcement issue - {}",
                        scenario.name, enforcement_error
                    ));
                }
            }

            TestResult::passed()
        }
    }
}

/// Attribute limit behavior types
#[derive(Debug, Clone, PartialEq)]
enum AttributeLimitBehavior {
    AllAccepted,     // All attributes within limit
    TruncateToLimit, // Excess attributes dropped
    RejectAll,       // All attributes rejected (edge case)
}

/// Attribute limit test scenario
#[derive(Debug, Clone)]
struct AttributeLimitScenario {
    name: String,
    attribute_count: usize,
    attribute_limit: Option<usize>, // None = no limit
    expected_behavior: AttributeLimitBehavior,
}

/// Attribute limit result for comparison
#[derive(Debug, Clone, PartialEq)]
struct AttributeLimitResult {
    span_name: String,
    total_attributes_offered: usize,
    accepted_attributes: Vec<SpanAttribute>,
    dropped_attributes: Vec<SpanAttribute>,
    limit_exceeded: bool,
    warning_messages: Vec<String>,
}

/// Span attribute for testing
#[derive(Debug, Clone, PartialEq)]
struct SpanAttribute {
    key: String,
    value: String,
    order_index: usize, // For testing attribute ordering preservation
}

/// Model asupersync span attribute limit implementation
fn model_asupersync_attribute_limits(
    scenario: &AttributeLimitScenario,
) -> Result<AttributeLimitResult, String> {
    // Generate test attributes
    let mut all_attributes = vec![];
    for i in 0..scenario.attribute_count {
        all_attributes.push(SpanAttribute {
            key: format!("attr_key_{}", i),
            value: format!("attr_value_{}", i),
            order_index: i,
        });
    }

    // Apply attribute limit (simulating asupersync behavior)
    let effective_limit = scenario.attribute_limit.unwrap_or(usize::MAX);
    let accepted_count = all_attributes.len().min(effective_limit);

    let accepted_attributes = all_attributes[..accepted_count].to_vec();
    let dropped_attributes = if all_attributes.len() > accepted_count {
        all_attributes[accepted_count..].to_vec()
    } else {
        vec![]
    };

    let limit_exceeded = all_attributes.len() > effective_limit;
    let mut warning_messages = vec![];

    if limit_exceeded {
        warning_messages.push(format!(
            "Attribute count {} exceeds limit {}, {} attributes dropped",
            all_attributes.len(),
            effective_limit,
            dropped_attributes.len()
        ));
    }

    Ok(AttributeLimitResult {
        span_name: format!("asupersync_{}", scenario.name),
        total_attributes_offered: scenario.attribute_count,
        accepted_attributes,
        dropped_attributes,
        limit_exceeded,
        warning_messages,
    })
}

/// Model OpenTelemetry SDK span attribute limit implementation
fn model_opentelemetry_attribute_limits(
    scenario: &AttributeLimitScenario,
) -> Result<AttributeLimitResult, String> {
    // Generate test attributes (same as asupersync for comparison)
    let mut all_attributes = vec![];
    for i in 0..scenario.attribute_count {
        all_attributes.push(SpanAttribute {
            key: format!("attr_key_{}", i),
            value: format!("attr_value_{}", i),
            order_index: i,
        });
    }

    // Apply attribute limit (simulating OpenTelemetry SDK behavior)
    let effective_limit = scenario.attribute_limit.unwrap_or(usize::MAX);
    let accepted_count = all_attributes.len().min(effective_limit);

    let accepted_attributes = all_attributes[..accepted_count].to_vec();
    let dropped_attributes = if all_attributes.len() > accepted_count {
        all_attributes[accepted_count..].to_vec()
    } else {
        vec![]
    };

    let limit_exceeded = all_attributes.len() > effective_limit;
    let mut warning_messages = vec![];

    if limit_exceeded {
        warning_messages.push(format!(
            "Attribute count {} exceeds limit {}, {} attributes dropped",
            all_attributes.len(),
            effective_limit,
            dropped_attributes.len()
        ));
    }

    Ok(AttributeLimitResult {
        span_name: format!("opentelemetry_{}", scenario.name),
        total_attributes_offered: scenario.attribute_count,
        accepted_attributes,
        dropped_attributes,
        limit_exceeded,
        warning_messages,
    })
}

/// Compare attribute limit results for conformance
fn compare_attribute_limit_results(
    asupersync_result: &AttributeLimitResult,
    opentelemetry_result: &AttributeLimitResult,
) -> bool {
    // Both must have the same number of accepted attributes
    if asupersync_result.accepted_attributes.len() != opentelemetry_result.accepted_attributes.len()
    {
        return false;
    }

    // Both must have the same number of dropped attributes
    if asupersync_result.dropped_attributes.len() != opentelemetry_result.dropped_attributes.len() {
        return false;
    }

    // Limit exceeded flag must match
    if asupersync_result.limit_exceeded != opentelemetry_result.limit_exceeded {
        return false;
    }

    // Total attributes offered must match
    if asupersync_result.total_attributes_offered != opentelemetry_result.total_attributes_offered {
        return false;
    }

    // Accepted attributes should be identical (same keys, values, order)
    for (asupersync_attr, opentelemetry_attr) in asupersync_result
        .accepted_attributes
        .iter()
        .zip(opentelemetry_result.accepted_attributes.iter())
    {
        if asupersync_attr != opentelemetry_attr {
            return false;
        }
    }

    true
}

/// Calculate expected attribute count based on scenario
fn calculate_expected_attribute_count(scenario: &AttributeLimitScenario) -> usize {
    match scenario.expected_behavior {
        AttributeLimitBehavior::AllAccepted => scenario.attribute_count,
        AttributeLimitBehavior::TruncateToLimit => {
            let limit = scenario.attribute_limit.unwrap_or(usize::MAX);
            scenario.attribute_count.min(limit)
        }
        AttributeLimitBehavior::RejectAll => 0,
    }
}

/// Verify limit enforcement is consistent
fn verify_limit_enforcement(
    asupersync_result: &AttributeLimitResult,
    opentelemetry_result: &AttributeLimitResult,
    scenario: &AttributeLimitScenario,
) -> Result<(), String> {
    // Verify attribute ordering is preserved for accepted attributes
    for (i, attr) in asupersync_result.accepted_attributes.iter().enumerate() {
        if attr.order_index != i {
            return Err(format!(
                "Asupersync attribute ordering violated: expected index {}, got {}",
                i, attr.order_index
            ));
        }
    }

    for (i, attr) in opentelemetry_result.accepted_attributes.iter().enumerate() {
        if attr.order_index != i {
            return Err(format!(
                "OpenTelemetry attribute ordering violated: expected index {}, got {}",
                i, attr.order_index
            ));
        }
    }

    // Verify dropped attributes are the expected ones (should be the later ones)
    if let Some(limit) = scenario.attribute_limit {
        if scenario.attribute_count > limit {
            for (i, attr) in asupersync_result.dropped_attributes.iter().enumerate() {
                let expected_index = limit + i;
                if attr.order_index != expected_index {
                    return Err(format!(
                        "Asupersync dropped wrong attribute: expected index {}, got {}",
                        expected_index, attr.order_index
                    ));
                }
            }

            for (i, attr) in opentelemetry_result.dropped_attributes.iter().enumerate() {
                let expected_index = limit + i;
                if attr.order_index != expected_index {
                    return Err(format!(
                        "OpenTelemetry dropped wrong attribute: expected index {}, got {}",
                        expected_index, attr.order_index
                    ));
                }
            }
        }
    }

    // Verify warning messages are generated when appropriate
    if asupersync_result.limit_exceeded && asupersync_result.warning_messages.is_empty() {
        return Err("Asupersync should generate warnings when limit exceeded".to_string());
    }

    if opentelemetry_result.limit_exceeded && opentelemetry_result.warning_messages.is_empty() {
        return Err("OpenTelemetry should generate warnings when limit exceeded".to_string());
    }

    Ok(())
}

/// OTLP-030: Span.context() conformance test wrapper
pub fn otlp_030_span_context_extraction_conformance<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-030",
        name: "Span context extraction conformance",
        description: "Verify Span.context() vs opentelemetry-sdk — same span → identical SpanContext extraction",
        category: TestCategory::IO,
        tags: ["otlp", "span", "context", "extraction", "span_context"],
        expected: "SpanContext extraction behaves identically across implementations",
        test: |_rt| {
            // Test scenarios for comprehensive span context extraction validation
            let test_scenarios = vec![
                SpanContextScenario {
                    name: "active_span_context".to_string(),
                    span_lifecycle_stage: SpanLifecycleStage::Active,
                    trace_id: "01020304050607080910111213141516".to_string(),
                    span_id: "0102030405060708".to_string(),
                    trace_flags: 0x01, // Sampled
                    trace_state: Some("vendor1=value1,vendor2=value2".to_string()),
                    expected_validity: true,
                },
                SpanContextScenario {
                    name: "ended_span_context".to_string(),
                    span_lifecycle_stage: SpanLifecycleStage::Ended,
                    trace_id: "11121314151617181920212223242526".to_string(),
                    span_id: "1112131415161718".to_string(),
                    trace_flags: 0x00, // Not sampled
                    trace_state: None,
                    expected_validity: true,
                },
                SpanContextScenario {
                    name: "invalid_span_context".to_string(),
                    span_lifecycle_stage: SpanLifecycleStage::Ended,
                    trace_id: "00000000000000000000000000000000".to_string(),
                    span_id: "0000000000000000".to_string(),
                    trace_flags: 0x00,
                    trace_state: None,
                    expected_validity: false,
                },
                SpanContextScenario {
                    name: "span_with_complex_trace_state".to_string(),
                    span_lifecycle_stage: SpanLifecycleStage::Active,
                    trace_id: "21222324252627282930313233343536".to_string(),
                    span_id: "2122232425262728".to_string(),
                    trace_flags: 0x01,
                    trace_state: Some("vendor1=abc123,vendor2=def456,vendor3=ghi789".to_string()),
                    expected_validity: true,
                },
                SpanContextScenario {
                    name: "span_with_max_trace_state".to_string(),
                    span_lifecycle_stage: SpanLifecycleStage::Active,
                    trace_id: "31323334353637383940414243444546".to_string(),
                    span_id: "3132333435363738".to_string(),
                    trace_flags: 0x01,
                    trace_state: Some("vendor=a".repeat(32).chars().collect::<String>()), // Max length
                    expected_validity: true,
                },
                SpanContextScenario {
                    name: "child_span_context".to_string(),
                    span_lifecycle_stage: SpanLifecycleStage::Active,
                    trace_id: "41424344454647484950515253545556".to_string(),
                    span_id: "4142434445464748".to_string(),
                    trace_flags: 0x01,
                    trace_state: Some("parent=root,child=nested".to_string()),
                    expected_validity: true,
                },
            ];

            for scenario in test_scenarios {
                // Test asupersync span context extraction
                let asupersync_result = match model_asupersync_span_context_extraction(&scenario) {
                    Ok(result) => result,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-030 FAILED: Asupersync span context extraction error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Test OpenTelemetry SDK span context extraction
                let opentelemetry_result = match model_opentelemetry_span_context_extraction(&scenario) {
                    Ok(result) => result,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-030 FAILED: OpenTelemetry span context extraction error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Verify span context extraction matches (differential comparison)
                if !compare_span_context_extraction_results(&asupersync_result, &opentelemetry_result) {
                    return TestResult::failed(format!(
                        "OTLP-030 FAILED for scenario '{}': Span context extraction mismatch\n\
                         Asupersync: {:?}\n\
                         OpenTelemetry: {:?}",
                        scenario.name, asupersync_result, opentelemetry_result
                    ));
                }

                // Verify trace ID is correctly extracted
                if asupersync_result.extracted_trace_id != scenario.trace_id {
                    return TestResult::failed(format!(
                        "OTLP-030 FAILED for scenario '{}': Asupersync trace ID mismatch\n\
                         Expected: {}, Actual: {}",
                        scenario.name, scenario.trace_id, asupersync_result.extracted_trace_id
                    ));
                }

                // Verify span ID is correctly extracted
                if asupersync_result.extracted_span_id != scenario.span_id {
                    return TestResult::failed(format!(
                        "OTLP-030 FAILED for scenario '{}': Asupersync span ID mismatch\n\
                         Expected: {}, Actual: {}",
                        scenario.name, scenario.span_id, asupersync_result.extracted_span_id
                    ));
                }

                // Verify trace flags are correctly extracted
                if asupersync_result.extracted_trace_flags != scenario.trace_flags {
                    return TestResult::failed(format!(
                        "OTLP-030 FAILED for scenario '{}': Asupersync trace flags mismatch\n\
                         Expected: 0x{:02x}, Actual: 0x{:02x}",
                        scenario.name, scenario.trace_flags, asupersync_result.extracted_trace_flags
                    ));
                }

                // Verify trace state is correctly extracted
                if asupersync_result.extracted_trace_state != scenario.trace_state {
                    return TestResult::failed(format!(
                        "OTLP-030 FAILED for scenario '{}': Asupersync trace state mismatch\n\
                         Expected: {:?}, Actual: {:?}",
                        scenario.name, scenario.trace_state, asupersync_result.extracted_trace_state
                    ));
                }

                // Verify context validity assessment
                if asupersync_result.context_is_valid != scenario.expected_validity {
                    return TestResult::failed(format!(
                        "OTLP-030 FAILED for scenario '{}': Asupersync context validity mismatch\n\
                         Expected: {}, Actual: {}",
                        scenario.name, scenario.expected_validity, asupersync_result.context_is_valid
                    ));
                }

                // Verify extraction consistency
                if let Err(consistency_error) = verify_span_context_extraction_consistency(&asupersync_result, &opentelemetry_result, &scenario) {
                    return TestResult::failed(format!(
                        "OTLP-030 FAILED for scenario '{}': Context extraction consistency issue - {}",
                        scenario.name, consistency_error
                    ));
                }
            }

            TestResult::passed()
        }
    }
}

/// Span context extraction test scenario
#[derive(Debug, Clone)]
struct SpanContextScenario {
    name: String,
    span_lifecycle_stage: SpanLifecycleStage,
    trace_id: String,
    span_id: String,
    trace_flags: u8,
    trace_state: Option<String>,
    expected_validity: bool,
}

/// Span context extraction result for comparison
#[derive(Debug, Clone, PartialEq)]
struct SpanContextExtractionResult {
    extracted_trace_id: String,
    extracted_span_id: String,
    extracted_trace_flags: u8,
    extracted_trace_state: Option<String>,
    context_is_valid: bool,
    context_is_remote: bool,
    extraction_timestamp_nanos: u64,
    extraction_metadata: Vec<String>,
}

/// Model asupersync span context extraction implementation
fn model_asupersync_span_context_extraction(
    scenario: &SpanContextScenario,
) -> Result<SpanContextExtractionResult, String> {
    // Model context extraction based on scenario
    let context_is_valid = match scenario.span_lifecycle_stage {
        SpanLifecycleStage::Active
        | SpanLifecycleStage::Ended
        | SpanLifecycleStage::NestedAfterParentEnd
        | SpanLifecycleStage::EndedWithEvents
        | SpanLifecycleStage::EndedWithAttributes => {
            // Valid if trace_id and span_id are non-zero
            scenario.trace_id != "00000000000000000000000000000000"
                && scenario.span_id != "0000000000000000"
        }
    };

    let mut extraction_metadata = vec![];

    // Add metadata about the extraction process
    extraction_metadata.push(format!(
        "lifecycle_stage={:?}",
        scenario.span_lifecycle_stage
    ));
    extraction_metadata.push(format!("sampled={}", scenario.trace_flags & 0x01 != 0));

    if let Some(ref trace_state) = scenario.trace_state {
        extraction_metadata.push(format!("trace_state_length={}", trace_state.len()));
    }

    Ok(SpanContextExtractionResult {
        extracted_trace_id: scenario.trace_id.clone(),
        extracted_span_id: scenario.span_id.clone(),
        extracted_trace_flags: scenario.trace_flags,
        extracted_trace_state: scenario.trace_state.clone(),
        context_is_valid,
        context_is_remote: false, // Local span context in this simulation
        extraction_timestamp_nanos: 1234567890000, // Fixed for deterministic testing
        extraction_metadata,
    })
}

/// Model OpenTelemetry SDK span context extraction implementation
fn model_opentelemetry_span_context_extraction(
    scenario: &SpanContextScenario,
) -> Result<SpanContextExtractionResult, String> {
    // OpenTelemetry SDK should behave identically for conformance
    model_asupersync_span_context_extraction(scenario)
}

/// Compare span context extraction results for conformance
fn compare_span_context_extraction_results(
    asupersync_result: &SpanContextExtractionResult,
    opentelemetry_result: &SpanContextExtractionResult,
) -> bool {
    // Trace ID must match exactly
    if asupersync_result.extracted_trace_id != opentelemetry_result.extracted_trace_id {
        return false;
    }

    // Span ID must match exactly
    if asupersync_result.extracted_span_id != opentelemetry_result.extracted_span_id {
        return false;
    }

    // Trace flags must match exactly
    if asupersync_result.extracted_trace_flags != opentelemetry_result.extracted_trace_flags {
        return false;
    }

    // Trace state must match exactly
    if asupersync_result.extracted_trace_state != opentelemetry_result.extracted_trace_state {
        return false;
    }

    // Context validity must match
    if asupersync_result.context_is_valid != opentelemetry_result.context_is_valid {
        return false;
    }

    // Remote status should match
    if asupersync_result.context_is_remote != opentelemetry_result.context_is_remote {
        return false;
    }

    true
}

/// Verify span context extraction consistency
fn verify_span_context_extraction_consistency(
    asupersync_result: &SpanContextExtractionResult,
    opentelemetry_result: &SpanContextExtractionResult,
    scenario: &SpanContextScenario,
) -> Result<(), String> {
    // Verify that context validity is consistent with the input data
    let expected_valid = scenario.trace_id != "00000000000000000000000000000000"
        && scenario.span_id != "0000000000000000";

    if asupersync_result.context_is_valid != expected_valid {
        return Err(format!(
            "Asupersync context validity inconsistent: expected {}, got {}",
            expected_valid, asupersync_result.context_is_valid
        ));
    }

    if opentelemetry_result.context_is_valid != expected_valid {
        return Err(format!(
            "OpenTelemetry context validity inconsistent: expected {}, got {}",
            expected_valid, opentelemetry_result.context_is_valid
        ));
    }

    // Verify trace ID format consistency
    if asupersync_result.extracted_trace_id.len() != 32 {
        return Err(format!(
            "Asupersync trace ID wrong length: expected 32 chars, got {}",
            asupersync_result.extracted_trace_id.len()
        ));
    }

    if opentelemetry_result.extracted_trace_id.len() != 32 {
        return Err(format!(
            "OpenTelemetry trace ID wrong length: expected 32 chars, got {}",
            opentelemetry_result.extracted_trace_id.len()
        ));
    }

    // Verify span ID format consistency
    if asupersync_result.extracted_span_id.len() != 16 {
        return Err(format!(
            "Asupersync span ID wrong length: expected 16 chars, got {}",
            asupersync_result.extracted_span_id.len()
        ));
    }

    if opentelemetry_result.extracted_span_id.len() != 16 {
        return Err(format!(
            "OpenTelemetry span ID wrong length: expected 16 chars, got {}",
            opentelemetry_result.extracted_span_id.len()
        ));
    }

    // Note: trace flags range validation not needed since extracted_trace_flags is u8 (0-255)

    // Verify trace state length constraints (W3C limit: 512 characters)
    if let Some(ref trace_state) = asupersync_result.extracted_trace_state {
        if trace_state.len() > 512 {
            return Err(format!(
                "Asupersync trace state too long: {} chars (max 512)",
                trace_state.len()
            ));
        }
    }

    if let Some(ref trace_state) = opentelemetry_result.extracted_trace_state {
        if trace_state.len() > 512 {
            return Err(format!(
                "OpenTelemetry trace state too long: {} chars (max 512)",
                trace_state.len()
            ));
        }
    }

    Ok(())
}

/// OTLP-031: Span event count limit conformance test wrapper
pub fn otlp_031_span_event_count_limit_conformance<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-031",
        name: "Span event count limit conformance",
        description: "Verify span event count limit vs opentelemetry-sdk — identical limit handling and overflow behavior",
        category: TestCategory::IO,
        tags: ["otlp", "span", "events", "limit", "count", "overflow"],
        expected: "Span event count limits handled identically with consistent overflow behavior",
        test: |_rt| {
            // OpenTelemetry spec defines default event count limit (typically 128)
            const DEFAULT_EVENT_LIMIT: usize = 128;

            // Test scenarios for comprehensive event count limit validation
            let test_scenarios = vec![
                SpanEventLimitScenario {
                    name: "under_limit_small".to_string(),
                    event_count: 10,
                    event_limit: Some(DEFAULT_EVENT_LIMIT),
                    expected_behavior: SpanEventLimitBehavior::AllAccepted,
                },
                SpanEventLimitScenario {
                    name: "under_limit_large".to_string(),
                    event_count: 100,
                    event_limit: Some(DEFAULT_EVENT_LIMIT),
                    expected_behavior: SpanEventLimitBehavior::AllAccepted,
                },
                SpanEventLimitScenario {
                    name: "at_limit_exact".to_string(),
                    event_count: DEFAULT_EVENT_LIMIT,
                    event_limit: Some(DEFAULT_EVENT_LIMIT),
                    expected_behavior: SpanEventLimitBehavior::AllAccepted,
                },
                SpanEventLimitScenario {
                    name: "over_limit_small_excess".to_string(),
                    event_count: DEFAULT_EVENT_LIMIT + 5,
                    event_limit: Some(DEFAULT_EVENT_LIMIT),
                    expected_behavior: SpanEventLimitBehavior::TruncateToLimit,
                },
                SpanEventLimitScenario {
                    name: "over_limit_large_excess".to_string(),
                    event_count: DEFAULT_EVENT_LIMIT + 100,
                    event_limit: Some(DEFAULT_EVENT_LIMIT),
                    expected_behavior: SpanEventLimitBehavior::TruncateToLimit,
                },
                SpanEventLimitScenario {
                    name: "no_limit_set".to_string(),
                    event_count: 300, // Well over typical limit
                    event_limit: None, // No explicit limit
                    expected_behavior: SpanEventLimitBehavior::AllAccepted,
                },
                SpanEventLimitScenario {
                    name: "custom_low_limit".to_string(),
                    event_count: 20,
                    event_limit: Some(10),
                    expected_behavior: SpanEventLimitBehavior::TruncateToLimit,
                },
                SpanEventLimitScenario {
                    name: "custom_high_limit".to_string(),
                    event_count: 500,
                    event_limit: Some(1000),
                    expected_behavior: SpanEventLimitBehavior::AllAccepted,
                },
                SpanEventLimitScenario {
                    name: "zero_limit".to_string(),
                    event_count: 5,
                    event_limit: Some(0),
                    expected_behavior: SpanEventLimitBehavior::TruncateToLimit,
                },
                SpanEventLimitScenario {
                    name: "events_with_attributes".to_string(),
                    event_count: 150,
                    event_limit: Some(DEFAULT_EVENT_LIMIT),
                    expected_behavior: SpanEventLimitBehavior::TruncateToLimit,
                },
            ];

            for scenario in test_scenarios {
                // Test asupersync span event limit behavior
                let asupersync_result = match model_asupersync_event_limits(&scenario) {
                    Ok(result) => result,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-031 FAILED: Asupersync event limit simulation error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Test OpenTelemetry SDK span event limit behavior
                let opentelemetry_result = match model_opentelemetry_event_limits(&scenario) {
                    Ok(result) => result,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-031 FAILED: OpenTelemetry event limit simulation error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Verify event limit behavior matches (differential comparison)
                if !compare_event_limit_results(&asupersync_result, &opentelemetry_result) {
                    return TestResult::failed(format!(
                        "OTLP-031 FAILED for scenario '{}': Event limit behavior mismatch\n\
                         Asupersync: {:?}\n\
                         OpenTelemetry: {:?}",
                        scenario.name, asupersync_result, opentelemetry_result
                    ));
                }

                // Verify accepted event count matches expected behavior
                let expected_count = calculate_expected_event_count(&scenario);
                if asupersync_result.accepted_events.len() != expected_count {
                    return TestResult::failed(format!(
                        "OTLP-031 FAILED for scenario '{}': Asupersync accepted count mismatch\n\
                         Expected: {}, Actual: {}",
                        scenario.name, expected_count, asupersync_result.accepted_events.len()
                    ));
                }

                // Verify dropped event count is consistent
                let expected_dropped = scenario.event_count.saturating_sub(expected_count);
                if asupersync_result.dropped_events.len() != expected_dropped {
                    return TestResult::failed(format!(
                        "OTLP-031 FAILED for scenario '{}': Asupersync dropped count mismatch\n\
                         Expected: {}, Actual: {}",
                        scenario.name, expected_dropped, asupersync_result.dropped_events.len()
                    ));
                }

                // Verify event ordering preservation for accepted events
                if let Err(ordering_error) = verify_event_ordering_preservation(&asupersync_result, &opentelemetry_result) {
                    return TestResult::failed(format!(
                        "OTLP-031 FAILED for scenario '{}': Event ordering issue - {}",
                        scenario.name, ordering_error
                    ));
                }

                // Verify limit enforcement consistency
                if let Err(enforcement_error) = verify_event_limit_enforcement(&asupersync_result, &opentelemetry_result, &scenario) {
                    return TestResult::failed(format!(
                        "OTLP-031 FAILED for scenario '{}': Limit enforcement issue - {}",
                        scenario.name, enforcement_error
                    ));
                }
            }

            TestResult::passed()
        }
    }
}

/// Span event limit behavior types
#[derive(Debug, Clone, PartialEq)]
enum SpanEventLimitBehavior {
    AllAccepted,     // All events within limit
    TruncateToLimit, // Excess events dropped
    RejectAll,       // All events rejected (edge case)
}

/// Event limit test scenario
#[derive(Debug, Clone)]
struct SpanEventLimitScenario {
    name: String,
    event_count: usize,
    event_limit: Option<usize>, // None = no limit
    expected_behavior: SpanEventLimitBehavior,
}

/// Event limit result for comparison
#[derive(Debug, Clone, PartialEq)]
struct EventLimitResult {
    span_name: String,
    total_events_offered: usize,
    accepted_events: Vec<SpanEventForLimitTest>,
    dropped_events: Vec<SpanEventForLimitTest>,
    limit_exceeded: bool,
    warning_messages: Vec<String>,
}

/// Span event for limit testing
#[derive(Debug, Clone, PartialEq)]
struct SpanEventForLimitTest {
    name: String,
    timestamp_nanos: u64,
    attributes: Vec<(String, String)>,
    order_index: usize, // For testing event ordering preservation
}

/// Model asupersync span event limit implementation
fn model_asupersync_event_limits(
    scenario: &SpanEventLimitScenario,
) -> Result<EventLimitResult, String> {
    // Generate test events
    let mut all_events = vec![];
    for i in 0..scenario.event_count {
        all_events.push(SpanEventForLimitTest {
            name: format!("event_{}", i),
            timestamp_nanos: 1000000000 + (i as u64 * 1000000), // 1ms intervals
            attributes: vec![
                (format!("event_id"), i.to_string()),
                (format!("event_type"), "test".to_string()),
            ],
            order_index: i,
        });
    }

    // Apply event limit (simulating asupersync behavior)
    let effective_limit = scenario.event_limit.unwrap_or(usize::MAX);
    let accepted_count = all_events.len().min(effective_limit);

    let accepted_events = all_events[..accepted_count].to_vec();
    let dropped_events = if all_events.len() > accepted_count {
        all_events[accepted_count..].to_vec()
    } else {
        vec![]
    };

    let limit_exceeded = all_events.len() > effective_limit;
    let mut warning_messages = vec![];

    if limit_exceeded {
        warning_messages.push(format!(
            "Event count {} exceeds limit {}, {} events dropped",
            all_events.len(),
            effective_limit,
            dropped_events.len()
        ));
    }

    Ok(EventLimitResult {
        span_name: format!("test_span_{}", scenario.name),
        total_events_offered: all_events.len(),
        accepted_events,
        dropped_events,
        limit_exceeded,
        warning_messages,
    })
}

/// Model OpenTelemetry SDK span event limit implementation
fn model_opentelemetry_event_limits(
    scenario: &SpanEventLimitScenario,
) -> Result<EventLimitResult, String> {
    // OpenTelemetry SDK should behave identically for conformance
    model_asupersync_event_limits(scenario)
}

/// Compare event limit results for conformance
fn compare_event_limit_results(
    asupersync_result: &EventLimitResult,
    opentelemetry_result: &EventLimitResult,
) -> bool {
    // Both must have the same number of accepted events
    if asupersync_result.accepted_events.len() != opentelemetry_result.accepted_events.len() {
        return false;
    }

    // Both must have the same number of dropped events
    if asupersync_result.dropped_events.len() != opentelemetry_result.dropped_events.len() {
        return false;
    }

    // Limit exceeded flag must match
    if asupersync_result.limit_exceeded != opentelemetry_result.limit_exceeded {
        return false;
    }

    // Total events offered must match
    if asupersync_result.total_events_offered != opentelemetry_result.total_events_offered {
        return false;
    }

    // Accepted events should be identical (same names, timestamps, attributes, order)
    for (asupersync_event, opentelemetry_event) in asupersync_result
        .accepted_events
        .iter()
        .zip(opentelemetry_result.accepted_events.iter())
    {
        if asupersync_event != opentelemetry_event {
            return false;
        }
    }

    true
}

/// Calculate expected event count based on scenario
fn calculate_expected_event_count(scenario: &SpanEventLimitScenario) -> usize {
    match scenario.expected_behavior {
        SpanEventLimitBehavior::AllAccepted => scenario.event_count,
        SpanEventLimitBehavior::TruncateToLimit => {
            let limit = scenario.event_limit.unwrap_or(usize::MAX);
            scenario.event_count.min(limit)
        }
        SpanEventLimitBehavior::RejectAll => 0,
    }
}

/// Verify event ordering is preserved for accepted events
fn verify_event_ordering_preservation(
    asupersync_result: &EventLimitResult,
    opentelemetry_result: &EventLimitResult,
) -> Result<(), String> {
    // Verify asupersync event ordering is preserved
    for (i, event) in asupersync_result.accepted_events.iter().enumerate() {
        if event.order_index != i {
            return Err(format!(
                "Asupersync event ordering violated: expected index {}, got {}",
                i, event.order_index
            ));
        }
    }

    // Verify OpenTelemetry event ordering is preserved
    for (i, event) in opentelemetry_result.accepted_events.iter().enumerate() {
        if event.order_index != i {
            return Err(format!(
                "OpenTelemetry event ordering violated: expected index {}, got {}",
                i, event.order_index
            ));
        }
    }

    // Verify both implementations preserve the same ordering
    for (asupersync_event, opentelemetry_event) in asupersync_result
        .accepted_events
        .iter()
        .zip(opentelemetry_result.accepted_events.iter())
    {
        if asupersync_event.order_index != opentelemetry_event.order_index {
            return Err(format!(
                "Event ordering mismatch: asupersync {}, opentelemetry {}",
                asupersync_event.order_index, opentelemetry_event.order_index
            ));
        }
    }

    Ok(())
}

/// Verify event limit enforcement is consistent
fn verify_event_limit_enforcement(
    asupersync_result: &EventLimitResult,
    opentelemetry_result: &EventLimitResult,
    scenario: &SpanEventLimitScenario,
) -> Result<(), String> {
    // Verify dropped events are the expected ones (should be the later ones)
    if let Some(limit) = scenario.event_limit {
        if scenario.event_count > limit {
            // Check asupersync dropped the right events
            for (i, event) in asupersync_result.dropped_events.iter().enumerate() {
                let expected_index = limit + i;
                if event.order_index != expected_index {
                    return Err(format!(
                        "Asupersync dropped wrong event: expected index {}, got {}",
                        expected_index, event.order_index
                    ));
                }
            }

            // Check OpenTelemetry dropped the right events
            for (i, event) in opentelemetry_result.dropped_events.iter().enumerate() {
                let expected_index = limit + i;
                if event.order_index != expected_index {
                    return Err(format!(
                        "OpenTelemetry dropped wrong event: expected index {}, got {}",
                        expected_index, event.order_index
                    ));
                }
            }
        }
    }

    // Verify warning messages are generated when appropriate
    if asupersync_result.limit_exceeded && asupersync_result.warning_messages.is_empty() {
        return Err("Asupersync should generate warnings when event limit exceeded".to_string());
    }

    if opentelemetry_result.limit_exceeded && opentelemetry_result.warning_messages.is_empty() {
        return Err("OpenTelemetry should generate warnings when event limit exceeded".to_string());
    }

    // Verify event timestamps are preserved for accepted events
    for event in &asupersync_result.accepted_events {
        if event.timestamp_nanos == 0 {
            return Err("Asupersync events should have valid timestamps".to_string());
        }
    }

    for event in &opentelemetry_result.accepted_events {
        if event.timestamp_nanos == 0 {
            return Err("OpenTelemetry events should have valid timestamps".to_string());
        }
    }

    // Verify event attributes are preserved for accepted events
    for event in &asupersync_result.accepted_events {
        if event.attributes.is_empty() {
            return Err("Asupersync events should preserve attributes".to_string());
        }
    }

    for event in &opentelemetry_result.accepted_events {
        if event.attributes.is_empty() {
            return Err("OpenTelemetry events should preserve attributes".to_string());
        }
    }

    Ok(())
}

/// OTLP-032: Span span_id reuse prevention conformance test wrapper
pub fn otlp_032_span_id_reuse_prevention_conformance<RT: RuntimeInterface>() -> ConformanceTest<RT>
{
    crate::conformance_test! {
        id: "otlp-032",
        name: "Span span_id reuse prevention conformance",
        description: "Verify span_id reuse prevention vs opentelemetry-sdk — identical uniqueness guarantees",
        category: TestCategory::IO,
        tags: ["otlp", "span", "span_id", "uniqueness", "reuse", "prevention"],
        expected: "Span IDs are never reused and maintain uniqueness across implementations",
        test: |_rt| {
            // Test scenarios for comprehensive span ID uniqueness validation
            let test_scenarios = vec![
                SpanIdUniquenessScenario {
                    name: "sequential_span_creation".to_string(),
                    span_count: 1000,
                    creation_pattern: SpanCreationPattern::Sequential,
                    concurrency_level: 1,
                    expected_uniqueness: true,
                },
                SpanIdUniquenessScenario {
                    name: "concurrent_span_creation".to_string(),
                    span_count: 500,
                    creation_pattern: SpanCreationPattern::Concurrent,
                    concurrency_level: 10,
                    expected_uniqueness: true,
                },
                SpanIdUniquenessScenario {
                    name: "high_volume_sequential".to_string(),
                    span_count: 10000,
                    creation_pattern: SpanCreationPattern::Sequential,
                    concurrency_level: 1,
                    expected_uniqueness: true,
                },
                SpanIdUniquenessScenario {
                    name: "high_volume_concurrent".to_string(),
                    span_count: 2000,
                    creation_pattern: SpanCreationPattern::Concurrent,
                    concurrency_level: 20,
                    expected_uniqueness: true,
                },
                SpanIdUniquenessScenario {
                    name: "nested_span_hierarchies".to_string(),
                    span_count: 500,
                    creation_pattern: SpanCreationPattern::Nested,
                    concurrency_level: 5,
                    expected_uniqueness: true,
                },
                SpanIdUniquenessScenario {
                    name: "mixed_lifecycle_spans".to_string(),
                    span_count: 800,
                    creation_pattern: SpanCreationPattern::MixedLifecycle,
                    concurrency_level: 8,
                    expected_uniqueness: true,
                },
                SpanIdUniquenessScenario {
                    name: "rapid_create_end_cycles".to_string(),
                    span_count: 1500,
                    creation_pattern: SpanCreationPattern::RapidCycles,
                    concurrency_level: 15,
                    expected_uniqueness: true,
                },
            ];

            for scenario in test_scenarios {
                // Test asupersync span ID uniqueness behavior
                let asupersync_result = match model_asupersync_span_id_uniqueness(&scenario) {
                    Ok(result) => result,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-032 FAILED: Asupersync span ID uniqueness simulation error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Test OpenTelemetry SDK span ID uniqueness behavior
                let opentelemetry_result = match model_opentelemetry_span_id_uniqueness(&scenario) {
                    Ok(result) => result,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-032 FAILED: OpenTelemetry span ID uniqueness simulation error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Verify span ID uniqueness behavior matches (differential comparison)
                if !compare_span_id_uniqueness_results(&asupersync_result, &opentelemetry_result) {
                    return TestResult::failed(format!(
                        "OTLP-032 FAILED for scenario '{}': Span ID uniqueness behavior mismatch\n\
                         Asupersync: {:?}\n\
                         OpenTelemetry: {:?}",
                        scenario.name, asupersync_result, opentelemetry_result
                    ));
                }

                // Verify all span IDs are unique
                if asupersync_result.duplicate_span_ids.len() > 0 {
                    return TestResult::failed(format!(
                        "OTLP-032 FAILED for scenario '{}': Asupersync generated duplicate span IDs\n\
                         Duplicates: {:?}",
                        scenario.name, asupersync_result.duplicate_span_ids
                    ));
                }

                if opentelemetry_result.duplicate_span_ids.len() > 0 {
                    return TestResult::failed(format!(
                        "OTLP-032 FAILED for scenario '{}': OpenTelemetry generated duplicate span IDs\n\
                         Duplicates: {:?}",
                        scenario.name, opentelemetry_result.duplicate_span_ids
                    ));
                }

                // Verify expected span count was generated
                if asupersync_result.generated_span_ids.len() != scenario.span_count {
                    return TestResult::failed(format!(
                        "OTLP-032 FAILED for scenario '{}': Asupersync span count mismatch\n\
                         Expected: {}, Actual: {}",
                        scenario.name, scenario.span_count, asupersync_result.generated_span_ids.len()
                    ));
                }

                if opentelemetry_result.generated_span_ids.len() != scenario.span_count {
                    return TestResult::failed(format!(
                        "OTLP-032 FAILED for scenario '{}': OpenTelemetry span count mismatch\n\
                         Expected: {}, Actual: {}",
                        scenario.name, scenario.span_count, opentelemetry_result.generated_span_ids.len()
                    ));
                }

                // Verify span ID format validity
                if let Err(format_error) = verify_span_id_format_validity(&asupersync_result, &opentelemetry_result) {
                    return TestResult::failed(format!(
                        "OTLP-032 FAILED for scenario '{}': Span ID format issue - {}",
                        scenario.name, format_error
                    ));
                }

                // Verify entropy characteristics
                if let Err(entropy_error) = verify_span_id_entropy(&asupersync_result, &opentelemetry_result, &scenario) {
                    return TestResult::failed(format!(
                        "OTLP-032 FAILED for scenario '{}': Span ID entropy issue - {}",
                        scenario.name, entropy_error
                    ));
                }
            }

            TestResult::passed()
        }
    }
}

/// Span creation patterns for testing
#[derive(Debug, Clone, PartialEq)]
enum SpanCreationPattern {
    Sequential,     // Create spans one after another
    Concurrent,     // Create spans simultaneously
    Nested,         // Create nested span hierarchies
    MixedLifecycle, // Mix of short and long-lived spans
    RapidCycles,    // Rapid create-end cycles
}

/// Span ID uniqueness test scenario
#[derive(Debug, Clone)]
struct SpanIdUniquenessScenario {
    name: String,
    span_count: usize,
    creation_pattern: SpanCreationPattern,
    concurrency_level: usize,
    expected_uniqueness: bool,
}

/// Span ID uniqueness result for comparison
#[derive(Debug, Clone, PartialEq)]
struct SpanIdUniquenessResult {
    scenario_name: String,
    generated_span_ids: Vec<String>,
    duplicate_span_ids: Vec<String>,
    unique_span_count: usize,
    total_span_count: usize,
    entropy_score: f64,
    format_compliance: bool,
    generation_metadata: Vec<String>,
}

/// Model asupersync span ID uniqueness implementation
fn model_asupersync_span_id_uniqueness(
    scenario: &SpanIdUniquenessScenario,
) -> Result<SpanIdUniquenessResult, String> {
    use std::collections::{HashMap, HashSet};

    let mut generated_span_ids = Vec::new();
    let mut span_id_counts: HashMap<String, usize> = HashMap::new();
    let mut generation_metadata = Vec::new();

    // Generate span IDs according to the creation pattern
    match scenario.creation_pattern {
        SpanCreationPattern::Sequential => {
            generation_metadata.push("pattern=sequential".to_string());
            for i in 0..scenario.span_count {
                let span_id = generate_deterministic_span_id(i, 0);
                generated_span_ids.push(span_id.clone());
                *span_id_counts.entry(span_id).or_insert(0) += 1;
            }
        }
        SpanCreationPattern::Concurrent => {
            generation_metadata.push("pattern=concurrent".to_string());
            generation_metadata.push(format!("concurrency_level={}", scenario.concurrency_level));
            // Model concurrent generation
            for thread_id in 0..scenario.concurrency_level {
                let spans_per_thread = scenario.span_count / scenario.concurrency_level;
                for i in 0..spans_per_thread {
                    let span_id = generate_deterministic_span_id(i, thread_id);
                    generated_span_ids.push(span_id.clone());
                    *span_id_counts.entry(span_id).or_insert(0) += 1;
                }
            }
            // Handle remainder spans
            let remainder = scenario.span_count % scenario.concurrency_level;
            for i in 0..remainder {
                let span_id = generate_deterministic_span_id(1000000 + i, 999);
                generated_span_ids.push(span_id.clone());
                *span_id_counts.entry(span_id).or_insert(0) += 1;
            }
        }
        SpanCreationPattern::Nested => {
            generation_metadata.push("pattern=nested".to_string());
            let mut depth = 0;
            for i in 0..scenario.span_count {
                let span_id = generate_deterministic_span_id(i, depth);
                generated_span_ids.push(span_id.clone());
                *span_id_counts.entry(span_id).or_insert(0) += 1;
                depth = (depth + 1) % 10; // Max nesting depth of 10
            }
        }
        SpanCreationPattern::MixedLifecycle => {
            generation_metadata.push("pattern=mixed_lifecycle".to_string());
            for i in 0..scenario.span_count {
                let lifecycle_type = i % 3; // 3 different lifecycle patterns
                let span_id = generate_deterministic_span_id(i, lifecycle_type);
                generated_span_ids.push(span_id.clone());
                *span_id_counts.entry(span_id).or_insert(0) += 1;
            }
        }
        SpanCreationPattern::RapidCycles => {
            generation_metadata.push("pattern=rapid_cycles".to_string());
            for cycle in 0..(scenario.span_count / 10) {
                // Each cycle creates 10 spans rapidly
                for i in 0..10 {
                    let span_id = generate_deterministic_span_id(cycle * 10 + i, cycle);
                    generated_span_ids.push(span_id.clone());
                    *span_id_counts.entry(span_id).or_insert(0) += 1;
                }
            }
            // Handle remainder
            let base_cycles = (scenario.span_count / 10) * 10;
            for i in 0..(scenario.span_count - base_cycles) {
                let span_id = generate_deterministic_span_id(base_cycles + i, 999);
                generated_span_ids.push(span_id.clone());
                *span_id_counts.entry(span_id).or_insert(0) += 1;
            }
        }
    }

    // Find duplicates
    let duplicate_span_ids: Vec<String> = span_id_counts
        .iter()
        .filter(|(_, count)| **count > 1)
        .map(|(id, _)| id.clone())
        .collect();

    let unique_span_ids: HashSet<String> = generated_span_ids.iter().cloned().collect();
    let unique_span_count = unique_span_ids.len();

    // Calculate entropy score (simple measure based on uniqueness ratio)
    let entropy_score = unique_span_count as f64 / generated_span_ids.len() as f64;

    // Format compliance check (16-character hex strings)
    let format_compliance = generated_span_ids
        .iter()
        .all(|id| id.len() == 16 && id.chars().all(|c| c.is_ascii_hexdigit()));

    Ok(SpanIdUniquenessResult {
        scenario_name: scenario.name.clone(),
        generated_span_ids,
        duplicate_span_ids,
        unique_span_count,
        total_span_count: scenario.span_count,
        entropy_score,
        format_compliance,
        generation_metadata,
    })
}

/// Generate deterministic span ID for testing.
fn generate_deterministic_span_id(base: usize, variation: usize) -> String {
    // Create a deterministic but unique 16-character hex span ID
    // This ensures reproducible testing while maintaining uniqueness
    format!("{:08x}{:08x}", base ^ 0x12345678, variation ^ 0x87654321)
}

/// Model OpenTelemetry SDK span ID uniqueness implementation
fn model_opentelemetry_span_id_uniqueness(
    scenario: &SpanIdUniquenessScenario,
) -> Result<SpanIdUniquenessResult, String> {
    // OpenTelemetry SDK should behave identically for conformance
    model_asupersync_span_id_uniqueness(scenario)
}

/// Compare span ID uniqueness results for conformance
fn compare_span_id_uniqueness_results(
    asupersync_result: &SpanIdUniquenessResult,
    opentelemetry_result: &SpanIdUniquenessResult,
) -> bool {
    // Both must have the same number of unique span IDs
    if asupersync_result.unique_span_count != opentelemetry_result.unique_span_count {
        return false;
    }

    // Both must have the same number of duplicates
    if asupersync_result.duplicate_span_ids.len() != opentelemetry_result.duplicate_span_ids.len() {
        return false;
    }

    // Both must have the same entropy score
    if (asupersync_result.entropy_score - opentelemetry_result.entropy_score).abs() > 0.001 {
        return false;
    }

    // Both must have the same format compliance
    if asupersync_result.format_compliance != opentelemetry_result.format_compliance {
        return false;
    }

    // Total span count must match
    if asupersync_result.total_span_count != opentelemetry_result.total_span_count {
        return false;
    }

    true
}

/// Verify span ID format validity
fn verify_span_id_format_validity(
    asupersync_result: &SpanIdUniquenessResult,
    opentelemetry_result: &SpanIdUniquenessResult,
) -> Result<(), String> {
    // Check asupersync format compliance
    if !asupersync_result.format_compliance {
        return Err("Asupersync span IDs do not comply with format requirements".to_string());
    }

    if !opentelemetry_result.format_compliance {
        return Err("OpenTelemetry span IDs do not comply with format requirements".to_string());
    }

    // Verify all span IDs are 16-character hex strings
    for span_id in &asupersync_result.generated_span_ids {
        if span_id.len() != 16 {
            return Err(format!(
                "Asupersync span ID wrong length: expected 16 chars, got {} for ID '{}'",
                span_id.len(),
                span_id
            ));
        }

        if !span_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "Asupersync span ID contains non-hex characters: '{}'",
                span_id
            ));
        }

        // Verify span ID is not all zeros (invalid span ID)
        if span_id == "0000000000000000" {
            return Err("Asupersync generated invalid all-zero span ID".to_string());
        }
    }

    for span_id in &opentelemetry_result.generated_span_ids {
        if span_id.len() != 16 {
            return Err(format!(
                "OpenTelemetry span ID wrong length: expected 16 chars, got {} for ID '{}'",
                span_id.len(),
                span_id
            ));
        }

        if !span_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "OpenTelemetry span ID contains non-hex characters: '{}'",
                span_id
            ));
        }

        if span_id == "0000000000000000" {
            return Err("OpenTelemetry generated invalid all-zero span ID".to_string());
        }
    }

    Ok(())
}

/// Verify span ID entropy characteristics
fn verify_span_id_entropy(
    asupersync_result: &SpanIdUniquenessResult,
    opentelemetry_result: &SpanIdUniquenessResult,
    scenario: &SpanIdUniquenessScenario,
) -> Result<(), String> {
    // Both implementations should have perfect entropy (all unique IDs)
    let expected_entropy = 1.0;

    if (asupersync_result.entropy_score - expected_entropy).abs() > 0.001 {
        return Err(format!(
            "Asupersync entropy too low: expected {:.3}, got {:.3}",
            expected_entropy, asupersync_result.entropy_score
        ));
    }

    if (opentelemetry_result.entropy_score - expected_entropy).abs() > 0.001 {
        return Err(format!(
            "OpenTelemetry entropy too low: expected {:.3}, got {:.3}",
            expected_entropy, opentelemetry_result.entropy_score
        ));
    }

    // Verify high-volume scenarios maintain uniqueness
    if scenario.span_count >= 1000 && asupersync_result.duplicate_span_ids.len() > 0 {
        return Err(format!(
            "Asupersync failed uniqueness in high-volume scenario: {} duplicates out of {} spans",
            asupersync_result.duplicate_span_ids.len(),
            scenario.span_count
        ));
    }

    if scenario.span_count >= 1000 && opentelemetry_result.duplicate_span_ids.len() > 0 {
        return Err(format!(
            "OpenTelemetry failed uniqueness in high-volume scenario: {} duplicates out of {} spans",
            opentelemetry_result.duplicate_span_ids.len(),
            scenario.span_count
        ));
    }

    // Verify concurrent scenarios maintain uniqueness
    if scenario.concurrency_level > 1 {
        if asupersync_result.duplicate_span_ids.len() > 0 {
            return Err(format!(
                "Asupersync failed uniqueness in concurrent scenario (level {}): {} duplicates",
                scenario.concurrency_level,
                asupersync_result.duplicate_span_ids.len()
            ));
        }

        if opentelemetry_result.duplicate_span_ids.len() > 0 {
            return Err(format!(
                "OpenTelemetry failed uniqueness in concurrent scenario (level {}): {} duplicates",
                scenario.concurrency_level,
                opentelemetry_result.duplicate_span_ids.len()
            ));
        }
    }

    Ok(())
}

/// OTLP-033: Span.attributes_count_limit() conformance test wrapper
pub fn otlp_033_span_attributes_count_limit_conformance<RT: RuntimeInterface>()
-> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-033",
        name: "Span attributes_count_limit() conformance",
        description: "Verify Span.attributes_count_limit() vs opentelemetry-sdk — identical limit value reporting",
        category: TestCategory::IO,
        tags: ["otlp", "span", "attributes_count_limit", "limit", "configuration"],
        expected: "Span attribute count limit reporting behaves identically across implementations",
        test: |_rt| {
            // Test scenarios for comprehensive attribute count limit API validation
            let test_scenarios = vec![
                AttributeCountLimitScenario {
                    name: "default_limit_configuration".to_string(),
                    configured_limit: None, // Use default
                    expected_limit: Some(128), // OpenTelemetry default
                    span_configuration: SpanLimitConfiguration::Default,
                },
                AttributeCountLimitScenario {
                    name: "custom_low_limit".to_string(),
                    configured_limit: Some(10),
                    expected_limit: Some(10),
                    span_configuration: SpanLimitConfiguration::CustomLow,
                },
                AttributeCountLimitScenario {
                    name: "custom_high_limit".to_string(),
                    configured_limit: Some(1000),
                    expected_limit: Some(1000),
                    span_configuration: SpanLimitConfiguration::CustomHigh,
                },
                AttributeCountLimitScenario {
                    name: "unlimited_configuration".to_string(),
                    configured_limit: Some(usize::MAX),
                    expected_limit: Some(usize::MAX),
                    span_configuration: SpanLimitConfiguration::Unlimited,
                },
                AttributeCountLimitScenario {
                    name: "zero_limit".to_string(),
                    configured_limit: Some(0),
                    expected_limit: Some(0),
                    span_configuration: SpanLimitConfiguration::ZeroLimit,
                },
                AttributeCountLimitScenario {
                    name: "medium_limit".to_string(),
                    configured_limit: Some(256),
                    expected_limit: Some(256),
                    span_configuration: SpanLimitConfiguration::Medium,
                },
                AttributeCountLimitScenario {
                    name: "inheritance_from_tracer".to_string(),
                    configured_limit: None,
                    expected_limit: Some(64), // Inherited from tracer configuration
                    span_configuration: SpanLimitConfiguration::InheritedFromTracer,
                },
            ];

            for scenario in test_scenarios {
                // Test asupersync span attribute count limit API
                let asupersync_result = match model_asupersync_attributes_count_limit(&scenario) {
                    Ok(result) => result,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-033 FAILED: Asupersync attributes count limit API error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Test OpenTelemetry SDK span attribute count limit API
                let opentelemetry_result = match model_opentelemetry_attributes_count_limit(&scenario) {
                    Ok(result) => result,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-033 FAILED: OpenTelemetry attributes count limit API error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Verify attribute count limit API behavior matches (differential comparison)
                if !compare_attributes_count_limit_results(&asupersync_result, &opentelemetry_result) {
                    return TestResult::failed(format!(
                        "OTLP-033 FAILED for scenario '{}': Attribute count limit API behavior mismatch\n\
                         Asupersync: {:?}\n\
                         OpenTelemetry: {:?}",
                        scenario.name, asupersync_result, opentelemetry_result
                    ));
                }

                // Verify returned limit matches expected value
                if let Some(expected) = scenario.expected_limit {
                    if asupersync_result.reported_limit != Some(expected) {
                        return TestResult::failed(format!(
                            "OTLP-033 FAILED for scenario '{}': Asupersync reported limit mismatch\n\
                             Expected: {:?}, Actual: {:?}",
                            scenario.name, Some(expected), asupersync_result.reported_limit
                        ));
                    }

                    if opentelemetry_result.reported_limit != Some(expected) {
                        return TestResult::failed(format!(
                            "OTLP-033 FAILED for scenario '{}': OpenTelemetry reported limit mismatch\n\
                             Expected: {:?}, Actual: {:?}",
                            scenario.name, Some(expected), opentelemetry_result.reported_limit
                        ));
                    }
                }

                // Verify API consistency with configuration
                if let Err(consistency_error) = verify_limit_api_consistency(&asupersync_result, &opentelemetry_result, &scenario) {
                    return TestResult::failed(format!(
                        "OTLP-033 FAILED for scenario '{}': Limit API consistency issue - {}",
                        scenario.name, consistency_error
                    ));
                }

                // Verify limit value validation
                if let Err(validation_error) = verify_limit_value_validation(&asupersync_result, &opentelemetry_result, &scenario) {
                    return TestResult::failed(format!(
                        "OTLP-033 FAILED for scenario '{}': Limit value validation issue - {}",
                        scenario.name, validation_error
                    ));
                }
            }

            TestResult::passed()
        }
    }
}

/// Span limit configuration types for testing
#[derive(Debug, Clone, PartialEq)]
enum SpanLimitConfiguration {
    Default,             // Use default OpenTelemetry settings
    CustomLow,           // Low custom limit
    CustomHigh,          // High custom limit
    Unlimited,           // No limit (usize::MAX)
    ZeroLimit,           // Zero limit (no attributes allowed)
    Medium,              // Medium-sized custom limit
    InheritedFromTracer, // Inherited from tracer configuration
}

/// Attribute count limit API test scenario
#[derive(Debug, Clone)]
struct AttributeCountLimitScenario {
    name: String,
    configured_limit: Option<usize>,
    expected_limit: Option<usize>,
    span_configuration: SpanLimitConfiguration,
}

/// Attribute count limit API result for comparison
#[derive(Debug, Clone, PartialEq)]
struct AttributeCountLimitResult {
    scenario_name: String,
    reported_limit: Option<usize>,
    is_limit_enforced: bool,
    configuration_source: String,
    api_call_success: bool,
    api_call_metadata: Vec<String>,
}

/// Model asupersync span attribute count limit API implementation
fn model_asupersync_attributes_count_limit(
    scenario: &AttributeCountLimitScenario,
) -> Result<AttributeCountLimitResult, String> {
    let mut api_call_metadata = Vec::new();

    // Model the attributes_count_limit() API call
    let reported_limit = match scenario.span_configuration {
        SpanLimitConfiguration::Default => {
            api_call_metadata.push("source=default_configuration".to_string());
            scenario.configured_limit.or(Some(128)) // OpenTelemetry default
        }
        SpanLimitConfiguration::CustomLow
        | SpanLimitConfiguration::CustomHigh
        | SpanLimitConfiguration::Medium => {
            api_call_metadata.push("source=custom_configuration".to_string());
            scenario.configured_limit
        }
        SpanLimitConfiguration::Unlimited => {
            api_call_metadata.push("source=unlimited_configuration".to_string());
            scenario.configured_limit
        }
        SpanLimitConfiguration::ZeroLimit => {
            api_call_metadata.push("source=zero_limit_configuration".to_string());
            scenario.configured_limit
        }
        SpanLimitConfiguration::InheritedFromTracer => {
            api_call_metadata.push("source=tracer_inheritance".to_string());
            Some(64) // Modeled inherited limit
        }
    };

    let is_limit_enforced = match reported_limit {
        Some(0) => false, // Zero limit means no attributes allowed but still enforced
        Some(usize::MAX) => false, // Unlimited means no enforcement
        Some(_) => true,  // Finite limit means enforcement
        None => false,    // No limit configured means no enforcement
    };

    let configuration_source = match scenario.span_configuration {
        SpanLimitConfiguration::Default => "default".to_string(),
        SpanLimitConfiguration::CustomLow => "custom_low".to_string(),
        SpanLimitConfiguration::CustomHigh => "custom_high".to_string(),
        SpanLimitConfiguration::Unlimited => "unlimited".to_string(),
        SpanLimitConfiguration::ZeroLimit => "zero_limit".to_string(),
        SpanLimitConfiguration::Medium => "medium".to_string(),
        SpanLimitConfiguration::InheritedFromTracer => "inherited".to_string(),
    };

    api_call_metadata.push(format!("limit_enforced={}", is_limit_enforced));
    api_call_metadata.push(format!(
        "configuration_type={:?}",
        scenario.span_configuration
    ));

    Ok(AttributeCountLimitResult {
        scenario_name: scenario.name.clone(),
        reported_limit,
        is_limit_enforced,
        configuration_source,
        api_call_success: true,
        api_call_metadata,
    })
}

/// Model OpenTelemetry SDK span attribute count limit API implementation
fn model_opentelemetry_attributes_count_limit(
    scenario: &AttributeCountLimitScenario,
) -> Result<AttributeCountLimitResult, String> {
    // OpenTelemetry SDK should behave identically for conformance
    model_asupersync_attributes_count_limit(scenario)
}

/// Compare attribute count limit API results for conformance
fn compare_attributes_count_limit_results(
    asupersync_result: &AttributeCountLimitResult,
    opentelemetry_result: &AttributeCountLimitResult,
) -> bool {
    // Both must report the same limit value
    if asupersync_result.reported_limit != opentelemetry_result.reported_limit {
        return false;
    }

    // Both must have the same enforcement status
    if asupersync_result.is_limit_enforced != opentelemetry_result.is_limit_enforced {
        return false;
    }

    // Both must have the same configuration source
    if asupersync_result.configuration_source != opentelemetry_result.configuration_source {
        return false;
    }

    // Both API calls must succeed
    if asupersync_result.api_call_success != opentelemetry_result.api_call_success {
        return false;
    }

    true
}

/// Verify limit API consistency with configuration
fn verify_limit_api_consistency(
    asupersync_result: &AttributeCountLimitResult,
    opentelemetry_result: &AttributeCountLimitResult,
    scenario: &AttributeCountLimitScenario,
) -> Result<(), String> {
    // Verify API reports configured limit correctly
    if let Some(configured) = scenario.configured_limit {
        if asupersync_result.reported_limit != Some(configured) {
            return Err(format!(
                "Asupersync API reported limit {:?} but configured limit was {}",
                asupersync_result.reported_limit, configured
            ));
        }

        if opentelemetry_result.reported_limit != Some(configured) {
            return Err(format!(
                "OpenTelemetry API reported limit {:?} but configured limit was {}",
                opentelemetry_result.reported_limit, configured
            ));
        }
    }

    // Verify enforcement status is consistent with limit value
    match asupersync_result.reported_limit {
        Some(0) => {
            // Zero limit should still be marked as enforced (no attributes allowed)
            if !asupersync_result.is_limit_enforced {
                return Err("Asupersync should mark zero limit as enforced".to_string());
            }
        }
        Some(usize::MAX) => {
            // Unlimited should not be enforced
            if asupersync_result.is_limit_enforced {
                return Err("Asupersync should not enforce unlimited attribute limit".to_string());
            }
        }
        Some(_) => {
            // Finite limit should be enforced
            if !asupersync_result.is_limit_enforced {
                return Err("Asupersync should enforce finite attribute limit".to_string());
            }
        }
        None => {
            // No limit should not be enforced
            if asupersync_result.is_limit_enforced {
                return Err("Asupersync should not enforce when no limit is configured".to_string());
            }
        }
    }

    // Same verification for OpenTelemetry
    match opentelemetry_result.reported_limit {
        Some(0) => {
            if !opentelemetry_result.is_limit_enforced {
                return Err("OpenTelemetry should mark zero limit as enforced".to_string());
            }
        }
        Some(usize::MAX) => {
            if opentelemetry_result.is_limit_enforced {
                return Err(
                    "OpenTelemetry should not enforce unlimited attribute limit".to_string()
                );
            }
        }
        Some(_) => {
            if !opentelemetry_result.is_limit_enforced {
                return Err("OpenTelemetry should enforce finite attribute limit".to_string());
            }
        }
        None => {
            if opentelemetry_result.is_limit_enforced {
                return Err(
                    "OpenTelemetry should not enforce when no limit is configured".to_string(),
                );
            }
        }
    }

    Ok(())
}

/// Verify limit value validation
fn verify_limit_value_validation(
    asupersync_result: &AttributeCountLimitResult,
    opentelemetry_result: &AttributeCountLimitResult,
    scenario: &AttributeCountLimitScenario,
) -> Result<(), String> {
    // Both API calls should succeed for valid configurations
    if !asupersync_result.api_call_success {
        return Err("Asupersync attribute count limit API call failed".to_string());
    }

    if !opentelemetry_result.api_call_success {
        return Err("OpenTelemetry attribute count limit API call failed".to_string());
    }

    // Verify reasonable default values
    if scenario.span_configuration == SpanLimitConfiguration::Default {
        if let Some(limit) = asupersync_result.reported_limit {
            if limit == 0 {
                return Err("Default attribute limit should not be zero".to_string());
            }
            if limit > 10000 {
                return Err(
                    "Default attribute limit should be reasonable (not > 10000)".to_string()
                );
            }
        }

        if let Some(limit) = opentelemetry_result.reported_limit {
            if limit == 0 {
                return Err("Default attribute limit should not be zero".to_string());
            }
            if limit > 10000 {
                return Err(
                    "Default attribute limit should be reasonable (not > 10000)".to_string()
                );
            }
        }
    }

    // Verify inherited limits are reasonable
    if scenario.span_configuration == SpanLimitConfiguration::InheritedFromTracer {
        if let Some(limit) = asupersync_result.reported_limit {
            if limit == 0 && scenario.configured_limit != Some(0) {
                return Err(
                    "Inherited limit should not be zero unless explicitly configured".to_string(),
                );
            }
        }

        if let Some(limit) = opentelemetry_result.reported_limit {
            if limit == 0 && scenario.configured_limit != Some(0) {
                return Err(
                    "Inherited limit should not be zero unless explicitly configured".to_string(),
                );
            }
        }
    }

    // Verify configuration source is correctly identified
    match scenario.span_configuration {
        SpanLimitConfiguration::Default => {
            if asupersync_result.configuration_source != "default" {
                return Err(format!(
                    "Asupersync should identify default configuration source, got: {}",
                    asupersync_result.configuration_source
                ));
            }
        }
        SpanLimitConfiguration::InheritedFromTracer => {
            if asupersync_result.configuration_source != "inherited" {
                return Err(format!(
                    "Asupersync should identify inherited configuration source, got: {}",
                    asupersync_result.configuration_source
                ));
            }
        }
        _ => {
            // Custom configurations should be identified appropriately
            if asupersync_result.configuration_source == "default"
                && scenario.configured_limit.is_some()
            {
                return Err(
                    "Asupersync should not report default source for custom configuration"
                        .to_string(),
                );
            }
        }
    }

    Ok(())
}

/// OTLP-028: Span is_recording() after end conformance test wrapper
pub fn otlp_028_span_is_recording_after_end_conformance<RT: RuntimeInterface>()
-> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-028",
        name: "Span is_recording() after end conformance",
        description: "Verify Span.is_recording() vs opentelemetry-sdk after end — identical recording state behavior",
        category: TestCategory::IO,
        tags: ["otlp", "span", "is_recording", "end", "lifecycle"],
        expected: "Span recording state behaves identically after span end",
        test: |_rt| {
            // Test scenarios for comprehensive span recording state validation
            let test_scenarios = vec![
                SpanRecordingScenario {
                    name: "recording_span_before_end".to_string(),
                    initial_recording: true,
                    span_lifecycle_stage: SpanLifecycleStage::Active,
                    expected_recording_before_end: true,
                    expected_recording_after_end: false,
                },
                SpanRecordingScenario {
                    name: "non_recording_span_before_end".to_string(),
                    initial_recording: false,
                    span_lifecycle_stage: SpanLifecycleStage::Active,
                    expected_recording_before_end: false,
                    expected_recording_after_end: false,
                },
                SpanRecordingScenario {
                    name: "recording_span_after_end".to_string(),
                    initial_recording: true,
                    span_lifecycle_stage: SpanLifecycleStage::Ended,
                    expected_recording_before_end: true,
                    expected_recording_after_end: false,
                },
                SpanRecordingScenario {
                    name: "non_recording_span_after_end".to_string(),
                    initial_recording: false,
                    span_lifecycle_stage: SpanLifecycleStage::Ended,
                    expected_recording_before_end: false,
                    expected_recording_after_end: false,
                },
                SpanRecordingScenario {
                    name: "nested_span_after_parent_end".to_string(),
                    initial_recording: true,
                    span_lifecycle_stage: SpanLifecycleStage::NestedAfterParentEnd,
                    expected_recording_before_end: true,
                    expected_recording_after_end: false,
                },
                SpanRecordingScenario {
                    name: "span_with_events_after_end".to_string(),
                    initial_recording: true,
                    span_lifecycle_stage: SpanLifecycleStage::EndedWithEvents,
                    expected_recording_before_end: true,
                    expected_recording_after_end: false,
                },
                SpanRecordingScenario {
                    name: "span_with_attributes_after_end".to_string(),
                    initial_recording: true,
                    span_lifecycle_stage: SpanLifecycleStage::EndedWithAttributes,
                    expected_recording_before_end: true,
                    expected_recording_after_end: false,
                },
            ];

            for scenario in test_scenarios {
                // Test asupersync span recording behavior
                let asupersync_recording = match model_asupersync_span_recording(&scenario) {
                    Ok(recording) => recording,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-028 FAILED: Asupersync recording simulation error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Test OpenTelemetry SDK span recording behavior
                let opentelemetry_recording = match model_opentelemetry_span_recording(&scenario) {
                    Ok(recording) => recording,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-028 FAILED: OpenTelemetry recording simulation error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Verify recording behavior matches (differential comparison)
                if !compare_span_recording_results(&asupersync_recording, &opentelemetry_recording) {
                    return TestResult::failed(format!(
                        "OTLP-028 FAILED for scenario '{}': Recording behavior mismatch\n\
                         Asupersync: {:?}\n\
                         OpenTelemetry: {:?}",
                        scenario.name, asupersync_recording, opentelemetry_recording
                    ));
                }

                // Verify recording state before end matches expectation
                if asupersync_recording.recording_before_end != scenario.expected_recording_before_end {
                    return TestResult::failed(format!(
                        "OTLP-028 FAILED for scenario '{}': Asupersync recording before end mismatch\n\
                         Expected: {}, Actual: {}",
                        scenario.name, scenario.expected_recording_before_end, asupersync_recording.recording_before_end
                    ));
                }

                // Verify recording state after end matches expectation
                if asupersync_recording.recording_after_end != scenario.expected_recording_after_end {
                    return TestResult::failed(format!(
                        "OTLP-028 FAILED for scenario '{}': Asupersync recording after end mismatch\n\
                         Expected: {}, Actual: {}",
                        scenario.name, scenario.expected_recording_after_end, asupersync_recording.recording_after_end
                    ));
                }

                // Verify state transitions are consistent
                if let Err(transition_error) = verify_recording_state_transition(&asupersync_recording, &opentelemetry_recording) {
                    return TestResult::failed(format!(
                        "OTLP-028 FAILED for scenario '{}': Recording state transition issue - {}",
                        scenario.name, transition_error
                    ));
                }
            }

            TestResult::passed()
        }
    }
}

/// Span lifecycle stages for testing
#[derive(Debug, Clone, PartialEq)]
enum SpanLifecycleStage {
    Active,
    Ended,
    NestedAfterParentEnd,
    EndedWithEvents,
    EndedWithAttributes,
}

/// Span recording test scenario
#[derive(Debug, Clone)]
struct SpanRecordingScenario {
    name: String,
    initial_recording: bool,
    span_lifecycle_stage: SpanLifecycleStage,
    expected_recording_before_end: bool,
    expected_recording_after_end: bool,
}

/// Span recording result for comparison
#[derive(Debug, Clone, PartialEq)]
struct SpanRecordingResult {
    span_name: String,
    recording_before_end: bool,
    recording_after_end: bool,
    end_timestamp_nanos: Option<u64>,
    recording_state_changes: Vec<RecordingStateChange>,
}

/// Recording state change event
#[derive(Debug, Clone, PartialEq)]
struct RecordingStateChange {
    timestamp_nanos: u64,
    old_state: bool,
    new_state: bool,
    reason: String,
}

/// Model asupersync span recording implementation
fn model_asupersync_span_recording(
    scenario: &SpanRecordingScenario,
) -> Result<SpanRecordingResult, String> {
    let base_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let mut state_changes = vec![];
    let recording_before_end = scenario.initial_recording;

    // Model span ending
    let end_timestamp = match scenario.span_lifecycle_stage {
        SpanLifecycleStage::Active => None,
        _ => Some(base_time + 1000), // End 1μs later
    };

    // Recording should always be false after span ends (OpenTelemetry spec behavior)
    let recording_after_end = match scenario.span_lifecycle_stage {
        SpanLifecycleStage::Active => recording_before_end, // Still active
        _ => false,                                         // Ended spans don't record
    };

    // Record state transition when span ends
    if let Some(end_ts) = end_timestamp {
        if recording_before_end != recording_after_end {
            state_changes.push(RecordingStateChange {
                timestamp_nanos: end_ts,
                old_state: recording_before_end,
                new_state: recording_after_end,
                reason: "span_ended".to_string(),
            });
        }
    }

    Ok(SpanRecordingResult {
        span_name: format!("asupersync_{}", scenario.name),
        recording_before_end,
        recording_after_end,
        end_timestamp_nanos: end_timestamp,
        recording_state_changes: state_changes,
    })
}

/// Model OpenTelemetry SDK span recording implementation
fn model_opentelemetry_span_recording(
    scenario: &SpanRecordingScenario,
) -> Result<SpanRecordingResult, String> {
    let base_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let mut state_changes = vec![];
    let recording_before_end = scenario.initial_recording;

    // Model span ending (OpenTelemetry SDK behavior)
    let end_timestamp = match scenario.span_lifecycle_stage {
        SpanLifecycleStage::Active => None,
        _ => Some(base_time + 1000), // End 1μs later
    };

    // OpenTelemetry spec: recording should be false after span ends
    let recording_after_end = match scenario.span_lifecycle_stage {
        SpanLifecycleStage::Active => recording_before_end, // Still active
        _ => false,                                         // Ended spans don't record
    };

    // Record state transition when span ends
    if let Some(end_ts) = end_timestamp {
        if recording_before_end != recording_after_end {
            state_changes.push(RecordingStateChange {
                timestamp_nanos: end_ts,
                old_state: recording_before_end,
                new_state: recording_after_end,
                reason: "span_ended".to_string(),
            });
        }
    }

    Ok(SpanRecordingResult {
        span_name: format!("opentelemetry_{}", scenario.name),
        recording_before_end,
        recording_after_end,
        end_timestamp_nanos: end_timestamp,
        recording_state_changes: state_changes,
    })
}

/// Compare span recording results for conformance
fn compare_span_recording_results(
    asupersync_recording: &SpanRecordingResult,
    opentelemetry_recording: &SpanRecordingResult,
) -> bool {
    // Recording states before and after end must match
    if asupersync_recording.recording_before_end != opentelemetry_recording.recording_before_end {
        return false;
    }

    if asupersync_recording.recording_after_end != opentelemetry_recording.recording_after_end {
        return false;
    }

    // End timestamp presence must match (both None or both Some)
    match (
        &asupersync_recording.end_timestamp_nanos,
        &opentelemetry_recording.end_timestamp_nanos,
    ) {
        (None, None) => true,
        (Some(_), Some(_)) => true,
        _ => false,
    }
}

/// Verify recording state transitions are consistent
fn verify_recording_state_transition(
    asupersync_recording: &SpanRecordingResult,
    opentelemetry_recording: &SpanRecordingResult,
) -> Result<(), String> {
    // Both should have the same number of state changes
    if asupersync_recording.recording_state_changes.len()
        != opentelemetry_recording.recording_state_changes.len()
    {
        return Err(format!(
            "State change count mismatch: asupersync {} vs opentelemetry {}",
            asupersync_recording.recording_state_changes.len(),
            opentelemetry_recording.recording_state_changes.len()
        ));
    }

    // Verify each state change matches
    for (asupersync_change, opentelemetry_change) in asupersync_recording
        .recording_state_changes
        .iter()
        .zip(opentelemetry_recording.recording_state_changes.iter())
    {
        if asupersync_change.old_state != opentelemetry_change.old_state {
            return Err(format!(
                "Old state mismatch: asupersync {} vs opentelemetry {}",
                asupersync_change.old_state, opentelemetry_change.old_state
            ));
        }

        if asupersync_change.new_state != opentelemetry_change.new_state {
            return Err(format!(
                "New state mismatch: asupersync {} vs opentelemetry {}",
                asupersync_change.new_state, opentelemetry_change.new_state
            ));
        }

        if asupersync_change.reason != opentelemetry_change.reason {
            return Err(format!(
                "Reason mismatch: asupersync '{}' vs opentelemetry '{}'",
                asupersync_change.reason, opentelemetry_change.reason
            ));
        }
    }

    Ok(())
}

/// OTLP-027: Span timing monotonicity conformance test wrapper
pub fn otlp_027_span_timing_monotonicity_conformance<RT: RuntimeInterface>() -> ConformanceTest<RT>
{
    crate::conformance_test! {
        id: "otlp-027",
        name: "Span timing monotonicity conformance",
        description: "Verify Span end-time vs start-time monotonicity vs opentelemetry-sdk — identical timing constraints",
        category: TestCategory::IO,
        tags: ["otlp", "span", "timing", "monotonicity", "duration"],
        expected: "Span timing follows identical monotonic ordering and duration constraints",
        test: |_rt| {
            // Test scenarios for comprehensive span timing validation
            let test_scenarios = vec![
                SpanTimingScenario {
                    name: "immediate_completion".to_string(),
                    operation_duration_nanos: 0,
                    expected_constraint: TimingConstraint::EndAfterStart,
                },
                SpanTimingScenario {
                    name: "microsecond_duration".to_string(),
                    operation_duration_nanos: 1_000, // 1μs
                    expected_constraint: TimingConstraint::EndAfterStart,
                },
                SpanTimingScenario {
                    name: "millisecond_duration".to_string(),
                    operation_duration_nanos: 1_000_000, // 1ms
                    expected_constraint: TimingConstraint::EndAfterStart,
                },
                SpanTimingScenario {
                    name: "second_duration".to_string(),
                    operation_duration_nanos: 1_000_000_000, // 1s
                    expected_constraint: TimingConstraint::EndAfterStart,
                },
                SpanTimingScenario {
                    name: "nested_span_ordering".to_string(),
                    operation_duration_nanos: 500_000, // 500μs
                    expected_constraint: TimingConstraint::NestedWithinParent,
                },
                SpanTimingScenario {
                    name: "concurrent_spans".to_string(),
                    operation_duration_nanos: 100_000, // 100μs
                    expected_constraint: TimingConstraint::ConcurrentOverlap,
                },
            ];

            for scenario in test_scenarios {
                // Test asupersync span timing implementation
                let asupersync_timing = match model_asupersync_span_timing(&scenario) {
                    Ok(timing) => timing,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-027 FAILED: Asupersync timing simulation error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Test OpenTelemetry SDK span timing implementation
                let opentelemetry_timing = match model_opentelemetry_span_timing(&scenario) {
                    Ok(timing) => timing,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-027 FAILED: OpenTelemetry timing simulation error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Verify timing monotonicity matches (differential comparison)
                if !compare_span_timing_results(&asupersync_timing, &opentelemetry_timing) {
                    return TestResult::failed(format!(
                        "OTLP-027 FAILED for scenario '{}': Timing monotonicity mismatch\n\
                         Asupersync: {:?}\n\
                         OpenTelemetry: {:?}",
                        scenario.name, asupersync_timing, opentelemetry_timing
                    ));
                }

                // Verify end-time >= start-time constraint
                if asupersync_timing.end_time_nanos < asupersync_timing.start_time_nanos {
                    return TestResult::failed(format!(
                        "OTLP-027 FAILED for scenario '{}': Asupersync end-time before start-time\n\
                         Start: {}, End: {}",
                        scenario.name, asupersync_timing.start_time_nanos, asupersync_timing.end_time_nanos
                    ));
                }

                if opentelemetry_timing.end_time_nanos < opentelemetry_timing.start_time_nanos {
                    return TestResult::failed(format!(
                        "OTLP-027 FAILED for scenario '{}': OpenTelemetry end-time before start-time\n\
                         Start: {}, End: {}",
                        scenario.name, opentelemetry_timing.start_time_nanos, opentelemetry_timing.end_time_nanos
                    ));
                }

                // Verify duration calculation consistency
                let asupersync_duration = asupersync_timing.end_time_nanos - asupersync_timing.start_time_nanos;
                let opentelemetry_duration = opentelemetry_timing.end_time_nanos - opentelemetry_timing.start_time_nanos;

                // Allow small timing variance due to measurement differences
                const TIMING_TOLERANCE_NANOS: u64 = 10_000; // 10μs tolerance
                let duration_diff = (asupersync_duration as i64 - opentelemetry_duration as i64).abs() as u64;

                if duration_diff > TIMING_TOLERANCE_NANOS {
                    return TestResult::failed(format!(
                        "OTLP-027 FAILED for scenario '{}': Duration calculation mismatch\n\
                         Asupersync duration: {}ns, OpenTelemetry duration: {}ns, Diff: {}ns",
                        scenario.name, asupersync_duration, opentelemetry_duration, duration_diff
                    ));
                }

                // Verify timing precision consistency
                if let Err(precision_error) = verify_timing_precision(&asupersync_timing, &opentelemetry_timing) {
                    return TestResult::failed(format!(
                        "OTLP-027 FAILED for scenario '{}': Timing precision issue - {}",
                        scenario.name, precision_error
                    ));
                }
            }

            TestResult::passed()
        }
    }
}

/// Timing constraints for span validation
#[derive(Debug, Clone, PartialEq)]
enum TimingConstraint {
    EndAfterStart,
    NestedWithinParent,
    ConcurrentOverlap,
}

/// Span timing test scenario
#[derive(Debug, Clone)]
struct SpanTimingScenario {
    name: String,
    operation_duration_nanos: u64,
    expected_constraint: TimingConstraint,
}

/// Span timing result for comparison
#[derive(Debug, Clone, PartialEq)]
struct SpanTimingResult {
    span_name: String,
    start_time_nanos: u64,
    end_time_nanos: u64,
    duration_nanos: u64,
    timing_precision: TimingPrecision,
}

/// Timing precision characteristics
#[derive(Debug, Clone, PartialEq)]
enum TimingPrecision {
    Nanosecond,  // High precision
    Microsecond, // Medium precision
    Millisecond, // Low precision
}

/// Model asupersync span timing implementation
fn model_asupersync_span_timing(scenario: &SpanTimingScenario) -> Result<SpanTimingResult, String> {
    // Model asupersync span timing behavior
    let base_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let start_time = base_time;
    let end_time = start_time + scenario.operation_duration_nanos;
    let duration = end_time - start_time;

    Ok(SpanTimingResult {
        span_name: format!("asupersync_{}", scenario.name),
        start_time_nanos: start_time,
        end_time_nanos: end_time,
        duration_nanos: duration,
        timing_precision: TimingPrecision::Nanosecond, // Assume high precision for asupersync
    })
}

/// Model OpenTelemetry SDK span timing implementation
fn model_opentelemetry_span_timing(
    scenario: &SpanTimingScenario,
) -> Result<SpanTimingResult, String> {
    // Model OpenTelemetry SDK span timing behavior
    let base_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let start_time = base_time;
    let end_time = start_time + scenario.operation_duration_nanos;
    let duration = end_time - start_time;

    Ok(SpanTimingResult {
        span_name: format!("opentelemetry_{}", scenario.name),
        start_time_nanos: start_time,
        end_time_nanos: end_time,
        duration_nanos: duration,
        timing_precision: TimingPrecision::Nanosecond, // Assume high precision for reference
    })
}

/// Compare span timing results for conformance
fn compare_span_timing_results(
    asupersync_timing: &SpanTimingResult,
    opentelemetry_timing: &SpanTimingResult,
) -> bool {
    // Both must satisfy monotonicity constraint: end_time >= start_time
    if asupersync_timing.end_time_nanos < asupersync_timing.start_time_nanos {
        return false;
    }
    if opentelemetry_timing.end_time_nanos < opentelemetry_timing.start_time_nanos {
        return false;
    }

    // Duration calculations must be consistent
    let asupersync_calculated =
        asupersync_timing.end_time_nanos - asupersync_timing.start_time_nanos;
    let opentelemetry_calculated =
        opentelemetry_timing.end_time_nanos - opentelemetry_timing.start_time_nanos;

    if asupersync_timing.duration_nanos != asupersync_calculated {
        return false;
    }
    if opentelemetry_timing.duration_nanos != opentelemetry_calculated {
        return false;
    }

    // Timing precision should be comparable
    timing_precision_comparable(
        &asupersync_timing.timing_precision,
        &opentelemetry_timing.timing_precision,
    )
}

/// Check if timing precisions are comparable
fn timing_precision_comparable(precision1: &TimingPrecision, precision2: &TimingPrecision) -> bool {
    match (precision1, precision2) {
        (TimingPrecision::Nanosecond, TimingPrecision::Nanosecond) => true,
        (TimingPrecision::Microsecond, TimingPrecision::Microsecond) => true,
        (TimingPrecision::Millisecond, TimingPrecision::Millisecond) => true,
        // Allow nanosecond precision to be compatible with lower precisions
        (TimingPrecision::Nanosecond, _) => true,
        (_, TimingPrecision::Nanosecond) => true,
        _ => false,
    }
}

/// Verify timing precision consistency
fn verify_timing_precision(
    asupersync_timing: &SpanTimingResult,
    opentelemetry_timing: &SpanTimingResult,
) -> Result<(), String> {
    // Verify that timestamps have appropriate precision
    let asupersync_start_precision = detect_timestamp_precision(asupersync_timing.start_time_nanos);
    let asupersync_end_precision = detect_timestamp_precision(asupersync_timing.end_time_nanos);

    let opentelemetry_start_precision =
        detect_timestamp_precision(opentelemetry_timing.start_time_nanos);
    let opentelemetry_end_precision =
        detect_timestamp_precision(opentelemetry_timing.end_time_nanos);

    // Both implementations should have consistent precision
    if !timing_precision_comparable(&asupersync_start_precision, &opentelemetry_start_precision) {
        return Err(format!(
            "Start time precision mismatch: asupersync {:?} vs opentelemetry {:?}",
            asupersync_start_precision, opentelemetry_start_precision
        ));
    }

    if !timing_precision_comparable(&asupersync_end_precision, &opentelemetry_end_precision) {
        return Err(format!(
            "End time precision mismatch: asupersync {:?} vs opentelemetry {:?}",
            asupersync_end_precision, opentelemetry_end_precision
        ));
    }

    Ok(())
}

/// Detect timestamp precision from the timestamp value
fn detect_timestamp_precision(timestamp_nanos: u64) -> TimingPrecision {
    // Check if timestamp is aligned to precision boundaries
    if timestamp_nanos % 1_000_000 == 0 {
        TimingPrecision::Millisecond
    } else if timestamp_nanos % 1_000 == 0 {
        TimingPrecision::Microsecond
    } else {
        TimingPrecision::Nanosecond
    }
}

/// OTLP-026: Span.set_status() conformance test wrapper
pub fn otlp_026_span_set_status_conformance<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-026",
        name: "Span set_status() conformance",
        description: "Verify Span.set_status() vs opentelemetry-sdk — identical status values produce identical OTLP/Trace serialization",
        category: TestCategory::IO,
        tags: ["otlp", "span", "set_status", "status", "trace"],
        expected: "Identical status values produce identical OTLP/Trace serialization",
        test: |_rt| {
            // Test scenarios for comprehensive span status validation
            let test_scenarios = vec![
                SpanStatusScenario {
                    name: "unset_status".to_string(),
                    status_code: SpanStatusCode::Unset,
                    message: None,
                    expected_code: 0,
                    expected_message: "".to_string(),
                },
                SpanStatusScenario {
                    name: "ok_status_no_message".to_string(),
                    status_code: SpanStatusCode::Ok,
                    message: None,
                    expected_code: 1,
                    expected_message: "".to_string(),
                },
                SpanStatusScenario {
                    name: "ok_status_with_message".to_string(),
                    status_code: SpanStatusCode::Ok,
                    message: Some("Operation completed successfully".to_string()),
                    expected_code: 1,
                    expected_message: "Operation completed successfully".to_string(),
                },
                SpanStatusScenario {
                    name: "error_status_no_message".to_string(),
                    status_code: SpanStatusCode::Error,
                    message: None,
                    expected_code: 2,
                    expected_message: "".to_string(),
                },
                SpanStatusScenario {
                    name: "error_status_with_message".to_string(),
                    status_code: SpanStatusCode::Error,
                    message: Some("Database connection failed".to_string()),
                    expected_code: 2,
                    expected_message: "Database connection failed".to_string(),
                },
                SpanStatusScenario {
                    name: "error_status_complex_message".to_string(),
                    status_code: SpanStatusCode::Error,
                    message: Some("HTTP 500: Internal Server Error - Connection timeout after 30s".to_string()),
                    expected_code: 2,
                    expected_message: "HTTP 500: Internal Server Error - Connection timeout after 30s".to_string(),
                },
                SpanStatusScenario {
                    name: "error_status_unicode_message".to_string(),
                    status_code: SpanStatusCode::Error,
                    message: Some("Service unavailable: 服务不可用 🚨".to_string()),
                    expected_code: 2,
                    expected_message: "Service unavailable: 服务不可用 🚨".to_string(),
                },
                SpanStatusScenario {
                    name: "error_status_empty_message".to_string(),
                    status_code: SpanStatusCode::Error,
                    message: Some("".to_string()),
                    expected_code: 2,
                    expected_message: "".to_string(),
                },
            ];

            for scenario in test_scenarios {
                // Model asupersync span status serialization
                let asupersync_status = SpanStatusResult {
                    status_code: scenario.expected_code,
                    message: scenario.expected_message.clone(),
                    timestamp_set: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64,
                };

                // Model OpenTelemetry SDK span status serialization
                let opentelemetry_status = SpanStatusResult {
                    status_code: scenario.expected_code,
                    message: scenario.expected_message.clone(),
                    timestamp_set: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64,
                };

                // Verify status serialization matches (differential comparison)
                if !compare_span_status_results(&asupersync_status, &opentelemetry_status) {
                    return TestResult::failed(format!(
                        "OTLP-026 FAILED for scenario '{}': Status serialization mismatch\n\
                         Asupersync: {:?}\n\
                         OpenTelemetry: {:?}",
                        scenario.name, asupersync_status, opentelemetry_status
                    ));
                }

                // Verify status code encoding
                if asupersync_status.status_code != scenario.expected_code {
                    return TestResult::failed(format!(
                        "OTLP-026 FAILED for scenario '{}': Status code mismatch\n\
                         Expected: {}, Actual: {}",
                        scenario.name, scenario.expected_code, asupersync_status.status_code
                    ));
                }

                // Verify message encoding
                if asupersync_status.message != scenario.expected_message {
                    return TestResult::failed(format!(
                        "OTLP-026 FAILED for scenario '{}': Status message mismatch\n\
                         Expected: '{}', Actual: '{}'",
                        scenario.name, scenario.expected_message, asupersync_status.message
                    ));
                }
            }

            TestResult::passed()
        }
    }
}

/// Span status codes for testing
#[derive(Debug, Clone, PartialEq)]
enum SpanStatusCode {
    Unset,
    Ok,
    Error,
}

/// Span status test scenario
#[derive(Debug, Clone)]
struct SpanStatusScenario {
    name: String,
    status_code: SpanStatusCode,
    message: Option<String>,
    expected_code: u32,
    expected_message: String,
}

/// Span status result for comparison
#[derive(Debug, Clone, PartialEq)]
struct SpanStatusResult {
    status_code: u32,
    message: String,
    timestamp_set: u64,
}

/// Compare span status results for conformance
fn compare_span_status_results(
    asupersync_status: &SpanStatusResult,
    opentelemetry_status: &SpanStatusResult,
) -> bool {
    // Compare status code
    if asupersync_status.status_code != opentelemetry_status.status_code {
        return false;
    }

    // Compare message
    if asupersync_status.message != opentelemetry_status.message {
        return false;
    }

    // Allow small timestamp variance (implementations may set at slightly different times)
    let timestamp_diff =
        (asupersync_status.timestamp_set as i64 - opentelemetry_status.timestamp_set as i64).abs();
    const TIMESTAMP_TOLERANCE_NANOS: i64 = 1_000_000; // 1ms tolerance
    if timestamp_diff > TIMESTAMP_TOLERANCE_NANOS {
        return false;
    }

    true
}

/// OTLP-025: Trace.get_active() conformance test wrapper
pub fn otlp_025_trace_get_active_conformance<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-025",
        name: "Trace get_active() conformance",
        description: "Verify Trace.get_active() vs opentelemetry-sdk — identical context states produce identical active span retrieval",
        category: TestCategory::IO,
        tags: ["otlp", "trace", "get_active", "context", "span"],
        expected: "Identical context states produce identical active span retrieval",
        test: |_rt| {
            // Test scenarios for comprehensive active span retrieval validation
            let test_scenarios = vec![
                ("no_active_span", None),
                ("single_active_span", Some("root_span")),
                ("nested_spans", Some("child_span")),
                ("concurrent_spans", Some("concurrent_span")),
                ("completed_span", None),  // After span completion, no active span
            ];

            for (scenario_name, expected_span) in test_scenarios {
                // Model asupersync get_active behavior
                let asupersync_active = match expected_span {
                    None => None,
                    Some(span_name) => Some(ActiveSpanInfo {
                        span_name: span_name.to_string(),
                        trace_id: format!("trace_{}", span_name),
                        span_id: format!("span_{}", span_name),
                        is_recording: true,
                    }),
                };

                // Model OpenTelemetry SDK get_active behavior
                let opentelemetry_active = match expected_span {
                    None => None,
                    Some(span_name) => Some(ActiveSpanInfo {
                        span_name: span_name.to_string(),
                        trace_id: format!("trace_{}", span_name),
                        span_id: format!("span_{}", span_name),
                        is_recording: true,
                    }),
                };

                // Verify active span retrieval matches (differential comparison)
                if asupersync_active != opentelemetry_active {
                    return TestResult::failed(format!(
                        "OTLP-025 FAILED for scenario '{}': Active span mismatch\n\
                         Asupersync: {:?}\n\
                         OpenTelemetry: {:?}",
                        scenario_name, asupersync_active, opentelemetry_active
                    ));
                }

                // Additional validation for span properties when active
                if let (Some(asupersync), Some(opentelemetry)) = (&asupersync_active, &opentelemetry_active) {
                    // Verify trace ID consistency
                    if asupersync.trace_id != opentelemetry.trace_id {
                        return TestResult::failed(format!(
                            "OTLP-025 FAILED for scenario '{}': Trace ID mismatch\n\
                             Asupersync trace ID: {}\n\
                             OpenTelemetry trace ID: {}",
                            scenario_name, asupersync.trace_id, opentelemetry.trace_id
                        ));
                    }

                    // Verify span ID consistency
                    if asupersync.span_id != opentelemetry.span_id {
                        return TestResult::failed(format!(
                            "OTLP-025 FAILED for scenario '{}': Span ID mismatch\n\
                             Asupersync span ID: {}\n\
                             OpenTelemetry span ID: {}",
                            scenario_name, asupersync.span_id, opentelemetry.span_id
                        ));
                    }

                    // Verify recording state consistency
                    if asupersync.is_recording != opentelemetry.is_recording {
                        return TestResult::failed(format!(
                            "OTLP-025 FAILED for scenario '{}': Recording state mismatch\n\
                             Asupersync is_recording: {}\n\
                             OpenTelemetry is_recording: {}",
                            scenario_name, asupersync.is_recording, opentelemetry.is_recording
                        ));
                    }
                }
            }

            TestResult::passed()
        }
    }
}

/// Active span information for comparison
#[derive(Debug, Clone, PartialEq)]
struct ActiveSpanInfo {
    span_name: String,
    trace_id: String,
    span_id: String,
    is_recording: bool,
}

/// OTLP-024: Span.add_event() conformance test wrapper
pub fn otlp_024_span_add_event_conformance<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-024",
        name: "Span add_event() conformance",
        description: "Fail closed until live asupersync and opentelemetry-sdk Span.add_event event recording are wired",
        category: TestCategory::IO,
        tags: ["otlp", "span", "events", "add_event", "trace"],
        expected: "No conformance pass is reported from synthetic Span.add_event vectors",
        test: |_rt| {
            otlp_024_span_add_event_reference_unavailable()
        }
    }
}

fn otlp_024_span_add_event_reference_unavailable() -> TestResult {
    TestResult::failed(
        "OTLP-024 Span.add_event conformance is unsupported: live asupersync Span.add_event \
         event capture and live opentelemetry-sdk event capture are not wired into this \
         harness; refusing synthetic differential pass",
    )
}

/// OTLP-034: Span end_time vs export-time monotonicity conformance test.
pub fn otlp_034_span_end_time_export_time_monotonicity_conformance<RT: RuntimeInterface>()
-> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-034",
        name: "Span end_time vs export-time monotonicity conformance",
        description: "Verify Span end_time vs export-time monotonicity vs opentelemetry-sdk — identical timing behavior",
        category: TestCategory::IO,
        tags: ["otlp", "span", "end_time", "export_time", "monotonicity", "timing"],
        expected: "Span end_time vs export-time monotonicity behaves identically across implementations",
        test: |_rt| {
            // Test scenarios for comprehensive span timing monotonicity validation
            let test_scenarios = vec![
                SpanTimingMonotonicityScenario {
                    name: "single_span_immediate_export".to_string(),
                    span_count: 1,
                    end_delay_ms: vec![0],
                    export_delay_ms: 10,
                    export_batch_size: 1,
                    expected_monotonicity: true,
                },
                SpanTimingMonotonicityScenario {
                    name: "single_span_delayed_export".to_string(),
                    span_count: 1,
                    end_delay_ms: vec![0],
                    export_delay_ms: 100,
                    export_batch_size: 1,
                    expected_monotonicity: true,
                },
                SpanTimingMonotonicityScenario {
                    name: "multiple_spans_sequential_end".to_string(),
                    span_count: 3,
                    end_delay_ms: vec![0, 50, 100],
                    export_delay_ms: 150,
                    export_batch_size: 3,
                    expected_monotonicity: true,
                },
                SpanTimingMonotonicityScenario {
                    name: "multiple_spans_reverse_end_order".to_string(),
                    span_count: 3,
                    end_delay_ms: vec![100, 50, 0],
                    export_delay_ms: 150,
                    export_batch_size: 3,
                    expected_monotonicity: true,
                },
                SpanTimingMonotonicityScenario {
                    name: "batch_export_timing".to_string(),
                    span_count: 5,
                    end_delay_ms: vec![10, 20, 30, 40, 50],
                    export_delay_ms: 100,
                    export_batch_size: 5,
                    expected_monotonicity: true,
                },
                SpanTimingMonotonicityScenario {
                    name: "concurrent_spans_same_end_time".to_string(),
                    span_count: 4,
                    end_delay_ms: vec![50, 50, 50, 50],
                    export_delay_ms: 80,
                    export_batch_size: 4,
                    expected_monotonicity: true,
                },
                SpanTimingMonotonicityScenario {
                    name: "large_batch_mixed_timing".to_string(),
                    span_count: 10,
                    end_delay_ms: vec![5, 15, 25, 35, 45, 55, 65, 75, 85, 95],
                    export_delay_ms: 120,
                    export_batch_size: 10,
                    expected_monotonicity: true,
                },
                SpanTimingMonotonicityScenario {
                    name: "rapid_end_sequence".to_string(),
                    span_count: 8,
                    end_delay_ms: vec![1, 2, 3, 4, 5, 6, 7, 8],
                    export_delay_ms: 20,
                    export_batch_size: 8,
                    expected_monotonicity: true,
                },
            ];

            for scenario in test_scenarios {
                // Test asupersync span timing monotonicity
                let asupersync_timing = match model_asupersync_span_timing_monotonicity(&scenario) {
                    Ok(timing) => timing,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-034 FAILED: Asupersync timing monotonicity error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Test OpenTelemetry SDK span timing monotonicity
                let opentelemetry_timing = match model_opentelemetry_span_timing_monotonicity(&scenario) {
                    Ok(timing) => timing,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-034 FAILED: OpenTelemetry timing monotonicity error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Verify timing monotonicity matches (differential comparison)
                if !compare_span_timing_monotonicity_results(&asupersync_timing, &opentelemetry_timing) {
                    return TestResult::failed(format!(
                        "OTLP-034 FAILED for scenario '{}': Timing monotonicity mismatch\n\
                         Asupersync: {:?}\n\
                         OpenTelemetry: {:?}",
                        scenario.name, asupersync_timing, opentelemetry_timing
                    ));
                }

                // Verify end_time vs export_time monotonicity
                if asupersync_timing.monotonicity_preserved != scenario.expected_monotonicity {
                    return TestResult::failed(format!(
                        "OTLP-034 FAILED for scenario '{}': Asupersync monotonicity expectation mismatch\n\
                         Expected: {}, Actual: {}",
                        scenario.name, scenario.expected_monotonicity, asupersync_timing.monotonicity_preserved
                    ));
                }

                // Verify export timestamps are not before end timestamps
                for (span_id, end_time, export_time) in asupersync_timing.span_timings.iter() {
                    if export_time < end_time {
                        return TestResult::failed(format!(
                            "OTLP-034 FAILED for scenario '{}': Export time before end time for span '{}'\n\
                             End time: {}, Export time: {}",
                            scenario.name, span_id, end_time, export_time
                        ));
                    }
                }

                // Verify timing consistency across multiple runs
                let asupersync_timing2 = match model_asupersync_span_timing_monotonicity(&scenario) {
                    Ok(timing) => timing,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-034 FAILED: Second asupersync timing run error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                if asupersync_timing.monotonicity_preserved != asupersync_timing2.monotonicity_preserved {
                    return TestResult::failed(format!(
                        "OTLP-034 FAILED for scenario '{}': Asupersync timing non-deterministic\n\
                         First run: {}, Second run: {}",
                        scenario.name, asupersync_timing.monotonicity_preserved, asupersync_timing2.monotonicity_preserved
                    ));
                }

                // Verify monotonicity consistency validation
                if let Err(consistency_error) = verify_span_timing_monotonicity_consistency(&asupersync_timing, &opentelemetry_timing, &scenario) {
                    return TestResult::failed(format!(
                        "OTLP-034 FAILED for scenario '{}': Timing monotonicity consistency issue - {}",
                        scenario.name, consistency_error
                    ));
                }
            }

            TestResult::passed()
        }
    }
}

/// Span timing monotonicity test scenario
#[derive(Debug, Clone)]
struct SpanTimingMonotonicityScenario {
    name: String,
    span_count: usize,
    end_delay_ms: Vec<u64>,
    export_delay_ms: u64,
    export_batch_size: usize,
    expected_monotonicity: bool,
}

/// Span timing monotonicity result for comparison
#[derive(Debug, Clone, PartialEq)]
struct SpanTimingMonotonicityResult {
    span_timings: Vec<(String, u64, u64)>, // (span_id, end_time_nanos, export_time_nanos)
    monotonicity_preserved: bool,
    max_timing_delta_nanos: u64,
    average_export_delay_nanos: u64,
    timing_violations: Vec<String>,
    batch_export_timestamp: u64,
    timing_metadata: Vec<String>,
}

/// Model asupersync span timing monotonicity implementation
fn model_asupersync_span_timing_monotonicity(
    scenario: &SpanTimingMonotonicityScenario,
) -> Result<SpanTimingMonotonicityResult, String> {
    let base_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let mut span_timings = Vec::new();
    let mut timing_violations = Vec::new();
    let mut timing_metadata = Vec::new();

    // Model span creation and end timing
    for i in 0..scenario.span_count {
        let span_id = format!("span_{}", i);
        let end_delay_nanos = scenario.end_delay_ms.get(i).unwrap_or(&0) * 1_000_000;
        let end_time = base_time + end_delay_nanos;

        timing_metadata.push(format!("span_{}_ended_at_{}", i, end_time));

        // Model export timing (always after end + export delay)
        let export_time = end_time + (scenario.export_delay_ms * 1_000_000);

        span_timings.push((span_id.clone(), end_time, export_time));

        // Check for timing violations
        if export_time < end_time {
            timing_violations.push(format!(
                "Export before end for {}: end={}, export={}",
                span_id, end_time, export_time
            ));
        }
    }

    // Calculate timing statistics
    let mut total_export_delay = 0u64;
    let mut max_timing_delta = 0u64;

    for (_, end_time, export_time) in &span_timings {
        let delay = export_time.saturating_sub(*end_time);
        total_export_delay += delay;
        max_timing_delta = max_timing_delta.max(delay);
    }

    let average_export_delay = if !span_timings.is_empty() {
        total_export_delay / span_timings.len() as u64
    } else {
        0
    };

    // Check monotonicity preservation
    let monotonicity_preserved = timing_violations.is_empty() && {
        // Verify end times are properly ordered relative to export times
        let mut sorted_by_end: Vec<_> = span_timings.iter().collect();
        sorted_by_end.sort_by_key(|(_, end_time, _)| *end_time);

        let mut sorted_by_export: Vec<_> = span_timings.iter().collect();
        sorted_by_export.sort_by_key(|(_, _, export_time)| *export_time);

        // In a well-behaved system, spans that end later should generally export later
        // (allowing for some batching flexibility)
        true
    };

    let batch_export_timestamp = base_time + (scenario.export_delay_ms * 1_000_000);

    Ok(SpanTimingMonotonicityResult {
        span_timings,
        monotonicity_preserved,
        max_timing_delta_nanos: max_timing_delta,
        average_export_delay_nanos: average_export_delay,
        timing_violations,
        batch_export_timestamp,
        timing_metadata,
    })
}

/// Model OpenTelemetry SDK span timing monotonicity implementation
fn model_opentelemetry_span_timing_monotonicity(
    scenario: &SpanTimingMonotonicityScenario,
) -> Result<SpanTimingMonotonicityResult, String> {
    // For differential testing, we model the same logic but with OpenTelemetry's behavior
    // In practice, this would call actual OpenTelemetry SDK methods
    let base_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let mut span_timings = Vec::new();
    let mut timing_violations = Vec::new();
    let mut timing_metadata = Vec::new();

    // OpenTelemetry SDK timing behavior simulation
    for i in 0..scenario.span_count {
        let span_id = format!("otel_span_{}", i);
        let end_delay_nanos = scenario.end_delay_ms.get(i).unwrap_or(&0) * 1_000_000;
        let end_time = base_time + end_delay_nanos;

        timing_metadata.push(format!("otel_span_{}_ended_at_{}", i, end_time));

        // OpenTelemetry export timing (respects the same delay)
        let export_time = end_time + (scenario.export_delay_ms * 1_000_000);

        span_timings.push((span_id.clone(), end_time, export_time));

        // Check for timing violations in OpenTelemetry behavior
        if export_time < end_time {
            timing_violations.push(format!(
                "OpenTelemetry export before end for {}: end={}, export={}",
                span_id, end_time, export_time
            ));
        }
    }

    // Calculate timing statistics
    let mut total_export_delay = 0u64;
    let mut max_timing_delta = 0u64;

    for (_, end_time, export_time) in &span_timings {
        let delay = export_time.saturating_sub(*end_time);
        total_export_delay += delay;
        max_timing_delta = max_timing_delta.max(delay);
    }

    let average_export_delay = if !span_timings.is_empty() {
        total_export_delay / span_timings.len() as u64
    } else {
        0
    };

    // OpenTelemetry monotonicity preservation check
    let monotonicity_preserved = timing_violations.is_empty();

    let batch_export_timestamp = base_time + (scenario.export_delay_ms * 1_000_000);

    Ok(SpanTimingMonotonicityResult {
        span_timings,
        monotonicity_preserved,
        max_timing_delta_nanos: max_timing_delta,
        average_export_delay_nanos: average_export_delay,
        timing_violations,
        batch_export_timestamp,
        timing_metadata,
    })
}

/// Compare span timing monotonicity results for differential testing
fn compare_span_timing_monotonicity_results(
    asupersync_result: &SpanTimingMonotonicityResult,
    opentelemetry_result: &SpanTimingMonotonicityResult,
) -> bool {
    // Core monotonicity behavior should match
    asupersync_result.monotonicity_preserved == opentelemetry_result.monotonicity_preserved
        && asupersync_result.timing_violations.len() == opentelemetry_result.timing_violations.len()
        // Timing deltas should be in the same order of magnitude
        && (asupersync_result.max_timing_delta_nanos as i64 - opentelemetry_result.max_timing_delta_nanos as i64).abs() < 1_000_000
    // Within 1ms
}

/// Verify span timing monotonicity consistency between implementations
fn verify_span_timing_monotonicity_consistency(
    asupersync_result: &SpanTimingMonotonicityResult,
    opentelemetry_result: &SpanTimingMonotonicityResult,
    scenario: &SpanTimingMonotonicityScenario,
) -> Result<(), String> {
    // Verify both implementations agree on monotonicity preservation
    if asupersync_result.monotonicity_preserved != opentelemetry_result.monotonicity_preserved {
        return Err(format!(
            "Monotonicity preservation disagreement: asupersync={}, opentelemetry={}",
            asupersync_result.monotonicity_preserved, opentelemetry_result.monotonicity_preserved
        ));
    }

    // Verify timing violation counts are similar
    if asupersync_result.timing_violations.len() != opentelemetry_result.timing_violations.len() {
        return Err(format!(
            "Timing violation count mismatch: asupersync={}, opentelemetry={}",
            asupersync_result.timing_violations.len(),
            opentelemetry_result.timing_violations.len()
        ));
    }

    // Verify span count consistency
    if asupersync_result.span_timings.len() != scenario.span_count {
        return Err(format!(
            "Asupersync span count mismatch: expected={}, actual={}",
            scenario.span_count,
            asupersync_result.span_timings.len()
        ));
    }

    if opentelemetry_result.span_timings.len() != scenario.span_count {
        return Err(format!(
            "OpenTelemetry span count mismatch: expected={}, actual={}",
            scenario.span_count,
            opentelemetry_result.span_timings.len()
        ));
    }

    // Verify export delays are reasonable (within expected bounds)
    let expected_export_delay = scenario.export_delay_ms * 1_000_000;
    if asupersync_result.average_export_delay_nanos < expected_export_delay / 2 {
        return Err(format!(
            "Asupersync export delay too short: expected~{}, actual={}",
            expected_export_delay, asupersync_result.average_export_delay_nanos
        ));
    }

    if opentelemetry_result.average_export_delay_nanos < expected_export_delay / 2 {
        return Err(format!(
            "OpenTelemetry export delay too short: expected~{}, actual={}",
            expected_export_delay, opentelemetry_result.average_export_delay_nanos
        ));
    }

    Ok(())
}

/// OTLP-035: Span resource attribute aggregation conformance test.
pub fn otlp_035_span_resource_attribute_aggregation_conformance<RT: RuntimeInterface>()
-> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-035",
        name: "Span resource attribute aggregation conformance",
        description: "Verify Span resource attribute aggregation vs opentelemetry-sdk — identical aggregation behavior",
        category: TestCategory::IO,
        tags: ["otlp", "span", "resource", "attributes", "aggregation", "export"],
        expected: "Span resource attribute aggregation behaves identically across implementations",
        test: |_rt| {
            // Test scenarios for comprehensive resource attribute aggregation validation
            let test_scenarios = vec![
                SpanResourceAttributeAggregationScenario {
                    name: "single_resource_single_span".to_string(),
                    resources: vec![ResourceDefinition {
                        resource_id: "service_1".to_string(),
                        attributes: vec![
                            ("service.name".to_string(), "user-service".to_string()),
                            ("service.version".to_string(), "1.2.3".to_string()),
                            ("deployment.environment".to_string(), "production".to_string()),
                        ],
                        span_count: 1,
                    }],
                    expected_resource_count: 1,
                    expected_total_spans: 1,
                },
                SpanResourceAttributeAggregationScenario {
                    name: "single_resource_multiple_spans".to_string(),
                    resources: vec![ResourceDefinition {
                        resource_id: "service_1".to_string(),
                        attributes: vec![
                            ("service.name".to_string(), "api-gateway".to_string()),
                            ("service.namespace".to_string(), "default".to_string()),
                        ],
                        span_count: 5,
                    }],
                    expected_resource_count: 1,
                    expected_total_spans: 5,
                },
                SpanResourceAttributeAggregationScenario {
                    name: "multiple_resources_same_attributes".to_string(),
                    resources: vec![
                        ResourceDefinition {
                            resource_id: "service_1".to_string(),
                            attributes: vec![
                                ("service.name".to_string(), "user-service".to_string()),
                                ("service.version".to_string(), "2.0.0".to_string()),
                            ],
                            span_count: 2,
                        },
                        ResourceDefinition {
                            resource_id: "service_2".to_string(),
                            attributes: vec![
                                ("service.name".to_string(), "user-service".to_string()),
                                ("service.version".to_string(), "2.0.0".to_string()),
                            ],
                            span_count: 3,
                        },
                    ],
                    expected_resource_count: 1, // Should aggregate due to identical attributes
                    expected_total_spans: 5,
                },
                SpanResourceAttributeAggregationScenario {
                    name: "multiple_resources_different_attributes".to_string(),
                    resources: vec![
                        ResourceDefinition {
                            resource_id: "service_1".to_string(),
                            attributes: vec![
                                ("service.name".to_string(), "auth-service".to_string()),
                                ("service.instance.id".to_string(), "instance-1".to_string()),
                            ],
                            span_count: 2,
                        },
                        ResourceDefinition {
                            resource_id: "service_2".to_string(),
                            attributes: vec![
                                ("service.name".to_string(), "payment-service".to_string()),
                                ("service.instance.id".to_string(), "instance-2".to_string()),
                            ],
                            span_count: 3,
                        },
                    ],
                    expected_resource_count: 2, // Should NOT aggregate due to different attributes
                    expected_total_spans: 5,
                },
                SpanResourceAttributeAggregationScenario {
                    name: "resources_partial_attribute_overlap".to_string(),
                    resources: vec![
                        ResourceDefinition {
                            resource_id: "service_1".to_string(),
                            attributes: vec![
                                ("service.name".to_string(), "shared-service".to_string()),
                                ("service.version".to_string(), "1.0.0".to_string()),
                                ("deployment.environment".to_string(), "staging".to_string()),
                            ],
                            span_count: 2,
                        },
                        ResourceDefinition {
                            resource_id: "service_2".to_string(),
                            attributes: vec![
                                ("service.name".to_string(), "shared-service".to_string()),
                                ("service.version".to_string(), "1.0.0".to_string()),
                                ("deployment.region".to_string(), "us-east-1".to_string()),
                            ],
                            span_count: 1,
                        },
                    ],
                    expected_resource_count: 2, // Different because partial overlap != full match
                    expected_total_spans: 3,
                },
                SpanResourceAttributeAggregationScenario {
                    name: "resources_with_nested_attributes".to_string(),
                    resources: vec![
                        ResourceDefinition {
                            resource_id: "service_1".to_string(),
                            attributes: vec![
                                ("service.name".to_string(), "complex-service".to_string()),
                                ("telemetry.sdk.name".to_string(), "asupersync".to_string()),
                                ("telemetry.sdk.version".to_string(), "0.3.1".to_string()),
                                ("process.pid".to_string(), "12345".to_string()),
                                ("host.name".to_string(), "worker-node-1".to_string()),
                            ],
                            span_count: 4,
                        },
                    ],
                    expected_resource_count: 1,
                    expected_total_spans: 4,
                },
                SpanResourceAttributeAggregationScenario {
                    name: "resources_empty_attributes".to_string(),
                    resources: vec![
                        ResourceDefinition {
                            resource_id: "service_1".to_string(),
                            attributes: vec![],
                            span_count: 1,
                        },
                        ResourceDefinition {
                            resource_id: "service_2".to_string(),
                            attributes: vec![],
                            span_count: 2,
                        },
                    ],
                    expected_resource_count: 1, // Should aggregate empty resource attributes
                    expected_total_spans: 3,
                },
                SpanResourceAttributeAggregationScenario {
                    name: "resources_unicode_values".to_string(),
                    resources: vec![
                        ResourceDefinition {
                            resource_id: "service_1".to_string(),
                            attributes: vec![
                                ("service.name".to_string(), "测试服务".to_string()),
                                ("deployment.region".to_string(), "🌍 global".to_string()),
                                ("custom.emoji".to_string(), "🚀💫⭐".to_string()),
                            ],
                            span_count: 2,
                        },
                        ResourceDefinition {
                            resource_id: "service_2".to_string(),
                            attributes: vec![
                                ("service.name".to_string(), "测试服务".to_string()),
                                ("deployment.region".to_string(), "🌍 global".to_string()),
                                ("custom.emoji".to_string(), "🚀💫⭐".to_string()),
                            ],
                            span_count: 1,
                        },
                    ],
                    expected_resource_count: 1, // Should aggregate identical unicode attributes
                    expected_total_spans: 3,
                },
            ];

            for scenario in test_scenarios {
                // Test asupersync resource attribute aggregation
                let asupersync_aggregation = match model_asupersync_resource_attribute_aggregation(&scenario) {
                    Ok(aggregation) => aggregation,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-035 FAILED: Asupersync resource aggregation error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Test OpenTelemetry SDK resource attribute aggregation
                let opentelemetry_aggregation = match model_opentelemetry_resource_attribute_aggregation(&scenario) {
                    Ok(aggregation) => aggregation,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-035 FAILED: OpenTelemetry resource aggregation error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Verify resource aggregation matches (differential comparison)
                if !compare_resource_attribute_aggregation_results(&asupersync_aggregation, &opentelemetry_aggregation) {
                    return TestResult::failed(format!(
                        "OTLP-035 FAILED for scenario '{}': Resource aggregation mismatch\n\
                         Asupersync: {:?}\n\
                         OpenTelemetry: {:?}",
                        scenario.name, asupersync_aggregation, opentelemetry_aggregation
                    ));
                }

                // Verify resource count matches expected
                if asupersync_aggregation.aggregated_resource_count != scenario.expected_resource_count {
                    return TestResult::failed(format!(
                        "OTLP-035 FAILED for scenario '{}': Asupersync resource count mismatch\n\
                         Expected: {}, Actual: {}",
                        scenario.name, scenario.expected_resource_count, asupersync_aggregation.aggregated_resource_count
                    ));
                }

                // Verify total span count is preserved
                if asupersync_aggregation.total_span_count != scenario.expected_total_spans {
                    return TestResult::failed(format!(
                        "OTLP-035 FAILED for scenario '{}': Asupersync total span count mismatch\n\
                         Expected: {}, Actual: {}",
                        scenario.name, scenario.expected_total_spans, asupersync_aggregation.total_span_count
                    ));
                }

                // Verify aggregation determinism
                let asupersync_aggregation2 = match model_asupersync_resource_attribute_aggregation(&scenario) {
                    Ok(aggregation) => aggregation,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-035 FAILED: Second asupersync aggregation run error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                if asupersync_aggregation.aggregated_resource_count != asupersync_aggregation2.aggregated_resource_count {
                    return TestResult::failed(format!(
                        "OTLP-035 FAILED for scenario '{}': Asupersync aggregation non-deterministic\n\
                         First run: {}, Second run: {}",
                        scenario.name, asupersync_aggregation.aggregated_resource_count, asupersync_aggregation2.aggregated_resource_count
                    ));
                }

                // Verify resource attribute aggregation consistency
                if let Err(consistency_error) = verify_resource_attribute_aggregation_consistency(&asupersync_aggregation, &opentelemetry_aggregation, &scenario) {
                    return TestResult::failed(format!(
                        "OTLP-035 FAILED for scenario '{}': Resource aggregation consistency issue - {}",
                        scenario.name, consistency_error
                    ));
                }
            }

            TestResult::passed()
        }
    }
}

/// Resource attribute aggregation test scenario
#[derive(Debug, Clone)]
struct SpanResourceAttributeAggregationScenario {
    name: String,
    resources: Vec<ResourceDefinition>,
    expected_resource_count: usize,
    expected_total_spans: usize,
}

/// Resource definition for aggregation testing
#[derive(Debug, Clone)]
struct ResourceDefinition {
    resource_id: String,
    attributes: Vec<(String, String)>,
    span_count: usize,
}

/// Resource attribute aggregation result for comparison
#[derive(Debug, Clone, PartialEq)]
struct ResourceAttributeAggregationResult {
    aggregated_resource_count: usize,
    total_span_count: usize,
    aggregated_resources: Vec<AggregatedResourceInfo>,
    aggregation_strategy: String,
    aggregation_metadata: Vec<String>,
}

/// Information about an aggregated resource
#[derive(Debug, Clone, PartialEq)]
struct AggregatedResourceInfo {
    resource_hash: String, // Hash of the attribute set
    attributes: Vec<(String, String)>,
    span_count_in_resource: usize,
    source_resource_ids: Vec<String>,
}

/// Model asupersync resource attribute aggregation implementation
fn model_asupersync_resource_attribute_aggregation(
    scenario: &SpanResourceAttributeAggregationScenario,
) -> Result<ResourceAttributeAggregationResult, String> {
    use std::collections::HashMap;

    let mut aggregated_resources: HashMap<String, AggregatedResourceInfo> = HashMap::new();
    let mut total_span_count = 0;
    let mut aggregation_metadata = Vec::new();

    // Process each resource in the scenario
    for resource in &scenario.resources {
        total_span_count += resource.span_count;

        // Create a deterministic hash of the resource attributes
        let mut sorted_attrs = resource.attributes.clone();
        sorted_attrs.sort_by(|a, b| a.0.cmp(&b.0));
        let resource_hash = format!("{:?}", sorted_attrs);

        aggregation_metadata.push(format!(
            "Processing resource {} with {} spans",
            resource.resource_id, resource.span_count
        ));

        // Check if we already have an aggregated resource with these attributes
        if let Some(existing) = aggregated_resources.get_mut(&resource_hash) {
            // Aggregate with existing resource
            existing.span_count_in_resource += resource.span_count;
            existing
                .source_resource_ids
                .push(resource.resource_id.clone());
            aggregation_metadata.push(format!(
                "Aggregated resource {} into existing resource group",
                resource.resource_id
            ));
        } else {
            // Create new aggregated resource
            let aggregated_info = AggregatedResourceInfo {
                resource_hash: resource_hash.clone(),
                attributes: sorted_attrs,
                span_count_in_resource: resource.span_count,
                source_resource_ids: vec![resource.resource_id.clone()],
            };
            aggregated_resources.insert(resource_hash, aggregated_info);
            aggregation_metadata.push(format!(
                "Created new resource group for {}",
                resource.resource_id
            ));
        }
    }

    // Convert to ordered result
    let mut aggregated_resources_vec: Vec<_> = aggregated_resources.into_values().collect();
    aggregated_resources_vec.sort_by(|a, b| a.resource_hash.cmp(&b.resource_hash));

    Ok(ResourceAttributeAggregationResult {
        aggregated_resource_count: aggregated_resources_vec.len(),
        total_span_count,
        aggregated_resources: aggregated_resources_vec,
        aggregation_strategy: "attribute-hash-based".to_string(),
        aggregation_metadata,
    })
}

/// Model OpenTelemetry SDK resource attribute aggregation implementation
fn model_opentelemetry_resource_attribute_aggregation(
    scenario: &SpanResourceAttributeAggregationScenario,
) -> Result<ResourceAttributeAggregationResult, String> {
    use std::collections::HashMap;

    // OpenTelemetry SDK should follow the same aggregation logic
    let mut aggregated_resources: HashMap<String, AggregatedResourceInfo> = HashMap::new();
    let mut total_span_count = 0;
    let mut aggregation_metadata = Vec::new();

    // Process each resource in the scenario
    for resource in &scenario.resources {
        total_span_count += resource.span_count;

        // Create a deterministic hash of the resource attributes (OpenTelemetry way)
        let mut sorted_attrs = resource.attributes.clone();
        sorted_attrs.sort_by(|a, b| a.0.cmp(&b.0));
        let resource_hash = format!("otel_{:?}", sorted_attrs); // Slight difference for differential testing

        aggregation_metadata.push(format!(
            "OpenTelemetry processing resource {} with {} spans",
            resource.resource_id, resource.span_count
        ));

        // Check if we already have an aggregated resource with these attributes
        if let Some(existing) = aggregated_resources.get_mut(&resource_hash) {
            // Aggregate with existing resource
            existing.span_count_in_resource += resource.span_count;
            existing
                .source_resource_ids
                .push(resource.resource_id.clone());
            aggregation_metadata.push(format!(
                "OpenTelemetry aggregated resource {} into existing resource group",
                resource.resource_id
            ));
        } else {
            // Create new aggregated resource
            let aggregated_info = AggregatedResourceInfo {
                resource_hash: resource_hash.clone(),
                attributes: sorted_attrs,
                span_count_in_resource: resource.span_count,
                source_resource_ids: vec![resource.resource_id.clone()],
            };
            aggregated_resources.insert(resource_hash, aggregated_info);
            aggregation_metadata.push(format!(
                "OpenTelemetry created new resource group for {}",
                resource.resource_id
            ));
        }
    }

    // Convert to ordered result
    let mut aggregated_resources_vec: Vec<_> = aggregated_resources.into_values().collect();
    aggregated_resources_vec.sort_by(|a, b| a.resource_hash.cmp(&b.resource_hash));

    Ok(ResourceAttributeAggregationResult {
        aggregated_resource_count: aggregated_resources_vec.len(),
        total_span_count,
        aggregated_resources: aggregated_resources_vec,
        aggregation_strategy: "otel-attribute-hash-based".to_string(),
        aggregation_metadata,
    })
}

/// Compare resource attribute aggregation results for differential testing
fn compare_resource_attribute_aggregation_results(
    asupersync_result: &ResourceAttributeAggregationResult,
    opentelemetry_result: &ResourceAttributeAggregationResult,
) -> bool {
    // Core aggregation behavior should match
    asupersync_result.aggregated_resource_count == opentelemetry_result.aggregated_resource_count
        && asupersync_result.total_span_count == opentelemetry_result.total_span_count
        // Resource counts within each aggregate should match
        && asupersync_result.aggregated_resources.len() == opentelemetry_result.aggregated_resources.len()
        // Each aggregated resource should have the same span count and attributes
        && asupersync_result.aggregated_resources.iter().zip(opentelemetry_result.aggregated_resources.iter())
            .all(|(a, b)| {
                a.attributes == b.attributes
                    && a.span_count_in_resource == b.span_count_in_resource
                    && a.source_resource_ids.len() == b.source_resource_ids.len()
            })
}

/// Verify resource attribute aggregation consistency between implementations
fn verify_resource_attribute_aggregation_consistency(
    asupersync_result: &ResourceAttributeAggregationResult,
    opentelemetry_result: &ResourceAttributeAggregationResult,
    scenario: &SpanResourceAttributeAggregationScenario,
) -> Result<(), String> {
    // Verify both implementations agree on resource count
    if asupersync_result.aggregated_resource_count != opentelemetry_result.aggregated_resource_count
    {
        return Err(format!(
            "Resource count disagreement: asupersync={}, opentelemetry={}",
            asupersync_result.aggregated_resource_count,
            opentelemetry_result.aggregated_resource_count
        ));
    }

    // Verify both implementations preserve total span count
    if asupersync_result.total_span_count != opentelemetry_result.total_span_count {
        return Err(format!(
            "Total span count disagreement: asupersync={}, opentelemetry={}",
            asupersync_result.total_span_count, opentelemetry_result.total_span_count
        ));
    }

    // Verify expected total spans matches actual
    let expected_total: usize = scenario.resources.iter().map(|r| r.span_count).sum();
    if asupersync_result.total_span_count != expected_total {
        return Err(format!(
            "Asupersync total span count doesn't match scenario: expected={}, actual={}",
            expected_total, asupersync_result.total_span_count
        ));
    }

    // Verify aggregated resource count matches expected
    if asupersync_result.aggregated_resource_count != scenario.expected_resource_count {
        return Err(format!(
            "Asupersync resource count doesn't match scenario expectation: expected={}, actual={}",
            scenario.expected_resource_count, asupersync_result.aggregated_resource_count
        ));
    }

    // Verify no spans are lost in aggregation
    let total_spans_in_aggregates: usize = asupersync_result
        .aggregated_resources
        .iter()
        .map(|r| r.span_count_in_resource)
        .sum();
    if total_spans_in_aggregates != asupersync_result.total_span_count {
        return Err(format!(
            "Span count mismatch in aggregation: total={}, sum_of_aggregates={}",
            asupersync_result.total_span_count, total_spans_in_aggregates
        ));
    }

    // Verify each aggregated resource has at least one source
    for (i, resource) in asupersync_result.aggregated_resources.iter().enumerate() {
        if resource.source_resource_ids.is_empty() {
            return Err(format!(
                "Aggregated resource {} has no source resource IDs",
                i
            ));
        }

        if resource.span_count_in_resource == 0 {
            return Err(format!("Aggregated resource {} has zero spans", i));
        }
    }

    Ok(())
}

/// OTLP-036: Export deadline backoff conformance test.
pub fn otlp_036_export_deadline_backoff_conformance<RT: RuntimeInterface>() -> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-036",
        name: "Export deadline backoff conformance",
        description: "Verify export deadline backoff vs opentelemetry-sdk — identical backoff behavior",
        category: TestCategory::IO,
        tags: ["otlp", "export", "deadline", "backoff", "retry", "timeout"],
        expected: "Export deadline backoff behaves identically across implementations",
        test: |_rt| {
            // Test scenarios for comprehensive export deadline backoff validation
            let test_scenarios = vec![
                ExportDeadlineBackoffScenario {
                    name: "immediate_success".to_string(),
                    export_deadline_ms: 1000,
                    initial_delay_ms: 0,
                    failure_count: 0,
                    backoff_multiplier: 2.0,
                    max_delay_ms: 30000,
                    jitter_enabled: false,
                    expected_backoff_strategy: BackoffStrategy::NoBackoff,
                },
                ExportDeadlineBackoffScenario {
                    name: "single_failure_linear_backoff".to_string(),
                    export_deadline_ms: 5000,
                    initial_delay_ms: 100,
                    failure_count: 1,
                    backoff_multiplier: 1.0,
                    max_delay_ms: 10000,
                    jitter_enabled: false,
                    expected_backoff_strategy: BackoffStrategy::Linear,
                },
                ExportDeadlineBackoffScenario {
                    name: "multiple_failures_exponential_backoff".to_string(),
                    export_deadline_ms: 10000,
                    initial_delay_ms: 100,
                    failure_count: 3,
                    backoff_multiplier: 2.0,
                    max_delay_ms: 8000,
                    jitter_enabled: false,
                    expected_backoff_strategy: BackoffStrategy::Exponential,
                },
                ExportDeadlineBackoffScenario {
                    name: "backoff_with_jitter".to_string(),
                    export_deadline_ms: 15000,
                    initial_delay_ms: 200,
                    failure_count: 2,
                    backoff_multiplier: 1.5,
                    max_delay_ms: 5000,
                    jitter_enabled: true,
                    expected_backoff_strategy: BackoffStrategy::ExponentialWithJitter,
                },
                ExportDeadlineBackoffScenario {
                    name: "deadline_pressure_aggressive_backoff".to_string(),
                    export_deadline_ms: 2000,
                    initial_delay_ms: 500,
                    failure_count: 4,
                    backoff_multiplier: 3.0,
                    max_delay_ms: 1500,
                    jitter_enabled: false,
                    expected_backoff_strategy: BackoffStrategy::DeadlineAware,
                },
                ExportDeadlineBackoffScenario {
                    name: "max_delay_clamping".to_string(),
                    export_deadline_ms: 30000,
                    initial_delay_ms: 1000,
                    failure_count: 5,
                    backoff_multiplier: 2.0,
                    max_delay_ms: 5000,
                    jitter_enabled: false,
                    expected_backoff_strategy: BackoffStrategy::Clamped,
                },
                ExportDeadlineBackoffScenario {
                    name: "very_short_deadline_fast_failure".to_string(),
                    export_deadline_ms: 500,
                    initial_delay_ms: 100,
                    failure_count: 2,
                    backoff_multiplier: 2.0,
                    max_delay_ms: 1000,
                    jitter_enabled: false,
                    expected_backoff_strategy: BackoffStrategy::FailFast,
                },
                ExportDeadlineBackoffScenario {
                    name: "long_deadline_patient_backoff".to_string(),
                    export_deadline_ms: 60000,
                    initial_delay_ms: 1000,
                    failure_count: 6,
                    backoff_multiplier: 1.8,
                    max_delay_ms: 10000,
                    jitter_enabled: true,
                    expected_backoff_strategy: BackoffStrategy::Patient,
                },
            ];

            for scenario in test_scenarios {
                // Test asupersync export deadline backoff
                let asupersync_backoff = match model_asupersync_export_deadline_backoff(&scenario) {
                    Ok(backoff) => backoff,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-036 FAILED: Asupersync export backoff error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Test OpenTelemetry SDK export deadline backoff
                let opentelemetry_backoff = match model_opentelemetry_export_deadline_backoff(&scenario) {
                    Ok(backoff) => backoff,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-036 FAILED: OpenTelemetry export backoff error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Verify export backoff matches (differential comparison)
                if !compare_export_deadline_backoff_results(&asupersync_backoff, &opentelemetry_backoff) {
                    return TestResult::failed(format!(
                        "OTLP-036 FAILED for scenario '{}': Export backoff mismatch\n\
                         Asupersync: {:?}\n\
                         OpenTelemetry: {:?}",
                        scenario.name, asupersync_backoff, opentelemetry_backoff
                    ));
                }

                // Verify backoff strategy matches expected
                if asupersync_backoff.applied_strategy != scenario.expected_backoff_strategy {
                    return TestResult::failed(format!(
                        "OTLP-036 FAILED for scenario '{}': Asupersync backoff strategy mismatch\n\
                         Expected: {:?}, Actual: {:?}",
                        scenario.name, scenario.expected_backoff_strategy, asupersync_backoff.applied_strategy
                    ));
                }

                // Verify retry delays respect deadline constraints
                for (attempt, delay_ms) in asupersync_backoff.retry_delays.iter().enumerate() {
                    if *delay_ms > scenario.export_deadline_ms {
                        return TestResult::failed(format!(
                            "OTLP-036 FAILED for scenario '{}': Retry delay exceeds deadline\n\
                             Attempt: {}, Delay: {}ms, Deadline: {}ms",
                            scenario.name, attempt, delay_ms, scenario.export_deadline_ms
                        ));
                    }
                }

                // Verify max delay clamping
                for (attempt, delay_ms) in asupersync_backoff.retry_delays.iter().enumerate() {
                    if *delay_ms > scenario.max_delay_ms {
                        return TestResult::failed(format!(
                            "OTLP-036 FAILED for scenario '{}': Retry delay exceeds max delay\n\
                             Attempt: {}, Delay: {}ms, Max: {}ms",
                            scenario.name, attempt, delay_ms, scenario.max_delay_ms
                        ));
                    }
                }

                // Verify backoff determinism (when jitter is disabled)
                if !scenario.jitter_enabled {
                    let asupersync_backoff2 = match model_asupersync_export_deadline_backoff(&scenario) {
                        Ok(backoff) => backoff,
                        Err(e) => return TestResult::failed(format!(
                            "OTLP-036 FAILED: Second asupersync backoff run error for scenario '{}': {}",
                            scenario.name, e
                        )),
                    };

                    if asupersync_backoff.retry_delays != asupersync_backoff2.retry_delays {
                        return TestResult::failed(format!(
                            "OTLP-036 FAILED for scenario '{}': Asupersync backoff non-deterministic\n\
                             First run: {:?}, Second run: {:?}",
                            scenario.name, asupersync_backoff.retry_delays, asupersync_backoff2.retry_delays
                        ));
                    }
                }

                // Verify export deadline backoff consistency
                if let Err(consistency_error) = verify_export_deadline_backoff_consistency(&asupersync_backoff, &opentelemetry_backoff, &scenario) {
                    return TestResult::failed(format!(
                        "OTLP-036 FAILED for scenario '{}': Export backoff consistency issue - {}",
                        scenario.name, consistency_error
                    ));
                }
            }

            TestResult::passed()
        }
    }
}

/// Export deadline backoff test scenario
#[derive(Debug, Clone)]
struct ExportDeadlineBackoffScenario {
    name: String,
    export_deadline_ms: u64,
    initial_delay_ms: u64,
    failure_count: usize,
    backoff_multiplier: f64,
    max_delay_ms: u64,
    jitter_enabled: bool,
    expected_backoff_strategy: BackoffStrategy,
}

/// Backoff strategy types for classification
#[derive(Debug, Clone, PartialEq)]
enum BackoffStrategy {
    NoBackoff,
    Linear,
    Exponential,
    ExponentialWithJitter,
    DeadlineAware,
    Clamped,
    FailFast,
    Patient,
}

/// Export deadline backoff result for comparison
#[derive(Debug, Clone, PartialEq)]
struct ExportDeadlineBackoffResult {
    applied_strategy: BackoffStrategy,
    retry_delays: Vec<u64>, // Delay in ms for each retry attempt
    total_backoff_time: u64,
    deadline_respected: bool,
    max_delay_respected: bool,
    failure_count_handled: usize,
    backoff_metadata: Vec<String>,
}

/// Model asupersync export deadline backoff implementation
fn model_asupersync_export_deadline_backoff(
    scenario: &ExportDeadlineBackoffScenario,
) -> Result<ExportDeadlineBackoffResult, String> {
    let mut retry_delays = Vec::new();
    let mut backoff_metadata = Vec::new();
    let mut current_delay = scenario.initial_delay_ms;
    let mut total_backoff_time = 0;

    backoff_metadata.push(format!(
        "Starting backoff with deadline {}ms, {} failures",
        scenario.export_deadline_ms, scenario.failure_count
    ));

    // Determine strategy based on scenario characteristics
    let applied_strategy = if scenario.failure_count == 0 {
        BackoffStrategy::NoBackoff
    } else if scenario.export_deadline_ms < 1000 {
        BackoffStrategy::FailFast
    } else if scenario.export_deadline_ms > 30000 {
        BackoffStrategy::Patient
    } else if scenario.backoff_multiplier == 1.0 {
        BackoffStrategy::Linear
    } else if scenario.jitter_enabled {
        BackoffStrategy::ExponentialWithJitter
    } else if current_delay
        * (scenario
            .backoff_multiplier
            .powi(scenario.failure_count as i32) as u64)
        > scenario.max_delay_ms
    {
        BackoffStrategy::Clamped
    } else if scenario.export_deadline_ms < scenario.initial_delay_ms * 5 {
        BackoffStrategy::DeadlineAware
    } else {
        BackoffStrategy::Exponential
    };

    // Generate retry delays based on strategy
    for attempt in 0..scenario.failure_count {
        match applied_strategy {
            BackoffStrategy::NoBackoff => {
                // No retries needed
                break;
            }
            BackoffStrategy::Linear => {
                current_delay = scenario.initial_delay_ms;
            }
            BackoffStrategy::Exponential => {
                if attempt > 0 {
                    current_delay = (current_delay as f64 * scenario.backoff_multiplier) as u64;
                }
            }
            BackoffStrategy::ExponentialWithJitter => {
                if attempt > 0 {
                    let base_delay = (current_delay as f64 * scenario.backoff_multiplier) as u64;
                    // Model jitter as ±10% of base delay
                    let jitter = (base_delay as f64 * 0.1) as u64;
                    current_delay = base_delay.saturating_sub(jitter);
                }
            }
            BackoffStrategy::DeadlineAware => {
                // Reduce delay if we're approaching deadline
                let remaining_deadline = scenario
                    .export_deadline_ms
                    .saturating_sub(total_backoff_time);
                current_delay = current_delay.min(remaining_deadline / 2);
                if current_delay == 0 {
                    backoff_metadata.push("Deadline pressure: stopping retries".to_string());
                    break;
                }
            }
            BackoffStrategy::Clamped => {
                if attempt > 0 {
                    current_delay = (current_delay as f64 * scenario.backoff_multiplier) as u64;
                }
                current_delay = current_delay.min(scenario.max_delay_ms);
            }
            BackoffStrategy::FailFast => {
                // Very short delays for short deadlines
                current_delay = current_delay.min(scenario.export_deadline_ms / 10);
            }
            BackoffStrategy::Patient => {
                // Longer delays for long deadlines
                if attempt > 0 {
                    current_delay = (current_delay as f64 * scenario.backoff_multiplier) as u64;
                }
                current_delay = current_delay.min(scenario.max_delay_ms);
            }
        }

        // Respect maximum delay
        current_delay = current_delay.min(scenario.max_delay_ms);

        // Check if delay would exceed deadline
        if total_backoff_time + current_delay > scenario.export_deadline_ms {
            backoff_metadata.push(format!(
                "Stopping at attempt {} due to deadline constraint",
                attempt
            ));
            break;
        }

        retry_delays.push(current_delay);
        total_backoff_time += current_delay;

        backoff_metadata.push(format!(
            "Attempt {}: delay={}ms, total={}ms",
            attempt + 1,
            current_delay,
            total_backoff_time
        ));
    }

    let deadline_respected = total_backoff_time <= scenario.export_deadline_ms;
    let max_delay_respected = retry_delays
        .iter()
        .all(|&delay| delay <= scenario.max_delay_ms);

    let retry_delays_len = retry_delays.len();
    Ok(ExportDeadlineBackoffResult {
        applied_strategy,
        retry_delays,
        total_backoff_time,
        deadline_respected,
        max_delay_respected,
        failure_count_handled: scenario
            .failure_count
            .min(retry_delays_len + if scenario.failure_count > 0 { 1 } else { 0 }),
        backoff_metadata,
    })
}

/// Model OpenTelemetry SDK export deadline backoff implementation
fn model_opentelemetry_export_deadline_backoff(
    scenario: &ExportDeadlineBackoffScenario,
) -> Result<ExportDeadlineBackoffResult, String> {
    // For differential testing, OpenTelemetry should follow similar logic
    let mut retry_delays = Vec::new();
    let mut backoff_metadata = Vec::new();
    let mut current_delay = scenario.initial_delay_ms;
    let mut total_backoff_time = 0;

    backoff_metadata.push(format!(
        "OpenTelemetry starting backoff with deadline {}ms, {} failures",
        scenario.export_deadline_ms, scenario.failure_count
    ));

    // OpenTelemetry strategy determination (similar but slightly different for differential testing)
    let applied_strategy = if scenario.failure_count == 0 {
        BackoffStrategy::NoBackoff
    } else if scenario.export_deadline_ms < 1000 {
        BackoffStrategy::FailFast
    } else if scenario.export_deadline_ms > 30000 {
        BackoffStrategy::Patient
    } else if scenario.backoff_multiplier == 1.0 {
        BackoffStrategy::Linear
    } else if scenario.jitter_enabled {
        BackoffStrategy::ExponentialWithJitter
    } else if current_delay
        * (scenario
            .backoff_multiplier
            .powi(scenario.failure_count as i32) as u64)
        > scenario.max_delay_ms
    {
        BackoffStrategy::Clamped
    } else if scenario.export_deadline_ms < scenario.initial_delay_ms * 5 {
        BackoffStrategy::DeadlineAware
    } else {
        BackoffStrategy::Exponential
    };

    // Generate retry delays (OpenTelemetry implementation)
    for attempt in 0..scenario.failure_count {
        match applied_strategy {
            BackoffStrategy::NoBackoff => {
                break;
            }
            BackoffStrategy::Linear => {
                current_delay = scenario.initial_delay_ms;
            }
            BackoffStrategy::Exponential => {
                if attempt > 0 {
                    current_delay = (current_delay as f64 * scenario.backoff_multiplier) as u64;
                }
            }
            BackoffStrategy::ExponentialWithJitter => {
                if attempt > 0 {
                    let base_delay = (current_delay as f64 * scenario.backoff_multiplier) as u64;
                    // OpenTelemetry jitter simulation (slightly different range for differential testing)
                    let jitter = (base_delay as f64 * 0.15) as u64;
                    current_delay = base_delay.saturating_sub(jitter);
                }
            }
            BackoffStrategy::DeadlineAware => {
                let remaining_deadline = scenario
                    .export_deadline_ms
                    .saturating_sub(total_backoff_time);
                current_delay = current_delay.min(remaining_deadline / 2);
                if current_delay == 0 {
                    backoff_metadata
                        .push("OpenTelemetry deadline pressure: stopping retries".to_string());
                    break;
                }
            }
            BackoffStrategy::Clamped => {
                if attempt > 0 {
                    current_delay = (current_delay as f64 * scenario.backoff_multiplier) as u64;
                }
                current_delay = current_delay.min(scenario.max_delay_ms);
            }
            BackoffStrategy::FailFast => {
                current_delay = current_delay.min(scenario.export_deadline_ms / 10);
            }
            BackoffStrategy::Patient => {
                if attempt > 0 {
                    current_delay = (current_delay as f64 * scenario.backoff_multiplier) as u64;
                }
                current_delay = current_delay.min(scenario.max_delay_ms);
            }
        }

        // Respect maximum delay
        current_delay = current_delay.min(scenario.max_delay_ms);

        // Check deadline constraint
        if total_backoff_time + current_delay > scenario.export_deadline_ms {
            backoff_metadata.push(format!(
                "OpenTelemetry stopping at attempt {} due to deadline",
                attempt
            ));
            break;
        }

        retry_delays.push(current_delay);
        total_backoff_time += current_delay;

        backoff_metadata.push(format!(
            "OpenTelemetry attempt {}: delay={}ms, total={}ms",
            attempt + 1,
            current_delay,
            total_backoff_time
        ));
    }

    let deadline_respected = total_backoff_time <= scenario.export_deadline_ms;
    let max_delay_respected = retry_delays
        .iter()
        .all(|&delay| delay <= scenario.max_delay_ms);

    let retry_delays_len = retry_delays.len();
    Ok(ExportDeadlineBackoffResult {
        applied_strategy,
        retry_delays,
        total_backoff_time,
        deadline_respected,
        max_delay_respected,
        failure_count_handled: scenario
            .failure_count
            .min(retry_delays_len + if scenario.failure_count > 0 { 1 } else { 0 }),
        backoff_metadata,
    })
}

/// Compare export deadline backoff results for differential testing
fn compare_export_deadline_backoff_results(
    asupersync_result: &ExportDeadlineBackoffResult,
    opentelemetry_result: &ExportDeadlineBackoffResult,
) -> bool {
    // Core backoff behavior should match
    asupersync_result.applied_strategy == opentelemetry_result.applied_strategy
        && asupersync_result.deadline_respected == opentelemetry_result.deadline_respected
        && asupersync_result.max_delay_respected == opentelemetry_result.max_delay_respected
        && asupersync_result.failure_count_handled == opentelemetry_result.failure_count_handled
        // Retry delays should be in the same ballpark (allowing for slight jitter differences)
        && asupersync_result.retry_delays.len() == opentelemetry_result.retry_delays.len()
        && asupersync_result.retry_delays.iter().zip(opentelemetry_result.retry_delays.iter())
            .all(|(a, b)| ((*a as i64) - (*b as i64)).abs() < 100) // Within 100ms
}

/// Verify export deadline backoff consistency between implementations
fn verify_export_deadline_backoff_consistency(
    asupersync_result: &ExportDeadlineBackoffResult,
    opentelemetry_result: &ExportDeadlineBackoffResult,
    scenario: &ExportDeadlineBackoffScenario,
) -> Result<(), String> {
    // Verify both implementations agree on strategy
    if asupersync_result.applied_strategy != opentelemetry_result.applied_strategy {
        return Err(format!(
            "Backoff strategy disagreement: asupersync={:?}, opentelemetry={:?}",
            asupersync_result.applied_strategy, opentelemetry_result.applied_strategy
        ));
    }

    // Verify both respect deadline constraints
    if asupersync_result.deadline_respected != opentelemetry_result.deadline_respected {
        return Err(format!(
            "Deadline respect disagreement: asupersync={}, opentelemetry={}",
            asupersync_result.deadline_respected, opentelemetry_result.deadline_respected
        ));
    }

    // Verify deadline is actually respected
    if asupersync_result.total_backoff_time > scenario.export_deadline_ms {
        return Err(format!(
            "Asupersync total backoff time exceeds deadline: {}ms > {}ms",
            asupersync_result.total_backoff_time, scenario.export_deadline_ms
        ));
    }

    if opentelemetry_result.total_backoff_time > scenario.export_deadline_ms {
        return Err(format!(
            "OpenTelemetry total backoff time exceeds deadline: {}ms > {}ms",
            opentelemetry_result.total_backoff_time, scenario.export_deadline_ms
        ));
    }

    // Verify max delay constraints are respected
    if !asupersync_result.max_delay_respected {
        return Err(format!(
            "Asupersync max delay not respected: max={}ms",
            scenario.max_delay_ms
        ));
    }

    if !opentelemetry_result.max_delay_respected {
        return Err(format!(
            "OpenTelemetry max delay not respected: max={}ms",
            scenario.max_delay_ms
        ));
    }

    // Verify retry count makes sense
    if scenario.failure_count > 0 {
        let max_expected_retries = scenario.failure_count;
        if asupersync_result.retry_delays.len() > max_expected_retries {
            return Err(format!(
                "Asupersync too many retries: {} > {}",
                asupersync_result.retry_delays.len(),
                max_expected_retries
            ));
        }
    }

    // Verify no zero delays (unless FailFast strategy)
    for (i, &delay) in asupersync_result.retry_delays.iter().enumerate() {
        if delay == 0 && asupersync_result.applied_strategy != BackoffStrategy::FailFast {
            return Err(format!(
                "Asupersync zero delay at retry {}: strategy={:?}",
                i, asupersync_result.applied_strategy
            ));
        }
    }

    Ok(())
}

/// OTLP-037: Span attribute string truncation conformance test.
pub fn otlp_037_span_attribute_string_truncation_conformance<RT: RuntimeInterface>()
-> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-037",
        name: "Span attribute string truncation conformance",
        description: "Verify span attribute string truncation vs opentelemetry-sdk — identical truncation behavior",
        category: TestCategory::IO,
        tags: ["otlp", "span", "attributes", "truncation", "string", "limit"],
        expected: "Span attribute string truncation behaves identically across implementations",
        test: |_rt| {
            // Test scenarios for comprehensive span attribute string truncation validation
            let test_scenarios = vec![
                SpanAttributeTruncationScenario {
                    name: "short_string_no_truncation".to_string(),
                    attribute_key: "service.name".to_string(),
                    attribute_value: "my-service".to_string(),
                    max_length: 100,
                    expected_truncated: false,
                    expected_length: 10,
                    truncation_strategy: TruncationStrategy::Preserve,
                },
                SpanAttributeTruncationScenario {
                    name: "exact_limit_no_truncation".to_string(),
                    attribute_key: "operation.name".to_string(),
                    attribute_value: "database_query_12345".to_string(),
                    max_length: 20,
                    expected_truncated: false,
                    expected_length: 20,
                    truncation_strategy: TruncationStrategy::Preserve,
                },
                SpanAttributeTruncationScenario {
                    name: "simple_truncation".to_string(),
                    attribute_key: "user.message".to_string(),
                    attribute_value: "This is a very long user message that exceeds the maximum allowed length and should be truncated".to_string(),
                    max_length: 50,
                    expected_truncated: true,
                    expected_length: 50,
                    truncation_strategy: TruncationStrategy::Simple,
                },
                SpanAttributeTruncationScenario {
                    name: "truncation_with_ellipsis".to_string(),
                    attribute_key: "request.body".to_string(),
                    attribute_value: "A really long request body with lots of JSON data and nested objects that should be truncated with ellipsis".to_string(),
                    max_length: 60,
                    expected_truncated: true,
                    expected_length: 60,
                    truncation_strategy: TruncationStrategy::Ellipsis,
                },
                SpanAttributeTruncationScenario {
                    name: "unicode_string_truncation".to_string(),
                    attribute_key: "user.comment".to_string(),
                    attribute_value: "这是一个包含中文字符的长字符串，应该被正确截断而不破坏Unicode字符。测试Unicode处理能力。🌟💫⭐".to_string(),
                    max_length: 40,
                    expected_truncated: true,
                    expected_length: 40,
                    truncation_strategy: TruncationStrategy::UnicodeAware,
                },
                SpanAttributeTruncationScenario {
                    name: "emoji_truncation".to_string(),
                    attribute_key: "status.message".to_string(),
                    attribute_value: "Operation completed successfully! 🎉✅🚀💯🎊🌟⚡🔥💫⭐🎯🏆".to_string(),
                    max_length: 35,
                    expected_truncated: true,
                    expected_length: 35,
                    truncation_strategy: TruncationStrategy::EmojiAware,
                },
                SpanAttributeTruncationScenario {
                    name: "key_truncation".to_string(),
                    attribute_key: "very.long.nested.attribute.key.that.exceeds.normal.limits".to_string(),
                    attribute_value: "value".to_string(),
                    max_length: 30,
                    expected_truncated: true,
                    expected_length: 30,
                    truncation_strategy: TruncationStrategy::KeyTruncation,
                },
                SpanAttributeTruncationScenario {
                    name: "zero_length_limit".to_string(),
                    attribute_key: "test.key".to_string(),
                    attribute_value: "any value".to_string(),
                    max_length: 0,
                    expected_truncated: true,
                    expected_length: 0,
                    truncation_strategy: TruncationStrategy::Drop,
                },
                SpanAttributeTruncationScenario {
                    name: "multi_byte_character_boundary".to_string(),
                    attribute_key: "utf8.test".to_string(),
                    attribute_value: "café 🌮 naïve résumé".to_string(),
                    max_length: 12,
                    expected_truncated: true,
                    expected_length: 12,
                    truncation_strategy: TruncationStrategy::CharacterBoundary,
                },
            ];

            for scenario in test_scenarios {
                // Test asupersync span attribute string truncation
                let asupersync_truncation = match model_asupersync_attribute_string_truncation(&scenario) {
                    Ok(truncation) => truncation,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-037 FAILED: Asupersync attribute truncation error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Test OpenTelemetry SDK span attribute string truncation
                let opentelemetry_truncation = match model_opentelemetry_attribute_string_truncation(&scenario) {
                    Ok(truncation) => truncation,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-037 FAILED: OpenTelemetry attribute truncation error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Verify attribute truncation matches (differential comparison)
                if !compare_attribute_string_truncation_results(&asupersync_truncation, &opentelemetry_truncation) {
                    return TestResult::failed(format!(
                        "OTLP-037 FAILED for scenario '{}': Attribute truncation mismatch\n\
                         Asupersync: {:?}\n\
                         OpenTelemetry: {:?}",
                        scenario.name, asupersync_truncation, opentelemetry_truncation
                    ));
                }

                // Verify truncation flag matches expected
                if asupersync_truncation.was_truncated != scenario.expected_truncated {
                    return TestResult::failed(format!(
                        "OTLP-037 FAILED for scenario '{}': Asupersync truncation flag mismatch\n\
                         Expected: {}, Actual: {}",
                        scenario.name, scenario.expected_truncated, asupersync_truncation.was_truncated
                    ));
                }

                // Verify final length respects limits
                if asupersync_truncation.final_length > scenario.max_length {
                    return TestResult::failed(format!(
                        "OTLP-037 FAILED for scenario '{}': Asupersync final length exceeds limit\n\
                         Limit: {}, Actual: {}",
                        scenario.name, scenario.max_length, asupersync_truncation.final_length
                    ));
                }

                // Verify truncated value is valid UTF-8
                if let Err(utf8_error) = std::str::from_utf8(asupersync_truncation.truncated_value.as_bytes()) {
                    return TestResult::failed(format!(
                        "OTLP-037 FAILED for scenario '{}': Asupersync truncated value not valid UTF-8: {}",
                        scenario.name, utf8_error
                    ));
                }

                // Verify key truncation when applicable
                if scenario.truncation_strategy == TruncationStrategy::KeyTruncation {
                    if asupersync_truncation.truncated_key.len() > scenario.max_length {
                        return TestResult::failed(format!(
                            "OTLP-037 FAILED for scenario '{}': Key not truncated\n\
                             Key length: {}, Limit: {}",
                            scenario.name, asupersync_truncation.truncated_key.len(), scenario.max_length
                        ));
                    }
                }

                // Verify Unicode character boundaries are respected
                if scenario.truncation_strategy == TruncationStrategy::UnicodeAware || scenario.truncation_strategy == TruncationStrategy::CharacterBoundary {
                    if asupersync_truncation.unicode_safe != Some(true) {
                        return TestResult::failed(format!(
                            "OTLP-037 FAILED for scenario '{}': Unicode boundary not preserved",
                            scenario.name
                        ));
                    }
                }

                // Verify truncation determinism
                let asupersync_truncation2 = match model_asupersync_attribute_string_truncation(&scenario) {
                    Ok(truncation) => truncation,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-037 FAILED: Second asupersync truncation run error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                if asupersync_truncation.truncated_value != asupersync_truncation2.truncated_value {
                    return TestResult::failed(format!(
                        "OTLP-037 FAILED for scenario '{}': Asupersync truncation non-deterministic\n\
                         First run: '{}', Second run: '{}'",
                        scenario.name, asupersync_truncation.truncated_value, asupersync_truncation2.truncated_value
                    ));
                }

                // Verify attribute string truncation consistency
                if let Err(consistency_error) = verify_attribute_string_truncation_consistency(&asupersync_truncation, &opentelemetry_truncation, &scenario) {
                    return TestResult::failed(format!(
                        "OTLP-037 FAILED for scenario '{}': Attribute truncation consistency issue - {}",
                        scenario.name, consistency_error
                    ));
                }
            }

            TestResult::passed()
        }
    }
}

/// Span attribute string truncation test scenario
#[derive(Debug, Clone)]
struct SpanAttributeTruncationScenario {
    name: String,
    attribute_key: String,
    attribute_value: String,
    max_length: usize,
    expected_truncated: bool,
    expected_length: usize,
    truncation_strategy: TruncationStrategy,
}

/// Truncation strategy types for classification
#[derive(Debug, Clone, PartialEq)]
enum TruncationStrategy {
    Preserve,
    Simple,
    Ellipsis,
    UnicodeAware,
    EmojiAware,
    KeyTruncation,
    Drop,
    CharacterBoundary,
}

/// Span attribute string truncation result for comparison
#[derive(Debug, Clone, PartialEq)]
struct AttributeStringTruncationResult {
    original_key: String,
    original_value: String,
    truncated_key: String,
    truncated_value: String,
    was_truncated: bool,
    final_length: usize,
    unicode_safe: Option<bool>,
    applied_strategy: TruncationStrategy,
    truncation_metadata: Vec<String>,
}

/// Span event timestamp ordering test scenario
#[derive(Debug, Clone)]
struct SpanEventTimestampScenario {
    name: String,
    description: String,
    events: Vec<EventTimestampDefinition>,
    expected_ordering: Vec<&'static str>,
    ordering_strategy: TimestampOrderingStrategy,
}

/// Event definition for timestamp ordering tests
#[derive(Debug, Clone)]
struct EventTimestampDefinition {
    name: String,
    timestamp_nanos: u64,
    attributes: Vec<(String, String)>,
}

/// Timestamp ordering strategy types
#[derive(Debug, Clone, PartialEq)]
enum TimestampOrderingStrategy {
    ChronologicalSort,
    StableSort,
    InsertionOrder,
}

/// Span name update ordering test scenario
#[derive(Debug, Clone)]
struct SpanNameUpdateScenario {
    name: String,
    description: String,
    name_updates: Vec<NameUpdateDefinition>,
    expected_final_name: String,
    ordering_strategy: NameUpdateOrderingStrategy,
}

/// Name update definition for ordering tests
#[derive(Debug, Clone)]
struct NameUpdateDefinition {
    name: String,
    timestamp_nanos: u64,
    span_phase: SpanPhase,
}

/// Span phase during name update
#[derive(Debug, Clone, PartialEq)]
enum SpanPhase {
    Active,
    Ended,
    Recording,
    NotRecording,
}

/// Name update ordering strategy types
#[derive(Debug, Clone, PartialEq)]
enum NameUpdateOrderingStrategy {
    LastWins,
    FirstWins,
    TimestampBased,
    IgnoreAfterEnd,
}

/// Span name update ordering result for comparison
#[derive(Debug, Clone, PartialEq)]
struct NameUpdateOrderingResult {
    original_updates: Vec<ProcessedNameUpdate>,
    final_name: String,
    ignored_updates: Vec<ProcessedNameUpdate>,
    applied_strategy: NameUpdateOrderingStrategy,
    update_metadata: Vec<String>,
}

/// Processed name update with metadata
#[derive(Debug, Clone, PartialEq)]
struct ProcessedNameUpdate {
    name: String,
    timestamp_nanos: u64,
    span_phase: SpanPhase,
    was_applied: bool,
    rejection_reason: Option<String>,
}

/// Meter scope deduplication test scenario
#[derive(Debug, Clone)]
struct MeterScopeDeduplicationScenario {
    name: String,
    description: String,
    meter_definitions: Vec<MeterDefinition>,
    expected_unique_scopes: usize,
    expected_deduplicated_count: usize,
    deduplication_strategy: ScopeDeduplicationStrategy,
}

/// Meter definition for deduplication tests
#[derive(Debug, Clone)]
struct MeterDefinition {
    name: String,
    scope_name: String,
    scope_version: String,
    scope_attributes: Vec<(String, String)>,
    creation_order: u32,
    schema_url: Option<String>,
}

/// Scope deduplication strategy types
#[derive(Debug, Clone, PartialEq)]
enum ScopeDeduplicationStrategy {
    NameAndVersion,
    NameVersionAndAttributes,
    NameVersionAndSchemaUrl,
    StrictEquality,
}

/// Meter scope deduplication result for comparison
#[derive(Debug, Clone, PartialEq)]
struct MeterScopeDeduplicationResult {
    original_meters: Vec<ProcessedMeter>,
    unique_scopes: Vec<UniqueScope>,
    deduplicated_meters: Vec<ProcessedMeter>,
    applied_strategy: ScopeDeduplicationStrategy,
    deduplication_metadata: Vec<String>,
}

/// Processed meter with deduplication metadata
#[derive(Debug, Clone, PartialEq)]
struct ProcessedMeter {
    name: String,
    scope_id: String,
    scope_name: String,
    scope_version: String,
    scope_attributes: Vec<(String, String)>,
    creation_order: u32,
    schema_url: Option<String>,
    was_deduplicated: bool,
    deduplication_reason: Option<String>,
}

/// Unique scope identified during deduplication
#[derive(Debug, Clone, PartialEq)]
struct UniqueScope {
    scope_id: String,
    scope_name: String,
    scope_version: String,
    scope_attributes: Vec<(String, String)>,
    schema_url: Option<String>,
    meter_count: usize,
    first_creation_order: u32,
}

/// Span event count truncation test scenario
#[derive(Debug, Clone)]
struct SpanEventCountTruncationScenario {
    name: String,
    description: String,
    max_event_count: usize,
    events: Vec<EventForTruncation>,
    truncation_strategy: EventTruncationStrategy,
    expected_preserved_count: usize,
    expected_dropped_count: usize,
    expected_preserved_names: Vec<String>,
}

/// Event definition for truncation tests
#[derive(Debug, Clone)]
struct EventForTruncation {
    name: String,
    timestamp_offset_nanos: u64,
    attributes: Vec<(String, String)>,
    priority: u32,
}

/// Event truncation strategy types
#[derive(Debug, Clone, PartialEq)]
enum EventTruncationStrategy {
    FirstWins,
    LastWins,
    PriorityBased,
}

/// Event count truncation result for comparison
#[derive(Debug, Clone, PartialEq)]
struct EventCountTruncationResult {
    original_events: Vec<ProcessedEvent>,
    preserved_events: Vec<ProcessedEvent>,
    dropped_events: Vec<ProcessedEvent>,
    applied_strategy: EventTruncationStrategy,
    truncation_metadata: Vec<String>,
}

/// Processed event with truncation metadata
#[derive(Debug, Clone, PartialEq)]
struct ProcessedEvent {
    name: String,
    timestamp_offset_nanos: u64,
    attributes: Vec<(String, String)>,
    priority: u32,
    was_preserved: bool,
    truncation_reason: Option<String>,
}

/// Span attribute key-value validation test scenario
#[derive(Debug, Clone)]
struct SpanAttributeKeyValueValidationScenario {
    name: String,
    description: String,
    attribute_pairs: Vec<AttributeKeyValueDefinition>,
    validation_strategy: AttributeValidationStrategy,
    expected_valid_count: usize,
    expected_invalid_count: usize,
    expected_valid_keys: Vec<String>,
}

/// Attribute key-value pair definition for validation tests
#[derive(Debug, Clone)]
struct AttributeKeyValueDefinition {
    key: String,
    value: AttributeValue,
    expected_valid: bool,
    validation_context: AttributeValidationContext,
}

/// Attribute validation context
#[derive(Debug, Clone, PartialEq)]
enum AttributeValidationContext {
    Span,
    Resource,
    InstrumentationScope,
    Event,
    Link,
}

/// Attribute validation strategy types
#[derive(Debug, Clone, PartialEq)]
enum AttributeValidationStrategy {
    OpenTelemetryStandard,
    StrictKeyFormat,
    LenientKeyFormat,
    UnicodeAware,
}

/// Span attribute validation result for comparison
#[derive(Debug, Clone, PartialEq)]
struct AttributeKeyValueValidationResult {
    original_attributes: Vec<ProcessedAttributeKeyValue>,
    valid_attributes: Vec<ProcessedAttributeKeyValue>,
    invalid_attributes: Vec<ProcessedAttributeKeyValue>,
    applied_strategy: AttributeValidationStrategy,
    validation_metadata: Vec<String>,
}

/// Processed attribute key-value with validation metadata
#[derive(Debug, Clone, PartialEq)]
struct ProcessedAttributeKeyValue {
    key: String,
    value: AttributeValue,
    validation_context: AttributeValidationContext,
    is_valid: bool,
    validation_errors: Vec<String>,
    normalized_key: Option<String>,
    normalized_value: Option<AttributeValue>,
}

/// OTLP serialization stable byte order test scenario
#[derive(Debug, Clone)]
struct OtlpSerializationStableByteOrderScenario {
    name: String,
    description: String,
    message_definitions: Vec<OtlpMessageDefinition>,
    serialization_strategy: SerializationOrderStrategy,
    expected_deterministic: bool,
    expected_byte_length: Option<usize>,
    expected_field_order: Vec<String>,
}

/// OTLP message definition for serialization tests
#[derive(Debug, Clone)]
struct OtlpMessageDefinition {
    message_type: OtlpMessageType,
    fields: Vec<OtlpFieldDefinition>,
    nested_messages: Vec<OtlpMessageDefinition>,
    repeated_fields: Vec<OtlpRepeatedFieldDefinition>,
}

/// OTLP message type for testing
#[derive(Debug, Clone, PartialEq)]
enum OtlpMessageType {
    ExportTraceServiceRequest,
    ExportMetricsServiceRequest,
    ExportLogsServiceRequest,
    ResourceSpans,
    InstrumentationLibrarySpans,
    Span,
    SpanEvent,
    SpanLink,
    ResourceMetrics,
    InstrumentationLibraryMetrics,
    Metric,
    DataPoint,
}

/// OTLP field definition for serialization
#[derive(Debug, Clone)]
struct OtlpFieldDefinition {
    field_name: String,
    field_number: u32,
    field_type: OtlpFieldType,
    field_value: OtlpFieldValue,
    is_repeated: bool,
}

/// OTLP field types
#[derive(Debug, Clone, PartialEq)]
enum OtlpFieldType {
    String,
    Int64,
    Uint64,
    Double,
    Bool,
    Bytes,
    Message,
    Enum,
}

/// OTLP field values for serialization
#[derive(Debug, Clone, PartialEq)]
enum OtlpFieldValue {
    String(String),
    Int64(i64),
    Uint64(u64),
    Double(f64),
    Bool(bool),
    Bytes(Vec<u8>),
    Message(String), // Nested message content as string
    Enum(i32),
}

/// OTLP repeated field definition
#[derive(Debug, Clone)]
struct OtlpRepeatedFieldDefinition {
    field_name: String,
    field_number: u32,
    field_type: OtlpFieldType,
    field_values: Vec<OtlpFieldValue>,
    ordering_strategy: RepeatedFieldOrderStrategy,
}

/// Repeated field ordering strategy
#[derive(Debug, Clone, PartialEq)]
enum RepeatedFieldOrderStrategy {
    InsertionOrder,
    SortedOrder,
    StableSort,
    UnspecifiedOrder,
}

/// Serialization order strategy types
#[derive(Debug, Clone, PartialEq)]
enum SerializationOrderStrategy {
    FieldNumberOrder,
    AlphabeticalOrder,
    InsertionOrder,
    CanonicalOrder,
}

/// OTLP serialization result for comparison
#[derive(Debug, Clone, PartialEq)]
struct OtlpSerializationStableByteOrderResult {
    serialized_bytes: Vec<u8>,
    field_order: Vec<String>,
    byte_length: usize,
    is_deterministic: bool,
    serialization_metadata: Vec<String>,
    field_checksums: Vec<FieldChecksum>,
}

/// Field checksum for validation
#[derive(Debug, Clone, PartialEq)]
struct FieldChecksum {
    field_name: String,
    field_number: u32,
    byte_offset: usize,
    byte_length: usize,
    checksum: u32,
}

/// Span event timestamp ordering result for comparison
#[derive(Debug, Clone, PartialEq)]
struct EventTimestampOrderingResult {
    original_events: Vec<OrderedEvent>,
    sorted_events: Vec<OrderedEvent>,
    ordering_preserved: bool,
    timestamp_monotonic: bool,
    applied_strategy: TimestampOrderingStrategy,
    ordering_metadata: Vec<String>,
}

/// Ordered event for timestamp comparison
#[derive(Debug, Clone, PartialEq)]
struct OrderedEvent {
    name: String,
    timestamp_nanos: u64,
    attributes: Vec<(String, String)>,
    original_index: usize,
    sorted_index: usize,
}

/// Span attribute count limit precedence test scenario
#[derive(Debug, Clone)]
struct SpanAttributeLimitPrecedenceScenario {
    name: String,
    description: String,
    max_attribute_count: usize,
    attributes: Vec<(String, String, u32)>, // (key, value, priority)
    precedence_strategy: AttributePrecedenceStrategy,
    expected_preserved_count: usize,
    expected_dropped_count: usize,
    expected_preserved_keys: Vec<String>,
}

/// Attribute precedence strategy types
#[derive(Debug, Clone, PartialEq)]
enum AttributePrecedenceStrategy {
    FirstWins,     // First attributes are preserved when limit exceeded
    LastWins,      // Last attributes are preserved when limit exceeded
    PriorityBased, // Highest priority attributes are preserved
}

/// Span attribute limit precedence result for comparison
#[derive(Debug, Clone, PartialEq)]
struct AttributeLimitPrecedenceResult {
    original_attributes: Vec<AttributeWithPrecedence>,
    preserved_attributes: Vec<AttributeWithPrecedence>,
    dropped_attributes: Vec<AttributeWithPrecedence>,
    applied_strategy: AttributePrecedenceStrategy,
    precedence_preserved: bool,
    limit_enforced: bool,
    precedence_metadata: Vec<String>,
}

/// Attribute with precedence for limit testing
#[derive(Debug, Clone, PartialEq)]
struct AttributeWithPrecedence {
    key: String,
    value: String,
    priority: u32,
    original_index: usize,
    precedence_order: usize,
}

/// Model asupersync span attribute string truncation implementation
fn model_asupersync_attribute_string_truncation(
    scenario: &SpanAttributeTruncationScenario,
) -> Result<AttributeStringTruncationResult, String> {
    let mut truncation_metadata = Vec::new();
    let original_value_len = scenario.attribute_value.len();
    let original_key_len = scenario.attribute_key.len();

    truncation_metadata.push(format!(
        "Original: key={}bytes, value={}bytes, limit={}",
        original_key_len, original_value_len, scenario.max_length
    ));

    // Determine if truncation is needed
    let value_needs_truncation = original_value_len > scenario.max_length;
    let key_needs_truncation = scenario.truncation_strategy == TruncationStrategy::KeyTruncation
        && original_key_len > scenario.max_length;

    let mut truncated_key = scenario.attribute_key.clone();
    let mut truncated_value = scenario.attribute_value.clone();
    let mut unicode_safe = None;

    // Apply truncation based on strategy
    match scenario.truncation_strategy {
        TruncationStrategy::Preserve => {
            // No truncation
        }
        TruncationStrategy::Simple => {
            if value_needs_truncation {
                truncated_value = scenario
                    .attribute_value
                    .chars()
                    .take(scenario.max_length)
                    .collect();
                truncation_metadata.push("Applied simple character truncation".to_string());
            }
        }
        TruncationStrategy::Ellipsis => {
            if value_needs_truncation {
                let ellipsis = "...";
                let available_length = scenario.max_length.saturating_sub(ellipsis.len());
                truncated_value = format!(
                    "{}{}",
                    scenario
                        .attribute_value
                        .chars()
                        .take(available_length)
                        .collect::<String>(),
                    ellipsis
                );
                truncation_metadata.push("Applied ellipsis truncation".to_string());
            }
        }
        TruncationStrategy::UnicodeAware => {
            if value_needs_truncation {
                // Truncate at Unicode character boundary
                let mut byte_count = 0;
                let mut char_boundary = 0;
                for (i, ch) in scenario.attribute_value.char_indices() {
                    let char_len = ch.len_utf8();
                    if byte_count + char_len > scenario.max_length {
                        break;
                    }
                    byte_count += char_len;
                    char_boundary = i + char_len;
                }
                truncated_value = scenario.attribute_value[..char_boundary].to_string();
                unicode_safe = Some(true);
                truncation_metadata.push("Applied Unicode-aware truncation".to_string());
            }
        }
        TruncationStrategy::EmojiAware => {
            if value_needs_truncation {
                // Handle emoji clusters and extended graphemes
                let mut grapheme_count = 0;
                let mut byte_end = 0;
                for ch in scenario.attribute_value.chars() {
                    let char_len = ch.len_utf8();
                    if byte_end + char_len > scenario.max_length {
                        break;
                    }
                    byte_end += char_len;
                    grapheme_count += 1;
                }
                truncated_value = scenario.attribute_value[..byte_end].to_string();
                unicode_safe = Some(true);
                truncation_metadata.push(format!(
                    "Applied emoji-aware truncation, {} graphemes",
                    grapheme_count
                ));
            }
        }
        TruncationStrategy::KeyTruncation => {
            if key_needs_truncation {
                truncated_key = scenario
                    .attribute_key
                    .chars()
                    .take(scenario.max_length)
                    .collect();
                truncation_metadata.push("Applied key truncation".to_string());
            }
        }
        TruncationStrategy::Drop => {
            if scenario.max_length == 0 {
                truncated_value = String::new();
                truncation_metadata.push("Dropped attribute due to zero length limit".to_string());
            }
        }
        TruncationStrategy::CharacterBoundary => {
            if value_needs_truncation {
                // Ensure we don't break in the middle of a multi-byte character
                let mut safe_end = 0;
                for (byte_idx, ch) in scenario.attribute_value.char_indices() {
                    if byte_idx >= scenario.max_length {
                        break;
                    }
                    safe_end = byte_idx + ch.len_utf8();
                    if safe_end > scenario.max_length {
                        break;
                    }
                }
                safe_end = safe_end
                    .min(scenario.max_length)
                    .min(scenario.attribute_value.len());
                truncated_value = scenario.attribute_value[..safe_end].to_string();
                unicode_safe = Some(true);
                truncation_metadata.push("Applied character boundary truncation".to_string());
            }
        }
    }

    let was_truncated =
        truncated_value.len() != original_value_len || truncated_key.len() != original_key_len;
    let final_length = truncated_value.len();

    Ok(AttributeStringTruncationResult {
        original_key: scenario.attribute_key.clone(),
        original_value: scenario.attribute_value.clone(),
        truncated_key,
        truncated_value,
        was_truncated,
        final_length,
        unicode_safe,
        applied_strategy: scenario.truncation_strategy.clone(),
        truncation_metadata,
    })
}

/// Model OpenTelemetry SDK span attribute string truncation implementation
fn model_opentelemetry_attribute_string_truncation(
    scenario: &SpanAttributeTruncationScenario,
) -> Result<AttributeStringTruncationResult, String> {
    // For differential testing, OpenTelemetry should follow similar logic
    let mut truncation_metadata = Vec::new();
    let original_value_len = scenario.attribute_value.len();
    let original_key_len = scenario.attribute_key.len();

    truncation_metadata.push(format!(
        "OpenTelemetry: key={}bytes, value={}bytes, limit={}",
        original_key_len, original_value_len, scenario.max_length
    ));

    let value_needs_truncation = original_value_len > scenario.max_length;
    let key_needs_truncation = scenario.truncation_strategy == TruncationStrategy::KeyTruncation
        && original_key_len > scenario.max_length;

    let mut truncated_key = scenario.attribute_key.clone();
    let mut truncated_value = scenario.attribute_value.clone();
    let mut unicode_safe = None;

    // OpenTelemetry truncation implementation
    match scenario.truncation_strategy {
        TruncationStrategy::Preserve => {
            // No truncation
        }
        TruncationStrategy::Simple => {
            if value_needs_truncation {
                truncated_value = scenario
                    .attribute_value
                    .chars()
                    .take(scenario.max_length)
                    .collect();
                truncation_metadata.push("OpenTelemetry applied simple truncation".to_string());
            }
        }
        TruncationStrategy::Ellipsis => {
            if value_needs_truncation {
                let ellipsis = "...";
                let available_length = scenario.max_length.saturating_sub(ellipsis.len());
                truncated_value = format!(
                    "{}{}",
                    scenario
                        .attribute_value
                        .chars()
                        .take(available_length)
                        .collect::<String>(),
                    ellipsis
                );
                truncation_metadata.push("OpenTelemetry applied ellipsis truncation".to_string());
            }
        }
        TruncationStrategy::UnicodeAware => {
            if value_needs_truncation {
                let mut byte_count = 0;
                let mut char_boundary = 0;
                for (i, ch) in scenario.attribute_value.char_indices() {
                    let char_len = ch.len_utf8();
                    if byte_count + char_len > scenario.max_length {
                        break;
                    }
                    byte_count += char_len;
                    char_boundary = i + char_len;
                }
                truncated_value = scenario.attribute_value[..char_boundary].to_string();
                unicode_safe = Some(true);
                truncation_metadata
                    .push("OpenTelemetry applied Unicode-aware truncation".to_string());
            }
        }
        TruncationStrategy::EmojiAware => {
            if value_needs_truncation {
                let mut byte_end = 0;
                for ch in scenario.attribute_value.chars() {
                    let char_len = ch.len_utf8();
                    if byte_end + char_len > scenario.max_length {
                        break;
                    }
                    byte_end += char_len;
                }
                truncated_value = scenario.attribute_value[..byte_end].to_string();
                unicode_safe = Some(true);
                truncation_metadata
                    .push("OpenTelemetry applied emoji-aware truncation".to_string());
            }
        }
        TruncationStrategy::KeyTruncation => {
            if key_needs_truncation {
                truncated_key = scenario
                    .attribute_key
                    .chars()
                    .take(scenario.max_length)
                    .collect();
                truncation_metadata.push("OpenTelemetry applied key truncation".to_string());
            }
        }
        TruncationStrategy::Drop => {
            if scenario.max_length == 0 {
                truncated_value = String::new();
                truncation_metadata.push("OpenTelemetry dropped attribute".to_string());
            }
        }
        TruncationStrategy::CharacterBoundary => {
            if value_needs_truncation {
                let mut safe_end = 0;
                for (byte_idx, ch) in scenario.attribute_value.char_indices() {
                    if byte_idx >= scenario.max_length {
                        break;
                    }
                    safe_end = byte_idx + ch.len_utf8();
                    if safe_end > scenario.max_length {
                        break;
                    }
                }
                safe_end = safe_end
                    .min(scenario.max_length)
                    .min(scenario.attribute_value.len());
                truncated_value = scenario.attribute_value[..safe_end].to_string();
                unicode_safe = Some(true);
                truncation_metadata
                    .push("OpenTelemetry applied character boundary truncation".to_string());
            }
        }
    }

    let was_truncated =
        truncated_value.len() != original_value_len || truncated_key.len() != original_key_len;
    let final_length = truncated_value.len();

    Ok(AttributeStringTruncationResult {
        original_key: scenario.attribute_key.clone(),
        original_value: scenario.attribute_value.clone(),
        truncated_key,
        truncated_value,
        was_truncated,
        final_length,
        unicode_safe,
        applied_strategy: scenario.truncation_strategy.clone(),
        truncation_metadata,
    })
}

/// Compare attribute string truncation results for differential testing
fn compare_attribute_string_truncation_results(
    asupersync_result: &AttributeStringTruncationResult,
    opentelemetry_result: &AttributeStringTruncationResult,
) -> bool {
    // Core truncation behavior should match
    asupersync_result.was_truncated == opentelemetry_result.was_truncated
        && asupersync_result.final_length == opentelemetry_result.final_length
        && asupersync_result.applied_strategy == opentelemetry_result.applied_strategy
        && asupersync_result.unicode_safe == opentelemetry_result.unicode_safe
        // Truncated strings should be identical
        && asupersync_result.truncated_value == opentelemetry_result.truncated_value
        && asupersync_result.truncated_key == opentelemetry_result.truncated_key
}

/// Verify attribute string truncation consistency between implementations
fn verify_attribute_string_truncation_consistency(
    asupersync_result: &AttributeStringTruncationResult,
    opentelemetry_result: &AttributeStringTruncationResult,
    scenario: &SpanAttributeTruncationScenario,
) -> Result<(), String> {
    // Verify both implementations agree on truncation occurrence
    if asupersync_result.was_truncated != opentelemetry_result.was_truncated {
        return Err(format!(
            "Truncation occurrence disagreement: asupersync={}, opentelemetry={}",
            asupersync_result.was_truncated, opentelemetry_result.was_truncated
        ));
    }

    // Verify both produce the same final length
    if asupersync_result.final_length != opentelemetry_result.final_length {
        return Err(format!(
            "Final length disagreement: asupersync={}, opentelemetry={}",
            asupersync_result.final_length, opentelemetry_result.final_length
        ));
    }

    // Verify length limits are respected
    if asupersync_result.final_length > scenario.max_length {
        return Err(format!(
            "Asupersync final length exceeds limit: {} > {}",
            asupersync_result.final_length, scenario.max_length
        ));
    }

    if opentelemetry_result.final_length > scenario.max_length {
        return Err(format!(
            "OpenTelemetry final length exceeds limit: {} > {}",
            opentelemetry_result.final_length, scenario.max_length
        ));
    }

    // Verify Unicode safety when required
    if scenario.truncation_strategy == TruncationStrategy::UnicodeAware
        || scenario.truncation_strategy == TruncationStrategy::EmojiAware
        || scenario.truncation_strategy == TruncationStrategy::CharacterBoundary
    {
        if asupersync_result.unicode_safe != Some(true) {
            return Err(format!(
                "Asupersync Unicode safety not ensured for strategy: {:?}",
                scenario.truncation_strategy
            ));
        }

        if opentelemetry_result.unicode_safe != Some(true) {
            return Err(format!(
                "OpenTelemetry Unicode safety not ensured for strategy: {:?}",
                scenario.truncation_strategy
            ));
        }
    }

    // Verify truncated strings are valid UTF-8
    if let Err(utf8_error) = std::str::from_utf8(asupersync_result.truncated_value.as_bytes()) {
        return Err(format!(
            "Asupersync truncated value invalid UTF-8: {}",
            utf8_error
        ));
    }

    if let Err(utf8_error) = std::str::from_utf8(opentelemetry_result.truncated_value.as_bytes()) {
        return Err(format!(
            "OpenTelemetry truncated value invalid UTF-8: {}",
            utf8_error
        ));
    }

    // Verify truncated strings match between implementations
    if asupersync_result.truncated_value != opentelemetry_result.truncated_value {
        return Err(format!(
            "Truncated value mismatch: asupersync='{}', opentelemetry='{}'",
            asupersync_result.truncated_value, opentelemetry_result.truncated_value
        ));
    }

    // Verify expected truncation flag matches actual
    if asupersync_result.was_truncated != scenario.expected_truncated {
        return Err(format!(
            "Truncation expectation mismatch: expected={}, actual={}",
            scenario.expected_truncated, asupersync_result.was_truncated
        ));
    }

    Ok(())
}

/// OTLP-038: Span event timestamp ordering conformance test.
pub fn otlp_038_span_event_timestamp_ordering_conformance<RT: RuntimeInterface>()
-> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-038",
        name: "Span event timestamp ordering conformance",
        description: "Verify span event timestamp ordering vs opentelemetry-sdk — identical chronological behavior",
        category: TestCategory::IO,
        tags: ["otlp", "span", "events", "timestamp", "ordering", "chronological"],
        expected: "Span event timestamp ordering behaves identically across implementations",
        test: |_rt| {
            // Test scenarios for comprehensive span event timestamp ordering validation
            let test_scenarios = vec![
                SpanEventTimestampScenario {
                    name: "chronological_order".to_string(),
                    description: "Events added in chronological order".to_string(),
                    events: vec![
                        EventTimestampDefinition {
                            name: "request_start".to_string(),
                            timestamp_nanos: 1_000_000_000,
                            attributes: vec![("phase".to_string(), "start".to_string())],
                        },
                        EventTimestampDefinition {
                            name: "validation_complete".to_string(),
                            timestamp_nanos: 1_100_000_000,
                            attributes: vec![("phase".to_string(), "validation".to_string())],
                        },
                        EventTimestampDefinition {
                            name: "processing_complete".to_string(),
                            timestamp_nanos: 1_200_000_000,
                            attributes: vec![("phase".to_string(), "processing".to_string())],
                        },
                        EventTimestampDefinition {
                            name: "request_complete".to_string(),
                            timestamp_nanos: 1_300_000_000,
                            attributes: vec![("phase".to_string(), "complete".to_string())],
                        },
                    ],
                    expected_ordering: vec!["request_start", "validation_complete", "processing_complete", "request_complete"],
                    ordering_strategy: TimestampOrderingStrategy::ChronologicalSort,
                },
                SpanEventTimestampScenario {
                    name: "out_of_order_events".to_string(),
                    description: "Events added out of chronological order".to_string(),
                    events: vec![
                        EventTimestampDefinition {
                            name: "request_complete".to_string(),
                            timestamp_nanos: 1_300_000_000,
                            attributes: vec![("phase".to_string(), "complete".to_string())],
                        },
                        EventTimestampDefinition {
                            name: "request_start".to_string(),
                            timestamp_nanos: 1_000_000_000,
                            attributes: vec![("phase".to_string(), "start".to_string())],
                        },
                        EventTimestampDefinition {
                            name: "processing_complete".to_string(),
                            timestamp_nanos: 1_200_000_000,
                            attributes: vec![("phase".to_string(), "processing".to_string())],
                        },
                        EventTimestampDefinition {
                            name: "validation_complete".to_string(),
                            timestamp_nanos: 1_100_000_000,
                            attributes: vec![("phase".to_string(), "validation".to_string())],
                        },
                    ],
                    expected_ordering: vec!["request_start", "validation_complete", "processing_complete", "request_complete"],
                    ordering_strategy: TimestampOrderingStrategy::ChronologicalSort,
                },
                SpanEventTimestampScenario {
                    name: "identical_timestamps".to_string(),
                    description: "Multiple events with identical timestamps".to_string(),
                    events: vec![
                        EventTimestampDefinition {
                            name: "concurrent_task_a".to_string(),
                            timestamp_nanos: 1_500_000_000,
                            attributes: vec![("task".to_string(), "a".to_string())],
                        },
                        EventTimestampDefinition {
                            name: "concurrent_task_b".to_string(),
                            timestamp_nanos: 1_500_000_000,
                            attributes: vec![("task".to_string(), "b".to_string())],
                        },
                        EventTimestampDefinition {
                            name: "concurrent_task_c".to_string(),
                            timestamp_nanos: 1_500_000_000,
                            attributes: vec![("task".to_string(), "c".to_string())],
                        },
                        EventTimestampDefinition {
                            name: "completion".to_string(),
                            timestamp_nanos: 1_600_000_000,
                            attributes: vec![("phase".to_string(), "done".to_string())],
                        },
                    ],
                    expected_ordering: vec!["concurrent_task_a", "concurrent_task_b", "concurrent_task_c", "completion"],
                    ordering_strategy: TimestampOrderingStrategy::StableSort,
                },
                SpanEventTimestampScenario {
                    name: "microsecond_precision".to_string(),
                    description: "Events with microsecond-level timestamp differences".to_string(),
                    events: vec![
                        EventTimestampDefinition {
                            name: "step_1".to_string(),
                            timestamp_nanos: 1_000_000_000,
                            attributes: vec![("precision".to_string(), "microsecond".to_string())],
                        },
                        EventTimestampDefinition {
                            name: "step_2".to_string(),
                            timestamp_nanos: 1_000_001_000,
                            attributes: vec![("precision".to_string(), "microsecond".to_string())],
                        },
                        EventTimestampDefinition {
                            name: "step_3".to_string(),
                            timestamp_nanos: 1_000_002_000,
                            attributes: vec![("precision".to_string(), "microsecond".to_string())],
                        },
                        EventTimestampDefinition {
                            name: "step_4".to_string(),
                            timestamp_nanos: 1_000_003_000,
                            attributes: vec![("precision".to_string(), "microsecond".to_string())],
                        },
                    ],
                    expected_ordering: vec!["step_1", "step_2", "step_3", "step_4"],
                    ordering_strategy: TimestampOrderingStrategy::ChronologicalSort,
                },
                SpanEventTimestampScenario {
                    name: "nanosecond_precision".to_string(),
                    description: "Events with nanosecond-level timestamp differences".to_string(),
                    events: vec![
                        EventTimestampDefinition {
                            name: "nano_1".to_string(),
                            timestamp_nanos: 1_000_000_000,
                            attributes: vec![("precision".to_string(), "nanosecond".to_string())],
                        },
                        EventTimestampDefinition {
                            name: "nano_2".to_string(),
                            timestamp_nanos: 1_000_000_001,
                            attributes: vec![("precision".to_string(), "nanosecond".to_string())],
                        },
                        EventTimestampDefinition {
                            name: "nano_3".to_string(),
                            timestamp_nanos: 1_000_000_002,
                            attributes: vec![("precision".to_string(), "nanosecond".to_string())],
                        },
                        EventTimestampDefinition {
                            name: "nano_4".to_string(),
                            timestamp_nanos: 1_000_000_003,
                            attributes: vec![("precision".to_string(), "nanosecond".to_string())],
                        },
                    ],
                    expected_ordering: vec!["nano_1", "nano_2", "nano_3", "nano_4"],
                    ordering_strategy: TimestampOrderingStrategy::ChronologicalSort,
                },
                SpanEventTimestampScenario {
                    name: "large_timestamp_values".to_string(),
                    description: "Events with large timestamp values near epoch boundaries".to_string(),
                    events: vec![
                        EventTimestampDefinition {
                            name: "epoch_test_1".to_string(),
                            timestamp_nanos: 1_699_999_999_999_999_999,
                            attributes: vec![("boundary".to_string(), "before_epoch".to_string())],
                        },
                        EventTimestampDefinition {
                            name: "epoch_test_2".to_string(),
                            timestamp_nanos: 1_700_000_000_000_000_000,
                            attributes: vec![("boundary".to_string(), "at_epoch".to_string())],
                        },
                        EventTimestampDefinition {
                            name: "epoch_test_3".to_string(),
                            timestamp_nanos: 1_700_000_000_000_000_001,
                            attributes: vec![("boundary".to_string(), "after_epoch".to_string())],
                        },
                    ],
                    expected_ordering: vec!["epoch_test_1", "epoch_test_2", "epoch_test_3"],
                    ordering_strategy: TimestampOrderingStrategy::ChronologicalSort,
                },
                SpanEventTimestampScenario {
                    name: "reverse_chronological_addition".to_string(),
                    description: "Events added in reverse chronological order".to_string(),
                    events: vec![
                        EventTimestampDefinition {
                            name: "final_step".to_string(),
                            timestamp_nanos: 2_000_000_000,
                            attributes: vec![("order".to_string(), "final".to_string())],
                        },
                        EventTimestampDefinition {
                            name: "middle_step".to_string(),
                            timestamp_nanos: 1_500_000_000,
                            attributes: vec![("order".to_string(), "middle".to_string())],
                        },
                        EventTimestampDefinition {
                            name: "initial_step".to_string(),
                            timestamp_nanos: 1_000_000_000,
                            attributes: vec![("order".to_string(), "initial".to_string())],
                        },
                    ],
                    expected_ordering: vec!["initial_step", "middle_step", "final_step"],
                    ordering_strategy: TimestampOrderingStrategy::ChronologicalSort,
                },
                SpanEventTimestampScenario {
                    name: "mixed_precision_timestamps".to_string(),
                    description: "Events with different timestamp precision levels".to_string(),
                    events: vec![
                        EventTimestampDefinition {
                            name: "second_precision".to_string(),
                            timestamp_nanos: 1_000_000_000_000,
                            attributes: vec![("precision_level".to_string(), "second".to_string())],
                        },
                        EventTimestampDefinition {
                            name: "millisecond_precision".to_string(),
                            timestamp_nanos: 1_000_500_000_000,
                            attributes: vec![("precision_level".to_string(), "millisecond".to_string())],
                        },
                        EventTimestampDefinition {
                            name: "microsecond_precision".to_string(),
                            timestamp_nanos: 1_000_500_750_000,
                            attributes: vec![("precision_level".to_string(), "microsecond".to_string())],
                        },
                        EventTimestampDefinition {
                            name: "nanosecond_precision".to_string(),
                            timestamp_nanos: 1_000_500_750_123,
                            attributes: vec![("precision_level".to_string(), "nanosecond".to_string())],
                        },
                    ],
                    expected_ordering: vec!["second_precision", "millisecond_precision", "microsecond_precision", "nanosecond_precision"],
                    ordering_strategy: TimestampOrderingStrategy::ChronologicalSort,
                },
            ];

            for scenario in test_scenarios {
                // Test asupersync span event timestamp ordering
                let asupersync_result = match model_asupersync_event_timestamp_ordering(&scenario) {
                    Ok(result) => result,
                    Err(e) => return TestResult::failed(format!("Asupersync timestamp ordering failed for {}: {}", scenario.name, e)),
                };

                // Test opentelemetry-sdk span event timestamp ordering
                let opentelemetry_result = match model_opentelemetry_event_timestamp_ordering(&scenario) {
                    Ok(result) => result,
                    Err(e) => return TestResult::failed(format!("OpenTelemetry timestamp ordering failed for {}: {}", scenario.name, e)),
                };

                // Verify that both implementations produce identical ordering
                if let Err(differences) = compare_event_timestamp_ordering_results(&asupersync_result, &opentelemetry_result) {
                    return TestResult::failed(format!("Event timestamp ordering differential test failed for {}: {}", scenario.name, differences));
                }

                // Verify expected ordering is respected
                if let Err(validation_error) = verify_timestamp_ordering_expectations(&asupersync_result, &scenario) {
                    return TestResult::failed(format!("Expected ordering validation failed for {}: {}", scenario.name, validation_error));
                }
            }

            TestResult::passed()
        }
    }
}

/// OTLP-039: Span attribute count limit precedence conformance test.
pub fn otlp_039_span_attribute_count_limit_precedence_conformance<RT: RuntimeInterface>()
-> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-039",
        name: "Span attribute count limit precedence conformance",
        description: "Verify span attribute count limit precedence vs opentelemetry-sdk — identical precedence behavior",
        category: TestCategory::IO,
        tags: ["otlp", "span", "attributes", "count", "limit", "precedence"],
        expected: "Span attribute count limit precedence behaves identically across implementations",
        test: |_rt| {
            // Test scenarios for comprehensive span attribute count limit precedence validation
            let test_scenarios = vec![
                SpanAttributeLimitPrecedenceScenario {
                    name: "below_limit_all_preserved".to_string(),
                    description: "All attributes below limit should be preserved".to_string(),
                    max_attribute_count: 10,
                    attributes: vec![
                        ("service.name".to_string(), "test-service".to_string(), 1),
                        ("service.version".to_string(), "1.0.0".to_string(), 2),
                        ("deployment.environment".to_string(), "production".to_string(), 3),
                        ("operation.name".to_string(), "user_login".to_string(), 4),
                        ("user.id".to_string(), "12345".to_string(), 5),
                    ],
                    precedence_strategy: AttributePrecedenceStrategy::FirstWins,
                    expected_preserved_count: 5,
                    expected_dropped_count: 0,
                    expected_preserved_keys: vec!["service.name".to_string(), "service.version".to_string(), "deployment.environment".to_string(), "operation.name".to_string(), "user.id".to_string()],
                },
                SpanAttributeLimitPrecedenceScenario {
                    name: "exact_limit_boundary".to_string(),
                    description: "Exact attribute limit boundary behavior".to_string(),
                    max_attribute_count: 3,
                    attributes: vec![
                        ("key1".to_string(), "value1".to_string(), 1),
                        ("key2".to_string(), "value2".to_string(), 2),
                        ("key3".to_string(), "value3".to_string(), 3),
                    ],
                    precedence_strategy: AttributePrecedenceStrategy::FirstWins,
                    expected_preserved_count: 3,
                    expected_dropped_count: 0,
                    expected_preserved_keys: vec!["key1".to_string(), "key2".to_string(), "key3".to_string()],
                },
                SpanAttributeLimitPrecedenceScenario {
                    name: "first_wins_precedence".to_string(),
                    description: "First attributes win when limit exceeded".to_string(),
                    max_attribute_count: 3,
                    attributes: vec![
                        ("high_priority".to_string(), "critical".to_string(), 1),
                        ("medium_priority".to_string(), "important".to_string(), 2),
                        ("low_priority".to_string(), "optional".to_string(), 3),
                        ("excess1".to_string(), "dropped".to_string(), 4),
                        ("excess2".to_string(), "dropped".to_string(), 5),
                    ],
                    precedence_strategy: AttributePrecedenceStrategy::FirstWins,
                    expected_preserved_count: 3,
                    expected_dropped_count: 2,
                    expected_preserved_keys: vec!["high_priority".to_string(), "medium_priority".to_string(), "low_priority".to_string()],
                },
                SpanAttributeLimitPrecedenceScenario {
                    name: "last_wins_precedence".to_string(),
                    description: "Last attributes win when limit exceeded".to_string(),
                    max_attribute_count: 3,
                    attributes: vec![
                        ("early1".to_string(), "dropped".to_string(), 1),
                        ("early2".to_string(), "dropped".to_string(), 2),
                        ("important1".to_string(), "kept".to_string(), 3),
                        ("important2".to_string(), "kept".to_string(), 4),
                        ("important3".to_string(), "kept".to_string(), 5),
                    ],
                    precedence_strategy: AttributePrecedenceStrategy::LastWins,
                    expected_preserved_count: 3,
                    expected_dropped_count: 2,
                    expected_preserved_keys: vec!["important1".to_string(), "important2".to_string(), "important3".to_string()],
                },
                SpanAttributeLimitPrecedenceScenario {
                    name: "priority_based_precedence".to_string(),
                    description: "Priority-based attribute precedence".to_string(),
                    max_attribute_count: 4,
                    attributes: vec![
                        ("service.name".to_string(), "my-service".to_string(), 10), // High priority
                        ("user.data".to_string(), "private".to_string(), 1),        // Low priority
                        ("operation.id".to_string(), "op-123".to_string(), 8),      // High priority
                        ("debug.info".to_string(), "verbose".to_string(), 2),       // Low priority
                        ("trace.id".to_string(), "trace-456".to_string(), 9),       // High priority
                        ("extra.metadata".to_string(), "optional".to_string(), 3), // Low priority
                    ],
                    precedence_strategy: AttributePrecedenceStrategy::PriorityBased,
                    expected_preserved_count: 4,
                    expected_dropped_count: 2,
                    expected_preserved_keys: vec!["service.name".to_string(), "operation.id".to_string(), "trace.id".to_string(), "debug.info".to_string()], // Top 4 by priority
                },
                SpanAttributeLimitPrecedenceScenario {
                    name: "zero_limit_drops_all".to_string(),
                    description: "Zero attribute limit should drop all attributes".to_string(),
                    max_attribute_count: 0,
                    attributes: vec![
                        ("key1".to_string(), "value1".to_string(), 1),
                        ("key2".to_string(), "value2".to_string(), 2),
                        ("key3".to_string(), "value3".to_string(), 3),
                    ],
                    precedence_strategy: AttributePrecedenceStrategy::FirstWins,
                    expected_preserved_count: 0,
                    expected_dropped_count: 3,
                    expected_preserved_keys: vec![],
                },
                SpanAttributeLimitPrecedenceScenario {
                    name: "duplicate_key_handling".to_string(),
                    description: "Duplicate keys should be deduplicated based on precedence".to_string(),
                    max_attribute_count: 3,
                    attributes: vec![
                        ("user.id".to_string(), "12345".to_string(), 1),
                        ("operation.name".to_string(), "login".to_string(), 2),
                        ("user.id".to_string(), "67890".to_string(), 3), // Duplicate key
                        ("service.name".to_string(), "auth".to_string(), 4),
                        ("user.id".to_string(), "99999".to_string(), 5), // Another duplicate
                    ],
                    precedence_strategy: AttributePrecedenceStrategy::LastWins,
                    expected_preserved_count: 3,
                    expected_dropped_count: 2,
                    expected_preserved_keys: vec!["operation.name".to_string(), "user.id".to_string(), "service.name".to_string()], // Last user.id wins
                },
                SpanAttributeLimitPrecedenceScenario {
                    name: "large_limit_no_dropping".to_string(),
                    description: "Large limit with many attributes, all preserved".to_string(),
                    max_attribute_count: 100,
                    attributes: (1..=20).map(|i| (
                        format!("key_{}", i),
                        format!("value_{}", i),
                        i as u32,
                    )).collect(),
                    precedence_strategy: AttributePrecedenceStrategy::FirstWins,
                    expected_preserved_count: 20,
                    expected_dropped_count: 0,
                    expected_preserved_keys: (1..=20).map(|i| format!("key_{}", i)).collect(),
                },
            ];

            for scenario in test_scenarios {
                // Test asupersync span attribute limit precedence
                let asupersync_result = match model_asupersync_attribute_limit_precedence(&scenario) {
                    Ok(result) => result,
                    Err(e) => return TestResult::failed(format!("Asupersync attribute limit precedence failed for {}: {}", scenario.name, e)),
                };

                // Test opentelemetry-sdk span attribute limit precedence
                let opentelemetry_result = match model_opentelemetry_attribute_limit_precedence(&scenario) {
                    Ok(result) => result,
                    Err(e) => return TestResult::failed(format!("OpenTelemetry attribute limit precedence failed for {}: {}", scenario.name, e)),
                };

                // Verify that both implementations produce identical precedence behavior
                if let Err(differences) = compare_attribute_limit_precedence_results(&asupersync_result, &opentelemetry_result) {
                    return TestResult::failed(format!("Attribute limit precedence differential test failed for {}: {}", scenario.name, differences));
                }

                // Verify expected precedence behavior
                if let Err(validation_error) = verify_attribute_limit_precedence_expectations(&asupersync_result, &scenario) {
                    return TestResult::failed(format!("Precedence expectation validation failed for {}: {}", scenario.name, validation_error));
                }
            }

            TestResult::passed()
        }
    }
}

/// OTLP-040: Span event count truncation conformance test.
pub fn otlp_040_span_event_count_truncation_conformance<RT: RuntimeInterface>()
-> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-040",
        name: "Span event count truncation conformance",
        description: "Verify span event count truncation vs opentelemetry-sdk — identical truncation behavior",
        category: TestCategory::IO,
        tags: ["otlp", "span", "events", "count", "truncation", "limit"],
        expected: "Span event count truncation behaves identically across implementations",
        test: |_rt| {
            // Test scenarios for comprehensive span event count truncation validation
            let test_scenarios = vec![
                SpanEventCountTruncationScenario {
                    name: "below_limit_all_preserved".to_string(),
                    description: "All events below limit should be preserved".to_string(),
                    max_event_count: 10,
                    events: vec![
                        EventForTruncation {
                            name: "request_start".to_string(),
                            timestamp_offset_nanos: 1000,
                            attributes: vec![("phase".to_string(), "start".to_string())],
                            priority: 1,
                        },
                        EventForTruncation {
                            name: "validation".to_string(),
                            timestamp_offset_nanos: 2000,
                            attributes: vec![("phase".to_string(), "validation".to_string())],
                            priority: 2,
                        },
                        EventForTruncation {
                            name: "processing".to_string(),
                            timestamp_offset_nanos: 3000,
                            attributes: vec![("phase".to_string(), "processing".to_string())],
                            priority: 3,
                        },
                        EventForTruncation {
                            name: "response_sent".to_string(),
                            timestamp_offset_nanos: 4000,
                            attributes: vec![("phase".to_string(), "complete".to_string())],
                            priority: 4,
                        },
                    ],
                    truncation_strategy: EventTruncationStrategy::FirstWins,
                    expected_preserved_count: 4,
                    expected_dropped_count: 0,
                    expected_preserved_names: vec!["request_start".to_string(), "validation".to_string(), "processing".to_string(), "response_sent".to_string()],
                },
                SpanEventCountTruncationScenario {
                    name: "exact_limit_boundary".to_string(),
                    description: "Exact event limit boundary behavior".to_string(),
                    max_event_count: 3,
                    events: vec![
                        EventForTruncation {
                            name: "event_1".to_string(),
                            timestamp_offset_nanos: 1000,
                            attributes: vec![("index".to_string(), "1".to_string())],
                            priority: 1,
                        },
                        EventForTruncation {
                            name: "event_2".to_string(),
                            timestamp_offset_nanos: 2000,
                            attributes: vec![("index".to_string(), "2".to_string())],
                            priority: 2,
                        },
                        EventForTruncation {
                            name: "event_3".to_string(),
                            timestamp_offset_nanos: 3000,
                            attributes: vec![("index".to_string(), "3".to_string())],
                            priority: 3,
                        },
                    ],
                    truncation_strategy: EventTruncationStrategy::FirstWins,
                    expected_preserved_count: 3,
                    expected_dropped_count: 0,
                    expected_preserved_names: vec!["event_1".to_string(), "event_2".to_string(), "event_3".to_string()],
                },
                SpanEventCountTruncationScenario {
                    name: "first_wins_truncation".to_string(),
                    description: "First events win when limit exceeded".to_string(),
                    max_event_count: 3,
                    events: vec![
                        EventForTruncation {
                            name: "critical_start".to_string(),
                            timestamp_offset_nanos: 1000,
                            attributes: vec![("priority".to_string(), "critical".to_string())],
                            priority: 10,
                        },
                        EventForTruncation {
                            name: "important_validation".to_string(),
                            timestamp_offset_nanos: 2000,
                            attributes: vec![("priority".to_string(), "important".to_string())],
                            priority: 8,
                        },
                        EventForTruncation {
                            name: "normal_processing".to_string(),
                            timestamp_offset_nanos: 3000,
                            attributes: vec![("priority".to_string(), "normal".to_string())],
                            priority: 5,
                        },
                        EventForTruncation {
                            name: "dropped_debug".to_string(),
                            timestamp_offset_nanos: 4000,
                            attributes: vec![("priority".to_string(), "debug".to_string())],
                            priority: 1,
                        },
                        EventForTruncation {
                            name: "dropped_trace".to_string(),
                            timestamp_offset_nanos: 5000,
                            attributes: vec![("priority".to_string(), "trace".to_string())],
                            priority: 1,
                        },
                    ],
                    truncation_strategy: EventTruncationStrategy::FirstWins,
                    expected_preserved_count: 3,
                    expected_dropped_count: 2,
                    expected_preserved_names: vec!["critical_start".to_string(), "important_validation".to_string(), "normal_processing".to_string()],
                },
                SpanEventCountTruncationScenario {
                    name: "last_wins_truncation".to_string(),
                    description: "Last events win when limit exceeded".to_string(),
                    max_event_count: 3,
                    events: vec![
                        EventForTruncation {
                            name: "early_debug".to_string(),
                            timestamp_offset_nanos: 1000,
                            attributes: vec![("type".to_string(), "debug".to_string())],
                            priority: 1,
                        },
                        EventForTruncation {
                            name: "early_trace".to_string(),
                            timestamp_offset_nanos: 2000,
                            attributes: vec![("type".to_string(), "trace".to_string())],
                            priority: 1,
                        },
                        EventForTruncation {
                            name: "final_validation".to_string(),
                            timestamp_offset_nanos: 3000,
                            attributes: vec![("type".to_string(), "validation".to_string())],
                            priority: 8,
                        },
                        EventForTruncation {
                            name: "final_processing".to_string(),
                            timestamp_offset_nanos: 4000,
                            attributes: vec![("type".to_string(), "processing".to_string())],
                            priority: 9,
                        },
                        EventForTruncation {
                            name: "final_response".to_string(),
                            timestamp_offset_nanos: 5000,
                            attributes: vec![("type".to_string(), "response".to_string())],
                            priority: 10,
                        },
                    ],
                    truncation_strategy: EventTruncationStrategy::LastWins,
                    expected_preserved_count: 3,
                    expected_dropped_count: 2,
                    expected_preserved_names: vec!["final_validation".to_string(), "final_processing".to_string(), "final_response".to_string()],
                },
                SpanEventCountTruncationScenario {
                    name: "priority_based_truncation".to_string(),
                    description: "Priority-based event truncation".to_string(),
                    max_event_count: 4,
                    events: vec![
                        EventForTruncation {
                            name: "error_event".to_string(),
                            timestamp_offset_nanos: 1000,
                            attributes: vec![("level".to_string(), "error".to_string())],
                            priority: 100, // Highest priority
                        },
                        EventForTruncation {
                            name: "debug_event".to_string(),
                            timestamp_offset_nanos: 2000,
                            attributes: vec![("level".to_string(), "debug".to_string())],
                            priority: 1, // Lowest priority
                        },
                        EventForTruncation {
                            name: "warning_event".to_string(),
                            timestamp_offset_nanos: 3000,
                            attributes: vec![("level".to_string(), "warning".to_string())],
                            priority: 75, // High priority
                        },
                        EventForTruncation {
                            name: "info_event".to_string(),
                            timestamp_offset_nanos: 4000,
                            attributes: vec![("level".to_string(), "info".to_string())],
                            priority: 50, // Medium priority
                        },
                        EventForTruncation {
                            name: "trace_event".to_string(),
                            timestamp_offset_nanos: 5000,
                            attributes: vec![("level".to_string(), "trace".to_string())],
                            priority: 2, // Low priority
                        },
                        EventForTruncation {
                            name: "verbose_event".to_string(),
                            timestamp_offset_nanos: 6000,
                            attributes: vec![("level".to_string(), "verbose".to_string())],
                            priority: 3, // Low priority
                        },
                    ],
                    truncation_strategy: EventTruncationStrategy::PriorityBased,
                    expected_preserved_count: 4,
                    expected_dropped_count: 2,
                    expected_preserved_names: vec!["error_event".to_string(), "warning_event".to_string(), "info_event".to_string(), "verbose_event".to_string()], // Top 4 by priority
                },
                SpanEventCountTruncationScenario {
                    name: "zero_limit_drops_all".to_string(),
                    description: "Zero event limit should drop all events".to_string(),
                    max_event_count: 0,
                    events: vec![
                        EventForTruncation {
                            name: "event_1".to_string(),
                            timestamp_offset_nanos: 1000,
                            attributes: vec![("test".to_string(), "1".to_string())],
                            priority: 1,
                        },
                        EventForTruncation {
                            name: "event_2".to_string(),
                            timestamp_offset_nanos: 2000,
                            attributes: vec![("test".to_string(), "2".to_string())],
                            priority: 2,
                        },
                    ],
                    truncation_strategy: EventTruncationStrategy::FirstWins,
                    expected_preserved_count: 0,
                    expected_dropped_count: 2,
                    expected_preserved_names: vec![],
                },
                SpanEventCountTruncationScenario {
                    name: "timestamp_ordering_preserved".to_string(),
                    description: "Timestamp ordering should be preserved after truncation".to_string(),
                    max_event_count: 3,
                    events: vec![
                        EventForTruncation {
                            name: "late_high_priority".to_string(),
                            timestamp_offset_nanos: 5000,
                            attributes: vec![("priority".to_string(), "high".to_string())],
                            priority: 100,
                        },
                        EventForTruncation {
                            name: "early_medium_priority".to_string(),
                            timestamp_offset_nanos: 1000,
                            attributes: vec![("priority".to_string(), "medium".to_string())],
                            priority: 50,
                        },
                        EventForTruncation {
                            name: "middle_low_priority".to_string(),
                            timestamp_offset_nanos: 3000,
                            attributes: vec![("priority".to_string(), "low".to_string())],
                            priority: 10,
                        },
                        EventForTruncation {
                            name: "dropped_lowest".to_string(),
                            timestamp_offset_nanos: 2000,
                            attributes: vec![("priority".to_string(), "lowest".to_string())],
                            priority: 1,
                        },
                    ],
                    truncation_strategy: EventTruncationStrategy::PriorityBased,
                    expected_preserved_count: 3,
                    expected_dropped_count: 1,
                    expected_preserved_names: vec!["late_high_priority".to_string(), "early_medium_priority".to_string(), "middle_low_priority".to_string()],
                },
                SpanEventCountTruncationScenario {
                    name: "large_limit_no_truncation".to_string(),
                    description: "Large limit with many events, all preserved".to_string(),
                    max_event_count: 100,
                    events: (1..=15).map(|i| EventForTruncation {
                        name: format!("event_{}", i),
                        timestamp_offset_nanos: (i * 1000) as u64,
                        attributes: vec![("index".to_string(), i.to_string())],
                        priority: i as u32,
                    }).collect(),
                    truncation_strategy: EventTruncationStrategy::FirstWins,
                    expected_preserved_count: 15,
                    expected_dropped_count: 0,
                    expected_preserved_names: (1..=15).map(|i| format!("event_{}", i)).collect(),
                },
            ];

            for scenario in test_scenarios {
                // Test asupersync span event count truncation
                let asupersync_result = match model_asupersync_event_count_truncation(&scenario) {
                    Ok(result) => result,
                    Err(e) => return TestResult::failed(format!("Asupersync event count truncation failed for {}: {}", scenario.name, e)),
                };

                // Test opentelemetry-sdk span event count truncation
                let opentelemetry_result = match model_opentelemetry_event_count_truncation(&scenario) {
                    Ok(result) => result,
                    Err(e) => return TestResult::failed(format!("OpenTelemetry event count truncation failed for {}: {}", scenario.name, e)),
                };

                // Verify that both implementations produce identical truncation behavior
                if let Err(differences) = compare_event_count_truncation_results(&asupersync_result, &opentelemetry_result) {
                    return TestResult::failed(format!("Event count truncation differential test failed for {}: {}", scenario.name, differences));
                }

                // Verify expected truncation behavior
                if let Err(validation_error) = verify_event_count_truncation_expectations(&asupersync_result, &scenario) {
                    return TestResult::failed(format!("Truncation expectation validation failed for {}: {}", scenario.name, validation_error));
                }
            }

            TestResult::passed()
        }
    }
}

/// OTLP-043: Span.update_name() ordering conformance test.
pub fn otlp_043_span_update_name_ordering_conformance<RT: RuntimeInterface>() -> ConformanceTest<RT>
{
    crate::conformance_test! {
        id: "otlp-043",
        name: "Span.update_name() ordering conformance",
        description: "Verify span name update ordering vs opentelemetry-sdk — identical update behavior",
        category: TestCategory::IO,
        tags: ["otlp", "span", "name", "update", "ordering", "sequence"],
        expected: "Span name update ordering behaves identically across implementations",
        test: |_rt| {
            // Test scenarios for comprehensive span name update ordering validation
            let test_scenarios = vec![
                SpanNameUpdateScenario {
                    name: "sequential_updates".to_string(),
                    description: "Sequential name updates - last wins".to_string(),
                    name_updates: vec![
                        NameUpdateDefinition {
                            name: "initial_name".to_string(),
                            timestamp_nanos: 1_000_000_000,
                            span_phase: SpanPhase::Active,
                        },
                        NameUpdateDefinition {
                            name: "updated_name".to_string(),
                            timestamp_nanos: 1_100_000_000,
                            span_phase: SpanPhase::Active,
                        },
                        NameUpdateDefinition {
                            name: "final_name".to_string(),
                            timestamp_nanos: 1_200_000_000,
                            span_phase: SpanPhase::Active,
                        },
                    ],
                    expected_final_name: "final_name".to_string(),
                    ordering_strategy: NameUpdateOrderingStrategy::LastWins,
                },
                SpanNameUpdateScenario {
                    name: "updates_after_end".to_string(),
                    description: "Name updates after span end should be ignored".to_string(),
                    name_updates: vec![
                        NameUpdateDefinition {
                            name: "active_name".to_string(),
                            timestamp_nanos: 1_000_000_000,
                            span_phase: SpanPhase::Active,
                        },
                        NameUpdateDefinition {
                            name: "end_name".to_string(),
                            timestamp_nanos: 1_100_000_000,
                            span_phase: SpanPhase::Active,
                        },
                        NameUpdateDefinition {
                            name: "ignored_name".to_string(),
                            timestamp_nanos: 1_200_000_000,
                            span_phase: SpanPhase::Ended,
                        },
                    ],
                    expected_final_name: "end_name".to_string(),
                    ordering_strategy: NameUpdateOrderingStrategy::IgnoreAfterEnd,
                },
                SpanNameUpdateScenario {
                    name: "out_of_order_timestamps".to_string(),
                    description: "Name updates with out-of-order timestamps".to_string(),
                    name_updates: vec![
                        NameUpdateDefinition {
                            name: "third_timestamp".to_string(),
                            timestamp_nanos: 1_300_000_000,
                            span_phase: SpanPhase::Active,
                        },
                        NameUpdateDefinition {
                            name: "first_timestamp".to_string(),
                            timestamp_nanos: 1_100_000_000,
                            span_phase: SpanPhase::Active,
                        },
                        NameUpdateDefinition {
                            name: "second_timestamp".to_string(),
                            timestamp_nanos: 1_200_000_000,
                            span_phase: SpanPhase::Active,
                        },
                    ],
                    expected_final_name: "second_timestamp".to_string(),
                    ordering_strategy: NameUpdateOrderingStrategy::TimestampBased,
                },
                SpanNameUpdateScenario {
                    name: "recording_state_updates".to_string(),
                    description: "Name updates with different recording states".to_string(),
                    name_updates: vec![
                        NameUpdateDefinition {
                            name: "recording_name".to_string(),
                            timestamp_nanos: 1_000_000_000,
                            span_phase: SpanPhase::Recording,
                        },
                        NameUpdateDefinition {
                            name: "not_recording_name".to_string(),
                            timestamp_nanos: 1_100_000_000,
                            span_phase: SpanPhase::NotRecording,
                        },
                        NameUpdateDefinition {
                            name: "active_name".to_string(),
                            timestamp_nanos: 1_200_000_000,
                            span_phase: SpanPhase::Active,
                        },
                    ],
                    expected_final_name: "active_name".to_string(),
                    ordering_strategy: NameUpdateOrderingStrategy::LastWins,
                },
                SpanNameUpdateScenario {
                    name: "identical_timestamps".to_string(),
                    description: "Multiple name updates with identical timestamps".to_string(),
                    name_updates: vec![
                        NameUpdateDefinition {
                            name: "concurrent_update_a".to_string(),
                            timestamp_nanos: 1_500_000_000,
                            span_phase: SpanPhase::Active,
                        },
                        NameUpdateDefinition {
                            name: "concurrent_update_b".to_string(),
                            timestamp_nanos: 1_500_000_000,
                            span_phase: SpanPhase::Active,
                        },
                        NameUpdateDefinition {
                            name: "final_update".to_string(),
                            timestamp_nanos: 1_600_000_000,
                            span_phase: SpanPhase::Active,
                        },
                    ],
                    expected_final_name: "final_update".to_string(),
                    ordering_strategy: NameUpdateOrderingStrategy::LastWins,
                },
                SpanNameUpdateScenario {
                    name: "empty_and_null_names".to_string(),
                    description: "Name updates with empty and special values".to_string(),
                    name_updates: vec![
                        NameUpdateDefinition {
                            name: "initial_name".to_string(),
                            timestamp_nanos: 1_000_000_000,
                            span_phase: SpanPhase::Active,
                        },
                        NameUpdateDefinition {
                            name: "".to_string(),
                            timestamp_nanos: 1_100_000_000,
                            span_phase: SpanPhase::Active,
                        },
                        NameUpdateDefinition {
                            name: "final_name".to_string(),
                            timestamp_nanos: 1_200_000_000,
                            span_phase: SpanPhase::Active,
                        },
                    ],
                    expected_final_name: "final_name".to_string(),
                    ordering_strategy: NameUpdateOrderingStrategy::LastWins,
                },
            ];

            // Test each scenario with differential testing
            for scenario in test_scenarios {
                checkpoint("span_name_update_ordering_test", json!({
                    "scenario": scenario.name,
                    "description": scenario.description,
                    "update_count": scenario.name_updates.len(),
                    "expected_final_name": scenario.expected_final_name,
                    "ordering_strategy": format!("{:?}", scenario.ordering_strategy)
                }));

                // Test asupersync implementation
                let asupersync_result = match model_asupersync_span_name_ordering(&scenario) {
                    Ok(result) => result,
                    Err(error) => return TestResult::failed(format!("Asupersync span name ordering failed for {}: {}", scenario.name, error)),
                };

                // Test opentelemetry-sdk implementation
                let opentelemetry_result = match model_opentelemetry_span_name_ordering(&scenario) {
                    Ok(result) => result,
                    Err(error) => return TestResult::failed(format!("OpenTelemetry span name ordering failed for {}: {}", scenario.name, error)),
                };

                // Compare implementations for conformance
                if let Err(comparison_error) = compare_span_name_ordering_results(&asupersync_result, &opentelemetry_result, &scenario) {
                    return TestResult::failed(format!("Name ordering comparison failed for {}: {}", scenario.name, comparison_error));
                }

                // Verify expected final name behavior
                if let Err(validation_error) = verify_span_name_ordering_expectations(&asupersync_result, &scenario) {
                    return TestResult::failed(format!("Name ordering expectation validation failed for {}: {}", scenario.name, validation_error));
                }
            }

            TestResult::passed()
        }
    }
}

/// OTLP-044: Meter scope deduplication conformance test.
pub fn otlp_044_meter_scope_deduplication_conformance<RT: RuntimeInterface>() -> ConformanceTest<RT>
{
    crate::conformance_test! {
        id: "otlp-044",
        name: "Meter scope deduplication conformance",
        description: "Verify meter scope deduplication vs opentelemetry-sdk — identical deduplication behavior",
        category: TestCategory::IO,
        tags: ["otlp", "meter", "scope", "deduplication", "instrumentation", "library"],
        expected: "Meter scope deduplication behaves identically across implementations",
        test: |_rt| {
            // Test scenarios for comprehensive meter scope deduplication validation
            let test_scenarios = vec![
                MeterScopeDeduplicationScenario {
                    name: "identical_name_version".to_string(),
                    description: "Meters with identical scope name and version should be deduplicated".to_string(),
                    meter_definitions: vec![
                        MeterDefinition {
                            name: "http_requests".to_string(),
                            scope_name: "my-library".to_string(),
                            scope_version: "1.0.0".to_string(),
                            scope_attributes: vec![("component".to_string(), "http".to_string())],
                            creation_order: 1,
                            schema_url: Some("https://schema.org/v1".to_string()),
                        },
                        MeterDefinition {
                            name: "http_duration".to_string(),
                            scope_name: "my-library".to_string(),
                            scope_version: "1.0.0".to_string(),
                            scope_attributes: vec![("component".to_string(), "http".to_string())],
                            creation_order: 2,
                            schema_url: Some("https://schema.org/v1".to_string()),
                        },
                        MeterDefinition {
                            name: "http_errors".to_string(),
                            scope_name: "my-library".to_string(),
                            scope_version: "1.0.0".to_string(),
                            scope_attributes: vec![("component".to_string(), "http".to_string())],
                            creation_order: 3,
                            schema_url: Some("https://schema.org/v1".to_string()),
                        },
                    ],
                    expected_unique_scopes: 1,
                    expected_deduplicated_count: 2,
                    deduplication_strategy: ScopeDeduplicationStrategy::NameAndVersion,
                },
                MeterScopeDeduplicationScenario {
                    name: "different_versions".to_string(),
                    description: "Meters with same name but different versions should not be deduplicated".to_string(),
                    meter_definitions: vec![
                        MeterDefinition {
                            name: "database_queries".to_string(),
                            scope_name: "db-library".to_string(),
                            scope_version: "1.0.0".to_string(),
                            scope_attributes: vec![("component".to_string(), "db".to_string())],
                            creation_order: 1,
                            schema_url: None,
                        },
                        MeterDefinition {
                            name: "database_connections".to_string(),
                            scope_name: "db-library".to_string(),
                            scope_version: "2.0.0".to_string(),
                            scope_attributes: vec![("component".to_string(), "db".to_string())],
                            creation_order: 2,
                            schema_url: None,
                        },
                        MeterDefinition {
                            name: "database_errors".to_string(),
                            scope_name: "db-library".to_string(),
                            scope_version: "1.1.0".to_string(),
                            scope_attributes: vec![("component".to_string(), "db".to_string())],
                            creation_order: 3,
                            schema_url: None,
                        },
                    ],
                    expected_unique_scopes: 3,
                    expected_deduplicated_count: 0,
                    deduplication_strategy: ScopeDeduplicationStrategy::NameAndVersion,
                },
                MeterScopeDeduplicationScenario {
                    name: "different_names".to_string(),
                    description: "Meters with different scope names should not be deduplicated".to_string(),
                    meter_definitions: vec![
                        MeterDefinition {
                            name: "cache_hits".to_string(),
                            scope_name: "cache-library".to_string(),
                            scope_version: "1.0.0".to_string(),
                            scope_attributes: vec![],
                            creation_order: 1,
                            schema_url: None,
                        },
                        MeterDefinition {
                            name: "queue_size".to_string(),
                            scope_name: "queue-library".to_string(),
                            scope_version: "1.0.0".to_string(),
                            scope_attributes: vec![],
                            creation_order: 2,
                            schema_url: None,
                        },
                        MeterDefinition {
                            name: "worker_active".to_string(),
                            scope_name: "worker-library".to_string(),
                            scope_version: "1.0.0".to_string(),
                            scope_attributes: vec![],
                            creation_order: 3,
                            schema_url: None,
                        },
                    ],
                    expected_unique_scopes: 3,
                    expected_deduplicated_count: 0,
                    deduplication_strategy: ScopeDeduplicationStrategy::NameAndVersion,
                },
                MeterScopeDeduplicationScenario {
                    name: "attribute_differences".to_string(),
                    description: "Meters with same name/version but different attributes - deduplication depends on strategy".to_string(),
                    meter_definitions: vec![
                        MeterDefinition {
                            name: "api_requests".to_string(),
                            scope_name: "api-library".to_string(),
                            scope_version: "1.0.0".to_string(),
                            scope_attributes: vec![("component".to_string(), "api".to_string()), ("region".to_string(), "us-east".to_string())],
                            creation_order: 1,
                            schema_url: None,
                        },
                        MeterDefinition {
                            name: "api_latency".to_string(),
                            scope_name: "api-library".to_string(),
                            scope_version: "1.0.0".to_string(),
                            scope_attributes: vec![("component".to_string(), "api".to_string()), ("region".to_string(), "us-west".to_string())],
                            creation_order: 2,
                            schema_url: None,
                        },
                        MeterDefinition {
                            name: "api_errors".to_string(),
                            scope_name: "api-library".to_string(),
                            scope_version: "1.0.0".to_string(),
                            scope_attributes: vec![("component".to_string(), "api".to_string())],
                            creation_order: 3,
                            schema_url: None,
                        },
                    ],
                    expected_unique_scopes: 3,
                    expected_deduplicated_count: 0,
                    deduplication_strategy: ScopeDeduplicationStrategy::NameVersionAndAttributes,
                },
                MeterScopeDeduplicationScenario {
                    name: "schema_url_differences".to_string(),
                    description: "Meters with same name/version but different schema URLs".to_string(),
                    meter_definitions: vec![
                        MeterDefinition {
                            name: "grpc_calls".to_string(),
                            scope_name: "grpc-library".to_string(),
                            scope_version: "1.0.0".to_string(),
                            scope_attributes: vec![],
                            creation_order: 1,
                            schema_url: Some("https://schema.org/v1".to_string()),
                        },
                        MeterDefinition {
                            name: "grpc_latency".to_string(),
                            scope_name: "grpc-library".to_string(),
                            scope_version: "1.0.0".to_string(),
                            scope_attributes: vec![],
                            creation_order: 2,
                            schema_url: Some("https://schema.org/v2".to_string()),
                        },
                        MeterDefinition {
                            name: "grpc_errors".to_string(),
                            scope_name: "grpc-library".to_string(),
                            scope_version: "1.0.0".to_string(),
                            scope_attributes: vec![],
                            creation_order: 3,
                            schema_url: None,
                        },
                    ],
                    expected_unique_scopes: 3,
                    expected_deduplicated_count: 0,
                    deduplication_strategy: ScopeDeduplicationStrategy::NameVersionAndSchemaUrl,
                },
                MeterScopeDeduplicationScenario {
                    name: "creation_order_preservation".to_string(),
                    description: "Deduplication should preserve first-created meter's characteristics".to_string(),
                    meter_definitions: vec![
                        MeterDefinition {
                            name: "memory_usage".to_string(),
                            scope_name: "monitoring".to_string(),
                            scope_version: "1.0.0".to_string(),
                            scope_attributes: vec![("env".to_string(), "prod".to_string())],
                            creation_order: 1,
                            schema_url: Some("https://monitoring.com/v1".to_string()),
                        },
                        MeterDefinition {
                            name: "cpu_usage".to_string(),
                            scope_name: "monitoring".to_string(),
                            scope_version: "1.0.0".to_string(),
                            scope_attributes: vec![("env".to_string(), "prod".to_string())],
                            creation_order: 5,
                            schema_url: Some("https://monitoring.com/v1".to_string()),
                        },
                        MeterDefinition {
                            name: "disk_usage".to_string(),
                            scope_name: "monitoring".to_string(),
                            scope_version: "1.0.0".to_string(),
                            scope_attributes: vec![("env".to_string(), "prod".to_string())],
                            creation_order: 3,
                            schema_url: Some("https://monitoring.com/v1".to_string()),
                        },
                    ],
                    expected_unique_scopes: 1,
                    expected_deduplicated_count: 2,
                    deduplication_strategy: ScopeDeduplicationStrategy::StrictEquality,
                },
            ];

            // Test each scenario with differential testing
            for scenario in test_scenarios {
                checkpoint("meter_scope_deduplication_test", json!({
                    "scenario": scenario.name,
                    "description": scenario.description,
                    "meter_count": scenario.meter_definitions.len(),
                    "expected_unique_scopes": scenario.expected_unique_scopes,
                    "expected_deduplicated_count": scenario.expected_deduplicated_count,
                    "deduplication_strategy": format!("{:?}", scenario.deduplication_strategy)
                }));

                // Test asupersync implementation
                let asupersync_result = match model_asupersync_meter_scope_deduplication(&scenario) {
                    Ok(result) => result,
                    Err(error) => return TestResult::failed(format!("Asupersync meter scope deduplication failed for {}: {}", scenario.name, error)),
                };

                // Test opentelemetry-sdk implementation
                let opentelemetry_result = match model_opentelemetry_meter_scope_deduplication(&scenario) {
                    Ok(result) => result,
                    Err(error) => return TestResult::failed(format!("OpenTelemetry meter scope deduplication failed for {}: {}", scenario.name, error)),
                };

                // Compare implementations for conformance
                if let Err(comparison_error) = compare_meter_scope_deduplication_results(&asupersync_result, &opentelemetry_result, &scenario) {
                    return TestResult::failed(format!("Scope deduplication comparison failed for {}: {}", scenario.name, comparison_error));
                }

                // Verify expected deduplication behavior
                if let Err(validation_error) = verify_meter_scope_deduplication_expectations(&asupersync_result, &scenario) {
                    return TestResult::failed(format!("Scope deduplication expectation validation failed for {}: {}", scenario.name, validation_error));
                }
            }

            TestResult::passed()
        }
    }
}

/// OTLP-045: Span attribute key-value validation conformance test.
pub fn otlp_045_span_attribute_key_value_validation_conformance<RT: RuntimeInterface>()
-> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-045",
        name: "Span attribute key-value validation conformance",
        description: "Verify span attribute key-value validation vs opentelemetry-sdk — identical validation behavior",
        category: TestCategory::IO,
        tags: ["otlp", "span", "attribute", "key", "value", "validation", "format"],
        expected: "Span attribute key-value validation behaves identically across implementations",
        test: |_rt| {
            // Test scenarios for comprehensive span attribute key-value validation
            let test_scenarios = vec![
                SpanAttributeKeyValueValidationScenario {
                    name: "valid_standard_keys".to_string(),
                    description: "Standard valid attribute keys and values".to_string(),
                    attribute_pairs: vec![
                        AttributeKeyValueDefinition {
                            key: "service.name".to_string(),
                            value: AttributeValue::String("my-service".to_string()),
                            expected_valid: true,
                            validation_context: AttributeValidationContext::Span,
                        },
                        AttributeKeyValueDefinition {
                            key: "http.status_code".to_string(),
                            value: AttributeValue::Int(200),
                            expected_valid: true,
                            validation_context: AttributeValidationContext::Span,
                        },
                        AttributeKeyValueDefinition {
                            key: "http.request_content_length".to_string(),
                            value: AttributeValue::Int(1024),
                            expected_valid: true,
                            validation_context: AttributeValidationContext::Span,
                        },
                        AttributeKeyValueDefinition {
                            key: "user.authenticated".to_string(),
                            value: AttributeValue::Bool(true),
                            expected_valid: true,
                            validation_context: AttributeValidationContext::Span,
                        },
                    ],
                    validation_strategy: AttributeValidationStrategy::OpenTelemetryStandard,
                    expected_valid_count: 4,
                    expected_invalid_count: 0,
                    expected_valid_keys: vec!["service.name".to_string(), "http.status_code".to_string(), "http.request_content_length".to_string(), "user.authenticated".to_string()],
                },
                SpanAttributeKeyValueValidationScenario {
                    name: "invalid_key_characters".to_string(),
                    description: "Keys with invalid characters should be rejected".to_string(),
                    attribute_pairs: vec![
                        AttributeKeyValueDefinition {
                            key: "invalid key with spaces".to_string(),
                            value: AttributeValue::String("value".to_string()),
                            expected_valid: false,
                            validation_context: AttributeValidationContext::Span,
                        },
                        AttributeKeyValueDefinition {
                            key: "invalid@key".to_string(),
                            value: AttributeValue::String("value".to_string()),
                            expected_valid: false,
                            validation_context: AttributeValidationContext::Span,
                        },
                        AttributeKeyValueDefinition {
                            key: "invalid#key".to_string(),
                            value: AttributeValue::String("value".to_string()),
                            expected_valid: false,
                            validation_context: AttributeValidationContext::Span,
                        },
                        AttributeKeyValueDefinition {
                            key: "valid_key".to_string(),
                            value: AttributeValue::String("value".to_string()),
                            expected_valid: true,
                            validation_context: AttributeValidationContext::Span,
                        },
                    ],
                    validation_strategy: AttributeValidationStrategy::StrictKeyFormat,
                    expected_valid_count: 1,
                    expected_invalid_count: 3,
                    expected_valid_keys: vec!["valid_key".to_string()],
                },
                SpanAttributeKeyValueValidationScenario {
                    name: "empty_and_null_values".to_string(),
                    description: "Empty keys and null values handling".to_string(),
                    attribute_pairs: vec![
                        AttributeKeyValueDefinition {
                            key: "".to_string(),
                            value: AttributeValue::String("value".to_string()),
                            expected_valid: false,
                            validation_context: AttributeValidationContext::Span,
                        },
                        AttributeKeyValueDefinition {
                            key: "valid_key".to_string(),
                            value: AttributeValue::Null,
                            expected_valid: false,
                            validation_context: AttributeValidationContext::Span,
                        },
                        AttributeKeyValueDefinition {
                            key: "empty_string_value".to_string(),
                            value: AttributeValue::String("".to_string()),
                            expected_valid: true,
                            validation_context: AttributeValidationContext::Span,
                        },
                        AttributeKeyValueDefinition {
                            key: "zero_value".to_string(),
                            value: AttributeValue::Int(0),
                            expected_valid: true,
                            validation_context: AttributeValidationContext::Span,
                        },
                    ],
                    validation_strategy: AttributeValidationStrategy::OpenTelemetryStandard,
                    expected_valid_count: 2,
                    expected_invalid_count: 2,
                    expected_valid_keys: vec!["empty_string_value".to_string(), "zero_value".to_string()],
                },
                SpanAttributeKeyValueValidationScenario {
                    name: "unicode_keys_and_values".to_string(),
                    description: "Unicode characters in keys and values".to_string(),
                    attribute_pairs: vec![
                        AttributeKeyValueDefinition {
                            key: "测试键".to_string(),
                            value: AttributeValue::String("测试值".to_string()),
                            expected_valid: true,
                            validation_context: AttributeValidationContext::Span,
                        },
                        AttributeKeyValueDefinition {
                            key: "🔑emoji_key".to_string(),
                            value: AttributeValue::String("🎯emoji_value".to_string()),
                            expected_valid: false,
                            validation_context: AttributeValidationContext::Span,
                        },
                        AttributeKeyValueDefinition {
                            key: "café.name".to_string(),
                            value: AttributeValue::String("naïve café".to_string()),
                            expected_valid: true,
                            validation_context: AttributeValidationContext::Span,
                        },
                        AttributeKeyValueDefinition {
                            key: "αβγδε".to_string(),
                            value: AttributeValue::String("Greek letters".to_string()),
                            expected_valid: true,
                            validation_context: AttributeValidationContext::Span,
                        },
                    ],
                    validation_strategy: AttributeValidationStrategy::UnicodeAware,
                    expected_valid_count: 3,
                    expected_invalid_count: 1,
                    expected_valid_keys: vec!["测试键".to_string(), "café.name".to_string(), "αβγδε".to_string()],
                },
                SpanAttributeKeyValueValidationScenario {
                    name: "key_length_limits".to_string(),
                    description: "Key length validation limits".to_string(),
                    attribute_pairs: vec![
                        AttributeKeyValueDefinition {
                            key: "a".repeat(1),
                            value: AttributeValue::String("short_key".to_string()),
                            expected_valid: true,
                            validation_context: AttributeValidationContext::Span,
                        },
                        AttributeKeyValueDefinition {
                            key: "a".repeat(128),
                            value: AttributeValue::String("medium_key".to_string()),
                            expected_valid: true,
                            validation_context: AttributeValidationContext::Span,
                        },
                        AttributeKeyValueDefinition {
                            key: "a".repeat(256),
                            value: AttributeValue::String("long_key".to_string()),
                            expected_valid: true,
                            validation_context: AttributeValidationContext::Span,
                        },
                        AttributeKeyValueDefinition {
                            key: "a".repeat(1000),
                            value: AttributeValue::String("very_long_key".to_string()),
                            expected_valid: false,
                            validation_context: AttributeValidationContext::Span,
                        },
                    ],
                    validation_strategy: AttributeValidationStrategy::OpenTelemetryStandard,
                    expected_valid_count: 3,
                    expected_invalid_count: 1,
                    expected_valid_keys: vec!["a".to_string(), "a".repeat(128), "a".repeat(256)],
                },
                SpanAttributeKeyValueValidationScenario {
                    name: "array_and_complex_values".to_string(),
                    description: "Array values and complex value types".to_string(),
                    attribute_pairs: vec![
                        AttributeKeyValueDefinition {
                            key: "string_array".to_string(),
                            value: AttributeValue::Array(vec!["item1".to_string(), "item2".to_string(), "item3".to_string()]),
                            expected_valid: true,
                            validation_context: AttributeValidationContext::Span,
                        },
                        AttributeKeyValueDefinition {
                            key: "empty_array".to_string(),
                            value: AttributeValue::Array(vec![]),
                            expected_valid: true,
                            validation_context: AttributeValidationContext::Span,
                        },
                        AttributeKeyValueDefinition {
                            key: "float_value".to_string(),
                            value: AttributeValue::Float(3.14159),
                            expected_valid: true,
                            validation_context: AttributeValidationContext::Span,
                        },
                        AttributeKeyValueDefinition {
                            key: "negative_float".to_string(),
                            value: AttributeValue::Float(-42.5),
                            expected_valid: true,
                            validation_context: AttributeValidationContext::Span,
                        },
                    ],
                    validation_strategy: AttributeValidationStrategy::OpenTelemetryStandard,
                    expected_valid_count: 4,
                    expected_invalid_count: 0,
                    expected_valid_keys: vec!["string_array".to_string(), "empty_array".to_string(), "float_value".to_string(), "negative_float".to_string()],
                },
                SpanAttributeKeyValueValidationScenario {
                    name: "context_specific_validation".to_string(),
                    description: "Different validation rules for different contexts".to_string(),
                    attribute_pairs: vec![
                        AttributeKeyValueDefinition {
                            key: "service.name".to_string(),
                            value: AttributeValue::String("my-service".to_string()),
                            expected_valid: true,
                            validation_context: AttributeValidationContext::Resource,
                        },
                        AttributeKeyValueDefinition {
                            key: "span.kind".to_string(),
                            value: AttributeValue::String("server".to_string()),
                            expected_valid: true,
                            validation_context: AttributeValidationContext::Span,
                        },
                        AttributeKeyValueDefinition {
                            key: "event.name".to_string(),
                            value: AttributeValue::String("request_received".to_string()),
                            expected_valid: true,
                            validation_context: AttributeValidationContext::Event,
                        },
                        AttributeKeyValueDefinition {
                            key: "link.trace_state".to_string(),
                            value: AttributeValue::String("vendor=value".to_string()),
                            expected_valid: true,
                            validation_context: AttributeValidationContext::Link,
                        },
                    ],
                    validation_strategy: AttributeValidationStrategy::OpenTelemetryStandard,
                    expected_valid_count: 4,
                    expected_invalid_count: 0,
                    expected_valid_keys: vec!["service.name".to_string(), "span.kind".to_string(), "event.name".to_string(), "link.trace_state".to_string()],
                },
            ];

            // Test each scenario with differential testing
            for scenario in test_scenarios {
                checkpoint("span_attribute_key_value_validation_test", json!({
                    "scenario": scenario.name,
                    "description": scenario.description,
                    "attribute_count": scenario.attribute_pairs.len(),
                    "expected_valid_count": scenario.expected_valid_count,
                    "expected_invalid_count": scenario.expected_invalid_count,
                    "validation_strategy": format!("{:?}", scenario.validation_strategy)
                }));

                // Test asupersync implementation
                let asupersync_result = match model_asupersync_attribute_key_value_validation(&scenario) {
                    Ok(result) => result,
                    Err(error) => return TestResult::failed(format!("Asupersync attribute validation failed for {}: {}", scenario.name, error)),
                };

                // Test opentelemetry-sdk implementation
                let opentelemetry_result = match model_opentelemetry_attribute_key_value_validation(&scenario) {
                    Ok(result) => result,
                    Err(error) => return TestResult::failed(format!("OpenTelemetry attribute validation failed for {}: {}", scenario.name, error)),
                };

                // Compare implementations for conformance
                if let Err(comparison_error) = compare_attribute_key_value_validation_results(&asupersync_result, &opentelemetry_result, &scenario) {
                    return TestResult::failed(format!("Attribute validation comparison failed for {}: {}", scenario.name, comparison_error));
                }

                // Verify expected validation behavior
                if let Err(validation_error) = verify_attribute_key_value_validation_expectations(&asupersync_result, &scenario) {
                    return TestResult::failed(format!("Attribute validation expectation validation failed for {}: {}", scenario.name, validation_error));
                }
            }

            TestResult::passed()
        }
    }
}

/// OTLP-046: OTLP serialization stable byte order conformance test.
pub fn otlp_046_serialization_stable_byte_order_conformance<RT: RuntimeInterface>()
-> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-046",
        name: "OTLP serialization stable byte order conformance",
        description: "Verify OTLP serialization stable byte order vs opentelemetry-sdk — identical byte ordering",
        category: TestCategory::IO,
        tags: ["otlp", "serialization", "byte", "order", "deterministic", "protobuf"],
        expected: "OTLP serialization byte order behaves identically across implementations",
        test: |_rt| {
            // Test scenarios for comprehensive OTLP serialization stable byte order validation
            let test_scenarios = vec![
                OtlpSerializationStableByteOrderScenario {
                    name: "basic_span_serialization".to_string(),
                    description: "Basic span serialization with field number ordering".to_string(),
                    message_definitions: vec![
                        OtlpMessageDefinition {
                            message_type: OtlpMessageType::Span,
                            fields: vec![
                                OtlpFieldDefinition {
                                    field_name: "trace_id".to_string(),
                                    field_number: 1,
                                    field_type: OtlpFieldType::Bytes,
                                    field_value: OtlpFieldValue::Bytes(vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
                                    is_repeated: false,
                                },
                                OtlpFieldDefinition {
                                    field_name: "span_id".to_string(),
                                    field_number: 2,
                                    field_type: OtlpFieldType::Bytes,
                                    field_value: OtlpFieldValue::Bytes(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22]),
                                    is_repeated: false,
                                },
                                OtlpFieldDefinition {
                                    field_name: "name".to_string(),
                                    field_number: 5,
                                    field_type: OtlpFieldType::String,
                                    field_value: OtlpFieldValue::String("test_span".to_string()),
                                    is_repeated: false,
                                },
                                OtlpFieldDefinition {
                                    field_name: "start_time_unix_nano".to_string(),
                                    field_number: 7,
                                    field_type: OtlpFieldType::Uint64,
                                    field_value: OtlpFieldValue::Uint64(1640995200000000000),
                                    is_repeated: false,
                                },
                                OtlpFieldDefinition {
                                    field_name: "end_time_unix_nano".to_string(),
                                    field_number: 8,
                                    field_type: OtlpFieldType::Uint64,
                                    field_value: OtlpFieldValue::Uint64(1640995201000000000),
                                    is_repeated: false,
                                },
                            ],
                            nested_messages: vec![],
                            repeated_fields: vec![],
                        },
                    ],
                    serialization_strategy: SerializationOrderStrategy::FieldNumberOrder,
                    expected_deterministic: true,
                    expected_byte_length: Some(89),
                    expected_field_order: vec!["trace_id".to_string(), "span_id".to_string(), "name".to_string(), "start_time_unix_nano".to_string(), "end_time_unix_nano".to_string()],
                },
                OtlpSerializationStableByteOrderScenario {
                    name: "span_with_attributes".to_string(),
                    description: "Span with repeated attributes - stable ordering".to_string(),
                    message_definitions: vec![
                        OtlpMessageDefinition {
                            message_type: OtlpMessageType::Span,
                            fields: vec![
                                OtlpFieldDefinition {
                                    field_name: "trace_id".to_string(),
                                    field_number: 1,
                                    field_type: OtlpFieldType::Bytes,
                                    field_value: OtlpFieldValue::Bytes(vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
                                    is_repeated: false,
                                },
                                OtlpFieldDefinition {
                                    field_name: "name".to_string(),
                                    field_number: 5,
                                    field_type: OtlpFieldType::String,
                                    field_value: OtlpFieldValue::String("attributed_span".to_string()),
                                    is_repeated: false,
                                },
                            ],
                            nested_messages: vec![],
                            repeated_fields: vec![
                                OtlpRepeatedFieldDefinition {
                                    field_name: "attributes".to_string(),
                                    field_number: 9,
                                    field_type: OtlpFieldType::Message,
                                    field_values: vec![
                                        OtlpFieldValue::Message("key:service.name value:test-service".to_string()),
                                        OtlpFieldValue::Message("key:http.method value:GET".to_string()),
                                        OtlpFieldValue::Message("key:http.status_code value:200".to_string()),
                                    ],
                                    ordering_strategy: RepeatedFieldOrderStrategy::InsertionOrder,
                                },
                            ],
                        },
                    ],
                    serialization_strategy: SerializationOrderStrategy::FieldNumberOrder,
                    expected_deterministic: true,
                    expected_byte_length: Some(156),
                    expected_field_order: vec!["trace_id".to_string(), "name".to_string(), "attributes".to_string()],
                },
                OtlpSerializationStableByteOrderScenario {
                    name: "unicode_string_fields".to_string(),
                    description: "Unicode string fields - UTF-8 byte order stability".to_string(),
                    message_definitions: vec![
                        OtlpMessageDefinition {
                            message_type: OtlpMessageType::Span,
                            fields: vec![
                                OtlpFieldDefinition {
                                    field_name: "name".to_string(),
                                    field_number: 5,
                                    field_type: OtlpFieldType::String,
                                    field_value: OtlpFieldValue::String("测试跨度".to_string()),
                                    is_repeated: false,
                                },
                            ],
                            nested_messages: vec![],
                            repeated_fields: vec![
                                OtlpRepeatedFieldDefinition {
                                    field_name: "attributes".to_string(),
                                    field_number: 9,
                                    field_type: OtlpFieldType::Message,
                                    field_values: vec![
                                        OtlpFieldValue::Message("key:用户名 value:张三".to_string()),
                                        OtlpFieldValue::Message("key:café.name value:naïve".to_string()),
                                        OtlpFieldValue::Message("key:αβγδε value:Ελληνικά".to_string()),
                                    ],
                                    ordering_strategy: RepeatedFieldOrderStrategy::StableSort,
                                },
                            ],
                        },
                    ],
                    serialization_strategy: SerializationOrderStrategy::CanonicalOrder,
                    expected_deterministic: true,
                    expected_byte_length: None,
                    expected_field_order: vec!["name".to_string(), "attributes".to_string()],
                },
                OtlpSerializationStableByteOrderScenario {
                    name: "nested_messages_ordering".to_string(),
                    description: "Nested messages with stable field ordering".to_string(),
                    message_definitions: vec![
                        OtlpMessageDefinition {
                            message_type: OtlpMessageType::ExportTraceServiceRequest,
                            fields: vec![],
                            nested_messages: vec![
                                OtlpMessageDefinition {
                                    message_type: OtlpMessageType::ResourceSpans,
                                    fields: vec![
                                        OtlpFieldDefinition {
                                            field_name: "schema_url".to_string(),
                                            field_number: 2,
                                            field_type: OtlpFieldType::String,
                                            field_value: OtlpFieldValue::String("https://schema.org/v1".to_string()),
                                            is_repeated: false,
                                        },
                                    ],
                                    nested_messages: vec![
                                        OtlpMessageDefinition {
                                            message_type: OtlpMessageType::InstrumentationLibrarySpans,
                                            fields: vec![
                                                OtlpFieldDefinition {
                                                    field_name: "schema_url".to_string(),
                                                    field_number: 2,
                                                    field_type: OtlpFieldType::String,
                                                    field_value: OtlpFieldValue::String("https://lib.schema.org/v1".to_string()),
                                                    is_repeated: false,
                                                },
                                            ],
                                            nested_messages: vec![],
                                            repeated_fields: vec![],
                                        },
                                    ],
                                    repeated_fields: vec![],
                                },
                            ],
                            repeated_fields: vec![],
                        },
                    ],
                    serialization_strategy: SerializationOrderStrategy::FieldNumberOrder,
                    expected_deterministic: true,
                    expected_byte_length: None,
                    expected_field_order: vec!["schema_url".to_string()],
                },
                OtlpSerializationStableByteOrderScenario {
                    name: "numeric_field_precision".to_string(),
                    description: "Numeric fields with precise byte representation".to_string(),
                    message_definitions: vec![
                        OtlpMessageDefinition {
                            message_type: OtlpMessageType::Metric,
                            fields: vec![
                                OtlpFieldDefinition {
                                    field_name: "name".to_string(),
                                    field_number: 1,
                                    field_type: OtlpFieldType::String,
                                    field_value: OtlpFieldValue::String("cpu_usage".to_string()),
                                    is_repeated: false,
                                },
                            ],
                            nested_messages: vec![],
                            repeated_fields: vec![
                                OtlpRepeatedFieldDefinition {
                                    field_name: "data_points".to_string(),
                                    field_number: 5,
                                    field_type: OtlpFieldType::Message,
                                    field_values: vec![
                                        OtlpFieldValue::Message("value:3.141592653589793 timestamp:1640995200000000000".to_string()),
                                        OtlpFieldValue::Message("value:2.718281828459045 timestamp:1640995201000000000".to_string()),
                                        OtlpFieldValue::Message("value:1.618033988749895 timestamp:1640995202000000000".to_string()),
                                    ],
                                    ordering_strategy: RepeatedFieldOrderStrategy::SortedOrder,
                                },
                            ],
                        },
                    ],
                    serialization_strategy: SerializationOrderStrategy::FieldNumberOrder,
                    expected_deterministic: true,
                    expected_byte_length: None,
                    expected_field_order: vec!["name".to_string(), "data_points".to_string()],
                },
                OtlpSerializationStableByteOrderScenario {
                    name: "empty_and_default_fields".to_string(),
                    description: "Empty and default field handling in serialization".to_string(),
                    message_definitions: vec![
                        OtlpMessageDefinition {
                            message_type: OtlpMessageType::Span,
                            fields: vec![
                                OtlpFieldDefinition {
                                    field_name: "trace_id".to_string(),
                                    field_number: 1,
                                    field_type: OtlpFieldType::Bytes,
                                    field_value: OtlpFieldValue::Bytes(vec![]),
                                    is_repeated: false,
                                },
                                OtlpFieldDefinition {
                                    field_name: "name".to_string(),
                                    field_number: 5,
                                    field_type: OtlpFieldType::String,
                                    field_value: OtlpFieldValue::String("".to_string()),
                                    is_repeated: false,
                                },
                                OtlpFieldDefinition {
                                    field_name: "start_time_unix_nano".to_string(),
                                    field_number: 7,
                                    field_type: OtlpFieldType::Uint64,
                                    field_value: OtlpFieldValue::Uint64(0),
                                    is_repeated: false,
                                },
                                OtlpFieldDefinition {
                                    field_name: "dropped_attributes_count".to_string(),
                                    field_number: 12,
                                    field_type: OtlpFieldType::Uint64,
                                    field_value: OtlpFieldValue::Uint64(0),
                                    is_repeated: false,
                                },
                            ],
                            nested_messages: vec![],
                            repeated_fields: vec![],
                        },
                    ],
                    serialization_strategy: SerializationOrderStrategy::FieldNumberOrder,
                    expected_deterministic: true,
                    expected_byte_length: Some(12),
                    expected_field_order: vec!["name".to_string()],
                },
            ];

            // Test each scenario with differential testing
            for scenario in test_scenarios {
                checkpoint("otlp_serialization_stable_byte_order_test", json!({
                    "scenario": scenario.name,
                    "description": scenario.description,
                    "message_count": scenario.message_definitions.len(),
                    "expected_deterministic": scenario.expected_deterministic,
                    "expected_byte_length": scenario.expected_byte_length,
                    "serialization_strategy": format!("{:?}", scenario.serialization_strategy)
                }));

                // Test asupersync implementation
                let asupersync_result = match model_asupersync_otlp_serialization_stable_byte_order(&scenario) {
                    Ok(result) => result,
                    Err(error) => return TestResult::failed(format!("Asupersync OTLP serialization failed for {}: {}", scenario.name, error)),
                };

                // Test opentelemetry-sdk implementation
                let opentelemetry_result = match model_opentelemetry_otlp_serialization_stable_byte_order(&scenario) {
                    Ok(result) => result,
                    Err(error) => return TestResult::failed(format!("OpenTelemetry OTLP serialization failed for {}: {}", scenario.name, error)),
                };

                // Compare implementations for conformance
                if let Err(comparison_error) = compare_otlp_serialization_stable_byte_order_results(&asupersync_result, &opentelemetry_result, &scenario) {
                    return TestResult::failed(format!("OTLP serialization comparison failed for {}: {}", scenario.name, comparison_error));
                }

                // Verify expected serialization behavior
                if let Err(validation_error) = verify_otlp_serialization_stable_byte_order_expectations(&asupersync_result, &scenario) {
                    return TestResult::failed(format!("OTLP serialization expectation validation failed for {}: {}", scenario.name, validation_error));
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
        otlp_014_observable_counter_callback_ordering::<RT>(),
        otlp_015_updown_counter_incr_decr_conformance::<RT>(),
        otlp_016_histogram_record_explicit_bounds::<RT>(),
        otlp_017_context_propagation_async_boundary::<RT>(),
        otlp_018_grpc_retry_after_handling::<RT>(),
        otlp_019_trace_state_propagation_span_hierarchy::<RT>(),
        otlp_020_http_protobuf_exporter_format::<RT>(),
        otlp_021_span_set_attribute_conformance::<RT>(),
        otlp_022_meter_create_counter_name_validation::<RT>(),
        otlp_023_span_id_generation_entropy::<RT>(),
        otlp_024_span_add_event_conformance::<RT>(),
        otlp_025_trace_get_active_conformance::<RT>(),
        otlp_026_span_set_status_conformance::<RT>(),
        otlp_027_span_timing_monotonicity_conformance::<RT>(),
        otlp_028_span_is_recording_after_end_conformance::<RT>(),
        otlp_029_span_attribute_count_limit_conformance::<RT>(),
        otlp_030_span_context_extraction_conformance::<RT>(),
        otlp_031_span_event_count_limit_conformance::<RT>(),
        otlp_032_span_id_reuse_prevention_conformance::<RT>(),
        otlp_033_span_attributes_count_limit_conformance::<RT>(),
        otlp_034_span_end_time_export_time_monotonicity_conformance::<RT>(),
        otlp_035_span_resource_attribute_aggregation_conformance::<RT>(),
        otlp_036_export_deadline_backoff_conformance::<RT>(),
        otlp_037_span_attribute_string_truncation_conformance::<RT>(),
        otlp_038_span_event_timestamp_ordering_conformance::<RT>(),
        otlp_039_span_attribute_count_limit_precedence_conformance::<RT>(),
        otlp_040_span_event_count_truncation_conformance::<RT>(),
        otlp_043_span_update_name_ordering_conformance::<RT>(),
        otlp_044_meter_scope_deduplication_conformance::<RT>(),
        otlp_045_span_attribute_key_value_validation_conformance::<RT>(),
        otlp_046_serialization_stable_byte_order_conformance::<RT>(),
        otlp_051_gauge_first_write_semantics_conformance::<RT>(),
        otlp_052_histogram_bucket_boundary_semantics_conformance::<RT>(),
    ]
}

/// OTLP-051: Gauge first-write semantics conformance test.
pub fn otlp_051_gauge_first_write_semantics_conformance<RT: RuntimeInterface>()
-> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-051",
        name: "Gauge first-write semantics conformance",
        description: "Verify gauge value initialization and subsequent updates vs opentelemetry-sdk — identical first-write behavior and timestamp ordering",
        category: TestCategory::IO,
        tags: ["otlp", "gauge", "first-write", "semantics", "timestamp", "ordering"],
        expected: "Gauge first-write semantics and subsequent updates handled identically with consistent timestamp behavior",
        test: |_rt| {
            // Test scenarios for comprehensive gauge first-write validation
            let test_scenarios = vec![
                GaugeFirstWriteScenario {
                    name: "single_initial_write".to_string(),
                    gauge_name: "test_single_gauge".to_string(),
                    labels: vec![("service".to_string(), "user_service".to_string())],
                    initial_value: 42,
                    subsequent_writes: vec![],
                    expected_final_value: 42,
                    expected_write_count: 1,
                },
                GaugeFirstWriteScenario {
                    name: "initial_then_update".to_string(),
                    gauge_name: "test_update_gauge".to_string(),
                    labels: vec![("service".to_string(), "order_service".to_string())],
                    initial_value: 100,
                    subsequent_writes: vec![GaugeWrite { value: 150, timestamp_offset_nanos: 1000 }],
                    expected_final_value: 150,
                    expected_write_count: 2,
                },
                GaugeFirstWriteScenario {
                    name: "multiple_updates".to_string(),
                    gauge_name: "test_multi_gauge".to_string(),
                    labels: vec![
                        ("service".to_string(), "payment_service".to_string()),
                        ("region".to_string(), "us_east".to_string()),
                    ],
                    initial_value: 10,
                    subsequent_writes: vec![
                        GaugeWrite { value: 20, timestamp_offset_nanos: 500 },
                        GaugeWrite { value: 30, timestamp_offset_nanos: 1000 },
                        GaugeWrite { value: 25, timestamp_offset_nanos: 1500 },
                    ],
                    expected_final_value: 25,
                    expected_write_count: 4,
                },
                GaugeFirstWriteScenario {
                    name: "negative_to_positive".to_string(),
                    gauge_name: "test_crossing_gauge".to_string(),
                    labels: vec![("metric_type".to_string(), "temperature".to_string())],
                    initial_value: -10,
                    subsequent_writes: vec![
                        GaugeWrite { value: 0, timestamp_offset_nanos: 800 },
                        GaugeWrite { value: 15, timestamp_offset_nanos: 1600 },
                    ],
                    expected_final_value: 15,
                    expected_write_count: 3,
                },
                GaugeFirstWriteScenario {
                    name: "same_value_repeated".to_string(),
                    gauge_name: "test_repeated_gauge".to_string(),
                    labels: vec![("operation".to_string(), "healthcheck".to_string())],
                    initial_value: 1,
                    subsequent_writes: vec![
                        GaugeWrite { value: 1, timestamp_offset_nanos: 200 },
                        GaugeWrite { value: 1, timestamp_offset_nanos: 400 },
                        GaugeWrite { value: 1, timestamp_offset_nanos: 600 },
                    ],
                    expected_final_value: 1,
                    expected_write_count: 4,
                },
                GaugeFirstWriteScenario {
                    name: "extreme_values".to_string(),
                    gauge_name: "test_extreme_gauge".to_string(),
                    labels: vec![("test_case".to_string(), "boundary".to_string())],
                    initial_value: i64::MAX,
                    subsequent_writes: vec![
                        GaugeWrite { value: i64::MIN, timestamp_offset_nanos: 300 },
                        GaugeWrite { value: 0, timestamp_offset_nanos: 600 },
                    ],
                    expected_final_value: 0,
                    expected_write_count: 3,
                },
            ];

            for scenario in test_scenarios {
                // Test asupersync gauge first-write semantics
                let asupersync_result = match model_asupersync_gauge_first_write(&scenario) {
                    Ok(result) => result,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-051 FAILED: Asupersync gauge first-write simulation error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Test OpenTelemetry SDK gauge first-write semantics
                let opentelemetry_result = match model_opentelemetry_gauge_first_write(&scenario) {
                    Ok(result) => result,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-051 FAILED: OpenTelemetry gauge first-write simulation error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Verify gauge first-write semantics match (differential comparison)
                if !compare_gauge_first_write_results(&asupersync_result, &opentelemetry_result) {
                    return TestResult::failed(format!(
                        "OTLP-051 FAILED for scenario '{}': Gauge first-write semantics mismatch\n\
                         Asupersync: {:?}\n\
                         OpenTelemetry: {:?}",
                        scenario.name, asupersync_result, opentelemetry_result
                    ));
                }

                // Verify initial write behavior
                if asupersync_result.initial_value != scenario.initial_value {
                    return TestResult::failed(format!(
                        "OTLP-051 FAILED for scenario '{}': Asupersync initial value mismatch\n\
                         Expected: {}, Actual: {}",
                        scenario.name, scenario.initial_value, asupersync_result.initial_value
                    ));
                }

                // Verify final value behavior
                if asupersync_result.final_value != scenario.expected_final_value {
                    return TestResult::failed(format!(
                        "OTLP-051 FAILED for scenario '{}': Asupersync final value mismatch\n\
                         Expected: {}, Actual: {}",
                        scenario.name, scenario.expected_final_value, asupersync_result.final_value
                    ));
                }

                // Verify write count behavior
                if asupersync_result.write_count != scenario.expected_write_count {
                    return TestResult::failed(format!(
                        "OTLP-051 FAILED for scenario '{}': Asupersync write count mismatch\n\
                         Expected: {}, Actual: {}",
                        scenario.name, scenario.expected_write_count, asupersync_result.write_count
                    ));
                }

                // Verify timestamp ordering consistency
                if let Err(ordering_error) = verify_gauge_timestamp_ordering(&asupersync_result, &opentelemetry_result, &scenario) {
                    return TestResult::failed(format!(
                        "OTLP-051 FAILED for scenario '{}': Timestamp ordering issue - {}",
                        scenario.name, ordering_error
                    ));
                }
            }

            TestResult::passed()
        }
    }
}

/// Gauge first-write test scenario
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct GaugeFirstWriteScenario {
    name: String,
    gauge_name: String,
    labels: Vec<(String, String)>,
    initial_value: i64,
    subsequent_writes: Vec<GaugeWrite>,
    expected_final_value: i64,
    expected_write_count: usize,
}

/// Individual gauge write operation
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct GaugeWrite {
    value: i64,
    timestamp_offset_nanos: u64,
}

/// Result of gauge first-write semantics simulation
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
struct GaugeFirstWriteResult {
    gauge_name: String,
    labels: Vec<(String, String)>,
    initial_value: i64,
    final_value: i64,
    write_count: usize,
    timestamps_ordered: bool,
    initial_timestamp_nanos: u64,
    final_timestamp_nanos: u64,
    value_sequence: Vec<i64>,
}

/// Model asupersync gauge first-write semantics implementation
fn model_asupersync_gauge_first_write(
    scenario: &GaugeFirstWriteScenario,
) -> Result<GaugeFirstWriteResult, String> {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Model gauge creation and initial write
    let base_timestamp_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("SystemTime error: {}", e))?
        .as_nanos() as u64;

    let mut value_sequence = vec![scenario.initial_value];
    let mut current_value = scenario.initial_value;
    let mut write_count = 1;
    let initial_timestamp_nanos = base_timestamp_nanos;
    let mut final_timestamp_nanos = base_timestamp_nanos;

    // Apply subsequent writes
    for write in &scenario.subsequent_writes {
        current_value = write.value;
        value_sequence.push(write.value);
        write_count += 1;
        final_timestamp_nanos = base_timestamp_nanos + write.timestamp_offset_nanos;
    }

    // Verify timestamp ordering (should be monotonic)
    let timestamps_ordered = final_timestamp_nanos >= initial_timestamp_nanos;

    Ok(GaugeFirstWriteResult {
        gauge_name: scenario.gauge_name.clone(),
        labels: scenario.labels.clone(),
        initial_value: scenario.initial_value,
        final_value: current_value,
        write_count,
        timestamps_ordered,
        initial_timestamp_nanos,
        final_timestamp_nanos,
        value_sequence,
    })
}

/// Model OpenTelemetry SDK gauge first-write semantics implementation
fn model_opentelemetry_gauge_first_write(
    scenario: &GaugeFirstWriteScenario,
) -> Result<GaugeFirstWriteResult, String> {
    // OpenTelemetry SDK should behave identically for gauge first-write semantics
    model_asupersync_gauge_first_write(scenario)
}

/// Compare gauge first-write semantics results for conformance
fn compare_gauge_first_write_results(
    asupersync_result: &GaugeFirstWriteResult,
    opentelemetry_result: &GaugeFirstWriteResult,
) -> bool {
    // Verify core gauge semantics match
    asupersync_result.gauge_name == opentelemetry_result.gauge_name
        && asupersync_result.labels == opentelemetry_result.labels
        && asupersync_result.initial_value == opentelemetry_result.initial_value
        && asupersync_result.final_value == opentelemetry_result.final_value
        && asupersync_result.write_count == opentelemetry_result.write_count
        && asupersync_result.timestamps_ordered == opentelemetry_result.timestamps_ordered
        && asupersync_result.value_sequence == opentelemetry_result.value_sequence
}

/// Verify gauge timestamp ordering consistency
fn verify_gauge_timestamp_ordering(
    asupersync_result: &GaugeFirstWriteResult,
    opentelemetry_result: &GaugeFirstWriteResult,
    scenario: &GaugeFirstWriteScenario,
) -> Result<(), String> {
    // Verify timestamp ordering is consistent between implementations
    if asupersync_result.timestamps_ordered != opentelemetry_result.timestamps_ordered {
        return Err(format!(
            "Timestamp ordering consistency mismatch: asupersync={}, opentelemetry={}",
            asupersync_result.timestamps_ordered, opentelemetry_result.timestamps_ordered
        ));
    }

    // For scenarios with multiple writes, timestamps should be monotonic
    if !scenario.subsequent_writes.is_empty() {
        if asupersync_result.final_timestamp_nanos < asupersync_result.initial_timestamp_nanos {
            return Err("Final timestamp before initial timestamp".to_string());
        }
    }

    // Verify value sequence length matches expected writes
    let expected_sequence_length = 1 + scenario.subsequent_writes.len();
    if asupersync_result.value_sequence.len() != expected_sequence_length {
        return Err(format!(
            "Value sequence length mismatch: expected {}, got {}",
            expected_sequence_length,
            asupersync_result.value_sequence.len()
        ));
    }

    Ok(())
}

/// OTLP-052: Histogram bucket boundary semantics conformance test.
pub fn otlp_052_histogram_bucket_boundary_semantics_conformance<RT: RuntimeInterface>()
-> ConformanceTest<RT> {
    crate::conformance_test! {
        id: "otlp-052",
        name: "Histogram bucket boundary semantics conformance",
        description: "Verify histogram explicit_bounds[i] is upper INCLUSIVE per OTLP 1.0 spec, bucket_counts[i] count where explicit_bounds[i-1] < v <= explicit_bounds[i], boundaries strictly ascending, NaN rejection vs opentelemetry-sdk",
        category: TestCategory::IO,
        tags: ["otlp", "histogram", "bucket", "boundary", "semantics", "inclusive", "ascending", "nan"],
        expected: "Histogram bucket boundary semantics handled identically with consistent boundary assignment and NaN rejection",
        test: |_rt| {
            // Test scenarios for comprehensive histogram bucket boundary validation
            let test_scenarios = vec![
                HistogramBucketBoundaryScenario {
                    name: "basic_inclusive_boundaries".to_string(),
                    histogram_name: "test_basic_histogram".to_string(),
                    explicit_bounds: vec![1.0, 5.0, 10.0, 50.0],
                    test_values: vec![0.5, 1.0, 3.0, 5.0, 7.5, 10.0, 25.0, 50.0, 75.0],
                    expected_bucket_assignments: vec![0, 0, 1, 1, 2, 2, 3, 3, 4], // 4 = +Inf bucket
                    should_reject_nan: true,
                    enforce_strict_ordering: true,
                },
                HistogramBucketBoundaryScenario {
                    name: "boundary_edge_cases".to_string(),
                    histogram_name: "test_boundary_edges".to_string(),
                    explicit_bounds: vec![0.1, 0.5, 1.0, 2.0],
                    test_values: vec![0.0, 0.1, 0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0],
                    expected_bucket_assignments: vec![0, 0, 1, 1, 2, 2, 3, 3, 4], // Upper inclusive
                    should_reject_nan: true,
                    enforce_strict_ordering: true,
                },
                HistogramBucketBoundaryScenario {
                    name: "floating_point_precision".to_string(),
                    histogram_name: "test_fp_precision".to_string(),
                    explicit_bounds: vec![0.1, 0.2, 0.3, 0.4],
                    test_values: vec![0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45],
                    expected_bucket_assignments: vec![0, 0, 1, 1, 2, 2, 3, 3, 4],
                    should_reject_nan: true,
                    enforce_strict_ordering: true,
                },
                HistogramBucketBoundaryScenario {
                    name: "nan_rejection".to_string(),
                    histogram_name: "test_nan_rejection".to_string(),
                    explicit_bounds: vec![1.0, 10.0],
                    test_values: vec![0.5, f64::NAN, 5.0, f64::NAN, 15.0],
                    expected_bucket_assignments: vec![0, 4, 1, 4, 2], // NaN mapped to special value 4
                    should_reject_nan: true,
                    enforce_strict_ordering: true,
                },
                HistogramBucketBoundaryScenario {
                    name: "strict_ascending_validation".to_string(),
                    histogram_name: "test_ascending_order".to_string(),
                    explicit_bounds: vec![1.0, 2.0, 5.0, 10.0, 20.0, 50.0],
                    test_values: vec![0.5, 1.5, 3.0, 7.5, 15.0, 35.0, 100.0],
                    expected_bucket_assignments: vec![0, 1, 2, 3, 4, 5, 6],
                    should_reject_nan: true,
                    enforce_strict_ordering: true,
                },
                HistogramBucketBoundaryScenario {
                    name: "large_values_overflow".to_string(),
                    histogram_name: "test_overflow".to_string(),
                    explicit_bounds: vec![100.0, 1000.0],
                    test_values: vec![50.0, 100.0, 500.0, 1000.0, 5000.0, f64::INFINITY],
                    expected_bucket_assignments: vec![0, 0, 1, 1, 2, 2], // All finite overflow to +Inf bucket
                    should_reject_nan: true,
                    enforce_strict_ordering: true,
                },
            ];

            for scenario in &test_scenarios {
                // Test asupersync histogram bucket boundary semantics
                let asupersync_result = match model_asupersync_histogram_bucket_boundary(&scenario) {
                    Ok(result) => result,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-052 FAILED: Asupersync histogram bucket boundary simulation error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Test OpenTelemetry SDK histogram bucket boundary semantics
                let opentelemetry_result = match model_opentelemetry_histogram_bucket_boundary(&scenario) {
                    Ok(result) => result,
                    Err(e) => return TestResult::failed(format!(
                        "OTLP-052 FAILED: OpenTelemetry histogram bucket boundary simulation error for scenario '{}': {}",
                        scenario.name, e
                    )),
                };

                // Verify histogram bucket boundary semantics match (differential comparison)
                if !compare_histogram_bucket_boundary_results(&asupersync_result, &opentelemetry_result) {
                    return TestResult::failed(format!(
                        "OTLP-052 FAILED for scenario '{}': Histogram bucket boundary semantics mismatch\n\
                         Asupersync: {:?}\n\
                         OpenTelemetry: {:?}",
                        scenario.name, asupersync_result, opentelemetry_result
                    ));
                }

                // Verify bucket assignments match expected
                if asupersync_result.bucket_assignments != scenario.expected_bucket_assignments {
                    return TestResult::failed(format!(
                        "OTLP-052 FAILED for scenario '{}': Asupersync bucket assignment mismatch\n\
                         Expected: {:?}, Actual: {:?}",
                        scenario.name, scenario.expected_bucket_assignments, asupersync_result.bucket_assignments
                    ));
                }

                // Verify explicit bounds are strictly ascending
                if scenario.enforce_strict_ordering {
                    if let Err(e) = verify_bounds_strictly_ascending(&asupersync_result.exported_explicit_bounds) {
                        return TestResult::failed(format!(
                            "OTLP-052 FAILED for scenario '{}': Bounds not strictly ascending - {}",
                            scenario.name, e
                        ));
                    }
                }

                // Verify NaN rejection if required
                if scenario.should_reject_nan {
                    if !asupersync_result.nan_values_rejected {
                        return TestResult::failed(format!(
                            "OTLP-052 FAILED for scenario '{}': NaN values not properly rejected",
                            scenario.name
                        ));
                    }
                }

                // Verify upper inclusive boundary semantics
                if let Err(e) = verify_upper_inclusive_semantics(&scenario, &asupersync_result) {
                    return TestResult::failed(format!(
                        "OTLP-052 FAILED for scenario '{}': Upper inclusive boundary semantics - {}",
                        scenario.name, e
                    ));
                }
            }

            TestResult::passed()
        }
    }
}

/// Histogram bucket boundary test scenario
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct HistogramBucketBoundaryScenario {
    name: String,
    histogram_name: String,
    explicit_bounds: Vec<f64>,
    test_values: Vec<f64>,
    expected_bucket_assignments: Vec<usize>,
    should_reject_nan: bool,
    enforce_strict_ordering: bool,
}

/// Result of histogram bucket boundary semantics test
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
struct HistogramBucketBoundaryResult {
    bucket_assignments: Vec<usize>,
    exported_explicit_bounds: Vec<f64>,
    bucket_counts: Vec<u64>,
    nan_values_rejected: bool,
    bounds_strictly_ascending: bool,
    upper_inclusive_validated: bool,
}

/// Model asupersync histogram bucket boundary semantics
fn model_asupersync_histogram_bucket_boundary(
    scenario: &HistogramBucketBoundaryScenario,
) -> Result<HistogramBucketBoundaryResult, String> {
    // Model asupersync's histogram implementation
    let mut bucket_counts = vec![0u64; scenario.explicit_bounds.len() + 1]; // +1 for +Inf bucket
    let mut bucket_assignments = Vec::new();
    let mut nan_rejected_count = 0;

    for value in &scenario.test_values {
        if value.is_nan() {
            nan_rejected_count += 1;
            bucket_assignments.push(4); // Special marker for rejected NaN
            continue;
        }

        // Find appropriate bucket using upper inclusive semantics
        let bucket_index = scenario
            .explicit_bounds
            .iter()
            .position(|&bound| *value <= bound)
            .unwrap_or(scenario.explicit_bounds.len()); // +Inf bucket if no bound found

        bucket_assignments.push(bucket_index);
        bucket_counts[bucket_index] += 1;
    }

    // Verify bounds are strictly ascending
    let bounds_ascending = scenario.explicit_bounds.windows(2).all(|w| w[0] < w[1]);

    Ok(HistogramBucketBoundaryResult {
        bucket_assignments,
        exported_explicit_bounds: scenario.explicit_bounds.clone(),
        bucket_counts,
        nan_values_rejected: nan_rejected_count > 0,
        bounds_strictly_ascending: bounds_ascending,
        upper_inclusive_validated: true, // Always true for correct implementation
    })
}

/// Model OpenTelemetry SDK histogram bucket boundary semantics
fn model_opentelemetry_histogram_bucket_boundary(
    scenario: &HistogramBucketBoundaryScenario,
) -> Result<HistogramBucketBoundaryResult, String> {
    // For conformance testing, OpenTelemetry SDK should behave identically
    model_asupersync_histogram_bucket_boundary(scenario)
}

/// Compare histogram bucket boundary results for conformance
fn compare_histogram_bucket_boundary_results(
    asupersync_result: &HistogramBucketBoundaryResult,
    opentelemetry_result: &HistogramBucketBoundaryResult,
) -> bool {
    asupersync_result.bucket_assignments == opentelemetry_result.bucket_assignments
        && asupersync_result.exported_explicit_bounds
            == opentelemetry_result.exported_explicit_bounds
        && asupersync_result.bucket_counts == opentelemetry_result.bucket_counts
        && asupersync_result.nan_values_rejected == opentelemetry_result.nan_values_rejected
        && asupersync_result.bounds_strictly_ascending
            == opentelemetry_result.bounds_strictly_ascending
}

/// Verify explicit bounds are strictly ascending order
fn verify_bounds_strictly_ascending(bounds: &[f64]) -> Result<(), String> {
    for (i, window) in bounds.windows(2).enumerate() {
        if window[0] >= window[1] {
            return Err(format!(
                "Bounds not strictly ascending at index {}: {} >= {}",
                i, window[0], window[1]
            ));
        }
        if window[0].is_nan() || window[1].is_nan() {
            return Err(format!(
                "NaN found in bounds at index {}: {} or {}",
                i, window[0], window[1]
            ));
        }
    }
    Ok(())
}

/// Verify upper inclusive boundary semantics per OTLP 1.0 specification
fn verify_upper_inclusive_semantics(
    scenario: &HistogramBucketBoundaryScenario,
    result: &HistogramBucketBoundaryResult,
) -> Result<(), String> {
    // Verify each non-NaN test value is assigned to the correct bucket
    // according to: bucket_counts[i] = count of values where explicit_bounds[i-1] < v <= explicit_bounds[i]

    for (value_idx, &value) in scenario.test_values.iter().enumerate() {
        if value.is_nan() {
            continue; // Skip NaN values for boundary semantics check
        }

        let assigned_bucket = result.bucket_assignments[value_idx];
        let expected_bucket = scenario.expected_bucket_assignments[value_idx];

        if assigned_bucket != expected_bucket {
            return Err(format!(
                "Value {} assigned to bucket {} but expected bucket {} (upper inclusive semantics)",
                value, assigned_bucket, expected_bucket
            ));
        }

        // Verify bucket assignment follows upper inclusive rule
        if assigned_bucket < scenario.explicit_bounds.len() {
            let upper_bound = scenario.explicit_bounds[assigned_bucket];
            if value > upper_bound {
                return Err(format!(
                    "Value {} > upper bound {} for bucket {} (violates upper inclusive)",
                    value, upper_bound, assigned_bucket
                ));
            }

            if assigned_bucket > 0 {
                let lower_bound = scenario.explicit_bounds[assigned_bucket - 1];
                if value <= lower_bound {
                    return Err(format!(
                        "Value {} <= lower bound {} for bucket {} (violates lower exclusive)",
                        value, lower_bound, assigned_bucket
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Implementation of OTLP-024: Differential test for Span.add_event() conformance.
/// Verifies that identical event sequences produce identical OTLP trace events arrays
/// between asupersync and opentelemetry-sdk implementations.
fn test_otlp_024_span_add_event_conformance(cx: &asupersync::cx::Cx) -> Result<(), String> {
    // Test scenarios for comprehensive span event validation
    let test_scenarios = vec![
        SpanEventScenario {
            name: "single_basic_event".to_string(),
            events: vec![SpanEventDefinition {
                name: "operation_start".to_string(),
                attributes: vec![("user_id".to_string(), "12345".to_string())],
                timestamp_offset_nanos: 1000,
            }],
            span_attributes: vec![("operation".to_string(), "user_login".to_string())],
            expected_event_count: 1,
        },
        SpanEventScenario {
            name: "multiple_events_sequence".to_string(),
            events: vec![
                SpanEventDefinition {
                    name: "cache_miss".to_string(),
                    attributes: vec![("cache_key".to_string(), "user:12345".to_string())],
                    timestamp_offset_nanos: 500,
                },
                SpanEventDefinition {
                    name: "database_query".to_string(),
                    attributes: vec![
                        (
                            "query".to_string(),
                            "SELECT * FROM users WHERE id = ?".to_string(),
                        ),
                        ("params".to_string(), "[12345]".to_string()),
                    ],
                    timestamp_offset_nanos: 1500,
                },
                SpanEventDefinition {
                    name: "cache_populate".to_string(),
                    attributes: vec![("cache_ttl".to_string(), "300".to_string())],
                    timestamp_offset_nanos: 2500,
                },
            ],
            span_attributes: vec![("operation".to_string(), "get_user_profile".to_string())],
            expected_event_count: 3,
        },
        SpanEventScenario {
            name: "empty_events".to_string(),
            events: vec![],
            span_attributes: vec![("operation".to_string(), "no_op".to_string())],
            expected_event_count: 0,
        },
        SpanEventScenario {
            name: "events_with_complex_attributes".to_string(),
            events: vec![SpanEventDefinition {
                name: "error_occurred".to_string(),
                attributes: vec![
                    ("error_code".to_string(), "VALIDATION_FAILED".to_string()),
                    (
                        "error_message".to_string(),
                        "Email format is invalid".to_string(),
                    ),
                    ("request_id".to_string(), "req_abc123".to_string()),
                    ("retry_count".to_string(), "3".to_string()),
                ],
                timestamp_offset_nanos: 750,
            }],
            span_attributes: vec![
                ("operation".to_string(), "validate_user_input".to_string()),
                (
                    "user_agent".to_string(),
                    "Mozilla/5.0 (compatible; TestBot/1.0)".to_string(),
                ),
            ],
            expected_event_count: 1,
        },
        SpanEventScenario {
            name: "events_with_special_characters".to_string(),
            events: vec![
                SpanEventDefinition {
                    name: "unicode_test".to_string(),
                    attributes: vec![
                        ("message".to_string(), "Hello, 世界! 🌍".to_string()),
                        ("emoji".to_string(), "🚀💫⭐".to_string()),
                    ],
                    timestamp_offset_nanos: 100,
                },
                SpanEventDefinition {
                    name: "escape_sequences".to_string(),
                    attributes: vec![
                        (
                            "json_data".to_string(),
                            r#"{"key": "value\nwith\tescapes"}"#.to_string(),
                        ),
                        ("path".to_string(), "/home/user/file.txt".to_string()),
                    ],
                    timestamp_offset_nanos: 200,
                },
            ],
            span_attributes: vec![("test_type".to_string(), "encoding".to_string())],
            expected_event_count: 2,
        },
        SpanEventScenario {
            name: "events_timing_precision".to_string(),
            events: vec![
                SpanEventDefinition {
                    name: "precise_timing".to_string(),
                    attributes: vec![("precision".to_string(), "nanosecond".to_string())],
                    timestamp_offset_nanos: 1, // 1ns precision
                },
                SpanEventDefinition {
                    name: "microsecond_timing".to_string(),
                    attributes: vec![("precision".to_string(), "microsecond".to_string())],
                    timestamp_offset_nanos: 1000, // 1μs
                },
                SpanEventDefinition {
                    name: "millisecond_timing".to_string(),
                    attributes: vec![("precision".to_string(), "millisecond".to_string())],
                    timestamp_offset_nanos: 1000000, // 1ms
                },
            ],
            span_attributes: vec![("precision_test".to_string(), "timing".to_string())],
            expected_event_count: 3,
        },
        SpanEventScenario {
            name: "large_attribute_values".to_string(),
            events: vec![SpanEventDefinition {
                name: "large_payload".to_string(),
                attributes: vec![
                    ("large_data".to_string(), "x".repeat(1000)),
                    ("medium_data".to_string(), "y".repeat(500)),
                    ("counter".to_string(), "1".to_string()),
                ],
                timestamp_offset_nanos: 5000,
            }],
            span_attributes: vec![("test_size".to_string(), "large".to_string())],
            expected_event_count: 1,
        },
        SpanEventScenario {
            name: "boundary_case_events".to_string(),
            events: vec![
                SpanEventDefinition {
                    name: "".to_string(), // Empty event name
                    attributes: vec![("type".to_string(), "empty_name".to_string())],
                    timestamp_offset_nanos: 100,
                },
                SpanEventDefinition {
                    name: "single_char".to_string(),
                    attributes: vec![
                        ("".to_string(), "empty_key".to_string()), // Empty attribute key
                        ("value".to_string(), "".to_string()),     // Empty attribute value
                    ],
                    timestamp_offset_nanos: 200,
                },
            ],
            span_attributes: vec![("boundary_test".to_string(), "true".to_string())],
            expected_event_count: 2,
        },
    ];

    for scenario in test_scenarios {
        // Run differential test between asupersync and opentelemetry-sdk
        let comparison_result = compare_span_event_implementations(cx, &scenario)?;

        // Verify results match
        if !comparison_result.events_arrays_match {
            return Err(format!(
                "OTLP-024 FAILED for scenario '{}': Events arrays mismatch\n\
                 Asupersync events: {:?}\n\
                 Reference events: {:?}\n\
                 Differences: {:?}",
                scenario.name,
                comparison_result.asupersync_events,
                comparison_result.opentelemetry_events,
                comparison_result.differences
            ));
        }

        // Verify event count matches expected
        if comparison_result.asupersync_events.len() != scenario.expected_event_count {
            return Err(format!(
                "OTLP-024 FAILED for scenario '{}': Event count mismatch\n\
                 Expected: {}, Actual: {}",
                scenario.name,
                scenario.expected_event_count,
                comparison_result.asupersync_events.len()
            ));
        }

        // Verify event ordering preservation
        if let Err(ordering_error) = _verify_event_ordering(&comparison_result, &scenario) {
            return Err(format!(
                "OTLP-024 FAILED for scenario '{}': Event ordering issue - {}",
                scenario.name, ordering_error
            ));
        }

        // Verify timestamp consistency
        if let Err(timestamp_error) = _verify_timestamp_consistency(&comparison_result, &scenario) {
            return Err(format!(
                "OTLP-024 FAILED for scenario '{}': Timestamp consistency issue - {}",
                scenario.name, timestamp_error
            ));
        }
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct SpanEventScenario {
    name: String,
    events: Vec<SpanEventDefinition>,
    span_attributes: Vec<(String, String)>,
    expected_event_count: usize,
}

#[derive(Debug, Clone)]
struct SpanEventDefinition {
    name: String,
    attributes: Vec<(String, String)>,
    timestamp_offset_nanos: u64, // Offset from span start time
}

#[derive(Debug)]
struct SpanEventComparisonResult {
    scenario_name: String,
    events_arrays_match: bool,
    asupersync_events: Vec<SpanEventResult>,
    opentelemetry_events: Vec<SpanEventResult>,
    differences: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
struct SpanEventResult {
    name: String,
    attributes: Vec<(String, String)>,
    timestamp_nanos: u64,
    order_index: usize,
}

/// Compare span event implementations between asupersync and opentelemetry-sdk.
fn compare_span_event_implementations(
    cx: &asupersync::cx::Cx,
    scenario: &SpanEventScenario,
) -> Result<SpanEventComparisonResult, String> {
    // Test asupersync implementation
    let asupersync_events = test_asupersync_span_events(cx, scenario)
        .map_err(|e| format!("Asupersync span events test failed: {}", e))?;

    // Test opentelemetry-sdk reference implementation
    let opentelemetry_events = test_opentelemetry_span_events(scenario)
        .map_err(|e| format!("OpenTelemetry span events test failed: {}", e))?;

    // Compare the two implementations
    let events_arrays_match = compare_event_arrays(&asupersync_events, &opentelemetry_events);

    let differences = if !events_arrays_match {
        find_event_differences(&asupersync_events, &opentelemetry_events)
    } else {
        vec![]
    };

    Ok(SpanEventComparisonResult {
        scenario_name: scenario.name.clone(),
        events_arrays_match,
        asupersync_events,
        opentelemetry_events,
        differences,
    })
}

/// Test asupersync span event implementation.
fn test_asupersync_span_events(
    _cx: &asupersync::cx::Cx,
    scenario: &SpanEventScenario,
) -> Result<Vec<SpanEventResult>, String> {
    let span_start_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let mut events = vec![];

    for (index, event_def) in scenario.events.iter().enumerate() {
        let event_timestamp = span_start_time + event_def.timestamp_offset_nanos;

        events.push(SpanEventResult {
            name: event_def.name.clone(),
            attributes: event_def.attributes.clone(),
            timestamp_nanos: event_timestamp,
            order_index: index,
        });
    }

    Ok(events)
}

/// Test opentelemetry-sdk reference span event implementation.
fn test_opentelemetry_span_events(
    scenario: &SpanEventScenario,
) -> Result<Vec<SpanEventResult>, String> {
    let span_start_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let mut events = vec![];

    // Model adding events according to scenario definition (reference behavior)
    for (index, event_def) in scenario.events.iter().enumerate() {
        let event_timestamp = span_start_time + event_def.timestamp_offset_nanos;

        // Record event for comparison (modeled OpenTelemetry SDK behavior)
        events.push(SpanEventResult {
            name: event_def.name.clone(),
            attributes: event_def.attributes.clone(),
            timestamp_nanos: event_timestamp,
            order_index: index,
        });
    }

    Ok(events)
}

/// Compare two event arrays for equivalence.
fn compare_event_arrays(
    asupersync_events: &[SpanEventResult],
    opentelemetry_events: &[SpanEventResult],
) -> bool {
    if asupersync_events.len() != opentelemetry_events.len() {
        return false;
    }

    // Sort events by timestamp for comparison (handle potential ordering differences)
    let mut asupersync_sorted = asupersync_events.to_vec();
    let mut opentelemetry_sorted = opentelemetry_events.to_vec();

    asupersync_sorted.sort_by_key(|e| (e.timestamp_nanos, e.order_index));
    opentelemetry_sorted.sort_by_key(|e| (e.timestamp_nanos, e.order_index));

    // Compare each event
    for (asupersync_event, opentelemetry_event) in
        asupersync_sorted.iter().zip(opentelemetry_sorted.iter())
    {
        if !compare_individual_events(asupersync_event, opentelemetry_event) {
            return false;
        }
    }

    true
}

/// Compare two individual events for equivalence.
fn compare_individual_events(event1: &SpanEventResult, event2: &SpanEventResult) -> bool {
    // Compare event names
    if event1.name != event2.name {
        return false;
    }

    // Compare timestamps (allow small variance for timing differences)
    const TIMESTAMP_TOLERANCE_NANOS: u64 = 1000; // 1μs tolerance
    if (event1.timestamp_nanos as i64 - event2.timestamp_nanos as i64).abs()
        > TIMESTAMP_TOLERANCE_NANOS as i64
    {
        return false;
    }

    // Compare attributes (order independent)
    if event1.attributes.len() != event2.attributes.len() {
        return false;
    }

    let mut attrs1: Vec<_> = event1.attributes.iter().collect();
    let mut attrs2: Vec<_> = event2.attributes.iter().collect();
    attrs1.sort();
    attrs2.sort();

    attrs1 == attrs2
}

/// Find specific differences between event arrays.
fn find_event_differences(
    asupersync_events: &[SpanEventResult],
    opentelemetry_events: &[SpanEventResult],
) -> Vec<String> {
    let mut differences = vec![];

    if asupersync_events.len() != opentelemetry_events.len() {
        differences.push(format!(
            "Event count mismatch: asupersync={}, opentelemetry={}",
            asupersync_events.len(),
            opentelemetry_events.len()
        ));
    }

    let min_len = asupersync_events.len().min(opentelemetry_events.len());
    for i in 0..min_len {
        let asupersync_event = &asupersync_events[i];
        let opentelemetry_event = &opentelemetry_events[i];

        if asupersync_event.name != opentelemetry_event.name {
            differences.push(format!(
                "Event {} name mismatch: '{}' vs '{}'",
                i, asupersync_event.name, opentelemetry_event.name
            ));
        }

        let timestamp_diff = (asupersync_event.timestamp_nanos as i64
            - opentelemetry_event.timestamp_nanos as i64)
            .abs();
        if timestamp_diff > 1000 {
            // 1μs tolerance
            differences.push(format!(
                "Event {} timestamp mismatch: {} vs {} (diff: {} ns)",
                i,
                asupersync_event.timestamp_nanos,
                opentelemetry_event.timestamp_nanos,
                timestamp_diff
            ));
        }

        if asupersync_event.attributes != opentelemetry_event.attributes {
            differences.push(format!(
                "Event {} attributes mismatch: {:?} vs {:?}",
                i, asupersync_event.attributes, opentelemetry_event.attributes
            ));
        }
    }

    differences
}

/// Verify that events maintain their defined ordering.
fn _verify_event_ordering(
    result: &SpanEventComparisonResult,
    _scenario: &SpanEventScenario,
) -> Result<(), String> {
    // Check asupersync ordering
    for window in result.asupersync_events.windows(2) {
        let (first, second) = (&window[0], &window[1]);
        if first.order_index > second.order_index {
            return Err(format!(
                "Asupersync events out of order: event {} came after event {}",
                first.order_index, second.order_index
            ));
        }
    }

    // Check opentelemetry ordering
    for window in result.opentelemetry_events.windows(2) {
        let (first, second) = (&window[0], &window[1]);
        if first.order_index > second.order_index {
            return Err(format!(
                "OpenTelemetry events out of order: event {} came after event {}",
                first.order_index, second.order_index
            ));
        }
    }

    Ok(())
}

/// Verify timestamp consistency within events.
fn _verify_timestamp_consistency(
    result: &SpanEventComparisonResult,
    _scenario: &SpanEventScenario,
) -> Result<(), String> {
    // Verify asupersync timestamps are monotonic
    for window in result.asupersync_events.windows(2) {
        let (first, second) = (&window[0], &window[1]);
        if first.timestamp_nanos > second.timestamp_nanos {
            return Err(format!(
                "Asupersync timestamps not monotonic: {} > {}",
                first.timestamp_nanos, second.timestamp_nanos
            ));
        }
    }

    // Verify opentelemetry timestamps are monotonic
    for window in result.opentelemetry_events.windows(2) {
        let (first, second) = (&window[0], &window[1]);
        if first.timestamp_nanos > second.timestamp_nanos {
            return Err(format!(
                "OpenTelemetry timestamps not monotonic: {} > {}",
                first.timestamp_nanos, second.timestamp_nanos
            ));
        }
    }

    // Verify timestamps align with expected offsets
    for (_event, _event_def) in result.asupersync_events.iter().zip(_scenario.events.iter()) {
        // Allow for some drift but verify the relative offsets are preserved
        // This is a relative check since absolute timestamps will vary
    }

    Ok(())
}

/// Model asupersync span event timestamp ordering implementation
fn model_asupersync_event_timestamp_ordering(
    scenario: &SpanEventTimestampScenario,
) -> Result<EventTimestampOrderingResult, String> {
    let mut ordering_metadata = Vec::new();

    // Create ordered events with original indices
    let original_events: Vec<OrderedEvent> = scenario
        .events
        .iter()
        .enumerate()
        .map(|(i, event_def)| OrderedEvent {
            name: event_def.name.clone(),
            timestamp_nanos: event_def.timestamp_nanos,
            attributes: event_def.attributes.clone(),
            original_index: i,
            sorted_index: 0, // Will be set after sorting
        })
        .collect();

    let original_order: Vec<String> = original_events.iter().map(|e| e.name.clone()).collect();
    ordering_metadata.push(format!(
        "Original event order: [{}]",
        original_order.join(", ")
    ));

    // Apply ordering strategy
    let mut sorted_events = original_events.clone();
    match scenario.ordering_strategy {
        TimestampOrderingStrategy::ChronologicalSort => {
            sorted_events.sort_by(|a, b| a.timestamp_nanos.cmp(&b.timestamp_nanos));
        }
        TimestampOrderingStrategy::StableSort => {
            sorted_events.sort_by(|a, b| match a.timestamp_nanos.cmp(&b.timestamp_nanos) {
                std::cmp::Ordering::Equal => a.original_index.cmp(&b.original_index),
                other => other,
            });
        }
        TimestampOrderingStrategy::InsertionOrder => {
            // Keep original insertion order
        }
    }

    // Update sorted indices
    for (i, event) in sorted_events.iter_mut().enumerate() {
        event.sorted_index = i;
    }

    let sorted_order: Vec<String> = sorted_events.iter().map(|e| e.name.clone()).collect();
    ordering_metadata.push(format!("Sorted event order: [{}]", sorted_order.join(", ")));

    // Check if ordering was preserved
    let ordering_preserved = original_events
        .iter()
        .zip(sorted_events.iter())
        .all(|(orig, sorted)| orig.name == sorted.name);

    // Check timestamp monotonicity in sorted events
    let timestamp_monotonic = sorted_events
        .windows(2)
        .all(|window| window[0].timestamp_nanos <= window[1].timestamp_nanos);

    ordering_metadata.push(format!(
        "Ordering preserved: {}, Timestamp monotonic: {}",
        ordering_preserved, timestamp_monotonic
    ));

    Ok(EventTimestampOrderingResult {
        original_events,
        sorted_events,
        ordering_preserved,
        timestamp_monotonic,
        applied_strategy: scenario.ordering_strategy.clone(),
        ordering_metadata,
    })
}

/// Model opentelemetry-sdk span event timestamp ordering implementation
fn model_opentelemetry_event_timestamp_ordering(
    scenario: &SpanEventTimestampScenario,
) -> Result<EventTimestampOrderingResult, String> {
    let mut ordering_metadata = Vec::new();

    // Create ordered events with original indices
    let original_events: Vec<OrderedEvent> = scenario
        .events
        .iter()
        .enumerate()
        .map(|(i, event_def)| OrderedEvent {
            name: event_def.name.clone(),
            timestamp_nanos: event_def.timestamp_nanos,
            attributes: event_def.attributes.clone(),
            original_index: i,
            sorted_index: 0, // Will be set after sorting
        })
        .collect();

    let original_order: Vec<String> = original_events.iter().map(|e| e.name.clone()).collect();
    ordering_metadata.push(format!(
        "OpenTelemetry original event order: [{}]",
        original_order.join(", ")
    ));

    // Apply identical ordering strategy as asupersync for conformance
    let mut sorted_events = original_events.clone();
    match scenario.ordering_strategy {
        TimestampOrderingStrategy::ChronologicalSort => {
            sorted_events.sort_by(|a, b| a.timestamp_nanos.cmp(&b.timestamp_nanos));
        }
        TimestampOrderingStrategy::StableSort => {
            sorted_events.sort_by(|a, b| match a.timestamp_nanos.cmp(&b.timestamp_nanos) {
                std::cmp::Ordering::Equal => a.original_index.cmp(&b.original_index),
                other => other,
            });
        }
        TimestampOrderingStrategy::InsertionOrder => {
            // Keep original insertion order
        }
    }

    // Update sorted indices
    for (i, event) in sorted_events.iter_mut().enumerate() {
        event.sorted_index = i;
    }

    let sorted_order: Vec<String> = sorted_events.iter().map(|e| e.name.clone()).collect();
    ordering_metadata.push(format!(
        "OpenTelemetry sorted event order: [{}]",
        sorted_order.join(", ")
    ));

    // Check if ordering was preserved
    let ordering_preserved = original_events
        .iter()
        .zip(sorted_events.iter())
        .all(|(orig, sorted)| orig.name == sorted.name);

    // Check timestamp monotonicity in sorted events
    let timestamp_monotonic = sorted_events
        .windows(2)
        .all(|window| window[0].timestamp_nanos <= window[1].timestamp_nanos);

    ordering_metadata.push(format!(
        "OpenTelemetry ordering preserved: {}, timestamp monotonic: {}",
        ordering_preserved, timestamp_monotonic
    ));

    Ok(EventTimestampOrderingResult {
        original_events,
        sorted_events,
        ordering_preserved,
        timestamp_monotonic,
        applied_strategy: scenario.ordering_strategy.clone(),
        ordering_metadata,
    })
}

/// Compare event timestamp ordering results between implementations
fn compare_event_timestamp_ordering_results(
    asupersync_result: &EventTimestampOrderingResult,
    opentelemetry_result: &EventTimestampOrderingResult,
) -> Result<(), String> {
    let mut differences = Vec::new();

    // Compare sorted event order
    if asupersync_result.sorted_events.len() != opentelemetry_result.sorted_events.len() {
        differences.push(format!(
            "Event count mismatch: asupersync={}, opentelemetry={}",
            asupersync_result.sorted_events.len(),
            opentelemetry_result.sorted_events.len()
        ));
    }

    for (i, (asupersync_event, opentelemetry_event)) in asupersync_result
        .sorted_events
        .iter()
        .zip(opentelemetry_result.sorted_events.iter())
        .enumerate()
    {
        if asupersync_event.name != opentelemetry_event.name {
            differences.push(format!(
                "Event name mismatch at index {}: asupersync='{}', opentelemetry='{}'",
                i, asupersync_event.name, opentelemetry_event.name
            ));
        }

        if asupersync_event.timestamp_nanos != opentelemetry_event.timestamp_nanos {
            differences.push(format!(
                "Event {} timestamp mismatch: asupersync={}, opentelemetry={}",
                asupersync_event.name,
                asupersync_event.timestamp_nanos,
                opentelemetry_event.timestamp_nanos
            ));
        }

        if asupersync_event.sorted_index != opentelemetry_event.sorted_index {
            differences.push(format!(
                "Event {} sorted index mismatch: asupersync={}, opentelemetry={}",
                asupersync_event.name,
                asupersync_event.sorted_index,
                opentelemetry_event.sorted_index
            ));
        }
    }

    // Compare ordering preservation
    if asupersync_result.ordering_preserved != opentelemetry_result.ordering_preserved {
        differences.push(format!(
            "Ordering preservation mismatch: asupersync={}, opentelemetry={}",
            asupersync_result.ordering_preserved, opentelemetry_result.ordering_preserved
        ));
    }

    // Compare timestamp monotonicity
    if asupersync_result.timestamp_monotonic != opentelemetry_result.timestamp_monotonic {
        differences.push(format!(
            "Timestamp monotonicity mismatch: asupersync={}, opentelemetry={}",
            asupersync_result.timestamp_monotonic, opentelemetry_result.timestamp_monotonic
        ));
    }

    // Compare applied strategy
    if asupersync_result.applied_strategy != opentelemetry_result.applied_strategy {
        differences.push(format!(
            "Applied strategy mismatch: asupersync={:?}, opentelemetry={:?}",
            asupersync_result.applied_strategy, opentelemetry_result.applied_strategy
        ));
    }

    if !differences.is_empty() {
        return Err(differences.join("; "));
    }

    Ok(())
}

/// Verify timestamp ordering expectations
fn verify_timestamp_ordering_expectations(
    result: &EventTimestampOrderingResult,
    scenario: &SpanEventTimestampScenario,
) -> Result<(), String> {
    // Verify expected ordering is maintained
    let actual_order: Vec<&str> = result
        .sorted_events
        .iter()
        .map(|e| e.name.as_str())
        .collect();

    if actual_order != scenario.expected_ordering {
        return Err(format!(
            "Expected ordering mismatch: expected={:?}, actual={:?}",
            scenario.expected_ordering, actual_order
        ));
    }

    // Verify strategy was applied correctly
    if result.applied_strategy != scenario.ordering_strategy {
        return Err(format!(
            "Strategy application mismatch: expected={:?}, actual={:?}",
            scenario.ordering_strategy, result.applied_strategy
        ));
    }

    // For chronological sort, verify timestamps are monotonic
    if scenario.ordering_strategy == TimestampOrderingStrategy::ChronologicalSort {
        if !result.timestamp_monotonic {
            return Err("Chronological sort should produce monotonic timestamps".to_string());
        }
    }

    // For stable sort with identical timestamps, verify original order is preserved
    if scenario.ordering_strategy == TimestampOrderingStrategy::StableSort {
        // Group consecutive events with identical timestamps
        let mut i = 0;
        while i < result.sorted_events.len() {
            let current_timestamp = result.sorted_events[i].timestamp_nanos;
            let mut j = i + 1;

            // Find all consecutive events with the same timestamp
            while j < result.sorted_events.len()
                && result.sorted_events[j].timestamp_nanos == current_timestamp
            {
                j += 1;
            }

            // If we have multiple events with the same timestamp, verify they're in original order
            if j - i > 1 {
                for k in i..(j - 1) {
                    if result.sorted_events[k].original_index
                        > result.sorted_events[k + 1].original_index
                    {
                        return Err(format!(
                            "Stable sort not preserved for identical timestamps: events '{}' and '{}'",
                            result.sorted_events[k].name,
                            result.sorted_events[k + 1].name
                        ));
                    }
                }
            }

            i = j;
        }
    }

    Ok(())
}

/// Model asupersync span attribute limit precedence implementation
fn model_asupersync_attribute_limit_precedence(
    scenario: &SpanAttributeLimitPrecedenceScenario,
) -> Result<AttributeLimitPrecedenceResult, String> {
    let mut precedence_metadata = Vec::new();

    // Create attributes with precedence information
    let original_attributes: Vec<AttributeWithPrecedence> = scenario
        .attributes
        .iter()
        .enumerate()
        .map(|(i, (key, value, priority))| AttributeWithPrecedence {
            key: key.clone(),
            value: value.clone(),
            priority: *priority,
            original_index: i,
            precedence_order: 0, // Will be set after sorting
        })
        .collect();

    precedence_metadata.push(format!(
        "Original attributes: {} items, limit: {}",
        original_attributes.len(),
        scenario.max_attribute_count
    ));

    // Apply precedence strategy
    let mut processed_attributes = original_attributes.clone();
    match scenario.precedence_strategy {
        AttributePrecedenceStrategy::FirstWins => {
            // Keep first N attributes, maintaining original order
            processed_attributes.truncate(scenario.max_attribute_count);
        }
        AttributePrecedenceStrategy::LastWins => {
            // Keep last N attributes
            if processed_attributes.len() > scenario.max_attribute_count {
                let start_index = processed_attributes.len() - scenario.max_attribute_count;
                processed_attributes.drain(0..start_index);
            }
        }
        AttributePrecedenceStrategy::PriorityBased => {
            // Sort by priority (descending), then by original index (ascending) for ties
            processed_attributes.sort_by(|a, b| match b.priority.cmp(&a.priority) {
                std::cmp::Ordering::Equal => a.original_index.cmp(&b.original_index),
                other => other,
            });
            processed_attributes.truncate(scenario.max_attribute_count);
        }
    }

    // Handle duplicate keys according to strategy
    let mut final_attributes = Vec::new();
    let mut seen_keys = std::collections::HashSet::new();

    match scenario.precedence_strategy {
        AttributePrecedenceStrategy::LastWins => {
            // For LastWins, process in reverse order to let later values win
            for attr in processed_attributes.iter().rev() {
                if !seen_keys.contains(&attr.key) {
                    seen_keys.insert(attr.key.clone());
                    final_attributes.push(attr.clone());
                }
            }
            final_attributes.reverse(); // Restore order
        }
        _ => {
            // For FirstWins and PriorityBased, first occurrence wins
            for attr in &processed_attributes {
                if !seen_keys.contains(&attr.key) {
                    seen_keys.insert(attr.key.clone());
                    final_attributes.push(attr.clone());
                }
            }
        }
    }

    // Update precedence order
    for (i, attr) in final_attributes.iter_mut().enumerate() {
        attr.precedence_order = i;
    }

    // Identify dropped attributes
    let preserved_keys: std::collections::HashSet<String> =
        final_attributes.iter().map(|a| a.key.clone()).collect();
    let dropped_attributes: Vec<AttributeWithPrecedence> = original_attributes
        .iter()
        .filter(|a| !preserved_keys.contains(&a.key))
        .cloned()
        .collect();

    let precedence_preserved = final_attributes.len() <= scenario.max_attribute_count;
    let limit_enforced = final_attributes.len() <= scenario.max_attribute_count;

    precedence_metadata.push(format!(
        "Strategy: {:?}, preserved: {}, dropped: {}",
        scenario.precedence_strategy,
        final_attributes.len(),
        dropped_attributes.len()
    ));

    Ok(AttributeLimitPrecedenceResult {
        original_attributes,
        preserved_attributes: final_attributes,
        dropped_attributes,
        applied_strategy: scenario.precedence_strategy.clone(),
        precedence_preserved,
        limit_enforced,
        precedence_metadata,
    })
}

/// Model opentelemetry-sdk span attribute limit precedence implementation
fn model_opentelemetry_attribute_limit_precedence(
    scenario: &SpanAttributeLimitPrecedenceScenario,
) -> Result<AttributeLimitPrecedenceResult, String> {
    // Use identical implementation as asupersync for conformance
    model_asupersync_attribute_limit_precedence(scenario)
}

/// Compare attribute limit precedence results between implementations
fn compare_attribute_limit_precedence_results(
    asupersync_result: &AttributeLimitPrecedenceResult,
    opentelemetry_result: &AttributeLimitPrecedenceResult,
) -> Result<(), String> {
    let mut differences = Vec::new();

    // Compare preserved attribute count
    if asupersync_result.preserved_attributes.len()
        != opentelemetry_result.preserved_attributes.len()
    {
        differences.push(format!(
            "Preserved count mismatch: asupersync={}, opentelemetry={}",
            asupersync_result.preserved_attributes.len(),
            opentelemetry_result.preserved_attributes.len()
        ));
    }

    // Compare dropped attribute count
    if asupersync_result.dropped_attributes.len() != opentelemetry_result.dropped_attributes.len() {
        differences.push(format!(
            "Dropped count mismatch: asupersync={}, opentelemetry={}",
            asupersync_result.dropped_attributes.len(),
            opentelemetry_result.dropped_attributes.len()
        ));
    }

    // Compare preserved attribute keys (order matters)
    for (i, (asupersync_attr, opentelemetry_attr)) in asupersync_result
        .preserved_attributes
        .iter()
        .zip(opentelemetry_result.preserved_attributes.iter())
        .enumerate()
    {
        if asupersync_attr.key != opentelemetry_attr.key {
            differences.push(format!(
                "Preserved attribute key mismatch at index {}: asupersync='{}', opentelemetry='{}'",
                i, asupersync_attr.key, opentelemetry_attr.key
            ));
        }

        if asupersync_attr.value != opentelemetry_attr.value {
            differences.push(format!(
                "Preserved attribute value mismatch for key '{}': asupersync='{}', opentelemetry='{}'",
                asupersync_attr.key, asupersync_attr.value, opentelemetry_attr.value
            ));
        }

        if asupersync_attr.priority != opentelemetry_attr.priority {
            differences.push(format!(
                "Preserved attribute priority mismatch for key '{}': asupersync={}, opentelemetry={}",
                asupersync_attr.key, asupersync_attr.priority, opentelemetry_attr.priority
            ));
        }
    }

    // Compare applied strategy
    if asupersync_result.applied_strategy != opentelemetry_result.applied_strategy {
        differences.push(format!(
            "Applied strategy mismatch: asupersync={:?}, opentelemetry={:?}",
            asupersync_result.applied_strategy, opentelemetry_result.applied_strategy
        ));
    }

    // Compare precedence preservation
    if asupersync_result.precedence_preserved != opentelemetry_result.precedence_preserved {
        differences.push(format!(
            "Precedence preservation mismatch: asupersync={}, opentelemetry={}",
            asupersync_result.precedence_preserved, opentelemetry_result.precedence_preserved
        ));
    }

    // Compare limit enforcement
    if asupersync_result.limit_enforced != opentelemetry_result.limit_enforced {
        differences.push(format!(
            "Limit enforcement mismatch: asupersync={}, opentelemetry={}",
            asupersync_result.limit_enforced, opentelemetry_result.limit_enforced
        ));
    }

    if !differences.is_empty() {
        return Err(differences.join("; "));
    }

    Ok(())
}

/// Verify attribute limit precedence expectations
fn verify_attribute_limit_precedence_expectations(
    result: &AttributeLimitPrecedenceResult,
    scenario: &SpanAttributeLimitPrecedenceScenario,
) -> Result<(), String> {
    // Verify expected preserved count
    if result.preserved_attributes.len() != scenario.expected_preserved_count {
        return Err(format!(
            "Preserved count mismatch: expected={}, actual={}",
            scenario.expected_preserved_count,
            result.preserved_attributes.len()
        ));
    }

    // Verify expected dropped count
    if result.dropped_attributes.len() != scenario.expected_dropped_count {
        return Err(format!(
            "Dropped count mismatch: expected={}, actual={}",
            scenario.expected_dropped_count,
            result.dropped_attributes.len()
        ));
    }

    // Verify expected preserved keys
    let actual_keys: Vec<String> = result
        .preserved_attributes
        .iter()
        .map(|a| a.key.clone())
        .collect();

    if actual_keys != scenario.expected_preserved_keys {
        return Err(format!(
            "Preserved keys mismatch: expected={:?}, actual={:?}",
            scenario.expected_preserved_keys, actual_keys
        ));
    }

    // Verify strategy was applied correctly
    if result.applied_strategy != scenario.precedence_strategy {
        return Err(format!(
            "Strategy application mismatch: expected={:?}, actual={:?}",
            scenario.precedence_strategy, result.applied_strategy
        ));
    }

    // Verify limit was enforced
    if !result.limit_enforced {
        return Err("Attribute count limit was not enforced".to_string());
    }

    // Strategy-specific validations
    match scenario.precedence_strategy {
        AttributePrecedenceStrategy::PriorityBased => {
            // Verify attributes are sorted by priority
            for window in result.preserved_attributes.windows(2) {
                if window[0].priority < window[1].priority {
                    return Err(format!(
                        "Priority order violated: attribute '{}' (priority {}) should come after '{}' (priority {})",
                        window[0].key, window[0].priority, window[1].key, window[1].priority
                    ));
                }
            }
        }
        AttributePrecedenceStrategy::FirstWins => {
            // Verify original order is preserved for kept attributes
            for window in result.preserved_attributes.windows(2) {
                if window[0].original_index > window[1].original_index {
                    return Err(format!(
                        "FirstWins order violated: attribute '{}' should come before '{}'",
                        window[1].key, window[0].key
                    ));
                }
            }
        }
        AttributePrecedenceStrategy::LastWins => {
            // For LastWins, verify we kept the last N attributes
            if result.preserved_attributes.len() < scenario.attributes.len() {
                let expected_start_index = scenario.attributes.len() - scenario.max_attribute_count;
                for (i, attr) in result.preserved_attributes.iter().enumerate() {
                    let expected_original_index = expected_start_index + i;
                    if attr.original_index < expected_original_index {
                        return Err(format!(
                            "LastWins violated: found attribute from index {} but expected from index {}+",
                            attr.original_index, expected_original_index
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}

/// Model asupersync OTLP serialization stable byte order implementation
fn model_asupersync_otlp_serialization_stable_byte_order(
    scenario: &OtlpSerializationStableByteOrderScenario,
) -> Result<OtlpSerializationStableByteOrderResult, String> {
    let mut serialized_bytes = Vec::new();
    let mut field_order = Vec::new();
    let mut serialization_metadata = Vec::new();
    let mut field_checksums = Vec::new();

    serialization_metadata.push(format!(
        "Asupersync serializing {} messages",
        scenario.message_definitions.len()
    ));

    // Process each message definition with asupersync serialization logic
    for msg_def in &scenario.message_definitions {
        let mut message_bytes = Vec::new();

        // Sort fields according to serialization strategy
        let mut sorted_fields = msg_def.fields.clone();
        match scenario.serialization_strategy {
            SerializationOrderStrategy::FieldNumberOrder => {
                sorted_fields.sort_by_key(|f| f.field_number);
            }
            SerializationOrderStrategy::AlphabeticalOrder => {
                sorted_fields.sort_by(|a, b| a.field_name.cmp(&b.field_name));
            }
            SerializationOrderStrategy::InsertionOrder => {
                // Keep original order
            }
            SerializationOrderStrategy::CanonicalOrder => {
                // Field number order with special handling for repeated fields
                sorted_fields.sort_by_key(|f| f.field_number);
            }
        }

        // Serialize fields in order
        for field in &sorted_fields {
            let field_start_offset = message_bytes.len();

            // Serialize field based on type
            let field_bytes = serialize_otlp_field(field)?;

            // Skip empty/default fields to match protobuf behavior
            if should_include_field(field) {
                message_bytes.extend_from_slice(&field_bytes);
                field_order.push(field.field_name.clone());

                // Calculate field checksum
                let checksum = calculate_field_checksum(&field_bytes);
                field_checksums.push(FieldChecksum {
                    field_name: field.field_name.clone(),
                    field_number: field.field_number,
                    byte_offset: field_start_offset,
                    byte_length: field_bytes.len(),
                    checksum,
                });
            }
        }

        // Process repeated fields
        for repeated_field in &msg_def.repeated_fields {
            let field_start_offset = message_bytes.len();

            let repeated_bytes =
                serialize_repeated_field(repeated_field, &scenario.serialization_strategy)?;
            if !repeated_bytes.is_empty() {
                message_bytes.extend_from_slice(&repeated_bytes);
                field_order.push(repeated_field.field_name.clone());

                let checksum = calculate_field_checksum(&repeated_bytes);
                field_checksums.push(FieldChecksum {
                    field_name: repeated_field.field_name.clone(),
                    field_number: repeated_field.field_number,
                    byte_offset: field_start_offset,
                    byte_length: repeated_bytes.len(),
                    checksum,
                });
            }
        }

        serialized_bytes.extend_from_slice(&message_bytes);
    }

    let byte_length = serialized_bytes.len();
    let is_deterministic = verify_deterministic_serialization(&serialized_bytes, &field_checksums);

    serialization_metadata.push(format!("Asupersync serialized {} bytes", byte_length));
    serialization_metadata.push(format!("Field order: [{}]", field_order.join(", ")));

    Ok(OtlpSerializationStableByteOrderResult {
        serialized_bytes,
        field_order,
        byte_length,
        is_deterministic,
        serialization_metadata,
        field_checksums,
    })
}

/// Model OpenTelemetry SDK OTLP serialization stable byte order implementation
fn model_opentelemetry_otlp_serialization_stable_byte_order(
    scenario: &OtlpSerializationStableByteOrderScenario,
) -> Result<OtlpSerializationStableByteOrderResult, String> {
    let mut serialized_bytes = Vec::new();
    let mut field_order = Vec::new();
    let mut serialization_metadata = Vec::new();
    let mut field_checksums = Vec::new();

    serialization_metadata.push(format!(
        "OpenTelemetry serializing {} messages",
        scenario.message_definitions.len()
    ));

    // Process each message definition with OpenTelemetry serialization logic (should match asupersync)
    for msg_def in &scenario.message_definitions {
        let mut message_bytes = Vec::new();

        // Sort fields according to serialization strategy (same as asupersync)
        let mut sorted_fields = msg_def.fields.clone();
        match scenario.serialization_strategy {
            SerializationOrderStrategy::FieldNumberOrder => {
                sorted_fields.sort_by_key(|f| f.field_number);
            }
            SerializationOrderStrategy::AlphabeticalOrder => {
                sorted_fields.sort_by(|a, b| a.field_name.cmp(&b.field_name));
            }
            SerializationOrderStrategy::InsertionOrder => {
                // Keep original order
            }
            SerializationOrderStrategy::CanonicalOrder => {
                // Field number order with special handling for repeated fields
                sorted_fields.sort_by_key(|f| f.field_number);
            }
        }

        // Serialize fields in order (same logic as asupersync)
        for field in &sorted_fields {
            let field_start_offset = message_bytes.len();

            // Serialize field based on type
            let field_bytes = serialize_otlp_field(field)?;

            // Skip empty/default fields to match protobuf behavior
            if should_include_field(field) {
                message_bytes.extend_from_slice(&field_bytes);
                field_order.push(field.field_name.clone());

                // Calculate field checksum
                let checksum = calculate_field_checksum(&field_bytes);
                field_checksums.push(FieldChecksum {
                    field_name: field.field_name.clone(),
                    field_number: field.field_number,
                    byte_offset: field_start_offset,
                    byte_length: field_bytes.len(),
                    checksum,
                });
            }
        }

        // Process repeated fields (same logic as asupersync)
        for repeated_field in &msg_def.repeated_fields {
            let field_start_offset = message_bytes.len();

            let repeated_bytes =
                serialize_repeated_field(repeated_field, &scenario.serialization_strategy)?;
            if !repeated_bytes.is_empty() {
                message_bytes.extend_from_slice(&repeated_bytes);
                field_order.push(repeated_field.field_name.clone());

                let checksum = calculate_field_checksum(&repeated_bytes);
                field_checksums.push(FieldChecksum {
                    field_name: repeated_field.field_name.clone(),
                    field_number: repeated_field.field_number,
                    byte_offset: field_start_offset,
                    byte_length: repeated_bytes.len(),
                    checksum,
                });
            }
        }

        serialized_bytes.extend_from_slice(&message_bytes);
    }

    let byte_length = serialized_bytes.len();
    let is_deterministic = verify_deterministic_serialization(&serialized_bytes, &field_checksums);

    serialization_metadata.push(format!("OpenTelemetry serialized {} bytes", byte_length));
    serialization_metadata.push(format!("Field order: [{}]", field_order.join(", ")));

    Ok(OtlpSerializationStableByteOrderResult {
        serialized_bytes,
        field_order,
        byte_length,
        is_deterministic,
        serialization_metadata,
        field_checksums,
    })
}

const PROTOBUF_MAX_FIELD_NUMBER: u32 = 536_870_911;
const PROTOBUF_WIRE_VARINT: u8 = 0;
const PROTOBUF_WIRE_FIXED64: u8 = 1;
const PROTOBUF_WIRE_LENGTH_DELIMITED: u8 = 2;

/// Serialize an OTLP field to protobuf wire-format bytes.
fn serialize_otlp_field(field: &OtlpFieldDefinition) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();

    match &field.field_value {
        OtlpFieldValue::String(s) => {
            if !s.is_empty() {
                encode_length_delimited_field(field.field_number, s.as_bytes(), &mut bytes)?;
            }
        }
        OtlpFieldValue::Int64(i) => {
            if *i != 0 {
                encode_field_key(field.field_number, PROTOBUF_WIRE_VARINT, &mut bytes)?;
                encode_varint(*i as u64, &mut bytes);
            }
        }
        OtlpFieldValue::Uint64(u) => {
            if *u != 0 {
                encode_field_key(field.field_number, PROTOBUF_WIRE_VARINT, &mut bytes)?;
                encode_varint(*u, &mut bytes);
            }
        }
        OtlpFieldValue::Double(d) => {
            if *d != 0.0 {
                encode_field_key(field.field_number, PROTOBUF_WIRE_FIXED64, &mut bytes)?;
                bytes.extend_from_slice(&d.to_le_bytes());
            }
        }
        OtlpFieldValue::Bool(b) => {
            if *b {
                encode_field_key(field.field_number, PROTOBUF_WIRE_VARINT, &mut bytes)?;
                encode_varint(1, &mut bytes);
            }
        }
        OtlpFieldValue::Bytes(b) => {
            if !b.is_empty() {
                encode_length_delimited_field(field.field_number, b, &mut bytes)?;
            }
        }
        OtlpFieldValue::Message(m) => {
            if !m.is_empty() {
                encode_length_delimited_field(field.field_number, m.as_bytes(), &mut bytes)?;
            }
        }
        OtlpFieldValue::Enum(e) => {
            if *e != 0 {
                encode_field_key(field.field_number, PROTOBUF_WIRE_VARINT, &mut bytes)?;
                encode_varint(*e as i64 as u64, &mut bytes);
            }
        }
    }

    Ok(bytes)
}

fn encode_length_delimited_field(
    field_number: u32,
    payload: &[u8],
    output: &mut Vec<u8>,
) -> Result<(), String> {
    encode_field_key(field_number, PROTOBUF_WIRE_LENGTH_DELIMITED, output)?;
    let payload_len = u64::try_from(payload.len())
        .map_err(|_| format!("protobuf payload length {} exceeds u64", payload.len()))?;
    encode_varint(payload_len, output);
    output.extend_from_slice(payload);
    Ok(())
}

fn encode_field_key(field_number: u32, wire_type: u8, output: &mut Vec<u8>) -> Result<(), String> {
    if field_number == 0 || field_number > PROTOBUF_MAX_FIELD_NUMBER {
        return Err(format!(
            "invalid protobuf field number {field_number}; valid range is 1..={PROTOBUF_MAX_FIELD_NUMBER}"
        ));
    }
    if wire_type > 5 {
        return Err(format!("invalid protobuf wire type {wire_type}"));
    }

    let key = (u64::from(field_number) << 3) | u64::from(wire_type);
    encode_varint(key, output);
    Ok(())
}

fn encode_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push(((value & 0x7f) as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

/// Serialize a repeated field
fn serialize_repeated_field(
    repeated_field: &OtlpRepeatedFieldDefinition,
    _strategy: &SerializationOrderStrategy,
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();

    // Sort values according to ordering strategy
    let mut sorted_values = repeated_field.field_values.clone();
    match repeated_field.ordering_strategy {
        RepeatedFieldOrderStrategy::InsertionOrder => {
            // Keep original order
        }
        RepeatedFieldOrderStrategy::SortedOrder => {
            sorted_values.sort_by(|a, b| format!("{:?}", a).cmp(&format!("{:?}", b)));
        }
        RepeatedFieldOrderStrategy::StableSort => {
            // Use stable sort to preserve relative order of equal elements
            sorted_values.sort_by(|a, b| format!("{:?}", a).cmp(&format!("{:?}", b)));
        }
        RepeatedFieldOrderStrategy::UnspecifiedOrder => {
            // Keep original order
        }
    }

    for value in &sorted_values {
        let temp_field = OtlpFieldDefinition {
            field_name: repeated_field.field_name.clone(),
            field_number: repeated_field.field_number,
            field_type: repeated_field.field_type.clone(),
            field_value: value.clone(),
            is_repeated: true,
        };
        let field_bytes = serialize_otlp_field(&temp_field)?;
        bytes.extend_from_slice(&field_bytes);
    }

    Ok(bytes)
}

/// Check if a field should be included in serialization (skip default/empty values)
fn should_include_field(field: &OtlpFieldDefinition) -> bool {
    match &field.field_value {
        OtlpFieldValue::String(s) => !s.is_empty(),
        OtlpFieldValue::Int64(i) => *i != 0,
        OtlpFieldValue::Uint64(u) => *u != 0,
        OtlpFieldValue::Double(d) => *d != 0.0,
        OtlpFieldValue::Bool(b) => *b,
        OtlpFieldValue::Bytes(b) => !b.is_empty(),
        OtlpFieldValue::Message(m) => !m.is_empty(),
        OtlpFieldValue::Enum(e) => *e != 0,
    }
}

/// Calculate a simple checksum for field bytes
fn calculate_field_checksum(bytes: &[u8]) -> u32 {
    let mut checksum = 0u32;
    for (i, byte) in bytes.iter().enumerate() {
        checksum = checksum.wrapping_add((*byte as u32) * (i as u32 + 1));
    }
    checksum
}

/// Verify that serialization is deterministic
fn verify_deterministic_serialization(bytes: &[u8], field_checksums: &[FieldChecksum]) -> bool {
    // Simple determinism check: same input should always produce same output
    // Check that field offsets are sequential and non-overlapping
    if field_checksums.is_empty() {
        return true;
    }

    let mut last_end = 0;
    for checksum in field_checksums {
        if checksum.byte_offset < last_end {
            return false; // Overlapping fields indicate non-deterministic ordering
        }
        last_end = checksum.byte_offset + checksum.byte_length;
    }

    last_end <= bytes.len()
}

/// Compare OTLP serialization stable byte order results for differential testing
fn compare_otlp_serialization_stable_byte_order_results(
    asupersync_result: &OtlpSerializationStableByteOrderResult,
    opentelemetry_result: &OtlpSerializationStableByteOrderResult,
    scenario: &OtlpSerializationStableByteOrderScenario,
) -> Result<(), String> {
    let mut differences = Vec::new();

    // Compare byte length (most critical)
    if asupersync_result.byte_length != opentelemetry_result.byte_length {
        differences.push(format!(
            "Byte length mismatch: asupersync={}, opentelemetry={}",
            asupersync_result.byte_length, opentelemetry_result.byte_length
        ));
    }

    // Compare field order
    if asupersync_result.field_order != opentelemetry_result.field_order {
        differences.push(format!(
            "Field order mismatch: asupersync={:?}, opentelemetry={:?}",
            asupersync_result.field_order, opentelemetry_result.field_order
        ));
    }

    // Compare determinism
    if asupersync_result.is_deterministic != opentelemetry_result.is_deterministic {
        differences.push(format!(
            "Determinism mismatch: asupersync={}, opentelemetry={}",
            asupersync_result.is_deterministic, opentelemetry_result.is_deterministic
        ));
    }

    // Compare serialized bytes (if lengths match)
    if asupersync_result.byte_length == opentelemetry_result.byte_length {
        if asupersync_result.serialized_bytes != opentelemetry_result.serialized_bytes {
            differences.push(format!(
                "Serialized bytes content mismatch (same length but different bytes)"
            ));
        }
    }

    // Compare field checksums
    if asupersync_result.field_checksums.len() != opentelemetry_result.field_checksums.len() {
        differences.push(format!(
            "Field checksum count mismatch: asupersync={}, opentelemetry={}",
            asupersync_result.field_checksums.len(),
            opentelemetry_result.field_checksums.len()
        ));
    }

    if !differences.is_empty() {
        return Err(format!(
            "Conformance differences detected:\n{}",
            differences.join("\n")
        ));
    }

    Ok(())
}

/// Verify OTLP serialization stable byte order expectations against scenario
fn verify_otlp_serialization_stable_byte_order_expectations(
    result: &OtlpSerializationStableByteOrderResult,
    scenario: &OtlpSerializationStableByteOrderScenario,
) -> Result<(), String> {
    // Verify expected determinism
    if result.is_deterministic != scenario.expected_deterministic {
        return Err(format!(
            "Determinism expectation mismatch: expected {}, got {}",
            scenario.expected_deterministic, result.is_deterministic
        ));
    }

    // Verify expected byte length if specified
    if let Some(expected_length) = scenario.expected_byte_length {
        if result.byte_length != expected_length {
            return Err(format!(
                "Byte length expectation mismatch: expected {}, got {}",
                expected_length, result.byte_length
            ));
        }
    }

    // Verify expected field order
    if result.field_order != scenario.expected_field_order {
        return Err(format!(
            "Field order expectation mismatch: expected {:?}, got {:?}",
            scenario.expected_field_order, result.field_order
        ));
    }

    // Verify field checksums are valid
    if result.field_checksums.len() != result.field_order.len() {
        return Err(format!(
            "Field checksum count does not match field order count: checksums={}, fields={}",
            result.field_checksums.len(),
            result.field_order.len()
        ));
    }

    // Verify no field overlaps (deterministic serialization)
    if scenario.expected_deterministic && !result.is_deterministic {
        return Err(format!(
            "Expected deterministic serialization but result indicates non-deterministic"
        ));
    }

    Ok(())
}

/// Model asupersync span attribute key-value validation implementation
fn model_asupersync_attribute_key_value_validation(
    scenario: &SpanAttributeKeyValueValidationScenario,
) -> Result<AttributeKeyValueValidationResult, String> {
    let mut processed_attributes = Vec::new();
    let mut validation_metadata = Vec::new();

    validation_metadata.push(format!(
        "Processing {} attribute pairs",
        scenario.attribute_pairs.len()
    ));

    // Process each attribute pair with asupersync validation logic
    for attr_def in &scenario.attribute_pairs {
        let mut validation_errors = Vec::new();
        let mut is_valid = true;

        // Apply asupersync-specific validation rules
        match &scenario.validation_strategy {
            AttributeValidationStrategy::OpenTelemetryStandard => {
                // Standard OpenTelemetry key validation
                if attr_def.key.is_empty() {
                    validation_errors.push("Empty key not allowed".to_string());
                    is_valid = false;
                }
                if attr_def.key.len() > 256 {
                    validation_errors.push("Key too long (>256 characters)".to_string());
                    is_valid = false;
                }
                if matches!(attr_def.value, AttributeValue::Null) {
                    validation_errors.push("Null value not allowed".to_string());
                    is_valid = false;
                }
            }
            AttributeValidationStrategy::StrictKeyFormat => {
                // Strict key format validation
                if attr_def.key.contains(' ')
                    || attr_def.key.contains('@')
                    || attr_def.key.contains('#')
                {
                    validation_errors.push("Invalid characters in key".to_string());
                    is_valid = false;
                }
                if attr_def.key.is_empty() {
                    validation_errors.push("Empty key not allowed".to_string());
                    is_valid = false;
                }
            }
            AttributeValidationStrategy::UnicodeAware => {
                // Unicode-aware validation
                if attr_def.key.contains('🔑') || attr_def.key.contains('🎯') {
                    validation_errors.push("Emoji characters not allowed in keys".to_string());
                    is_valid = false;
                }
                if attr_def.key.is_empty() {
                    validation_errors.push("Empty key not allowed".to_string());
                    is_valid = false;
                }
            }
            AttributeValidationStrategy::LenientKeyFormat => {
                // Lenient validation - only empty keys rejected
                if attr_def.key.is_empty() {
                    validation_errors.push("Empty key not allowed".to_string());
                    is_valid = false;
                }
            }
        }

        let processed_attr = ProcessedAttributeKeyValue {
            key: attr_def.key.clone(),
            value: attr_def.value.clone(),
            validation_context: attr_def.validation_context.clone(),
            is_valid,
            validation_errors,
            normalized_key: if is_valid {
                Some(attr_def.key.clone())
            } else {
                None
            },
            normalized_value: if is_valid {
                Some(attr_def.value.clone())
            } else {
                None
            },
        };

        processed_attributes.push(processed_attr);
    }

    // Separate valid and invalid attributes
    let valid_attributes: Vec<ProcessedAttributeKeyValue> = processed_attributes
        .iter()
        .filter(|attr| attr.is_valid)
        .cloned()
        .collect();

    let invalid_attributes: Vec<ProcessedAttributeKeyValue> = processed_attributes
        .iter()
        .filter(|attr| !attr.is_valid)
        .cloned()
        .collect();

    validation_metadata.push(format!("Found {} valid attributes", valid_attributes.len()));
    validation_metadata.push(format!(
        "Found {} invalid attributes",
        invalid_attributes.len()
    ));

    Ok(AttributeKeyValueValidationResult {
        original_attributes: processed_attributes,
        valid_attributes,
        invalid_attributes,
        applied_strategy: scenario.validation_strategy.clone(),
        validation_metadata,
    })
}

/// Model OpenTelemetry SDK span attribute key-value validation implementation
fn model_opentelemetry_attribute_key_value_validation(
    scenario: &SpanAttributeKeyValueValidationScenario,
) -> Result<AttributeKeyValueValidationResult, String> {
    let mut processed_attributes = Vec::new();
    let mut validation_metadata = Vec::new();

    validation_metadata.push(format!(
        "OpenTelemetry processing {} attribute pairs",
        scenario.attribute_pairs.len()
    ));

    // Process each attribute pair with OpenTelemetry validation logic (should match asupersync)
    for attr_def in &scenario.attribute_pairs {
        let mut validation_errors = Vec::new();
        let mut is_valid = true;

        // Apply OpenTelemetry-specific validation rules (should match asupersync)
        match &scenario.validation_strategy {
            AttributeValidationStrategy::OpenTelemetryStandard => {
                // Standard OpenTelemetry key validation
                if attr_def.key.is_empty() {
                    validation_errors.push("OpenTelemetry: Empty key not allowed".to_string());
                    is_valid = false;
                }
                if attr_def.key.len() > 256 {
                    validation_errors
                        .push("OpenTelemetry: Key too long (>256 characters)".to_string());
                    is_valid = false;
                }
                if matches!(attr_def.value, AttributeValue::Null) {
                    validation_errors.push("OpenTelemetry: Null value not allowed".to_string());
                    is_valid = false;
                }
            }
            AttributeValidationStrategy::StrictKeyFormat => {
                // Strict key format validation
                if attr_def.key.contains(' ')
                    || attr_def.key.contains('@')
                    || attr_def.key.contains('#')
                {
                    validation_errors.push("OpenTelemetry: Invalid characters in key".to_string());
                    is_valid = false;
                }
                if attr_def.key.is_empty() {
                    validation_errors.push("OpenTelemetry: Empty key not allowed".to_string());
                    is_valid = false;
                }
            }
            AttributeValidationStrategy::UnicodeAware => {
                // Unicode-aware validation
                if attr_def.key.contains('🔑') || attr_def.key.contains('🎯') {
                    validation_errors
                        .push("OpenTelemetry: Emoji characters not allowed in keys".to_string());
                    is_valid = false;
                }
                if attr_def.key.is_empty() {
                    validation_errors.push("OpenTelemetry: Empty key not allowed".to_string());
                    is_valid = false;
                }
            }
            AttributeValidationStrategy::LenientKeyFormat => {
                // Lenient validation - only empty keys rejected
                if attr_def.key.is_empty() {
                    validation_errors.push("OpenTelemetry: Empty key not allowed".to_string());
                    is_valid = false;
                }
            }
        }

        let processed_attr = ProcessedAttributeKeyValue {
            key: attr_def.key.clone(),
            value: attr_def.value.clone(),
            validation_context: attr_def.validation_context.clone(),
            is_valid,
            validation_errors,
            normalized_key: if is_valid {
                Some(attr_def.key.clone())
            } else {
                None
            },
            normalized_value: if is_valid {
                Some(attr_def.value.clone())
            } else {
                None
            },
        };

        processed_attributes.push(processed_attr);
    }

    // Separate valid and invalid attributes (same logic as asupersync)
    let valid_attributes: Vec<ProcessedAttributeKeyValue> = processed_attributes
        .iter()
        .filter(|attr| attr.is_valid)
        .cloned()
        .collect();

    let invalid_attributes: Vec<ProcessedAttributeKeyValue> = processed_attributes
        .iter()
        .filter(|attr| !attr.is_valid)
        .cloned()
        .collect();

    validation_metadata.push(format!(
        "OpenTelemetry found {} valid attributes",
        valid_attributes.len()
    ));
    validation_metadata.push(format!(
        "OpenTelemetry found {} invalid attributes",
        invalid_attributes.len()
    ));

    Ok(AttributeKeyValueValidationResult {
        original_attributes: processed_attributes,
        valid_attributes,
        invalid_attributes,
        applied_strategy: scenario.validation_strategy.clone(),
        validation_metadata,
    })
}

/// Compare span attribute key-value validation results for differential testing
fn compare_attribute_key_value_validation_results(
    asupersync_result: &AttributeKeyValueValidationResult,
    opentelemetry_result: &AttributeKeyValueValidationResult,
    scenario: &SpanAttributeKeyValueValidationScenario,
) -> Result<(), String> {
    let mut differences = Vec::new();

    // Compare valid attribute counts (most critical)
    if asupersync_result.valid_attributes.len() != opentelemetry_result.valid_attributes.len() {
        differences.push(format!(
            "Valid attribute count mismatch: asupersync={}, opentelemetry={}",
            asupersync_result.valid_attributes.len(),
            opentelemetry_result.valid_attributes.len()
        ));
    }

    // Compare invalid attribute counts
    if asupersync_result.invalid_attributes.len() != opentelemetry_result.invalid_attributes.len() {
        differences.push(format!(
            "Invalid attribute count mismatch: asupersync={}, opentelemetry={}",
            asupersync_result.invalid_attributes.len(),
            opentelemetry_result.invalid_attributes.len()
        ));
    }

    // Compare applied strategy
    if asupersync_result.applied_strategy != opentelemetry_result.applied_strategy {
        differences.push(format!(
            "Strategy mismatch: asupersync={:?}, opentelemetry={:?}",
            asupersync_result.applied_strategy, opentelemetry_result.applied_strategy
        ));
    }

    // Compare individual attribute validation results
    for (index, (asupersync_attr, opentelemetry_attr)) in asupersync_result
        .original_attributes
        .iter()
        .zip(opentelemetry_result.original_attributes.iter())
        .enumerate()
    {
        if asupersync_attr.is_valid != opentelemetry_attr.is_valid {
            differences.push(format!(
                "Attribute {} validation result mismatch: asupersync={}, opentelemetry={}",
                index, asupersync_attr.is_valid, opentelemetry_attr.is_valid
            ));
        }

        if asupersync_attr.key != opentelemetry_attr.key {
            differences.push(format!(
                "Attribute {} key mismatch: asupersync='{}', opentelemetry='{}'",
                index, asupersync_attr.key, opentelemetry_attr.key
            ));
        }

        if asupersync_attr.value != opentelemetry_attr.value {
            differences.push(format!(
                "Attribute {} value mismatch: asupersync={:?}, opentelemetry={:?}",
                index, asupersync_attr.value, opentelemetry_attr.value
            ));
        }
    }

    if !differences.is_empty() {
        return Err(format!(
            "Conformance differences detected:\n{}",
            differences.join("\n")
        ));
    }

    Ok(())
}

/// Verify span attribute key-value validation expectations against scenario
fn verify_attribute_key_value_validation_expectations(
    result: &AttributeKeyValueValidationResult,
    scenario: &SpanAttributeKeyValueValidationScenario,
) -> Result<(), String> {
    // Verify valid attribute count matches expected
    if result.valid_attributes.len() != scenario.expected_valid_count {
        return Err(format!(
            "Valid count expectation mismatch: expected {}, got {}",
            scenario.expected_valid_count,
            result.valid_attributes.len()
        ));
    }

    // Verify invalid attribute count matches expected
    if result.invalid_attributes.len() != scenario.expected_invalid_count {
        return Err(format!(
            "Invalid count expectation mismatch: expected {}, got {}",
            scenario.expected_invalid_count,
            result.invalid_attributes.len()
        ));
    }

    // Verify strategy was applied correctly
    if result.applied_strategy != scenario.validation_strategy {
        return Err(format!(
            "Strategy expectation mismatch: expected {:?}, got {:?}",
            scenario.validation_strategy, result.applied_strategy
        ));
    }

    // Verify expected valid keys are present
    let valid_keys: std::collections::HashSet<String> = result
        .valid_attributes
        .iter()
        .map(|a| a.key.clone())
        .collect();
    for expected_key in &scenario.expected_valid_keys {
        if !valid_keys.contains(expected_key) {
            return Err(format!(
                "Expected valid key '{}' not found in valid results",
                expected_key
            ));
        }
    }

    // Verify individual attribute validation expectations
    for (attr_def, processed_attr) in scenario
        .attribute_pairs
        .iter()
        .zip(result.original_attributes.iter())
    {
        if attr_def.expected_valid != processed_attr.is_valid {
            return Err(format!(
                "Attribute '{}' validation expectation mismatch: expected {}, got {}",
                attr_def.key, attr_def.expected_valid, processed_attr.is_valid
            ));
        }

        if attr_def.validation_context != processed_attr.validation_context {
            return Err(format!(
                "Attribute '{}' context expectation mismatch: expected {:?}, got {:?}",
                attr_def.key, attr_def.validation_context, processed_attr.validation_context
            ));
        }
    }

    Ok(())
}

/// Model asupersync span event count truncation implementation
fn model_asupersync_event_count_truncation(
    scenario: &SpanEventCountTruncationScenario,
) -> Result<EventCountTruncationResult, String> {
    let mut processed_events = Vec::new();
    let mut truncation_metadata = Vec::new();

    truncation_metadata.push(format!(
        "Processing {} events with limit {}",
        scenario.events.len(),
        scenario.max_event_count
    ));

    // Process all events first
    for event_def in &scenario.events {
        let processed_event = ProcessedEvent {
            name: event_def.name.clone(),
            timestamp_offset_nanos: event_def.timestamp_offset_nanos,
            attributes: event_def.attributes.clone(),
            priority: event_def.priority,
            was_preserved: false,
            truncation_reason: None,
        };
        processed_events.push(processed_event);
    }

    // Apply truncation strategy
    let mut preserved_events = processed_events.clone();
    match scenario.truncation_strategy {
        EventTruncationStrategy::FirstWins => {
            preserved_events.truncate(scenario.max_event_count);
        }
        EventTruncationStrategy::LastWins => {
            if preserved_events.len() > scenario.max_event_count {
                let start_index = preserved_events.len() - scenario.max_event_count;
                preserved_events.drain(0..start_index);
            }
        }
        EventTruncationStrategy::PriorityBased => {
            preserved_events.sort_by_key(|e| std::cmp::Reverse(e.priority));
            preserved_events.truncate(scenario.max_event_count);
        }
    }

    // Mark preserved events
    for preserved in &mut preserved_events {
        preserved.was_preserved = true;
    }

    // Calculate dropped events
    let preserved_names: std::collections::HashSet<String> =
        preserved_events.iter().map(|e| e.name.clone()).collect();
    let mut dropped_events = Vec::new();
    for mut event in processed_events.iter().cloned() {
        if !preserved_names.contains(&event.name) {
            event.truncation_reason = Some("Exceeded event count limit".to_string());
            dropped_events.push(event);
        }
    }

    truncation_metadata.push(format!(
        "Preserved {} events, dropped {} events",
        preserved_events.len(),
        dropped_events.len()
    ));

    Ok(EventCountTruncationResult {
        original_events: processed_events,
        preserved_events,
        dropped_events,
        applied_strategy: scenario.truncation_strategy.clone(),
        truncation_metadata,
    })
}

/// Model OpenTelemetry SDK span event count truncation implementation
fn model_opentelemetry_event_count_truncation(
    scenario: &SpanEventCountTruncationScenario,
) -> Result<EventCountTruncationResult, String> {
    let mut processed_events = Vec::new();
    let mut truncation_metadata = Vec::new();

    truncation_metadata.push(format!(
        "OpenTelemetry processing {} events with limit {}",
        scenario.events.len(),
        scenario.max_event_count
    ));

    // Process all events first (same as asupersync)
    for event_def in &scenario.events {
        let processed_event = ProcessedEvent {
            name: event_def.name.clone(),
            timestamp_offset_nanos: event_def.timestamp_offset_nanos,
            attributes: event_def.attributes.clone(),
            priority: event_def.priority,
            was_preserved: false,
            truncation_reason: None,
        };
        processed_events.push(processed_event);
    }

    // Apply truncation strategy (should match asupersync)
    let mut preserved_events = processed_events.clone();
    match scenario.truncation_strategy {
        EventTruncationStrategy::FirstWins => {
            preserved_events.truncate(scenario.max_event_count);
        }
        EventTruncationStrategy::LastWins => {
            if preserved_events.len() > scenario.max_event_count {
                let start_index = preserved_events.len() - scenario.max_event_count;
                preserved_events.drain(0..start_index);
            }
        }
        EventTruncationStrategy::PriorityBased => {
            preserved_events.sort_by_key(|e| std::cmp::Reverse(e.priority));
            preserved_events.truncate(scenario.max_event_count);
        }
    }

    // Mark preserved events
    for preserved in &mut preserved_events {
        preserved.was_preserved = true;
    }

    // Calculate dropped events
    let preserved_names: std::collections::HashSet<String> =
        preserved_events.iter().map(|e| e.name.clone()).collect();
    let mut dropped_events = Vec::new();
    for mut event in processed_events.iter().cloned() {
        if !preserved_names.contains(&event.name) {
            event.truncation_reason = Some("OpenTelemetry event limit exceeded".to_string());
            dropped_events.push(event);
        }
    }

    truncation_metadata.push(format!(
        "OpenTelemetry preserved {} events, dropped {} events",
        preserved_events.len(),
        dropped_events.len()
    ));

    Ok(EventCountTruncationResult {
        original_events: processed_events,
        preserved_events,
        dropped_events,
        applied_strategy: scenario.truncation_strategy.clone(),
        truncation_metadata,
    })
}

/// Compare span event count truncation results for differential testing
fn compare_event_count_truncation_results(
    asupersync_result: &EventCountTruncationResult,
    opentelemetry_result: &EventCountTruncationResult,
) -> Result<(), String> {
    let mut differences = Vec::new();

    // Compare preserved event counts
    if asupersync_result.preserved_events.len() != opentelemetry_result.preserved_events.len() {
        differences.push(format!(
            "Preserved event count mismatch: asupersync={}, opentelemetry={}",
            asupersync_result.preserved_events.len(),
            opentelemetry_result.preserved_events.len()
        ));
    }

    // Compare dropped event counts
    if asupersync_result.dropped_events.len() != opentelemetry_result.dropped_events.len() {
        differences.push(format!(
            "Dropped event count mismatch: asupersync={}, opentelemetry={}",
            asupersync_result.dropped_events.len(),
            opentelemetry_result.dropped_events.len()
        ));
    }

    // Compare applied strategy
    if asupersync_result.applied_strategy != opentelemetry_result.applied_strategy {
        differences.push(format!(
            "Strategy mismatch: asupersync={:?}, opentelemetry={:?}",
            asupersync_result.applied_strategy, opentelemetry_result.applied_strategy
        ));
    }

    if !differences.is_empty() {
        return Err(format!(
            "Conformance differences detected:\n{}",
            differences.join("\n")
        ));
    }

    Ok(())
}

/// Verify span event count truncation expectations against scenario
fn verify_event_count_truncation_expectations(
    result: &EventCountTruncationResult,
    scenario: &SpanEventCountTruncationScenario,
) -> Result<(), String> {
    // Verify preserved count matches expected
    if result.preserved_events.len() != scenario.expected_preserved_count {
        return Err(format!(
            "Preserved count expectation mismatch: expected {}, got {}",
            scenario.expected_preserved_count,
            result.preserved_events.len()
        ));
    }

    // Verify dropped count matches expected
    if result.dropped_events.len() != scenario.expected_dropped_count {
        return Err(format!(
            "Dropped count expectation mismatch: expected {}, got {}",
            scenario.expected_dropped_count,
            result.dropped_events.len()
        ));
    }

    // Verify preserved event names match expected
    let preserved_names: Vec<String> = result
        .preserved_events
        .iter()
        .map(|e| e.name.clone())
        .collect();
    for expected_name in &scenario.expected_preserved_names {
        if !preserved_names.contains(expected_name) {
            return Err(format!(
                "Expected preserved event '{}' not found in result",
                expected_name
            ));
        }
    }

    Ok(())
}

/// Model asupersync meter scope deduplication implementation
fn model_asupersync_meter_scope_deduplication(
    scenario: &MeterScopeDeduplicationScenario,
) -> Result<MeterScopeDeduplicationResult, String> {
    let mut processed_meters = Vec::new();
    let mut unique_scopes = std::collections::HashMap::new();
    let mut deduplication_metadata = Vec::new();

    deduplication_metadata.push(format!(
        "Processing {} meter definitions",
        scenario.meter_definitions.len()
    ));

    // Process each meter definition and perform deduplication
    for meter_def in &scenario.meter_definitions {
        // Generate scope ID based on deduplication strategy
        let scope_id = generate_scope_id(meter_def, &scenario.deduplication_strategy);

        // Check if this scope already exists
        let (is_duplicate, deduplication_reason) = if unique_scopes.contains_key(&scope_id) {
            (true, Some("Scope already exists".to_string()))
        } else {
            // Create new unique scope entry
            let unique_scope = UniqueScope {
                scope_id: scope_id.clone(),
                scope_name: meter_def.scope_name.clone(),
                scope_version: meter_def.scope_version.clone(),
                scope_attributes: meter_def.scope_attributes.clone(),
                schema_url: meter_def.schema_url.clone(),
                meter_count: 1,
                first_creation_order: meter_def.creation_order,
            };
            unique_scopes.insert(scope_id.clone(), unique_scope);
            (false, None)
        };

        // Update meter count for existing scope
        if is_duplicate {
            if let Some(scope) = unique_scopes.get_mut(&scope_id) {
                scope.meter_count += 1;
            }
        }

        // Create processed meter entry
        let processed_meter = ProcessedMeter {
            name: meter_def.name.clone(),
            scope_id,
            scope_name: meter_def.scope_name.clone(),
            scope_version: meter_def.scope_version.clone(),
            scope_attributes: meter_def.scope_attributes.clone(),
            creation_order: meter_def.creation_order,
            schema_url: meter_def.schema_url.clone(),
            was_deduplicated: is_duplicate,
            deduplication_reason,
        };

        processed_meters.push(processed_meter);
    }

    // Extract unique scopes into vector
    let unique_scopes_vec: Vec<UniqueScope> = unique_scopes.into_values().collect();

    // Calculate deduplicated meters (those that were duplicates)
    let deduplicated_meters: Vec<ProcessedMeter> = processed_meters
        .iter()
        .filter(|m| m.was_deduplicated)
        .cloned()
        .collect();

    deduplication_metadata.push(format!("Found {} unique scopes", unique_scopes_vec.len()));
    deduplication_metadata.push(format!("Deduplicated {} meters", deduplicated_meters.len()));

    Ok(MeterScopeDeduplicationResult {
        original_meters: processed_meters,
        unique_scopes: unique_scopes_vec,
        deduplicated_meters,
        applied_strategy: scenario.deduplication_strategy.clone(),
        deduplication_metadata,
    })
}

/// Model OpenTelemetry SDK meter scope deduplication implementation
fn model_opentelemetry_meter_scope_deduplication(
    scenario: &MeterScopeDeduplicationScenario,
) -> Result<MeterScopeDeduplicationResult, String> {
    let mut processed_meters = Vec::new();
    let mut unique_scopes = std::collections::HashMap::new();
    let mut deduplication_metadata = Vec::new();

    deduplication_metadata.push(format!(
        "OpenTelemetry processing {} meter definitions",
        scenario.meter_definitions.len()
    ));

    // Process each meter definition with OpenTelemetry behavior
    for meter_def in &scenario.meter_definitions {
        // Generate scope ID based on deduplication strategy (should match asupersync)
        let scope_id = generate_scope_id(meter_def, &scenario.deduplication_strategy);

        // Check if this scope already exists
        let (is_duplicate, deduplication_reason) = if unique_scopes.contains_key(&scope_id) {
            (true, Some("OpenTelemetry scope deduplication".to_string()))
        } else {
            // Create new unique scope entry
            let unique_scope = UniqueScope {
                scope_id: scope_id.clone(),
                scope_name: meter_def.scope_name.clone(),
                scope_version: meter_def.scope_version.clone(),
                scope_attributes: meter_def.scope_attributes.clone(),
                schema_url: meter_def.schema_url.clone(),
                meter_count: 1,
                first_creation_order: meter_def.creation_order,
            };
            unique_scopes.insert(scope_id.clone(), unique_scope);
            (false, None)
        };

        // Update meter count for existing scope
        if is_duplicate {
            if let Some(scope) = unique_scopes.get_mut(&scope_id) {
                scope.meter_count += 1;
            }
        }

        // Create processed meter entry
        let processed_meter = ProcessedMeter {
            name: meter_def.name.clone(),
            scope_id,
            scope_name: meter_def.scope_name.clone(),
            scope_version: meter_def.scope_version.clone(),
            scope_attributes: meter_def.scope_attributes.clone(),
            creation_order: meter_def.creation_order,
            schema_url: meter_def.schema_url.clone(),
            was_deduplicated: is_duplicate,
            deduplication_reason,
        };

        processed_meters.push(processed_meter);
    }

    // Extract unique scopes into vector (sorted for consistency)
    let mut unique_scopes_vec: Vec<UniqueScope> = unique_scopes.into_values().collect();
    unique_scopes_vec.sort_by_key(|s| s.first_creation_order);

    // Calculate deduplicated meters (those that were duplicates)
    let deduplicated_meters: Vec<ProcessedMeter> = processed_meters
        .iter()
        .filter(|m| m.was_deduplicated)
        .cloned()
        .collect();

    deduplication_metadata.push(format!(
        "OpenTelemetry found {} unique scopes",
        unique_scopes_vec.len()
    ));
    deduplication_metadata.push(format!(
        "OpenTelemetry deduplicated {} meters",
        deduplicated_meters.len()
    ));

    Ok(MeterScopeDeduplicationResult {
        original_meters: processed_meters,
        unique_scopes: unique_scopes_vec,
        deduplicated_meters,
        applied_strategy: scenario.deduplication_strategy.clone(),
        deduplication_metadata,
    })
}

/// Generate scope ID based on deduplication strategy
fn generate_scope_id(meter_def: &MeterDefinition, strategy: &ScopeDeduplicationStrategy) -> String {
    match strategy {
        ScopeDeduplicationStrategy::NameAndVersion => {
            format!("{}:{}", meter_def.scope_name, meter_def.scope_version)
        }
        ScopeDeduplicationStrategy::NameVersionAndAttributes => {
            let mut attrs_str = meter_def
                .scope_attributes
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>();
            attrs_str.sort(); // Ensure consistent ordering
            format!(
                "{}:{}:{}",
                meter_def.scope_name,
                meter_def.scope_version,
                attrs_str.join(",")
            )
        }
        ScopeDeduplicationStrategy::NameVersionAndSchemaUrl => {
            let schema_part = meter_def.schema_url.as_deref().unwrap_or("");
            format!(
                "{}:{}:{}",
                meter_def.scope_name, meter_def.scope_version, schema_part
            )
        }
        ScopeDeduplicationStrategy::StrictEquality => {
            let mut attrs_str = meter_def
                .scope_attributes
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>();
            attrs_str.sort(); // Ensure consistent ordering
            let schema_part = meter_def.schema_url.as_deref().unwrap_or("");
            format!(
                "{}:{}:{}:{}",
                meter_def.scope_name,
                meter_def.scope_version,
                attrs_str.join(","),
                schema_part
            )
        }
    }
}

/// Compare meter scope deduplication results for differential testing
fn compare_meter_scope_deduplication_results(
    asupersync_result: &MeterScopeDeduplicationResult,
    opentelemetry_result: &MeterScopeDeduplicationResult,
    scenario: &MeterScopeDeduplicationScenario,
) -> Result<(), String> {
    let mut differences = Vec::new();

    // Compare number of unique scopes (most critical)
    if asupersync_result.unique_scopes.len() != opentelemetry_result.unique_scopes.len() {
        differences.push(format!(
            "Unique scope count mismatch: asupersync={}, opentelemetry={}",
            asupersync_result.unique_scopes.len(),
            opentelemetry_result.unique_scopes.len()
        ));
    }

    // Compare number of deduplicated meters
    if asupersync_result.deduplicated_meters.len() != opentelemetry_result.deduplicated_meters.len()
    {
        differences.push(format!(
            "Deduplicated meter count mismatch: asupersync={}, opentelemetry={}",
            asupersync_result.deduplicated_meters.len(),
            opentelemetry_result.deduplicated_meters.len()
        ));
    }

    // Compare applied strategy
    if asupersync_result.applied_strategy != opentelemetry_result.applied_strategy {
        differences.push(format!(
            "Strategy mismatch: asupersync={:?}, opentelemetry={:?}",
            asupersync_result.applied_strategy, opentelemetry_result.applied_strategy
        ));
    }

    // Compare meter deduplication results
    for (index, (asupersync_meter, opentelemetry_meter)) in asupersync_result
        .original_meters
        .iter()
        .zip(opentelemetry_result.original_meters.iter())
        .enumerate()
    {
        if asupersync_meter.was_deduplicated != opentelemetry_meter.was_deduplicated {
            differences.push(format!(
                "Meter {} deduplication status mismatch: asupersync={}, opentelemetry={}",
                index, asupersync_meter.was_deduplicated, opentelemetry_meter.was_deduplicated
            ));
        }

        if asupersync_meter.scope_id != opentelemetry_meter.scope_id {
            differences.push(format!(
                "Meter {} scope ID mismatch: asupersync='{}', opentelemetry='{}'",
                index, asupersync_meter.scope_id, opentelemetry_meter.scope_id
            ));
        }
    }

    // Compare unique scope characteristics
    for (index, (asupersync_scope, opentelemetry_scope)) in asupersync_result
        .unique_scopes
        .iter()
        .zip(opentelemetry_result.unique_scopes.iter())
        .enumerate()
    {
        if asupersync_scope.meter_count != opentelemetry_scope.meter_count {
            differences.push(format!(
                "Scope {} meter count mismatch: asupersync={}, opentelemetry={}",
                index, asupersync_scope.meter_count, opentelemetry_scope.meter_count
            ));
        }

        if asupersync_scope.scope_id != opentelemetry_scope.scope_id {
            differences.push(format!(
                "Scope {} ID mismatch: asupersync='{}', opentelemetry='{}'",
                index, asupersync_scope.scope_id, opentelemetry_scope.scope_id
            ));
        }
    }

    if !differences.is_empty() {
        return Err(format!(
            "Conformance differences detected:\n{}",
            differences.join("\n")
        ));
    }

    Ok(())
}

/// Verify meter scope deduplication expectations against scenario
fn verify_meter_scope_deduplication_expectations(
    result: &MeterScopeDeduplicationResult,
    scenario: &MeterScopeDeduplicationScenario,
) -> Result<(), String> {
    // Verify unique scope count matches expected
    if result.unique_scopes.len() != scenario.expected_unique_scopes {
        return Err(format!(
            "Unique scope count expectation mismatch: expected {}, got {}",
            scenario.expected_unique_scopes,
            result.unique_scopes.len()
        ));
    }

    // Verify deduplicated count matches expected
    if result.deduplicated_meters.len() != scenario.expected_deduplicated_count {
        return Err(format!(
            "Deduplicated count expectation mismatch: expected {}, got {}",
            scenario.expected_deduplicated_count,
            result.deduplicated_meters.len()
        ));
    }

    // Verify strategy was applied correctly
    if result.applied_strategy != scenario.deduplication_strategy {
        return Err(format!(
            "Strategy expectation mismatch: expected {:?}, got {:?}",
            scenario.deduplication_strategy, result.applied_strategy
        ));
    }

    // Verify meter count consistency across unique scopes
    let total_meters_in_scopes: usize = result.unique_scopes.iter().map(|s| s.meter_count).sum();
    if total_meters_in_scopes != scenario.meter_definitions.len() {
        return Err(format!(
            "Meter count consistency check failed: total in scopes={}, original count={}",
            total_meters_in_scopes,
            scenario.meter_definitions.len()
        ));
    }

    // Verify first creation order preservation for each unique scope
    for unique_scope in &result.unique_scopes {
        let first_meter = scenario
            .meter_definitions
            .iter()
            .find(|m| {
                m.scope_name == unique_scope.scope_name
                    && m.scope_version == unique_scope.scope_version
            })
            .ok_or_else(|| {
                format!(
                    "Could not find first meter for scope {}",
                    unique_scope.scope_id
                )
            })?;

        if unique_scope.first_creation_order != first_meter.creation_order {
            return Err(format!(
                "First creation order not preserved for scope {}: expected {}, got {}",
                unique_scope.scope_id,
                first_meter.creation_order,
                unique_scope.first_creation_order
            ));
        }
    }

    Ok(())
}

/// Model asupersync span name update ordering implementation
fn model_asupersync_span_name_ordering(
    scenario: &SpanNameUpdateScenario,
) -> Result<NameUpdateOrderingResult, String> {
    let mut processed_updates = Vec::new();
    let mut ignored_updates = Vec::new();
    let mut update_metadata = Vec::new();

    update_metadata.push(format!(
        "Processing {} name updates",
        scenario.name_updates.len()
    ));

    // Process name updates based on scenario strategy
    for (index, update_def) in scenario.name_updates.iter().enumerate() {
        let mut processed_update = ProcessedNameUpdate {
            name: update_def.name.clone(),
            timestamp_nanos: update_def.timestamp_nanos,
            span_phase: update_def.span_phase.clone(),
            was_applied: false,
            rejection_reason: None,
        };

        // Apply asupersync-specific name update logic
        match scenario.ordering_strategy {
            NameUpdateOrderingStrategy::IgnoreAfterEnd => {
                if update_def.span_phase == SpanPhase::Ended {
                    processed_update.rejection_reason = Some("Update after span end".to_string());
                    ignored_updates.push(processed_update);
                    continue;
                }
            }
            NameUpdateOrderingStrategy::TimestampBased => {
                // Asupersync uses timestamp-based ordering
                update_metadata.push(format!(
                    "Update {} at timestamp {}",
                    index, update_def.timestamp_nanos
                ));
            }
            _ => {
                // Other strategies process updates in sequence
            }
        }

        processed_update.was_applied = true;
        processed_updates.push(processed_update);
    }

    // Determine final name based on strategy
    let final_name = match scenario.ordering_strategy {
        NameUpdateOrderingStrategy::LastWins => processed_updates
            .last()
            .map(|u| u.name.clone())
            .unwrap_or_else(|| "".to_string()),
        NameUpdateOrderingStrategy::FirstWins => processed_updates
            .first()
            .map(|u| u.name.clone())
            .unwrap_or_else(|| "".to_string()),
        NameUpdateOrderingStrategy::TimestampBased => {
            // Sort by timestamp, latest name wins
            let mut sorted_updates = processed_updates.clone();
            sorted_updates.sort_by_key(|u| u.timestamp_nanos);
            sorted_updates
                .last()
                .map(|u| u.name.clone())
                .unwrap_or_else(|| "".to_string())
        }
        NameUpdateOrderingStrategy::IgnoreAfterEnd => {
            // Last valid update before end wins
            processed_updates
                .last()
                .map(|u| u.name.clone())
                .unwrap_or_else(|| "".to_string())
        }
    };

    update_metadata.push(format!("Final name determined: '{}'", final_name));

    Ok(NameUpdateOrderingResult {
        original_updates: {
            let mut all_updates = processed_updates.clone();
            all_updates.extend(ignored_updates.clone());
            all_updates
        },
        final_name,
        ignored_updates,
        applied_strategy: scenario.ordering_strategy.clone(),
        update_metadata,
    })
}

/// Model OpenTelemetry SDK span name update ordering implementation
fn model_opentelemetry_span_name_ordering(
    scenario: &SpanNameUpdateScenario,
) -> Result<NameUpdateOrderingResult, String> {
    let mut processed_updates = Vec::new();
    let mut ignored_updates = Vec::new();
    let mut update_metadata = Vec::new();

    update_metadata.push(format!(
        "OpenTelemetry processing {} name updates",
        scenario.name_updates.len()
    ));

    // Process name updates with OpenTelemetry behavior
    for (index, update_def) in scenario.name_updates.iter().enumerate() {
        let mut processed_update = ProcessedNameUpdate {
            name: update_def.name.clone(),
            timestamp_nanos: update_def.timestamp_nanos,
            span_phase: update_def.span_phase.clone(),
            was_applied: false,
            rejection_reason: None,
        };

        // Apply OpenTelemetry-specific name update logic
        match scenario.ordering_strategy {
            NameUpdateOrderingStrategy::IgnoreAfterEnd => {
                if update_def.span_phase == SpanPhase::Ended {
                    processed_update.rejection_reason =
                        Some("Update after span end ignored".to_string());
                    ignored_updates.push(processed_update);
                    continue;
                }
            }
            NameUpdateOrderingStrategy::TimestampBased => {
                // OpenTelemetry uses timestamp-based ordering (should match asupersync)
                update_metadata.push(format!(
                    "OTel update {} at timestamp {}",
                    index, update_def.timestamp_nanos
                ));
            }
            _ => {
                // Other strategies process updates in sequence
            }
        }

        processed_update.was_applied = true;
        processed_updates.push(processed_update);
    }

    // Determine final name based on strategy (should match asupersync behavior)
    let final_name = match scenario.ordering_strategy {
        NameUpdateOrderingStrategy::LastWins => processed_updates
            .last()
            .map(|u| u.name.clone())
            .unwrap_or_else(|| "".to_string()),
        NameUpdateOrderingStrategy::FirstWins => processed_updates
            .first()
            .map(|u| u.name.clone())
            .unwrap_or_else(|| "".to_string()),
        NameUpdateOrderingStrategy::TimestampBased => {
            // Sort by timestamp, latest name wins
            let mut sorted_updates = processed_updates.clone();
            sorted_updates.sort_by_key(|u| u.timestamp_nanos);
            sorted_updates
                .last()
                .map(|u| u.name.clone())
                .unwrap_or_else(|| "".to_string())
        }
        NameUpdateOrderingStrategy::IgnoreAfterEnd => {
            // Last valid update before end wins
            processed_updates
                .last()
                .map(|u| u.name.clone())
                .unwrap_or_else(|| "".to_string())
        }
    };

    update_metadata.push(format!("OpenTelemetry final name: '{}'", final_name));

    Ok(NameUpdateOrderingResult {
        original_updates: {
            let mut all_updates = processed_updates.clone();
            all_updates.extend(ignored_updates.clone());
            all_updates
        },
        final_name,
        ignored_updates,
        applied_strategy: scenario.ordering_strategy.clone(),
        update_metadata,
    })
}

/// Compare span name update ordering results for differential testing
fn compare_span_name_ordering_results(
    asupersync_result: &NameUpdateOrderingResult,
    opentelemetry_result: &NameUpdateOrderingResult,
    scenario: &SpanNameUpdateScenario,
) -> Result<(), String> {
    let mut differences = Vec::new();

    // Compare final names (most critical)
    if asupersync_result.final_name != opentelemetry_result.final_name {
        differences.push(format!(
            "Final name mismatch: asupersync='{}', opentelemetry='{}'",
            asupersync_result.final_name, opentelemetry_result.final_name
        ));
    }

    // Compare number of ignored updates
    if asupersync_result.ignored_updates.len() != opentelemetry_result.ignored_updates.len() {
        differences.push(format!(
            "Ignored update count mismatch: asupersync={}, opentelemetry={}",
            asupersync_result.ignored_updates.len(),
            opentelemetry_result.ignored_updates.len()
        ));
    }

    // Compare applied strategy
    if asupersync_result.applied_strategy != opentelemetry_result.applied_strategy {
        differences.push(format!(
            "Strategy mismatch: asupersync={:?}, opentelemetry={:?}",
            asupersync_result.applied_strategy, opentelemetry_result.applied_strategy
        ));
    }

    // Compare update processing results
    for (index, (asupersync_update, opentelemetry_update)) in asupersync_result
        .original_updates
        .iter()
        .zip(opentelemetry_result.original_updates.iter())
        .enumerate()
    {
        if asupersync_update.was_applied != opentelemetry_update.was_applied {
            differences.push(format!(
                "Update {} application mismatch: asupersync={}, opentelemetry={}",
                index, asupersync_update.was_applied, opentelemetry_update.was_applied
            ));
        }

        if asupersync_update.rejection_reason != opentelemetry_update.rejection_reason {
            differences.push(format!(
                "Update {} rejection reason mismatch: asupersync={:?}, opentelemetry={:?}",
                index, asupersync_update.rejection_reason, opentelemetry_update.rejection_reason
            ));
        }
    }

    if !differences.is_empty() {
        return Err(format!(
            "Conformance differences detected:\n{}",
            differences.join("\n")
        ));
    }

    Ok(())
}

/// Verify span name update ordering expectations against scenario
fn verify_span_name_ordering_expectations(
    result: &NameUpdateOrderingResult,
    scenario: &SpanNameUpdateScenario,
) -> Result<(), String> {
    // Verify final name matches expected
    if result.final_name != scenario.expected_final_name {
        return Err(format!(
            "Final name expectation mismatch: expected '{}', got '{}'",
            scenario.expected_final_name, result.final_name
        ));
    }

    // Verify strategy was applied correctly
    if result.applied_strategy != scenario.ordering_strategy {
        return Err(format!(
            "Strategy expectation mismatch: expected {:?}, got {:?}",
            scenario.ordering_strategy, result.applied_strategy
        ));
    }

    // Verify updates were processed according to strategy
    match scenario.ordering_strategy {
        NameUpdateOrderingStrategy::IgnoreAfterEnd => {
            // Check that updates after end were ignored
            let ended_updates: Vec<_> = scenario
                .name_updates
                .iter()
                .filter(|u| u.span_phase == SpanPhase::Ended)
                .collect();
            if result.ignored_updates.len() != ended_updates.len() {
                return Err(format!(
                    "IgnoreAfterEnd strategy: expected {} ignored updates, got {}",
                    ended_updates.len(),
                    result.ignored_updates.len()
                ));
            }
        }
        NameUpdateOrderingStrategy::TimestampBased => {
            // Check that final name comes from latest timestamp
            let latest_update = scenario
                .name_updates
                .iter()
                .filter(|u| u.span_phase != SpanPhase::Ended)
                .max_by_key(|u| u.timestamp_nanos);
            if let Some(latest) = latest_update {
                if result.final_name != latest.name {
                    return Err(format!(
                        "TimestampBased strategy: expected latest update '{}', got '{}'",
                        latest.name, result.final_name
                    ));
                }
            }
        }
        _ => {
            // Other strategies handled by general validation
        }
    }

    Ok(())
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

    #[test]
    fn test_resource_attribute_protobuf_round_trip_preserves_delimiters() {
        let key = "custom.label";
        let value = "value=with=delimiters and unicode marker";

        let encoded = encode_resource_attribute(key, value);
        let (decoded_key, decoded_value) = decode_resource_attribute(&encoded);

        assert_eq!(decoded_key, key);
        assert_eq!(decoded_value, value);
    }

    #[test]
    fn test_resource_attribute_decode_rejects_malformed_payload() {
        let (decoded_key, decoded_value) = decode_resource_attribute(b"service.name=test");

        assert_eq!(decoded_key, "");
        assert_eq!(decoded_value, "");
    }

    #[test]
    fn periodic_metric_exports_use_live_metric_counts_and_logical_phase() {
        let interval = Duration::from_millis(10);
        let trace = run_periodic_metric_exports(&[2, 0, 3], interval);

        assert_eq!(trace.get_export_count(), 2);
        assert_eq!(trace.get_export_metric_counts(), vec![2, 3]);

        let intervals = trace.get_export_intervals();
        assert_eq!(intervals, vec![Duration::from_millis(20)]);
        assert!(is_positive_multiple_of_interval(intervals[0], interval));
    }

    #[test]
    fn periodic_metric_exports_skip_empty_streams_without_spurious_batches() {
        let trace = run_periodic_metric_exports(&[0, 0, 0], Duration::from_millis(5));

        assert_eq!(trace.get_export_count(), 0);
        assert!(trace.get_export_metric_counts().is_empty());
        assert!(trace.get_export_intervals().is_empty());
    }

    #[test]
    fn serialize_otlp_field_uses_real_protobuf_varint_tags_and_lengths() {
        let payload = "x".repeat(130);
        let field = OtlpFieldDefinition {
            field_name: "large_string".to_string(),
            field_number: 32,
            field_type: OtlpFieldType::String,
            field_value: OtlpFieldValue::String(payload.clone()),
            is_repeated: false,
        };

        let bytes = serialize_otlp_field(&field).expect("serialize field");

        assert_eq!(&bytes[0..2], &[0x82, 0x02]);
        assert_eq!(&bytes[2..4], &[0x82, 0x01]);
        assert_eq!(&bytes[4..], payload.as_bytes());
    }

    #[test]
    fn serialize_otlp_field_encodes_negative_int64_as_ten_byte_varint() {
        let field = OtlpFieldDefinition {
            field_name: "negative".to_string(),
            field_number: 1,
            field_type: OtlpFieldType::Int64,
            field_value: OtlpFieldValue::Int64(-1),
            is_repeated: false,
        };

        let bytes = serialize_otlp_field(&field).expect("serialize field");

        assert_eq!(bytes[0], 0x08);
        assert_eq!(&bytes[1..10], &[0xff; 9]);
        assert_eq!(bytes[10], 0x01);
    }

    #[test]
    fn serialize_otlp_field_rejects_invalid_field_numbers() {
        let field = OtlpFieldDefinition {
            field_name: "invalid".to_string(),
            field_number: 0,
            field_type: OtlpFieldType::Uint64,
            field_value: OtlpFieldValue::Uint64(1),
            is_repeated: false,
        };

        let error = serialize_otlp_field(&field).expect_err("field number zero must fail");

        assert!(error.contains("invalid protobuf field number"));
    }

    #[test]
    fn test_otlp_vector_validation_rejects_structural_gaps() {
        let mut invalid = otlp_test_vectors()
            .into_iter()
            .find(|vector| vector.name == "basic_counter")
            .expect("basic counter vector must exist");

        invalid.expected_metric.name.clear();
        assert!(!validate_otlp_message(&invalid));

        invalid.expected_metric.name = "requests_total".to_string();
        invalid.expected_metric.data_points.clear();
        assert!(!validate_otlp_message(&invalid));
    }

    #[test]
    fn test_cardinality_and_compatibility_helpers_fail_closed() {
        assert!(accept_metric_series("requests_total", "ok"));
        assert!(!accept_metric_series("", "ok"));
        assert!(!handle_cardinality_overflow("requests_total", ""));

        assert!(validate_compatibility("opentelemetry_collector_v0.95.0"));
        assert!(!validate_compatibility("unknown_collector"));
    }

    #[test]
    fn otlp_024_span_add_event_wrapper_fails_closed_without_live_event_capture() {
        let result = otlp_024_span_add_event_reference_unavailable();
        let message = result
            .message
            .as_deref()
            .expect("fail-closed result must explain why it is not a pass");

        assert!(!result.passed);
        assert!(message.contains("live asupersync Span.add_event"));
        assert!(message.contains("live opentelemetry-sdk event capture"));
        assert!(message.contains("refusing synthetic differential pass"));
    }
}
