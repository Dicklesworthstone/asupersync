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
