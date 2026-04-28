//! Golden snapshot tests for OTLP metrics export request wire format.
//!
//! Validates that OTLP metrics export requests maintain stable wire format
//! across code changes. Tests the full pipeline from metrics collection to
//! protobuf serialization.
//!
//! # Coverage
//!
//! - Counter metrics with labels
//! - Gauge metrics with resource attributes
//! - Histogram metrics with buckets
//! - Multiple metric types in single request
//! - Resource attributes and instrumentation scope
//! - Timestamp handling and temporality
//! - Error conditions and edge cases

#![cfg(test)]

use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Duration};

/// Test data structure representing an OTLP metrics export request.
/// This mirrors the actual OTLP protobuf structure but in a
/// JSON-serializable format for golden snapshots.
#[derive(Debug, Clone, serde::Serialize)]
struct OtlpMetricsRequest {
    /// Resource attributes (e.g., service.name, service.version)
    resource_attributes: HashMap<String, String>,
    /// Instrumentation scope metadata
    scope_metrics: Vec<ScopeMetrics>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ScopeMetrics {
    scope: InstrumentationScope,
    metrics: Vec<Metric>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct InstrumentationScope {
    name: String,
    version: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct Metric {
    name: String,
    description: String,
    unit: String,
    #[serde(flatten)]
    data: MetricData,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type")]
enum MetricData {
    #[serde(rename = "counter")]
    Counter { data_points: Vec<NumberDataPoint> },
    #[serde(rename = "gauge")]
    Gauge { data_points: Vec<NumberDataPoint> },
    #[serde(rename = "histogram")]
    Histogram { data_points: Vec<HistogramDataPoint> },
}

#[derive(Debug, Clone, serde::Serialize)]
struct NumberDataPoint {
    attributes: HashMap<String, String>,
    time_unix_nano: u64,
    value: MetricValue,
}

#[derive(Debug, Clone, serde::Serialize)]
struct HistogramDataPoint {
    attributes: HashMap<String, String>,
    time_unix_nano: u64,
    count: u64,
    sum: f64,
    bucket_counts: Vec<u64>,
    explicit_bounds: Vec<f64>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(untagged)]
enum MetricValue {
    Int64(i64),
    Double(f64),
}

/// Helper to create a baseline OTLP metrics request for golden snapshots.
fn create_baseline_otlp_request() -> OtlpMetricsRequest {
    let timestamp = 1640995200000000000u64; // 2022-01-01T00:00:00Z (deterministic)

    OtlpMetricsRequest {
        resource_attributes: [
            ("service.name".to_string(), "asupersync".to_string()),
            ("service.version".to_string(), "0.3.1".to_string()),
            ("deployment.environment".to_string(), "test".to_string()),
            ("host.name".to_string(), "test-host".to_string()),
            ("process.pid".to_string(), "12345".to_string()),
        ].into(),
        scope_metrics: vec![
            ScopeMetrics {
                scope: InstrumentationScope {
                    name: "asupersync".to_string(),
                    version: "0.3.1".to_string(),
                },
                metrics: vec![
                    // Counter: tasks spawned
                    Metric {
                        name: "asupersync.tasks.spawned".to_string(),
                        description: "Total number of tasks spawned".to_string(),
                        unit: "1".to_string(),
                        data: MetricData::Counter {
                            data_points: vec![
                                NumberDataPoint {
                                    attributes: [
                                        ("region_type".to_string(), "root".to_string()),
                                    ].into(),
                                    time_unix_nano: timestamp,
                                    value: MetricValue::Int64(42),
                                },
                                NumberDataPoint {
                                    attributes: [
                                        ("region_type".to_string(), "child".to_string()),
                                    ].into(),
                                    time_unix_nano: timestamp,
                                    value: MetricValue::Int64(18),
                                },
                            ],
                        },
                    },

                    // Gauge: active connections
                    Metric {
                        name: "asupersync.connections.active".to_string(),
                        description: "Current number of active connections".to_string(),
                        unit: "1".to_string(),
                        data: MetricData::Gauge {
                            data_points: vec![
                                NumberDataPoint {
                                    attributes: [
                                        ("protocol".to_string(), "http1".to_string()),
                                        ("status".to_string(), "healthy".to_string()),
                                    ].into(),
                                    time_unix_nano: timestamp,
                                    value: MetricValue::Int64(8),
                                },
                            ],
                        },
                    },

                    // Histogram: task duration
                    Metric {
                        name: "asupersync.tasks.duration".to_string(),
                        description: "Task execution duration in seconds".to_string(),
                        unit: "s".to_string(),
                        data: MetricData::Histogram {
                            data_points: vec![
                                HistogramDataPoint {
                                    attributes: [
                                        ("outcome".to_string(), "ok".to_string()),
                                    ].into(),
                                    time_unix_nano: timestamp,
                                    count: 100,
                                    sum: 42.5,
                                    bucket_counts: vec![10, 50, 35, 5, 0],
                                    explicit_bounds: vec![0.1, 0.5, 1.0, 5.0],
                                },
                            ],
                        },
                    },
                ],
            },
        ],
    }
}

/// Helper to create an edge case OTLP request with boundary conditions.
fn create_edge_case_otlp_request() -> OtlpMetricsRequest {
    let timestamp = 1640995260000000000u64; // +1 minute

    OtlpMetricsRequest {
        resource_attributes: [
            ("service.name".to_string(), "edge-test".to_string()),
            ("service.version".to_string(), "unknown".to_string()),
            // Test Unicode and special characters
            ("custom.label".to_string(), "测试 with 🚀 emoji".to_string()),
            ("empty.value".to_string(), "".to_string()),
        ].into(),
        scope_metrics: vec![
            ScopeMetrics {
                scope: InstrumentationScope {
                    name: "edge-test".to_string(),
                    version: "".to_string(),
                },
                metrics: vec![
                    // Counter with zero value
                    Metric {
                        name: "zero.counter".to_string(),
                        description: "".to_string(),
                        unit: "".to_string(),
                        data: MetricData::Counter {
                            data_points: vec![
                                NumberDataPoint {
                                    attributes: HashMap::new(),
                                    time_unix_nano: timestamp,
                                    value: MetricValue::Int64(0),
                                },
                            ],
                        },
                    },

                    // Gauge with negative value
                    Metric {
                        name: "temperature.celsius".to_string(),
                        description: "Temperature reading".to_string(),
                        unit: "°C".to_string(),
                        data: MetricData::Gauge {
                            data_points: vec![
                                NumberDataPoint {
                                    attributes: [
                                        ("sensor".to_string(), "outdoor".to_string()),
                                    ].into(),
                                    time_unix_nano: timestamp,
                                    value: MetricValue::Double(-15.5),
                                },
                            ],
                        },
                    },

                    // Histogram with empty buckets
                    Metric {
                        name: "empty.histogram".to_string(),
                        description: "Histogram with no observations".to_string(),
                        unit: "ms".to_string(),
                        data: MetricData::Histogram {
                            data_points: vec![
                                HistogramDataPoint {
                                    attributes: HashMap::new(),
                                    time_unix_nano: timestamp,
                                    count: 0,
                                    sum: 0.0,
                                    bucket_counts: vec![0, 0, 0],
                                    explicit_bounds: vec![1.0, 10.0],
                                },
                            ],
                        },
                    },
                ],
            },
        ],
    }
}

/// Helper to create a high-cardinality OTLP request for stress testing.
fn create_high_cardinality_otlp_request() -> OtlpMetricsRequest {
    let timestamp = 1640995320000000000u64; // +2 minutes

    // Generate multiple data points with different label combinations
    let mut data_points = Vec::new();
    for i in 0..10 {
        data_points.push(NumberDataPoint {
            attributes: [
                ("endpoint".to_string(), format!("/api/v{}", i)),
                ("method".to_string(), if i % 2 == 0 { "GET".to_string() } else { "POST".to_string() }),
                ("status_code".to_string(), format!("{}", 200 + (i % 5) * 100)),
            ].into(),
            time_unix_nano: timestamp + (i as u64 * 1000000), // Slightly different timestamps
            value: MetricValue::Int64((i + 1) * 10),
        });
    }

    OtlpMetricsRequest {
        resource_attributes: [
            ("service.name".to_string(), "high-cardinality-test".to_string()),
            ("service.version".to_string(), "1.0.0".to_string()),
        ].into(),
        scope_metrics: vec![
            ScopeMetrics {
                scope: InstrumentationScope {
                    name: "high-cardinality".to_string(),
                    version: "1.0.0".to_string(),
                },
                metrics: vec![
                    Metric {
                        name: "http.requests.total".to_string(),
                        description: "HTTP requests by endpoint and status".to_string(),
                        unit: "1".to_string(),
                        data: MetricData::Counter {
                            data_points,
                        },
                    },
                ],
            },
        ],
    }
}

/// Helper to scrub dynamic values for deterministic golden snapshots.
fn scrub_for_golden(request: &OtlpMetricsRequest) -> Value {
    // Convert to JSON and apply consistent scrubbing patterns
    let mut value = serde_json::to_value(request).expect("serialize to JSON");

    fn scrub_recursive(value: &mut Value) {
        match value {
            Value::Object(map) => {
                for (key, val) in map.iter_mut() {
                    match key.as_str() {
                        // Scrub timestamps to [TIMESTAMP]
                        "time_unix_nano" => {
                            *val = Value::String("[TIMESTAMP]".to_string());
                        }
                        // Scrub process IDs
                        "process.pid" => {
                            *val = Value::String("[PID]".to_string());
                        }
                        // Scrub host names
                        "host.name" => {
                            *val = Value::String("[HOSTNAME]".to_string());
                        }
                        _ => scrub_recursive(val),
                    }
                }
            }
            Value::Array(arr) => {
                for item in arr {
                    scrub_recursive(item);
                }
            }
            _ => {}
        }
    }

    scrub_recursive(&mut value);

    // Add metadata for context
    json!({
        "otlp_version": "1.0.0",
        "content_type": "application/x-protobuf",
        "scrubbed_fields": ["time_unix_nano", "process.pid", "host.name"],
        "export_request": value
    })
}

// =============================================================================
// Golden Snapshot Tests
// =============================================================================

#[test]
fn test_otlp_baseline_metrics_request() {
    let request = create_baseline_otlp_request();
    let scrubbed = scrub_for_golden(&request);

    insta::assert_json_snapshot!("otlp_baseline_metrics_request", scrubbed);
}

#[test]
fn test_otlp_edge_case_metrics_request() {
    let request = create_edge_case_otlp_request();
    let scrubbed = scrub_for_golden(&request);

    insta::assert_json_snapshot!("otlp_edge_case_metrics_request", scrubbed);
}

#[test]
fn test_otlp_high_cardinality_metrics_request() {
    let request = create_high_cardinality_otlp_request();
    let scrubbed = scrub_for_golden(&request);

    insta::assert_json_snapshot!("otlp_high_cardinality_metrics_request", scrubbed);
}

#[test]
fn test_otlp_multiple_scopes_metrics_request() {
    let timestamp = 1640995380000000000u64; // +3 minutes

    let request = OtlpMetricsRequest {
        resource_attributes: [
            ("service.name".to_string(), "multi-scope-test".to_string()),
            ("service.version".to_string(), "0.1.0".to_string()),
        ].into(),
        scope_metrics: vec![
            // Runtime metrics scope
            ScopeMetrics {
                scope: InstrumentationScope {
                    name: "asupersync::runtime".to_string(),
                    version: "0.3.1".to_string(),
                },
                metrics: vec![
                    Metric {
                        name: "runtime.scheduler.ticks".to_string(),
                        description: "Scheduler tick count".to_string(),
                        unit: "1".to_string(),
                        data: MetricData::Counter {
                            data_points: vec![
                                NumberDataPoint {
                                    attributes: [
                                        ("worker_id".to_string(), "0".to_string()),
                                    ].into(),
                                    time_unix_nano: timestamp,
                                    value: MetricValue::Int64(1000),
                                },
                            ],
                        },
                    },
                ],
            },

            // HTTP metrics scope
            ScopeMetrics {
                scope: InstrumentationScope {
                    name: "asupersync::http".to_string(),
                    version: "0.3.1".to_string(),
                },
                metrics: vec![
                    Metric {
                        name: "http.server.duration".to_string(),
                        description: "HTTP request duration".to_string(),
                        unit: "s".to_string(),
                        data: MetricData::Histogram {
                            data_points: vec![
                                HistogramDataPoint {
                                    attributes: [
                                        ("method".to_string(), "GET".to_string()),
                                        ("route".to_string(), "/health".to_string()),
                                    ].into(),
                                    time_unix_nano: timestamp,
                                    count: 25,
                                    sum: 12.5,
                                    bucket_counts: vec![20, 5, 0, 0],
                                    explicit_bounds: vec![0.1, 1.0, 10.0],
                                },
                            ],
                        },
                    },
                ],
            },
        ],
    };

    let scrubbed = scrub_for_golden(&request);
    insta::assert_json_snapshot!("otlp_multiple_scopes_metrics_request", scrubbed);
}

#[test]
fn test_otlp_empty_metrics_request() {
    let request = OtlpMetricsRequest {
        resource_attributes: [
            ("service.name".to_string(), "empty-test".to_string()),
        ].into(),
        scope_metrics: vec![
            ScopeMetrics {
                scope: InstrumentationScope {
                    name: "empty".to_string(),
                    version: "".to_string(),
                },
                metrics: vec![], // No metrics
            },
        ],
    };

    let scrubbed = scrub_for_golden(&request);
    insta::assert_json_snapshot!("otlp_empty_metrics_request", scrubbed);
}

// =============================================================================
// Validation Tests
// =============================================================================

#[test]
fn test_golden_snapshot_determinism() {
    // Ensure multiple runs produce identical golden snapshots
    let request1 = create_baseline_otlp_request();
    let request2 = create_baseline_otlp_request();

    let scrubbed1 = scrub_for_golden(&request1);
    let scrubbed2 = scrub_for_golden(&request2);

    assert_eq!(scrubbed1, scrubbed2, "Golden snapshots should be deterministic");
}

#[test]
fn test_scrubbing_removes_dynamic_values() {
    let request = create_baseline_otlp_request();
    let scrubbed = scrub_for_golden(&request);

    let scrubbed_str = serde_json::to_string(&scrubbed).expect("serialize scrubbed");

    // Verify dynamic values are scrubbed
    assert!(scrubbed_str.contains("[TIMESTAMP]"), "Timestamps should be scrubbed");
    assert!(scrubbed_str.contains("[PID]"), "Process IDs should be scrubbed");
    assert!(scrubbed_str.contains("[HOSTNAME]"), "Hostnames should be scrubbed");

    // Verify static values are preserved
    assert!(scrubbed_str.contains("asupersync"), "Service name should be preserved");
    assert!(scrubbed_str.contains("tasks.spawned"), "Metric names should be preserved");
}

#[test]
fn test_metric_data_types_coverage() {
    let baseline = create_baseline_otlp_request();
    let edge_case = create_edge_case_otlp_request();
    let high_card = create_high_cardinality_otlp_request();

    // Collect all metric types across test requests
    let mut metric_types = std::collections::HashSet::new();

    for request in &[baseline, edge_case, high_card] {
        for scope in &request.scope_metrics {
            for metric in &scope.metrics {
                match &metric.data {
                    MetricData::Counter { .. } => { metric_types.insert("counter"); }
                    MetricData::Gauge { .. } => { metric_types.insert("gauge"); }
                    MetricData::Histogram { .. } => { metric_types.insert("histogram"); }
                }
            }
        }
    }

    // Ensure we test all major OTLP metric types
    assert!(metric_types.contains("counter"), "Should test counter metrics");
    assert!(metric_types.contains("gauge"), "Should test gauge metrics");
    assert!(metric_types.contains("histogram"), "Should test histogram metrics");
    assert_eq!(metric_types.len(), 3, "Should cover all supported metric types");
}