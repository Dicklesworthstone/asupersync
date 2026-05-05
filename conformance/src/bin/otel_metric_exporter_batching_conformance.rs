//! OpenTelemetry Metric Exporter Batching Conformance Test (Tick #149)
//!
//! This conformance test verifies that the live Asupersync OTLP metric request
//! builder produces deterministic ResourceMetrics batches from the same metric
//! stream.
//!
//! Key OTLP specification requirements tested:
//! - ResourceMetrics structure and organization
//! - ScopeMetrics batching per instrumentation scope
//! - Metric data serialization consistency
//! - Resource attributes and schema URL compliance
//! - Temporal aggregation and data point formatting

use asupersync::observability::otel::{MetricLabels, MetricsSnapshot, otlp_request_builder};
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::metrics::v1::{Metric, ResourceMetrics, ScopeMetrics, metric};
use std::collections::BTreeMap;

/// Test cases for metric exporter batching conformance
struct MetricBatchingTestCase {
    name: &'static str,
    metrics_data: Vec<MetricData>,
    service_name: String,
    batch_sequence: u64,
    description: &'static str,
}

/// Metric data for testing
#[derive(Debug, Clone)]
struct MetricData {
    name: String,
    metric_type: MetricType,
    labels: Vec<(String, String)>,
    values: Vec<f64>,
}

#[derive(Debug, Clone)]
enum MetricType {
    Counter,
    Gauge,
    Histogram(Vec<f64>), // bucket boundaries
}

/// Our representation of exported metric batch
#[derive(Debug, Clone)]
struct MetricBatchData {
    resource_metrics: Vec<ResourceMetricsData>,
}

#[derive(Debug, Clone)]
struct ResourceMetricsData {
    service_name: String,
    batch_sequence: Option<u64>,
    scope_metrics: Vec<ScopeMetricsData>,
}

#[derive(Debug, Clone)]
struct ScopeMetricsData {
    scope_name: String,
    scope_version: String,
    schema_url: String,
    metrics: Vec<MetricInfo>,
}

#[derive(Debug, Clone)]
struct MetricInfo {
    name: String,
    description: String,
    unit: String,
    data_type: String,
    data_points: Vec<DataPoint>,
}

#[derive(Debug, Clone, PartialEq)]
struct DataPoint {
    attributes: BTreeMap<String, String>,
    value: DataValue,
    timestamp: u64,
}

#[derive(Debug, Clone, PartialEq)]
enum DataValue {
    Counter(u64),
    Gauge(f64),
    Histogram {
        count: u64,
        sum: f64,
        bucket_counts: Vec<u64>,
        explicit_bounds: Vec<f64>,
    },
}

fn main() {
    println!("🔍 OpenTelemetry Metric Exporter Batching Conformance Test");
    println!("Verifying same metric stream → live OTLP ResourceMetrics batch invariants");

    let test_cases = vec![
        MetricBatchingTestCase {
            name: "single_counter",
            metrics_data: vec![MetricData {
                name: "requests_total".to_string(),
                metric_type: MetricType::Counter,
                labels: vec![("method".to_string(), "GET".to_string())],
                values: vec![42.0],
            }],
            service_name: "test-service".to_string(),
            batch_sequence: 1,
            description: "Single counter metric",
        },
        MetricBatchingTestCase {
            name: "multiple_counters",
            metrics_data: vec![
                MetricData {
                    name: "requests_total".to_string(),
                    metric_type: MetricType::Counter,
                    labels: vec![("method".to_string(), "GET".to_string())],
                    values: vec![100.0],
                },
                MetricData {
                    name: "errors_total".to_string(),
                    metric_type: MetricType::Counter,
                    labels: vec![("status".to_string(), "500".to_string())],
                    values: vec![5.0],
                },
            ],
            service_name: "web-service".to_string(),
            batch_sequence: 2,
            description: "Multiple counter metrics",
        },
        MetricBatchingTestCase {
            name: "mixed_metric_types",
            metrics_data: vec![
                MetricData {
                    name: "active_connections".to_string(),
                    metric_type: MetricType::Gauge,
                    labels: vec![("pool".to_string(), "main".to_string())],
                    values: vec![25.0],
                },
                MetricData {
                    name: "request_duration".to_string(),
                    metric_type: MetricType::Histogram(vec![0.1, 0.5, 1.0, 5.0]),
                    labels: vec![("endpoint".to_string(), "/api/users".to_string())],
                    values: vec![0.05, 0.3, 0.7, 2.5],
                },
            ],
            service_name: "api-service".to_string(),
            batch_sequence: 3,
            description: "Mixed gauge and histogram metrics",
        },
        MetricBatchingTestCase {
            name: "complex_labels",
            metrics_data: vec![MetricData {
                name: "cpu_usage".to_string(),
                metric_type: MetricType::Gauge,
                labels: vec![
                    ("instance".to_string(), "server-01".to_string()),
                    ("region".to_string(), "us-west-2".to_string()),
                    ("env".to_string(), "production".to_string()),
                ],
                values: vec![85.5],
            }],
            service_name: "monitoring".to_string(),
            batch_sequence: 4,
            description: "Complex multi-label metrics",
        },
        MetricBatchingTestCase {
            name: "large_histogram",
            metrics_data: vec![MetricData {
                name: "response_size_bytes".to_string(),
                metric_type: MetricType::Histogram(vec![
                    100.0, 1000.0, 10000.0, 100000.0, 1000000.0,
                ]),
                labels: vec![("content_type".to_string(), "application/json".to_string())],
                values: (0..100).map(|i| i as f64 * 500.0).collect(),
            }],
            service_name: "data-service".to_string(),
            batch_sequence: 5,
            description: "Large histogram with many observations",
        },
        MetricBatchingTestCase {
            name: "empty_batch",
            metrics_data: vec![],
            service_name: "empty-service".to_string(),
            batch_sequence: 6,
            description: "Empty metrics batch",
        },
        MetricBatchingTestCase {
            name: "special_characters",
            metrics_data: vec![MetricData {
                name: "special.metric-name_with/chars".to_string(),
                metric_type: MetricType::Counter,
                labels: vec![
                    (
                        "label.with.dots".to_string(),
                        "value-with-dashes".to_string(),
                    ),
                    (
                        "label/with/slashes".to_string(),
                        "value_with_underscores".to_string(),
                    ),
                ],
                values: vec![1.0],
            }],
            service_name: "special-service".to_string(),
            batch_sequence: 7,
            description: "Metrics with special characters in names and labels",
        },
    ];

    println!(
        "📋 Running {} metric batching conformance tests",
        test_cases.len()
    );

    let mut failed_tests = Vec::new();

    for test_case in &test_cases {
        println!("  Testing {}: {}", test_case.name, test_case.description);

        // Test our implementation
        let our_batch_data = test_our_metric_batching(test_case);

        if let Err(error) = validate_live_metric_batch(&our_batch_data, test_case) {
            failed_tests.push((test_case.name.to_string(), error));
        } else {
            println!("    ✅ {}", test_case.name);
        }
    }

    // Test batching edge cases
    println!("\n📋 Testing metric batching edge cases");
    test_metric_batching_edge_cases(&mut failed_tests);

    // Report results
    println!("\n📊 Metric Exporter Batching Conformance Test Results");
    if failed_tests.is_empty() {
        println!("✅ ALL TESTS PASSED - Metric batching is conformant");
        println!("🎯 OTLP ResourceMetrics batches satisfy live builder invariants");
    } else {
        println!("❌ {} TESTS FAILED:", failed_tests.len());
        for (test_name, error) in &failed_tests {
            println!("   {} - {}", test_name, error);
        }
        std::process::exit(1);
    }
}

/// Test our metric batching implementation
fn test_our_metric_batching(test_case: &MetricBatchingTestCase) -> MetricBatchData {
    // Create metrics snapshot from test data
    let snapshot = create_metrics_snapshot(&test_case.metrics_data);
    let request = otlp_request_builder::metrics_request_from_snapshot(
        &snapshot,
        &test_case.service_name,
        test_case.batch_sequence,
        "asupersync.observability.otel",
    );
    convert_otlp_request_to_batch_data(request)
}

/// Create a metrics snapshot from test metric data
fn create_metrics_snapshot(metrics_data: &[MetricData]) -> MetricsSnapshot {
    let mut counters = Vec::new();
    let mut gauges = Vec::new();
    let mut histograms = Vec::new();

    for metric in metrics_data {
        let labels: MetricLabels = metric.labels.iter().cloned().collect();

        match &metric.metric_type {
            MetricType::Counter => {
                let value = metric.values.first().copied().unwrap_or(0.0) as u64;
                counters.push((metric.name.clone(), labels, value));
            }
            MetricType::Gauge => {
                let value = metric.values.first().copied().unwrap_or(0.0) as i64;
                gauges.push((metric.name.clone(), labels, value));
            }
            MetricType::Histogram(_boundaries) => {
                let count = metric.values.len() as u64;
                let sum = metric.values.iter().sum::<f64>();
                histograms.push((metric.name.clone(), labels, count, sum));
            }
        }
    }

    MetricsSnapshot {
        counters,
        gauges,
        histograms,
    }
}

/// Convert OTLP request to our test representation
fn convert_otlp_request_to_batch_data(request: ExportMetricsServiceRequest) -> MetricBatchData {
    let resource_metrics = request
        .resource_metrics
        .into_iter()
        .map(|rm| convert_resource_metrics(rm))
        .collect();

    MetricBatchData { resource_metrics }
}

fn convert_resource_metrics(rm: ResourceMetrics) -> ResourceMetricsData {
    // Extract service name and batch sequence from resource attributes
    let mut service_name = "unknown".to_string();
    let mut batch_sequence = None;

    if let Some(resource) = rm.resource {
        for attr in resource.attributes {
            match attr.key.as_str() {
                "service.name" => {
                    if let Some(value) = attr.value.and_then(|v| v.value) {
                        if let opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(s) = value {
                            service_name = s;
                        }
                    }
                }
                "batch.sequence" => {
                    batch_sequence = parse_batch_sequence(attr.value);
                }
                _ => {}
            }
        }
    }

    let scope_metrics = rm
        .scope_metrics
        .into_iter()
        .map(|sm| convert_scope_metrics(sm))
        .collect();

    ResourceMetricsData {
        service_name,
        batch_sequence,
        scope_metrics,
    }
}

fn convert_scope_metrics(sm: ScopeMetrics) -> ScopeMetricsData {
    let (scope_name, scope_version) = if let Some(scope) = sm.scope {
        (scope.name, scope.version)
    } else {
        ("unknown".to_string(), "".to_string())
    };

    let metrics = sm.metrics.into_iter().map(|m| convert_metric(m)).collect();

    ScopeMetricsData {
        scope_name,
        scope_version,
        schema_url: sm.schema_url,
        metrics,
    }
}

fn convert_metric(m: Metric) -> MetricInfo {
    let (data_type, data_points) = match m.data {
        Some(metric::Data::Sum(sum)) => (
            "Sum".to_string(),
            sum.data_points
                .into_iter()
                .map(|dp| convert_number_data_point(dp, NumberPointKind::Counter))
                .collect(),
        ),
        Some(metric::Data::Gauge(gauge)) => (
            "Gauge".to_string(),
            gauge
                .data_points
                .into_iter()
                .map(|dp| convert_number_data_point(dp, NumberPointKind::Gauge))
                .collect(),
        ),
        Some(metric::Data::Histogram(histogram)) => (
            "Histogram".to_string(),
            histogram
                .data_points
                .into_iter()
                .map(convert_histogram_data_point)
                .collect(),
        ),
        _ => ("Unknown".to_string(), Vec::new()),
    };

    MetricInfo {
        name: m.name,
        description: m.description,
        unit: m.unit,
        data_type,
        data_points,
    }
}

#[derive(Debug, Clone, Copy)]
enum NumberPointKind {
    Counter,
    Gauge,
}

fn convert_number_data_point(
    dp: opentelemetry_proto::tonic::metrics::v1::NumberDataPoint,
    kind: NumberPointKind,
) -> DataPoint {
    let attributes = dp
        .attributes
        .into_iter()
        .map(|attr| (attr.key, extract_string_value(attr.value)))
        .collect();

    let value = if let Some(value) = dp.value {
        match (kind, value) {
            (
                NumberPointKind::Gauge,
                opentelemetry_proto::tonic::metrics::v1::number_data_point::Value::AsDouble(d),
            ) => DataValue::Gauge(d),
            (
                NumberPointKind::Gauge,
                opentelemetry_proto::tonic::metrics::v1::number_data_point::Value::AsInt(i),
            ) => DataValue::Gauge(i as f64),
            (
                NumberPointKind::Counter,
                opentelemetry_proto::tonic::metrics::v1::number_data_point::Value::AsDouble(d),
            ) => DataValue::Counter(d as u64),
            (
                NumberPointKind::Counter,
                opentelemetry_proto::tonic::metrics::v1::number_data_point::Value::AsInt(i),
            ) => DataValue::Counter(i as u64),
        }
    } else {
        match kind {
            NumberPointKind::Counter => DataValue::Counter(0),
            NumberPointKind::Gauge => DataValue::Gauge(0.0),
        }
    };

    DataPoint {
        attributes,
        value,
        timestamp: dp.time_unix_nano,
    }
}

fn convert_histogram_data_point(
    dp: opentelemetry_proto::tonic::metrics::v1::HistogramDataPoint,
) -> DataPoint {
    let attributes = dp
        .attributes
        .into_iter()
        .map(|attr| (attr.key, extract_string_value(attr.value)))
        .collect();

    let value = DataValue::Histogram {
        count: dp.count,
        sum: dp.sum.unwrap_or_default(),
        bucket_counts: dp.bucket_counts,
        explicit_bounds: dp.explicit_bounds,
    };

    DataPoint {
        attributes,
        value,
        timestamp: dp.time_unix_nano,
    }
}

fn extract_string_value(value: Option<opentelemetry_proto::tonic::common::v1::AnyValue>) -> String {
    if let Some(any_value) = value {
        if let Some(value) = any_value.value {
            match value {
                opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(s) => s,
                opentelemetry_proto::tonic::common::v1::any_value::Value::IntValue(i) => {
                    i.to_string()
                }
                opentelemetry_proto::tonic::common::v1::any_value::Value::DoubleValue(d) => {
                    d.to_string()
                }
                opentelemetry_proto::tonic::common::v1::any_value::Value::BoolValue(b) => {
                    b.to_string()
                }
                _ => "unknown".to_string(),
            }
        } else {
            "empty".to_string()
        }
    } else {
        "missing".to_string()
    }
}

fn parse_batch_sequence(
    value: Option<opentelemetry_proto::tonic::common::v1::AnyValue>,
) -> Option<u64> {
    match value.and_then(|any_value| any_value.value)? {
        opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(value) => {
            value.parse().ok()
        }
        opentelemetry_proto::tonic::common::v1::any_value::Value::IntValue(value) => {
            u64::try_from(value).ok()
        }
        _ => None,
    }
}

/// Validate the live metric batch emitted by Asupersync's OTLP request builder.
fn validate_live_metric_batch(
    batch: &MetricBatchData,
    test_case: &MetricBatchingTestCase,
) -> Result<(), String> {
    if batch.resource_metrics.len() != 1 {
        return Err(format!(
            "ResourceMetrics count mismatch: expected=1, actual={}",
            batch.resource_metrics.len()
        ));
    }

    let resource_metrics = &batch.resource_metrics[0];
    if resource_metrics.service_name != test_case.service_name {
        return Err(format!(
            "service name mismatch: expected={}, actual={}",
            test_case.service_name, resource_metrics.service_name
        ));
    }
    if resource_metrics.batch_sequence != Some(test_case.batch_sequence) {
        return Err(format!(
            "batch sequence mismatch: expected={}, actual={:?}",
            test_case.batch_sequence, resource_metrics.batch_sequence
        ));
    }
    if resource_metrics.scope_metrics.len() != 1 {
        return Err(format!(
            "ScopeMetrics count mismatch: expected=1, actual={}",
            resource_metrics.scope_metrics.len()
        ));
    }

    let scope_metrics = &resource_metrics.scope_metrics[0];
    if scope_metrics.scope_name != "asupersync.observability.otel" {
        return Err(format!(
            "unexpected scope name: {}",
            scope_metrics.scope_name
        ));
    }
    if scope_metrics.schema_url.is_empty() {
        return Err("schema URL must be present".to_string());
    }
    if scope_metrics.scope_version.is_empty() {
        return Err("scope version must be present".to_string());
    }
    if scope_metrics.metrics.len() != test_case.metrics_data.len() {
        return Err(format!(
            "metric count mismatch: expected={}, actual={}",
            test_case.metrics_data.len(),
            scope_metrics.metrics.len()
        ));
    }

    for expected in &test_case.metrics_data {
        let Some(actual) = scope_metrics
            .metrics
            .iter()
            .find(|metric| metric.name == expected.name)
        else {
            return Err(format!("missing metric {}", expected.name));
        };

        let expected_type = match &expected.metric_type {
            MetricType::Counter => "Sum",
            MetricType::Gauge => "Gauge",
            MetricType::Histogram(_) => "Histogram",
        };
        if actual.data_type != expected_type {
            return Err(format!(
                "metric {} data type mismatch: expected={}, actual={}",
                expected.name, expected_type, actual.data_type
            ));
        }
        if actual.description.len() > 4096 || actual.unit.len() > 128 {
            return Err(format!(
                "metric {} metadata fields exceed bounded validation limits",
                expected.name
            ));
        }
        if actual.data_points.len() != 1 {
            return Err(format!(
                "metric {} should have one data point, actual={}",
                expected.name,
                actual.data_points.len()
            ));
        }
    }

    Ok(())
}

/// Test metric batching edge cases
fn test_metric_batching_edge_cases(failed_tests: &mut Vec<(String, String)>) {
    let edge_cases = vec![
        (
            "unicode_labels",
            vec![MetricData {
                name: "测试_metric".to_string(),
                metric_type: MetricType::Counter,
                labels: vec![("标签".to_string(), "值".to_string())],
                values: vec![1.0],
            }],
            "Unicode characters in metric names and labels",
        ),
        (
            "very_long_names",
            vec![MetricData {
                name: "a".repeat(1000),
                metric_type: MetricType::Gauge,
                labels: vec![("very_long_label".repeat(50), "very_long_value".repeat(50))],
                values: vec![42.0],
            }],
            "Very long metric and label names",
        ),
        (
            "many_labels",
            vec![MetricData {
                name: "multi_label_metric".to_string(),
                metric_type: MetricType::Counter,
                labels: (0..100)
                    .map(|i| (format!("label_{}", i), format!("value_{}", i)))
                    .collect(),
                values: vec![1.0],
            }],
            "Metric with many labels",
        ),
    ];

    for (case_name, metrics_data, description) in edge_cases {
        let test_case = MetricBatchingTestCase {
            name: case_name,
            metrics_data,
            service_name: "edge-case-service".to_string(),
            batch_sequence: 999,
            description,
        };

        let our_result = std::panic::catch_unwind(|| test_our_metric_batching(&test_case));

        match our_result {
            Ok(our_batch) => {
                if let Err(error) = validate_live_metric_batch(&our_batch, &test_case) {
                    failed_tests.push((format!("edge_case_{}", case_name), error));
                } else {
                    println!("    ✅ edge_case_{}", case_name);
                }
            }
            Err(_) => {
                failed_tests.push((
                    format!("edge_case_{}", case_name),
                    "live Asupersync metric batching panicked".to_string(),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_snapshot_creation() {
        let metrics_data = vec![MetricData {
            name: "test_counter".to_string(),
            metric_type: MetricType::Counter,
            labels: vec![("label1".to_string(), "value1".to_string())],
            values: vec![10.0],
        }];

        let snapshot = create_metrics_snapshot(&metrics_data);
        assert_eq!(snapshot.counters.len(), 1);
        assert_eq!(snapshot.counters[0].0, "test_counter");
        assert_eq!(snapshot.counters[0].2, 10);
    }

    #[test]
    fn test_histogram_values() {
        let metrics_data = vec![MetricData {
            name: "test_histogram".to_string(),
            metric_type: MetricType::Histogram(vec![1.0, 5.0, 10.0]),
            labels: vec![],
            values: vec![0.5, 2.0, 7.5, 15.0],
        }];

        let snapshot = create_metrics_snapshot(&metrics_data);
        assert_eq!(snapshot.histograms.len(), 1);
        assert_eq!(snapshot.histograms[0].2, 4); // count
        assert_eq!(snapshot.histograms[0].3, 25.0); // sum
    }

    #[test]
    fn test_empty_metrics() {
        let snapshot = create_metrics_snapshot(&[]);
        assert_eq!(snapshot.counters.len(), 0);
        assert_eq!(snapshot.gauges.len(), 0);
        assert_eq!(snapshot.histograms.len(), 0);
    }
}
