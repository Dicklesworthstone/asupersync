//! OpenTelemetry Sum Aggregator Conformance Test (Tick #127)
//!
//! This conformance test verifies that our metric Sum aggregator produces
//! identical Sum values and preserves the monotonicity flag compared to
//! the reference opentelemetry-sdk implementation.

use asupersync::observability::otel::{MetricsSnapshot, OtelMetrics};
use opentelemetry::metrics::{Counter, Histogram, Meter, ObservableGauge, UpDownCounter};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{
    ManualReader, PeriodicReader, SdkMeterProvider, Temporality,
    data::{Metric as SdkMetric, MetricKind, ResourceMetrics, ScopeMetrics, Sum},
};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Test cases for Sum aggregator conformance.
struct SumAggregatorTestCase {
    name: &'static str,
    counter_name: &'static str,
    data_points: Vec<(Vec<(&'static str, &'static str)>, i64)>, // (labels, value)
    is_monotonic: bool,
    description: &'static str,
}

fn main() {
    println!("🔍 OpenTelemetry Sum Aggregator Conformance Test");
    println!("Verifying Sum aggregator produces identical values and preserves monotonicity");

    let test_cases = vec![
        SumAggregatorTestCase {
            name: "monotonic_counter_basic",
            counter_name: "requests_total",
            data_points: vec![
                (vec![("method", "GET"), ("status", "200")], 10),
                (vec![("method", "POST"), ("status", "201")], 5),
                (vec![("method", "GET"), ("status", "404")], 2),
            ],
            is_monotonic: true,
            description: "Basic monotonic counter with multiple label sets",
        },
        SumAggregatorTestCase {
            name: "monotonic_counter_single_series",
            counter_name: "events_processed",
            data_points: vec![
                (vec![("service", "api")], 100),
                (vec![("service", "api")], 50), // Same labels, accumulated
            ],
            is_monotonic: true,
            description: "Single time series with accumulation",
        },
        SumAggregatorTestCase {
            name: "updown_counter_positive_negative",
            counter_name: "active_connections",
            data_points: vec![
                (vec![("region", "us-east")], 10),
                (vec![("region", "us-east")], -3), // Negative increment
                (vec![("region", "us-west")], 5),
                (vec![("region", "us-west")], -1),
            ],
            is_monotonic: false,
            description: "UpDownCounter with positive and negative increments",
        },
        SumAggregatorTestCase {
            name: "zero_values",
            counter_name: "zero_test",
            data_points: vec![
                (vec![("type", "zero")], 0),
                (vec![("type", "positive")], 5),
                (vec![("type", "zero")], 0), // More zeros
            ],
            is_monotonic: true,
            description: "Counter with zero value increments",
        },
        SumAggregatorTestCase {
            name: "large_values",
            counter_name: "large_counter",
            data_points: vec![
                (vec![("size", "large")], i64::MAX / 2),
                (vec![("size", "small")], 1),
                (vec![("size", "large")], 1000), // Should not overflow
            ],
            is_monotonic: true,
            description: "Large values near i64::MAX",
        },
    ];

    println!(
        "📋 Running {} Sum aggregator conformance tests",
        test_cases.len()
    );

    let mut failed_tests = Vec::new();

    for test_case in &test_cases {
        println!("  Testing {}: {}", test_case.name, test_case.description);

        // Test our implementation
        let our_sum_data = test_our_sum_aggregator(test_case);

        // Test reference implementation
        let reference_sum_data = test_reference_sum_aggregator(test_case);

        // Compare results
        if let Err(error) = compare_sum_data(&our_sum_data, &reference_sum_data, test_case) {
            failed_tests.push((test_case.name.to_string(), error));
        } else {
            println!("    ✅ {}", test_case.name);
        }
    }

    // Test edge cases
    println!("\n📋 Testing Sum aggregator edge cases");
    test_sum_aggregator_edge_cases(&mut failed_tests);

    // Report results
    println!("\n📊 Sum Aggregator Conformance Test Results");
    if failed_tests.is_empty() {
        println!("✅ ALL TESTS PASSED - Sum aggregator is conformant");
        println!("🎯 Sum values and monotonicity flags match opentelemetry-sdk exactly");
    } else {
        println!("❌ {} TESTS FAILED:", failed_tests.len());
        for (test_name, error) in &failed_tests {
            println!("   {} - {}", test_name, error);
        }
        std::process::exit(1);
    }
}

/// Test our Sum aggregator implementation.
fn test_our_sum_aggregator(test_case: &SumAggregatorTestCase) -> Vec<SumDataPoint> {
    // Create OtelMetrics instance
    let meter = create_test_meter("asupersync_test");
    let mut otel_metrics = OtelMetrics::new(meter.clone());

    // Create counter or updown counter based on monotonicity
    if test_case.is_monotonic {
        let counter = meter.create_counter(test_case.counter_name).build();

        for (labels, value) in &test_case.data_points {
            let kvs: Vec<_> = labels
                .iter()
                .map(|(k, v)| opentelemetry::KeyValue::new(*k, *v))
                .collect();
            counter.add(*value as u64, &kvs);
        }
    } else {
        let updown_counter = meter.create_up_down_counter(test_case.counter_name).build();

        for (labels, value) in &test_case.data_points {
            let kvs: Vec<_> = labels
                .iter()
                .map(|(k, v)| opentelemetry::KeyValue::new(*k, *v))
                .collect();
            updown_counter.add(*value, &kvs);
        }
    }

    // Get metrics snapshot
    let snapshot = otel_metrics.snapshot();

    // Convert to our test format
    extract_sum_data_from_snapshot(&snapshot, test_case.counter_name, test_case.is_monotonic)
}

/// Test reference opentelemetry-sdk Sum aggregator.
fn test_reference_sum_aggregator(test_case: &SumAggregatorTestCase) -> Vec<SumDataPoint> {
    // Create SDK meter provider with manual reader
    let reader = ManualReader::builder()
        .with_temporality(opentelemetry_sdk::metrics::Temporality::Cumulative)
        .build();

    let provider = SdkMeterProvider::builder()
        .with_reader(reader.clone())
        .with_resource(Resource::new(vec![opentelemetry::KeyValue::new(
            "service.name",
            "test",
        )]))
        .build();

    let meter = provider.meter("test");

    // Create counter or updown counter based on monotonicity
    if test_case.is_monotonic {
        let counter = meter.u64_counter(test_case.counter_name).build();

        for (labels, value) in &test_case.data_points {
            let kvs: Vec<_> = labels
                .iter()
                .map(|(k, v)| opentelemetry::KeyValue::new(*k, *v))
                .collect();
            counter.add(*value as u64, &kvs);
        }
    } else {
        let updown_counter = meter.i64_up_down_counter(test_case.counter_name).build();

        for (labels, value) in &test_case.data_points {
            let kvs: Vec<_> = labels
                .iter()
                .map(|(k, v)| opentelemetry::KeyValue::new(*k, *v))
                .collect();
            updown_counter.add(*value, &kvs);
        }
    }

    // Collect metrics
    let mut resource_metrics = Vec::new();
    reader
        .collect(&mut resource_metrics)
        .expect("collect metrics");

    // Extract Sum data
    extract_sum_data_from_sdk(
        &resource_metrics,
        test_case.counter_name,
        test_case.is_monotonic,
    )
}

/// Our test representation of Sum data point.
#[derive(Debug, Clone, PartialEq)]
struct SumDataPoint {
    labels: Vec<(String, String)>,
    value: i64,
    is_monotonic: bool,
}

/// Extract Sum data points from our metrics snapshot.
fn extract_sum_data_from_snapshot(
    snapshot: &MetricsSnapshot,
    counter_name: &str,
    is_monotonic: bool,
) -> Vec<SumDataPoint> {
    let mut data_points = Vec::new();

    // Check counters (monotonic)
    if is_monotonic {
        for (name, labels, value) in &snapshot.counters {
            if name == counter_name {
                let sorted_labels: Vec<_> =
                    labels.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                data_points.push(SumDataPoint {
                    labels: sorted_labels,
                    value: *value as i64,
                    is_monotonic: true,
                });
            }
        }
    } else {
        // For UpDownCounters, we'd need to check gauges or a separate field
        // This is a simplification for the conformance test
        for (name, labels, value) in &snapshot.gauges {
            if name == counter_name {
                let sorted_labels: Vec<_> =
                    labels.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                data_points.push(SumDataPoint {
                    labels: sorted_labels,
                    value: *value,
                    is_monotonic: false,
                });
            }
        }
    }

    // Sort for deterministic comparison
    data_points.sort_by(|a, b| a.labels.cmp(&b.labels));
    data_points
}

/// Extract Sum data points from opentelemetry-sdk ResourceMetrics.
fn extract_sum_data_from_sdk(
    resource_metrics: &[ResourceMetrics],
    counter_name: &str,
    expected_monotonic: bool,
) -> Vec<SumDataPoint> {
    let mut data_points = Vec::new();

    for resource_metric in resource_metrics {
        for scope_metric in &resource_metric.scope_metrics {
            for metric in &scope_metric.metrics {
                if metric.name == counter_name {
                    if let MetricKind::Sum(sum_data) = &metric.data {
                        for data_point in &sum_data.data_points {
                            let labels: Vec<_> = data_point
                                .attributes
                                .iter()
                                .map(|kv| (kv.key.to_string(), kv.value.to_string()))
                                .collect();

                            data_points.push(SumDataPoint {
                                labels,
                                value: data_point.value as i64,
                                is_monotonic: sum_data.is_monotonic,
                            });
                        }
                    }
                }
            }
        }
    }

    // Sort for deterministic comparison
    data_points.sort_by(|a, b| a.labels.cmp(&b.labels));
    data_points
}

/// Compare Sum data from our implementation vs reference.
fn compare_sum_data(
    our_data: &[SumDataPoint],
    reference_data: &[SumDataPoint],
    test_case: &SumAggregatorTestCase,
) -> Result<(), String> {
    if our_data.len() != reference_data.len() {
        return Err(format!(
            "Data point count mismatch: our={}, reference={}",
            our_data.len(),
            reference_data.len()
        ));
    }

    for (i, (our_point, ref_point)) in our_data.iter().zip(reference_data.iter()).enumerate() {
        // Check monotonicity flag
        if our_point.is_monotonic != ref_point.is_monotonic {
            return Err(format!(
                "Monotonicity flag mismatch at index {}: our={}, reference={}",
                i, our_point.is_monotonic, ref_point.is_monotonic
            ));
        }

        // Check expected monotonicity
        if our_point.is_monotonic != test_case.is_monotonic {
            return Err(format!(
                "Monotonicity flag wrong at index {}: expected={}, actual={}",
                i, test_case.is_monotonic, our_point.is_monotonic
            ));
        }

        // Check labels
        if our_point.labels != ref_point.labels {
            return Err(format!(
                "Labels mismatch at index {}: our={:?}, reference={:?}",
                i, our_point.labels, ref_point.labels
            ));
        }

        // Check values
        if our_point.value != ref_point.value {
            return Err(format!(
                "Value mismatch at index {}: our={}, reference={}",
                i, our_point.value, ref_point.value
            ));
        }
    }

    Ok(())
}

/// Test edge cases for Sum aggregator.
fn test_sum_aggregator_edge_cases(failed_tests: &mut Vec<(String, String)>) {
    // Test empty counter
    let empty_case = SumAggregatorTestCase {
        name: "empty_counter",
        counter_name: "empty_test",
        data_points: vec![],
        is_monotonic: true,
        description: "Empty counter with no data points",
    };

    let our_data = test_our_sum_aggregator(&empty_case);
    let reference_data = test_reference_sum_aggregator(&empty_case);

    if let Err(error) = compare_sum_data(&our_data, &reference_data, &empty_case) {
        failed_tests.push(("empty_counter".to_string(), error));
    } else {
        println!("    ✅ empty_counter");
    }

    // Test accumulation consistency
    let accumulation_case = SumAggregatorTestCase {
        name: "accumulation_consistency",
        counter_name: "accumulation_test",
        data_points: vec![
            (vec![("key", "same")], 10),
            (vec![("key", "same")], 20),
            (vec![("key", "same")], 5),
        ],
        is_monotonic: true,
        description: "Multiple increments to same label set",
    };

    let our_data = test_our_sum_aggregator(&accumulation_case);
    let reference_data = test_reference_sum_aggregator(&accumulation_case);

    if let Err(error) = compare_sum_data(&our_data, &reference_data, &accumulation_case) {
        failed_tests.push(("accumulation_consistency".to_string(), error));
    } else {
        println!("    ✅ accumulation_consistency");
    }
}

/// Create a test meter.
fn create_test_meter(name: &str) -> Meter {
    use opentelemetry::global;
    global::meter(name)
}
