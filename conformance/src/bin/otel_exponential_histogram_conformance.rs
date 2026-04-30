//! OpenTelemetry ExponentialHistogram Aggregator Conformance Test (Tick #135)
//!
//! This conformance test verifies that our ExponentialHistogram aggregator produces
//! identical scale and bucket-counts compared to the opentelemetry-sdk reference
//! implementation for Base2ExponentialHistogram aggregation.

use asupersync::observability::otel::{MetricsSnapshot, OtelMetrics};
use opentelemetry::metrics::{Histogram, Meter};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{
    Aggregation, ManualReader, SdkMeterProvider, Temporality,
    data::{ExponentialHistogram as SdkExponentialHistogram, MetricKind, ResourceMetrics},
};
use std::collections::BTreeMap;

/// Test cases for ExponentialHistogram aggregator conformance.
struct ExponentialHistogramTestCase {
    name: &'static str,
    histogram_name: &'static str,
    observations: Vec<(Vec<(&'static str, &'static str)>, Vec<f64>)>, // (labels, values)
    max_size: u32,     // Maximum number of buckets
    max_scale: i8,     // Maximum resolution scale
    description: &'static str,
}

fn main() {
    println!("🔍 OpenTelemetry ExponentialHistogram Aggregator Conformance Test");
    println!("Verifying identical scale + bucket-counts vs opentelemetry-sdk");

    let test_cases = vec![
        ExponentialHistogramTestCase {
            name: "exponential_histogram_default",
            histogram_name: "request_latency",
            observations: vec![
                (
                    vec![("method", "GET"), ("status", "200")],
                    vec![0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
                ),
                (
                    vec![("method", "POST"), ("status", "201")],
                    vec![0.003, 0.008, 0.015, 0.03, 0.06, 0.12],
                ),
            ],
            max_size: 160,  // Default max bucket count
            max_scale: 20,  // Default max scale
            description: "Default ExponentialHistogram configuration with latency observations",
        },
        ExponentialHistogramTestCase {
            name: "exponential_histogram_high_precision",
            histogram_name: "response_time",
            observations: vec![
                (
                    vec![("endpoint", "/api/users")],
                    vec![1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0],
                ),
                (
                    vec![("endpoint", "/api/orders")],
                    vec![0.5, 1.5, 3.0, 6.0, 12.0, 24.0],
                ),
            ],
            max_size: 320,  // Higher precision
            max_scale: 20,
            description: "High precision ExponentialHistogram with power-of-2 aligned values",
        },
        ExponentialHistogramTestCase {
            name: "exponential_histogram_coarse_scale",
            histogram_name: "file_size",
            observations: vec![
                (
                    vec![("type", "image")],
                    vec![1024.0, 2048.0, 4096.0, 8192.0, 16384.0],
                ),
                (
                    vec![("type", "document")],
                    vec![512.0, 1536.0, 3072.0, 6144.0],
                ),
            ],
            max_size: 80,   // Lower bucket count
            max_scale: 10,  // Coarser scale
            description: "Coarse scale ExponentialHistogram for file sizes",
        },
        ExponentialHistogramTestCase {
            name: "exponential_histogram_wide_range",
            histogram_name: "memory_usage",
            observations: vec![
                (
                    vec![("component", "cache")],
                    vec![1e-6, 1e-3, 1.0, 1e3, 1e6, 1e9],
                ),
                (
                    vec![("component", "buffer")],
                    vec![5e-4, 2e-1, 50.0, 5e4],
                ),
            ],
            max_size: 160,
            max_scale: 15,
            description: "Wide range values testing scale adaptation",
        },
        ExponentialHistogramTestCase {
            name: "exponential_histogram_edge_values",
            histogram_name: "cpu_usage",
            observations: vec![
                (
                    vec![("host", "server-1")],
                    vec![0.0, f64::EPSILON, 1.0 - f64::EPSILON, 1.0, 1.0 + f64::EPSILON],
                ),
                (
                    vec![("host", "server-2")],
                    vec![0.5, 0.999999, 1.000001, 2.0],
                ),
            ],
            max_size: 160,
            max_scale: 20,
            description: "Edge values near floating-point precision limits",
        },
    ];

    println!(
        "📋 Running {} ExponentialHistogram aggregator conformance tests",
        test_cases.len()
    );

    let mut failed_tests = Vec::new();

    for test_case in &test_cases {
        println!("  Testing {}: {}", test_case.name, test_case.description);

        // Test our implementation
        let our_histogram_data = test_our_exponential_histogram_aggregator(test_case);

        // Test reference implementation
        let reference_histogram_data = test_reference_exponential_histogram_aggregator(test_case);

        // Compare results - focus on scale and bucket-counts as specified
        if let Err(error) = compare_exponential_histogram_data(
            &our_histogram_data,
            &reference_histogram_data,
            test_case,
        ) {
            failed_tests.push((test_case.name.to_string(), error));
        } else {
            println!("    ✅ {}", test_case.name);
        }
    }

    // Test exponential histogram edge cases
    println!("\n📋 Testing ExponentialHistogram edge cases");
    test_exponential_histogram_edge_cases(&mut failed_tests);

    // Report results
    println!("\n📊 ExponentialHistogram Aggregator Conformance Test Results");
    if failed_tests.is_empty() {
        println!("✅ ALL TESTS PASSED - ExponentialHistogram aggregator is conformant");
        println!("🎯 Scale and bucket-counts match opentelemetry-sdk exactly");
    } else {
        println!("❌ {} TESTS FAILED:", failed_tests.len());
        for (test_name, error) in &failed_tests {
            println!("   {} - {}", test_name, error);
        }
        std::process::exit(1);
    }
}

/// Our test representation of ExponentialHistogram data.
#[derive(Debug, Clone, PartialEq)]
struct ExponentialHistogramDataPoint {
    labels: Vec<(String, String)>,
    count: u64,
    sum: f64,
    scale: i32,
    zero_count: u64,
    positive_offset: i32,
    positive_bucket_counts: Vec<u64>,
    negative_offset: i32,
    negative_bucket_counts: Vec<u64>,
    min: Option<f64>,
    max: Option<f64>,
}

/// Test our ExponentialHistogram aggregator implementation.
fn test_our_exponential_histogram_aggregator(
    test_case: &ExponentialHistogramTestCase,
) -> Vec<ExponentialHistogramDataPoint> {
    // TODO: Implement our ExponentialHistogram aggregation
    // For now, we'll create placeholder data that should be replaced with actual implementation
    let mut data_points = Vec::new();

    for (labels, observations) in &test_case.observations {
        // This is placeholder logic - replace with actual ExponentialHistogram implementation
        let mut positive_buckets = BTreeMap::new();
        let mut count = 0;
        let mut sum = 0.0;
        let mut min_val = f64::INFINITY;
        let mut max_val = f64::NEG_INFINITY;
        let mut zero_count = 0;

        for &value in observations {
            count += 1;
            sum += value;
            min_val = min_val.min(value);
            max_val = max_val.max(value);

            if value == 0.0 {
                zero_count += 1;
            } else if value > 0.0 {
                // Simplified bucket calculation for base-2 exponential histogram
                let bucket_index = if value >= 1.0 {
                    (value.log2().floor() as i32).max(0)
                } else {
                    -((-value.log2().floor() as i32).max(1))
                };
                *positive_buckets.entry(bucket_index).or_insert(0) += 1;
            }
        }

        // Convert to bucket arrays
        let (min_index, max_index) = if positive_buckets.is_empty() {
            (0, 0)
        } else {
            let min_idx = *positive_buckets.keys().min().unwrap();
            let max_idx = *positive_buckets.keys().max().unwrap();
            (min_idx, max_idx)
        };

        let mut positive_bucket_counts = Vec::new();
        if !positive_buckets.is_empty() {
            for i in min_index..=max_index {
                positive_bucket_counts.push(*positive_buckets.get(&i).unwrap_or(&0));
            }
        }

        data_points.push(ExponentialHistogramDataPoint {
            labels: labels.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            count,
            sum,
            scale: test_case.max_scale as i32, // Simplified - should be calculated
            zero_count,
            positive_offset: min_index,
            positive_bucket_counts,
            negative_offset: 0, // Simplified - no negative values in test data
            negative_bucket_counts: Vec::new(),
            min: if min_val.is_finite() { Some(min_val) } else { None },
            max: if max_val.is_finite() { Some(max_val) } else { None },
        });
    }

    data_points
}

/// Test the reference opentelemetry-sdk ExponentialHistogram aggregator.
fn test_reference_exponential_histogram_aggregator(
    test_case: &ExponentialHistogramTestCase,
) -> Vec<ExponentialHistogramDataPoint> {
    let resource = Resource::default();
    let reader = ManualReader::builder()
        .with_temporality(Temporality::Cumulative)
        .build();

    let provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(reader.clone())
        .build();

    let meter = provider.meter("test_meter");

    // Create histogram with ExponentialHistogram aggregation
    let histogram = meter
        .f64_histogram(test_case.histogram_name)
        .with_description("Test ExponentialHistogram for conformance")
        .build();

    // Record observations
    for (labels, observations) in &test_case.observations {
        let attribute_set: Vec<_> = labels.iter()
            .map(|(k, v)| opentelemetry::KeyValue::new(*k, *v))
            .collect();

        for &value in observations {
            histogram.record(value, &attribute_set);
        }
    }

    // Collect metrics
    let metrics = reader.collect(&mut opentelemetry::Context::new()).unwrap();

    // Extract ExponentialHistogram data
    extract_exponential_histogram_data_from_sdk(&metrics, test_case.histogram_name)
}

/// Extract ExponentialHistogram data from SDK ResourceMetrics.
fn extract_exponential_histogram_data_from_sdk(
    metrics: &ResourceMetrics,
    histogram_name: &str,
) -> Vec<ExponentialHistogramDataPoint> {
    let mut data_points = Vec::new();

    for scope_metrics in &metrics.scope_metrics {
        for metric in &scope_metrics.metrics {
            if metric.name == histogram_name {
                if let MetricKind::ExponentialHistogram(ref exponential_histogram) = metric.data {
                    for data_point in &exponential_histogram.data_points {
                        let labels: Vec<(String, String)> = data_point.attributes.iter()
                            .map(|kv| (kv.key.to_string(), kv.value.to_string()))
                            .collect();

                        data_points.push(ExponentialHistogramDataPoint {
                            labels,
                            count: data_point.count,
                            sum: data_point.sum,
                            scale: data_point.scale,
                            zero_count: data_point.zero_count,
                            positive_offset: data_point.positive_bucket.offset,
                            positive_bucket_counts: data_point.positive_bucket.bucket_counts.clone(),
                            negative_offset: data_point.negative_bucket.offset,
                            negative_bucket_counts: data_point.negative_bucket.bucket_counts.clone(),
                            min: data_point.min,
                            max: data_point.max,
                        });
                    }
                }
            }
        }
    }

    data_points
}

/// Compare ExponentialHistogram data between our implementation and reference.
/// Focus on scale and bucket-counts as specified in requirements.
fn compare_exponential_histogram_data(
    our_data: &[ExponentialHistogramDataPoint],
    reference_data: &[ExponentialHistogramDataPoint],
    test_case: &ExponentialHistogramTestCase,
) -> Result<(), String> {
    if our_data.len() != reference_data.len() {
        return Err(format!(
            "Data point count mismatch: our={}, reference={}",
            our_data.len(),
            reference_data.len()
        ));
    }

    // Sort both by labels for consistent comparison
    let mut our_sorted = our_data.to_vec();
    let mut ref_sorted = reference_data.to_vec();
    our_sorted.sort_by(|a, b| a.labels.cmp(&b.labels));
    ref_sorted.sort_by(|a, b| a.labels.cmp(&b.labels));

    for (our_point, ref_point) in our_sorted.iter().zip(ref_sorted.iter()) {
        // Check labels match
        if our_point.labels != ref_point.labels {
            return Err(format!(
                "Label mismatch: our={:?}, reference={:?}",
                our_point.labels, ref_point.labels
            ));
        }

        // Core requirement: identical scale
        if our_point.scale != ref_point.scale {
            return Err(format!(
                "Scale mismatch for labels {:?}: our={}, reference={}",
                our_point.labels, our_point.scale, ref_point.scale
            ));
        }

        // Core requirement: identical bucket-counts
        if our_point.positive_bucket_counts != ref_point.positive_bucket_counts {
            return Err(format!(
                "Positive bucket counts mismatch for labels {:?}: our={:?}, reference={:?}",
                our_point.labels, our_point.positive_bucket_counts, ref_point.positive_bucket_counts
            ));
        }

        if our_point.negative_bucket_counts != ref_point.negative_bucket_counts {
            return Err(format!(
                "Negative bucket counts mismatch for labels {:?}: our={:?}, reference={:?}",
                our_point.labels, our_point.negative_bucket_counts, ref_point.negative_bucket_counts
            ));
        }

        // Additional verifications for completeness
        if our_point.count != ref_point.count {
            return Err(format!(
                "Count mismatch for labels {:?}: our={}, reference={}",
                our_point.labels, our_point.count, ref_point.count
            ));
        }

        if our_point.zero_count != ref_point.zero_count {
            return Err(format!(
                "Zero count mismatch for labels {:?}: our={}, reference={}",
                our_point.labels, our_point.zero_count, ref_point.zero_count
            ));
        }

        // Sum comparison with epsilon for floating point
        let sum_diff = (our_point.sum - ref_point.sum).abs();
        if sum_diff > 1e-10 {
            return Err(format!(
                "Sum mismatch for labels {:?}: our={}, reference={}, diff={}",
                our_point.labels, our_point.sum, ref_point.sum, sum_diff
            ));
        }

        // Offset comparison
        if our_point.positive_offset != ref_point.positive_offset {
            return Err(format!(
                "Positive offset mismatch for labels {:?}: our={}, reference={}",
                our_point.labels, our_point.positive_offset, ref_point.positive_offset
            ));
        }

        if our_point.negative_offset != ref_point.negative_offset {
            return Err(format!(
                "Negative offset mismatch for labels {:?}: our={}, reference={}",
                our_point.labels, our_point.negative_offset, ref_point.negative_offset
            ));
        }
    }

    Ok(())
}

/// Test edge cases for ExponentialHistogram aggregation.
fn test_exponential_histogram_edge_cases(failed_tests: &mut Vec<(String, String)>) {
    let edge_cases = vec![
        ("zero_only", vec![0.0, 0.0, 0.0]),
        ("single_value", vec![42.0]),
        ("identical_values", vec![1.5, 1.5, 1.5, 1.5]),
        ("min_max_values", vec![f64::MIN_POSITIVE, f64::MAX / 1e10]),
    ];

    for (case_name, observations) in edge_cases {
        let test_case = ExponentialHistogramTestCase {
            name: case_name,
            histogram_name: "edge_case_test",
            observations: vec![(vec![("edge", case_name)], observations)],
            max_size: 160,
            max_scale: 20,
            description: "Edge case testing",
        };

        let our_data = test_our_exponential_histogram_aggregator(&test_case);
        let reference_data = test_reference_exponential_histogram_aggregator(&test_case);

        if let Err(error) = compare_exponential_histogram_data(&our_data, &reference_data, &test_case) {
            failed_tests.push((format!("edge_case_{}", case_name), error));
        } else {
            println!("    ✅ edge_case_{}", case_name);
        }
    }
}