//! OpenTelemetry Histogram Aggregator Conformance Test (br-asupersync-j5f)
//!
//! This conformance test records through the live asupersync histogram API and
//! compares the exported snapshot with a deterministic explicit-boundary
//! reference model. The production histogram surface currently exposes count,
//! sum, explicit bucket boundaries, and per-bucket counts; min/max and
//! attribute-scoped data points are not claimed here.

use asupersync::observability::metrics::{HistogramSnapshot, Metrics};

/// Test cases for Histogram aggregator conformance.
struct HistogramAggregatorTestCase {
    name: &'static str,
    histogram_name: &'static str,
    observations: Vec<f64>,
    bucket_boundaries: Vec<f64>,
    description: &'static str,
}

fn main() {
    println!("🔍 OpenTelemetry Histogram Aggregator Conformance Test");
    println!("Verifying live asupersync histogram snapshots");

    let test_cases = vec![
        HistogramAggregatorTestCase {
            name: "default_explicit_buckets",
            histogram_name: "request_duration",
            observations: vec![0.05, 0.1, 0.15, 0.2, 0.5, 0.8, 1.0, 1.5, 2.5],
            bucket_boundaries: default_explicit_boundaries(),
            description: "Default explicit bucket boundaries with mixed observations",
        },
        HistogramAggregatorTestCase {
            name: "custom_explicit_buckets",
            histogram_name: "response_size_bytes",
            observations: vec![50.0, 100.0, 500.0, 1000.0, 5000.0, 10000.0, 100000.0],
            bucket_boundaries: vec![10.0, 100.0, 1000.0, 10000.0, 100000.0, 1000000.0],
            description: "Custom explicit bucket boundaries for response sizes",
        },
        HistogramAggregatorTestCase {
            name: "boundary_edge_values",
            histogram_name: "latency_ms",
            observations: vec![
                0.0,
                f64::EPSILON,
                0.001,
                999.999,
                1000.0,
                1000.001,
                f64::MAX / 1e10,
            ],
            bucket_boundaries: vec![0.001, 0.01, 0.1, 1.0, 10.0, 100.0, 1000.0, 10000.0],
            description: "Edge values near bucket boundaries",
        },
        HistogramAggregatorTestCase {
            name: "single_bucket_multiple_values",
            histogram_name: "cpu_usage",
            observations: vec![0.1, 0.12, 0.15, 0.18, 0.2, 0.22, 0.25, 0.3],
            bucket_boundaries: vec![0.5, 1.0],
            description: "Multiple values falling in same bucket",
        },
        HistogramAggregatorTestCase {
            name: "wide_range_explicit_buckets",
            histogram_name: "file_size",
            observations: vec![1e-6, 1e-3, 1.0, 1e3, 1e6, 1e9],
            bucket_boundaries: vec![1e-9, 1e-6, 1e-3, 1.0, 1e3, 1e6, 1e9, 1e12],
            description: "Wide range exponential values across many orders of magnitude",
        },
    ];

    println!(
        "📋 Running {} Histogram aggregator conformance tests",
        test_cases.len()
    );

    let mut failed_tests = Vec::new();

    for test_case in &test_cases {
        println!("  Testing {}: {}", test_case.name, test_case.description);

        let our_histogram_data = test_our_histogram_aggregator(test_case);
        let reference_histogram_data = test_reference_histogram_aggregator(test_case);

        if let Err(error) =
            compare_histogram_data(&our_histogram_data, &reference_histogram_data, test_case)
        {
            failed_tests.push((test_case.name.to_string(), error));
        } else {
            println!("    ✅ {}", test_case.name);
        }
    }

    // Test exponential bucket generation edge cases
    println!("\n📋 Testing exponential bucket edge cases");
    test_histogram_aggregator_edge_cases(&mut failed_tests);

    // Report results
    println!("\n📊 Histogram Aggregator Conformance Test Results");
    if failed_tests.is_empty() {
        println!("✅ ALL TESTS PASSED - Histogram aggregator is conformant");
        println!("🎯 Live snapshot bucket distributions match the explicit-boundary model");
    } else {
        println!("❌ {} TESTS FAILED:", failed_tests.len());
        for (test_name, error) in &failed_tests {
            println!("   {} - {}", test_name, error);
        }
        std::process::exit(1);
    }
}

/// Our test representation of Histogram data.
#[derive(Debug, Clone, PartialEq)]
struct HistogramDataPoint {
    name: String,
    bucket_counts: Vec<u64>,
    bucket_boundaries: Vec<f64>,
    count: u64,
    sum: f64,
    min: Option<f64>,
    max: Option<f64>,
}

/// Test our Histogram aggregator implementation.
fn test_our_histogram_aggregator(test_case: &HistogramAggregatorTestCase) -> HistogramDataPoint {
    let mut metrics = Metrics::new();
    let histogram = metrics.histogram(
        test_case.histogram_name,
        test_case.bucket_boundaries.clone(),
    );

    for &value in &test_case.observations {
        histogram.observe(value);
    }

    histogram_data_from_snapshot(histogram.snapshot())
}

/// Test the deterministic explicit-boundary reference model.
fn test_reference_histogram_aggregator(
    test_case: &HistogramAggregatorTestCase,
) -> HistogramDataPoint {
    let mut boundaries = test_case.bucket_boundaries.clone();
    boundaries.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    let mut bucket_counts = vec![0; boundaries.len() + 1];
    let mut sum = 0.0;

    for &value in &test_case.observations {
        let bucket_index = boundaries
            .iter()
            .position(|&boundary| value <= boundary)
            .unwrap_or(boundaries.len());
        bucket_counts[bucket_index] += 1;
        sum += value;
    }

    HistogramDataPoint {
        name: test_case.histogram_name.to_string(),
        bucket_counts,
        bucket_boundaries: boundaries,
        count: observation_count(test_case.observations.len()),
        sum,
        min: None,
        max: None,
    }
}

fn histogram_data_from_snapshot(snapshot: HistogramSnapshot) -> HistogramDataPoint {
    HistogramDataPoint {
        name: snapshot.name,
        bucket_counts: snapshot.bucket_counts,
        bucket_boundaries: snapshot.bucket_boundaries,
        count: snapshot.count,
        sum: snapshot.sum,
        min: None,
        max: None,
    }
}

/// Compare Histogram data from our implementation vs reference.
fn compare_histogram_data(
    our_point: &HistogramDataPoint,
    ref_point: &HistogramDataPoint,
    test_case: &HistogramAggregatorTestCase,
) -> Result<(), String> {
    if our_point.name != ref_point.name {
        return Err(format!(
            "Histogram name mismatch for {}: our={}, reference={}",
            test_case.name, our_point.name, ref_point.name
        ));
    }

    if !bucket_boundaries_equal(&our_point.bucket_boundaries, &ref_point.bucket_boundaries) {
        return Err(format!(
            "Bucket boundaries mismatch for {}: our={:?}, reference={:?}",
            test_case.name, our_point.bucket_boundaries, ref_point.bucket_boundaries
        ));
    }

    if our_point.bucket_counts != ref_point.bucket_counts {
        return Err(format!(
            "Bucket counts mismatch for {}: our={:?}, reference={:?}",
            test_case.name, our_point.bucket_counts, ref_point.bucket_counts
        ));
    }

    if our_point.count != ref_point.count {
        return Err(format!(
            "Total count mismatch for {}: our={}, reference={}",
            test_case.name, our_point.count, ref_point.count
        ));
    }

    if !values_equal(our_point.sum, ref_point.sum, 1e-10) {
        return Err(format!(
            "Sum mismatch for {}: our={}, reference={}",
            test_case.name, our_point.sum, ref_point.sum
        ));
    }

    if our_point.min != ref_point.min || our_point.max != ref_point.max {
        return Err(format!(
            "Min/max support mismatch for {}: our=({:?}, {:?}), reference=({:?}, {:?})",
            test_case.name, our_point.min, our_point.max, ref_point.min, ref_point.max
        ));
    }

    Ok(())
}

/// Check if two bucket boundary arrays are equal within tolerance.
fn bucket_boundaries_equal(a: &[f64], b: &[f64]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    for (a_val, b_val) in a.iter().zip(b.iter()) {
        if !values_equal(*a_val, *b_val, 1e-10) {
            return false;
        }
    }

    true
}

/// Check if two floating-point values are equal within tolerance.
fn values_equal(a: f64, b: f64, tolerance: f64) -> bool {
    if a.is_infinite() && b.is_infinite() && a.signum() == b.signum() {
        return true;
    }
    if a.is_nan() && b.is_nan() {
        return true;
    }
    (a - b).abs() <= tolerance
}

/// OpenTelemetry-style default explicit histogram bucket boundaries.
fn default_explicit_boundaries() -> Vec<f64> {
    vec![
        0.0, 5.0, 10.0, 25.0, 50.0, 75.0, 100.0, 250.0, 500.0, 750.0, 1000.0, 2500.0, 5000.0,
        7500.0, 10000.0,
    ]
}

fn observation_count(len: usize) -> u64 {
    u64::try_from(len).expect("histogram conformance observation count fits u64")
}

/// Test edge cases for Histogram aggregator.
fn test_histogram_aggregator_edge_cases(failed_tests: &mut Vec<(String, String)>) {
    // Test empty histogram
    let empty_case = HistogramAggregatorTestCase {
        name: "empty_histogram",
        histogram_name: "empty_test",
        observations: vec![],
        bucket_boundaries: default_explicit_boundaries(),
        description: "Empty histogram with no observations",
    };

    let our_data = test_our_histogram_aggregator(&empty_case);
    let reference_data = test_reference_histogram_aggregator(&empty_case);

    if let Err(error) = compare_histogram_data(&our_data, &reference_data, &empty_case) {
        failed_tests.push(("empty_histogram".to_string(), error));
    } else {
        println!("    ✅ empty_histogram");
    }

    // Test zero values
    let zero_case = HistogramAggregatorTestCase {
        name: "zero_values",
        histogram_name: "zero_test",
        observations: vec![0.0, 0.0, 0.0],
        bucket_boundaries: vec![0.1, 1.0, 10.0],
        description: "Multiple zero value observations",
    };

    let our_data = test_our_histogram_aggregator(&zero_case);
    let reference_data = test_reference_histogram_aggregator(&zero_case);

    if let Err(error) = compare_histogram_data(&our_data, &reference_data, &zero_case) {
        failed_tests.push(("zero_values".to_string(), error));
    } else {
        println!("    ✅ zero_values");
    }
}
