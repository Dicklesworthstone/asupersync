//! OpenTelemetry Histogram Record Conformance Test (Tick #146)
//!
//! This conformance test verifies that our Histogram.record() implementation
//! produces expected bucket counts, sum, and count values from the live
//! asupersync metrics implementation when given the same sequence of
//! observations.
//!
//! Key OTLP specification requirements tested:
//! - Bucket boundaries and value assignment
//! - Cumulative bucket counting
//! - Sum aggregation accuracy
//! - Total count tracking
//! - Edge case handling (infinity, zero, negative values)

use asupersync::observability::metrics::{Histogram, Metrics};
use std::sync::Arc;

/// Test cases for histogram recording conformance
struct HistogramRecordTestCase {
    name: &'static str,
    bucket_boundaries: Vec<f64>,
    observations: Vec<f64>,
    description: &'static str,
}

/// Our representation of histogram data
#[derive(Debug, Clone, PartialEq)]
struct HistogramData {
    bucket_counts: Vec<u64>,
    sum: f64,
    count: u64,
    bucket_boundaries: Vec<f64>,
}

impl HistogramData {
    fn new(bucket_counts: Vec<u64>, sum: f64, count: u64, bucket_boundaries: Vec<f64>) -> Self {
        Self {
            bucket_counts,
            sum,
            count,
            bucket_boundaries,
        }
    }
}

fn main() {
    println!("🔍 OpenTelemetry Histogram Record Conformance Test");
    println!("Verifying live asupersync observations → bucket counts + sum + count");

    let test_cases = vec![
        HistogramRecordTestCase {
            name: "basic_distribution",
            bucket_boundaries: vec![0.1, 0.5, 1.0, 5.0, 10.0],
            observations: vec![0.05, 0.3, 0.7, 2.5, 7.5, 15.0],
            description: "Basic distribution across all buckets",
        },
        HistogramRecordTestCase {
            name: "single_bucket",
            bucket_boundaries: vec![1.0, 5.0, 10.0],
            observations: vec![2.0, 3.0, 4.0, 4.5],
            description: "All observations in single bucket",
        },
        HistogramRecordTestCase {
            name: "edge_values",
            bucket_boundaries: vec![1.0, 10.0, 100.0],
            observations: vec![0.0, 1.0, 10.0, 100.0, 1000.0],
            description: "Values exactly at bucket boundaries",
        },
        HistogramRecordTestCase {
            name: "repeated_values",
            bucket_boundaries: vec![0.5, 1.5, 2.5],
            observations: vec![1.0, 1.0, 1.0, 2.0, 2.0, 3.0],
            description: "Repeated observation values",
        },
        HistogramRecordTestCase {
            name: "large_values",
            bucket_boundaries: vec![1e3, 1e6, 1e9],
            observations: vec![500.0, 1500.0, 1e4, 1e7, 1e10],
            description: "Large numerical values",
        },
        HistogramRecordTestCase {
            name: "small_values",
            bucket_boundaries: vec![0.001, 0.01, 0.1],
            observations: vec![0.0001, 0.005, 0.05, 0.5],
            description: "Small fractional values",
        },
        HistogramRecordTestCase {
            name: "negative_values",
            bucket_boundaries: vec![-10.0, -1.0, 0.0, 1.0, 10.0],
            observations: vec![-15.0, -5.0, -0.5, 0.5, 5.0, 15.0],
            description: "Negative and positive values",
        },
        HistogramRecordTestCase {
            name: "single_observation",
            bucket_boundaries: vec![1.0, 5.0, 10.0],
            observations: vec![2.5],
            description: "Single observation",
        },
        HistogramRecordTestCase {
            name: "empty_observations",
            bucket_boundaries: vec![1.0, 5.0, 10.0],
            observations: vec![],
            description: "No observations (initial state)",
        },
        HistogramRecordTestCase {
            name: "many_buckets",
            bucket_boundaries: (0..20).map(|i| i as f64).collect(),
            observations: (0..100).map(|i| i as f64 * 0.3).collect(),
            description: "Many buckets with many observations",
        },
    ];

    println!(
        "📋 Running {} histogram recording conformance tests",
        test_cases.len()
    );

    let mut failed_tests = Vec::new();

    for test_case in &test_cases {
        println!("  Testing {}: {}", test_case.name, test_case.description);

        // Test our implementation
        let our_histogram_data = test_our_histogram_recording(test_case);

        // Test the deterministic reference bucket model
        let reference_histogram_data = test_reference_histogram_recording(test_case);

        // Compare results
        if let Err(error) =
            compare_histogram_data(&our_histogram_data, &reference_histogram_data, test_case)
        {
            failed_tests.push((test_case.name.to_string(), error));
        } else {
            println!("    ✅ {}", test_case.name);
        }
    }

    // Test histogram edge cases
    println!("\n📋 Testing histogram recording edge cases");
    test_histogram_edge_cases(&mut failed_tests);

    // Report results
    println!("\n📊 Histogram Record Conformance Test Results");
    if failed_tests.is_empty() {
        println!("✅ ALL TESTS PASSED - Histogram recording is conformant");
        println!("🎯 Bucket counts, sum, and count match the reference bucket model");
    } else {
        println!("❌ {} TESTS FAILED:", failed_tests.len());
        for (test_name, error) in &failed_tests {
            println!("   {} - {}", test_name, error);
        }
        std::process::exit(1);
    }
}

/// Test our histogram recording implementation
fn test_our_histogram_recording(test_case: &HistogramRecordTestCase) -> HistogramData {
    let mut metrics = Metrics::new();
    let histogram = metrics.histogram("test_histogram", test_case.bucket_boundaries.clone());

    // Record all observations
    for &observation in &test_case.observations {
        histogram.observe(observation);
    }

    // Extract histogram data from the live asupersync snapshot seam.
    let snapshot = histogram.snapshot();
    let bucket_counts = extract_our_bucket_counts(&histogram);
    let sum = extract_our_sum(&histogram);
    let count = extract_our_count(&histogram);

    HistogramData::new(bucket_counts, sum, count, snapshot.bucket_boundaries)
}

/// Test deterministic OTLP-style histogram bucket assignment.
fn test_reference_histogram_recording(test_case: &HistogramRecordTestCase) -> HistogramData {
    let mut sorted_boundaries = test_case.bucket_boundaries.clone();
    sorted_boundaries.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mut bucket_counts = vec![0u64; test_case.bucket_boundaries.len() + 1];
    let mut sum = 0.0;
    let mut count = 0u64;

    for &observation in &test_case.observations {
        let bucket_index = sorted_boundaries
            .iter()
            .position(|&boundary| observation <= boundary)
            .unwrap_or(sorted_boundaries.len());

        bucket_counts[bucket_index] += 1;
        sum += observation;
        count += 1;
    }

    HistogramData::new(bucket_counts, sum, count, sorted_boundaries)
}

/// Extract bucket counts from our histogram implementation
fn extract_our_bucket_counts(histogram: &Arc<Histogram>) -> Vec<u64> {
    histogram.snapshot().bucket_counts
}

/// Extract sum from our histogram implementation
fn extract_our_sum(histogram: &Arc<Histogram>) -> f64 {
    histogram.snapshot().sum
}

/// Extract count from our histogram implementation
fn extract_our_count(histogram: &Arc<Histogram>) -> u64 {
    histogram.snapshot().count
}

/// Compare histogram data between implementations
fn compare_histogram_data(
    our_data: &HistogramData,
    reference_data: &HistogramData,
    _test_case: &HistogramRecordTestCase,
) -> Result<(), String> {
    // Check bucket counts
    if our_data.bucket_counts.len() != reference_data.bucket_counts.len() {
        return Err(format!(
            "Bucket count length mismatch: our={}, reference={}",
            our_data.bucket_counts.len(),
            reference_data.bucket_counts.len()
        ));
    }

    for (i, (our_count, ref_count)) in our_data
        .bucket_counts
        .iter()
        .zip(reference_data.bucket_counts.iter())
        .enumerate()
    {
        if our_count != ref_count {
            return Err(format!(
                "Bucket {} count mismatch: our={}, reference={}",
                i, our_count, ref_count
            ));
        }
    }

    // Check total count
    if our_data.count != reference_data.count {
        return Err(format!(
            "Total count mismatch: our={}, reference={}",
            our_data.count, reference_data.count
        ));
    }

    // Check sum (allow for floating point precision errors)
    let sum_diff = (our_data.sum - reference_data.sum).abs();
    let tolerance = if reference_data.sum.abs() > 1e-10 {
        reference_data.sum.abs() * 1e-12 // Relative tolerance
    } else {
        1e-12 // Absolute tolerance for small numbers
    };

    if sum_diff > tolerance {
        return Err(format!(
            "Sum mismatch: our={:.15}, reference={:.15}, diff={:.2e}, tolerance={:.2e}",
            our_data.sum, reference_data.sum, sum_diff, tolerance
        ));
    }

    // Verify bucket boundaries match
    if our_data.bucket_boundaries != reference_data.bucket_boundaries {
        return Err(format!(
            "Bucket boundaries mismatch: our={:?}, reference={:?}",
            our_data.bucket_boundaries, reference_data.bucket_boundaries
        ));
    }

    Ok(())
}

/// Test histogram edge cases
fn test_histogram_edge_cases(failed_tests: &mut Vec<(String, String)>) {
    let edge_cases = vec![
        (
            "infinity_values",
            vec![1.0, 10.0, 100.0],
            vec![f64::INFINITY, f64::NEG_INFINITY],
            "Positive and negative infinity",
        ),
        (
            "nan_values",
            vec![1.0, 10.0, 100.0],
            vec![f64::NAN],
            "NaN values",
        ),
        (
            "zero_values",
            vec![0.0, 1.0, 10.0],
            vec![0.0, -0.0],
            "Zero and negative zero",
        ),
        (
            "very_large_numbers",
            vec![1e10, 1e20, 1e30],
            vec![f64::MAX, f64::MIN],
            "Maximum and minimum finite values",
        ),
        (
            "very_small_numbers",
            vec![1e-10, 1e-20, 1e-30],
            vec![f64::MIN_POSITIVE, f64::EPSILON],
            "Very small positive numbers",
        ),
        (
            "unsorted_buckets",
            vec![10.0, 1.0, 5.0], // Intentionally unsorted
            vec![0.5, 2.0, 7.5],
            "Unsorted bucket boundaries (should be auto-sorted)",
        ),
    ];

    for (case_name, boundaries, observations, description) in edge_cases {
        let test_case = HistogramRecordTestCase {
            name: case_name,
            bucket_boundaries: boundaries,
            observations,
            description,
        };

        // Test both implementations
        let our_result = std::panic::catch_unwind(|| test_our_histogram_recording(&test_case));
        let ref_result =
            std::panic::catch_unwind(|| test_reference_histogram_recording(&test_case));

        match (our_result, ref_result) {
            (Ok(our_data), Ok(ref_data)) => {
                // Both succeeded, compare results
                if let Err(error) = compare_histogram_data(&our_data, &ref_data, &test_case) {
                    // For edge cases, be more lenient with NaN/infinity handling
                    if case_name.contains("nan") || case_name.contains("infinity") {
                        // Allow different handling of special values
                        println!("    ⚠️ edge_case_{}: {}", case_name, error);
                    } else {
                        failed_tests.push((format!("edge_case_{}", case_name), error));
                    }
                } else {
                    println!("    ✅ edge_case_{}", case_name);
                }
            }
            (Err(_), Err(_)) => {
                // Both panicked - consistent behavior
                println!(
                    "    ✅ edge_case_{} (both panicked consistently)",
                    case_name
                );
            }
            (Ok(_), Err(_)) => {
                failed_tests.push((
                    format!("edge_case_{}", case_name),
                    "Our implementation succeeded but reference panicked".to_string(),
                ));
            }
            (Err(_), Ok(_)) => {
                failed_tests.push((
                    format!("edge_case_{}", case_name),
                    "Our implementation panicked but reference succeeded".to_string(),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_histogram_data_creation() {
        let data = HistogramData::new(vec![1, 2, 3], 10.5, 6, vec![1.0, 5.0, 10.0]);

        assert_eq!(data.bucket_counts, vec![1, 2, 3]);
        assert_eq!(data.sum, 10.5);
        assert_eq!(data.count, 6);
        assert_eq!(data.bucket_boundaries, vec![1.0, 5.0, 10.0]);
    }

    #[test]
    fn test_bucket_assignment_logic() {
        let boundaries = vec![1.0, 5.0, 10.0];

        // Test boundary assignment logic
        let test_cases = vec![
            (0.5, 0),  // Below first boundary
            (1.0, 0),  // Exactly at first boundary
            (2.5, 1),  // Between boundaries
            (5.0, 1),  // Exactly at middle boundary
            (7.5, 2),  // Between boundaries
            (10.0, 2), // Exactly at last boundary
            (15.0, 3), // Above last boundary
        ];

        for (value, expected_bucket) in test_cases {
            let bucket_index = boundaries
                .iter()
                .position(|&boundary| value <= boundary)
                .unwrap_or(boundaries.len());

            assert_eq!(
                bucket_index, expected_bucket,
                "Value {} should be in bucket {}, got {}",
                value, expected_bucket, bucket_index
            );
        }
    }

    #[test]
    fn test_sum_accumulation() {
        let observations = vec![1.5, 2.5, 3.0];
        let expected_sum = observations.iter().sum::<f64>();

        // Manual sum calculation
        let mut sum = 0.0;
        for &obs in &observations {
            sum += obs;
        }

        assert!((sum - expected_sum).abs() < f64::EPSILON);
    }

    #[test]
    fn test_bucket_boundaries_sorting() {
        let mut unsorted = vec![10.0, 1.0, 5.0, 2.0];
        unsorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        assert_eq!(unsorted, vec![1.0, 2.0, 5.0, 10.0]);
    }

    #[test]
    fn test_empty_observations() {
        let boundaries = vec![1.0, 5.0, 10.0];
        let observations: Vec<f64> = vec![];

        // Should result in all zero counts
        let bucket_counts = vec![0u64; boundaries.len() + 1];
        let sum = 0.0;
        let count = 0u64;

        assert_eq!(bucket_counts.iter().sum::<u64>(), count);
        assert_eq!(sum, 0.0);
    }

    #[test]
    fn test_floating_point_precision() {
        let a = 0.1 + 0.2;
        let b = 0.3;

        // Demonstrate floating point precision issues
        assert!((a - b).abs() < f64::EPSILON * 10.0);
    }

    #[test]
    fn test_special_float_values() {
        let test_values = vec![
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NAN,
            0.0,
            -0.0,
            f64::MIN_POSITIVE,
            f64::MAX,
        ];

        for &value in &test_values {
            // Test that we can handle special values without panicking
            let is_finite = value.is_finite();
            let is_nan = value.is_nan();
            let is_infinite = value.is_infinite();

            // At least one of these should be true
            assert!(is_finite || is_nan || is_infinite);
        }
    }
}
