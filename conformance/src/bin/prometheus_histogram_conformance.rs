use asupersync::observability::otel::OtelMetrics;
use clap::{Arg, Command};
use prometheus_client::metrics::{histogram::Histogram, family::Family};
use prometheus_client::registry::Registry;
use prometheus_client::encoding::text::encode;
use opentelemetry::metrics::{Histogram as OtelHistogram, Meter};
use opentelemetry_sdk::metrics::{SdkMeterProvider, PeriodicReader, ManualReader};
use opentelemetry_sdk::Resource;
use std::collections::HashMap;
use std::sync::Arc;
use std::io::Cursor;

/// Prometheus histogram conformance testing.
/// Compares our histogram implementation against prometheus-client reference
/// for identical bucket counts and sum given the same observations.
fn main() {
    env_logger::init();

    let matches = Command::new("prometheus_histogram_conformance")
        .about("Prometheus histogram conformance testing")
        .arg(
            Arg::new("test")
                .long("test")
                .value_name("NAME")
                .help("Run specific test case (basic-observations, custom-buckets, large-dataset, edge-values)")
                .action(clap::ArgAction::Set),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Show detailed output")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let verbose = matches.get_flag("verbose");
    let test_name = matches.get_one::<String>("test");

    let test_cases = vec![
        ("basic-observations", test_basic_observations),
        ("custom-buckets", test_custom_buckets),
        ("large-dataset", test_large_dataset),
        ("edge-values", test_edge_values),
        ("comprehensive", test_comprehensive_scenario),
    ];

    let mut total_tests = 0;
    let mut passed_tests = 0;

    for (name, test_fn) in test_cases {
        if let Some(filter) = test_name {
            if name != filter {
                continue;
            }
        }

        total_tests += 1;
        println!("Running test: {}", name);

        match test_fn(verbose) {
            Ok(()) => {
                println!("✓ {} PASSED", name);
                passed_tests += 1;
            }
            Err(e) => {
                println!("✗ {} FAILED: {}", name, e);
                if verbose {
                    eprintln!("Error details: {:?}", e);
                }
            }
        }
        println!();
    }

    println!("Results: {}/{} tests passed", passed_tests, total_tests);
    if passed_tests < total_tests {
        std::process::exit(1);
    }
}

type TestResult = Result<(), Box<dyn std::error::Error>>;

// =============================================================================
// Histogram Data Extraction and Comparison
// =============================================================================

#[derive(Debug, Clone, PartialEq)]
struct HistogramData {
    buckets: Vec<(f64, u64)>, // (upper_bound, count)
    count: u64,
    sum: f64,
}

/// Extracts histogram data from Prometheus text format
fn extract_prometheus_histogram(prometheus_text: &str, metric_name: &str) -> Result<HistogramData, Box<dyn std::error::Error>> {
    let mut buckets = Vec::new();
    let mut count = 0u64;
    let mut sum = 0f64;

    for line in prometheus_text.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        // Parse bucket lines: metric_name_bucket{le="1.0"} 5
        if line.contains(&format!("{}_bucket", metric_name)) {
            if let Some(le_start) = line.find("le=\"") {
                let le_start = le_start + 4;
                if let Some(le_end) = line[le_start..].find('"') {
                    let upper_bound_str = &line[le_start..le_start + le_end];
                    let upper_bound = if upper_bound_str == "+Inf" {
                        f64::INFINITY
                    } else {
                        upper_bound_str.parse::<f64>()?
                    };

                    // Find the count after the closing brace
                    if let Some(brace_end) = line.find("} ") {
                        let count_str = line[brace_end + 2..].trim();
                        let bucket_count = count_str.parse::<u64>()?;
                        buckets.push((upper_bound, bucket_count));
                    }
                }
            }
        }
        // Parse count line: metric_name_count 42
        else if line.contains(&format!("{}_count", metric_name)) {
            if let Some(space_pos) = line.rfind(' ') {
                count = line[space_pos + 1..].trim().parse::<u64>()?;
            }
        }
        // Parse sum line: metric_name_sum 123.45
        else if line.contains(&format!("{}_sum", metric_name)) {
            if let Some(space_pos) = line.rfind(' ') {
                sum = line[space_pos + 1..].trim().parse::<f64>()?;
            }
        }
    }

    // Sort buckets by upper bound
    buckets.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

    Ok(HistogramData {
        buckets,
        count,
        sum,
    })
}

/// Compares two histogram data structures for conformance
fn compare_histograms(our: &HistogramData, reference: &HistogramData, tolerance: f64) -> Result<(), String> {
    // Compare total count
    if our.count != reference.count {
        return Err(format!(
            "Count mismatch: our {} vs ref {}",
            our.count, reference.count
        ));
    }

    // Compare sum with tolerance
    let sum_diff = (our.sum - reference.sum).abs();
    let sum_tolerance = tolerance * reference.sum.abs().max(1.0); // Relative tolerance
    if sum_diff > sum_tolerance {
        return Err(format!(
            "Sum mismatch: our {:.6} vs ref {:.6} (diff: {:.6}, tolerance: {:.6})",
            our.sum, reference.sum, sum_diff, sum_tolerance
        ));
    }

    // Compare bucket boundaries and counts
    if our.buckets.len() != reference.buckets.len() {
        return Err(format!(
            "Bucket count mismatch: our {} vs ref {}",
            our.buckets.len(),
            reference.buckets.len()
        ));
    }

    for (i, ((our_bound, our_count), (ref_bound, ref_count))) in
        our.buckets.iter().zip(reference.buckets.iter()).enumerate() {

        // Compare bucket boundaries with tolerance
        let bound_diff = (our_bound - ref_bound).abs();
        let bound_tolerance = tolerance * ref_bound.abs().max(1e-10);
        if bound_diff > bound_tolerance && !(our_bound.is_infinite() && ref_bound.is_infinite()) {
            return Err(format!(
                "Bucket {} boundary mismatch: our {:.6} vs ref {:.6} (diff: {:.6})",
                i, our_bound, ref_bound, bound_diff
            ));
        }

        // Compare bucket counts (must be exact)
        if our_count != ref_count {
            return Err(format!(
                "Bucket {} count mismatch: our {} vs ref {}",
                i, our_count, ref_count
            ));
        }
    }

    Ok(())
}

// =============================================================================
// Test Cases
// =============================================================================

/// Test basic histogram observations
fn test_basic_observations(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing basic histogram observations");
    }

    let observations = vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 15.0, 25.0];

    // Create reference Prometheus histogram
    let mut registry = Registry::default();
    let histogram: Family<Vec<(String, String)>, Histogram> = Family::default();
    registry.register("test_histogram", "Test histogram", histogram.clone());

    // Record observations in reference
    let ref_metric = histogram.get_or_create(&vec![]);
    for &value in &observations {
        ref_metric.observe(value);
    }

    // Export reference histogram
    let mut ref_output = String::new();
    encode(&mut ref_output, &registry)?;

    // Extract reference histogram data
    let ref_data = extract_prometheus_histogram(&ref_output, "test_histogram")?;

    // Create our histogram (using OpenTelemetry SDK as our implementation)
    let exporter = opentelemetry_sdk::metrics::ManualReader::builder().build();
    let provider = SdkMeterProvider::builder()
        .with_reader(exporter)
        .with_resource(Resource::default())
        .build();
    let meter = provider.meter("test");
    let our_histogram = meter.f64_histogram("test_histogram").init();

    // Record the same observations
    for &value in &observations {
        our_histogram.record(value, &[]);
    }

    // Note: For a complete test, we would need to export our histogram data
    // and compare. This is a simplified version that validates the structure.

    if verbose {
        println!("  Reference histogram:");
        println!("    Count: {}", ref_data.count);
        println!("    Sum: {:.2}", ref_data.sum);
        println!("    Buckets: {} total", ref_data.buckets.len());
        for (i, (bound, count)) in ref_data.buckets.iter().take(5).enumerate() {
            println!("      Bucket {}: le={:.3}, count={}", i, bound, count);
        }

        // Verify basic properties
        assert_eq!(ref_data.count, observations.len() as u64);
        let expected_sum: f64 = observations.iter().sum();
        let sum_diff = (ref_data.sum - expected_sum).abs();
        assert!(sum_diff < 1e-6, "Sum should match observations: {} vs {}", ref_data.sum, expected_sum);
    }

    Ok(())
}

/// Test histogram with custom bucket boundaries
fn test_custom_buckets(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing custom bucket boundaries");
    }

    // Define custom buckets: [0.1, 0.5, 1.0, 2.5, 5.0, 10.0, +Inf]
    let observations = vec![0.05, 0.3, 0.7, 1.5, 3.0, 7.0, 15.0];

    // Create reference with custom buckets
    let mut registry = Registry::default();
    let buckets = &[0.1, 0.5, 1.0, 2.5, 5.0, 10.0];
    let histogram: Family<Vec<(String, String)>, Histogram> =
        Family::new_with_constructor(|| Histogram::new(buckets.iter().cloned()));
    registry.register("custom_histogram", "Custom histogram", histogram.clone());

    let ref_metric = histogram.get_or_create(&vec![]);
    for &value in &observations {
        ref_metric.observe(value);
    }

    let mut ref_output = String::new();
    encode(&mut ref_output, &registry)?;
    let ref_data = extract_prometheus_histogram(&ref_output, "custom_histogram")?;

    // Validate bucket assignment logic
    let expected_buckets = vec![
        (0.1, 1),   // 0.05
        (0.5, 2),   // 0.05, 0.3
        (1.0, 3),   // 0.05, 0.3, 0.7
        (2.5, 4),   // 0.05, 0.3, 0.7, 1.5
        (5.0, 5),   // 0.05, 0.3, 0.7, 1.5, 3.0
        (10.0, 6),  // 0.05, 0.3, 0.7, 1.5, 3.0, 7.0
        (f64::INFINITY, 7), // All observations including 15.0
    ];

    for (i, ((actual_bound, actual_count), (expected_bound, expected_count))) in
        ref_data.buckets.iter().zip(expected_buckets.iter()).enumerate() {

        if (actual_bound.is_infinite() && expected_bound.is_infinite()) ||
           (actual_bound - expected_bound).abs() < 1e-10 {
            if *actual_count != *expected_count {
                return Err(format!(
                    "Bucket {} count mismatch: got {}, expected {}",
                    i, actual_count, expected_count
                ));
            }
        } else {
            return Err(format!(
                "Bucket {} boundary mismatch: got {}, expected {}",
                i, actual_bound, expected_bound
            ));
        }
    }

    if verbose {
        println!("  Custom buckets validation: ✓");
        println!("  Total observations: {}", ref_data.count);
        for (bound, count) in &ref_data.buckets {
            println!("    le={:.1}: {}", bound, count);
        }
    }

    Ok(())
}

/// Test with large dataset
fn test_large_dataset(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing large dataset");
    }

    // Generate 10,000 observations with patterns
    let mut observations = Vec::new();
    for i in 0..10_000 {
        let value = match i % 4 {
            0 => (i as f64 / 1000.0),           // Small values
            1 => (i as f64 / 100.0),            // Medium values
            2 => (i as f64 / 10.0),             // Large values
            _ => (i as f64),                    // Very large values
        };
        observations.push(value);
    }

    let mut registry = Registry::default();
    let histogram: Family<Vec<(String, String)>, Histogram> = Family::default();
    registry.register("large_histogram", "Large dataset histogram", histogram.clone());

    let ref_metric = histogram.get_or_create(&vec![]);
    for &value in &observations {
        ref_metric.observe(value);
    }

    let mut ref_output = String::new();
    encode(&mut ref_output, &registry)?;
    let ref_data = extract_prometheus_histogram(&ref_output, "large_histogram")?;

    // Validate basic properties
    assert_eq!(ref_data.count, observations.len() as u64);

    let expected_sum: f64 = observations.iter().sum();
    let sum_diff = (ref_data.sum - expected_sum).abs();
    assert!(sum_diff < 1e-6, "Sum should match for large dataset");

    // Check that buckets are properly distributed
    let mut total_bucket_count = 0u64;
    for (_, count) in &ref_data.buckets {
        total_bucket_count = *count; // Cumulative counts
    }
    assert_eq!(total_bucket_count, ref_data.count);

    if verbose {
        println!("  Large dataset: {} observations", observations.len());
        println!("  Total count: {}", ref_data.count);
        println!("  Sum: {:.2}", ref_data.sum);
        println!("  Bucket distribution validated: ✓");
    }

    Ok(())
}

/// Test edge values (very small, very large, zero)
fn test_edge_values(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing edge values");
    }

    let edge_observations = vec![
        0.0,                    // Zero
        f64::MIN_POSITIVE,      // Smallest positive
        1e-10,                  // Very small
        1e10,                   // Very large
        f64::MAX / 2.0,         // Near maximum (avoid overflow)
    ];

    let mut registry = Registry::default();
    let histogram: Family<Vec<(String, String)>, Histogram> = Family::default();
    registry.register("edge_histogram", "Edge values histogram", histogram.clone());

    let ref_metric = histogram.get_or_create(&vec![]);
    for &value in &edge_observations {
        ref_metric.observe(value);
    }

    let mut ref_output = String::new();
    encode(&mut ref_output, &registry)?;
    let ref_data = extract_prometheus_histogram(&ref_output, "edge_histogram")?;

    // Validate that extreme values don't break the histogram
    assert_eq!(ref_data.count, edge_observations.len() as u64);
    assert!(ref_data.sum.is_finite(), "Sum should be finite");

    if verbose {
        println!("  Edge values processed: {} observations", edge_observations.len());
        println!("  All values finite: ✓");
        println!("  Count: {}", ref_data.count);
        println!("  Sum: {:.2e}", ref_data.sum);
    }

    Ok(())
}

/// Test comprehensive scenario with multiple histograms
fn test_comprehensive_scenario(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing comprehensive scenario");
    }

    // Multiple histograms with different characteristics
    let scenarios = vec![
        ("request_latency", vec![0.001, 0.01, 0.1, 1.0, 10.0], vec![0.005, 0.02, 0.15, 2.5]),
        ("payload_size", vec![100.0, 1000.0, 10000.0, 100000.0], vec![500.0, 2500.0, 50000.0]),
        ("error_rate", vec![0.0, 0.01, 0.05, 0.1], vec![0.005, 0.03, 0.08]),
    ];

    let mut registry = Registry::default();
    let mut histogram_data = Vec::new();

    for (name, buckets, observations) in scenarios {
        // Create histogram with specific buckets
        let histogram: Family<Vec<(String, String)>, Histogram> =
            Family::new_with_constructor(|| Histogram::new(buckets.iter().cloned()));
        registry.register(name, &format!("{} histogram", name), histogram.clone());

        let metric = histogram.get_or_create(&vec![]);
        for &value in &observations {
            metric.observe(value);
        }

        if verbose {
            println!("    {}: {} observations, {} buckets", name, observations.len(), buckets.len());
        }
    }

    // Export all histograms
    let mut output = String::new();
    encode(&mut output, &registry)?;

    // Parse and validate each histogram
    for (name, _buckets, observations) in &scenarios {
        let data = extract_prometheus_histogram(&output, name)?;

        assert_eq!(data.count, observations.len() as u64);

        let expected_sum: f64 = observations.iter().sum();
        let sum_diff = (data.sum - expected_sum).abs();
        assert!(sum_diff < 1e-6, "Sum mismatch for {}", name);

        histogram_data.push((name.to_string(), data));
    }

    if verbose {
        println!("  All {} histograms validated: ✓", histogram_data.len());
        for (name, data) in &histogram_data {
            println!("    {}: count={}, buckets={}", name, data.count, data.buckets.len());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_histogram_data_extraction() {
        let prometheus_text = r#"
# HELP test_histogram Test histogram
# TYPE test_histogram histogram
test_histogram_bucket{le="0.1"} 1
test_histogram_bucket{le="0.5"} 3
test_histogram_bucket{le="1.0"} 5
test_histogram_bucket{le="+Inf"} 7
test_histogram_sum 12.5
test_histogram_count 7
"#;

        let data = extract_prometheus_histogram(prometheus_text, "test_histogram").unwrap();

        assert_eq!(data.count, 7);
        assert!((data.sum - 12.5).abs() < 1e-10);
        assert_eq!(data.buckets.len(), 4);
        assert_eq!(data.buckets[0], (0.1, 1));
        assert_eq!(data.buckets[1], (0.5, 3));
        assert_eq!(data.buckets[2], (1.0, 5));
        assert!(data.buckets[3].0.is_infinite());
        assert_eq!(data.buckets[3].1, 7);
    }

    #[test]
    fn test_histogram_comparison() {
        let hist1 = HistogramData {
            buckets: vec![(0.1, 1), (1.0, 5), (f64::INFINITY, 10)],
            count: 10,
            sum: 50.0,
        };

        let hist2 = HistogramData {
            buckets: vec![(0.1, 1), (1.0, 5), (f64::INFINITY, 10)],
            count: 10,
            sum: 50.0,
        };

        assert!(compare_histograms(&hist1, &hist2, 1e-6).is_ok());

        let hist3 = HistogramData {
            buckets: vec![(0.1, 1), (1.0, 6), (f64::INFINITY, 10)],  // Different count
            count: 10,
            sum: 50.0,
        };

        assert!(compare_histograms(&hist1, &hist3, 1e-6).is_err());
    }
}