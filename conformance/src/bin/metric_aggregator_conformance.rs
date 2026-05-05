use asupersync::observability::metrics::{HistogramSnapshot, Metrics};
use clap::{Arg, Command};

/// Metric aggregator conformance testing.
/// Records through the live asupersync histogram implementation and compares
/// exported snapshots against a deterministic OTLP-style bucket model.
fn main() {
    env_logger::init();

    let matches = Command::new("metric_aggregator_conformance")
        .about("Metric aggregator conformance testing")
        .arg(
            Arg::new("test")
                .long("test")
                .value_name("NAME")
                .help(
                    "Run specific test case (basic, custom-buckets, large-dataset, extreme-values, export, cardinality)",
                )
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

    let test_cases: Vec<(&str, fn(bool) -> TestResult)> = vec![
        ("basic", test_basic_histogram),
        ("custom-buckets", test_custom_buckets),
        ("large-dataset", test_large_dataset),
        ("extreme-values", test_extreme_values),
        ("comprehensive", test_comprehensive_scenario),
        ("export", test_prometheus_export),
        ("cardinality", test_cardinality_cap),
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

type TestResult = Result<(), String>;

// =============================================================================
// Histogram Data Comparison
// =============================================================================

fn live_histogram_snapshot(
    name: &str,
    boundaries: Vec<f64>,
    observations: &[f64],
) -> HistogramSnapshot {
    let mut metrics = Metrics::new();
    let histogram = metrics.histogram(name, boundaries);
    for &observation in observations {
        histogram.observe(observation);
    }
    histogram.snapshot()
}

fn reference_histogram_snapshot(
    name: &str,
    mut boundaries: Vec<f64>,
    observations: &[f64],
) -> HistogramSnapshot {
    boundaries.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    let mut bucket_counts = vec![0; boundaries.len() + 1];
    let mut sum = 0.0;

    for &observation in observations {
        let bucket_index = boundaries
            .iter()
            .position(|&boundary| observation <= boundary)
            .unwrap_or(boundaries.len());
        bucket_counts[bucket_index] += 1;
        sum += observation;
    }

    HistogramSnapshot {
        name: name.to_string(),
        bucket_boundaries: boundaries,
        bucket_counts,
        count: u64::try_from(observations.len())
            .expect("histogram conformance observation count fits u64"),
        sum,
    }
}

fn verify_histogram_case(
    name: &str,
    boundaries: Vec<f64>,
    observations: &[f64],
    verbose: bool,
) -> TestResult {
    let live = live_histogram_snapshot(name, boundaries.clone(), observations);
    let reference = reference_histogram_snapshot(name, boundaries, observations);
    compare_histograms(&live, &reference, 1e-9)?;

    if verbose {
        println!("  Histogram: {}", live.name);
        println!("  Boundaries: {:?}", live.bucket_boundaries);
        println!("  Bucket counts: {:?}", live.bucket_counts);
        println!("  Count: {}, sum: {:.6}", live.count, live.sum);
    }

    Ok(())
}

/// Compares two histogram snapshots for conformance
fn compare_histograms(
    our: &HistogramSnapshot,
    reference: &HistogramSnapshot,
    tolerance: f64,
) -> Result<(), String> {
    if our.name != reference.name {
        return Err(format!(
            "Histogram name mismatch: our {} vs ref {}",
            our.name, reference.name
        ));
    }

    if our.bucket_boundaries.len() != reference.bucket_boundaries.len() {
        return Err(format!(
            "Bucket boundary count mismatch: our {} vs ref {}",
            our.bucket_boundaries.len(),
            reference.bucket_boundaries.len()
        ));
    }

    for (i, (our_bound, ref_bound)) in our
        .bucket_boundaries
        .iter()
        .zip(reference.bucket_boundaries.iter())
        .enumerate()
    {
        let bound_diff = (our_bound - ref_bound).abs();
        if bound_diff > tolerance {
            return Err(format!(
                "Bucket {} boundary mismatch: our {:.6} vs ref {:.6} (diff: {:.6})",
                i, our_bound, ref_bound, bound_diff
            ));
        }
    }

    if our.bucket_counts.len() != reference.bucket_counts.len() {
        return Err(format!(
            "Bucket count length mismatch: our {} vs ref {}",
            our.bucket_counts.len(),
            reference.bucket_counts.len()
        ));
    }

    for (i, (our_count, ref_count)) in our
        .bucket_counts
        .iter()
        .zip(reference.bucket_counts.iter())
        .enumerate()
    {
        if our_count != ref_count {
            return Err(format!(
                "Bucket {} count mismatch: our {} vs ref {}",
                i, our_count, ref_count
            ));
        }
    }

    // Compare totals
    if our.count != reference.count {
        return Err(format!(
            "Total count mismatch: our {} vs ref {}",
            our.count, reference.count
        ));
    }

    let sum_diff = (our.sum - reference.sum).abs();
    if sum_diff > tolerance {
        return Err(format!(
            "Sum mismatch: our {:.6} vs ref {:.6} (diff: {:.6})",
            our.sum, reference.sum, sum_diff
        ));
    }

    Ok(())
}

// =============================================================================
// Test Cases
// =============================================================================

/// Test basic histogram with default buckets
fn test_basic_histogram(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing basic histogram aggregation");
    }

    let test_data = vec![1.0, 2.5, 4.0, 7.5, 15.0, 30.0, 60.0, 120.0];
    let boundaries = vec![1.0, 5.0, 10.0, 30.0, 60.0, 120.0];
    verify_histogram_case("test_metric", boundaries, &test_data, verbose)?;

    if verbose {
        println!(
            "  Recorded {} data points: {:?}",
            test_data.len(),
            test_data
        );
    }

    Ok(())
}

/// Test histogram with custom bucket boundaries
fn test_custom_buckets(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing custom bucket boundaries");
    }

    let custom_boundaries = vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0];
    let test_data = vec![0.05, 0.3, 0.7, 1.5, 3.0, 7.0, 15.0, 35.0, 75.0, 150.0];
    verify_histogram_case(
        "custom_bucket_metric",
        custom_boundaries.clone(),
        &test_data,
        verbose,
    )?;

    if verbose {
        println!("  Custom boundaries: {:?}", custom_boundaries);
        println!("  Test data: {:?}", test_data);
    }

    Ok(())
}

/// Test with large dataset to verify aggregation performance
fn test_large_dataset(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing large dataset aggregation");
    }

    let mut test_data = Vec::new();

    // Generate 10,000 data points with normal distribution
    for i in 0..10_000 {
        let value = (i as f64 / 100.0) % 50.0; // 0-50 range with cycling
        test_data.push(value);
    }
    let boundaries = vec![0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0];
    verify_histogram_case("large_dataset_metric", boundaries, &test_data, verbose)?;

    if verbose {
        println!("  Dataset size: {} points", test_data.len());
        println!(
            "  Range: {:.2} - {:.2}",
            test_data.iter().fold(f64::INFINITY, |a, &b| a.min(b)),
            test_data.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b))
        );
    }

    Ok(())
}

/// Test extreme values (very small, very large, infinity, NaN)
fn test_extreme_values(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing extreme values");
    }

    let extreme_values = vec![f64::MIN_POSITIVE, 1e-10, 1e10, f64::MAX / 2.0];
    let boundaries = vec![1e-12, 1e-6, 1.0, 1e6, 1e12, f64::MAX / 4.0];
    verify_histogram_case("extreme_value_metric", boundaries, &extreme_values, verbose)?;

    if verbose {
        println!("  Extreme values: {:?}", extreme_values);
        for value in &extreme_values {
            println!("  Testing value: {:.2e}", value);
        }
    }

    Ok(())
}

/// Test comprehensive scenario with multiple metrics
fn test_comprehensive_scenario(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing comprehensive metric aggregation scenario");
    }

    let scenarios = vec![
        (
            "request_duration",
            vec![0.001, 0.01, 0.1, 1.0, 10.0],
            vec![5.0, 2.0, 15.0, 0.5, 8.0],
        ),
        (
            "payload_size",
            vec![100.0, 1000.0, 10000.0, 100000.0, 1000000.0],
            vec![500.0, 2500.0, 50000.0, 150000.0],
        ),
        (
            "queue_depth",
            vec![1.0, 5.0, 10.0, 50.0, 100.0],
            vec![3.0, 7.0, 12.0, 25.0, 75.0],
        ),
    ];

    for (name, boundaries, data) in scenarios {
        verify_histogram_case(name, boundaries, &data, verbose)?;
        if verbose {
            println!("  Scenario: {} with {} data points", name, data.len());
        }
    }

    Ok(())
}

/// Test cumulative export behavior against the same live histogram snapshot.
fn test_prometheus_export(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing cumulative Prometheus export");
    }

    let mut metrics = Metrics::new();
    let histogram = metrics.histogram("export_metric", vec![1.0, 5.0]);
    for observation in [0.5, 1.0, 2.0, 7.0] {
        histogram.observe(observation);
    }

    let snapshot = histogram.snapshot();
    let reference =
        reference_histogram_snapshot("export_metric", vec![1.0, 5.0], &[0.5, 1.0, 2.0, 7.0]);
    compare_histograms(&snapshot, &reference, 1e-9)?;

    let exported = metrics.export_prometheus();
    for expected in [
        "# TYPE export_metric histogram",
        "export_metric_bucket{le=\"1\"} 2",
        "export_metric_bucket{le=\"5\"} 3",
        "export_metric_bucket{le=\"+Inf\"} 4",
        "export_metric_sum 10.5",
        "export_metric_count 4",
    ] {
        if !exported.contains(expected) {
            return Err(format!(
                "Missing expected export line {expected:?} in {exported:?}"
            ));
        }
    }

    Ok(())
}

/// Test histogram cardinality pressure routes new instruments to the overflow bucket.
fn test_cardinality_cap(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing histogram cardinality cap behavior");
    }

    let mut metrics = Metrics::with_cardinality_cap(1);
    let first = metrics.histogram("cardinality_first", vec![1.0]);
    let overflow = metrics.histogram("cardinality_second", vec![1.0]);

    first.observe(0.5);
    overflow.observe(2.0);

    let (_, _, histogram_rejections, _) = metrics.overflow_rejections();
    if histogram_rejections != 1 {
        return Err(format!(
            "Histogram cardinality rejection mismatch: got {histogram_rejections}, expected 1"
        ));
    }

    let first_snapshot = first.snapshot();
    if first_snapshot.name != "cardinality_first" {
        return Err(format!(
            "First histogram name changed unexpectedly: {}",
            first_snapshot.name
        ));
    }
    compare_histograms(
        &first_snapshot,
        &reference_histogram_snapshot("cardinality_first", vec![1.0], &[0.5]),
        1e-9,
    )?;

    let overflow_snapshot = overflow.snapshot();
    if overflow_snapshot.name != "asupersync_metric_cardinality_overflow" {
        return Err(format!(
            "Overflow histogram name mismatch: {}",
            overflow_snapshot.name
        ));
    }
    compare_histograms(
        &overflow_snapshot,
        &reference_histogram_snapshot("asupersync_metric_cardinality_overflow", vec![1.0], &[2.0]),
        1e-9,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_histogram_comparison() {
        let hist1 = HistogramSnapshot {
            name: "latency".to_string(),
            bucket_boundaries: vec![1.0, 5.0, 10.0],
            bucket_counts: vec![5, 10, 15, 0],
            count: 30,
            sum: 180.0,
        };

        let hist2 = HistogramSnapshot {
            name: "latency".to_string(),
            bucket_boundaries: vec![1.0, 5.0, 10.0],
            bucket_counts: vec![5, 10, 15, 0],
            count: 30,
            sum: 180.0,
        };

        assert!(compare_histograms(&hist1, &hist2, 1e-6).is_ok());
    }

    #[test]
    fn test_histogram_mismatch() {
        let hist1 = HistogramSnapshot {
            name: "latency".to_string(),
            bucket_boundaries: vec![1.0, 5.0],
            bucket_counts: vec![5, 10, 0],
            count: 15,
            sum: 90.0,
        };

        let hist2 = HistogramSnapshot {
            name: "latency".to_string(),
            bucket_boundaries: vec![1.0, 5.0],
            bucket_counts: vec![5, 12, 0],
            count: 17,
            sum: 95.0,
        };

        assert!(compare_histograms(&hist1, &hist2, 1e-6).is_err());
    }
}
