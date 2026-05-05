//! OpenTelemetry ExponentialHistogram Aggregator Conformance Test
//!
//! asupersync currently exposes explicit-boundary histograms through
//! `observability::metrics::Histogram`; it does not expose a Base2
//! ExponentialHistogram aggregation API. This binary is therefore a truthful
//! unsupported-status check: it records representative observations through the
//! live explicit-boundary histogram fallback and refuses to claim exponential
//! scale/bucket parity that the production API does not provide.

use asupersync::observability::metrics::{HistogramSnapshot, Metrics};

/// Test cases that would require a production ExponentialHistogram surface.
struct ExponentialHistogramTestCase {
    name: &'static str,
    histogram_name: &'static str,
    observations: Vec<f64>,
    explicit_boundaries: Vec<f64>,
    requested_max_size: u32,
    requested_max_scale: i8,
    description: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UnsupportedStatus {
    feature: &'static str,
    reason: &'static str,
}

fn main() {
    println!("🔍 OpenTelemetry ExponentialHistogram Aggregator Conformance Test");
    println!("Verifying truthful unsupported status plus live explicit histogram fallback");

    let status = exponential_histogram_status();
    let test_cases = vec![
        ExponentialHistogramTestCase {
            name: "exponential_histogram_default",
            histogram_name: "request_latency",
            observations: vec![
                0.001, 0.002, 0.003, 0.005, 0.008, 0.01, 0.015, 0.025, 0.03, 0.05, 0.06, 0.1, 0.12,
                0.25, 0.5, 1.0,
            ],
            explicit_boundaries: vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
            requested_max_size: 160,
            requested_max_scale: 20,
            description: "Default exponential-histogram request with latency observations",
        },
        ExponentialHistogramTestCase {
            name: "exponential_histogram_high_precision",
            histogram_name: "response_time",
            observations: vec![0.5, 1.0, 1.5, 2.0, 3.0, 4.0, 6.0, 8.0, 12.0, 16.0, 24.0],
            explicit_boundaries: vec![0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0],
            requested_max_size: 320,
            requested_max_scale: 20,
            description: "High-precision request with power-of-two aligned values",
        },
        ExponentialHistogramTestCase {
            name: "exponential_histogram_wide_range",
            histogram_name: "memory_usage",
            observations: vec![1e-6, 5e-4, 1e-3, 2e-1, 1.0, 50.0, 1e3, 5e4, 1e6, 1e9],
            explicit_boundaries: vec![1e-6, 1e-3, 1.0, 1e3, 1e6, 1e9],
            requested_max_size: 160,
            requested_max_scale: 15,
            description: "Wide range request that would require scale adaptation",
        },
        ExponentialHistogramTestCase {
            name: "exponential_histogram_edge_values",
            histogram_name: "cpu_usage",
            observations: vec![
                0.0,
                f64::EPSILON,
                0.5,
                0.999_999,
                1.0 - f64::EPSILON,
                1.0,
                1.0 + f64::EPSILON,
                1.000_001,
                2.0,
            ],
            explicit_boundaries: vec![0.0, f64::EPSILON, 0.5, 1.0, 2.0],
            requested_max_size: 160,
            requested_max_scale: 20,
            description: "Edge values near zero and one",
        },
    ];

    let mut failed_tests = Vec::new();

    for test_case in &test_cases {
        println!(
            "  Testing {}: {} (requested max_size={}, max_scale={})",
            test_case.name,
            test_case.description,
            test_case.requested_max_size,
            test_case.requested_max_scale
        );

        if let Err(error) = verify_unsupported_case(test_case, &status) {
            failed_tests.push((test_case.name.to_string(), error));
        } else {
            println!("    ✅ {} unsupported truthfully", test_case.name);
            println!("    ↳ {}: {}", status.feature, status.reason);
        }
    }

    println!("\n📊 ExponentialHistogram Aggregator Conformance Test Results");
    if failed_tests.is_empty() {
        println!("✅ ALL TESTS PASSED - ExponentialHistogram status is truthful");
        println!(
            "🎯 unsupported={}, live_fallback_checks={}",
            test_cases.len(),
            test_cases.len()
        );
    } else {
        println!("❌ {} TESTS FAILED:", failed_tests.len());
        for (test_name, error) in &failed_tests {
            println!("   {} - {}", test_name, error);
        }
        std::process::exit(1);
    }
}

fn exponential_histogram_status() -> UnsupportedStatus {
    UnsupportedStatus {
        feature: "Base2ExponentialHistogram",
        reason: "asupersync exposes explicit-boundary Histogram snapshots; scale, zero-count, and positive/negative exponential buckets are not production APIs",
    }
}

fn verify_unsupported_case(
    test_case: &ExponentialHistogramTestCase,
    status: &UnsupportedStatus,
) -> Result<(), String> {
    if status.feature != "Base2ExponentialHistogram" {
        return Err(format!(
            "Unexpected unsupported feature: {}",
            status.feature
        ));
    }

    let live = live_explicit_histogram_snapshot(test_case);
    let reference = reference_explicit_histogram_snapshot(test_case);
    compare_explicit_snapshots(&live, &reference)
}

fn live_explicit_histogram_snapshot(test_case: &ExponentialHistogramTestCase) -> HistogramSnapshot {
    let mut metrics = Metrics::new();
    let histogram = metrics.histogram(
        test_case.histogram_name,
        test_case.explicit_boundaries.clone(),
    );

    for &observation in &test_case.observations {
        histogram.observe(observation);
    }

    histogram.snapshot()
}

fn reference_explicit_histogram_snapshot(
    test_case: &ExponentialHistogramTestCase,
) -> HistogramSnapshot {
    let mut boundaries = test_case.explicit_boundaries.clone();
    boundaries.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    let mut bucket_counts = vec![0; boundaries.len() + 1];
    let mut sum = 0.0;

    for &observation in &test_case.observations {
        let bucket_index = boundaries
            .iter()
            .position(|&boundary| observation <= boundary)
            .unwrap_or(boundaries.len());
        bucket_counts[bucket_index] += 1;
        sum += observation;
    }

    HistogramSnapshot {
        name: test_case.histogram_name.to_string(),
        bucket_boundaries: boundaries,
        bucket_counts,
        count: u64::try_from(test_case.observations.len())
            .expect("exponential histogram conformance observation count fits u64"),
        sum,
    }
}

fn compare_explicit_snapshots(
    live: &HistogramSnapshot,
    reference: &HistogramSnapshot,
) -> Result<(), String> {
    if live.name != reference.name {
        return Err(format!(
            "Histogram name mismatch: live={}, reference={}",
            live.name, reference.name
        ));
    }
    if live.bucket_boundaries != reference.bucket_boundaries {
        return Err(format!(
            "Explicit boundaries mismatch: live={:?}, reference={:?}",
            live.bucket_boundaries, reference.bucket_boundaries
        ));
    }
    if live.bucket_counts != reference.bucket_counts {
        return Err(format!(
            "Explicit bucket counts mismatch: live={:?}, reference={:?}",
            live.bucket_counts, reference.bucket_counts
        ));
    }
    if live.count != reference.count {
        return Err(format!(
            "Count mismatch: live={}, reference={}",
            live.count, reference.count
        ));
    }
    if (live.sum - reference.sum).abs() > 1e-10 {
        return Err(format!(
            "Sum mismatch: live={}, reference={}",
            live.sum, reference.sum
        ));
    }

    Ok(())
}
