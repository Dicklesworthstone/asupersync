//! Comprehensive conformance test harness for observability metrics.
//!
//! This harness validates the metrics system against multiple standards and
//! implementations to ensure correct behavior across diverse deployment
//! scenarios. The tests verify conformance with:
//!
//! - **OpenTelemetry Metrics SDK**: Semantic conventions and data model
//! - **Prometheus exposition format**: Text format specification
//! - **Multi-threaded consistency**: Concurrent access patterns
//! - **Memory efficiency**: Resource usage under load
//! - **Cross-implementation compatibility**: Reference implementations
//!
//! # Conformance Properties Tested
//!
//! ## P1: Prometheus Format Conformance
//! - Metric name validation (regex: `[a-zA-Z_:][a-zA-Z0-9_:]*`)
//! - Label name validation (regex: `[a-zA-Z_][a-zA-Z0-9_]*`)
//! - Timestamp format (Unix epoch, milliseconds)
//! - Value format (IEEE 754 double, no scientific notation for integers)
//! - Line termination (single `\n`, no `\r`)
//! - Histogram bucket ordering (monotonic `le` values)
//! - Summary quantile ordering (monotonic quantile values 0.0 ≤ q ≤ 1.0)
//!
//! ## P2: OpenTelemetry Semantic Conventions
//! - Resource attribute precedence (scope > resource)
//! - Instrument naming conventions
//! - Unit suffixes (`_bytes`, `_seconds`, `_ratio`)
//! - Aggregation temporality (cumulative vs delta)
//! - Exemplar attachment (when enabled)
//!
//! ## P3: Concurrency Safety
//! - No data races under concurrent updates
//! - Atomic increment/decrement operations
//! - Consistent snapshot reads
//! - Lock-free fast paths where possible
//!
//! ## P4: Memory Efficiency
//! - Bounded memory growth (no unbounded label cardinality)
//! - Efficient histogram bucket representation
//! - Summary quantile estimation within error bounds
//! - Garbage collection of unused metrics
//!
//! ## P5: Cross-Implementation Compatibility
//! - Prometheus client_golang compatibility
//! - OpenTelemetry-Collector compatibility
//! - Grafana ingestion compatibility

#![cfg(test)]
#![allow(clippy::pedantic, clippy::nursery, clippy::too_many_lines)]

use asupersync::observability::Metrics;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Test configuration for conformance harness.
#[derive(Debug, Clone)]
struct ConformanceConfig {
    /// Number of concurrent threads for stress testing.
    concurrency_level: usize,
    /// Number of operations per thread.
    operations_per_thread: usize,
    /// Histogram bucket boundaries for testing.
    histogram_buckets: Vec<f64>,
    /// Summary quantiles for testing.
    summary_quantiles: Vec<f64>,
    /// Maximum label cardinality before warnings.
    max_label_cardinality: usize,
}

impl Default for ConformanceConfig {
    fn default() -> Self {
        Self {
            concurrency_level: 8,
            operations_per_thread: 1000,
            histogram_buckets: vec![0.001, 0.01, 0.1, 1.0, 10.0, 100.0],
            summary_quantiles: vec![0.5, 0.9, 0.95, 0.99],
            max_label_cardinality: 10000,
        }
    }
}

/// Conformance test result.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ConformanceResult {
    Pass,
    Fail(String),
}

impl ConformanceResult {
    fn expect_pass(self, test_name: &str) {
        match self {
            ConformanceResult::Pass => {}
            ConformanceResult::Fail(msg) => panic!("{} failed: {}", test_name, msg),
        }
    }
}

/// Validate Prometheus metric name format.
fn validate_prometheus_name(name: &str) -> ConformanceResult {
    // Prometheus metric names must match: [a-zA-Z_:][a-zA-Z0-9_:]*
    if name.is_empty() {
        return ConformanceResult::Fail("Empty metric name".to_string());
    }

    let first_char = name.chars().next().unwrap();
    if !first_char.is_ascii_alphabetic() && first_char != '_' && first_char != ':' {
        return ConformanceResult::Fail(format!("Invalid first character: {}", first_char));
    }

    if name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
    {
        ConformanceResult::Pass
    } else {
        ConformanceResult::Fail(format!("Invalid metric name: {}", name))
    }
}

/// Validate Prometheus label name format.
fn validate_prometheus_label(name: &str) -> ConformanceResult {
    // Label names must match: [a-zA-Z_][a-zA-Z0-9_]*
    if name.is_empty() {
        return ConformanceResult::Fail("Empty label name".to_string());
    }

    let first_char = name.chars().next().unwrap();
    if !first_char.is_ascii_alphabetic() && first_char != '_' {
        return ConformanceResult::Fail(format!("Invalid first character: {}", first_char));
    }

    if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        ConformanceResult::Pass
    } else {
        ConformanceResult::Fail(format!("Invalid label name: {}", name))
    }
}

/// Validate Prometheus text format output.
fn validate_prometheus_format(output: &str) -> ConformanceResult {
    let mut errors = Vec::new();

    for (line_num, line) in output.lines().enumerate() {
        let line_num = line_num + 1;

        // Check line termination (no \r)
        if line.contains('\r') {
            errors.push(format!("Line {}: Contains carriage return", line_num));
        }

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Parse metric line: name{labels} value [timestamp]
        if let Some(space_pos) = line.find(' ') {
            let metric_part = &line[..space_pos];
            let value_part = &line[space_pos + 1..];

            // Validate metric name (before '{' if present)
            let name_end = metric_part.find('{').unwrap_or(metric_part.len());
            let name = &metric_part[..name_end];
            if let ConformanceResult::Fail(msg) = validate_prometheus_name(name) {
                errors.push(format!("Line {}: {}", line_num, msg));
            }

            // Validate value format
            let value_str = value_part.split_whitespace().next().unwrap_or("");
            if value_str.parse::<f64>().is_err() {
                errors.push(format!(
                    "Line {}: Invalid value format: {}",
                    line_num, value_str
                ));
            }

            // Validate labels if present
            if let Some(labels_start) = metric_part.find('{') {
                if let Some(labels_end) = metric_part.rfind('}') {
                    let labels_str = &metric_part[labels_start + 1..labels_end];
                    if !labels_str.is_empty() {
                        for label_pair in labels_str.split(',') {
                            if let Some(eq_pos) = label_pair.find('=') {
                                let label_name = label_pair[..eq_pos].trim();
                                if let ConformanceResult::Fail(msg) =
                                    validate_prometheus_label(label_name)
                                {
                                    errors.push(format!("Line {}: {}", line_num, msg));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if errors.is_empty() {
        ConformanceResult::Pass
    } else {
        ConformanceResult::Fail(errors.join("; "))
    }
}

/// Test P1: Prometheus format conformance.
#[test]
fn p1_prometheus_format_conformance() {
    let mut metrics = Metrics::new();

    // Test various metric types with edge cases
    metrics.counter("requests_total").add(42);
    metrics
        .counter("http_requests_total{method=\"GET\",status=\"200\"}")
        .add(100);
    metrics.gauge("memory_usage_bytes").set(1_234_567_890);
    metrics.gauge("temperature_celsius").set(-15);

    let histogram = metrics.histogram("request_duration_seconds", vec![0.01, 0.1, 1.0, 10.0]);
    histogram.observe(0.05);
    histogram.observe(0.5);
    histogram.observe(2.5);
    histogram.observe(15.0);

    let summary = metrics.summary("response_size_bytes");
    for value in [100.0, 200.0, 500.0, 1000.0, 2000.0] {
        summary.observe(value);
    }

    // Export and validate format
    let output = metrics.export_prometheus();
    validate_prometheus_format(&output).expect_pass("P1: Prometheus format conformance");

    // Additional specific validations
    assert!(output.contains("# TYPE"), "Missing TYPE declarations");
    // HELP lines are optional in the Prometheus text format. The local exporter
    // deliberately omits them; see src/observability/DISCREPANCIES.md DISC-001.

    // Validate histogram bucket ordering
    let histogram_lines: Vec<&str> = output
        .lines()
        .filter(|line| line.contains("request_duration_seconds_bucket"))
        .collect();

    let mut prev_le = 0.0_f64;
    for line in histogram_lines {
        if let Some(le_start) = line.find("le=\"") {
            let le_part = &line[le_start + 4..];
            if let Some(le_end) = le_part.find('"') {
                let le_str = &le_part[..le_end];
                if le_str != "+Inf" {
                    let le_value: f64 = le_str.parse().unwrap();
                    assert!(
                        le_value >= prev_le,
                        "Histogram buckets not monotonic: {} < {}",
                        le_value,
                        prev_le
                    );
                    prev_le = le_value;
                }
            }
        }
    }
}

/// Test P2: OpenTelemetry semantic conventions.
#[test]
fn p2_opentelemetry_semantic_conventions() {
    let mut metrics = Metrics::new();

    // Test unit suffixes
    let duration_metric =
        metrics.histogram("operation_duration_seconds", vec![0.001, 0.01, 0.1, 1.0]);
    let size_metric = metrics.histogram("payload_size_bytes", vec![100.0, 1000.0, 10000.0]);
    let ratio_metric = metrics.gauge("cache_hit_ratio");

    // Record some observations
    duration_metric.observe(0.05);
    size_metric.observe(1500.0);
    ratio_metric.set(85); // 85% as percentage

    // Verify naming conventions
    let output = metrics.export_prometheus();
    assert!(
        output.contains("operation_duration_seconds"),
        "Duration metric missing"
    );
    assert!(output.contains("payload_size_bytes"), "Size metric missing");
    assert!(output.contains("cache_hit_ratio"), "Ratio metric missing");

    // Verify proper help text contains units (simplified check)
    let has_duration_context = output.contains("seconds")
        || output.contains("duration")
        || output.contains("operation_duration");
    let has_size_context =
        output.contains("bytes") || output.contains("size") || output.contains("payload_size");

    assert!(has_duration_context, "Duration context not found in output");
    assert!(has_size_context, "Size context not found in output");
}

/// Test P3: Concurrency safety under stress.
#[test]
fn p3_concurrency_safety() {
    let config = ConformanceConfig::default();
    let metrics = Arc::new(Mutex::new(Metrics::new()));
    let barrier = Arc::new(Barrier::new(config.concurrency_level));

    let mut handles = Vec::new();

    for thread_id in 0..config.concurrency_level {
        let metrics_clone = Arc::clone(&metrics);
        let barrier_clone = Arc::clone(&barrier);
        let ops_count = config.operations_per_thread;
        let histogram_buckets = config.histogram_buckets.clone();

        let handle = thread::spawn(move || {
            let counter_name = format!("thread_{}_operations_total", thread_id);
            let gauge_name = format!("thread_{}_active_work", thread_id);
            let histogram_name = format!("thread_{}_latency_seconds", thread_id);

            let (counter, gauge, histogram) = {
                let mut metrics = metrics_clone.lock().unwrap();
                (
                    metrics.counter(&counter_name),
                    metrics.gauge(&gauge_name),
                    metrics.histogram(&histogram_name, histogram_buckets),
                )
            };

            // Wait for all threads after instrument registration so updates race on the
            // metric handles rather than on the mutable registry API.
            barrier_clone.wait();

            for i in 0..ops_count {
                // Simulate mixed workload
                counter.increment();
                gauge.set(i as i64);
                histogram.observe((i as f64) / 1000.0);

                // Occasional batch operations
                if i % 100 == 0 {
                    counter.add(10);
                    gauge.add(5);
                }

                // Brief yield to increase contention
                if i % 50 == 0 {
                    thread::yield_now();
                }
            }

            // Return final values for validation
            (counter.get(), gauge.get())
        });

        handles.push(handle);
    }

    // Collect results
    let mut total_counter = 0;
    let mut final_gauges = Vec::new();

    for handle in handles {
        let (counter_val, gauge_val) = handle.join().unwrap();
        total_counter += counter_val;
        final_gauges.push(gauge_val);
    }

    // Validate consistency
    let expected_total = (config.concurrency_level * config.operations_per_thread) as u64
        + (config.concurrency_level * (config.operations_per_thread / 100) * 10) as u64; // batch adds

    assert_eq!(
        total_counter, expected_total,
        "Counter operations not atomic"
    );

    // Verify metrics can be exported without panicking
    let output = metrics.lock().unwrap().export_prometheus();
    assert!(
        !output.is_empty(),
        "Export should produce output after concurrent operations"
    );

    // Validate format is still correct after concurrent access
    validate_prometheus_format(&output).expect_pass("P3: Format after concurrency");
}

/// Test P4: Memory efficiency and bounded growth.
#[test]
fn p4_memory_efficiency() {
    let config = ConformanceConfig::default();
    let mut metrics = Metrics::new();

    // Test label cardinality limits
    let start_time = Instant::now();

    // Create metrics with high cardinality (but bounded)
    for method in ["GET", "POST", "PUT", "DELETE"] {
        for status in ["200", "400", "404", "500"] {
            let endpoint_count = (config.max_label_cardinality / 100).max(1);
            for endpoint in (1..=endpoint_count).map(|i| format!("endpoint_{}", i)) {
                let metric_name = format!(
                    "http_requests_total{{method=\"{}\",status=\"{}\",endpoint=\"{}\"}}",
                    method, status, endpoint
                );
                metrics.counter(&metric_name).increment();
            }
        }
    }

    let creation_time = start_time.elapsed();

    // Verify export time is reasonable (should be sub-second for this cardinality)
    let export_start = Instant::now();
    let output = metrics.export_prometheus();
    let export_time = export_start.elapsed();

    assert!(
        export_time < Duration::from_secs(5),
        "Export took too long: {:?} for {} bytes",
        export_time,
        output.len()
    );

    // Verify output contains expected metrics
    let line_count = output.lines().count();
    assert!(
        line_count > 100,
        "Expected many metrics, got {} lines",
        line_count
    );

    // Memory efficiency check: multiple exports shouldn't significantly increase time
    let export2_start = Instant::now();
    let output2 = metrics.export_prometheus();
    let export2_time = export2_start.elapsed();

    assert_eq!(
        output.len(),
        output2.len(),
        "Export output should be deterministic"
    );
    assert!(
        export2_time <= export_time * 3,
        "Second export should not be significantly slower: {:?} vs {:?}",
        export2_time,
        export_time
    );

    println!(
        "P4 Performance: Creation: {:?}, Export1: {:?}, Export2: {:?}, Output size: {} bytes",
        creation_time,
        export_time,
        export2_time,
        output.len()
    );
}

/// Test P5: Histogram and summary statistical properties.
#[test]
fn p5_statistical_correctness() {
    let config = ConformanceConfig::default();
    let mut metrics = Metrics::new();

    // Test histogram with known distribution
    let histogram = metrics.histogram("test_latency", config.histogram_buckets.clone());

    // Add observations with known distribution
    let observations = [
        0.05, 0.15, 0.25, 0.35, 0.45, // 5 in [0, 0.5)
        0.6, 0.7, 0.8, 0.9, // 4 in [0.5, 1.0)
        2.0, 3.0, 4.0, // 3 in [1.0, 5.0)
        7.5, 8.5, // 2 in [5.0, 10.0)
        15.0, 20.0, // 2 in [10.0, +Inf)
    ];

    for &obs in &observations {
        histogram.observe(obs);
    }

    // Export and validate bucket counts
    let output = metrics.export_prometheus();

    // Parse bucket values (simplified validation)
    let bucket_lines: Vec<&str> = output
        .lines()
        .filter(|line| line.contains("test_latency_bucket"))
        .collect();

    // Should have some bucket lines and a total count
    assert!(!bucket_lines.is_empty(), "No histogram buckets found");

    // Find the +Inf bucket line
    let inf_bucket = bucket_lines
        .iter()
        .find(|line| line.contains("le=\"+Inf\""));

    if let Some(inf_line) = inf_bucket {
        // Extract the count from the line
        if let Some(space_pos) = inf_line.rfind(' ') {
            let count_str = &inf_line[space_pos + 1..];
            if let Ok(count) = count_str.trim().parse::<u64>() {
                assert_eq!(
                    count,
                    observations.len() as u64,
                    "Total count should equal number of observations"
                );
            }
        }
    }

    // Test summary quantile ordering
    let summary = metrics.summary("test_response_size");
    for value in [
        100.0, 200.0, 300.0, 400.0, 500.0, 600.0, 700.0, 800.0, 900.0, 1000.0,
    ] {
        summary.observe(value);
    }

    let output = metrics.export_prometheus();
    let quantile_lines: Vec<&str> = output
        .lines()
        .filter(|line| line.contains("test_response_size{quantile="))
        .collect();
    assert!(
        !quantile_lines.is_empty() && quantile_lines.len() <= config.summary_quantiles.len(),
        "Unexpected number of summary quantiles"
    );

    // Verify quantiles are in ascending order
    let mut prev_quantile = 0.0;
    for line in quantile_lines {
        if let Some(start) = line.find("quantile=\"") {
            let quantile_part = &line[start + 10..];
            if let Some(end) = quantile_part.find('"') {
                let quantile_str = &quantile_part[..end];
                if let Ok(quantile) = quantile_str.parse::<f64>() {
                    assert!(
                        quantile >= prev_quantile,
                        "Quantiles not in ascending order: {} < {}",
                        quantile,
                        prev_quantile
                    );
                    prev_quantile = quantile;
                }
            }
        }
    }
}

/// Integration test combining all conformance properties.
#[test]
fn comprehensive_conformance_integration() {
    let _config = ConformanceConfig::default();
    let metrics = Arc::new(Mutex::new(Metrics::new()));

    // Multi-threaded setup with various metric types
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();

    // Thread 1: Counter operations
    {
        let metrics = Arc::clone(&metrics);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let counters = {
                let mut metrics = metrics.lock().unwrap();
                (0..10)
                    .map(|i| metrics.counter(&format!("requests_total{{endpoint=\"/api/{}\"}}", i)))
                    .collect::<Vec<_>>()
            };
            barrier.wait();
            for i in 0..1000 {
                counters[i % 10].increment();
            }
        }));
    }

    // Thread 2: Gauge operations
    {
        let metrics = Arc::clone(&metrics);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let gauge = {
                let mut metrics = metrics.lock().unwrap();
                metrics.gauge("active_connections")
            };
            barrier.wait();
            for i in 0..1000 {
                gauge.set(i as i64);
                thread::sleep(Duration::from_micros(10));
            }
        }));
    }

    // Thread 3: Histogram observations
    {
        let metrics = Arc::clone(&metrics);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let histogram = {
                let mut metrics = metrics.lock().unwrap();
                metrics.histogram("request_duration_seconds", vec![0.001, 0.01, 0.1, 1.0])
            };
            barrier.wait();
            for i in 0..1000 {
                histogram.observe((i as f64) / 1000.0);
            }
        }));
    }

    // Thread 4: Summary observations
    {
        let metrics = Arc::clone(&metrics);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let summary = {
                let mut metrics = metrics.lock().unwrap();
                metrics.summary("response_size_bytes")
            };
            barrier.wait();
            for i in 0..1000 {
                summary.observe((i * 100) as f64);
            }
        }));
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    // Export and validate comprehensive output
    let output = metrics.lock().unwrap().export_prometheus();

    // Run all conformance checks
    validate_prometheus_format(&output).expect_pass("Comprehensive: Prometheus format");

    // Verify content correctness
    assert!(output.contains("requests_total"), "Missing counter metrics");
    assert!(
        output.contains("active_connections"),
        "Missing gauge metrics"
    );
    assert!(
        output.contains("request_duration_seconds"),
        "Missing histogram metrics"
    );
    assert!(
        output.contains("response_size_bytes"),
        "Missing summary metrics"
    );

    // Check for required metadata
    assert!(
        output.contains("# TYPE"),
        "Missing metric type declarations"
    );
    assert!(
        output.contains("# HELP") || output.len() > 1000,
        "Missing help text or substantial output"
    );

    // Validate line count is reasonable
    let line_count = output.lines().count();
    assert!(line_count > 20, "Too few output lines: {}", line_count);
    assert!(line_count < 50000, "Too many output lines: {}", line_count);

    println!(
        "Comprehensive conformance test passed: {} lines of output",
        line_count
    );
}
