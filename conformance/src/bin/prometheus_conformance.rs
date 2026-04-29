//! Prometheus Exposition Format Conformance Testing
//!
//! Pattern 1: Differential Testing vs prometheus_client crate
//! Ensures byte-identical output for same metric sets

use asupersync::observability::metrics::Metrics;
use clap::{Arg, Command};
use prometheus_client::{
    encoding::text::encode,
    metrics::{
        counter::Counter as PrometheusCounter,
        gauge::Gauge as PrometheusGauge,
        histogram::Histogram as PrometheusHistogram,
    },
    registry::Registry as PrometheusRegistry,
};
use std::sync::atomic::{AtomicI64, AtomicU64};

/// Conformance test result tracking
#[derive(Debug, Clone, PartialEq)]
enum ConformanceTestResult {
    Pass,
    Fail { reason: String },
    ExpectedFailure { reason: String },
}

/// Test metadata for conformance tracking
#[derive(Debug)]
struct ConformanceCase {
    name: &'static str,
    description: &'static str,
    requirement_level: RequirementLevel,
}

#[derive(Debug, PartialEq)]
enum RequirementLevel {
    Must,    // Prometheus spec MUST clause
    Should,  // Prometheus spec SHOULD clause
    May,     // Prometheus spec MAY clause
}

fn main() {
    env_logger::init();

    let matches = Command::new("prometheus_conformance")
        .version("0.1.0")
        .about("Prometheus exposition format conformance testing")
        .arg(
            Arg::new("test")
                .help("Test to run")
                .value_parser([
                    "counter-basic",
                    "gauge-basic",
                    "histogram-basic",
                    "comprehensive",
                    "edge-cases",
                    "report",
                    "all"
                ])
                .default_value("all")
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Verbose output")
                .action(clap::ArgAction::SetTrue)
        )
        .get_matches();

    let test_name = matches.get_one::<String>("test").unwrap();
    let verbose = matches.get_flag("verbose");

    match test_name.as_str() {
        "counter-basic" => run_counter_basic_test(verbose),
        "gauge-basic" => run_gauge_basic_test(verbose),
        "histogram-basic" => run_histogram_basic_test(verbose),
        "comprehensive" => run_comprehensive_test(verbose),
        "edge-cases" => run_edge_cases_test(verbose),
        "report" => {
            generate_compliance_report();
            return;
        },
        "all" => run_all_tests(verbose),
        _ => {
            eprintln!("Unknown test: {}", test_name);
            std::process::exit(1);
        }
    }
}

fn run_all_tests(verbose: bool) {
    println!("=== Prometheus Exposition Format Conformance Testing ===\n");

    let mut total = 0;
    let mut passed = 0;
    let mut failed = 0;
    let mut xfail = 0;

    // Run all test cases
    let results = vec![
        ("counter-basic", run_counter_basic_test(verbose)),
        ("gauge-basic", run_gauge_basic_test(verbose)),
        ("histogram-basic", run_histogram_basic_test(verbose)),
        ("comprehensive", run_comprehensive_test(verbose)),
        ("edge-cases", run_edge_cases_test(verbose)),
    ];

    for (name, result) in results {
        total += 1;
        match result {
            ConformanceTestResult::Pass => {
                passed += 1;
                println!("✓ {}: PASS", name);
            }
            ConformanceTestResult::Fail { ref reason } => {
                failed += 1;
                println!("✗ {}: FAIL - {}", name, reason);
            }
            ConformanceTestResult::ExpectedFailure { ref reason } => {
                xfail += 1;
                println!("? {}: XFAIL - {}", name, reason);
            }
        }
    }

    println!("\n=== Summary ===");
    println!("Total: {} | Passed: {} | Failed: {} | Expected Failures: {}",
             total, passed, failed, xfail);
    println!("Success Rate: {:.1}%", (passed as f32 / total as f32) * 100.0);

    if failed > 0 {
        println!("\nDifferences documented in DISCREPANCIES.md");
        std::process::exit(1);
    }
}

/// Core differential testing: basic counters
fn run_counter_basic_test(verbose: bool) -> ConformanceTestResult {
    let test_case = ConformanceCase {
        name: "counter_basic",
        description: "Basic counter metrics produce identical exposition format",
        requirement_level: RequirementLevel::Must,
    };

    if verbose {
        println!("Running {}: {}", test_case.name, test_case.description);
    }

    // Our implementation
    let mut our_metrics = Metrics::new();
    our_metrics.counter("http_requests_total").add(1247);
    our_metrics.counter("errors_total").add(42);
    let our_output = our_metrics.export_prometheus();

    // Reference implementation (prometheus_client)
    let mut registry = PrometheusRegistry::default();
    let requests_counter = PrometheusCounter::<u64, AtomicU64>::default();
    let errors_counter = PrometheusCounter::<u64, AtomicU64>::default();

    registry.register("http_requests_total", "Counter for HTTP requests", requests_counter.clone());
    registry.register("errors_total", "Counter for errors", errors_counter.clone());

    requests_counter.inc_by(1247);
    errors_counter.inc_by(42);

    let mut reference_output = String::new();
    encode(&mut reference_output, &registry).unwrap();

    let result = compare_prometheus_outputs(&our_output, &reference_output);

    if verbose {
        match &result {
            ConformanceTestResult::Pass => println!("✓ Test passed"),
            ConformanceTestResult::Fail { reason } => {
                println!("✗ Test failed: {}", reason);
                println!("Our output:\n{}", our_output);
                println!("Reference output:\n{}", reference_output);
            }
            ConformanceTestResult::ExpectedFailure { reason } => {
                println!("? Expected failure: {}", reason);
            }
        }
    }

    result
}

/// Test gauge conformance
fn run_gauge_basic_test(verbose: bool) -> ConformanceTestResult {
    let test_case = ConformanceCase {
        name: "gauge_basic",
        description: "Basic gauge metrics produce identical exposition format",
        requirement_level: RequirementLevel::Must,
    };

    if verbose {
        println!("Running {}: {}", test_case.name, test_case.description);
    }

    // Our implementation
    let mut our_metrics = Metrics::new();
    our_metrics.gauge("memory_usage_bytes").set(4096);
    our_metrics.gauge("active_connections").set(-1); // Negative values
    let our_output = our_metrics.export_prometheus();

    // Reference implementation
    let mut registry = PrometheusRegistry::default();
    let memory_gauge = PrometheusGauge::<i64, AtomicI64>::default();
    let connections_gauge = PrometheusGauge::<i64, AtomicI64>::default();

    registry.register("memory_usage_bytes", "Memory usage in bytes", memory_gauge.clone());
    registry.register("active_connections", "Active connections", connections_gauge.clone());

    memory_gauge.set(4096);
    connections_gauge.set(-1);

    let mut reference_output = String::new();
    encode(&mut reference_output, &registry).unwrap();

    let result = compare_prometheus_outputs(&our_output, &reference_output);

    if verbose {
        match &result {
            ConformanceTestResult::Pass => println!("✓ Test passed"),
            ConformanceTestResult::Fail { reason } => {
                println!("✗ Test failed: {}", reason);
                println!("Our output:\n{}", our_output);
                println!("Reference output:\n{}", reference_output);
            }
            ConformanceTestResult::ExpectedFailure { reason } => {
                println!("? Expected failure: {}", reason);
            }
        }
    }

    result
}

/// Test histogram conformance - most complex metric type
fn run_histogram_basic_test(verbose: bool) -> ConformanceTestResult {
    let test_case = ConformanceCase {
        name: "histogram_basic",
        description: "Basic histogram metrics produce identical exposition format",
        requirement_level: RequirementLevel::Must,
    };

    if verbose {
        println!("Running {}: {}", test_case.name, test_case.description);
    }

    // Our implementation
    let mut our_metrics = Metrics::new();
    let our_hist = our_metrics.histogram("request_latency_seconds", vec![0.01, 0.1, 1.0, 10.0]);
    our_hist.observe(0.005);  // Below first bucket
    our_hist.observe(0.05);   // Second bucket
    our_hist.observe(0.5);    // Third bucket
    our_hist.observe(5.0);    // Fourth bucket
    our_hist.observe(50.0);   // Above all buckets
    let our_output = our_metrics.export_prometheus();

    // Reference implementation
    let mut registry = PrometheusRegistry::default();
    let buckets = vec![0.01, 0.1, 1.0, 10.0];
    let reference_hist = PrometheusHistogram::new(buckets.into_iter());

    registry.register("request_latency_seconds", "Request latency in seconds", reference_hist.clone());

    reference_hist.observe(0.005);
    reference_hist.observe(0.05);
    reference_hist.observe(0.5);
    reference_hist.observe(5.0);
    reference_hist.observe(50.0);

    let mut reference_output = String::new();
    encode(&mut reference_output, &registry).unwrap();

    let result = compare_prometheus_outputs(&our_output, &reference_output);

    if verbose {
        match &result {
            ConformanceTestResult::Pass => println!("✓ Test passed"),
            ConformanceTestResult::Fail { reason } => {
                println!("✗ Test failed: {}", reason);
                println!("Our output:\n{}", our_output);
                println!("Reference output:\n{}", reference_output);
            }
            ConformanceTestResult::ExpectedFailure { reason } => {
                println!("? Expected failure: {}", reason);
            }
        }
    }

    result
}

/// Comprehensive differential test: 5 counters, 3 histograms, 1 gauge
/// This matches the golden snapshot test for complete validation
fn run_comprehensive_test(verbose: bool) -> ConformanceTestResult {
    let test_case = ConformanceCase {
        name: "comprehensive_5c_3h_1g",
        description: "Comprehensive metric set produces identical exposition format",
        requirement_level: RequirementLevel::Must,
    };

    if verbose {
        println!("Running {}: {}", test_case.name, test_case.description);
    }

    // Our implementation - match the golden test exactly
    let mut our_metrics = Metrics::new();

    // 5 Counters
    our_metrics.counter("http_requests_total").add(1247);
    our_metrics.counter("tcp_connections_opened_total").add(89);
    our_metrics.counter("bytes_transmitted_total").add(524288);
    our_metrics.counter("task_spawns_total").add(0);
    our_metrics.counter("region_closures_total").add(u64::MAX);

    // 3 Histograms with observations
    let request_latency = our_metrics.histogram("request_latency_seconds", vec![0.001, 0.01, 0.1, 1.0]);
    request_latency.observe(0.0005);
    request_latency.observe(0.025);
    request_latency.observe(0.15);
    request_latency.observe(2.5);

    let memory_alloc = our_metrics.histogram("memory_allocation_bytes", vec![1024.0, 4096.0, 16384.0, 65536.0]);
    memory_alloc.observe(512.0);
    memory_alloc.observe(2048.0);
    memory_alloc.observe(8192.0);
    memory_alloc.observe(32768.0);
    memory_alloc.observe(131072.0);

    let task_duration = our_metrics.histogram("task_execution_duration_ms", vec![1.0, 5.0, 10.0, 50.0, 100.0]);
    task_duration.observe(0.5);
    task_duration.observe(3.0);
    task_duration.observe(7.5);
    task_duration.observe(25.0);
    task_duration.observe(75.0);
    task_duration.observe(250.0);

    // 1 Gauge
    our_metrics.gauge("active_worker_threads").set(8);

    let our_output = our_metrics.export_prometheus();

    // Reference implementation - create equivalent metrics
    let mut registry = PrometheusRegistry::default();

    // Counters
    let http_counter = PrometheusCounter::<u64, AtomicU64>::default();
    let tcp_counter = PrometheusCounter::<u64, AtomicU64>::default();
    let bytes_counter = PrometheusCounter::<u64, AtomicU64>::default();
    let spawns_counter = PrometheusCounter::<u64, AtomicU64>::default();
    let closures_counter = PrometheusCounter::<u64, AtomicU64>::default();

    registry.register("http_requests_total", "", http_counter.clone());
    registry.register("tcp_connections_opened_total", "", tcp_counter.clone());
    registry.register("bytes_transmitted_total", "", bytes_counter.clone());
    registry.register("task_spawns_total", "", spawns_counter.clone());
    registry.register("region_closures_total", "", closures_counter.clone());

    http_counter.inc_by(1247);
    tcp_counter.inc_by(89);
    bytes_counter.inc_by(524288);
    spawns_counter.inc_by(0);
    closures_counter.inc_by(u64::MAX);

    // Histograms
    let req_hist = PrometheusHistogram::new(vec![0.001, 0.01, 0.1, 1.0].into_iter());
    let mem_hist = PrometheusHistogram::new(vec![1024.0, 4096.0, 16384.0, 65536.0].into_iter());
    let task_hist = PrometheusHistogram::new(vec![1.0, 5.0, 10.0, 50.0, 100.0].into_iter());

    registry.register("request_latency_seconds", "", req_hist.clone());
    registry.register("memory_allocation_bytes", "", mem_hist.clone());
    registry.register("task_execution_duration_ms", "", task_hist.clone());

    // Record observations
    req_hist.observe(0.0005);
    req_hist.observe(0.025);
    req_hist.observe(0.15);
    req_hist.observe(2.5);

    mem_hist.observe(512.0);
    mem_hist.observe(2048.0);
    mem_hist.observe(8192.0);
    mem_hist.observe(32768.0);
    mem_hist.observe(131072.0);

    task_hist.observe(0.5);
    task_hist.observe(3.0);
    task_hist.observe(7.5);
    task_hist.observe(25.0);
    task_hist.observe(75.0);
    task_hist.observe(250.0);

    // Gauge
    let threads_gauge = PrometheusGauge::<i64, AtomicI64>::default();
    registry.register("active_worker_threads", "", threads_gauge.clone());
    threads_gauge.set(8);

    let mut reference_output = String::new();
    encode(&mut reference_output, &registry).unwrap();

    let result = compare_prometheus_outputs(&our_output, &reference_output);

    if verbose {
        match &result {
            ConformanceTestResult::Pass => println!("✓ Test passed"),
            ConformanceTestResult::Fail { reason } => {
                println!("✗ Test failed: {}", reason);

                // Write outputs to files for manual inspection
                if let Err(e) = std::fs::write("/tmp/our_output.txt", &our_output) {
                    eprintln!("Failed to write our output: {}", e);
                }
                if let Err(e) = std::fs::write("/tmp/reference_output.txt", &reference_output) {
                    eprintln!("Failed to write reference output: {}", e);
                }
                println!("Outputs saved to /tmp/our_output.txt and /tmp/reference_output.txt");
            }
            ConformanceTestResult::ExpectedFailure { reason } => {
                println!("? Expected failure: {}", reason);
            }
        }
    }

    result
}

/// Test edge cases: empty metrics, special values, sanitization
fn run_edge_cases_test(verbose: bool) -> ConformanceTestResult {
    let test_case = ConformanceCase {
        name: "edge_cases",
        description: "Edge cases produce conformant output",
        requirement_level: RequirementLevel::Must,
    };

    if verbose {
        println!("Running {}: {}", test_case.name, test_case.description);
    }

    // Our implementation - edge cases
    let mut our_metrics = Metrics::new();
    our_metrics.counter("zero_counter").add(0);
    our_metrics.counter("max_counter").add(u64::MAX);
    our_metrics.gauge("negative_gauge").set(i64::MIN);
    our_metrics.gauge("positive_gauge").set(i64::MAX);

    // Test metric name sanitization
    our_metrics.counter("metric.with.dots").add(5);
    our_metrics.counter("metric_with_underscores").add(7);

    let our_output = our_metrics.export_prometheus();

    // Reference implementation - same edge cases
    let mut registry = PrometheusRegistry::default();

    let zero_counter = PrometheusCounter::<u64, AtomicU64>::default();
    let max_counter = PrometheusCounter::<u64, AtomicU64>::default();
    let neg_gauge = PrometheusGauge::<i64, AtomicI64>::default();
    let pos_gauge = PrometheusGauge::<i64, AtomicI64>::default();
    let dots_counter = PrometheusCounter::<u64, AtomicU64>::default();
    let under_counter = PrometheusCounter::<u64, AtomicU64>::default();

    registry.register("zero_counter", "", zero_counter.clone());
    registry.register("max_counter", "", max_counter.clone());
    registry.register("negative_gauge", "", neg_gauge.clone());
    registry.register("positive_gauge", "", pos_gauge.clone());
    registry.register("metric.with.dots", "", dots_counter.clone());
    registry.register("metric_with_underscores", "", under_counter.clone());

    zero_counter.inc_by(0);
    max_counter.inc_by(u64::MAX);
    neg_gauge.set(i64::MIN);
    pos_gauge.set(i64::MAX);
    dots_counter.inc_by(5);
    under_counter.inc_by(7);

    let mut reference_output = String::new();
    encode(&mut reference_output, &registry).unwrap();

    let result = compare_prometheus_outputs(&our_output, &reference_output);

    if verbose {
        match &result {
            ConformanceTestResult::Pass => println!("✓ Test passed"),
            ConformanceTestResult::Fail { reason } => {
                println!("✗ Test failed: {}", reason);
                println!("Our output:\n{}", our_output);
                println!("Reference output:\n{}", reference_output);
            }
            ConformanceTestResult::ExpectedFailure { reason } => {
                println!("? Expected failure: {}", reason);
            }
        }
    }

    result
}

/// Compare two Prometheus exposition format outputs
/// Returns Pass if byte-identical, Fail with details if different
fn compare_prometheus_outputs(our_output: &str, reference_output: &str) -> ConformanceTestResult {
    if our_output == reference_output {
        ConformanceTestResult::Pass
    } else {
        // Analyze differences for debugging
        let our_lines: Vec<&str> = our_output.lines().collect();
        let ref_lines: Vec<&str> = reference_output.lines().collect();

        let mut differences = Vec::new();

        // Line count difference
        if our_lines.len() != ref_lines.len() {
            differences.push(format!(
                "Line count differs: ours={}, reference={}",
                our_lines.len(),
                ref_lines.len()
            ));
        }

        // Line-by-line comparison (limit to first 10 differences)
        for (i, (our_line, ref_line)) in our_lines.iter().zip(ref_lines.iter()).enumerate() {
            if our_line != ref_line && differences.len() < 10 {
                differences.push(format!("Line {}: ours='{}', reference='{}'", i + 1, our_line, ref_line));
            }
        }

        // Check for extra lines (limit reporting)
        if our_lines.len() > ref_lines.len() {
            for (i, line) in our_lines.iter().skip(ref_lines.len()).take(5).enumerate() {
                differences.push(format!("Extra our line {}: '{}'", ref_lines.len() + i + 1, line));
            }
        }
        if ref_lines.len() > our_lines.len() {
            for (i, line) in ref_lines.iter().skip(our_lines.len()).take(5).enumerate() {
                differences.push(format!(
                    "Extra reference line {}: '{}'",
                    our_lines.len() + i + 1,
                    line
                ));
            }
        }

        ConformanceTestResult::Fail {
            reason: format!("Format differences detected:\n{}", differences.join("\n")),
        }
    }
}

/// Generate conformance compliance report
fn generate_compliance_report() {
    let test_cases = vec![
        ConformanceCase {
            name: "counter_basic",
            description: "Basic counter exposition format",
            requirement_level: RequirementLevel::Must,
        },
        ConformanceCase {
            name: "gauge_basic",
            description: "Basic gauge exposition format",
            requirement_level: RequirementLevel::Must,
        },
        ConformanceCase {
            name: "histogram_basic",
            description: "Basic histogram exposition format",
            requirement_level: RequirementLevel::Must,
        },
        ConformanceCase {
            name: "comprehensive_5c_3h_1g",
            description: "Complex multi-metric scenario",
            requirement_level: RequirementLevel::Must,
        },
        ConformanceCase {
            name: "edge_cases",
            description: "Edge cases and sanitization",
            requirement_level: RequirementLevel::Must,
        },
    ];

    println!("=== Prometheus Exposition Format Conformance Report ===");
    println!("Testing against prometheus_client crate (Pattern 1: Differential Testing)");
    println!("Total test cases: {}", test_cases.len());
    println!(
        "MUST clauses tested: {}",
        test_cases
            .iter()
            .filter(|tc| tc.requirement_level == RequirementLevel::Must)
            .count()
    );
    println!("\nTest cases:");
    for tc in &test_cases {
        println!("  - {} ({:?}): {}", tc.name, tc.requirement_level, tc.description);
    }
    println!("\nRun 'prometheus_conformance all -v' for detailed test execution.");
    println!("Any differences will be documented in DISCREPANCIES.md");
}