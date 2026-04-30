//! OpenTelemetry Resource Detection Conformance Testing
//!
//! Pattern 1: Differential Testing vs opentelemetry-sdk crate
//! Ensures identical Resource attributes for same env vars + hostname

use clap::{Arg, Command};
use opentelemetry::KeyValue;
use opentelemetry_sdk::Resource as SdkResource;
use std::collections::{BTreeMap, BTreeSet};
use std::env;

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
    Must,   // OpenTelemetry spec MUST clause
    Should, // OpenTelemetry spec SHOULD clause
    May,    // OpenTelemetry spec MAY clause
}

fn main() {
    env_logger::init();

    let matches = Command::new("otel_resource_conformance")
        .version("0.1.0")
        .about("OpenTelemetry Resource detection conformance testing")
        .arg(
            Arg::new("test")
                .help("Test to run")
                .value_parser([
                    "basic-detection",
                    "env-vars",
                    "hostname",
                    "service-detection",
                    "comprehensive",
                    "report",
                    "all",
                ])
                .default_value("all"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Verbose output")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let test_name = matches.get_one::<String>("test").unwrap();
    let verbose = matches.get_flag("verbose");

    match test_name.as_str() {
        "basic-detection" => run_basic_detection_test(verbose),
        "env-vars" => run_env_vars_test(verbose),
        "hostname" => run_hostname_test(verbose),
        "service-detection" => run_service_detection_test(verbose),
        "comprehensive" => run_comprehensive_test(verbose),
        "report" => {
            generate_compliance_report();
            return;
        }
        "all" => run_all_tests(verbose),
        _ => {
            eprintln!("Unknown test: {}", test_name);
            std::process::exit(1);
        }
    }
}

fn run_all_tests(verbose: bool) {
    println!("=== OpenTelemetry Resource Detection Conformance Testing ===\n");

    let mut total = 0;
    let mut passed = 0;
    let mut failed = 0;
    let mut xfail = 0;

    // Save original environment
    let original_env = save_environment();

    // Run all test cases
    let results = vec![
        ("basic-detection", run_basic_detection_test(verbose)),
        ("env-vars", run_env_vars_test(verbose)),
        ("hostname", run_hostname_test(verbose)),
        ("service-detection", run_service_detection_test(verbose)),
        ("comprehensive", run_comprehensive_test(verbose)),
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

    // Restore original environment
    restore_environment(original_env);

    println!("\n=== Summary ===");
    println!(
        "Total: {} | Passed: {} | Failed: {} | Expected Failures: {}",
        total, passed, failed, xfail
    );
    println!(
        "Success Rate: {:.1}%",
        (passed as f32 / total as f32) * 100.0
    );

    if failed > 0 {
        println!("\nDifferences documented in DISCREPANCIES.md");
        std::process::exit(1);
    }
}

/// Test basic Resource detection without environment variables
fn run_basic_detection_test(verbose: bool) -> ConformanceTestResult {
    let test_case = ConformanceCase {
        name: "basic_detection",
        description: "Basic Resource detection produces identical default attributes",
        requirement_level: RequirementLevel::Must,
    };

    if verbose {
        println!("Running {}: {}", test_case.name, test_case.description);
    }

    // Clear environment variables that might affect Resource detection
    clear_otel_env_vars();

    // Our implementation
    let our_resource = create_our_resource();
    let our_attrs = resource_to_sorted_map(&our_resource);

    // Reference implementation
    let ref_resource = SdkResource::default();
    let ref_attrs = sdk_resource_to_sorted_map(&ref_resource);

    let result = compare_resource_attributes(&our_attrs, &ref_attrs, "basic detection");

    if verbose {
        match &result {
            ConformanceTestResult::Pass => println!("✓ Test passed"),
            ConformanceTestResult::Fail { reason } => {
                println!("✗ Test failed: {}", reason);
                println!("Our attributes: {:?}", our_attrs);
                println!("Reference attributes: {:?}", ref_attrs);
            }
            ConformanceTestResult::ExpectedFailure { reason } => {
                println!("? Expected failure: {}", reason);
            }
        }
    }

    result
}

/// Test environment variable-based Resource detection
fn run_env_vars_test(verbose: bool) -> ConformanceTestResult {
    let test_case = ConformanceCase {
        name: "env_vars",
        description: "Environment variable Resource detection produces identical attributes",
        requirement_level: RequirementLevel::Must,
    };

    if verbose {
        println!("Running {}: {}", test_case.name, test_case.description);
    }

    // Set standard OpenTelemetry environment variables
    env::set_var("OTEL_SERVICE_NAME", "test-service");
    env::set_var("OTEL_SERVICE_VERSION", "1.0.0");
    env::set_var("OTEL_RESOURCE_ATTRIBUTES", "key1=value1,key2=value2");

    // Our implementation
    let our_resource = create_our_resource_from_env();
    let our_attrs = resource_to_sorted_map(&our_resource);

    // Reference implementation
    let ref_resource = SdkResource::from_detectors(
        std::time::Duration::from_secs(5),
        vec![Box::new(
            opentelemetry_sdk::resource::EnvResourceDetector::new(),
        )],
    );
    let ref_attrs = sdk_resource_to_sorted_map(&ref_resource);

    let result = compare_resource_attributes(&our_attrs, &ref_attrs, "environment variables");

    // Clean up environment
    env::remove_var("OTEL_SERVICE_NAME");
    env::remove_var("OTEL_SERVICE_VERSION");
    env::remove_var("OTEL_RESOURCE_ATTRIBUTES");

    if verbose {
        match &result {
            ConformanceTestResult::Pass => println!("✓ Test passed"),
            ConformanceTestResult::Fail { reason } => {
                println!("✗ Test failed: {}", reason);
                println!("Our attributes: {:?}", our_attrs);
                println!("Reference attributes: {:?}", ref_attrs);
            }
            ConformanceTestResult::ExpectedFailure { reason } => {
                println!("? Expected failure: {}", reason);
            }
        }
    }

    result
}

/// Test hostname detection
fn run_hostname_test(verbose: bool) -> ConformanceTestResult {
    let test_case = ConformanceCase {
        name: "hostname_detection",
        description: "Hostname detection produces identical host.name attribute",
        requirement_level: RequirementLevel::Should,
    };

    if verbose {
        println!("Running {}: {}", test_case.name, test_case.description);
    }

    clear_otel_env_vars();

    // Our implementation with hostname detection
    let our_resource = create_our_resource_with_hostname();
    let our_attrs = resource_to_sorted_map(&our_resource);

    // Reference implementation with hostname detection
    let ref_resource = SdkResource::from_detectors(
        std::time::Duration::from_secs(5),
        vec![Box::new(
            opentelemetry_sdk::resource::SdkProvidedResourceDetector,
        )],
    );
    let ref_attrs = sdk_resource_to_sorted_map(&ref_resource);

    let result = compare_resource_attributes(&our_attrs, &ref_attrs, "hostname detection");

    if verbose {
        match &result {
            ConformanceTestResult::Pass => println!("✓ Test passed"),
            ConformanceTestResult::Fail { reason } => {
                println!("✗ Test failed: {}", reason);
                println!("Our attributes: {:?}", our_attrs);
                println!("Reference attributes: {:?}", ref_attrs);
            }
            ConformanceTestResult::ExpectedFailure { reason } => {
                println!("? Expected failure: {}", reason);
            }
        }
    }

    result
}

/// Test service detection
fn run_service_detection_test(verbose: bool) -> ConformanceTestResult {
    let test_case = ConformanceCase {
        name: "service_detection",
        description: "Service detection produces identical service attributes",
        requirement_level: RequirementLevel::Must,
    };

    if verbose {
        println!("Running {}: {}", test_case.name, test_case.description);
    }

    clear_otel_env_vars();
    env::set_var("OTEL_SERVICE_NAME", "conformance-test");
    env::set_var("OTEL_SERVICE_VERSION", "0.1.0");
    env::set_var("OTEL_SERVICE_NAMESPACE", "testing");

    // Our implementation
    let our_resource = create_our_resource_from_env();
    let our_attrs = resource_to_sorted_map(&our_resource);

    // Reference implementation
    let ref_resource = SdkResource::from_detectors(
        std::time::Duration::from_secs(5),
        vec![Box::new(
            opentelemetry_sdk::resource::EnvResourceDetector::new(),
        )],
    );
    let ref_attrs = sdk_resource_to_sorted_map(&ref_resource);

    let result = compare_resource_attributes(&our_attrs, &ref_attrs, "service detection");

    // Clean up
    env::remove_var("OTEL_SERVICE_NAME");
    env::remove_var("OTEL_SERVICE_VERSION");
    env::remove_var("OTEL_SERVICE_NAMESPACE");

    if verbose {
        match &result {
            ConformanceTestResult::Pass => println!("✓ Test passed"),
            ConformanceTestResult::Fail { reason } => {
                println!("✗ Test failed: {}", reason);
                println!("Our attributes: {:?}", our_attrs);
                println!("Reference attributes: {:?}", ref_attrs);
            }
            ConformanceTestResult::ExpectedFailure { reason } => {
                println!("? Expected failure: {}", reason);
            }
        }
    }

    result
}

/// Comprehensive test with all detection methods
fn run_comprehensive_test(verbose: bool) -> ConformanceTestResult {
    let test_case = ConformanceCase {
        name: "comprehensive_detection",
        description: "Comprehensive Resource detection produces identical attributes",
        requirement_level: RequirementLevel::Must,
    };

    if verbose {
        println!("Running {}: {}", test_case.name, test_case.description);
    }

    // Set comprehensive environment
    env::set_var("OTEL_SERVICE_NAME", "comprehensive-test");
    env::set_var("OTEL_SERVICE_VERSION", "2.1.0");
    env::set_var("OTEL_SERVICE_NAMESPACE", "conformance");
    env::set_var(
        "OTEL_RESOURCE_ATTRIBUTES",
        "environment=test,region=us-west-2,cluster=production",
    );

    // Our implementation
    let our_resource = create_comprehensive_resource();
    let our_attrs = resource_to_sorted_map(&our_resource);

    // Reference implementation with all detectors
    let ref_resource = SdkResource::from_detectors(
        std::time::Duration::from_secs(5),
        vec![
            Box::new(opentelemetry_sdk::resource::EnvResourceDetector::new()),
            Box::new(opentelemetry_sdk::resource::SdkProvidedResourceDetector),
        ],
    );
    let ref_attrs = sdk_resource_to_sorted_map(&ref_resource);

    let result = compare_resource_attributes(&our_attrs, &ref_attrs, "comprehensive detection");

    // Clean up
    env::remove_var("OTEL_SERVICE_NAME");
    env::remove_var("OTEL_SERVICE_VERSION");
    env::remove_var("OTEL_SERVICE_NAMESPACE");
    env::remove_var("OTEL_RESOURCE_ATTRIBUTES");

    if verbose {
        match &result {
            ConformanceTestResult::Pass => println!("✓ Test passed"),
            ConformanceTestResult::Fail { reason } => {
                println!("✗ Test failed: {}", reason);

                // Write outputs to files for manual inspection
                if let Err(e) = std::fs::write("/tmp/our_resource.txt", format!("{:?}", our_attrs))
                {
                    eprintln!("Failed to write our resource: {}", e);
                }
                if let Err(e) =
                    std::fs::write("/tmp/reference_resource.txt", format!("{:?}", ref_attrs))
                {
                    eprintln!("Failed to write reference resource: {}", e);
                }
                println!(
                    "Resource outputs saved to /tmp/our_resource.txt and /tmp/reference_resource.txt"
                );
            }
            ConformanceTestResult::ExpectedFailure { reason } => {
                println!("? Expected failure: {}", reason);
            }
        }
    }

    result
}

/// Our implementation of Resource creation (placeholder - would be real implementation)
fn create_our_resource() -> BTreeMap<String, String> {
    // Placeholder for our Resource detection implementation
    // This would be the actual asupersync Resource detection logic
    let mut attrs = BTreeMap::new();
    attrs.insert("telemetry.sdk.name".to_string(), "asupersync".to_string());
    attrs.insert("telemetry.sdk.language".to_string(), "rust".to_string());
    attrs.insert(
        "telemetry.sdk.version".to_string(),
        env!("CARGO_PKG_VERSION").to_string(),
    );
    attrs
}

/// Our implementation with environment variable detection
fn create_our_resource_from_env() -> BTreeMap<String, String> {
    let mut attrs = create_our_resource();

    // Read standard OpenTelemetry environment variables
    if let Ok(service_name) = env::var("OTEL_SERVICE_NAME") {
        attrs.insert("service.name".to_string(), service_name);
    }

    if let Ok(service_version) = env::var("OTEL_SERVICE_VERSION") {
        attrs.insert("service.version".to_string(), service_version);
    }

    if let Ok(service_namespace) = env::var("OTEL_SERVICE_NAMESPACE") {
        attrs.insert("service.namespace".to_string(), service_namespace);
    }

    // Parse OTEL_RESOURCE_ATTRIBUTES
    if let Ok(resource_attrs) = env::var("OTEL_RESOURCE_ATTRIBUTES") {
        for pair in resource_attrs.split(',') {
            if let Some((key, value)) = pair.split_once('=') {
                attrs.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }

    attrs
}

/// Our implementation with hostname detection
fn create_our_resource_with_hostname() -> BTreeMap<String, String> {
    let mut attrs = create_our_resource();

    // Add hostname detection
    if let Ok(hostname) = hostname::get() {
        if let Some(hostname_str) = hostname.to_str() {
            attrs.insert("host.name".to_string(), hostname_str.to_string());
        }
    }

    attrs
}

/// Our comprehensive Resource implementation
fn create_comprehensive_resource() -> BTreeMap<String, String> {
    let mut attrs = create_our_resource_with_hostname();

    // Add environment variable detection
    let env_attrs = create_our_resource_from_env();
    for (k, v) in env_attrs {
        attrs.insert(k, v);
    }

    attrs
}

/// Convert our Resource representation to sorted map for comparison
fn resource_to_sorted_map(resource: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    resource.clone()
}

/// Convert SDK Resource to sorted map for comparison
fn sdk_resource_to_sorted_map(resource: &SdkResource) -> BTreeMap<String, String> {
    let mut attrs = BTreeMap::new();
    for kv in resource.iter() {
        let key = kv.key.as_str().to_string();
        let value = format!("{}", kv.value);
        attrs.insert(key, value);
    }
    attrs
}

/// Compare Resource attributes from both implementations
fn compare_resource_attributes(
    our_attrs: &BTreeMap<String, String>,
    ref_attrs: &BTreeMap<String, String>,
    test_context: &str,
) -> ConformanceTestResult {
    if our_attrs == ref_attrs {
        ConformanceTestResult::Pass
    } else {
        // Analyze differences
        let mut differences = Vec::new();

        // Check for missing attributes in our implementation
        for (key, ref_value) in ref_attrs {
            match our_attrs.get(key) {
                Some(our_value) if our_value != ref_value => {
                    differences.push(format!(
                        "Attribute '{}': ours='{}', reference='{}'",
                        key, our_value, ref_value
                    ));
                }
                None => {
                    differences.push(format!(
                        "Missing attribute '{}' in our implementation (reference='{}')",
                        key, ref_value
                    ));
                }
                _ => {} // Values match
            }
        }

        // Check for extra attributes in our implementation
        for (key, our_value) in our_attrs {
            if !ref_attrs.contains_key(key) {
                differences.push(format!(
                    "Extra attribute '{}' in our implementation: '{}'",
                    key, our_value
                ));
            }
        }

        ConformanceTestResult::Fail {
            reason: format!(
                "Resource {} differences detected:\n{}",
                test_context,
                differences.join("\n")
            ),
        }
    }
}

/// Clear OpenTelemetry environment variables for clean testing
fn clear_otel_env_vars() {
    let otel_vars = [
        "OTEL_SERVICE_NAME",
        "OTEL_SERVICE_VERSION",
        "OTEL_SERVICE_NAMESPACE",
        "OTEL_RESOURCE_ATTRIBUTES",
        "OTEL_SDK_DISABLED",
    ];

    for var in &otel_vars {
        env::remove_var(var);
    }
}

/// Save current environment state
fn save_environment() -> BTreeMap<String, String> {
    env::vars().collect()
}

/// Restore environment state
fn restore_environment(original_env: BTreeMap<String, String>) {
    // Clear current environment
    for (key, _) in env::vars() {
        if key.starts_with("OTEL_") {
            env::remove_var(key);
        }
    }

    // Restore original values
    for (key, value) in original_env {
        if key.starts_with("OTEL_") {
            env::set_var(key, value);
        }
    }
}

/// Generate conformance compliance report
fn generate_compliance_report() {
    let test_cases = vec![
        ConformanceCase {
            name: "basic_detection",
            description: "Basic Resource detection",
            requirement_level: RequirementLevel::Must,
        },
        ConformanceCase {
            name: "env_vars",
            description: "Environment variable Resource detection",
            requirement_level: RequirementLevel::Must,
        },
        ConformanceCase {
            name: "hostname_detection",
            description: "Hostname detection",
            requirement_level: RequirementLevel::Should,
        },
        ConformanceCase {
            name: "service_detection",
            description: "Service detection",
            requirement_level: RequirementLevel::Must,
        },
        ConformanceCase {
            name: "comprehensive_detection",
            description: "Comprehensive Resource detection",
            requirement_level: RequirementLevel::Must,
        },
    ];

    println!("=== OpenTelemetry Resource Detection Conformance Report ===");
    println!("Testing against opentelemetry-sdk crate (Pattern 1: Differential Testing)");
    println!("Total test cases: {}", test_cases.len());
    println!(
        "MUST clauses tested: {}",
        test_cases
            .iter()
            .filter(|tc| tc.requirement_level == RequirementLevel::Must)
            .count()
    );
    println!(
        "SHOULD clauses tested: {}",
        test_cases
            .iter()
            .filter(|tc| tc.requirement_level == RequirementLevel::Should)
            .count()
    );
    println!("\nTest cases:");
    for tc in &test_cases {
        println!(
            "  - {} ({:?}): {}",
            tc.name, tc.requirement_level, tc.description
        );
    }
    println!("\nRun 'otel_resource_conformance all -v' for detailed test execution.");
    println!("Any differences will be documented in DISCREPANCIES.md");
}
