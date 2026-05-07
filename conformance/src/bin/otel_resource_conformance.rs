//! OpenTelemetry Resource Detection Conformance Testing
//!
//! Pattern 1: Differential Testing vs opentelemetry-sdk crate
//! Compares asupersync resource detection with the matching opentelemetry-sdk detectors.

use asupersync::observability::otel::OtlpResourceBuilder;
use clap::{Arg, Command};
use opentelemetry_sdk::Resource as SdkResource;
use opentelemetry_sdk::resource::{EnvResourceDetector, SdkProvidedResourceDetector};
use std::collections::BTreeMap;
use std::env;

const OTEL_ENV_VARS: &[&str] = &[
    "OTEL_SERVICE_NAME",
    "OTEL_SERVICE_VERSION",
    "OTEL_SERVICE_NAMESPACE",
    "OTEL_RESOURCE_ATTRIBUTES",
    "OTEL_SDK_DISABLED",
];

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
        "basic-detection" => exit_if_failed(run_basic_detection_test(verbose)),
        "env-vars" => exit_if_failed(run_env_vars_test(verbose)),
        "hostname" => exit_if_failed(run_hostname_test(verbose)),
        "service-detection" => exit_if_failed(run_service_detection_test(verbose)),
        "comprehensive" => exit_if_failed(run_comprehensive_test(verbose)),
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

fn exit_if_failed(result: ConformanceTestResult) {
    if let ConformanceTestResult::Fail { reason } = result {
        eprintln!("Conformance test failed: {reason}");
        std::process::exit(1);
    }
}

fn run_all_tests(verbose: bool) {
    println!("=== OpenTelemetry Resource Detection Conformance Testing ===\n");

    let mut total = 0;
    let mut passed = 0;
    let mut failed = 0;
    let mut xfail = 0;

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
        description: "Basic Resource detection produces the same default service.name",
        requirement_level: RequirementLevel::Must,
    };

    if verbose {
        println!("Running {}: {}", test_case.name, test_case.description);
    }

    let _guard = OtelEnvGuard::clear();

    // Our implementation
    let our_resource = create_our_resource();
    let our_attrs = select_attrs(&resource_to_sorted_map(&our_resource), &["service.name"]);

    // Reference implementation
    let ref_resource = SdkResource::builder_empty()
        .with_detector(Box::new(SdkProvidedResourceDetector))
        .build();
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

    let _guard =
        OtelEnvGuard::with(&[("OTEL_RESOURCE_ATTRIBUTES", Some("key1=value1,key2=value2"))]);

    // Our implementation
    let our_attrs = create_our_env_resource_attributes();

    // Reference implementation
    let ref_resource = SdkResource::builder_empty()
        .with_detector(Box::new(EnvResourceDetector::new()))
        .build();
    let ref_attrs = sdk_resource_to_sorted_map(&ref_resource);

    let result = compare_resource_attributes(&our_attrs, &ref_attrs, "environment variables");

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

    let _guard = OtelEnvGuard::clear();

    let result = ConformanceTestResult::ExpectedFailure {
        reason: "host.name detection is not implemented by OtlpResourceBuilder; opentelemetry 0.31 keeps host detectors outside opentelemetry_sdk".to_string(),
    };

    if verbose {
        match &result {
            ConformanceTestResult::Pass => println!("✓ Test passed"),
            ConformanceTestResult::Fail { reason } => println!("✗ Test failed: {}", reason),
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

    let _guard = OtelEnvGuard::with(&[(
        "OTEL_RESOURCE_ATTRIBUTES",
        Some("service.name=conformance-test"),
    )]);

    // Our implementation
    let our_resource = create_our_resource_from_env();
    let our_attrs = select_attrs(&resource_to_sorted_map(&our_resource), &["service.name"]);

    // Reference implementation
    let ref_resource = SdkResource::builder_empty()
        .with_detector(Box::new(SdkProvidedResourceDetector))
        .build();
    let ref_attrs = select_attrs(
        &sdk_resource_to_sorted_map(&ref_resource),
        &["service.name"],
    );

    let result = compare_resource_attributes(&our_attrs, &ref_attrs, "service detection");

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

    let _guard = OtelEnvGuard::with(&[(
        "OTEL_RESOURCE_ATTRIBUTES",
        Some(
            "service.name=comprehensive-test,service.version=2.1.0,service.namespace=conformance,environment=test,region=us-west-2,cluster=production",
        ),
    )]);

    // Our implementation
    let our_resource = create_our_resource_from_env();
    let comparison_keys = [
        "service.name",
        "service.version",
        "service.namespace",
        "environment",
        "region",
        "cluster",
    ];
    let our_attrs = select_attrs(&resource_to_sorted_map(&our_resource), &comparison_keys);

    // Reference implementation with all detectors
    let ref_resource = SdkResource::builder_empty()
        .with_detector(Box::new(SdkProvidedResourceDetector))
        .with_detector(Box::new(EnvResourceDetector::new()))
        .build();
    let ref_attrs = select_attrs(&sdk_resource_to_sorted_map(&ref_resource), &comparison_keys);

    let result = compare_resource_attributes(&our_attrs, &ref_attrs, "comprehensive detection");

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

fn create_our_resource() -> BTreeMap<String, String> {
    OtlpResourceBuilder::new().build().into_iter().collect()
}

/// Our implementation with environment variable detection
fn create_our_resource_from_env() -> BTreeMap<String, String> {
    OtlpResourceBuilder::new()
        .with_env_resource_attributes()
        .build()
        .into_iter()
        .collect()
}

fn create_our_env_resource_attributes() -> BTreeMap<String, String> {
    OtlpResourceBuilder::new()
        .with_env_resource_attributes()
        .environment_attributes()
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// Convert our Resource representation to sorted map for comparison
fn resource_to_sorted_map(resource: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    resource.clone()
}

/// Convert SDK Resource to sorted map for comparison
fn sdk_resource_to_sorted_map(resource: &SdkResource) -> BTreeMap<String, String> {
    let mut attrs = BTreeMap::new();
    for (key, value) in resource.iter() {
        let key = key.as_str().to_string();
        let value = value.to_string();
        attrs.insert(key, value);
    }
    attrs
}

fn select_attrs(attrs: &BTreeMap<String, String>, keys: &[&str]) -> BTreeMap<String, String> {
    keys.iter()
        .filter_map(|key| {
            attrs
                .get(*key)
                .map(|value| ((*key).to_string(), value.clone()))
        })
        .collect()
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
    for var in OTEL_ENV_VARS {
        remove_env_var(var);
    }
}

struct OtelEnvGuard {
    previous: BTreeMap<&'static str, Option<String>>,
}

impl OtelEnvGuard {
    fn clear() -> Self {
        Self::with(&[])
    }

    fn with(updates: &[(&'static str, Option<&str>)]) -> Self {
        let previous = OTEL_ENV_VARS
            .iter()
            .map(|var| (*var, env::var(var).ok()))
            .collect();

        clear_otel_env_vars();

        for (key, value) in updates {
            match value {
                Some(value) => set_env_var(key, value),
                None => remove_env_var(key),
            }
        }

        Self { previous }
    }
}

impl Drop for OtelEnvGuard {
    fn drop(&mut self) {
        for (key, value) in &self.previous {
            match value {
                Some(value) => set_env_var(key, value),
                None => remove_env_var(key),
            }
        }
    }
}

fn set_env_var(key: &str, value: &str) {
    unsafe {
        env::set_var(key, value);
    }
}

fn remove_env_var(key: &str) {
    unsafe {
        env::remove_var(key);
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
