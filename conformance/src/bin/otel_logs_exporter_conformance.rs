//! OpenTelemetry LogRecord Exporter Conformance Guard
//!
//! This binary exercises the asupersync OTLP/Logs protobuf builder, but it must
//! not claim differential conformance until a live opentelemetry-sdk exporter
//! reference is wired.

use asupersync::observability::otel::otlp_request_builder::{
    OtlpLogRecordInput, OtlpLogScopeInput, logs_request, severity_number_from_bucket,
    severity_text_from_bucket,
};
use clap::{Arg, Command};
use opentelemetry::logs::Severity;
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use prost::Message;
use std::collections::HashMap;
use std::time::SystemTime;

/// Conformance test result tracking
#[derive(Debug, Clone, PartialEq)]
enum ConformanceTestResult {
    Fail { reason: String },
    ExpectedFailure { reason: String },
}

#[derive(Debug, PartialEq)]
enum RequirementLevel {
    Must,   // OpenTelemetry spec MUST clause
    Should, // OpenTelemetry spec SHOULD clause
}

/// Test cases for LogRecord exporter conformance
struct LogExporterTestCase {
    name: &'static str,
    description: &'static str,
    log_inputs: Vec<TestLogInput>,
    requirement_level: RequirementLevel,
}

/// Input for a single log record
#[derive(Clone)]
struct TestLogInput {
    timestamp: SystemTime,
    observed_timestamp: Option<SystemTime>,
    severity: Severity,
    body: String,
    attributes: Vec<(String, String)>,
    resource_attributes: Vec<(String, String)>,
    scope_name: String,
    scope_version: Option<String>,
}

fn main() {
    env_logger::init();

    let matches = Command::new("otel_logs_exporter_conformance")
        .version("0.1.0")
        .about("OpenTelemetry LogRecord exporter fail-closed conformance guard")
        .arg(
            Arg::new("test")
                .help("Test to run")
                .value_parser([
                    "basic-log-export",
                    "severity-levels",
                    "attributes",
                    "timestamps",
                    "multiple-scopes",
                    "resource-attributes",
                    "protobuf-serialization",
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

    let result = match test_name.as_str() {
        "basic-log-export" => run_basic_log_export_test(verbose),
        "severity-levels" => run_severity_levels_test(verbose),
        "attributes" => run_attributes_test(verbose),
        "timestamps" => run_timestamps_test(verbose),
        "multiple-scopes" => run_multiple_scopes_test(verbose),
        "resource-attributes" => run_resource_attributes_test(verbose),
        "protobuf-serialization" => run_protobuf_serialization_test(verbose),
        "report" => {
            generate_compliance_report();
            return;
        }
        "all" => {
            run_all_tests(verbose);
            return;
        }
        _ => {
            eprintln!("Unknown test: {}", test_name);
            std::process::exit(1);
        }
    };

    let exit_code = exit_code_for_result(&result);
    match &result {
        ConformanceTestResult::Fail { reason } => {
            eprintln!("❌ TEST FAILED: {}", reason);
        }
        ConformanceTestResult::ExpectedFailure { reason } => {
            eprintln!("⚠️ EXPECTED FAILURE: {}", reason);
        }
    }

    std::process::exit(exit_code);
}

fn run_all_tests(verbose: bool) {
    println!("=== OpenTelemetry LogRecord Exporter Conformance Guard ===\n");

    let mut total = 0;
    let mut failed = 0;
    let mut xfail = 0;

    // Define test cases
    let test_cases = vec![
        LogExporterTestCase {
            name: "basic-log-export",
            description: "Basic log record export requires a live reference comparison",
            requirement_level: RequirementLevel::Must,
            log_inputs: vec![TestLogInput {
                timestamp: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1640995200),
                observed_timestamp: Some(
                    SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1640995201),
                ),
                severity: Severity::Info,
                body: "Test log message".to_string(),
                attributes: vec![("key1".to_string(), "value1".to_string())],
                resource_attributes: vec![("service.name".to_string(), "test-service".to_string())],
                scope_name: "test-scope".to_string(),
                scope_version: Some("1.0.0".to_string()),
            }],
        },
        LogExporterTestCase {
            name: "severity-levels",
            description: "All severity levels map to correct OTLP values",
            requirement_level: RequirementLevel::Must,
            log_inputs: vec![
                create_test_log(Severity::Trace, "Trace message"),
                create_test_log(Severity::Debug, "Debug message"),
                create_test_log(Severity::Info, "Info message"),
                create_test_log(Severity::Warn, "Warn message"),
                create_test_log(Severity::Error, "Error message"),
                create_test_log(Severity::Fatal, "Fatal message"),
            ],
        },
        LogExporterTestCase {
            name: "attributes",
            description: "Log attributes serialize correctly to OTLP",
            requirement_level: RequirementLevel::Must,
            log_inputs: vec![TestLogInput {
                timestamp: SystemTime::UNIX_EPOCH,
                observed_timestamp: None,
                severity: Severity::Info,
                body: "Message with attributes".to_string(),
                attributes: vec![
                    ("string_attr".to_string(), "string_value".to_string()),
                    ("int_attr".to_string(), "42".to_string()),
                    ("bool_attr".to_string(), "true".to_string()),
                    ("float_attr".to_string(), "3.14".to_string()),
                ],
                resource_attributes: vec![("service.name".to_string(), "attr-test".to_string())],
                scope_name: "attributes-scope".to_string(),
                scope_version: None,
            }],
        },
        LogExporterTestCase {
            name: "timestamps",
            description: "Timestamp and observed timestamp handling",
            requirement_level: RequirementLevel::Must,
            log_inputs: vec![TestLogInput {
                timestamp: SystemTime::UNIX_EPOCH
                    + std::time::Duration::from_nanos(1640995200_123456789),
                observed_timestamp: Some(
                    SystemTime::UNIX_EPOCH + std::time::Duration::from_nanos(1640995200_987654321),
                ),
                severity: Severity::Info,
                body: "Timestamp test".to_string(),
                attributes: vec![],
                resource_attributes: vec![(
                    "service.name".to_string(),
                    "timestamp-test".to_string(),
                )],
                scope_name: "timestamp-scope".to_string(),
                scope_version: None,
            }],
        },
        LogExporterTestCase {
            name: "multiple-scopes",
            description: "Multiple log scopes in single export",
            requirement_level: RequirementLevel::Should,
            log_inputs: vec![
                create_test_log_with_scope(
                    Severity::Info,
                    "Message from scope 1",
                    "scope1",
                    Some("1.0.0"),
                ),
                create_test_log_with_scope(
                    Severity::Warn,
                    "Message from scope 2",
                    "scope2",
                    Some("2.0.0"),
                ),
                create_test_log_with_scope(Severity::Error, "Message from scope 3", "scope3", None),
            ],
        },
    ];

    println!(
        "📋 Running {} LogRecord exporter conformance tests\n",
        test_cases.len()
    );

    for test_case in &test_cases {
        total += 1;

        print!(
            "  Testing {}: {} ... ",
            test_case.name, test_case.description
        );

        let result = run_log_export_conformance_test(test_case, verbose);

        match &result {
            ConformanceTestResult::Fail { reason } => {
                failed += 1;
                println!("❌ FAIL");
                if verbose {
                    println!("    Reason: {}", reason);
                }
            }
            ConformanceTestResult::ExpectedFailure { reason } => {
                xfail += 1;
                println!("⚠️ XFAIL");
                if verbose {
                    println!("    Expected failure: {}", reason);
                }
            }
        }

        // Output structured JSON for CI parsing
        eprintln!(
            "{{\"test\":\"{}\",\"status\":\"{}\",\"level\":\"{:?}\"}}",
            test_case.name,
            match &result {
                ConformanceTestResult::Fail { .. } => "FAIL",
                ConformanceTestResult::ExpectedFailure { .. } => "XFAIL",
            },
            test_case.requirement_level
        );
    }

    // Generate compliance report
    println!("\n📊 OpenTelemetry LogRecord Exporter Conformance Results");
    println!("┌─────────────────────────────────────┐");
    println!("│          CONFORMANCE REPORT         │");
    println!("├─────────────────────────────────────┤");
    println!("│  📋 Total: {}                      │", total);
    println!("│  ✅ Proven: 0                     │");
    println!("│  ❌ Failed: {}                     │", failed);
    println!("│  ⚠️ Expected: {}                   │", xfail);
    println!("│                                     │");
    println!("│  🎯 Score: 0.0%                   │");
    println!("└─────────────────────────────────────┘");

    println!("\n{}", final_status_line(total, failed, xfail));

    let exit_code = exit_code_for_summary(total, failed, xfail);
    if exit_code != 0 {
        if failed > 0 {
            eprintln!("\n❌ {} conformance tests failed", failed);
        }
        if xfail > 0 {
            eprintln!("\n⚠️ {} expected-failure tests require review", xfail);
        }
        std::process::exit(exit_code);
    }

    println!("🎯 OTLP/Logs exporter guard completed without synthetic reference claims");
}

fn exit_code_for_result(result: &ConformanceTestResult) -> i32 {
    match result {
        ConformanceTestResult::Fail { .. } | ConformanceTestResult::ExpectedFailure { .. } => 1,
    }
}

fn exit_code_for_summary(total: usize, failed: usize, expected_failures: usize) -> i32 {
    if total == 0 || failed > 0 || expected_failures > 0 {
        1
    } else {
        0
    }
}

fn final_status_line(total: usize, failed: usize, expected_failures: usize) -> String {
    if total == 0 {
        "NO TESTS EXECUTED".to_string()
    } else if failed > 0 {
        format!("FAILURES PRESENT ({failed} failed, {expected_failures} expected failures)")
    } else if expected_failures > 0 {
        format!("NO FAILURES; PARTIAL COVERAGE ({expected_failures} expected failures)")
    } else {
        "✅ ALL TESTS PASSED - live LogRecord exporter reference matched".to_string()
    }
}

/// Run conformance test for a single test case
fn run_log_export_conformance_test(
    test_case: &LogExporterTestCase,
    _verbose: bool,
) -> ConformanceTestResult {
    // Generate our implementation's OTLP request
    let our_request = match generate_our_otlp_request(test_case) {
        Ok(req) => req,
        Err(e) => {
            return ConformanceTestResult::Fail {
                reason: format!("Failed to generate our OTLP request: {}", e),
            };
        }
    };

    let _our_bytes = our_request.encode_to_vec();

    live_logs_exporter_reference_unavailable(test_case.name)
}

fn live_logs_exporter_reference_unavailable(test_name: &str) -> ConformanceTestResult {
    ConformanceTestResult::ExpectedFailure {
        reason: format!(
            "OpenTelemetry Logs exporter conformance for '{test_name}' is unsupported: \
             no live opentelemetry-sdk logs exporter reference is wired; refusing \
             synthetic protobuf comparison"
        ),
    }
}

/// Generate OTLP request using our implementation
fn generate_our_otlp_request(
    test_case: &LogExporterTestCase,
) -> Result<ExportLogsServiceRequest, Box<dyn std::error::Error>> {
    // Group logs by scope
    let mut scopes_map: HashMap<String, Vec<OtlpLogRecordInput>> = HashMap::new();

    for log_input in &test_case.log_inputs {
        let scope_key = format!(
            "{}:{}",
            log_input.scope_name,
            log_input.scope_version.as_deref().unwrap_or("")
        );

        let otlp_log = OtlpLogRecordInput {
            time_unix_nano: log_input
                .timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
            observed_time_unix_nano: log_input
                .observed_timestamp
                .map(|t| t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos() as u64)
                .unwrap_or(0),
            severity_number: severity_number_from_bucket(severity_to_bucket(&log_input.severity)),
            severity_text: severity_text_from_bucket(severity_to_bucket(&log_input.severity)),
            body: log_input.body.clone(),
            attributes: log_input.attributes.clone(),
        };

        scopes_map.entry(scope_key).or_default().push(otlp_log);
    }

    // Build scope inputs
    let scope_inputs: Vec<OtlpLogScopeInput> = scopes_map
        .into_iter()
        .enumerate()
        .map(|(i, (scope_key, log_records))| {
            let scope_parts: Vec<&str> = scope_key.split(':').collect();
            OtlpLogScopeInput {
                service_name: test_case
                    .log_inputs
                    .get(0)
                    .and_then(|log| {
                        log.resource_attributes
                            .iter()
                            .find(|(k, _)| k == "service.name")
                            .map(|(_, v)| v.clone())
                    })
                    .unwrap_or_else(|| "test-service".to_string()),
                batch_sequence: i as u64,
                scope_name: scope_parts[0].to_string(),
                log_records,
            }
        })
        .collect();

    Ok(logs_request(&scope_inputs))
}

/// Helper to create a test log with default values
fn create_test_log(severity: Severity, body: &str) -> TestLogInput {
    TestLogInput {
        timestamp: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1640995200),
        observed_timestamp: None,
        severity,
        body: body.to_string(),
        attributes: vec![],
        resource_attributes: vec![("service.name".to_string(), "test-service".to_string())],
        scope_name: "test-scope".to_string(),
        scope_version: None,
    }
}

/// Helper to create a test log with specific scope
fn create_test_log_with_scope(
    severity: Severity,
    body: &str,
    scope: &str,
    version: Option<&str>,
) -> TestLogInput {
    TestLogInput {
        timestamp: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1640995200),
        observed_timestamp: None,
        severity,
        body: body.to_string(),
        attributes: vec![],
        resource_attributes: vec![("service.name".to_string(), "multi-scope-test".to_string())],
        scope_name: scope.to_string(),
        scope_version: version.map(|s| s.to_string()),
    }
}

/// Convert Severity to internal bucket representation
fn severity_to_bucket(severity: &Severity) -> u8 {
    match severity {
        Severity::Trace => 1,
        Severity::Trace2 => 2,
        Severity::Trace3 => 3,
        Severity::Trace4 => 4,
        Severity::Debug => 5,
        Severity::Debug2 => 6,
        Severity::Debug3 => 7,
        Severity::Debug4 => 8,
        Severity::Info => 9,
        Severity::Info2 => 10,
        Severity::Info3 => 11,
        Severity::Info4 => 12,
        Severity::Warn => 13,
        Severity::Warn2 => 14,
        Severity::Warn3 => 15,
        Severity::Warn4 => 16,
        Severity::Error => 17,
        Severity::Error2 => 18,
        Severity::Error3 => 19,
        Severity::Error4 => 20,
        Severity::Fatal => 21,
        Severity::Fatal2 => 22,
        Severity::Fatal3 => 23,
        Severity::Fatal4 => 24,
    }
}

/// Individual test runners for specific test cases
fn run_basic_log_export_test(_verbose: bool) -> ConformanceTestResult {
    let test_case = LogExporterTestCase {
        name: "basic-log-export",
        description: "Basic log record export",
        requirement_level: RequirementLevel::Must,
        log_inputs: vec![create_test_log(Severity::Info, "Basic test message")],
    };

    run_log_export_conformance_test(&test_case, false)
}

fn run_severity_levels_test(_verbose: bool) -> ConformanceTestResult {
    let test_case = LogExporterTestCase {
        name: "severity-levels",
        description: "All severity levels",
        requirement_level: RequirementLevel::Must,
        log_inputs: vec![
            create_test_log(Severity::Trace, "Trace message"),
            create_test_log(Severity::Debug, "Debug message"),
            create_test_log(Severity::Info, "Info message"),
            create_test_log(Severity::Warn, "Warn message"),
            create_test_log(Severity::Error, "Error message"),
            create_test_log(Severity::Fatal, "Fatal message"),
        ],
    };

    run_log_export_conformance_test(&test_case, false)
}

fn run_attributes_test(_verbose: bool) -> ConformanceTestResult {
    let test_case = LogExporterTestCase {
        name: "attributes",
        description: "Log attributes serialization",
        requirement_level: RequirementLevel::Must,
        log_inputs: vec![TestLogInput {
            timestamp: SystemTime::UNIX_EPOCH,
            observed_timestamp: None,
            severity: Severity::Info,
            body: "Message with attributes".to_string(),
            attributes: vec![
                ("string_attr".to_string(), "string_value".to_string()),
                ("int_attr".to_string(), "42".to_string()),
            ],
            resource_attributes: vec![("service.name".to_string(), "attr-test".to_string())],
            scope_name: "attributes-scope".to_string(),
            scope_version: None,
        }],
    };

    run_log_export_conformance_test(&test_case, false)
}

fn run_timestamps_test(_verbose: bool) -> ConformanceTestResult {
    let test_case = LogExporterTestCase {
        name: "timestamps",
        description: "Timestamp handling",
        requirement_level: RequirementLevel::Must,
        log_inputs: vec![TestLogInput {
            timestamp: SystemTime::UNIX_EPOCH
                + std::time::Duration::from_nanos(1640995200_123456789),
            observed_timestamp: Some(
                SystemTime::UNIX_EPOCH + std::time::Duration::from_nanos(1640995200_987654321),
            ),
            severity: Severity::Info,
            body: "Timestamp test".to_string(),
            attributes: vec![],
            resource_attributes: vec![("service.name".to_string(), "timestamp-test".to_string())],
            scope_name: "timestamp-scope".to_string(),
            scope_version: None,
        }],
    };

    run_log_export_conformance_test(&test_case, false)
}

fn run_multiple_scopes_test(_verbose: bool) -> ConformanceTestResult {
    let test_case = LogExporterTestCase {
        name: "multiple-scopes",
        description: "Multiple log scopes",
        requirement_level: RequirementLevel::Should,
        log_inputs: vec![
            create_test_log_with_scope(
                Severity::Info,
                "Message from scope 1",
                "scope1",
                Some("1.0.0"),
            ),
            create_test_log_with_scope(
                Severity::Warn,
                "Message from scope 2",
                "scope2",
                Some("2.0.0"),
            ),
        ],
    };

    run_log_export_conformance_test(&test_case, false)
}

fn run_resource_attributes_test(_verbose: bool) -> ConformanceTestResult {
    let test_case = LogExporterTestCase {
        name: "resource-attributes",
        description: "Resource attributes serialization",
        requirement_level: RequirementLevel::Must,
        log_inputs: vec![TestLogInput {
            timestamp: SystemTime::UNIX_EPOCH,
            observed_timestamp: None,
            severity: Severity::Info,
            body: "Resource attributes test".to_string(),
            attributes: vec![],
            resource_attributes: vec![
                ("service.name".to_string(), "resource-test".to_string()),
                ("service.version".to_string(), "1.0.0".to_string()),
                ("deployment.environment".to_string(), "test".to_string()),
            ],
            scope_name: "resource-scope".to_string(),
            scope_version: None,
        }],
    };

    run_log_export_conformance_test(&test_case, false)
}

fn run_protobuf_serialization_test(_verbose: bool) -> ConformanceTestResult {
    let test_case = LogExporterTestCase {
        name: "protobuf-serialization",
        description: "Protobuf serialization consistency",
        requirement_level: RequirementLevel::Must,
        log_inputs: vec![create_test_log(Severity::Info, "Protobuf test message")],
    };

    run_log_export_conformance_test(&test_case, false)
}

/// Generate comprehensive compliance report
fn generate_compliance_report() {
    println!("=== OpenTelemetry LogRecord Exporter Compliance Report ===\n");

    println!("## Coverage Matrix");
    println!();
    println!("| Test Case | Requirement Level | Status | Description |");
    println!("|-----------|--------------------|--------|-------------|");
    println!(
        "| basic-log-export | MUST | XFAIL | Live opentelemetry-sdk logs exporter reference not wired |"
    );
    println!(
        "| severity-levels | MUST | XFAIL | Live opentelemetry-sdk logs exporter reference not wired |"
    );
    println!(
        "| attributes | MUST | XFAIL | Live opentelemetry-sdk logs exporter reference not wired |"
    );
    println!(
        "| timestamps | MUST | XFAIL | Live opentelemetry-sdk logs exporter reference not wired |"
    );
    println!(
        "| multiple-scopes | SHOULD | XFAIL | Live opentelemetry-sdk logs exporter reference not wired |"
    );
    println!(
        "| resource-attributes | MUST | XFAIL | Live opentelemetry-sdk logs exporter reference not wired |"
    );
    println!(
        "| protobuf-serialization | MUST | XFAIL | Live opentelemetry-sdk logs exporter reference not wired |"
    );
    println!();

    println!("## Specification Coverage");
    println!();
    println!("### MUST clauses: 0/6 proven");
    println!("### SHOULD clauses: 0/1 proven");
    println!("### Overall score: 0% proven");
    println!();

    println!("## Known Divergences");
    println!();
    println!(
        "All rows are expected failures until a live opentelemetry-sdk logs exporter reference is wired."
    );
    println!();

    println!(
        "REFERENCE UNAVAILABLE - live opentelemetry-sdk logs exporter reference is not wired; refusing synthetic parity claims"
    );
}

#[cfg(test)]
mod tests {
    use super::{
        ConformanceTestResult, exit_code_for_result, exit_code_for_summary, final_status_line,
        live_logs_exporter_reference_unavailable, run_basic_log_export_test,
    };

    #[test]
    fn exit_code_is_nonzero_for_expected_failure_results() {
        let result = ConformanceTestResult::ExpectedFailure {
            reason: "known divergence".to_string(),
        };

        assert_eq!(exit_code_for_result(&result), 1);
    }

    #[test]
    fn exit_code_is_nonzero_for_failure_results() {
        let result = ConformanceTestResult::Fail {
            reason: "mismatch".to_string(),
        };

        assert_eq!(exit_code_for_result(&result), 1);
    }

    #[test]
    fn exit_code_is_zero_only_for_clean_summary() {
        assert_eq!(exit_code_for_summary(5, 0, 0), 0);
        assert_eq!(exit_code_for_summary(0, 0, 0), 1);
        assert_eq!(exit_code_for_summary(5, 1, 0), 1);
        assert_eq!(exit_code_for_summary(5, 0, 1), 1);
    }

    #[test]
    fn final_status_line_reports_partial_coverage_for_xfail_only() {
        let status = final_status_line(5, 0, 1);

        assert!(status.contains("NO FAILURES; PARTIAL COVERAGE"));
        assert!(!status.contains("ALL TESTS PASSED"));
    }

    #[test]
    fn final_status_line_reports_zero_coverage() {
        assert_eq!(final_status_line(0, 0, 0), "NO TESTS EXECUTED");
    }

    #[test]
    fn final_status_line_reports_true_all_pass() {
        assert!(final_status_line(5, 0, 0).contains("ALL TESTS PASSED"));
    }

    #[test]
    fn log_export_conformance_fails_closed_without_live_reference() {
        let result = run_basic_log_export_test(false);

        match result {
            ConformanceTestResult::ExpectedFailure { reason } => {
                assert!(reason.contains("live opentelemetry-sdk logs exporter reference"));
                assert!(reason.contains("refusing synthetic protobuf comparison"));
            }
            other => panic!("expected fail-closed xfail, got {other:?}"),
        }
    }

    #[test]
    fn reference_unavailable_message_names_test_case() {
        let result = live_logs_exporter_reference_unavailable("attributes");

        match result {
            ConformanceTestResult::ExpectedFailure { reason } => {
                assert!(reason.contains("attributes"));
                assert!(reason.contains("no live opentelemetry-sdk logs exporter reference"));
            }
            other => panic!("expected fail-closed xfail, got {other:?}"),
        }
    }

    #[test]
    fn source_no_longer_contains_synthetic_reference_claims() {
        let source = include_str!("otel_logs_exporter_conformance.rs");

        assert!(!source.contains(concat!(
            "For ",
            "now, create",
            " a simplified reference request manually"
        )));
        assert!(!source.contains(concat!(
            "produces identical OTLP/Logs protobuf",
            " vs opentelemetry-sdk"
        )));
        assert!(!source.contains(concat!("Overall score: ", "100%")));
    }
}
