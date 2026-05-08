//! OpenTelemetry Span Status Conformance Test
//!
//! Local OTLP/Trace status-field checks with fail-closed handling for the
//! missing live opentelemetry-sdk exporter reference.

use asupersync::observability::otel::otlp_request_builder::{OTEL_SCOPE_NAME, traces_request};
use asupersync::observability::otel::span_semantics::TestSpan;
use clap::{Arg, Command};
use opentelemetry::trace::{
    SpanContext, SpanId, SpanKind, Status, TraceFlags, TraceId, TraceState,
};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::trace::v1::{
    Span as ProtoSpan, status::StatusCode as ProtoStatusCode,
};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const OTEL_SDK_REFERENCE_UNIMPLEMENTED: &str =
    "live opentelemetry-sdk span status reference is not wired";

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

/// Test cases for Span Status conformance
struct SpanStatusTestCase {
    name: &'static str,
    description: &'static str,
    span_inputs: Vec<TestSpanInput>,
    requirement_level: RequirementLevel,
}

/// Input for a single span with status
#[derive(Clone)]
struct TestSpanInput {
    name: String,
    span_kind: SpanKind,
    start_time: SystemTime,
    end_time: SystemTime,
    status: Status,
    attributes: Vec<(String, String)>,
    events: Vec<TestSpanEvent>,
    trace_id: [u8; 16],
    span_id: [u8; 8],
    parent_span_id: Option<[u8; 8]>,
}

/// Test span event
#[derive(Clone)]
struct TestSpanEvent {
    name: String,
    attributes: Vec<(String, String)>,
}

fn main() {
    env_logger::init();

    let matches = Command::new("otel_span_status_conformance")
        .version("0.1.0")
        .about("OpenTelemetry Span Status local checks; live opentelemetry-sdk reference is XFAIL")
        .arg(
            Arg::new("test")
                .help("Test to run")
                .value_parser([
                    "basic-status-codes",
                    "status-with-messages",
                    "status-transitions",
                    "error-status-scenarios",
                    "unset-status-default",
                    "status-protobuf-serialization",
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
        "basic-status-codes" => {
            exit_if_not_pass("basic-status-codes", run_basic_status_codes_test(verbose))
        }
        "status-with-messages" => exit_if_not_pass(
            "status-with-messages",
            run_status_with_messages_test(verbose),
        ),
        "status-transitions" => {
            exit_if_not_pass("status-transitions", run_status_transitions_test(verbose))
        }
        "error-status-scenarios" => exit_if_not_pass(
            "error-status-scenarios",
            run_error_status_scenarios_test(verbose),
        ),
        "unset-status-default" => exit_if_not_pass(
            "unset-status-default",
            run_unset_status_default_test(verbose),
        ),
        "status-protobuf-serialization" => exit_if_not_pass(
            "status-protobuf-serialization",
            run_status_protobuf_serialization_test(verbose),
        ),
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

fn exit_if_not_pass(test_name: &str, result: ConformanceTestResult) {
    let exit_code = exit_code_for_result(&result);
    if exit_code == 0 {
        return;
    }

    match result {
        ConformanceTestResult::Fail { reason } => {
            eprintln!("{test_name}: FAIL - {reason}");
        }
        ConformanceTestResult::ExpectedFailure { reason } => {
            eprintln!("{test_name}: XFAIL - {reason}");
        }
    }

    std::process::exit(exit_code);
}

fn run_all_tests(verbose: bool) {
    println!("=== OpenTelemetry Span Status Conformance Testing ===\n");

    let mut total = 0;
    let passed = 0;
    let mut failed = 0;
    let mut xfail = 0;

    // Define test cases
    let test_cases = vec![
        SpanStatusTestCase {
            name: "basic-status-codes",
            description: "Basic status codes (UNSET, OK, ERROR) map correctly to OTLP",
            requirement_level: RequirementLevel::Must,
            span_inputs: vec![
                create_test_span_with_status("span_unset", Status::Unset),
                create_test_span_with_status("span_ok", Status::Ok),
                create_test_span_with_status("span_error", Status::error("Basic error")),
            ],
        },
        SpanStatusTestCase {
            name: "status-with-messages",
            description: "Status with custom messages serialize correctly",
            requirement_level: RequirementLevel::Must,
            span_inputs: vec![
                create_test_span_with_status(
                    "span_error_with_msg",
                    Status::error("Database connection failed"),
                ),
                create_test_span_with_status(
                    "span_error_long_msg",
                    Status::error(
                        "A very long error message that should be preserved in the OTLP protobuf serialization exactly as provided without truncation or modification",
                    ),
                ),
                create_test_span_with_status("span_error_empty_msg", Status::error("")),
            ],
        },
        SpanStatusTestCase {
            name: "status-transitions",
            description: "Status transitions within span lifecycle",
            requirement_level: RequirementLevel::Should,
            span_inputs: vec![
                create_test_span_with_status("span_final_ok", Status::Ok),
                create_test_span_with_status(
                    "span_final_error",
                    Status::error("Final error state"),
                ),
            ],
        },
        SpanStatusTestCase {
            name: "error-status-scenarios",
            description: "Various error status scenarios",
            requirement_level: RequirementLevel::Must,
            span_inputs: vec![
                create_test_span_with_status("timeout_error", Status::error("Operation timed out")),
                create_test_span_with_status(
                    "validation_error",
                    Status::error("Invalid input parameters"),
                ),
                create_test_span_with_status("network_error", Status::error("Network unreachable")),
                create_test_span_with_status("auth_error", Status::error("Authentication failed")),
            ],
        },
        SpanStatusTestCase {
            name: "unset-status-default",
            description: "Default UNSET status behavior",
            requirement_level: RequirementLevel::Must,
            span_inputs: vec![create_test_span_with_status(
                "default_status",
                Status::Unset,
            )],
        },
    ];

    println!(
        "📋 Running {} Span Status conformance tests\n",
        test_cases.len()
    );

    for test_case in &test_cases {
        total += 1;

        print!(
            "  Testing {}: {} ... ",
            test_case.name, test_case.description
        );

        let result = run_span_status_conformance_test(test_case, verbose);

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
    println!("\n📊 OpenTelemetry Span Status Conformance Results");
    println!("┌─────────────────────────────────────┐");
    println!("│          CONFORMANCE REPORT         │");
    println!("├─────────────────────────────────────┤");
    println!("│  📋 Total: {}                      │", total);
    println!("│  ✅ Passed: {}                     │", passed);
    println!("│  ❌ Failed: {}                     │", failed);
    println!("│  ⚠️ Expected: {}                   │", xfail);
    println!("│                                     │");
    let score = if total > 0 {
        (passed as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    println!("│  🎯 Score: {:.1}%                   │", score);
    println!("└─────────────────────────────────────┘");

    println!("\n{}", final_status_line(total, failed, xfail));

    if exit_code_for_summary(total, failed, xfail) != 0 {
        eprintln!("\nDifferences documented in DISCREPANCIES.md");
        std::process::exit(exit_code_for_summary(total, failed, xfail));
    } else {
        println!("🎯 All enabled OTLP/Trace status checks passed");
    }
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
        "✅ ALL ENABLED CHECKS PASSED - Span Status local checks passed".to_string()
    }
}

/// Run conformance test for a single test case
fn run_span_status_conformance_test(
    test_case: &SpanStatusTestCase,
    _verbose: bool,
) -> ConformanceTestResult {
    // Generate the local asupersync OTLP request and verify it against the
    // explicit test oracle before reporting the missing reference seam.
    let our_request = match generate_our_otlp_traces_request(test_case) {
        Ok(req) => req,
        Err(e) => {
            return ConformanceTestResult::Fail {
                reason: format!("Failed to generate our OTLP request: {}", e),
            };
        }
    };

    if let Err(reason) = verify_status_fields_against_inputs(test_case, &our_request) {
        return ConformanceTestResult::Fail {
            reason: format!("local OTLP status request mismatch: {reason}"),
        };
    }

    ConformanceTestResult::ExpectedFailure {
        reason: format!(
            "{OTEL_SDK_REFERENCE_UNIMPLEMENTED}; local status request matched the test oracle, but live opentelemetry-sdk parity remains unexercised"
        ),
    }
}

fn verify_status_fields_against_inputs(
    test_case: &SpanStatusTestCase,
    request: &ExportTraceServiceRequest,
) -> Result<(), String> {
    let spans: Vec<&ProtoSpan> = request
        .resource_spans
        .iter()
        .flat_map(|rs| rs.scope_spans.iter())
        .flat_map(|ss| ss.spans.iter())
        .collect();

    if spans.len() != test_case.span_inputs.len() {
        return Err(format!(
            "span count mismatch: expected={}, got={}",
            test_case.span_inputs.len(),
            spans.len()
        ));
    }

    for (index, (span, input)) in spans.iter().zip(test_case.span_inputs.iter()).enumerate() {
        let Some(status) = span.status.as_ref() else {
            return Err(format!(
                "span[{index}] '{}' missing status field",
                input.name
            ));
        };

        let expected_code = status_to_proto_code(&input.status);
        if status.code != expected_code {
            return Err(format!(
                "span[{index}] '{}' status code mismatch: expected={}, got={}",
                input.name, expected_code, status.code
            ));
        }

        let expected_message = status_to_message(&input.status);
        if status.message != expected_message {
            return Err(format!(
                "span[{index}] '{}' status message mismatch: expected='{}', got='{}'",
                input.name, expected_message, status.message
            ));
        }
    }

    Ok(())
}

/// Generate OTLP traces request using our implementation
fn generate_our_otlp_traces_request(
    test_case: &SpanStatusTestCase,
) -> Result<ExportTraceServiceRequest, Box<dyn std::error::Error>> {
    // Convert test spans to our format
    let our_spans: Vec<TestSpan> = test_case
        .span_inputs
        .iter()
        .map(|input| {
            // Create SpanContext
            let trace_id = TraceId::from_bytes(input.trace_id);
            let span_id = SpanId::from_bytes(input.span_id);
            let trace_flags = TraceFlags::default();
            let trace_state = TraceState::default();
            let span_context =
                SpanContext::new(trace_id, span_id, trace_flags, false, trace_state.clone());

            // Create parent context if provided
            let parent_context = input.parent_span_id.map(|parent_id| {
                let parent_span_id = SpanId::from_bytes(parent_id);
                SpanContext::new(
                    trace_id,
                    parent_span_id,
                    trace_flags,
                    false,
                    trace_state.clone(),
                )
            });

            let mut span = TestSpan::new(&input.name, input.span_kind.clone());
            span.context = span_context;
            span.start_time = input.start_time;
            span.end_time = Some(input.end_time);
            span.parent_context = parent_context;
            span.set_status(input.status.clone());

            for (key, value) in &input.attributes {
                span.set_attribute(key, value);
            }

            for event in &input.events {
                let attributes: HashMap<String, String> =
                    event.attributes.iter().cloned().collect();
                span.add_event(&event.name, attributes);
            }

            span
        })
        .collect();

    Ok(traces_request(
        "test-service",
        0, // batch_sequence
        OTEL_SCOPE_NAME,
        &our_spans,
    ))
}

/// Helper to create a test span with specific status
fn create_test_span_with_status(name: &str, status: Status) -> TestSpanInput {
    TestSpanInput {
        name: name.to_string(),
        span_kind: SpanKind::Internal,
        start_time: UNIX_EPOCH + Duration::from_secs(1640995200),
        end_time: UNIX_EPOCH + Duration::from_secs(1640995201),
        status,
        attributes: vec![],
        events: vec![],
        trace_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        span_id: [1, 2, 3, 4, 5, 6, 7, 8],
        parent_span_id: None,
    }
}

/// Convert OpenTelemetry Status to protobuf status code
fn status_to_proto_code(status: &Status) -> i32 {
    match status {
        Status::Unset => ProtoStatusCode::Unset as i32,
        Status::Ok => ProtoStatusCode::Ok as i32,
        Status::Error { .. } => ProtoStatusCode::Error as i32,
    }
}

/// Extract status message from OpenTelemetry Status
fn status_to_message(status: &Status) -> String {
    match status {
        Status::Unset => String::new(),
        Status::Ok => String::new(),
        Status::Error { description } => description.to_string(),
    }
}

/// Individual test runners for specific test cases
fn run_basic_status_codes_test(_verbose: bool) -> ConformanceTestResult {
    let test_case = SpanStatusTestCase {
        name: "basic-status-codes",
        description: "Basic status codes",
        requirement_level: RequirementLevel::Must,
        span_inputs: vec![
            create_test_span_with_status("span_unset", Status::Unset),
            create_test_span_with_status("span_ok", Status::Ok),
            create_test_span_with_status("span_error", Status::error("Test error")),
        ],
    };

    run_span_status_conformance_test(&test_case, false)
}

fn run_status_with_messages_test(_verbose: bool) -> ConformanceTestResult {
    let test_case = SpanStatusTestCase {
        name: "status-with-messages",
        description: "Status with messages",
        requirement_level: RequirementLevel::Must,
        span_inputs: vec![
            create_test_span_with_status("span_error_msg", Status::error("Database error")),
            create_test_span_with_status("span_error_empty", Status::error("")),
        ],
    };

    run_span_status_conformance_test(&test_case, false)
}

fn run_status_transitions_test(_verbose: bool) -> ConformanceTestResult {
    let test_case = SpanStatusTestCase {
        name: "status-transitions",
        description: "Status transitions",
        requirement_level: RequirementLevel::Should,
        span_inputs: vec![
            create_test_span_with_status("final_ok", Status::Ok),
            create_test_span_with_status("final_error", Status::error("Final error")),
        ],
    };

    run_span_status_conformance_test(&test_case, false)
}

fn run_error_status_scenarios_test(_verbose: bool) -> ConformanceTestResult {
    let test_case = SpanStatusTestCase {
        name: "error-status-scenarios",
        description: "Error scenarios",
        requirement_level: RequirementLevel::Must,
        span_inputs: vec![
            create_test_span_with_status("timeout", Status::error("Timeout")),
            create_test_span_with_status("auth_fail", Status::error("Auth failed")),
        ],
    };

    run_span_status_conformance_test(&test_case, false)
}

fn run_unset_status_default_test(_verbose: bool) -> ConformanceTestResult {
    let test_case = SpanStatusTestCase {
        name: "unset-status-default",
        description: "Default UNSET status",
        requirement_level: RequirementLevel::Must,
        span_inputs: vec![create_test_span_with_status("default", Status::Unset)],
    };

    run_span_status_conformance_test(&test_case, false)
}

fn run_status_protobuf_serialization_test(_verbose: bool) -> ConformanceTestResult {
    let test_case = SpanStatusTestCase {
        name: "status-protobuf-serialization",
        description: "Protobuf serialization",
        requirement_level: RequirementLevel::Must,
        span_inputs: vec![create_test_span_with_status(
            "serialization",
            Status::error("Serialization test"),
        )],
    };

    run_span_status_conformance_test(&test_case, false)
}

/// Generate comprehensive compliance report
fn generate_compliance_report() {
    println!("=== OpenTelemetry Span Status Compliance Report ===\n");

    println!("## Coverage Matrix");
    println!();
    println!("| Test Case | Requirement Level | Local Status Oracle | Live SDK Reference |");
    println!("|-----------|--------------------|---------------------|--------------------|");
    println!("| basic-status-codes | MUST | checked | XFAIL - not wired |");
    println!("| status-with-messages | MUST | checked | XFAIL - not wired |");
    println!("| status-transitions | SHOULD | checked | XFAIL - not wired |");
    println!("| error-status-scenarios | MUST | checked | XFAIL - not wired |");
    println!("| unset-status-default | MUST | checked | XFAIL - not wired |");
    println!("| status-protobuf-serialization | MUST | checked | XFAIL - not wired |");
    println!();

    println!("## Specification Coverage");
    println!();
    println!("### Local OTLP status oracle: available");
    println!("### Live opentelemetry-sdk reference: unavailable");
    println!("### Overall score: unavailable");
    println!();

    println!("## Known Divergences");
    println!();
    println!("- {OTEL_SDK_REFERENCE_UNIMPLEMENTED}");
    println!();

    println!(
        "⚠️ **XFAIL** - Span Status local checks run, but live opentelemetry-sdk parity is not proven"
    );
}

#[cfg(test)]
mod tests {
    use super::{
        ConformanceTestResult, OTEL_SDK_REFERENCE_UNIMPLEMENTED, exit_code_for_result,
        exit_code_for_summary, final_status_line, run_basic_status_codes_test,
    };

    #[test]
    fn exit_code_is_nonzero_for_expected_failure_results() {
        let result = ConformanceTestResult::ExpectedFailure {
            reason: "known divergence".to_string(),
        };

        assert_eq!(exit_code_for_result(&result), 1);
    }

    #[test]
    fn span_status_runner_xfails_without_live_sdk_reference() {
        let result = run_basic_status_codes_test(false);

        match result {
            ConformanceTestResult::ExpectedFailure { reason } => {
                assert!(reason.contains(OTEL_SDK_REFERENCE_UNIMPLEMENTED));
                assert!(reason.contains("local status request matched the test oracle"));
            }
            other => panic!("expected XFAIL while SDK reference is unwired, got {other:?}"),
        }
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
        let status = final_status_line(5, 0, 0);

        assert!(status.contains("ALL ENABLED CHECKS PASSED"));
        assert!(!status.contains("conformant"));
    }

    #[test]
    fn source_no_longer_claims_synthetic_sdk_parity() {
        let source = include_str!("otel_span_status_conformance.rs");

        assert!(!source.contains(concat!("generate_reference_", "otlp_traces_request")));
        assert!(!source.contains(concat!("MUST clauses: 5/5 ", "(100%)")));
        assert!(!source.contains(concat!(
            "CONFORMANT** - Span Status setting produces ",
            "identical ",
            "OTLP/Trace status field vs opentelemetry"
        )));
        assert!(!source.contains(concat!(
            "Pattern 1: Differential Testing vs ",
            "opentelemetry-sdk"
        )));
    }
}
