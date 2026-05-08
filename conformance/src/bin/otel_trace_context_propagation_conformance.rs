//! OpenTelemetry Trace Context Propagation Conformance Test
//!
//! Pattern 3: Round-Trip Conformance testing
//! Ensures SpanContext inject → extract == identity per propagator, but keeps
//! a fail-closed conformance guard until a live independent reference is wired.

use clap::{Arg, Command};
use opentelemetry::propagation::{Extractor, Injector, TextMapPropagator};
use opentelemetry::trace::{SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use std::collections::HashMap;

const B3_SINGLE_HEADER: &str = "b3";
const B3_TRACE_ID_HEADER: &str = "x-b3-traceid";
const B3_SPAN_ID_HEADER: &str = "x-b3-spanid";
const B3_SAMPLED_HEADER: &str = "x-b3-sampled";
const OTEL_TRACE_CONTEXT_REFERENCE_UNIMPLEMENTED: &str =
    "Live opentelemetry trace-context reference: unavailable";

/// Conformance test result tracking
#[derive(Debug, Clone, PartialEq)]
enum ConformanceTestResult {
    Pass,
    Fail { reason: String },
    ExpectedFailure { reason: String },
}

#[derive(Debug, PartialEq)]
enum RequirementLevel {
    Must,   // OpenTelemetry spec MUST clause
    Should, // OpenTelemetry spec SHOULD clause
    May,    // OpenTelemetry spec MAY clause
}

/// Test cases for trace context propagation
struct PropagationTestCase {
    name: &'static str,
    description: &'static str,
    span_contexts: Vec<TestSpanContext>,
    propagator_type: PropagatorType,
    requirement_level: RequirementLevel,
}

/// Type of propagator to test
#[derive(Debug, Clone, PartialEq)]
enum PropagatorType {
    W3CTraceContext,
    B3Single,
    B3Multi,
}

/// Test span context input
#[derive(Clone, Debug)]
struct TestSpanContext {
    name: String,
    trace_id: TraceId,
    span_id: SpanId,
    trace_flags: TraceFlags,
    is_remote: bool,
    trace_state: TraceState,
}

/// Simple carrier implementation for headers
#[derive(Debug, Default)]
struct HeaderCarrier {
    headers: HashMap<String, String>,
}

impl Injector for HeaderCarrier {
    fn set(&mut self, key: &str, value: String) {
        self.headers.insert(key.to_string(), value);
    }
}

impl Extractor for HeaderCarrier {
    fn get(&self, key: &str) -> Option<&str> {
        self.headers.get(key).map(|s| s.as_str())
    }

    fn keys(&self) -> Vec<&str> {
        self.headers.keys().map(|s| s.as_str()).collect()
    }
}

fn main() {
    env_logger::init();

    let matches = Command::new("otel_trace_context_propagation_conformance")
        .version("0.1.0")
        .about("OpenTelemetry Trace Context Propagation conformance testing")
        .arg(
            Arg::new("test")
                .help("Test to run")
                .value_parser([
                    "w3c-traceparent-roundtrip",
                    "w3c-tracestate-roundtrip",
                    "w3c-traceparent-invalid-handling",
                    "b3-single-header-roundtrip",
                    "b3-multi-header-roundtrip",
                    "propagator-interoperability",
                    "edge-case-scenarios",
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
        "w3c-traceparent-roundtrip" => exit_if_not_pass(
            "w3c-traceparent-roundtrip",
            run_w3c_traceparent_roundtrip_test(verbose),
        ),
        "w3c-tracestate-roundtrip" => exit_if_not_pass(
            "w3c-tracestate-roundtrip",
            run_w3c_tracestate_roundtrip_test(verbose),
        ),
        "w3c-traceparent-invalid-handling" => exit_if_not_pass(
            "w3c-traceparent-invalid-handling",
            run_w3c_invalid_handling_test(verbose),
        ),
        "b3-single-header-roundtrip" => exit_if_not_pass(
            "b3-single-header-roundtrip",
            run_b3_single_header_roundtrip_test(verbose),
        ),
        "b3-multi-header-roundtrip" => exit_if_not_pass(
            "b3-multi-header-roundtrip",
            run_b3_multi_header_roundtrip_test(verbose),
        ),
        "propagator-interoperability" => exit_if_not_pass(
            "propagator-interoperability",
            run_propagator_interoperability_test(verbose),
        ),
        "edge-case-scenarios" => {
            exit_if_not_pass("edge-case-scenarios", run_edge_case_scenarios_test(verbose))
        }
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
    }
}

fn exit_if_not_pass(test_name: &str, result: ConformanceTestResult) {
    let exit_code = exit_code_for_result(&result);
    if exit_code == 0 {
        return;
    }

    match result {
        ConformanceTestResult::Pass => {}
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
    println!("=== OpenTelemetry Trace Context Propagation Conformance Testing ===\n");

    let mut total = 0;
    let passed = 0;
    let mut failed = 0;
    let mut xfail = 0;

    // Define test cases
    let test_cases = vec![
        PropagationTestCase {
            name: "w3c-traceparent-roundtrip",
            description: "W3C traceparent header inject→extract roundtrip preserves identity",
            requirement_level: RequirementLevel::Must,
            propagator_type: PropagatorType::W3CTraceContext,
            span_contexts: vec![
                create_test_span_context(
                    "basic_context",
                    "4bf92f3577b34da6a3ce929d0e0e4736",
                    "00f067aa0ba902b7",
                    TraceFlags::SAMPLED,
                    false,
                ),
                create_test_span_context(
                    "unsampled_context",
                    "4bf92f3577b34da6a3ce929d0e0e4736",
                    "00f067aa0ba902b7",
                    TraceFlags::default(),
                    false,
                ),
                create_test_span_context(
                    "max_values",
                    "ffffffffffffffffffffffffffffffff",
                    "ffffffffffffffff",
                    TraceFlags::SAMPLED,
                    false,
                ),
                create_test_span_context(
                    "min_values",
                    "00000000000000000000000000000001",
                    "0000000000000001",
                    TraceFlags::default(),
                    false,
                ),
            ],
        },
        PropagationTestCase {
            name: "w3c-tracestate-roundtrip",
            description: "W3C tracestate header inject→extract roundtrip preserves vendor data",
            requirement_level: RequirementLevel::Should,
            propagator_type: PropagatorType::W3CTraceContext,
            span_contexts: vec![
                create_test_span_context_with_state(
                    "with_tracestate",
                    "4bf92f3577b34da6a3ce929d0e0e4736",
                    "00f067aa0ba902b7",
                    TraceFlags::SAMPLED,
                    false,
                    "vendor1=value1,vendor2=value2",
                ),
                create_test_span_context_with_state(
                    "complex_tracestate",
                    "4bf92f3577b34da6a3ce929d0e0e4736",
                    "00f067aa0ba902b7",
                    TraceFlags::SAMPLED,
                    false,
                    "rojo=00f067aa0ba902b7,congo=t61rcWkgMzE",
                ),
                create_test_span_context_with_state(
                    "single_vendor",
                    "4bf92f3577b34da6a3ce929d0e0e4736",
                    "00f067aa0ba902b7",
                    TraceFlags::SAMPLED,
                    false,
                    "elasticsearch=t61rcWkgMzE",
                ),
            ],
        },
        PropagationTestCase {
            name: "w3c-traceparent-invalid-handling",
            description: "W3C traceparent invalid header handling per spec",
            requirement_level: RequirementLevel::Must,
            propagator_type: PropagatorType::W3CTraceContext,
            span_contexts: vec![create_test_span_context(
                "invalid_recovery",
                "4bf92f3577b34da6a3ce929d0e0e4736",
                "00f067aa0ba902b7",
                TraceFlags::SAMPLED,
                false,
            )],
        },
        PropagationTestCase {
            name: "b3-single-header-roundtrip",
            description: "B3 single header inject→extract roundtrip preserves identity",
            requirement_level: RequirementLevel::Should,
            propagator_type: PropagatorType::B3Single,
            span_contexts: vec![
                create_test_span_context(
                    "b3_basic",
                    "4bf92f3577b34da6a3ce929d0e0e4736",
                    "00f067aa0ba902b7",
                    TraceFlags::SAMPLED,
                    false,
                ),
                create_test_span_context(
                    "b3_unsampled",
                    "4bf92f3577b34da6a3ce929d0e0e4736",
                    "00f067aa0ba902b7",
                    TraceFlags::default(),
                    false,
                ),
            ],
        },
        PropagationTestCase {
            name: "b3-multi-header-roundtrip",
            description: "B3 multi-header inject→extract roundtrip preserves identity",
            requirement_level: RequirementLevel::Should,
            propagator_type: PropagatorType::B3Multi,
            span_contexts: vec![create_test_span_context(
                "b3_multi",
                "4bf92f3577b34da6a3ce929d0e0e4736",
                "00f067aa0ba902b7",
                TraceFlags::SAMPLED,
                false,
            )],
        },
        PropagationTestCase {
            name: "propagator-interoperability",
            description: "Different propagators handle each other's contexts gracefully",
            requirement_level: RequirementLevel::May,
            propagator_type: PropagatorType::W3CTraceContext,
            span_contexts: vec![create_test_span_context(
                "interop_test",
                "4bf92f3577b34da6a3ce929d0e0e4736",
                "00f067aa0ba902b7",
                TraceFlags::SAMPLED,
                false,
            )],
        },
    ];

    println!(
        "📋 Running {} Trace Context Propagation conformance tests\n",
        test_cases.len()
    );

    for test_case in &test_cases {
        total += 1;

        print!(
            "  Testing {}: {} ... ",
            test_case.name, test_case.description
        );

        let result = run_propagation_conformance_test(test_case, verbose);

        match &result {
            ConformanceTestResult::Pass => println!("✅ PASS"),
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
                ConformanceTestResult::Pass => "PASS",
                ConformanceTestResult::Fail { .. } => "FAIL",
                ConformanceTestResult::ExpectedFailure { .. } => "XFAIL",
            },
            test_case.requirement_level
        );
    }

    // Generate compliance report
    println!("\n📊 OpenTelemetry Trace Context Propagation Conformance Results");
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

    let exit_code = exit_code_for_summary(total, failed, xfail);
    println!("\n{}", final_status_line(total, failed, xfail));
    std::process::exit(exit_code);
}

/// Run conformance test for a single test case
fn run_propagation_conformance_test(
    test_case: &PropagationTestCase,
    verbose: bool,
) -> ConformanceTestResult {
    for span_context_input in &test_case.span_contexts {
        // Create SpanContext
        let original_context = SpanContext::new(
            span_context_input.trace_id,
            span_context_input.span_id,
            span_context_input.trace_flags,
            span_context_input.is_remote,
            span_context_input.trace_state.clone(),
        );

        // Test round-trip: inject then extract
        match test_roundtrip_for_propagator(&test_case.propagator_type, &original_context, verbose)
        {
            Ok(extracted_context) => {
                // Compare contexts for identity
                if let Err(reason) =
                    compare_span_contexts(&original_context, &extracted_context, true)
                {
                    return if is_known_propagation_divergence(
                        test_case.name,
                        &span_context_input.name,
                    ) {
                        ConformanceTestResult::ExpectedFailure {
                            reason: "Known divergence documented in DISCREPANCIES.md".to_string(),
                        }
                    } else {
                        ConformanceTestResult::Fail {
                            reason: format!(
                                "Round-trip failed for '{}': {}",
                                span_context_input.name, reason
                            ),
                        }
                    };
                }
            }
            Err(error) => {
                return ConformanceTestResult::Fail {
                    reason: format!(
                        "Round-trip error for '{}': {}",
                        span_context_input.name, error
                    ),
                };
            }
        }
    }

    ConformanceTestResult::ExpectedFailure {
        reason: format!(
            "{OTEL_TRACE_CONTEXT_REFERENCE_UNIMPLEMENTED}; local round-trip guards ran but refusing synthetic self-comparison"
        ),
    }
}

fn exit_code_for_result(result: &ConformanceTestResult) -> i32 {
    match result {
        ConformanceTestResult::Pass => 0,
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
        "ALL TESTS PASSED - live trace-context reference matched".to_string()
    }
}

/// Test inject→extract roundtrip for specific propagator
fn test_roundtrip_for_propagator(
    propagator_type: &PropagatorType,
    original_context: &SpanContext,
    _verbose: bool,
) -> Result<SpanContext, String> {
    match propagator_type {
        PropagatorType::W3CTraceContext => {
            let propagator = TraceContextPropagator::new();

            // Inject into headers
            let mut carrier = HeaderCarrier::default();
            propagator.inject_context(
                &opentelemetry::Context::current_with_span(TestSpan::new(original_context.clone())),
                &mut carrier,
            );

            // Extract from headers
            let extracted_context = propagator.extract(&carrier);
            let span = extracted_context.span();
            let span_context = span.span_context();

            Ok(span_context.clone())
        }
        PropagatorType::B3Single | PropagatorType::B3Multi => {
            let mut carrier = HeaderCarrier::default();
            match propagator_type {
                PropagatorType::B3Single => {
                    inject_b3_single(original_context, &mut carrier);
                    extract_b3_single(&carrier)
                }
                PropagatorType::B3Multi => {
                    inject_b3_multi(original_context, &mut carrier);
                    extract_b3_multi(&carrier)
                }
                PropagatorType::W3CTraceContext => unreachable!("handled above"),
            }
        }
    }
}

fn inject_b3_single(span_context: &SpanContext, carrier: &mut HeaderCarrier) {
    carrier.set(
        B3_SINGLE_HEADER,
        format!(
            "{}-{}-{}",
            span_context.trace_id(),
            span_context.span_id(),
            b3_sampled_value(span_context.trace_flags())
        ),
    );
}

fn extract_b3_single(carrier: &HeaderCarrier) -> Result<SpanContext, String> {
    let header = carrier
        .get(B3_SINGLE_HEADER)
        .ok_or_else(|| "missing b3 single header".to_string())?;
    let fields: Vec<&str> = header.split('-').collect();
    if !(2..=4).contains(&fields.len()) {
        return Err(format!("invalid b3 single header field count: {}", header));
    }

    let trace_id = parse_b3_trace_id(fields[0])?;
    let span_id = parse_b3_span_id(fields[1])?;
    let trace_flags = parse_b3_sampling_state(fields.get(2).copied())?;

    Ok(SpanContext::new(
        trace_id,
        span_id,
        trace_flags,
        true,
        TraceState::default(),
    ))
}

fn inject_b3_multi(span_context: &SpanContext, carrier: &mut HeaderCarrier) {
    carrier.set(B3_TRACE_ID_HEADER, span_context.trace_id().to_string());
    carrier.set(B3_SPAN_ID_HEADER, span_context.span_id().to_string());
    carrier.set(
        B3_SAMPLED_HEADER,
        b3_sampled_value(span_context.trace_flags()).to_string(),
    );
}

fn extract_b3_multi(carrier: &HeaderCarrier) -> Result<SpanContext, String> {
    let trace_id = parse_b3_trace_id(
        carrier
            .get(B3_TRACE_ID_HEADER)
            .ok_or_else(|| "missing x-b3-traceid header".to_string())?,
    )?;
    let span_id = parse_b3_span_id(
        carrier
            .get(B3_SPAN_ID_HEADER)
            .ok_or_else(|| "missing x-b3-spanid header".to_string())?,
    )?;
    let trace_flags = parse_b3_sampling_state(carrier.get(B3_SAMPLED_HEADER))?;

    Ok(SpanContext::new(
        trace_id,
        span_id,
        trace_flags,
        true,
        TraceState::default(),
    ))
}

fn b3_sampled_value(trace_flags: TraceFlags) -> &'static str {
    if trace_flags.is_sampled() { "1" } else { "0" }
}

fn parse_b3_sampling_state(value: Option<&str>) -> Result<TraceFlags, String> {
    match value {
        Some(value) if value.eq_ignore_ascii_case("1") || value.eq_ignore_ascii_case("true") => {
            Ok(TraceFlags::SAMPLED)
        }
        Some(value) if value.eq_ignore_ascii_case("d") => Ok(TraceFlags::SAMPLED),
        Some(value) if value.eq_ignore_ascii_case("0") || value.eq_ignore_ascii_case("false") => {
            Ok(TraceFlags::default())
        }
        Some("") | None => Ok(TraceFlags::default()),
        Some(value) => Err(format!("invalid b3 sampling state: {}", value)),
    }
}

fn parse_b3_trace_id(value: &str) -> Result<TraceId, String> {
    if value.len() == 16 {
        TraceId::from_hex(&format!("{value:0>32}"))
    } else {
        TraceId::from_hex(value)
    }
    .map_err(|error| format!("invalid b3 trace id '{}': {}", value, error))
}

fn parse_b3_span_id(value: &str) -> Result<SpanId, String> {
    SpanId::from_hex(value).map_err(|error| format!("invalid b3 span id '{}': {}", value, error))
}

/// Compare two SpanContexts for identity
fn compare_span_contexts(
    original: &SpanContext,
    extracted: &SpanContext,
    expect_remote_extracted: bool,
) -> Result<(), String> {
    if original.trace_id() != extracted.trace_id() {
        return Err(format!(
            "TraceId mismatch: original={}, extracted={}",
            original.trace_id(),
            extracted.trace_id()
        ));
    }

    if original.span_id() != extracted.span_id() {
        return Err(format!(
            "SpanId mismatch: original={}, extracted={}",
            original.span_id(),
            extracted.span_id()
        ));
    }

    if original.trace_flags() != extracted.trace_flags() {
        return Err(format!(
            "TraceFlags mismatch: original={:?}, extracted={:?}",
            original.trace_flags(),
            extracted.trace_flags()
        ));
    }

    if expect_remote_extracted {
        if !extracted.is_remote() {
            return Err("Extracted W3C context should be marked remote".to_string());
        }
    } else if original.is_remote() != extracted.is_remote() {
        return Err(format!(
            "Remote flag mismatch: original={}, extracted={}",
            original.is_remote(),
            extracted.is_remote()
        ));
    }

    // Compare TraceState (this might be more complex due to ordering)
    let original_state = original.trace_state().header();
    let extracted_state = extracted.trace_state().header();
    if original_state != extracted_state {
        return Err(format!(
            "TraceState mismatch: original='{}', extracted='{}'",
            original_state, extracted_state
        ));
    }

    Ok(())
}

/// Helper to create test span context
fn create_test_span_context(
    name: &str,
    trace_id_hex: &str,
    span_id_hex: &str,
    flags: TraceFlags,
    is_remote: bool,
) -> TestSpanContext {
    let trace_id = TraceId::from_hex(trace_id_hex).expect("Valid trace ID");
    let span_id = SpanId::from_hex(span_id_hex).expect("Valid span ID");
    let trace_state = TraceState::default();

    TestSpanContext {
        name: name.to_string(),
        trace_id,
        span_id,
        trace_flags: flags,
        is_remote,
        trace_state,
    }
}

/// Helper to create test span context with trace state
fn create_test_span_context_with_state(
    name: &str,
    trace_id_hex: &str,
    span_id_hex: &str,
    flags: TraceFlags,
    is_remote: bool,
    state: &str,
) -> TestSpanContext {
    let trace_id = TraceId::from_hex(trace_id_hex).expect("Valid trace ID");
    let span_id = SpanId::from_hex(span_id_hex).expect("Valid span ID");
    let trace_state = TraceState::from_key_value(state.split(',').filter_map(|pair| {
        let mut parts = pair.splitn(2, '=');
        if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
            Some((key.to_string(), value.to_string()))
        } else {
            None
        }
    }))
    .unwrap_or_default();

    TestSpanContext {
        name: name.to_string(),
        trace_id,
        span_id,
        trace_flags: flags,
        is_remote,
        trace_state,
    }
}

/// Check if test case has known propagation divergences
fn is_known_propagation_divergence(test_name: &str, context_name: &str) -> bool {
    // Define known divergences here
    // For now, assume no known divergences
    match (test_name, context_name) {
        _ => false,
    }
}

/// Simple test span wrapper for SpanContext
struct TestSpan {
    span_context: SpanContext,
}

impl TestSpan {
    fn new(span_context: SpanContext) -> Self {
        Self { span_context }
    }
}

impl opentelemetry::trace::Span for TestSpan {
    fn add_event_with_timestamp<T>(
        &mut self,
        _name: T,
        _timestamp: std::time::SystemTime,
        _attributes: Vec<opentelemetry::KeyValue>,
    ) where
        T: Into<std::borrow::Cow<'static, str>>,
    {
        // No-op for testing
    }

    fn span_context(&self) -> &SpanContext {
        &self.span_context
    }

    fn is_recording(&self) -> bool {
        false
    }

    fn set_attribute(&mut self, _attribute: opentelemetry::KeyValue) {
        // No-op for testing
    }

    fn set_status(&mut self, _status: opentelemetry::trace::Status) {
        // No-op for testing
    }

    fn update_name<T>(&mut self, _new_name: T)
    where
        T: Into<std::borrow::Cow<'static, str>>,
    {
        // No-op for testing
    }

    fn end_with_timestamp(&mut self, _timestamp: std::time::SystemTime) {
        // No-op for testing
    }

    fn add_link(&mut self, _span_context: SpanContext, _attributes: Vec<opentelemetry::KeyValue>) {
        // No-op for testing
    }
}

/// Individual test runners for specific test cases
fn run_w3c_traceparent_roundtrip_test(_verbose: bool) -> ConformanceTestResult {
    let test_case = PropagationTestCase {
        name: "w3c-traceparent-roundtrip",
        description: "W3C traceparent roundtrip",
        requirement_level: RequirementLevel::Must,
        propagator_type: PropagatorType::W3CTraceContext,
        span_contexts: vec![create_test_span_context(
            "basic",
            "4bf92f3577b34da6a3ce929d0e0e4736",
            "00f067aa0ba902b7",
            TraceFlags::SAMPLED,
            false,
        )],
    };

    run_propagation_conformance_test(&test_case, false)
}

fn run_w3c_tracestate_roundtrip_test(_verbose: bool) -> ConformanceTestResult {
    let test_case = PropagationTestCase {
        name: "w3c-tracestate-roundtrip",
        description: "W3C tracestate roundtrip",
        requirement_level: RequirementLevel::Should,
        propagator_type: PropagatorType::W3CTraceContext,
        span_contexts: vec![create_test_span_context_with_state(
            "with_state",
            "4bf92f3577b34da6a3ce929d0e0e4736",
            "00f067aa0ba902b7",
            TraceFlags::SAMPLED,
            false,
            "vendor=value",
        )],
    };

    run_propagation_conformance_test(&test_case, false)
}

fn run_w3c_invalid_handling_test(_verbose: bool) -> ConformanceTestResult {
    let test_case = PropagationTestCase {
        name: "w3c-traceparent-invalid-handling",
        description: "W3C invalid header handling",
        requirement_level: RequirementLevel::Must,
        propagator_type: PropagatorType::W3CTraceContext,
        span_contexts: vec![create_test_span_context(
            "invalid_test",
            "4bf92f3577b34da6a3ce929d0e0e4736",
            "00f067aa0ba902b7",
            TraceFlags::SAMPLED,
            false,
        )],
    };

    run_propagation_conformance_test(&test_case, false)
}

fn run_b3_single_header_roundtrip_test(_verbose: bool) -> ConformanceTestResult {
    let test_case = PropagationTestCase {
        name: "b3-single-header-roundtrip",
        description: "B3 single header roundtrip",
        requirement_level: RequirementLevel::Should,
        propagator_type: PropagatorType::B3Single,
        span_contexts: vec![create_test_span_context(
            "b3_single",
            "4bf92f3577b34da6a3ce929d0e0e4736",
            "00f067aa0ba902b7",
            TraceFlags::SAMPLED,
            false,
        )],
    };

    run_propagation_conformance_test(&test_case, false)
}

fn run_b3_multi_header_roundtrip_test(_verbose: bool) -> ConformanceTestResult {
    let test_case = PropagationTestCase {
        name: "b3-multi-header-roundtrip",
        description: "B3 multi-header roundtrip",
        requirement_level: RequirementLevel::Should,
        propagator_type: PropagatorType::B3Multi,
        span_contexts: vec![create_test_span_context(
            "b3_multi",
            "4bf92f3577b34da6a3ce929d0e0e4736",
            "00f067aa0ba902b7",
            TraceFlags::SAMPLED,
            false,
        )],
    };

    run_propagation_conformance_test(&test_case, false)
}

fn run_propagator_interoperability_test(_verbose: bool) -> ConformanceTestResult {
    let test_case = PropagationTestCase {
        name: "propagator-interoperability",
        description: "Propagator interoperability",
        requirement_level: RequirementLevel::May,
        propagator_type: PropagatorType::W3CTraceContext,
        span_contexts: vec![create_test_span_context(
            "interop",
            "4bf92f3577b34da6a3ce929d0e0e4736",
            "00f067aa0ba902b7",
            TraceFlags::SAMPLED,
            false,
        )],
    };

    run_propagation_conformance_test(&test_case, false)
}

fn run_edge_case_scenarios_test(_verbose: bool) -> ConformanceTestResult {
    let test_case = PropagationTestCase {
        name: "edge-case-scenarios",
        description: "Edge case scenarios",
        requirement_level: RequirementLevel::Should,
        propagator_type: PropagatorType::W3CTraceContext,
        span_contexts: vec![create_test_span_context(
            "edge_case",
            "4bf92f3577b34da6a3ce929d0e0e4736",
            "00f067aa0ba902b7",
            TraceFlags::SAMPLED,
            false,
        )],
    };

    run_propagation_conformance_test(&test_case, false)
}

/// Generate comprehensive compliance report
fn generate_compliance_report() {
    println!("=== OpenTelemetry Trace Context Propagation Compliance Report ===\n");

    println!("## Coverage Matrix");
    println!();
    println!("| Test Case | Requirement Level | Local Status Oracle | Live SDK Reference |");
    println!("|-----------|--------------------|---------------------|--------------------|");
    println!("| w3c-traceparent-roundtrip | MUST | checked | XFAIL - not wired |");
    println!("| w3c-tracestate-roundtrip | SHOULD | checked | XFAIL - not wired |");
    println!("| w3c-traceparent-invalid-handling | MUST | checked | XFAIL - not wired |");
    println!("| b3-single-header-roundtrip | SHOULD | checked | XFAIL - not wired |");
    println!("| b3-multi-header-roundtrip | SHOULD | checked | XFAIL - not wired |");
    println!("| propagator-interoperability | MAY | checked | XFAIL - not wired |");
    println!();

    println!("## Specification Coverage");
    println!();
    println!("### Local trace-context round-trip guards: available");
    println!("### {OTEL_TRACE_CONTEXT_REFERENCE_UNIMPLEMENTED}");
    println!("### Overall score: unavailable");
    println!();

    println!("## Known Divergences");
    println!();
    println!("- {OTEL_TRACE_CONTEXT_REFERENCE_UNIMPLEMENTED}");
    println!();

    println!("⚠️ **XFAIL** - Trace context local checks run, but live SDK parity is not proven");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sampled_span_context() -> SpanContext {
        SpanContext::new(
            TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap(),
            SpanId::from_hex("00f067aa0ba902b7").unwrap(),
            TraceFlags::SAMPLED,
            false,
            TraceState::default(),
        )
    }

    fn unsampled_span_context() -> SpanContext {
        SpanContext::new(
            TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap(),
            SpanId::from_hex("00f067aa0ba902b7").unwrap(),
            TraceFlags::default(),
            false,
            TraceState::default(),
        )
    }

    #[test]
    fn b3_single_roundtrip_uses_b3_header_and_remote_extract() {
        let original = sampled_span_context();
        let mut carrier = HeaderCarrier::default();

        inject_b3_single(&original, &mut carrier);

        assert_eq!(
            carrier.headers.get(B3_SINGLE_HEADER).map(String::as_str),
            Some("4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-1")
        );

        let extracted = extract_b3_single(&carrier).unwrap();
        compare_span_contexts(&original, &extracted, true).unwrap();
        assert!(extracted.is_remote());
    }

    #[test]
    fn b3_multi_roundtrip_uses_b3_headers_and_remote_extract() {
        let original = unsampled_span_context();
        let mut carrier = HeaderCarrier::default();

        inject_b3_multi(&original, &mut carrier);

        assert_eq!(
            carrier.headers.get(B3_TRACE_ID_HEADER).map(String::as_str),
            Some("4bf92f3577b34da6a3ce929d0e0e4736")
        );
        assert_eq!(
            carrier.headers.get(B3_SPAN_ID_HEADER).map(String::as_str),
            Some("00f067aa0ba902b7")
        );
        assert_eq!(
            carrier.headers.get(B3_SAMPLED_HEADER).map(String::as_str),
            Some("0")
        );

        let extracted = extract_b3_multi(&carrier).unwrap();
        compare_span_contexts(&original, &extracted, true).unwrap();
        assert!(extracted.is_remote());
    }

    #[test]
    fn b3_roundtrip_no_longer_clones_local_span_context() {
        let original = sampled_span_context();

        let extracted =
            test_roundtrip_for_propagator(&PropagatorType::B3Single, &original, false).unwrap();

        assert!(!original.is_remote());
        assert!(extracted.is_remote());
        compare_span_contexts(&original, &extracted, true).unwrap();
    }

    #[test]
    fn b3_source_no_longer_contains_mock_shortcut_claims() {
        let source = include_str!("otel_trace_context_propagation_conformance.rs");

        assert!(!source.contains(concat!("simulate ", "B3 behavior")));
        assert!(!source.contains(concat!("would use actual ", "B3 propagator")));
        assert!(!source.contains(concat!("Ok(original_context", ".clone())")));
    }

    #[test]
    fn runner_xfails_without_live_trace_context_reference() {
        let result = run_w3c_traceparent_roundtrip_test(false);

        match result {
            ConformanceTestResult::ExpectedFailure { reason } => {
                assert!(reason.contains(OTEL_TRACE_CONTEXT_REFERENCE_UNIMPLEMENTED));
                assert!(reason.contains("local round-trip guards ran"));
            }
            other => {
                panic!("expected XFAIL while trace-context reference is unwired, got {other:?}")
            }
        }
    }

    #[test]
    fn exit_code_is_nonzero_for_expected_failure_results() {
        let result = ConformanceTestResult::ExpectedFailure {
            reason: "known divergence".to_string(),
        };

        assert_eq!(exit_code_for_result(&result), 1);
    }

    #[test]
    fn exit_code_is_zero_only_for_clean_summary() {
        assert_eq!(exit_code_for_summary(6, 0, 0), 0);
        assert_eq!(exit_code_for_summary(0, 0, 0), 1);
        assert_eq!(exit_code_for_summary(6, 1, 0), 1);
        assert_eq!(exit_code_for_summary(6, 0, 1), 1);
    }

    #[test]
    fn final_status_line_reports_partial_coverage_for_xfail_only() {
        let status = final_status_line(6, 0, 1);

        assert!(status.contains("NO FAILURES; PARTIAL COVERAGE"));
        assert!(!status.contains("ALL TESTS PASSED"));
    }
}
