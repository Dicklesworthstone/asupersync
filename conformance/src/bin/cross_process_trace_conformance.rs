use asupersync::trace::distributed::context::{SymbolTraceContext, TraceFlags as AsuperTraceFlags, RegionTag};
use asupersync::trace::distributed::id::{DistTraceId, SymbolSpanId};
use asupersync::util::DetRng;
use clap::{Arg, Command};
use opentelemetry::trace::{SpanContext, SpanId, TraceFlags as OtelTraceFlags, TraceId, TraceState};
use opentelemetry::{Context, KeyValue, propagation::TextMapPropagator, Baggage};
use opentelemetry_sdk::trace::{TracerProvider, Config, Sampler};
use opentelemetry_sdk::{Resource, runtime::Tokio};
use std::collections::HashMap;

/// Cross-process trace context propagation conformance testing.
/// Tests W3C trace context and B3 propagation formats to ensure identical
/// SpanContext + Baggage roundtrip across process boundaries.
fn main() {
    env_logger::init();

    let matches = Command::new("cross_process_trace_conformance")
        .about("Cross-process trace context propagation conformance testing")
        .arg(
            Arg::new("test")
                .long("test")
                .value_name("NAME")
                .help("Run specific test case (w3c-roundtrip, b3-roundtrip, baggage-roundtrip, mixed-headers)")
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
        ("w3c-roundtrip", test_w3c_roundtrip),
        ("b3-roundtrip", test_b3_roundtrip),
        ("baggage-roundtrip", test_baggage_roundtrip),
        ("mixed-headers", test_mixed_headers),
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
// Header Format Converters
// =============================================================================

/// W3C Trace Context format: traceparent + tracestate
#[derive(Debug, Clone)]
struct W3cHeaders {
    traceparent: String,
    tracestate: Option<String>,
}

/// B3 format: X-B3-TraceId, X-B3-SpanId, X-B3-Sampled, X-B3-Flags
#[derive(Debug, Clone)]
struct B3Headers {
    trace_id: String,
    span_id: String,
    sampled: Option<String>,
    flags: Option<String>,
}

/// Converts SymbolTraceContext to W3C headers
fn to_w3c_headers(ctx: &SymbolTraceContext) -> W3cHeaders {
    let traceparent = format!(
        "00-{:016x}{:016x}-{:016x}-{:02x}",
        ctx.trace_id().high(),
        ctx.trace_id().low(),
        ctx.span_id().as_u64(),
        ctx.flags().as_byte()
    );

    let tracestate = if ctx.baggage().is_empty() {
        None
    } else {
        let entries: Vec<String> = ctx.baggage()
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        Some(entries.join(","))
    };

    W3cHeaders { traceparent, tracestate }
}

/// Converts SymbolTraceContext to B3 headers
fn to_b3_headers(ctx: &SymbolTraceContext) -> B3Headers {
    let trace_id = format!("{:016x}{:016x}", ctx.trace_id().high(), ctx.trace_id().low());
    let span_id = format!("{:016x}", ctx.span_id().as_u64());

    let sampled = if ctx.flags().is_sampled() {
        Some("1".to_string())
    } else {
        Some("0".to_string())
    };

    B3Headers {
        trace_id,
        span_id,
        sampled,
        flags: None,
    }
}

/// Parses W3C traceparent header back to components
fn parse_w3c_traceparent(traceparent: &str) -> Result<(DistTraceId, SymbolSpanId, AsuperTraceFlags), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = traceparent.split('-').collect();
    if parts.len() != 4 || parts[0] != "00" {
        return Err("Invalid traceparent format".into());
    }

    let trace_id_str = parts[1];
    let span_id_str = parts[2];
    let flags_str = parts[3];

    if trace_id_str.len() != 32 {
        return Err("Invalid trace ID length".into());
    }

    let trace_high = u64::from_str_radix(&trace_id_str[0..16], 16)?;
    let trace_low = u64::from_str_radix(&trace_id_str[16..32], 16)?;
    let trace_id = DistTraceId::new(trace_high, trace_low);

    let span_id_val = u64::from_str_radix(span_id_str, 16)?;
    let span_id = SymbolSpanId::new(span_id_val);

    let flags_val = u8::from_str_radix(flags_str, 16)?;
    let flags = AsuperTraceFlags::from_byte(flags_val);

    Ok((trace_id, span_id, flags))
}

/// Creates OpenTelemetry SpanContext for comparison
fn create_otel_span_context(trace_id: DistTraceId, span_id: SymbolSpanId, flags: AsuperTraceFlags, baggage: &[(String, String)]) -> Result<SpanContext, Box<dyn std::error::Error>> {
    let trace_id_bytes = [
        &trace_id.high().to_be_bytes(),
        &trace_id.low().to_be_bytes()
    ].concat();
    let otel_trace_id = TraceId::from_bytes(trace_id_bytes.try_into().unwrap());

    let span_id_bytes = span_id.as_u64().to_be_bytes();
    let otel_span_id = SpanId::from_bytes(span_id_bytes);

    let otel_flags = if flags.is_sampled() {
        OtelTraceFlags::SAMPLED
    } else {
        OtelTraceFlags::default()
    };

    let mut trace_state = TraceState::default();
    for (key, value) in baggage {
        trace_state = trace_state.with_key_value(key, value)?;
    }

    Ok(SpanContext::new(otel_trace_id, otel_span_id, otel_flags, false, trace_state))
}

// =============================================================================
// Test Cases
// =============================================================================

/// Test W3C trace context roundtrip across process boundary
fn test_w3c_roundtrip(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing W3C trace context roundtrip");
    }

    // Create original context
    let mut rng = DetRng::new(500);
    let original_ctx = SymbolTraceContext::new_for_encoding(
        DistTraceId::new(0x1234567890abcdef, 0xfedcba0987654321),
        SymbolSpanId::new(0x1111222233334444),
        RegionTag::new("service-a"),
        &mut rng,
    )
    .with_baggage("service", "user-api")
    .with_baggage("version", "1.0.0")
    .with_baggage("region", "us-west-2");

    // Convert to W3C headers (simulate sending across process boundary)
    let w3c_headers = to_w3c_headers(&original_ctx);

    if verbose {
        println!("  Original trace: {:016x}{:016x}",
            original_ctx.trace_id().high(),
            original_ctx.trace_id().low());
        println!("  W3C traceparent: {}", w3c_headers.traceparent);
        if let Some(ref tracestate) = w3c_headers.tracestate {
            println!("  W3C tracestate: {}", tracestate);
        }
    }

    // Parse headers back (simulate receiving in another process)
    let (parsed_trace_id, parsed_span_id, parsed_flags) = parse_w3c_traceparent(&w3c_headers.traceparent)?;

    // Verify roundtrip accuracy
    if parsed_trace_id != original_ctx.trace_id() {
        return Err(format!(
            "Trace ID roundtrip failed: {:016x}{:016x} != {:016x}{:016x}",
            parsed_trace_id.high(), parsed_trace_id.low(),
            original_ctx.trace_id().high(), original_ctx.trace_id().low()
        ).into());
    }

    if parsed_span_id != original_ctx.span_id() {
        return Err(format!(
            "Span ID roundtrip failed: {:016x} != {:016x}",
            parsed_span_id.as_u64(),
            original_ctx.span_id().as_u64()
        ).into());
    }

    if parsed_flags.as_byte() != original_ctx.flags().as_byte() {
        return Err(format!(
            "Flags roundtrip failed: {:02x} != {:02x}",
            parsed_flags.as_byte(),
            original_ctx.flags().as_byte()
        ).into());
    }

    // Test against OpenTelemetry reference
    let otel_span_context = create_otel_span_context(
        original_ctx.trace_id(),
        original_ctx.span_id(),
        original_ctx.flags(),
        original_ctx.baggage()
    )?;

    let propagator = opentelemetry::propagation::TraceContextPropagator::new();
    let mut ref_headers = HashMap::new();
    let ctx = Context::default().with_span(MockSpan::new(otel_span_context));
    propagator.inject_context(&ctx, &mut HeaderInjector(&mut ref_headers));

    let ref_traceparent = ref_headers.get("traceparent")
        .ok_or("Reference traceparent missing")?;

    if &w3c_headers.traceparent != ref_traceparent {
        return Err(format!(
            "W3C conformance mismatch:\n  Our: {}\n  Ref: {}",
            w3c_headers.traceparent, ref_traceparent
        ).into());
    }

    if verbose {
        println!("  Roundtrip verification: ✓");
        println!("  OpenTelemetry conformance: ✓");
    }

    Ok(())
}

/// Test B3 trace context roundtrip
fn test_b3_roundtrip(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing B3 trace context roundtrip");
    }

    let mut rng = DetRng::new(600);
    let original_ctx = SymbolTraceContext::new_for_encoding(
        DistTraceId::new(0xabcdef1234567890, 0x0123456789abcdef),
        SymbolSpanId::new(0x5555666677778888),
        RegionTag::new("service-b"),
        &mut rng,
    );

    let b3_headers = to_b3_headers(&original_ctx);

    if verbose {
        println!("  B3 Trace-Id: {}", b3_headers.trace_id);
        println!("  B3 Span-Id: {}", b3_headers.span_id);
        if let Some(ref sampled) = b3_headers.sampled {
            println!("  B3 Sampled: {}", sampled);
        }
    }

    // Parse back trace ID and span ID
    let parsed_trace_high = u64::from_str_radix(&b3_headers.trace_id[0..16], 16)?;
    let parsed_trace_low = u64::from_str_radix(&b3_headers.trace_id[16..32], 16)?;
    let parsed_trace_id = DistTraceId::new(parsed_trace_high, parsed_trace_low);

    let parsed_span_id = SymbolSpanId::new(u64::from_str_radix(&b3_headers.span_id, 16)?);

    // Verify roundtrip
    if parsed_trace_id != original_ctx.trace_id() {
        return Err("B3 trace ID roundtrip failed".into());
    }

    if parsed_span_id != original_ctx.span_id() {
        return Err("B3 span ID roundtrip failed".into());
    }

    // Check sampling flag
    let expected_sampled = if original_ctx.flags().is_sampled() { "1" } else { "0" };
    if b3_headers.sampled.as_deref() != Some(expected_sampled) {
        return Err("B3 sampling flag mismatch".into());
    }

    if verbose {
        println!("  B3 roundtrip verification: ✓");
    }

    Ok(())
}

/// Test baggage propagation across process boundaries
fn test_baggage_roundtrip(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing baggage roundtrip");
    }

    let mut rng = DetRng::new(700);
    let original_ctx = SymbolTraceContext::new_for_encoding(
        DistTraceId::new(0x1111111111111111, 0x2222222222222222),
        SymbolSpanId::new(0x3333333333333333),
        RegionTag::new("baggage-test"),
        &mut rng,
    )
    .with_baggage("user_id", "user-12345")
    .with_baggage("session_id", "sess-abcdef")
    .with_baggage("request_id", "req-xyz789")
    .with_baggage("correlation", "corr-123");

    // Convert to W3C format (includes baggage as tracestate)
    let w3c_headers = to_w3c_headers(&original_ctx);

    let tracestate = w3c_headers.tracestate
        .ok_or("Tracestate should be present with baggage")?;

    if verbose {
        println!("  Original baggage count: {}", original_ctx.baggage().len());
        println!("  Tracestate: {}", tracestate);
    }

    // Parse tracestate back to baggage
    let parsed_baggage: Vec<(String, String)> = tracestate
        .split(',')
        .map(|entry| {
            let parts: Vec<&str> = entry.split('=').collect();
            (parts[0].to_string(), parts[1].to_string())
        })
        .collect();

    // Verify all baggage items preserved
    for (key, value) in original_ctx.baggage() {
        let found = parsed_baggage.iter()
            .any(|(k, v)| k == key && v == value);

        if !found {
            return Err(format!("Baggage item lost: {}={}", key, value).into());
        }
    }

    if verbose {
        println!("  Parsed baggage count: {}", parsed_baggage.len());
        println!("  Baggage roundtrip verification: ✓");
    }

    Ok(())
}

/// Test mixed header formats in same context
fn test_mixed_headers(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing mixed W3C and B3 headers");
    }

    let mut rng = DetRng::new(800);
    let ctx = SymbolTraceContext::new_for_encoding(
        DistTraceId::new(0xfafafafafafafafa, 0xbbbbbbbbbbbbbbb),
        SymbolSpanId::new(0xcccccccccccccccc),
        RegionTag::new("mixed-test"),
        &mut rng,
    )
    .with_baggage("format", "mixed")
    .with_baggage("test", "conformance");

    // Generate both header formats
    let w3c_headers = to_w3c_headers(&ctx);
    let b3_headers = to_b3_headers(&ctx);

    // Both should represent the same trace context
    let (w3c_trace_id, _, _) = parse_w3c_traceparent(&w3c_headers.traceparent)?;

    let b3_trace_high = u64::from_str_radix(&b3_headers.trace_id[0..16], 16)?;
    let b3_trace_low = u64::from_str_radix(&b3_headers.trace_id[16..32], 16)?;
    let b3_trace_id = DistTraceId::new(b3_trace_high, b3_trace_low);

    if w3c_trace_id != b3_trace_id {
        return Err("Mixed headers have different trace IDs".into());
    }

    if verbose {
        println!("  W3C format: {}", w3c_headers.traceparent);
        println!("  B3 format: X-B3-TraceId={}, X-B3-SpanId={}",
            b3_headers.trace_id, b3_headers.span_id);
        println!("  Cross-format consistency: ✓");
    }

    Ok(())
}

/// Test comprehensive cross-process scenario
fn test_comprehensive_scenario(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing comprehensive cross-process scenario");
    }

    // Simulate: Service A -> Service B -> Service C
    let mut rng = DetRng::new(900);

    // Service A initiates request
    let service_a_ctx = SymbolTraceContext::new_for_encoding(
        DistTraceId::new(0x1000000000000001, 0x2000000000000002),
        SymbolSpanId::new(0x3000000000000003),
        RegionTag::new("service-a"),
        &mut rng,
    )
    .with_baggage("request_id", "req-root-123")
    .with_baggage("user_id", "user-456");

    // Service A -> Service B (W3C headers)
    let a_to_b_headers = to_w3c_headers(&service_a_ctx);
    let (trace_id, _, flags) = parse_w3c_traceparent(&a_to_b_headers.traceparent)?;

    // Service B creates child span
    let service_b_ctx = SymbolTraceContext::new_for_encoding(
        trace_id,
        service_a_ctx.span_id(), // Parent span
        RegionTag::new("service-b"),
        &mut rng,
    )
    .with_baggage("request_id", "req-root-123") // Inherited
    .with_baggage("user_id", "user-456")       // Inherited
    .with_baggage("service_b_op", "process");  // Added

    // Service B -> Service C (B3 headers)
    let b_to_c_headers = to_b3_headers(&service_b_ctx);
    let b3_trace_high = u64::from_str_radix(&b_to_c_headers.trace_id[0..16], 16)?;
    let b3_trace_low = u64::from_str_radix(&b_to_c_headers.trace_id[16..32], 16)?;
    let b3_trace_id = DistTraceId::new(b3_trace_high, b3_trace_low);

    // Verify trace ID propagated correctly across all services
    if service_a_ctx.trace_id() != service_b_ctx.trace_id() ||
       service_b_ctx.trace_id() != b3_trace_id {
        return Err("Trace ID not preserved across service calls".into());
    }

    // Verify baggage propagation and evolution
    if service_a_ctx.get_baggage("request_id") != service_b_ctx.get_baggage("request_id") {
        return Err("Request ID not preserved in baggage".into());
    }

    if service_b_ctx.get_baggage("service_b_op") != Some("process") {
        return Err("Service B did not add its baggage".into());
    }

    if verbose {
        println!("  Service A trace: {:016x}{:016x}",
            service_a_ctx.trace_id().high(),
            service_a_ctx.trace_id().low());
        println!("  Service B trace: {:016x}{:016x}",
            service_b_ctx.trace_id().high(),
            service_b_ctx.trace_id().low());
        println!("  Service C trace: {:016x}{:016x}",
            b3_trace_id.high(),
            b3_trace_id.low());
        println!("  A->B headers: W3C");
        println!("  B->C headers: B3");
        println!("  Trace continuity: ✓");
        println!("  Baggage evolution: ✓");
    }

    Ok(())
}

// =============================================================================
// Mock Implementations
// =============================================================================

struct MockSpan {
    context: SpanContext,
}

impl MockSpan {
    fn new(context: SpanContext) -> Self {
        Self { context }
    }
}

impl opentelemetry::trace::Span for MockSpan {
    fn add_event_with_timestamp<T>(&mut self, _name: T, _timestamp: std::time::SystemTime)
    where
        T: Into<std::borrow::Cow<'static, str>>,
    {
        // No-op
    }

    fn span_context(&self) -> &SpanContext {
        &self.context
    }

    fn is_recording(&self) -> bool {
        false
    }

    fn set_attribute(&mut self, _attribute: KeyValue) {
        // No-op
    }

    fn set_status(&mut self, _status: opentelemetry::trace::Status) {
        // No-op
    }

    fn update_name<T>(&mut self, _new_name: T)
    where
        T: Into<std::borrow::Cow<'static, str>>,
    {
        // No-op
    }

    fn end_with_timestamp(&mut self, _timestamp: std::time::SystemTime) {
        // No-op
    }
}

struct HeaderInjector<'a>(&'a mut HashMap<String, String>);

impl<'a> opentelemetry::propagation::Injector for HeaderInjector<'a> {
    fn set(&mut self, key: &str, value: String) {
        self.0.insert(key.to_string(), value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_w3c_header_format() {
        let mut rng = DetRng::new(42);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new(0x1234567890abcdef, 0xfedcba0987654321),
            SymbolSpanId::new(0x1111222233334444),
            RegionTag::new("test"),
            &mut rng,
        );

        let headers = to_w3c_headers(&ctx);
        let expected = format!(
            "00-1234567890abcdeffedcba0987654321-{:016x}-01",
            ctx.span_id().as_u64()
        );

        assert!(headers.traceparent.starts_with("00-1234567890abcdeffedcba0987654321"));
        assert!(headers.traceparent.ends_with("-01")); // SAMPLED flag
    }

    #[test]
    fn test_traceparent_parsing() {
        let traceparent = "00-1234567890abcdeffedcba0987654321-5555666677778888-01";
        let (trace_id, span_id, flags) = parse_w3c_traceparent(traceparent).unwrap();

        assert_eq!(trace_id.high(), 0x1234567890abcdef);
        assert_eq!(trace_id.low(), 0xfedcba0987654321);
        assert_eq!(span_id.as_u64(), 0x5555666677778888);
        assert!(flags.is_sampled());
    }
}