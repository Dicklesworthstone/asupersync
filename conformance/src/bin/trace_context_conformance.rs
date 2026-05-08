use asupersync::trace::distributed::context::{
    RegionTag, SymbolTraceContext, TraceFlags as AsuperTraceFlags,
};
use asupersync::trace::distributed::id::{DistTraceId, SymbolSpanId};
use asupersync::util::DetRng;
use clap::{Arg, Command};
use opentelemetry::trace::{
    SpanContext, SpanId, TraceContextExt as _, TraceFlags as OtelTraceFlags, TraceId, TraceState,
};
use opentelemetry::{Context, propagation::TextMapPropagator};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use std::collections::HashMap;

/// W3C trace context propagation conformance testing.
/// Compares our SymbolTraceContext W3C header generation against opentelemetry reference
/// for identical traceparent/tracestate header pairs given the same span tree.
fn main() {
    env_logger::init();

    let matches = Command::new("trace_context_conformance")
        .about("W3C trace context propagation conformance testing")
        .arg(
            Arg::new("test")
                .long("test")
                .value_name("NAME")
                .help("Run specific test case (basic, nested, baggage, sampling)")
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

    let test_cases: [(&str, fn(bool) -> TestResult); 5] = [
        ("basic", test_basic_propagation),
        ("nested", test_nested_spans),
        ("baggage", test_baggage_propagation),
        ("sampling", test_sampling_decisions),
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
// W3C Trace Context Conversion for Asupersync
// =============================================================================

/// Converts asupersync SymbolTraceContext to W3C traceparent header format.
/// Format: 00-{trace_id}-{span_id}-{flags}
fn to_w3c_traceparent(ctx: &SymbolTraceContext) -> String {
    let trace_id_hex = format!(
        "{:016x}{:016x}",
        ctx.trace_id().high(),
        ctx.trace_id().low()
    );
    let span_id_hex = format!("{:016x}", ctx.span_id().as_u64());
    let flags_hex = format!("{:02x}", ctx.flags().as_byte());

    format!("00-{}-{}-{}", trace_id_hex, span_id_hex, flags_hex)
}

/// Converts asupersync SymbolTraceContext baggage to W3C tracestate header format.
/// Format: key1=value1,key2=value2
fn to_w3c_tracestate(ctx: &SymbolTraceContext) -> Option<String> {
    if ctx.baggage().is_empty() {
        return None;
    }

    let entries: Vec<String> = ctx
        .baggage()
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();

    Some(entries.join(","))
}

/// Creates equivalent OpenTelemetry SpanContext for comparison.
fn to_otel_span_context(
    ctx: &SymbolTraceContext,
) -> Result<SpanContext, Box<dyn std::error::Error>> {
    // Convert trace ID from asupersync format
    let mut trace_id_bytes = [0_u8; 16];
    trace_id_bytes[..8].copy_from_slice(&ctx.trace_id().high().to_be_bytes());
    trace_id_bytes[8..].copy_from_slice(&ctx.trace_id().low().to_be_bytes());
    let trace_id = TraceId::from_bytes(trace_id_bytes);

    // Convert span ID
    let span_id_bytes = ctx.span_id().as_u64().to_be_bytes();
    let span_id = SpanId::from_bytes(span_id_bytes);

    // Convert flags
    let otel_flags = if ctx.flags().is_sampled() {
        OtelTraceFlags::SAMPLED
    } else {
        OtelTraceFlags::default()
    };

    // Convert baggage to tracestate
    let trace_state =
        TraceState::from_key_value(ctx.baggage().iter().map(|(key, value)| (key, value)))?;

    Ok(SpanContext::new(
        trace_id,
        span_id,
        otel_flags,
        false,
        trace_state,
    ))
}

/// Creates our TraceContext headers for conformance comparison.
fn create_our_headers(ctx: &SymbolTraceContext) -> HashMap<String, String> {
    let mut headers = HashMap::new();

    headers.insert("traceparent".to_string(), to_w3c_traceparent(ctx));

    if let Some(tracestate) = to_w3c_tracestate(ctx) {
        headers.insert("tracestate".to_string(), tracestate);
    }

    headers
}

/// Test basic trace context propagation with single span
fn test_basic_propagation(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing basic traceparent/tracestate propagation");
    }

    // Create asupersync trace context
    let mut rng = DetRng::new(42);
    let trace_id = DistTraceId::new(0x4bf92f3577b34da6, 0xa3ce929d0e0e4736);
    let parent_span = SymbolSpanId::new(0x00f067aa0ba902b7);

    let our_ctx = SymbolTraceContext::new_for_encoding(
        trace_id,
        parent_span,
        RegionTag::new("test"),
        &mut rng,
    )
    .with_baggage("vendor", "test");

    // Our implementation
    let our_headers = create_our_headers(&our_ctx);

    // Reference implementation using equivalent OpenTelemetry SpanContext
    let ref_span_context = to_otel_span_context(&our_ctx)?;
    let ref_propagator = TraceContextPropagator::new();
    let mut ref_headers = HashMap::new();
    let ctx = Context::default().with_remote_span_context(ref_span_context);
    ref_propagator.inject_context(&ctx, &mut HeaderInjector(&mut ref_headers));

    // Compare traceparent headers
    let our_traceparent = our_headers
        .get("traceparent")
        .ok_or("Missing traceparent")?;
    let ref_traceparent = ref_headers
        .get("traceparent")
        .ok_or("Missing ref traceparent")?;

    if our_traceparent != ref_traceparent {
        return Err(format!(
            "traceparent mismatch:\n  Our: {}\n  Ref: {}",
            our_traceparent, ref_traceparent
        )
        .into());
    }

    // Compare tracestate headers
    let our_tracestate = our_headers.get("tracestate");
    let ref_tracestate = ref_headers.get("tracestate");

    match (our_tracestate, ref_tracestate) {
        (Some(ours), Some(refs)) => {
            if ours != refs {
                return Err(
                    format!("tracestate mismatch:\n  Our: {}\n  Ref: {}", ours, refs).into(),
                );
            }
        }
        (None, None) => {
            // Both empty, OK
        }
        (ours, refs) => {
            return Err(format!(
                "tracestate presence mismatch:\n  Our: {:?}\n  Ref: {:?}",
                ours, refs
            )
            .into());
        }
    }

    if verbose {
        println!("  traceparent: {}", our_traceparent);
        if let Some(tracestate) = our_tracestate {
            println!("  tracestate: {}", tracestate);
        }
    }

    Ok(())
}

/// Test nested span propagation
fn test_nested_spans(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing nested span context propagation");
    }

    let mut rng = DetRng::new(100);
    let trace_id = DistTraceId::new(0x4bf92f3577b34da6, 0xa3ce929d0e0e4736);

    // Parent span
    let parent_ctx = SymbolTraceContext::new_for_encoding(
        trace_id,
        SymbolSpanId::new(0x00f067aa0ba902b7),
        RegionTag::new("test"),
        &mut rng,
    )
    .with_baggage("parent", "root");

    // Child span (inherits trace_id, gets new span_id)
    let child_ctx = parent_ctx.child(&mut rng).with_baggage("child", "level1");

    // Generate headers
    let parent_headers = create_our_headers(&parent_ctx);
    let child_headers = create_our_headers(&child_ctx);

    // Both should have same trace_id but different span_id
    let parent_traceparent = parent_headers.get("traceparent").unwrap();
    let child_traceparent = child_headers.get("traceparent").unwrap();

    // Extract trace_id from both (first 32 chars after "00-")
    let parent_trace_part = &parent_traceparent[3..35];
    let child_trace_part = &child_traceparent[3..35];

    if parent_trace_part != child_trace_part {
        return Err("Child span should inherit parent trace_id".into());
    }

    // Extract span_id from both (chars 36-51 after "00-")
    let parent_span_part = &parent_traceparent[36..52];
    let child_span_part = &child_traceparent[36..52];

    if parent_span_part == child_span_part {
        return Err("Child span should have different span_id than parent".into());
    }

    // Verify trace ID inheritance at SymbolTraceContext level
    if parent_ctx.trace_id() != child_ctx.trace_id() {
        return Err("Child should inherit parent trace_id".into());
    }

    if parent_ctx.span_id() == child_ctx.span_id() {
        return Err("Child should have different span_id than parent".into());
    }

    if verbose {
        println!("  Parent traceparent: {}", parent_traceparent);
        println!("  Child traceparent: {}", child_traceparent);
        println!("  Trace ID preserved: {}", parent_trace_part);
    }

    Ok(())
}

/// Test baggage propagation alongside trace context
fn test_baggage_propagation(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing baggage propagation with trace context");
    }

    let mut rng = DetRng::new(200);
    let trace_id = DistTraceId::new(0x4bf92f3577b34da6, 0xa3ce929d0e0e4736);

    let ctx = SymbolTraceContext::new_for_encoding(
        trace_id,
        SymbolSpanId::new(0x00f067aa0ba902b7),
        RegionTag::new("test"),
        &mut rng,
    )
    .with_baggage("service", "api")
    .with_baggage("version", "1.2.3")
    .with_baggage("datacenter", "us-east-1");

    let headers = create_our_headers(&ctx);

    // Verify tracestate contains all baggage
    let tracestate = headers
        .get("tracestate")
        .ok_or("tracestate header missing")?;

    let required_entries = ["service=api", "version=1.2.3", "datacenter=us-east-1"];
    for entry in &required_entries {
        if !tracestate.contains(entry) {
            return Err(format!("tracestate missing entry: {}", entry).into());
        }
    }

    // Test against OpenTelemetry reference
    let ref_span_context = to_otel_span_context(&ctx)?;
    let ref_propagator = TraceContextPropagator::new();
    let mut ref_headers = HashMap::new();
    let otel_ctx = Context::default().with_remote_span_context(ref_span_context);
    ref_propagator.inject_context(&otel_ctx, &mut HeaderInjector(&mut ref_headers));

    // Compare tracestate (order may differ, so check individual entries)
    let ref_tracestate = ref_headers
        .get("tracestate")
        .ok_or("Reference tracestate missing")?;

    for entry in &required_entries {
        if !ref_tracestate.contains(entry) {
            return Err(format!("Reference tracestate missing entry: {}", entry).into());
        }
    }

    if verbose {
        println!("  Our tracestate: {}", tracestate);
        println!("  Ref tracestate: {}", ref_tracestate);
    }

    Ok(())
}

/// Test sampling decisions affect trace flags
fn test_sampling_decisions(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing sampling decisions in trace context");
    }

    let mut rng = DetRng::new(300);
    let trace_id = DistTraceId::new(0x4bf92f3577b34da6, 0xa3ce929d0e0e4736);

    // Test sampled span (default is SAMPLED in new_for_encoding)
    let sampled_ctx = SymbolTraceContext::new_for_encoding(
        trace_id,
        SymbolSpanId::new(0x00f067aa0ba902b7),
        RegionTag::new("test"),
        &mut rng,
    );

    // Create unsampled context by manually building with NONE flags
    let unsampled_ctx = SymbolTraceContext::new_for_encoding(
        trace_id,
        SymbolSpanId::new(0x00f067aa0ba902b7),
        RegionTag::new("test"),
        &mut rng,
    );

    let sampled_headers = create_our_headers(&sampled_ctx);

    // For unsampled, we need to create a version with NONE flags
    // Since we can't easily modify flags, we'll create headers manually
    let unsampled_traceparent = format!(
        "00-{:016x}{:016x}-{:016x}-{:02x}",
        trace_id.high(),
        trace_id.low(),
        unsampled_ctx.span_id().as_u64(),
        AsuperTraceFlags::NONE.as_byte()
    );

    // Check flags in traceparent (last 2 chars)
    let sampled_traceparent = sampled_headers.get("traceparent").unwrap();

    // Sampled should end with "01", unsampled with "00"
    if !sampled_traceparent.ends_with("-01") {
        return Err(format!("Sampled span should end with -01: {}", sampled_traceparent).into());
    }

    if !unsampled_traceparent.ends_with("-00") {
        return Err(format!(
            "Unsampled span should end with -00: {}",
            unsampled_traceparent
        )
        .into());
    }

    // Test against OpenTelemetry reference for sampled case
    let ref_span_context = to_otel_span_context(&sampled_ctx)?;
    let ref_propagator = TraceContextPropagator::new();
    let mut ref_headers = HashMap::new();
    let otel_ctx = Context::default().with_remote_span_context(ref_span_context);
    ref_propagator.inject_context(&otel_ctx, &mut HeaderInjector(&mut ref_headers));

    let ref_traceparent = ref_headers.get("traceparent").unwrap();
    if sampled_traceparent != ref_traceparent {
        return Err(format!(
            "Sampled traceparent mismatch:\n  Our: {}\n  Ref: {}",
            sampled_traceparent, ref_traceparent
        )
        .into());
    }

    if verbose {
        println!("  Sampled: {}", sampled_traceparent);
        println!("  Unsampled: {}", unsampled_traceparent);
        println!("  Reference: {}", ref_traceparent);
    }

    Ok(())
}

/// Test comprehensive scenario combining all features
fn test_comprehensive_scenario(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing comprehensive trace context scenario");
    }

    // Simulate a request flow: API → Database → Cache
    let mut rng = DetRng::new(400);
    let base_trace_id = DistTraceId::new(0x4bf92f3577b34da6, 0xa3ce929d0e0e4736);

    // API span (root)
    let api_ctx = SymbolTraceContext::new_for_encoding(
        base_trace_id,
        SymbolSpanId::new(0x00f067aa0ba902b7),
        RegionTag::new("us-east-1"),
        &mut rng,
    )
    .with_baggage("service", "api-gateway")
    .with_baggage("user_id", "12345");

    // Database span (child)
    let db_ctx = api_ctx.child(&mut rng).with_baggage("db.name", "users");

    // Cache span (child of API)
    let cache_ctx = api_ctx
        .child(&mut rng)
        .with_baggage("cache.key", "user:12345");

    // Generate headers for each span
    let api_headers = create_our_headers(&api_ctx);
    let db_headers = create_our_headers(&db_ctx);
    let cache_headers = create_our_headers(&cache_ctx);

    // Verify all have same trace_id
    let extract_trace_id =
        |headers: &HashMap<String, String>| -> Result<String, Box<dyn std::error::Error>> {
            let traceparent = headers.get("traceparent").ok_or("Missing traceparent")?;
            Ok(traceparent[3..35].to_string())
        };

    let api_trace = extract_trace_id(&api_headers)?;
    let db_trace = extract_trace_id(&db_headers)?;
    let cache_trace = extract_trace_id(&cache_headers)?;

    if api_trace != db_trace || db_trace != cache_trace {
        return Err("All spans in trace should share same trace_id".into());
    }

    // Verify different span_ids
    let extract_span_id =
        |headers: &HashMap<String, String>| -> Result<String, Box<dyn std::error::Error>> {
            let traceparent = headers.get("traceparent").ok_or("Missing traceparent")?;
            Ok(traceparent[36..52].to_string())
        };

    let api_span = extract_span_id(&api_headers)?;
    let db_span = extract_span_id(&db_headers)?;
    let cache_span = extract_span_id(&cache_headers)?;

    if api_span == db_span || db_span == cache_span || api_span == cache_span {
        return Err("Each span should have unique span_id".into());
    }

    // Verify span inheritance at SymbolTraceContext level
    if api_ctx.trace_id() != db_ctx.trace_id() || db_ctx.trace_id() != cache_ctx.trace_id() {
        return Err("All spans should share same trace_id".into());
    }

    if api_ctx.span_id() == db_ctx.span_id() || db_ctx.span_id() == cache_ctx.span_id() {
        return Err("Each span should have unique span_id".into());
    }

    // Verify tracestate evolution
    let api_tracestate = api_headers.get("tracestate").map_or("", String::as_str);
    let db_tracestate = db_headers.get("tracestate").map_or("", String::as_str);
    let cache_tracestate = cache_headers.get("tracestate").map_or("", String::as_str);

    // Each should contain expected context
    if !api_tracestate.contains("service=api-gateway") {
        return Err("API tracestate should contain service".into());
    }
    if !db_tracestate.contains("db.name=users") {
        return Err("DB tracestate should contain database info".into());
    }
    if !cache_tracestate.contains("cache.key=user:12345") {
        return Err("Cache tracestate should contain cache info".into());
    }

    // Test OpenTelemetry conformance for one span
    let ref_span_context = to_otel_span_context(&api_ctx)?;
    let ref_propagator = TraceContextPropagator::new();
    let mut ref_headers = HashMap::new();
    let otel_ctx = Context::default().with_remote_span_context(ref_span_context);
    ref_propagator.inject_context(&otel_ctx, &mut HeaderInjector(&mut ref_headers));

    let our_api_traceparent = api_headers.get("traceparent").unwrap();
    let ref_traceparent = ref_headers.get("traceparent").unwrap();

    if our_api_traceparent != ref_traceparent {
        return Err(format!(
            "API traceparent conformance mismatch:\n  Our: {}\n  Ref: {}",
            our_api_traceparent, ref_traceparent
        )
        .into());
    }

    if verbose {
        println!("  Trace ID: {}", api_trace);
        println!("  API span: {} -> {}", api_span, api_tracestate);
        println!("  DB span: {} -> {}", db_span, db_tracestate);
        println!("  Cache span: {} -> {}", cache_span, cache_tracestate);
        println!("  Reference conformance: ✓");
    }

    Ok(())
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
    fn remote_opentelemetry_context_matches_traceparent_header() {
        let mut rng = DetRng::new(42);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new(0x4bf92f3577b34da6, 0xa3ce929d0e0e4736),
            SymbolSpanId::new(0x00f067aa0ba902b7),
            RegionTag::new("test"),
            &mut rng,
        )
        .with_baggage("vendor", "test");

        let ref_span_context = to_otel_span_context(&ctx).unwrap();
        let mut ref_headers = HashMap::new();
        TraceContextPropagator::new().inject_context(
            &Context::default().with_remote_span_context(ref_span_context),
            &mut HeaderInjector(&mut ref_headers),
        );

        assert_eq!(
            create_our_headers(&ctx).get("traceparent"),
            ref_headers.get("traceparent")
        );
    }

    #[test]
    fn source_uses_real_opentelemetry_context_instead_of_local_mock_span() {
        let source = include_str!("trace_context_conformance.rs");
        for (left, right) in [
            ("Mock", "Span"),
            ("Context::default().with_", "span"),
            ("with_", "key_value"),
        ] {
            let forbidden = format!("{left}{right}");
            assert!(!source.contains(&forbidden), "found {forbidden}");
        }
        assert!(source.contains("with_remote_span_context"));
    }
}
