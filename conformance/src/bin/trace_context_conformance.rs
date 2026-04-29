use asupersync::observability::otel::{TraceContext, TraceContextPropagator};
use clap::{Arg, Command};
use opentelemetry::trace::{SpanContext, SpanId, TraceFlags, TraceId, TraceState};
use opentelemetry::{Context, KeyValue};
use opentelemetry_sdk::trace::{TracerProvider, Config, Sampler};
use opentelemetry_sdk::{Resource, runtime::Tokio};
use std::collections::HashMap;

/// W3C trace context propagation conformance testing.
/// Compares our TraceContext implementation against opentelemetry reference for identical
/// traceparent/tracestate header pairs given the same span tree.
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

    let test_cases = vec![
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

/// Test basic trace context propagation with single span
fn test_basic_propagation(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing basic traceparent/tracestate propagation");
    }

    // Create a simple span context
    let trace_id = TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736")?;
    let span_id = SpanId::from_hex("00f067aa0ba902b7")?;
    let trace_flags = TraceFlags::SAMPLED;
    let trace_state = TraceState::from_key_value_pairs([("vendor", "test")])?;

    let span_context = SpanContext::new(trace_id, span_id, trace_flags, false, trace_state);

    // Our implementation
    let our_propagator = TraceContextPropagator::new();
    let our_headers = our_propagator.inject(&span_context)?;

    // Reference implementation
    let ref_propagator = opentelemetry::propagation::TextMapPropagator::new();
    let mut ref_headers = HashMap::new();
    let ctx = Context::default().with_span(MockSpan::new(span_context));
    ref_propagator.inject_context(&ctx, &mut HeaderInjector(&mut ref_headers));

    // Compare traceparent headers
    let our_traceparent = our_headers.get("traceparent").ok_or("Missing traceparent")?;
    let ref_traceparent = ref_headers.get("traceparent").ok_or("Missing ref traceparent")?;

    if our_traceparent != ref_traceparent {
        return Err(format!(
            "traceparent mismatch:\n  Our: {}\n  Ref: {}",
            our_traceparent, ref_traceparent
        ).into());
    }

    // Compare tracestate headers
    let our_tracestate = our_headers.get("tracestate");
    let ref_tracestate = ref_headers.get("tracestate");

    match (our_tracestate, ref_tracestate) {
        (Some(ours), Some(refs)) => {
            if ours != refs {
                return Err(format!(
                    "tracestate mismatch:\n  Our: {}\n  Ref: {}",
                    ours, refs
                ).into());
            }
        }
        (None, None) => {
            // Both empty, OK
        }
        (ours, refs) => {
            return Err(format!(
                "tracestate presence mismatch:\n  Our: {:?}\n  Ref: {:?}",
                ours, refs
            ).into());
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

    // Parent span
    let parent_trace_id = TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736")?;
    let parent_span_id = SpanId::from_hex("00f067aa0ba902b7")?;
    let parent_flags = TraceFlags::SAMPLED;
    let parent_state = TraceState::from_key_value_pairs([("parent", "root")])?;

    let parent_context = SpanContext::new(
        parent_trace_id,
        parent_span_id,
        parent_flags,
        false,
        parent_state
    );

    // Child span (inherits trace_id, gets new span_id)
    let child_span_id = SpanId::from_hex("1234567890abcdef")?;
    let child_state = TraceState::from_key_value_pairs([("parent", "root"), ("child", "level1")])?;

    let child_context = SpanContext::new(
        parent_trace_id,  // Same trace_id
        child_span_id,    // New span_id
        parent_flags,     // Inherit sampling
        false,
        child_state
    );

    // Test parent propagation
    let our_propagator = TraceContextPropagator::new();
    let parent_headers = our_propagator.inject(&parent_context)?;
    let child_headers = our_propagator.inject(&child_context)?;

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

    let trace_id = TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736")?;
    let span_id = SpanId::from_hex("00f067aa0ba902b7")?;
    let trace_flags = TraceFlags::SAMPLED;

    // TraceState with baggage-like entries
    let trace_state = TraceState::from_key_value_pairs([
        ("service", "api"),
        ("version", "1.2.3"),
        ("datacenter", "us-east-1")
    ])?;

    let span_context = SpanContext::new(trace_id, span_id, trace_flags, false, trace_state);

    let our_propagator = TraceContextPropagator::new();
    let headers = our_propagator.inject(&span_context)?;

    // Verify tracestate contains all baggage
    let tracestate = headers.get("tracestate")
        .ok_or("tracestate header missing")?;

    let required_entries = ["service=api", "version=1.2.3", "datacenter=us-east-1"];
    for entry in &required_entries {
        if !tracestate.contains(entry) {
            return Err(format!("tracestate missing entry: {}", entry).into());
        }
    }

    if verbose {
        println!("  tracestate with baggage: {}", tracestate);
    }

    Ok(())
}

/// Test sampling decisions affect trace flags
fn test_sampling_decisions(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing sampling decisions in trace context");
    }

    let trace_id = TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736")?;
    let span_id = SpanId::from_hex("00f067aa0ba902b7")?;

    // Test sampled span
    let sampled_context = SpanContext::new(
        trace_id,
        span_id,
        TraceFlags::SAMPLED,
        false,
        TraceState::default()
    );

    // Test unsampled span
    let unsampled_context = SpanContext::new(
        trace_id,
        span_id,
        TraceFlags::default(),
        false,
        TraceState::default()
    );

    let our_propagator = TraceContextPropagator::new();

    let sampled_headers = our_propagator.inject(&sampled_context)?;
    let unsampled_headers = our_propagator.inject(&unsampled_context)?;

    // Check flags in traceparent (last 2 chars)
    let sampled_traceparent = sampled_headers.get("traceparent").unwrap();
    let unsampled_traceparent = unsampled_headers.get("traceparent").unwrap();

    // Sampled should end with "01", unsampled with "00"
    if !sampled_traceparent.ends_with("-01") {
        return Err(format!("Sampled span should end with -01: {}", sampled_traceparent).into());
    }

    if !unsampled_traceparent.ends_with("-00") {
        return Err(format!("Unsampled span should end with -00: {}", unsampled_traceparent).into());
    }

    if verbose {
        println!("  Sampled: {}", sampled_traceparent);
        println!("  Unsampled: {}", unsampled_traceparent);
    }

    Ok(())
}

/// Test comprehensive scenario combining all features
fn test_comprehensive_scenario(verbose: bool) -> TestResult {
    if verbose {
        println!("  Testing comprehensive trace context scenario");
    }

    // Simulate a request flow: API → Database → Cache
    let base_trace_id = TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736")?;

    // API span (root)
    let api_span_id = SpanId::from_hex("00f067aa0ba902b7")?;
    let api_state = TraceState::from_key_value_pairs([
        ("service", "api-gateway"),
        ("user_id", "12345")
    ])?;
    let api_context = SpanContext::new(
        base_trace_id,
        api_span_id,
        TraceFlags::SAMPLED,
        false,
        api_state
    );

    // Database span (child)
    let db_span_id = SpanId::from_hex("1234567890abcdef")?;
    let db_state = TraceState::from_key_value_pairs([
        ("service", "api-gateway"),
        ("user_id", "12345"),
        ("db.name", "users")
    ])?;
    let db_context = SpanContext::new(
        base_trace_id,
        db_span_id,
        TraceFlags::SAMPLED,
        false,
        db_state
    );

    // Cache span (child)
    let cache_span_id = SpanId::from_hex("fedcba0987654321")?;
    let cache_state = TraceState::from_key_value_pairs([
        ("service", "api-gateway"),
        ("user_id", "12345"),
        ("cache.key", "user:12345")
    ])?;
    let cache_context = SpanContext::new(
        base_trace_id,
        cache_span_id,
        TraceFlags::SAMPLED,
        false,
        cache_state
    );

    let our_propagator = TraceContextPropagator::new();

    // Generate headers for each span
    let api_headers = our_propagator.inject(&api_context)?;
    let db_headers = our_propagator.inject(&db_context)?;
    let cache_headers = our_propagator.inject(&cache_context)?;

    // Verify all have same trace_id
    let extract_trace_id = |headers: &HashMap<String, String>| -> Result<String, Box<dyn std::error::Error>> {
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
    let extract_span_id = |headers: &HashMap<String, String>| -> Result<String, Box<dyn std::error::Error>> {
        let traceparent = headers.get("traceparent").ok_or("Missing traceparent")?;
        Ok(traceparent[36..52].to_string())
    };

    let api_span = extract_span_id(&api_headers)?;
    let db_span = extract_span_id(&db_headers)?;
    let cache_span = extract_span_id(&cache_headers)?;

    if api_span == db_span || db_span == cache_span || api_span == cache_span {
        return Err("Each span should have unique span_id".into());
    }

    // Verify tracestate evolution
    let api_tracestate = api_headers.get("tracestate").unwrap_or(&String::new());
    let db_tracestate = db_headers.get("tracestate").unwrap_or(&String::new());
    let cache_tracestate = cache_headers.get("tracestate").unwrap_or(&String::new());

    // Each should contain increasing context
    if !api_tracestate.contains("service=api-gateway") {
        return Err("API tracestate should contain service".into());
    }
    if !db_tracestate.contains("db.name=users") {
        return Err("DB tracestate should contain database info".into());
    }
    if !cache_tracestate.contains("cache.key=user:12345") {
        return Err("Cache tracestate should contain cache info".into());
    }

    if verbose {
        println!("  Trace ID: {}", api_trace);
        println!("  API span: {} -> {}", api_span, api_tracestate);
        println!("  DB span: {} -> {}", db_span, db_tracestate);
        println!("  Cache span: {} -> {}", cache_span, cache_tracestate);
    }

    Ok(())
}

// Mock implementations for testing

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