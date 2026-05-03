//! Integration proofs for trace storage profile budgeting and runtime plumbing.

use asupersync::observability::{CancellationTracerConfig, StructuredCancellationConfig};
use asupersync::runtime::{RuntimeBuilder, TraceStorageProfile};
use asupersync::trace::distributed::collector::SymbolTraceCollector;
use asupersync::trace::distributed::context::RegionTag;

#[test]
fn large_memory_trace_profile_budget_is_strictly_larger_than_default() {
    let default_budget = TraceStorageProfile::Default.budget();
    let large_budget = TraceStorageProfile::LargeMemory256G.budget();

    assert!(
        large_budget.trace_event_slots > default_budget.trace_event_slots,
        "large-memory profile should widen the hot trace ring"
    );
    assert!(
        large_budget.cancellation_trace_slots > default_budget.cancellation_trace_slots,
        "large-memory profile should retain more cancellation traces"
    );
    assert!(
        large_budget.distributed_trace_slots > default_budget.distributed_trace_slots,
        "large-memory profile should retain more distributed traces"
    );
    assert!(
        large_budget.estimated_total_bytes() > default_budget.estimated_total_bytes(),
        "large-memory profile should expose a larger operator-visible memory budget"
    );
}

#[test]
fn runtime_builder_applies_trace_storage_profile_to_live_trace_buffer() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(1)
        .trace_storage_profile(TraceStorageProfile::LargeMemory256G)
        .build()
        .expect("large-memory trace profile should build");

    assert_eq!(
        runtime.config().trace_storage_profile,
        TraceStorageProfile::LargeMemory256G,
        "runtime config should preserve the selected trace storage profile"
    );
    assert_eq!(
        runtime.trace_buffer_capacity(),
        TraceStorageProfile::LargeMemory256G.trace_buffer_capacity(),
        "live runtime state should size the hot trace ring from the selected profile"
    );
    assert_eq!(
        runtime.config().trace_storage_budget(),
        TraceStorageProfile::LargeMemory256G.budget(),
        "runtime config should surface the operator-visible storage budget"
    );
}

#[test]
fn large_memory_trace_profile_widens_cold_trace_retention_limits() {
    let default_tracer =
        CancellationTracerConfig::for_trace_storage_profile(TraceStorageProfile::Default);
    let large_tracer =
        CancellationTracerConfig::for_trace_storage_profile(TraceStorageProfile::LargeMemory256G);
    assert!(
        large_tracer.max_traces > default_tracer.max_traces,
        "large-memory profile should retain more cancellation traces"
    );

    let default_collector = SymbolTraceCollector::new(RegionTag::new("default"))
        .with_trace_storage_profile(TraceStorageProfile::Default);
    let large_collector = SymbolTraceCollector::new(RegionTag::new("large-memory"))
        .with_trace_storage_profile(TraceStorageProfile::LargeMemory256G);

    assert!(
        large_collector.max_traces() > default_collector.max_traces(),
        "large-memory profile should retain more distributed traces"
    );
    assert!(
        large_collector.max_age() > default_collector.max_age(),
        "large-memory profile should extend distributed trace retention age"
    );
}

#[test]
fn large_memory_trace_profile_scales_structured_cancellation_budget() {
    let default_config =
        StructuredCancellationConfig::for_trace_storage_profile(TraceStorageProfile::Default);
    let large_config = StructuredCancellationConfig::for_trace_storage_profile(
        TraceStorageProfile::LargeMemory256G,
    );

    assert!(
        large_config.tracer_config.max_traces > default_config.tracer_config.max_traces,
        "large-memory profile should retain more cancellation traces in the analyzer"
    );
    assert!(
        large_config.max_memory_usage_mb > default_config.max_memory_usage_mb,
        "large-memory profile should publish a larger cold-trace memory budget"
    );
    assert!(
        large_config.trace_retention_duration > default_config.trace_retention_duration,
        "large-memory profile should retain structured cancellation traces longer"
    );
}
