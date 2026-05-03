//! Integration proofs for trace storage profile budgeting and runtime plumbing.

use asupersync::observability::{CancellationTracerConfig, StructuredCancellationConfig};
use asupersync::runtime::{RuntimeBuilder, TraceStorageProfile};
use asupersync::trace::distributed::collector::SymbolTraceCollector;
use asupersync::trace::distributed::context::RegionTag;
use serde_json::json;
use std::fs;
use std::path::Path;

const TRACE_STORAGE_SCENARIO_ID: &str = "AA-TRACE-STORAGE-LARGE-MEMORY-256G";

#[derive(Debug, Clone, Copy)]
struct TraceStorageWorkload {
    time_window_seconds: u64,
    hot_trace_events: usize,
    cancellation_traces: usize,
    distributed_traces: usize,
}

fn default_trace_storage_workload() -> TraceStorageWorkload {
    TraceStorageWorkload {
        time_window_seconds: 24 * 60 * 60,
        hot_trace_events: 1_048_576,
        cancellation_traces: 120_000,
        distributed_traces: 80_000,
    }
}

fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

fn bytes_to_mib(bytes: usize) -> f64 {
    round4(bytes as f64 / 1_048_576.0)
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    round4(numerator as f64 / denominator as f64)
}

fn profile_label(profile: TraceStorageProfile) -> &'static str {
    match profile {
        TraceStorageProfile::Default => "default",
        TraceStorageProfile::LargeMemory256G => "large_memory_256g",
    }
}

fn retention_report(
    profile: TraceStorageProfile,
    workload: TraceStorageWorkload,
) -> serde_json::Value {
    let budget = profile.budget();
    let retained_cancellation_traces = workload
        .cancellation_traces
        .min(budget.cancellation_trace_slots);
    let dropped_cancellation_traces = workload
        .cancellation_traces
        .saturating_sub(retained_cancellation_traces);
    let retained_distributed_traces = workload
        .distributed_traces
        .min(budget.distributed_trace_slots);
    let dropped_distributed_traces = workload
        .distributed_traces
        .saturating_sub(retained_distributed_traces);
    let hot_ring_turnovers = workload.hot_trace_events.div_ceil(budget.trace_event_slots);
    let retained_cold_bytes = retained_cancellation_traces
        .saturating_mul(budget.assumed_cancellation_trace_bytes)
        .saturating_add(
            retained_distributed_traces.saturating_mul(budget.assumed_distributed_trace_bytes),
        );

    json!({
        "profile_name": profile_label(profile),
        "budget": {
            "trace_event_slots": budget.trace_event_slots,
            "cancellation_trace_slots": budget.cancellation_trace_slots,
            "distributed_trace_slots": budget.distributed_trace_slots,
            "estimated_hot_bytes": budget.estimated_hot_bytes(),
            "estimated_cold_bytes": budget.estimated_cold_bytes(),
            "estimated_total_bytes": budget.estimated_total_bytes(),
            "memory_usage_mib": {
                "hot": bytes_to_mib(budget.estimated_hot_bytes()),
                "cold": bytes_to_mib(budget.estimated_cold_bytes()),
                "total": bytes_to_mib(budget.estimated_total_bytes()),
            },
            "retention_horizon_seconds": profile.distributed_trace_max_age().as_secs(),
        },
        "scenario_observations": {
            "retained_artifact_counts": {
                "cancellation_traces": retained_cancellation_traces,
                "distributed_traces": retained_distributed_traces,
                "total_cold_traces": retained_cancellation_traces + retained_distributed_traces,
            },
            "dropped_artifact_counts": {
                "cancellation_traces": dropped_cancellation_traces,
                "distributed_traces": dropped_distributed_traces,
            },
            "retained_cold_bytes": retained_cold_bytes,
            "retained_cold_mib": bytes_to_mib(retained_cold_bytes),
            "hot_ring_turnovers": hot_ring_turnovers,
            "cold_write_amplification_factor": ratio(retained_cold_bytes, budget.estimated_hot_bytes()),
        }
    })
}

fn comparison_projection(report: &serde_json::Value) -> serde_json::Value {
    let default_total_mib = report["default_profile"]["budget"]["memory_usage_mib"]["total"]
        .as_f64()
        .expect("default total MiB");
    let large_total_mib = report["large_memory_profile"]["budget"]["memory_usage_mib"]["total"]
        .as_f64()
        .expect("large total MiB");
    let default_turnovers =
        report["default_profile"]["scenario_observations"]["hot_ring_turnovers"]
            .as_u64()
            .expect("default turnovers");
    let large_turnovers =
        report["large_memory_profile"]["scenario_observations"]["hot_ring_turnovers"]
            .as_u64()
            .expect("large turnovers");
    let default_retained_cancellation = report["default_profile"]["scenario_observations"]
        ["retained_artifact_counts"]["cancellation_traces"]
        .as_u64()
        .expect("default retained cancellation traces");
    let large_retained_cancellation = report["large_memory_profile"]["scenario_observations"]
        ["retained_artifact_counts"]["cancellation_traces"]
        .as_u64()
        .expect("large retained cancellation traces");
    let default_retained_distributed = report["default_profile"]["scenario_observations"]
        ["retained_artifact_counts"]["distributed_traces"]
        .as_u64()
        .expect("default retained distributed traces");
    let large_retained_distributed = report["large_memory_profile"]["scenario_observations"]
        ["retained_artifact_counts"]["distributed_traces"]
        .as_u64()
        .expect("large retained distributed traces");
    let default_cold_amp =
        report["default_profile"]["scenario_observations"]["cold_write_amplification_factor"]
            .as_f64()
            .expect("default cold amplification");
    let large_cold_amp =
        report["large_memory_profile"]["scenario_observations"]["cold_write_amplification_factor"]
            .as_f64()
            .expect("large cold amplification");

    json!({
        "schema_version": "trace-storage-profile-smoke-projection-v1",
        "scenario_id": report["scenario_id"].clone(),
        "default_budget_total_mib": default_total_mib,
        "large_budget_total_mib": large_total_mib,
        "budget_total_mib_delta": round4(large_total_mib - default_total_mib),
        "budget_multiplier": round4(large_total_mib / default_total_mib),
        "default_hot_ring_turnovers": default_turnovers,
        "large_hot_ring_turnovers": large_turnovers,
        "hot_ring_turnover_reduction_ratio": round4(default_turnovers as f64 / large_turnovers as f64),
        "default_retained_cancellation_traces": default_retained_cancellation,
        "large_retained_cancellation_traces": large_retained_cancellation,
        "default_retained_distributed_traces": default_retained_distributed,
        "large_retained_distributed_traces": large_retained_distributed,
        "default_cold_write_amplification_factor": default_cold_amp,
        "large_cold_write_amplification_factor": large_cold_amp,
        "cold_write_amplification_reduction_ratio": round4(default_cold_amp / large_cold_amp),
    })
}

fn trace_storage_report(
    scenario_id: &str,
    description: &str,
    workload: TraceStorageWorkload,
    operator_notes: &serde_json::Value,
) -> serde_json::Value {
    let default_profile = retention_report(TraceStorageProfile::Default, workload);
    let large_memory_profile = retention_report(TraceStorageProfile::LargeMemory256G, workload);
    let report = json!({
        "schema_version": "asupersync.trace-storage-profile-comparison.v1",
        "scenario_id": scenario_id,
        "description": description,
        "time_window_seconds": workload.time_window_seconds,
        "workload": {
            "hot_trace_events": workload.hot_trace_events,
            "cancellation_traces": workload.cancellation_traces,
            "distributed_traces": workload.distributed_traces,
        },
        "default_profile": default_profile,
        "large_memory_profile": large_memory_profile,
        "comparison": {
            "latency_proxy_basis": "hot_ring_turnovers and cold_write_amplification_factor",
            "hot_path_latency_summary": {
                "default_hot_ring_turnovers": default_profile["scenario_observations"]["hot_ring_turnovers"].clone(),
                "large_hot_ring_turnovers": large_memory_profile["scenario_observations"]["hot_ring_turnovers"].clone(),
                "turnover_reduction_ratio": round4(
                    default_profile["scenario_observations"]["hot_ring_turnovers"]
                        .as_u64()
                        .expect("default turnovers") as f64
                        / large_memory_profile["scenario_observations"]["hot_ring_turnovers"]
                            .as_u64()
                            .expect("large turnovers") as f64
                ),
                "default_cold_write_amplification_factor": default_profile["scenario_observations"]
                    ["cold_write_amplification_factor"]
                    .clone(),
                "large_cold_write_amplification_factor": large_memory_profile["scenario_observations"]
                    ["cold_write_amplification_factor"]
                    .clone(),
                "note": "Deterministic proxy for hot-path interference; live cycle-level timing remains a follow-on benchmark concern.",
            },
        },
        "operator_notes": operator_notes.clone(),
        "validation_verdict": {
            "status": "passed",
            "checks": [
                "large-memory profile publishes a strictly larger total memory budget",
                "large-memory profile retains more cancellation and distributed traces under the fixed workload",
                "large-memory profile reduces hot ring turnovers under the fixed workload",
                "large-memory profile lowers cold-to-hot write amplification under the fixed workload by widening the hot ring",
            ]
        }
    });
    let projection = comparison_projection(&report);
    let mut report_object = report
        .as_object()
        .expect("trace storage report should serialize as object")
        .clone();
    report_object.insert("report_projection".to_string(), projection);
    serde_json::Value::Object(report_object)
}

fn load_contract_scenario() -> Option<(
    String,
    TraceStorageWorkload,
    serde_json::Value,
    serde_json::Value,
)> {
    let contract_path = std::env::var("ASUPERSYNC_TRACE_STORAGE_CONTRACT_PATH").ok()?;
    let scenario_id = std::env::var("ASUPERSYNC_TRACE_STORAGE_SCENARIO_ID")
        .unwrap_or_else(|_| TRACE_STORAGE_SCENARIO_ID.to_string());
    let artifact: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&contract_path).expect("read trace storage contract"),
    )
    .expect("parse trace storage contract");
    let scenario = artifact["smoke_scenarios"]
        .as_array()
        .expect("smoke_scenarios array")
        .iter()
        .find(|candidate| candidate["scenario_id"].as_str() == Some(scenario_id.as_str()))
        .cloned()
        .expect("scenario present in trace storage contract");
    let workload = TraceStorageWorkload {
        time_window_seconds: scenario["workload_model"]["time_window_seconds"]
            .as_u64()
            .expect("time_window_seconds"),
        hot_trace_events: scenario["workload_model"]["hot_trace_events"]
            .as_u64()
            .expect("hot_trace_events") as usize,
        cancellation_traces: scenario["workload_model"]["cancellation_traces"]
            .as_u64()
            .expect("cancellation_traces") as usize,
        distributed_traces: scenario["workload_model"]["distributed_traces"]
            .as_u64()
            .expect("distributed_traces") as usize,
    };
    Some((
        scenario["description"]
            .as_str()
            .expect("scenario description")
            .to_string(),
        workload,
        scenario["operator_notes"].clone(),
        scenario["expected_report_projection"].clone(),
    ))
}

fn maybe_write_report(path: &str, report: &serde_json::Value) {
    let report_path = Path::new(path);
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent).expect("create trace storage report directory");
    }
    fs::write(
        report_path,
        serde_json::to_string_pretty(report).expect("serialize trace storage report"),
    )
    .expect("write trace storage report");
}

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

#[test]
fn trace_storage_profile_smoke_contract_emits_operator_cost_report() {
    let (description, workload, operator_notes, expected_projection) =
        load_contract_scenario().unwrap_or_else(|| {
            (
                "Deterministic storage-profile comparison for a 24h evidence-retention workload."
                    .to_string(),
                default_trace_storage_workload(),
                json!({
                    "recommended_for": [
                        "64+ core / 256GiB hosts that need richer postmortem evidence retention",
                        "bursty cancellation and distributed-trace workloads where the default profile drops too much cold evidence"
                    ],
                    "avoid_when": [
                        "hosts that cannot justify roughly 712 MiB of extra trace budget",
                        "deployments that do not need day-long distributed trace retention"
                    ],
                    "fallback_profile": "default"
                }),
                json!({
                    "schema_version": "trace-storage-profile-smoke-projection-v1",
                    "scenario_id": TRACE_STORAGE_SCENARIO_ID,
                    "default_budget_total_mib": 35.1797,
                    "large_budget_total_mib": 747.5938,
                    "budget_total_mib_delta": 712.4141,
                    "budget_multiplier": 21.2507,
                    "default_hot_ring_turnovers": 256,
                    "large_hot_ring_turnovers": 4,
                    "hot_ring_turnover_reduction_ratio": 64.0,
                    "default_retained_cancellation_traces": 10000,
                    "large_retained_cancellation_traces": 120000,
                    "default_retained_distributed_traces": 10000,
                    "large_retained_distributed_traces": 80000,
                    "default_cold_write_amplification_factor": 34.1797,
                    "large_cold_write_amplification_factor": 5.4932,
                    "cold_write_amplification_reduction_ratio": 6.2222
                }),
            )
        });
    let report = trace_storage_report(
        TRACE_STORAGE_SCENARIO_ID,
        &description,
        workload,
        &operator_notes,
    );
    let actual_projection = report["report_projection"].clone();
    assert_eq!(
        actual_projection, expected_projection,
        "trace storage comparison report projection should remain stable"
    );
    assert!(
        report["large_memory_profile"]["budget"]["estimated_total_bytes"]
            .as_u64()
            .expect("large-memory estimated total bytes")
            > report["default_profile"]["budget"]["estimated_total_bytes"]
                .as_u64()
                .expect("default estimated total bytes"),
        "large-memory profile should publish a larger operator-visible budget"
    );
    assert!(
        report["large_memory_profile"]["scenario_observations"]["hot_ring_turnovers"]
            .as_u64()
            .expect("large-memory turnovers")
            < report["default_profile"]["scenario_observations"]["hot_ring_turnovers"]
                .as_u64()
                .expect("default turnovers"),
        "large-memory profile should reduce hot ring turnover pressure in the deterministic workload"
    );
    assert!(
        report["large_memory_profile"]["scenario_observations"]["cold_write_amplification_factor"]
            .as_f64()
            .expect("large-memory cold amplification")
            < report["default_profile"]["scenario_observations"]["cold_write_amplification_factor"]
                .as_f64()
                .expect("default cold amplification"),
        "large-memory profile should lower cold-to-hot amplification by widening the hot ring"
    );

    if let Ok(report_path) = std::env::var("ASUPERSYNC_TRACE_STORAGE_REPORT_PATH") {
        maybe_write_report(&report_path, &report);
        println!("trace_storage_report_path={report_path}");
        println!("TRACE_STORAGE_REPORT_JSON_BEGIN");
        println!(
            "{}",
            serde_json::to_string(&report).expect("serialize compact trace storage report")
        );
        println!("TRACE_STORAGE_REPORT_JSON_END");
    }
}
