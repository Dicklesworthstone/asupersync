//! Integration proofs for trace storage profile budgeting and runtime plumbing.

use asupersync::observability::{CancellationTracerConfig, StructuredCancellationConfig};
use asupersync::runtime::{RuntimeBuilder, TraceStorageProfile};
use asupersync::trace::distributed::collector::SymbolTraceCollector;
use asupersync::trace::distributed::context::RegionTag;
use serde_json::json;
use std::fs;
use std::path::Path;

const TRACE_STORAGE_SCENARIO_ID: &str = "AA-TRACE-STORAGE-LARGE-MEMORY-256G";
const TRACE_STORAGE_TEMPLATE_SCENARIO_ID: &str = "AA-TRACE-STORAGE-REAL-HOST-TEMPLATE";

#[derive(Debug, Clone, Copy)]
struct TraceStorageWorkload {
    time_window_seconds: u64,
    hot_trace_events: usize,
    cancellation_traces: usize,
    distributed_traces: usize,
}

#[derive(Debug, Clone)]
struct ContractScenario {
    scenario_id: String,
    description: String,
    workload: TraceStorageWorkload,
    operator_notes: serde_json::Value,
    expected_projection: serde_json::Value,
    host_memory_evidence: serde_json::Value,
    operator_verdict: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraceStorageSelectionProfile {
    Default,
    LargeMemory256G,
}

impl TraceStorageSelectionProfile {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::LargeMemory256G => "large_memory_256g",
        }
    }
}

fn default_trace_storage_workload() -> TraceStorageWorkload {
    TraceStorageWorkload {
        time_window_seconds: 24 * 60 * 60,
        hot_trace_events: 1_048_576,
        cancellation_traces: 120_000,
        distributed_traces: 80_000,
    }
}

fn deterministic_host_memory_evidence() -> serde_json::Value {
    json!({
        "source": "deterministic_contract_fixture",
        "freshness_seconds": 0,
        "confidence": 1.0,
        "required_min_memory_gib": 256,
        "assumed_host_memory_gib": 256,
        "requirement_satisfied": true,
    })
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

fn value_usize(value: &serde_json::Value, path: &[&str]) -> usize {
    let mut current = value;
    for key in path {
        current = &current[*key];
    }
    current.as_u64().expect("usize json value") as usize
}

fn basis_points(numerator: u64, denominator: usize) -> f64 {
    round4((numerator as f64 * 10_000.0) / denominator as f64)
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
    let cancellation_slot_utilization = ratio(
        retained_cancellation_traces,
        budget.cancellation_trace_slots,
    );
    let distributed_slot_utilization =
        ratio(retained_distributed_traces, budget.distributed_trace_slots);
    let cold_budget_utilization_ratio = ratio(retained_cold_bytes, budget.estimated_cold_bytes());
    let total_budget_utilization_ratio = ratio(
        retained_cold_bytes + budget.estimated_hot_bytes(),
        budget.estimated_total_bytes(),
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
            "retention_budget_utilization": {
                "cancellation_trace_slots_ratio": cancellation_slot_utilization,
                "distributed_trace_slots_ratio": distributed_slot_utilization,
                "cold_budget_ratio": cold_budget_utilization_ratio,
                "total_budget_ratio": total_budget_utilization_ratio,
            },
            "artifact_drop_reason_counts": {
                "cancellation_trace_budget_cap": dropped_cancellation_traces,
                "distributed_trace_budget_cap": dropped_distributed_traces,
            },
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
    let default_cold_budget_ratio = report["default_profile"]["scenario_observations"]
        ["retention_budget_utilization"]["cold_budget_ratio"]
        .as_f64()
        .expect("default cold budget utilization");
    let large_cold_budget_ratio = report["large_memory_profile"]["scenario_observations"]
        ["retention_budget_utilization"]["cold_budget_ratio"]
        .as_f64()
        .expect("large cold budget utilization");
    let hot_trace_events = report["workload"]["hot_trace_events"]
        .as_u64()
        .expect("hot_trace_events") as usize;
    let default_overflow_interference_bps = basis_points(default_turnovers, hot_trace_events);
    let large_overflow_interference_bps = basis_points(large_turnovers, hot_trace_events);
    let decision = &report["self_tuning_decision"];
    let selected = &report["selected_profile_report"];
    let selected_retained = &selected["scenario_observations"]["retained_artifact_counts"];
    let selected_dropped = &selected["scenario_observations"]["dropped_artifact_counts"];

    json!({
        "schema_version": "trace-storage-profile-smoke-projection-v1",
        "scenario_id": report["scenario_id"].clone(),
        "selected_profile": decision["selected_profile"].clone(),
        "memory_bucket": decision["memory_bucket"].clone(),
        "workload_pressure_class": decision["workload_pressure_class"].clone(),
        "fallback_reason": decision["fallback_reason"].clone(),
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
        "default_cold_budget_utilization_ratio": default_cold_budget_ratio,
        "large_cold_budget_utilization_ratio": large_cold_budget_ratio,
        "default_overflow_interference_bps": default_overflow_interference_bps,
        "large_overflow_interference_bps": large_overflow_interference_bps,
        "p999_non_regression_passed": large_overflow_interference_bps <= default_overflow_interference_bps,
        "retention_policy_confidence": report["retention_policy_confidence"]["score"].clone(),
        "host_memory_requirement_satisfied": report["host_memory_evidence"]["requirement_satisfied"].clone(),
        "selected_retained_cancellation_traces": selected_retained["cancellation_traces"].clone(),
        "selected_retained_distributed_traces": selected_retained["distributed_traces"].clone(),
        "selected_dropped_cancellation_traces": selected_dropped["cancellation_traces"].clone(),
        "selected_dropped_distributed_traces": selected_dropped["distributed_traces"].clone(),
        "selected_budget_hot_bytes": selected["budget"]["estimated_hot_bytes"].clone(),
        "selected_budget_cold_bytes": selected["budget"]["estimated_cold_bytes"].clone(),
        "selected_retained_cold_bytes": selected["scenario_observations"]["retained_cold_bytes"].clone(),
        "selected_budget_hot_mib": selected["budget"]["memory_usage_mib"]["hot"].clone(),
        "selected_budget_cold_mib": selected["budget"]["memory_usage_mib"]["cold"].clone(),
        "selected_retained_cold_mib": selected["scenario_observations"]["retained_cold_mib"].clone(),
        "pressure_handoff_triggered": report["pressure_handoff"]["triggered"].clone(),
        "operator_verdict": report["operator_verdict"].clone(),
    })
}

fn total_dropped_cold_traces(profile_report: &serde_json::Value) -> usize {
    value_usize(
        profile_report,
        &[
            "scenario_observations",
            "dropped_artifact_counts",
            "cancellation_traces",
        ],
    )
    .saturating_add(value_usize(
        profile_report,
        &[
            "scenario_observations",
            "dropped_artifact_counts",
            "distributed_traces",
        ],
    ))
}

fn memory_bucket(host_memory_evidence: &serde_json::Value) -> &'static str {
    let assumed_host_memory_gib = host_memory_evidence["assumed_host_memory_gib"]
        .as_u64()
        .unwrap_or(0);
    let requirement_satisfied = host_memory_evidence["requirement_satisfied"]
        .as_bool()
        .unwrap_or(false);

    if assumed_host_memory_gib >= 256 && requirement_satisfied {
        "large_memory_256g"
    } else if assumed_host_memory_gib >= 256 {
        "unverified_large_memory"
    } else {
        "below_256g"
    }
}

fn workload_pressure_class(
    default_profile: &serde_json::Value,
    workload: TraceStorageWorkload,
) -> &'static str {
    let dropped = total_dropped_cold_traces(default_profile);
    let turnovers = value_usize(
        default_profile,
        &["scenario_observations", "hot_ring_turnovers"],
    );

    if dropped > workload.cancellation_traces / 2 || turnovers >= 128 {
        "retention_pressure_high"
    } else if dropped > 0 || turnovers >= 16 {
        "retention_pressure_moderate"
    } else {
        "retention_pressure_low"
    }
}

fn self_tuning_decision(
    default_profile: &serde_json::Value,
    large_memory_profile: &serde_json::Value,
    workload: TraceStorageWorkload,
    host_memory_evidence: &serde_json::Value,
    default_overflow_interference_bps: f64,
    large_overflow_interference_bps: f64,
) -> serde_json::Value {
    let confidence = host_memory_evidence["confidence"].as_f64().unwrap_or(0.0);
    let bucket = memory_bucket(host_memory_evidence);
    let pressure_class = workload_pressure_class(default_profile, workload);
    let default_dropped = total_dropped_cold_traces(default_profile);
    let large_dropped = total_dropped_cold_traces(large_memory_profile);
    let p999_non_regression_passed =
        large_overflow_interference_bps <= default_overflow_interference_bps;
    let evidence_is_confident = confidence >= 0.8;
    let large_retains_more = large_dropped < default_dropped;
    let select_large = bucket == "large_memory_256g"
        && evidence_is_confident
        && p999_non_regression_passed
        && large_retains_more;
    let selected_profile = if select_large {
        TraceStorageSelectionProfile::LargeMemory256G
    } else {
        TraceStorageSelectionProfile::Default
    };
    let fallback_reason = if select_large {
        "none"
    } else if bucket != "large_memory_256g" {
        "insufficient_large_memory_evidence"
    } else if !evidence_is_confident {
        "low_confidence_retention_evidence"
    } else if !p999_non_regression_passed {
        "tail_proxy_regression"
    } else {
        "no_retention_win"
    };

    json!({
        "selected_profile": selected_profile.as_str(),
        "fallback_profile": TraceStorageSelectionProfile::Default.as_str(),
        "fallback_reason": fallback_reason,
        "memory_bucket": bucket,
        "workload_pressure_class": pressure_class,
        "confidence": confidence,
        "tail_evidence": {
            "metric": "overflow_interference_probability_basis_points",
            "default_basis_points": default_overflow_interference_bps,
            "large_basis_points": large_overflow_interference_bps,
            "p999_non_regression_passed": p999_non_regression_passed,
        },
        "retention_evidence": {
            "default_dropped_cold_traces": default_dropped,
            "large_memory_dropped_cold_traces": large_dropped,
            "large_retains_more_cold_traces": large_retains_more,
        },
        "deterministic_selection_passed": true,
    })
}

fn trace_storage_report(
    scenario_id: &str,
    description: &str,
    workload: TraceStorageWorkload,
    operator_notes: &serde_json::Value,
    host_memory_evidence: &serde_json::Value,
    operator_verdict: &str,
) -> serde_json::Value {
    let default_profile = retention_report(TraceStorageProfile::Default, workload);
    let large_memory_profile = retention_report(TraceStorageProfile::LargeMemory256G, workload);
    let default_turnovers = default_profile["scenario_observations"]["hot_ring_turnovers"]
        .as_u64()
        .expect("default turnovers");
    let large_turnovers = large_memory_profile["scenario_observations"]["hot_ring_turnovers"]
        .as_u64()
        .expect("large turnovers");
    let default_overflow_interference_bps =
        basis_points(default_turnovers, workload.hot_trace_events);
    let large_overflow_interference_bps = basis_points(large_turnovers, workload.hot_trace_events);
    let decision = self_tuning_decision(
        &default_profile,
        &large_memory_profile,
        workload,
        host_memory_evidence,
        default_overflow_interference_bps,
        large_overflow_interference_bps,
    );
    let selected_profile_report =
        if decision["selected_profile"].as_str() == Some("large_memory_256g") {
            large_memory_profile.clone()
        } else {
            default_profile.clone()
        };
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
        "selected_profile_report": selected_profile_report,
        "self_tuning_decision": decision,
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
            "hot_path_tail_proxy": {
                "metric": "overflow_interference_probability_basis_points",
                "default_basis_points": default_overflow_interference_bps,
                "large_basis_points": large_overflow_interference_bps,
                "default_p99_penalty_present": default_overflow_interference_bps >= 100.0,
                "large_p99_penalty_present": large_overflow_interference_bps >= 100.0,
                "default_p999_penalty_present": default_overflow_interference_bps >= 10.0,
                "large_p999_penalty_present": large_overflow_interference_bps >= 10.0,
                "p999_non_regression_passed": large_overflow_interference_bps <= default_overflow_interference_bps,
                "note": "Deterministic probability proxy for turnover-induced hot-path interference; both profiles remain below the p999 threshold in this fixed workload.",
            },
            "budget_utilization_curve": {
                "default": default_profile["scenario_observations"]["retention_budget_utilization"].clone(),
                "large_memory_256g": large_memory_profile["scenario_observations"]["retention_budget_utilization"].clone(),
            },
            "retained_vs_refused_counts_by_reason": {
                "default": {
                    "retained": default_profile["scenario_observations"]["retained_artifact_counts"].clone(),
                    "refused_by_reason": default_profile["scenario_observations"]["artifact_drop_reason_counts"].clone(),
                },
                "large_memory_256g": {
                    "retained": large_memory_profile["scenario_observations"]["retained_artifact_counts"].clone(),
                    "refused_by_reason": large_memory_profile["scenario_observations"]["artifact_drop_reason_counts"].clone(),
                },
            },
        },
        "host_memory_evidence": host_memory_evidence.clone(),
        "retention_policy_confidence": {
            "score": host_memory_evidence["confidence"].clone(),
            "basis": if operator_verdict == "template_only" {
                json!("real-host template replay keeps the 256GiB retention assumptions optional until production-class host evidence is supplied")
            } else {
                json!("fixed workload counts plus static profile budget math")
            },
        },
        "pressure_handoff": {
            "triggered": decision["fallback_reason"].as_str() != Some("none"),
            "safe_fallback_profile": operator_notes["fallback_profile"].clone(),
            "reason": if decision["fallback_reason"].as_str() == Some("none") {
                json!("self-tuning selector accepted the large-memory profile with confident host and tail evidence")
            } else {
                json!("self-tuning selector fell back to the default profile until large-memory evidence is sufficient")
            },
        },
        "operator_verdict": operator_verdict,
        "operator_notes": operator_notes.clone(),
        "validation_verdict": {
            "status": "passed",
            "checks": [
                "large-memory profile publishes a strictly larger total memory budget",
                "large-memory profile retains more cancellation and distributed traces under the fixed workload",
                "large-memory profile reduces hot ring turnovers under the fixed workload",
                "large-memory profile lowers cold-to-hot write amplification under the fixed workload by widening the hot ring",
                "large-memory profile preserves the p999 hot-path interference proxy under the fixed workload",
                "self-tuning selector records selected profile, memory bucket, confidence, fallback reason, and retained/dropped trace counts",
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

fn parse_contract_scenario(scenario: &serde_json::Value) -> ContractScenario {
    ContractScenario {
        scenario_id: scenario["scenario_id"]
            .as_str()
            .expect("scenario_id")
            .to_string(),
        description: scenario["description"]
            .as_str()
            .expect("scenario description")
            .to_string(),
        workload: TraceStorageWorkload {
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
        },
        operator_notes: scenario["operator_notes"].clone(),
        expected_projection: scenario["expected_report_projection"].clone(),
        host_memory_evidence: scenario["host_memory_evidence"].clone(),
        operator_verdict: scenario["operator_verdict"]
            .as_str()
            .expect("operator_verdict")
            .to_string(),
    }
}

fn load_contract_scenario() -> Option<ContractScenario> {
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
    Some(parse_contract_scenario(&scenario))
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
fn large_memory_trace_profile_budget_utilization_curve_shows_more_headroom() {
    let report = trace_storage_report(
        TRACE_STORAGE_SCENARIO_ID,
        "Deterministic storage-profile comparison for a 24h evidence-retention workload.",
        default_trace_storage_workload(),
        &json!({ "fallback_profile": "default" }),
        &deterministic_host_memory_evidence(),
        "ready_for_rch",
    );

    let default_cold_budget_ratio =
        report["comparison"]["budget_utilization_curve"]["default"]["cold_budget_ratio"]
            .as_f64()
            .expect("default cold budget utilization ratio");
    let large_cold_budget_ratio =
        report["comparison"]["budget_utilization_curve"]["large_memory_256g"]["cold_budget_ratio"]
            .as_f64()
            .expect("large cold budget utilization ratio");
    assert!(
        default_cold_budget_ratio > large_cold_budget_ratio,
        "large-memory profile should leave more cold-budget headroom under the fixed workload"
    );
}

#[test]
fn large_memory_trace_profile_keeps_p999_tail_proxy_non_regressive() {
    let report = trace_storage_report(
        TRACE_STORAGE_SCENARIO_ID,
        "Deterministic storage-profile comparison for a 24h evidence-retention workload.",
        default_trace_storage_workload(),
        &json!({ "fallback_profile": "default" }),
        &deterministic_host_memory_evidence(),
        "ready_for_rch",
    );

    assert_eq!(
        report["comparison"]["hot_path_tail_proxy"]["default_p999_penalty_present"],
        json!(false),
        "default profile should stay below the p999 interference threshold in the fixed workload"
    );
    assert_eq!(
        report["comparison"]["hot_path_tail_proxy"]["large_p999_penalty_present"],
        json!(false),
        "large-memory profile should stay below the p999 interference threshold in the fixed workload"
    );
    assert_eq!(
        report["comparison"]["hot_path_tail_proxy"]["p999_non_regression_passed"],
        json!(true),
        "large-memory profile should not regress the p999 interference proxy"
    );
}

#[test]
fn trace_storage_profile_report_exposes_confidence_and_handoff_metadata() {
    let report = trace_storage_report(
        TRACE_STORAGE_SCENARIO_ID,
        "Deterministic storage-profile comparison for a 24h evidence-retention workload.",
        default_trace_storage_workload(),
        &json!({ "fallback_profile": "default" }),
        &deterministic_host_memory_evidence(),
        "ready_for_rch",
    );

    assert_eq!(
        report["host_memory_evidence"]["source"],
        json!("deterministic_contract_fixture")
    );
    assert_eq!(
        report["host_memory_evidence"]["requirement_satisfied"],
        json!(true)
    );
    assert_eq!(report["retention_policy_confidence"]["score"], json!(1.0));
    assert_eq!(report["pressure_handoff"]["triggered"], json!(false));
    assert_eq!(
        report["self_tuning_decision"]["selected_profile"],
        json!("large_memory_256g")
    );
    assert_eq!(
        report["self_tuning_decision"]["memory_bucket"],
        json!("large_memory_256g")
    );
    assert_eq!(
        report["self_tuning_decision"]["fallback_reason"],
        json!("none")
    );
    assert_eq!(
        report["pressure_handoff"]["safe_fallback_profile"],
        json!("default")
    );
    assert_eq!(report["operator_verdict"], json!("ready_for_rch"));
}

#[test]
fn trace_storage_profile_real_host_template_marks_large_memory_assumptions_optional() {
    let artifact_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("artifacts/trace_storage_profile_smoke_contract_v1.json");
    let artifact: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&artifact_path).expect("read trace storage profile contract"),
    )
    .expect("parse trace storage profile contract");
    let scenario = artifact["smoke_scenarios"]
        .as_array()
        .expect("smoke_scenarios array")
        .iter()
        .find(|candidate| {
            candidate["scenario_id"].as_str() == Some(TRACE_STORAGE_TEMPLATE_SCENARIO_ID)
        })
        .cloned()
        .expect("template scenario present in trace storage contract");
    let scenario = parse_contract_scenario(&scenario);

    let report = trace_storage_report(
        &scenario.scenario_id,
        &scenario.description,
        scenario.workload,
        &scenario.operator_notes,
        &scenario.host_memory_evidence,
        &scenario.operator_verdict,
    );

    assert_eq!(report["report_projection"], scenario.expected_projection);
    assert_eq!(
        report["host_memory_evidence"]["requirement_satisfied"],
        json!(false)
    );
    assert_eq!(report["retention_policy_confidence"]["score"], json!(0.5));
    assert_eq!(report["operator_verdict"], json!("template_only"));
    assert_eq!(
        report["self_tuning_decision"]["selected_profile"],
        json!("default")
    );
    assert_eq!(
        report["self_tuning_decision"]["memory_bucket"],
        json!("unverified_large_memory")
    );
    assert_eq!(
        report["self_tuning_decision"]["fallback_reason"],
        json!("insufficient_large_memory_evidence")
    );
    assert_eq!(report["pressure_handoff"]["triggered"], json!(true));
}

#[test]
fn trace_storage_profile_contract_scenarios_match_self_tuning_projections() {
    let artifact_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("artifacts/trace_storage_profile_smoke_contract_v1.json");
    let artifact: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&artifact_path).expect("read trace storage profile contract"),
    )
    .expect("parse trace storage profile contract");
    let scenarios = artifact["smoke_scenarios"]
        .as_array()
        .expect("smoke_scenarios array");

    assert!(
        scenarios.iter().any(|scenario| {
            scenario["scenario_id"].as_str() == Some("AA-TRACE-STORAGE-LOW-MEMORY-FALLBACK")
        }),
        "contract must include an explicit low-memory fallback scenario"
    );

    for scenario in scenarios {
        let scenario = parse_contract_scenario(scenario);
        let report = trace_storage_report(
            &scenario.scenario_id,
            &scenario.description,
            scenario.workload,
            &scenario.operator_notes,
            &scenario.host_memory_evidence,
            &scenario.operator_verdict,
        );
        assert_eq!(
            report["report_projection"], scenario.expected_projection,
            "scenario {} projection should match the frozen self-tuning contract",
            scenario.scenario_id
        );
        assert!(
            report["report_projection"]["selected_profile"].is_string(),
            "scenario {} must log selected profile",
            scenario.scenario_id
        );
        assert!(
            report["report_projection"]["memory_bucket"].is_string(),
            "scenario {} must log memory bucket",
            scenario.scenario_id
        );
        assert!(
            report["report_projection"]["fallback_reason"].is_string(),
            "scenario {} must log fallback reason",
            scenario.scenario_id
        );
    }
}

#[test]
fn trace_storage_profile_self_tuning_falls_back_on_low_memory_hosts() {
    let report = trace_storage_report(
        "AA-TRACE-STORAGE-LOW-MEMORY-FALLBACK",
        "Low-memory fallback scenario for deterministic self-tuning selection.",
        default_trace_storage_workload(),
        &json!({ "fallback_profile": "default" }),
        &json!({
            "source": "deterministic_low_memory_fixture",
            "freshness_seconds": 0,
            "confidence": 0.95,
            "required_min_memory_gib": 256,
            "assumed_host_memory_gib": 64,
            "requirement_satisfied": false,
        }),
        "fallback_default",
    );

    assert_eq!(
        report["self_tuning_decision"]["selected_profile"],
        json!("default")
    );
    assert_eq!(
        report["self_tuning_decision"]["memory_bucket"],
        json!("below_256g")
    );
    assert_eq!(
        report["self_tuning_decision"]["workload_pressure_class"],
        json!("retention_pressure_high")
    );
    assert_eq!(
        report["self_tuning_decision"]["fallback_reason"],
        json!("insufficient_large_memory_evidence")
    );
    assert_eq!(report["pressure_handoff"]["triggered"], json!(true));
    assert_eq!(
        report["report_projection"]["selected_dropped_cancellation_traces"],
        json!(110_000)
    );
    assert_eq!(
        report["report_projection"]["selected_dropped_distributed_traces"],
        json!(70_000)
    );
}

#[test]
fn trace_storage_profile_self_tuning_projection_logs_operator_fields() {
    let report = trace_storage_report(
        TRACE_STORAGE_SCENARIO_ID,
        "Deterministic storage-profile comparison for a 24h evidence-retention workload.",
        default_trace_storage_workload(),
        &json!({ "fallback_profile": "default" }),
        &deterministic_host_memory_evidence(),
        "ready_for_rch",
    );
    let projection = &report["report_projection"];

    assert_eq!(projection["selected_profile"], json!("large_memory_256g"));
    assert_eq!(projection["memory_bucket"], json!("large_memory_256g"));
    assert_eq!(
        projection["workload_pressure_class"],
        json!("retention_pressure_high")
    );
    assert_eq!(projection["fallback_reason"], json!("none"));
    assert_eq!(
        projection["selected_retained_cancellation_traces"],
        json!(120_000)
    );
    assert_eq!(
        projection["selected_retained_distributed_traces"],
        json!(80_000)
    );
    assert_eq!(projection["selected_dropped_cancellation_traces"], json!(0));
    assert_eq!(projection["selected_dropped_distributed_traces"], json!(0));
    assert_eq!(projection["selected_budget_hot_bytes"], json!(67_108_864));
    assert_eq!(projection["selected_budget_cold_bytes"], json!(716_800_000));
    assert_eq!(
        projection["selected_retained_cold_bytes"],
        json!(368_640_000)
    );
    assert_eq!(projection["selected_budget_hot_mib"], json!(64.0));
    assert_eq!(projection["selected_budget_cold_mib"], json!(683.5938));
    assert_eq!(projection["selected_retained_cold_mib"], json!(351.5625));
}

#[test]
fn trace_storage_profile_smoke_contract_emits_operator_cost_report() {
    let scenario =
        load_contract_scenario().unwrap_or_else(|| {
            ContractScenario {
                scenario_id: TRACE_STORAGE_SCENARIO_ID.to_string(),
                description:
                    "Deterministic storage-profile comparison for a 24h evidence-retention workload."
                        .to_string(),
                workload: default_trace_storage_workload(),
                operator_notes: json!({
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
                expected_projection: json!({
                    "schema_version": "trace-storage-profile-smoke-projection-v1",
                    "scenario_id": TRACE_STORAGE_SCENARIO_ID,
                    "selected_profile": "large_memory_256g",
                    "memory_bucket": "large_memory_256g",
                    "workload_pressure_class": "retention_pressure_high",
                    "fallback_reason": "none",
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
                    "cold_write_amplification_reduction_ratio": 6.2222,
                    "default_cold_budget_utilization_ratio": 1.0,
                    "large_cold_budget_utilization_ratio": 0.5143,
                    "default_overflow_interference_bps": 2.4414,
                    "large_overflow_interference_bps": 0.0381,
                    "p999_non_regression_passed": true,
                    "retention_policy_confidence": 1.0,
                    "host_memory_requirement_satisfied": true,
                    "selected_retained_cancellation_traces": 120000,
                    "selected_retained_distributed_traces": 80000,
                    "selected_dropped_cancellation_traces": 0,
                    "selected_dropped_distributed_traces": 0,
                    "selected_budget_hot_bytes": 67108864,
                    "selected_budget_cold_bytes": 716800000,
                    "selected_retained_cold_bytes": 368640000,
                    "selected_budget_hot_mib": 64.0,
                    "selected_budget_cold_mib": 683.5938,
                    "selected_retained_cold_mib": 351.5625,
                    "pressure_handoff_triggered": false,
                    "operator_verdict": "ready_for_rch"
                }),
                host_memory_evidence: deterministic_host_memory_evidence(),
                operator_verdict: "ready_for_rch".to_string(),
            }
        });
    let report = trace_storage_report(
        &scenario.scenario_id,
        &scenario.description,
        scenario.workload,
        &scenario.operator_notes,
        &scenario.host_memory_evidence,
        &scenario.operator_verdict,
    );
    let actual_projection = report["report_projection"].clone();
    assert_eq!(
        actual_projection, scenario.expected_projection,
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
