//! Contract tests for swarm contention heatmap ledgers.

use asupersync::lab::{
    SWARM_CONTENTION_HEATMAP_LEDGER_SCHEMA_VERSION, SwarmContentionHeatmapInput,
    SwarmContentionHeatmapVerdict, SwarmContentionHotspotKind, SwarmContentionLockMetric,
    SwarmContentionSchedulerLaneMetric, SwarmContentionSeverity, SwarmPressureTraceQueueHotSpot,
    SwarmReplayAdmissionDecision, SwarmReplayScenario, build_swarm_contention_heatmap,
    render_swarm_contention_heatmap_text, run_swarm_replay_scenario, summarize_swarm_replay_trace,
};
use serde_json::Value;
use std::path::Path;

const ARTIFACT_PATH: &str = "artifacts/swarm_contention_heatmap_ledger_contract_v1.json";

fn healthy_replay_scenario() -> SwarmReplayScenario {
    SwarmReplayScenario {
        scenario_id: "contention-heatmap-healthy".to_string(),
        seed: 0xC011_7EAD,
        worker_count: 2,
        cohort_count: 1,
        region_count: 2,
        tasks_per_region: 3,
        yields_per_task: 2,
        yield_jitter: 1,
        channel_capacity: 8,
        messages_per_task: 2,
        semaphore_permits_per_task: 1,
        pool_slots_per_task: 1,
        obligations_per_task: 2,
        timer_ticks_per_task: 1,
        cancellation_tree_depth: 2,
        artifact_bytes_per_task: 64,
        region_task_admission_limit: None,
        region_over_limit_decision: SwarmReplayAdmissionDecision::Shed,
        region_memory_bytes_per_task: 1024,
        region_queue_depth_units_per_task: 1,
        region_blocking_pool_units_per_task: 1,
        region_cleanup_poll_quota_per_task: 1,
        cancel_after_steps: None,
        max_steps: 10_000,
    }
}

fn healthy_trace_summary() -> asupersync::lab::SwarmPressureTraceSummary {
    let replay = run_swarm_replay_scenario(&healthy_replay_scenario()).expect("healthy replay");
    summarize_swarm_replay_trace(&replay)
}

fn lock_metric(
    name: &str,
    contentions: u64,
    p95_wait_ns: u64,
    p99_wait_ns: u64,
) -> SwarmContentionLockMetric {
    SwarmContentionLockMetric {
        name: name.to_string(),
        acquisitions: 128,
        contentions,
        wait_ns: p95_wait_ns.saturating_mul(128),
        hold_ns: 25_000,
        max_wait_ns: p99_wait_ns,
        max_hold_ns: 10_000,
        p50_wait_ns: p95_wait_ns / 4,
        p95_wait_ns,
        p99_wait_ns,
        wait_percentile_sample_count: Some(128),
        p95_hold_ns: 5_000,
        p99_hold_ns: 10_000,
        hold_percentile_sample_count: Some(128),
        instrumentation_mode: "fixture_lock_metrics".to_string(),
    }
}

fn lane_metric(
    lane_id: &str,
    p95_wait_ns: u64,
    p99_wait_ns: u64,
    queue_depth_p95: u64,
    queue_depth_p99: u64,
) -> SwarmContentionSchedulerLaneMetric {
    SwarmContentionSchedulerLaneMetric {
        lane_id: lane_id.to_string(),
        dispatched_tasks: 512,
        p50_wait_ns: p95_wait_ns / 4,
        p95_wait_ns,
        p99_wait_ns,
        queue_depth_p50: queue_depth_p95 / 4,
        queue_depth_p95,
        queue_depth_p99,
        steal_attempts: 12,
        fairness_yields: 0,
    }
}

fn healthy_input() -> SwarmContentionHeatmapInput {
    SwarmContentionHeatmapInput {
        ledger_id: "contention-heatmap-fixture".to_string(),
        baseline_id: Some("baseline-2026-05-30".to_string()),
        baseline_age_secs: 60,
        max_baseline_age_secs: 86_400,
        trace_summary: Some(healthy_trace_summary()),
        lock_metrics: vec![lock_metric("runtime_state", 2, 10_000, 20_000)],
        scheduler_lanes: vec![lane_metric("ready", 12_000, 24_000, 1, 2)],
        source_trace_ids: vec![
            "trace-summary-closed-asupersync-vssefs.7".to_string(),
            "trace-summary-closed-asupersync-vssefs.7".to_string(),
        ],
        proof_command: Some("RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_swarm_contention_heatmap cargo test -p asupersync --test swarm_contention_heatmap_contract swarm_contention_heatmap --features test-internals -- --nocapture".to_string()),
    }
}

fn assert_common_contract(ledger: &asupersync::lab::SwarmContentionHeatmapLedger) {
    assert_eq!(
        ledger.schema_version,
        SWARM_CONTENTION_HEATMAP_LEDGER_SCHEMA_VERSION
    );
    assert_eq!(
        ledger.source_trace_ids,
        vec!["trace-summary-closed-asupersync-vssefs.7".to_string()]
    );
    assert!(
        ledger
            .proof_command
            .as_deref()
            .is_some_and(|command| command.contains("RCH_REQUIRE_REMOTE=1 rch exec"))
    );
}

#[test]
fn swarm_contention_heatmap_contract_artifact_is_source_backed() {
    let raw = std::fs::read_to_string(ARTIFACT_PATH).expect("read heatmap contract artifact");
    let artifact: Value = serde_json::from_str(&raw).expect("parse heatmap artifact");

    assert_eq!(
        artifact["contract_version"].as_str(),
        Some("swarm-contention-heatmap-ledger-contract-v1")
    );
    assert_eq!(artifact["bead_id"].as_str(), Some("asupersync-vssefs.9.4"));
    assert_eq!(
        artifact["schema_version"].as_str(),
        Some(SWARM_CONTENTION_HEATMAP_LEDGER_SCHEMA_VERSION)
    );

    let source = artifact
        .get("source_of_truth")
        .expect("source_of_truth object");
    for key in ["contract", "contract_test", "runtime_policy_source"] {
        let path = source
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("source_of_truth.{key} must be a string"));
        assert!(
            Path::new(path).exists(),
            "source_of_truth.{key} must point to a live repo file: {path}"
        );
    }
}

#[test]
fn percentile_horizon_heatmap_healthy_report_passes_with_stable_text() {
    let ledger = build_swarm_contention_heatmap(&healthy_input());
    let text = render_swarm_contention_heatmap_text(&ledger);

    eprintln!("{text}");

    assert_common_contract(&ledger);
    assert_eq!(ledger.verdict, SwarmContentionHeatmapVerdict::Pass);
    assert_eq!(ledger.max_severity, SwarmContentionSeverity::Nominal);
    assert!(ledger.required_fields_present);
    assert!(ledger.missing_required_fields.is_empty());
    assert!(
        ledger
            .lock_hotspots
            .iter()
            .any(|row| row.key == "runtime_state")
    );
    let lock_hotspot = ledger
        .lock_hotspots
        .iter()
        .find(|row| row.key == "runtime_state")
        .expect("runtime_state lock hotspot");
    assert_eq!(lock_hotspot.wait_percentile_sample_count, Some(128));
    assert_eq!(lock_hotspot.hold_percentile_sample_count, Some(128));
    assert!(
        lock_hotspot
            .evidence
            .contains("wait_percentile_sample_count=128")
    );
    assert!(
        lock_hotspot
            .evidence
            .contains("hold_percentile_sample_count=128")
    );
    assert!(ledger.region_hotspots.iter().any(|row| {
        row.kind == SwarmContentionHotspotKind::Region
            && row.owner_surface.contains("src/lab/swarm_replay.rs")
    }));
    assert!(text.contains("verdict: Pass"));
    assert!(text.contains("top_hotspots:"));
    assert!(text.contains("wait_percentile_sample_count=128"));
    assert!(text.contains("hold_percentile_sample_count=128"));
}

#[test]
fn percentile_horizon_survives_projection_and_legacy_rows_remain_compatible() {
    let snapshot = asupersync::sync::LockMetricsSnapshot {
        name: "retained_suffix_lock",
        acquisitions: 21,
        contentions: 3,
        wait_ns: 420_000,
        hold_ns: 210_000,
        max_wait_ns: 90_000,
        max_hold_ns: 45_000,
        p95_wait_ns: 70_000,
        p999_wait_ns: 90_000,
        wait_percentile_sample_count: 17,
        p95_hold_ns: 35_000,
        p999_hold_ns: 45_000,
        hold_percentile_sample_count: 13,
        instrumentation_mode: "exact_retained_samples",
    };
    let metric = SwarmContentionLockMetric::from_lock_metrics_snapshot(&snapshot);
    assert_eq!(metric.wait_percentile_sample_count, Some(17));
    assert_eq!(metric.hold_percentile_sample_count, Some(13));

    let mut input = healthy_input();
    input.lock_metrics = vec![metric.clone()];
    let ledger = build_swarm_contention_heatmap(&input);
    let hotspot = ledger
        .lock_hotspots
        .iter()
        .find(|row| row.key == "retained_suffix_lock")
        .expect("projected live lock hotspot");
    assert_eq!(hotspot.wait_percentile_sample_count, Some(17));
    assert_eq!(hotspot.hold_percentile_sample_count, Some(13));

    let mut legacy_hotspot_json = serde_json::to_value(hotspot).expect("serialize hotspot");
    let legacy_hotspot_object = legacy_hotspot_json.as_object_mut().expect("hotspot object");
    legacy_hotspot_object.remove("wait_percentile_sample_count");
    legacy_hotspot_object.remove("hold_percentile_sample_count");
    let legacy_hotspot: asupersync::lab::SwarmContentionHotSpot =
        serde_json::from_value(legacy_hotspot_json).expect("deserialize legacy hotspot");
    assert_eq!(legacy_hotspot.wait_percentile_sample_count, None);
    assert_eq!(legacy_hotspot.hold_percentile_sample_count, None);
    let reserialized_hotspot =
        serde_json::to_value(legacy_hotspot).expect("re-serialize legacy hotspot");
    let reserialized_hotspot_object = reserialized_hotspot.as_object().expect("hotspot object");
    assert!(!reserialized_hotspot_object.contains_key("wait_percentile_sample_count"));
    assert!(!reserialized_hotspot_object.contains_key("hold_percentile_sample_count"));

    let mut legacy_json = serde_json::to_value(metric).expect("serialize lock metric");
    let legacy_object = legacy_json.as_object_mut().expect("lock metric object");
    legacy_object.remove("wait_percentile_sample_count");
    legacy_object.remove("hold_percentile_sample_count");
    let legacy_metric: SwarmContentionLockMetric =
        serde_json::from_value(legacy_json).expect("deserialize legacy lock metric");
    assert_eq!(legacy_metric.wait_percentile_sample_count, None);
    assert_eq!(legacy_metric.hold_percentile_sample_count, None);
    let reserialized =
        serde_json::to_value(legacy_metric).expect("re-serialize legacy lock metric");
    let reserialized_object = reserialized.as_object().expect("lock metric object");
    assert!(!reserialized_object.contains_key("wait_percentile_sample_count"));
    assert!(!reserialized_object.contains_key("hold_percentile_sample_count"));
}

#[test]
fn swarm_contention_heatmap_scheduler_hot_lane_routes_to_scheduler_owner() {
    let mut input = healthy_input();
    input.scheduler_lanes = vec![lane_metric("ready", 120_000, 300_000, 40, 80)];

    let ledger = build_swarm_contention_heatmap(&input);

    assert_eq!(ledger.verdict, SwarmContentionHeatmapVerdict::Degraded);
    assert_eq!(ledger.scheduler_lane_hotspots[0].key, "ready");
    assert_eq!(
        ledger.scheduler_lane_hotspots[0].kind,
        SwarmContentionHotspotKind::SchedulerLane
    );
    assert_eq!(
        ledger.scheduler_lane_hotspots[0].severity,
        SwarmContentionSeverity::Warning
    );
    assert!(
        ledger
            .routing_hints
            .iter()
            .any(|hint| hint.contains("src/runtime/scheduler/three_lane.rs"))
    );
}

#[test]
fn swarm_contention_heatmap_lock_hotspot_ranks_lock_waits_first() {
    let mut input = healthy_input();
    input.lock_metrics = vec![
        lock_metric("runtime_state", 2, 10_000, 20_000),
        lock_metric("tasks_queue", 40, 600_000, 1_200_000),
    ];

    let ledger = build_swarm_contention_heatmap(&input);

    assert_eq!(ledger.verdict, SwarmContentionHeatmapVerdict::Degraded);
    assert_eq!(ledger.max_severity, SwarmContentionSeverity::Critical);
    assert_eq!(ledger.lock_hotspots[0].key, "tasks_queue");
    assert_eq!(
        ledger.top_hotspots[0].kind,
        SwarmContentionHotspotKind::Lock
    );
    assert_eq!(ledger.top_hotspots[0].key, "tasks_queue");
}

#[test]
fn swarm_contention_heatmap_queue_hotspot_consumes_trace_summary_output() {
    let mut trace = healthy_trace_summary();
    trace.largest_queues.push(SwarmPressureTraceQueueHotSpot {
        scope: "region:1:ready".to_string(),
        queue_depth: 96,
        event_kind: "ready_queue_pressure".to_string(),
        route_hint: "src/runtime/scheduler/three_lane.rs".to_string(),
    });
    let mut input = healthy_input();
    input.trace_summary = Some(trace);

    let ledger = build_swarm_contention_heatmap(&input);

    assert_eq!(ledger.verdict, SwarmContentionHeatmapVerdict::Degraded);
    assert!(
        ledger
            .queue_hotspots
            .iter()
            .any(|row| row.key == "region:1:ready"
                && row.kind == SwarmContentionHotspotKind::Queue
                && row.severity == SwarmContentionSeverity::Warning)
    );
}

#[test]
fn swarm_contention_heatmap_missing_trace_or_lock_metrics_is_incomplete() {
    let mut input = healthy_input();
    input.trace_summary = None;
    input.lock_metrics.clear();

    let ledger = build_swarm_contention_heatmap(&input);

    assert_eq!(ledger.verdict, SwarmContentionHeatmapVerdict::Incomplete);
    assert!(!ledger.required_fields_present);
    assert_eq!(
        ledger.missing_required_fields,
        vec!["lock_metrics".to_string(), "trace_summary".to_string()]
    );
    assert!(
        ledger
            .routing_hints
            .iter()
            .any(|hint| hint.contains("missing contention evidence"))
    );
}

#[test]
fn swarm_contention_heatmap_incomplete_trace_never_reports_success() {
    let mut trace = healthy_trace_summary();
    trace.required_fields_present = false;
    trace.missing_required_fields = vec!["obligation_commits".to_string()];
    let mut input = healthy_input();
    input.trace_summary = Some(trace);

    let ledger = build_swarm_contention_heatmap(&input);

    assert_eq!(ledger.verdict, SwarmContentionHeatmapVerdict::Incomplete);
    assert!(
        ledger
            .missing_required_fields
            .contains(&"trace_summary.obligation_commits".to_string())
    );
}

#[test]
fn swarm_contention_heatmap_stale_baseline_fails_closed_separately() {
    let mut input = healthy_input();
    input.baseline_age_secs = 172_800;
    input.max_baseline_age_secs = 86_400;

    let ledger = build_swarm_contention_heatmap(&input);

    assert_eq!(ledger.verdict, SwarmContentionHeatmapVerdict::StaleEvidence);
    assert!(ledger.required_fields_present);
    assert!(ledger.stale_baseline);
    assert!(
        ledger
            .routing_hints
            .iter()
            .any(|hint| hint.contains("refresh baseline baseline-2026-05-30"))
    );
}
