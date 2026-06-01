#![allow(missing_docs)]

use asupersync::lab::{
    SWARM_OPERATOR_COCKPIT_REPORT_SCHEMA_VERSION, SwarmContentionHeatmapInput,
    SwarmContentionHeatmapVerdict, SwarmContentionLockMetric, SwarmContentionSchedulerLaneMetric,
    SwarmFailureInvariantClass, SwarmFailureMinimizerReport, SwarmFailureMinimizerStopReason,
    SwarmFailureMinimizerVerdict, SwarmOperatorCockpitInput, SwarmOperatorCockpitMemoryDecision,
    SwarmOperatorCockpitObligationVerdict, SwarmOperatorCockpitOutcome, SwarmProofLaneDecision,
    SwarmProofLaneRchProvenance, SwarmProofLaneRequest, SwarmReplayAdmissionDecision,
    SwarmReplayScenario, build_swarm_contention_heatmap, build_swarm_operator_cockpit_report,
    plan_swarm_proof_lane, render_swarm_operator_cockpit_text, run_swarm_replay_scenario,
    summarize_swarm_replay_trace,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/swarm_operator_cockpit_report_contract_v1.json";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn contract() -> Value {
    let raw = std::fs::read_to_string(repo_path(ARTIFACT_PATH))
        .unwrap_or_else(|error| panic!("read {ARTIFACT_PATH}: {error}"));
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {ARTIFACT_PATH}: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn replay_command() -> String {
    "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_swarm_operator_cockpit_report cargo test -p asupersync --test swarm_operator_cockpit_report_contract --features test-internals -- --nocapture".to_string()
}

fn scenario(scenario_id: &str) -> SwarmReplayScenario {
    SwarmReplayScenario {
        scenario_id: scenario_id.to_string(),
        seed: 0xC0C1_7111,
        worker_count: 3,
        cohort_count: 1,
        region_count: 3,
        tasks_per_region: 4,
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

fn trace_for(scenario: &SwarmReplayScenario) -> asupersync::lab::SwarmPressureTraceSummary {
    let replay = run_swarm_replay_scenario(scenario).expect("replay scenario");
    summarize_swarm_replay_trace(&replay)
}

fn lock_metric(name: &str, p95_wait_ns: u64, p99_wait_ns: u64) -> SwarmContentionLockMetric {
    SwarmContentionLockMetric {
        name: name.to_string(),
        acquisitions: 64,
        contentions: 1,
        wait_ns: p95_wait_ns.saturating_mul(64),
        hold_ns: 8_000,
        max_wait_ns: p99_wait_ns,
        max_hold_ns: 5_000,
        p50_wait_ns: p95_wait_ns / 4,
        p95_wait_ns,
        p99_wait_ns,
        p95_hold_ns: 2_000,
        p99_hold_ns: 5_000,
        instrumentation_mode: "cockpit_fixture".to_string(),
    }
}

fn lane_metric(
    lane_id: &str,
    p95_wait_ns: u64,
    p99_wait_ns: u64,
) -> SwarmContentionSchedulerLaneMetric {
    SwarmContentionSchedulerLaneMetric {
        lane_id: lane_id.to_string(),
        dispatched_tasks: 128,
        p50_wait_ns: p95_wait_ns / 4,
        p95_wait_ns,
        p99_wait_ns,
        queue_depth_p50: 1,
        queue_depth_p95: 2,
        queue_depth_p99: 3,
        steal_attempts: 2,
        fairness_yields: 0,
    }
}

fn contention_ledger(
    trace: asupersync::lab::SwarmPressureTraceSummary,
) -> asupersync::lab::SwarmContentionHeatmapLedger {
    build_swarm_contention_heatmap(&SwarmContentionHeatmapInput {
        ledger_id: "cockpit-contention-ledger".to_string(),
        baseline_id: Some("baseline-main-2026-06-01".to_string()),
        baseline_age_secs: 30,
        max_baseline_age_secs: 86_400,
        trace_summary: Some(trace),
        lock_metrics: vec![lock_metric("runtime_state", 8_000, 16_000)],
        scheduler_lanes: vec![lane_metric("ready", 10_000, 20_000)],
        source_trace_ids: vec!["trace-summary-cockpit-fixture".to_string()],
        proof_command: Some(replay_command()),
    })
}

fn proof_plan(
    scenario_id: &str,
    expected_head: &str,
    observed_head: &str,
    with_rch_provenance: bool,
) -> asupersync::lab::SwarmProofLanePlan {
    let target_dir = "${TMPDIR:-/tmp}/rch_target_swarm_operator_cockpit_report";
    let request = SwarmProofLaneRequest {
        lane_id: format!("{scenario_id}-cockpit-report"),
        scenario_id: scenario_id.to_string(),
        source_artifacts: vec![
            ARTIFACT_PATH.to_string(),
            "src/lab/swarm_replay.rs".to_string(),
            "tests/swarm_operator_cockpit_report_contract.rs".to_string(),
        ],
        touched_surfaces: vec![
            "src/lab/swarm_replay.rs".to_string(),
            "src/lab/mod.rs".to_string(),
            "tests/swarm_operator_cockpit_report_contract.rs".to_string(),
        ],
        command: replay_command(),
        target_dir: target_dir.to_string(),
        features: vec!["test-internals".to_string()],
        expected_artifacts: vec![
            ARTIFACT_PATH.to_string(),
            "target/lab-replay/swarm-operator-cockpit-report/proof.json".to_string(),
        ],
        timeout_secs: 1200,
        remote_required: true,
        local_fallback_authorized: false,
        expected_head: Some(expected_head.to_string()),
        observed_head: Some(observed_head.to_string()),
        rch_provenance: with_rch_provenance.then(|| SwarmProofLaneRchProvenance {
            worker_id: "rch-worker-fixture-06".to_string(),
            remote_observed: true,
            observed_head: observed_head.to_string(),
            target_dir: target_dir.to_string(),
            exit_status: Some(0),
        }),
        transcript_markers: vec![
            "remote worker rch-worker-fixture-06".to_string(),
            "test result: ok".to_string(),
        ],
        covers: vec![
            "operator_cockpit_report_contract".to_string(),
            "stable_json_release_evidence".to_string(),
        ],
        does_not_cover: vec![
            "workspace_release_health".to_string(),
            "broad_conformance".to_string(),
        ],
    };
    plan_swarm_proof_lane(&request)
}

fn healthy_input(scenario_id: &str) -> SwarmOperatorCockpitInput {
    let scenario = scenario(scenario_id);
    let trace = trace_for(&scenario);
    SwarmOperatorCockpitInput {
        report_id: format!("{scenario_id}-cockpit"),
        scenario: Some(scenario),
        trace_summary: Some(trace.clone()),
        proof_lanes: vec![proof_plan(
            scenario_id,
            "cccccccccccccccccccccccccccccccccccccccc",
            "cccccccccccccccccccccccccccccccccccccccc",
            true,
        )],
        contention_ledger: Some(contention_ledger(trace)),
        minimizer_report: None,
        memory_decision: SwarmOperatorCockpitMemoryDecision::Nominal,
        memory_decision_reason: Some("no brownout required".to_string()),
        latency_p50_ns: Some(12_000),
        latency_p95_ns: Some(25_000),
        latency_p99_ns: Some(40_000),
        latency_cv_bps: Some(320),
        source_artifacts: vec![
            ARTIFACT_PATH.to_string(),
            "src/lab/swarm_replay.rs".to_string(),
            "tests/swarm_operator_cockpit_report_contract.rs".to_string(),
        ],
        redaction_policy_id: Some("agent-mail-safe-redaction-v1".to_string()),
        secret_like_value_count: 0,
        generated_by: "swarm-operator-cockpit-contract".to_string(),
    }
}

fn minimized_failure_report(scenario: SwarmReplayScenario) -> SwarmFailureMinimizerReport {
    SwarmFailureMinimizerReport {
        schema_version: asupersync::lab::SWARM_FAILURE_MINIMIZER_SCHEMA_VERSION.to_string(),
        minimizer_id: "cockpit-minimized-failure".to_string(),
        bundle_id: "bundle-cockpit-failure".to_string(),
        original_artifact: "artifacts/swarm-failure-cockpit.json".to_string(),
        original_scenario_id: scenario.scenario_id.clone(),
        minimized_scenario: scenario,
        replay_command: Some(replay_command()),
        verdict: SwarmFailureMinimizerVerdict::Minimized,
        invariant_class: SwarmFailureInvariantClass::DeadlockOrLostWakeup,
        first_failure: "ready queue made no progress".to_string(),
        stop_reason: SwarmFailureMinimizerStopReason::InvariantPreserved,
        preserved_invariant: true,
        required_fields_present: true,
        missing_required_fields: Vec::new(),
        proof_lane_decision: Some(SwarmProofLaneDecision::Ready),
        source_trace_ids: vec!["trace-summary-cockpit-fixture".to_string()],
        redaction_policy_id: Some("agent-mail-safe-redaction-v1".to_string()),
        redaction_preserved: true,
        reduction_steps: Vec::new(),
        original_task_count: 12,
        minimized_task_count: 4,
        reduction_ratio_bps: 6666,
        owner_surface: "src/runtime/scheduler/three_lane.rs".to_string(),
        owner_bead_hint: "asupersync-vssefs.9.5-follow-up:scheduler-wakeup".to_string(),
        routing_hints: vec!["route minimized failure to scheduler wakeup owner".to_string()],
        destructive_cleanup_required: false,
        branch_or_worktree_required: false,
    }
}

#[test]
fn cockpit_artifact_is_source_backed_and_declares_outcome_contract() {
    let contract = contract();
    assert_eq!(
        contract["contract_version"].as_str(),
        Some("swarm-operator-cockpit-report-contract-v1")
    );
    assert_eq!(contract["bead_id"].as_str(), Some("asupersync-vssefs.9.6"));
    assert_eq!(
        contract["schema_version"].as_str(),
        Some(SWARM_OPERATOR_COCKPIT_REPORT_SCHEMA_VERSION)
    );

    let source = contract
        .get("source_of_truth")
        .expect("source_of_truth object");
    for key in ["contract", "contract_test", "runtime_policy_source"] {
        let path = string(source, key);
        assert!(
            repo_path(path).exists(),
            "source_of_truth.{key} must point to a live repo file: {path}"
        );
    }

    let outcomes = string_set(&contract, "required_outcomes");
    for outcome in [
        "pass",
        "degraded",
        "no_win",
        "blocked",
        "stale_evidence",
        "malformed",
        "unsupported",
    ] {
        assert!(outcomes.contains(outcome), "missing outcome {outcome}");
    }
}

#[test]
fn cockpit_healthy_run_passes_with_stable_json_and_compact_text() {
    let report = build_swarm_operator_cockpit_report(&healthy_input("cockpit-healthy"));
    let text = render_swarm_operator_cockpit_text(&report);

    eprintln!("{text}");

    assert_eq!(
        report.schema_version,
        SWARM_OPERATOR_COCKPIT_REPORT_SCHEMA_VERSION
    );
    assert_eq!(report.outcome, SwarmOperatorCockpitOutcome::Pass);
    assert!(report.required_fields_present);
    assert_eq!(report.quiescent, Some(true));
    assert_eq!(
        report.obligation_verdict,
        SwarmOperatorCockpitObligationVerdict::Clean
    );
    assert_eq!(report.ready_proof_lane_count, 1);
    assert!(report.rch_remote_provenance_observed);
    assert_eq!(
        report.contention_verdict,
        Some(SwarmContentionHeatmapVerdict::Pass)
    );
    assert!(report.redaction_preserved);
    assert!(text.contains("outcome=Pass"));
    assert!(text.contains("proof_lanes: ready=1/1 remote_observed=true"));
    assert!(text.contains("redaction: policy=agent-mail-safe-redaction-v1 preserved=true"));
    assert!(
        text.len() < 2_500,
        "Agent Mail summary too large: {}",
        text.len()
    );

    let roundtrip: asupersync::lab::SwarmOperatorCockpitReport =
        serde_json::from_str(&serde_json::to_string(&report).expect("serialize report"))
            .expect("parse report");
    assert_eq!(roundtrip, report);
}

#[test]
fn cockpit_degraded_brownout_is_explicit_but_still_publishable() {
    let mut input = healthy_input("cockpit-brownout");
    input.memory_decision = SwarmOperatorCockpitMemoryDecision::BrownoutOptional;
    input.memory_decision_reason = Some("shed optional heatmap rows under memory cap".to_string());

    let report = build_swarm_operator_cockpit_report(&input);

    assert_eq!(report.outcome, SwarmOperatorCockpitOutcome::Degraded);
    assert!(report.required_fields_present);
    assert_eq!(
        report.memory_decision,
        SwarmOperatorCockpitMemoryDecision::BrownoutOptional
    );
}

#[test]
fn cockpit_no_win_and_unsupported_outcomes_are_distinct() {
    let mut no_win = healthy_input("cockpit-no-win");
    no_win.memory_decision = SwarmOperatorCockpitMemoryDecision::NoWin;
    no_win.memory_decision_reason =
        Some("memory cap leaves no admissible core surface".to_string());

    let no_win_report = build_swarm_operator_cockpit_report(&no_win);

    assert_eq!(no_win_report.outcome, SwarmOperatorCockpitOutcome::NoWin);

    let mut unsupported = healthy_input("cockpit-unsupported");
    unsupported.memory_decision = SwarmOperatorCockpitMemoryDecision::Unsupported;
    unsupported.memory_decision_reason =
        Some("source evidence predates cockpit memory policy".to_string());

    let unsupported_report = build_swarm_operator_cockpit_report(&unsupported);

    assert_eq!(
        unsupported_report.outcome,
        SwarmOperatorCockpitOutcome::Unsupported
    );
}

#[test]
fn cockpit_incomplete_trace_rejects_missing_quiescence_and_obligations() {
    let mut input = healthy_input("cockpit-incomplete-trace");
    let trace = input.trace_summary.as_mut().expect("trace");
    trace.required_fields_present = false;
    trace.missing_required_fields = vec!["quiescence_verdict".to_string()];
    trace.obligations.fields_present = false;

    let report = build_swarm_operator_cockpit_report(&input);

    assert_eq!(report.outcome, SwarmOperatorCockpitOutcome::Malformed);
    assert!(!report.required_fields_present);
    assert!(
        report
            .missing_required_fields
            .contains(&"trace_summary.quiescence_verdict".to_string())
    );
    assert!(
        report
            .missing_required_fields
            .contains(&"trace_summary.obligation_verdict".to_string())
    );
    assert_eq!(
        report.obligation_verdict,
        SwarmOperatorCockpitObligationVerdict::Missing
    );
}

#[test]
fn cockpit_missing_scenario_id_is_malformed() {
    let mut input = healthy_input("cockpit-missing-scenario-id");
    input.scenario = Some(scenario(""));

    let report = build_swarm_operator_cockpit_report(&input);

    assert_eq!(report.outcome, SwarmOperatorCockpitOutcome::Malformed);
    assert!(
        report
            .missing_required_fields
            .contains(&"scenario.scenario_id".to_string())
    );
}

#[test]
fn cockpit_minimized_failure_fixture_degrades_and_routes_owner() {
    let mut input = healthy_input("cockpit-minimized-failure");
    let minimizer_scenario = input.scenario.as_ref().expect("scenario").clone();
    input.minimizer_report = Some(minimized_failure_report(minimizer_scenario));

    let report = build_swarm_operator_cockpit_report(&input);

    assert_eq!(report.outcome, SwarmOperatorCockpitOutcome::Degraded);
    assert_eq!(
        report.minimizer_verdict,
        Some(SwarmFailureMinimizerVerdict::Minimized)
    );
    assert_eq!(
        report.first_invariant_violation.as_deref(),
        Some("ready queue made no progress")
    );
    assert_eq!(
        report.next_owner_bead,
        "asupersync-vssefs.9.5-follow-up:scheduler-wakeup"
    );
}

#[test]
fn cockpit_stale_proof_head_fails_closed_as_stale_evidence() {
    let mut input = healthy_input("cockpit-stale-proof");
    input.proof_lanes = vec![proof_plan(
        "cockpit-stale-proof",
        "dddddddddddddddddddddddddddddddddddddddd",
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        true,
    )];

    let report = build_swarm_operator_cockpit_report(&input);

    assert_eq!(report.outcome, SwarmOperatorCockpitOutcome::StaleEvidence);
    assert_eq!(
        report.stale_proof_lane_ids,
        vec!["cockpit-stale-proof-cockpit-report".to_string()]
    );
}

#[test]
fn cockpit_missing_remote_rch_provenance_is_blocked_not_green() {
    let mut input = healthy_input("cockpit-missing-rch");
    input.proof_lanes = vec![proof_plan(
        "cockpit-missing-rch",
        "ffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffff",
        false,
    )];

    let report = build_swarm_operator_cockpit_report(&input);

    assert_eq!(report.outcome, SwarmOperatorCockpitOutcome::Blocked);
    assert!(!report.required_fields_present);
    assert!(
        report
            .missing_required_fields
            .contains(&"proof_lanes.remote_provenance".to_string())
    );
    assert_eq!(
        report.blocked_proof_lane_ids,
        vec!["cockpit-missing-rch-cockpit-report".to_string()]
    );
}

#[test]
fn cockpit_unredacted_secret_like_values_are_malformed() {
    let mut input = healthy_input("cockpit-redaction-failure");
    input.secret_like_value_count = 1;

    let report = build_swarm_operator_cockpit_report(&input);

    assert_eq!(report.outcome, SwarmOperatorCockpitOutcome::Malformed);
    assert!(!report.redaction_preserved);
    assert!(
        report
            .missing_required_fields
            .contains(&"redaction.secret_like_values".to_string())
    );
}
