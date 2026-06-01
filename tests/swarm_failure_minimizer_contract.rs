#![allow(missing_docs)]

use asupersync::lab::{
    SWARM_FAILURE_MINIMIZER_SCHEMA_VERSION, SwarmFailureBundle, SwarmFailureInvariantClass,
    SwarmFailureMinimizerInput, SwarmFailureMinimizerReport, SwarmFailureMinimizerStopReason,
    SwarmFailureMinimizerVerdict, SwarmPressureTraceDrainHotSpot,
    SwarmPressureTraceObligationLeakSuspect, SwarmPressureTraceQueueHotSpot,
    SwarmPressureTraceVerdict, SwarmProofLaneDecision, SwarmProofLaneRchProvenance,
    SwarmProofLaneRequest, SwarmReplayAdmissionDecision, SwarmReplayScenario,
    minimize_swarm_failure, plan_swarm_proof_lane, render_swarm_failure_minimizer_text,
    run_swarm_replay_scenario, summarize_swarm_replay_trace,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/swarm_failure_minimizer_contract_v1.json";

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
    "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_swarm_failure_minimizer cargo test -p asupersync --test swarm_failure_minimizer_contract --features test-internals -- --nocapture".to_string()
}

fn base_scenario(scenario_id: &str) -> SwarmReplayScenario {
    SwarmReplayScenario {
        scenario_id: scenario_id.to_string(),
        seed: 0xFA11_5EED,
        worker_count: 4,
        cohort_count: 2,
        region_count: 8,
        tasks_per_region: 16,
        yields_per_task: 4,
        yield_jitter: 1,
        channel_capacity: 32,
        messages_per_task: 2,
        semaphore_permits_per_task: 1,
        pool_slots_per_task: 1,
        obligations_per_task: 2,
        timer_ticks_per_task: 1,
        cancellation_tree_depth: 3,
        artifact_bytes_per_task: 64,
        region_task_admission_limit: None,
        region_over_limit_decision: SwarmReplayAdmissionDecision::Shed,
        region_memory_bytes_per_task: 1024,
        region_queue_depth_units_per_task: 1,
        region_blocking_pool_units_per_task: 1,
        region_cleanup_poll_quota_per_task: 1,
        cancel_after_steps: Some(8),
        max_steps: 5_000,
    }
}

fn minimal_scenario(scenario_id: &str) -> SwarmReplayScenario {
    SwarmReplayScenario {
        scenario_id: scenario_id.to_string(),
        seed: 0xFA11_5EED,
        worker_count: 1,
        cohort_count: 1,
        region_count: 1,
        tasks_per_region: 1,
        yields_per_task: 1,
        yield_jitter: 0,
        channel_capacity: 1,
        messages_per_task: 1,
        semaphore_permits_per_task: 1,
        pool_slots_per_task: 1,
        obligations_per_task: 1,
        timer_ticks_per_task: 1,
        cancellation_tree_depth: 1,
        artifact_bytes_per_task: 16,
        region_task_admission_limit: None,
        region_over_limit_decision: SwarmReplayAdmissionDecision::Shed,
        region_memory_bytes_per_task: 256,
        region_queue_depth_units_per_task: 1,
        region_blocking_pool_units_per_task: 1,
        region_cleanup_poll_quota_per_task: 1,
        cancel_after_steps: None,
        max_steps: 64,
    }
}

fn trace_for(
    scenario: &SwarmReplayScenario,
    invariant_class: SwarmFailureInvariantClass,
) -> asupersync::lab::SwarmPressureTraceSummary {
    let replay = run_swarm_replay_scenario(scenario).expect("replay scenario");
    let mut trace = summarize_swarm_replay_trace(&replay);
    trace.verdict = SwarmPressureTraceVerdict::Fail;
    trace.required_fields_present = true;
    trace.missing_required_fields.clear();
    trace.first_invariant_violation = Some(
        match invariant_class {
            SwarmFailureInvariantClass::CancellationStorm => "cancel loser drain exceeded budget",
            SwarmFailureInvariantClass::DeadlockOrLostWakeup => "ready queue made no progress",
            SwarmFailureInvariantClass::ObligationLeak => "obligation unresolved at close",
            SwarmFailureInvariantClass::AdmissionFailure => "admission shed required work",
            SwarmFailureInvariantClass::QueuePressure => "ready queue pressure exceeded bound",
            SwarmFailureInvariantClass::InvariantViolation => "region close without quiescence",
        }
        .to_string(),
    );
    trace
        .routing_hints
        .push(format!("fixture route for {:?}", invariant_class));
    trace
}

fn ready_proof_plan(scenario_id: &str) -> asupersync::lab::SwarmProofLanePlan {
    let request = SwarmProofLaneRequest {
        lane_id: format!("{scenario_id}-failure-minimizer"),
        scenario_id: scenario_id.to_string(),
        source_artifacts: vec![
            ARTIFACT_PATH.to_string(),
            "src/lab/swarm_replay.rs".to_string(),
            "tests/swarm_failure_minimizer_contract.rs".to_string(),
        ],
        touched_surfaces: vec![
            "src/lab/swarm_replay.rs".to_string(),
            "src/lab/mod.rs".to_string(),
            "tests/swarm_failure_minimizer_contract.rs".to_string(),
        ],
        command: replay_command(),
        target_dir: "${TMPDIR:-/tmp}/rch_target_swarm_failure_minimizer".to_string(),
        features: vec!["test-internals".to_string()],
        expected_artifacts: vec![
            ARTIFACT_PATH.to_string(),
            "target/lab-replay/swarm-failure-minimizer/proof.json".to_string(),
        ],
        timeout_secs: 1200,
        remote_required: true,
        local_fallback_authorized: false,
        expected_head: Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()),
        observed_head: Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()),
        rch_provenance: Some(SwarmProofLaneRchProvenance {
            worker_id: "rch-worker-fixture-02".to_string(),
            remote_observed: true,
            observed_head: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            target_dir: "${TMPDIR:-/tmp}/rch_target_swarm_failure_minimizer".to_string(),
            exit_status: Some(0),
        }),
        transcript_markers: vec![
            "remote worker rch-worker-fixture-02".to_string(),
            "test result: ok".to_string(),
        ],
        covers: vec![
            "deterministic_failure_minimization".to_string(),
            "invariant_preservation_gate".to_string(),
        ],
        does_not_cover: vec![
            "workspace_release_health".to_string(),
            "broad_conformance".to_string(),
        ],
    };
    plan_swarm_proof_lane(&request)
}

fn input_for(
    scenario: SwarmReplayScenario,
    invariant_class: SwarmFailureInvariantClass,
) -> SwarmFailureMinimizerInput {
    let mut trace = trace_for(&scenario, invariant_class);
    match invariant_class {
        SwarmFailureInvariantClass::CancellationStorm => {
            trace.cancellation.cancellation_requests = 1;
            trace.cancellation.cancelled_tasks = 10;
            trace.cancellation.cancellation_drain_steps = 30;
            trace.cancellation.losers_drained = false;
            trace.region_lifecycle.non_quiescent_regions = 2;
            trace.longest_drains.push(SwarmPressureTraceDrainHotSpot {
                scope: "region:1".to_string(),
                drain_steps: 30,
                quiescent: false,
                reason: "cancel storm drain exceeded budget".to_string(),
            });
        }
        SwarmFailureInvariantClass::DeadlockOrLostWakeup => {
            trace.task_lifecycle.non_terminal_tasks = 6;
            trace.task_lifecycle.task_leaks = 6;
            trace.region_lifecycle.non_quiescent_regions = 2;
            trace.longest_drains.push(SwarmPressureTraceDrainHotSpot {
                scope: "scheduler:ready".to_string(),
                drain_steps: 144,
                quiescent: false,
                reason: "lost wakeup suspect".to_string(),
            });
        }
        SwarmFailureInvariantClass::ObligationLeak => {
            trace.obligations.unresolved_obligations = 3;
            trace
                .obligation_leak_suspects
                .push(SwarmPressureTraceObligationLeakSuspect {
                    scope: "region:2".to_string(),
                    unresolved_obligations: 3,
                    evidence: "3 obligations still open after region close".to_string(),
                    route_hint: "src/obligation/mod.rs".to_string(),
                });
        }
        SwarmFailureInvariantClass::AdmissionFailure => {
            trace.admission.combiner_or_admission_decisions = 2;
            trace.admission.shed = 1;
            trace.admission.first_rejection =
                Some("region admission limit rejected required task".to_string());
        }
        SwarmFailureInvariantClass::QueuePressure => {
            trace.queue_pressure.peak_queue_depth = 48;
            trace.queue_pressure.pressure_event_count = 10;
            trace.largest_queues.push(SwarmPressureTraceQueueHotSpot {
                scope: "region:3:ready".to_string(),
                queue_depth: 48,
                event_kind: "ready_queue_pressure".to_string(),
                route_hint: "src/runtime/scheduler/three_lane.rs".to_string(),
            });
        }
        SwarmFailureInvariantClass::InvariantViolation => {
            trace.task_lifecycle.non_terminal_tasks = 1;
            trace.region_lifecycle.non_quiescent_regions = 1;
        }
    }

    SwarmFailureMinimizerInput {
        minimizer_id: format!("{}-minimizer", scenario.scenario_id),
        failure_bundle: SwarmFailureBundle {
            bundle_id: format!("{}-bundle", scenario.scenario_id),
            original_artifact: format!("target/lab-replay/{}/failure.json", scenario.scenario_id),
            invariant_class,
            invariant_reproduced: true,
            first_failure: trace
                .first_invariant_violation
                .clone()
                .expect("fixture invariant"),
            trace_summary: Some(trace),
            proof_lane_plan: Some(ready_proof_plan(&scenario.scenario_id)),
            redaction_policy_id: Some("swarm-redaction-v1".to_string()),
            secret_like_value_count: 0,
        },
        original_scenario: scenario,
        minimum_regions: 1,
        minimum_tasks_per_region: 2,
        minimum_replay_steps: 64,
        max_reduction_passes: 4,
        source_trace_ids: vec![
            "trace-asupersync-vssefs.7".to_string(),
            "trace-asupersync-vssefs.7".to_string(),
        ],
        replay_command: Some(replay_command()),
    }
}

fn assert_minimized_common(report: &SwarmFailureMinimizerReport) {
    assert_eq!(
        report.schema_version,
        SWARM_FAILURE_MINIMIZER_SCHEMA_VERSION
    );
    assert_eq!(report.verdict, SwarmFailureMinimizerVerdict::Minimized);
    assert!(report.preserved_invariant);
    assert!(report.required_fields_present);
    assert!(report.redaction_preserved);
    assert_eq!(
        report.proof_lane_decision,
        Some(SwarmProofLaneDecision::Ready)
    );
    assert_eq!(
        report.source_trace_ids,
        vec!["trace-asupersync-vssefs.7".to_string()]
    );
    assert!(report.original_task_count > report.minimized_task_count);
    assert!(report.reduction_ratio_bps > 0);
    assert!(
        report
            .replay_command
            .as_deref()
            .is_some_and(|command| command.contains("RCH_REQUIRE_REMOTE=1 rch exec"))
    );
    assert!(!report.original_artifact.trim().is_empty());
    assert!(!report.first_failure.trim().is_empty());
    assert!(!report.owner_surface.trim().is_empty());
    assert!(!report.owner_bead_hint.trim().is_empty());
    assert!(!report.destructive_cleanup_required);
    assert!(!report.branch_or_worktree_required);
}

#[test]
fn swarm_failure_minimizer_artifact_declares_source_schema_and_boundaries() {
    let contract = contract();
    assert_eq!(
        contract["contract_version"].as_str(),
        Some("swarm-failure-minimizer-contract-v1")
    );
    assert_eq!(contract["bead_id"].as_str(), Some("asupersync-vssefs.9.5"));
    assert_eq!(
        contract["schema_version"].as_str(),
        Some(SWARM_FAILURE_MINIMIZER_SCHEMA_VERSION)
    );

    let source = contract
        .get("source_of_truth")
        .expect("source_of_truth object");
    for key in ["contract", "contract_test", "runtime_minimizer_source"] {
        let path = string(source, key);
        assert!(
            repo_path(path).exists(),
            "source_of_truth.{key} must point to a live repo file: {path}"
        );
    }
    assert_eq!(
        string(source, "runtime_input_type"),
        "asupersync::lab::SwarmFailureMinimizerInput"
    );
    assert_eq!(
        string(source, "runtime_report_type"),
        "asupersync::lab::SwarmFailureMinimizerReport"
    );
    assert_eq!(
        string(source, "runtime_minimizer"),
        "asupersync::lab::minimize_swarm_failure"
    );
}

#[test]
fn already_minimal_failure_stops_without_claiming_extra_reduction() {
    let input = input_for(
        minimal_scenario("swarm-failure-already-minimal"),
        SwarmFailureInvariantClass::InvariantViolation,
    );
    let report = minimize_swarm_failure(&input);
    let text = render_swarm_failure_minimizer_text(&report);

    assert_eq!(report.verdict, SwarmFailureMinimizerVerdict::AlreadyMinimal);
    assert_eq!(
        report.stop_reason,
        SwarmFailureMinimizerStopReason::AlreadyMinimal
    );
    assert!(report.preserved_invariant);
    assert!(report.reduction_steps.is_empty());
    assert_eq!(report.original_task_count, report.minimized_task_count);
    assert!(text.contains("verdict: AlreadyMinimal"));
    assert!(text.contains("reduction_steps:"));
}

#[test]
fn non_reproducible_failure_never_reports_minimized() {
    let mut input = input_for(
        base_scenario("swarm-failure-non-repro"),
        SwarmFailureInvariantClass::CancellationStorm,
    );
    input.failure_bundle.invariant_reproduced = false;
    input
        .failure_bundle
        .trace_summary
        .as_mut()
        .expect("trace")
        .verdict = SwarmPressureTraceVerdict::Pass;

    let report = minimize_swarm_failure(&input);

    assert_eq!(
        report.verdict,
        SwarmFailureMinimizerVerdict::NonReproducible
    );
    assert_eq!(
        report.stop_reason,
        SwarmFailureMinimizerStopReason::NonReproducible
    );
    assert!(!report.preserved_invariant);
    assert!(report.reduction_steps.is_empty());
    assert_eq!(report.minimized_scenario, input.original_scenario);
    assert!(
        report
            .routing_hints
            .iter()
            .any(|hint| hint.contains("do not mark minimized"))
    );
}

#[test]
fn cancellation_storm_minimizes_scale_and_keeps_replay_command() {
    let input = input_for(
        base_scenario("swarm-failure-cancel-storm"),
        SwarmFailureInvariantClass::CancellationStorm,
    );
    let report = minimize_swarm_failure(&input);

    assert_minimized_common(&report);
    assert_eq!(
        report.invariant_class,
        SwarmFailureInvariantClass::CancellationStorm
    );
    assert_eq!(
        report.stop_reason,
        SwarmFailureMinimizerStopReason::InvariantPreserved
    );
    assert_eq!(report.minimized_scenario.region_count, 2);
    assert_eq!(report.minimized_scenario.tasks_per_region, 5);
    assert_eq!(report.minimized_scenario.max_steps, 64);
    assert!(
        report
            .reduction_steps
            .iter()
            .any(|step| step.knob == "tasks_per_region")
    );
    assert!(report.owner_surface.contains("src/cancel"));
}

#[test]
fn deadlock_or_lost_wakeup_routes_to_scheduler_owner() {
    let input = input_for(
        base_scenario("swarm-failure-deadlock"),
        SwarmFailureInvariantClass::DeadlockOrLostWakeup,
    );
    let report = minimize_swarm_failure(&input);

    assert_minimized_common(&report);
    assert_eq!(
        report.invariant_class,
        SwarmFailureInvariantClass::DeadlockOrLostWakeup
    );
    assert_eq!(report.minimized_scenario.region_count, 2);
    assert_eq!(report.minimized_scenario.tasks_per_region, 3);
    assert!(
        report
            .owner_surface
            .contains("src/runtime/scheduler/three_lane.rs")
    );
}

#[test]
fn obligation_leak_preserves_leak_suspect_and_owner_hint() {
    let input = input_for(
        base_scenario("swarm-failure-obligation-leak"),
        SwarmFailureInvariantClass::ObligationLeak,
    );
    let report = minimize_swarm_failure(&input);

    assert_minimized_common(&report);
    assert_eq!(
        report.invariant_class,
        SwarmFailureInvariantClass::ObligationLeak
    );
    assert_eq!(report.minimized_scenario.region_count, 1);
    assert_eq!(report.minimized_scenario.tasks_per_region, 3);
    assert!(report.owner_surface.contains("src/obligation"));
    assert!(
        report
            .routing_hints
            .iter()
            .any(|hint| hint.contains("obligation"))
    );
}

#[test]
fn redaction_required_fails_closed_and_preserves_original_pointer() {
    let mut input = input_for(
        base_scenario("swarm-failure-redaction"),
        SwarmFailureInvariantClass::CancellationStorm,
    );
    input.failure_bundle.secret_like_value_count = 2;

    let report = minimize_swarm_failure(&input);

    assert_eq!(report.verdict, SwarmFailureMinimizerVerdict::Incomplete);
    assert_eq!(
        report.stop_reason,
        SwarmFailureMinimizerStopReason::RedactionRequired
    );
    assert!(!report.redaction_preserved);
    assert!(!report.preserved_invariant);
    assert_eq!(
        report.original_artifact,
        "target/lab-replay/swarm-failure-redaction/failure.json"
    );
    assert_eq!(
        report.redaction_policy_id.as_deref(),
        Some("swarm-redaction-v1")
    );
    assert!(report.reduction_steps.is_empty());
    assert!(
        report
            .routing_hints
            .iter()
            .any(|hint| hint.contains("redaction policy swarm-redaction-v1"))
    );
}

#[test]
fn schema_fields_are_source_backed_and_report_serializes_stably() {
    let contract = contract();
    let source_path = string(&contract["source_of_truth"], "runtime_minimizer_source");
    let source = std::fs::read_to_string(repo_path(source_path))
        .unwrap_or_else(|error| panic!("read {source_path}: {error}"));
    for token in [
        "SWARM_FAILURE_MINIMIZER_SCHEMA_VERSION",
        "pub struct SwarmFailureMinimizerInput",
        "pub struct SwarmFailureMinimizerReport",
        "pub fn minimize_swarm_failure",
        "pub fn render_swarm_failure_minimizer_text",
    ] {
        assert!(source.contains(token), "minimizer source missing {token}");
    }

    let input = input_for(
        base_scenario("swarm-failure-serializes"),
        SwarmFailureInvariantClass::QueuePressure,
    );
    let value = serde_json::to_value(minimize_swarm_failure(&input)).expect("report to JSON");
    let object = value.as_object().expect("report JSON object");
    for field in string_set(&contract["schema"], "required_report_fields") {
        assert!(object.contains_key(&field), "report JSON missing {field}");
    }
}
