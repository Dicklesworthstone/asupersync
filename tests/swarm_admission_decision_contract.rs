#![allow(missing_docs)]

use asupersync::cx::Cx;
use asupersync::observability::swarm_pressure_governor::SwarmWorkloadLeaseTransition;
use asupersync::observability::{
    AdmissionDecision, SwarmAdmissionOwner, SwarmPressureGovernor, SwarmPressureGovernorConfig,
    SwarmProofLaneKind, SwarmWorkloadAdmissionRequest, SwarmWorkloadPressureFeedback,
};
use asupersync::runtime::RuntimeBuilder;
use asupersync::runtime::resource_monitor::RegionPriority;
use asupersync::{Budget, LabConfig, LabRuntime, RegionId};
use serde_json::Value as JsonValue;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const ARTIFACT_PATH: &str = "artifacts/swarm_admission_decision_contract_v1.json";
const REQUIRED_INPUT_CLASSES: [&str; 6] = [
    "capacity_snapshot",
    "proof_lane_status",
    "agent_mail_reservation_pressure",
    "beads_backlog_state",
    "host_pressure_snapshot",
    "rch_admissibility",
];
const REQUIRED_DECISION_OUTPUTS: [&str; 8] = [
    "admit_full",
    "brownout_degraded_optional",
    "no_win",
    "defer_tracker_blocked",
    "fail_closed_stale_evidence",
    "fail_closed_unsupported_host_data",
    "fail_closed_malformed_input",
    "fail_closed_local_rch_fallback",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct Decision {
    decision: String,
    rule_id: String,
    issue_kind: String,
}

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn artifact() -> JsonValue {
    let path = repo_path(ARTIFACT_PATH);
    let body = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_json::from_str(&body).unwrap_or_else(|err| panic!("parse {}: {err}", path.display()))
}

fn array<'a>(value: &'a JsonValue, key: &str) -> &'a Vec<JsonValue> {
    value
        .get(key)
        .and_then(JsonValue::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string<'a>(value: &'a JsonValue, key: &str) -> &'a str {
    let item = value
        .get(key)
        .and_then(JsonValue::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!item.trim().is_empty(), "{key} must be nonempty");
    item
}

fn optional_string<'a>(value: &'a JsonValue, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(JsonValue::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn bool_value(value: &JsonValue, key: &str) -> bool {
    value
        .get(key)
        .and_then(JsonValue::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn u64_value(value: &JsonValue, key: &str) -> u64 {
    value
        .get(key)
        .and_then(JsonValue::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

fn string_set(value: &JsonValue, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn nested<'a>(value: &'a JsonValue, key: &str) -> &'a JsonValue {
    value
        .get(key)
        .unwrap_or_else(|| panic!("missing required object {key}"))
}

fn max_age_seconds(artifact: &JsonValue) -> u64 {
    u64_value(
        nested(artifact, "staleness_policy"),
        "max_source_age_seconds",
    )
}

fn has_stale_evidence(scenario: &JsonValue, max_age: u64) -> bool {
    REQUIRED_INPUT_CLASSES
        .iter()
        .filter_map(|key| scenario.get(*key))
        .any(|input| {
            input
                .get("evidence_age_seconds")
                .and_then(JsonValue::as_u64)
                .is_some_and(|age| age > max_age)
        })
}

fn expected_decision(scenario: &JsonValue) -> Decision {
    let expected = nested(scenario, "expected_decision");
    Decision {
        decision: string(expected, "decision").to_string(),
        rule_id: string(expected, "rule_id").to_string(),
        issue_kind: optional_string(expected, "issue_kind").to_string(),
    }
}

fn evaluate_scenario(
    scenario: &JsonValue,
    allowed_pressure_sources: &BTreeSet<String>,
    max_age: u64,
) -> Decision {
    if string(scenario, "input_status") == "malformed" {
        return Decision {
            decision: "fail_closed_malformed_input".to_string(),
            rule_id: "malformed-input".to_string(),
            issue_kind: "malformed_input".to_string(),
        };
    }

    let host_pressure = nested(scenario, "host_pressure_snapshot");
    let pressure_source = string(host_pressure, "pressure_source");
    if !allowed_pressure_sources.contains(pressure_source) {
        return Decision {
            decision: "fail_closed_unsupported_host_data".to_string(),
            rule_id: "unsupported-pressure-source".to_string(),
            issue_kind: "unsupported_pressure_source".to_string(),
        };
    }

    let proof_lane = nested(scenario, "proof_lane_status");
    if bool_value(proof_lane, "local_fallback_marker_detected") {
        return Decision {
            decision: "fail_closed_local_rch_fallback".to_string(),
            rule_id: "local-rch-fallback".to_string(),
            issue_kind: "local_rch_fallback".to_string(),
        };
    }

    if has_stale_evidence(scenario, max_age) {
        return Decision {
            decision: "fail_closed_stale_evidence".to_string(),
            rule_id: "stale-evidence".to_string(),
            issue_kind: "stale_evidence".to_string(),
        };
    }

    let agent_mail = nested(scenario, "agent_mail_reservation_pressure");
    let beads = nested(scenario, "beads_backlog_state");
    if bool_value(agent_mail, "tracker_reserved") || !bool_value(beads, "tracker_writable") {
        return Decision {
            decision: "defer_tracker_blocked".to_string(),
            rule_id: "tracker-blocked".to_string(),
            issue_kind: "tracker_blocked".to_string(),
        };
    }

    let rch = nested(scenario, "rch_admissibility");
    if bool_value(rch, "remote_required") && !bool_value(rch, "workers_admissible") {
        return Decision {
            decision: "no_win".to_string(),
            rule_id: "remote-required-no-worker".to_string(),
            issue_kind: "remote_worker_unavailable".to_string(),
        };
    }

    if bool_value(host_pressure, "disk_critical")
        || u64_value(host_pressure, "memory_pressure_bps") >= 9_000
        || u64_value(host_pressure, "cpu_saturation_bps") >= 9_000
    {
        return Decision {
            decision: "brownout_degraded_optional".to_string(),
            rule_id: "brownout-pressure".to_string(),
            issue_kind: "brownout_pressure".to_string(),
        };
    }

    Decision {
        decision: "admit_full".to_string(),
        rule_id: "admit-full".to_string(),
        issue_kind: String::new(),
    }
}

fn scenario_by_id<'a>(artifact: &'a JsonValue, scenario_id: &str) -> &'a JsonValue {
    array(artifact, "scenarios")
        .iter()
        .find(|scenario| {
            scenario.get("scenario_id").and_then(JsonValue::as_str) == Some(scenario_id)
        })
        .unwrap_or_else(|| panic!("missing scenario {scenario_id}"))
}

fn run_deterministic_swarm_workload_fixture(workload_count: usize, seed: u64) -> Vec<String> {
    let mut lab = LabRuntime::new(
        LabConfig::new(seed)
            .worker_count(4)
            .max_steps((workload_count as u64).saturating_mul(64).max(1024)),
    );
    assert_eq!(
        lab.run_until_quiescent(),
        0,
        "empty lab harness should start quiescent before workload admission simulation"
    );

    let runtime = std::sync::Arc::new(
        RuntimeBuilder::new()
            .worker_threads(1)
            .build()
            .expect("create test runtime"),
    );
    let mut config = SwarmPressureGovernorConfig::default();
    config.max_regions_per_instance = workload_count + 8;
    config.default_workload_lease_ttl = Duration::from_secs(20 * 60);
    config.workload_feedback_max_age = Duration::from_secs(20 * 60);
    config.workload_lease_starvation_aging_step = Duration::from_secs(60);
    let governor =
        SwarmPressureGovernor::new_without_pressure_governor(config, runtime.resource_monitor());
    let cx = Cx::for_testing_with_budget(Budget::INFINITE);
    let deadline = Instant::now() + Duration::from_secs(15 * 60);
    let mut region_ids = Vec::with_capacity(workload_count);

    for index in 0..workload_count {
        let priority = match index % 5 {
            0 => RegionPriority::Critical,
            1 => RegionPriority::High,
            2 => RegionPriority::Normal,
            3 => RegionPriority::Low,
            _ => RegionPriority::BestEffort,
        };
        let proof_lane = match index % 7 {
            0 => SwarmProofLaneKind::ReleaseProof,
            1 => SwarmProofLaneKind::CargoCheckAllTargets,
            2 => SwarmProofLaneKind::ClippyAllTargets,
            3 => SwarmProofLaneKind::CargoCheckLib,
            4 => SwarmProofLaneKind::Test,
            5 => SwarmProofLaneKind::RustfmtCheck,
            _ => SwarmProofLaneKind::SourceOnly,
        };
        let workload_id = format!("asw-lab-{workload_count}-{index:03}");
        let request = SwarmWorkloadAdmissionRequest::new(
            workload_id.clone(),
            SwarmAdmissionOwner::new("DustyGorge")
                .with_bead_id("asupersync-oxqrae.2")
                .with_reservation_scope(format!("asw-lab/{workload_count}/{index:03}")),
        )
        .with_priority(priority)
        .with_proof_lane(proof_lane)
        .with_declared_resources(
            Some(1024 + index as u64),
            Some(10 + (index % 17) as u64),
            Some(1 + (index % 11) as u64),
        )
        .with_deadline(deadline)
        .with_cancellation_budget(Duration::from_millis(250 + (index % 13) as u64 * 10));

        let decision = governor
            .check_workload_admission(&cx, &request)
            .expect("workload admission should classify");
        assert!(matches!(decision.decision, AdmissionDecision::Admit));
        assert!(
            decision
                .decision_receipt
                .replay_pointer
                .starts_with("swarm-admission://decision/")
        );
        assert_eq!(
            decision
                .decision_receipt
                .peer_pressure_backpressure_threshold_scaled,
            8000
        );
        assert!(
            !decision
                .decision_receipt
                .peer_pressure_backpressure_triggered
        );
        assert_eq!(
            decision
                .decision_receipt
                .workload_feedback_backpressure_threshold_scaled,
            8000
        );
        assert!(
            !decision
                .decision_receipt
                .workload_feedback_backpressure_triggered
        );

        let region_id = RegionId::new_for_test(
            70 + u32::try_from(workload_count).expect("fixture count fits u32"),
            u32::try_from(index + 1).expect("fixture index fits u32"),
        );
        region_ids.push(region_id);
        governor.register_region_envelope(
            region_id,
            decision
                .envelope
                .clone()
                .expect("admitted workload should include an envelope"),
        );
        let lease = governor
            .acquire_workload_lease(region_id, &request, &decision)
            .expect("admitted workload should acquire a lease");
        if index % 2 == 0 {
            governor
                .commit_workload_lease(lease.lease_id)
                .expect("even-indexed workload lease should commit");
        }

        governor
            .record_workload_pressure_feedback(
                SwarmWorkloadPressureFeedback::new(
                    workload_id,
                    SwarmAdmissionOwner::new("DustyGorge").with_bead_id("asupersync-oxqrae.2"),
                    proof_lane,
                )
                .with_pressures(
                    ((index * 37 + workload_count) % 100) as f64 / 100.0,
                    ((index * 17 + workload_count) % 100) as f64 / 100.0,
                    ((index * 23 + workload_count) % 100) as f64 / 100.0,
                    ((index * 29 + workload_count) % 100) as f64 / 100.0,
                    ((index * 31 + workload_count) % 100) as f64 / 100.0,
                ),
            )
            .expect("deterministic workload feedback should record");
    }

    let schedule = governor.workload_lease_schedule();
    assert_eq!(
        schedule.len(),
        workload_count,
        "schedule must contain exactly one bounded row per live workload lease"
    );
    let mut last_effective_priority_rank = 0;
    for (expected_rank, entry) in schedule.iter().enumerate() {
        assert_eq!(entry.scheduling_rank, expected_rank as u64);
        assert!(
            entry.effective_priority_rank >= last_effective_priority_rank,
            "effective priority ranks must be monotonic to avoid priority inversion: {} after {}",
            entry.effective_priority_rank,
            last_effective_priority_rank
        );
        last_effective_priority_rank = entry.effective_priority_rank;
        assert!(entry.pressure_feedback_present);
        assert!(
            entry.reason.contains("dominant_pressure_source="),
            "live workload lease should expose the dominant pressure source in its schedule reason"
        );
        assert!(
            entry.reason.contains("workload_pressure_deferral="),
            "live workload lease should expose workload pressure deferral in its schedule reason"
        );
        let workload_index = entry
            .workload_id
            .rsplit('-')
            .next()
            .expect("fixture workload id should end with an index")
            .parse::<usize>()
            .expect("fixture workload index should parse");
        let expected_cancellation_budget_ms = 250 + (workload_index % 13) as u64 * 10;
        assert_eq!(
            entry.cancellation_budget_ms,
            Some(expected_cancellation_budget_ms)
        );
        assert!(
            entry.reason.contains(&format!(
                "cancellation_budget_ms={expected_cancellation_budget_ms}"
            )),
            "live workload lease should expose the cancellation budget in its schedule reason"
        );
        assert!(
            entry
                .replay_pointer
                .starts_with("swarm-workload-lease://lease/")
        );
        assert!(
            entry.time_to_expiry_ms > 0,
            "live workload lease should expose a structured time-to-expiry field"
        );
        assert!(entry.reason.contains("workload_id=asw-lab-"));
    }

    let metrics = governor.metrics();
    assert_eq!(metrics.active_region_count, workload_count as u64);
    assert_eq!(metrics.active_workload_lease_count, workload_count as u64);
    assert_eq!(metrics.terminal_workload_lease_count, 0);
    assert_eq!(
        metrics.live_workload_feedback_reports,
        workload_count as u64
    );
    let live_audit = governor.workload_lease_audit_snapshot();
    assert_eq!(live_audit.live_lease_count, workload_count as u64);
    assert_eq!(live_audit.terminal_lease_count, 0);
    assert_eq!(live_audit.live_unregistered_region_count, 0);
    assert_eq!(live_audit.live_expired_count, 0);
    assert_eq!(
        live_audit.duplicate_live_owner_agent_count,
        workload_count.saturating_sub(1) as u64
    );
    assert_eq!(
        live_audit.duplicate_live_bead_id_count,
        workload_count.saturating_sub(1) as u64
    );
    assert!(
        !live_audit.leak_detected,
        "deterministic live workload fixture should be leak-free: {}",
        live_audit.reason
    );

    let fingerprint = schedule
        .iter()
        .map(|entry| {
            format!(
                "{}|{}|{}|{:?}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                entry.scheduling_rank,
                entry.workload_id,
                entry.proof_lane.as_str(),
                entry.priority,
                entry.effective_priority_rank,
                entry.dominant_pressure_source.as_str(),
                entry.workload_pressure_deferral,
                entry.cancellation_budget_ms.unwrap_or(0),
                entry.queue_pressure_scaled,
                entry.disk_io_pressure_scaled,
                entry.rch_queue_pressure_scaled,
                entry.validation_frontier_pressure_scaled,
                entry.cancellation_tail_pressure_scaled
            )
        })
        .collect();

    for region_id in region_ids {
        let receipts = governor.release_region_workload_leases(region_id);
        assert_eq!(receipts.len(), 1);
        assert_eq!(
            receipts[0].transition,
            SwarmWorkloadLeaseTransition::ReleasedByRegionClose
        );
        assert!(
            receipts[0]
                .replay_pointer
                .starts_with("swarm-workload-lease://lease/")
        );
        assert!(
            receipts[0]
                .replay_pointer
                .ends_with("/transition/released_by_region_close")
        );
        assert!(
            governor.unregister_region_envelope(region_id).is_some(),
            "region envelope should be removed after region-close lease release"
        );
    }
    let metrics = governor.metrics();
    assert_eq!(metrics.active_region_count, 0);
    assert_eq!(metrics.active_workload_lease_count, 0);
    assert_eq!(metrics.terminal_workload_lease_count, workload_count as u64);
    assert_eq!(metrics.live_workload_feedback_reports, 0);
    let terminal_audit = governor.workload_lease_audit_snapshot();
    assert_eq!(terminal_audit.live_lease_count, 0);
    assert_eq!(terminal_audit.terminal_lease_count, workload_count as u64);
    assert_eq!(terminal_audit.terminal_missing_terminal_at_count, 0);
    assert_eq!(terminal_audit.duplicate_live_owner_agent_count, 0);
    assert_eq!(terminal_audit.duplicate_live_bead_id_count, 0);
    assert!(
        !terminal_audit.leak_detected,
        "deterministic terminal workload fixture should be leak-free: {}",
        terminal_audit.reason
    );
    assert_eq!(lab.run_until_quiescent(), 0);

    fingerprint
}

#[test]
fn artifact_declares_schema_sources_and_report_only_safety() {
    let artifact = artifact();
    assert_eq!(
        artifact.get("schema_version").and_then(JsonValue::as_str),
        Some("swarm-admission-decision-contract-v1")
    );
    assert_eq!(
        artifact.get("bead_id").and_then(JsonValue::as_str),
        Some("asupersync-vjc3pv.2")
    );
    assert_eq!(
        artifact.get("capability_id").and_then(JsonValue::as_str),
        Some("deterministic_swarm_admission_decision")
    );

    for path_key in ["artifact_path", "contract_test"] {
        let path = string(&artifact, path_key);
        assert!(
            repo_path(path).is_file(),
            "{path_key} path must exist: {path}"
        );
    }

    let side_effect_policy = nested(&artifact, "side_effect_policy");
    assert_eq!(string(side_effect_policy, "mode"), "report_only");
    for key in [
        "beads_mutation_allowed",
        "agent_mail_mutation_allowed",
        "filesystem_cleanup_allowed",
        "cargo_execution_allowed",
    ] {
        assert!(!bool_value(side_effect_policy, key), "{key} must be false");
    }

    for forbidden in string_set(&artifact, "forbidden_command_fragments") {
        assert!(
            !forbidden.trim().is_empty(),
            "forbidden fragment must be nonempty"
        );
    }
}

#[test]
fn scenario_matrix_covers_required_input_classes_and_decision_outputs() {
    let artifact = artifact();
    assert_eq!(
        string_set(&artifact, "required_input_classes"),
        REQUIRED_INPUT_CLASSES
            .into_iter()
            .map(String::from)
            .collect()
    );
    assert_eq!(
        string_set(&artifact, "required_decision_outputs"),
        REQUIRED_DECISION_OUTPUTS
            .into_iter()
            .map(String::from)
            .collect()
    );

    let mut covered_decisions = BTreeSet::new();
    for scenario in array(&artifact, "scenarios") {
        let scenario_id = string(scenario, "scenario_id");
        let expected = expected_decision(scenario);
        covered_decisions.insert(expected.decision.to_string());
        if string(scenario, "input_status") == "complete" {
            for key in REQUIRED_INPUT_CLASSES {
                assert!(
                    scenario.get(key).is_some(),
                    "{scenario_id} missing required input class {key}"
                );
            }
        }
    }

    assert_eq!(
        covered_decisions,
        REQUIRED_DECISION_OUTPUTS
            .into_iter()
            .map(String::from)
            .collect(),
        "scenario matrix must cover every decision output"
    );
}

#[test]
fn deterministic_precedence_maps_inputs_to_expected_decisions() {
    let artifact = artifact();
    let allowed_sources = string_set(&artifact, "allowed_pressure_sources");
    let max_age = max_age_seconds(&artifact);
    let priorities = array(&artifact, "decision_rules")
        .iter()
        .map(|rule| {
            (
                u64_value(rule, "priority"),
                string(rule, "rule_id").to_string(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        priorities.len(),
        array(&artifact, "decision_rules").len(),
        "decision rule priorities must be unique"
    );

    for scenario in array(&artifact, "scenarios") {
        assert_eq!(
            evaluate_scenario(scenario, &allowed_sources, max_age),
            expected_decision(scenario),
            "{} must follow the deterministic precedence ladder",
            string(scenario, "scenario_id")
        );
    }
}

#[test]
fn brownout_and_no_win_decisions_require_receipts() {
    let artifact = artifact();
    for scenario in array(&artifact, "scenarios") {
        let scenario_id = string(scenario, "scenario_id");
        match expected_decision(scenario).decision.as_str() {
            "brownout_degraded_optional" => {
                let receipt = nested(scenario, "brownout_receipt");
                assert!(
                    !string(receipt, "receipt_id").is_empty(),
                    "{scenario_id} brownout receipt id"
                );
                assert!(
                    !array(receipt, "degraded_optional_surfaces").is_empty(),
                    "{scenario_id} must name degraded optional surfaces"
                );
                assert!(
                    !array(receipt, "preserved_surfaces").is_empty(),
                    "{scenario_id} must name preserved surfaces"
                );
                assert!(
                    string(receipt, "recovery_condition").contains("local_fallback"),
                    "{scenario_id} recovery condition must keep local fallback fail-closed"
                );
            }
            "no_win" => {
                let receipt = nested(scenario, "no_win_receipt");
                assert!(
                    !string(receipt, "receipt_id").is_empty(),
                    "{scenario_id} no-win receipt id"
                );
                assert!(
                    bool_value(receipt, "local_fallback_refused"),
                    "{scenario_id} no-win receipt must refuse local fallback"
                );
                assert!(
                    !string(receipt, "first_blocker").is_empty(),
                    "{scenario_id} no-win receipt must preserve first blocker"
                );
            }
            _ => {}
        }
    }
}

#[test]
fn stale_unsupported_malformed_and_local_fallback_cases_fail_closed() {
    let artifact = artifact();
    let cases = [
        (
            "ASWARM-ADMISSION-FAIL-STALE-EVIDENCE",
            "fail_closed_stale_evidence",
            "stale_evidence",
        ),
        (
            "ASWARM-ADMISSION-FAIL-UNSUPPORTED-HOST-DATA",
            "fail_closed_unsupported_host_data",
            "unsupported_pressure_source",
        ),
        (
            "ASWARM-ADMISSION-FAIL-MALFORMED-INPUT",
            "fail_closed_malformed_input",
            "malformed_input",
        ),
        (
            "ASWARM-ADMISSION-FAIL-LOCAL-RCH-FALLBACK",
            "fail_closed_local_rch_fallback",
            "local_rch_fallback",
        ),
    ];

    for (scenario_id, decision, issue_kind) in cases {
        let expected = expected_decision(scenario_by_id(&artifact, scenario_id));
        assert_eq!(expected.decision, decision, "{scenario_id} decision");
        assert_eq!(expected.issue_kind, issue_kind, "{scenario_id} issue");
    }
}

#[test]
fn deterministic_agent_swarm_simulates_10_50_200_workloads() {
    for workload_count in [10, 50, 200] {
        let seed = 0xA5A5_0200 + workload_count as u64;
        let first = run_deterministic_swarm_workload_fixture(workload_count, seed);
        let replay = run_deterministic_swarm_workload_fixture(workload_count, seed);
        assert_eq!(
            first, replay,
            "same seeded ASW lab fixture should replay the same schedule fingerprint \
             for {workload_count} workloads"
        );
    }
}

#[test]
fn validation_lanes_are_remote_required_and_isolated() {
    let artifact = artifact();
    let validation = nested(&artifact, "validation");
    let remote = string(validation, "remote_required_contract_test");
    assert!(
        remote.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_boldtower_swarm_admission_contract"),
        "remote proof lane must require rch remote execution and a stable target dir"
    );
    assert!(
        remote.contains(
            " cargo test -p asupersync --test swarm_admission_decision_contract -- --nocapture"
        ),
        "remote proof lane must point at the contract test"
    );
    assert!(
        string(validation, "local_fallback_policy").contains("fail-closed"),
        "validation docs must state local fallback fails closed"
    );

    for forbidden in string_set(&artifact, "forbidden_command_fragments") {
        assert!(
            !remote.contains(&forbidden),
            "remote validation command must not include forbidden fragment {forbidden}"
        );
    }
}
