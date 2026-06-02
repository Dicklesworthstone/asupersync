#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const CONTRACT_PATH: &str = "artifacts/admission_aware_runtime_pressure_atlas_contract_v1.json";
const EXPECTED_SECTIONS: [&str; 12] = [
    "lock_contention",
    "scheduler_pressure",
    "region_memory_budget_pressure",
    "spectral_wait_graph",
    "trapped_cycle_witness",
    "rch_proof_lane_admission",
    "dirty_tree_peer_ownership",
    "agent_mail_reservations",
    "br_tracker_status",
    "large_host_worker_warmth",
    "claim_boundary_labels",
    "operator_closeout_receipt",
];

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

fn contract() -> Value {
    json(CONTRACT_PATH)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn object_string<'a>(value: &'a serde_json::Map<String, Value>, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
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

fn rows_by_id<'a>(value: &'a Value, key: &str, id_key: &str) -> BTreeMap<String, &'a Value> {
    let mut rows = BTreeMap::new();
    for row in array(value, key) {
        let id = string(row, id_key).to_string();
        assert!(rows.insert(id.clone(), row).is_none(), "duplicate {id}");
    }
    rows
}

#[test]
fn contract_declares_sources_scope_and_side_effect_boundaries() {
    let contract = contract();
    assert_eq!(
        contract["contract_version"].as_str(),
        Some("admission-aware-runtime-pressure-atlas-contract-v1")
    );
    assert_eq!(
        contract["schema_version"].as_str(),
        Some("admission-aware-runtime-pressure-atlas-v1")
    );
    assert_eq!(contract["bead_id"].as_str(), Some("asupersync-bt63nr.2"));

    let source = object(&contract, "source_of_truth");
    for key in [
        "contract",
        "contract_test",
        "lock_contention_contract",
        "lock_contention_test",
        "lock_ordering_source",
        "contended_mutex_source",
        "runtime_pressure_contract",
        "runtime_pressure_test",
        "runtime_pressure_source",
        "rch_health_source",
        "spectral_health_source",
        "diagnostics_source",
        "proof_lane_input_schema",
        "proof_lane_input_test",
        "proof_lane_decision_script",
        "proof_lane_decision_test",
        "reservation_work_finder_script",
        "reservation_work_finder_test",
        "swarm_proof_lane_contract",
        "swarm_proof_lane_test",
        "swarm_proof_lane_source",
        "operator_runbook",
    ] {
        let path = object_string(source, key);
        assert!(
            repo_path(path).exists(),
            "source_of_truth.{key} must point to a live repo file: {path}"
        );
    }
    assert_eq!(
        object_string(source, "tracker_inventory_bead"),
        "asupersync-bt63nr.1"
    );

    let scope = Value::Object(object(&contract, "scope_boundary").clone());
    for key in [
        "defines_schema_only",
        "builds_runtime_snapshot",
        "starts_proof_lanes",
        "runs_cargo",
        "runs_rch",
        "mutates_beads",
        "sends_agent_mail",
        "changes_runtime_policy",
        "production_admission_default_enabled",
    ] {
        assert!(scope.get(key).is_some(), "scope boundary missing {key}");
    }
    assert!(bool_field(&scope, "defines_schema_only"));
    for key in [
        "builds_runtime_snapshot",
        "starts_proof_lanes",
        "runs_cargo",
        "runs_rch",
        "mutates_beads",
        "sends_agent_mail",
        "changes_runtime_policy",
        "production_admission_default_enabled",
    ] {
        assert!(!bool_field(&scope, key), "{key} must remain false");
    }

    let non_coverage = string_set(&scope, "non_coverage")
        .into_iter()
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    for required in [
        "real-host throughput",
        "rch fleet availability",
        "production admission",
        "scheduler regression",
        "allocator enforcement",
        "deadlock",
    ] {
        assert!(
            non_coverage.contains(required),
            "non_coverage must name {required}"
        );
    }
}

#[test]
fn schema_sections_are_complete_source_backed_and_field_owned() {
    let contract = contract();
    let declared = string_set(&contract, "required_sections");
    let expected = EXPECTED_SECTIONS
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    assert_eq!(declared, expected);

    let rows = rows_by_id(&contract, "sections", "section_id");
    assert_eq!(
        rows.keys().cloned().collect::<BTreeSet<_>>(),
        expected,
        "sections must match required_sections exactly"
    );

    for section_id in EXPECTED_SECTIONS {
        let row = rows.get(section_id).expect("section exists");
        assert!(
            !string(row, "description").is_empty(),
            "{section_id} description"
        );
        assert!(
            !string(row, "claim_boundary").is_empty(),
            "{section_id} claim boundary"
        );

        let owner = string(row, "owner_source");
        let implementation = string(row, "implementation_source");
        assert!(
            owner.starts_with("asupersync-")
                || owner.starts_with("mcp-agent-mail:")
                || repo_path(owner).exists(),
            "{section_id} owner source must be live or bead/tool-backed: {owner}"
        );
        assert!(
            implementation.starts_with("br ")
                || implementation.starts_with("mcp-agent-mail:")
                || repo_path(implementation).exists(),
            "{section_id} implementation source must be live or tool-backed: {implementation}"
        );

        let fields = string_set(row, "required_fields");
        assert!(!fields.is_empty(), "{section_id} requires fields");
        assert!(
            fields.contains("sample_freshness")
                || fields.contains("witness_freshness")
                || fields.contains("freshness_summary"),
            "{section_id} must carry freshness evidence"
        );
    }

    let field_ownership = rows_by_id(&contract, "field_ownership", "field");
    for field in [
        "sample_freshness",
        "deadlock_proven",
        "production_admission_default_enabled",
        "local_fallback_allowed",
        "worker_saturation",
        "advisory_batching_decision",
        "advisory_non_claims",
    ] {
        let row = field_ownership
            .get(field)
            .unwrap_or_else(|| panic!("field ownership missing {field}"));
        assert!(!string(row, "owner_source").is_empty());
        assert!(!string(row, "description").is_empty());
    }
}

#[test]
fn freshness_policy_fails_closed_for_missing_stale_or_malformed_inputs() {
    let contract = contract();
    let policy = Value::Object(object(&contract, "freshness_policy").clone());
    assert!(bool_field(&policy, "required_for_all_external_rows"));
    assert_eq!(
        string(&policy, "stale_or_missing_default_outcome"),
        "stale_evidence"
    );
    assert_eq!(
        string(&policy, "malformed_default_outcome"),
        "validation_blocked"
    );
    assert_eq!(
        string(&policy, "unsupported_default_outcome"),
        "validation_blocked"
    );

    let statuses = string_set(&policy, "freshness_statuses");
    assert_eq!(
        statuses,
        BTreeSet::from([
            "fresh".to_string(),
            "malformed".to_string(),
            "missing".to_string(),
            "stale".to_string(),
            "unsupported".to_string(),
        ])
    );
    assert!(
        string(&policy, "clock_source_policy").contains("provenance"),
        "clock source policy must keep wall-clock timestamps scoped to provenance"
    );
}

#[test]
fn claim_labels_prevent_deadlock_and_validation_overclaims() {
    let contract = contract();
    let labels = rows_by_id(&contract, "claim_labels", "label");
    for label in [
        "advisory",
        "replay_backed",
        "trapped_cycle_proven",
        "deadlock_proven",
        "validation_blocked",
        "stale_evidence",
    ] {
        let row = labels
            .get(label)
            .unwrap_or_else(|| panic!("missing claim label {label}"));
        assert!(!string(row, "description").is_empty());
        assert!(
            !array(row, "required_evidence").is_empty(),
            "{label} requires evidence"
        );
        assert!(
            !array(row, "forbidden_overclaims").is_empty(),
            "{label} forbids overclaims"
        );
    }

    for label in ["trapped_cycle_proven", "deadlock_proven"] {
        let evidence = string_set(labels.get(label).expect("label"), "required_evidence");
        for required in [
            "trapped_cycle_witness",
            "wait_edges",
            "held_resources",
            "replay_command",
        ] {
            assert!(
                evidence.contains(required),
                "{label} must require {required}"
            );
        }
    }

    let advisory = labels.get("advisory").expect("advisory label");
    let advisory_forbidden = string_set(advisory, "forbidden_overclaims")
        .into_iter()
        .collect::<Vec<_>>()
        .join("\n");
    assert!(advisory_forbidden.contains("deadlock proven"));
    assert!(advisory_forbidden.contains("production admission enabled"));
}

#[test]
fn large_host_profile_is_advisory_batched_and_overclaim_guarded() {
    let contract = contract();
    let section_rows = rows_by_id(&contract, "sections", "section_id");
    let section = section_rows
        .get("large_host_worker_warmth")
        .expect("large host section");
    let fields = string_set(section, "required_fields");
    for required in [
        "worker_id",
        "cpu_cores",
        "memory_bytes",
        "numa_nodes",
        "disk_headroom_bytes",
        "worker_queue_state",
        "worker_available_cores",
        "worker_available_memory_bytes",
        "cache_warmth",
        "target_dir_isolated",
        "active_project_excluded",
        "proof_lane_cost_estimate",
        "worker_saturation",
        "advisory_batching_decision",
        "advisory_batching_reason_codes",
        "advisory_batch_size_hint",
        "advisory_non_claims",
        "advisory_only",
        "sample_freshness",
    ] {
        assert!(
            fields.contains(required),
            "large host section missing {required}"
        );
    }
    assert!(
        string(section, "claim_boundary").contains("advisory"),
        "large host claim boundary must stay advisory"
    );

    let profile = object(&contract, "large_host_advisory_profile");
    assert_eq!(
        profile.get("target_cpu_cores").and_then(Value::as_u64),
        Some(64)
    );
    assert_eq!(
        profile.get("target_memory_gib").and_then(Value::as_u64),
        Some(256)
    );
    assert_eq!(
        profile.get("minimum_numa_nodes").and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        profile.get("batch_core_floor").and_then(Value::as_u64),
        Some(8)
    );
    assert_eq!(
        profile
            .get("batch_memory_floor_gib")
            .and_then(Value::as_u64),
        Some(64)
    );
    assert_eq!(
        profile
            .get("disk_headroom_floor_gib")
            .and_then(Value::as_u64),
        Some(128)
    );
    assert_eq!(
        object_string(profile, "planner_boundary"),
        "advisory_batching_only"
    );

    let profile_value = Value::Object(profile.clone());
    let non_claims = string_set(&profile_value, "non_claims");
    assert_eq!(
        non_claims,
        BTreeSet::from([
            "allocator_enforcement".to_string(),
            "production_admission_default".to_string(),
            "throughput_improvement".to_string(),
        ])
    );

    let fixture_cases = rows_by_id(&profile_value, "deterministic_fixture_cases", "case_id");
    for (case_id, expected_decision) in [
        ("large_host_admission", "prefer_warm_worker"),
        ("large_host_low_memory_queueing", "queue_low_memory"),
        ("large_host_worker_saturation", "defer_worker_saturated"),
        ("large_host_cold_cache_batching", "admit_batch"),
    ] {
        let row = fixture_cases
            .get(case_id)
            .unwrap_or_else(|| panic!("missing large-host fixture case {case_id}"));
        assert_eq!(string(row, "expected_decision"), expected_decision);
        let reason_codes = string_set(row, "required_reason_codes");
        assert!(
            reason_codes.contains("advisory_batching_only"),
            "{case_id} must remain advisory"
        );
    }
}

#[test]
fn negative_cases_cover_required_fail_closed_behaviors() {
    let contract = contract();
    let cases = rows_by_id(&contract, "negative_cases", "case_id");
    for case in [
        "deadlock_proven_without_trapped_cycle_witness",
        "spectral_warning_overclaimed_as_deadlock",
        "production_admission_implied_by_default",
        "remote_required_with_local_fallback_allowed",
        "stale_agent_mail_reservation_snapshot",
        "active_exclusive_agent_mail_conflict",
        "peer_owned_dirty_tree_overlap",
        "expired_agent_mail_reservation",
        "tracker_only_dirty_tree_change",
        "unrelated_peer_work",
        "large_host_low_memory_queueing",
        "large_host_worker_saturation_defer",
        "large_host_warm_worker_preference",
        "large_host_advisory_overclaim_guard",
    ] {
        let row = cases
            .get(case)
            .unwrap_or_else(|| panic!("missing negative case {case}"));
        assert!(row.get("input_pattern").is_some(), "{case} input pattern");
        assert!(!string(row, "expected_outcome").is_empty());
        assert!(!string(row, "required_reason_code").is_empty());
    }

    assert_eq!(
        string(
            cases
                .get("deadlock_proven_without_trapped_cycle_witness")
                .expect("deadlock case"),
            "expected_outcome"
        ),
        "validation_blocked"
    );
    assert_eq!(
        string(
            cases
                .get("production_admission_implied_by_default")
                .expect("production case"),
            "required_reason_code"
        ),
        "production_admission_must_remain_opt_in"
    );
    assert_eq!(
        string(
            cases
                .get("peer_owned_dirty_tree_overlap")
                .expect("peer overlap case"),
            "expected_outcome"
        ),
        "handoff_required"
    );
    assert_eq!(
        string(
            cases
                .get("expired_agent_mail_reservation")
                .expect("expired reservation case"),
            "expected_outcome"
        ),
        "proceed"
    );
}

#[test]
fn referenced_sources_contain_the_expected_live_contract_tokens() {
    let contract = contract();
    let source = object(&contract, "source_of_truth");

    let lock_ordering = read_repo_file(object_string(source, "lock_ordering_source"));
    for token in [
        "LockOrderAtlasSnapshot",
        "LockOrderViolation",
        "lock_order_atlas_snapshot",
    ] {
        assert!(
            lock_ordering.contains(token),
            "lock ordering missing {token}"
        );
    }

    let runtime_pressure = read_repo_file(object_string(source, "runtime_pressure_source"));
    for token in [
        "AdmissionAwareTrappedCycleWitnessRow",
        "AdmissionAwareTrappedCycleWaitEdgeRow",
        "AdmissionAwareTrappedCycleWitnessProofStatus",
        "AdmissionAwareCoordinationOverlapClass",
        "AdmissionAwareCoordinationDecision",
        "AdmissionAwareLargeHostWorkerSaturation",
        "AdmissionAwareLargeHostBatchingDecision",
        "coordination_reason_codes",
        "advisory_batching_decision",
        "advisory_non_claims",
        "active_exclusive_agent_mail_conflict",
        "peer_dirty_tree_overlap",
        "source_step_or_timestamp",
        "witness_freshness",
        "RUNTIME_PRESSURE_SNAPSHOT_SCHEMA_VERSION",
        "RUNTIME_PRESSURE_RCH_PROOF_LANE_SCHEMA_VERSION",
        "RUNTIME_PRESSURE_REGION_MEMORY_BUDGET_SCHEMA_VERSION",
        "RUNTIME_PRESSURE_ADMISSION_DECISION_SCHEMA_VERSION",
    ] {
        assert!(
            runtime_pressure.contains(token),
            "runtime pressure missing {token}"
        );
    }

    let spectral = read_repo_file(object_string(source, "spectral_health_source"));
    for token in ["EarlyWarningSeverity", "SpectralHealthReport"] {
        assert!(spectral.contains(token), "spectral source missing {token}");
    }

    let decision_script = read_repo_file(object_string(source, "proof_lane_decision_script"));
    for token in [
        "proof-lane-admission-decision-receipt-v1",
        "dry_run_only",
        "non_mutating",
    ] {
        assert!(
            decision_script.contains(token),
            "proof-lane decision script missing {token}"
        );
    }

    let swarm = read_repo_file(object_string(source, "swarm_proof_lane_source"));
    for token in [
        "SwarmProofLaneRequest",
        "SwarmProofLanePlan",
        "plan_swarm_proof_lane",
        "render_swarm_proof_lane_agent_mail_summary",
    ] {
        assert!(swarm.contains(token), "swarm proof source missing {token}");
    }
}

#[test]
fn validation_lane_is_remote_required_and_narrowly_scoped() {
    let contract = contract();
    let validation = Value::Object(object(&contract, "validation").clone());
    let command = string(&validation, "proof_command");
    for required in [
        "RCH_REQUIRE_REMOTE=1",
        "rch exec -- env",
        "CARGO_TARGET_DIR=",
        "cargo test -p asupersync --test admission_aware_runtime_pressure_atlas_contract",
    ] {
        assert!(
            command.contains(required),
            "proof command missing {required}"
        );
    }

    let non_coverage = string_set(&validation, "does_not_cover")
        .into_iter()
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    for required in [
        "runtime snapshot builder",
        "proof-lane admission planner",
        "renderer implementation",
        "rch fleet availability",
        "production runtime throughput",
    ] {
        assert!(
            non_coverage.contains(required),
            "validation non-coverage must mention {required}"
        );
    }
}
