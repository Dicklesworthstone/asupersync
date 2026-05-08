//! Contract-backed proofs for the capability budget planner.

use asupersync::runtime::{RegionCreateError, RuntimeState};
use asupersync::{
    Budget, CapabilityBudget, CapabilityBudgetDimension, CapabilityBudgetRefusal,
    CapabilityBudgetRequirements, Cx, TaskId,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct CapabilityBudgetPlannerContract {
    contract_version: String,
    owner_bead: String,
    proof_lane: String,
    proof_command: String,
    required_dimensions: Vec<DimensionContract>,
    runtime_semantics: Vec<RuntimeSemanticContract>,
    e2e_log_contract: E2eLogContract,
    source_paths: Vec<SourcePathContract>,
}

#[derive(Debug, Deserialize)]
struct DimensionContract {
    dimension: String,
    requirement_builder: String,
    required_enum_variant: String,
}

#[derive(Debug, Deserialize)]
struct RuntimeSemanticContract {
    scenario_id: String,
    expected_status: String,
    description: String,
}

#[derive(Debug, Deserialize)]
struct E2eLogContract {
    scenario_id: String,
    required_fields: Vec<String>,
    required_admission_failure: E2eAdmissionFailureContract,
    required_final_state: E2eFinalStateContract,
}

#[derive(Debug, Deserialize)]
struct E2eAdmissionFailureContract {
    reason: String,
    dimension: String,
}

#[derive(Debug, Deserialize)]
struct E2eFinalStateContract {
    pending_obligations: usize,
    live_tasks: usize,
    runtime_quiescent: bool,
    no_obligation_leak: bool,
}

#[derive(Debug, Deserialize)]
struct SourcePathContract {
    path: String,
    required_markers: Vec<String>,
    #[serde(default)]
    forbidden_markers: Vec<String>,
}

fn contract() -> CapabilityBudgetPlannerContract {
    serde_json::from_str(include_str!(
        "../artifacts/capability_budget_planner_contract_v1.json"
    ))
    .expect("capability budget planner contract must parse")
}

fn read_source(path: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|err| panic!("failed to read {path}: {err}"))
}

fn all_requirements() -> CapabilityBudgetRequirements {
    CapabilityBudgetRequirements::new()
        .require_memory_bytes()
        .require_cpu_units()
        .require_io_bytes()
        .require_cleanup()
        .require_artifact_bytes()
}

fn requirement_for(dimension: CapabilityBudgetDimension) -> CapabilityBudgetRequirements {
    match dimension {
        CapabilityBudgetDimension::MemoryBytes => {
            CapabilityBudgetRequirements::new().require_memory_bytes()
        }
        CapabilityBudgetDimension::CpuUnits => {
            CapabilityBudgetRequirements::new().require_cpu_units()
        }
        CapabilityBudgetDimension::IoBytes => {
            CapabilityBudgetRequirements::new().require_io_bytes()
        }
        CapabilityBudgetDimension::Cleanup => CapabilityBudgetRequirements::new().require_cleanup(),
        CapabilityBudgetDimension::ArtifactBytes => {
            CapabilityBudgetRequirements::new().require_artifact_bytes()
        }
    }
}

fn dimension_from_variant(variant: &str) -> CapabilityBudgetDimension {
    match variant {
        "MemoryBytes" => CapabilityBudgetDimension::MemoryBytes,
        "CpuUnits" => CapabilityBudgetDimension::CpuUnits,
        "IoBytes" => CapabilityBudgetDimension::IoBytes,
        "Cleanup" => CapabilityBudgetDimension::Cleanup,
        "ArtifactBytes" => CapabilityBudgetDimension::ArtifactBytes,
        other => panic!("unknown capability budget dimension variant {other}"),
    }
}

fn exhausted_budget_for(dimension: CapabilityBudgetDimension) -> CapabilityBudget {
    match dimension {
        CapabilityBudgetDimension::MemoryBytes => CapabilityBudget::new().with_memory_bytes(0),
        CapabilityBudgetDimension::CpuUnits => CapabilityBudget::new().with_cpu_units(0),
        CapabilityBudgetDimension::IoBytes => CapabilityBudget::new().with_io_bytes(0),
        CapabilityBudgetDimension::Cleanup => {
            CapabilityBudget::new().with_cleanup_budget(Budget::new().with_poll_quota(0))
        }
        CapabilityBudgetDimension::ArtifactBytes => CapabilityBudget::new().with_artifact_bytes(0),
    }
}

fn json_path_exists(value: &Value, path: &str) -> bool {
    let mut current = value;
    for segment in path.split('.') {
        let Some(next) = current.get(segment) else {
            return false;
        };
        current = next;
    }
    true
}

fn required_delta(parent: Option<u64>, child: Option<u64>) -> i64 {
    let parent = parent.expect("parent budget dimension");
    let child = child.expect("child budget dimension");
    i64::try_from(child).expect("child budget fits signed delta")
        - i64::try_from(parent).expect("parent budget fits signed delta")
}

fn required_cost_delta(parent: Option<u64>, child: Option<u64>) -> i64 {
    let parent = parent.expect("parent cleanup cost quota");
    let child = child.expect("child cleanup cost quota");
    i64::try_from(child).expect("child cleanup cost fits signed delta")
        - i64::try_from(parent).expect("parent cleanup cost fits signed delta")
}

fn admission_failure_log(err: RegionCreateError) -> Value {
    match err {
        RegionCreateError::CapabilityBudgetRefused { parent, reason } => {
            let (reason, dimension) = match reason {
                CapabilityBudgetRefusal::MissingRequired(dimension) => {
                    ("MissingRequired", dimension)
                }
                CapabilityBudgetRefusal::Exhausted(dimension) => ("Exhausted", dimension),
            };
            json!({
                "parent_region_id": parent.as_u64(),
                "reason": reason,
                "dimension": dimension.as_str(),
            })
        }
        other => panic!("unexpected region admission error {other:?}"),
    }
}

fn capability_budget_e2e_log() -> Value {
    let parent_capability_budget = CapabilityBudget::new()
        .with_memory_bytes(4_096)
        .with_cpu_units(64)
        .with_io_bytes(8_192)
        .with_cleanup_budget(Budget::new().with_poll_quota(16).with_cost_quota(80))
        .with_artifact_bytes(512);
    let child_request = CapabilityBudget::new()
        .with_memory_bytes(1_024)
        .with_cpu_units(8)
        .with_cleanup_budget(Budget::new().with_poll_quota(4).with_cost_quota(20))
        .with_artifact_bytes(256);

    let mut state = RuntimeState::new();
    let root_region =
        state.create_root_region_with_capability_budget(Budget::INFINITE, parent_capability_budget);
    let child_region = state
        .create_child_region_with_capability_budget(
            root_region,
            Budget::INFINITE,
            child_request,
            all_requirements(),
        )
        .expect("child should be admitted");
    let root_budget = state
        .region_capability_budget(root_region)
        .expect("root capability budget must be stored");
    let child_budget = state
        .region_capability_budget(child_region)
        .expect("child capability budget must be stored");
    let root_cleanup = root_budget.cleanup_budget.expect("root cleanup budget");
    let child_cleanup = child_budget.cleanup_budget.expect("child cleanup budget");

    let mut refusal_state = RuntimeState::new();
    let refused_parent = refusal_state.create_root_region_with_capability_budget(
        Budget::INFINITE,
        CapabilityBudget::new().with_memory_bytes(1_024),
    );
    let admission_failure = refusal_state
        .create_child_region_with_capability_budget(
            refused_parent,
            Budget::INFINITE,
            CapabilityBudget::UNSPECIFIED,
            CapabilityBudgetRequirements::new().require_artifact_bytes(),
        )
        .expect_err("missing required artifact envelope must reject child");

    json!({
        "schema_version": "capability-budget-e2e-log-v1",
        "scenario_id": "capability-budget-e2e-log-v1",
        "root_region_id": root_region.as_u64(),
        "child_region_id": child_region.as_u64(),
        "budget_deltas": {
            "memory_bytes": {
                "parent": root_budget.memory_bytes,
                "child": child_budget.memory_bytes,
                "delta": required_delta(root_budget.memory_bytes, child_budget.memory_bytes),
                "source": "tightened"
            },
            "cpu_units": {
                "parent": root_budget.cpu_units,
                "child": child_budget.cpu_units,
                "delta": required_delta(root_budget.cpu_units, child_budget.cpu_units),
                "source": "tightened"
            },
            "io_bytes": {
                "parent": root_budget.io_bytes,
                "child": child_budget.io_bytes,
                "delta": required_delta(root_budget.io_bytes, child_budget.io_bytes),
                "source": "inherited"
            },
            "cleanup": {
                "parent_poll_quota": root_cleanup.poll_quota,
                "child_poll_quota": child_cleanup.poll_quota,
                "poll_quota_delta": i64::from(child_cleanup.poll_quota)
                    - i64::from(root_cleanup.poll_quota),
                "parent_cost_quota": root_cleanup.cost_quota,
                "child_cost_quota": child_cleanup.cost_quota,
                "cost_quota_delta": required_cost_delta(
                    root_cleanup.cost_quota,
                    child_cleanup.cost_quota
                ),
                "source": "tightened"
            },
            "artifact_bytes": {
                "parent": root_budget.artifact_bytes,
                "child": child_budget.artifact_bytes,
                "delta": required_delta(root_budget.artifact_bytes, child_budget.artifact_bytes),
                "source": "tightened"
            }
        },
        "cleanup_drain": {
            "parent_poll_quota": root_cleanup.poll_quota,
            "child_poll_quota": child_cleanup.poll_quota,
            "child_cost_quota": child_cleanup.cost_quota
        },
        "admission_failure": admission_failure_log(admission_failure),
        "final_state": {
            "pending_obligations": state.pending_obligation_count(),
            "live_tasks": state.live_task_count(),
            "live_regions": state.live_region_count(),
            "runtime_quiescent": state.is_quiescent(),
            "no_obligation_leak": state.pending_obligation_count() == 0
        }
    })
}

#[test]
fn contract_declares_rch_routed_proof_lane() {
    let contract = contract();

    assert_eq!(
        contract.contract_version,
        "capability-budget-planner-contract-v1"
    );
    assert_eq!(contract.owner_bead, "asupersync-3dhff2");
    assert_eq!(contract.proof_lane, "contract-and-runtime-ratchet");
    assert!(contract.proof_command.starts_with("rch exec -- env "));
    assert!(contract.proof_command.contains(
        "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_capability_budget_planner_contract"
    ));
    assert!(
        contract
            .proof_command
            .contains("cargo test -p asupersync --test capability_budget_planner_contract")
    );
    assert_eq!(contract.required_dimensions.len(), 5);
    assert!(contract.runtime_semantics.len() >= 4);
    assert!(contract.source_paths.len() >= 8);
}

#[test]
fn source_markers_match_contract() {
    for source_path in contract().source_paths {
        let source = read_source(&source_path.path);

        for marker in &source_path.required_markers {
            assert!(
                source.contains(marker),
                "{} is missing required marker {marker:?}",
                source_path.path
            );
        }

        for marker in &source_path.forbidden_markers {
            assert!(
                !source.contains(marker),
                "{} contains forbidden marker {marker:?}",
                source_path.path
            );
        }
    }
}

#[test]
fn dimension_rows_match_runtime_semantics() {
    let source = read_source("src/types/budget.rs");

    for row in contract().required_dimensions {
        let dimension = dimension_from_variant(&row.required_enum_variant);
        assert_eq!(dimension.as_str(), row.dimension);
        assert!(
            source.contains(&format!("pub const fn {}(", row.requirement_builder)),
            "missing requirement builder {}",
            row.requirement_builder
        );

        let missing = CapabilityBudget::UNSPECIFIED
            .plan_child(CapabilityBudget::UNSPECIFIED, requirement_for(dimension))
            .expect_err("required absent dimension must fail closed");
        assert_eq!(missing, CapabilityBudgetRefusal::MissingRequired(dimension));

        let exhausted = exhausted_budget_for(dimension)
            .plan_child(CapabilityBudget::UNSPECIFIED, requirement_for(dimension))
            .expect_err("required exhausted dimension must fail closed");
        assert_eq!(exhausted, CapabilityBudgetRefusal::Exhausted(dimension));
    }
}

#[test]
fn planner_meets_parent_and_child_envelopes_for_all_dimensions() {
    let parent = CapabilityBudget::new()
        .with_memory_bytes(1_024)
        .with_cpu_units(64)
        .with_io_bytes(4_096)
        .with_cleanup_budget(Budget::new().with_poll_quota(10).with_cost_quota(50))
        .with_artifact_bytes(256);
    let child = CapabilityBudget::new()
        .with_memory_bytes(2_048)
        .with_cpu_units(32)
        .with_cleanup_budget(Budget::new().with_poll_quota(3).with_cost_quota(20))
        .with_artifact_bytes(128);

    let effective = parent
        .plan_child(child, all_requirements())
        .expect("all required dimensions should be admitted");

    assert_eq!(effective.memory_bytes, Some(1_024));
    assert_eq!(effective.cpu_units, Some(32));
    assert_eq!(effective.io_bytes, Some(4_096));
    assert_eq!(effective.cleanup_budget.expect("cleanup").poll_quota, 3);
    assert_eq!(
        effective.cleanup_budget.expect("cleanup").cost_quota,
        Some(20)
    );
    assert_eq!(effective.artifact_bytes, Some(128));
}

#[test]
fn cx_scope_region_and_task_paths_carry_capability_budget() {
    let inherited = CapabilityBudget::new()
        .with_memory_bytes(4_096)
        .with_cpu_units(64)
        .with_io_bytes(8_192)
        .with_cleanup_budget(Budget::new().with_poll_quota(16))
        .with_artifact_bytes(512);
    let mut state = RuntimeState::new();
    let parent = state.create_root_region_with_capability_budget(Budget::INFINITE, inherited);
    let cx: Cx = Cx::new(parent, TaskId::new_for_test(9_001, 0), Budget::INFINITE);

    cx.apply_child_capability_budget(inherited, all_requirements())
        .expect("root cx capability budget should apply");

    let scope = cx
        .scope_with_budget_and_capability_budget(
            Budget::new().with_poll_quota(64),
            CapabilityBudget::new()
                .with_memory_bytes(2_048)
                .with_artifact_bytes(128),
            all_requirements(),
        )
        .expect("scope should be admitted");

    assert_eq!(scope.capability_budget().memory_bytes, Some(2_048));
    assert_eq!(scope.capability_budget().cpu_units, Some(64));
    assert_eq!(scope.capability_budget().io_bytes, Some(8_192));
    assert_eq!(
        scope
            .capability_budget()
            .cleanup_budget
            .expect("cleanup budget")
            .poll_quota,
        16
    );
    assert_eq!(scope.capability_budget().artifact_bytes, Some(128));

    let (handle, _stored) = scope
        .spawn(&mut state, &cx, |child_cx| async move {
            child_cx.capability_budget()
        })
        .expect("spawned task should inherit scope capability budget");
    let task_budget = state
        .task(handle.task_id())
        .expect("spawned task record")
        .cx_inner
        .as_ref()
        .expect("spawned task cx")
        .read()
        .capability_budget;

    assert_eq!(task_budget, scope.capability_budget());

    let child = state
        .create_child_region_with_capability_budget(
            parent,
            Budget::INFINITE,
            CapabilityBudget::new()
                .with_memory_bytes(1_024)
                .with_cpu_units(8),
            all_requirements(),
        )
        .expect("child region should be admitted");
    let child_budget = state
        .region_capability_budget(child)
        .expect("child region budget must be stored");

    assert_eq!(child_budget.memory_bytes, Some(1_024));
    assert_eq!(child_budget.cpu_units, Some(8));
    assert_eq!(child_budget.io_bytes, Some(8_192));
    assert_eq!(child_budget.artifact_bytes, Some(512));
}

#[test]
fn region_admission_reports_fail_closed_refusal() {
    let mut state = RuntimeState::new();
    let parent = state.create_root_region_with_capability_budget(
        Budget::INFINITE,
        CapabilityBudget::new().with_memory_bytes(1_024),
    );

    let err = state
        .create_child_region_with_capability_budget(
            parent,
            Budget::INFINITE,
            CapabilityBudget::UNSPECIFIED,
            CapabilityBudgetRequirements::new().require_artifact_bytes(),
        )
        .expect_err("missing required artifact envelope must reject child");

    assert!(matches!(
        err,
        RegionCreateError::CapabilityBudgetRefused {
            parent: refused_parent,
            reason: CapabilityBudgetRefusal::MissingRequired(
                CapabilityBudgetDimension::ArtifactBytes
            ),
        } if refused_parent == parent
    ));
}

#[test]
fn e2e_log_captures_budget_deltas_cleanup_drain_and_no_leak() {
    let contract = contract().e2e_log_contract;
    let log = capability_budget_e2e_log();

    assert_eq!(contract.scenario_id, "capability-budget-e2e-log-v1");
    for field_path in &contract.required_fields {
        assert!(
            json_path_exists(&log, field_path),
            "e2e log is missing required field {field_path}"
        );
    }

    assert_eq!(log["schema_version"], "capability-budget-e2e-log-v1");
    assert_eq!(log["scenario_id"], contract.scenario_id);
    assert_ne!(log["root_region_id"], log["child_region_id"]);
    assert_eq!(log["budget_deltas"]["memory_bytes"]["delta"], json!(-3_072));
    assert_eq!(log["budget_deltas"]["cpu_units"]["delta"], json!(-56));
    assert_eq!(log["budget_deltas"]["io_bytes"]["delta"], json!(0));
    assert_eq!(
        log["budget_deltas"]["cleanup"]["poll_quota_delta"],
        json!(-12)
    );
    assert_eq!(
        log["budget_deltas"]["cleanup"]["cost_quota_delta"],
        json!(-60)
    );
    assert_eq!(log["budget_deltas"]["artifact_bytes"]["delta"], json!(-256));
    assert_eq!(log["budget_deltas"]["io_bytes"]["source"], "inherited");
    assert_eq!(log["cleanup_drain"]["parent_poll_quota"], json!(16));
    assert_eq!(log["cleanup_drain"]["child_poll_quota"], json!(4));
    assert_eq!(log["cleanup_drain"]["child_cost_quota"], json!(20));
    assert_eq!(
        log["admission_failure"]["reason"],
        contract.required_admission_failure.reason
    );
    assert_eq!(
        log["admission_failure"]["dimension"],
        contract.required_admission_failure.dimension
    );
    assert_eq!(
        log["final_state"]["pending_obligations"],
        json!(contract.required_final_state.pending_obligations)
    );
    assert_eq!(
        log["final_state"]["live_tasks"],
        json!(contract.required_final_state.live_tasks)
    );
    assert_eq!(
        log["final_state"]["runtime_quiescent"],
        json!(contract.required_final_state.runtime_quiescent)
    );
    assert_eq!(
        log["final_state"]["no_obligation_leak"],
        json!(contract.required_final_state.no_obligation_leak)
    );
}

#[test]
fn runtime_semantic_rows_are_executed_by_this_contract() {
    let executed = [
        "child-inherits-and-tightens-every-dimension",
        "required-dimension-missing-fails-closed",
        "required-dimension-exhausted-fails-closed",
        "cx-scope-region-task-propagation",
        "e2e-log-captures-region-budget-deltas-cleanup-drain-and-no-leak",
    ];

    for row in contract().runtime_semantics {
        assert!(
            executed.contains(&row.scenario_id.as_str()),
            "runtime semantic {} is declared but not executed: {}",
            row.scenario_id,
            row.description
        );
        assert_eq!(row.expected_status, "pass");
    }
}
