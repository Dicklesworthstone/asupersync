#![allow(missing_docs)]

use asupersync::cx::{
    CapacityTicketReceiptStatus, CapacityTicketRequest, CapacityTicketWorkKind,
    request_capacity_ticket_from_budget,
};
use asupersync::{
    Budget, CancelKind, CancelReason, CapabilityBudget, CapabilityBudgetDimension,
    CapabilityBudgetRefusal, CapabilityBudgetRequirements, RegionId, TaskId,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/capacity_ticket_agent_admission_contract_v1.json";
const DOC_PATH: &str = "docs/capacity_ticket_agent_admission.md";
const FORBIDDEN_ALLOW_LOCAL: &str = concat!("RCH_ALLOW_LOCAL", "=1");
const FORBIDDEN_REMOTE_ZERO: &str = concat!("RCH_REQUIRE_REMOTE", "=0");

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn contract() -> Value {
    serde_json::from_str(&read_repo_file(ARTIFACT_PATH)).expect("contract artifact parses")
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
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

fn owner() -> (RegionId, TaskId) {
    (RegionId::new_for_test(410, 1), TaskId::new_for_test(410, 0))
}

fn agent_request(reason: &str) -> CapacityTicketRequest {
    CapacityTicketRequest::agent_swarm_admission(
        CapabilityBudget::new()
            .with_memory_bytes(4096)
            .with_cpu_units(8)
            .with_artifact_bytes(512),
        reason,
    )
}

#[test]
fn capacity_ticket_contract_artifact_is_remote_required_and_no_local_fallback() {
    let contract = contract();
    assert_eq!(
        string(&contract, "contract_version"),
        "capacity-ticket-agent-admission-contract-v1"
    );
    assert_eq!(
        string(&contract, "owner_bead"),
        "asupersync-capacity-ticket-agent-admission-od29tn"
    );

    let proof_lane = &contract["proof_lane"];
    let command = string(proof_lane, "proof_command");
    assert!(
        command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "),
        "proof command must require remote rch: {command}"
    );
    assert!(
        command.contains(
            "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_capacity_ticket_agent_admission"
        ),
        "proof command must isolate target dir: {command}"
    );
    assert!(
        command
            .contains("cargo test -p asupersync --test capacity_ticket_agent_admission_contract"),
        "proof command must run this focused contract test: {command}"
    );
    assert_eq!(proof_lane["remote_required"], Value::Bool(true));
    assert_eq!(proof_lane["local_fallback_allowed"], Value::Bool(false));
    assert!(!command.contains(FORBIDDEN_ALLOW_LOCAL));
    assert!(!command.contains(FORBIDDEN_REMOTE_ZERO));

    let work_kinds = string_set(&contract, "work_kinds");
    assert_eq!(
        work_kinds,
        BTreeSet::from([
            "agent_swarm_admission".to_string(),
            "core_runtime".to_string(),
            "operator_diagnostics".to_string(),
            "optional_background".to_string(),
            "proof_artifact".to_string(),
        ])
    );

    let statuses = string_set(&contract, "receipt_statuses");
    assert_eq!(
        statuses,
        BTreeSet::from([
            "released".to_string(),
            "revoked".to_string(),
            "unreleased".to_string(),
        ])
    );
}

#[test]
fn source_paths_docs_and_forbidden_markers_match_contract() {
    let contract = contract();
    for entry in array(&contract, "source_paths") {
        let path = string(entry, "path");
        let content = read_repo_file(path);
        for marker in array(entry, "required_markers") {
            let marker = marker
                .as_str()
                .expect("required marker entries must be strings");
            assert!(
                content.contains(marker),
                "{path} must contain marker {marker:?}"
            );
        }
        for marker in array(entry, "forbidden_markers") {
            let marker = marker
                .as_str()
                .expect("forbidden marker entries must be strings");
            assert!(
                !content.contains(marker),
                "{path} must not contain forbidden marker {marker:?}"
            );
        }
    }

    let doc = read_repo_file(DOC_PATH);
    for marker in [
        "Capacity Ticket Agent Admission",
        "No Ambient Authority",
        "Failure Policy",
        "Validation",
        ARTIFACT_PATH,
        "request_capacity_ticket",
        "request_capacity_ticket_from_budget",
        "RCH_REQUIRE_REMOTE=1 rch exec -- env",
    ] {
        assert!(doc.contains(marker), "doc must contain {marker}");
    }
}

#[test]
fn capacity_ticket_budget_semantics_fail_closed_and_preserve_owner() {
    let (region, task) = owner();
    let ticket = request_capacity_ticket_from_budget(
        region,
        task,
        CapabilityBudget::UNSPECIFIED,
        agent_request("root admission"),
    )
    .expect("ticket admits when child supplies all required dimensions");

    assert_eq!(ticket.owner_region(), region);
    assert_eq!(ticket.owner_task(), task);
    assert_eq!(ticket.id().owner_region(), region);
    assert_eq!(ticket.id().owner_task(), task);
    assert_eq!(ticket.id().lineage(), 0);
    assert_eq!(
        ticket.work_kind(),
        CapacityTicketWorkKind::AgentSwarmAdmission
    );
    assert_eq!(ticket.reason(), "root admission");
    assert_eq!(ticket.granted().memory_bytes, Some(4096));
    assert_eq!(ticket.granted().cpu_units, Some(8));
    assert_eq!(ticket.granted().artifact_bytes, Some(512));

    let err = request_capacity_ticket_from_budget(
        region,
        task,
        CapabilityBudget::UNSPECIFIED,
        CapacityTicketRequest::agent_swarm_admission(
            CapabilityBudget::new()
                .with_cpu_units(8)
                .with_artifact_bytes(512),
            "missing memory",
        ),
    )
    .expect_err("missing required memory fails closed");
    assert_eq!(err.owner_region(), region);
    assert_eq!(err.owner_task(), task);
    assert_eq!(err.request_reason(), "missing memory");
    assert_eq!(
        err.budget_refusal(),
        CapabilityBudgetRefusal::MissingRequired(CapabilityBudgetDimension::MemoryBytes)
    );
}

#[test]
fn split_lend_and_receipts_are_meet_based_and_leak_visible() {
    let (region, task) = owner();
    let parent = request_capacity_ticket_from_budget(
        region,
        task,
        CapabilityBudget::UNSPECIFIED,
        agent_request("parent"),
    )
    .expect("parent admits");

    let split = parent
        .split(
            CapabilityBudget::new()
                .with_memory_bytes(8192)
                .with_cpu_units(2)
                .with_artifact_bytes(128),
            CapabilityBudgetRequirements::new()
                .require_memory_bytes()
                .require_cpu_units()
                .require_artifact_bytes(),
            "split",
        )
        .expect("split child admits by meeting parent");
    assert_eq!(split.granted().memory_bytes, Some(4096));
    assert_eq!(split.granted().cpu_units, Some(2));
    assert_eq!(split.granted().artifact_bytes, Some(128));
    assert_eq!(split.parent_id(), Some(parent.id()));
    assert_eq!(split.id().lineage(), 1);

    let borrower_region = RegionId::new_for_test(411, 1);
    let borrower_task = TaskId::new_for_test(411, 0);
    let lent = parent
        .lend_to_for(
            borrower_region,
            borrower_task,
            CapacityTicketWorkKind::ProofArtifact,
            CapabilityBudget::new()
                .with_memory_bytes(1024)
                .with_cpu_units(1)
                .with_artifact_bytes(256)
                .with_cleanup_budget(Budget::MINIMAL),
            CapabilityBudgetRequirements::new()
                .require_memory_bytes()
                .require_cpu_units()
                .require_artifact_bytes()
                .require_cleanup(),
            "lend proof",
        )
        .expect("lend admits with explicit borrower");
    assert_eq!(lent.owner_region(), borrower_region);
    assert_eq!(lent.owner_task(), borrower_task);
    assert_eq!(lent.work_kind(), CapacityTicketWorkKind::ProofArtifact);
    assert_eq!(lent.parent_id(), Some(parent.id()));

    let unreleased = parent.unreleased_receipt();
    assert_eq!(unreleased.status, CapacityTicketReceiptStatus::Unreleased);
    assert!(!unreleased.obligation_leak_free);
    assert!(unreleased.no_ambient_authority);

    let released = split.release();
    assert_eq!(released.status.as_str(), "released");
    assert!(released.obligation_leak_free);
    assert!(released.cancel_reason.is_none());

    let revoked = lent.revoke(CancelReason::new(CancelKind::User));
    assert_eq!(revoked.status.as_str(), "revoked");
    assert!(revoked.obligation_leak_free);
    assert_eq!(
        revoked.cancel_reason.as_ref().map(|reason| reason.kind),
        Some(CancelKind::User)
    );
}

#[test]
fn explicit_no_claims_keep_capacity_ticket_scope_narrow() {
    let contract = contract();
    let no_claims = string_set(&contract, "does_not_prove");
    for expected in [
        "No automatic scheduler admission policy is enabled by this API.",
        "No production host throughput, latency, fairness, or memory regression claim is made.",
        "No fourth-wave governor or proof-lane planner claim is replaced by this contract.",
        "No broad cargo check, clippy, rustdoc, all-target, or workspace-health claim is made.",
        "No RCH fleet availability claim is made beyond the cited focused command transcript.",
    ] {
        assert!(
            no_claims.contains(expected),
            "contract no-claims must contain {expected}"
        );
    }
}
