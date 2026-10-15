//! Contract tests for PROOF-TRAFFIC A2 admission receipts.
//!
//! These tests pin the deterministic receipt classifier for
//! `asupersync-proof-traffic-control-kuyx64.2`: every focused proof intent must
//! resolve to one of the documented fail-closed decisions, produce paste-ready
//! Agent Mail / `br` handoff text, and avoid forbidden local or destructive
//! recommendations.

#![allow(missing_docs)]

use asupersync::audit::proof_traffic_receipt::{
    PROOF_TRAFFIC_ADMISSION_SCHEMA_VERSION, ProofTrafficActiveBuild, ProofTrafficAdmissionInput,
    ProofTrafficAdmissionReceipt, ProofTrafficBuildOwner, ProofTrafficCapabilityProbe,
    ProofTrafficDecision, ProofTrafficIntent, ProofTrafficQueueSnapshot,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/proof_traffic_admission_receipts_v1.json";
const DOCS_PATH: &str = "docs/proof_traffic_control.md";
const GATE_ID: &str = "asupersync-proof-traffic-control-kuyx64.2";

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

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} array"))
        .as_slice()
}

fn string_field<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| entry.as_str().expect("string entry").to_string())
        .collect()
}

fn intent() -> ProofTrafficIntent {
    ProofTrafficIntent::new(
        "2918140b6deadbeef".to_string(),
        "cargo test -p asupersync --test proof_traffic_admission_receipt_contract -- --nocapture"
            .to_string(),
        "${TMPDIR:-/tmp}/rch_target_proof_traffic_admission_receipt_contract".to_string(),
        vec![
            "tests/proof_traffic_admission_receipt_contract.rs".to_string(),
            "src/audit/proof_traffic_receipt.rs".to_string(),
        ],
    )
}

fn supported_capability() -> ProofTrafficCapabilityProbe {
    ProofTrafficCapabilityProbe::new(
        "rch-1.0.41-help".to_string(),
        true,
        vec!["remote-required supported".to_string()],
    )
}

fn unsupported_capability() -> ProofTrafficCapabilityProbe {
    ProofTrafficCapabilityProbe::new(
        "rch-1.0.41-help".to_string(),
        false,
        vec![
            "--base missing".to_string(),
            "--clean-overlay missing".to_string(),
            "--overlay-path missing".to_string(),
        ],
    )
}

fn receipt(
    queue: ProofTrafficQueueSnapshot,
    capability: ProofTrafficCapabilityProbe,
    clean_overlay_required: bool,
    report_only: bool,
) -> ProofTrafficAdmissionReceipt {
    let input = ProofTrafficAdmissionInput::new(
        GATE_ID.to_string(),
        intent(),
        capability,
        queue,
        clean_overlay_required,
        report_only,
    );
    ProofTrafficAdmissionReceipt::decide(&input)
}

fn active_build(
    build_id: &str,
    owner: ProofTrafficBuildOwner,
    heartbeat_fresh: bool,
    progress_stale: bool,
    worker_healthy: bool,
) -> ProofTrafficActiveBuild {
    ProofTrafficActiveBuild::new(
        build_id.to_string(),
        owner,
        heartbeat_fresh,
        progress_stale,
        worker_healthy,
        "cargo test -p asupersync --test peer_lane".to_string(),
    )
}

fn assert_decision(got: ProofTrafficDecision, expected: ProofTrafficDecision, label: &str) {
    assert_eq!(got, expected, "{label}");
}

fn assert_no_forbidden_recommendations(receipt: &ProofTrafficAdmissionReceipt) {
    assert!(
        receipt.forbidden_recommendations().is_empty(),
        "forbidden recommendation tokens in {}: {:?}",
        receipt.decision.label(),
        receipt.forbidden_recommendations()
    );
    assert!(!receipt.local_cargo_fallback_allowed);
    assert!(!receipt.peer_build_cancellation_allowed);
    assert!(!receipt.branch_or_worktree_allowed);
    assert!(!receipt.file_deletion_allowed);
}

#[test]
fn taxonomy_labels_are_exhaustive_and_stable() {
    let labels = [
        ProofTrafficDecision::RunNow.label(),
        ProofTrafficDecision::QueueWait.label(),
        ProofTrafficDecision::ParkRerunRequired.label(),
        ProofTrafficDecision::BlockedByPeer.label(),
        ProofTrafficDecision::BlockedByCapabilityDrift.label(),
        ProofTrafficDecision::RemoteRequiredRefused.label(),
        ProofTrafficDecision::ReportOnly.label(),
    ];
    assert_eq!(
        labels,
        [
            "run-now",
            "queue-wait",
            "park-rerun-required",
            "blocked-by-peer",
            "blocked-by-capability-drift",
            "remote-required-refused",
            "report-only",
        ]
    );
}

#[test]
fn fixtures_cover_required_decision_paths() {
    let empty_queue = receipt(
        ProofTrafficQueueSnapshot::empty(),
        supported_capability(),
        false,
        false,
    );
    assert_decision(
        empty_queue.decision,
        ProofTrafficDecision::RunNow,
        "empty queue",
    );
    assert!(empty_queue.proof_may_run_now);

    let active_project_exclusion = receipt(
        ProofTrafficQueueSnapshot::new(true, false, false, vec![]),
        supported_capability(),
        false,
        false,
    );
    assert_decision(
        active_project_exclusion.decision,
        ProofTrafficDecision::ParkRerunRequired,
        "active project exclusion",
    );
    assert!(
        active_project_exclusion
            .retry_condition
            .contains("active_project_exclusion")
    );

    let worker_health_refusal = receipt(
        ProofTrafficQueueSnapshot::new(false, false, true, vec![]),
        supported_capability(),
        false,
        false,
    );
    assert_decision(
        worker_health_refusal.decision,
        ProofTrafficDecision::ParkRerunRequired,
        "worker health refusal",
    );
    assert!(
        worker_health_refusal
            .retry_condition
            .contains("worker-health")
    );

    let heartbeat_fresh_progress_stale_peer = receipt(
        ProofTrafficQueueSnapshot::new(
            false,
            false,
            false,
            vec![active_build(
                "29887347701055960",
                ProofTrafficBuildOwner::PeerOwned,
                true,
                true,
                true,
            )],
        ),
        supported_capability(),
        false,
        false,
    );
    assert_decision(
        heartbeat_fresh_progress_stale_peer.decision,
        ProofTrafficDecision::BlockedByPeer,
        "peer-owned heartbeat-fresh/progress-stale",
    );
    assert!(
        heartbeat_fresh_progress_stale_peer
            .rch_worker_or_refusal
            .contains("29887347701055960")
    );

    let self_owned_stale = receipt(
        ProofTrafficQueueSnapshot::new(
            false,
            false,
            false,
            vec![active_build(
                "self-build-7",
                ProofTrafficBuildOwner::SelfOwned,
                true,
                true,
                true,
            )],
        ),
        supported_capability(),
        false,
        false,
    );
    assert_decision(
        self_owned_stale.decision,
        ProofTrafficDecision::ParkRerunRequired,
        "self-owned stale build",
    );

    let unsupported_overlay = receipt(
        ProofTrafficQueueSnapshot::empty(),
        unsupported_capability(),
        true,
        false,
    );
    assert_decision(
        unsupported_overlay.decision,
        ProofTrafficDecision::BlockedByCapabilityDrift,
        "unsupported overlay capability",
    );
    assert!(
        unsupported_overlay
            .retry_condition
            .contains("installed RCH supports")
    );

    let remote_required_refused = receipt(
        ProofTrafficQueueSnapshot::new(false, true, false, vec![]),
        supported_capability(),
        false,
        false,
    );
    assert_decision(
        remote_required_refused.decision,
        ProofTrafficDecision::RemoteRequiredRefused,
        "remote-required refusal",
    );

    let healthy_active_build = receipt(
        ProofTrafficQueueSnapshot::new(
            false,
            false,
            false,
            vec![active_build(
                "healthy-build-3",
                ProofTrafficBuildOwner::PeerOwned,
                true,
                false,
                true,
            )],
        ),
        supported_capability(),
        false,
        false,
    );
    assert_decision(
        healthy_active_build.decision,
        ProofTrafficDecision::QueueWait,
        "healthy active build",
    );

    let report_only = receipt(
        ProofTrafficQueueSnapshot::new(true, true, true, vec![]),
        unsupported_capability(),
        true,
        true,
    );
    assert_decision(
        report_only.decision,
        ProofTrafficDecision::ReportOnly,
        "report-only has precedence",
    );

    for receipt in [
        empty_queue,
        active_project_exclusion,
        worker_health_refusal,
        heartbeat_fresh_progress_stale_peer,
        self_owned_stale,
        unsupported_overlay,
        remote_required_refused,
        healthy_active_build,
        report_only,
    ] {
        assert_no_forbidden_recommendations(&receipt);
    }
}

#[test]
fn markdown_json_and_handoff_bodies_include_required_fields() {
    let receipt = receipt(
        ProofTrafficQueueSnapshot::new(
            false,
            false,
            false,
            vec![active_build(
                "healthy-build-3",
                ProofTrafficBuildOwner::PeerOwned,
                true,
                false,
                true,
            )],
        ),
        supported_capability(),
        false,
        false,
    );

    let json = serde_json::to_value(&receipt).expect("serialize receipt");
    assert_eq!(
        string_field(&json, "schema_version"),
        PROOF_TRAFFIC_ADMISSION_SCHEMA_VERSION
    );
    assert_eq!(string_field(&json, "gate_id"), GATE_ID);
    assert_eq!(json["decision"].as_str(), Some("queue-wait"));
    assert_eq!(string_field(&json, "head_commit"), "2918140b6deadbeef");
    assert!(
        string_field(&json, "command_intent").contains("proof_traffic_admission_receipt_contract")
    );
    assert!(string_field(&json, "target_dir").contains("rch_target_proof_traffic_admission"));
    assert_eq!(
        json["selected_paths"].as_array().expect("selected").len(),
        2
    );
    assert_eq!(
        string_field(&json, "capability_probe_version"),
        "rch-1.0.41-help"
    );
    assert_eq!(
        json["active_build_ids"][0].as_str(),
        Some("healthy-build-3")
    );
    assert_eq!(
        string_field(&json, "rch_worker_or_refusal"),
        "waiting-on-active-builds:healthy-build-3"
    );
    assert!(string_field(&json, "retry_condition").contains("active build ids"));
    assert!(
        json["no_claim_boundaries"]
            .as_array()
            .expect("claims")
            .len()
            >= 8
    );

    let markdown = receipt.render_markdown();
    for required in [
        "gate_id",
        "status",
        "head_commit",
        "command_intent",
        "target_dir",
        "selected_paths",
        "capability_probe_version",
        "capability_findings",
        "rch_worker_or_refusal",
        "retry_condition",
        "no_claim_boundaries",
    ] {
        assert!(markdown.contains(required), "markdown missing {required}");
    }
    assert_eq!(
        markdown,
        receipt.render_markdown(),
        "markdown deterministic"
    );

    let agent_mail = receipt.agent_mail_body();
    let br_comment = receipt.br_comment_body();
    for body in [agent_mail, br_comment] {
        assert!(body.contains("gate_id"));
        assert!(body.contains("status"));
        assert!(body.contains("retry_condition"));
        assert!(body.contains("local_cargo_fallback_allowed: `false`"));
        assert!(body.contains("peer_build_cancellation_allowed: `false`"));
    }
}

#[test]
fn artifact_and_docs_pin_a2_contract_scope() {
    let artifact = json(ARTIFACT_PATH);
    assert_eq!(
        string_field(&artifact, "schema_version"),
        "proof-traffic-admission-receipts-v1"
    );
    assert_eq!(string_field(&artifact, "bead_id"), GATE_ID);
    assert_eq!(string_field(&artifact, "status"), "contract_guarded");

    for path in [
        string_field(&artifact["source_of_truth"], "artifact"),
        string_field(&artifact["source_of_truth"], "operator_doc"),
        string_field(&artifact["source_of_truth"], "contract_test"),
        string_field(&artifact["source_of_truth"], "rust_module"),
        string_field(&artifact["source_of_truth"], "capability_artifact"),
    ] {
        assert!(repo_path(path).exists(), "{path} must exist");
    }

    let artifact_taxonomy = string_set(&artifact, "decision_taxonomy");
    let expected_taxonomy = BTreeSet::from([
        "run-now".to_string(),
        "queue-wait".to_string(),
        "park-rerun-required".to_string(),
        "blocked-by-peer".to_string(),
        "blocked-by-capability-drift".to_string(),
        "remote-required-refused".to_string(),
        "report-only".to_string(),
    ]);
    assert_eq!(artifact_taxonomy, expected_taxonomy);

    let fixtures = array(&artifact, "fixture_coverage")
        .iter()
        .map(|fixture| string_field(fixture, "fixture_id").to_string())
        .collect::<BTreeSet<_>>();
    for fixture in [
        "empty-queue",
        "active-project-exclusion",
        "worker-health-refusal",
        "heartbeat-fresh-progress-stale-peer",
        "peer-owned-stale-build",
        "self-owned-stale-build",
        "unsupported-overlay-capability",
    ] {
        assert!(fixtures.contains(fixture), "missing fixture {fixture}");
    }

    let forbidden = artifact["forbidden_recommendations"]
        .as_object()
        .expect("forbidden recommendations");
    for key in [
        "local_cargo_fallback",
        "peer_build_cancellation",
        "branch_or_worktree",
        "file_deletion",
    ] {
        assert_eq!(forbidden.get(key).and_then(Value::as_bool), Some(true));
    }

    let docs = read_repo_file(DOCS_PATH);
    for needle in [
        "Proof-Traffic A2 Admission Receipts",
        "run-now",
        "queue-wait",
        "park-rerun-required",
        "blocked-by-peer",
        "blocked-by-capability-drift",
        "remote-required-refused",
        "report-only",
        "artifacts/proof_traffic_admission_receipts_v1.json",
        "tests/proof_traffic_admission_receipt_contract.rs",
    ] {
        assert!(docs.contains(needle), "docs missing {needle}");
    }
}

#[test]
fn serde_roundtrip_preserves_decision_and_no_claim_boundaries() {
    let receipt = receipt(
        ProofTrafficQueueSnapshot::new(
            false,
            false,
            false,
            vec![active_build(
                "peer-stale-1",
                ProofTrafficBuildOwner::PeerOwned,
                true,
                true,
                true,
            )],
        ),
        supported_capability(),
        false,
        false,
    );
    let json = serde_json::to_string(&receipt).expect("serialize");
    let back: ProofTrafficAdmissionReceipt = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, receipt);
    assert_eq!(back.decision, ProofTrafficDecision::BlockedByPeer);
    assert!(
        back.no_claim_boundaries
            .iter()
            .any(|boundary| boundary.contains("No peer-owned build cancellation authority."))
    );
}
