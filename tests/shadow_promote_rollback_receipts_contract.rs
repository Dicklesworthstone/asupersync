//! Contract-backed proofs for shadow promotion and rollback receipts.

use asupersync::runtime::config::{
    CapacityEnvelopeHostFingerprint, ControllerInterferenceTwinVerdict, HostProfileHostResources,
    HostProfileId, HostProfilePlannerObjective, SHADOW_PROMOTE_ROLLBACK_RECEIPT_SCHEMA_VERSION,
    ShadowPromoteRollbackDecision, ShadowPromoteRollbackReceipt,
    ShadowPromoteRollbackReceiptRequest, SignedProfileBundleBundle,
    SignedProfileBundleCapacityCertificateReference, SignedProfileBundleChildEvidenceHash,
    SignedProfileBundleControllerVersion, SignedProfileBundleExecutionMode,
    SignedProfileBundleIntegrityMode, SignedProfileBundleManifest,
    SignedProfileBundleRollbackReceipt, SignedProfileBundleShadowRunDecision,
    SignedProfileBundleShadowRunEvaluation, SignedProfileBundleVerificationResult,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs;
use std::path::Path;

const DEFAULT_SCENARIO_ID: &str = "AA-SHADOW-PROMOTE-ROLLBACK-RECEIPT-64C-256G";
const CAPACITY_CERTIFICATE_ID: &str = "artifacts/capacity_envelope_planner_smoke_contract_v1.json";
const LATENCY_CERTIFICATE_ID: &str =
    "artifacts/runtime_latency_budget_certificate_contract_v1.json";
const RECEIPT_PATH: &str = "shadow_promote_rollback_receipt.json";

#[derive(Debug, Deserialize)]
struct ShadowReceiptContract {
    contract_version: String,
    smoke_scenarios: Vec<ShadowReceiptScenario>,
}

#[derive(Debug, Deserialize)]
struct ShadowReceiptScenario {
    scenario_id: String,
    expected_decision: String,
}

fn contract() -> ShadowReceiptContract {
    serde_json::from_str(include_str!(
        "../artifacts/shadow_promote_rollback_receipts_smoke_contract_v1.json"
    ))
    .expect("shadow promote rollback receipt contract must parse")
}

fn digest(seed: char) -> String {
    seed.to_string().repeat(64)
}

fn host_resources() -> HostProfileHostResources {
    HostProfileHostResources {
        cpu_cores: 64,
        memory_gib: 256,
    }
}

fn host_fingerprint() -> CapacityEnvelopeHostFingerprint {
    CapacityEnvelopeHostFingerprint {
        hostname: "lab-64c-256g-a".to_string(),
        arch: "x86_64".to_string(),
        cpu_cores: 64,
        memory_gib: 256,
    }
}

fn controller_versions() -> Vec<SignedProfileBundleControllerVersion> {
    ["admission", "batching", "brownout", "topology"]
        .into_iter()
        .map(|controller| SignedProfileBundleControllerVersion {
            controller: controller.to_string(),
            contract_version: format!("{controller}-v1"),
        })
        .collect()
}

fn child_evidence_hashes() -> Vec<SignedProfileBundleChildEvidenceHash> {
    ["admission", "batching", "brownout", "topology"]
        .into_iter()
        .enumerate()
        .map(|(index, controller)| SignedProfileBundleChildEvidenceHash {
            controller: controller.to_string(),
            artifact_id: format!("artifacts/{controller}_smoke_contract_v1.json"),
            digest_sha256: digest(char::from(b'a' + index as u8)),
        })
        .collect()
}

fn shadow_evaluation(
    decision: SignedProfileBundleShadowRunDecision,
) -> SignedProfileBundleShadowRunEvaluation {
    let hold_reasons = if decision == SignedProfileBundleShadowRunDecision::Hold {
        vec!["candidate regret margin 80bps was below promote threshold 250bps".to_string()]
    } else {
        Vec::new()
    };
    SignedProfileBundleShadowRunEvaluation {
        decision,
        candidate_profile: HostProfileId::LocalityFirst64C256G,
        baseline_profile: HostProfileId::ConservativeBaseline,
        candidate_worker_count: 64,
        candidate_agent_count: 512,
        baseline_worker_count: 64,
        baseline_agent_count: 384,
        candidate_loss_basis_points: 79_434,
        baseline_loss_basis_points: 109_592,
        regret_margin_basis_points: if decision == SignedProfileBundleShadowRunDecision::Promote {
            30_158
        } else {
            80
        },
        hold_reasons,
        dominant_reasons: vec![
            "candidate p99 improved by 120000ns".to_string(),
            "candidate safe agent ceiling increased by 128".to_string(),
            "candidate memory pressure decreased by 500bps".to_string(),
            "counterfactual regret margin 30158bps".to_string(),
        ],
    }
}

fn signed_bundle(
    decision: SignedProfileBundleShadowRunDecision,
    verification_accepted: bool,
) -> SignedProfileBundleBundle {
    let versions = controller_versions();
    let evidence_hashes = child_evidence_hashes();
    let manifest = SignedProfileBundleManifest {
        bundle_id: "shadow-promote-locality-first-64c-256g-v1".to_string(),
        objective: HostProfilePlannerObjective::LocalityFirst,
        requested_profile: Some(HostProfileId::LocalityFirst64C256G),
        selected_profile: HostProfileId::LocalityFirst64C256G,
        fallback_profile: HostProfileId::ConservativeBaseline,
        used_safe_fallback: false,
        planning_refusal_reasons: Vec::new(),
        requested_host_resources: host_resources(),
        host_fingerprint: host_fingerprint(),
        integrity_mode: SignedProfileBundleIntegrityMode::DigestOnlySha256,
        integrity_limitations: vec![
            "digest-only mode; review-only integrity without asymmetric authentication".to_string(),
        ],
        signed_mode_required: false,
        verification_time_unix_seconds: None,
        minimum_bundle_epoch: None,
        trusted_signing_keys: Vec::new(),
        signature: None,
        proof_command_classes: vec![
            "rch_cargo_test".to_string(),
            "smoke_runner".to_string(),
            "shadow_run".to_string(),
        ],
        feature_gates: vec!["governor".to_string(), "capacity_hints".to_string()],
        manual_override_fields: Vec::new(),
        require_operator_confirmation: true,
        profile_bundle_digest: digest('2'),
        final_bundle_digest: digest('3'),
        config_diff_digest: digest('4'),
        previous_config_digest: digest('5'),
        rollback_command_template:
            "offline_tuner apply-profile --profile conservative_baseline --verify-only".to_string(),
        sanitized_operator_note: Some("ticket=OPS-SHADOW api_token=[REDACTED]".to_string()),
        sanitized_validation_command: Some("run_id=SHADOW token=[REDACTED]".to_string()),
        manifest_digest_sha256: digest('6'),
        capacity_certificate_reference: SignedProfileBundleCapacityCertificateReference {
            artifact_id: CAPACITY_CERTIFICATE_ID.to_string(),
            contract_version: "capacity-envelope-planner-smoke-contract-v1".to_string(),
            scenario_id: "AA-CAPACITY-ENVELOPE-LOCALITY-CERT-64C-256G".to_string(),
        },
        controller_versions: versions.clone(),
        supported_controller_versions: versions,
        child_evidence_hashes: evidence_hashes,
    };
    SignedProfileBundleBundle {
        verification: SignedProfileBundleVerificationResult {
            accepted: verification_accepted,
            refusal_reasons: if verification_accepted {
                Vec::new()
            } else {
                vec!["capacity certificate digest lock did not match".to_string()]
            },
            tamper_field: if verification_accepted {
                None
            } else {
                Some("signature.capacity_certificate_digest_sha256".to_string())
            },
            execute_mode: SignedProfileBundleExecutionMode::ShadowRun,
            expected_manifest_digest_sha256: manifest.manifest_digest_sha256.clone(),
            observed_manifest_digest_sha256: manifest.manifest_digest_sha256.clone(),
        },
        rollback_receipt: SignedProfileBundleRollbackReceipt {
            previous_config_digest: manifest.previous_config_digest.clone(),
            applied_bundle_digest: manifest.manifest_digest_sha256.clone(),
            rollback_command_template: manifest.rollback_command_template.clone(),
            fallback_profile: manifest.fallback_profile,
            host_fingerprint: manifest.host_fingerprint.clone(),
            artifact_paths: vec![
                "signed_profile_bundle_manifest.json".to_string(),
                "rollback_receipt.json".to_string(),
                CAPACITY_CERTIFICATE_ID.to_string(),
            ],
            receipt_digest_sha256: digest('7'),
        },
        shadow_run_evaluation: Some(shadow_evaluation(decision)),
        manifest,
    }
}

fn base_request() -> ShadowPromoteRollbackReceiptRequest {
    ShadowPromoteRollbackReceiptRequest {
        scenario_id: DEFAULT_SCENARIO_ID.to_string(),
        candidate_bundle: signed_bundle(SignedProfileBundleShadowRunDecision::Promote, true),
        baseline_bundle_digest_sha256: digest('8'),
        candidate_bundle_digest_sha256: digest('3'),
        baseline_evidence_hash_sha256: digest('9'),
        candidate_evidence_hash_sha256: digest('9'),
        capacity_certificate_id: CAPACITY_CERTIFICATE_ID.to_string(),
        latency_certificate_id: LATENCY_CERTIFICATE_ID.to_string(),
        p99_delta_ns: -120_000,
        p999_delta_ns: -380_000,
        evidence_age_hours: 8,
        max_evidence_age_hours: 24,
        sample_count: 96,
        min_sample_count: 32,
        controller_interference_verdict: Some(ControllerInterferenceTwinVerdict::Pass),
        dirty_artifacts: Vec::new(),
        receipt_path: RECEIPT_PATH.to_string(),
        replay_command:
            "rch exec -- cargo test -p asupersync --test shadow_promote_rollback_receipts_contract"
                .to_string(),
    }
}

fn receipt_json(receipt: &ShadowPromoteRollbackReceipt) -> Value {
    json!({
        "schema_version": receipt.schema_version,
        "scenario_id": receipt.scenario_id,
        "decision": receipt.decision.as_str(),
        "accepted": receipt.accepted,
        "no_win": receipt.no_win,
        "fallback_decision": receipt.fallback_decision,
        "baseline_bundle_digest_sha256": receipt.baseline_bundle_digest_sha256,
        "candidate_bundle_digest_sha256": receipt.candidate_bundle_digest_sha256,
        "candidate_manifest_digest_sha256": receipt.candidate_manifest_digest_sha256,
        "baseline_evidence_hash_sha256": receipt.baseline_evidence_hash_sha256,
        "candidate_evidence_hash_sha256": receipt.candidate_evidence_hash_sha256,
        "capacity_certificate_id": receipt.capacity_certificate_id,
        "latency_certificate_id": receipt.latency_certificate_id,
        "shadow_run_decision": receipt.shadow_run_decision.map(|decision| decision.as_str()),
        "regret_margin_basis_points": receipt.regret_margin_basis_points,
        "p99_delta_ns": receipt.p99_delta_ns,
        "p999_delta_ns": receipt.p999_delta_ns,
        "shadow_hold_reasons": receipt.shadow_hold_reasons,
        "refusal_reasons": receipt.refusal_reasons,
        "rollback_receipt_digest_sha256": receipt.rollback_receipt_digest_sha256,
        "rollback_receipt_path": receipt.rollback_receipt_path,
        "dirty_artifacts": receipt.dirty_artifacts,
        "replay_command": receipt.replay_command,
        "promotion_receipt_digest_sha256": receipt.promotion_receipt_digest_sha256,
    })
}

#[test]
fn shadow_promote_receipt_promotes_clean_candidate() {
    let receipt = base_request().evaluate();

    assert_eq!(
        receipt.schema_version,
        SHADOW_PROMOTE_ROLLBACK_RECEIPT_SCHEMA_VERSION
    );
    assert_eq!(receipt.decision, ShadowPromoteRollbackDecision::Promote);
    assert!(receipt.accepted);
    assert!(!receipt.no_win);
    assert!(receipt.refusal_reasons.is_empty());
    assert_eq!(receipt.fallback_decision, "promote_candidate_bundle");
    assert_eq!(receipt.promotion_receipt_digest_sha256.len(), 64);
}

#[test]
fn shadow_promote_receipt_holds_when_shadow_run_holds() {
    let mut request = base_request();
    request.candidate_bundle = signed_bundle(SignedProfileBundleShadowRunDecision::Hold, true);

    let receipt = request.evaluate();

    assert_eq!(receipt.decision, ShadowPromoteRollbackDecision::Hold);
    assert!(!receipt.accepted);
    assert!(!receipt.no_win);
    assert!(
        receipt
            .refusal_reasons
            .iter()
            .any(|reason| reason.contains("shadow-run gate held"))
    );
}

#[test]
fn shadow_promote_receipt_rolls_back_rejected_bundle() {
    let mut request = base_request();
    request.candidate_bundle = signed_bundle(SignedProfileBundleShadowRunDecision::Promote, false);

    let receipt = request.evaluate();

    assert_eq!(receipt.decision, ShadowPromoteRollbackDecision::Rollback);
    assert!(!receipt.accepted);
    assert!(
        receipt
            .refusal_reasons
            .iter()
            .any(|reason| reason.contains("bundle verification rejected"))
    );
}

#[test]
fn shadow_promote_receipt_uses_no_win_for_stale_evidence() {
    let mut request = base_request();
    request.evidence_age_hours = 72;

    let receipt = request.evaluate();

    assert_eq!(receipt.decision, ShadowPromoteRollbackDecision::NoWin);
    assert!(receipt.no_win);
    assert!(
        receipt
            .refusal_reasons
            .iter()
            .any(|reason| reason.contains("evidence age"))
    );
}

#[test]
fn shadow_promote_receipt_uses_no_win_for_missing_certificate() {
    let mut request = base_request();
    request.capacity_certificate_id.clear();

    let receipt = request.evaluate();

    assert_eq!(receipt.decision, ShadowPromoteRollbackDecision::NoWin);
    assert!(
        receipt
            .refusal_reasons
            .iter()
            .any(|reason| reason.contains("capacity_certificate_id"))
    );
}

#[test]
fn shadow_promote_receipt_uses_no_win_for_controller_interference() {
    let mut request = base_request();
    request.controller_interference_verdict = Some(ControllerInterferenceTwinVerdict::NoWin);

    let receipt = request.evaluate();

    assert_eq!(receipt.decision, ShadowPromoteRollbackDecision::NoWin);
    assert!(
        receipt
            .refusal_reasons
            .iter()
            .any(|reason| reason.contains("controller interference"))
    );
}

#[test]
fn shadow_promote_receipt_is_deterministic() {
    let mut request = base_request();
    request.dirty_artifacts = vec![
        "artifacts/z_dirty.json".to_string(),
        "artifacts/a_dirty.json".to_string(),
        "artifacts/z_dirty.json".to_string(),
    ];
    let mut permuted = request.clone();
    permuted.dirty_artifacts.reverse();

    let receipt = request.evaluate();
    let permuted_receipt = permuted.evaluate();

    assert_eq!(
        receipt.promotion_receipt_digest_sha256,
        permuted_receipt.promotion_receipt_digest_sha256
    );
    assert_eq!(receipt.dirty_artifacts, permuted_receipt.dirty_artifacts);
    assert_eq!(receipt.decision, ShadowPromoteRollbackDecision::NoWin);
}

#[test]
fn shadow_promote_rollback_receipt_smoke_emits_report() {
    let contract = contract();
    assert_eq!(
        contract.contract_version,
        "shadow-promote-rollback-receipts-smoke-contract-v1"
    );
    let scenario = contract
        .smoke_scenarios
        .iter()
        .find(|scenario| scenario.scenario_id == DEFAULT_SCENARIO_ID)
        .expect("default shadow receipt scenario");
    let receipt = base_request().evaluate();
    assert_eq!(receipt.decision.as_str(), scenario.expected_decision);

    let report = receipt_json(&receipt);
    assert_eq!(
        report["schema_version"],
        json!(SHADOW_PROMOTE_ROLLBACK_RECEIPT_SCHEMA_VERSION)
    );
    assert_eq!(report["decision"], json!("promote"));
    assert_eq!(
        report["fallback_decision"],
        json!("promote_candidate_bundle")
    );
    assert_eq!(
        report["capacity_certificate_id"],
        json!(CAPACITY_CERTIFICATE_ID)
    );
    assert_eq!(
        report["latency_certificate_id"],
        json!(LATENCY_CERTIFICATE_ID)
    );
    assert_eq!(report["rollback_receipt_path"], json!(RECEIPT_PATH));
    assert!(
        report["replay_command"]
            .as_str()
            .expect("replay command")
            .contains("rch exec")
    );

    if let Ok(path) = std::env::var("ASUPERSYNC_SHADOW_PROMOTE_ROLLBACK_RECEIPT_PATH") {
        let compact_report = serde_json::to_string(&report).expect("report renders compactly");
        println!("ASUPERSYNC_SHADOW_PROMOTE_ROLLBACK_RECEIPT_JSON={compact_report}");
        if let Some(parent) = Path::new(&path).parent() {
            fs::create_dir_all(parent).expect("report parent directory exists");
        }
        fs::write(
            path,
            serde_json::to_string_pretty(&report).expect("report renders"),
        )
        .expect("report writes");
    }
}
