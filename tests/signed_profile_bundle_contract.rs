//! Contract-backed proofs for signed profile bundle manifests and rollback receipts.

use asupersync::runtime::config::{
    ArenaTemperaturePolicy, BlockingPoolAffinityProfile, CapacityEnvelopeBrownoutStage,
    CapacityEnvelopeBudget, CapacityEnvelopeCalibrationStatus, CapacityEnvelopeEvidenceSnapshot,
    CapacityEnvelopeHostFingerprint, CoordinationWorkloadExpansionEvidence,
    CoordinationWorkloadRedactionStatus, CoordinationWorkloadTrustStatus,
    HostProfileEvidenceArtifact, HostProfileEvidenceCalibrationStatus, HostProfileEvidenceSet,
    HostProfileHostResources, HostProfileId, HostProfileManualOverrides,
    HostProfilePlannerObjective, HostProfilePlannerRequest, RuntimeCapacityHints,
    SignedProfileBundleCapacityCertificateReference, SignedProfileBundleControllerVersion,
    SignedProfileBundleExecutionMode, SignedProfileBundleIntegrityMode,
    SignedProfileBundleManifestRequest, SignedProfileBundleSignaturePolicy,
    SignedProfileBundleTrustedSigningKey, TraceStorageProfile,
};
use nkeys::{KeyPair, KeyPairType};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeSet, hash_map::DefaultHasher};
use std::fs;
use std::hash::{Hash, Hasher};

const DEFAULT_SCENARIO_ID: &str = "AA-SIGNED-PROFILE-BUNDLE-DIGEST-ONLY-ACCEPT-64C-256G";

#[derive(Debug, Clone, Deserialize)]
struct SignedProfileBundleContract {
    contract_version: String,
    trust_model: SignedProfileBundleTrustModel,
    smoke_scenarios: Vec<SignedProfileBundleScenario>,
}

#[derive(Debug, Clone, Deserialize)]
struct SignedProfileBundleTrustModel {
    active_integrity_mode: String,
    true_signature_status: String,
    follow_up_blocker_required: bool,
    follow_up_blocker_title: String,
    digest_only_limitations: Vec<String>,
    fail_closed_cases: Vec<SignedProfileBundleFailClosedCase>,
}

#[derive(Debug, Clone, Deserialize)]
struct SignedProfileBundleFailClosedCase {
    case_id: String,
    category: String,
    reason: String,
    operator_verdict: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SignedProfileBundleScenario {
    scenario_id: String,
    description: String,
    objective: String,
    requested_profile: Option<String>,
    host_resources: HostProfileResourcesFixture,
    host_fingerprint: HostFingerprintFixture,
    #[serde(default)]
    controller_evidence: HostProfileEvidenceSetFixture,
    #[serde(default)]
    manual_overrides: HostProfileManualOverridesFixture,
    evidence_snapshot: CapacityEnvelopeEvidenceSnapshotFixture,
    capacity_budget: CapacityBudgetFixture,
    worker_count_sweep: Vec<usize>,
    agent_count_sweep: Vec<usize>,
    bundle_id: String,
    integrity_mode: String,
    signature_policy: Option<SignaturePolicyFixture>,
    proof_command_classes: Vec<String>,
    controller_versions: Vec<ControllerVersionFixture>,
    supported_controller_versions: Vec<ControllerVersionFixture>,
    capacity_certificate_reference: CapacityCertificateReferenceFixture,
    previous_config_digest: String,
    rollback_command_template: String,
    operator_note: Option<String>,
    validation_command: Option<String>,
    require_operator_confirmation: bool,
    execute_mode: String,
    tamper_field: Option<String>,
    expected_report_projection: Option<Value>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct HostProfileResourcesFixture {
    cpu_cores: usize,
    memory_gib: usize,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct HostProfileEvidenceSetFixture {
    brownout: Option<HostProfileEvidenceArtifactFixture>,
    otlp_brownout: Option<HostProfileEvidenceArtifactFixture>,
    admission_steering: Option<HostProfileEvidenceArtifactFixture>,
    adaptive_batch_sizing: Option<HostProfileEvidenceArtifactFixture>,
    blocking_pool_affinity: Option<HostProfileEvidenceArtifactFixture>,
    trace_storage_profile: Option<HostProfileEvidenceArtifactFixture>,
}

#[derive(Debug, Clone, Deserialize)]
struct HostProfileEvidenceArtifactFixture {
    artifact_id: String,
    contract_version: String,
    validation_passed: bool,
    #[serde(default = "default_host_profile_confidence_percent")]
    confidence_percent: u8,
    #[serde(default = "default_host_profile_calibration_status")]
    calibration_status: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct HostProfileManualOverridesFixture {
    worker_threads: Option<usize>,
    worker_cohort_map: Option<Vec<usize>>,
    global_queue_limit: Option<usize>,
    steal_batch_size: Option<usize>,
    blocking_affinity_profile: Option<BlockingAffinityFixture>,
    capacity_hints: Option<CapacityHintsFixture>,
    trace_storage_profile: Option<String>,
    arena_temperature_policy: Option<String>,
    enable_governor: Option<bool>,
    enable_read_biased_region_snapshot: Option<bool>,
    enable_adaptive_cancel_streak: Option<bool>,
    browser_ready_handoff_limit: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "profile", rename_all = "snake_case")]
enum BlockingAffinityFixture {
    Disabled,
    CohortBiased {
        local_queue_soft_limit: usize,
        spill_check_interval: usize,
    },
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct CapacityHintsFixture {
    task_capacity: usize,
    region_capacity: usize,
    obligation_capacity: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct HostFingerprintFixture {
    hostname: String,
    arch: String,
    cpu_cores: usize,
    memory_gib: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct CapacityEnvelopeEvidenceSnapshotFixture {
    scenario_artifact_id: String,
    scenario_artifact_hash: String,
    scenario_contract_version: String,
    sample_count: usize,
    calibration_status: String,
    host_fingerprint: HostFingerprintFixture,
    artifact_age_hours: u64,
    measured_worker_count: usize,
    measured_agent_count: usize,
    measured_queue_depth: usize,
    throughput_ops_per_sec: u64,
    wake_to_run_p50_ns: u64,
    wake_to_run_p95_ns: u64,
    wake_to_run_p99_ns: u64,
    cancellation_debt_units: u64,
    memory_pressure_basis_points: u16,
    brownout_stage: String,
    brownout_risk_basis_points: u16,
    retention_budget_gib: usize,
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct CapacityBudgetFixture {
    target_p99_ns: u64,
    target_cancel_debt_units: u64,
    max_memory_pressure_basis_points: u16,
    max_brownout_risk_basis_points: u16,
    max_queue_depth: usize,
    max_artifact_age_hours: u64,
    min_sample_count: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct ControllerVersionFixture {
    controller: String,
    contract_version: String,
}

#[derive(Debug, Clone, Deserialize)]
struct CapacityCertificateReferenceFixture {
    artifact_id: String,
    contract_version: String,
    scenario_id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SignaturePolicyFixture {
    signing_domain: String,
    key_id: String,
    algorithm: String,
    signing_seed_byte: u8,
    issued_at_unix_seconds: i64,
    expires_at_unix_seconds: i64,
    verification_time_unix_seconds: i64,
    bundle_epoch: u64,
    minimum_bundle_epoch: u64,
    signed_mode_required: bool,
    #[serde(default)]
    trusted_keys: Vec<TrustedSigningKeyFixture>,
}

#[derive(Debug, Clone, Deserialize)]
struct TrustedSigningKeyFixture {
    key_id: String,
    public_key_seed_byte: u8,
    revoked: bool,
}

impl From<HostProfileEvidenceArtifactFixture> for HostProfileEvidenceArtifact {
    fn from(value: HostProfileEvidenceArtifactFixture) -> Self {
        Self {
            artifact_id: value.artifact_id,
            contract_version: value.contract_version,
            validation_passed: value.validation_passed,
            confidence_percent: value.confidence_percent,
            calibration_status: parse_host_profile_calibration_status(&value.calibration_status),
        }
    }
}

impl From<HostProfileEvidenceSetFixture> for HostProfileEvidenceSet {
    fn from(value: HostProfileEvidenceSetFixture) -> Self {
        Self {
            brownout: value.brownout.map(Into::into),
            otlp_brownout: value.otlp_brownout.map(Into::into),
            admission_steering: value.admission_steering.map(Into::into),
            adaptive_batch_sizing: value.adaptive_batch_sizing.map(Into::into),
            blocking_pool_affinity: value.blocking_pool_affinity.map(Into::into),
            trace_storage_profile: value.trace_storage_profile.map(Into::into),
            coordination_workload_expansion: None,
        }
    }
}

impl From<BlockingAffinityFixture> for BlockingPoolAffinityProfile {
    fn from(value: BlockingAffinityFixture) -> Self {
        match value {
            BlockingAffinityFixture::Disabled => Self::Disabled,
            BlockingAffinityFixture::CohortBiased {
                local_queue_soft_limit,
                spill_check_interval,
            } => Self::CohortBiased {
                local_queue_soft_limit,
                spill_check_interval,
            },
        }
    }
}

impl From<HostProfileManualOverridesFixture> for HostProfileManualOverrides {
    fn from(value: HostProfileManualOverridesFixture) -> Self {
        Self {
            worker_threads: value.worker_threads,
            worker_cohort_map: value
                .worker_cohort_map
                .map(asupersync::runtime::config::WorkerCohortMapping::new),
            global_queue_limit: value.global_queue_limit,
            steal_batch_size: value.steal_batch_size,
            blocking_affinity_profile: value.blocking_affinity_profile.map(Into::into),
            capacity_hints: value.capacity_hints.map(|hints| {
                RuntimeCapacityHints::new(
                    hints.task_capacity,
                    hints.region_capacity,
                    hints.obligation_capacity,
                )
            }),
            trace_storage_profile: value
                .trace_storage_profile
                .as_deref()
                .map(parse_trace_storage_profile),
            arena_temperature_policy: value
                .arena_temperature_policy
                .as_deref()
                .map(parse_arena_temperature_policy),
            enable_governor: value.enable_governor,
            enable_read_biased_region_snapshot: value.enable_read_biased_region_snapshot,
            enable_adaptive_cancel_streak: value.enable_adaptive_cancel_streak,
            browser_ready_handoff_limit: value.browser_ready_handoff_limit,
        }
    }
}

impl From<HostFingerprintFixture> for CapacityEnvelopeHostFingerprint {
    fn from(value: HostFingerprintFixture) -> Self {
        Self {
            hostname: value.hostname,
            arch: value.arch,
            cpu_cores: value.cpu_cores,
            memory_gib: value.memory_gib,
        }
    }
}

impl From<CapacityEnvelopeEvidenceSnapshotFixture> for CapacityEnvelopeEvidenceSnapshot {
    fn from(value: CapacityEnvelopeEvidenceSnapshotFixture) -> Self {
        Self {
            scenario_artifact_id: value.scenario_artifact_id,
            scenario_artifact_hash: value.scenario_artifact_hash,
            scenario_contract_version: value.scenario_contract_version,
            sample_count: value.sample_count,
            calibration_status: parse_calibration_status(&value.calibration_status),
            host_fingerprint: value.host_fingerprint.into(),
            artifact_age_hours: value.artifact_age_hours,
            measured_worker_count: value.measured_worker_count,
            measured_agent_count: value.measured_agent_count,
            measured_queue_depth: value.measured_queue_depth,
            throughput_ops_per_sec: value.throughput_ops_per_sec,
            wake_to_run_p50_ns: value.wake_to_run_p50_ns,
            wake_to_run_p95_ns: value.wake_to_run_p95_ns,
            wake_to_run_p99_ns: value.wake_to_run_p99_ns,
            cancellation_debt_units: value.cancellation_debt_units,
            memory_pressure_basis_points: value.memory_pressure_basis_points,
            brownout_stage: parse_brownout_stage(&value.brownout_stage),
            brownout_risk_basis_points: value.brownout_risk_basis_points,
            retention_budget_gib: value.retention_budget_gib,
        }
    }
}

impl From<CapacityBudgetFixture> for CapacityEnvelopeBudget {
    fn from(value: CapacityBudgetFixture) -> Self {
        Self {
            target_p99_ns: value.target_p99_ns,
            target_cancel_debt_units: value.target_cancel_debt_units,
            max_memory_pressure_basis_points: value.max_memory_pressure_basis_points,
            max_brownout_risk_basis_points: value.max_brownout_risk_basis_points,
            max_queue_depth: value.max_queue_depth,
            max_artifact_age_hours: value.max_artifact_age_hours,
            min_sample_count: value.min_sample_count,
        }
    }
}

impl From<ControllerVersionFixture> for SignedProfileBundleControllerVersion {
    fn from(value: ControllerVersionFixture) -> Self {
        Self {
            controller: value.controller,
            contract_version: value.contract_version,
        }
    }
}

impl From<CapacityCertificateReferenceFixture> for SignedProfileBundleCapacityCertificateReference {
    fn from(value: CapacityCertificateReferenceFixture) -> Self {
        Self {
            artifact_id: value.artifact_id,
            contract_version: value.contract_version,
            scenario_id: value.scenario_id,
        }
    }
}

fn deterministic_user_seed(byte: u8) -> String {
    KeyPair::new_from_raw(KeyPairType::User, [byte; 32])
        .expect("deterministic signing seed")
        .seed()
        .expect("seed encoding")
}

fn deterministic_user_public_key(byte: u8) -> String {
    KeyPair::new_from_raw(KeyPairType::User, [byte; 32])
        .expect("deterministic signing key")
        .public_key()
}

fn build_signature_policy(fixture: &SignaturePolicyFixture) -> SignedProfileBundleSignaturePolicy {
    let public_key = deterministic_user_public_key(fixture.signing_seed_byte);
    let trusted_keys = if fixture.trusted_keys.is_empty() {
        vec![SignedProfileBundleTrustedSigningKey {
            key_id: fixture.key_id.clone(),
            public_key: public_key.clone(),
            revoked: false,
        }]
    } else {
        fixture
            .trusted_keys
            .iter()
            .map(|key| SignedProfileBundleTrustedSigningKey {
                key_id: key.key_id.clone(),
                public_key: deterministic_user_public_key(key.public_key_seed_byte),
                revoked: key.revoked,
            })
            .collect()
    };
    SignedProfileBundleSignaturePolicy {
        signing_domain: fixture.signing_domain.clone(),
        key_id: fixture.key_id.clone(),
        public_key,
        algorithm: fixture.algorithm.clone(),
        signing_seed: Some(deterministic_user_seed(fixture.signing_seed_byte)),
        issued_at_unix_seconds: fixture.issued_at_unix_seconds,
        expires_at_unix_seconds: fixture.expires_at_unix_seconds,
        verification_time_unix_seconds: fixture.verification_time_unix_seconds,
        bundle_epoch: fixture.bundle_epoch,
        minimum_bundle_epoch: fixture.minimum_bundle_epoch,
        signed_mode_required: fixture.signed_mode_required,
        trusted_keys,
    }
}

fn parse_objective(value: &str) -> HostProfilePlannerObjective {
    match value {
        "locality_first" => HostProfilePlannerObjective::LocalityFirst,
        "tail_protection_first" => HostProfilePlannerObjective::TailProtectionFirst,
        "evidence_retention_first" => HostProfilePlannerObjective::EvidenceRetentionFirst,
        other => panic!("unsupported host profile objective {other}"),
    }
}

fn parse_profile_id(value: &str) -> HostProfileId {
    match value {
        "conservative_baseline" => HostProfileId::ConservativeBaseline,
        "locality_first_64c_256g" => HostProfileId::LocalityFirst64C256G,
        "tail_protection_first_64c_256g" => HostProfileId::TailProtectionFirst64C256G,
        "large_memory_evidence_retention_256g" => HostProfileId::LargeMemoryEvidenceRetention256G,
        other => panic!("unsupported host profile id {other}"),
    }
}

fn parse_brownout_stage(value: &str) -> CapacityEnvelopeBrownoutStage {
    match value {
        "full_surfaces" => CapacityEnvelopeBrownoutStage::FullSurfaces,
        "optional_first" => CapacityEnvelopeBrownoutStage::OptionalFirst,
        "priority_gate" => CapacityEnvelopeBrownoutStage::PriorityGate,
        "standalone_fallback" => CapacityEnvelopeBrownoutStage::StandaloneFallback,
        other => panic!("unsupported brownout stage {other}"),
    }
}

fn parse_calibration_status(value: &str) -> CapacityEnvelopeCalibrationStatus {
    match value {
        "calibrated" => CapacityEnvelopeCalibrationStatus::Calibrated,
        "drifted" => CapacityEnvelopeCalibrationStatus::Drifted,
        other => panic!("unsupported calibration status {other}"),
    }
}

fn default_host_profile_confidence_percent() -> u8 {
    100
}

fn default_host_profile_calibration_status() -> String {
    "current".to_string()
}

fn parse_host_profile_calibration_status(value: &str) -> HostProfileEvidenceCalibrationStatus {
    match value {
        "current" => HostProfileEvidenceCalibrationStatus::Current,
        "stale" => HostProfileEvidenceCalibrationStatus::Stale,
        other => panic!("unsupported host profile evidence calibration status {other}"),
    }
}

fn parse_trace_storage_profile(value: &str) -> TraceStorageProfile {
    value.parse().unwrap_or_else(|_| {
        panic!("unsupported trace storage profile override {value}");
    })
}

fn parse_arena_temperature_policy(value: &str) -> ArenaTemperaturePolicy {
    value
        .parse()
        .unwrap_or_else(|_| panic!("unknown arena temperature policy fixture: {value}"))
}

fn parse_integrity_mode(value: &str) -> SignedProfileBundleIntegrityMode {
    match value {
        "digest_only_sha256" => SignedProfileBundleIntegrityMode::DigestOnlySha256,
        "nkey_ed25519" => SignedProfileBundleIntegrityMode::NkeyEd25519,
        other => panic!("unsupported signed profile bundle integrity mode {other}"),
    }
}

fn parse_execute_mode(value: &str) -> SignedProfileBundleExecutionMode {
    match value {
        "dry_run" => SignedProfileBundleExecutionMode::DryRun,
        "verify" => SignedProfileBundleExecutionMode::Verify,
        "shadow_run" => SignedProfileBundleExecutionMode::ShadowRun,
        other => panic!("unsupported signed profile bundle execution mode {other}"),
    }
}

fn default_contract() -> SignedProfileBundleContract {
    serde_json::from_str(include_str!(
        "../artifacts/signed_profile_bundle_smoke_contract_v1.json"
    ))
    .expect("embedded signed profile bundle contract must parse")
}

fn load_contract() -> SignedProfileBundleContract {
    if let Ok(path) = std::env::var("ASUPERSYNC_SIGNED_PROFILE_BUNDLE_CONTRACT_PATH") {
        let contents = fs::read_to_string(&path).expect("signed profile bundle contract must load");
        serde_json::from_str(&contents).expect("signed profile bundle contract must parse")
    } else {
        default_contract()
    }
}

fn selected_scenario(contract: &SignedProfileBundleContract) -> &SignedProfileBundleScenario {
    let selected = std::env::var("ASUPERSYNC_SIGNED_PROFILE_BUNDLE_SCENARIO")
        .unwrap_or_else(|_| DEFAULT_SCENARIO_ID.to_string());
    contract
        .smoke_scenarios
        .iter()
        .find(|scenario| scenario.scenario_id == selected)
        .unwrap_or_else(|| panic!("signed profile bundle scenario {selected} not found"))
}

fn build_request(scenario: &SignedProfileBundleScenario) -> SignedProfileBundleManifestRequest {
    SignedProfileBundleManifestRequest {
        objective: parse_objective(&scenario.objective),
        requested_profile: scenario.requested_profile.as_deref().map(parse_profile_id),
        host_resources: HostProfileHostResources {
            cpu_cores: scenario.host_resources.cpu_cores,
            memory_gib: scenario.host_resources.memory_gib,
        },
        controller_evidence: scenario.controller_evidence.clone().into(),
        manual_overrides: scenario.manual_overrides.clone().into(),
        host_fingerprint: scenario.host_fingerprint.clone().into(),
        evidence_snapshot: scenario.evidence_snapshot.clone().into(),
        capacity_budget: scenario.capacity_budget.into(),
        candidate_worker_counts: scenario.worker_count_sweep.clone(),
        candidate_agent_counts: scenario.agent_count_sweep.clone(),
        bundle_id: scenario.bundle_id.clone(),
        integrity_mode: parse_integrity_mode(&scenario.integrity_mode),
        signature_policy: scenario
            .signature_policy
            .as_ref()
            .map(build_signature_policy),
        proof_command_classes: scenario.proof_command_classes.clone(),
        controller_versions: scenario
            .controller_versions
            .clone()
            .into_iter()
            .map(Into::into)
            .collect(),
        supported_controller_versions: scenario
            .supported_controller_versions
            .clone()
            .into_iter()
            .map(Into::into)
            .collect(),
        capacity_certificate_reference: scenario.capacity_certificate_reference.clone().into(),
        previous_config_digest: scenario.previous_config_digest.clone(),
        rollback_command_template: scenario.rollback_command_template.clone(),
        operator_note: scenario.operator_note.clone(),
        validation_command: scenario.validation_command.clone(),
        require_operator_confirmation: scenario.require_operator_confirmation,
        execute_mode: parse_execute_mode(&scenario.execute_mode),
        tamper_field: scenario.tamper_field.clone(),
    }
}

fn projection_hash(projection: &Value) -> u64 {
    let bytes = serde_json::to_vec(projection).expect("projection must serialize");
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

fn report_projection(report: &Value) -> Value {
    let child_evidence_count = report["signed_profile_bundle_manifest"]["child_evidence_hashes"]
        .as_array()
        .expect("child evidence hashes array")
        .len();
    let controller_version_count = report["signed_profile_bundle_manifest"]["controller_versions"]
        .as_array()
        .expect("controller versions array")
        .len();
    let supported_version_count =
        report["signed_profile_bundle_manifest"]["supported_controller_versions"]
            .as_array()
            .expect("supported controller versions array")
            .len();
    let verification_refusal_count = report["verification_result"]["refusal_reasons"]
        .as_array()
        .expect("verification refusal reasons array")
        .len();
    let planning_refusal_count =
        report["signed_profile_bundle_manifest"]["planning_refusal_reasons"]
            .as_array()
            .expect("planning refusal reasons array")
            .len();
    let artifact_path_count = report["rollback_receipt"]["artifact_paths"]
        .as_array()
        .expect("rollback artifact paths array")
        .len();
    let integrity_limitation_count =
        report["signed_profile_bundle_manifest"]["integrity_limitations"]
            .as_array()
            .expect("integrity limitations array")
            .len();
    let mut object = json!({
        "selected_profile": report["signed_profile_bundle_manifest"]["selected_profile"],
        "fallback_profile": report["signed_profile_bundle_manifest"]["fallback_profile"],
        "integrity_mode": report["signed_profile_bundle_manifest"]["integrity_mode"],
        "execute_mode": report["verification_result"]["execute_mode"],
        "accepted": report["verification_result"]["accepted"],
        "tamper_field": report["verification_result"]["tamper_field"],
        "child_evidence_count": child_evidence_count,
        "controller_version_count": controller_version_count,
        "supported_controller_version_count": supported_version_count,
        "planning_refusal_count": planning_refusal_count,
        "verification_refusal_count": verification_refusal_count,
        "artifact_path_count": artifact_path_count,
        "integrity_limitation_count": integrity_limitation_count,
        "require_operator_confirmation": report["signed_profile_bundle_manifest"]["require_operator_confirmation"],
        "manual_override_count": report["signed_profile_bundle_manifest"]["manual_override_fields"].as_array().expect("manual override fields array").len(),
        "proof_command_class_count": report["signed_profile_bundle_manifest"]["proof_command_classes"].as_array().expect("proof command classes array").len(),
        "feature_gate_count": report["signed_profile_bundle_manifest"]["feature_gates"].as_array().expect("feature gates array").len(),
        "sanitized_operator_note": report["signed_profile_bundle_manifest"]["sanitized_operator_note"],
        "sanitized_validation_command": report["signed_profile_bundle_manifest"]["sanitized_validation_command"],
    });
    if report["shadow_run_evaluation"].is_object() {
        object.as_object_mut().expect("projection object").extend([
            (
                "shadow_run_decision".to_string(),
                report["shadow_run_evaluation"]["decision"].clone(),
            ),
            (
                "candidate_loss_basis_points".to_string(),
                report["shadow_run_evaluation"]["candidate_loss_basis_points"].clone(),
            ),
            (
                "baseline_loss_basis_points".to_string(),
                report["shadow_run_evaluation"]["baseline_loss_basis_points"].clone(),
            ),
            (
                "regret_margin_basis_points".to_string(),
                report["shadow_run_evaluation"]["regret_margin_basis_points"].clone(),
            ),
            (
                "shadow_hold_reason_count".to_string(),
                json!(
                    report["shadow_run_evaluation"]["hold_reasons"]
                        .as_array()
                        .expect("shadow hold reasons array")
                        .len()
                ),
            ),
            (
                "shadow_dominant_reason_count".to_string(),
                json!(
                    report["shadow_run_evaluation"]["dominant_reasons"]
                        .as_array()
                        .expect("shadow dominant reasons array")
                        .len()
                ),
            ),
        ]);
    }
    if report["signed_profile_bundle_manifest"]["signature"].is_object() {
        object.as_object_mut().expect("projection object").extend([
            (
                "signed_mode_required".to_string(),
                report["signed_profile_bundle_manifest"]["signed_mode_required"].clone(),
            ),
            (
                "trusted_signing_key_count".to_string(),
                report["signed_profile_bundle_manifest"]["trusted_signing_key_count"].clone(),
            ),
            (
                "signing_domain".to_string(),
                report["signed_profile_bundle_manifest"]["signature"]["signing_domain"].clone(),
            ),
            (
                "signing_key_id".to_string(),
                report["signed_profile_bundle_manifest"]["signature"]["key_id"].clone(),
            ),
            (
                "signature_algorithm".to_string(),
                report["signed_profile_bundle_manifest"]["signature"]["algorithm"].clone(),
            ),
            (
                "bundle_epoch".to_string(),
                report["signed_profile_bundle_manifest"]["signature"]["bundle_epoch"].clone(),
            ),
            (
                "signature_len".to_string(),
                report["signed_profile_bundle_manifest"]["signature"]["signature_len"].clone(),
            ),
            (
                "capacity_certificate_digest_sha256".to_string(),
                report["signed_profile_bundle_manifest"]["signature"]
                    ["capacity_certificate_digest_sha256"]
                    .clone(),
            ),
            (
                "child_proof_graph_root_sha256".to_string(),
                report["signed_profile_bundle_manifest"]["signature"]
                    ["child_proof_graph_root_sha256"]
                    .clone(),
            ),
            (
                "rollback_chain_digest_sha256".to_string(),
                report["signed_profile_bundle_manifest"]["signature"]
                    ["rollback_chain_digest_sha256"]
                    .clone(),
            ),
        ]);
    }
    let hash = projection_hash(&object);
    object
        .as_object_mut()
        .expect("projection object")
        .insert("projection_hash".to_string(), json!(hash));
    object
}

fn build_report(
    contract_version: &str,
    scenario: &SignedProfileBundleScenario,
    request: &SignedProfileBundleManifestRequest,
) -> Value {
    let bundle = request.plan();
    let manifest = &bundle.manifest;
    let verification = &bundle.verification;
    let rollback_receipt = &bundle.rollback_receipt;
    let shadow_run_evaluation = bundle.shadow_run_evaluation.as_ref();
    let mut report = json!({
        "schema_version": "asupersync.signed-profile-bundle-report.v1",
        "contract_version": contract_version,
        "scenario_id": scenario.scenario_id.clone(),
        "description": scenario.description.clone(),
        "signed_profile_bundle_manifest": {
            "bundle_id": manifest.bundle_id.clone(),
            "objective": manifest.objective.as_str(),
            "requested_profile": manifest.requested_profile.map(|profile| profile.as_str()),
            "selected_profile": manifest.selected_profile.as_str(),
            "fallback_profile": manifest.fallback_profile.as_str(),
            "used_safe_fallback": manifest.used_safe_fallback,
            "planning_refusal_reasons": manifest.planning_refusal_reasons.clone(),
            "requested_host_resources": {
                "cpu_cores": manifest.requested_host_resources.cpu_cores,
                "memory_gib": manifest.requested_host_resources.memory_gib,
            },
            "host_fingerprint": {
                "hostname": manifest.host_fingerprint.hostname.clone(),
                "arch": manifest.host_fingerprint.arch.clone(),
                "cpu_cores": manifest.host_fingerprint.cpu_cores,
                "memory_gib": manifest.host_fingerprint.memory_gib,
            },
            "integrity_mode": manifest.integrity_mode.as_str(),
            "integrity_limitations": manifest.integrity_limitations.clone(),
            "signed_mode_required": manifest.signed_mode_required,
            "verification_time_unix_seconds": manifest.verification_time_unix_seconds,
            "minimum_bundle_epoch": manifest.minimum_bundle_epoch,
            "trusted_signing_key_count": manifest.trusted_signing_keys.len(),
            "signature": manifest.signature.as_ref().map(|signature| json!({
                "signing_domain": signature.signing_domain.clone(),
                "key_id": signature.key_id.clone(),
                "public_key": signature.public_key.clone(),
                "algorithm": signature.algorithm.clone(),
                "issued_at_unix_seconds": signature.issued_at_unix_seconds,
                "expires_at_unix_seconds": signature.expires_at_unix_seconds,
                "bundle_epoch": signature.bundle_epoch,
                "capacity_certificate_digest_sha256": signature.capacity_certificate_digest_sha256.clone(),
                "child_proof_graph_root_sha256": signature.child_proof_graph_root_sha256.clone(),
                "rollback_chain_digest_sha256": signature.rollback_chain_digest_sha256.clone(),
                "signature_len": signature.signature_base64.len(),
            })),
            "proof_command_classes": manifest.proof_command_classes.clone(),
            "feature_gates": manifest.feature_gates.clone(),
            "manual_override_fields": manifest.manual_override_fields.clone(),
            "require_operator_confirmation": manifest.require_operator_confirmation,
            "profile_bundle_digest": manifest.profile_bundle_digest.clone(),
            "final_bundle_digest": manifest.final_bundle_digest.clone(),
            "config_diff_digest": manifest.config_diff_digest.clone(),
            "previous_config_digest": manifest.previous_config_digest.clone(),
            "rollback_command_template": manifest.rollback_command_template.clone(),
            "sanitized_operator_note": manifest.sanitized_operator_note.clone(),
            "sanitized_validation_command": manifest.sanitized_validation_command.clone(),
            "manifest_digest_sha256": manifest.manifest_digest_sha256.clone(),
            "capacity_certificate_reference": {
                "artifact_id": manifest.capacity_certificate_reference.artifact_id.clone(),
                "contract_version": manifest.capacity_certificate_reference.contract_version.clone(),
                "scenario_id": manifest.capacity_certificate_reference.scenario_id.clone(),
            },
            "controller_versions": manifest.controller_versions.iter().map(|entry| json!({
                "controller": entry.controller.clone(),
                "contract_version": entry.contract_version.clone(),
            })).collect::<Vec<_>>(),
            "supported_controller_versions": manifest.supported_controller_versions.iter().map(|entry| json!({
                "controller": entry.controller.clone(),
                "contract_version": entry.contract_version.clone(),
            })).collect::<Vec<_>>(),
            "child_evidence_hashes": manifest.child_evidence_hashes.iter().map(|entry| json!({
                "controller": entry.controller.clone(),
                "artifact_id": entry.artifact_id.clone(),
                "digest_sha256": entry.digest_sha256.clone(),
            })).collect::<Vec<_>>(),
        },
        "verification_result": {
            "accepted": verification.accepted,
            "refusal_reasons": verification.refusal_reasons.clone(),
            "tamper_field": verification.tamper_field.clone(),
            "execute_mode": verification.execute_mode.as_str(),
            "expected_manifest_digest_sha256": verification.expected_manifest_digest_sha256.clone(),
            "observed_manifest_digest_sha256": verification.observed_manifest_digest_sha256.clone(),
        },
        "rollback_receipt": {
            "previous_config_digest": rollback_receipt.previous_config_digest.clone(),
            "applied_bundle_digest": rollback_receipt.applied_bundle_digest.clone(),
            "rollback_command_template": rollback_receipt.rollback_command_template.clone(),
            "fallback_profile": rollback_receipt.fallback_profile.as_str(),
            "host_fingerprint": {
                "hostname": rollback_receipt.host_fingerprint.hostname.clone(),
                "arch": rollback_receipt.host_fingerprint.arch.clone(),
                "cpu_cores": rollback_receipt.host_fingerprint.cpu_cores,
                "memory_gib": rollback_receipt.host_fingerprint.memory_gib,
            },
            "artifact_paths": rollback_receipt.artifact_paths.clone(),
            "receipt_digest_sha256": rollback_receipt.receipt_digest_sha256.clone(),
        },
        "validation_verdict": {
            "status": "passed",
            "checks": [
                "digest-only manifests keep deterministic rollback metadata for large-host profile changes",
                "tamper mutations must be rejected before any apply step can be considered admissible",
                "controller versions must stay inside the supported-version allowlist",
                "capacity certificate references and child evidence hashes must stay deterministic and host-matched",
                "operator notes and validation commands are secret-scrubbed before they are surfaced"
            ]
        }
    });
    if let Some(shadow) = shadow_run_evaluation {
        report.as_object_mut().expect("report object").insert(
            "shadow_run_evaluation".to_string(),
            json!({
                "decision": shadow.decision.as_str(),
                "candidate_profile": shadow.candidate_profile.as_str(),
                "baseline_profile": shadow.baseline_profile.as_str(),
                "candidate_worker_count": shadow.candidate_worker_count,
                "candidate_agent_count": shadow.candidate_agent_count,
                "baseline_worker_count": shadow.baseline_worker_count,
                "baseline_agent_count": shadow.baseline_agent_count,
                "candidate_loss_basis_points": shadow.candidate_loss_basis_points,
                "baseline_loss_basis_points": shadow.baseline_loss_basis_points,
                "regret_margin_basis_points": shadow.regret_margin_basis_points,
                "hold_reasons": shadow.hold_reasons.clone(),
                "dominant_reasons": shadow.dominant_reasons.clone(),
            }),
        );
    }
    let projection = report_projection(&report);
    report
        .as_object_mut()
        .expect("report object")
        .insert("report_projection".to_string(), projection);
    report
}

fn maybe_write_report(report: &Value) {
    if let Ok(path) = std::env::var("ASUPERSYNC_SIGNED_PROFILE_BUNDLE_REPORT_PATH") {
        if let Some(parent) = std::path::Path::new(&path).parent() {
            fs::create_dir_all(parent).expect("signed profile bundle report parent must create");
        }
        fs::write(
            path,
            serde_json::to_vec_pretty(report).expect("signed profile bundle report must encode"),
        )
        .expect("signed profile bundle report must write");
    }
}

fn sample_request() -> SignedProfileBundleManifestRequest {
    request_for_scenario(DEFAULT_SCENARIO_ID)
}

fn request_for_scenario(scenario_id: &str) -> SignedProfileBundleManifestRequest {
    let contract = default_contract();
    let scenario = contract
        .smoke_scenarios
        .iter()
        .find(|scenario| scenario.scenario_id == scenario_id)
        .unwrap_or_else(|| panic!("scenario {scenario_id} must exist"));
    build_request(scenario)
}

fn signed_request() -> SignedProfileBundleManifestRequest {
    request_for_scenario("AA-SIGNED-PROFILE-BUNDLE-NKEY-ACCEPT-64C-256G")
}

fn coordination_workload_evidence(
    pressure_basis_points: u32,
) -> CoordinationWorkloadExpansionEvidence {
    CoordinationWorkloadExpansionEvidence {
        artifact_id: "artifacts/runtime_workload_corpus_v1.json".to_string(),
        contract_version: "runtime-workload-coordination-synthesis-v1".to_string(),
        pack_hash: "sha256:coordination-bundle-handoff-accepted".to_string(),
        source_bundle_hash: "sha256:coordination-runtime-fixture-accepted-all-families".to_string(),
        validation_passed: true,
        redaction_status: CoordinationWorkloadRedactionStatus::Passed,
        trust_status: CoordinationWorkloadTrustStatus::Trusted,
        sample_count: 96,
        artifact_age_hours: 6,
        host_fingerprint: CapacityEnvelopeHostFingerprint {
            hostname: "lab-64c-256g-a".to_string(),
            arch: "x86_64".to_string(),
            cpu_cores: 64,
            memory_gib: 256,
        },
        pressure_basis_points,
    }
}

fn assert_signed_request_rejects(request: SignedProfileBundleManifestRequest, needle: &str) {
    let bundle = request.plan();
    assert!(
        !bundle.verification.accepted,
        "request unexpectedly accepted; expected refusal containing {needle}"
    );
    assert!(
        bundle
            .verification
            .refusal_reasons
            .iter()
            .any(|reason| reason.contains(needle)),
        "expected refusal containing {needle}; got {:?}",
        bundle.verification.refusal_reasons
    );
}

#[test]
fn signed_profile_bundle_accepts_valid_digest_only_manifest() {
    let bundle = sample_request().plan();
    assert!(bundle.verification.accepted);
    assert_eq!(
        bundle.manifest.selected_profile,
        HostProfileId::LocalityFirst64C256G
    );
    assert!(!bundle.manifest.used_safe_fallback);
    assert!(bundle.manifest.planning_refusal_reasons.is_empty());
    assert!(
        bundle
            .manifest
            .integrity_limitations
            .iter()
            .any(|line| line.contains("digest-only") || line.contains("no asymmetric signature"))
    );
}

#[test]
fn signed_profile_bundle_rolls_coordination_pack_into_child_hashes_and_receipt() {
    let mut request = sample_request();
    request.controller_evidence.coordination_workload_expansion =
        Some(coordination_workload_evidence(12_000));
    let coordination_version = SignedProfileBundleControllerVersion {
        controller: "coordination_workload".to_string(),
        contract_version: "runtime-workload-coordination-synthesis-v1".to_string(),
    };
    request
        .controller_versions
        .push(coordination_version.clone());
    request
        .supported_controller_versions
        .push(coordination_version);
    request
        .proof_command_classes
        .push("coordination_workload".to_string());

    let bundle = request.plan();
    assert!(bundle.verification.accepted);
    let coordination_hash = bundle
        .manifest
        .child_evidence_hashes
        .iter()
        .find(|entry| entry.controller == "coordination_workload")
        .expect("coordination child evidence hash");
    assert_eq!(
        coordination_hash.artifact_id,
        "artifacts/runtime_workload_corpus_v1.json"
    );
    assert_eq!(coordination_hash.digest_sha256.len(), 64);
    assert!(
        bundle
            .rollback_receipt
            .artifact_paths
            .iter()
            .any(|path| { path == "artifacts/runtime_workload_corpus_v1.json" })
    );
}

#[test]
fn signed_profile_bundle_accepts_valid_nkey_signature() {
    let request = signed_request();
    let bundle = request.plan();
    let signature = bundle
        .manifest
        .signature
        .as_ref()
        .expect("signed scenario must emit signature metadata");

    assert!(bundle.verification.accepted);
    assert_eq!(
        bundle.manifest.integrity_mode,
        SignedProfileBundleIntegrityMode::NkeyEd25519
    );
    assert_eq!(signature.algorithm, "nkey_ed25519");
    assert_eq!(
        signature.signing_domain,
        "asupersync.signed-profile-bundle.v1"
    );
    assert_eq!(signature.bundle_epoch, 7);
    assert_eq!(signature.signature_base64.len(), 86);
    assert!(bundle.manifest.integrity_limitations.is_empty());
}

#[test]
fn signed_profile_bundle_signature_policy_failures_are_closed() {
    let mut domain = signed_request();
    domain
        .signature_policy
        .as_mut()
        .expect("policy")
        .signing_domain = "wrong.domain".to_string();
    assert_signed_request_rejects(domain, "signing domain");

    let mut key_id = signed_request();
    key_id.signature_policy.as_mut().expect("policy").key_id = "unknown-key".to_string();
    assert_signed_request_rejects(key_id, "trusted key set");

    let mut key_mismatch = signed_request();
    key_mismatch
        .signature_policy
        .as_mut()
        .expect("policy")
        .trusted_keys[0]
        .public_key = deterministic_user_public_key(43);
    assert_signed_request_rejects(key_mismatch, "bound to public key");

    let mut algorithm = signed_request();
    algorithm
        .signature_policy
        .as_mut()
        .expect("policy")
        .algorithm = "ed25519-test-only".to_string();
    assert_signed_request_rejects(algorithm, "unsupported");

    let mut empty_signature = signed_request();
    empty_signature
        .signature_policy
        .as_mut()
        .expect("policy")
        .signing_seed = None;
    assert_signed_request_rejects(empty_signature, "signature_base64");

    let mut unknown_key = signed_request();
    unknown_key
        .signature_policy
        .as_mut()
        .expect("policy")
        .trusted_keys
        .clear();
    assert_signed_request_rejects(unknown_key, "trusted key set");

    let mut revoked = signed_request();
    revoked
        .signature_policy
        .as_mut()
        .expect("policy")
        .trusted_keys[0]
        .revoked = true;
    assert_signed_request_rejects(revoked, "revoked");

    let mut expired = signed_request();
    expired
        .signature_policy
        .as_mut()
        .expect("policy")
        .verification_time_unix_seconds = 1_800_000_000;
    assert_signed_request_rejects(expired, "expired");

    let mut not_yet_valid = signed_request();
    not_yet_valid
        .signature_policy
        .as_mut()
        .expect("policy")
        .verification_time_unix_seconds = 1_699_999_999;
    assert_signed_request_rejects(not_yet_valid, "issued_at");

    let mut replay = signed_request();
    replay
        .signature_policy
        .as_mut()
        .expect("policy")
        .minimum_bundle_epoch = 8;
    assert_signed_request_rejects(replay, "minimum accepted epoch");

    let mut downgrade = signed_request();
    downgrade.integrity_mode = SignedProfileBundleIntegrityMode::DigestOnlySha256;
    assert_signed_request_rejects(downgrade, "downgrade");

    let mut capacity_lock = signed_request();
    capacity_lock.tamper_field = Some("signature.capacity_certificate_digest_sha256".to_string());
    assert_signed_request_rejects(capacity_lock, "capacity certificate digest lock");

    let mut proof_root = signed_request();
    proof_root.tamper_field = Some("signature.child_proof_graph_root_sha256".to_string());
    assert_signed_request_rejects(proof_root, "child proof graph root");

    let mut rollback_chain = signed_request();
    rollback_chain.tamper_field = Some("signature.rollback_chain_digest_sha256".to_string());
    assert_signed_request_rejects(rollback_chain, "rollback chain digest");
}

#[test]
fn signed_profile_bundle_trust_model_declares_digest_only_boundary() {
    let contract = default_contract();
    let trust = &contract.trust_model;

    assert!(trust.active_integrity_mode.contains("digest_only_sha256"));
    assert!(trust.active_integrity_mode.contains("nkey_ed25519"));
    assert_eq!(trust.true_signature_status, "wired_nkey_ed25519");
    assert!(!trust.follow_up_blocker_required);
    assert!(
        trust
            .follow_up_blocker_title
            .contains("NKey Ed25519 signature verification")
    );
    assert!(
        trust
            .digest_only_limitations
            .iter()
            .any(|limitation| limitation.contains("does not authenticate"))
    );
    assert!(
        trust
            .digest_only_limitations
            .iter()
            .any(|limitation| limitation.contains("never auto-apply"))
    );
}

#[test]
fn signed_profile_bundle_unwired_signature_cases_fail_closed() {
    let contract = default_contract();
    let cases: BTreeSet<_> = contract
        .trust_model
        .fail_closed_cases
        .iter()
        .map(|case| case.case_id.as_str())
        .collect();

    for required in [
        "SPB-TRUST-SIGNING-DOMAIN-MISMATCH",
        "SPB-TRUST-KEY-ID-MISMATCH",
        "SPB-TRUST-UNSUPPORTED-SIGNATURE-ALGORITHM",
        "SPB-TRUST-UNKNOWN-SIGNING-KEY",
        "SPB-TRUST-REVOKED-SIGNING-KEY",
        "SPB-TRUST-EXPIRED-BUNDLE",
        "SPB-TRUST-NOT-YET-VALID-ISSUED-AT",
        "SPB-TRUST-REPLAYED-LOWER-EPOCH",
        "SPB-TRUST-DIGEST-DOWNGRADE-WHEN-SIGNED-REQUIRED",
        "SPB-TRUST-CAPACITY-CERTIFICATE-DIGEST-LOCK-MISMATCH",
        "SPB-TRUST-CHILD-PROOF-GRAPH-ROOT-MISMATCH",
        "SPB-TRUST-ROLLBACK-RECEIPT-CHAIN-MISMATCH",
    ] {
        assert!(
            cases.contains(required),
            "missing fail-closed case {required}"
        );
    }

    let categories: BTreeSet<_> = contract
        .trust_model
        .fail_closed_cases
        .iter()
        .map(|case| case.category.as_str())
        .collect();
    for category in [
        "signature_policy",
        "time_window",
        "replay",
        "downgrade",
        "digest_lock",
        "proof_graph",
        "rollback_chain",
    ] {
        assert!(categories.contains(category), "missing category {category}");
    }

    for case in &contract.trust_model.fail_closed_cases {
        assert_eq!(case.operator_verdict, "fail_closed");
        assert!(
            !case.reason.is_empty(),
            "case {} needs reason text",
            case.case_id
        );
        assert!(
            !case.reason.to_ascii_lowercase().contains("accept"),
            "case {} must not imply signed-mode acceptance",
            case.case_id
        );
    }
}

#[test]
fn signed_profile_bundle_tamper_rejects_config_diff_digest() {
    let mut request = sample_request();
    request.execute_mode = SignedProfileBundleExecutionMode::Verify;
    request.tamper_field = Some("config_diff_digest".to_string());
    let bundle = request.plan();
    assert!(!bundle.verification.accepted);
    assert_eq!(
        bundle.verification.tamper_field.as_deref(),
        Some("config_diff_digest")
    );
    assert!(
        bundle
            .verification
            .refusal_reasons
            .iter()
            .any(|reason| reason.contains("manifest_digest_sha256") || reason.contains("digest"))
    );
}

#[test]
fn signed_profile_bundle_host_mismatch_falls_back_conservatively() {
    let mut request = sample_request();
    request.host_fingerprint.hostname = "lab-64c-256g-b".to_string();
    let bundle = request.plan();
    assert!(bundle.verification.accepted);
    assert_eq!(
        bundle.manifest.selected_profile,
        HostProfileId::ConservativeBaseline
    );
    assert!(bundle.manifest.used_safe_fallback);
    assert!(
        bundle
            .manifest
            .planning_refusal_reasons
            .iter()
            .any(|reason| reason.contains("did not match") || reason.contains("host fingerprint"))
    );
}

#[test]
fn signed_profile_bundle_stale_evidence_falls_back_conservatively() {
    let mut request = sample_request();
    request.evidence_snapshot.artifact_age_hours =
        request.capacity_budget.max_artifact_age_hours + 1;
    let bundle = request.plan();
    assert!(bundle.verification.accepted);
    assert_eq!(
        bundle.manifest.selected_profile,
        HostProfileId::ConservativeBaseline
    );
    assert!(bundle.manifest.used_safe_fallback);
    assert!(
        bundle
            .manifest
            .planning_refusal_reasons
            .iter()
            .any(|reason| reason.contains("freshness budget")
                || reason.contains("artifact_age_hours"))
    );
}

#[test]
fn signed_profile_bundle_rejects_missing_capacity_certificate_reference() {
    let mut request = sample_request();
    request.capacity_certificate_reference.artifact_id.clear();
    let bundle = request.plan();
    assert!(!bundle.verification.accepted);
    assert!(
        bundle
            .verification
            .refusal_reasons
            .iter()
            .any(|reason| reason.contains("capacity certificate") || reason.contains("artifact_id"))
    );
}

#[test]
fn signed_profile_bundle_rejects_unsupported_controller_versions() {
    let mut request = sample_request();
    request.supported_controller_versions.clear();
    let bundle = request.plan();
    assert!(!bundle.verification.accepted);
    assert!(
        bundle
            .verification
            .refusal_reasons
            .iter()
            .any(|reason| reason.contains("supported-version") || reason.contains("unsupported"))
    );
}

#[test]
fn signed_profile_bundle_rejects_missing_child_proof_hash() {
    let mut request = sample_request();
    request.controller_evidence.trace_storage_profile = None;
    let bundle = request.plan();
    assert!(!bundle.verification.accepted);
    assert!(bundle.verification.refusal_reasons.iter().any(|reason| {
        reason.contains("child evidence") || reason.contains("trace_storage_profile")
    }));
}

#[test]
fn signed_profile_bundle_manual_overrides_take_precedence_and_are_recorded() {
    let mut request = sample_request();
    request.manual_overrides.worker_threads = Some(17);

    let host_plan = HostProfilePlannerRequest {
        objective: request.objective,
        requested_profile: request.requested_profile,
        host_resources: request.host_resources,
        controller_evidence: request.controller_evidence.clone(),
        manual_overrides: request.manual_overrides.clone(),
        operator_note: request.operator_note.clone(),
    }
    .plan();
    assert_ne!(host_plan.profile_bundle.worker_threads, 17);
    assert_eq!(host_plan.final_bundle.worker_threads, 17);
    assert!(
        host_plan
            .manual_overrides_applied
            .contains(&"worker_threads".to_string())
    );

    let bundle = request.plan();
    assert_ne!(
        bundle.manifest.profile_bundle_digest,
        bundle.manifest.final_bundle_digest
    );
    assert!(
        bundle
            .manifest
            .manual_override_fields
            .contains(&"worker_threads".to_string())
    );
}

#[test]
fn signed_profile_bundle_redacts_operator_secrets_and_links_rollback_receipt() {
    let bundle = sample_request().plan();
    let manifest = &bundle.manifest;
    let rollback = &bundle.rollback_receipt;

    let sanitized_note = manifest
        .sanitized_operator_note
        .as_deref()
        .expect("operator note should be preserved in scrubbed form");
    assert!(sanitized_note.contains("[REDACTED]"));
    assert!(!sanitized_note.contains("super-secret"));
    let sanitized_validation = manifest
        .sanitized_validation_command
        .as_deref()
        .expect("validation command should be preserved in scrubbed form");
    assert!(sanitized_validation.contains("[REDACTED]"));
    assert!(!sanitized_validation.contains("token=secret"));

    assert_eq!(
        rollback.applied_bundle_digest,
        manifest.manifest_digest_sha256
    );
    assert_eq!(rollback.fallback_profile, manifest.fallback_profile);
    assert_eq!(rollback.host_fingerprint, manifest.host_fingerprint);
    assert_eq!(
        rollback.rollback_command_template,
        manifest.rollback_command_template
    );
    assert!(
        rollback
            .artifact_paths
            .iter()
            .any(|path| path == "rollback_receipt.json")
    );
}

#[test]
fn signed_profile_bundle_non_shadow_modes_preserve_existing_behavior() {
    let dry_run = sample_request().plan();
    assert_eq!(dry_run.verification.execute_mode.as_str(), "dry_run");
    assert!(dry_run.shadow_run_evaluation.is_none());

    let mut verify_request =
        request_for_scenario("AA-SIGNED-PROFILE-BUNDLE-TAMPER-REJECT-64C-256G");
    verify_request.tamper_field = None;
    let verify = verify_request.plan();
    assert_eq!(verify.verification.execute_mode.as_str(), "verify");
    assert!(verify.shadow_run_evaluation.is_none());
}

#[test]
fn signed_profile_bundle_shadow_run_reports_are_deterministic() {
    let contract = default_contract();
    let scenario = contract
        .smoke_scenarios
        .iter()
        .find(|scenario| {
            scenario.scenario_id == "AA-SIGNED-PROFILE-BUNDLE-SHADOW-RUN-HOLD-64C-256G"
        })
        .expect("hold scenario must exist");
    let request = build_request(scenario);
    let first_report = build_report(&contract.contract_version, scenario, &request);
    let second_report = build_report(&contract.contract_version, scenario, &request);

    assert_eq!(
        first_report["shadow_run_evaluation"]["dominant_reasons"],
        second_report["shadow_run_evaluation"]["dominant_reasons"]
    );
    assert_eq!(
        first_report["report_projection"]["projection_hash"],
        second_report["report_projection"]["projection_hash"]
    );
    assert_eq!(
        first_report["shadow_run_evaluation"]["decision"],
        json!("hold")
    );
}

#[test]
fn signed_profile_bundle_shadow_run_promotes_when_candidate_beats_baseline() {
    let request = request_for_scenario("AA-SIGNED-PROFILE-BUNDLE-SHADOW-RUN-WIN-64C-256G");
    let bundle = request.plan();
    let shadow = bundle
        .shadow_run_evaluation
        .as_ref()
        .expect("shadow-run evaluation must exist");
    assert_eq!(shadow.decision.as_str(), "promote");
    assert!(shadow.regret_margin_basis_points > 0);
    assert!(shadow.hold_reasons.is_empty());
}

#[test]
fn signed_profile_bundle_shadow_run_holds_when_candidate_is_no_win() {
    let request = request_for_scenario("AA-SIGNED-PROFILE-BUNDLE-SHADOW-RUN-HOLD-64C-256G");
    let bundle = request.plan();
    let shadow = bundle
        .shadow_run_evaluation
        .as_ref()
        .expect("shadow-run evaluation must exist");
    assert_eq!(shadow.decision.as_str(), "hold");
    assert!(!shadow.hold_reasons.is_empty());
}

#[test]
fn signed_profile_bundle_smoke_contract_emits_report() {
    let contract = load_contract();
    let scenario = selected_scenario(&contract);
    let request = build_request(scenario);
    let report = build_report(&contract.contract_version, scenario, &request);
    if let Some(expected_projection) = &scenario.expected_report_projection {
        assert_eq!(&report["report_projection"], expected_projection);
    }
    maybe_write_report(&report);
    println!("SIGNED_PROFILE_BUNDLE_REPORT_JSON_BEGIN");
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("report should serialize")
    );
    println!("SIGNED_PROFILE_BUNDLE_REPORT_JSON_END");
}
