//! Integration tests for scheduler evidence artifacts and recommendations.

use asupersync::runtime::scheduler::{
    SCHEDULER_EVIDENCE_SCHEMA_VERSION, SchedulerEvidenceArtifact, SchedulerEvidenceError,
    SchedulerEvidenceMetrics, SchedulerKnobProfile, SchedulerRecommendationReason,
    SchedulerTopologyDescriptor, SchedulerWorkloadClass,
};
use serde_json::Value;

fn sample_artifact() -> SchedulerEvidenceArtifact {
    SchedulerEvidenceArtifact {
        schema_version: SCHEDULER_EVIDENCE_SCHEMA_VERSION.to_string(),
        run_label: "mixed-burst-64c".to_string(),
        workload_class: SchedulerWorkloadClass::MixedBurst,
        topology: SchedulerTopologyDescriptor {
            worker_threads: 64,
            cohort_count: 2,
            memory_budget_gib: 256,
        },
        current_knobs: SchedulerKnobProfile {
            worker_threads: 64,
            steal_batch_size: 8,
            cancel_streak_limit: 16,
            global_queue_limit: 0,
            parking_enabled: true,
        },
        metrics: SchedulerEvidenceMetrics {
            wake_to_run_p50_ns: 8_000,
            wake_to_run_p95_ns: 90_000,
            wake_to_run_p99_ns: 220_000,
            queue_residency_p50_ns: 16_000,
            queue_residency_p95_ns: 200_000,
            queue_residency_p99_ns: 520_000,
            ready_backlog_p95: 192,
            ready_backlog_p99: 320,
            cancel_debt_p95: 48,
            cancel_debt_p99: 128,
            remote_steal_ratio_pct: Some(42),
            cross_cohort_wake_p99_ns: Some(180_000),
        },
        notes: vec!["deterministic_lab".to_string()],
    }
}

#[test]
fn scheduler_evidence_artifact_round_trips_through_json() {
    let artifact = sample_artifact();
    let json = serde_json::to_string_pretty(&artifact).expect("serialize artifact");
    let reparsed: SchedulerEvidenceArtifact =
        serde_json::from_str(&json).expect("deserialize artifact");
    assert_eq!(reparsed, artifact);
}

#[test]
fn scheduler_evidence_artifact_generates_stable_recommendations() {
    let artifact = sample_artifact();
    let report = artifact.tune_report().expect("valid report");

    assert_eq!(report.source_run_label, "mixed-burst-64c");
    assert_eq!(report.profile_name, "scale_workers");
    assert_eq!(report.recommended_knobs.worker_threads, 66);
    assert_eq!(report.recommended_knobs.steal_batch_size, 16);
    assert_eq!(report.recommended_knobs.cancel_streak_limit, 32);
    assert_eq!(report.global_queue_limit_hint, Some(640));
    assert_eq!(report.fallback_profile, artifact.current_knobs);
    assert_eq!(report.confidence_percent, 90);
    assert_eq!(
        report.reason_codes,
        vec![
            SchedulerRecommendationReason::WorkersSaturated,
            SchedulerRecommendationReason::QueueResidencyDominant,
            SchedulerRecommendationReason::CancelDebtDominant,
            SchedulerRecommendationReason::RemoteStealPressure,
        ]
    );
}

#[test]
fn scheduler_evidence_artifact_rejects_invalid_inputs() {
    let mut artifact = sample_artifact();
    artifact.schema_version = "asupersync.scheduler-evidence.v0".to_string();
    assert_eq!(
        artifact.validate(),
        Err(SchedulerEvidenceError::UnsupportedSchemaVersion {
            expected: SCHEDULER_EVIDENCE_SCHEMA_VERSION.to_string(),
            found: "asupersync.scheduler-evidence.v0".to_string(),
        })
    );

    let mut artifact = sample_artifact();
    artifact.metrics.remote_steal_ratio_pct = Some(101);
    assert_eq!(
        artifact.validate(),
        Err(SchedulerEvidenceError::RemoteStealRatioOutOfRange(101))
    );
}

fn load_scheduler_recommend_contract() -> Value {
    serde_json::from_str(include_str!(
        "../artifacts/scheduler_recommend_smoke_contract_v1.json"
    ))
    .expect("parse scheduler recommend smoke contract")
}

fn scenario_by_id<'a>(contract: &'a Value, scenario_id: &str) -> &'a Value {
    contract["smoke_scenarios"]
        .as_array()
        .expect("smoke_scenarios should be an array")
        .iter()
        .find(|scenario| scenario["scenario_id"].as_str() == Some(scenario_id))
        .unwrap_or_else(|| panic!("missing scenario: {scenario_id}"))
}

#[test]
fn scheduler_recommend_smoke_contract_matches_tuning_projection() {
    let contract = load_scheduler_recommend_contract();
    assert_eq!(
        contract["runner_script"].as_str(),
        Some("scripts/run_scheduler_recommend_smoke.sh")
    );
    assert!(
        contract["required_bundle_fields"]
            .as_array()
            .expect("required_bundle_fields")
            .iter()
            .any(|field| field.as_str() == Some("scenario_class"))
    );
    assert!(
        contract["required_run_report_fields"]
            .as_array()
            .expect("required_run_report_fields")
            .iter()
            .any(|field| field.as_str() == Some("execution_policy"))
    );

    let scenarios = contract["smoke_scenarios"]
        .as_array()
        .expect("smoke_scenarios should be an array");
    assert_eq!(
        scenarios.len(),
        2,
        "expected deterministic + real-host scenarios"
    );

    let scenario = scenario_by_id(&contract, "AA-SCHED-RECOMMEND-MIXED-BURST-64C");
    assert_eq!(
        scenario["scenario_id"].as_str(),
        Some("AA-SCHED-RECOMMEND-MIXED-BURST-64C")
    );
    assert_eq!(
        scenario["scenario_class"].as_str(),
        Some("deterministic_lab_safe")
    );
    assert_eq!(
        scenario["execution_policy"].as_str(),
        Some("execute_or_dry_run")
    );

    let evidence: SchedulerEvidenceArtifact =
        serde_json::from_value(scenario["evidence_artifact"].clone())
            .expect("scenario evidence should deserialize");
    let report = evidence
        .tune_report()
        .expect("scenario evidence should tune");

    let actual_projection = serde_json::json!({
        "schema_version": report.schema_version,
        "source_run_label": report.source_run_label,
        "workload_class": report.workload_class,
        "profile_name": report.profile_name,
        "recommended_knobs": report.recommended_knobs,
        "global_queue_limit_hint": report.global_queue_limit_hint,
        "fallback_profile": report.fallback_profile,
        "confidence_percent": report.confidence_percent,
        "reason_codes": report.reason_codes,
    });

    assert_eq!(actual_projection, scenario["expected_report"]);
}

#[test]
fn scheduler_recommend_smoke_contract_declares_real_host_template() {
    let contract = load_scheduler_recommend_contract();
    let scenario = scenario_by_id(&contract, "AA-SCHED-RECOMMEND-REAL-HOST-64C-256G");

    assert_eq!(
        scenario["scenario_class"].as_str(),
        Some("real_host_template")
    );
    assert_eq!(scenario["execution_policy"].as_str(), Some("dry_run_only"));
    assert_eq!(
        scenario["host_requirements"]["min_worker_threads"].as_u64(),
        Some(64)
    );
    assert_eq!(
        scenario["host_requirements"]["min_memory_gib"].as_u64(),
        Some(256)
    );
    assert_eq!(
        scenario["expected_profile_name_hint"].as_str(),
        Some("operator_captured")
    );
    assert_eq!(
        scenario["expected_report"],
        serde_json::Value::Null,
        "template scenario should not pin a fake report projection"
    );
    assert!(
        scenario["template_env"]["ASUPERSYNC_SCHEDULER_EVIDENCE_CAPTURE"]
            .as_str()
            .is_some()
    );

    let evidence: SchedulerEvidenceArtifact =
        serde_json::from_value(scenario["evidence_artifact"].clone())
            .expect("real host template evidence should deserialize");
    assert!(
        evidence
            .notes
            .iter()
            .any(|note| note == "real_host_template"),
        "template evidence should self-identify as real-host-only"
    );
}
