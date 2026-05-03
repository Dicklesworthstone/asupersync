//! Integration tests for scheduler evidence artifacts and recommendations.

use asupersync::runtime::scheduler::{
    SCHEDULER_EVIDENCE_SCHEMA_VERSION, SchedulerEvidenceArtifact, SchedulerEvidenceError,
    SchedulerEvidenceMetrics, SchedulerKnobProfile, SchedulerRecommendationReason,
    SchedulerTopologyDescriptor, SchedulerWorkloadClass,
};

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
