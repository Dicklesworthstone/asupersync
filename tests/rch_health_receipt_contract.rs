//! Public RCH worker-health admission receipt contract tests.

use asupersync::runtime::rch_health::{
    RchAdmissionDecision, RchArtifactRetrievalReliability, RchCacheWarmthHint, RchProofLaneRequest,
    RchProofPriority, RchQueueState, RchRefusalClass, RchTargetDirClass, RchWorkerAdmissionPolicy,
    RchWorkerDiskPressure, RchWorkerSnapshot, admit_rch_worker,
};

fn request(remote_required: bool) -> RchProofLaneRequest {
    RchProofLaneRequest::new(
        "cargo-test-admission",
        RchTargetDirClass::Warm,
        remote_required,
        RchProofPriority::Foreground,
    )
}

fn worker(raw_worker_id: &str, warmth_bps: u16) -> RchWorkerSnapshot {
    RchWorkerSnapshot::new(
        raw_worker_id,
        true,
        RchQueueState::Open,
        false,
        vec![RchCacheWarmthHint::new(
            Some("cargo-test-admission"),
            RchTargetDirClass::Warm,
            warmth_bps,
        )],
        RchWorkerDiskPressure::new(80.0, 100.0, 0.2, 0.3),
        RchArtifactRetrievalReliability::new(3, 0, 0),
        30,
        95,
        0,
    )
}

#[test]
fn receipt_summarizes_cache_warm_capacity_without_host_leaks() {
    let mut cold = worker("vmi-cold.internal", 0);
    cold.cache_warmth.clear();
    let mut blocked = worker("vmi-blocked.internal", 90);
    blocked.queue_state = RchQueueState::Saturated;
    let hot = worker("vmi-hot.internal", 100);

    let receipt = admit_rch_worker(
        &request(true),
        &[blocked, cold, hot],
        &RchWorkerAdmissionPolicy::default(),
    );

    assert_eq!(receipt.schema_version, "rch-worker-admission-receipt-v1");
    assert_eq!(receipt.decision, RchAdmissionDecision::Admit);
    assert_eq!(receipt.admissible_worker_count(), 2);
    assert_eq!(receipt.blocked_worker_count(), 1);
    assert_eq!(receipt.cache_warm_admissible_worker_count(), 1);
    assert!(!receipt.local_fallback_allowed);
    assert!(receipt.selected_worker.is_some());
    assert!(receipt.candidates.iter().all(|candidate| {
        candidate.worker_id.as_str().starts_with("rchw-")
            && !candidate.worker_id.as_str().contains("vmi-")
            && !candidate.worker_id.as_str().contains("internal")
    }));
}

#[test]
fn remote_required_receipt_refuses_local_fallback_when_workers_are_excluded() {
    let mut excluded = worker("vmi-excluded.internal", 80);
    excluded.active_project_exclusion = true;

    let receipt = admit_rch_worker(
        &request(true),
        &[excluded],
        &RchWorkerAdmissionPolicy::default(),
    );

    assert_eq!(receipt.decision, RchAdmissionDecision::Refuse);
    assert_eq!(
        receipt.refusal_class,
        Some(RchRefusalClass::LocalFallbackRefused)
    );
    assert_eq!(receipt.admissible_worker_count(), 0);
    assert_eq!(receipt.blocked_worker_count(), 1);
    assert_eq!(receipt.cache_warm_admissible_worker_count(), 0);
    assert!(!receipt.local_fallback_allowed);
    assert!(
        receipt
            .reasons
            .iter()
            .any(|reason| reason.contains("local Cargo fallback"))
    );
}

#[test]
fn non_remote_required_deferred_receipt_preserves_local_fallback_policy() {
    let mut saturated = worker("vmi-saturated.internal", 80);
    saturated.queue_state = RchQueueState::Saturated;

    let receipt = admit_rch_worker(
        &request(false),
        &[saturated],
        &RchWorkerAdmissionPolicy::default(),
    );
    let row = receipt.schedule_row();

    assert_eq!(receipt.decision, RchAdmissionDecision::Defer);
    assert_eq!(receipt.refusal_class, Some(RchRefusalClass::QueueSaturated));
    assert_eq!(receipt.admissible_worker_count(), 0);
    assert_eq!(receipt.blocked_worker_count(), 1);
    assert!(receipt.local_fallback_allowed);
    assert!(row.local_fallback_allowed);
    assert_eq!(row.decision_code, "defer");
    assert_eq!(row.refusal_code, Some("queue_saturated"));
    assert!(!row.reason_codes.contains(&"remote_required"));
    assert!(!row.reason_codes.contains(&"local_fallback_refused"));
    assert!(
        receipt
            .reasons
            .iter()
            .any(|reason| reason.contains("local Cargo fallback remains allowed"))
    );
}
