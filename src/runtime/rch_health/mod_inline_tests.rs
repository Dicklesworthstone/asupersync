    use super::*;

    fn request() -> RchProofLaneRequest {
        RchProofLaneRequest::new(
            "cargo-test-admission",
            RchTargetDirClass::Warm,
            true,
            RchProofPriority::Foreground,
        )
    }

    fn healthy_worker(name: &str) -> RchWorkerSnapshot {
        RchWorkerSnapshot::new(
            name,
            true,
            RchQueueState::Open,
            false,
            vec![RchCacheWarmthHint::new(
                Some("cargo-test-admission"),
                RchTargetDirClass::Warm,
                80,
            )],
            RchWorkerDiskPressure::new(80.0, 100.0, 0.2, 0.3),
            RchArtifactRetrievalReliability::new(3, 0, 0),
            30,
            95,
            0,
        )
    }

    fn admit(snapshots: &[RchWorkerSnapshot]) -> RchWorkerAdmissionReceipt {
        admit_rch_worker(&request(), snapshots, &RchWorkerAdmissionPolicy::default())
    }

    #[test]
    fn healthy_worker_is_admitted_with_redacted_identity() {
        let receipt = admit(&[healthy_worker("vmi-prod-a.internal")]);

        assert_eq!(receipt.decision, RchAdmissionDecision::Admit);
        assert_eq!(receipt.refusal_class, None);
        assert!(!receipt.local_fallback_allowed);
        let selected = receipt.selected_worker.expect("selected worker");
        assert!(selected.as_str().starts_with("rchw-"));
        assert!(!selected.as_str().contains("vmi-prod-a"));
    }

    #[test]
    fn cache_warm_worker_wins_deterministically() {
        let mut cold = healthy_worker("vmi-cold");
        cold.cache_warmth = vec![RchCacheWarmthHint::new(
            Some("cargo-test-admission"),
            RchTargetDirClass::Warm,
            10,
        )];
        let mut hot = healthy_worker("vmi-hot");
        hot.cache_warmth = vec![RchCacheWarmthHint::new(
            Some("cargo-test-admission"),
            RchTargetDirClass::Warm,
            100,
        )];

        let receipt = admit(&[cold, hot.clone()]);

        assert_eq!(receipt.decision, RchAdmissionDecision::Admit);
        assert_eq!(receipt.selected_worker, Some(hot.worker_id));
        assert_eq!(receipt.candidates[0].cache_warmth_bps, 100);
    }

    #[test]
    fn receipt_counts_cache_warm_capacity_without_leaking_worker_names() {
        let mut cold = healthy_worker("vmi-cold.internal");
        cold.cache_warmth.clear();
        let mut blocked = healthy_worker("vmi-blocked.internal");
        blocked.queue_state = RchQueueState::Saturated;
        let hot = healthy_worker("vmi-hot.internal");

        let receipt = admit(&[blocked, cold, hot]);

        assert_eq!(receipt.admissible_worker_count(), 2);
        assert_eq!(receipt.blocked_worker_count(), 1);
        assert_eq!(receipt.cache_warm_admissible_worker_count(), 1);
        assert!(
            receipt
                .candidates
                .iter()
                .all(|candidate| !candidate.worker_id.as_str().contains("vmi-"))
        );
    }

    #[test]
    fn background_lane_defers_busy_worker_but_foreground_can_use_it() {
        let mut busy = healthy_worker("vmi-busy");
        busy.queue_state = RchQueueState::Busy;
        let background = RchProofLaneRequest::new(
            "cargo-test-admission",
            RchTargetDirClass::Warm,
            true,
            RchProofPriority::Background,
        );

        let deferred = admit_rch_worker(
            &background,
            &[busy.clone()],
            &RchWorkerAdmissionPolicy::default(),
        );
        let foreground = admit(&[busy]);

        assert_eq!(deferred.decision, RchAdmissionDecision::Refuse);
        assert_eq!(
            deferred.refusal_class,
            Some(RchRefusalClass::LocalFallbackRefused)
        );
        assert_eq!(foreground.decision, RchAdmissionDecision::Admit);
    }

    #[test]
    fn lane_specific_cache_warmth_preserves_fairness_between_proof_lanes() {
        let mut cargo_hot = healthy_worker("vmi-cargo-hot.internal");
        cargo_hot.cache_warmth = vec![
            RchCacheWarmthHint::new(Some("cargo-test-admission"), RchTargetDirClass::Warm, 100),
            RchCacheWarmthHint::new(Some("cargo-clippy-admission"), RchTargetDirClass::Warm, 20),
        ];
        let mut clippy_hot = healthy_worker("vmi-clippy-hot.internal");
        clippy_hot.cache_warmth = vec![
            RchCacheWarmthHint::new(Some("cargo-test-admission"), RchTargetDirClass::Warm, 30),
            RchCacheWarmthHint::new(Some("cargo-clippy-admission"), RchTargetDirClass::Warm, 95),
        ];
        let clippy_request = RchProofLaneRequest::new(
            "cargo-clippy-admission",
            RchTargetDirClass::Warm,
            true,
            RchProofPriority::Foreground,
        );

        let cargo_receipt = admit(&[clippy_hot.clone(), cargo_hot.clone()]);
        let clippy_receipt = admit_rch_worker(
            &clippy_request,
            &[clippy_hot.clone(), cargo_hot.clone()],
            &RchWorkerAdmissionPolicy::default(),
        );

        assert_eq!(
            cargo_receipt.selected_worker,
            Some(cargo_hot.worker_id.clone())
        );
        assert_eq!(
            clippy_receipt.selected_worker,
            Some(clippy_hot.worker_id.clone())
        );
        assert_eq!(cargo_receipt.candidates[0].cache_warmth_bps, 100);
        assert_eq!(clippy_receipt.candidates[0].cache_warmth_bps, 95);
        assert!(
            cargo_receipt
                .candidates
                .iter()
                .chain(clippy_receipt.candidates.iter())
                .all(|candidate| !candidate.worker_id.as_str().contains("vmi-"))
        );
    }

    #[test]
    fn active_project_exclusion_refuses_remote_required_without_local_fallback() {
        let mut excluded = healthy_worker("vmi-excluded");
        excluded.active_project_exclusion = true;

        let receipt = admit(&[excluded]);

        assert_eq!(receipt.decision, RchAdmissionDecision::Refuse);
        assert_eq!(
            receipt.refusal_class,
            Some(RchRefusalClass::LocalFallbackRefused)
        );
        assert!(!receipt.local_fallback_allowed);
        assert!(
            receipt
                .reasons
                .iter()
                .any(|reason| reason.contains("local Cargo fallback"))
        );
    }

    #[test]
    fn disk_pressure_disqualifies_worker() {
        let mut worker = healthy_worker("vmi-disk");
        worker.disk_pressure = RchWorkerDiskPressure::new(100.0, 2.0, 0.1, 0.1);

        let receipt = admit(&[worker]);

        assert_eq!(receipt.decision, RchAdmissionDecision::Refuse);
        assert_eq!(
            receipt.candidates[0].refusal_class,
            Some(RchRefusalClass::DiskPressure)
        );
    }

    #[test]
    fn retrieval_flakiness_triggers_backoff() {
        let mut worker = healthy_worker("vmi-flaky");
        worker.retrieval = RchArtifactRetrievalReliability::new(1, 2, 0);

        let receipt = admit(&[worker]);

        assert_eq!(
            receipt.candidates[0].refusal_class,
            Some(RchRefusalClass::RetrievalFlaky)
        );
    }

    #[test]
    fn stale_snapshot_fails_closed() {
        let mut worker = healthy_worker("vmi-stale");
        worker.last_seen_age_secs = 3_600;

        let receipt = admit(&[worker]);

        assert_eq!(
            receipt.candidates[0].refusal_class,
            Some(RchRefusalClass::StaleSnapshot)
        );
    }

    #[test]
    fn contradictory_snapshot_fails_closed_before_reachability() {
        let mut worker = healthy_worker("vmi-contradictory");
        worker.reachable = false;
        worker.queue_state = RchQueueState::Open;

        let receipt = admit(&[worker]);

        assert_eq!(
            receipt.candidates[0].refusal_class,
            Some(RchRefusalClass::ContradictorySnapshot)
        );
    }

    #[test]
    fn hysteresis_backoff_blocks_flapping_worker() {
        let mut worker = healthy_worker("vmi-flap");
        worker.consecutive_unhealthy_samples = 2;

        let receipt = admit(&[worker]);

        assert_eq!(
            receipt.candidates[0].refusal_class,
            Some(RchRefusalClass::HysteresisBackoff)
        );
    }

    #[test]
    fn schedule_row_summarizes_cache_warm_capacity_without_host_leaks() {
        let mut blocked = healthy_worker("vmi-blocked.internal");
        blocked.queue_state = RchQueueState::Saturated;
        let hot = healthy_worker("vmi-hot.internal");

        let receipt = admit(&[blocked, hot.clone()]);
        let row = receipt.schedule_row();

        assert_eq!(row.schema_version, "rch-worker-admission-schedule-row-v1");
        assert_eq!(row.lane_id, "cargo-test-admission");
        assert_eq!(row.decision, RchAdmissionDecision::Admit);
        assert_eq!(row.decision_code, "admit");
        assert_eq!(row.refusal_class, None);
        assert_eq!(row.refusal_code, None);
        assert_eq!(row.selected_worker, Some(hot.worker_id));
        assert_eq!(row.candidate_count, 2);
        assert_eq!(row.admissible_worker_count, 1);
        assert_eq!(row.blocked_worker_count, 1);
        assert_eq!(row.cache_warm_admissible_worker_count, 1);
        assert!(row.reason_codes.contains(&"remote_required"));
        assert!(row.reason_codes.contains(&"cache_warm_capacity_present"));
        assert!(!row.reason_codes.contains(&"local_fallback_refused"));
        assert!(
            row.selected_worker
                .as_ref()
                .is_some_and(|worker| !worker.as_str().contains("vmi-"))
        );
    }

    #[test]
    fn schedule_row_records_remote_required_refusal_without_local_fallback() {
        let mut excluded = healthy_worker("vmi-excluded.internal");
        excluded.active_project_exclusion = true;

        let receipt = admit(&[excluded]);
        let row = receipt.schedule_row();

        assert_eq!(row.decision, RchAdmissionDecision::Refuse);
        assert_eq!(row.decision_code, "refuse");
        assert_eq!(
            row.refusal_class,
            Some(RchRefusalClass::LocalFallbackRefused)
        );
        assert_eq!(row.refusal_code, Some("local_fallback_refused"));
        assert!(!row.local_fallback_allowed);
        assert!(row.reason_codes.contains(&"remote_required"));
        assert!(row.reason_codes.contains(&"local_fallback_refused"));
        assert_eq!(
            row.reason_codes
                .iter()
                .filter(|code| **code == "local_fallback_refused")
                .count(),
            1
        );
    }

    #[test]
    fn non_remote_required_defer_preserves_local_fallback_allowed() {
        let mut saturated = healthy_worker("vmi-saturated.internal");
        saturated.queue_state = RchQueueState::Saturated;
        let local_allowed_request = RchProofLaneRequest::new(
            "cargo-test-admission",
            RchTargetDirClass::Warm,
            false,
            RchProofPriority::Foreground,
        );

        let receipt = admit_rch_worker(
            &local_allowed_request,
            &[saturated],
            &RchWorkerAdmissionPolicy::default(),
        );
        let row = receipt.schedule_row();

        assert_eq!(receipt.decision, RchAdmissionDecision::Defer);
        assert_eq!(receipt.refusal_class, Some(RchRefusalClass::QueueSaturated));
        assert!(receipt.local_fallback_allowed);
        assert!(row.local_fallback_allowed);
        assert!(row.reason_codes.contains(&"defer"));
        assert!(!row.reason_codes.contains(&"remote_required"));
        assert!(!row.reason_codes.contains(&"local_fallback_refused"));
        assert!(
            receipt
                .reasons
                .iter()
                .any(|reason| reason.contains("local Cargo fallback remains allowed"))
        );
    }
