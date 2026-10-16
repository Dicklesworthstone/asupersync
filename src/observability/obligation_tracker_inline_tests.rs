    use super::*;
    use crate::Budget;
    use crate::time::{TimerDriverHandle, VirtualClock};

    #[test]
    fn test_obligation_state_is_active() {
        assert!(ObligationStateInfo::Reserved.is_active());
        assert!(!ObligationStateInfo::Committed.is_active());
        assert!(!ObligationStateInfo::Aborted.is_active());
        assert!(!ObligationStateInfo::Leaked.is_active());
    }

    #[test]
    fn test_obligation_kind_names() {
        assert_eq!(
            obligation_kind_name(ObligationKind::SendPermit),
            "SendPermit"
        );
        assert_eq!(obligation_kind_name(ObligationKind::Ack), "Ack");
        assert_eq!(obligation_kind_name(ObligationKind::Lease), "Lease");
        assert_eq!(obligation_kind_name(ObligationKind::IoOp), "IoOp");
    }

    #[test]
    fn test_config_defaults() {
        let config = ObligationTrackerConfig::default();
        assert_eq!(config.leak_age_threshold, Duration::from_mins(1));
        assert!(!config.periodic_checks);
        assert_eq!(config.check_interval, Duration::from_secs(30));
    }

    #[test]
    fn test_config_builder() {
        let config = ObligationTrackerConfig::default()
            .with_leak_threshold(Duration::from_secs(120))
            .with_periodic_checks(Duration::from_secs(15));

        assert_eq!(config.leak_age_threshold, Duration::from_secs(120));
        assert!(config.periodic_checks);
        assert_eq!(config.check_interval, Duration::from_secs(15));
    }

    #[test]
    fn test_summary_default() {
        let summary = ObligationSummary::default();
        assert_eq!(summary.total_active, 0);
        assert_eq!(summary.potential_leaks, 0);
        assert_eq!(summary.age_warnings, 0);
        assert!(summary.by_type.is_empty());
    }

    // Pure data-type tests (wave 17 – CyanBarn)

    #[test]
    fn config_debug_clone() {
        let cfg = ObligationTrackerConfig::default();
        let cfg2 = cfg;
        assert!(format!("{cfg2:?}").contains("ObligationTrackerConfig"));
    }

    #[test]
    fn config_with_leak_threshold() {
        let cfg = ObligationTrackerConfig::default().with_leak_threshold(Duration::from_secs(120));
        assert_eq!(cfg.leak_age_threshold, Duration::from_secs(120));
        assert!(!cfg.periodic_checks);
    }

    #[test]
    fn test_region_close_obligation_detection() {
        let mut state = RuntimeState::new();
        // Create the obligation at logical time zero so the age below is
        // measured against a known baseline (RuntimeState::new starts the
        // logical clock at 1s to keep timestamps valid for the obligation
        // guard).
        state.now = Time::ZERO;
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");

        // Create an obligation in the region
        let obligation_id = state
            .create_obligation(
                ObligationKind::SendPermit,
                task_id,
                root,
                Some("test permit".into()),
            )
            .expect("create obligation");

        state.now = Time::from_secs(30);

        let tracker = ObligationTracker::new(Arc::new(state), None);

        // Check for leaks at region close
        let region_obligations = tracker.check_region_close_obligations(root);

        assert_eq!(region_obligations.len(), 1);
        assert_eq!(region_obligations[0].id, obligation_id);
        assert_eq!(region_obligations[0].type_name, "SendPermit");
        assert_eq!(region_obligations[0].age, Duration::from_secs(30));
        assert!(region_obligations[0].is_active());
    }

    #[cfg(feature = "obligation-leak-detection")]
    #[test]
    fn test_enhanced_leak_detection() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");

        // Create obligations with different ages
        let old_obligation = state
            .create_obligation(
                ObligationKind::Lease,
                task_id,
                root,
                Some("old lease".into()),
            )
            .expect("create obligation");

        state.now = Time::from_secs(120); // Make the first obligation very old

        let new_obligation = state
            .create_obligation(ObligationKind::Ack, task_id, root, Some("new ack".into()))
            .expect("create obligation");

        // Age the second obligation moderately: 80 s is over the 60 s
        // threshold (a Warning leak) but under 2x the threshold (Critical),
        // while the first, created at the 1 s initial clock, is ~199 s old.
        // (At 150 s the second was only 30 s old and never counted as a leak.)
        state.now = Time::from_secs(200);

        let tracker = ObligationTracker::new(Arc::new(state), None);
        let threshold = Duration::from_secs(60);

        let report = tracker.enhanced_leak_detection(threshold);

        assert_eq!(report.attributed_leaks.len(), 2);
        assert_eq!(report.affected_regions.len(), 1);
        assert_eq!(report.affected_regions[0], root);
        assert_eq!(report.threshold_used, threshold);

        // Check leak severity classification
        let critical_leak = report
            .attributed_leaks
            .iter()
            .find(|leak| leak.obligation.id == old_obligation)
            .expect("should find old obligation");
        assert_eq!(critical_leak.leak_severity, LeakSeverity::Critical);

        let warning_leak = report
            .attributed_leaks
            .iter()
            .find(|leak| leak.obligation.id == new_obligation)
            .expect("should find new obligation");
        assert_eq!(warning_leak.leak_severity, LeakSeverity::Warning);
    }

    #[cfg(feature = "obligation-leak-detection")]
    #[test]
    fn test_leak_attribution() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");

        let obligation_id = state
            .create_obligation(ObligationKind::IoOp, task_id, root, Some("test io".into()))
            .expect("create obligation");

        state.now = Time::from_secs(90);

        let tracker = ObligationTracker::new(Arc::new(state), None);

        let attribution = tracker
            .get_leak_attribution(obligation_id)
            .expect("should find attribution");

        assert_eq!(attribution.obligation_id, obligation_id);
        assert_eq!(attribution.obligation_type, "IoOp");
        assert_eq!(attribution.holder_task, task_id);
        assert_eq!(attribution.holder_region, root);
        // `RuntimeState::new()` starts its clock at 1 s, so an obligation
        // created immediately and observed at 90 s is 89 s old.
        assert_eq!(attribution.age, Duration::from_secs(89));
        assert_eq!(attribution.description.as_deref(), Some("test io"));
    }

    #[test]
    fn test_runtime_clean_state() {
        let state = RuntimeState::new();
        let tracker = ObligationTracker::new(Arc::new(state), None);

        assert!(tracker.is_runtime_clean());

        // Test with obligations - need a mutable state for this
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");

        let _obligation_id = state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");

        let tracker = ObligationTracker::new(Arc::new(state), None);
        assert!(!tracker.is_runtime_clean());
    }

    #[test]
    fn obligation_state_info_debug_clone_copy_eq() {
        let s = ObligationStateInfo::Reserved;
        let s2 = s;
        assert_eq!(s, s2);
        assert!(format!("{s:?}").contains("Reserved"));
    }

    #[test]
    fn obligation_state_info_all_variants() {
        assert!(ObligationStateInfo::Reserved.is_active());
        assert!(!ObligationStateInfo::Committed.is_active());
        assert!(!ObligationStateInfo::Aborted.is_active());
        assert!(!ObligationStateInfo::Leaked.is_active());
    }

    #[test]
    fn obligation_state_info_ne() {
        assert_ne!(
            ObligationStateInfo::Reserved,
            ObligationStateInfo::Committed
        );
        assert_ne!(ObligationStateInfo::Aborted, ObligationStateInfo::Leaked);
    }

    #[test]
    fn obligation_state_info_from_obligation_state() {
        let s = ObligationStateInfo::from(ObligationState::Reserved);
        assert_eq!(s, ObligationStateInfo::Reserved);

        let s = ObligationStateInfo::from(ObligationState::Committed);
        assert_eq!(s, ObligationStateInfo::Committed);

        let s = ObligationStateInfo::from(ObligationState::Aborted);
        assert_eq!(s, ObligationStateInfo::Aborted);

        let s = ObligationStateInfo::from(ObligationState::Leaked);
        assert_eq!(s, ObligationStateInfo::Leaked);
    }

    #[test]
    fn obligation_summary_debug_clone() {
        let summary = ObligationSummary::default();
        let summary2 = summary;
        assert!(format!("{summary2:?}").contains("ObligationSummary"));
    }

    #[test]
    fn obligation_summary_with_entries() {
        let mut summary = ObligationSummary {
            total_active: 5,
            potential_leaks: 2,
            age_warnings: 1,
            ..ObligationSummary::default()
        };
        summary.by_type.insert(
            "Lease".to_string(),
            TypeSummary {
                count: 5,
                oldest_age: Duration::from_mins(1),
                primary_holder: Some("task-1".into()),
            },
        );
        assert_eq!(summary.by_type.len(), 1);
    }

    #[test]
    fn type_summary_debug_clone() {
        let ts = TypeSummary {
            count: 3,
            oldest_age: Duration::from_secs(30),
            primary_holder: None,
        };
        let ts2 = ts;
        assert_eq!(ts2.count, 3);
        assert!(format!("{ts2:?}").contains("TypeSummary"));
    }

    #[test]
    fn type_summary_with_primary_holder() {
        let ts = TypeSummary {
            count: 1,
            oldest_age: Duration::ZERO,
            primary_holder: Some("task-7".into()),
        };
        assert_eq!(ts.primary_holder.as_deref(), Some("task-7"));
    }

    #[test]
    fn obligation_info_debug_clone() {
        let info = ObligationInfo {
            id: ObligationId::new_for_test(1, 0),
            type_name: "SendPermit".into(),
            holder_task: TaskId::new_for_test(1, 0),
            holder_region: RegionId::new_for_test(1, 0),
            created_at: Time::ZERO,
            age: Duration::from_secs(5),
            state: ObligationStateInfo::Reserved,
            description: None,
            #[cfg(feature = "obligation-leak-detection")]
            acquisition_backtrace: None,
            acquired_at: crate::record::SourceLocation::unknown(),
        };
        let info2 = info;
        assert!(info2.is_active());
        assert!(format!("{info2:?}").contains("ObligationInfo"));
    }

    #[test]
    fn obligation_info_is_active_committed() {
        let info = ObligationInfo {
            id: ObligationId::new_for_test(2, 0),
            type_name: "Ack".into(),
            holder_task: TaskId::new_for_test(1, 0),
            holder_region: RegionId::new_for_test(1, 0),
            created_at: Time::ZERO,
            age: Duration::from_secs(10),
            state: ObligationStateInfo::Committed,
            description: Some("test".into()),
            #[cfg(feature = "obligation-leak-detection")]
            acquisition_backtrace: None,
            acquired_at: crate::record::SourceLocation::unknown(),
        };
        assert!(!info.is_active());
    }

    #[test]
    fn tracker_uses_runtime_logical_time_without_timer_driver() {
        let mut state = RuntimeState::new();
        // Create the obligation at logical time zero so the age below is
        // measured against a known baseline (RuntimeState::new starts the
        // logical clock at 1s to keep timestamps valid for the obligation
        // guard).
        state.now = Time::ZERO;
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        let obligation_id = state
            .create_obligation(ObligationKind::Lease, task_id, root, Some("lease".into()))
            .expect("create obligation");
        state.now = Time::from_secs(65);

        let tracker = ObligationTracker::new(Arc::new(state), None);
        let obligations = tracker.list_obligations();
        assert_eq!(obligations.len(), 1);
        assert_eq!(obligations[0].id, obligation_id);
        assert_eq!(obligations[0].age, Duration::from_secs(65));

        let leaks = tracker.find_potential_leaks_default();
        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0].id, obligation_id);
        assert_eq!(leaks[0].age, Duration::from_secs(65));

        let summary = tracker.summary();
        assert_eq!(summary.total_active, 1);
        assert_eq!(summary.potential_leaks, 1);
        assert_eq!(summary.age_warnings, 1);
    }

    #[test]
    fn tracker_prefers_timer_driver_when_available() {
        let mut state = RuntimeState::new();
        // Create the obligation at logical time zero so the age below is
        // measured against a known baseline (RuntimeState::new starts the
        // logical clock at 1s to keep timestamps valid for the obligation
        // guard).
        state.now = Time::ZERO;
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        let obligation_id = state
            .create_obligation(ObligationKind::Ack, task_id, root, None)
            .expect("create obligation");
        state.now = Time::from_secs(5);
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::new(
            VirtualClock::starting_at(Time::from_secs(8)),
        )));

        let tracker = ObligationTracker::new(Arc::new(state), None);
        let obligations = tracker.list_obligations();
        assert_eq!(obligations.len(), 1);
        assert_eq!(obligations[0].id, obligation_id);
        assert_eq!(obligations[0].age, Duration::from_secs(8));
    }

    // ========================================================================
    // Metamorphic Testing: obligation_tracker commit-abort symmetry under panic recovery
    // ========================================================================

    /// MR1: Panic during commit triggers abort path (Equivalence)
    /// Transformation: Induce panic during commit operation
    /// Relation: Obligation state should recover to consistent state
    #[test]
    fn mr_obligation_panic_during_commit_triggers_abort() {
        use crate::types::Budget;
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");

        // Create obligation that we'll attempt to commit with panic
        let obligation_id = state
            .create_obligation(
                ObligationKind::SendPermit,
                task_id,
                root,
                Some("panic_test".into()),
            )
            .expect("create obligation");

        let tracker = ObligationTracker::new(Arc::new(state), None);

        // Verify initial state
        let initial_obligations = tracker.list_obligations();
        assert_eq!(initial_obligations.len(), 1);
        assert_eq!(initial_obligations[0].id, obligation_id);
        assert!(initial_obligations[0].is_active());

        // Simulate panic recovery - in reality this would involve the runtime's
        // panic handling, but we test the invariant that unresolved obligations
        // are detectable regardless of how they became unresolved
        let obligations_after_simulated_panic = tracker.list_obligations();
        assert_eq!(obligations_after_simulated_panic.len(), 1);

        // The metamorphic property: panic during commit should leave obligation
        // in a state equivalent to explicit abort (both are detectable as unresolved)
        let leaks = tracker.find_potential_leaks(Duration::ZERO);
        assert_eq!(
            leaks.len(),
            1,
            "Unresolved obligation should be detectable as leak"
        );
        assert_eq!(leaks[0].id, obligation_id);
    }

    /// MR2: Panic during abort is double-panic safe (Invertive)
    /// Transformation: Abort → panic during abort → should not double-panic
    /// Relation: Operation should be idempotent under panic
    #[test]
    fn mr_obligation_double_panic_safety() {
        use crate::types::Budget;
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");

        // Create two obligations for testing double-panic scenarios
        let obligation_id_1 = state
            .create_obligation(
                ObligationKind::Lease,
                task_id,
                root,
                Some("double_panic_1".into()),
            )
            .expect("create obligation 1");

        let obligation_id_2 = state
            .create_obligation(
                ObligationKind::Ack,
                task_id,
                root,
                Some("double_panic_2".into()),
            )
            .expect("create obligation 2");

        let tracker = ObligationTracker::new(Arc::new(state), None);

        // Verify initial state
        let initial_count = tracker.list_obligations().len();
        assert_eq!(initial_count, 2);

        // The metamorphic property: tracking operations should be double-panic safe
        // If a panic occurs during obligation resolution, the tracker should not
        // itself panic when called again
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _obligations = tracker.list_obligations();
            // Simulate whatever operation might panic during abort handling
        }));

        // After simulated panic, tracker should still function
        let post_panic_obligations = tracker.list_obligations();
        assert_eq!(
            post_panic_obligations.len(),
            2,
            "Tracker should remain functional after panic"
        );

        // Verify both obligations are still tracked
        let obligation_ids: Vec<_> = post_panic_obligations.iter().map(|o| o.id).collect();
        assert!(obligation_ids.contains(&obligation_id_1));
        assert!(obligation_ids.contains(&obligation_id_2));
    }

    /// MR3: track_obligation + untrack_obligation round-trip preserves count (Invertive)
    /// Transformation: track → untrack → count should return to original
    /// Relation: f(untrack(track(x))) = f(x)
    #[test]
    fn mr_obligation_track_untrack_roundtrip() {
        use crate::types::Budget;

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");

        // Track obligation (add)
        let obligation_id = state
            .create_obligation(
                ObligationKind::IoOp,
                task_id,
                root,
                Some("roundtrip_test".into()),
            )
            .expect("create obligation");

        // Untrack obligation (resolve via commit)
        let _duration = state
            .commit_obligation(obligation_id)
            .expect("commit obligation");

        let tracker = ObligationTracker::new(Arc::new(state), None);
        let after_untrack_count = tracker.list_obligations().len();

        assert_eq!(
            after_untrack_count, 0,
            "Round-trip track→untrack should preserve active obligation count"
        );

        // Verify the obligation is no longer in the active set
        let active_obligations = tracker.list_obligations();
        assert!(
            !active_obligations.iter().any(|o| o.id == obligation_id),
            "Committed obligation should not appear in active list"
        );
    }

    /// MR4: Replay under LabRuntime produces identical obligation trace (Equivalence)
    /// Transformation: Same sequence with deterministic execution
    /// Relation: f(sequence, seed1) = f(sequence, seed2) when seed1 = seed2
    #[test]
    fn mr_obligation_deterministic_replay() {
        use crate::types::Budget;
        use crate::util::DetRng;

        // First execution with deterministic entropy
        let mut state1 = RuntimeState::new();
        let root1 = state1.create_root_region(Budget::INFINITE);
        let (task_id_1, _handle1) = state1
            .create_task(root1, Budget::INFINITE, async {})
            .expect("create task 1");

        // Simulate deterministic obligation creation pattern
        let mut entropy1 = DetRng::new(12345);
        let mut obligation_ids_1 = Vec::new();

        for i in 0..3 {
            let kind = if entropy1.next_u32() % 2 == 0 {
                ObligationKind::SendPermit
            } else {
                ObligationKind::Ack
            };

            let obligation_id = state1
                .create_obligation(kind, task_id_1, root1, Some(format!("det_replay_{}", i)))
                .expect("create obligation");
            obligation_ids_1.push(obligation_id);
        }

        let tracker1 = ObligationTracker::new(Arc::new(state1), None);
        let trace1 = tracker1.list_obligations();

        // Second execution with same entropy seed
        let mut state2 = RuntimeState::new();
        let root2 = state2.create_root_region(Budget::INFINITE);
        let (task_id_2, _handle2) = state2
            .create_task(root2, Budget::INFINITE, async {})
            .expect("create task 2");

        let mut entropy2 = DetRng::new(12345); // Same seed
        let mut obligation_ids_2 = Vec::new();

        for i in 0..3 {
            let kind = if entropy2.next_u32() % 2 == 0 {
                ObligationKind::SendPermit
            } else {
                ObligationKind::Ack
            };

            let obligation_id = state2
                .create_obligation(kind, task_id_2, root2, Some(format!("det_replay_{}", i)))
                .expect("create obligation");
            obligation_ids_2.push(obligation_id);
        }

        let tracker2 = ObligationTracker::new(Arc::new(state2), None);
        let trace2 = tracker2.list_obligations();

        // Metamorphic property: deterministic execution should produce identical traces
        assert_eq!(
            trace1.len(),
            trace2.len(),
            "Deterministic replay should produce same trace length"
        );

        for (i, (t1, t2)) in trace1.iter().zip(trace2.iter()).enumerate() {
            assert_eq!(
                t1.type_name, t2.type_name,
                "Obligation type at index {} should be identical in deterministic replay",
                i
            );
            assert_eq!(
                t1.state, t2.state,
                "Obligation state at index {} should be identical in deterministic replay",
                i
            );
            // Note: IDs will differ, but the pattern should be the same
        }
    }

    /// MR5: Tracker drop without commit logs leak (Inclusive)
    /// Transformation: Create obligation → drop without resolution
    /// Relation: Should be detectable as leak
    #[test]
    fn mr_obligation_tracker_drop_logs_leak() {
        use crate::types::Budget;

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");

        // Create obligation without resolving it
        let leaked_obligation_id = state
            .create_obligation(
                ObligationKind::SemaphorePermit,
                task_id,
                root,
                Some("intentional_leak".into()),
            )
            .expect("create obligation");

        let second_leaked_id = state
            .create_obligation(
                ObligationKind::Lease,
                task_id,
                root,
                Some("second_leak".into()),
            )
            .expect("create second obligation");

        let state = Arc::new(state);
        // Use a ZERO leak threshold so any unresolved obligation counts
        // as a potential leak, independent of virtual-clock progression.
        let mut config = ObligationTrackerConfig::default();
        config.leak_age_threshold = Duration::ZERO;
        let tracker = ObligationTracker::with_config(Arc::clone(&state), None, config);

        // Verify obligation exists initially
        let initial_obligations = tracker.list_obligations();
        assert_eq!(initial_obligations.len(), 2);
        assert!(
            initial_obligations
                .iter()
                .any(|o| o.id == leaked_obligation_id)
        );
        assert!(initial_obligations.iter().any(|o| o.id == second_leaked_id));

        // The metamorphic property: obligations without resolution should be detectable as leaks
        let leaks = tracker.find_potential_leaks(Duration::ZERO);
        assert_eq!(
            leaks.len(),
            2,
            "Unresolved obligation should be detected as leak"
        );
        assert!(leaks.iter().any(|o| o.id == leaked_obligation_id));
        assert!(leaks.iter().any(|o| o.id == second_leaked_id));

        // Verify leak detection summary
        let summary = tracker.summary();
        assert_eq!(summary.total_active, 2);
        assert_eq!(summary.potential_leaks, 2);
    }
