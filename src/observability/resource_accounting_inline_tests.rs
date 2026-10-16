    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn assert_summary_snapshot(snapshot_name: &str, summary: &str) {
        insta::with_settings!({
            snapshot_path => "snapshots",
            prepend_module_to_snapshot => false,
        }, {
            insta::assert_snapshot!(snapshot_name, summary);
        });
    }

    #[test]
    fn obligation_lifecycle_tracking() {
        let acc = ResourceAccounting::new();

        acc.obligation_reserved(ObligationKind::SendPermit);
        acc.obligation_reserved(ObligationKind::SendPermit);
        acc.obligation_reserved(ObligationKind::Lease);

        assert_eq!(
            acc.obligations_reserved_by_kind(ObligationKind::SendPermit),
            2
        );
        assert_eq!(acc.obligations_reserved_by_kind(ObligationKind::Lease), 1);
        assert_eq!(acc.obligations_reserved_by_kind(ObligationKind::Ack), 0);
        assert_eq!(acc.obligations_reserved_total(), 3);
        assert_eq!(acc.obligations_pending(), 3);
        assert_eq!(acc.obligations_peak(), 3);

        acc.obligation_committed(ObligationKind::SendPermit);
        assert_eq!(
            acc.obligations_committed_by_kind(ObligationKind::SendPermit),
            1
        );
        assert_eq!(acc.obligations_pending(), 2);

        acc.obligation_aborted(ObligationKind::SendPermit);
        assert_eq!(
            acc.obligations_aborted_by_kind(ObligationKind::SendPermit),
            1
        );
        assert_eq!(acc.obligations_pending(), 1);

        acc.obligation_leaked(ObligationKind::Lease);
        assert_eq!(acc.obligations_leaked_by_kind(ObligationKind::Lease), 1);
        assert_eq!(acc.obligations_pending(), 0);
        assert_eq!(acc.obligations_leaked_total(), 1);

        // Peak should still be 3
        assert_eq!(acc.obligations_peak(), 3);
    }

    #[test]
    fn peak_updates_correctly() {
        let acc = ResourceAccounting::new();

        // Reserve 5, then resolve 3, then reserve 2 more
        for _ in 0..5 {
            acc.obligation_reserved(ObligationKind::Ack);
        }
        assert_eq!(acc.obligations_peak(), 5);

        for _ in 0..3 {
            acc.obligation_committed(ObligationKind::Ack);
        }
        assert_eq!(acc.obligations_pending(), 2);
        assert_eq!(acc.obligations_peak(), 5); // peak unchanged

        for _ in 0..2 {
            acc.obligation_reserved(ObligationKind::Ack);
        }
        assert_eq!(acc.obligations_pending(), 4);
        assert_eq!(acc.obligations_peak(), 5); // peak still 5

        // Push past peak
        for _ in 0..2 {
            acc.obligation_reserved(ObligationKind::Ack);
        }
        assert_eq!(acc.obligations_peak(), 6);
    }

    #[test]
    fn budget_consumption_tracking() {
        let acc = ResourceAccounting::new();

        acc.poll_consumed(10);
        acc.poll_consumed(5);
        assert_eq!(acc.total_poll_consumed(), 15);

        acc.cost_consumed(100);
        assert_eq!(acc.total_cost_consumed(), 100);

        acc.poll_quota_exhausted();
        acc.poll_quota_exhausted();
        assert_eq!(acc.total_poll_exhaustions(), 2);

        acc.cost_quota_exhausted();
        assert_eq!(acc.total_cost_exhaustions(), 1);

        acc.deadline_missed();
        acc.deadline_missed();
        acc.deadline_missed();
        assert_eq!(acc.total_deadline_misses(), 3);
    }

    #[test]
    fn admission_control_tracking() {
        let acc = ResourceAccounting::new();

        acc.admission_succeeded(AdmissionKind::Task);
        acc.admission_succeeded(AdmissionKind::Task);
        acc.admission_succeeded(AdmissionKind::Task);
        acc.admission_rejected(AdmissionKind::Task);

        assert_eq!(acc.admissions_succeeded_by_kind(AdmissionKind::Task), 3);
        assert_eq!(acc.admissions_rejected_by_kind(AdmissionKind::Task), 1);

        acc.admission_rejected(AdmissionKind::Child);
        acc.admission_rejected(AdmissionKind::Obligation);
        assert_eq!(acc.admissions_rejected_total(), 3);
    }

    #[test]
    fn high_water_marks() {
        let acc = ResourceAccounting::new();

        acc.update_tasks_peak(5);
        assert_eq!(acc.tasks_peak(), 5);

        acc.update_tasks_peak(3); // lower — no change
        assert_eq!(acc.tasks_peak(), 5);

        acc.update_tasks_peak(8); // higher — updates
        assert_eq!(acc.tasks_peak(), 8);

        acc.update_children_peak(2);
        assert_eq!(acc.children_peak(), 2);

        acc.update_heap_bytes_peak(1024);
        assert_eq!(acc.heap_bytes_peak(), 1024);
    }

    #[test]
    fn snapshot_captures_all_stats() {
        let acc = ResourceAccounting::new();

        acc.obligation_reserved(ObligationKind::SendPermit);
        acc.obligation_reserved(ObligationKind::Lease);
        acc.obligation_committed(ObligationKind::SendPermit);
        acc.obligation_leaked(ObligationKind::Lease);
        acc.admission_rejected(AdmissionKind::Task);
        acc.poll_consumed(42);
        acc.deadline_missed();

        let snap = acc.snapshot();

        assert_eq!(snap.total_reserved(), 2);
        assert_eq!(snap.total_leaked(), 1);
        assert_eq!(snap.total_rejections(), 1);
        assert!(!snap.is_leak_free());
        assert_eq!(snap.poll_quota_consumed, 42);
        assert_eq!(snap.deadline_misses, 1);
    }

    #[test]
    fn snapshot_is_leak_free() {
        let acc = ResourceAccounting::new();

        acc.obligation_reserved(ObligationKind::SendPermit);
        acc.obligation_committed(ObligationKind::SendPermit);

        let snap = acc.snapshot();
        assert!(snap.is_leak_free());
        assert!(snap.is_cleanup_complete());
    }

    #[test]
    fn pending_obligations_block_cleanup_completion() {
        let acc = ResourceAccounting::new();

        acc.obligation_reserved(ObligationKind::SendPermit);

        let snap = acc.snapshot();
        assert!(snap.is_leak_free(), "pending is not an explicit leak");
        assert!(snap.has_unresolved_obligations());
        assert!(
            !snap.is_cleanup_complete(),
            "cleanup is incomplete while obligations remain pending"
        );
    }

    #[test]
    fn derived_pending_prevents_fail_open_cleanup_completion() {
        let acc = ResourceAccounting::new();

        acc.obligation_reserved(ObligationKind::SendPermit);
        // Simulate a caller bug: resolving the wrong kind decrements the global
        // gauge even though the send permit itself is still unresolved.
        acc.obligation_aborted(ObligationKind::Ack);

        let snap = acc.snapshot();
        let send_permit = snap
            .obligation_stats
            .iter()
            .find(|stats| stats.kind == ObligationKind::SendPermit)
            .expect("send permit stats must be present");

        assert_eq!(
            snap.obligations_pending, 0,
            "global gauge was driven to zero"
        );
        assert_eq!(
            send_permit.pending(),
            1,
            "per-kind ledger still shows the unresolved obligation"
        );
        assert_eq!(snap.total_pending_by_stats(), 1);
        assert!(snap.has_accounting_mismatch());
        assert!(snap.has_unresolved_obligations());
        assert!(
            !snap.is_cleanup_complete(),
            "cleanup must fail closed when global and per-kind accounting disagree"
        );
    }

    #[test]
    fn obligation_kind_stats_methods() {
        let stats = ObligationKindStats {
            kind: ObligationKind::SendPermit,
            reserved: 10,
            committed: 6,
            aborted: 2,
            leaked: 1,
        };

        assert_eq!(stats.pending(), 1);
        assert!((stats.leak_rate() - 0.1).abs() < 0.001);
    }

    #[test]
    fn obligation_kind_stats_zero_reserved() {
        let stats = ObligationKindStats {
            kind: ObligationKind::Ack,
            reserved: 0,
            committed: 0,
            aborted: 0,
            leaked: 0,
        };

        assert_eq!(stats.pending(), 0);
        assert!(stats.leak_rate().abs() < f64::EPSILON);
    }

    #[test]
    fn admission_kind_stats_rejection_rate() {
        let stats = AdmissionKindStats {
            kind: AdmissionKind::Task,
            successes: 90,
            rejections: 10,
        };

        assert!((stats.rejection_rate() - 0.1).abs() < 0.001);
    }

    #[test]
    fn admission_kind_stats_zero_attempts() {
        let stats = AdmissionKindStats {
            kind: AdmissionKind::Child,
            successes: 0,
            rejections: 0,
        };

        assert!(stats.rejection_rate().abs() < f64::EPSILON);
    }

    #[test]
    fn snapshot_summary_format() {
        let acc = ResourceAccounting::new();
        acc.obligation_reserved(ObligationKind::SendPermit);
        acc.obligation_committed(ObligationKind::SendPermit);
        acc.admission_rejected(AdmissionKind::Task);

        let snap = acc.snapshot();
        let summary = snap.summary();
        assert_summary_snapshot("resource_accounting_summary_cleanup_complete", &summary);
    }

    #[test]
    fn snapshot_summary_reports_accounting_mismatch() {
        let acc = ResourceAccounting::new();
        acc.obligation_reserved(ObligationKind::Lease);
        acc.obligation_committed(ObligationKind::Ack);

        let summary = acc.snapshot().summary();
        assert_summary_snapshot("resource_accounting_summary_accounting_mismatch", &summary);
    }

    #[test]
    fn default_is_new() {
        let a = ResourceAccounting::new();
        let b = ResourceAccounting::default();

        assert_eq!(a.obligations_pending(), b.obligations_pending());
        assert_eq!(a.obligations_peak(), b.obligations_peak());
    }

    #[test]
    fn all_obligation_kinds_covered() {
        let acc = ResourceAccounting::new();

        // Ensure all kinds can be tracked without panic
        for &kind in &ALL_OBLIGATION_KINDS {
            acc.obligation_reserved(kind);
            acc.obligation_committed(kind);
        }

        let obligation_kind_count =
            u64::try_from(ALL_OBLIGATION_KINDS.len()).expect("obligation kind count fits in u64");
        assert_eq!(acc.obligations_reserved_total(), obligation_kind_count);
        assert_eq!(acc.obligations_committed_total(), obligation_kind_count);
        assert_eq!(acc.obligations_pending(), 0);
    }

    #[test]
    fn semaphore_permit_is_included_in_snapshot_and_totals() {
        let acc = ResourceAccounting::new();

        acc.obligation_reserved(ObligationKind::SemaphorePermit);
        acc.obligation_leaked(ObligationKind::SemaphorePermit);

        let snapshot = acc.snapshot();
        let stats = snapshot
            .obligation_stats
            .iter()
            .find(|stats| stats.kind == ObligationKind::SemaphorePermit)
            .expect("SemaphorePermit stats must be present");

        assert_eq!(stats.reserved, 1);
        assert_eq!(stats.leaked, 1);
        assert_eq!(snapshot.total_reserved(), 1);
        assert_eq!(snapshot.total_leaked(), 1);
    }

    #[test]
    fn all_admission_kinds_covered() {
        let acc = ResourceAccounting::new();

        for &kind in &ALL_ADMISSION_KINDS {
            acc.admission_succeeded(kind);
            acc.admission_rejected(kind);
        }

        assert_eq!(acc.admissions_rejected_total(), 4);
    }

    #[test]
    fn extra_resolution_does_not_underflow_pending_gauge() {
        let acc = ResourceAccounting::new();

        acc.obligation_committed(ObligationKind::SendPermit);
        acc.obligation_aborted(ObligationKind::Ack);
        acc.obligation_leaked(ObligationKind::Lease);

        assert_eq!(acc.obligations_pending(), 0);

        let snapshot = acc.snapshot();
        assert_eq!(snapshot.obligations_pending, 0);
    }

    #[test]
    fn duplicate_resolution_clamps_pending_gauge_at_zero() {
        let acc = ResourceAccounting::new();

        acc.obligation_reserved(ObligationKind::IoOp);
        acc.obligation_committed(ObligationKind::IoOp);
        acc.obligation_committed(ObligationKind::IoOp);
        acc.obligation_aborted(ObligationKind::IoOp);
        acc.obligation_leaked(ObligationKind::IoOp);

        assert_eq!(acc.obligations_pending(), 0);

        let stats = acc
            .snapshot()
            .obligation_stats
            .into_iter()
            .find(|stats| stats.kind == ObligationKind::IoOp)
            .expect("IoOp stats must be present");
        assert_eq!(stats.pending(), 0);
    }
