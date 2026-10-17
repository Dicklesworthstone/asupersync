    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::types::{CancelKind, CancelReason};

    #[test]
    fn test_debt_monitor_creation() {
        let config = CancellationDebtConfig::default();
        let monitor = CancellationDebtMonitor::new(config);

        let snapshot = monitor.get_debt_snapshot();
        assert_eq!(snapshot.total_pending, 0);
        assert_eq!(snapshot.debt_percentage, 0.0);
    }

    #[test]
    fn test_work_lifecycle() {
        let monitor = CancellationDebtMonitor::default();

        let work_id = monitor.queue_work(
            WorkType::TaskCleanup,
            "test-task".to_string(),
            10,
            100,
            &CancelReason::user("test"),
            CancelKind::User,
            Vec::new(),
        );

        let snapshot = monitor.get_debt_snapshot();
        assert_eq!(snapshot.total_pending, 1);
        assert!(
            snapshot
                .pending_by_type
                .contains_key(&WorkType::TaskCleanup)
        );

        let completed = monitor.complete_work(work_id);
        assert!(completed);

        let snapshot = monitor.get_debt_snapshot();
        assert_eq!(snapshot.total_pending, 0);
    }

    #[test]
    fn test_debt_calculation() {
        let mut config = CancellationDebtConfig::default();
        config.max_queue_depth = 100;
        let monitor = CancellationDebtMonitor::new(config);

        // Queue 75 items (should trigger warning at 75% threshold)
        for i in 0..75 {
            monitor.queue_work(
                WorkType::TaskCleanup,
                format!("task-{}", i),
                1,
                10,
                &CancelReason::user("test"),
                CancelKind::User,
                Vec::new(),
            );
        }

        let snapshot = monitor.get_debt_snapshot();
        assert_eq!(snapshot.total_pending, 75);
        assert_eq!(snapshot.debt_percentage, 75.0);
    }

    #[test]
    fn test_batch_completion() {
        let monitor = CancellationDebtMonitor::default();

        let work_ids: Vec<u64> = (0..5)
            .map(|i| {
                monitor.queue_work(
                    WorkType::ResourceFinalization,
                    format!("resource-{}", i),
                    1,
                    50,
                    &CancelReason::user("batch_test"),
                    CancelKind::User,
                    Vec::new(),
                )
            })
            .collect();

        let completed = monitor.complete_work_batch(&work_ids);
        assert_eq!(completed, 5);

        let snapshot = monitor.get_debt_snapshot();
        assert_eq!(snapshot.total_pending, 0);
    }

    #[test]
    fn test_priority_work_retrieval() {
        let monitor = CancellationDebtMonitor::default();

        // Queue work with different priorities
        monitor.queue_work(
            WorkType::TaskCleanup,
            "low-priority".to_string(),
            1,
            10,
            &CancelReason::user("test"),
            CancelKind::User,
            Vec::new(),
        );

        monitor.queue_work(
            WorkType::TaskCleanup,
            "high-priority".to_string(),
            100,
            10,
            &CancelReason::user("test"),
            CancelKind::User,
            Vec::new(),
        );

        let priority_work = monitor.get_priority_work(5);
        assert_eq!(priority_work.len(), 2);
        assert_eq!(priority_work[0].priority, 100); // High priority first
        assert_eq!(priority_work[1].priority, 1);
    }

    #[test]
    fn test_emergency_cleanup() {
        let monitor = CancellationDebtMonitor::default();

        // Queue some work and explicitly age it; relying on a 1 ms wall-clock
        // gap is scheduler- and platform-dependent.
        let work_id = monitor.queue_work(
            WorkType::ChannelCleanup,
            "old-work".to_string(),
            1,
            10,
            &CancelReason::user("test"),
            CancelKind::User,
            Vec::new(),
        );
        {
            let mut pending = monitor.pending_work.lock();
            let work = pending
                .get_mut(&WorkType::ChannelCleanup)
                .and_then(|work_map| work_map.get_mut(&work_id))
                .expect("queued work must be present");
            work.queued_at = SystemTime::UNIX_EPOCH;
        }

        // Emergency cleanup with very short age (should clean everything)
        let cleaned = monitor.emergency_cleanup(Duration::from_millis(1));
        assert!(cleaned > 0);

        let snapshot = monitor.get_debt_snapshot();
        assert_eq!(snapshot.total_pending, 0);
    }

    /// br-asupersync-i40ap4 — long cancel-reason text is truncated at the
    /// configured byte cap so attacker-controlled reasons cannot amplify
    /// the per-entry memory footprint.
    #[test]
    fn cancel_reason_truncated_at_byte_cap() {
        let mut config = CancellationDebtConfig::default();
        config.max_cancel_reason_bytes = 16;
        let monitor = CancellationDebtMonitor::new(config);

        let long = "A".repeat(10_000);
        let mut reason = CancelReason::new(CancelKind::User);
        reason.message = Some(long);
        let id = monitor.queue_work(
            WorkType::TaskCleanup,
            "entity".into(),
            1,
            1,
            &reason,
            CancelKind::User,
            Vec::new(),
        );

        let work = monitor
            .get_priority_work(10)
            .into_iter()
            .find(|w| w.work_id == id)
            .expect("queued work present");
        // Truncated text is at most max_cancel_reason_bytes + 3 (ellipsis is
        // 3 bytes in UTF-8) and ends with the ellipsis character.
        assert!(
            work.cancel_reason.len() <= 16 + 3,
            "cancel_reason exceeded cap: {} bytes",
            work.cancel_reason.len()
        );
        assert!(
            work.cancel_reason.ends_with('…'),
            "expected ellipsis suffix on truncated reason: {:?}",
            work.cancel_reason
        );
    }

    /// br-asupersync-i40ap4 — short cancel-reason text passes through
    /// unchanged (no spurious truncation).
    #[test]
    fn cancel_reason_short_passes_through() {
        let monitor = CancellationDebtMonitor::default();
        let reason = CancelReason::user("short");
        let id = monitor.queue_work(
            WorkType::TaskCleanup,
            "entity".into(),
            1,
            1,
            &reason,
            CancelKind::User,
            Vec::new(),
        );
        let work = monitor
            .get_priority_work(10)
            .into_iter()
            .find(|w| w.work_id == id)
            .unwrap();
        assert!(!work.cancel_reason.ends_with('…'));
        assert!(!work.cancel_reason.is_empty());
    }

    /// br-asupersync-i40ap4 — once per-WorkType cap is reached, the oldest
    /// entry is evicted on each new insert and `eviction_count` advances.
    #[test]
    fn per_work_type_cap_evicts_oldest() {
        let mut config = CancellationDebtConfig::default();
        config.max_pending_per_work_type = 4;
        let monitor = CancellationDebtMonitor::new(config);

        let mut ids = Vec::new();
        for i in 0..4 {
            ids.push(monitor.queue_work(
                WorkType::TaskCleanup,
                format!("task-{i}"),
                1,
                1,
                &CancelReason::user("x"),
                CancelKind::User,
                Vec::new(),
            ));
        }
        assert_eq!(monitor.get_debt_snapshot().total_pending, 4);
        assert_eq!(monitor.eviction_count(), 0);

        // Inserting a 5th must evict an older entry.
        let _new_id = monitor.queue_work(
            WorkType::TaskCleanup,
            "task-5".into(),
            1,
            1,
            &CancelReason::user("x"),
            CancelKind::User,
            Vec::new(),
        );
        assert_eq!(monitor.get_debt_snapshot().total_pending, 4);
        assert_eq!(monitor.eviction_count(), 1);

        // Sanity: a different WorkType is independently capped.
        for i in 0..4 {
            monitor.queue_work(
                WorkType::ChannelCleanup,
                format!("chan-{i}"),
                1,
                1,
                &CancelReason::user("x"),
                CancelKind::User,
                Vec::new(),
            );
        }
        assert_eq!(monitor.get_debt_snapshot().total_pending, 8);
        assert_eq!(monitor.eviction_count(), 1);
    }

    /// br-asupersync-37sffr — the alert level transitions atomically through
    /// the AtomicU8 store; concurrent observers always see one of the
    /// well-formed enum variants, never a torn/poisoned state.
    #[test]
    fn alert_level_atomic_roundtrip() {
        for level in [
            DebtAlertLevel::Normal,
            DebtAlertLevel::Watch,
            DebtAlertLevel::Warning,
            DebtAlertLevel::Critical,
            DebtAlertLevel::Emergency,
        ] {
            assert_eq!(DebtAlertLevel::from_u8(level.as_u8()), level);
        }
        // Out-of-range bytes defensively decode to Normal.
        assert_eq!(DebtAlertLevel::from_u8(255), DebtAlertLevel::Normal);
        assert_eq!(DebtAlertLevel::from_u8(99), DebtAlertLevel::Normal);
    }

    /// br-asupersync-i40ap4 — `truncate_to_bytes` respects UTF-8 character
    /// boundaries (does not split a multi-byte codepoint mid-sequence).
    #[test]
    fn truncate_to_bytes_respects_utf8_boundaries() {
        // 4-byte UTF-8 codepoint (😀 = U+1F600 = F0 9F 98 80).
        let s = "ABC😀DEF";
        // Cap of 5 forces truncation between A,B,C and the emoji.
        let out = truncate_to_bytes(s, 5);
        assert!(out.is_char_boundary(out.len()));
        // 4 bytes ABC + 3 bytes for ellipsis.
        // The truncation may stop after "ABC" (3 bytes) so the resulting
        // truncated portion is "ABC" + "…".
        assert!(out.starts_with("ABC"));
        assert!(out.ends_with('…'));
        // Cap exceeding the input length leaves it untouched.
        assert_eq!(truncate_to_bytes("hi", 100), "hi");
    }

    #[test]
    fn system_time_windows_do_not_underflow_near_epoch() {
        let mut stats = ProcessingStats {
            items_processed: VecDeque::new(),
            total_processed: AtomicU64::new(0),
            last_rate: 0.0,
            last_rate_time: SystemTime::UNIX_EPOCH,
        };

        stats.record_processing(1, SystemTime::UNIX_EPOCH, Duration::MAX);
        let rate = stats.calculate_rate(
            Duration::MAX,
            SystemTime::UNIX_EPOCH + Duration::from_secs(6),
        );

        assert_eq!(
            saturating_system_time_sub(SystemTime::UNIX_EPOCH, Duration::MAX),
            SystemTime::UNIX_EPOCH
        );
        assert!(rate.is_finite());
    }

    #[test]
    fn age_based_cleanup_tolerates_oversized_windows() {
        let monitor = CancellationDebtMonitor::default();
        let id = monitor.queue_work(
            WorkType::ChannelCleanup,
            "epoch-safe-work".to_string(),
            1,
            10,
            &CancelReason::user("epoch-safe"),
            CancelKind::User,
            Vec::new(),
        );

        monitor.clear_old_alerts(Duration::MAX);
        let cleaned = monitor.emergency_cleanup(Duration::MAX);

        assert_eq!(cleaned, 0);
        assert!(monitor.complete_work(id));
    }

    /// br-asupersync-af24n5 — entity_queue_depths in DebtSnapshot
    /// MUST stay bounded when work is queued under attacker-shaped
    /// (high-cardinality) entity_ids. Excess entities fold into
    /// the `__overflow__` sentinel.
    #[test]
    fn af24n5_entity_queue_depths_cap_with_overflow_bucket() {
        let monitor = CancellationDebtMonitor::default();
        let cap = super::MAX_QUEUE_DEPTH_ENTITIES;
        let total = cap + 100;
        let reason = CancelReason::user("af24n5-cap-test");
        for i in 0..total {
            let _ = monitor.queue_work(
                WorkType::TaskCleanup,
                format!("entity_{i}"),
                10,
                1,
                &reason,
                CancelKind::User,
                Vec::new(),
            );
        }
        let snapshot = monitor.get_debt_snapshot();
        assert!(
            snapshot.entity_queue_depths.len() <= cap + 1,
            "entity_queue_depths grew past cap+overflow: {} (cap {cap})",
            snapshot.entity_queue_depths.len()
        );
        assert!(
            snapshot
                .entity_queue_depths
                .contains_key(super::QUEUE_DEPTH_OVERFLOW_BUCKET),
            "overflow sentinel must be present once cap is exceeded"
        );
    }
