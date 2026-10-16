    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::record::TaskRecord;
    use crate::types::{Budget, CxInner, RegionId, TaskId};
    use parking_lot::{Mutex, RwLock};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, OnceLock};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    static TEST_NOW_OFFSET_NS: AtomicU64 = AtomicU64::new(0);
    static TEST_NOW_BASE: OnceLock<Instant> = OnceLock::new();
    static TEST_TIME_LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();

    fn lock_test_clock() -> std::sync::MutexGuard<'static, ()> {
        TEST_TIME_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn set_test_time(nanos: u64) {
        // Test clock access is serialized by lock_test_clock and carries no
        // side data, so atomicity is sufficient here.
        TEST_NOW_OFFSET_NS.store(nanos, Ordering::Relaxed);
    }

    fn test_now() -> Instant {
        TEST_NOW_BASE
            .get_or_init(|| {
                Instant::now()
                    .checked_add(Duration::from_secs(3600))
                    .unwrap_or_else(Instant::now)
            })
            .checked_add(Duration::from_nanos(
                TEST_NOW_OFFSET_NS.load(Ordering::Relaxed),
            ))
            .expect("deadline monitor test instant overflow")
    }

    fn make_task(
        task_id: TaskId,
        region_id: RegionId,
        created_at: Time,
        deadline: Time,
        last_checkpoint: Option<Time>,
        last_message: Option<&str>,
        task_type: Option<&str>,
    ) -> TaskRecord {
        let budget = Budget::new().with_deadline(deadline);
        let mut record = TaskRecord::new_with_time(task_id, region_id, budget, created_at);
        let mut inner = CxInner::new(region_id, task_id, budget);
        if let Some(checkpoint) = last_checkpoint {
            if let Some(message) = last_message {
                inner
                    .checkpoint_state
                    .record_with_message_at(message.to_string(), checkpoint);
            } else {
                inner.checkpoint_state.record_at(checkpoint);
            }
        }
        inner.task_type = task_type.map(std::string::ToString::to_string);
        record.set_cx_inner(Arc::new(RwLock::new(inner)));
        record
    }

    #[test]
    fn warns_on_approaching_deadline() {
        init_test("warns_on_approaching_deadline");
        let _clock_guard = lock_test_clock();
        set_test_time(0);
        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.2,
            checkpoint_timeout: Duration::from_secs(30),
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        };
        let mut monitor = DeadlineMonitor::with_time_getter(config, test_now);

        let warnings: Arc<Mutex<Vec<WarningReason>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_ref = warnings.clone();
        monitor.on_warning(move |warning| {
            warnings_ref.lock().push(warning.reason);
        });

        let task = make_task(
            TaskId::new_for_test(1, 0),
            RegionId::new_for_test(1, 0),
            Time::from_secs(0),
            Time::from_secs(100),
            Some(Time::from_secs(90)),
            None,
            None,
        );

        monitor.check(Time::from_secs(90), std::iter::once(&task));

        let recorded = {
            let recorded = warnings.lock();
            recorded.clone()
        };
        crate::assert_with_log!(
            recorded.as_slice() == [WarningReason::ApproachingDeadline],
            "approaching deadline warned",
            vec![WarningReason::ApproachingDeadline],
            recorded
        );
        crate::test_complete!("warns_on_approaching_deadline");
    }

    #[test]
    fn warns_on_no_progress() {
        init_test("warns_on_no_progress");
        let _clock_guard = lock_test_clock();
        set_test_time(0);
        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.1,
            checkpoint_timeout: Duration::from_secs(10),
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        };
        let mut monitor = DeadlineMonitor::with_time_getter(config, test_now);

        let warnings: Arc<Mutex<Vec<WarningReason>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_ref = warnings.clone();
        monitor.on_warning(move |warning| {
            warnings_ref.lock().push(warning.reason);
        });

        let task = make_task(
            TaskId::new_for_test(2, 0),
            RegionId::new_for_test(1, 0),
            Time::from_secs(0),
            Time::from_secs(1000),
            Some(Time::from_secs(0)),
            Some("stuck"),
            None,
        );

        monitor.check(Time::from_secs(100), std::iter::once(&task));

        let recorded = {
            let recorded = warnings.lock();
            recorded.clone()
        };
        crate::assert_with_log!(
            recorded.as_slice() == [WarningReason::NoProgress],
            "no progress warned",
            vec![WarningReason::NoProgress],
            recorded
        );
        crate::test_complete!("warns_on_no_progress");
    }

    #[test]
    fn warns_on_no_progress_for_old_task_without_checkpoint_on_first_scan() {
        init_test("warns_on_no_progress_for_old_task_without_checkpoint_on_first_scan");
        let _clock_guard = lock_test_clock();
        set_test_time(0);
        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.0,
            checkpoint_timeout: Duration::from_secs(10),
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        };
        let mut monitor = DeadlineMonitor::with_time_getter(config, test_now);

        let warnings: Arc<Mutex<Vec<WarningReason>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_ref = warnings.clone();
        monitor.on_warning(move |warning| {
            warnings_ref.lock().push(warning.reason);
        });

        let task = make_task(
            TaskId::new_for_test(21, 0),
            RegionId::new_for_test(1, 0),
            Time::from_secs(0),
            Time::from_secs(1_000),
            None,
            None,
            None,
        );

        // Task age is 100s without checkpoints; first scan should detect NoProgress immediately.
        monitor.check(Time::from_secs(100), std::iter::once(&task));

        let recorded = warnings.lock().clone();
        crate::assert_with_log!(
            recorded.as_slice() == [WarningReason::NoProgress],
            "old task without checkpoint warns on first scan",
            vec![WarningReason::NoProgress],
            recorded
        );
        crate::test_complete!("warns_on_no_progress_for_old_task_without_checkpoint_on_first_scan");
    }

    #[test]
    fn warns_on_no_progress_after_checkpoint_when_logical_time_advances() {
        init_test("warns_on_no_progress_after_checkpoint_when_logical_time_advances");
        let _clock_guard = lock_test_clock();
        set_test_time(0);
        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.0,
            checkpoint_timeout: Duration::from_secs(10),
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        };
        let mut monitor = DeadlineMonitor::with_time_getter(config, test_now);

        let warnings: Arc<Mutex<Vec<WarningReason>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_ref = warnings.clone();
        monitor.on_warning(move |warning| {
            warnings_ref.lock().push(warning.reason);
        });

        let task = make_task(
            TaskId::new_for_test(22, 0),
            RegionId::new_for_test(1, 0),
            Time::from_secs(0),
            Time::from_secs(1_000),
            Some(Time::from_secs(10)),
            Some("checkpointed"),
            None,
        );

        monitor.check(Time::from_secs(10), std::iter::once(&task));
        let first_count = warnings.lock().len();
        crate::assert_with_log!(
            first_count == 0,
            "no warning immediately after observing checkpoint",
            0usize,
            first_count
        );

        monitor.check(Time::from_secs(25), std::iter::once(&task));

        let recorded = warnings.lock().clone();
        crate::assert_with_log!(
            recorded.as_slice() == [WarningReason::NoProgress],
            "logical-time fallback still warns after a checkpointed task stalls",
            vec![WarningReason::NoProgress],
            recorded
        );
        crate::test_complete!("warns_on_no_progress_after_checkpoint_when_logical_time_advances");
    }

    #[test]
    fn repeated_checkpoint_count_resets_progress_without_time_advance() {
        init_test("repeated_checkpoint_count_resets_progress_without_time_advance");
        let _clock_guard = lock_test_clock();
        set_test_time(0);
        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.0,
            checkpoint_timeout: Duration::from_millis(1),
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        };
        let mut monitor = DeadlineMonitor::with_time_getter(config, test_now);

        let warnings: Arc<Mutex<Vec<WarningReason>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_ref = warnings.clone();
        monitor.on_warning(move |warning| {
            warnings_ref.lock().push(warning.reason);
        });

        let task = make_task(
            TaskId::new_for_test(23, 0),
            RegionId::new_for_test(1, 0),
            Time::from_secs(0),
            Time::from_secs(1_000),
            Some(Time::from_secs(5)),
            Some("checkpointed"),
            None,
        );

        monitor.check(Time::from_secs(5), std::iter::once(&task));
        let first_count = warnings.lock().len();
        crate::assert_with_log!(
            first_count == 0,
            "no warning on initial checkpoint observation",
            0usize,
            first_count
        );

        if let Some(inner) = task.cx_inner.as_ref() {
            let mut guard = inner.write();
            guard.checkpoint_state.checkpoint_count += 1;
            guard.checkpoint_state.last_message = Some("checkpointed again".to_string());
        }

        set_test_time(
            Duration::from_millis(2)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        monitor.check(Time::from_secs(5), std::iter::once(&task));

        let recorded = warnings.lock().clone();
        crate::assert_with_log!(
            recorded.is_empty(),
            "checkpoint count refresh suppresses false stale warning",
            true,
            recorded.is_empty()
        );
        crate::test_complete!("repeated_checkpoint_count_resets_progress_without_time_advance");
    }

    #[test]
    fn warns_only_once_per_task() {
        init_test("warns_only_once_per_task");
        let _clock_guard = lock_test_clock();
        set_test_time(0);
        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.2,
            checkpoint_timeout: Duration::from_secs(30),
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        };
        let mut monitor = DeadlineMonitor::with_time_getter(config, test_now);

        let warnings: Arc<Mutex<Vec<WarningReason>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_ref = warnings.clone();
        monitor.on_warning(move |warning| {
            warnings_ref.lock().push(warning.reason);
        });

        let task = make_task(
            TaskId::new_for_test(3, 0),
            RegionId::new_for_test(1, 0),
            Time::from_secs(0),
            Time::from_secs(10),
            None,
            None,
            None,
        );

        monitor.check(Time::from_secs(9), std::iter::once(&task));
        monitor.check(Time::from_secs(9), std::iter::once(&task));

        let count = warnings.lock().len();
        crate::assert_with_log!(count == 1, "warned once", 1usize, count);
        crate::test_complete!("warns_only_once_per_task");
    }

    #[test]
    fn check_interval_uses_logical_time_not_wall_clock() {
        init_test("check_interval_uses_logical_time_not_wall_clock");
        let _clock_guard = lock_test_clock();
        set_test_time(0);
        let config = MonitorConfig {
            check_interval: Duration::from_secs(1),
            warning_threshold_fraction: 0.2,
            checkpoint_timeout: Duration::from_secs(3600),
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        };
        let mut monitor = DeadlineMonitor::with_time_getter(config, test_now);

        let warnings: Arc<Mutex<Vec<WarningReason>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_ref = warnings.clone();
        monitor.on_warning(move |warning| {
            warnings_ref.lock().push(warning.reason);
        });

        let task = make_task(
            TaskId::new_for_test(31, 0),
            RegionId::new_for_test(1, 0),
            Time::from_secs(0),
            Time::from_secs(100),
            None,
            None,
            None,
        );

        // First scan at t=0 should not warn.
        monitor.check(Time::from_secs(0), std::iter::once(&task));
        let first_count = warnings.lock().len();
        crate::assert_with_log!(first_count == 0, "no warning at t=0", 0usize, first_count);

        // Immediate second call advances logical time beyond check_interval and near deadline.
        // This must produce a warning even when little wall-clock time has elapsed.
        monitor.check(Time::from_secs(90), std::iter::once(&task));
        let recorded = warnings.lock().clone();
        crate::assert_with_log!(
            recorded.as_slice() == [WarningReason::ApproachingDeadline],
            "warning emitted after logical-time advance",
            vec![WarningReason::ApproachingDeadline],
            recorded
        );
        crate::test_complete!("check_interval_uses_logical_time_not_wall_clock");
    }

    #[test]
    fn check_interval_falls_back_to_time_getter_when_logical_time_is_stable() {
        init_test("check_interval_falls_back_to_time_getter_when_logical_time_is_stable");
        let _clock_guard = lock_test_clock();
        set_test_time(0);
        let config = MonitorConfig {
            check_interval: Duration::from_millis(5),
            warning_threshold_fraction: 0.0,
            checkpoint_timeout: Duration::from_millis(1),
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        };
        let mut monitor = DeadlineMonitor::with_time_getter(config, test_now);

        let warnings: Arc<Mutex<Vec<WarningReason>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_ref = warnings.clone();
        monitor.on_warning(move |warning| {
            warnings_ref.lock().push(warning.reason);
        });

        let task = make_task(
            TaskId::new_for_test(32, 0),
            RegionId::new_for_test(1, 0),
            Time::from_secs(0),
            Time::from_secs(1_000),
            None,
            None,
            None,
        );

        monitor.check(Time::from_secs(0), std::iter::once(&task));
        let first_count = warnings.lock().len();
        crate::assert_with_log!(
            first_count == 0,
            "no warning on first scan",
            0usize,
            first_count
        );

        set_test_time(
            Duration::from_millis(10)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        monitor.check(Time::from_secs(0), std::iter::once(&task));
        let recorded = warnings.lock().clone();
        crate::assert_with_log!(
            recorded.as_slice() == [WarningReason::NoProgress],
            "time getter fallback allows progress checks with stable logical time",
            vec![WarningReason::NoProgress],
            recorded
        );
        crate::test_complete!(
            "check_interval_falls_back_to_time_getter_when_logical_time_is_stable"
        );
    }

    #[test]
    fn warns_on_both_conditions() {
        init_test("warns_on_both_conditions");
        let _clock_guard = lock_test_clock();
        set_test_time(0);
        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.5,
            checkpoint_timeout: Duration::from_secs(10),
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        };
        let mut monitor = DeadlineMonitor::with_time_getter(config, test_now);

        let warnings: Arc<Mutex<Vec<WarningReason>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_ref = warnings.clone();
        monitor.on_warning(move |warning| {
            warnings_ref.lock().push(warning.reason);
        });

        let task = make_task(
            TaskId::new_for_test(4, 0),
            RegionId::new_for_test(1, 0),
            Time::from_secs(0),
            Time::from_secs(20),
            Some(Time::from_secs(0)),
            None,
            None,
        );

        monitor.check(Time::from_secs(11), std::iter::once(&task));

        let recorded = {
            let recorded = warnings.lock();
            recorded.clone()
        };
        crate::assert_with_log!(
            recorded.as_slice() == [WarningReason::ApproachingDeadlineNoProgress],
            "warned for both conditions",
            vec![WarningReason::ApproachingDeadlineNoProgress],
            recorded
        );
        drop(recorded);
        crate::test_complete!("warns_on_both_conditions");
    }

    #[test]
    fn no_warning_with_recent_checkpoint() {
        init_test("no_warning_with_recent_checkpoint");
        let _clock_guard = lock_test_clock();
        set_test_time(0);
        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.0,
            checkpoint_timeout: Duration::from_secs(60),
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        };
        let mut monitor = DeadlineMonitor::with_time_getter(config, test_now);

        let warnings: Arc<Mutex<Vec<DeadlineWarning>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_ref = warnings.clone();
        monitor.on_warning(move |warning| {
            warnings_ref.lock().push(warning);
        });

        let task = make_task(
            TaskId::new_for_test(5, 0),
            RegionId::new_for_test(1, 0),
            Time::from_secs(0),
            Time::from_secs(1000),
            Some(Time::from_secs(10)),
            Some("recent checkpoint"),
            None,
        );

        monitor.check(Time::from_secs(10), std::iter::once(&task));

        let empty = warnings.lock().is_empty();
        crate::assert_with_log!(empty, "no warnings", true, empty);
        crate::test_complete!("no_warning_with_recent_checkpoint");
    }

    #[test]
    fn no_warning_when_checkpoint_time_is_ahead_of_monitor_clock() {
        init_test("no_warning_when_checkpoint_time_is_ahead_of_monitor_clock");
        let _clock_guard = lock_test_clock();
        set_test_time(0);
        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.0,
            checkpoint_timeout: Duration::from_secs(1),
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        };
        let mut monitor = DeadlineMonitor::with_time_getter(config, test_now);

        let warnings: Arc<Mutex<Vec<DeadlineWarning>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_ref = warnings.clone();
        monitor.on_warning(move |warning| {
            warnings_ref.lock().push(warning);
        });

        let future_checkpoint = Time::from_secs(130);

        let task = make_task(
            TaskId::new_for_test(51, 0),
            RegionId::new_for_test(1, 0),
            Time::from_secs(0),
            Time::from_secs(1_000),
            Some(future_checkpoint),
            Some("forward skew"),
            None,
        );

        monitor.check(Time::from_secs(10), std::iter::once(&task));

        let empty = warnings.lock().is_empty();
        crate::assert_with_log!(
            empty,
            "future checkpoint should not panic or force stale warning",
            true,
            empty
        );
        crate::test_complete!("no_warning_when_checkpoint_time_is_ahead_of_monitor_clock");
    }

    #[test]
    fn check_interval_tolerates_time_getter_going_backwards() {
        init_test("check_interval_tolerates_time_getter_going_backwards");
        let _clock_guard = lock_test_clock();
        set_test_time(1_000_000_000);
        let config = MonitorConfig {
            check_interval: Duration::from_millis(10),
            warning_threshold_fraction: 0.0,
            checkpoint_timeout: Duration::from_secs(60),
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        };
        let mut monitor = DeadlineMonitor::with_time_getter(config, test_now);

        let warnings: Arc<Mutex<Vec<DeadlineWarning>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_ref = warnings.clone();
        monitor.on_warning(move |warning| {
            warnings_ref.lock().push(warning);
        });

        let task = make_task(
            TaskId::new_for_test(52, 0),
            RegionId::new_for_test(1, 0),
            Time::from_secs(0),
            Time::from_secs(1_000),
            Some(Time::from_secs(1)),
            Some("baseline"),
            None,
        );

        monitor.check(Time::from_secs(1), std::iter::once(&task));
        set_test_time(100_000_000);
        monitor.check(Time::from_secs(2), std::iter::once(&task));

        let empty = warnings.lock().is_empty();
        crate::assert_with_log!(
            empty,
            "backward monitor clock should not panic",
            true,
            empty
        );
        crate::test_complete!("check_interval_tolerates_time_getter_going_backwards");
    }

    #[test]
    fn warning_includes_checkpoint_message() {
        init_test("warning_includes_checkpoint_message");
        let _clock_guard = lock_test_clock();
        set_test_time(0);
        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.0,
            checkpoint_timeout: Duration::ZERO,
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        };
        let mut monitor = DeadlineMonitor::with_time_getter(config, test_now);

        let warnings: Arc<Mutex<Vec<DeadlineWarning>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_ref = warnings.clone();
        monitor.on_warning(move |warning| {
            warnings_ref.lock().push(warning);
        });

        let task = make_task(
            TaskId::new_for_test(6, 0),
            RegionId::new_for_test(1, 0),
            Time::from_secs(0),
            Time::from_secs(1000),
            Some(Time::from_secs(0)),
            Some("checkpoint message"),
            None,
        );

        monitor.check(Time::from_secs(10), std::iter::once(&task));

        let warning = warnings.lock().first().cloned().expect("expected warning");
        crate::assert_with_log!(
            warning.reason == WarningReason::NoProgress,
            "reason",
            WarningReason::NoProgress,
            warning.reason
        );
        crate::assert_with_log!(
            warning.last_checkpoint_message.as_deref() == Some("checkpoint message"),
            "checkpoint message",
            Some("checkpoint message"),
            warning.last_checkpoint_message.as_deref()
        );
        crate::assert_with_log!(
            warning.checkpoint_history.as_slice()
                == [(Time::from_secs(0), "checkpoint message".to_string())],
            "checkpoint history trail",
            vec![(Time::from_secs(0), "checkpoint message".to_string())],
            warning.checkpoint_history.clone()
        );
        crate::test_complete!("warning_includes_checkpoint_message");
    }

    #[test]
    fn render_checkpoint_trail_golden() {
        // AC3: golden rendering of the trail. Logical `Time` is deterministic,
        // so the rendered string is fully scrubbed (no wall-clock content).
        init_test("render_checkpoint_trail_golden");
        let trail = vec![
            (Time::from_nanos(1), "connect".to_string()),
            (Time::from_nanos(2), "auth".to_string()),
            (Time::from_nanos(5_000), "query".to_string()),
        ];
        let rendered = render_checkpoint_trail(&trail).expect("non-empty trail renders");
        crate::assert_with_log!(
            rendered == "[t=1ns] connect → [t=2ns] auth → [t=5us] query",
            "golden trail rendering",
            "[t=1ns] connect → [t=2ns] auth → [t=5us] query",
            rendered
        );
        assert_eq!(
            render_checkpoint_trail(&[]),
            None,
            "empty trail renders None"
        );
        crate::test_complete!("render_checkpoint_trail_golden");
    }

    #[test]
    fn render_checkpoint_trail_scrubs_control_characters() {
        // Scrubbing keeps the diagnostic single-line and injection-safe.
        init_test("render_checkpoint_trail_scrubs_control_characters");
        let trail = vec![(
            Time::from_nanos(7),
            "evil\nline\tbreak\r\u{1b}[31m".to_string(),
        )];
        let rendered = render_checkpoint_trail(&trail).expect("renders");
        assert!(
            !rendered.contains('\n') && !rendered.contains('\t') && !rendered.contains('\r'),
            "control characters must be scrubbed: {rendered:?}"
        );
        crate::assert_with_log!(
            rendered == "[t=7ns] evil line break  [31m",
            "scrubbed trail rendering",
            "[t=7ns] evil line break  [31m",
            rendered
        );
        crate::test_complete!("render_checkpoint_trail_scrubs_control_characters");
    }

    #[test]
    fn render_checkpoint_trail_bounds_overflow() {
        // The defensive render bound summarises overflow rather than emitting
        // an unbounded line, even if handed more than the per-task ring cap.
        init_test("render_checkpoint_trail_bounds_overflow");
        let trail: Vec<(Time, String)> = (0..(MAX_RENDERED_TRAIL_ENTRIES as u64 + 3))
            .map(|n| (Time::from_nanos(n), format!("step{n}")))
            .collect();
        let rendered = render_checkpoint_trail(&trail).expect("renders");
        assert!(
            rendered.ends_with("… (+3 more)"),
            "overflow summarised: {rendered}"
        );
        // Exactly MAX_RENDERED_TRAIL_ENTRIES separators-worth of entries shown.
        assert_eq!(
            rendered.matches(" → ").count(),
            MAX_RENDERED_TRAIL_ENTRIES - 1
        );
        crate::test_complete!("render_checkpoint_trail_bounds_overflow");
    }

    #[test]
    fn render_checkpoint_trail_is_byte_identical_across_replays() {
        // AC4: lab determinism. The render is a pure function of logical time
        // and bounded messages, so independently-built identical trails (as a
        // deterministic replay would reproduce) render byte-for-byte the same.
        init_test("render_checkpoint_trail_is_byte_identical_across_replays");
        let build = || {
            let mut state = crate::types::CheckpointState::with_history_capacity(8);
            for (n, msg) in ["connect", "auth", "query", "write", "flush"]
                .iter()
                .enumerate()
            {
                state.record_with_message_at((*msg).to_string(), Time::from_nanos(n as u64 + 1));
            }
            let trail: Vec<(Time, String)> = state
                .history()
                .into_iter()
                .map(|e| (e.at, e.message))
                .collect();
            render_checkpoint_trail(&trail)
        };
        let first = build();
        let second = build();
        crate::assert_with_log!(
            first == second,
            "byte-identical trail across replays",
            first.clone(),
            second.clone()
        );
        assert_eq!(
            first.as_deref(),
            Some("[t=1ns] connect → [t=2ns] auth → [t=3ns] query → [t=4ns] write → [t=5ns] flush")
        );
        crate::test_complete!("render_checkpoint_trail_is_byte_identical_across_replays");
    }

    #[derive(Default)]
    struct TestMetrics {
        warnings: AtomicU64,
        violations: AtomicU64,
        stuck: AtomicU64,
        remaining_samples: Mutex<Vec<Duration>>,
        checkpoint_intervals: Mutex<Vec<Duration>>,
    }

    impl MetricsProvider for TestMetrics {
        fn task_spawned(&self, _: RegionId, _: TaskId) {}
        fn task_completed(
            &self,
            _: TaskId,
            _: crate::observability::metrics::OutcomeKind,
            _: Duration,
        ) {
        }
        fn region_created(&self, _: RegionId, _: Option<RegionId>) {}
        fn region_closed(&self, _: RegionId, _: Duration) {}
        fn cancellation_requested(&self, _: RegionId, _: crate::types::CancelKind) {}
        fn drain_completed(&self, _: RegionId, _: Duration) {}
        fn deadline_set(&self, _: RegionId, _: Duration) {}
        fn deadline_exceeded(&self, _: RegionId) {}
        fn obligation_created(&self, _: RegionId) {}
        fn obligation_discharged(&self, _: RegionId) {}
        fn obligation_leaked(&self, _: RegionId) {}
        fn scheduler_tick(&self, _: usize, _: Duration) {}

        fn deadline_warning(&self, _: &str, _: &'static str, _: Duration) {
            self.warnings.fetch_add(1, Ordering::Relaxed);
        }

        fn deadline_violation(&self, _: &str, _: Duration) {
            self.violations.fetch_add(1, Ordering::Relaxed);
        }

        fn deadline_remaining(&self, _: &str, remaining: Duration) {
            self.remaining_samples.lock().push(remaining);
        }

        fn checkpoint_interval(&self, _: &str, interval: Duration) {
            self.checkpoint_intervals.lock().push(interval);
        }

        fn task_stuck_detected(&self, _: &str) {
            self.stuck.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn adaptive_threshold_uses_percentile() {
        init_test("adaptive_threshold_uses_percentile");
        let _clock_guard = lock_test_clock();
        set_test_time(0);
        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.2,
            checkpoint_timeout: Duration::from_secs(60),
            adaptive: AdaptiveDeadlineConfig {
                adaptive_enabled: true,
                warning_percentile: 0.5,
                min_samples: 3,
                max_history: 1000,
                fallback_threshold: Duration::from_secs(5),
            },
            enabled: true,
        };
        let mut monitor = DeadlineMonitor::with_time_getter(config, test_now);

        monitor.record_completion(
            TaskId::new_for_test(10, 0),
            "alpha",
            Duration::from_secs(10),
            None,
            Time::from_secs(10),
        );
        monitor.record_completion(
            TaskId::new_for_test(11, 0),
            "alpha",
            Duration::from_secs(20),
            None,
            Time::from_secs(20),
        );
        monitor.record_completion(
            TaskId::new_for_test(12, 0),
            "alpha",
            Duration::from_secs(30),
            None,
            Time::from_secs(30),
        );

        let warnings: Arc<Mutex<Vec<WarningReason>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_ref = warnings.clone();
        monitor.on_warning(move |warning| {
            warnings_ref.lock().push(warning.reason);
        });

        let task = make_task(
            TaskId::new_for_test(7, 0),
            RegionId::new_for_test(1, 0),
            Time::from_secs(0),
            Time::from_secs(1000),
            None,
            None,
            Some("alpha"),
        );

        // Elapsed 25s > p50 (20s) => warning
        monitor.check(Time::from_secs(25), std::iter::once(&task));

        let recorded = warnings.lock().clone();
        crate::assert_with_log!(
            recorded.as_slice() == [WarningReason::ApproachingDeadline],
            "adaptive warning",
            vec![WarningReason::ApproachingDeadline],
            recorded
        );
        crate::test_complete!("adaptive_threshold_uses_percentile");
    }

    #[test]
    fn adaptive_threshold_fallback_used() {
        init_test("adaptive_threshold_fallback_used");
        let _clock_guard = lock_test_clock();
        set_test_time(0);
        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.2,
            checkpoint_timeout: Duration::from_secs(60),
            adaptive: AdaptiveDeadlineConfig {
                adaptive_enabled: true,
                warning_percentile: 0.9,
                min_samples: 5,
                max_history: 1000,
                fallback_threshold: Duration::from_secs(5),
            },
            enabled: true,
        };
        let mut monitor = DeadlineMonitor::with_time_getter(config, test_now);

        monitor.record_completion(
            TaskId::new_for_test(13, 0),
            "beta",
            Duration::from_secs(2),
            None,
            Time::from_secs(2),
        );

        let warnings: Arc<Mutex<Vec<WarningReason>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_ref = warnings.clone();
        monitor.on_warning(move |warning| {
            warnings_ref.lock().push(warning.reason);
        });

        let task = make_task(
            TaskId::new_for_test(8, 0),
            RegionId::new_for_test(1, 0),
            Time::from_secs(0),
            Time::from_secs(1000),
            None,
            None,
            Some("beta"),
        );

        // Elapsed 6s > fallback 5s => warning
        monitor.check(Time::from_secs(6), std::iter::once(&task));

        let recorded = warnings.lock().clone();
        crate::assert_with_log!(
            recorded.as_slice() == [WarningReason::ApproachingDeadline],
            "fallback warning",
            vec![WarningReason::ApproachingDeadline],
            recorded
        );
        crate::test_complete!("adaptive_threshold_fallback_used");
    }

    #[test]
    fn deadline_metrics_emitted() {
        init_test("deadline_metrics_emitted");
        let _clock_guard = lock_test_clock();
        set_test_time(0);
        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.0,
            checkpoint_timeout: Duration::ZERO,
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        };
        let mut monitor = DeadlineMonitor::with_time_getter(config, test_now);
        let metrics = Arc::new(TestMetrics::default());
        monitor.set_metrics_provider(metrics.clone());

        let task = make_task(
            TaskId::new_for_test(9, 0),
            RegionId::new_for_test(1, 0),
            Time::from_secs(0),
            Time::from_secs(10),
            Some(Time::from_secs(0)),
            Some("stuck"),
            Some("gamma"),
        );

        monitor.check(Time::from_secs(9), std::iter::once(&task));

        let warnings = metrics.warnings.load(Ordering::Relaxed);
        let stuck = metrics.stuck.load(Ordering::Relaxed);
        crate::assert_with_log!(warnings == 1, "warnings", 1u64, warnings);
        crate::assert_with_log!(stuck == 1, "stuck", 1u64, stuck);

        // Record completion with deadline exceeded to emit remaining + violation.
        monitor.record_completion(
            TaskId::new_for_test(9, 0),
            "gamma",
            Duration::from_secs(12),
            Some(Time::from_secs(10)),
            Time::from_secs(12),
        );

        let violations = metrics.violations.load(Ordering::Relaxed);
        crate::assert_with_log!(violations == 1, "violations", 1u64, violations);
        let remaining = metrics.remaining_samples.lock().len();
        crate::assert_with_log!(remaining == 1, "remaining samples", 1usize, remaining);
        crate::test_complete!("deadline_metrics_emitted");
    }

    #[test]
    fn checkpoint_interval_metrics_emitted() {
        init_test("checkpoint_interval_metrics_emitted");
        let _clock_guard = lock_test_clock();
        set_test_time(0);
        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.2,
            checkpoint_timeout: Duration::from_secs(60),
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        };
        let mut monitor = DeadlineMonitor::with_time_getter(config, test_now);
        let metrics = Arc::new(TestMetrics::default());
        monitor.set_metrics_provider(metrics.clone());

        let first = Time::from_millis(100);
        let second = Time::from_millis(700);
        let task = make_task(
            TaskId::new_for_test(10, 0),
            RegionId::new_for_test(1, 0),
            Time::from_secs(0),
            Time::from_secs(100),
            Some(first),
            None,
            Some("delta"),
        );

        monitor.check(Time::from_secs(1), std::iter::once(&task));

        if let Some(inner) = task.cx_inner.as_ref() {
            let mut guard = inner.write();
            guard.checkpoint_state.last_checkpoint = Some(second);
            guard.checkpoint_state.checkpoint_count += 1;
        }

        monitor.check(Time::from_secs(2), std::iter::once(&task));

        let intervals = metrics.checkpoint_intervals.lock().len();
        crate::assert_with_log!(intervals == 1, "checkpoint intervals", 1usize, intervals);
        crate::test_complete!("checkpoint_interval_metrics_emitted");
    }

    #[test]
    fn adaptive_deadline_config_debug() {
        init_test("adaptive_deadline_config_debug");
        let cfg = AdaptiveDeadlineConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("AdaptiveDeadlineConfig"));
        crate::test_complete!("adaptive_deadline_config_debug");
    }

    #[test]
    fn adaptive_deadline_config_clone() {
        init_test("adaptive_deadline_config_clone");
        let cfg = AdaptiveDeadlineConfig {
            adaptive_enabled: true,
            warning_percentile: 0.95,
            min_samples: 20,
            max_history: 500,
            fallback_threshold: Duration::from_secs(60),
        };
        let cfg2 = cfg;
        assert!(cfg2.adaptive_enabled);
        assert!((cfg2.warning_percentile - 0.95).abs() < f64::EPSILON);
        assert_eq!(cfg2.min_samples, 20);
        assert_eq!(cfg2.max_history, 500);
        assert_eq!(cfg2.fallback_threshold, Duration::from_secs(60));
        crate::test_complete!("adaptive_deadline_config_clone");
    }

    #[test]
    fn adaptive_deadline_config_default_values() {
        init_test("adaptive_deadline_config_default_values");
        let cfg = AdaptiveDeadlineConfig::default();
        assert!(!cfg.adaptive_enabled);
        assert!((cfg.warning_percentile - 0.90).abs() < f64::EPSILON);
        assert_eq!(cfg.min_samples, 10);
        assert_eq!(cfg.max_history, 1000);
        assert_eq!(cfg.fallback_threshold, Duration::from_secs(30));
        crate::test_complete!("adaptive_deadline_config_default_values");
    }

    #[test]
    fn monitor_config_debug() {
        init_test("monitor_config_debug");
        let cfg = MonitorConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("MonitorConfig"));
        crate::test_complete!("monitor_config_debug");
    }

    #[test]
    fn monitor_config_clone() {
        init_test("monitor_config_clone");
        let cfg = MonitorConfig {
            check_interval: Duration::from_millis(500),
            warning_threshold_fraction: 0.1,
            checkpoint_timeout: Duration::from_secs(10),
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: false,
        };
        let cfg2 = cfg;
        assert_eq!(cfg2.check_interval, Duration::from_millis(500));
        assert!((cfg2.warning_threshold_fraction - 0.1).abs() < f64::EPSILON);
        assert_eq!(cfg2.checkpoint_timeout, Duration::from_secs(10));
        assert!(!cfg2.enabled);
        crate::test_complete!("monitor_config_clone");
    }

    #[test]
    fn monitor_config_default_values() {
        init_test("monitor_config_default_values");
        let cfg = MonitorConfig::default();
        assert_eq!(cfg.check_interval, Duration::from_secs(1));
        assert!((cfg.warning_threshold_fraction - 0.2).abs() < f64::EPSILON);
        assert_eq!(cfg.checkpoint_timeout, Duration::from_secs(30));
        assert!(cfg.enabled);
        crate::test_complete!("monitor_config_default_values");
    }

    #[test]
    fn warning_reason_debug() {
        init_test("warning_reason_debug");
        let dbg = format!("{:?}", WarningReason::ApproachingDeadline);
        assert_eq!(dbg, "ApproachingDeadline");
        let dbg = format!("{:?}", WarningReason::NoProgress);
        assert_eq!(dbg, "NoProgress");
        let dbg = format!("{:?}", WarningReason::ApproachingDeadlineNoProgress);
        assert_eq!(dbg, "ApproachingDeadlineNoProgress");
        crate::test_complete!("warning_reason_debug");
    }

    #[test]
    fn warning_reason_clone_copy_eq() {
        init_test("warning_reason_clone_copy_eq");
        let r = WarningReason::NoProgress;
        let r2 = r;
        let r3 = r;
        assert_eq!(r2, r3);
        assert_ne!(
            WarningReason::NoProgress,
            WarningReason::ApproachingDeadline
        );
        crate::test_complete!("warning_reason_clone_copy_eq");
    }

    #[test]
    fn deadline_monitor_debug() {
        init_test("deadline_monitor_debug");
        let monitor = DeadlineMonitor::new(MonitorConfig::default());
        let dbg = format!("{monitor:?}");
        assert!(dbg.contains("DeadlineMonitor"));
        crate::test_complete!("deadline_monitor_debug");
    }

    #[test]
    fn deadline_monitor_config_accessor() {
        init_test("deadline_monitor_config_accessor");
        let cfg = MonitorConfig {
            check_interval: Duration::from_millis(250),
            ..MonitorConfig::default()
        };
        let monitor = DeadlineMonitor::new(cfg);
        assert_eq!(monitor.config().check_interval, Duration::from_millis(250));
        crate::test_complete!("deadline_monitor_config_accessor");
    }

    #[test]
    fn deadline_monitor_on_warning_callback() {
        init_test("deadline_monitor_on_warning_callback");
        let mut monitor = DeadlineMonitor::new(MonitorConfig::default());
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called_ref = called;
        monitor.on_warning(move |_| {
            called_ref.store(true, Ordering::Relaxed);
        });
        // Callback registered without panic
        let dbg = format!("{monitor:?}");
        assert!(dbg.contains("DeadlineMonitor"));
        crate::test_complete!("deadline_monitor_on_warning_callback");
    }
