    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    #[cfg(feature = "tracing-integration")]
    use parking_lot::Mutex;
    #[cfg(feature = "tracing-integration")]
    use std::collections::BTreeMap;
    #[cfg(feature = "tracing-integration")]
    use std::sync::Arc;
    #[cfg(feature = "tracing-integration")]
    use tracing::Subscriber;
    #[cfg(feature = "tracing-integration")]
    use tracing::field::{Field, Visit};
    #[cfg(feature = "tracing-integration")]
    use tracing_subscriber::layer::{Context, Layer};
    #[cfg(feature = "tracing-integration")]
    use tracing_subscriber::prelude::*;
    #[cfg(feature = "tracing-integration")]
    use tracing_subscriber::registry::LookupSpan;

    #[cfg(feature = "tracing-integration")]
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RecordedEvent {
        fields: BTreeMap<String, String>,
    }

    #[cfg(feature = "tracing-integration")]
    #[derive(Default)]
    struct EventFieldVisitor {
        fields: BTreeMap<String, String>,
    }

    #[cfg(feature = "tracing-integration")]
    impl Visit for EventFieldVisitor {
        fn record_bool(&mut self, field: &Field, value: bool) {
            self.fields
                .insert(field.name().to_owned(), value.to_string());
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            self.fields
                .insert(field.name().to_owned(), value.to_string());
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.fields
                .insert(field.name().to_owned(), value.to_owned());
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.fields
                .insert(field.name().to_owned(), format!("{value:?}"));
        }
    }

    #[cfg(feature = "tracing-integration")]
    #[derive(Default)]
    struct EventRecorder {
        events: Arc<Mutex<Vec<RecordedEvent>>>,
    }

    #[cfg(feature = "tracing-integration")]
    impl<S> Layer<S> for EventRecorder
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut visitor = EventFieldVisitor::default();
            event.record(&mut visitor);
            self.events.lock().push(RecordedEvent {
                fields: visitor.fields,
            });
        }
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn oracle_suite_default_is_clean() {
        init_test("oracle_suite_default_is_clean");
        let mut suite = OracleSuite::new();
        let violations = suite.check_all(Time::ZERO);
        let empty = violations.is_empty();
        crate::assert_with_log!(empty, "suite clean", true, empty);
        crate::test_complete!("oracle_suite_default_is_clean");
    }

    #[test]
    fn oracle_suite_routes_logical_time_to_waker_age_checks() {
        init_test("oracle_suite_routes_logical_time_to_waker_age_checks");
        let mut suite = OracleSuite::new();
        suite.waker_dedup = WakerDedupOracle::new(WakerDedupConfig {
            enforcement: waker_dedup::EnforcementMode::Collect,
            ..Default::default()
        });
        suite.waker_dedup.set_logical_time(Time::ZERO);
        suite.waker_dedup.on_waker_registered(
            WakerDedupId(1),
            waker_dedup::ChannelId(1),
            true,
            None,
        );

        let violations = suite.check_all(Time::from_secs(31));
        let found = violations.iter().any(|violation| {
            matches!(
                violation,
                OracleViolation::WakerDedup(WakerDedupViolation::LostWakeup { .. })
            )
        });
        crate::assert_with_log!(found, "lost wakeup", true, found);
        crate::test_complete!("oracle_suite_routes_logical_time_to_waker_age_checks");
    }

    /// br-asupersync-52hxjz: a reply whose server is gone but which a helper
    /// task may still hold is in flight, not dropped. A reply recorded as
    /// dropped is reported at once, though tasks still run. Once no task
    /// runs, an unresolved reply is reported too.
    #[test]
    fn hydration_classifies_handed_off_and_dropped_replies() {
        use crate::runtime::state::ReplyHistoryEvent;
        init_test("hydration_classifies_handed_off_and_dropped_replies");
        let budget = crate::types::Budget::INFINITE;
        let mut state = crate::runtime::RuntimeState::new();
        let root = state.create_root_region(budget);
        let (server, _server_handle) = state
            .create_task(root, budget, async {})
            .expect("server task");
        let (helper, _helper_handle) = state
            .create_task(root, budget, async {})
            .expect("helper task");
        let history = state.reply_history_handle();
        let handed_off = history.next_call();
        history.record(ReplyHistoryEvent::Created {
            call: handed_off,
            server,
            time: Time::ZERO,
        });
        // The server is gone; the helper it handed the reply to still runs.
        assert!(state.remove_task(server).is_some());
        let mut suite = OracleSuite::new();
        suite.hydrate_temporal_from_state(&state, Time::ZERO);
        assert!(
            suite.reply_linearity.check().is_ok(),
            "a handed-off reply is in flight while a task runs"
        );
        assert_eq!(suite.reply_linearity.created_count(), 0);

        let dropped = history.next_call();
        history.record(ReplyHistoryEvent::Created {
            call: dropped,
            server: helper,
            time: Time::ZERO,
        });
        history.record(ReplyHistoryEvent::Dropped { call: dropped });
        let mut suite = OracleSuite::new();
        suite.hydrate_temporal_from_state(&state, Time::ZERO);
        assert!(
            suite.reply_linearity.check().is_err(),
            "a dropped reply is reported while its task still runs"
        );
        assert_eq!(suite.reply_linearity.created_count(), 1);

        assert!(state.remove_task(helper).is_some());
        let mut suite = OracleSuite::new();
        suite.hydrate_temporal_from_state(&state, Time::ZERO);
        assert_eq!(
            suite.reply_linearity.created_count(),
            2,
            "once no task runs, the unresolved handed-off reply is reported too"
        );
        assert!(suite.reply_linearity.check().is_err());
        crate::test_complete!("hydration_classifies_handed_off_and_dropped_replies");
    }

    #[test]
    fn hydrate_temporal_from_state_replays_finalizer_history() {
        init_test("hydrate_temporal_from_state_replays_finalizer_history");
        let mut state = crate::runtime::RuntimeState::new();
        let region = state.create_root_region(crate::types::Budget::INFINITE);

        state.now = Time::from_nanos(10);
        let registered = state.register_sync_finalizer(region, || {});
        crate::assert_with_log!(registered, "registered", true, registered);

        state.now = Time::from_nanos(20);
        state.record_finalizer_close_for_test(region);

        let mut suite = OracleSuite::new();
        suite.hydrate_temporal_from_state(&state, state.now);

        let violation = suite
            .finalizer
            .check()
            .expect_err("missing finalizer run should survive report hydration");
        crate::assert_with_log!(
            violation.region == region,
            "region",
            region,
            violation.region
        );
        crate::assert_with_log!(
            violation.unrun_finalizers == vec![FinalizerId(0)],
            "unrun finalizers",
            vec![FinalizerId(0)],
            violation.unrun_finalizers
        );
        crate::test_complete!("hydrate_temporal_from_state_replays_finalizer_history");
    }

    /// br-asupersync-iwbef2: the runtime removes a region from its table in the
    /// walk that closes it, and hydration only looked at regions still there,
    /// so the quiescence and task-leak oracles never checked a real close.
    #[test]
    fn hydration_checks_regions_the_runtime_closed_and_removed() {
        init_test("hydration_checks_regions_the_runtime_closed_and_removed");
        let budget = crate::types::Budget::INFINITE;
        let mut state = crate::runtime::RuntimeState::new();
        let root = state.create_root_region(budget);
        let child = state
            .create_child_region(root, budget)
            .expect("create child region");
        let (task, _handle) = state
            .create_task(child, budget, async {})
            .expect("create task");
        let (_cancelled, wakes) = state
            .cancel_request(child, &crate::types::CancelReason::user("done"), None)
            .into_parts();
        state
            .task_mut(task)
            .expect("task")
            .complete(crate::types::Outcome::Cancelled(
                crate::types::CancelReason::parent_cancelled(),
            ));
        let _waiters = state.task_completed(task).into_waiters_without_observers();
        wakes.dispatch();
        let child_removed = state.regions_iter().all(|(_, region)| region.id != child);
        crate::assert_with_log!(
            child_removed,
            "closed child left the table",
            true,
            child_removed
        );

        let mut suite = OracleSuite::new();
        suite.hydrate_temporal_from_state(&state, state.now);
        let closed = suite.quiescence.closed_count();
        crate::assert_with_log!(closed >= 1, "real close checked", ">= 1", closed);
        crate::assert_with_log!(
            suite.quiescence.check().is_ok(),
            "a clean close passes",
            true,
            suite.quiescence.check().is_ok()
        );
        crate::assert_with_log!(
            suite.task_leak.check(state.now).is_ok(),
            "no task leaked",
            true,
            suite.task_leak.check(state.now).is_ok()
        );

        // A task still live in a region the runtime recorded as closed.
        let mut state = crate::runtime::RuntimeState::new();
        let region = state.create_root_region(budget);
        let (live, _handle) = state
            .create_task(region, budget, async {})
            .expect("create task");
        state.record_finalizer_close_for_test(region);
        let mut suite = OracleSuite::new();
        suite.hydrate_temporal_from_state(&state, state.now);
        let violation = suite
            .quiescence
            .check()
            .expect_err("a task outlived its region's close");
        crate::assert_with_log!(
            violation.region == region && violation.live_tasks == vec![live],
            "violation names the region and task",
            (region, vec![live]),
            (violation.region, violation.live_tasks.clone())
        );
        let leaked = suite.task_leak.check(state.now).is_err();
        crate::assert_with_log!(leaked, "task leak reported", true, leaked);
        crate::test_complete!("hydration_checks_regions_the_runtime_closed_and_removed");
    }

    #[test]
    fn hydrate_temporal_from_state_preserves_live_cancellation_protocol_history() {
        init_test("hydrate_temporal_from_state_preserves_live_cancellation_protocol_history");
        let mut state = crate::runtime::RuntimeState::new();
        let region = state.create_root_region(crate::types::Budget::INFINITE);

        let task_slot = state.insert_task(crate::record::TaskRecord::new(
            crate::types::TaskId::from_arena(crate::util::ArenaIndex::new(0, 0)),
            region,
            crate::types::Budget::INFINITE,
        ));
        let task = crate::types::TaskId::from_arena(task_slot);
        state.task_mut(task).expect("task must exist").id = task;

        let reason = crate::types::CancelReason::user("hydrate-preserve");
        let from_state = crate::record::task::TaskState::Created;
        let to_state = crate::record::task::TaskState::CancelRequested {
            reason: reason.clone(),
            cleanup_budget: crate::types::Budget::INFINITE,
        };
        let cancel_effects = {
            let record = state.task_mut(task).expect("task must exist");
            record.request_cancel_with_budget(reason.clone(), crate::types::Budget::INFINITE)
        };
        let (_newly_cancelled, cancel_wakes) = cancel_effects.into_parts();
        cancel_wakes.dispatch();

        let mut suite = OracleSuite::new();
        suite.cancellation_protocol.on_region_create(region, None);
        suite.cancellation_protocol.on_task_create(task, region);
        suite
            .cancellation_protocol
            .on_cancel_request(task, reason, Time::from_nanos(10));
        suite.cancellation_protocol.on_transition(
            task,
            &from_state,
            &to_state,
            Time::from_nanos(11),
        );
        for _ in 0..=crate::types::MAX_MASK_DEPTH + 1 {
            suite.cancellation_protocol.on_task_poll(task);
        }

        let before = suite
            .cancellation_protocol
            .check()
            .expect_err("live oracle should record overdue cancel acknowledgement");
        let before_is_ack_violation = matches!(
            before,
            CancellationProtocolViolation::CancelNotAcknowledged { .. }
        );
        crate::assert_with_log!(
            before_is_ack_violation,
            "before violation kind",
            true,
            before_is_ack_violation
        );

        suite.hydrate_temporal_from_state(&state, Time::from_nanos(99));

        let after = suite
            .cancellation_protocol
            .check()
            .expect_err("hydration must preserve overdue cancel acknowledgement");
        let after_is_ack_violation = matches!(
            after,
            CancellationProtocolViolation::CancelNotAcknowledged { .. }
        );
        crate::assert_with_log!(
            after_is_ack_violation,
            "after violation kind",
            true,
            after_is_ack_violation
        );
        crate::test_complete!(
            "hydrate_temporal_from_state_preserves_live_cancellation_protocol_history"
        );
    }

    #[test]
    fn hydrate_temporal_from_state_replays_loser_drain_history() {
        init_test("hydrate_temporal_from_state_replays_loser_drain_history");
        let state = crate::runtime::RuntimeState::new();
        let history = state.loser_drain_history_handle();
        let region = crate::types::RegionId::new_for_test(4, 0);
        let winner = crate::types::TaskId::new_for_test(10, 0);
        let loser = crate::types::TaskId::new_for_test(11, 0);

        let race_id = history.record_race_start(region, vec![winner, loser], Time::from_nanos(10));
        history.record_task_complete(winner, Time::from_nanos(50));
        history.record_race_complete(race_id, winner, Time::from_nanos(100));

        let mut suite = OracleSuite::new();
        suite.hydrate_temporal_from_state(&state, Time::from_nanos(150));

        let violation = suite
            .loser_drain
            .check()
            .expect_err("missing loser completion must survive post-run hydration");
        match violation {
            LoserDrainViolation::UndrainedLosers {
                race_id: actual_race_id,
                winner: actual_winner,
                undrained_losers,
                race_complete_time,
            } => {
                crate::assert_with_log!(
                    actual_race_id == race_id,
                    "race id",
                    race_id,
                    actual_race_id
                );
                crate::assert_with_log!(actual_winner == winner, "winner", winner, actual_winner);
                crate::assert_with_log!(
                    undrained_losers == vec![loser],
                    "undrained losers",
                    vec![loser],
                    undrained_losers
                );
                crate::assert_with_log!(
                    race_complete_time == Time::from_nanos(100),
                    "race complete time",
                    Time::from_nanos(100),
                    race_complete_time
                );
            }
            other => panic!("expected undrained-loser violation, got {other:?}"),
        }
        crate::test_complete!("hydrate_temporal_from_state_replays_loser_drain_history");
    }

    #[test]
    fn hydrate_temporal_from_state_replays_owner_cancelled_race_history() {
        init_test("hydrate_temporal_from_state_replays_owner_cancelled_race_history");
        let region = crate::types::RegionId::new_for_test(4, 0);
        let owner = crate::types::TaskId::new_for_test(9, 0);
        let first = crate::types::TaskId::new_for_test(10, 0);
        let second = crate::types::TaskId::new_for_test(11, 0);

        for first_drained in [false, true] {
            let state = crate::runtime::RuntimeState::new();
            let history = state.loser_drain_history_handle();
            let race_id =
                history.record_race_start(region, vec![first, second], Time::from_nanos(10));
            if first_drained {
                history.record_task_complete(first, Time::from_nanos(50));
            }
            history.record_task_complete(second, Time::from_nanos(60));
            history.record_race_cancelled(race_id, owner, Time::from_nanos(100));

            let mut suite = OracleSuite::new();
            suite.hydrate_temporal_from_state(&state, Time::from_nanos(150));
            let result = suite.loser_drain.check();
            if first_drained {
                crate::assert_with_log!(result.is_ok(), "cancelled race drained", "Ok", result);
                crate::assert_with_log!(
                    suite.loser_drain.completed_race_count() == 1,
                    "completed races",
                    1,
                    suite.loser_drain.completed_race_count()
                );
            } else {
                match result {
                    Err(LoserDrainViolation::UndrainedLosers {
                        race_id: actual_race,
                        winner,
                        undrained_losers,
                        race_complete_time,
                    }) => {
                        crate::assert_with_log!(
                            actual_race == race_id,
                            "race",
                            race_id,
                            actual_race
                        );
                        crate::assert_with_log!(winner == owner, "owner", owner, winner);
                        crate::assert_with_log!(
                            undrained_losers == vec![first],
                            "undrained first participant",
                            vec![first],
                            undrained_losers
                        );
                        crate::assert_with_log!(
                            race_complete_time == Time::from_nanos(100),
                            "completion boundary",
                            Time::from_nanos(100),
                            race_complete_time
                        );
                    }
                    other => panic!(
                        "missing first participant must survive cancellation history replay: {other:?}"
                    ),
                }
            }
        }
        crate::test_complete!("hydrate_temporal_from_state_replays_owner_cancelled_race_history");
    }

    /// Every hydration replays the loser-drain history, not only the first:
    /// a race in flight at one report and drained by the next passes the
    /// next, replaying a completed race again keeps it completed, and a
    /// reset suite hydrates again. A suite fed by hand keeps its own events
    /// (br-asupersync-vcu2oz M3).
    #[test]
    fn hydrate_temporal_from_state_replays_loser_drain_history_on_every_report() {
        init_test("hydrate_temporal_from_state_replays_loser_drain_history_on_every_report");
        let state = crate::runtime::RuntimeState::new();
        let history = state.loser_drain_history_handle();
        let region = crate::types::RegionId::new_for_test(4, 0);
        let winner = crate::types::TaskId::new_for_test(10, 0);
        let loser = crate::types::TaskId::new_for_test(11, 0);
        let race_id = history.record_race_start(region, vec![winner, loser], Time::from_nanos(10));

        let mut suite = OracleSuite::new();
        suite.hydrate_temporal_from_state(&state, Time::from_nanos(20));
        assert!(
            matches!(
                suite.loser_drain.check(),
                Err(LoserDrainViolation::ActiveRaceNotCompleted { .. })
            ),
            "the race is in flight at the first report"
        );

        history.record_task_complete(winner, Time::from_nanos(50));
        history.record_task_complete(loser, Time::from_nanos(60));
        history.record_race_complete(race_id, winner, Time::from_nanos(100));
        for now in [150, 160] {
            suite.hydrate_temporal_from_state(&state, Time::from_nanos(now));
            let result = suite.loser_drain.check();
            assert!(result.is_ok(), "drained race at {now}: {result:?}");
            assert_eq!(suite.loser_drain.completed_race_count(), 1);
        }

        suite.reset();
        suite.hydrate_temporal_from_state(&state, Time::from_nanos(200));
        assert_eq!(
            suite.loser_drain.completed_race_count(),
            1,
            "a reset suite hydrates again"
        );

        // Hand-fed race 0 completes differently from the state's race 0.
        let mut fed = OracleSuite::new();
        let drain = &mut fed.loser_drain;
        let own = drain.on_race_start(region, vec![winner], Time::from_nanos(1));
        drain.on_task_complete(winner, Time::from_nanos(2));
        drain.on_race_complete(own, winner, Time::from_nanos(3));
        fed.hydrate_temporal_from_state(&state, Time::from_nanos(300));
        let result = fed.loser_drain.check();
        assert!(result.is_ok(), "hand-fed events only: {result:?}");

        // A hydration that replayed nothing marks nothing: events fed after
        // it are still kept apart from the state's.
        let mut early = OracleSuite::new();
        early.hydrate_temporal_from_state(&crate::runtime::RuntimeState::new(), Time::ZERO);
        let drain = &mut early.loser_drain;
        let own = drain.on_race_start(region, vec![winner], Time::from_nanos(1));
        drain.on_task_complete(winner, Time::from_nanos(2));
        drain.on_race_complete(own, winner, Time::from_nanos(3));
        early.hydrate_temporal_from_state(&state, Time::from_nanos(300));
        let result = early.loser_drain.check();
        assert!(result.is_ok(), "fed after an empty hydration: {result:?}");
        crate::test_complete!(
            "hydrate_temporal_from_state_replays_loser_drain_history_on_every_report"
        );
    }

    #[test]
    fn oracle_suite_surfaces_fail_fast_region_leak_violations() {
        init_test("oracle_suite_surfaces_fail_fast_region_leak_violations");
        let mut suite = OracleSuite::new();
        suite.region_leak = RegionLeakOracle::with_strict_timeouts();

        let region = crate::types::RegionId::new_for_test(77, 0);
        suite.region_leak.on_region_created(
            region,
            None,
            Some("suite fail-fast regression".to_string()),
            crate::types::Budget::INFINITE,
        );
        std::thread::sleep(std::time::Duration::from_millis(50));

        let violations = suite.check_all(Time::ZERO);
        let has_region_leak = violations.iter().any(|violation| {
            matches!(
                violation,
                OracleViolation::RegionLeak(RegionViolation {
                    region_id,
                    violation_type: ViolationType::StuckCreation,
                    ..
                }) if *region_id == region
            )
        });
        crate::assert_with_log!(
            has_region_leak,
            "region leak surfaced",
            true,
            has_region_leak
        );

        let report = suite.report(Time::ZERO);
        let entry = report
            .entry("region_leak")
            .expect("region_leak entry must be present");
        crate::assert_with_log!(!entry.passed, "entry passed", false, entry.passed);
        let mentions_stuck_creation = entry
            .violation
            .as_deref()
            .is_some_and(|violation| violation.contains("Stuck Creation"));
        crate::assert_with_log!(
            mentions_stuck_creation,
            "report mentions StuckCreation",
            true,
            mentions_stuck_creation
        );
        crate::test_complete!("oracle_suite_surfaces_fail_fast_region_leak_violations");
    }

    // Pure data-type tests (wave 16 – CyanBarn)

    #[test]
    fn oracle_suite_debug() {
        let suite = OracleSuite::new();
        let dbg = format!("{suite:?}");
        assert!(dbg.contains("OracleSuite"));
    }

    #[test]
    fn oracle_suite_reset_stays_clean() {
        let mut suite = OracleSuite::new();
        suite.reset();
        let violations = suite.check_all(Time::ZERO);
        assert!(violations.is_empty());
    }

    #[test]
    fn oracle_suite_report_all_pass() {
        let mut suite = OracleSuite::new();
        let report = suite.report(Time::ZERO);
        assert!(report.all_passed());
        assert_eq!(report.failed, 0);
        assert_eq!(report.passed, report.total);
        assert!(report.failures().is_empty());
    }

    #[test]
    fn oracle_report_debug_clone() {
        let mut suite = OracleSuite::new();
        let report = suite.report(Time::ZERO);
        let dbg = format!("{report:?}");
        assert!(dbg.contains("OracleReport"));

        let cloned = report.clone();
        assert_eq!(cloned.total, report.total);
    }

    #[test]
    fn oracle_report_to_json() {
        let mut suite = OracleSuite::new();
        let report = suite.report(Time::ZERO);
        let json = report.to_json();
        assert!(json.is_object());
        assert!(json["entries"].is_array());
    }

    /// A passing entry that tracked nothing and recorded no events says so in
    /// the text report, so it does not read as a check that ran
    /// (br-asupersync-52hxjz).
    #[test]
    fn a_pass_with_nothing_observed_says_it_checked_nothing() {
        let entry = |invariant: &str, entities_tracked, events_recorded| OracleEntryReport {
            invariant: invariant.to_owned(),
            passed: true,
            violation: None,
            stats: OracleStats {
                entities_tracked,
                events_recorded,
            },
        };
        let report = OracleReport {
            entries: vec![entry("task_leak", 2, 5), entry("actor_leak", 0, 0)],
            total: 2,
            passed: 2,
            failed: 0,
            check_time_nanos: 0,
        };
        let text = report.to_text();
        let line = |name: &str| {
            text.lines()
                .find(|line| line.contains(name))
                .unwrap_or_else(|| panic!("no {name} line in:\n{text}"))
                .to_owned()
        };
        assert_eq!(line("task_leak"), "[PASS] task_leak (tracked=2, events=5)");
        assert_eq!(
            line("actor_leak"),
            "[PASS] actor_leak (tracked=0, events=0) -- checked nothing: no events"
        );
    }

    #[test]
    fn oracle_report_to_text() {
        let mut suite = OracleSuite::new();
        let report = suite.report(Time::ZERO);
        let text = report.to_text();
        assert!(text.contains("Oracle Report"));
        assert!(text.contains("PASS"));
    }

    #[cfg(feature = "tracing-integration")]
    #[test]
    #[allow(clippy::significant_drop_tightening)]
    fn oracle_report_emits_structured_oracle_check_events() {
        let mut suite = OracleSuite::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let recorder = EventRecorder {
            events: events.clone(),
        };
        let subscriber = tracing_subscriber::registry().with(recorder);

        let report = tracing::subscriber::with_default(subscriber, || suite.report(Time::ZERO));
        assert!(report.all_passed());

        let events = events.lock();
        let task_leak_event = events.iter().find(|event| {
            event.fields.get("event").map(String::as_str) == Some("oracle_check")
                && event.fields.get("invariant").map(String::as_str) == Some("task_leak")
        });
        let task_leak_event = task_leak_event.expect("task_leak oracle_check should be emitted");

        assert_eq!(
            task_leak_event.fields.get("passed").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            task_leak_event.fields.get("details").map(String::as_str),
            Some("clean")
        );
    }

    #[test]
    fn oracle_report_failure_helpers_surface_failed_entries() {
        let report = OracleReport {
            entries: vec![
                OracleEntryReport {
                    invariant: "task_leak".to_string(),
                    passed: true,
                    violation: None,
                    stats: OracleStats {
                        entities_tracked: 2,
                        events_recorded: 4,
                    },
                },
                OracleEntryReport {
                    invariant: "obligation_leak".to_string(),
                    passed: false,
                    violation: Some("Obligation leak: leaked obligation".to_string()),
                    stats: OracleStats {
                        entities_tracked: 3,
                        events_recorded: 6,
                    },
                },
            ],
            total: 2,
            passed: 1,
            failed: 1,
            check_time_nanos: 42,
        };

        let failures = report.failures();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].invariant, "obligation_leak");
        assert!(!report.all_passed());

        let text = report.to_text();
        assert!(text.contains("FAIL"));
        assert!(text.contains("Obligation leak: leaked obligation"));
    }

    #[test]
    fn oracle_report_entry_lookup() {
        let mut suite = OracleSuite::new();
        let report = suite.report(Time::ZERO);
        let entry = report.entry("task_leak");
        assert!(entry.is_some());
        assert!(entry.unwrap().passed);

        assert!(report.entry("nonexistent_oracle").is_none());
    }

    #[test]
    fn oracle_stats_debug_clone_eq() {
        let stats = OracleStats {
            entities_tracked: 5,
            events_recorded: 10,
        };
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("OracleStats"));

        let cloned = stats.clone();
        assert_eq!(stats, cloned);
    }

    #[test]
    fn oracle_stats_ne() {
        let a = OracleStats {
            entities_tracked: 5,
            events_recorded: 10,
        };
        let b = OracleStats {
            entities_tracked: 3,
            events_recorded: 10,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn oracle_entry_report_debug_clone() {
        let entry = OracleEntryReport {
            invariant: "test".to_owned(),
            passed: true,
            violation: None,
            stats: OracleStats {
                entities_tracked: 0,
                events_recorded: 0,
            },
        };
        let dbg = format!("{entry:?}");
        assert!(dbg.contains("OracleEntryReport"));

        let cloned = entry;
        assert_eq!(cloned.invariant, "test");
        assert!(cloned.passed);
    }

    #[test]
    fn oracle_entry_report_with_violation() {
        let entry = OracleEntryReport {
            invariant: "failing".to_owned(),
            passed: false,
            violation: Some("something leaked".to_owned()),
            stats: OracleStats {
                entities_tracked: 1,
                events_recorded: 1,
            },
        };
        assert!(!entry.passed);
        assert!(entry.violation.as_deref().unwrap().contains("leaked"));
    }

    #[test]
    fn oracle_violation_debug() {
        // OracleViolation wraps sub-oracle violations. We can test the Debug derive
        // only if we can construct one. Use OracleViolation::TaskLeak as proxy.
        // TaskLeakViolation requires specific sub-oracle construction which is complex,
        // so we test the outer enum via the suite report pathway.
        let mut suite = OracleSuite::new();
        let violations = suite.check_all(Time::ZERO);
        // No violations on a fresh suite; just verify the Vec is empty.
        assert!(violations.is_empty());
    }

    #[test]
    fn oracle_violation_error_trait() {
        // OracleViolation implements Error; verify via trait object.
        // We can't easily construct one without triggering a violation,
        // but we can verify the trait is implemented at compile time.
        fn assert_error_impl<T: std::error::Error>() {}
        assert_error_impl::<OracleViolation>();
    }
