    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    /// Regression for #42: ModuleDesync is a heuristic skew
    /// observation, not a runtime invariant violation. The event is
    /// kept (so callers can query `all_violations()`) but its tracing
    /// emit level must be DEBUG, not ERROR — otherwise the routine
    /// pattern of TaskTable advancing past unused RegionTable spams
    /// the default-level log with `epoch_consistency_violation
    /// violation_type="module_desync"`.
    ///
    /// AdvancementOrderViolation, the *real* invariant violation
    /// (dependent module ahead of its dependency), still emits at
    /// ERROR — sibling test below.
    #[cfg(feature = "tracing-integration")]
    #[test]
    fn module_desync_emits_at_debug_not_error() {
        use parking_lot::Mutex;
        use std::sync::Arc;
        use tracing::Subscriber;
        use tracing_subscriber::layer::{Context, Layer};
        use tracing_subscriber::prelude::*;
        use tracing_subscriber::registry::LookupSpan;

        init_test("module_desync_emits_at_debug_not_error");

        #[derive(Clone)]
        struct Captured {
            level: tracing::Level,
            violation_type: Option<String>,
        }
        struct Recorder {
            events: Arc<Mutex<Vec<Captured>>>,
        }
        struct VisitField {
            violation_type: Option<String>,
        }
        impl tracing::field::Visit for VisitField {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "violation_type" && self.violation_type.is_none() {
                    let rendered = format!("{value:?}");
                    self.violation_type = Some(rendered.trim_matches('"').to_string());
                }
            }
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "violation_type" {
                    self.violation_type = Some(value.to_string());
                }
            }
        }
        impl<S> Layer<S> for Recorder
        where
            S: Subscriber + for<'a> LookupSpan<'a>,
        {
            fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
                let mut v = VisitField {
                    violation_type: None,
                };
                event.record(&mut v);
                self.events.lock().push(Captured {
                    level: *event.metadata().level(),
                    violation_type: v.violation_type,
                });
            }
        }

        let events = Arc::new(Mutex::new(Vec::new()));
        let recorder = Recorder {
            events: events.clone(),
        };
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::filter::LevelFilter::TRACE)
            .with(recorder);

        tracing::subscriber::with_default(subscriber, || {
            let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
            // Reproduce the #42 repro shape: TaskTable advances past
            // RegionTable@Genesis (skew > max_epoch_skew).
            let now = Time::from_nanos(1000);
            tracker.notify_epoch_transition(
                ModuleId::Scheduler,
                EpochId::GENESIS,
                EpochId::new(1),
                now,
            );
            tracker.notify_epoch_transition(
                ModuleId::TaskTable,
                EpochId::GENESIS,
                EpochId::new(1),
                now,
            );
            for to in 2u64..=5 {
                tracker.notify_epoch_transition(
                    ModuleId::TaskTable,
                    EpochId::new(to - 1),
                    EpochId::new(to),
                    Time::from_nanos(1000 + to * 100),
                );
            }
            tracker.notify_epoch_transition(
                ModuleId::RegionTable,
                EpochId::GENESIS,
                EpochId::new(1),
                now,
            );
            tracker.drain_telemetry().dispatch();
        });

        let captured = events.lock();
        let desync_events: Vec<&Captured> = captured
            .iter()
            .filter(|c| c.violation_type.as_deref() == Some("module_desync"))
            .collect();
        crate::assert_with_log!(
            !desync_events.is_empty(),
            "module_desync events must still be emitted (just at debug level)",
            true,
            !desync_events.is_empty()
        );
        for ev in &desync_events {
            crate::assert_with_log!(
                ev.level == tracing::Level::DEBUG,
                "module_desync events must emit at DEBUG (regression #42)",
                tracing::Level::DEBUG,
                ev.level
            );
            crate::assert_with_log!(
                ev.level != tracing::Level::ERROR,
                "module_desync events must NOT emit at ERROR — that was the #42 noise",
                "not ERROR",
                ev.level
            );
        }
        crate::test_complete!("module_desync_emits_at_debug_not_error");
    }

    #[test]
    fn epoch_telemetry_outbox_is_bounded_and_drains_in_receipt_order() {
        init_test("epoch_telemetry_outbox_is_bounded_and_drains_in_receipt_order");

        let tracker = EpochConsistencyTracker::with_config_time_getter_and_telemetry_capacity(
            EpochConsistencyConfig::default(),
            Arc::new(|| Time::ZERO),
            3,
        );
        let now = Time::from_nanos(10);
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );

        let full = tracker.telemetry_statistics();
        assert_eq!(full.pending, 3);
        assert_eq!(full.capacity, 3);
        assert_eq!(full.overflow_count, 1);

        let first = tracker.telemetry.pop_batch(2);
        assert!(matches!(
            first.as_slice(),
            [
                EpochTelemetryReceipt::Transition { .. },
                EpochTelemetryReceipt::ConsistencyCheckLatency { .. }
            ]
        ));
        assert_eq!(tracker.telemetry_statistics().pending, 1);
        EpochTelemetryDispatch::dispatch_receipts(&tracker.telemetry, first);

        let second = tracker.telemetry.pop_batch(2);
        assert!(matches!(
            second.as_slice(),
            [EpochTelemetryReceipt::TransitionDuplicate { .. }]
        ));
        EpochTelemetryDispatch::dispatch_receipts(&tracker.telemetry, second);

        let drained = tracker.telemetry_statistics();
        assert_eq!(drained.pending, 0);
        assert_eq!(drained.emitted_count, 3);
        assert_eq!(drained.overflow_count, 1);
        crate::test_complete!("epoch_telemetry_outbox_is_bounded_and_drains_in_receipt_order");
    }

    #[test]
    fn epoch_telemetry_public_drain_enforces_production_batch_limit() {
        init_test("epoch_telemetry_public_drain_enforces_production_batch_limit");

        let tracker = EpochConsistencyTracker::with_config_time_getter_and_telemetry_capacity(
            EpochConsistencyConfig::default(),
            Arc::new(|| Time::ZERO),
            DEFAULT_TELEMETRY_CAPACITY,
        );
        let now = Time::from_nanos(10);
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );
        for _ in 0..DEFAULT_TELEMETRY_DRAIN_LIMIT {
            tracker.notify_epoch_transition(
                ModuleId::Scheduler,
                EpochId::GENESIS,
                EpochId::new(1),
                now,
            );
        }

        let first = tracker.drain_telemetry();
        assert_eq!(
            tracker.telemetry_statistics().pending,
            DEFAULT_TELEMETRY_DRAIN_LIMIT + 2,
            "creating a delivery token must not remove receipts"
        );
        first.dispatch();
        assert_eq!(tracker.telemetry_statistics().pending, 2);
        assert_eq!(
            tracker.telemetry_statistics().emitted_count,
            DEFAULT_TELEMETRY_DRAIN_LIMIT as u64
        );

        let second = tracker.drain_telemetry();
        second.dispatch();
        assert_eq!(tracker.telemetry_statistics().pending, 0);
        crate::test_complete!("epoch_telemetry_public_drain_enforces_production_batch_limit");
    }

    #[test]
    fn epoch_telemetry_abandoned_delivery_leaves_receipts_pending() {
        init_test("epoch_telemetry_abandoned_delivery_leaves_receipts_pending");

        let tracker = EpochConsistencyTracker::new();
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(10),
        );
        assert_eq!(tracker.telemetry_statistics().pending, 2);

        let abandoned = tracker.drain_telemetry();
        assert!(!abandoned.is_empty());
        drop(abandoned);
        assert_eq!(
            tracker.telemetry_statistics().pending,
            2,
            "dropping an undispatched token must leave receipts available"
        );

        tracker.drain_telemetry().dispatch();
        let delivered = tracker.telemetry_statistics();
        assert_eq!(delivered.pending, 0);
        assert_eq!(delivered.emitted_count, 2);
        crate::test_complete!("epoch_telemetry_abandoned_delivery_leaves_receipts_pending");
    }

    #[test]
    fn epoch_telemetry_delivery_waits_for_in_flight_publication() {
        init_test("epoch_telemetry_delivery_waits_for_in_flight_publication");

        let tracker = Arc::new(EpochConsistencyTracker::new());
        let publication = tracker.telemetry_publication.lock();
        tracker.enqueue_telemetry(
            &publication,
            EpochTelemetryReceipt::EnabledChanged { enabled: true },
        );

        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(0);
        let (delivery_tx, delivery_rx) = std::sync::mpsc::sync_channel(0);
        std::thread::scope(|scope| {
            let tracker = Arc::clone(&tracker);
            scope.spawn(move || {
                started_tx.send(()).expect("test receiver must remain live");
                let delivery = tracker.drain_telemetry();
                delivery_tx
                    .send(delivery)
                    .expect("test receiver must remain live");
            });

            started_rx
                .recv()
                .expect("delivery thread must reach the publication boundary");
            assert!(
                matches!(
                    delivery_rx.recv_timeout(std::time::Duration::from_millis(50)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                ),
                "delivery must not capture receipts from an in-flight producer"
            );

            drop(publication);
            let delivery = delivery_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("delivery must resume after the producer publishes");
            assert!(!delivery.is_empty());
            delivery.dispatch();
        });

        let statistics = tracker.telemetry_statistics();
        assert_eq!(statistics.pending, 0);
        assert_eq!(statistics.emitted_count, 1);
        crate::test_complete!("epoch_telemetry_delivery_waits_for_in_flight_publication");
    }

    #[test]
    fn epoch_telemetry_delivery_cutoff_excludes_newer_receipts_even_out_of_order() {
        init_test("epoch_telemetry_delivery_cutoff_excludes_newer_receipts_even_out_of_order");

        let tracker = EpochConsistencyTracker::new();
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(10),
        );
        let first_old_delivery = tracker.drain_telemetry();
        let second_old_delivery = tracker.drain_telemetry();

        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::new(1),
            EpochId::new(2),
            Time::from_nanos(20),
        );
        let newer_delivery = tracker.drain_telemetry();

        first_old_delivery.dispatch();
        let after_old = tracker.telemetry_statistics();
        assert_eq!(after_old.pending, 2);
        assert_eq!(after_old.emitted_count, 2);

        newer_delivery.dispatch();
        let after_newer = tracker.telemetry_statistics();
        assert_eq!(after_newer.pending, 0);
        assert_eq!(after_newer.emitted_count, 4);

        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::new(2),
            EpochId::new(3),
            Time::from_nanos(30),
        );
        assert!(
            second_old_delivery.is_empty(),
            "an old token must not adopt receipts enqueued after its creation"
        );
        second_old_delivery.dispatch();
        let after_stale = tracker.telemetry_statistics();
        assert_eq!(after_stale.pending, 2);
        assert_eq!(after_stale.emitted_count, 4);

        tracker.drain_telemetry().dispatch();
        let delivered = tracker.telemetry_statistics();
        assert_eq!(delivered.pending, 0);
        assert_eq!(delivered.emitted_count, 6);
        crate::test_complete!(
            "epoch_telemetry_delivery_cutoff_excludes_newer_receipts_even_out_of_order"
        );
    }

    #[test]
    fn epoch_telemetry_reset_does_not_retarget_existing_delivery() {
        init_test("epoch_telemetry_reset_does_not_retarget_existing_delivery");

        let tracker = EpochConsistencyTracker::new();
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(10),
        );
        let pre_reset_delivery = tracker.drain_telemetry();

        tracker.reset();
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(20),
        );

        assert!(
            pre_reset_delivery.is_empty(),
            "a pre-reset token must not adopt post-reset receipts"
        );
        pre_reset_delivery.dispatch();
        let after_stale = tracker.telemetry_statistics();
        assert_eq!(after_stale.pending, 2);
        assert_eq!(after_stale.emitted_count, 0);

        tracker.drain_telemetry().dispatch();
        let delivered = tracker.telemetry_statistics();
        assert_eq!(delivered.pending, 0);
        assert_eq!(delivered.emitted_count, 2);
        crate::test_complete!("epoch_telemetry_reset_does_not_retarget_existing_delivery");
    }

    #[cfg(feature = "tracing-integration")]
    #[test]
    fn epoch_telemetry_dispatch_allows_subscriber_reentry_after_tracker_unlock() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        use tracing::Subscriber;
        use tracing_subscriber::layer::{Context, Layer};
        use tracing_subscriber::prelude::*;
        use tracing_subscriber::registry::LookupSpan;

        init_test("epoch_telemetry_dispatch_allows_subscriber_reentry_after_tracker_unlock");

        struct ReenteringLayer {
            tracker: Arc<EpochConsistencyTracker>,
            events: Arc<AtomicUsize>,
        }
        impl<S> Layer<S> for ReenteringLayer
        where
            S: Subscriber + for<'a> LookupSpan<'a>,
        {
            fn on_event(&self, _event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
                let _ = self.tracker.transition_statistics();
                self.events.fetch_add(1, AtomicOrdering::Relaxed);
            }
        }

        let tracker = Arc::new(EpochConsistencyTracker::new());
        let events = Arc::new(AtomicUsize::new(0));
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::filter::LevelFilter::TRACE)
            .with(ReenteringLayer {
                tracker: Arc::clone(&tracker),
                events: Arc::clone(&events),
            });

        tracing::subscriber::with_default(subscriber, || {
            tracker.notify_epoch_transition(
                ModuleId::Scheduler,
                EpochId::GENESIS,
                EpochId::new(1),
                Time::from_nanos(10),
            );
            assert_eq!(events.load(AtomicOrdering::Relaxed), 0);
            tracker.drain_telemetry().dispatch();
        });

        assert_eq!(events.load(AtomicOrdering::Relaxed), 2);
        assert_eq!(tracker.telemetry_statistics().dispatch_panic_count, 0);
        crate::test_complete!(
            "epoch_telemetry_dispatch_allows_subscriber_reentry_after_tracker_unlock"
        );
    }

    #[cfg(feature = "tracing-integration")]
    #[test]
    fn epoch_telemetry_dispatch_contains_enabled_and_on_event_panics() {
        const PANIC_SITE_ENV: &str = "ASUPERSYNC_EPOCH_TELEMETRY_PANIC_SITE";
        const TEST_NAME: &str = concat!(
            "runtime::epoch_tracker::tests::",
            "epoch_telemetry_dispatch_contains_enabled_and_on_event_panics"
        );

        use tracing::Subscriber;
        use tracing_subscriber::layer::{Context, Layer};
        use tracing_subscriber::prelude::*;
        use tracing_subscriber::registry::LookupSpan;

        #[derive(Clone, Copy)]
        enum PanicSite {
            Enabled,
            OnEvent,
        }
        struct PanickingLayer(PanicSite);
        impl<S> Layer<S> for PanickingLayer
        where
            S: Subscriber + for<'a> LookupSpan<'a>,
        {
            fn enabled(&self, _metadata: &tracing::Metadata<'_>, _ctx: Context<'_, S>) -> bool {
                if matches!(self.0, PanicSite::Enabled) {
                    panic!("enabled panic"); // ubs:ignore -- adversarial containment fixture
                }
                true
            }

            fn on_event(&self, _event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
                if matches!(self.0, PanicSite::OnEvent) {
                    panic!("on_event panic"); // ubs:ignore -- adversarial containment fixture
                }
            }
        }

        if let Some(site) = std::env::var_os(PANIC_SITE_ENV) {
            let panic_site = match site.to_str() {
                Some("enabled") => PanicSite::Enabled,
                Some("on_event") => PanicSite::OnEvent,
                // ubs:ignore -- child-process test protocol rejects invalid modes.
                other => panic!("unknown epoch telemetry panic site: {other:?}"),
            };
            let tracker = EpochConsistencyTracker::new();
            tracker.notify_epoch_transition(
                ModuleId::Scheduler,
                EpochId::GENESIS,
                EpochId::new(1),
                Time::from_nanos(10),
            );
            let subscriber = tracing_subscriber::registry()
                .with(tracing_subscriber::filter::LevelFilter::TRACE)
                .with(PanickingLayer(panic_site));
            let delivery = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                tracing::subscriber::with_default(subscriber, || {
                    tracker.drain_telemetry().dispatch();
                });
            }));
            if let Err(payload) = delivery {
                assert!(
                    matches!(panic_site, PanicSite::Enabled),
                    "on_event panic must be fully contained by dispatch"
                );
                drop(payload);
            }

            let after_panic = tracker.telemetry_statistics();
            assert_eq!(after_panic.pending, 0);
            assert_eq!(after_panic.dispatch_panic_count, 1);

            tracker.notify_epoch_transition(
                ModuleId::Scheduler,
                EpochId::new(1),
                EpochId::new(2),
                Time::from_nanos(20),
            );
            assert_eq!(tracker.transition_statistics().total_transitions, 2);
            assert_eq!(tracker.telemetry_statistics().dispatch_panic_count, 1);
            return;
        }

        init_test("epoch_telemetry_dispatch_contains_enabled_and_on_event_panics");
        for panic_site in ["enabled", "on_event"] {
            let status = std::process::Command::new(
                std::env::current_exe().expect("current epoch telemetry test executable"),
            )
            .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
            .env(PANIC_SITE_ENV, panic_site)
            .status()
            .expect("run isolated epoch telemetry panic test");
            assert!(
                status.success(),
                "isolated {panic_site} panic test failed with {status}"
            );
        }
        crate::test_complete!("epoch_telemetry_dispatch_contains_enabled_and_on_event_panics");
    }

    #[test]
    fn desync_range_scan_matches_grouped_reference() {
        // Preserve the previous grouping algorithm as an independent oracle
        // for the allocation-free range scan, including its report ordering.
        fn grouped_reference(
            tracker: &EpochConsistencyTracker,
            records: &DetHashMap<ModuleId, EpochTransitionRecord>,
            now: Time,
            suppress_batch: bool,
        ) -> Option<(Vec<(ModuleId, EpochId)>, Time, u64)> {
            let mut epochs = std::collections::BTreeMap::<EpochId, Vec<ModuleId>>::new();
            for (&module, record) in records {
                epochs.entry(record.current_epoch).or_default().push(module);
            }
            if epochs.len() <= 1 {
                return None;
            }
            let epoch_ids: Vec<_> = epochs.keys().copied().collect();
            let min = epoch_ids[0];
            let max = epoch_ids[epoch_ids.len() - 1];
            let skew = max.distance(min);
            if skew <= tracker.config.max_epoch_skew
                || (suppress_batch
                    && tracker.is_single_step_batch_transition(records, min, max, now))
            {
                return None;
            }
            let mut modules = Vec::new();
            for (&epoch, group) in &epochs {
                for &module in group {
                    modules.push((module, epoch));
                }
            }
            modules.sort_by_key(|(module, epoch)| (*epoch, *module));
            Some((modules, now, skew))
        }

        let modules = [
            ModuleId::Scheduler,
            ModuleId::TaskTable,
            ModuleId::RegionTable,
        ];
        let epochs = [
            None,
            Some(0),
            Some(1),
            Some(2),
            Some(u64::MAX - 1),
            Some(u64::MAX),
        ];
        let now = Time::from_nanos(1000);
        let mut tracker = EpochConsistencyTracker::new();
        for shape in 0..216 {
            for timestamp_mask in 0..8 {
                for reverse in [false, true] {
                    let mut records = DetHashMap::default();
                    for position in 0..3 {
                        let index = if reverse { 2 - position } else { position };
                        let Some(epoch) = epochs[(shape / 6_usize.pow(index as u32)) % 6] else {
                            continue;
                        };
                        records.insert(
                            modules[index],
                            EpochTransitionRecord {
                                current_epoch: EpochId::new(epoch),
                                last_transition_time: Time::from_nanos(
                                    999 + ((timestamp_mask >> index) & 1),
                                ),
                                transition_start_time: None,
                                transition_count: 1,
                            },
                        );
                    }
                    for skew in [0, 1, 2, u64::MAX] {
                        tracker.config.max_epoch_skew = skew;
                        for suppress_batch in [false, true] {
                            let expected =
                                grouped_reference(&tracker, &records, now, suppress_batch);
                            let actual = tracker
                                .current_module_desync_violation(&records, now, suppress_batch)
                                .map(|violation| match violation {
                                    EpochConsistencyViolation::ModuleDesync {
                                        modules,
                                        detected_at,
                                        max_skew,
                                    } => (modules, detected_at, max_skew),
                                    _ => {
                                        unreachable!("desync check returned another violation type")
                                    }
                                });
                            assert_eq!(
                                actual, expected,
                                "shape={shape} timestamps={timestamp_mask} reverse={reverse} skew={skew} suppress={suppress_batch}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn tracker_detects_module_desync() {
        init_test("tracker_detects_module_desync");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        let now = Time::from_nanos(1000);

        // Advance scheduler to epoch 2
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );
        tracker.notify_epoch_transition(ModuleId::Scheduler, EpochId::new(1), EpochId::new(2), now);

        // Keep task table at epoch 1 (creating desync)
        tracker.notify_epoch_transition(
            ModuleId::TaskTable,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );

        // Should detect desync violation
        let violation = tracker.check_consistency();
        crate::assert_with_log!(
            violation.is_some(),
            "violation detected",
            true,
            violation.is_some()
        );

        if let Some(EpochConsistencyViolation::ModuleDesync { max_skew, .. }) = violation {
            crate::assert_with_log!(max_skew == 1, "skew is 1", 1, max_skew);
        } else {
            panic!("Expected ModuleDesync violation"); // ubs:ignore - test logic
        }

        crate::test_complete!("tracker_detects_module_desync");
    }

    #[test]
    fn tracker_records_distinct_desync_states_with_same_skew() {
        init_test("tracker_records_distinct_desync_states_with_same_skew");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());

        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(1000),
        );
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::new(1),
            EpochId::new(2),
            Time::from_nanos(1100),
        );
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::new(2),
            EpochId::new(3),
            Time::from_nanos(1200),
        );
        tracker.notify_epoch_transition(
            ModuleId::TaskTable,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(1300),
        );
        tracker.notify_epoch_transition(
            ModuleId::TaskTable,
            EpochId::new(1),
            EpochId::new(2),
            Time::from_nanos(1400),
        );
        tracker.notify_epoch_transition(
            ModuleId::RegionTable,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(1500),
        );

        let violations = tracker.all_violations();
        let desyncs: Vec<Vec<(ModuleId, EpochId)>> = violations
            .into_iter()
            .filter_map(|violation| match violation {
                EpochConsistencyViolation::ModuleDesync { modules, .. } => Some(modules),
                _ => None,
            })
            .collect();

        crate::assert_with_log!(
            desyncs.len() == 3,
            "strict mode records each distinct desync state, including intermediate skew changes",
            3,
            desyncs.len()
        );
        crate::assert_with_log!(
            desyncs[0]
                == vec![
                    (ModuleId::TaskTable, EpochId::new(1)),
                    (ModuleId::Scheduler, EpochId::new(3)),
                ],
            "first desync captures scheduler/task skew",
            true,
            desyncs[0]
                == vec![
                    (ModuleId::TaskTable, EpochId::new(1)),
                    (ModuleId::Scheduler, EpochId::new(3)),
                ]
        );
        crate::assert_with_log!(
            desyncs[1]
                == vec![
                    (ModuleId::TaskTable, EpochId::new(2)),
                    (ModuleId::Scheduler, EpochId::new(3)),
                ],
            "second desync captures the intermediate scheduler/task skew state",
            true,
            desyncs[1]
                == vec![
                    (ModuleId::TaskTable, EpochId::new(2)),
                    (ModuleId::Scheduler, EpochId::new(3)),
                ]
        );
        crate::assert_with_log!(
            desyncs[2]
                == vec![
                    (ModuleId::RegionTable, EpochId::new(1)),
                    (ModuleId::TaskTable, EpochId::new(2)),
                    (ModuleId::Scheduler, EpochId::new(3)),
                ],
            "third desync captures the expanded module set with renewed skew",
            true,
            desyncs[2]
                == vec![
                    (ModuleId::RegionTable, EpochId::new(1)),
                    (ModuleId::TaskTable, EpochId::new(2)),
                    (ModuleId::Scheduler, EpochId::new(3)),
                ]
        );

        crate::test_complete!("tracker_records_distinct_desync_states_with_same_skew");
    }

    #[test]
    fn tracker_allows_synchronized_modules() {
        init_test("tracker_allows_synchronized_modules");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        let now = Time::from_nanos(1000);

        // Advance all modules synchronously
        for module in [
            ModuleId::Scheduler,
            ModuleId::TaskTable,
            ModuleId::RegionTable,
        ] {
            tracker.notify_epoch_transition(module, EpochId::GENESIS, EpochId::new(1), now);
            tracker.notify_epoch_transition(module, EpochId::new(1), EpochId::new(2), now);
        }

        // Should not detect any violations
        let violation = tracker.check_consistency();
        crate::assert_with_log!(
            violation.is_none(),
            "no violation",
            None::<EpochConsistencyViolation>,
            violation
        );

        crate::test_complete!("tracker_allows_synchronized_modules");
    }

    #[test]
    fn tracker_allows_same_timestamp_second_wave_without_false_desync() {
        init_test("tracker_allows_same_timestamp_second_wave_without_false_desync");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        let first_wave = Time::from_nanos(1000);
        let second_wave = Time::from_nanos(2000);

        for module in [
            ModuleId::Scheduler,
            ModuleId::TaskTable,
            ModuleId::RegionTable,
        ] {
            tracker.notify_epoch_transition(module, EpochId::GENESIS, EpochId::new(1), first_wave);
        }

        for module in [
            ModuleId::Scheduler,
            ModuleId::TaskTable,
            ModuleId::RegionTable,
        ] {
            tracker.notify_epoch_transition(module, EpochId::new(1), EpochId::new(2), second_wave);
        }

        crate::assert_with_log!(
            tracker.check_consistency().is_none(),
            "no desync recorded for coherent second-wave rollout",
            None::<EpochConsistencyViolation>,
            tracker.check_consistency()
        );
        crate::assert_with_log!(
            tracker
                .all_violations()
                .into_iter()
                .all(|violation| !matches!(
                    violation,
                    EpochConsistencyViolation::ModuleDesync { .. }
                )),
            "second-wave rollout does not leave behind latent desync evidence",
            true,
            tracker
                .all_violations()
                .into_iter()
                .all(|violation| !matches!(
                    violation,
                    EpochConsistencyViolation::ModuleDesync { .. }
                ))
        );

        crate::test_complete!("tracker_allows_same_timestamp_second_wave_without_false_desync");
    }

    #[test]
    fn tracker_check_consistency_surfaces_stuck_single_step_wave() {
        init_test("tracker_check_consistency_surfaces_stuck_single_step_wave");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        let baseline = Time::from_nanos(1000);
        let stuck_wave = Time::from_nanos(2000);

        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            baseline,
        );
        tracker.notify_epoch_transition(
            ModuleId::TaskTable,
            EpochId::GENESIS,
            EpochId::new(1),
            baseline,
        );

        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::new(1),
            EpochId::new(2),
            stuck_wave,
        );

        crate::assert_with_log!(
            tracker
                .all_violations()
                .into_iter()
                .all(|violation| !matches!(
                    violation,
                    EpochConsistencyViolation::ModuleDesync { .. }
                )),
            "notify-time batch suppression leaves no stored desync evidence yet",
            true,
            tracker
                .all_violations()
                .into_iter()
                .all(|violation| !matches!(
                    violation,
                    EpochConsistencyViolation::ModuleDesync { .. }
                ))
        );

        let violation = tracker.check_consistency();
        let expected_modules = vec![
            (ModuleId::TaskTable, EpochId::new(1)),
            (ModuleId::Scheduler, EpochId::new(2)),
        ];
        let has_stuck_half_wave_desync = matches!(
            violation.as_ref(),
            Some(EpochConsistencyViolation::ModuleDesync {
                modules,
                max_skew,
                ..
            }) if *max_skew == 1 && modules == &expected_modules
        );
        crate::assert_with_log!(
            has_stuck_half_wave_desync,
            "explicit consistency check must surface a stuck half-wave desync",
            true,
            has_stuck_half_wave_desync
        );

        crate::test_complete!("tracker_check_consistency_surfaces_stuck_single_step_wave");
    }

    #[test]
    fn tracker_statistics() {
        init_test("tracker_statistics");

        let tracker = EpochConsistencyTracker::new();
        let now = Time::from_nanos(1000);

        // Perform some transitions
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );
        tracker.notify_epoch_transition(
            ModuleId::TaskTable,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );

        let stats = tracker.transition_statistics();
        crate::assert_with_log!(
            stats.total_transitions == 2,
            "total transitions",
            2,
            stats.total_transitions
        );
        crate::assert_with_log!(
            stats.latest_epoch == EpochId::new(1),
            "latest epoch",
            EpochId::new(1),
            stats.latest_epoch
        );
        crate::assert_with_log!(
            stats.per_module_stats.len() == 2,
            "module count",
            2,
            stats.per_module_stats.len()
        );

        crate::test_complete!("tracker_statistics");
    }

    #[test]
    fn tracker_ignores_duplicate_completion_notifications() {
        init_test("tracker_ignores_duplicate_completion_notifications");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        let now = Time::from_nanos(1000);

        tracker.notify_epoch_transition(
            ModuleId::RegionTable,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );
        tracker.notify_epoch_transition(
            ModuleId::RegionTable,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(2000),
        );

        let stats = tracker.transition_statistics();
        crate::assert_with_log!(
            stats.total_transitions == 1,
            "duplicate transition does not increment totals",
            1,
            stats.total_transitions
        );
        crate::assert_with_log!(
            stats
                .per_module_stats
                .get(&ModuleId::RegionTable)
                .is_some_and(|s| s.transition_count == 1),
            "duplicate transition does not increment module count",
            true,
            stats
                .per_module_stats
                .get(&ModuleId::RegionTable)
                .is_some_and(|s| s.transition_count == 1)
        );
        crate::assert_with_log!(
            tracker.check_consistency().is_none(),
            "duplicate completion is not reported as missing transition",
            None::<EpochConsistencyViolation>,
            tracker.check_consistency()
        );

        crate::test_complete!("tracker_ignores_duplicate_completion_notifications");
    }

    #[test]
    fn tracker_does_not_mask_backward_transition_as_duplicate() {
        init_test("tracker_does_not_mask_backward_transition_as_duplicate");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        tracker.notify_epoch_transition(
            ModuleId::RegionTable,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(1000),
        );
        tracker.notify_epoch_transition(
            ModuleId::RegionTable,
            EpochId::new(1),
            EpochId::new(2),
            Time::from_nanos(1500),
        );
        tracker.notify_epoch_transition(
            ModuleId::RegionTable,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(2000),
        );

        crate::assert_with_log!(
            tracker.check_consistency().is_none(),
            "stale backward report does not poison current consistency",
            None::<EpochConsistencyViolation>,
            tracker.check_consistency()
        );
        crate::assert_with_log!(
            matches!(
                tracker.latest_violation(),
                Some(EpochConsistencyViolation::MissingTransition { .. })
            ),
            "backward transition still records historical violation evidence",
            true,
            matches!(
                tracker.latest_violation(),
                Some(EpochConsistencyViolation::MissingTransition { .. })
            )
        );

        let stats = tracker.transition_statistics();
        crate::assert_with_log!(
            stats
                .per_module_stats
                .get(&ModuleId::RegionTable)
                .is_some_and(|s| s.current_epoch == EpochId::new(2)),
            "stale backward report must not rewind tracked epoch",
            true,
            stats
                .per_module_stats
                .get(&ModuleId::RegionTable)
                .is_some_and(|s| s.current_epoch == EpochId::new(2))
        );
        crate::assert_with_log!(
            stats.total_transitions == 2,
            "ignored stale report must not increment totals",
            2,
            stats.total_transitions
        );

        crate::test_complete!("tracker_does_not_mask_backward_transition_as_duplicate");
    }

    #[test]
    fn tracker_records_skipped_forward_transition_from_current_epoch() {
        init_test("tracker_records_skipped_forward_transition_from_current_epoch");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        tracker.notify_epoch_transition(
            ModuleId::RegionTable,
            EpochId::GENESIS,
            EpochId::new(2),
            Time::from_nanos(1000),
        );

        let violation = tracker.latest_violation();
        crate::assert_with_log!(
            matches!(
                violation,
                Some(EpochConsistencyViolation::MissingTransition {
                    module: ModuleId::RegionTable,
                    expected_epoch,
                    actual_epoch,
                    ..
                }) if expected_epoch == EpochId::new(1) && actual_epoch == EpochId::new(2)
            ),
            "initial skipped-forward report must surface missing-transition evidence",
            true,
            matches!(
                violation,
                Some(EpochConsistencyViolation::MissingTransition {
                    module: ModuleId::RegionTable,
                    expected_epoch,
                    actual_epoch,
                    ..
                }) if expected_epoch == EpochId::new(1) && actual_epoch == EpochId::new(2)
            )
        );
        crate::assert_with_log!(
            tracker.check_consistency().is_none(),
            "historical skipped-forward evidence does not imply current inconsistency",
            None::<EpochConsistencyViolation>,
            tracker.check_consistency()
        );

        let stats = tracker.transition_statistics();
        crate::assert_with_log!(
            stats
                .per_module_stats
                .get(&ModuleId::RegionTable)
                .is_some_and(|s| s.current_epoch == EpochId::new(2)),
            "skipped-forward transition still advances tracked epoch",
            true,
            stats
                .per_module_stats
                .get(&ModuleId::RegionTable)
                .is_some_and(|s| s.current_epoch == EpochId::new(2))
        );
        crate::assert_with_log!(
            stats.total_transitions == 1,
            "skipped-forward transition counts once",
            1,
            stats.total_transitions
        );

        crate::test_complete!("tracker_records_skipped_forward_transition_from_current_epoch");
    }

    #[test]
    fn tracker_does_not_mask_skipped_transition_as_duplicate() {
        init_test("tracker_does_not_mask_skipped_transition_as_duplicate");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        tracker.notify_epoch_transition(
            ModuleId::RegionTable,
            EpochId::GENESIS,
            EpochId::new(2),
            Time::from_nanos(1000),
        );
        tracker.notify_epoch_transition(
            ModuleId::RegionTable,
            EpochId::GENESIS,
            EpochId::new(2),
            Time::from_nanos(2000),
        );

        let violation = tracker.latest_violation();
        crate::assert_with_log!(
            matches!(
                violation,
                Some(EpochConsistencyViolation::MissingTransition {
                    module: ModuleId::RegionTable,
                    expected_epoch,
                    actual_epoch,
                    ..
                }) if expected_epoch == EpochId::new(3) && actual_epoch == EpochId::new(2)
            ),
            "late skipped-transition report must remain visible as missing-transition evidence",
            true,
            matches!(
                violation,
                Some(EpochConsistencyViolation::MissingTransition {
                    module: ModuleId::RegionTable,
                    expected_epoch,
                    actual_epoch,
                    ..
                }) if expected_epoch == EpochId::new(3) && actual_epoch == EpochId::new(2)
            )
        );
        crate::assert_with_log!(
            tracker.check_consistency().is_none(),
            "duplicate skipped-forward reports remain historical only once state stabilizes",
            None::<EpochConsistencyViolation>,
            tracker.check_consistency()
        );

        crate::test_complete!("tracker_does_not_mask_skipped_transition_as_duplicate");
    }

    #[test]
    fn tracker_separates_current_health_from_historical_violation_log() {
        init_test("tracker_separates_current_health_from_historical_violation_log");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        tracker.notify_epoch_transition(
            ModuleId::RegionTable,
            EpochId::GENESIS,
            EpochId::new(2),
            Time::from_nanos(1000),
        );
        tracker.notify_epoch_transition(
            ModuleId::TaskTable,
            EpochId::GENESIS,
            EpochId::new(2),
            Time::from_nanos(1000),
        );

        crate::assert_with_log!(
            tracker.check_consistency().is_none(),
            "current state is healthy once modules converge on the same epoch",
            None::<EpochConsistencyViolation>,
            tracker.check_consistency()
        );
        crate::assert_with_log!(
            matches!(
                tracker.latest_violation(),
                Some(EpochConsistencyViolation::MissingTransition { .. })
            ),
            "historical skipped-forward evidence remains queryable separately",
            true,
            matches!(
                tracker.latest_violation(),
                Some(EpochConsistencyViolation::MissingTransition { .. })
            )
        );

        crate::test_complete!("tracker_separates_current_health_from_historical_violation_log");
    }

    #[test]
    fn disabled_tracker_does_nothing() {
        init_test("disabled_tracker_does_nothing");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::disabled());
        let now = Time::from_nanos(1000);

        // Create obvious desync
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(10),
            now,
        );
        tracker.notify_epoch_transition(
            ModuleId::TaskTable,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );

        // Should not detect violations when disabled
        let violation = tracker.check_consistency();
        crate::assert_with_log!(
            violation.is_none(),
            "no violation when disabled",
            None::<EpochConsistencyViolation>,
            violation
        );

        let stats = tracker.transition_statistics();
        crate::assert_with_log!(
            stats.total_transitions == 0,
            "no transitions tracked when disabled",
            0,
            stats.total_transitions
        );

        crate::test_complete!("disabled_tracker_does_nothing");
    }

    #[test]
    fn tracker_structured_logging_integration() {
        init_test("tracker_structured_logging_integration");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        let now = Time::from_nanos(1000);

        // Test epoch transition logging
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );

        // Test violation logging - create a desync violation
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::new(1),
            EpochId::new(3), // Skip epoch 2
            now,
        );
        tracker.notify_epoch_transition(
            ModuleId::TaskTable,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );

        // Check that violations are detected and logged
        let violation = tracker.check_consistency();
        crate::assert_with_log!(
            violation.is_some(),
            "violation logged",
            true,
            violation.is_some()
        );

        // Test state logging
        tracker.log_epoch_state();
        tracker.drain_telemetry().dispatch();

        // Test replay command generation
        let replay_cmd = tracker
            .generate_replay_command("test_scenario", &[("module", "Scheduler"), ("epoch", "1")]);
        crate::assert_with_log!(
            replay_cmd.contains("epoch-tracker-replay"),
            "replay command generated",
            true,
            replay_cmd.contains("epoch-tracker-replay")
        );

        crate::test_complete!("tracker_structured_logging_integration");
    }

    #[test]
    fn tracker_performance_metrics() {
        init_test("tracker_performance_metrics");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        let now = Time::from_nanos(1000);

        // Start a transition to test latency tracking
        tracker.notify_epoch_transition_start(ModuleId::Scheduler, EpochId::GENESIS, now);

        // Simulate some delay
        let later = Time::from_nanos(1_001_000); // 1ms later
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            later,
        );

        // Verify transition completed
        let stats = tracker.transition_statistics();
        crate::assert_with_log!(
            stats.total_transitions >= 1,
            "transition tracked",
            true,
            stats.total_transitions >= 1
        );

        crate::test_complete!("tracker_performance_metrics");
    }

    #[test]
    fn tracker_runtime_configuration() {
        init_test("tracker_runtime_configuration");

        let mut tracker = EpochConsistencyTracker::new();

        // Test enable/disable
        tracker.set_enabled(false);
        let now = Time::from_nanos(1000);

        // Should not track when disabled
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );

        let stats = tracker.transition_statistics();
        crate::assert_with_log!(
            stats.total_transitions == 0,
            "no tracking when disabled",
            0,
            stats.total_transitions
        );

        // Test threshold update
        tracker.set_slow_transition_threshold(5_000_000); // 5ms

        // Re-enable and verify it works
        tracker.set_enabled(true);
        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            now,
        );

        let stats = tracker.transition_statistics();
        crate::assert_with_log!(
            stats.total_transitions >= 1,
            "tracking enabled again",
            true,
            stats.total_transitions >= 1
        );

        crate::test_complete!("tracker_runtime_configuration");
    }

    #[test]
    fn tracker_check_consistency_surfaces_active_slow_transition() {
        init_test("tracker_check_consistency_surfaces_active_slow_transition");

        let now = Arc::new(AtomicU64::new(500));
        let tracker = EpochConsistencyTracker::with_config_and_time_getter(
            EpochConsistencyConfig {
                max_epoch_skew: 10,
                slow_transition_threshold_ns: 100,
                strict_ordering: false,
                enabled: true,
            },
            {
                let now = Arc::clone(&now);
                Arc::new(move || Time::from_nanos(now.load(Ordering::Relaxed)))
            },
        );

        tracker.notify_epoch_transition_start(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            Time::from_nanos(100),
        );
        tracker.notify_epoch_transition(
            ModuleId::TaskTable,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(500),
        );

        let violation = tracker.check_consistency();
        crate::assert_with_log!(
            matches!(
                violation,
                Some(EpochConsistencyViolation::SlowTransition {
                    module: ModuleId::Scheduler,
                    from_epoch,
                    to_epoch,
                    started_at,
                    duration_ns,
                    ..
                }) if from_epoch == EpochId::GENESIS
                    && to_epoch == EpochId::new(1)
                    && started_at == Time::from_nanos(100)
                    && duration_ns == 400
            ),
            "active slow transitions must be surfaced by current-health checks",
            true,
            matches!(
                violation,
                Some(EpochConsistencyViolation::SlowTransition { .. })
            )
        );

        crate::test_complete!("tracker_check_consistency_surfaces_active_slow_transition");
    }

    #[test]
    fn tracker_transition_start_preserves_earliest_witness_timestamp() {
        init_test("tracker_transition_start_preserves_earliest_witness_timestamp");

        let now = Arc::new(AtomicU64::new(1_000));
        let tracker = EpochConsistencyTracker::with_config_and_time_getter(
            EpochConsistencyConfig {
                max_epoch_skew: 10,
                slow_transition_threshold_ns: 500,
                strict_ordering: false,
                enabled: true,
            },
            {
                let now = Arc::clone(&now);
                Arc::new(move || Time::from_nanos(now.load(Ordering::Relaxed)))
            },
        );

        tracker.notify_epoch_transition_start(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            Time::from_nanos(100),
        );
        tracker.notify_epoch_transition_start(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            Time::from_nanos(900),
        );
        tracker.notify_epoch_transition(
            ModuleId::TaskTable,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(1000),
        );

        let violation = tracker.check_consistency();
        crate::assert_with_log!(
            matches!(
                violation,
                Some(EpochConsistencyViolation::SlowTransition {
                    module: ModuleId::Scheduler,
                    started_at,
                    duration_ns,
                    ..
                }) if started_at == Time::from_nanos(100) && duration_ns == 900
            ),
            "duplicate start witnesses must preserve the original transition start time",
            true,
            matches!(
                violation,
                Some(EpochConsistencyViolation::SlowTransition { .. })
            )
        );

        crate::test_complete!("tracker_transition_start_preserves_earliest_witness_timestamp");
    }

    #[test]
    fn tracker_transition_start_ignores_stale_epoch_snapshot() {
        init_test("tracker_transition_start_ignores_stale_epoch_snapshot");

        let now = Arc::new(AtomicU64::new(500));
        let tracker = EpochConsistencyTracker::with_config_and_time_getter(
            EpochConsistencyConfig {
                max_epoch_skew: 10,
                slow_transition_threshold_ns: 100,
                strict_ordering: false,
                enabled: true,
            },
            {
                let now = Arc::clone(&now);
                Arc::new(move || Time::from_nanos(now.load(Ordering::Relaxed)))
            },
        );

        tracker.notify_epoch_transition(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(100),
        );
        tracker.notify_epoch_transition_start(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            Time::from_nanos(200),
        );
        tracker.notify_epoch_transition(
            ModuleId::TaskTable,
            EpochId::GENESIS,
            EpochId::new(1),
            Time::from_nanos(500),
        );

        crate::assert_with_log!(
            tracker.check_consistency().is_none(),
            "stale transition-start witnesses must not manufacture an in-flight slow transition",
            None::<EpochConsistencyViolation>,
            tracker.check_consistency()
        );
        crate::assert_with_log!(
            matches!(
                tracker.latest_violation(),
                Some(EpochConsistencyViolation::MissingTransition {
                    module: ModuleId::Scheduler,
                    expected_epoch,
                    actual_epoch,
                    ..
                }) if expected_epoch == EpochId::new(1) && actual_epoch == EpochId::GENESIS
            ),
            "stale transition-start witness must remain visible as historical evidence",
            true,
            matches!(
                tracker.latest_violation(),
                Some(EpochConsistencyViolation::MissingTransition { .. })
            )
        );

        crate::test_complete!("tracker_transition_start_ignores_stale_epoch_snapshot");
    }

    #[test]
    fn tracker_check_consistency_uses_live_time_for_idle_slow_transition() {
        init_test("tracker_check_consistency_uses_live_time_for_idle_slow_transition");

        let now = Arc::new(AtomicU64::new(100));
        let tracker = EpochConsistencyTracker::with_config_and_time_getter(
            EpochConsistencyConfig {
                max_epoch_skew: 10,
                slow_transition_threshold_ns: 25,
                strict_ordering: false,
                enabled: true,
            },
            {
                let now = Arc::clone(&now);
                Arc::new(move || Time::from_nanos(now.load(Ordering::Relaxed)))
            },
        );

        tracker.notify_epoch_transition_start(
            ModuleId::Scheduler,
            EpochId::GENESIS,
            Time::from_nanos(100),
        );
        now.store(200, Ordering::Relaxed);

        let violation = tracker.check_consistency();
        crate::assert_with_log!(
            matches!(
                violation,
                Some(EpochConsistencyViolation::SlowTransition {
                    module: ModuleId::Scheduler,
                    from_epoch,
                    to_epoch,
                    started_at,
                    duration_ns,
                    ..
                }) if from_epoch == EpochId::GENESIS
                    && to_epoch == EpochId::new(1)
                    && started_at == Time::from_nanos(100)
                    && duration_ns == 100
            ),
            "idle in-flight transitions must age against the live clock",
            true,
            matches!(
                violation,
                Some(EpochConsistencyViolation::SlowTransition { .. })
            )
        );

        crate::test_complete!("tracker_check_consistency_uses_live_time_for_idle_slow_transition");
    }

    #[test]
    fn tracker_violation_correlation_ids() {
        init_test("tracker_violation_correlation_ids");

        let tracker = EpochConsistencyTracker::with_config(EpochConsistencyConfig::strict());
        let _now = Time::from_nanos(1000);

        // Create multiple violations to test correlation ID uniqueness
        for i in 0..3 {
            let epoch_time = Time::from_nanos(1000 + i * 1000);
            tracker.notify_epoch_transition(
                ModuleId::Scheduler,
                EpochId::new(i),
                EpochId::new(i + 2), // Skip epoch i+1
                epoch_time,
            );
        }

        let violations = tracker.all_violations();
        crate::assert_with_log!(
            violations.len() >= 2,
            "multiple violations detected",
            true,
            violations.len() >= 2
        );

        // Verify each violation has structured information
        for violation in &violations {
            match violation {
                EpochConsistencyViolation::MissingTransition { module, .. } => {
                    crate::assert_with_log!(
                        matches!(module, ModuleId::Scheduler),
                        "correct module in violation",
                        true,
                        matches!(module, ModuleId::Scheduler)
                    );
                }
                _ => {} // Other violation types are also valid
            }
        }

        crate::test_complete!("tracker_violation_correlation_ids");
    }

    #[test]
    fn independent_modules_ignore_cross_module_counters_but_keep_continuity() {
        init_test("independent_modules_ignore_cross_module_counters_but_keep_continuity");
        let tracker =
            EpochConsistencyTracker::with_config(EpochConsistencyConfig::independent_modules());
        let now = Time::from_nanos(1000);

        // Obligation mutations outnumber task mutations, as in a real
        // runtime: the obligation counter runs far ahead of the task counter.
        let mut obligation = EpochId::GENESIS;
        for _ in 0..20 {
            let next = obligation.next();
            tracker.notify_epoch_transition(ModuleId::ObligationTable, obligation, next, now);
            obligation = next;
        }
        tracker.notify_epoch_transition(
            ModuleId::TaskTable,
            EpochId::GENESIS,
            EpochId::GENESIS.next(),
            now,
        );
        assert_eq!(tracker.violation_count(), 0);
        assert!(tracker.check_consistency().is_none());

        // A skipped epoch within one module is still a violation.
        let skipped = obligation.next().next();
        tracker.notify_epoch_transition(ModuleId::ObligationTable, obligation, skipped, now);
        assert_eq!(tracker.violation_count(), 1);
        assert!(matches!(
            tracker.all_violations()[0],
            EpochConsistencyViolation::MissingTransition {
                module: ModuleId::ObligationTable,
                ..
            }
        ));
        crate::test_complete!(
            "independent_modules_ignore_cross_module_counters_but_keep_continuity"
        );
    }

/// The violation buffer keeps the newest `max_violations` entries in order.
/// It trims from the front of a ring buffer: a Vec trimmed with
/// drain(0..excess) shifted every retained entry on each new violation once
/// full (GitHub #82).
#[test]
fn violation_buffer_keeps_the_newest_entries_in_order() {
    init_test("violation_buffer_keeps_the_newest_entries_in_order");
    let tracker = EpochConsistencyTracker::new();
    let publication = tracker.telemetry_publication.lock();
    let total = tracker.max_violations as u64 + 5;
    for actual in 0..total {
        tracker.record_violation(
            &publication,
            EpochConsistencyViolation::MissingTransition {
                module: ModuleId::TaskTable,
                expected_epoch: EpochId::GENESIS,
                actual_epoch: EpochId::new(actual),
                detected_at: Time::ZERO,
            },
        );
    }
    drop(publication);
    let retained: Vec<u64> = tracker
        .all_violations()
        .iter()
        .map(|violation| match violation {
            EpochConsistencyViolation::MissingTransition { actual_epoch, .. } => actual_epoch.0,
            other => panic!("unexpected violation {other:?}"),
        })
        .collect();
    let expected: Vec<u64> = (5..total).collect();
    assert_eq!(retained, expected);
    assert_eq!(tracker.violation_count(), tracker.max_violations);
    match tracker.latest_violation() {
        Some(EpochConsistencyViolation::MissingTransition { actual_epoch, .. }) => {
            assert_eq!(actual_epoch.0, total - 1);
        }
        other => panic!("unexpected latest violation {other:?}"),
    }
}
