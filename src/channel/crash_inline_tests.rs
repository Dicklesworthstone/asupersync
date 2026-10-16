    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::channel::mpsc;
    use crate::cx::Cx;
    use crate::evidence_sink::CollectorSink;
    use std::future::Future;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex as StdMutex, Weak};
    use std::task::{Context, Poll};

    fn test_cx() -> Cx<crate::cx::cap::All> {
        Cx::for_testing()
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        let waker = std::task::Waker::noop().clone();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Box::pin(f);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn make_crash_channel(
        config: CrashConfig,
    ) -> (
        CrashSender<u32>,
        mpsc::Receiver<u32>,
        Arc<CrashController>,
        Arc<CollectorSink>,
    ) {
        let collector = Arc::new(CollectorSink::new());
        let sink: Arc<dyn EvidenceSink> = collector.clone();
        let (tx, rx, ctrl) = crash_channel::<u32>(16, config, sink);
        (tx, rx, ctrl, collector)
    }

    #[derive(Debug, Default)]
    struct ControllerLockProbeSink {
        controller: StdMutex<Weak<CrashController>>,
        lock_free_observations: StdMutex<Vec<bool>>,
        timestamp_seq: AtomicU64,
    }

    impl ControllerLockProbeSink {
        fn attach(&self, controller: &Arc<CrashController>) {
            *self
                .controller
                .lock()
                .expect("probe controller mutex should not poison") = Arc::downgrade(controller);
        }

        fn observations(&self) -> Vec<bool> {
            self.lock_free_observations
                .lock()
                .expect("probe observations mutex should not poison")
                .clone()
        }
    }

    impl EvidenceSink for ControllerLockProbeSink {
        fn emit(&self, _entry: &EvidenceLedger) {
            let controller = self
                .controller
                .lock()
                .expect("probe controller mutex should not poison")
                .upgrade()
                .expect("controller should still be alive during emit");
            self.lock_free_observations
                .lock()
                .expect("probe observations mutex should not poison")
                .push(
                    controller.state.try_lock().is_some()
                        && controller.send_commit.try_lock().is_some(),
                );
        }

        fn next_evidence_ts(&self) -> u64 {
            self.timestamp_seq
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1)
        }
    }

    // --- Config validation ---

    #[test]
    #[should_panic(expected = "crash probability must be in [0.0, 1.0]")]
    fn config_rejects_invalid_crash_probability() {
        let _ = CrashConfig::new(42).with_crash_probability(1.5);
    }

    #[test]
    fn config_default_is_disabled() {
        let config = CrashConfig::new(42);
        assert!(!config.is_enabled());
    }

    #[test]
    fn config_probabilistic_is_enabled() {
        let config = CrashConfig::new(42).with_crash_probability(0.5);
        assert!(config.is_enabled());
    }

    #[test]
    fn config_deterministic_is_enabled() {
        let config = CrashConfig::new(42).with_crash_after_sends(10);
        assert!(config.is_enabled());
    }

    // --- Passthrough (no faults) ---

    #[test]
    fn passthrough_when_disabled() {
        let config = CrashConfig::new(42);
        let (tx, mut rx, ctrl, _) = make_crash_channel(config);
        let cx = test_cx();

        for i in 0..10 {
            block_on(tx.send(&cx, i)).unwrap();
        }

        for i in 0..10 {
            assert_eq!(rx.try_recv().unwrap(), i);
        }
        assert!(!ctrl.is_crashed());
    }

    // --- Manual crash/restart ---

    #[test]
    fn manual_crash_rejects_sends() {
        let config = CrashConfig::new(42);
        let (tx, _rx, ctrl, _) = make_crash_channel(config);
        let cx = test_cx();

        block_on(tx.send(&cx, 1)).unwrap();
        ctrl.crash();

        let err = block_on(tx.send(&cx, 2)).unwrap_err();
        assert!(matches!(err, SendError::Disconnected(2)));
    }

    #[test]
    fn restart_re_enables_sends() {
        let config = CrashConfig::new(42);
        let (tx, mut rx, ctrl, _) = make_crash_channel(config);
        let cx = test_cx();

        ctrl.crash();
        assert!(block_on(tx.send(&cx, 1)).is_err());

        ctrl.restart();
        block_on(tx.send(&cx, 2)).unwrap();
        assert_eq!(rx.try_recv().unwrap(), 2);
    }

    #[test]
    fn crash_already_crashed_returns_false() {
        let config = CrashConfig::new(42);
        let (_, _, ctrl, _) = make_crash_channel(config);

        assert!(ctrl.crash());
        assert!(!ctrl.crash()); // Already crashed.
    }

    #[test]
    fn restart_when_not_crashed_returns_false() {
        let config = CrashConfig::new(42);
        let (_, _, ctrl, _) = make_crash_channel(config);

        assert!(!ctrl.restart()); // Not crashed.
    }

    // --- Deterministic crash after N sends ---

    #[test]
    fn crash_after_sends() {
        let config = CrashConfig::new(42).with_crash_after_sends(5);
        let (tx, mut rx, ctrl, _) = make_crash_channel(config);
        let cx = test_cx();

        for i in 0..5 {
            block_on(tx.send(&cx, i)).unwrap();
        }

        // 6th send should trigger crash.
        let err = block_on(tx.send(&cx, 5)).unwrap_err();
        assert!(matches!(err, SendError::Disconnected(5)));
        assert!(ctrl.is_crashed());

        // Verify the first 5 were delivered.
        for i in 0..5 {
            assert_eq!(rx.try_recv().unwrap(), i);
        }
    }

    #[test]
    fn concurrent_sends_stop_at_exact_deterministic_limit() {
        let config = CrashConfig::new(42).with_crash_after_sends(1);
        let (tx, mut rx, ctrl) = crash_channel::<u32>(
            1,
            config,
            Arc::new(CollectorSink::new()) as Arc<dyn EvidenceSink>,
        );
        let cx_a = test_cx();
        let cx_b = test_cx();
        tx.inner()
            .try_send(99)
            .expect("sentinel must fill the inner channel");

        let mut send_a = Box::pin(tx.send(&cx_a, 1));
        let mut send_b = Box::pin(tx.send(&cx_b, 2));
        let waker = std::task::Waker::noop().clone();
        let mut task_cx = Context::from_waker(&waker);

        assert!(send_a.as_mut().poll(&mut task_cx).is_pending());
        assert!(send_b.as_mut().poll(&mut task_cx).is_pending());
        assert_eq!(rx.try_recv(), Ok(99));
        assert!(matches!(
            send_a.as_mut().poll(&mut task_cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(rx.try_recv(), Ok(1));
        assert!(matches!(
            send_b.as_mut().poll(&mut task_cx),
            Poll::Ready(Err(SendError::Disconnected(2)))
        ));

        assert!(rx.try_recv().is_err(), "only one wrapped send may commit");
        assert_eq!(tx.send_count(), 1);
        assert!(ctrl.is_crashed());
        assert_eq!(
            ctrl.stats().snapshot(),
            CrashStatsSnapshot {
                sends_attempted: 2,
                sends_succeeded: 1,
                sends_rejected: 1,
                crashes: 1,
                restarts: 0,
            }
        );
    }

    #[test]
    fn cancelled_pending_send_does_not_consume_send_budget() {
        let config = CrashConfig::new(42).with_crash_after_sends(1);
        let (tx, mut rx, ctrl) = crash_channel::<u32>(
            1,
            config,
            Arc::new(CollectorSink::new()) as Arc<dyn EvidenceSink>,
        );
        let cx_a = test_cx();
        let cx_cancelled = test_cx();
        tx.inner()
            .try_send(99)
            .expect("sentinel must fill the inner channel");

        let mut send_a = Box::pin(tx.send(&cx_a, 1));
        let mut cancelled = Box::pin(tx.send(&cx_cancelled, 2));
        let waker = std::task::Waker::noop().clone();
        let mut task_cx = Context::from_waker(&waker);

        assert!(send_a.as_mut().poll(&mut task_cx).is_pending());
        assert!(cancelled.as_mut().poll(&mut task_cx).is_pending());
        cx_cancelled.set_cancel_requested(true);
        assert!(matches!(
            cancelled.as_mut().poll(&mut task_cx),
            Poll::Ready(Err(SendError::Cancelled(2)))
        ));

        assert_eq!(rx.try_recv(), Ok(99));
        assert!(matches!(
            send_a.as_mut().poll(&mut task_cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(rx.try_recv(), Ok(1));
        assert_eq!(tx.send_count(), 1);
        assert!(!ctrl.is_crashed());
        let stats = ctrl.stats().snapshot();
        assert_eq!(stats.sends_attempted, 2);
        assert_eq!(stats.sends_succeeded, 1);
        assert_eq!(stats.sends_rejected, 0);
    }

    #[test]
    fn disconnect_releases_exact_send_serialization_without_success() {
        let config = CrashConfig::new(42).with_crash_after_sends(1);
        let (tx, mut rx, ctrl) = crash_channel::<u32>(
            1,
            config,
            Arc::new(CollectorSink::new()) as Arc<dyn EvidenceSink>,
        );
        let cx_a = test_cx();
        let cx_b = test_cx();
        tx.inner()
            .try_send(99)
            .expect("sentinel must fill the inner channel");

        let mut send_a = Box::pin(tx.send(&cx_a, 1));
        let mut send_b = Box::pin(tx.send(&cx_b, 2));
        let waker = std::task::Waker::noop().clone();
        let mut task_cx = Context::from_waker(&waker);
        assert!(send_a.as_mut().poll(&mut task_cx).is_pending());
        assert!(send_b.as_mut().poll(&mut task_cx).is_pending());

        rx.close();
        assert!(matches!(
            send_a.as_mut().poll(&mut task_cx),
            Poll::Ready(Err(SendError::Disconnected(1)))
        ));
        assert!(matches!(
            send_b.as_mut().poll(&mut task_cx),
            Poll::Ready(Err(SendError::Disconnected(2)))
        ));
        assert_eq!(rx.try_recv(), Ok(99), "close preserves queued messages");
        assert_eq!(tx.send_count(), 0);
        assert!(!ctrl.is_crashed());
        let stats = ctrl.stats().snapshot();
        assert_eq!(stats.sends_attempted, 2);
        assert_eq!(stats.sends_succeeded, 0);
        assert_eq!(stats.sends_rejected, 0);
    }

    #[test]
    fn panicking_receiver_wake_preserves_commit_and_releases_mutex() {
        struct PanicWake;

        impl std::task::Wake for PanicWake {
            fn wake(self: Arc<Self>) {
                panic!("injected receiver wake panic");
            }

            fn wake_by_ref(self: &Arc<Self>) {
                panic!("injected receiver wake panic");
            }
        }

        let config = CrashConfig::new(42).with_crash_after_sends(1);
        let (tx, mut rx, ctrl, _) = make_crash_channel(config);
        let recv_cx = test_cx();
        let mut recv = Box::pin(rx.recv(&recv_cx));
        let panic_waker = std::task::Waker::from(Arc::new(PanicWake));
        let mut panic_cx = Context::from_waker(&panic_waker);
        assert!(recv.as_mut().poll(&mut panic_cx).is_pending());

        let send_cx = test_cx();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block_on(tx.send(&send_cx, 7))
        }));
        assert!(panic.is_err(), "receiver Waker must inject an unwind");
        drop(recv);

        assert_eq!(
            rx.try_recv(),
            Ok(7),
            "message committed before receiver wake"
        );
        assert_eq!(tx.send_count(), 1, "committed message counted before wake");
        assert_eq!(ctrl.stats().snapshot().sends_succeeded, 1);

        let next_cx = test_cx();
        assert!(matches!(
            block_on(tx.send(&next_cx, 8)),
            Err(SendError::Disconnected(8))
        ));
        assert!(
            ctrl.is_crashed(),
            "released commit mutex admits the threshold check"
        );
        assert_eq!(tx.send_count(), 1);
    }

    // --- Restart limit exhaustion ---

    #[test]
    fn restart_exhaustion() {
        let config = CrashConfig::new(42).with_max_restarts(2);
        let (_, _, ctrl, _) = make_crash_channel(config);

        ctrl.crash();
        assert!(ctrl.restart()); // restart 1
        ctrl.crash();
        assert!(ctrl.restart()); // restart 2
        ctrl.crash();
        assert!(!ctrl.restart()); // exhausted
        assert!(ctrl.is_exhausted());
    }

    #[test]
    fn exhausted_controller_rejects_sends() {
        let config = CrashConfig::new(42)
            .with_crash_after_sends(1)
            .with_max_restarts(0);
        let (tx, _rx, ctrl, _) = make_crash_channel(config);
        let cx = test_cx();

        block_on(tx.send(&cx, 0)).unwrap(); // 1 successful send.
        assert!(block_on(tx.send(&cx, 1)).is_err()); // Crash triggers.
        assert!(ctrl.is_crashed());

        // Can't restart — exhausted.
        assert!(!ctrl.restart());
        assert!(ctrl.is_exhausted());
    }

    // --- Stats tracking ---

    #[test]
    fn stats_track_all_operations() {
        let config = CrashConfig::new(42).with_crash_after_sends(3);
        let (tx, _rx, ctrl, _) = make_crash_channel(config);
        let cx = test_cx();

        // 3 successful, 1 triggers crash, 1 rejected while crashed.
        for i in 0..5 {
            let _ = block_on(tx.send(&cx, i));
        }

        let snap = ctrl.stats().snapshot();
        assert_eq!(snap.sends_attempted, 5);
        assert_eq!(snap.sends_succeeded, 3);
        assert_eq!(snap.sends_rejected, 2);
        assert_eq!(snap.crashes, 1);
    }

    // --- Evidence logging ---

    #[test]
    fn evidence_logged_for_crash_events() {
        let config = CrashConfig::new(42).with_crash_after_sends(2);
        let (tx, _rx, ctrl, collector) = make_crash_channel(config);
        let cx = test_cx();

        block_on(tx.send(&cx, 0)).unwrap();
        block_on(tx.send(&cx, 1)).unwrap();
        let _ = block_on(tx.send(&cx, 2)); // Triggers crash.

        assert!(ctrl.restart());
        block_on(tx.send(&cx, 3)).expect("cold restart resets the send limit");

        let entries = collector.entries();
        let actions: Vec<String> = entries.iter().map(|e| e.action.clone()).collect();
        assert!(
            actions.iter().any(|a| a.contains("crash")),
            "Expected crash evidence, got: {actions:?}"
        );
    }

    #[test]
    fn evidence_timestamps_follow_deterministic_event_sequence() {
        let config = CrashConfig::new(42).with_crash_after_sends(1);
        let (tx, _rx, ctrl, collector) = make_crash_channel(config);
        let cx = test_cx();

        block_on(tx.send(&cx, 0)).unwrap();
        assert!(block_on(tx.send(&cx, 1)).is_err());
        assert!(ctrl.restart());

        let timestamps: Vec<u64> = collector
            .entries()
            .iter()
            .map(|entry| entry.ts_unix_ms)
            .collect();
        assert_eq!(timestamps, vec![1, 2, 3]);
    }

    #[test]
    fn crash_controller_emits_evidence_after_releasing_controller_locks() {
        let normal_probe = Arc::new(ControllerLockProbeSink::default());
        let normal_sink: Arc<dyn EvidenceSink> = normal_probe.clone();
        let normal_ctrl = Arc::new(CrashController::new(&CrashConfig::new(42), normal_sink));
        normal_probe.attach(&normal_ctrl);

        assert!(normal_ctrl.crash());
        assert!(normal_ctrl.restart());
        assert_eq!(normal_probe.observations(), vec![true, true]);

        let exhausted_probe = Arc::new(ControllerLockProbeSink::default());
        let exhausted_sink: Arc<dyn EvidenceSink> = exhausted_probe.clone();
        let exhausted_config = CrashConfig::new(42).with_max_restarts(0);
        let exhausted_ctrl = Arc::new(CrashController::new(&exhausted_config, exhausted_sink));
        exhausted_probe.attach(&exhausted_ctrl);

        assert!(exhausted_ctrl.crash());
        assert!(!exhausted_ctrl.restart());
        assert_eq!(exhausted_probe.observations(), vec![true, true]);
    }

    // --- Cold vs warm restart ---

    #[test]
    fn send_waiting_across_cold_restart_cannot_enter_new_incarnation() {
        let config = CrashConfig::new(42)
            .with_crash_after_sends(2)
            .with_restart_mode(RestartMode::Cold);
        let (tx, mut rx, ctrl) = crash_channel::<u32>(
            1,
            config,
            Arc::new(CollectorSink::new()) as Arc<dyn EvidenceSink>,
        );
        let cx = test_cx();
        tx.inner()
            .try_send(99)
            .expect("sentinel must fill the inner channel");

        let mut stale_send = Box::pin(tx.send(&cx, 1));
        let waker = std::task::Waker::noop().clone();
        let mut task_cx = Context::from_waker(&waker);
        assert!(stale_send.as_mut().poll(&mut task_cx).is_pending());

        assert!(ctrl.crash());
        assert!(ctrl.restart());
        assert_eq!(tx.send_count(), 0);

        assert_eq!(rx.try_recv(), Ok(99));
        assert!(matches!(
            stale_send.as_mut().poll(&mut task_cx),
            Poll::Ready(Err(SendError::Disconnected(1)))
        ));
        assert!(rx.try_recv().is_err(), "stale send must not cross restart");
        assert_eq!(
            ctrl.stats().snapshot(),
            CrashStatsSnapshot {
                sends_attempted: 0,
                sends_succeeded: 0,
                sends_rejected: 0,
                crashes: 1,
                restarts: 1,
            }
        );

        block_on(tx.send(&cx, 2)).expect("fresh-incarnation send must succeed");
        assert_eq!(tx.send_count(), 1);
        assert_eq!(rx.try_recv(), Ok(2));
    }

    #[test]
    fn cold_restart_resets_send_count() {
        let config = CrashConfig::new(42)
            .with_crash_after_sends(3)
            .with_restart_mode(RestartMode::Cold);
        let (tx, _rx, ctrl, _) = make_crash_channel(config);
        let cx = test_cx();

        // 3 sends then crash.
        for i in 0..3 {
            block_on(tx.send(&cx, i)).unwrap();
        }
        assert!(block_on(tx.send(&cx, 3)).is_err());
        assert!(ctrl.is_crashed());

        // Cold restart completes the count and send-stat reset itself.
        assert!(ctrl.restart());
        assert_eq!(tx.send_count(), 0);
        assert_eq!(
            ctrl.stats().snapshot(),
            CrashStatsSnapshot {
                sends_attempted: 0,
                sends_succeeded: 0,
                sends_rejected: 0,
                crashes: 1,
                restarts: 1,
            }
        );

        // Should be able to send 3 more before next crash.
        for i in 10..13 {
            block_on(tx.send(&cx, i)).unwrap();
        }
        assert!(block_on(tx.send(&cx, 13)).is_err());
        assert!(ctrl.is_crashed());
        assert_eq!(tx.send_count(), 3);
        assert_eq!(
            ctrl.stats().snapshot(),
            CrashStatsSnapshot {
                sends_attempted: 4,
                sends_succeeded: 3,
                sends_rejected: 1,
                crashes: 2,
                restarts: 1,
            }
        );
    }

    #[test]
    fn warm_restart_preserves_send_count() {
        let config = CrashConfig::new(42)
            .with_crash_after_sends(3)
            .with_restart_mode(RestartMode::Warm);
        let (tx, _rx, ctrl, _) = make_crash_channel(config);
        let cx = test_cx();

        // 3 sends then crash.
        for i in 0..3 {
            block_on(tx.send(&cx, i)).unwrap();
        }
        assert!(block_on(tx.send(&cx, 3)).is_err());
        let before_restart = ctrl.stats().snapshot();

        // Warm restart: count preserved → immediate crash on next send.
        assert!(ctrl.restart());
        assert_eq!(tx.send_count(), 3);
        let after_restart = ctrl.stats().snapshot();
        assert_eq!(
            after_restart.sends_attempted,
            before_restart.sends_attempted
        );
        assert_eq!(
            after_restart.sends_succeeded,
            before_restart.sends_succeeded
        );
        assert_eq!(after_restart.sends_rejected, before_restart.sends_rejected);
        assert_eq!(after_restart.crashes, before_restart.crashes);
        assert_eq!(after_restart.restarts, before_restart.restarts + 1);
        assert!(block_on(tx.send(&cx, 4)).is_err());
        assert_eq!(tx.send_count(), 3);
    }

    // =========================================================================
    // Pure data-type tests (wave 41 – CyanBarn)
    // =========================================================================

    #[test]
    fn restart_mode_debug_clone_copy_eq() {
        let cold = RestartMode::Cold;
        let warm = RestartMode::Warm;
        let copied = cold;
        let cloned = cold;
        assert_eq!(copied, cloned);
        assert_eq!(copied, RestartMode::Cold);
        assert_ne!(cold, warm);
        assert!(format!("{cold:?}").contains("Cold"));
        assert!(format!("{warm:?}").contains("Warm"));
    }

    #[test]
    fn crash_stats_snapshot_debug_clone_eq_display() {
        let snap = CrashStatsSnapshot {
            sends_attempted: 10,
            sends_succeeded: 8,
            sends_rejected: 2,
            crashes: 1,
            restarts: 1,
        };
        let cloned = snap.clone();
        assert_eq!(cloned, snap);
        let dbg = format!("{snap:?}");
        assert!(dbg.contains("CrashStatsSnapshot"));
        let display = format!("{snap}");
        assert!(display.contains("attempted: 10"));
        assert!(display.contains("crashes: 1"));
    }

    #[test]
    fn crash_config_debug_clone() {
        let config = CrashConfig::new(42)
            .with_crash_probability(0.5)
            .with_crash_after_sends(10)
            .with_max_restarts(3)
            .with_restart_mode(RestartMode::Warm);
        let cloned = config.clone();
        assert_eq!(cloned.seed, 42);
        assert_eq!(cloned.restart_mode, RestartMode::Warm);
        assert_eq!(cloned.max_restarts, Some(3));
        let dbg = format!("{config:?}");
        assert!(dbg.contains("CrashConfig"));
    }
