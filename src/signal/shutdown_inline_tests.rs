    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::super::SignalKind;
    use super::super::signal::inject_test_signal;
    use super::*;
    use serde_json::json;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};
    use std::thread;
    use std::time::Duration;
    #[cfg(unix)]
    use std::time::Instant;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn poll_once<F: std::future::Future + Unpin>(fut: &mut F) -> Poll<F::Output> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        std::pin::Pin::new(fut).poll(&mut cx)
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[cfg(unix)]
    fn wait_until(mut condition: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if condition() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        condition()
    }

    #[test]
    fn shutdown_controller_initial_state() {
        init_test("shutdown_controller_initial_state");
        let controller = ShutdownController::new();
        let shutting_down = controller.is_shutting_down();
        crate::assert_with_log!(
            !shutting_down,
            "controller not shutting down",
            false,
            shutting_down
        );

        let receiver = controller.subscribe();
        let rx_shutdown = receiver.is_shutting_down();
        crate::assert_with_log!(
            !rx_shutdown,
            "receiver not shutting down",
            false,
            rx_shutdown
        );
        crate::test_complete!("shutdown_controller_initial_state");
    }

    #[test]
    fn shutdown_controller_initiates() {
        init_test("shutdown_controller_initiates");
        let controller = ShutdownController::new();
        let receiver = controller.subscribe();

        controller.shutdown();

        let ctrl_shutdown = controller.is_shutting_down();
        crate::assert_with_log!(
            ctrl_shutdown,
            "controller shutting down",
            true,
            ctrl_shutdown
        );
        let rx_shutdown = receiver.is_shutting_down();
        crate::assert_with_log!(rx_shutdown, "receiver shutting down", true, rx_shutdown);
        crate::test_complete!("shutdown_controller_initiates");
    }

    #[test]
    fn shutdown_only_once() {
        init_test("shutdown_only_once");
        let controller = ShutdownController::new();

        // Multiple shutdown calls should be idempotent.
        controller.shutdown();
        controller.shutdown();
        controller.shutdown();

        let shutting_down = controller.is_shutting_down();
        crate::assert_with_log!(shutting_down, "shutting down", true, shutting_down);
        crate::test_complete!("shutdown_only_once");
    }

    #[test]
    fn multiple_receivers() {
        init_test("multiple_receivers");
        let controller = ShutdownController::new();
        let rx1 = controller.subscribe();
        let rx2 = controller.subscribe();
        let rx3 = controller.subscribe();

        let rx1_shutdown = rx1.is_shutting_down();
        crate::assert_with_log!(!rx1_shutdown, "rx1 not shutting down", false, rx1_shutdown);
        let rx2_shutdown = rx2.is_shutting_down();
        crate::assert_with_log!(!rx2_shutdown, "rx2 not shutting down", false, rx2_shutdown);
        let rx3_shutdown = rx3.is_shutting_down();
        crate::assert_with_log!(!rx3_shutdown, "rx3 not shutting down", false, rx3_shutdown);

        controller.shutdown();

        let rx1_shutdown = rx1.is_shutting_down();
        crate::assert_with_log!(rx1_shutdown, "rx1 shutting down", true, rx1_shutdown);
        let rx2_shutdown = rx2.is_shutting_down();
        crate::assert_with_log!(rx2_shutdown, "rx2 shutting down", true, rx2_shutdown);
        let rx3_shutdown = rx3.is_shutting_down();
        crate::assert_with_log!(rx3_shutdown, "rx3 shutting down", true, rx3_shutdown);
        crate::test_complete!("multiple_receivers");
    }

    #[test]
    fn receiver_wait_after_shutdown() {
        init_test("receiver_wait_after_shutdown");
        let controller = ShutdownController::new();
        let mut receiver = controller.subscribe();

        controller.shutdown();

        // Wait should return immediately.
        let mut fut = Box::pin(receiver.wait());
        let ready = poll_once(&mut fut).is_ready();
        crate::assert_with_log!(ready, "wait ready", true, ready);
        crate::test_complete!("receiver_wait_after_shutdown");
    }

    #[test]
    fn receiver_wait_before_shutdown() {
        init_test("receiver_wait_before_shutdown");
        let controller = Arc::new(ShutdownController::new());
        let controller2 = Arc::clone(&controller);
        let mut receiver = controller.subscribe();

        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            controller2.shutdown();
        });

        // First poll should be pending.
        let mut fut = Box::pin(receiver.wait());
        let pending = poll_once(&mut fut).is_pending();
        crate::assert_with_log!(pending, "wait pending", true, pending);

        // Wait for shutdown.
        handle.join().expect("thread panicked");

        // Now should be ready.
        let ready = poll_once(&mut fut).is_ready();
        crate::assert_with_log!(ready, "wait ready", true, ready);
        crate::test_complete!("receiver_wait_before_shutdown");
    }

    #[test]
    fn receiver_clone() {
        init_test("receiver_clone");
        let controller = ShutdownController::new();
        let rx1 = controller.subscribe();
        let rx2 = rx1.clone();

        let rx1_shutdown = rx1.is_shutting_down();
        crate::assert_with_log!(!rx1_shutdown, "rx1 not shutting down", false, rx1_shutdown);
        let rx2_shutdown = rx2.is_shutting_down();
        crate::assert_with_log!(!rx2_shutdown, "rx2 not shutting down", false, rx2_shutdown);

        controller.shutdown();

        let rx1_shutdown = rx1.is_shutting_down();
        crate::assert_with_log!(rx1_shutdown, "rx1 shutting down", true, rx1_shutdown);
        let rx2_shutdown = rx2.is_shutting_down();
        crate::assert_with_log!(rx2_shutdown, "rx2 shutting down", true, rx2_shutdown);
        crate::test_complete!("receiver_clone");
    }

    #[test]
    fn receiver_clone_preserves_state() {
        init_test("receiver_clone_preserves_state");
        let controller = ShutdownController::new();
        controller.shutdown();

        let rx1 = controller.subscribe();
        let rx2 = rx1.clone();

        // Both should see shutdown already initiated.
        let rx1_shutdown = rx1.is_shutting_down();
        crate::assert_with_log!(rx1_shutdown, "rx1 shutting down", true, rx1_shutdown);
        let rx2_shutdown = rx2.is_shutting_down();
        crate::assert_with_log!(rx2_shutdown, "rx2 shutting down", true, rx2_shutdown);
        crate::test_complete!("receiver_clone_preserves_state");
    }

    #[test]
    fn controller_clone() {
        init_test("controller_clone");
        let controller1 = ShutdownController::new();
        let controller2 = controller1.clone();
        let receiver = controller1.subscribe();

        // Shutdown via clone.
        controller2.shutdown();

        // All should see it.
        let ctrl1 = controller1.is_shutting_down();
        crate::assert_with_log!(ctrl1, "controller1 shutting down", true, ctrl1);
        let ctrl2 = controller2.is_shutting_down();
        crate::assert_with_log!(ctrl2, "controller2 shutting down", true, ctrl2);
        let rx_shutdown = receiver.is_shutting_down();
        crate::assert_with_log!(rx_shutdown, "receiver shutting down", true, rx_shutdown);
        crate::test_complete!("controller_clone");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn listen_for_signals_triggers_shutdown() {
        init_test("listen_for_signals_triggers_shutdown");
        let controller = Arc::new(ShutdownController::new());
        let mut receiver = controller.subscribe();

        controller.listen_for_signals();
        inject_test_signal(SignalKind::terminate()).expect("test signal injection");

        let mut fut = Box::pin(receiver.wait());
        for _ in 0..50 {
            if poll_once(&mut fut).is_ready() {
                let shutting_down = controller.is_shutting_down();
                crate::assert_with_log!(
                    shutting_down,
                    "controller shutting down via signal listener",
                    true,
                    shutting_down
                );
                crate::test_complete!("listen_for_signals_triggers_shutdown");
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }

        crate::assert_with_log!(
            false,
            "signal listener triggered shutdown before timeout",
            true,
            false
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn listen_for_signals_is_idempotent() {
        init_test("listen_for_signals_is_idempotent");
        let controller = Arc::new(ShutdownController::new());

        controller.listen_for_signals();
        controller.listen_for_signals();

        let started = controller
            .state
            .signal_listeners_started
            .load(Ordering::Acquire);
        crate::assert_with_log!(started, "signal listeners installed once", true, started);

        controller.shutdown();
        let shutting_down = controller.is_shutting_down();
        crate::assert_with_log!(
            shutting_down,
            "manual shutdown still works",
            true,
            shutting_down
        );
        crate::test_complete!("listen_for_signals_is_idempotent");
    }

    #[test]
    fn reload_controller_request_wakes_receiver_without_shutdown() {
        init_test("reload_controller_request_wakes_receiver_without_shutdown");
        let reload = ReloadController::new();
        let shutdown = ShutdownController::new();
        let mut reload_rx = reload.subscribe();
        let shutdown_rx = shutdown.subscribe();

        let sequence = reload.request_reload();
        crate::assert_with_log!(sequence == 1, "reload sequence", 1, sequence);

        let mut fut = Box::pin(reload_rx.wait());
        let observed = futures_lite::future::block_on(fut.as_mut());
        crate::assert_with_log!(observed == 1, "receiver observed sequence", 1, observed);
        crate::assert_with_log!(
            !shutdown.is_shutting_down(),
            "reload does not trigger shutdown controller",
            false,
            shutdown.is_shutting_down()
        );
        crate::assert_with_log!(
            !shutdown_rx.is_shutting_down(),
            "reload does not trigger shutdown receiver",
            false,
            shutdown_rx.is_shutting_down()
        );
        crate::test_complete!("reload_controller_request_wakes_receiver_without_shutdown");
    }

    #[test]
    fn reload_receiver_drains_queued_sequences() {
        init_test("reload_receiver_drains_queued_sequences");
        let reload = ReloadController::new();
        let mut receiver = reload.subscribe();

        reload.request_reload();
        reload.request_reload();

        let first = futures_lite::future::block_on(receiver.wait());
        let second = futures_lite::future::block_on(receiver.wait());
        crate::assert_with_log!(first == 1, "first reload sequence", 1, first);
        crate::assert_with_log!(second == 2, "second reload sequence", 2, second);
        crate::assert_with_log!(
            receiver.seen_reload_count() == 2,
            "receiver seen sequence",
            2,
            receiver.seen_reload_count()
        );
        crate::test_complete!("reload_receiver_drains_queued_sequences");
    }

    #[test]
    fn reload_receiver_invokes_handler_and_reports_outcome() {
        init_test("reload_receiver_invokes_handler_and_reports_outcome");
        let reload = ReloadController::new();
        let mut receiver = reload.subscribe();

        reload.request_reload();
        let completed =
            futures_lite::future::block_on(receiver.handle_next_reload(|sequence| async move {
                crate::assert_with_log!(sequence == 1, "handler sequence", 1, sequence);
                Ok::<(), &'static str>(())
            }));
        crate::assert_with_log!(
            completed == ReloadOutcome::Completed { sequence: 1 },
            "handler completed",
            ReloadOutcome::<&'static str>::Completed { sequence: 1 },
            completed
        );

        reload.request_reload();
        let failed =
            futures_lite::future::block_on(receiver.handle_next_reload(|_sequence| async {
                Err::<(), &'static str>("reload failed")
            }));
        crate::assert_with_log!(
            failed
                == ReloadOutcome::Failed {
                    sequence: 2,
                    error: "reload failed"
                },
            "handler failed",
            ReloadOutcome::Failed {
                sequence: 2,
                error: "reload failed"
            },
            failed
        );
        crate::test_complete!("reload_receiver_invokes_handler_and_reports_outcome");
    }

    #[test]
    fn reload_wait_or_shutdown_returns_none_when_shutdown_wins() {
        init_test("reload_wait_or_shutdown_returns_none_when_shutdown_wins");
        let reload = ReloadController::new();
        let shutdown = ShutdownController::new();
        let mut reload_rx = reload.subscribe();
        let mut shutdown_rx = shutdown.subscribe();

        shutdown.shutdown();

        let observed = futures_lite::future::block_on(reload_rx.wait_or_shutdown(&mut shutdown_rx));
        crate::assert_with_log!(
            observed.is_none(),
            "shutdown wins before reload request",
            None::<u64>,
            observed
        );
        crate::assert_with_log!(
            reload_rx.seen_reload_count() == 0,
            "no reload sequence consumed",
            0,
            reload_rx.seen_reload_count()
        );
        crate::test_complete!("reload_wait_or_shutdown_returns_none_when_shutdown_wins");
    }

    #[test]
    fn reload_handler_reports_cancelled_when_shutdown_wins() {
        init_test("reload_handler_reports_cancelled_when_shutdown_wins");
        let reload = ReloadController::new();
        let shutdown = ShutdownController::new();
        let mut reload_rx = reload.subscribe();
        let mut shutdown_rx = shutdown.subscribe();

        reload.request_reload();
        shutdown.shutdown();

        let outcome = futures_lite::future::block_on(reload_rx.handle_next_reload_or_shutdown(
            &mut shutdown_rx,
            |sequence| {
                crate::assert_with_log!(sequence == 1, "handler sequence", 1, sequence);
                std::future::pending::<Result<(), &'static str>>()
            },
        ));
        crate::assert_with_log!(
            outcome == ReloadOutcome::<&'static str>::Cancelled { sequence: Some(1) },
            "shutdown cancels pending reload handler",
            ReloadOutcome::<&'static str>::Cancelled { sequence: Some(1) },
            outcome
        );
        crate::test_complete!("reload_handler_reports_cancelled_when_shutdown_wins");
    }

    #[cfg(unix)]
    #[test]
    fn sighup_triggers_reload_only_and_sigterm_triggers_shutdown() {
        init_test("sighup_triggers_reload_only_and_sigterm_triggers_shutdown");
        let reload = Arc::new(ReloadController::new());
        let shutdown = Arc::new(ShutdownController::new());
        let mut reload_rx = reload.subscribe();
        let mut shutdown_rx = shutdown.subscribe();

        let listener_installed = reload.listen_for_sighup().is_ok();
        crate::assert_with_log!(
            listener_installed,
            "install SIGHUP listener",
            true,
            listener_installed
        );
        if !listener_installed {
            return;
        }
        let shutdown_watches_sighup = watched_signal_kinds().contains(&SignalKind::hangup());
        crate::assert_with_log!(
            !shutdown_watches_sighup,
            "shutdown listener excludes SIGHUP",
            false,
            shutdown_watches_sighup
        );

        let sighup_injected = inject_test_signal(SignalKind::hangup()).is_ok();
        crate::assert_with_log!(sighup_injected, "inject SIGHUP", true, sighup_injected);
        if !sighup_injected {
            return;
        }
        if !wait_until(|| reload.reload_count() > 0) {
            crate::assert_with_log!(false, "SIGHUP triggered reload before timeout", true, false);
            return;
        }

        let mut reload_fut = Box::pin(reload_rx.wait());
        let reload_sequence = match poll_once(&mut reload_fut) {
            Poll::Ready(sequence) => sequence,
            Poll::Pending => {
                crate::assert_with_log!(
                    false,
                    "SIGHUP triggered reload before timeout",
                    true,
                    false
                );
                return;
            }
        };
        crate::assert_with_log!(
            reload_sequence == 1,
            "SIGHUP triggers reload sequence",
            1,
            reload_sequence
        );
        crate::assert_with_log!(
            !shutdown.is_shutting_down(),
            "SIGHUP does not trigger shutdown",
            false,
            shutdown.is_shutting_down()
        );

        shutdown.listen_for_signals();
        let sigterm_injected = inject_test_signal(SignalKind::terminate()).is_ok();
        crate::assert_with_log!(sigterm_injected, "inject SIGTERM", true, sigterm_injected);
        if !sigterm_injected {
            return;
        }
        let mut fut = Box::pin(shutdown_rx.wait());
        if wait_until(|| poll_once(&mut fut).is_ready()) {
            crate::assert_with_log!(
                shutdown.is_shutting_down(),
                "SIGTERM triggers shutdown",
                true,
                shutdown.is_shutting_down()
            );
            crate::test_complete!("sighup_triggers_reload_only_and_sigterm_triggers_shutdown");
            return;
        }

        crate::assert_with_log!(
            false,
            "SIGTERM triggered shutdown before timeout",
            true,
            false
        );
    }

    #[test]
    fn shutdown_sequence_snapshot_scrubbed() {
        let controller = ShutdownController::new();
        let rx_a = controller.subscribe();
        let rx_b = controller.subscribe();

        let before = json!({
            "controller": controller.is_shutting_down(),
            "receivers": [
                {"receiver": "[RX_A]", "shutting_down": rx_a.is_shutting_down()},
                {"receiver": "[RX_B]", "shutting_down": rx_b.is_shutting_down()},
            ],
        });

        controller.shutdown();

        insta::assert_json_snapshot!(
            "shutdown_sequence_scrubbed",
            json!({
                "before": before,
                "after": {
                    "controller": controller.is_shutting_down(),
                    "receivers": [
                        {"receiver": "[RX_A]", "shutting_down": rx_a.is_shutting_down()},
                        {"receiver": "[RX_B]", "shutting_down": rx_b.is_shutting_down()},
                    ],
                }
            })
        );
    }
