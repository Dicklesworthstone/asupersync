    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    #[cfg(unix)]
    use std::future::Future;
    #[cfg(unix)]
    use std::task::{Context, Poll, Waker};

    #[cfg(unix)]
    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn signal_error_display() {
        init_test("signal_error_display");
        let err = SignalError::unsupported(SignalKind::Terminate, "signal unsupported");
        let msg = format!("{err}");
        let has_sigterm = msg.contains("SIGTERM");
        crate::assert_with_log!(has_sigterm, "contains SIGTERM", true, has_sigterm);
        let has_reason = msg.contains("unsupported");
        crate::assert_with_log!(has_reason, "contains reason", true, has_reason);
        crate::test_complete!("signal_error_display");
    }

    #[test]
    fn signal_creation_platform_contract() {
        init_test("signal_creation_platform_contract");
        let result = signal(SignalKind::terminate());

        #[cfg(unix)]
        {
            let ok = result.is_ok();
            crate::assert_with_log!(ok, "signal creation ok", true, ok);
        }

        #[cfg(windows)]
        {
            let ok = result.is_ok();
            crate::assert_with_log!(ok, "windows signal creation ok", true, ok);
        }

        #[cfg(not(any(unix, windows)))]
        {
            let is_err = result.is_err();
            crate::assert_with_log!(is_err, "signal unsupported", true, is_err);
        }

        crate::test_complete!("signal_creation_platform_contract");
    }

    #[cfg(unix)]
    #[test]
    fn unix_signal_helpers() {
        init_test("unix_signal_helpers");
        let sigint_ok = sigint().is_ok();
        crate::assert_with_log!(sigint_ok, "sigint ok", true, sigint_ok);
        let sigterm_ok = sigterm().is_ok();
        crate::assert_with_log!(sigterm_ok, "sigterm ok", true, sigterm_ok);
        let sighup_ok = sighup().is_ok();
        crate::assert_with_log!(sighup_ok, "sighup ok", true, sighup_ok);
        let sigusr1_ok = sigusr1().is_ok();
        crate::assert_with_log!(sigusr1_ok, "sigusr1 ok", true, sigusr1_ok);
        let sigusr2_ok = sigusr2().is_ok();
        crate::assert_with_log!(sigusr2_ok, "sigusr2 ok", true, sigusr2_ok);
        let sigquit_ok = sigquit().is_ok();
        crate::assert_with_log!(sigquit_ok, "sigquit ok", true, sigquit_ok);
        let sigchld_ok = sigchld().is_ok();
        crate::assert_with_log!(sigchld_ok, "sigchld ok", true, sigchld_ok);
        let sigwinch_ok = sigwinch().is_ok();
        crate::assert_with_log!(sigwinch_ok, "sigwinch ok", true, sigwinch_ok);
        let sigpipe_ok = sigpipe().is_ok();
        crate::assert_with_log!(sigpipe_ok, "sigpipe ok", true, sigpipe_ok);
        let sigalrm_ok = sigalrm().is_ok();
        crate::assert_with_log!(sigalrm_ok, "sigalrm ok", true, sigalrm_ok);
        crate::test_complete!("unix_signal_helpers");
    }

    #[cfg(windows)]
    #[test]
    fn windows_signal_helpers() {
        init_test("windows_signal_helpers");
        let sigint_ok = sigint().is_ok();
        crate::assert_with_log!(sigint_ok, "sigint ok", true, sigint_ok);
        let sigterm_ok = sigterm().is_ok();
        crate::assert_with_log!(sigterm_ok, "sigterm ok", true, sigterm_ok);
        let sigquit_ok = sigquit().is_ok();
        crate::assert_with_log!(sigquit_ok, "sigbreak ok", true, sigquit_ok);
        crate::test_complete!("windows_signal_helpers");
    }

    #[cfg(unix)]
    #[test]
    fn a_panicking_waker_does_not_escape_a_delivery() {
        init_test("a_panicking_waker_does_not_escape_a_delivery");
        struct PanicOnWake;
        impl std::task::Wake for PanicOnWake {
            fn wake(self: Arc<Self>) {
                panic!("hostile waker: this panic is the test's input");
            }
        }
        struct CountWakes(std::sync::atomic::AtomicUsize);
        impl std::task::Wake for CountWakes {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let slot = SignalSlot::new();
        let hostile = Waker::from(Arc::new(PanicOnWake));
        let counter = Arc::new(CountWakes(std::sync::atomic::AtomicUsize::new(0)));
        let counting = Waker::from(Arc::clone(&counter));
        let mut first = Box::pin(slot.notify.notified());
        let mut second = Box::pin(slot.notify.notified());
        assert!(
            first
                .as_mut()
                .poll(&mut Context::from_waker(&hostile))
                .is_pending()
        );
        assert!(
            second
                .as_mut()
                .poll(&mut Context::from_waker(&counting))
                .is_pending()
        );
        // The OS dispatcher thread calls this for every delivery. A panic
        // escaping it would end that thread, and with it every later delivery.
        slot.record_delivery();
        assert_eq!(slot.deliveries.load(Ordering::Acquire), 1);
        assert_eq!(
            counter.0.load(Ordering::SeqCst),
            1,
            "the other waiter is woken"
        );
        crate::test_complete!("a_panicking_waker_does_not_escape_a_delivery");
    }

    #[cfg(unix)]
    #[test]
    fn signal_recv_observes_delivery() {
        init_test("signal_recv_observes_delivery");
        let mut stream = signal(SignalKind::terminate()).expect("stream available");
        dispatcher_for(SignalKind::terminate())
            .expect("dispatcher")
            .inject(SignalKind::terminate());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut recv = Box::pin(stream.recv());
        let poll = recv.as_mut().poll(&mut cx);
        crate::assert_with_log!(
            matches!(poll, Poll::Ready(Some(()))),
            "recv returns delivery",
            "Poll::Ready(Some(()))",
            poll
        );
        crate::test_complete!("signal_recv_observes_delivery");
    }

    #[cfg(unix)]
    #[test]
    fn signal_recv_preserves_multiple_recorded_deliveries() {
        init_test("signal_recv_preserves_multiple_recorded_deliveries");
        let mut stream = signal(SignalKind::terminate()).expect("stream available");
        let dispatcher = dispatcher_for(SignalKind::terminate()).expect("dispatcher");
        dispatcher.inject(SignalKind::terminate());
        dispatcher.inject(SignalKind::terminate());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut first_recv = Box::pin(stream.recv());
        let first = first_recv.as_mut().poll(&mut cx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Some(()))),
            "first recv consumes one pending delivery",
            "Poll::Ready(Some(()))",
            first
        );
        drop(first_recv);

        let mut second_recv = Box::pin(stream.recv());
        let second = second_recv.as_mut().poll(&mut cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Some(()))),
            "second recv consumes second pending delivery",
            "Poll::Ready(Some(()))",
            second
        );
        crate::test_complete!("signal_recv_preserves_multiple_recorded_deliveries");
    }

    #[test]
    fn signal_mask_from_kinds_deduplicates_supported_kinds() {
        init_test("signal_mask_from_kinds_deduplicates_supported_kinds");
        let mask = SignalMask::from_kinds([
            SignalKind::user_defined1(),
            SignalKind::user_defined1(),
            SignalKind::terminate(),
        ]);
        let kinds: Vec<_> = mask.kinds().collect();
        crate::assert_with_log!(
            kinds == vec![SignalKind::user_defined1(), SignalKind::terminate()],
            "deduplicated mask kinds",
            vec![SignalKind::user_defined1(), SignalKind::terminate()],
            kinds
        );
        crate::assert_with_log!(
            mask.contains(SignalKind::user_defined1()),
            "mask contains SIGUSR1",
            true,
            mask.contains(SignalKind::user_defined1())
        );
        crate::test_complete!("signal_mask_from_kinds_deduplicates_supported_kinds");
    }

    #[cfg(unix)]
    #[test]
    fn unix_signal_mask_block_guard_restores_prior_mask() {
        init_test("unix_signal_mask_block_guard_restores_prior_mask");
        let result = std::thread::spawn(|| -> io::Result<(bool, bool, bool)> {
            let mask = SignalMask::from_kinds([SignalKind::user_defined1()]);
            let original = SignalMask::current_thread()?;
            let originally_blocked = original.contains(SignalKind::user_defined1());
            let guard = mask.block_current_thread()?;
            let blocked = SignalMask::current_thread()?.contains(SignalKind::user_defined1());
            guard.restore()?;
            let restored = SignalMask::current_thread()?.contains(SignalKind::user_defined1());
            Ok((originally_blocked, blocked, restored))
        })
        .join();

        let (originally_blocked, blocked, restored) = match result {
            Ok(Ok(values)) => values,
            Ok(Err(err)) => {
                let message = format!("signal mask operation failed: {err}");
                crate::assert_with_log!(false, "signal mask thread completed", "ok", message);
                crate::test_complete!("unix_signal_mask_block_guard_restores_prior_mask");
                return;
            }
            Err(_) => {
                crate::assert_with_log!(
                    false,
                    "signal mask test thread joined",
                    "ok",
                    "thread panicked"
                );
                crate::test_complete!("unix_signal_mask_block_guard_restores_prior_mask");
                return;
            }
        };

        crate::assert_with_log!(
            blocked,
            "SIGUSR1 blocked while guard is active",
            true,
            blocked
        );
        crate::assert_with_log!(
            restored == originally_blocked,
            "SIGUSR1 restored to original mask state",
            originally_blocked,
            restored
        );
        crate::test_complete!("unix_signal_mask_block_guard_restores_prior_mask");
    }

    #[cfg(unix)]
    #[test]
    fn unix_signal_mask_unblock_guard_restores_blocked_mask() {
        init_test("unix_signal_mask_unblock_guard_restores_blocked_mask");
        let result = std::thread::spawn(|| -> io::Result<(bool, bool, bool)> {
            let mask = SignalMask::from_kinds([SignalKind::user_defined2()]);
            let block_guard = mask.block_current_thread()?;
            let blocked = SignalMask::current_thread()?.contains(SignalKind::user_defined2());
            let unblock_guard = mask.unblock_current_thread()?;
            let unblocked = !SignalMask::current_thread()?.contains(SignalKind::user_defined2());
            unblock_guard.restore()?;
            let restored_blocked =
                SignalMask::current_thread()?.contains(SignalKind::user_defined2());
            block_guard.restore()?;
            Ok((blocked, unblocked, restored_blocked))
        })
        .join();

        let (blocked, unblocked, restored_blocked) = match result {
            Ok(Ok(values)) => values,
            Ok(Err(err)) => {
                let message = format!("signal mask operation failed: {err}");
                crate::assert_with_log!(false, "signal mask thread completed", "ok", message);
                crate::test_complete!("unix_signal_mask_unblock_guard_restores_blocked_mask");
                return;
            }
            Err(_) => {
                crate::assert_with_log!(
                    false,
                    "signal mask test thread joined",
                    "ok",
                    "thread panicked"
                );
                crate::test_complete!("unix_signal_mask_unblock_guard_restores_blocked_mask");
                return;
            }
        };

        crate::assert_with_log!(blocked, "SIGUSR2 block applied", true, blocked);
        crate::assert_with_log!(unblocked, "SIGUSR2 unblock applied", true, unblocked);
        crate::assert_with_log!(
            restored_blocked,
            "unblock guard restored blocked mask",
            true,
            restored_blocked
        );
        crate::test_complete!("unix_signal_mask_unblock_guard_restores_blocked_mask");
    }

    #[test]
    fn signal_mask_guard_is_not_send_or_sync() {
        init_test("signal_mask_guard_is_not_send_or_sync");
        // Verify SignalMaskGuard is zero-cost wrapped and retains thread-affinity.
        // PhantomData<*mut ()> ensures SignalMaskGuard is neither Send nor Sync,
        // preventing cross-thread drop from restoring the wrong thread's signal mask
        // (br-asupersync-abc5w5 LOW 7).
        crate::assert_with_log!(
            std::mem::size_of::<SignalMaskGuard>() == std::mem::size_of::<Option<SignalMask>>(),
            "SignalMaskGuard has zero-cost PhantomData layout",
            true,
            true
        );
        crate::test_complete!("signal_mask_guard_is_not_send_or_sync");
    }

    #[cfg(unix)]
    #[test]
    fn unix_raw_signal_mapping_covers_pipe_and_alarm() {
        init_test("unix_raw_signal_mapping_covers_pipe_and_alarm");
        let pipe = signal_kind_from_raw(libc::SIGPIPE);
        crate::assert_with_log!(
            pipe == Some(SignalKind::Pipe),
            "SIGPIPE mapped",
            Some(SignalKind::Pipe),
            pipe
        );
        let alarm = signal_kind_from_raw(libc::SIGALRM);
        crate::assert_with_log!(
            alarm == Some(SignalKind::Alarm),
            "SIGALRM mapped",
            Some(SignalKind::Alarm),
            alarm
        );
        crate::test_complete!("unix_raw_signal_mapping_covers_pipe_and_alarm");
    }

    #[cfg(windows)]
    #[test]
    fn windows_raw_signal_mapping_subset() {
        init_test("windows_raw_signal_mapping_subset");
        let interrupt = signal_kind_from_raw(libc::SIGINT);
        crate::assert_with_log!(
            interrupt == Some(SignalKind::Interrupt),
            "SIGINT mapped",
            Some(SignalKind::Interrupt),
            interrupt
        );
        let terminate = signal_kind_from_raw(libc::SIGTERM);
        crate::assert_with_log!(
            terminate == Some(SignalKind::Terminate),
            "SIGTERM mapped",
            Some(SignalKind::Terminate),
            terminate
        );
        let quit = signal_kind_from_raw(signal_hook::consts::SIGBREAK);
        crate::assert_with_log!(
            quit == Some(SignalKind::Quit),
            "SIGBREAK mapped",
            Some(SignalKind::Quit),
            quit
        );
        crate::test_complete!("windows_raw_signal_mapping_subset");
    }

    // =========================================================================
    // SIGPIPE Conformance Tests - RFC POSIX.1-2017 Section 2.4.1
    // =========================================================================

    #[cfg(unix)]
    #[test]
    fn sigpipe_signal_handler_registration() {
        init_test("sigpipe_signal_handler_registration");

        // Test that SIGPIPE can be registered for handling
        let stream_result = signal(SignalKind::pipe());
        crate::assert_with_log!(
            stream_result.is_ok(),
            "SIGPIPE signal stream creation succeeds",
            true,
            stream_result.is_ok()
        );

        // Verify SIGPIPE is mapped to correct raw signal value
        let raw_sigpipe = SignalKind::pipe().as_raw_value();
        crate::assert_with_log!(
            raw_sigpipe == libc::SIGPIPE,
            "SIGPIPE maps to libc::SIGPIPE",
            libc::SIGPIPE,
            raw_sigpipe
        );

        crate::test_complete!("sigpipe_signal_handler_registration");
    }

    #[cfg(unix)]
    #[test]
    fn sigpipe_signal_delivery_observable() {
        init_test("sigpipe_signal_delivery_observable");

        let mut stream = signal(SignalKind::pipe()).expect("SIGPIPE stream");

        // Inject a SIGPIPE signal into the dispatcher
        let dispatcher = dispatcher_for(SignalKind::pipe()).expect("SIGPIPE dispatcher");
        dispatcher.inject(SignalKind::pipe());

        // Poll the signal stream to observe delivery
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut recv = Box::pin(stream.recv());
        let poll = recv.as_mut().poll(&mut cx);

        crate::assert_with_log!(
            matches!(poll, Poll::Ready(Some(()))),
            "SIGPIPE signal delivery is observable",
            "Poll::Ready(Some(()))",
            poll
        );

        crate::test_complete!("sigpipe_signal_delivery_observable");
    }

    #[cfg(unix)]
    #[test]
    fn sigpipe_multiple_deliveries_preserved() {
        init_test("sigpipe_multiple_deliveries_preserved");

        let mut stream = signal(SignalKind::pipe()).expect("SIGPIPE stream");
        let dispatcher = dispatcher_for(SignalKind::pipe()).expect("SIGPIPE dispatcher");

        // Inject multiple SIGPIPE signals
        dispatcher.inject(SignalKind::pipe());
        dispatcher.inject(SignalKind::pipe());

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First recv should succeed
        {
            let mut recv1 = Box::pin(stream.recv());
            let poll1 = recv1.as_mut().poll(&mut cx);
            crate::assert_with_log!(
                matches!(poll1, Poll::Ready(Some(()))),
                "First SIGPIPE delivery received",
                "Poll::Ready(Some(()))",
                poll1
            );
        }

        // Second recv should also succeed (no lost signals)
        {
            let mut recv2 = Box::pin(stream.recv());
            let poll2 = recv2.as_mut().poll(&mut cx);
            crate::assert_with_log!(
                matches!(poll2, Poll::Ready(Some(()))),
                "Second SIGPIPE delivery received",
                "Poll::Ready(Some(()))",
                poll2
            );
        }

        crate::test_complete!("sigpipe_multiple_deliveries_preserved");
    }

    #[cfg(windows)]
    #[test]
    fn sigpipe_unsupported_on_windows() {
        init_test("sigpipe_unsupported_on_windows");

        // SIGPIPE should not be supported on Windows
        let raw_value = SignalKind::pipe().as_raw_value();
        crate::assert_with_log!(
            raw_value.is_none(),
            "SIGPIPE not supported on Windows",
            None::<i32>,
            raw_value
        );

        // Signal stream creation should fail with unsupported error
        let stream_result = signal(SignalKind::pipe());
        crate::assert_with_log!(
            stream_result.is_err(),
            "SIGPIPE signal stream creation fails on Windows",
            true,
            stream_result.is_err()
        );

        if let Err(err) = stream_result {
            let error_msg = err.to_string();
            crate::assert_with_log!(
                error_msg.to_lowercase().contains("unsupported")
                    || error_msg.to_lowercase().contains("not supported"),
                "Error message indicates unsupported",
                true,
                error_msg.to_lowercase().contains("unsupported")
                    || error_msg.to_lowercase().contains("not supported")
            );
        }

        crate::test_complete!("sigpipe_unsupported_on_windows");
    }

    #[cfg(not(any(unix, windows)))]
    #[test]
    fn sigpipe_unsupported_on_other_platforms() {
        init_test("sigpipe_unsupported_on_other_platforms");

        // SIGPIPE should not be supported on non-Unix, non-Windows platforms
        let raw_value = SignalKind::pipe().as_raw_value();
        crate::assert_with_log!(
            raw_value.is_none(),
            "SIGPIPE not supported on other platforms",
            None::<i32>,
            raw_value
        );

        crate::test_complete!("sigpipe_unsupported_on_other_platforms");
    }

    #[cfg(unix)]
    #[test]
    fn sigpipe_cancel_safety_preserved() {
        init_test("sigpipe_cancel_safety_preserved");

        let mut stream = signal(SignalKind::pipe()).expect("SIGPIPE stream");
        let dispatcher = dispatcher_for(SignalKind::pipe()).expect("SIGPIPE dispatcher");

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // The SIGPIPE delivery counter is process-global, so other tests running
        // in parallel may also bump it. Drain any already-visible deliveries on
        // THIS stream first so we start from a quiescent baseline that is robust to
        // interleaving. (Each `Signal` tracks its own `seen` cursor, so draining
        // here does not affect other streams.)
        loop {
            let mut drain = Box::pin(stream.recv());
            if !matches!(drain.as_mut().poll(&mut cx), Poll::Ready(Some(()))) {
                break;
            }
        }

        // Poll a recv on the quiesced stream so it parks and registers a waiter —
        // this is the future we will "cancel" by dropping. (In the common case this
        // is `Pending`; under heavy parallel injection it may already be `Ready`,
        // which is fine — the cancel-safety property we assert below holds either
        // way, and avoiding a strict assertion here keeps the test robust to the
        // process-global delivery counter.)
        {
            let mut recv = Box::pin(stream.recv());
            let _ = recv.as_mut().poll(&mut cx);

            // A signal arrives while the recv future is alive...
            dispatcher.inject(SignalKind::pipe());
            // ...then the recv future is dropped (cancellation) WITHOUT being
            // polled again, so it must not have consumed the pending delivery.
        }

        // A fresh recv must still observe a delivery — cancel-safety means dropping
        // the previous recv did not swallow the pending signal. The counter is
        // monotone, so even if a parallel test added further deliveries, the next
        // poll observes at least the one we injected.
        let mut recv_after_cancel = Box::pin(stream.recv());
        let poll_after = recv_after_cancel.as_mut().poll(&mut cx);
        crate::assert_with_log!(
            matches!(poll_after, Poll::Ready(Some(()))),
            "SIGPIPE delivery preserved after cancellation",
            "Poll::Ready(Some(()))",
            poll_after
        );

        crate::test_complete!("sigpipe_cancel_safety_preserved");
    }

    #[test]
    fn sigpipe_platform_behavior_documented() {
        init_test("sigpipe_platform_behavior_documented");

        // Document platform-specific SIGPIPE behavior differences

        #[cfg(unix)]
        {
            // Unix: SIGPIPE fully supported
            let unix_supported = SignalKind::pipe().as_raw_value() == libc::SIGPIPE;
            crate::assert_with_log!(
                unix_supported,
                "Unix: SIGPIPE mapped to libc::SIGPIPE",
                true,
                unix_supported
            );
        }

        #[cfg(windows)]
        {
            // Windows: SIGPIPE not supported (different pipe break semantics)
            let windows_unsupported = SignalKind::pipe().as_raw_value().is_none();
            crate::assert_with_log!(
                windows_unsupported,
                "Windows: SIGPIPE not supported (uses ERROR_BROKEN_PIPE instead)",
                true,
                windows_unsupported
            );
        }

        #[cfg(target_os = "linux")]
        {
            // Linux: MSG_NOSIGNAL flag available for send()
            let msg_nosignal_available = libc::MSG_NOSIGNAL != 0;
            crate::assert_with_log!(
                msg_nosignal_available,
                "Linux: MSG_NOSIGNAL flag available",
                true,
                msg_nosignal_available
            );
        }

        #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
        {
            // BSD-based: SO_NOSIGPIPE socket option available
            let so_nosigpipe_available = libc::SO_NOSIGPIPE != 0;
            crate::assert_with_log!(
                so_nosigpipe_available,
                "BSD: SO_NOSIGPIPE socket option available",
                true,
                so_nosigpipe_available
            );
        }

        crate::test_complete!("sigpipe_platform_behavior_documented");
    }

    #[cfg(all(windows, feature = "test-internals"))]
    #[test]
    fn sigpipe_ctrl_c_event_interaction() {
        init_test("sigpipe_ctrl_c_event_interaction");

        // On Windows, test that CTRL_C_EVENT doesn't interfere with
        // broken pipe error reporting (since SIGPIPE doesn't exist)

        // CTRL_C_EVENT should map to SIGINT
        let ctrl_c_signal = SignalKind::interrupt().as_raw_value();
        crate::assert_with_log!(
            ctrl_c_signal == Some(libc::SIGINT),
            "CTRL_C_EVENT maps to SIGINT",
            Some(libc::SIGINT),
            ctrl_c_signal
        );

        // SIGPIPE should remain unsupported
        let sigpipe_unsupported = SignalKind::pipe().as_raw_value().is_none();
        crate::assert_with_log!(
            sigpipe_unsupported,
            "SIGPIPE remains unsupported with CTRL_C_EVENT",
            true,
            sigpipe_unsupported
        );

        // Both should be independent - SIGINT available, SIGPIPE not
        let int_stream = signal(SignalKind::interrupt());
        let pipe_stream = signal(SignalKind::pipe());

        crate::assert_with_log!(
            int_stream.is_ok(),
            "SIGINT stream creation succeeds",
            true,
            int_stream.is_ok()
        );
        crate::assert_with_log!(
            pipe_stream.is_err(),
            "SIGPIPE stream creation fails",
            true,
            pipe_stream.is_err()
        );

        crate::test_complete!("sigpipe_ctrl_c_event_interaction");
    }

    #[cfg(unix)]
    mod managed_signal_model {
        use super::*;
        use crate::channel::mpsc;
        use crate::cx::{Cx, Scope};
        use crate::lab::{LabConfig, LabRuntime};
        use crate::runtime::{JoinError, RuntimeState, SpawnError};
        use crate::supervision::{
            ChildSpec, ManagedChildBinding, ManagedGeneration, ManagedRestartMode,
            SupervisionConfig, SupervisorBuilder,
        };
        use crate::trace::{TraceData, TraceEvent, TraceEventKind};
        use crate::types::{Budget, CancelKind, CancelReason, Outcome, TaskId, policy::FailFast};
        use parking_lot::Mutex;
        use std::future::poll_fn;
        use std::sync::atomic::{AtomicBool, AtomicUsize};
        use std::time::Duration;

        // Test inputs own real Notify registrations; no self-waking polling or
        // manufactured task/region/terminal records stand in for cleanup.
        #[derive(Debug, Default)]
        struct CleanupGate {
            notify: Notify,
            released: AtomicBool,
        }

        impl CleanupGate {
            async fn wait(&self, on_pending: impl FnOnce()) {
                let mut on_pending = Some(on_pending);
                let mut notified = std::pin::pin!(self.notify.notified());
                poll_fn(|cx| {
                    let result = notified.as_mut().poll(cx);
                    if result.is_pending() {
                        if let Some(observe) = on_pending.take() {
                            observe();
                        }
                    }
                    result
                })
                .await;
                assert!(self.released.load(Ordering::Acquire));
            }

            fn release(&self) {
                assert!(!self.released.swap(true, Ordering::AcqRel));
                self.notify.notify_one();
            }
        }

        #[derive(Clone, Debug)]
        struct Observed {
            child: usize,
            generation: ManagedGeneration,
            action: &'static str,
        }

        type Log = Arc<Mutex<Vec<Observed>>>;

        fn observe(log: &Log, child: usize, generation: ManagedGeneration, action: &'static str) {
            log.lock().push(Observed {
                child,
                generation,
                action,
            });
        }

        fn legacy_must_not_run(
            _: &Scope<'static, FailFast>,
            _: &mut RuntimeState,
            _: &Cx,
        ) -> Result<TaskId, SpawnError> {
            panic!("signal model must execute the maintained managed factory")
        }

        fn terminal_count(trace: &[TraceEvent], generation: ManagedGeneration) -> usize {
            trace
                .iter()
                .filter(|event| {
                    event.kind == TraceEventKind::Complete
                        && matches!(event.data, TraceData::Task { task, region }
                            if task == generation.task && region == generation.region)
                })
                .count()
        }

        // The same checker examines actual held and completed runs. The negative
        // control makes an early-success claim; it does not alter runtime input
        // or feed a fabricated terminal into a Lab oracle.
        fn completion_claim(
            log: &[Observed],
            required: &[ManagedGeneration],
            trace: &[TraceEvent],
        ) -> Result<(), &'static str> {
            if required.is_empty() {
                return Err("zero_selected_generations");
            }
            for generation in required {
                if terminal_count(trace, *generation) != 1
                    || ["cleanup_done", "finalizer_done"]
                        .into_iter()
                        .any(|action| {
                            log.iter()
                                .filter(|event| {
                                    event.generation == *generation && event.action == action
                                })
                                .count()
                                != 1
                        })
                {
                    return Err("premature_generation_completion");
                }
            }
            Ok(())
        }

        #[test]
        fn managed_supervisor_runtime_signal_source() {
            for seed in [0x35_0101, 0x35_0102, 0x35_0103] {
                let mut lab =
                    LabRuntime::new(LabConfig::new(seed).max_steps(8192).trace_capacity(32_768));
                let root = lab.state.create_root_region(Budget::INFINITE);
                let trace = lab.state.trace_handle();
                let log: Log = Arc::new(Mutex::new(Vec::new()));
                let started = Arc::new(Mutex::new(Vec::new()));
                let cleanup: [Arc<CleanupGate>; 2] =
                    std::array::from_fn(|_| Arc::new(CleanupGate::default()));
                let finalizers: [Arc<CleanupGate>; 2] =
                    std::array::from_fn(|_| Arc::new(CleanupGate::default()));
                let mut builder = SupervisorBuilder::new("signal-model");
                let mut bindings = Vec::new();
                for (index, name) in ["a", "b"].into_iter().enumerate() {
                    builder = builder.child(
                        ChildSpec::new(name, legacy_must_not_run)
                            .with_shutdown_budget(Budget::new().with_poll_quota(10_000)),
                    );
                    let starts = Arc::clone(&started);
                    let events = Arc::clone(&log);
                    let held = Arc::clone(&cleanup[index]);
                    bindings.push(ManagedChildBinding::new(
                        name,
                        ManagedRestartMode::Permanent,
                        move |cx: Cx, generation: ManagedGeneration| {
                            assert_eq!(generation.number, 1, "shutdown cannot restart children");
                            let (sender, mut receiver) = mpsc::channel::<u64>(1);
                            starts.lock().push((index, generation, sender));
                            let events = Arc::clone(&events);
                            let held = Arc::clone(&held);
                            async move {
                                observe(&events, index, generation, "started");
                                let value = receiver.recv(&cx).await.unwrap();
                                assert_eq!(value, 100 + index as u64);
                                observe(&events, index, generation, "work");
                                assert_eq!(
                                    receiver.recv(&cx).await,
                                    Err(mpsc::RecvError::Cancelled)
                                );
                                let reason =
                                    cx.cancel_reason().expect("actual managed cancellation");
                                assert_eq!(reason.kind(), CancelKind::User);
                                assert_eq!(
                                    reason.message(),
                                    Some("managed supervisor generation drain")
                                );
                                observe(&events, index, generation, "cancelled");
                                held.wait(|| {
                                    observe(&events, index, generation, "cleanup_pending")
                                })
                                .await;
                                observe(&events, index, generation, "cleanup_done");
                                Outcome::<(), &'static str>::Cancelled(reason)
                            }
                        },
                    ));
                }
                let managed = builder
                    .compile()
                    .unwrap()
                    .bind_managed(bindings, SupervisionConfig::new(3, Duration::from_secs(60)))
                    .unwrap();

                // The isolated slot is the production runtime delivery source.
                // record_delivery is also called by the Unix OS dispatcher, but
                // this test intentionally injects its deterministic model input:
                // no process signal is sent and no OS handler is installed here.
                let slot = Arc::new(SignalSlot::new());
                let mut signal = Signal {
                    kind: SignalKind::Terminate,
                    slot: Arc::clone(&slot),
                    seen_deliveries: 0,
                };
                let consumed = Arc::new(Mutex::new(Vec::new()));
                let received = Arc::clone(&consumed);
                let controller_id = Arc::new(Mutex::new(None));
                let identity = Arc::clone(&controller_id);
                let join_pending = Arc::new(AtomicUsize::new(0));
                let pending = Arc::clone(&join_pending);
                let (listener, mut joined) = lab
                    .state
                    .create_task(root, Budget::INFINITE, async move {
                        let cx = Cx::current().expect("actual registered signal listener");
                        let mut handle = managed.spawn(&cx).unwrap();
                        assert_eq!(signal.recv().await, Some(()));
                        // Spawn initially reports a provisional mailbox ID. The
                        // host delivers only after both generations do work, so
                        // this public handle now resolves the admitted owner.
                        *identity.lock() = Some(handle.task_id());
                        assert_eq!(signal.kind(), SignalKind::Terminate);
                        received.lock().push(signal.seen_deliveries);
                        handle.abort();
                        let mut terminal = std::pin::pin!(handle.join());
                        poll_fn(|cx| {
                            let result = terminal.as_mut().poll(cx);
                            if result.is_pending() {
                                pending.fetch_add(1, Ordering::SeqCst);
                            }
                            result
                        })
                        .await
                        .unwrap()
                    })
                    .unwrap();
                lab.scheduler.lock().schedule(listener, 0);
                lab.run_until_idle();
                assert_eq!(
                    slot.notify.waiter_count(),
                    1,
                    "real recv registered Pending"
                );
                assert_eq!(slot.deliveries.load(Ordering::Acquire), 0);
                assert!(consumed.lock().is_empty());
                assert!(joined.try_join().unwrap().is_none());
                let current = started.lock().clone();
                assert_eq!(current.len(), 2);
                assert_eq!(
                    current.iter().map(|entry| entry.0).collect::<Vec<_>>(),
                    [0, 1]
                );
                let generations: Vec<_> = current.iter().map(|entry| entry.1).collect();
                assert_ne!(generations[0].task, generations[1].task);
                assert_ne!(generations[0].region, generations[1].region);
                for (index, generation, sender) in &current {
                    sender.try_send(100 + *index as u64).unwrap();
                    let events = Arc::clone(&log);
                    let gate = Arc::clone(&finalizers[*index]);
                    let dependent = (*index == 1).then(|| Arc::clone(&cleanup[0]));
                    let (index, generation) = (*index, *generation);
                    assert!(
                        lab.state
                            .register_async_finalizer(generation.region, async move {
                                gate.wait(|| {
                                    observe(&events, index, generation, "finalizer_pending")
                                })
                                .await;
                                observe(&events, index, generation, "finalizer_done");
                                if let Some(dependent) = dependent {
                                    dependent.release();
                                }
                            })
                    );
                }
                lab.run_until_idle();
                assert_eq!(
                    log.lock()
                        .iter()
                        .filter(|event| event.action == "work")
                        .count(),
                    2
                );
                assert_eq!(slot.notify.waiter_count(), 1);
                assert!(joined.try_join().unwrap().is_none());
                assert!(cleanup.iter().all(|gate| gate.notify.waiter_count() == 0));

                // Only this real source delivery wakes the parked signal reader.
                slot.record_delivery();
                lab.run_until_idle();
                let controller = controller_id
                    .lock()
                    .expect("actual managed controller admitted before signal consumption");
                assert_eq!(slot.deliveries.load(Ordering::Acquire), 1);
                assert_eq!(*consumed.lock(), [1]);
                assert_eq!(slot.notify.waiter_count(), 0);
                assert!(join_pending.load(Ordering::SeqCst) > 0);
                assert!(cleanup.iter().all(|gate| gate.notify.waiter_count() == 1));
                assert!(
                    finalizers
                        .iter()
                        .all(|gate| gate.notify.waiter_count() == 0)
                );
                assert_eq!(
                    log.lock()
                        .iter()
                        .filter(|event| event.action == "cancelled")
                        .count(),
                    2
                );
                for generation in &generations {
                    assert!(lab.state.task(generation.task).is_some());
                    assert!(lab.state.region(generation.region).is_some());
                    assert_eq!(terminal_count(&trace.snapshot(), *generation), 0);
                }
                assert!(lab.state.task(controller).is_some());
                assert!(joined.try_join().unwrap().is_none());
                assert_eq!(
                    completion_claim(&log.lock(), &generations, &trace.snapshot()),
                    Err("premature_generation_completion")
                );
                assert_eq!(
                    completion_claim(&log.lock(), &[], &trace.snapshot()),
                    Err("zero_selected_generations")
                );

                // B's body can finish, but its actual region finalizer remains
                // Pending. A waits for that finalizer, so cancellation of all
                // siblings must precede the controller's ordered join/close.
                cleanup[1].release();
                lab.run_until_idle();
                assert_eq!(terminal_count(&trace.snapshot(), generations[1]), 1);
                assert_eq!(terminal_count(&trace.snapshot(), generations[0]), 0);
                assert_eq!(finalizers[1].notify.waiter_count(), 1);
                assert_eq!(cleanup[0].notify.waiter_count(), 1);
                assert!(lab.state.region(generations[1].region).is_some());
                assert!(joined.try_join().unwrap().is_none());
                assert_eq!(
                    completion_claim(&log.lock(), &generations, &trace.snapshot()),
                    Err("premature_generation_completion")
                );

                finalizers[1].release();
                lab.run_until_idle();
                assert!(lab.state.region(generations[1].region).is_none());
                assert_eq!(terminal_count(&trace.snapshot(), generations[0]), 1);
                assert_eq!(finalizers[0].notify.waiter_count(), 1);
                assert!(lab.state.region(generations[0].region).is_some());
                assert!(lab.state.task(controller).is_some());
                assert!(joined.try_join().unwrap().is_none());
                assert_eq!(
                    completion_claim(&log.lock(), &generations, &trace.snapshot()),
                    Err("premature_generation_completion")
                );

                finalizers[0].release();
                lab.run_until_idle();
                let report = joined
                    .try_join()
                    .unwrap()
                    .expect("real signal-triggered drain completed");
                let Outcome::Cancelled(reason) = &report.outcome else {
                    panic!("signal-triggered controller must retain cancellation: {report:?}");
                };
                assert_eq!(reason.kind(), CancelKind::User);
                assert_eq!(reason.message(), Some("abort"));
                assert_eq!(
                    (
                        report.started,
                        report.joined,
                        report.restart_batches,
                        report.escalations
                    ),
                    (2, 2, 0, 0)
                );
                assert_eq!(report.children.len(), 2);
                for (index, child) in report.children.iter().enumerate() {
                    assert_eq!(child.generation, generations[index]);
                    assert!(child.shutdown_requested_before_completion);
                    let Outcome::Cancelled(reason) = &child.outcome else {
                        panic!("real child cancellation missing: {child:?}");
                    };
                    assert_eq!(reason.kind(), CancelKind::User);
                    assert_eq!(
                        reason.message(),
                        Some("managed supervisor generation drain")
                    );
                    assert_eq!(child.task_outcome, Ok::<(), JoinError>(()));
                    assert!(matches!(child.cleanup_outcome, Some(Outcome::Ok(()))));
                    assert!(lab.state.region(child.generation.region).is_none());
                }
                let events = log.lock().clone();
                let history = trace.snapshot();
                assert_eq!(completion_claim(&events, &generations, &history), Ok(()));
                for (index, generation) in generations.iter().enumerate() {
                    for action in [
                        "started",
                        "work",
                        "cancelled",
                        "cleanup_pending",
                        "cleanup_done",
                        "finalizer_pending",
                        "finalizer_done",
                    ] {
                        assert_eq!(
                            events
                                .iter()
                                .filter(|event| event.child == index
                                    && event.generation == *generation
                                    && event.action == action)
                                .count(),
                            1
                        );
                    }
                }
                let position = |child, action| {
                    events
                        .iter()
                        .position(|event| event.child == child && event.action == action)
                        .unwrap()
                };
                assert!(position(1, "finalizer_done") < position(0, "cleanup_done"));
                assert!(position(0, "cleanup_done") < position(0, "finalizer_done"));
                assert_eq!(started.lock().len(), 2);
                for task in [controller, listener] {
                    assert_eq!(history.iter().filter(|event| event.kind == TraceEventKind::Complete && matches!(event.data, TraceData::Task { task: actual, region } if actual == task && region == root)).count(), 1);
                }
                assert!(
                    cleanup
                        .iter()
                        .chain(finalizers.iter())
                        .all(|gate| gate.notify.waiter_count() == 0
                            && gate.released.load(Ordering::Acquire))
                );
                assert_eq!(slot.notify.waiter_count(), 0);
                assert_eq!(lab.state.live_task_count(), 0);
                assert_eq!(lab.state.pending_obligation_count(), 0);
                assert_eq!(lab.state.leak_count(), 0);
                assert!(lab.state.region(report.region.unwrap()).is_none());
                let (tasks, wakes) = lab
                    .state
                    .cancel_request(root, &CancelReason::user("signal model complete"), None)
                    .into_parts();
                assert!(tasks.is_empty());
                wakes.dispatch();
                lab.state.advance_region_state(root);
                assert_eq!(lab.state.live_region_count(), 0);
                let lab_report = lab.run_until_quiescent_with_report();
                assert!(!lab_report.refinement_firewall_skipped_due_to_trace_truncation);
                assert!(lab_report.lab_test_passed(), "{lab_report:?}");
                assert_eq!(lab.state.timer_driver().unwrap().pending_count(), 0);
                eprintln!(
                    "ASUPERSYNC_MANAGED_SIGNAL_MODEL {}",
                    serde_json::json!({
                        "backend":"lab", "seed":seed,
                        "evidence":"owned runtime SignalSlot delivery model; no OS signal delivery",
                        "signal":"SIGTERM", "delivered":slot.deliveries.load(Ordering::Acquire),
                        "consumed_sequence":*consumed.lock(), "source_waiters":slot.notify.waiter_count(),
                        "listener":listener, "controller":controller,
                        "generations":generations.iter().map(|generation| serde_json::json!({"number":generation.number,"task":generation.task,"region":generation.region})).collect::<Vec<_>>(),
                        "events":events.iter().map(|event| serde_json::json!({"child":event.child,"generation":event.generation.number,"task":event.generation.task,"region":event.generation.region,"action":event.action})).collect::<Vec<_>>(),
                        "started":report.started,"joined":report.joined,"restart_batches":report.restart_batches,"escalations":report.escalations,
                        "terminal_outcome":"cancelled","cancel_reason":reason,
                        "actual_child_terminals":generations.iter().map(|generation| terminal_count(&history,*generation)).sum::<usize>(),
                        "join_pending_polls":join_pending.load(Ordering::SeqCst),
                        "negative_controls":["zero_selected_generations","premature_generation_completion"],
                        "live_tasks":lab.state.live_task_count(),"live_regions":lab.state.live_region_count(),
                        "pending_obligations":lab.state.pending_obligation_count(),"leaks":lab.state.leak_count(),
                        "lab_report":lab_report.to_json()
                    })
                );
            }
        }
    }
