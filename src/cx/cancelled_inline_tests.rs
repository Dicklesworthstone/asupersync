    use super::*;
    use crate::types::CancelKind;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::Wake;

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counter() -> (Arc<WakeCount>, Waker) {
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(count.clone());
        (count, waker)
    }

    fn registrations<Caps>(cx: &Cx<Caps>) -> usize {
        cx.inner.read().cancel_waker_registrations.len()
    }

    #[test]
    fn construction_is_lazy_and_pre_cancelled_poll_does_not_register() {
        let cx = Cx::for_testing();
        let mut wait = Box::pin(cx.cancelled());
        assert_eq!(registrations(&cx), 0);
        cx.cancel_fast(CancelKind::User);
        assert!(
            wait.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
        assert_eq!(registrations(&cx), 0);
        assert!(!cx.inner.read().cancel_acknowledged);
    }

    #[test]
    fn parked_observer_is_woken_then_unregisters_on_completion() {
        let cx = Cx::for_testing();
        let (count, waker) = counter();
        let mut task = Context::from_waker(&waker);
        let mut wait = Box::pin(cx.cancelled());
        assert!(wait.as_mut().poll(&mut task).is_pending());
        assert_eq!(registrations(&cx), 1);
        cx.cancel_fast(CancelKind::User);
        // Verify notification before any manual repoll can hide a lost wake.
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert!(wait.as_mut().poll(&mut task).is_ready());
        assert_eq!(registrations(&cx), 0);
        assert!(!cx.inner.read().cancel_acknowledged);
    }

    #[test]
    fn every_public_request_publisher_wakes_an_observer() {
        for publisher in 0..4 {
            let cx = Cx::for_testing();
            let (count, waker) = counter();
            let mut task = Context::from_waker(&waker);
            let mut wait = Box::pin(cx.cancelled());
            assert!(wait.as_mut().poll(&mut task).is_pending());
            match publisher {
                0 => cx.cancel_fast(CancelKind::User),
                1 => cx.cancel_with(CancelKind::User, Some("observer test")),
                2 => cx.set_cancel_requested(true),
                _ => cx.set_cancel_reason(crate::types::CancelReason::new(CancelKind::User)),
            }
            assert!(count.0.load(Ordering::SeqCst) > 0);
            assert!(wait.as_mut().poll(&mut task).is_ready());
            assert_eq!(registrations(&cx), 0);
        }
    }

    #[test]
    fn dropping_one_same_waker_observer_preserves_the_other_owner() {
        let cx = Cx::for_testing();
        let (count, waker) = counter();
        let mut task = Context::from_waker(&waker);
        let mut first = Box::pin(cx.cancelled());
        let mut second = Box::pin(cx.cancelled());
        assert!(first.as_mut().poll(&mut task).is_pending());
        assert!(second.as_mut().poll(&mut task).is_pending());
        assert_eq!(registrations(&cx), 2);
        drop(first);
        assert_eq!(registrations(&cx), 1);
        cx.cancel_fast(CancelKind::User);
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert!(second.as_mut().poll(&mut task).is_ready());
        assert_eq!(registrations(&cx), 0);
    }

    #[test]
    fn unchanged_repolls_reuse_one_owned_registration() {
        let cx = Cx::for_testing();
        let (_, waker) = counter();
        let mut task = Context::from_waker(&waker);
        let mut wait = Box::pin(cx.cancelled());
        assert!(wait.as_mut().poll(&mut task).is_pending());
        let token = wait.registration.as_ref().unwrap().token;
        for _ in 0..64 {
            assert!(wait.as_mut().poll(&mut task).is_pending());
            assert_eq!(wait.registration.as_ref().unwrap().token, token);
            assert_eq!(registrations(&cx), 1);
        }
        drop(wait);
        assert_eq!(registrations(&cx), 0);
    }

    #[test]
    fn task_migration_refreshes_the_waker_without_leaking_entries() {
        let cx = Cx::for_testing();
        let (old, old_waker) = counter();
        let (new, new_waker) = counter();
        let mut wait = Box::pin(cx.cancelled());
        assert!(
            wait.as_mut()
                .poll(&mut Context::from_waker(&old_waker))
                .is_pending()
        );
        assert!(
            wait.as_mut()
                .poll(&mut Context::from_waker(&new_waker))
                .is_pending()
        );
        assert_eq!(registrations(&cx), 1);
        cx.cancel_fast(CancelKind::User);
        assert_eq!(old.0.load(Ordering::SeqCst), 0);
        assert!(new.0.load(Ordering::SeqCst) > 0);
    }

    #[test]
    fn drop_retires_task_payload_outside_the_context_lock() {
        struct ReenterDrop {
            cx: Cx,
            retired_unlocked: Arc<AtomicBool>,
        }
        // The owned waker payload must run the reentrant destructor below;
        // Waker::noop() would remove the behavior this regression checks.
        #[allow(clippy::manual_noop_waker)]
        impl Wake for ReenterDrop {
            fn wake(self: Arc<Self>) {}
        }
        impl Drop for ReenterDrop {
            fn drop(&mut self) {
                self.retired_unlocked
                    .store(self.cx.inner.try_write().is_some(), Ordering::SeqCst);
            }
        }
        let cx = Cx::for_testing();
        let retired_unlocked = Arc::new(AtomicBool::new(false));
        let waker = Waker::from(Arc::new(ReenterDrop {
            cx: cx.clone(),
            retired_unlocked: retired_unlocked.clone(),
        }));
        let mut wait = Box::pin(cx.cancelled());
        assert!(
            wait.as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        drop(waker);
        drop(wait);
        assert_eq!(registrations(&cx), 0);
        assert!(retired_unlocked.load(Ordering::SeqCst));
    }

    #[test]
    fn mask_agnostic_observation_does_not_acknowledge_cancellation() {
        let cx = Cx::for_testing();
        let mut wait = Box::pin(cx.cancelled());
        cx.cancel_fast(CancelKind::User);
        cx.masked(|| {
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
            );
            assert!(cx.checkpoint().is_ok());
            assert!(!cx.inner.read().cancel_acknowledged);
        });
        assert!(!cx.inner.read().cancel_acknowledged);
        assert!(cx.checkpoint().is_err());
        assert!(cx.inner.read().cancel_acknowledged);
    }

    #[test]
    fn completed_observer_stays_ready_after_test_only_request_reset() {
        let cx = Cx::for_testing();
        let mut wait = Box::pin(cx.cancelled());
        let mut task = Context::from_waker(Waker::noop());
        cx.cancel_fast(CancelKind::User);
        assert!(wait.as_mut().poll(&mut task).is_ready());
        cx.set_cancel_requested(false);
        assert!(wait.as_mut().poll(&mut task).is_ready());
        assert_eq!(registrations(&cx), 0);
    }

    #[test]
    fn detached_no_capability_context_supports_wake_driven_observation() {
        let cx = Cx::detached_cancel_context();
        let (count, waker) = counter();
        let mut wait = Box::pin(cx.cancelled());
        let mut task = Context::from_waker(&waker);
        assert!(wait.as_mut().poll(&mut task).is_pending());
        cx.cancel_with(CancelKind::User, None);
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert!(wait.as_mut().poll(&mut task).is_ready());
        assert_eq!(registrations(&cx), 0);
    }

    #[test]
    fn cancellation_racing_first_registration_cannot_leave_an_unwoken_waiter() {
        for _ in 0..64 {
            let cx = Cx::for_testing();
            let (count, waker) = counter();
            let mut wait = Box::pin(cx.cancelled());
            let first_poll = std::thread::scope(|scope| {
                scope.spawn(|| cx.cancel_fast(CancelKind::User));
                wait.as_mut().poll(&mut Context::from_waker(&waker))
            });
            // The cancellation thread has joined. Either the first poll saw
            // its request or its owned registration must have been notified.
            if first_poll.is_pending() {
                assert!(count.0.load(Ordering::SeqCst) > 0);
            }
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_ready()
            );
            assert_eq!(registrations(&cx), 0);
        }
    }

    #[test]
    fn completed_context_cancelled_future_resolves_ready_if_already_cancelled() {
        let cx = Cx::for_testing();
        cx.cancel_fast(CancelKind::User);
        let retired = cx.inner.write().take_cancel_wakers();
        drop(retired);

        let mut wait = Box::pin(cx.cancelled());
        assert!(
            wait.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
        assert_eq!(registrations(&cx), 0);
    }

    #[test]
    fn completed_context_cancelled_future_returns_pending_when_uncancelled_and_does_not_register() {
        let cx = Cx::for_testing();
        let retired = cx.inner.write().take_cancel_wakers();
        drop(retired);

        let (count, waker) = counter();
        let mut task = Context::from_waker(&waker);
        let mut wait = Box::pin(cx.cancelled());

        // Polling on an uncancelled completed context returns Pending and does not leak a registration.
        assert!(wait.as_mut().poll(&mut task).is_pending());
        assert_eq!(registrations(&cx), 0);

        // Subsequent cancellation sets cancel_requested. Because the task finished and its registry
        // closed, the waker is not woken, but a subsequent poll observes the cancellation.
        cx.cancel_fast(CancelKind::User);
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        assert!(wait.as_mut().poll(&mut task).is_ready());
        assert_eq!(registrations(&cx), 0);
    }

    #[test]
    fn cancelled_observer_registered_before_completion_retires_on_finish_and_resolves_on_repoll() {
        let cx = Cx::for_testing();
        let (count, waker) = counter();
        let mut task = Context::from_waker(&waker);
        let mut wait = Box::pin(cx.cancelled());

        // Register observer before task completion.
        assert!(wait.as_mut().poll(&mut task).is_pending());
        assert_eq!(registrations(&cx), 1);

        // Task completion detaches and retires all cancel wakers without waking them.
        let retired = cx.inner.write().take_cancel_wakers();
        drop(retired);
        assert_eq!(registrations(&cx), 0);
        assert_eq!(count.0.load(Ordering::SeqCst), 0);

        // Late cancellation sets the flag on the context.
        cx.cancel_fast(CancelKind::User);
        assert_eq!(count.0.load(Ordering::SeqCst), 0);

        // Repolling observes the cancellation and completes.
        assert!(wait.as_mut().poll(&mut task).is_ready());
        assert_eq!(registrations(&cx), 0);
    }

    /// A checkpoint that observes its own budget cancellation defers the
    /// observers' wakes to the scheduler's reconciliation. A task that finishes
    /// first must still deliver them when completion retires its targets.
    #[test]
    fn completion_delivers_a_cancellation_its_observers_were_still_owed() {
        let cx = Cx::for_testing_with_budget(crate::types::Budget::new().with_poll_quota(0));
        let (count, waker) = counter();
        let mut task = Context::from_waker(&waker);
        let mut wait = Box::pin(cx.cancelled());
        assert!(wait.as_mut().poll(&mut task).is_pending());
        assert_eq!(registrations(&cx), 1);

        assert!(cx.checkpoint().is_err(), "an exhausted poll quota cancels");
        assert!(cx.inner.read().cancel_wakers_pending);
        assert_eq!(count.0.load(Ordering::SeqCst), 0, "the wake is deferred");

        let retired = cx.inner.write().take_cancel_wakers();
        assert_eq!(
            count.0.load(Ordering::SeqCst),
            0,
            "nothing wakes under the lock"
        );
        drop(retired);
        assert_eq!(
            count.0.load(Ordering::SeqCst),
            1,
            "retiring the observer delivers the cancellation it was owed"
        );
        assert!(wait.as_mut().poll(&mut task).is_ready());
        assert_eq!(registrations(&cx), 0);
    }
