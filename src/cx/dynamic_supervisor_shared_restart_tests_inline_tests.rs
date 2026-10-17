    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    #[test]
    fn shared_reservations_atomically_limit_concurrent_controllers() {
        let domain = Arc::new(SharedRestartDomain::new(
            SharedRestartConfig::new(3, Duration::from_secs(1)),
        ));
        let barrier = Arc::new(std::sync::Barrier::new(16));
        // Every thread must be spawned before any join: the barrier waits for
        // all 16, so joining from a lazy iterator would deadlock.
        #[allow(clippy::needless_collect)]
        let threads: Vec<_> = (0..16).map(|_| {
            let domain = Arc::clone(&domain);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                domain.admit_with_clock(|| 10).is_allowed()
            })
        }).collect();
        let allowed = threads.into_iter()
            .map(|thread| thread.join().expect("reservation caller terminated"))
            .filter(|allowed| *allowed).count();
        assert_eq!(allowed, 3);
        let state = domain.state.lock();
        assert_eq!((state.admitted, state.pending), (3, 0));
        assert!(state.refusal.is_some());
    }

    #[test]
    fn shared_admission_timestamps_are_sampled_after_the_slot_is_reserved() {
        let domain = SharedRestartDomain::new(
            SharedRestartConfig::new(2, Duration::from_nanos(10)),
        );
        assert!(domain.admit_with_clock(|| 100).is_allowed());
        let calls = AtomicUsize::new(0);
        assert!(domain.admit_with_clock(|| {
            if calls.fetch_add(1, Ordering::Relaxed) == 0 { 0 } else { 100 }
        }).is_allowed());
        assert!(matches!(domain.admit_with_clock(|| 101), RestartVerdict::Denied {
            refusal: BudgetRefusal::WindowExhausted { max_restarts: 2, .. }
        }));
        assert_eq!(domain.state.lock().tracker.recent_count(101), 2);
    }

    #[test]
    fn shared_pending_slots_are_counted_and_clock_panic_does_not_refund() {
        let domain = SharedRestartDomain::new(
            SharedRestartConfig::new(2, Duration::from_nanos(10))
                .with_backoff(BackoffStrategy::Exponential {
                    initial: Duration::from_millis(1), max: Duration::from_secs(1), multiplier: 2.0,
                }),
        );
        let calls = AtomicUsize::new(0);
        assert!(catch_unwind(AssertUnwindSafe(|| domain.admit_with_clock(|| {
            assert_eq!(calls.fetch_add(1, Ordering::Relaxed), 0, "post-reservation clock panic");
            0
        }))).is_err());
        assert_eq!(domain.state.lock().pending, 1);
        assert_eq!(domain.status().recent, 1);
        assert!(matches!(domain.admit_with_clock(|| 100), RestartVerdict::Allowed {
            attempt: 2, delay: Some(delay),
        } if delay == Duration::from_millis(2)));
        assert!(matches!(domain.admit_with_clock(|| 101), RestartVerdict::Denied { .. }));
        assert_eq!(domain.status().admitted, 2);
    }

    #[test]
    fn shared_window_expires_but_a_latched_refusal_never_reopens() {
        let domain = SharedRestartDomain::new(
            SharedRestartConfig::new(1, Duration::from_nanos(10)),
        );
        assert!(domain.admit_with_clock(|| 0).is_allowed());
        assert!(domain.admit_with_clock(|| 11).is_allowed());
        assert!(matches!(domain.admit_with_clock(|| 21), RestartVerdict::Denied { .. }));
        assert!(matches!(domain.admit_with_clock(|| 1_000), RestartVerdict::Denied { .. }));
        assert_eq!(domain.status().admitted, 2);
    }

    #[test]
    fn shared_refusal_contains_a_panicking_notification_after_unlock() {
        struct Panics;
        impl std::task::Wake for Panics {
            fn wake(self: Arc<Self>) { panic!("notification panic"); }
        }
        let domain = SharedRestartDomain::new(
            SharedRestartConfig::new(0, Duration::from_secs(1)),
        );
        domain.register(&Waker::from(Arc::new(Panics)));
        assert!(matches!(domain.admit_with_clock(|| 0), RestartVerdict::Denied { .. }));
        assert!(domain.status().refusal.is_some());
    }
