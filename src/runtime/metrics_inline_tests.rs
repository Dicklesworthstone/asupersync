    use super::*;

    /// With the feature off, the API is a no-op and `snapshot()` is all-zero.
    #[cfg(not(feature = "runtime-metrics"))]
    #[test]
    fn snapshot_is_zero_when_feature_disabled() {
        record_timer_thread_spawned();
        record_sched_yield();
        record_worker_spin();
        record_worker_park();
        record_worker_unpark();
        record_timer_registered();
        record_timers_fired(5);
        record_timer_cancelled();
        assert_eq!(snapshot(), Metrics::default());
    }

    /// With the feature on, each `record_*` helper moves its own counter.
    ///
    /// The counters are process-global and the lib test suite runs in parallel,
    /// so other tests (e.g. scheduler/timer tests driving a real runtime) may
    /// bump these concurrently. We therefore assert MONOTONIC LOWER BOUNDS on
    /// the delta (`>=`): a counter can only be observed to move forward, so
    /// `after >= before + my_calls` is robust to concurrent increments while
    /// still proving each helper drives its intended counter.
    #[cfg(feature = "runtime-metrics")]
    #[test]
    fn record_helpers_increment_their_counters() {
        let before = snapshot();

        record_timer_thread_spawned();
        record_sched_yield();
        record_sched_yield();
        record_worker_spin();
        record_worker_park();
        record_worker_unpark();
        record_timer_registered();
        record_timer_registered();
        record_timer_registered();
        record_timers_fired(2);
        record_timer_cancelled();

        let after = snapshot();
        assert!(after.timer_threads_spawned > before.timer_threads_spawned);
        assert!(after.sched_yield_calls >= before.sched_yield_calls + 2);
        assert!(after.worker_spins > before.worker_spins);
        assert!(after.worker_parks > before.worker_parks);
        assert!(after.worker_unparks > before.worker_unparks);
        assert!(after.timers_registered >= before.timers_registered + 3);
        assert!(after.timers_fired >= before.timers_fired + 2);
        assert!(after.timers_cancelled > before.timers_cancelled);
    }

    /// `active_timers` is always the saturating-consistent derivation of the
    /// other three timer counters in the SAME snapshot, and never underflows.
    #[cfg(feature = "runtime-metrics")]
    #[test]
    fn active_timers_is_consistent_and_saturating() {
        record_timer_registered();
        record_timers_fired(1);
        let m = snapshot();
        // snapshot() derives active_timers from exactly these returned fields,
        // so this holds by construction and proves the saturating derivation.
        assert_eq!(
            m.active_timers,
            m.timers_registered
                .saturating_sub(m.timers_fired.saturating_add(m.timers_cancelled))
        );
    }

    /// `Display` renders every counter (used by the bench human summary).
    #[test]
    fn display_lists_all_counters() {
        let s = format!("{}", Metrics::default());
        for key in [
            "timer_threads_spawned",
            "sched_yield_calls",
            "worker_spins",
            "worker_parks",
            "worker_unparks",
            "timers_registered",
            "timers_fired",
            "timers_cancelled",
            "active_timers",
        ] {
            assert!(s.contains(key), "Display missing {key}: {s}");
        }
    }
