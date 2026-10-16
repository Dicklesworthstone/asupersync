    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use parking_lot::Mutex;
    use std::collections::VecDeque;
    use std::future::Future as StdFuture;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    #[derive(Default)]
    struct CountingWake {
        wakes: AtomicUsize,
    }

    impl Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counting_waker() -> (Arc<CountingWake>, Waker) {
        let counter = Arc::new(CountingWake::default());
        let waker = Waker::from(Arc::clone(&counter));
        (counter, waker)
    }

    std::thread_local! {
        static TEST_NOW: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    fn test_time() -> Time {
        Time::from_nanos(TEST_NOW.with(std::cell::Cell::get))
    }

    fn set_test_time(t: u64) {
        TEST_NOW.with(|now| now.set(t));
    }

    #[derive(Debug, Clone)]
    struct TimedPlan {
        ready_at: u64,
        result: Result<u32, &'static str>,
    }

    impl TimedPlan {
        fn ok_at(ready_at: u64, value: u32) -> Self {
            Self {
                ready_at,
                result: Ok(value),
            }
        }

        fn err_at(ready_at: u64, err: &'static str) -> Self {
            Self {
                ready_at,
                result: Err(err),
            }
        }
    }

    #[derive(Clone, Debug)]
    struct TimedService {
        plans: Arc<Mutex<VecDeque<TimedPlan>>>,
        calls: Arc<AtomicUsize>,
    }

    impl TimedService {
        fn new(plans: Vec<TimedPlan>, calls: Arc<AtomicUsize>) -> Self {
            Self {
                plans: Arc::new(Mutex::new(plans.into())),
                calls,
            }
        }
    }

    #[derive(Debug)]
    struct TimedFuture {
        ready_at: u64,
        result: Option<Result<u32, &'static str>>,
    }

    impl StdFuture for TimedFuture {
        type Output = Result<u32, &'static str>;

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if TEST_NOW.with(std::cell::Cell::get) >= self.ready_at {
                Poll::Ready(
                    self.result
                        .take()
                        .expect("timed future must only complete once"),
                )
            } else {
                Poll::Pending
            }
        }
    }

    impl Service<u32> for TimedService {
        type Response = u32;
        type Error = &'static str;
        type Future = TimedFuture;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: u32) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let plan = self
                .plans
                .lock()
                .pop_front()
                .expect("timed service exhausted test plans");
            TimedFuture {
                ready_at: plan.ready_at,
                result: Some(plan.result),
            }
        }
    }

    // ================================================================
    // HedgeConfig
    // ================================================================

    #[test]
    fn config_new() {
        init_test("config_new");
        let config = HedgeConfig::new(Duration::from_millis(100));
        assert_eq!(config.delay, Duration::from_millis(100));
        assert_eq!(config.max_pending, 10);
        crate::test_complete!("config_new");
    }

    #[test]
    fn config_max_pending() {
        let config = HedgeConfig::new(Duration::from_millis(50)).max_pending(5);
        assert_eq!(config.max_pending, 5);
    }

    #[test]
    fn config_debug_clone() {
        let config = HedgeConfig::new(Duration::from_millis(100));
        let dbg = format!("{config:?}");
        assert!(dbg.contains("HedgeConfig"));
        let cloned = config.clone();
        assert_eq!(cloned.delay, Duration::from_millis(100));
        assert_eq!(config.delay, Duration::from_millis(100));
    }

    #[test]
    fn config_with_time_getter() {
        set_test_time(55);
        let config = HedgeConfig::new(Duration::from_nanos(5)).with_time_getter(test_time);
        assert_eq!((config.time_getter())(), Time::from_nanos(55));
    }

    /// br-asupersync-1sxucf LOW: the default config passed the wall clock as a
    /// custom time getter. A `Sleep` with a custom getter cannot use the shared
    /// fallback timer, so off the runtime every request's hedge delay spawned
    /// a thread that polled the clock every millisecond.
    #[test]
    fn default_config_waits_on_the_runtime_clock_not_a_custom_getter() {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        for (config, custom) in [
            (HedgeConfig::new(Duration::from_secs(30)), false),
            (
                HedgeConfig::new(Duration::from_secs(30)).with_time_getter(test_time),
                true,
            ),
        ] {
            let plans = vec![TimedPlan::ok_at(u64::MAX, 1)];
            let mut hedge = Hedge::new(
                TimedService::new(plans, Arc::new(AtomicUsize::new(0))),
                config,
            );
            assert!(matches!(hedge.poll_ready(&mut cx), Poll::Ready(Ok(()))));
            let future = hedge.call(1);
            let HedgeFutureState::Running { sleep, .. } = &future.state else {
                panic!("the call was authorized");
            };
            assert_eq!(sleep.has_custom_time_getter(), custom);
        }
    }

    #[test]
    fn config_with_adaptive_delay() {
        let controller = Arc::new(PeakEwmaHedgeController::default_rpc());
        let config = HedgeConfig::new(Duration::from_millis(50))
            .with_adaptive_delay(Arc::clone(&controller));
        assert!(config.adaptive_controller().is_some());
    }

    // ================================================================
    // HedgeLayer
    // ================================================================

    #[test]
    fn layer_new() {
        let layer = HedgeLayer::new(HedgeConfig::new(Duration::from_millis(100)));
        let dbg = format!("{layer:?}");
        assert!(dbg.contains("HedgeLayer"));
    }

    #[test]
    fn layer_with_delay() {
        let layer = HedgeLayer::with_delay(Duration::from_millis(200));
        let dbg = format!("{layer:?}");
        assert!(dbg.contains("HedgeLayer"));
    }

    #[test]
    fn layer_with_adaptive_delay() {
        let controller = Arc::new(PeakEwmaHedgeController::default_rpc());
        let layer = HedgeLayer::with_adaptive_delay(Arc::clone(&controller));
        assert!(layer.config.adaptive_controller().is_some());
    }

    #[test]
    fn layer_clone() {
        let layer = HedgeLayer::with_delay(Duration::from_millis(100));
        let cloned = layer.clone();
        assert_eq!(cloned.config.delay, Duration::from_millis(100));
        assert_eq!(layer.config.delay, Duration::from_millis(100));
    }

    // ================================================================
    // Hedge service
    // ================================================================

    #[derive(Clone, Debug)]
    struct MockSvc;

    #[derive(Clone, Debug)]
    struct PanicOnCallService;

    #[derive(Clone, Debug)]
    struct RequiresReadyService {
        ready: bool,
        calls: Arc<AtomicUsize>,
    }

    impl Service<u32> for PanicOnCallService {
        type Response = ();
        type Error = ();
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: u32) -> Self::Future {
            panic!("panic during hedge call construction");
        }
    }

    impl Service<u32> for RequiresReadyService {
        type Response = u32;
        type Error = &'static str;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.ready = true;
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: u32) -> Self::Future {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let was_ready = std::mem::replace(&mut self.ready, false);
            if was_ready {
                std::future::ready(Ok(req))
            } else {
                std::future::ready(Err("not ready"))
            }
        }
    }

    #[test]
    fn hedge_new() {
        init_test("hedge_new");
        let hedge = Hedge::new(MockSvc, HedgeConfig::new(Duration::from_millis(100)));
        assert_eq!(hedge.delay(), Duration::from_millis(100));
        assert_eq!(hedge.max_pending(), 10);
        assert_eq!(hedge.total_requests(), 0);
        assert_eq!(hedge.hedged_requests(), 0);
        assert_eq!(hedge.hedge_wins(), 0);
        assert!((hedge.hedge_rate() - 0.0).abs() < f64::EPSILON);
        crate::test_complete!("hedge_new");
    }

    #[test]
    fn hedge_stats() {
        init_test("hedge_stats");
        let hedge = Hedge::new(MockSvc, HedgeConfig::new(Duration::from_millis(100)));
        hedge.record_request();
        hedge.record_request();
        hedge.record_hedge();
        hedge.record_hedge_win();
        assert_eq!(hedge.total_requests(), 2);
        assert_eq!(hedge.hedged_requests(), 1);
        assert_eq!(hedge.hedge_wins(), 1);
        assert!((hedge.hedge_rate() - 0.5).abs() < f64::EPSILON);
        crate::test_complete!("hedge_stats");
    }

    #[test]
    fn hedge_call_panic_does_not_overcount_total_requests() {
        init_test("hedge_call_panic_does_not_overcount_total_requests");
        let mut hedge = Hedge::new(
            PanicOnCallService,
            HedgeConfig::new(Duration::from_millis(100)),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let ready = hedge.poll_ready(&mut cx);
        assert!(matches!(ready, Poll::Ready(Ok(()))));

        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _f = hedge.call(7);
        }));
        let panicked = panic.is_err();
        crate::assert_with_log!(panicked, "inner call panicked", true, panicked);

        let total = hedge.total_requests();
        crate::assert_with_log!(total == 0, "total requests", 0, total);
        crate::test_complete!("hedge_call_panic_does_not_overcount_total_requests");
    }

    #[test]
    fn hedge_call_without_poll_ready_fails_closed() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hedge = Hedge::new(
            RequiresReadyService {
                ready: false,
                calls: Arc::clone(&calls),
            },
            HedgeConfig::new(Duration::from_millis(100)),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = hedge.call(7);
        let result = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(result, Poll::Ready(Err(HedgeError::NotReady))));
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(hedge.total_requests(), 0);
    }

    #[test]
    fn hedge_ready_window_is_consumed_by_call() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hedge = Hedge::new(
            RequiresReadyService {
                ready: false,
                calls: Arc::clone(&calls),
            },
            HedgeConfig::new(Duration::from_millis(100)),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first_ready = hedge.poll_ready(&mut cx);
        assert!(matches!(first_ready, Poll::Ready(Ok(()))));

        let mut first = hedge.call(11);
        let first_result = Pin::new(&mut first).poll(&mut cx);
        assert!(matches!(first_result, Poll::Ready(Ok(11))));

        let mut second = hedge.call(22);
        let second_result = Pin::new(&mut second).poll(&mut cx);
        assert!(matches!(
            second_result,
            Poll::Ready(Err(HedgeError::NotReady))
        ));

        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(hedge.total_requests(), 1);
    }

    #[test]
    fn hedge_clone_does_not_inherit_ready_window() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hedge = Hedge::new(
            RequiresReadyService {
                ready: false,
                calls: Arc::clone(&calls),
            },
            HedgeConfig::new(Duration::from_millis(100)),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = hedge.poll_ready(&mut cx);
        assert!(matches!(ready, Poll::Ready(Ok(()))));

        let mut clone = hedge.clone();
        let mut fut = clone.call(99);
        let result = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(result, Poll::Ready(Err(HedgeError::NotReady))));

        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(clone.total_requests(), 0);
    }

    #[test]
    fn hedge_primary_completes_before_delay_without_backup() {
        set_test_time(0);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hedge = Hedge::new(
            TimedService::new(
                vec![TimedPlan::ok_at(5, 11), TimedPlan::ok_at(20, 22)],
                Arc::clone(&calls),
            ),
            HedgeConfig::new(Duration::from_nanos(10)).with_time_getter(test_time),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(hedge.poll_ready(&mut cx), Poll::Ready(Ok(()))));

        let mut future = hedge.call(7);
        let res = Pin::new(&mut future).poll(&mut cx);
        assert!(res.is_pending(), "Expected pending, got {res:?}");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        set_test_time(5);
        let result = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(result, Poll::Ready(Ok(11))));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(hedge.hedged_requests(), 0);
        assert_eq!(hedge.hedge_wins(), 0);
    }

    /// asupersync-bi2462.168: `Sleep` completes on its registering poll when
    /// the current task is cancelled. The future used to keep that completed
    /// Sleep and poll it again ("Sleep polled after completion"). A cancelled
    /// task must also not start the backup.
    #[test]
    fn cancelled_task_never_repolls_the_delay_sleep_or_starts_a_backup() {
        set_test_time(0);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hedge = Hedge::new(
            TimedService::new(
                vec![TimedPlan::ok_at(50, 11), TimedPlan::ok_at(60, 22)],
                Arc::clone(&calls),
            ),
            HedgeConfig::new(Duration::from_nanos(10)).with_time_getter(test_time),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(hedge.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        let owner = crate::cx::Cx::for_testing();
        owner.cancel_with(
            crate::types::CancelKind::User,
            Some("hedge owner cancelled"),
        );
        let _current = crate::cx::Cx::set_current(Some(owner));

        let mut future = hedge.call(7);
        for poll in 0..3 {
            let res = Pin::new(&mut future).poll(&mut cx);
            assert!(
                res.is_pending(),
                "poll {poll}: expected pending, got {res:?}"
            );
        }
        // Past the delay by the injected clock: still no backup.
        set_test_time(20);
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a cancelled task starts no backup"
        );
        assert_eq!(hedge.hedged_requests(), 0);

        set_test_time(50);
        let result = Pin::new(&mut future).poll(&mut cx);
        assert!(
            matches!(result, Poll::Ready(Ok(11))),
            "primary still completes: {result:?}"
        );
    }

    #[test]
    fn hedge_dispatches_backup_after_delay_and_backup_can_win() {
        set_test_time(0);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hedge = Hedge::new(
            TimedService::new(
                vec![TimedPlan::ok_at(30, 11), TimedPlan::ok_at(12, 22)],
                Arc::clone(&calls),
            ),
            HedgeConfig::new(Duration::from_nanos(10))
                .max_pending(1)
                .with_time_getter(test_time),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(hedge.poll_ready(&mut cx), Poll::Ready(Ok(()))));

        let mut future = hedge.call(7);
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        set_test_time(10);
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(hedge.hedged_requests(), 1);

        set_test_time(12);
        let result = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(result, Poll::Ready(Ok(22))));
        assert_eq!(hedge.hedge_wins(), 1);
    }

    /// asupersync-m82nx1: backup dispatches according to the controller's delay,
    /// and a slow primary raises subsequent delay via observe.
    #[test]
    fn hedge_adaptive_delay_follows_controller_and_slow_primary_raises_delay() {
        set_test_time(0);
        let calls = Arc::new(AtomicUsize::new(0));

        // Controller configured with initial 20ns, min 10ns, max 200ns, decay 0.99
        let controller = Arc::new(PeakEwmaHedgeController::new(
            Duration::from_nanos(20),
            Duration::from_nanos(10),
            Duration::from_nanos(200),
            0.99,
        ));

        // Static delay is set to 100ns, but adaptive delay is 20ns
        let config = HedgeConfig::new(Duration::from_nanos(100))
            .with_adaptive_delay(Arc::clone(&controller))
            .with_time_getter(test_time);

        let mut hedge = Hedge::new(
            TimedService::new(
                vec![
                    // First request: primary ready at 50ns (slow, should trigger hedge at 20ns)
                    TimedPlan::ok_at(50, 1),
                    // Hedge backup ready at 25ns
                    TimedPlan::ok_at(25, 2),
                    // Second request: primary ready at 160ns (started at 80ns, takes 80ns)
                    TimedPlan::ok_at(160, 3),
                    // Third request: primary ready at 300ns (started at 160ns, slow)
                    TimedPlan::ok_at(300, 4),
                    // Third request backup ready at 250ns
                    TimedPlan::ok_at(250, 5),
                ],
                Arc::clone(&calls),
            ),
            config,
        );

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // 1. First request: verify backup fires at controller delay (20ns), NOT static delay (100ns)
        assert!(matches!(hedge.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        let mut first = hedge.call(10);
        assert!(Pin::new(&mut first).poll(&mut cx).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Advance to 15ns - below controller delay (20ns), backup must NOT fire
        set_test_time(15);
        assert!(Pin::new(&mut first).poll(&mut cx).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Advance to 20ns - reaches controller delay, backup MUST fire
        set_test_time(20);
        assert!(Pin::new(&mut first).poll(&mut cx).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 2, "backup fires at controller delay (20ns)");
        assert_eq!(hedge.hedged_requests(), 1);

        // Advance to 25ns - backup wins
        set_test_time(25);
        let res1 = Pin::new(&mut first).poll(&mut cx);
        assert!(matches!(res1, Poll::Ready(Ok(2))));
        assert_eq!(hedge.hedge_wins(), 1);

        // 2. Second request: primary completes successfully and updates controller
        set_test_time(80);
        assert!(matches!(hedge.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        let mut second = hedge.call(20);
        assert!(Pin::new(&mut second).poll(&mut cx).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        // Complete primary at 160ns (elapsed = 80ns).
        // Since controller delay was 20ns, this slow primary (80ns) feeds observe(80ns).
        set_test_time(160);
        let res2 = Pin::new(&mut second).poll(&mut cx);
        assert!(matches!(res2, Poll::Ready(Ok(3))));
        // Controller delay should now have increased to 80ns!
        assert_eq!(controller.current_delay(), Duration::from_nanos(80));

        // 3. Third request: uses updated higher delay (80ns), so at t=160 + 50ns = 210ns it does NOT hedge
        assert!(matches!(hedge.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        let mut third = hedge.call(30);
        assert!(Pin::new(&mut third).poll(&mut cx).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 4);

        set_test_time(210); // 50ns elapsed, which is > old delay (20ns) but < new delay (80ns)
        assert!(Pin::new(&mut third).poll(&mut cx).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 4, "backup did not fire at old 20ns threshold");

        // Advance to 240ns (80ns elapsed) -> backup fires!
        set_test_time(240);
        assert!(Pin::new(&mut third).poll(&mut cx).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 5, "backup fires at updated 80ns threshold");
    }

    #[test]
    fn hedge_slot_release_wakes_live_waiter_past_completed_stale_waiter() {
        set_test_time(0);
        let calls = Arc::new(AtomicUsize::new(0));
        let hedge = Hedge::new(
            TimedService::new(
                vec![
                    TimedPlan::ok_at(u64::MAX, 11),
                    TimedPlan::ok_at(u64::MAX, 12),
                    TimedPlan::ok_at(20, 13),
                    TimedPlan::ok_at(u64::MAX, 21),
                    TimedPlan::ok_at(u64::MAX, 22),
                ],
                Arc::clone(&calls),
            ),
            HedgeConfig::new(Duration::from_nanos(10))
                .max_pending(1)
                .with_time_getter(test_time),
        );
        let mut holder_service = hedge.clone();
        let mut live_service = hedge.clone();
        let mut stale_service = hedge.clone();

        let holder_waker = noop_waker();
        let (live_wakes, live_waker) = counting_waker();
        let (stale_wakes, stale_waker) = counting_waker();
        let mut holder_cx = Context::from_waker(&holder_waker);
        let mut live_cx = Context::from_waker(&live_waker);
        let mut stale_cx = Context::from_waker(&stale_waker);
        assert!(matches!(
            holder_service.poll_ready(&mut holder_cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            live_service.poll_ready(&mut live_cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            stale_service.poll_ready(&mut stale_cx),
            Poll::Ready(Ok(()))
        ));

        let mut holder = holder_service.call(1);
        let mut live = live_service.call(2);
        let mut stale = stale_service.call(3);

        set_test_time(10);
        assert!(Pin::new(&mut holder).poll(&mut holder_cx).is_pending());
        assert!(Pin::new(&mut live).poll(&mut live_cx).is_pending());
        assert!(Pin::new(&mut stale).poll(&mut stale_cx).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert_eq!(hedge.stats.slot_waiters.lock().len(), 2);

        set_test_time(20);
        assert!(matches!(
            Pin::new(&mut stale).poll(&mut stale_cx),
            Poll::Ready(Ok(13))
        ));
        assert_eq!(hedge.stats.slot_waiters.lock().len(), 2);

        drop(holder);
        assert_eq!(live_wakes.wakes.load(Ordering::SeqCst), 1);
        assert_eq!(stale_wakes.wakes.load(Ordering::SeqCst), 1);
        assert!(hedge.stats.slot_waiters.lock().is_empty());

        assert!(Pin::new(&mut live).poll(&mut live_cx).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 5);
        assert_eq!(hedge.hedged_requests(), 2);
    }

    #[test]
    fn hedge_selected_waiter_cancellation_does_not_strand_peer() {
        set_test_time(0);
        let calls = Arc::new(AtomicUsize::new(0));
        let hedge = Hedge::new(
            TimedService::new(
                vec![
                    TimedPlan::ok_at(u64::MAX, 11),
                    TimedPlan::ok_at(u64::MAX, 12),
                    TimedPlan::ok_at(u64::MAX, 13),
                    TimedPlan::ok_at(u64::MAX, 21),
                    TimedPlan::ok_at(u64::MAX, 22),
                ],
                Arc::clone(&calls),
            ),
            HedgeConfig::new(Duration::from_nanos(10))
                .max_pending(1)
                .with_time_getter(test_time),
        );
        let mut holder_service = hedge.clone();
        let mut live_service = hedge.clone();
        let mut selected_service = hedge.clone();

        let holder_waker = noop_waker();
        let (live_wakes, live_waker) = counting_waker();
        let (selected_wakes, selected_waker) = counting_waker();
        let mut holder_cx = Context::from_waker(&holder_waker);
        let mut live_cx = Context::from_waker(&live_waker);
        let mut selected_cx = Context::from_waker(&selected_waker);
        assert!(matches!(
            holder_service.poll_ready(&mut holder_cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            live_service.poll_ready(&mut live_cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            selected_service.poll_ready(&mut selected_cx),
            Poll::Ready(Ok(()))
        ));

        let mut holder = holder_service.call(1);
        let mut live = live_service.call(2);
        let mut selected = selected_service.call(3);

        set_test_time(10);
        assert!(Pin::new(&mut holder).poll(&mut holder_cx).is_pending());
        assert!(Pin::new(&mut live).poll(&mut live_cx).is_pending());
        assert!(Pin::new(&mut selected).poll(&mut selected_cx).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert_eq!(hedge.stats.slot_waiters.lock().len(), 2);

        drop(holder);
        assert_eq!(live_wakes.wakes.load(Ordering::SeqCst), 1);
        assert_eq!(selected_wakes.wakes.load(Ordering::SeqCst), 1);
        drop(selected);

        assert!(Pin::new(&mut live).poll(&mut live_cx).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 5);
        assert_eq!(hedge.hedged_requests(), 2);
    }

    #[test]
    fn hedge_backup_can_rescue_primary_error() {
        set_test_time(0);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hedge = Hedge::new(
            TimedService::new(
                vec![
                    TimedPlan::err_at(30, "primary failed"),
                    TimedPlan::ok_at(12, 77),
                ],
                Arc::clone(&calls),
            ),
            HedgeConfig::new(Duration::from_nanos(10))
                .max_pending(1)
                .with_time_getter(test_time),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(hedge.poll_ready(&mut cx), Poll::Ready(Ok(()))));

        let mut future = hedge.call(7);
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());

        set_test_time(10);
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
        set_test_time(12);
        let result = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(result, Poll::Ready(Ok(77))));
        assert_eq!(hedge.hedged_requests(), 1);
        assert_eq!(hedge.hedge_wins(), 1);
    }

    #[test]
    fn hedge_reports_both_failed_when_primary_and_backup_fail() {
        set_test_time(0);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hedge = Hedge::new(
            TimedService::new(
                vec![
                    TimedPlan::err_at(30, "primary failed"),
                    TimedPlan::err_at(12, "hedge failed"),
                ],
                Arc::clone(&calls),
            ),
            HedgeConfig::new(Duration::from_nanos(10))
                .max_pending(1)
                .with_time_getter(test_time),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(hedge.poll_ready(&mut cx), Poll::Ready(Ok(()))));

        let mut future = hedge.call(7);
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
        set_test_time(10);
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
        set_test_time(12);
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
        set_test_time(30);
        let result = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(
            result,
            Poll::Ready(Err(HedgeError::BothFailed {
                primary: "primary failed",
                hedge: "hedge failed"
            }))
        ));
    }

    #[test]
    fn hedge_max_pending_zero_disables_backup_dispatch() {
        set_test_time(0);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hedge = Hedge::new(
            TimedService::new(
                vec![TimedPlan::ok_at(30, 11), TimedPlan::ok_at(12, 22)],
                Arc::clone(&calls),
            ),
            HedgeConfig::new(Duration::from_nanos(10))
                .max_pending(0)
                .with_time_getter(test_time),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(hedge.poll_ready(&mut cx), Poll::Ready(Ok(()))));

        let mut future = hedge.call(7);
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
        set_test_time(10);
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(hedge.hedged_requests(), 0);

        set_test_time(30);
        let result = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(result, Poll::Ready(Ok(11))));
    }

    #[test]
    fn hedge_inner() {
        let hedge = Hedge::new(42u32, HedgeConfig::new(Duration::from_millis(100)));
        assert_eq!(*hedge.inner(), 42);
    }

    #[test]
    fn hedge_inner_mut() {
        let mut hedge = Hedge::new(42u32, HedgeConfig::new(Duration::from_millis(100)));
        *hedge.inner_mut() = 99;
        assert_eq!(*hedge.inner(), 99);
    }

    #[test]
    fn hedge_config_ref() {
        let hedge = Hedge::new(MockSvc, HedgeConfig::new(Duration::from_millis(100)));
        assert_eq!(hedge.config().delay, Duration::from_millis(100));
    }

    #[test]
    fn hedge_debug() {
        let hedge = Hedge::new(MockSvc, HedgeConfig::new(Duration::from_millis(100)));
        let dbg = format!("{hedge:?}");
        assert!(dbg.contains("Hedge"));
    }

    #[test]
    fn hedge_clone() {
        let hedge = Hedge::new(MockSvc, HedgeConfig::new(Duration::from_millis(100)));
        hedge.record_request();
        let cloned = hedge.clone();
        // Clone shares hedge statistics but not readiness tickets.
        assert_eq!(cloned.total_requests(), 1);
        assert_eq!(cloned.delay(), Duration::from_millis(100));
        assert_eq!(hedge.total_requests(), 1);
    }

    #[test]
    fn hedge_layer_applies() {
        init_test("hedge_layer_applies");
        let layer = HedgeLayer::with_delay(Duration::from_millis(50));
        let svc = layer.layer(MockSvc);
        assert_eq!(svc.delay(), Duration::from_millis(50));
        crate::test_complete!("hedge_layer_applies");
    }

    // ================================================================
    // HedgeError
    // ================================================================

    #[test]
    fn error_inner_display() {
        let err: HedgeError<std::io::Error> = HedgeError::Inner(std::io::Error::other("fail"));
        assert!(format!("{err}").contains("service error"));
    }

    #[test]
    fn error_not_ready_display() {
        let err: HedgeError<std::io::Error> = HedgeError::NotReady;
        assert_eq!(format!("{err}"), "poll_ready required before call");
    }

    #[test]
    fn error_polled_after_completion_display() {
        let err: HedgeError<std::io::Error> = HedgeError::PolledAfterCompletion;
        assert_eq!(format!("{err}"), "hedge future polled after completion");
    }

    #[test]
    fn error_both_failed_display() {
        let err: HedgeError<std::io::Error> = HedgeError::BothFailed {
            primary: std::io::Error::other("p"),
            hedge: std::io::Error::other("h"),
        };
        assert!(format!("{err}").contains("both primary and hedge failed"));
    }

    #[test]
    fn error_source() {
        use std::error::Error;
        let err: HedgeError<std::io::Error> = HedgeError::Inner(std::io::Error::other("fail"));
        assert!(err.source().is_some());

        let not_ready: HedgeError<std::io::Error> = HedgeError::NotReady;
        assert!(not_ready.source().is_none());

        let done: HedgeError<std::io::Error> = HedgeError::PolledAfterCompletion;
        assert!(done.source().is_none());
    }

    #[test]
    fn error_debug() {
        let err: HedgeError<std::io::Error> = HedgeError::Inner(std::io::Error::other("fail"));
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Inner"));
    }

    #[test]
    fn error_debug_includes_polled_after_completion() {
        let err: HedgeError<std::io::Error> = HedgeError::PolledAfterCompletion;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("PolledAfterCompletion"));
    }

    // ================================================================
    // HedgeFuture
    // ================================================================

    #[test]
    fn hedge_future_debug() {
        let fut: HedgeFuture<TimedService, u32> = HedgeFuture::not_ready();
        let dbg = format!("{fut:?}");
        assert!(dbg.contains("HedgeFuture"));
    }

    /// Regression: hedge delay elapses, slot acquired, but service.poll_ready
    /// returns Pending. On next poll, the completed Sleep must NOT be
    /// re-polled (which would panic).
    #[test]
    fn hedge_does_not_repoll_completed_sleep_when_slot_held() {
        // Use a dedicated time source to avoid races with other tests
        // that share the module-level TEST_NOW static.
        static LOCAL_NOW: AtomicU64 = AtomicU64::new(0);
        fn local_time() -> Time {
            Time::from_nanos(LOCAL_NOW.load(Ordering::SeqCst))
        }

        // A service that returns Pending from poll_ready on the first calls,
        // then Ready(Ok(())) once the countdown reaches zero.
        #[derive(Clone, Debug)]
        struct DelayedReadyService {
            ready_countdown: Arc<AtomicUsize>,
            calls: Arc<AtomicUsize>,
        }

        impl Service<u32> for DelayedReadyService {
            type Response = u32;
            type Error = &'static str;
            type Future = TimedFuture;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                let prev = self.ready_countdown.fetch_sub(1, Ordering::SeqCst);
                if prev > 0 {
                    Poll::Pending
                } else {
                    Poll::Ready(Ok(()))
                }
            }

            fn call(&mut self, _req: u32) -> Self::Future {
                self.calls.fetch_add(1, Ordering::SeqCst);
                TimedFuture {
                    ready_at: 0,
                    result: Some(Ok(99)),
                }
            }
        }

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        LOCAL_NOW.store(0, Ordering::SeqCst);
        let calls = Arc::new(AtomicUsize::new(0));
        let svc = DelayedReadyService {
            // Pending twice: once on the first try after slot acquire
            // (within the same poll's progress loop), then again on the
            // next external poll which re-enters with slot_held=true.
            ready_countdown: Arc::new(AtomicUsize::new(2)),
            calls: Arc::clone(&calls),
        };
        let stats = Arc::new(super::HedgeStats {
            total: AtomicU64::new(0),
            hedged: AtomicU64::new(0),
            hedge_wins: AtomicU64::new(0),
            pending: AtomicU64::new(0),
            slot_waiters: parking_lot::Mutex::new(Vec::new()),
        });

        // Primary future that never completes (stays Pending).
        let primary = TimedFuture {
            ready_at: u64::MAX,
            result: Some(Ok(0)),
        };

        // Use a large delay so other tests' TEST_NOW values cannot
        // accidentally elapse it.
        let config = HedgeConfig::new(Duration::from_millis(1))
            .with_time_getter(local_time)
            .max_pending(5);
        let mut fut = HedgeFuture::new(primary, Some(svc), 42_u32, &config, stats);

        // Poll 1: timer not elapsed yet, both primary and hedge pending.
        let p1 = Pin::new(&mut fut).poll(&mut cx);
        assert!(p1.is_pending());

        // Advance time past the delay.
        LOCAL_NOW.store(2_000_000, Ordering::SeqCst);

        // Poll 2: timer elapses, slot acquired, poll_ready returns Pending
        // twice (once in progress loop, once after re-enter). Returns Pending
        // because the service is not yet ready.
        let p2 = Pin::new(&mut fut).poll(&mut cx);
        assert!(p2.is_pending());

        // Poll 3: this used to panic ("Sleep polled after completion") before
        // the fix. Now it should skip the sleep (slot_held=true), re-poll
        // poll_ready which returns Ready, dispatch the hedge, and the hedge
        // future completes immediately.
        let p3 = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(p3, Poll::Ready(Ok(99))));
    }

    #[test]
    fn hedge_future_second_poll_fails_closed() {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        set_test_time(0);
        let mut fut = HedgeFuture::new(
            TimedFuture {
                ready_at: 0,
                result: Some(Ok(42)),
            },
            None::<TimedService>,
            7_u32,
            &HedgeConfig::new(Duration::from_nanos(10)).with_time_getter(test_time),
            Arc::new(super::HedgeStats {
                total: AtomicU64::new(0),
                hedged: AtomicU64::new(0),
                hedge_wins: AtomicU64::new(0),
                pending: AtomicU64::new(0),
                slot_waiters: parking_lot::Mutex::new(Vec::new()),
            }),
        );

        let first = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(first, Poll::Ready(Ok(42))));

        let second = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(HedgeError::PolledAfterCompletion))
        ));
    }

    // ================================================================
    // Metamorphic Testing Properties
    // ================================================================

    /// MR1: Request permutation invariance
    /// Property: shuffle(requests) → hedge service → same stats as requests → hedge service
    #[test]
    fn metamorphic_request_permutation_invariance() {
        init_test("metamorphic_request_permutation_invariance");

        let requests = vec![1u32, 2, 3, 4, 5];
        let mut shuffled = requests.clone();
        shuffled.reverse(); // Simple deterministic permutation

        let original_stats = execute_request_sequence(&requests);
        let shuffled_stats = execute_request_sequence(&shuffled);

        assert_eq!(
            original_stats.total, shuffled_stats.total,
            "Total requests should be invariant under permutation"
        );
        assert_eq!(
            original_stats.hedged, shuffled_stats.hedged,
            "Hedged requests should be invariant under permutation"
        );
        assert_eq!(
            original_stats.hedge_wins, shuffled_stats.hedge_wins,
            "Hedge wins should be invariant under permutation"
        );

        crate::test_complete!("metamorphic_request_permutation_invariance");
    }

    /// MR2: Delay scaling property
    /// Property: scale(delays) × k → hedge(delay × k) should preserve timing relationships
    #[test]
    fn metamorphic_delay_scaling_preserves_relationships() {
        init_test("metamorphic_delay_scaling_preserves_relationships");

        let base_delay = Duration::from_nanos(10);
        let scale_factor = 3;
        let scaled_delay = Duration::from_nanos(10 * scale_factor);

        // Fast completion - should never hedge in either case
        let fast_plans = vec![TimedPlan::ok_at(5, 42)]; // Completes before any delay
        let base_hedge_rate = test_delay_scenario(&fast_plans, base_delay);
        let scaled_hedge_rate = test_delay_scenario(&fast_plans, scaled_delay);

        assert!(
            (base_hedge_rate - scaled_hedge_rate).abs() < f64::EPSILON,
            "Fast requests should have same hedge rate regardless of delay scaling"
        );

        crate::test_complete!("metamorphic_delay_scaling_preserves_relationships");
    }

    /// MR3: Service equivalence under hedging
    /// Property: hedge(identical_service) should behave like original service for fast requests
    #[test]
    fn metamorphic_service_equivalence_fast_requests() {
        init_test("metamorphic_service_equivalence_fast_requests");

        set_test_time(0);
        let calls = Arc::new(AtomicUsize::new(0));

        // Create hedge service with long delay
        let mut hedge = Hedge::new(
            TimedService::new(
                vec![TimedPlan::ok_at(5, 42)], // Completes before hedge delay
                Arc::clone(&calls),
            ),
            HedgeConfig::new(Duration::from_nanos(100)) // Much longer than completion
                .max_pending(0) // Disable hedging
                .with_time_getter(test_time),
        );

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(hedge.poll_ready(&mut cx), Poll::Ready(Ok(()))));

        let mut future = hedge.call(7);
        set_test_time(5);
        let result = Pin::new(&mut future).poll(&mut cx);

        assert!(
            matches!(result, Poll::Ready(Ok(42))),
            "Fast request should return original service result"
        );
        assert_eq!(
            hedge.hedged_requests(),
            0,
            "No hedge should be dispatched for fast requests"
        );

        crate::test_complete!("metamorphic_service_equivalence_fast_requests");
    }

    /// MR4: Parallel request cancellation independence
    /// Property: cancel(request_i) should not affect unrelated concurrent request_j
    #[test]
    fn metamorphic_parallel_cancellation_independence() {
        init_test("metamorphic_parallel_cancellation_independence");

        set_test_time(0);
        let calls1 = Arc::new(AtomicUsize::new(0));
        let calls2 = Arc::new(AtomicUsize::new(0));

        let mut hedge1 = Hedge::new(
            TimedService::new(vec![TimedPlan::ok_at(20, 11)], Arc::clone(&calls1)),
            HedgeConfig::new(Duration::from_nanos(10))
                .max_pending(2)
                .with_time_getter(test_time),
        );

        let mut hedge2 = Hedge::new(
            TimedService::new(vec![TimedPlan::ok_at(25, 22)], Arc::clone(&calls2)),
            HedgeConfig::new(Duration::from_nanos(10))
                .max_pending(2)
                .with_time_getter(test_time),
        );

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Start both requests
        assert!(matches!(hedge1.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        assert!(matches!(hedge2.poll_ready(&mut cx), Poll::Ready(Ok(()))));

        let mut future1 = hedge1.call(1);
        let mut future2 = hedge2.call(2);

        // Poll both to pending
        assert!(Pin::new(&mut future1).poll(&mut cx).is_pending());
        assert!(Pin::new(&mut future2).poll(&mut cx).is_pending());

        // Drop future1 (simulates cancellation)
        drop(future1);

        // future2 should still complete normally
        set_test_time(25);
        let result2 = Pin::new(&mut future2).poll(&mut cx);
        assert!(
            matches!(result2, Poll::Ready(Ok(22))),
            "Independent request should complete despite other cancellation"
        );

        crate::test_complete!("metamorphic_parallel_cancellation_independence");
    }

    /// MR5: Statistics consistency invariants
    /// Property: hedge_wins ≤ hedged_requests ≤ total_requests always holds
    #[test]
    fn metamorphic_statistics_consistency() {
        init_test("metamorphic_statistics_consistency");

        // Test various scenarios
        let scenarios = vec![
            vec![TimedPlan::ok_at(5, 1)],                           // Fast, no hedge
            vec![TimedPlan::ok_at(30, 1), TimedPlan::ok_at(15, 2)], // Hedge wins
            vec![TimedPlan::ok_at(15, 1), TimedPlan::ok_at(30, 2)], // Primary wins
            vec![TimedPlan::err_at(30, "fail"), TimedPlan::ok_at(15, 2)], // Hedge rescues
        ];

        for (i, plans) in scenarios.iter().enumerate() {
            let stats = test_delay_scenario_with_stats(plans, Duration::from_nanos(10));

            assert!(
                stats.hedge_wins <= stats.hedged,
                "Scenario {}: hedge wins ({}) cannot exceed hedged requests ({})",
                i,
                stats.hedge_wins,
                stats.hedged
            );
            assert!(
                stats.hedged <= stats.total,
                "Scenario {}: hedged requests ({}) cannot exceed total requests ({})",
                i,
                stats.hedged,
                stats.total
            );
            assert!(
                stats.hedge_wins <= stats.total,
                "Scenario {}: hedge wins ({}) cannot exceed total requests ({})",
                i,
                stats.hedge_wins,
                stats.total
            );
        }

        crate::test_complete!("metamorphic_statistics_consistency");
    }

    /// MR6: Hedge timeout vs instant completion equivalence
    /// Property: requests that complete instantly should behave identically regardless of hedge config
    #[test]
    fn metamorphic_instant_completion_equivalence() {
        init_test("metamorphic_instant_completion_equivalence");

        let instant_plans = vec![TimedPlan::ok_at(0, 99)]; // Instant completion

        // Test with different hedge configurations
        let short_delay_stats =
            test_delay_scenario_with_stats(&instant_plans, Duration::from_nanos(1));
        let long_delay_stats =
            test_delay_scenario_with_stats(&instant_plans, Duration::from_nanos(1000));
        let zero_pending_stats =
            test_delay_scenario_with_max_pending(&instant_plans, Duration::from_nanos(10), 0);

        // All should have same results for instant completion
        assert_eq!(short_delay_stats.total, 1);
        assert_eq!(long_delay_stats.total, 1);
        assert_eq!(zero_pending_stats.total, 1);

        assert_eq!(
            short_delay_stats.hedged, 0,
            "Instant completion should never trigger hedge"
        );
        assert_eq!(
            long_delay_stats.hedged, 0,
            "Instant completion should never trigger hedge"
        );
        assert_eq!(
            zero_pending_stats.hedged, 0,
            "Instant completion should never trigger hedge"
        );

        crate::test_complete!("metamorphic_instant_completion_equivalence");
    }

    /// MR7: Hedge dispatch idempotence under re-polling
    /// Property: multiple polls of the same future after hedge dispatch should be idempotent
    #[test]
    fn metamorphic_hedge_dispatch_idempotence() {
        init_test("metamorphic_hedge_dispatch_idempotence");

        set_test_time(0);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hedge = Hedge::new(
            TimedService::new(
                vec![TimedPlan::ok_at(30, 11), TimedPlan::ok_at(15, 22)],
                Arc::clone(&calls),
            ),
            HedgeConfig::new(Duration::from_nanos(10))
                .max_pending(1)
                .with_time_getter(test_time),
        );

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(hedge.poll_ready(&mut cx), Poll::Ready(Ok(()))));

        let mut future = hedge.call(7);

        // Poll to start primary
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
        let initial_calls = calls.load(Ordering::SeqCst);

        // Advance time to trigger hedge
        set_test_time(10);
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
        let hedge_calls = calls.load(Ordering::SeqCst);

        // Multiple polls after hedge dispatch should not create more requests
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
        let final_calls = calls.load(Ordering::SeqCst);

        assert_eq!(
            hedge_calls,
            initial_calls + 1,
            "Hedge dispatch should create exactly one additional call"
        );
        assert_eq!(
            final_calls, hedge_calls,
            "Re-polling should not create additional calls"
        );

        crate::test_complete!("metamorphic_hedge_dispatch_idempotence");
    }

    // ================================================================
    // Helper functions for metamorphic tests
    // ================================================================

    #[derive(Debug, Clone)]
    struct TestHedgeStats {
        total: u64,
        hedged: u64,
        hedge_wins: u64,
    }

    fn execute_request_sequence(requests: &[u32]) -> TestHedgeStats {
        set_test_time(0);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hedge = Hedge::new(
            TimedService::new(
                vec![TimedPlan::ok_at(5, 42); requests.len()],
                Arc::clone(&calls),
            ),
            HedgeConfig::new(Duration::from_nanos(100)) // Long delay, no hedging
                .max_pending(0)
                .with_time_getter(test_time),
        );

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        for &req in requests {
            assert!(matches!(hedge.poll_ready(&mut cx), Poll::Ready(Ok(()))));
            let mut future = hedge.call(req);
            set_test_time(5);
            let _ = Pin::new(&mut future).poll(&mut cx);
        }

        TestHedgeStats {
            total: hedge.total_requests(),
            hedged: hedge.hedged_requests(),
            hedge_wins: hedge.hedge_wins(),
        }
    }

    fn test_delay_scenario(plans: &[TimedPlan], delay: Duration) -> f64 {
        let stats = test_delay_scenario_with_stats(plans, delay);
        if stats.total == 0 {
            0.0
        } else {
            stats.hedged as f64 / stats.total as f64
        }
    }

    fn test_delay_scenario_with_stats(plans: &[TimedPlan], delay: Duration) -> TestHedgeStats {
        test_delay_scenario_with_max_pending(plans, delay, 1)
    }

    fn test_delay_scenario_with_max_pending(
        plans: &[TimedPlan],
        delay: Duration,
        max_pending: u32,
    ) -> TestHedgeStats {
        set_test_time(0);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hedge = Hedge::new(
            TimedService::new(plans.to_vec(), Arc::clone(&calls)),
            HedgeConfig::new(delay)
                .max_pending(max_pending)
                .with_time_getter(test_time),
        );

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(hedge.poll_ready(&mut cx), Poll::Ready(Ok(()))));

        let mut future = hedge.call(1);

        // Run until completion
        for time_step in 0..50u64 {
            set_test_time(time_step);
            if let Poll::Ready(_) = Pin::new(&mut future).poll(&mut cx) {
                break;
            }
        }

        TestHedgeStats {
            total: hedge.total_requests(),
            hedged: hedge.hedged_requests(),
            hedge_wins: hedge.hedge_wins(),
        }
    }
