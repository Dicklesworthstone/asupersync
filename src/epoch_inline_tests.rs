    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::combinator::{BulkheadPolicy, CircuitBreakerPolicy};
    use crate::time::VirtualClock;
    use futures_lite::future::block_on;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[derive(Debug)]
    struct TestEpochSource {
        current: AtomicU64,
    }

    impl TestEpochSource {
        fn new(epoch: EpochId) -> Self {
            Self {
                current: AtomicU64::new(epoch.as_u64()),
            }
        }

        fn set(&self, epoch: EpochId) {
            self.current.store(epoch.as_u64(), Ordering::Release);
        }
    }

    impl EpochSource for TestEpochSource {
        fn current(&self) -> EpochId {
            EpochId(self.current.load(Ordering::Acquire))
        }
    }

    // Test 1: EpochId ordering and arithmetic
    #[test]
    fn test_epoch_id_ordering() {
        init_test("test_epoch_id_ordering");
        let e1 = EpochId(5);
        let e2 = EpochId(10);

        let before = e1.is_before(e2);
        crate::assert_with_log!(before, "e1 before e2", true, before);
        let after = e2.is_after(e1);
        crate::assert_with_log!(after, "e2 after e1", true, after);
        let same_before = e1.is_before(e1);
        crate::assert_with_log!(!same_before, "e1 before e1", false, same_before);
        let dist12 = e1.distance(e2);
        crate::assert_with_log!(dist12 == 5, "distance 1->2", 5, dist12);
        let dist21 = e2.distance(e1);
        crate::assert_with_log!(dist21 == 5, "distance 2->1", 5, dist21);
        crate::test_complete!("test_epoch_id_ordering");
    }

    // Test 2: EpochId next/prev
    #[test]
    fn test_epoch_id_navigation() {
        init_test("test_epoch_id_navigation");
        let e = EpochId(5);

        crate::assert_with_log!(e.next() == EpochId(6), "next", EpochId(6), e.next());
        crate::assert_with_log!(
            e.prev() == Some(EpochId(4)),
            "prev",
            Some(EpochId(4)),
            e.prev()
        );
        let genesis_prev_none = EpochId::GENESIS.prev().is_none();
        crate::assert_with_log!(
            genesis_prev_none,
            "genesis prev none",
            true,
            genesis_prev_none
        );
        crate::assert_with_log!(
            EpochId::MAX.saturating_next() == EpochId::MAX,
            "max saturating_next",
            EpochId::MAX,
            EpochId::MAX.saturating_next()
        );
        crate::test_complete!("test_epoch_id_navigation");
    }

    // Test 3: EpochConfig validation
    #[test]
    fn test_epoch_config_validation() {
        init_test("test_epoch_config_validation");
        let valid = EpochConfig::default();
        let valid_ok = valid.validate().is_ok();
        crate::assert_with_log!(valid_ok, "valid ok", true, valid_ok);

        let invalid_min = EpochConfig {
            min_duration: Time::from_secs(100),
            target_duration: Time::from_secs(60),
            ..EpochConfig::default()
        };
        let invalid_min_err = invalid_min.validate().is_err();
        crate::assert_with_log!(invalid_min_err, "invalid min err", true, invalid_min_err);

        let invalid_quorum = EpochConfig {
            require_quorum: true,
            quorum_size: 0,
            ..EpochConfig::default()
        };
        let invalid_quorum_err = invalid_quorum.validate().is_err();
        crate::assert_with_log!(
            invalid_quorum_err,
            "invalid quorum err",
            true,
            invalid_quorum_err
        );
        crate::test_complete!("test_epoch_config_validation");
    }

    // Test 4: Epoch lifecycle
    #[test]
    fn test_epoch_lifecycle() {
        init_test("test_epoch_lifecycle");
        let config = EpochConfig::default();
        let mut epoch = Epoch::new(EpochId(1), Time::from_millis(0), config);

        crate::assert_with_log!(
            epoch.state == EpochState::Active,
            "state active",
            EpochState::Active,
            epoch.state
        );
        let active = epoch.state.is_active();
        crate::assert_with_log!(active, "is_active", true, active);

        epoch.begin_ending(Time::from_secs(60)).unwrap();
        crate::assert_with_log!(
            epoch.state == EpochState::Ending,
            "state ending",
            EpochState::Ending,
            epoch.state
        );
        let allows = epoch.state.allows_completion();
        crate::assert_with_log!(allows, "allows completion", true, allows);

        epoch.complete(Time::from_secs(70)).unwrap();
        crate::assert_with_log!(
            epoch.state == EpochState::Ended,
            "state ended",
            EpochState::Ended,
            epoch.state
        );
        let terminal = epoch.state.is_terminal();
        crate::assert_with_log!(terminal, "terminal", true, terminal);
        crate::test_complete!("test_epoch_lifecycle");
    }

    // Test 5: Epoch transition timing
    #[test]
    fn test_epoch_transition_timing() {
        init_test("test_epoch_transition_timing");
        let config = EpochConfig {
            min_duration: Time::from_secs(30),
            target_duration: Time::from_secs(60),
            max_duration: Time::from_secs(120),
            ..EpochConfig::default()
        };
        let epoch = Epoch::new(EpochId(1), Time::from_secs(0), config);

        // Before min duration
        let can = epoch.can_transition(Time::from_secs(20));
        crate::assert_with_log!(!can, "before min", false, can);

        // After min duration
        let can = epoch.can_transition(Time::from_secs(40));
        crate::assert_with_log!(can, "after min", true, can);

        // Not overdue yet
        let overdue = epoch.is_overdue(Time::from_secs(100));
        crate::assert_with_log!(!overdue, "not overdue", false, overdue);

        // Overdue
        let overdue = epoch.is_overdue(Time::from_secs(130));
        crate::assert_with_log!(overdue, "overdue", true, overdue);
        crate::test_complete!("test_epoch_transition_timing");
    }

    // Test 6: SymbolValidityWindow contains
    #[test]
    fn test_validity_window_contains() {
        init_test("test_validity_window_contains");
        let window = SymbolValidityWindow::new(EpochId(4), EpochId(10));

        let contains4 = window.contains(EpochId(4));
        crate::assert_with_log!(contains4, "contains 4", true, contains4);
        let contains5 = window.contains(EpochId(5));
        crate::assert_with_log!(contains5, "contains 5", true, contains5);
        let contains7 = window.contains(EpochId(7));
        crate::assert_with_log!(contains7, "contains 7", true, contains7);
        let contains10 = window.contains(EpochId(10));
        crate::assert_with_log!(contains10, "contains 10", true, contains10);
        let contains11 = window.contains(EpochId(11));
        crate::assert_with_log!(!contains11, "contains 11", false, contains11);
        crate::test_complete!("test_validity_window_contains");
    }

    // Test 7: SymbolValidityWindow overlap
    #[test]
    fn test_validity_window_overlap() {
        init_test("test_validity_window_overlap");
        let w1 = SymbolValidityWindow::new(EpochId(1), EpochId(5));
        let w2 = SymbolValidityWindow::new(EpochId(4), EpochId(8));
        let w3 = SymbolValidityWindow::new(EpochId(6), EpochId(10));

        let w1_w2 = w1.overlaps(&w2);
        crate::assert_with_log!(w1_w2, "w1 overlaps w2", true, w1_w2);
        let w2_w1 = w2.overlaps(&w1);
        crate::assert_with_log!(w2_w1, "w2 overlaps w1", true, w2_w1);
        let w1_w3 = w1.overlaps(&w3);
        crate::assert_with_log!(!w1_w3, "w1 overlaps w3", false, w1_w3);

        let intersection = w1.intersection(&w2);
        crate::assert_with_log!(
            intersection == Some(SymbolValidityWindow::new(EpochId(4), EpochId(5))),
            "intersection",
            Some(SymbolValidityWindow::new(EpochId(4), EpochId(5))),
            intersection
        );
        crate::test_complete!("test_validity_window_overlap");
    }

    // Test 8: SymbolValidityWindow special constructors
    #[test]
    fn test_validity_window_constructors() {
        init_test("test_validity_window_constructors");
        let single = SymbolValidityWindow::single(EpochId(5));
        let span = single.span();
        crate::assert_with_log!(span == 1, "single span", 1, span);
        let contains5 = single.contains(EpochId(5));
        crate::assert_with_log!(contains5, "contains 5", true, contains5);
        let contains4 = single.contains(EpochId(4));
        crate::assert_with_log!(!contains4, "contains 4", false, contains4);

        let infinite = SymbolValidityWindow::infinite();
        let contains_genesis = infinite.contains(EpochId::GENESIS);
        crate::assert_with_log!(contains_genesis, "contains genesis", true, contains_genesis);
        let contains_max = infinite.contains(EpochId::MAX);
        crate::assert_with_log!(contains_max, "contains max", true, contains_max);

        let from = SymbolValidityWindow::from_epoch(EpochId(5));
        let contains4 = from.contains(EpochId(4));
        crate::assert_with_log!(!contains4, "from contains 4", false, contains4);
        let contains5 = from.contains(EpochId(5));
        crate::assert_with_log!(contains5, "from contains 5", true, contains5);
        let contains_max = from.contains(EpochId::MAX);
        crate::assert_with_log!(contains_max, "from contains max", true, contains_max);
        crate::test_complete!("test_validity_window_constructors");
    }

    // Test 9: EpochBarrier basic operation
    #[test]
    fn test_epoch_barrier_basic() {
        init_test("test_epoch_barrier_basic");
        let barrier = EpochBarrier::new(EpochId(1), 3, Time::from_nanos(1_000_000_000));

        let remaining = barrier.remaining();
        crate::assert_with_log!(remaining == 3, "remaining", 3, remaining);
        let triggered = barrier.is_triggered();
        crate::assert_with_log!(!triggered, "triggered", false, triggered);

        barrier.arrive("node1", Time::from_secs(1)).unwrap();
        let arrived = barrier.arrived();
        crate::assert_with_log!(arrived == 1, "arrived", 1, arrived);
        let remaining = barrier.remaining();
        crate::assert_with_log!(remaining == 2, "remaining", 2, remaining);

        barrier.arrive("node2", Time::from_secs(2)).unwrap();
        let arrived = barrier.arrived();
        crate::assert_with_log!(arrived == 2, "arrived", 2, arrived);

        let result = barrier.arrive("node3", Time::from_secs(3)).unwrap();
        let some = result.is_some();
        crate::assert_with_log!(some, "result some", true, some);
        let trigger = result.unwrap().trigger;
        crate::assert_with_log!(
            trigger == BarrierTrigger::AllArrived,
            "trigger",
            BarrierTrigger::AllArrived,
            trigger
        );
        let triggered = barrier.is_triggered();
        crate::assert_with_log!(triggered, "triggered", true, triggered);
        crate::test_complete!("test_epoch_barrier_basic");
    }

    // Test 10: EpochBarrier duplicate arrival
    #[test]
    fn test_epoch_barrier_duplicate() {
        init_test("test_epoch_barrier_duplicate");
        let barrier = EpochBarrier::new(EpochId(1), 2, Time::from_nanos(1_000_000_000));

        barrier.arrive("node1", Time::from_secs(1)).unwrap();

        // Duplicate arrival should fail
        let result = barrier.arrive("node1", Time::from_secs(2));
        let err = result.is_err();
        crate::assert_with_log!(err, "duplicate err", true, err);
        crate::test_complete!("test_epoch_barrier_duplicate");
    }

    // Test 11: EpochBarrier timeout
    #[test]
    fn test_epoch_barrier_timeout() {
        init_test("test_epoch_barrier_timeout");
        let barrier = EpochBarrier::new(EpochId(1), 3, Time::from_nanos(1_000_000_000))
            .with_timeout(Time::from_secs(10));

        barrier.arrive("node1", Time::from_secs(1)).unwrap();

        // Arrival after timeout
        let result = barrier.arrive("node2", Time::from_secs(15)).unwrap();
        let some = result.is_some();
        crate::assert_with_log!(some, "result some", true, some);
        let trigger = result.unwrap().trigger;
        crate::assert_with_log!(
            trigger == BarrierTrigger::Timeout,
            "trigger",
            BarrierTrigger::Timeout,
            trigger
        );
        crate::test_complete!("test_epoch_barrier_timeout");
    }

    // Test 12: EpochClock advance
    #[test]
    fn test_epoch_clock_advance() {
        init_test("test_epoch_clock_advance");
        let config = EpochConfig::short_lived();
        let min_duration_ns = config.min_duration.as_nanos();
        let clock = EpochClock::new(config);
        let started_at = Time::from_nanos(1_000_000_000);
        clock.initialize(started_at);

        crate::assert_with_log!(
            clock.current() == EpochId::GENESIS,
            "current genesis",
            EpochId::GENESIS,
            clock.current()
        );

        // Advance after minimum duration
        let new_epoch = clock
            .advance(started_at.saturating_add_nanos(min_duration_ns.saturating_add(1)))
            .unwrap();
        crate::assert_with_log!(new_epoch == EpochId(1), "new epoch", EpochId(1), new_epoch);
        crate::assert_with_log!(
            clock.current() == EpochId(1),
            "current",
            EpochId(1),
            clock.current()
        );
        crate::test_complete!("test_epoch_clock_advance");
    }

    // Test 13: EpochClock history retention
    #[test]
    fn test_epoch_clock_history() {
        init_test("test_epoch_clock_history");
        let config = EpochConfig {
            min_duration: Time::from_millis(10),
            target_duration: Time::from_millis(50),
            max_duration: Time::from_millis(100),
            retention_epochs: 3,
            ..EpochConfig::default()
        };
        let min_duration_ns = config.min_duration.as_nanos();
        let clock = EpochClock::new(config);
        let mut now = Time::from_nanos(1_000_000_000);
        clock.initialize(now);

        // Advance through multiple epochs
        for _ in 1..=5 {
            now = now.saturating_add_nanos(min_duration_ns.saturating_add(1));
            clock.advance(now).unwrap();
        }

        let history = clock.history();
        let within = history.len() <= 3;
        crate::assert_with_log!(within, "history len <= 3", true, within);
        crate::test_complete!("test_epoch_clock_history");
    }

    // Test 14: EpochError display
    #[test]
    fn test_epoch_error_display() {
        init_test("test_epoch_error_display");
        let expired = EpochError::Expired { epoch: EpochId(5) };
        let expired_str = expired.to_string();
        let has_num = expired_str.contains('5');
        crate::assert_with_log!(has_num, "contains 5", true, has_num);
        let has_expired = expired_str.contains("expired");
        crate::assert_with_log!(has_expired, "contains expired", true, has_expired);

        let transition = EpochError::TransitionOccurred {
            from: EpochId(1),
            to: EpochId(2),
        };
        let transition_str = transition.to_string();
        let has_transition = transition_str.contains("transition");
        crate::assert_with_log!(has_transition, "contains transition", true, has_transition);
        crate::test_complete!("test_epoch_error_display");
    }

    // Test 15: Epoch metadata
    #[test]
    fn test_epoch_metadata() {
        init_test("test_epoch_metadata");
        let config = EpochConfig::default();
        let mut epoch = Epoch::new(EpochId(1), Time::from_nanos(1_000_000_000), config);

        epoch.set_metadata("version", "1.0.0");
        epoch.set_metadata("leader", "node-1");

        let expected_version = "1.0.0".to_string();
        let expected_leader = "node-1".to_string();
        let version = epoch.metadata.get("version");
        crate::assert_with_log!(
            version == Some(&expected_version),
            "version",
            Some(&expected_version),
            version
        );
        let leader = epoch.metadata.get("leader");
        crate::assert_with_log!(
            leader == Some(&expected_leader),
            "leader",
            Some(&expected_leader),
            leader
        );
        crate::test_complete!("test_epoch_metadata");
    }

    // Test 16: EpochContext budget tracking
    #[test]
    fn test_epoch_context_budget() {
        init_test("test_epoch_context_budget");
        let ctx = EpochContext::new(
            EpochId(1),
            Time::from_nanos(1_000_000_000),
            Time::from_secs(10),
        )
        .with_operation_budget(1);
        let first = ctx.record_operation();
        crate::assert_with_log!(first, "first record", true, first);
        let second = ctx.record_operation();
        crate::assert_with_log!(!second, "second record", false, second);
        let exhausted = ctx.is_budget_exhausted();
        crate::assert_with_log!(exhausted, "exhausted", true, exhausted);
        let used = ctx.operations_used();
        crate::assert_with_log!(used == 1, "operations used", 1, used);
        crate::test_complete!("test_epoch_context_budget");
    }

    // Test 17: EpochScoped expires when past deadline
    #[test]
    fn test_epoch_scoped_expired() {
        init_test("test_epoch_scoped_expired");
        let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(5)));
        let epoch = EpochContext::new(
            EpochId(1),
            Time::from_nanos(1_000_000_000),
            Time::from_secs(1),
        );
        let source = Arc::new(TestEpochSource::new(EpochId(1)));
        let policy = EpochPolicy::strict();

        let fut = EpochScoped::new(Box::pin(async { 42u32 }), epoch, policy, clock, source);
        let result = block_on(fut);
        let expired = matches!(result, Err(EpochError::Expired { .. }));
        crate::assert_with_log!(expired, "expired", true, expired);
        crate::test_complete!("test_epoch_scoped_expired");
    }

    // Test 18: EpochScoped detects transitions
    #[test]
    fn test_epoch_scoped_transition() {
        init_test("test_epoch_scoped_transition");
        let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(1_000_000_000)));
        let source = Arc::new(TestEpochSource::new(EpochId(1)));
        source.set(EpochId(2));

        let epoch = EpochContext::new(
            EpochId(1),
            Time::from_nanos(1_000_000_000),
            Time::from_secs(10),
        );
        let policy = EpochPolicy::strict();
        let fut = EpochScoped::new(Box::pin(async { 7u8 }), epoch, policy, clock, source);
        let result = block_on(fut);
        let transitioned = matches!(result, Err(EpochError::TransitionOccurred { .. }));
        crate::assert_with_log!(transitioned, "transitioned", true, transitioned);
        crate::test_complete!("test_epoch_scoped_transition");
    }

    // Test 19: Epoch-select completes left branch
    #[test]
    fn test_epoch_select_left() {
        init_test("test_epoch_select_left");
        let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(1_000_000_000)));
        let source = Arc::new(TestEpochSource::new(EpochId(1)));
        let epoch = EpochContext::new(
            EpochId(1),
            Time::from_nanos(1_000_000_000),
            Time::from_secs(10),
        );
        let policy = EpochPolicy::strict();

        let fut = epoch_select(
            Box::pin(async { 1u8 }),
            Box::pin(async { 2u8 }),
            epoch,
            policy,
            clock,
            source,
        );
        let result = block_on(fut);
        let ok = matches!(result, Ok(Either::Left(Ok(1))));
        crate::assert_with_log!(ok, "epoch_select left result", true, ok);
        crate::test_complete!("test_epoch_select_left");
    }

    // Test 20: Bulkhead/CircuitBreaker epoch wrappers
    #[test]
    fn test_epoch_wrapped_bulkhead_and_circuit_breaker() {
        init_test("test_epoch_wrapped_bulkhead_and_circuit_breaker");

        let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(1_000_000_000)));
        let epoch_source = Arc::new(TestEpochSource::new(EpochId(1)));
        let policy = EpochPolicy::strict();
        let epoch_ctx = EpochContext::new(
            EpochId(1),
            Time::from_nanos(1_000_000_000),
            Time::from_secs(10),
        );

        let bulkhead = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            ..Default::default()
        });
        let breaker = CircuitBreaker::new(CircuitBreakerPolicy::default());

        let bulkhead_result = bulkhead_call_in_epoch(
            &bulkhead,
            &epoch_ctx,
            &policy,
            &*clock,
            &*epoch_source,
            || Ok::<_, &str>(5u32),
        )
        .expect("bulkhead call should succeed");
        crate::assert_with_log!(bulkhead_result == 5, "bulkhead result", 5, bulkhead_result);

        let breaker_result = circuit_breaker_call_in_epoch(
            &breaker,
            &epoch_ctx,
            &policy,
            &*clock,
            &*epoch_source,
            || Ok::<_, &str>(9u32),
        )
        .expect("circuit breaker call should succeed");
        crate::assert_with_log!(breaker_result == 9, "breaker result", 9, breaker_result);
        crate::test_complete!("test_epoch_wrapped_bulkhead_and_circuit_breaker");
    }

    // ============================================================================
    // Additional Epoch Tests (asupersync-ups)
    // ============================================================================

    // Test 21: EpochId overflow handling (saturating at MAX)
    #[test]
    fn test_epoch_id_overflow_saturation() {
        init_test("test_epoch_id_overflow_saturation");
        let max_epoch = EpochId::MAX;

        // saturating_next should stay at MAX
        let saturated = max_epoch.saturating_next();
        crate::assert_with_log!(
            saturated == EpochId::MAX,
            "saturating_next at MAX",
            EpochId::MAX,
            saturated
        );

        // Multiple saturating_next calls should all return MAX
        let double_saturated = saturated.saturating_next();
        crate::assert_with_log!(
            double_saturated == EpochId::MAX,
            "double saturating_next",
            EpochId::MAX,
            double_saturated
        );

        crate::test_complete!("test_epoch_id_overflow_saturation");
    }

    // Test 22: EpochId next overflow panic
    #[test]
    #[should_panic(expected = "EpochId overflow")]
    fn test_epoch_id_next_overflow_panics() {
        init_test("test_epoch_id_next_overflow_panics");
        let max_epoch = EpochId::MAX;
        // This should panic due to overflow
        let _ = max_epoch.next();
    }

    // Test 23: EpochBarrier force trigger
    #[test]
    fn test_epoch_barrier_force_trigger() {
        init_test("test_epoch_barrier_force_trigger");
        let barrier = EpochBarrier::new(EpochId(1), 5, Time::from_nanos(1_000_000_000));

        // Only one participant arrived
        barrier.arrive("node1", Time::from_secs(1)).unwrap();
        let arrived = barrier.arrived();
        crate::assert_with_log!(arrived == 1, "arrived before force", 1, arrived);

        // Force trigger before all arrive
        let result = barrier.force_trigger(Time::from_secs(2));
        crate::assert_with_log!(
            result.trigger == BarrierTrigger::Forced,
            "trigger type",
            BarrierTrigger::Forced,
            result.trigger
        );
        crate::assert_with_log!(result.arrived == 1, "arrived in result", 1, result.arrived);
        crate::assert_with_log!(
            result.expected == 5,
            "expected in result",
            5,
            result.expected
        );

        // Barrier should now be triggered
        let triggered = barrier.is_triggered();
        crate::assert_with_log!(triggered, "is_triggered", true, triggered);

        crate::test_complete!("test_epoch_barrier_force_trigger");
    }

    // Test 24: EpochBarrier cancel
    #[test]
    fn test_epoch_barrier_cancel() {
        init_test("test_epoch_barrier_cancel");
        let barrier = EpochBarrier::new(EpochId(2), 3, Time::from_nanos(1_000_000_000));

        barrier.arrive("node1", Time::from_secs(1)).unwrap();
        barrier.arrive("node2", Time::from_secs(2)).unwrap();

        // Cancel before all arrive
        let result = barrier.cancel(Time::from_secs(3));
        crate::assert_with_log!(
            result.trigger == BarrierTrigger::Cancelled,
            "trigger type",
            BarrierTrigger::Cancelled,
            result.trigger
        );
        crate::assert_with_log!(result.arrived == 2, "arrived", 2, result.arrived);

        // Further arrivals should fail since barrier is triggered
        let late_arrival = barrier.arrive("node3", Time::from_secs(4));
        let err = late_arrival.is_err();
        crate::assert_with_log!(err, "late arrival err", true, err);

        crate::test_complete!("test_epoch_barrier_cancel");
    }

    // Test 25: EpochClock advance before minimum duration fails
    #[test]
    fn test_epoch_clock_advance_too_early() {
        init_test("test_epoch_clock_advance_too_early");
        let config = EpochConfig {
            min_duration: Time::from_secs(30),
            target_duration: Time::from_secs(60),
            max_duration: Time::from_secs(120),
            ..EpochConfig::default()
        };
        let clock = EpochClock::new(config);
        clock.initialize(Time::from_nanos(1_000_000_000));

        // Try to advance before minimum duration
        let result = clock.advance(Time::from_secs(10));
        let err = result.is_err();
        crate::assert_with_log!(err, "advance too early err", true, err);

        // Epoch should still be GENESIS
        crate::assert_with_log!(
            clock.current() == EpochId::GENESIS,
            "still genesis",
            EpochId::GENESIS,
            clock.current()
        );

        crate::test_complete!("test_epoch_clock_advance_too_early");
    }

    // Test 26: EpochClock advance when overdue
    #[test]
    fn test_epoch_clock_advance_overdue() {
        init_test("test_epoch_clock_advance_overdue");
        let config = EpochConfig {
            min_duration: Time::from_secs(30),
            target_duration: Time::from_secs(60),
            max_duration: Time::from_secs(120),
            ..EpochConfig::default()
        };
        let clock = EpochClock::new(config);
        clock.initialize(Time::from_nanos(1_000_000_000));

        // Advance when overdue (past max_duration) - should succeed
        let result = clock.advance(Time::from_secs(150));
        let ok = result.is_ok();
        crate::assert_with_log!(ok, "advance when overdue ok", true, ok);
        crate::assert_with_log!(
            clock.current() == EpochId(1),
            "advanced to epoch 1",
            EpochId(1),
            clock.current()
        );

        crate::test_complete!("test_epoch_clock_advance_overdue");
    }

    // Test 27: EpochContext expiry check
    #[test]
    fn test_epoch_context_expiry() {
        init_test("test_epoch_context_expiry");
        let ctx = EpochContext::new(
            EpochId(1),
            Time::from_nanos(1_000_000_000),
            Time::from_secs(10),
        );

        // Not expired before deadline
        let expired_before = ctx.is_expired(Time::from_secs(5));
        crate::assert_with_log!(!expired_before, "not expired at t=5", false, expired_before);

        // Expired at deadline
        let expired_at = ctx.is_expired(Time::from_secs(10));
        crate::assert_with_log!(expired_at, "expired at t=10", true, expired_at);

        // Expired after deadline
        let expired_after = ctx.is_expired(Time::from_secs(15));
        crate::assert_with_log!(expired_after, "expired at t=15", true, expired_after);

        // Check remaining time
        let remaining = ctx.remaining_time(Time::from_secs(3));
        crate::assert_with_log!(
            remaining == Some(Duration::from_secs(7)),
            "remaining at t=3",
            Some(Duration::from_secs(7)),
            remaining
        );

        let no_remaining = ctx.remaining_time(Time::from_secs(12));
        crate::assert_with_log!(
            no_remaining.is_none(),
            "no remaining at t=12",
            true,
            no_remaining.is_none()
        );

        crate::test_complete!("test_epoch_context_expiry");
    }

    // Test 28: SymbolValidityWindow extend_to
    #[test]
    fn test_validity_window_extend() {
        init_test("test_validity_window_extend");
        let window = SymbolValidityWindow::new(EpochId(5), EpochId(10));

        // Extend to include earlier epoch
        let extended_earlier = window.extend_to(EpochId(2));
        crate::assert_with_log!(
            extended_earlier.start == EpochId(2),
            "extended start",
            EpochId(2),
            extended_earlier.start
        );
        crate::assert_with_log!(
            extended_earlier.end == EpochId(10),
            "extended end unchanged",
            EpochId(10),
            extended_earlier.end
        );

        // Extend to include later epoch
        let extended_later = window.extend_to(EpochId(15));
        crate::assert_with_log!(
            extended_later.start == EpochId(5),
            "extended start unchanged",
            EpochId(5),
            extended_later.start
        );
        crate::assert_with_log!(
            extended_later.end == EpochId(15),
            "extended end",
            EpochId(15),
            extended_later.end
        );

        // Extend to epoch already in window (no change)
        let no_change = window.extend_to(EpochId(7));
        crate::assert_with_log!(
            no_change == window,
            "no change for contained epoch",
            window,
            no_change
        );

        crate::test_complete!("test_validity_window_extend");
    }

    // Test 29: Epoch state predicates comprehensive
    #[test]
    fn test_epoch_state_predicates_comprehensive() {
        init_test("test_epoch_state_predicates_comprehensive");

        // Preparing state
        let preparing = EpochState::Preparing;
        crate::assert_with_log!(
            !preparing.is_active(),
            "preparing not active",
            false,
            preparing.is_active()
        );
        crate::assert_with_log!(
            !preparing.is_terminal(),
            "preparing not terminal",
            false,
            preparing.is_terminal()
        );
        crate::assert_with_log!(
            !preparing.allows_completion(),
            "preparing not allows_completion",
            false,
            preparing.allows_completion()
        );

        // Active state
        let active = EpochState::Active;
        crate::assert_with_log!(
            active.is_active(),
            "active is_active",
            true,
            active.is_active()
        );
        crate::assert_with_log!(
            !active.is_terminal(),
            "active not terminal",
            false,
            active.is_terminal()
        );
        crate::assert_with_log!(
            active.allows_completion(),
            "active allows_completion",
            true,
            active.allows_completion()
        );

        // Ending state
        let ending = EpochState::Ending;
        crate::assert_with_log!(
            !ending.is_active(),
            "ending not active",
            false,
            ending.is_active()
        );
        crate::assert_with_log!(
            !ending.is_terminal(),
            "ending not terminal",
            false,
            ending.is_terminal()
        );
        crate::assert_with_log!(
            ending.allows_completion(),
            "ending allows_completion",
            true,
            ending.allows_completion()
        );

        // Ended state
        let ended = EpochState::Ended;
        crate::assert_with_log!(
            !ended.is_active(),
            "ended not active",
            false,
            ended.is_active()
        );
        crate::assert_with_log!(
            ended.is_terminal(),
            "ended is_terminal",
            true,
            ended.is_terminal()
        );
        crate::assert_with_log!(
            !ended.allows_completion(),
            "ended not allows_completion",
            false,
            ended.allows_completion()
        );

        crate::test_complete!("test_epoch_state_predicates_comprehensive");
    }

    // Test 30: Epoch operation counting
    #[test]
    fn test_epoch_operation_counting() {
        init_test("test_epoch_operation_counting");
        let config = EpochConfig::default();
        let mut epoch = Epoch::new(EpochId(1), Time::from_nanos(1_000_000_000), config);

        crate::assert_with_log!(
            epoch.operation_count == 0,
            "initial count",
            0,
            epoch.operation_count
        );

        epoch.record_operation();
        crate::assert_with_log!(
            epoch.operation_count == 1,
            "after first",
            1,
            epoch.operation_count
        );

        epoch.record_operation();
        epoch.record_operation();
        crate::assert_with_log!(
            epoch.operation_count == 3,
            "after three",
            3,
            epoch.operation_count
        );

        crate::test_complete!("test_epoch_operation_counting");
    }

    // Test 31: Epoch remaining time calculation
    #[test]
    fn test_epoch_remaining_time() {
        init_test("test_epoch_remaining_time");
        let config = EpochConfig {
            target_duration: Time::from_secs(100),
            ..EpochConfig::default()
        };
        let mut epoch = Epoch::new(EpochId(1), Time::from_secs(10), config);

        // Active epoch - duration is elapsed time
        let duration_active = epoch.duration(Time::from_secs(25));
        crate::assert_with_log!(
            duration_active == Duration::from_secs(15),
            "active duration",
            Duration::from_secs(15),
            duration_active
        );

        // Complete the epoch
        epoch.begin_ending(Time::from_secs(50)).unwrap();
        epoch.complete(Time::from_secs(60)).unwrap();

        // Completed epoch - duration is fixed
        let duration_ended = epoch.duration(Time::from_secs(100));
        crate::assert_with_log!(
            duration_ended == Duration::from_secs(50),
            "ended duration",
            Duration::from_secs(50),
            duration_ended
        );

        crate::test_complete!("test_epoch_remaining_time");
    }

    // Test 32: EpochPolicy variants
    #[test]
    fn test_epoch_policy_variants() {
        init_test("test_epoch_policy_variants");

        let strict = EpochPolicy::strict();
        crate::assert_with_log!(
            strict.on_transition == EpochTransitionBehavior::AbortAll,
            "strict aborts",
            EpochTransitionBehavior::AbortAll,
            strict.on_transition
        );
        crate::assert_with_log!(
            strict.check_on_poll,
            "strict checks",
            true,
            strict.check_on_poll
        );

        let lenient = EpochPolicy::lenient();
        crate::assert_with_log!(
            lenient.on_transition == EpochTransitionBehavior::DrainExecuting,
            "lenient drains",
            EpochTransitionBehavior::DrainExecuting,
            lenient.on_transition
        );
        crate::assert_with_log!(
            !lenient.check_on_poll,
            "lenient no check",
            false,
            lenient.check_on_poll
        );
        crate::assert_with_log!(
            lenient.grace_period.is_some(),
            "lenient has grace",
            true,
            lenient.grace_period.is_some()
        );

        let ignore = EpochPolicy::ignore();
        crate::assert_with_log!(
            ignore.on_transition == EpochTransitionBehavior::Ignore,
            "ignore ignores",
            EpochTransitionBehavior::Ignore,
            ignore.on_transition
        );
        crate::assert_with_log!(
            !ignore.propagate_to_children,
            "ignore no propagate",
            false,
            ignore.propagate_to_children
        );

        crate::test_complete!("test_epoch_policy_variants");
    }

    // ========================================================================
    // Pure data-type trait coverage (wave 24)
    // ========================================================================

    #[test]
    fn epoch_id_debug_format() {
        let id = EpochId::new(42);
        let dbg = format!("{id:?}");
        assert!(dbg.contains("42"), "Debug should show value: {dbg}");
    }

    #[test]
    fn epoch_id_display_format() {
        let id = EpochId::new(7);
        let disp = format!("{id}");
        assert_eq!(disp, "Epoch(7)");
    }

    #[test]
    fn epoch_id_from_conversions() {
        let id: EpochId = 99u64.into();
        assert_eq!(id, EpochId::new(99));
        let raw: u64 = id.into();
        assert_eq!(raw, 99);
        assert_eq!(id.as_u64(), 99);
    }

    #[test]
    fn epoch_id_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(EpochId::new(1));
        set.insert(EpochId::new(2));
        set.insert(EpochId::new(1)); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn epoch_id_constants() {
        assert_eq!(EpochId::GENESIS, EpochId::new(0));
        assert_eq!(EpochId::MAX, EpochId::new(u64::MAX));
        assert!(EpochId::GENESIS.is_before(EpochId::MAX));
    }

    #[test]
    fn epoch_config_debug_clone() {
        let cfg = EpochConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("EpochConfig"));
        let cfg2 = cfg.clone();
        assert_eq!(cfg2.target_duration, cfg.target_duration);
        assert_eq!(cfg2.retention_epochs, cfg.retention_epochs);
    }

    #[test]
    fn epoch_config_short_lived_values() {
        let cfg = EpochConfig::short_lived();
        assert_eq!(cfg.target_duration, Time::from_millis(100));
        assert_eq!(cfg.min_duration, Time::from_millis(50));
        assert_eq!(cfg.max_duration, Time::from_millis(200));
        assert_eq!(cfg.retention_epochs, 5);
        assert!(!cfg.require_quorum);
    }

    #[test]
    fn epoch_config_long_lived_values() {
        let cfg = EpochConfig::long_lived();
        assert_eq!(cfg.target_duration, Time::from_secs(300));
        assert_eq!(cfg.min_duration, Time::from_secs(120));
        assert!(cfg.require_quorum);
        assert_eq!(cfg.quorum_size, 3);
    }

    #[test]
    fn epoch_config_validate_target_exceeds_max() {
        let cfg = EpochConfig {
            target_duration: Time::from_secs(200),
            max_duration: Time::from_secs(100),
            ..EpochConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn epoch_state_debug_clone_copy() {
        let s = EpochState::Active;
        let s2 = s; // Copy
        let s3 = s; // Copy again
        assert_eq!(s2, s3);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Active"));
    }

    #[test]
    fn epoch_debug_clone() {
        let cfg = EpochConfig::default();
        let epoch = Epoch::new(EpochId::new(5), Time::from_secs(10), cfg);
        let dbg = format!("{epoch:?}");
        assert!(dbg.contains("Epoch"));
        let epoch2 = epoch;
        assert_eq!(epoch2.id, EpochId::new(5));
        assert_eq!(epoch2.state, EpochState::Active);
    }

    #[test]
    fn epoch_genesis_constructor() {
        let cfg = EpochConfig::default();
        let epoch = Epoch::genesis(cfg);
        assert_eq!(epoch.id, EpochId::GENESIS);
        assert_eq!(epoch.started_at, Time::from_nanos(1_000_000_000));
        assert_eq!(epoch.state, EpochState::Active);
        assert_eq!(epoch.operation_count, 0);
    }

    #[test]
    fn symbol_validity_window_default_is_infinite() {
        let w = SymbolValidityWindow::default();
        assert_eq!(w.start, EpochId::GENESIS);
        assert_eq!(w.end, EpochId::MAX);
        assert!(w.contains(EpochId::new(1_000_000)));
    }

    #[test]
    fn symbol_validity_window_until_epoch() {
        let w = SymbolValidityWindow::until_epoch(EpochId::new(10));
        assert_eq!(w.start, EpochId::GENESIS);
        assert_eq!(w.end, EpochId::new(10));
        assert!(w.contains(EpochId::new(0)));
        assert!(w.contains(EpochId::new(10)));
        assert!(!w.contains(EpochId::new(11)));
    }

    #[test]
    fn symbol_validity_window_span_multi() {
        let w = SymbolValidityWindow::new(EpochId::new(3), EpochId::new(7));
        assert_eq!(w.span(), 5); // 3,4,5,6,7
    }

    #[test]
    fn barrier_trigger_debug_clone_eq() {
        let t = BarrierTrigger::AllArrived;
        let t2 = t.clone();
        assert_eq!(t, t2);
        assert!(format!("{t:?}").contains("AllArrived"));

        assert_ne!(BarrierTrigger::Timeout, BarrierTrigger::Cancelled);
        assert_ne!(BarrierTrigger::Forced, BarrierTrigger::AllArrived);
    }

    #[test]
    fn barrier_result_debug_clone_eq() {
        let r = BarrierResult {
            trigger: BarrierTrigger::AllArrived,
            arrived: 3,
            expected: 3,
            triggered_at: Time::from_secs(10),
        };
        let r2 = r.clone();
        assert_eq!(r, r2);
        assert!(format!("{r:?}").contains("BarrierResult"));
        assert_eq!(r.arrived, 3);
    }

    #[test]
    fn epoch_transition_behavior_default() {
        let b = EpochTransitionBehavior::default();
        assert_eq!(b, EpochTransitionBehavior::AbortAll);
        let b2 = b; // Copy
        assert_eq!(b, b2);
        assert!(format!("{b:?}").contains("AbortAll"));
    }

    #[test]
    fn epoch_error_display_all_variants() {
        let e1 = EpochError::BudgetExhausted {
            epoch: EpochId::new(1),
            budget: 100,
            used: 100,
        };
        let s1 = e1.to_string();
        assert!(s1.contains("budget"), "BudgetExhausted: {s1}");
        assert!(s1.contains("100"));

        let e2 = EpochError::Mismatch {
            expected: EpochId::new(1),
            actual: EpochId::new(2),
        };
        assert!(e2.to_string().contains("mismatch"));

        let e3 = EpochError::ValidityViolation {
            symbol_epoch: EpochId::new(5),
            window: SymbolValidityWindow::new(EpochId::new(1), EpochId::new(3)),
        };
        assert!(e3.to_string().contains("validity"));

        let e4 = EpochError::BarrierTimeout {
            epoch: EpochId::new(1),
            arrived: 2,
            expected: 5,
        };
        let s4 = e4.to_string();
        assert!(s4.contains("barrier") || s4.contains("timeout"), "{s4}");
    }

    #[test]
    fn epoch_error_is_std_error() {
        let e = EpochError::Expired {
            epoch: EpochId::new(1),
        };
        let err: &dyn std::error::Error = &e;
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn epoch_error_clone_eq() {
        let e1 = EpochError::Expired {
            epoch: EpochId::new(3),
        };
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }

    #[test]
    fn epoch_context_debug_clone() {
        let ctx = EpochContext::new(
            EpochId::new(1),
            Time::from_nanos(1_000_000_000),
            Time::from_secs(10),
        );
        let dbg = format!("{ctx:?}");
        assert!(dbg.contains("EpochContext"));
        let ctx2 = ctx;
        assert_eq!(ctx2.epoch_id, EpochId::new(1));
    }

    #[test]
    fn epoch_policy_debug_clone_default() {
        let p = EpochPolicy::default();
        let dbg = format!("{p:?}");
        assert!(dbg.contains("EpochPolicy"));
        let p2 = p;
        assert_eq!(p2.on_transition, EpochTransitionBehavior::AbortAll);
        assert!(p2.check_on_poll);
        assert!(p2.propagate_to_children);
        assert!(p2.grace_period.is_none());
    }
