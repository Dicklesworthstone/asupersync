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

    fn finalizer_policy_table() -> String {
        [
            FinalizerEscalation::Soft,
            FinalizerEscalation::BoundedLog,
            FinalizerEscalation::BoundedPanic,
        ]
        .into_iter()
        .map(|policy| {
            format!(
                "{policy:?}|soft={}|continue={}|polls={}|time_ns={}",
                policy.is_soft(),
                policy.allows_continuation(),
                FINALIZER_POLL_BUDGET,
                FINALIZER_TIME_BUDGET_NANOS
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn finalizer_stack_lifo_order() {
        init_test("finalizer_stack_lifo_order");
        let mut stack = FinalizerStack::new();
        let order = std::sync::Arc::new(Mutex::new(Vec::new()));
        let o1 = order.clone();
        let o2 = order.clone();
        let o3 = order.clone();

        stack.push_sync(move || o1.lock().push(1));
        stack.push_sync(move || o2.lock().push(2));
        stack.push_sync(move || o3.lock().push(3));

        // Pop and execute in LIFO order
        while let Some(finalizer) = stack.pop() {
            if let Finalizer::Sync(f) = finalizer {
                f();
            }
        }

        // Should be 3, 2, 1 (LIFO)
        let order = order.lock().clone();
        crate::assert_with_log!(order == vec![3, 2, 1], "order", vec![3, 2, 1], order);
        crate::test_complete!("finalizer_stack_lifo_order");
    }

    #[test]
    fn finalizer_stack_empty() {
        init_test("finalizer_stack_empty");
        let mut stack = FinalizerStack::new();
        let empty = stack.is_empty();
        crate::assert_with_log!(empty, "empty", true, empty);
        let len = stack.len();
        crate::assert_with_log!(len == 0, "len", 0, len);
        let pop = stack.pop();
        crate::assert_with_log!(pop.is_none(), "pop none", true, pop.is_none());
        crate::test_complete!("finalizer_stack_empty");
    }

    #[test]
    fn finalizer_escalation_policies() {
        init_test("finalizer_escalation_policies");
        let soft = FinalizerEscalation::Soft.is_soft();
        crate::assert_with_log!(soft, "soft is soft", true, soft);
        let log_soft = FinalizerEscalation::BoundedLog.is_soft();
        crate::assert_with_log!(!log_soft, "log not soft", false, log_soft);
        let panic_soft = FinalizerEscalation::BoundedPanic.is_soft();
        crate::assert_with_log!(!panic_soft, "panic not soft", false, panic_soft);

        let log_cont = FinalizerEscalation::BoundedLog.allows_continuation();
        crate::assert_with_log!(log_cont, "log allows", true, log_cont);
        let soft_cont = FinalizerEscalation::Soft.allows_continuation();
        crate::assert_with_log!(!soft_cont, "soft no continue", false, soft_cont);
        let panic_cont = FinalizerEscalation::BoundedPanic.allows_continuation();
        crate::assert_with_log!(!panic_cont, "panic no continue", false, panic_cont);
        crate::test_complete!("finalizer_escalation_policies");
    }

    #[test]
    fn finalizer_timeout_diagnostic_has_asup_e303_prefix() {
        let diagnostic =
            FinalizerTimeoutDiagnostic::for_default_budget(42, FinalizerEscalation::BoundedPanic);
        let rendered = diagnostic.to_string();

        assert!(rendered.starts_with("[ASUP-E303]"), "{rendered}");
        assert!(rendered.contains("finalizer 42"), "{rendered}");
        assert!(rendered.contains("5000000000ns"), "{rendered}");
        assert!(rendered.contains("BoundedPanic"), "{rendered}");
    }

    #[test]
    fn finalizer_budget_has_expected_values() {
        init_test("finalizer_budget_has_expected_values");
        let budget = finalizer_budget();
        crate::assert_with_log!(
            budget.poll_quota == FINALIZER_POLL_BUDGET,
            "poll_quota",
            FINALIZER_POLL_BUDGET,
            budget.poll_quota
        );
        crate::test_complete!("finalizer_budget_has_expected_values");
    }

    #[test]
    fn finalizer_debug_impl() {
        init_test("finalizer_debug_impl");
        let sync_finalizer = Finalizer::Sync(Box::new(|| {}));
        let debug_str = format!("{sync_finalizer:?}");
        let sync_debug_present = debug_str.contains("Sync");
        crate::assert_with_log!(sync_debug_present, "sync debug", true, sync_debug_present);

        let async_finalizer = Finalizer::Async(Box::pin(async {}));
        let debug_str = format!("{async_finalizer:?}");
        let async_debug_present = debug_str.contains("Async");
        crate::assert_with_log!(
            async_debug_present,
            "async debug",
            true,
            async_debug_present
        );
        crate::test_complete!("finalizer_debug_impl");
    }

    // =========================================================================
    // Wave 51 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn finalizer_escalation_debug_clone_copy_eq_default() {
        let e = FinalizerEscalation::BoundedLog;
        let dbg = format!("{e:?}");
        assert!(dbg.contains("BoundedLog"), "{dbg}");
        let copied = e;
        let cloned = e;
        assert_eq!(copied, cloned);
        let def = FinalizerEscalation::default();
        assert_eq!(def, FinalizerEscalation::BoundedLog);
    }

    #[test]
    fn finalizer_stack_debug_default() {
        let stack = FinalizerStack::default();
        let dbg = format!("{stack:?}");
        assert!(dbg.contains("FinalizerStack"), "{dbg}");
        assert!(stack.is_empty());
    }

    #[test]
    fn finalizer_policy_table_snapshot() {
        insta::assert_snapshot!("finalizer_policy_table", finalizer_policy_table());
    }

    // =========================================================================
    // Golden artifact tests for finalizer outputs
    // =========================================================================

    /// Generate structured budget configuration output for golden testing
    fn budget_configuration_table() -> String {
        let budget = finalizer_budget();
        vec![
            format!("poll_quota={}", budget.poll_quota),
            format!("cost_quota={:?}", budget.cost_quota),
            format!("priority={}", budget.priority),
            format!("deadline={:?}", budget.deadline),
            format!("constants.poll_budget={}", FINALIZER_POLL_BUDGET),
            format!("constants.time_budget_ns={}", FINALIZER_TIME_BUDGET_NANOS),
        ]
        .join("\n")
    }

    /// Generate debug representations of finalizers for golden testing
    fn finalizer_debug_representations() -> String {
        let sync_finalizer = Finalizer::Sync(Box::new(|| {}));
        let async_finalizer = Finalizer::Async(Box::pin(async {}));

        vec![
            format!("Sync: {:?}", sync_finalizer),
            format!("Async: {:?}", async_finalizer),
        ]
        .join("\n")
    }

    /// Generate finalizer stack states for golden testing
    fn finalizer_stack_operations() -> String {
        let mut lines = Vec::new();

        // Empty stack
        let mut stack = FinalizerStack::new();
        lines.push(format!(
            "empty_stack: len={}, is_empty={}, escalation={:?}",
            stack.len(),
            stack.is_empty(),
            stack.escalation()
        ));

        // Stack with custom escalation
        let stack_panic = FinalizerStack::with_escalation(FinalizerEscalation::BoundedPanic);
        lines.push(format!(
            "panic_stack: len={}, is_empty={}, escalation={:?}",
            stack_panic.len(),
            stack_panic.is_empty(),
            stack_panic.escalation()
        ));

        // Add finalizers and show progression
        stack.push_sync(|| {});
        lines.push(format!(
            "after_sync_push: len={}, is_empty={}",
            stack.len(),
            stack.is_empty()
        ));

        stack.push_async(async {});
        lines.push(format!(
            "after_async_push: len={}, is_empty={}",
            stack.len(),
            stack.is_empty()
        ));

        stack.push_sync(|| {});
        lines.push(format!(
            "after_second_sync: len={}, is_empty={}",
            stack.len(),
            stack.is_empty()
        ));

        // Pop operations (don't execute, just show types)
        if let Some(finalizer) = stack.pop() {
            match finalizer {
                Finalizer::Sync(_) => lines.push("popped: Sync".to_string()),
                Finalizer::Async(_) => lines.push("popped: Async".to_string()),
            }
        }
        lines.push(format!(
            "after_first_pop: len={}, is_empty={}",
            stack.len(),
            stack.is_empty()
        ));

        if let Some(finalizer) = stack.pop() {
            match finalizer {
                Finalizer::Sync(_) => lines.push("popped: Sync".to_string()),
                Finalizer::Async(_) => lines.push("popped: Async".to_string()),
            }
        }
        lines.push(format!(
            "after_second_pop: len={}, is_empty={}",
            stack.len(),
            stack.is_empty()
        ));

        if let Some(finalizer) = stack.pop() {
            match finalizer {
                Finalizer::Sync(_) => lines.push("popped: Sync".to_string()),
                Finalizer::Async(_) => lines.push("popped: Async".to_string()),
            }
        }
        lines.push(format!(
            "after_third_pop: len={}, is_empty={}",
            stack.len(),
            stack.is_empty()
        ));

        // Test pop from empty
        let empty_pop = stack.pop();
        lines.push(format!(
            "empty_pop: {}",
            if empty_pop.is_none() { "None" } else { "Some" }
        ));

        lines.join("\n")
    }

    /// Generate escalation policy behavior matrix for golden testing
    fn escalation_policy_matrix() -> String {
        let policies = [
            FinalizerEscalation::Soft,
            FinalizerEscalation::BoundedLog,
            FinalizerEscalation::BoundedPanic,
        ];

        let mut lines = Vec::new();
        lines.push("policy|is_soft|allows_continuation|default_match".to_string());

        for policy in policies {
            let is_default = policy == FinalizerEscalation::default();
            lines.push(format!(
                "{:?}|{}|{}|{}",
                policy,
                policy.is_soft(),
                policy.allows_continuation(),
                is_default
            ));
        }

        lines.join("\n")
    }

    /// Generate finalizer stack debug output for golden testing
    fn finalizer_stack_debug_output() -> String {
        let mut lines = Vec::new();

        // Empty stack debug
        let empty_stack = FinalizerStack::new();
        lines.push(format!("empty: {:?}", empty_stack));

        // Stack with escalation debug
        let panic_stack = FinalizerStack::with_escalation(FinalizerEscalation::BoundedPanic);
        lines.push(format!("panic_escalation: {:?}", panic_stack));

        let soft_stack = FinalizerStack::with_escalation(FinalizerEscalation::Soft);
        lines.push(format!("soft_escalation: {:?}", soft_stack));

        lines.join("\n")
    }

    #[test]
    fn finalizer_budget_configuration() {
        insta::assert_snapshot!("budget_configuration", budget_configuration_table());
    }

    #[test]
    fn finalizer_debug_output() {
        insta::assert_snapshot!("debug_representations", finalizer_debug_representations());
    }

    #[test]
    fn finalizer_stack_state_transitions() {
        insta::assert_snapshot!("stack_operations", finalizer_stack_operations());
    }

    #[test]
    fn finalizer_escalation_behavior_matrix() {
        insta::assert_snapshot!("escalation_matrix", escalation_policy_matrix());
    }

    #[test]
    fn finalizer_stack_debug_variants() {
        insta::assert_snapshot!("stack_debug_output", finalizer_stack_debug_output());
    }

    struct BudgetProbe {
        polls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        drops: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        ready_at: Option<usize>,
        panic_poll: bool,
        panic_drop: bool,
        wake_pending: bool,
        advance: Option<(
            std::sync::Arc<crate::time::VirtualClock>,
            crate::types::Time,
        )>,
        update_budget: Option<(ShutdownBudget, Option<Budget>)>,
    }

    impl BudgetProbe {
        fn new(ready_at: Option<usize>) -> Self {
            Self {
                polls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                drops: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                ready_at,
                panic_poll: false,
                panic_drop: false,
                wake_pending: false,
                advance: None,
                update_budget: None,
            }
        }
    }

    impl Future for BudgetProbe {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
            let polled = self.polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            assert!(!self.panic_poll, "budgeted finalizer body panic");
            if let Some((clock, time)) = self.advance.take() {
                clock.advance_to(time);
            }
            if let Some((shared, next)) = self.update_budget.take() {
                *shared.write() = next;
            }
            if self.ready_at == Some(polled) {
                std::task::Poll::Ready(())
            } else {
                if self.wake_pending {
                    cx.waker().wake_by_ref();
                }
                std::task::Poll::Pending
            }
        }
    }

    impl Drop for BudgetProbe {
        fn drop(&mut self) {
            assert_eq!(
                self.drops.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                0
            );
            assert!(!self.panic_drop, "budgeted finalizer destructor panic");
        }
    }

    #[derive(Default)]
    struct BudgetWake(std::sync::atomic::AtomicUsize);

    impl std::task::Wake for BudgetWake {
        fn wake(self: std::sync::Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }

        fn wake_by_ref(self: &std::sync::Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn shutdown_budget(budget: Option<Budget>) -> ShutdownBudget {
        std::sync::Arc::new(parking_lot::RwLock::new(budget))
    }

    #[test]
    fn explicit_finalizer_poll_budget_counts_actual_work_and_retires_once() {
        use crate::types::Outcome;
        use std::sync::atomic::Ordering;
        use std::task::Poll;
        for limit in [0, 1, 3] {
            let mut probe = BudgetProbe::new(None);
            probe.wake_pending = true;
            let polls = probe.polls.clone();
            let drops = probe.drops.clone();
            let mut bounded = BudgetedFinalizer::new(
                Box::pin(probe),
                shutdown_budget(Some(Budget::INFINITE.with_poll_quota(limit))),
                None,
            );
            let wake = std::sync::Arc::new(BudgetWake::default());
            let waker = std::task::Waker::from(wake.clone());
            let mut cx = std::task::Context::from_waker(&waker);
            for _ in 0..limit.saturating_sub(1) {
                assert!(Pin::new(&mut bounded).poll(&mut cx).is_pending());
                assert_eq!(drops.load(Ordering::SeqCst), 0);
            }
            assert_eq!(
                Pin::new(&mut bounded).poll(&mut cx),
                Poll::Ready(Outcome::Err(FinalizerBudgetError::PollQuota {
                    limit,
                    polled: limit
                }))
            );
            assert_eq!(polls.load(Ordering::SeqCst), limit as usize);
            assert_eq!(wake.0.load(Ordering::SeqCst), limit as usize);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            drop(bounded);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }
        // Ready on the last permitted user poll is real successful cleanup.
        for limit in [1, 3] {
            let probe = BudgetProbe::new(Some(limit as usize));
            let polls = probe.polls.clone();
            let drops = probe.drops.clone();
            let mut bounded = BudgetedFinalizer::new(
                Box::pin(probe),
                shutdown_budget(Some(Budget::INFINITE.with_poll_quota(limit))),
                None,
            );
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            for _ in 1..limit {
                assert!(Pin::new(&mut bounded).poll(&mut cx).is_pending());
            }
            assert_eq!(
                Pin::new(&mut bounded).poll(&mut cx),
                Poll::Ready(Outcome::Ok(()))
            );
            assert_eq!(polls.load(Ordering::SeqCst), limit as usize);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            drop(bounded);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn explicit_finalizer_deadline_owns_real_wake_and_refuses_missing_clock() {
        use crate::time::{TimerDriverHandle, VirtualClock};
        use crate::types::{Outcome, Time};
        use std::sync::atomic::Ordering;
        use std::task::Poll;
        let start = Time::from_secs(7);
        let deadline = start.saturating_add_nanos(2_000_000);
        let clock = std::sync::Arc::new(VirtualClock::starting_at(start));
        let driver = TimerDriverHandle::with_virtual_clock(clock.clone());
        let probe = BudgetProbe::new(None);
        let polls = probe.polls.clone();
        let drops = probe.drops.clone();
        let wake = std::sync::Arc::new(BudgetWake::default());
        let waker = std::task::Waker::from(wake.clone());
        let mut cx = std::task::Context::from_waker(&waker);
        let mut bounded = BudgetedFinalizer::new(
            Box::pin(probe),
            shutdown_budget(Some(
                Budget::INFINITE.with_poll_quota(3).with_deadline(deadline),
            )),
            Some(driver.clone()),
        );
        assert!(Pin::new(&mut bounded).poll(&mut cx).is_pending());
        assert_eq!(driver.pending_count(), 1);
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(
            wake.0.load(Ordering::SeqCst),
            0,
            "user future did not wake itself"
        );
        clock.advance_to(Time::from_nanos(deadline.as_nanos() - 1));
        assert_eq!(driver.process_timers(), 0);
        clock.advance_to(deadline);
        assert_eq!(driver.process_timers(), 1);
        assert_eq!(wake.0.load(Ordering::SeqCst), 1);
        assert_eq!(
            Pin::new(&mut bounded).poll(&mut cx),
            Poll::Ready(Outcome::Err(FinalizerBudgetError::Deadline {
                deadline,
                observed: deadline
            }))
        );
        assert_eq!(
            polls.load(Ordering::SeqCst),
            1,
            "deadline wake never repolls expired user work"
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(driver.pending_count(), 0);

        for missing_driver in [false, true] {
            let probe = BudgetProbe::new(Some(1));
            let polls = probe.polls.clone();
            let drops = probe.drops.clone();
            let mut bounded = BudgetedFinalizer::new(
                Box::pin(probe),
                shutdown_budget(Some(
                    Budget::INFINITE.with_poll_quota(0).with_deadline(deadline),
                )),
                (!missing_driver).then(|| driver.clone()),
            );
            let expected = if missing_driver {
                FinalizerBudgetError::TimerUnavailable { deadline }
            } else {
                FinalizerBudgetError::Deadline {
                    deadline,
                    observed: deadline,
                }
            };
            assert_eq!(
                Pin::new(&mut bounded).poll(&mut cx),
                Poll::Ready(Outcome::Err(expected))
            );
            assert_eq!(polls.load(Ordering::SeqCst), 0);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(driver.pending_count(), 0);
        }
    }

    #[test]
    fn explicit_finalizer_post_poll_deadline_and_destructor_panic_precedence() {
        use crate::time::{TimerDriverHandle, VirtualClock};
        use crate::types::{Outcome, Time};
        use std::sync::atomic::Ordering;
        use std::task::Poll;
        for cause in 0..6 {
            let start = Time::from_secs(11);
            let deadline = start.saturating_add_nanos(3_000_000);
            let clock = std::sync::Arc::new(VirtualClock::starting_at(start));
            let driver = TimerDriverHandle::with_virtual_clock(clock.clone());
            let mut probe = BudgetProbe::new((cause == 0 || cause == 5).then_some(1));
            probe.panic_poll = cause == 2 || cause == 3;
            probe.panic_drop = matches!(cause, 1 | 3 | 4 | 5);
            if cause == 0 {
                probe.advance = Some((clock, deadline));
            }
            let polls = probe.polls.clone();
            let drops = probe.drops.clone();
            let quota = if cause == 4 { 0 } else { 1 };
            let mut bounded = BudgetedFinalizer::new(
                Box::pin(probe),
                shutdown_budget(Some(
                    Budget::INFINITE
                        .with_poll_quota(quota)
                        .with_deadline(deadline),
                )),
                Some(driver.clone()),
            );
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            let Poll::Ready(outcome) = Pin::new(&mut bounded).poll(&mut cx) else {
                panic!("this bounded control must terminate in one wrapper poll");
            };
            match cause {
                0 => assert_eq!(
                    outcome,
                    Outcome::Err(FinalizerBudgetError::Deadline {
                        deadline,
                        observed: deadline
                    })
                ),
                2 => assert!(
                    matches!(outcome, Outcome::Panicked(ref payload) if payload.message() == "budgeted finalizer body panic")
                ),
                _ => assert!(
                    matches!(outcome, Outcome::Panicked(ref payload) if payload.message() == "budgeted finalizer destructor panic")
                ),
            }
            assert_eq!(polls.load(Ordering::SeqCst), usize::from(cause != 4));
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(driver.pending_count(), 0);
            drop(bounded);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn explicit_finalizer_abandonment_retires_future_and_timer_without_double_drop() {
        use crate::time::{TimerDriverHandle, VirtualClock};
        use crate::types::Time;
        use std::sync::atomic::Ordering;
        for panic_drop in [false, true] {
            let clock = std::sync::Arc::new(VirtualClock::starting_at(Time::from_secs(19)));
            let driver = TimerDriverHandle::with_virtual_clock(clock);
            let mut probe = BudgetProbe::new(None);
            probe.panic_drop = panic_drop;
            let drops = probe.drops.clone();
            let mut bounded = BudgetedFinalizer::new(
                Box::pin(probe),
                shutdown_budget(Some(
                    Budget::INFINITE
                        .with_poll_quota(3)
                        .with_deadline(Time::from_secs(20)),
                )),
                Some(driver.clone()),
            );
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(Pin::new(&mut bounded).poll(&mut cx).is_pending());
            assert_eq!(driver.pending_count(), 1);
            let retired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(bounded)));
            assert_eq!(retired.is_err(), panic_drop);
            if let Err(payload) = retired {
                assert_eq!(
                    crate::cx::scope::payload_to_string(&payload),
                    "budgeted finalizer destructor panic"
                );
            }
            assert_eq!(driver.pending_count(), 0);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn explicit_finalizer_late_activation_and_tightening_are_monotone() {
        use crate::types::Outcome;
        use std::sync::atomic::Ordering;
        use std::task::Poll;
        let shared = shutdown_budget(None);
        let probe = BudgetProbe::new(None);
        let polls = probe.polls.clone();
        let drops = probe.drops.clone();
        let mut bounded = BudgetedFinalizer::new(Box::pin(probe), shared.clone(), None);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        for _ in 0..150 {
            assert!(Pin::new(&mut bounded).poll(&mut cx).is_pending());
        }
        assert_eq!(
            polls.load(Ordering::SeqCst),
            150,
            "None retains legacy progress beyond the old nominal 100-poll budget"
        );
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        *shared.write() = Some(Budget::INFINITE.with_poll_quota(3));
        assert!(Pin::new(&mut bounded).poll(&mut cx).is_pending());
        *shared.write() = Some(Budget::INFINITE.with_poll_quota(5));
        assert!(Pin::new(&mut bounded).poll(&mut cx).is_pending());
        *shared.write() = None;
        assert_eq!(
            Pin::new(&mut bounded).poll(&mut cx),
            Poll::Ready(Outcome::Err(FinalizerBudgetError::PollQuota {
                limit: 3,
                polled: 3
            }))
        );
        assert_eq!(polls.load(Ordering::SeqCst), 153);
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        let shared = shutdown_budget(Some(Budget::INFINITE.with_poll_quota(5)));
        let probe = BudgetProbe::new(None);
        let polls = probe.polls.clone();
        let drops = probe.drops.clone();
        let mut bounded = BudgetedFinalizer::new(Box::pin(probe), shared.clone(), None);
        assert!(Pin::new(&mut bounded).poll(&mut cx).is_pending());
        *shared.write() = Some(Budget::INFINITE.with_poll_quota(0));
        assert_eq!(
            Pin::new(&mut bounded).poll(&mut cx),
            Poll::Ready(Outcome::Err(FinalizerBudgetError::PollQuota {
                limit: 0,
                polled: 1
            }))
        );
        assert_eq!(
            polls.load(Ordering::SeqCst),
            1,
            "tightened zero ceiling never grants another poll"
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        // Activation during a returning user poll cannot retroactively stop
        // that poll, but zero still refuses its completion and retires it.
        let shared = shutdown_budget(None);
        let mut probe = BudgetProbe::new(Some(1));
        probe.update_budget = Some((shared.clone(), Some(Budget::INFINITE.with_poll_quota(0))));
        let polls = probe.polls.clone();
        let drops = probe.drops.clone();
        let mut bounded = BudgetedFinalizer::new(Box::pin(probe), shared, None);
        assert_eq!(
            Pin::new(&mut bounded).poll(&mut cx),
            Poll::Ready(Outcome::Err(FinalizerBudgetError::PollQuota {
                limit: 0,
                polled: 0
            }))
        );
        assert_eq!(
            polls.load(Ordering::SeqCst),
            1,
            "the sole poll began before activation"
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn explicit_finalizer_late_deadline_arms_and_tightening_replaces_real_timer() {
        use crate::time::{TimerDriverHandle, VirtualClock};
        use crate::types::{Outcome, Time};
        use std::sync::atomic::Ordering;
        use std::task::Poll;
        for activate_during_poll in [false, true] {
            let start = Time::from_secs(31);
            let deadline = start.saturating_add_nanos(2_000_000);
            let later = start.saturating_add_nanos(6_000_000);
            let clock = std::sync::Arc::new(VirtualClock::starting_at(start));
            let driver = TimerDriverHandle::with_virtual_clock(clock.clone());
            let shared = shutdown_budget(
                (!activate_during_poll)
                    .then_some(Budget::INFINITE.with_poll_quota(8).with_deadline(later)),
            );
            let mut probe = BudgetProbe::new(None);
            if activate_during_poll {
                probe.update_budget = Some((
                    shared.clone(),
                    Some(Budget::INFINITE.with_poll_quota(8).with_deadline(deadline)),
                ));
            }
            let polls = probe.polls.clone();
            let drops = probe.drops.clone();
            let wake = std::sync::Arc::new(BudgetWake::default());
            let waker = std::task::Waker::from(wake.clone());
            let mut cx = std::task::Context::from_waker(&waker);
            let mut bounded =
                BudgetedFinalizer::new(Box::pin(probe), shared.clone(), Some(driver.clone()));
            assert!(Pin::new(&mut bounded).poll(&mut cx).is_pending());
            if !activate_during_poll {
                assert_eq!(driver.next_deadline(), Some(later));
                *shared.write() = Some(Budget::INFINITE.with_poll_quota(8).with_deadline(deadline));
                assert!(Pin::new(&mut bounded).poll(&mut cx).is_pending());
            }
            assert_eq!(driver.pending_count(), 1);
            assert_eq!(driver.next_deadline(), Some(deadline));
            let observed_polls = polls.load(Ordering::SeqCst);
            assert_eq!(observed_polls, if activate_during_poll { 1 } else { 2 });
            clock.advance_to(deadline);
            assert_eq!(driver.process_timers(), 1);
            assert_eq!(wake.0.load(Ordering::SeqCst), 1);
            assert_eq!(
                Pin::new(&mut bounded).poll(&mut cx),
                Poll::Ready(Outcome::Err(FinalizerBudgetError::Deadline {
                    deadline,
                    observed: deadline
                }))
            );
            assert_eq!(polls.load(Ordering::SeqCst), observed_polls);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(driver.pending_count(), 0);
        }
    }

    #[test]
    fn explicit_finalizer_timer_horizon_wake_is_not_the_true_deadline() {
        use crate::time::{TimerDriverHandle, VirtualClock};
        use crate::types::{Outcome, Time};
        use std::sync::atomic::Ordering;
        use std::task::Poll;
        let start = Time::from_secs(37);
        let clock = std::sync::Arc::new(VirtualClock::starting_at(start));
        let driver = TimerDriverHandle::with_virtual_clock(clock.clone());
        let horizon = u64::try_from(driver.max_timer_duration().as_nanos()).unwrap();
        let partial = start.saturating_add_nanos(horizon);
        let deadline = partial.saturating_add_nanos(horizon);
        let probe = BudgetProbe::new(None);
        let polls = probe.polls.clone();
        let drops = probe.drops.clone();
        let mut bounded = BudgetedFinalizer::new(
            Box::pin(probe),
            shutdown_budget(Some(
                Budget::INFINITE.with_poll_quota(4).with_deadline(deadline),
            )),
            Some(driver.clone()),
        );
        let first = std::sync::Arc::new(BudgetWake::default());
        let first_waker = std::task::Waker::from(first.clone());
        let mut first_cx = std::task::Context::from_waker(&first_waker);
        assert!(Pin::new(&mut bounded).poll(&mut first_cx).is_pending());
        assert_eq!(driver.next_deadline(), Some(partial));
        clock.advance_to(partial);
        assert_eq!(driver.process_timers(), 1);
        assert_eq!(first.0.load(Ordering::SeqCst), 1);
        let second = std::sync::Arc::new(BudgetWake::default());
        let second_waker = std::task::Waker::from(second.clone());
        let mut second_cx = std::task::Context::from_waker(&second_waker);
        assert!(Pin::new(&mut bounded).poll(&mut second_cx).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_eq!(driver.pending_count(), 1);
        assert_eq!(driver.next_deadline(), Some(deadline));
        clock.advance_to(deadline);
        assert_eq!(driver.process_timers(), 1);
        assert_eq!(second.0.load(Ordering::SeqCst), 1);
        assert_eq!(first.0.load(Ordering::SeqCst), 1);
        assert_eq!(
            Pin::new(&mut bounded).poll(&mut second_cx),
            Poll::Ready(Outcome::Err(FinalizerBudgetError::Deadline {
                deadline,
                observed: deadline
            }))
        );
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(driver.pending_count(), 0);
    }

    #[test]
    fn explicit_finalizer_actual_lab_task_deadline_wakes_through_cancel_mask() {
        use crate::lab::{LabConfig, LabRuntime};
        use crate::types::{CancelReason, Outcome, Time};
        use std::sync::atomic::Ordering;
        let mut lab = LabRuntime::new(
            LabConfig::new(3401)
                .max_steps(10_000)
                .trace_capacity(10_000),
        );
        lab.advance_time_to(Time::from_secs(23));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let probe = BudgetProbe::new(None);
        let polls = probe.polls.clone();
        let drops = probe.drops.clone();
        let deadline = Time::from_secs(23).saturating_add_nanos(2_000_000);
        let observed_outcome = std::sync::Arc::new(parking_lot::Mutex::new(None));
        let completed_outcome = std::sync::Arc::clone(&observed_outcome);
        let (task, mut joined) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = crate::Cx::current().expect("real scheduled finalizer-wrapper owner");
                let mut bounded = BudgetedFinalizer::new(
                    Box::pin(probe),
                    shutdown_budget(Some(
                        Budget::INFINITE.with_poll_quota(8).with_deadline(deadline),
                    )),
                    cx.timer_driver(),
                );
                let outcome = std::future::poll_fn(|poll_cx| {
                    cx.masked(|| {
                        assert!(
                            cx.checkpoint().is_ok(),
                            "the actual task is masked during finalizer polling"
                        );
                        Pin::new(&mut bounded).poll(poll_cx)
                    })
                })
                .await;
                assert!(
                    cx.checkpoint().is_err(),
                    "acknowledge the caller's real cancellation after cleanup"
                );
                *completed_outcome.lock() = Some(outcome);
            })
            .unwrap();
        lab.scheduler.lock().schedule(task, 0);
        lab.run_until_idle();
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        let driver = lab.state.timer_driver_handle().unwrap();
        assert_eq!(driver.pending_count(), 1);
        assert!(joined.try_join().unwrap().is_none());
        let cancellation = CancelReason::user("finalizer wrapper test cancellation");
        joined.abort_with_reason(cancellation.clone());
        lab.run_until_idle();
        assert!(
            joined.try_join().unwrap().is_none(),
            "mask does not turn cancellation into timeout readiness"
        );
        assert_eq!(lab.state.live_task_count(), 1);
        assert_eq!(driver.pending_count(), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        let before_deadline = polls.load(Ordering::SeqCst);
        assert!((1..8).contains(&before_deadline));
        assert_eq!(lab.advance_to_next_timer(), 1);
        lab.run_until_idle();
        assert_eq!(
            joined.try_join(),
            Err(crate::runtime::task_handle::JoinError::Cancelled(
                cancellation
            )),
            "the low-level owner retains actual cancellation attribution"
        );
        assert_eq!(
            observed_outcome
                .lock()
                .take()
                .expect("actual timer woke and retired the wrapper"),
            Outcome::Err(FinalizerBudgetError::Deadline {
                deadline,
                observed: deadline
            })
        );
        assert_eq!(polls.load(Ordering::SeqCst), before_deadline);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(driver.pending_count(), 0);
        assert_eq!(lab.state.live_task_count(), 0);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert_eq!(lab.state.leak_count(), 0);
        lab.state
            .close_region_command(root, &CancelReason::user("finalizer wrapper test complete"));
        assert!(lab.state.region(root).is_none());
        let report = lab.run_until_quiescent_with_report();
        assert!(report.lab_test_passed(), "{report:?}");
        assert!(!report.refinement_firewall_skipped_due_to_trace_truncation);
        eprintln!(
            "explicit_finalizer_deadline task={task:?} region={root:?} deadline={deadline:?} user_polls={before_deadline} retired=1 timer_pending=0 report={report:?}"
        );
    }
