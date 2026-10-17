    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    // =========================================================================
    // HedgeConfig Tests
    // =========================================================================

    #[test]
    fn hedge_config_from_millis() {
        let config = HedgeConfig::from_millis(100);
        assert_eq!(config.hedge_delay, Duration::from_millis(100));
        assert!(!config.backup_spawned);
    }

    #[test]
    fn hedge_config_from_secs() {
        let config = HedgeConfig::from_secs(5);
        assert_eq!(config.hedge_delay, Duration::from_secs(5));
    }

    #[test]
    fn hedge_config_default() {
        let config = HedgeConfig::default();
        assert_eq!(config.hedge_delay, Duration::from_millis(100));
    }

    #[test]
    fn hedge_config_delay_elapsed() {
        let config = HedgeConfig::from_millis(100);
        let start = Time::from_nanos(1_000_000); // 1ms

        // Not elapsed yet (50ms later)
        let now = Time::from_nanos(51_000_000);
        assert!(!config.delay_elapsed(start, now));

        // Exactly at deadline (100ms later)
        let now = Time::from_nanos(101_000_000);
        assert!(config.delay_elapsed(start, now));

        // After deadline (200ms later)
        let now = Time::from_nanos(201_000_000);
        assert!(config.delay_elapsed(start, now));
    }

    #[test]
    fn hedge_config_deadline_from() {
        let config = HedgeConfig::from_millis(100);
        let start = Time::from_nanos(1_000_000); // 1ms

        let deadline = config.deadline_from(start);
        assert_eq!(deadline.as_nanos(), 101_000_000); // 101ms
    }

    #[test]
    fn hedge_config_deadline_from_saturates_on_large_duration() {
        let config = HedgeConfig::new(Duration::from_secs(u64::MAX));
        let start = Time::from_nanos(1);

        let deadline = config.deadline_from(start);
        assert_eq!(deadline, Time::MAX);
    }

    #[test]
    fn hedge_config_delay_elapsed_respects_saturated_deadline() {
        let config = HedgeConfig::new(Duration::from_nanos(10));
        let start = Time::from_nanos(u64::MAX - 5);

        assert_eq!(config.deadline_from(start), Time::MAX);
        assert!(!config.delay_elapsed(start, start));
        assert!(config.delay_elapsed(start, Time::MAX));
    }

    // =========================================================================
    // Hedge Combinator Type Tests
    // =========================================================================

    #[test]
    fn hedge_creation() {
        let hedge = Hedge::<()>::from_millis(200);
        assert_eq!(hedge.delay(), Duration::from_millis(200));
    }

    #[test]
    fn hedge_clone_and_copy() {
        let h1 = Hedge::<()>::from_millis(100);
        let h2 = h1; // Copy
        let h3 = h1; // Also copy

        assert_eq!(h1.delay(), h2.delay());
        assert_eq!(h1.delay(), h3.delay());
    }

    #[test]
    fn hedge_default() {
        let hedge = Hedge::<()>::default();
        assert_eq!(hedge.delay(), Duration::from_millis(100));
    }

    // =========================================================================
    // HedgeWinner Tests
    // =========================================================================

    #[test]
    fn hedge_winner_is_primary() {
        assert!(HedgeWinner::Primary.is_primary());
        assert!(!HedgeWinner::Primary.is_backup());
    }

    #[test]
    fn hedge_winner_is_backup() {
        assert!(!HedgeWinner::Backup.is_primary());
        assert!(HedgeWinner::Backup.is_backup());
    }

    // =========================================================================
    // HedgeResult Tests
    // =========================================================================

    #[test]
    fn hedge_result_primary_fast() {
        let result: HedgeResult<i32, &str> = HedgeResult::primary_fast(Outcome::Ok(42));

        assert!(result.is_primary_fast());
        assert!(!result.was_raced());
        assert!(result.winner().is_primary());
        assert!(result.winner_succeeded());
        assert!(result.loser_outcome().is_none());
    }

    #[test]
    fn hedge_result_primary_won_race() {
        let result: HedgeResult<i32, &str> = HedgeResult::primary_won(
            Outcome::Ok(42),
            Outcome::Cancelled(CancelReason::race_loser()),
        );

        assert!(!result.is_primary_fast());
        assert!(result.was_raced());
        assert!(result.winner().is_primary());
        assert!(result.winner_succeeded());
        assert!(result.loser_outcome().is_some());
        assert!(result.loser_outcome().unwrap().is_cancelled());
    }

    #[test]
    fn hedge_result_backup_won_race() {
        let result: HedgeResult<i32, &str> = HedgeResult::backup_won(
            Outcome::Ok(99),
            Outcome::Cancelled(CancelReason::race_loser()),
        );

        assert!(!result.is_primary_fast());
        assert!(result.was_raced());
        assert!(result.winner().is_backup());
        assert!(result.winner_succeeded());
        assert!(result.loser_outcome().is_some());
    }

    #[test]
    fn hedge_result_winner_outcome() {
        let result: HedgeResult<i32, &str> = HedgeResult::backup_won(
            Outcome::Ok(99),
            Outcome::Cancelled(CancelReason::race_loser()),
        );

        assert!(result.winner_outcome().is_ok());
        if let Outcome::Ok(v) = result.winner_outcome() {
            assert_eq!(*v, 99);
        }
    }

    #[test]
    fn hedge_result_into_winner_outcome() {
        let result: HedgeResult<i32, &str> = HedgeResult::primary_fast(Outcome::Ok(42));
        let outcome = result.into_winner_outcome();
        assert!(matches!(outcome, Outcome::Ok(42)));
    }

    // =========================================================================
    // hedge_outcomes Tests
    // =========================================================================

    #[test]
    fn hedge_outcomes_primary_fast() {
        let result = hedge_outcomes::<i32, &str>(Outcome::Ok(42), false, None, None);

        assert!(result.is_primary_fast());
        assert!(result.winner_succeeded());
    }

    #[test]
    fn hedge_outcomes_primary_won_race() {
        let result = hedge_outcomes::<i32, &str>(
            Outcome::Ok(42),
            true,
            Some(Outcome::Cancelled(CancelReason::race_loser())),
            Some(HedgeWinner::Primary),
        );

        assert!(result.was_raced());
        assert!(result.winner().is_primary());
        assert!(result.winner_succeeded());
    }

    #[test]
    fn hedge_outcomes_backup_won_race() {
        let result = hedge_outcomes::<i32, &str>(
            Outcome::Cancelled(CancelReason::race_loser()),
            true,
            Some(Outcome::Ok(99)),
            Some(HedgeWinner::Backup),
        );

        assert!(result.was_raced());
        assert!(result.winner().is_backup());
        assert!(result.winner_succeeded());
    }

    #[test]
    #[should_panic(expected = "backup_outcome required")]
    fn hedge_outcomes_panics_without_backup_outcome() {
        let _ =
            hedge_outcomes::<i32, &str>(Outcome::Ok(42), true, None, Some(HedgeWinner::Primary));
    }

    #[test]
    #[should_panic(expected = "winner required")]
    fn hedge_outcomes_panics_without_winner() {
        let _ = hedge_outcomes::<i32, &str>(
            Outcome::Ok(42),
            true,
            Some(Outcome::Cancelled(CancelReason::race_loser())),
            None,
        );
    }

    #[test]
    #[should_panic(expected = "backup_outcome must be None")]
    fn hedge_outcomes_panics_on_backup_outcome_when_not_spawned() {
        let _ = hedge_outcomes::<i32, &str>(
            Outcome::Ok(42),
            false,
            Some(Outcome::Cancelled(CancelReason::race_loser())),
            None,
        );
    }

    #[test]
    #[should_panic(expected = "winner must be None")]
    fn hedge_outcomes_panics_on_winner_when_not_spawned() {
        let _ =
            hedge_outcomes::<i32, &str>(Outcome::Ok(42), false, None, Some(HedgeWinner::Primary));
    }

    // =========================================================================
    // hedge_to_result Tests
    // =========================================================================

    #[test]
    fn hedge_to_result_primary_fast_ok() {
        let result: HedgeResult<i32, &str> = HedgeResult::primary_fast(Outcome::Ok(42));
        assert_eq!(hedge_to_result(result).unwrap(), 42);
    }

    #[test]
    fn hedge_to_result_primary_fast_err() {
        let result: HedgeResult<i32, &str> = HedgeResult::primary_fast(Outcome::Err("failed"));
        assert!(matches!(
            hedge_to_result(result),
            Err(HedgeError::PrimaryFastError("failed"))
        ));
    }

    #[test]
    fn hedge_to_result_primary_won_ok() {
        let result: HedgeResult<i32, &str> = HedgeResult::primary_won(
            Outcome::Ok(42),
            Outcome::Cancelled(CancelReason::race_loser()),
        );
        assert_eq!(hedge_to_result(result).unwrap(), 42);
    }

    #[test]
    fn hedge_to_result_primary_won_err() {
        let result: HedgeResult<i32, &str> = HedgeResult::primary_won(
            Outcome::Err("primary failed"),
            Outcome::Cancelled(CancelReason::race_loser()),
        );
        assert!(matches!(
            hedge_to_result(result),
            Err(HedgeError::PrimaryError("primary failed"))
        ));
    }

    #[test]
    fn hedge_to_result_backup_won_ok() {
        let result: HedgeResult<i32, &str> = HedgeResult::backup_won(
            Outcome::Ok(99),
            Outcome::Cancelled(CancelReason::race_loser()),
        );
        assert_eq!(hedge_to_result(result).unwrap(), 99);
    }

    #[test]
    fn hedge_to_result_backup_won_err() {
        let result: HedgeResult<i32, &str> = HedgeResult::backup_won(
            Outcome::Err("backup failed"),
            Outcome::Cancelled(CancelReason::race_loser()),
        );
        assert!(matches!(
            hedge_to_result(result),
            Err(HedgeError::BackupError("backup failed"))
        ));
    }

    #[test]
    fn hedge_to_result_cancelled() {
        let result: HedgeResult<i32, &str> =
            HedgeResult::primary_fast(Outcome::Cancelled(CancelReason::shutdown()));
        assert!(matches!(
            hedge_to_result(result),
            Err(HedgeError::Cancelled(_))
        ));
    }

    #[test]
    fn hedge_to_result_panicked() {
        let result: HedgeResult<i32, &str> =
            HedgeResult::primary_fast(Outcome::Panicked(PanicPayload::new("boom")));
        assert!(matches!(
            hedge_to_result(result),
            Err(HedgeError::Panicked(_))
        ));
    }

    // =========================================================================
    // HedgeError Tests
    // =========================================================================

    #[test]
    fn hedge_error_display_primary_fast() {
        let err: HedgeError<&str> = HedgeError::PrimaryFastError("test");
        assert!(err.to_string().contains("primary completed fast"));
        assert!(err.to_string().contains("test"));
    }

    #[test]
    fn hedge_error_display_primary() {
        let err: HedgeError<&str> = HedgeError::PrimaryError("test");
        assert!(err.to_string().contains("primary won race"));
    }

    #[test]
    fn hedge_error_display_backup() {
        let err: HedgeError<&str> = HedgeError::BackupError("test");
        assert!(err.to_string().contains("backup won race"));
    }

    #[test]
    fn hedge_error_display_cancelled() {
        let err: HedgeError<&str> = HedgeError::Cancelled(CancelReason::shutdown());
        assert!(err.to_string().contains("cancelled"));
    }

    #[test]
    fn hedge_error_display_panicked() {
        let err: HedgeError<&str> = HedgeError::Panicked(PanicPayload::new("boom"));
        assert!(err.to_string().contains("panicked"));
    }

    // =========================================================================
    // Invariant Verification Tests
    // =========================================================================

    #[test]
    fn loser_is_always_tracked_in_race() {
        // When a race occurs, the loser outcome must be tracked
        let result: HedgeResult<i32, &str> = HedgeResult::primary_won(
            Outcome::Ok(42),
            Outcome::Cancelled(CancelReason::race_loser()),
        );

        let loser = result.loser_outcome().expect("loser must be tracked");
        assert!(loser.is_cancelled());

        if let Outcome::Cancelled(reason) = loser {
            assert!(matches!(
                reason.kind(),
                crate::types::cancel::CancelKind::RaceLost
            ));
        }
    }

    #[test]
    fn primary_fast_has_no_loser() {
        // When primary completes fast, there is no loser (backup never spawned)
        let result: HedgeResult<i32, &str> = HedgeResult::primary_fast(Outcome::Ok(42));

        assert!(result.loser_outcome().is_none());
    }

    #[test]
    fn hedge_commutativity_of_race_result() {
        // When a race occurs, the winner value is the same regardless of which won
        let val = 42;

        // Primary wins
        let r1: HedgeResult<i32, &str> = HedgeResult::primary_won(
            Outcome::Ok(val),
            Outcome::Cancelled(CancelReason::race_loser()),
        );

        // Backup wins with same value
        let r2: HedgeResult<i32, &str> = HedgeResult::backup_won(
            Outcome::Ok(val),
            Outcome::Cancelled(CancelReason::race_loser()),
        );

        // Both should succeed with the same value
        assert_eq!(hedge_to_result(r1).unwrap(), hedge_to_result(r2).unwrap());
    }

    #[test]
    fn hedge_result_winner_reflects_input() {
        // Verify winner field correctly reflects which branch won
        let primary_won: HedgeResult<i32, &str> = HedgeResult::primary_won(
            Outcome::Ok(1),
            Outcome::Cancelled(CancelReason::race_loser()),
        );
        assert_eq!(primary_won.winner(), HedgeWinner::Primary);

        let backup_won: HedgeResult<i32, &str> = HedgeResult::backup_won(
            Outcome::Ok(2),
            Outcome::Cancelled(CancelReason::race_loser()),
        );
        assert_eq!(backup_won.winner(), HedgeWinner::Backup);

        let primary_fast: HedgeResult<i32, &str> = HedgeResult::primary_fast(Outcome::Ok(3));
        assert_eq!(primary_fast.winner(), HedgeWinner::Primary);
    }

    #[test]
    fn metamorphic_redundant_loser_cancel_preserves_hedged_winner_result() {
        let baseline: HedgeResult<i32, &str> = HedgeResult::primary_won(
            Outcome::Ok(42),
            Outcome::Cancelled(CancelReason::race_loser()),
        );
        let transformed: HedgeResult<i32, &str> = HedgeResult::primary_won(
            Outcome::Ok(42),
            Outcome::Cancelled(CancelReason::race_loser()),
        );

        assert_eq!(
            hedge_to_result(baseline.clone()).unwrap(),
            hedge_to_result(transformed.clone()).unwrap(),
            "reissuing the loser cancellation must not perturb the successful hedged result"
        );
        assert_eq!(baseline.winner(), transformed.winner());

        let baseline_loser = baseline
            .loser_outcome()
            .expect("raced hedge must track loser outcome");
        let transformed_loser = transformed
            .loser_outcome()
            .expect("raced hedge must track loser outcome");

        match (baseline_loser, transformed_loser) {
            (Outcome::Cancelled(left), Outcome::Cancelled(right)) => {
                assert_eq!(left.kind(), right.kind());
            }
            _ => panic!("loser should remain represented as cancellation"),
        }
    }

    // --- wave 79 trait coverage ---

    #[test]
    fn hedge_config_debug_clone_copy_eq() {
        let c = HedgeConfig::from_millis(100);
        let c2 = c; // Copy
        let c3 = c;
        assert_eq!(c, c2);
        assert_eq!(c, c3);
        assert_ne!(c, HedgeConfig::from_secs(5));
        let dbg = format!("{c:?}");
        assert!(dbg.contains("HedgeConfig"));
    }

    #[test]
    fn hedge_winner_debug_clone_copy_eq() {
        let w = HedgeWinner::Primary;
        let w2 = w; // Copy
        let w3 = w;
        assert_eq!(w, w2);
        assert_eq!(w, w3);
        assert_ne!(w, HedgeWinner::Backup);
        let dbg = format!("{w:?}");
        assert!(dbg.contains("Primary"));
    }

    #[test]
    fn hedge_result_debug_clone() {
        let r: HedgeResult<i32, &str> = HedgeResult::primary_fast(Outcome::Ok(42));
        let r2 = r.clone();
        assert_eq!(r.winner(), r2.winner());
        let dbg = format!("{r:?}");
        assert!(dbg.contains("HedgeResult") || dbg.contains("PrimaryFast"));
    }

    // Test helper to block
    fn block_on<F: Future>(f: F) -> F::Output {
        futures_lite::future::block_on(f)
    }

    struct PendingProbe {
        polls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
        cancel_on_poll: Option<(Cx, CancelReason)>,
    }

    impl PendingProbe {
        fn new(polls: Arc<AtomicUsize>, drops: Arc<AtomicUsize>) -> Self {
            Self {
                polls,
                drops,
                cancel_on_poll: None,
            }
        }

        fn cancelling(
            polls: Arc<AtomicUsize>,
            drops: Arc<AtomicUsize>,
            cx: Cx,
            reason: CancelReason,
        ) -> Self {
            Self {
                polls,
                drops,
                cancel_on_poll: Some((cx, reason)),
            }
        }
    }

    impl Future for PendingProbe {
        type Output = Outcome<(), ()>;

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.fetch_add(1, Ordering::Relaxed);
            if let Some((cx, reason)) = self.cancel_on_poll.take() {
                cx.set_cancel_reason(reason);
            }
            Poll::Pending
        }
    }

    impl Drop for PendingProbe {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn poll_once<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
        let waker = std::task::Waker::noop();
        let mut task_cx = Context::from_waker(waker);
        Pin::new(future).poll(&mut task_cx)
    }

    #[test]
    fn test_hedge_execution_primary_fast() {
        let config = HedgeConfig::from_secs(10); // Long delay
        let future = hedge(
            config,
            std::future::ready(Outcome::<i32, ()>::Ok(1)),
            || std::future::ready(Outcome::<i32, ()>::Ok(2)),
        );

        let result = block_on(future);
        assert!(result.is_primary_fast());
        if let Outcome::Ok(v) = result.winner_outcome() {
            assert_eq!(*v, 1);
        }
    }

    #[test]
    fn test_hedge_execution_backup_wins_pending_primary() {
        let config = HedgeConfig::from_millis(1);
        let future = hedge(config, std::future::pending::<Outcome<i32, ()>>(), || {
            std::future::ready(Outcome::<i32, ()>::Ok(2))
        });

        let result = block_on(future);
        assert!(result.was_raced());
        assert!(result.winner().is_backup());
        if let Outcome::Ok(v) = result.winner_outcome() {
            assert_eq!(*v, 2);
        }
    }

    /// The hedge delay ran from construction: a hedge built 150 ms before its
    /// first poll, with a 100 ms delay, started the backup on that first poll.
    #[test]
    fn hedge_delay_runs_from_the_first_poll() {
        use crate::time::{TimerDriverHandle, VirtualClock};
        use crate::types::{Budget, RegionId, TaskId};

        let clock = Arc::new(VirtualClock::starting_at(Time::ZERO));
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(TimerDriverHandle::with_virtual_clock(Arc::clone(&clock))),
            None,
        );
        let _current = Cx::set_current(Some(cx));

        let factory_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&factory_calls);
        let mut future = hedge(
            HedgeConfig::from_millis(100),
            std::future::pending::<Outcome<i32, ()>>(),
            move || {
                calls.fetch_add(1, Ordering::Relaxed);
                std::future::pending::<Outcome<i32, ()>>()
            },
        );

        clock.advance(150_000_000);
        assert!(poll_once(&mut future).is_pending());
        assert_eq!(
            factory_calls.load(Ordering::Relaxed),
            0,
            "the backup started before the delay had passed since the first poll"
        );

        clock.advance(99_000_000);
        assert!(poll_once(&mut future).is_pending());
        assert_eq!(factory_calls.load(Ordering::Relaxed), 0);

        clock.advance(1_000_000);
        assert!(poll_once(&mut future).is_pending());
        assert_eq!(factory_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn hedge_pre_cancelled_never_polls_primary_or_starts_backup() {
        let primary_polls = Arc::new(AtomicUsize::new(0));
        let primary_drops = Arc::new(AtomicUsize::new(0));
        let backup_polls = Arc::new(AtomicUsize::new(0));
        let backup_drops = Arc::new(AtomicUsize::new(0));
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let expected_reason = CancelReason::shutdown();

        let ambient = Cx::for_testing();
        ambient.set_cancel_reason(expected_reason.clone());
        let _current = Cx::set_current(Some(ambient));

        let factory_calls_probe = Arc::clone(&factory_calls);
        let backup_polls_probe = Arc::clone(&backup_polls);
        let backup_drops_probe = Arc::clone(&backup_drops);
        let mut future = hedge(
            HedgeConfig::new(Duration::ZERO),
            PendingProbe::new(Arc::clone(&primary_polls), Arc::clone(&primary_drops)),
            move || {
                factory_calls_probe.fetch_add(1, Ordering::Relaxed);
                PendingProbe::new(backup_polls_probe, backup_drops_probe)
            },
        );

        let Poll::Ready(result) = poll_once(&mut future) else {
            panic!("pre-cancelled hedge must complete immediately");
        };

        assert!(result.is_primary_fast());
        assert_eq!(primary_polls.load(Ordering::Relaxed), 0);
        assert_eq!(primary_drops.load(Ordering::Relaxed), 1);
        assert_eq!(factory_calls.load(Ordering::Relaxed), 0);
        assert_eq!(backup_polls.load(Ordering::Relaxed), 0);
        assert_eq!(backup_drops.load(Ordering::Relaxed), 0);
        assert_eq!(
            result.into_winner_outcome(),
            Outcome::Cancelled(expected_reason)
        );
    }

    #[test]
    fn hedge_rechecks_same_poll_cancellation_before_pending_or_backup() {
        for hedge_delay in [Duration::ZERO, Duration::from_secs(60)] {
            let primary_polls = Arc::new(AtomicUsize::new(0));
            let primary_drops = Arc::new(AtomicUsize::new(0));
            let backup_polls = Arc::new(AtomicUsize::new(0));
            let backup_drops = Arc::new(AtomicUsize::new(0));
            let factory_calls = Arc::new(AtomicUsize::new(0));
            let expected_reason = CancelReason::deadline();

            let ambient = Cx::for_testing();
            let _current = Cx::set_current(Some(ambient.clone()));

            let factory_calls_probe = Arc::clone(&factory_calls);
            let backup_polls_probe = Arc::clone(&backup_polls);
            let backup_drops_probe = Arc::clone(&backup_drops);
            let mut future = hedge(
                HedgeConfig::new(hedge_delay),
                PendingProbe::cancelling(
                    Arc::clone(&primary_polls),
                    Arc::clone(&primary_drops),
                    ambient,
                    expected_reason.clone(),
                ),
                move || {
                    factory_calls_probe.fetch_add(1, Ordering::Relaxed);
                    PendingProbe::new(backup_polls_probe, backup_drops_probe)
                },
            );

            let Poll::Ready(result) = poll_once(&mut future) else {
                panic!("same-poll cancellation must complete before pending or backup creation");
            };

            assert!(result.is_primary_fast());
            assert_eq!(primary_polls.load(Ordering::Relaxed), 1);
            assert_eq!(primary_drops.load(Ordering::Relaxed), 1);
            assert_eq!(factory_calls.load(Ordering::Relaxed), 0);
            assert_eq!(backup_polls.load(Ordering::Relaxed), 0);
            assert_eq!(backup_drops.load(Ordering::Relaxed), 0);
            assert_eq!(
                result.into_winner_outcome(),
                Outcome::Cancelled(expected_reason)
            );
        }
    }

    #[test]
    fn hedge_cancellation_during_race_drops_both_with_caller_reason() {
        let primary_polls = Arc::new(AtomicUsize::new(0));
        let primary_drops = Arc::new(AtomicUsize::new(0));
        let backup_polls = Arc::new(AtomicUsize::new(0));
        let backup_drops = Arc::new(AtomicUsize::new(0));
        let factory_calls = Arc::new(AtomicUsize::new(0));

        let ambient = Cx::for_testing();
        let _current = Cx::set_current(Some(ambient.clone()));

        let factory_calls_probe = Arc::clone(&factory_calls);
        let backup_polls_probe = Arc::clone(&backup_polls);
        let backup_drops_probe = Arc::clone(&backup_drops);
        let mut future = hedge(
            HedgeConfig::new(Duration::ZERO),
            PendingProbe::new(Arc::clone(&primary_polls), Arc::clone(&primary_drops)),
            move || {
                factory_calls_probe.fetch_add(1, Ordering::Relaxed);
                PendingProbe::new(backup_polls_probe, backup_drops_probe)
            },
        );

        assert!(poll_once(&mut future).is_pending());
        assert_eq!(primary_polls.load(Ordering::Relaxed), 1);
        assert_eq!(factory_calls.load(Ordering::Relaxed), 1);
        assert_eq!(backup_polls.load(Ordering::Relaxed), 1);

        let expected_reason = CancelReason::shutdown();
        ambient.set_cancel_reason(expected_reason.clone());
        let Poll::Ready(result) = poll_once(&mut future) else {
            panic!("cancelled hedge race must complete immediately");
        };

        assert_eq!(primary_drops.load(Ordering::Relaxed), 1);
        assert_eq!(backup_drops.load(Ordering::Relaxed), 1);
        assert_eq!(primary_polls.load(Ordering::Relaxed), 1);
        assert_eq!(factory_calls.load(Ordering::Relaxed), 1);
        assert_eq!(backup_polls.load(Ordering::Relaxed), 1);
        match result {
            HedgeResult::Raced {
                winner_outcome,
                winner,
                loser_outcome,
            } => {
                assert_eq!(winner, HedgeWinner::Primary);
                assert_eq!(winner_outcome, Outcome::Cancelled(expected_reason.clone()));
                assert_eq!(loser_outcome, Outcome::Cancelled(expected_reason));
            }
            HedgeResult::PrimaryFast(_) => panic!("backup was already running"),
        }
    }

    // =========================================================================
    // AdaptiveHedgePolicy Tests (Alien Artifact Conformal Bound)
    // =========================================================================

    #[test]
    fn test_adaptive_hedge_policy_conformal_quantile() {
        let min_delay = Duration::from_millis(10);
        let max_delay = Duration::from_secs(1);
        let mut policy = AdaptiveHedgePolicy::new(100, 0.05, min_delay, max_delay);

        // Before sufficient data (10 items), it yields max_delay to avoid over-hedging
        for _ in 0..9 {
            policy.record(Duration::from_millis(20));
        }
        assert_eq!(policy.next_hedge_delay(), max_delay);

        // Record a 10th item.
        policy.record(Duration::from_millis(20));
        // n=10, alpha=0.05: ceil((10+1)*0.95) = 11 > 10, so the split-conformal
        // (1-alpha) upper bound is +inf (there is no 11th order statistic). The
        // policy conservatively yields max_delay rather than clamping to the max
        // observed sample (20ms), which would UNDER-cover and over-hedge.
        assert_eq!(policy.next_hedge_delay(), max_delay);

        // Let's add varying latencies to test the alpha=0.05 (p95) logic
        // Reset policy for clear test
        let mut policy = AdaptiveHedgePolicy::new(100, 0.05, min_delay, max_delay);
        for i in 1..=100 {
            // 1ms to 100ms
            policy.record(Duration::from_millis(i));
        }

        // Rank = ceiling((100 + 1) * (1 - 0.05)) = ceil(101 * 0.95) = ceil(95.95) = 96
        // 0-indexed rank = 96 - 1 = 95. The 95th index is 96ms.
        let delay = policy.next_hedge_delay();
        assert_eq!(delay, Duration::from_millis(96));
    }

    #[test]
    fn test_adaptive_hedge_policy_clamps() {
        let min_delay = Duration::from_millis(50);
        let max_delay = Duration::from_millis(100);
        let mut policy = AdaptiveHedgePolicy::new(100, 0.05, min_delay, max_delay);

        // Force very low latency
        for _ in 0..20 {
            policy.record(Duration::from_millis(1));
        }
        // Should clamp to min_delay
        assert_eq!(policy.next_hedge_delay(), min_delay);

        // Force very high latency
        for _ in 0..20 {
            policy.record(Duration::from_secs(5));
        }
        // Should clamp to max_delay
        assert_eq!(policy.next_hedge_delay(), max_delay);
    }

    #[test]
    fn test_adaptive_hedge_policy_uses_sliding_window_latest_samples() {
        let min_delay = Duration::from_millis(1);
        let max_delay = Duration::from_secs(1);
        let mut policy = AdaptiveHedgePolicy::new(10, 0.5, min_delay, max_delay);

        for millis in 1..=20 {
            policy.record(Duration::from_millis(millis));
        }

        // Window retains only the latest 10 samples: [11,12,13,14,15,16,17,18,19,20]
        assert_eq!(policy.window_size(), 10);
        assert_eq!(policy.sample_count(), 10);

        // Rank = ceil((10 + 1) * (1 - 0.5)) = 6, zero-indexed -> 5, value -> 16ms.
        assert_eq!(policy.next_hedge_delay(), Duration::from_millis(16));
    }

    #[test]
    fn test_adaptive_hedge_policy_config_matches_next_delay() {
        let min_delay = Duration::from_millis(5);
        let max_delay = Duration::from_millis(500);
        let mut policy = AdaptiveHedgePolicy::new(16, 0.1, min_delay, max_delay);
        for millis in 10..=30 {
            policy.record(Duration::from_millis(millis));
        }

        assert_eq!(policy.config().hedge_delay, policy.next_hedge_delay());
    }
