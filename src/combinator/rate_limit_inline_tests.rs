    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    // =========================================================================
    // Token Bucket Basic Tests
    // =========================================================================

    #[test]
    fn new_limiter_has_burst_tokens() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 10,
            burst: 5,
            ..Default::default()
        });

        let tokens = rl.available_tokens();
        assert_eq!(tokens, 5);
    }

    #[test]
    fn acquire_reduces_tokens() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 10,
            burst: 10,
            ..Default::default()
        });

        let now = Time::from_millis(0);
        assert!(rl.try_acquire(3, now));

        let tokens = rl.available_tokens();
        assert_eq!(tokens, 7);
    }

    #[test]
    fn acquire_fails_when_insufficient_tokens() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 10,
            burst: 5,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Use all tokens
        assert!(rl.try_acquire(5, now));

        // Should fail
        assert!(!rl.try_acquire(1, now));
    }

    #[test]
    fn tokens_refill_over_time() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 10, // 10 per second
            period: Duration::from_secs(1),
            burst: 10,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Exhaust tokens
        assert!(rl.try_acquire(10, now));
        assert!(!rl.try_acquire(1, now));

        // After 100ms, should have ~1 token
        let later = Time::from_millis(100);
        rl.refill(later);

        let tokens = rl.available_tokens();
        assert_eq!(
            tokens, 1,
            "Expected 1 token after 100ms refill, got {tokens}"
        );
    }

    #[test]
    fn tokens_cap_at_burst() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 100,
            period: Duration::from_secs(1),
            burst: 10,
            ..Default::default()
        });

        let now = Time::from_millis(0);
        rl.refill(now);

        // Wait long time
        let later = Time::from_millis(10_000);
        rl.refill(later);

        // Should still only have burst tokens
        assert_eq!(rl.available_tokens(), 10);
    }

    #[test]
    fn zero_cost_always_succeeds() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 10,
            burst: 0, // No burst capacity
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Zero cost should always succeed
        assert!(rl.try_acquire(0, now));
    }

    #[test]
    fn try_acquire_defers_to_queued_waiter_when_count_lags() {
        // enqueue() pushes a waiter onto the wait queue BEFORE it bumps
        // pending_queue_count, so there is a window where the queue holds a
        // waiting entry (result == None) but the counter still reads 0. A
        // fast-path try_acquire must defer to that waiter for FIFO fairness, not
        // barge its token (d8ji01). Reconstruct the window directly: a queued
        // unprocessed entry with the counter left at 0, and tokens available.
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 10,
            burst: 10,
            wait_strategy: WaitStrategy::Block,
            ..Default::default()
        });
        let now = Time::from_millis(0);

        rl.wait_queue.write().push_back(QueueEntry {
            id: 1,
            cost: 1,
            enqueued_at_millis: 0,
            deadline_millis: u64::MAX,
            result: None,
        });
        assert_eq!(
            rl.pending_queue_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "test models the window before enqueue bumps the count",
        );

        assert!(
            !rl.try_acquire(1, now),
            "try_acquire must defer to a queued waiter even when the count lags",
        );
    }

    #[test]
    fn reset_clears_pending_queue_state() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            burst: 1,
            wait_strategy: WaitStrategy::Block,
            ..Default::default()
        });

        let now = Time::from_millis(0);
        assert!(rl.try_acquire(1, now), "first token should be available");

        let entry_id = rl.enqueue(1, now).expect("second request should enqueue");
        assert_ne!(entry_id, u64::MAX, "enqueued entries use real IDs");
        assert_eq!(
            rl.pending_queue_count
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(rl.wait_queue.read().len(), 1);

        rl.reset();

        assert_eq!(
            rl.pending_queue_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "reset must clear pending queue count"
        );
        assert!(
            rl.wait_queue.read().is_empty(),
            "reset must clear wait queue"
        );
        assert!(
            rl.available_tokens() == 1,
            "reset must restore full burst capacity"
        );
    }

    #[test]
    fn reset_racing_cancel_never_wraps_the_pending_count() {
        // br-asupersync-r0x5ho: cancel_entry decremented the pending count after
        // releasing the queue lock, so a reset() zeroing it in between wrapped
        // it to u32::MAX and every later try_acquire failed. The window is a
        // few instructions wide, so this loops; a wrapped count is never a
        // legitimate value, whatever reset runs afterwards.
        let rl = Arc::new(RateLimiter::new(RateLimitPolicy {
            rate: 1,
            burst: 1,
            wait_strategy: WaitStrategy::Block,
            ..Default::default()
        }));
        let now = Time::from_millis(0);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let resetter = {
            let rl = Arc::clone(&rl);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    rl.reset();
                }
            })
        };
        for _ in 0..50_000 {
            let _ = rl.try_acquire(1, now);
            if let Ok(entry_id) = rl.enqueue(1, now) {
                rl.cancel_entry(entry_id, now);
            }
            let pending = rl
                .pending_queue_count
                .load(std::sync::atomic::Ordering::Relaxed);
            assert!(pending < 1 << 16, "pending count wrapped to {pending}");
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        resetter.join().expect("resetter thread");
        rl.reset();
        assert!(rl.try_acquire(1, now), "the fast path stays open");
    }

    #[test]
    fn reset_racing_a_grant_leaves_the_bucket_full() {
        // br-asupersync-e9gn8y L3: reset refilled the bucket, released the
        // state lock, then cleared the queue. A process_queue in between
        // granted the queued waiter from the fresh tokens and the clear dropped
        // that grant, so the bucket stayed short after the reset. Either order
        // of the two whole operations leaves it full. The window is narrow,
        // so this loops.
        let now = Time::from_millis(0);
        for _ in 0..20_000 {
            let rl = Arc::new(RateLimiter::new(RateLimitPolicy {
                rate: 1,
                burst: 1,
                wait_strategy: WaitStrategy::Block,
                ..Default::default()
            }));
            assert!(rl.try_acquire(1, now));
            let entry_id = rl.enqueue(1, now).expect("queued behind the empty bucket");
            assert_ne!(entry_id, IMMEDIATE_ACQUIRE_SENTINEL);
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let granter = {
                let rl = Arc::clone(&rl);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let _ = rl.process_queue(now);
                })
            };
            barrier.wait();
            rl.reset();
            granter.join().expect("granter thread");
            assert_eq!(
                rl.available_tokens(),
                1,
                "a grant the reset discarded kept its token"
            );
        }
    }

    #[test]
    fn retry_after_counts_the_tokens_queued_waiters_take_first() {
        // br-asupersync-r0x5ho: with tokens free but a queued waiter needing
        // more, try_acquire refuses (FIFO) yet retry_after said ZERO, so a
        // caller backing off on it spun.
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 5,
            period: Duration::from_secs(1),
            burst: 5,
            wait_strategy: WaitStrategy::Block,
            ..Default::default()
        });
        let now = Time::from_millis(0);
        assert!(rl.try_acquire(2, now));
        let waiter = rl.enqueue(5, now).expect("enqueue the waiter");
        assert_ne!(
            waiter, IMMEDIATE_ACQUIRE_SENTINEL,
            "3 tokens cannot serve 5"
        );
        assert!(!rl.try_acquire(1, now), "the queued waiter goes first");
        // 5 queued + 1 requested - 3 free = 3 tokens at 5 per second.
        assert_eq!(rl.retry_after(1, now), Duration::from_millis(600));
    }

    #[test]
    fn reset_clears_fractional_accumulator() {
        // Regression: reset() must zero the fractional accumulator so the
        // first refill period after reset starts fresh.
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: Duration::from_secs(10),
            burst: 10,
            ..Default::default()
        });

        // Drain all tokens and advance time to accumulate a fractional remainder.
        let t0 = Time::from_millis(0);
        assert!(rl.try_acquire(10, t0));

        // Advance 5 seconds: adds 0.5 tokens → 0 whole tokens, fractional = 5000.
        let t1 = Time::from_millis(5_000);
        rl.refill(t1);
        assert_eq!(
            rl.available_tokens(),
            0,
            "half-period yields no whole token"
        );

        rl.reset();

        // After reset, tokens should be full burst and fractional should be 0.
        assert_eq!(rl.available_tokens(), 10);

        // Drain again and advance exactly one period: should get exactly 1 token,
        // NOT 1 + leftover from stale fractional.
        let t2 = Time::from_millis(100_000);
        assert!(rl.try_acquire(10, t2));
        let t3 = Time::from_millis(110_000);
        rl.refill(t3);
        assert_eq!(
            rl.available_tokens(),
            1,
            "exactly one period after reset+drain must yield exactly 1 token"
        );
    }

    #[test]
    fn sub_millisecond_period_refills_after_one_millisecond() {
        // br-asupersync-e9gn8y: a 100 us period truncated to 0 ms, so the
        // bucket never refilled and retry_after said Duration::MAX.
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: Duration::from_micros(100),
            burst: 1,
            ..Default::default()
        });
        let t0 = Time::from_millis(1_000);
        assert!(rl.try_acquire(1, t0));
        assert!(!rl.try_acquire(1, t0));
        assert_eq!(rl.retry_after(1, t0), Duration::from_millis(1));
        assert!(rl.try_acquire(1, Time::from_millis(1_001)));
    }

    #[test]
    fn fractional_millisecond_period_admits_at_most_the_rate() {
        // br-asupersync-e9gn8y: a 1.9 ms period truncated to 1 ms admitted a
        // token every millisecond, 1.9 times the rate. Rounded up to 2 ms, it
        // never admits more than the rate.
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: Duration::from_micros(1_900),
            burst: 1,
            ..Default::default()
        });
        assert!(rl.try_acquire(1, Time::from_millis(1_000)));
        assert!(
            !rl.try_acquire(1, Time::from_millis(1_001)),
            "1 ms is less than one 1.9 ms period"
        );
        assert!(rl.try_acquire(1, Time::from_millis(1_002)));
    }

    #[test]
    fn sliding_window_sub_millisecond_period_expires_entries() {
        // br-asupersync-e9gn8y: a 100 us period truncated to 0 ms, so no entry
        // ever expired and the window stayed full forever.
        let rl = SlidingWindowRateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: Duration::from_micros(100),
            ..Default::default()
        });
        let t0 = Time::from_millis(1_000);
        assert!(rl.try_acquire(1, t0));
        assert!(!rl.try_acquire(1, t0));
        assert_eq!(rl.time_until_available(1, t0), Duration::from_millis(1));
        assert!(rl.try_acquire(1, Time::from_millis(1_001)));
    }

    // =========================================================================
    // Wait Strategy Tests
    // =========================================================================

    #[test]
    fn reject_strategy_fails_immediately() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            burst: 1,
            wait_strategy: WaitStrategy::Reject,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Use the token
        assert!(rl.try_acquire(1, now));

        // Next should fail
        assert!(!rl.try_acquire(1, now));
    }

    #[test]
    fn enqueue_with_reject_strategy_returns_error() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            burst: 1,
            wait_strategy: WaitStrategy::Reject,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Use the token
        assert!(rl.try_acquire(1, now));

        // Enqueue should return error
        let result = rl.enqueue(1, now);
        assert!(matches!(result, Err(RateLimitError::RateLimitExceeded)));
    }

    // =========================================================================
    // Weighted Operations Tests
    // =========================================================================

    #[test]
    fn weighted_operations_consume_multiple_tokens() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 100,
            burst: 10,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Heavy operation costs 5 tokens
        assert!(rl.try_acquire(5, now));
        assert_eq!(rl.available_tokens(), 5);

        // Another heavy operation
        assert!(rl.try_acquire(5, now));
        assert_eq!(rl.available_tokens(), 0);

        // Cannot do even light operation
        assert!(!rl.try_acquire(1, now));
    }

    #[test]
    fn call_panic_restores_consumed_tokens() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            burst: 1,
            period: Duration::from_secs(60),
            ..Default::default()
        });
        let now = Time::from_millis(0);

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = rl.call(now, || -> Result<(), &'static str> {
                panic!("intentional rate-limit call panic")
            });
        }));
        assert!(panic.is_err(), "inner operation should panic");
        assert_eq!(
            rl.available_tokens(),
            1,
            "panic path must refund the consumed token"
        );

        let result = rl.call(now, || Ok::<u32, &'static str>(7));
        assert_eq!(result.unwrap(), 7);
    }

    // =========================================================================
    // Time Until Available Tests
    // =========================================================================

    #[test]
    fn time_until_available_when_empty() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 10, // 10 per second
            period: Duration::from_secs(1),
            burst: 10,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Exhaust tokens
        assert!(rl.try_acquire(10, now));

        // Need 1 token = 100ms // ubs:ignore - test comment
        let wait = rl.time_until_available(1, now);
        assert!(
            wait.as_millis() >= 90 && wait.as_millis() <= 110,
            "Expected ~100ms, got {wait:?}"
        );
    }

    #[test]
    fn time_until_available_zero_when_sufficient() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 100,
            burst: 10,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        let wait = rl.time_until_available(5, now);
        assert_eq!(wait, Duration::ZERO);
    }

    #[test]
    fn retry_after_uses_provided_time() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 10,
            period: Duration::from_secs(1),
            burst: 10,
            ..Default::default()
        });

        let now = Time::from_millis(0);
        assert!(rl.try_acquire(10, now));

        // Using the provided time (not system time)
        let retry = rl.retry_after(1, now);
        assert!(retry.as_millis() >= 90 && retry.as_millis() <= 110);

        // With later time, should be less
        let later = Time::from_millis(50);
        let retry_later = rl.retry_after(1, later);
        assert!(retry_later < retry);
    }

    // =========================================================================
    // Metrics Tests
    // =========================================================================

    #[test]
    fn metrics_initial_values() {
        let rl = RateLimiter::new(RateLimitPolicy {
            name: "test".into(),
            rate: 100,
            burst: 10,
            ..Default::default()
        });

        let m = rl.metrics();
        assert_eq!(m.total_allowed, 0);
        assert_eq!(m.total_rejected, 0);
        assert_eq!(m.total_waited, 0);
        assert_eq!(m.total_wait_time, Duration::ZERO);
        assert_eq!(m.max_wait_time, Duration::ZERO);
    }

    #[test]
    fn metrics_track_allowed() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 100,
            burst: 10,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        assert!(rl.try_acquire(1, now));
        assert!(rl.try_acquire(1, now));
        assert!(rl.try_acquire(1, now));

        assert_eq!(rl.metrics().total_allowed, 3);
    }

    // =========================================================================
    // Queue Tests
    // =========================================================================

    #[test]
    fn enqueue_immediate_acquisition_returns_sentinel() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 100,
            burst: 10,
            wait_strategy: WaitStrategy::Block,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Should succeed immediately and return sentinel
        let result = rl.enqueue(1, now);
        assert_eq!(result, Ok(IMMEDIATE_ACQUIRE_SENTINEL));
    }

    #[test]
    fn enqueue_adds_to_queue_when_exhausted() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: Duration::from_secs(1),
            burst: 1,
            wait_strategy: WaitStrategy::Block,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Exhaust tokens
        assert!(rl.try_acquire(1, now));

        // Enqueue should succeed and return a real ID
        let result = rl.enqueue(1, now);
        assert!(result.is_ok());
        assert_ne!(result.unwrap(), IMMEDIATE_ACQUIRE_SENTINEL);
    }

    #[test]
    fn queued_entry_ids_fail_closed_when_id_space_exhausts() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: Duration::from_secs(1),
            burst: 1,
            wait_strategy: WaitStrategy::Block,
            ..Default::default()
        });

        let now = Time::from_millis(0);
        assert!(rl.try_acquire(1, now), "first token should be consumed");

        let first_live_id = rl
            .enqueue(1, now)
            .expect("first queued entry should be accepted");
        assert_eq!(first_live_id, 0);

        let last_real_id = rl
            .enqueue(1, now)
            .expect("queue entry before wrap should be accepted");
        assert_eq!(last_real_id, 1);

        rl.next_id
            .store(IMMEDIATE_ACQUIRE_SENTINEL - 1, Ordering::Relaxed);

        let edge_id = rl
            .enqueue(1, now)
            .expect("queue entry at wrap edge should be accepted");
        assert_eq!(edge_id, IMMEDIATE_ACQUIRE_SENTINEL - 1);

        let exhausted = rl.enqueue(1, now);
        assert_eq!(
            exhausted,
            Err(RateLimitError::QueueIdExhausted),
            "allocator must fail closed instead of reusing queue IDs after exhaustion"
        );
        assert_ne!(edge_id, IMMEDIATE_ACQUIRE_SENTINEL);
        assert_ne!(edge_id, first_live_id);
        assert_ne!(edge_id, last_real_id);
    }

    #[test]
    fn stale_queue_handle_cannot_alias_later_waiter_after_exhaustion() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: Duration::from_secs(1),
            burst: 1,
            wait_strategy: WaitStrategy::Block,
            ..Default::default()
        });

        let now = Time::from_millis(0);
        assert!(rl.try_acquire(1, now), "first token should be consumed");

        let stale_id = rl
            .enqueue(1, now)
            .expect("first queued entry should be accepted");
        assert_eq!(stale_id, 0);
        rl.cancel_entry(stale_id, now);

        rl.next_id
            .store(IMMEDIATE_ACQUIRE_SENTINEL - 1, Ordering::Relaxed);

        let live_id = rl
            .enqueue(1, now)
            .expect("last queue ID before exhaustion should still be usable");
        assert_eq!(live_id, IMMEDIATE_ACQUIRE_SENTINEL - 1);

        assert_eq!(
            rl.enqueue(1, now),
            Err(RateLimitError::QueueIdExhausted),
            "new waiters must not reuse a stale external handle after exhaustion"
        );

        rl.cancel_entry(stale_id, now);
        assert!(
            matches!(rl.check_entry(live_id, now), Ok(false)),
            "stale handle cancellation must not affect the later waiter"
        );
    }

    #[test]
    fn process_queue_grants_when_tokens_available() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 10, // 10 per second
            period: Duration::from_secs(1),
            burst: 1,
            wait_strategy: WaitStrategy::Block,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Exhaust tokens
        assert!(rl.try_acquire(1, now));

        // Enqueue
        let entry_id = rl.enqueue(1, now).unwrap();

        // Process at same time - should not grant
        assert!(rl.process_queue(now).is_none());

        // Process after 100ms - should grant (tokens refilled)
        let later = Time::from_millis(100);
        let granted = rl.process_queue(later);
        assert_eq!(granted, Some(entry_id));
    }

    #[test]
    fn check_entry_returns_granted() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 10,
            period: Duration::from_secs(1),
            burst: 1,
            wait_strategy: WaitStrategy::Block,
            ..Default::default()
        });

        let now = Time::from_millis(0);
        assert!(rl.try_acquire(1, now));

        let entry_id = rl.enqueue(1, now).unwrap();

        // Still waiting at t=0
        let result = rl.check_entry(entry_id, now);
        assert!(matches!(result, Ok(false)));

        // Granted at t=100
        let later = Time::from_millis(100);
        let result = rl.check_entry(entry_id, later);
        assert!(matches!(result, Ok(true)));
    }

    #[test]
    fn check_entry_timeout() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: Duration::from_secs(60), // Very slow refill
            burst: 1,
            wait_strategy: WaitStrategy::BlockWithTimeout(Duration::from_millis(100)),
            ..Default::default()
        });

        let now = Time::from_millis(0);
        assert!(rl.try_acquire(1, now));

        let entry_id = rl.enqueue(1, now).unwrap();

        // Check after timeout
        let later = Time::from_millis(200);
        let result = rl.check_entry(entry_id, later);
        assert!(matches!(result, Err(RateLimitError::Timeout { .. })));
    }

    #[test]
    fn check_entry_grants_when_tokens_refill_exactly_at_timeout_boundary() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: Duration::from_millis(100),
            burst: 1,
            wait_strategy: WaitStrategy::BlockWithTimeout(Duration::from_millis(100)),
            ..Default::default()
        });

        let now = Time::from_millis(0);
        assert!(rl.try_acquire(1, now));

        let entry_id = rl.enqueue(1, now).unwrap();

        let boundary = Time::from_millis(100);
        let result = rl.check_entry(entry_id, boundary);
        assert!(
            matches!(result, Ok(true)),
            "entry should be granted when refill lands exactly on the timeout boundary, got {result:?}"
        );
    }

    #[test]
    fn cancel_entry_triggers_cancelled_error() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: Duration::from_secs(60),
            burst: 1,
            wait_strategy: WaitStrategy::Block,
            ..Default::default()
        });

        let now = Time::from_millis(0);
        assert!(rl.try_acquire(1, now));

        let entry_id = rl.enqueue(1, now).unwrap();

        // Cancel
        rl.cancel_entry(entry_id, now);

        // Check - should return Cancelled
        let result = rl.check_entry(entry_id, now);
        assert!(matches!(result, Err(RateLimitError::Cancelled)));
    }

    #[test]
    fn checked_timeout_behind_granted_is_immediately_removed() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: Duration::from_millis(100),
            burst: 1,
            wait_strategy: WaitStrategy::BlockWithTimeout(Duration::from_millis(150)),
            ..Default::default()
        });

        let now = Time::from_millis(0);
        assert!(rl.try_acquire(1, now));

        let id1 = rl.enqueue(1, now).unwrap();
        let id2 = rl.enqueue(1, now).unwrap();

        let grant_time = Time::from_millis(100);
        assert_eq!(rl.process_queue(grant_time), Some(id1));
        assert_eq!(rl.wait_queue.read().len(), 2);

        let timeout_time = Time::from_millis(200);
        let result = rl.check_entry(id2, timeout_time);
        assert!(matches!(result, Err(RateLimitError::Timeout { .. })));
        assert_eq!(
            rl.wait_queue.read().len(),
            1,
            "timed-out entry is immediately removed; only the unconsumed granted entry remains"
        );

        let _ = rl.check_entry(id1, timeout_time);
        assert_eq!(
            rl.wait_queue.read().len(),
            0,
            "granted entry removed on claim"
        );
    }

    #[test]
    fn try_acquire_clears_timed_out_queue_entries_before_rejecting_fast_path() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: Duration::from_millis(100),
            burst: 1,
            wait_strategy: WaitStrategy::BlockWithTimeout(Duration::from_millis(10)),
            ..Default::default()
        });

        let now = Time::from_millis(0);
        assert!(rl.try_acquire(1, now));
        let _entry_id = rl.enqueue(1, now).expect("second request should enqueue");

        let later = Time::from_millis(200);
        assert!(
            rl.try_acquire(1, later),
            "timed-out queue entries must not permanently block later fast-path acquires"
        );
    }

    #[test]
    fn try_acquire_processes_queue_grants_before_evaluating_fast_path() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: Duration::from_millis(100),
            burst: 1,
            wait_strategy: WaitStrategy::Block,
            ..Default::default()
        });

        let now = Time::from_millis(0);
        assert!(rl.try_acquire(1, now));
        let entry_id = rl.enqueue(1, now).expect("second request should enqueue");

        let later = Time::from_millis(100);
        assert!(
            !rl.try_acquire(1, later),
            "queued waiter must be granted before a new fast-path caller can consume refilled tokens"
        );
        assert!(
            matches!(rl.check_entry(entry_id, later), Ok(true)),
            "queued waiter should have been granted when try_acquire processed the queue"
        );
    }

    #[test]
    fn metamorphic_appending_tail_waiters_preserves_first_fifo_grant() {
        let base = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: Duration::from_millis(100),
            burst: 1,
            wait_strategy: WaitStrategy::Block,
            ..Default::default()
        });
        let extended = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: Duration::from_millis(100),
            burst: 1,
            wait_strategy: WaitStrategy::Block,
            ..Default::default()
        });

        let now = Time::from_millis(0);
        assert!(base.try_acquire(1, now));
        assert!(extended.try_acquire(1, now));

        let base_head = base.enqueue(1, now).expect("head waiter should enqueue");
        let extended_head = extended
            .enqueue(1, now)
            .expect("head waiter should enqueue");
        let extended_tail = extended
            .enqueue(1, now)
            .expect("tail waiter should enqueue");

        let refill = Time::from_millis(100);
        assert_eq!(base.process_queue(refill), Some(base_head));
        assert_eq!(extended.process_queue(refill), Some(extended_head));

        assert!(
            matches!(base.check_entry(base_head, refill), Ok(true)),
            "single queued waiter should be granted on first refill"
        );
        assert!(
            matches!(extended.check_entry(extended_head, refill), Ok(true)),
            "head waiter must still win first refill after appending tail waiters"
        );
        assert!(
            matches!(extended.check_entry(extended_tail, refill), Ok(false)),
            "tail waiter must remain queued until a later refill"
        );
    }

    // =========================================================================
    // Sliding Window Tests
    // =========================================================================

    #[test]
    fn sliding_window_enforces_rate() {
        let rl = SlidingWindowRateLimiter::new(RateLimitPolicy {
            rate: 5,
            period: Duration::from_secs(1),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // 5 operations should succeed
        for _ in 0..5 {
            assert!(rl.try_acquire(1, now));
        }

        // 6th should fail
        assert!(!rl.try_acquire(1, now));
    }

    #[test]
    fn sliding_window_clears_old_entries() {
        let rl = SlidingWindowRateLimiter::new(RateLimitPolicy {
            rate: 5,
            period: Duration::from_secs(1),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Fill window
        for _ in 0..5 {
            assert!(rl.try_acquire(1, now));
        }

        // After period, should allow more
        let later = Time::from_millis(1100);
        assert!(rl.try_acquire(1, later));
    }

    #[test]
    fn sliding_window_time_until_available() {
        let rl = SlidingWindowRateLimiter::new(RateLimitPolicy {
            name: "test".into(),
            rate: 5,
            period: Duration::from_secs(1),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Fill window
        for _ in 0..5 {
            assert!(rl.try_acquire(1, now));
        }

        // Should need to wait for first entry to expire
        let wait = rl.time_until_available(1, now);
        assert!(
            wait >= Duration::from_millis(900) && wait <= Duration::from_millis(1100),
            "Expected ~1000ms, got {wait:?}"
        );
    }

    #[test]
    fn sliding_window_max_rate_boundary_uses_wide_arithmetic() {
        let period = Duration::from_secs(1);
        let rl = SlidingWindowRateLimiter::new(RateLimitPolicy {
            rate: u32::MAX,
            period,
            ..Default::default()
        });
        let start = Time::from_millis(7);

        assert!(rl.try_acquire(u32::MAX - 1, start));
        assert!(rl.try_acquire(1, start), "exactly-at-limit cost must fit");
        assert!(
            !rl.try_acquire(1, start),
            "cost beyond u32::MAX rate must not be admitted by saturation"
        );
        assert_eq!(rl.time_until_available(1, start), period);

        let boundary = Time::from_millis(1_007);
        assert!(
            rl.try_acquire(1, boundary),
            "capacity must return exactly when the window expires"
        );
    }

    #[test]
    fn sliding_window_extreme_policy_does_not_preallocate_from_limits() {
        let max_rate = SlidingWindowRateLimiter::new(RateLimitPolicy {
            rate: u32::MAX,
            ..Default::default()
        });
        let max_burst = SlidingWindowRateLimiter::new(RateLimitPolicy {
            burst: u32::MAX,
            ..Default::default()
        });

        assert_eq!(max_rate.window.read().entries.capacity(), 0);
        assert_eq!(max_burst.window.read().entries.capacity(), 0);
    }

    #[test]
    fn sliding_window_cost_total_matches_a_full_resum() {
        // br-asupersync-e9gn8y L4: the window's cost was re-summed over every
        // entry on each call, O(rate) under the write lock. The running total
        // must make exactly the decisions the full re-sum made, through admits,
        // refusals, zero-cost calls, expiry and a reset.
        let policy = RateLimitPolicy {
            rate: 10,
            period: Duration::from_millis(100),
            ..Default::default()
        };
        let rl = SlidingWindowRateLimiter::new(policy.clone());
        let mut model: VecDeque<(u64, u32)> = VecDeque::new();
        let (mut admitted, mut refused) = (0, 0);
        for step in 0..200u64 {
            let now = step * 7;
            let cost = u32::try_from(step % 5).unwrap();
            if step == 120 {
                rl.reset();
                model.clear();
            }
            model.retain(|&(t, _)| now - t < 100);
            let used: u64 = model.iter().map(|&(_, c)| u64::from(c)).sum();
            let expected = used + u64::from(cost) <= u64::from(policy.rate);
            let expected_wait = if expected {
                Duration::ZERO
            } else {
                let needed = used + u64::from(cost) - u64::from(policy.rate);
                let mut freed = 0;
                let (t, _) = model
                    .iter()
                    .find(|&&(_, c)| {
                        freed += u64::from(c);
                        freed >= needed
                    })
                    .copied()
                    .expect("a refused cost within the rate frees up");
                Duration::from_millis(t + 100 - now)
            };
            assert_eq!(
                rl.time_until_available(cost, Time::from_millis(now)),
                expected_wait,
                "step {step}: wait for cost {cost} with {used} in the window"
            );
            assert_eq!(
                rl.try_acquire(cost, Time::from_millis(now)),
                expected,
                "step {step}: cost {cost} with {used} in the window"
            );
            if expected {
                admitted += 1;
                if cost > 0 {
                    model.push_back((now, cost));
                }
            } else {
                refused += 1;
            }
            let window = rl.window.read();
            assert_eq!(window.entries, model, "step {step}");
            assert_eq!(
                window.cost,
                model.iter().map(|&(_, c)| u64::from(c)).sum::<u64>(),
                "step {step}"
            );
        }
        assert!(
            admitted > 50 && refused > 20,
            "{admitted} admitted, {refused} refused"
        );
    }

    #[test]
    fn sliding_window_period_overflow_does_not_wrap() {
        let overflowing_millis = Duration::new(18_446_744_073_709_551, 616_000_000);
        let rl = SlidingWindowRateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: overflowing_millis,
            ..Default::default()
        });

        let now = Time::from_millis(0);
        assert!(rl.try_acquire(1, now));
        // With saturating conversion this second acquire must be rejected:
        // the first entry remains inside the (effectively max) window.
        assert!(!rl.try_acquire(1, Time::from_millis(1)));
    }

    // =========================================================================
    // Registry Tests
    // =========================================================================

    #[test]
    fn registry_creates_named_limiters() {
        let registry = RateLimiterRegistry::new(RateLimitPolicy::default());

        let l1 = registry.get_or_create("api-a");
        let l2 = registry.get_or_create("api-b");
        let l3 = registry.get_or_create("api-a");

        assert!(Arc::ptr_eq(&l1, &l3));
        assert!(!Arc::ptr_eq(&l1, &l2));
    }

    #[test]
    fn registry_uses_provided_name() {
        let registry = RateLimiterRegistry::new(RateLimitPolicy::default());

        let l = registry.get_or_create("my-api");
        assert_eq!(l.name(), "my-api");
    }

    #[test]
    fn registry_custom_policy() {
        let registry = RateLimiterRegistry::new(RateLimitPolicy::default());

        let l = registry.get_or_create_with(
            "custom",
            RateLimitPolicy {
                rate: 1000,
                burst: 500,
                ..Default::default()
            },
        );

        assert_eq!(l.available_tokens(), 500);
    }

    #[test]
    fn registry_remove() {
        let registry = RateLimiterRegistry::new(RateLimitPolicy::default());

        let l1 = registry.get_or_create("temp");
        let removed = registry.remove("temp");

        assert!(removed.is_some());
        assert!(Arc::ptr_eq(&l1, &removed.unwrap()));
        assert!(registry.remove("temp").is_none());
    }

    #[test]
    fn registry_all_metrics() {
        let registry = RateLimiterRegistry::new(RateLimitPolicy::default());

        let l1 = registry.get_or_create("api-1");
        let l2 = registry.get_or_create("api-2");

        let now = Time::from_millis(0);
        assert!(l1.try_acquire(1, now));
        assert!(l2.try_acquire(2, now));

        let all = registry.all_metrics();
        assert_eq!(all.len(), 2);
        assert_eq!(all.get("api-1").unwrap().total_allowed, 1);
        assert_eq!(all.get("api-2").unwrap().total_allowed, 1);
    }

    // =========================================================================
    // Concurrent Access Tests
    // =========================================================================

    #[test]
    fn concurrent_acquire_safe() {
        use std::sync::atomic::AtomicU32;
        use std::thread;

        let rl = Arc::new(RateLimiter::new(RateLimitPolicy {
            rate: 1000,
            burst: 1000,
            ..Default::default()
        }));

        let now = Time::from_millis(0);
        let acquired = Arc::new(AtomicU32::new(0));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let rl = rl.clone();
                let acq = acquired.clone();
                thread::spawn(move || {
                    for _ in 0..100 {
                        if rl.try_acquire(1, now) {
                            acq.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // Should have acquired exactly burst amount
        assert_eq!(acquired.load(Ordering::SeqCst), 1000);
    }

    // =========================================================================
    // Builder Tests
    // =========================================================================

    #[test]
    fn builder_creates_policy() {
        let policy = RateLimitPolicyBuilder::new()
            .name("test")
            .rate(50)
            .period(Duration::from_millis(500))
            .burst(20)
            .default_cost(2)
            .wait_strategy(WaitStrategy::Reject)
            .build();

        assert_eq!(policy.name, "test");
        assert_eq!(policy.rate, 50);
        assert_eq!(policy.period, Duration::from_millis(500));
        assert_eq!(policy.burst, 20);
        assert_eq!(policy.default_cost, 2);
        assert!(matches!(policy.wait_strategy, WaitStrategy::Reject));
    }

    // =========================================================================
    // Error Display Tests
    // =========================================================================

    #[test]
    fn error_display() {
        let exceeded: RateLimitError<&str> = RateLimitError::RateLimitExceeded;
        assert!(exceeded.to_string().contains("exceeded"));

        let exhausted: RateLimitError<&str> = RateLimitError::QueueIdExhausted;
        assert!(exhausted.to_string().contains("queue ID space exhausted"));

        let timeout: RateLimitError<&str> = RateLimitError::Timeout {
            waited: Duration::from_millis(100),
        };
        assert!(timeout.to_string().contains("timeout"));

        let cancelled: RateLimitError<&str> = RateLimitError::Cancelled;
        assert!(cancelled.to_string().contains("cancelled"));

        let inner: RateLimitError<&str> = RateLimitError::Inner("inner error");
        assert_eq!(inner.to_string(), "inner error");
    }

    #[test]
    fn rate_limit_error_debug_clone_eq() {
        let e = RateLimitError::<String>::RateLimitExceeded;
        let dbg = format!("{e:?}");
        assert!(dbg.contains("RateLimitExceeded"), "{dbg}");
        let cloned = e.clone();
        assert_eq!(e, cloned);

        let e2 = RateLimitError::<String>::Timeout {
            waited: Duration::from_millis(200),
        };
        assert_ne!(e, e2);
    }

    #[test]
    fn test_slow_rate_starvation() {
        // Rate: 0.5 per second (1 per 2000ms)
        // 0.5 tokens/sec = 0.0005 tokens/ms
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: Duration::from_secs(2),
            burst: 1,
            ..Default::default()
        });

        let now = Time::from_millis(0);
        // Consume burst
        assert!(rl.try_acquire(1, now));

        // Poll every 1ms for 4 seconds.
        // Should accrue ~2 tokens.
        let mut acquired = false;
        let mut t = now;

        for _ in 0..4000 {
            t = Time::from_millis(t.as_millis() + 1);
            // Try to acquire 1 token
            if rl.try_acquire(1, t) {
                acquired = true;
                break;
            }
        }

        assert!(
            acquired,
            "Failed to acquire token due to precision loss starvation"
        );
    }

mod queued_acquisition_ownership {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::{Barrier, mpsc};
    use std::time::Instant;

    fn limiter(rate: u32, burst: u32) -> RateLimiter {
        RateLimiter::new(RateLimitPolicy {
            rate,
            period: Duration::from_secs(1),
            burst,
            ..Default::default()
        })
    }

    #[test]
    fn immediate_guard_refunds_or_transfers_its_credit_exactly_once() {
        let rl = limiter(0, 3);
        let now = Time::ZERO;

        let guard = rl.acquire_queued_bounded(2, now, 0).unwrap();
        assert_eq!(rl.available_tokens(), 1);
        assert!(rl.wait_queue.read().is_empty());
        drop(guard);
        assert_eq!(rl.available_tokens(), 3);

        let mut guard = rl.acquire_queued_bounded(2, now, 0).unwrap();
        let permit = guard.poll_claim(now).unwrap().expect("immediate permit");
        assert!(matches!(
            guard.poll_claim(now),
            Err(RateLimitError::Cancelled)
        ));
        assert!(rl.try_acquire(1, now));
        drop(guard);
        assert_eq!(rl.available_tokens(), 0, "only the permit owns the credit");
        drop(permit);
        assert_eq!(rl.available_tokens(), 2);

        let mut guard = rl.acquire_queued(2, now).unwrap();
        guard.poll_claim(now).unwrap().unwrap().commit();
        drop(guard);
        assert_eq!(rl.available_tokens(), 0, "committed credit stays consumed");
        assert!(matches!(
            rl.acquire_queued_bounded(1, now, 0),
            Err(RateLimitError::RateLimitExceeded)
        ));
        assert!(rl.wait_queue.read().is_empty());
    }

    #[test]
    fn dropping_a_pending_guard_releases_capacity_and_wait_accounting() {
        let rl = limiter(0, 2);
        assert!(rl.try_acquire(2, Time::ZERO));

        let mut guard = rl.acquire_queued_bounded(2, Time::ZERO, 1).unwrap();
        assert!(guard.poll_claim(Time::from_millis(9)).unwrap().is_none());
        assert!(matches!(
            rl.acquire_queued_bounded(1, Time::from_millis(9), 1),
            Err(RateLimitError::RateLimitExceeded)
        ));
        assert_eq!(rl.wait_queue.read().len(), 1);
        assert_eq!(rl.pending_queue_count.load(Ordering::Relaxed), 1);
        drop(guard);

        assert!(rl.wait_queue.read().is_empty());
        assert_eq!(rl.pending_queue_count.load(Ordering::Relaxed), 0);
        assert_eq!(rl.metrics().total_wait_time, Duration::from_millis(9));
        assert_eq!(rl.available_tokens(), 0, "an ungranted entry has no refund");
        drop(
            rl.acquire_queued_bounded(1, Time::from_millis(9), 1)
                .unwrap(),
        );
        assert!(rl.wait_queue.read().is_empty());
    }

    #[test]
    fn a_grant_keeps_queue_capacity_until_claim_and_refunds_only_via_its_owner() {
        let rl = limiter(1, 1);
        assert!(rl.try_acquire(1, Time::ZERO));
        let mut first = rl.acquire_queued_bounded(1, Time::ZERO, 1).unwrap();
        let granted_at = Time::from_millis(1000);
        assert!(rl.process_queue(granted_at).is_some());
        assert_eq!(rl.pending_queue_count.load(Ordering::Relaxed), 0);
        assert_eq!(rl.wait_queue.read().len(), 1);
        assert!(matches!(
            rl.acquire_queued_bounded(1, granted_at, 1),
            Err(RateLimitError::RateLimitExceeded)
        ));

        let permit = first.poll_claim(granted_at).unwrap().unwrap();
        assert!(rl.wait_queue.read().is_empty());
        let mut second = rl.acquire_queued_bounded(1, granted_at, 1).unwrap();
        drop(first);
        assert_eq!(rl.available_tokens(), 0);
        assert!(second.poll_claim(granted_at).unwrap().is_none());
        drop(permit);

        second.poll_claim(granted_at).unwrap().unwrap().commit();
        drop(second);
        assert_eq!(rl.available_tokens(), 0);
        assert!(rl.wait_queue.read().is_empty());
    }

    #[test]
    fn dropping_an_unclaimed_grant_hands_its_credit_to_the_next_waiter() {
        let rl = limiter(1, 2);
        assert!(rl.try_acquire(2, Time::ZERO));
        let first = rl.acquire_queued_bounded(2, Time::ZERO, 2).unwrap();
        let mut second = rl.acquire_queued_bounded(1, Time::ZERO, 2).unwrap();
        let granted_at = Time::from_millis(2000);
        assert!(rl.process_queue(granted_at).is_some());
        assert_eq!(rl.available_tokens(), 0);
        assert_eq!(rl.pending_queue_count.load(Ordering::Relaxed), 1);

        drop(first);
        assert_eq!(rl.wait_queue.read().len(), 1);
        assert_eq!(rl.pending_queue_count.load(Ordering::Relaxed), 0);
        assert_eq!(rl.available_tokens(), 1);
        let permit = second.poll_claim(granted_at).unwrap().unwrap();
        drop(second);
        assert_eq!(rl.available_tokens(), 1);
        permit.commit();
        assert_eq!(rl.available_tokens(), 1);
        assert!(rl.wait_queue.read().is_empty());
    }

    #[test]
    fn queued_ownership_preserves_weighted_fifo_until_the_head_is_cancelled() {
        let rl = limiter(1, 3);
        assert!(rl.try_acquire(3, Time::ZERO));
        let head = rl.acquire_queued_bounded(3, Time::ZERO, 2).unwrap();
        let mut tail = rl.acquire_queued_bounded(1, Time::ZERO, 2).unwrap();
        let now = Time::from_millis(2000);

        assert!(tail.poll_claim(now).unwrap().is_none());
        assert_eq!(rl.available_tokens(), 2);
        assert!(!rl.try_acquire(1, now), "new work cannot bypass the head");
        drop(head);
        tail.poll_claim(now).unwrap().unwrap().commit();
        assert_eq!(rl.available_tokens(), 1);
        assert!(rl.wait_queue.read().is_empty());
    }

    #[test]
    fn timeout_records_count_toward_the_bound_until_observed_or_dropped() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 0,
            burst: 1,
            wait_strategy: WaitStrategy::BlockWithTimeout(Duration::from_millis(10)),
            ..Default::default()
        });
        assert!(rl.try_acquire(1, Time::ZERO));
        let mut first = rl.acquire_queued_bounded(1, Time::ZERO, 1).unwrap();
        let deadline = Time::from_millis(10);
        assert!(rl.process_queue(deadline).is_none());
        assert_eq!(rl.pending_queue_count.load(Ordering::Relaxed), 0);
        assert_eq!(rl.wait_queue.read().len(), 1);
        assert!(matches!(
            rl.acquire_queued_bounded(1, deadline, 1),
            Err(RateLimitError::RateLimitExceeded)
        ));
        assert!(matches!(
            first.poll_claim(deadline),
            Err(RateLimitError::Timeout { waited }) if waited == Duration::from_millis(10)
        ));
        assert!(matches!(
            first.poll_claim(deadline),
            Err(RateLimitError::Cancelled)
        ));
        drop(first);
        assert!(rl.wait_queue.read().is_empty());

        let second = rl.acquire_queued_bounded(1, deadline, 1).unwrap();
        assert!(rl.process_queue(Time::from_millis(20)).is_none());
        assert_eq!(rl.wait_queue.read().len(), 1);
        drop(second);
        assert!(rl.wait_queue.read().is_empty());
        assert_eq!(rl.available_tokens(), 0, "timeouts never refund tokens");
    }

    #[test]
    fn a_grant_at_the_deadline_wins_over_timeout() {
        let rl = RateLimiter::new(RateLimitPolicy {
            rate: 100,
            period: Duration::from_secs(1),
            burst: 1,
            wait_strategy: WaitStrategy::BlockWithTimeout(Duration::from_millis(10)),
            ..Default::default()
        });
        assert!(rl.try_acquire(1, Time::ZERO));
        let mut guard = rl.acquire_queued_bounded(1, Time::ZERO, 1).unwrap();
        guard
            .poll_claim(Time::from_millis(10))
            .unwrap()
            .expect("tokens become available at the deadline")
            .commit();
        assert!(rl.wait_queue.read().is_empty());
        assert_eq!(rl.available_tokens(), 0);
    }

    #[test]
    fn a_reset_invalidates_a_queued_guard_without_refunding_new_work() {
        let rl = limiter(0, 1);
        assert!(rl.try_acquire(1, Time::ZERO));
        let mut guard = rl.acquire_queued_bounded(1, Time::ZERO, 1).unwrap();
        rl.reset();
        assert!(rl.try_acquire(1, Time::ZERO));
        assert!(matches!(
            guard.poll_claim(Time::ZERO),
            Err(RateLimitError::Cancelled)
        ));
        drop(guard);
        assert!(rl.wait_queue.read().is_empty());
        assert_eq!(rl.pending_queue_count.load(Ordering::Relaxed), 0);
        assert_eq!(rl.available_tokens(), 0);
    }

    #[test]
    fn concurrent_bounded_admission_cannot_overfill_the_queue() {
        const CALLERS: usize = 8;
        const LIMIT: usize = 3;
        let rl = limiter(0, 1);
        assert!(rl.try_acquire(1, Time::ZERO));
        let admitted = AtomicUsize::new(0);
        let barrier = Barrier::new(CALLERS + 1);

        let (retained, pending, outcomes) = std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for _ in 0..CALLERS {
                let rl = &rl;
                let admitted = &admitted;
                let barrier = &barrier;
                workers.push(scope.spawn(move || {
                    let guard = rl.acquire_queued_bounded(1, Time::ZERO, LIMIT);
                    if guard.is_ok() {
                        admitted.fetch_add(1, Ordering::SeqCst);
                    }
                    let expected_error = matches!(&guard, Err(RateLimitError::RateLimitExceeded));
                    // Every successful guard remains alive until the observer
                    // measures the queue, so admissions cannot reuse slots.
                    barrier.wait();
                    barrier.wait();
                    let granted = guard.is_ok();
                    drop(guard);
                    (granted, expected_error)
                }));
            }
            barrier.wait();
            let retained = rl.wait_queue.read().len();
            let pending = rl.pending_queue_count.load(Ordering::Relaxed);
            // Release workers before making assertions, including on failure.
            barrier.wait();
            let outcomes = workers
                .into_iter()
                .map(|worker| worker.join().expect("queue admission worker"))
                .collect::<Vec<_>>();
            (retained, pending, outcomes)
        });

        assert_eq!(admitted.load(Ordering::SeqCst), LIMIT);
        assert_eq!(retained, LIMIT);
        assert_eq!(pending as usize, LIMIT);
        assert!(
            outcomes
                .iter()
                .all(|(granted, rejected)| granted != rejected)
        );
        assert_eq!(rl.metrics().total_waited, LIMIT as u64);
        assert_eq!(rl.metrics().total_rejected, (CALLERS - LIMIT) as u64);
        assert_eq!(rl.next_id.load(Ordering::Relaxed), LIMIT as u64);
        assert!(rl.wait_queue.read().is_empty());
        assert_eq!(rl.pending_queue_count.load(Ordering::Relaxed), 0);
    }

    fn native_cancelled_owner(multi_thread: bool, grant_before_cancel: bool) {
        use crate::Cx;
        use crate::channel::oneshot;
        use crate::runtime::{RuntimeBuilder, yield_now};
        use std::future::{Future, poll_fn};

        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let runner = std::thread::spawn(move || {
            let builder = if multi_thread {
                RuntimeBuilder::multi_thread().worker_threads(2)
            } else {
                RuntimeBuilder::current_thread()
            };
            let runtime = builder.build().expect("build native rate-limit runtime");
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().expect("native task context");
                let rl = Arc::new(limiter(1, 1));
                assert!(rl.try_acquire(1, Time::ZERO));
                let parked = Arc::new(AtomicBool::new(false));
                let child_parked = Arc::clone(&parked);
                let child_rl = Arc::clone(&rl);
                let (_hold_tx, mut hold_rx) = oneshot::channel::<()>();
                let child = cx
                    .spawn(move |child_cx| async move {
                        let guard = child_rl
                            .acquire_queued_bounded(1, Time::ZERO, 1)
                            .expect("queue the cancellable owner");
                        let mut wait = std::pin::pin!(hold_rx.recv(&child_cx));
                        let result = poll_fn(|task_cx| {
                            let result = wait.as_mut().poll(task_cx);
                            if result.is_pending() {
                                child_parked.store(true, Ordering::SeqCst);
                            }
                            result
                        })
                        .await;
                        assert!(result.is_err(), "the owner must observe cancellation");
                        drop(guard);
                    })
                    .expect("spawn queued acquisition owner");

                let started = Instant::now();
                while !parked.load(Ordering::SeqCst) {
                    assert!(
                        started.elapsed() < Duration::from_secs(5),
                        "owner must park while retaining its queue entry"
                    );
                    yield_now().await;
                }
                assert_eq!(rl.wait_queue.read().len(), 1);
                if grant_before_cancel {
                    assert!(rl.process_queue(Time::from_millis(1000)).is_some());
                    assert_eq!(rl.pending_queue_count.load(Ordering::Relaxed), 0);
                } else {
                    assert_eq!(rl.pending_queue_count.load(Ordering::Relaxed), 1);
                }

                let mut child = if multi_thread {
                    std::thread::spawn(move || {
                        child.abort();
                        child
                    })
                    .join()
                    .expect("cross-thread cancellation request")
                } else {
                    child.abort();
                    child
                };
                child.join(&cx).await.expect("join cancelled queue owner");
                assert!(rl.wait_queue.read().is_empty());
                assert_eq!(rl.pending_queue_count.load(Ordering::Relaxed), 0);
                assert_eq!(rl.available_tokens(), u32::from(grant_before_cancel));
                drop(
                    rl.acquire_queued_bounded(1, Time::ZERO, 1)
                        .expect("cancelled owner released queue capacity"),
                );
                assert!(rl.wait_queue.read().is_empty());
            }));

            let started = Instant::now();
            while !runtime.is_quiescent() {
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "cancelled rate-limit owner must retire"
                );
                std::thread::yield_now();
            }
            assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
            drop(runtime);
            done_tx
                .send(())
                .expect("native test observer remains alive");
        });

        match done_rx.recv_timeout(Duration::from_secs(20)) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                runner.join().expect("native rate-limit scenario must pass");
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("native rate-limit cancellation exceeded its watchdog");
            }
        }
    }

    #[test]
    fn native_cancelled_queue_owners_release_pending_and_granted_credit() {
        for multi_thread in [false, true] {
            for grant_before_cancel in [false, true] {
                native_cancelled_owner(multi_thread, grant_before_cancel);
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod async_admission_tests {
    use super::*;
    use crate::cx::ChildRegionSpec;
    use crate::runtime::{RuntimeBuilder, yield_now};
    use crate::time::{TimerDriver, TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, CancelKind, RegionId, TaskId};
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::{Mutex as StdMutex, mpsc};
    use std::task::{Context, Wake, Waker};

    fn native<F, Fut>(workers: usize, scenario: F)
    where
        F: FnOnce(Cx) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let runner = std::thread::spawn(move || {
            let builder = if workers == 1 {
                RuntimeBuilder::current_thread()
            } else {
                RuntimeBuilder::multi_thread().worker_threads(workers)
            };
            let runtime = builder.build().unwrap();
            let completed = Arc::new(AtomicBool::new(false));
            let completion = Arc::clone(&completed);
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().expect("admitted rate-limit scenario");
                crate::time::timeout(cx.now(), Duration::from_secs(10), scenario(cx))
                    .await
                    .expect("rate-limit admission scenario watchdog");
                completion.store(true, Ordering::Release);
            }));
            assert!(completed.load(Ordering::Acquire));
            assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
            assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
            done_tx.send(()).unwrap();
        });
        match done_rx.recv_timeout(Duration::from_secs(20)) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                runner.join().expect("native rate-limit admission scenario");
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("native rate-limit admission exceeded watchdog");
            }
        }
    }

    fn stalled(burst: u32) -> RateLimiter {
        RateLimiter::new(RateLimitPolicy {
            rate: 0,
            burst,
            wait_strategy: WaitStrategy::Block,
            ..Default::default()
        })
    }

    async fn wait_parked(limiter: &RateLimiter, count: usize) {
        while limiter.changed.waiter_count() < count {
            yield_now().await;
        }
    }

    fn assert_empty(limiter: &RateLimiter, tokens: u32) {
        assert!(limiter.wait_queue.read().is_empty());
        assert_eq!(limiter.pending_queue_count.load(Ordering::Acquire), 0);
        assert_eq!(limiter.changed.waiter_count(), 0);
        assert_eq!(limiter.available_tokens(), tokens);
    }

    fn virtual_context(budget: Budget) -> (Cx, Arc<VirtualClock>) {
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriverHandle::new(Arc::new(TimerDriver::with_clock(Arc::clone(&clock))));
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            budget,
            None,
            None,
            None,
            Some(driver),
            None,
        );
        (cx, clock)
    }

    #[test]
    fn time_only_context_can_claim_existing_tokens_without_a_driver() {
        type TimeOnly = crate::cx::cap::CapSet<false, true, false, false, false>;
        let cx = Cx::for_testing().restrict::<TimeOnly>();
        let limiter = stalled(1);
        let mut task = Context::from_waker(Waker::noop());
        let mut immediate = Box::pin(limiter.acquire_async_bounded(&cx, 1, 0));
        let permit = match immediate.as_mut().poll(&mut task) {
            Poll::Ready(Ok(permit)) => permit,
            _ => panic!("existing credit must be available without a timer"),
        };
        drop(immediate);
        let mut waiting = Box::pin(limiter.acquire_async_bounded(&cx, 1, 1));
        assert!(matches!(
            waiting.as_mut().poll(&mut task),
            Poll::Ready(Err(RateLimitAcquireError::TimerUnavailable))
        ));
        drop(waiting);
        assert_empty(&limiter, 0);
        drop(permit);
        assert_empty(&limiter, 1);

        cx.cancel_fast(CancelKind::User);
        let mut cancelled = Box::pin(limiter.acquire_async_bounded(&cx, 1, 0));
        assert!(matches!(
            cancelled.as_mut().poll(&mut task),
            Poll::Ready(Err(RateLimitAcquireError::Cancelled(reason)))
                if reason.kind == CancelKind::User
        ));
        drop(cancelled);
        assert_empty(&limiter, 1);
    }

    async fn fifo_refund_scenario(cx: Cx) {
        let limiter = Arc::new(stalled(3));
        let held = limiter.acquire_permit(3, cx.now()).unwrap();
        let order = Arc::new(StdMutex::new(Vec::new()));
        let release = Arc::new(AtomicBool::new(false));
        let changed = Arc::new(Notify::new());

        let first_limiter = Arc::clone(&limiter);
        let first_order = Arc::clone(&order);
        let first_release = Arc::clone(&release);
        let first_changed = Arc::clone(&changed);
        let mut first = cx
            .spawn(move |owner| async move {
                let _permit = first_limiter
                    .acquire_async_bounded(&owner, 3, 2)
                    .await
                    .unwrap();
                first_order.lock().unwrap().push(1);
                first_changed.notify_waiters();
                first_changed
                    .wait_until(|| first_release.load(Ordering::Acquire))
                    .await;
            })
            .unwrap();
        wait_parked(&limiter, 1).await;

        let second_limiter = Arc::clone(&limiter);
        let second_order = Arc::clone(&order);
        let mut second = cx
            .spawn(move |owner| async move {
                let permit = second_limiter
                    .acquire_async_bounded(&owner, 1, 2)
                    .await
                    .unwrap();
                second_order.lock().unwrap().push(2);
                permit.commit();
            })
            .unwrap();
        wait_parked(&limiter, 2).await;
        assert_eq!(limiter.wait_queue.read().len(), 2);
        assert!(order.lock().unwrap().is_empty());

        std::thread::scope(|scope| {
            scope.spawn(move || drop(held)).join().unwrap();
        });
        changed
            .wait_until(|| !order.lock().unwrap().is_empty())
            .await;
        assert_eq!(*order.lock().unwrap(), vec![1]);
        assert_eq!(limiter.available_tokens(), 0);
        release.store(true, Ordering::Release);
        changed.notify_waiters();
        first.join(&cx).await.unwrap();
        second.join(&cx).await.unwrap();
        assert_eq!(*order.lock().unwrap(), vec![1, 2]);
        assert_empty(&limiter, 2);
    }

    #[test]
    fn native_refunds_wake_weighted_fifo_and_commit_consumes_credit() {
        for workers in [1, 2] {
            native(workers, fifo_refund_scenario);
        }
    }

    #[test]
    fn native_cancellation_and_reset_wake_actually_parked_owners() {
        for workers in [1, 2] {
            native(workers, |cx| async move {
                for reset in [false, true] {
                    let limiter = Arc::new(stalled(1));
                    let held = limiter.acquire_permit(1, cx.now()).unwrap();
                    let child_limiter = Arc::clone(&limiter);
                    let mut child = cx
                        .spawn(move |owner| async move {
                            let result = child_limiter.acquire_async_bounded(&owner, 1, 1).await;
                            if reset {
                                assert!(matches!(
                                    result,
                                    Err(RateLimitAcquireError::Admission(RateLimitError::Cancelled))
                                ));
                            } else {
                                assert!(matches!(
                                    result,
                                    Err(RateLimitAcquireError::Cancelled(reason))
                                        if reason.kind == CancelKind::User
                                ));
                            }
                        })
                        .unwrap();
                    wait_parked(&limiter, 1).await;
                    if reset {
                        limiter.reset();
                    } else {
                        child = std::thread::spawn(move || {
                            child.abort();
                            child
                        })
                        .join()
                        .unwrap();
                    }
                    child.join(&cx).await.unwrap();
                    assert_empty(&limiter, u32::from(reset));
                    drop(held);
                    assert_empty(&limiter, 1);
                }
            });
        }
    }

    #[test]
    fn native_removing_a_raw_head_wakes_a_zero_rate_follower() {
        for workers in [1, 2] {
            native(workers, |cx| async move {
                let limiter = Arc::new(stalled(3));
                let held = limiter.acquire_permit(1, cx.now()).unwrap();
                let head = limiter.acquire_queued_bounded(3, cx.now(), 2).unwrap();
                let child_limiter = Arc::clone(&limiter);
                let mut child = cx
                    .spawn(move |owner| async move {
                        child_limiter
                            .acquire_async_bounded(&owner, 1, 2)
                            .await
                            .unwrap()
                            .commit();
                    })
                    .unwrap();
                wait_parked(&limiter, 1).await;
                assert_eq!(limiter.available_tokens(), 2);
                std::thread::scope(|scope| {
                    scope.spawn(move || drop(head)).join().unwrap();
                });
                child.join(&cx).await.unwrap();
                assert_empty(&limiter, 1);
                drop(held);
                assert_empty(&limiter, 2);
            });
        }
    }

    #[test]
    fn native_tokens_arrive_without_an_external_queue_driver() {
        for workers in [1, 2] {
            native(workers, |cx| async move {
                let limiter = RateLimiter::new(RateLimitPolicy {
                    rate: 1,
                    period: Duration::from_millis(250),
                    burst: 1,
                    ..Default::default()
                });
                let started = cx.now();
                assert!(limiter.try_acquire(1, started));
                let mut waiting = Box::pin(limiter.acquire_async_bounded(&cx, 1, 1));
                poll_fn(|task| {
                    assert!(waiting.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                })
                .await;
                assert_eq!(limiter.changed.waiter_count(), 1);
                waiting.await.unwrap().commit();
                assert!(cx.now().as_millis() >= started.as_millis() + 250);
                assert_empty(&limiter, 0);
            });
        }
    }

    #[test]
    fn native_queue_timeout_and_owner_deadline_wake_without_refill() {
        for workers in [1, 2] {
            native(workers, |cx| async move {
                for inherited in [false, true] {
                    let timeout = Duration::from_millis(250);
                    let mut spec = ChildRegionSpec::inherit();
                    if inherited {
                        spec = spec.with_budget(
                            Budget::new().with_deadline(cx.now() + timeout),
                        );
                    }
                    let parent = cx.open_child_region(spec).await.unwrap();
                    let limiter = Arc::new(RateLimiter::new(RateLimitPolicy {
                        rate: 0,
                        burst: 1,
                        wait_strategy: if inherited {
                            WaitStrategy::Block
                        } else {
                            WaitStrategy::BlockWithTimeout(timeout)
                        },
                        ..Default::default()
                    }));
                    let held = limiter.acquire_permit(1, cx.now()).unwrap();
                    let child_limiter = Arc::clone(&limiter);
                    let mut child = parent
                        .cx()
                        .spawn(move |owner| async move {
                            let result = child_limiter.acquire_async_bounded(&owner, 1, 1).await;
                            if inherited {
                                assert!(matches!(
                                    result,
                                    Err(RateLimitAcquireError::Cancelled(reason))
                                        if reason.kind == CancelKind::Deadline
                                ));
                            } else {
                                assert!(matches!(
                                    result,
                                    Err(RateLimitAcquireError::Admission(
                                        RateLimitError::Timeout { waited }
                                    )) if waited >= timeout
                                ));
                            }
                        })
                        .unwrap();
                    wait_parked(&limiter, 1).await;
                    child.join(&cx).await.unwrap();
                    assert_empty(&limiter, 0);
                    drop(held);
                    parent.close().await.unwrap();
                }
            });
        }
    }

    #[test]
    fn async_bound_and_drop_account_for_pending_and_unclaimed_credit() {
        let (cx, _) = virtual_context(Budget::INFINITE);
        let limiter = stalled(1);
        let held = limiter.acquire_permit(1, Time::ZERO).unwrap();
        let mut task = Context::from_waker(Waker::noop());
        let mut waiting = Box::pin(limiter.acquire_async_bounded(&cx, 1, 1));
        assert!(waiting.as_mut().poll(&mut task).is_pending());
        assert_eq!(limiter.wait_queue.read().len(), 1);

        let mut full = Box::pin(limiter.acquire_async_bounded(&cx, 1, 1));
        assert!(matches!(
            full.as_mut().poll(&mut task),
            Poll::Ready(Err(RateLimitAcquireError::Admission(
                RateLimitError::RateLimitExceeded
            )))
        ));
        drop(full);
        drop(waiting);
        assert_empty(&limiter, 0);

        let mut waiting = Box::pin(limiter.acquire_async_bounded(&cx, 1, 1));
        assert!(waiting.as_mut().poll(&mut task).is_pending());
        drop(held);
        assert!(limiter.process_queue(Time::ZERO).is_some());
        assert_eq!(limiter.pending_queue_count.load(Ordering::Acquire), 0);
        assert_eq!(limiter.wait_queue.read().len(), 1);
        let mut full = Box::pin(limiter.acquire_async_bounded(&cx, 1, 1));
        assert!(matches!(
            full.as_mut().poll(&mut task),
            Poll::Ready(Err(RateLimitAcquireError::Admission(
                RateLimitError::RateLimitExceeded
            )))
        ));
        drop(full);
        drop(waiting);
        assert_empty(&limiter, 1);

        let mut committed = Box::pin(limiter.acquire_async_bounded(&cx, 1, 0));
        match committed.as_mut().poll(&mut task) {
            Poll::Ready(Ok(permit)) => permit.commit(),
            _ => panic!("dropping the unclaimed grant must restore immediate quota"),
        }
        drop(committed);
        assert_empty(&limiter, 0);
    }

    #[test]
    fn dropping_an_async_grant_uses_current_time_before_handing_off() {
        let (cx, clock) = virtual_context(Budget::INFINITE);
        let limiter = RateLimiter::new(RateLimitPolicy {
            rate: 0,
            burst: 1,
            wait_strategy: WaitStrategy::BlockWithTimeout(Duration::from_millis(10)),
            ..Default::default()
        });
        let held = limiter.acquire_permit(1, Time::ZERO).unwrap();
        let mut task = Context::from_waker(Waker::noop());
        let mut first = Box::pin(limiter.acquire_async_bounded(&cx, 1, 2));
        assert!(first.as_mut().poll(&mut task).is_pending());
        let mut follower = limiter.acquire_queued_bounded(1, Time::ZERO, 2).unwrap();
        drop(held);
        clock.advance_to(Time::from_millis(5));
        assert!(limiter.process_queue(cx.now()).is_some());
        assert_eq!(limiter.available_tokens(), 0);

        // The future has not been polled since time zero. Its drop must use
        // the captured clock, so it cannot grant the now-expired follower.
        clock.advance_to(Time::from_millis(20));
        drop(first);
        assert!(matches!(
            follower.poll_claim(cx.now()),
            Err(RateLimitError::Timeout { waited }) if waited == Duration::from_millis(20)
        ));
        drop(follower);
        assert_empty(&limiter, 1);
    }

    #[test]
    fn an_expired_masked_context_parks_until_a_real_event() {
        let (cx, clock) = virtual_context(
            Budget::new().with_deadline(Time::from_millis(1)),
        );
        let limiter = stalled(1);
        let held = limiter.acquire_permit(1, Time::ZERO).unwrap();
        let mut waiting = Box::pin(limiter.acquire_async_bounded(&cx, 1, 1));
        let mut task = Context::from_waker(Waker::noop());
        clock.advance_to(Time::from_millis(2));
        cx.masked(|| {
            assert!(waiting.as_mut().poll(&mut task).is_pending());
        });
        assert_eq!(limiter.changed.waiter_count(), 1);
        // Explicitly repoll after the synchronous mask; masks do not promise
        // a separate wakeup, and the expired timer must not drive a hot loop.
        assert!(matches!(
            waiting.as_mut().poll(&mut task),
            Poll::Ready(Err(RateLimitAcquireError::Cancelled(reason)))
                if reason.kind == CancelKind::Deadline
        ));
        drop(waiting);
        assert_empty(&limiter, 0);
        drop(held);
        assert_empty(&limiter, 1);
    }

    #[test]
    fn lab_drives_weighted_fifo_timeouts_and_fractional_periods() {
        use crate::{LabConfig, LabRuntime};
        for seed in [17, 41, 93] {
            let mut lab = LabRuntime::new(LabConfig::new(seed).worker_count(2).max_steps(8192));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let (task, mut join) = lab
                .state
                .create_task(root, Budget::INFINITE, async {
                    let cx = Cx::current().unwrap();
                    crate::time::sleep(cx.now(), Duration::from_millis(713)).await;

                    let limiter = RateLimiter::new(RateLimitPolicy {
                        rate: 1,
                        period: Duration::from_millis(100),
                        burst: 3,
                        ..Default::default()
                    });
                    let started = cx.now();
                    assert!(limiter.try_acquire(3, started));
                    let mut raw_head = limiter.acquire_queued_bounded(3, started, 2).unwrap();
                    limiter.acquire_async_bounded(&cx, 1, 2).await.unwrap().commit();
                    assert_eq!(cx.now(), started + Duration::from_millis(400));
                    raw_head.poll_claim(cx.now()).unwrap().unwrap().commit();
                    drop(raw_head);
                    assert_empty(&limiter, 0);

                    // The async follower must drive an unpolled predecessor's
                    // earlier timeout even though it already has enough tokens.
                    let limiter = RateLimiter::new(RateLimitPolicy {
                        rate: 1,
                        period: Duration::from_millis(200),
                        burst: 2,
                        wait_strategy: WaitStrategy::BlockWithTimeout(Duration::from_millis(100)),
                        ..Default::default()
                    });
                    let started = cx.now();
                    let held = limiter.acquire_permit(1, started).unwrap();
                    let mut raw_head = limiter.acquire_queued_bounded(2, started, 2).unwrap();
                    crate::time::sleep(cx.now(), Duration::from_millis(50)).await;
                    let permit = limiter.acquire_async_bounded(&cx, 1, 2).await.unwrap();
                    assert_eq!(cx.now(), started + Duration::from_millis(100));
                    assert!(matches!(
                        raw_head.poll_claim(cx.now()),
                        Err(RateLimitError::Timeout { waited })
                            if waited == Duration::from_millis(100)
                    ));
                    drop(raw_head);
                    drop(permit);
                    drop(held);
                    assert_empty(&limiter, 2);

                    let limiter = RateLimiter::new(RateLimitPolicy {
                        rate: 1,
                        period: Duration::from_millis(100),
                        burst: 1,
                        wait_strategy: WaitStrategy::BlockWithTimeout(Duration::from_millis(100)),
                        ..Default::default()
                    });
                    let started = cx.now();
                    assert!(limiter.try_acquire(1, started));
                    limiter.acquire_async_bounded(&cx, 1, 1).await.unwrap().commit();
                    assert_eq!(cx.now(), started + Duration::from_millis(100));
                    assert_empty(&limiter, 0);

                    // Whole-ms accounting must wake at the absolute boundary,
                    // not add a rounded duration to this half-ms starting time.
                    crate::time::sleep(cx.now(), Duration::from_micros(500)).await;
                    let limiter = RateLimiter::new(RateLimitPolicy {
                        rate: 1,
                        period: Duration::from_micros(1_900),
                        burst: 1,
                        ..Default::default()
                    });
                    let started = cx.now();
                    assert!(limiter.try_acquire(1, started));
                    limiter.acquire_async_bounded(&cx, 1, 1).await.unwrap().commit();
                    assert_eq!(cx.now(), Time::from_millis(started.as_millis() + 2));
                    assert_empty(&limiter, 0);
                })
                .unwrap();
            lab.scheduler.lock().schedule(task, 0);
            let virtual_time = lab.run_with_auto_advance();
            let report = lab.run_until_quiescent_with_report();
            assert!(matches!(join.try_join(), Ok(Some(()))), "{virtual_time:?} {report:?}");
            assert!(lab.state.tasks_is_empty());
            assert!(lab.state.obligations_iter().all(|(_, obligation)| !obligation.is_pending()));
            assert!(report.lab_test_passed(), "{report:?}");
        }
    }

    struct PanicWake;
    impl Wake for PanicWake {
        fn wake(self: Arc<Self>) {
            panic!("rate-limit notification wake panic");
        }
    }

    struct CountWake(AtomicUsize);
    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[test]
    fn notification_panics_cannot_interrupt_queue_or_refund_publication() {
        let limiter = stalled(1);
        let held = limiter.acquire_permit(1, Time::ZERO).unwrap();
        let hostile_waker = Waker::from(Arc::new(PanicWake));
        let mut hostile = Box::pin(limiter.changed.notified());
        assert!(hostile.as_mut().poll(&mut Context::from_waker(&hostile_waker)).is_pending());
        let counter = Arc::new(CountWake(AtomicUsize::new(0)));
        let other_waker = Waker::from(Arc::clone(&counter));
        let mut other = Box::pin(limiter.changed.notified());
        assert!(other.as_mut().poll(&mut Context::from_waker(&other_waker)).is_pending());

        let queued = limiter.acquire_queued_bounded(1, Time::ZERO, 1).unwrap();
        assert_eq!(counter.0.load(Ordering::Acquire), 1);
        assert_eq!(limiter.wait_queue.read().len(), 1);
        drop(queued);
        drop(hostile);
        drop(other);

        let mut hostile = Box::pin(limiter.changed.notified());
        assert!(hostile.as_mut().poll(&mut Context::from_waker(&hostile_waker)).is_pending());
        drop(held);
        drop(hostile);
        assert_empty(&limiter, 1);
    }

    #[test]
    fn crossing_an_owner_deadline_before_queue_inspection_cannot_park() {
        use crate::time::TimeSource;

        #[derive(Debug, Default)]
        struct CrossingClock {
            reads: AtomicUsize,
        }
        impl TimeSource for CrossingClock {
            fn now(&self) -> Time {
                if self.reads.fetch_add(1, Ordering::SeqCst) < 4 {
                    Time::ZERO
                } else {
                    Time::from_millis(1)
                }
            }
        }

        let clock = Arc::new(CrossingClock::default());
        let driver = TimerDriverHandle::new(Arc::new(TimerDriver::with_clock(Arc::clone(&clock))));
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::new().with_deadline(Time::from_millis(1)),
            None,
            None,
            None,
            Some(driver),
            None,
        );
        let limiter = stalled(1);
        let held = limiter.acquire_permit(1, Time::ZERO).unwrap();
        clock.reads.store(0, Ordering::SeqCst);
        let mut waiting = Box::pin(limiter.acquire_async_bounded(&cx, 1, 1));
        let mut task = Context::from_waker(Waker::noop());
        assert!(matches!(
            waiting.as_mut().poll(&mut task),
            Poll::Ready(Err(RateLimitAcquireError::Cancelled(reason)))
                if reason.kind == CancelKind::Deadline
        ));
        assert_eq!(limiter.metrics().total_waited, 1);
        assert!(clock.reads.load(Ordering::SeqCst) >= 5);
        drop(waiting);
        assert_empty(&limiter, 0);
        drop(held);
        assert_empty(&limiter, 1);
    }

    #[test]
    fn refill_at_max_time_preserves_a_nonempty_burst() {
        let limiter = RateLimiter::new(RateLimitPolicy {
            rate: u32::MAX,
            period: Duration::from_millis(1),
            burst: 2,
            ..Default::default()
        });

        limiter.refill(Time::MAX);
        assert_eq!(limiter.available_tokens(), 2);
        assert!(limiter.try_acquire(2, Time::MAX));
        assert!(!limiter.try_acquire(1, Time::MAX));
    }

    #[test]
    fn refund_to_full_discards_fractional_credit_independent_of_queries() {
        let make_limiter = || {
            RateLimiter::new(RateLimitPolicy {
                rate: 1,
                period: Duration::from_millis(10),
                burst: 1,
                ..Default::default()
            })
        };
        let queried = make_limiter();
        let unqueried = make_limiter();
        let queried_permit = queried.acquire_permit(1, Time::ZERO).unwrap();
        let unqueried_permit = unqueried.acquire_permit(1, Time::ZERO).unwrap();

        assert_eq!(
            queried.retry_after(1, Time::from_millis(5)),
            Duration::from_millis(5)
        );
        drop(queried_permit);
        drop(unqueried_permit);

        for limiter in [&queried, &unqueried] {
            assert!(limiter.try_acquire(1, Time::from_millis(5)));
            assert!(!limiter.try_acquire(1, Time::from_millis(10)));
            assert!(limiter.try_acquire(1, Time::from_millis(15)));
        }
    }

    #[test]
    fn async_wake_uses_head_fraction_and_only_representable_progress() {
        let limiter = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: Duration::from_micros(1_900),
            burst: 1,
            wait_strategy: WaitStrategy::Block,
            ..Default::default()
        });
        assert!(limiter.try_acquire(1, Time::ZERO));
        let mut head = limiter.acquire_queued_bounded(1, Time::ZERO, 2).unwrap();
        let follower = limiter.acquire_queued_bounded(1, Time::ZERO, 2).unwrap();

        // The rounded policy period is 2 ms. At 1.5 ms, half a token
        // exists: the head needs the 2 ms boundary, irrespective of the
        // follower's demand or the fractional part of the current time.
        assert_eq!(
            limiter.next_async_wake(Time::from_nanos(1_500_000)),
            Some(Time::from_millis(2))
        );
        assert!(head.poll_claim(Time::from_nanos(1_999_999)).unwrap().is_none());
        head.poll_claim(Time::from_millis(2))
            .unwrap()
            .expect("head should receive the token at the whole-ms boundary")
            .commit();
        assert_eq!(
            limiter.next_async_wake(Time::from_millis(2)),
            Some(Time::from_millis(4))
        );
        drop(follower);

        let saturated = RateLimiter::new(RateLimitPolicy {
            rate: 1,
            period: Duration::from_millis(1),
            burst: 1,
            wait_strategy: WaitStrategy::Block,
            ..Default::default()
        });
        assert!(saturated.try_acquire(1, Time::MAX));
        let mut pending = saturated.acquire_queued_bounded(1, Time::MAX, 1).unwrap();
        assert!(pending.poll_claim(Time::MAX).unwrap().is_none());
        assert_eq!(saturated.next_async_wake(Time::MAX), None);
        drop(pending);

        for (rate, period) in [
            (0, Duration::from_millis(1)),
            (1, Duration::ZERO),
        ] {
            let stalled = RateLimiter::new(RateLimitPolicy {
                rate,
                period,
                burst: 1,
                wait_strategy: WaitStrategy::BlockWithTimeout(Duration::from_millis(3)),
                ..Default::default()
            });
            assert!(stalled.try_acquire(1, Time::ZERO));
            let mut pending = stalled.acquire_queued_bounded(1, Time::ZERO, 1).unwrap();
            assert_eq!(
                stalled.next_async_wake(Time::ZERO),
                Some(Time::from_millis(3))
            );
            assert!(matches!(
                pending.poll_claim(Time::from_millis(3)),
                Err(RateLimitError::Timeout { .. })
            ));
        }
    }
}
