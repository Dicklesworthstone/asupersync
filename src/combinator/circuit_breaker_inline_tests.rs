    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use proptest::prelude::*;

    // =========================================================================
    // State Bit Packing Tests
    // =========================================================================

    #[test]
    fn state_bits_roundtrip_closed() {
        let state = State::Closed { failures: 42 };
        let bits = state.to_bits();
        let recovered = State::from_bits(bits);
        assert_eq!(state, recovered);
    }

    #[test]
    fn state_bits_roundtrip_open() {
        let state = State::Open {
            since_millis: 123_456_789,
        };
        let bits = state.to_bits();
        let recovered = State::from_bits(bits);
        assert_eq!(state, recovered);
    }

    #[test]
    fn state_bits_roundtrip_half_open() {
        let state = State::HalfOpen {
            epoch: 123,
            probes_active: 3,
            successes: 7,
        };
        let bits = state.to_bits();
        let recovered = State::from_bits(bits);
        assert_eq!(state, recovered);
    }

    // =========================================================================
    // Basic State Machine Tests
    // =========================================================================

    #[test]
    fn new_circuit_starts_closed() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy::default());
        assert_eq!(cb.state(), State::Closed { failures: 0 });
    }

    #[test]
    fn dropping_unrecorded_permit_guard_releases_half_open_probe() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            success_threshold: 1,
            open_duration: Duration::from_millis(100),
            half_open_max_probes: 1,
            ..Default::default()
        });
        let t0 = Time::from_millis(0);

        // Trip Closed -> Open with a single failure.
        let permit = cb.should_allow(t0).expect("closed allows");
        cb.record_failure(permit, "boom", t0);

        // After open_duration, the next call probes (HalfOpen, probes_active = 1).
        let t1 = Time::from_millis(150);
        let guard = cb.acquire_guarded(t1).expect("half-open probe granted");
        assert!(
            matches!(guard.permit(), Some(Permit::Probe { .. })),
            "first half-open call should receive a probe permit",
        );

        // Drop the guard WITHOUT recording an outcome: the probe slot must be
        // freed (record_ignored), not leaked (5vzqse).
        drop(guard);

        // The freed slot must be re-acquirable; a leaked probe would make this
        // fail with HalfOpenFull.
        let guard2 = cb.acquire_guarded(t1);
        assert!(
            guard2.is_ok(),
            "half-open probe slot must be free after dropping the unrecorded guard",
        );
        drop(guard2); // also released as ignored -> no leak either way
    }

    #[test]
    fn closed_allows_calls() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy::default());
        let now = Time::from_millis(0);

        assert!(cb.should_allow(now).is_ok());
    }

    #[test]
    fn failures_increment_count() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 5,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        for i in 0..4 {
            let permit = cb.should_allow(now).unwrap();
            cb.record_failure(permit, "test error", now);

            assert_eq!(cb.state(), State::Closed { failures: i + 1 });
            assert_eq!(cb.metrics().current_failure_streak, i + 1);
        }
    }

    #[test]
    fn threshold_failures_opens_circuit() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 3,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        for _ in 0..3 {
            let permit = cb.should_allow(now).unwrap();
            cb.record_failure(permit, "test error", now);
        }

        assert!(matches!(cb.state(), State::Open { .. }));
        assert_eq!(cb.metrics().times_opened, 1);
    }

    #[test]
    fn open_circuit_rejects_calls() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            open_duration: Duration::from_secs(30),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Trigger open
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "fail", now);

        // Should be rejected
        let result = cb.should_allow(now);
        assert!(matches!(
            result,
            Err(CircuitBreakerError::Open { remaining }) if remaining == Duration::from_secs(30)
        ));

        // Verify rejection was tracked
        assert_eq!(cb.metrics().total_rejected, 1);
    }

    #[test]
    fn open_transitions_to_half_open_after_duration() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            open_duration: Duration::from_secs(10),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Trigger open
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "fail", now);

        // After open_duration, should allow probe
        let later = Time::from_millis(11_000);
        let result = cb.should_allow(later);
        assert!(result.is_ok());
        assert!(matches!(cb.state(), State::HalfOpen { .. }));
    }

    #[test]
    fn open_to_half_open_updates_metrics_state() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            open_duration: Duration::from_secs(10),
            ..Default::default()
        });

        let now = Time::from_millis(0);
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "fail", now);

        let later = Time::from_millis(11_000);
        let result = cb.should_allow(later);
        assert!(matches!(result, Ok(Permit::Probe { .. })));
        assert!(matches!(
            cb.metrics().current_state,
            State::HalfOpen {
                probes_active: 1,
                successes: 0,
                ..
            }
        ));
    }

    #[test]
    fn half_open_limits_concurrent_probes() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            open_duration: Duration::from_millis(0),
            half_open_max_probes: 1,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Trigger open
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "fail", now);

        // First probe allowed
        let probe1 = cb.should_allow(now);
        assert!(probe1.is_ok());

        // Second probe rejected (max 1)
        let probe2 = cb.should_allow(now);
        assert!(matches!(probe2, Err(CircuitBreakerError::HalfOpenFull)));
    }

    #[test]
    fn successful_probes_close_circuit() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            success_threshold: 2,
            open_duration: Duration::from_millis(0),
            half_open_max_probes: 5,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Trigger open
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "fail", now);

        // Two successful probes
        for _ in 0..2 {
            let permit = cb.should_allow(now).unwrap();
            cb.record_success(permit, now);
        }

        assert_eq!(cb.state(), State::Closed { failures: 0 });
    }

    #[test]
    fn failed_probe_reopens_circuit() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            open_duration: Duration::from_millis(0),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Trigger open -> half-open
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "fail", now);

        // Get probe permit
        let permit = cb.should_allow(now).unwrap();

        // Probe fails
        cb.record_failure(permit, "probe fail", now);

        // Should be open again
        assert!(matches!(cb.state(), State::Open { .. }));
        assert_eq!(cb.metrics().times_opened, 2);
    }

    #[test]
    fn half_open_epoch_is_independent_of_times_opened() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            open_duration: Duration::ZERO,
            ..Default::default()
        });
        cb.times_opened.store(7, Ordering::Relaxed);
        cb.open_generation.store(42, Ordering::Relaxed);
        cb.state_bits
            .store(State::Open { since_millis: 0 }.to_bits(), Ordering::Release);

        let permit = cb
            .should_allow(Time::ZERO)
            .expect("expired Open state should admit a probe");
        assert_eq!(permit, Permit::Probe { epoch: 42 });

        let before = cb.state();
        cb.record_failure(Permit::Probe { epoch: 7 }, "stale", Time::ZERO);
        assert_eq!(
            cb.state(),
            before,
            "metric-derived stale permit must not mutate the new HalfOpen episode"
        );
        assert_eq!(cb.metrics().times_opened, 7);
    }

    #[test]
    fn failed_open_cas_has_no_observable_side_effects() {
        let callback_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed_callbacks = Arc::clone(&callback_count);
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            sliding_window: Some(SlidingWindowConfig {
                window_duration: Duration::from_secs(10),
                minimum_calls: 2,
                failure_rate_threshold: 0.5,
            }),
            on_state_change: Some(Arc::new(move |_, _, _| {
                observed_callbacks.fetch_add(1, Ordering::SeqCst);
            })),
            ..Default::default()
        });

        let window = cb
            .sliding_window
            .as_ref()
            .expect("test policy should install a sliding window");
        {
            let mut window = window.write();
            window.record_success(1);
            window.record_failure(2);
        }
        let window_before = {
            let window = window.read();
            (
                window.entries.clone(),
                window.success_count,
                window.failure_count,
            )
        };

        let stale_bits = State::Closed { failures: 0 }.to_bits();
        let actual_state = State::Closed { failures: 1 };
        cb.state_bits
            .store(actual_state.to_bits(), Ordering::Release);

        assert_eq!(
            cb.try_transition_to_open(stale_bits, 3),
            Err(actual_state.to_bits())
        );
        assert_eq!(cb.state(), actual_state);
        assert_eq!(cb.open_generation.load(Ordering::Relaxed), 1);
        assert_eq!(cb.metrics().times_opened, 0);
        assert_eq!(callback_count.load(Ordering::SeqCst), 0);

        let window_after = window.read();
        assert_eq!(window_after.entries, window_before.0);
        assert_eq!(window_after.success_count, window_before.1);
        assert_eq!(window_after.failure_count, window_before.2);
    }

    // =========================================================================
    // Success Resets Failure Count
    // =========================================================================

    #[test]
    fn success_resets_failure_count() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 5,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // 3 failures
        for _ in 0..3 {
            let permit = cb.should_allow(now).unwrap();
            cb.record_failure(permit, "fail", now);
        }
        assert_eq!(cb.metrics().current_failure_streak, 3);

        // 1 success resets
        let permit = cb.should_allow(now).unwrap();
        cb.record_success(permit, now);

        assert_eq!(cb.metrics().current_failure_streak, 0);
        assert_eq!(cb.state(), State::Closed { failures: 0 });
    }

    // =========================================================================
    // Failure Predicate Tests
    // =========================================================================

    #[test]
    fn failure_predicate_filters_errors() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            failure_predicate: FailurePredicate::ByType(|e| e.contains("timeout")),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Non-matching error doesn't count
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "network error", now);
        assert_eq!(cb.state(), State::Closed { failures: 0 });
        assert_eq!(cb.metrics().total_ignored_errors, 1);

        // Matching error opens circuit
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "timeout error", now);
        assert!(matches!(cb.state(), State::Open { .. }));
    }

    // =========================================================================
    // Sliding Window Tests
    // =========================================================================

    #[test]
    fn sliding_window_tracks_failure_rate() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1000, // High count threshold
            sliding_window: Some(SlidingWindowConfig {
                window_duration: Duration::from_secs(60),
                minimum_calls: 10,
                failure_rate_threshold: 0.5,
            }),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // 10 calls: 6 failures (60% failure rate)
        for i in 0..10 {
            let permit = cb.should_allow(now).unwrap();
            if i < 6 {
                cb.record_failure(permit, "fail", now);
            } else {
                cb.record_success(permit, now);
            }
        }

        // Should be open due to 60% > 50% threshold
        assert!(matches!(cb.state(), State::Open { .. }));
        assert_eq!(cb.metrics().times_opened, 1);
    }

    #[test]
    fn sliding_window_minimum_calls_required() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1000,
            sliding_window: Some(SlidingWindowConfig {
                window_duration: Duration::from_secs(60),
                minimum_calls: 10,
                failure_rate_threshold: 0.5,
            }),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Only 5 failures (below minimum_calls)
        for _ in 0..5 {
            let permit = cb.should_allow(now).unwrap();
            cb.record_failure(permit, "fail", now);
        }

        // Should still be closed (minimum not met)
        // Failure count is 5
        assert_eq!(cb.state(), State::Closed { failures: 5 });
    }

    // =========================================================================
    // Metrics Tests
    // =========================================================================

    #[test]
    fn metrics_track_calls() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 100,
            ..Default::default()
        });
        let now = Time::from_millis(0);

        // 3 successes, 2 failures
        for _ in 0..3 {
            let permit = cb.should_allow(now).unwrap();
            cb.record_success(permit, now);
        }
        for _ in 0..2 {
            let permit = cb.should_allow(now).unwrap();
            cb.record_failure(permit, "fail", now);
        }

        let metrics = cb.metrics();
        assert_eq!(metrics.total_success, 3);
        assert_eq!(metrics.total_failure, 2);
    }

    #[test]
    fn metrics_track_rejections() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            open_duration: Duration::from_secs(60),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Trigger open
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "fail", now);

        // Try to call (will be rejected)
        for _ in 0..5 {
            let _ = cb.should_allow(now);
        }

        assert_eq!(cb.metrics().total_rejected, 5);
    }

    // =========================================================================
    // State Change Callback Tests
    // =========================================================================

    #[test]
    fn state_change_callback_invoked() {
        use std::sync::atomic::AtomicUsize;

        let callback_count = Arc::new(AtomicUsize::new(0));
        let callback_count_clone = callback_count.clone();

        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            on_state_change: Some(Arc::new(move |_from, _to, _| {
                callback_count_clone.fetch_add(1, Ordering::SeqCst);
            })),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Trigger open
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "fail", now);

        assert_eq!(callback_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn state_change_callback_invoked_for_open_to_half_open() {
        use std::sync::atomic::AtomicUsize;

        let callback_count = Arc::new(AtomicUsize::new(0));
        let callback_count_clone = callback_count.clone();

        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            open_duration: Duration::from_secs(10),
            on_state_change: Some(Arc::new(move |_from, _to, _| {
                callback_count_clone.fetch_add(1, Ordering::SeqCst);
            })),
            ..Default::default()
        });

        let now = Time::from_millis(0);
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "fail", now);

        let later = Time::from_millis(11_000);
        let permit = cb.should_allow(later);
        assert!(matches!(permit, Ok(Permit::Probe { .. })));

        // 1 transition for Closed->Open and 1 transition for Open->HalfOpen.
        assert_eq!(callback_count.load(Ordering::SeqCst), 2);
    }

    // =========================================================================
    // Concurrent Access Tests
    // =========================================================================

    #[test]
    fn concurrent_calls_safe() {
        use std::thread;

        let cb = Arc::new(CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 100,
            ..Default::default()
        }));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let cb = cb.clone();
                thread::spawn(move || {
                    let now = Time::from_millis(0);
                    for _ in 0..100 {
                        if let Ok(permit) = cb.should_allow(now) {
                            cb.record_success(permit, now);
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // No panics = success
        assert_eq!(cb.metrics().total_success, 1000);
    }

    // =========================================================================
    // Call Helper Tests
    // =========================================================================

    #[test]
    fn call_executes_and_records_success() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy::default());
        let now = Time::from_millis(0);

        let result = cb.call(now, || Ok::<_, &str>(42));

        assert_eq!(result.unwrap(), 42);
        assert_eq!(cb.metrics().total_success, 1);
    }

    #[test]
    fn call_executes_and_records_failure() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 5,
            ..Default::default()
        });
        let now = Time::from_millis(0);

        let result: Result<i32, CircuitBreakerError<&str>> = cb.call(now, || Err("error"));

        assert!(matches!(result, Err(CircuitBreakerError::Inner("error"))));
        assert_eq!(cb.metrics().total_failure, 1);
    }

    #[test]
    fn call_rejects_when_open() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            open_duration: Duration::from_secs(60),
            ..Default::default()
        });
        let now = Time::from_millis(0);

        // Open the circuit
        let _ = cb.call(now, || Err::<i32, _>("fail"));

        // Next call should be rejected
        let mut called = false;
        let result: Result<i32, CircuitBreakerError<&str>> = cb.call(now, || {
            called = true;
            Ok(42)
        });

        assert!(!called, "Operation should not have been called");
        assert!(matches!(result, Err(CircuitBreakerError::Open { .. })));
    }

    // =========================================================================
    // Builder Tests
    // =========================================================================

    #[test]
    fn builder_creates_policy() {
        let policy = CircuitBreakerPolicyBuilder::new()
            .name("test")
            .failure_threshold(10)
            .success_threshold(3)
            .open_duration(Duration::from_secs(60))
            .half_open_max_probes(2)
            .build();

        assert_eq!(policy.name, "test");
        assert_eq!(policy.failure_threshold, 10);
        assert_eq!(policy.success_threshold, 3);
        assert_eq!(policy.open_duration, Duration::from_secs(60));
        assert_eq!(policy.half_open_max_probes, 2);
    }

    #[test]
    fn builder_clamps_max_probes() {
        let policy = CircuitBreakerPolicyBuilder::new()
            .half_open_max_probes(20_000_000) // > 2^16
            .build();

        assert_eq!(policy.half_open_max_probes, MAX_HALF_OPEN_PROBES);
        assert_eq!(policy.half_open_max_probes, 0xFFFF);
    }

    #[test]
    fn builder_clamps_zero_probes_to_minimum() {
        let policy = CircuitBreakerPolicyBuilder::new()
            .half_open_max_probes(0)
            .build();

        assert_eq!(policy.half_open_max_probes, MIN_HALF_OPEN_PROBES);
    }

    #[test]
    fn constructor_clamps_zero_probes_to_minimum_semantics() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            open_duration: Duration::ZERO,
            half_open_max_probes: 0,
            ..Default::default()
        });
        let now = Time::from_millis(0);

        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "trip", now);
        assert!(matches!(cb.state(), State::Open { .. }));

        let probe = cb.should_allow(now);
        assert!(matches!(probe, Ok(Permit::Probe { .. })));

        let second_probe = cb.should_allow(now);
        assert!(matches!(
            second_probe,
            Err(CircuitBreakerError::HalfOpenFull)
        ));
    }

    // =========================================================================
    // Reset Tests
    // =========================================================================

    #[test]
    fn reset_clears_state() {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            ..Default::default()
        });
        let now = Time::from_millis(0);

        // Open the circuit
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "fail", now);
        assert!(matches!(cb.state(), State::Open { .. }));
        let generation = cb.open_generation.load(Ordering::Relaxed);
        assert_eq!(generation, 1);

        // Reset
        cb.reset();

        assert_eq!(cb.state(), State::Closed { failures: 0 });
        assert_eq!(cb.metrics().current_failure_streak, 0);
        assert_eq!(
            cb.open_generation.load(Ordering::Relaxed),
            generation,
            "manual reset must not recycle stale HalfOpen epochs"
        );
    }

    // =========================================================================
    // Display Tests
    // =========================================================================

    #[test]
    fn error_display() {
        let open: CircuitBreakerError<&str> = CircuitBreakerError::Open {
            remaining: Duration::from_secs(30),
        };
        assert!(open.to_string().contains("circuit open"));

        let half_open: CircuitBreakerError<&str> = CircuitBreakerError::HalfOpenFull;
        assert!(half_open.to_string().contains("half-open"));

        let inner: CircuitBreakerError<&str> = CircuitBreakerError::Inner("test error");
        assert_eq!(inner.to_string(), "test error");
    }

    // =========================================================================
    // Regression Tests for Bug Fixes
    // =========================================================================

    #[test]
    fn halfopen_bit_packing_large_probes_active() {
        // Regression: probes_active > 64K (16-bit max) would corrupt successes
        // field due to bit overlap in to_bits(). Now probes_active is masked to
        // 16 bits in encoding, matching the decode mask.
        let state = State::HalfOpen {
            epoch: 5,
            probes_active: 0xFFFF, // max 16-bit value
            successes: 42,
        };
        let roundtripped = State::from_bits(state.to_bits());
        assert_eq!(
            roundtripped,
            State::HalfOpen {
                epoch: 5,
                probes_active: 0xFFFF,
                successes: 42,
            }
        );

        // Value exceeding 16 bits gets truncated (saturated by mask)
        let overflow = State::HalfOpen {
            epoch: 5,
            probes_active: 0x1FFFF, // 17 bits - bit 16 set
            successes: 7,
        };
        let rt = State::from_bits(overflow.to_bits());
        // The high bit is lost, but successes must remain uncorrupted
        assert_eq!(
            rt,
            State::HalfOpen {
                epoch: 5,
                probes_active: 0xFFFF,
                successes: 7,
            }
        );
    }

    #[test]
    fn halfopen_bit_packing_successes_isolated() {
        // Verify successes field is completely independent of probes_active
        for probes in [0u32, 1, 255, 0xFFFF] {
            for succ in [0u32, 1, 100, 0xFFFF] {
                let state = State::HalfOpen {
                    epoch: 77,
                    probes_active: probes,
                    successes: succ,
                };
                let rt = State::from_bits(state.to_bits());
                match rt {
                    State::HalfOpen {
                        epoch: e,
                        probes_active: p,
                        successes: s,
                    } => {
                        assert_eq!(e, 77, "epoch mismatch");
                        assert_eq!(p, probes, "probes_active mismatch for ({probes}, {succ})");
                        assert_eq!(s, succ, "successes mismatch for ({probes}, {succ})");
                    }
                    _ => panic!("Expected HalfOpen"),
                }
            }
        }
    }

    #[test]
    fn call_panics_leak_probes() {
        // This test demonstrates that panicking inside `call` leaks the probe permit,
        // eventually preventing any further probes when half_open_max_probes is reached.
        let cb = std::sync::Arc::new(CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            open_duration: Duration::ZERO,
            half_open_max_probes: 1,
            ..Default::default()
        }));
        let now = Time::from_millis(0);

        // Trip to Open
        let permit = cb.should_allow(now).unwrap();
        cb.record_failure(permit, "fail", now);
        assert!(matches!(cb.state(), State::Open { .. }));

        // First probe panics
        let cb_clone = cb.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _: Result<(), CircuitBreakerError<String>> =
                cb_clone.call::<(), String, _>(now, || panic!("oops"));
        }));

        // State should be Open (probe failed due to panic)
        // With the fix, the CallGuard records a failure on drop.
        assert!(
            matches!(cb.state(), State::Open { .. }),
            "Panic should record failure and reopen circuit"
        );

        // Subsequent call should not be blocked by a leaked probe permit.
        // With zero open_duration, Open may transition immediately to HalfOpen.
        let result = cb.should_allow(now);
        assert!(
            matches!(
                result,
                Ok(Permit::Probe { .. }) | Err(CircuitBreakerError::Open { .. })
            ),
            "Expected reopened circuit to permit probe or briefly report Open"
        );
    }

    #[test]
    fn panic_trips_breaker_regardless_of_failure_predicate() {
        // Regression: a panic unwinding out of `call` is an unconditional hard
        // failure. The failure predicate classifies domain error *values*, not
        // panics — so panics must trip the breaker even when a selective
        // predicate would not match the internal "Panic" sentinel. Previously a
        // panicking dependency was classified as an ignored error and never
        // opened the breaker, leaving it admitting every call.
        let cb = std::sync::Arc::new(CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 3,
            failure_predicate: FailurePredicate::ByType(|e| e.contains("503")),
            ..Default::default()
        }));
        let now = Time::from_millis(0);

        for _ in 0..3 {
            let cb_clone = cb.clone();
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _: Result<(), CircuitBreakerError<String>> =
                    cb_clone.call::<(), String, _>(now, || panic!("bug"));
            }));
        }

        assert!(
            matches!(cb.state(), State::Open { .. }),
            "panics must trip the breaker even under a selective failure predicate, got {:?}",
            cb.state()
        );
        // The panics were counted as real failures, never routed to the
        // ignored-error branch.
        assert_eq!(cb.metrics().total_ignored_errors, 0);
    }

    #[test]
    fn sliding_window_huge_duration_does_not_over_evict() {
        let mut window = SlidingWindow::new(SlidingWindowConfig {
            window_duration: Duration::MAX,
            minimum_calls: 1,
            failure_rate_threshold: 1.0,
        });

        window.record_failure(10);
        window.record_success(20);

        window.cleanup(u64::MAX);

        assert_eq!(window.entries.len(), 2);
        assert_eq!(window.failure_count, 1);
        assert_eq!(window.success_count, 1);
    }

    #[test]
    fn state_debug_clone_copy_eq_default() {
        let s = State::default();
        assert_eq!(s, State::Closed { failures: 0 });
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Closed"), "{dbg}");
        let copied: State = s;
        let cloned = s;
        assert_eq!(copied, cloned);

        let open = State::Open { since_millis: 999 };
        assert_ne!(s, open);
        let dbg_open = format!("{open:?}");
        assert!(dbg_open.contains("Open"), "{dbg_open}");
    }

    #[test]
    fn circuit_breaker_metrics_debug_clone_default() {
        let m = CircuitBreakerMetrics::default();
        let dbg = format!("{m:?}");
        assert!(dbg.contains("CircuitBreakerMetrics"), "{dbg}");
        assert_eq!(m.total_success, 0);
        let cloned = m;
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn permit_debug_clone_copy_eq() {
        let p = Permit::Normal;
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Normal"), "{dbg}");
        let copied: Permit = p;
        let cloned = p;
        assert_eq!(copied, cloned);
        assert_ne!(p, Permit::Probe { epoch: 999 });
    }

    #[test]
    fn half_open_to_closed_preserves_probe_success_history_in_sliding_window() {
        // Opening the breaker already resets the sliding window. Closing after
        // multiple successful probes must preserve those successes so the next
        // ordinary failure is evaluated against the full recovery sample.
        let policy = CircuitBreakerPolicy {
            failure_threshold: 2,
            success_threshold: 2,
            open_duration: Duration::from_millis(100),
            sliding_window: Some(SlidingWindowConfig {
                window_duration: Duration::from_secs(60),
                minimum_calls: 2,
                failure_rate_threshold: 0.5,
            }),
            ..CircuitBreakerPolicy::default()
        };
        let cb = CircuitBreaker::new(policy);
        let now = Time::from_millis(1_000);

        // Trip the circuit via consecutive failures.
        let permit = cb.should_allow(now).expect("closed");
        cb.record_failure(permit, "fail-1", now);
        let permit = cb.should_allow(now).expect("closed after 1 failure");
        cb.record_failure(permit, "fail-2", now);
        assert!(
            cb.should_allow(now).is_err(),
            "circuit should be open after 2 failures"
        );

        // Wait for the open duration to expire.
        let after_open = Time::from_millis(1_200);
        let probe1 = cb
            .should_allow(after_open)
            .expect("first half-open probe should be allowed");
        assert!(matches!(probe1, Permit::Probe { .. }));
        cb.record_success(probe1, after_open);

        let second_probe_time = Time::from_millis(1_201);
        let probe2 = cb
            .should_allow(second_probe_time)
            .expect("second half-open probe should be allowed");
        assert!(matches!(probe2, Permit::Probe { .. }));
        cb.record_success(probe2, second_probe_time);

        let post_close = cb.should_allow(second_probe_time);
        assert!(
            post_close.is_ok(),
            "circuit should close after the required half-open successes, got {post_close:?}"
        );

        let post_recovery_failure_time = Time::from_millis(1_202);
        let permit = cb
            .should_allow(post_recovery_failure_time)
            .expect("closed breaker should allow a normal call after recovery");
        cb.record_failure(
            permit,
            "single post-recovery failure",
            post_recovery_failure_time,
        );

        let state = cb.state();
        assert_eq!(
            state,
            State::Closed { failures: 1 },
            "one post-recovery failure should not reopen the breaker when the successful probe history is preserved"
        );
        let after_failure = cb.should_allow(post_recovery_failure_time);
        assert!(
            after_failure.is_ok(),
            "preserving the successful probe history keeps the breaker closed after one ordinary failure, got {after_failure:?}"
        );
    }

    #[test]
    fn opening_circuit_clears_sliding_window_before_half_open_recovery() {
        // Opening the breaker is what clears stale failures from the rate
        // window. Half-open recovery should not need a second reset on close.
        let policy = CircuitBreakerPolicy {
            failure_threshold: 2,
            success_threshold: 1,
            open_duration: Duration::from_millis(100),
            sliding_window: Some(SlidingWindowConfig {
                window_duration: Duration::from_secs(60),
                minimum_calls: 3,
                failure_rate_threshold: 0.5,
            }),
            ..CircuitBreakerPolicy::default()
        };
        let cb = CircuitBreaker::new(policy);
        let now = Time::from_millis(1_000);

        // Trip via consecutive failures (threshold = 2).
        let p = cb.should_allow(now).expect("closed");
        cb.record_failure(p, "err", now);
        let p = cb.should_allow(now).expect("closed after 1");
        cb.record_failure(p, "err", now);
        assert!(cb.should_allow(now).is_err(), "should be open");
        assert_eq!(
            cb.metrics().sliding_window_failure_rate,
            Some(0.0),
            "opening the breaker should clear stale failure history from the sliding window"
        );

        // Wait for open duration, get a probe.
        let later = Time::from_millis(1_200);
        let probe = cb.should_allow(later).expect("half-open probe");
        assert!(matches!(probe, Permit::Probe { .. }));

        // Successful probe closes the circuit.
        cb.record_success(probe, later);
        assert_eq!(
            cb.state(),
            State::Closed { failures: 0 },
            "single successful probe should close the circuit when success_threshold=1"
        );

        // The circuit must stay closed because the stale failures were already
        // cleared when the breaker opened.
        let post = cb.should_allow(later);
        assert!(
            post.is_ok(),
            "circuit should stay closed after half-open recovery when open already cleared the window, got {post:?}"
        );
    }

    /// Calls admitted while Closed that failed after the breaker opened were
    /// written into the window the open had just cleared, so the half-open
    /// probe's success closed the breaker and the window opened it again.
    #[test]
    fn late_failures_from_before_the_open_do_not_reopen_after_recovery() {
        let policy = CircuitBreakerPolicy {
            failure_threshold: 1000,
            success_threshold: 1,
            open_duration: Duration::from_secs(10),
            sliding_window: Some(SlidingWindowConfig {
                window_duration: Duration::from_secs(60),
                minimum_calls: 4,
                failure_rate_threshold: 0.5,
            }),
            ..CircuitBreakerPolicy::default()
        };
        let cb = CircuitBreaker::new(policy);
        let start = Time::from_millis(1_000);
        let permits: Vec<_> = (0..8)
            .map(|_| cb.should_allow(start).expect("closed"))
            .collect();
        let mut permits = permits.into_iter();

        // Four failures fill the window at a 100% failure rate: it opens and
        // the window is cleared.
        for permit in permits.by_ref().take(4) {
            cb.record_failure(permit, "err", start);
        }
        assert!(cb.should_allow(start).is_err(), "should be open");

        // The other four calls fail later, while the breaker is open.
        let late = Time::from_millis(2_000);
        for permit in permits {
            cb.record_failure(permit, "err", late);
        }

        let recovery = Time::from_millis(11_500);
        let probe = cb.should_allow(recovery).expect("half-open probe");
        cb.record_success(probe, recovery);
        assert_eq!(cb.state(), State::Closed { failures: 0 });
        assert_eq!(
            cb.metrics().times_opened,
            1,
            "the probe's success must not re-open the breaker"
        );
    }

    /// Probes of a half-open episode that already re-opened are as stale as
    /// ordinary calls from before an open: their failures filled the window
    /// the re-open had cleared, so the next recovery's closing probe opened
    /// the breaker again at once (br-asupersync-e9gn8y).
    #[test]
    fn stale_probe_failures_do_not_reopen_after_recovery() {
        let policy = CircuitBreakerPolicy {
            failure_threshold: 1000,
            success_threshold: 1,
            half_open_max_probes: 4,
            open_duration: Duration::from_secs(10),
            sliding_window: Some(SlidingWindowConfig {
                window_duration: Duration::from_secs(60),
                minimum_calls: 4,
                failure_rate_threshold: 0.5,
            }),
            ..CircuitBreakerPolicy::default()
        };
        let cb = CircuitBreaker::new(policy);
        let start = Time::from_millis(1_000);
        for _ in 0..4 {
            let permit = cb.should_allow(start).expect("closed");
            cb.record_failure(permit, "err", start);
        }
        assert!(cb.should_allow(start).is_err(), "should be open");

        // Four probes of one half-open episode: the first fails and re-opens
        // the breaker, the others fail later, while it is open again.
        let half_open = Time::from_millis(11_500);
        let probes: Vec<_> = (0..4)
            .map(|_| cb.should_allow(half_open).expect("half-open probe"))
            .collect();
        let mut probes = probes.into_iter();
        cb.record_failure(probes.next().expect("a probe"), "err", half_open);
        assert!(cb.should_allow(half_open).is_err(), "re-opened");
        let late = Time::from_millis(12_000);
        for probe in probes {
            cb.record_failure(probe, "err", late);
        }

        let recovery = Time::from_millis(22_500);
        let probe = cb.should_allow(recovery).expect("next half-open probe");
        cb.record_success(probe, recovery);
        assert_eq!(cb.state(), State::Closed { failures: 0 });
        assert_eq!(
            cb.metrics().times_opened,
            2,
            "the recovery must not re-open the breaker"
        );
    }

    #[derive(Debug, PartialEq, Eq)]
    struct OpenRecoverySnapshot {
        post_probe_states: Vec<State>,
        final_state: State,
        total_success: u64,
        total_failure: u64,
        total_rejected: u64,
        times_opened: u64,
        times_closed: u64,
        terminal_allows_normal: bool,
    }

    fn run_open_recovery_trace(
        success_threshold: u32,
        extra_open_polls: u32,
    ) -> OpenRecoverySnapshot {
        let cb = CircuitBreaker::new(CircuitBreakerPolicy {
            failure_threshold: 1,
            success_threshold,
            open_duration: Duration::from_millis(10),
            half_open_max_probes: 1,
            ..Default::default()
        });
        let opened_at = Time::from_millis(1_000);

        let permit = cb.should_allow(opened_at).expect("closed call should pass");
        cb.record_failure(permit, "trip", opened_at);
        assert!(matches!(cb.state(), State::Open { .. }));

        let pre_expiry = Time::from_millis(1_005);
        for _ in 0..extra_open_polls {
            let result = cb.should_allow(pre_expiry);
            assert!(
                matches!(
                    result,
                    Err(CircuitBreakerError::Open { remaining })
                        if remaining > Duration::ZERO && remaining <= Duration::from_millis(10)
                ),
                "pre-expiry polls must stay rejected while open: {result:?}"
            );
        }

        let recovery_at = Time::from_millis(1_020);
        let mut post_probe_states = Vec::new();
        for step in 0..success_threshold {
            let now = Time::from_millis(recovery_at.as_millis() + u64::from(step));
            let permit = cb
                .should_allow(now)
                .expect("recovery probe should be allowed");
            assert!(matches!(permit, Permit::Probe { .. }));
            cb.record_success(permit, now);
            post_probe_states.push(cb.state());
        }

        let terminal_allows_normal = matches!(
            cb.should_allow(Time::from_millis(
                recovery_at.as_millis() + u64::from(success_threshold) + 1
            )),
            Ok(Permit::Normal)
        );
        let metrics = cb.metrics();
        OpenRecoverySnapshot {
            post_probe_states,
            final_state: cb.state(),
            total_success: metrics.total_success,
            total_failure: metrics.total_failure,
            total_rejected: metrics.total_rejected,
            times_opened: metrics.times_opened,
            times_closed: metrics.times_closed,
            terminal_allows_normal,
        }
    }

    proptest! {
        #[test]
        fn metamorphic_open_rejections_do_not_perturb_recovery(
            success_threshold in 1u32..=6,
            extra_open_polls in 0u32..20,
        ) {
            let baseline = run_open_recovery_trace(success_threshold, 0);
            let transformed = run_open_recovery_trace(success_threshold, extra_open_polls);

            prop_assert_eq!(transformed.post_probe_states, baseline.post_probe_states);
            prop_assert_eq!(transformed.final_state, baseline.final_state);
            prop_assert_eq!(transformed.final_state, State::Closed { failures: 0 });

            prop_assert_eq!(baseline.total_success, u64::from(success_threshold));
            prop_assert_eq!(transformed.total_success, u64::from(success_threshold));
            prop_assert_eq!(transformed.total_failure, baseline.total_failure);
            prop_assert_eq!(baseline.total_failure, 1);
            prop_assert_eq!(transformed.times_opened, baseline.times_opened);
            prop_assert_eq!(transformed.times_closed, baseline.times_closed);
            prop_assert_eq!(baseline.times_opened, 1);
            prop_assert_eq!(baseline.times_closed, 1);

            prop_assert_eq!(
                transformed.total_rejected,
                baseline.total_rejected + u64::from(extra_open_polls)
            );
            prop_assert!(baseline.terminal_allows_normal);
            prop_assert!(transformed.terminal_allows_normal);
        }
    }
