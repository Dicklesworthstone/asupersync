    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn backoff_increases() {
        let backoff =
            ExponentialBackoff::new(Duration::from_millis(10), Duration::from_secs(1), 2.0, 5)
                .with_jitter(0.0); // Disable jitter for predictable test

        assert_eq!(backoff.backoff_duration(0), Duration::from_millis(10));
        assert_eq!(backoff.backoff_duration(1), Duration::from_millis(20));
        assert_eq!(backoff.backoff_duration(2), Duration::from_millis(40));
    }

    #[test]
    fn backoff_saturates_for_attempts_beyond_i32_range() {
        let backoff = ExponentialBackoff::new(
            Duration::from_millis(10),
            Duration::from_secs(1),
            2.0,
            u32::MAX,
        )
        .with_jitter(0.0);

        let duration = backoff.backoff_duration((i32::MAX as u32).saturating_add(1));
        assert_eq!(
            duration,
            Duration::from_secs(1),
            "large attempts must saturate at max delay instead of wrapping the exponent"
        );
    }

    #[test]
    fn jitter_is_clamped_to_documented_range() {
        let high =
            ExponentialBackoff::new(Duration::from_millis(10), Duration::from_secs(1), 2.0, 5)
                .with_jitter(5.0);
        assert_eq!(high.jitter.to_bits(), 1.0f64.to_bits());

        let low =
            ExponentialBackoff::new(Duration::from_millis(10), Duration::from_secs(1), 2.0, 5)
                .with_jitter(-1.0);
        assert_eq!(low.jitter.to_bits(), 0.0f64.to_bits());

        let nan =
            ExponentialBackoff::new(Duration::from_millis(10), Duration::from_secs(1), 2.0, 5)
                .with_jitter(f64::NAN);
        assert_eq!(nan.jitter.to_bits(), 0.0f64.to_bits());
    }

    #[test]
    fn circuit_breaker_trips() {
        let cb = CircuitBreaker::new(2, Duration::from_secs(1));
        let t0 = Time::from_secs(100);

        assert!(cb.should_try(t0));
        cb.record_failure(t0); // 1 failure
        assert!(cb.should_try(t0));
        cb.record_failure(t0); // 2 failures -> Open

        assert!(!cb.should_try(t0));
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn circuit_breaker_recovers() {
        let cb = CircuitBreaker::new(1, Duration::from_secs(1));
        let t0 = Time::from_secs(100);
        let t1 = Time::from_secs(102);

        cb.record_failure(t0); // Open
        assert!(!cb.should_try(t0));

        // Time passes
        assert!(cb.should_try(t1)); // Transition to HalfOpen
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    // --- wave 78 trait coverage ---

    #[test]
    fn reset_does_not_overwrite_concurrent_open() {
        // Regression: reset() used unconditional store(Closed) which could
        // silently overwrite a concurrent HalfOpen→Open from record_failure.
        let cb = CircuitBreaker::new(1, Duration::from_secs(1));
        let t0 = Time::from_secs(100);
        let t1 = Time::from_secs(102);

        cb.record_failure(t0); // Open
        assert!(cb.should_try(t1)); // HalfOpen

        // Simulate the race: record_failure transitions HalfOpen→Open first
        cb.record_failure(t1);
        assert_eq!(cb.state(), CircuitState::Open);

        // Now call reset — should NOT overwrite Open with Closed
        cb.reset();
        assert_eq!(
            cb.state(),
            CircuitState::Open,
            "reset must not overwrite concurrent HalfOpen→Open transition"
        );
    }

    #[test]
    fn circuit_state_debug_clone_copy_eq() {
        let s = CircuitState::Closed;
        let s2 = s; // Copy
        let s3 = s;
        assert_eq!(s, s2);
        assert_eq!(s, s3);
        assert_ne!(s, CircuitState::Open);
        assert_ne!(s, CircuitState::HalfOpen);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Closed"));
    }
