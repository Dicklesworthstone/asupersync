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
    fn config_default() {
        let config = ObservabilityConfig::default();
        assert_eq!(config.log_level(), LogLevel::Info);
        assert!(!config.trace_all_symbols());
        assert!((config.sample_rate() - 1.0).abs() < f64::EPSILON);
        assert!(config.metrics_enabled());
    }

    /// br-asupersync-z5ge0x: try_replayable_system_time returns None
    /// when there is no Cx in scope AND no global observability clock
    /// has been installed. This is the strict-no-fallback variant; it
    /// must NEVER consult ambient SystemTime::now and NEVER emit the
    /// warn line.
    ///
    /// Note: this test runs in a dedicated thread to ensure no prior
    /// test in the same thread installed a Cx via thread-local that we
    /// might inherit; OnceLock state is process-wide so we only assert
    /// the None case if no installer has fired earlier in the process.
    #[test]
    fn try_replayable_system_time_returns_none_without_source_in_isolated_thread() {
        // Spawn a fresh thread so no thread-local Cx leaks in.
        let result = std::thread::spawn(|| {
            // If a prior test in this process installed the global
            // clock, try_replayable_system_time returns Some — that's
            // valid behaviour, just not the case we're asserting. Skip
            // the assertion in that scenario.
            if GLOBAL_OBSERVABILITY_CLOCK.get().is_some() {
                return;
            }
            let observed = try_replayable_system_time();
            assert!(
                observed.is_none(),
                "try_replayable_system_time must return None when neither Cx nor global clock is available; observed {observed:?}"
            );
        })
        .join();
        assert!(result.is_ok());
    }

    /// br-asupersync-z5ge0x: install_global_observability_clock installs
    /// the singleton at most once per process. The first installation
    /// returns Ok; subsequent calls return Err and do NOT replace
    /// the installed clock.
    ///
    /// Because OnceLock is process-wide and other tests may install
    /// their own clock, this test only asserts the once-only semantic
    /// — it accepts EITHER (a) we won the install race and observe the
    /// time from our deterministic clock, OR (b) we lost the race to
    /// some prior test and observe a Time from THEIR clock. In both
    /// cases install_global_observability_clock must reject our second
    /// call with Err.
    #[test]
    fn install_global_observability_clock_is_once_only() {
        fn fixed_clock() -> std::time::SystemTime {
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(0xC0FFEE)
        }
        // First install: may succeed (we won) or fail (someone else won).
        let first = install_global_observability_clock(fixed_clock);
        // Second install must always fail (OnceLock is set after first).
        let second = install_global_observability_clock(fixed_clock);
        assert!(
            second.is_err(),
            "second install must return Err per OnceLock semantics; first attempt was {first:?}"
        );
        // The clock is now definitely populated (either by us or a
        // prior test); try_replayable_system_time must return Some
        // even with no Cx in scope.
        let observed = std::thread::spawn(try_replayable_system_time)
            .join()
            .expect("isolated-thread query");
        assert!(
            observed.is_some(),
            "with the global clock populated, try_replayable_system_time must return Some"
        );
    }

    #[test]
    fn retry_after_parses_delay_seconds_and_http_date_formats() {
        fn fixed_time(
            year: i32,
            month: u32,
            day: u32,
            hour: u32,
            minute: u32,
            second: u32,
        ) -> std::time::SystemTime {
            let unix_seconds = unix_seconds_from_utc(year, month, day, hour, minute, second)
                .expect("valid fixed test time");
            std::time::UNIX_EPOCH
                + std::time::Duration::from_secs(
                    u64::try_from(unix_seconds).expect("post-epoch time"),
                )
        }

        let delay_headers = vec![("Retry-After".to_string(), " 42 ".to_string())];
        assert_eq!(
            parse_http_retry_after_at(&delay_headers, std::time::UNIX_EPOCH),
            Some(std::time::Duration::from_secs(42))
        );

        let one_minute_before_imf = fixed_time(2015, 10, 21, 7, 27, 0);
        let one_minute_before_obs = fixed_time(1994, 11, 6, 8, 48, 37);

        for value in [
            "Wed, 21 Oct 2015 07:28:00 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
        ] {
            let now = if value.starts_with("Wed") {
                one_minute_before_imf
            } else {
                one_minute_before_obs
            };
            let headers = vec![("Retry-After".to_string(), value.to_string())];
            assert_eq!(
                parse_http_retry_after_at(&headers, now),
                Some(std::time::Duration::from_secs(60)),
                "Retry-After HTTP-date should parse: {value}"
            );
        }

        let past_headers = vec![(
            "Retry-After".to_string(),
            "Wed, 21 Oct 2015 07:28:00 GMT".to_string(),
        )];
        assert_eq!(
            parse_http_retry_after_at(&past_headers, fixed_time(2015, 10, 21, 7, 29, 0)),
            Some(std::time::Duration::ZERO),
            "past Retry-After HTTP-date should allow immediate retry"
        );

        let malformed_headers = vec![("Retry-After".to_string(), "next Tuesday".to_string())];
        assert_eq!(
            parse_http_retry_after_at(&malformed_headers, std::time::UNIX_EPOCH),
            None
        );
    }

    /// Under a Cx the local "now" is runtime time (1970 plus uptime), which
    /// turned every HTTP-date Retry-After into decades and so into the
    /// exporter's maximum backoff. The response's own Date is the server's
    /// clock, the one the Retry-After instant is on.
    #[test]
    fn retry_after_http_date_is_measured_against_the_response_date() {
        let runtime_now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(300);
        let with_date = |date: &str| {
            vec![
                ("Date".to_string(), date.to_string()),
                (
                    "Retry-After".to_string(),
                    "Wed, 21 Oct 2015 07:28:00 GMT".to_string(),
                ),
            ]
        };
        assert_eq!(
            parse_http_retry_after_at(&with_date("Wed, 21 Oct 2015 07:27:58 GMT"), runtime_now),
            Some(std::time::Duration::from_secs(2))
        );
        assert_eq!(
            parse_http_retry_after_at(&with_date("Wed, 21 Oct 2015 07:29:00 GMT"), runtime_now),
            Some(std::time::Duration::ZERO)
        );
        // An unparseable Date falls back to the caller's clock.
        let one_minute_before = std::time::UNIX_EPOCH
            + std::time::Duration::from_secs(
                u64::try_from(
                    unix_seconds_from_utc(2015, 10, 21, 7, 27, 0).expect("valid fixed test time"),
                )
                .expect("post-epoch time"),
            );
        assert_eq!(
            parse_http_retry_after_at(&with_date("yesterday"), one_minute_before),
            Some(std::time::Duration::from_secs(60))
        );
    }

    #[test]
    fn config_builder() {
        let config = ObservabilityConfig::new()
            .with_log_level(LogLevel::Debug)
            .with_trace_all_symbols(true)
            .with_sample_rate(0.5)
            .with_max_spans(500)
            .with_max_log_entries(5000)
            .with_include_timestamps(false)
            .with_metrics_enabled(false);

        assert_eq!(config.log_level(), LogLevel::Debug);
        assert!(config.trace_all_symbols());
        assert!((config.sample_rate() - 0.5).abs() < f64::EPSILON);
        assert_eq!(config.max_spans(), 500);
        assert_eq!(config.max_log_entries(), 5000);
        assert!(!config.include_timestamps());
        assert!(!config.metrics_enabled());
    }

    #[test]
    fn config_presets() {
        let dev = ObservabilityConfig::development();
        assert_eq!(dev.log_level(), LogLevel::Debug);
        assert!(dev.trace_all_symbols());

        let prod = ObservabilityConfig::production();
        assert_eq!(prod.log_level(), LogLevel::Warn);
        assert!(!prod.trace_all_symbols());
        assert!(prod.sample_rate() < 0.1);

        let test = ObservabilityConfig::testing();
        assert_eq!(test.log_level(), LogLevel::Trace);
        assert!(test.trace_all_symbols());
    }

    #[test]
    fn config_create_collector() {
        let config = ObservabilityConfig::new()
            .with_log_level(LogLevel::Warn)
            .with_max_log_entries(100);

        let collector = config.create_collector();
        assert_eq!(collector.min_level(), LogLevel::Warn);
        assert_eq!(collector.capacity(), 100);
    }

    #[test]
    fn config_create_metrics() {
        let enabled = ObservabilityConfig::new().with_metrics_enabled(true);
        assert!(enabled.create_metrics().is_some());

        let disabled = ObservabilityConfig::new().with_metrics_enabled(false);
        assert!(disabled.create_metrics().is_none());
    }

    #[test]
    fn config_sampling() {
        let full = ObservabilityConfig::new().with_sample_rate(1.0);
        assert!(full.should_sample(0));
        assert!(full.should_sample(u64::MAX));

        let none = ObservabilityConfig::new().with_sample_rate(0.0);
        assert!(!none.should_sample(0));
        assert!(!none.should_sample(u64::MAX));

        let half = ObservabilityConfig::new().with_sample_rate(0.5);
        // Deterministic: same key always gives same result
        let result1 = half.should_sample(12345);
        let result2 = half.should_sample(12345);
        assert_eq!(result1, result2);
    }

    #[test]
    fn config_sampling_hashes_low_sequential_keys() {
        let half = ObservabilityConfig::new().with_sample_rate(0.5);
        let sampled = (0..64).filter(|&key| half.should_sample(key)).count();

        assert!(
            sampled > 0,
            "hashed sampling should accept some low sequential keys"
        );
        assert!(
            sampled < 64,
            "hashed sampling should not deterministically accept every low sequential key"
        );
    }

    #[test]
    #[should_panic(expected = "sample_rate must be between 0.0 and 1.0")]
    fn config_invalid_sample_rate_high() {
        let _ = ObservabilityConfig::new().with_sample_rate(1.5);
    }

    #[test]
    #[should_panic(expected = "sample_rate must be between 0.0 and 1.0")]
    fn config_invalid_sample_rate_negative() {
        let _ = ObservabilityConfig::new().with_sample_rate(-0.1);
    }
