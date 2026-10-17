    use super::*;
    use crate::runtime::config::RuntimeConfig;

    fn apply_env_overrides(config: &mut RuntimeConfig) -> Result<(), BuildError> {
        super::apply_env_overrides(config, &SystemEnvReader::new())
    }

    fn with_clean_env<F, R>(f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _guard = crate::test_utils::env_lock();
        clean_env_locked();
        f()
    }

    // Helper: set env var for the duration of a closure, then unset.
    fn with_env<F, R>(var: &str, val: &str, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        with_clean_env(|| {
            // SAFETY: test helpers guard environment mutation with env_lock.
            unsafe { std::env::set_var(var, val) };
            let result = f();
            // SAFETY: test helpers guard environment mutation with env_lock.
            unsafe { std::env::remove_var(var) };
            result
        })
    }

    fn with_envs<F, R>(vars: &[(&str, &str)], f: F) -> R
    where
        F: FnOnce() -> R,
    {
        with_clean_env(|| {
            for (k, v) in vars {
                // SAFETY: test helpers guard environment mutation with env_lock.
                unsafe { std::env::set_var(k, v) };
            }
            let result = f();
            for (k, _) in vars {
                // SAFETY: test helpers guard environment mutation with env_lock.
                unsafe { std::env::remove_var(k) };
            }
            result
        })
    }

    fn clean_env_locked() {
        for var in &[
            ENV_WORKER_THREADS,
            ENV_TASK_QUEUE_DEPTH,
            ENV_THREAD_STACK_SIZE,
            ENV_THREAD_NAME_PREFIX,
            ENV_STEAL_BATCH_SIZE,
            ENV_BLOCKING_MIN_THREADS,
            ENV_BLOCKING_MAX_THREADS,
            ENV_ENABLE_PARKING,
            ENV_POLL_BUDGET,
            ENV_CANCEL_LANE_MAX_STREAK,
            ENV_ENABLE_GOVERNOR,
            ENV_GOVERNOR_INTERVAL,
            ENV_ENABLE_ADAPTIVE_CANCEL_STREAK,
            ENV_ADAPTIVE_CANCEL_EPOCH_STEPS,
        ] {
            // SAFETY: test helpers guard environment mutation with env_lock.
            unsafe { std::env::remove_var(var) };
        }
    }

    // --- parse helpers ---

    #[test]
    fn parse_usize_valid() {
        assert_eq!(
            super::parse_usize("TEST", "42").expect("should parse valid usize '42'"),
            42
        );
        assert_eq!(
            super::parse_usize("TEST", " 100 ")
                .expect("should parse valid usize ' 100 ' with whitespace"),
            100
        );
        assert_eq!(
            super::parse_usize("TEST", "0").expect("should parse valid usize '0'"),
            0
        );
    }

    #[test]
    fn parse_usize_invalid() {
        assert!(super::parse_usize("TEST", "abc").is_err());
        assert!(super::parse_usize("TEST", "-1").is_err());
        assert!(super::parse_usize("TEST", "3.14").is_err());
        assert!(super::parse_usize("TEST", "").is_err());
    }

    #[test]
    fn parse_u32_valid() {
        assert_eq!(
            super::parse_u32("TEST", "128").expect("should parse valid u32 '128'"),
            128
        );
    }

    #[test]
    fn parse_u32_invalid() {
        assert!(super::parse_u32("TEST", "not_a_number").is_err());
    }

    #[test]
    fn parse_bool_all_truthy() {
        for val in &["true", "1", "yes", "on", "TRUE", "Yes", "ON"] {
            assert!(
                super::parse_bool("TEST", val)
                    .unwrap_or_else(|_| panic!("should parse truthy value '{}'", val)),
                "expected true for {val}"
            );
        }
    }

    #[test]
    fn parse_bool_all_falsy() {
        for val in &["false", "0", "no", "off", "FALSE", "No", "OFF"] {
            assert!(
                !super::parse_bool("TEST", val)
                    .unwrap_or_else(|_| panic!("should parse falsy value '{}'", val)),
                "expected false for {val}"
            );
        }
    }

    #[test]
    fn parse_bool_invalid() {
        assert!(super::parse_bool("TEST", "maybe").is_err());
        assert!(super::parse_bool("TEST", "2").is_err());
        assert!(super::parse_bool("TEST", "").is_err());
    }

    // --- apply_env_overrides ---

    #[test]
    fn env_overrides_worker_threads() {
        with_env(ENV_WORKER_THREADS, "8", || {
            let mut config = RuntimeConfig::default();
            apply_env_overrides(&mut config).expect("should apply worker_threads env override");
            assert_eq!(config.worker_threads, 8);
        });
    }

    #[test]
    fn env_overrides_task_queue_depth() {
        with_env(ENV_TASK_QUEUE_DEPTH, "2048", || {
            let mut config = RuntimeConfig::default();
            apply_env_overrides(&mut config).expect("should apply task_queue_depth env override");
            assert_eq!(config.global_queue_limit, 2048);
        });
    }

    #[test]
    fn env_overrides_thread_stack_size() {
        with_env(ENV_THREAD_STACK_SIZE, "4194304", || {
            let mut config = RuntimeConfig::default();
            apply_env_overrides(&mut config).expect("should apply thread_stack_size env override");
            assert_eq!(config.thread_stack_size, 4_194_304);
        });
    }

    #[test]
    fn env_overrides_thread_name_prefix() {
        with_env(ENV_THREAD_NAME_PREFIX, "myapp-worker", || {
            let mut config = RuntimeConfig::default();
            apply_env_overrides(&mut config).expect("should apply thread_name_prefix env override");
            assert_eq!(config.thread_name_prefix, "myapp-worker");
        });
    }

    #[test]
    fn env_rejects_thread_name_prefix_with_nul() {
        let mut vars = HashMap::new();
        vars.insert(
            ENV_THREAD_NAME_PREFIX.to_string(),
            "bad\0prefix".to_string(),
        );
        let reader = TestEnvReader::new(vars);
        let mut config = RuntimeConfig::default();

        let err = super::apply_env_overrides(&mut config, &reader)
            .expect_err("NUL prefix must be rejected");

        assert!(err.to_string().contains("NUL"), "unexpected error: {err}");
    }

    #[test]
    fn env_layer_parses_before_applying_any_field() {
        let mut vars = HashMap::new();
        vars.insert(ENV_WORKER_THREADS.to_owned(), "8".to_owned());
        vars.insert(
            ENV_ENABLE_ADAPTIVE_CANCEL_STREAK.to_owned(),
            "invalid".to_owned(),
        );
        let reader = TestEnvReader::new(vars);
        let mut config = RuntimeConfig::default();
        let original_worker_threads = config.worker_threads;

        let error = super::apply_env_overrides(&mut config, &reader)
            .expect_err("invalid late variable must reject the whole layer");

        assert!(
            error
                .to_string()
                .contains(ENV_ENABLE_ADAPTIVE_CANCEL_STREAK)
        );
        assert_eq!(config.worker_threads, original_worker_threads);
    }

    #[test]
    fn env_overrides_steal_batch_size() {
        with_env(ENV_STEAL_BATCH_SIZE, "32", || {
            let mut config = RuntimeConfig::default();
            apply_env_overrides(&mut config).unwrap();
            assert_eq!(config.steal_batch_size, 32);
        });
    }

    #[test]
    fn env_overrides_blocking_threads() {
        with_envs(
            &[
                (ENV_BLOCKING_MIN_THREADS, "2"),
                (ENV_BLOCKING_MAX_THREADS, "16"),
            ],
            || {
                let mut config = RuntimeConfig::default();
                apply_env_overrides(&mut config).unwrap();
                assert_eq!(config.blocking.min_threads, 2);
                assert_eq!(config.blocking.max_threads, 16);
            },
        );
    }

    #[test]
    fn env_overrides_blocking_threads_normalizes_partial_override() {
        with_env(ENV_BLOCKING_MIN_THREADS, "8", || {
            let mut config = RuntimeConfig::default();
            apply_env_overrides(&mut config).unwrap();
            assert_eq!(config.blocking.min_threads, 8);
            assert_eq!(config.blocking.max_threads, 8);
        });

        with_env(ENV_BLOCKING_MAX_THREADS, "4", || {
            let mut config = RuntimeConfig::default();
            config.blocking.min_threads = 6;

            apply_env_overrides(&mut config).unwrap();

            assert_eq!(config.blocking.min_threads, 6);
            assert_eq!(config.blocking.max_threads, 6);
        });
    }

    #[test]
    fn env_overrides_enable_parking() {
        with_env(ENV_ENABLE_PARKING, "false", || {
            let mut config = RuntimeConfig::default();
            apply_env_overrides(&mut config).unwrap();
            assert!(!config.enable_parking);
        });
    }

    #[test]
    fn env_overrides_poll_budget() {
        with_env(ENV_POLL_BUDGET, "64", || {
            let mut config = RuntimeConfig::default();
            apply_env_overrides(&mut config).unwrap();
            assert_eq!(config.poll_budget, 64);
        });
    }

    #[test]
    fn env_overrides_cancel_lane_max_streak() {
        with_env(ENV_CANCEL_LANE_MAX_STREAK, "7", || {
            let mut config = RuntimeConfig::default();
            apply_env_overrides(&mut config).unwrap();
            assert_eq!(config.cancel_lane_max_streak, 7);
        });
    }

    #[test]
    fn env_overrides_governor_settings() {
        with_envs(
            &[(ENV_ENABLE_GOVERNOR, "true"), (ENV_GOVERNOR_INTERVAL, "41")],
            || {
                let mut config = RuntimeConfig::default();
                apply_env_overrides(&mut config).unwrap();
                assert!(config.enable_governor);
                assert_eq!(config.governor_interval, 41);
            },
        );
    }

    #[test]
    fn env_overrides_adaptive_cancel_settings() {
        with_envs(
            &[
                (ENV_ENABLE_ADAPTIVE_CANCEL_STREAK, "true"),
                (ENV_ADAPTIVE_CANCEL_EPOCH_STEPS, "77"),
            ],
            || {
                let mut config = RuntimeConfig::default();
                apply_env_overrides(&mut config).unwrap();
                assert!(config.enable_adaptive_cancel_streak);
                assert_eq!(config.adaptive_cancel_streak_epoch_steps, 77);
            },
        );
    }

    #[test]
    fn env_overrides_multiple() {
        with_envs(
            &[
                (ENV_WORKER_THREADS, "4"),
                (ENV_POLL_BUDGET, "256"),
                (ENV_ENABLE_PARKING, "no"),
            ],
            || {
                let mut config = RuntimeConfig::default();
                apply_env_overrides(&mut config).unwrap();
                assert_eq!(config.worker_threads, 4);
                assert_eq!(config.poll_budget, 256);
                assert!(!config.enable_parking);
            },
        );
    }

    #[test]
    fn env_overrides_unset_vars_leave_defaults() {
        with_clean_env(|| {
            let defaults = RuntimeConfig::default();
            let mut config = RuntimeConfig::default();
            apply_env_overrides(&mut config).unwrap();
            assert_eq!(config.worker_threads, defaults.worker_threads);
            assert_eq!(config.poll_budget, defaults.poll_budget);
            assert_eq!(config.enable_parking, defaults.enable_parking);
        });
    }

    #[test]
    fn env_overrides_invalid_value_returns_error() {
        with_env(ENV_WORKER_THREADS, "not_a_number", || {
            let mut config = RuntimeConfig::default();
            let result = apply_env_overrides(&mut config);
            assert!(result.is_err());
            let err = result.unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains(ENV_WORKER_THREADS),
                "error should mention var name: {msg}"
            );
            assert!(
                msg.contains("not_a_number"),
                "error should mention bad value: {msg}"
            );
        });
    }

    #[test]
    fn clean_env_locked_removes_governor_related_vars() {
        let _guard = crate::test_utils::env_lock();
        // SAFETY: this test holds env_lock for exclusive process-wide env mutation.
        unsafe {
            std::env::set_var(ENV_CANCEL_LANE_MAX_STREAK, "99");
            std::env::set_var(ENV_ENABLE_GOVERNOR, "true");
            std::env::set_var(ENV_GOVERNOR_INTERVAL, "123");
            std::env::set_var(ENV_ENABLE_ADAPTIVE_CANCEL_STREAK, "true");
            std::env::set_var(ENV_ADAPTIVE_CANCEL_EPOCH_STEPS, "77");
        }

        clean_env_locked();

        assert!(std::env::var(ENV_CANCEL_LANE_MAX_STREAK).is_err());
        assert!(std::env::var(ENV_ENABLE_GOVERNOR).is_err());
        assert!(std::env::var(ENV_GOVERNOR_INTERVAL).is_err());
        assert!(std::env::var(ENV_ENABLE_ADAPTIVE_CANCEL_STREAK).is_err());
        assert!(std::env::var(ENV_ADAPTIVE_CANCEL_EPOCH_STEPS).is_err());
    }

    #[test]
    fn env_overrides_invalid_bool_returns_error() {
        with_env(ENV_ENABLE_PARKING, "maybe", || {
            let mut config = RuntimeConfig::default();
            let result = apply_env_overrides(&mut config);
            assert!(result.is_err());
            let msg = result.unwrap_err().to_string();
            assert!(msg.contains("maybe"));
        });
    }
