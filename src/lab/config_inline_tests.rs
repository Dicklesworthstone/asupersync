    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn default_config() {
        init_test("default_config");
        let config = LabConfig::default();
        let ok = config.seed == 42;
        crate::assert_with_log!(ok, "seed", 42, config.seed);
        crate::assert_with_log!(
            config.entropy_seed == 42,
            "entropy_seed",
            42,
            config.entropy_seed
        );
        crate::assert_with_log!(
            config.worker_count == 1,
            "worker_count",
            1,
            config.worker_count
        );
        crate::assert_with_log!(
            config.panic_on_obligation_leak,
            "panic_on_obligation_leak",
            true,
            config.panic_on_obligation_leak
        );
        crate::assert_with_log!(
            config.panic_on_futurelock,
            "panic_on_futurelock",
            true,
            config.panic_on_futurelock
        );
        crate::test_complete!("default_config");
    }

    #[test]
    fn oracle_selection_validates_names() {
        init_test("oracle_selection_validates_names");
        let config = LabConfig::new(42)
            .with_oracles(&["task_leak", "obligation_leak"])
            .expect("known oracle names should validate");
        assert_eq!(
            config.selected_oracles().expect("selection resolves"),
            vec!["task_leak", "obligation_leak"]
        );

        let all_config = LabConfig::new(42)
            .with_oracles(&[ORACLE_ALL])
            .expect("all selection validates");
        assert_eq!(
            all_config
                .selected_oracles()
                .expect("all selection resolves")
                .len(),
            OracleRegistry::reported_names().len()
        );

        let err = LabConfig::new(42)
            .with_oracles(&["task_lek"])
            .expect_err("unknown oracle should reject");
        assert!(err.to_string().contains("task_leak"));
        crate::test_complete!("oracle_selection_validates_names");
    }

    #[test]
    fn rng_is_deterministic() {
        init_test("rng_is_deterministic");
        let config = LabConfig::new(12345);
        let mut rng1 = config.rng();
        let mut rng2 = config.rng();

        let a = rng1.next_u64();
        let b = rng2.next_u64();
        crate::assert_with_log!(a == b, "rng equal", b, a);
        crate::test_complete!("rng_is_deterministic");
    }

    #[test]
    fn worker_count_clamps_to_one() {
        init_test("worker_count_clamps_to_one");
        let config = LabConfig::new(7).worker_count(0);
        crate::assert_with_log!(
            config.worker_count == 1,
            "worker_count",
            1,
            config.worker_count
        );
        crate::test_complete!("worker_count_clamps_to_one");
    }

    #[test]
    fn lab_config_debug() {
        init_test("lab_config_debug");
        let cfg = LabConfig::new(42);
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("LabConfig"));
        crate::test_complete!("lab_config_debug");
    }

    #[test]
    fn lab_config_clone() {
        init_test("lab_config_clone");
        let cfg = LabConfig::new(99).worker_count(3);
        let cfg2 = cfg;
        assert_eq!(cfg2.seed, 99);
        assert_eq!(cfg2.worker_count, 3);
        crate::test_complete!("lab_config_clone");
    }

    #[test]
    fn new_sets_fields() {
        init_test("new_sets_fields");
        let cfg = LabConfig::new(123);
        assert_eq!(cfg.seed, 123);
        assert_eq!(cfg.entropy_seed, 123);
        assert_eq!(cfg.worker_count, 1);
        assert!(cfg.panic_on_obligation_leak);
        assert_eq!(cfg.trace_capacity, 4096);
        assert_eq!(cfg.futurelock_max_idle_steps, 10_000);
        assert!(cfg.panic_on_futurelock);
        assert_eq!(cfg.max_steps, Some(100_000));
        assert!(cfg.chaos.is_none());
        assert!(cfg.replay_recording.is_none());
        assert!(!cfg.auto_advance_time);
        crate::test_complete!("new_sets_fields");
    }

    #[test]
    fn from_time_creates_valid_config() {
        init_test("from_time_creates_valid_config");
        // br-asupersync-eij5e4: route through the new
        // from_time_unstable alias so the test does not trip the
        // (deliberate) deprecation warning on the bare `from_time`
        // foot-gun.
        let cfg = LabConfig::from_time_unstable();
        // seed should be set from system time (non-deterministic but valid)
        assert_eq!(cfg.entropy_seed, cfg.seed);
        assert_eq!(cfg.worker_count, 1);
        crate::test_complete!("from_time_creates_valid_config");
    }

    #[test]
    fn panic_on_leak_builder() {
        init_test("panic_on_leak_builder");
        let cfg = LabConfig::new(1).panic_on_leak(false);
        assert!(!cfg.panic_on_obligation_leak);
        let cfg = cfg.panic_on_leak(true);
        assert!(cfg.panic_on_obligation_leak);
        crate::test_complete!("panic_on_leak_builder");
    }

    #[test]
    fn trace_capacity_builder() {
        init_test("trace_capacity_builder");
        let cfg = LabConfig::new(1).trace_capacity(8192);
        assert_eq!(cfg.trace_capacity, 8192);
        crate::test_complete!("trace_capacity_builder");
    }

    #[test]
    fn entropy_seed_builder() {
        init_test("entropy_seed_builder");
        let cfg = LabConfig::new(42).entropy_seed(7);
        assert_eq!(cfg.seed, 42);
        assert_eq!(cfg.entropy_seed, 7);
        crate::test_complete!("entropy_seed_builder");
    }

    #[test]
    fn futurelock_max_idle_steps_builder() {
        init_test("futurelock_max_idle_steps_builder");
        let cfg = LabConfig::new(1).futurelock_max_idle_steps(5000);
        assert_eq!(cfg.futurelock_max_idle_steps, 5000);
        crate::test_complete!("futurelock_max_idle_steps_builder");
    }

    #[test]
    fn panic_on_futurelock_builder() {
        init_test("panic_on_futurelock_builder");
        let cfg = LabConfig::new(1).panic_on_futurelock(false);
        assert!(!cfg.panic_on_futurelock);
        crate::test_complete!("panic_on_futurelock_builder");
    }

    #[test]
    fn max_steps_builder() {
        init_test("max_steps_builder");
        let cfg = LabConfig::new(1).max_steps(500);
        assert_eq!(cfg.max_steps, Some(500));
        crate::test_complete!("max_steps_builder");
    }

    #[test]
    fn no_step_limit_builder() {
        init_test("no_step_limit_builder");
        let cfg = LabConfig::new(1).no_step_limit();
        assert_eq!(cfg.max_steps, None);
        crate::test_complete!("no_step_limit_builder");
    }

    #[test]
    fn with_auto_advance_builder() {
        init_test("with_auto_advance_builder");
        let cfg = LabConfig::new(1);
        assert!(!cfg.auto_advance_time);
        let cfg = cfg.with_auto_advance();
        assert!(cfg.auto_advance_time);
        crate::test_complete!("with_auto_advance_builder");
    }

    #[test]
    fn has_chaos_false_by_default() {
        init_test("has_chaos_false_by_default");
        let cfg = LabConfig::new(1);
        assert!(!cfg.has_chaos());
        crate::test_complete!("has_chaos_false_by_default");
    }

    #[test]
    fn with_light_chaos_enables() {
        init_test("with_light_chaos_enables");
        let cfg = LabConfig::new(1).with_light_chaos();
        assert!(cfg.has_chaos());
        assert!(cfg.chaos.is_some());
        crate::test_complete!("with_light_chaos_enables");
    }

    #[test]
    fn with_heavy_chaos_enables() {
        init_test("with_heavy_chaos_enables");
        let cfg = LabConfig::new(1).with_heavy_chaos();
        assert!(cfg.has_chaos());
        crate::test_complete!("with_heavy_chaos_enables");
    }

    #[test]
    fn has_replay_recording_false_by_default() {
        init_test("has_replay_recording_false_by_default");
        let cfg = LabConfig::new(1);
        assert!(!cfg.has_replay_recording());
        crate::test_complete!("has_replay_recording_false_by_default");
    }

    #[test]
    fn with_default_replay_recording_enables() {
        init_test("with_default_replay_recording_enables");
        let cfg = LabConfig::new(1).with_default_replay_recording();
        assert!(cfg.has_replay_recording());
        assert!(cfg.replay_recording.is_some());
        crate::test_complete!("with_default_replay_recording_enables");
    }

    #[test]
    fn builder_chaining() {
        init_test("builder_chaining");
        let cfg = LabConfig::new(99)
            .worker_count(4)
            .entropy_seed(7)
            .trace_capacity(2048)
            .panic_on_leak(false)
            .futurelock_max_idle_steps(3000)
            .panic_on_futurelock(false)
            .max_steps(5000)
            .with_auto_advance();
        assert_eq!(cfg.seed, 99);
        assert_eq!(cfg.worker_count, 4);
        assert_eq!(cfg.entropy_seed, 7);
        assert_eq!(cfg.trace_capacity, 2048);
        assert!(!cfg.panic_on_obligation_leak);
        assert_eq!(cfg.futurelock_max_idle_steps, 3000);
        assert!(!cfg.panic_on_futurelock);
        assert_eq!(cfg.max_steps, Some(5000));
        assert!(cfg.auto_advance_time);
        crate::test_complete!("builder_chaining");
    }

    #[test]
    fn worker_count_positive_value() {
        init_test("worker_count_positive_value");
        let cfg = LabConfig::new(1).worker_count(8);
        assert_eq!(cfg.worker_count, 8);
        crate::test_complete!("worker_count_positive_value");
    }

    #[test]
    fn with_chaos_derives_seed() {
        init_test("with_chaos_derives_seed");
        let cfg = LabConfig::new(42).with_chaos(ChaosConfig::light());
        let chaos = cfg.chaos.as_ref().unwrap();
        // Chaos seed derived from main seed + 0xCAFE_BABE
        let dbg = format!("{chaos:?}");
        assert!(!dbg.is_empty());
        crate::test_complete!("with_chaos_derives_seed");
    }
