    use super::*;

    #[test]
    fn standard_profile_materializes_explicit_bounded_admission() {
        let profile = DesktopRuntimeProfile::standard();
        let config = profile.runtime_config().expect("standard profile is valid");

        assert_eq!(DESKTOP_RUNTIME_PROFILE_NAME, "desktop-bounded-v1");
        assert_eq!(config.worker_threads, 2);
        assert_eq!(config.global_queue_limit, 256);
        assert_eq!(config.blocking.min_threads, 1);
        assert_eq!(config.blocking.max_threads, 2);
        assert_eq!(
            config.root_region_limits.as_ref().unwrap().max_tasks,
            Some(1_024)
        );
        assert_eq!(config.thread_name_prefix, "asupersync-desktop");
    }

    #[test]
    fn zero_queue_is_rejected_instead_of_normalized_to_unbounded() {
        let profile = DesktopRuntimeProfile::with_limits(1, 0, 1, 1, 0, 0, 1, 1, 1, 1);
        assert_eq!(
            profile.validate(),
            Err(DesktopRuntimeProfileError::UnboundedGlobalQueue)
        );
    }

    #[test]
    fn inverted_blocking_range_is_rejected() {
        let profile = DesktopRuntimeProfile::with_limits(1, 1, 1, 1, 2, 1, 1, 1, 1, 1);
        assert_eq!(
            profile.validate(),
            Err(DesktopRuntimeProfileError::BlockingRangeInverted { min: 2, max: 1 })
        );
    }

    #[test]
    fn unit_limits_are_the_valid_boundary() {
        let profile = DesktopRuntimeProfile::with_limits(1, 1, 1, 1, 0, 0, 1, 1, 1, 1);
        let config = profile.runtime_config().expect("unit limits are valid");

        assert_eq!(config.global_queue_limit, 1);
        assert_eq!(config.steal_batch_size, 1);
        assert_eq!(config.poll_budget, 1);
        assert_eq!(
            config.root_region_limits.as_ref().unwrap().max_heap_bytes,
            Some(1)
        );
    }
