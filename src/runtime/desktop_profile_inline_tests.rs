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

    /// With a pool that admits work the fallible foreign call runs the operation once, on a pool thread, returns its value
    /// and marks the receipt complete, never refused.
    #[test]
    fn try_run_foreign_call_on_a_bounded_pool_runs_once_and_completes_the_receipt() {
        let pool = crate::runtime::BlockingPool::new(1, 1);
        let guard = crate::cx::Cx::set_current(Some(
            crate::cx::Cx::for_testing().with_blocking_pool_handle(Some(pool.handle())),
        ));
        let caller = std::thread::current().id();
        let completion = ForeignCallCompletion::new();
        let (value, ran_on) =
            futures_lite::future::block_on(try_run_foreign_call(completion.clone(), || {
                (21_u32, std::thread::current().id())
            }))
            .expect("a bounded pool admits the foreign call");
        assert_eq!(value, 21);
        assert_ne!(ran_on, caller, "the operation runs on a pool thread");
        assert!(completion.is_complete());
        assert!(!completion.was_refused());
        drop(guard);
        assert!(pool.shutdown_and_wait(Duration::from_secs(5)));
    }

    /// A forbidden pool, a closed pool and a context with no pool each refuse: the operation never starts (not inline, not
    /// on a thread), the receipt ends refused and never complete, and nothing is left waiting. The compatibility call still
    /// runs the same operation inline where there is no pool.
    #[test]
    fn try_run_foreign_call_refuses_forbidden_closed_and_absent_pools_and_never_starts() {
        use std::sync::atomic::AtomicU32;

        let forbidden = crate::runtime::BlockingPool::with_config_and_policies(
            0,
            1,
            crate::runtime::blocking_pool::BlockingPoolOptions::default(),
            crate::runtime::BlockingQueuePolicy::Fifo,
            crate::runtime::BlockingAdmissionPolicy::Forbidden,
        );
        let closed = crate::runtime::BlockingPool::new(1, 1);
        let closed_handle = closed.handle();
        closed.shutdown();
        let cases = [
            ("forbidden", Some(forbidden.handle())),
            ("closed", Some(closed_handle)),
            ("absent", None),
        ];
        for (name, handle) in cases {
            let ran = Arc::new(AtomicU32::new(0));
            let ran_in_operation = Arc::clone(&ran);
            let completion = ForeignCallCompletion::new();
            let guard = crate::cx::Cx::set_current(Some(
                crate::cx::Cx::for_testing().with_blocking_pool_handle(handle),
            ));
            let refused =
                futures_lite::future::block_on(try_run_foreign_call(completion.clone(), move || {
                    ran_in_operation.fetch_add(1, Ordering::SeqCst);
                    1_u8
                }));
            drop(guard);
            assert_eq!(refused, Err(SpawnError::RuntimeUnavailable), "{name}");
            assert_eq!(
                ran.load(Ordering::SeqCst),
                0,
                "{name}: the operation must not start"
            );
            assert!(
                !completion.is_complete(),
                "{name}: a refused call is never complete"
            );
            assert!(
                completion.was_refused(),
                "{name}: the receipt must end refused"
            );
        }
        forbidden.shutdown();

        // Control: the compatibility call runs the same operation inline where there is no pool.
        let guard = crate::cx::Cx::set_current(Some(crate::cx::Cx::for_testing()));
        let completion = ForeignCallCompletion::new();
        let inline = futures_lite::future::block_on(run_foreign_call(completion.clone(), || {
            std::thread::current().id()
        }));
        drop(guard);
        assert_eq!(inline, std::thread::current().id());
        assert!(completion.is_complete());
        assert!(!completion.was_refused());
    }
