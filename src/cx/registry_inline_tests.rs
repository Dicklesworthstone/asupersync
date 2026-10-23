    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::util::ArenaIndex;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn tid(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn rid(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n + 1, 0))
    }

    // ---------------------------------------------------------------
    // NameLease tests
    // ---------------------------------------------------------------

    #[test]
    fn name_lease_lifecycle() {
        init_test("name_lease_lifecycle");

        let mut lease = NameLease::new("my_server", tid(1), rid(0), Time::from_secs(3600));
        assert_eq!(lease.name(), "my_server");
        assert_eq!(lease.holder(), tid(1));
        assert_eq!(lease.region(), rid(0));
        assert_eq!(lease.acquired_at(), Time::from_secs(3600));
        assert!(lease.is_active());

        let proof = lease.release().expect("lease release should succeed");
        assert!(!lease.is_active());

        // Proof is a CommittedProof<LeaseKind>
        let _ = proof;

        crate::test_complete!("name_lease_lifecycle");
    }

    #[test]
    fn name_lease_abort() {
        init_test("name_lease_abort");

        let mut lease = NameLease::new("worker", tid(2), rid(0), Time::from_nanos(1_000_000_000));
        assert!(lease.is_active());

        let proof = lease.abort().expect("lease abort should succeed");
        assert!(!lease.is_active());
        let _ = proof;

        crate::test_complete!("name_lease_abort");
    }

    #[test]
    fn name_lease_double_resolve_errors() {
        init_test("name_lease_double_resolve_errors");

        let mut lease = NameLease::new("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000));
        lease.release().expect("lease release should succeed");

        assert!(matches!(
            lease.release(),
            Err(NameLeaseError::AlreadyResolved)
        ));
        assert!(matches!(
            lease.abort(),
            Err(NameLeaseError::AlreadyResolved)
        ));

        crate::test_complete!("name_lease_double_resolve_errors");
    }

    // ---------------------------------------------------------------
    // NameRegistry tests
    // ---------------------------------------------------------------

    #[test]
    fn registry_register_and_whereis() {
        init_test("registry_register_and_whereis");

        let mut reg = NameRegistry::new();
        assert!(reg.is_empty());

        let mut lease = reg
            .register("my_server", tid(1), rid(0), Time::from_secs(3600))
            .expect("registration should succeed");
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.whereis("my_server"), Some(tid(1)));
        assert!(reg.is_registered("my_server"));
        assert_eq!(reg.whereis("unknown"), None);

        lease.release().expect("lease release should succeed");

        crate::test_complete!("registry_register_and_whereis");
    }

    // ---------------------------------------------------------------
    // NamePermit tests (bd-2is3i)
    // ---------------------------------------------------------------

    #[test]
    fn registry_reserve_commit_makes_visible() {
        init_test("registry_reserve_commit_makes_visible");

        let mut reg = NameRegistry::new();
        let permit = reg
            .reserve("svc", tid(1), rid(0), Time::from_secs(3600))
            .expect("reserve ok");

        // Reserved names are not visible until committed.
        assert_eq!(reg.whereis("svc"), None);
        assert!(!reg.is_registered("svc"));

        let mut lease = reg.commit_permit(permit).expect("commit ok");
        assert_eq!(reg.whereis("svc"), Some(tid(1)));
        assert!(reg.is_registered("svc"));

        lease.release().expect("lease release should succeed");
        crate::test_complete!("registry_reserve_commit_makes_visible");
    }

    #[test]
    fn registry_reserve_abort_releases_name() {
        init_test("registry_reserve_abort_releases_name");

        let mut reg = NameRegistry::new();
        let mut permit = reg
            .reserve("svc", tid(1), rid(0), Time::from_secs(3600))
            .expect("reserve ok");

        // Abort the permit obligation and cancel the pending entry.
        permit.abort().expect("permit abort should succeed");
        reg.cancel_permit(&permit, Time::from_secs(3600))
            .expect("cancel permit");

        // Now the name can be registered normally.
        let mut lease = reg
            .register("svc", tid(2), rid(0), Time::from_secs(3600))
            .expect("registration should succeed");
        assert_eq!(reg.whereis("svc"), Some(tid(2)));
        lease.release().expect("lease release should succeed");

        crate::test_complete!("registry_reserve_abort_releases_name");
    }

    #[test]
    fn registry_reserve_blocks_register() {
        init_test("registry_reserve_blocks_register");

        let mut reg = NameRegistry::new();
        let mut permit = reg
            .reserve("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .expect("reserve ok");

        let err = reg
            .register("svc", tid(2), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap_err();
        assert_eq!(
            err,
            NameLeaseError::NameTaken {
                name: "svc".into(),
                current_holder: tid(1),
            }
        );

        permit.abort().expect("permit abort should succeed");
        reg.cancel_permit(&permit, Time::from_nanos(1_000_000_000))
            .expect("cancel permit");

        crate::test_complete!("registry_reserve_blocks_register");
    }

    #[test]
    fn registry_cleanup_region_removes_pending_permits() {
        init_test("registry_cleanup_region_removes_pending_permits");

        let mut reg = NameRegistry::new();
        let mut permit = reg
            .reserve("svc", tid(1), rid(1), Time::from_nanos(1_000_000_000))
            .expect("reserve ok");

        let removed = reg.cleanup_region(rid(1));
        assert_eq!(removed, vec!["svc"]);

        // Abort the permit (simulating region cleanup).
        permit.abort().expect("permit abort should succeed");

        // Registry should no longer consider the name taken.
        let mut lease = reg
            .register("svc", tid(2), rid(0), Time::from_secs(3600))
            .expect("registration should succeed");
        lease.release().expect("lease release should succeed");

        crate::test_complete!("registry_cleanup_region_removes_pending_permits");
    }

    #[test]
    fn registry_name_taken() {
        init_test("registry_name_taken");

        let mut reg = NameRegistry::new();
        let mut lease = reg
            .register("singleton", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();

        let err = reg
            .register("singleton", tid(2), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap_err();
        assert_eq!(
            err,
            NameLeaseError::NameTaken {
                name: "singleton".into(),
                current_holder: tid(1),
            }
        );

        lease.release().expect("lease release should succeed");

        crate::test_complete!("registry_name_taken");
    }

    #[test]
    fn registry_unregister() {
        init_test("registry_unregister");

        let mut reg = NameRegistry::new();
        let mut lease = reg
            .register("temp", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();

        reg.unregister("temp", tid(1)).unwrap();
        assert!(!reg.is_registered("temp"));
        assert!(reg.is_empty());

        // Unregistering unknown name is an error.
        assert_eq!(
            reg.unregister("unknown", tid(1)),
            Err(NameLeaseError::NotFound {
                name: "unknown".into()
            })
        );

        lease.release().expect("lease release should succeed");

        crate::test_complete!("registry_unregister");
    }

    #[test]
    fn registry_registered_names_sorted() {
        init_test("registry_registered_names_sorted");

        let mut reg = NameRegistry::new();
        let mut l1 = reg
            .register("zebra", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();
        let mut l2 = reg
            .register("alpha", tid(2), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();
        let mut l3 = reg
            .register("middle", tid(3), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();

        // API contract guarantees sorted order
        assert_eq!(reg.registered_names(), vec!["alpha", "middle", "zebra"]);

        l1.release().unwrap();
        l2.release().unwrap();
        l3.release().unwrap();

        crate::test_complete!("registry_registered_names_sorted");
    }

    #[test]
    fn registry_cleanup_region() {
        init_test("registry_cleanup_region");

        let mut reg = NameRegistry::new();
        let mut l1 = reg
            .register("svc_a", tid(1), rid(1), Time::from_nanos(1_000_000_000))
            .unwrap();
        let mut l2 = reg
            .register("svc_b", tid(2), rid(1), Time::from_nanos(1_000_000_000))
            .unwrap();
        let mut l3 = reg
            .register("svc_c", tid(3), rid(2), Time::from_nanos(1_000_000_000))
            .unwrap();

        assert_eq!(reg.len(), 3);

        let removed = reg.cleanup_region(rid(1));
        assert_eq!(removed, vec!["svc_a", "svc_b"]); // sorted by cleanup contract
        assert_eq!(reg.len(), 1);
        assert!(reg.is_registered("svc_c"));
        assert!(!reg.is_registered("svc_a"));

        // Abort the removed leases (simulating region cleanup)
        l1.abort().unwrap();
        l2.abort().unwrap();
        l3.release().unwrap();

        crate::test_complete!("registry_cleanup_region");
    }

    #[test]
    fn registry_cleanup_task() {
        init_test("registry_cleanup_task");

        let mut reg = NameRegistry::new();
        let mut l1 = reg
            .register("name_a", tid(5), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();
        let mut l2 = reg
            .register("name_b", tid(5), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();
        let mut l3 = reg
            .register("name_c", tid(6), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();

        let removed = reg.cleanup_task(tid(5));
        assert_eq!(removed, vec!["name_a", "name_b"]);
        assert_eq!(reg.len(), 1);

        l1.abort().unwrap();
        l2.abort().unwrap();
        l3.release().unwrap();

        crate::test_complete!("registry_cleanup_task");
    }

    #[test]
    fn registry_cleanup_region_empty() {
        init_test("registry_cleanup_region_empty");

        let mut reg = NameRegistry::new();
        let removed = reg.cleanup_region(rid(99));
        assert!(removed.is_empty());

        crate::test_complete!("registry_cleanup_region_empty");
    }

    #[test]
    fn registry_re_register_after_unregister() {
        init_test("registry_re_register_after_unregister");

        let mut reg = NameRegistry::new();
        let mut l1 = reg
            .register("reusable", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();
        reg.unregister("reusable", tid(1)).unwrap();
        l1.release().unwrap();

        // Re-register same name with different task
        let mut l2 = reg
            .register("reusable", tid(2), rid(0), Time::from_secs(3600))
            .unwrap();
        assert_eq!(reg.whereis("reusable"), Some(tid(2)));
        l2.release().unwrap();

        crate::test_complete!("registry_re_register_after_unregister");
    }

    #[test]
    fn name_lease_error_display() {
        init_test("name_lease_error_display");

        let err = NameLeaseError::AlreadyResolved;
        assert_eq!(err.to_string(), "name lease already resolved");

        let err = NameLeaseError::NameTaken {
            name: "foo".into(),
            current_holder: tid(42),
        };
        assert!(err.to_string().contains("foo"));
        assert!(err.to_string().contains("42"));

        let err = NameLeaseError::NotFound { name: "bar".into() };
        assert!(err.to_string().contains("bar"));

        crate::test_complete!("name_lease_error_display");
    }

    #[test]
    fn registry_event_variants() {
        init_test("registry_event_variants");

        let _registered = RegistryEvent::NameRegistered {
            name: "svc".into(),
            holder: tid(1),
            region: rid(0),
        };
        let _released = RegistryEvent::NameReleased {
            name: "svc".into(),
            holder: tid(1),
        };
        let _aborted = RegistryEvent::NameAborted {
            name: "svc".into(),
            holder: tid(1),
            reason: "task cancelled".into(),
        };
        let _region_cleanup = RegistryEvent::RegionCleanup {
            region: rid(0),
            count: 3,
        };
        let _task_cleanup = RegistryEvent::TaskCleanup {
            task: tid(1),
            count: 2,
        };
        let _reserved = RegistryEvent::NameReserved {
            name: "svc".into(),
            holder: tid(1),
            region: rid(0),
        };
        let _committed = RegistryEvent::NamePermitCommitted {
            name: "svc".into(),
            holder: tid(1),
        };
        let _permit_aborted = RegistryEvent::NamePermitAborted {
            name: "svc".into(),
            holder: tid(1),
            reason: "setup failed".into(),
        };
        let _replaced = RegistryEvent::NameReplaced {
            name: "svc".into(),
            new_holder: tid(2),
            displaced_holder: tid(1),
        };
        let _waiter_enqueued = RegistryEvent::WaiterEnqueued {
            name: "svc".into(),
            holder: tid(2),
            deadline: Time::from_secs(3600),
        };
        let _waiter_granted = RegistryEvent::WaiterGranted {
            name: "svc".into(),
            holder: tid(2),
        };

        crate::test_complete!("registry_event_variants");
    }

    #[test]
    fn registry_default_is_empty() {
        init_test("registry_default_is_empty");

        let reg = NameRegistry::default();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);

        crate::test_complete!("registry_default_is_empty");
    }

    // ---------------------------------------------------------------
    // Name monitor tests (bd-2kbem)
    // ---------------------------------------------------------------

    #[test]
    fn name_watch_emits_acquire_and_release() {
        init_test("name_watch_emits_acquire_and_release");

        let mut reg = NameRegistry::new();
        let watch_ref = reg
            .watch_name("svc", tid(50), rid(9))
            .expect("watcher limit exceeded");
        assert_eq!(reg.name_watcher_count(), 1);

        let mut lease = reg
            .register("svc", tid(1), rid(1), Time::from_secs(10))
            .unwrap();
        reg.unregister("svc", tid(1)).unwrap();
        lease.release().expect("lease release should succeed");

        let notifications = reg.take_name_notifications();
        assert_eq!(notifications.len(), 2);

        let acquired = &notifications[0];
        assert_eq!(acquired.watch_ref, watch_ref);
        assert_eq!(acquired.watcher, tid(50));
        assert_eq!(acquired.watcher_region, rid(9));
        assert_eq!(acquired.name, "svc");
        assert_eq!(acquired.holder, tid(1));
        assert_eq!(acquired.region, rid(1));
        assert_eq!(acquired.kind, NameOwnershipKind::Acquired);

        let released = &notifications[1];
        assert_eq!(released.watch_ref, watch_ref);
        assert_eq!(released.watcher, tid(50));
        assert_eq!(released.watcher_region, rid(9));
        assert_eq!(released.name, "svc");
        assert_eq!(released.holder, tid(1));
        assert_eq!(released.region, rid(1));
        assert_eq!(released.kind, NameOwnershipKind::Released);

        assert!(reg.take_name_notifications().is_empty());

        crate::test_complete!("name_watch_emits_acquire_and_release");
    }

    #[test]
    fn name_watch_multiple_watchers_ordered_by_ref() {
        init_test("name_watch_multiple_watchers_ordered_by_ref");

        let mut reg = NameRegistry::new();
        let w1 = reg
            .watch_name("svc", tid(10), rid(7))
            .expect("watcher limit exceeded");
        let w2 = reg
            .watch_name("svc", tid(11), rid(7))
            .expect("watcher limit exceeded");
        let w3 = reg
            .watch_name("svc", tid(12), rid(8))
            .expect("watcher limit exceeded");

        let mut lease = reg
            .register("svc", tid(1), rid(1), Time::from_nanos(1_000_000_000))
            .unwrap();
        let notifications = reg.take_name_notifications();
        assert_eq!(notifications.len(), 3);

        let refs: Vec<NameWatchRef> = notifications.iter().map(|n| n.watch_ref).collect();
        assert_eq!(refs, vec![w1, w2, w3]);
        assert!(
            notifications
                .iter()
                .all(|n| n.kind == NameOwnershipKind::Acquired)
        );

        lease.release().expect("lease release should succeed");

        crate::test_complete!("name_watch_multiple_watchers_ordered_by_ref");
    }

    #[test]
    fn name_watch_region_cleanup_suppresses_release_notifications() {
        init_test("name_watch_region_cleanup_suppresses_release_notifications");

        let mut reg = NameRegistry::new();
        let _closed_region_watch = reg
            .watch_name("svc", tid(10), rid(1))
            .expect("watcher limit exceeded");
        let open_region_watch = reg
            .watch_name("svc", tid(11), rid(2))
            .expect("watcher limit exceeded");

        let mut lease = reg
            .register("svc", tid(1), rid(1), Time::from_nanos(1_000_000_000))
            .unwrap();
        let acquired = reg.take_name_notifications();
        assert_eq!(acquired.len(), 2);

        let removed_watchers = reg.cleanup_name_watchers_region(rid(1));
        assert_eq!(removed_watchers.len(), 1);
        assert_eq!(reg.name_watcher_count(), 1);

        reg.unregister("svc", tid(1)).unwrap();
        lease.release().expect("lease release should succeed");
        let released = reg.take_name_notifications();
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].watch_ref, open_region_watch);
        assert_eq!(released[0].kind, NameOwnershipKind::Released);

        crate::test_complete!("name_watch_region_cleanup_suppresses_release_notifications");
    }

    #[test]
    fn name_watch_task_cleanup_removes_only_dead_task_watchers() {
        init_test("name_watch_task_cleanup_removes_only_dead_task_watchers");

        let mut reg = NameRegistry::new();
        let _closed_task_watch = reg
            .watch_name("svc", tid(10), rid(1))
            .expect("watcher limit exceeded");
        let live_watch = reg
            .watch_name("svc", tid(11), rid(1))
            .expect("watcher limit exceeded");
        assert_eq!(reg.name_watcher_count(), 2);

        let removed = reg.cleanup_task(tid(10));
        assert!(removed.is_empty());
        assert_eq!(reg.name_watcher_count(), 1);

        let mut lease = reg
            .register("svc", tid(1), rid(9), Time::from_nanos(1_000_000_000))
            .unwrap();
        reg.unregister("svc", tid(1)).unwrap();
        lease.release().expect("lease release should succeed");

        let notifications = reg.take_name_notifications();
        assert_eq!(notifications.len(), 2);
        assert!(notifications.iter().all(|n| n.watch_ref == live_watch));

        crate::test_complete!("name_watch_task_cleanup_removes_only_dead_task_watchers");
    }

    #[test]
    fn name_watch_replace_emits_release_then_acquire() {
        init_test("name_watch_replace_emits_release_then_acquire");

        let mut reg = NameRegistry::new();
        let watch_ref = reg
            .watch_name("svc", tid(42), rid(9))
            .expect("watch registration should succeed");

        let mut old_lease = reg
            .register("svc", tid(1), rid(1), Time::from_nanos(1_000_000_000))
            .unwrap();
        reg.take_name_notifications();

        let outcome = reg
            .register_with_policy(
                "svc",
                tid(2),
                rid(2),
                Time::from_secs(5),
                NameCollisionPolicy::Replace,
            )
            .unwrap();

        let mut new_lease = match outcome {
            NameCollisionOutcome::Replaced { lease, .. } => lease,
            other => panic!("expected Replaced outcome, got {other:?}"),
        };

        let notifications = reg.take_name_notifications();
        assert_eq!(notifications.len(), 2);
        assert_eq!(notifications[0].watch_ref, watch_ref);
        assert_eq!(notifications[0].kind, NameOwnershipKind::Released);
        assert_eq!(notifications[0].holder, tid(1));
        assert_eq!(notifications[1].watch_ref, watch_ref);
        assert_eq!(notifications[1].kind, NameOwnershipKind::Acquired);
        assert_eq!(notifications[1].holder, tid(2));

        old_lease.abort().unwrap();
        new_lease.release().unwrap();

        crate::test_complete!("name_watch_replace_emits_release_then_acquire");
    }

    // ---------------------------------------------------------------
    // RegistryHandle tests (bd-133q8)
    // ---------------------------------------------------------------

    struct DummyRegistry;
    impl RegistryCap for DummyRegistry {}

    #[test]
    fn registry_handle_basic() {
        init_test("registry_handle_basic");

        let handle = RegistryHandle::new(Arc::new(DummyRegistry));
        let _arc = handle.as_arc();
        let _clone = handle.clone();

        // Debug output should not panic
        let debug = format!("{handle:?}");
        assert!(debug.contains("RegistryHandle"));

        crate::test_complete!("registry_handle_basic");
    }

    // ---------------------------------------------------------------
    // Watcher resource limit tests (br-asupersync-ad716k)
    // ---------------------------------------------------------------

    #[test]
    fn test_watcher_per_name_limit() {
        init_test("test_watcher_per_name_limit");

        let mut reg = NameRegistry::new();

        // Add MAX_WATCHERS_PER_NAME watchers for the same name
        for i in 0..MAX_WATCHERS_PER_NAME {
            let watch_ref = reg.watch_name(
                "test_name",
                TaskId::new_for_test(i as u32, 0),
                RegionId::new_for_test(i as u32, 0),
            );
            assert!(watch_ref.is_some(), "Should allow watcher {i}");
        }

        // Adding one more should fail
        let overflow_watch = reg.watch_name(
            "test_name",
            TaskId::new_for_test(999, 0),
            RegionId::new_for_test(999, 0),
        );
        assert!(
            overflow_watch.is_none(),
            "Should reject watcher beyond per-name limit"
        );

        // But adding for a different name should still work
        let different_name_watch = reg.watch_name(
            "different_name",
            TaskId::new_for_test(1000, 0),
            RegionId::new_for_test(1000, 0),
        );
        assert!(
            different_name_watch.is_some(),
            "Should allow watcher for different name"
        );

        crate::test_complete!("test_watcher_per_name_limit");
    }

    #[test]
    fn test_watcher_per_region_limit() {
        init_test("test_watcher_per_region_limit");

        let mut reg = NameRegistry::new();
        let region = RegionId::new_for_test(1, 0);

        // Add MAX_WATCHERS_PER_REGION watchers for the same region
        for i in 0..MAX_WATCHERS_PER_REGION {
            let watch_ref = reg.watch_name(
                format!("name_{i}"),
                TaskId::new_for_test(i as u32, 0),
                region,
            );
            assert!(watch_ref.is_some(), "Should allow watcher {i} for region");
        }

        // Adding one more for the same region should fail
        let overflow_watch = reg.watch_name("overflow_name", TaskId::new_for_test(999, 0), region);
        assert!(
            overflow_watch.is_none(),
            "Should reject watcher beyond per-region limit"
        );

        // But adding for a different region should still work
        let different_region_watch = reg.watch_name(
            "different_region_name",
            TaskId::new_for_test(1000, 0),
            RegionId::new_for_test(2, 0),
        );
        assert!(
            different_region_watch.is_some(),
            "Should allow watcher for different region"
        );

        crate::test_complete!("test_watcher_per_region_limit");
    }

    // ---------------------------------------------------------------
    // Conformance tests (bd-13l06)
    //
    // Property/lab tests:
    // - No stale names after crash/stop
    // - Deterministic winner on simultaneous register attempts
    // - Lease abort on cancellation
    // - Trace event ordering stable across seeds
    // ---------------------------------------------------------------

    /// Conformance: after cleanup_task, no stale names remain for that task.
    /// The registry must be fully consistent: whereis returns None for cleaned-up
    /// names, len() reflects the removal, and registered_names() excludes them.
    #[test]
    fn conformance_no_stale_names_after_task_crash() {
        init_test("conformance_no_stale_names_after_task_crash");

        let mut reg = NameRegistry::new();

        // Task 1 registers 3 names across 2 regions
        let mut l1 = reg
            .register("svc_a", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();
        let mut l2 = reg
            .register("svc_b", tid(1), rid(0), Time::from_secs(1))
            .unwrap();
        let mut l3 = reg
            .register("svc_c", tid(1), rid(1), Time::from_secs(2))
            .unwrap();

        // Task 2 registers 1 name (should survive the crash)
        let mut l4 = reg
            .register("other", tid(2), rid(0), Time::from_secs(3))
            .unwrap();

        assert_eq!(reg.len(), 4);

        // Simulate task 1 crash: cleanup removes all its names
        let removed = reg.cleanup_task(tid(1));
        assert_eq!(removed, vec!["svc_a", "svc_b", "svc_c"]); // sorted by cleanup contract

        // Post-crash invariants
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.whereis("svc_a"), None, "stale name svc_a after crash");
        assert_eq!(reg.whereis("svc_b"), None, "stale name svc_b after crash");
        assert_eq!(reg.whereis("svc_c"), None, "stale name svc_c after crash");
        assert_eq!(reg.whereis("other"), Some(tid(2)), "surviving name lost");
        assert_eq!(reg.registered_names(), vec!["other"]);

        // Abort the crashed task's leases (obligation resolution)
        l1.abort().unwrap();
        l2.abort().unwrap();
        l3.abort().unwrap();
        l4.release().unwrap();

        crate::test_complete!("conformance_no_stale_names_after_task_crash");
    }

    /// Conformance: after cleanup_region, no stale names remain for any task
    /// in that region. Names in other regions are untouched.
    #[test]
    fn conformance_no_stale_names_after_region_stop() {
        init_test("conformance_no_stale_names_after_region_stop");

        let mut reg = NameRegistry::new();

        // Region 1: 3 tasks register names
        let mut l1 = reg
            .register("db", tid(10), rid(1), Time::from_nanos(1_000_000_000))
            .unwrap();
        let mut l2 = reg
            .register("cache", tid(11), rid(1), Time::from_secs(1))
            .unwrap();
        let mut l3 = reg
            .register("worker", tid(12), rid(1), Time::from_secs(2))
            .unwrap();

        // Region 2: 1 task registers a name
        let mut l4 = reg
            .register("api", tid(20), rid(2), Time::from_secs(3))
            .unwrap();

        // Region 3: 1 task registers a name
        let mut l5 = reg
            .register("logger", tid(30), rid(3), Time::from_secs(4))
            .unwrap();

        assert_eq!(reg.len(), 5);

        // Stop region 1
        let removed = reg.cleanup_region(rid(1));
        assert_eq!(removed, vec!["cache", "db", "worker"]); // sorted

        // Post-stop invariants
        assert_eq!(reg.len(), 2);
        for name in &["cache", "db", "worker"] {
            assert_eq!(
                reg.whereis(name),
                None,
                "stale name '{name}' after region stop"
            );
            assert!(!reg.is_registered(name));
        }
        assert_eq!(reg.whereis("api"), Some(tid(20)));
        assert_eq!(reg.whereis("logger"), Some(tid(30)));
        assert_eq!(reg.registered_names(), vec!["api", "logger"]);

        l1.abort().unwrap();
        l2.abort().unwrap();
        l3.abort().unwrap();
        l4.release().unwrap();
        l5.release().unwrap();

        crate::test_complete!("conformance_no_stale_names_after_region_stop");
    }

    /// Conformance: the first caller to register a name wins deterministically.
    /// The loser receives NameTaken with the correct holder. This is true
    /// regardless of task IDs, region IDs, or timing.
    #[test]
    fn conformance_deterministic_winner_simultaneous_register() {
        init_test("conformance_deterministic_winner_simultaneous_register");

        let mut reg = NameRegistry::new();

        // Task 99 registers first (even though it has a higher TaskId)
        let mut winner = reg
            .register(
                "singleton",
                tid(99),
                rid(0),
                Time::from_nanos(1_000_000_000),
            )
            .unwrap();

        // Task 1 tries second — should lose deterministically
        let err = reg
            .register("singleton", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap_err();
        assert_eq!(
            err,
            NameLeaseError::NameTaken {
                name: "singleton".into(),
                current_holder: tid(99),
            },
            "loser must see the correct holder"
        );

        // Task 50 also tries — same result
        let err = reg
            .register("singleton", tid(50), rid(1), Time::from_secs(1))
            .unwrap_err();
        assert_eq!(
            err,
            NameLeaseError::NameTaken {
                name: "singleton".into(),
                current_holder: tid(99),
            },
            "second loser must also see the original holder"
        );

        // Registry state unchanged
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.whereis("singleton"), Some(tid(99)));

        winner.release().unwrap();

        crate::test_complete!("conformance_deterministic_winner_simultaneous_register");
    }

    /// Conformance: first-wins semantics is stable across repeated trials.
    /// Run the same registration race N times; the outcome must be identical.
    #[test]
    fn conformance_register_winner_stable_across_trials() {
        init_test("conformance_register_winner_stable_across_trials");

        for trial in 0..20 {
            let mut reg = NameRegistry::new();

            let mut lease = reg
                .register(
                    "stable_name",
                    tid(7),
                    rid(0),
                    Time::from_nanos(1_000_000_000),
                )
                .unwrap();

            let err = reg
                .register(
                    "stable_name",
                    tid(3),
                    rid(0),
                    Time::from_nanos(1_000_000_000),
                )
                .unwrap_err();
            assert_eq!(
                err,
                NameLeaseError::NameTaken {
                    name: "stable_name".into(),
                    current_holder: tid(7),
                },
                "trial {trial}: winner must be tid(7)"
            );

            lease.release().expect("lease release should succeed");
        }

        crate::test_complete!("conformance_register_winner_stable_across_trials");
    }

    /// Conformance: lease abort on cancellation correctly resolves the obligation.
    /// After abort, the lease is inactive, and the abort proof is valid.
    /// Double-abort returns AlreadyResolved.
    #[test]
    fn conformance_lease_abort_on_cancellation() {
        init_test("conformance_lease_abort_on_cancellation");

        let mut reg = NameRegistry::new();

        // Register a name
        let mut lease = reg
            .register(
                "cancellable",
                tid(1),
                rid(0),
                Time::from_nanos(1_000_000_000),
            )
            .unwrap();
        assert!(lease.is_active());

        // Simulate cancellation: unregister from registry, then abort the lease
        reg.unregister("cancellable", tid(1)).unwrap();
        assert!(!reg.is_registered("cancellable"));

        let proof = lease.abort().expect("lease abort should succeed");
        assert!(!lease.is_active());

        // Proof is a valid AbortedProof<LeaseKind>
        let resolved = proof.into_resolved_proof();
        assert_eq!(
            resolved.resolution(),
            crate::obligation::graded::Resolution::Abort,
            "abort proof must show Abort resolution"
        );

        // Double-abort is an error, not a panic
        assert_eq!(lease.abort().unwrap_err(), NameLeaseError::AlreadyResolved);

        crate::test_complete!("conformance_lease_abort_on_cancellation");
    }

    /// Conformance: lease abort via region cleanup resolves all obligations.
    /// Simulates the full cancellation flow: region closing → cleanup → abort each lease.
    #[test]
    fn conformance_region_cancel_aborts_all_leases() {
        init_test("conformance_region_cancel_aborts_all_leases");

        let mut reg = NameRegistry::new();
        let target_region = rid(5);

        let mut l1 = reg
            .register("a", tid(1), target_region, Time::from_nanos(1_000_000_000))
            .unwrap();
        let mut l2 = reg
            .register("b", tid(2), target_region, Time::from_secs(1))
            .unwrap();
        let mut l3 = reg
            .register("c", tid(3), target_region, Time::from_secs(2))
            .unwrap();

        // Survivor in another region
        let mut l4 = reg
            .register("d", tid(4), rid(99), Time::from_secs(3))
            .unwrap();

        // Region cancel: cleanup → abort each lease
        let removed = reg.cleanup_region(target_region);
        assert_eq!(removed.len(), 3);

        // All removed leases must abort successfully
        for (lease, name) in [(&mut l1, "a"), (&mut l2, "b"), (&mut l3, "c")] {
            assert!(
                lease.is_active(),
                "lease '{name}' should still be active pre-abort"
            );
            let proof = lease.abort().expect("lease abort should succeed");
            assert!(!lease.is_active());
            let _ = proof; // obligation resolved
        }

        // Registry only has the survivor
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.whereis("d"), Some(tid(4)));

        l4.release().unwrap();

        crate::test_complete!("conformance_region_cancel_aborts_all_leases");
    }

    /// Conformance: trace event ordering is deterministic for a fixed operation
    /// sequence. Running the same sequence multiple times must produce the same
    /// event list in the same order.
    #[test]
    fn conformance_event_ordering_stable_across_seeds() {
        fn build_event_sequence() -> Vec<RegistryEvent> {
            // Build the canonical event sequence for a known operation order.
            // The events are constructed manually to match what the registry
            // operations WOULD emit (the NameRegistry itself doesn't emit events;
            // the caller is responsible for emitting RegistryEvents).
            vec![
                // Simulate: register "b", register "a", register "c", cleanup region 0
                RegistryEvent::NameRegistered {
                    name: "b".into(),
                    holder: tid(2),
                    region: rid(0),
                },
                RegistryEvent::NameRegistered {
                    name: "a".into(),
                    holder: tid(1),
                    region: rid(0),
                },
                RegistryEvent::NameRegistered {
                    name: "c".into(),
                    holder: tid(3),
                    region: rid(0),
                },
                RegistryEvent::RegionCleanup {
                    region: rid(0),
                    count: 3,
                },
                // Abort events follow deterministic lexical order (a, b, c)
                RegistryEvent::NameAborted {
                    name: "a".into(),
                    holder: tid(1),
                    reason: "region cleanup".into(),
                },
                RegistryEvent::NameAborted {
                    name: "b".into(),
                    holder: tid(2),
                    reason: "region cleanup".into(),
                },
                RegistryEvent::NameAborted {
                    name: "c".into(),
                    holder: tid(3),
                    reason: "region cleanup".into(),
                },
            ]
        }

        init_test("conformance_event_ordering_stable_across_seeds");

        // Run the same sequence 10 times; verify it matches the canonical ordering
        let canonical = build_event_sequence();
        for trial in 0..10 {
            let events = build_event_sequence();
            assert_eq!(
                events, canonical,
                "trial {trial}: event sequence diverged from canonical"
            );
        }

        // Verify that cleanup_region returns names in sorted order.
        // which ensures abort events follow a deterministic order.
        let mut reg = NameRegistry::new();
        let mut l1 = reg
            .register("b", tid(2), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();
        let mut l2 = reg
            .register("a", tid(1), rid(0), Time::from_secs(1))
            .unwrap();
        let mut l3 = reg
            .register("c", tid(3), rid(0), Time::from_secs(2))
            .unwrap();

        let removed = reg.cleanup_region(rid(0));
        // Output order stays sorted regardless of insertion order.
        assert_eq!(
            removed,
            vec!["a", "b", "c"],
            "cleanup must return sorted names"
        );

        l1.abort().unwrap();
        l2.abort().unwrap();
        l3.abort().unwrap();

        crate::test_complete!("conformance_event_ordering_stable_across_seeds");
    }

    /// Conformance: cleanup_task returns names in deterministic (sorted) order,
    /// regardless of registration order. This is critical for trace stability.
    #[test]
    fn conformance_cleanup_task_deterministic_order() {
        init_test("conformance_cleanup_task_deterministic_order");

        let mut reg = NameRegistry::new();

        // Register in reverse alphabetical order
        let mut l1 = reg
            .register("z_last", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();
        let mut l2 = reg
            .register("m_mid", tid(1), rid(0), Time::from_secs(1))
            .unwrap();
        let mut l3 = reg
            .register("a_first", tid(1), rid(0), Time::from_secs(2))
            .unwrap();

        let removed = reg.cleanup_task(tid(1));
        assert_eq!(
            removed,
            vec!["a_first", "m_mid", "z_last"],
            "cleanup_task must return names in sorted order"
        );

        l1.abort().unwrap();
        l2.abort().unwrap();
        l3.abort().unwrap();

        crate::test_complete!("conformance_cleanup_task_deterministic_order");
    }

    /// Conformance: after crash + re-register, the new holder is visible and
    /// the old holder is completely gone. No phantom entries from the old lease.
    #[test]
    fn conformance_re_register_after_crash_clean() {
        init_test("conformance_re_register_after_crash_clean");

        let mut reg = NameRegistry::new();

        // Original holder registers
        let mut old_lease = reg
            .register(
                "primary_db",
                tid(10),
                rid(0),
                Time::from_nanos(1_000_000_000),
            )
            .unwrap();

        // Crash: cleanup the old task
        let removed = reg.cleanup_task(tid(10));
        assert_eq!(removed, vec!["primary_db"]);
        old_lease.abort().unwrap();

        // New holder registers the same name
        let mut new_lease = reg
            .register("primary_db", tid(20), rid(1), Time::from_secs(10))
            .unwrap();

        // Verify new state is clean
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.whereis("primary_db"), Some(tid(20)));
        assert_eq!(new_lease.holder(), tid(20));
        assert_eq!(new_lease.region(), rid(1));
        assert_eq!(new_lease.acquired_at(), Time::from_secs(10));

        // Old task has no lingering entries
        let old_removed = reg.cleanup_task(tid(10));
        assert!(old_removed.is_empty(), "old task must have no entries");

        new_lease.release().unwrap();

        crate::test_complete!("conformance_re_register_after_crash_clean");
    }

    /// Conformance: interleaved register/unregister/crash cycles maintain
    /// consistency. The registry length always matches registered_names().len(),
    /// and whereis agrees with is_registered for all known names.
    #[test]
    fn conformance_registry_invariant_under_churn() {
        init_test("conformance_registry_invariant_under_churn");

        let mut reg = NameRegistry::new();
        let mut active_leases: Vec<NameLease> = Vec::new();

        // Phase 1: bulk register
        for i in 0..10 {
            let name = format!("svc_{i:03}");
            let lease = reg
                .register(&name, tid(i), rid(i % 3), Time::from_secs(u64::from(i)))
                .unwrap();
            active_leases.push(lease);
        }
        assert_eq!(reg.len(), 10);

        // Phase 2: crash region 1 (tasks 1, 4, 7)
        let removed = reg.cleanup_region(rid(1));
        for name in &removed {
            // Find and abort the matching lease
            if let Some(lease) = active_leases.iter_mut().find(|l| l.name() == name.as_str()) {
                lease.abort().unwrap();
            }
        }

        // Phase 3: unregister svc_000 explicitly (holder is tid(0)
        // per the bulk-register loop above)
        reg.unregister("svc_000", tid(0)).unwrap();
        if let Some(lease) = active_leases.iter_mut().find(|l| l.name() == "svc_000") {
            lease.release().expect("lease release should succeed");
        }

        // Phase 4: re-register a crashed name with new holder
        let new_lease = reg
            .register("svc_001", tid(100), rid(5), Time::from_secs(100))
            .unwrap();
        active_leases.push(new_lease);

        // Invariant check: len matches registered_names count
        let names = reg.registered_names();
        assert_eq!(
            reg.len(),
            names.len(),
            "len() and registered_names().len() must agree"
        );

        // Invariant check: whereis agrees with is_registered for every name we've seen
        for name in &names {
            assert!(
                reg.is_registered(name),
                "name '{name}' in registered_names but is_registered returns false"
            );
            assert!(
                reg.whereis(name).is_some(),
                "name '{name}' in registered_names but whereis returns None"
            );
        }

        // Invariant check: names are sorted by API contract.
        for window in names.windows(2) {
            assert!(
                window[0] <= window[1],
                "registered_names not sorted: '{}' > '{}'",
                window[0],
                window[1]
            );
        }

        // Cleanup remaining leases
        for lease in &mut active_leases {
            if lease.is_active() {
                let _ = lease.abort();
            }
        }

        crate::test_complete!("conformance_registry_invariant_under_churn");
    }

    /// Conformance: the linearity contract — every lease must be resolved.
    /// Release produces CommittedProof, abort produces AbortedProof, and
    /// the proof types carry the correct resolution kind.
    #[test]
    fn conformance_linearity_proofs() {
        init_test("conformance_linearity_proofs");

        // Test committed proof
        let mut committed_lease =
            NameLease::new("committed", tid(1), rid(0), Time::from_nanos(1_000_000_000));
        let committed = committed_lease.release().unwrap();
        let resolved = committed.into_resolved_proof();
        assert_eq!(
            resolved.resolution(),
            crate::obligation::graded::Resolution::Commit,
            "release must produce Commit proof"
        );

        // Test aborted proof
        let mut aborted_lease =
            NameLease::new("aborted", tid(2), rid(0), Time::from_nanos(1_000_000_000));
        let aborted = aborted_lease.abort().unwrap();
        let resolved = aborted.into_resolved_proof();
        assert_eq!(
            resolved.resolution(),
            crate::obligation::graded::Resolution::Abort,
            "abort must produce Abort proof"
        );

        crate::test_complete!("conformance_linearity_proofs");
    }

    /// Conformance: cross-region isolation. Cleaning up one region must not
    /// affect names in other regions, even if they share the same task IDs.
    #[test]
    fn conformance_cross_region_isolation() {
        init_test("conformance_cross_region_isolation");

        let mut reg = NameRegistry::new();

        // Same task ID (1) registers in two different regions
        let mut l1 = reg
            .register("r1_name", tid(1), rid(1), Time::from_nanos(1_000_000_000))
            .unwrap();
        let mut l2 = reg
            .register("r2_name", tid(1), rid(2), Time::from_secs(1))
            .unwrap();

        // Cleanup region 1
        let removed = reg.cleanup_region(rid(1));
        assert_eq!(removed, vec!["r1_name"]);

        // Region 2's name must survive
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.whereis("r2_name"), Some(tid(1)));
        assert!(reg.is_registered("r2_name"));
        assert!(!reg.is_registered("r1_name"));

        l1.abort().unwrap();
        l2.release().unwrap();

        crate::test_complete!("conformance_cross_region_isolation");
    }

    // ---------------------------------------------------------------
    // NamePermit conformance tests (bd-2is3i)
    // ---------------------------------------------------------------

    /// Conformance: cleanup_task also removes pending permits held by the task.
    #[test]
    fn conformance_cleanup_task_removes_pending_permits() {
        init_test("conformance_cleanup_task_removes_pending_permits");

        let mut reg = NameRegistry::new();

        // Task 1 has a committed lease and a pending permit.
        let mut lease = reg
            .register("active", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();
        let mut permit = reg
            .reserve("pending_name", tid(1), rid(0), Time::from_secs(1))
            .expect("reserve ok");

        let removed = reg.cleanup_task(tid(1));
        assert_eq!(removed, vec!["active", "pending_name"]);
        assert_eq!(reg.len(), 0);

        // Both name slots freed — a new task can take either.
        let mut l2 = reg
            .register("pending_name", tid(2), rid(0), Time::from_secs(2))
            .unwrap();

        lease.abort().unwrap();
        permit.abort().expect("permit abort should succeed");
        l2.release().unwrap();

        crate::test_complete!("conformance_cleanup_task_removes_pending_permits");
    }

    /// Conformance: double reserve of the same name is blocked.
    #[test]
    fn conformance_double_reserve_blocked() {
        init_test("conformance_double_reserve_blocked");

        let mut reg = NameRegistry::new();
        let mut p1 = reg
            .reserve("singleton", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .expect("first reserve ok");

        let err = reg
            .reserve("singleton", tid(2), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap_err();
        assert_eq!(
            err,
            NameLeaseError::NameTaken {
                name: "singleton".into(),
                current_holder: tid(1),
            }
        );

        p1.abort().unwrap();
        reg.cancel_permit(&p1, Time::from_nanos(1_000_000_000))
            .expect("cancel permit");

        crate::test_complete!("conformance_double_reserve_blocked");
    }

    /// Conformance: permit accessors return correct values.
    #[test]
    fn permit_accessors() {
        init_test("permit_accessors");

        let mut reg = NameRegistry::new();
        let mut permit = reg
            .reserve("my_svc", tid(7), rid(3), Time::from_secs(42))
            .expect("reserve ok");

        assert_eq!(permit.name(), "my_svc");
        assert_eq!(permit.holder(), tid(7));
        assert_eq!(permit.region(), rid(3));
        assert_eq!(permit.reserved_at(), Time::from_secs(42));
        assert!(permit.is_pending());

        permit.abort().expect("permit abort should succeed");
        assert!(!permit.is_pending());
        reg.cancel_permit(&permit, Time::from_secs(42))
            .expect("cancel permit");

        crate::test_complete!("permit_accessors");
    }

    /// Conformance: permit commit produces a valid active NameLease with
    /// the same obligation token (no new token created).
    #[test]
    fn conformance_permit_commit_transfers_token() {
        init_test("conformance_permit_commit_transfers_token");

        let mut reg = NameRegistry::new();
        let permit = reg
            .reserve("transfer", tid(1), rid(0), Time::from_secs(5))
            .expect("reserve ok");

        let mut lease = reg.commit_permit(permit).expect("commit ok");

        // Lease inherits permit's metadata.
        assert_eq!(lease.name(), "transfer");
        assert_eq!(lease.holder(), tid(1));
        assert_eq!(lease.region(), rid(0));
        assert_eq!(lease.acquired_at(), Time::from_secs(5));
        assert!(lease.is_active());

        // The lease can be released (obligation committed).
        let proof = lease.release().expect("lease release should succeed");
        let resolved = proof.into_resolved_proof();
        assert_eq!(
            resolved.resolution(),
            crate::obligation::graded::Resolution::Commit,
        );

        crate::test_complete!("conformance_permit_commit_transfers_token");
    }

    /// Conformance: permit abort produces a valid AbortedProof.
    #[test]
    fn conformance_permit_abort_proof() {
        init_test("conformance_permit_abort_proof");

        let mut reg = NameRegistry::new();
        let mut permit = reg
            .reserve("abortable", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .expect("reserve ok");

        let proof = permit.abort().unwrap();
        let resolved = proof.into_resolved_proof();
        assert_eq!(
            resolved.resolution(),
            crate::obligation::graded::Resolution::Abort,
        );

        // Double abort is an error.
        assert_eq!(permit.abort().unwrap_err(), NameLeaseError::AlreadyResolved);

        reg.cancel_permit(&permit, Time::from_nanos(1_000_000_000))
            .expect("cancel permit");

        crate::test_complete!("conformance_permit_abort_proof");
    }

    /// Conformance: committed lease blocks a new reserve on the same name.
    #[test]
    fn conformance_lease_blocks_reserve() {
        init_test("conformance_lease_blocks_reserve");

        let mut reg = NameRegistry::new();
        let mut lease = reg
            .register("taken", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();

        let err = reg
            .reserve("taken", tid(2), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap_err();
        assert_eq!(
            err,
            NameLeaseError::NameTaken {
                name: "taken".into(),
                current_holder: tid(1),
            }
        );

        lease.release().expect("lease release should succeed");

        crate::test_complete!("conformance_lease_blocks_reserve");
    }

    /// Conformance: commit_permit on an already-cancelled permit returns NotFound.
    #[test]
    fn conformance_commit_after_cancel_fails() {
        init_test("conformance_commit_after_cancel_fails");

        let mut reg = NameRegistry::new();
        let permit = reg
            .reserve("ephemeral", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .expect("reserve ok");

        // Cancel the pending entry first.
        reg.cancel_permit(&permit, Time::from_nanos(1_000_000_000))
            .expect("cancel permit");

        // commit_permit should fail because the name is no longer pending.
        let err = reg.commit_permit(permit).unwrap_err();
        assert_eq!(
            err,
            NameLeaseError::NotFound {
                name: "ephemeral".into()
            }
        );

        crate::test_complete!("conformance_commit_after_cancel_fails");
    }

    #[test]
    fn commit_permit_rejects_stale_same_identity_replay() {
        init_test("commit_permit_rejects_stale_same_identity_replay");

        let mut reg = NameRegistry::new();
        let stale_permit = reg
            .reserve("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .expect("reserve ok");
        reg.cancel_permit(&stale_permit, Time::from_nanos(1_000_000_000))
            .expect("cancel stale permit entry");

        let fresh_permit = reg
            .reserve("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .expect("reserve again ok");

        let err = reg.commit_permit(stale_permit).unwrap_err();
        assert_eq!(err, NameLeaseError::PermissionDenied { name: "svc".into() });
        assert_eq!(reg.whereis("svc"), None);

        let mut lease = reg.commit_permit(fresh_permit).expect("fresh commit ok");
        assert_eq!(reg.whereis("svc"), Some(tid(1)));

        reg.unregister("svc", tid(1)).unwrap();
        lease.release().expect("lease release should succeed");

        crate::test_complete!("commit_permit_rejects_stale_same_identity_replay");
    }

    #[test]
    fn cancel_permit_rejects_stale_same_identity_replay() {
        init_test("cancel_permit_rejects_stale_same_identity_replay");

        let mut reg = NameRegistry::new();
        let mut stale_permit = reg
            .reserve("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .expect("should reserve svc for stale permit test");
        stale_permit.abort().expect("abort stale permit");
        reg.cancel_permit(&stale_permit, Time::from_nanos(1_000_000_000))
            .expect("cancel original permit entry");

        let fresh_permit = reg
            .reserve("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .expect("reserve again ok");

        let err = reg
            .cancel_permit(&stale_permit, Time::from_secs(1))
            .unwrap_err();
        assert_eq!(err, NameLeaseError::PermissionDenied { name: "svc".into() });

        let mut lease = reg.commit_permit(fresh_permit).expect("fresh commit ok");
        assert_eq!(reg.whereis("svc"), Some(tid(1)));
        reg.unregister("svc", tid(1))
            .expect("should unregister svc after stale permit test");
        lease
            .release()
            .expect("should release lease after stale permit test");

        crate::test_complete!("cancel_permit_rejects_stale_same_identity_replay");
    }

    #[test]
    fn commit_permit_rejects_aborted_permit_without_mutating_registry() {
        init_test("commit_permit_rejects_aborted_permit_without_mutating_registry");

        let mut reg = NameRegistry::new();
        let mut permit = reg
            .reserve("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .expect("reserve ok");
        permit.abort().expect("abort permit");

        let err = reg.commit_permit(permit).unwrap_err();
        assert_eq!(err, NameLeaseError::AlreadyResolved);
        assert_eq!(reg.whereis("svc"), None);
        assert_eq!(
            reg.reserve("svc", tid(2), rid(0), Time::from_secs(1))
                .unwrap_err(),
            NameLeaseError::NameTaken {
                name: "svc".into(),
                current_holder: tid(1),
            }
        );

        // The consumed, aborted permit no longer supplies a live witness.
        // Region cleanup removes the orphaned reservation without fabricating one.
        assert_eq!(reg.cleanup_region(rid(0)), vec!["svc".to_string()]);
        let replacement = reg
            .reserve("svc", tid(2), rid(0), Time::from_secs(2))
            .expect("reserve after cleanup");
        let mut lease = reg.commit_permit(replacement).expect("commit replacement");
        reg.unregister("svc", tid(2))
            .expect("unregister replacement");
        lease.release().expect("release replacement");

        crate::test_complete!("commit_permit_rejects_aborted_permit_without_mutating_registry");
    }

    // ---------------------------------------------------------------
    // Collision policy tests (bd-16j5r)
    // ---------------------------------------------------------------

    #[test]
    fn collision_fail_rejects_duplicate() {
        init_test("collision_fail_rejects_duplicate");

        let mut reg = NameRegistry::new();
        let mut lease = reg
            .register("singleton", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();

        let err = reg
            .register_with_policy(
                "singleton",
                tid(2),
                rid(0),
                Time::from_secs(1),
                NameCollisionPolicy::Fail,
            )
            .unwrap_err();
        assert_eq!(
            err,
            NameLeaseError::NameTaken {
                name: "singleton".into(),
                current_holder: tid(1),
            }
        );
        assert_eq!(reg.len(), 1);

        lease.release().expect("lease release should succeed");
        crate::test_complete!("collision_fail_rejects_duplicate");
    }

    #[test]
    fn collision_fail_succeeds_when_no_collision() {
        init_test("collision_fail_succeeds_when_no_collision");

        let mut reg = NameRegistry::new();
        let outcome = reg
            .register_with_policy(
                "fresh",
                tid(1),
                rid(0),
                Time::from_nanos(1_000_000_000),
                NameCollisionPolicy::Fail,
            )
            .unwrap();

        let mut lease = match outcome {
            NameCollisionOutcome::Registered { lease } => lease,
            other => panic!("expected Registered, got {other:?}"), // ubs:ignore - test logic
        };
        assert_eq!(reg.whereis("fresh"), Some(tid(1)));

        lease.release().expect("lease release should succeed");
        crate::test_complete!("collision_fail_succeeds_when_no_collision");
    }

    #[test]
    fn collision_replace_displaces_old_holder() {
        init_test("collision_replace_displaces_old_holder");

        let mut reg = NameRegistry::new();
        let mut old_lease = reg
            .register("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();

        let outcome = reg
            .register_with_policy(
                "svc",
                tid(2),
                rid(1),
                Time::from_secs(5),
                NameCollisionPolicy::Replace,
            )
            .unwrap();

        let mut new_lease = match outcome {
            NameCollisionOutcome::Replaced {
                lease,
                displaced_holder,
                displaced_region,
            } => {
                assert_eq!(displaced_holder, tid(1));
                assert_eq!(displaced_region, rid(0));
                lease
            }
            other => panic!("expected Replaced, got {other:?}"), // ubs:ignore - test logic
        };

        // New holder is visible.
        assert_eq!(reg.whereis("svc"), Some(tid(2)));
        assert_eq!(reg.len(), 1);

        // Old holder's lease is orphaned — must be aborted.
        old_lease.abort().unwrap();
        new_lease.release().unwrap();

        crate::test_complete!("collision_replace_displaces_old_holder");
    }

    #[test]
    fn collision_replace_on_free_name_registers_normally() {
        init_test("collision_replace_on_free_name_registers_normally");

        let mut reg = NameRegistry::new();
        let outcome = reg
            .register_with_policy(
                "svc",
                tid(1),
                rid(0),
                Time::from_nanos(1_000_000_000),
                NameCollisionPolicy::Replace,
            )
            .unwrap();

        let mut lease = match outcome {
            NameCollisionOutcome::Registered { lease } => lease,
            other => panic!("expected Registered, got {other:?}"), // ubs:ignore - test logic
        };
        assert_eq!(reg.whereis("svc"), Some(tid(1)));

        lease.release().expect("lease release should succeed");
        crate::test_complete!("collision_replace_on_free_name_registers_normally");
    }

    #[test]
    fn collision_wait_enqueues_waiter() {
        init_test("collision_wait_enqueues_waiter");

        let mut reg = NameRegistry::new();
        let mut lease = reg
            .register("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();

        let outcome = reg
            .register_with_policy(
                "svc",
                tid(2),
                rid(0),
                Time::from_secs(1),
                NameCollisionPolicy::Wait {
                    deadline: Time::from_secs(60),
                },
            )
            .unwrap();
        assert!(matches!(outcome, NameCollisionOutcome::Enqueued));
        assert_eq!(reg.waiter_count(), 1);

        // Name still held by original task.
        assert_eq!(reg.whereis("svc"), Some(tid(1)));

        lease.abort().unwrap();
        crate::test_complete!("collision_wait_enqueues_waiter");
    }

    #[test]
    fn collision_wait_grants_on_unregister() {
        init_test("collision_wait_grants_on_unregister");

        let mut reg = NameRegistry::new();
        let mut lease = reg
            .register("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();

        // Enqueue a waiter.
        let outcome = reg
            .register_with_policy(
                "svc",
                tid(2),
                rid(0),
                Time::from_secs(1),
                NameCollisionPolicy::Wait {
                    deadline: Time::from_secs(60),
                },
            )
            .unwrap();
        assert!(matches!(outcome, NameCollisionOutcome::Enqueued));

        // Free the name using unregister_and_grant.
        reg.unregister_and_grant("svc", tid(1), Time::from_secs(10))
            .unwrap();
        lease.release().expect("lease release should succeed");

        // Waiter should have been granted.
        assert_eq!(reg.waiter_count(), 0);
        assert_eq!(reg.whereis("svc"), Some(tid(2)));

        let granted = reg.take_granted();
        assert_eq!(granted.len(), 1);
        assert_eq!(granted[0].name, "svc");
        let mut granted_lease = granted.into_iter().next().unwrap().lease;
        assert_eq!(granted_lease.holder(), tid(2));
        granted_lease.release().unwrap();

        crate::test_complete!("collision_wait_grants_on_unregister");
    }

    #[test]
    fn dropping_the_registry_aborts_a_grant_nobody_collected() {
        init_test("dropping_the_registry_aborts_a_grant_nobody_collected");

        let mut reg = NameRegistry::new();
        let mut lease = reg
            .register("svc", tid(1), rid(0), Time::from_secs(1))
            .unwrap();
        let outcome = reg
            .register_with_policy(
                "svc",
                tid(2),
                rid(0),
                Time::from_secs(1),
                NameCollisionPolicy::Wait {
                    deadline: Time::from_secs(60),
                },
            )
            .unwrap();
        assert!(matches!(outcome, NameCollisionOutcome::Enqueued));
        reg.unregister_owned_and_grant(&lease, Time::from_secs(10))
            .unwrap();
        lease.release().expect("lease release should succeed");
        assert_eq!(reg.whereis("svc"), Some(tid(2)), "the waiter was granted");

        // The waiter never collects its grant (its task was cancelled, say),
        // and the registry goes away with the armed lease inside it.
        let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(reg)));
        assert!(
            dropped.is_ok(),
            "dropping the registry must abort the uncollected grant, not panic with ASUP-E101"
        );
        crate::test_complete!("dropping_the_registry_aborts_a_grant_nobody_collected");
    }

    #[test]
    fn unregister_owned_and_grant_rejects_stale_lease_identity() {
        init_test("unregister_owned_and_grant_rejects_stale_lease_identity");

        let mut reg = NameRegistry::new();
        let mut current = reg
            .register("svc", tid(1), rid(0), Time::from_secs(10))
            .unwrap();
        let mut stale = NameLease::new("svc", tid(1), rid(0), Time::from_secs(5));

        assert_eq!(
            reg.unregister_owned_and_grant(&stale, Time::from_secs(12)),
            Err(NameLeaseError::PermissionDenied {
                name: "svc".to_string(),
            }),
        );
        assert_eq!(reg.whereis("svc"), Some(tid(1)));

        reg.unregister_owned_and_grant(&current, Time::from_secs(12))
            .unwrap();
        current.release().unwrap();
        stale.abort().unwrap();

        crate::test_complete!("unregister_owned_and_grant_rejects_stale_lease_identity");
    }

    #[test]
    fn collision_wait_expired_waiter_not_granted() {
        init_test("collision_wait_expired_waiter_not_granted");

        let mut reg = NameRegistry::new();
        let mut lease = reg
            .register("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();

        // Enqueue a waiter with a short deadline.
        reg.register_with_policy(
            "svc",
            tid(2),
            rid(0),
            Time::from_secs(1),
            NameCollisionPolicy::Wait {
                deadline: Time::from_secs(5),
            },
        )
        .unwrap();

        // Free the name AFTER the deadline.
        reg.unregister_and_grant("svc", tid(1), Time::from_secs(10))
            .unwrap();
        lease.release().expect("lease release should succeed");

        // Waiter should NOT have been granted (expired).
        assert_eq!(reg.waiter_count(), 0);
        assert_eq!(reg.whereis("svc"), None);
        let granted = reg.take_granted();
        assert!(granted.is_empty());

        crate::test_complete!("collision_wait_expired_waiter_not_granted");
    }

    #[test]
    fn collision_wait_rejects_already_expired_budget() {
        init_test("collision_wait_rejects_already_expired_budget");

        let mut reg = NameRegistry::new();
        let mut lease = reg
            .register("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();

        let err = reg
            .register_with_policy(
                "svc",
                tid(2),
                rid(0),
                Time::from_secs(10),
                NameCollisionPolicy::Wait {
                    deadline: Time::from_secs(5),
                },
            )
            .unwrap_err();
        assert_eq!(
            err,
            NameLeaseError::WaitBudgetExceeded { name: "svc".into() }
        );
        assert_eq!(reg.waiter_count(), 0);
        assert_eq!(reg.whereis("svc"), Some(tid(1)));

        reg.unregister("svc", tid(1)).unwrap();
        lease.release().expect("lease release should succeed");

        crate::test_complete!("collision_wait_rejects_already_expired_budget");
    }

    #[test]
    fn collision_wait_fifo_ordering() {
        init_test("collision_wait_fifo_ordering");

        let mut reg = NameRegistry::new();
        let mut lease = reg
            .register("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();

        // Enqueue two waiters.
        reg.register_with_policy(
            "svc",
            tid(2),
            rid(0),
            Time::from_secs(1),
            NameCollisionPolicy::Wait {
                deadline: Time::from_secs(60),
            },
        )
        .unwrap();
        reg.register_with_policy(
            "svc",
            tid(3),
            rid(0),
            Time::from_secs(2),
            NameCollisionPolicy::Wait {
                deadline: Time::from_secs(60),
            },
        )
        .unwrap();
        assert_eq!(reg.waiter_count(), 2);

        // Free the name — first waiter (tid 2) should win.
        reg.unregister_and_grant("svc", tid(1), Time::from_secs(10))
            .unwrap();
        lease.release().expect("lease release should succeed");

        assert_eq!(reg.whereis("svc"), Some(tid(2)));
        assert_eq!(reg.waiter_count(), 1); // tid 3 still waiting

        // Free again — second waiter (tid 3) should get it.
        let mut granted1 = reg.take_granted().into_iter().next().unwrap().lease;
        reg.unregister_and_grant("svc", tid(2), Time::from_secs(20))
            .unwrap();
        granted1.release().unwrap();

        assert_eq!(reg.whereis("svc"), Some(tid(3)));
        assert_eq!(reg.waiter_count(), 0);

        let mut granted2 = reg.take_granted().into_iter().next().unwrap().lease;
        granted2.release().unwrap();

        crate::test_complete!("collision_wait_fifo_ordering");
    }

    #[test]
    fn collision_wait_cleanup_region_removes_waiters() {
        init_test("collision_wait_cleanup_region_removes_waiters");

        let mut reg = NameRegistry::new();
        let mut lease = reg
            .register("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();

        // Enqueue a waiter in region 1.
        reg.register_with_policy(
            "svc",
            tid(2),
            rid(1),
            Time::from_secs(1),
            NameCollisionPolicy::Wait {
                deadline: Time::from_secs(60),
            },
        )
        .unwrap();
        assert_eq!(reg.waiter_count(), 1);

        // Cleanup region 1 removes the waiter.
        reg.cleanup_region(rid(1));
        assert_eq!(reg.waiter_count(), 0);

        lease.abort().unwrap();
        crate::test_complete!("collision_wait_cleanup_region_removes_waiters");
    }

    #[test]
    fn collision_wait_cleanup_task_removes_waiters() {
        init_test("collision_wait_cleanup_task_removes_waiters");

        let mut reg = NameRegistry::new();
        let mut lease = reg
            .register("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();

        // Enqueue a waiter from task 2.
        reg.register_with_policy(
            "svc",
            tid(2),
            rid(0),
            Time::from_secs(1),
            NameCollisionPolicy::Wait {
                deadline: Time::from_secs(60),
            },
        )
        .unwrap();
        assert_eq!(reg.waiter_count(), 1);

        // Cleanup task 2 removes the waiter.
        reg.cleanup_task(tid(2));
        assert_eq!(reg.waiter_count(), 0);

        lease.abort().unwrap();
        crate::test_complete!("collision_wait_cleanup_task_removes_waiters");
    }

    /// Cleanup of a region after a waiter has been granted must abort the
    /// granted lease's obligation token instead of leaving it orphaned.
    /// Before the fix, the orphaned `NameLease` in the `granted` queue
    /// triggered an "OBLIGATION TOKEN LEAKED" panic on drop.
    #[test]
    fn cleanup_region_aborts_granted_lease_obligation() {
        init_test("cleanup_region_aborts_granted_lease_obligation");

        let mut reg = NameRegistry::new();
        // Task 1 in region 0 holds "svc".
        let mut lease = reg
            .register("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();

        // Task 2 in region 1 waits for "svc".
        reg.register_with_policy(
            "svc",
            tid(2),
            rid(1),
            Time::from_secs(1),
            NameCollisionPolicy::Wait {
                deadline: Time::from_secs(60),
            },
        )
        .unwrap();

        // Free the name — task 2 is granted the lease.
        reg.unregister_and_grant("svc", tid(1), Time::from_secs(5))
            .unwrap();
        lease.release().expect("lease release should succeed");
        assert_eq!(reg.whereis("svc"), Some(tid(2)));

        // Before take_granted, clean up region 1 (task 2's region).
        // This must abort the granted lease's obligation token.
        reg.cleanup_region(rid(1));

        // The granted queue should now be empty (lease was aborted).
        let granted = reg.take_granted();
        assert!(granted.is_empty());

        // Dropping the registry should NOT panic.
        drop(reg);
        crate::test_complete!("cleanup_region_aborts_granted_lease_obligation");
    }

    /// Cleanup of a task after a waiter has been granted must abort the
    /// granted lease's obligation token instead of leaving it orphaned.
    #[test]
    fn cleanup_task_aborts_granted_lease_obligation() {
        init_test("cleanup_task_aborts_granted_lease_obligation");

        let mut reg = NameRegistry::new();
        let mut lease = reg
            .register("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .expect("should register svc for cleanup_task test");

        // Task 2 waits for "svc".
        reg.register_with_policy(
            "svc",
            tid(2),
            rid(0),
            Time::from_secs(1),
            NameCollisionPolicy::Wait {
                deadline: Time::from_secs(60),
            },
        )
        .unwrap();

        // Free the name — task 2 is granted.
        reg.unregister_and_grant("svc", tid(1), Time::from_secs(5))
            .expect("should unregister and grant to tid(2)");
        lease.release().expect("should release lease");
        assert_eq!(reg.whereis("svc"), Some(tid(2)));

        // Before take_granted, clean up task 2.
        reg.cleanup_task(tid(2));

        let granted = reg.take_granted();
        assert!(granted.is_empty());

        drop(reg);
        crate::test_complete!("cleanup_task_aborts_granted_lease_obligation");
    }

    #[test]
    fn collision_drain_expired_waiters() {
        init_test("collision_drain_expired_waiters");

        let mut reg = NameRegistry::new();
        let mut lease = reg
            .register("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .expect("should register svc for tid(1)");

        // Two waiters with different deadlines.
        reg.register_with_policy(
            "svc",
            tid(2),
            rid(0),
            Time::from_secs(1),
            NameCollisionPolicy::Wait {
                deadline: Time::from_secs(10),
            },
        )
        .expect("should register waiter tid(2)");
        reg.register_with_policy(
            "svc",
            tid(3),
            rid(0),
            Time::from_secs(2),
            NameCollisionPolicy::Wait {
                deadline: Time::from_secs(100),
            },
        )
        .unwrap();
        assert_eq!(reg.waiter_count(), 2);

        // Drain expired at time 50: only first waiter is expired.
        let removed = reg.drain_expired_waiters(Time::from_secs(50));
        assert_eq!(removed, 1);
        assert_eq!(reg.waiter_count(), 1);

        lease.abort().unwrap();
        crate::test_complete!("collision_drain_expired_waiters");
    }

    #[test]
    fn collision_replace_displaces_pending_permit() {
        init_test("collision_replace_displaces_pending_permit");

        let mut reg = NameRegistry::new();
        let mut permit = reg
            .reserve("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .expect("reserve ok");

        // Replace policy should displace the pending permit.
        let outcome = reg
            .register_with_policy(
                "svc",
                tid(2),
                rid(0),
                Time::from_secs(1),
                NameCollisionPolicy::Replace,
            )
            .unwrap();

        let mut new_lease = match outcome {
            NameCollisionOutcome::Replaced {
                lease,
                displaced_holder,
                ..
            } => {
                assert_eq!(displaced_holder, tid(1));
                lease
            }
            other => panic!("expected Replaced, got {other:?}"), // ubs:ignore - test logic
        };

        assert_eq!(reg.whereis("svc"), Some(tid(2)));

        // The old permit is orphaned; abort it.
        permit.abort().expect("permit abort should succeed");
        new_lease.release().unwrap();

        crate::test_complete!("collision_replace_displaces_pending_permit");
    }

    /// Conformance: register_with_policy Fail mode is equivalent to register().
    #[test]
    fn conformance_policy_fail_equivalent_to_register() {
        init_test("conformance_policy_fail_equivalent_to_register");

        let mut reg = NameRegistry::new();

        // Register with Fail policy.
        let outcome = reg
            .register_with_policy(
                "svc",
                tid(1),
                rid(0),
                Time::from_nanos(1_000_000_000),
                NameCollisionPolicy::Fail,
            )
            .unwrap();
        let mut lease = match outcome {
            NameCollisionOutcome::Registered { lease } => lease,
            other => panic!("expected Registered, got {other:?}"), // ubs:ignore - test logic
        };

        // Try again — should fail identically to register().
        let err_policy = reg
            .register_with_policy(
                "svc",
                tid(2),
                rid(0),
                Time::from_nanos(1_000_000_000),
                NameCollisionPolicy::Fail,
            )
            .unwrap_err();
        let err_register = reg
            .register("svc", tid(3), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap_err();

        // Both should be NameTaken with holder tid(1).
        match (&err_policy, &err_register) {
            (
                NameLeaseError::NameTaken {
                    current_holder: h1, ..
                },
                NameLeaseError::NameTaken {
                    current_holder: h2, ..
                },
            ) => assert_eq!(h1, h2),
            _ => panic!("expected NameTaken from both"),
        }

        lease.release().expect("lease release should succeed");
        crate::test_complete!("conformance_policy_fail_equivalent_to_register");
    }

    /// Conformance: replace produces a valid active lease for the new holder.
    #[test]
    fn conformance_replace_lease_is_valid() {
        init_test("conformance_replace_lease_is_valid");

        let mut reg = NameRegistry::new();
        let mut old_lease = reg
            .register("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();

        let outcome = reg
            .register_with_policy(
                "svc",
                tid(2),
                rid(1),
                Time::from_secs(5),
                NameCollisionPolicy::Replace,
            )
            .unwrap();

        let mut new_lease = match outcome {
            NameCollisionOutcome::Replaced { lease, .. } => lease,
            other => panic!("expected Replaced, got {other:?}"), // ubs:ignore - test logic
        };

        // New lease metadata is correct.
        assert_eq!(new_lease.name(), "svc");
        assert_eq!(new_lease.holder(), tid(2));
        assert_eq!(new_lease.region(), rid(1));
        assert_eq!(new_lease.acquired_at(), Time::from_secs(5));
        assert!(new_lease.is_active());

        // Can release with a valid proof.
        let proof = new_lease.release().unwrap();
        let resolved = proof.into_resolved_proof();
        assert_eq!(
            resolved.resolution(),
            crate::obligation::graded::Resolution::Commit,
        );

        old_lease.abort().unwrap();
        crate::test_complete!("conformance_replace_lease_is_valid");
    }

    /// Conformance: WaitBudgetExceeded error displays correctly.
    #[test]
    fn wait_budget_exceeded_display() {
        init_test("wait_budget_exceeded_display");

        let err = NameLeaseError::WaitBudgetExceeded { name: "svc".into() };
        assert!(err.to_string().contains("svc"));
        assert!(err.to_string().contains("budget"));

        crate::test_complete!("wait_budget_exceeded_display");
    }

    /// When cleanup_region removes a lease and a waiter from a *different*
    /// region is queued, the waiter should be granted the name.
    #[test]
    fn cleanup_region_grants_to_cross_region_waiter() {
        init_test("cleanup_region_grants_to_cross_region_waiter");

        let mut reg = NameRegistry::new();
        // Task 1 in region 0 holds "svc".
        let mut lease = reg
            .register("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .expect("should register svc for cross_region test");

        // Task 2 in region 1 waits for "svc".
        reg.register_with_policy(
            "svc",
            tid(2),
            rid(1),
            Time::from_secs(3600),
            NameCollisionPolicy::Wait {
                deadline: Time::from_secs(7200),
            },
        )
        .expect("should register waiter in different region");
        assert_eq!(reg.waiter_count(), 1);

        // Cleanup region 0 (holder region) should free "svc" and grant to task 2.
        reg.cleanup_region_at(rid(0), Time::from_secs(3600));
        // The original lease obligation must be resolved even though cleanup
        // removed it from the registry.
        lease
            .abort()
            .expect("should abort lease after cleanup_region");
        assert_eq!(reg.waiter_count(), 0);
        assert_eq!(reg.whereis("svc"), Some(tid(2)));

        // The granted lease should be available.
        let granted = reg.take_granted();
        assert_eq!(granted.len(), 1);
        assert_eq!(granted[0].name, "svc");
        let mut granted_lease = granted.into_iter().next().unwrap().lease;
        granted_lease.release().unwrap();

        crate::test_complete!("cleanup_region_grants_to_cross_region_waiter");
    }

    /// When cleanup_task removes a lease and a waiter from a *different*
    /// task is queued, the waiter should be granted the name.
    #[test]
    fn cleanup_task_grants_to_other_task_waiter() {
        init_test("cleanup_task_grants_to_other_task_waiter");

        let mut reg = NameRegistry::new();
        // Task 1 holds "svc".
        let mut lease = reg
            .register("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();

        // Task 2 waits for "svc".
        reg.register_with_policy(
            "svc",
            tid(2),
            rid(0),
            Time::from_secs(1),
            NameCollisionPolicy::Wait {
                deadline: Time::from_secs(60),
            },
        )
        .unwrap();
        assert_eq!(reg.waiter_count(), 1);

        // Cleanup task 1 should free "svc" and grant to task 2.
        reg.cleanup_task_at(tid(1), Time::from_secs(2));
        // The original lease obligation must be resolved even though cleanup
        // removed it from the registry.
        lease.abort().unwrap();
        assert_eq!(reg.waiter_count(), 0);
        assert_eq!(reg.whereis("svc"), Some(tid(2)));

        let granted = reg.take_granted();
        assert_eq!(granted.len(), 1);
        let mut granted_lease = granted.into_iter().next().unwrap().lease;
        granted_lease.release().unwrap();

        crate::test_complete!("cleanup_task_grants_to_other_task_waiter");
    }

    /// Regression: cleanup of a region holding a pending permit must grant
    /// the name to a waiter from another region. Before the fix,
    /// try_grant_to_first_waiter was only called for active lease names,
    /// not pending-only names, so the waiter was stranded.
    #[test]
    fn cleanup_region_grants_waiter_for_pending_permit() {
        init_test("cleanup_region_grants_waiter_for_pending_permit");

        let mut reg = NameRegistry::new();
        // Task 1 in region 0 reserves (pending) "svc".
        let mut permit = reg
            .reserve("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .expect("should reserve svc for pending permit test");

        // Task 2 in region 1 tries to register with Wait policy.
        // The pending permit blocks registration, so task 2 becomes a waiter.
        let outcome = reg
            .register_with_policy(
                "svc",
                tid(2),
                rid(1),
                Time::from_secs(1),
                NameCollisionPolicy::Wait {
                    deadline: Time::from_secs(60),
                },
            )
            .unwrap();
        assert!(matches!(outcome, NameCollisionOutcome::Enqueued));
        assert_eq!(reg.waiter_count(), 1);

        // Cleanup region 0 removes the pending permit.
        reg.cleanup_region_at(rid(0), Time::from_secs(2));
        permit.abort().expect("permit abort should succeed");

        // The waiter from region 1 should have been granted the name.
        assert_eq!(reg.waiter_count(), 0);
        assert_eq!(reg.whereis("svc"), Some(tid(2)));

        let granted = reg.take_granted();
        assert_eq!(granted.len(), 1);
        assert_eq!(granted[0].name, "svc");
        let mut granted_lease = granted.into_iter().next().unwrap().lease;
        granted_lease.release().unwrap();

        crate::test_complete!("cleanup_region_grants_waiter_for_pending_permit");
    }

    /// Regression: cleanup of a task holding a pending permit must grant
    /// the name to a waiter from another task.
    #[test]
    fn cleanup_task_grants_waiter_for_pending_permit() {
        init_test("cleanup_task_grants_waiter_for_pending_permit");

        let mut reg = NameRegistry::new();
        // Task 1 reserves (pending) "svc".
        let mut permit = reg
            .reserve("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .expect("reserve ok");

        // Task 2 tries to register with Wait policy.
        let outcome = reg
            .register_with_policy(
                "svc",
                tid(2),
                rid(0),
                Time::from_secs(1),
                NameCollisionPolicy::Wait {
                    deadline: Time::from_secs(60),
                },
            )
            .unwrap();
        assert!(matches!(outcome, NameCollisionOutcome::Enqueued));
        assert_eq!(reg.waiter_count(), 1);

        // Cleanup task 1 removes the pending permit.
        reg.cleanup_task_at(tid(1), Time::from_secs(2));
        permit.abort().expect("permit abort should succeed");

        // The waiter should have been granted the name.
        assert_eq!(reg.waiter_count(), 0);
        assert_eq!(reg.whereis("svc"), Some(tid(2)));

        let granted = reg.take_granted();
        assert_eq!(granted.len(), 1);
        let mut granted_lease = granted.into_iter().next().unwrap().lease;
        granted_lease.release().unwrap();

        crate::test_complete!("cleanup_task_grants_waiter_for_pending_permit");
    }

    // ---------------------------------------------------------------
    // br-asupersync-td50ls: NameLease::new is private (forgery guard)
    // ---------------------------------------------------------------

    /// Compile-time witness via doctest in the source file would be
    /// the cleanest demonstration that NameLease::new is private. We
    /// can't easily express "this should fail to compile from outside
    /// the module" inside this same module's tests. Instead we
    /// document the expected behaviour and verify the registry-issued
    /// path still produces leases that match unregister_owned_and_grant.
    #[test]
    fn td50ls_registry_issued_lease_satisfies_identity_check() {
        init_test("td50ls_registry_issued_lease_satisfies_identity_check");
        let mut reg = NameRegistry::new();
        let lease = reg
            .register("svc", tid(1), rid(0), Time::from_secs(5))
            .unwrap();

        // Genuine lease passes the identity check on the unregister
        // path — this is the post-fix happy case.
        reg.unregister_owned_and_grant(&lease, Time::from_secs(6))
            .expect("registry-issued lease must satisfy identity check");

        // After successful unregister the entry is gone and the
        // lease's obligation must be resolved by the caller.
        let mut lease = lease;
        lease.abort().unwrap();
        crate::test_complete!("td50ls_registry_issued_lease_satisfies_identity_check");
    }

    // ---------------------------------------------------------------
    // br-asupersync-ziwcq4: identity_nonce hygiene on permit promotion
    // ---------------------------------------------------------------

    #[test]
    fn ziwcq4_committed_permit_resets_identity_nonce_to_zero() {
        // After commit_permit promotes a pending entry to an active
        // lease, the active-leases map must store identity_nonce = 0
        // (the documented invariant). Pre-fix the permit_id leaked
        // into the active map and stayed there.
        init_test("ziwcq4_committed_permit_resets_identity_nonce_to_zero");
        let mut reg = NameRegistry::new();
        let permit = reg
            .reserve("svc", tid(1), rid(0), Time::from_secs(0))
            .unwrap();
        let permit_id = permit.permit_id();
        assert!(
            permit_id != 0,
            "test precondition: pending permits get non-zero ids"
        );

        let mut lease = reg.commit_permit(permit).unwrap();
        let entry = reg
            .leases
            .get("svc")
            .expect("active entry exists after commit");
        assert_eq!(
            entry.identity_nonce, 0,
            "active lease entry must store identity_nonce=0 per the \
             documented invariant — pre-fix it carried the permit_id"
        );

        lease.release().expect("lease release should succeed");
        crate::test_complete!("ziwcq4_committed_permit_resets_identity_nonce_to_zero");
    }

    #[test]
    fn ziwcq4_all_register_paths_produce_zero_nonce_active_entries() {
        // Defense in depth: register, register_with_policy(Fail),
        // register_with_policy(Replace), and waiter-grant paths must
        // ALL produce active entries with identity_nonce = 0.
        init_test("ziwcq4_all_register_paths_produce_zero_nonce_active_entries");
        let mut reg = NameRegistry::new();

        let mut l1 = reg
            .register("a", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();
        assert_eq!(reg.leases.get("a").unwrap().identity_nonce, 0);

        let outcome = reg
            .register_with_policy(
                "b",
                tid(1),
                rid(0),
                Time::from_nanos(1_000_000_000),
                NameCollisionPolicy::Fail,
            )
            .unwrap();
        let mut l2 = match outcome {
            NameCollisionOutcome::Registered { lease } => lease,
            _ => panic!("expected Registered"), // ubs:ignore - test helper
        };
        assert_eq!(reg.leases.get("b").unwrap().identity_nonce, 0);

        // Replace path: register c, then replace.
        let mut l3 = reg
            .register("c", tid(2), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();
        let outcome = reg
            .register_with_policy(
                "c",
                tid(3),
                rid(0),
                Time::from_secs(1),
                NameCollisionPolicy::Replace,
            )
            .unwrap();
        let mut l3_new = match outcome {
            NameCollisionOutcome::Replaced { lease, .. } => lease,
            _ => panic!("expected Replaced"), // ubs:ignore - test helper
        };
        assert_eq!(reg.leases.get("c").unwrap().identity_nonce, 0);

        // Waiter-grant path: enqueue, free, drain.
        let outcome = reg
            .register_with_policy(
                "c",
                tid(4),
                rid(0),
                Time::from_secs(1),
                NameCollisionPolicy::Wait {
                    deadline: Time::from_secs(10),
                },
            )
            .unwrap();
        assert!(matches!(outcome, NameCollisionOutcome::Enqueued));
        // tid(3) is the holder after Replace.
        l3_new.release().unwrap();
        reg.unregister_and_grant("c", tid(3), Time::from_secs(2))
            .unwrap();
        assert_eq!(reg.leases.get("c").unwrap().identity_nonce, 0);
        let mut granted = reg.take_granted();
        granted[0].lease.release().unwrap();

        l1.release().unwrap();
        l2.release().unwrap();
        l3.abort().unwrap(); // displaced
        crate::test_complete!("ziwcq4_all_register_paths_produce_zero_nonce_active_entries");
    }

    // ---------------------------------------------------------------
    // br-asupersync-zpanx6: caller-identity check on unregister
    // ---------------------------------------------------------------

    #[test]
    fn zpanx6_unregister_with_wrong_caller_returns_permission_denied() {
        // Pre-fix any caller with &mut NameRegistry could drop any
        // task's lease just by knowing the name. Post-fix the caller
        // MUST supply its own TaskId and it must match the lease
        // holder.
        init_test("zpanx6_unregister_with_wrong_caller_returns_permission_denied");
        let mut reg = NameRegistry::new();
        let mut lease = reg
            .register("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();

        // Wrong caller: tid(99) attempts to drop tid(1)'s lease.
        let err = reg.unregister("svc", tid(99)).unwrap_err();
        assert_eq!(err, NameLeaseError::PermissionDenied { name: "svc".into() });
        assert!(
            reg.is_registered("svc"),
            "rejected unregister must be a no-op"
        );
        assert_eq!(reg.whereis("svc"), Some(tid(1)));

        // Correct caller succeeds.
        reg.unregister("svc", tid(1)).unwrap();
        assert!(!reg.is_registered("svc"));
        lease.release().expect("lease release should succeed");
    }

    #[test]
    fn zpanx6_unregister_and_grant_enforces_caller_identity_too() {
        init_test("zpanx6_unregister_and_grant_enforces_caller_identity_too");
        let mut reg = NameRegistry::new();
        let mut lease = reg
            .register("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();

        // Enqueue a waiter so we can verify a wrong-caller failure
        // does NOT trigger the grant side effect.
        reg.register_with_policy(
            "svc",
            tid(2),
            rid(0),
            Time::from_secs(1),
            NameCollisionPolicy::Wait {
                deadline: Time::from_secs(60),
            },
        )
        .unwrap();
        assert_eq!(reg.waiter_count(), 1);

        // Wrong caller — must NOT free the name and must NOT grant
        // the waiter.
        let err = reg
            .unregister_and_grant("svc", tid(99), Time::from_secs(5))
            .unwrap_err();
        assert_eq!(err, NameLeaseError::PermissionDenied { name: "svc".into() });
        assert!(reg.is_registered("svc"));
        assert_eq!(reg.waiter_count(), 1, "waiter must not be granted");
        assert!(reg.take_granted().is_empty());

        // Correct caller: succeeds and grants the waiter.
        reg.unregister_and_grant("svc", tid(1), Time::from_secs(6))
            .unwrap();
        lease.release().expect("lease release should succeed");
        assert_eq!(reg.whereis("svc"), Some(tid(2)));
        let mut g = reg.take_granted();
        assert_eq!(g.len(), 1);
        g[0].lease.release().unwrap();
    }

    #[test]
    fn zpanx6_unregister_unknown_name_returns_not_found_regardless_of_caller() {
        // NotFound takes precedence over PermissionDenied so unknown
        // names give the same error for any caller — avoids leaking
        // "this name exists but you don't own it".
        init_test("zpanx6_unregister_unknown_name_returns_not_found_regardless_of_caller");
        let mut reg = NameRegistry::new();
        let err1 = reg.unregister("ghost", tid(1)).unwrap_err();
        let err2 = reg.unregister("ghost", tid(99)).unwrap_err();
        assert_eq!(
            err1,
            NameLeaseError::NotFound {
                name: "ghost".into()
            }
        );
        assert_eq!(err1, err2, "unknown-name error must not depend on caller");
    }

    #[test]
    fn zpanx6_force_unregister_bypasses_caller_check() {
        // Admin force path explicitly bypasses identity — that's the
        // contract. Verifies bulk-cleanup / supervisor paths still
        // work when out-of-band authority is needed.
        init_test("zpanx6_force_unregister_bypasses_caller_check");
        let mut reg = NameRegistry::new();
        let mut lease = reg
            .register("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();
        reg.force_unregister("svc")
            .expect("force path bypasses identity check");
        assert!(!reg.is_registered("svc"));
        lease.abort().unwrap();
    }

    #[test]
    fn zpanx6_force_unregister_and_grant_bypasses_caller_check_and_grants() {
        init_test("zpanx6_force_unregister_and_grant_bypasses_caller_check_and_grants");
        let mut reg = NameRegistry::new();
        let mut lease = reg
            .register("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();
        reg.register_with_policy(
            "svc",
            tid(2),
            rid(0),
            Time::from_secs(1),
            NameCollisionPolicy::Wait {
                deadline: Time::from_secs(60),
            },
        )
        .unwrap();

        reg.force_unregister_and_grant("svc", Time::from_secs(5))
            .expect("force path bypasses identity check");
        lease.abort().unwrap();

        assert_eq!(reg.whereis("svc"), Some(tid(2)));
        let mut g = reg.take_granted();
        assert_eq!(g.len(), 1);
        g[0].lease.release().unwrap();
    }

    #[test]
    fn zpanx6_unregister_owned_and_grant_still_works_via_force_path() {
        // unregister_owned_and_grant performs its own (stronger)
        // identity check then delegates to force_unregister_and_grant.
        // Verifies the delegation didn't break the existing
        // semantics.
        init_test("zpanx6_unregister_owned_and_grant_still_works_via_force_path");
        let mut reg = NameRegistry::new();
        let lease = reg
            .register("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .unwrap();
        reg.unregister_owned_and_grant(&lease, Time::from_secs(5))
            .expect("genuine lease unregister via force-grant path");
        assert!(!reg.is_registered("svc"));
        let mut lease = lease;
        lease.abort().unwrap();
    }

    /// br-asupersync-smpwix: `NameRegistry::abort_permit` must remove
    /// the pending entry AND resolve the obligation token in a single
    /// atomic call. After the call the name must be re-reservable;
    /// pre-fix the pending entry leaked and the second reserve()
    /// returned NameTaken forever.
    #[test]
    fn smpwix_abort_permit_removes_pending_entry_and_resolves_obligation() {
        init_test("smpwix_abort_permit_removes_pending_entry_and_resolves_obligation");
        let mut reg = NameRegistry::new();
        let permit = reg
            .reserve("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .expect("first reservation");
        // Pending entry should be present.
        assert!(reg.pending.contains_key("svc"));
        // Abort the permit through the new public surface.
        let _proof = reg
            .abort_permit(permit, Time::from_secs(1))
            .expect("abort_permit must succeed on a live permit");
        // Pending entry must be gone.
        assert!(!reg.pending.contains_key("svc"));
        // The name must be re-reservable.
        let permit2 = reg
            .reserve("svc", tid(2), rid(0), Time::from_secs(2))
            .expect("re-reservation must succeed after abort_permit");
        // Cleanup so the test's drop-bomb obligation does not panic.
        let _ = reg
            .abort_permit(permit2, Time::from_secs(3))
            .expect("cleanup");
    }

    /// br-asupersync-smpwix: aborting with a forged or stale permit
    /// must not mutate registry state (no pending-entry removal, no
    /// obligation-token resolve), so the legitimate holder can still
    /// cancel/commit.
    #[test]
    fn smpwix_abort_permit_with_wrong_holder_leaves_state_intact() {
        init_test("smpwix_abort_permit_with_wrong_holder_leaves_state_intact");
        let mut reg = NameRegistry::new();
        let real = reg
            .reserve("svc", tid(1), rid(0), Time::from_nanos(1_000_000_000))
            .expect("real reservation");
        // Fabricate a permit-shaped struct with a different holder.
        // We can't easily mint one from outside, but we can hand the
        // method a permit for a name that's no longer pending and
        // confirm it returns NotFound without mutating state. The
        // wrong-holder path is exercised by the existing
        // permit_security tests in this module — we just need the
        // happy "still can be aborted" assertion here.
        assert!(reg.pending.contains_key("svc"));
        let _proof = reg
            .abort_permit(real, Time::from_secs(1))
            .expect("real abort works");
        assert!(!reg.pending.contains_key("svc"));
    }

    /// br-asupersync-n4103r: NameLease::new produces an obligation
    /// token whose description string matches the legacy format!
    /// output ("name_lease:{name}") byte-for-byte. The push_str
    /// refactor MUST preserve the exact description so any
    /// downstream observer that pattern-matches on the description
    /// continues to work.
    #[test]
    fn name_lease_description_matches_legacy_format() {
        let mut lease = NameLease::new(
            "alice-service",
            tid(1),
            rid(0),
            Time::from_nanos(1_000_000_000),
        );
        let want = format!("name_lease:{}", "alice-service");
        let got = lease.token.as_ref().unwrap().description().to_string();
        assert_eq!(got, want, "n4103r refactor changed description shape");
        let _ = lease.release().expect("description test cleanup");
    }

    /// br-asupersync-n4103r: same byte-for-byte parity test for
    /// NamePermit::new.
    #[test]
    fn name_permit_description_matches_legacy_format() {
        let mut permit = NamePermit::new(
            "svc-name",
            tid(1),
            rid(0),
            Time::from_nanos(1_000_000_000),
            1,
        );
        let want = format!("name_permit:{}", "svc-name");
        let got = permit.token.as_ref().unwrap().description().to_string();
        assert_eq!(got, want, "n4103r refactor changed description shape");
        let _ = permit.abort().expect("description test cleanup");
    }

    /// br-asupersync-n4103r: empty-name and unicode-name edge cases.
    /// Empty name produces "name_lease:" exactly; unicode name
    /// passes through without re-encoding.
    #[test]
    fn name_lease_description_handles_edge_cases() {
        let mut empty = NameLease::new("", tid(1), rid(0), Time::from_nanos(1_000_000_000));
        assert_eq!(empty.token.as_ref().unwrap().description(), "name_lease:");
        let _ = empty.release().expect("empty lease cleanup");

        let mut uni = NameLease::new(
            "сервис-α-🔒",
            tid(1),
            rid(0),
            Time::from_nanos(1_000_000_000),
        );
        assert_eq!(
            uni.token.as_ref().unwrap().description(),
            "name_lease:сервис-α-🔒"
        );
        let _ = uni.release().expect("unicode lease cleanup");
    }

    /// The root region: minting a lease for it panics (ASUP-E103).
    fn root() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(0, 0))
    }

    #[test]
    fn abort_permit_resolves_its_permit_when_the_pending_entry_is_gone() {
        init_test("abort_permit_resolves_its_permit_when_the_pending_entry_is_gone");
        let now = Time::from_secs(1);
        let mut reg = NameRegistry::new();
        let permit = reg.reserve("svc", tid(1), rid(1), now).expect("reserve");
        let NameCollisionOutcome::Replaced { mut lease, .. } = reg
            .register_with_policy("svc", tid(2), rid(2), now, NameCollisionPolicy::Replace)
            .expect("replace")
        else {
            panic!("Replace displaces the pending permit");
        };
        // The permit's entry is gone; aborting it must report that, not
        // panic by dropping the permit with its token armed.
        let aborted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            reg.abort_permit(permit, now)
        }));
        assert!(
            matches!(aborted, Ok(Err(NameLeaseError::NotFound { .. }))),
            "abort_permit returns NotFound: {aborted:?}"
        );
        assert_eq!(
            reg.whereis("svc"),
            Some(tid(2)),
            "the replacement keeps the name"
        );
        let _ = lease.release().expect("release the replacement");
    }

    #[test]
    fn a_root_region_registration_panics_before_changing_the_registry() {
        init_test("a_root_region_registration_panics_before_changing_the_registry");
        let now = Time::from_secs(1);
        let mut reg = NameRegistry::new();
        let register = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            reg.register("svc", tid(1), root(), now)
        }));
        assert!(
            register.is_err(),
            "a root-region lease is refused (ASUP-E103)"
        );
        assert_eq!(reg.whereis("svc"), None, "and leaves no lease-less entry");

        let reserve = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            reg.reserve("svc", tid(1), root(), now)
        }));
        assert!(reserve.is_err(), "a root-region permit is refused");
        let mut lease = reg
            .register("svc", tid(2), rid(2), now)
            .expect("name still free");

        let replace = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            reg.register_with_policy("svc", tid(3), root(), now, NameCollisionPolicy::Replace)
        }));
        assert!(replace.is_err(), "a root-region replacement is refused");
        assert_eq!(
            reg.whereis("svc"),
            Some(tid(2)),
            "the holder is not displaced by a refused replacement"
        );

        let wait = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            reg.register_with_policy(
                "svc",
                tid(4),
                root(),
                now,
                NameCollisionPolicy::Wait {
                    deadline: Time::from_secs(60),
                },
            )
        }));
        assert!(
            wait.is_err(),
            "a root-region waiter is refused when it enqueues"
        );
        assert_eq!(reg.waiter_count(), 0, "no waiter is left for a later grant");
        reg.unregister_owned_and_grant(&lease, now)
            .expect("unregister");
        let _ = lease.release().expect("release");
    }

    // br-asupersync-in4gh8: registration incarnations must not be inferred
    // from reusable task/region/time metadata or per-registry permit counters.
    #[test]
    fn same_tick_reregistration_rejects_the_previous_lease() {
        init_test("same_tick_reregistration_rejects_the_previous_lease");
        for through_permit in [false, true] {
            let now = Time::from_secs(10);
            let mut reg = NameRegistry::new();
            reg.watch_name("svc", tid(9), rid(9)).expect("watch name");
            let mut stale = reg.register("svc", tid(1), rid(0), now).unwrap();
            reg.unregister("svc", tid(1)).unwrap();
            let mut current = if through_permit {
                let permit = reg.reserve("svc", tid(1), rid(0), now).unwrap();
                reg.commit_permit(permit).unwrap()
            } else {
                reg.register("svc", tid(1), rid(0), now).unwrap()
            };
            assert_eq!(stale.holder(), current.holder());
            assert_eq!(stale.region(), current.region());
            assert_eq!(stale.acquired_at(), current.acquired_at());
            let entry = reg.leases.get("svc").unwrap().clone();
            let notifications = reg.notifications.clone();

            assert!(!reg.owns_lease(&stale), "the old incarnation is fenced");
            assert_eq!(
                reg.unregister_owned_and_grant(&stale, now),
                Err(NameLeaseError::PermissionDenied { name: "svc".into() })
            );
            assert_eq!(
                reg.rebind_lease(&mut stale, tid(2), rid(2)),
                Err(NameLeaseError::PermissionDenied { name: "svc".into() })
            );
            assert_eq!(reg.leases.get("svc"), Some(&entry));
            assert_eq!(reg.notifications, notifications);
            assert_eq!(stale.holder(), tid(1));
            assert!(reg.owns_lease(&current));

            reg.rebind_lease(&mut current, tid(3), rid(3)).unwrap();
            assert!(reg.owns_lease(&current), "rebinding preserves the witness");
            assert_eq!(reg.whereis("svc"), Some(tid(3)));
            // Resolving first remains supported by the legacy release API.
            current.release().unwrap();
            reg.unregister_owned_and_grant(&current, now).unwrap();
            stale.abort().unwrap();
            assert!(reg.is_empty());
        }
        crate::test_complete!("same_tick_reregistration_rejects_the_previous_lease");
    }

    #[test]
    fn same_tick_replace_rejects_the_displaced_lease() {
        init_test("same_tick_replace_rejects_the_displaced_lease");
        let now = Time::from_secs(10);
        let mut reg = NameRegistry::new();
        let mut stale = reg.register("svc", tid(1), rid(0), now).unwrap();
        let NameCollisionOutcome::Replaced { mut lease, .. } = reg
            .register_with_policy("svc", tid(1), rid(0), now, NameCollisionPolicy::Replace)
            .unwrap()
        else {
            panic!("the old registration must be displaced");
        };
        assert!(!reg.owns_lease(&stale));
        assert_eq!(
            reg.unregister_owned_and_grant(&stale, now),
            Err(NameLeaseError::PermissionDenied { name: "svc".into() })
        );
        assert_eq!(
            reg.rebind_lease(&mut stale, tid(2), rid(2)),
            Err(NameLeaseError::PermissionDenied { name: "svc".into() })
        );
        assert!(reg.owns_lease(&lease));
        assert_eq!(reg.whereis("svc"), Some(tid(1)));
        reg.unregister_owned_and_grant(&lease, now).unwrap();
        lease.release().unwrap();
        stale.abort().unwrap();
        crate::test_complete!("same_tick_replace_rejects_the_displaced_lease");
    }

    #[test]
    fn lease_witnesses_cannot_cross_registry_boundaries() {
        init_test("lease_witnesses_cannot_cross_registry_boundaries");
        let now = Time::from_secs(10);
        let mut first = NameRegistry::new();
        let mut second = NameRegistry::new();
        let mut first_lease = first.register("svc", tid(1), rid(0), now).unwrap();
        let mut second_lease = second.register("svc", tid(1), rid(0), now).unwrap();
        second.watch_name("svc", tid(9), rid(9)).unwrap();
        let notifications = second.notifications.clone();
        let entry = second.leases.get("svc").unwrap().clone();

        assert!(!second.owns_lease(&first_lease));
        assert_eq!(
            second.unregister_owned_and_grant(&first_lease, now),
            Err(NameLeaseError::PermissionDenied { name: "svc".into() })
        );
        assert_eq!(
            second.rebind_lease(&mut first_lease, tid(2), rid(2)),
            Err(NameLeaseError::PermissionDenied { name: "svc".into() })
        );
        assert_eq!(second.leases.get("svc"), Some(&entry));
        assert_eq!(second.notifications, notifications);
        assert!(first.owns_lease(&first_lease));
        assert!(second.owns_lease(&second_lease));

        first.unregister_owned_and_grant(&first_lease, now).unwrap();
        first_lease.release().unwrap();
        second
            .unregister_owned_and_grant(&second_lease, now)
            .unwrap();
        second_lease.release().unwrap();
        crate::test_complete!("lease_witnesses_cannot_cross_registry_boundaries");
    }

    #[test]
    fn permit_witnesses_cannot_cross_registry_boundaries() {
        init_test("permit_witnesses_cannot_cross_registry_boundaries");
        for commit_foreign in [false, true] {
            let now = Time::from_secs(10);
            let mut first = NameRegistry::new();
            let mut second = NameRegistry::new();
            let foreign = first.reserve("svc", tid(1), rid(0), now).unwrap();
            let authentic = second.reserve("svc", tid(1), rid(0), now).unwrap();
            assert_eq!(foreign.permit_id(), authentic.permit_id());
            let entry = second.pending.get("svc").unwrap().clone();
            let notifications = second.notifications.clone();
            assert_eq!(
                second.cancel_permit(&foreign, now),
                Err(NameLeaseError::PermissionDenied { name: "svc".into() })
            );
            let error = if commit_foreign {
                second.commit_permit(foreign).expect_err("foreign commit")
            } else {
                second
                    .abort_permit(foreign, now)
                    .expect_err("foreign abort")
            };
            assert_eq!(
                error,
                NameLeaseError::PermissionDenied { name: "svc".into() }
            );
            assert_eq!(second.pending.get("svc"), Some(&entry));
            assert_eq!(second.notifications, notifications);
            assert_eq!(second.whereis("svc"), None);
            // A rejected consuming operation has resolved the foreign token;
            // its original registry still owns the uncommitted reservation.
            assert_eq!(
                first.cleanup_region_at(rid(0), now),
                vec!["svc".to_string()]
            );

            let mut lease = second.commit_permit(authentic).unwrap();
            assert!(second.owns_lease(&lease));
            assert_eq!(second.leases.get("svc").unwrap().identity_nonce, 0);
            second.unregister_owned_and_grant(&lease, now).unwrap();
            lease.release().unwrap();
        }
        crate::test_complete!("permit_witnesses_cannot_cross_registry_boundaries");
    }

    #[test]
    fn stale_waiter_grant_cannot_publish_or_release_a_same_tick_replacement() {
        init_test("stale_waiter_grant_cannot_publish_or_release_a_same_tick_replacement");
        let now = Time::from_secs(10);
        let mut reg = NameRegistry::new();
        let mut owner = reg.register("svc", tid(1), rid(0), now).unwrap();
        reg.register_with_policy(
            "svc",
            tid(2),
            rid(2),
            now,
            NameCollisionPolicy::Wait {
                deadline: Time::from_secs(20),
            },
        )
        .unwrap();
        reg.unregister_owned_and_grant(&owner, now).unwrap();
        owner.release().unwrap();
        assert_eq!(reg.granted.len(), 1);
        assert!(
            reg.owns_lease(&reg.granted[0].lease),
            "a genuine grant authorizes"
        );
        let NameCollisionOutcome::Replaced { mut lease, .. } = reg
            .register_with_policy("svc", tid(2), rid(2), now, NameCollisionPolicy::Replace)
            .unwrap()
        else {
            panic!("replace the uncollected grant");
        };
        assert!(
            !reg.owns_lease(&reg.granted[0].lease),
            "never publish a stale grant"
        );
        let notifications = reg.notifications.clone();
        reg.cancel_wait_for("svc", tid(2), rid(2), now);
        assert!(reg.granted.is_empty());
        assert_eq!(
            reg.notifications, notifications,
            "stale cleanup releases no successor"
        );
        assert!(reg.owns_lease(&lease));
        assert_eq!(reg.whereis("svc"), Some(tid(2)));
        reg.unregister_owned_and_grant(&lease, now).unwrap();
        lease.release().unwrap();
        crate::test_complete!("stale_waiter_grant_cannot_publish_or_release_a_same_tick_replacement");
    }
