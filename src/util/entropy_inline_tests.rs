    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    // Use independent policies so these tests exercise the production guard
    // implementation without changing the global gate used by parallel OS
    // entropy tests elsewhere in the crate.
    #[test]
    fn strict_guards_preserve_isolation_in_every_drop_order() {
        static POLICY: StrictEntropyPolicy = StrictEntropyPolicy::new();
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let mut guards = [
                Some(StrictEntropyGuard::with_policy(&POLICY)),
                Some(StrictEntropyGuard::with_policy(&POLICY)),
                Some(StrictEntropyGuard::with_policy(&POLICY)),
            ];
            assert!(POLICY.enabled());
            for (dropped, index) in order.into_iter().enumerate() {
                drop(guards[index].take());
                assert_eq!(POLICY.enabled(), dropped < 2, "order={order:?}");
            }
        }
    }

    #[test]
    fn strict_guards_do_not_restore_stale_explicit_policy() {
        static POLICY: StrictEntropyPolicy = StrictEntropyPolicy::new();
        POLICY.enable();
        let guard = StrictEntropyGuard::with_policy(&POLICY);
        POLICY.disable();
        assert!(
            POLICY.enabled(),
            "explicit disable cannot revoke a live guard"
        );
        drop(guard);
        assert!(
            !POLICY.enabled(),
            "the old enabled bit must not be restored"
        );

        let guard = StrictEntropyGuard::with_policy(&POLICY);
        POLICY.enable();
        drop(guard);
        assert!(
            POLICY.enabled(),
            "dropping a guard cannot undo explicit enable"
        );
        POLICY.disable();
        assert!(!POLICY.enabled());
    }

    #[test]
    fn strict_guards_preserve_another_threads_live_scope() {
        static POLICY: StrictEntropyPolicy = StrictEntropyPolicy::new();
        let first = StrictEntropyGuard::with_policy(&POLICY);
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let worker = std::thread::spawn(move || {
            let second = StrictEntropyGuard::with_policy(&POLICY);
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            assert!(POLICY.enabled());
            drop(second);
        });

        entered_rx.recv().unwrap();
        drop(first);
        let protected = POLICY.enabled();
        // Always release and join the worker before asserting, including when
        // testing an implementation with the original out-of-order-drop bug.
        release_tx.send(()).unwrap();
        worker.join().unwrap();
        assert!(protected, "the worker still owned an isolation guard");
        assert!(!POLICY.enabled());
    }

    #[test]
    fn strict_guard_unwind_releases_only_its_own_claim() {
        static POLICY: StrictEntropyPolicy = StrictEntropyPolicy::new();
        let outer = StrictEntropyGuard::with_policy(&POLICY);
        let result = std::panic::catch_unwind(|| {
            let _inner = StrictEntropyGuard::with_policy(&POLICY);
            panic!("exercise strict entropy cleanup");
        });
        assert!(result.is_err());
        assert!(POLICY.enabled());
        drop(outer);
        assert!(!POLICY.enabled());
    }

    #[test]
    fn strict_guard_overflow_fails_closed_without_changing_policy() {
        static POLICY: StrictEntropyPolicy = StrictEntropyPolicy {
            state: AtomicUsize::new(usize::MAX - 1),
        };
        let result = std::panic::catch_unwind(|| StrictEntropyGuard::with_policy(&POLICY));
        assert!(result.is_err());
        assert_eq!(POLICY.state.load(STRICT_ENTROPY_ORDERING), usize::MAX - 1);
        assert!(POLICY.enabled());
    }

    // =========================================================================
    // DetEntropy Core Functionality
    // =========================================================================

    #[test]
    fn det_entropy_same_seed_same_sequence() {
        let e1 = DetEntropy::new(42);
        let e2 = DetEntropy::new(42);

        for _ in 0..32 {
            assert_eq!(e1.next_u64(), e2.next_u64());
        }
    }

    #[test]
    fn det_entropy_different_seeds_different_sequences() {
        let e1 = DetEntropy::new(12345);
        let e2 = DetEntropy::new(54321);

        let v1 = e1.next_u64();
        let v2 = e2.next_u64();
        assert_ne!(v1, v2, "Different seeds should produce different values");
    }

    #[test]
    fn det_entropy_fill_bytes_deterministic() {
        let e1 = DetEntropy::new(42);
        let e2 = DetEntropy::new(42);

        let mut buf1 = [0u8; 64];
        let mut buf2 = [0u8; 64];

        e1.fill_bytes(&mut buf1);
        e2.fill_bytes(&mut buf2);

        assert_eq!(buf1, buf2);
    }

    #[test]
    fn det_entropy_seed_42_matches_stable_vector() {
        let e = DetEntropy::new(42);

        assert_eq!(e.next_u64(), 0x0000_000A_9551_4AAA);

        let mut bytes = [0u8; 8];
        let e = DetEntropy::new(42);
        e.fill_bytes(&mut bytes);
        assert_eq!(bytes, [0xAA, 0x4A, 0x51, 0x95, 0x0A, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn det_entropy_fork_deterministic() {
        let parent1 = DetEntropy::new(99);
        let parent2 = DetEntropy::new(99);
        let task = TaskId::new_for_test(7, 0);

        let child1 = parent1.fork(task);
        let child2 = parent2.fork(task);

        for _ in 0..16 {
            assert_eq!(child1.next_u64(), child2.next_u64());
        }
    }

    #[test]
    fn det_entropy_fork_different_tasks_different_sequences() {
        let parent = DetEntropy::new(42);

        let task1 = TaskId::new_for_test(1, 0);
        let task2 = TaskId::new_for_test(2, 0);

        let child1 = parent.fork(task1);
        let child2 = parent.fork(task2);

        assert_ne!(
            child1.next_u64(),
            child2.next_u64(),
            "Different task IDs should produce different children"
        );
    }

    #[test]
    fn det_entropy_sequential_forks_different() {
        let parent = DetEntropy::new(42);
        let task_id = TaskId::new_for_test(1, 0);

        let child1 = parent.fork(task_id);
        let child2 = parent.fork(task_id);

        assert_ne!(
            child1.next_u64(),
            child2.next_u64(),
            "Sequential forks of same task should differ (fork counter)"
        );
    }

    #[test]
    fn det_entropy_source_id() {
        let e = DetEntropy::new(42);
        assert_eq!(e.source_id(), "deterministic");
    }

    // =========================================================================
    // OsEntropy Tests
    // =========================================================================

    #[test]
    fn os_entropy_produces_different_values() {
        let os = OsEntropy;
        let v1 = os.next_u64();
        let v2 = os.next_u64();

        // Extremely unlikely to be equal
        assert_ne!(v1, v2, "OS entropy should produce different values");
    }

    #[test]
    fn os_entropy_fill_bytes_works() {
        let os = OsEntropy;
        let mut buf = [0u8; 32];
        os.fill_bytes(&mut buf);

        // Check not all zeros (astronomically unlikely with real entropy)
        assert!(
            buf.iter().any(|&b| b != 0),
            "OS entropy should produce non-zero bytes"
        );
    }

    #[test]
    fn os_entropy_source_id() {
        let os = OsEntropy;
        assert_eq!(os.source_id(), "os");
    }

    #[test]
    fn os_entropy_fork_returns_os_entropy() {
        let os = OsEntropy;
        let task_id = TaskId::new_for_test(1, 0);
        let forked = os.fork(task_id);
        assert_eq!(forked.source_id(), "os");
    }

    // =========================================================================
    // BrowserEntropy Tests
    // =========================================================================

    #[test]
    fn browser_entropy_source_id() {
        let entropy = BrowserEntropy;
        assert_eq!(entropy.source_id(), "browser");
    }

    #[test]
    fn browser_entropy_fork_preserves_browser_identity() {
        let entropy = BrowserEntropy;
        let task_id = TaskId::new_for_test(1, 0);
        let forked = entropy.fork(task_id);
        assert_eq!(forked.source_id(), "browser");
    }

    #[test]
    fn browser_entropy_fill_bytes_works() {
        let entropy = BrowserEntropy;
        let mut buf = [0u8; 32];
        entropy.fill_bytes(&mut buf);
        assert!(
            buf.iter().any(|&b| b != 0),
            "browser entropy should produce non-zero bytes"
        );
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn det_entropy_zero_seed_works() {
        let e = DetEntropy::new(0);
        let _ = e.next_u64(); // Should not panic
    }

    #[test]
    fn det_entropy_max_seed_works() {
        let e = DetEntropy::new(u64::MAX);
        let _ = e.next_u64(); // Should not panic or overflow
    }

    #[test]
    fn det_entropy_fill_zero_bytes() {
        let e = DetEntropy::new(42);
        let mut buf: [u8; 0] = [];
        e.fill_bytes(&mut buf); // Should not panic
    }

    // =========================================================================
    // ThreadLocalEntropy Tests
    // =========================================================================

    #[test]
    fn thread_local_entropy_deterministic() {
        let tl1 = ThreadLocalEntropy::new(1234);
        let tl2 = ThreadLocalEntropy::new(1234);

        let e1 = tl1.for_thread(3);
        let e2 = tl2.for_thread(3);

        assert_eq!(e1.next_u64(), e2.next_u64());
    }

    #[test]
    fn thread_local_entropy_different_threads() {
        let tl = ThreadLocalEntropy::new(12345);

        let e0 = tl.for_thread(0);
        let e1 = tl.for_thread(1);

        assert_ne!(e0.next_u64(), e1.next_u64());
    }

    #[test]
    fn thread_local_entropy_zero_seed_not_correlated() {
        // Regression: global_seed=0 previously produced correlated thread seeds
        // because 0 * constant = 0, making seeds just 0, 1, 2, ...
        let tl = ThreadLocalEntropy::new(0);

        let e0 = tl.for_thread(0);
        let e1 = tl.for_thread(1);
        let e2 = tl.for_thread(2);

        let v0 = e0.next_u64();
        let v1 = e1.next_u64();
        let v2 = e2.next_u64();

        assert_ne!(v0, v1);
        assert_ne!(v1, v2);
        assert_ne!(v0, v2);
    }

    // =========================================================================
    // Thread Safety Tests
    // =========================================================================

    #[test]
    fn det_entropy_thread_safe() {
        use std::thread;

        let e = Arc::new(DetEntropy::new(42));
        let mut handles = vec![];

        for _ in 0..4 {
            let entropy = Arc::clone(&e);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    let _ = entropy.next_u64();
                }
            }));
        }

        for handle in handles {
            handle.join().expect("thread panicked");
        }
    }

    // =========================================================================
    // DeferredFork Tests
    // =========================================================================

    #[derive(Debug)]
    struct FixedEntropy(u64);

    impl EntropySource for FixedEntropy {
        fn fill_bytes(&self, dest: &mut [u8]) {
            dest.fill(self.0 as u8);
        }
        fn next_u64(&self) -> u64 {
            self.0
        }
        fn fork(&self, _task_id: TaskId) -> Arc<dyn EntropySource> {
            Arc::new(FixedEntropy(self.0))
        }
        fn source_id(&self) -> &'static str {
            "fixed"
        }
    }

    #[derive(Debug)]
    struct CountingEntropy {
        forks: AtomicUsize,
        panics_on_fork: bool,
    }

    impl EntropySource for CountingEntropy {
        fn fill_bytes(&self, dest: &mut [u8]) {
            dest.fill(42);
        }

        fn next_u64(&self) -> u64 {
            42
        }

        fn fork(&self, _task_id: TaskId) -> Arc<dyn EntropySource> {
            self.forks.fetch_add(1, Ordering::SeqCst);
            if self.panics_on_fork {
                panic!("user entropy fork panic");
            }
            Arc::new(FixedEntropy(42))
        }

        fn source_id(&self) -> &'static str {
            "counting"
        }
    }

    #[test]
    fn deferred_fork_lazily_evaluates_on_first_use() {
        let parent = Arc::new(CountingEntropy {
            forks: AtomicUsize::new(0),
            panics_on_fork: false,
        });

        let deferred = DeferredFork::new(
            parent.clone(),
            TaskId::from_arena(crate::util::ArenaIndex::new(1, 0)),
        );
        assert_eq!(
            parent.forks.load(Ordering::SeqCst),
            0,
            "fork must not be called upon DeferredFork creation"
        );

        assert_eq!(deferred.next_u64(), 42);
        assert_eq!(
            parent.forks.load(Ordering::SeqCst),
            1,
            "fork evaluated on first use"
        );

        // Subsequent calls do not re-invoke parent.fork
        assert_eq!(deferred.next_u64(), 42);
        assert_eq!(
            parent.forks.load(Ordering::SeqCst),
            1,
            "fork cached in OnceLock"
        );
    }

    #[test]
    fn deferred_fork_isolates_panic_until_access() {
        let parent = Arc::new(CountingEntropy {
            forks: AtomicUsize::new(0),
            panics_on_fork: true,
        });

        // Creating the deferred fork must not panic
        let deferred = DeferredFork::new(
            parent.clone(),
            TaskId::from_arena(crate::util::ArenaIndex::new(2, 0)),
        );
        assert_eq!(parent.forks.load(Ordering::SeqCst), 0);

        // Calling next_u64 triggers the panicking fork
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            deferred.next_u64();
        }));
        assert!(result.is_err(), "panic should only occur on actual access");
        assert_eq!(parent.forks.load(Ordering::SeqCst), 1);
    }
