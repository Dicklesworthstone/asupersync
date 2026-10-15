//! Conformance tests for the io_uring registered buffer pool.
//!
//! These drive the real `IoUringReactor` buffer-pool API: kernel
//! registration through `io_uring_register_buffers`, allocation, return,
//! exhaustion and unregistration (asupersync-dt6j4e). The suite this replaced
//! tested a local simulation that never recorded its pool.
//!
//! A host without io_uring, or whose kernel refuses fixed-buffer
//! registration, skips with a printed reason. Set
//! `ASUPERSYNC_REQUIRE_IO_URING=1` to turn every skip into a failure, so a
//! lane that must exercise the kernel cannot pass vacuously.

#[cfg(all(target_os = "linux", feature = "io-uring"))]
mod linux_io_uring_tests {
    use asupersync::runtime::reactor::IoUringReactor;
    use std::collections::HashSet;
    use std::io;
    use std::sync::{Arc, Mutex};

    fn require_kernel() -> bool {
        std::env::var("ASUPERSYNC_REQUIRE_IO_URING").is_ok_and(|value| value == "1")
    }

    fn skip(reason: &str) {
        assert!(
            !require_kernel(),
            "io_uring required but unavailable: {reason}"
        );
        eprintln!("SKIP conformance_io_uring_buffer_pool: {reason}");
    }

    /// A reactor whose kernel accepts fixed-buffer registration, or `None`
    /// after reporting why the test is skipped.
    fn registering_reactor() -> Option<IoUringReactor> {
        let reactor = match IoUringReactor::new() {
            Ok(reactor) => reactor,
            Err(err) => {
                skip(&format!("IoUringReactor::new failed: {err}"));
                return None;
            }
        };
        match reactor.is_buffer_registration_supported() {
            Ok(true) => Some(reactor),
            Ok(false) => {
                skip("the kernel does not support fixed-buffer registration");
                None
            }
            Err(err) => {
                skip(&format!("fixed-buffer registration probe failed: {err}"));
                None
            }
        }
    }

    #[test]
    fn an_unregistered_reactor_reports_no_pool() {
        let Some(reactor) = registering_reactor() else {
            return;
        };
        assert_eq!(reactor.total_buffer_count(), 0);
        assert_eq!(reactor.available_buffer_count(), 0);
        assert!(!reactor.is_buffer_pool_exhausted());
        assert!(reactor.allocate_buffer().is_none());
        let err = reactor
            .unregister_buffer_pool()
            .expect_err("nothing to unregister");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn a_zero_buffer_pool_is_refused() {
        let Some(reactor) = registering_reactor() else {
            return;
        };
        let err = reactor
            .register_buffer_pool(0, 4096)
            .expect_err("zero buffers");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(reactor.total_buffer_count(), 0);
    }

    /// Kernel registration succeeds, every buffer can be allocated once with
    /// a distinct in-range id, and the pool then reports exhaustion.
    #[test]
    fn a_registered_pool_allocates_each_buffer_once_then_reports_exhaustion() {
        let Some(reactor) = registering_reactor() else {
            return;
        };
        reactor
            .register_buffer_pool(4, 4096)
            .expect("kernel registration");
        assert_eq!(reactor.total_buffer_count(), 4);
        assert_eq!(reactor.available_buffer_count(), 4);
        assert!(!reactor.is_buffer_pool_exhausted());

        let mut ids = HashSet::new();
        for remaining in (0..4).rev() {
            let id = reactor.allocate_buffer().expect("a free buffer");
            assert!(id.id() < 4, "id {} is out of range", id.id());
            assert!(ids.insert(id.id()), "id {} allocated twice", id.id());
            assert_eq!(reactor.available_buffer_count(), remaining);
        }
        assert!(reactor.is_buffer_pool_exhausted());
        assert!(reactor.allocate_buffer().is_none());
        reactor.unregister_buffer_pool().expect("unregister");
    }

    /// A returned buffer can be allocated again; returning it twice, or
    /// returning an id from a larger pool, is refused.
    #[test]
    fn returned_buffers_are_reusable_and_bad_returns_are_refused() {
        let Some(small) = registering_reactor() else {
            return;
        };
        let Some(large) = registering_reactor() else {
            return;
        };
        small
            .register_buffer_pool(2, 1024)
            .expect("small registration");
        large
            .register_buffer_pool(8, 1024)
            .expect("large registration");

        let first = small.allocate_buffer().expect("first");
        let second = small.allocate_buffer().expect("second");
        assert!(small.is_buffer_pool_exhausted());

        small.return_buffer(first).expect("return");
        assert_eq!(small.available_buffer_count(), 1);
        let err = small.return_buffer(first).expect_err("double return");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        let again = small.allocate_buffer().expect("reallocated");
        assert_eq!(again.id(), first.id());

        let foreign = loop {
            let id = large.allocate_buffer().expect("large pool has a high id");
            if id.id() >= 2 {
                break id;
            }
        };
        let err = small
            .return_buffer(foreign)
            .expect_err("an id beyond this pool");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        small.return_buffer(second).expect("return second");
        small.return_buffer(again).expect("return again");
        assert_eq!(small.available_buffer_count(), 2);
        small.unregister_buffer_pool().expect("unregister small");
        large.unregister_buffer_pool().expect("unregister large");
    }

    /// One pool per reactor: a second registration is refused until the
    /// first is unregistered, after which the pool is gone and can be
    /// registered again.
    #[test]
    fn registration_is_exclusive_and_unregistration_clears_the_pool() {
        let Some(reactor) = registering_reactor() else {
            return;
        };
        reactor.register_buffer_pool(2, 512).expect("first");
        let held = reactor.allocate_buffer().expect("a buffer");
        let err = reactor
            .register_buffer_pool(2, 512)
            .expect_err("already registered");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);

        reactor.unregister_buffer_pool().expect("unregister");
        assert_eq!(reactor.total_buffer_count(), 0);
        assert!(reactor.allocate_buffer().is_none());
        let err = reactor
            .return_buffer(held)
            .expect_err("no pool to return to");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        let err = reactor
            .unregister_buffer_pool()
            .expect_err("already unregistered");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        reactor.register_buffer_pool(3, 512).expect("re-register");
        assert_eq!(reactor.total_buffer_count(), 3);
        assert_eq!(reactor.available_buffer_count(), 3);
        reactor.unregister_buffer_pool().expect("final unregister");
    }

    /// Concurrent allocate/return from several threads never hands out the
    /// same buffer twice at once, and every buffer is back at the end.
    #[test]
    fn concurrent_allocation_never_double_issues_a_buffer() {
        let Some(reactor) = registering_reactor() else {
            return;
        };
        reactor.register_buffer_pool(4, 256).expect("registration");
        let reactor = Arc::new(reactor);
        let outstanding = Arc::new(Mutex::new(HashSet::new()));
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let reactor = Arc::clone(&reactor);
                let outstanding = Arc::clone(&outstanding);
                std::thread::spawn(move || {
                    for _ in 0..2_000 {
                        let Some(id) = reactor.allocate_buffer() else {
                            std::thread::yield_now();
                            continue;
                        };
                        assert!(
                            outstanding.lock().unwrap().insert(id.id()),
                            "buffer {} issued twice",
                            id.id()
                        );
                        std::thread::yield_now();
                        assert!(outstanding.lock().unwrap().remove(&id.id()));
                        reactor.return_buffer(id).expect("return");
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("worker thread");
        }
        assert!(outstanding.lock().unwrap().is_empty());
        assert_eq!(reactor.available_buffer_count(), 4);
        reactor.unregister_buffer_pool().expect("unregister");
    }
}
