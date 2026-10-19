    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::cx::Cx;
    use crate::io::AsyncReadExt;
    use crate::runtime::{IoDriverHandle, LabReactor};
    use crate::types::{Budget, RegionId, TaskId};
    use std::io::Write;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};
    use tempfile::tempdir;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    /// GH#67 follow-up (asupersync-tx9j0f): a `UnixListener` polled for a
    /// connection with no I/O driver on the current `Cx` parks on the
    /// process-global fallback driver instead of re-waking its accept
    /// waiters into a hot loop.
    mod gh67_fallback_io_driver {
        use super::*;
        use crate::net::udp::fallback_io_test_support::signal_waker;
        use std::time::Duration;

        #[test]
        fn poll_accept_without_io_driver_parks_until_a_peer_connects() {
            assert!(
                Cx::current().is_none(),
                "test must run without an ambient Cx"
            );
            let dir = tempdir().expect("create temp dir");
            let path = dir.path().join("driverless_accept.sock");
            let std_listener = net::UnixListener::bind(&path).expect("bind listener");
            std_listener
                .set_nonblocking(true)
                .expect("nonblocking listener");
            let listener = UnixListener::from_std(std_listener).expect("wrap listener");
            let (signal, waker, rx) = signal_waker();
            let mut task_cx = Context::from_waker(&waker);

            assert!(matches!(listener.poll_accept(&mut task_cx), Poll::Pending));
            assert_eq!(
                signal.hits.load(Ordering::SeqCst),
                0,
                "driverless accept poll must park, not self-wake (GH#67)"
            );
            assert!(
                listener.registration.lock().on_fallback(),
                "driverless accept registers with the process-global fallback I/O driver"
            );
            assert!(
                rx.recv_timeout(Duration::from_millis(200)).is_err(),
                "no wake may arrive while nobody connects"
            );

            let _peer = net::UnixStream::connect(&path).expect("peer connect");
            rx.recv_timeout(Duration::from_secs(5))
                .expect("fallback reactor pump delivers the readiness wake");
            assert_eq!(signal.hits.load(Ordering::SeqCst), 1);
            match listener.poll_accept(&mut task_cx) {
                Poll::Ready(Ok((_stream, _addr))) => {}
                other => panic!("expected the connection after the wake, got {other:?}"),
            }
        }
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    struct CountingWaker {
        hits: Arc<AtomicUsize>,
    }

    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.hits.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn owner_departure_wakes_survivors_outside_the_waiter_lock() {
        struct Retired {
            waiters: std::sync::Weak<AcceptWaiters>,
            dropped: Arc<AtomicUsize>,
        }
        impl Wake for Retired {
            fn wake(self: Arc<Self>) {
                panic!("a departed accept owner must not be woken");
            }
        }
        impl Drop for Retired {
            fn drop(&mut self) {
                if let Some(waiters) = self.waiters.upgrade() {
                    assert!(waiters.waiters.try_lock().is_some(), "drop outside gate");
                }
                self.dropped.fetch_add(1, Ordering::SeqCst);
            }
        }
        struct Survivor {
            waiters: std::sync::Weak<AcceptWaiters>,
            hits: Arc<AtomicUsize>,
        }
        impl Wake for Survivor {
            fn wake(self: Arc<Self>) {
                let waiters = self.waiters.upgrade().expect("live waiter list");
                assert!(waiters.waiters.try_lock().is_some(), "wake outside gate");
                waiters.register(Some(100), Waker::noop());
                self.hits.fetch_add(1, Ordering::SeqCst);
            }
        }

        let waiters = Arc::new(AcceptWaiters::default());
        let dropped = Arc::new(AtomicUsize::new(0));
        let hits = Arc::new(AtomicUsize::new(0));
        let retired_owner = waiters.next_owner();
        let survivor_owner = waiters.next_owner();
        let retired = Waker::from(Arc::new(Retired {
            waiters: Arc::downgrade(&waiters),
            dropped: Arc::clone(&dropped),
        }));
        let survivor = Waker::from(Arc::new(Survivor {
            waiters: Arc::downgrade(&waiters),
            hits: Arc::clone(&hits),
        }));
        waiters.register(Some(retired_owner), &retired);
        waiters.register(Some(survivor_owner), &survivor);
        drop(retired);
        waiters.remove(retired_owner);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(waiters.waiters.lock()[0].owner, Some(100));

        waiters.remove(retired_owner);
        waiters.remove(survivor_owner);
        assert_eq!(hits.load(Ordering::SeqCst), 1, "stale departures do not wake");
        assert_eq!(waiters.waiters.lock().len(), 1);
        waiters.wake_all();
        let late_hits = Arc::new(AtomicUsize::new(0));
        let late = Waker::from(Arc::new(CountingWaker {
            hits: Arc::clone(&late_hits),
        }));
        waiters.register(Some(101), &late);
        waiters.remove(100);
        assert_eq!(late_hits.load(Ordering::SeqCst), 0, "fired ticket is a no-op");
        assert_eq!(waiters.waiters.lock()[0].owner, Some(101));
    }

    #[test]
    fn test_bind_and_local_addr() {
        init_test("test_bind_and_local_addr");
        futures_lite::future::block_on(async {
            let dir = tempdir().expect("create temp dir");
            let path = dir.path().join("test.sock");

            let listener = UnixListener::bind(&path).await.expect("bind failed");
            let addr = listener.local_addr().expect("local_addr failed");

            // Should be a pathname socket
            let pathname = addr.as_pathname();
            crate::assert_with_log!(
                pathname.is_some(),
                "pathname exists",
                true,
                pathname.is_some()
            );
            let pathname = pathname.unwrap();
            crate::assert_with_log!(pathname == path, "pathname", path, pathname);
        });
        crate::test_complete!("test_bind_and_local_addr");
    }

    #[test]
    fn test_bind_refuses_non_socket_path() {
        init_test("test_bind_refuses_non_socket_path");
        futures_lite::future::block_on(async {
            let dir = tempdir().expect("create temp dir");
            let path = dir.path().join("non_socket_target");
            std::fs::write(&path, b"not a socket").expect("write file");

            let err = UnixListener::bind(&path)
                .await
                .expect_err("bind should reject non-socket path");
            crate::assert_with_log!(
                err.kind() == std::io::ErrorKind::AlreadyExists,
                "error kind",
                std::io::ErrorKind::AlreadyExists,
                err.kind()
            );

            let contents = std::fs::read(&path).expect("read file");
            let unchanged = contents == b"not a socket";
            crate::assert_with_log!(unchanged, "file unchanged", true, unchanged);
        });
        crate::test_complete!("test_bind_refuses_non_socket_path");
    }

    #[test]
    fn test_bind_refuses_stale_socket_file() {
        init_test("test_bind_refuses_stale_socket_file");
        futures_lite::future::block_on(async {
            let dir = tempdir().expect("create temp dir");
            let path = dir.path().join("stale_socket.sock");

            let stale = net::UnixListener::bind(&path).expect("create stale socket");
            drop(stale);

            let exists = path.exists();
            crate::assert_with_log!(exists, "stale socket exists", true, exists);

            let err = UnixListener::bind(&path)
                .await
                .expect_err("bind should refuse stale socket path");
            crate::assert_with_log!(
                err.kind() == io::ErrorKind::AddrInUse,
                "bind error kind",
                io::ErrorKind::AddrInUse,
                err.kind()
            );

            let exists = path.exists();
            crate::assert_with_log!(exists, "stale socket preserved", true, exists);
        });
        crate::test_complete!("test_bind_refuses_stale_socket_file");
    }

    #[test]
    fn test_bind_refuses_live_socket_file() {
        init_test("test_bind_refuses_live_socket_file");
        futures_lite::future::block_on(async {
            let dir = tempdir().expect("create temp dir");
            let path = dir.path().join("live_socket.sock");

            let original = net::UnixListener::bind(&path).expect("create live socket");

            let err = UnixListener::bind(&path)
                .await
                .expect_err("bind should refuse live socket path");
            crate::assert_with_log!(
                err.kind() == io::ErrorKind::AddrInUse,
                "bind error kind",
                io::ErrorKind::AddrInUse,
                err.kind()
            );
            crate::assert_with_log!(path.exists(), "live socket preserved", true, path.exists());

            drop(original);
            std::fs::remove_file(&path).ok();
        });
        crate::test_complete!("test_bind_refuses_live_socket_file");
    }

    #[test]
    fn test_accept() {
        init_test("test_accept");
        futures_lite::future::block_on(async {
            let dir = tempdir().expect("create temp dir");
            let path = dir.path().join("accept_test.sock");

            let listener = UnixListener::bind(&path).await.expect("bind failed");

            // Connect from another thread
            let path_clone = path.clone();
            let handle = std::thread::spawn(move || {
                let mut stream = net::UnixStream::connect(&path_clone).expect("connect failed");
                stream.write_all(b"hello").expect("write failed");
            });

            // Accept the connection
            let (mut stream, _addr) = listener.accept().await.expect("accept failed");

            // Read the data using async read
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.expect("read failed");
            crate::assert_with_log!(&buf == b"hello", "buf", b"hello", buf);

            handle.join().expect("thread failed");
        });
        crate::test_complete!("test_accept");
    }

    #[test]
    fn incoming_registers_on_wouldblock() {
        init_test("incoming_registers_on_wouldblock");
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("incoming_register.sock");

        let std_listener = net::UnixListener::bind(&path).expect("bind failed");
        std_listener
            .set_nonblocking(true)
            .expect("nonblocking failed");

        let reactor = Arc::new(LabReactor::new());
        let driver = IoDriverHandle::new(reactor);
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let listener = UnixListener::from_std(std_listener).expect("from_std failed");
        let mut incoming = listener.incoming();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut incoming).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Pending));

        assert!(
            listener.registration.lock().is_some(),
            "incoming should register interest"
        );
        crate::test_complete!("incoming_registers_on_wouldblock");
    }

    #[test]
    fn listener_fanout_wakes_all_pending_accept_waiters() {
        init_test("listener_fanout_wakes_all_pending_accept_waiters");
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("listener_fanout.sock");

        let std_listener = net::UnixListener::bind(&path).expect("bind failed");
        std_listener
            .set_nonblocking(true)
            .expect("nonblocking failed");

        let reactor = Arc::new(LabReactor::new());
        let driver = IoDriverHandle::new(reactor);
        let cx_cap = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _guard = Cx::set_current(Some(cx_cap));

        let listener = UnixListener::from_std(std_listener).expect("from_std failed");
        let hits1 = Arc::new(AtomicUsize::new(0));
        let hits2 = Arc::new(AtomicUsize::new(0));
        let waker1 = Waker::from(Arc::new(CountingWaker {
            hits: Arc::clone(&hits1),
        }));
        let waker2 = Waker::from(Arc::new(CountingWaker {
            hits: Arc::clone(&hits2),
        }));
        let mut cx1 = Context::from_waker(&waker1);
        let mut cx2 = Context::from_waker(&waker2);

        assert!(matches!(listener.poll_accept(&mut cx1), Poll::Pending));
        assert!(matches!(listener.poll_accept(&mut cx2), Poll::Pending));

        let _client1 = net::UnixStream::connect(&path).expect("connect first client");
        listener.accept_waiters.wake_all();

        assert_eq!(hits1.load(Ordering::SeqCst), 1);
        assert_eq!(hits2.load(Ordering::SeqCst), 1);

        assert!(matches!(listener.poll_accept(&mut cx2), Poll::Ready(Ok(_))));
        assert!(matches!(listener.poll_accept(&mut cx1), Poll::Pending));

        let _client2 = net::UnixStream::connect(&path).expect("connect second client");
        listener.accept_waiters.wake_all();

        assert_eq!(hits1.load(Ordering::SeqCst), 2);
        assert!(matches!(listener.poll_accept(&mut cx1), Poll::Ready(Ok(_))));

        crate::test_complete!("listener_fanout_wakes_all_pending_accept_waiters");
    }

    /// More accept() futures than the 32-entry cap the waiter list used to
    /// evict from: registering one must not wake another (the 33rd used to
    /// evict and wake the first, which evicted the next, forever), and a
    /// dropped accept() future must take its waiter with it.
    #[test]
    fn many_pending_accepts_neither_wake_each_other_nor_outlive_their_futures() {
        init_test("many_pending_accepts_neither_wake_each_other_nor_outlive_their_futures");
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("many_accepts.sock");
        let std_listener = net::UnixListener::bind(&path).expect("bind failed");
        std_listener
            .set_nonblocking(true)
            .expect("nonblocking failed");
        let reactor = Arc::new(LabReactor::new());
        let driver = IoDriverHandle::new(reactor);
        let cx_cap = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _guard = Cx::set_current(Some(cx_cap));
        let listener = UnixListener::from_std(std_listener).expect("from_std failed");
        let hits: Vec<Arc<AtomicUsize>> = (0..40).map(|_| Arc::new(AtomicUsize::new(0))).collect();
        let wakers: Vec<Waker> = hits
            .iter()
            .map(|hits| {
                Waker::from(Arc::new(CountingWaker {
                    hits: Arc::clone(hits),
                }))
            })
            .collect();
        let mut accepts: Vec<_> = (0..40).map(|_| Box::pin(listener.accept())).collect();
        for (accept, waker) in accepts.iter_mut().zip(&wakers) {
            let mut task_cx = Context::from_waker(waker);
            assert!(accept.as_mut().poll(&mut task_cx).is_pending());
        }
        let woken: usize = hits.iter().map(|hits| hits.load(Ordering::SeqCst)).sum();
        assert_eq!(woken, 0, "a pending accept must not wake another");
        assert_eq!(listener.accept_waiters.waiters.lock().len(), 40);

        drop(accepts);
        assert!(
            listener.accept_waiters.waiters.lock().is_empty(),
            "a dropped accept() future must remove its waiter"
        );
    }

    #[test]
    fn incoming_recovers_after_registration_lock_panic() {
        init_test("incoming_recovers_after_registration_lock_panic");
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("incoming_poisoned_lock.sock");

        let std_listener = net::UnixListener::bind(&path).expect("bind failed");
        std_listener
            .set_nonblocking(true)
            .expect("nonblocking failed");

        let reactor = Arc::new(LabReactor::new());
        let driver = IoDriverHandle::new(reactor);
        let cx_cap = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver),
            None,
        );
        let _guard = Cx::set_current(Some(cx_cap));

        let listener = UnixListener::from_std(std_listener).expect("from_std failed");
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = listener.registration.lock();
            panic!("panic while holding registration lock"); // ubs:ignore - test helper
        }));

        let mut incoming = listener.incoming();
        let waker = noop_waker();
        let mut poll_cx = Context::from_waker(&waker);

        let poll_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Pin::new(&mut incoming).poll_next(&mut poll_cx)
        }));
        assert!(
            poll_result.is_ok(),
            "poll_next should not panic after a registration-lock panic"
        );

        match poll_result.expect("poll result available") {
            Poll::Pending => {}
            other @ Poll::Ready(_) => {
                panic!("expected Poll::Pending after re-registration path, got {other:?}") // ubs:ignore - test helper
            }
        }

        crate::test_complete!("incoming_recovers_after_registration_lock_panic");
    }

    #[test]
    fn test_socket_cleanup_on_drop() {
        init_test("test_socket_cleanup_on_drop");
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("cleanup_test.sock");

        futures_lite::future::block_on(async {
            let listener = UnixListener::bind(&path).await.expect("bind failed");
            let exists = path.exists();
            crate::assert_with_log!(exists, "socket exists", true, exists);
            drop(listener);
        });

        let exists = path.exists();
        crate::assert_with_log!(!exists, "socket cleaned up", false, exists);
        crate::test_complete!("test_socket_cleanup_on_drop");
    }

    #[test]
    fn test_from_std_no_cleanup() {
        init_test("test_from_std_no_cleanup");
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("from_std_test.sock");

        // Create with std
        let std_listener = net::UnixListener::bind(&path).expect("bind failed");

        // Wrap in async version
        let listener = UnixListener::from_std(std_listener).expect("from_std failed");
        let exists = path.exists();
        crate::assert_with_log!(exists, "socket exists", true, exists);

        // Drop async listener
        drop(listener);

        // Socket file should still exist (from_std doesn't clean up)
        let exists = path.exists();
        crate::assert_with_log!(exists, "socket remains", true, exists);

        // Clean up manually
        std::fs::remove_file(&path).ok();
        crate::test_complete!("test_from_std_no_cleanup");
    }

    #[test]
    fn test_take_path_prevents_cleanup() {
        init_test("test_take_path_prevents_cleanup");
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("take_path_test.sock");

        futures_lite::future::block_on(async {
            let mut listener = UnixListener::bind(&path).await.expect("bind failed");

            // Take the path
            let taken = listener.take_path();
            crate::assert_with_log!(taken.is_some(), "taken some", true, taken.is_some());
            let taken = taken.unwrap();
            crate::assert_with_log!(taken == path, "taken path", path, taken);

            drop(listener);
        });

        // Socket should still exist
        let exists = path.exists();
        crate::assert_with_log!(exists, "socket remains", true, exists);

        // Clean up manually
        std::fs::remove_file(&path).ok();
        crate::test_complete!("test_take_path_prevents_cleanup");
    }

    #[test]
    fn replacement_socket_path_survives_old_listener_drop() {
        init_test("replacement_socket_path_survives_old_listener_drop");
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("listener_rebind.sock");

        let original =
            futures_lite::future::block_on(UnixListener::bind(&path)).expect("bind failed");
        crate::assert_with_log!(path.exists(), "socket exists", true, path.exists());

        std::fs::remove_file(&path).expect("unlink original path");
        let replacement = net::UnixListener::bind(&path).expect("bind replacement failed");
        crate::assert_with_log!(path.exists(), "replacement exists", true, path.exists());

        drop(original);

        crate::assert_with_log!(
            path.exists(),
            "old listener drop preserved replacement path",
            true,
            path.exists()
        );

        drop(replacement);
        std::fs::remove_file(&path).ok();
        crate::test_complete!("replacement_socket_path_survives_old_listener_drop");
    }

    #[test]
    fn test_bind_cleanup_on_post_bind_init_failure() {
        init_test("test_listener_bind_cleanup_on_post_bind_init_failure");
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("listener_init_failure.sock");

        remove_stale_socket_file(&path).expect("clear stale socket");
        let inner = net::UnixListener::bind(&path).expect("bind failed");
        let err = UnixListener::from_bound_with(&path, inner, |_socket| {
            Err(io::Error::other("injected listener init failure"))
        })
        .expect_err("post-bind init should fail");

        crate::assert_with_log!(
            err.kind() == io::ErrorKind::Other,
            "init error kind",
            io::ErrorKind::Other,
            err.kind()
        );
        crate::assert_with_log!(
            !path.exists(),
            "socket path cleaned after init failure",
            false,
            path.exists()
        );

        crate::test_complete!("test_listener_bind_cleanup_on_post_bind_init_failure");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_abstract_socket() {
        init_test("test_abstract_socket");
        futures_lite::future::block_on(async {
            let name = b"asupersync_test_abstract_socket";
            let listener = UnixListener::bind_abstract(name)
                .await
                .expect("bind failed");
            let addr = listener.local_addr().expect("local_addr failed");

            // Should be an abstract socket
            let pathname = addr.as_pathname();
            crate::assert_with_log!(
                pathname.is_none(),
                "no pathname",
                "None",
                format!("{:?}", pathname)
            );
        });
        crate::test_complete!("test_abstract_socket");
    }
