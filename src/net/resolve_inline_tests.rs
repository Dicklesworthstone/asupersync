    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use futures_lite::future;
    use parking_lot::{Condvar, Mutex};
    use std::future::Future;
    use std::future::poll_fn;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::task::Poll;

    #[test]
    fn lookup_one_passthrough_socket_addr() {
        future::block_on(async {
            let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
            let resolved = lookup_one(addr).await.unwrap();
            assert_eq!(resolved, addr);
        });
    }

    #[test]
    fn lookup_all_passthrough_socket_addr() {
        future::block_on(async {
            let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
            let resolved = lookup_all(addr).await.unwrap();
            assert_eq!(resolved, vec![addr]);
        });
    }

    #[test]
    fn lookup_one_resolves_localhost() {
        future::block_on(async {
            let resolved = lookup_all("localhost:80").await.unwrap();
            assert!(!resolved.is_empty());
        });
    }

    #[test]
    fn lookup_one_rejects_invalid_port() {
        future::block_on(async {
            let err = lookup_one("127.0.0.1:bogus").await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        });
    }

    #[test]
    fn lookup_one_rejects_empty_resolution() {
        struct EmptyAddrs;

        impl ToSocketAddrs for EmptyAddrs {
            type Iter = std::vec::IntoIter<SocketAddr>;

            fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
                Ok(Vec::new().into_iter())
            }
        }

        future::block_on(async {
            let err = lookup_one(EmptyAddrs).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(err.to_string(), NO_SOCKET_ADDRESSES_FOUND);
        });
    }

    #[test]
    fn lookup_all_rejects_empty_resolution() {
        struct EmptyAddrs;

        impl ToSocketAddrs for EmptyAddrs {
            type Iter = std::vec::IntoIter<SocketAddr>;

            fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
                Ok(Vec::new().into_iter())
            }
        }

        future::block_on(async {
            let err = lookup_all(EmptyAddrs).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(err.to_string(), NO_SOCKET_ADDRESSES_FOUND);
        });
    }

    #[test]
    fn lookup_one_cancel_does_not_deadlock() {
        struct BlockingAddrs {
            gate: Arc<(Mutex<bool>, Condvar)>,
            addr: SocketAddr,
        }

        impl ToSocketAddrs for BlockingAddrs {
            type Iter = std::vec::IntoIter<SocketAddr>;

            fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
                let (lock, cvar) = &*self.gate;
                let mut ready = lock.lock();
                while !*ready {
                    cvar.wait(&mut ready);
                }
                drop(ready);
                Ok(vec![self.addr].into_iter())
            }
        }

        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let addr = BlockingAddrs {
            gate: Arc::clone(&gate),
            addr: "127.0.0.1:9090".parse().unwrap(),
        };

        let mut fut = Box::pin(lookup_one(addr));
        future::block_on(poll_fn(|cx| match fut.as_mut().poll(cx) {
            Poll::Pending | Poll::Ready(_) => Poll::Ready(()),
        }));

        drop(fut);

        let (lock, cvar) = &*gate;
        let mut ready = lock.lock();
        *ready = true;
        cvar.notify_one();
        drop(ready);
    }

    /// asupersync-bi2462.119: a caller cancelled while its lookup is blocked
    /// in the resolver gets `Interrupted` at once instead of waiting for it.
    #[test]
    fn lookup_all_returns_promptly_when_the_caller_is_cancelled() {
        struct BlockingAddrs {
            gate: Arc<(Mutex<bool>, Condvar)>,
        }

        impl ToSocketAddrs for BlockingAddrs {
            type Iter = std::vec::IntoIter<SocketAddr>;

            fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
                let (lock, cvar) = &*self.gate;
                let mut ready = lock.lock();
                while !*ready {
                    cvar.wait(&mut ready);
                }
                drop(ready);
                Ok(vec!["127.0.0.1:9091".parse().unwrap()].into_iter())
            }
        }

        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let cx = Cx::for_testing();
        let _current = Cx::set_current(Some(cx.clone()));
        let mut fut = Box::pin(lookup_all(BlockingAddrs {
            gate: Arc::clone(&gate),
        }));
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(
            fut.as_mut().poll(&mut task).is_pending(),
            "the lookup is blocked in the resolver"
        );

        cx.cancel_with(crate::types::CancelKind::User, Some("dns caller cancelled"));
        let result = fut.as_mut().poll(&mut task);
        assert!(
            matches!(&result, Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::Interrupted),
            "a cancelled caller returns Interrupted without waiting, got {result:?}"
        );

        drop(fut);
        let (lock, cvar) = &*gate;
        *lock.lock() = true;
        cvar.notify_one();
    }

    #[test]
    fn lookup_all_on_a_forbidden_blocking_pool_returns_unsupported_and_resolves_nothing() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingAddrs(Arc<AtomicUsize>);

        impl ToSocketAddrs for CountingAddrs {
            type Iter = std::vec::IntoIter<SocketAddr>;

            fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(vec!["127.0.0.1:9092".parse().unwrap()].into_iter())
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let forbidden = crate::runtime::BlockingPool::with_config_and_policies(
            0,
            1,
            crate::runtime::blocking_pool::BlockingPoolOptions::default(),
            crate::runtime::BlockingQueuePolicy::Fifo,
            crate::runtime::BlockingAdmissionPolicy::Forbidden,
        );
        {
            let cx = Cx::for_testing().with_blocking_pool_handle(Some(forbidden.handle()));
            let _current = Cx::set_current(Some(cx));
            let result = future::block_on(lookup_all(CountingAddrs(Arc::clone(&calls))));
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "no lookup may run on a thread"
        );
        forbidden.shutdown();

        // Remove the plant: with an open pool the same lookup runs once and resolves.
        let open = crate::runtime::BlockingPool::new(1, 1);
        {
            let cx = Cx::for_testing().with_blocking_pool_handle(Some(open.handle()));
            let _current = Cx::set_current(Some(cx));
            let resolved = future::block_on(lookup_all(CountingAddrs(Arc::clone(&calls))));
            assert_eq!(resolved.unwrap().len(), 1);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        open.shutdown();
    }

    /// A pool that was shut down is a refusal, not a lookup run inline on the polling thread; with an open pool the same
    /// lookup resolves once.
    #[test]
    fn lookup_all_on_a_closed_blocking_pool_is_refused_and_resolves_nothing() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingAddrs(Arc<AtomicUsize>);

        impl ToSocketAddrs for CountingAddrs {
            type Iter = std::vec::IntoIter<SocketAddr>;

            fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(vec!["127.0.0.1:9093".parse().unwrap()].into_iter())
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let closed = crate::runtime::BlockingPool::new(1, 1);
        let closed_handle = closed.handle();
        closed.shutdown();
        {
            let cx = Cx::for_testing().with_blocking_pool_handle(Some(closed_handle));
            let _current = Cx::set_current(Some(cx));
            let error = future::block_on(lookup_all(CountingAddrs(Arc::clone(&calls))))
                .expect_err("a closed pool admits nothing");
            assert_eq!(error.kind(), io::ErrorKind::Other);
            assert!(error.to_string().contains("not admitted"), "{error}");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a closed pool must not run the lookup inline"
        );

        // Remove the plant: with an open pool the same lookup runs once and resolves.
        let open = crate::runtime::BlockingPool::new(1, 1);
        {
            let cx = Cx::for_testing().with_blocking_pool_handle(Some(open.handle()));
            let _current = Cx::set_current(Some(cx));
            let resolved = future::block_on(lookup_all(CountingAddrs(Arc::clone(&calls))));
            assert_eq!(resolved.unwrap().len(), 1);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        open.shutdown();
    }

    /// A spawn-restricted context hides its pool from the public getter, not from placement. One whose inherited pool is
    /// closed is refused: the lookup runs nowhere, neither inline nor on a dedicated thread. One whose inherited pool is
    /// open runs the lookup on that pool's worker, not on a dedicated thread.
    #[test]
    fn lookup_all_under_a_spawn_restricted_context_follows_the_pool_it_inherited() {
        use crate::cx::cap::CapSet;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct RecordingAddrs {
            calls: Arc<AtomicUsize>,
            ran_on: Arc<Mutex<Vec<Option<String>>>>,
        }

        impl ToSocketAddrs for RecordingAddrs {
            type Iter = std::vec::IntoIter<SocketAddr>;

            fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.ran_on
                    .lock()
                    .push(std::thread::current().name().map(str::to_owned));
                Ok(vec!["127.0.0.1:9094".parse().unwrap()].into_iter())
            }
        }

        // Spawn removed; time, randomness, I/O and remote kept, so the lookup's own I/O gate still passes.
        type NoSpawn = CapSet<false, true, true, true, true>;

        let calls = Arc::new(AtomicUsize::new(0));
        let ran_on = Arc::new(Mutex::new(Vec::new()));
        let recorder = || RecordingAddrs {
            calls: Arc::clone(&calls),
            ran_on: Arc::clone(&ran_on),
        };

        let closed = crate::runtime::BlockingPool::new(1, 1);
        let closed_handle = closed.handle();
        closed.shutdown();
        {
            let restricted = Cx::for_testing()
                .with_blocking_pool_handle(Some(closed_handle))
                .restrict::<NoSpawn>();
            let _current = restricted.set_current_restricted();
            assert!(
                Cx::current()
                    .expect("restricted ambient context")
                    .blocking_pool_handle()
                    .is_none(),
                "the restriction hides the public handle, which is the case under test"
            );
            let error = future::block_on(lookup_all(recorder()))
                .expect_err("a closed inherited pool admits nothing");
            assert_eq!(error.kind(), io::ErrorKind::Other);
            assert!(error.to_string().contains("not admitted"), "{error}");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a closed inherited pool must not run the lookup, inline or on a dedicated thread"
        );
        assert!(ran_on.lock().is_empty());

        // Remove the plant: an open inherited pool runs the same lookup, on its own worker thread.
        let open = crate::runtime::BlockingPool::new(1, 1);
        {
            let restricted = Cx::for_testing()
                .with_blocking_pool_handle(Some(open.handle()))
                .restrict::<NoSpawn>();
            let _current = restricted.set_current_restricted();
            assert!(
                Cx::current()
                    .expect("restricted ambient context")
                    .blocking_pool_handle()
                    .is_none(),
                "the restriction hides the public handle, which is the case under test"
            );
            let resolved = future::block_on(lookup_all(recorder()))
                .expect("an open inherited pool admits the lookup");
            assert_eq!(resolved.len(), 1);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let names = ran_on.lock().clone();
        assert!(
            matches!(names.as_slice(), [Some(name)] if name.starts_with("asupersync-blocking-")),
            "the lookup must run on the pool's worker, not on the dedicated thread `asupersync-blocking`: {names:?}"
        );
        open.shutdown();
    }
