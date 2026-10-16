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
