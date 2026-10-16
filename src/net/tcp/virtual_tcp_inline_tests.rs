    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Waker};

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    struct CountWaker(std::sync::atomic::AtomicUsize);

    impl Wake for CountWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn count_waker() -> (Arc<CountWaker>, Waker) {
        let inner = Arc::new(CountWaker(std::sync::atomic::AtomicUsize::new(0)));
        (Arc::clone(&inner), Waker::from(inner))
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn virtual_stream_pair_read_write() {
        let (mut a, mut b) = VirtualTcpStream::pair(addr("127.0.0.1:1000"), addr("127.0.0.1:2000"));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Write from A
        let data = b"hello";
        let result = Pin::new(&mut a).poll_write(&mut cx, data);
        assert!(matches!(result, Poll::Ready(Ok(5))));

        // Read from B
        let mut buf = [0u8; 16];
        let mut read_buf = ReadBuf::new(&mut buf);
        let result = Pin::new(&mut b).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled(), b"hello");
    }

    #[test]
    fn virtual_stream_addresses() {
        let (a, b) = VirtualTcpStream::pair(addr("127.0.0.1:1000"), addr("127.0.0.1:2000"));

        assert_eq!(a.local_addr().unwrap(), addr("127.0.0.1:1000"));
        assert_eq!(a.peer_addr().unwrap(), addr("127.0.0.1:2000"));
        assert_eq!(b.local_addr().unwrap(), addr("127.0.0.1:2000"));
        assert_eq!(b.peer_addr().unwrap(), addr("127.0.0.1:1000"));
    }

    #[test]
    fn virtual_stream_eof_on_write_shutdown() {
        let (mut a, mut b) = VirtualTcpStream::pair(addr("127.0.0.1:1000"), addr("127.0.0.1:2000"));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Shutdown A's write side
        let result = Pin::new(&mut a).poll_shutdown(&mut cx);
        assert!(matches!(result, Poll::Ready(Ok(()))));

        // B should see EOF when reading
        let mut buf = [0u8; 16];
        let mut read_buf = ReadBuf::new(&mut buf);
        let result = Pin::new(&mut b).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled().len(), 0); // EOF
    }

    #[test]
    fn virtual_stream_eof_on_drop() {
        let (a, mut b) = VirtualTcpStream::pair(addr("127.0.0.1:1000"), addr("127.0.0.1:2000"));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        drop(a);

        let mut buf = [0u8; 16];
        let mut read_buf = ReadBuf::new(&mut buf);
        let result = Pin::new(&mut b).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled().len(), 0); // EOF
    }

    #[test]
    fn virtual_stream_write_after_shutdown_errors() {
        let (mut a, _b) = VirtualTcpStream::pair(addr("127.0.0.1:1000"), addr("127.0.0.1:2000"));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            Pin::new(&mut a).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));

        let result = Pin::new(&mut a).poll_write(&mut cx, b"data");
        assert!(matches!(result, Poll::Ready(Err(_))));
    }

    #[test]
    fn virtual_stream_pending_when_empty() {
        let (_a, mut b) = VirtualTcpStream::pair(addr("127.0.0.1:1000"), addr("127.0.0.1:2000"));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut buf = [0u8; 16];
        let mut read_buf = ReadBuf::new(&mut buf);
        let result = Pin::new(&mut b).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(result, Poll::Pending));
    }

    #[test]
    fn virtual_listener_bind_and_accept() {
        let listener = VirtualTcpListener::new(addr("127.0.0.1:8080"));
        assert_eq!(listener.local_addr().unwrap(), addr("127.0.0.1:8080"));
        assert_eq!(listener.pending_count(), 0);
        assert_eq!(listener.pending_connections(), Some(0));

        // Inject a connection
        let (client, server) =
            VirtualTcpStream::pair(addr("127.0.0.1:9000"), addr("127.0.0.1:8080"));
        let _ = client; // Client side (not used in this test)
        listener.inject_connection(server, addr("127.0.0.1:9000"));

        assert_eq!(listener.pending_count(), 1);

        // Accept it
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let result = listener.poll_accept(&mut cx);
        match &result {
            Poll::Ready(Ok((stream, remote_addr))) => {
                assert_eq!(*remote_addr, addr("127.0.0.1:9000"));
                assert_eq!(stream.local_addr().unwrap(), addr("127.0.0.1:8080"));
            }
            other => {
                assert!(
                    matches!(other, Poll::Ready(Ok(_))),
                    "expected Ready(Ok(...)), got: {other:?}",
                );
            }
        }
    }

    #[test]
    fn virtual_listener_pending_when_no_connections() {
        let listener = VirtualTcpListener::new(addr("127.0.0.1:8080"));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let result = listener.poll_accept(&mut cx);
        assert!(matches!(result, Poll::Pending));
    }

    #[test]
    fn virtual_listener_wakes_all_pending_accept_waiters() {
        let listener = VirtualTcpListener::new(addr("127.0.0.1:8080"));
        let (hits1, waker1) = count_waker();
        let (hits2, waker2) = count_waker();
        let mut cx1 = Context::from_waker(&waker1);
        let mut cx2 = Context::from_waker(&waker2);

        assert!(matches!(listener.poll_accept(&mut cx1), Poll::Pending));
        assert!(matches!(listener.poll_accept(&mut cx2), Poll::Pending));

        let (_client1, server1) =
            VirtualTcpStream::pair(addr("127.0.0.1:9000"), addr("127.0.0.1:8080"));
        listener.inject_connection(server1, addr("127.0.0.1:9000"));

        assert_eq!(hits1.0.load(Ordering::Relaxed), 1);
        assert_eq!(hits2.0.load(Ordering::Relaxed), 1);

        assert!(matches!(listener.poll_accept(&mut cx2), Poll::Ready(Ok(_))));
        assert!(matches!(listener.poll_accept(&mut cx1), Poll::Pending));

        let (_client2, server2) =
            VirtualTcpStream::pair(addr("127.0.0.1:9001"), addr("127.0.0.1:8080"));
        listener.inject_connection(server2, addr("127.0.0.1:9001"));

        assert_eq!(hits1.0.load(Ordering::Relaxed), 2);
    }

    /// A connection injected between an accept's empty-queue check and its
    /// waker registration is accepted (br-asupersync-8vrx8q). It used to wake
    /// an empty waiter list, and the acceptor slept with it queued.
    #[test]
    fn a_connection_injected_before_the_accept_registers_is_not_lost() {
        let listener = VirtualTcpListener::new(addr("127.0.0.1:8080"));
        let injector = listener.injector();
        let (_client, server) =
            VirtualTcpStream::pair(addr("127.0.0.1:9000"), addr("127.0.0.1:8080"));
        let mut server = Some(server);
        BEFORE_ACCEPT_REGISTER.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                if let Some(server) = server.take() {
                    injector.inject(server, addr("127.0.0.1:9000"));
                }
            }));
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let result = listener.poll_accept(&mut cx);
        BEFORE_ACCEPT_REGISTER.with(|hook| hook.borrow_mut().take());
        assert!(
            matches!(result, Poll::Ready(Ok(_))),
            "the connection injected before the registration is accepted"
        );
    }

    /// accept() returns Interrupted once its task is cancelled, as
    /// poll_accept does; it used to wait for a connection.
    #[test]
    fn accept_observes_cancellation() {
        let listener = VirtualTcpListener::new(addr("127.0.0.1:8080"));
        let cx = crate::cx::Cx::for_testing();
        cx.set_cancel_requested(true);
        let _guard = crate::cx::Cx::set_current(Some(cx));
        let mut accept = std::pin::pin!(listener.accept());
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        match std::future::Future::poll(accept.as_mut(), &mut task_cx) {
            Poll::Ready(Err(error)) => assert_eq!(error.kind(), io::ErrorKind::Interrupted),
            other => panic!(
                "a cancelled accept must return Interrupted, got {:?}",
                other.map(|r| r.map(|(_, a)| a))
            ),
        }
    }

    #[test]
    fn virtual_listener_closed_returns_error() {
        let listener = VirtualTcpListener::new(addr("127.0.0.1:8080"));
        listener.close();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let result = listener.poll_accept(&mut cx);
        assert!(matches!(result, Poll::Ready(Err(_))));
    }

    #[test]
    fn virtual_listener_close_drops_pending_connections() {
        let listener = VirtualTcpListener::new(addr("127.0.0.1:8080"));
        let (_client, server) =
            VirtualTcpStream::pair(addr("127.0.0.1:9000"), addr("127.0.0.1:8080"));
        listener.inject_connection(server, addr("127.0.0.1:9000"));
        assert_eq!(listener.pending_count(), 1);

        listener.close();
        assert_eq!(listener.pending_count(), 0);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let result = listener.poll_accept(&mut cx);
        assert!(matches!(result, Poll::Ready(Err(_))));
    }

    #[test]
    fn virtual_listener_inject_after_close_is_ignored() {
        let listener = VirtualTcpListener::new(addr("127.0.0.1:8080"));
        listener.close();

        let (_client, server) =
            VirtualTcpStream::pair(addr("127.0.0.1:9001"), addr("127.0.0.1:8080"));
        listener.inject_connection(server, addr("127.0.0.1:9001"));
        assert_eq!(listener.pending_count(), 0);

        let injector = listener.injector();
        let (_client2, server2) =
            VirtualTcpStream::pair(addr("127.0.0.1:9002"), addr("127.0.0.1:8080"));
        injector.inject(server2, addr("127.0.0.1:9002"));
        assert_eq!(listener.pending_count(), 0);
    }

    #[test]
    fn virtual_listener_injector_works() {
        let listener = VirtualTcpListener::new(addr("127.0.0.1:8080"));
        let injector = listener.injector();

        let (_client, server) =
            VirtualTcpStream::pair(addr("127.0.0.1:9000"), addr("127.0.0.1:8080"));
        injector.inject(server, addr("127.0.0.1:9000"));

        assert_eq!(listener.pending_count(), 1);
    }

    #[test]
    fn virtual_listener_drop_marks_closed() {
        let listener = VirtualTcpListener::new(addr("127.0.0.1:8080"));
        let state = Arc::clone(&listener.state);
        drop(listener);

        let closed = state.lock().closed;
        assert!(closed);
    }

    #[test]
    fn virtual_listener_bind_via_trait() {
        futures_lite::future::block_on(async {
            let listener = VirtualTcpListener::bind("127.0.0.1:0").await.expect("bind");
            // VirtualTcpListener resolves the address; port 0 maps to port 0
            assert!(listener.local_addr().is_ok());
        });
    }

    #[test]
    fn virtual_stream_bidirectional() {
        let (mut a, mut b) = VirtualTcpStream::pair(addr("127.0.0.1:1000"), addr("127.0.0.1:2000"));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // A writes, B reads
        assert!(matches!(
            Pin::new(&mut a).poll_write(&mut cx, b"from-a"),
            Poll::Ready(Ok(6))
        ));
        let mut buf = [0u8; 16];
        let mut read_buf = ReadBuf::new(&mut buf);
        assert!(matches!(
            Pin::new(&mut b).poll_read(&mut cx, &mut read_buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(read_buf.filled(), b"from-a");

        // B writes, A reads
        assert!(matches!(
            Pin::new(&mut b).poll_write(&mut cx, b"from-b"),
            Poll::Ready(Ok(6))
        ));
        let mut buf2 = [0u8; 16];
        let mut read_buf2 = ReadBuf::new(&mut buf2);
        assert!(matches!(
            Pin::new(&mut a).poll_read(&mut cx, &mut read_buf2),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(read_buf2.filled(), b"from-b");
    }

    #[test]
    fn virtual_stream_nodelay_and_ttl() {
        let (a, b) = VirtualTcpStream::pair(addr("127.0.0.1:1000"), addr("127.0.0.1:2000"));

        // Defaults
        assert!(!a.nodelay().unwrap());
        assert_eq!(a.ttl().unwrap(), 64);
        assert!(!b.nodelay().unwrap());
        assert_eq!(b.ttl().unwrap(), 64);

        // set_nodelay/set_ttl should be reflected by getters.
        assert!(a.set_nodelay(true).is_ok());
        assert!(a.set_ttl(128).is_ok());
        assert!(a.nodelay().unwrap());
        assert_eq!(a.ttl().unwrap(), 128);

        // Stream-local options should not bleed into the peer handle.
        assert!(!b.nodelay().unwrap());
        assert_eq!(b.ttl().unwrap(), 64);
    }

    #[test]
    fn virtual_stream_shutdown_both() {
        let (a, mut b) = VirtualTcpStream::pair(addr("127.0.0.1:1000"), addr("127.0.0.1:2000"));

        a.shutdown(Shutdown::Both).unwrap();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // B reads EOF
        let mut buf = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut buf);
        let result = Pin::new(&mut b).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled().len(), 0);
    }

    #[test]
    fn virtual_stream_shutdown_read_rejects_peer_write() {
        let (mut a, mut b) = VirtualTcpStream::pair(addr("127.0.0.1:1000"), addr("127.0.0.1:2000"));

        a.shutdown(Shutdown::Read).unwrap();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Peer write should fail once the other side stops accepting data.
        let result = Pin::new(&mut b).poll_write(&mut cx, b"discarded");
        assert!(matches!(
            result,
            Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::BrokenPipe
        ));

        // Reader sees EOF immediately.
        let mut buf = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut buf);
        let result = Pin::new(&mut a).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled().len(), 0);
    }

    #[test]
    fn virtual_stream_shutdown_read_wakes_blocked_writer() {
        let (mut a, b) = VirtualTcpStream::pair(addr("127.0.0.1:1000"), addr("127.0.0.1:2000"));

        let full = vec![7u8; VIRTUAL_TCP_CHANNEL_CAPACITY_BYTES];
        let (wake_counter, waker) = count_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            Pin::new(&mut a).poll_write(&mut cx, &full),
            Poll::Ready(Ok(VIRTUAL_TCP_CHANNEL_CAPACITY_BYTES))
        ));
        assert!(matches!(
            Pin::new(&mut a).poll_write(&mut cx, b"x"),
            Poll::Pending
        ));

        b.shutdown(Shutdown::Read).unwrap();
        assert_eq!(wake_counter.0.load(Ordering::Relaxed), 1);

        assert!(matches!(
            Pin::new(&mut a).poll_write(&mut cx, b"x"),
            Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::BrokenPipe
        ));
    }

    #[test]
    fn virtual_stream_zero_len_write_on_full_buffer_is_ready() {
        let (mut a, _b) = VirtualTcpStream::pair(addr("127.0.0.1:1000"), addr("127.0.0.1:2000"));

        let full = vec![5u8; VIRTUAL_TCP_CHANNEL_CAPACITY_BYTES];
        let (wake_counter, waker) = count_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            Pin::new(&mut a).poll_write(&mut cx, &full),
            Poll::Ready(Ok(VIRTUAL_TCP_CHANNEL_CAPACITY_BYTES))
        ));
        assert!(matches!(
            Pin::new(&mut a).poll_write(&mut cx, b""),
            Poll::Ready(Ok(0))
        ));
        assert_eq!(
            wake_counter.0.load(Ordering::Relaxed),
            0,
            "zero-length writes must not register a blocked-writer wake"
        );
    }

    #[test]
    fn virtual_stream_drop_wakes_blocked_writer() {
        let (mut a, b) = VirtualTcpStream::pair(addr("127.0.0.1:1000"), addr("127.0.0.1:2000"));

        let full = vec![9u8; VIRTUAL_TCP_CHANNEL_CAPACITY_BYTES];
        let (wake_counter, waker) = count_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            Pin::new(&mut a).poll_write(&mut cx, &full),
            Poll::Ready(Ok(VIRTUAL_TCP_CHANNEL_CAPACITY_BYTES))
        ));
        assert!(matches!(
            Pin::new(&mut a).poll_write(&mut cx, b"y"),
            Poll::Pending
        ));

        drop(b);
        assert_eq!(wake_counter.0.load(Ordering::Relaxed), 1);

        assert!(matches!(
            Pin::new(&mut a).poll_write(&mut cx, b"y"),
            Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::BrokenPipe
        ));
    }

    #[test]
    fn virtual_stream_connect_returns_unsupported() {
        futures_lite::future::block_on(async {
            let result = VirtualTcpStream::connect("127.0.0.1:8080").await;
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
        });
    }
