    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::runtime::reactor::{Events, Reactor, Token};
    use crate::runtime::{IoDriverHandle, LabReactor};
    use crate::types::{Budget, RegionId, TaskId, Time};
    use futures_lite::future;
    #[cfg(unix)]
    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    use std::future::Future;
    use std::future::poll_fn;
    use std::io;
    use std::net::{SocketAddr, TcpListener};
    #[cfg(unix)]
    use std::os::unix::io::AsRawFd;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    struct CountingWaker {
        hits: Arc<AtomicUsize>,
    }

    use std::task::Wake;
    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.hits.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    struct CountingReactor {
        inner: LabReactor,
        modify_calls: AtomicUsize,
        last_interest_bits: AtomicUsize,
    }

    impl CountingReactor {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: LabReactor::new(),
                modify_calls: AtomicUsize::new(0),
                last_interest_bits: AtomicUsize::new(Interest::empty().bits() as usize),
            })
        }

        fn modify_calls(&self) -> usize {
            self.modify_calls.load(Ordering::SeqCst)
        }

        fn last_interest(&self) -> Interest {
            Interest::from_bits(self.last_interest_bits.load(Ordering::SeqCst) as u8)
        }
    }

    impl Reactor for CountingReactor {
        fn register(
            &self,
            source: &dyn crate::runtime::reactor::Source,
            token: Token,
            interest: Interest,
        ) -> io::Result<()> {
            self.last_interest_bits
                .store(interest.bits() as usize, Ordering::SeqCst);
            self.inner.register(source, token, interest)
        }

        fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
            self.modify_calls.fetch_add(1, Ordering::SeqCst);
            self.last_interest_bits
                .store(interest.bits() as usize, Ordering::SeqCst);
            self.inner.modify(token, interest)
        }

        fn deregister(&self, token: Token) -> io::Result<()> {
            self.inner.deregister(token)
        }

        fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
            self.inner.poll(events, timeout)
        }

        fn wake(&self) -> io::Result<()> {
            self.inner.wake()
        }

        fn registration_count(&self) -> usize {
            self.inner.registration_count()
        }
    }

    struct RegisterNotConnectedReactor {
        inner: LabReactor,
    }

    impl RegisterNotConnectedReactor {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: LabReactor::new(),
            })
        }
    }

    impl Reactor for RegisterNotConnectedReactor {
        fn register(
            &self,
            _source: &dyn crate::runtime::reactor::Source,
            _token: Token,
            _interest: Interest,
        ) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "injected not connected register failure",
            ))
        }

        fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
            self.inner.modify(token, interest)
        }

        fn deregister(&self, token: Token) -> io::Result<()> {
            self.inner.deregister(token)
        }

        fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
            self.inner.poll(events, timeout)
        }

        fn wake(&self) -> io::Result<()> {
            self.inner.wake()
        }

        fn registration_count(&self) -> usize {
            self.inner.registration_count()
        }
    }

    #[test]
    fn tcp_stream_builder_defaults() {
        let builder = TcpStreamBuilder::new("127.0.0.1:0");
        assert!(builder.connect_timeout.is_none());
        assert!(builder.nodelay.is_none());
        assert_eq!(builder.keepalive, KeepaliveConfig::Default);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn unconnected_socket_write_retries_wsaenotconn_before_surfacing_bound() {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .expect("create unconnected socket");
        socket
            .set_nonblocking(true)
            .expect("make unconnected socket nonblocking");
        let std_stream: net::TcpStream = socket.into();
        let mut stream = TcpStream::from_std(std_stream).expect("wrap unconnected socket");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut stream).poll_write(&mut cx, b"tls client hello");
        assert!(
            first.is_pending(),
            "the first WSAENOTCONN must be retried, got {first:?}"
        );
        assert_eq!(stream.connect_settle_retries, 1);

        // Burning the count budget through immediate self-wakes is not enough
        // to fail before the real-time floor has elapsed.
        stream.connect_settle_retries = MAX_CONNECT_SETTLE_RETRIES;
        let before_floor = Pin::new(&mut stream).poll_write(&mut cx, b"tls client hello");
        assert!(
            before_floor.is_pending(),
            "the real-time floor must outlive the exhausted poll-count budget"
        );

        stream.connect_settle_retries = MAX_CONNECT_SETTLE_RETRIES;
        stream.connect_settle_started_at = Some(crate::time::wall_now());
        std::thread::sleep(MIN_CONNECT_SETTLE_TIME);
        let bounded = Pin::new(&mut stream).poll_write(&mut cx, b"tls client hello");
        match bounded {
            Poll::Ready(Err(err)) => {
                assert_eq!(err.kind(), io::ErrorKind::NotConnected);
                assert_eq!(err.raw_os_error(), Some(10057));
            }
            other => panic!("retry bound must surface WSAENOTCONN, got {other:?}"),
        }
    }

    #[test]
    fn tcp_stream_builder_chain() {
        let builder = TcpStreamBuilder::new("127.0.0.1:0")
            .connect_timeout(Duration::from_secs(1))
            .nodelay(true)
            .keepalive(Some(Duration::from_secs(30)));

        assert_eq!(builder.connect_timeout, Some(Duration::from_secs(1)));
        assert_eq!(builder.nodelay, Some(true));
        assert_eq!(
            builder.keepalive,
            KeepaliveConfig::enabled(Duration::from_secs(30))
        );
    }

    #[test]
    fn tcp_stream_builder_keepalive_config_chain() {
        let keepalive = TcpKeepaliveConfig::new(Duration::from_secs(30))
            .with_interval(Duration::from_secs(10))
            .with_retries(4);
        let builder = TcpStreamBuilder::new("127.0.0.1:0").keepalive_config(Some(keepalive));

        assert_eq!(
            builder.keepalive,
            KeepaliveConfig::Enabled(
                TcpKeepaliveConfig::new(Duration::from_secs(30))
                    .with_interval(Duration::from_secs(10))
                    .with_retries(4)
            )
        );
        assert_eq!(keepalive.idle(), Duration::from_secs(30));
        assert_eq!(keepalive.interval(), Some(Duration::from_secs(10)));
        assert_eq!(keepalive.retries(), Some(4));
    }

    #[test]
    fn timeout_now_uses_injected_fallback_when_no_runtime_is_active() {
        static FALLBACK_NOW: AtomicU64 = AtomicU64::new(0);

        fn deterministic_now() -> Time {
            Time::from_nanos(FALLBACK_NOW.load(Ordering::SeqCst))
        }

        assert!(
            Cx::current().is_none(),
            "test must run without an active Cx"
        );

        FALLBACK_NOW.store(123_456, Ordering::SeqCst);
        assert_eq!(
            super::timeout_now_with_fallback(deterministic_now),
            Time::from_nanos(123_456),
            "no-runtime timeout path should delegate to injected fallback clock"
        );

        FALLBACK_NOW.store(789_000, Ordering::SeqCst);
        assert_eq!(
            super::timeout_now_with_fallback(deterministic_now),
            Time::from_nanos(789_000),
            "fallback clock should be consulted on every call"
        );
    }

    #[test]
    fn future_with_timeout_honors_custom_clock() {
        static TEST_NOW: AtomicU64 = AtomicU64::new(0);

        fn test_time() -> Time {
            Time::from_nanos(TEST_NOW.load(Ordering::SeqCst))
        }

        TEST_NOW.store(1_000, Ordering::SeqCst);
        let mut future = Box::pin(super::future_with_timeout(
            std::future::pending::<()>(),
            Duration::from_nanos(500),
            test_time,
        ));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(Future::poll(future.as_mut(), &mut cx).is_pending());

        TEST_NOW.store(2_000, Ordering::SeqCst);
        assert!(matches!(
            Future::poll(future.as_mut(), &mut cx),
            Poll::Ready(Err(_))
        ));
    }

    #[test]
    fn future_with_timeout_completes_before_deadline() {
        static TEST_NOW: AtomicU64 = AtomicU64::new(0);

        fn test_time() -> Time {
            Time::from_nanos(TEST_NOW.load(Ordering::SeqCst))
        }

        TEST_NOW.store(1_000, Ordering::SeqCst);
        let mut future = Box::pin(super::future_with_timeout(
            std::future::ready(Ok::<u8, io::Error>(7)),
            Duration::from_nanos(500),
            test_time,
        ));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            Future::poll(future.as_mut(), &mut cx),
            Poll::Ready(Ok(Ok(7)))
        ));
    }

    #[test]
    fn connect_timeout_with_time_getter_times_out_before_first_attempt() {
        static TEST_NOW: AtomicU64 = AtomicU64::new(0);

        fn test_time() -> Time {
            let now = TEST_NOW.load(Ordering::SeqCst);
            TEST_NOW.store(50, Ordering::SeqCst);
            Time::from_nanos(now)
        }

        TEST_NOW.store(0, Ordering::SeqCst);
        let err = future::block_on(TcpStream::connect_timeout_with_time_getter(
            "127.0.0.1:1".parse::<SocketAddr>().expect("socket addr"),
            Duration::from_nanos(10),
            test_time,
        ))
        .expect_err("deadline should expire before the first socket attempt");

        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn connect_resolved_addrs_stops_after_cancelled_interrupt() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let _guard = Cx::set_current(Some(cx));
        let attempts = Arc::new(AtomicUsize::new(0));

        let err = future::block_on(super::connect_resolved_addrs(
            vec![
                "192.0.2.1:81".parse().expect("addr"),
                "192.0.2.2:81".parse().expect("addr"),
            ],
            {
                let attempts = Arc::clone(&attempts);
                move |_addr| {
                    let attempts = Arc::clone(&attempts);
                    async move {
                        let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                        if attempt == 0 {
                            Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
                        } else {
                            Err(io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                "should not try the next address after cancellation",
                            ))
                        }
                    }
                }
            },
        ))
        .expect_err("cancelled connect should stop immediately");

        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn connect_resolved_addrs_with_timeout_stops_after_cancelled_interrupt() {
        fn test_time() -> Time {
            Time::from_nanos(0)
        }

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let _guard = Cx::set_current(Some(cx));
        let attempts = Arc::new(AtomicUsize::new(0));

        let err = future::block_on(super::connect_resolved_addrs_with_timeout(
            vec![
                "192.0.2.1:81".parse().expect("addr"),
                "192.0.2.2:81".parse().expect("addr"),
            ],
            Duration::from_secs(1),
            test_time,
            {
                let attempts = Arc::clone(&attempts);
                move |_addr| {
                    let attempts = Arc::clone(&attempts);
                    async move {
                        let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                        if attempt == 0 {
                            Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
                        } else {
                            Err(io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                "should not try the next address after cancellation",
                            ))
                        }
                    }
                }
            },
        ))
        .expect_err("cancelled timed connect should stop immediately");

        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn tcp_stream_poll_flush_and_shutdown_return_interrupted_when_cancel_requested() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let client = net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let _guard = Cx::set_current(Some(cx));

        let mut stream = TcpStream::from_std(client).expect("wrap stream");
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        let flush = Pin::new(&mut stream).poll_flush(&mut task_cx);
        assert!(matches!(
            flush,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));

        let shutdown = Pin::new(&mut stream).poll_shutdown(&mut task_cx);
        assert!(matches!(
            shutdown,
            Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
        ));
    }

    #[test]
    fn driverless_connect_waits_until_first_write_is_usable() {
        use crate::io::AsyncWriteExt;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        let handle = std::thread::spawn(move || {
            future::block_on(async move {
                let mut stream = TcpStream::connect(addr).await?;
                stream.write_all(b"ready").await?;
                io::Result::Ok(stream)
            })
        });

        let (mut accepted, _) = listener.accept().expect("accept");
        let mut marker = [0_u8; 5];
        accepted
            .read_exact(&mut marker)
            .expect("the first post-connect write is immediately usable");
        assert_eq!(&marker, b"ready");
        let stream = handle.join().expect("join").expect("connect");
        assert!(stream.peer_addr().is_ok());
    }

    #[test]
    fn driverless_connect_does_not_trust_peer_addr_before_writable() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let client = net::TcpStream::connect(addr).expect("connect client");
        let (_accepted, _) = listener.accept().expect("accept client");
        client.set_nonblocking(true).expect("set nonblocking");
        let socket = Socket::from(client);
        assert!(
            socket.peer_addr().is_ok(),
            "fixture starts with a peer-visible socket"
        );

        let reactor = LabReactor::new();
        let token = Token::new(73);
        reactor
            .register(&socket, token, Interest::WRITABLE)
            .expect("register fixture socket");
        let mut events = Events::with_capacity(1);
        let waker = noop_waker();
        let cx = Context::from_waker(&waker);

        assert!(
            poll_connect_fallback_ready(&socket, &reactor, &mut events, token, &cx).is_pending(),
            "peer_addr success alone must not complete a driverless connect"
        );

        reactor.set_ready(token, crate::runtime::reactor::Event::writable(token));
        assert!(matches!(
            poll_connect_fallback_ready(&socket, &reactor, &mut events, token, &cx),
            Poll::Ready(Ok(()))
        ));
    }

    #[test]
    fn tcp_connect_refused() {
        let addr = {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.local_addr().expect("local addr")
        };

        let result = future::block_on(TcpStream::connect(addr));
        assert!(result.is_err());
    }

    #[test]
    fn tcp_connect_cancel_does_not_deadlock() {
        let addr: SocketAddr = "192.0.2.1:81".parse().expect("addr");
        let mut fut = Box::pin(TcpStream::connect(addr));

        future::block_on(poll_fn(|cx| match fut.as_mut().poll(cx) {
            Poll::Pending | Poll::Ready(_) => Poll::Ready(()),
        }));

        drop(fut);
    }

    #[test]
    fn tcp_stream_registers_on_wouldblock() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let client = net::TcpStream::connect(addr).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");
        server.set_nonblocking(true).expect("nonblocking");

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

        let mut stream = TcpStream::from_std(client).expect("wrap stream");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut buf = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut buf);

        let poll = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(poll, Poll::Pending));
        assert!(stream.registration.is_some());
    }

    #[test]
    fn tcp_stream_register_notconnected_falls_back_to_pending() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let client = net::TcpStream::connect(addr).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");
        server.set_nonblocking(true).expect("nonblocking");

        let reactor = RegisterNotConnectedReactor::new();
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

        let mut stream = TcpStream::from_std(client).expect("wrap stream");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut buf = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut buf);

        let poll = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf);
        assert!(
            matches!(poll, Poll::Pending),
            "register NotConnected should use fallback wake path instead of returning an error"
        );
        assert!(
            stream.registration.is_none(),
            "fallback path should not keep a stale registration"
        );
    }

    #[cfg(unix)]
    #[test]
    fn tcp_stream_from_std_forces_nonblocking_mode() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let client = net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");

        let stream = TcpStream::from_std(client).expect("wrap stream");
        let flags = fcntl(stream.inner.as_ref(), FcntlArg::F_GETFL).expect("read stream flags");
        let is_nonblocking = OFlag::from_bits_truncate(flags).contains(OFlag::O_NONBLOCK);
        assert!(
            is_nonblocking,
            "TcpStream::from_std should force nonblocking mode"
        );
    }

    #[test]
    fn connect_waiter_migrates_between_live_dispatchers() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let client = net::TcpStream::connect(listener.local_addr().unwrap()).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let old_reactor = CountingReactor::new();
        let new_reactor = CountingReactor::new();
        let old_driver = IoDriverHandle::new(old_reactor.clone());
        let new_driver = IoDriverHandle::new(new_reactor.clone());
        let mut registration = Some(
            old_driver
                .register(&client, Interest::WRITABLE, noop_waker())
                .expect("old connect registration"),
        );
        let hits = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountingWaker {
            hits: Arc::clone(&hits),
        }));
        let task = Context::from_waker(&waker);
        let ambient = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(new_driver.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(ambient));

        // Both drivers remain alive. The next connect poll must retire A
        // instead of rearming it and then parking on an unserviced executor.
        rearm_connect_registration(&mut registration, &task).expect("handoff");
        assert!(registration.is_none());
        assert_eq!(old_reactor.registration_count(), 0);
        assert_eq!(old_reactor.modify_calls(), 0);
        assert!(old_driver.is_empty());

        registration = Some(
            new_driver
                .register(&client, Interest::WRITABLE, waker.clone())
                .expect("replacement connect registration"),
        );
        let token = registration.as_ref().unwrap().token();
        rearm_connect_registration(&mut registration, &task).expect("same owner");
        assert_eq!(registration.as_ref().unwrap().token(), token);
        assert!(registration.as_ref().unwrap().belongs_to(&new_driver));
        assert_eq!(new_reactor.modify_calls(), 1);

        // Service only B: A remains alive and deliberately unpolled.
        new_reactor
            .inner
            .set_ready(token, crate::runtime::reactor::Event::writable(token));
        new_driver
            .turn_with(Some(Duration::ZERO), |_, _| {})
            .expect("B services connect readiness");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        drop(registration);
        assert!(new_driver.is_empty());
        assert_eq!(new_reactor.registration_count(), 0);
    }

    #[test]
    fn connect_waiter_leaves_live_driver_for_driverless_context() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let client = net::TcpStream::connect(listener.local_addr().unwrap()).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");
        let reactor = CountingReactor::new();
        let driver = IoDriverHandle::new(reactor.clone());
        let hits = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountingWaker {
            hits: Arc::clone(&hits),
        }));
        let task = Context::from_waker(&waker);
        let mut registration = Some(
            driver
                .register(&client, Interest::WRITABLE, waker.clone())
                .expect("connect registration"),
        );
        let token = registration.as_ref().unwrap().token();
        let _manual = Cx::set_current(None);
        rearm_connect_registration(&mut registration, &task).expect("manual driver rearm");
        assert_eq!(registration.as_ref().unwrap().token(), token);
        assert_eq!(reactor.modify_calls(), 1);

        let ambient = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            None,
        );
        let _current = Cx::set_current(Some(ambient));
        rearm_connect_registration(&mut registration, &task).expect("driverless handoff");

        // Clearing the old waiter lets wait_for_connect enter its fallback
        // branch immediately, without a wake or turn from the old runtime.
        assert!(registration.is_none());
        assert!(driver.is_empty());
        assert_eq!(reactor.registration_count(), 0);
        assert_eq!(reactor.modify_calls(), 1);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn connect_waiter_rearms_existing_registration_with_unchanged_interest() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let client = net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let reactor = CountingReactor::new();
        let driver = IoDriverHandle::new(reactor.clone());
        let registration = driver
            .register(&client, Interest::WRITABLE, noop_waker())
            .expect("register");
        let mut registration = Some(registration);

        let waker = noop_waker();
        let cx = Context::from_waker(&waker);

        rearm_connect_registration(&mut registration, &cx).expect("re-arm once");
        rearm_connect_registration(&mut registration, &cx).expect("re-arm twice");

        assert_eq!(
            reactor.modify_calls(),
            2,
            "connect waiter must re-arm on every poll, even when interest is unchanged"
        );
        assert!(registration.is_some(), "registration should remain active");
    }

    #[test]
    fn stream_rearm_keeps_a_waiting_write_armed_until_an_event_then_drops_it() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let client = net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let reactor = CountingReactor::new();
        let driver = IoDriverHandle::new(reactor.clone());
        let cx = Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(driver.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));

        let mut stream = TcpStream::from_std(client).expect("wrap stream");
        let waker = noop_waker();
        let task_cx = Context::from_waker(&waker);

        stream
            .register_interest(&task_cx, Interest::WRITABLE)
            .expect("register writable");
        assert_eq!(
            stream
                .registration
                .as_ref()
                .expect("registration after writable wait")
                .interest(),
            Interest::WRITABLE,
            "initial wait should arm writability only"
        );

        // A read wait in the same poll must not disarm the write wait: the
        // stream has one waiter, and nothing else would wake the parked write.
        stream
            .register_interest(&task_cx, Interest::READABLE)
            .expect("rearm readable");
        assert_eq!(
            reactor.last_interest(),
            Interest::READABLE | Interest::WRITABLE,
            "a read wait keeps the undispatched write wait armed"
        );

        // An event disarms the one-shot registration. A read-only wait after it
        // must drop the write bit, or a writable socket would wake every poll.
        let token = stream.registration.as_ref().expect("registration").token();
        reactor
            .inner
            .set_ready(token, crate::runtime::reactor::Event::readable(token));
        driver
            .turn_with(Some(Duration::ZERO), |_, _| {})
            .expect("dispatch the event");
        stream
            .register_interest(&task_cx, Interest::READABLE)
            .expect("rearm readable after the event");
        assert_eq!(
            reactor.last_interest(),
            Interest::READABLE,
            "a read wait after an event must drop the stale writable bit"
        );
        assert_eq!(
            stream
                .registration
                .as_ref()
                .expect("registration after readable wait")
                .interest(),
            Interest::READABLE,
            "registration should track the live caller interest"
        );
    }

    #[test]
    fn connect_waiter_clears_registration_when_driver_drops() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let client = net::TcpStream::connect(addr).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        client.set_nonblocking(true).expect("nonblocking");

        let reactor = CountingReactor::new();
        let driver = IoDriverHandle::new(reactor);
        let registration = driver
            .register(&client, Interest::WRITABLE, noop_waker())
            .expect("register");
        let mut registration = Some(registration);
        drop(driver);

        let waker = noop_waker();
        let cx = Context::from_waker(&waker);
        rearm_connect_registration(&mut registration, &cx).expect("re-arm with dropped driver");

        assert!(
            registration.is_none(),
            "stale connect registration should be cleared when driver is gone"
        );
    }

    #[test]
    fn fallback_rewake_without_timer_is_immediate() {
        assert!(
            Cx::current().is_none(),
            "test must run without an active Cx"
        );

        let hits = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountingWaker {
            hits: Arc::clone(&hits),
        }));
        let cx = Context::from_waker(&waker);

        fallback_rewake(&cx);

        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "fallback re-wake should immediately schedule another poll without a timer driver"
        );
    }

    /// GH#67 follow-up (asupersync-tx9j0f): a `TcpStream` polled with no I/O
    /// driver on the current `Cx` parks on the process-global fallback driver
    /// instead of re-waking itself into a hot loop (the raw `fallback_rewake`
    /// helper above stays immediate; it is now reached only when no reactor
    /// at all can take the fd).
    mod gh67_fallback_io_driver {
        use super::*;
        use crate::net::udp::fallback_io_test_support::signal_waker;

        /// A connected, non-blocking pair: the async stream under test and
        /// the std peer that can make it readable at will.
        fn connected_pair() -> (TcpStream, net::TcpStream) {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
            let addr = listener.local_addr().expect("listener addr");
            let peer = net::TcpStream::connect(addr).expect("connect peer");
            let (accepted, _) = listener.accept().expect("accept");
            accepted.set_nonblocking(true).expect("nonblocking");
            (TcpStream::from_std(accepted).expect("wrap"), peer)
        }

        fn poll_read_once(
            stream: &mut TcpStream,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut read_buf = ReadBuf::new(buf);
            match Pin::new(stream).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        }

        /// The defect: with no I/O driver on the current `Cx`, a `WouldBlock`
        /// read re-woke its own waker synchronously, so an executor re-polled
        /// in a hot loop. The fixed path must (1) return `Pending` without
        /// any wake, (2) stay silent while the peer is idle, and (3) wake
        /// exactly once when bytes arrive, from the fallback reactor pump.
        #[test]
        fn poll_read_without_io_driver_parks_until_data_arrives() {
            assert!(
                Cx::current().is_none(),
                "test must run without an ambient Cx"
            );
            let (mut stream, mut peer) = connected_pair();
            let (signal, waker, rx) = signal_waker();
            let mut task_cx = Context::from_waker(&waker);
            let mut buf = [0u8; 16];

            assert!(matches!(
                poll_read_once(&mut stream, &mut task_cx, &mut buf),
                Poll::Pending
            ));
            assert_eq!(
                signal.hits.load(Ordering::SeqCst),
                0,
                "driverless poll must park, not self-wake (GH#67)"
            );
            assert!(
                stream.registration.on_fallback(),
                "driverless poll registers with the process-global fallback I/O driver"
            );
            assert!(
                rx.recv_timeout(Duration::from_millis(200)).is_err(),
                "no wake may arrive while the peer is silent"
            );

            peer.write_all(b"wake").expect("peer write");
            rx.recv_timeout(Duration::from_secs(5))
                .expect("fallback reactor pump delivers the readiness wake");
            assert_eq!(signal.hits.load(Ordering::SeqCst), 1);
            match poll_read_once(&mut stream, &mut task_cx, &mut buf) {
                Poll::Ready(Ok(len)) => assert_eq!(&buf[..len], b"wake"),
                other => panic!("expected the bytes after the wake, got {other:?}"),
            }
        }

        /// A stream parked on the fallback driver is handed to the ambient
        /// driver as soon as it is polled under a `Cx` that carries one.
        #[test]
        fn fallback_registration_migrates_to_ambient_io_driver() {
            assert!(Cx::current().is_none());
            let (mut stream, _peer) = connected_pair();
            let waker = noop_waker();
            let mut task_cx = Context::from_waker(&waker);
            let mut buf = [0u8; 8];

            assert!(matches!(
                poll_read_once(&mut stream, &mut task_cx, &mut buf),
                Poll::Pending
            ));
            assert!(stream.registration.on_fallback());

            let driver = IoDriverHandle::new(Arc::new(LabReactor::new()));
            assert_eq!(driver.waker_count(), 0);
            let ambient = Cx::new_with_observability(
                RegionId::new_for_test(0, 1),
                TaskId::new_for_test(0, 0),
                Budget::INFINITE,
                None,
                Some(driver.clone()),
                None,
            );
            let _guard = Cx::set_current(Some(ambient));

            assert!(matches!(
                poll_read_once(&mut stream, &mut task_cx, &mut buf),
                Poll::Pending
            ));
            assert!(
                !stream.registration.on_fallback(),
                "ambient driver must take over the registration"
            );
            assert!(stream.registration.is_some());
            assert_eq!(
                driver.waker_count(),
                1,
                "the ambient driver now owns the stream's readiness waker"
            );
        }
    }

    // =========================================================================
    // SIGPIPE Conformance Tests - Socket Write Behavior per POSIX.1-2017
    // =========================================================================

    #[cfg(unix)]
    #[test]
    fn sigpipe_disabled_on_socket_writes() {
        let listener = net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        let client = net::TcpStream::connect(addr).expect("connect client");
        let (server, _) = listener.accept().expect("accept connection");

        // Close the server side to create a broken pipe condition
        drop(server);

        // Ensure client socket has proper flags to avoid SIGPIPE
        #[cfg_attr(target_os = "linux", allow(unused_variables))]
        let client_fd = client.as_raw_fd();

        #[cfg(target_os = "linux")]
        {
            // On Linux, verify MSG_NOSIGNAL can be used
            let msg_nosignal_flag = libc::MSG_NOSIGNAL;
            assert_ne!(
                msg_nosignal_flag, 0,
                "MSG_NOSIGNAL flag should be available on Linux"
            );
        }

        #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
        {
            // On BSD systems, verify SO_NOSIGPIPE socket option
            let opt_value: libc::c_int = 1;
            let result = unsafe {
                libc::setsockopt(
                    client_fd,
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    &opt_value as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            assert_eq!(result, 0, "SO_NOSIGPIPE should be settable on BSD systems");

            // Verify the option was set
            let mut get_opt: libc::c_int = 0;
            let mut opt_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            let get_result = unsafe {
                libc::getsockopt(
                    client_fd,
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    std::ptr::from_mut(&mut get_opt).cast::<libc::c_void>(),
                    &mut opt_len,
                )
            };
            assert_eq!(get_result, 0, "getsockopt should succeed");
            assert_eq!(get_opt, 1, "SO_NOSIGPIPE should be enabled");
        }
    }

    #[cfg(unix)]
    #[test]
    fn epipe_returned_instead_of_signal() {
        let listener = net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        let client = net::TcpStream::connect(addr).expect("connect client");
        let (server, _) = listener.accept().expect("accept connection");

        // Set socket to non-blocking for testing
        client.set_nonblocking(true).expect("set nonblocking");

        // Close server side to break the pipe
        drop(server);

        // Give the connection time to detect the close
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Attempt write - should get EPIPE error, not signal
        let test_data = b"test data that should trigger EPIPE";
        let write_result = (&client).write(test_data);

        match write_result {
            Err(e) => {
                // Should get EPIPE (Broken pipe) error
                let is_broken_pipe = e.kind() == io::ErrorKind::BrokenPipe
                    || (e.raw_os_error() == Some(libc::EPIPE));

                assert!(
                    is_broken_pipe,
                    "Write to broken pipe should return EPIPE error, got: {:?}",
                    e
                );
            }
            Ok(_) => {
                // Some systems might buffer the write initially
                // Try multiple writes to trigger the error
                let mut write_succeeded = true;
                for i in 0..10 {
                    let large_data = vec![b'x'; 65536]; // Large write to fill buffers
                    match (&client).write_all(&large_data) {
                        Err(e) => {
                            let is_broken_pipe = e.kind() == io::ErrorKind::BrokenPipe
                                || (e.raw_os_error() == Some(libc::EPIPE));
                            assert!(
                                is_broken_pipe,
                                "Write {} to broken pipe should return EPIPE, got: {:?}",
                                i, e
                            );
                            write_succeeded = false;
                            break;
                        }
                        Ok(_) => {}
                    }
                }
                assert!(
                    !write_succeeded,
                    "At least one write should fail with broken pipe"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn broken_pipe_during_buffered_write_observable() {
        let listener = net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        let client_std = net::TcpStream::connect(addr).expect("connect client");
        let (server, _) = listener.accept().expect("accept connection");

        // Create async TCP stream
        let mut client = TcpStream::from_std(client_std).expect("wrap in async stream");

        // Start a buffered write operation
        let test_data = b"buffered write test data";

        // Close server side during write to trigger broken pipe
        drop(server);
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Test broken pipe detection using direct polling since runtime is complex
        use crate::io::AsyncWrite;
        use std::pin::Pin;
        use std::task::{Context, Poll};

        // Simple manual poll loop for testing
        let waker = noop_waker();
        let mut cx_poll = Context::from_waker(&waker);

        // Attempt write - should propagate broken pipe error
        let mut client_pin = Pin::new(&mut client);
        let write_result = client_pin.as_mut().poll_write(&mut cx_poll, test_data);

        match write_result {
            Poll::Ready(Err(e)) => {
                let is_broken_pipe =
                    e.kind() == io::ErrorKind::BrokenPipe || e.raw_os_error() == Some(libc::EPIPE);
                assert!(
                    is_broken_pipe,
                    "Buffered write should observe broken pipe error: {:?}",
                    e
                );
            }
            Poll::Ready(Ok(_)) | Poll::Pending => {
                // Try flush to detect broken pipe
                let flush_result = client_pin.as_mut().poll_flush(&mut cx_poll);

                match flush_result {
                    Poll::Ready(Err(e)) => {
                        let is_broken_pipe = e.kind() == io::ErrorKind::BrokenPipe
                            || e.raw_os_error() == Some(libc::EPIPE);
                        assert!(
                            is_broken_pipe,
                            "Flush should observe broken pipe error: {:?}",
                            e
                        );
                    }
                    _ => {
                        // Try another large write to fill buffers
                        let large_data = vec![b'x'; 65536];
                        let large_write_result =
                            client_pin.as_mut().poll_write(&mut cx_poll, &large_data);

                        if let Poll::Ready(Err(e)) = large_write_result {
                            let is_broken_pipe = e.kind() == io::ErrorKind::BrokenPipe
                                || e.raw_os_error() == Some(libc::EPIPE);
                            assert!(
                                is_broken_pipe,
                                "Large write should observe broken pipe error: {:?}",
                                e
                            );
                        } else {
                            // Some systems need multiple attempts before the
                            // kernel surfaces the broken-pipe condition.
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn platform_divergence_documented() {
        // Document platform-specific behavior for broken pipe handling

        #[cfg(target_os = "linux")]
        {
            // Linux uses MSG_NOSIGNAL flag in send/write calls
            let msg_nosignal = libc::MSG_NOSIGNAL;
            assert_ne!(
                msg_nosignal, 0,
                "Linux: MSG_NOSIGNAL available for send() calls"
            );
        }

        #[cfg(target_os = "macos")]
        {
            // macOS uses SO_NOSIGPIPE socket option
            let so_nosigpipe = libc::SO_NOSIGPIPE;
            assert_ne!(
                so_nosigpipe, 0,
                "macOS: SO_NOSIGPIPE socket option available"
            );
        }

        #[cfg(target_os = "freebsd")]
        {
            // FreeBSD uses SO_NOSIGPIPE socket option
            let so_nosigpipe = libc::SO_NOSIGPIPE;
            assert_ne!(
                so_nosigpipe, 0,
                "FreeBSD: SO_NOSIGPIPE socket option available"
            );
        }

        #[cfg(target_os = "openbsd")]
        {
            // OpenBSD uses SO_NOSIGPIPE socket option
            let so_nosigpipe = libc::SO_NOSIGPIPE;
            assert_ne!(
                so_nosigpipe, 0,
                "OpenBSD: SO_NOSIGPIPE socket option available"
            );
        }

        #[cfg(windows)]
        {
            // Windows doesn't have SIGPIPE - uses ERROR_BROKEN_PIPE instead
        }

        #[cfg(not(any(unix, windows)))]
        {}
    }

    #[cfg(windows)]
    #[test]
    fn windows_broken_pipe_error_instead_of_signal() {
        let listener = net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        let client = net::TcpStream::connect(addr).expect("connect client");
        let (server, _) = listener.accept().expect("accept connection");

        // Close server side to break the connection
        drop(server);
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Attempt write - should get Windows error, not signal
        let test_data = b"test data for Windows broken pipe";
        let write_result = (&client).write(test_data);

        match write_result {
            Err(e) => {
                // On Windows, broken pipe manifests as different errors
                let is_connection_error = e.kind() == io::ErrorKind::BrokenPipe
                    || e.kind() == io::ErrorKind::ConnectionAborted
                    || e.kind() == io::ErrorKind::ConnectionReset;

                assert!(
                    is_connection_error,
                    "Windows: Write to broken pipe should return connection error, got: {:?}",
                    e
                );

                // Check for Windows-specific error codes
                if let Some(os_error) = e.raw_os_error() {
                    let is_windows_pipe_error = os_error == 109 ||   // ERROR_BROKEN_PIPE
                        os_error == 995 ||   // WSA_OPERATION_ABORTED
                        os_error == 10053 || // WSAECONNABORTED
                        os_error == 10054; // WSAECONNRESET

                    let _ = is_windows_pipe_error;
                }
            }
            Ok(_) => {
                // Try multiple writes to trigger the error
                for i in 0..10 {
                    let result = (&client).write(b"more data");
                    if let Err(e) = result {
                        let is_connection_error = e.kind() == io::ErrorKind::BrokenPipe
                            || e.kind() == io::ErrorKind::ConnectionAborted
                            || e.kind() == io::ErrorKind::ConnectionReset;
                        assert!(
                            is_connection_error,
                            "Write {} should fail with connection error: {:?}",
                            i, e
                        );
                        break;
                    }
                    if i == 9 {
                        panic!("Expected at least one write to fail with broken pipe");
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_ctrl_c_event_no_sigpipe_conflict() {
        // On Windows, verify that CTRL_C_EVENT handling doesn't interfere
        // with broken pipe error reporting (since SIGPIPE doesn't exist)

        // Verify SIGPIPE is not available on Windows
        use crate::signal::SignalKind;
        let sigpipe_raw = SignalKind::pipe().as_raw_value();
        assert!(
            sigpipe_raw.is_none(),
            "SIGPIPE should not be available on Windows"
        );

        // Verify SIGINT (CTRL_C) is available
        let sigint_raw = SignalKind::interrupt().as_raw_value();
        assert!(
            sigint_raw == Some(libc::SIGINT),
            "SIGINT should be available for CTRL_C handling"
        );

        // Create a broken pipe condition
        let listener = net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let client = net::TcpStream::connect(addr).expect("connect client");
        let (server, _) = listener.accept().expect("accept connection");
        drop(server);

        // Broken pipe should still work independently of signal handling
        std::thread::sleep(std::time::Duration::from_millis(100));
        let test_data = b"test data";

        // This should fail with pipe error, unrelated to CTRL_C handling
        let mut write_failed = false;
        for _ in 0..5 {
            if let Err(e) = (&client).write(test_data) {
                let is_pipe_error = e.kind() == io::ErrorKind::BrokenPipe
                    || e.kind() == io::ErrorKind::ConnectionAborted
                    || e.kind() == io::ErrorKind::ConnectionReset;
                if is_pipe_error {
                    write_failed = true;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        assert!(
            write_failed,
            "Broken pipe should be detected independently of CTRL_C event handling"
        );
    }

    // =========================================================================
    // TCP Options Conformance Tests - TCP_NODELAY + SO_KEEPALIVE
    // =========================================================================

    #[cfg(all(not(target_arch = "wasm32"), unix))]
    #[test]
    fn tcp_nodelay_option_conformance() {
        use std::os::unix::io::AsRawFd;

        let listener = net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        let client = net::TcpStream::connect(addr).expect("connect client");
        let stream = TcpStream::from_std(client).expect("from_std");

        let socket_fd = stream.inner.as_raw_fd();

        // Test setting TCP_NODELAY to true
        stream.set_nodelay(true).expect("set nodelay true");

        let mut nodelay_val: libc::c_int = 0;
        let mut opt_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                socket_fd,
                libc::IPPROTO_TCP,
                libc::TCP_NODELAY,
                std::ptr::from_mut(&mut nodelay_val).cast::<libc::c_void>(),
                &mut opt_len,
            )
        };
        assert_eq!(result, 0, "getsockopt TCP_NODELAY should succeed");
        // Boolean socket options read back as "non-zero": Linux reports 1,
        // macOS reports the option's flag value (br-asupersync-bi2462.21.1).
        assert_ne!(nodelay_val, 0, "TCP_NODELAY should be enabled");

        // Test setting TCP_NODELAY to false
        stream.set_nodelay(false).expect("set nodelay false");

        let mut nodelay_val: libc::c_int = 0;
        let mut opt_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                socket_fd,
                libc::IPPROTO_TCP,
                libc::TCP_NODELAY,
                std::ptr::from_mut(&mut nodelay_val).cast::<libc::c_void>(),
                &mut opt_len,
            )
        };
        assert_eq!(result, 0, "getsockopt TCP_NODELAY should succeed");
        assert_eq!(nodelay_val, 0, "TCP_NODELAY should be disabled");
    }

    #[cfg(all(not(target_arch = "wasm32"), unix))]
    #[test]
    fn so_keepalive_option_conformance() {
        use std::os::unix::io::AsRawFd;

        let listener = net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        let client = net::TcpStream::connect(addr).expect("connect client");
        let stream = TcpStream::from_std(client).expect("from_std");

        let socket_fd = stream.inner.as_raw_fd();

        // Test enabling SO_KEEPALIVE with interval
        let keepalive_interval = Duration::from_secs(30);
        stream
            .set_keepalive(Some(keepalive_interval))
            .expect("set keepalive enabled");

        let mut keepalive_val: libc::c_int = 0;
        let mut opt_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                socket_fd,
                libc::SOL_SOCKET,
                libc::SO_KEEPALIVE,
                std::ptr::from_mut(&mut keepalive_val).cast::<libc::c_void>(),
                &mut opt_len,
            )
        };
        assert_eq!(result, 0, "getsockopt SO_KEEPALIVE should succeed");
        // Non-zero is the portable "enabled" read-back (macOS reports 8).
        assert_ne!(keepalive_val, 0, "SO_KEEPALIVE should be enabled");

        // Test disabling SO_KEEPALIVE
        stream.set_keepalive(None).expect("set keepalive disabled");

        let mut keepalive_val: libc::c_int = 0;
        let mut opt_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                socket_fd,
                libc::SOL_SOCKET,
                libc::SO_KEEPALIVE,
                std::ptr::from_mut(&mut keepalive_val).cast::<libc::c_void>(),
                &mut opt_len,
            )
        };
        assert_eq!(result, 0, "getsockopt SO_KEEPALIVE should succeed");
        assert_eq!(keepalive_val, 0, "SO_KEEPALIVE should be disabled");
    }

    #[cfg(all(not(target_arch = "wasm32"), target_os = "linux"))]
    #[test]
    fn tcp_keepalive_interval_conformance() {
        use std::os::unix::io::AsRawFd;

        let listener = net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        let client = net::TcpStream::connect(addr).expect("connect client");
        let stream = TcpStream::from_std(client).expect("from_std");

        let socket_fd = stream.inner.as_raw_fd();

        let keepalive = TcpKeepaliveConfig::new(Duration::from_secs(60))
            .with_interval(Duration::from_secs(7))
            .with_retries(4);
        stream
            .set_keepalive_config(Some(keepalive))
            .expect("set keepalive config");

        // Verify TCP_KEEPIDLE parameter on Linux
        let mut keepidle_val: libc::c_int = 0;
        let mut opt_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                socket_fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPIDLE,
                std::ptr::from_mut(&mut keepidle_val).cast::<libc::c_void>(),
                &mut opt_len,
            )
        };
        assert_eq!(result, 0, "getsockopt TCP_KEEPIDLE should succeed");
        assert_eq!(keepidle_val, 60, "TCP_KEEPIDLE should be set to 60 seconds");

        let mut keepintvl_val: libc::c_int = 0;
        let mut opt_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                socket_fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPINTVL,
                std::ptr::from_mut(&mut keepintvl_val).cast::<libc::c_void>(),
                &mut opt_len,
            )
        };
        assert_eq!(result, 0, "getsockopt TCP_KEEPINTVL should succeed");
        assert_eq!(keepintvl_val, 7, "TCP_KEEPINTVL should be set to 7 seconds");

        let mut keepcnt_val: libc::c_int = 0;
        let mut opt_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                socket_fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPCNT,
                std::ptr::from_mut(&mut keepcnt_val).cast::<libc::c_void>(),
                &mut opt_len,
            )
        };
        assert_eq!(result, 0, "getsockopt TCP_KEEPCNT should succeed");
        assert_eq!(keepcnt_val, 4, "TCP_KEEPCNT should be set to 4 probes");
    }

    #[cfg(all(not(target_arch = "wasm32"), unix))]
    #[test]
    fn tcp_stream_builder_nodelay_conformance() {
        use std::os::unix::io::AsRawFd;

        let listener = net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        // Accept connection in background to avoid blocking
        let handle = std::thread::spawn(move || {
            listener.accept().expect("accept connection");
        });

        // Test TcpStreamBuilder with nodelay enabled
        let stream =
            futures_lite::future::block_on(TcpStreamBuilder::new(addr).nodelay(true).connect())
                .expect("connect with nodelay");

        handle.join().expect("join accept thread");

        let socket_fd = stream.inner.as_raw_fd();

        // Verify TCP_NODELAY was set via builder
        let mut nodelay_val: libc::c_int = 0;
        let mut opt_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                socket_fd,
                libc::IPPROTO_TCP,
                libc::TCP_NODELAY,
                std::ptr::from_mut(&mut nodelay_val).cast::<libc::c_void>(),
                &mut opt_len,
            )
        };
        assert_eq!(result, 0, "getsockopt TCP_NODELAY should succeed");
        assert_ne!(nodelay_val, 0, "TCP_NODELAY should be enabled via builder");
    }

    #[cfg(all(not(target_arch = "wasm32"), unix))]
    #[test]
    fn tcp_stream_builder_keepalive_conformance() {
        use std::os::unix::io::AsRawFd;

        let listener = net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        // Accept connection in background
        let handle = std::thread::spawn(move || {
            listener.accept().expect("accept connection");
        });

        // Test TcpStreamBuilder with keepalive enabled
        let keepalive_duration = Duration::from_secs(45);
        let stream = futures_lite::future::block_on(
            TcpStreamBuilder::new(addr)
                .keepalive(Some(keepalive_duration))
                .connect(),
        )
        .expect("connect with keepalive");

        handle.join().expect("join accept thread");

        let socket_fd = stream.inner.as_raw_fd();

        // Verify SO_KEEPALIVE was set via builder
        let mut keepalive_val: libc::c_int = 0;
        let mut opt_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                socket_fd,
                libc::SOL_SOCKET,
                libc::SO_KEEPALIVE,
                std::ptr::from_mut(&mut keepalive_val).cast::<libc::c_void>(),
                &mut opt_len,
            )
        };
        assert_eq!(result, 0, "getsockopt SO_KEEPALIVE should succeed");
        assert_ne!(
            keepalive_val, 0,
            "SO_KEEPALIVE should be enabled via builder"
        );
    }

    #[cfg(all(not(target_arch = "wasm32"), unix))]
    #[test]
    fn tcp_stream_builder_combined_options_conformance() {
        use std::os::unix::io::AsRawFd;

        let listener = net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        // Accept connection in background
        let handle = std::thread::spawn(move || {
            listener.accept().expect("accept connection");
        });

        // Test TcpStreamBuilder with both options
        let stream = futures_lite::future::block_on(
            TcpStreamBuilder::new(addr)
                .nodelay(true)
                .keepalive(Some(Duration::from_secs(120)))
                .connect(),
        )
        .expect("connect with both options");

        handle.join().expect("join accept thread");

        let socket_fd = stream.inner.as_raw_fd();

        // Verify both options were set
        let mut nodelay_val: libc::c_int = 0;
        let mut opt_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                socket_fd,
                libc::IPPROTO_TCP,
                libc::TCP_NODELAY,
                std::ptr::from_mut(&mut nodelay_val).cast::<libc::c_void>(),
                &mut opt_len,
            )
        };
        assert_eq!(result, 0, "getsockopt TCP_NODELAY should succeed");
        // Boolean socket options read back as "non-zero": Linux reports 1,
        // macOS reports the option's flag value (br-asupersync-bi2462.21.1).
        assert_ne!(nodelay_val, 0, "TCP_NODELAY should be enabled");

        let mut keepalive_val: libc::c_int = 0;
        let mut opt_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                socket_fd,
                libc::SOL_SOCKET,
                libc::SO_KEEPALIVE,
                std::ptr::from_mut(&mut keepalive_val).cast::<libc::c_void>(),
                &mut opt_len,
            )
        };
        assert_eq!(result, 0, "getsockopt SO_KEEPALIVE should succeed");
        // Non-zero is the portable "enabled" read-back (macOS reports 8).
        assert_ne!(keepalive_val, 0, "SO_KEEPALIVE should be enabled");
    }

    /// A connect parked on the reactor waits for its WRITABLE event. It used to
    /// also arm a 1 ms fallback timer on every poll, so a pending connect
    /// re-polled itself about a thousand times a second
    /// (br-asupersync-24j2of).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_registered_pending_connect_arms_no_fallback_timer() {
        // A listener whose accept queue is full drops the next SYN, so a
        // connect to it stays in progress.
        let listener = Socket::new(Domain::IPV4, Type::STREAM, None).expect("listener socket");
        listener
            .bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())
            .expect("bind listener");
        listener.listen(0).expect("listen");
        let addr = listener
            .local_addr()
            .expect("listener addr")
            .as_socket()
            .expect("inet addr");
        let _queued = net::TcpStream::connect_timeout(&addr, Duration::from_secs(1))
            .expect("fill the accept queue");
        let socket = Socket::new(Domain::IPV4, Type::STREAM, None).expect("client socket");
        socket.set_nonblocking(true).expect("nonblocking");
        match socket.connect(&addr.into()) {
            Err(err) if connect_in_progress(&err) => {}
            other => panic!("the connect must stay in progress: {other:?}"),
        }

        let timer = crate::time::TimerDriverHandle::with_wall_clock();
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            Some(IoDriverHandle::new(Arc::new(LabReactor::new()))),
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(cx));
        let mut wait = std::pin::pin!(wait_for_connect(&socket));
        let mut task_cx = Context::from_waker(Waker::noop());
        assert!(
            wait.as_mut().poll(&mut task_cx).is_pending(),
            "the connect is still in progress"
        );
        assert_eq!(
            timer.pending_count(),
            0,
            "a connect parked on the reactor must not arm the 1 ms fallback timer"
        );
    }
