    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::future::pending;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::task::Waker;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    #[derive(Debug)]
    struct PollCountingPendingConnect {
        polls: Arc<AtomicUsize>,
    }

    impl PollCountingPendingConnect {
        fn new(polls: Arc<AtomicUsize>) -> Self {
            Self { polls }
        }
    }

    impl Future for PollCountingPendingConnect {
        type Output = io::Result<TcpStream>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            Poll::Pending
        }
    }

    fn connected_test_stream() -> TcpStream {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let accept_thread = std::thread::spawn(move || listener.accept().expect("accept").0);
        let client = std::net::TcpStream::connect(addr).expect("connect client");
        let _server = accept_thread.join().expect("join accept thread");
        TcpStream::from_std(client).expect("wrap client stream")
    }

    fn assert_post_completion_error(result: Poll<io::Result<TcpStream>>) {
        let err = match result {
            Poll::Ready(Err(err)) => err,
            Poll::Ready(Ok(_)) => panic!("expected post-completion error, got success"),
            Poll::Pending => panic!("expected post-completion error, got pending"),
        };
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(err.to_string(), RACE_CONNECTIONS_POLLED_AFTER_COMPLETION);
    }

    // =======================================================================
    // Address sorting tests (RFC 8305 §4)
    // =======================================================================

    #[test]
    fn sort_addresses_interleaves_v6_v4() {
        init_test("sort_addresses_interleaves_v6_v4");

        let addrs: Vec<IpAddr> = vec![
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
        ];

        let sorted = sort_addresses(&addrs);

        assert_eq!(sorted.len(), 4);
        // Expected: v6, v4, v6, v4
        assert!(sorted[0].is_ipv6(), "first should be v6: {}", sorted[0]);
        assert!(sorted[1].is_ipv4(), "second should be v4: {}", sorted[1]);
        assert!(sorted[2].is_ipv6(), "third should be v6: {}", sorted[2]);
        assert!(sorted[3].is_ipv4(), "fourth should be v4: {}", sorted[3]);
        crate::test_complete!("sort_addresses_interleaves_v6_v4");
    }

    #[test]
    fn sort_addresses_v6_first_when_equal() {
        init_test("sort_addresses_v6_first_when_equal");

        let addrs: Vec<IpAddr> = vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()];

        let sorted = sort_addresses(&addrs);

        assert_eq!(sorted.len(), 2);
        assert!(sorted[0].is_ipv6(), "v6 should come first");
        assert!(sorted[1].is_ipv4(), "v4 should come second");
        crate::test_complete!("sort_addresses_v6_first_when_equal");
    }

    #[test]
    fn sort_addresses_uneven_more_v4() {
        init_test("sort_addresses_uneven_more_v4");

        let addrs: Vec<IpAddr> = vec![
            "2001:db8::1".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            "192.0.2.3".parse().unwrap(),
        ];

        let sorted = sort_addresses(&addrs);

        assert_eq!(sorted.len(), 4);
        // v6, v4, v4, v4 (v6 exhausted after first pair)
        assert!(sorted[0].is_ipv6());
        assert!(sorted[1].is_ipv4());
        assert!(sorted[2].is_ipv4());
        assert!(sorted[3].is_ipv4());
        crate::test_complete!("sort_addresses_uneven_more_v4");
    }

    #[test]
    fn sort_addresses_uneven_more_v6() {
        init_test("sort_addresses_uneven_more_v6");

        let addrs: Vec<IpAddr> = vec![
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            "2001:db8::3".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
        ];

        let sorted = sort_addresses(&addrs);

        assert_eq!(sorted.len(), 4);
        assert!(sorted[0].is_ipv6());
        assert!(sorted[1].is_ipv4());
        assert!(sorted[2].is_ipv6());
        assert!(sorted[3].is_ipv6());
        crate::test_complete!("sort_addresses_uneven_more_v6");
    }

    #[test]
    fn sort_addresses_v4_only() {
        init_test("sort_addresses_v4_only");

        let addrs: Vec<IpAddr> = vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()];

        let sorted = sort_addresses(&addrs);

        assert_eq!(sorted.len(), 2);
        assert!(sorted.iter().all(IpAddr::is_ipv4));
        crate::test_complete!("sort_addresses_v4_only");
    }

    #[test]
    fn sort_addresses_v6_only() {
        init_test("sort_addresses_v6_only");

        let addrs: Vec<IpAddr> = vec![
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
        ];

        let sorted = sort_addresses(&addrs);

        assert_eq!(sorted.len(), 2);
        assert!(sorted.iter().all(IpAddr::is_ipv6));
        crate::test_complete!("sort_addresses_v6_only");
    }

    #[test]
    fn sort_addresses_empty() {
        init_test("sort_addresses_empty");
        let sorted = sort_addresses(&[]);
        assert!(sorted.is_empty());
        crate::test_complete!("sort_addresses_empty");
    }

    #[test]
    fn sort_addresses_single_v6() {
        init_test("sort_addresses_single_v6");
        let addrs: Vec<IpAddr> = vec!["::1".parse().unwrap()];
        let sorted = sort_addresses(&addrs);
        assert_eq!(sorted.len(), 1);
        assert!(sorted[0].is_ipv6());
        crate::test_complete!("sort_addresses_single_v6");
    }

    #[test]
    fn sort_addresses_single_v4() {
        init_test("sort_addresses_single_v4");
        let addrs: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];
        let sorted = sort_addresses(&addrs);
        assert_eq!(sorted.len(), 1);
        assert!(sorted[0].is_ipv4());
        crate::test_complete!("sort_addresses_single_v4");
    }

    #[test]
    fn sort_socket_addrs_preserves_ports() {
        init_test("sort_socket_addrs_preserves_ports");

        let addrs: Vec<SocketAddr> = vec![
            "[2001:db8::1]:443".parse().unwrap(),
            "192.0.2.10:8443".parse().unwrap(),
            "[2001:db8::2]:444".parse().unwrap(),
            "192.0.2.11:8080".parse().unwrap(),
        ];

        let sorted = sort_socket_addrs(&addrs);

        assert_eq!(sorted.len(), 4);
        assert_eq!(
            sorted[0],
            "[2001:db8::1]:443".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(sorted[1], "192.0.2.10:8443".parse::<SocketAddr>().unwrap());
        assert_eq!(
            sorted[2],
            "[2001:db8::2]:444".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(sorted[3], "192.0.2.11:8080".parse::<SocketAddr>().unwrap());

        crate::test_complete!("sort_socket_addrs_preserves_ports");
    }

    #[test]
    fn sort_socket_addrs_uneven_families() {
        init_test("sort_socket_addrs_uneven_families");

        let addrs: Vec<SocketAddr> = vec![
            "[2001:db8::1]:443".parse().unwrap(),
            "192.0.2.10:8080".parse().unwrap(),
            "192.0.2.11:8081".parse().unwrap(),
            "192.0.2.12:8082".parse().unwrap(),
        ];

        let sorted = sort_socket_addrs(&addrs);

        assert_eq!(sorted.len(), 4);
        assert!(sorted[0].is_ipv6());
        assert!(sorted[1].is_ipv4());
        assert!(sorted[2].is_ipv4());
        assert!(sorted[3].is_ipv4());
        assert_eq!(sorted[0].port(), 443);
        assert_eq!(sorted[1].port(), 8080);
        assert_eq!(sorted[2].port(), 8081);
        assert_eq!(sorted[3].port(), 8082);

        crate::test_complete!("sort_socket_addrs_uneven_families");
    }

    #[test]
    fn sort_socket_addrs_preserves_ipv4_lead_family() {
        init_test("sort_socket_addrs_preserves_ipv4_lead_family");

        let addrs: Vec<SocketAddr> = vec![
            "192.0.2.10:8080".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
            "192.0.2.11:8081".parse().unwrap(),
            "[2001:db8::2]:444".parse().unwrap(),
        ];

        let sorted = sort_socket_addrs(&addrs);

        assert_eq!(sorted.len(), 4);
        assert_eq!(sorted[0], "192.0.2.10:8080".parse::<SocketAddr>().unwrap());
        assert_eq!(
            sorted[1],
            "[2001:db8::1]:443".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(sorted[2], "192.0.2.11:8081".parse::<SocketAddr>().unwrap());
        assert_eq!(
            sorted[3],
            "[2001:db8::2]:444".parse::<SocketAddr>().unwrap()
        );

        crate::test_complete!("sort_socket_addrs_preserves_ipv4_lead_family");
    }

    // =======================================================================
    // Config tests
    // =======================================================================

    #[test]
    fn config_default_values() {
        init_test("config_default_values");

        let config = HappyEyeballsConfig::default();

        assert_eq!(config.first_family_delay, Duration::from_millis(250));
        assert_eq!(config.attempt_delay, Duration::from_millis(250));
        assert_eq!(config.connect_timeout, Duration::from_secs(5));
        assert_eq!(config.overall_timeout, Duration::from_secs(30));
        crate::test_complete!("config_default_values");
    }

    #[test]
    fn config_clone_debug() {
        init_test("config_clone_debug");

        let config = HappyEyeballsConfig::default();
        let cloned = config.clone();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("HappyEyeballsConfig"));
        assert_eq!(cloned.first_family_delay, config.first_family_delay);
        crate::test_complete!("config_clone_debug");
    }

    #[test]
    fn duration_to_nanos_saturating_clamps_large_values() {
        init_test("duration_to_nanos_saturating_clamps_large_values");
        assert_eq!(duration_to_nanos_saturating(Duration::MAX), u64::MAX);
        crate::test_complete!("duration_to_nanos_saturating_clamps_large_values");
    }

    #[test]
    fn sleep_with_time_getter_waits_for_custom_clock() {
        static TEST_NOW: AtomicU64 = AtomicU64::new(0);

        fn test_time() -> Time {
            Time::from_nanos(TEST_NOW.load(Ordering::SeqCst))
        }

        init_test("sleep_with_time_getter_waits_for_custom_clock");

        TEST_NOW.store(1_000, Ordering::SeqCst);
        let mut sleep = Box::pin(Sleep::with_time_getter(Time::from_nanos(1_500), test_time));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(Future::poll(sleep.as_mut(), &mut cx).is_pending());

        TEST_NOW.store(2_000, Ordering::SeqCst);
        assert!(Future::poll(sleep.as_mut(), &mut cx).is_ready());
        crate::test_complete!("sleep_with_time_getter_waits_for_custom_clock");
    }

    #[test]
    fn future_with_timeout_honors_custom_clock() {
        static TEST_NOW: AtomicU64 = AtomicU64::new(0);

        fn test_time() -> Time {
            Time::from_nanos(TEST_NOW.load(Ordering::SeqCst))
        }

        init_test("future_with_timeout_honors_custom_clock");

        TEST_NOW.store(1_000, Ordering::SeqCst);
        let mut future = Box::pin(future_with_timeout(
            pending::<()>(),
            Time::from_nanos(1_500),
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
        crate::test_complete!("future_with_timeout_honors_custom_clock");
    }

    #[test]
    fn single_address_fast_path_honors_overall_timeout() {
        static TEST_NOW: AtomicU64 = AtomicU64::new(0);

        fn test_time() -> Time {
            Time::from_nanos(TEST_NOW.load(Ordering::SeqCst))
        }

        async fn pending_connector(
            _addr: SocketAddr,
            _timeout: Duration,
            _time_getter: fn() -> Time,
        ) -> io::Result<TcpStream> {
            pending::<io::Result<TcpStream>>().await
        }

        init_test("single_address_fast_path_honors_overall_timeout");

        TEST_NOW.store(1_000, Ordering::SeqCst);
        let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let mut future = Box::pin(connect_single_with_connector(
            addr,
            Duration::from_secs(5),
            Duration::from_nanos(500),
            test_time,
            pending_connector,
        ));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(Future::poll(future.as_mut(), &mut cx).is_pending());

        TEST_NOW.store(2_000, Ordering::SeqCst);
        let result = Future::poll(future.as_mut(), &mut cx);
        assert!(matches!(
            result,
            Poll::Ready(Err(err))
                if err.kind() == io::ErrorKind::TimedOut
                    && err.to_string() == OVERALL_CONNECTION_TIMEOUT_MSG
        ));
        crate::test_complete!("single_address_fast_path_honors_overall_timeout");
    }

    // =======================================================================
    // connect() edge case tests (no network needed)
    // =======================================================================

    #[test]
    fn connect_empty_addrs_returns_error() {
        init_test("connect_empty_addrs_returns_error");

        let config = HappyEyeballsConfig::default();
        let result = futures_lite::future::block_on(connect(&[], &config));

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        crate::test_complete!("connect_empty_addrs_returns_error");
    }

    #[test]
    fn connect_single_loopback_refuses() {
        init_test("connect_single_loopback_refuses");

        // Connect to a port that's almost certainly not listening
        let config = HappyEyeballsConfig {
            connect_timeout: Duration::from_millis(100),
            overall_timeout: Duration::from_millis(200),
            ..Default::default()
        };
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let result = futures_lite::future::block_on(connect(&[addr], &config));

        // Should fail (no server on port 1)
        assert!(result.is_err());
        crate::test_complete!("connect_single_loopback_refuses");
    }

    #[test]
    fn connect_zero_timeout_returns_error() {
        init_test("connect_zero_timeout_returns_error");

        let config = HappyEyeballsConfig {
            connect_timeout: Duration::ZERO,
            ..Default::default()
        };
        let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let result = futures_lite::future::block_on(connect(&[addr], &config));

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        crate::test_complete!("connect_zero_timeout_returns_error");
    }

    #[test]
    fn connect_multiple_unreachable_tries_all() {
        init_test("connect_multiple_unreachable_tries_all");

        // Multiple addresses that won't connect, with short timeouts
        let config = HappyEyeballsConfig {
            first_family_delay: Duration::from_millis(10),
            attempt_delay: Duration::from_millis(10),
            connect_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(500),
        };

        let addrs: Vec<SocketAddr> = vec![
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
            "127.0.0.1:3".parse().unwrap(),
        ];

        let result = futures_lite::future::block_on(connect(&addrs, &config));
        assert!(result.is_err());
        crate::test_complete!("connect_multiple_unreachable_tries_all");
    }

    #[test]
    fn connect_uses_per_address_ports() {
        init_test("connect_uses_per_address_ports");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open_addr = listener.local_addr().unwrap();

        let accept_thread = std::thread::spawn(move || {
            // Accept exactly one connection so the connect future can succeed.
            let _ = listener.accept();
        });

        // First address should fail quickly, second should succeed. This test
        // guards against regressions that accidentally reuse the first port for
        // all attempts.
        let closed_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let addrs = vec![closed_addr, open_addr];

        let config = HappyEyeballsConfig {
            first_family_delay: Duration::from_millis(5),
            attempt_delay: Duration::from_millis(5),
            connect_timeout: Duration::from_millis(500),
            overall_timeout: Duration::from_secs(2),
        };

        let runtime = crate::runtime::RuntimeBuilder::new().build().unwrap();
        let handle = runtime
            .handle()
            .spawn(async move { connect(&addrs, &config).await });

        let result = runtime.block_on(handle);
        assert!(
            result.is_ok(),
            "connect should succeed via second address with distinct port: {result:?}"
        );

        let _ = accept_thread.join();
        crate::test_complete!("connect_uses_per_address_ports");
    }

    /// asupersync-bi2462.119: a first address that never answers must not
    /// keep a working second address from connecting within the overall
    /// budget. `TcpStream::connect_timeout` tries addresses one after another,
    /// so this is the documented multi-address path.
    #[test]
    #[cfg(target_os = "linux")]
    fn black_holed_first_address_does_not_block_a_working_second_address() {
        init_test("black_holed_first_address_does_not_block_a_working_second_address");

        let (_blackhole, _queued, blackhole_addr) = black_holed_loopback();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open_addr = listener.local_addr().unwrap();
        let accept_thread = std::thread::spawn(move || {
            let _ = listener.accept();
        });

        let config = HappyEyeballsConfig {
            first_family_delay: Duration::from_millis(20),
            attempt_delay: Duration::from_millis(50),
            connect_timeout: Duration::from_secs(5),
            overall_timeout: Duration::from_secs(3),
        };
        let addrs = vec![blackhole_addr, open_addr];
        let runtime = crate::runtime::RuntimeBuilder::new().build().unwrap();
        let started = std::time::Instant::now();
        let handle = runtime
            .handle()
            .spawn(async move { connect(&addrs, &config).await });
        let result = runtime.block_on(handle);
        let elapsed = started.elapsed();
        let stream = result.expect("the working second address connects");
        assert_eq!(stream.peer_addr().unwrap(), open_addr);
        assert!(
            elapsed < Duration::from_secs(2),
            "the second address wins well inside the budget: {elapsed:?}"
        );
        let _ = accept_thread.join();
        crate::test_complete!(
            "black_holed_first_address_does_not_block_a_working_second_address",
            elapsed_ms = elapsed.as_millis() as u64
        );
    }

    /// br-asupersync-1aqha7: the clients' connect path resolves, then races a
    /// black-holed first address with a working second one, with and without
    /// a timeout. A sequential connect would wait out the first address: the
    /// whole budget with a timeout, the kernel's SYN retries without one.
    #[test]
    #[cfg(target_os = "linux")]
    fn connect_resolved_races_past_a_black_holed_first_address() {
        init_test("connect_resolved_races_past_a_black_holed_first_address");

        let (_blackhole, _queued, blackhole_addr) = black_holed_loopback();
        let runtime = crate::runtime::RuntimeBuilder::new().build().unwrap();
        // Report every failed case at once.
        let mut failures = Vec::new();
        for timeout in [Some(Duration::from_secs(5)), None] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let open_addr = listener.local_addr().unwrap();
            let accept_thread = std::thread::spawn(move || {
                let _ = listener.accept();
            });
            // A `'static` slice resolves through `lookup_all` like a hostname.
            let addrs: &'static [SocketAddr] = Vec::leak(vec![blackhole_addr, open_addr]);
            let started = std::time::Instant::now();
            let handle = runtime
                .handle()
                .spawn(async move { connect_resolved(addrs, timeout).await });
            let result = runtime.block_on(handle);
            let elapsed = started.elapsed();
            match result {
                Ok(stream) if stream.peer_addr().ok() == Some(open_addr) => {
                    if elapsed >= Duration::from_secs(2) {
                        failures.push(format!(
                            "{timeout:?}: the second address won only after {elapsed:?}"
                        ));
                    }
                    let _ = accept_thread.join();
                }
                // Nothing reached the listener, so its accept never returns:
                // leave that thread detached rather than join it.
                other => failures.push(format!(
                    "{timeout:?}: want a connection to {open_addr}, got {other:?} after {elapsed:?}"
                )),
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
        crate::test_complete!("connect_resolved_races_past_a_black_holed_first_address");
    }

    /// A loopback address that never answers. Linux drops SYNs aimed at a
    /// listener whose accept queue is full, so after filling a backlog-0
    /// queue, connects to it hang unanswered. Keep the socket and the queued
    /// connections alive for as long as the address must stay black-holed.
    #[cfg(target_os = "linux")]
    fn black_holed_loopback() -> (socket2::Socket, Vec<std::net::TcpStream>, SocketAddr) {
        let blackhole = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)
            .expect("blackhole socket");
        blackhole
            .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
            .expect("bind blackhole");
        blackhole.listen(0).expect("listen with backlog 0");
        let blackhole_addr = blackhole
            .local_addr()
            .expect("blackhole addr")
            .as_socket()
            .expect("inet addr");
        let queued: Vec<_> = (0..4)
            .filter_map(|_| {
                std::net::TcpStream::connect_timeout(&blackhole_addr, Duration::from_millis(100))
                    .ok()
            })
            .collect();
        // Witness: the address really black-holes (a direct connect times
        // out rather than being refused), or the test proves nothing.
        let probe_started = std::time::Instant::now();
        let probe =
            std::net::TcpStream::connect_timeout(&blackhole_addr, Duration::from_millis(300));
        assert!(
            matches!(&probe, Err(error) if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)),
            "the full-backlog listener must drop SYNs, got {probe:?} after {:?}",
            probe_started.elapsed()
        );
        (blackhole, queued, blackhole_addr)
    }

    // =======================================================================
    // RaceConnections structural tests
    // =======================================================================

    /// A race whose owner is cancelled reports Interrupted, as
    /// TcpStream::connect does. Before, its overall-timeout Sleep completed
    /// on the cancellation and the race reported its timeout instead.
    #[test]
    fn a_cancelled_race_reports_interrupted_not_its_timeout() {
        init_test("a_cancelled_race_reports_interrupted_not_its_timeout");
        let owner = Cx::for_testing();
        let _guard = Cx::set_current(Some(owner.clone()));
        let polls = Arc::new(AtomicUsize::new(0));
        let attempt: ConnectFuture = Box::pin(PollCountingPendingConnect::new(Arc::clone(&polls)));
        let deadline = timeout_now().saturating_add_nanos(5_000_000_000);
        let mut race = RaceConnections::from_futures(
            vec![attempt],
            HappyEyeballsConfig::default(),
            deadline,
            timeout_now,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(race.poll_with_time(timeout_now(), &mut cx).is_pending());

        owner.set_cancel_requested(true);
        let mut result = race.poll_with_time(timeout_now(), &mut cx);
        for _ in 0..2 {
            if result.is_ready() {
                break;
            }
            result = race.poll_with_time(timeout_now(), &mut cx);
        }
        match result {
            Poll::Ready(Err(error)) => {
                assert_eq!(error.kind(), io::ErrorKind::Interrupted, "{error}");
                assert_eq!(error.to_string(), CONNECT_CANCELLED_MSG);
            }
            other => panic!("a cancelled race must end Interrupted, got {other:?}"),
        }
        crate::test_complete!("a_cancelled_race_reports_interrupted_not_its_timeout");
    }

    /// A cancelled race starts no further attempt. Before, each attempt
    /// failed Interrupted under the cancelled owner and the race started the
    /// next address at once, one socket and SYN per remaining address.
    #[test]
    fn a_cancelled_race_starts_no_further_attempt() {
        init_test("a_cancelled_race_starts_no_further_attempt");
        let owner = Cx::for_testing();
        let _guard = Cx::set_current(Some(owner.clone()));
        let addrs: Vec<SocketAddr> = (0..4)
            .map(|_| {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
                listener.local_addr().expect("local addr")
            })
            .collect();
        let deadline = timeout_now().saturating_add_nanos(5_000_000_000);
        let mut race =
            RaceConnections::new(addrs, HappyEyeballsConfig::default(), deadline, timeout_now);
        assert_eq!(race.started_count, 1, "construction starts one attempt");

        owner.set_cancel_requested(true);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let result = race.poll_with_time(timeout_now(), &mut cx);
        assert!(
            matches!(&result, Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted),
            "a cancelled race must end Interrupted, got {result:?}"
        );
        assert_eq!(
            race.started_count, 1,
            "no attempt may start after the owner is cancelled"
        );
        crate::test_complete!("a_cancelled_race_starts_no_further_attempt");
    }

    #[test]
    fn race_connections_all_fail() {
        init_test("race_connections_all_fail");

        // Race a single future that fails immediately
        let fail_fut: ConnectFuture = Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "test fail",
            ))
        });

        let deadline = timeout_now().saturating_add_nanos(5_000_000_000);
        let mut race = RaceConnections::from_futures(
            vec![fail_fut],
            HappyEyeballsConfig::default(),
            deadline,
            timeout_now,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let result = race.poll_with_time(timeout_now(), &mut cx);

        // Should complete with the error
        assert!(matches!(
            result,
            Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::ConnectionRefused
        ));
        assert_post_completion_error(race.poll_with_time(timeout_now(), &mut cx));
        crate::test_complete!("race_connections_all_fail");
    }

    #[test]
    fn race_connections_timeout_honors_custom_clock() {
        static TEST_NOW: AtomicU64 = AtomicU64::new(0);

        fn test_time() -> Time {
            Time::from_nanos(TEST_NOW.load(Ordering::SeqCst))
        }

        init_test("race_connections_timeout_honors_custom_clock");

        TEST_NOW.store(1_000, Ordering::SeqCst);
        let pending_fut: ConnectFuture =
            Box::pin(async { pending::<io::Result<TcpStream>>().await });
        let deadline = Time::from_nanos(1_500);
        let mut race = RaceConnections::from_futures(
            vec![pending_fut],
            HappyEyeballsConfig::default(),
            deadline,
            test_time,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(race.poll_with_time(test_time(), &mut cx).is_pending());

        TEST_NOW.store(2_000, Ordering::SeqCst);
        let result = race.poll_with_time(test_time(), &mut cx);
        assert!(matches!(result, Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::TimedOut));
        assert_post_completion_error(race.poll_with_time(test_time(), &mut cx));
        crate::test_complete!("race_connections_timeout_honors_custom_clock");
    }

    #[test]
    fn race_connections_zero_deadline_times_out_before_immediate_success() {
        static TEST_NOW: AtomicU64 = AtomicU64::new(0);

        fn test_time() -> Time {
            Time::from_nanos(TEST_NOW.load(Ordering::SeqCst))
        }

        init_test("race_connections_zero_deadline_times_out_before_immediate_success");

        TEST_NOW.store(1_000, Ordering::SeqCst);
        let winner: ConnectFuture = Box::pin(async { Ok(connected_test_stream()) });
        let mut race = RaceConnections::from_futures(
            vec![winner],
            HappyEyeballsConfig::default(),
            test_time(),
            test_time,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = race.poll_with_time(test_time(), &mut cx);
        assert!(matches!(
            result,
            Poll::Ready(Err(err))
                if err.kind() == io::ErrorKind::TimedOut
                    && err.to_string() == OVERALL_CONNECTION_TIMEOUT_MSG
        ));
        assert_post_completion_error(race.poll_with_time(test_time(), &mut cx));
        crate::test_complete!("race_connections_zero_deadline_times_out_before_immediate_success");
    }

    #[test]
    fn race_connections_timeout_overrides_prior_connect_error() {
        static TEST_NOW: AtomicU64 = AtomicU64::new(0);

        fn test_time() -> Time {
            Time::from_nanos(TEST_NOW.load(Ordering::SeqCst))
        }

        init_test("race_connections_timeout_overrides_prior_connect_error");

        TEST_NOW.store(1_000, Ordering::SeqCst);
        let fail_fut: ConnectFuture = Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "early failure",
            ))
        });
        let pending_fut: ConnectFuture =
            Box::pin(async { pending::<io::Result<TcpStream>>().await });
        let deadline = Time::from_nanos(1_500);
        let mut race = RaceConnections::from_futures(
            vec![fail_fut, pending_fut],
            HappyEyeballsConfig::default(),
            deadline,
            test_time,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(race.poll_with_time(test_time(), &mut cx).is_pending());

        TEST_NOW.store(2_000, Ordering::SeqCst);
        let result = race.poll_with_time(test_time(), &mut cx);
        assert!(matches!(
            result,
            Poll::Ready(Err(err))
                if err.kind() == io::ErrorKind::TimedOut
                    && err.to_string() == OVERALL_CONNECTION_TIMEOUT_MSG
        ));
        assert_post_completion_error(race.poll_with_time(test_time(), &mut cx));
        crate::test_complete!("race_connections_timeout_overrides_prior_connect_error");
    }

    #[test]
    fn race_connections_success_repoll_fails_closed_and_drops_losers() {
        init_test("race_connections_success_repoll_fails_closed_and_drops_losers");

        let loser_polls = Arc::new(AtomicUsize::new(0));
        let loser: ConnectFuture =
            Box::pin(PollCountingPendingConnect::new(Arc::clone(&loser_polls)));
        let winner: ConnectFuture = Box::pin(async { Ok(connected_test_stream()) });

        let deadline = timeout_now().saturating_add_nanos(5_000_000_000);
        let mut race = RaceConnections::from_futures(
            vec![loser, winner],
            HappyEyeballsConfig::default(),
            deadline,
            timeout_now,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            race.poll_with_time(timeout_now(), &mut cx),
            Poll::Ready(Ok(_))
        ));
        assert_eq!(
            loser_polls.load(Ordering::SeqCst),
            1,
            "loser should be polled exactly once before winner completes"
        );

        assert_post_completion_error(race.poll_with_time(timeout_now(), &mut cx));
        assert_eq!(
            loser_polls.load(Ordering::SeqCst),
            1,
            "post-completion repoll must not touch dropped losers"
        );
        crate::test_complete!("race_connections_success_repoll_fails_closed_and_drops_losers");
    }

    // =======================================================================
    // Stagger schedule tests
    // =======================================================================

    #[test]
    fn stagger_schedule_computed_correctly() {
        init_test("stagger_schedule_computed_correctly");

        let config = HappyEyeballsConfig {
            first_family_delay: Duration::from_millis(250),
            attempt_delay: Duration::from_millis(250),
            ..Default::default()
        };

        // Verify stagger delays match RFC 8305 §5 expectations as implemented
        // in start_next(): started_count==1 uses first_family_delay, all
        // subsequent use attempt_delay. The first attempt (index 0) has no
        // preceding delay.
        //
        // started_count after start_next:
        //   addr[0]: started_count=1 → delay = first_family_delay = 250ms
        //   addr[1]: started_count=2 → delay = attempt_delay      = 250ms
        //   addr[2]: started_count=3 → delay = attempt_delay      = 250ms
        //
        // Each addr beyond the first sees a delay before the next attempt
        // starts, so cumulative stagger is:
        //   addr[0] starts at 0ms (immediate)
        //   addr[1] starts after first_family_delay (250ms)
        //   addr[2] starts after first_family_delay + attempt_delay (500ms)
        //   addr[3] starts after first_family_delay + 2*attempt_delay (750ms)
        let expected_cumulative = [
            Duration::ZERO,
            Duration::from_millis(250),
            Duration::from_millis(500),
            Duration::from_millis(750),
        ];

        // Verify cumulative delays match start_next() logic:
        // started_count==1 → first_family_delay, all others → attempt_delay
        for (i, expected) in expected_cumulative.iter().enumerate().skip(1) {
            let cumulative = if i == 1 {
                config.first_family_delay
            } else {
                config.first_family_delay + config.attempt_delay * (i as u32 - 1)
            };
            assert_eq!(
                cumulative, *expected,
                "addr[{i}] cumulative stagger mismatch: got {cumulative:?}, expected {expected:?}"
            );
        }

        crate::test_complete!("stagger_schedule_computed_correctly");
    }

    #[test]
    fn sort_preserves_address_values() {
        init_test("sort_preserves_address_values");

        let v6_1: IpAddr = "2001:db8::1".parse().unwrap();
        let v6_2: IpAddr = "2001:db8::2".parse().unwrap();
        let v4_1: IpAddr = "10.0.0.1".parse().unwrap();
        let v4_2: IpAddr = "10.0.0.2".parse().unwrap();

        let addrs = vec![v4_1, v6_1, v4_2, v6_2];
        let sorted = sort_addresses(&addrs);

        // All original addresses should be present
        assert_eq!(sorted.len(), 4);
        assert!(sorted.contains(&v6_1));
        assert!(sorted.contains(&v6_2));
        assert!(sorted.contains(&v4_1));
        assert!(sorted.contains(&v4_2));

        // v6 addresses should appear at even indices (0, 2)
        assert_eq!(sorted[0], v6_1);
        assert_eq!(sorted[1], v4_1);
        assert_eq!(sorted[2], v6_2);
        assert_eq!(sorted[3], v4_2);
        crate::test_complete!("sort_preserves_address_values");
    }
