    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::net::{self, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::time::Duration;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[cfg(target_os = "linux")]
    fn assert_linux_keepalive_options(
        stream: &net::TcpStream,
        expected_idle: Duration,
        expected_interval: Duration,
        expected_retries: u32,
    ) {
        let socket = socket2::SockRef::from(stream);
        assert!(socket.keepalive().expect("read SO_KEEPALIVE"));
        assert_eq!(
            socket.tcp_keepalive_time().expect("read TCP_KEEPIDLE"),
            expected_idle,
            "TCP_KEEPIDLE value"
        );
        assert_eq!(
            socket.tcp_keepalive_interval().expect("read TCP_KEEPINTVL"),
            expected_interval,
            "TCP_KEEPINTVL value"
        );
        assert_eq!(
            socket.tcp_keepalive_retries().expect("read TCP_KEEPCNT"),
            expected_retries,
            "TCP_KEEPCNT value"
        );
    }

    #[test]
    fn test_bind_family_match_v4() {
        init_test("test_bind_family_match_v4");
        let socket = TcpSocket::new_v4().expect("new_v4");
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let result = socket.bind(addr);
        crate::assert_with_log!(result.is_ok(), "bind v4", true, result.is_ok());
        crate::test_complete!("test_bind_family_match_v4");
    }

    #[test]
    fn test_bind_family_mismatch() {
        init_test("test_bind_family_mismatch");
        let socket = TcpSocket::new_v4().expect("new_v4");
        let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, 0));
        let err = socket.bind(addr).expect_err("expected mismatch error");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::InvalidInput,
            "bind mismatch kind",
            io::ErrorKind::InvalidInput,
            err.kind()
        );
        crate::test_complete!("test_bind_family_mismatch");
    }

    #[test]
    fn test_bind_rejects_rebind_and_preserves_original_local_identity() {
        init_test("test_bind_rejects_rebind_and_preserves_original_local_identity");
        let socket = TcpSocket::new_v4().expect("new_v4");
        let first = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let second = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));

        socket.bind(first).expect("first bind");
        let err = socket.bind(second).expect_err("second bind should fail");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::InvalidInput,
            "rebind rejected",
            io::ErrorKind::InvalidInput,
            err.kind()
        );
        crate::assert_with_log!(
            socket.state.lock().bound == Some(first),
            "first bind preserved in socket state",
            Some(first),
            socket.state.lock().bound
        );

        let listener = socket.listen(128).expect("listen after rejected rebind");
        let local = listener.local_addr().expect("listener local_addr");
        crate::assert_with_log!(
            local.ip() == first.ip(),
            "listen uses original local identity",
            first.ip(),
            local.ip()
        );
        crate::test_complete!("test_bind_rejects_rebind_and_preserves_original_local_identity");
    }

    #[test]
    fn test_listen_requires_bind() {
        init_test("test_listen_requires_bind");
        let socket = TcpSocket::new_v4().expect("new_v4");
        let err = socket.listen(128).expect_err("listen without bind");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::InvalidInput,
            "listen requires bind",
            io::ErrorKind::InvalidInput,
            err.kind()
        );
        crate::test_complete!("test_listen_requires_bind");
    }

    #[test]
    fn test_listen_with_reuseaddr() {
        init_test("test_listen_with_reuseaddr");
        let socket = TcpSocket::new_v4().expect("new_v4");
        socket
            .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind");
        socket.set_reuseaddr(true).expect("set_reuseaddr");
        let listener = socket
            .listen(128)
            .expect("listen with reuseaddr should succeed");
        let addr = listener.local_addr().expect("local_addr");
        crate::assert_with_log!(addr.port() > 0, "bound port", true, addr.port() > 0);
        crate::test_complete!("test_listen_with_reuseaddr");
    }

    #[test]
    fn test_socket_records_tcp_convenience_options() {
        init_test("test_socket_records_tcp_convenience_options");
        let socket = TcpSocket::new_v4().expect("new_v4");
        let keepalive = TcpKeepaliveConfig::new(Duration::from_secs(42))
            .with_interval(Duration::from_secs(8))
            .with_retries(5);

        socket.set_nodelay(true).expect("set nodelay");
        socket
            .set_keepalive_config(Some(keepalive))
            .expect("set keepalive config");

        let state = socket.state.lock();
        crate::assert_with_log!(
            state.nodelay == Some(true),
            "nodelay state",
            Some(true),
            state.nodelay
        );
        crate::assert_with_log!(
            state.keepalive == KeepaliveConfig::Enabled(keepalive),
            "keepalive state",
            KeepaliveConfig::Enabled(keepalive),
            state.keepalive
        );
        crate::test_complete!("test_socket_records_tcp_convenience_options");
    }

    #[test]
    fn test_connect_applies_nodelay_and_keepalive_options() {
        init_test("test_connect_applies_nodelay_and_keepalive_options");
        let listener = net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let _ = listener.accept().expect("accept");
            let _ = tx.send(());
        });

        futures_lite::future::block_on(async {
            let socket = TcpSocket::new_v4().expect("new_v4");
            socket.set_nodelay(true).expect("set nodelay");
            socket
                .set_keepalive(Some(Duration::from_secs(30)))
                .expect("set keepalive");

            let stream = socket.connect(addr).await.expect("connect");
            let std_stream = stream.try_as_std().expect("std tcp stream");
            crate::assert_with_log!(
                std_stream.nodelay().expect("read nodelay"),
                "connected stream nodelay",
                true,
                std_stream.nodelay().expect("read nodelay")
            );

            let sock = socket2::SockRef::from(std_stream);
            crate::assert_with_log!(
                sock.keepalive().expect("read keepalive"),
                "connected stream keepalive",
                true,
                sock.keepalive().expect("read keepalive")
            );
        });

        let accepted = rx.recv_timeout(Duration::from_secs(1)).is_ok();
        crate::assert_with_log!(accepted, "accepted connection", true, accepted);
        handle.join().expect("join accept thread");
        crate::test_complete!("test_connect_applies_nodelay_and_keepalive_options");
    }

    #[test]
    fn test_connect_applies_nodelay_and_keepalive_options_ipv6_when_available() {
        init_test("test_connect_applies_nodelay_and_keepalive_options_ipv6_when_available");
        let listener = match net::TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))) {
            Ok(listener) => listener,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::AddrNotAvailable | io::ErrorKind::Unsupported
                ) =>
            {
                crate::test_complete!(
                    "test_connect_applies_nodelay_and_keepalive_options_ipv6_when_available"
                );
                return;
            }
            Err(err) => panic!("bind IPv6 listener: {err}"),
        };
        let addr = listener.local_addr().expect("local addr");
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let _ = listener.accept().expect("accept");
            let _ = tx.send(());
        });

        futures_lite::future::block_on(async {
            let socket = TcpSocket::new_v6().expect("new_v6");
            socket.set_nodelay(true).expect("set nodelay");
            socket
                .set_keepalive(Some(Duration::from_secs(30)))
                .expect("set keepalive");

            let stream = socket.connect(addr).await.expect("connect");
            let std_stream = stream.try_as_std().expect("std tcp stream");
            crate::assert_with_log!(
                std_stream.nodelay().expect("read nodelay"),
                "connected IPv6 stream nodelay",
                true,
                std_stream.nodelay().expect("read nodelay")
            );

            let sock = socket2::SockRef::from(std_stream);
            crate::assert_with_log!(
                sock.keepalive().expect("read keepalive"),
                "connected IPv6 stream keepalive",
                true,
                sock.keepalive().expect("read keepalive")
            );
        });

        let accepted = rx.recv_timeout(Duration::from_secs(1)).is_ok();
        crate::assert_with_log!(accepted, "accepted IPv6 connection", true, accepted);
        handle.join().expect("join accept thread");
        crate::test_complete!(
            "test_connect_applies_nodelay_and_keepalive_options_ipv6_when_available"
        );
    }

    #[cfg(all(not(target_arch = "wasm32"), target_os = "linux"))]
    #[test]
    fn test_connect_applies_keepalive_config_knobs() {
        init_test("test_connect_applies_keepalive_config_knobs");
        let listener = net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let handle = std::thread::spawn(move || {
            let _ = listener.accept().expect("accept");
        });

        futures_lite::future::block_on(async {
            let socket = TcpSocket::new_v4().expect("new_v4");
            socket
                .set_keepalive_config(Some(
                    TcpKeepaliveConfig::new(Duration::from_secs(33))
                        .with_interval(Duration::from_secs(6))
                        .with_retries(4),
                ))
                .expect("set keepalive config");

            let stream = socket.connect(addr).await.expect("connect");
            let std_stream = stream.try_as_std().expect("std tcp stream");
            assert_linux_keepalive_options(
                std_stream,
                Duration::from_secs(33),
                Duration::from_secs(6),
                4,
            );
        });

        handle.join().expect("join accept thread");
        crate::test_complete!("test_connect_applies_keepalive_config_knobs");
    }

    #[cfg(all(not(target_arch = "wasm32"), target_os = "linux"))]
    #[test]
    fn test_listen_propagates_tcp_keepalive_options_to_accepted_stream() {
        init_test("test_listen_propagates_tcp_keepalive_options_to_accepted_stream");
        let socket = TcpSocket::new_v4().expect("new_v4");
        socket
            .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind");
        socket.set_nodelay(true).expect("set nodelay");
        socket
            .set_keepalive_config(Some(
                TcpKeepaliveConfig::new(Duration::from_secs(44))
                    .with_interval(Duration::from_secs(9))
                    .with_retries(3),
            ))
            .expect("set keepalive config");

        let listener = socket.listen(128).expect("listen");
        let addr = listener.local_addr().expect("local addr");
        let handle = std::thread::spawn(move || {
            net::TcpStream::connect(addr).expect("client connect");
        });

        let (accepted, _) = futures_lite::future::block_on(listener.accept()).expect("accept");
        handle.join().expect("join client thread");

        let std_stream = accepted.try_as_std().expect("std tcp stream");
        crate::assert_with_log!(
            std_stream.nodelay().expect("read nodelay"),
            "accepted stream nodelay",
            true,
            std_stream.nodelay().expect("read nodelay")
        );
        assert_linux_keepalive_options(
            std_stream,
            Duration::from_secs(44),
            Duration::from_secs(9),
            3,
        );
        crate::test_complete!("test_listen_propagates_tcp_keepalive_options_to_accepted_stream");
    }

    #[cfg(unix)]
    #[test]
    fn test_listen_with_reuseport() {
        init_test("test_listen_with_reuseport");
        let socket = TcpSocket::new_v4().expect("new_v4");
        socket
            .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind");
        socket.set_reuseport(true).expect("set_reuseport");
        let listener = socket
            .listen(128)
            .expect("listen with reuseport should succeed");
        let addr = listener.local_addr().expect("local_addr");
        crate::assert_with_log!(addr.port() > 0, "bound port", true, addr.port() > 0);
        crate::test_complete!("test_listen_with_reuseport");
    }

    #[test]
    fn test_listen_success_v4() {
        init_test("test_listen_success_v4");
        let socket = TcpSocket::new_v4().expect("new_v4");
        socket
            .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind");
        let listener = socket.listen(128).expect("listen");
        let local = listener.local_addr().expect("local_addr");
        crate::assert_with_log!(
            local.ip() == Ipv4Addr::LOCALHOST,
            "local addr ip",
            Ipv4Addr::LOCALHOST,
            local.ip()
        );
        crate::assert_with_log!(
            local.port() != 0,
            "local port assigned",
            true,
            local.port() != 0
        );
        crate::test_complete!("test_listen_success_v4");
    }

    #[test]
    fn test_connect_with_bind_success() {
        init_test("test_connect_with_bind_success");
        let listener = net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind listener");
        let listen_addr = listener.local_addr().expect("local addr");
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let _ = listener.accept().expect("accept");
            let _ = tx.send(());
        });

        futures_lite::future::block_on(async {
            let socket = TcpSocket::new_v4().expect("new_v4");
            // Bind to an ephemeral port
            socket
                .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .expect("bind");

            let stream = socket.connect(listen_addr).await;
            crate::assert_with_log!(stream.is_ok(), "connect with bind ok", true, stream.is_ok());

            if let Ok(stream) = stream {
                let local = stream.local_addr().expect("local addr");
                // Verify we are indeed bound to local loopback (port will be non-zero)
                crate::assert_with_log!(
                    local.ip() == Ipv4Addr::LOCALHOST,
                    "local ip",
                    Ipv4Addr::LOCALHOST,
                    local.ip()
                );
            }
        });

        let accepted = rx.recv_timeout(Duration::from_secs(1)).is_ok();
        crate::assert_with_log!(accepted, "accepted connection", true, accepted);
        handle.join().expect("join accept thread");
        crate::test_complete!("test_connect_with_bind_success");
    }

    #[test]
    fn test_connect_family_mismatch() {
        init_test("test_connect_family_mismatch");
        futures_lite::future::block_on(async {
            let socket = TcpSocket::new_v4().expect("new_v4");
            let err = socket
                .connect(SocketAddr::from((Ipv6Addr::LOCALHOST, 80)))
                .await
                .expect_err("connect should reject IPv6");
            crate::assert_with_log!(
                err.kind() == io::ErrorKind::InvalidInput,
                "connect family mismatch",
                io::ErrorKind::InvalidInput,
                err.kind()
            );
        });
        crate::test_complete!("test_connect_family_mismatch");
    }

    #[test]
    fn test_connect_success_v4() {
        init_test("test_connect_success_v4");
        let listener = net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let _ = listener.accept().expect("accept");
            let _ = tx.send(());
        });

        futures_lite::future::block_on(async {
            let stream = TcpSocket::new_v4().expect("new_v4").connect(addr).await;
            crate::assert_with_log!(stream.is_ok(), "connect ok", true, stream.is_ok());
            if let Ok(stream) = stream {
                let peer = stream.peer_addr().expect("peer addr");
                crate::assert_with_log!(peer.ip() == addr.ip(), "peer ip", addr.ip(), peer.ip());
            }
        });

        let accepted = rx.recv_timeout(Duration::from_secs(1)).is_ok();
        crate::assert_with_log!(accepted, "accepted connection", true, accepted);
        handle.join().expect("join accept thread");
        crate::test_complete!("test_connect_success_v4");
    }

    #[test]
    fn test_listen_reuseaddr() {
        init_test("test_listen_reuseaddr");
        let socket = TcpSocket::new_v4().expect("new_v4");
        socket.set_reuseaddr(true).expect("set_reuseaddr");
        socket
            .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind");
        let listener = socket.listen(128);
        crate::assert_with_log!(listener.is_ok(), "listen ok", true, listener.is_ok());
        crate::test_complete!("test_listen_reuseaddr");
    }
