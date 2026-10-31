    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::sync::Arc;
    use std::task::{Context, Waker};

    /// A fresh directory for a test socket, under `/tmp` rather than `TMPDIR`.
    ///
    /// `sun_path` holds 108 bytes on Linux (104 on macOS) including the
    /// terminating NUL. rch workers set `TMPDIR` to `<project root>/.rch-tmp`,
    /// 70 or more bytes, and `tempdir()` appends `/.tmpXXXXXX`, so a 26-byte
    /// socket name no longer fit there.
    fn socket_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("asu")
            .tempdir_in("/tmp")
            .expect("create socket dir")
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    /// GH#67 follow-up (asupersync-tx9j0f): a `UnixDatagram` polled with no
    /// I/O driver on the current `Cx` parks on the process-global fallback
    /// driver instead of re-waking itself into a hot loop.
    mod gh67_fallback_io_driver {
        use super::*;
        use crate::cx::Cx;
        use crate::net::udp::fallback_io_test_support::signal_waker;
        use std::sync::atomic::Ordering;
        use std::task::Poll;
        use std::time::Duration;

        #[test]
        fn poll_recv_ready_without_io_driver_parks_until_datagram_arrives() {
            assert!(
                Cx::current().is_none(),
                "test must run without an ambient Cx"
            );
            let (mut socket, peer) = UnixDatagram::pair().expect("socket pair");
            let (signal, waker, rx) = signal_waker();
            let mut task_cx = Context::from_waker(&waker);

            assert!(matches!(
                socket.poll_recv_ready(&mut task_cx),
                Poll::Pending
            ));
            assert_eq!(
                signal.hits.load(Ordering::SeqCst),
                0,
                "driverless poll must park, not self-wake (GH#67)"
            );
            assert!(
                socket.registration.on_fallback(),
                "driverless poll registers with the process-global fallback I/O driver"
            );
            assert!(
                rx.recv_timeout(Duration::from_millis(200)).is_err(),
                "no wake may arrive while the peer is silent"
            );

            peer.inner.send(b"wake").expect("peer send");
            rx.recv_timeout(Duration::from_secs(5))
                .expect("fallback reactor pump delivers the readiness wake");
            assert_eq!(signal.hits.load(Ordering::SeqCst), 1);
            assert!(matches!(
                socket.poll_recv_ready(&mut task_cx),
                Poll::Ready(Ok(()))
            ));
            let mut buf = [0u8; 8];
            let len = socket.inner.recv(&mut buf).expect("recv the datagram");
            assert_eq!(&buf[..len], b"wake");
        }
    }

    #[test]
    fn test_pair() {
        init_test("test_datagram_pair");
        futures_lite::future::block_on(async {
            let (mut a, mut b) = UnixDatagram::pair().expect("pair failed");

            a.send(b"hello").await.expect("send failed");
            let mut buf = [0u8; 5];
            let n = b.recv(&mut buf).await.expect("recv failed");

            crate::assert_with_log!(n == 5, "received bytes", 5, n);
            crate::assert_with_log!(&buf == b"hello", "received data", b"hello", buf);
        });
        crate::test_complete!("test_datagram_pair");
    }

    #[test]
    fn test_bind_and_send_to() {
        init_test("test_datagram_bind_send_to");
        futures_lite::future::block_on(async {
            let dir = socket_dir();
            let server_path = dir.path().join("server.sock");

            let mut server = UnixDatagram::bind(&server_path).expect("bind failed");
            let mut client = UnixDatagram::unbound().expect("unbound failed");

            // Send from client to server
            let sent = client
                .send_to(b"hello", &server_path)
                .await
                .expect("send_to failed");
            crate::assert_with_log!(sent == 5, "sent bytes", 5, sent);

            // Receive on server
            let mut buf = [0u8; 5];
            let (n, _addr) = server.recv_from(&mut buf).await.expect("recv_from failed");
            crate::assert_with_log!(n == 5, "received bytes", 5, n);
            crate::assert_with_log!(&buf == b"hello", "received data", b"hello", buf);
        });
        crate::test_complete!("test_datagram_bind_send_to");
    }

    #[test]
    fn test_peek_from_reports_peer_and_preserves_data() {
        init_test("test_datagram_peek_from");
        futures_lite::future::block_on(async {
            let dir = socket_dir();
            let server_path = dir.path().join("server.sock");
            let client_path = dir.path().join("client.sock");

            let mut server = UnixDatagram::bind(&server_path).expect("bind server failed");
            let mut client = UnixDatagram::bind(&client_path).expect("bind client failed");

            client
                .send_to(b"peek", &server_path)
                .await
                .expect("send_to failed");

            let mut peek_buf = [0u8; 4];
            let (n, addr) = server
                .peek_from(&mut peek_buf)
                .await
                .expect("peek_from failed");
            crate::assert_with_log!(n == 4, "peek bytes", 4, n);
            crate::assert_with_log!(&peek_buf == b"peek", "peek data", b"peek", peek_buf);
            let peek_path = addr.as_pathname().map(std::path::Path::to_path_buf);
            crate::assert_with_log!(
                peek_path.as_ref() == Some(&client_path),
                "peek addr",
                Some(&client_path),
                peek_path.as_ref()
            );

            let mut recv_buf = [0u8; 4];
            let (n2, addr2) = server
                .recv_from(&mut recv_buf)
                .await
                .expect("recv_from failed");
            crate::assert_with_log!(n2 == 4, "recv bytes", 4, n2);
            crate::assert_with_log!(&recv_buf == b"peek", "recv data", b"peek", recv_buf);
            let recv_path = addr2.as_pathname().map(std::path::Path::to_path_buf);
            crate::assert_with_log!(
                recv_path.as_ref() == Some(&client_path),
                "recv addr",
                Some(&client_path),
                recv_path.as_ref()
            );
        });
        crate::test_complete!("test_datagram_peek_from");
    }

    #[test]
    fn test_peek_from_unbound_sender_reports_unnamed_addr() {
        init_test("test_datagram_peek_from_unbound_sender_reports_unnamed_addr");
        futures_lite::future::block_on(async {
            let dir = socket_dir();
            let server_path = dir.path().join("server.sock");

            let mut server = UnixDatagram::bind(&server_path).expect("bind server failed");
            let mut client = UnixDatagram::unbound().expect("unbound failed");

            client
                .send_to(b"peek", &server_path)
                .await
                .expect("send_to failed");

            let mut peek_buf = [0u8; 4];
            let (peeked, peek_addr) = server
                .peek_from(&mut peek_buf)
                .await
                .expect("peek_from failed");
            crate::assert_with_log!(peeked == 4, "peek bytes", 4, peeked);
            crate::assert_with_log!(&peek_buf == b"peek", "peek data", b"peek", peek_buf);
            crate::assert_with_log!(
                peek_addr.is_unnamed(),
                "peek addr unnamed",
                true,
                peek_addr.is_unnamed()
            );
            crate::assert_with_log!(
                peek_addr.as_pathname().is_none(),
                "peek addr pathname",
                "None",
                format!("{:?}", peek_addr.as_pathname())
            );

            let mut recv_buf = [0u8; 4];
            let (received, recv_addr) = server
                .recv_from(&mut recv_buf)
                .await
                .expect("recv_from failed");
            crate::assert_with_log!(received == 4, "recv bytes", 4, received);
            crate::assert_with_log!(&recv_buf == b"peek", "recv data", b"peek", recv_buf);
            crate::assert_with_log!(
                recv_addr.is_unnamed(),
                "recv addr unnamed",
                true,
                recv_addr.is_unnamed()
            );
            crate::assert_with_log!(
                recv_addr.as_pathname().is_none(),
                "recv addr pathname",
                "None",
                format!("{:?}", recv_addr.as_pathname())
            );
        });
        crate::test_complete!("test_datagram_peek_from_unbound_sender_reports_unnamed_addr");
    }

    #[test]
    fn test_recv_from_rejects_empty_buffer_without_consuming_datagram() {
        init_test("test_datagram_recv_from_empty_buffer");
        futures_lite::future::block_on(async {
            let dir = socket_dir();
            let server_path = dir.path().join("server.sock");
            let client_path = dir.path().join("client.sock");

            let mut server = UnixDatagram::bind(&server_path).expect("bind server failed");
            let mut client = UnixDatagram::bind(&client_path).expect("bind client failed");

            client
                .send_to(b"ping", &server_path)
                .await
                .expect("send_to failed");

            let mut empty = [];
            let err = server
                .recv_from(&mut empty)
                .await
                .expect_err("empty buffer must fail");
            crate::assert_with_log!(
                err.kind() == io::ErrorKind::InvalidInput,
                "error kind",
                io::ErrorKind::InvalidInput,
                err.kind()
            );

            let mut buf = [0u8; 4];
            let (received, addr) = server
                .recv_from(&mut buf)
                .await
                .expect("recv_from after error failed");
            crate::assert_with_log!(received == 4, "recv bytes", 4, received);
            crate::assert_with_log!(&buf == b"ping", "recv data", b"ping", buf);
            let recv_path = addr.as_pathname().map(std::path::Path::to_path_buf);
            crate::assert_with_log!(
                recv_path.as_ref() == Some(&client_path),
                "recv addr",
                Some(&client_path),
                recv_path.as_ref()
            );
        });
        crate::test_complete!("test_datagram_recv_from_empty_buffer");
    }

    #[test]
    fn test_connect() {
        init_test("test_datagram_connect");
        futures_lite::future::block_on(async {
            let dir = socket_dir();
            let server_path = dir.path().join("server.sock");
            let client_path = dir.path().join("client.sock");

            let mut server = UnixDatagram::bind(&server_path).expect("bind server failed");
            let mut client = UnixDatagram::bind(&client_path).expect("bind client failed");

            // Connect client to server
            client.connect(&server_path).expect("connect failed");

            // Now we can use send/recv instead of send_to/recv_from
            client.send(b"ping").await.expect("send failed");

            let mut buf = [0u8; 4];
            let (n, addr) = server.recv_from(&mut buf).await.expect("recv_from failed");
            crate::assert_with_log!(n == 4, "received bytes", 4, n);
            crate::assert_with_log!(&buf == b"ping", "received data", b"ping", buf);

            // Check the source address
            let pathname = addr.as_pathname();
            crate::assert_with_log!(pathname.is_some(), "has pathname", true, pathname.is_some());
        });
        crate::test_complete!("test_datagram_connect");
    }

    #[test]
    fn test_socket_cleanup_on_drop() {
        init_test("test_datagram_cleanup_on_drop");
        let dir = socket_dir();
        let path = dir.path().join("cleanup_test.sock");

        {
            let _socket = UnixDatagram::bind(&path).expect("bind failed");
            let exists = path.exists();
            crate::assert_with_log!(exists, "socket exists", true, exists);
        }

        let exists = path.exists();
        crate::assert_with_log!(!exists, "socket cleaned up", false, exists);
        crate::test_complete!("test_datagram_cleanup_on_drop");
    }

    #[test]
    fn test_from_std_no_cleanup() {
        init_test("test_datagram_from_std_no_cleanup");
        let dir = socket_dir();
        let path = dir.path().join("from_std_test.sock");

        // Create with std
        let std_socket = net::UnixDatagram::bind(&path).expect("bind failed");

        {
            // Wrap in async version
            let _socket = UnixDatagram::from_std(std_socket).expect("from_std failed");
        }

        // Socket file should still exist (from_std doesn't clean up)
        let exists = path.exists();
        crate::assert_with_log!(exists, "socket remains", true, exists);

        // Clean up manually
        std::fs::remove_file(&path).ok();
        crate::test_complete!("test_datagram_from_std_no_cleanup");
    }

    #[test]
    fn test_take_path_prevents_cleanup() {
        init_test("test_datagram_take_path");
        let dir = socket_dir();
        let path = dir.path().join("take_path_test.sock");

        {
            let mut socket = UnixDatagram::bind(&path).expect("bind failed");

            // Take the path
            let taken = socket.take_path();
            crate::assert_with_log!(taken.is_some(), "taken some", true, taken.is_some());
        }

        // Socket should still exist
        let exists = path.exists();
        crate::assert_with_log!(exists, "socket remains", true, exists);

        // Clean up manually
        std::fs::remove_file(&path).ok();
        crate::test_complete!("test_datagram_take_path");
    }

    #[test]
    fn test_bind_refuses_stale_socket_file() {
        init_test("test_datagram_bind_refuses_stale_socket_file");
        let dir = socket_dir();
        let path = dir.path().join("stale_datagram.sock");

        let stale = net::UnixDatagram::bind(&path).expect("create stale socket");
        drop(stale);

        crate::assert_with_log!(path.exists(), "stale socket exists", true, path.exists());

        let err = UnixDatagram::bind(&path).expect_err("bind should refuse stale socket path");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::AddrInUse,
            "bind error kind",
            io::ErrorKind::AddrInUse,
            err.kind()
        );
        crate::assert_with_log!(path.exists(), "stale socket preserved", true, path.exists());
        crate::test_complete!("test_datagram_bind_refuses_stale_socket_file");
    }

    #[test]
    fn test_bind_refuses_live_socket_file() {
        init_test("test_datagram_bind_refuses_live_socket_file");
        let dir = socket_dir();
        let path = dir.path().join("live_datagram.sock");

        let original = net::UnixDatagram::bind(&path).expect("create live socket");

        let err = UnixDatagram::bind(&path).expect_err("bind should refuse live socket path");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::AddrInUse,
            "bind error kind",
            io::ErrorKind::AddrInUse,
            err.kind()
        );
        crate::assert_with_log!(path.exists(), "live socket preserved", true, path.exists());

        drop(original);
        std::fs::remove_file(&path).ok();
        crate::test_complete!("test_datagram_bind_refuses_live_socket_file");
    }

    #[test]
    fn replacement_socket_path_survives_old_datagram_drop() {
        init_test("replacement_socket_path_survives_old_datagram_drop");
        let dir = socket_dir();
        let path = dir.path().join("datagram_rebind.sock");

        let original = UnixDatagram::bind(&path).expect("bind failed");
        crate::assert_with_log!(path.exists(), "socket exists", true, path.exists());

        std::fs::remove_file(&path).expect("unlink original path");
        let replacement = net::UnixDatagram::bind(&path).expect("bind replacement failed");
        crate::assert_with_log!(path.exists(), "replacement exists", true, path.exists());

        drop(original);

        crate::assert_with_log!(
            path.exists(),
            "old datagram drop preserved replacement path",
            true,
            path.exists()
        );

        drop(replacement);
        std::fs::remove_file(&path).ok();
        crate::test_complete!("replacement_socket_path_survives_old_datagram_drop");
    }

    #[test]
    fn test_bind_cleanup_on_post_bind_init_failure() {
        init_test("test_datagram_bind_cleanup_on_post_bind_init_failure");
        let dir = socket_dir();
        let path = dir.path().join("datagram_init_failure.sock");

        crate::net::unix::listener::remove_stale_socket_file(&path).expect("clear stale socket");
        let inner = net::UnixDatagram::bind(&path).expect("bind failed");
        let err = UnixDatagram::from_bound_with(&path, inner, |_socket| {
            Err(io::Error::other("injected datagram init failure"))
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

        crate::test_complete!("test_datagram_bind_cleanup_on_post_bind_init_failure");
    }

    #[test]
    fn test_local_addr() {
        init_test("test_datagram_local_addr");
        let dir = socket_dir();
        let path = dir.path().join("local_addr_test.sock");

        let socket = UnixDatagram::bind(&path).expect("bind failed");
        let addr = socket.local_addr().expect("local_addr failed");

        let pathname = addr.as_pathname();
        crate::assert_with_log!(pathname.is_some(), "has pathname", true, pathname.is_some());
        let pathname = pathname.unwrap();
        crate::assert_with_log!(pathname == path, "pathname matches", path, pathname);
        crate::test_complete!("test_datagram_local_addr");
    }

    #[test]
    fn test_unbound_local_addr() {
        init_test("test_datagram_unbound_local_addr");
        let socket = UnixDatagram::unbound().expect("unbound failed");
        let addr = socket.local_addr().expect("local_addr failed");

        // Unbound sockets have no pathname
        let pathname = addr.as_pathname();
        crate::assert_with_log!(
            pathname.is_none(),
            "no pathname",
            "None",
            format!("{:?}", pathname)
        );
        crate::test_complete!("test_datagram_unbound_local_addr");
    }

    #[test]
    fn test_peek() {
        init_test("test_datagram_peek");
        futures_lite::future::block_on(async {
            let (mut a, mut b) = UnixDatagram::pair().expect("pair failed");

            a.send(b"hello").await.expect("send failed");

            // Peek should see the data
            let mut buf = [0u8; 5];
            let n = b.peek(&mut buf).await.expect("peek failed");
            crate::assert_with_log!(n == 5, "peeked bytes", 5, n);
            crate::assert_with_log!(&buf == b"hello", "peeked data", b"hello", buf);

            // Data should still be there for recv
            let mut buf2 = [0u8; 5];
            let n = b.recv(&mut buf2).await.expect("recv failed");
            crate::assert_with_log!(n == 5, "received bytes", 5, n);
            crate::assert_with_log!(&buf2 == b"hello", "received data", b"hello", buf2);
        });
        crate::test_complete!("test_datagram_peek");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_abstract_socket() {
        init_test("test_datagram_abstract_socket");
        futures_lite::future::block_on(async {
            let server_name = b"asupersync_test_datagram_abstract";
            let mut server = UnixDatagram::bind_abstract(server_name).expect("bind failed");

            let mut client = UnixDatagram::unbound().expect("unbound failed");
            client
                .connect_abstract(server_name)
                .expect("connect failed");

            client.send(b"hello").await.expect("send failed");

            let mut buf = [0u8; 5];
            let n = server.recv(&mut buf).await.expect("recv failed");
            crate::assert_with_log!(n == 5, "received bytes", 5, n);
        });
        crate::test_complete!("test_datagram_abstract_socket");
    }

    #[test]
    fn test_datagram_registers_on_wouldblock() {
        use crate::cx::Cx;
        use crate::runtime::LabReactor;
        use crate::runtime::io_driver::IoDriverHandle;
        use crate::types::{Budget, RegionId, TaskId};

        init_test("test_datagram_registers_on_wouldblock");

        // Create a pair and drain the socket to ensure WouldBlock on recv
        let (mut a, mut b) = UnixDatagram::pair().expect("pair failed");

        // Set up reactor context
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

        let waker = noop_waker();
        let mut poll_cx = Context::from_waker(&waker);

        // Try to poll recv when no data available - should return Pending and register
        let poll = b.poll_recv_ready(&mut poll_cx);
        crate::assert_with_log!(
            matches!(poll, Poll::Pending),
            "poll is Pending",
            "Poll::Pending",
            format!("{:?}", poll)
        );
        let has_registration = b.registration.is_some();
        crate::assert_with_log!(
            has_registration,
            "registration present",
            true,
            has_registration
        );

        // Now send some data
        futures_lite::future::block_on(async {
            a.send(b"test").await.expect("send failed");
        });

        // Poll should succeed
        let poll = b.poll_recv_ready(&mut poll_cx);
        crate::assert_with_log!(
            matches!(poll, Poll::Ready(Ok(()))),
            "poll is Ready",
            "Poll::Ready(Ok(()))",
            format!("{:?}", poll)
        );

        crate::test_complete!("test_datagram_registers_on_wouldblock");
    }

    #[test]
    fn test_datagram_send_registers_on_wouldblock() {
        use crate::cx::Cx;
        use crate::runtime::LabReactor;
        use crate::runtime::io_driver::IoDriverHandle;
        use crate::types::{Budget, RegionId, TaskId};

        init_test("test_datagram_send_registers_on_wouldblock");

        // Create a pair
        let (mut a, _b) = UnixDatagram::pair().expect("pair failed");

        // Set up reactor context
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

        let waker = noop_waker();
        let mut poll_cx = Context::from_waker(&waker);

        // poll_send_ready should work without blocking for an empty socket
        let poll = a.poll_send_ready(&mut poll_cx);
        // Either ready or pending with registration is acceptable
        if matches!(poll, Poll::Pending) {
            let has_registration = a.registration.is_some();
            crate::assert_with_log!(
                has_registration,
                "registration present on Pending",
                true,
                has_registration
            );
        }

        crate::test_complete!("test_datagram_send_registers_on_wouldblock");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_cancelled_datagram_ops_return_interrupted_without_registration() {
        use crate::cx::Cx;

        init_test("test_cancelled_datagram_ops_return_interrupted_without_registration");

        let dir = socket_dir();
        let server_path = dir.path().join("cancel-server.sock");
        let client_path = dir.path().join("cancel-client.sock");

        let mut path_server = UnixDatagram::bind(&server_path).expect("bind server failed");
        let mut path_client = UnixDatagram::bind(&client_path).expect("bind client failed");
        let (mut connected_a, mut connected_b) = UnixDatagram::pair().expect("pair failed");

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let _guard = Cx::set_current(Some(cx));

        let err = futures_lite::future::block_on(path_client.send_to(b"hello", &server_path))
            .expect_err("cancelled send_to must fail");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::Interrupted,
            "send_to cancelled",
            io::ErrorKind::Interrupted,
            err.kind()
        );
        crate::assert_with_log!(
            path_client.registration.is_none(),
            "send_to registration skipped",
            true,
            path_client.registration.is_none()
        );

        let mut buf = [0u8; 8];

        let err = futures_lite::future::block_on(path_server.recv_from(&mut buf))
            .expect_err("cancelled recv_from must fail");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::Interrupted,
            "recv_from cancelled",
            io::ErrorKind::Interrupted,
            err.kind()
        );
        crate::assert_with_log!(
            path_server.registration.is_none(),
            "recv_from registration skipped",
            true,
            path_server.registration.is_none()
        );

        let err = futures_lite::future::block_on(connected_a.send(b"hello"))
            .expect_err("cancelled send must fail");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::Interrupted,
            "send cancelled",
            io::ErrorKind::Interrupted,
            err.kind()
        );
        crate::assert_with_log!(
            connected_a.registration.is_none(),
            "send registration skipped",
            true,
            connected_a.registration.is_none()
        );

        let err = futures_lite::future::block_on(connected_b.recv(&mut buf))
            .expect_err("cancelled recv must fail");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::Interrupted,
            "recv cancelled",
            io::ErrorKind::Interrupted,
            err.kind()
        );
        crate::assert_with_log!(
            connected_b.registration.is_none(),
            "recv registration skipped",
            true,
            connected_b.registration.is_none()
        );

        let err = futures_lite::future::block_on(connected_b.peek(&mut buf))
            .expect_err("cancelled peek must fail");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::Interrupted,
            "peek cancelled",
            io::ErrorKind::Interrupted,
            err.kind()
        );
        crate::assert_with_log!(
            connected_b.registration.is_none(),
            "peek registration skipped",
            true,
            connected_b.registration.is_none()
        );

        let err = futures_lite::future::block_on(path_server.peek_from(&mut buf))
            .expect_err("cancelled peek_from must fail");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::Interrupted,
            "peek_from cancelled",
            io::ErrorKind::Interrupted,
            err.kind()
        );
        crate::assert_with_log!(
            path_server.registration.is_none(),
            "peek_from registration skipped",
            true,
            path_server.registration.is_none()
        );

        let waker = noop_waker();
        let mut poll_cx = Context::from_waker(&waker);

        let recv_ready = path_server.poll_recv_ready(&mut poll_cx);
        crate::assert_with_log!(
            matches!(
                recv_ready,
                Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
            ),
            "poll_recv_ready cancelled",
            "Poll::Ready(Interrupted)",
            format!("{recv_ready:?}")
        );
        crate::assert_with_log!(
            path_server.registration.is_none(),
            "poll_recv_ready registration skipped",
            true,
            path_server.registration.is_none()
        );

        let send_ready = connected_a.poll_send_ready(&mut poll_cx);
        crate::assert_with_log!(
            matches!(
                send_ready,
                Poll::Ready(Err(ref err)) if err.kind() == io::ErrorKind::Interrupted
            ),
            "poll_send_ready cancelled",
            "Poll::Ready(Interrupted)",
            format!("{send_ready:?}")
        );
        crate::assert_with_log!(
            connected_a.registration.is_none(),
            "poll_send_ready registration skipped",
            true,
            connected_a.registration.is_none()
        );

        crate::test_complete!(
            "test_cancelled_datagram_ops_return_interrupted_without_registration"
        );
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    #[test]
    fn test_peer_cred() {
        init_test("test_datagram_peer_cred");
        let (a, b) = UnixDatagram::pair().expect("pair failed");

        // Both sides should be able to get peer credentials. macOS answers
        // the datagram pair with a typed `Unsupported` (LOCAL_PEERCRED is a
        // stream-socket facility there); that is the documented contract, so
        // the test records it instead of asserting Linux behaviour.
        let (cred_a, cred_b) = match (a.peer_cred(), b.peer_cred()) {
            (Ok(cred_a), Ok(cred_b)) => (cred_a, cred_b),
            (Err(err), _) | (_, Err(err))
                if cfg!(not(target_os = "linux")) && err.kind() == io::ErrorKind::Unsupported =>
            {
                crate::assert_with_log!(
                    true,
                    "datagram peer credentials unsupported on this platform (typed)",
                    "Unsupported",
                    err.kind()
                );
                crate::test_complete!("test_datagram_peer_cred");
                return;
            }
            (Err(err), _) | (_, Err(err)) => panic!("peer_cred failed: {err}"),
        };

        // Both should report the same process (ourselves)
        let user_id = nix::unistd::getuid().as_raw();
        let group_id = nix::unistd::getgid().as_raw();

        crate::assert_with_log!(cred_a.uid == user_id, "a uid", user_id, cred_a.uid);
        crate::assert_with_log!(cred_a.gid == group_id, "a gid", group_id, cred_a.gid);
        crate::assert_with_log!(cred_b.uid == user_id, "b uid", user_id, cred_b.uid);
        crate::assert_with_log!(cred_b.gid == group_id, "b gid", group_id, cred_b.gid);

        // On Linux, pid should be available and match our process
        #[cfg(target_os = "linux")]
        {
            let proc_id = i32::try_from(std::process::id()).expect("process id fits in i32");
            let pid_a = cred_a.pid.expect("pid should be available on Linux");
            let pid_b = cred_b.pid.expect("pid should be available on Linux");
            crate::assert_with_log!(pid_a == proc_id, "a pid", proc_id, pid_a);
            crate::assert_with_log!(pid_b == proc_id, "b pid", proc_id, pid_b);
        }

        crate::test_complete!("test_datagram_peer_cred");
    }

    /// br-asupersync-unix-socket-audit-alx18f item 4: Linux SO_PEERCRED answers
    /// an unconnected datagram socket, and one connected with connect(), with
    /// uid and gid -1. peer_cred must refuse them, not return them.
    #[cfg(target_os = "linux")]
    #[test]
    fn peer_cred_refuses_sockets_without_kernel_credentials() {
        init_test("peer_cred_refuses_sockets_without_kernel_credentials");
        let unbound = UnixDatagram::unbound().expect("unbound socket");
        let err = unbound
            .peer_cred()
            .expect_err("an unconnected socket has no peer credentials");
        assert_eq!(err.kind(), io::ErrorKind::NotConnected, "{err}");

        let name = format!("asupersync-peer-cred-{}", std::process::id());
        let _receiver = UnixDatagram::bind_abstract(name.as_bytes()).expect("bind abstract");
        let sender = UnixDatagram::unbound().expect("unbound sender");
        sender
            .connect_abstract(name.as_bytes())
            .expect("connect to the abstract name");
        let err = sender
            .peer_cred()
            .expect_err("connect() records no peer credentials for a datagram socket");
        assert_eq!(err.kind(), io::ErrorKind::NotConnected, "{err}");
        crate::test_complete!("peer_cred_refuses_sockets_without_kernel_credentials");
    }

    #[test]
    fn test_bind_refuses_non_socket_path() {
        init_test("test_datagram_bind_refuses_non_socket_path");
        let dir = socket_dir();
        let path = dir.path().join("not_a_socket");
        std::fs::write(&path, b"important data").expect("write file");

        let err = UnixDatagram::bind(&path).expect_err("bind should reject non-socket path");
        crate::assert_with_log!(
            err.kind() == std::io::ErrorKind::AlreadyExists,
            "error kind",
            std::io::ErrorKind::AlreadyExists,
            err.kind()
        );

        // Verify the file was NOT deleted
        let contents = std::fs::read(&path).expect("read file");
        let unchanged = contents == b"important data";
        crate::assert_with_log!(unchanged, "file unchanged", true, unchanged);
        crate::test_complete!("test_datagram_bind_refuses_non_socket_path");
    }
