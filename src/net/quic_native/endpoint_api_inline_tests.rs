    #![allow(clippy::cast_possible_truncation)]
    use super::*;

    fn test_cx() -> Cx<crate::cx::cap::All> {
        Cx::for_testing()
    }

    fn pair() -> (QuicConnection, QuicConnection) {
        // `NativeQuicConnectionConfig` is `Copy`, so each constructor copies it.
        let cfg = NativeQuicConnectionConfig::default();
        (QuicConnection::client(cfg), QuicConnection::server(cfg))
    }

    fn established_pair(cx: &Cx) -> (QuicConnection, QuicConnection) {
        let (mut client, mut server) = pair();
        client.record_verified_server_identity();
        establish_loopback(cx, &mut client, &mut server).expect("loopback establishes");
        (client, server)
    }

    #[test]
    fn poll_open_stream_resumes_from_peer_credit_and_carries_application_bytes() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Wake, Waker};

        #[derive(Default)]
        struct OpenWake(AtomicUsize);
        impl Wake for OpenWake {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let cx = test_cx();
        let mut client = QuicConnection::client(NativeQuicConnectionConfig {
            max_local_bidi: 0,
            max_local_uni: 0,
            ..NativeQuicConnectionConfig::default()
        });
        let mut server = QuicConnection::server(NativeQuicConnectionConfig::default());
        server.inner_mut().set_remote_stream_limits(0, 0);
        client.record_verified_server_identity();
        establish_loopback(&cx, &mut client, &mut server).unwrap();
        let wakes = Arc::new(OpenWake::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut task_cx = TaskContext::from_waker(&waker);
        assert!(client.poll_open_bidi_stream(&cx, &mut task_cx).is_pending());
        assert!(client.poll_open_uni_stream(&cx, &mut task_cx).is_pending());
        assert_eq!(client.inner().streams().len(), 0);

        server.inner_mut().set_remote_stream_limits(1, 1);
        assert!(pump_app_data(&cx, &mut server, &mut client, 1200, 10).unwrap() > 0);
        assert_eq!(wakes.0.load(Ordering::SeqCst), 2);
        assert_eq!(client.inner().streams().len(), 0, "credit does not allocate");
        assert_eq!(client.poll_open_bidi_stream(&cx, &mut task_cx), Poll::Ready(Ok(StreamId(0))));
        assert_eq!(client.poll_open_uni_stream(&cx, &mut task_cx), Poll::Ready(Ok(StreamId(2))));
        client.write_stream(&cx, StreamId(0), Bytes::from_static(b"request"), true).unwrap();
        client.write_stream(&cx, StreamId(2), Bytes::from_static(b"feedback"), true).unwrap();
        assert!(pump_app_data(&cx, &mut client, &mut server, 1200, 20).unwrap() > 0);
        assert_eq!(server.read_stream(&cx, StreamId(0), 32).unwrap().as_ref(), b"request");
        assert_eq!(server.read_stream(&cx, StreamId(2), 32).unwrap().as_ref(), b"feedback");
        assert!(server.is_control_eof(StreamId(0)).unwrap());
        assert!(server.is_control_eof(StreamId(2)).unwrap());
        assert!(cx.inner.read().cancel_waker_registrations.is_empty());
    }

    #[test]
    fn loopback_reassembly_backpressure_retains_reliable_frames_for_retry() {
        let cx = test_cx();
        let (mut client, mut server) = established_pair(&cx);
        // Settle server HANDSHAKE_DONE and its ACK before testing whether a
        // rejected stream packet produces any output. Neither handshake
        // control frame is a response to the backpressured stream packet.
        assert_eq!(
            pump_app_data(&cx, &mut server, &mut client, 1200, 0).unwrap(),
            1
        );
        assert_eq!(
            pump_app_data(&cx, &mut client, &mut server, 1200, 0).unwrap(),
            1
        );
        assert_eq!(
            pump_app_data(&cx, &mut server, &mut client, 1200, 0).unwrap(),
            0
        );
        let id = client.open_bidi_stream(&cx).unwrap();
        let mut expected = vec![b'.'; 8192];
        for fragment in 0..4095usize {
            expected[1 + fragment * 2] = b'x';
        }
        expected[8191] = b'z';
        client
            .write_stream(&cx, id, Bytes::copy_from_slice(&expected[..8191]), false)
            .unwrap();
        // Consume the sender's prefix into a fixture hole pattern. The actual
        // pump below must requeue its rejected tail and deliver it on retry.
        let prefix = client
            .inner
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 65535)
            .unwrap();
        client.inner.on_generated_frames_delivered(&prefix).unwrap();
        server.inner.accept_remote_stream(&cx, id).unwrap();
        for fragment in 0..4095u64 {
            server
                .inner
                .receive_stream_bytes(&cx, id, 1 + fragment * 2, Bytes::from_static(b"x"), false)
                .unwrap();
        }
        client
            .write_stream(&cx, id, Bytes::from_static(b"z"), true)
            .unwrap();
        assert_eq!(
            pump_app_data(&cx, &mut client, &mut server, 1200, 1).unwrap(),
            0
        );
        assert!(client.has_pending_stream_frames(id));
        assert!(
            server
                .inner
                .generate_frames(&cx, PacketNumberSpace::ApplicationData, 65535)
                .unwrap()
                .is_empty()
        );
        server
            .inner
            .receive_stream_bytes(&cx, id, 0, Bytes::copy_from_slice(&expected[..8191]), false)
            .unwrap();
        assert!(pump_app_data(&cx, &mut client, &mut server, 1200, 2).unwrap() > 0);
        assert!(!client.has_pending_stream_frames(id));
        let mut received = Vec::new();
        while !server.is_control_eof(id).unwrap() {
            let bytes = server.read_stream(&cx, id, 8192).unwrap();
            assert!(!bytes.is_empty());
            received.extend_from_slice(&bytes);
        }
        assert_eq!(received, expected);
        assert!(server.is_control_eof(id).unwrap());
    }

    #[test]
    fn loopback_reaches_established_on_both_sides() {
        let cx = test_cx();
        let (client, server) = established_pair(&cx);
        assert_eq!(client.state(), QuicConnectionState::Established);
        assert_eq!(server.state(), QuicConnectionState::Established);
        assert!(client.can_send_app_data());
        assert!(server.can_send_app_data());
        assert_eq!(client.role(), StreamRole::Client);
        assert_eq!(server.role(), StreamRole::Server);
    }

    #[test]
    fn client_handshake_fails_closed_without_verified_identity() {
        let cx = test_cx();
        let (mut client, mut server) = pair();
        // No record_verified_server_identity() -> client confirm must fail closed.
        let err = establish_loopback(&cx, &mut client, &mut server)
            .expect_err("client must fail closed without verified identity");
        assert!(
            matches!(err, NativeQuicConnectionError::Tls(_)),
            "expected a TLS fail-closed error, got {err:?}"
        );
        assert_ne!(client.state(), QuicConnectionState::Established);
    }

    #[test]
    fn datagram_roundtrip_exact_and_fifo() {
        let cx = test_cx();
        let (mut client, mut server) = established_pair(&cx);

        let payloads: [&[u8]; 3] = [b"first-symbol", b"second", b"third-datagram-payload"];
        for p in payloads {
            client
                .send_datagram(&cx, Bytes::copy_from_slice(p))
                .expect("queue datagram");
        }
        let moved = pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            1000,
        )
        .expect("pump");
        assert!(
            moved >= payloads.len(),
            "expected >= {} frames",
            payloads.len()
        );

        for expected in payloads {
            let got = server.recv_datagram().expect("a datagram arrived");
            assert_eq!(got.as_ref(), expected, "exact payload, FIFO order");
        }
        assert!(server.recv_datagram().is_none(), "no extra datagrams");
        assert_eq!(client.datagrams_sent(), payloads.len() as u64);
        assert_eq!(server.datagrams_received(), payloads.len() as u64);
    }

    #[test]
    fn datagram_send_before_established_is_rejected() {
        let cx = test_cx();
        let (mut client, _server) = pair();
        let err = client
            .send_datagram(&cx, Bytes::from_static(b"too early"))
            .expect_err("must reject before established");
        assert!(matches!(err, NativeQuicConnectionError::InvalidState(_)));
    }

    #[test]
    fn oversize_datagram_is_rejected_fail_closed() {
        let cx = test_cx();
        let (mut client, _server) = established_pair(&cx);
        let huge = Bytes::from(vec![0xABu8; 4096]);
        let err = client
            .send_datagram(&cx, huge)
            .expect_err("oversize datagram must be rejected");
        assert!(matches!(
            err,
            NativeQuicConnectionError::DatagramTooLarge { .. }
        ));
    }

    #[test]
    fn control_stream_roundtrip_multi_packet_reassembly() {
        let cx = test_cx();
        let (mut client, mut server) = established_pair(&cx);

        let stream = client
            .open_control_stream(&cx)
            .expect("open control stream");
        // A payload large enough to span several small packets.
        let body: Vec<u8> = (0..2048u32).map(|i| (i % 251) as u8).collect();
        client
            .write_control(&cx, stream, Bytes::copy_from_slice(&body), true)
            .expect("write control bytes + FIN");

        // Tiny budget forces multi-packet fragmentation across the pump.
        let moved = pump_until_idle(&cx, &mut client, &mut server, 256, 2000).expect("pump");
        assert!(
            moved > 1,
            "large payload should span multiple packets, moved {moved}"
        );

        let mut received = Vec::new();
        loop {
            let chunk = server
                .read_control(&cx, stream, 4096)
                .expect("read control");
            if chunk.is_empty() {
                break;
            }
            received.extend_from_slice(&chunk);
        }
        assert_eq!(received, body, "stream bytes reassembled in order");
        assert!(
            server.is_control_eof(stream).expect("eof query"),
            "FIN should be observed after consuming all bytes"
        );
    }

    #[test]
    fn poll_recv_datagram_pending_then_ready() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::Wake;

        struct CountingWaker(AtomicUsize);
        impl Wake for CountingWaker {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let cx = test_cx();
        let (mut client, mut server) = established_pair(&cx);

        let counter = Arc::new(CountingWaker(AtomicUsize::new(0)));
        let waker = counter.clone().into();
        let mut task_cx = TaskContext::from_waker(&waker);

        // Empty queue: registers the waker, returns Pending (no busy-poll).
        assert!(matches!(
            server.poll_recv_datagram(&cx, &mut task_cx),
            Poll::Pending
        ));

        // Deliver a datagram; the registered waker must fire.
        client
            .send_datagram(&cx, Bytes::from_static(b"wakeup"))
            .expect("queue datagram");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            3000,
        )
        .expect("pump");
        assert!(
            counter.0.load(Ordering::SeqCst) >= 1,
            "arrival must wake the registered task"
        );

        // Now the poll resolves with the exact payload.
        match server.poll_recv_datagram(&cx, &mut task_cx) {
            Poll::Ready(Ok(got)) => assert_eq!(got.as_ref(), b"wakeup"),
            other => panic!("expected Ready(Ok), got {other:?}"),
        }
    }

    #[test]
    fn path_stats_are_exposed() {
        let cx = test_cx();
        let (client, _server) = established_pair(&cx);
        let stats = client.path_stats();
        // Congestion window has a nonzero initial value; in-flight starts at 0.
        assert!(stats.congestion_window_bytes > 0);
        assert_eq!(stats.bytes_in_flight, 0);
        assert_eq!(stats.pto_count, 0);
        assert_eq!(stats.packets_acked, 0);
        assert_eq!(stats.packets_lost, 0);
        assert_eq!(stats.loss_rate, 0.0);
    }

    #[test]
    fn graceful_close_transitions_out_of_established() {
        let cx = test_cx();
        let (mut client, _server) = established_pair(&cx);
        client.begin_close(&cx, 5000, 0).expect("begin close");
        assert_ne!(client.state(), QuicConnectionState::Established);
    }
