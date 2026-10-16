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
    use futures_lite::future;
    use std::pin::Pin;

    use std::task::Poll;

    enum WriteBehavior {
        Immediate,
        PendingFirst,
        PartialThenPending(PartialWriteStage),
    }

    enum PartialWriteStage {
        WritePrefix(usize),
        PendingTail,
    }

    struct TestIo {
        read_data: Vec<u8>,
        read_pos: usize,
        written: Vec<u8>,
        fail_writes: bool,
        pending_first_read: bool,
        write_behavior: WriteBehavior,
        pending_first_flush: bool,
        flush_calls: usize,
        shutdown_calls: usize,
    }

    impl TestIo {
        fn new() -> Self {
            Self::with_read_data(Vec::new())
        }

        fn with_read_data(read_data: Vec<u8>) -> Self {
            Self {
                read_data,
                read_pos: 0,
                written: Vec::new(),
                fail_writes: false,
                pending_first_read: false,
                write_behavior: WriteBehavior::Immediate,
                pending_first_flush: false,
                flush_calls: 0,
                shutdown_calls: 0,
            }
        }

        fn with_write_failure(mut self) -> Self {
            self.fail_writes = true;
            self
        }

        fn with_pending_first_read(mut self) -> Self {
            self.pending_first_read = true;
            self
        }

        fn with_pending_first_write(mut self) -> Self {
            self.write_behavior = WriteBehavior::PendingFirst;
            self
        }

        fn with_partial_first_write(mut self, len: usize) -> Self {
            self.write_behavior =
                WriteBehavior::PartialThenPending(PartialWriteStage::WritePrefix(len));
            self
        }

        fn with_pending_first_flush(mut self) -> Self {
            self.pending_first_flush = true;
            self
        }
    }

    fn encode_client_frame(frame: Frame) -> Vec<u8> {
        let mut codec = FrameCodec::client();
        let mut out = BytesMut::new();
        codec
            .encode(frame, &mut out)
            .expect("frame encoding should succeed");
        out.to_vec()
    }

    fn encode_server_frame(frame: Frame) -> Vec<u8> {
        let mut codec = FrameCodec::server();
        let mut out = BytesMut::new();
        codec
            .encode(frame, &mut out)
            .expect("frame encoding should succeed");
        out.to_vec()
    }

    impl AsyncRead for TestIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.pending_first_read {
                self.pending_first_read = false;
                _cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let remaining = &self.read_data[self.read_pos..];
            let to_read = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_read]);
            self.read_pos += to_read;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for TestIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.fail_writes {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "synthetic write failure",
                )));
            }
            match std::mem::replace(&mut self.write_behavior, WriteBehavior::Immediate) {
                WriteBehavior::Immediate => {}
                WriteBehavior::PendingFirst
                | WriteBehavior::PartialThenPending(PartialWriteStage::PendingTail) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                WriteBehavior::PartialThenPending(PartialWriteStage::WritePrefix(len)) => {
                    let to_write = len.min(buf.len());
                    self.written.extend_from_slice(&buf[..to_write]);
                    self.write_behavior =
                        WriteBehavior::PartialThenPending(PartialWriteStage::PendingTail);
                    return Poll::Ready(Ok(to_write));
                }
            }
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            self.flush_calls += 1;
            if self.pending_first_flush {
                self.pending_first_flush = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            self.shutdown_calls += 1;
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn test_acceptor_builder() {
        let acceptor = WebSocketAcceptor::new()
            .protocol("chat")
            .protocol("superchat")
            .max_frame_size(1024 * 1024)
            .max_pending_write_bytes(4096)
            .slow_consumer_policy(SlowConsumerPolicy::CloseWithTryAgainLater)
            .ping_interval(Some(Duration::from_secs(30)))
            .close_timeout(Duration::from_secs(10));

        assert_eq!(acceptor.config.max_frame_size, 1024 * 1024);
        assert_eq!(acceptor.config.max_pending_write_bytes, 4096);
        assert_eq!(
            acceptor.config.slow_consumer_policy,
            SlowConsumerPolicy::CloseWithTryAgainLater
        );
        assert_eq!(acceptor.config.ping_interval, Some(Duration::from_secs(30)));
        assert_eq!(
            acceptor.config.close_config.close_timeout,
            Duration::from_secs(10)
        );
    }

    #[test]
    fn test_ws_accept_error_display() {
        let err = WsAcceptError::Cancelled;
        assert_eq!(err.to_string(), "accept cancelled");

        let err = WsAcceptError::InvalidRequest("bad header".into());
        assert!(err.to_string().contains("invalid request"));
    }

    #[test]
    fn acceptor_protocol_and_extension_builder() {
        let acceptor = WebSocketAcceptor::new()
            .protocol("graphql-ws")
            .protocol("graphql-transport-ws")
            .extension("permessage-deflate");

        // Protocols should be tracked in config.
        assert_eq!(acceptor.config.protocols.len(), 2);
        assert_eq!(acceptor.config.protocols[0], "graphql-ws");
        assert_eq!(acceptor.config.protocols[1], "graphql-transport-ws");
    }

    #[test]
    fn acceptor_default() {
        let acceptor = WebSocketAcceptor::default();
        assert_eq!(acceptor.config.max_frame_size, 16 * 1024 * 1024);
        assert!(acceptor.config.protocols.is_empty());
    }

    #[test]
    fn acceptor_max_message_size_builder() {
        let acceptor = WebSocketAcceptor::new().max_message_size(1024);
        assert_eq!(acceptor.config.max_message_size, 1024);
    }

    #[test]
    fn ws_accept_error_source() {
        use std::error::Error;

        let err = WsAcceptError::Cancelled;
        assert!(err.source().is_none());

        let io_err = WsAcceptError::Io(io::Error::new(io::ErrorKind::BrokenPipe, "broken"));
        assert!(io_err.source().is_some());
    }

    #[test]
    fn ws_accept_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        let ws_err = WsAcceptError::from(io_err);
        assert!(matches!(ws_err, WsAcceptError::Io(_)));
        assert!(ws_err.to_string().contains("I/O error"));
    }

    // Pure data-type tests (wave 15 – CyanBarn)

    #[test]
    fn acceptor_debug() {
        let acceptor = WebSocketAcceptor::new();
        let dbg = format!("{acceptor:?}");
        assert!(dbg.contains("WebSocketAcceptor"));
    }

    #[test]
    fn acceptor_clone() {
        let acceptor = WebSocketAcceptor::new()
            .protocol("chat")
            .max_frame_size(4096);
        let cloned = acceptor;
        assert_eq!(cloned.config.max_frame_size, 4096);
        assert_eq!(cloned.config.protocols.len(), 1);
    }

    #[test]
    fn acceptor_close_timeout_default() {
        let acceptor = WebSocketAcceptor::default();
        // Default close timeout should be reasonable (non-zero).
        assert!(acceptor.config.close_config.close_timeout > Duration::ZERO);
    }

    #[test]
    fn acceptor_builder_chain_all() {
        let acceptor = WebSocketAcceptor::new()
            .protocol("mqtt")
            .extension("permessage-deflate")
            .max_frame_size(512)
            .max_message_size(2048)
            .max_pending_write_bytes(1024)
            .ping_interval(Some(Duration::from_secs(15)))
            .close_timeout(Duration::from_secs(5));

        assert_eq!(acceptor.config.max_frame_size, 512);
        assert_eq!(acceptor.config.max_message_size, 2048);
        assert_eq!(acceptor.config.max_pending_write_bytes, 1024);
        assert_eq!(acceptor.config.ping_interval, Some(Duration::from_secs(15)));
        assert_eq!(
            acceptor.config.close_config.close_timeout,
            Duration::from_secs(5)
        );
    }

    #[test]
    fn acceptor_ping_interval_none() {
        let acceptor = WebSocketAcceptor::new().ping_interval(None);
        assert_eq!(acceptor.config.ping_interval, None);
    }

    #[test]
    fn ws_accept_error_display_invalid_request() {
        let err = WsAcceptError::InvalidRequest("missing Upgrade header".into());
        let s = err.to_string();
        assert!(s.contains("invalid request"));
        assert!(s.contains("missing Upgrade header"));
    }

    #[test]
    fn ws_accept_error_display_cancelled() {
        let err = WsAcceptError::Cancelled;
        assert_eq!(err.to_string(), "accept cancelled");
    }

    #[test]
    fn ws_accept_error_debug() {
        let err = WsAcceptError::Cancelled;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Cancelled"));
    }

    #[test]
    fn ws_accept_error_from_ws_error() {
        let ws_err = WsError::ProtocolViolation("bad frame");
        let accept_err = WsAcceptError::from(ws_err);
        assert!(matches!(accept_err, WsAcceptError::Protocol(_)));
    }

    #[test]
    fn pending_pong_queue_keeps_most_recent_payloads() {
        let mut pending = std::collections::VecDeque::new();
        for n in 0u8..20 {
            enqueue_pending_pong(&mut pending, crate::bytes::Bytes::from(vec![n]));
        }

        assert_eq!(pending.len(), MAX_PENDING_PONGS);
        let kept: Vec<u8> = pending
            .into_iter()
            .map(|payload| *payload.first().expect("single-byte payload"))
            .collect();
        assert_eq!(kept, (4u8..20).collect::<Vec<_>>());
    }

    #[test]
    fn send_close_message_initiates_close_handshake() {
        future::block_on(async {
            let accept = AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let mut ws = ServerWebSocket::from_upgraded(
                TestIo::new(),
                WebSocketConfig::default(),
                accept,
                &[],
            );
            let cx = Cx::for_testing();

            assert!(ws.is_open(), "connection should start open");
            ws.send(&cx, Message::Close(None))
                .await
                .expect("sending close should succeed");
            assert!(
                !ws.is_open(),
                "sending Message::Close must transition handshake out of open state"
            );

            let err = ws
                .send(&cx, Message::text("late payload"))
                .await
                .expect_err("data frames must be rejected after close initiation");
            assert!(
                matches!(err, WsError::Io(ref e) if e.kind() == io::ErrorKind::NotConnected),
                "expected NotConnected after close initiation, got {err:?}"
            );
        });
    }

    // A Ping or Pong payload over 125 bytes made send and ping panic in
    // Frame::ping / Frame::pong. They now return ControlFrameTooLarge and
    // write nothing.
    #[test]
    fn oversized_control_payloads_are_errors_not_panics() {
        future::block_on(async {
            let accept = AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let mut ws = ServerWebSocket::from_upgraded(
                TestIo::new(),
                WebSocketConfig::default(),
                accept,
                &[],
            );
            let cx = Cx::for_testing();
            let big = crate::bytes::Bytes::from(vec![0_u8; 126]);
            let results = [
                ws.send(&cx, Message::Ping(big.clone())).await,
                ws.send(&cx, Message::Pong(big.clone())).await,
                ws.ping(&cx, big.clone()).await,
            ];
            for result in results {
                assert!(
                    matches!(result, Err(WsError::ControlFrameTooLarge(126))),
                    "unexpected result {result:?}"
                );
            }
            assert!(ws.io.written.is_empty());
            ws.ping(&cx, crate::bytes::Bytes::from(vec![0_u8; 125]))
                .await
                .expect("a 125-byte ping is allowed");
            assert_eq!(ws.io.written.len(), 2 + 125);
        });
    }

    #[test]
    fn send_rejects_frame_larger_than_pending_write_budget_before_writing() {
        future::block_on(async {
            let accept = AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let config = WebSocketConfig::default()
                .max_pending_write_bytes(4)
                .slow_consumer_policy(SlowConsumerPolicy::CloseWithTryAgainLater);
            let mut ws = ServerWebSocket::from_upgraded(TestIo::new(), config, accept, &[]);
            let cx = Cx::for_testing();

            let err = ws
                .send(&cx, Message::text("hello"))
                .await
                .expect_err("oversize encoded frame must be rejected before writing");

            assert!(
                matches!(
                    err,
                    WsError::OutboundBufferFull {
                        pending: 0,
                        attempted,
                        max: 4,
                        action: "close-with-1013",
                    } if attempted > 4
                ),
                "expected outbound buffer cap error, got {err:?}"
            );
            assert!(
                ws.io.written.is_empty(),
                "budget rejection must not commit a partial server frame"
            );
            assert!(ws.is_closed(), "close policy must close the connection");
            assert_eq!(
                ws.close_handshake
                    .our_reason()
                    .and_then(|reason| reason.code),
                Some(crate::net::websocket::CloseCode::TryAgainLater)
            );
        });
    }

    #[test]
    fn recv_keeps_close_received_state_if_response_send_fails() {
        future::block_on(async {
            let accept = AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let io = TestIo::with_read_data(encode_client_frame(Frame::close(Some(1000), None)))
                .with_write_failure();
            let mut ws =
                ServerWebSocket::from_upgraded(io, WebSocketConfig::default(), accept, &[]);
            let cx = Cx::for_testing();

            let err = ws
                .recv(&cx)
                .await
                .expect_err("close response write should fail");
            assert!(
                matches!(err, WsError::Io(ref e) if e.kind() == io::ErrorKind::BrokenPipe),
                "expected synthetic broken-pipe write failure, got {err:?}"
            );
            assert!(
                !ws.is_closed(),
                "failed close response writes must not incorrectly finish the handshake"
            );
            assert_eq!(
                ws.close_handshake.state(),
                crate::net::websocket::CloseState::CloseReceived,
                "failed close response writes must leave the handshake waiting for a retry"
            );
        });
    }

    #[test]
    fn send_ignores_cancel_while_masked() {
        let accept = AcceptResponse {
            accept_key: String::new(),
            protocol: None,
            extensions: Vec::new(),
        };
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let _guard = Cx::set_current(Some(cx.clone()));
        let mut ws =
            ServerWebSocket::from_upgraded(TestIo::new(), WebSocketConfig::default(), accept, &[]);
        let masked = Message::text("masked");

        cx.masked(|| future::block_on(ws.send(&cx, masked.clone())))
            .expect("masked server send should defer cancellation");

        assert_eq!(
            ws.io.written,
            encode_server_frame(Frame::from(masked)),
            "masked server send should still flush the original frame"
        );
        assert!(
            cx.is_cancel_requested(),
            "masked send must not clear the pending cancellation"
        );
        assert!(
            cx.checkpoint().is_err(),
            "cancellation must still surface after the mask is released"
        );
    }

    #[test]
    fn send_mid_write_cancel_uses_explicit_cx_without_ambient_current() {
        future::block_on(async {
            let accept = AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let mut ws = ServerWebSocket::from_upgraded(
                TestIo::new().with_pending_first_write(),
                WebSocketConfig::default(),
                accept,
                &[],
            );
            let cx = Cx::for_testing();
            assert!(
                Cx::current().is_none(),
                "regression must not rely on ambient Cx::current()"
            );

            let mut send = Box::pin(ws.send(&cx, Message::text("cancelled")));
            let waker = std::task::Waker::noop().clone();
            let mut poll_cx = std::task::Context::from_waker(&waker);

            assert!(
                matches!(send.as_mut().poll(&mut poll_cx), Poll::Pending),
                "first send poll should park in the transport write"
            );

            cx.set_cancel_requested(true);
            let err = match send.as_mut().poll(&mut poll_cx) {
                Poll::Ready(Err(err)) => err,
                other => panic!("expected cancelled send error, got {other:?}"),
            };

            assert!(
                matches!(err, WsError::Io(ref e) if e.kind() == io::ErrorKind::Interrupted),
                "expected interrupted send after explicit Cx cancellation, got {err:?}"
            );
            drop(send);
            assert!(
                ws.io.written.is_empty(),
                "cancelled server send must not commit bytes after a pending write"
            );
            assert!(
                ws.write_buf.is_empty(),
                "cancelled server send must not leave buffered bytes when no write committed"
            );
        });
    }

    #[test]
    fn pre_cancelled_send_emits_close_frame_before_error() {
        future::block_on(async {
            let accept = AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let mut ws = ServerWebSocket::from_upgraded(
                TestIo::new(),
                WebSocketConfig::default(),
                accept,
                &[],
            );
            let cx = Cx::for_testing();
            cx.set_cancel_requested(true);

            let err = ws
                .send(&cx, Message::text("cancelled"))
                .await
                .expect_err("pre-cancelled send should fail");

            assert!(
                matches!(err, WsError::Io(ref e) if e.kind() == io::ErrorKind::Interrupted),
                "expected interrupted send after pre-cancelled Cx, got {err:?}"
            );
            assert_eq!(
                ws.close_handshake.state(),
                CloseState::CloseSent,
                "pre-cancelled send should initiate a close handshake"
            );
            assert_eq!(
                ws.io.written,
                encode_server_frame(Frame::close(Some(1001), None)),
                "pre-cancelled server send should emit exactly one going-away close frame"
            );
        });
    }

    #[test]
    fn cancellation_closes_with_the_configured_code() {
        // br-asupersync-y6naky: CloseConfig::with_cancellation_code was
        // accepted but cancellation always sent GoingAway (1001).
        future::block_on(async {
            let accept = AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let config = WebSocketConfig {
                close_config: super::super::CloseConfig::new()
                    .with_cancellation_code(super::super::CloseCode::ServiceRestart),
                ..WebSocketConfig::default()
            };
            let mut ws = ServerWebSocket::from_upgraded(TestIo::new(), config, accept, &[]);
            let cx = Cx::for_testing();
            cx.set_cancel_requested(true);
            let _ = ws.send(&cx, Message::text("cancelled")).await;
            assert_eq!(
                ws.io.written,
                encode_server_frame(Frame::close(Some(1012), None)),
                "the cancellation close frame carries the configured code"
            );
        });
    }

    #[test]
    fn cancelled_send_does_not_flush_frame_later() {
        future::block_on(async {
            let accept = AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let mut ws = ServerWebSocket::from_upgraded(
                TestIo::new().with_pending_first_write(),
                WebSocketConfig::default(),
                accept,
                &[],
            );
            let cx = Cx::for_testing();
            let cancelled = Message::text("cancelled");
            let delivered = Message::text("delivered");
            let mut cancelled_send = Box::pin(ws.send(&cx, cancelled));
            let waker = std::task::Waker::noop().clone();
            let mut poll_cx = std::task::Context::from_waker(&waker);

            assert!(
                matches!(cancelled_send.as_mut().poll(&mut poll_cx), Poll::Pending),
                "first send should park before any bytes are written"
            );
            drop(cancelled_send);

            assert!(
                ws.write_buf.is_empty(),
                "dropping a parked send must not leave its frame in the shared write buffer"
            );

            ws.send(&cx, delivered.clone())
                .await
                .expect("second send should succeed");

            let expected = vec![129, 9, 100, 101, 108, 105, 118, 101, 114, 101, 100];
            assert_eq!(
                ws.io.written, expected,
                "later flushes must not emit bytes from a cancelled send"
            );
        });
    }

    #[test]
    fn cancelled_send_after_partial_write_preserves_tail_for_later_flush() {
        future::block_on(async {
            let accept = AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let mut ws = ServerWebSocket::from_upgraded(
                TestIo::new().with_partial_first_write(1),
                WebSocketConfig::default(),
                accept,
                &[],
            );
            let cx = Cx::for_testing();
            let cancelled = Message::text("cancelled");
            let delivered = Message::text("delivered");
            let expected_cancelled = encode_server_frame(Frame::from(cancelled.clone()));
            let expected_delivered = encode_server_frame(Frame::from(delivered.clone()));
            let mut cancelled_send = Box::pin(ws.send(&cx, cancelled));
            let waker = std::task::Waker::noop().clone();
            let mut poll_cx = std::task::Context::from_waker(&waker);

            assert!(
                matches!(cancelled_send.as_mut().poll(&mut poll_cx), Poll::Pending),
                "send should park after the first byte is written and the remainder is buffered"
            );
            drop(cancelled_send);

            assert!(
                !ws.write_buf.is_empty(),
                "after any byte hits the wire, the unwritten tail must stay durable"
            );
            assert_eq!(
                ws.io.written,
                expected_cancelled[..1].to_vec(),
                "the transport should contain only the committed prefix before retry"
            );

            ws.send(&cx, delivered)
                .await
                .expect("later sends should flush the durable tail first");

            assert_eq!(
                ws.io.written,
                [expected_cancelled, expected_delivered].concat(),
                "retrying send must finish the first server frame before appending the second"
            );
        });
    }

    #[test]
    fn close_after_cancelled_recv_flushes_pending_echo_without_second_close() {
        future::block_on(async {
            let accept = AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let read_data = encode_client_frame(Frame::close(Some(1000), None));
            let mut ws = ServerWebSocket::from_upgraded(
                TestIo::with_read_data(read_data).with_pending_first_write(),
                WebSocketConfig::default(),
                accept,
                &[],
            );
            let cx = Cx::for_testing();
            let mut cancelled_recv = Box::pin(ws.recv(&cx));
            let waker = std::task::Waker::noop().clone();
            let mut poll_cx = std::task::Context::from_waker(&waker);

            assert!(
                matches!(cancelled_recv.as_mut().poll(&mut poll_cx), Poll::Pending),
                "recv should park while flushing the echoed close response"
            );
            drop(cancelled_recv);

            assert_eq!(
                ws.close_handshake.state(),
                CloseState::CloseReceived,
                "cancelling recv mid-flush must leave the echoed response pending"
            );
            assert!(
                !ws.write_buf.is_empty(),
                "the echoed close response should stay buffered for a later retry"
            );

            ws.close(&cx, CloseReason::going_away())
                .await
                .expect("close should finish the pending echoed response");

            assert!(
                ws.is_closed(),
                "finishing the pending echoed response must close the handshake"
            );
            assert_eq!(
                ws.io.written,
                encode_server_frame(Frame::close(Some(1000), None)),
                "retrying close after a cancelled recv must not append a second close frame"
            );
        });
    }

    // RFC 6455 section 5.5.1: the server MUST close the TCP connection once
    // the close handshake is complete. Neither close() nor a recv that echoed
    // the client's Close shut the transport down, so it stayed open until the
    // value was dropped while the client waited for it.
    #[test]
    fn server_shuts_down_the_transport_after_the_close_handshake() {
        future::block_on(async {
            let accept = || AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let cx = Cx::for_testing();
            let client_close = encode_client_frame(Frame::close(Some(1000), None));

            // The client starts the close: recv echoes it, then shuts down.
            let mut ws = ServerWebSocket::from_upgraded(
                TestIo::with_read_data(client_close.clone()),
                WebSocketConfig::default(),
                accept(),
                &[],
            );
            let message = ws.recv(&cx).await.expect("recv the client's close");
            assert!(matches!(message, Some(Message::Close(_))), "{message:?}");
            assert_eq!(
                ws.io.written,
                encode_server_frame(Frame::close(Some(1000), None))
            );
            assert_eq!(ws.io.shutdown_calls, 1);

            // The server starts the close: close() shuts down after the reply.
            let mut ws = ServerWebSocket::from_upgraded(
                TestIo::with_read_data(client_close),
                WebSocketConfig::default(),
                accept(),
                &[],
            );
            ws.close(&cx, CloseReason::normal())
                .await
                .expect("close handshake");
            assert!(ws.is_closed());
            assert_eq!(ws.io.shutdown_calls, 1);
        });
    }

    #[test]
    fn recv_mid_read_cancel_uses_explicit_cx_without_ambient_current() {
        future::block_on(async {
            let accept = AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let read_data = encode_client_frame(Frame::binary(vec![1, 2, 3]));
            let mut ws = ServerWebSocket::from_upgraded(
                TestIo::with_read_data(read_data).with_pending_first_read(),
                WebSocketConfig::default(),
                accept,
                &[],
            );
            let cx = Cx::for_testing();
            assert!(
                Cx::current().is_none(),
                "regression must not rely on ambient Cx::current()"
            );

            let mut recv = Box::pin(ws.recv(&cx));
            let waker = std::task::Waker::noop().clone();
            let mut poll_cx = std::task::Context::from_waker(&waker);

            assert!(
                matches!(recv.as_mut().poll(&mut poll_cx), Poll::Pending),
                "first receive poll should park in the transport read"
            );

            cx.set_cancel_requested(true);
            let err = match recv.as_mut().poll(&mut poll_cx) {
                Poll::Ready(Err(err)) => err,
                other => panic!("expected cancelled receive error, got {other:?}"),
            };
            drop(recv);

            assert!(
                matches!(err, WsError::Io(ref e) if e.kind() == io::ErrorKind::Interrupted),
                "expected interrupted receive after explicit Cx cancellation, got {err:?}"
            );
            assert_eq!(
                ws.io.read_pos, 0,
                "cancelled server recv must not consume transport bytes after pending read"
            );
            assert!(
                ws.read_buf.is_empty(),
                "cancelled server recv must not seed the websocket read buffer"
            );
        });
    }

    #[test]
    fn close_after_cancelled_recv_retries_pending_transport_flush_without_second_close() {
        future::block_on(async {
            let accept = AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let read_data = encode_client_frame(Frame::close(Some(1000), None));
            let mut ws = ServerWebSocket::from_upgraded(
                TestIo::with_read_data(read_data).with_pending_first_flush(),
                WebSocketConfig::default(),
                accept,
                &[],
            );
            let cx = Cx::for_testing();
            let mut cancelled_recv = Box::pin(ws.recv(&cx));
            let waker = std::task::Waker::noop().clone();
            let mut poll_cx = std::task::Context::from_waker(&waker);

            assert!(
                matches!(cancelled_recv.as_mut().poll(&mut poll_cx), Poll::Pending),
                "recv should park while the echoed close response is waiting on poll_flush"
            );
            drop(cancelled_recv);

            assert_eq!(
                ws.close_handshake.state(),
                CloseState::CloseReceived,
                "cancelling recv during poll_flush must leave the echoed response pending"
            );
            assert!(
                ws.write_buf.is_empty(),
                "all close-response bytes should already be written before the deferred flush"
            );
            assert_eq!(
                ws.io.flush_calls, 1,
                "the cancelled recv should have attempted exactly one transport flush"
            );

            ws.close(&cx, CloseReason::going_away())
                .await
                .expect("close should retry the deferred transport flush");

            assert!(
                ws.is_closed(),
                "retrying the deferred flush must close the handshake"
            );
            assert_eq!(
                ws.io.written,
                encode_server_frame(Frame::close(Some(1000), None)),
                "retrying close after a cancelled recv must not append a second close frame"
            );
            assert_eq!(
                ws.io.flush_calls, 2,
                "close should retry the deferred transport flush once"
            );
        });
    }

    #[test]
    fn close_retry_flushes_partially_sent_close_without_second_close() {
        future::block_on(async {
            let accept = AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let peer_close = encode_client_frame(Frame::close(Some(1000), None));
            let mut ws = ServerWebSocket::from_upgraded(
                TestIo::with_read_data(peer_close).with_partial_first_write(1),
                WebSocketConfig::default(),
                accept,
                &[],
            );
            let cx = Cx::for_testing();
            let expected = encode_server_frame(Frame::close(Some(1001), None));
            let mut cancelled_close = Box::pin(ws.close(&cx, CloseReason::going_away()));
            let waker = std::task::Waker::noop().clone();
            let mut poll_cx = std::task::Context::from_waker(&waker);

            assert!(
                matches!(cancelled_close.as_mut().poll(&mut poll_cx), Poll::Pending),
                "close should park after partially writing the initiated close frame"
            );
            drop(cancelled_close);

            assert_eq!(
                ws.close_handshake.state(),
                CloseState::CloseSent,
                "cancelling close after a partial write must keep the handshake in CloseSent"
            );
            assert!(
                !ws.write_buf.is_empty(),
                "the initiated close tail must remain buffered after partial I/O"
            );
            assert_eq!(
                ws.io.written,
                expected[..1].to_vec(),
                "only the committed close-frame prefix should hit the transport before retry"
            );

            ws.close(&cx, CloseReason::going_away())
                .await
                .expect("retrying close should flush the durable close tail and finish");

            assert!(
                ws.is_closed(),
                "the peer close should complete the handshake"
            );
            assert_eq!(
                ws.io.written, expected,
                "retrying close must finish the original server close frame without appending another"
            );
        });
    }

    /// br-asupersync-fmw87f M2: a close() dropped before the first byte of
    /// its Close frame was written still sends that Close when retried. The
    /// frame sat in a local buffer, so the retry found the handshake
    /// CloseSent, flushed an empty buffer and finished without ever sending
    /// a Close.
    #[test]
    fn close_dropped_before_writing_sends_its_close_on_retry() {
        future::block_on(async {
            let accept = AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let peer_close = encode_client_frame(Frame::close(Some(1000), None));
            let mut ws = ServerWebSocket::from_upgraded(
                TestIo::with_read_data(peer_close).with_pending_first_write(),
                WebSocketConfig::default(),
                accept,
                &[],
            );
            let cx = Cx::for_testing();
            let expected = encode_server_frame(Frame::close(Some(1001), None));
            let mut dropped_close = Box::pin(ws.close(&cx, CloseReason::going_away()));
            let waker = std::task::Waker::noop().clone();
            let mut poll_cx = std::task::Context::from_waker(&waker);
            assert!(
                matches!(dropped_close.as_mut().poll(&mut poll_cx), Poll::Pending),
                "close parks before its first write"
            );
            drop(dropped_close);
            assert_eq!(ws.close_handshake.state(), CloseState::CloseSent);
            assert!(ws.io.written.is_empty(), "nothing reached the transport");

            ws.close(&cx, CloseReason::going_away())
                .await
                .expect("the retried close finishes");
            assert!(ws.is_closed());
            assert_eq!(ws.io.written, expected, "the retry sent the original Close");
        });
    }

    /// br-asupersync-fmw87f: close_timeout bounds writing our Close as well
    /// as waiting for the answer. A peer that stopped reading held close()
    /// until cancellation, and without cancellation it never returned.
    #[test]
    fn close_on_a_stalled_peer_ends_at_the_close_timeout() {
        struct NeverWritableIo;
        impl AsyncRead for NeverWritableIo {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }
        impl AsyncWrite for NeverWritableIo {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Pending
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let closer = std::thread::Builder::new()
            .name("ws-stalled-close-timeout".into())
            .spawn(move || {
                let accept = AcceptResponse {
                    accept_key: String::new(),
                    protocol: None,
                    extensions: Vec::new(),
                };
                let mut config = WebSocketConfig::default();
                config.close_config.close_timeout = std::time::Duration::from_millis(100);
                let outcome = future::block_on(async {
                    let mut ws =
                        ServerWebSocket::from_upgraded(NeverWritableIo, config, accept, &[]);
                    let result = ws.close(&Cx::for_testing(), CloseReason::normal()).await;
                    (result, ws.is_closed())
                });
                let _ = done_tx.send(outcome);
            })
            .expect("spawn closer thread");

        let (result, closed) = done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("close() must end at its close timeout; it never returned");
        closer.join().expect("closer thread");
        assert!(result.is_ok(), "{result:?}");
        assert!(closed, "the connection is closed after the timeout");
    }

    #[test]
    fn close_replies_to_ping_before_finishing_handshake() {
        future::block_on(async {
            let accept = AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let read_data = [
                encode_client_frame(Frame::ping(crate::bytes::Bytes::from_static(b"hb"))),
                encode_client_frame(Frame::close(Some(1000), None)),
            ]
            .concat();
            let mut ws = ServerWebSocket::from_upgraded(
                TestIo::with_read_data(read_data),
                WebSocketConfig::default(),
                accept,
                &[],
            );
            let cx = Cx::for_testing();

            ws.close(&cx, CloseReason::going_away())
                .await
                .expect("close should answer ping and finish handshake");

            assert!(ws.is_closed(), "peer close should complete the handshake");
            assert_eq!(
                ws.io.written,
                [
                    encode_server_frame(Frame::close(Some(1001), None)),
                    encode_server_frame(Frame::pong(crate::bytes::Bytes::from_static(b"hb"))),
                ]
                .concat(),
                "close must still reply to ping frames received during the handshake"
            );
        });
    }

    #[test]
    fn write_external_cancel_wakes_a_parked_write() {
        // br-asupersync-2k3o9x: the server write path (flush_write_buf_with_cx /
        // write_buf_to_io_with_cx) parked on a stalled reader — a client that
        // connects then stops reading, so its TCP receive window fills and
        // poll_write never completes — must be woken by an external cancel, not
        // hang until the OS TCP timeout. NeverWritableIo returns Pending forever
        // WITHOUT self-waking, so the CancelWakerGuard's registered Waker is the
        // only thing that can re-poll the block_on task. (The existing
        // with_pending_first_write mock calls wake_by_ref before returning
        // Pending, so it only exercises the self-poll checkpoint, never this
        // truly-parked cross-thread cancel path.) client.rs has the identical
        // write path, fixed in 8947b2263.
        struct NeverWritableIo;
        impl AsyncRead for NeverWritableIo {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }
        impl AsyncWrite for NeverWritableIo {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Pending
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let cx = Cx::for_testing();
        let canceller = cx.clone();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let writer = std::thread::Builder::new()
            .name("ws-parked-writer".into())
            .spawn(move || {
                let started = std::time::Instant::now();
                let result = future::block_on(async {
                    let accept = AcceptResponse {
                        accept_key: String::new(),
                        protocol: None,
                        extensions: Vec::new(),
                    };
                    let mut ws = ServerWebSocket::from_upgraded(
                        NeverWritableIo,
                        WebSocketConfig::default(),
                        accept,
                        &[],
                    );
                    assert!(ws.is_open(), "connection should start open");
                    // Buffer bytes so the flush loop must call poll_write, which
                    // parks forever on NeverWritableIo.
                    ws.write_buf.extend_from_slice(b"a parked frame the stalled reader never drains");
                    ws.flush_write_buf_with_cx(Some(&cx)).await
                });
                let _ = done_tx.send((result, started.elapsed()));
            })
            .expect("spawn writer thread");

        std::thread::sleep(std::time::Duration::from_millis(150));
        canceller.cancel_with(
            crate::types::CancelKind::User,
            Some("external cancel while ws write is parked"),
        );

        let (result, elapsed) = done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("cancel must wake the parked write; the write never returned");
        writer.join().expect("writer thread");
        assert!(
            matches!(result, Err(WsError::Io(ref e)) if e.kind() == io::ErrorKind::Interrupted),
            "expected an Interrupted cancel from a parked write, got {result:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "cancel must wake the parked write promptly, took {elapsed:?}"
        );
    }

    /// close() whose Close frame parks on a peer that stopped reading ends
    /// when its explicit Cx is cancelled (br-asupersync-fmw87f). The handshake
    /// is CloseSent by then, and the write path ignored cancellation in that
    /// state, so close() hung forever. NeverWritableIo never self-wakes: only
    /// the registered cancel waker can re-poll the task.
    #[test]
    fn close_on_a_stalled_peer_ends_when_cancelled() {
        struct NeverWritableIo;
        impl AsyncRead for NeverWritableIo {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }
        impl AsyncWrite for NeverWritableIo {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Pending
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let cx = Cx::for_testing();
        let canceller = cx.clone();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let closer = std::thread::Builder::new()
            .name("ws-stalled-close".into())
            .spawn(move || {
                let result = future::block_on(async {
                    let accept = AcceptResponse {
                        accept_key: String::new(),
                        protocol: None,
                        extensions: Vec::new(),
                    };
                    let mut ws = ServerWebSocket::from_upgraded(
                        NeverWritableIo,
                        WebSocketConfig::default(),
                        accept,
                        &[],
                    );
                    ws.close(&cx, CloseReason::normal()).await
                });
                let _ = done_tx.send(result);
            })
            .expect("spawn closer thread");

        std::thread::sleep(std::time::Duration::from_millis(150));
        canceller.cancel_with(
            crate::types::CancelKind::User,
            Some("external cancel while the close frame is parked"),
        );

        let result = done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("cancel must end a close parked on a stalled peer; close() never returned");
        closer.join().expect("closer thread");
        assert!(
            matches!(result, Err(WsError::Io(ref e)) if e.kind() == io::ErrorKind::Interrupted),
            "expected an Interrupted cancel, got {result:?}"
        );
    }

    /// RFC 6455 §7.1.7: once message assembly fails the connection, `recv`
    /// must not deliver the data frame buffered behind the violation.
    #[test]
    fn recv_processes_no_data_after_an_assembly_failure() {
        future::block_on(async {
            let accept = AcceptResponse {
                accept_key: String::new(),
                protocol: None,
                extensions: Vec::new(),
            };
            let mut wire = encode_client_frame(Frame::text(crate::bytes::Bytes::from_static(&[
                0xFF, 0xFE,
            ])));
            wire.extend(encode_client_frame(Frame::text(
                crate::bytes::Bytes::from_static(b"after-failure"),
            )));
            let mut ws = ServerWebSocket::from_upgraded(
                TestIo::with_read_data(wire),
                WebSocketConfig::default(),
                accept,
                &[],
            );
            let cx = Cx::for_testing();

            let first = ws.recv(&cx).await;
            assert!(
                first.is_err(),
                "invalid UTF-8 text must fail the connection, got {first:?}"
            );
            let second = ws.recv(&cx).await;
            assert!(
                !matches!(second, Ok(Some(Message::Text(_) | Message::Binary(_)))),
                "data after the failure must not be delivered, got {second:?}"
            );
        });
    }
