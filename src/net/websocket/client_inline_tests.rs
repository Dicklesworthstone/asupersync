    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::codec::Encoder;
    use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
    use crate::types::{Budget, RegionId, TaskId};
    use crate::util::EntropySource;
    use futures_lite::future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::Poll;

    struct TestIo {
        read_data: Vec<u8>,
        read_pos: usize,
        written: Vec<u8>,
        fail_writes: bool,
        pending_first_read: bool,
        pending_first_write: bool,
        partial_first_write_len: Option<usize>,
        pending_after_partial_write: bool,
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
                pending_first_write: false,
                partial_first_write_len: None,
                pending_after_partial_write: false,
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
            self.pending_first_write = true;
            self
        }

        fn with_partial_first_write(mut self, len: usize) -> Self {
            self.partial_first_write_len = Some(len);
            self.pending_after_partial_write = true;
            self
        }
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

    fn encode_client_frame_with_entropy(frame: &Frame, entropy: &dyn EntropySource) -> Vec<u8> {
        let codec = FrameCodec::client();
        let mut out = BytesMut::new();
        codec
            .encode_with_entropy(frame, &mut out, entropy)
            .expect("frame encoding should succeed");
        out.to_vec()
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
            if self.pending_first_write {
                self.pending_first_write = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if let Some(len) = self.partial_first_write_len.take() {
                let to_write = len.min(buf.len());
                self.written.extend_from_slice(&buf[..to_write]);
                return Poll::Ready(Ok(to_write));
            }
            if self.pending_after_partial_write {
                self.pending_after_partial_write = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn read_http_response_accepts_lf_only_headers_and_preserves_trailing_bytes() {
        future::block_on(async {
            let mut io = TestIo::with_read_data(
                b"HTTP/1.1 101 Switching Protocols\n\
                  Upgrade: websocket\n\
                  Connection: Upgrade\n\
                  Sec-WebSocket-Accept: xyz\n\
                  \n\
                  \x81\x00"
                    .to_vec(),
            );

            let (headers, trailing) = read_http_response(&mut io)
                .await
                .expect("LF-only response should still parse");

            assert_eq!(
                headers,
                b"HTTP/1.1 101 Switching Protocols\n\
                  Upgrade: websocket\n\
                  Connection: Upgrade\n\
                  Sec-WebSocket-Accept: xyz\n\
                  \n"
            );
            assert_eq!(trailing, vec![0x81, 0x00]);

            let parsed = HttpResponse::parse(&headers).expect("parsed response");
            assert_eq!(parsed.status, 101);
            assert_eq!(parsed.header("upgrade"), Some("websocket"));
        });
    }

    #[test]
    fn test_message_from_frame() {
        let frame = Frame::text("Hello");
        let msg = Message::try_from(frame).unwrap();
        assert!(matches!(msg, Message::Text(s) if s == "Hello"));

        let frame = Frame::binary(vec![1, 2, 3]);
        let msg = Message::try_from(frame).unwrap();
        assert!(matches!(msg, Message::Binary(b) if b.as_ref() == [1, 2, 3]));

        let frame = Frame::ping("ping");
        let msg = Message::try_from(frame).unwrap();
        assert!(matches!(msg, Message::Ping(_)));

        let frame = Frame::pong("pong");
        let msg = Message::try_from(frame).unwrap();
        assert!(matches!(msg, Message::Pong(_)));

        let frame = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Continuation,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(b"tail"),
        };
        let err = Message::try_from(frame).unwrap_err();
        assert!(matches!(err, WsError::ProtocolViolation(_)));
    }

    #[test]
    fn test_frame_from_message() {
        let msg = Message::text("Hello");
        let frame = Frame::from(msg);
        assert_eq!(frame.opcode, Opcode::Text);
        assert_eq!(frame.payload.as_ref(), b"Hello");

        let msg = Message::binary(vec![1, 2, 3]);
        let frame = Frame::from(msg);
        assert_eq!(frame.opcode, Opcode::Binary);
        assert_eq!(frame.payload.as_ref(), &[1, 2, 3]);
    }

    #[test]
    fn test_config_builder() {
        let config = WebSocketConfig::new()
            .max_frame_size(1024)
            .max_message_size(4096)
            .max_pending_write_bytes(2048)
            .slow_consumer_policy(SlowConsumerPolicy::CloseWithTryAgainLater)
            .ping_interval(Some(Duration::from_secs(60)))
            .protocol("chat")
            .nodelay(false);

        assert_eq!(config.max_frame_size, 1024);
        assert_eq!(config.max_message_size, 4096);
        assert_eq!(config.max_pending_write_bytes, 2048);
        assert_eq!(
            config.slow_consumer_policy,
            SlowConsumerPolicy::CloseWithTryAgainLater
        );
        assert_eq!(config.ping_interval, Some(Duration::from_secs(60)));
        assert_eq!(config.protocols, vec!["chat".to_string()]);
        assert!(!config.nodelay);
    }

    #[test]
    fn send_rejects_frame_larger_than_pending_write_budget_before_writing() {
        future::block_on(async {
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0xAB, 0xCD, 0xEF, 0x01]));
            let config = WebSocketConfig::default().max_pending_write_bytes(4);
            let mut ws =
                WebSocket::from_upgraded_with_entropy(TestIo::new(), config, Arc::clone(&entropy));
            let cx = test_cx_with_entropy(entropy);

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
                        action: "wait",
                    } if attempted > 4
                ),
                "expected bounded-buffer error, got {err:?}"
            );
            assert!(
                ws.io.written.is_empty(),
                "budget rejection must not commit a partial frame"
            );
            assert!(
                ws.is_open(),
                "wait policy reports the error without closing the connection"
            );
        });
    }

    #[test]
    fn close_policy_records_1013_when_outbound_budget_is_exceeded() {
        future::block_on(async {
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0xAB, 0xCD, 0xEF, 0x01]));
            let config = WebSocketConfig::default()
                .max_pending_write_bytes(4)
                .slow_consumer_policy(SlowConsumerPolicy::CloseWithTryAgainLater);
            let mut ws =
                WebSocket::from_upgraded_with_entropy(TestIo::new(), config, Arc::clone(&entropy));
            let cx = test_cx_with_entropy(entropy);

            let err = ws
                .send(&cx, Message::text("hello"))
                .await
                .expect_err("close policy must reject oversize retained frames");

            assert!(matches!(
                err,
                WsError::OutboundBufferFull {
                    action: "close-with-1013",
                    ..
                }
            ));
            assert!(
                ws.is_closed(),
                "close policy must force the connection closed after rejecting the frame"
            );
            assert_eq!(
                ws.close_handshake
                    .our_reason()
                    .and_then(|reason| reason.code),
                Some(CloseCode::TryAgainLater)
            );
            assert!(
                ws.io.written.is_empty(),
                "close-policy rejection still must not write a partial data frame"
            );
        });
    }

    #[test]
    fn test_message_is_control() {
        assert!(!Message::text("test").is_control());
        assert!(!Message::binary(vec![]).is_control());
        assert!(Message::ping(vec![]).is_control());
        assert!(Message::pong(vec![]).is_control());
        assert!(Message::Close(None).is_control());
    }

    #[test]
    fn message_assembler_rejects_invalid_utf8() {
        let mut assembler = MessageAssembler::new(1024);
        let frame = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Text,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(&[0xFF]),
        };

        let result = assembler.push_frame(frame);
        assert!(matches!(result, Err(WsError::InvalidUtf8)));
    }

    #[test]
    fn message_assembler_reassembles_fragmented_text() {
        let mut assembler = MessageAssembler::new(1024);
        let frame1 = Frame {
            fin: false,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Text,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(b"hel"),
        };
        let frame2 = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Continuation,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(b"lo"),
        };

        let result1 = assembler.push_frame(frame1).unwrap();
        assert!(result1.is_none());
        let result2 = assembler.push_frame(frame2).unwrap();
        assert!(matches!(result2, Some(Message::Text(s)) if s == "hello"));
    }

    #[test]
    fn message_assembler_rejects_unexpected_continuation() {
        let mut assembler = MessageAssembler::new(1024);
        let frame = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Continuation,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(b"oops"),
        };

        let result = assembler.push_frame(frame);
        assert!(matches!(result, Err(WsError::ProtocolViolation(_))));
    }

    #[test]
    fn message_assembler_enforces_max_message_size() {
        let mut assembler = MessageAssembler::new(4);
        let frame = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Binary,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(b"012345"),
        };

        let result = assembler.push_frame(frame);
        assert!(matches!(
            result,
            Err(WsError::PayloadTooLarge { max: 4, .. })
        ));
    }

    #[test]
    fn message_assembler_rejects_double_data_frame() {
        // Starting a new data frame while a fragmented message is in progress
        // is a protocol violation (must send continuation).
        let mut assembler = MessageAssembler::new(1024);

        // Start a fragmented message (fin=false).
        let frame1 = Frame {
            fin: false,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Text,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(b"part1"),
        };
        assert!(assembler.push_frame(frame1).unwrap().is_none());

        // Send another data frame (not continuation) — protocol violation.
        let frame2 = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Binary,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(b"wrong"),
        };
        let result = assembler.push_frame(frame2);
        assert!(matches!(result, Err(WsError::ProtocolViolation(_))));
    }

    #[test]
    fn message_assembler_continuation_exceeds_max_size() {
        // Individual fragments are small, but total exceeds limit.
        let mut assembler = MessageAssembler::new(8);

        let frame1 = Frame {
            fin: false,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Binary,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(b"12345"), // 5 bytes
        };
        assert!(assembler.push_frame(frame1).unwrap().is_none());

        let frame2 = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Continuation,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(b"6789A"), // 5 more = 10 > 8
        };
        let result = assembler.push_frame(frame2);
        assert!(matches!(
            result,
            Err(WsError::PayloadTooLarge { max: 8, .. })
        ));
    }

    #[test]
    fn config_defaults() {
        let config = WebSocketConfig::default();
        assert_eq!(config.max_frame_size, 16 * 1024 * 1024);
        assert_eq!(config.max_message_size, 64 * 1024 * 1024);
        assert_eq!(config.ping_interval, Some(Duration::from_secs(30)));
        assert!(config.protocols.is_empty());
        assert_eq!(config.connect_timeout, Some(Duration::from_secs(30)));
        assert!(config.nodelay);
    }

    #[test]
    fn config_connect_timeout_builder() {
        let config = WebSocketConfig::new().connect_timeout(None);
        assert_eq!(config.connect_timeout, None);

        let config = WebSocketConfig::new().connect_timeout(Some(Duration::from_secs(5)));
        assert_eq!(config.connect_timeout, Some(Duration::from_secs(5)));
    }

    #[test]
    fn ws_connect_error_display() {
        let err = WsConnectError::TlsRequired;
        assert!(err.to_string().contains("TLS"));

        let err = WsConnectError::Cancelled;
        assert!(err.to_string().contains("cancelled"));

        let err = WsConnectError::Io(io::Error::new(io::ErrorKind::TimedOut, "timeout"));
        assert!(err.to_string().contains("I/O error"));
    }

    #[test]
    fn interrupted_tcp_connect_maps_to_cancelled_when_cx_is_cancelled() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let err = super::map_tcp_connect_error(
            &cx,
            io::Error::new(io::ErrorKind::Interrupted, "cancelled"),
        );

        assert!(matches!(err, WsConnectError::Cancelled));
    }

    #[test]
    fn interrupted_tcp_connect_stays_io_when_cx_is_not_cancelled() {
        let cx = Cx::for_testing();

        let err = super::map_tcp_connect_error(
            &cx,
            io::Error::new(io::ErrorKind::Interrupted, "cancelled"),
        );

        assert!(
            matches!(err, WsConnectError::Io(ref io_err) if io_err.kind() == io::ErrorKind::Interrupted)
        );
    }

    #[test]
    fn interrupted_tcp_connect_stays_io_when_cx_is_cancelled_but_masked() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let err = cx.masked(|| {
            super::map_tcp_connect_error(
                &cx,
                io::Error::new(io::ErrorKind::Interrupted, "cancelled"),
            )
        });

        assert!(
            matches!(err, WsConnectError::Io(ref io_err) if io_err.kind() == io::ErrorKind::Interrupted)
        );
        assert!(
            cx.is_cancel_requested(),
            "masking should defer, not clear, the pending cancellation"
        );
        assert!(
            cx.checkpoint().is_err(),
            "cancellation must still be observed once the mask is released"
        );
    }

    #[test]
    fn message_constructors() {
        let msg = Message::text("hello");
        assert!(matches!(msg, Message::Text(s) if s == "hello"));

        let msg = Message::binary(vec![1, 2]);
        assert!(matches!(msg, Message::Binary(_)));

        let msg = Message::ping(vec![3]);
        assert!(matches!(msg, Message::Ping(_)));

        let msg = Message::pong(vec![4]);
        assert!(matches!(msg, Message::Pong(_)));

        let reason = CloseReason::normal();
        let msg = Message::close(reason);
        assert!(matches!(msg, Message::Close(Some(_))));
    }

    #[test]
    fn message_assembler_binary_single_frame() {
        let mut assembler = MessageAssembler::new(1024);
        let frame = Frame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: Opcode::Binary,
            masked: false,
            mask_key: None,
            payload: Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF]),
        };
        let msg = assembler.push_frame(frame).unwrap().unwrap();
        assert!(matches!(msg, Message::Binary(b) if b.as_ref() == [0xDE, 0xAD, 0xBE, 0xEF]));
    }

    // A Ping or Pong payload over 125 bytes made send and ping panic in
    // Frame::ping / Frame::pong. They now return ControlFrameTooLarge and
    // write nothing.
    #[test]
    fn oversized_control_payloads_are_errors_not_panics() {
        future::block_on(async {
            let mut ws = WebSocket::from_upgraded(TestIo::new(), WebSocketConfig::default());
            let cx = Cx::for_testing();
            let big = Bytes::from(vec![0_u8; 126]);
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
            ws.ping(&cx, Bytes::from(vec![0_u8; 125]))
                .await
                .expect("a 125-byte ping is allowed");
            // Client frames are masked: 2 header bytes and a 4-byte key.
            assert_eq!(ws.io.written.len(), 6 + 125);
        });
    }

    #[test]
    fn send_close_message_initiates_close_handshake() {
        future::block_on(async {
            let mut ws = WebSocket::from_upgraded(TestIo::new(), WebSocketConfig::default());
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

    #[test]
    fn close_uses_explicit_cx_and_closes_on_peer_eof() {
        future::block_on(async {
            let mut ws = WebSocket::from_upgraded(TestIo::new(), WebSocketConfig::default());
            let cx = Cx::for_testing();

            ws.close(&cx, CloseReason::normal())
                .await
                .expect("close should complete cleanly on EOF");

            assert!(ws.is_closed(), "close handshake should finish closed");
            assert!(
                !ws.io.written.is_empty(),
                "close should emit a close frame before waiting for peer shutdown"
            );
        });
    }

    #[test]
    fn recv_keeps_close_received_state_if_response_send_fails() {
        future::block_on(async {
            let io = TestIo::with_read_data(encode_server_frame(Frame::close(Some(1000), None)))
                .with_write_failure();
            let mut ws = WebSocket::from_upgraded(io, WebSocketConfig::default());
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
                ws.close_state(),
                CloseState::CloseReceived,
                "failed close response writes must leave the handshake waiting for a retry"
            );
        });
    }

    #[test]
    fn pre_cancelled_send_emits_close_frame_before_error() {
        future::block_on(async {
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0x32, 0x54, 0x76, 0x98]));
            let cx = test_cx_with_entropy(Arc::clone(&entropy));
            cx.set_cancel_requested(true);
            let mut ws = WebSocket::from_upgraded_with_entropy(
                TestIo::new(),
                WebSocketConfig::default(),
                Arc::clone(&entropy),
            );

            let err = ws
                .send(&cx, Message::text("cancelled"))
                .await
                .expect_err("pre-cancelled send should fail");

            assert!(
                matches!(err, WsError::Io(ref e) if e.kind() == io::ErrorKind::Interrupted),
                "expected interrupted send after pre-cancelled Cx, got {err:?}"
            );
            assert_eq!(
                ws.close_state(),
                CloseState::CloseSent,
                "pre-cancelled send should initiate a close handshake"
            );
            assert_eq!(
                ws.io.written,
                encode_client_frame_with_entropy(&Frame::close(Some(1001), None), entropy.as_ref()),
                "pre-cancelled client send should emit exactly one going-away close frame"
            );
        });
    }

    #[test]
    fn cancellation_closes_with_the_configured_code() {
        // br-asupersync-y6naky: CloseConfig::with_cancellation_code was
        // accepted but cancellation always sent GoingAway (1001).
        future::block_on(async {
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0x32, 0x54, 0x76, 0x98]));
            let cx = test_cx_with_entropy(Arc::clone(&entropy));
            cx.set_cancel_requested(true);
            let config = WebSocketConfig {
                close_config: CloseConfig::new().with_cancellation_code(CloseCode::ServiceRestart),
                ..WebSocketConfig::default()
            };
            let mut ws =
                WebSocket::from_upgraded_with_entropy(TestIo::new(), config, Arc::clone(&entropy));
            let _ = ws.send(&cx, Message::text("cancelled")).await;
            assert_eq!(
                ws.io.written,
                encode_client_frame_with_entropy(&Frame::close(Some(1012), None), entropy.as_ref()),
                "the cancellation close frame carries the configured code"
            );
        });
    }

    #[test]
    fn cancelled_send_does_not_flush_frame_later() {
        future::block_on(async {
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0x12, 0x34, 0x56, 0x78]));
            let cx = test_cx_with_entropy(Arc::clone(&entropy));
            let mut ws = WebSocket::from_upgraded(
                TestIo::new().with_pending_first_write(),
                WebSocketConfig::default(),
            );

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

            let expected =
                encode_client_frame_with_entropy(&Frame::from(delivered), entropy.as_ref());
            assert_eq!(
                ws.io.written, expected,
                "later flushes must not emit bytes from a cancelled send"
            );
        });
    }

    #[test]
    fn cancelled_send_after_partial_write_preserves_tail_for_later_flush() {
        future::block_on(async {
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0x12, 0x34, 0x56, 0x78]));
            let cx = test_cx_with_entropy(Arc::clone(&entropy));
            let mut ws = WebSocket::from_upgraded(
                TestIo::new().with_partial_first_write(1),
                WebSocketConfig::default(),
            );

            let cancelled = Message::text("cancelled");
            let delivered = Message::text("delivered");
            let expected_cancelled =
                encode_client_frame_with_entropy(&Frame::from(cancelled.clone()), entropy.as_ref());
            let expected_delivered =
                encode_client_frame_with_entropy(&Frame::from(delivered.clone()), entropy.as_ref());
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
                .expect("second send should flush the durable tail before the next frame");

            let mut expected = expected_cancelled;
            expected.extend_from_slice(&expected_delivered);
            assert_eq!(
                ws.io.written, expected,
                "later flushes must preserve the partially written frame before the next send"
            );
        });
    }

    #[test]
    fn close_after_cancelled_recv_flushes_pending_echo_without_second_close() {
        future::block_on(async {
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0x21, 0x43, 0x65, 0x87]));
            let cx = test_cx_with_entropy(Arc::clone(&entropy));
            let peer_close = encode_server_frame(Frame::close(Some(1000), None));
            let mut ws = WebSocket::from_upgraded(
                TestIo::with_read_data(peer_close).with_pending_first_write(),
                WebSocketConfig::default(),
            );
            let mut cancelled_recv = Box::pin(ws.recv(&cx));
            let waker = std::task::Waker::noop().clone();
            let mut poll_cx = std::task::Context::from_waker(&waker);

            assert!(
                matches!(cancelled_recv.as_mut().poll(&mut poll_cx), Poll::Pending),
                "recv should park while flushing the echoed close response"
            );
            drop(cancelled_recv);

            assert_eq!(
                ws.close_state(),
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

            let expected =
                encode_client_frame_with_entropy(&Frame::close(Some(1000), None), entropy.as_ref());
            assert_eq!(
                ws.io.written, expected,
                "retrying close after a cancelled recv must not append a second close frame"
            );
        });
    }

    #[test]
    fn recv_mid_read_cancel_uses_explicit_cx_without_ambient_current() {
        future::block_on(async {
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0x21, 0x43, 0x65, 0x87]));
            let cx = test_cx_with_entropy(entropy);
            let read_data = encode_server_frame(Frame::binary(vec![1, 2, 3]));
            let mut ws = WebSocket::from_upgraded(
                TestIo::with_read_data(read_data).with_pending_first_read(),
                WebSocketConfig::default(),
            );
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
                "cancelled client recv must not consume transport bytes after pending read"
            );
            assert!(
                ws.read_buf.is_empty(),
                "cancelled client recv must not seed the websocket read buffer"
            );
        });
    }

    #[test]
    fn close_after_partially_flushed_echo_preserves_tail_without_second_close() {
        future::block_on(async {
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0x21, 0x43, 0x65, 0x87]));
            let cx = test_cx_with_entropy(Arc::clone(&entropy));
            let peer_close = encode_server_frame(Frame::close(Some(1000), None));
            let mut ws = WebSocket::from_upgraded(
                TestIo::with_read_data(peer_close).with_partial_first_write(1),
                WebSocketConfig::default(),
            );
            let expected =
                encode_client_frame_with_entropy(&Frame::close(Some(1000), None), entropy.as_ref());
            let mut cancelled_recv = Box::pin(ws.recv(&cx));
            let waker = std::task::Waker::noop().clone();
            let mut poll_cx = std::task::Context::from_waker(&waker);

            assert!(
                matches!(cancelled_recv.as_mut().poll(&mut poll_cx), Poll::Pending),
                "recv should park after partially flushing the echoed close response"
            );
            drop(cancelled_recv);

            assert_eq!(
                ws.close_state(),
                CloseState::CloseReceived,
                "partial close-response flush must leave the handshake awaiting completion"
            );
            assert!(
                !ws.write_buf.is_empty(),
                "the echoed close tail must remain buffered after partial I/O"
            );
            assert_eq!(
                ws.io.written,
                expected[..1].to_vec(),
                "only the committed close-frame prefix should hit the transport before retry"
            );

            ws.close(&cx, CloseReason::going_away())
                .await
                .expect("close should flush the durable close tail");

            assert!(
                ws.is_closed(),
                "completing the echoed close tail must close the handshake"
            );
            assert_eq!(
                ws.io.written, expected,
                "retrying close must finish the original close frame without appending a second one"
            );
        });
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
                    let mut ws =
                        WebSocket::from_upgraded(NeverWritableIo, WebSocketConfig::default());
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

    #[test]
    fn close_retry_flushes_partially_sent_close_without_second_close() {
        future::block_on(async {
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0x23, 0x45, 0x67, 0x89]));
            let cx = test_cx_with_entropy(Arc::clone(&entropy));
            let peer_close = encode_server_frame(Frame::close(Some(1000), None));
            let mut ws = WebSocket::from_upgraded_with_entropy(
                TestIo::with_read_data(peer_close).with_partial_first_write(1),
                WebSocketConfig::default(),
                Arc::clone(&entropy),
            );
            let expected =
                encode_client_frame_with_entropy(&Frame::close(Some(1001), None), entropy.as_ref());
            let mut cancelled_close = Box::pin(ws.close(&cx, CloseReason::going_away()));
            let waker = std::task::Waker::noop().clone();
            let mut poll_cx = std::task::Context::from_waker(&waker);

            assert!(
                matches!(cancelled_close.as_mut().poll(&mut poll_cx), Poll::Pending),
                "close should park after partially writing the initiated close frame"
            );
            drop(cancelled_close);

            assert_eq!(
                ws.close_state(),
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
                "retrying close must finish the original close frame without appending another"
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
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0x23, 0x45, 0x67, 0x89]));
            let cx = test_cx_with_entropy(Arc::clone(&entropy));
            let peer_close = encode_server_frame(Frame::close(Some(1000), None));
            let mut ws = WebSocket::from_upgraded_with_entropy(
                TestIo::with_read_data(peer_close).with_pending_first_write(),
                WebSocketConfig::default(),
                Arc::clone(&entropy),
            );
            let expected =
                encode_client_frame_with_entropy(&Frame::close(Some(1001), None), entropy.as_ref());
            let mut dropped_close = Box::pin(ws.close(&cx, CloseReason::going_away()));
            let waker = std::task::Waker::noop().clone();
            let mut poll_cx = std::task::Context::from_waker(&waker);
            assert!(
                matches!(dropped_close.as_mut().poll(&mut poll_cx), Poll::Pending),
                "close parks before its first write"
            );
            drop(dropped_close);
            assert_eq!(ws.close_state(), CloseState::CloseSent);
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
                let mut config = WebSocketConfig::default();
                config.close_config.close_timeout = std::time::Duration::from_millis(100);
                let outcome = future::block_on(async {
                    let mut ws = WebSocket::from_upgraded(NeverWritableIo, config);
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

    struct CloseShutdownIo {
        inner: TestIo,
        park_reads: bool,
        shutdown_polls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl AsyncRead for CloseShutdownIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.park_reads {
                return Poll::Pending;
            }
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for CloseShutdownIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            self.shutdown_polls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Poll::Pending
        }
    }

    struct CloseTimeoutWake(std::sync::atomic::AtomicUsize);

    impl std::task::Wake for CloseTimeoutWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn client_close_clock(
        start: u64,
    ) -> (Arc<crate::time::VirtualClock>, crate::time::TimerDriverHandle, Cx) {
        let clock = Arc::new(crate::time::VirtualClock::starting_at(
            crate::types::Time::from_secs(start),
        ));
        let timer = crate::time::TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(91, 1),
            TaskId::new_for_test(91, 1),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        (clock, timer, cx)
    }

    #[test]
    fn close_deadline_still_bounds_transport_shutdown_after_the_peer_replies() {
        use std::future::Future;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Context, Waker};

        let (clock, timer, cx) = client_close_clock(100);
        let (_, _, foreign_cx) = client_close_clock(1_000_000);
        let _ambient = Cx::set_current(Some(foreign_cx));
        let shutdown_polls = Arc::new(AtomicUsize::new(0));
        let io = CloseShutdownIo {
            inner: TestIo::with_read_data(encode_server_frame(Frame::close(Some(1000), None))),
            park_reads: false,
            shutdown_polls: Arc::clone(&shutdown_polls),
        };
        let mut config = WebSocketConfig::default();
        config.ping_interval = None;
        config.close_config.close_timeout = Duration::from_secs(10);
        let mut ws = WebSocket::from_upgraded_with_entropy(
            io,
            config,
            Arc::new(FixedEntropy([1, 2, 3, 4])),
        );
        let counter = Arc::new(CloseTimeoutWake(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&counter));
        let mut task = Context::from_waker(&waker);
        {
            let mut close = std::pin::pin!(ws.close(&cx, CloseReason::normal()));
            assert!(close.as_mut().poll(&mut task).is_pending());
            assert!(shutdown_polls.load(Ordering::SeqCst) > 0);
            clock.set(crate::types::Time::from_secs(109));
            assert_eq!(timer.process_timers(), 0);
            assert!(close.as_mut().poll(&mut task).is_pending());
            let before = counter.0.load(Ordering::SeqCst);
            clock.set(crate::types::Time::from_secs(110));
            assert!(timer.process_timers() > 0);
            assert!(counter.0.load(Ordering::SeqCst) > before);
            assert!(matches!(close.as_mut().poll(&mut task), Poll::Ready(Ok(()))));
        }
        assert!(ws.is_closed());
    }

    #[test]
    fn reunited_client_close_and_recv_keep_the_original_deadline_and_clock() {
        use std::future::Future;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Context, Waker};

        for receive in [false, true] {
            let (clock, timer, first_cx) = client_close_clock(100);
            let (_, _, later_cx) = client_close_clock(1_000_000);
            let io = CloseShutdownIo {
                inner: TestIo::new(),
                park_reads: true,
                shutdown_polls: Arc::new(AtomicUsize::new(0)),
            };
            let mut config = WebSocketConfig::default();
            config.ping_interval = None;
            config.close_config.close_timeout = Duration::from_secs(10);
            let ws = WebSocket::from_upgraded_with_entropy(
                io,
                config,
                Arc::new(FixedEntropy([1, 2, 3, 4])),
            );
            let (read, mut write) = ws.split();
            future::block_on(write.send(&first_cx, Message::Close(Some(CloseReason::normal()))))
                .expect("the original Close is flushed");
            clock.set(crate::types::Time::from_secs(103));
            let mut ws = read.reunite(write).expect("matching halves reunite");
            let _ambient = Cx::set_current(Some(later_cx.clone()));
            let counter = Arc::new(CloseTimeoutWake(AtomicUsize::new(0)));
            let waker = Waker::from(Arc::clone(&counter));
            let mut task = Context::from_waker(&waker);
            {
                let mut operation = std::pin::pin!(async {
                    if receive {
                        ws.recv(&later_cx).await.map(|message| {
                            assert!(message.is_none(), "the bounded receive ends on close timeout");
                        })
                    } else {
                        ws.close(&later_cx, CloseReason::normal()).await
                    }
                });
                assert!(operation.as_mut().poll(&mut task).is_pending());
                clock.set(crate::types::Time::from_secs(109));
                assert_eq!(timer.process_timers(), 0);
                assert!(operation.as_mut().poll(&mut task).is_pending());
                let before = counter.0.load(Ordering::SeqCst);
                clock.set(crate::types::Time::from_secs(110));
                assert!(timer.process_timers() > 0, "reunite must keep the original timer");
                assert!(counter.0.load(Ordering::SeqCst) > before);
                assert!(matches!(operation.as_mut().poll(&mut task), Poll::Ready(Ok(()))));
            }
            assert!(ws.is_closed(), "receive={receive}");
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct FixedEntropy([u8; 4]);

    impl EntropySource for FixedEntropy {
        fn fill_bytes(&self, dest: &mut [u8]) {
            for (idx, byte) in dest.iter_mut().enumerate() {
                *byte = self.0[idx % self.0.len()];
            }
        }

        fn next_u64(&self) -> u64 {
            u64::from_le_bytes([
                self.0[0], self.0[1], self.0[2], self.0[3], self.0[0], self.0[1], self.0[2],
                self.0[3],
            ])
        }

        fn fork(&self, _task_id: TaskId) -> Arc<dyn EntropySource> {
            Arc::new(*self)
        }

        fn source_id(&self) -> &'static str {
            "fixed"
        }
    }

    fn test_cx_with_entropy(entropy: Arc<dyn EntropySource>) -> Cx {
        Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            Some(entropy),
        )
    }

    #[test]
    fn send_ignores_cancel_while_masked() {
        let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0xAA, 0xBB, 0xCC, 0xDD]));
        let cx = test_cx_with_entropy(Arc::clone(&entropy));
        cx.set_cancel_requested(true);
        let _guard = Cx::set_current(Some(cx.clone()));
        let mut ws = WebSocket::from_upgraded(TestIo::new(), WebSocketConfig::default());
        let masked = Message::text("masked");

        cx.masked(|| future::block_on(ws.send(&cx, masked.clone())))
            .expect("masked send should defer cancellation");

        assert_eq!(
            ws.io.written,
            encode_client_frame_with_entropy(&Frame::from(masked), entropy.as_ref()),
            "masked send should still flush the original frame"
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
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0x12, 0x34, 0x56, 0x78]));
            let cx = test_cx_with_entropy(entropy);
            let mut ws = WebSocket::from_upgraded(
                TestIo::new().with_pending_first_write(),
                WebSocketConfig::default(),
            );
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
                other => panic!("expected cancelled send error, got {other:?}"), // ubs:ignore - test helper
            };

            assert!(
                matches!(err, WsError::Io(ref e) if e.kind() == io::ErrorKind::Interrupted),
                "expected interrupted send after explicit Cx cancellation, got {err:?}"
            );
            drop(send);
            assert!(
                ws.io.written.is_empty(),
                "cancelled client send must not commit bytes after a pending write"
            );
            assert!(
                ws.write_buf.is_empty(),
                "cancelled client send must not leave buffered bytes when no write committed"
            );
        });
    }

    #[test]
    fn send_uses_cx_entropy_for_client_masking() {
        future::block_on(async {
            let mut ws = WebSocket::from_upgraded(TestIo::new(), WebSocketConfig::default());
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0xAA, 0xBB, 0xCC, 0xDD]));
            let cx = test_cx_with_entropy(entropy);

            ws.send(&cx, Message::text("hi"))
                .await
                .expect("send should succeed");

            assert_eq!(&ws.io.written[2..6], &[0xAA, 0xBB, 0xCC, 0xDD]);
        });
    }

    #[test]
    fn read_some_io_external_cancel_wakes_a_parked_read() {
        // br-asupersync-r8n4qx: read_some_io parked on a silent stream (a peer
        // that sends no frame) must be woken by an external cancel, not hang
        // until a frame finally arrives. NeverReadyIo returns Pending forever;
        // the cancel is set from another thread WHILE the read is parked, so the
        // CancelWakerGuard's registered Waker is the only thing that can re-poll
        // the block_on task. Without it, block_on never returns and recv_timeout
        // turns the hang into a failure. server.rs has the identical read_some_io.
        struct NeverReadyIo;
        impl AsyncRead for NeverReadyIo {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }

        let cx = Cx::for_testing();
        let canceller = cx.clone();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let reader = std::thread::Builder::new()
            .name("ws-parked-reader".into())
            .spawn(move || {
                let started = std::time::Instant::now();
                let result = future::block_on(async {
                    let mut io = NeverReadyIo;
                    let mut buf = [0u8; 16];
                    read_some_io(&cx, &mut io, &mut buf, true).await
                });
                let _ = done_tx.send((result, started.elapsed()));
            })
            .expect("spawn reader thread");

        std::thread::sleep(std::time::Duration::from_millis(150));
        canceller.cancel_with(
            crate::types::CancelKind::User,
            Some("external cancel while ws read is parked"),
        );

        let (result, elapsed) = done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("cancel must wake the parked read; the read never returned");
        reader.join().expect("reader thread");
        assert!(
            matches!(result, Err(WsError::Io(ref e)) if e.kind() == io::ErrorKind::Interrupted),
            "expected an Interrupted cancel from a parked read, got {result:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "cancel must wake the parked read promptly, took {elapsed:?}"
        );
    }

    /// A peer that takes the whole upgrade request and never answers. Each
    /// write is reported so a test can prove the exchange reached its parked
    /// response read before it times out or is cancelled.
    struct SilentUpgradePeer {
        written: std::sync::mpsc::Sender<usize>,
    }

    impl AsyncRead for SilentUpgradePeer {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for SilentUpgradePeer {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let _ = self.written.send(buf.len());
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    type ExchangeOutcome = (
        Result<(Vec<u8>, Vec<u8>), WsConnectError>,
        std::time::Duration,
    );

    /// Runs the upgrade exchange against a silent peer on its own thread.
    /// Returns once the whole request is written, with the exchange parked on
    /// the response read.
    fn park_upgrade_exchange(
        cx: Cx,
        limit: Option<std::time::Duration>,
    ) -> std::sync::mpsc::Receiver<ExchangeOutcome> {
        let request = b"GET /chat HTTP/1.1\r\nHost: peer\r\n\r\n".to_vec();
        let (written_tx, written_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let expected = request.len();
        std::thread::Builder::new()
            .name("ws-upgrade-exchange".into())
            .spawn(move || {
                let started = std::time::Instant::now();
                let mut peer = SilentUpgradePeer {
                    written: written_tx,
                };
                let result =
                    future::block_on(bounded_upgrade_exchange(&cx, &mut peer, &request, limit));
                let _ = done_tx.send((result, started.elapsed()));
            })
            .expect("spawn exchange thread");
        let mut written = 0;
        while written < expected {
            written += written_rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("the upgrade request reaches the peer");
        }
        done_rx
    }

    #[test]
    fn upgrade_exchange_times_out_when_the_peer_never_answers() {
        let limit = std::time::Duration::from_millis(200);
        let done = park_upgrade_exchange(Cx::for_testing(), Some(limit));
        let (result, elapsed) = done
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("a silent peer must not hold the upgrade past connect_timeout");
        assert!(
            matches!(&result, Err(WsConnectError::Io(error)) if error.kind() == io::ErrorKind::TimedOut),
            "expected TimedOut, got {result:?}"
        );
        assert!(
            elapsed >= limit && elapsed < std::time::Duration::from_secs(5),
            "timed out after {elapsed:?} for a {limit:?} bound"
        );
    }

    #[test]
    fn cancelling_a_parked_upgrade_exchange_returns_cancelled() {
        let cx = Cx::for_testing();
        let canceller = cx.clone();
        // No bound: only the cancellation can end this exchange.
        let done = park_upgrade_exchange(cx, None);
        canceller.cancel_with(
            crate::types::CancelKind::User,
            Some("cancel while the upgrade response is awaited"),
        );
        let (result, elapsed) = done
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("cancel must wake the parked upgrade read");
        assert!(
            matches!(result, Err(WsConnectError::Cancelled)),
            "expected Cancelled, got {result:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "took {elapsed:?}"
        );
    }

    #[test]
    fn connect_times_out_when_a_tcp_server_never_answers_the_upgrade() {
        // The server accepts, reads the complete upgrade request, then stays
        // silent with the socket open until the test releases it.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (request_seen_tx, request_seen_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            use std::io::Read;
            let (mut socket, _) = listener.accept().expect("accept");
            let mut request = Vec::new();
            let mut chunk = [0u8; 512];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let n = socket.read(&mut chunk).expect("read request");
                assert!(n > 0, "client closed before finishing the request");
                request.extend_from_slice(&chunk[..n]);
            }
            let _ = request_seen_tx.send(request);
            let _ = release_rx.recv_timeout(std::time::Duration::from_secs(20));
        });

        let limit = std::time::Duration::from_millis(300);
        let url = format!("ws://{addr}/chat");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let client = std::thread::spawn(move || {
            let runtime = crate::runtime::RuntimeBuilder::new()
                .build()
                .expect("runtime");
            let started = std::time::Instant::now();
            let handle = runtime.handle().spawn(async move {
                let cx = Cx::current().expect("runtime task context");
                let config = WebSocketConfig::new().connect_timeout(Some(limit));
                WebSocket::connect_with_config(&cx, &url, config)
                    .await
                    .map(|_| ())
            });
            let result = runtime.block_on(handle);
            let _ = done_tx.send((result, started.elapsed()));
        });

        let request = request_seen_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the upgrade request reaches the server");
        assert!(request.starts_with(b"GET /chat HTTP/1.1\r\n"));
        let (result, elapsed) = done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("connect must not hang on a server that never answers");
        let _ = release_tx.send(());
        server.join().expect("server thread");
        client.join().expect("client thread");
        assert!(
            matches!(&result, Err(WsConnectError::Io(error)) if error.kind() == io::ErrorKind::TimedOut),
            "expected TimedOut, got {result:?}"
        );
        assert!(
            elapsed >= limit && elapsed < std::time::Duration::from_secs(5),
            "connect timed out after {elapsed:?} for a {limit:?} bound"
        );
    }
