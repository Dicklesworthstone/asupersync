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
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, RegionId, TaskId, Time};
    use crate::util::EntropySource;
    use futures_lite::future;
    use std::future::Future;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};

    // In-memory I/O for testing
    struct TestIo {
        read_data: Vec<u8>,
        read_pos: usize,
        written: Vec<u8>,
        fail_writes: bool,
        pending_first_read: bool,
        pending_first_write: bool,
        partial_first_write_len: Option<usize>,
        pending_after_partial_write: bool,
        stall_reads: bool,
        stall_writes: bool,
        stall_flush_after_write: bool,
        write_polls: usize,
        flush_polls: usize,
    }

    impl TestIo {
        fn new(read_data: Vec<u8>) -> Self {
            Self {
                read_data,
                read_pos: 0,
                written: Vec::new(),
                fail_writes: false,
                pending_first_read: false,
                pending_first_write: false,
                partial_first_write_len: None,
                pending_after_partial_write: false,
                stall_reads: false,
                stall_writes: false,
                stall_flush_after_write: false,
                write_polls: 0,
                flush_polls: 0,
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

        fn with_stalled_writes(mut self) -> Self {
            self.stall_writes = true;
            self
        }

        fn with_stalled_reads(mut self) -> Self {
            self.stall_reads = true;
            self
        }

        fn with_stalled_flush(mut self) -> Self {
            self.stall_flush_after_write = true;
            self
        }
    }

    struct InterleavingIo {
        written: Vec<u8>,
        pending_next: bool,
    }

    impl InterleavingIo {
        fn new() -> Self {
            Self {
                written: Vec::new(),
                pending_next: false,
            }
        }
    }

    impl AsyncRead for TestIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.stall_reads {
                return Poll::Pending;
            }
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

    impl AsyncRead for InterleavingIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for TestIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.write_polls += 1;
            if self.stall_writes {
                return Poll::Pending;
            }
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
            mut self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            self.flush_polls += 1;
            if self.stall_flush_after_write && !self.written.is_empty() {
                return Poll::Pending;
            }
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for InterleavingIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            if self.pending_next {
                self.pending_next = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.pending_next = true;
            self.written.push(buf[0]);
            Poll::Ready(Ok(1))
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

    fn encode_server_frame(frame: Frame) -> Vec<u8> {
        let mut codec = FrameCodec::server();
        let mut out = BytesMut::new();
        codec
            .encode(frame, &mut out)
            .expect("frame encoding should succeed");
        out.to_vec()
    }

    fn encode_client_frame_with_entropy(frame: &Frame, entropy: &dyn EntropySource) -> Vec<u8> {
        let codec = FrameCodec::client();
        let mut out = BytesMut::new();
        codec
            .encode_with_entropy(frame, &mut out, entropy)
            .expect("frame encoding should succeed");
        out.to_vec()
    }

    // The read half echoes a peer Close while the write half's frame is parked
    // unsent. The writer appended its unsent tail after the queued echo, so
    // the wire carried X[..n], Close, X[n..] and the peer saw a corrupt frame
    // instead of a clean close.
    #[test]
    fn split_close_echo_never_lands_inside_a_frame_the_writer_is_sending() {
        future::block_on(async {
            let peer_close = encode_client_frame_with_entropy(
                &Frame::close(Some(1000), None),
                &FixedEntropy([0x11, 0x22, 0x33, 0x44]),
            );
            let ws = WebSocket::from_upgraded(
                TestIo::new(peer_close)
                    .with_pending_first_write()
                    .with_partial_first_write(100),
                WebSocketConfig::default(),
            );
            let (mut read, write) = ws.split();
            read.shared.lock().codec = FrameCodec::server();
            let cx = Cx::for_testing();
            let frame = Frame::binary(Bytes::from(vec![0xAB; 1000]));

            let waker = std::task::Waker::noop().clone();
            let mut poll_cx = Context::from_waker(&waker);
            let mut send = Box::pin(write.send_frame(&frame));
            assert!(
                send.as_mut().poll(&mut poll_cx).is_pending(),
                "the writer parks in its first write, holding the write permit"
            );
            let mut recv = Box::pin(read.recv(&cx));
            assert!(
                recv.as_mut().poll(&mut poll_cx).is_pending(),
                "the Close echo waits for the write permit"
            );

            let (sent, received) = future::zip(send, recv).await;
            sent.expect("the writer's frame is sent");
            assert!(
                matches!(received, Ok(Some(Message::Close(_)))),
                "the peer's Close is delivered: {received:?}"
            );

            let ws = read.reunite(write).expect("split halves must reunite");
            let mut expected = encode_server_frame(frame);
            expected.extend_from_slice(&encode_server_frame(Frame::close(Some(1000), None)));
            assert_eq!(
                ws.io.written, expected,
                "the whole frame, then the Close echo"
            );
        });
    }

    // br-asupersync-4en1sw W3: after a partial write, the frame's tail was
    // checked against the budget again, now counting the Close echo the read
    // half had queued meanwhile. Over budget, the send failed and the tail was
    // dropped although the frame's first bytes were already on the wire.
    #[test]
    fn a_partly_written_frame_keeps_its_tail_when_an_echo_fills_the_budget() {
        future::block_on(async {
            let peer_close = encode_client_frame_with_entropy(
                &Frame::close(Some(1000), None),
                &FixedEntropy([0x11, 0x22, 0x33, 0x44]),
            );
            let frame = Frame::binary(Bytes::from(vec![0xAB; 1000]));
            let frame_len = encode_server_frame(frame.clone()).len();
            let ws = WebSocket::from_upgraded(
                TestIo::new(peer_close)
                    .with_pending_first_write()
                    .with_partial_first_write(2),
                WebSocketConfig::default().max_pending_write_bytes(frame_len),
            );
            let (mut read, write) = ws.split();
            read.shared.lock().codec = FrameCodec::server();
            let cx = Cx::for_testing();

            let waker = std::task::Waker::noop().clone();
            let mut poll_cx = Context::from_waker(&waker);
            let mut send = Box::pin(write.send_frame(&frame));
            assert!(send.as_mut().poll(&mut poll_cx).is_pending());
            let mut recv = Box::pin(read.recv(&cx));
            assert!(recv.as_mut().poll(&mut poll_cx).is_pending());

            let (sent, received) = future::zip(send, recv).await;
            sent.expect("a frame whose first bytes went out is finished");
            assert!(
                matches!(received, Ok(Some(Message::Close(_)))),
                "{received:?}"
            );
            let ws = read.reunite(write).expect("split halves must reunite");
            let mut expected = encode_server_frame(frame);
            expected.extend_from_slice(&encode_server_frame(Frame::close(Some(1000), None)));
            assert_eq!(ws.io.written, expected, "the whole frame, then the echo");
        });
    }

    // br-asupersync-4en1sw W2: close() counted the retained tail of a partly
    // written frame against the budget, so a frame near the budget left the
    // write half unable to close (OutboundBufferFull under Wait). v0.4.3
    // flushed the tail and then sent the Close.
    #[test]
    fn close_after_a_dropped_partial_send_flushes_the_tail_then_closes() {
        future::block_on(async {
            let frame = Frame::binary(Bytes::from(vec![0xCD; 1000]));
            let frame_len =
                encode_client_frame_with_entropy(&frame, &FixedEntropy([0x46, 0xD0, 0x1B, 0x0A]))
                    .len();
            let ws = WebSocket::from_upgraded(
                TestIo::new(vec![]).with_partial_first_write(2),
                WebSocketConfig::default().max_pending_write_bytes(frame_len),
            );
            let (read, mut write) = ws.split();
            let waker = std::task::Waker::noop().clone();
            let mut poll_cx = Context::from_waker(&waker);
            {
                let mut send = Box::pin(write.send_frame(&frame));
                assert!(send.as_mut().poll(&mut poll_cx).is_pending());
            }
            assert_eq!(read.shared.lock().write_buf.len(), frame_len - 2);

            write
                .close(CloseReason::normal())
                .await
                .expect("the retained tail does not count against the Close");
            assert_eq!(write.close_state(), CloseState::CloseSent);
            let state = read.shared.lock();
            assert!(state.write_buf.is_empty());
            assert_eq!(state.io.written.len(), frame_len + 8);
        });
    }

    // br-asupersync-4en1sw W1: a recv dropped while flushing a retained Close
    // (our echo, or our own Close after a crossing peer Close) left it
    // retained, and a retried recv returned without writing it.
    #[test]
    fn a_retried_recv_flushes_the_close_its_dropped_predecessor_retained() {
        future::block_on(async {
            // Echo: the peer closed first.
            let peer_close = encode_server_frame(Frame::close(Some(1000), None));
            let ws = WebSocket::from_upgraded(
                TestIo::new(peer_close).with_pending_first_write(),
                WebSocketConfig::default(),
            );
            let (mut read, write) = ws.split();
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0x46, 0xD0, 0x1B, 0x0A]));
            let cx = test_cx_with_entropy(Arc::clone(&entropy));
            let waker = std::task::Waker::noop().clone();
            let mut poll_cx = Context::from_waker(&waker);
            {
                let mut first = Box::pin(read.recv(&cx));
                assert!(first.as_mut().poll(&mut poll_cx).is_pending());
            }
            assert_eq!(write.close_state(), CloseState::CloseReceived);
            assert!(read.recv(&cx).await.expect("retried recv").is_none());
            assert_eq!(write.close_state(), CloseState::Closed);
            let ws = read.reunite(write).expect("split halves must reunite");
            assert_eq!(
                ws.io.written,
                encode_client_frame_with_entropy(&Frame::close(Some(1000), None), entropy.as_ref()),
                "the retried recv wrote the echo once"
            );

            // Crossing: our close() was dropped before its first byte, then the
            // peer's Close arrived.
            let peer_close = encode_client_frame_with_entropy(
                &Frame::close(Some(1000), None),
                &FixedEntropy([0x11, 0x22, 0x33, 0x44]),
            );
            let ws = WebSocket::from_upgraded(
                TestIo::new(peer_close).with_pending_first_write(),
                WebSocketConfig::default(),
            );
            let (mut read, mut write) = ws.split();
            read.shared.lock().codec = FrameCodec::server();
            let cx = Cx::for_testing();
            let expected = encode_server_frame(CloseReason::going_away().to_frame());
            {
                let mut close = Box::pin(write.close(CloseReason::going_away()));
                assert!(close.as_mut().poll(&mut poll_cx).is_pending());
            }
            read.shared.lock().io.pending_first_write = true;
            {
                let mut recv = Box::pin(read.recv(&cx));
                assert!(recv.as_mut().poll(&mut poll_cx).is_pending());
            }
            assert!(read.recv(&cx).await.expect("retried recv").is_none());
            let state = read.shared.lock();
            assert_eq!(state.close_handshake.state(), CloseState::Closed);
            assert_eq!(
                state.io.written, expected,
                "the retried recv wrote our Close"
            );
        });
    }

    // A Ping or Pong payload over 125 bytes made the write half's send and
    // ping panic in Frame::ping / Frame::pong. They now return
    // ControlFrameTooLarge and write nothing.
    #[test]
    fn split_oversized_control_payloads_are_errors_not_panics() {
        future::block_on(async {
            let ws = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
            let (read, mut write) = ws.split();
            let cx = Cx::for_testing();
            let big = Bytes::from(vec![0_u8; 126]);
            let results = [
                write.send(&cx, Message::Ping(big.clone())).await,
                write.send(&cx, Message::Pong(big.clone())).await,
                write.ping(big.clone()).await,
            ];
            for result in results {
                assert!(
                    matches!(result, Err(WsError::ControlFrameTooLarge(126))),
                    "unexpected result {result:?}"
                );
            }
            write
                .ping(Bytes::from(vec![0_u8; 125]))
                .await
                .expect("a 125-byte ping is allowed");
            let ws = read.reunite(write).expect("split halves must reunite");
            // Client frames are masked: 2 header bytes and a 4-byte key.
            assert_eq!(ws.io.written.len(), 6 + 125);
        });
    }

    #[test]
    fn split_writes_do_not_interleave_frame_bytes() {
        future::block_on(async {
            let ws = WebSocket::from_upgraded(InterleavingIo::new(), WebSocketConfig::default());
            let (read, write) = ws.split();

            let read_frame = Frame::binary(Bytes::from_static(b"read-half"));
            let write_frame = Frame::binary(Bytes::from_static(b"write-half"));

            let expected_read = encode_server_frame(read_frame.clone());
            let expected_write = encode_server_frame(write_frame.clone());

            {
                let mut shared = read.shared.lock();
                shared.codec = FrameCodec::server();
            }

            let (read_result, write_result): (Result<(), _>, Result<(), _>) = future::zip(
                read.send_frame_internal(&read_frame),
                write.send_frame(&write_frame),
            )
            .await;
            assert!(read_result.is_ok(), "read half frame send must succeed");
            assert!(write_result.is_ok(), "write half frame send must succeed");

            let ws = read.reunite(write).expect("split halves must reunite");
            let written = ws.io.written;

            let mut read_then_write = expected_read.clone();
            read_then_write.extend_from_slice(&expected_write);

            let mut write_then_read = expected_write;
            write_then_read.extend_from_slice(&expected_read);

            assert!(
                written == read_then_write || written == write_then_read,
                "concurrent writes must preserve full-frame atomicity"
            );
        });
    }

    #[test]
    fn split_write_rejects_frame_larger_than_pending_write_budget_before_writing() {
        future::block_on(async {
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0xAB, 0xCD, 0xEF, 0x01]));
            let config = WebSocketConfig::default().max_pending_write_bytes(4);
            let ws = WebSocket::from_upgraded_with_entropy(
                TestIo::new(vec![]),
                config,
                Arc::clone(&entropy),
            );
            let (read, mut write) = ws.split();
            let cx = test_cx_with_entropy(entropy);

            let err = write
                .send(&cx, Message::text("hello"))
                .await
                .expect_err("split write must enforce the outbound buffer cap");

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
                "expected outbound buffer cap error, got {err:?}"
            );

            let ws = read.reunite(write).expect("split halves must reunite");
            assert!(
                ws.io.written.is_empty(),
                "split budget rejection must not commit a partial frame"
            );
            assert!(
                ws.is_open(),
                "wait policy must leave the split connection open"
            );
        });
    }

    #[test]
    fn test_reunite_error_display() {
        let err_msg = "attempted to reunite mismatched WebSocket halves";
        // Just verify the message format is correct
        assert!(err_msg.contains("reunite"));
        assert!(err_msg.contains("mismatched"));
    }

    #[test]
    fn flush_write_buf_clears_eagerly_for_cancel_safety() {
        // Verifies that write_buf is cleared before writing, so a cancel
        // during write_all won't leave stale data for the next flush.
        future::block_on(async {
            let ws = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
            let (read, _write) = ws.split();

            // Manually inject data into write_buf
            {
                let mut shared = read.shared.lock();
                shared.write_buf.extend_from_slice(b"stale-pong-data");
            }

            // flush_write_buf should clear write_buf before writing
            let result = flush_write_buf(&read.shared).await;
            assert!(result.is_ok());

            // write_buf must be empty after flush regardless of outcome
            let is_empty = read.shared.lock().write_buf.is_empty();
            assert!(
                is_empty,
                "write_buf must be cleared eagerly, not after write completes"
            );
        });
    }

    #[test]
    fn multiple_pong_payloads_all_encoded() {
        // Verifies that when multiple pongs are pending, all are encoded
        // and in FIFO order.
        future::block_on(async {
            let ws = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
            let (read, _write) = ws.split();

            // Push multiple pong payloads
            {
                let mut shared = read.shared.lock();
                shared
                    .pending_pongs
                    .push_back(Bytes::from_static(b"pong-a"));
                shared
                    .pending_pongs
                    .push_back(Bytes::from_static(b"pong-b"));
                shared
                    .pending_pongs
                    .push_back(Bytes::from_static(b"pong-c"));
                shared.pending_pong_flush = false;
            }

            // Encode pongs (same block as recv() does)
            {
                let shared = &mut *read.shared.lock();
                shared.write_buf.clear();
                let pongs: Vec<_> = shared.pending_pongs.drain(..).collect();
                for payload in pongs {
                    let pong = Frame::pong(payload);
                    shared.codec.encode(pong, &mut shared.write_buf).unwrap();
                }
                shared.pending_pong_flush = true;
            }

            let encoded = {
                let shared = read.shared.lock();
                BytesMut::from(shared.write_buf.as_ref())
            };
            let mut decode_buf = encoded;
            let mut decoder = FrameCodec::server();
            let mut payloads = Vec::new();

            while let Some(frame) = decoder.decode(&mut decode_buf).unwrap() {
                assert_eq!(frame.opcode, Opcode::Pong);
                payloads.push(frame.payload);
            }

            assert_eq!(
                payloads,
                vec![
                    Bytes::from_static(b"pong-a"),
                    Bytes::from_static(b"pong-b"),
                    Bytes::from_static(b"pong-c"),
                ],
                "pending pong payloads must be emitted in receive order"
            );
        });
    }

    #[test]
    fn recv_flushes_pongs_left_encoded_by_cancelled_attempt() {
        future::block_on(async {
            let ws = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
            let (mut read, _write) = ws.split();
            let cx = test_cx_with_entropy(Arc::new(FixedEntropy([0xAB, 0xCD, 0xEF, 0x01])));

            {
                let shared = &mut *read.shared.lock();
                let pong = Frame::pong(Bytes::from_static(b"pong-after-cancel"));
                shared
                    .codec
                    .encode(pong, &mut shared.write_buf)
                    .expect("must encode synthetic pong");
                shared.pending_pong_flush = true;
            }

            let result = read.recv(&cx).await.expect("recv must succeed");
            assert!(
                result.is_none(),
                "EOF should surface once buffered pongs flush"
            );

            let shared = read.shared.lock();
            assert!(
                !shared.pending_pong_flush,
                "recv must clear the deferred pong flush marker after flushing"
            );
            assert!(
                shared.write_buf.is_empty(),
                "recv must flush the encoded pong bytes before returning"
            );
            assert!(
                !shared.io.written.is_empty(),
                "recv must actually flush deferred pong bytes to the transport"
            );
        });
    }

    #[test]
    fn pending_pong_queue_keeps_most_recent_payloads() {
        let mut pending = std::collections::VecDeque::new();
        for n in 0u8..20 {
            enqueue_pending_pong(&mut pending, Bytes::from(vec![n]));
        }

        assert_eq!(pending.len(), MAX_PENDING_PONGS);
        let kept: Vec<u8> = pending
            .into_iter()
            .map(|payload| *payload.first().expect("single-byte payload"))
            .collect();
        assert_eq!(kept, (4u8..20).collect::<Vec<_>>());
    }

    #[test]
    fn reunite_mismatched_halves_returns_error() {
        let ws1 = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
        let ws2 = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
        let (read1, _write1) = ws1.split();
        let (_read2, write2) = ws2.split();

        let result = read1.reunite(write2);
        assert!(result.is_err(), "mismatched halves must fail reunite");
    }

    #[test]
    fn reunite_matching_halves_succeeds() {
        let ws = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
        let (read, write) = ws.split();

        let result = read.reunite(write);
        assert!(result.is_ok(), "matching halves must reunite successfully");
    }

    #[test]
    fn writer_permit_serializes_access() {
        // Verifies that the write permit prevents concurrent access.
        future::block_on(async {
            let ws = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
            let (read, _write) = ws.split();

            // Acquire write permit
            let permit = acquire_write_permit(&read.shared).await;

            // Verify writer_active is true
            assert!(
                read.shared.lock().writer_active,
                "writer_active must be true while permit is held"
            );

            // Drop permit
            drop(permit);

            // Verify writer_active is false
            assert!(
                !read.shared.lock().writer_active,
                "writer_active must be false after permit is dropped"
            );
        });
    }

    struct CountingWake {
        wake_count: AtomicUsize,
    }

    impl CountingWake {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                wake_count: AtomicUsize::new(0),
            })
        }

        fn count(&self) -> usize {
            self.wake_count.load(Ordering::SeqCst)
        }
    }

    use std::task::Wake;
    impl Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.wake_count.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wake_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn close_timer_context(start: u64) -> (Arc<VirtualClock>, TimerDriverHandle, Cx) {
        let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(start)));
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(77, 1),
            TaskId::new_for_test(77, 1),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        (clock, timer, cx)
    }

    fn websocket_with_close_timeout(io: TestIo) -> WebSocket<TestIo> {
        let mut config = WebSocketConfig::default();
        config.close_config.close_timeout = std::time::Duration::from_secs(10);
        config.ping_interval = None;
        WebSocket::from_upgraded_with_entropy(
            io,
            config,
            Arc::new(FixedEntropy([0x11, 0x22, 0x33, 0x44])),
        )
    }

    fn assert_close_expires_at(
        close: impl Future<Output = Result<(), WsError>>,
        clock: &VirtualClock,
        timer: &TimerDriverHandle,
        deadline_seconds: u64,
    ) {
        let counter = CountingWake::new();
        let waker = Waker::from(Arc::clone(&counter));
        let mut task = Context::from_waker(&waker);
        let mut close = std::pin::pin!(close);
        assert!(close.as_mut().poll(&mut task).is_pending());
        clock.set(Time::from_secs(deadline_seconds - 1));
        assert_eq!(timer.process_timers(), 0, "close must not expire early");
        assert!(close.as_mut().poll(&mut task).is_pending());
        let before = counter.count();
        clock.set(Time::from_secs(deadline_seconds));
        assert!(timer.process_timers() > 0, "the original deadline must be armed");
        assert!(counter.count() > before, "timeout must wake never-ready I/O");
        assert!(
            matches!(close.as_mut().poll(&mut task), Poll::Ready(Ok(()))),
            "close completes abortively when its bounded handshake expires"
        );
    }

    #[test]
    fn split_parked_reader_wakes_when_writer_starts_a_close() {
        let (clock, timer, cx) = close_timer_context(100);
        let ws = websocket_with_close_timeout(TestIo::new(vec![]).with_stalled_reads());
        let (mut read, mut write) = ws.split();
        let reader_counter = CountingWake::new();
        let reader_waker = Waker::from(Arc::clone(&reader_counter));
        let mut reader_task = Context::from_waker(&reader_waker);
        let mut recv = Box::pin(read.recv(&cx));
        assert!(recv.as_mut().poll(&mut reader_task).is_pending());
        assert_eq!(reader_counter.count(), 0, "the transport never wakes reads");

        let mut close = std::pin::pin!(write.send(&cx, Message::Close(None)));
        assert!(matches!(
            close.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        ));
        assert!(
            reader_counter.count() > 0,
            "an already parked reader must learn that the other half started closing"
        );
        assert!(recv.as_mut().poll(&mut reader_task).is_pending());
        clock.set(Time::from_secs(109));
        assert_eq!(timer.process_timers(), 0);
        let before = reader_counter.count();
        clock.set(Time::from_secs(110));
        assert!(timer.process_timers() > 0);
        assert!(reader_counter.count() > before);
        assert!(matches!(recv.as_mut().poll(&mut reader_task), Poll::Ready(Ok(None))));
        drop(recv);
        assert!(read.is_closed());
    }

    #[test]
    fn split_close_timeout_bounds_never_ready_writes_and_flushes() {
        for explicit_cx in [false, true] {
            for stall_flush in [false, true] {
                let (clock, timer, cx) = close_timer_context(100);
                let _current = (!explicit_cx).then(|| Cx::set_current(Some(cx.clone())));
                let io = if stall_flush {
                    TestIo::new(vec![]).with_stalled_flush()
                } else {
                    TestIo::new(vec![]).with_stalled_writes()
                };
                let (read, mut write) = websocket_with_close_timeout(io).split();
                assert_close_expires_at(
                    async {
                        if explicit_cx {
                            write.send(&cx, Message::Close(None)).await
                        } else {
                            write.close(CloseReason::normal()).await
                        }
                    },
                    &clock,
                    &timer,
                    110,
                );
                assert!(write.is_closed());
                let ws = read.reunite(write).expect("timeout releases writer ownership");
                if stall_flush {
                    assert_eq!(
                        ws.io.written,
                        encode_client_frame_with_entropy(
                            &CloseReason::normal().to_frame(),
                            &FixedEntropy([0x11, 0x22, 0x33, 0x44]),
                        ),
                        "a stalled flush must not duplicate the already written Close"
                    );
                } else {
                    assert!(ws.io.written.is_empty());
                }
            }
        }
    }

    #[test]
    fn split_crossing_peer_close_keeps_timeout_until_the_final_flush_finishes() {
        let (clock, timer, cx) = close_timer_context(100);
        let peer_close = encode_server_frame(CloseReason::normal().to_frame());
        let ws = websocket_with_close_timeout(TestIo::new(peer_close).with_stalled_flush());
        let (mut read, mut write) = ws.split();
        let writer_counter = CountingWake::new();
        let writer_waker = Waker::from(Arc::clone(&writer_counter));
        let mut writer_task = Context::from_waker(&writer_waker);
        let mut close = Box::pin(write.send(&cx, Message::Close(None)));
        assert!(close.as_mut().poll(&mut writer_task).is_pending());
        let reader_counter = CountingWake::new();
        let reader_waker = Waker::from(Arc::clone(&reader_counter));
        let mut reader_task = Context::from_waker(&reader_waker);
        let mut recv = Box::pin(read.recv(&cx));
        assert!(
            recv.as_mut().poll(&mut reader_task).is_pending(),
            "receiving the peer Close still owes our final transport flush"
        );
        clock.set(Time::from_secs(109));
        assert_eq!(timer.process_timers(), 0);
        assert!(close.as_mut().poll(&mut writer_task).is_pending());
        assert!(recv.as_mut().poll(&mut reader_task).is_pending());
        let writer_before = writer_counter.count();
        let reader_before = reader_counter.count();
        clock.set(Time::from_secs(110));
        assert!(timer.process_timers() > 0);
        assert!(writer_counter.count() > writer_before);
        assert!(reader_counter.count() > reader_before);
        assert!(matches!(recv.as_mut().poll(&mut reader_task), Poll::Ready(Ok(None))));
        assert!(matches!(close.as_mut().poll(&mut writer_task), Poll::Ready(Ok(()))));
        drop(recv);
        drop(close);
        let ws = read.reunite(write).expect("timeout releases the stalled final flush");
        assert!(ws.is_closed());
        assert_eq!(
            ws.io.written,
            encode_client_frame_with_entropy(
                &CloseReason::normal().to_frame(),
                &FixedEntropy([0x11, 0x22, 0x33, 0x44]),
            ),
            "crossing closes must not resend the already written Close"
        );
    }

    #[test]
    fn split_close_timeout_bounds_a_writer_waiting_for_the_readers_permit() {
        let (clock, timer, cx) = close_timer_context(100);
        let peer_ping = encode_server_frame(Frame::ping(Bytes::from_static(b"peer ping")));
        let ws = websocket_with_close_timeout(TestIo::new(peer_ping).with_stalled_writes());
        let (mut read, mut write) = ws.split();
        let reader_counter = CountingWake::new();
        let reader_waker = Waker::from(Arc::clone(&reader_counter));
        let mut reader_task = Context::from_waker(&reader_waker);
        let mut recv = Box::pin(read.recv(&cx));
        // Receiving Ping parks while its automatic Pong owns the write path.
        assert!(recv.as_mut().poll(&mut reader_task).is_pending());
        let before_close = reader_counter.count();
        let writer_counter = CountingWake::new();
        let writer_waker = Waker::from(Arc::clone(&writer_counter));
        let mut writer_task = Context::from_waker(&writer_waker);
        let mut close = Box::pin(write.send(&cx, Message::Close(None)));
        assert!(close.as_mut().poll(&mut writer_task).is_pending());
        assert!(reader_counter.count() > before_close);
        assert!(recv.as_mut().poll(&mut reader_task).is_pending());
        let reader_before = reader_counter.count();
        let writer_before = writer_counter.count();
        clock.set(Time::from_secs(110));
        assert!(timer.process_timers() > 0);
        assert!(reader_counter.count() > reader_before);
        assert!(writer_counter.count() > writer_before);
        assert!(matches!(close.as_mut().poll(&mut writer_task), Poll::Ready(Ok(()))));
        assert!(matches!(recv.as_mut().poll(&mut reader_task), Poll::Ready(Ok(None))));
        drop(close);
        drop(recv);
        let ws = read.reunite(write).expect("both stalled operations release ownership");
        assert!(ws.is_closed());
        assert!(ws.io.written.is_empty(), "timeout must not depend on releasing the transport");
    }

    #[test]
    fn split_peer_close_times_out_an_already_parked_data_writer() {
        let (clock, timer, cx) = close_timer_context(100);
        let peer_close = encode_server_frame(CloseReason::normal().to_frame());
        let ws = websocket_with_close_timeout(TestIo::new(peer_close).with_stalled_writes());
        let (mut read, mut write) = ws.split();
        let writer_counter = CountingWake::new();
        let writer_waker = Waker::from(Arc::clone(&writer_counter));
        let mut writer_task = Context::from_waker(&writer_waker);
        let mut send = Box::pin(write.send(&cx, Message::text("parked data")));
        assert!(send.as_mut().poll(&mut writer_task).is_pending());
        let before_close = writer_counter.count();
        let reader_counter = CountingWake::new();
        let reader_waker = Waker::from(Arc::clone(&reader_counter));
        let mut reader_task = Context::from_waker(&reader_waker);
        let mut recv = Box::pin(read.recv(&cx));
        assert!(recv.as_mut().poll(&mut reader_task).is_pending());
        assert!(writer_counter.count() > before_close, "peer Close wakes the parked writer");
        assert!(send.as_mut().poll(&mut writer_task).is_pending());
        let before_timeout = writer_counter.count();
        clock.set(Time::from_secs(110));
        assert!(timer.process_timers() > 0);
        assert!(writer_counter.count() > before_timeout);
        assert!(matches!(
            send.as_mut().poll(&mut writer_task),
            Poll::Ready(Err(WsError::Io(ref error))) if error.kind() == io::ErrorKind::TimedOut
        ));
        assert!(matches!(recv.as_mut().poll(&mut reader_task), Poll::Ready(Ok(None))));
        drop(send);
        drop(recv);
        let ws = read.reunite(write).expect("timed-out data writer releases its permit");
        assert!(ws.is_closed());
        assert!(ws.io.written.is_empty());
    }

    #[test]
    fn split_close_retry_and_reunite_keep_the_original_clock_and_deadline() {
        for migration in 0..3 {
            let (clock, timer, cx) = close_timer_context(100);
            let (read, mut write) =
                websocket_with_close_timeout(TestIo::new(vec![]).with_stalled_writes()).split();
            let mut first = Box::pin(write.send(&cx, Message::Close(Some(CloseReason::going_away()))));
            assert!(first.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
            clock.set(Time::from_secs(106));
            drop(first);
            // A later caller uses a different clock domain. The active close
            // still belongs to its original clock and expires at t=110, not
            // ten seconds after retry or at an unrelated clock's t=1010.
            let (_later_clock, _later_timer, later_cx) = close_timer_context(1000);
            if migration == 0 {
                assert_close_expires_at(
                    write.send(&later_cx, Message::Close(None)),
                    &clock,
                    &timer,
                    110,
                );
                assert!(write.is_closed());
                assert!(read.reunite(write).unwrap().is_closed());
            } else {
                let mut ws = read.reunite(write).expect("dropping a close releases its waiter");
                if migration == 1 {
                    assert_close_expires_at(
                        ws.close(&later_cx, CloseReason::normal()),
                        &clock,
                        &timer,
                        110,
                    );
                    assert!(ws.is_closed());
                } else {
                    let (read, mut write) = ws.split();
                    assert_close_expires_at(
                        write.send(&later_cx, Message::Close(None)),
                        &clock,
                        &timer,
                        110,
                    );
                    assert!(read.reunite(write).unwrap().is_closed());
                }
            }
        }
    }

    #[test]
    fn split_inherits_the_deadline_of_an_unsplit_peer_close_echo() {
        for stall_flush in [false, true] {
            let (clock, timer, cx) = close_timer_context(100);
            let peer_close = encode_server_frame(CloseReason::normal().to_frame());
            let io = if stall_flush {
                TestIo::new(peer_close).with_stalled_flush()
            } else {
                TestIo::new(peer_close).with_stalled_writes()
            };
            let mut ws = websocket_with_close_timeout(io);
            let mut recv = Box::pin(ws.recv(&cx));
            assert!(
                recv.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending(),
                "the unsplit peer-close echo must reach the stalled write or flush"
            );
            clock.set(Time::from_secs(106));
            drop(recv);
            let committed = ws.io.written.clone();
            assert_eq!(committed.is_empty(), !stall_flush);

            let (_later_clock, _later_timer, later_cx) = close_timer_context(1000);
            let (read, mut write) = ws.split();
            assert_close_expires_at(
                write.send(&later_cx, Message::Close(None)),
                &clock,
                &timer,
                110,
            );
            let ws = read.reunite(write).expect("timeout releases the inherited close echo");
            assert!(ws.is_closed());
            assert_eq!(
                ws.io.written, committed,
                "retry must not duplicate a peer-close echo already written before split"
            );
        }
    }

    #[test]
    fn split_open_reader_has_no_close_timeout_until_closing_starts() {
        let (clock, timer, cx) = close_timer_context(100);
        let (mut read, write) =
            websocket_with_close_timeout(TestIo::new(vec![]).with_stalled_reads()).split();
        let counter = CountingWake::new();
        let waker = Waker::from(Arc::clone(&counter));
        let mut task = Context::from_waker(&waker);
        let mut recv = Box::pin(read.recv(&cx));
        assert!(recv.as_mut().poll(&mut task).is_pending());
        clock.set(Time::from_secs(1000));
        assert_eq!(timer.process_timers(), 0);
        assert_eq!(counter.count(), 0);
        assert!(recv.as_mut().poll(&mut task).is_pending());
        drop(recv);
        assert!(read.reunite(write).unwrap().is_open());
    }

    #[test]
    fn writer_permit_release_wakes_first_waiter() {
        future::block_on(async {
            let ws = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
            let (read, _write) = ws.split();

            // Hold permit so subsequent acquires become waiters.
            let permit = acquire_write_permit(&read.shared).await;

            let mut first_waiter = Box::pin(acquire_write_permit(&read.shared));
            let mut second_waiter = Box::pin(acquire_write_permit(&read.shared));

            let counter_a = CountingWake::new();
            let counter_b = CountingWake::new();
            let first_task_waker: Waker = Waker::from(Arc::clone(&counter_a));
            let second_task_waker: Waker = Waker::from(Arc::clone(&counter_b));
            let mut first_context = Context::from_waker(&first_task_waker);
            let mut second_context = Context::from_waker(&second_task_waker);

            assert!(matches!(
                first_waiter.as_mut().poll(&mut first_context),
                Poll::Pending
            ));
            assert!(matches!(
                second_waiter.as_mut().poll(&mut second_context),
                Poll::Pending
            ));

            drop(permit);

            assert!(
                counter_a.count() > 0,
                "first waiter must be woken when permit is released"
            );
            assert_eq!(
                counter_b.count(),
                0,
                "second waiter must NOT be woken when permit is released (no thundering herd)"
            );
        });
    }

    #[test]
    fn writer_permit_queue_preserves_fifo_when_second_waiter_polls_first() {
        future::block_on(async {
            let ws = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
            let (read, _write) = ws.split();

            let permit = acquire_write_permit(&read.shared).await;

            let mut first_waiter = Box::pin(acquire_write_permit(&read.shared));
            let mut second_waiter = Box::pin(acquire_write_permit(&read.shared));

            let first_waker: Waker = std::task::Waker::noop().clone();
            let second_waker: Waker = std::task::Waker::noop().clone();
            let mut first_context = Context::from_waker(&first_waker);
            let mut second_context = Context::from_waker(&second_waker);

            assert!(matches!(
                first_waiter.as_mut().poll(&mut first_context),
                Poll::Pending
            ));
            assert!(matches!(
                second_waiter.as_mut().poll(&mut second_context),
                Poll::Pending
            ));

            drop(permit);

            assert!(
                matches!(
                    second_waiter.as_mut().poll(&mut second_context),
                    Poll::Pending
                ),
                "later waiters must not bypass the queued head when the permit becomes free"
            );
            assert!(
                matches!(
                    first_waiter.as_mut().poll(&mut first_context),
                    Poll::Ready(_)
                ),
                "the head waiter must acquire the permit first"
            );
        });
    }

    #[test]
    fn split_send_close_message_initiates_close_handshake() {
        future::block_on(async {
            let ws = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
            let (_read, mut write) = ws.split();
            let cx = Cx::for_testing();

            assert!(write.is_open(), "connection should start open");
            write
                .send(&cx, Message::Close(None))
                .await
                .expect("sending close should succeed");
            assert!(
                !write.is_open(),
                "sending Message::Close must transition handshake out of open state"
            );

            let err = write
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
    fn split_close_dropped_before_first_write_retains_original_frame() {
        future::block_on(async {
            for server_role in [false, true] {
                for via_send in [false, true] {
                    let entropy: Arc<dyn EntropySource> =
                        Arc::new(FixedEntropy([0xD2, 0x10, 0x44, 0x9A]));
                    let ws = WebSocket::from_upgraded_with_entropy(
                        TestIo::new(vec![]).with_pending_first_write(),
                        WebSocketConfig::default(),
                        Arc::clone(&entropy),
                    );
                    let (read, mut write) = ws.split();
                    if server_role {
                        read.shared.lock().codec = FrameCodec::server();
                    }
                    let cx = test_cx_with_entropy(Arc::clone(&entropy));
                    let reason = CloseReason::with_text(super::super::CloseCode::GoingAway, "first");
                    let expected = if server_role {
                        encode_server_frame(reason.to_frame())
                    } else {
                        encode_client_frame_with_entropy(&reason.to_frame(), entropy.as_ref())
                    };
                    let mut close = Box::pin(async {
                        if via_send {
                            write.send(&cx, Message::Close(Some(reason))).await
                        } else {
                            write.close(reason).await
                        }
                    });
                    let waker = Waker::noop().clone();
                    let mut task = Context::from_waker(&waker);
                    assert!(
                        close.as_mut().poll(&mut task).is_pending(),
                        "close must reach the first transport write"
                    );
                    {
                        let shared = read.shared.lock();
                        assert!(shared.writer_active);
                        assert!(shared.io.written.is_empty());
                        assert_eq!(shared.close_handshake.state(), CloseState::CloseSent);
                    }
                    drop(close);
                    {
                        let shared = read.shared.lock();
                        assert_eq!(&shared.write_buf[..], expected.as_slice());
                        assert!(!shared.writer_active);
                        assert!(shared.writer_waiters.is_empty());
                    }

                    write
                        .close(CloseReason::normal())
                        .await
                        .expect("retry must flush the retained Close");
                    let ws = read.reunite(write).expect("split halves must reunite");
                    assert_eq!(ws.close_state(), CloseState::CloseSent);
                    assert!(ws.write_buf.is_empty());
                    assert_eq!(
                        ws.io.written, expected,
                        "retry sends the original reason and mask exactly once"
                    );
                }
            }
        });
    }

    #[test]
    fn split_close_dropped_waiting_for_writer_survives_reunite() {
        future::block_on(async {
            let entropy: Arc<dyn EntropySource> =
                Arc::new(FixedEntropy([0x11, 0x22, 0x33, 0x44]));
            let ws = WebSocket::from_upgraded_with_entropy(
                TestIo::new(vec![]),
                WebSocketConfig::default(),
                Arc::clone(&entropy),
            );
            let (read, mut write) = ws.split();
            let cx = test_cx_with_entropy(Arc::clone(&entropy));
            let permit = acquire_write_permit(&read.shared).await;
            let reason = CloseReason::going_away();
            let expected = encode_client_frame_with_entropy(&reason.to_frame(), entropy.as_ref());
            let mut close = Box::pin(write.send(&cx, Message::Close(Some(reason))));
            let waker = Waker::noop().clone();
            let mut task = Context::from_waker(&waker);
            assert!(close.as_mut().poll(&mut task).is_pending());
            {
                let shared = read.shared.lock();
                assert_eq!(shared.writer_waiters.len(), 1);
                assert_eq!(shared.close_handshake.state(), CloseState::CloseSent);
                assert!(shared.io.written.is_empty());
            }
            drop(close);
            assert!(read.shared.lock().writer_waiters.is_empty());
            drop(permit);

            let mut ws = read.reunite(write).expect("no permit or waiter may leak");
            assert_eq!(&ws.write_buf[..], expected.as_slice());
            ws.send(&cx, Message::Close(Some(CloseReason::normal())))
                .await
                .expect("unsplit retry must flush the retained split Close");
            assert!(ws.write_buf.is_empty());
            assert_eq!(ws.io.written, expected);
        });
    }

    #[test]
    fn split_close_dropped_during_prior_frame_flush_preserves_wire_order() {
        future::block_on(async {
            let ws = WebSocket::from_upgraded(
                TestIo::new(vec![]).with_partial_first_write(1),
                WebSocketConfig::default(),
            );
            let (read, mut write) = ws.split();
            read.shared.lock().codec = FrameCodec::server();
            let cx = Cx::for_testing();
            let message = Message::text("already started");
            let data = encode_server_frame(Frame::from(message.clone()));
            let mut send = Box::pin(write.send(&cx, message));
            let waker = Waker::noop().clone();
            let mut task = Context::from_waker(&waker);
            assert!(send.as_mut().poll(&mut task).is_pending());
            drop(send);
            {
                let mut shared = read.shared.lock();
                assert_eq!(&shared.io.written[..], &data[..1]);
                assert_eq!(&shared.write_buf[..], &data[1..]);
                shared.io.pending_first_write = true;
            }

            let close_frame = encode_server_frame(CloseReason::going_away().to_frame());
            let mut close = Box::pin(write.close(CloseReason::going_away()));
            assert!(close.as_mut().poll(&mut task).is_pending());
            drop(close);
            let mut retained = data[1..].to_vec();
            retained.extend_from_slice(&close_frame);
            {
                let shared = read.shared.lock();
                assert_eq!(&shared.write_buf[..], retained.as_slice());
                assert!(!shared.writer_active);
                assert!(shared.writer_waiters.is_empty());
            }

            write.close(CloseReason::normal()).await.unwrap();
            let ws = read.reunite(write).unwrap();
            let mut expected = data;
            expected.extend_from_slice(&close_frame);
            assert_eq!(ws.io.written, expected, "DATA tail must precede Close");
            assert!(ws.write_buf.is_empty());
        });
    }

    #[test]
    fn split_crossing_peer_close_flushes_a_dropped_local_close() {
        future::block_on(async {
            for retry_after_crossing in 0..3 {
                let peer_close = encode_client_frame_with_entropy(
                    &Frame::close(Some(1000), None),
                    &FixedEntropy([0x11, 0x22, 0x33, 0x44]),
                );
                let ws = WebSocket::from_upgraded(
                    TestIo::new(peer_close).with_pending_first_write(),
                    WebSocketConfig::default(),
                );
                let (mut read, mut write) = ws.split();
                read.shared.lock().codec = FrameCodec::server();
                let cx = Cx::for_testing();
                let expected = encode_server_frame(CloseReason::going_away().to_frame());
                let waker = Waker::noop().clone();
                let mut task = Context::from_waker(&waker);
                let mut close = Box::pin(write.close(CloseReason::going_away()));
                assert!(close.as_mut().poll(&mut task).is_pending());
                drop(close);
                {
                    let mut state = read.shared.lock();
                    assert_eq!(state.close_handshake.state(), CloseState::CloseSent);
                    assert!(state.io.written.is_empty());
                    assert_eq!(&state.write_buf[..], expected.as_slice());
                    state.io.pending_first_write = retry_after_crossing != 0;
                }

                if retry_after_crossing != 0 {
                    let mut recv = Box::pin(read.recv(&cx));
                    assert!(
                        recv.as_mut().poll(&mut task).is_pending(),
                        "the crossing peer Close must flush our pending Close"
                    );
                    drop(recv);
                    {
                        let state = read.shared.lock();
                        assert_eq!(state.close_handshake.state(), CloseState::Closed);
                        assert!(state.io.written.is_empty());
                        assert_eq!(&state.write_buf[..], expected.as_slice());
                        assert!(!state.writer_active);
                        assert!(state.writer_waiters.is_empty());
                    }
                    if retry_after_crossing == 2 {
                        let mut ws = read.reunite(write).unwrap();
                        ws.send(&cx, Message::Close(Some(CloseReason::normal())))
                            .await
                            .expect("reunited Closed retains the original local Close");
                        assert!(ws.is_closed());
                        assert!(ws.write_buf.is_empty());
                        assert_eq!(ws.io.written, expected);
                        continue;
                    }
                    write
                        .close(CloseReason::normal())
                        .await
                        .expect("Closed can still retain an unsent local Close");
                } else {
                    assert!(matches!(read.recv(&cx).await, Ok(Some(Message::Close(_)))));
                }

                let ws = read.reunite(write).unwrap();
                assert!(ws.is_closed());
                assert!(ws.write_buf.is_empty());
                assert_eq!(
                    ws.io.written, expected,
                    "send the original local Close exactly once, without a second echo"
                );
            }
        });
    }

    #[test]
    fn split_crossing_close_final_flush_survives_retry_and_reunite() {
        future::block_on(async {
            for reunite_before_retry in [false, true] {
                for force_close in [false, true] {
                    let peer_close = encode_client_frame_with_entropy(
                        &Frame::close(Some(1000), None),
                        &FixedEntropy([0x11, 0x22, 0x33, 0x44]),
                    );
                    let ws = WebSocket::from_upgraded(
                        TestIo::new(peer_close).with_pending_first_write(),
                        WebSocketConfig::default(),
                    );
                    let (mut read, mut write) = ws.split();
                    read.shared.lock().codec = FrameCodec::server();
                    let cx = Cx::for_testing();
                    let expected = encode_server_frame(CloseReason::going_away().to_frame());
                    let waker = Waker::noop().clone();
                    let mut task = Context::from_waker(&waker);
                    let mut close = Box::pin(write.close(CloseReason::going_away()));
                    assert!(close.as_mut().poll(&mut task).is_pending());
                    drop(close);
                    read.shared.lock().io.stall_flush_after_write = true;

                    let mut recv = Box::pin(read.recv(&cx));
                    assert!(recv.as_mut().poll(&mut task).is_pending());
                    drop(recv);
                    {
                        let state = read.shared.lock();
                        assert_eq!(state.close_handshake.state(), CloseState::Closed);
                        assert!(state.close_handshake.peer_reason().is_some());
                        assert_eq!(state.io.written, expected);
                        assert!(state.write_buf.is_empty());
                        assert!(state.close_flush_pending);
                        assert_eq!(state.io.flush_polls, 1);
                        assert!(!state.writer_active);
                        assert!(state.writer_waiters.is_empty());
                    }

                    if force_close {
                        // A heartbeat failure force-closes while retaining
                        // peer_reason. It must disable the pending I/O retry.
                        read.fail_heartbeat();
                        let state = read.shared.lock();
                        assert!(state.close_handshake.peer_reason().is_some());
                        assert!(!state.close_flush_pending);
                    } else {
                        read.shared.lock().io.stall_flush_after_write = false;
                    }
                    let expected_flush_polls = if force_close { 1 } else { 2 };

                    if reunite_before_retry {
                        let mut ws = read.reunite(write).unwrap();
                        let mut retry = Box::pin(
                            ws.send(&cx, Message::Close(Some(CloseReason::normal()))),
                        );
                        assert!(matches!(
                            retry.as_mut().poll(&mut task),
                            Poll::Ready(Ok(()))
                        ));
                        drop(retry);
                        assert!(ws.is_closed());
                        assert!(!ws.close_flush_pending);
                        assert!(ws.write_buf.is_empty());
                        assert_eq!(ws.io.written, expected);
                        assert_eq!(ws.io.flush_polls, expected_flush_polls);

                        // A completed close stays idempotent even if another
                        // transport flush would now hang (e.g. after shutdown).
                        ws.io.stall_flush_after_write = true;
                        let mut retry = Box::pin(ws.send(&cx, Message::Close(None)));
                        assert!(matches!(
                            retry.as_mut().poll(&mut task),
                            Poll::Ready(Ok(()))
                        ));
                        drop(retry);
                        assert_eq!(ws.io.flush_polls, expected_flush_polls);
                    } else {
                        let mut retry = Box::pin(write.close(CloseReason::normal()));
                        assert!(matches!(
                            retry.as_mut().poll(&mut task),
                            Poll::Ready(Ok(()))
                        ));
                        drop(retry);
                        {
                            let mut state = read.shared.lock();
                            assert!(!state.close_flush_pending);
                            assert!(state.write_buf.is_empty());
                            assert_eq!(state.io.written, expected);
                            assert_eq!(state.io.flush_polls, expected_flush_polls);
                            state.io.stall_flush_after_write = true;
                        }
                        let mut retry = Box::pin(write.close(CloseReason::normal()));
                        assert!(matches!(
                            retry.as_mut().poll(&mut task),
                            Poll::Ready(Ok(()))
                        ));
                        drop(retry);
                        assert_eq!(read.shared.lock().io.flush_polls, expected_flush_polls);
                        let ws = read.reunite(write).unwrap();
                        assert!(ws.is_closed());
                        assert!(!ws.close_flush_pending);
                    }
                }
            }
        });
    }

    #[test]
    fn split_data_waiting_for_writer_cannot_follow_close_echo() {
        future::block_on(async {
            let peer_close = encode_client_frame_with_entropy(
                &Frame::close(Some(1000), None),
                &FixedEntropy([0x11, 0x22, 0x33, 0x44]),
            );
            let ws = WebSocket::from_upgraded(TestIo::new(peer_close), WebSocketConfig::default());
            let (mut read, mut write) = ws.split();
            read.shared.lock().codec = FrameCodec::server();
            let shared = Arc::clone(&read.shared);
            let cx = Cx::for_testing();
            let permit = acquire_write_permit(&shared).await;
            let waker = Waker::noop().clone();
            let mut task = Context::from_waker(&waker);
            let mut send = Box::pin(write.send(&cx, Message::text("too late")));
            assert!(send.as_mut().poll(&mut task).is_pending());
            assert!(shared.lock().close_handshake.is_open());
            let mut recv = Box::pin(read.recv(&cx));
            assert!(recv.as_mut().poll(&mut task).is_pending());
            {
                let state = shared.lock();
                assert_eq!(state.writer_waiters.len(), 2);
                assert_eq!(state.close_handshake.state(), CloseState::CloseReceived);
                assert!(!state.write_buf.is_empty());
                assert!(state.io.written.is_empty());
            }
            drop(permit);

            let (sent, received) = future::zip(send, recv).await;
            assert!(
                matches!(sent, Err(WsError::Io(ref err)) if err.kind() == io::ErrorKind::NotConnected),
                "queued DATA must be refused once Close is received: {sent:?}"
            );
            assert!(matches!(received, Ok(Some(Message::Close(_)))));
            {
                let state = shared.lock();
                assert!(!state.writer_active);
                assert!(state.writer_waiters.is_empty());
                assert!(state.write_buf.is_empty());
            }
            drop(shared);
            let ws = read.reunite(write).unwrap();
            assert!(ws.is_closed());
            assert_eq!(
                ws.io.written,
                encode_server_frame(Frame::close(Some(1000), None)),
                "the wire must contain only the Close echo"
            );
        });
    }

    #[test]
    fn split_data_flushing_prior_tail_cannot_follow_close_echo() {
        future::block_on(async {
            let peer_close = encode_client_frame_with_entropy(
                &Frame::close(Some(1000), None),
                &FixedEntropy([0x11, 0x22, 0x33, 0x44]),
            );
            let ws = WebSocket::from_upgraded(
                TestIo::new(peer_close).with_partial_first_write(1),
                WebSocketConfig::default(),
            );
            let (mut read, mut write) = ws.split();
            read.shared.lock().codec = FrameCodec::server();
            let shared = Arc::clone(&read.shared);
            let cx = Cx::for_testing();
            let first = Message::text("already started");
            let expected_first = encode_server_frame(Frame::from(first.clone()));
            let waker = Waker::noop().clone();
            let mut task = Context::from_waker(&waker);
            let mut first_send = Box::pin(write.send(&cx, first));
            assert!(first_send.as_mut().poll(&mut task).is_pending());
            drop(first_send);
            {
                let mut state = shared.lock();
                assert_eq!(&state.io.written[..], &expected_first[..1]);
                assert_eq!(&state.write_buf[..], &expected_first[1..]);
                state.io.pending_first_write = true;
            }

            let mut late_send = Box::pin(write.send(&cx, Message::text("too late")));
            assert!(late_send.as_mut().poll(&mut task).is_pending());
            assert!(shared.lock().writer_active);
            let mut recv = Box::pin(read.recv(&cx));
            assert!(recv.as_mut().poll(&mut task).is_pending());
            assert_eq!(shared.lock().close_handshake.state(), CloseState::CloseReceived);
            let (sent, received) = future::zip(late_send, recv).await;
            assert!(
                matches!(sent, Err(WsError::Io(ref err)) if err.kind() == io::ErrorKind::NotConnected),
                "admission must be checked after flushing the prior tail: {sent:?}"
            );
            assert!(matches!(received, Ok(Some(Message::Close(_)))));
            {
                let state = shared.lock();
                assert!(!state.writer_active);
                assert!(state.writer_waiters.is_empty());
            }
            drop(shared);
            let ws = read.reunite(write).unwrap();
            let mut expected = expected_first;
            expected.extend_from_slice(&encode_server_frame(Frame::close(Some(1000), None)));
            assert_eq!(ws.io.written, expected);
            assert!(ws.write_buf.is_empty());
            assert!(ws.is_closed());
        });
    }

    #[test]
    fn split_close_budget_rejection_does_not_lose_a_close_in_close_sent() {
        future::block_on(async {
            for policy in [
                super::super::SlowConsumerPolicy::Wait,
                super::super::SlowConsumerPolicy::CloseWithTryAgainLater,
            ] {
                let config = WebSocketConfig::default()
                    .max_pending_write_bytes(4)
                    .slow_consumer_policy(policy);
                let ws = WebSocket::from_upgraded(TestIo::new(vec![]), config);
                let (read, mut write) = ws.split();
                let err = write
                    .close(CloseReason::normal())
                    .await
                    .expect_err("a masked Close cannot fit within four bytes");
                assert!(matches!(
                    err,
                    WsError::OutboundBufferFull {
                        pending: 0,
                        attempted: 8,
                        max: 4,
                        ..
                    }
                ));
                let expected_state = match policy {
                    super::super::SlowConsumerPolicy::Wait => CloseState::Open,
                    super::super::SlowConsumerPolicy::CloseWithTryAgainLater => CloseState::Closed,
                };
                assert_eq!(write.close_state(), expected_state);
                let state = read.shared.lock();
                assert!(state.write_buf.is_empty());
                assert!(state.io.written.is_empty());
                assert!(!state.writer_active);
                assert!(state.writer_waiters.is_empty());
            }
        });
    }

    #[test]
    fn typed_write_close_consumes_open_state() {
        future::block_on(async {
            let ws = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
            let (read, write) = ws.split();
            let cx = Cx::for_testing();

            let mut open = write.into_typed_open();
            assert!(open.is_open(), "typed write should start in open state");

            open.send_text(&cx, "typed hello")
                .await
                .expect("typed open write must send data");

            let mut closing = open
                .close(&cx, CloseReason::going_away())
                .await
                .expect("typed close should initiate the dynamic close handshake");
            assert_eq!(
                closing.close_state(),
                CloseState::CloseSent,
                "typed close must leave the underlying handshake in CloseSent"
            );

            closing
                .flush_close(&cx)
                .await
                .expect("typed CloseSent retry should flush without new data methods");

            let write = closing.into_dynamic();
            assert!(
                !write.is_open(),
                "dynamic escape hatch must preserve close-handshake state"
            );
            let _ws = read.reunite(write).expect("split halves must reunite");
        });
    }

    #[test]
    fn split_recv_keeps_close_received_state_if_response_send_fails() {
        future::block_on(async {
            let read_data = encode_server_frame(Frame::close(Some(1000), None));
            let ws = WebSocket::from_upgraded(
                TestIo::new(read_data).with_write_failure(),
                WebSocketConfig::default(),
            );
            let (mut read, _write) = ws.split();
            let cx = Cx::for_testing();

            let err = read
                .recv(&cx)
                .await
                .expect_err("close response write should fail");
            assert!(
                matches!(err, WsError::Io(ref e) if e.kind() == io::ErrorKind::BrokenPipe),
                "expected synthetic broken-pipe write failure, got {err:?}"
            );
            assert!(
                !read.is_closed(),
                "failed close response writes must not incorrectly finish the handshake"
            );
            assert_eq!(
                read.shared.lock().close_handshake.state(),
                CloseState::CloseReceived,
                "failed close response writes must leave the handshake waiting for a retry"
            );
        });
    }

    #[test]
    fn cancelled_write_half_send_does_not_flush_frame_later() {
        future::block_on(async {
            let ws = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
            let (read, mut write) = ws.split();
            let cx = test_cx_with_entropy(Arc::new(FixedEntropy([0xAA, 0xBB, 0xCC, 0xDD])));

            {
                let mut shared = read.shared.lock();
                shared.codec = FrameCodec::server();
            }

            let permit = acquire_write_permit(&read.shared).await;
            let cancelled = Message::text("cancelled");
            let delivered = Message::text("delivered");
            let mut cancelled_send = Box::pin(write.send(&cx, cancelled));
            let wake_counter = CountingWake::new();
            let task_waker: Waker = Waker::from(Arc::clone(&wake_counter));
            let mut task_cx = Context::from_waker(&task_waker);

            assert!(
                matches!(cancelled_send.as_mut().poll(&mut task_cx), Poll::Pending),
                "first send should park waiting for the write permit"
            );
            drop(cancelled_send);
            assert!(
                read.shared.lock().write_buf.is_empty(),
                "dropping a parked split send must not leave bytes in the shared write buffer"
            );

            drop(permit);
            write
                .send(&cx, delivered.clone())
                .await
                .expect("second send should succeed");

            let ws = read.reunite(write).expect("split halves must reunite");
            assert_eq!(
                ws.io.written,
                encode_server_frame(Frame::from(delivered)),
                "later flushes must not emit bytes from a cancelled split send"
            );
        });
    }

    #[test]
    fn write_half_send_ignores_cancel_while_masked() {
        let ws = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
        let (read, mut write) = ws.split();
        let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0xDE, 0xAD, 0xBE, 0xEF]));
        let cx = test_cx_with_entropy(Arc::clone(&entropy));
        cx.set_cancel_requested(true);
        let _guard = Cx::set_current(Some(cx.clone()));
        let masked = Message::text("masked");

        cx.masked(|| future::block_on(write.send(&cx, masked.clone())))
            .expect("masked split send should defer cancellation");

        let ws = read.reunite(write).expect("split halves must reunite");
        assert_eq!(
            ws.io.written,
            encode_client_frame_with_entropy(&Frame::from(masked), entropy.as_ref()),
            "masked split send should still flush the original frame"
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
    fn split_native_stalled_write_and_flush_wake_for_operation_cancellation() {
        for operation in 0..3 {
            for stall_flush in [false, true] {
                let runtime = crate::runtime::RuntimeBuilder::current_thread()
                    .build()
                    .expect("build native runtime");
                runtime.block_on(runtime.handle().spawn(async move {
                    let parent = Cx::current().expect("native task context");
                    let io = if stall_flush {
                        TestIo::new(vec![]).with_stalled_flush()
                    } else {
                        TestIo::new(vec![]).with_stalled_writes()
                    };
                    let ws = WebSocket::from_upgraded(io, WebSocketConfig::default());
                    let (read, mut write) = ws.split();
                    read.shared.lock().codec = FrameCodec::server();
                    // This operation context is deliberately independent of
                    // the task context. Cancelling it cannot rely on the
                    // scheduler's TaskHandle/abort wake registration.
                    let operation_cx = Cx::for_testing();
                    let writer_cx = operation_cx.clone();
                    let expected = encode_server_frame(match operation {
                        0 => Frame::text("payload"),
                        1 => CloseReason::normal().to_frame(),
                        _ => Frame::ping(Bytes::from_static(b"probe")),
                    });
                    let mut writer = parent
                        .spawn(move |_| async move {
                            let result = if operation == 2 {
                                // ping() has no explicit Cx parameter: exercise
                                // the legacy ambient-context write path too.
                                let mut ping =
                                    std::pin::pin!(write.ping(Bytes::from_static(b"probe")));
                                std::future::poll_fn(|task| {
                                    let _current = Cx::set_current(Some(writer_cx.clone()));
                                    ping.as_mut().poll(task)
                                })
                                .await
                            } else {
                                let message = if operation == 1 {
                                    Message::Close(Some(CloseReason::normal()))
                                } else {
                                    Message::text("payload")
                                };
                                write.send(&writer_cx, message).await
                            };
                            (write, result)
                        })
                        .expect("spawn native writer");

                    for _ in 0..512 {
                        let parked = {
                            let state = read.shared.lock();
                            state.io.write_polls == 1
                                && (!stall_flush || !state.io.written.is_empty())
                        };
                        if parked {
                            break;
                        }
                        crate::runtime::yield_now().await;
                    }
                    let polls_before = {
                        let state = read.shared.lock();
                        assert!(state.writer_active, "writer must own the permit");
                        assert_eq!(
                            state.io.write_polls, 1,
                            "transport must be parked without self-wakes"
                        );
                        if stall_flush {
                            assert_eq!(state.io.written, expected);
                        } else {
                            assert!(state.io.written.is_empty());
                        }
                        (state.io.write_polls, state.io.flush_polls)
                    };
                    let registrations_while_parked =
                        operation_cx.inner.read().cancel_waker_registrations.len();
                    let canceller = operation_cx.clone();
                    std::thread::spawn(move || {
                        canceller.cancel_with(
                            crate::types::CancelKind::User,
                            Some("cancel independently parked split write"),
                        );
                    })
                    .join()
                    .expect("cross-thread canceller");

                    let completion = crate::time::timeout(
                        parent.now(),
                        std::time::Duration::from_secs(2),
                        std::future::poll_fn(|task| writer.poll_join(task)),
                    )
                    .await;
                    let cancelled_without_transport_wake = completion.is_ok();
                    let joined = match completion {
                        Ok(joined) => joined,
                        Err(_) => {
                            // Clean up the old-code failure without leaving
                            // a native task behind. This forced wake must not
                            // count as successful cancellation propagation.
                            let wake = read.shared.lock().heartbeat_writer.clone().unwrap();
                            wake.wake();
                            writer.join(&parent).await
                        }
                    };
                    let (write, result) = joined.expect("writer must return its typed result");
                    assert!(
                        matches!(result, Err(WsError::Io(ref err)) if err.kind() == io::ErrorKind::Interrupted),
                        "expected operation-level cancellation, got {result:?}"
                    );
                    {
                        let state = read.shared.lock();
                        assert_eq!((state.io.write_polls, state.io.flush_polls), polls_before);
                        assert!(!state.writer_active);
                        assert!(state.writer_waiters.is_empty());
                    }
                    assert!(operation_cx.inner.read().cancel_waker_registrations.is_empty());
                    let ws = read.reunite(write).expect("no split ownership may leak");
                    if stall_flush {
                        assert_eq!(ws.io.written, expected);
                        assert!(ws.write_buf.is_empty());
                    } else {
                        assert!(ws.io.written.is_empty());
                        if operation == 1 {
                            assert_eq!(&ws.write_buf[..], expected.as_slice());
                        } else {
                            assert!(ws.write_buf.is_empty());
                        }
                    }
                    assert_eq!(registrations_while_parked, 1);
                    assert!(
                        cancelled_without_transport_wake,
                        "external cancellation must wake the native task at its original park"
                    );
                }));
            }
        }
    }

    #[test]
    fn split_native_writer_cancels_while_reader_still_owns_the_permit() {
        for send_close in [false, true] {
            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .expect("build native runtime");
            runtime.block_on(runtime.handle().spawn(async move {
                let parent = Cx::current().expect("native task context");
                let payload = Bytes::from_static(b"peer ping");
                let peer_ping = encode_client_frame_with_entropy(
                    &Frame::ping(payload.clone()),
                    &FixedEntropy([0x11, 0x22, 0x33, 0x44]),
                );
                let ws = WebSocket::from_upgraded(
                    TestIo::new(peer_ping).with_stalled_writes(),
                    WebSocketConfig::default(),
                );
                let (mut read, mut write) = ws.split();
                let shared = Arc::clone(&read.shared);
                shared.lock().codec = FrameCodec::server();
                let mut reader = parent
                    .spawn(move |cx| async move {
                        let result = read.recv(&cx).await;
                        (read, result)
                    })
                    .expect("spawn native reader");
                for _ in 0..512 {
                    if shared.lock().io.write_polls == 1 {
                        break;
                    }
                    crate::runtime::yield_now().await;
                }
                {
                    let state = shared.lock();
                    assert!(state.writer_active);
                    assert_eq!(state.io.write_polls, 1, "Pong flush must be parked");
                    assert!(state.io.written.is_empty());
                }

                let operation_cx = Cx::for_testing();
                let writer_cx = operation_cx.clone();
                let mut writer = parent
                    .spawn(move |_| async move {
                        let message = if send_close {
                            Message::Close(Some(CloseReason::normal()))
                        } else {
                            Message::text("cancelled before admission")
                        };
                        let result = write.send(&writer_cx, message).await;
                        (write, result)
                    })
                    .expect("spawn native writer");
                for _ in 0..512 {
                    if shared.lock().writer_waiters.len() == 1 {
                        break;
                    }
                    crate::runtime::yield_now().await;
                }
                assert_eq!(shared.lock().writer_waiters.len(), 1);
                let registrations_while_queued =
                    operation_cx.inner.read().cancel_waker_registrations.len();
                let canceller = operation_cx.clone();
                std::thread::spawn(move || {
                    canceller.cancel_with(
                        crate::types::CancelKind::User,
                        Some("cancel split writer behind stalled reader"),
                    );
                })
                .join()
                .expect("cross-thread canceller");
                let completion = crate::time::timeout(
                    parent.now(),
                    std::time::Duration::from_secs(2),
                    std::future::poll_fn(|task| writer.poll_join(task)),
                )
                .await;
                let cancelled_before_reader_release = completion.is_ok();
                let clean_while_reader_parked = {
                    let state = shared.lock();
                    state.writer_active
                        && state.writer_waiters.is_empty()
                        && state.io.write_polls == 1
                        && state.io.written.is_empty()
                };

                // Release the deliberately stalled reader in both success and
                // old-code failure paths, then drain both native children.
                let wake = {
                    let mut state = shared.lock();
                    state.io.stall_writes = false;
                    state.heartbeat_writer.clone().unwrap()
                };
                wake.wake();
                let joined = match completion {
                    Ok(joined) => joined,
                    Err(_) => writer.join(&parent).await,
                };
                let (write, result) = joined.expect("writer must return its typed result");
                assert!(
                    matches!(result, Err(WsError::Io(ref err)) if err.kind() == io::ErrorKind::Interrupted),
                    "expected cancellation while acquiring the permit, got {result:?}"
                );
                let (read, received) = reader.join(&parent).await.expect("drain reader");
                assert!(matches!(received, Ok(None)));
                {
                    let state = shared.lock();
                    assert!(!state.writer_active);
                    assert!(state.writer_waiters.is_empty());
                    assert!(state.write_buf.is_empty());
                }
                assert!(operation_cx.inner.read().cancel_waker_registrations.is_empty());
                drop(shared);
                let ws = read.reunite(write).expect("native children must release both halves");
                let mut expected = encode_server_frame(Frame::pong(payload));
                if send_close {
                    expected.extend_from_slice(&encode_server_frame(
                        CloseReason::normal().to_frame(),
                    ));
                }
                assert_eq!(ws.io.written, expected);
                assert_eq!(registrations_while_queued, 1);
                assert!(
                    cancelled_before_reader_release,
                    "cancellation must not wait for the reader's permit"
                );
                assert!(
                    clean_while_reader_parked,
                    "cancelled writer must unlink without disturbing the active reader"
                );
            }));
        }
    }

    #[test]
    fn split_dropped_permit_wait_removes_only_its_cancel_registration() {
        future::block_on(async {
            let ws = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
            let (read, mut write) = ws.split();
            let cx = Cx::for_testing();
            let permit = acquire_write_permit(&read.shared).await;
            let counter = CountingWake::new();
            let waker = Waker::from(Arc::clone(&counter));
            let mut task = Context::from_waker(&waker);
            let unrelated = cx.refresh_cancel_waker(None, &waker);
            let mut send = Box::pin(write.send(&cx, Message::text("uncommitted")));
            for _ in 0..8 {
                assert!(send.as_mut().poll(&mut task).is_pending());
                assert_eq!(cx.inner.read().cancel_waker_registrations.len(), 2);
                assert_eq!(read.shared.lock().writer_waiters.len(), 1);
            }
            drop(send);
            assert_eq!(cx.inner.read().cancel_waker_registrations.len(), 1);
            {
                let state = read.shared.lock();
                assert!(state.writer_active);
                assert!(state.writer_waiters.is_empty());
                assert!(state.write_buf.is_empty());
                assert!(state.io.written.is_empty());
            }
            cx.cancel_with(
                crate::types::CancelKind::User,
                Some("unrelated registration survives"),
            );
            assert_eq!(counter.count(), 1);
            cx.clear_cancel_waker(unrelated);
            drop(permit);
            assert!(cx.inner.read().cancel_waker_registrations.is_empty());
        });
    }

    #[test]
    fn write_half_send_mid_write_cancel_uses_explicit_cx_without_ambient_current() {
        future::block_on(async {
            let ws = WebSocket::from_upgraded(
                TestIo::new(vec![]).with_pending_first_write(),
                WebSocketConfig::default(),
            );
            let (_read, mut write) = ws.split();
            let cx = test_cx_with_entropy(Arc::new(FixedEntropy([0x46, 0xD0, 0x1B, 0x0A])));
            assert!(
                Cx::current().is_none(),
                "regression must not rely on ambient Cx::current()"
            );

            let mut send = Box::pin(write.send(&cx, Message::text("cancelled")));
            let waker = std::task::Waker::noop().clone();
            let mut poll_cx = Context::from_waker(&waker);

            assert!(
                matches!(send.as_mut().poll(&mut poll_cx), Poll::Pending),
                "first split-send poll should park in the transport write"
            );

            cx.set_cancel_requested(true);
            let err = match send.as_mut().poll(&mut poll_cx) {
                Poll::Ready(Err(err)) => err,
                other => panic!("expected cancelled split send error, got {other:?}"), // ubs:ignore - test helper
            };

            assert!(
                matches!(err, WsError::Io(ref e) if e.kind() == io::ErrorKind::Interrupted),
                "expected interrupted split send after explicit Cx cancellation, got {err:?}"
            );
            drop(send);
            let guard = write.shared.lock();
            assert!(
                guard.io.written.is_empty(),
                "cancelled split send must not commit bytes after a pending write"
            );
            assert!(
                guard.write_buf.is_empty(),
                "cancelled split send must not leave buffered bytes when no write committed"
            );
        });
    }

    #[test]
    fn cancelled_write_half_send_after_partial_write_preserves_tail_for_later_flush() {
        future::block_on(async {
            let ws = WebSocket::from_upgraded(
                TestIo::new(vec![]).with_partial_first_write(1),
                WebSocketConfig::default(),
            );
            let (read, mut write) = ws.split();
            let cx = test_cx_with_entropy(Arc::new(FixedEntropy([0xAA, 0xBB, 0xCC, 0xDD])));

            {
                let mut shared = read.shared.lock();
                shared.codec = FrameCodec::server();
            }

            let cancelled = Message::text("cancelled");
            let delivered = Message::text("delivered");
            let expected_cancelled = encode_server_frame(Frame::from(cancelled.clone()));
            let expected_delivered = encode_server_frame(Frame::from(delivered.clone()));
            let mut cancelled_send = Box::pin(write.send(&cx, cancelled));
            let waker = std::task::Waker::noop().clone();
            let mut poll_cx = Context::from_waker(&waker);

            assert!(
                matches!(cancelled_send.as_mut().poll(&mut poll_cx), Poll::Pending),
                "send should park after partially writing the frame and buffering the tail"
            );
            drop(cancelled_send);

            assert!(
                !read.shared.lock().write_buf.is_empty(),
                "after any byte hits the wire, the unwritten split-send tail must stay durable"
            );

            write
                .send(&cx, delivered)
                .await
                .expect("later sends should flush the durable tail first");

            let ws = read.reunite(write).expect("split halves must reunite");
            let mut expected = expected_cancelled;
            expected.extend_from_slice(&expected_delivered);
            assert_eq!(
                ws.io.written, expected,
                "later flushes must preserve the partially written split frame before the next send"
            );
        });
    }

    #[test]
    fn close_after_cancelled_recv_flushes_pending_echo_without_second_close() {
        future::block_on(async {
            let peer_close = encode_server_frame(Frame::close(Some(1000), None));
            let ws = WebSocket::from_upgraded(
                TestIo::new(peer_close).with_pending_first_write(),
                WebSocketConfig::default(),
            );
            let (mut read, mut write) = ws.split();
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0x46, 0xD0, 0x1B, 0x0A]));
            let cx = test_cx_with_entropy(Arc::clone(&entropy));
            let mut cancelled_recv = Box::pin(read.recv(&cx));
            let waker = std::task::Waker::noop().clone();
            let mut poll_cx = Context::from_waker(&waker);

            assert!(
                matches!(cancelled_recv.as_mut().poll(&mut poll_cx), Poll::Pending),
                "recv should park while flushing the echoed close response"
            );
            drop(cancelled_recv);

            assert_eq!(
                write.close_state(),
                CloseState::CloseReceived,
                "cancelling recv mid-flush must leave the echoed response pending"
            );
            assert!(
                !read.shared.lock().write_buf.is_empty(),
                "the echoed close response should stay buffered for a later retry"
            );

            write
                .close(CloseReason::going_away())
                .await
                .expect("close should finish the pending echoed response");

            assert_eq!(
                write.close_state(),
                CloseState::Closed,
                "finishing the pending echoed response must close the handshake"
            );

            let ws = read.reunite(write).expect("split halves must reunite");
            assert_eq!(
                ws.io.written,
                encode_client_frame_with_entropy(&Frame::close(Some(1000), None), entropy.as_ref()),
                "retrying close after a cancelled recv must not append a second close frame"
            );
        });
    }

    #[test]
    fn read_half_mid_read_cancel_uses_explicit_cx_without_ambient_current() {
        future::block_on(async {
            let read_data = encode_server_frame(Frame::binary(vec![1, 2, 3]));
            let ws = WebSocket::from_upgraded(
                TestIo::new(read_data).with_pending_first_read(),
                WebSocketConfig::default(),
            );
            let (mut read, write) = ws.split();
            let cx = test_cx_with_entropy(Arc::new(FixedEntropy([0x46, 0xD0, 0x1B, 0x0A])));
            assert!(
                Cx::current().is_none(),
                "regression must not rely on ambient Cx::current()"
            );

            let mut recv = Box::pin(read.recv(&cx));
            let waker = std::task::Waker::noop().clone();
            let mut poll_cx = Context::from_waker(&waker);

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
            {
                let shared = read.shared.lock();
                assert_eq!(
                    shared.io.read_pos, 0,
                    "cancelled split recv must not consume transport bytes after pending read"
                );
                assert!(
                    shared.read_buf.is_empty(),
                    "cancelled split recv must not seed the websocket read buffer"
                );
            }
            drop(write);
        });
    }

    #[test]
    fn close_after_partially_flushed_echo_preserves_tail_without_second_close() {
        future::block_on(async {
            let peer_close = encode_server_frame(Frame::close(Some(1000), None));
            let ws = WebSocket::from_upgraded(
                TestIo::new(peer_close).with_partial_first_write(1),
                WebSocketConfig::default(),
            );
            let (mut read, mut write) = ws.split();
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0x46, 0xD0, 0x1B, 0x0A]));
            let cx = test_cx_with_entropy(Arc::clone(&entropy));
            let expected =
                encode_client_frame_with_entropy(&Frame::close(Some(1000), None), entropy.as_ref());
            let mut cancelled_recv = Box::pin(read.recv(&cx));
            let waker = std::task::Waker::noop().clone();
            let mut poll_cx = Context::from_waker(&waker);

            assert!(
                matches!(cancelled_recv.as_mut().poll(&mut poll_cx), Poll::Pending),
                "recv should park after partially flushing the echoed close response"
            );
            drop(cancelled_recv);

            assert_eq!(
                write.close_state(),
                CloseState::CloseReceived,
                "partial close-response flush must leave the split handshake awaiting completion"
            );
            assert!(
                !read.shared.lock().write_buf.is_empty(),
                "the echoed split close tail must remain buffered after partial I/O"
            );
            {
                let guard = read.shared.lock();
                assert_eq!(
                    guard.io.written,
                    expected[..1].to_vec(),
                    "only the committed close-frame prefix should hit the transport before retry"
                );
            }

            write
                .close(CloseReason::going_away())
                .await
                .expect("close should flush the durable close tail");

            assert_eq!(
                write.close_state(),
                CloseState::Closed,
                "completing the echoed close tail must close the split handshake"
            );

            let ws = read.reunite(write).expect("split halves must reunite");
            assert_eq!(
                ws.io.written, expected,
                "retrying close must finish the original split close frame without appending a second one"
            );
        });
    }

    #[test]
    fn close_retry_flushes_partially_sent_close_without_second_close() {
        future::block_on(async {
            let ws = WebSocket::from_upgraded(
                TestIo::new(vec![]).with_partial_first_write(1),
                WebSocketConfig::default(),
            );
            let (_read, mut write) = ws.split();
            let entropy: Arc<dyn EntropySource> = Arc::new(FixedEntropy([0xD2, 0x10, 0x44, 0x9A]));
            write.shared.lock().entropy = Arc::clone(&entropy);
            let expected =
                encode_client_frame_with_entropy(&Frame::close(Some(1001), None), entropy.as_ref());
            let mut cancelled_close = Box::pin(write.close(CloseReason::going_away()));
            let waker = std::task::Waker::noop().clone();
            let mut poll_cx = Context::from_waker(&waker);

            assert!(
                matches!(cancelled_close.as_mut().poll(&mut poll_cx), Poll::Pending),
                "close should park after partially writing the initiated split close frame"
            );
            drop(cancelled_close);

            assert_eq!(
                write.close_state(),
                CloseState::CloseSent,
                "cancelling split close after a partial write must keep the handshake in CloseSent"
            );
            assert!(
                !write.shared.lock().write_buf.is_empty(),
                "the initiated split close tail must remain buffered after partial I/O"
            );
            {
                let guard = write.shared.lock();
                assert_eq!(
                    guard.io.written,
                    expected[..1].to_vec(),
                    "only the committed split close prefix should hit the transport before retry"
                );
            }

            write
                .close(CloseReason::going_away())
                .await
                .expect("retrying close should flush the durable split close tail");

            assert_eq!(
                write.close_state(),
                CloseState::CloseSent,
                "split close retries should flush bytes without inventing a peer response"
            );
            {
                let guard = write.shared.lock();
                assert_eq!(
                    guard.io.written, expected,
                    "retrying split close must finish the original close frame without appending another"
                );
            }
        });
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
    fn split_send_uses_cx_entropy_for_client_masking() {
        future::block_on(async {
            let ws = WebSocket::from_upgraded(TestIo::new(vec![]), WebSocketConfig::default());
            let (read, mut write) = ws.split();
            let cx = test_cx_with_entropy(Arc::new(FixedEntropy([0xDE, 0xAD, 0xBE, 0xEF])));

            write
                .send(&cx, Message::text("hi"))
                .await
                .expect("split send should succeed");

            let ws = read.reunite(write).expect("split halves must reunite");
            assert_eq!(&ws.io.written[2..6], &[0xDE, 0xAD, 0xBE, 0xEF]);
        });
    }

    /// RFC 6455 §7.1.7: once message assembly fails the connection, the read
    /// half must not deliver the data frame buffered behind the violation.
    #[test]
    fn read_half_processes_no_data_after_an_assembly_failure() {
        future::block_on(async {
            let mut wire = encode_server_frame(Frame::text(Bytes::from_static(&[0xFF, 0xFE])));
            wire.extend(encode_server_frame(Frame::text(Bytes::from_static(
                b"after-failure",
            ))));
            let ws = WebSocket::from_upgraded(TestIo::new(wire), WebSocketConfig::default());
            let (mut read, _write) = ws.split();
            let cx = test_cx_with_entropy(Arc::new(FixedEntropy([1, 2, 3, 4])));

            let first = read.recv(&cx).await;
            assert!(
                first.is_err(),
                "invalid UTF-8 text must fail the connection, got {first:?}"
            );
            let second = read.recv(&cx).await;
            assert!(
                !matches!(second, Ok(Some(Message::Text(_) | Message::Binary(_)))),
                "data after the failure must not be delivered, got {second:?}"
            );
        });
    }
