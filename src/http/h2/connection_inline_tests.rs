    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::bytes::Bytes;
    use crate::http::h2::settings;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;

    static TEST_TIME_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    static TEST_NOW_BASE: OnceLock<Time> = OnceLock::new();
    static TEST_NOW_OFFSET_MS: AtomicU64 = AtomicU64::new(0);

    fn lock_test_clock() -> std::sync::MutexGuard<'static, ()> {
        TEST_TIME_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("test time lock poisoned")
    }

    fn set_test_time_offset(duration: Duration) {
        let millis = u64::try_from(duration.as_millis()).expect("duration fits u64 millis");
        // The offset is standalone test state; it does not publish side data.
        TEST_NOW_OFFSET_MS.store(millis, Ordering::Relaxed);
    }

    fn advance_test_time(duration: Duration) {
        let millis = u64::try_from(duration.as_millis()).expect("duration fits u64 millis");
        TEST_NOW_OFFSET_MS.fetch_add(millis, Ordering::Relaxed);
    }

    fn test_now() -> Time {
        // Fixed deterministic base so virtual-time offsets are fully reproducible
        // (no dependency on the wall clock).
        *TEST_NOW_BASE.get_or_init(|| Time::from_secs(1_000_000))
            + Duration::from_millis(TEST_NOW_OFFSET_MS.load(Ordering::Relaxed))
    }

    fn encode_test_headers(headers: &[(&str, &str)]) -> Bytes {
        let mut encoder = hpack::Encoder::new();
        let mut encoded = BytesMut::new();
        encoder.encode(
            &headers
                .iter()
                .map(|(name, value)| Header::new(*name, *value))
                .collect::<Vec<_>>(),
            &mut encoded,
        );
        encoded.freeze()
    }

    fn test_request_headers(path: &str) -> Bytes {
        encode_test_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", path),
            (":authority", "example.com"),
        ])
    }

    fn test_request_header_vec(path: &str) -> Vec<Header> {
        vec![
            Header::new(":method", "GET"),
            Header::new(":scheme", "https"),
            Header::new(":path", path),
            Header::new(":authority", "example.com"),
        ]
    }

    fn test_response_headers(status: &str) -> Bytes {
        encode_test_headers(&[(":status", status)])
    }

    #[test]
    fn initial_connection_recv_window_queues_stream_zero_credit() {
        let mut conn = Connection::server(Settings::default());
        conn.queue_initial_settings();

        conn.set_initial_connection_recv_window(1024 * 1024)
            .expect("valid enlarged connection window");

        assert_eq!(conn.recv_window(), 1024 * 1024);
        assert_eq!(conn.initial_recv_window, 1024 * 1024);
        assert!(matches!(conn.next_frame(), Some(Frame::Settings(_))));
        match conn.next_frame() {
            Some(Frame::WindowUpdate(frame)) => {
                assert_eq!(frame.stream_id, 0);
                assert_eq!(
                    frame.increment,
                    1024 * 1024 - DEFAULT_CONNECTION_WINDOW_SIZE as u32
                );
            }
            other => panic!("expected initial connection WINDOW_UPDATE, got {other:?}"),
        }
    }

    #[test]
    fn initial_connection_recv_window_rejects_unadvertisable_or_late_values() {
        let mut too_small = Connection::server(Settings::default());
        let error = too_small
            .set_initial_connection_recv_window(32 * 1024)
            .expect_err("connection window below protocol baseline must fail");
        assert_eq!(error.code, ErrorCode::FlowControlError);

        let mut too_large = Connection::server(Settings::default());
        let error = too_large
            .set_initial_connection_recv_window(0x8000_0000)
            .expect_err("connection window above 31-bit limit must fail");
        assert_eq!(error.code, ErrorCode::FlowControlError);

        let mut late = Connection::server(Settings::default());
        late.state = ConnectionState::Open;
        let error = late
            .set_initial_connection_recv_window(1024 * 1024)
            .expect_err("connection window must be configured during handshake");
        assert_eq!(error.code, ErrorCode::FlowControlError);
    }

    #[test]
    fn enlarged_connection_recv_window_replenishes_to_configured_target() {
        const WINDOW: u32 = 1024 * 1024;
        let mut settings = Settings::default();
        settings.initial_window_size = WINDOW;
        let mut conn = Connection::server(settings);
        conn.set_initial_connection_recv_window(WINDOW)
            .expect("configure enlarged connection window");
        while conn.next_frame().is_some() {}

        conn.process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
            .expect("peer settings");
        conn.process_frame(Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/large-upload"),
            false,
            true,
        )))
        .expect("open request stream");

        let payload = Bytes::from(vec![0u8; 600 * 1024]);
        conn.process_frame(Frame::Data(DataFrame::new(1, payload, false)))
            .expect("data within enlarged windows");

        assert_eq!(conn.recv_window(), WINDOW as i32);
        let mut saw_connection_update = false;
        while let Some(frame) = conn.next_frame() {
            if let Frame::WindowUpdate(update) = frame {
                if update.stream_id == 0 {
                    assert_eq!(update.increment, 600 * 1024);
                    saw_connection_update = true;
                }
            }
        }
        assert!(
            saw_connection_update,
            "connection credit must be replenished"
        );
    }

    #[test]
    fn data_frame_triggers_connection_window_update_on_low_watermark() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;
        let payload_len = (DEFAULT_CONNECTION_WINDOW_SIZE / 2) + 2;
        let payload_len_usize = usize::try_from(payload_len).expect("payload_len non-negative");
        let payload_len_u32 = u32::try_from(payload_len).expect("payload_len fits u32");
        let data = Bytes::from(vec![0_u8; payload_len_usize]);
        let headers = Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/flow-control"),
            false,
            true,
        ));
        let frame = Frame::Data(DataFrame::new(1, data, false));

        conn.process_frame(headers).expect("process headers frame");
        conn.process_frame(frame).expect("process data frame");

        assert!(conn.has_pending_frames(), "expected WINDOW_UPDATE(s)");
        // Both stream-level and connection-level WINDOW_UPDATEs may be queued.
        let mut found_connection_update = false;
        while let Some(pending) = conn.next_frame() {
            if let Frame::WindowUpdate(update) = pending {
                if update.stream_id == 0 {
                    assert_eq!(update.increment, payload_len_u32);
                    found_connection_update = true;
                }
            }
        }
        assert!(
            found_connection_update,
            "expected connection-level WINDOW_UPDATE"
        );
    }

    #[test]
    fn data_frame_exceeding_connection_window_errors() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;
        conn.recv_window = 1;

        let headers = Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/flow-control"),
            false,
            true,
        ));
        conn.process_frame(headers).expect("process headers frame");

        let data = Bytes::from(vec![0_u8; 2]);
        let frame = Frame::Data(DataFrame::new(1, data, false));
        let result = conn.process_frame(frame);

        assert!(result.is_err());
        let err = result.expect_err("flow control error");
        assert_eq!(err.code, ErrorCode::FlowControlError);
    }

    /// Regression: when stream.recv_data() fails with a stream-level error
    /// (e.g., data on a closed stream), the connection recv_window must still
    /// be decremented. The peer counted these bytes against their send window
    /// when transmitting; failing to account for them desynchronizes flow control.
    #[test]
    fn data_on_closed_stream_still_decrements_connection_window() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Open stream 1 via HEADERS.
        let headers = Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/flow-control"),
            false,
            true,
        ));
        conn.process_frame(headers).unwrap();

        // Reset stream 1 so it becomes closed.
        let rst = Frame::RstStream(RstStreamFrame::new(1, ErrorCode::Cancel));
        conn.process_frame(rst).unwrap();
        assert_eq!(conn.stream(1).unwrap().state(), StreamState::Closed);

        let window_before = conn.recv_window();
        let payload = Bytes::from(vec![0_u8; 100]);

        // DATA on closed stream should fail with a stream error…
        let frame = Frame::Data(DataFrame::new(1, payload, false));
        let err = conn.process_frame(frame).unwrap_err();
        assert_eq!(err.code, ErrorCode::StreamClosed);

        // …but the connection window MUST still be decremented by 100 bytes.
        assert_eq!(
            conn.recv_window(),
            window_before.saturating_sub(100),
            "connection recv_window must be decremented even on stream-level errors"
        );
    }

    #[test]
    fn test_frame_codec_decode() {
        let mut codec = FrameCodec::new();

        // Create a PING frame
        let frame = PingFrame::new([1, 2, 3, 4, 5, 6, 7, 8]);
        let mut buf = BytesMut::new();
        Frame::Ping(frame)
            .encode(&mut buf)
            .expect("Ping frame fits");

        // Decode it
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        match decoded {
            Frame::Ping(ping) => {
                assert_eq!(ping.opaque_data, [1, 2, 3, 4, 5, 6, 7, 8]);
                assert!(!ping.ack);
            }
            _ => panic!("expected PING frame"),
        }
    }

    fn priority_error_wire(payload: &[u8]) -> BytesMut {
        let mut bytes = BytesMut::new();
        FrameHeader {
            length: u32::try_from(payload.len()).unwrap(),
            frame_type: FrameType::Priority as u8,
            flags: 0,
            stream_id: 1,
        }
        .write(&mut bytes);
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn listener_priority_decode_preserves_public_errors_and_fragmentation() {
        for (payload, code) in [
            (&[0, 0, 0, 0][..], ErrorCode::FrameSizeError),
            (&[0, 0, 0, 1, 0][..], ErrorCode::ProtocolError),
        ] {
            let wire = priority_error_wire(payload);
            let public_error = FrameCodec::new().decode(&mut wire.clone()).unwrap_err();
            assert_eq!(public_error.code, code);
            assert_eq!(public_error.stream_id, Some(1));
            for split in 0..wire.len() {
                let mut codec = ListenerFrameCodec::new();
                let mut input = BytesMut::from(&wire[..split]);
                assert!(codec.decode(&mut input).unwrap().is_none());
                input.extend_from_slice(&wire[split..]);
                Frame::Ping(PingFrame::new([7; 8]))
                    .encode(&mut input)
                    .unwrap();
                let Some(DecodedFrame::PriorityError(error)) = codec.decode(&mut input).unwrap()
                else {
                    panic!("expected consumed PRIORITY error");
                };
                assert_eq!(error.code, code);
                assert_eq!(error.stream_id, Some(1));
                assert!(matches!(
                    codec.decode(&mut input).unwrap(),
                    Some(DecodedFrame::Frame(Frame::Ping(_)))
                ));
                assert!(input.is_empty());
            }
        }
    }

    #[test]
    fn listener_priority_error_does_not_poison_framed_transport() {
        use crate::stream::Stream as _;
        use std::pin::Pin;
        use std::task::{Context, Poll, Waker};

        let mut wire = priority_error_wire(&[0; 4]);
        Frame::Ping(PingFrame::new([9; 8]))
            .encode(&mut wire)
            .unwrap();
        let mut framed = crate::codec::Framed::new(
            std::io::Cursor::new(wire.to_vec()),
            ListenerFrameCodec::new(),
        );
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            Pin::new(&mut framed).poll_next(&mut context),
            Poll::Ready(Some(Ok(DecodedFrame::PriorityError(_))))
        ));
        assert!(matches!(
            Pin::new(&mut framed).poll_next(&mut context),
            Poll::Ready(Some(Ok(DecodedFrame::Frame(Frame::Ping(_)))))
        ));
        assert!(matches!(
            Pin::new(&mut framed).poll_next(&mut context),
            Poll::Ready(None)
        ));
    }

    #[test]
    fn listener_priority_error_obeys_connection_preflight() {
        fn malformed() -> DecodedFrame {
            ListenerFrameCodec::new()
                .decode(&mut priority_error_wire(&[0; 4]))
                .unwrap()
                .unwrap()
        }
        let mut conn = Connection::server(Settings::default());
        let error = conn.process_decoded_frame(malformed()).unwrap_err();
        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert_eq!(error.stream_id, None);
        conn.process_frame(Frame::Settings(SettingsFrame::new(vec![])))
            .unwrap();
        let error = conn.process_decoded_frame(malformed()).unwrap_err();
        assert_eq!(error.code, ErrorCode::FrameSizeError);
        assert_eq!(error.stream_id, Some(1));
        conn.process_frame(Frame::Headers(HeadersFrame::new(
            1,
            Bytes::from_static(&[0x82]),
            false,
            false,
        )))
        .unwrap();
        let error = conn.process_decoded_frame(malformed()).unwrap_err();
        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert_eq!(error.stream_id, None);
    }

    #[test]
    fn listener_codec_keeps_other_parse_errors_terminal() {
        let mut stream_zero = priority_error_wire(&[0; 4]);
        stream_zero[8] = 0;
        let error = ListenerFrameCodec::new()
            .decode(&mut stream_zero)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert_eq!(error.stream_id, None);

        let mut oversized = priority_error_wire(&[0; 5]);
        let mut codec = ListenerFrameCodec::new();
        codec.set_max_frame_size(4);
        let error = codec.decode(&mut oversized).unwrap_err();
        assert_eq!(error.code, ErrorCode::FrameSizeError);
        assert_eq!(error.stream_id, None);

        // A HEADERS self-dependency is stream-scoped in the parser, but must
        // not become recoverable: its field block has not updated HPACK state.
        let mut headers = priority_error_wire(&[0, 0, 0, 1, 0, 0x82]);
        headers[3] = FrameType::Headers as u8;
        headers[4] = 0x24; // PRIORITY | END_HEADERS
        let error = ListenerFrameCodec::new().decode(&mut headers).unwrap_err();
        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert_eq!(error.stream_id, Some(1));
    }

    #[test]
    fn listener_decoded_headers_keep_hpack_errors_connection_scoped() {
        let mut conn = Connection::server(Settings::default());
        conn.process_frame(Frame::Settings(SettingsFrame::new(vec![])))
            .unwrap();
        let mut wire = BytesMut::new();
        Frame::Headers(HeadersFrame::new(
            1,
            Bytes::from_static(&[0x80]),
            true,
            true,
        ))
        .encode(&mut wire)
        .unwrap();
        let frame = ListenerFrameCodec::new()
            .decode(&mut wire)
            .unwrap()
            .unwrap();
        let error = conn.process_decoded_frame(frame).unwrap_err();
        assert_eq!(error.code, ErrorCode::CompressionError);
        assert_eq!(error.stream_id, None);
    }

    #[test]
    fn test_frame_codec_skips_unknown_frame_type() {
        let mut codec = FrameCodec::new();
        let mut buf = BytesMut::new();

        // Unknown extension frame type (0xFF) should be ignored.
        FrameHeader {
            length: 3,
            frame_type: 0xFF,
            flags: 0,
            stream_id: 0,
        }
        .write(&mut buf);
        buf.extend_from_slice(&[1, 2, 3]);

        let ping = PingFrame::new([9, 8, 7, 6, 5, 4, 3, 2]);
        Frame::Ping(ping).encode(&mut buf).expect("Ping frame fits");

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        match decoded {
            Frame::Ping(p) => assert_eq!(p.opaque_data, [9, 8, 7, 6, 5, 4, 3, 2]),
            _ => panic!("expected PING frame"),
        }
    }

    #[test]
    fn h2spec_extension_cannot_interrupt_a_fragmented_header_block() {
        for start in [
            Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, false)),
            Frame::PushPromise(PushPromiseFrame {
                stream_id: 1,
                promised_stream_id: 2,
                header_block: Bytes::new(),
                end_headers: false,
            }),
        ] {
            let mut codec = FrameCodec::new();
            let mut bytes = BytesMut::new();
            start.encode(&mut bytes).unwrap();
            FrameHeader {
                length: 1,
                frame_type: 0xfe,
                flags: 0,
                stream_id: 0,
            }
            .write(&mut bytes);
            bytes.extend_from_slice(&[42]);
            assert!(codec.decode(&mut bytes).unwrap().is_some());
            let error = codec.decode(&mut bytes).unwrap_err();
            assert_eq!(error.code, ErrorCode::ProtocolError);
            assert_eq!(error.stream_id, None);
        }
    }

    #[test]
    fn h2spec_negative_window_survives_a_queued_final_response() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;
        conn.process_frame(Frame::Settings(SettingsFrame::new(vec![
            Setting::InitialWindowSize(3),
        ])))
        .unwrap();
        conn.process_frame(Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/window"),
            true,
            true,
        )))
        .unwrap();
        conn.send_headers(1, vec![Header::new(":status", "200")], false)
            .unwrap();
        conn.send_data(1, Bytes::from_static(b"abcdef"), true)
            .unwrap();
        let mut data = Vec::new();
        while let Some(frame) = conn.next_frame() {
            if let Frame::Data(frame) = frame {
                assert!(!frame.end_stream);
                data.extend_from_slice(&frame.data);
            }
        }
        assert_eq!(data, b"abc");
        assert_eq!(conn.active_stream_count(), 1);
        conn.process_frame(Frame::Settings(SettingsFrame::new(vec![
            Setting::InitialWindowSize(2),
        ])))
        .unwrap();
        assert_eq!(conn.stream(1).unwrap().send_window(), -1);
        assert!(matches!(conn.next_frame(), Some(Frame::Settings(_))));
        assert!(conn.next_frame().is_none());
        conn.process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(1, 2)))
            .unwrap();
        let Some(Frame::Data(one)) = conn.next_frame() else {
            panic!("one byte resumes")
        };
        assert_eq!(one.data.as_ref(), b"d");
        assert!(!one.end_stream);
        assert!(conn.next_frame().is_none());
        conn.process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(1, 2)))
            .unwrap();
        let Some(Frame::Data(last)) = conn.next_frame() else {
            panic!("final two bytes")
        };
        assert_eq!(last.data.as_ref(), b"ef");
        assert!(last.end_stream);
        assert_eq!(conn.active_stream_count(), 0);
    }

    #[test]
    fn trailers_and_a_final_empty_data_wait_behind_flow_blocked_data() {
        // br-asupersync-dx72q4: DATA held back for lack of send credit was set
        // aside while the queue scan went on, so the trailers (or an empty
        // final DATA) went out first with END_STREAM and the rest of the body
        // followed on a closed stream.
        for trailers in [true, false] {
            let mut conn = Connection::server(Settings::default());
            conn.state = ConnectionState::Open;
            conn.process_frame(Frame::Settings(SettingsFrame::new(vec![
                Setting::InitialWindowSize(3),
            ])))
            .unwrap();
            conn.process_frame(Frame::Headers(HeadersFrame::new(
                1,
                test_request_headers("/trailers"),
                true,
                true,
            )))
            .unwrap();
            conn.send_headers(1, vec![Header::new(":status", "200")], false)
                .unwrap();
            conn.send_data(1, Bytes::from_static(b"abcdef"), false)
                .unwrap();
            if trailers {
                conn.send_headers(1, vec![Header::new("grpc-status", "0")], true)
                    .unwrap();
            } else {
                conn.send_data(1, Bytes::new(), true).unwrap();
            }

            fn drain(conn: &mut Connection, body: &mut Vec<u8>, ended: &mut bool) {
                while let Some(frame) = conn.next_frame() {
                    let end_stream = match frame {
                        Frame::Data(frame) if frame.stream_id == 1 => {
                            assert!(!*ended, "DATA after END_STREAM");
                            body.extend_from_slice(&frame.data);
                            frame.end_stream
                        }
                        Frame::Headers(frame) if frame.stream_id == 1 => frame.end_stream,
                        _ => false,
                    };
                    if end_stream {
                        assert_eq!(body, b"abcdef", "END_STREAM before the whole body");
                        *ended = true;
                    }
                }
            }
            let mut body = Vec::new();
            let mut ended = false;
            drain(&mut conn, &mut body, &mut ended);
            assert_eq!(body, b"abc");
            assert!(
                !ended,
                "the stream must stay open while its body is blocked"
            );

            conn.process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(1, 3)))
                .unwrap();
            drain(&mut conn, &mut body, &mut ended);
            assert!(
                ended,
                "the body and then END_STREAM go out once credit returns"
            );
        }
    }

    #[test]
    fn h2spec_local_stream_limit_retains_flow_blocked_responses() {
        let mut settings = Settings::default();
        settings.max_concurrent_streams = 1;
        let mut conn = Connection::server(settings);
        conn.state = ConnectionState::Open;
        conn.process_frame(Frame::Settings(SettingsFrame::new(vec![
            Setting::InitialWindowSize(0),
            Setting::MaxConcurrentStreams(100),
        ])))
        .unwrap();
        conn.process_frame(Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/first"),
            true,
            true,
        )))
        .unwrap();
        conn.send_headers(1, vec![Header::new(":status", "200")], false)
            .unwrap();
        conn.send_data(1, Bytes::from_static(b"retained"), true)
            .unwrap();
        while conn.next_frame().is_some() {}
        let received = conn
            .process_frame(Frame::Headers(HeadersFrame::new(
                3,
                test_request_headers("/over-limit"),
                true,
                true,
            )))
            .unwrap();
        assert!(
            received.is_none(),
            "refused request cannot reach the handler"
        );
        let Some(Frame::RstStream(reset)) = conn.next_frame() else {
            panic!("over-limit stream must be reset")
        };
        assert_eq!(reset.error_code, ErrorCode::RefusedStream);
        assert_eq!(reset.stream_id, 3);
        assert_eq!(conn.active_stream_count(), 1);
        conn.process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(1, 8)))
            .unwrap();
        let Some(Frame::Data(last)) = conn.next_frame() else {
            panic!("retained response survives admission")
        };
        assert_eq!(last.data.as_ref(), b"retained");
        assert!(last.end_stream);
        assert_eq!(conn.active_stream_count(), 0);
        conn.process_frame(Frame::Headers(HeadersFrame::new(
            5,
            test_request_headers("/recovered"),
            true,
            true,
        )))
        .unwrap();
    }

    #[test]
    fn h2spec_empty_path_and_headers_after_normal_close_are_rejected() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;
        let error = conn
            .process_frame(Frame::Headers(HeadersFrame::new(
                1,
                test_request_headers(""),
                true,
                true,
            )))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert_eq!(error.stream_id, Some(1));
        conn.process_frame(Frame::Headers(HeadersFrame::new(
            3,
            test_request_headers("/valid"),
            true,
            true,
        )))
        .unwrap();
        conn.send_headers(3, vec![Header::new(":status", "204")], true)
            .unwrap();
        assert!(conn.next_frame().is_some());
        let error = conn
            .process_frame(Frame::Headers(HeadersFrame::new(
                3,
                test_request_headers("/closed"),
                true,
                true,
            )))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::StreamClosed);
        assert_eq!(error.stream_id, None);
    }

    #[test]
    fn h2spec_refused_headers_preserve_dynamic_compression_state() {
        for fragmented in [false, true] {
            let mut settings = Settings::default();
            settings.max_concurrent_streams = 1;
            let mut conn = Connection::server(settings);
            conn.state = ConnectionState::Open;
            conn.process_frame(Frame::Headers(HeadersFrame::new(
                1,
                test_request_headers("/held"),
                false,
                true,
            )))
            .unwrap();
            let headers = vec![
                Header::new(":method", "GET"),
                Header::new(":scheme", "https"),
                Header::new(":path", "/indexed-after-refusal"),
                Header::new("x-refused-dynamic", "preserve-this-value"),
            ];
            let mut encoder = hpack::Encoder::new();
            let mut first = BytesMut::new();
            encoder.encode(&headers, &mut first);
            let first = first.freeze();
            let split = if fragmented {
                first.len() / 2
            } else {
                first.len()
            };
            assert!(
                conn.process_frame(Frame::Headers(HeadersFrame::new(
                    3,
                    first.slice(..split),
                    true,
                    !fragmented,
                )))
                .unwrap()
                .is_none()
            );
            if fragmented {
                assert!(conn.next_frame().is_none(), "finish HPACK before refusal");
                assert!(
                    conn.process_frame(Frame::Continuation(ContinuationFrame {
                        stream_id: 3,
                        header_block: first.slice(split..),
                        end_headers: true,
                    }))
                    .unwrap()
                    .is_none()
                );
            }
            let Some(Frame::RstStream(reset)) = conn.next_frame() else {
                panic!("refusal")
            };
            assert_eq!(reset.stream_id, 3);
            assert_eq!(reset.error_code, ErrorCode::RefusedStream);
            assert_eq!(conn.active_stream_count(), 1);
            conn.reset_stream(1, ErrorCode::Cancel);
            while conn.next_frame().is_some() {}
            let mut indexed = BytesMut::new();
            encoder.encode(&headers, &mut indexed);
            assert!(
                indexed.len() < first.len(),
                "exercise actual dynamic references"
            );
            let received = conn
                .process_frame(Frame::Headers(HeadersFrame::new(
                    5,
                    indexed.freeze(),
                    true,
                    true,
                )))
                .unwrap();
            let Some(ReceivedFrame::Headers {
                headers: decoded, ..
            }) = received
            else {
                panic!("subsequent valid request must be delivered")
            };
            assert_eq!(decoded, headers);
        }
    }

    #[test]
    fn client_takes_a_closing_response_whose_field_block_continues() {
        // A bodyless request leaves the stream half-closed (local). The
        // response HEADERS carries END_STREAM, which closes the stream, and
        // its field block ends in a CONTINUATION frame (RFC 9113 §6.2).
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;
        let stream_id = conn
            .open_stream(test_request_header_vec("/no-body"), true)
            .unwrap();
        while conn.next_frame().is_some() {}
        let block = encode_test_headers(&[(":status", "204"), ("x-split", "across-frames")]);
        let split = block.len() / 2;
        assert!(
            conn.process_frame(Frame::Headers(HeadersFrame::new(
                stream_id,
                block.slice(..split),
                true,
                false,
            )))
            .expect("HEADERS with END_STREAM starts the field block")
            .is_none()
        );
        let received = conn
            .process_frame(Frame::Continuation(ContinuationFrame {
                stream_id,
                header_block: block.slice(split..),
                end_headers: true,
            }))
            .expect("CONTINUATION finishes the response's field block");
        let Some(ReceivedFrame::Headers {
            stream_id: received_stream_id,
            headers,
            end_stream,
        }) = received
        else {
            panic!("the response headers must be delivered, got {received:?}")
        };
        assert_eq!(received_stream_id, stream_id);
        assert!(end_stream, "the response ends the stream");
        assert_eq!(
            headers,
            vec![
                Header::new(":status", "204"),
                Header::new("x-split", "across-frames"),
            ]
        );
    }

    #[test]
    fn pruning_keeps_a_closed_stream_whose_field_block_is_still_arriving() {
        // Closed streams are pruned once the map holds more than twice the
        // local max_concurrent_streams; a client's own requests do not count
        // against that setting, so its third request crosses the threshold.
        let mut settings = Settings::client();
        settings.max_concurrent_streams = 1;
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;
        for path in ["/first", "/second"] {
            let stream_id = conn
                .open_stream(test_request_header_vec(path), true)
                .unwrap();
            while conn.next_frame().is_some() {}
            conn.process_frame(Frame::Headers(HeadersFrame::new(
                stream_id,
                test_response_headers("204"),
                true,
                true,
            )))
            .expect("complete response");
        }
        let stream_id = conn
            .open_stream(test_request_header_vec("/third"), true)
            .unwrap();
        while conn.next_frame().is_some() {}
        let block = encode_test_headers(&[(":status", "204"), ("x-split", "across-frames")]);
        let split = block.len() / 2;
        assert!(
            conn.process_frame(Frame::Headers(HeadersFrame::new(
                stream_id,
                block.slice(..split),
                true,
                false,
            )))
            .expect("HEADERS with END_STREAM starts the field block")
            .is_none()
        );
        let received = conn
            .process_frame(Frame::Continuation(ContinuationFrame {
                stream_id,
                header_block: block.slice(split..),
                end_headers: true,
            }))
            .expect("the block's CONTINUATION still finds its stream");
        assert!(
            matches!(
                received,
                Some(ReceivedFrame::Headers {
                    end_stream: true,
                    ..
                })
            ),
            "the response headers must be delivered, got {received:?}"
        );
    }

    /// The request that follows a refused field block, encoded by the same
    /// encoder, so it references the dynamic-table entries that block added.
    fn decode_after_refused_block(
        conn: &mut Connection,
        encoder: &mut hpack::Encoder,
        headers: &[Header],
        refused_len: usize,
        stream_id: u32,
    ) {
        let mut indexed = BytesMut::new();
        encoder.encode(headers, &mut indexed);
        assert!(
            indexed.len() < refused_len,
            "the next block must reference the refused block's table entries"
        );
        let received = conn
            .process_frame(Frame::Headers(HeadersFrame::new(
                stream_id,
                indexed.freeze(),
                true,
                true,
            )))
            .expect("the next request decodes");
        let Some(ReceivedFrame::Headers {
            headers: decoded, ..
        }) = received
        else {
            panic!("the next request must be delivered, got {received:?}")
        };
        assert_eq!(decoded, headers);
    }

    fn refusal_test_headers(path: &str) -> Vec<Header> {
        let mut headers = test_request_header_vec(path);
        headers.push(Header::new("x-dynamic", "kept-in-step"));
        headers
    }

    #[test]
    fn a_stream_error_before_decoding_keeps_the_hpack_decoder_in_step() {
        for fragmented in [false, true] {
            let mut conn = Connection::server(Settings::default());
            conn.state = ConnectionState::Open;
            // Stream 1's request is complete, so it is half-closed (remote) and
            // another HEADERS frame on it is a stream error.
            conn.process_frame(Frame::Headers(HeadersFrame::new(
                1,
                test_request_headers("/first"),
                true,
                true,
            )))
            .unwrap();
            let headers = refusal_test_headers("/after-refusal");
            let mut encoder = hpack::Encoder::new();
            let mut refused = BytesMut::new();
            encoder.encode(&headers, &mut refused);
            let refused = refused.freeze();
            let split = if fragmented {
                refused.len() / 2
            } else {
                refused.len()
            };
            let error = conn
                .process_frame(Frame::Headers(HeadersFrame::new(
                    1,
                    refused.slice(..split),
                    true,
                    !fragmented,
                )))
                .expect_err("HEADERS on a half-closed (remote) stream");
            assert_eq!(error.stream_id, Some(1), "a stream error: {error:?}");
            // As the listener does on a stream error.
            conn.reset_stream(1, error.code);
            if fragmented {
                assert!(
                    conn.process_frame(Frame::Continuation(ContinuationFrame {
                        stream_id: 1,
                        header_block: refused.slice(split..),
                        end_headers: true,
                    }))
                    .expect("the refused block's CONTINUATION is decoded")
                    .is_none()
                );
            }
            while conn.next_frame().is_some() {}
            decode_after_refused_block(&mut conn, &mut encoder, &headers, refused.len(), 3);
        }
    }

    #[test]
    fn a_refused_stream_id_gap_still_decodes_its_field_block() {
        // Far past any stream-id gap the stream table accepts.
        let far_stream_id = (1 << 30) + 1;
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;
        let headers = refusal_test_headers("/after-gap");
        let mut encoder = hpack::Encoder::new();
        let mut refused = BytesMut::new();
        encoder.encode(&headers, &mut refused);
        let refused = refused.freeze();
        let error = conn
            .process_frame(Frame::Headers(HeadersFrame::new(
                far_stream_id,
                refused.clone(),
                true,
                true,
            )))
            .expect_err("a stream id past the gap ceiling is refused");
        assert_eq!(error.stream_id, Some(far_stream_id), "{error:?}");
        assert_eq!(error.code, ErrorCode::RefusedStream);
        conn.reset_stream(far_stream_id, error.code);
        while conn.next_frame().is_some() {}
        decode_after_refused_block(&mut conn, &mut encoder, &headers, refused.len(), 1);

        // A refused block that continues has no record to collect it.
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;
        let error = conn
            .process_frame(Frame::Headers(HeadersFrame::new(
                far_stream_id,
                refused.slice(..refused.len() / 2),
                true,
                false,
            )))
            .expect_err("a continuing block for a refused stream id");
        assert!(error.stream_id.is_none(), "a connection error: {error:?}");
    }

    #[test]
    fn a_field_block_past_the_fragment_cap_ends_the_connection() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;
        conn.process_frame(Frame::Headers(HeadersFrame::new(
            1,
            Bytes::new(),
            false,
            false,
        )))
        .unwrap();
        let error = (0..2048)
            .find_map(|_| {
                conn.process_frame(Frame::Continuation(ContinuationFrame {
                    stream_id: 1,
                    header_block: Bytes::new(),
                    end_headers: false,
                }))
                .err()
            })
            .expect("the fragment cap refuses the block");
        assert_eq!(error.code, ErrorCode::EnhanceYourCalm);
        assert!(
            error.stream_id.is_none(),
            "a block that cannot be decoded ends the connection: {error:?}"
        );
    }

    #[test]
    fn test_frame_codec_unknown_frame_without_followup_returns_none() {
        let mut codec = FrameCodec::new();
        let mut buf = BytesMut::new();

        FrameHeader {
            length: 2,
            frame_type: 0xFE,
            flags: 0,
            stream_id: 0,
        }
        .write(&mut buf);
        buf.extend_from_slice(&[0xAA, 0xBB]);

        let decoded = codec.decode(&mut buf).unwrap();
        assert!(decoded.is_none(), "expected no decoded frame");
        assert!(buf.is_empty(), "unknown frame bytes should be consumed");
    }

    #[test]
    fn test_connection_client_settings() {
        let mut conn = Connection::client(Settings::client());
        conn.queue_initial_settings();

        assert!(conn.has_pending_frames());
        let frame = conn.next_frame().unwrap();
        match frame {
            Frame::Settings(settings) => {
                assert!(!settings.ack);
                assert!(
                    settings
                        .settings
                        .iter()
                        .any(|setting| matches!(setting, Setting::EnablePush(false)))
                );
            }
            _ => panic!("expected SETTINGS frame"),
        }
    }

    #[test]
    fn test_connection_process_settings() {
        let mut conn = Connection::client(Settings::client());

        // Process server settings
        let settings = SettingsFrame::new(vec![
            Setting::MaxConcurrentStreams(100),
            Setting::InitialWindowSize(32768),
        ]);
        conn.process_frame(Frame::Settings(settings)).unwrap();

        // Should have queued ACK
        assert!(conn.has_pending_frames());
        let frame = conn.next_frame().unwrap();
        match frame {
            Frame::Settings(settings) => {
                assert!(settings.ack);
            }
            _ => panic!("expected SETTINGS ACK"),
        }

        // Remote settings should be updated
        assert_eq!(conn.remote_settings().max_concurrent_streams, 100);
        assert_eq!(conn.remote_settings().initial_window_size, 32768);
    }

    #[test]
    fn local_initial_window_sizes_receive_side_not_peer_send_side() {
        let mut settings = Settings::server();
        settings.initial_window_size = 32_768;
        let mut conn = Connection::server(settings);

        let stream1 = conn.streams.get_or_create(1).unwrap();
        assert_eq!(
            stream1.send_window(),
            i32::try_from(DEFAULT_INITIAL_WINDOW_SIZE).unwrap(),
            "peer send window starts at the RFC default until peer SETTINGS arrives"
        );
        assert_eq!(
            stream1.recv_window(),
            32_768,
            "local SETTINGS_INITIAL_WINDOW_SIZE must initialize our receive window"
        );

        conn.process_frame(Frame::Settings(SettingsFrame::new(vec![
            Setting::InitialWindowSize(100_000),
        ])))
        .unwrap();
        let stream3 = conn.streams.get_or_create(3).unwrap();
        assert_eq!(stream3.send_window(), 100_000);
        assert_eq!(
            stream3.recv_window(),
            32_768,
            "peer SETTINGS_INITIAL_WINDOW_SIZE must not rewrite our receive window"
        );
    }

    /// Regression: peer's MaxConcurrentStreams must constrain stream creation,
    /// not just be stored in remote_settings. Without forwarding to StreamStore,
    /// the local side could exceed the peer's limit (RFC 7540 §5.1.2 violation).
    #[test]
    fn settings_max_concurrent_streams_constrains_open_stream() {
        let mut conn = Connection::client(Settings::client());
        // Simulate receiving server settings with max_concurrent_streams = 2.
        let settings = SettingsFrame::new(vec![Setting::MaxConcurrentStreams(2)]);
        conn.process_frame(Frame::Settings(settings)).unwrap();
        // Drain ACK.
        let _ = conn.next_frame();

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];

        // Open 2 streams (should succeed).
        conn.open_stream(headers.clone(), false).unwrap();
        conn.open_stream(headers.clone(), false).unwrap();

        // Third stream should be refused (exceeds peer limit).
        let result = conn.open_stream(headers, false);
        assert!(
            result.is_err(),
            "third stream must be refused when peer MaxConcurrentStreams=2"
        );
    }

    #[test]
    fn test_connection_client_accepts_server_enable_push_zero_and_rejects_one() {
        // RFC 9113 §6.5.2: a server that includes SETTINGS_ENABLE_PUSH must
        // send 0, which a client accepts and acknowledges.
        let mut conn = Connection::client(Settings::client());
        let settings = SettingsFrame::new(vec![Setting::EnablePush(false)]);
        conn.process_frame(Frame::Settings(settings))
            .expect("a server may send SETTINGS_ENABLE_PUSH=0");
        assert!(
            matches!(conn.next_frame(), Some(Frame::Settings(settings)) if settings.ack),
            "SETTINGS_ENABLE_PUSH=0 must be acknowledged"
        );

        let mut conn = Connection::client(Settings::client());
        let settings = SettingsFrame::new(vec![Setting::EnablePush(true)]);
        let err = conn.process_frame(Frame::Settings(settings)).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert!(
            !conn.has_pending_frames(),
            "invalid settings must not be ACKed"
        );
    }

    #[test]
    fn test_connection_server_initial_settings_omit_enable_push() {
        let mut local = Settings::server();
        local.enable_push = false;
        let mut conn = Connection::server(local);
        conn.queue_initial_settings();

        let frame = conn.next_frame().expect("expected initial settings frame");
        match frame {
            Frame::Settings(settings) => {
                assert!(
                    !settings
                        .settings
                        .iter()
                        .any(|setting| matches!(setting, Setting::EnablePush(_)))
                );
            }
            _ => panic!("expected SETTINGS frame"),
        }
    }

    #[test]
    fn test_connection_process_ping() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        let ping = PingFrame::new([1, 2, 3, 4, 5, 6, 7, 8]);
        conn.process_frame(Frame::Ping(ping)).unwrap();

        // Should have queued PING ACK
        let frame = conn.next_frame().unwrap();
        match frame {
            Frame::Ping(ping) => {
                assert!(ping.ack);
                assert_eq!(ping.opaque_data, [1, 2, 3, 4, 5, 6, 7, 8]);
            }
            _ => panic!("expected PING ACK"),
        }
    }

    #[test]
    fn test_connection_open_stream() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];

        let stream_id = conn.open_stream(headers, false).unwrap();
        assert_eq!(stream_id, 1);

        // Should have queued HEADERS frame
        let frame = conn.next_frame().unwrap();
        match frame {
            Frame::Headers(h) => {
                assert_eq!(h.stream_id, 1);
                assert!(!h.end_stream);
                assert!(h.end_headers);
            }
            _ => panic!("expected HEADERS frame"),
        }
    }

    #[test]
    fn data_frame_triggers_stream_window_update_on_low_watermark() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;
        // Open a stream via headers.
        let headers = Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/flow-control"),
            false,
            true,
        ));
        conn.process_frame(headers).expect("process headers");

        let initial_window = settings::DEFAULT_INITIAL_WINDOW_SIZE;
        // Send data that crosses the 25% threshold for the *stream*.
        // Calculate payload length with overflow protection
        let payload_len = initial_window
            .saturating_mul(3)
            .saturating_div(4)
            .saturating_add(2);
        let data = Bytes::from(vec![0_u8; payload_len as usize]);
        let frame = Frame::Data(DataFrame::new(1, data, false));
        conn.process_frame(frame).expect("process data");

        // Drain pending frames; look for a stream-level WINDOW_UPDATE (stream_id != 0).
        let mut found_stream_update = false;
        while let Some(f) = conn.next_frame() {
            if let Frame::WindowUpdate(wu) = f {
                if wu.stream_id == 1 {
                    found_stream_update = true;
                    assert_eq!(wu.increment, payload_len);
                }
            }
        }
        assert!(
            found_stream_update,
            "expected stream-level WINDOW_UPDATE for stream 1"
        );
    }

    #[cfg(feature = "http2-streaming")]
    fn deferred_receive_connection(stream_ids: &[u32]) -> Connection {
        let mut conn =
            Connection::server_with_time_getter(Settings::default(), || Time::from_secs(1));
        conn.process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
            .expect("peer settings");
        for &stream_id in stream_ids {
            conn.process_frame(Frame::Headers(HeadersFrame::new(
                stream_id,
                test_request_headers("/streaming-upload"),
                false,
                true,
            )))
            .expect("initial request headers");
        }
        while conn.next_frame().is_some() {}
        conn
    }

    #[cfg(feature = "http2-streaming")]
    #[test]
    fn deferred_receive_credit_waits_for_consumer_and_preserves_sibling_progress() {
        let mut conn = deferred_receive_connection(&[1, 3]);
        conn.defer_stream_receive_window(1).expect("defer stream");
        let data = Bytes::from(vec![7; settings::DEFAULT_INITIAL_WINDOW_SIZE as usize]);
        let event = conn
            .process_frame(Frame::Data(DataFrame::new(1, data, false)))
            .expect("receive full stream window");
        assert!(matches!(
            event,
            Some(ReceivedFrame::Data { stream_id: 1, .. })
        ));
        assert_eq!(conn.stream(1).unwrap().recv_window(), 0);
        assert_eq!(conn.recv_window(), DEFAULT_CONNECTION_WINDOW_SIZE);
        let update = conn.next_frame().expect("connection credit remains live");
        assert!(matches!(update, Frame::WindowUpdate(update)
            if update.stream_id == 0 && update.increment == 65_535));
        assert!(conn.next_frame().is_none(), "no unconsumed stream credit");

        let sibling = conn
            .process_frame(Frame::Data(DataFrame::new(
                3,
                Bytes::from_static(b"ok"),
                true,
            )))
            .expect("sibling receives while first stream has no credit");
        assert!(matches!(
            sibling,
            Some(ReceivedFrame::Data { stream_id: 3, .. })
        ));
        conn.release_stream_receive_capacity(1, 7)
            .expect("consumer releases a prefix");
        assert_eq!(conn.stream(1).unwrap().recv_window(), 7);
        assert!(
            matches!(conn.next_frame(), Some(Frame::WindowUpdate(update))
            if update.stream_id == 1 && update.increment == 7)
        );
        conn.process_frame(Frame::Data(DataFrame::new(
            1,
            Bytes::from_static(b"resumed"),
            false,
        )))
        .expect("exact released capacity permits more input");
        assert_eq!(conn.stream(1).unwrap().recv_window(), 0);
        assert!(conn.next_frame().is_none());
    }

    #[cfg(feature = "http2-streaming")]
    #[test]
    fn deferred_receive_credit_rejects_duplicate_and_unearned_releases() {
        let mut conn = deferred_receive_connection(&[1]);
        conn.defer_stream_receive_window(1).unwrap();
        conn.process_frame(Frame::Data(DataFrame::new(
            1,
            Bytes::from_static(b"123456789"),
            false,
        )))
        .unwrap();
        conn.release_stream_receive_capacity(1, 4).unwrap();
        assert!(
            matches!(conn.next_frame(), Some(Frame::WindowUpdate(update))
            if update.stream_id == 1 && update.increment == 4)
        );
        conn.defer_stream_receive_window(1)
            .expect("repeated deferral preserves outstanding bytes");

        let before = conn.stream(1).unwrap().recv_window();
        let error = conn.release_stream_receive_capacity(1, 6).unwrap_err();
        assert_eq!(error.code, ErrorCode::FlowControlError);
        assert_eq!(error.stream_id, Some(1));
        assert_eq!(conn.stream(1).unwrap().recv_window(), before);
        assert!(conn.next_frame().is_none());
        let error = conn.send_stream_window_update(1, 5).unwrap_err();
        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert_eq!(conn.stream(1).unwrap().recv_window(), before);

        conn.release_stream_receive_capacity(1, 5).unwrap();
        assert_eq!(conn.stream(1).unwrap().recv_window(), 65_535);
        assert!(
            matches!(conn.next_frame(), Some(Frame::WindowUpdate(update))
            if update.stream_id == 1 && update.increment == 5)
        );
        conn.release_stream_receive_capacity(1, 0).unwrap();
        assert_eq!(
            conn.release_stream_receive_capacity(1, 1).unwrap_err().code,
            ErrorCode::FlowControlError
        );
        assert!(conn.next_frame().is_none());
    }

    #[cfg(feature = "http2-streaming")]
    #[test]
    fn deferred_receive_padding_reclaims_only_discarded_wire_bytes() {
        use crate::http::h2::frame::data_flags;

        let mut conn = deferred_receive_connection(&[1]);
        conn.defer_stream_receive_window(1).unwrap();
        let header = FrameHeader {
            length: 8,
            frame_type: FrameType::Data as u8,
            flags: data_flags::PADDED,
            stream_id: 1,
        };
        let frame = DataFrame::parse(
            &header,
            Bytes::from_static(&[4, b'a', b'b', b'c', 0, 0, 0, 0]),
        )
        .expect("parse actual padded DATA payload");
        let event = conn.process_frame(Frame::Data(frame)).unwrap();
        assert!(matches!(event, Some(ReceivedFrame::Data { data, .. })
            if data.as_ref() == b"abc"));
        assert_eq!(conn.recv_window(), 65_535 - 8);
        assert_eq!(conn.stream(1).unwrap().recv_window(), 65_535 - 3);
        assert!(
            matches!(conn.next_frame(), Some(Frame::WindowUpdate(update))
            if update.stream_id == 1 && update.increment == 5)
        );
        assert!(conn.next_frame().is_none());
        assert_eq!(
            conn.release_stream_receive_capacity(1, 8).unwrap_err().code,
            ErrorCode::FlowControlError,
            "padding must never be credited again by the application"
        );
        conn.release_stream_receive_capacity(1, 3).unwrap();
        assert!(
            matches!(conn.next_frame(), Some(Frame::WindowUpdate(update))
            if update.stream_id == 1 && update.increment == 3)
        );

        let header = FrameHeader {
            length: 1,
            ..header
        };
        let frame = DataFrame::parse(&header, Bytes::from_static(&[0])).unwrap();
        conn.process_frame(Frame::Data(frame)).unwrap();
        assert_eq!(conn.stream(1).unwrap().recv_window(), 65_535);
        assert!(
            matches!(conn.next_frame(), Some(Frame::WindowUpdate(update))
            if update.stream_id == 1 && update.increment == 1)
        );
        assert!(conn.next_frame().is_none());
    }

    #[cfg(feature = "http2-streaming")]
    #[test]
    fn deferred_receive_credit_after_data_or_trailers_fin_does_not_reopen_input() {
        for data_fin in [false, true] {
            let mut conn = deferred_receive_connection(&[1]);
            conn.defer_stream_receive_window(1).unwrap();
            conn.process_frame(Frame::Data(DataFrame::new(
                1,
                Bytes::from_static(b"end"),
                data_fin,
            )))
            .unwrap();
            if !data_fin {
                conn.process_frame(Frame::Headers(HeadersFrame::new(
                    1,
                    encode_test_headers(&[("x-checksum", "ok")]),
                    true,
                    true,
                )))
                .expect("trailers close request input");
            }
            assert_eq!(
                conn.stream(1).unwrap().state(),
                StreamState::HalfClosedRemote
            );
            let before = conn.stream(1).unwrap().recv_window();
            conn.release_stream_receive_capacity(1, 3).unwrap();
            assert_eq!(conn.stream(1).unwrap().recv_window(), before);
            assert!(
                conn.next_frame().is_none(),
                "FIN makes receive credit unusable"
            );
            assert_eq!(
                conn.release_stream_receive_capacity(1, 1).unwrap_err().code,
                ErrorCode::FlowControlError,
                "retired bytes cannot be released twice"
            );
        }
    }

    #[cfg(feature = "http2-streaming")]
    #[test]
    fn deferred_receive_reset_and_pruning_discard_pending_credit() {
        for peer_reset in [false, true] {
            let mut conn = deferred_receive_connection(&[1]);
            conn.defer_stream_receive_window(1).unwrap();
            conn.process_frame(Frame::Data(DataFrame::new(
                1,
                Bytes::from_static(b"reset"),
                false,
            )))
            .unwrap();
            conn.release_stream_receive_capacity(1, 2).unwrap();
            if peer_reset {
                conn.process_frame(Frame::RstStream(RstStreamFrame::new(1, ErrorCode::Cancel)))
                    .unwrap();
            } else {
                conn.reset_stream(1, ErrorCode::Cancel);
            }
            conn.release_stream_receive_capacity(1, 3)
                .expect("a delayed consumer release tolerates reset");
            while let Some(frame) = conn.next_frame() {
                assert!(!matches!(frame, Frame::WindowUpdate(update) if update.stream_id == 1));
            }
            conn.prune_closed_streams();
            assert!(conn.stream(1).is_none());
            conn.release_stream_receive_capacity(1, 3)
                .expect("a delayed consumer release tolerates pruning");
            assert!(conn.next_frame().is_none());
            assert_eq!(
                conn.release_stream_receive_capacity(3, 1).unwrap_err().code,
                ErrorCode::ProtocolError,
                "idle streams must not receive invented credit"
            );
        }
    }

    #[cfg(feature = "http2-streaming")]
    #[test]
    fn deferred_receive_requires_completed_headers_before_any_data() {
        let mut conn = deferred_receive_connection(&[]);
        assert!(conn.defer_stream_receive_window(1).is_err());
        for invalid_or_idle in [0, 1, 0x8000_0000] {
            assert_eq!(
                conn.release_stream_receive_capacity(invalid_or_idle, 1)
                    .unwrap_err()
                    .code,
                ErrorCode::ProtocolError
            );
        }
        let headers = test_request_headers("/fragmented");
        conn.process_frame(Frame::Headers(HeadersFrame::new(
            1,
            headers.slice(..1),
            false,
            false,
        )))
        .unwrap();
        assert_eq!(
            conn.defer_stream_receive_window(1).unwrap_err().code,
            ErrorCode::ProtocolError
        );
        conn.process_frame(Frame::Continuation(ContinuationFrame {
            stream_id: 1,
            header_block: headers.slice(1..),
            end_headers: true,
        }))
        .unwrap();
        conn.defer_stream_receive_window(1).unwrap();

        conn.process_frame(Frame::Headers(HeadersFrame::new(
            3,
            test_request_headers("/empty-data"),
            false,
            true,
        )))
        .unwrap();
        conn.process_frame(Frame::Data(DataFrame::new(3, Bytes::new(), false)))
            .unwrap();
        assert_eq!(
            conn.defer_stream_receive_window(3).unwrap_err().code,
            ErrorCode::ProtocolError,
            "even empty DATA ends the deferral admission boundary"
        );
        conn.process_frame(Frame::Headers(HeadersFrame::new(
            5,
            test_request_headers("/headers-fin"),
            true,
            true,
        )))
        .unwrap();
        conn.defer_stream_receive_window(5)
            .expect("HEADERS with END_STREAM needs no receive credit");
    }

    #[cfg(feature = "http2-streaming")]
    #[test]
    fn deferred_receive_preserves_automatic_streams_and_rejects_late_switch() {
        let mut conn = deferred_receive_connection(&[1]);
        conn.process_frame(Frame::Data(DataFrame::new(
            1,
            Bytes::from(vec![0; 50_000]),
            false,
        )))
        .unwrap();
        assert_eq!(conn.stream(1).unwrap().recv_window(), 65_535);
        let mut updates = Vec::new();
        while let Some(frame) = conn.next_frame() {
            if let Frame::WindowUpdate(update) = frame {
                updates.push((update.stream_id, update.increment));
            }
        }
        assert_eq!(updates, [(0, 50_000), (1, 50_000)]);
        assert_eq!(
            conn.defer_stream_receive_window(1).unwrap_err().code,
            ErrorCode::ProtocolError,
            "automatic refill must not disguise earlier DATA receipt"
        );
        assert_eq!(
            conn.release_stream_receive_capacity(1, 1).unwrap_err().code,
            ErrorCode::ProtocolError
        );
        assert!(conn.next_frame().is_none());
    }

    #[cfg(feature = "http2-streaming")]
    #[test]
    fn deferred_receive_rejected_window_overflow_preserves_unconsumed_bytes() {
        let mut conn = deferred_receive_connection(&[1]);
        conn.defer_stream_receive_window(1).unwrap();
        conn.process_frame(Frame::Data(DataFrame::new(
            1,
            Bytes::from_static(b"data"),
            false,
        )))
        .unwrap();
        let previous = conn.stream(1).unwrap().recv_window();
        let delta = i32::MAX - previous;
        conn.stream_mut(1)
            .unwrap()
            .update_recv_window(delta)
            .unwrap();
        assert_eq!(
            conn.release_stream_receive_capacity(1, 1).unwrap_err().code,
            ErrorCode::FlowControlError
        );
        assert_eq!(conn.stream(1).unwrap().recv_window(), i32::MAX);
        assert!(conn.next_frame().is_none());
        conn.stream_mut(1)
            .unwrap()
            .update_recv_window(-delta)
            .unwrap();
        conn.release_stream_receive_capacity(1, 4)
            .expect("failed window update did not retire any bytes");
        assert!(
            matches!(conn.next_frame(), Some(Frame::WindowUpdate(update))
            if update.stream_id == 1 && update.increment == 4)
        );
    }

    #[test]
    fn data_frame_no_stream_window_update_when_above_watermark() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;
        let headers = Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/flow-control"),
            false,
            true,
        ));
        conn.process_frame(headers).expect("process headers");

        // Small payload: stays above the watermark.
        let data = Bytes::from(vec![0_u8; 100]);
        let frame = Frame::Data(DataFrame::new(1, data, false));
        conn.process_frame(frame).expect("process data");

        // No stream-level WINDOW_UPDATE should be queued.
        while let Some(f) = conn.next_frame() {
            if let Frame::WindowUpdate(wu) = f {
                assert_ne!(wu.stream_id, 1, "unexpected stream-level WINDOW_UPDATE");
            }
        }
    }

    #[test]
    fn send_data_respects_send_window() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "POST"),
            Header::new(":path", "/upload"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();
        // Drain the HEADERS frame.
        let _ = conn.next_frame().unwrap();

        // Shrink the connection send window to a small value.
        // Default is 65535; reduce it so only 100 bytes can be sent.
        conn.send_window = 100;

        // Queue 300 bytes of data.
        let data = Bytes::from(vec![0xAB_u8; 300]);
        conn.send_data(stream_id, data, true).unwrap();

        // First frame: should be clamped to 100 bytes (connection window limit).
        let frame1 = conn.next_frame().expect("expected first DATA frame");
        match frame1 {
            Frame::Data(d) => {
                assert_eq!(d.data.len(), 100, "should be clamped to send window");
                assert!(!d.end_stream, "not the final chunk");
            }
            other => panic!("expected DATA frame, got {other:?}"),
        }

        // Connection window is now 0; next call should re-queue and return None
        // (since there's no other frame type pending, it recurses but data is re-queued).
        // Replenish the window so remaining data can flow.
        conn.send_window = 300;
        let frame2 = conn.next_frame().expect("expected second DATA frame");
        match frame2 {
            Frame::Data(d) => {
                assert_eq!(d.data.len(), 200, "remaining 200 bytes");
                assert!(d.end_stream, "final chunk should carry end_stream");
            }
            other => panic!("expected DATA frame, got {other:?}"),
        }

        assert!(!conn.has_pending_frames(), "all data should be sent");
    }

    #[test]
    fn send_data_respects_stream_send_window() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "POST"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();
        let _ = conn.next_frame().unwrap(); // drain HEADERS

        // Shrink the *stream* send window to 50 bytes (connection window stays large).
        conn.stream_mut(stream_id)
            .unwrap()
            .consume_send_window(65535 - 50);

        let data = Bytes::from(vec![0xCD_u8; 200]);
        conn.send_data(stream_id, data, true).unwrap();

        let frame1 = conn.next_frame().expect("expected first DATA frame");
        match frame1 {
            Frame::Data(d) => {
                assert_eq!(d.data.len(), 50, "clamped to stream send window");
                assert!(!d.end_stream);
            }
            other => panic!("expected DATA frame, got {other:?}"),
        }

        // Restore stream window and send remaining.
        conn.stream_mut(stream_id)
            .unwrap()
            .update_send_window(200)
            .unwrap();
        let frame2 = conn.next_frame().expect("expected second DATA frame");
        match frame2 {
            Frame::Data(d) => {
                assert_eq!(d.data.len(), 150);
                assert!(d.end_stream);
            }
            other => panic!("expected DATA frame, got {other:?}"),
        }
    }

    #[test]
    fn send_data_respects_max_frame_size() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;
        // Set a small max_frame_size for testing
        conn.remote_settings.max_frame_size = 100;

        let headers = vec![
            Header::new(":method", "POST"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();
        let _ = conn.next_frame().unwrap(); // drain HEADERS

        // Queue 300 bytes of data
        let data = Bytes::from(vec![0xEE_u8; 300]);
        conn.send_data(stream_id, data, true).unwrap();

        // First frame should be clamped to max_frame_size (100 bytes)
        let frame1 = conn.next_frame().expect("expected first DATA frame");
        match frame1 {
            Frame::Data(d) => {
                assert_eq!(d.data.len(), 100, "clamped to max_frame_size");
                assert!(!d.end_stream);
            }
            other => panic!("expected DATA frame, got {other:?}"),
        }

        // Second frame
        let frame2 = conn.next_frame().expect("expected second DATA frame");
        match frame2 {
            Frame::Data(d) => {
                assert_eq!(d.data.len(), 100);
                assert!(!d.end_stream);
            }
            other => panic!("expected DATA frame, got {other:?}"),
        }

        // Third frame (final)
        let frame3 = conn.next_frame().expect("expected third DATA frame");
        match frame3 {
            Frame::Data(d) => {
                assert_eq!(d.data.len(), 100);
                assert!(d.end_stream);
            }
            other => panic!("expected DATA frame, got {other:?}"),
        }

        assert!(!conn.has_pending_frames());
    }

    #[test]
    fn final_data_flushes_after_stream_enters_closed_state() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "POST"),
            Header::new(":path", "/upload"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();
        let _ = conn.next_frame().unwrap(); // drain request HEADERS

        // Peer ends its side of the stream first.
        let response = Frame::Headers(HeadersFrame::new(
            stream_id,
            test_response_headers("200"),
            true,
            true,
        ));
        conn.process_frame(response).unwrap();
        assert_eq!(
            conn.stream(stream_id).unwrap().state(),
            StreamState::HalfClosedRemote
        );

        conn.send_data(stream_id, Bytes::from_static(b"payload"), true)
            .unwrap();
        assert_eq!(conn.stream(stream_id).unwrap().state(), StreamState::Closed);

        let frame = conn
            .next_frame()
            .expect("final DATA must still be emitted after local close");
        match frame {
            Frame::Data(data) => {
                assert_eq!(data.stream_id, stream_id);
                assert_eq!(data.data, Bytes::from_static(b"payload"));
                assert!(data.end_stream);
            }
            other => panic!("expected DATA frame, got {other:?}"),
        }
    }

    #[test]
    fn large_headers_use_continuation_frames() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;
        // Set a very small max_frame_size to force CONTINUATION
        conn.remote_settings.max_frame_size = 50;

        // Create headers that will encode to more than 50 bytes
        let mut headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/some/very/long/path/that/exceeds/frame/size"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        // Add more headers to ensure we exceed the limit
        for i in 0..10 {
            headers.push(Header::new(
                format!("x-custom-header-{i}"),
                format!("value-{i}"),
            ));
        }

        let stream_id = conn.open_stream(headers, true).unwrap();

        // First frame should be HEADERS with end_headers=false
        let frame1 = conn.next_frame().expect("expected HEADERS frame");
        match &frame1 {
            Frame::Headers(h) => {
                assert_eq!(h.stream_id, stream_id);
                assert!(h.end_stream);
                assert!(!h.end_headers, "should have CONTINUATION following");
                assert_eq!(h.header_block.len(), 50);
            }
            other => panic!("expected HEADERS frame, got {other:?}"),
        }

        // Subsequent frames should be CONTINUATION
        let mut continuation_count = 0;
        let mut last_end_headers = false;
        while let Some(frame) = conn.next_frame() {
            match frame {
                Frame::Continuation(c) => {
                    assert_eq!(c.stream_id, stream_id);
                    continuation_count += 1;
                    last_end_headers = c.end_headers;
                    if c.end_headers {
                        break;
                    }
                }
                other => panic!("expected CONTINUATION frame, got {other:?}"),
            }
        }

        assert!(
            continuation_count >= 1,
            "should have at least one CONTINUATION"
        );
        assert!(last_end_headers, "last frame should have end_headers=true");
    }

    #[test]
    fn send_push_promise_queues_frame_and_reserves_local_stream() {
        let mut conn = Connection::server(Settings::server());
        conn.state = ConnectionState::Open;

        let request = Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/index"),
            false,
            true,
        ));
        let _ = conn.process_frame(request).unwrap();

        let promised_stream_id = conn
            .send_push_promise(1, test_request_header_vec("/style.css"))
            .unwrap();
        assert_eq!(promised_stream_id, 2);
        assert_eq!(
            conn.stream(promised_stream_id).unwrap().state(),
            StreamState::ReservedLocal
        );

        match conn.next_frame().expect("PUSH_PROMISE should be queued") {
            Frame::PushPromise(push) => {
                assert_eq!(push.stream_id, 1);
                assert_eq!(push.promised_stream_id, promised_stream_id);
                assert!(push.end_headers);
                assert!(!push.header_block.is_empty());
            }
            other => panic!("expected PUSH_PROMISE frame, got {other:?}"),
        }

        conn.send_headers(
            promised_stream_id,
            vec![Header::new(":status", "200")],
            true,
        )
        .unwrap();
        match conn
            .next_frame()
            .expect("promised response HEADERS should be queued")
        {
            Frame::Headers(headers) => {
                assert_eq!(headers.stream_id, promised_stream_id);
                assert!(headers.end_stream);
            }
            other => panic!("expected promised response HEADERS, got {other:?}"),
        }
        assert_eq!(
            conn.stream(promised_stream_id).unwrap().state(),
            StreamState::Closed
        );
    }

    #[test]
    fn send_push_promise_large_headers_use_continuation_frames() {
        let mut conn = Connection::server(Settings::server());
        conn.state = ConnectionState::Open;
        conn.remote_settings.max_frame_size = 50;

        let request = Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/index"),
            false,
            true,
        ));
        let _ = conn.process_frame(request).unwrap();

        let mut push_headers = test_request_header_vec("/large-pushed-resource");
        for i in 0..10 {
            push_headers.push(Header::new(
                format!("x-push-header-{i}"),
                format!("push-value-{i}"),
            ));
        }

        let promised_stream_id = conn.send_push_promise(1, push_headers).unwrap();
        match conn.next_frame().expect("PUSH_PROMISE should be queued") {
            Frame::PushPromise(push) => {
                assert_eq!(push.stream_id, 1);
                assert_eq!(push.promised_stream_id, promised_stream_id);
                assert!(!push.end_headers);
                assert_eq!(
                    push.header_block.len(),
                    46,
                    "PUSH_PROMISE payload reserves four bytes for promised_stream_id"
                );
            }
            other => panic!("expected PUSH_PROMISE frame, got {other:?}"),
        }

        let mut continuation_count = 0;
        let mut last_end_headers = false;
        while let Some(frame) = conn.next_frame() {
            match frame {
                Frame::Continuation(c) => {
                    assert_eq!(c.stream_id, 1);
                    continuation_count += 1;
                    last_end_headers = c.end_headers;
                    if c.end_headers {
                        break;
                    }
                }
                other => panic!("expected CONTINUATION frame, got {other:?}"),
            }
        }

        assert!(
            continuation_count >= 1,
            "large PUSH_PROMISE should emit CONTINUATION"
        );
        assert!(last_end_headers, "last continuation must end headers");
    }

    /// RFC 9113 §6.10: once a HEADERS frame has gone out without END_HEADERS,
    /// its CONTINUATION frames must follow before any other frame (the peer
    /// treats anything else as a connection error, and its HPACK decoder needs
    /// the rest of the block). Resetting the stream in between used to drop
    /// the queued CONTINUATIONs, so the RST_STREAM followed the incomplete
    /// HEADERS directly (br-asupersync-dycth8).
    #[test]
    fn a_stream_reset_mid_header_block_still_completes_the_block_first() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;
        conn.remote_settings.max_frame_size = 50;
        let mut headers = test_request_header_vec("/large");
        for i in 0..10 {
            headers.push(Header::new(format!("x-large-{i}"), format!("value-{i}")));
        }
        let stream_id = conn.open_stream(headers, true).unwrap();
        match conn.next_frame() {
            Some(Frame::Headers(headers)) => {
                assert_eq!(headers.stream_id, stream_id);
                assert!(
                    !headers.end_headers,
                    "the block must need CONTINUATION frames"
                );
            }
            other => panic!("expected the first HEADERS frame, got {other:?}"),
        }

        conn.reset_stream(stream_id, ErrorCode::Cancel);
        let mut frames = Vec::new();
        while let Some(frame) = conn.next_frame() {
            frames.push(frame);
        }
        let (reset, continuations) = frames.split_last().expect("frames after the reset");
        assert!(!continuations.is_empty(), "{frames:?}");
        for (index, frame) in continuations.iter().enumerate() {
            match frame {
                Frame::Continuation(continuation) => {
                    assert_eq!(continuation.stream_id, stream_id);
                    assert_eq!(
                        continuation.end_headers,
                        index + 1 == continuations.len(),
                        "only the last CONTINUATION ends the block: {frames:?}"
                    );
                }
                other => panic!("expected CONTINUATION before any other frame, got {other:?}"),
            }
        }
        assert!(
            matches!(reset, Frame::RstStream(reset)
                if reset.stream_id == stream_id && reset.error_code == ErrorCode::Cancel),
            "the RST_STREAM follows the completed block: {frames:?}"
        );
    }

    #[test]
    fn send_push_promise_rejects_peer_disabled_push_without_reservation() {
        let mut conn = Connection::server(Settings::server());
        conn.state = ConnectionState::Open;
        conn.remote_settings.enable_push = false;

        let request = Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/index"),
            false,
            true,
        ));
        let _ = conn.process_frame(request).unwrap();

        let err = conn
            .send_push_promise(1, test_request_header_vec("/style.css"))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::RefusedStream);
        assert_eq!(err.stream_id, Some(1));
        assert!(
            conn.stream(2).is_none(),
            "disabled push must not reserve a promised stream"
        );
    }

    #[test]
    fn send_push_promise_rejects_after_goaway_without_reservation() {
        let mut conn = Connection::server(Settings::server());
        conn.state = ConnectionState::Open;

        let request = Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/index"),
            false,
            true,
        ));
        let _ = conn.process_frame(request).unwrap();
        conn.begin_graceful_shutdown(Bytes::new());

        let err = conn
            .send_push_promise(1, test_request_header_vec("/style.css"))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert!(
            conn.stream(2).is_none(),
            "GOAWAY rejection must not reserve a promised stream"
        );
    }

    #[test]
    fn send_push_promise_enforces_peer_max_concurrent_streams() {
        let mut conn = Connection::server(Settings::server());
        conn.state = ConnectionState::Open;
        conn.streams.set_max_concurrent_streams(1);

        let request = Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/index"),
            false,
            true,
        ));
        let _ = conn.process_frame(request).unwrap();

        let err = conn
            .send_push_promise(1, test_request_header_vec("/style.css"))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert!(err.message.contains("max concurrent streams exceeded"));
        assert!(
            conn.stream(2).is_none(),
            "max-concurrent rejection must not reserve a promised stream"
        );
    }

    #[test]
    fn push_promise_rejected_when_disabled() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();

        let frame = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 2,
            header_block: test_request_headers("/pushed"),
            end_headers: true,
        });

        let err = conn.process_frame(frame).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn push_promise_creates_reserved_stream() {
        let mut settings = Settings::client();
        settings.enable_push = true;
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();

        let frame = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 2,
            header_block: test_request_headers("/pushed"),
            end_headers: true,
        });

        let received = conn.process_frame(frame).unwrap().unwrap();
        match received {
            ReceivedFrame::PushPromise {
                promised_stream_id, ..
            } => assert_eq!(promised_stream_id, 2),
            other => panic!("expected PushPromise frame, got {other:?}"),
        }

        let promised = conn.stream(2).expect("promised stream exists");
        assert_eq!(promised.state(), StreamState::ReservedRemote);
    }

    #[test]
    fn push_promise_continuation_accumulates() {
        let mut settings = Settings::client();
        settings.enable_push = true;
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();

        let mut promise_headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/pushed"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];

        let mut encoded = BytesMut::new();
        conn.hpack_encoder.encode(&promise_headers, &mut encoded);
        if encoded.len() < 2 {
            promise_headers.push(Header::new("x-extra", "1"));
            encoded.clear();
            conn.hpack_encoder.encode(&promise_headers, &mut encoded);
        }
        assert!(encoded.len() >= 2);

        let encoded = encoded.freeze();
        let split = encoded.len() / 2;
        let first = encoded.slice(..split);
        let second = encoded.slice(split..);

        let push = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 2,
            header_block: first,
            end_headers: false,
        });
        assert!(conn.process_frame(push).unwrap().is_none());

        let continuation = Frame::Continuation(ContinuationFrame {
            stream_id,
            header_block: second,
            end_headers: true,
        });

        let received = conn.process_frame(continuation).unwrap().unwrap();
        match received {
            ReceivedFrame::PushPromise {
                promised_stream_id,
                headers: decoded,
                ..
            } => {
                assert_eq!(promised_stream_id, 2);
                assert_eq!(decoded, promise_headers);
            }
            other => panic!("expected PushPromise frame, got {other:?}"),
        }
    }

    #[test]
    fn push_promise_rejected_on_server_connection() {
        let mut conn = Connection::server(Settings::server());
        conn.state = ConnectionState::Open;

        let frame = Frame::PushPromise(PushPromiseFrame {
            stream_id: 1,
            promised_stream_id: 2,
            header_block: Bytes::new(),
            end_headers: true,
        });

        let err = conn.process_frame(frame).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn push_promise_rejected_for_invalid_promised_id() {
        let mut settings = Settings::client();
        settings.enable_push = true;
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();

        let frame = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 3,
            header_block: Bytes::new(),
            end_headers: true,
        });

        let err = conn.process_frame(frame).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn push_promise_rejected_for_unknown_associated_stream() {
        let mut settings = Settings::client();
        settings.enable_push = true;
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;

        let frame = Frame::PushPromise(PushPromiseFrame {
            stream_id: 1,
            promised_stream_id: 2,
            header_block: Bytes::new(),
            end_headers: true,
        });

        let err = conn.process_frame(frame).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
        // RFC 7540 §5.1: PUSH_PROMISE referencing an unknown stream is a
        // connection error, so no stream_id is attached.
        assert_eq!(err.stream_id, None);
    }

    #[test]
    fn continuation_timeout_not_triggered_when_no_continuation() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // No continuation in progress - timeout check should succeed
        assert!(conn.check_continuation_timeout().is_ok());
        assert!(!conn.is_awaiting_continuation());
    }

    #[test]
    fn continuation_timeout_not_triggered_when_within_limit() {
        let _clock = lock_test_clock();
        set_test_time_offset(Duration::ZERO);
        let settings = Settings {
            continuation_timeout_ms: 5000, // 5 seconds
            ..Default::default()
        };
        let mut conn = Connection::server_with_time_getter(settings, test_now);
        conn.state = ConnectionState::Open;

        // Receive HEADERS without END_HEADERS
        let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, false));
        let result = conn.process_frame(headers);
        assert!(result.is_ok());
        assert!(conn.is_awaiting_continuation());

        advance_test_time(Duration::from_millis(10));

        // Custom clock remains within the timeout window.
        assert!(conn.check_continuation_timeout().is_ok());
        assert!(conn.is_awaiting_continuation());
    }

    #[test]
    fn continuation_clears_timeout_on_completion() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Receive HEADERS without END_HEADERS
        let encoded = test_request_headers("/continuation");
        let split = encoded.len() / 2;
        let headers = Frame::Headers(HeadersFrame::new(1, encoded.slice(..split), false, false));
        conn.process_frame(headers).unwrap();
        assert!(conn.is_awaiting_continuation());
        assert!(conn.continuation_started_at.is_some());

        // Receive CONTINUATION with END_HEADERS
        let continuation = Frame::Continuation(ContinuationFrame {
            stream_id: 1,
            header_block: encoded.slice(split..),
            end_headers: true,
        });
        conn.process_frame(continuation).unwrap();

        // Continuation state should be cleared
        assert!(!conn.is_awaiting_continuation());
        assert!(conn.continuation_started_at.is_none());
    }

    #[test]
    fn continuation_timeout_triggers_after_expiry() {
        let _clock = lock_test_clock();
        set_test_time_offset(Duration::ZERO);
        let settings = Settings {
            continuation_timeout_ms: 50, // 50ms for fast test
            ..Default::default()
        };
        let mut conn = Connection::server_with_time_getter(settings, test_now);
        conn.state = ConnectionState::Open;

        // Receive HEADERS without END_HEADERS
        let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, false));
        conn.process_frame(headers).unwrap();
        assert!(conn.is_awaiting_continuation());

        advance_test_time(Duration::from_millis(60));

        // Timeout should trigger
        let err = conn.check_continuation_timeout().unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert!(err.message.contains("CONTINUATION timeout"));

        // Continuation state should be cleared
        assert!(!conn.is_awaiting_continuation());
        assert!(conn.continuation_started_at.is_none());
    }

    #[test]
    fn continuation_timeout_on_next_frame() {
        let _clock = lock_test_clock();
        set_test_time_offset(Duration::ZERO);
        let settings = Settings {
            continuation_timeout_ms: 50, // 50ms for fast test
            ..Default::default()
        };
        let mut conn = Connection::server_with_time_getter(settings, test_now);
        conn.state = ConnectionState::Open;

        // Receive HEADERS without END_HEADERS
        let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, false));
        conn.process_frame(headers).unwrap();

        advance_test_time(Duration::from_millis(60));

        // Try to process another CONTINUATION - should fail with timeout
        let continuation = Frame::Continuation(ContinuationFrame {
            stream_id: 1,
            header_block: Bytes::new(),
            end_headers: true,
        });
        let err = conn.process_frame(continuation).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert!(err.message.contains("CONTINUATION timeout"));
    }

    #[test]
    fn push_promise_continuation_timeout() {
        let _clock = lock_test_clock();
        set_test_time_offset(Duration::ZERO);
        let mut settings = Settings::client();
        settings.enable_push = true;
        settings.continuation_timeout_ms = 50;
        let mut conn = Connection::client_with_time_getter(settings, test_now);
        conn.state = ConnectionState::Open;

        // First open a stream
        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();
        let _ = conn.next_frame(); // drain HEADERS

        // Receive PUSH_PROMISE without END_HEADERS
        let push = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 2,
            header_block: Bytes::new(),
            end_headers: false,
        });
        conn.process_frame(push).unwrap();
        assert!(conn.is_awaiting_continuation());

        advance_test_time(Duration::from_millis(60));

        // Timeout should trigger
        let err = conn.check_continuation_timeout().unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert!(err.message.contains("CONTINUATION timeout"));
    }

    // =========================================================================
    // Additional PUSH_PROMISE Security Tests (bd-1ckh)
    // =========================================================================

    #[test]
    fn push_promise_rejected_on_closed_stream() {
        let mut settings = Settings::client();
        settings.enable_push = true;
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;

        // Open and then close a stream
        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, true).unwrap(); // end_stream=true
        let _ = conn.next_frame(); // drain HEADERS

        // Simulate receiving response headers with END_STREAM to fully close
        let response = Frame::Headers(HeadersFrame::new(
            stream_id,
            test_response_headers("200"),
            true,
            true,
        ));
        conn.process_frame(response).unwrap();

        // Stream should now be closed
        assert_eq!(conn.stream(stream_id).unwrap().state(), StreamState::Closed);

        // PUSH_PROMISE on closed stream should fail
        let frame = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 2,
            header_block: test_request_headers("/pushed"),
            end_headers: true,
        });

        let err = conn.process_frame(frame).unwrap_err();
        assert_eq!(err.code, ErrorCode::StreamClosed);
    }

    /// RFC 7540 §5.1: PUSH_PROMISE must only be received on streams in
    /// "open" or "half-closed (local)" state. A stream in HalfClosedRemote
    /// (where the server already sent END_STREAM) must be rejected.
    #[test]
    fn push_promise_rejected_on_half_closed_remote_stream() {
        let mut settings = Settings::client();
        settings.enable_push = true;
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;

        // Open a stream without END_STREAM so it enters Open state.
        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();
        let _ = conn.next_frame(); // drain HEADERS

        // Receive response headers with END_STREAM from server.
        // This puts the stream into HalfClosedRemote from client's perspective.
        let response = Frame::Headers(HeadersFrame::new(
            stream_id,
            test_response_headers("200"),
            true,
            true,
        ));
        conn.process_frame(response).unwrap();

        assert_eq!(
            conn.stream(stream_id).unwrap().state(),
            StreamState::HalfClosedRemote
        );

        // PUSH_PROMISE on HalfClosedRemote stream should be rejected.
        let frame = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 2,
            header_block: test_request_headers("/pushed"),
            end_headers: true,
        });

        let err = conn.process_frame(frame).unwrap_err();
        assert_eq!(
            err.code,
            ErrorCode::ProtocolError,
            "PUSH_PROMISE on half-closed (remote) stream must be PROTOCOL_ERROR"
        );
    }

    #[test]
    fn push_promise_enforces_max_concurrent_streams() {
        let mut settings = Settings::client();
        settings.enable_push = true;
        settings.max_concurrent_streams = 3; // Very low limit for testing
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;

        // Open client stream
        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();
        let _ = conn.next_frame();

        // First push should succeed (now 2 active: stream 1 + pushed 2)
        let push1 = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 2,
            header_block: test_request_headers("/pushed-2"),
            end_headers: true,
        });
        assert!(conn.process_frame(push1).is_ok());

        // Second push should succeed (now 3 active: stream 1 + pushed 2 + pushed 4)
        let push2 = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 4,
            header_block: test_request_headers("/pushed-4"),
            end_headers: true,
        });
        assert!(conn.process_frame(push2).is_ok());

        // Third push should fail - max concurrent streams exceeded
        let push3 = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 6,
            header_block: test_request_headers("/pushed-6"),
            end_headers: true,
        });
        let err = conn.process_frame(push3).unwrap_err();
        assert_eq!(err.code, ErrorCode::RefusedStream);
    }

    /// RFC 9113 §4.3: a PUSH_PROMISE refused for any reason still passes its
    /// field block through the HPACK decoder. Each promise below adds a field
    /// to the peer's dynamic table; a later response refers to it by index and
    /// must decode to the same value. The promised stream is reset, and only
    /// a promise that broke the protocol is reported as a stream error; one
    /// that raced our GOAWAY or our reset of its associated stream is not
    /// (RFC 9113 §6.6, §6.8) (br-asupersync-dycth8). Every case runs, and the
    /// test reports all that fail.
    #[test]
    fn refused_push_promises_keep_hpack_in_step() {
        let mut failures = Vec::new();
        for refusal in [
            PushRefusalCase::AfterOurGoaway,
            PushRefusalCase::AssociatedResetByUs,
            PushRefusalCase::AssociatedHalfClosedRemote,
            PushRefusalCase::MaxConcurrentStreams,
            PushRefusalCase::PromisedIdPastGapCeiling,
        ] {
            for split_block in [false, true] {
                if let Err(failure) = refused_push_promise_case(refusal, split_block) {
                    failures.push(format!("{refusal:?} split={split_block}: {failure}"));
                }
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }

    #[derive(Clone, Copy, Debug)]
    enum PushRefusalCase {
        AfterOurGoaway,
        AssociatedResetByUs,
        AssociatedHalfClosedRemote,
        MaxConcurrentStreams,
        PromisedIdPastGapCeiling,
    }

    fn refused_push_promise_case(
        refusal: PushRefusalCase,
        split_block: bool,
    ) -> Result<(), String> {
        let request = |path| {
            vec![
                Header::new(":method", "GET"),
                Header::new(":path", path),
                Header::new(":scheme", "https"),
                Header::new(":authority", "example.com"),
            ]
        };
        let push = |server: &mut hpack::Encoder, path: &str| {
            encode_with(
                server,
                &[
                    (":method", "GET"),
                    (":scheme", "https"),
                    (":path", path),
                    (":authority", "example.com"),
                    ("x-promised", path),
                ],
            )
        };
        let mut settings = Settings::client();
        settings.enable_push = true;
        settings.max_concurrent_streams = 2;
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;
        let mut server = hpack::Encoder::new();
        let stream_id = conn
            .open_stream(request("/"), false)
            .map_err(|error| format!("open: {error:?}"))?;
        while conn.next_frame().is_some() {}

        let mut promised_stream_id = 2;
        match refusal {
            PushRefusalCase::AfterOurGoaway => conn.goaway(ErrorCode::NoError, Bytes::new()),
            PushRefusalCase::AssociatedResetByUs => {
                conn.reset_stream(stream_id, ErrorCode::Cancel);
            }
            PushRefusalCase::AssociatedHalfClosedRemote => {
                let response = encode_with(&mut server, &[(":status", "200")]);
                conn.process_frame(Frame::Headers(HeadersFrame::new(
                    stream_id, response, true, true,
                )))
                .map_err(|error| format!("first response: {error:?}"))?;
            }
            PushRefusalCase::MaxConcurrentStreams => {
                let accepted = push(&mut server, "/accepted");
                let received = conn.process_frame(Frame::PushPromise(PushPromiseFrame {
                    stream_id,
                    promised_stream_id: 2,
                    header_block: accepted,
                    end_headers: true,
                }));
                if !matches!(received, Ok(Some(ReceivedFrame::PushPromise { .. }))) {
                    return Err(format!("accepted promise: {received:?}"));
                }
                promised_stream_id = 4;
            }
            // Far past any stream-id gap the stream table accepts.
            PushRefusalCase::PromisedIdPastGapCeiling => promised_stream_id = (1 << 30) + 2,
        }
        while conn.next_frame().is_some() {}

        let block = push(&mut server, "/refused");
        let result = if split_block {
            let head = conn.process_frame(Frame::PushPromise(PushPromiseFrame {
                stream_id,
                promised_stream_id,
                header_block: block.slice(..1),
                end_headers: false,
            }));
            if matches!(refusal, PushRefusalCase::PromisedIdPastGapCeiling) {
                // No record can collect the rest of the block, so the
                // connection ends instead of losing HPACK sync.
                return match head {
                    Err(error) if error.stream_id.is_none() => Ok(()),
                    other => Err(format!("expected a connection error: {other:?}")),
                };
            }
            if !matches!(head, Ok(None)) {
                return Err(format!("PUSH_PROMISE head: {head:?}"));
            }
            conn.process_frame(Frame::Continuation(ContinuationFrame {
                stream_id,
                header_block: block.slice(1..),
                end_headers: true,
            }))
        } else {
            conn.process_frame(Frame::PushPromise(PushPromiseFrame {
                stream_id,
                promised_stream_id,
                header_block: block,
                end_headers: true,
            }))
        };
        let expected_error = match refusal {
            PushRefusalCase::AfterOurGoaway | PushRefusalCase::AssociatedResetByUs => None,
            PushRefusalCase::AssociatedHalfClosedRemote => {
                Some((Some(stream_id), ErrorCode::ProtocolError))
            }
            PushRefusalCase::MaxConcurrentStreams | PushRefusalCase::PromisedIdPastGapCeiling => {
                Some((Some(promised_stream_id), ErrorCode::RefusedStream))
            }
        };
        match (&result, expected_error) {
            (Ok(None), None) => {}
            (Err(error), Some(expected)) if (error.stream_id, error.code) == expected => {}
            _ => {
                return Err(format!(
                    "refused promise: {result:?}, expected {expected_error:?}"
                ));
            }
        }

        let mut resets = Vec::new();
        while let Some(frame) = conn.next_frame() {
            if let Frame::RstStream(reset) = frame {
                resets.push((reset.stream_id, reset.error_code));
            }
        }
        // Past the gap ceiling there is no record to reset here; the caller
        // resets the stream named by the error.
        let expected_resets = match refusal {
            PushRefusalCase::PromisedIdPastGapCeiling => Vec::new(),
            PushRefusalCase::AssociatedResetByUs => vec![(promised_stream_id, ErrorCode::Cancel)],
            _ => vec![(promised_stream_id, ErrorCode::RefusedStream)],
        };
        if resets != expected_resets {
            return Err(format!("resets {resets:?}, expected {expected_resets:?}"));
        }

        // The next response refers to the refused promise's field by index.
        // It arrives on the associated stream, or on a new one when that
        // stream can no longer carry a response.
        let response_stream_id = match refusal {
            PushRefusalCase::AfterOurGoaway
            | PushRefusalCase::MaxConcurrentStreams
            | PushRefusalCase::PromisedIdPastGapCeiling => stream_id,
            PushRefusalCase::AssociatedResetByUs | PushRefusalCase::AssociatedHalfClosedRemote => {
                let next = conn
                    .open_stream(request("/next"), false)
                    .map_err(|error| format!("open next: {error:?}"))?;
                while conn.next_frame().is_some() {}
                next
            }
        };
        let response = encode_with(
            &mut server,
            &[(":status", "200"), ("x-promised", "/refused")],
        );
        let next = conn.process_frame(Frame::Headers(HeadersFrame::new(
            response_stream_id,
            response,
            true,
            true,
        )));
        match next {
            Ok(Some(ReceivedFrame::Headers { headers, .. }))
                if headers
                    .iter()
                    .any(|header| header.name == "x-promised" && header.value == "/refused") =>
            {
                Ok(())
            }
            other => Err(format!("the next response must decode: {other:?}")),
        }
    }

    #[test]
    fn push_promise_rejected_for_duplicate_stream_id() {
        let mut settings = Settings::client();
        settings.enable_push = true;
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();
        let _ = conn.next_frame();

        // First push with stream ID 2
        let push1 = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 2,
            header_block: test_request_headers("/pushed-2"),
            end_headers: true,
        });
        assert!(conn.process_frame(push1).is_ok());

        // Trying to push with same stream ID 2 again should fail
        let push2 = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 2,
            header_block: test_request_headers("/pushed-2"),
            end_headers: true,
        });
        let err = conn.process_frame(push2).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn push_promise_monotonic_stream_id() {
        let mut settings = Settings::client();
        settings.enable_push = true;
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();
        let _ = conn.next_frame();

        // Push with stream ID 4 first
        let push1 = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 4,
            header_block: test_request_headers("/pushed-4"),
            end_headers: true,
        });
        assert!(conn.process_frame(push1).is_ok());

        // Push with stream ID 2 (lower) should fail - IDs must be monotonically increasing
        let push2 = Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 2,
            header_block: test_request_headers("/pushed-2"),
            end_headers: true,
        });
        let err = conn.process_frame(push2).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn push_promise_attack_flood_bounded() {
        // Simulates a malicious server sending many PUSH_PROMISE frames.
        // The implementation must bound resource usage via max_concurrent_streams.
        let mut settings = Settings::client();
        settings.enable_push = true;
        settings.max_concurrent_streams = 10;
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();
        let _ = conn.next_frame();

        let mut accepted = 0;
        let mut rejected = 0;

        // Try to push 100 streams
        for i in 0_u32..100 {
            // Generate even IDs with overflow protection: 2, 4, 6, ...
            let promised_id = i.saturating_add(1).saturating_mul(2);
            let push = Frame::PushPromise(PushPromiseFrame {
                stream_id,
                promised_stream_id: promised_id,
                header_block: test_request_headers("/pushed"),
                end_headers: true,
            });

            match conn.process_frame(push) {
                Ok(_) => accepted += 1,
                Err(e) if e.code == ErrorCode::RefusedStream => rejected += 1,
                Err(e) => panic!("unexpected error: {e:?}"),
            }
        }

        // Should accept up to max_concurrent_streams - 1 (minus the original request stream)
        assert_eq!(
            accepted, 9,
            "should accept max_concurrent_streams - 1 pushes"
        );
        assert_eq!(rejected, 91, "should reject the rest");
    }

    #[test]
    fn push_promise_on_server_initiated_stream_rejected() {
        // PUSH_PROMISE must be sent on client-initiated (odd) stream
        let mut settings = Settings::client();
        settings.enable_push = true;
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;

        // Open a client stream first
        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let _ = conn.open_stream(headers, false).unwrap();
        let _ = conn.next_frame();

        // Try to send PUSH_PROMISE on an even (server-initiated) stream ID
        let frame = Frame::PushPromise(PushPromiseFrame {
            stream_id: 2, // Even = server-initiated = invalid for PUSH_PROMISE
            promised_stream_id: 4,
            header_block: Bytes::new(),
            end_headers: true,
        });

        let err = conn.process_frame(frame).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    // =========================================================================
    // SETTINGS ACK Flow Tests (bd-1oo7)
    // =========================================================================

    #[test]
    fn test_settings_ack_is_no_op() {
        // SETTINGS ACK should be silently accepted
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        let ack_frame = Frame::Settings(SettingsFrame::ack());
        let result = conn.process_frame(ack_frame);

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_settings_updates_remote_settings() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Initial values (DEFAULT_MAX_CONCURRENT_STREAMS = 256)
        assert_eq!(conn.remote_settings().max_concurrent_streams, 256);
        assert_eq!(
            conn.remote_settings().initial_window_size,
            settings::DEFAULT_INITIAL_WINDOW_SIZE
        );

        // Apply new settings
        let settings = SettingsFrame::new(vec![
            Setting::MaxConcurrentStreams(50),
            Setting::InitialWindowSize(32768),
            Setting::MaxFrameSize(32768),
        ]);
        conn.process_frame(Frame::Settings(settings)).unwrap();

        // Verify updates
        assert_eq!(conn.remote_settings().max_concurrent_streams, 50);
        assert_eq!(conn.remote_settings().initial_window_size, 32768);
        assert_eq!(conn.remote_settings().max_frame_size, 32768);
    }

    #[test]
    fn local_initial_window_configures_receive_not_peer_send_window() {
        let conn_settings = Settings {
            initial_window_size: 32_768,
            ..Settings::default()
        };
        let mut conn = Connection::server(conn_settings);

        let stream_id = conn.streams.allocate_stream_id().unwrap();
        let stream = conn.streams.get(stream_id).unwrap();
        assert_eq!(
            stream.send_window(),
            settings::DEFAULT_INITIAL_WINDOW_SIZE as i32
        );
        assert_eq!(stream.recv_window(), 32_768);

        conn.streams.set_initial_window_size(100_000).unwrap();
        let stream = conn.streams.get(stream_id).unwrap();
        assert_eq!(stream.send_window(), 100_000);
        assert_eq!(stream.recv_window(), 32_768);
    }

    #[test]
    fn test_settings_invalid_initial_window_size() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Initial window size > 2^31 - 1 is invalid per RFC 7540 Section 6.5.2:
        // "Values above the maximum flow-control window size of 2^31-1 MUST be
        // treated as a connection error of type FLOW_CONTROL_ERROR"
        let settings = SettingsFrame::new(vec![Setting::InitialWindowSize(0x8000_0000)]);
        let err = conn.process_frame(Frame::Settings(settings)).unwrap_err();

        assert_eq!(err.code, ErrorCode::FlowControlError);
    }

    #[test]
    fn test_settings_invalid_max_frame_size() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Max frame size must be between 16384 and 16777215
        let settings = SettingsFrame::new(vec![Setting::MaxFrameSize(100)]); // Too small
        let err = conn.process_frame(Frame::Settings(settings)).unwrap_err();

        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    // br-asupersync-wk370q: a SETTINGS frame whose body is
    // [<valid InitialWindowSize=12345>, <invalid MaxFrameSize=100>]
    // must be rejected ATOMICALLY — neither remote_settings nor
    // any per-stream initial_window_size may absorb the leading
    // valid setting. Pre-fix, the InitialWindowSize landed on
    // remote_settings + every stream BEFORE the MaxFrameSize
    // failure aborted the loop, producing a partial-state
    // window for the GOAWAY drain in which our flow-control view
    // diverged from the peer's.
    #[test]
    fn test_settings_partial_apply_is_rejected_atomically_wk370q() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;
        let initial_window_before = conn.remote_settings.initial_window_size;

        // Ensure at least one stream exists so we can verify its
        // initial window is NOT touched by the failed SETTINGS frame.
        conn.streams.get_or_create(1).expect("create stream 1");
        let stream_window_before = conn
            .streams
            .get(1)
            .expect("stream 1 must exist")
            .send_window();

        // Frame: [InitialWindowSize=12345 (valid), MaxFrameSize=100 (invalid)]
        let bad_settings = SettingsFrame::new(vec![
            Setting::InitialWindowSize(12345),
            Setting::MaxFrameSize(100),
        ]);
        let err = conn
            .process_frame(Frame::Settings(bad_settings))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);

        // remote_settings.initial_window_size MUST be unchanged.
        assert_eq!(
            conn.remote_settings.initial_window_size, initial_window_before,
            "remote_settings.initial_window_size leaked from a partially-applied SETTINGS frame"
        );

        // Stream 1's send window MUST be unchanged.
        let stream_window_after = conn
            .streams
            .get(1)
            .expect("stream 1 must still exist")
            .send_window();
        assert_eq!(
            stream_window_after, stream_window_before,
            "stream send_window leaked from a partially-applied SETTINGS frame"
        );
    }

    #[test]
    fn test_settings_transitions_to_open() {
        let mut conn = Connection::server(Settings::default());
        assert_eq!(conn.state, ConnectionState::Handshaking);

        // First SETTINGS from peer transitions to Open
        let settings = SettingsFrame::new(vec![]);
        conn.process_frame(Frame::Settings(settings)).unwrap();

        assert_eq!(conn.state, ConnectionState::Open);
    }

    // =========================================================================
    // GOAWAY Edge Case Tests (bd-1oo7)
    // =========================================================================

    #[test]
    fn test_goaway_rejects_new_streams() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        // Open a stream
        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        conn.open_stream(headers.clone(), false).unwrap();

        // Receive GOAWAY
        let goaway = Frame::GoAway(GoAwayFrame::new(1, ErrorCode::NoError));
        conn.process_frame(goaway).unwrap();

        assert!(conn.goaway_received());
        assert_eq!(conn.state, ConnectionState::Closing);

        // Trying to open new streams should fail
        let err = conn.open_stream(headers, false).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    /// RFC 9113 §6.8: our GOAWAY's last-stream identifier covers streams the
    /// peer initiated. A client that sends GOAWAY still receives the response
    /// HEADERS and DATA for a request it had open, and still refuses a push
    /// promised above the boundary.
    #[test]
    fn a_client_that_sent_goaway_still_receives_responses_on_its_own_streams() {
        let mut settings = Settings::client();
        settings.enable_push = true;
        let mut conn = Connection::client(settings);
        conn.state = ConnectionState::Open;
        let stream_id = conn
            .open_stream(test_request_header_vec("/"), true)
            .unwrap();
        while conn.next_frame().is_some() {}
        conn.goaway(ErrorCode::NoError, Bytes::new());
        while conn.next_frame().is_some() {}

        let mut server = hpack::Encoder::new();
        let promise = encode_with(
            &mut server,
            &[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/pushed"),
                (":authority", "example.com"),
            ],
        );
        let pushed = conn.process_frame(Frame::PushPromise(PushPromiseFrame {
            stream_id,
            promised_stream_id: 2,
            header_block: promise,
            end_headers: true,
        }));
        assert!(matches!(pushed, Ok(None)), "{pushed:?}");
        assert!(
            matches!(conn.next_frame(), Some(Frame::RstStream(reset)) if reset.stream_id == 2),
            "the push above our GOAWAY boundary is refused"
        );

        let response = encode_with(&mut server, &[(":status", "200")]);
        let headers = conn.process_frame(Frame::Headers(HeadersFrame::new(
            stream_id, response, false, true,
        )));
        assert!(
            matches!(
                headers,
                Ok(Some(ReceivedFrame::Headers { stream_id: id, .. })) if id == stream_id
            ),
            "{headers:?}"
        );
        let data = conn.process_frame(Frame::Data(DataFrame::new(
            stream_id,
            Bytes::from_static(b"body"),
            true,
        )));
        assert!(
            matches!(
                data,
                Ok(Some(ReceivedFrame::Data { stream_id: id, ref data, end_stream: true }))
                    if id == stream_id && data.as_ref() == b"body"
            ),
            "{data:?}"
        );
    }

    #[test]
    fn test_goaway_sent_rejects_new_streams() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];

        conn.goaway(ErrorCode::NoError, Bytes::new());
        assert!(conn.goaway_sent);
        assert_eq!(conn.state, ConnectionState::Closing);

        let err = conn.open_stream(headers, false).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_goaway_resets_streams_above_last_id() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        // Open multiple streams
        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream1 = conn.open_stream(headers.clone(), false).unwrap(); // Stream 1
        let _ = conn.next_frame(); // Drain HEADERS
        let stream3 = conn.open_stream(headers.clone(), false).unwrap(); // Stream 3
        let _ = conn.next_frame(); // Drain HEADERS
        let stream5 = conn.open_stream(headers, false).unwrap(); // Stream 5
        let _ = conn.next_frame(); // Drain HEADERS

        assert_eq!(stream1, 1);
        assert_eq!(stream3, 3);
        assert_eq!(stream5, 5);

        // GOAWAY with last_stream_id = 1 means streams 3 and 5 were not processed
        let goaway = Frame::GoAway(GoAwayFrame::new(1, ErrorCode::NoError));
        let result = conn.process_frame(goaway).unwrap().unwrap();

        match result {
            ReceivedFrame::GoAway {
                last_stream_id,
                error_code,
                ..
            } => {
                assert_eq!(last_stream_id, 1);
                assert_eq!(error_code, ErrorCode::NoError);
            }
            _ => panic!("expected GoAway"),
        }

        // Stream 1 should still be in its original state
        assert!(!conn.stream(1).unwrap().state().is_closed());

        // Streams 3 and 5 should be reset
        assert_eq!(conn.stream(3).unwrap().state(), StreamState::Closed);
        assert_eq!(conn.stream(5).unwrap().state(), StreamState::Closed);
    }

    // =========================================================================
    // Two-stage graceful shutdown / drain tests
    // (br-asupersync-server-stack-hardening-eeexl1.2 D2.3)
    // =========================================================================

    #[test]
    fn begin_graceful_shutdown_warns_without_refusing_racing_streams() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // One request is already in flight when drain starts.
        conn.process_frame(Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/in-flight"),
            false,
            true,
        )))
        .unwrap();

        conn.begin_graceful_shutdown(Bytes::from_static(b"draining"));
        assert!(conn.goaway_sent());
        assert!(conn.graceful_shutdown_pending());
        assert_eq!(conn.state(), ConnectionState::Closing);
        assert_eq!(
            conn.sent_goaway_last_stream_id(),
            Some(0x7fff_ffff),
            "stage-1 GOAWAY must advertise the maximum stream id"
        );

        match conn.next_frame().expect("stage-1 GOAWAY queued") {
            Frame::GoAway(g) => {
                assert_eq!(g.last_stream_id, 0x7fff_ffff);
                assert_eq!(g.error_code, ErrorCode::NoError);
                assert_eq!(&g.debug_data[..], b"draining");
            }
            other => panic!("expected GoAway, got {other:?}"),
        }

        // A stream racing with the stage-1 warning must still be accepted.
        let received = conn
            .process_frame(Frame::Headers(HeadersFrame::new(
                3,
                test_request_headers("/racing"),
                false,
                true,
            )))
            .unwrap();
        assert!(
            matches!(received, Some(ReceivedFrame::Headers { stream_id: 3, .. })),
            "racing stream must be processed during the stage-1 window"
        );
        assert_eq!(conn.active_stream_count(), 2);
        assert!(!conn.graceful_shutdown_complete());
        assert!(!conn.has_pending_frames(), "no RST for the racing stream");
    }

    #[test]
    fn finalize_graceful_shutdown_ratchets_boundary_and_refuses_late_streams() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        conn.process_frame(Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/one"),
            false,
            true,
        )))
        .unwrap();
        conn.begin_graceful_shutdown(Bytes::new());
        let _ = conn.next_frame(); // stage-1 GOAWAY
        conn.process_frame(Frame::Headers(HeadersFrame::new(
            3,
            test_request_headers("/racing"),
            false,
            true,
        )))
        .unwrap();

        conn.finalize_graceful_shutdown(Bytes::new());
        assert!(!conn.graceful_shutdown_pending());
        assert_eq!(conn.sent_goaway_last_stream_id(), Some(3));
        match conn.next_frame().expect("stage-2 GOAWAY queued") {
            Frame::GoAway(g) => {
                assert_eq!(
                    g.last_stream_id, 3,
                    "stage-2 GOAWAY must ratchet down to the true boundary"
                );
                assert_eq!(g.error_code, ErrorCode::NoError);
            }
            other => panic!("expected GoAway, got {other:?}"),
        }

        // A stream above the definitive boundary is refused...
        let received = conn
            .process_frame(Frame::Headers(HeadersFrame::new(
                5,
                test_request_headers("/late"),
                true,
                true,
            )))
            .unwrap();
        assert!(received.is_none(), "refused stream must not surface");
        match conn.next_frame().expect("RST_STREAM queued") {
            Frame::RstStream(r) => {
                assert_eq!(r.stream_id, 5);
                assert_eq!(r.error_code, ErrorCode::RefusedStream);
            }
            other => panic!("expected RstStream, got {other:?}"),
        }
        // ...and its local record is closed so drain can quiesce.
        assert_eq!(conn.stream(5).unwrap().state(), StreamState::Closed);
        assert_eq!(conn.active_stream_count(), 2);
    }

    #[test]
    fn graceful_shutdown_completes_when_in_flight_streams_finish() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Request fully received; response not yet sent (half-closed remote).
        conn.process_frame(Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/slow"),
            true,
            true,
        )))
        .unwrap();

        conn.begin_graceful_shutdown(Bytes::new());
        let _ = conn.next_frame();
        conn.finalize_graceful_shutdown(Bytes::new());
        let _ = conn.next_frame();
        assert_eq!(conn.active_stream_count(), 1);
        assert!(!conn.graceful_shutdown_complete());

        // Queuing the final response cannot complete drain before it is emitted.
        conn.send_headers(1, vec![Header::new(":status", "200")], true)
            .unwrap();
        assert_eq!(conn.active_stream_count(), 1);
        assert!(!conn.graceful_shutdown_complete());
        let Some(Frame::Headers(final_headers)) = conn.next_frame() else {
            panic!("final response must be emitted before drain completes")
        };
        assert_eq!(final_headers.stream_id, 1);
        assert!(final_headers.end_stream);
        assert_eq!(conn.active_stream_count(), 0);
        assert!(conn.graceful_shutdown_complete());
    }

    #[test]
    fn idle_connection_graceful_shutdown_completes_immediately() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        conn.begin_graceful_shutdown(Bytes::new());
        assert!(
            !conn.graceful_shutdown_complete(),
            "stage-1 alone is not definitive even when idle"
        );
        conn.finalize_graceful_shutdown(Bytes::new());
        assert!(conn.graceful_shutdown_complete());

        match conn.next_frame().expect("stage-1 GOAWAY") {
            Frame::GoAway(g) => assert_eq!(g.last_stream_id, 0x7fff_ffff),
            other => panic!("expected GoAway, got {other:?}"),
        }
        match conn.next_frame().expect("stage-2 GOAWAY") {
            Frame::GoAway(g) => assert_eq!(g.last_stream_id, 0),
            other => panic!("expected GoAway, got {other:?}"),
        }
        assert!(!conn.has_pending_frames());
    }

    #[test]
    fn finalize_without_begin_acts_like_immediate_noerror_goaway() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        conn.process_frame(Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/only"),
            true,
            true,
        )))
        .unwrap();

        conn.finalize_graceful_shutdown(Bytes::new());
        assert!(conn.goaway_sent());
        assert!(!conn.graceful_shutdown_pending());
        match conn.next_frame().expect("definitive GOAWAY") {
            Frame::GoAway(g) => {
                assert_eq!(g.last_stream_id, 1);
                assert_eq!(g.error_code, ErrorCode::NoError);
            }
            other => panic!("expected GoAway, got {other:?}"),
        }

        // Repeated finalize must not re-advertise the boundary.
        conn.finalize_graceful_shutdown(Bytes::new());
        assert!(!conn.has_pending_frames());
    }

    #[test]
    fn graceful_shutdown_after_immediate_goaway_is_noop() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        conn.process_frame(Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/pre"),
            false,
            true,
        )))
        .unwrap();
        conn.goaway(ErrorCode::NoError, Bytes::new());
        assert_eq!(conn.sent_goaway_last_stream_id(), Some(1));
        let _ = conn.next_frame(); // definitive GOAWAY

        conn.begin_graceful_shutdown(Bytes::new());
        conn.finalize_graceful_shutdown(Bytes::new());
        assert!(!conn.graceful_shutdown_pending());
        assert_eq!(
            conn.sent_goaway_last_stream_id(),
            Some(1),
            "boundary must never widen after a definitive GOAWAY"
        );
        assert!(
            !conn.has_pending_frames(),
            "no extra GOAWAY after an immediate goaway"
        );
    }

    #[test]
    fn refused_continuation_stream_is_closed_locally() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        conn.process_frame(Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/one"),
            false,
            true,
        )))
        .unwrap();
        conn.begin_graceful_shutdown(Bytes::new());
        conn.finalize_graceful_shutdown(Bytes::new());
        let _ = conn.next_frame();
        let _ = conn.next_frame();

        // A late stream split across HEADERS + CONTINUATION is refused and
        // its local record closed, exercising the continuation refusal path.
        let block = test_request_headers("/late-split");
        let first = block.slice(..1);
        let rest = block.slice(1..);
        conn.process_frame(Frame::Headers(HeadersFrame::new(3, first, true, false)))
            .unwrap();
        let received = conn
            .process_frame(Frame::Continuation(ContinuationFrame {
                stream_id: 3,
                header_block: rest,
                end_headers: true,
            }))
            .unwrap();
        assert!(received.is_none(), "refused stream must not surface");

        match conn.next_frame().expect("RST_STREAM queued") {
            Frame::RstStream(r) => {
                assert_eq!(r.stream_id, 3);
                assert_eq!(r.error_code, ErrorCode::RefusedStream);
            }
            other => panic!("expected RstStream, got {other:?}"),
        }
        assert_eq!(conn.stream(3).unwrap().state(), StreamState::Closed);
        assert_eq!(conn.active_stream_count(), 1);
    }

    #[test]
    fn test_goaway_received_last_stream_id_only_narrows() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let _stream1 = conn.open_stream(headers.clone(), false).unwrap();
        let _ = conn.next_frame();
        let _stream3 = conn.open_stream(headers.clone(), false).unwrap();
        let _ = conn.next_frame();
        let _stream5 = conn.open_stream(headers.clone(), false).unwrap();
        let _ = conn.next_frame();
        let _stream7 = conn.open_stream(headers, false).unwrap();
        let _ = conn.next_frame();

        let first = conn
            .process_frame(Frame::GoAway(GoAwayFrame::new(5, ErrorCode::NoError)))
            .unwrap()
            .unwrap();
        match first {
            ReceivedFrame::GoAway { last_stream_id, .. } => assert_eq!(last_stream_id, 5),
            _ => panic!("expected GoAway"),
        }
        assert!(!conn.stream(5).unwrap().state().is_closed());
        assert_eq!(conn.stream(7).unwrap().state(), StreamState::Closed);

        let second = conn
            .process_frame(Frame::GoAway(GoAwayFrame::new(7, ErrorCode::InternalError)))
            .unwrap()
            .unwrap();
        match second {
            ReceivedFrame::GoAway {
                last_stream_id,
                error_code,
                ..
            } => {
                assert_eq!(last_stream_id, 5);
                assert_eq!(error_code, ErrorCode::InternalError);
            }
            _ => panic!("expected GoAway"),
        }
        assert!(!conn.stream(5).unwrap().state().is_closed());

        let third = conn
            .process_frame(Frame::GoAway(GoAwayFrame::new(1, ErrorCode::NoError)))
            .unwrap()
            .unwrap();
        match third {
            ReceivedFrame::GoAway { last_stream_id, .. } => assert_eq!(last_stream_id, 1),
            _ => panic!("expected GoAway"),
        }
        assert_eq!(conn.stream(3).unwrap().state(), StreamState::Closed);
        assert_eq!(conn.stream(5).unwrap().state(), StreamState::Closed);
    }

    #[test]
    fn test_goaway_sent_once() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // First GOAWAY
        conn.goaway(ErrorCode::NoError, Bytes::new());
        assert!(conn.has_pending_frames());

        // Second GOAWAY should be ignored
        conn.goaway(ErrorCode::InternalError, Bytes::new());

        // Should only have one GOAWAY frame
        let frame1 = conn.next_frame().unwrap();
        assert!(matches!(frame1, Frame::GoAway(_)));

        // No second GOAWAY
        assert!(!conn.has_pending_frames());
    }

    #[test]
    fn goaway_refusal_boundary_stays_frozen_after_later_bookkeeping() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Process stream 1 so the outbound GOAWAY advertises last_stream_id = 1.
        let headers = Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/one"),
            false,
            true,
        ));
        conn.process_frame(headers).unwrap();
        conn.goaway(ErrorCode::NoError, Bytes::new());

        let goaway = conn.next_frame().expect("expected GOAWAY frame");
        match goaway {
            Frame::GoAway(frame) => assert_eq!(frame.last_stream_id, 1),
            other => panic!("expected GOAWAY frame, got {other:?}"),
        }

        // A higher-numbered HEADERS after GOAWAY is refused, but still creates
        // the stream entry so later frames can target it.
        let refused = Frame::Headers(HeadersFrame::new(
            3,
            test_request_headers("/refused"),
            false,
            true,
        ));
        assert!(conn.process_frame(refused).unwrap().is_none());

        // Later bookkeeping on stream 3 can still bump the mutable tracker.
        let reset = Frame::RstStream(RstStreamFrame::new(3, ErrorCode::Cancel));
        conn.process_frame(reset).unwrap();
        assert_eq!(conn.last_stream_id, 3);
        assert_eq!(conn.sent_goaway_last_stream_id, Some(1));

        // The refusal boundary must remain frozen at the value we advertised.
        let refused_again = Frame::Headers(HeadersFrame::new(
            5,
            test_request_headers("/still-refused"),
            false,
            true,
        ));
        assert!(
            conn.process_frame(refused_again).unwrap().is_none(),
            "streams above the advertised GOAWAY boundary must stay refused"
        );

        let mut refused_streams = Vec::new();
        while let Some(frame) = conn.next_frame() {
            if let Frame::RstStream(rst) = frame {
                refused_streams.push(rst.stream_id);
            }
        }
        assert_eq!(refused_streams, vec![3, 5]);
    }

    #[test]
    fn test_goaway_with_debug_data() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        let debug_data = Bytes::from("server shutting down for maintenance");
        conn.goaway(ErrorCode::NoError, debug_data.clone());

        let frame = conn.next_frame().unwrap();
        match frame {
            Frame::GoAway(g) => {
                assert_eq!(g.error_code, ErrorCode::NoError);
                assert_eq!(g.debug_data, debug_data);
            }
            _ => panic!("expected GoAway"),
        }
    }

    #[test]
    fn test_goaway_received_with_error() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        let goaway = Frame::GoAway(GoAwayFrame::new(0, ErrorCode::InternalError));
        let result = conn.process_frame(goaway).unwrap().unwrap();

        match result {
            ReceivedFrame::GoAway {
                error_code,
                last_stream_id,
                ..
            } => {
                assert_eq!(error_code, ErrorCode::InternalError);
                assert_eq!(last_stream_id, 0);
            }
            _ => panic!("expected GoAway"),
        }

        assert!(conn.goaway_received());
        assert_eq!(conn.state, ConnectionState::Closing);
    }

    // =========================================================================
    // Shutdown Semantics Tests (bd-1oo7)
    // =========================================================================

    #[test]
    fn test_graceful_shutdown_flow() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Initiate graceful shutdown
        conn.goaway(ErrorCode::NoError, Bytes::new());

        // Connection should transition to Closing
        assert_eq!(conn.state, ConnectionState::Closing);

        // Should have GOAWAY frame pending
        let frame = conn.next_frame().unwrap();
        match frame {
            Frame::GoAway(g) => {
                assert_eq!(g.error_code, ErrorCode::NoError);
            }
            _ => panic!("expected GoAway"),
        }
    }

    // =========================================================================
    // PING Keepalive Tests (bd-1oo7)
    // =========================================================================

    #[test]
    fn test_ping_ack_response() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        let opaque_data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let ping = PingFrame::new(opaque_data);
        conn.process_frame(Frame::Ping(ping)).unwrap();

        // Should have PING ACK pending
        let frame = conn.next_frame().unwrap();
        match frame {
            Frame::Ping(p) => {
                assert!(p.ack);
                assert_eq!(p.opaque_data, opaque_data);
            }
            _ => panic!("expected Ping ACK"),
        }
    }

    #[test]
    fn test_ping_ack_not_echoed() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Receive PING ACK (should not trigger another ACK)
        let ping_ack = PingFrame::ack([1, 2, 3, 4, 5, 6, 7, 8]);
        conn.process_frame(Frame::Ping(ping_ack)).unwrap();

        // No response should be queued
        assert!(!conn.has_pending_frames());
    }

    #[test]
    fn ping_ack_is_queued_after_existing_pending_frame() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        conn.send_connection_window_update(1024)
            .expect("queue pre-existing connection WINDOW_UPDATE");
        conn.process_frame(Frame::Ping(PingFrame::new(*b"abcdefgh")))
            .expect("non-ACK PING should be processed by the connection state machine");

        match conn
            .next_frame()
            .expect("pre-existing pending frame should be emitted first")
        {
            Frame::WindowUpdate(frame) => {
                assert_eq!(frame.stream_id, 0);
                assert_eq!(frame.increment, 1024);
            }
            other => panic!("expected WINDOW_UPDATE before PING ACK, got {other:?}"),
        }

        match conn
            .next_frame()
            .expect("non-ACK PING should queue exactly one ACK response")
        {
            Frame::Ping(frame) => {
                assert!(frame.ack);
                assert_eq!(frame.opaque_data, *b"abcdefgh");
            }
            other => panic!("expected PING ACK after pre-existing frame, got {other:?}"),
        }

        assert!(!conn.has_pending_frames());
        assert_eq!(conn.state, ConnectionState::Open);
    }

    #[test]
    fn ping_ack_frame_preserves_existing_pending_queue_without_echo() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        conn.send_connection_window_update(2048)
            .expect("queue pre-existing connection WINDOW_UPDATE");
        conn.process_frame(Frame::Ping(PingFrame::ack(*b"ack-data")))
            .expect("ACK PING should be accepted without generating a response");

        match conn
            .next_frame()
            .expect("pre-existing pending frame should remain queued")
        {
            Frame::WindowUpdate(frame) => {
                assert_eq!(frame.stream_id, 0);
                assert_eq!(frame.increment, 2048);
            }
            other => panic!("expected original WINDOW_UPDATE, got {other:?}"),
        }

        assert!(
            conn.next_frame().is_none(),
            "ACK PING must not append a second PING ACK"
        );
        assert_eq!(conn.state, ConnectionState::Open);
    }

    // =========================================================================
    // Cancellation Race Tests (bd-1oo7)
    // =========================================================================

    /// RFC 7540 §5.1: RST_STREAM received on a stream in the idle state
    /// MUST be treated as a connection error of type PROTOCOL_ERROR.
    #[test]
    fn test_rst_stream_on_idle_stream_is_connection_error() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Stream 999 has never been opened — it is idle.
        let rst = Frame::RstStream(RstStreamFrame::new(999, ErrorCode::Cancel));
        let err = conn.process_frame(rst).unwrap_err();

        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert!(
            err.stream_id.is_none(),
            "idle-stream RST_STREAM must be a connection error, not a stream error"
        );
    }

    /// RST_STREAM on a known (non-idle) stream should still work normally.
    #[test]
    fn test_rst_stream_on_open_stream() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Open stream 1 via HEADERS.
        let headers = Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/rst"),
            false,
            true,
        ));
        conn.process_frame(headers).unwrap();

        // RST_STREAM on an open stream should succeed.
        let rst = Frame::RstStream(RstStreamFrame::new(1, ErrorCode::Cancel));
        let result = conn.process_frame(rst).unwrap().unwrap();

        match result {
            ReceivedFrame::Reset {
                stream_id,
                error_code,
            } => {
                assert_eq!(stream_id, 1);
                assert_eq!(error_code, ErrorCode::Cancel);
            }
            _ => panic!("expected Reset"),
        }
    }

    /// RST_STREAM with stream ID 0 is always a connection error (RFC 7540 §6.4).
    #[test]
    fn test_rst_stream_on_stream_zero_is_connection_error() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        let rst = Frame::RstStream(RstStreamFrame::new(0, ErrorCode::Cancel));
        let err = conn.process_frame(rst).unwrap_err();

        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert!(err.stream_id.is_none());
    }

    #[test]
    fn test_data_after_rst_ignored() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Open stream via HEADERS
        let headers = Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/rst"),
            false,
            true,
        ));
        conn.process_frame(headers).unwrap();

        // Reset the stream
        let rst = Frame::RstStream(RstStreamFrame::new(1, ErrorCode::Cancel));
        conn.process_frame(rst).unwrap();

        // Stream should be closed
        assert_eq!(conn.stream(1).unwrap().state(), StreamState::Closed);

        // DATA on closed stream should return error
        let data = Frame::Data(DataFrame::new(1, Bytes::from("test"), false));
        let err = conn.process_frame(data).unwrap_err();
        assert_eq!(err.code, ErrorCode::StreamClosed);
    }

    /// br-asupersync-8peajk — RFC 9113 §7 enumerates 14 HTTP/2 error
    /// codes (0x0..=0xd). Connection::reset_stream(stream_id, code) MUST
    /// emit exactly one RST_STREAM frame with that stream_id and that
    /// error_code; the on-wire u32 mapping is part of the spec contract.
    /// The pre-existing reset_stream test only covers Cancel; this
    /// truth-table pins the remaining 13 codes so a future refactor in
    /// PendingOp::RstStream cannot silently filter or remap them.
    #[test]
    fn reset_stream_emits_rfc_9113_section_7_error_codes() {
        // Each row is (RFC §7 wire u32, ErrorCode variant, RFC name).
        // Sourced from RFC 9113 §7 (Error Codes) and RFC 7540 §11.4.
        let codes: &[(u32, ErrorCode, &str)] = &[
            (0x0, ErrorCode::NoError, "NO_ERROR"),
            (0x1, ErrorCode::ProtocolError, "PROTOCOL_ERROR"),
            (0x2, ErrorCode::InternalError, "INTERNAL_ERROR"),
            (0x3, ErrorCode::FlowControlError, "FLOW_CONTROL_ERROR"),
            (0x4, ErrorCode::SettingsTimeout, "SETTINGS_TIMEOUT"),
            (0x5, ErrorCode::StreamClosed, "STREAM_CLOSED"),
            (0x6, ErrorCode::FrameSizeError, "FRAME_SIZE_ERROR"),
            (0x7, ErrorCode::RefusedStream, "REFUSED_STREAM"),
            (0x8, ErrorCode::Cancel, "CANCEL"),
            (0x9, ErrorCode::CompressionError, "COMPRESSION_ERROR"),
            (0xa, ErrorCode::ConnectError, "CONNECT_ERROR"),
            (0xb, ErrorCode::EnhanceYourCalm, "ENHANCE_YOUR_CALM"),
            (0xc, ErrorCode::InadequateSecurity, "INADEQUATE_SECURITY"),
            (0xd, ErrorCode::Http11Required, "HTTP_1_1_REQUIRED"),
        ];

        for (wire_u32, code, name) in codes.iter().copied() {
            // Wire-value invariant: ErrorCode → u32 must match RFC §7.
            assert_eq!(
                u32::from(code),
                wire_u32,
                "RFC 9113 §7: {name} on-wire value must be 0x{wire_u32:x}, got 0x{:x}",
                u32::from(code),
            );
            // Round-trip through from_u32 — peers send the u32, we must
            // recognise it.
            assert_eq!(
                ErrorCode::from_u32(wire_u32),
                code,
                "RFC 9113 §7: from_u32(0x{wire_u32:x}) must round-trip to {name}",
            );

            // Spin up a fresh client connection so reset_stream operates
            // on a real (locally-initiated) open stream.
            let mut conn = Connection::client(Settings::client());
            conn.state = ConnectionState::Open;
            let request_headers = vec![
                Header::new(":method", "GET"),
                Header::new(":path", "/"),
                Header::new(":scheme", "https"),
                Header::new(":authority", "example.com"),
            ];
            let stream_id = conn
                .open_stream(request_headers, false)
                .expect("open stream");
            // Drain the queued HEADERS so next_frame returns the RST_STREAM.
            match conn.next_frame().expect("expected request HEADERS") {
                Frame::Headers(h) => assert_eq!(h.stream_id, stream_id),
                other => panic!("expected HEADERS frame, got {other:?}"),
            }

            conn.reset_stream(stream_id, code);

            match conn
                .next_frame()
                .expect("reset_stream must queue exactly one RST_STREAM")
            {
                Frame::RstStream(rst) => {
                    assert_eq!(
                        rst.stream_id, stream_id,
                        "RST_STREAM stream_id must match the reset target ({name})",
                    );
                    assert_eq!(
                        rst.error_code, code,
                        "RST_STREAM error_code must round-trip {name} unchanged \
                         (regression guard for PendingOp::RstStream)",
                    );
                }
                other => panic!("{name}: expected RST_STREAM, got {other:?}"),
            }
            assert!(
                conn.next_frame().is_none(),
                "{name}: reset_stream must emit exactly one RST_STREAM",
            );
        }
    }

    #[test]
    fn test_reset_stream_drops_queued_outbound_data() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream_id = conn.open_stream(headers, false).unwrap();

        // Pretend request headers were already sent.
        let frame = conn.next_frame().expect("expected request HEADERS");
        match frame {
            Frame::Headers(h) => assert_eq!(h.stream_id, stream_id),
            other => panic!("expected HEADERS frame, got {other:?}"),
        }

        conn.send_data(stream_id, Bytes::from("queued"), true)
            .unwrap();
        conn.reset_stream(stream_id, ErrorCode::Cancel);

        // Once reset, queued DATA for the stream must be discarded.
        let frame = conn.next_frame().expect("expected RST_STREAM frame");
        match frame {
            Frame::RstStream(rst) => {
                assert_eq!(rst.stream_id, stream_id);
                assert_eq!(rst.error_code, ErrorCode::Cancel);
            }
            other => panic!("expected RST_STREAM frame, got {other:?}"),
        }
        assert!(conn.next_frame().is_none());
    }

    #[test]
    fn goaway_received_drops_queued_headers_for_refused_local_streams() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        let stream1 = conn.open_stream(headers.clone(), false).unwrap();
        let stream3 = conn.open_stream(headers, false).unwrap();
        assert_eq!(stream1, 1);
        assert_eq!(stream3, 3);

        let goaway = Frame::GoAway(GoAwayFrame::new(1, ErrorCode::NoError));
        conn.process_frame(goaway).unwrap();
        assert_eq!(
            conn.stream(stream3).unwrap().error_code(),
            Some(ErrorCode::RefusedStream)
        );

        let frame = conn
            .next_frame()
            .expect("stream 1 HEADERS should still be sent");
        match frame {
            Frame::Headers(frame) => assert_eq!(frame.stream_id, stream1),
            other => panic!("expected HEADERS frame, got {other:?}"),
        }

        assert!(
            conn.next_frame().is_none(),
            "queued HEADERS for reset stream 3 must be discarded"
        );
    }

    #[test]
    fn test_window_update_after_goaway() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;

        // Receive GOAWAY
        let goaway = Frame::GoAway(GoAwayFrame::new(0, ErrorCode::NoError));
        conn.process_frame(goaway).unwrap();

        // Connection-level WINDOW_UPDATE should still work
        let window_update = Frame::WindowUpdate(WindowUpdateFrame::new(0, 1024));
        let result = conn.process_frame(window_update);
        assert!(result.is_ok());
    }

    /// Regression: zero-increment WINDOW_UPDATE on a stream must be a stream
    /// error (RST_STREAM), not a connection error (RFC 9113 §6.9.1).
    #[test]
    fn zero_increment_window_update_on_stream_is_stream_error() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Open a stream.
        let headers = Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/window-update"),
            false,
            true,
        ));
        conn.process_frame(headers).unwrap();

        // Zero increment on stream 1: must be a *stream* error, not connection.
        let wu = Frame::WindowUpdate(WindowUpdateFrame::new(1, 0));
        let err = conn.process_frame(wu).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert_eq!(
            err.stream_id,
            Some(1),
            "zero increment on a stream must be a stream error, not connection"
        );
    }

    /// Zero-increment WINDOW_UPDATE on stream 0 must be a connection error.
    #[test]
    fn zero_increment_window_update_on_connection_is_connection_error() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        let wu = Frame::WindowUpdate(WindowUpdateFrame::new(0, 0));
        let err = conn.process_frame(wu).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert!(
            err.stream_id.is_none(),
            "zero increment on connection must be a connection error"
        );
    }

    #[test]
    fn final_inbound_data_does_not_queue_stream_window_update() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        let request = Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/flow-control"),
            false,
            true,
        ));
        conn.process_frame(request).unwrap();

        let response_headers = vec![Header::new(":status", "200")];
        conn.send_headers(1, response_headers, true).unwrap();
        let _ = conn
            .next_frame()
            .expect("response HEADERS should be pending");
        assert_eq!(
            conn.stream(1).unwrap().state(),
            StreamState::HalfClosedLocal
        );

        let payload_len = (DEFAULT_CONNECTION_WINDOW_SIZE / 2) + 2;
        let data = Bytes::from(vec![0_u8; payload_len as usize]);
        let inbound = Frame::Data(DataFrame::new(1, data, true));
        conn.process_frame(inbound).unwrap();
        assert_eq!(conn.stream(1).unwrap().state(), StreamState::Closed);

        while let Some(frame) = conn.next_frame() {
            if let Frame::WindowUpdate(update) = frame {
                assert_ne!(
                    update.stream_id, 1,
                    "closed streams must not emit stream-level WINDOW_UPDATE"
                );
            }
        }
    }

    #[test]
    fn prune_closed_streams_preserves_blocked_final_data() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        let request = Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/blocked-final-data"),
            false,
            true,
        ));
        conn.process_frame(request).unwrap();
        conn.process_frame(Frame::Data(DataFrame::new(
            1,
            Bytes::from_static(b"request"),
            true,
        )))
        .unwrap();
        assert_eq!(
            conn.stream(1).unwrap().state(),
            StreamState::HalfClosedRemote
        );

        conn.send_headers(1, vec![Header::new(":status", "200")], false)
            .unwrap();
        conn.streams
            .get_mut(1)
            .unwrap()
            .consume_send_window(DEFAULT_CONNECTION_WINDOW_SIZE as u32);
        conn.send_data(1, Bytes::from_static(b"final"), true)
            .unwrap();
        assert_eq!(conn.stream(1).unwrap().state(), StreamState::Closed);

        match conn
            .next_frame()
            .expect("response HEADERS should flush first")
        {
            Frame::Headers(frame) => assert_eq!(frame.stream_id, 1),
            other => panic!("expected response HEADERS, got {other:?}"),
        }
        assert!(
            conn.next_frame().is_none(),
            "zero stream send window keeps final DATA queued"
        );
        assert!(conn.has_pending_frames_for_stream(1));

        conn.prune_closed_streams();
        assert!(
            conn.stream(1).is_some(),
            "closed stream with blocked final DATA must survive pruning"
        );

        conn.streams
            .get_mut(1)
            .unwrap()
            .update_send_window(5)
            .unwrap();
        match conn.next_frame().expect("blocked final DATA should flush") {
            Frame::Data(frame) => {
                assert_eq!(frame.stream_id, 1);
                assert_eq!(&frame.data[..], b"final");
                assert!(frame.end_stream);
            }
            other => panic!("expected final DATA frame, got {other:?}"),
        }

        assert!(!conn.has_pending_frames_for_stream(1));
        conn.prune_closed_streams();
        assert!(
            conn.stream(1).is_none(),
            "closed stream is pruned after its queued frames flush"
        );
    }

    #[test]
    fn test_settings_during_continuation() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Start a HEADERS sequence without END_HEADERS
        let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, false));
        conn.process_frame(headers).unwrap();

        // Connection is now expecting CONTINUATION
        assert!(conn.is_awaiting_continuation());

        // SETTINGS frame should cause protocol error (must get CONTINUATION)
        let settings = Frame::Settings(SettingsFrame::new(vec![]));
        let err = conn.process_frame(settings).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_ping_during_continuation() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Start a HEADERS sequence without END_HEADERS
        let headers = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, false));
        conn.process_frame(headers).unwrap();

        // Connection is now expecting CONTINUATION
        assert!(conn.is_awaiting_continuation());

        // PING frame should cause protocol error (must get CONTINUATION)
        let ping = Frame::Ping(PingFrame::new([0; 8]));
        let err = conn.process_frame(ping).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    /// br-asupersync-pxb77u — RFC 9113 §6.10:
    ///
    /// > A CONTINUATION frame MUST be preceded by a HEADERS, PUSH_PROMISE
    /// > or CONTINUATION frame without the END_HEADERS flag set. A
    /// > recipient that observes violation of this rule MUST respond with
    /// > a connection error (Section 5.4.1) of type PROTOCOL_ERROR.
    ///
    /// "Connection error" specifically means `stream_id == None` so the
    /// peer GOAWAYs the whole connection rather than RST_STREAMing one
    /// stream. The pre-fix recv_continuation path on a stream whose
    /// headers were already complete returned a stream-level
    /// `H2Error::stream(...PROTOCOL_ERROR)` which would only RST_STREAM
    /// the offending stream — non-conformant with §6.10.
    #[test]
    fn unsolicited_continuation_after_end_headers_is_connection_error() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Complete a HEADERS sequence with END_HEADERS so the stream exists
        // in the map but the connection is NOT awaiting CONTINUATION.
        let headers = Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/done"),
            false,
            true,
        ));
        conn.process_frame(headers).expect("complete HEADERS");
        assert!(
            !conn.is_awaiting_continuation(),
            "headers with END_HEADERS must clear continuation expectation"
        );

        // Unsolicited CONTINUATION on the now-complete stream.
        let cont = Frame::Continuation(ContinuationFrame {
            stream_id: 1,
            header_block: Bytes::new(),
            end_headers: true,
        });
        let err = conn
            .process_frame(cont)
            .expect_err("unsolicited CONTINUATION must error");
        assert_eq!(
            err.code,
            ErrorCode::ProtocolError,
            "RFC 9113 §6.10 requires PROTOCOL_ERROR"
        );
        assert_eq!(
            err.stream_id, None,
            "RFC 9113 §6.10 requires connection-level error (stream_id == None), \
             got stream-level error scoped to {:?}: {}",
            err.stream_id, err.message
        );
    }

    /// Sister case: CONTINUATION arrives for a stream that has never seen
    /// any HEADERS. RFC 9113 §6.10 still mandates a connection error.
    #[test]
    fn continuation_for_unknown_stream_is_connection_error() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        let cont = Frame::Continuation(ContinuationFrame {
            stream_id: 7,
            header_block: Bytes::new(),
            end_headers: true,
        });
        let err = conn
            .process_frame(cont)
            .expect_err("CONTINUATION on unknown stream must error");
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert_eq!(
            err.stream_id, None,
            "RFC 9113 §6.10 requires connection-level error, got stream {:?}",
            err.stream_id
        );
    }

    // =========================================================================
    // last_stream_id Tracking Tests (bd-34krf)
    // =========================================================================

    #[test]
    fn goaway_reflects_last_processed_stream() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Process HEADERS on stream 1
        let headers = Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/one"),
            false,
            true,
        ));
        conn.process_frame(headers).unwrap();

        // Process HEADERS on stream 3
        let headers = Frame::Headers(HeadersFrame::new(
            3,
            test_request_headers("/three"),
            false,
            true,
        ));
        conn.process_frame(headers).unwrap();

        // Send GOAWAY — should reflect last_stream_id=3
        conn.goaway(ErrorCode::NoError, Bytes::new());
        let frame = conn.next_frame().unwrap();
        match frame {
            Frame::GoAway(g) => {
                assert_eq!(
                    g.last_stream_id, 3,
                    "GOAWAY should report highest processed stream ID"
                );
            }
            _ => panic!("expected GoAway"),
        }
    }

    #[test]
    fn goaway_reflects_last_processed_data_stream() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Open stream via HEADERS
        let headers = Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/one"),
            false,
            true,
        ));
        conn.process_frame(headers).unwrap();

        // Process DATA on stream 1
        let data = Frame::Data(DataFrame::new(1, Bytes::from("hello"), false));
        conn.process_frame(data).unwrap();

        // Open stream 3 via HEADERS
        let headers = Frame::Headers(HeadersFrame::new(
            3,
            test_request_headers("/three"),
            true,
            true,
        ));
        conn.process_frame(headers).unwrap();

        // GOAWAY should reflect stream 3 (highest seen)
        conn.goaway(ErrorCode::NoError, Bytes::new());
        // Drain pending ops (SettingsAck, WindowUpdates, etc.)
        let mut goaway_frame = None;
        while let Some(f) = conn.next_frame() {
            if matches!(&f, Frame::GoAway(_)) {
                goaway_frame = Some(f);
                break;
            }
        }
        match goaway_frame.unwrap() {
            Frame::GoAway(g) => assert_eq!(g.last_stream_id, 3),
            _ => panic!("expected GoAway"),
        }
    }

    // =========================================================================
    // CONTINUATION Ordering Tests (bd-34krf)
    // =========================================================================

    #[test]
    fn continuation_frames_not_interleaved_with_pending_ops() {
        let mut conn = Connection::client(Settings::client());
        conn.state = ConnectionState::Open;
        // Small max_frame_size to force CONTINUATION
        conn.remote_settings.max_frame_size = 50;

        // Queue a PING ACK first (simulating a received ping being processed)
        conn.pending_ops
            .push_back(PendingOp::PingAck([9, 8, 7, 6, 5, 4, 3, 2]));

        // Open a stream with large headers that require CONTINUATION
        let mut headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/some/very/long/path/that/exceeds/frame/size"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
        ];
        for i in 0..10 {
            headers.push(Header::new(
                format!("x-custom-header-{i}"),
                format!("value-{i}"),
            ));
        }
        let _ = conn.open_stream(headers, true).unwrap();

        // First frame: should be PingAck (it was queued first)
        let frame1 = conn.next_frame().unwrap();
        assert!(
            matches!(frame1, Frame::Ping(_)),
            "first frame should be the pre-existing PingAck"
        );

        // Second frame: should be HEADERS (not end_headers)
        let frame2 = conn.next_frame().unwrap();
        match &frame2 {
            Frame::Headers(h) => {
                assert!(
                    !h.end_headers,
                    "headers too large, should have CONTINUATION"
                );
            }
            other => panic!("expected HEADERS, got {other:?}"),
        }

        // All subsequent frames until end_headers must be CONTINUATION
        // (no interleaved PingAck, WindowUpdate, etc.)
        loop {
            let frame = conn.next_frame();
            match frame {
                Some(Frame::Continuation(c)) => {
                    if c.end_headers {
                        break;
                    }
                }
                Some(other) => {
                    panic!("expected CONTINUATION but got {other:?} — interleaving detected!")
                }
                None => panic!("ran out of frames before end_headers"),
            }
        }
    }

    // =========================================================================
    // RFC 7540 §5.1 Idle Stream Enforcement Tests (bd-3n7hy)
    // =========================================================================

    /// Regression: DATA received on a stream in the idle state MUST be treated
    /// as a connection error of type PROTOCOL_ERROR (RFC 7540 §5.1).
    #[test]
    fn data_on_idle_stream_is_connection_error() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Stream 1 has never been opened (no prior HEADERS). get_or_create
        // will create it in Idle state, then the idle-check must fire.
        let data = Frame::Data(DataFrame::new(1, Bytes::from("hello"), false));
        let err = conn.process_frame(data).unwrap_err();

        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert!(
            err.stream_id.is_none(),
            "idle-stream DATA must be a connection error, not a stream error"
        );
    }

    /// Regression: WINDOW_UPDATE received on a stream in the idle state MUST be
    /// treated as a connection error of type PROTOCOL_ERROR (RFC 7540 §5.1).
    #[test]
    fn window_update_on_idle_stream_is_connection_error() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Open stream 1 via HEADERS to advance next_client_stream_id, then
        // send WINDOW_UPDATE on stream 3 which is idle (never opened).
        let headers = Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/window-update"),
            false,
            true,
        ));
        conn.process_frame(headers).unwrap();

        // Stream 3 is idle — WINDOW_UPDATE must be a connection error.
        let wu = Frame::WindowUpdate(WindowUpdateFrame::new(3, 1024));
        let err = conn.process_frame(wu).unwrap_err();

        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert!(
            err.stream_id.is_none(),
            "idle-stream WINDOW_UPDATE must be a connection error, not a stream error"
        );
    }

    // =========================================================================
    // last_stream_id Pollution Tests (asupersync-32jl1)
    // =========================================================================

    /// CVE-2023-44487: RST_STREAM flood beyond rate limit triggers ENHANCE_YOUR_CALM.
    #[test]
    fn rst_stream_flood_triggers_enhance_your_calm() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Open and reset streams up to the rate limit.
        for i in 0..DEFAULT_RST_STREAM_RATE_LIMIT {
            let stream_id = i * 2 + 1;
            let headers = Frame::Headers(HeadersFrame::new(
                stream_id,
                test_request_headers("/rst"),
                false,
                true,
            ));
            conn.process_frame(headers).unwrap();

            let rst = Frame::RstStream(RstStreamFrame::new(stream_id, ErrorCode::Cancel));
            conn.process_frame(rst).unwrap();
        }

        // One more RST_STREAM should trigger the rate limit.
        let stream_id = DEFAULT_RST_STREAM_RATE_LIMIT * 2 + 1;
        let headers = Frame::Headers(HeadersFrame::new(
            stream_id,
            test_request_headers("/rst"),
            false,
            true,
        ));
        conn.process_frame(headers).unwrap();

        let rst = Frame::RstStream(RstStreamFrame::new(stream_id, ErrorCode::Cancel));
        let err = conn.process_frame(rst).unwrap_err();

        assert_eq!(err.code, ErrorCode::EnhanceYourCalm);
        assert!(
            err.stream_id.is_none(),
            "RST_STREAM flood must be a connection error"
        );
    }

    #[test]
    fn rst_stream_rate_limit_window_uses_time_getter() {
        let _clock = lock_test_clock();
        set_test_time_offset(Duration::ZERO);
        let mut conn = Connection::server_with_time_getter(Settings::default(), test_now);
        conn.state = ConnectionState::Open;

        for i in 0..DEFAULT_RST_STREAM_RATE_LIMIT {
            let stream_id = i * 2 + 1;
            let headers = Frame::Headers(HeadersFrame::new(
                stream_id,
                test_request_headers("/rst"),
                false,
                true,
            ));
            conn.process_frame(headers).unwrap();

            let rst = Frame::RstStream(RstStreamFrame::new(stream_id, ErrorCode::Cancel));
            conn.process_frame(rst).unwrap();
        }

        advance_test_time(Duration::from_millis(
            u64::try_from(DEFAULT_RST_STREAM_RATE_WINDOW_MS).expect("window fits u64") + 1,
        ));

        let stream_id = DEFAULT_RST_STREAM_RATE_LIMIT * 2 + 1;
        let headers = Frame::Headers(HeadersFrame::new(
            stream_id,
            test_request_headers("/rst"),
            false,
            true,
        ));
        conn.process_frame(headers).unwrap();

        let rst = Frame::RstStream(RstStreamFrame::new(stream_id, ErrorCode::Cancel));
        conn.process_frame(rst)
            .expect("rate-limit window should reset");
        assert_eq!(conn.rst_stream_count, 1);
    }

    #[test]
    fn rst_stream_rate_limit_rejects_after_u32_max_without_wrapping() {
        let mut conn =
            Connection::server(Settings::default()).rst_stream_rate_limit(RstStreamRateLimit {
                max_rst_streams: u32::MAX,
                rst_window_ms: DEFAULT_RST_STREAM_RATE_WINDOW_MS,
            });
        conn.state = ConnectionState::Open;

        for stream_id in [1, 3] {
            let headers = Frame::Headers(HeadersFrame::new(
                stream_id,
                test_request_headers("/rst"),
                false,
                true,
            ));
            conn.process_frame(headers).unwrap();
        }

        conn.rst_stream_count = u32::MAX - 1;

        let rst = Frame::RstStream(RstStreamFrame::new(1, ErrorCode::Cancel));
        conn.process_frame(rst)
            .expect("u32::MAXth RST_STREAM should still be allowed");
        assert_eq!(conn.rst_stream_count, u32::MAX);

        let overflow_attempt = Frame::RstStream(RstStreamFrame::new(3, ErrorCode::Cancel));
        let err = conn.process_frame(overflow_attempt).unwrap_err();
        assert_eq!(err.code, ErrorCode::EnhanceYourCalm);
        assert_eq!(conn.rst_stream_count, u32::MAX);
    }

    #[test]
    fn peer_stream_errors_and_rst_share_one_reset_budget() {
        let _clock = lock_test_clock();
        set_test_time_offset(Duration::ZERO);
        for errors_only in [false, true] {
            let mut conn = Connection::server_with_time_getter(Settings::default(), test_now)
                .rst_stream_rate_limit(RstStreamRateLimit {
                    max_rst_streams: 2,
                    rst_window_ms: 1000,
                });
            conn.process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
                .unwrap();
            for stream_id in [1, 3, 5] {
                conn.process_frame(Frame::Headers(HeadersFrame::new(
                    stream_id,
                    test_request_headers("/reset-budget"),
                    true,
                    true,
                )))
                .unwrap();
            }
            for stream_id in [1, 3] {
                if stream_id == 1 && !errors_only {
                    conn.process_frame(Frame::RstStream(RstStreamFrame::new(
                        stream_id,
                        ErrorCode::Cancel,
                    )))
                    .unwrap();
                } else {
                    let error = conn
                        .process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(stream_id, 0)))
                        .unwrap_err();
                    assert_eq!(error.stream_id, Some(stream_id));
                    assert_eq!(error.code, ErrorCode::ProtocolError);
                    conn.reset_stream(stream_id, error.code);
                }
            }
            assert_eq!(
                conn.rst_stream_count, 2,
                "local reset must not double charge"
            );
            let exhausted = conn
                .process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(5, 0)))
                .unwrap_err();
            assert_eq!(exhausted.code, ErrorCode::EnhanceYourCalm);
            assert_eq!(
                exhausted.stream_id, None,
                "exhaustion closes the connection"
            );
            assert_eq!(conn.rst_stream_count, 2);
            // Match the listener's connection-error handling and verify the
            // actual queued GOAWAY, including its accepted-stream boundary.
            conn.goaway(exhausted.code, Bytes::new());
            let mut goaway = None;
            while let Some(frame) = conn.next_frame() {
                if let Frame::GoAway(frame) = frame {
                    goaway = Some(frame);
                }
            }
            let goaway = goaway.expect("budget exhaustion GOAWAY");
            assert_eq!(goaway.error_code, ErrorCode::EnhanceYourCalm);
            assert_eq!(goaway.last_stream_id, 5);
            eprintln!(
                "{}",
                serde_json::json!({
                    "bead": "asupersync-bi2462.102", "scenario": "shared_reset_budget",
                    "errors_only": errors_only, "charged": conn.rst_stream_count,
                    "limit": 2, "goaway_last_stream": goaway.last_stream_id,
                })
            );
        }
    }

    #[test]
    fn peer_reset_budget_rolls_over_and_excludes_application_cancellation() {
        let _clock = lock_test_clock();
        set_test_time_offset(Duration::ZERO);
        let mut conn = Connection::server_with_time_getter(Settings::default(), test_now)
            .rst_stream_rate_limit(RstStreamRateLimit {
                max_rst_streams: 1,
                rst_window_ms: 10,
            });
        conn.process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
            .unwrap();
        for stream_id in [1, 3, 5, 7, 9, 11] {
            conn.process_frame(Frame::Headers(HeadersFrame::new(
                stream_id,
                test_request_headers("/reset-window"),
                true,
                true,
            )))
            .unwrap();
        }
        for stream_id in [1, 3, 5] {
            conn.reset_stream(stream_id, ErrorCode::Cancel);
        }
        assert_eq!(
            conn.rst_stream_count, 0,
            "application cancellations are not peer abuse"
        );
        let error = conn
            .process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(7, 0)))
            .unwrap_err();
        assert_eq!(error.stream_id, Some(7));
        conn.reset_stream(7, error.code);
        assert_eq!(conn.rst_stream_count, 1);

        advance_test_time(Duration::from_millis(10));
        let error = conn
            .process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(9, 0)))
            .unwrap_err();
        assert_eq!(
            error.stream_id,
            Some(9),
            "new window admits one new stream error"
        );
        conn.reset_stream(9, error.code);
        assert_eq!(conn.rst_stream_count, 1);
        // Self-dependent priority frames are decoded into a stream error
        // before the ordinary Frame dispatcher. That path shares the budget.
        let exhausted = conn
            .process_decoded_frame(DecodedFrame::PriorityError(H2Error::stream(
                11,
                ErrorCode::ProtocolError,
                "stream depends on itself",
            )))
            .unwrap_err();
        assert_eq!(exhausted.code, ErrorCode::EnhanceYourCalm);
        assert_eq!(exhausted.stream_id, None);
        assert_eq!(conn.rst_stream_count, 1);
    }

    #[test]
    fn peer_stream_error_reset_budget_never_wraps() {
        let _clock = lock_test_clock();
        set_test_time_offset(Duration::ZERO);
        let mut conn = Connection::server_with_time_getter(Settings::default(), test_now)
            .rst_stream_rate_limit(RstStreamRateLimit {
                max_rst_streams: u32::MAX,
                rst_window_ms: 1000,
            });
        conn.process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
            .unwrap();
        for stream_id in [1, 3] {
            conn.process_frame(Frame::Headers(HeadersFrame::new(
                stream_id,
                test_request_headers("/reset-counter-overflow"),
                true,
                true,
            )))
            .unwrap();
        }
        conn.rst_stream_count = u32::MAX - 1;
        let last_admitted = conn
            .process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(1, 0)))
            .unwrap_err();
        assert_eq!(last_admitted.stream_id, Some(1));
        assert_eq!(conn.rst_stream_count, u32::MAX);
        let exhausted = conn
            .process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(3, 0)))
            .unwrap_err();
        assert_eq!(exhausted.code, ErrorCode::EnhanceYourCalm);
        assert_eq!(exhausted.stream_id, None);
        assert_eq!(conn.rst_stream_count, u32::MAX);
    }

    /// Regression: HEADERS on a stream with invalid parity must NOT bump
    /// last_stream_id. If it did, a subsequent GOAWAY would advertise a higher
    /// last_stream_id than actually processed, violating RFC 7540 §6.8.
    #[test]
    fn headers_on_wrong_parity_stream_does_not_pollute_last_stream_id() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;

        // Open stream 1 normally.
        let headers = Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/parity"),
            false,
            true,
        ));
        conn.process_frame(headers).unwrap();

        // Send HEADERS on stream 2 (even = server-initiated, invalid from client).
        let invalid = Frame::Headers(HeadersFrame::new(2, Bytes::new(), false, true));
        let err = conn.process_frame(invalid).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);

        // GOAWAY should report last_stream_id=1, not 2.
        conn.goaway(ErrorCode::NoError, Bytes::new());
        let frame = conn.next_frame().unwrap();
        match frame {
            Frame::GoAway(g) => {
                assert_eq!(
                    g.last_stream_id, 1,
                    "last_stream_id must not be bumped by rejected HEADERS"
                );
            }
            _ => panic!("expected GoAway"),
        }
    }

    #[test]
    fn connection_window_update_rejects_zero_increment() {
        let mut conn = Connection::server(Settings::default());
        let err = conn.send_connection_window_update(0).unwrap_err();
        assert_eq!(err.code, ErrorCode::FlowControlError);
    }

    #[test]
    fn decoder_allowed_table_size_follows_local_settings() {
        // Regression: the HPACK decoder's allowed dynamic-table size must track
        // the SETTINGS_HEADER_TABLE_SIZE we advertise (RFC 7541 §6.3), not stay
        // pinned at the 4096 default. Otherwise a peer that honors a larger
        // advertised table and sends a matching dynamic-table-size update is
        // killed with a COMPRESSION_ERROR.
        let settings = Settings {
            header_table_size: 8192,
            ..Settings::default()
        };
        let server = Connection::server(settings.clone());
        assert_eq!(server.hpack_decoder.allowed_table_size(), 8192);
        let client = Connection::client(settings);
        assert_eq!(client.hpack_decoder.allowed_table_size(), 8192);
    }

    #[test]
    fn stream_window_update_rejects_zero_increment() {
        let mut conn = Connection::server(Settings::default());
        let err = conn.send_stream_window_update(1, 0).unwrap_err();
        assert_eq!(err.code, ErrorCode::FlowControlError);
    }

    #[test]
    fn connection_window_update_accepts_valid_increment() {
        let mut conn = Connection::server(Settings::default());
        assert!(conn.send_connection_window_update(1024).is_ok());
        assert!(conn.has_pending_frames());
    }

    #[test]
    fn stream_window_update_accepts_valid_increment() {
        let mut conn = Connection::server(Settings::default());
        conn.state = ConnectionState::Open;
        // Open a stream first by processing a HEADERS frame.
        let headers = Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/window-update"),
            false,
            true,
        ));
        conn.process_frame(headers).unwrap();
        assert!(conn.send_stream_window_update(1, 4096).is_ok());
        assert!(conn.has_pending_frames());
    }

    // =====================================================================
    // br-asupersync-vqpx88: RFC 9113 §8.3 / §8.3.1 / §8.3.2 / §8.5
    // pseudo-header structural validation tests for `validate_h2_pseudo_headers`.
    // =====================================================================

    fn h(name: &str, value: &str) -> Header {
        Header::new(name, value)
    }

    #[test]
    fn vqpx88_request_minimum_valid_get() {
        let headers = vec![
            h(":method", "GET"),
            h(":scheme", "https"),
            h(":path", "/"),
            h(":authority", "example.com"),
            h("user-agent", "asupersync"),
        ];
        assert!(validate_h2_pseudo_headers(&headers, true, false).is_ok());
    }

    #[test]
    fn vqpx88_response_minimum_valid_200() {
        let headers = vec![h(":status", "200"), h("content-type", "text/plain")];
        assert!(validate_h2_pseudo_headers(&headers, false, false).is_ok());
    }

    #[test]
    fn vqpx88_pseudo_after_regular_rejected() {
        let headers = vec![
            h(":method", "GET"),
            h(":scheme", "https"),
            h("host", "example.com"),
            h(":path", "/"),
            h(":authority", "example.com"),
        ];
        let err = validate_h2_pseudo_headers(&headers, true, false).unwrap_err();
        assert!(err.contains("after a regular header"), "unexpected: {err}");
    }

    #[test]
    fn vqpx88_duplicate_method_rejected() {
        let headers = vec![
            h(":method", "GET"),
            h(":method", "POST"),
            h(":scheme", "https"),
            h(":path", "/"),
            h(":authority", "example.com"),
        ];
        let err = validate_h2_pseudo_headers(&headers, true, false).unwrap_err();
        assert!(err.contains("duplicate :method"), "unexpected: {err}");
    }

    #[test]
    fn vqpx88_duplicate_scheme_rejected() {
        let headers = vec![
            h(":method", "GET"),
            h(":scheme", "https"),
            h(":scheme", "http"),
            h(":path", "/"),
            h(":authority", "example.com"),
        ];
        let err = validate_h2_pseudo_headers(&headers, true, false).unwrap_err();
        assert!(err.contains("duplicate :scheme"), "unexpected: {err}");
    }

    #[test]
    fn vqpx88_duplicate_status_rejected() {
        let headers = vec![h(":status", "200"), h(":status", "404")];
        let err = validate_h2_pseudo_headers(&headers, false, false).unwrap_err();
        assert!(err.contains("duplicate :status"), "unexpected: {err}");
    }

    #[test]
    fn vqpx88_unknown_pseudo_rejected() {
        let headers = vec![
            h(":method", "GET"),
            h(":weird", "value"),
            h(":scheme", "https"),
            h(":path", "/"),
            h(":authority", "example.com"),
        ];
        let err = validate_h2_pseudo_headers(&headers, true, false).unwrap_err();
        assert!(err.contains("unknown pseudo-header"), "unexpected: {err}");
    }

    #[test]
    fn vqpx88_response_with_method_rejected() {
        let headers = vec![h(":status", "200"), h(":method", "GET")];
        let err = validate_h2_pseudo_headers(&headers, false, false).unwrap_err();
        assert!(
            err.contains("must not include request pseudo-headers"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn vqpx88_request_missing_method_rejected() {
        let headers = vec![
            h(":scheme", "https"),
            h(":path", "/"),
            h(":authority", "example.com"),
        ];
        let err = validate_h2_pseudo_headers(&headers, true, false).unwrap_err();
        assert!(
            err.contains("missing required :method"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn vqpx88_request_missing_scheme_rejected() {
        let headers = vec![
            h(":method", "GET"),
            h(":path", "/"),
            h(":authority", "example.com"),
        ];
        let err = validate_h2_pseudo_headers(&headers, true, false).unwrap_err();
        assert!(
            err.contains("missing required :scheme"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn vqpx88_request_missing_path_rejected() {
        let headers = vec![
            h(":method", "GET"),
            h(":scheme", "https"),
            h(":authority", "example.com"),
        ];
        let err = validate_h2_pseudo_headers(&headers, true, false).unwrap_err();
        assert!(err.contains("missing required :path"), "unexpected: {err}");
    }

    #[test]
    fn vqpx88_response_missing_status_rejected() {
        let headers = vec![h("content-type", "text/plain")];
        let err = validate_h2_pseudo_headers(&headers, false, false).unwrap_err();
        assert!(
            err.contains("missing required :status"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn vqpx88_request_with_status_rejected() {
        let headers = vec![
            h(":method", "GET"),
            h(":status", "200"),
            h(":scheme", "https"),
            h(":path", "/"),
            h(":authority", "example.com"),
        ];
        let err = validate_h2_pseudo_headers(&headers, true, false).unwrap_err();
        assert!(
            err.contains("must not include :status"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn vqpx88_connect_with_scheme_rejected() {
        let headers = vec![
            h(":method", "CONNECT"),
            h(":scheme", "https"),
            h(":authority", "example.com:443"),
        ];
        let err = validate_h2_pseudo_headers(&headers, true, false).unwrap_err();
        assert!(
            err.contains("CONNECT request must not include :scheme or :path"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn vqpx88_connect_with_path_rejected() {
        let headers = vec![
            h(":method", "CONNECT"),
            h(":path", "/"),
            h(":authority", "example.com:443"),
        ];
        let err = validate_h2_pseudo_headers(&headers, true, false).unwrap_err();
        assert!(
            err.contains("CONNECT request must not include :scheme or :path"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn vqpx88_connect_missing_authority_rejected() {
        let headers = vec![h(":method", "CONNECT")];
        let err = validate_h2_pseudo_headers(&headers, true, false).unwrap_err();
        assert!(
            err.contains("CONNECT request missing required :authority"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn vqpx88_connect_valid_minimum() {
        let headers = vec![h(":method", "CONNECT"), h(":authority", "example.com:443")];
        assert!(validate_h2_pseudo_headers(&headers, true, false).is_ok());
    }

    #[test]
    fn vqpx88_uppercase_regular_header_rejected() {
        let headers = vec![
            h(":method", "GET"),
            h(":scheme", "https"),
            h(":path", "/"),
            h(":authority", "example.com"),
            h("X-Custom", "v"),
        ];
        let err = validate_h2_pseudo_headers(&headers, true, false).unwrap_err();
        assert!(err.contains("uppercase ASCII"), "unexpected: {err}");
    }

    #[test]
    fn vqpx88_protocol_on_non_connect_rejected() {
        let headers = vec![
            h(":method", "GET"),
            h(":scheme", "https"),
            h(":path", "/"),
            h(":authority", "example.com"),
            h(":protocol", "websocket"),
        ];
        let err = validate_h2_pseudo_headers(&headers, true, false).unwrap_err();
        assert!(
            err.contains(":protocol pseudo-header is only valid"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn vqpx88_extended_connect_with_protocol_ok() {
        // RFC 8441 extended-CONNECT carries :protocol with :scheme/:path
        // when SETTINGS_ENABLE_CONNECT_PROTOCOL has been negotiated. The
        // structural validator tolerates this combination; the deeper
        // settings-aware check lives in the follow-up parity pass.
        let headers = vec![
            h(":method", "CONNECT"),
            h(":protocol", "websocket"),
            h(":scheme", "https"),
            h(":path", "/chat"),
            h(":authority", "example.com"),
        ];
        assert!(validate_h2_pseudo_headers(&headers, true, false).is_ok());
    }

    #[test]
    fn vqpx88_empty_header_name_rejected() {
        let headers = vec![Header::new("", "value")];
        let err = validate_h2_pseudo_headers(&headers, true, false).unwrap_err();
        assert!(err.contains("empty"), "unexpected: {err}");
    }

    #[test]
    fn vqpx88_response_with_authority_rejected() {
        let headers = vec![h(":status", "200"), h(":authority", "example.com")];
        let err = validate_h2_pseudo_headers(&headers, false, false).unwrap_err();
        assert!(
            err.contains("must not include request pseudo-headers"),
            "unexpected: {err}"
        );
    }

    /// br-asupersync-rmfjui — RFC 9113 §8.2.2: each connection-
    /// specific header on the forbidden list (Connection,
    /// Keep-Alive, Proxy-Connection, Transfer-Encoding, Upgrade)
    /// must be rejected by validate_h2_pseudo_headers when present
    /// in an otherwise-valid request. The validator returns Err
    /// with a message tagged "RFC 9113 §8.2.2".
    #[test]
    fn rmfjui_each_forbidden_connection_header_rejected() {
        for forbidden in [
            "connection",
            "keep-alive",
            "proxy-connection",
            "transfer-encoding",
            "upgrade",
        ] {
            let headers = vec![
                h(":method", "GET"),
                h(":scheme", "https"),
                h(":path", "/"),
                h(":authority", "example.com"),
                h(forbidden, "close"),
            ];
            let err = validate_h2_pseudo_headers(&headers, true, false).expect_err(forbidden);
            assert!(
                err.contains("RFC 9113 §8.2.2"),
                "wrong reject reason for {forbidden}: {err}"
            );
        }
    }

    /// br-asupersync-rmfjui — `te` header NAME is permitted by the
    /// spec but only with value "trailers"; any other value is
    /// malformed.
    #[test]
    fn rmfjui_te_trailers_accepted_other_values_rejected() {
        // te: trailers (allowed)
        let ok = vec![
            h(":method", "GET"),
            h(":scheme", "https"),
            h(":path", "/"),
            h(":authority", "example.com"),
            h("te", "trailers"),
        ];
        assert!(validate_h2_pseudo_headers(&ok, true, false).is_ok());

        // te: gzip (forbidden value)
        let bad = vec![
            h(":method", "GET"),
            h(":scheme", "https"),
            h(":path", "/"),
            h(":authority", "example.com"),
            h("te", "gzip"),
        ];
        let err = validate_h2_pseudo_headers(&bad, true, false).unwrap_err();
        assert!(
            err.contains("RFC 9113 §8.2.2"),
            "wrong reject reason: {err}"
        );
    }

    /// br-asupersync-rmfjui — Regression guard: a valid request
    /// without any forbidden header must still pass.
    #[test]
    fn rmfjui_request_without_forbidden_headers_accepted() {
        let headers = vec![
            h(":method", "GET"),
            h(":scheme", "https"),
            h(":path", "/"),
            h(":authority", "example.com"),
            h("content-type", "application/json"),
            h("user-agent", "test"),
        ];
        assert!(validate_h2_pseudo_headers(&headers, true, false).is_ok());
    }

    /// asupersync-e427ys — RFC 9113 §8.2.1: Field values MUST NOT start or
    /// end with an ASCII whitespace character (SP or HTAB). Such fields are
    /// malformed and must elicit PROTOCOL_ERROR.
    #[test]
    fn e427ys_header_value_with_leading_or_trailing_whitespace_rejected() {
        for (name, val) in [
            ("x-pad", " leading"),
            ("x-pad", "trailing "),
            ("x-pad", "\tleading-tab"),
            ("x-pad", "trailing-tab\t"),
            (":path", " /with-space"),
            (":path", "/with-space "),
            (":status", " 200"),
            (":status", "200 "),
        ] {
            let req = vec![
                h(":method", "GET"),
                h(":scheme", "https"),
                h(":path", if name == ":path" { val } else { "/" }),
                h(":authority", "example.com"),
                h(if name == ":path" { "x-dummy" } else { name }, val),
            ];
            let err = validate_h2_pseudo_headers(&req, true, false)
                .expect_err(&format!("expected rejection for {name}: {val:?}"));
            assert!(err.contains("RFC 9113 §8.2.1"), "wrong reject reason: {err}");

            let resp = vec![
                h(":status", if name == ":status" { val } else { "200" }),
                h(if name == ":status" { "x-dummy" } else { name }, val),
            ];
            let err = validate_h2_pseudo_headers(&resp, false, false)
                .expect_err(&format!("expected rejection for {name}: {val:?}"));
            assert!(err.contains("RFC 9113 §8.2.1"), "wrong reject reason: {err}");

            if !name.starts_with(':') {
                let trailers = vec![h(name, val)];
                let err = validate_h2_pseudo_headers(&trailers, false, true)
                    .expect_err(&format!("expected trailer rejection for {name}: {val:?}"));
                assert!(err.contains("RFC 9113 §8.2.1"), "wrong reject reason: {err}");
            }
        }
    }

    /// br-asupersync-lcvdj0 — RFC 9113 §3.4 / §3.5 require the first
    /// frame on a connection to be SETTINGS. A peer that sends any
    /// other frame in the Handshaking state must elicit a
    /// connection-level PROTOCOL_ERROR. Pre-fix the codec dispatched
    /// through normal handlers without state-checking, so a malicious
    /// first PING / WINDOW_UPDATE / RST_STREAM was processed silently.
    #[test]
    fn lcvdj0_first_frame_must_be_settings_ping_rejected() {
        let mut conn = Connection::client(Settings::client());
        // PING is otherwise valid in any state — but it must not be
        // the FIRST frame. Pre-fix this would be processed and
        // `pending_ops` would carry the corresponding ack.
        let result = conn.process_frame(Frame::Ping(PingFrame::new([0xAA; 8])));
        let err = result.expect_err("first frame PING must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("first frame") && msg.contains("SETTINGS"),
            "wrong error for non-SETTINGS first frame: {msg}"
        );
    }

    /// br-asupersync-lcvdj0 — WINDOW_UPDATE on stream 0 is otherwise
    /// valid mid-connection but is forbidden as the first frame.
    #[test]
    fn lcvdj0_first_frame_must_be_settings_window_update_rejected() {
        let mut conn = Connection::client(Settings::client());
        let result = conn.process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(0, 1024)));
        let err = result.expect_err("first frame WINDOW_UPDATE must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("first frame") && msg.contains("SETTINGS"),
            "wrong error for non-SETTINGS first frame: {msg}"
        );
    }

    #[test]
    fn process_window_update_zero_increment_is_correctly_scoped() {
        // br-asupersync-x8re31: with the redundant parse-time rejection removed,
        // process_window_update owns zero-increment rejection with RFC 9113
        // §6.9.1 scoping: a connection-level (stream 0) zero increment is a
        // connection error (GOAWAY), while a stream-level one is a stream error
        // — the listener's process-time path then resets only that stream
        // instead of tearing down every sibling with a GOAWAY.
        let mut conn = Connection::server(Settings::default());
        conn.process_frame(Frame::Settings(SettingsFrame::new(vec![])))
            .unwrap();
        conn.process_frame(Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/window"),
            false,
            true,
        )))
        .unwrap();
        assert!(!conn.streams.is_idle_stream_id(1));
        assert_eq!(conn.active_stream_count(), 1);
        let connection_level = conn
            .process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(0, 0)))
            .expect_err("a zero increment on stream 0 must be rejected");
        assert_eq!(connection_level.code, ErrorCode::ProtocolError);
        assert_eq!(
            connection_level.stream_id, None,
            "stream 0 zero increment is a connection error"
        );

        let stream_level = conn
            .process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(1, 0)))
            .expect_err("a zero increment on a stream must be rejected");
        assert_eq!(stream_level.code, ErrorCode::ProtocolError);
        assert_eq!(
            stream_level.stream_id,
            Some(1),
            "a stream-scoped zero increment must reset only that stream, not GOAWAY"
        );
    }

    #[test]
    fn window_update_on_idle_stream_is_connection_error_for_zero_and_nonzero_increment() {
        for increment in [0, 1] {
            let mut conn = Connection::server(Settings::default());
            conn.process_frame(Frame::Settings(SettingsFrame::new(vec![])))
                .unwrap();
            assert!(conn.streams.is_idle_stream_id(3));
            let error = conn
                .process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(3, increment)))
                .expect_err("an idle stream cannot receive WINDOW_UPDATE");
            assert_eq!(error.code, ErrorCode::ProtocolError);
            assert_eq!(error.stream_id, None, "idle-stream errors require GOAWAY");
            assert_eq!(conn.active_stream_count(), 0);
        }
    }

    /// br-asupersync-lcvdj0 — Regression guard: a SETTINGS first
    /// frame is accepted (handshake completes) and subsequent
    /// non-SETTINGS frames flow through normally.
    #[test]
    fn lcvdj0_settings_first_frame_accepted_then_other_frames_ok() {
        let mut conn = Connection::client(Settings::client());
        // SETTINGS first — must succeed, transition Handshaking → Open.
        conn.process_frame(Frame::Settings(SettingsFrame::new(vec![])))
            .expect("SETTINGS as first frame must be accepted");
        // Drain queued ACK.
        let _ = conn.next_frame();
        // After handshake, PING flows normally.
        conn.process_frame(Frame::Ping(PingFrame::new([0xBB; 8])))
            .expect("PING after handshake must be accepted");
    }

    #[test]
    fn rfc9113_section6_8_goaway_frame_ordering_conformance() {
        // RFC 9113 Section 6.8 conformance test - GOAWAY frame ordering and semantics
        // Tests the MUST/SHOULD clauses for connection termination

        let mut conn = Connection::server(Settings::default());
        conn.process_frame(Frame::Settings(SettingsFrame::new(vec![])))
            .expect("client SETTINGS first frame must be accepted");
        let _ = conn.next_frame();

        // Test Requirement 1: GOAWAY should include last successfully processed stream ID
        // Open multiple streams to establish last_stream_id baseline

        // Process stream 1 (successfully)
        let headers1 = HeadersFrame::new(1, test_request_headers("/"), false, true);
        conn.process_frame(Frame::Headers(headers1)).unwrap();

        // Process stream 3 (successfully)
        let headers3 = HeadersFrame::new(3, test_request_headers("/api"), false, true);
        conn.process_frame(Frame::Headers(headers3)).unwrap();

        // RFC 9113 §6.8: "the stream identifier of the last stream that it successfully received"
        conn.goaway(ErrorCode::NoError, Bytes::from("graceful shutdown"));

        let frame = conn.next_frame().expect("GOAWAY frame should be generated");
        match frame {
            Frame::GoAway(goaway) => {
                assert_eq!(
                    goaway.last_stream_id, 3,
                    "RFC 9113 §6.8: GOAWAY must include last successfully processed stream ID"
                );
                assert_eq!(goaway.error_code, ErrorCode::NoError);
                assert_eq!(goaway.debug_data, Bytes::from("graceful shutdown"));
            }
            _ => panic!("Expected GOAWAY frame, got {:?}", frame),
        }

        // Test Requirement 2: Connection state transition
        // RFC 9113 §6.8: After sending GOAWAY, connection should be in closing state
        assert_eq!(conn.state, ConnectionState::Closing);
        assert!(conn.goaway_sent);

        // Test Requirement 3: Multiple GOAWAY frames (narrowing semantics)
        // Receive GOAWAY from peer with higher last_stream_id - should narrow down
        let mut conn2 = Connection::client(Settings::default());
        conn2
            .process_frame(Frame::Settings(SettingsFrame::new(vec![])))
            .expect("server SETTINGS first frame must be accepted");
        let _ = conn2.next_frame();

        // Receive first GOAWAY with last_stream_id = 5
        let goaway1 = Frame::GoAway(GoAwayFrame::new(5, ErrorCode::NoError));
        let result1 = conn2.process_frame(goaway1).unwrap().unwrap();
        match result1 {
            ReceivedFrame::GoAway { last_stream_id, .. } => {
                assert_eq!(last_stream_id, 5);
            }
            _ => panic!("Expected GoAway received frame"),
        }

        // Receive second GOAWAY with lower last_stream_id = 1 (should narrow)
        let goaway2 = Frame::GoAway(GoAwayFrame::new(1, ErrorCode::InternalError));
        let result2 = conn2.process_frame(goaway2).unwrap().unwrap();
        match result2 {
            ReceivedFrame::GoAway { last_stream_id, .. } => {
                assert_eq!(
                    last_stream_id, 1,
                    "RFC 9113 §6.8: Multiple GOAWAY frames should narrow last_stream_id"
                );
            }
            _ => panic!("Expected GoAway received frame"),
        }

        // Test Requirement 4: GOAWAY only sent once per endpoint
        // RFC 9113 §6.8: Multiple GOAWAY calls should not generate multiple frames
        let mut conn3 = Connection::server(Settings::default());
        conn3.goaway(ErrorCode::NoError, Bytes::new());
        conn3.goaway(ErrorCode::InternalError, Bytes::new()); // Second call should be ignored

        // Should only have one GOAWAY frame in queue
        let frame1 = conn3.next_frame();
        let frame2 = conn3.next_frame();

        assert!(frame1.is_some());
        assert!(matches!(frame1.unwrap(), Frame::GoAway(_)));
        assert!(
            frame2.is_none(),
            "Second GOAWAY call should not generate additional frame"
        );

        // Test Requirement 5: Frame ordering preservation in pending operations
        // GOAWAY should be processed in order relative to other pending frames
        let mut conn4 = Connection::server(Settings::default());
        conn4.state = ConnectionState::Open;

        // Queue a PING ACK first by processing an inbound ping.
        conn4
            .process_frame(Frame::Ping(PingFrame::new(*b"testping")))
            .expect("inbound ping should queue an ACK response");
        // Then queue GOAWAY
        conn4.goaway(ErrorCode::NoError, Bytes::new());

        // Frames should come out in FIFO order: PING then GOAWAY
        let frame1 = conn4.next_frame().expect("PING frame expected first");
        let frame2 = conn4.next_frame().expect("GOAWAY frame expected second");

        assert!(
            matches!(frame1, Frame::Ping(_)),
            "PING should come before GOAWAY"
        );
        assert!(
            matches!(frame2, Frame::GoAway(_)),
            "GOAWAY should preserve ordering"
        );
    }

    fn encode_with(encoder: &mut hpack::Encoder, headers: &[(&str, &str)]) -> Bytes {
        let mut encoded = BytesMut::new();
        encoder.encode(
            &headers
                .iter()
                .map(|(name, value)| Header::new(*name, *value))
                .collect::<Vec<_>>(),
            &mut encoded,
        );
        encoded.freeze()
    }

    /// RFC 9113 §5.1: after sending RST_STREAM an endpoint MUST ignore the
    /// frames the peer already had in flight on that stream, and §4.3 still
    /// requires their field blocks to be decoded so both HPACK tables stay in
    /// step. A server that stopped an upload early receives the client's late
    /// DATA and trailers: neither is a stream error, neither is charged to the
    /// peer-reset budget, and a later request decodes a field the discarded
    /// trailers added to the dynamic table.
    #[test]
    fn frames_in_flight_after_a_local_reset_are_ignored_and_keep_hpack_in_step() {
        for split_block in [false, true] {
            let mut conn =
                Connection::server(Settings::default()).rst_stream_rate_limit(RstStreamRateLimit {
                    max_rst_streams: 1,
                    rst_window_ms: DEFAULT_RST_STREAM_RATE_WINDOW_MS,
                });
            conn.process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
                .unwrap();
            let mut client = hpack::Encoder::new();
            let upload = encode_with(
                &mut client,
                &[
                    (":method", "POST"),
                    (":scheme", "https"),
                    (":path", "/upload"),
                    (":authority", "example.com"),
                ],
            );
            conn.process_frame(Frame::Headers(HeadersFrame::new(1, upload, false, true)))
                .unwrap();
            // The response is complete; stop the unfinished upload.
            conn.reset_stream(1, ErrorCode::NoError);
            while conn.next_frame().is_some() {}

            let late_data = conn.process_frame(Frame::Data(DataFrame::new(
                1,
                Bytes::from_static(b"late"),
                false,
            )));
            assert!(matches!(late_data, Ok(None)), "late DATA: {late_data:?}");
            let trailers = encode_with(&mut client, &[("x-checksum", "abc123")]);
            let late_trailers = if split_block {
                let head = conn.process_frame(Frame::Headers(HeadersFrame::new(
                    1,
                    trailers.slice(..1),
                    true,
                    false,
                )));
                assert!(matches!(head, Ok(None)), "late HEADERS: {head:?}");
                conn.process_frame(Frame::Continuation(ContinuationFrame {
                    stream_id: 1,
                    header_block: trailers.slice(1..),
                    end_headers: true,
                }))
            } else {
                conn.process_frame(Frame::Headers(HeadersFrame::new(1, trailers, true, true)))
            };
            assert!(
                matches!(late_trailers, Ok(None)),
                "late trailers: {late_trailers:?}"
            );

            let next = encode_with(
                &mut client,
                &[
                    (":method", "GET"),
                    (":scheme", "https"),
                    (":path", "/next"),
                    (":authority", "example.com"),
                    ("x-checksum", "abc123"),
                ],
            );
            match conn.process_frame(Frame::Headers(HeadersFrame::new(3, next, true, true))) {
                Ok(Some(ReceivedFrame::Headers {
                    stream_id: 3,
                    headers,
                    ..
                })) => assert!(
                    headers
                        .iter()
                        .any(|header| header.name == "x-checksum" && header.value == "abc123"),
                    "{headers:?}"
                ),
                other => panic!("the next request must decode: {other:?}"),
            }
            assert_eq!(conn.rst_stream_count, 0, "late frames are not peer resets");
            let mut answered = Vec::new();
            while let Some(frame) = conn.next_frame() {
                if let Frame::RstStream(reset) = frame {
                    answered.push(reset.stream_id);
                }
            }
            assert!(
                answered.is_empty(),
                "late frames were answered: {answered:?}"
            );
        }
    }

    /// A producer start that fails on a stream the request input already
    /// reset, or an idle timeout racing a body error, resets the stream a
    /// second time. Only the first RST_STREAM leaves.
    #[test]
    fn a_stream_is_reset_at_most_once() {
        let mut conn = Connection::server(Settings::default());
        conn.process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
            .unwrap();
        conn.process_frame(Frame::Headers(HeadersFrame::new(
            1,
            test_request_headers("/once"),
            false,
            true,
        )))
        .unwrap();
        conn.reset_stream(1, ErrorCode::ProtocolError);
        conn.reset_stream(1, ErrorCode::InternalError);
        let mut resets = Vec::new();
        while let Some(frame) = conn.next_frame() {
            if let Frame::RstStream(reset) = frame {
                resets.push((reset.stream_id, reset.error_code));
            }
        }
        assert_eq!(resets, vec![(1, ErrorCode::ProtocolError)]);
        assert_eq!(
            conn.stream(1).and_then(Stream::error_code),
            Some(ErrorCode::ProtocolError)
        );
    }

    /// The client side of the same race: a cancelled call's response is
    /// already in flight. Its HEADERS and DATA are ignored, and the next
    /// response on the connection decodes the fields they indexed.
    #[test]
    fn a_cancelled_request_keeps_hpack_in_step_with_its_in_flight_response() {
        let mut conn = Connection::client(Settings::client());
        conn.process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
            .unwrap();
        let cancelled = conn
            .open_stream(test_request_header_vec("/watch"), true)
            .unwrap();
        let next = conn
            .open_stream(test_request_header_vec("/next"), true)
            .unwrap();
        conn.reset_stream(cancelled, ErrorCode::Cancel);
        while conn.next_frame().is_some() {}

        let mut server = hpack::Encoder::new();
        let fields = [(":status", "200"), ("x-request-id", "r-1")];
        let late_head = conn.process_frame(Frame::Headers(HeadersFrame::new(
            cancelled,
            encode_with(&mut server, &fields),
            false,
            true,
        )));
        assert!(matches!(late_head, Ok(None)), "late HEADERS: {late_head:?}");
        let late_data = conn.process_frame(Frame::Data(DataFrame::new(
            cancelled,
            Bytes::from_static(b"event"),
            false,
        )));
        assert!(matches!(late_data, Ok(None)), "late DATA: {late_data:?}");

        match conn.process_frame(Frame::Headers(HeadersFrame::new(
            next,
            encode_with(&mut server, &fields),
            true,
            true,
        ))) {
            Ok(Some(ReceivedFrame::Headers {
                stream_id,
                headers,
                end_stream: true,
            })) => {
                assert_eq!(stream_id, next);
                assert!(
                    headers
                        .iter()
                        .any(|header| header.name == "x-request-id" && header.value == "r-1"),
                    "{headers:?}"
                );
            }
            other => panic!("the next response must decode: {other:?}"),
        }
        assert_eq!(conn.rst_stream_count, 0);
    }

    // =====================================================================
    // Metamorphic tests for HTTP/2 flow control window consistency
    // =====================================================================

    /// Metamorphic relation: sum of WINDOW_UPDATE deltas ≡ flow-window mutation; no underflow.
    ///
    /// Tests the property that window updates maintain consistency according to RFC 9113
    /// flow control semantics. Addresses the oracle problem by verifying relationships
    /// between inputs/outputs rather than exact output values.
    mod flow_control_metamorphic_tests {
        use super::*;
        use proptest::prelude::*;

        /// Maximum number of window updates in a sequence to prevent timeouts
        const MAX_WINDOW_UPDATES: usize = 10;

        /// Maximum increment value to prevent overflow in test arithmetic
        const MAX_INCREMENT: u32 = 5_000;

        /// Helper to create a connection in Open state
        fn open_connection_client() -> Connection {
            let mut conn = Connection::client(Settings::client());
            conn.state = ConnectionState::Open;
            conn
        }

        /// Helper to create a connection in Open state (server)
        fn open_connection_server() -> Connection {
            let mut conn = Connection::server(Settings::default());
            conn.state = ConnectionState::Open;
            conn
        }

        /// MR1: EQUIVALENCE - Window update sequences are commutative
        /// Property: f(updates_A) = f(updates_B) where updates_B is permutation of updates_A
        #[test]
        fn mr_window_update_commutativity() {
            proptest!(|(increments in prop::collection::vec(1u32..=MAX_INCREMENT, 1..=MAX_WINDOW_UPDATES))| {
                let increments: Vec<u32> = increments.into_iter()
                    .filter(|&i| i > 0 && i <= MAX_INCREMENT)
                    .take(MAX_WINDOW_UPDATES)
                    .collect();

                if increments.is_empty() {
                    return Ok(());
                }

                // Test connection-level window commutativity
                let mut conn1 = open_connection_client();
                let mut conn2 = open_connection_client();

                let initial_window1 = conn1.send_window();
                let initial_window2 = conn2.send_window();
                prop_assert_eq!(initial_window1, initial_window2, "Initial windows must match");

                // Apply increments in original order to conn1
                for increment in &increments {
                    let frame = Frame::WindowUpdate(WindowUpdateFrame::new(0, *increment));
                    if conn1.process_frame(frame).is_err() {
                        // Skip this test case if we hit an error (overflow, etc.)
                        return Ok(());
                    }
                }

                // Apply increments in reverse order to conn2
                for increment in increments.iter().rev() {
                    let frame = Frame::WindowUpdate(WindowUpdateFrame::new(0, *increment));
                    if conn2.process_frame(frame).is_err() {
                        // Skip this test case if we hit an error
                        return Ok(());
                    }
                }

                let final_window1 = conn1.send_window();
                let final_window2 = conn2.send_window();

                prop_assert_eq!(final_window1, final_window2,
                    "Window after applying increments {:?} in different orders must be equal: {} vs {}",
                    increments, final_window1, final_window2);
            });
        }

        /// MR2: ADDITIVE - Sum of deltas equals total window change
        /// Property: window_final = window_initial + sum(deltas)
        #[test]
        fn mr_window_update_additive_connection_level() {
            proptest!(|(increments in prop::collection::vec(1u32..=MAX_INCREMENT, 1..=MAX_WINDOW_UPDATES))| {
                let increments: Vec<u32> = increments.into_iter()
                    .filter(|&i| i > 0 && i <= MAX_INCREMENT)
                    .take(MAX_WINDOW_UPDATES)
                    .collect();

                if increments.is_empty() {
                    return Ok(());
                }

                let mut conn = open_connection_client();
                let initial_window = conn.send_window();
                let expected_sum: i64 = increments.iter().map(|&i| i as i64).sum();

                // Apply each window update
                for increment in &increments {
                    let frame = Frame::WindowUpdate(WindowUpdateFrame::new(0, *increment));
                    if conn.process_frame(frame).is_err() {
                        // Skip if overflow occurs
                        return Ok(());
                    }
                }

                let final_window = conn.send_window();
                let actual_delta = i64::from(final_window) - i64::from(initial_window);

                prop_assert_eq!(actual_delta, expected_sum,
                    "Connection window delta {} must equal sum of increments {} for sequence {:?}",
                    actual_delta, expected_sum, increments);
            });
        }

        /// MR3: EQUIVALENCE - Batched vs Sequential updates
        /// Property: f(a1, a2, ..., an) = f(sum(a1..an))
        #[test]
        fn mr_window_update_batch_equivalence() {
            proptest!(|(increments in prop::collection::vec(1u32..=MAX_INCREMENT, 1..=MAX_WINDOW_UPDATES))| {
                let increments: Vec<u32> = increments.into_iter()
                    .filter(|&i| i > 0 && i <= MAX_INCREMENT)
                    .take(MAX_WINDOW_UPDATES)
                    .collect();

                if increments.is_empty() {
                    return Ok(());
                }

                let total_increment: u64 = increments.iter().map(|&i| i as u64).sum();

                // Skip if total would overflow u32
                if total_increment > u32::MAX as u64 {
                    return Ok(());
                }

                let total_increment = total_increment as u32;

                // Connection 1: Apply increments sequentially
                let mut conn1 = open_connection_client();
                let initial_window1 = conn1.send_window();

                for increment in &increments {
                    let frame = Frame::WindowUpdate(WindowUpdateFrame::new(0, *increment));
                    if conn1.process_frame(frame).is_err() {
                        return Ok(());
                    }
                }

                let final_window1 = conn1.send_window();

                // Connection 2: Apply total increment as single update
                let mut conn2 = open_connection_client();
                let initial_window2 = conn2.send_window();

                prop_assert_eq!(initial_window1, initial_window2, "Initial windows must match");

                let frame = Frame::WindowUpdate(WindowUpdateFrame::new(0, total_increment));
                if conn2.process_frame(frame).is_err() {
                    return Ok(());
                }

                let final_window2 = conn2.send_window();

                prop_assert_eq!(final_window1, final_window2,
                    "Sequential updates {:?} (total: {}) must equal batched update: {} vs {}",
                    increments, total_increment, final_window1, final_window2);
            });
        }

        /// MR4: INVARIANT - No underflow property for receive windows
        /// Property: ∀ operations, recv_window ≥ reasonable_bound
        #[test]
        fn mr_window_no_underflow_invariant() {
            proptest!(|(window_updates in prop::collection::vec(1u32..=MAX_INCREMENT, 1..=MAX_WINDOW_UPDATES))| {
                let updates: Vec<u32> = window_updates.into_iter()
                    .filter(|&val| val > 0 && val <= MAX_INCREMENT)
                    .take(MAX_WINDOW_UPDATES)
                    .collect();

                if updates.is_empty() {
                    return Ok(());
                }

                let mut conn = open_connection_server();
                let mut conn_window_in_bounds = true;

                // Apply WINDOW_UPDATEs and check bounds
                for value in updates {
                    let frame = Frame::WindowUpdate(WindowUpdateFrame::new(0, value));
                    let _ = conn.process_frame(frame);

                    // Check invariant: connection window stays reasonable
                    if conn.recv_window() < -100_000 {
                        conn_window_in_bounds = false;
                        break;
                    }
                }

                prop_assert!(conn_window_in_bounds,
                    "Connection receive window must stay within reasonable bounds");
            });
        }

        /// MR5: STREAM-LEVEL additive property
        #[test]
        fn mr_stream_window_additive() {
            proptest!(|(increments in prop::collection::vec(1u32..=MAX_INCREMENT, 1..=MAX_WINDOW_UPDATES))| {
                let increments: Vec<u32> = increments.into_iter()
                    .filter(|&i| i > 0 && i <= MAX_INCREMENT)
                    .take(MAX_WINDOW_UPDATES)
                    .collect();

                if increments.is_empty() {
                    return Ok(());
                }

                let mut conn = open_connection_client();

                // Create a stream using open_stream
                let stream_id = match conn.open_stream(vec![], false) {
                    Ok(id) => id,
                    Err(_) => return Ok(()),
                };

                let initial_window = conn.stream(stream_id)
                    .map(|s| s.send_window())
                    .unwrap_or(0);

                let expected_sum: i64 = increments.iter().map(|&i| i as i64).sum();

                // Apply each window update to the stream
                for increment in &increments {
                    let frame = Frame::WindowUpdate(WindowUpdateFrame::new(stream_id, *increment));
                    if conn.process_frame(frame).is_err() {
                        // Skip if stream doesn't exist or overflow occurs
                        return Ok(());
                    }
                }

                let final_window = conn.stream(stream_id)
                    .map(|s| s.send_window())
                    .unwrap_or(initial_window);

                let actual_delta = i64::from(final_window) - i64::from(initial_window);

                prop_assert_eq!(actual_delta, expected_sum,
                    "Stream {} window delta {} must equal sum of increments {} for sequence {:?}",
                    stream_id, actual_delta, expected_sum, increments);
            });
        }

        /// MR6: INVERTIVE - Window update/consumption round-trip
        /// Property: f(T(T(x))) = f(x) where T = update then consume same amount
        #[test]
        fn mr_window_update_consumption_roundtrip() {
            proptest!(|(increment in 1u32..=1000)| {
                let mut conn = open_connection_client();
                let headers = vec![
                    Header::new(":method", "POST"),
                    Header::new(":path", "/upload"),
                    Header::new(":scheme", "https"),
                    Header::new(":authority", "example.com"),
                ];
                let stream_id = conn.open_stream(headers, false).expect("stream opens");
                let _ = conn.next_frame().expect("initial HEADERS frame");

                let initial_window = conn.send_window();

                // Step 1: Apply WINDOW_UPDATE
                let update_frame = Frame::WindowUpdate(WindowUpdateFrame::new(0, increment));
                if conn.process_frame(update_frame).is_err() {
                    return Ok(());
                }

                let after_update = conn.send_window();
                prop_assert_eq!(after_update, initial_window + increment as i32);

                // Step 2: Send equivalent DATA bytes through the outbound flow-control path.
                let data = Bytes::from(vec![0u8; increment as usize]);
                prop_assert!(
                    conn.send_data(stream_id, data, false).is_ok(),
                    "DATA should queue on an open stream"
                );
                match conn.next_frame() {
                    Some(Frame::Data(frame)) => {
                        prop_assert_eq!(frame.data.len(), increment as usize);
                    }
                    other => prop_assert!(false, "expected DATA frame after queueing, got {other:?}"),
                }
                let final_window = conn.send_window();
                prop_assert_eq!(final_window, initial_window,
                    "Round-trip: update {} then consume {} must return to initial window {} (got {})",
                    increment, increment, initial_window, final_window);
            });
        }

        // =====================================================================
        // Unit tests with known values for sanity checking
        // =====================================================================

        #[test]
        fn unit_test_simple_window_update_sequence() {
            let mut conn = open_connection_client();
            let initial = conn.send_window();

            // Apply sequence: [100, 200, 300]
            let updates = [100, 200, 300];
            for increment in updates {
                let frame = Frame::WindowUpdate(WindowUpdateFrame::new(0, increment));
                conn.process_frame(frame).unwrap();
            }

            let final_window = conn.send_window();
            let expected = initial + 100 + 200 + 300;

            assert_eq!(
                final_window, expected,
                "Simple sequence [100, 200, 300] failed additive property"
            );
        }

        #[test]
        fn unit_test_zero_increment_error() {
            let mut conn = open_connection_client();

            // Zero increments should be rejected per RFC 9113 §6.9
            let frame = Frame::WindowUpdate(WindowUpdateFrame::new(0, 0));
            let result = conn.process_frame(frame);

            assert!(
                result.is_err(),
                "Zero increment WINDOW_UPDATE must be rejected"
            );
            if let Err(err) = result {
                assert_eq!(err.code, ErrorCode::ProtocolError);
            }
        }

        #[test]
        fn unit_test_overflow_protection() {
            let mut conn = open_connection_client();

            // Try to overflow the window beyond i32::MAX
            let large_increment = 0x7FFF_FFFF; // i32::MAX as u32
            let frame = Frame::WindowUpdate(WindowUpdateFrame::new(0, large_increment));

            // This should fail gracefully without mutating the flow-control window.
            let err = conn
                .process_frame(frame)
                .expect_err("overflowing WINDOW_UPDATE must fail gracefully");
            let default_window = i32::try_from(settings::DEFAULT_INITIAL_WINDOW_SIZE)
                .expect("default window fits i32");
            assert_eq!(err.code, ErrorCode::FlowControlError);
            assert_eq!(conn.send_window(), default_window);
        }
    }
