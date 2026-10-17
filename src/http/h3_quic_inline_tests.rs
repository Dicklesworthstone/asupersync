    use super::*;
    use crate::http::h3_native::H3PseudoHeaders;
    use crate::net::quic_native::NativeQuicConnectionConfig;

    fn field_limit_fixture(
        cx: &Cx,
        server: bool,
        streaming: bool,
        limit: Option<u64>,
    ) -> (NativeH3Session, QuicConnection) {
        let mut connection = if server {
            QuicConnection::server(NativeQuicConnectionConfig::default())
        } else {
            QuicConnection::client(NativeQuicConnectionConfig::default())
        };
        connection.begin_handshake(cx).unwrap();
        connection.mark_handshake_keys_available(cx).unwrap();
        connection.mark_app_keys_available(cx).unwrap();
        if !server {
            // A client refuses to confirm until a verifying handshake recorded the
            // server identity (br-asupersync-7pwwwe); these tests stand in for one.
            connection.record_verified_server_identity();
        }
        connection.confirm_handshake(cx).unwrap();
        let mut session = if server { NativeH3Session::server() } else { NativeH3Session::client() };
        if streaming {
            session.enable_streaming_receive(NonZeroUsize::new(8).unwrap()).unwrap();
        }
        session.initialize(cx, &mut connection, H3Settings {
            max_field_section_size: limit,
            ..H3Settings::default()
        }).unwrap();
        (session, connection)
    }

    fn field_limit_request() -> H3RequestHead {
        H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("GET".to_owned()),
                scheme: Some("https".to_owned()),
                authority: Some("example.test".to_owned()),
                path: Some("/".to_owned()),
                ..H3PseudoHeaders::default()
            },
            Vec::new(),
        ).unwrap()
    }

    fn inject_field_frame(
        cx: &Cx,
        connection: &mut QuicConnection,
        stream: StreamId,
        offset: u64,
        section: Vec<u8>,
        fin: bool,
    ) -> u64 {
        let wire = encode_frame(H3Frame::Headers(section)).unwrap();
        let next = offset + u64::try_from(wire.len()).unwrap();
        connection.inner_mut().receive_stream_bytes(cx, stream, offset, wire, fin).unwrap();
        next
    }

    fn next_field_limit_event(
        cx: &Cx,
        session: &mut NativeH3Session,
        connection: &mut QuicConnection,
    ) -> NativeH3Event {
        // All transport bytes have already been injected; repeated calls only
        // drive the production session's bounded parser steps. This is not a
        // timing-based witness or a native TLS/UDP integration test.
        for _ in 0..512 {
            if let Some(event) = session.next_event(cx, connection).unwrap() {
                return event;
            }
        }
        panic!("buffered wire bytes did not produce the expected field event");
    }

    #[test]
    fn request_field_limit_refuses_before_fin_and_preserves_same_connection_recovery() {
        for streaming in [false, true] {
            let cx = Cx::for_testing();
            let (mut session, mut connection) = field_limit_fixture(&cx, true, streaming, Some(178));
            let mut oversized = field_limit_request();
            oversized.headers.push(("x-padding".to_owned(), "x".to_owned()));
            let rejected = StreamId(0);
            connection.inner_mut().accept_remote_stream(&cx, rejected).unwrap();
            inject_field_frame(&cx, &mut connection, rejected, 0,
                qpack_encode_request_field_section(&oversized).unwrap(), false);
            assert_eq!(next_field_limit_event(&cx, &mut session, &mut connection),
                NativeH3Event::StreamReset { stream_id: rejected, error_code: H3_EXCESSIVE_LOAD, final_size: 0 });
            let state = connection.inner().streams().stream(rejected).unwrap();
            assert_eq!(state.send_reset, Some((H3_EXCESSIVE_LOAD, 0)));
            assert_eq!(state.receive_stopped_error_code, Some(H3_EXCESSIVE_LOAD));
            assert!(state.final_size.is_none(), "peer never sent FIN");
            assert_eq!(session.state.active_request_stream_count(), 0);
            assert!(!session.incoming.contains_key(&rejected));
            assert!(session.terminal_streams.contains(rejected));
            assert!(connection.can_send_app_data());

            let accepted = StreamId(4);
            connection.inner_mut().accept_remote_stream(&cx, accepted).unwrap();
            let head = field_limit_request();
            inject_field_frame(&cx, &mut connection, accepted, 0,
                qpack_encode_request_field_section(&head).unwrap(), true);
            assert_eq!(next_field_limit_event(&cx, &mut session, &mut connection),
                NativeH3Event::RequestHeaders { stream_id: accepted, head });
            assert_eq!(next_field_limit_event(&cx, &mut session, &mut connection),
                NativeH3Event::Finished { stream_id: accepted });
            assert_eq!(session.state.active_request_stream_count(), 0);
            assert!(session.incoming.is_empty());
        }
    }

    #[test]
    fn request_trailer_field_limit_refuses_before_fin() {
        for streaming in [false, true] {
            let cx = Cx::for_testing();
            let (mut session, mut connection) = field_limit_fixture(&cx, true, streaming, Some(178));
            let stream = StreamId(0);
            connection.inner_mut().accept_remote_stream(&cx, stream).unwrap();
            let head = field_limit_request();
            let offset = inject_field_frame(&cx, &mut connection, stream, 0,
                qpack_encode_request_field_section(&head).unwrap(), false);
            assert_eq!(next_field_limit_event(&cx, &mut session, &mut connection),
                NativeH3Event::RequestHeaders { stream_id: stream, head });
            let trailer = qpack_encode_trailer_field_section(&[
                ("x-trailer".to_owned(), "x".repeat(140)),
            ]).unwrap();
            // 9 + 140 + 32 = 181, independently larger than the 178-byte cap.
            inject_field_frame(&cx, &mut connection, stream, offset, trailer, false);
            assert_eq!(next_field_limit_event(&cx, &mut session, &mut connection),
                NativeH3Event::StreamReset { stream_id: stream, error_code: H3_EXCESSIVE_LOAD, final_size: 0 });
            assert_eq!(session.state.active_request_stream_count(), 0);
            assert!(!session.incoming.contains_key(&stream));
            assert!(connection.can_send_app_data());
        }
    }

    #[test]
    fn request_field_limit_default_none_and_zero_have_distinct_behavior() {
        for limit in [None, Some(0)] {
            let cx = Cx::for_testing();
            let (mut session, mut connection) = field_limit_fixture(&cx, true, false, limit);
            let stream = StreamId(0);
            connection.inner_mut().accept_remote_stream(&cx, stream).unwrap();
            let mut head = field_limit_request();
            head.headers.push(("x-padding".to_owned(), "x".repeat(1024)));
            inject_field_frame(&cx, &mut connection, stream, 0,
                qpack_encode_request_field_section(&head).unwrap(), false);
            let event = next_field_limit_event(&cx, &mut session, &mut connection);
            if limit.is_none() {
                assert_eq!(event, NativeH3Event::RequestHeaders { stream_id: stream, head });
            } else {
                assert_eq!(event, NativeH3Event::StreamReset {
                    stream_id: stream, error_code: H3_EXCESSIVE_LOAD, final_size: 0,
                });
            }
        }
    }

    #[test]
    fn client_field_limit_applies_separately_to_informational_final_and_trailer_sections() {
        use crate::http::h3_native::{QpackFieldPlan, qpack_encode_field_section};
        for streaming in [false, true] {
            let cx = Cx::for_testing();
            let (mut session, mut connection) = field_limit_fixture(&cx, false, streaming, Some(42));
            let rejected = session.send_request(&cx, &mut connection, &field_limit_request(), Bytes::new()).unwrap();
            let oversized = qpack_encode_field_section(&[
                QpackFieldPlan::Literal { name: ":status".to_owned(), value: "200".to_owned() },
                QpackFieldPlan::Literal { name: "x-note".to_owned(), value: "value".to_owned() },
            ]).unwrap();
            inject_field_frame(&cx, &mut connection, rejected, 0, oversized, false);
            assert_eq!(next_field_limit_event(&cx, &mut session, &mut connection),
                NativeH3Event::StreamReset { stream_id: rejected, error_code: H3_EXCESSIVE_LOAD, final_size: 0 });
            let stream = session.send_request(&cx, &mut connection, &field_limit_request(), Bytes::new()).unwrap();
            let mut offset = 0;
            for status in [103, 200] {
                let fields = qpack_encode_field_section(&[
                    QpackFieldPlan::Literal { name: ":status".to_owned(), value: status.to_string() },
                ]).unwrap();
                offset = inject_field_frame(&cx, &mut connection, stream, offset, fields, false);
                assert!(matches!(next_field_limit_event(&cx, &mut session, &mut connection),
                    NativeH3Event::ResponseHeaders { stream_id, head }
                    if stream_id == stream && head.status == status));
            }
            // Each preceding section fits exactly. A legal but oversized
            // trailer must still be refused; it is not exempt after final HEADERS.
            let trailer = qpack_encode_trailer_field_section(&[
                ("x-trailer".to_owned(), "too large".to_owned()),
            ]).unwrap();
            inject_field_frame(&cx, &mut connection, stream, offset, trailer, false);
            assert_eq!(next_field_limit_event(&cx, &mut session, &mut connection),
                NativeH3Event::StreamReset { stream_id: stream, error_code: H3_EXCESSIVE_LOAD, final_size: 0 });
            assert!(connection.can_send_app_data());
            assert!(!session.incoming.contains_key(&stream));

            let survivor = session.send_request(&cx, &mut connection, &field_limit_request(), Bytes::new()).unwrap();
            let fields = qpack_encode_field_section(&[
                QpackFieldPlan::Literal { name: ":status".to_owned(), value: "200".to_owned() },
            ]).unwrap();
            inject_field_frame(&cx, &mut connection, survivor, 0, fields, true);
            assert!(matches!(next_field_limit_event(&cx, &mut session, &mut connection),
                NativeH3Event::ResponseHeaders { stream_id, head }
                if stream_id == survivor && head.status == 200));
            assert_eq!(next_field_limit_event(&cx, &mut session, &mut connection),
                NativeH3Event::Finished { stream_id: survivor });
        }
    }

    #[test]
    fn field_limit_does_not_turn_invalid_qpack_into_an_application_refusal() {
        let cx = Cx::for_testing();
        let (mut session, mut connection) = field_limit_fixture(&cx, true, false, Some(0));
        let stream = StreamId(0);
        connection.inner_mut().accept_remote_stream(&cx, stream).unwrap();
        // RIC=0, Base=0, static index 63+127=190 (outside the static table).
        inject_field_frame(&cx, &mut connection, stream, 0, vec![0, 0, 0xff, 0x7f], false);
        assert_eq!(session.next_event(&cx, &mut connection),
            Err(NativeH3SessionError::Protocol(H3NativeError::InvalidFrame("unknown static qpack index"))));
        assert!(session.rejected_requests.is_empty());
    }

    #[test]
    fn field_limit_counts_duplicate_utf8_bytes_and_field_overhead() {
        let fields = vec![
            (":status".to_owned(), "200".to_owned()),
            ("x-note".to_owned(), "é".to_owned()),
            ("x-note".to_owned(), "é".to_owned()),
        ];
        // 42 for :status, then 6 + 2 + 32 for EACH occurrence of x-note.
        assert!(received_field_section_fits(&fields, 122));
        assert!(!received_field_section_fits(&fields, 121));
        assert!(!received_field_section_fits(&fields, 82));
        assert!(received_field_section_fits(&fields, u64::MAX));
        assert!(received_field_section_fits(&[], 0));
        assert!(!received_field_section_fits(&fields, 0));
    }

    #[test]
    fn field_limit_invalid_setting_does_not_consume_control_stream_or_seal_settings() {
        use crate::http::h3_native::H3_SETTING_MAX_FIELD_SECTION_SIZE;
        use crate::net::atp::protocol::quic_frames::QuicFrame;
        use crate::net::atp::protocol::varint::VarInt;
        use crate::net::quic_native::PacketNumberSpace;

        let cx = Cx::for_testing();
        let mut connection = QuicConnection::server(NativeQuicConnectionConfig::default());
        connection.begin_handshake(&cx).unwrap();
        connection.mark_handshake_keys_available(&cx).unwrap();
        connection.mark_app_keys_available(&cx).unwrap();
        connection.confirm_handshake(&cx).unwrap();
        let mut session = NativeH3Session::server();
        for limit in [QUIC_VARINT_MAX + 1, u64::MAX] {
            assert_eq!(
                session.initialize(
                    &cx,
                    &mut connection,
                    H3Settings {
                        max_field_section_size: Some(limit),
                        ..H3Settings::default()
                    },
                ),
                Err(NativeH3SessionError::Protocol(
                    H3NativeError::InvalidSettingValue(H3_SETTING_MAX_FIELD_SECTION_SIZE),
                )),
            );
            assert!(!session.initialized);
            assert!(session.local_control_stream.is_none());
            assert!(session.max_field_section_size.is_none());
        }
        let control = session
            .initialize(
                &cx,
                &mut connection,
                H3Settings {
                    max_field_section_size: Some(178),
                    ..H3Settings::default()
                },
            )
            .unwrap();
        assert_eq!(control, StreamId(3), "failed calls must not spend stream IDs");
        assert_eq!(session.max_field_section_size, Some(178));
        let mut wire = Vec::new();
        for frame in connection
            .inner_mut()
            .generate_stream_frames_for(&cx, PacketNumberSpace::ApplicationData, control, 65_536)
            .unwrap()
        {
            if let QuicFrame::Stream {
                stream_id,
                offset,
                data,
                fin,
            } = frame
            {
                assert_eq!(stream_id.value(), control.0);
                assert_eq!(offset.map_or(0, VarInt::value), u64::try_from(wire.len()).unwrap());
                assert!(!fin);
                wire.extend_from_slice(&data);
            }
        }
        let (kind, prefix) = decode_varint(&wire).unwrap();
        assert_eq!(kind, H3_CONTROL_STREAM_TYPE);
        let (frame, consumed) = H3Frame::decode(&wire[prefix..], &session.config).unwrap();
        assert_eq!(prefix + consumed, wire.len());
        let H3Frame::Settings(settings) = frame else {
            panic!("the first control frame must advertise SETTINGS");
        };
        assert_eq!(settings.max_field_section_size, session.max_field_section_size);
        assert!(session
            .initialize(&cx, &mut connection, H3Settings::default())
            .is_err());
        assert_eq!(session.max_field_section_size, Some(178));
    }

    fn server_with_request_limit(cx: &Cx, limit: u64) -> (NativeH3Session, QuicConnection) {
        let mut connection = QuicConnection::server(NativeQuicConnectionConfig::default());
        connection.begin_handshake(cx).expect("begin handshake");
        connection
            .mark_handshake_keys_available(cx)
            .expect("handshake keys");
        connection
            .mark_app_keys_available(cx)
            .expect("application keys");
        connection.confirm_handshake(cx).expect("confirm handshake");
        let mut session = NativeH3Session::with_config(H3ConnectionConfig {
            endpoint_role: H3EndpointRole::Server,
            max_concurrent_request_streams: Some(limit),
            ..H3ConnectionConfig::default()
        });
        session
            .initialize(cx, &mut connection, H3Settings::default())
            .expect("initialize server session");
        (session, connection)
    }

    fn receive_request_head(
        cx: &Cx,
        connection: &mut QuicConnection,
        stream_id: StreamId,
        fin: bool,
    ) -> u64 {
        let head = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("GET".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("example.test".to_string()),
                path: Some("/".to_string()),
                ..H3PseudoHeaders::default()
            },
            Vec::new(),
        )
        .expect("valid request head");
        let wire = encode_frame(H3Frame::Headers(
            qpack_encode_request_field_section(&head).expect("encode request head"),
        ))
        .expect("encode HEADERS frame");
        let final_size = u64::try_from(wire.len()).expect("bounded request wire size");
        connection
            .inner_mut()
            .accept_remote_stream(cx, stream_id)
            .expect("accept request stream");
        connection
            .inner_mut()
            .receive_stream_bytes(cx, stream_id, 0, wire, fin)
            .expect("receive request HEADERS");
        final_size
    }

    #[test]
    fn native_h3_session_local_receive_stop_releases_request_concurrency() {
        let cx = Cx::for_testing();
        let (mut session, mut connection) = server_with_request_limit(&cx, 1);
        let refused = StreamId(0);
        receive_request_head(&cx, &mut connection, refused, false);
        assert!(matches!(
            session.next_event(&cx, &mut connection).expect("request HEADERS"),
            Some(NativeH3Event::RequestHeaders { stream_id, .. }) if stream_id == refused
        ));
        assert_eq!(session.state.active_request_stream_count(), 1);
        session
            .cancel_request(&cx, &mut connection, refused)
            .expect("cancel incomplete request");
        assert_eq!(
            session
                .next_event(&cx, &mut connection)
                .expect("receive stop"),
            None
        );
        assert_eq!(session.state.active_request_stream_count(), 0);
        assert!(!session.incoming.contains_key(&refused));
        assert!(session.terminal_streams.contains(refused));

        let survivor = StreamId(4);
        receive_request_head(&cx, &mut connection, survivor, true);
        assert!(matches!(
            session.next_event(&cx, &mut connection).expect("survivor HEADERS"),
            Some(NativeH3Event::RequestHeaders { stream_id, .. }) if stream_id == survivor
        ));
        assert_eq!(
            session
                .next_event(&cx, &mut connection)
                .expect("survivor FIN"),
            Some(NativeH3Event::Finished {
                stream_id: survivor
            })
        );
        assert_eq!(session.state.active_request_stream_count(), 0);
        assert!(session.incoming.is_empty());
    }

    #[test]
    fn native_h3_session_peer_reset_after_request_fin_is_delivered_once() {
        let cx = Cx::for_testing();
        let (mut session, mut connection) = server_with_request_limit(&cx, 1);
        let cancelled = StreamId(0);
        let final_size = receive_request_head(&cx, &mut connection, cancelled, true);
        assert!(matches!(
            session.next_event(&cx, &mut connection).expect("request HEADERS"),
            Some(NativeH3Event::RequestHeaders { stream_id, .. }) if stream_id == cancelled
        ));
        assert_eq!(
            session
                .next_event(&cx, &mut connection)
                .expect("request FIN"),
            Some(NativeH3Event::Finished {
                stream_id: cancelled
            })
        );
        assert!(session.terminal_streams.contains(cancelled));
        assert_eq!(session.state.active_request_stream_count(), 0);

        connection
            .inner_mut()
            .reset_stream_receive(&cx, cancelled, H3_REQUEST_CANCELLED, final_size)
            .expect("peer cancels after request FIN");
        assert_eq!(
            session
                .next_event(&cx, &mut connection)
                .expect("late peer reset"),
            Some(NativeH3Event::StreamReset {
                stream_id: cancelled,
                error_code: H3_REQUEST_CANCELLED,
                final_size,
            })
        );
        session
            .cancel_request(&cx, &mut connection, cancelled)
            .expect("acknowledge cancelled dispatch");
        connection
            .inner_mut()
            .reset_stream_receive(&cx, cancelled, H3_REQUEST_CANCELLED, final_size)
            .expect("duplicate peer reset");
        assert_eq!(
            session
                .next_event(&cx, &mut connection)
                .expect("no repeated reset"),
            None
        );
        assert_eq!(session.state.active_request_stream_count(), 0);

        let survivor = StreamId(4);
        receive_request_head(&cx, &mut connection, survivor, true);
        assert!(matches!(
            session.next_event(&cx, &mut connection).expect("survivor HEADERS"),
            Some(NativeH3Event::RequestHeaders { stream_id, .. }) if stream_id == survivor
        ));
        assert_eq!(
            session
                .next_event(&cx, &mut connection)
                .expect("survivor FIN"),
            Some(NativeH3Event::Finished {
                stream_id: survivor
            })
        );
        assert_eq!(session.state.active_request_stream_count(), 0);
        assert!(session.incoming.is_empty());
    }

    #[test]
    fn produced_h3_data_wire_length_tracks_varint_boundaries_exactly() {
        assert_eq!(h3_data_frame_wire_len(0).expect("zero"), 2);
        assert_eq!(h3_data_frame_wire_len(63).expect("63"), 65);
        assert_eq!(h3_data_frame_wire_len(64).expect("64"), 67);
        assert_eq!(h3_data_frame_wire_len(16_383).expect("16383"), 16_386);
        assert_eq!(h3_data_frame_wire_len(16_384).expect("16384"), 16_389);
        if let Ok(max_payload) = usize::try_from(QUIC_VARINT_MAX) {
            assert!(
                h3_data_frame_wire_len(max_payload).is_err(),
                "payload plus H3 framing must fit the QUIC varint credit range"
            );
        }
    }

    #[test]
    fn native_h3_adapter_terminal_stream_tracker_tracks_out_of_order_classes() {
        let mut tracker = TerminalStreamTracker::default();
        tracker.insert(StreamId(8)).expect("track stream 8");
        assert!(tracker.contains(StreamId(8)));
        for open in [0, 4, 12] {
            assert!(!tracker.contains(StreamId(open)));
        }
        tracker.insert(StreamId(0)).expect("track stream 0");
        assert!(!tracker.contains(StreamId(4)));
        tracker.insert(StreamId(4)).expect("track stream 4");
        for stream_id in [0, 4, 8] {
            assert!(tracker.contains(StreamId(stream_id)));
        }

        tracker.insert(StreamId(7)).expect("track stream 7");
        assert!(!tracker.contains(StreamId(3)));
        tracker.insert(StreamId(3)).expect("track stream 3");
        assert!(tracker.contains(StreamId(3)) && tracker.contains(StreamId(7)));
        for untouched_class in [1, 2] {
            assert!(!tracker.contains(StreamId(untouched_class)));
        }
    }

    #[test]
    fn native_h3_adapter_terminal_stream_tracker_survives_a_long_lived_stream() {
        // Stream 0 stays open, like a control stream or a streaming request,
        // while many later streams finish. That must not exhaust the tracker.
        let mut tracker = TerminalStreamTracker::default();
        let finished = 3 * u64::try_from(MAX_OPEN_STREAM_RUNS).unwrap();
        for ordinal in 1..=finished {
            tracker
                .insert(StreamId(ordinal * 4))
                .expect("a long-lived stream must not pin the tracking window");
        }
        assert_eq!(tracker.ensure_healthy(), Ok(()));
        assert!(!tracker.contains(StreamId(0)));
        assert!(tracker.contains(StreamId(4)) && tracker.contains(StreamId(finished * 4)));
        tracker
            .insert(StreamId(0))
            .expect("the long-lived stream finishes");
        assert!(tracker.contains(StreamId(0)));

        // A peer may open a high stream first; every lower id is implicitly
        // open, and that costs one run rather than one entry per id.
        let mut tracker = TerminalStreamTracker::default();
        tracker
            .insert(StreamId(4 * 1_000_000))
            .expect("a far jump is one open run");
        assert!(tracker.contains(StreamId(4 * 1_000_000)));
        assert!(!tracker.contains(StreamId(4 * 500_000)));
    }

    #[test]
    fn native_h3_adapter_terminal_stream_tracker_fails_closed_at_open_run_budget() {
        // Finishing every other stream leaves one open run per unfinished
        // stream; the tracker refuses past its bound instead of growing.
        let mut tracker = TerminalStreamTracker::default();
        let budget = u64::try_from(MAX_OPEN_STREAM_RUNS).unwrap();
        for ordinal in 0..budget {
            tracker
                .insert(StreamId((2 * ordinal + 1) * 4))
                .expect("within the open-run budget");
        }
        let error = tracker
            .insert(StreamId((2 * budget + 1) * 4))
            .expect_err("terminal tracker must fail closed at its hard bound");
        assert_eq!(
            error,
            H3NativeError::ControlProtocol("terminal stream tracking window exceeded")
        );
        assert_eq!(tracker.ensure_healthy(), Err(error));
    }

    /// Decoding removed each item from the front of a Vec, which shifted the
    /// rest of the buffer every time. A peer's run of one-byte QPACK decoder
    /// instructions (or of tiny frames) cost quadratic copying and blocked the
    /// listener loop that serves every connection.
    #[test]
    fn decoding_a_long_run_of_one_byte_instructions_is_linear() {
        let cx = Cx::for_testing();
        let (mut session, _connection) = server_with_request_limit(&cx, 1);
        let stream_id = StreamId(11);
        let mut incoming = IncomingStream::new(stream_id);
        incoming.kind = IncomingStreamKind::QpackDecoder;
        // 0x40 is a Stream Cancellation for stream 0, one byte long.
        incoming.bytes.extend_from_slice(&vec![0x40; 1 << 20]);
        session.incoming.insert(stream_id, incoming);

        let started = std::time::Instant::now();
        session
            .decode_stream(stream_id)
            .expect("each instruction is legal");
        let elapsed = started.elapsed();
        assert!(session.incoming[&stream_id].bytes.is_empty());
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "1 MiB of one-byte instructions took {elapsed:?}"
        );
    }

    #[test]
    fn recv_buf_consumes_from_the_front_and_compacts() {
        let mut buf = RecvBuf::default();
        buf.extend_from_slice(b"abcdef");
        buf.consume(1);
        assert_eq!(&*buf, b"bcdef");
        assert_eq!(buf.take_front(2), b"bc".to_vec());
        assert_eq!(&*buf, b"def");
        assert_eq!(buf.start, 0, "consuming half the buffer compacts it");
        buf.extend_from_slice(b"gh");
        buf.consume(5);
        assert!(buf.is_empty());
        assert_eq!((buf.start, buf.data.len()), (0, 0));
    }

    mod response_fragmentation {
        use super::*;
        use crate::net::atp::protocol::quic_frames::QuicFrame;
        use crate::net::atp::protocol::varint::VarInt;
        use crate::net::quic_native::PacketNumberSpace;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::Wake;

        fn fixture(
            cx: &Cx,
            head: &H3ResponseHead,
            end_stream: bool,
        ) -> (QuicConnection, NativeH3ResponseWriter) {
            let (mut session, mut connection) = server_with_request_limit(cx, 1);
            receive_request_head(cx, &mut connection, StreamId(0), true);
            while session.next_event(cx, &mut connection).unwrap().is_some() {}
            let writer = session
                .start_response_writer(&connection, StreamId(0), head, end_stream)
                .unwrap();
            (connection, writer)
        }

        fn drain(cx: &Cx, connection: &mut QuicConnection, wire: &mut Vec<u8>) -> usize {
            let mut fins = 0;
            for frame in connection
                .inner_mut()
                .generate_stream_frames_for(cx, PacketNumberSpace::ApplicationData, StreamId(0), 65_536)
                .unwrap()
            {
                if let QuicFrame::Stream { stream_id, offset, data, fin } = frame {
                    assert_eq!(stream_id.value(), 0);
                    assert_eq!(offset.map_or(0, VarInt::value), wire.len() as u64);
                    wire.extend_from_slice(&data);
                    fins += usize::from(fin);
                }
            }
            fins
        }

        fn grant(cx: &Cx, connection: &mut QuicConnection, stream_limit: u64, connection_limit: u64) {
            for frame in [
                QuicFrame::MaxStreamData {
                    stream_id: VarInt::from_u64_unchecked(0),
                    maximum_stream_data: VarInt::from_u64_unchecked(stream_limit),
                },
                QuicFrame::MaxData {
                    maximum_data: VarInt::from_u64_unchecked(connection_limit),
                },
            ] {
                connection
                    .inner_mut()
                    .process_frame(cx, &frame, PacketNumberSpace::ApplicationData)
                    .unwrap();
            }
        }

        fn constrain(cx: &Cx, connection: &mut QuicConnection, stream: u64, aggregate: u64) -> u64 {
            connection.inner_mut().set_fresh_stream_send_limit(cx, StreamId(0), stream).unwrap();
            let used = connection.inner().streams().connection_send_limit()
                - connection.inner().streams().connection_send_remaining();
            connection.inner_mut().constrain_connection_send_limit_for_testing(cx, used + aggregate).unwrap();
            used
        }

        #[test]
        fn response_headers_data_and_trailers_cross_small_credit_without_repeating_bytes() {
            let cx = Cx::for_testing();
            let head = H3ResponseHead::new(200, vec![("x-large".to_owned(), "h".repeat(512))]).unwrap();
            let (mut connection, mut writer) = fixture(&cx, &head, false);
            constrain(&cx, &mut connection, 17, 11);
            let data = Bytes::from(vec![0xa5; 2048]);
            let trailers = vec![("x-check".to_owned(), "t".repeat(256))];
            let mut expected = Vec::new();
            H3Frame::Headers(qpack_encode_response_field_section(&head).unwrap()).encode(&mut expected).unwrap();
            H3Frame::Data(data.to_vec()).encode(&mut expected).unwrap();
            H3Frame::Headers(qpack_encode_trailer_field_section(&trailers).unwrap()).encode(&mut expected).unwrap();
            let mut task_cx = TaskContext::from_waker(Waker::noop());
            let mut wire = Vec::new();
            let mut fins = 0;
            let mut pending_polls = 0;
            for expected_event in [
                NativeH3WriteEvent::Head { end_stream: false },
                NativeH3WriteEvent::Data { payload_bytes: data.len() },
                NativeH3WriteEvent::Trailers,
            ] {
                match expected_event {
                    NativeH3WriteEvent::Data { .. } => writer.queue_data(data.clone()).unwrap(),
                    NativeH3WriteEvent::Trailers => writer.queue_trailers(&trailers).unwrap(),
                    _ => {}
                }
                if !matches!(expected_event, NativeH3WriteEvent::Head { .. }) {
                    let next = connection.inner().streams().stream(StreamId(0)).unwrap().send_offset + 17;
                    let aggregate = connection.inner().streams().connection_send_limit() + 17;
                    grant(&cx, &mut connection, next, aggregate);
                }
                loop {
                    let before = wire.len();
                    let result = writer.poll_flush_one(&cx, &mut connection, &mut task_cx);
                    assert!(connection.pending_stream_data_bytes(StreamId(0)) <= 17);
                    if result.is_pending() {
                        assert!(writer.has_pending_write());
                        assert!(!writer.is_finished());
                        assert!(writer.queue_data(Bytes::new()).is_err());
                        let remaining = writer.pending.as_ref().unwrap().wire.len();
                        assert!(writer.poll_flush_one(&cx, &mut connection, &mut task_cx).is_pending());
                        assert_eq!(writer.pending.as_ref().unwrap().wire.len(), remaining);
                    }
                    fins += drain(&cx, &mut connection, &mut wire);
                    assert!(wire.len() > before, "nonzero credit must send a prefix, not wait for the whole frame");
                    match result {
                        Poll::Ready(Ok(Some(event))) => {
                            assert_eq!(event, expected_event);
                            break;
                        }
                        Poll::Pending => {
                            pending_polls += 1;
                            assert!(pending_polls < 512);
                            assert_eq!(fins, 0, "FIN cannot overtake the retained suffix");
                            let next = connection.inner().streams().stream(StreamId(0)).unwrap().send_offset + 17;
                            let aggregate = connection.inner().streams().connection_send_limit() + 17;
                            grant(&cx, &mut connection, next, aggregate);
                        }
                        other @ Poll::Ready(_) => panic!("unexpected response flush: {other:?}"),
                    }
                }
            }
            assert!(pending_polls > 100);
            assert_eq!(wire, expected);
            assert_eq!(fins, 1);
            assert!(writer.is_finished());
            assert!(!writer.has_pending_write());
            assert_eq!(writer.poll_flush_one(&cx, &mut connection, &mut task_cx), Poll::Ready(Ok(None)));
        }

        #[test]
        fn head_only_response_attaches_fin_only_to_its_last_header_fragment() {
            let cx = Cx::for_testing();
            let head = H3ResponseHead::new(204, vec![("x-large".to_owned(), "h".repeat(128))]).unwrap();
            let (mut connection, mut writer) = fixture(&cx, &head, true);
            let used = constrain(&cx, &mut connection, 1, 1);
            let expected = encode_frame(H3Frame::Headers(qpack_encode_response_field_section(&head).unwrap())).unwrap();
            let mut wire = Vec::new();
            let mut task_cx = TaskContext::from_waker(Waker::noop());
            for sent in 1..=expected.len() {
                let result = writer.poll_flush_one(&cx, &mut connection, &mut task_cx);
                let fins = drain(&cx, &mut connection, &mut wire);
                assert_eq!(wire.len(), sent);
                assert_eq!(wire, expected[..sent]);
                if sent == expected.len() {
                    assert_eq!(result, Poll::Ready(Ok(Some(NativeH3WriteEvent::Head { end_stream: true }))));
                    assert_eq!(fins, 1);
                    assert!(writer.is_finished());
                } else {
                    assert!(result.is_pending());
                    assert_eq!(fins, 0);
                    assert!(!writer.is_finished());
                    grant(&cx, &mut connection, sent as u64 + 1, used + sent as u64 + 1);
                }
            }
        }

        #[test]
        fn fin_only_response_write_needs_no_byte_credit_but_waits_for_prior_queue_drain() {
            let cx = Cx::for_testing();
            let head = H3ResponseHead::new(200, Vec::new()).unwrap();
            let (mut connection, mut writer) = fixture(&cx, &head, false);
            let head_bytes = writer.pending.as_ref().unwrap().wire.len() as u64;
            constrain(&cx, &mut connection, head_bytes, head_bytes);
            let mut task_cx = TaskContext::from_waker(Waker::noop());
            assert_eq!(writer.poll_flush_one(&cx, &mut connection, &mut task_cx), Poll::Ready(Ok(Some(NativeH3WriteEvent::Head { end_stream: false }))));
            writer.finish().unwrap();
            assert!(writer.poll_flush_one(&cx, &mut connection, &mut task_cx).is_pending());
            let mut wire = Vec::new();
            assert_eq!(drain(&cx, &mut connection, &mut wire), 0);
            assert_eq!(connection.inner().streams().connection_send_remaining(), 0);
            assert_eq!(writer.poll_flush_one(&cx, &mut connection, &mut task_cx), Poll::Ready(Ok(Some(NativeH3WriteEvent::Finished))));
            assert_eq!(drain(&cx, &mut connection, &mut wire), 1);
            assert_eq!(wire.len() as u64, head_bytes);
            assert!(writer.is_finished());
        }

        #[derive(Default)]
        struct WakeCount(AtomicUsize);

        impl Wake for WakeCount {
            fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
            fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
        }

        #[test]
        fn response_fragment_waits_for_both_credit_scopes_without_self_waking() {
            let cx = Cx::for_testing();
            let head = H3ResponseHead::new(200, Vec::new()).unwrap();
            let (mut connection, mut writer) = fixture(&cx, &head, false);
            let used = constrain(&cx, &mut connection, 0, 0);
            let counter = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&counter));
            let mut task_cx = TaskContext::from_waker(&waker);
            for _ in 0..3 {
                assert!(writer.poll_flush_one(&cx, &mut connection, &mut task_cx).is_pending());
            }
            assert_eq!(counter.0.load(Ordering::SeqCst), 0);
            grant(&cx, &mut connection, 1, used);
            counter.0.store(0, Ordering::SeqCst);
            assert!(writer.poll_flush_one(&cx, &mut connection, &mut task_cx).is_pending());
            assert_eq!(counter.0.load(Ordering::SeqCst), 0);
            assert_eq!(connection.pending_stream_data_bytes(StreamId(0)), 0);
            grant(&cx, &mut connection, 1, used + 1);
            assert!(writer.poll_flush_one(&cx, &mut connection, &mut task_cx).is_pending());
            assert_eq!(connection.pending_stream_data_bytes(StreamId(0)), 1);
            let remaining = writer.pending.as_ref().unwrap().wire.len();
            counter.0.store(0, Ordering::SeqCst);
            assert!(writer.poll_flush_one(&cx, &mut connection, &mut task_cx).is_pending());
            assert_eq!(counter.0.load(Ordering::SeqCst), 0);
            assert_eq!(writer.pending.as_ref().unwrap().wire.len(), remaining);
        }

        #[test]
        fn peer_stop_after_a_response_prefix_prevents_suffix_and_fin_publication() {
            let cx = Cx::for_testing();
            let head = H3ResponseHead::new(200, Vec::new()).unwrap();
            let (mut connection, mut writer) = fixture(&cx, &head, true);
            constrain(&cx, &mut connection, 1, 1);
            let mut task_cx = TaskContext::from_waker(Waker::noop());
            assert!(writer.poll_flush_one(&cx, &mut connection, &mut task_cx).is_pending());
            let mut wire = Vec::new();
            assert_eq!(drain(&cx, &mut connection, &mut wire), 0);
            assert_eq!(wire.len(), 1, "cancellation must follow real prefix transmission");
            connection.inner_mut().process_frame(&cx, &QuicFrame::StopSending {
                stream_id: VarInt::from_u64_unchecked(0),
                error_code: VarInt::from_u64_unchecked(H3_REQUEST_CANCELLED),
            }, PacketNumberSpace::ApplicationData).unwrap();
            assert!(matches!(writer.poll_flush_one(&cx, &mut connection, &mut task_cx), Poll::Ready(Err(_))));
            assert!(!writer.is_finished());
            assert_eq!(drain(&cx, &mut connection, &mut wire), 0);
            assert_eq!(wire.len(), 1);
            assert_eq!(connection.pending_stream_data_bytes(StreamId(0)), 0);
        }
    }
