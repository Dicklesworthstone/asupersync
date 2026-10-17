    use super::*;
    use crate::http::h3_native::{
        H3ConnectionConfig, H3Frame, H3PseudoHeaders, H3RequestHead, H3ResponseHead,
        H3Settings, qpack_encode_request_field_section, qpack_encode_response_field_section,
        qpack_encode_trailer_field_section,
    };
    use crate::http::h3_quic::{NativeH3Event, NativeH3Session};
    use crate::net::atp::protocol::quic_frames::QuicFrame;
    use crate::net::atp::protocol::varint::VarInt;
    use crate::net::quic_native::{NativeQuicConnectionConfig, PacketNumberSpace};
    use std::sync::atomic::AtomicUsize;
    use std::task::Wake;

    fn client(max_frame_payload_size: usize) -> (Cx, QuicConnection, NativeH3Session) {
        let cx = Cx::for_testing();
        let mut connection = QuicConnection::client(NativeQuicConnectionConfig::default());
        connection.begin_handshake(&cx).unwrap();
        connection.mark_handshake_keys_available(&cx).unwrap();
        connection.mark_app_keys_available(&cx).unwrap();
        // A client refuses to confirm until a verifying handshake recorded the
        // server identity (br-asupersync-7pwwwe); these tests stand in for one.
        connection.record_verified_server_identity();
        connection.confirm_handshake(&cx).unwrap();
        let mut session = NativeH3Session::with_config(H3ConnectionConfig {
            max_frame_payload_size,
            ..H3ConnectionConfig::default()
        });
        session.initialize(&cx, &mut connection, H3Settings::default()).unwrap();
        (cx, connection, session)
    }

    fn head() -> H3RequestHead {
        H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("POST".to_owned()),
                scheme: Some("https".to_owned()),
                authority: Some("example.test".to_owned()),
                path: Some("/upload".to_owned()),
                ..H3PseudoHeaders::default()
            },
            Vec::new(),
        )
        .unwrap()
    }

    fn drain(
        cx: &Cx,
        connection: &mut QuicConnection,
        stream: StreamId,
        bytes: &mut Vec<u8>,
    ) -> usize {
        let mut fins = 0;
        for frame in connection.inner_mut().generate_stream_frames_for(
            cx, PacketNumberSpace::ApplicationData, stream, 65_536,
        ).unwrap() {
            if let QuicFrame::Stream { stream_id, offset, data, fin } = frame {
                assert_eq!(stream_id.value(), stream.0);
                assert_eq!(offset.map_or(0, VarInt::value), bytes.len() as u64);
                bytes.extend_from_slice(&data);
                fins += usize::from(fin);
            }
        }
        fins
    }

    fn replenish(cx: &Cx, connection: &mut QuicConnection, stream: StreamId, step: u64) {
        let limit = connection.inner().streams().stream(stream).unwrap().send_offset + step;
        let connection_limit = connection.inner().streams().connection_send_limit() + step;
        for frame in [
            QuicFrame::MaxStreamData {
                stream_id: VarInt::from_u64_unchecked(stream.0),
                maximum_stream_data: VarInt::from_u64_unchecked(limit),
            },
            QuicFrame::MaxData { maximum_data: VarInt::from_u64_unchecked(connection_limit) },
        ] {
            connection.inner_mut().process_frame(cx, &frame, PacketNumberSpace::ApplicationData).unwrap();
        }
    }

    #[test]
    fn incremental_request_fragments_headers_data_and_trailers_without_repeating_prefixes() {
        let (cx, mut connection, mut session) = client(4096);
        let mut head = head();
        head.headers.push(("x-large".to_owned(), "h".repeat(512)));
        let mut writer = session.start_request_writer(&cx, &mut connection, &head, false).unwrap();
        let stream = writer.stream_id();
        connection.inner_mut().set_fresh_stream_send_limit(&cx, stream, 17).unwrap();
        let sent = connection.inner().streams().connection_send_limit()
            - connection.inner().streams().connection_send_remaining();
        connection.inner_mut().constrain_connection_send_limit_for_testing(&cx, sent + 11).unwrap();
        assert!(writer.queue_data(Bytes::new()).is_err(), "HEADERS must go first");
        let data = Bytes::from(vec![0xa5; 2048]);
        let trailers = vec![("x-upload-check".to_owned(), "t".repeat(256))];
        let mut expected = Vec::new();
        H3Frame::Headers(qpack_encode_request_field_section(&head).unwrap()).encode(&mut expected).unwrap();
        H3Frame::Data(data.to_vec()).encode(&mut expected).unwrap();
        H3Frame::Headers(qpack_encode_trailer_field_section(&trailers).unwrap()).encode(&mut expected).unwrap();
        let mut wire = Vec::new();
        let mut fins = 0;
        let mut pending_polls = 0;
        let mut task_cx = Context::from_waker(Waker::noop());
        for expected_event in [
            NativeH3RequestWriteEvent::Headers { end_stream: false },
            NativeH3RequestWriteEvent::Data { payload_bytes: data.len() },
            NativeH3RequestWriteEvent::Trailers,
        ] {
            if matches!(expected_event, NativeH3RequestWriteEvent::Data { .. }) {
                writer.queue_data(data.clone()).unwrap();
                assert!(writer.queue_data(Bytes::new()).is_err(), "only one retained frame");
            } else if expected_event == NativeH3RequestWriteEvent::Trailers {
                writer.queue_trailers(&trailers).unwrap();
                assert!(writer.queue_data(Bytes::new()).is_err(), "trailers are terminal");
            }
            loop {
                let result = writer.poll_flush(&cx, &mut connection, &mut task_cx);
                assert!(connection.pending_stream_data_bytes(stream) <= 17);
                // A second poll before packet assembly cannot enqueue another
                // fragment or change the retained offset.
                if result.is_pending() && connection.has_pending_stream_frames(stream) {
                    let offset = writer.write_offset;
                    assert!(writer.poll_flush(&cx, &mut connection, &mut task_cx).is_pending());
                    assert_eq!(writer.write_offset, offset);
                }
                fins += drain(&cx, &mut connection, stream, &mut wire);
                match result {
                    Poll::Ready(Ok(Some(event))) => { assert_eq!(event, expected_event); break; }
                    Poll::Pending => {
                        pending_polls += 1;
                        assert!(pending_polls < 512, "bounded frame must make credit-driven progress");
                        replenish(&cx, &mut connection, stream, 17);
                    }
                    other @ Poll::Ready(_) => panic!("unexpected upload flush: {other:?}"),
                }
            }
        }
        assert!(pending_polls > 100);
        assert_eq!(wire, expected);
        assert_eq!(fins, 1);
        assert!(writer.is_finished());
        assert!(!writer.has_pending_write());
        writer.finish().unwrap();
        drop(writer);
        assert_eq!(session.next_event(&cx, &mut connection).unwrap(), None);
        assert!(session.request_writers.is_empty());
        assert!(connection.inner().streams().stream(stream).unwrap().send_reset.is_none());
    }

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
        fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }

    #[test]
    fn incremental_request_drop_wakes_session_and_cancellation_releases_pending_bytes() {
        for finish in 0..3 {
            let cancelled_context = finish != 0;
            let (cx, mut connection, mut session) = client(4096);
            let mut writer = session.start_request_writer(&cx, &mut connection, &head(), false).unwrap();
            let stream = writer.stream_id();
            connection.inner_mut().set_fresh_stream_send_limit(&cx, stream, 0).unwrap();
            let counter = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&counter));
            let mut task_cx = Context::from_waker(&waker);
            assert!(session.poll_event(&cx, &mut connection, &mut task_cx).is_pending());
            assert!(writer.poll_flush(&cx, &mut connection, &mut task_cx).is_pending());
            assert_eq!(counter.0.load(Ordering::SeqCst), 0);
            if cancelled_context {
                cx.set_cancel_requested(true);
                if finish == 1 {
                    assert!(matches!(
                        writer.poll_flush(&cx, &mut connection, &mut task_cx),
                        Poll::Ready(Err(_))
                    ));
                } else {
                    writer.cancel(&cx, &mut connection).unwrap();
                }
                assert!(!writer.has_pending_write());
            }
            drop(writer);
            assert!(counter.0.load(Ordering::SeqCst) > 0, "drop must wake the parked session");
            let result = session.next_event(&cx, &mut connection);
            assert_eq!(result.is_err(), cancelled_context);
            let state = connection.inner().streams().stream(stream).unwrap();
            assert_eq!(state.send_reset, Some((H3_REQUEST_CANCELLED, 0)));
            assert_eq!(state.receive_stopped_error_code, Some(H3_REQUEST_CANCELLED));
            assert!(session.request_writers.is_empty());
            assert_eq!(connection.pending_stream_data_bytes(stream), 0);
        }
    }

    #[test]
    fn incremental_request_early_response_fin_does_not_close_upload() {
        let (cx, mut connection, mut session) = client(4096);
        let mut writer = session.start_request_writer(&cx, &mut connection, &head(), false).unwrap();
        let stream = writer.stream_id();
        let mut task_cx = Context::from_waker(Waker::noop());
        assert!(matches!(writer.poll_flush(&cx, &mut connection, &mut task_cx), Poll::Ready(Ok(Some(_)))));
        let mut sent = Vec::new();
        assert_eq!(drain(&cx, &mut connection, stream, &mut sent), 0);
        let response = H3ResponseHead::new(200, Vec::new()).unwrap();
        let mut wire = Vec::new();
        H3Frame::Headers(qpack_encode_response_field_section(&response).unwrap()).encode(&mut wire).unwrap();
        connection.inner_mut().receive_stream_bytes(&cx, stream, 0, Bytes::from(wire), true).unwrap();
        assert_eq!(session.next_event(&cx, &mut connection).unwrap(), Some(NativeH3Event::ResponseHeaders { stream_id: stream, head: response }));
        assert_eq!(session.next_event(&cx, &mut connection).unwrap(), Some(NativeH3Event::Finished { stream_id: stream }));
        assert!(!writer.is_finished());
        writer.queue_data(Bytes::from_static(b"upload after response FIN")).unwrap();
        assert!(matches!(writer.poll_flush(&cx, &mut connection, &mut task_cx), Poll::Ready(Ok(Some(NativeH3RequestWriteEvent::Data { .. })))));
        drain(&cx, &mut connection, stream, &mut sent);
        writer.finish().unwrap();
        assert_eq!(writer.poll_flush(&cx, &mut connection, &mut task_cx), Poll::Ready(Ok(Some(NativeH3RequestWriteEvent::Finished))));
        assert_eq!(drain(&cx, &mut connection, stream, &mut sent), 1);
        assert!(writer.is_finished());
    }

    #[test]
    fn incremental_request_refuses_oversized_head_before_stream_allocation() {
        let (cx, mut connection, mut session) = client(8);
        assert!(matches!(
            session.start_request_writer(&cx, &mut connection, &head(), false),
            Err(NativeH3SessionError::Protocol(crate::http::h3_native::H3NativeError::FrameTooLarge { .. }))
        ));
        assert_eq!(session.next_local_request_stream_id, 0);
        assert!(session.request_writers.is_empty());
        assert_eq!(connection.open_bidi_stream(&cx).unwrap(), StreamId(0));
    }
