    use super::*;
    use crate::http::h3_native::H3PseudoHeaders;
    use crate::net::quic_native::NativeQuicConnectionConfig;

    mod outbound_dynamic_profile {
        use super::*;
        use crate::http::h3_native::{
            H3UniStreamType, QpackDecoderInstruction, QpackInstructionStreamState,
            qpack_decode_request_field_section, qpack_decode_response_field_section,
            qpack_encode_decoder_instruction, qpack_field_section_metadata,
        };
        use crate::net::atp::protocol::quic_frames::QuicFrame;
        use crate::net::atp::protocol::varint::VarInt;
        use crate::net::quic_native::PacketNumberSpace;

        fn fixture(cx: &Cx, server: bool, capacity: u64) -> (NativeH3Session, QuicConnection) {
            let mut connection = if server {
                QuicConnection::server(NativeQuicConnectionConfig::default())
            } else {
                QuicConnection::client(NativeQuicConnectionConfig::default())
            };
            connection.begin_handshake(cx).unwrap();
            connection.mark_handshake_keys_available(cx).unwrap();
            connection.mark_app_keys_available(cx).unwrap();
            if !server {
                connection.record_verified_server_identity();
            }
            connection.confirm_handshake(cx).unwrap();
            // Encoding is independent of dynamic receive. Local SETTINGS must
            // retain the existing static receive profile in this fixture.
            let mut session = if server {
                NativeH3Session::server()
            } else {
                NativeH3Session::client()
            };
            session.enable_dynamic_qpack_encoder(NonZeroUsize::new(256).unwrap()).unwrap();
            session.initialize(cx, &mut connection, H3Settings::default()).unwrap();
            let settings = H3Settings {
                qpack_max_table_capacity: Some(capacity),
                qpack_blocked_streams: Some(0),
                ..H3Settings::default()
            };
            let mut wire = vec![0];
            H3Frame::Settings(settings.clone()).encode(&mut wire).unwrap();
            let peer_control = StreamId(if server { 2 } else { 3 });
            connection.inner_mut().accept_remote_stream(cx, peer_control).unwrap();
            connection.inner_mut().receive_stream_bytes(
                cx, peer_control, 0, Bytes::from(wire), false,
            ).unwrap();
            assert_eq!(
                next_field_limit_event(cx, &mut session, &mut connection),
                NativeH3Event::Settings(settings),
            );
            (session, connection)
        }

        fn collect_wire(cx: &Cx, connection: &mut QuicConnection, stream: StreamId) -> Vec<u8> {
            collect_wire_at(cx, connection, stream, 0)
        }

        fn collect_wire_at(cx: &Cx, connection: &mut QuicConnection, stream: StreamId, start: u64) -> Vec<u8> {
            let mut wire = Vec::new();
            for frame in connection.inner_mut().generate_stream_frames_for(
                cx, PacketNumberSpace::ApplicationData, stream, 65_536,
            ).unwrap() {
                if let QuicFrame::Stream { stream_id, offset, data, .. } = frame {
                    assert_eq!(stream_id.value(), stream.0);
                    assert_eq!(offset.map_or(0, VarInt::value), start + wire.len() as u64);
                    wire.extend_from_slice(&data);
                }
            }
            wire
        }

        fn sections(wire: &[u8]) -> Vec<Vec<u8>> {
            let mut rest = wire;
            let mut sections = Vec::new();
            while !rest.is_empty() {
                let (frame, consumed) = H3Frame::decode(rest, &H3ConnectionConfig::default()).unwrap();
                rest = &rest[consumed..];
                match frame {
                    H3Frame::Headers(section) => sections.push(section),
                    other => panic!("unexpected header-only wire frame: {other:?}"),
                }
            }
            assert!(!sections.is_empty());
            sections
        }

        fn receive_insertions(
            cx: &Cx,
            session: &mut NativeH3Session,
            connection: &mut QuicConnection,
            capacity: u64,
        ) -> QpackInstructionStreamState {
            for _ in 0..8 {
                assert_eq!(session.next_event(cx, connection).unwrap(), None);
            }
            let encoder = StreamId(if session.role == H3EndpointRole::Server { 7 } else { 6 });
            let wire = collect_wire(cx, connection, encoder);
            assert_eq!(wire.first(), Some(&2));
            let sender = session.dynamic_send.as_ref().unwrap();
            assert_eq!(sender.encoder_stream(), Some(encoder));
            assert_eq!(sender.queued_encoder_bytes(), 0);
            assert_eq!(sender.active_table_capacity(), 256);
            assert_eq!(sender.known_received_count(), 0);
            let mut peer = QpackInstructionStreamState::from_local_and_peer_settings(
                H3QpackMode::DynamicTableAllowed,
                &H3Settings {
                    qpack_max_table_capacity: Some(capacity),
                    qpack_blocked_streams: Some(0),
                    ..H3Settings::default()
                },
                &H3Settings::default(),
            ).unwrap();
            peer.register_stream(encoder.0, H3UniStreamType::QpackEncoder).unwrap();
            // Exercise the actual incremental peer parser, including the
            // multi-byte capacity and header string prefixes.
            for byte in &wire[1..] {
                peer.feed_encoder_stream_bytes(encoder.0, &[*byte]).unwrap();
            }
            assert!(peer.received_context().dynamic_table().capacity() <= 256);
            peer
        }

        fn feedback(
            cx: &Cx,
            session: &mut NativeH3Session,
            connection: &mut QuicConnection,
            peer: &mut QpackInstructionStreamState,
            instruction: QpackDecoderInstruction,
            offset: &mut u64,
        ) {
            let decoder = StreamId(if session.role == H3EndpointRole::Server { 6 } else { 7 });
            let mut wire = Vec::new();
            if *offset == 0 {
                connection.inner_mut().accept_remote_stream(cx, decoder).unwrap();
                wire.push(3);
            }
            peer.apply_local_decoder_instruction(&instruction).unwrap();
            qpack_encode_decoder_instruction(&mut wire, &instruction).unwrap();
            let length = wire.len() as u64;
            connection.inner_mut().receive_stream_bytes(
                cx, decoder, *offset, Bytes::from(wire), false,
            ).unwrap();
            *offset += length;
            for _ in 0..8 {
                assert_eq!(session.next_event(cx, connection).unwrap(), None);
            }
        }

        fn ready_response(cx: &Cx, session: &mut NativeH3Session, connection: &mut QuicConnection, stream: StreamId) {
            receive_request_head(cx, connection, stream, true);
            assert!(matches!(
                next_field_limit_event(cx, session, connection),
                NativeH3Event::RequestHeaders { stream_id, .. } if stream_id == stream
            ));
            assert_eq!(
                next_field_limit_event(cx, session, connection),
                NativeH3Event::Finished { stream_id: stream },
            );
        }

        #[test]
        fn requests_reuse_only_acknowledged_metadata_in_both_send_paths() {
            for incremental in [false, true] {
                for capacity in [4096, (1_u64 << 40).min(usize::MAX as u64)] {
                    let cx = Cx::for_testing();
                    let (mut session, mut connection) = fixture(&cx, false, capacity);
                    let mut head = field_limit_request();
                    head.headers = vec![
                        ("accept".to_owned(), "application/asupersync-long-lived-metadata+json".to_owned()),
                        ("authorization".to_owned(), "Bearer private-request-value".to_owned()),
                        ("x-private".to_owned(), "never automatically indexed".to_owned()),
                    ];
                    let send = |session: &mut NativeH3Session, connection: &mut QuicConnection| {
                        if incremental {
                            let mut writer = session.start_request_writer(&cx, connection, &head, true).unwrap();
                            let stream = writer.stream_id();
                            assert!(matches!(
                                writer.poll_flush(&cx, connection, &mut TaskContext::from_waker(Waker::noop())),
                                Poll::Ready(Ok(Some(NativeH3RequestWriteEvent::Headers { end_stream: true })))
                            ));
                            stream
                        } else {
                            session.send_request(&cx, connection, &head, Bytes::new()).unwrap()
                        }
                    };
                    let first = send(&mut session, &mut connection);
                    let first_sections = sections(&collect_wire(&cx, &mut connection, first));
                    assert_eq!(first_sections.len(), 1);
                    assert_eq!(first_sections[0][0], 0, "unacknowledged insertions cannot be referenced");
                    let mut peer = receive_insertions(&cx, &mut session, &mut connection, capacity);
                    assert_eq!(peer.received_context().dynamic_table().insertion_counter(), 1);
                    let entry = peer.received_context().dynamic_table().get_by_insertion_id(0).unwrap();
                    assert_eq!(entry.name(), "accept");
                    assert_eq!(entry.value(), head.headers[0].1);
                    let mut feedback_offset = 0;
                    feedback(&cx, &mut session, &mut connection, &mut peer,
                        QpackDecoderInstruction::InsertCountIncrement { increment: 1 }, &mut feedback_offset);
                    let second = send(&mut session, &mut connection);
                    assert_eq!(second.0, first.0 + 4);
                    let compressed = sections(&collect_wire(&cx, &mut connection, second));
                    let metadata = qpack_field_section_metadata(
                        &compressed[0], H3QpackMode::DynamicTableAllowed, Some(peer.received_context()),
                    ).unwrap();
                    assert_eq!(metadata.required_insert_count(), 1);
                    assert!(compressed[0].len() < first_sections[0].len());
                    assert_eq!(
                        qpack_decode_request_field_section(
                            &compressed[0], H3QpackMode::DynamicTableAllowed, Some(peer.received_context()),
                        ).unwrap(),
                        head,
                    );
                    peer.submit_received_field_section(second.0, &compressed[0]).unwrap();
                    let sender = session.dynamic_send.as_ref().unwrap();
                    assert_eq!(sender.prepared_section_count(), 0);
                    assert_eq!(sender.outstanding_section_count(second), 1);
                    assert_eq!(sender.outstanding_reference_count(), 1);
                    assert_eq!(sender.known_received_count(), 1);
                    feedback(&cx, &mut session, &mut connection, &mut peer,
                        QpackDecoderInstruction::HeaderAcknowledgement { stream_id: second.0 }, &mut feedback_offset);
                    assert_eq!(peer.received_decoder_feedback().outstanding_reference_count(), 0);
                    assert_eq!(session.dynamic_send.as_ref().unwrap().outstanding_reference_count(), 0);
                }
            }
        }

        #[test]
        fn informational_and_final_responses_keep_dynamic_acknowledgements_in_order() {
            for incremental in [false, true] {
                let cx = Cx::for_testing();
                let (mut session, mut connection) = fixture(&cx, true, 4096);
                let head = H3ResponseHead::new(200, vec![
                    ("content-type".to_owned(), "application/asupersync-stream+json".to_owned()),
                    ("set-cookie".to_owned(), "private=session-token".to_owned()),
                ]).unwrap();
                ready_response(&cx, &mut session, &mut connection, StreamId(0));
                session.send_response(&cx, &mut connection, StreamId(0), &head, Bytes::new()).unwrap();
                let first = sections(&collect_wire(&cx, &mut connection, StreamId(0)));
                assert_eq!(first[0][0], 0);
                let mut peer = receive_insertions(&cx, &mut session, &mut connection, 4096);
                assert_eq!(peer.received_context().dynamic_table().insertion_counter(), 1);
                assert_eq!(peer.received_context().dynamic_table().get_by_insertion_id(0).unwrap().name(), "content-type");
                let mut feedback_offset = 0;
                feedback(&cx, &mut session, &mut connection, &mut peer,
                    QpackDecoderInstruction::InsertCountIncrement { increment: 1 }, &mut feedback_offset);
                let stream = StreamId(4);
                ready_response(&cx, &mut session, &mut connection, stream);
                let informational = H3ResponseHead::new(103, head.headers.clone()).unwrap();
                session.send_informational_response(&cx, &mut connection, stream, &informational).unwrap();
                let mut response_wire = collect_wire(&cx, &mut connection, stream);
                if incremental {
                    let mut writer = session.start_response_writer(&connection, stream, &head, true).unwrap();
                    assert!(matches!(
                        writer.poll_flush_one(&cx, &mut connection, &mut TaskContext::from_waker(Waker::noop())),
                        Poll::Ready(Ok(Some(NativeH3WriteEvent::Head { end_stream: true })))
                    ));
                } else {
                    session.send_response(&cx, &mut connection, stream, &head, Bytes::new()).unwrap();
                }
                response_wire.extend_from_slice(&collect_wire_at(
                    &cx, &mut connection, stream, response_wire.len() as u64,
                ));
                let compressed = sections(&response_wire);
                assert_eq!(compressed.len(), 2);
                assert_eq!(session.dynamic_send.as_ref().unwrap().outstanding_section_count(stream), 2);
                for (section, expected) in compressed.iter().zip([&informational, &head]) {
                    assert_eq!(qpack_field_section_metadata(
                        section, H3QpackMode::DynamicTableAllowed, Some(peer.received_context()),
                    ).unwrap().required_insert_count(), 1);
                    assert_eq!(&qpack_decode_response_field_section(
                        section, H3QpackMode::DynamicTableAllowed, Some(peer.received_context()),
                    ).unwrap(), expected);
                    peer.submit_received_field_section(stream.0, section).unwrap();
                }
                for _ in 0..2 {
                    feedback(&cx, &mut session, &mut connection, &mut peer,
                        QpackDecoderInstruction::HeaderAcknowledgement { stream_id: stream.0 }, &mut feedback_offset);
                }
                assert_eq!(peer.received_decoder_feedback().outstanding_reference_count(), 0);
                assert_eq!(session.dynamic_send.as_ref().unwrap().outstanding_reference_count(), 0);
            }
        }

        #[test]
        fn native_encoder_preserves_peer_modulus_after_many_local_table_evictions() {
            let cx = Cx::for_testing();
            let capacity = (1_u64 << 40).min(usize::MAX as u64);
            let (mut session, mut connection) = fixture(&cx, false, capacity);
            let mut peer = QpackInstructionStreamState::from_local_and_peer_settings(
                H3QpackMode::DynamicTableAllowed,
                &H3Settings {
                    qpack_max_table_capacity: Some(capacity),
                    qpack_blocked_streams: Some(0),
                    ..H3Settings::default()
                },
                &H3Settings::default(),
            ).unwrap();
            let encoder = StreamId(6);
            peer.register_stream(encoder.0, H3UniStreamType::QpackEncoder).unwrap();
            let mut encoder_offset = 0;
            let mut feedback_offset = 0;
            let mut head = field_limit_request();
            for index in 0..21 {
                head.headers = vec![(
                    "accept".to_owned(),
                    format!("application/sequence-{index:02}-many-evictions+json"),
                )];
                let stream = session.send_request(&cx, &mut connection, &head, Bytes::new()).unwrap();
                assert_eq!(sections(&collect_wire(&cx, &mut connection, stream))[0][0], 0);
                assert_eq!(session.next_event(&cx, &mut connection).unwrap(), None);
                let wire = collect_wire_at(&cx, &mut connection, encoder, encoder_offset);
                let instructions = if encoder_offset == 0 {
                    assert_eq!(wire[0], 2);
                    &wire[1..]
                } else {
                    &wire[..]
                };
                encoder_offset += wire.len() as u64;
                peer.feed_encoder_stream_bytes(encoder.0, instructions).unwrap();
                assert_eq!(peer.received_context().dynamic_table().insertion_counter(), index + 1);
                assert!(peer.received_context().dynamic_table().size() <= 256);
                feedback(&cx, &mut session, &mut connection, &mut peer,
                    QpackDecoderInstruction::InsertCountIncrement { increment: 1 }, &mut feedback_offset);
            }
            assert!(peer.received_context().dynamic_table().get_by_insertion_id(0).is_none());
            let stream = session.send_request(&cx, &mut connection, &head, Bytes::new()).unwrap();
            let compressed = sections(&collect_wire(&cx, &mut connection, stream));
            // With a falsely clamped maximum of 256 bytes, FullRange would be
            // sixteen and this prefix would be six. The peer's true maximum
            // keeps the complete count here even though the active table is tiny.
            assert_eq!(compressed[0][0], 22);
            assert_eq!(qpack_field_section_metadata(
                &compressed[0], H3QpackMode::DynamicTableAllowed, Some(peer.received_context()),
            ).unwrap().required_insert_count(), 21);
            assert_eq!(qpack_decode_request_field_section(
                &compressed[0], H3QpackMode::DynamicTableAllowed, Some(peer.received_context()),
            ).unwrap(), head);
            peer.submit_received_field_section(stream.0, &compressed[0]).unwrap();
            feedback(&cx, &mut session, &mut connection, &mut peer,
                QpackDecoderInstruction::HeaderAcknowledgement { stream_id: stream.0 }, &mut feedback_offset);
            assert_eq!(session.dynamic_send.as_ref().unwrap().outstanding_reference_count(), 0);
        }

        #[test]
        fn abandoned_request_writers_release_only_unexposed_dynamic_references() {
            let cx = Cx::for_testing();
            let (mut session, mut connection) = fixture(&cx, false, 4096);
            let mut head = field_limit_request();
            head.headers.push(("accept".to_owned(), "application/owned-request+json".to_owned()));
            session.send_request(&cx, &mut connection, &head, Bytes::new()).unwrap();
            let _first_wire = collect_wire(&cx, &mut connection, StreamId(0));
            let mut peer = receive_insertions(&cx, &mut session, &mut connection, 4096);
            let mut feedback_offset = 0;
            feedback(&cx, &mut session, &mut connection, &mut peer,
                QpackDecoderInstruction::InsertCountIncrement { increment: 1 }, &mut feedback_offset);

            let writer = session.start_request_writer(&cx, &mut connection, &head, true).unwrap();
            let unsent = writer.stream_id();
            let sender = session.dynamic_send.as_ref().unwrap().clone();
            assert_eq!(sender.prepared_section_count(), 1);
            assert_eq!(sender.outstanding_reference_count(), 0);
            assert_eq!(connection.pending_stream_data_bytes(unsent), 0);
            drop(writer);
            assert_eq!(sender.prepared_section_count(), 0);
            assert_eq!(sender.outstanding_reference_count(), 0);
            assert_eq!(session.next_event(&cx, &mut connection).unwrap(), None);
            assert!(!session.request_writers.contains_key(&unsent));

            let mut writer = session.start_request_writer(&cx, &mut connection, &head, true).unwrap();
            let exposed = writer.stream_id();
            connection.inner_mut().set_fresh_stream_send_limit(&cx, exposed, 1).unwrap();
            assert!(writer.poll_flush(
                &cx, &mut connection, &mut TaskContext::from_waker(Waker::noop()),
            ).is_pending());
            assert_eq!(connection.pending_stream_data_bytes(exposed), 1, "HEADERS prefix reached QUIC");
            assert_eq!(sender.prepared_section_count(), 0);
            assert_eq!(sender.outstanding_section_count(exposed), 1);
            drop(writer);
            assert_eq!(session.next_event(&cx, &mut connection).unwrap(), None);
            assert!(!session.request_writers.contains_key(&exposed));
            assert_eq!(sender.outstanding_reference_count(), 1, "a local reset cannot release exposed references");
            feedback(&cx, &mut session, &mut connection, &mut peer,
                QpackDecoderInstruction::StreamCancellation { stream_id: exposed.0 }, &mut feedback_offset);
            assert_eq!(sender.outstanding_section_count(exposed), 0);
            assert_eq!(sender.outstanding_reference_count(), 0);
        }
    }

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

    fn receive_peer_field_limit(
        cx: &Cx,
        session: &mut NativeH3Session,
        connection: &mut QuicConnection,
        limit: u64,
    ) {
        let stream = StreamId(if session.role == H3EndpointRole::Server { 2 } else { 3 });
        let settings = H3Settings {
            max_field_section_size: Some(limit),
            ..H3Settings::default()
        };
        let mut wire = vec![0]; // Peer control-stream type.
        H3Frame::Settings(settings.clone()).encode(&mut wire).unwrap();
        connection.inner_mut().accept_remote_stream(cx, stream).unwrap();
        connection
            .inner_mut()
            .receive_stream_bytes(cx, stream, 0, Bytes::from(wire), false)
            .unwrap();
        assert_eq!(
            next_field_limit_event(cx, session, connection),
            NativeH3Event::Settings(settings)
        );
    }

    fn peer_field_limit_error() -> NativeH3SessionError {
        NativeH3SessionError::InvalidState(
            "field section exceeds peer SETTINGS_MAX_FIELD_SECTION_SIZE",
        )
    }

    fn drain_peer_limit_stream(cx: &Cx, connection: &mut QuicConnection, stream: StreamId) {
        connection
            .inner_mut()
            .generate_stream_frames_for(
                cx,
                crate::net::quic_native::PacketNumberSpace::ApplicationData,
                stream,
                65_536,
            )
            .unwrap();
    }

    #[test]
    fn peer_field_limit_refuses_both_request_paths_before_opening_a_stream() {
        for incremental in [false, true] {
            for duplicate_utf8 in [false, true] {
                let cx = Cx::for_testing();
                // Our receive limit must not be confused with the peer's limit.
                let (mut session, mut connection) =
                    field_limit_fixture(&cx, false, false, Some(0));
                let mut head = field_limit_request();
                let limit = if duplicate_utf8 {
                    head.headers = vec![
                        ("x".to_owned(), "é".to_owned()),
                        ("x".to_owned(), "é".to_owned()),
                    ];
                    // Base 178 + two occurrences of (1 + 2 + 32) = 248.
                    247
                } else {
                    head.pseudo.path = Some("//".to_owned());
                    178
                };
                receive_peer_field_limit(&cx, &mut session, &mut connection, limit);
                assert!(qpack_encode_request_field_section(&head).unwrap().len() < limit as usize);
                let credit = connection.inner().streams().connection_send_remaining();
                let error = if incremental {
                    session
                        .start_request_writer(&cx, &mut connection, &head, true)
                        .unwrap_err()
                } else {
                    session
                        .send_request(&cx, &mut connection, &head, Bytes::new())
                        .unwrap_err()
                };
                assert_eq!(error, peer_field_limit_error());
                assert_eq!(session.next_local_request_stream_id, 0);
                assert!(session.request_writers.is_empty());
                assert!(connection.inner().streams().stream(StreamId(0)).is_err());
                assert_eq!(connection.inner().streams().connection_send_remaining(), credit);

                if duplicate_utf8 {
                    head.headers[1].1 = "e".to_owned();
                } else {
                    head.pseudo.path = Some("/".to_owned());
                }
                if incremental {
                    let mut writer = session
                        .start_request_writer(&cx, &mut connection, &head, true)
                        .expect("exact uncompressed limit is permitted");
                    assert_eq!(writer.stream_id(), StreamId(0));
                    let mut task = TaskContext::from_waker(Waker::noop());
                    assert!(matches!(
                        writer.poll_flush(&cx, &mut connection, &mut task),
                        Poll::Ready(Ok(Some(NativeH3RequestWriteEvent::Headers { end_stream: true })))
                    ));
                } else {
                    assert_eq!(
                        session.send_request(&cx, &mut connection, &head, Bytes::new()).unwrap(),
                        StreamId(0)
                    );
                }
                assert_eq!(session.next_local_request_stream_id, 4);
            }
        }
    }

    #[test]
    fn peer_field_limit_applies_separately_to_informational_and_final_response_paths() {
        for incremental in [false, true] {
            let cx = Cx::for_testing();
            let (mut session, mut connection) = field_limit_fixture(&cx, true, false, None);
            receive_request_head(&cx, &mut connection, StreamId(0), true);
            while session.next_event(&cx, &mut connection).unwrap().is_some() {}
            // :status + three status bytes + 32 bytes overhead is exactly 42.
            receive_peer_field_limit(&cx, &mut session, &mut connection, 42);
            let mut informational = H3ResponseHead::new(
                103,
                vec![("x".to_owned(), String::new())],
            ).unwrap();
            assert_eq!(
                session.send_informational_response(
                    &cx, &mut connection, StreamId(0), &informational,
                ).unwrap_err(),
                peer_field_limit_error()
            );
            assert_eq!(connection.inner().streams().stream(StreamId(0)).unwrap().send_offset, 0);
            informational.headers.clear();
            session.send_informational_response(
                &cx, &mut connection, StreamId(0), &informational,
            ).unwrap();
            let offset = connection.inner().streams().stream(StreamId(0)).unwrap().send_offset;
            drain_peer_limit_stream(&cx, &mut connection, StreamId(0));

            let mut final_head = H3ResponseHead::new(
                200,
                vec![("x".to_owned(), String::new())],
            ).unwrap();
            let error = if incremental {
                session.start_response_writer(&connection, StreamId(0), &final_head, true)
                    .unwrap_err()
            } else {
                session.send_response(
                    &cx, &mut connection, StreamId(0), &final_head, Bytes::new(),
                ).unwrap_err()
            };
            assert_eq!(error, peer_field_limit_error());
            let stream = connection.inner().streams().stream(StreamId(0)).unwrap();
            assert_eq!(stream.send_offset, offset);
            assert!(stream.send_final_size.is_none());
            final_head.headers.clear();
            if incremental {
                let mut writer = session
                    .start_response_writer(&connection, StreamId(0), &final_head, true)
                    .unwrap();
                let mut task = TaskContext::from_waker(Waker::noop());
                assert!(matches!(
                    writer.poll_flush_one(&cx, &mut connection, &mut task),
                    Poll::Ready(Ok(Some(NativeH3WriteEvent::Head { end_stream: true })))
                ));
            } else {
                session.send_response(
                    &cx, &mut connection, StreamId(0), &final_head, Bytes::new(),
                ).unwrap();
            }
            assert!(connection.inner().streams().stream(StreamId(0)).unwrap().send_final_size.is_some());
        }
    }

    #[test]
    fn existing_request_writer_observes_late_peer_limits_for_trailers() {
        for limit in [0, 35] {
            let cx = Cx::for_testing();
            let (mut session, mut connection) = field_limit_fixture(&cx, false, false, None);
            let mut writer = session
                .start_request_writer(&cx, &mut connection, &field_limit_request(), false)
                .unwrap();
            let mut task = TaskContext::from_waker(Waker::noop());
            assert!(matches!(
                writer.poll_flush(&cx, &mut connection, &mut task),
                Poll::Ready(Ok(Some(NativeH3RequestWriteEvent::Headers { end_stream: false })))
            ));
            drain_peer_limit_stream(&cx, &mut connection, StreamId(0));
            receive_peer_field_limit(&cx, &mut session, &mut connection, limit);
            let oversized = vec![("x".to_owned(), "éé".to_owned())];
            assert_eq!(writer.queue_trailers(&oversized).unwrap_err(), peer_field_limit_error());
            assert!(!writer.has_pending_write());
            assert!(!writer.is_finished());
            assert!(connection.inner().streams().stream(StreamId(0)).unwrap().send_final_size.is_none());
            let accepted = if limit == 0 {
                Vec::new()
            } else {
                vec![("x".to_owned(), "é".to_owned())]
            };
            writer.queue_trailers(&accepted).expect("refusal leaves the writer usable");
            assert!(matches!(
                writer.poll_flush(&cx, &mut connection, &mut task),
                Poll::Ready(Ok(Some(NativeH3RequestWriteEvent::Trailers)))
            ));
            assert!(writer.is_finished());
        }
    }

    #[test]
    fn existing_response_writer_observes_late_peer_limits_for_trailers() {
        for limit in [0, 35] {
            let cx = Cx::for_testing();
            let (mut session, mut connection) = field_limit_fixture(&cx, true, false, None);
            receive_request_head(&cx, &mut connection, StreamId(0), true);
            while session.next_event(&cx, &mut connection).unwrap().is_some() {}
            let head = H3ResponseHead::new(200, Vec::new()).unwrap();
            let mut writer = session
                .start_response_writer(&connection, StreamId(0), &head, false)
                .unwrap();
            let mut task = TaskContext::from_waker(Waker::noop());
            assert!(matches!(
                writer.poll_flush_one(&cx, &mut connection, &mut task),
                Poll::Ready(Ok(Some(NativeH3WriteEvent::Head { end_stream: false })))
            ));
            drain_peer_limit_stream(&cx, &mut connection, StreamId(0));
            receive_peer_field_limit(&cx, &mut session, &mut connection, limit);
            let oversized = vec![("x".to_owned(), "éé".to_owned())];
            assert_eq!(writer.queue_trailers(&oversized).unwrap_err(), peer_field_limit_error());
            assert!(!writer.has_pending_write());
            assert!(!writer.is_finished());
            assert!(connection.inner().streams().stream(StreamId(0)).unwrap().send_final_size.is_none());
            let accepted = if limit == 0 {
                Vec::new()
            } else {
                vec![("x".to_owned(), "é".to_owned())]
            };
            writer.queue_trailers(&accepted).expect("refusal leaves the writer usable");
            assert!(matches!(
                writer.poll_flush_one(&cx, &mut connection, &mut task),
                Poll::Ready(Ok(Some(NativeH3WriteEvent::Trailers)))
            ));
            assert!(writer.is_finished());
        }
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

    mod dynamic_receive {
        use super::*;
        use crate::http::h3_native::{
            QpackBlockedStreamStatus, QpackFieldPlan, QpackInstructionStreamState,
            qpack_decode_decoder_instruction, qpack_encode_encoder_instruction,
            qpack_encode_field_section_with_context, qpack_static_plan_for_request,
        };
        use crate::net::atp::protocol::quic_frames::QuicFrame;
        use crate::net::atp::protocol::varint::VarInt;
        use crate::net::quic_native::PacketNumberSpace;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::Wake;

        fn connection(cx: &Cx, server: bool) -> QuicConnection {
            connection_with_config(cx, server, NativeQuicConnectionConfig::default())
        }

        fn connection_with_config(
            cx: &Cx,
            server: bool,
            config: NativeQuicConnectionConfig,
        ) -> QuicConnection {
            let mut connection = if server {
                QuicConnection::server(config)
            } else {
                QuicConnection::client(config)
            };
            connection.begin_handshake(cx).unwrap();
            connection.mark_handshake_keys_available(cx).unwrap();
            connection.mark_app_keys_available(cx).unwrap();
            if !server {
                connection.record_verified_server_identity();
            }
            connection.confirm_handshake(cx).unwrap();
            connection
        }

        fn fixture(
            cx: &Cx,
            server: bool,
            streaming: bool,
            settings: H3Settings,
        ) -> (NativeH3Session, QuicConnection) {
            let mut connection = connection(cx, server);
            let mut session = NativeH3Session::with_config(
                H3ConnectionConfig {
                    endpoint_role: if server {
                        H3EndpointRole::Server
                    } else {
                        H3EndpointRole::Client
                    },
                    ..H3ConnectionConfig::default()
                }
                .with_dynamic_qpack(),
            );
            if streaming {
                session
                    .enable_streaming_receive(NonZeroUsize::new(8).unwrap())
                    .unwrap();
            }
            session.initialize(cx, &mut connection, settings).unwrap();
            (session, connection)
        }

        fn peer_encoder(capacity: u64) -> QpackInstructionStreamState {
            peer_encoder_with_blocked_streams(capacity, 0)
        }

        fn peer_encoder_with_blocked_streams(
            capacity: u64,
            blocked_streams: u64,
        ) -> QpackInstructionStreamState {
            QpackInstructionStreamState::from_local_and_peer_settings(
                H3QpackMode::DynamicTableAllowed,
                &H3Settings::default(),
                &H3Settings {
                    qpack_max_table_capacity: Some(capacity),
                    qpack_blocked_streams: Some(blocked_streams),
                    ..H3Settings::default()
                },
            )
            .unwrap()
        }

        fn encoder_wire(
            peer: &mut QpackInstructionStreamState,
            fields: &[(&str, &str)],
        ) -> Vec<u8> {
            let mut wire = vec![2]; // QPACK encoder-stream type.
            let capacity = QpackEncoderInstruction::SetDynamicTableCapacity {
                capacity: u64::try_from(peer.context().max_table_capacity()).unwrap(),
            };
            peer.apply_local_encoder_instruction(&capacity).unwrap();
            qpack_encode_encoder_instruction(&mut wire, &capacity).unwrap();
            for (name, value) in fields {
                let instruction = QpackEncoderInstruction::InsertWithoutNameReference {
                    name: (*name).to_owned(),
                    value: (*value).to_owned(),
                };
                peer.apply_local_encoder_instruction(&instruction).unwrap();
                qpack_encode_encoder_instruction(&mut wire, &instruction).unwrap();
            }
            wire
        }

        fn inject_encoder(
            cx: &Cx,
            session: &mut NativeH3Session,
            connection: &mut QuicConnection,
            wire: Vec<u8>,
        ) {
            let stream = StreamId(if session.role == H3EndpointRole::Server {
                6
            } else {
                7
            });
            connection
                .inner_mut()
                .accept_remote_stream(cx, stream)
                .unwrap();
            connection
                .inner_mut()
                .receive_stream_bytes(cx, stream, 0, Bytes::from(wire), false)
                .unwrap();
            assert_eq!(session.next_event(cx, connection).unwrap(), None);
        }

        fn drain_stream(
            cx: &Cx,
            connection: &mut QuicConnection,
            stream: StreamId,
            wire: &mut Vec<u8>,
        ) -> usize {
            let mut fins = 0;
            for frame in connection
                .inner_mut()
                .generate_stream_frames_for(cx, PacketNumberSpace::ApplicationData, stream, 65_536)
                .unwrap()
            {
                if let QuicFrame::Stream {
                    stream_id,
                    offset,
                    data,
                    fin,
                } = frame
                {
                    assert_eq!(stream_id.value(), stream.0);
                    assert_eq!(offset.map_or(0, VarInt::value), wire.len() as u64);
                    wire.extend_from_slice(&data);
                    fins += usize::from(fin);
                }
            }
            fins
        }

        fn feedback(
            cx: &Cx,
            session: &mut NativeH3Session,
            connection: &mut QuicConnection,
            peer: &mut QpackInstructionStreamState,
            wire: &mut Vec<u8>,
        ) -> Vec<QpackDecoderInstruction> {
            let stream = session
                .dynamic_receive
                .as_ref()
                .unwrap()
                .decoder_stream
                .expect("feedback opens the local decoder stream");
            let previous = wire.len();
            for _ in 0..64 {
                assert_eq!(drain_stream(cx, connection, stream, wire), 0);
                if session.dynamic_receive.as_ref().unwrap().feedback.is_empty() {
                    break;
                }
                // Draining packet assembly admits the next retained prefix;
                // encoder-only traffic does not supply another incoming event.
                assert_eq!(session.next_event(cx, connection).unwrap(), None);
            }
            assert!(session.dynamic_receive.as_ref().unwrap().feedback.is_empty());
            let mut bytes = &wire[previous..];
            if previous == 0 {
                assert_eq!(bytes.first(), Some(&3), "decoder-stream type prefix");
                bytes = &bytes[1..];
                peer.register_stream(stream.0, H3UniStreamType::QpackDecoder)
                    .unwrap();
            }
            let outcome = peer.feed_decoder_stream_bytes(stream.0, bytes).unwrap();
            let mut instructions = Vec::new();
            while !bytes.is_empty() {
                let (instruction, consumed) = qpack_decode_decoder_instruction(bytes).unwrap();
                instructions.push(instruction);
                bytes = &bytes[consumed..];
            }
            assert_eq!(outcome.instructions_processed(), instructions.len());
            instructions
        }

        fn request_section(peer: &QpackInstructionStreamState, entry: u64) -> Vec<u8> {
            let mut plan = qpack_static_plan_for_request(&field_limit_request());
            plan.push(QpackFieldPlan::DynamicIndex(entry));
            qpack_encode_field_section_with_context(&plan, Some(peer.context())).unwrap()
        }

        #[test]
        fn fragmented_encoder_before_settings_survives_and_acknowledges_the_request() {
            for streaming in [false, true] {
                let cx = Cx::for_testing();
                let (mut session, mut connection) =
                    fixture(&cx, true, streaming, H3Settings::default());
                let mut peer = peer_encoder(NATIVE_H3_DEFAULT_QPACK_DECODER_CAPACITY as u64);
                let wire = encoder_wire(&mut peer, &[("x-before-settings", "retained")]);
                let encoder = StreamId(6);
                connection
                    .inner_mut()
                    .accept_remote_stream(&cx, encoder)
                    .unwrap();
                for (offset, byte) in wire.iter().enumerate() {
                    connection
                        .inner_mut()
                        .receive_stream_bytes(
                            &cx,
                            encoder,
                            offset as u64,
                            Bytes::copy_from_slice(&[*byte]),
                            false,
                        )
                        .unwrap();
                    assert_eq!(session.next_event(&cx, &mut connection).unwrap(), None);
                    assert_eq!(
                        session
                            .dynamic_receive
                            .as_ref()
                            .unwrap()
                            .qpack
                            .received_context()
                            .dynamic_table()
                            .insertion_counter(),
                        u64::from(offset + 1 == wire.len()),
                        "an incomplete encoder literal must not publish an insertion"
                    );
                }
                let mut decoder_wire = Vec::new();
                assert_eq!(
                    feedback(&cx, &mut session, &mut connection, &mut peer, &mut decoder_wire),
                    vec![QpackDecoderInstruction::InsertCountIncrement { increment: 1 }]
                );
                assert_eq!(peer.known_received_count(), 1);

                // SETTINGS arriving after the encoder stream must preserve its table.
                receive_peer_field_limit(&cx, &mut session, &mut connection, 65_536);
                let section = request_section(&peer, 0);
                assert_eq!(
                    peer.submit_field_section(0, &section).unwrap(),
                    QpackBlockedStreamStatus::Ready
                );
                connection
                    .inner_mut()
                    .accept_remote_stream(&cx, StreamId(0))
                    .unwrap();
                inject_field_frame(&cx, &mut connection, StreamId(0), 0, section, true);
                let NativeH3Event::RequestHeaders { stream_id, head } =
                    next_field_limit_event(&cx, &mut session, &mut connection)
                else {
                    panic!("dynamic request HEADERS were not decoded");
                };
                assert_eq!(stream_id, StreamId(0));
                assert_eq!(
                    head.headers,
                    vec![("x-before-settings".to_owned(), "retained".to_owned())]
                );
                assert_eq!(
                    next_field_limit_event(&cx, &mut session, &mut connection),
                    NativeH3Event::Finished { stream_id }
                );
                assert_eq!(
                    feedback(&cx, &mut session, &mut connection, &mut peer, &mut decoder_wire),
                    vec![QpackDecoderInstruction::HeaderAcknowledgement { stream_id: 0 }]
                );
                assert_eq!(peer.decoder_feedback().outstanding_reference_count(), 0);
                assert!(peer.decoder_feedback().cancelled_stream_ids().is_empty());
                assert!(session.dynamic_receive.as_ref().unwrap().feedback.is_empty());
            }
        }

        #[test]
        fn dynamic_informational_final_and_trailer_sections_each_emit_one_ack() {
            for streaming in [false, true] {
                let cx = Cx::for_testing();
                let (mut session, mut connection) =
                    fixture(&cx, false, streaming, H3Settings::default());
                let stream = session
                    .send_request(&cx, &mut connection, &field_limit_request(), Bytes::new())
                    .unwrap();
                let mut request_wire = Vec::new();
                assert_eq!(drain_stream(&cx, &mut connection, stream, &mut request_wire), 1);
                let (H3Frame::Headers(outbound), _) =
                    H3Frame::decode(&request_wire, &H3ConnectionConfig::default()).unwrap()
                else {
                    panic!("outbound request HEADERS missing");
                };
                assert_eq!(&outbound[..2], &[0, 0], "outbound encoding stays static");

                let mut peer = peer_encoder(NATIVE_H3_DEFAULT_QPACK_DECODER_CAPACITY as u64);
                let wire = encoder_wire(
                    &mut peer,
                    &[(":status", "103"), (":status", "200"), ("x-checksum", "done")],
                );
                inject_encoder(&cx, &mut session, &mut connection, wire);
                let mut decoder_wire = Vec::new();
                let increments = feedback(
                    &cx,
                    &mut session,
                    &mut connection,
                    &mut peer,
                    &mut decoder_wire,
                );
                assert_eq!(
                    increments
                        .iter()
                        .map(|instruction| match instruction {
                            QpackDecoderInstruction::InsertCountIncrement { increment } => {
                                *increment
                            }
                            other => panic!("unexpected insertion feedback: {other:?}"),
                        })
                        .sum::<u64>(),
                    3
                );

                let mut offset = 0;
                for section_index in 0..4 {
                    let dynamic_entry = match section_index {
                        0 => Some(0),
                        1 => None,
                        2 => Some(1),
                        _ => Some(2),
                    };
                    let section = if let Some(entry) = dynamic_entry {
                        let section = qpack_encode_field_section_with_context(
                            &[QpackFieldPlan::DynamicIndex(entry)],
                            Some(peer.context()),
                        )
                        .unwrap();
                        assert_eq!(
                            peer.submit_field_section(stream.0, &section).unwrap(),
                            QpackBlockedStreamStatus::Ready
                        );
                        section
                    } else {
                        qpack_encode_response_field_section(
                            &H3ResponseHead::new(100, Vec::new()).unwrap(),
                        )
                        .unwrap()
                    };
                    offset = inject_field_frame(
                        &cx,
                        &mut connection,
                        stream,
                        offset,
                        section,
                        section_index == 3,
                    );
                    let event = next_field_limit_event(&cx, &mut session, &mut connection);
                    if section_index == 3 {
                        assert_eq!(event, NativeH3Event::Trailers {
                            stream_id: stream,
                            fields: vec![("x-checksum".to_owned(), "done".to_owned())],
                        });
                    } else {
                        let NativeH3Event::ResponseHeaders { stream_id, head } = event else {
                            panic!("response HEADERS missing");
                        };
                        assert_eq!(stream_id, stream);
                        assert_eq!(head.status, [103, 100, 200][section_index]);
                    }
                    let expected = if dynamic_entry.is_some() {
                        vec![QpackDecoderInstruction::HeaderAcknowledgement {
                            stream_id: stream.0,
                        }]
                    } else {
                        Vec::new()
                    };
                    assert_eq!(
                        feedback(&cx, &mut session, &mut connection, &mut peer, &mut decoder_wire),
                        expected,
                        "a static section must not consume a dynamic section's ACK"
                    );
                    assert_eq!(peer.decoder_feedback().outstanding_reference_count(), 0);
                }
                assert_eq!(
                    next_field_limit_event(&cx, &mut session, &mut connection),
                    NativeH3Event::Finished { stream_id: stream }
                );
                assert!(
                    feedback(&cx, &mut session, &mut connection, &mut peer, &mut decoder_wire)
                        .is_empty()
                );
                assert!(peer.decoder_feedback().cancelled_stream_ids().is_empty());
            }
        }

        #[test]
        fn refused_dynamic_headers_acknowledge_before_cancelling_only_the_bad_stream() {
            for streaming in [false, true] {
                for oversized in [false, true] {
                    let cx = Cx::for_testing();
                    let (mut session, mut connection) = fixture(
                        &cx,
                        true,
                        streaming,
                        H3Settings {
                            max_field_section_size: oversized.then_some(200),
                            ..H3Settings::default()
                        },
                    );
                    let mut peer =
                        peer_encoder(NATIVE_H3_DEFAULT_QPACK_DECODER_CAPACITY as u64);
                    let value = "x".repeat(64);
                    let field = if oversized {
                        ("x-padding", value.as_str())
                    } else {
                        ("connection", "keep-alive")
                    };
                    let wire = encoder_wire(&mut peer, &[field]);
                    inject_encoder(&cx, &mut session, &mut connection, wire);
                    let mut decoder_wire = Vec::new();
                    assert_eq!(
                        feedback(
                            &cx,
                            &mut session,
                            &mut connection,
                            &mut peer,
                            &mut decoder_wire,
                        ),
                        vec![QpackDecoderInstruction::InsertCountIncrement { increment: 1 }]
                    );
                    let section = request_section(&peer, 0);
                    peer.submit_field_section(0, &section).unwrap();
                    connection
                        .inner_mut()
                        .accept_remote_stream(&cx, StreamId(0))
                        .unwrap();
                    inject_field_frame(&cx, &mut connection, StreamId(0), 0, section, false);
                    assert_eq!(
                        next_field_limit_event(&cx, &mut session, &mut connection),
                        NativeH3Event::StreamReset {
                            stream_id: StreamId(0),
                            error_code: if oversized {
                                H3_EXCESSIVE_LOAD
                            } else {
                                H3_MESSAGE_ERROR
                            },
                            final_size: 0,
                        }
                    );
                    assert_eq!(
                        feedback(
                            &cx,
                            &mut session,
                            &mut connection,
                            &mut peer,
                            &mut decoder_wire,
                        ),
                        vec![
                            QpackDecoderInstruction::HeaderAcknowledgement { stream_id: 0 },
                            QpackDecoderInstruction::StreamCancellation { stream_id: 0 },
                        ],
                        "QPACK decoding succeeds before HTTP validation refuses the stream"
                    );
                    assert_eq!(peer.decoder_feedback().outstanding_reference_count(), 0);
                    assert!(peer.decoder_feedback().cancelled_stream_ids().contains(&0));
                    let receive = session.dynamic_receive.as_ref().unwrap();
                    assert_eq!(
                        receive.qpack.received_decoder_feedback().outstanding_reference_count(),
                        0
                    );
                    assert_eq!(
                        receive.qpack.received_blocked_scheduler().pending_section_count(0),
                        0
                    );
                    assert!(!session.incoming.contains_key(&StreamId(0)));
                    assert_eq!(session.state.active_request_stream_count(), 0);

                    receive_request_head(&cx, &mut connection, StreamId(4), false);
                    assert!(matches!(
                        next_field_limit_event(&cx, &mut session, &mut connection),
                        NativeH3Event::RequestHeaders { stream_id: StreamId(4), .. }
                    ));
                    assert!(
                        feedback(
                            &cx,
                            &mut session,
                            &mut connection,
                            &mut peer,
                            &mut decoder_wire,
                        )
                        .is_empty()
                    );
                }
            }
        }

        #[test]
        fn a_reset_before_headers_still_releases_the_peers_possible_qpack_references() {
            let cx = Cx::for_testing();
            let (mut session, mut connection) =
                fixture(&cx, true, false, H3Settings::default());
            connection
                .inner_mut()
                .accept_remote_stream(&cx, StreamId(0))
                .unwrap();
            connection
                .inner_mut()
                .reset_stream_receive(&cx, StreamId(0), H3_REQUEST_CANCELLED, 0)
                .unwrap();
            assert_eq!(
                next_field_limit_event(&cx, &mut session, &mut connection),
                NativeH3Event::StreamReset {
                    stream_id: StreamId(0),
                    error_code: H3_REQUEST_CANCELLED,
                    final_size: 0,
                }
            );
            let mut peer = peer_encoder(NATIVE_H3_DEFAULT_QPACK_DECODER_CAPACITY as u64);
            let mut wire = Vec::new();
            assert_eq!(
                feedback(&cx, &mut session, &mut connection, &mut peer, &mut wire),
                vec![QpackDecoderInstruction::StreamCancellation { stream_id: 0 }]
            );
            assert_eq!(peer.known_received_count(), 0);
            assert!(peer.decoder_feedback().cancelled_stream_ids().contains(&0));
            assert_eq!(session.next_event(&cx, &mut connection).unwrap(), None);
            assert!(feedback(&cx, &mut session, &mut connection, &mut peer, &mut wire).is_empty());
        }

        #[derive(Default)]
        struct WakeCount(AtomicUsize);

        impl Wake for WakeCount {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn grant_stream_credit(
            cx: &Cx,
            connection: &mut QuicConnection,
            stream: StreamId,
            limit: u64,
        ) {
            connection
                .inner_mut()
                .process_frame(
                    cx,
                    &QuicFrame::MaxStreamData {
                        stream_id: VarInt::from_u64_unchecked(stream.0),
                        maximum_stream_data: VarInt::from_u64_unchecked(limit),
                    },
                    PacketNumberSpace::ApplicationData,
                )
                .unwrap();
        }

        fn grant_connection_credit(cx: &Cx, connection: &mut QuicConnection, limit: u64) {
            connection
                .inner_mut()
                .process_frame(
                    cx,
                    &QuicFrame::MaxData {
                        maximum_data: VarInt::from_u64_unchecked(limit),
                    },
                    PacketNumberSpace::ApplicationData,
                )
                .unwrap();
        }

        #[test]
        fn feedback_resumes_on_both_credit_wakes_without_new_input_and_detects_decoder_stop() {
            for streaming in [false, true] {
                assert_feedback_credit_wakes_and_critical_stop(streaming);
            }
        }

        fn feedback_stream_limit_fixture(cx: &Cx) -> (NativeH3Session, QuicConnection) {
            let mut connection = connection_with_config(cx, true, NativeQuicConnectionConfig {
                max_local_uni: 1,
                ..NativeQuicConnectionConfig::default()
            });
            let mut session = NativeH3Session::with_config(H3ConnectionConfig {
                endpoint_role: H3EndpointRole::Server,
                ..H3ConnectionConfig::default()
            }.with_dynamic_qpack());
            session.initialize(cx, &mut connection, H3Settings {
                qpack_blocked_streams: Some(1),
                ..H3Settings::default()
            }).unwrap();
            assert_eq!(session.local_control_stream, Some(StreamId(3)));
            (session, connection)
        }

        fn grant_stream_count(
            cx: &Cx,
            connection: &mut QuicConnection,
            bidirectional: bool,
            limit: u64,
        ) {
            connection.inner_mut().process_frame(
                cx,
                &QuicFrame::MaxStreams {
                    bidirectional,
                    maximum_streams: VarInt::from_u64_unchecked(limit),
                },
                PacketNumberSpace::ApplicationData,
            ).unwrap();
        }

        #[test]
        fn decoder_feedback_waits_for_stream_count_credit_and_replays_its_exact_fifo() {
            let cx = Cx::for_testing();
            let (mut session, mut connection) = feedback_stream_limit_fixture(&cx);
            let mut peer = peer_encoder_with_blocked_streams(4096, 1);
            let encoder_bytes = encoder_wire(&mut peer, &[("x-credit", "retained")]);
            inject_encoder(&cx, &mut session, &mut connection, encoder_bytes);
            let section = request_section(&peer, 0);
            peer.submit_field_section(0, &section).unwrap();
            connection.inner_mut().accept_remote_stream(&cx, StreamId(0)).unwrap();
            inject_field_frame(&cx, &mut connection, StreamId(0), 0, section, true);
            assert!(matches!(
                next_field_limit_event(&cx, &mut session, &mut connection),
                NativeH3Event::RequestHeaders { stream_id: StreamId(0), .. }
            ));
            assert_eq!(
                next_field_limit_event(&cx, &mut session, &mut connection),
                NativeH3Event::Finished { stream_id: StreamId(0) }
            );
            let retained = session.dynamic_receive.as_ref().unwrap().feedback.clone();
            assert_eq!(retained.iter().copied().collect::<Vec<_>>(), vec![3, 1, 0x80]);
            assert!(session.dynamic_receive.as_ref().unwrap().decoder_stream.is_none());
            assert!(connection.inner().streams().stream(StreamId(7)).is_err());
            for _ in 0..3 {
                assert_eq!(session.next_event(&cx, &mut connection).unwrap(), None);
                assert_eq!(session.dynamic_receive.as_ref().unwrap().feedback, retained);
            }

            let counter = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&counter));
            let mut task = TaskContext::from_waker(&waker);
            for _ in 0..3 {
                assert!(session.poll_event(&cx, &mut connection, &mut task).is_pending());
            }
            assert_eq!(counter.0.load(Ordering::SeqCst), 0, "stream-count wait must park");
            grant_stream_count(&cx, &mut connection, true, 129);
            grant_stream_count(&cx, &mut connection, false, 1);
            assert_eq!(counter.0.load(Ordering::SeqCst), 0, "unrelated or duplicate grants do not wake");
            assert!(session.poll_event(&cx, &mut connection, &mut task).is_pending());
            grant_stream_count(&cx, &mut connection, false, 2);
            assert!(counter.0.load(Ordering::SeqCst) > 0);
            assert!(session.poll_event(&cx, &mut connection, &mut task).is_pending());
            assert_eq!(session.dynamic_receive.as_ref().unwrap().decoder_stream, Some(StreamId(7)));
            assert!(session.dynamic_receive.as_ref().unwrap().feedback.is_empty());
            let mut decoder_wire = Vec::new();
            assert_eq!(
                feedback(&cx, &mut session, &mut connection, &mut peer, &mut decoder_wire),
                vec![
                    QpackDecoderInstruction::InsertCountIncrement { increment: 1 },
                    QpackDecoderInstruction::HeaderAcknowledgement { stream_id: 0 },
                ]
            );
            assert_eq!(decoder_wire, retained.into_iter().collect::<Vec<_>>());
            assert_eq!(peer.decoder_feedback().outstanding_reference_count(), 0);
            assert_eq!(peer.known_received_count(), 1);
            assert!(session.poll_event(&cx, &mut connection, &mut task).is_pending());
            assert!(feedback(&cx, &mut session, &mut connection, &mut peer, &mut decoder_wire).is_empty());
            assert_eq!(connection.open_uni_stream(&cx).unwrap_err(), NativeQuicConnectionError::StreamTable(
                StreamTableError::StreamLimitExceeded {
                    direction: StreamDirection::Unidirectional, limit: 2,
                }
            ));
        }

        #[test]
        fn parked_decoder_stream_admission_observes_cancellation_and_connection_close() {
            for cancel in [false, true] {
                let cx = Cx::for_testing();
                let driver_cx = Cx::for_testing();
                let (mut session, mut connection) = feedback_stream_limit_fixture(&cx);
                let mut peer = peer_encoder_with_blocked_streams(4096, 1);
                let encoder_bytes = encoder_wire(&mut peer, &[("x-credit", "retained")]);
                inject_encoder(&cx, &mut session, &mut connection, encoder_bytes);
                let retained = session.dynamic_receive.as_ref().unwrap().feedback.clone();
                let counter = Arc::new(WakeCount::default());
                let waker = Waker::from(Arc::clone(&counter));
                let mut task = TaskContext::from_waker(&waker);
                assert!(session.poll_event(&cx, &mut connection, &mut task).is_pending());
                assert_eq!(counter.0.load(Ordering::SeqCst), 0);
                if cancel {
                    cx.set_cancel_requested(true);
                } else {
                    connection.inner_mut().close_immediately(&driver_cx, H3_REQUEST_CANCELLED).unwrap();
                }
                assert!(counter.0.load(Ordering::SeqCst) > 0, "terminal transition must wake the owner");
                let expected = if cancel {
                    NativeH3SessionError::Transport(NativeQuicConnectionError::Cancelled)
                } else {
                    NativeH3SessionError::InvalidState("QUIC connection is not established for application data")
                };
                assert_eq!(session.poll_event(&cx, &mut connection, &mut task), Poll::Ready(Err(expected)));
                assert_eq!(session.dynamic_receive.as_ref().unwrap().feedback, retained);
                assert!(session.dynamic_receive.as_ref().unwrap().decoder_stream.is_none());
                assert!(connection.inner().streams().stream(StreamId(7)).is_err());
                assert!(cx.inner.read().cancel_waker_registrations.is_empty());
                if cancel {
                    // Cancelling this drive attempt cannot erase already owed
                    // feedback when the same session is driven with a fresh Cx.
                    grant_stream_count(&driver_cx, &mut connection, false, 2);
                    assert_eq!(session.next_event(&driver_cx, &mut connection).unwrap(), None);
                    let mut decoder_wire = Vec::new();
                    assert_eq!(
                        feedback(&driver_cx, &mut session, &mut connection, &mut peer, &mut decoder_wire),
                        vec![QpackDecoderInstruction::InsertCountIncrement { increment: 1 }]
                    );
                    assert_eq!(decoder_wire, retained.into_iter().collect::<Vec<_>>());
                }
            }
        }

        #[test]
        fn decoder_preserves_critical_wake_after_queuing_its_final_feedback() {
            let cx = Cx::for_testing();
            let (mut session, mut connection) = fixture(&cx, true, false, H3Settings::default());
            drain_peer_limit_stream(&cx, &mut connection, session.local_control_stream.unwrap());
            let used = connection.inner().streams().connection_send_limit()
                - connection.inner().streams().connection_send_remaining();
            connection.inner_mut().constrain_connection_send_limit_for_testing(&cx, used).unwrap();
            let mut peer = peer_encoder(NATIVE_H3_DEFAULT_QPACK_DECODER_CAPACITY as u64);
            let wire = encoder_wire(&mut peer, &[("x-final-feedback", "retained")]);
            inject_encoder(&cx, &mut session, &mut connection, wire);
            let decoder = session.dynamic_receive.as_ref().unwrap().decoder_stream.unwrap();
            assert_eq!(session.dynamic_receive.as_ref().unwrap().feedback.len(), 2);
            grant_connection_credit(&cx, &mut connection, used + 2);
            let counter = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&counter));
            let mut task = TaskContext::from_waker(&waker);
            session.drive_qpack_feedback(&cx, &mut connection, Some(&mut task)).unwrap();
            assert!(session.dynamic_receive.as_ref().unwrap().feedback.is_empty());
            assert_eq!(connection.pending_stream_data_bytes(decoder), 2);
            assert_eq!(counter.0.load(Ordering::SeqCst), 0);
            // No later event poll or packet-assembly wake can restore a watcher
            // lost when the last feedback bytes passed write admission.
            connection.inner_mut().process_frame(
                &cx,
                &QuicFrame::StopSending {
                    stream_id: VarInt::from_u64_unchecked(decoder.0),
                    error_code: VarInt::from_u64_unchecked(H3_REQUEST_CANCELLED),
                },
                PacketNumberSpace::ApplicationData,
            ).unwrap();
            assert!(counter.0.load(Ordering::SeqCst) > 0);
            assert_eq!(
                session.drive_qpack_feedback(&cx, &mut connection, Some(&mut task)),
                Err(NativeH3SessionError::CriticalStreamClosed {
                    stream_id: decoder,
                    stream_type: H3UniStreamType::QpackDecoder,
                }),
            );
        }

        fn assert_feedback_credit_wakes_and_critical_stop(streaming: bool) {
            let cx = Cx::for_testing();
            let (mut session, mut connection) =
                fixture(&cx, true, streaming, H3Settings::default());
            let control = session.local_control_stream.unwrap();
            drain_peer_limit_stream(&cx, &mut connection, control);
            let used = connection.inner().streams().connection_send_limit()
                - connection.inner().streams().connection_send_remaining();
            connection
                .inner_mut()
                .constrain_connection_send_limit_for_testing(&cx, used)
                .unwrap();
            let mut peer = peer_encoder(NATIVE_H3_DEFAULT_QPACK_DECODER_CAPACITY as u64);
            let wire = encoder_wire(&mut peer, &[("x-credit", "retained")]);
            inject_encoder(&cx, &mut session, &mut connection, wire);
            let decoder = session.dynamic_receive.as_ref().unwrap().decoder_stream.unwrap();
            connection
                .inner_mut()
                .set_fresh_stream_send_limit(&cx, decoder, 0)
                .unwrap();
            assert_eq!(connection.pending_stream_data_bytes(decoder), 0);
            assert!(!session.dynamic_receive.as_ref().unwrap().feedback.is_empty());

            let counter = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&counter));
            let mut task = TaskContext::from_waker(&waker);
            for _ in 0..3 {
                assert!(session.poll_event(&cx, &mut connection, &mut task).is_pending());
            }
            assert_eq!(counter.0.load(Ordering::SeqCst), 0);

            // Each credit scope wakes the real parked task. Opening only one
            // scope must preserve the entire suffix and re-register the wait.
            grant_stream_credit(&cx, &mut connection, decoder, 1);
            assert!(counter.0.swap(0, Ordering::SeqCst) > 0);
            assert!(session.poll_event(&cx, &mut connection, &mut task).is_pending());
            assert_eq!(connection.pending_stream_data_bytes(decoder), 0);
            assert_eq!(counter.0.load(Ordering::SeqCst), 0);
            grant_connection_credit(&cx, &mut connection, used + 1);
            assert!(counter.0.swap(0, Ordering::SeqCst) > 0);
            assert!(session.poll_event(&cx, &mut connection, &mut task).is_pending());
            let mut decoder_wire = Vec::new();
            assert_eq!(drain_stream(&cx, &mut connection, decoder, &mut decoder_wire), 0);
            assert_eq!(decoder_wire, vec![3], "one-byte window sends only the type prefix");

            counter.0.store(0, Ordering::SeqCst);
            assert!(session.poll_event(&cx, &mut connection, &mut task).is_pending());
            assert_eq!(counter.0.load(Ordering::SeqCst), 0);
            grant_connection_credit(&cx, &mut connection, used + 2);
            assert!(counter.0.swap(0, Ordering::SeqCst) > 0);
            assert!(session.poll_event(&cx, &mut connection, &mut task).is_pending());
            assert_eq!(connection.pending_stream_data_bytes(decoder), 0);
            grant_stream_credit(&cx, &mut connection, decoder, 2);
            assert!(counter.0.swap(0, Ordering::SeqCst) > 0);
            assert!(session.poll_event(&cx, &mut connection, &mut task).is_pending());
            assert_eq!(drain_stream(&cx, &mut connection, decoder, &mut decoder_wire), 0);
            assert_eq!(decoder_wire, vec![3, 1], "increment survives prefix fragmentation");
            assert!(session.dynamic_receive.as_ref().unwrap().feedback.is_empty());
            peer.register_stream(decoder.0, H3UniStreamType::QpackDecoder).unwrap();
            assert_eq!(
                peer.feed_decoder_stream_bytes(decoder.0, &decoder_wire[1..])
                    .unwrap()
                    .instructions_processed(),
                1
            );
            assert_eq!(peer.known_received_count(), 1);

            // An empty feedback queue does not make the critical decoder stream optional.
            assert!(session.poll_event(&cx, &mut connection, &mut task).is_pending());
            counter.0.store(0, Ordering::SeqCst);
            connection
                .inner_mut()
                .process_frame(
                    &cx,
                    &QuicFrame::StopSending {
                        stream_id: VarInt::from_u64_unchecked(decoder.0),
                        error_code: VarInt::from_u64_unchecked(H3_REQUEST_CANCELLED),
                    },
                    PacketNumberSpace::ApplicationData,
                )
                .unwrap();
            assert!(counter.0.load(Ordering::SeqCst) > 0, "critical STOP must wake the session");
            assert_eq!(
                session.poll_event(&cx, &mut connection, &mut task),
                Poll::Ready(Err(NativeH3SessionError::CriticalStreamClosed {
                    stream_id: decoder,
                    stream_type: H3UniStreamType::QpackDecoder,
                }))
            );
        }

        #[test]
        fn dynamic_receive_rejects_an_unavailable_reference_with_zero_blocked_streams() {
            let cx = Cx::for_testing();
            let (mut session, mut connection) =
                fixture(&cx, true, false, H3Settings::default());
            let mut peer = peer_encoder(NATIVE_H3_DEFAULT_QPACK_DECODER_CAPACITY as u64);
            // Encode a real dynamic reference, but deliberately withhold its encoder stream.
            let _wire = encoder_wire(&mut peer, &[("x-late", "unavailable")]);
            let section = request_section(&peer, 0);
            connection
                .inner_mut()
                .accept_remote_stream(&cx, StreamId(0))
                .unwrap();
            inject_field_frame(&cx, &mut connection, StreamId(0), 0, section, false);
            let error = session.next_event(&cx, &mut connection).unwrap_err();
            assert_eq!(
                error,
                NativeH3SessionError::Protocol(H3NativeError::QpackPolicy(
                    "qpack blocked stream capacity is zero"
                ))
            );
            assert_eq!(session.next_event(&cx, &mut connection).unwrap_err(), error);
            let receive = session.dynamic_receive.as_ref().unwrap();
            assert_eq!(receive.qpack.received_blocked_scheduler().blocked_stream_count(), 0);
            assert_eq!(receive.qpack.received_decoder_feedback().outstanding_reference_count(), 0);
            assert!(receive.feedback.is_empty());
            assert!(receive.decoder_stream.is_none());
        }

        fn poll_buffered_event(
            cx: &Cx,
            session: &mut NativeH3Session,
            connection: &mut QuicConnection,
            task: &mut TaskContext<'_>,
        ) -> NativeH3Event {
            for _ in 0..512 {
                if let Poll::Ready(result) = session.poll_event(cx, connection, task) {
                    return result.expect("buffered protocol input remains valid");
                }
            }
            panic!("buffered input did not resume the parked HTTP/3 event consumer");
        }

        #[test]
        fn blocked_request_resumes_on_encoder_input_without_stalling_other_streams() {
            for explicit_chunks in [false, true] {
                let cx = Cx::for_testing();
                let (mut session, mut connection) = fixture(
                    &cx,
                    true,
                    explicit_chunks,
                    H3Settings {
                        qpack_blocked_streams: Some(2),
                        ..H3Settings::default()
                    },
                );
                let mut peer = peer_encoder_with_blocked_streams(4096, 2);
                let encoder_bytes = encoder_wire(&mut peer, &[("x-late", "arrived")]);
                let section = request_section(&peer, 0);
                assert_eq!(
                    peer.submit_field_section(0, &section).unwrap(),
                    QpackBlockedStreamStatus::Blocked
                );
                let body = b"body retained behind compressed headers";
                let mut wire = Vec::new();
                H3Frame::Headers(section.clone()).encode(&mut wire).unwrap();
                H3Frame::Data(body.to_vec()).encode(&mut wire).unwrap();
                let stream = StreamId(0);
                connection.inner_mut().accept_remote_stream(&cx, stream).unwrap();
                connection.inner_mut().receive_stream_bytes(
                    &cx, stream, 0, Bytes::from(wire), true,
                ).unwrap();
                assert_eq!(session.next_event(&cx, &mut connection).unwrap(), None);
                let receive = session.dynamic_receive.as_ref().unwrap();
                assert_eq!(receive.qpack.received_blocked_scheduler().blocked_stream_count(), 1);
                assert_eq!(receive.pending_section_bytes, section.len());
                assert_eq!(session.incoming.get(&stream).unwrap().header_blocks_seen, 0);
                assert!(!session.terminal_streams.contains(stream));
                assert!(session.events.is_empty());

                let sibling = StreamId(4);
                connection.inner_mut().accept_remote_stream(&cx, sibling).unwrap();
                inject_field_frame(
                    &cx, &mut connection, sibling, 0,
                    qpack_encode_request_field_section(&field_limit_request()).unwrap(), true,
                );
                assert_eq!(
                    next_field_limit_event(&cx, &mut session, &mut connection),
                    NativeH3Event::RequestHeaders { stream_id: sibling, head: field_limit_request() }
                );
                assert_eq!(
                    next_field_limit_event(&cx, &mut session, &mut connection),
                    NativeH3Event::Finished { stream_id: sibling }
                );

                let counter = Arc::new(WakeCount::default());
                let waker = Waker::from(Arc::clone(&counter));
                let mut task = TaskContext::from_waker(&waker);
                for _ in 0..3 {
                    assert!(session.poll_event(&cx, &mut connection, &mut task).is_pending());
                }
                assert_eq!(counter.0.load(Ordering::SeqCst), 0, "a blocked stream must park");

                let encoder = StreamId(6);
                connection.inner_mut().accept_remote_stream(&cx, encoder).unwrap();
                let split = encoder_bytes.len() - 1;
                connection.inner_mut().receive_stream_bytes(
                    &cx, encoder, 0, Bytes::copy_from_slice(&encoder_bytes[..split]), false,
                ).unwrap();
                assert_eq!(session.next_event(&cx, &mut connection).unwrap(), None);
                assert_eq!(
                    session.dynamic_receive.as_ref().unwrap().qpack
                        .received_blocked_scheduler().blocked_stream_count(),
                    1,
                    "an incomplete encoder instruction cannot unblock HEADERS"
                );
                assert!(session.poll_event(&cx, &mut connection, &mut task).is_pending());
                counter.0.store(0, Ordering::SeqCst);
                connection.inner_mut().receive_stream_bytes(
                    &cx, encoder, split as u64,
                    Bytes::copy_from_slice(&encoder_bytes[split..]), false,
                ).unwrap();
                assert!(counter.0.load(Ordering::SeqCst) > 0, "encoder input must wake the waiter");
                let NativeH3Event::RequestHeaders { stream_id, head } =
                    poll_buffered_event(&cx, &mut session, &mut connection, &mut task)
                else {
                    panic!("HEADERS must precede buffered DATA and FIN");
                };
                assert_eq!(stream_id, stream);
                assert_eq!(head.headers, vec![("x-late".to_owned(), "arrived".to_owned())]);
                assert_eq!(session.dynamic_receive.as_ref().unwrap().pending_section_bytes, 0);

                session.pause_request_stream(stream).unwrap();
                counter.0.store(0, Ordering::SeqCst);
                assert!(session.poll_event(&cx, &mut connection, &mut task).is_pending());
                assert_eq!(counter.0.load(Ordering::SeqCst), 0);
                assert!(session.resume_request_stream(stream).unwrap());
                assert!(counter.0.load(Ordering::SeqCst) > 0);
                let mut received = Vec::new();
                loop {
                    match poll_buffered_event(&cx, &mut session, &mut connection, &mut task) {
                        NativeH3Event::Data { stream_id, bytes } => {
                            assert_eq!(stream_id, stream);
                            received.extend_from_slice(&bytes);
                        }
                        NativeH3Event::Finished { stream_id } => {
                            assert_eq!(stream_id, stream);
                            break;
                        }
                        event => panic!("unexpected event after HEADERS: {event:?}"),
                    }
                }
                assert_eq!(received, body);
                assert!(!session.incoming.contains_key(&stream));
                assert!(session.dynamic_receive.as_ref().unwrap().pending_sections.is_empty());
                let mut decoder_wire = Vec::new();
                assert_eq!(
                    feedback(&cx, &mut session, &mut connection, &mut peer, &mut decoder_wire),
                    vec![
                        QpackDecoderInstruction::InsertCountIncrement { increment: 1 },
                        QpackDecoderInstruction::HeaderAcknowledgement { stream_id: 0 },
                    ]
                );
                assert_eq!(peer.decoder_feedback().outstanding_reference_count(), 0);
            }
        }

        #[test]
        fn reset_or_cancel_of_a_blocked_fin_releases_state_without_resurrection() {
            for terminal in 0..3 {
                let cx = Cx::for_testing();
                let (mut session, mut connection) = fixture(
                    &cx, true, true,
                    H3Settings { qpack_blocked_streams: Some(1), ..H3Settings::default() },
                );
                let mut peer = peer_encoder_with_blocked_streams(4096, 1);
                let encoder_bytes = encoder_wire(&mut peer, &[("x-late", "discarded")]);
                let section = request_section(&peer, 0);
                peer.submit_field_section(0, &section).unwrap();
                let stream = StreamId(0);
                connection.inner_mut().accept_remote_stream(&cx, stream).unwrap();
                let final_size = inject_field_frame(
                    &cx, &mut connection, stream, 0, section, true,
                );
                assert_eq!(session.next_event(&cx, &mut connection).unwrap(), None);
                assert_eq!(
                    session.dynamic_receive.as_ref().unwrap().qpack
                        .received_blocked_scheduler().blocked_stream_count(),
                    1
                );
                assert!(!session.terminal_streams.contains(stream), "blocked FIN is deferred");
                match terminal {
                    0 => {
                        connection.inner_mut().reset_stream_receive(
                            &cx, stream, H3_REQUEST_CANCELLED, final_size,
                        ).unwrap();
                        assert_eq!(
                            next_field_limit_event(&cx, &mut session, &mut connection),
                            NativeH3Event::StreamReset {
                                stream_id: stream, error_code: H3_REQUEST_CANCELLED, final_size,
                            }
                        );
                    }
                    1 => session.cancel_request(&cx, &mut connection, stream).unwrap(),
                    _ => connection.stop_stream_receiving(&cx, stream, H3_REQUEST_CANCELLED).unwrap(),
                }
                assert_eq!(session.next_event(&cx, &mut connection).unwrap(), None);
                let receive = session.dynamic_receive.as_ref().unwrap();
                assert!(receive.pending_sections.is_empty());
                assert_eq!(receive.pending_section_bytes, 0);
                assert_eq!(receive.qpack.received_blocked_scheduler().pending_section_count(0), 0);
                assert!(!session.incoming.contains_key(&stream));
                assert!(!session.streaming_receive.as_ref().unwrap().ready.contains_key(&stream));
                let mut decoder_wire = Vec::new();
                assert_eq!(
                    feedback(&cx, &mut session, &mut connection, &mut peer, &mut decoder_wire),
                    vec![QpackDecoderInstruction::StreamCancellation { stream_id: 0 }]
                );
                assert_eq!(peer.decoder_feedback().outstanding_reference_count(), 0);

                inject_encoder(&cx, &mut session, &mut connection, encoder_bytes);
                assert_eq!(
                    feedback(&cx, &mut session, &mut connection, &mut peer, &mut decoder_wire),
                    vec![QpackDecoderInstruction::InsertCountIncrement { increment: 1 }]
                );
                assert_eq!(session.next_event(&cx, &mut connection).unwrap(), None);
                let sibling = StreamId(4);
                connection.inner_mut().accept_remote_stream(&cx, sibling).unwrap();
                inject_field_frame(
                    &cx, &mut connection, sibling, 0,
                    qpack_encode_request_field_section(&field_limit_request()).unwrap(), true,
                );
                assert!(matches!(
                    next_field_limit_event(&cx, &mut session, &mut connection),
                    NativeH3Event::RequestHeaders { stream_id, .. } if stream_id == sibling
                ));
            }
        }

        #[test]
        fn blocked_stream_count_limit_is_a_sticky_protocol_error() {
            let cx = Cx::for_testing();
            let (mut session, mut connection) = fixture(
                &cx, true, false,
                H3Settings { qpack_blocked_streams: Some(1), ..H3Settings::default() },
            );
            let mut peer = peer_encoder_with_blocked_streams(4096, 2);
            let _encoder_bytes = encoder_wire(&mut peer, &[("x-late", "unavailable")]);
            let mut plan = qpack_static_plan_for_request(&field_limit_request());
            plan.push(QpackFieldPlan::DynamicIndex(0));
            plan.push(QpackFieldPlan::Literal {
                name: "x-padding".to_owned(),
                value: "~".repeat(NATIVE_H3_MAX_QPACK_BLOCKED_SECTION_BYTES / 2),
            });
            let section = qpack_encode_field_section_with_context(&plan, Some(peer.context())).unwrap();
            assert!(section.len() > NATIVE_H3_MAX_QPACK_BLOCKED_SECTION_BYTES / 2);
            // The second section violates both limits. The local byte budget
            // must not downgrade the peer's SETTINGS violation to a reset.
            for id in [0, 4] {
                connection.inner_mut().accept_remote_stream(&cx, StreamId(id)).unwrap();
                inject_field_frame(&cx, &mut connection, StreamId(id), 0, section.clone(), true);
                if id == 0 {
                    assert_eq!(session.next_event(&cx, &mut connection).unwrap(), None);
                    assert_eq!(session.dynamic_receive.as_ref().unwrap().pending_section_bytes, section.len());
                }
            }
            let error = NativeH3SessionError::Protocol(H3NativeError::QpackPolicy(
                "qpack blocked stream capacity exceeded",
            ));
            assert_eq!(session.next_event(&cx, &mut connection).unwrap_err(), error);
            assert_eq!(session.next_event(&cx, &mut connection).unwrap_err(), error);
            let receive = session.dynamic_receive.as_ref().unwrap();
            assert_eq!(receive.qpack.received_blocked_scheduler().blocked_stream_count(), 1);
            assert_eq!(receive.pending_section_bytes, section.len());
            assert!(receive.feedback.is_empty(), "undecoded sections cannot be acknowledged");
            assert!(session.events.is_empty());
        }

        #[test]
        fn blocked_field_sections_have_a_connection_wide_retained_byte_limit() {
            let cx = Cx::for_testing();
            let (mut session, mut connection) = fixture(
                &cx, true, false,
                H3Settings { qpack_blocked_streams: Some(16), ..H3Settings::default() },
            );
            let mut peer = peer_encoder_with_blocked_streams(4096, 16);
            let _encoder_bytes = encoder_wire(&mut peer, &[("x-late", "unavailable")]);
            let mut plan = qpack_static_plan_for_request(&field_limit_request());
            plan.push(QpackFieldPlan::DynamicIndex(0));
            plan.push(QpackFieldPlan::Literal {
                name: "x-padding".to_owned(),
                // This value does not get smaller under QPACK's Huffman code.
                value: "~".repeat(NATIVE_H3_MAX_QPACK_BLOCKED_SECTION_BYTES / 2),
            });
            let section = qpack_encode_field_section_with_context(&plan, Some(peer.context())).unwrap();
            assert!(section.len() > NATIVE_H3_MAX_QPACK_BLOCKED_SECTION_BYTES / 2);
            assert!(section.len() < session.config.max_frame_payload_size);
            peer.submit_field_section(0, &section).unwrap();
            peer.submit_field_section(4, &section).unwrap();
            connection.inner_mut().accept_remote_stream(&cx, StreamId(0)).unwrap();
            inject_field_frame(&cx, &mut connection, StreamId(0), 0, section.clone(), true);
            assert_eq!(session.next_event(&cx, &mut connection).unwrap(), None);
            assert_eq!(session.dynamic_receive.as_ref().unwrap().pending_section_bytes, section.len());
            connection.inner_mut().accept_remote_stream(&cx, StreamId(4)).unwrap();
            inject_field_frame(&cx, &mut connection, StreamId(4), 0, section.clone(), true);
            assert_eq!(
                next_field_limit_event(&cx, &mut session, &mut connection),
                NativeH3Event::StreamReset {
                    stream_id: StreamId(4), error_code: H3_EXCESSIVE_LOAD, final_size: 0,
                }
            );
            let receive = session.dynamic_receive.as_ref().unwrap();
            assert_eq!(receive.pending_sections.len(), 1);
            assert_eq!(receive.pending_section_bytes, section.len());
            assert_eq!(receive.qpack.received_blocked_scheduler().pending_section_count(4), 0);
            assert!(receive.first_failure.is_none());
            assert!(session.events.is_empty());
            let mut decoder_wire = Vec::new();
            assert_eq!(
                feedback(&cx, &mut session, &mut connection, &mut peer, &mut decoder_wire),
                vec![QpackDecoderInstruction::StreamCancellation { stream_id: 4 }]
            );
            session.cancel_request(&cx, &mut connection, StreamId(0)).unwrap();
            assert_eq!(session.next_event(&cx, &mut connection).unwrap(), None);
            assert_eq!(session.dynamic_receive.as_ref().unwrap().pending_section_bytes, 0);
            assert_eq!(
                feedback(&cx, &mut session, &mut connection, &mut peer, &mut decoder_wire),
                vec![QpackDecoderInstruction::StreamCancellation { stream_id: 0 }]
            );
            assert_eq!(peer.decoder_feedback().outstanding_reference_count(), 0);
        }

        #[test]
        fn blocked_informational_final_and_trailer_sections_resume_in_wire_order() {
            for explicit_chunks in [false, true] {
                let cx = Cx::for_testing();
                let (mut session, mut connection) = fixture(
                    &cx, false, explicit_chunks,
                    H3Settings { qpack_blocked_streams: Some(1), ..H3Settings::default() },
                );
                let stream = session.send_request(
                    &cx, &mut connection, &field_limit_request(), Bytes::new(),
                ).unwrap();
                let mut peer = peer_encoder_with_blocked_streams(4096, 1);
                let capacity = QpackEncoderInstruction::SetDynamicTableCapacity { capacity: 4096 };
                peer.apply_local_encoder_instruction(&capacity).unwrap();
                let mut chunks = vec![vec![2], Vec::new(), Vec::new()];
                qpack_encode_encoder_instruction(&mut chunks[0], &capacity).unwrap();
                for (index, (name, value)) in [
                    (":status", "103"), (":status", "200"), ("x-trailer", "complete"),
                ].into_iter().enumerate() {
                    let instruction = QpackEncoderInstruction::InsertWithoutNameReference {
                        name: name.to_owned(), value: value.to_owned(),
                    };
                    peer.apply_local_encoder_instruction(&instruction).unwrap();
                    qpack_encode_encoder_instruction(&mut chunks[index], &instruction).unwrap();
                }
                let mut wire = Vec::new();
                for entry in 0..3 {
                    let section = qpack_encode_field_section_with_context(
                        &[QpackFieldPlan::DynamicIndex(entry)], Some(peer.context()),
                    ).unwrap();
                    assert_eq!(peer.submit_field_section(stream.0, &section).unwrap(), QpackBlockedStreamStatus::Blocked);
                    H3Frame::Headers(section).encode(&mut wire).unwrap();
                    if entry == 1 {
                        H3Frame::Data(b"ok".to_vec()).encode(&mut wire).unwrap();
                    }
                }
                connection.inner_mut().receive_stream_bytes(
                    &cx, stream, 0, Bytes::from(wire), true,
                ).unwrap();
                assert_eq!(session.next_event(&cx, &mut connection).unwrap(), None);
                let encoder = StreamId(7);
                connection.inner_mut().accept_remote_stream(&cx, encoder).unwrap();
                let mut encoder_offset = 0;
                let mut decoder_wire = Vec::new();
                for (index, chunk) in chunks.into_iter().enumerate() {
                    assert_eq!(
                        session.dynamic_receive.as_ref().unwrap().qpack
                            .received_blocked_scheduler().blocked_stream_count(),
                        1
                    );
                    let len = chunk.len();
                    connection.inner_mut().receive_stream_bytes(
                        &cx, encoder, encoder_offset, Bytes::from(chunk), false,
                    ).unwrap();
                    encoder_offset += len as u64;
                    let event = next_field_limit_event(&cx, &mut session, &mut connection);
                    if index < 2 {
                        assert_eq!(event, NativeH3Event::ResponseHeaders {
                            stream_id: stream,
                            head: H3ResponseHead::new(if index == 0 { 103 } else { 200 }, Vec::new()).unwrap(),
                        });
                    } else {
                        assert_eq!(event, NativeH3Event::Trailers {
                            stream_id: stream,
                            fields: vec![("x-trailer".to_owned(), "complete".to_owned())],
                        });
                    }
                    assert!(session.events.is_empty(), "resume expands only one event");
                    if index == 1 {
                        let mut body = Vec::new();
                        while body.len() < 2 {
                            let NativeH3Event::Data { stream_id, bytes } =
                                next_field_limit_event(&cx, &mut session, &mut connection)
                            else {
                                panic!("DATA must follow final HEADERS and precede trailers");
                            };
                            assert_eq!(stream_id, stream);
                            body.extend_from_slice(&bytes);
                        }
                        assert_eq!(body, b"ok");
                    }
                    if index == 2 {
                        assert_eq!(
                            next_field_limit_event(&cx, &mut session, &mut connection),
                            NativeH3Event::Finished { stream_id: stream }
                        );
                    }
                    assert_eq!(session.next_event(&cx, &mut connection).unwrap(), None);
                    assert_eq!(
                        feedback(&cx, &mut session, &mut connection, &mut peer, &mut decoder_wire),
                        vec![
                            QpackDecoderInstruction::InsertCountIncrement { increment: 1 },
                            QpackDecoderInstruction::HeaderAcknowledgement { stream_id: stream.0 },
                        ]
                    );
                }
                assert!(session.dynamic_receive.as_ref().unwrap().pending_sections.is_empty());
                assert_eq!(peer.decoder_feedback().outstanding_reference_count(), 0);
                assert!(peer.decoder_feedback().cancelled_stream_ids().is_empty());
            }
        }

        #[test]
        fn unblocked_expansion_is_size_checked_before_header_delivery() {
            let cx = Cx::for_testing();
            let (mut session, mut connection) = fixture(
                &cx, true, false,
                H3Settings {
                    qpack_max_table_capacity: Some(NATIVE_H3_MAX_QPACK_DECODER_CAPACITY as u64),
                    qpack_blocked_streams: Some(1),
                    ..H3Settings::default()
                },
            );
            let mut peer = peer_encoder_with_blocked_streams(
                NATIVE_H3_MAX_QPACK_DECODER_CAPACITY as u64, 1,
            );
            let value = "x".repeat(60_000);
            let encoder_bytes = encoder_wire(&mut peer, &[("x-expanded", value.as_str())]);
            let mut plan = qpack_static_plan_for_request(&field_limit_request());
            plan.extend((0..20).map(|_| QpackFieldPlan::DynamicIndex(0)));
            let section = qpack_encode_field_section_with_context(&plan, Some(peer.context())).unwrap();
            assert!(section.len() < 64, "tiny compressed input expands beyond the field limit");
            peer.submit_field_section(0, &section).unwrap();
            connection.inner_mut().accept_remote_stream(&cx, StreamId(0)).unwrap();
            inject_field_frame(&cx, &mut connection, StreamId(0), 0, section, true);
            assert_eq!(session.next_event(&cx, &mut connection).unwrap(), None);
            connection.inner_mut().accept_remote_stream(&cx, StreamId(6)).unwrap();
            connection.inner_mut().receive_stream_bytes(
                &cx, StreamId(6), 0, Bytes::from(encoder_bytes), false,
            ).unwrap();
            assert_eq!(
                next_field_limit_event(&cx, &mut session, &mut connection),
                NativeH3Event::StreamReset {
                    stream_id: StreamId(0), error_code: H3_EXCESSIVE_LOAD, final_size: 0,
                }
            );
            assert!(session.events.is_empty());
            assert!(session.dynamic_receive.as_ref().unwrap().pending_sections.is_empty());
            assert_eq!(session.dynamic_receive.as_ref().unwrap().pending_section_bytes, 0);
            let mut decoder_wire = Vec::new();
            assert_eq!(
                feedback(&cx, &mut session, &mut connection, &mut peer, &mut decoder_wire),
                vec![
                    QpackDecoderInstruction::InsertCountIncrement { increment: 1 },
                    QpackDecoderInstruction::HeaderAcknowledgement { stream_id: 0 },
                    QpackDecoderInstruction::StreamCancellation { stream_id: 0 },
                ]
            );
            assert_eq!(peer.decoder_feedback().outstanding_reference_count(), 0);
            connection.inner_mut().accept_remote_stream(&cx, StreamId(4)).unwrap();
            inject_field_frame(
                &cx, &mut connection, StreamId(4), 0,
                qpack_encode_request_field_section(&field_limit_request()).unwrap(), true,
            );
            assert!(matches!(
                next_field_limit_event(&cx, &mut session, &mut connection),
                NativeH3Event::RequestHeaders { stream_id: StreamId(4), .. }
            ));
        }

        #[test]
        fn dynamic_settings_are_bounded_before_stream_mutation_and_static_defaults_stay_static() {
            let cx = Cx::for_testing();
            for invalid in [
                H3Settings {
                    qpack_max_table_capacity: Some(NATIVE_H3_MAX_QPACK_DECODER_CAPACITY as u64 + 1),
                    ..H3Settings::default()
                },
                H3Settings {
                    qpack_blocked_streams: Some(NATIVE_H3_MAX_QPACK_BLOCKED_STREAMS + 1),
                    ..H3Settings::default()
                },
            ] {
                let mut connection = connection(&cx, true);
                let mut session = NativeH3Session::with_config(
                    H3ConnectionConfig {
                        endpoint_role: H3EndpointRole::Server,
                        ..H3ConnectionConfig::default()
                    }
                    .with_dynamic_qpack(),
                );
                assert!(session.initialize(&cx, &mut connection, invalid).is_err());
                assert!(!session.initialized);
                assert!(session.local_control_stream.is_none());
                assert!(connection.inner().streams().stream(StreamId(3)).is_err());
                session.initialize(&cx, &mut connection, H3Settings::default()).unwrap();
                assert_eq!(session.local_control_stream, Some(StreamId(3)));
                let mut wire = Vec::new();
                assert_eq!(drain_stream(&cx, &mut connection, StreamId(3), &mut wire), 0);
                assert_eq!(wire.first(), Some(&0));
                let (H3Frame::Settings(settings), consumed) =
                    H3Frame::decode(&wire[1..], &H3ConnectionConfig::default()).unwrap()
                else {
                    panic!("local SETTINGS missing");
                };
                assert_eq!(consumed, wire.len() - 1);
                assert_eq!(
                    settings.qpack_max_table_capacity,
                    Some(NATIVE_H3_DEFAULT_QPACK_DECODER_CAPACITY as u64)
                );
                assert_eq!(settings.qpack_blocked_streams, Some(0));
                assert_eq!(
                    settings.max_field_section_size,
                    Some(NATIVE_H3_MAX_QPACK_FIELD_SECTION_SIZE)
                );
            }

            let mut connection = connection(&cx, true);
            let mut session = NativeH3Session::server();
            session.initialize(&cx, &mut connection, H3Settings {
                qpack_max_table_capacity: Some(4096),
                qpack_blocked_streams: Some(8),
                ..H3Settings::default()
            }).unwrap();
            assert!(session.dynamic_receive.is_none());
            let mut wire = Vec::new();
            assert_eq!(drain_stream(&cx, &mut connection, StreamId(3), &mut wire), 0);
            let (H3Frame::Settings(settings), _) =
                H3Frame::decode(&wire[1..], &H3ConnectionConfig::default()).unwrap()
            else {
                panic!("static local SETTINGS missing");
            };
            assert_eq!(settings.qpack_max_table_capacity, Some(0));
            assert_eq!(settings.qpack_blocked_streams, Some(0));
            assert_eq!(settings.max_field_section_size, None);
        }

        #[test]
        fn repeated_large_dynamic_references_obey_the_decoded_field_limit() {
            let cx = Cx::for_testing();
            let (mut session, mut connection) = fixture(
                &cx,
                true,
                false,
                H3Settings {
                    qpack_max_table_capacity: Some(NATIVE_H3_MAX_QPACK_DECODER_CAPACITY as u64),
                    max_field_section_size: Some(u64::MAX >> 2),
                    ..H3Settings::default()
                },
            );
            assert_eq!(
                session.max_field_section_size,
                Some(NATIVE_H3_MAX_QPACK_FIELD_SECTION_SIZE)
            );
            let mut peer = peer_encoder(NATIVE_H3_MAX_QPACK_DECODER_CAPACITY as u64);
            let value = "x".repeat(64_000);
            let wire = encoder_wire(&mut peer, &[("x-expanded", value.as_str())]);
            inject_encoder(&cx, &mut session, &mut connection, wire);
            let mut decoder_wire = Vec::new();
            assert_eq!(
                feedback(&cx, &mut session, &mut connection, &mut peer, &mut decoder_wire),
                vec![QpackDecoderInstruction::InsertCountIncrement { increment: 1 }]
            );
            let mut plan = qpack_static_plan_for_request(&field_limit_request());
            plan.extend((0..17).map(|_| QpackFieldPlan::DynamicIndex(0)));
            let section =
                qpack_encode_field_section_with_context(&plan, Some(peer.context())).unwrap();
            assert!(section.len() < 128, "small wire input expands past the one-MiB bound");
            peer.submit_field_section(0, &section).unwrap();
            connection
                .inner_mut()
                .accept_remote_stream(&cx, StreamId(0))
                .unwrap();
            inject_field_frame(&cx, &mut connection, StreamId(0), 0, section, false);
            assert_eq!(
                next_field_limit_event(&cx, &mut session, &mut connection),
                NativeH3Event::StreamReset {
                    stream_id: StreamId(0),
                    error_code: H3_EXCESSIVE_LOAD,
                    final_size: 0,
                }
            );
            assert_eq!(
                feedback(&cx, &mut session, &mut connection, &mut peer, &mut decoder_wire),
                vec![
                    QpackDecoderInstruction::HeaderAcknowledgement { stream_id: 0 },
                    QpackDecoderInstruction::StreamCancellation { stream_id: 0 },
                ]
            );
            assert_eq!(peer.decoder_feedback().outstanding_reference_count(), 0);
            receive_request_head(&cx, &mut connection, StreamId(4), false);
            assert!(matches!(
                next_field_limit_event(&cx, &mut session, &mut connection),
                NativeH3Event::RequestHeaders { stream_id: StreamId(4), .. }
            ));
        }

        #[test]
        fn feedback_exhaustion_is_sticky_and_does_not_acquire_field_section_references() {
            let cx = Cx::for_testing();
            let (mut session, mut connection) =
                fixture(&cx, true, false, H3Settings::default());
            let mut peer = peer_encoder(NATIVE_H3_DEFAULT_QPACK_DECODER_CAPACITY as u64);
            let wire = encoder_wire(&mut peer, &[("x-pressure", "retained")]);
            inject_encoder(&cx, &mut session, &mut connection, wire);
            let mut decoder_wire = Vec::new();
            assert_eq!(
                feedback(&cx, &mut session, &mut connection, &mut peer, &mut decoder_wire),
                vec![QpackDecoderInstruction::InsertCountIncrement { increment: 1 }]
            );
            let decoder = session.dynamic_receive.as_ref().unwrap().decoder_stream.unwrap();
            connection
                .inner_mut()
                .set_fresh_stream_send_limit(&cx, decoder, decoder_wire.len() as u64)
                .unwrap();
            let used = connection.inner().streams().connection_send_limit()
                - connection.inner().streams().connection_send_remaining();
            connection
                .inner_mut()
                .constrain_connection_send_limit_for_testing(&cx, used)
                .unwrap();
            // Plant exact queue pressure without creating 65,536 unrelated
            // requests. No staged byte can leave either exhausted send window.
            session.dynamic_receive.as_mut().unwrap().feedback.resize(
                NATIVE_H3_MAX_QPACK_FEEDBACK_BYTES,
                0x40,
            );
            let section = request_section(&peer, 0);
            peer.submit_field_section(0, &section).unwrap();
            connection
                .inner_mut()
                .accept_remote_stream(&cx, StreamId(0))
                .unwrap();
            inject_field_frame(&cx, &mut connection, StreamId(0), 0, section, false);
            let error = NativeH3SessionError::Protocol(H3NativeError::QpackPolicy(
                "qpack decoder feedback buffer limit exceeded",
            ));
            assert_eq!(session.next_event(&cx, &mut connection).unwrap_err(), error);
            let receive = session.dynamic_receive.as_ref().unwrap();
            assert_eq!(receive.feedback.len(), NATIVE_H3_MAX_QPACK_FEEDBACK_BYTES);
            assert_eq!(receive.qpack.received_decoder_feedback().outstanding_reference_count(), 0);
            assert_eq!(receive.qpack.received_blocked_scheduler().pending_section_count(0), 0);
            // A cloned table retains reference counts. Successful eviction
            // proves no entry was protected before ACK space was reserved.
            let mut context = receive.qpack.received_context().clone();
            context.set_dynamic_table_capacity(0).unwrap();
            assert_eq!(connection.pending_stream_data_bytes(decoder), 0);
            assert_eq!(session.next_event(&cx, &mut connection).unwrap_err(), error);
        }

        #[test]
        fn a_coalesced_dynamic_header_burst_expands_only_the_event_being_delivered() {
            for explicit_chunks in [false, true] {
                let cx = Cx::for_testing();
                let (mut session, mut connection) = fixture(
                    &cx,
                    false,
                    explicit_chunks,
                    H3Settings {
                        qpack_max_table_capacity: Some(NATIVE_H3_MAX_QPACK_DECODER_CAPACITY as u64),
                        ..H3Settings::default()
                    },
                );
                assert_eq!(
                    session.streaming_receive.as_ref().unwrap().max_chunk_bytes.get(),
                    if explicit_chunks {
                        8
                    } else {
                        NATIVE_H3_DYNAMIC_RECEIVE_CHUNK_BYTES
                    }
                );
                assert_eq!(NATIVE_H3_DYNAMIC_RECEIVE_CHUNK_BYTES, 64 * 1024);
                let stream = session
                    .send_request(&cx, &mut connection, &field_limit_request(), Bytes::new())
                    .unwrap();
                let mut peer = peer_encoder(NATIVE_H3_MAX_QPACK_DECODER_CAPACITY as u64);
                let value = "x".repeat(60_000);
                let encoder = encoder_wire(&mut peer, &[("x-expanded", value.as_str())]);
                inject_encoder(&cx, &mut session, &mut connection, encoder);
                let mut decoder_wire = Vec::new();
                assert_eq!(
                    feedback(&cx, &mut session, &mut connection, &mut peer, &mut decoder_wire),
                    vec![QpackDecoderInstruction::InsertCountIncrement { increment: 1 }]
                );

                // Each tiny section expands to 960,000 value bytes. Decoding the
                // entire coalesced read before delivering its first event
                // would retain eight expanded copies in the session queue.
                let mut plan = vec![QpackFieldPlan::StaticIndex(24)]; // :status 103
                plan.extend((0..16).map(|_| QpackFieldPlan::DynamicIndex(0)));
                let section =
                    qpack_encode_field_section_with_context(&plan, Some(peer.context())).unwrap();
                assert!(section.len() < 32);
                let mut burst = Vec::new();
                for _ in 0..8 {
                    assert_eq!(
                        peer.submit_field_section(stream.0, &section).unwrap(),
                        QpackBlockedStreamStatus::Ready
                    );
                    H3Frame::Headers(section.clone()).encode(&mut burst).unwrap();
                }
                H3Frame::Headers(
                    qpack_encode_response_field_section(
                        &H3ResponseHead::new(200, Vec::new()).unwrap(),
                    )
                    .unwrap(),
                )
                .encode(&mut burst)
                .unwrap();
                assert!(burst.len() < 256);
                connection
                    .inner_mut()
                    .receive_stream_bytes(&cx, stream, 0, Bytes::from(burst), true)
                    .unwrap();

                let mut task = TaskContext::from_waker(Waker::noop());
                for index in 0..8 {
                    // Alternate both public drivers without injecting any
                    // more transport bytes or readiness notifications.
                    let event = if index % 2 == 0 {
                        next_field_limit_event(&cx, &mut session, &mut connection)
                    } else {
                        let Poll::Ready(Ok(event)) =
                            session.poll_event(&cx, &mut connection, &mut task)
                        else {
                            panic!("retained field-section lookahead did not produce its event");
                        };
                        event
                    };
                    let NativeH3Event::ResponseHeaders { stream_id, head } = event else {
                        panic!("informational HEADERS lost their receive order");
                    };
                    assert_eq!(stream_id, stream);
                    assert_eq!(head.status, 103);
                    assert_eq!(head.headers.len(), 16);
                    assert!(head.headers.iter().all(|(name, value)| {
                        name == "x-expanded" && value.len() == 60_000
                    }));
                    assert!(
                        session.events.is_empty(),
                        "later compressed sections must not be expanded into queued events"
                    );
                    assert!(!session.terminal_streams.contains(stream));
                    assert!(
                        session.streaming_receive.as_ref().unwrap().ready.contains_key(&stream)
                    );
                    if index == 0 && !explicit_chunks {
                        assert!(!session.incoming.get(&stream).unwrap().bytes.is_empty());
                    }
                    drop(head);
                }
                let NativeH3Event::ResponseHeaders { stream_id, head } =
                    next_field_limit_event(&cx, &mut session, &mut connection)
                else {
                    panic!("final response HEADERS missing");
                };
                assert_eq!(stream_id, stream);
                assert_eq!(head.status, 200);
                assert!(session.events.is_empty());
                assert_eq!(
                    next_field_limit_event(&cx, &mut session, &mut connection),
                    NativeH3Event::Finished { stream_id: stream }
                );
                assert!(session.events.is_empty());
                assert!(!session.incoming.contains_key(&stream));
                assert_eq!(
                    feedback(&cx, &mut session, &mut connection, &mut peer, &mut decoder_wire),
                    vec![
                        QpackDecoderInstruction::HeaderAcknowledgement {
                            stream_id: stream.0,
                        };
                        8
                    ]
                );
                assert_eq!(peer.decoder_feedback().outstanding_reference_count(), 0);
                assert!(peer.decoder_feedback().cancelled_stream_ids().is_empty());
            }
        }
    }
