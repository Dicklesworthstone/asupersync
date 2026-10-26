    use super::*;
    use crate::http::h3::H3Settings;
    use crate::net::quic_core::QUIC_VARINT_MAX;

    #[test]
    fn omitted_field_limit_preserves_default_wire_settings() {
        let config = NativeH3ListenerConfig::default();
        assert_eq!(config.max_request_field_section_size, None);
        assert_eq!(config.local_h3_settings(), H3Settings::default());
        let mut wire = Vec::new();
        config.local_h3_settings().encode_payload(&mut wire).unwrap();
        assert!(wire.is_empty());
    }

    #[test]
    fn field_settings_preserve_inclusive_range_and_do_not_reduce_body_reservations() {
        for streaming in [None, NonZeroUsize::new(64)] {
            let mut config = NativeH3ListenerConfig {
                streaming_request_body_buffer_bytes: streaming,
                ..NativeH3ListenerConfig::default()
            };
            let reserved = config.request_body_reservation_bytes();
            for limit in [0, 1, 63, 64, 16_383, 16_384, 65_536, QUIC_VARINT_MAX] {
                config.max_request_field_section_size = Some(limit);
                let mut wire = Vec::new();
                config.local_h3_settings().encode_payload(&mut wire).unwrap();
                let decoded = H3Settings::decode_payload(&wire).unwrap();
                assert_eq!(decoded.max_field_section_size, Some(limit));
                assert_eq!(decoded.qpack_max_table_capacity, None);
                assert_eq!(decoded.qpack_blocked_streams, None);
                assert!(decoded.unknown.is_empty());
                assert_eq!(config.request_body_reservation_bytes(), reserved);
            }
        }
    }

    #[test]
    fn listener_dynamic_profile_advertises_its_limits_on_the_actual_control_stream() {
        use crate::http::h3::{
            H3EndpointRole, H3Frame, H3QpackMode, NATIVE_H3_MAX_QPACK_FIELD_SECTION_SIZE,
        };
        use crate::net::atp::protocol::quic_frames::QuicFrame;
        use crate::net::atp::protocol::varint::VarInt;
        use crate::net::quic_core::decode_varint;
        use crate::net::quic_native::{NativeQuicConnectionConfig, PacketNumberSpace};

        for streaming in [None, NonZeroUsize::new(8)] {
            for (capacity, field_limit) in [
                (None, None),
                (None, Some(32)),
                (NonZeroUsize::new(1), Some(0)),
                (NonZeroUsize::new(4096), Some(512)),
                (NonZeroUsize::new(65_536), None),
                (NonZeroUsize::new(65_536), Some(QUIC_VARINT_MAX)),
            ] {
                let config = NativeH3ListenerConfig {
                    qpack_decoder_table_capacity: capacity,
                    max_request_field_section_size: field_limit,
                    streaming_request_body_buffer_bytes: streaming,
                    ..NativeH3ListenerConfig::default()
                };
                let session_config = config.session_config();
                assert_eq!(session_config.endpoint_role, H3EndpointRole::Server);
                assert_eq!(
                    session_config.qpack_mode,
                    if capacity.is_some() {
                        H3QpackMode::DynamicTableAllowed
                    } else {
                        H3QpackMode::StaticOnly
                    }
                );
                let cx = Cx::for_testing();
                let mut connection = QuicConnection::server(NativeQuicConnectionConfig::default());
                connection.begin_handshake(&cx).unwrap();
                connection.mark_handshake_keys_available(&cx).unwrap();
                connection.mark_app_keys_available(&cx).unwrap();
                connection.confirm_handshake(&cx).unwrap();
                let mut session = NativeH3Session::with_config(session_config);
                if let Some(chunk) = streaming {
                    session.enable_streaming_receive(chunk).unwrap();
                }
                let control = session
                    .initialize(&cx, &mut connection, config.local_h3_settings())
                    .unwrap();
                let mut wire = Vec::new();
                for frame in connection
                    .inner_mut()
                    .generate_stream_frames_for(
                        &cx,
                        PacketNumberSpace::ApplicationData,
                        control,
                        65_536,
                    )
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
                        assert_eq!(offset.map_or(0, VarInt::value), wire.len() as u64);
                        assert!(!fin);
                        wire.extend_from_slice(&data);
                    }
                }
                let (kind, prefix) = decode_varint(&wire).unwrap();
                assert_eq!(kind, 0);
                let (frame, consumed) = H3Frame::decode(&wire[prefix..], &session_config).unwrap();
                assert_eq!(prefix + consumed, wire.len());
                let H3Frame::Settings(settings) = frame else {
                    panic!("the listener must advertise SETTINGS first");
                };
                assert_eq!(
                    settings.qpack_max_table_capacity,
                    capacity.map(|n| n.get() as u64)
                );
                assert_eq!(settings.qpack_blocked_streams, capacity.map(|_| 0));
                let expected_field_limit = if capacity.is_some() {
                    Some(
                        field_limit
                            .unwrap_or(NATIVE_H3_MAX_QPACK_FIELD_SECTION_SIZE)
                            .min(NATIVE_H3_MAX_QPACK_FIELD_SECTION_SIZE),
                    )
                } else {
                    field_limit
                };
                assert_eq!(settings.max_field_section_size, expected_field_limit);
            }
        }
    }
