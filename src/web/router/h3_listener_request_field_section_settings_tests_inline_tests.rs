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
