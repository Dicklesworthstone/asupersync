    use super::*;
    use crate::bytes::BufMut;
    use crate::net::atp::protocol::varint::VARINT_MAX;

    fn encode_raw_param(id: TransportParamId, value: &[u8]) -> BytesMut {
        let mut buf = BytesMut::new();
        id.to_varint().encode(&mut buf).unwrap();
        VarInt::new(value.len() as u64)
            .unwrap()
            .encode(&mut buf)
            .unwrap();
        buf.put_slice(value);
        buf
    }

    #[test]
    fn test_transport_params_roundtrip() {
        let mut params = TransportParameters::new();
        params.set_integer(TransportParamId::MaxIdleTimeout, 30000);
        params.set_integer(TransportParamId::InitialMaxData, 1048576);
        params.set_flag(TransportParamId::DisableActiveMigration);
        params.set_bytes(
            TransportParamId::StatelessResetToken,
            Bytes::from_static(b"0123456789abcdef"),
        );

        let encoded = params.encode().unwrap();
        let decoded = TransportParameters::decode(&encoded).unwrap();

        assert_eq!(
            decoded.get_integer(TransportParamId::MaxIdleTimeout),
            Some(30000)
        );
        assert_eq!(
            decoded.get_integer(TransportParamId::InitialMaxData),
            Some(1048576)
        );
        assert!(decoded.has_flag(TransportParamId::DisableActiveMigration));
        assert_eq!(
            decoded.get_bytes(TransportParamId::StatelessResetToken),
            Some(&Bytes::from_static(b"0123456789abcdef"))
        );
    }

    #[test]
    fn test_client_defaults() {
        let params = TransportParameters::client_defaults();

        assert!(
            params
                .get_integer(TransportParamId::MaxIdleTimeout)
                .is_some()
        );
        assert!(
            params
                .get_integer(TransportParamId::InitialMaxData)
                .is_some()
        );
        assert!(!params.has_flag(TransportParamId::DisableActiveMigration));
    }

    #[test]
    fn test_validation() {
        let mut params = TransportParameters::new();
        params.set_integer(TransportParamId::AckDelayExponent, 25); // Too large

        assert!(params.validate().is_err());

        params.set_integer(TransportParamId::AckDelayExponent, 3); // Valid
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_duplicate_parameter() {
        let mut buf = BytesMut::new();

        // Add same parameter twice
        VarInt::new(0x01).unwrap().encode(&mut buf).unwrap(); // MaxIdleTimeout
        VarInt::new(2).unwrap().encode(&mut buf).unwrap(); // Length
        buf.put_u16(30000);

        VarInt::new(0x01).unwrap().encode(&mut buf).unwrap(); // MaxIdleTimeout again
        VarInt::new(2).unwrap().encode(&mut buf).unwrap(); // Length
        buf.put_u16(60000);

        let result = TransportParameters::decode(&buf);
        assert!(matches!(
            result,
            Outcome::Err(HandshakeError::DuplicateTransportParam { .. })
        ));
    }

    #[test]
    fn test_decode_rejects_malformed_integer_parameter_values() {
        let empty = encode_raw_param(TransportParamId::AckDelayExponent, &[]);
        assert!(matches!(
            TransportParameters::decode(&empty),
            Outcome::Err(HandshakeError::InvalidTransportParam { .. })
        ));

        let trailing = encode_raw_param(TransportParamId::MaxIdleTimeout, &[0x01, 0x00]);
        assert!(matches!(
            TransportParameters::decode(&trailing),
            Outcome::Err(HandshakeError::InvalidTransportParam { .. })
        ));

        let non_canonical = encode_raw_param(TransportParamId::AckDelayExponent, &[0x40, 0x01]);
        assert!(matches!(
            TransportParameters::decode(&non_canonical),
            Outcome::Err(HandshakeError::InvalidTransportParam { .. })
        ));
    }

    #[test]
    fn test_encode_rejects_oversized_integer_parameter() {
        let mut params = TransportParameters::new();
        params.set_integer(TransportParamId::MaxIdleTimeout, VARINT_MAX + 1);

        assert!(matches!(
            params.encode(),
            Outcome::Err(HandshakeError::InvalidTransportParam { .. })
        ));
    }

    #[test]
    fn test_max_idle_timeout_duration() {
        let mut params = TransportParameters::new();
        params.set_integer(TransportParamId::MaxIdleTimeout, 5000);

        assert_eq!(params.max_idle_timeout(), Some(Duration::from_millis(5000)));
    }

    #[test]
    fn test_max_datagram_frame_size_roundtrip() {
        let mut params = TransportParameters::new();
        params.set_integer(TransportParamId::MaxDatagramFrameSize, 1200);

        let encoded = params.encode().unwrap();
        let decoded = TransportParameters::decode(&encoded).unwrap();

        assert_eq!(
            decoded.get_integer(TransportParamId::MaxDatagramFrameSize),
            Some(1200)
        );
    }
