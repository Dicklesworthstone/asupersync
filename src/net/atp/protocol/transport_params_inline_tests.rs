    use super::*;

    #[test]
    fn test_transport_parameters_basic() {
        let mut params = TransportParameters::new();

        // Set some basic parameters
        params
            .set_varint(TransportParameterId::InitialMaxData, 65536)
            .unwrap();
        params
            .set_varint(TransportParameterId::MaxIdleTimeout, 30000)
            .unwrap();
        params.set_empty(TransportParameterId::DisableActiveMigration);

        assert_eq!(
            params.get_varint(TransportParameterId::InitialMaxData),
            Some(65536)
        );
        assert_eq!(
            params.get_varint(TransportParameterId::MaxIdleTimeout),
            Some(30000)
        );
        assert!(params.has_empty(TransportParameterId::DisableActiveMigration));
    }

    #[test]
    fn test_transport_parameters_encoding_roundtrip() {
        let mut params = TransportParameters::new();

        // Set required parameters
        params
            .set_varint(TransportParameterId::InitialMaxData, 65536)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataBidiLocal, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataBidiRemote, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataUni, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamsBidi, 100)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamsUni, 100)
            .unwrap();

        // Add an unknown parameter
        params.set_unknown_parameter(0xFF00, Bytes::from_static(b"extension_data"));

        // Encode and decode
        let encoded = params.encode().unwrap();
        let decoded = TransportParameters::decode(encoded).unwrap();

        // Check that parameters match
        assert_eq!(
            decoded.get_varint(TransportParameterId::InitialMaxData),
            Some(65536)
        );
        assert_eq!(
            decoded.get_unknown_parameter(0xFF00),
            Some(&Bytes::from_static(b"extension_data"))
        );
    }

    #[test]
    fn test_transport_parameters_validation() {
        let mut params = TransportParameters::new();

        // Missing required parameters should fail validation
        assert!(params.validate(false).is_err());

        // Add all required parameters
        params
            .set_varint(TransportParameterId::InitialMaxData, 65536)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataBidiLocal, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataBidiRemote, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataUni, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamsBidi, 100)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamsUni, 100)
            .unwrap();

        // Should now validate successfully
        assert!(params.validate(false).is_ok());
    }

    #[test]
    fn test_invalid_parameter_values() {
        let mut params = TransportParameters::new();

        // Add required parameters
        params
            .set_varint(TransportParameterId::InitialMaxData, 65536)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataBidiLocal, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataBidiRemote, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataUni, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamsBidi, 100)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamsUni, 100)
            .unwrap();

        // Add invalid ACK delay exponent
        params
            .set_varint(TransportParameterId::AckDelayExponent, 25)
            .unwrap(); // > 20

        assert!(params.validate(false).is_err());
    }

    #[test]
    fn test_forbidden_parameters() {
        let mut params = TransportParameters::new();

        // Add required parameters
        params
            .set_varint(TransportParameterId::InitialMaxData, 65536)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataBidiLocal, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataBidiRemote, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataUni, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamsBidi, 100)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamsUni, 100)
            .unwrap();

        // Add server-only parameter for client
        params.set_bytes(
            TransportParameterId::StatelessResetToken,
            Bytes::from(vec![0u8; 16]),
        );

        // Should fail validation for client
        assert!(params.validate(false).is_err());

        // Should succeed for server
        assert!(params.validate(true).is_ok());
    }

    #[test]
    fn test_duplicate_parameter_detection() {
        let mut buf = BytesMut::new();

        // Encode the same parameter twice
        let max_data_id = TransportParameterId::InitialMaxData.to_varint();
        let value = VarInt::new(65536).unwrap();

        // First instance
        max_data_id
            .encode_to_buf_for(TransportParameterId::InitialMaxData, &mut buf)
            .unwrap();
        TransportParameterValue::VarInt(value)
            .encode(TransportParameterId::InitialMaxData, &mut buf)
            .unwrap();

        // Duplicate instance
        max_data_id
            .encode_to_buf_for(TransportParameterId::InitialMaxData, &mut buf)
            .unwrap();
        TransportParameterValue::VarInt(value)
            .encode(TransportParameterId::InitialMaxData, &mut buf)
            .unwrap();

        // Decoding should fail
        let result = TransportParameters::decode(buf.freeze());
        assert!(matches!(
            result,
            Err(TransportParameterError::DuplicateParameter(_))
        ));
    }

    #[test]
    fn test_decode_rejects_malformed_varint_parameter_values() {
        let ack_delay_id = TransportParameterId::AckDelayExponent.to_varint();

        let mut empty = BytesMut::new();
        ack_delay_id
            .encode_to_buf_for(TransportParameterId::AckDelayExponent, &mut empty)
            .unwrap();
        VarInt::new(0).unwrap().encode(&mut empty).unwrap();
        assert!(matches!(
            TransportParameters::decode(empty.freeze()),
            Err(TransportParameterError::InvalidParameterLength { .. })
        ));

        let mut trailing = BytesMut::new();
        ack_delay_id
            .encode_to_buf_for(TransportParameterId::AckDelayExponent, &mut trailing)
            .unwrap();
        VarInt::new(2).unwrap().encode(&mut trailing).unwrap();
        trailing.put_u8(0x01);
        trailing.put_u8(0x00);
        assert!(matches!(
            TransportParameters::decode(trailing.freeze()),
            Err(TransportParameterError::InvalidParameterValue {
                parameter: TransportParameterId::AckDelayExponent,
                ..
            })
        ));

        let mut non_canonical = BytesMut::new();
        ack_delay_id
            .encode_to_buf_for(TransportParameterId::AckDelayExponent, &mut non_canonical)
            .unwrap();
        VarInt::new(2).unwrap().encode(&mut non_canonical).unwrap();
        non_canonical.put_u8(0x40);
        non_canonical.put_u8(0x01);
        assert!(matches!(
            TransportParameters::decode(non_canonical.freeze()),
            Err(TransportParameterError::VarInt(
                VarIntError::InvalidEncoding
            ))
        ));
    }

    #[test]
    fn test_conflicting_parameters() {
        let mut params = TransportParameters::new();

        // Add required parameters
        params
            .set_varint(TransportParameterId::InitialMaxData, 65536)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataBidiLocal, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataBidiRemote, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataUni, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamsBidi, 100)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamsUni, 100)
            .unwrap();

        // Set conflicting parameters
        params.set_empty(TransportParameterId::DisableActiveMigration);
        params.set_bytes(
            TransportParameterId::PreferredAddress,
            Bytes::from_static(b"preferred_address_fixture"),
        );

        // Should fail validation
        assert!(params.validate(true).is_err());
    }
